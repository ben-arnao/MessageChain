"""
Proof-of-Stake consensus for MessageChain.

Validators stake tokens to participate in block production.
The proposer for each block is selected deterministically based on
the previous block hash and stake-weighted randomness.

Validators also attest (vote) for blocks they consider valid. A block
needs 2/3+ of total stake attesting to become finalized. Finalized
blocks can never be reverted.
"""

import hashlib
import struct
import time
from messagechain.config import (
    HASH_ALGO, VALIDATOR_MIN_STAKE, GRADUATED_STAKE_TIERS,
    CONSENSUS_THRESHOLD_NUMERATOR,
    CONSENSUS_THRESHOLD_DENOMINATOR, MAX_TXS_PER_BLOCK, MAX_BLOCK_MESSAGE_BYTES,
)
from messagechain.core.block import Block, BlockHeader, compute_merkle_root
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import verify_signature
from messagechain.consensus.attestation import Attestation, create_attestation, verify_attestation


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def graduated_min_stake(block_height: int) -> int:
    """Return the minimum stake required at a given block height.

    Early network is accessible (1 token minimum). As the chain matures,
    the barrier increases to harden sybil resistance.
    """
    for threshold, min_stake in GRADUATED_STAKE_TIERS:
        if threshold is not None and block_height < threshold:
            return min_stake
    # Final tier (threshold is None)
    return GRADUATED_STAKE_TIERS[-1][1]


class ProofOfStake:
    """Stake-weighted block proposer selection and validation."""

    def __init__(self):
        self.stakes: dict[bytes, int] = {}  # entity_id -> staked amount
        self._bootstrap_ended: bool = False  # one-way flag

    @property
    def is_bootstrap_mode(self) -> bool:
        """Bootstrap mode: permissive proposer + attestation rules.

        Stays active until at least MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        distinct validators are registered, so we never end up with a
        1-validator post-bootstrap chain that has a single point of
        failure for both liveness and finality. Once exited, the flag
        is one-way: we never re-enter bootstrap even if validators leave.
        """
        if self._bootstrap_ended:
            return False
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        return len(self.stakes) < MIN_VALIDATORS_TO_EXIT_BOOTSTRAP

    def register_validator(self, entity_id: bytes, stake_amount: int, block_height: int = 0) -> bool:
        """Register a validator with their stake."""
        if stake_amount < graduated_min_stake(block_height):
            return False
        self.stakes[entity_id] = self.stakes.get(entity_id, 0) + stake_amount
        # Bootstrap mode ends only once we have enough distinct validators
        # for the network to survive a single failure.
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        if len(self.stakes) >= MIN_VALIDATORS_TO_EXIT_BOOTSTRAP:
            self._bootstrap_ended = True
        return True

    def remove_validator(self, entity_id: bytes):
        self.stakes.pop(entity_id, None)

    @property
    def total_stake(self) -> int:
        return sum(self.stakes.values())

    @property
    def validator_count(self) -> int:
        return len(self.stakes)

    def select_proposer(
        self,
        prev_block_hash: bytes,
        randao_mix: bytes | None = None,
        round_number: int = 0,
    ) -> bytes | None:
        """
        Deterministically select the block proposer for a given round.

        Uses the previous block hash, optional RANDAO mix, and the round
        number as the seed. Every node computes the same result for the
        same chain state and round.

        round_number rotates the proposer when an earlier round timed out
        without producing a block. Round 0 is the primary proposer; round
        N is the fallback after the previous N proposers failed to produce
        within their slot window. This is the network's liveness escape
        hatch — without it, a single offline validator stalls the chain
        forever.
        """
        if not self.stakes:
            return None

        # Sort validators for deterministic ordering
        validators = sorted(self.stakes.items(), key=lambda x: x[0])
        total = self.total_stake
        if total == 0:
            return None  # all stakes are zero — no valid proposer

        # Build seed from prev_block_hash, optional RANDAO mix, and round number
        seed_input = prev_block_hash
        if randao_mix is not None:
            seed_input = seed_input + randao_mix
        seed_input = seed_input + struct.pack(">I", round_number)
        seed = _hash(seed_input + b"proposer_selection")
        rand_value = int.from_bytes(seed, "big") % total

        # Stake-weighted selection
        cumulative = 0
        for entity_id, stake in validators:
            cumulative += stake
            if rand_value < cumulative:
                return entity_id

        return validators[-1][0]  # fallback

    def validate_proposer(
        self,
        entity_id: bytes,
        prev_block_hash: bytes,
        randao_mix: bytes | None = None,
        round_number: int = 0,
    ) -> bool:
        """Check if entity_id is the legitimate proposer for the given round."""
        expected = self.select_proposer(prev_block_hash, randao_mix=randao_mix, round_number=round_number)
        return expected == entity_id

    def validate_block_attestations(
        self,
        block: Block,
        public_keys: dict[bytes, bytes] | None = None,
    ) -> bool:
        """
        Check that enough validators have attested to the block's parent.

        Requires >= CONSENSUS_THRESHOLD of total stake to have attested.
        Attestations are carried in the block and vote for the parent block.

        During bootstrap (no validators staked), this is permissive.
        """
        bootstrap = self.is_bootstrap_mode

        total = self.total_stake
        if total == 0 and not bootstrap:
            return False  # post-bootstrap with zero stake — cannot meet threshold

        # SECURITY: during bootstrap we relax the THRESHOLD requirement
        # (accepting blocks with fewer attestations) but we still VERIFY
        # SIGNATURES on any attestations that are present, when public keys
        # are available.  Earlier revisions returned True immediately in
        # bootstrap, which let forged attestations become "finalized" before
        # the network hardened.
        if public_keys is not None and block.attestations:
            for att in block.attestations:
                pub = public_keys.get(att.validator_id)
                if pub is not None and not verify_attestation(att, pub):
                    return False  # bad sig — reject even in bootstrap

        if bootstrap:
            return True  # threshold is relaxed, but sigs were checked above

        # Post-bootstrap: require public keys for attestation counting.
        if public_keys is None:
            return False

        attested_stake = 0
        seen = set()
        for att in block.attestations:
            if att.validator_id in seen:
                continue  # skip duplicates
            seen.add(att.validator_id)

            # A validator's public key must be known AND the attestation
            # signature must verify. Anything else is rejected.
            pub = public_keys.get(att.validator_id)
            if pub is None:
                continue
            if not verify_attestation(att, pub):
                continue

            if att.validator_id in self.stakes:
                attested_stake += self.stakes[att.validator_id]

        # Integer arithmetic to avoid floating-point rounding errors in consensus.
        # attested/total >= NUM/DEN  ↔  attested * DEN >= total * NUM
        return (attested_stake * CONSENSUS_THRESHOLD_DENOMINATOR
                >= total * CONSENSUS_THRESHOLD_NUMERATOR)

    def create_block(
        self,
        proposer_entity,
        transactions: list[MessageTransaction],
        prev_block: Block,
        state_root: bytes = b"\x00" * 32,
        attestations: list[Attestation] | None = None,
        transfer_transactions: list | None = None,
        slash_transactions: list | None = None,
        timestamp: float | None = None,
    ) -> Block:
        """Create a new block as the selected proposer.

        Attestations are votes for the parent block (prev_block), collected
        from validators after the parent was proposed.

        slash_transactions (if any) are committed into the merkle_root so
        that a byzantine relayer cannot strip them from the block without
        invalidating the proposer's signature. Previously, slash_transactions
        were attached post-signing and not cryptographically bound — any
        relay node could drop them in transit.
        """
        # Apply both tx count cap and message byte budget.
        # Byte budget ensures large messages compete for limited space.
        txs = []
        msg_bytes_used = 0
        for tx in transactions[:MAX_TXS_PER_BLOCK]:
            tx_msg_size = len(tx.message)
            if msg_bytes_used + tx_msg_size > MAX_BLOCK_MESSAGE_BYTES:
                break
            txs.append(tx)
            msg_bytes_used += tx_msg_size
        transfer_txs = (transfer_transactions or [])[:MAX_TXS_PER_BLOCK]
        slash_txs = list(slash_transactions or [])
        tx_hashes = (
            [tx.tx_hash for tx in txs]
            + [tx.tx_hash for tx in transfer_txs]
            + [tx.tx_hash for tx in slash_txs]
        )
        merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")

        header = BlockHeader(
            version=1,
            block_number=prev_block.header.block_number + 1,
            prev_hash=prev_block.block_hash,
            merkle_root=merkle_root,
            timestamp=time.time() if timestamp is None else timestamp,
            proposer_id=proposer_entity.entity_id,
            state_root=state_root,
        )

        # Proposer signs the block header. randao_mix is excluded from
        # signable_data to break a circular dependency (the mix is derived
        # from this very signature) but is bound to the block via _compute_hash.
        header_hash = _hash(header.signable_data())
        header.proposer_signature = proposer_entity.keypair.sign(header_hash)

        # Derive RANDAO mix from parent.randao_mix + proposer signature.
        # Each grinding attempt requires a new signature → consumes a fresh
        # WOTS+ leaf, observable on chain via proposer_sig_counts.
        from messagechain.consensus.randao import derive_randao_mix
        header.randao_mix = derive_randao_mix(
            prev_block.header.randao_mix, header.proposer_signature
        )

        block = Block(
            header=header,
            transactions=txs,
            attestations=attestations or [],
            transfer_transactions=transfer_txs,
            slash_transactions=slash_txs,
        )
        block.block_hash = block._compute_hash()
        return block
