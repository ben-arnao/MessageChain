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
    HASH_ALGO, VALIDATOR_MIN_STAKE,
    CONSENSUS_THRESHOLD_NUMERATOR,
    CONSENSUS_THRESHOLD_DENOMINATOR, MAX_TXS_PER_BLOCK, MAX_BLOCK_MESSAGE_BYTES,
)
from messagechain.core.block import Block, BlockHeader, compute_merkle_root
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import verify_signature
from messagechain.consensus.attestation import Attestation, create_attestation, verify_attestation


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class ProofOfStake:
    """Stake-weighted block proposer selection and validation."""

    def __init__(self):
        self.stakes: dict[bytes, int] = {}  # entity_id -> staked amount
        self._bootstrap_ended: bool = False  # one-way flag

    @property
    def is_bootstrap_mode(self) -> bool:
        """PoS-local "not enough validators yet" heuristic.

        Stays active until at least MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        distinct validators are registered — once exited, the flag is
        one-way.

        This is NOT the canonical bootstrap state.  The canonical signal
        is `Blockchain.bootstrap_progress` (a monotonic [0, 1] gradient
        that drives min-stake, attester-committee weighting, escrow
        window, and seed-exclusion rules — see
        messagechain/consensus/bootstrap_gradient.py).  This property
        survives as a local PoS-layer signal used by
        `validate_block_attestations`, which does not have a Blockchain
        reference and needs a local answer to "is the validator set
        large enough for a 2/3-of-stake threshold to count as finality?"
        The historical name is kept so dynamic test overrides continue
        to work without churn (see tests/__init__.py).
        """
        if self._bootstrap_ended:
            return False
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        return len(self.stakes) < MIN_VALIDATORS_TO_EXIT_BOOTSTRAP

    def register_validator(self, entity_id: bytes, stake_amount: int, block_height: int = 0) -> bool:
        """Register a validator with their stake."""
        if stake_amount < VALIDATOR_MIN_STAKE:
            return False
        self.stakes[entity_id] = self.stakes.get(entity_id, 0) + stake_amount
        # Local bootstrap-heuristic ends once we have enough distinct
        # validators for the finality floor.  This only flips a PoS-
        # internal flag; the canonical bootstrap signal
        # (Blockchain.bootstrap_progress) is independent.
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

            # H1: Attestations must vote for the parent block. Reject
            # attestations for a different block hash or block number —
            # prevents replaying valid attestations from other blocks.
            if att.block_hash != block.header.prev_hash:
                continue
            if att.block_number != block.header.block_number - 1:
                continue

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
        governance_txs: list | None = None,
        authority_txs: list | None = None,
        stake_transactions: list | None = None,
        unstake_transactions: list | None = None,
        registration_transactions: list | None = None,
        finality_votes: list | None = None,
        timestamp: float | None = None,
        mempool_tx_hashes: list[bytes] | None = None,
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
        gov_txs = list(governance_txs or [])
        auth_txs = list(authority_txs or [])
        stake_txs = list(stake_transactions or [])
        unstake_txs = list(unstake_transactions or [])
        registration_txs = list(registration_transactions or [])
        fin_votes = list(finality_votes or [])
        tx_hashes = (
            [tx.tx_hash for tx in txs]
            + [tx.tx_hash for tx in transfer_txs]
            + [tx.tx_hash for tx in slash_txs]
            + [tx.tx_hash for tx in gov_txs]
            + [tx.tx_hash for tx in auth_txs]
            + [tx.tx_hash for tx in stake_txs]
            + [tx.tx_hash for tx in unstake_txs]
            + [tx.tx_hash for tx in registration_txs]
            + [v.consensus_hash() for v in fin_votes]
        )
        merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")

        # Inclusion attestation: commit to mempool state at proposal time.
        if mempool_tx_hashes:
            from messagechain.consensus.inclusion_attestation import (
                compute_mempool_snapshot_root,
            )
            snapshot_root = compute_mempool_snapshot_root(mempool_tx_hashes)
        else:
            snapshot_root = b"\x00" * 32

        header = BlockHeader(
            version=1,
            block_number=prev_block.header.block_number + 1,
            prev_hash=prev_block.block_hash,
            merkle_root=merkle_root,
            timestamp=time.time() if timestamp is None else timestamp,
            proposer_id=proposer_entity.entity_id,
            state_root=state_root,
            mempool_snapshot_root=snapshot_root,
        )

        # Guard against WOTS+ leaf reuse: if the proposer also has
        # transactions in this block (signed earlier, possibly before a
        # keypair restart), the keypair's _next_leaf may not have been
        # advanced past those txs' leaves.  Scan all tx lists for the
        # proposer's entity_id and advance past the highest used leaf to
        # guarantee the header signature gets a fresh leaf.
        proposer_id = proposer_entity.entity_id
        for tx_list in (txs, transfer_txs, slash_txs, gov_txs,
                        auth_txs, stake_txs, unstake_txs, registration_txs):
            for tx in tx_list:
                tx_entity = getattr(tx, "entity_id", None)
                if tx_entity == proposer_id:
                    sig = getattr(tx, "signature", None) or getattr(tx, "registration_proof", None)
                    if sig is not None and hasattr(sig, "leaf_index"):
                        proposer_entity.keypair.advance_to_leaf(sig.leaf_index + 1)

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
            governance_txs=gov_txs,
            authority_txs=auth_txs,
            stake_transactions=stake_txs,
            unstake_transactions=unstake_txs,
            registration_transactions=registration_txs,
            finality_votes=fin_votes,
        )
        block.block_hash = block._compute_hash()
        return block
