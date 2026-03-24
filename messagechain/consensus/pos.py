"""
Proof-of-Stake consensus for MessageChain.

Validators stake tokens to participate in block production.
The proposer for each block is selected deterministically based on
the previous block hash and stake-weighted randomness.
"""

import hashlib
import struct
import time
from messagechain.config import HASH_ALGO, VALIDATOR_MIN_STAKE, CONSENSUS_THRESHOLD, MAX_TXS_PER_BLOCK
from messagechain.core.block import Block, BlockHeader, compute_merkle_root
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class ProofOfStake:
    """Stake-weighted block proposer selection and validation."""

    def __init__(self):
        self.stakes: dict[bytes, int] = {}  # entity_id -> staked amount

    def register_validator(self, entity_id: bytes, stake_amount: int) -> bool:
        """Register a validator with their stake."""
        if stake_amount < VALIDATOR_MIN_STAKE:
            return False
        self.stakes[entity_id] = self.stakes.get(entity_id, 0) + stake_amount
        return True

    def remove_validator(self, entity_id: bytes):
        self.stakes.pop(entity_id, None)

    @property
    def total_stake(self) -> int:
        return sum(self.stakes.values())

    @property
    def validator_count(self) -> int:
        return len(self.stakes)

    def select_proposer(self, prev_block_hash: bytes) -> bytes | None:
        """
        Deterministically select the next block proposer.

        Uses the previous block hash as a seed, weighted by stake.
        Every node computes the same result for the same chain state.
        """
        if not self.stakes:
            return None

        # Sort validators for deterministic ordering
        validators = sorted(self.stakes.items(), key=lambda x: x[0])
        total = self.total_stake

        # Hash the prev block to get a random value
        seed = _hash(prev_block_hash + b"proposer_selection")
        rand_value = int.from_bytes(seed[:8], "big") % total

        # Stake-weighted selection
        cumulative = 0
        for entity_id, stake in validators:
            cumulative += stake
            if rand_value < cumulative:
                return entity_id

        return validators[-1][0]  # fallback

    def validate_proposer(self, entity_id: bytes, prev_block_hash: bytes) -> bool:
        """Check if entity_id is the legitimate proposer for this round."""
        expected = self.select_proposer(prev_block_hash)
        return expected == entity_id

    def validate_block_attestations(self, block: Block) -> bool:
        """
        Check that enough validators have signed off on the block.

        Requires >= CONSENSUS_THRESHOLD of total stake to have attested.
        """
        if not self.stakes:
            return True  # no validators = permissive (bootstrap phase)

        attested_stake = 0
        for entity_id, sig in block.validator_signatures:
            if entity_id in self.stakes:
                attested_stake += self.stakes[entity_id]

        return (attested_stake / self.total_stake) >= CONSENSUS_THRESHOLD

    def create_block(
        self,
        proposer_entity,
        transactions: list[MessageTransaction],
        prev_block: Block,
        state_root: bytes = b"\x00" * 32,
    ) -> Block:
        """Create a new block as the selected proposer."""
        txs = transactions[:MAX_TXS_PER_BLOCK]
        tx_hashes = [tx.tx_hash for tx in txs]
        merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")

        header = BlockHeader(
            version=1,
            block_number=prev_block.header.block_number + 1,
            prev_hash=prev_block.block_hash,
            merkle_root=merkle_root,
            timestamp=time.time(),
            proposer_id=proposer_entity.entity_id,
            state_root=state_root,
        )

        # Proposer signs the block header
        header_hash = _hash(header.signable_data())
        header.proposer_signature = proposer_entity.keypair.sign(header_hash)

        block = Block(header=header, transactions=txs)
        block.block_hash = block._compute_hash()
        return block
