"""
Blockchain state machine for MessageChain.

Maintains the canonical chain, validates blocks and transactions,
and tracks all state (balances, nonces, public keys).
"""

import hashlib
from messagechain.config import HASH_ALGO, GENESIS_SUPPLY, GENESIS_ALLOCATION, MAX_TXS_PER_BLOCK
from messagechain.core.block import Block, compute_merkle_root, create_genesis_block
from messagechain.core.transaction import MessageTransaction, verify_transaction
from messagechain.economics.deflation import SupplyTracker
from messagechain.crypto.keys import verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class Blockchain:
    """The chain: ordered list of validated blocks + derived state."""

    def __init__(self):
        self.chain: list[Block] = []
        self.supply = SupplyTracker()
        self.nonces: dict[bytes, int] = {}  # entity_id -> next expected nonce
        self.public_keys: dict[bytes, bytes] = {}  # entity_id -> public_key
        self.entity_message_count: dict[bytes, int] = {}  # for stats

    def initialize_genesis(self, genesis_entity) -> Block:
        """Create the genesis block and initialize chain state."""
        genesis_block = create_genesis_block(genesis_entity)
        self.chain.append(genesis_block)

        # Register genesis entity
        self.public_keys[genesis_entity.entity_id] = genesis_entity.public_key
        self.nonces[genesis_entity.entity_id] = 0

        # Distribute initial supply: genesis entity gets an allocation,
        # rest stays in a "reserve" that gets distributed to new entities
        self.supply.initialize_balance(genesis_entity.entity_id, GENESIS_ALLOCATION)
        # The unallocated supply still counts toward total_supply for deflation math
        # but isn't spendable until allocated to entities

        return genesis_block

    def register_entity(self, entity) -> bool:
        """Register a new entity on the chain (receive initial allocation)."""
        if entity.entity_id in self.public_keys:
            return False  # already registered

        self.public_keys[entity.entity_id] = entity.public_key
        self.nonces[entity.entity_id] = 0
        self.supply.initialize_balance(entity.entity_id, GENESIS_ALLOCATION)
        return True

    def get_latest_block(self) -> Block | None:
        return self.chain[-1] if self.chain else None

    def get_block(self, index: int) -> Block | None:
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    @property
    def height(self) -> int:
        return len(self.chain)

    def validate_transaction(self, tx: MessageTransaction) -> tuple[bool, str]:
        """Validate a transaction against current chain state."""
        # Check entity is registered
        if tx.entity_id not in self.public_keys:
            return False, "Unknown entity"

        # Check nonce
        expected_nonce = self.nonces.get(tx.entity_id, 0)
        if tx.nonce != expected_nonce:
            return False, f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"

        # Check balance
        if not self.supply.can_afford(tx.entity_id):
            return False, "Insufficient balance"

        # Check burn amount matches current cost
        expected_burn = self.supply.calculate_burn_cost()
        if tx.burn_amount < expected_burn:
            return False, f"Burn amount too low: need {expected_burn}"

        # Verify signature
        public_key = self.public_keys[tx.entity_id]
        if not verify_transaction(tx, public_key):
            return False, "Invalid signature"

        return True, "Valid"

    def validate_block(self, block: Block) -> tuple[bool, str]:
        """Validate a block before adding it to the chain."""
        latest = self.get_latest_block()
        if latest is None:
            return False, "No genesis block"

        # Check prev_hash links
        if block.header.prev_hash != latest.block_hash:
            return False, "Invalid prev_hash"

        # Check block number
        if block.header.block_number != latest.header.block_number + 1:
            return False, "Invalid block number"

        # Check transaction count
        if len(block.transactions) > MAX_TXS_PER_BLOCK:
            return False, "Too many transactions"

        # Verify merkle root
        tx_hashes = [tx.tx_hash for tx in block.transactions]
        expected_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")
        if block.header.merkle_root != expected_root:
            return False, "Invalid merkle root"

        # Verify proposer signature
        if block.header.proposer_id not in self.public_keys:
            return False, "Unknown proposer"

        proposer_pk = self.public_keys[block.header.proposer_id]
        if block.header.proposer_signature:
            header_hash = _hash(block.header.signable_data())
            if not verify_signature(header_hash, block.header.proposer_signature, proposer_pk):
                return False, "Invalid proposer signature"

        # Validate all transactions
        for tx in block.transactions:
            valid, reason = self.validate_transaction(tx)
            if not valid:
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: {reason}"

        return True, "Valid"

    def add_block(self, block: Block) -> tuple[bool, str]:
        """Validate and append a block to the chain, updating state."""
        if self.height == 0:
            # Genesis block - just append
            self.chain.append(block)
            return True, "Genesis block added"

        valid, reason = self.validate_block(block)
        if not valid:
            return False, reason

        # Apply state changes
        for tx in block.transactions:
            self.supply.execute_burn(tx.entity_id, tx.burn_amount)
            self.nonces[tx.entity_id] = tx.nonce + 1
            self.entity_message_count[tx.entity_id] = (
                self.entity_message_count.get(tx.entity_id, 0) + 1
            )

        self.chain.append(block)
        return True, "Block added"

    def get_entity_stats(self, entity_id: bytes) -> dict:
        return {
            "entity_id": entity_id.hex(),
            "balance": self.supply.get_balance(entity_id),
            "staked": self.supply.get_staked(entity_id),
            "messages_posted": self.entity_message_count.get(entity_id, 0),
            "nonce": self.nonces.get(entity_id, 0),
        }

    def get_chain_info(self) -> dict:
        return {
            "height": self.height,
            "latest_block_hash": self.chain[-1].block_hash.hex() if self.chain else None,
            "registered_entities": len(self.public_keys),
            **self.supply.get_supply_stats(),
        }
