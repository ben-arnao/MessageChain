"""
Blockchain state machine for MessageChain.

Core invariants:
- One entity per person (duplicate biometrics rejected)
- Every transaction is timestamped
- Fees follow BTC-style bidding (set by user, collected by proposer)
- Supply inflates via block rewards to offset natural loss
- Base layer is minimal — L2 handles everything else

Now supports:
- Persistent storage (SQLite) — chain survives restarts
- Fork choice — tracks multiple chain tips, picks heaviest
- Chain reorganization — rolls back and replays when a better fork appears
"""

import hashlib
import logging
from messagechain.config import HASH_ALGO, MAX_TXS_PER_BLOCK
from messagechain.core.block import Block, compute_merkle_root, compute_state_root, create_genesis_block
from messagechain.core.transaction import MessageTransaction, verify_transaction
from messagechain.core.key_rotation import (
    KeyRotationTransaction, verify_key_rotation,
)
from messagechain.consensus.slashing import (
    SlashTransaction, verify_slashing_evidence,
)
from messagechain.economics.inflation import SupplyTracker
from messagechain.crypto.keys import verify_signature
from messagechain.consensus.fork_choice import (
    ForkChoice, compute_block_stake_weight, find_fork_point, MAX_REORG_DEPTH,
)

logger = logging.getLogger(__name__)


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class Blockchain:
    """The chain: ordered list of validated blocks + derived state.

    Can operate in two modes:
    - In-memory (default, backward compatible): no db argument
    - Persistent (SQLite): pass a ChainDB instance
    """

    def __init__(self, db=None):
        self.db = db  # optional ChainDB for persistence
        self.chain: list[Block] = []
        self.supply = SupplyTracker()
        self.nonces: dict[bytes, int] = {}  # entity_id -> next expected nonce
        self.public_keys: dict[bytes, bytes] = {}  # entity_id -> public_key
        self.entity_message_count: dict[bytes, int] = {}
        self.key_rotation_counts: dict[bytes, int] = {}  # entity_id -> rotation number
        self.proposer_sig_counts: dict[bytes, int] = {}  # entity_id -> block signatures made
        self.slashed_validators: set[bytes] = set()  # entity IDs that have been slashed
        self.fork_choice = ForkChoice()
        self._block_by_hash: dict[bytes, Block] = {}  # in-memory block index

        # If db exists, try to load persisted state
        if self.db is not None:
            self._load_from_db()

    def _load_from_db(self):
        """Restore chain state from persistent storage on startup."""
        block_count = self.db.get_block_count()
        if block_count == 0:
            return  # fresh database, nothing to load

        logger.info(f"Loading {block_count} blocks from database...")

        # Load state
        self.public_keys = self.db.get_all_public_keys()
        self.nonces = self.db.get_all_nonces()
        self.entity_message_count = self.db.get_all_message_counts()

        # Restore supply tracker
        self.supply.balances = self.db.get_all_balances()
        self.supply.staked = self.db.get_all_staked()
        self.supply.total_supply = self.db.get_supply_meta("total_supply")
        self.supply.total_minted = self.db.get_supply_meta("total_minted")
        self.supply.total_fees_collected = self.db.get_supply_meta("total_fees_collected")

        # Restore proposer signature counts (for WOTS+ leaf tracking)
        if hasattr(self.db, 'get_all_proposer_sig_counts'):
            self.proposer_sig_counts = self.db.get_all_proposer_sig_counts()

        # Restore slashed validators
        if hasattr(self.db, 'get_all_slashed'):
            self.slashed_validators = self.db.get_all_slashed()

        # Rebuild in-memory chain from best tip
        best_tip = self.db.get_best_tip()
        if best_tip is None:
            return

        tip_hash, tip_height, tip_weight = best_tip

        # Load all blocks into chain list (ordered by height)
        for height in range(tip_height + 1):
            block = self.db.get_block_by_number(height)
            if block:
                self.chain.append(block)
                self._block_by_hash[block.block_hash] = block

        # Restore fork choice tips
        for tip_hash_db, tip_num, tip_w in self.db.get_all_tips():
            self.fork_choice.add_tip(tip_hash_db, tip_num, tip_w)

        logger.info(f"Loaded chain: height={self.height}, tips={len(self.fork_choice.tips)}")

    def _persist_state(self):
        """Write current in-memory state to database."""
        if self.db is None:
            return
        for eid, bal in self.supply.balances.items():
            self.db.set_balance(eid, bal)
        for eid, stk in self.supply.staked.items():
            self.db.set_staked(eid, stk)
        for eid, nonce in self.nonces.items():
            self.db.set_nonce(eid, nonce)
        for eid, pk in self.public_keys.items():
            self.db.set_public_key(eid, pk)
        for eid, cnt in self.entity_message_count.items():
            self.db.set_message_count(eid, cnt)
        for eid, cnt in self.proposer_sig_counts.items():
            self.db.set_proposer_sig_count(eid, cnt)
        self.db.set_supply_meta("total_supply", self.supply.total_supply)
        self.db.set_supply_meta("total_minted", self.supply.total_minted)
        self.db.set_supply_meta("total_fees_collected", self.supply.total_fees_collected)
        # Persist slashed validators
        if hasattr(self.db, 'add_slashed_validator'):
            for eid in self.slashed_validators:
                self.db.add_slashed_validator(eid, self.height, b"")
        self.db.flush_state()

    def initialize_genesis(self, genesis_entity) -> Block:
        """Create the genesis block and initialize chain state."""
        genesis_block = create_genesis_block(genesis_entity)
        self.chain.append(genesis_block)
        self._block_by_hash[genesis_block.block_hash] = genesis_block

        # Register genesis entity
        self.public_keys[genesis_entity.entity_id] = genesis_entity.public_key
        self.nonces[genesis_entity.entity_id] = 0
        # Genesis block was signed — track the WOTS+ leaf consumed
        self.proposer_sig_counts[genesis_entity.entity_id] = 1

        # Track as chain tip
        self.fork_choice.add_tip(genesis_block.block_hash, 0, 0)

        # Persist
        if self.db is not None:
            self.db.store_block(genesis_block)
            self.db.add_chain_tip(genesis_block.block_hash, 0, 0)
            self._persist_state()

        return genesis_block

    def register_entity(self, entity_id: bytes, public_key: bytes) -> tuple[bool, str]:
        """
        Register a new entity on the chain.

        Accepts only the public entity_id and public_key — never private key
        material. The server never needs to see biometric hashes or seeds.

        ENFORCES: one entity per person. If the entity_id (derived from
        biometrics) already exists, registration is REJECTED.
        """
        if entity_id in self.public_keys:
            return False, "Entity already exists — duplicate biometrics rejected"

        self.public_keys[entity_id] = public_key
        self.nonces[entity_id] = 0

        if self.db is not None:
            self.db.set_public_key(entity_id, public_key)
            self.db.set_nonce(entity_id, 0)
            self.db.set_balance(entity_id, self.supply.get_balance(entity_id))
            self.db.flush_state()

        return True, "Entity registered"

    def get_latest_block(self) -> Block | None:
        return self.chain[-1] if self.chain else None

    def get_block(self, index: int) -> Block | None:
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def get_block_by_hash(self, block_hash: bytes) -> Block | None:
        """Look up a block by its hash (in-memory index or DB)."""
        block = self._block_by_hash.get(block_hash)
        if block is None and self.db is not None:
            block = self.db.get_block_by_hash(block_hash)
            if block:
                self._block_by_hash[block_hash] = block
        return block

    @property
    def height(self) -> int:
        return len(self.chain)

    def has_block(self, block_hash: bytes) -> bool:
        if block_hash in self._block_by_hash:
            return True
        if self.db is not None:
            return self.db.has_block(block_hash)
        return False

    def validate_transaction(self, tx: MessageTransaction) -> tuple[bool, str]:
        """Validate a transaction against current chain state."""
        if tx.entity_id not in self.public_keys:
            return False, "Unknown entity — must register first"

        expected_nonce = self.nonces.get(tx.entity_id, 0)
        if tx.nonce != expected_nonce:
            return False, f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"

        if tx.timestamp <= 0:
            return False, "Transaction must have a valid timestamp"

        if not self.supply.can_afford_fee(tx.entity_id, tx.fee):
            return False, f"Insufficient balance for fee of {tx.fee}"

        public_key = self.public_keys[tx.entity_id]
        if not verify_transaction(tx, public_key):
            return False, "Invalid signature"

        return True, "Valid"

    def validate_key_rotation(self, tx: KeyRotationTransaction) -> tuple[bool, str]:
        """Validate a key rotation transaction against current chain state."""
        if tx.entity_id not in self.public_keys:
            return False, "Unknown entity — must register first"

        current_pk = self.public_keys[tx.entity_id]

        expected_rotation = self.key_rotation_counts.get(tx.entity_id, 0)
        if tx.rotation_number != expected_rotation:
            return False, f"Invalid rotation number: expected {expected_rotation}, got {tx.rotation_number}"

        if not self.supply.can_afford_fee(tx.entity_id, tx.fee):
            return False, f"Insufficient balance for rotation fee of {tx.fee}"

        if not verify_key_rotation(tx, current_pk):
            return False, "Invalid key rotation signature or parameters"

        return True, "Valid"

    def apply_key_rotation(self, tx: KeyRotationTransaction, proposer_id: bytes) -> tuple[bool, str]:
        """Validate and apply a key rotation, updating the entity's public key."""
        valid, reason = self.validate_key_rotation(tx)
        if not valid:
            return False, reason

        # Pay fee to proposer
        self.supply.pay_fee(tx.entity_id, proposer_id, tx.fee)

        # Update the entity's public key
        self.public_keys[tx.entity_id] = tx.new_public_key
        self.key_rotation_counts[tx.entity_id] = tx.rotation_number + 1

        # Persist
        if self.db is not None:
            self.db.set_public_key(tx.entity_id, tx.new_public_key)
            self.db.flush_state()

        return True, "Key rotated successfully"

    def validate_slash_transaction(self, tx: SlashTransaction) -> tuple[bool, str]:
        """Validate a slash transaction against current chain state."""
        if tx.submitter_id not in self.public_keys:
            return False, "Unknown submitter — must register first"

        if tx.evidence.offender_id not in self.public_keys:
            return False, "Unknown offender"

        if tx.evidence.offender_id in self.slashed_validators:
            return False, "Validator already slashed"

        if self.supply.get_staked(tx.evidence.offender_id) == 0:
            return False, "Offender has no stake to slash"

        if not self.supply.can_afford_fee(tx.submitter_id, tx.fee):
            return False, "Submitter cannot afford fee"

        # Verify the evidence itself (two valid conflicting signatures)
        offender_pk = self.public_keys[tx.evidence.offender_id]
        valid, reason = verify_slashing_evidence(tx.evidence, offender_pk)
        if not valid:
            return False, f"Invalid evidence: {reason}"

        # Verify submitter's signature on the slash transaction
        submitter_pk = self.public_keys[tx.submitter_id]
        msg_hash = _hash(tx._signable_data())
        if not verify_signature(msg_hash, tx.signature, submitter_pk):
            return False, "Invalid submitter signature"

        return True, "Valid"

    def apply_slash_transaction(self, tx: SlashTransaction, proposer_id: bytes) -> tuple[bool, str]:
        """Validate and apply a slash transaction."""
        valid, reason = self.validate_slash_transaction(tx)
        if not valid:
            return False, reason

        # Pay fee to proposer
        self.supply.pay_fee(tx.submitter_id, proposer_id, tx.fee)

        # Slash the offender
        slashed, finder_reward = self.supply.slash_validator(
            tx.evidence.offender_id, tx.submitter_id
        )
        self.slashed_validators.add(tx.evidence.offender_id)

        logger.info(
            f"SLASHED validator {tx.evidence.offender_id.hex()[:16]}: "
            f"burned={slashed - finder_reward}, finder_reward={finder_reward}"
        )

        return True, f"Validator slashed (total={slashed}, reward={finder_reward})"

    def compute_current_state_root(self) -> bytes:
        """Compute a Merkle commitment to the current account state."""
        return compute_state_root(
            self.supply.balances,
            self.nonces,
            self.supply.staked,
        )

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

        # Verify proposer signature (mandatory — unsigned blocks are rejected)
        if block.header.proposer_id not in self.public_keys:
            return False, "Unknown proposer"

        if block.header.proposer_signature is None:
            return False, "Missing proposer signature — unsigned blocks are rejected"

        proposer_pk = self.public_keys[block.header.proposer_id]
        header_hash = _hash(block.header.signable_data())
        if not verify_signature(header_hash, block.header.proposer_signature, proposer_pk):
            return False, "Invalid proposer signature"

        # Validate all transactions
        for tx in block.transactions:
            valid, reason = self.validate_transaction(tx)
            if not valid:
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: {reason}"

        return True, "Valid"

    def validate_block_standalone(self, block: Block, parent: Block) -> tuple[bool, str]:
        """Validate a block against a specific parent (for fork validation)."""
        if block.header.prev_hash != parent.block_hash:
            return False, "Invalid prev_hash"
        if block.header.block_number != parent.header.block_number + 1:
            return False, "Invalid block number"
        if len(block.transactions) > MAX_TXS_PER_BLOCK:
            return False, "Too many transactions"

        tx_hashes = [tx.tx_hash for tx in block.transactions]
        expected_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")
        if block.header.merkle_root != expected_root:
            return False, "Invalid merkle root"

        return True, "Valid"

    def _apply_block_state(self, block: Block):
        """Apply a block's state changes (fees, nonces, rewards) without validation."""
        proposer_id = block.header.proposer_id
        for tx in block.transactions:
            self.supply.pay_fee(tx.entity_id, proposer_id, tx.fee)
            self.nonces[tx.entity_id] = tx.nonce + 1
            self.entity_message_count[tx.entity_id] = (
                self.entity_message_count.get(tx.entity_id, 0) + 1
            )
        # Apply slash transactions
        for stx in block.slash_transactions:
            self.supply.pay_fee(stx.submitter_id, proposer_id, stx.fee)
            self.supply.slash_validator(stx.evidence.offender_id, stx.submitter_id)
            self.slashed_validators.add(stx.evidence.offender_id)
        self.supply.mint_block_reward(proposer_id, block.header.block_number)
        # Track proposer's block signature count
        self.proposer_sig_counts[proposer_id] = (
            self.proposer_sig_counts.get(proposer_id, 0) + 1
        )

    def add_block(self, block: Block) -> tuple[bool, str]:
        """Validate and append a block, updating state (fees + inflation)."""
        if self.height == 0:
            self.chain.append(block)
            self._block_by_hash[block.block_hash] = block
            self.fork_choice.add_tip(block.block_hash, 0, 0)
            if self.db is not None:
                self.db.store_block(block)
                self.db.add_chain_tip(block.block_hash, 0, 0)
            return True, "Genesis block added"

        # Check if we already have this block
        if self.has_block(block.block_hash):
            return False, "Block already known"

        # Check if this block extends our current tip
        latest = self.get_latest_block()
        if block.header.prev_hash == latest.block_hash:
            # Normal case: extends current best chain
            valid, reason = self.validate_block(block)
            if not valid:
                return False, reason
            return self._append_block(block)

        # Check if parent exists (potential fork)
        parent = self.get_block_by_hash(block.header.prev_hash)
        if parent is not None:
            # This block creates or extends a fork
            return self._handle_fork(block, parent)

        # Orphan block — parent unknown
        return False, "Orphan block — parent not found"

    def _append_block(self, block: Block) -> tuple[bool, str]:
        """Append a validated block to the current best chain."""
        proposer_id = block.header.proposer_id

        # Validate ALL slash transactions BEFORE applying any state changes.
        # This prevents state corruption if a slash tx fails validation
        # partway through (previously, regular tx state was already applied).
        for stx in block.slash_transactions:
            valid, reason = self.validate_slash_transaction(stx)
            if not valid:
                return False, f"Invalid slash tx: {reason}"

        # Apply state changes (all validation passed above)
        for tx in block.transactions:
            self.supply.pay_fee(tx.entity_id, proposer_id, tx.fee)
            self.nonces[tx.entity_id] = tx.nonce + 1
            self.entity_message_count[tx.entity_id] = (
                self.entity_message_count.get(tx.entity_id, 0) + 1
            )

        for stx in block.slash_transactions:
            self.supply.pay_fee(stx.submitter_id, proposer_id, stx.fee)
            self.supply.slash_validator(stx.evidence.offender_id, stx.submitter_id)
            self.slashed_validators.add(stx.evidence.offender_id)

        reward = self.supply.mint_block_reward(proposer_id, block.header.block_number)

        # Track proposer's block signature count (for WOTS+ leaf management)
        self.proposer_sig_counts[proposer_id] = (
            self.proposer_sig_counts.get(proposer_id, 0) + 1
        )

        # Verify state_root commitment (skip for legacy blocks with zero state_root)
        if block.header.state_root != b"\x00" * 32:
            expected_state_root = self.compute_current_state_root()
            if block.header.state_root != expected_state_root:
                return False, "Invalid state_root — state commitment mismatch"

        self.chain.append(block)
        self._block_by_hash[block.block_hash] = block

        # Update fork choice: remove old tip, add new
        old_tip = block.header.prev_hash
        old_tip_data = self.fork_choice.tips.get(old_tip)
        old_weight = old_tip_data[1] if old_tip_data else 0
        block_weight = compute_block_stake_weight(block, self.supply.staked)
        new_weight = old_weight + block_weight

        self.fork_choice.remove_tip(old_tip)
        self.fork_choice.add_tip(block.block_hash, block.header.block_number, new_weight)

        # Persist
        if self.db is not None:
            self.db.store_block(block)
            self.db.remove_chain_tip(old_tip)
            self.db.add_chain_tip(block.block_hash, block.header.block_number, new_weight)
            self._persist_state()

        return True, f"Block added (reward: {reward}, fees: {sum(tx.fee for tx in block.transactions)})"

    def _handle_fork(self, block: Block, parent: Block) -> tuple[bool, str]:
        """Handle a block that creates or extends a fork."""
        # Basic structural validation against parent
        valid, reason = self.validate_block_standalone(block, parent)
        if not valid:
            return False, f"Fork block invalid: {reason}"

        # Store the block (even if not on best chain yet)
        self._block_by_hash[block.block_hash] = block
        if self.db is not None:
            self.db.store_block(block)

        # Compute cumulative weight for this fork
        fork_weight = self._compute_cumulative_weight(block)

        # Check if the parent was a known tip (extending existing fork)
        if parent.block_hash in self.fork_choice.tips:
            self.fork_choice.remove_tip(parent.block_hash)
            if self.db is not None:
                self.db.remove_chain_tip(parent.block_hash)
        # Add new tip
        self.fork_choice.add_tip(block.block_hash, block.header.block_number, fork_weight)
        if self.db is not None:
            self.db.add_chain_tip(block.block_hash, block.header.block_number, fork_weight)

        # Check if this fork is now better than our current chain
        best_tip = self.fork_choice.get_best_tip()
        current_tip = self.get_latest_block()

        if best_tip and current_tip and best_tip[0] != current_tip.block_hash:
            # The new fork is better — reorganize
            return self._reorganize(current_tip.block_hash, best_tip[0])

        return True, f"Fork block stored (not best chain, weight={fork_weight})"

    def _compute_cumulative_weight(self, block: Block) -> int:
        """Walk back from block to genesis, summing stake weights."""
        weight = 0
        current = block
        depth = 0
        while current and depth < MAX_REORG_DEPTH + 10:
            weight += compute_block_stake_weight(current, self.supply.staked)
            if current.header.prev_hash == b"\x00" * 32:
                break
            current = self.get_block_by_hash(current.header.prev_hash)
            depth += 1
        return weight

    def _reorganize(self, old_tip_hash: bytes, new_tip_hash: bytes) -> tuple[bool, str]:
        """
        Reorganize: switch from old_tip to new_tip.

        1. Find common ancestor
        2. Snapshot state
        3. Roll back to ancestor
        4. Apply new chain
        5. If anything fails, restore snapshot
        """
        logger.info(f"REORG: {old_tip_hash.hex()[:16]} -> {new_tip_hash.hex()[:16]}")

        # Find fork point
        ancestor_hash, rollback_blocks, apply_blocks = find_fork_point(
            old_tip_hash, new_tip_hash, self.get_block_by_hash
        )

        if ancestor_hash is None:
            return False, "Reorg failed — no common ancestor (too deep or incompatible)"

        if len(rollback_blocks) > MAX_REORG_DEPTH:
            return False, f"Reorg rejected — depth {len(rollback_blocks)} exceeds max {MAX_REORG_DEPTH}"

        # Snapshot current state for rollback
        if self.db is not None:
            snapshot = self.db.save_state_snapshot()
        else:
            snapshot = self._snapshot_memory_state()

        # Roll back: remove blocks after ancestor from chain list
        ancestor_height = None
        for i, blk in enumerate(self.chain):
            if blk.block_hash == ancestor_hash:
                ancestor_height = i
                break

        if ancestor_height is None:
            return False, "Reorg failed — ancestor not in active chain"

        rolled_back = self.chain[ancestor_height + 1:]
        self.chain = self.chain[:ancestor_height + 1]

        # Reset state to ancestor point — replay from genesis
        self._reset_state()
        for blk in self.chain:
            if blk.header.block_number > 0:
                self._apply_block_state(blk)

        # Apply new fork blocks
        for blk in apply_blocks:
            # Re-register entities that may be needed
            # (entities registered in rolled-back blocks might not be in state)
            # Validate and apply
            if self.height > 0:
                valid, reason = self.validate_block(blk)
                if not valid:
                    # Reorg failed — restore old state
                    logger.warning(f"Reorg failed at block #{blk.header.block_number}: {reason}")
                    if self.db is not None:
                        self.db.restore_state_snapshot(snapshot)
                    else:
                        self._restore_memory_snapshot(snapshot)
                    # Rebuild chain list
                    self.chain = self.chain[:ancestor_height + 1] + list(rolled_back)
                    self._reset_state()
                    for b in self.chain:
                        if b.header.block_number > 0:
                            self._apply_block_state(b)
                    return False, f"Reorg aborted — new chain invalid at block #{blk.header.block_number}"

            self._apply_block_state(blk)
            self.chain.append(blk)
            self._block_by_hash[blk.block_hash] = blk

        # Persist new state
        if self.db is not None:
            self._persist_state()

        logger.info(
            f"REORG complete: rolled back {len(rolled_back)} blocks, "
            f"applied {len(apply_blocks)} blocks. New height: {self.height}"
        )
        return True, f"Chain reorganized (rollback={len(rolled_back)}, applied={len(apply_blocks)})"

    def _reset_state(self):
        """Reset in-memory state to genesis defaults for replay.

        Public keys are preserved (they come from registration, not blocks),
        but all balance/nonce state is rebuilt from block replay.
        """
        old_pks = dict(self.public_keys)
        self.supply = SupplyTracker()
        self.nonces = {}
        self.entity_message_count = {}
        self.proposer_sig_counts = {}
        self.public_keys = {}
        self.slashed_validators = set()

        # Restore public keys with zero balances — balances rebuild from block replay
        for eid, pk in old_pks.items():
            self.public_keys[eid] = pk
            self.nonces[eid] = 0

    def _snapshot_memory_state(self) -> dict:
        """Capture in-memory state for rollback."""
        return {
            "balances": dict(self.supply.balances),
            "staked": dict(self.supply.staked),
            "nonces": dict(self.nonces),
            "public_keys": dict(self.public_keys),
            "message_counts": dict(self.entity_message_count),
            "proposer_sig_counts": dict(self.proposer_sig_counts),
            "total_supply": self.supply.total_supply,
            "total_minted": self.supply.total_minted,
            "total_fees_collected": self.supply.total_fees_collected,
            "chain_length": len(self.chain),
            "slashed_validators": set(self.slashed_validators),
        }

    def _restore_memory_snapshot(self, snapshot: dict):
        """Restore in-memory state from snapshot."""
        self.supply.balances = snapshot["balances"]
        self.supply.staked = snapshot["staked"]
        self.supply.total_supply = snapshot["total_supply"]
        self.supply.total_minted = snapshot["total_minted"]
        self.supply.total_fees_collected = snapshot["total_fees_collected"]
        self.nonces = snapshot["nonces"]
        self.public_keys = snapshot["public_keys"]
        self.entity_message_count = snapshot["message_counts"]
        self.proposer_sig_counts = snapshot.get("proposer_sig_counts", {})
        self.slashed_validators = snapshot.get("slashed_validators", set())

    def get_wots_leaves_used(self, entity_id: bytes) -> int:
        """Total WOTS+ leaves consumed by this entity (tx nonce + block sigs).

        Used to safely advance a keypair past already-used one-time keys
        when reconstructing from biometrics (e.g., on server restart).
        """
        return (
            self.nonces.get(entity_id, 0)
            + self.proposer_sig_counts.get(entity_id, 0)
        )

    def get_entity_stats(self, entity_id: bytes) -> dict:
        return {
            "entity_id": entity_id.hex(),
            "balance": self.supply.get_balance(entity_id),
            "staked": self.supply.get_staked(entity_id),
            "messages_posted": self.entity_message_count.get(entity_id, 0),
            "nonce": self.nonces.get(entity_id, 0),
        }

    def get_chain_info(self) -> dict:
        best_tip = self.fork_choice.get_best_tip()
        tip_count = len(self.fork_choice.tips)
        return {
            "height": self.height,
            "latest_block_hash": self.chain[-1].block_hash.hex() if self.chain else None,
            "registered_entities": len(self.public_keys),
            "chain_tips": tip_count,
            "best_tip_weight": best_tip[2] if best_tip else 0,
            **self.supply.get_supply_stats(self.height),
        }
