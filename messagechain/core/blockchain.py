"""
Blockchain state machine for MessageChain.

Core invariants:
- One entity per private key (duplicate entity IDs rejected)
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
from messagechain.config import (
    HASH_ALGO, MAX_TXS_PER_BLOCK, VALIDATOR_MIN_STAKE, GENESIS_ALLOCATION,
    MAX_BLOCK_SIG_COST, COINBASE_MATURITY, MTP_BLOCK_COUNT,
)
from messagechain.core.block import Block, compute_merkle_root, compute_state_root, create_genesis_block
from messagechain.core.transaction import MessageTransaction, verify_transaction
from messagechain.core.key_rotation import (
    KeyRotationTransaction, verify_key_rotation,
)
from messagechain.core.transfer import (
    TransferTransaction, verify_transfer_transaction,
)
from messagechain.consensus.slashing import (
    SlashTransaction, SlashingEvidence, AttestationSlashingEvidence,
    verify_slashing_evidence, verify_attestation_slashing_evidence,
)
from messagechain.consensus.attestation import (
    Attestation, FinalityTracker, verify_attestation,
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
        self.attestation_sig_counts: dict[bytes, int] = {}  # entity_id -> attestation signatures made
        self.slash_sig_counts: dict[bytes, int] = {}  # entity_id -> slash submission signatures made
        self.slashed_validators: set[bytes] = set()  # entity IDs that have been slashed
        self.fork_choice = ForkChoice()
        self.finality = FinalityTracker()
        self._block_by_hash: dict[bytes, Block] = {}  # in-memory block index
        # Immature block rewards: list of (block_height, proposer_id, reward_amount)
        self._immature_rewards: list[tuple[int, bytes, int]] = []

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
        """Write current in-memory state to database atomically.

        All writes are wrapped in a single SQL transaction so a crash
        mid-persist cannot leave the database in a partially-updated state.
        """
        if self.db is None:
            return
        self.db.begin_transaction()
        try:
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
            self.db.commit_transaction()
        except Exception:
            self.db.rollback_transaction()
            raise

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

        # Genesis allocation — bootstrap the economy so the genesis entity
        # can stake, pay fees, and transfer tokens to new participants.
        self.supply.balances[genesis_entity.entity_id] = GENESIS_ALLOCATION

        # Track as chain tip
        self.fork_choice.add_tip(genesis_block.block_hash, 0, 0)

        # Persist
        if self.db is not None:
            self.db.store_block(genesis_block)
            self.db.add_chain_tip(genesis_block.block_hash, 0, 0)
            self._persist_state()

        return genesis_block

    def register_entity(
        self,
        entity_id: bytes,
        public_key: bytes,
        registration_proof: "Signature | None" = None,
    ) -> tuple[bool, str]:
        """
        Register a new entity on the chain.

        Requires a registration_proof: a signature over
        SHA3-256("register" || entity_id) using the keypair corresponding
        to public_key. This proves the registrant controls the keypair
        and prevents fabrication of arbitrary identities.

        ENFORCES: one entity per key. If the entity_id already exists,
        registration is REJECTED.
        """
        if entity_id in self.public_keys:
            return False, "Entity already exists — duplicate entity rejected"

        # Require proof of key ownership
        if registration_proof is None:
            return False, "Registration proof required — must sign entity_id with keypair"

        proof_msg = _hash(b"register" + entity_id)
        if not verify_signature(proof_msg, registration_proof, public_key):
            return False, "Invalid registration proof — signature does not match public key"

        self.public_keys[entity_id] = public_key
        self.nonces[entity_id] = 0

        if self.db is not None:
            self.db.set_public_key(entity_id, public_key)
            self.db.set_nonce(entity_id, 0)
            self.db.set_balance(entity_id, self.supply.get_balance(entity_id))
            self.db.flush_state()

        return True, "Entity registered"

    def sync_consensus_stakes(self, consensus: "ProofOfStake"):
        """Populate consensus.stakes from the supply tracker's staked amounts.

        Must be called after loading from DB so that the consensus module
        has accurate stake data (prevents falling into permissive bootstrap mode).
        """
        for entity_id, amount in self.supply.staked.items():
            if amount >= VALIDATOR_MIN_STAKE:
                consensus.stakes[entity_id] = amount

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

        if self.get_spendable_balance(tx.entity_id) < tx.fee:
            return False, f"Insufficient spendable balance for fee of {tx.fee}"

        public_key = self.public_keys[tx.entity_id]
        if not verify_transaction(tx, public_key):
            return False, "Invalid signature"

        return True, "Valid"

    def validate_transfer_transaction(self, tx: TransferTransaction) -> tuple[bool, str]:
        """Validate a transfer transaction against current chain state."""
        if tx.entity_id not in self.public_keys:
            return False, "Unknown sender — must register first"

        if tx.recipient_id not in self.public_keys:
            return False, "Unknown recipient — must register first"

        expected_nonce = self.nonces.get(tx.entity_id, 0)
        if tx.nonce != expected_nonce:
            return False, f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"

        if self.get_spendable_balance(tx.entity_id) < tx.amount + tx.fee:
            return False, f"Insufficient spendable balance for transfer of {tx.amount} + fee {tx.fee}"

        public_key = self.public_keys[tx.entity_id]
        if not verify_transfer_transaction(tx, public_key):
            return False, "Invalid signature"

        return True, "Valid"

    def apply_transfer_transaction(self, tx: TransferTransaction, proposer_id: bytes):
        """Apply a validated transfer: move tokens from sender to recipient, fee to proposer."""
        self.supply.balances[tx.entity_id] = self.supply.get_balance(tx.entity_id) - tx.amount - tx.fee
        self.supply.balances[tx.recipient_id] = self.supply.get_balance(tx.recipient_id) + tx.amount
        self.supply.balances[proposer_id] = self.supply.get_balance(proposer_id) + tx.fee
        self.supply.total_fees_collected += tx.fee
        self.nonces[tx.entity_id] = tx.nonce + 1

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
        if isinstance(tx.evidence, AttestationSlashingEvidence):
            valid, reason = verify_attestation_slashing_evidence(tx.evidence, offender_pk)
        else:
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

    def get_median_time_past(self) -> float:
        """Compute Median Time Past from the last MTP_BLOCK_COUNT blocks.

        Returns the median timestamp of the most recent blocks. This prevents
        proposers from manipulating timestamps to affect timelocks, unbonding
        periods, and TTLs. Same mechanism as Bitcoin (BIP 113).
        """
        if not self.chain:
            return 0.0
        timestamps = [
            b.header.timestamp
            for b in self.chain[-MTP_BLOCK_COUNT:]
        ]
        timestamps.sort()
        return timestamps[len(timestamps) // 2]

    def get_immature_balance(self, entity_id: bytes) -> int:
        """Get the total immature (locked) block reward balance for an entity."""
        current_height = self.height
        return sum(
            amount for height, eid, amount in self._immature_rewards
            if eid == entity_id and current_height - height < COINBASE_MATURITY
        )

    def get_spendable_balance(self, entity_id: bytes) -> int:
        """Get spendable balance (total balance minus immature rewards)."""
        total = self.supply.get_balance(entity_id)
        immature = self.get_immature_balance(entity_id)
        return total - immature

    def compute_current_state_root(self) -> bytes:
        """Compute a Merkle commitment to the current account state."""
        return compute_state_root(
            self.supply.balances,
            self.nonces,
            self.supply.staked,
        )

    def compute_post_state_root(
        self,
        transactions: list[MessageTransaction],
        proposer_id: bytes,
        block_height: int,
        transfer_transactions: list[TransferTransaction] | None = None,
    ) -> bytes:
        """Compute the state root AFTER applying a set of transactions.

        Used by block proposers to compute the correct post-state commitment
        without actually mutating chain state. The block header commits to
        the post-application state so validators can verify consistency.
        """
        sim_balances = dict(self.supply.balances)
        sim_nonces = dict(self.nonces)
        sim_staked = dict(self.supply.staked)

        # Simulate fee payments for message transactions
        for tx in transactions:
            sim_balances[tx.entity_id] = sim_balances.get(tx.entity_id, 0) - tx.fee
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tx.fee
            sim_nonces[tx.entity_id] = tx.nonce + 1

        # Simulate transfer transactions
        for ttx in (transfer_transactions or []):
            sim_balances[ttx.entity_id] = sim_balances.get(ttx.entity_id, 0) - ttx.amount - ttx.fee
            sim_balances[ttx.recipient_id] = sim_balances.get(ttx.recipient_id, 0) + ttx.amount
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + ttx.fee
            sim_nonces[ttx.entity_id] = ttx.nonce + 1

        # Simulate block reward
        reward = self.supply.calculate_block_reward(block_height)
        sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + reward

        return compute_state_root(sim_balances, sim_nonces, sim_staked)

    def propose_block(
        self,
        consensus: "ProofOfStake",
        proposer_entity,
        transactions: list[MessageTransaction],
        attestations: list[Attestation] | None = None,
        transfer_transactions: list[TransferTransaction] | None = None,
    ) -> Block:
        """Create a block with the correct post-state root.

        Convenience method that computes the state root automatically,
        ensuring every block commits to the correct post-application state.
        """
        prev = self.get_latest_block()
        block_height = prev.header.block_number + 1
        state_root = self.compute_post_state_root(
            transactions, proposer_entity.entity_id, block_height,
            transfer_transactions=transfer_transactions,
        )
        return consensus.create_block(
            proposer_entity, transactions, prev,
            state_root=state_root, attestations=attestations,
            transfer_transactions=transfer_transactions,
        )

    def _validate_attestations(self, block: Block) -> tuple[bool, str]:
        """Validate all attestations included in a block.

        Each attestation must:
        1. Be from a registered entity
        2. Reference the parent block (block carries attestations for its parent)
        3. Have a valid signature
        4. Not be a duplicate (same validator attesting twice in same block)
        """
        seen_validators = set()
        for att in block.attestations:
            # Must reference the parent block
            if att.block_hash != block.header.prev_hash:
                return False, f"Attestation references wrong block: expected parent {block.header.prev_hash.hex()[:16]}"
            if att.block_number != block.header.block_number - 1:
                return False, "Attestation references wrong block height"

            # Must be from a registered entity
            if att.validator_id not in self.public_keys:
                return False, f"Attestation from unknown entity {att.validator_id.hex()[:16]}"

            # No duplicate attestations from same validator in one block
            if att.validator_id in seen_validators:
                return False, f"Duplicate attestation from {att.validator_id.hex()[:16]}"
            seen_validators.add(att.validator_id)

            # Verify signature
            pk = self.public_keys[att.validator_id]
            if not verify_attestation(att, pk):
                return False, f"Invalid attestation signature from {att.validator_id.hex()[:16]}"

        return True, "Attestations valid"

    def _process_attestations(self, block: Block, stakes: dict[bytes, int]):
        """Process attestations in a block, updating finality tracker.

        When a block accumulates 2/3+ of stake in attestations, it becomes
        finalized and can never be reverted by a reorg.
        """
        total_stake = sum(stakes.values())
        for att in block.attestations:
            validator_stake = stakes.get(att.validator_id, 0)
            justified = self.finality.add_attestation(att, validator_stake, total_stake)
            if justified:
                logger.info(
                    f"FINALIZED: block #{att.block_number} ({att.block_hash.hex()[:16]}) "
                    f"reached 2/3+ attestation threshold"
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

        # Check block timestamp against Median Time Past (BIP 113)
        mtp = self.get_median_time_past()
        if block.header.timestamp <= mtp:
            return False, f"Block timestamp {block.header.timestamp} must exceed median time past {mtp}"

        # Check transaction count
        if len(block.transactions) > MAX_TXS_PER_BLOCK:
            return False, "Too many transactions"

        # Check for duplicate transaction hashes within the block
        seen_tx_hashes = set()
        all_txs = list(block.transactions) + list(block.transfer_transactions)
        for tx in all_txs:
            if tx.tx_hash in seen_tx_hashes:
                return False, f"Duplicate transaction {tx.tx_hash.hex()[:16]} in block"
            seen_tx_hashes.add(tx.tx_hash)

        # Check total signature verification cost (sigops-style limit)
        # Each tx signature costs 1, proposer signature costs 1, each attestation costs 1
        import messagechain.config
        sig_cost = len(all_txs) + 1 + len(block.attestations)
        if sig_cost > messagechain.config.MAX_BLOCK_SIG_COST:
            return False, f"Block sig cost {sig_cost} exceeds MAX_BLOCK_SIG_COST {MAX_BLOCK_SIG_COST}"

        # Verify merkle root (includes message + transfer tx hashes)
        tx_hashes = [tx.tx_hash for tx in all_txs]
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

        # Validate all transactions, tracking nonce and balance increments
        # within the block to prevent duplicate-nonce / double-spend attacks.
        pending_nonces: dict[bytes, int] = {}
        pending_balance_spent: dict[bytes, int] = {}
        for tx in block.transactions:
            # Check nonce against chain state + any already-seen txs in this block
            expected_nonce = pending_nonces.get(
                tx.entity_id, self.nonces.get(tx.entity_id, 0)
            )
            if tx.nonce != expected_nonce:
                return False, (
                    f"Invalid tx {tx.tx_hash.hex()[:16]}: "
                    f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"
                )

            # Check cumulative fee spend within this block doesn't exceed spendable balance
            spent_so_far = pending_balance_spent.get(tx.entity_id, 0)
            if self.get_spendable_balance(tx.entity_id) < spent_so_far + tx.fee:
                return False, (
                    f"Invalid tx {tx.tx_hash.hex()[:16]}: "
                    f"Insufficient balance for fee of {tx.fee}"
                )

            # Verify entity is registered and signature is valid
            if tx.entity_id not in self.public_keys:
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: Unknown entity — must register first"
            public_key = self.public_keys[tx.entity_id]
            if not verify_transaction(tx, public_key):
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: Invalid signature"

            if tx.timestamp <= 0:
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: Transaction must have a valid timestamp"

            # Advance pending state for next tx in the same block
            pending_nonces[tx.entity_id] = expected_nonce + 1
            pending_balance_spent[tx.entity_id] = spent_so_far + tx.fee

        # Validate transfer transactions (same nonce/balance tracking)
        for ttx in block.transfer_transactions:
            if ttx.entity_id not in self.public_keys:
                return False, f"Invalid transfer {ttx.tx_hash.hex()[:16]}: Unknown sender"
            if ttx.recipient_id not in self.public_keys:
                return False, f"Invalid transfer {ttx.tx_hash.hex()[:16]}: Unknown recipient"

            expected_nonce = pending_nonces.get(
                ttx.entity_id, self.nonces.get(ttx.entity_id, 0)
            )
            if ttx.nonce != expected_nonce:
                return False, (
                    f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                    f"Invalid nonce: expected {expected_nonce}, got {ttx.nonce}"
                )

            spent_so_far = pending_balance_spent.get(ttx.entity_id, 0)
            if self.get_spendable_balance(ttx.entity_id) < spent_so_far + ttx.amount + ttx.fee:
                return False, (
                    f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                    f"Insufficient balance for transfer of {ttx.amount} + fee {ttx.fee}"
                )

            public_key = self.public_keys[ttx.entity_id]
            if not verify_transfer_transaction(ttx, public_key):
                return False, f"Invalid transfer {ttx.tx_hash.hex()[:16]}: Invalid signature"

            pending_nonces[ttx.entity_id] = expected_nonce + 1
            pending_balance_spent[ttx.entity_id] = spent_so_far + ttx.amount + ttx.fee

        # Validate attestations (votes for the parent block)
        valid, reason = self._validate_attestations(block)
        if not valid:
            return False, reason

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
        # Apply transfer transactions
        for ttx in block.transfer_transactions:
            self.apply_transfer_transaction(ttx, proposer_id)
        # Apply slash transactions — each consumes a WOTS+ leaf from the submitter
        for stx in block.slash_transactions:
            self.supply.pay_fee(stx.submitter_id, proposer_id, stx.fee)
            self.supply.slash_validator(stx.evidence.offender_id, stx.submitter_id)
            self.slashed_validators.add(stx.evidence.offender_id)
            self.slash_sig_counts[stx.submitter_id] = (
                self.slash_sig_counts.get(stx.submitter_id, 0) + 1
            )
        reward = self.supply.mint_block_reward(proposer_id, block.header.block_number)
        # Track immature reward for coinbase maturity enforcement
        self._immature_rewards.append(
            (block.header.block_number, proposer_id, reward)
        )
        # Prune fully-matured rewards to bound memory
        cutoff = block.header.block_number - COINBASE_MATURITY
        self._immature_rewards = [
            (h, eid, amt) for h, eid, amt in self._immature_rewards
            if h > cutoff
        ]
        # Track proposer's block signature count (WOTS+ leaf consumed)
        self.proposer_sig_counts[proposer_id] = (
            self.proposer_sig_counts.get(proposer_id, 0) + 1
        )
        # Track attestation signatures (each consumes a WOTS+ leaf from the validator)
        for att in block.attestations:
            self.attestation_sig_counts[att.validator_id] = (
                self.attestation_sig_counts.get(att.validator_id, 0) + 1
            )
        # Release matured pending unstakes
        self.supply.process_pending_unstakes(block.header.block_number)

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
        # Validate ALL slash transactions BEFORE applying any state changes.
        # This prevents state corruption if a slash tx fails validation
        # partway through (previously, regular tx state was already applied).
        for stx in block.slash_transactions:
            valid, reason = self.validate_slash_transaction(stx)
            if not valid:
                return False, f"Invalid slash tx: {reason}"

        # Apply state changes (single code path for normal + reorg)
        self._apply_block_state(block)
        reward = self.supply.calculate_block_reward(block.header.block_number)

        # Process pending unstakes at this block height
        self.supply.process_pending_unstakes(block.header.block_number)

        # Verify state_root commitment (mandatory for all post-genesis blocks).
        # Every block must commit to the post-application state. A zeroed
        # state_root no longer bypasses validation — this prevents attackers
        # from submitting blocks with fabricated state.
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

        # Process attestations for finality
        self._process_attestations(block, self.supply.staked)

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

        # Finality boundary: refuse to revert finalized blocks
        for blk in rollback_blocks:
            if self.finality.is_finalized(blk.block_hash):
                return False, (
                    f"Reorg rejected — block #{blk.header.block_number} "
                    f"({blk.block_hash.hex()[:16]}) is finalized"
                )

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
        self.attestation_sig_counts = {}
        self.slash_sig_counts = {}
        self.key_rotation_counts = {}
        self.public_keys = {}
        self.slashed_validators = set()
        self._immature_rewards = []

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
            "attestation_sig_counts": dict(self.attestation_sig_counts),
            "slash_sig_counts": dict(self.slash_sig_counts),
            "key_rotation_counts": dict(self.key_rotation_counts),
            "total_supply": self.supply.total_supply,
            "total_minted": self.supply.total_minted,
            "total_fees_collected": self.supply.total_fees_collected,
            "chain_length": len(self.chain),
            "slashed_validators": set(self.slashed_validators),
            "immature_rewards": list(self._immature_rewards),
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
        self.attestation_sig_counts = snapshot.get("attestation_sig_counts", {})
        self.slash_sig_counts = snapshot.get("slash_sig_counts", {})
        self.key_rotation_counts = snapshot.get("key_rotation_counts", {})
        self.slashed_validators = snapshot.get("slashed_validators", set())
        self._immature_rewards = snapshot.get("immature_rewards", [])

    def get_wots_leaves_used(self, entity_id: bytes) -> int:
        """Total WOTS+ leaves consumed by this entity across ALL signature types.

        Counts:
        - Message transaction signatures (nonce tracks these)
        - Block proposer signatures
        - Attestation signatures
        - Slash submission signatures
        - Key rotation signatures (rotation_count tracks these)

        Used to safely advance a keypair past already-used one-time keys
        when reconstructing from a private key (e.g., on server restart).
        """
        return (
            self.nonces.get(entity_id, 0)
            + self.proposer_sig_counts.get(entity_id, 0)
            + self.attestation_sig_counts.get(entity_id, 0)
            + self.slash_sig_counts.get(entity_id, 0)
            + self.key_rotation_counts.get(entity_id, 0)
        )

    def get_entity_stats(self, entity_id: bytes) -> dict:
        return {
            "entity_id": entity_id.hex(),
            "balance": self.supply.get_balance(entity_id),
            "staked": self.supply.get_staked(entity_id),
            "messages_posted": self.entity_message_count.get(entity_id, 0),
            "nonce": self.nonces.get(entity_id, 0),
        }

    def get_recent_messages(self, count: int) -> list[dict]:
        """Get the most recent messages from the chain, newest first."""
        messages = []
        for block in reversed(self.chain):
            for tx in reversed(block.transactions):
                messages.append({
                    "message": tx.message.decode("utf-8", errors="replace"),
                    "entity_id": tx.entity_id.hex(),
                    "timestamp": tx.timestamp,
                    "tx_hash": tx.tx_hash.hex(),
                    "block_number": block.header.block_number,
                })
                if len(messages) >= count:
                    return messages
        return messages

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
