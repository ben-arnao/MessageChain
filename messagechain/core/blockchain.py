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
import time as _time
from messagechain.config import (
    HASH_ALGO, MAX_TXS_PER_BLOCK, MAX_BLOCK_MESSAGE_BYTES,
    VALIDATOR_MIN_STAKE, GENESIS_ALLOCATION,
    MAX_BLOCK_SIG_COST, COINBASE_MATURITY, MTP_BLOCK_COUNT,
    DUST_LIMIT, MAX_ORPHAN_BLOCKS, ASSUME_VALID_BLOCK_HASH,
    MIN_FEE, MAX_TIMESTAMP_DRIFT, KEY_ROTATION_FEE, BASE_FEE_INITIAL,
)
from messagechain.core.block import Block, compute_merkle_root, compute_state_root, create_genesis_block
from messagechain.core.state_tree import SparseMerkleTree
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
from messagechain.crypto.sig_cache import get_global_cache
from messagechain.consensus.fork_choice import (
    ForkChoice, compute_block_stake_weight, find_fork_point, MAX_REORG_DEPTH,
)

logger = logging.getLogger(__name__)


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def compute_block_sig_cost(block) -> int:
    """Compute the total signature verification cost for a block.

    Each transaction sig, transfer sig, slash sig, proposer sig, and
    attestation sig costs 1 verification. This budget prevents DoS via
    blocks stuffed with expensive WOTS+ signature verifications.
    """
    return (
        len(block.transactions)
        + len(block.transfer_transactions)
        + len(block.slash_transactions)
        + 1  # proposer signature
        + len(block.attestations)
    )


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
        self.base_fee: int = self.supply.base_fee  # mirror for easy access
        self.nonces: dict[bytes, int] = {}  # entity_id -> next expected nonce
        self.public_keys: dict[bytes, bytes] = {}  # entity_id -> public_key
        self.entity_message_count: dict[bytes, int] = {}
        self.key_rotation_counts: dict[bytes, int] = {}  # entity_id -> rotation number
        self.proposer_sig_counts: dict[bytes, int] = {}  # entity_id -> block signatures made
        self.attestation_sig_counts: dict[bytes, int] = {}  # entity_id -> attestation signatures made
        self.slash_sig_counts: dict[bytes, int] = {}  # entity_id -> slash submission signatures made
        self.slashed_validators: set[bytes] = set()  # entity IDs that have been slashed
        self._processed_evidence: set[bytes] = set()  # evidence hashes already applied
        self.fork_choice = ForkChoice()
        self.finality = FinalityTracker()
        self._block_by_hash: dict[bytes, Block] = {}  # in-memory block index
        # Per-block stake snapshots. Maps block_number -> {validator_id: stake}
        # as of the END of that block. Used when processing attestations
        # (which vote for block N-1 but arrive bundled in block N) so the
        # 2/3 finality denominator is pinned to the stake set that existed
        # at the attestation's target block, not the post-churn live set.
        # Bounded to the last STAKE_SNAPSHOT_RETENTION blocks to cap memory.
        self._stake_snapshots: dict[int, dict[bytes, int]] = {}
        self._stake_snapshot_retention: int = 1024
        # Incremental state commitment. Kept in sync with supply.balances,
        # supply.staked, and self.nonces via _touch_state. O(TREE_DEPTH)
        # per update vs the O(N log N) full-rebuild compute_state_root was
        # doing, so block proposal / validation is independent of total
        # account count.
        self.state_tree: SparseMerkleTree = SparseMerkleTree()
        # Immature block rewards: list of (block_height, proposer_id, reward_amount)
        self._immature_rewards: list[tuple[int, bytes, int]] = []
        # Orphan block pool: blocks whose parent is not yet known (bounded)
        self.orphan_pool: dict[bytes, Block] = {}  # block_hash -> Block
        # Signature verification cache (invalidated on reorg)
        self.sig_cache = get_global_cache()
        # AssumeValid: skip signature verification for blocks at or below this hash
        self.assume_valid_hash: bytes | None = ASSUME_VALID_BLOCK_HASH
        self._assume_valid_height: int | None = None

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
        self.supply.total_burned = self.db.get_supply_meta("total_burned") or 0
        stored_base_fee = self.db.get_supply_meta("base_fee")
        if stored_base_fee is not None:
            self.supply.base_fee = stored_base_fee
            self.base_fee = stored_base_fee

        # Restore proposer signature counts (for WOTS+ leaf tracking)
        if hasattr(self.db, 'get_all_proposer_sig_counts'):
            self.proposer_sig_counts = self.db.get_all_proposer_sig_counts()

        # Restore slashed validators
        if hasattr(self.db, 'get_all_slashed'):
            self.slashed_validators = self.db.get_all_slashed()

        # Restore processed-evidence set so a restart cannot re-apply an
        # already-consumed slashing evidence transaction (which would let
        # a validator be slashed twice for the same offence).
        if hasattr(self.db, 'get_all_processed_evidence'):
            self._processed_evidence = self.db.get_all_processed_evidence()

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

        # Pin a single stake snapshot at the loaded tip so ongoing
        # finality processing after load has a correct denominator for
        # the next block's attestations. We can't reconstruct full
        # historical snapshots from a cold load, but the tip's snapshot
        # is all the next block needs.
        if self.chain:
            self._record_stake_snapshot(self.chain[-1].header.block_number)

        # Rebuild the incremental state tree from the loaded dicts so
        # that subsequent compute_current_state_root calls return the
        # right commitment without a full rebuild on every block.
        self._rebuild_state_tree()

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
            self.db.set_supply_meta("total_burned", self.supply.total_burned)
            self.db.set_supply_meta("base_fee", self.supply.base_fee)
            # Persist slashed validators
            if hasattr(self.db, 'add_slashed_validator'):
                for eid in self.slashed_validators:
                    self.db.add_slashed_validator(eid, self.height, b"")
            # Persist processed evidence hashes so they cannot be re-applied
            # after a restart.
            if hasattr(self.db, 'mark_evidence_processed'):
                for ev_hash in self._processed_evidence:
                    self.db.mark_evidence_processed(ev_hash, self.height)
            self.db.commit_transaction()
        except Exception:
            self.db.rollback_transaction()
            raise

    def initialize_genesis(
        self,
        genesis_entity,
        allocation_table: dict[bytes, int] | None = None,
    ) -> Block:
        """Create the genesis block and initialize chain state.

        Args:
            genesis_entity: The entity that signs the genesis block.
            allocation_table: Optional mapping of entity_id -> token amount.
                If provided, tokens are distributed per the table. If None,
                the genesis entity receives GENESIS_ALLOCATION (backward compat).
        """
        # Validate allocation table if provided
        if allocation_table is not None:
            for entity_id, amount in allocation_table.items():
                if amount <= 0:
                    raise ValueError(
                        f"Allocation must be positive, got {amount} "
                        f"for entity {entity_id.hex()[:16]}..."
                    )
            total_allocated = sum(allocation_table.values())
            if total_allocated > self.supply.total_supply:
                raise ValueError(
                    f"Allocation total ({total_allocated}) exceeds "
                    f"genesis supply ({self.supply.total_supply})"
                )

        genesis_block = create_genesis_block(genesis_entity)
        self.chain.append(genesis_block)
        self._block_by_hash[genesis_block.block_hash] = genesis_block

        # Register genesis entity
        self.public_keys[genesis_entity.entity_id] = genesis_entity.public_key
        self.nonces[genesis_entity.entity_id] = 0
        # Genesis block was signed — track the WOTS+ leaf consumed
        self.proposer_sig_counts[genesis_entity.entity_id] = 1

        # Distribute genesis allocation
        if allocation_table is not None:
            for entity_id, amount in allocation_table.items():
                self.supply.balances[entity_id] = (
                    self.supply.balances.get(entity_id, 0) + amount
                )
        else:
            # Backward-compatible single-entity allocation
            self.supply.balances[genesis_entity.entity_id] = GENESIS_ALLOCATION

        # Track as chain tip
        self.fork_choice.add_tip(genesis_block.block_hash, 0, 0)

        # Pin stake snapshot at genesis so the first post-genesis block's
        # attestations (which vote for block 0) can consult it.
        self._record_stake_snapshot(0)

        # Seed the incremental state tree with the initial allocation.
        # After this, every add_block uses O(K * TREE_DEPTH) incremental
        # updates instead of a full rebuild.
        self._rebuild_state_tree()

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
        # L4: Validate entity_id is correct length (SHA3-256 = 32 bytes)
        if len(entity_id) != 32:
            return False, f"Entity ID must be 32 bytes, got {len(entity_id)}"

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

    def sync_consensus_stakes(self, consensus: "ProofOfStake", block_height: int | None = None):
        """Populate consensus.stakes from the supply tracker's staked amounts.

        Must be called after loading from DB so that the consensus module
        has accurate stake data (prevents falling into permissive bootstrap mode).
        """
        from messagechain.consensus.pos import graduated_min_stake
        height = block_height if block_height is not None else self.height
        min_stake = graduated_min_stake(height)
        for entity_id, amount in self.supply.staked.items():
            if amount >= min_stake:
                consensus.stakes[entity_id] = amount

    def get_latest_block(self) -> Block | None:
        return self.chain[-1] if self.chain else None

    def _selected_proposer_for_slot(
        self, parent: Block, round_number: int
    ) -> bytes | None:
        """Compute the selected proposer for the slot after `parent` at
        round `round_number`, using the chain's own supply.staked as the
        authoritative stake state.

        Returns None when no validator meets the graduated minimum stake
        — that indicates bootstrap mode, and validate_block skips the
        proposer-match check so any registered entity may propose.

        This mirrors ProofOfStake.select_proposer but lives on Blockchain
        so validate_block can enforce proposer correctness without taking
        a consensus parameter. Keeping it here is a small duplication,
        but the upside is that consensus and validate_block agree on the
        selection algorithm byte-for-byte.
        """
        import struct
        from messagechain.consensus.pos import graduated_min_stake

        height = parent.header.block_number + 1
        min_stake = graduated_min_stake(height)
        # Slashed validators already have staked[eid] = 0, so the
        # min_stake filter excludes them implicitly.
        stakes = {
            eid: amt
            for eid, amt in self.supply.staked.items()
            if amt >= min_stake
        }
        if not stakes:
            return None  # bootstrap mode — no enforcement

        validators = sorted(stakes.items(), key=lambda x: x[0])
        total = sum(s for _, s in validators)
        if total == 0:
            return None

        seed_input = (
            parent.block_hash
            + parent.header.randao_mix
            + struct.pack(">I", round_number)
            + b"proposer_selection"
        )
        seed = _hash(seed_input)
        rand_value = int.from_bytes(seed, "big") % total

        cumulative = 0
        for entity_id, stake in validators:
            cumulative += stake
            if rand_value < cumulative:
                return entity_id
        return validators[-1][0]

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

        # Dust limit: reject transfers below minimum to prevent state bloat
        if tx.amount < DUST_LIMIT:
            return False, f"Transfer amount {tx.amount} below dust limit {DUST_LIMIT}"

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

        # Reject rotation to a public key already used by another entity
        for eid, pk in self.public_keys.items():
            if pk == tx.new_public_key and eid != tx.entity_id:
                return False, "New public key already registered to another entity"

        current_pk = self.public_keys[tx.entity_id]

        expected_rotation = self.key_rotation_counts.get(tx.entity_id, 0)
        if tx.rotation_number != expected_rotation:
            return False, f"Invalid rotation number: expected {expected_rotation}, got {tx.rotation_number}"

        if tx.fee < KEY_ROTATION_FEE:
            return False, f"Key rotation fee must be at least {KEY_ROTATION_FEE}, got {tx.fee}"

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

        # Pay fee with burn (same as all other tx types — base fee burned, tip to proposer)
        self.supply.pay_fee_with_burn(tx.entity_id, proposer_id, tx.fee, self.supply.base_fee)

        # Update the entity's public key
        self.public_keys[tx.entity_id] = tx.new_public_key
        self.key_rotation_counts[tx.entity_id] = tx.rotation_number + 1

        # Persist
        if self.db is not None:
            self.db.set_public_key(tx.entity_id, tx.new_public_key)
            self.db.flush_state()

        return True, "Key rotated successfully"

    def validate_slash_transaction(
        self, tx: SlashTransaction, chain_height: int | None = None,
    ) -> tuple[bool, str]:
        """Validate a slash transaction against current chain state."""
        if tx.submitter_id not in self.public_keys:
            return False, "Unknown submitter — must register first"

        if tx.evidence.offender_id not in self.public_keys:
            return False, "Unknown offender"

        if tx.evidence.offender_id in self.slashed_validators:
            return False, "Validator already slashed"

        # M8: Reject duplicate evidence submissions
        if tx.evidence.evidence_hash in self._processed_evidence:
            return False, "Evidence already submitted"

        if self.supply.get_staked(tx.evidence.offender_id) == 0:
            return False, "Offender has no stake to slash"

        if not self.supply.can_afford_fee(tx.submitter_id, tx.fee):
            return False, "Submitter cannot afford fee"

        # H6: Reject expired evidence. Evidence older than UNBONDING_PERIOD
        # is stale — the offender may have already unstaked and exited.
        # This prevents ancient evidence from being weaponized.
        from messagechain.config import UNBONDING_PERIOD
        height = chain_height if chain_height is not None else self.height
        evidence_height = self._evidence_block_number(tx.evidence)
        if evidence_height is not None and height - evidence_height > UNBONDING_PERIOD:
            return False, "Evidence expired — older than unbonding period"

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

    @staticmethod
    def _evidence_block_number(evidence) -> int | None:
        """Extract the block height from slashing evidence.

        Returns the block_number the conflicting headers/attestations
        reference, or None if the evidence type is unrecognized.
        """
        if hasattr(evidence, 'header_a'):
            return evidence.header_a.block_number
        if hasattr(evidence, 'attestation_a'):
            return evidence.attestation_a.block_number
        return None

    def apply_slash_transaction(self, tx: SlashTransaction, proposer_id: bytes) -> tuple[bool, str]:
        """Validate and apply a slash transaction."""
        valid, reason = self.validate_slash_transaction(tx)
        if not valid:
            return False, reason

        # Pay fee with burn (same as all other tx types — base fee burned, tip to proposer)
        self.supply.pay_fee_with_burn(tx.submitter_id, proposer_id, tx.fee, self.supply.base_fee)

        # Slash the offender
        slashed, finder_reward = self.supply.slash_validator(
            tx.evidence.offender_id, tx.submitter_id
        )
        self.slashed_validators.add(tx.evidence.offender_id)
        self._processed_evidence.add(tx.evidence.evidence_hash)

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
        """Get spendable balance (total balance minus immature rewards).

        Floor at 0 — immature tracking corruption must never produce a
        negative spendable balance that could be misinterpreted as a
        large positive value by callers expecting unsigned semantics.
        """
        total = self.supply.get_balance(entity_id)
        immature = self.get_immature_balance(entity_id)
        return max(0, total - immature)

    def _touch_state(self, entity_ids):
        """Sync the state tree with current dicts for the given entities.

        Called whenever code mutates supply.balances / supply.staked /
        nonces. Cheap — O(len(entity_ids) * TREE_DEPTH). The SMT is
        the authoritative state commitment, but the balance/nonce/stake
        dicts remain the source of truth for *values* — the tree just
        commits to them.
        """
        for eid in entity_ids:
            self.state_tree.set(
                eid,
                self.supply.balances.get(eid, 0),
                self.nonces.get(eid, 0),
                self.supply.staked.get(eid, 0),
            )

    def _rebuild_state_tree(self):
        """Synchronize the state tree with the live balance/nonce/stake dicts.

        Reuses the existing tree where possible — SparseMerkleTree.set()
        is a no-op when called with the same triple, so entities that
        haven't changed cost only a dict-lookup plus an integer compare.
        The expensive O(TREE_DEPTH) path-rehash only fires on actual
        changes. That makes steady-state re-sync O(N_accounts) dict
        operations plus O(changes * TREE_DEPTH) hashes — orders of
        magnitude cheaper than the naive "build a fresh tree from
        scratch" approach, which pays the full path-rehash cost for
        every leaf.

        Called from:
          * initialize_genesis (cold start — full population)
          * _load_from_db (cold start)
          * compute_current_state_root (warm path, reuses cached nodes)
          * reorg rollback (hot path, many changes)
        """
        live_keys = set(self.supply.balances) | set(self.nonces) | set(self.supply.staked)
        # Drop entries the tree holds that have been deleted from live.
        tree_keys = set(self.state_tree._accounts.keys())
        for eid in tree_keys - live_keys:
            self.state_tree.remove(eid)
        # Upsert everything else; set() is idempotent on unchanged triples.
        for eid in live_keys:
            self.state_tree.set(
                eid,
                self.supply.balances.get(eid, 0),
                self.nonces.get(eid, 0),
                self.supply.staked.get(eid, 0),
            )

    def compute_current_state_root(self) -> bytes:
        """Return the Merkle commitment to the current account state.

        Resyncs the SparseMerkleTree with the live balance/nonce/stake
        dicts before returning its root. The resync is cheap for
        unchanged entries (SMT.set() is idempotent) so the steady-state
        cost is O(N) dict lookups + O(changes * TREE_DEPTH) hash ops —
        a big improvement over the old flat-Merkle full rebuild, which
        paid O(N log N) in hash operations regardless of change rate.

        The resync-per-call design keeps correctness robust against
        call sites that mutate the underlying dicts directly (tests,
        reorg rollback, governance). A stricter incremental design
        that trusts the tree without resync is a follow-up, gated on
        auditing every mutation path through a single `_touch_state`
        hook.
        """
        self._rebuild_state_tree()
        return self.state_tree.root()

    def compute_post_state_root(
        self,
        transactions: list[MessageTransaction],
        proposer_id: bytes,
        block_height: int,
        transfer_transactions: list[TransferTransaction] | None = None,
        attestations: list[Attestation] | None = None,
    ) -> bytes:
        """Compute the state root AFTER applying a set of transactions.

        Used by block proposers to compute the correct post-state commitment
        without actually mutating chain state. The block header commits to
        the post-application state so validators can verify consistency.
        """
        from messagechain.config import (
            PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR,
            PROPOSER_REWARD_CAP, TREASURY_ENTITY_ID,
        )
        sim_balances = dict(self.supply.balances)
        sim_nonces = dict(self.nonces)
        sim_staked = dict(self.supply.staked)
        current_base_fee = self.supply.base_fee

        # Simulate fee payments for message transactions (with burn)
        for tx in transactions:
            # M1/M2: Clamp tip to >= 0 to prevent negative balances
            effective_base_fee = min(current_base_fee, tx.fee)
            tip = tx.fee - effective_base_fee
            sim_balances[tx.entity_id] = sim_balances.get(tx.entity_id, 0) - tx.fee
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
            # base_fee is burned — not added to any balance
            sim_nonces[tx.entity_id] = tx.nonce + 1

        # Simulate transfer transactions (with burn)
        for ttx in (transfer_transactions or []):
            effective_base_fee = min(current_base_fee, ttx.fee)
            tip = ttx.fee - effective_base_fee
            sim_balances[ttx.entity_id] = sim_balances.get(ttx.entity_id, 0) - ttx.amount - ttx.fee
            sim_balances[ttx.recipient_id] = sim_balances.get(ttx.recipient_id, 0) + ttx.amount
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
            sim_nonces[ttx.entity_id] = ttx.nonce + 1

        # Simulate block reward with attestation split and reward cap
        reward = self.supply.calculate_block_reward(block_height)
        is_bootstrap = not any(s > 0 for s in sim_staked.values())
        effective_cap = reward if is_bootstrap else PROPOSER_REWARD_CAP

        attestor_stakes = {}
        if attestations:
            for att in attestations:
                stake = sim_staked.get(att.validator_id, 0)
                if stake > 0:
                    attestor_stakes[att.validator_id] = stake

        if attestor_stakes:
            proposer_share = reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
            attestor_pool = reward - proposer_share
            total_att_stake = sum(attestor_stakes.values())
            sorted_atts = sorted(attestor_stakes.items(), key=lambda x: x[0])
            attestor_rewards = {}
            distributed = 0
            for i, (att_id, stake) in enumerate(sorted_atts):
                if i == len(sorted_atts) - 1:
                    att_reward = attestor_pool - distributed
                else:
                    att_reward = attestor_pool * stake // total_att_stake
                attestor_rewards[att_id] = att_reward
                sim_balances[att_id] = sim_balances.get(att_id, 0) + att_reward
                distributed += att_reward

            # Apply reward cap to proposer. Must mirror mint_block_reward's
            # claw-back path exactly, otherwise the committed state_root
            # diverges from the actual post-application state. The claw-back
            # removes the proposer's attestor share from their balance, then
            # credits them the full effective_cap as proposer_share. The
            # earlier simpler formulation (leave the attestor share in place
            # and reduce proposer_share) produced different sim_balances
            # when proposer == attestor.
            proposer_att_reward = attestor_rewards.get(proposer_id, 0)
            proposer_total = proposer_share + proposer_att_reward
            if proposer_total > effective_cap:
                treasury_excess = proposer_total - effective_cap
                sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) - proposer_att_reward
                proposer_share = effective_cap
                sim_balances[TREASURY_ENTITY_ID] = sim_balances.get(TREASURY_ENTITY_ID, 0) + treasury_excess

            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + proposer_share
        else:
            # No attestors — apply cap
            proposer_reward = min(reward, effective_cap)
            treasury_excess = reward - proposer_reward
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + proposer_reward
            if treasury_excess > 0:
                sim_balances[TREASURY_ENTITY_ID] = sim_balances.get(TREASURY_ENTITY_ID, 0) + treasury_excess

        return compute_state_root(sim_balances, sim_nonces, sim_staked)

    def propose_block(
        self,
        consensus: "ProofOfStake",
        proposer_entity,
        transactions: list[MessageTransaction],
        attestations: list[Attestation] | None = None,
        transfer_transactions: list[TransferTransaction] | None = None,
        slash_transactions: list | None = None,
    ) -> Block:
        """Create a block with the correct post-state root.

        Convenience method that computes the state root automatically,
        ensuring every block commits to the correct post-application state.

        Chooses a timestamp strictly greater than the current Median Time
        Past, as required by the BIP 113 check in validate_block. This
        prevents a race on fast machines where the proposer's wall-clock
        `time.time()` happens to equal the MTP (particularly when blocks
        are produced rapidly in tests), which would otherwise make the
        freshly-signed block fail its own validation.
        """
        prev = self.get_latest_block()
        block_height = prev.header.block_number + 1
        state_root = self.compute_post_state_root(
            transactions, proposer_entity.entity_id, block_height,
            transfer_transactions=transfer_transactions,
            attestations=attestations,
        )
        mtp = self.get_median_time_past()
        # A small epsilon greater than the minimum float resolution the
        # timestamp will be serialized at. Microsecond granularity is
        # plenty — real block production is on the order of seconds.
        now = _time.time()
        timestamp = now if now > mtp else mtp + 1e-6
        return consensus.create_block(
            proposer_entity, transactions, prev,
            state_root=state_root, attestations=attestations,
            transfer_transactions=transfer_transactions,
            slash_transactions=slash_transactions,
            timestamp=timestamp,
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

        Attestations in block N vote for block N-1. The 2/3 check must use
        the stake map pinned at the END of block N-1, not the live stake
        that already reflects block N's transactions. Without pinning,
        validator churn between N-1 and N corrupts both the numerator
        (ghost stake still counted) and the denominator (validators who
        unstaked make the threshold artificially easier or harder to hit).
        We consult _stake_snapshots[N-1] and fall back to `stakes` only
        when no snapshot is available (bootstrap / loaded-from-db edge).
        """
        for att in block.attestations:
            target_block = att.block_number
            pinned = self._stake_snapshots.get(target_block)
            if pinned is not None:
                stakes_for_att = pinned
            else:
                stakes_for_att = stakes
            validator_stake = stakes_for_att.get(att.validator_id, 0)
            total_stake = sum(stakes_for_att.values())
            justified = self.finality.add_attestation(att, validator_stake, total_stake)
            if justified:
                logger.info(
                    f"FINALIZED: block #{att.block_number} ({att.block_hash.hex()[:16]}) "
                    f"reached 2/3+ attestation threshold"
                )

    def _record_stake_snapshot(self, block_number: int):
        """Pin the current stake map for a block. See _process_attestations."""
        self._stake_snapshots[block_number] = dict(self.supply.staked)
        # Prune old snapshots past retention window
        if len(self._stake_snapshots) > self._stake_snapshot_retention:
            cutoff = block_number - self._stake_snapshot_retention
            stale = [n for n in self._stake_snapshots if n < cutoff]
            for n in stale:
                del self._stake_snapshots[n]

    def validate_block(self, block: Block) -> tuple[bool, str]:
        """Validate a block before adding it to the chain."""
        latest = self.get_latest_block()
        if latest is None:
            return False, "No genesis block"

        # Block version must be a known protocol version
        if block.header.version != 1:
            return False, f"Unknown block version {block.header.version}"

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

        # L1: Reject blocks with timestamps too far in the future (BTC: 2 hours)
        max_future = _time.time() + 7200
        if block.header.timestamp > max_future:
            return False, f"Block timestamp {block.header.timestamp} too far in the future"

        # Check transaction count (all types combined)
        total_tx_count = len(block.transactions) + len(block.transfer_transactions)
        if total_tx_count > MAX_TXS_PER_BLOCK:
            return False, "Too many transactions"

        # Check block message byte budget — limits total message payload per block.
        # This creates a secondary constraint: large messages compete for limited
        # byte space even when the tx count is under the cap.
        total_message_bytes = sum(len(tx.message) for tx in block.transactions)
        if total_message_bytes > MAX_BLOCK_MESSAGE_BYTES:
            return False, f"Block message bytes {total_message_bytes} exceed budget {MAX_BLOCK_MESSAGE_BYTES}"

        # Check for duplicate transaction hashes within the block
        seen_tx_hashes = set()
        all_txs = list(block.transactions) + list(block.transfer_transactions)
        for tx in all_txs:
            if tx.tx_hash in seen_tx_hashes:
                return False, f"Duplicate transaction {tx.tx_hash.hex()[:16]} in block"
            seen_tx_hashes.add(tx.tx_hash)

        # Check total signature verification cost (sigops-style limit)
        # Counts all tx sigs + proposer sig + attestation sigs + slash sigs
        import messagechain.config
        sig_cost = compute_block_sig_cost(block)
        if sig_cost > messagechain.config.MAX_BLOCK_SIG_COST:
            return False, f"Block sig cost {sig_cost} exceeds MAX_BLOCK_SIG_COST {messagechain.config.MAX_BLOCK_SIG_COST}"

        # Verify merkle root. Includes message txs, transfer txs, AND
        # slash txs — committing slash txs cryptographically prevents a
        # byzantine relayer from stripping them in transit (previously a
        # real gap: slash_transactions lived outside merkle_root).
        tx_hashes = (
            [tx.tx_hash for tx in all_txs]
            + [tx.tx_hash for tx in block.slash_transactions]
        )
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

        # Verify randao_mix is correctly derived from the parent's mix and
        # this block's proposer signature. This binds the mix to the
        # signature, so a malicious proposer cannot supply an arbitrary mix.
        from messagechain.consensus.randao import derive_randao_mix
        expected_mix = derive_randao_mix(
            latest.header.randao_mix, block.header.proposer_signature
        )
        if block.header.randao_mix != expected_mix:
            return False, "Invalid randao_mix"

        # Strict proposer enforcement: outside bootstrap mode, the block's
        # proposer_id must match the deterministically-selected proposer
        # for the slot+round indicated by the block's timestamp.
        #
        # Without this check, any registered validator could claim to be
        # the proposer for any slot — stealing block rewards, censoring
        # honest proposers via race conditions, and defeating the round-
        # rotation liveness fix. See commit message of the block-production
        # fix for background.
        import messagechain.config as _cfg
        from messagechain.config import BLOCK_TIME_TARGET
        selected_round_0 = self._selected_proposer_for_slot(latest, round_number=0)
        if selected_round_0 is not None:
            # Post-bootstrap: compute which round the block claims to be for,
            # based on its timestamp gap from the parent.
            ts_gap = block.header.timestamp - latest.header.timestamp
            if ts_gap < BLOCK_TIME_TARGET:
                # Block produced before the next slot window opens.
                # In strict mode this is illegal; in tests the round is
                # simply pinned to 0 so the proposer match still enforces.
                if _cfg.ENFORCE_SLOT_TIMING:
                    return False, (
                        f"Block timestamp too early: gap {ts_gap:.0f}s "
                        f"< BLOCK_TIME_TARGET {BLOCK_TIME_TARGET}s"
                    )
                round_number = 0
            else:
                round_number = int((ts_gap - BLOCK_TIME_TARGET) // BLOCK_TIME_TARGET)

            expected_proposer = self._selected_proposer_for_slot(latest, round_number)
            if expected_proposer != block.header.proposer_id:
                return False, (
                    f"Wrong proposer for slot "
                    f"(round {round_number}, expected "
                    f"{expected_proposer.hex()[:16] if expected_proposer else 'None'}, "
                    f"got {block.header.proposer_id.hex()[:16]})"
                )

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
            # L3: Enforce timestamp drift for txs within blocks (not just standalone)
            if tx.timestamp > _time.time() + MAX_TIMESTAMP_DRIFT:
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: Timestamp too far in future"

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

        # H7: Validate slash transactions during validate_block so blocks
        # with invalid evidence are rejected before relay/storage, not just
        # during _append_block. This prevents propagation of blocks with
        # fabricated slash evidence across the network.
        for stx in block.slash_transactions:
            valid, reason = self.validate_slash_transaction(stx)
            if not valid:
                return False, f"Invalid slash tx: {reason}"

        return True, "Valid"

    def validate_block_standalone(self, block: Block, parent: Block) -> tuple[bool, str]:
        """Validate a block against a specific parent (for fork validation).

        Performs full structural and cryptographic validation — same checks
        as validate_block but against an explicit parent rather than the
        current chain tip. This prevents forged blocks from being stored
        as valid fork tips.
        """
        if block.header.prev_hash != parent.block_hash:
            return False, "Invalid prev_hash"
        if block.header.block_number != parent.header.block_number + 1:
            return False, "Invalid block number"

        # Block version must be known
        if block.header.version != 1:
            return False, f"Unknown block version {block.header.version}"

        total_tx_count = len(block.transactions) + len(block.transfer_transactions)
        if total_tx_count > MAX_TXS_PER_BLOCK:
            return False, "Too many transactions"
        total_message_bytes = sum(len(tx.message) for tx in block.transactions)
        if total_message_bytes > MAX_BLOCK_MESSAGE_BYTES:
            return False, f"Block message bytes {total_message_bytes} exceed budget {MAX_BLOCK_MESSAGE_BYTES}"

        # Timestamp checks
        if block.header.timestamp <= parent.header.timestamp:
            return False, "Block timestamp must exceed parent timestamp"
        max_future = _time.time() + 7200
        if block.header.timestamp > max_future:
            return False, "Block timestamp too far in the future"

        # Duplicate tx check
        seen_tx_hashes = set()
        all_txs = list(block.transactions) + list(block.transfer_transactions)
        for tx in all_txs:
            if tx.tx_hash in seen_tx_hashes:
                return False, f"Duplicate transaction {tx.tx_hash.hex()[:16]} in block"
            seen_tx_hashes.add(tx.tx_hash)

        # Sig cost budget
        import messagechain.config
        sig_cost = compute_block_sig_cost(block)
        if sig_cost > messagechain.config.MAX_BLOCK_SIG_COST:
            return False, f"Block sig cost {sig_cost} exceeds limit"

        # Merkle root
        tx_hashes = (
            [tx.tx_hash for tx in all_txs]
            + [tx.tx_hash for tx in block.slash_transactions]
        )
        expected_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")
        if block.header.merkle_root != expected_root:
            return False, "Invalid merkle root"

        # Proposer signature (mandatory)
        if block.header.proposer_id not in self.public_keys:
            return False, "Unknown proposer"
        if block.header.proposer_signature is None:
            return False, "Missing proposer signature"
        proposer_pk = self.public_keys[block.header.proposer_id]
        header_hash = _hash(block.header.signable_data())
        if not verify_signature(header_hash, block.header.proposer_signature, proposer_pk):
            return False, "Invalid proposer signature"

        # RANDAO mix
        from messagechain.consensus.randao import derive_randao_mix
        expected_mix = derive_randao_mix(
            parent.header.randao_mix, block.header.proposer_signature
        )
        if block.header.randao_mix != expected_mix:
            return False, "Invalid randao_mix"

        # Validate transaction signatures
        for tx in block.transactions:
            if tx.entity_id not in self.public_keys:
                return False, f"Unknown entity in tx {tx.tx_hash.hex()[:16]}"
            pk = self.public_keys[tx.entity_id]
            from messagechain.core.transaction import verify_transaction
            if not verify_transaction(tx, pk):
                return False, f"Invalid signature in tx {tx.tx_hash.hex()[:16]}"

        for ttx in block.transfer_transactions:
            if ttx.entity_id not in self.public_keys:
                return False, f"Unknown sender in transfer {ttx.tx_hash.hex()[:16]}"
            pk = self.public_keys[ttx.entity_id]
            if not verify_transfer_transaction(ttx, pk):
                return False, f"Invalid signature in transfer {ttx.tx_hash.hex()[:16]}"

        return True, "Valid"

    def _apply_transfer_with_burn(self, tx, proposer_id: bytes, base_fee: int):
        """Apply a transfer transaction with EIP-1559 fee burning."""
        # M1: Clamp base_fee to the actual fee to prevent negative tip
        effective_base_fee = min(base_fee, tx.fee)
        tip = tx.fee - effective_base_fee
        self.supply.balances[tx.entity_id] = self.supply.get_balance(tx.entity_id) - tx.amount - tx.fee
        self.supply.balances[tx.recipient_id] = self.supply.get_balance(tx.recipient_id) + tx.amount
        self.supply.balances[proposer_id] = self.supply.get_balance(proposer_id) + tip
        self.supply.total_supply -= effective_base_fee  # burn
        self.supply.total_burned += effective_base_fee
        self.supply.total_fees_collected += tx.fee
        self.nonces[tx.entity_id] = tx.nonce + 1

    def _block_affected_entities(self, block: Block) -> set[bytes]:
        """Collect every entity_id whose balance/nonce/stake a block might touch.

        Used after _apply_block_state to incrementally refresh only the
        affected rows in state_tree, keeping the commitment update cost
        O(touched * TREE_DEPTH) rather than O(N * TREE_DEPTH).

        Includes:
          * the proposer (block reward, fees)
          * every tx sender (nonce + balance)
          * every transfer recipient (balance)
          * every attestor (attestation reward)
          * every slashed validator (stake zeroed)
          * every slash submitter (finder's reward)
          * TREASURY_ENTITY_ID (reward-cap overflow)
        """
        from messagechain.config import TREASURY_ENTITY_ID
        affected: set[bytes] = {block.header.proposer_id, TREASURY_ENTITY_ID}
        for tx in block.transactions:
            affected.add(tx.entity_id)
        for ttx in block.transfer_transactions:
            affected.add(ttx.entity_id)
            affected.add(ttx.recipient_id)
        for stx in block.slash_transactions:
            affected.add(stx.evidence.offender_id)
            affected.add(stx.submitter_id)
        for att in block.attestations:
            affected.add(att.validator_id)
        return affected

    def _apply_block_state(self, block: Block):
        """Apply a block's state changes (fees, nonces, rewards) without validation."""
        proposer_id = block.header.proposer_id
        current_base_fee = self.supply.base_fee

        # Count total txs for base fee adjustment
        total_tx_count = len(block.transactions) + len(block.transfer_transactions)

        # Apply message transaction fees (EIP-1559: burn base fee, tip to proposer)
        for tx in block.transactions:
            self.supply.pay_fee_with_burn(tx.entity_id, proposer_id, tx.fee, current_base_fee)
            self.nonces[tx.entity_id] = tx.nonce + 1
            self.entity_message_count[tx.entity_id] = (
                self.entity_message_count.get(tx.entity_id, 0) + 1
            )
        # Apply transfer transactions (also with burn)
        for ttx in block.transfer_transactions:
            self._apply_transfer_with_burn(ttx, proposer_id, current_base_fee)
        # Apply slash transactions
        for stx in block.slash_transactions:
            self.supply.pay_fee_with_burn(stx.submitter_id, proposer_id, stx.fee, current_base_fee)
            self.supply.slash_validator(stx.evidence.offender_id, stx.submitter_id)
            self.slashed_validators.add(stx.evidence.offender_id)
            self.slash_sig_counts[stx.submitter_id] = (
                self.slash_sig_counts.get(stx.submitter_id, 0) + 1
            )

        # Build attestor stakes map for reward distribution
        attestor_stakes = {}
        for att in block.attestations:
            stake = self.supply.get_staked(att.validator_id)
            if stake > 0:
                attestor_stakes[att.validator_id] = stake

        # Bootstrap mode: no validators have staked yet
        is_bootstrap = not any(s > 0 for s in self.supply.staked.values())

        # Mint block reward split between proposer and attestors
        result = self.supply.mint_block_reward(
            proposer_id, block.header.block_number,
            attestor_stakes=attestor_stakes,
            bootstrap=is_bootstrap,
        )

        # Track immature rewards for ALL recipients (proposer + attestors)
        self._immature_rewards.append(
            (block.header.block_number, proposer_id, result["proposer_reward"])
        )
        for att_id, att_reward in result["attestor_rewards"].items():
            if att_reward > 0:
                self._immature_rewards.append(
                    (block.header.block_number, att_id, att_reward)
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

        # Update base fee for next block based on this block's fullness
        self.supply.update_base_fee(total_tx_count)
        self.base_fee = self.supply.base_fee

    def add_block(self, block: Block) -> tuple[bool, str]:
        """Validate and append a block, updating state (fees + inflation)."""
        if self.height == 0:
            # Validate genesis block structure
            if block.header.block_number != 0:
                return False, f"First block must be block 0, got {block.header.block_number}"
            if block.header.prev_hash != b"\x00" * 32:
                return False, "Genesis block must have zero prev_hash"
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

        # Orphan block — parent unknown. Pre-validate structure before storing
        # to prevent attackers from filling the pool with garbage blocks.
        import messagechain.config
        sig_cost = compute_block_sig_cost(block)
        if sig_cost > messagechain.config.MAX_BLOCK_SIG_COST:
            return False, f"Orphan rejected — sig cost {sig_cost} exceeds limit"
        total_tx_count = len(block.transactions) + len(block.transfer_transactions)
        if total_tx_count > MAX_TXS_PER_BLOCK:
            return False, "Orphan rejected — too many transactions"
        total_message_bytes = sum(len(tx.message) for tx in block.transactions)
        if total_message_bytes > MAX_BLOCK_MESSAGE_BYTES:
            return False, "Orphan rejected — message bytes exceed budget"

        if len(self.orphan_pool) < MAX_ORPHAN_BLOCKS:
            self.orphan_pool[block.block_hash] = block
            logger.debug(f"Stored orphan block #{block.header.block_number} (pool: {len(self.orphan_pool)})")
        else:
            logger.warning(f"Orphan pool full ({MAX_ORPHAN_BLOCKS}), dropping block #{block.header.block_number}")
        return False, "Orphan block — parent not found"

    def _append_block(self, block: Block) -> tuple[bool, str]:
        """Append a validated block to the current best chain.

        Ordering note (Bitcoin-style validate-then-apply):
        We first use compute_post_state_root to simulate the block's effect
        without touching chain state. If the simulated root does not match
        the block's header commitment, we reject BEFORE any mutation. This
        mirrors Bitcoin Core's CheckBlock-before-ConnectBlock pattern and
        avoids relying solely on snapshot/rollback for correctness.

        We still snapshot + verify after application as defence-in-depth:
        the simulation and the real apply path run different code and any
        drift between them should be caught by the post-apply check.
        """
        # Validate ALL slash transactions BEFORE applying any state changes.
        # This prevents state corruption if a slash tx fails validation
        # partway through (previously, regular tx state was already applied).
        for stx in block.slash_transactions:
            valid, reason = self.validate_slash_transaction(stx)
            if not valid:
                return False, f"Invalid slash tx: {reason}"

        # Pre-check: simulate the block's state transition without mutating.
        # If the resulting state root doesn't match the header commitment,
        # reject immediately — no state changes have been applied yet.
        #
        # compute_post_state_root doesn't model slashing state transitions
        # (it simulates only transactions, transfers, and reward splits),
        # so we skip the pre-check for blocks containing slashing txs and
        # rely on the snapshot/rollback safety net further down.
        if not block.slash_transactions:
            try:
                simulated_root = self.compute_post_state_root(
                    transactions=block.transactions,
                    proposer_id=block.header.proposer_id,
                    block_height=block.header.block_number,
                    transfer_transactions=block.transfer_transactions,
                    attestations=block.attestations,
                )
            except Exception:
                # Simulation may be a superset of the real apply logic and
                # can legitimately fail on edge cases; fall through to the
                # existing snapshot/rollback path rather than rejecting on
                # simulation exceptions alone.
                simulated_root = None

            if simulated_root is not None and block.header.state_root != simulated_root:
                return False, "Invalid state_root — state commitment mismatch"

        # Snapshot state BEFORE mutation so we can rollback if state_root is wrong.
        # This prevents a block with invalid state_root from corrupting chain state.
        snapshot = self._snapshot_memory_state()

        # Apply state changes (single code path for normal + reorg)
        self._apply_block_state(block)
        reward = self.supply.calculate_block_reward(block.header.block_number)
        total_fees = sum(tx.fee for tx in block.transactions)
        burned = total_fees  # approximate — each tx burns base_fee

        # Incrementally refresh only the state_tree rows touched by this
        # block. This is the O(K * TREE_DEPTH) path that replaces the
        # O(N * TREE_DEPTH) full-rebuild — every block's cost is now
        # bounded by the number of entities it touched, not the total
        # account count.
        self._touch_state(self._block_affected_entities(block))

        # Verify state_root commitment (mandatory for all post-genesis blocks).
        # Every block must commit to the post-application state. A zeroed
        # state_root no longer bypasses validation — this prevents attackers
        # from submitting blocks with fabricated state.
        expected_state_root = self.compute_current_state_root()
        if block.header.state_root != expected_state_root:
            # Rollback: restore state from snapshot to prevent corruption.
            # The state_tree now diverges from the restored dicts, so
            # rebuild it from scratch to bring them back in sync. This
            # is the slow path (O(N * TREE_DEPTH)) but it only fires on
            # the rare rejection case.
            self._restore_memory_snapshot(snapshot)
            self._rebuild_state_tree()
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

        # Process attestations for finality — uses pinned snapshot for
        # the attestations' target block (N-1) rather than the live
        # post-N stake to avoid validator churn corrupting the 2/3 check.
        self._process_attestations(block, self.supply.staked)

        # Pin the stake snapshot for this block so the NEXT block's
        # attestations (which will target this block) can consult it.
        self._record_stake_snapshot(block.header.block_number)

        # Persist
        if self.db is not None:
            self.db.store_block(block)
            self.db.remove_chain_tip(old_tip)
            self.db.add_chain_tip(block.block_hash, block.header.block_number, new_weight)
            self._persist_state()

        # Process any orphan blocks that depend on this block
        self._process_orphans(block.block_hash)

        return True, f"Block added (reward: {reward}, fees: {total_fees})"

    def _process_orphans(self, parent_hash: bytes):
        """Check if any orphan blocks depend on the given parent and try to add them."""
        dependents = [
            orphan for orphan in self.orphan_pool.values()
            if orphan.header.prev_hash == parent_hash
        ]
        for orphan in dependents:
            del self.orphan_pool[orphan.block_hash]
            logger.debug(f"Processing orphan block #{orphan.header.block_number}")
            self.add_block(orphan)

    def is_assume_valid(self, block_height: int) -> bool:
        """Check if a block at the given height is below the assume-valid boundary.

        When assume_valid_hash is set, blocks at or below its height skip
        signature verification during IBD. This dramatically speeds up initial
        sync since WOTS+ verification is expensive.
        """
        if self.assume_valid_hash is None:
            return False

        # Lazily resolve the assume-valid height
        if self._assume_valid_height is None:
            av_block = self.get_block_by_hash(self.assume_valid_hash)
            if av_block is None:
                return False
            self._assume_valid_height = av_block.header.block_number

        return block_height <= self._assume_valid_height

    def _handle_fork(self, block: Block, parent: Block) -> tuple[bool, str]:
        """Handle a block that creates or extends a fork."""
        # Basic structural validation against parent
        valid, reason = self.validate_block_standalone(block, parent)
        if not valid:
            return False, f"Fork block invalid: {reason}"

        # Finality boundary: reject forks at or below a finalized height.
        # Walk the canonical chain to see if any block at this height is
        # already finalized — accepting a competing block would eventually
        # require reverting finalized state, violating PoS finality.
        for blk in self.chain:
            if blk.header.block_number == block.header.block_number:
                if self.finality.is_finalized(blk.block_hash):
                    return False, (
                        f"Fork rejected — height {block.header.block_number} "
                        f"has a finalized block ({blk.block_hash.hex()[:16]})"
                    )
                break  # only need to check the block at this height
            if blk.header.block_number > block.header.block_number:
                break
        # Also reject if any ancestor on the canonical chain between the
        # fork point and the tip is finalized (the fork would revert it).
        fork_height = block.header.block_number
        for blk in self.chain:
            if blk.header.block_number > parent.header.block_number:
                if blk.header.block_number <= fork_height:
                    if self.finality.is_finalized(blk.block_hash):
                        return False, (
                            f"Fork rejected — canonical block at height "
                            f"{blk.header.block_number} is finalized"
                        )

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

        # Invalidate signature cache — cached results from the old fork may
        # not be valid on the new fork (e.g., different nonce expectations).
        self.sig_cache.invalidate()

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
        """Capture in-memory state for rollback.

        Includes governance state (delegations, votes) so that chain
        reorganizations properly revert governance side-effects.
        """
        snapshot = {
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
            "total_burned": self.supply.total_burned,
            "base_fee": self.supply.base_fee,
            "chain_length": len(self.chain),
            "slashed_validators": set(self.slashed_validators),
            "immature_rewards": list(self._immature_rewards),
            "processed_evidence": set(self._processed_evidence),
            "pending_unstakes": {
                eid: list(entries)
                for eid, entries in self.supply.pending_unstakes.items()
            },
        }
        # Snapshot governance state if tracker is attached
        if hasattr(self, "governance") and self.governance is not None:
            gov = self.governance
            snapshot["gov_delegations"] = dict(gov.delegations)
            snapshot["gov_proposals"] = {
                pid: (dict(ps.votes), ps.created_at_block)
                for pid, ps in gov.proposals.items()
            }
            snapshot["gov_executed_treasury_spends"] = set(gov._executed_treasury_spends)
        return snapshot

    def _restore_memory_snapshot(self, snapshot: dict):
        """Restore in-memory state from snapshot (including governance)."""
        self.supply.balances = snapshot["balances"]
        self.supply.staked = snapshot["staked"]
        self.supply.total_supply = snapshot["total_supply"]
        self.supply.total_minted = snapshot["total_minted"]
        self.supply.total_fees_collected = snapshot["total_fees_collected"]
        self.supply.total_burned = snapshot.get("total_burned", 0)
        self.supply.base_fee = snapshot.get("base_fee", BASE_FEE_INITIAL)
        self.base_fee = self.supply.base_fee
        self.nonces = snapshot["nonces"]
        self.public_keys = snapshot["public_keys"]
        self.entity_message_count = snapshot["message_counts"]
        self.proposer_sig_counts = snapshot.get("proposer_sig_counts", {})
        self.attestation_sig_counts = snapshot.get("attestation_sig_counts", {})
        self.slash_sig_counts = snapshot.get("slash_sig_counts", {})
        self.key_rotation_counts = snapshot.get("key_rotation_counts", {})
        self.slashed_validators = snapshot.get("slashed_validators", set())
        self._immature_rewards = snapshot.get("immature_rewards", [])
        self._processed_evidence = snapshot.get("processed_evidence", set())
        if "pending_unstakes" in snapshot:
            self.supply.pending_unstakes = {
                eid: list(entries)
                for eid, entries in snapshot["pending_unstakes"].items()
            }
        # Restore governance state if tracker is attached and was snapshotted
        if hasattr(self, "governance") and self.governance is not None:
            if "gov_delegations" in snapshot:
                self.governance.delegations = snapshot["gov_delegations"]
            if "gov_executed_treasury_spends" in snapshot:
                self.governance._executed_treasury_spends = snapshot["gov_executed_treasury_spends"]

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
