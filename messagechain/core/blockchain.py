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

import copy
import hashlib
import logging
import time as _time
from messagechain.config import (
    HASH_ALGO, MAX_TXS_PER_BLOCK, MAX_TXS_PER_ENTITY_PER_BLOCK,
    MAX_BLOCK_MESSAGE_BYTES,
    VALIDATOR_MIN_STAKE, GENESIS_ALLOCATION,
    MAX_BLOCK_SIG_COST, COINBASE_MATURITY, MTP_BLOCK_COUNT,
    DUST_LIMIT, MAX_ORPHAN_BLOCKS, ASSUME_VALID_BLOCK_HASH,
    MIN_FEE, MAX_TIMESTAMP_DRIFT, KEY_ROTATION_FEE, BASE_FEE_INITIAL,
    NEW_ACCOUNT_FEE,
)
from messagechain.core.block import Block, compute_merkle_root, compute_state_root, create_genesis_block
from messagechain.core.state_tree import SparseMerkleTree
from messagechain.core.transaction import MessageTransaction, verify_transaction
from messagechain.core.key_rotation import (
    KeyRotationTransaction, verify_key_rotation,
)
from messagechain.core.authority_key import (
    SetAuthorityKeyTransaction, verify_set_authority_key_transaction,
)
from messagechain.core.emergency_revoke import (
    RevokeTransaction, verify_revoke_transaction,
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
from messagechain.consensus.finality import (
    FinalityVote, FinalityCheckpoints, verify_finality_vote,
    FinalityDoubleVoteEvidence,
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
        + len(block.governance_txs)
        + len(getattr(block, "authority_txs", []))
        + len(getattr(block, "stake_transactions", []))
        + len(getattr(block, "unstake_transactions", []))
        + 1  # proposer signature
        + len(block.attestations)
        + len(getattr(block, "finality_votes", []))
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
        # Next-safe WOTS+ leaf index per entity. Every chain-verified signature
        # bumps this forward; validation rejects any tx whose leaf_index is at
        # or below the watermark. Ratchet-only: never decreases, even across
        # reorgs — a leaf that was ever published on any fork is permanently
        # burned because its private material is public knowledge.
        self.leaf_watermarks: dict[bytes, int] = {}
        # Cold "authority" public key per entity, used to gate destructive
        # operations (unstake, emergency revoke) separately from the 24/7
        # hot signing key that lives on the validator server. If unset for
        # an entity, the signing public_key is used as the authority key by
        # default — backward compatible with the single-key identity model.
        self.authority_keys: dict[bytes, bytes] = {}
        # Revoked entities (emergency kill-switch, signed by cold key).
        # Block validation rejects blocks proposed by these entities; their
        # attestations are also rejected. Existing stake has already been
        # pushed into pending_unstakes at revoke time, so the cold-key
        # holder recovers funds through the normal unbonding path.
        self.revoked_entities: set[bytes] = set()
        self.slashed_validators: set[bytes] = set()  # entity IDs that have been slashed
        self._processed_evidence: set[bytes] = set()  # evidence hashes already applied
        self.fork_choice = ForkChoice()
        self.finality = FinalityTracker()
        # Long-range-attack defense — persistent finality checkpoints.
        # Distinct from `self.finality` (attestation-layer, in-memory,
        # immediate-parent finality).  FinalityCheckpoints accumulates
        # explicit FinalityVotes included in blocks; when a target
        # block accumulates 2/3 of stake at its height, its hash is
        # persisted via ChainDB.add_finalized_block so the reorg-
        # rejection rule survives restart.  Loaded from disk in
        # _load_from_db; rehydrated empty for in-memory chains.
        self.finalized_checkpoints: FinalityCheckpoints = FinalityCheckpoints()
        # On-chain governance state: proposals, votes, and append-only
        # audit logs for executed binding outcomes.  Block processing
        # calls _apply_governance_block(block) which dispatches
        # governance txs into this tracker, auto-executes closed binding
        # proposals, and prunes expired state.
        from messagechain.governance.governance import GovernanceTracker
        self.governance = GovernanceTracker()
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

        # Bootstrap gradient: pinned seed identity + monotonic progress
        # metric.  Populated in initialize_genesis from allocation_table
        # (treasury excluded).  Empty frozenset for the backward-compat
        # path where no allocation_table is supplied.
        self.seed_entity_ids: frozenset[bytes] = frozenset()
        from messagechain.consensus.bootstrap_gradient import RatchetState
        self._bootstrap_ratchet: RatchetState = RatchetState()

        # Seed-validator divestment snapshot: entity_id -> initial staked
        # amount captured at the first divestment block (H = START + 1).
        # The per-block decrement is `snapshot / window` and stays fixed
        # for the entire divestment window — deterministic from replay,
        # since every node re-applies block START+1 and records the same
        # value.  Snapshotted in _snapshot_memory_state for reorg safety.
        self.seed_initial_stakes: dict[bytes, int] = {}

        # Attester-reward escrow (stage 3).  Bootstrap-era committee
        # rewards sit here for escrow_blocks_for_progress(progress)
        # blocks before unlocking to spendable balance.  Slashable
        # during the window.  The ledger is in-memory; its contents are
        # deterministic from chain replay.  Balance itself is updated
        # at reward time (so the tokens exist in the state tree), but
        # spendable balance subtracts both immature + escrow so the
        # validator can't move the locked portion.
        from messagechain.economics.escrow import EscrowLedger
        self._escrow: EscrowLedger = EscrowLedger()

        # Reputation: accepted-attestation counter per validator.  The
        # reputation-weighted bootstrap lottery reads this to pick a
        # winner once per LOTTERY_INTERVAL blocks.  Mutation sites:
        #   * _process_attestations: +1 per attestation in an applied
        #     block (every node sees the same chain, so every node
        #     agrees on the count).
        #   * apply_slash_transaction: reset offender to 0.
        # Deterministic from chain replay — not persisted to db,
        # rebuilt from history on load.
        self.reputation: dict[bytes, int] = {}

        # Inactivity leak — Casper-style finalization-stall counter.
        # Incremented every block; reset to 0 when attestation-layer
        # finality fires (a block becomes justified in
        # _process_attestations).  Deterministic from chain replay.
        # When this counter exceeds INACTIVITY_LEAK_ACTIVATION_THRESHOLD,
        # non-attesting validators bleed stake quadratically until
        # honest participants regain 2/3 supermajority.
        self.blocks_since_last_finalization: int = 0

        # Entity-index registry: bidirectional map for bloat reduction.
        # Every registered entity is assigned a monotonic integer index
        # (starting at 1; 0 reserved as the "invalid / unassigned"
        # sentinel). Tx binary encoders write a varint index instead
        # of the full 32-byte entity_id, saving ~29 B per tx.
        #
        # Immutability: an index, once assigned, is part of the state
        # forever. Chain replay must produce identical indices on every
        # node — they're assigned deterministically in the order
        # RegistrationTransactions are applied (genesis seed first,
        # then in-block registrations in block order, left-to-right
        # within each block).
        #
        # _signable_data() across every tx type continues to use the
        # 32-byte entity_id; the index is a wire/storage optimization
        # only. A signed tx remains verifiable even under hypothetical
        # index churn — defense in depth.
        self.entity_id_to_index: dict[bytes, int] = {}
        self.entity_index_to_id: dict[int, bytes] = {}
        self._next_entity_index: int = 1  # 0 reserved

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

        # Restore leaf-reuse watermarks
        if hasattr(self.db, 'get_all_leaf_watermarks'):
            self.leaf_watermarks = self.db.get_all_leaf_watermarks()

        # Restore authority (cold) keys for hot/cold-separated validators
        if hasattr(self.db, 'get_all_authority_keys'):
            self.authority_keys = self.db.get_all_authority_keys()

        # Restore emergency-revoked entities
        if hasattr(self.db, 'get_all_revoked'):
            self.revoked_entities = self.db.get_all_revoked()

        # Restore key-rotation counts so a restored client can re-derive
        # the correct current rotated tree via rotation_number.
        if hasattr(self.db, 'get_all_key_rotation_counts'):
            self.key_rotation_counts = self.db.get_all_key_rotation_counts()

        # Restore slashed validators
        if hasattr(self.db, 'get_all_slashed'):
            self.slashed_validators = self.db.get_all_slashed()

        # Restore finalized-block checkpoints (long-range defense).
        # The (block_number -> block_hash) set persisted by the
        # on-chain finality path is the cryptographic commitment that
        # survives process restart.  Rehydrating it into
        # FinalityCheckpoints is what makes the reorg-rejection rule
        # durable — without this, a cold-booted node would accept a
        # competing long-range chain because it has no in-memory
        # record of what was finalized pre-restart.  Gated by attr
        # check so an older chaindb without the table still loads.
        if hasattr(self.db, 'get_all_finalized_blocks'):
            for bn, bh in self.db.get_all_finalized_blocks().items():
                self.finalized_checkpoints.mark_finalized(bh, bn)

        # Restore processed-evidence set so a restart cannot re-apply an
        # already-consumed slashing evidence transaction (which would let
        # a validator be slashed twice for the same offence).
        if hasattr(self.db, 'get_all_processed_evidence'):
            self._processed_evidence = self.db.get_all_processed_evidence()

        # Restore entity-index registry (bloat reduction). Indices are
        # assigned monotonically at registration time; rebuilding the
        # bidirectional map from the persisted table keeps a restart's
        # index assignments identical to the pre-restart ones so signed
        # txs already in flight (or arriving soon after restart) that
        # reference the entity by index decode to the same entity_id.
        if hasattr(self.db, 'get_all_entity_indices'):
            persisted = self.db.get_all_entity_indices()
            self.entity_id_to_index = dict(persisted)
            self.entity_index_to_id = {
                idx: eid for eid, idx in persisted.items()
            }
            if persisted:
                self._next_entity_index = max(persisted.values()) + 1

        # Rebuild in-memory chain from best tip
        best_tip = self.db.get_best_tip()
        if best_tip is None:
            return

        tip_hash, tip_height, tip_weight = best_tip

        # Load all blocks into chain list (ordered by height).  The
        # entity-index registry is already rehydrated above, so blocks
        # stored in the compact varint-index form decode cleanly here.
        for height in range(tip_height + 1):
            block = self.db.get_block_by_number(height, state=self)
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
            if hasattr(self.db, 'set_leaf_watermark'):
                for eid, nxt in self.leaf_watermarks.items():
                    self.db.set_leaf_watermark(eid, nxt)
            if hasattr(self.db, 'set_authority_key'):
                for eid, ak in self.authority_keys.items():
                    self.db.set_authority_key(eid, ak)
            if hasattr(self.db, 'set_revoked'):
                for eid in self.revoked_entities:
                    self.db.set_revoked(eid)
            if hasattr(self.db, 'set_key_rotation_count'):
                for eid, rn in self.key_rotation_counts.items():
                    self.db.set_key_rotation_count(eid, rn)
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
            # Persist the entity-index registry so a restart rehydrates
            # the bidirectional map with identical assignments.  The
            # underlying INSERT OR IGNORE makes re-persisting an
            # already-stored pair a no-op (indices are immutable).
            if hasattr(self.db, 'set_entity_index'):
                for eid, idx in self.entity_id_to_index.items():
                    self.db.set_entity_index(eid, idx)
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

        # Non-devnet safety: refuse to create genesis when no pinned hash
        # is configured.  A misconfigured production node with an empty
        # data dir would otherwise silently mint its own genesis block,
        # forking the network permanently.
        import messagechain.config as _cfg
        pinned = getattr(_cfg, "PINNED_GENESIS_HASH", None)
        devnet = getattr(_cfg, "DEVNET", False)
        if pinned is None and not devnet:
            raise RuntimeError(
                "PINNED_GENESIS_HASH is not set and DEVNET is False. "
                "A production node must have PINNED_GENESIS_HASH configured "
                "in messagechain/config.py to prevent accidental chain forks. "
                "Set DEVNET=True for local testing."
            )

        # If a canonical genesis hash is pinned in config, refuse to
        # initialize unless this entity happens to produce the exact same
        # block.  Prevents two nodes on fresh data directories from each
        # minting their own genesis and creating permanently bifurcated
        # chains that can never reconcile.
        if pinned is not None and pinned != genesis_block.block_hash:
            raise RuntimeError(
                f"Refusing to mint a local genesis: pinned genesis hash is "
                f"{pinned.hex()[:16]}..., this entity would produce "
                f"{genesis_block.block_hash.hex()[:16]}... instead. "
                f"Sync block 0 from a peer that has the canonical chain."
            )

        self.chain.append(genesis_block)
        self._block_by_hash[genesis_block.block_hash] = genesis_block

        # Register genesis entity
        self.public_keys[genesis_entity.entity_id] = genesis_entity.public_key
        self.nonces[genesis_entity.entity_id] = 0
        # Genesis entity gets the first entity_index (1). All subsequent
        # RegistrationTransactions extend this monotonic sequence.
        self._assign_entity_index(genesis_entity.entity_id)
        # Genesis block was signed — track the WOTS+ leaf consumed and
        # advance the leaf watermark so the state commitment reflects the
        # used leaf.  Without this, a fresh chain's state_root would lag
        # the genesis signer's keypair by one leaf, and every subsequent
        # block's sim would mispredict the next proposer leaf_index.
        self.proposer_sig_counts[genesis_entity.entity_id] = 1
        if genesis_block.header.proposer_signature is not None:
            self._bump_watermark(
                genesis_entity.entity_id,
                genesis_block.header.proposer_signature.leaf_index,
            )

        # Distribute genesis allocation
        if allocation_table is not None:
            for entity_id, amount in allocation_table.items():
                self.supply.balances[entity_id] = (
                    self.supply.balances.get(entity_id, 0) + amount
                )
                # Pre-allocate entity indices for every genesis-allocated
                # recipient.  Even non-seed recipients may transact later
                # (e.g., a treasury spend), and every transacting entity
                # needs an index for the compact wire form.  Iteration
                # order of dicts is insertion-order-stable since Python
                # 3.7, so every node replaying genesis from the same
                # allocation_table assigns identical indices.
                self._assign_entity_index(entity_id)
            # Pin seed identity at genesis: every entity in the allocation
            # table EXCEPT the treasury is a seed.  Treasury is excluded
            # because it is a protocol-owned address, not a validator.
            # Frozenset: "who is a seed" has exactly one answer for the
            # life of the chain and must never be mutated post-genesis.
            from messagechain.config import TREASURY_ENTITY_ID
            self.seed_entity_ids = frozenset(
                eid for eid in allocation_table.keys()
                if eid != TREASURY_ENTITY_ID
            )
            if not self.seed_entity_ids:
                # Allocation table supplied but contained ONLY the treasury.
                # Bootstrap seed-exclusion rules will have no effect, which
                # is almost never what the operator wants.  Loud warning
                # rather than hard error — tests may legitimately do this.
                logger.warning(
                    "initialize_genesis: allocation_table has no seed "
                    "entities (only TREASURY_ENTITY_ID present).  "
                    "seed_entity_ids will be empty, so bootstrap-era "
                    "seed-exclusion from the attester committee will "
                    "silently no-op.  Use bootstrap.build_launch_allocation() "
                    "for production deployments."
                )
        else:
            # Backward-compatible single-entity allocation.  No seed set
            # is pinned (seed_entity_ids stays as frozenset()) — this is
            # intended for tests and dev scaffolding, NOT production.
            # Log a warning so operators catch accidental production use
            # of this code path (every bootstrap gradient mechanism that
            # depends on identifying seeds silently no-ops otherwise).
            logger.warning(
                "initialize_genesis called without allocation_table — "
                "seed_entity_ids will be empty, so bootstrap-era "
                "seed-exclusion rules will silently no-op.  Use "
                "bootstrap.build_launch_allocation() or pass an "
                "explicit allocation_table for production deployments."
            )
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
            # Thread `self` as state so the compact entity-index wire form
            # lands on disk.  The genesis entity is already registered in
            # self.entity_id_to_index by this point, so the tx encoder
            # can swap its 32-byte id for a 1-byte varint index.
            self.db.store_block(genesis_block, state=self)
            self.db.add_chain_tip(genesis_block.block_hash, 0, 0)
            self._persist_state()

        return genesis_block

    def bootstrap_from_checkpoint(
        self,
        snapshot_bytes: bytes,
        checkpoint,
        signatures: list,
        stake_at_checkpoint: dict,
        public_keys_at_checkpoint: dict,
        checkpoint_block,
        recent_blocks: list,
    ) -> tuple[bool, str]:
        """Install a signed state snapshot + apply the recent blocks since X.

        This is the bootstrap-speed path: a new full-node / validator
        skips genesis-replay by downloading a >=2/3-stake-signed snapshot
        at block X plus the ~last N blocks since X.  After this call, the
        node is fully synced up through `recent_blocks[-1]` and can
        propose / validate further blocks indistinguishably from an
        archive node.

        The chain itself remains permanent — archive nodes retain every
        block — this is ONLY about letting a NEW node skip ancient
        history replay.

        Arguments:
            snapshot_bytes:           encode_snapshot(serialize_state(...))
            checkpoint:               StateCheckpoint committing to X
            signatures:               list[StateCheckpointSignature]
            stake_at_checkpoint:      entity_id -> stake, snapshotted at X
            public_keys_at_checkpoint:entity_id -> pubkey, as-of X
            checkpoint_block:         the Block at height X (needed so
                                      `recent_blocks[0].prev_hash` can
                                      link back)
            recent_blocks:            blocks X+1, X+2, ..., current tip

        Returns (ok, reason).  This method MUST be called on a fresh
        Blockchain instance that has never had initialize_genesis or any
        prior state installed — otherwise state installation would silently
        mix into pre-existing state.
        """
        from messagechain.storage.state_snapshot import (
            decode_snapshot,
            compute_state_root as compute_snapshot_root,
            MAX_STATE_SNAPSHOT_BYTES as _max_bytes_module,
        )
        # Pick up the live cap from the module so monkey-patching in tests
        # is honored.  (decode_snapshot accepts an explicit max_bytes kwarg,
        # so we pass through whatever the module currently holds.)
        import messagechain.storage.state_snapshot as _ss_mod
        from messagechain.consensus.state_checkpoint import (
            verify_state_checkpoint, StateCheckpoint,
        )

        # Refuse to bootstrap a chain that's already been initialized —
        # we would otherwise merge two different states.
        if self.chain:
            return False, (
                "Refusing to bootstrap: chain is already initialized "
                "(genesis or other blocks present)"
            )

        # 1. Size cap — cheap DoS guard before we parse anything.
        if len(snapshot_bytes) > _ss_mod.MAX_STATE_SNAPSHOT_BYTES:
            return False, (
                f"Snapshot too large: {len(snapshot_bytes)} bytes > "
                f"cap {_ss_mod.MAX_STATE_SNAPSHOT_BYTES}"
            )

        # 2. Parse the snapshot (decoder also enforces cap internally).
        try:
            snap = decode_snapshot(
                snapshot_bytes,
                max_bytes=_ss_mod.MAX_STATE_SNAPSHOT_BYTES,
            )
        except ValueError as e:
            return False, f"Snapshot decode failed: {e}"

        # 3. Verify the snapshot root matches the checkpoint.state_root.
        computed_root = compute_snapshot_root(snap)
        if computed_root != checkpoint.state_root:
            return False, (
                f"Mismatched state_root: checkpoint commits to "
                f"{checkpoint.state_root.hex()[:16]}, snapshot computes "
                f"{computed_root.hex()[:16]}"
            )

        # 4. Verify the checkpoint block hash matches the checkpoint.
        if checkpoint_block.block_hash != checkpoint.block_hash:
            return False, (
                f"checkpoint_block hash {checkpoint_block.block_hash.hex()[:16]}"
                f" does not match checkpoint.block_hash "
                f"{checkpoint.block_hash.hex()[:16]}"
            )
        if checkpoint_block.header.block_number != checkpoint.block_number:
            return False, (
                f"checkpoint_block height {checkpoint_block.header.block_number}"
                f" does not match checkpoint.block_number "
                f"{checkpoint.block_number}"
            )

        # 5. Verify >=2/3 of stake-at-X has signed the checkpoint.
        ok, reason = verify_state_checkpoint(
            checkpoint, signatures,
            stake_at_checkpoint, public_keys_at_checkpoint,
        )
        if not ok:
            return False, f"Checkpoint signature verification failed: {reason}"

        # 6. Install snapshot state into this blockchain instance.
        self._install_state_snapshot(snap)

        # 7. Install the checkpoint block as the current tip — later
        # add_block() calls validate `prev_hash` against it.
        self.chain.append(checkpoint_block)
        self._block_by_hash[checkpoint_block.block_hash] = checkpoint_block
        self.fork_choice.add_tip(
            checkpoint_block.block_hash,
            checkpoint_block.header.block_number,
            0,
        )
        # Pin a stake snapshot for the checkpoint height so the next
        # block's attestation/finality counters have a denominator.
        self._stake_snapshots[checkpoint_block.header.block_number] = dict(
            stake_at_checkpoint
        )

        # 8. Sanity: the snapshot's per-entity fields must reconcile with
        # the header's state_root (which covers only the per-entity tree).
        # Without this, a malicious snapshot could pass root-check on the
        # broader commitment while mis-stating the per-entity commitment
        # the chain's block pipeline actually uses.
        header_root_on_install = self.compute_current_state_root()
        if header_root_on_install != checkpoint_block.header.state_root:
            return False, (
                "Per-entity state root after install does not match "
                "checkpoint block header state_root — snapshot is "
                "internally inconsistent with the chain header"
            )

        # 9. Apply recent blocks in order.  Any failure leaves the chain
        # in a partially-synced but self-consistent state up to the last
        # successful block — caller can retry fetching missing blocks.
        for blk in recent_blocks:
            ok, reason = self.add_block(blk)
            if not ok:
                return False, (
                    f"recent_block {blk.header.block_number} "
                    f"rejected during bootstrap: {reason}"
                )

        # 10. Persist the verified checkpoint if a db is attached, so a
        # future warm restart sees the same bootstrap point.
        if self.db is not None and hasattr(
            self.db, "add_verified_state_checkpoint"
        ):
            self.db.add_verified_state_checkpoint(checkpoint, signatures)

        return True, "Bootstrap complete"

    def _install_state_snapshot(self, snap: dict) -> None:
        """Load a decoded state-snapshot dict into this blockchain.

        Only called by bootstrap_from_checkpoint on a fresh (no-genesis)
        chain, after the checkpoint signatures have been verified and
        the root has been confirmed to match the snapshot bytes.
        """
        # Per-entity fields
        self.supply.balances = dict(snap["balances"])
        self.supply.staked = dict(snap["staked"])
        self.nonces = dict(snap["nonces"])
        self.public_keys = dict(snap["public_keys"])
        self.authority_keys = dict(snap["authority_keys"])
        self.leaf_watermarks = dict(snap["leaf_watermarks"])
        self.key_rotation_counts = dict(snap["key_rotation_counts"])
        self.revoked_entities = set(snap["revoked_entities"])
        self.slashed_validators = set(snap["slashed_validators"])

        # Entity index registry
        self.entity_id_to_index = dict(snap["entity_id_to_index"])
        self.entity_index_to_id = {
            idx: eid for eid, idx in self.entity_id_to_index.items()
        }
        self._next_entity_index = int(snap["next_entity_index"])

        # Global fields
        self.supply.total_supply = int(snap["total_supply"])
        self.supply.total_minted = int(snap["total_minted"])
        self.supply.total_fees_collected = int(snap["total_fees_collected"])
        self.supply.total_burned = int(snap["total_burned"])
        self.supply.base_fee = int(snap["base_fee"])
        self.base_fee = int(snap["base_fee"])

        # Finalized checkpoints (long-range-attack defense — must carry
        # across the bootstrap boundary or the new node would accept a
        # competing chain that contradicts a known-finalized block).
        for bn, bh in snap["finalized_checkpoints"].items():
            self.finalized_checkpoints.mark_finalized(bh, bn)

        # Rebuild the per-entity sparse Merkle tree from the installed
        # state so compute_current_state_root reflects the snapshot.
        self._rebuild_state_tree()

    def get_authority_key(self, entity_id: bytes) -> bytes | None:
        """Return the authority (cold) public key for an entity.

        If the entity has never run SetAuthorityKey, the signing public_key
        is returned — the chain treats the signing key as its own authority
        by default. Returns None if the entity is not registered at all.
        """
        if entity_id in self.authority_keys:
            return self.authority_keys[entity_id]
        return self.public_keys.get(entity_id)

    def validate_set_authority_key(
        self, tx: SetAuthorityKeyTransaction,
    ) -> tuple[bool, str]:
        if tx.entity_id not in self.public_keys:
            return False, "Unknown entity — must register first"

        expected_nonce = self.nonces.get(tx.entity_id, 0)
        if tx.nonce != expected_nonce:
            return False, f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"

        if not self.supply.can_afford_fee(tx.entity_id, tx.fee):
            return False, f"Insufficient balance for fee of {tx.fee}"

        if tx.signature.leaf_index < self.leaf_watermarks.get(tx.entity_id, 0):
            return False, (
                f"WOTS+ leaf {tx.signature.leaf_index} already consumed "
                f"— leaf reuse rejected"
            )

        # Signed by the current signing key — the user is authenticating
        # themselves before handing the authority role to the new cold key.
        signing_pk = self.public_keys[tx.entity_id]
        if not verify_set_authority_key_transaction(tx, signing_pk):
            return False, "Invalid signature"

        # Reject the cold == hot no-op.  Operators legitimately share a
        # single cold wallet across multiple validators they control (the
        # standard cluster pattern), so we do NOT reject cross-entity
        # reuse — the signer is explicitly handing authority to whoever
        # holds that key, which is their call.  But setting the authority
        # key to your own signing key is always a mistake: it looks like
        # defense-in-depth without providing any, and there is no honest
        # use case for it.
        if tx.new_authority_key == signing_pk:
            return False, (
                "new_authority_key equals the entity's own signing key — "
                "defeats hot/cold separation"
            )

        return True, "Valid"

    def apply_set_authority_key(
        self,
        tx: SetAuthorityKeyTransaction,
        proposer_id: bytes,
    ) -> tuple[bool, str]:
        ok, reason = self.validate_set_authority_key(tx)
        if not ok:
            return False, reason

        if not self.supply.pay_fee_with_burn(
            tx.entity_id, proposer_id, tx.fee, self.supply.base_fee,
        ):
            return False, f"Fee payment failed (fee {tx.fee} vs base_fee {self.supply.base_fee})"
        self.authority_keys[tx.entity_id] = tx.new_authority_key
        self.nonces[tx.entity_id] = tx.nonce + 1
        self._bump_watermark(tx.entity_id, tx.signature.leaf_index)
        return True, "Authority key updated"

    def is_revoked(self, entity_id: bytes) -> bool:
        """True if this entity has been emergency-revoked by its cold key."""
        return entity_id in self.revoked_entities

    def validate_revoke(self, tx: RevokeTransaction) -> tuple[bool, str]:
        if tx.entity_id not in self.public_keys:
            return False, "Unknown entity"
        if tx.entity_id in self.revoked_entities:
            return False, "Entity already revoked"

        if not self.supply.can_afford_fee(tx.entity_id, tx.fee):
            return False, f"Insufficient balance for fee of {tx.fee}"

        # Authority-gated: signature must verify under the cold key.
        # Deliberately no nonce check — revoke is idempotent and the tx is
        # designed to be pre-signable offline, where the live nonce is
        # unavailable.  Replay protection comes from the "already revoked"
        # guard above: any second submission with the same effect is a no-op.
        authority_pk = self.get_authority_key(tx.entity_id)
        if authority_pk is None or not verify_revoke_transaction(tx, authority_pk):
            return False, (
                "Invalid signature — revoke must be signed by the authority "
                "(cold) key. The hot signing key cannot self-revoke."
            )
        return True, "Valid"

    def apply_revoke(
        self,
        tx: RevokeTransaction,
        proposer_id: bytes,
        current_block: int | None = None,
    ) -> tuple[bool, str]:
        """Apply an emergency revoke: flag entity, unbond all stake, burn fee."""
        ok, reason = self.validate_revoke(tx)
        if not ok:
            return False, reason

        if not self.supply.pay_fee_with_burn(
            tx.entity_id, proposer_id, tx.fee, self.supply.base_fee,
        ):
            return False, f"Fee payment failed (fee {tx.fee} vs base_fee {self.supply.base_fee})"

        # Push all active stake into the 7-day unbonding queue. Do NOT
        # release it immediately — in-flight slashing evidence must still
        # be able to reach it during the unbonding window.
        active_stake = self.supply.get_staked(tx.entity_id)
        if active_stake > 0:
            block_height = current_block if current_block is not None else self.height
            self.supply.unstake(
                tx.entity_id,
                active_stake,
                current_block=block_height,
                bootstrap_ended=False,  # don't fail revoke on min-stake check
            )

        self.revoked_entities.add(tx.entity_id)
        # Deliberately no nonce bump: revoke has no nonce (pre-signable on
        # paper offline).  The "already revoked" guard in validate_revoke
        # is the replay defense.

        # The revoke signature consumed a leaf from the COLD key tree.
        # The hot-key watermark is unaffected, so we deliberately do not
        # bump self.leaf_watermarks[entity_id] here — that watermark
        # tracks the hot tree, which may continue to be used up until
        # the chain enforces a full halt of the revoked entity.

        # Persist revocation immediately — this is a security-critical flag.
        if self.db is not None and hasattr(self.db, 'set_revoked'):
            self.db.set_revoked(tx.entity_id)
            self.db.flush_state()

        return True, "Entity revoked"

    def get_leaf_watermark(self, entity_id: bytes) -> int:
        """Return the next-safe WOTS+ leaf index for this entity.

        Clients must call advance_to_leaf(watermark) on their local KeyPair
        before signing, and sign with a leaf_index >= watermark. Any tx whose
        leaf_index is below the watermark is rejected as a reuse attempt.
        """
        return self.leaf_watermarks.get(entity_id, 0)

    def _bump_watermark(self, entity_id: bytes, leaf_index: int) -> None:
        """Ratchet the per-entity watermark to one past the supplied leaf.

        Invariant: the stored value only ever increases. This makes WOTS+
        leaf reuse impossible from the chain's perspective — once a leaf
        has been seen, no later tx signed at that leaf (or below) will
        ever pass validation.
        """
        nxt = leaf_index + 1
        current = self.leaf_watermarks.get(entity_id, 0)
        if nxt > current:
            self.leaf_watermarks[entity_id] = nxt

    def _install_pubkey_direct(
        self,
        entity_id: bytes,
        public_key: bytes,
        registration_proof: "Signature | None" = None,
    ) -> tuple[bool, str]:
        """
        INTERNAL / non-consensus-safe.  Install (entity_id -> public_key)
        directly into chain state without going through a block.

        Used in exactly two situations:
          * Genesis / bootstrap, when there is no block pipeline yet —
            see bootstrap.bootstrap_seed_local and the test helper
            tests.register_entity_for_test.
          * Test fixtures that set up chain state.

        The production flow for a new entity is receive-to-exist: an
        entity enters state when it RECEIVES a transfer (just a balance
        entry) and its pubkey is installed when it spends for the first
        time via a Transfer carrying `sender_pubkey` — NOT via this
        method.  Calling this mid-chain would bypass consensus: peers
        replaying the chain would never install the same pubkey and
        their state roots would diverge.

        Requires a registration_proof: a signature over
        SHA3-256("register" || entity_id) using the keypair corresponding
        to public_key. This proves the caller controls the keypair and
        prevents fabrication of arbitrary identities.

        ENFORCES: one entity per key. If the entity_id already exists,
        the call is REJECTED.
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

        # Leaf-reuse guard: a registration proof signed with a leaf at or
        # below the current watermark (e.g., an entity trying to re-register
        # with a rewound keypair) is rejected.
        if registration_proof.leaf_index < self.leaf_watermarks.get(entity_id, 0):
            return False, "Registration proof reuses an already-consumed WOTS+ leaf"

        self.public_keys[entity_id] = public_key
        self.nonces[entity_id] = 0
        self._bump_watermark(entity_id, registration_proof.leaf_index)
        self._assign_entity_index(entity_id)
        # Cover the mutation in the consensus state root — bootstrap
        # runs before any block is appended, so the next block's state
        # root reconstruction must include this leaf.
        self._touch_state({entity_id})

        if self.db is not None:
            self.db.set_public_key(entity_id, public_key)
            self.db.set_nonce(entity_id, 0)
            self.db.set_balance(entity_id, self.supply.get_balance(entity_id))
            self.db.flush_state()

        return True, "Entity registered"

    def _assign_entity_index(self, entity_id: bytes) -> int:
        """Assign the next monotonic index to `entity_id` if unassigned.

        Idempotent: returns the existing index if already registered.
        Persists the (entity_id, index) pair to ChainDB when present so
        a restart rehydrates the bidirectional map without replaying
        every RegistrationTransaction.

        Index 0 is reserved as the "invalid/unassigned" sentinel; the
        first real entity gets index 1. This matches the convention
        chosen by varint encoders (a 0 byte is cheap but is never a
        valid index on wire).
        """
        existing = self.entity_id_to_index.get(entity_id)
        if existing is not None:
            return existing
        idx = self._next_entity_index
        self.entity_id_to_index[entity_id] = idx
        self.entity_index_to_id[idx] = entity_id
        self._next_entity_index = idx + 1
        if self.db is not None and hasattr(self.db, "set_entity_index"):
            self.db.set_entity_index(entity_id, idx)
        return idx

    def sync_consensus_stakes(self, consensus: "ProofOfStake", block_height: int | None = None):
        """Populate consensus.stakes from the supply tracker's staked amounts.

        Must be called after loading from DB so that the consensus module
        has accurate stake data (prevents falling into permissive bootstrap mode).
        """
        from messagechain.config import VALIDATOR_MIN_STAKE
        for entity_id, amount in self.supply.staked.items():
            if amount >= VALIDATOR_MIN_STAKE:
                consensus.stakes[entity_id] = amount

    def get_latest_block(self) -> Block | None:
        return self.chain[-1] if self.chain else None

    def _selected_proposer_for_slot(
        self, parent: Block, round_number: int
    ) -> bytes | None:
        """Compute the selected proposer for the slot after `parent` at
        round `round_number`, using the chain's own supply.staked as the
        authoritative stake state.

        Returns None when no validator meets the minimum stake — that
        indicates bootstrap mode, and validate_block skips the
        proposer-match check so any registered entity may propose.

        This mirrors ProofOfStake.select_proposer but lives on Blockchain
        so validate_block can enforce proposer correctness without taking
        a consensus parameter. Keeping it here is a small duplication,
        but the upside is that consensus and validate_block agree on the
        selection algorithm byte-for-byte.
        """
        import struct
        from messagechain.config import VALIDATOR_MIN_STAKE

        height = parent.header.block_number + 1
        # Slashed validators already have staked[eid] = 0, so the
        # min_stake filter excludes them implicitly.
        stakes = {
            eid: amt
            for eid, amt in self.supply.staked.items()
            if amt >= VALIDATOR_MIN_STAKE
        }
        if not stakes:
            return None  # bootstrap mode — no enforcement

        validators = sorted(stakes.items(), key=lambda x: x[0])
        total = sum(s for _, s in validators)
        if total == 0:
            return None

        # VRF lookahead: use randao_mix from block (N - VRF_LOOKAHEAD)
        # instead of the immediate parent's mix. This makes the proposer
        # for block N unknowable until block N - VRF_LOOKAHEAD is finalized.
        from messagechain.config import VRF_ENABLED, VRF_LOOKAHEAD
        if VRF_ENABLED and len(self.chain) > 1:
            from messagechain.consensus.vrf import select_proposer_vrf
            target_block = max(0, height - VRF_LOOKAHEAD)
            target_block = min(target_block, len(self.chain) - 1)
            lookahead_mix = self.chain[target_block].header.randao_mix
            return select_proposer_vrf(
                lookahead_mix, height, dict(validators), round_number=round_number
            )

        # Fallback: pre-VRF deterministic selection (VRF_ENABLED=False
        # or very early chain with only genesis block).
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
            # Thread `self` as state so any compact-form entity refs
            # in the on-disk blob are resolved back to full ids.
            block = self.db.get_block_by_hash(block_hash, state=self)
            if block:
                self._block_by_hash[block_hash] = block
        return block

    @property
    def height(self) -> int:
        return len(self.chain)

    def _raw_bootstrap_progress(self) -> float:
        """Compute the un-ratcheted bootstrap_progress from current state.

        NEVER call this from read-side code paths.  The raw value can
        regress as stake fluctuates, which is exactly what the ratchet
        exists to guard against.  Only the apply path (`_apply_block_state`
        → `_update_bootstrap_ratchet`) is allowed to observe this value;
        every other caller should go through the `bootstrap_progress`
        property which returns the already-ratcheted max.
        """
        from messagechain.consensus.bootstrap_gradient import (
            compute_bootstrap_progress,
        )
        seed_stake = sum(
            self.supply.get_staked(eid) for eid in self.seed_entity_ids
        )
        non_seed_stake = 0
        for eid, amount in self.supply.staked.items():
            if amount <= 0:
                continue
            if eid in self.seed_entity_ids:
                continue
            non_seed_stake += amount
        return compute_bootstrap_progress(
            height=self.height,
            seed_stake=seed_stake,
            non_seed_stake=non_seed_stake,
        )

    @property
    def bootstrap_progress(self) -> float:
        """Monotonic value in [0, 1] driving the bootstrap-phase gradient.

        Ratcheted at block-apply time only (see `_update_bootstrap_ratchet`,
        called once at the end of `_apply_block_state`).  This property
        is a pure reader with no side effects, so two nodes with
        identical chain history always return the same value regardless
        of query timing — load-bearing because this value drives
        attester-committee selection.  A side-effectful read (the old
        behavior) could let two honest nodes latch onto different
        ratchet peaks based on when they queried, which would fork
        the chain on state_root.

        Downstream code uses this to smoothly interpolate bootstrap-era
        parameters (committee selection weight, min-stake requirement,
        escrow window, seed exclusion).  See
        messagechain.consensus.bootstrap_gradient for the design.
        """
        return self._bootstrap_ratchet.max_progress

    def _update_bootstrap_ratchet(self) -> None:
        """Observe current raw progress and ratchet it up.

        Called once per block apply (at the end of `_apply_block_state`),
        so the ratchet reflects post-apply chain state.  Every node
        applying the same block reaches the same ratchet value — this
        is what makes `bootstrap_progress` deterministic across nodes.
        """
        self._bootstrap_ratchet.observe(self._raw_bootstrap_progress())

    def has_block(self, block_hash: bytes) -> bool:
        if block_hash in self._block_by_hash:
            return True
        if self.db is not None:
            return self.db.has_block(block_hash)
        return False

    def validate_transaction(
        self, tx: MessageTransaction, *, expected_nonce: int | None = None,
    ) -> tuple[bool, str]:
        """Validate a transaction against current chain state.

        If *expected_nonce* is provided it overrides the on-chain nonce
        for this entity.  This allows the mempool layer to pass a
        "pending nonce" so users can submit sequential transactions
        without waiting for each to be mined.
        """
        if tx.entity_id not in self.public_keys:
            return False, "Unknown entity — must register first"

        # Crypto-agility gate: reject unknown signature schemes up-front so
        # the reason string is a clear "sig version" and not a generic
        # "invalid signature".  Applies before any hash/verify work.
        from messagechain.config import validate_sig_version
        ok, reason = validate_sig_version(tx.signature.sig_version)
        if not ok:
            return False, f"Invalid sig version: {reason}"

        effective_nonce = expected_nonce if expected_nonce is not None else self.nonces.get(tx.entity_id, 0)
        if tx.nonce != effective_nonce:
            return False, f"Invalid nonce: expected {effective_nonce}, got {tx.nonce}"

        if tx.timestamp <= 0:
            return False, "Transaction must have a valid timestamp"

        if self.get_spendable_balance(tx.entity_id) < tx.fee:
            return False, f"Insufficient spendable balance for fee of {tx.fee}"

        if tx.signature.leaf_index < self.leaf_watermarks.get(tx.entity_id, 0):
            return False, (
                f"WOTS+ leaf {tx.signature.leaf_index} already consumed "
                f"(watermark {self.leaf_watermarks[tx.entity_id]}) — leaf reuse rejected"
            )

        public_key = self.public_keys[tx.entity_id]
        if not verify_transaction(tx, public_key):
            return False, "Invalid signature"

        return True, "Valid"

    def _recipient_is_new(
        self,
        recipient_id: bytes,
        *,
        pending_new_account_created: set[bytes] | None = None,
    ) -> bool:
        """Return True iff `recipient_id` has no on-chain state at all.

        The canonical check is "state_tree has no leaf for this entity,"
        but the state_tree is only synced lazily (compute_current_state_root
        /_touch_state). During validation the live dicts are the
        authoritative source of truth.  An entity is "brand-new" iff it
        appears in NONE of: balances, staked, public_keys, authority_keys,
        leaf_watermarks, key_rotation_counts, revoked_entities,
        slashed_validators, or entity_index.  This matches the set of
        fields _rebuild_state_tree iterates when populating the SMT, so
        absence here == absence of any committed state.

        `pending_new_account_created`, if provided, lists recipients
        already funded by earlier txs within the same block but not yet
        flushed to dicts — used only by the block-path validator for
        intra-block pipelining.  If the recipient is in that set, we
        treat them as NOT new (since an earlier tx in this block already
        paid the surcharge).
        """
        if pending_new_account_created is not None and recipient_id in pending_new_account_created:
            return False
        if recipient_id in self.supply.balances:
            return False
        if recipient_id in self.supply.staked:
            return False
        if recipient_id in self.public_keys:
            return False
        if recipient_id in self.authority_keys:
            return False
        if recipient_id in self.leaf_watermarks:
            return False
        if recipient_id in self.key_rotation_counts:
            return False
        if recipient_id in self.revoked_entities:
            return False
        if recipient_id in self.slashed_validators:
            return False
        if recipient_id in self.entity_id_to_index:
            return False
        if recipient_id in self.nonces:
            return False
        return True

    def validate_transfer_transaction(
        self, tx: TransferTransaction, *, expected_nonce: int | None = None,
        pending_new_account_created: set[bytes] | None = None,
    ) -> tuple[bool, str]:
        """Validate a transfer transaction against current chain state.

        Receive-to-exist semantics:
          * Recipients never need to be pre-registered — an unknown
            recipient_id is fine; apply creates a balance entry.
          * Senders must either (a) already have a pubkey in state, in
            which case `sender_pubkey` must be empty, or (b) be making
            their FIRST outgoing transfer with `sender_pubkey` populated
            so we can derive+verify the entity_id and install the key.

        If *expected_nonce* is provided it overrides the on-chain nonce
        for this entity (see validate_transaction for rationale).
        """
        from messagechain.identity.identity import derive_entity_id

        # Dust limit: reject transfers below minimum to prevent state bloat
        if tx.amount < DUST_LIMIT:
            return False, f"Transfer amount {tx.amount} below dust limit {DUST_LIMIT}"

        # New-account surcharge: if the recipient has no on-chain state,
        # this tx is creating a permanent state entry and must pay
        # MIN_FEE + NEW_ACCOUNT_FEE at minimum.  The extra surcharge is
        # BURNED on apply (see _apply_transfer_with_burn).
        if self._recipient_is_new(
            tx.recipient_id,
            pending_new_account_created=pending_new_account_created,
        ):
            required = MIN_FEE + NEW_ACCOUNT_FEE
            if tx.fee < required:
                return False, (
                    f"Transfer to brand-new recipient requires "
                    f"fee >= {required} (MIN_FEE {MIN_FEE} + "
                    f"new-account surcharge {NEW_ACCOUNT_FEE}); got {tx.fee}"
                )

        # Resolve the pubkey we should verify against.  Two paths:
        #  (a) entity already known on chain -> use stored pubkey, and
        #      reject any non-empty sender_pubkey as malleability.
        #  (b) entity unknown -> require sender_pubkey in the tx,
        #      derive entity_id from it, verify the derivation matches,
        #      then use it for signature verification.
        if tx.entity_id in self.public_keys:
            if tx.sender_pubkey:
                return False, (
                    "sender_pubkey must be empty for an already-registered "
                    "entity — first-spend reveal is one-shot"
                )
            verifying_pubkey = self.public_keys[tx.entity_id]
            is_first_spend = False
        else:
            if not tx.sender_pubkey:
                return False, (
                    f"Entity {tx.entity_id.hex()[:16]} has no registered "
                    f"pubkey — first outgoing transfer must include "
                    f"sender_pubkey"
                )
            if derive_entity_id(tx.sender_pubkey) != tx.entity_id:
                return False, (
                    "sender_pubkey does not derive the claimed entity_id "
                    "(hash mismatch)"
                )
            verifying_pubkey = tx.sender_pubkey
            is_first_spend = True

        # Nonce.  For an entity that's never spent before, the expected
        # nonce is 0 (unless the caller has pinned something higher —
        # mempool pipelining).  self.nonces.get falls back to 0, which
        # is exactly what we want for first-spend.
        effective_nonce = (
            expected_nonce if expected_nonce is not None
            else self.nonces.get(tx.entity_id, 0)
        )
        if tx.nonce != effective_nonce:
            return False, f"Invalid nonce: expected {effective_nonce}, got {tx.nonce}"

        if self.get_spendable_balance(tx.entity_id) < tx.amount + tx.fee:
            return False, f"Insufficient spendable balance for transfer of {tx.amount} + fee {tx.fee}"

        # Leaf-reuse guard against the entity's own watermark (even
        # first-spend cases: if a burnt leaf was seen via some other
        # path, e.g. an attestation or proposer sig on a funded
        # validator-in-waiting, we must still refuse to accept its
        # reuse).
        if tx.signature.leaf_index < self.leaf_watermarks.get(tx.entity_id, 0):
            return False, (
                f"WOTS+ leaf {tx.signature.leaf_index} already consumed "
                f"(watermark {self.leaf_watermarks[tx.entity_id]}) — leaf reuse rejected"
            )

        if not verify_transfer_transaction(tx, verifying_pubkey):
            return False, "Invalid signature"

        return True, "Valid"

    def apply_transfer_transaction(self, tx: TransferTransaction, proposer_id: bytes):
        """Apply a validated transfer.

        Moves `tx.amount` from sender to recipient and credits `tx.fee`
        (minus the new-account surcharge, if applicable) to `proposer_id`.
        Implicitly:
          * creates a balance entry for the recipient if they were
            previously unknown; and
          * on first-spend (sender_pubkey populated + no existing
            pubkey in state) installs the sender's pubkey, initializes
            nonce to 0, and assigns their entity_index.

        Surcharge accounting: if the recipient was brand-new at call
        time, NEW_ACCOUNT_FEE of the tx fee is burned (total_supply
        decreases; total_burned increases) and the proposer only
        receives (tx.fee - NEW_ACCOUNT_FEE).  Permanent state entry →
        permanent supply reduction.
        """
        # Must snapshot "is recipient new" BEFORE any state mutation.
        recipient_was_new = self._recipient_is_new(tx.recipient_id)

        # First-spend pubkey install: runs BEFORE the balance/nonce
        # mutations so the state-tree sync captures the new pubkey in
        # the same _touch_state sweep the caller is about to do.
        if tx.sender_pubkey and tx.entity_id not in self.public_keys:
            self.public_keys[tx.entity_id] = tx.sender_pubkey
            # Nonce 0 is the genesis nonce for first-spend; the
            # `self.nonces[tx.entity_id] = tx.nonce + 1` at the bottom
            # of this function bumps it to 1.
            self.nonces.setdefault(tx.entity_id, 0)
            self._assign_entity_index(tx.entity_id)
            if self.db is not None:
                self.db.set_public_key(tx.entity_id, tx.sender_pubkey)

        # Surcharge burn for brand-new recipient.
        surcharge = NEW_ACCOUNT_FEE if recipient_was_new else 0
        proposer_credit = tx.fee - surcharge

        self.supply.balances[tx.entity_id] = self.supply.get_balance(tx.entity_id) - tx.amount - tx.fee
        self.supply.balances[tx.recipient_id] = self.supply.get_balance(tx.recipient_id) + tx.amount
        self.supply.balances[proposer_id] = self.supply.get_balance(proposer_id) + proposer_credit
        if surcharge > 0:
            self.supply.total_supply -= surcharge
            self.supply.total_burned += surcharge
        self.supply.total_fees_collected += tx.fee
        self.nonces[tx.entity_id] = tx.nonce + 1
        self._bump_watermark(tx.entity_id, tx.signature.leaf_index)

    def apply_stake_transaction(self, tx, proposer_id: bytes):
        """Apply a validated stake transaction (standalone, outside block apply).

        Receive-to-exist first-spend: on a stake from an entity that
        isn't yet in `self.public_keys` and that carries a non-empty
        `sender_pubkey`, install the pubkey BEFORE the balance/stake/
        nonce mutations so the state-tree sync captures the new pubkey.

        This path is exercised by standalone tests and by any caller
        applying a single stake outside the block pipeline.  The block
        pipeline's inline loop in `_apply_block_state` performs the
        same mutations in the same order.
        """
        # First-spend pubkey install (mirrors apply_transfer_transaction).
        if (
            getattr(tx, "sender_pubkey", b"")
            and tx.entity_id not in self.public_keys
        ):
            self.public_keys[tx.entity_id] = tx.sender_pubkey
            self.nonces.setdefault(tx.entity_id, 0)
            self._assign_entity_index(tx.entity_id)
            if self.db is not None:
                self.db.set_public_key(tx.entity_id, tx.sender_pubkey)

        # Pay fee (tip to proposer, base burned) — same semantics as the
        # block-apply path so standalone callers can't accidentally skip
        # the burn.
        if not self.supply.pay_fee_with_burn(
            tx.entity_id, proposer_id, tx.fee, self.supply.base_fee,
        ):
            logger.error(
                f"Stake tx {tx.tx_hash.hex()[:16]} fee payment failed"
            )
            return
        staked_ok = self.supply.stake(tx.entity_id, tx.amount)
        if not staked_ok:
            logger.error(
                f"Stake tx {tx.tx_hash.hex()[:16]} failed at apply-time "
                f"(validate_stake not called?)"
            )
        self.nonces[tx.entity_id] = tx.nonce + 1
        self._bump_watermark(tx.entity_id, tx.signature.leaf_index)

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

        if tx.signature.leaf_index < self.leaf_watermarks.get(tx.entity_id, 0):
            return False, (
                f"WOTS+ leaf {tx.signature.leaf_index} already consumed "
                f"(watermark {self.leaf_watermarks[tx.entity_id]}) — leaf reuse rejected"
            )

        if not verify_key_rotation(tx, current_pk):
            return False, "Invalid key rotation signature or parameters"

        return True, "Valid"

    def apply_key_rotation(self, tx: KeyRotationTransaction, proposer_id: bytes) -> tuple[bool, str]:
        """Validate and apply a key rotation, updating the entity's public key."""
        valid, reason = self.validate_key_rotation(tx)
        if not valid:
            return False, reason

        # Pay fee with burn (same as all other tx types — base fee burned, tip to proposer)
        if not self.supply.pay_fee_with_burn(tx.entity_id, proposer_id, tx.fee, self.supply.base_fee):
            return False, f"Fee payment failed (fee {tx.fee} vs base_fee {self.supply.base_fee})"

        # Rotation installs a fresh Merkle tree whose leaf indices re-count
        # from 0, independent of the old tree. Reset the watermark to 0 so
        # the new tree starts clean. The old tree's leaves (including the
        # one consumed to sign this rotation) are permanently unusable
        # regardless, because that key is no longer bound to this entity.
        self.leaf_watermarks[tx.entity_id] = 0

        # Update the entity's public key
        self.public_keys[tx.entity_id] = tx.new_public_key
        self.key_rotation_counts[tx.entity_id] = tx.rotation_number + 1

        # Persist
        if self.db is not None:
            self.db.set_public_key(tx.entity_id, tx.new_public_key)
            if hasattr(self.db, 'set_leaf_watermark'):
                self.db.set_leaf_watermark(tx.entity_id, 0)
            if hasattr(self.db, 'set_key_rotation_count'):
                self.db.set_key_rotation_count(
                    tx.entity_id, self.key_rotation_counts[tx.entity_id],
                )
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
        from messagechain.consensus.finality import (
            FinalityDoubleVoteEvidence, verify_finality_double_vote_evidence,
        )
        if isinstance(tx.evidence, AttestationSlashingEvidence):
            valid, reason = verify_attestation_slashing_evidence(tx.evidence, offender_pk)
        elif isinstance(tx.evidence, FinalityDoubleVoteEvidence):
            valid, reason = verify_finality_double_vote_evidence(tx.evidence, offender_pk)
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
        if hasattr(evidence, 'vote_a'):
            # FinalityDoubleVoteEvidence: use the target block number.
            return evidence.vote_a.target_block_number
        return None

    def apply_slash_transaction(self, tx: SlashTransaction, proposer_id: bytes) -> tuple[bool, str]:
        """Validate and apply a slash transaction."""
        valid, reason = self.validate_slash_transaction(tx)
        if not valid:
            return False, reason

        # Pay fee with burn (same as all other tx types — base fee burned, tip to proposer)
        if not self.supply.pay_fee_with_burn(tx.submitter_id, proposer_id, tx.fee, self.supply.base_fee):
            return False, f"Fee payment failed (fee {tx.fee} vs base_fee {self.supply.base_fee})"

        # Slash the offender: burn stake, burn bootstrap-era escrow.
        # Escrow burn happens BEFORE the stake burn returns so the
        # logged totals reflect the full penalty.  Bootstrap escrow
        # captures rewards earned during the slashable window — if the
        # offender was accumulating honest-looking rewards while also
        # equivocating, those rewards evaporate.  Tokens previously
        # credited to supply.balances are reclaimed via the supply
        # tracker's reduction path.
        escrow_burned = self._escrow.slash_all(tx.evidence.offender_id)
        if escrow_burned > 0:
            # Reduce both balance (tokens were credited there at mint)
            # and total_supply (escrow-burn is a permanent destruction,
            # same as stake-burn).
            cur_balance = self.supply.balances.get(tx.evidence.offender_id, 0)
            self.supply.balances[tx.evidence.offender_id] = max(
                0, cur_balance - escrow_burned,
            )
            self.supply.total_supply -= escrow_burned

        slashed, finder_reward = self.supply.slash_validator(
            tx.evidence.offender_id, tx.submitter_id
        )
        self.slashed_validators.add(tx.evidence.offender_id)
        self._processed_evidence.add(tx.evidence.evidence_hash)
        # Reputation reset: a slashed validator forfeits all accumulated
        # reputation and re-enters the lottery pool (if at all) as a
        # zero-reputation newcomer.  Prevents the "misbehave once, earn
        # back your reputation from cached history" attack.
        self.reputation.pop(tx.evidence.offender_id, None)

        logger.info(
            f"SLASHED validator {tx.evidence.offender_id.hex()[:16]}: "
            f"stake_burned={slashed - finder_reward}, "
            f"escrow_burned={escrow_burned}, "
            f"finder_reward={finder_reward}"
        )

        return True, (
            f"Validator slashed "
            f"(stake={slashed}, escrow={escrow_burned}, "
            f"reward={finder_reward})"
        )

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

    def get_escrowed_balance(self, entity_id: bytes) -> int:
        """Total attester rewards currently held in the escrow lock.

        Escrow is a parallel lock on top of balance — the tokens have
        been credited to `supply.balances` (so they're in the state
        tree), but they are not spendable until the escrow window
        elapses or a stage-4 slashing event burns them.
        """
        return self._escrow.total_escrowed(entity_id)

    def get_spendable_balance(self, entity_id: bytes) -> int:
        """Spendable balance = balance minus (immature + escrow) locks.

        Three concurrent lock sources, all subtracted:
          * immature: coinbase-maturity lock, 10 blocks, ~100 min
          * escrow:   bootstrap-era slashing window, up to 12,960 blocks
          * (stake is already excluded — `balance` only holds liquid tokens)

        Floor at 0 — tracking corruption must never produce a negative
        spendable balance that could be misinterpreted as a large
        positive value by callers expecting unsigned semantics.
        """
        total = self.supply.get_balance(entity_id)
        immature = self.get_immature_balance(entity_id)
        escrowed = self.get_escrowed_balance(entity_id)
        return max(0, total - immature - escrowed)

    def _touch_state(self, entity_ids):
        """Sync the state tree with current dicts for the given entities.

        Called whenever code mutates any per-entity state — balances,
        nonces, stake, cold authority key, signing public key, WOTS+
        leaf watermark, rotation count, or revoked flag.  All of these
        are inside the leaf commitment, so any mutation must end in a
        _touch_state call or the block's state_root will not match what
        validators reconstruct.  Cheap — O(len(entity_ids) * TREE_DEPTH).
        """
        for eid in entity_ids:
            self.state_tree.set(
                eid,
                self.supply.balances.get(eid, 0),
                self.nonces.get(eid, 0),
                self.supply.staked.get(eid, 0),
                authority_key=self.authority_keys.get(eid, b""),
                public_key=self.public_keys.get(eid, b""),
                leaf_watermark=self.leaf_watermarks.get(eid, 0),
                rotation_count=self.key_rotation_counts.get(eid, 0),
                is_revoked=(eid in self.revoked_entities),
                is_slashed=(eid in self.slashed_validators),
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
        # Union every source of per-entity state so an entity that shows
        # up only in authority_keys, revoked_entities, or slashed_validators
        # still lands in the tree.  Otherwise a post-rebuild root would
        # omit that leaf and differ from the incremental root validators
        # compute.
        live_keys = (
            set(self.supply.balances) | set(self.nonces)
            | set(self.supply.staked) | set(self.authority_keys)
            | set(self.public_keys) | set(self.leaf_watermarks)
            | set(self.key_rotation_counts) | set(self.revoked_entities)
            | set(self.slashed_validators)
        )
        # Drop entries the tree holds that have been deleted from live.
        tree_keys = set(self.state_tree._accounts.keys())
        for eid in tree_keys - live_keys:
            self.state_tree.remove(eid)
        # Upsert everything else; set() is idempotent on unchanged tuples.
        for eid in live_keys:
            self.state_tree.set(
                eid,
                self.supply.balances.get(eid, 0),
                self.nonces.get(eid, 0),
                self.supply.staked.get(eid, 0),
                authority_key=self.authority_keys.get(eid, b""),
                public_key=self.public_keys.get(eid, b""),
                leaf_watermark=self.leaf_watermarks.get(eid, 0),
                rotation_count=self.key_rotation_counts.get(eid, 0),
                is_revoked=(eid in self.revoked_entities),
                is_slashed=(eid in self.slashed_validators),
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
        authority_txs: list | None = None,
        stake_transactions: list | None = None,
        unstake_transactions: list | None = None,
        governance_txs: list | None = None,
        finality_votes: list | None = None,
        proposer_signature_leaf_index: int | None = None,
    ) -> bytes:
        """Compute the state root AFTER applying a set of transactions.

        Used by block proposers to compute the correct post-state commitment
        without actually mutating chain state. The block header commits to
        the post-application state so validators can verify consistency.

        `proposer_signature_leaf_index` is a heuristic.  The proposer's
        block signature consumes a WOTS+ leaf, and the apply path bumps
        the proposer's leaf_watermark to (leaf_index + 1).  That mutation
        lives inside the state_root commitment, so the sim has to predict
        it before the block is actually signed.

        Two callers always know the right value and pass it explicitly:
          * propose_block → proposer_entity.keypair._next_leaf
          * validate (add_block pre-check) → block.header.proposer_signature.leaf_index

        Callers who don't supply it (older test helpers that build a
        block via consensus.create_block directly) hit the default
        below: "the proposer's upcoming signature will consume the next
        leaf after the live watermark."  That's the canonical case — a
        proposer signing one block per slot with nothing else in flight.
        It breaks if a proposer has consumed keypair leaves out-of-band
        (e.g., pre-signing messages or extra governance txs not yet in
        the chain).  The mismatch surfaces as a state_root rejection at
        add_block, not silent corruption, so the blast radius is
        "callers must pass the explicit index in those edge cases," not
        a consensus hazard.
        """
        from messagechain.config import (
            PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR,
            PROPOSER_REWARD_CAP, TREASURY_ENTITY_ID,
        )
        sim_balances = dict(self.supply.balances)
        sim_nonces = dict(self.nonces)
        sim_staked = dict(self.supply.staked)
        # Authority-side state — included in the leaf commitment, so the
        # simulation must track every mutation path that _apply_block_state
        # performs.  Missing a field here means honest validators reject
        # otherwise-valid blocks with a state_root mismatch.
        sim_authority_keys = dict(self.authority_keys)
        sim_public_keys = dict(self.public_keys)
        sim_leaf_watermarks = dict(self.leaf_watermarks)
        sim_rotation_counts = dict(self.key_rotation_counts)
        sim_revoked = set(self.revoked_entities)
        sim_slashed = set(self.slashed_validators)
        current_base_fee = self.supply.base_fee

        def _bump_wm(eid: bytes, leaf_index: int) -> None:
            """Mirror Blockchain._bump_watermark: monotonic next-leaf cursor."""
            nxt = leaf_index + 1
            if nxt > sim_leaf_watermarks.get(eid, 0):
                sim_leaf_watermarks[eid] = nxt

        # Simulate fee payments for message transactions (with burn)
        for tx in transactions:
            # M1/M2: Clamp tip to >= 0 to prevent negative balances
            effective_base_fee = min(current_base_fee, tx.fee)
            tip = tx.fee - effective_base_fee
            sim_balances[tx.entity_id] = sim_balances.get(tx.entity_id, 0) - tx.fee
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
            # base_fee is burned — not added to any balance
            sim_nonces[tx.entity_id] = tx.nonce + 1
            _bump_wm(tx.entity_id, tx.signature.leaf_index)

        # Simulate transfer transactions (with burn).  Mirrors
        # _apply_transfer_with_burn: on a first-spend tx (sender_pubkey
        # populated + entity not yet in sim_public_keys), install the
        # pubkey so the committed state root matches the apply-path
        # mutation.  Also mirrors the NEW_ACCOUNT_FEE surcharge: when
        # the recipient is brand-new, NEW_ACCOUNT_FEE is burned and the
        # proposer tip is correspondingly reduced.
        def _sim_recipient_is_new(rid: bytes) -> bool:
            """Brand-new iff no on-chain state at all in the sim.

            Checks every per-entity source the SMT would commit to;
            mirrors self._recipient_is_new but against sim_* dicts so
            intra-block pipelining is captured naturally (once tx1
            upserts sim_balances[rid], tx2 sees it and skips the
            surcharge)."""
            if rid in sim_balances:
                return False
            if rid in sim_staked:
                return False
            if rid in sim_public_keys:
                return False
            if rid in sim_authority_keys:
                return False
            if rid in sim_leaf_watermarks:
                return False
            if rid in sim_rotation_counts:
                return False
            if rid in sim_revoked:
                return False
            if rid in sim_slashed:
                return False
            # Fall back to blockchain's own canonical check for fields
            # the sim doesn't maintain separately (e.g., entity_id_to_index
            # and nonces outside sim_nonces' view).
            return self._recipient_is_new(rid)

        for ttx in (transfer_transactions or []):
            if (
                getattr(ttx, "sender_pubkey", b"")
                and ttx.entity_id not in sim_public_keys
            ):
                sim_public_keys[ttx.entity_id] = ttx.sender_pubkey
            recipient_was_new = _sim_recipient_is_new(ttx.recipient_id)
            effective_base_fee = min(current_base_fee, ttx.fee)
            surcharge = NEW_ACCOUNT_FEE if recipient_was_new else 0
            if effective_base_fee + surcharge > ttx.fee:
                surcharge = max(0, ttx.fee - effective_base_fee)
            tip = ttx.fee - effective_base_fee - surcharge
            sim_balances[ttx.entity_id] = sim_balances.get(ttx.entity_id, 0) - ttx.amount - ttx.fee
            sim_balances[ttx.recipient_id] = sim_balances.get(ttx.recipient_id, 0) + ttx.amount
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
            # Note: surcharge burn reduces total_supply but NOT any
            # per-entity balance (it's truly destroyed).  The state_root
            # commits only to per-entity state, so we do not need to
            # reflect the burn itself anywhere in the sim state.
            sim_nonces[ttx.entity_id] = ttx.nonce + 1
            _bump_wm(ttx.entity_id, ttx.signature.leaf_index)

        # Simulate authority transactions — fee-with-burn plus each
        # type's distinctive authority-state mutation.  Keep in lockstep
        # with _apply_authority_tx: any field the apply path mutates MUST
        # be mutated here too, or the post-apply state_root won't match
        # and honest validators reject the block.
        for atx in (authority_txs or []):
            effective_base_fee = min(current_base_fee, atx.fee)
            tip = atx.fee - effective_base_fee
            sim_balances[atx.entity_id] = sim_balances.get(atx.entity_id, 0) - atx.fee
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
            cls_name = atx.__class__.__name__
            if cls_name == "SetAuthorityKeyTransaction":
                sim_nonces[atx.entity_id] = atx.nonce + 1
                sim_authority_keys[atx.entity_id] = atx.new_authority_key
                _bump_wm(atx.entity_id, atx.signature.leaf_index)
            elif cls_name == "RevokeTransaction":
                # Revoke: active stake → pending unbonding, revoked flag
                # set.  Nonce-free.  Signature consumed a leaf in the COLD
                # tree, so the apply path deliberately does NOT bump the
                # hot-key watermark — mirror that.
                sim_staked[atx.entity_id] = 0
                sim_revoked.add(atx.entity_id)
            elif cls_name == "KeyRotationTransaction":
                # Rotation swaps the signing key and resets the hot-key
                # watermark (new key = fresh leaf namespace).  Rotation
                # counter bumps so the next rotation must reference a
                # higher number.
                sim_public_keys[atx.entity_id] = atx.new_public_key
                sim_rotation_counts[atx.entity_id] = atx.rotation_number + 1
                sim_leaf_watermarks[atx.entity_id] = 0

        # Simulate stake transactions — fee (burn + tip), nonce bump, and
        # the actual stake movement from liquid balance to staked balance.
        # Must mirror the apply path exactly; any drift here and validators
        # reject otherwise-valid blocks with a state_root mismatch.
        # Clamp at 0 when the sender lacks balance — validate_block's
        # `_validate_stake_tx_in_block` will reject such a tx.  Clamping
        # here keeps the simulation from raising (e.g., on struct-packing
        # a negative value) when a dishonest proposer includes a bad tx.
        #
        # Receive-to-exist first-spend: if a stake carries sender_pubkey
        # and the entity isn't yet in sim_public_keys, install it here
        # so the committed state root matches the apply-path mutation
        # (see apply path's "first-spend pubkey install" block above).
        for stx in (stake_transactions or []):
            if (
                getattr(stx, "sender_pubkey", b"")
                and stx.entity_id not in sim_public_keys
            ):
                sim_public_keys[stx.entity_id] = stx.sender_pubkey
            effective_base_fee = min(current_base_fee, stx.fee)
            tip = stx.fee - effective_base_fee
            new_bal = sim_balances.get(stx.entity_id, 0) - stx.fee - stx.amount
            sim_balances[stx.entity_id] = max(new_bal, 0)
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
            sim_staked[stx.entity_id] = sim_staked.get(stx.entity_id, 0) + stx.amount
            sim_nonces[stx.entity_id] = stx.nonce + 1
            _bump_wm(stx.entity_id, stx.signature.leaf_index)

        # Simulate unstake transactions: fee burn, stake moves to pending
        # unbond (out of the active stake set for finality purposes, not
        # yet liquid).  State root only commits to active staked amount,
        # so subtracting from sim_staked is all we need.  Liquid balance
        # only changes when unbonding matures UNBONDING_PERIOD blocks
        # later (release_pending_unstakes) — not affected here.
        for utx in (unstake_transactions or []):
            effective_base_fee = min(current_base_fee, utx.fee)
            tip = utx.fee - effective_base_fee
            sim_balances[utx.entity_id] = max(
                sim_balances.get(utx.entity_id, 0) - utx.fee, 0
            )
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
            current_staked = sim_staked.get(utx.entity_id, 0)
            sim_staked[utx.entity_id] = max(current_staked - utx.amount, 0)
            sim_nonces[utx.entity_id] = utx.nonce + 1
            # Hot watermark bumps when the unstake was signed by the hot
            # key (single-key mode) — mirrors _apply_authority_tx's
            # conditional bump.
            ak_sim = sim_authority_keys.get(
                utx.entity_id, self.authority_keys.get(utx.entity_id, b""),
            )
            pk_sim = sim_public_keys.get(
                utx.entity_id, self.public_keys.get(utx.entity_id, b""),
            )
            if (ak_sim == b"" and pk_sim != b"") or ak_sim == pk_sim:
                _bump_wm(utx.entity_id, utx.signature.leaf_index)

        # Receive-to-exist: no separate registration simulation needed.
        # The transfer simulation above already installs pubkeys via the
        # `sim_public_keys[ttx.entity_id] = ttx.sender_pubkey` branch
        # for first-spend txs, keeping sim and apply paths in lockstep.

        # Simulate seed divestment — must byte-mirror _apply_seed_divestment.
        # Runs before attester-committee candidate selection so the seed's
        # reduced stake is reflected in committee weights for this block.
        # The snapshot dict is read-only here (sim does not persist its
        # first-block capture); the apply path owns the mutation.
        from messagechain.config import (
            SEED_DIVESTMENT_START_HEIGHT as _SDS,
            SEED_DIVESTMENT_END_HEIGHT as _SDE,
            SEED_DIVESTMENT_TREASURY_BPS as _SDT,
        )
        if (
            block_height > _SDS
            and block_height <= _SDE
            and self.seed_entity_ids
        ):
            _window = _SDE - _SDS
            for _seid in self.seed_entity_ids:
                # Apply path snapshots at the first divestment block from
                # live stake; on replay the same capture reproduces.  We
                # mirror that here: if the entry isn't yet in the live
                # dict, read the current live (pre-divestment) stake.
                _init = self.seed_initial_stakes.get(
                    _seid, sim_staked.get(_seid, 0),
                )
                if _init <= 0:
                    continue
                _per_block = _init // _window
                if _per_block <= 0:
                    continue
                _current = sim_staked.get(_seid, 0)
                _divest = min(_per_block, _current)
                if _divest <= 0:
                    continue
                _treasury_share = _divest * _SDT // 10_000
                sim_staked[_seid] = _current - _divest
                if _treasury_share > 0:
                    sim_balances[TREASURY_ENTITY_ID] = (
                        sim_balances.get(TREASURY_ENTITY_ID, 0) + _treasury_share
                    )
                # Burn portion reduces total_supply — not represented in
                # the per-entity state tree, so no sim_balances change.

        # Simulate block reward: committee-based attester distribution +
        # proposer share + PROPOSER_REWARD_CAP overflow.  Must mirror
        # mint_block_reward byte-for-byte; any divergence here produces
        # an "Invalid state_root" rejection on add_block.
        from messagechain.consensus.attester_committee import (
            ATTESTER_REWARD_PER_SLOT, select_attester_committee,
        )
        reward = self.supply.calculate_block_reward(block_height)
        is_bootstrap = not any(s > 0 for s in sim_staked.values())
        effective_cap = reward if is_bootstrap else PROPOSER_REWARD_CAP
        proposer_share = reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
        attester_pool = reward - proposer_share

        # Candidate pool (who attested) with their current stake.  Zero
        # stake is allowed — early-bootstrap validators register without
        # staking.  weights_for_progress falls back to uniform when all
        # stakes are zero.
        attester_candidates: list[tuple[bytes, int]] = []
        if attestations:
            for att in attestations:
                attester_candidates.append(
                    (att.validator_id, sim_staked.get(att.validator_id, 0))
                )

        # Randomness for deterministic committee selection.  Uses the
        # parent block's randao_mix rather than its full block_hash:
        # randao_mix is an accumulator specifically designed for
        # unpredictable randomness (hashed forward through every
        # proposer's signature), so a single parent proposer can't
        # grind their block contents to shape the next block's
        # committee nearly as freely.  Available at both call sites
        # (sim here, apply below) via the parent block in self.chain.
        parent_randao = (
            self.chain[-1].header.randao_mix
            if self.chain else b"\x00" * 32
        )
        committee_size = attester_pool // ATTESTER_REWARD_PER_SLOT
        attester_committee = select_attester_committee(
            candidates=attester_candidates,
            seed_entity_ids=self.seed_entity_ids,
            bootstrap_progress=self.bootstrap_progress,
            randomness=parent_randao,
            committee_size=committee_size,
        ) if attester_candidates else []

        if attester_committee:
            # Credit 1 ATTESTER_REWARD_PER_SLOT per committee member.
            attester_tokens_paid = 0
            for eid in attester_committee[:committee_size]:
                sim_balances[eid] = sim_balances.get(eid, 0) + ATTESTER_REWARD_PER_SLOT
                attester_tokens_paid += ATTESTER_REWARD_PER_SLOT
            treasury_excess = attester_pool - attester_tokens_paid

            # Proposer-cap check (matches mint_block_reward).
            proposer_att_reward = (
                ATTESTER_REWARD_PER_SLOT if proposer_id in attester_committee else 0
            )
            proposer_total = proposer_share + proposer_att_reward
            if proposer_total > effective_cap:
                overage = proposer_total - effective_cap
                treasury_excess += overage
                sim_balances[proposer_id] = (
                    sim_balances.get(proposer_id, 0) - proposer_att_reward
                )

            sim_balances[proposer_id] = (
                sim_balances.get(proposer_id, 0) + proposer_share
            )
            if treasury_excess > 0:
                sim_balances[TREASURY_ENTITY_ID] = (
                    sim_balances.get(TREASURY_ENTITY_ID, 0) + treasury_excess
                )
        else:
            # No attesters — proposer absorbs whole reward (capped).
            proposer_reward = min(reward, effective_cap)
            treasury_excess = reward - proposer_reward
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + proposer_reward
            if treasury_excess > 0:
                sim_balances[TREASURY_ENTITY_ID] = sim_balances.get(TREASURY_ENTITY_ID, 0) + treasury_excess

        # Simulate bootstrap lottery.  Must byte-mirror apply path —
        # at block_height % LOTTERY_INTERVAL == 0, compute the
        # progress-faded bounty and, if > 0, credit it to the winner's
        # balance.  Reputation snapshot used here is the pre-
        # attestation-of-this-block state (matches apply: lottery runs
        # before _process_attestations updates self.reputation with the
        # current block's attestations).
        from messagechain.config import (
            LOTTERY_INTERVAL as _LI,
            LOTTERY_BOUNTY as _LB,
            REPUTATION_CAP as _RC,
        )
        if block_height > 0 and block_height % _LI == 0:
            from messagechain.consensus.reputation_lottery import (
                select_lottery_winner, lottery_bounty_for_progress,
            )
            _bounty = lottery_bounty_for_progress(
                self.bootstrap_progress, full_bounty=_LB,
            )
            if _bounty > 0:
                _winner = select_lottery_winner(
                    candidates=list(self.reputation.items()),
                    seed_entity_ids=self.seed_entity_ids,
                    randomness=parent_randao,
                    reputation_cap=_RC,
                )
                if _winner is not None:
                    sim_balances[_winner] = (
                        sim_balances.get(_winner, 0) + _bounty
                    )

        # Apply-path parity for signature-driven watermark bumps.  Order
        # matters: attestations run first because the same entity can be
        # both a proposer and an attestor — chronologically they sign the
        # attestation, then sign the block, so the proposer sig consumes
        # a later leaf than any of their own attestations.  Bumping
        # attestations first makes the proposer's "next leaf" default
        # (read below) reflect those already-consumed leaves.
        #
        # The apply path itself is order-insensitive (_bump_watermark
        # takes a max), so either ordering produces identical results on
        # the apply side — this ordering only matters for the sim's
        # default prediction.
        for att in (attestations or []):
            _bump_wm(att.validator_id, att.signature.leaf_index)
        # Proposer's block signature — at propose time the block hasn't
        # been signed yet, so callers who know the upcoming leaf
        # (propose_block: proposer.keypair._next_leaf; validate path:
        # block.header.proposer_signature.leaf_index) pass it explicitly.
        # When unspecified we fall back to the live watermark — the
        # canonical value for a proposer signing one block per slot.
        if proposer_signature_leaf_index is None:
            proposer_signature_leaf_index = sim_leaf_watermarks.get(
                proposer_id, 0,
            )
        _bump_wm(proposer_id, proposer_signature_leaf_index)

        # Simulate governance-tx fees + auto-executed binding proposals.
        # _apply_governance_block runs AFTER block-reward mint, so this
        # block simulates the same order.  We reuse the live GovernanceTracker
        # and SupplyTracker via shallow clones so the simulation paths call
        # the same tally/execute code that the apply path runs — no risk of
        # the two drifting.
        gov_present = (
            (governance_txs and len(governance_txs) > 0)
            or (hasattr(self, "governance") and self.governance is not None
                and len(self.governance.proposals) > 0)
        )
        if gov_present:
            import copy as _copy
            from messagechain.config import GOVERNANCE_VOTING_WINDOW
            from messagechain.governance.governance import (
                ProposalTransaction, VoteTransaction,
                TreasurySpendTransaction,
            )

            sim_supply = _copy.copy(self.supply)
            sim_supply.balances = dict(sim_balances)
            sim_supply.staked = dict(sim_staked)
            sim_supply.pending_unstakes = {
                k: list(v) for k, v in self.supply.pending_unstakes.items()
            }
            sim_supply.base_fee = current_base_fee

            sim_tracker = _copy.deepcopy(self.governance)

            # Phase 1: register this block's governance txs on the sim tracker
            # and burn/pay fees through the sim supply.
            for gtx in (governance_txs or []):
                if isinstance(gtx, (ProposalTransaction,
                                    TreasurySpendTransaction)):
                    sender = gtx.proposer_id
                elif isinstance(gtx, VoteTransaction):
                    sender = gtx.voter_id
                else:
                    continue
                sim_supply.pay_fee_with_burn(
                    sender, proposer_id, gtx.fee, sim_supply.base_fee,
                )
                _bump_wm(sender, gtx.signature.leaf_index)
                if isinstance(gtx, (ProposalTransaction,
                                    TreasurySpendTransaction)):
                    sim_tracker.add_proposal(
                        gtx, block_height=block_height,
                        supply_tracker=sim_supply,
                    )
                elif isinstance(gtx, VoteTransaction):
                    sim_tracker.add_vote(gtx, current_block=block_height)

            # Phase 2: auto-execute closed treasury spends.  Must mirror
            # the apply-path ordering and predicates exactly.
            for pid, state in list(sim_tracker.proposals.items()):
                proposal = state.proposal
                if not isinstance(proposal, TreasurySpendTransaction):
                    continue
                if block_height - state.created_at_block <= GOVERNANCE_VOTING_WINDOW:
                    continue
                # New-account surcharge is charged if the recipient is
                # brand-new.  In sim, "brand-new" means absent from every
                # live dict.  We use the same helper as the real path so
                # byte-for-byte burn semantics match.
                def _sim_is_new(rid: bytes) -> bool:
                    if rid in sim_supply.balances:
                        return False
                    if rid in sim_supply.staked:
                        return False
                    return self._recipient_is_new(rid)
                sim_tracker.execute_treasury_spend(
                    proposal, sim_supply, current_block=block_height,
                    is_new_account=_sim_is_new,
                )

            # Read the post-governance state back into sim_* for state_root
            sim_balances = dict(sim_supply.balances)
            sim_staked = dict(sim_supply.staked)

        # Simulate finality votes.  Two side effects touch the state
        # root:
        #   a) treasury → proposer bounty of FINALITY_VOTE_INCLUSION_REWARD
        #      per vote (capped at available treasury balance)
        #   b) signer's leaf watermark bumps to (leaf_index + 1)
        # Must byte-mirror _apply_finality_votes or honest validators
        # will reject otherwise-valid blocks with a state_root mismatch.
        if finality_votes:
            from messagechain.config import (
                FINALITY_VOTE_INCLUSION_REWARD as _FVR,
            )
            for fv in finality_votes:
                _bump_wm(fv.signer_entity_id, fv.signature.leaf_index)
                if _FVR > 0:
                    _tbal = sim_balances.get(TREASURY_ENTITY_ID, 0)
                    _payout = min(_FVR, _tbal)
                    if _payout > 0:
                        sim_balances[TREASURY_ENTITY_ID] = _tbal - _payout
                        sim_balances[proposer_id] = (
                            sim_balances.get(proposer_id, 0) + _payout
                        )

        # Simulate inactivity leak — must mirror _apply_block_state.
        # The counter is incremented first; if the leak is active, inactive
        # validators have their sim_staked reduced.  The counter reset
        # from finalization happens in _process_attestations (after the
        # state root), so from the state root's perspective the counter
        # always increments.
        sim_blocks_since_fin = self.blocks_since_last_finalization + 1
        from messagechain.consensus.inactivity import (
            is_leak_active as _ila,
            get_inactive_validators as _giv,
            apply_inactivity_leak as _ail,
        )
        if _ila(sim_blocks_since_fin):
            _expected = {
                eid for eid, amt in sim_staked.items() if amt > 0
            }
            _actual = {
                att.validator_id for att in (attestations or [])
            }
            _inactive = _giv(_expected, _actual)
            if _inactive:
                _ail(sim_staked, sim_blocks_since_fin, _inactive,
                     min_stake=VALIDATOR_MIN_STAKE)

        return compute_state_root(
            sim_balances, sim_nonces, sim_staked,
            authority_keys=sim_authority_keys,
            public_keys=sim_public_keys,
            leaf_watermarks=sim_leaf_watermarks,
            key_rotation_counts=sim_rotation_counts,
            revoked_entities=sim_revoked,
            slashed_validators=sim_slashed,
        )

    def propose_block(
        self,
        consensus: "ProofOfStake",
        proposer_entity,
        transactions: list[MessageTransaction],
        attestations: list[Attestation] | None = None,
        transfer_transactions: list[TransferTransaction] | None = None,
        slash_transactions: list | None = None,
        governance_txs: list | None = None,
        authority_txs: list | None = None,
        stake_transactions: list | None = None,
        unstake_transactions: list | None = None,
        finality_votes: list | None = None,
        mempool_tx_hashes: list[bytes] | None = None,
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
        # Guard against WOTS+ leaf reuse: if the proposer also has
        # transactions in this block (signed earlier, possibly before a
        # keypair restart), the keypair's _next_leaf may not have been
        # advanced past those txs' leaves.  Advance past any such leaves
        # BEFORE reading expected_proposer_leaf — otherwise the state
        # root is computed with a stale leaf index and validators reject.
        proposer_id = proposer_entity.entity_id
        for tx_list in (
            transactions,
            transfer_transactions or [],
            slash_transactions or [],
            governance_txs or [],
            authority_txs or [],
            stake_transactions or [],
            unstake_transactions or [],
        ):
            for tx in tx_list:
                tx_entity = getattr(tx, "entity_id", None)
                if tx_entity == proposer_id:
                    sig = getattr(tx, "signature", None)
                    if sig is not None and hasattr(sig, "leaf_index"):
                        proposer_entity.keypair.advance_to_leaf(sig.leaf_index + 1)
        # The proposer's next signature will consume _next_leaf from their
        # keypair.  Read it BEFORE computing the state root so the sim
        # knows which watermark-bump the apply path will make after the
        # block is signed.  Without this, the committed state_root lags
        # the post-apply leaf_watermark by one and validators reject.
        expected_proposer_leaf = getattr(
            proposer_entity.keypair, "_next_leaf", None,
        )
        state_root = self.compute_post_state_root(
            transactions, proposer_entity.entity_id, block_height,
            transfer_transactions=transfer_transactions,
            attestations=attestations,
            authority_txs=authority_txs,
            stake_transactions=stake_transactions,
            unstake_transactions=unstake_transactions,
            governance_txs=governance_txs,
            finality_votes=finality_votes,
            proposer_signature_leaf_index=expected_proposer_leaf,
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
            governance_txs=governance_txs,
            authority_txs=authority_txs,
            stake_transactions=stake_transactions,
            unstake_transactions=unstake_transactions,
            finality_votes=finality_votes,
            timestamp=timestamp,
            mempool_tx_hashes=mempool_tx_hashes,
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

            # Reject attestations from emergency-revoked validators. The
            # cold-key holder has declared this hot key compromised; we
            # block its attestations for the same reason we block its
            # block proposals (see validate_block).  Without this a
            # revoked validator could still participate in finality and
            # move the justified/finalized tip while the operator watches.
            if att.validator_id in self.revoked_entities:
                return False, f"Attestation from revoked validator {att.validator_id.hex()[:16]}"

            # No duplicate attestations from same validator in one block
            if att.validator_id in seen_validators:
                return False, f"Duplicate attestation from {att.validator_id.hex()[:16]}"
            seen_validators.add(att.validator_id)

            # Verify signature
            pk = self.public_keys[att.validator_id]
            if not verify_attestation(att, pk):
                return False, f"Invalid attestation signature from {att.validator_id.hex()[:16]}"

        return True, "Attestations valid"

    def _validate_finality_votes(self, block: Block) -> tuple[bool, str]:
        """Validate all FinalityVotes embedded in a block.

        Checks:
        1. Count <= MAX_FINALITY_VOTES_PER_BLOCK (DoS guard)
        2. Each signer is a registered, non-revoked entity
        3. The target block exists in our local view (no votes for
           phantom blocks)
        4. Target block is not older than FINALITY_VOTE_MAX_AGE_BLOCKS
           below the current tip (prevents spam votes on ancient blocks)
        5. Each vote signature verifies under the signer's public key
        6. No two votes in the same block name the same signer at the
           same target height (a conflict in ONE block is a slashable
           offense too, but we reject the whole block first because
           it's provably malformed by the proposer)

        Returns (ok, reason).
        """
        from messagechain.config import (
            MAX_FINALITY_VOTES_PER_BLOCK, FINALITY_VOTE_MAX_AGE_BLOCKS,
        )
        votes = getattr(block, "finality_votes", [])
        if not votes:
            return True, "No finality votes"
        if len(votes) > MAX_FINALITY_VOTES_PER_BLOCK:
            return False, (
                f"Too many finality votes: {len(votes)} > "
                f"{MAX_FINALITY_VOTES_PER_BLOCK}"
            )
        seen_signer_height: set[tuple[bytes, int]] = set()
        current_height = block.header.block_number
        for v in votes:
            if v.signer_entity_id not in self.public_keys:
                return False, (
                    f"Finality vote from unknown entity "
                    f"{v.signer_entity_id.hex()[:16]}"
                )
            if v.signer_entity_id in self.revoked_entities:
                return False, (
                    f"Finality vote from revoked entity "
                    f"{v.signer_entity_id.hex()[:16]}"
                )
            if v.signer_entity_id in self.slashed_validators:
                return False, (
                    f"Finality vote from slashed entity "
                    f"{v.signer_entity_id.hex()[:16]}"
                )
            # Target block must be in our current view
            target = self.get_block_by_hash(v.target_block_hash)
            if target is None:
                return False, (
                    f"Finality vote targets unknown block "
                    f"{v.target_block_hash.hex()[:16]}"
                )
            if target.header.block_number != v.target_block_number:
                return False, (
                    f"Finality vote block_number {v.target_block_number} "
                    f"does not match target block's actual height "
                    f"{target.header.block_number}"
                )
            # Max-age horizon: votes on ancient blocks are rejected.
            # (Current block is being proposed; its number == parent+1.
            # We compare against the new height being validated.)
            if current_height - v.target_block_number > FINALITY_VOTE_MAX_AGE_BLOCKS:
                return False, (
                    f"Finality vote too old: target #{v.target_block_number} "
                    f"is more than {FINALITY_VOTE_MAX_AGE_BLOCKS} blocks "
                    f"below tip #{current_height}"
                )
            # Signature verification
            pk = self.public_keys[v.signer_entity_id]
            if not verify_finality_vote(v, pk):
                return False, (
                    f"Invalid finality vote signature from "
                    f"{v.signer_entity_id.hex()[:16]}"
                )
            # Reject block if a proposer packs two votes from the same
            # signer at the same height (self-conflicting block).  An
            # honest block author trims these; a malicious one produces
            # them as a griefing vector.  We reject the block outright
            # rather than half-apply the votes, and the slashable
            # offense still stands if the two conflicting votes reach
            # the slashing path via gossip.
            key = (v.signer_entity_id, v.target_block_number)
            if key in seen_signer_height:
                return False, (
                    f"Duplicate finality vote signer/height in block: "
                    f"{v.signer_entity_id.hex()[:16]} at "
                    f"#{v.target_block_number}"
                )
            seen_signer_height.add(key)
        return True, "Finality votes valid"

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
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        for att in block.attestations:
            # Reputation: +1 per accepted attestation in an applied
            # block.  Deterministic (same chain → same counts on every
            # node).  Read by the bootstrap lottery to pick a winner
            # every LOTTERY_INTERVAL blocks; drives "honest behavior =
            # real-time influence" during bootstrap.
            self.reputation[att.validator_id] = (
                self.reputation.get(att.validator_id, 0) + 1
            )
            target_block = att.block_number
            pinned = self._stake_snapshots.get(target_block)
            if pinned is not None:
                stakes_for_att = pinned
            else:
                stakes_for_att = stakes
            validator_stake = stakes_for_att.get(att.validator_id, 0)
            total_stake = sum(stakes_for_att.values())
            # Finality safety floor: independent of bootstrap_progress,
            # finalization always requires the active validator count
            # to meet the minimum.  Prevents a thinned-out chain from
            # finalizing via a single validator — 2/3 of tiny stake is
            # not a meaningful commitment.  See config comment: the
            # historical name reflects the old binary bootstrap flag;
            # the canonical bootstrap signal is bootstrap_progress.
            justified = self.finality.add_attestation(
                att, validator_stake, total_stake,
                min_validator_count=MIN_VALIDATORS_TO_EXIT_BOOTSTRAP,
            )
            if justified:
                # Reset inactivity leak counter: finalization resumed.
                # Penalties stop immediately on the next block.
                self.blocks_since_last_finalization = 0
                logger.info(
                    f"FINALIZED: block #{att.block_number} ({att.block_hash.hex()[:16]}) "
                    f"reached 2/3+ attestation threshold"
                )

    def _apply_finality_votes(self, block: Block, proposer_id: bytes):
        """Apply finality votes: bounty, watermark, checkpoint update.

        Called from _apply_block_state.  Every vote is individually
        validated at this point (validate_block already ran); here we
        just:

          1. Credit FINALITY_VOTE_INCLUSION_REWARD from the treasury
             entity to the proposer for each vote included.  If the
             treasury is short, we simply pay what the treasury has —
             keeps this from ever producing negative balances.
          2. Bump the signer's leaf watermark (a finality vote
             consumes a WOTS+ leaf just like any other signed
             artifact; observable on chain).
          3. Feed the vote into FinalityCheckpoints.  If the target
             crosses the 2/3-stake threshold, mark it finalized and
             persist the checkpoint so the long-range-defense rule
             survives restart.
          4. Pipe any auto-generated FinalityDoubleVoteEvidence into
             the slashing path so equivocating signers are burned
             100% immediately (same policy as double-attestation).
        """
        votes = getattr(block, "finality_votes", [])
        if not votes:
            return
        from messagechain.config import (
            FINALITY_VOTE_INCLUSION_REWARD, TREASURY_ENTITY_ID,
        )
        # 1+2: per-vote bounty and watermark
        for v in votes:
            self._bump_watermark(v.signer_entity_id, v.signature.leaf_index)
            if FINALITY_VOTE_INCLUSION_REWARD > 0:
                treasury_bal = self.supply.balances.get(TREASURY_ENTITY_ID, 0)
                payout = min(FINALITY_VOTE_INCLUSION_REWARD, treasury_bal)
                if payout > 0:
                    self.supply.balances[TREASURY_ENTITY_ID] = (
                        treasury_bal - payout
                    )
                    self.supply.balances[proposer_id] = (
                        self.supply.balances.get(proposer_id, 0) + payout
                    )

        # 3: checkpoint update.  Use the stake snapshot at the
        # target block so a validator who has since unstaked can
        # still be counted for finalizing a block they voted for.
        # Fall back to live staked map for very old targets whose
        # snapshot was pruned.
        for v in votes:
            pinned = self._stake_snapshots.get(v.target_block_number)
            stake_map = pinned if pinned is not None else dict(self.supply.staked)
            signer_stake = stake_map.get(v.signer_entity_id, 0)
            total_stake = sum(stake_map.values())
            crossed = self.finalized_checkpoints.add_vote(
                v, signer_stake, total_stake,
            )
            if crossed:
                # Persist the newly-finalized hash so a restart
                # rehydrates it and the reorg-rejection rule holds.
                if self.db is not None and hasattr(
                    self.db, "add_finalized_block",
                ):
                    self.db.add_finalized_block(
                        v.target_block_number, v.target_block_hash,
                    )
                logger.info(
                    f"FINALIZED via vote: block #{v.target_block_number} "
                    f"({v.target_block_hash.hex()[:16]}) crossed the "
                    f"2/3-stake commitment threshold"
                )

        # 4: auto-slash equivocating signers.  We produce evidence
        # but do NOT apply the slash here (slashing has its own
        # validation + on-chain evidence-tx flow).  Surface the
        # evidence on the Blockchain instance so operators / a
        # follow-up slash tx can consume it.  Re-use the existing
        # slashing plumbing: attach to the same list the attestation-
        # layer auto-slash uses, since it's the same "pending
        # evidence seen by consensus, not yet on-chain" bucket.
        pending = self.finalized_checkpoints.get_pending_slashing_evidence()
        if pending:
            if not hasattr(self, "_pending_finality_slashes"):
                self._pending_finality_slashes = []
            self._pending_finality_slashes.extend(pending)

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

        # Crypto-agility gate: reject any block whose header advertises an
        # unknown hash scheme.  This is the single chokepoint that activates
        # future hash algorithms via governance — until HASH_VERSION_CURRENT
        # moves, only the current scheme is accepted here.
        from messagechain.config import validate_hash_version, validate_sig_version
        ok, reason = validate_hash_version(block.header.hash_version)
        if not ok:
            return False, reason
        # Proposer signature must use an accepted sig scheme.  We check here
        # (not only inside verify_signature) so the reason string is clear
        # and rejection happens before any hash work.
        if block.header.proposer_signature is not None:
            ok, reason = validate_sig_version(
                block.header.proposer_signature.sig_version,
            )
            if not ok:
                return False, f"Proposer signature: {reason}"

        # Reject blocks proposed by emergency-revoked validators.  The cold-
        # key holder has declared this hot key compromised; the network
        # must stop honoring its block proposals immediately, regardless of
        # whether the signature technically verifies.
        if block.header.proposer_id in self.revoked_entities:
            return False, (
                f"Proposer {block.header.proposer_id.hex()[:16]}... is revoked"
            )

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

        # Per-entity message tx cap — prevents a single entity from
        # monopolizing block space (anti-flooding / anti-censorship).
        # Applies to MessageTransaction only; transfer/stake/governance
        # txs are already rare and don't need this constraint.
        entity_msg_counts: dict[bytes, int] = {}
        for tx in block.transactions:
            entity_msg_counts[tx.entity_id] = entity_msg_counts.get(tx.entity_id, 0) + 1
            if entity_msg_counts[tx.entity_id] > MAX_TXS_PER_ENTITY_PER_BLOCK:
                return False, (
                    f"Per-entity cap exceeded: entity {tx.entity_id.hex()[:16]}... "
                    f"has {entity_msg_counts[tx.entity_id]} message txs in block "
                    f"(max {MAX_TXS_PER_ENTITY_PER_BLOCK})"
                )

        # Check for duplicate transaction hashes within the block
        seen_tx_hashes = set()
        all_txs = list(block.transactions) + list(block.transfer_transactions)
        for tx in all_txs:
            if tx.tx_hash in seen_tx_hashes:
                return False, f"Duplicate transaction {tx.tx_hash.hex()[:16]} in block"
            seen_tx_hashes.add(tx.tx_hash)

        # WOTS+ leaf-reuse defense at the block level.  The per-tx watermark
        # check in validate_transaction reads chain state that hasn't been
        # bumped yet when the second tx is validated, so two txs sharing a
        # (entity_id, leaf_index) pair can both pass individual validation.
        # Reject the whole block if any such collision appears — reusing a
        # WOTS+ leaf leaks the private key, so this MUST be impossible.
        seen_leaves: set[tuple[bytes, int]] = set()
        def _check_leaf(entity_id: bytes, leaf_index: int, kind: str) -> tuple[bool, str]:
            key = (entity_id, leaf_index)
            if key in seen_leaves:
                return False, (
                    f"Block contains duplicate WOTS+ leaf use for entity "
                    f"{entity_id.hex()[:16]} at leaf {leaf_index} ({kind}) — "
                    "leaf reuse rejected"
                )
            seen_leaves.add(key)
            return True, ""
        for tx in block.transactions:
            ok, reason = _check_leaf(tx.entity_id, tx.signature.leaf_index, "message tx")
            if not ok:
                return False, reason
        for ttx in block.transfer_transactions:
            ok, reason = _check_leaf(ttx.entity_id, ttx.signature.leaf_index, "transfer tx")
            if not ok:
                return False, reason
        for stx in block.slash_transactions:
            ok, reason = _check_leaf(stx.submitter_id, stx.signature.leaf_index, "slash tx")
            if not ok:
                return False, reason
        for att in block.attestations:
            ok, reason = _check_leaf(att.validator_id, att.signature.leaf_index, "attestation")
            if not ok:
                return False, reason
        # Finality votes share the signer's hot-key leaf namespace.
        # Reusing a leaf between an attestation and a finality vote is
        # the same WOTS+ private-key leak as any other reuse, so the
        # dedupe set is the same.
        for v in getattr(block, "finality_votes", []):
            ok, reason = _check_leaf(
                v.signer_entity_id, v.signature.leaf_index, "finality vote",
            )
            if not ok:
                return False, reason
        for atx in getattr(block, "authority_txs", []):
            # authority txs (SetAuthorityKey, Revoke, KeyRotation) each carry a
            # signature keyed by their respective entity field.  Dispatch to
            # the right signer so the (entity_id, leaf_index) dedupe key is
            # accurate.  Revoke is signed by the COLD key, so its leaf does
            # not collide with any hot-key leaf from the same entity_id —
            # we treat the cold key's leaf-space as namespaced by the
            # authority-key bytes to prevent false positives between hot
            # and cold trees on the same entity.
            if atx.__class__.__name__ == "RevokeTransaction":
                authority_pk = self.get_authority_key(atx.entity_id)
                signer_key = authority_pk if authority_pk is not None else atx.entity_id
                ok, reason = _check_leaf(signer_key, atx.signature.leaf_index, "revoke tx")
            else:
                ok, reason = _check_leaf(atx.entity_id, atx.signature.leaf_index, "authority tx")
            if not ok:
                return False, reason
        for stx in getattr(block, "stake_transactions", []):
            ok, reason = _check_leaf(stx.entity_id, stx.signature.leaf_index, "stake tx")
            if not ok:
                return False, reason
        for utx in getattr(block, "unstake_transactions", []):
            # Unstake is authority-gated (signed by the cold key when one
            # has been promoted), so its leaf lives in the cold tree —
            # namespaced the same way revoke is to avoid false positives
            # with the hot tree.
            authority_pk = self.get_authority_key(utx.entity_id)
            signer_key = authority_pk if authority_pk is not None else utx.entity_id
            ok, reason = _check_leaf(signer_key, utx.signature.leaf_index, "unstake tx")
            if not ok:
                return False, reason
        if block.header.proposer_signature is not None:
            ok, reason = _check_leaf(
                block.header.proposer_id,
                block.header.proposer_signature.leaf_index,
                "proposer signature",
            )
            if not ok:
                return False, reason

        # Check total signature verification cost (sigops-style limit)
        # Counts all tx sigs + proposer sig + attestation sigs + slash sigs
        import messagechain.config
        sig_cost = compute_block_sig_cost(block)
        if sig_cost > messagechain.config.MAX_BLOCK_SIG_COST:
            return False, f"Block sig cost {sig_cost} exceeds MAX_BLOCK_SIG_COST {messagechain.config.MAX_BLOCK_SIG_COST}"

        # Verify merkle root. Includes message txs, transfer txs, slash txs,
        # governance txs, authority txs, and finality votes — committing
        # each cryptographically prevents a byzantine relayer from
        # stripping them in transit.  FinalityVotes use consensus_hash
        # (no tx_hash field; they're not transactions) in the same
        # commitment position so a stripped vote fails merkle verification.
        tx_hashes = (
            [tx.tx_hash for tx in all_txs]
            + [tx.tx_hash for tx in block.slash_transactions]
            + [tx.tx_hash for tx in block.governance_txs]
            + [tx.tx_hash for tx in getattr(block, "authority_txs", [])]
            + [tx.tx_hash for tx in getattr(block, "stake_transactions", [])]
            + [tx.tx_hash for tx in getattr(block, "unstake_transactions", [])]
            + [v.consensus_hash() for v in getattr(block, "finality_votes", [])]
        )
        expected_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")
        if block.header.merkle_root != expected_root:
            return False, "Invalid merkle root"

        # Receive-to-exist: no RegistrationTransaction type.  New
        # entities enter chain state implicitly on their first Transfer
        # (either as a recipient — balance only — or as a first-spend
        # sender, which installs the pubkey via sender_pubkey reveal).

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

        # ── Base fee gate ─────────────────────────────────────────────
        # Every fee-bearing transaction must cover the current base_fee.
        # Without this, transactions with MIN_FEE <= fee < base_fee pass
        # per-tx validation but silently fail at pay_fee_with_burn time,
        # allowing free state changes.  Check here once, before any
        # per-type validation, so no tx type can slip through.
        current_base_fee = self.supply.base_fee
        for tx in block.transactions:
            if tx.fee < current_base_fee:
                return False, (
                    f"Invalid tx {tx.tx_hash.hex()[:16]}: "
                    f"fee {tx.fee} below current base_fee {current_base_fee}"
                )
        for ttx in block.transfer_transactions:
            if ttx.fee < current_base_fee:
                return False, (
                    f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                    f"fee {ttx.fee} below current base_fee {current_base_fee}"
                )
        for stx in block.slash_transactions:
            if stx.fee < current_base_fee:
                return False, (
                    f"Invalid slash tx {stx.tx_hash.hex()[:16]}: "
                    f"fee {stx.fee} below current base_fee {current_base_fee}"
                )
        for gtx in block.governance_txs:
            if gtx.fee < current_base_fee:
                return False, (
                    f"Invalid governance tx {gtx.tx_hash.hex()[:16]}: "
                    f"fee {gtx.fee} below current base_fee {current_base_fee}"
                )
        for atx in getattr(block, "authority_txs", []):
            if atx.fee < current_base_fee:
                return False, (
                    f"Invalid authority tx {atx.tx_hash.hex()[:16]}: "
                    f"fee {atx.fee} below current base_fee {current_base_fee}"
                )
        for stx in getattr(block, "stake_transactions", []):
            if stx.fee < current_base_fee:
                return False, (
                    f"Invalid stake tx {stx.tx_hash.hex()[:16]}: "
                    f"fee {stx.fee} below current base_fee {current_base_fee}"
                )
        for utx in getattr(block, "unstake_transactions", []):
            if utx.fee < current_base_fee:
                return False, (
                    f"Invalid unstake tx {utx.tx_hash.hex()[:16]}: "
                    f"fee {utx.fee} below current base_fee {current_base_fee}"
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

        # Validate transfer transactions (same nonce/balance tracking).
        # Receive-to-exist: the recipient need not be pre-registered;
        # the sender may also be unknown on-chain iff the tx carries a
        # valid `sender_pubkey` (first-spend reveal).  Pubkeys installed
        # earlier in the same block are visible to later txs via
        # pending_pubkey_installs so a single block can contain "fund X
        # + first-spend from X" without rejecting the second tx.
        from messagechain.identity.identity import derive_entity_id
        pending_pubkey_installs: dict[bytes, bytes] = {}
        # Credits to recipients inside this block — lets a later Stake
        # from the same recipient see its same-block funding when the
        # block is of the form [fund X via Transfer, X stakes first-
        # spend].  The cumulative-balance check at stake-validate time
        # consults this alongside get_spendable_balance.
        pending_balance_credits: dict[bytes, int] = {}
        # Recipients funded earlier in this block — so a later tx to the
        # same recipient in the same block does NOT re-pay the
        # NEW_ACCOUNT_FEE surcharge.  Mirrors pending_pubkey_installs
        # for the sender side.  Only the FIRST tx to fund a given brand-
        # new recipient pays the surcharge.
        pending_new_account_created: set[bytes] = set()
        for ttx in block.transfer_transactions:
            # Dust limit: mirrors the standalone validator so block-
            # path validation cannot admit a transfer below the limit.
            if ttx.amount < DUST_LIMIT:
                return False, (
                    f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                    f"Transfer amount {ttx.amount} below dust limit {DUST_LIMIT}"
                )

            # New-account surcharge: if the recipient has no on-chain
            # state AND no earlier tx in this block has funded them,
            # this tx creates a permanent state entry and must pay
            # MIN_FEE + NEW_ACCOUNT_FEE.
            recipient_is_new = self._recipient_is_new(
                ttx.recipient_id,
                pending_new_account_created=pending_new_account_created,
            )
            if recipient_is_new:
                required = MIN_FEE + NEW_ACCOUNT_FEE
                if ttx.fee < required:
                    return False, (
                        f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                        f"Transfer to brand-new recipient requires fee "
                        f">= {required} (MIN_FEE {MIN_FEE} + new-account "
                        f"surcharge {NEW_ACCOUNT_FEE}); got {ttx.fee}"
                    )

            # Known-sender vs first-spend reveal.
            known_pk = self.public_keys.get(ttx.entity_id) or pending_pubkey_installs.get(ttx.entity_id)
            if known_pk is not None:
                if ttx.sender_pubkey:
                    return False, (
                        f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                        f"sender_pubkey must be empty for already-registered entity"
                    )
                verifying_pubkey = known_pk
            else:
                if not ttx.sender_pubkey:
                    return False, (
                        f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                        f"Unknown sender — first-spend transfer must include sender_pubkey"
                    )
                if derive_entity_id(ttx.sender_pubkey) != ttx.entity_id:
                    return False, (
                        f"Invalid transfer {ttx.tx_hash.hex()[:16]}: "
                        f"sender_pubkey does not derive claimed entity_id"
                    )
                verifying_pubkey = ttx.sender_pubkey

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

            if not verify_transfer_transaction(ttx, verifying_pubkey):
                return False, f"Invalid transfer {ttx.tx_hash.hex()[:16]}: Invalid signature"

            if known_pk is None:
                # Mark this first-spend pubkey as visible to later txs in
                # the same block (e.g., a stake-from-the-same-sender tx
                # after this transfer).
                pending_pubkey_installs[ttx.entity_id] = ttx.sender_pubkey

            # Mark the recipient as "created in this block" so later txs
            # to the same recipient don't re-charge the surcharge.
            if recipient_is_new:
                pending_new_account_created.add(ttx.recipient_id)

            pending_nonces[ttx.entity_id] = expected_nonce + 1
            pending_balance_spent[ttx.entity_id] = spent_so_far + ttx.amount + ttx.fee
            # Credit the recipient inside this block so a later Stake
            # (or any other fee-paying tx) from the same recipient can
            # see its same-block funding.
            pending_balance_credits[ttx.recipient_id] = (
                pending_balance_credits.get(ttx.recipient_id, 0) + ttx.amount
            )

        # Validate attestations (votes for the parent block)
        valid, reason = self._validate_attestations(block)
        if not valid:
            return False, reason

        # Validate embedded FinalityVotes (long-range-attack defense).
        # Votes reference any prior block (not just the parent); each
        # carries its own signature keyed by signer_entity_id.  See
        # _validate_finality_votes for the full rule set.
        valid, reason = self._validate_finality_votes(block)
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

        # Validate governance transactions.  Each carries its own signature
        # and minimum-fee rules; we check the sender is known, the signature
        # verifies, and the sender can afford the fee CUMULATIVELY with
        # other fee-paying txs from the same sender earlier in this block
        # (shares pending_balance_spent with message/transfer txs above).
        # Application-layer semantics (proposal-exists, voting-window-open,
        # duplicate vote) are enforced in _apply_block_state against the
        # GovernanceTracker.
        for gtx in block.governance_txs:
            valid, reason = self._validate_governance_tx_in_block(
                gtx, pending_balance_spent,
            )
            if not valid:
                return False, f"Invalid governance tx: {reason}"

        # Validate stake transactions — full check: signature, sender
        # registered (either in state OR revealed first-spend-style via
        # sender_pubkey), nonce, amount meets the graduated minimum, and
        # the sender can afford stake + fee.  Nonce and balance are
        # tracked cumulatively with message/transfer txs earlier in this
        # block.  pending_pubkey_installs is shared with the transfer
        # pass so a block containing "fund X via Transfer + X stakes
        # first-spend" validates both txs against the same view.
        for stx in getattr(block, "stake_transactions", []):
            ok, reason = self._validate_stake_tx_in_block(
                stx, pending_nonces, pending_balance_spent,
                pending_pubkey_installs,
                pending_balance_credits,
            )
            if not ok:
                return False, f"Invalid stake tx: {reason}"

        # Validate unstake transactions.  Authority-gated: signature must
        # verify under the cold key (which defaults to the signing key for
        # entities that haven't promoted one).  Amount must not exceed
        # current stake.  Nonce is cumulative with other fee-paying txs.
        for utx in getattr(block, "unstake_transactions", []):
            ok, reason = self._validate_unstake_tx_in_block(
                utx, pending_nonces, pending_balance_spent,
            )
            if not ok:
                return False, f"Invalid unstake tx: {reason}"

        # Receive-to-exist: no separate registration tx type to validate.
        return True, "Valid"

    def _validate_stake_tx_in_block(
        self, stx,
        pending_nonces: dict[bytes, int],
        pending_balance_spent: dict[bytes, int],
        pending_pubkey_installs: dict[bytes, bytes] | None = None,
        pending_balance_credits: dict[bytes, int] | None = None,
    ) -> tuple[bool, str]:
        """Validate a StakeTransaction within a block being proposed/received.

        Uses the cumulative (pending_nonces, pending_balance_spent) tracked
        alongside message and transfer txs so that a single block containing
        multiple fee-paying txs from the same sender is validated against
        the cumulative spend, not the pre-block balance.

        Receive-to-exist first-spend: a brand-new entity whose natural
        first on-chain action is Stake (not Transfer) may carry
        `sender_pubkey` so this path can verify the signature and install
        the key.  Dual branch mirrors `validate_transfer_transaction`:
          * entity already known (on chain or via a same-block first-spend
            tx recorded in `pending_pubkey_installs`): sender_pubkey must
            be empty (non-empty is malleability).
          * entity unknown: sender_pubkey required; its hash must equal
            entity_id; used for signature verification; recorded in
            `pending_pubkey_installs` so later txs in this block see it.
        """
        from messagechain.core.staking import (
            StakeTransaction, verify_stake_transaction,
        )
        from messagechain.consensus.bootstrap_gradient import (
            min_stake_for_progress,
        )
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.identity.identity import derive_entity_id

        if not isinstance(stx, StakeTransaction):
            return False, f"Unexpected type {type(stx).__name__}"

        # Match the unstake path: revoked entities cannot re-acquire stake.
        # Revoke is an authoritative kill switch — any re-staking would
        # silently re-enroll a validator the cold-key holder explicitly
        # retired, and because the unstake path is also revocation-blocked,
        # freshly staked tokens would be permanently trapped.
        if stx.entity_id in self.revoked_entities:
            return False, f"Entity {stx.entity_id.hex()[:16]} is revoked"

        # Resolve verifying pubkey — same two-branch logic as
        # validate_transfer_transaction.  A nil dict means "no
        # cross-tx bookkeeping" (standalone validation).
        if pending_pubkey_installs is None:
            pending_pubkey_installs = {}
        known_pk = (
            self.public_keys.get(stx.entity_id)
            or pending_pubkey_installs.get(stx.entity_id)
        )
        if known_pk is not None:
            if getattr(stx, "sender_pubkey", b""):
                return False, (
                    "sender_pubkey must be empty for an already-registered "
                    "entity — first-spend reveal is one-shot"
                )
            verifying_pubkey = known_pk
            is_first_spend = False
        else:
            if not getattr(stx, "sender_pubkey", b""):
                return False, (
                    f"Entity {stx.entity_id.hex()[:16]} has no registered "
                    f"pubkey — first on-chain stake must include "
                    f"sender_pubkey"
                )
            if derive_entity_id(stx.sender_pubkey) != stx.entity_id:
                return False, (
                    "sender_pubkey does not derive the claimed entity_id "
                    "(hash mismatch)"
                )
            verifying_pubkey = stx.sender_pubkey
            is_first_spend = True

        # Leaf-reuse guard — even on first-spend, reject reuse of a leaf
        # already past the watermark (same rationale as Transfer).  Runs
        # BEFORE signature verification so a caller mutating leaf_index
        # on a fresh tx is rejected on the right failure mode (leaf
        # reuse, not signature) — mirrors validate_transfer_transaction.
        if stx.signature.leaf_index < self.leaf_watermarks.get(stx.entity_id, 0):
            return False, (
                f"WOTS+ leaf {stx.signature.leaf_index} already consumed "
                f"(watermark {self.leaf_watermarks[stx.entity_id]}) — "
                f"leaf reuse rejected"
            )

        # verify_stake_transaction applies its own independent min-stake
        # check that we want to bypass during bootstrap (it uses the legacy
        # height-tier table, not the bootstrap_progress gradient).  Pass
        # the progress-derived min explicitly so the transaction-level
        # signature/structure verification uses the same threshold as the
        # block-level validation below.
        progress_min = min_stake_for_progress(
            self.bootstrap_progress, full_min_stake=VALIDATOR_MIN_STAKE,
        )
        if not verify_stake_transaction(
            stx, verifying_pubkey, block_height=self.height,
            min_stake_override=progress_min,
        ):
            return False, "Invalid signature or fields"

        expected_nonce = pending_nonces.get(
            stx.entity_id, self.nonces.get(stx.entity_id, 0),
        )
        if stx.nonce != expected_nonce:
            return False, f"Invalid nonce: expected {expected_nonce}, got {stx.nonce}"

        # Amount must meet the progress-derived minimum so under-bootstrap
        # newcomers can stake any positive amount, while post-bootstrap
        # new validators must clear VALIDATOR_MIN_STAKE.  The same gate is
        # applied at tx-level verification above; duplicated here so
        # callers that go directly through validate_block still see the
        # check even if verify_stake_transaction was short-circuited.
        if stx.amount < progress_min:
            return False, (
                f"Stake amount {stx.amount} below bootstrap-progress "
                f"minimum {progress_min}"
            )

        spent_so_far = pending_balance_spent.get(stx.entity_id, 0)
        credited_so_far = (
            pending_balance_credits.get(stx.entity_id, 0)
            if pending_balance_credits is not None else 0
        )
        needed = spent_so_far + stx.fee + stx.amount
        available = self.get_spendable_balance(stx.entity_id) + credited_so_far
        if available < needed:
            return False, (
                f"Insufficient balance for stake {stx.amount} + fee {stx.fee} "
                f"(cumulative with other txs in this block)"
            )

        pending_nonces[stx.entity_id] = expected_nonce + 1
        pending_balance_spent[stx.entity_id] = needed
        if is_first_spend:
            pending_pubkey_installs[stx.entity_id] = stx.sender_pubkey
        return True, "Valid"

    def _validate_stake_tx(self, stx) -> tuple[bool, str]:
        """Standalone (non-cumulative) validation for validate_block_standalone.

        Mirrors _validate_stake_tx_in_block but treats each tx independently
        against the current on-chain balance/nonce, since standalone validation
        is used in fork validation where cumulative tracking is unnecessary.
        """
        empty_nonces: dict[bytes, int] = {}
        empty_spent: dict[bytes, int] = {}
        empty_pubkeys: dict[bytes, bytes] = {}
        empty_credits: dict[bytes, int] = {}
        return self._validate_stake_tx_in_block(
            stx, empty_nonces, empty_spent, empty_pubkeys, empty_credits,
        )

    def _validate_unstake_tx_in_block(
        self, utx,
        pending_nonces: dict[bytes, int],
        pending_balance_spent: dict[bytes, int],
    ) -> tuple[bool, str]:
        """Validate an UnstakeTransaction within a block.

        Authority-gated: verified against the entity's cold authority key.
        Amount must not exceed the entity's current stake.  Fee is
        tracked cumulatively with the block's other fee-paying txs.
        """
        from messagechain.core.staking import (
            UnstakeTransaction, verify_unstake_transaction,
        )
        if not isinstance(utx, UnstakeTransaction):
            return False, f"Unexpected type {type(utx).__name__}"
        if utx.entity_id not in self.public_keys:
            return False, f"Unknown sender {utx.entity_id.hex()[:16]}"
        if utx.entity_id in self.revoked_entities:
            # Revoked entities can't unstake through this path — their
            # stake is already unbonding from the revoke tx itself.
            return False, f"Entity {utx.entity_id.hex()[:16]} is revoked"

        # Authority-gated signature check.
        authority_pk = self.get_authority_key(utx.entity_id)
        if authority_pk is None or not verify_unstake_transaction(utx, authority_pk):
            return False, (
                "Invalid signature — unstake must be signed by the authority "
                "(cold) key. The hot signing key cannot authorize withdrawal."
            )

        expected_nonce = pending_nonces.get(
            utx.entity_id, self.nonces.get(utx.entity_id, 0),
        )
        if utx.nonce != expected_nonce:
            return False, f"Invalid nonce: expected {expected_nonce}, got {utx.nonce}"

        if self.supply.get_staked(utx.entity_id) < utx.amount:
            return False, (
                f"Unstake {utx.amount} exceeds current stake "
                f"{self.supply.get_staked(utx.entity_id)}"
            )

        spent_so_far = pending_balance_spent.get(utx.entity_id, 0)
        needed = spent_so_far + utx.fee
        if self.get_spendable_balance(utx.entity_id) < needed:
            return False, f"Insufficient balance for unstake fee {utx.fee}"

        pending_nonces[utx.entity_id] = expected_nonce + 1
        pending_balance_spent[utx.entity_id] = needed
        return True, "Valid"

    def _validate_unstake_tx(self, utx) -> tuple[bool, str]:
        """Standalone unstake validation for validate_block_standalone."""
        empty_nonces: dict[bytes, int] = {}
        empty_spent: dict[bytes, int] = {}
        return self._validate_unstake_tx_in_block(utx, empty_nonces, empty_spent)

    def _validate_governance_tx_in_block(
        self, gtx,
        pending_balance_spent: dict[bytes, int],
    ) -> tuple[bool, str]:
        """Governance tx validation with cumulative balance tracking.

        Delegates signature/sender/min-fee checks to `_validate_governance_tx`,
        then adds a cumulative-balance guard: the sender's spendable balance
        must cover (prior-txs-in-block-spent + this-tx-fee).  This prevents
        silent fee drops when a sender puts several governance txs (or a
        mix of message/transfer + governance) from the same account in the
        same block.
        """
        ok, reason = self._validate_governance_tx(gtx)
        if not ok:
            return False, reason
        if hasattr(gtx, "voter_id"):
            sender = gtx.voter_id
        elif hasattr(gtx, "proposer_id"):
            sender = gtx.proposer_id
        else:
            return False, "Could not resolve sender for cumulative check"
        spent_so_far = pending_balance_spent.get(sender, 0)
        needed = spent_so_far + gtx.fee
        if self.get_spendable_balance(sender) < needed:
            return False, (
                f"Insufficient cumulative balance: spent_so_far {spent_so_far} "
                f"+ fee {gtx.fee} exceeds spendable"
            )
        pending_balance_spent[sender] = needed
        return True, "Valid"

    def _validate_governance_tx(self, gtx) -> tuple[bool, str]:
        """Verify a governance transaction's signature, author, and fee balance.

        Rejects txs whose sender is unknown to the chain, whose signature
        does not verify, or whose sender cannot afford the declared fee.
        The fee-balance check at validate time means `_apply_governance_block`
        can trust that pay_fee_with_burn will succeed.  Does NOT enforce
        application-layer rules (proposal-exists, window-closed, etc.) —
        those are handled by the GovernanceTracker at apply time so that
        benign-but-rejected txs (e.g., votes on an expired proposal) do
        not invalidate an otherwise well-formed block.
        """
        from messagechain.governance.governance import (
            ProposalTransaction, VoteTransaction,
            TreasurySpendTransaction,
            verify_proposal, verify_vote,
            verify_treasury_spend,
        )
        if isinstance(gtx, ProposalTransaction):
            sender = gtx.proposer_id
            verifier = verify_proposal
        elif isinstance(gtx, VoteTransaction):
            sender = gtx.voter_id
            verifier = verify_vote
        elif isinstance(gtx, TreasurySpendTransaction):
            sender = gtx.proposer_id
            verifier = verify_treasury_spend
        else:
            return False, f"Unknown governance tx type {type(gtx).__name__}"
        if sender not in self.public_keys:
            return False, f"Unknown sender {sender.hex()[:16]}"
        if not verifier(gtx, self.public_keys[sender]):
            return False, "Invalid signature or fields"
        if not self.supply.can_afford_fee(sender, gtx.fee):
            return False, (
                f"Insufficient balance for fee {gtx.fee} "
                f"from sender {sender.hex()[:16]}"
            )
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

        # Crypto-agility gate: mirror validate_block — unknown hash or sig
        # scheme is rejected at the consensus boundary regardless of which
        # entry point the block arrived through.
        from messagechain.config import validate_hash_version, validate_sig_version
        ok, reason = validate_hash_version(block.header.hash_version)
        if not ok:
            return False, reason
        if block.header.proposer_signature is not None:
            ok, reason = validate_sig_version(
                block.header.proposer_signature.sig_version,
            )
            if not ok:
                return False, f"Proposer signature: {reason}"

        total_tx_count = len(block.transactions) + len(block.transfer_transactions)
        if total_tx_count > MAX_TXS_PER_BLOCK:
            return False, "Too many transactions"
        total_message_bytes = sum(len(tx.message) for tx in block.transactions)
        if total_message_bytes > MAX_BLOCK_MESSAGE_BYTES:
            return False, f"Block message bytes {total_message_bytes} exceed budget {MAX_BLOCK_MESSAGE_BYTES}"

        # Per-entity message tx cap (same rule as validate_block).
        entity_msg_counts: dict[bytes, int] = {}
        for tx in block.transactions:
            entity_msg_counts[tx.entity_id] = entity_msg_counts.get(tx.entity_id, 0) + 1
            if entity_msg_counts[tx.entity_id] > MAX_TXS_PER_ENTITY_PER_BLOCK:
                return False, (
                    f"Per-entity cap exceeded: entity {tx.entity_id.hex()[:16]}... "
                    f"has {entity_msg_counts[tx.entity_id]} message txs in block "
                    f"(max {MAX_TXS_PER_ENTITY_PER_BLOCK})"
                )

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

        # Merkle root — includes governance, authority, and stake txs so a
        # relayer cannot strip them.
        tx_hashes = (
            [tx.tx_hash for tx in all_txs]
            + [tx.tx_hash for tx in block.slash_transactions]
            + [tx.tx_hash for tx in block.governance_txs]
            + [tx.tx_hash for tx in getattr(block, "authority_txs", [])]
            + [tx.tx_hash for tx in getattr(block, "stake_transactions", [])]
            + [tx.tx_hash for tx in getattr(block, "unstake_transactions", [])]
        )
        expected_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")
        if block.header.merkle_root != expected_root:
            return False, "Invalid merkle root"

        # Receive-to-exist: no RegistrationTransaction type to validate.

        # Governance txs — signature + sender checks (same as validate_block)
        for gtx in block.governance_txs:
            valid, reason = self._validate_governance_tx(gtx)
            if not valid:
                return False, f"Invalid governance tx: {reason}"

        # Stake txs — signature + sender + fee + amount checks
        for stx in getattr(block, "stake_transactions", []):
            valid, reason = self._validate_stake_tx(stx)
            if not valid:
                return False, f"Invalid stake tx: {reason}"

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

        # ── Base fee gate (mirrors validate_block) ────────────────
        current_base_fee = self.supply.base_fee
        for tx in block.transactions:
            if tx.fee < current_base_fee:
                return False, (
                    f"fee {tx.fee} below current base_fee {current_base_fee} "
                    f"in tx {tx.tx_hash.hex()[:16]}"
                )
        for ttx in block.transfer_transactions:
            if ttx.fee < current_base_fee:
                return False, (
                    f"fee {ttx.fee} below current base_fee {current_base_fee} "
                    f"in transfer {ttx.tx_hash.hex()[:16]}"
                )
        for stx in block.slash_transactions:
            if stx.fee < current_base_fee:
                return False, (
                    f"fee {stx.fee} below current base_fee {current_base_fee} "
                    f"in slash tx {stx.tx_hash.hex()[:16]}"
                )
        for gtx in block.governance_txs:
            if gtx.fee < current_base_fee:
                return False, (
                    f"fee {gtx.fee} below current base_fee {current_base_fee} "
                    f"in governance tx {gtx.tx_hash.hex()[:16]}"
                )
        for atx in getattr(block, "authority_txs", []):
            if atx.fee < current_base_fee:
                return False, (
                    f"fee {atx.fee} below current base_fee {current_base_fee} "
                    f"in authority tx {atx.tx_hash.hex()[:16]}"
                )
        for stx in getattr(block, "stake_transactions", []):
            if stx.fee < current_base_fee:
                return False, (
                    f"fee {stx.fee} below current base_fee {current_base_fee} "
                    f"in stake tx {stx.tx_hash.hex()[:16]}"
                )
        for utx in getattr(block, "unstake_transactions", []):
            if utx.fee < current_base_fee:
                return False, (
                    f"fee {utx.fee} below current base_fee {current_base_fee} "
                    f"in unstake tx {utx.tx_hash.hex()[:16]}"
                )

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

    def _apply_authority_tx(self, atx, proposer_id: bytes, base_fee: int) -> None:
        """Dispatch an authority tx from within _apply_block_state.

        Validates first — a block containing an invalid authority tx is a
        bug in block production, but we degrade gracefully by skipping
        the bad tx rather than corrupting state.  Fee-with-burn and leaf
        watermark bump happen uniformly; the per-type side effects
        (promote cold key / flip revoked / swap public_key) run inline.
        """
        cls_name = atx.__class__.__name__
        if cls_name == "SetAuthorityKeyTransaction":
            ok, _ = self.validate_set_authority_key(atx)
            if not ok:
                return
            if not self.supply.pay_fee_with_burn(atx.entity_id, proposer_id, atx.fee, base_fee):
                logger.error(
                    f"SetAuthorityKey fee payment failed (fee {atx.fee} vs "
                    f"base_fee {base_fee}) — skipping"
                )
                return
            self.authority_keys[atx.entity_id] = atx.new_authority_key
            self.nonces[atx.entity_id] = atx.nonce + 1
            self._bump_watermark(atx.entity_id, atx.signature.leaf_index)
            if self.db is not None and hasattr(self.db, "set_authority_key"):
                self.db.set_authority_key(atx.entity_id, atx.new_authority_key)
        elif cls_name == "RevokeTransaction":
            ok, _ = self.validate_revoke(atx)
            if not ok:
                return
            if not self.supply.pay_fee_with_burn(atx.entity_id, proposer_id, atx.fee, base_fee):
                logger.error(
                    f"Revoke fee payment failed (fee {atx.fee} vs "
                    f"base_fee {base_fee}) — skipping"
                )
                return
            active_stake = self.supply.get_staked(atx.entity_id)
            if active_stake > 0:
                self.supply.unstake(
                    atx.entity_id,
                    active_stake,
                    current_block=self.height,
                    bootstrap_ended=False,
                )
            self.revoked_entities.add(atx.entity_id)
            # Revoke is nonce-free; do NOT bump self.nonces.
            # Revoke signature consumed a leaf in the COLD tree — we
            # deliberately do not bump the hot-key watermark here.
            if self.db is not None and hasattr(self.db, "set_revoked"):
                self.db.set_revoked(atx.entity_id)
        elif cls_name == "KeyRotationTransaction":
            ok, _ = self.validate_key_rotation(atx)
            if not ok:
                return
            if not self.supply.pay_fee_with_burn(atx.entity_id, proposer_id, atx.fee, base_fee):
                logger.error(
                    f"KeyRotation fee payment failed (fee {atx.fee} vs "
                    f"base_fee {base_fee}) — skipping"
                )
                return
            self.public_keys[atx.entity_id] = atx.new_public_key
            self.key_rotation_counts[atx.entity_id] = atx.rotation_number + 1
            # New Merkle tree = independent leaf namespace, so reset.
            self.leaf_watermarks[atx.entity_id] = 0
            if self.db is not None:
                self.db.set_public_key(atx.entity_id, atx.new_public_key)
                if hasattr(self.db, "set_leaf_watermark"):
                    self.db.set_leaf_watermark(atx.entity_id, 0)
                if hasattr(self.db, "set_key_rotation_count"):
                    self.db.set_key_rotation_count(
                        atx.entity_id, self.key_rotation_counts[atx.entity_id],
                    )
        # Unknown class: silently skip. deserialize() would have rejected
        # an unknown type before reaching here, so this branch is defensive.

    def _apply_transfer_with_burn(self, tx, proposer_id: bytes, base_fee: int):
        """Apply a transfer transaction with EIP-1559 fee burning.

        Receive-to-exist: if `tx.sender_pubkey` is populated and the
        sender is not yet in `self.public_keys`, install the pubkey
        before touching balances.  That's how first-time senders cross
        from "balance-only" to "fully registered."

        New-account surcharge: if the recipient is brand-new (no
        on-chain state at call time), NEW_ACCOUNT_FEE is burned in
        addition to the EIP-1559 base-fee burn.  Proposer tip is
        (tx.fee - base_fee - NEW_ACCOUNT_FEE).
        """
        # Snapshot "is recipient new" BEFORE any state mutation.
        recipient_was_new = self._recipient_is_new(tx.recipient_id)

        # First-spend pubkey install (see apply_transfer_transaction
        # docstring — same semantics, inline here for the burn path).
        if tx.sender_pubkey and tx.entity_id not in self.public_keys:
            self.public_keys[tx.entity_id] = tx.sender_pubkey
            self.nonces.setdefault(tx.entity_id, 0)
            self._assign_entity_index(tx.entity_id)
            if self.db is not None:
                self.db.set_public_key(tx.entity_id, tx.sender_pubkey)

        # M1: Clamp base_fee to the actual fee to prevent negative tip
        effective_base_fee = min(base_fee, tx.fee)
        surcharge = NEW_ACCOUNT_FEE if recipient_was_new else 0
        # Block-path validation ensures tx.fee >= base_fee + surcharge for
        # brand-new recipients; clamp defensively so we never emit a
        # negative tip if that invariant is somehow violated (e.g., base
        # fee rose above the tx's ceiling post-admission).
        if effective_base_fee + surcharge > tx.fee:
            surcharge = max(0, tx.fee - effective_base_fee)
        tip = tx.fee - effective_base_fee - surcharge
        self.supply.balances[tx.entity_id] = self.supply.get_balance(tx.entity_id) - tx.amount - tx.fee
        self.supply.balances[tx.recipient_id] = self.supply.get_balance(tx.recipient_id) + tx.amount
        self.supply.balances[proposer_id] = self.supply.get_balance(proposer_id) + tip
        burned = effective_base_fee + surcharge
        self.supply.total_supply -= burned  # burn
        self.supply.total_burned += burned
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
        for atx in getattr(block, "authority_txs", []):
            affected.add(atx.entity_id)
        for stx in getattr(block, "stake_transactions", []):
            affected.add(stx.entity_id)
        for utx in getattr(block, "unstake_transactions", []):
            affected.add(utx.entity_id)
        # Seed divestment mutates seed stake + treasury every block within
        # the divestment window.  Cheap to always include (small set, often
        # a single seed); guarantees the incremental state-tree refresh
        # never misses the touched rows.
        affected.update(self.seed_entity_ids)
        return affected

    def _apply_seed_divestment(self, block_height: int) -> None:
        """Forcibly divest a linear fraction of each seed's genesis stake.

        Non-discretionary, always-on schedule.  Between SEED_DIVESTMENT_START
        (exclusive) and SEED_DIVESTMENT_END (inclusive), each block unbonds
        initial_seed_stake / window tokens per seed — 75% burned, 25% to
        treasury.  Outside that window this is a no-op.

        Snapshot is taken once at the first divestment block from the
        live staked balance so replay is deterministic (every node that
        re-applies that block captures the same value).  Stored in
        `self.seed_initial_stakes` and restored across reorg via
        _snapshot_memory_state / _restore_memory_snapshot.

        Called from `_apply_block_state` after all tx-driven stake moves
        so the divestment operates on the post-tx staked balance.  Any
        integer-rounding remainder accrues to burn (cleaner: smaller
        supply).  Stake is clamped at 0 — once a seed's stake is gone
        no further tokens move regardless of the schedule.
        """
        from messagechain.config import (
            SEED_DIVESTMENT_START_HEIGHT,
            SEED_DIVESTMENT_END_HEIGHT,
            SEED_DIVESTMENT_TREASURY_BPS,
            TREASURY_ENTITY_ID,
        )
        if block_height <= SEED_DIVESTMENT_START_HEIGHT:
            return
        if block_height > SEED_DIVESTMENT_END_HEIGHT:
            return
        if not self.seed_entity_ids:
            return
        window = SEED_DIVESTMENT_END_HEIGHT - SEED_DIVESTMENT_START_HEIGHT
        assert window > 0, "divestment window must be positive"

        for eid in self.seed_entity_ids:
            # First-block snapshot: capture the seed's then-current stake
            # once, so subsequent blocks decrement by a flat per-block
            # amount instead of rebasing against the decayed stake.
            if eid not in self.seed_initial_stakes:
                self.seed_initial_stakes[eid] = self.supply.get_staked(eid)
            initial = self.seed_initial_stakes[eid]
            if initial <= 0:
                continue

            per_block = initial // window  # integer floor — consensus-safe
            if per_block <= 0:
                continue

            current_stake = self.supply.get_staked(eid)
            divest = min(per_block, current_stake)
            if divest <= 0:
                continue

            # Split: treasury gets the exact 25% share (basis points);
            # burn gets the remainder so any integer-rounding remainder
            # always favors burn — smaller supply is the cleaner invariant.
            treasury_share = divest * SEED_DIVESTMENT_TREASURY_BPS // 10_000
            burn_share = divest - treasury_share
            assert treasury_share + burn_share == divest

            self.supply.staked[eid] = current_stake - divest
            if treasury_share > 0:
                self.supply.balances[TREASURY_ENTITY_ID] = (
                    self.supply.balances.get(TREASURY_ENTITY_ID, 0) + treasury_share
                )
            if burn_share > 0:
                self.supply.total_supply -= burn_share
                self.supply.total_burned += burn_share

    def _apply_block_state(self, block: Block):
        """Apply a block's state changes (fees, nonces, rewards) without validation."""
        proposer_id = block.header.proposer_id
        current_base_fee = self.supply.base_fee

        # Count total txs for base fee adjustment
        total_tx_count = len(block.transactions) + len(block.transfer_transactions)

        # Apply message transaction fees (EIP-1559: burn base fee, tip to proposer)
        for tx in block.transactions:
            if not self.supply.pay_fee_with_burn(tx.entity_id, proposer_id, tx.fee, current_base_fee):
                logger.error(
                    f"Message tx {tx.tx_hash.hex()[:16]} fee payment failed "
                    f"(fee {tx.fee} vs base_fee {current_base_fee}) — skipping"
                )
                continue
            self.nonces[tx.entity_id] = tx.nonce + 1
            self.entity_message_count[tx.entity_id] = (
                self.entity_message_count.get(tx.entity_id, 0) + 1
            )
            self._bump_watermark(tx.entity_id, tx.signature.leaf_index)
        # Apply transfer transactions (also with burn)
        for ttx in block.transfer_transactions:
            self._apply_transfer_with_burn(ttx, proposer_id, current_base_fee)
            self._bump_watermark(ttx.entity_id, ttx.signature.leaf_index)
        # Apply slash transactions.  Burns stake + accumulated escrow;
        # escrow burn runs first so any bootstrap-era rewards the
        # offender had built up also evaporate.  Matches the policy
        # from apply_slash_transaction (which is the other entry point
        # for slashing — kept semantically identical to avoid drift).
        for stx in block.slash_transactions:
            if not self.supply.pay_fee_with_burn(stx.submitter_id, proposer_id, stx.fee, current_base_fee):
                logger.error(
                    f"Slash tx {stx.tx_hash.hex()[:16]} fee payment failed — skipping"
                )
                continue
            escrow_burned = self._escrow.slash_all(stx.evidence.offender_id)
            if escrow_burned > 0:
                cur_balance = self.supply.balances.get(stx.evidence.offender_id, 0)
                self.supply.balances[stx.evidence.offender_id] = max(
                    0, cur_balance - escrow_burned,
                )
                self.supply.total_supply -= escrow_burned
            self.supply.slash_validator(stx.evidence.offender_id, stx.submitter_id)
            self.slashed_validators.add(stx.evidence.offender_id)
            # Reputation reset: same policy as apply_slash_transaction;
            # a slashed validator forfeits accumulated reputation.
            self.reputation.pop(stx.evidence.offender_id, None)
            self.slash_sig_counts[stx.submitter_id] = (
                self.slash_sig_counts.get(stx.submitter_id, 0) + 1
            )
            self._bump_watermark(stx.submitter_id, stx.signature.leaf_index)

        # Apply authority transactions (SetAuthorityKey / Revoke / KeyRotation).
        # These all carry block-level state changes that previously only
        # applied on the node receiving the RPC — committing them through
        # the block pipeline is what makes the hot/cold split, emergency
        # revoke, and key rotation consensus-visible across all peers.
        for atx in getattr(block, "authority_txs", []):
            self._apply_authority_tx(atx, proposer_id, current_base_fee)

        # Apply stake transactions.  validate_block already verified the
        # sender has sufficient balance and the amount meets the graduated
        # minimum, so both calls below must succeed.  Receive-to-exist
        # first-spend: if `sender_pubkey` is populated and the entity is
        # not yet known on chain, install the pubkey BEFORE mutating any
        # fee/balance/stake so the same-block state commitment captures
        # the install (mirrors `_apply_transfer_with_burn`).
        for stx in getattr(block, "stake_transactions", []):
            if (
                getattr(stx, "sender_pubkey", b"")
                and stx.entity_id not in self.public_keys
            ):
                self.public_keys[stx.entity_id] = stx.sender_pubkey
                self.nonces.setdefault(stx.entity_id, 0)
                self._assign_entity_index(stx.entity_id)
                if self.db is not None:
                    self.db.set_public_key(stx.entity_id, stx.sender_pubkey)
            if not self.supply.pay_fee_with_burn(
                stx.entity_id, proposer_id, stx.fee, current_base_fee,
            ):
                logger.error(
                    f"Stake tx {stx.tx_hash.hex()[:16]} fee payment failed — skipping"
                )
                continue
            staked_ok = self.supply.stake(stx.entity_id, stx.amount)
            if not staked_ok:
                # Only reachable if validate_block was bypassed — keep a loud
                # log rather than raising so a single malformed tx does not
                # abort the rest of the block.
                logger.error(
                    f"Stake tx {stx.tx_hash.hex()[:16]} failed at apply-time "
                    f"despite passing validate_block; chain state may be drift."
                )
            self.nonces[stx.entity_id] = stx.nonce + 1
            self._bump_watermark(stx.entity_id, stx.signature.leaf_index)

        # Apply unstake transactions.  Authority-gated; queues stake into
        # the UNBONDING_PERIOD unbond queue (not immediately spendable) so
        # in-flight slashing evidence stays effective during unbonding.
        for utx in getattr(block, "unstake_transactions", []):
            if not self.supply.pay_fee_with_burn(
                utx.entity_id, proposer_id, utx.fee, current_base_fee,
            ):
                logger.error(
                    f"Unstake tx {utx.tx_hash.hex()[:16]} fee payment failed — skipping"
                )
                continue
            unbond_ok = self.supply.unstake(
                utx.entity_id, utx.amount,
                current_block=block.header.block_number,
                bootstrap_ended=False,
            )
            if not unbond_ok:
                logger.error(
                    f"Unstake tx {utx.tx_hash.hex()[:16]} failed at apply-time "
                    f"despite passing validate_block; chain state may drift."
                )
            self.nonces[utx.entity_id] = utx.nonce + 1
            # Bump the hot-key watermark ONLY when the unstake was signed
            # by the hot signing key (single-key setup with no separate
            # cold key promoted).  When a dedicated cold key signed it,
            # the leaf lives in the cold tree's own namespace and must
            # not pollute the hot-tree watermark for this entity_id.
            authority_pk = self.get_authority_key(utx.entity_id)
            signing_pk = self.public_keys.get(utx.entity_id)
            if authority_pk == signing_pk:
                self._bump_watermark(utx.entity_id, utx.signature.leaf_index)

        # Receive-to-exist: first-spend pubkey install happens inside
        # `_apply_transfer_with_burn` above.  No separate registration
        # section is needed — an entity becomes "registered" the first
        # time it spends, and becomes visible in state the first time
        # it receives.

        # Non-discretionary seed divestment — runs after all tx-driven
        # stake moves so the schedule operates on the post-tx staked
        # balance, and before committee selection so the seed's reduced
        # stake is reflected in the same block's attester weights.
        self._apply_seed_divestment(block.header.block_number)

        # Candidate attesters for the reward committee: everyone whose
        # attestation was included in this block.  Stake is 0 during
        # early bootstrap where newcomers register without locking any
        # tokens — that's fine, the committee selection handles zero
        # stake naturally (weights fall back to uniform when total
        # stake is 0, see weights_for_progress).
        attester_candidates: list[tuple[bytes, int]] = []
        for att in block.attestations:
            stake = self.supply.get_staked(att.validator_id)
            attester_candidates.append((att.validator_id, stake))

        # Bootstrap mode flag: preserves the existing "no reward cap
        # during pre-stake bootstrap" semantics separately from the
        # bootstrap_progress gradient.  When no validator has any
        # stake at all (pure genesis), the PROPOSER_REWARD_CAP is
        # bypassed so genesis rewards aren't silently drained to
        # treasury on a network with no real validators yet.
        is_bootstrap = not any(s > 0 for s in self.supply.staked.values())

        # Select the committee that will actually be paid.  Up to
        # attester_pool tokens' worth of slots, 1 token each.  Seeds
        # are excluded during the first half of bootstrap (see
        # attester_committee.py); selection weight blends uniform and
        # stake-weighted by bootstrap_progress.
        from messagechain.consensus.attester_committee import (
            ATTESTER_REWARD_PER_SLOT,
            select_attester_committee,
        )
        from messagechain.config import (
            PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR,
        )
        block_reward = self.supply.calculate_block_reward(block.header.block_number)
        attester_pool_tokens = block_reward - (
            block_reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
        )
        committee_size = attester_pool_tokens // ATTESTER_REWARD_PER_SLOT
        # Randomness for committee selection: use parent block's
        # randao_mix rather than prev_hash.  Randao accumulates entropy
        # through every proposer's signature over the chain's history,
        # so a single parent proposer grinding their block contents
        # cannot cheaply shape which attesters get paid next block.
        # Must be identical on sim and apply paths — both derive it
        # from the parent block (at apply time, the current block has
        # not yet been appended to self.chain, so self.chain[-1] is
        # the parent — same indexing as the sim path).
        parent_randao = (
            self.chain[-1].header.randao_mix
            if self.chain else b"\x00" * 32
        )
        attester_committee = select_attester_committee(
            candidates=attester_candidates,
            seed_entity_ids=self.seed_entity_ids,
            bootstrap_progress=self.bootstrap_progress,
            randomness=parent_randao,
            committee_size=committee_size,
        )

        # Mint block reward: proposer share + committee slots
        result = self.supply.mint_block_reward(
            proposer_id, block.header.block_number,
            attester_committee=attester_committee,
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

        # Escrow: attester rewards are slashable for
        # escrow_blocks_for_progress(progress) blocks before becoming
        # fully liquid.  At progress=1.0 the escrow window collapses to
        # 0 (matches post-bootstrap normal PoS — no additional lock).
        # Balance is already credited via mint_block_reward; escrow is
        # a parallel lock recorded so (a) spendable balance reflects
        # the lock, and (b) slashing can burn the locked amount.
        from messagechain.consensus.bootstrap_gradient import (
            escrow_blocks_for_progress,
        )
        from messagechain.config import ATTESTER_ESCROW_BLOCKS
        escrow_len = escrow_blocks_for_progress(
            self.bootstrap_progress,
            max_escrow_blocks=ATTESTER_ESCROW_BLOCKS,
        )
        if escrow_len > 0:
            current_h = block.header.block_number
            unlock_at = current_h + escrow_len
            for att_id, att_reward in result["attestor_rewards"].items():
                if att_reward > 0 and att_id != proposer_id:
                    # Proposer-as-committee-member share is clawed back
                    # into proposer_reward by the PROPOSER_REWARD_CAP
                    # path in mint_block_reward, so we don't re-escrow
                    # it here — only pure-committee earnings.
                    self._escrow.add(
                        entity_id=att_id, amount=att_reward,
                        earned_at=current_h, unlock_at=unlock_at,
                    )

        # Reputation-weighted bootstrap lottery.  Fires every
        # LOTTERY_INTERVAL blocks; bounty fades linearly from full at
        # progress=0 to 0 at progress=1 via lottery_bounty_for_progress
        # — smooth time-bound handoff to normal PoS, no cliff.
        # Winner receives the (faded) bounty credited to balance AND
        # held in escrow for the current escrow window — slashable if
        # the winner then misbehaves.  Seeds are excluded; reputation
        # = 0 candidates can still win if nobody else has attested yet.
        from messagechain.config import (
            LOTTERY_INTERVAL, LOTTERY_BOUNTY,
            REPUTATION_CAP,
        )
        current_h = block.header.block_number
        if current_h > 0 and current_h % LOTTERY_INTERVAL == 0:
            from messagechain.consensus.reputation_lottery import (
                select_lottery_winner, lottery_bounty_for_progress,
            )
            bounty = lottery_bounty_for_progress(
                self.bootstrap_progress, full_bounty=LOTTERY_BOUNTY,
            )
            if bounty > 0:
                candidates = list(self.reputation.items())
                winner = select_lottery_winner(
                    candidates=candidates,
                    seed_entity_ids=self.seed_entity_ids,
                    randomness=parent_randao,
                    reputation_cap=REPUTATION_CAP,
                )
                if winner is not None:
                    self.supply.balances[winner] = (
                        self.supply.balances.get(winner, 0) + bounty
                    )
                    self.supply.total_supply += bounty
                    if escrow_len > 0:
                        self._escrow.add(
                            entity_id=winner, amount=bounty,
                            earned_at=current_h,
                            unlock_at=current_h + escrow_len,
                        )
                    logger.info(
                        f"LOTTERY: block #{current_h} — winner "
                        f"{winner.hex()[:16]} received {bounty} tokens "
                        f"(reputation={self.reputation.get(winner, 0)}, "
                        f"progress={self.bootstrap_progress:.3f}, "
                        f"escrow_blocks={escrow_len})"
                    )

        # Unlock matured escrow — no balance change (tokens were already
        # credited at mint time), just lifting the spendable-balance
        # restriction.
        self._escrow.pop_matured(block.header.block_number)
        # Track proposer's block signature count (WOTS+ leaf consumed)
        self.proposer_sig_counts[proposer_id] = (
            self.proposer_sig_counts.get(proposer_id, 0) + 1
        )
        if block.header.proposer_signature is not None:
            self._bump_watermark(proposer_id, block.header.proposer_signature.leaf_index)
        # Track attestation signatures (each consumes a WOTS+ leaf from the validator)
        for att in block.attestations:
            self.attestation_sig_counts[att.validator_id] = (
                self.attestation_sig_counts.get(att.validator_id, 0) + 1
            )
            self._bump_watermark(att.validator_id, att.signature.leaf_index)
        # Release matured pending unstakes
        self.supply.process_pending_unstakes(block.header.block_number)

        # Apply governance transactions after economic state has settled.
        # Lets auto-executed binding outcomes (treasury spends, ejections)
        # act on the fully-updated supply/stakes.
        self._apply_governance_block(block)

        # Apply FinalityVotes (long-range-attack defense).  Each vote
        # feeds into FinalityCheckpoints; when a target block crosses
        # the 2/3-stake threshold it is added to finalized_hashes and
        # persisted.  Conflicting votes from the same signer at the
        # same target height auto-generate slashing evidence that a
        # third party (or the node itself) can submit as a slash tx.
        # The proposer earns FINALITY_VOTE_INCLUSION_REWARD per vote
        # paid from treasury — mirrors the slashing finder's-reward
        # incentive and gives proposers a reason to actually include
        # votes instead of silently dropping them.
        self._apply_finality_votes(block, proposer_id)

        # Inactivity leak — Casper-style defense against liveness attacks.
        # Increment the finalization-stall counter.  If finalization happened
        # this block, _process_attestations (called after us from add_block)
        # will reset it to 0.  The counter drives quadratic penalties on
        # non-attesting validators during prolonged finalization stalls.
        self.blocks_since_last_finalization += 1

        from messagechain.consensus.inactivity import (
            is_leak_active,
            get_inactive_validators,
            apply_inactivity_leak,
        )
        if is_leak_active(self.blocks_since_last_finalization):
            # Expected attesters: all validators with positive stake.
            expected = {
                eid for eid, amt in self.supply.staked.items()
                if amt > 0
            }
            # Actual attesters in this block.
            actual = {att.validator_id for att in block.attestations}
            inactive = get_inactive_validators(expected, actual)
            if inactive:
                total_burned, deactivated = apply_inactivity_leak(
                    self.supply.staked,
                    self.blocks_since_last_finalization,
                    inactive,
                    min_stake=VALIDATOR_MIN_STAKE,
                )
                if total_burned > 0:
                    self.supply.total_supply -= total_burned
                    self.supply.total_burned += total_burned
                    logger.info(
                        f"INACTIVITY LEAK: block #{block.header.block_number} "
                        f"burned {total_burned} tokens from "
                        f"{len(inactive)} inactive validators "
                        f"(stall={self.blocks_since_last_finalization} blocks)"
                    )

        # Update base fee for next block based on this block's fullness
        self.supply.update_base_fee(total_tx_count)
        self.base_fee = self.supply.base_fee

        # Update bootstrap_progress ratchet.  Deliberately the LAST step
        # of apply so every upstream state mutation (balances, stakes,
        # escrow unlocks, governance-driven stake changes) is reflected
        # in the computed raw progress.  Called once per block —
        # `bootstrap_progress` is a pure reader elsewhere so committee
        # selection and the sim path see a consistent value until the
        # next apply ticks the ratchet forward.
        self._update_bootstrap_ratchet()

    def _apply_governance_block(self, block: Block):
        """Dispatch governance txs, auto-execute closed binding proposals,
        and prune expired state.

        Three phases, in order:

        1. REGISTER — for each governance tx in the block, update the
           tracker: proposals/treasury-spends are snapshotted; votes are
           recorded.  Fees follow the normal burn-and-tip path.
           Application-layer failures (vote on unknown proposal, etc.)
           are silently dropped — the tx was already block-level valid,
           so the block is not invalidated.

        2. AUTO-EXECUTE — binding proposals (treasury spends, validator
           ejections) whose voting window has closed by this block height
           are executed automatically.  No separate "execute" tx required,
           which eliminates a griefing vector where a passing proposal
           could be indefinitely ignored.

        3. PRUNE — closed proposals are dropped from the tracker to bound
           memory growth.  The audit log in `treasury_spend_log` survives
           pruning so post-hoc accountability does not depend on proposal
           retention.
        """
        if not hasattr(self, "governance") or self.governance is None:
            return
        from messagechain.governance.governance import (
            ProposalTransaction, VoteTransaction,
            TreasurySpendTransaction,
        )
        from messagechain.config import GOVERNANCE_VOTING_WINDOW

        tracker = self.governance
        current_block = block.header.block_number
        proposer_id = block.header.proposer_id
        current_base_fee = self.supply.base_fee

        # Phase 1: register
        for gtx in block.governance_txs:
            if isinstance(gtx, (ProposalTransaction, TreasurySpendTransaction)):
                if not self.supply.pay_fee_with_burn(
                    gtx.proposer_id, proposer_id, gtx.fee, current_base_fee,
                ):
                    logger.error(
                        f"Governance proposal fee payment failed — skipping"
                    )
                    continue
                tracker.add_proposal(
                    gtx, block_height=current_block, supply_tracker=self.supply,
                )
                self._bump_watermark(gtx.proposer_id, gtx.signature.leaf_index)
            elif isinstance(gtx, VoteTransaction):
                if not self.supply.pay_fee_with_burn(
                    gtx.voter_id, proposer_id, gtx.fee, current_base_fee,
                ):
                    logger.error(
                        f"Governance vote fee payment failed — skipping"
                    )
                    continue
                tracker.add_vote(gtx, current_block=current_block)
                self._bump_watermark(gtx.voter_id, gtx.signature.leaf_index)

        # Phase 2: auto-execute binding treasury spends whose window has closed
        for pid, state in list(tracker.proposals.items()):
            proposal = state.proposal
            if not isinstance(proposal, TreasurySpendTransaction):
                continue
            if current_block - state.created_at_block <= GOVERNANCE_VOTING_WINDOW:
                continue
            tracker.execute_treasury_spend(
                proposal, self.supply, current_block=current_block,
                is_new_account=self._recipient_is_new,
            )

        # Phase 3: prune
        tracker.prune_closed_proposals(current_block)

    def add_block(self, block: Block) -> tuple[bool, str]:
        """Validate and append a block, updating state (fees + inflation)."""
        if self.height == 0:
            # Validate genesis block structure
            if block.header.block_number != 0:
                return False, f"First block must be block 0, got {block.header.block_number}"
            if block.header.prev_hash != b"\x00" * 32:
                return False, "Genesis block must have zero prev_hash"
            # Canonical genesis pin: if the network has a declared block-0
            # hash, any incoming block 0 from a peer must match it.  Stops
            # a malicious or misconfigured peer from feeding us a
            # forked-genesis chain that would never reconcile.
            import messagechain.config as _cfg
            pinned = getattr(_cfg, "PINNED_GENESIS_HASH", None)
            if pinned is not None and pinned != block.block_hash:
                return False, (
                    f"Rejecting block 0: its hash "
                    f"{block.block_hash.hex()[:16]}... does not match the "
                    f"pinned genesis {pinned.hex()[:16]}..."
                )
            self.chain.append(block)
            self._block_by_hash[block.block_hash] = block
            self.fork_choice.add_tip(block.block_hash, 0, 0)
            if self.db is not None:
                self.db.store_block(block, state=self)
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
        # Per-entity cap (cheap structural check — no chain state needed).
        _orphan_entity_counts: dict[bytes, int] = {}
        for tx in block.transactions:
            _orphan_entity_counts[tx.entity_id] = _orphan_entity_counts.get(tx.entity_id, 0) + 1
            if _orphan_entity_counts[tx.entity_id] > MAX_TXS_PER_ENTITY_PER_BLOCK:
                return False, "Orphan rejected — per-entity message tx cap exceeded"

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
                proposer_sig_leaf = (
                    block.header.proposer_signature.leaf_index
                    if block.header.proposer_signature is not None
                    else None
                )
                simulated_root = self.compute_post_state_root(
                    transactions=block.transactions,
                    proposer_id=block.header.proposer_id,
                    block_height=block.header.block_number,
                    transfer_transactions=block.transfer_transactions,
                    attestations=block.attestations,
                    authority_txs=getattr(block, "authority_txs", []),
                    stake_transactions=getattr(block, "stake_transactions", []),
                    unstake_transactions=getattr(block, "unstake_transactions", []),
                    governance_txs=getattr(block, "governance_txs", []),
                    finality_votes=getattr(block, "finality_votes", []),
                    proposer_signature_leaf_index=proposer_sig_leaf,
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
            # Entity indices assigned by _apply_block_state above are
            # already in self.entity_id_to_index, so any RegistrationTx
            # in this block can now be referenced compactly too.
            self.db.store_block(block, state=self)
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
        # Two independent layers are consulted:
        #   * self.finality (attestation-layer, in-memory)
        #   * self.finalized_checkpoints (FinalityVote-layer, persistent;
        #     this is the long-range-attack-defense ratchet that survives
        #     restart)
        def _is_finalized(blk: Block) -> bool:
            return (
                self.finality.is_finalized(blk.block_hash)
                or self.finalized_checkpoints.is_finalized(blk.block_hash)
            )
        # Reject outright if the competing block targets a height whose
        # finalized hash differs from its own hash.  This is the explicit
        # long-range rule: no chain may contradict a finalized block.
        if self.finalized_checkpoints.is_height_finalized(
            block.header.block_number,
        ):
            finalized_hash = self.finalized_checkpoints.finalized_by_height[
                block.header.block_number
            ]
            if finalized_hash != block.block_hash:
                return False, (
                    f"Fork rejected — height {block.header.block_number} "
                    f"has a finalized block ({finalized_hash.hex()[:16]}) "
                    f"that this fork contradicts"
                )
        for blk in self.chain:
            if blk.header.block_number == block.header.block_number:
                if _is_finalized(blk):
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
                    if _is_finalized(blk):
                        return False, (
                            f"Fork rejected — canonical block at height "
                            f"{blk.header.block_number} is finalized"
                        )

        # Store the block (even if not on best chain yet).  A fork
        # block that registers a brand-new entity has NOT yet run
        # through _apply_block_state, so that entity lacks an index
        # in self.entity_id_to_index — encode_entity_ref falls back
        # to the legacy 32-byte form for it, which is safe.  Entities
        # registered in the ancestor chain are already indexed and
        # get the compact form here.
        self._block_by_hash[block.block_hash] = block
        if self.db is not None:
            self.db.store_block(block, state=self)

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

        # Finality boundary: refuse to revert finalized blocks.
        # Check both layers (attestation-finality and persistent
        # FinalityCheckpoints) — either is sufficient to pin a block
        # irreversibly.  FinalityCheckpoints is the long-range-attack
        # defense specifically because it survives restart.
        for blk in rollback_blocks:
            if (
                self.finality.is_finalized(blk.block_hash)
                or self.finalized_checkpoints.is_finalized(blk.block_hash)
            ):
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
        # slashed_validators is deliberately NOT cleared here — it is a
        # security ratchet, like revoked_entities and leaf_watermarks.
        # Once an equivocation is detected on any fork, the punishment
        # is permanent; clearing it would allow slash evasion via reorg.
        # _processed_evidence (also not cleared) stays consistent.
        self.reputation = {}
        self._immature_rewards = []
        # Reset the bootstrap ratchet — it will rebuild deterministically
        # as blocks replay via _update_bootstrap_ratchet.  Every node
        # replaying the same chain reaches the same ratchet peak.
        from messagechain.consensus.bootstrap_gradient import RatchetState
        self._bootstrap_ratchet = RatchetState()
        from messagechain.economics.escrow import EscrowLedger
        self._escrow = EscrowLedger()
        # Reset in-memory attestation finality tracker — old-fork finality
        # data must not persist.  Note: finalized_checkpoints (persistent,
        # long-range-attack defense) is deliberately NOT reset.
        self.finality = FinalityTracker()

        # Restore public keys with zero balances — balances rebuild from block replay
        for eid, pk in old_pks.items():
            self.public_keys[eid] = pk
            self.nonces[eid] = 0

    def _snapshot_memory_state(self) -> dict:
        """Capture in-memory state for rollback.

        Includes governance state (votes, executed spends) so that chain
        reorganizations properly revert governance side-effects.

        Fields that are DELIBERATELY NOT snapshotted (security-ratchet):
        - leaf_watermarks: a WOTS+ leaf that was ever published on any
          fork is permanently burned because its private material is
          public knowledge. Rolling it back would re-enable reuse.
        - revoked_entities: emergency revocation is an authority-key-signed
          kill-switch. Once broadcast it represents a clear authorized
          intent to disable the entity; we preserve it across reorgs.
        - slashed_validators: once an equivocation is detected on any
          fork, the punishment is permanent. Rolling it back would allow
          slash evasion via reorg while _processed_evidence still blocks
          re-submission of the same evidence.
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
            # Cold authority keys are set via a SetAuthorityKey tx that
            # lives inside a block. If that block is rolled back the
            # authority binding must also revert, otherwise a reorged-out
            # cold-key assignment would persist with no on-chain record.
            "authority_keys": dict(self.authority_keys),
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
            # Bootstrap ratchet.  Snapshotted so reorg rollback restores
            # the same peak the chain had before the reorg — the ratchet
            # is strictly monotonic within the canonical chain's history
            # and must not silently regress across a reorg that undoes
            # and re-applies blocks.
            "bootstrap_ratchet_max": self._bootstrap_ratchet.max_progress,
            "blocks_since_last_finalization": self.blocks_since_last_finalization,
            # Seed divestment snapshot: reorg-safe so the once-per-seed
            # initial-stake reference is not silently rebuilt from a
            # post-reorg stake value on replay.
            "seed_initial_stakes": dict(self.seed_initial_stakes),
        }
        # Snapshot governance state if tracker is attached.
        # deepcopy the full proposals dict so that nested mutation on a
        # later fork (e.g., new votes, flipped votes, updated
        # stake_snapshot) cannot leak through the rollback boundary.
        # Reorgs are rare, so correctness over performance here.
        if hasattr(self, "governance") and self.governance is not None:
            gov = self.governance
            snapshot["gov_proposals"] = copy.deepcopy(gov.proposals)
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
        # Restore bootstrap ratchet.  Default 0.0 matches a freshly-
        # built Blockchain (pre-any-block) and is safe for snapshots
        # that predate this field.  The ratchet is otherwise strictly
        # monotonic within the canonical chain, so any snapshot taken
        # at height H has the correct peak for block H.
        ratchet_value = snapshot.get("bootstrap_ratchet_max", 0.0)
        from messagechain.consensus.bootstrap_gradient import RatchetState
        self._bootstrap_ratchet = RatchetState()
        if ratchet_value > 0.0:
            self._bootstrap_ratchet.observe(ratchet_value)
        self.blocks_since_last_finalization = snapshot.get(
            "blocks_since_last_finalization", 0,
        )
        self.seed_initial_stakes = dict(
            snapshot.get("seed_initial_stakes", {})
        )
        if "authority_keys" in snapshot:
            self.authority_keys = dict(snapshot["authority_keys"])
        if "pending_unstakes" in snapshot:
            self.supply.pending_unstakes = {
                eid: list(entries)
                for eid, entries in snapshot["pending_unstakes"].items()
            }
        # Restore governance state if tracker is attached and was snapshotted.
        # deepcopy again on the way out so the snapshot itself is not
        # aliased with live state — a subsequent failed reorg could
        # otherwise mutate the stored dict through the restored reference.
        if hasattr(self, "governance") and self.governance is not None:
            if "gov_proposals" in snapshot:
                self.governance.proposals = copy.deepcopy(snapshot["gov_proposals"])
            if "gov_executed_treasury_spends" in snapshot:
                self.governance._executed_treasury_spends = set(
                    snapshot["gov_executed_treasury_spends"],
                )

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
                    "message": tx.plaintext.decode("utf-8", errors="replace"),
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

    def list_validators(self) -> list[dict]:
        """Return the staked validator set, sorted by stake desc.

        On-chain data only: entity ID, stake, blocks produced.
        Network-layer details (IP, uptime) are intentionally excluded —
        broadcasting those aids targeting and has no consensus purpose.
        """
        staked = {
            eid: amount
            for eid, amount in self.supply.staked.items()
            if amount > 0
        }
        total_stake = sum(staked.values())
        rows = []
        for eid, amount in staked.items():
            rows.append({
                "entity_id": eid.hex(),
                "staked": amount,
                "stake_pct": (100.0 * amount / total_stake) if total_stake else 0.0,
                "blocks_produced": self.proposer_sig_counts.get(eid, 0),
            })
        rows.sort(key=lambda r: r["staked"], reverse=True)
        return rows
