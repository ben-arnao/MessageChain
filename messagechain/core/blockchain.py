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
    MIN_FEE, MAX_TIMESTAMP_DRIFT, KEY_ROTATION_FEE,
    KEY_ROTATION_COOLDOWN_BLOCKS, BASE_FEE_INITIAL,
    NEW_ACCOUNT_FEE, MAX_NEW_ACCOUNTS_PER_BLOCK,
    EVIDENCE_INCLUSION_WINDOW, EVIDENCE_EXPIRY_BLOCKS,
)
from messagechain.core.block import (
    Block, compute_merkle_root, compute_state_root, create_genesis_block,
    canonical_block_tx_hashes,
)
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
from messagechain.core.receipt_subtree_root import (
    SetReceiptSubtreeRootTransaction,
    verify_set_receipt_subtree_root_transaction,
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
from messagechain.crypto.keys import (
    compute_root_from_signature,
    verify_signature,
)
from messagechain.crypto.sig_cache import get_global_cache
from messagechain.consensus.fork_choice import (
    ForkChoice, compute_block_stake_weight, find_fork_point, MAX_REORG_DEPTH,
)

logger = logging.getLogger(__name__)


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _canonicalize_authority_txs(authority_txs):
    """Deterministic in-block ordering for authority transactions.

    M4 audit fix: if a single block contains both a Revoke and a
    SetAuthorityKey for the same entity, their relative order was
    previously whatever order the block proposer listed them in —
    giving an attacker with a compromised hot key a race condition
    against the legitimate cold-key holder.

    The rule is simple: **Revoke precedes SetAuthorityKey**.  A Revoke
    is issued by the cold authority key specifically because the hot
    key is suspected compromised; a hot-key-signed SetAuthorityKey in
    the same block MUST NOT be allowed to land first and rotate the
    authority key out from under the revoker.

    Within each type we preserve the proposer's given order — this
    matters because SetAuthorityKey consumes a nonce, and a proposer
    may legitimately pack multiple Sets for different entities.  The
    sort is stable so same-type ordering is unchanged.

    Returns a NEW list; callers should iterate the returned list in
    both the simulation and apply paths so the committed state root
    matches between proposer and verifier.
    """
    if not authority_txs:
        return []

    def _priority(atx) -> int:
        # Lower number runs first.
        name = atx.__class__.__name__
        if name == "RevokeTransaction":
            return 0
        if name == "SetAuthorityKeyTransaction":
            return 1
        # KeyRotation and any future authority-tx types land after
        # SetAuthorityKey by default.  KeyRotation swaps the hot
        # signing key, which is conceptually independent of the
        # cold-key Set/Revoke decision, so its relative order among
        # the non-revoke types is not security-critical — keep it
        # after Set so a Revoke in the same block still dominates.
        return 2

    return sorted(authority_txs, key=_priority)


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
        # Each censorship-evidence tx carries one submitter signature +
        # one receipt signature — cost both.
        + 2 * len(getattr(block, "censorship_evidence_txs", []))
        # Each bogus-rejection-evidence tx carries one submitter
        # signature + one rejection signature — cost both.
        + 2 * len(getattr(block, "bogus_rejection_evidence_txs", []))
        # Each inclusion-list violation evidence tx carries ONE
        # submitter signature.  The bundled InclusionList carries
        # variable-many attester report sigs, but those are amortised
        # via the inclusion_list field below — counting them again
        # here would double-charge.
        + len(getattr(block, "inclusion_list_violation_evidence_txs", []))
        # Inclusion-list scalar slot: each attester report inside the
        # quorum_attestation carries one signature.  Cap-bounded by
        # MAX_INCLUSION_LIST_ENTRIES + the number of staked validators,
        # so this stays within the existing per-block sig budget.
        + (
            len(block.inclusion_list.quorum_attestation)
            if getattr(block, "inclusion_list", None) is not None
            else 0
        )
    )


class Blockchain:
    """The chain: ordered list of validated blocks + derived state.

    Can operate in two modes:
    - In-memory (default, backward compatible): no db argument
    - Persistent (SQLite): pass a ChainDB instance
    """

    def __init__(self, db=None, trusted_checkpoints=None):
        self.db = db  # optional ChainDB for persistence
        # Weak-subjectivity checkpoints — long-range-attack defense.
        # The gate lives in add_block so EVERY block-entry path inherits
        # it (IBD, ANNOUNCE_BLOCK, RESPONSE_BLOCK, reorg replay).  Keyed
        # by block_number → expected block_hash (32 bytes).  Accepts
        # either a list of WeakSubjectivityCheckpoint objects (duck-typed:
        # .block_number + .block_hash) or a pre-built dict.
        self._trusted_checkpoints: dict[int, bytes] = {}
        if trusted_checkpoints is not None:
            self.set_trusted_checkpoints(trusted_checkpoints)
        self.chain: list[Block] = []
        self.supply = SupplyTracker()
        self.base_fee: int = self.supply.base_fee  # mirror for easy access
        self.nonces: dict[bytes, int] = {}  # entity_id -> next expected nonce
        self.public_keys: dict[bytes, bytes] = {}  # entity_id -> public_key
        # WOTS+ Merkle tree height per entity, captured the moment the
        # entity's pubkey is installed on chain (genesis, first-spend
        # reveal, or _install_pubkey_direct).  Carried so a server
        # restart can rebuild the SAME keypair (same entity_id derivation)
        # from the private key without guessing a tree_height from global
        # config — a mismatch would silently produce a different entity_id
        # and make the node unable to sign for its own wallet.
        # Set-once per entity: a pubkey install that's already recorded
        # in this map never overwrites, so an entity's tree height is
        # as immutable as its entity_id.  Key rotation keeps the same
        # tree_height by construction (derive_rotated_keypair reuses the
        # keypair's height).
        self.wots_tree_heights: dict[bytes, int] = {}
        self.entity_message_count: dict[bytes, int] = {}
        self.key_rotation_counts: dict[bytes, int] = {}  # entity_id -> rotation number
        # In-memory rotation cooldown tracking (iter 6 H2).  See comment
        # at the _reset_state twin-init below for the rationale.
        self.key_rotation_last_height: dict[bytes, int] = {}
        # R6-A: Historical public-key record per entity.  Maps
        # entity_id -> [(installed_at_height, public_key), ...] sorted
        # ascending by install height.  Captured on first install
        # (registration / first-spend / genesis / founder bootstrap) and
        # every KeyRotation.  Consulted by slash verification to resolve
        # the key that was ACTIVE at evidence_height — without this, an
        # offender could equivocate at height N, rotate at N+1, and then
        # silently defeat any slash tx (evidence signature fails to
        # verify against the NEW current key).  Cheap: a handful of
        # entries per validator, permanent retention simplifies the code
        # path.
        self.key_history: dict[bytes, list[tuple[int, bytes]]] = {}
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
        # Retained permanently: CLAUDE.md principle #2 (permanence) —
        # historical finality proofs must remain reconstructible forever.
        # See _record_stake_snapshot for the storage-cost argument.
        self._stake_snapshots: dict[int, dict[bytes, int]] = {}
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
        # The per-block decrement is `(initial - RETAIN_FLOOR) / window`
        # and stays fixed for the entire divestment window —
        # deterministic from replay, since every node re-applies block
        # START+1 and records the same value.  Snapshotted in
        # _snapshot_memory_state for reorg safety.
        self.seed_initial_stakes: dict[bytes, int] = {}

        # Per-seed fractional debt for divestment accounting
        # (entity_id -> scaled fractional units).  SCALE = 10**9 of a
        # whole token.  Each divestment block adds
        # `(divestible * SCALE) // window` to the seed's debt; when debt
        # crosses SCALE, that many whole tokens are drained and the
        # integer-token portion is subtracted from the debt.
        #
        # Why fractional: the OLD formula `per_block = initial // window`
        # silently floored to 0 whenever `divestible < window`, producing
        # a no-op divestment for small stakes (e.g. 50K stake with a
        # 210K-block window).  The fractional representation is
        # integer-only (consensus-safe) and correctly drains tiny
        # amounts over the full window.
        #
        # Migration: pre-existing chains reload this dict as empty —
        # debt accumulates forward from the next divestment block.  A
        # chain reloading mid-window has a one-block timing discrepancy
        # where up to ~1 token of fractional debt is dropped; acceptable
        # for the prototype phase since the absolute error is bounded
        # by 1 token per seed per reload.
        self.seed_divestment_debt: dict[bytes, int] = {}

        # Proof-of-custody archive reward pool — single scalar balance
        # consensus-visible in the state root.  Funded by redirecting
        # ARCHIVE_BURN_REDIRECT_PCT of what would have burned from
        # EIP-1559 base fees; drained by apply_archive_rewards every
        # ARCHIVE_CHALLENGE_INTERVAL blocks to pay up to
        # ARCHIVE_PROOFS_PER_CHALLENGE custody-proof submitters.
        # Persists forever across blocks — unused rewards never expire
        # (permanence aligns with CLAUDE.md principle #2: the pool is
        # on-chain state like any balance).  See
        # docs/proof-of-custody-archive-rewards.md for the design.
        self.archive_reward_pool: int = 0

        # Archive-custody duty state (iteration 3b-ii).  Three pieces:
        #
        #   archive_active_snapshot:
        #     Optional[ActiveValidatorSnapshot].  Materialized at each
        #     challenge block (height % ARCHIVE_CHALLENGE_INTERVAL == 0)
        #     carrying the staked-validator set and the K challenge
        #     heights derived via compute_challenges.  Cleared at epoch
        #     close (challenge_block + ARCHIVE_SUBMISSION_WINDOW) after
        #     miss counters are updated.  At most one open epoch at a
        #     time — windows do not overlap under the current
        #     interval/window sizing.
        #
        #   validator_archive_misses:
        #     dict[entity_id -> int].  Persistent miss counter; +1 per
        #     epoch where validator was active-at-C and did not submit
        #     proofs for all K challenge heights within the window, -1
        #     (floor 0) per successful epoch, bootstrap-exempt during
        #     grace.  State-lean: zero entries are omitted.  Drives the
        #     graduated reward-withhold tier in iteration 3b-iii.
        #
        #   validator_first_active_block:
        #     dict[entity_id -> int].  Block height at which the
        #     validator was first observed above VALIDATOR_MIN_STAKE.
        #     Never advanced — a validator that drops below threshold
        #     and re-enters keeps their original first-active so they
        #     don't pick up a fresh bootstrap grace on every stake
        #     cycle.  Seeded lazily from _apply_block_state.
        #
        # Snapshot persistence (encode_snapshot / state_root inclusion)
        # is deferred to iteration 3b-iii alongside reward withholding,
        # so both consensus-surface changes share one version bump.
        from messagechain.consensus.archive_duty import (
            ActiveValidatorSnapshot as _ActiveSnapshot,  # noqa: F401
        )
        self.archive_active_snapshot = None  # Optional[ActiveValidatorSnapshot]
        self.validator_archive_misses: dict[bytes, int] = {}
        self.validator_first_active_block: dict[bytes, int] = {}

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

        # Censorship-evidence processor.  Lifecycle: every admitted
        # CensorshipEvidenceTx goes through processor.submit(), every
        # block triggers processor.observe_block() to void evidence
        # whose tx just landed, and at the end of _apply_block_state
        # processor.mature(height) returns evidences ready to slash.
        # Both maps (pending + processed) participate in the state
        # root so every node reaches identical slashing outcomes.
        # See messagechain.consensus.censorship_evidence for the
        # two-phase design rationale.
        from messagechain.consensus.censorship_evidence import (
            CensorshipEvidenceProcessor,
        )
        self.censorship_processor: CensorshipEvidenceProcessor = (
            CensorshipEvidenceProcessor()
        )

        # Bogus-rejection processor.  One-phase: every admitted
        # BogusRejectionEvidenceTx triggers processor.process(),
        # which (for the slashable subset of reason codes) re-verifies
        # the embedded message_tx and slashes the issuer immediately
        # if the rejection was bogus.  No pending map / no maturity
        # window — bogusness is decidable at apply-time from the tx
        # payload + chain state.  See
        # messagechain.consensus.bogus_rejection_evidence.
        from messagechain.consensus.bogus_rejection_evidence import (
            BogusRejectionProcessor,
        )
        self.bogus_rejection_processor: BogusRejectionProcessor = (
            BogusRejectionProcessor()
        )

        # Inclusion-list processor.  Tracks active forward windows for
        # quorum-signed inclusion lists and the (tx_hash, proposer_id)
        # set of violations already slashed (double-slash defence).
        # Lifecycle:
        #   - register(list, height) when a block carrying an
        #     inclusion_list is applied.
        #   - observe_block(block) every block apply: records which
        #     mandated txs landed and which proposer was active at
        #     each height.
        #   - expire(height) at end of each apply: drops lists whose
        #     window has closed; emits InclusionViolation records for
        #     missed txs.  Caller (Blockchain) handles the slashing
        #     via process_inclusion_list_violation when an evidence-tx
        #     arrives in a later block.
        # Snapshot-serialised so every node reaches identical slashing
        # outcomes after replay.  See
        # messagechain.consensus.inclusion_list.
        from messagechain.consensus.inclusion_list import (
            InclusionListProcessor,
        )
        self.inclusion_list_processor: InclusionListProcessor = (
            InclusionListProcessor()
        )

        # Per-validator receipt-subtree root registry.  Receipts are
        # signed with a DIFFERENT WOTS+ subtree than block-signing;
        # every validator that wants to issue receipts registers the
        # subtree root here.  Maps entity_id -> 32-byte root pubkey.
        # The CensorshipEvidenceTx validation path cross-checks that
        # the receipt's embedded root matches the registered root for
        # the issuer, so a stale receipt signed by an old subtree
        # cannot be weaponized against an operator who rotated.  An
        # unregistered issuer's receipts are treated as self-
        # contained: if the receipt signature verifies against its
        # embedded root, that's enough — the slashing check verifies
        # the embedded root IS the registered root only when the
        # issuer has one on file.
        self.receipt_subtree_roots: dict[bytes, bytes] = {}

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

    def set_trusted_checkpoints(self, checkpoints) -> None:
        """Install (or refresh) the weak-subjectivity checkpoint set.

        Called at Node/Server startup after loading from config +
        data_dir/checkpoints.json, and can be called again later if the
        operator ships a newer checkpoint file.  Replaces the current
        set entirely (no merge) so removing a stale checkpoint is
        possible from the operator side.

        Accepts either:
          - list[WeakSubjectivityCheckpoint] (or any duck-typed object
            exposing .block_number:int and .block_hash:bytes)
          - dict[int, bytes] mapping block_number → expected block_hash
        """
        new_map: dict[int, bytes] = {}
        if isinstance(checkpoints, dict):
            for bn, bh in checkpoints.items():
                if not isinstance(bn, int) or not isinstance(bh, (bytes, bytearray)):
                    continue
                new_map[int(bn)] = bytes(bh)
        else:
            for cp in (checkpoints or []):
                bn = getattr(cp, "block_number", None)
                bh = getattr(cp, "block_hash", None)
                if not isinstance(bn, int) or not isinstance(bh, (bytes, bytearray)):
                    continue
                new_map[bn] = bytes(bh)
        self._trusted_checkpoints = new_map

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

        # One-shot phantom-supply migration: legacy mainnet state has
        # total_supply=1B persisted (the pre-fix GENESIS_SUPPLY).  Detect
        # and rebase to the corrected 140M value before populating the
        # in-memory SupplyTracker, so the rest of this load path sees a
        # clean invariant.  Idempotent; no-op on fresh / already-migrated
        # chains.  See ChainDB.migrate_phantom_supply_if_needed.
        if hasattr(self.db, "migrate_phantom_supply_if_needed"):
            if self.db.migrate_phantom_supply_if_needed():
                logger.warning(
                    "Phantom-supply migration applied: rebased persisted "
                    "total_supply from 1_000_000_000 to 140_000_000 to "
                    "restore invariant total_supply == sum(balances) "
                    "+ sum(staked) + net inflation."
                )

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

        # Restore per-entity WOTS+ tree heights.  Consulted at server
        # startup to rebuild the SAME keypair from the operator's
        # private key, independent of whatever global config the
        # process was launched with.
        if hasattr(self.db, 'get_all_wots_tree_heights'):
            self.wots_tree_heights = self.db.get_all_wots_tree_heights()

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

        # Restore pending censorship-evidence + receipt-subtree roots.
        # Without these a cold-booted node loses the maturity pipeline
        # and silently fails to slash evidences admitted pre-restart.
        if hasattr(self.db, "get_all_pending_censorship_evidence"):
            from messagechain.consensus.censorship_evidence import (
                _PendingEvidence,
            )
            self.censorship_processor.pending = {}
            # Populate the processor's processed set from the main
            # processed_evidence table — censorship-evidence hashes
            # are recorded there too on mature/void.
            self.censorship_processor.processed = set(self._processed_evidence)
            for ev_hash, payload in self.db.get_all_pending_censorship_evidence().items():
                offender_id, tx_hash, admitted_height, evidence_tx_hash = payload
                self.censorship_processor.pending[ev_hash] = _PendingEvidence(
                    evidence_hash=ev_hash,
                    offender_id=offender_id,
                    tx_hash=tx_hash,
                    admitted_height=admitted_height,
                    evidence_tx_hash=evidence_tx_hash,
                )
        if hasattr(self.db, "get_all_receipt_subtree_roots"):
            self.receipt_subtree_roots = self.db.get_all_receipt_subtree_roots()

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

        # Rehydrate seed_entity_ids from block 0.  This set is consensus-
        # visible (attester committee tilt, reputation-lottery exclusion,
        # seed-divestment schedule) but was not previously persisted —
        # a restart would reset it to frozenset() and silently change
        # committee weights / lottery eligibility compared to a node
        # that never restarted.  Re-deriving from block 0 is safe: the
        # current protocol enforces exactly one seed (bootstrap.py line
        # `if len(seed_entity_ids) != 1`), and that seed is by
        # construction the proposer of block 0.
        if self.chain:
            genesis_proposer = self.chain[0].header.proposer_id
            if genesis_proposer and genesis_proposer != b"\x00" * 32:
                self.seed_entity_ids = frozenset({genesis_proposer})

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
            if hasattr(self.db, 'set_wots_tree_height'):
                # Set-once at the storage layer (INSERT OR IGNORE), so
                # re-persisting unchanged entries is a cheap no-op.
                for eid, th in self.wots_tree_heights.items():
                    self.db.set_wots_tree_height(eid, th)
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
            # Persist pending censorship-evidence so a restart picks
            # up the maturity pipeline mid-flight.
            if hasattr(self.db, "set_pending_censorship_evidence"):
                # The full set is written each flush; REPLACE
                # semantics make re-persisting unchanged entries a
                # no-op at the storage layer.
                for ev_hash, entry in self.censorship_processor.pending.items():
                    self.db.set_pending_censorship_evidence(
                        ev_hash,
                        entry.offender_id,
                        entry.tx_hash,
                        entry.admitted_height,
                        entry.evidence_tx_hash,
                    )
                # Persist processed censorship-evidence hashes into the
                # shared processed_evidence table (single source of
                # truth for evidence-dedupe across both slashing types).
                if hasattr(self.db, "mark_evidence_processed"):
                    for ev_hash in self.censorship_processor.processed:
                        self.db.mark_evidence_processed(ev_hash, self.height)
            if hasattr(self.db, "set_receipt_subtree_root"):
                for eid, rk in self.receipt_subtree_roots.items():
                    self.db.set_receipt_subtree_root(eid, rk)
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
        self._record_key_history(
            genesis_entity.entity_id, genesis_entity.public_key,
        )
        self.nonces[genesis_entity.entity_id] = 0
        # Capture the genesis entity's WOTS+ tree_height in chain state so
        # a server restart can reconstruct the same keypair from the
        # private key without trusting global config.
        self._set_tree_height_explicit(
            genesis_entity.entity_id, genesis_entity.keypair.height,
        )
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

        # Persist atomically.  Without the wrapping transaction, a
        # SIGKILL between store_block and _persist_state leaves block 0
        # on disk with NO founder pubkey / balances / stake — and
        # block 1 later fails state_root verification forever (val-2
        # operator sees a stuck height=1 with no repair path).
        if self.db is not None:
            self.db.begin_transaction()
            try:
                # Thread `self` as state so the compact entity-index wire form
                # lands on disk.  The genesis entity is already registered in
                # self.entity_id_to_index by this point, so the tx encoder
                # can swap its 32-byte id for a 1-byte varint index.
                self.db.store_block(genesis_block, state=self)
                self.db.add_chain_tip(genesis_block.block_hash, 0, 0)
                self._persist_state()
                self.db.commit_transaction()
            except BaseException:
                self.db.rollback_transaction()
                raise

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

        # Archive reward pool — consensus-visible balance that funds
        # custody-proof payouts.  Must be restored from the snapshot or
        # a cold-booted node starts with pool=0 while a replaying node
        # has pool=N; their next challenge block pays a different
        # number of provers and the chain forks.  The pool is hashed
        # into the snapshot root under _TAG_GLOBAL /
        # _GLOBAL_ARCHIVE_REWARD_POOL (see storage.state_snapshot), so
        # drift here is immediately detectable as a snapshot-root
        # mismatch.
        self.archive_reward_pool = int(snap.get("archive_reward_pool", 0))

        # Archive-duty state (v6+).  All three fields participate in
        # the state root, so a bootstrapping node inherits them from
        # the canonical snapshot; a replaying node would rebuild them
        # from block history and arrive at the same values.  Absent
        # entries default to empty maps / no open snapshot (pre-v6
        # snapshots or fresh chain state).
        self.validator_archive_misses = dict(
            snap.get("validator_archive_misses", {})
        )
        self.validator_first_active_block = dict(
            snap.get("validator_first_active_block", {})
        )
        self.archive_active_snapshot = snap.get(
            "archive_active_snapshot", None,
        )

        # Finalized checkpoints (long-range-attack defense — must carry
        # across the bootstrap boundary or the new node would accept a
        # competing chain that contradicts a known-finalized block).
        for bn, bh in snap["finalized_checkpoints"].items():
            self.finalized_checkpoints.mark_finalized(bh, bn)

        # Seed divestment reference dict — captured once at the first
        # divestment block and used as the denominator for the flat
        # per-block unbond through END.  Without this a state-synced
        # node mid-divestment would re-capture the *post-divestment*
        # stake at its next divestment block, producing a smaller
        # per-block decrement than replaying nodes and forking off the
        # canonical chain until END.  Consensus-critical; kept in the
        # snapshot root.  See state_snapshot._TAG_SEED_INIT_STAKES.
        self.seed_initial_stakes = dict(
            snap.get("seed_initial_stakes", {})
        )
        # Seed divestment fractional debt — per-seed fractional
        # remainder for the new divestion-to-floor schedule.  Must be
        # installed alongside seed_initial_stakes so a state-synced
        # node's next divestment block computes the identical per-block
        # integer drain as a replaying node.  See
        # state_snapshot._TAG_SEED_DIVEST_DEBT.
        self.seed_divestment_debt = dict(
            snap.get("seed_divestment_debt", {})
        )

        # Censorship-evidence processor state.  Install BEFORE
        # rebuilding the state tree so a subsequent state-root
        # computation reflects the installed pending/processed dicts.
        from messagechain.storage.state_snapshot import (
            _bytes_dict_to_pending,
        )
        from messagechain.consensus.censorship_evidence import (
            _PendingEvidence,
        )
        self.censorship_processor.pending = {}
        self.censorship_processor.processed = set(
            snap.get("censorship_processed", set())
        )
        for entry in _bytes_dict_to_pending(snap.get("censorship_pending", {})):
            ev_hash, offender_id, tx_hash, admitted_height, evidence_tx_hash = entry
            self.censorship_processor.pending[ev_hash] = _PendingEvidence(
                evidence_hash=ev_hash,
                offender_id=offender_id,
                tx_hash=tx_hash,
                admitted_height=admitted_height,
                evidence_tx_hash=evidence_tx_hash,
            )
        self.receipt_subtree_roots = dict(
            snap.get("receipt_subtree_roots", {})
        )

        # Bogus-rejection processor: install processed set from snapshot.
        # No pending counterpart — apply-time decision.
        self.bogus_rejection_processor.processed = set(
            snap.get("bogus_rejection_processed", set())
        )

        # Inclusion-list processor: install active forward-window
        # lists + processed_violations from snapshot.  Active lists are
        # canonical-bytes encoded under publish_height keys; the
        # processed-violations set is bytes(tx_hash || proposer_id)
        # concatenations.  Per-list bookkeeping (inclusions_seen +
        # proposers_by_height) is rebuilt empty — those are derived
        # from observe_block calls during forward replay and don't
        # affect any consensus decision once the active window has
        # closed (only the `expire()` time fires from them).  At the
        # snapshot height the chain is mid-window and observe_block
        # will repopulate as new blocks arrive.
        from messagechain.consensus.inclusion_list import (
            InclusionList as _InclusionList,
        )
        active = {}
        for ph, blob in snap.get("inclusion_list_active", {}).items():
            active[int(ph)] = _InclusionList.from_bytes(bytes(blob))
        self.inclusion_list_processor.active_lists = active
        self.inclusion_list_processor.proposers_by_height = {
            lst.list_hash: {} for lst in active.values()
        }
        self.inclusion_list_processor.inclusions_seen = {}
        violations: set[tuple[bytes, bytes]] = set()
        for compound in snap.get("inclusion_list_processed_violations", set()):
            # Each entry is bytes(tx_hash || proposer_id) — both 32
            # bytes.  Strict-shape check guards against a malformed
            # snapshot from a forked node.
            if len(compound) != 64:
                raise ValueError(
                    "inclusion_list_processed_violations entry must be "
                    f"64 bytes, got {len(compound)}"
                )
            violations.add((bytes(compound[:32]), bytes(compound[32:])))
        self.inclusion_list_processor.processed_violations = violations

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

        # M4: a revoked entity's hot key is suspected compromised.  The
        # whole point of the revoke is that subsequent hot-key actions
        # (including SetAuthorityKey signed by that hot key) must NOT be
        # allowed to take effect.  Combined with the canonical Revoke-
        # before-Set ordering in _apply_block_state, this makes a
        # same-block race unwinnable for the attacker.
        if tx.entity_id in self.revoked_entities:
            return False, "Entity is revoked — authority key is frozen"

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
        if not verify_set_authority_key_transaction(
            tx, signing_pk, current_height=self.height + 1,
        ):
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
        if authority_pk is None or not verify_revoke_transaction(
            tx, authority_pk, current_height=self.height + 1,
        ):
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
        self._record_key_history(entity_id, public_key)
        self.nonces[entity_id] = 0
        self._bump_watermark(entity_id, registration_proof.leaf_index)
        self._assign_entity_index(entity_id)
        # Bind the WOTS+ tree_height to this entity: derived from the
        # registration proof's auth_path length, so a server restart can
        # rebuild the exact same keypair without guessing a global
        # config value that may have drifted.
        self._record_tree_height(entity_id, registration_proof)
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
        # Upper bound: reject future-dated txs at the same threshold the
        # block-pack path enforces.  Without this, a future-stamped tx
        # in mempool lands with `now - tx.timestamp < 0`, so its mempool
        # TTL subtraction is negative and `expire_transactions` never
        # evicts it — the slot is pinned forever until fee-based eviction.
        import time as _time
        from messagechain.config import MAX_TIMESTAMP_DRIFT
        _now = int(_time.time())
        if tx.timestamp > _now + MAX_TIMESTAMP_DRIFT:
            return False, (
                f"Transaction timestamp {tx.timestamp} is >{MAX_TIMESTAMP_DRIFT}s "
                f"in the future (now={_now}) — reject future-dated tx"
            )

        if self.get_spendable_balance(tx.entity_id) < tx.fee:
            return False, f"Insufficient spendable balance for fee of {tx.fee}"

        if tx.signature.leaf_index < self.leaf_watermarks.get(tx.entity_id, 0):
            return False, (
                f"WOTS+ leaf {tx.signature.leaf_index} already consumed "
                f"(watermark {self.leaf_watermarks[tx.entity_id]}) — leaf reuse rejected"
            )

        public_key = self.public_keys[tx.entity_id]
        # A mempool-admitted tx lands in the next block (height+1), so gate
        # the fee-includes-signature rule on that target height.
        if not verify_transaction(
            tx, public_key, current_height=self.height + 1,
        ):
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

        if not verify_transfer_transaction(
            tx, verifying_pubkey, current_height=self.height + 1,
        ):
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
            self._record_key_history(tx.entity_id, tx.sender_pubkey)
            # Nonce 0 is the genesis nonce for first-spend; the
            # `self.nonces[tx.entity_id] = tx.nonce + 1` at the bottom
            # of this function bumps it to 1.
            self.nonces.setdefault(tx.entity_id, 0)
            self._assign_entity_index(tx.entity_id)
            # Capture the sender's WOTS+ tree_height from the signature
            # auth_path length — the canonical in-signature commitment
            # to tree height.  One-shot: only the first-spend install
            # binds the height.
            self._record_tree_height(tx.entity_id, tx.signature)
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
            self._record_key_history(tx.entity_id, tx.sender_pubkey)
            self.nonces.setdefault(tx.entity_id, 0)
            self._assign_entity_index(tx.entity_id)
            # Capture WOTS+ tree_height on first-spend (see
            # apply_transfer_transaction docstring for rationale).
            self._record_tree_height(tx.entity_id, tx.signature)
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

        # Cooldown between successive rotations by the same entity.
        # Blocks forensic-evasion spam where a funded attacker rotates
        # every block to erase recent-slashable-behavior associations.
        # See iter 6 H2 audit finding.  In-memory tracking only (resets
        # on restart, which is conservatively-safe: restart timing is
        # operator-controlled, not attacker-triggerable over RPC).
        last_rot_h = self.key_rotation_last_height.get(tx.entity_id, -KEY_ROTATION_COOLDOWN_BLOCKS)
        elapsed = self.height - last_rot_h
        if elapsed < KEY_ROTATION_COOLDOWN_BLOCKS:
            return False, (
                f"Key rotation cooldown: {KEY_ROTATION_COOLDOWN_BLOCKS - elapsed} "
                f"blocks remaining before next rotation allowed"
            )

        if not self.supply.can_afford_fee(tx.entity_id, tx.fee):
            return False, f"Insufficient balance for rotation fee of {tx.fee}"

        if tx.signature.leaf_index < self.leaf_watermarks.get(tx.entity_id, 0):
            return False, (
                f"WOTS+ leaf {tx.signature.leaf_index} already consumed "
                f"(watermark {self.leaf_watermarks[tx.entity_id]}) — leaf reuse rejected"
            )

        if not verify_key_rotation(
            tx, current_pk, current_height=self.height + 1,
        ):
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
        # R6-A: record the rotation in key_history so slash verification
        # of evidence predating the rotation uses the OLD key (which
        # signed the equivocation).
        self._record_key_history(tx.entity_id, tx.new_public_key)
        self.key_rotation_counts[tx.entity_id] = tx.rotation_number + 1
        # Track rotation block height for cooldown enforcement (iter 6 H2).
        self.key_rotation_last_height[tx.entity_id] = self.height

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

    def validate_set_receipt_subtree_root(
        self, tx: SetReceiptSubtreeRootTransaction,
    ) -> tuple[bool, str]:
        """Validate a SetReceiptSubtreeRoot tx against current chain state.

        Gated by the entity's authority (cold) key — same cold-key
        promise as Revoke / Unstake.  A compromised hot key cannot
        swap out the receipt-subtree root and invalidate in-flight
        evidence against this validator.
        """
        if tx.entity_id not in self.public_keys:
            return False, "Unknown entity — must register first"

        # A revoked entity is suspected compromised on its hot key; the
        # cold key is still in operator control, so the registration
        # path MUST remain available (operators need to publish the
        # receipt root when first onboarding after a cold-key ceremony,
        # even on a hot-key-frozen identity).  We therefore do NOT
        # reject revoked entities here — the signature is verified
        # against the cold key below, which is uncompromised by design.

        if not self.supply.can_afford_fee(tx.entity_id, tx.fee):
            return False, f"Insufficient balance for fee of {tx.fee}"

        authority_pk = self.get_authority_key(tx.entity_id)
        if authority_pk is None or not verify_set_receipt_subtree_root_transaction(
            tx, authority_pk, current_height=self.height + 1,
        ):
            return False, (
                "Invalid signature — set_receipt_subtree_root must be signed by "
                "the authority (cold) key.  The hot signing key cannot register "
                "a receipt-subtree root."
            )

        return True, "Valid"

    def apply_set_receipt_subtree_root(
        self,
        tx: SetReceiptSubtreeRootTransaction,
        proposer_id: bytes,
    ) -> tuple[bool, str]:
        """Validate, pay the fee, and install the receipt-subtree root.

        Idempotent: if the root already matches, the fee is still burned
        (a tx with a fee in-block consumes a block slot — we don't let
        operators sneak no-ops in for free) and the mapping is
        refreshed.  Rotation-safe: a new root replaces the old entry.
        """
        ok, reason = self.validate_set_receipt_subtree_root(tx)
        if not ok:
            return False, reason

        if not self.supply.pay_fee_with_burn(
            tx.entity_id, proposer_id, tx.fee, self.supply.base_fee,
        ):
            return False, (
                f"Fee payment failed (fee {tx.fee} vs "
                f"base_fee {self.supply.base_fee})"
            )

        self.receipt_subtree_roots[tx.entity_id] = tx.root_public_key

        # Persist through the chain-db so a cold restart recovers the
        # mapping without a full replay.
        if self.db is not None and hasattr(self.db, "set_receipt_subtree_root"):
            self.db.set_receipt_subtree_root(tx.entity_id, tx.root_public_key)
            # Best-effort flush — same pattern as Revoke / SetAuthorityKey.
            try:
                self.db.flush_state()
            except Exception:
                pass

        # Nonce-free (see module docstring).  Signature consumed a
        # leaf in the COLD tree, so the apply path deliberately does
        # NOT bump the hot-key watermark — mirrors Revoke.

        return True, "Receipt subtree root registered"

    def _record_key_history(self, entity_id: bytes, public_key: bytes) -> None:
        """Append (self.height, public_key) to the entity's key history.

        Called at every public-key install/rotation site so slash
        verification can look up the historical key that was active at
        evidence_height (R6-A).  Monotonic by construction: callers only
        invoke this when they're about to set/overwrite
        `self.public_keys[entity_id]`, and block application walks
        height forward.  We do not guard against duplicate entries at
        the same height — replay fidelity is more important than
        deduplication.
        """
        self.key_history.setdefault(entity_id, []).append(
            (self.height, public_key),
        )

    def _public_key_at_height(
        self, entity_id: bytes, height: int,
    ) -> bytes | None:
        """Return the public key that was active for entity_id at the given block height.

        Returns None if the entity had no key installed at that height (e.g., height
        before their first-spend registration)."""
        history = self.key_history.get(entity_id)
        if not history:
            return self.public_keys.get(entity_id)  # no history → fall back to current
        # history is sorted ascending by height; find the last entry with installed_at <= height
        active = None
        for installed_at, pk in history:
            if installed_at <= height:
                active = pk
            else:
                break
        return active

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

        # Include pending_unstakes: an offender who races their own
        # evidence by immediately unstaking would otherwise zero out
        # `staked` and escape the slash, even though slash_validator()
        # burns stake + unbonding.  Evidence stays valid for the full
        # evidence_ttl window below, so the gating check has to match.
        slashable = (
            self.supply.get_staked(tx.evidence.offender_id)
            + self.supply.get_pending_unstake(tx.evidence.offender_id)
        )
        if slashable == 0:
            return False, "Offender has no stake to slash"

        if not self.supply.can_afford_fee(tx.submitter_id, tx.fee):
            return False, "Submitter cannot afford fee"

        # R5-A: At/after FEE_INCLUDES_SIGNATURE_HEIGHT every tx type must
        # price its witness bytes to stop WOTS+ bloat at MIN_FEE.  Slash
        # has no flat-fee floor (historically fee=1 was legal), so we
        # apply MIN_FEE as the baseline, then max against the sig-aware
        # minimum.
        from messagechain.core.transaction import (
            MIN_FEE as _MIN_FEE, enforce_signature_aware_min_fee,
        )
        _height_for_fee = chain_height if chain_height is not None else self.height
        if not enforce_signature_aware_min_fee(
            tx.fee,
            signature_bytes=len(tx.signature.to_bytes()),
            current_height=_height_for_fee,
            flat_floor=_MIN_FEE,
        ):
            return False, (
                f"Fee {tx.fee} below signature-aware minimum at height "
                f"{_height_for_fee}"
            )

        # H6: Reject expired evidence.  Evidence window must cover the
        # longer of (a) unbonding (stake is slashable until unbonded)
        # and (b) attester-escrow lock (rewards are slashable until
        # escrow matures).  Using UNBONDING_PERIOD alone left
        # ATTESTER_ESCROW_BLOCKS - UNBONDING_PERIOD = 11,952 blocks
        # (~83 days) of escrow-locked rewards technically slashable in
        # the comment but unslashable in code - iter 6 H1 finding.
        # Using max() honors both bonding types.
        from messagechain.config import UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS
        height = chain_height if chain_height is not None else self.height
        evidence_height = self._evidence_block_number(tx.evidence)
        evidence_ttl = max(UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS)
        if evidence_height is not None and height - evidence_height > evidence_ttl:
            return False, (
                f"Evidence expired - older than {evidence_ttl} blocks "
                f"(unbonding + escrow window)"
            )

        # Verify the evidence itself (two valid conflicting signatures).
        # R6-A: Use the key that was ACTIVE at the evidence height, not
        # the current public key.  An offender who equivocated at height
        # H and then rotated keys at H+1 must still be slashable with
        # evidence from H; the old key verifies the old signatures, the
        # new key does not.  Without this lookup the rotation silently
        # defeats the 100% stake burn.
        ev_height = self._evidence_block_number(tx.evidence)
        if ev_height is None:
            return False, "cannot determine evidence block height"
        offender_pk = self._public_key_at_height(
            tx.evidence.offender_id, ev_height,
        )
        if offender_pk is None:
            return False, "offender had no key at evidence height"
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
            # same as stake-burn).  Also bump total_burned so the
            # net-inflation invariant (total_supply == GENESIS_SUPPLY +
            # total_minted - total_burned) holds.  Previously only
            # total_supply moved, silently breaking the audit math.
            cur_balance = self.supply.balances.get(tx.evidence.offender_id, 0)
            self.supply.balances[tx.evidence.offender_id] = max(
                0, cur_balance - escrow_burned,
            )
            self.supply.total_supply -= escrow_burned
            self.supply.total_burned += escrow_burned

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

    def _apply_censorship_slash(self, matured) -> None:
        """Apply a matured CensorshipEvidence as a partial stake slash.

        Unlike the full-100%-burn slash for equivocation, censorship
        slashing is PARTIAL (CENSORSHIP_SLASH_BPS of stake) and the
        tokens are BURNED — no finder reward.  No burn of escrow.  The
        offender remains a validator (unlike equivocation, which adds
        them to slashed_validators and takes them out of the set
        permanently) because censorship is a weaker offense.

        The `slashed_validators` set is NOT mutated here — an offender
        who is slashed for censorship stays in the validator set with
        reduced stake.  `_processed_evidence` IS mutated so the same
        evidence can never be applied twice.
        """
        from messagechain.consensus.censorship_evidence import (
            compute_slash_amount,
        )
        offender_id = matured.offender_id
        current_stake = self.supply.staked.get(offender_id, 0)
        slash_amount = compute_slash_amount(current_stake)
        if slash_amount <= 0:
            # No stake to slash — still record the evidence as
            # processed so it cannot be re-submitted.
            self._processed_evidence.add(matured.evidence_hash)
            logger.info(
                f"Censorship evidence {matured.evidence_hash.hex()[:16]} "
                f"matured but offender has no stake — no slash, marked processed"
            )
            return

        # Debit stake + burn (reduce total_supply, bump total_burned).
        self.supply.staked[offender_id] = current_stake - slash_amount
        self.supply.total_supply -= slash_amount
        self.supply.total_burned += slash_amount

        # Record as processed to prevent double-slashing.
        self._processed_evidence.add(matured.evidence_hash)

        logger.info(
            f"CENSORSHIP-SLASHED validator {offender_id.hex()[:16]}: "
            f"stake_burned={slash_amount}, "
            f"stake_after={current_stake - slash_amount}, "
            f"evidence={matured.evidence_hash.hex()[:16]}"
        )

    def validate_censorship_evidence_tx(
        self, tx, chain_height: int | None = None,
    ) -> tuple[bool, str]:
        """Admission-time validation for a CensorshipEvidenceTx.

        Checks (in order, cheap-first):
          * submitter is a registered entity
          * offender is a registered entity
          * offender has NOT been already slashed
          * evidence_hash has NOT already been processed (dedupe)
          * evidence is NOT already pending (dedupe)
          * receipt window elapsed: commit_height + WINDOW < height
          * receipt not stale: height - commit_height <= EXPIRY
          * receipted tx NOT already on-chain (nonce check)
          * receipt issuer root matches registered root (if any)
          * submitter can afford the fee
          * receipt signature + submitter signature verify
        """
        from messagechain.consensus.censorship_evidence import (
            verify_censorship_evidence_tx,
        )
        height = chain_height if chain_height is not None else self.height

        if tx.submitter_id not in self.public_keys:
            return False, "Unknown submitter — must register first"

        if tx.offender_id not in self.public_keys:
            return False, "Unknown offender"

        if tx.offender_id in self.slashed_validators:
            return False, "Offender already slashed"

        evidence_hash = tx.evidence_hash

        # Processor-level dedupe — prevents re-admitting the same
        # evidence after it has already matured / voided.
        if self.censorship_processor.has_processed(evidence_hash):
            return False, "Evidence already processed"
        if self.censorship_processor.is_pending(evidence_hash):
            return False, "Evidence already pending"
        # Belt-and-braces: the legacy slashing pipeline also records
        # processed evidence hashes in `_processed_evidence`.  Honor it.
        if evidence_hash in self._processed_evidence:
            return False, "Evidence already processed (legacy dedupe)"

        # Window gate: receipt must be old enough that an honest
        # proposer would have included the tx by now.
        if tx.receipt.commit_height + EVIDENCE_INCLUSION_WINDOW > height:
            return False, "Receipt too fresh — inclusion window not elapsed"

        # Staleness gate: a very old receipt is rejected to prevent
        # weaponizing ancient receipts against a long-past offender.
        if height - tx.receipt.commit_height > EVIDENCE_EXPIRY_BLOCKS:
            return False, "Receipt expired — older than EVIDENCE_EXPIRY_BLOCKS"

        # The receipted tx MUST still be absent from chain state.  We
        # detect presence via the entity's on-chain nonce: if
        # chain_nonce > receipt_tx.nonce, the tx has already been
        # applied (or a replacement with higher nonce has — either
        # way the offender isn't censoring).
        chain_nonce = self.nonces.get(tx.message_tx.entity_id, 0)
        if chain_nonce > tx.message_tx.nonce:
            return False, "Receipted tx already on-chain (nonce advanced)"

        # Registered-root check: if the chain knows a receipt-subtree
        # root for this issuer, the receipt's embedded root must match.
        registered_root = self.receipt_subtree_roots.get(tx.offender_id)
        if (
            registered_root is not None
            and registered_root != tx.receipt.issuer_root_public_key
        ):
            return False, (
                "Receipt signed with a different subtree root than "
                "the issuer's registered root"
            )

        if not self.supply.can_afford_fee(tx.submitter_id, tx.fee):
            return False, "Submitter cannot afford fee"

        submitter_pk = self.public_keys[tx.submitter_id]
        valid, reason = verify_censorship_evidence_tx(tx, submitter_pk)
        if not valid:
            return False, reason

        return True, "Valid"

    def validate_bogus_rejection_evidence_tx(
        self, tx,
    ) -> tuple[bool, str]:
        """Admission-time validation for a BogusRejectionEvidenceTx.

        Cheap-first checks (mirror validate_censorship_evidence_tx):
          * submitter is registered
          * offender is registered
          * offender is NOT already slashed
          * evidence_hash NOT already in processor.processed (dedupe)
          * receipt-subtree root matches the registered root for the
            offender (if any)
          * submitter can afford fee
          * stateless verify (rejection sig + submitter sig + tx_hash
            consistency + fee floor)

        Does NOT check whether the rejection is bogus — that's an
        apply-time decision (re-verify the message_tx's signature
        under its on-chain pubkey) so the same evidence_tx admission
        is content-neutral and predictable.
        """
        from messagechain.consensus.bogus_rejection_evidence import (
            verify_bogus_rejection_evidence_tx,
        )
        if tx.submitter_id not in self.public_keys:
            return False, "Unknown submitter — must register first"
        if tx.offender_id not in self.public_keys:
            return False, "Unknown offender"
        if tx.offender_id in self.slashed_validators:
            return False, "Offender already slashed"
        if self.bogus_rejection_processor.has_processed(tx.evidence_hash):
            return False, "Evidence already processed"
        registered_root = self.receipt_subtree_roots.get(tx.offender_id)
        if (
            registered_root is not None
            and registered_root != tx.rejection.issuer_root_public_key
        ):
            return False, (
                "Rejection signed with a different subtree root than "
                "the issuer's registered root"
            )
        if not self.supply.can_afford_fee(tx.submitter_id, tx.fee):
            return False, "Submitter cannot afford fee"
        submitter_pk = self.public_keys[tx.submitter_id]
        valid, reason = verify_bogus_rejection_evidence_tx(tx, submitter_pk)
        if not valid:
            return False, reason
        return True, "Valid"

    def get_median_time_past(self) -> float:
        """Compute Median Time Past from the last MTP_BLOCK_COUNT blocks.

        Returns the median timestamp of the most recent blocks. This prevents
        proposers from manipulating timestamps to affect timelocks and
        unbonding periods. Same mechanism as Bitcoin (BIP 113).
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
        slash_transactions: list | None = None,
        custody_proofs: list | None = None,
        censorship_evidence_txs: list | None = None,
        bogus_rejection_evidence_txs: list | None = None,
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
        #
        # M4: apply the canonical Revoke-before-Set ordering here too
        # so the simulated state_root matches the deterministic
        # apply-path ordering below.  Without this mirror, a block
        # proposer's listed order would drift from the verifier's
        # iteration order and every such block would be rejected.
        for atx in _canonicalize_authority_txs(authority_txs or []):
            cls_name = atx.__class__.__name__
            # M4: mirror _apply_authority_tx's validation-gated skip.  If
            # a Revoke for this entity ran earlier in the SAME block
            # (canonical ordering guarantees it would), the subsequent
            # SetAuthorityKey is rejected by validate_set_authority_key
            # and its fee/mutation are NOT applied.  Skip here too so
            # the simulated state root matches.
            if (
                cls_name == "SetAuthorityKeyTransaction"
                and atx.entity_id in sim_revoked
            ):
                continue

            effective_base_fee = min(current_base_fee, atx.fee)
            tip = atx.fee - effective_base_fee
            sim_balances[atx.entity_id] = sim_balances.get(atx.entity_id, 0) - atx.fee
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
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
            elif cls_name == "SetReceiptSubtreeRootTransaction":
                # Nonce-free, cold-key-signed registration of the
                # receipt-subtree root.  The root lives in
                # receipt_subtree_roots (committed via the snapshot
                # state root, NOT the per-entity SMT that compute_state_root
                # builds below) so we only need to simulate the fee-side
                # impact here.  The apply path does not bump the hot
                # watermark (leaf was consumed in the COLD tree), so we
                # don't bump it here either.
                pass

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
        #
        # H5: drop any unstake whose entity is also the offender of a
        # SlashTransaction in the same block.  The apply path pre-empts
        # such unstakes (their stake has already been burned by the
        # slash loop); the sim must match or state_root diverges.
        _slashed_offenders_sim = {
            stx.evidence.offender_id for stx in (slash_transactions or [])
        }
        for utx in (unstake_transactions or []):
            if utx.entity_id in _slashed_offenders_sim:
                continue
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
        # The snapshot dict and debt dict are read-only here (sim does not
        # persist its first-block capture or debt update); the apply path
        # owns the mutation.  The debt READ uses self.seed_divestment_debt
        # which holds the value as of the END of block_height-1.
        from messagechain.config import (
            SEED_DIVESTMENT_START_HEIGHT as _SDS,
            SEED_DIVESTMENT_END_HEIGHT as _SDE,
            get_seed_divestment_params as _gsdp,
        )
        if (
            block_height > _SDS
            and block_height <= _SDE
            and self.seed_entity_ids
        ):
            _window = _SDE - _SDS
            _SCALE = self._DIVESTMENT_SCALE
            # Activation-gated parameters — pre-activation returns the
            # legacy (1M floor, 25% treasury) values so sim/apply match
            # at every height across the fork boundary.
            _SDRF, _burn_bps, _SDT = _gsdp(block_height)
            for _seid in self.seed_entity_ids:
                # Apply path snapshots at the first divestment block from
                # live stake; on replay the same capture reproduces.  We
                # mirror that here: if the entry isn't yet in the live
                # dict, read the current live (pre-divestment) stake.
                _init = self.seed_initial_stakes.get(
                    _seid, sim_staked.get(_seid, 0),
                )
                if _init <= _SDRF:
                    continue
                _divestible = _init - _SDRF
                _current = sim_staked.get(_seid, 0)
                if _current <= _SDRF:
                    continue
                _per_block_scaled = (_divestible * _SCALE) // _window
                _debt = self.seed_divestment_debt.get(_seid, 0) + _per_block_scaled
                _whole = _debt // _SCALE
                if _whole <= 0:
                    continue
                _max_drainable = _current - _SDRF
                _divest = min(_whole, _max_drainable)
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

        # Simulate treasury rebase (hard fork): must byte-mirror
        # _apply_treasury_rebase, which runs AFTER seed divestment in
        # _apply_block_state.  Only sim_balances[TREASURY_ENTITY_ID]
        # is visible to the state root; total_supply is a supply-level
        # scalar outside the state-tree commitment, so we only touch
        # the treasury balance here.
        from messagechain.config import (
            TREASURY_REBASE_HEIGHT as _TRH,
            TREASURY_REBASE_BURN_AMOUNT as _TRBA,
        )
        if (
            block_height == _TRH
            and not self.supply.treasury_rebase_applied
        ):
            _cur_treasury = sim_balances.get(TREASURY_ENTITY_ID, 0)
            if _cur_treasury >= _TRBA:
                sim_balances[TREASURY_ENTITY_ID] = _cur_treasury - _TRBA

        # Simulate block reward: committee-based attester distribution +
        # proposer share + PROPOSER_REWARD_CAP overflow.  Must mirror
        # mint_block_reward byte-for-byte; any divergence here produces
        # an "Invalid state_root" rejection on add_block.
        from messagechain.consensus.attester_committee import (
            ATTESTER_REWARD_PER_SLOT, select_attester_committee,
        )
        from messagechain.config import (
            ATTESTER_REWARD_SPLIT_HEIGHT,
            ATTESTER_COMMITTEE_TARGET_SIZE,
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
        # Committee-size policy: pre-activation, the committee is
        # implicitly capped at what the pool can afford at 1 token per
        # slot (permanently 3 at BLOCK_REWARD_FLOOR — a decentralization
        # failure).  Post-activation we decouple: the committee is
        # sized by consensus policy (ATTESTER_COMMITTEE_TARGET_SIZE)
        # and the pool is divided pro-rata across the full committee.
        if block_height >= ATTESTER_REWARD_SPLIT_HEIGHT:
            committee_size = ATTESTER_COMMITTEE_TARGET_SIZE
        else:
            committee_size = attester_pool // ATTESTER_REWARD_PER_SLOT
        attester_committee = select_attester_committee(
            candidates=attester_candidates,
            seed_entity_ids=self.seed_entity_ids,
            bootstrap_progress=self.bootstrap_progress,
            randomness=parent_randao,
            committee_size=committee_size,
        ) if attester_candidates else []

        if attester_committee:
            # Distribution policy: pre-activation pays
            # ATTESTER_REWARD_PER_SLOT (1) per slot up to pool capacity;
            # post-activation divides the pool pro-rata across the full
            # committee, with integer-division remainder burning.  Must
            # match mint_block_reward exactly or state_root diverges.
            attester_tokens_paid = 0
            if block_height >= ATTESTER_REWARD_SPLIT_HEIGHT:
                n = len(attester_committee)
                per_slot_reward = (attester_pool // n) if n > 0 else 0
                for eid in attester_committee:
                    if per_slot_reward > 0:
                        sim_balances[eid] = (
                            sim_balances.get(eid, 0) + per_slot_reward
                        )
                    attester_tokens_paid += per_slot_reward
                proposer_att_reward = (
                    per_slot_reward if proposer_id in attester_committee else 0
                )
            else:
                for eid in attester_committee[:committee_size]:
                    sim_balances[eid] = (
                        sim_balances.get(eid, 0) + ATTESTER_REWARD_PER_SLOT
                    )
                    attester_tokens_paid += ATTESTER_REWARD_PER_SLOT
                proposer_att_reward = (
                    ATTESTER_REWARD_PER_SLOT
                    if proposer_id in attester_committee else 0
                )

            # Proposer-cap check (matches mint_block_reward).  Cap
            # overflow BURNs now — previously this flowed to treasury
            # which quietly accumulated rewards without a governance
            # vote.  Burn is supply-reduction only; no sim_balances
            # change needed beyond the cap-trim clawback below.
            proposer_total = proposer_share + proposer_att_reward
            if proposer_total > effective_cap:
                sim_balances[proposer_id] = (
                    sim_balances.get(proposer_id, 0) - proposer_att_reward
                )
                if proposer_share > effective_cap:
                    proposer_share = effective_cap

            sim_balances[proposer_id] = (
                sim_balances.get(proposer_id, 0) + proposer_share
            )
            # Burn portion (unfilled slots + cap overflow) reduces
            # total_supply — not represented in the per-entity state
            # tree, so no sim_balances change.
        else:
            # No attesters — proposer absorbs whole reward.  No cap
            # applies because the cap exists to protect a multi-
            # validator committee from mega-staker capture; with no
            # committee, proposer IS all the work.
            sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + reward

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
            # the apply-path ordering and predicates exactly — M5 fix
            # requires hex-sorted proposal_id iteration so the sim and
            # apply paths agree on which of N competing same-block spends
            # succeeds when the treasury can't cover them all.
            def _sim_is_new(rid: bytes) -> bool:
                if rid in sim_supply.balances:
                    return False
                if rid in sim_supply.staked:
                    return False
                return self._recipient_is_new(rid)
            sim_closed_spends = [
                (pid, state) for pid, state in sim_tracker.proposals.items()
                if isinstance(state.proposal, TreasurySpendTransaction)
                and block_height - state.created_at_block > GOVERNANCE_VOTING_WINDOW
            ]
            sim_closed_spends.sort(key=lambda kv: kv[0])
            for pid, state in sim_closed_spends:
                sim_tracker.execute_treasury_spend(
                    state.proposal, sim_supply, current_block=block_height,
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

        # Simulate archive-duty reward withhold (iter 3b-iii).  Must
        # mirror the apply path in _apply_block_state immediately
        # after mint_block_reward.  For every recipient that received
        # a gross reward this block, read their miss counter and
        # decrement sim_balances by withhold_pct%.  The pool-credit
        # side of withhold doesn't affect this SMT root (pool lives
        # under the snapshot-root global section, not the per-entity
        # tree), but the balance-debit side does.
        from messagechain.consensus.archive_duty import (
            is_bootstrap_exempt as _is_bootstrap_exempt,
            withhold_pct as _withhold_pct,
        )
        # Reconstruct the gross reward each recipient received from
        # the mint step above.  The sim credited: proposer_share +
        # (optionally) proposer_att_reward, and per-committee-member
        # per_slot_reward.  Mirror those exact quantities.
        _sim_gross: dict[bytes, int] = {}
        if attester_committee:
            if block_height >= ATTESTER_REWARD_SPLIT_HEIGHT:
                _n = len(attester_committee)
                _per_slot = (attester_pool // _n) if _n > 0 else 0
            else:
                _per_slot = ATTESTER_REWARD_PER_SLOT
            if _per_slot > 0:
                for eid in attester_committee:
                    _sim_gross[eid] = _sim_gross.get(eid, 0) + _per_slot
            # Proposer may or may not be in the committee; `proposer_share`
            # above was adjusted in-place if the cap was hit, so we read
            # back the post-cap value here.
            _sim_gross[proposer_id] = (
                _sim_gross.get(proposer_id, 0) + proposer_share
            )
        else:
            # No committee — proposer absorbed the full reward (no cap).
            _sim_gross[proposer_id] = (
                _sim_gross.get(proposer_id, 0) + reward
            )
        for _eid, _gross in _sim_gross.items():
            if _gross <= 0:
                continue
            # Mirror apply-path's bootstrap-grace defense-in-depth.
            if _is_bootstrap_exempt(
                entity_id=_eid,
                current_block=block_height,
                validator_first_active_block=(
                    self.validator_first_active_block
                ),
            ):
                continue
            _miss = self.validator_archive_misses.get(_eid, 0)
            _pct = _withhold_pct(_miss)
            if _pct <= 0:
                continue
            _withheld = _gross * _pct // 100
            if _withheld <= 0:
                continue
            sim_balances[_eid] = sim_balances.get(_eid, 0) - _withheld
            # Pool side doesn't affect the per-entity SMT state root,
            # but DOES affect the state-snapshot root (via _TAG_GLOBAL
            # _GLOBAL_ARCHIVE_REWARD_POOL).  That snapshot root is
            # consumed by a different code path; no action needed here.

        # Simulate archive-reward payouts — must mirror
        # _apply_archive_rewards.  Only changes that reach sim_balances
        # matter here: the pool scalar (self.archive_reward_pool) is
        # not in the state-tree commitment, but prover balances are.
        # Graceful no-op when pool is empty.
        if custody_proofs:
            from messagechain.consensus.archive_challenge import (
                ArchiveRewardPool,
                apply_archive_rewards,
            )
            # Use verify-free simulation here: the commit path runs
            # after validate_block, so each proof is already known
            # good.  Mirroring apply_archive_rewards' FCFS + cap +
            # dedupe invariants is what keeps state_root aligned.
            sim_pool = ArchiveRewardPool(balance=self.archive_reward_pool)
            # Take target_block_hash from the first proof to avoid a
            # second compute_challenge call here — validator has
            # already bound the list to the correct challenge.
            sim_expected_hash = custody_proofs[0].target_block_hash
            sim_result = apply_archive_rewards(
                proofs=custody_proofs,
                pool=sim_pool,
                expected_block_hash=sim_expected_hash,
            )
            for payout in sim_result.payouts:
                sim_balances[payout.prover_id] = (
                    sim_balances.get(payout.prover_id, 0) + payout.amount
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

        # Simulate censorship-evidence pipeline: submitter pays fee,
        # pending entries whose tx landed above get voided, then any
        # matured entries get partially slashed.  Mirror the apply-
        # time ordering exactly so the sim state root matches apply.
        #
        # The apply path runs `validate_censorship_evidence_tx` on
        # every etx at admit-time and SKIPS fee/admission/watermark-
        # bump for any etx the gate rejects (see _apply_block_state).
        # The sim MUST mirror this exactly: a block that bundles an
        # ordinary tx + a same-submitter evidence whose receipted tx
        # shares a nonce, or two evidences with the same evidence_hash,
        # otherwise drifts — sim charges both, apply rejects the
        # doomed ones, state_root mismatches, block rejected.
        from messagechain.consensus.censorship_evidence import (
            compute_slash_amount as _cslash,
            _PendingEvidence,
        )
        # Step 1: mirror observe_block — any pending evidence whose
        # tx appears in this block's `transactions` slot is voided.
        # Build a local copy of pending to simulate.
        sim_pending = {
            ev_hash: entry
            for ev_hash, entry in self.censorship_processor.pending.items()
        }
        sim_processed = set(self.censorship_processor.processed)
        sim_legacy_processed = set(self._processed_evidence)
        block_tx_hashes = {tx.tx_hash for tx in transactions}
        for ev_hash in list(sim_pending.keys()):
            if sim_pending[ev_hash].tx_hash in block_tx_hashes:
                del sim_pending[ev_hash]
                # observe_block also records voided evidence in
                # processed; mirror so a same-block evidence targeting
                # the same hash is correctly rejected.
                sim_processed.add(ev_hash)
        # Step 2: admit new evidence txs — run the same admission
        # gate `validate_censorship_evidence_tx` uses at apply-time
        # so the sim and apply paths agree on which evidences are
        # admitted.  For each admitted etx: submitter pays fee,
        # watermark bumps, and a pending entry lands in sim_pending.
        # For each rejected etx: NO fee, NO bump, NO pending entry.
        for etx in (censorship_evidence_txs or []):
            # ── admission gate (mirrors validate_censorship_evidence_tx) ──
            # Cheap unknown-entity gates first.
            if etx.submitter_id not in self.public_keys:
                continue
            if etx.offender_id not in self.public_keys:
                continue
            # Slashed/already-processed/pending gates.  Use sim-local
            # sets so a same-block dup etx is caught (first admits,
            # second hits is_pending and is rejected).
            if etx.offender_id in sim_slashed:
                continue
            if etx.evidence_hash in sim_processed:
                continue
            if etx.evidence_hash in sim_pending:
                continue
            if etx.evidence_hash in sim_legacy_processed:
                continue
            # Receipt window + staleness gates.
            if etx.receipt.commit_height + EVIDENCE_INCLUSION_WINDOW > block_height:
                continue
            if block_height - etx.receipt.commit_height > EVIDENCE_EXPIRY_BLOCKS:
                continue
            # Nonce-advanced gate — CRITICAL: read against sim_nonces
            # so a same-block ordinary tx from the same submitter that
            # bumped the nonce past the receipted tx's nonce correctly
            # causes us to reject the evidence here (same as apply).
            chain_nonce_sim = sim_nonces.get(
                etx.message_tx.entity_id,
                self.nonces.get(etx.message_tx.entity_id, 0),
            )
            if chain_nonce_sim > etx.message_tx.nonce:
                continue
            # Registered-root gate — use the LIVE receipt_subtree_roots.
            # This map is only mutated by SetReceiptSubtreeRoot authority
            # txs and the apply path re-reads the live value too; the sim
            # does not currently model same-block mutation of the map.
            registered_root = self.receipt_subtree_roots.get(etx.offender_id)
            if (
                registered_root is not None
                and registered_root != etx.receipt.issuer_root_public_key
            ):
                continue
            # Fee affordability — check against sim_balances so a
            # same-block ordinary tx draining the submitter's balance
            # is reflected.
            if sim_balances.get(etx.submitter_id, 0) < etx.fee:
                continue
            # Signature verification is independent of same-block state
            # (keys don't rotate mid-block in a way that affects this
            # etx's already-bound signatures), so skip at sim-time —
            # validate_block has already run the full check.  Any honest
            # proposer's etx that reaches the sim has passed signature
            # verification.
            # ── admission accepted ── charge fee, bump leaf, track pending.
            effective_base_fee = min(current_base_fee, etx.fee)
            tip = etx.fee - effective_base_fee
            sim_balances[etx.submitter_id] = (
                sim_balances.get(etx.submitter_id, 0) - etx.fee
            )
            sim_balances[proposer_id] = (
                sim_balances.get(proposer_id, 0) + tip
            )
            _bump_wm(etx.submitter_id, etx.signature.leaf_index)
            # Track newly-admitted evidence so a subsequent same-block
            # etx with the same evidence_hash is rejected by the
            # is_pending gate above.
            sim_pending[etx.evidence_hash] = _PendingEvidence(
                evidence_hash=etx.evidence_hash,
                offender_id=etx.offender_id,
                tx_hash=etx.message_tx.tx_hash,
                admitted_height=block_height,
                evidence_tx_hash=etx.tx_hash,
            )
        # Step 3: mature — any pending entry whose
        # admitted_height + MATURITY <= block_height gets slashed.
        from messagechain.config import EVIDENCE_MATURITY_BLOCKS as _EMB
        for ev_hash, entry in list(sim_pending.items()):
            if entry.admitted_height + _EMB <= block_height:
                current_stake = sim_staked.get(entry.offender_id, 0)
                slash_amount = _cslash(current_stake)
                if slash_amount > 0:
                    sim_staked[entry.offender_id] = current_stake - slash_amount

        # ── Bogus-rejection evidence: simulate the apply path ──
        # One-phase: each admitted etx pays a fee + bumps watermark; if
        # the rejection is provably bogus (slashable reason code + the
        # message_tx's signature actually verifies under its on-chain
        # pubkey), the issuer is immediately slashed.  An honest
        # rejection (sig actually fails) means the evidence is rejected
        # at apply-time and NO fee is charged.  Mirror exactly so the
        # state_root committed by the proposer matches the apply path.
        from messagechain.consensus.bogus_rejection_evidence import (
            _SLASHABLE_REASON_CODES as _BR_SLASHABLE,
        )
        from messagechain.core.transaction import (
            verify_transaction as _verify_msg_tx,
        )
        sim_br_processed = set(self.bogus_rejection_processor.processed)
        for etx in (bogus_rejection_evidence_txs or []):
            # Cheap unknown-entity gates first.
            if etx.submitter_id not in sim_public_keys:
                continue
            if etx.offender_id not in sim_public_keys:
                continue
            # Already-processed gate — sim-local so a same-block
            # duplicate is rejected.
            if etx.evidence_hash in sim_br_processed:
                continue
            # Registered receipt-subtree root gate (mirrors validation).
            registered_root = self.receipt_subtree_roots.get(etx.offender_id)
            if (
                registered_root is not None
                and registered_root != etx.rejection.issuer_root_public_key
            ):
                continue
            # Fee affordability.
            if sim_balances.get(etx.submitter_id, 0) < etx.fee:
                continue
            reason_code = etx.rejection.reason_code
            if reason_code in _BR_SLASHABLE:
                offender_pk = sim_public_keys.get(
                    etx.message_tx.entity_id, b"",
                )
                if not offender_pk:
                    # Honest rejection (no key to verify against) —
                    # evidence rejected at apply-time, no fee.
                    continue
                if not _verify_msg_tx(etx.message_tx, offender_pk):
                    # Honest rejection — evidence rejected, no fee.
                    continue
                # Bogus → slash + charge fee + record processed.
                current_stake = sim_staked.get(etx.offender_id, 0)
                slash_amount = _cslash(current_stake)
                if slash_amount > 0:
                    sim_staked[etx.offender_id] = (
                        current_stake - slash_amount
                    )
            # Charge fee + bump watermark + record processed.  Applies
            # to both the slash path AND the non-slashable-reason path
            # (forward-compat — caller pays fee for evidence that's
            # accepted but doesn't slash).
            effective_base_fee = min(current_base_fee, etx.fee)
            tip = etx.fee - effective_base_fee
            sim_balances[etx.submitter_id] = (
                sim_balances.get(etx.submitter_id, 0) - etx.fee
            )
            sim_balances[proposer_id] = (
                sim_balances.get(proposer_id, 0) + tip
            )
            _bump_wm(etx.submitter_id, etx.signature.leaf_index)
            sim_br_processed.add(etx.evidence_hash)

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
        custody_proofs: list | None = None,
        censorship_evidence_txs: list | None = None,
        bogus_rejection_evidence_txs: list | None = None,
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
            slash_transactions=slash_transactions,
            custody_proofs=custody_proofs,
            censorship_evidence_txs=censorship_evidence_txs,
            bogus_rejection_evidence_txs=bogus_rejection_evidence_txs,
        )
        # Periodic state-root checkpoint commitment — zero on every block
        # except multiples of CHECKPOINT_INTERVAL.  At a checkpoint
        # height the field commits to the FULL snapshot root of the
        # chain state AS OF the parent block — i.e., the state that
        # serves as INPUT to this block.  A bootstrapping node that
        # downloads a finalized checkpoint block at height H reads the
        # committed snapshot root, downloads a matching state snapshot
        # from any archive, and then replays blocks H, H+1, ... forward
        # from that state.  Using the parent's post-apply state keeps
        # the commitment deterministic with a single hash call against
        # the live chain — no dry-run apply / rollback needed — because
        # by the time propose_block runs, the parent block has already
        # been applied.  Scope: sync UX only; archives still retain
        # every block.
        from messagechain.config import is_state_root_checkpoint_block
        if is_state_root_checkpoint_block(block_height):
            state_root_checkpoint = self._compute_snapshot_root_live()
        else:
            state_root_checkpoint = b"\x00" * 32
        mtp = self.get_median_time_past()
        # Float timestamps retained: switching to integer-seconds here
        # breaks tests that create multiple blocks in the same wall-
        # clock second (the MTP-advance check `timestamp > mtp` needs
        # strictly-greater, which sub-second precision provides
        # naturally).  The sub-second bits are not signed (see
        # `signable_data` which truncates to int) so mutation of those
        # bits has no consensus effect — the dual-encoding is cosmetic.
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
            custody_proofs=custody_proofs,
            censorship_evidence_txs=censorship_evidence_txs,
            bogus_rejection_evidence_txs=bogus_rejection_evidence_txs,
            timestamp=timestamp,
            mempool_tx_hashes=mempool_tx_hashes,
            state_root_checkpoint=state_root_checkpoint,
        )

    def _compute_snapshot_root_live(self) -> bytes:
        """Snapshot-root commitment over the current live chain state.

        Thin wrapper that composes serialize_state + compute_state_root
        from storage.state_snapshot.  Used by propose_block (to fill
        the header's state_root_checkpoint on checkpoint-height blocks)
        and by validate_block (to re-derive the expected commitment on
        checkpoint-height blocks).  Keeping the two call sites on a
        single helper eliminates a silent drift risk — if the snapshot
        encoding ever changes, both callers move in lockstep.
        """
        from messagechain.storage.state_snapshot import (
            serialize_state,
            compute_state_root as compute_snapshot_root,
        )
        return compute_snapshot_root(serialize_state(self))

    def _validate_block_list_counts(self, block) -> tuple[bool, str]:
        """Hard per-block count caps on consensus-path lists.

        Rejects before any cryptographic work — placeholder objects
        are fine for the count test, which mirrors the pattern used by
        _validate_finality_votes.  See config.py for the sizing
        rationale; the short version is that these lists bypass the
        fee market (proposers insert them directly) so the protocol
        has to set the ceiling structurally.

        Custody proofs are already capped via ARCHIVE_PROOFS_PER_CHALLENGE
        in _validate_custody_proofs and are not re-checked here.
        Finality votes are capped in _validate_finality_votes.
        """
        from messagechain.config import (
            MAX_ATTESTATIONS_PER_BLOCK,
            MAX_VALIDATOR_SIGNATURES_PER_BLOCK,
            MAX_GOVERNANCE_TXS_PER_BLOCK,
            MAX_AUTHORITY_TXS_PER_BLOCK,
            MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK,
        )
        checks = (
            ("attestations", getattr(block, "attestations", []),
             MAX_ATTESTATIONS_PER_BLOCK),
            ("validator_signatures",
             getattr(block, "validator_signatures", []),
             MAX_VALIDATOR_SIGNATURES_PER_BLOCK),
            ("governance_txs", getattr(block, "governance_txs", []),
             MAX_GOVERNANCE_TXS_PER_BLOCK),
            ("authority_txs", getattr(block, "authority_txs", []),
             MAX_AUTHORITY_TXS_PER_BLOCK),
            ("censorship_evidence_txs",
             getattr(block, "censorship_evidence_txs", []),
             MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK),
        )
        for name, lst, cap in checks:
            if len(lst) > cap:
                return False, (
                    f"Too many {name}: {len(lst)} > {cap}"
                )
        return True, "OK"

    def _validate_authority_tx_sizes(self, authority_txs) -> tuple[bool, str]:
        """Per-tx byte ceiling on authority txs.

        Safety rail that complements the per-block COUNT cap
        (MAX_AUTHORITY_TXS_PER_BLOCK).  A real authority tx is
        dominated by its ~2.8 KB WOTS+ signature and can't
        meaningfully grow beyond that; the cap is here to reject
        malformed or future-incompatible variants on size alone
        before any signature verification.
        """
        from messagechain.config import MAX_AUTHORITY_TX_BYTES
        for atx in authority_txs:
            size = len(atx.to_bytes())
            if size > MAX_AUTHORITY_TX_BYTES:
                tx_hash_hex = getattr(atx, "tx_hash", b"").hex()[:16]
                return False, (
                    f"Authority tx {tx_hash_hex} exceeds size cap: "
                    f"{size} > {MAX_AUTHORITY_TX_BYTES} bytes"
                )
        return True, "OK"

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
        """Pin the current stake map for a block.

        Snapshots are permanent.  CLAUDE.md principle #2 (message
        permanence & censorship resistance) applies equally to
        consensus-critical state: a finality proof or attestation-
        validity check that works today must still work in 100+
        years, and that requires the stake map at every block to
        remain reconstructible from chain state.

        Snapshots are small — dict[entity_id_32B, int] — so the
        per-block footprint scales with live validator-set size,
        not chain length.  At ~500 validators with 40-byte entries
        (32B id + 8B int + dict overhead) a snapshot is ~20 KB.
        One block per ~12 s gives ~2.6M blocks/year, so an upper-
        bound annual cost is ~50 GB even if the validator set is
        saturated every single block — and in practice the set
        churns slowly and most snapshots share structure, so this
        is a comfortable ceiling, not a typical cost.  Relative to
        message payloads (every on-chain message lives forever too),
        stake snapshots are negligible.

        See `_process_attestations`: attestations in block N vote
        for block N-1, so the 2/3 denominator must be pinned to
        the stake set that existed at the attestation's target
        block, not the post-churn live set.  Finality votes
        (`_apply_finality_votes`) consult the same map for the
        long-range-defense threshold — both callers used to have
        "snapshot may have been pruned" fallbacks, but with
        unbounded retention those fallbacks only fire during cold-
        load bootstrap, never for organic traffic.
        """
        self._stake_snapshots[block_number] = dict(self.supply.staked)

    def _validate_custody_proofs(
        self, block: Block, parent: Block,
    ) -> tuple[bool, str]:
        """Verify block.custody_proofs against the hygiene + validity rules.

        Rules (in order):

          1. **Hygiene:** non-challenge blocks MUST carry an empty list.
             A non-empty list elsewhere is rejected — same pattern as
             the state_root_checkpoint zero-on-off-checkpoint rule.
             Without this, a proposer could smuggle garbage into
             merkle_root and burn validator CPU on every block.

          2. **Cap:** at most ARCHIVE_PROOFS_PER_CHALLENGE proofs on a
             challenge block.

          3. **Challenge derivation:** the challenge for block H is
             derived from H's PARENT block_hash (known when H is being
             proposed).  Every proof in H MUST target that challenge's
             `target_height`, and the proof's target_block_hash MUST
             match the chain's actual block at that height.

          4. **Per-proof verification:** verify_custody_proof against
             the actual block bytes (full merkle-inclusion proof in
             non-empty-block case, header-only in empty-block case).

          5. **Dedup:** no two proofs in the same block may share a
             prover_id.  The mempool already dedupes by (challenge,
             prover_id); this block-level check is defense-in-depth
             against a malicious proposer bypassing the mempool.

        Returns (ok, reason).
        """
        from messagechain.config import (
            ARCHIVE_PROOFS_PER_CHALLENGE,
            is_archive_challenge_block,
        )
        from messagechain.consensus.archive_challenge import (
            compute_challenge,
            verify_custody_proof,
        )
        proofs = getattr(block, "custody_proofs", None) or []
        height = block.header.block_number

        if not is_archive_challenge_block(height):
            if proofs:
                return False, (
                    f"Non-empty custody_proofs on non-challenge block "
                    f"(height {height} is not a multiple of the "
                    f"challenge interval)"
                )
            return True, "ok"

        if len(proofs) > ARCHIVE_PROOFS_PER_CHALLENGE:
            return False, (
                f"custody_proofs count {len(proofs)} exceeds cap "
                f"{ARCHIVE_PROOFS_PER_CHALLENGE}"
            )

        if not proofs:
            return True, "ok"

        # Derive this block's challenge from the parent's block hash.
        # Using the parent's hash (not this block's own hash) lets the
        # proposer resolve the target BEFORE building this block — the
        # challenge is the same one the mempool has been collecting for.
        challenge = compute_challenge(parent.block_hash, height)
        target_block = self.get_block(challenge.target_height)
        # A validator that is genuinely synced MUST have the target
        # block — the target is < current height by construction.
        # Reject outright if we don't have it; loud failure surfaces
        # a real bug rather than silently accepting unverifiable proofs.
        if target_block is None:
            return False, (
                f"Cannot validate custody_proofs: target block at "
                f"height {challenge.target_height} is missing locally"
            )
        expected_block_hash = target_block.block_hash

        seen_provers: set[bytes] = set()
        for proof in proofs:
            if proof.target_height != challenge.target_height:
                return False, (
                    f"Custody proof target_height {proof.target_height} "
                    f"does not match challenge target "
                    f"{challenge.target_height}"
                )
            if proof.target_block_hash != expected_block_hash:
                return False, (
                    "Custody proof target_block_hash does not match the "
                    "chain's block at the challenged height (stale fork?)"
                )
            if proof.prover_id in seen_provers:
                return False, (
                    f"Duplicate custody proof from prover "
                    f"{proof.prover_id.hex()[:16]} in challenge block"
                )
            seen_provers.add(proof.prover_id)
            ok, reason = verify_custody_proof(
                proof, expected_block_hash=expected_block_hash,
            )
            if not ok:
                return False, f"Invalid custody proof: {reason}"
        return True, "ok"

    def validate_block(self, block: Block) -> tuple[bool, str]:
        """Validate a block before adding it to the chain."""
        latest = self.get_latest_block()
        if latest is None:
            return False, "No genesis block"

        # Per-block count caps on consensus-path lists (attestations,
        # validator_signatures, governance/authority/censorship-
        # evidence txs).  Checked early so a bloated block is rejected
        # before any signature work.
        ok, reason = self._validate_block_list_counts(block)
        if not ok:
            return False, reason

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

        # Periodic state-root checkpoint commitment.  At checkpoint heights
        # (block_number a positive multiple of CHECKPOINT_INTERVAL) the
        # header must commit to the snapshot root of the chain state as of
        # the parent — i.e., OUR current live state, since at validation
        # time the parent has already been applied.  At all other heights
        # the field MUST be zero; allowing garbage in the field off-checkpoint
        # would let a proposer silently corrupt the commitment stream for a
        # future bootstrap consumer who trusts "this header bit holds a valid
        # snapshot commitment at every checkpoint height I look at."
        from messagechain.config import is_state_root_checkpoint_block as _is_ckpt
        if _is_ckpt(block.header.block_number):
            expected_ckpt = self._compute_snapshot_root_live()
            if block.header.state_root_checkpoint != expected_ckpt:
                return False, (
                    f"Invalid state_root_checkpoint — expected "
                    f"{expected_ckpt.hex()[:16]}, got "
                    f"{block.header.state_root_checkpoint.hex()[:16]}"
                )
        else:
            if block.header.state_root_checkpoint != b"\x00" * 32:
                return False, (
                    "Non-zero state_root_checkpoint on non-checkpoint "
                    f"block (height {block.header.block_number} is not a "
                    f"multiple of CHECKPOINT_INTERVAL)"
                )

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
        # Canonical tx-hash list — single source of truth across this
        # validator, the fork-path validator, pos.create_block, and
        # spv.generate_merkle_proof.  Includes the archive_proof_bundle
        # hash derived from custody_proofs when present.
        tx_hashes = canonical_block_tx_hashes(block)

        # Derivation-integrity check for archive_proof_bundle: whatever
        # the proposer placed in the block-body bundle slot must match
        # what the canonical helper just derived from custody_proofs.
        # A forged bundle fails merkle verification regardless, but
        # catching it here gives a clear reason rather than a cryptic
        # root mismatch.
        _cust_proofs_for_bundle = getattr(block, "custody_proofs", [])
        if _cust_proofs_for_bundle:
            from messagechain.consensus.archive_challenge import (
                ArchiveProofBundle as _ArchiveProofBundle,
            )
            _expected_bundle = _ArchiveProofBundle.from_proofs(
                _cust_proofs_for_bundle,
            )
            actual_bundle = getattr(block, "archive_proof_bundle", None)
            if actual_bundle is None:
                return False, (
                    "Block has custody_proofs but missing "
                    "archive_proof_bundle"
                )
            if actual_bundle.root != _expected_bundle.root:
                return False, (
                    "archive_proof_bundle does not match "
                    "ArchiveProofBundle.from_proofs(custody_proofs)"
                )
        else:
            # Hygiene: non-challenge blocks MUST NOT carry a bundle —
            # there's nothing to commit to, and a stray bundle would be
            # a gossip-layer smuggle attempt.
            if getattr(block, "archive_proof_bundle", None) is not None:
                return False, (
                    "archive_proof_bundle present on block with no "
                    "custody_proofs"
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
                # Round cap.  Without this a proposer could push the
                # timestamp forward by the full future-drift window
                # (~2 hours) to claim a round where someone else is
                # selected, skipping the honest round-0 proposer.  Cap
                # at a small constant — legitimate missed-slot fallback
                # rarely exceeds a handful of rounds, and any gap larger
                # than that is either network pathology or abuse.
                if round_number > _cfg.MAX_PROPOSER_FALLBACK_ROUNDS:
                    return False, (
                        f"Proposer round {round_number} exceeds cap "
                        f"{_cfg.MAX_PROPOSER_FALLBACK_ROUNDS} — "
                        f"timestamp-skew slot hijacking rejected"
                    )

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
        # Safety rail: reject any authority tx whose serialized size
        # exceeds the per-tx byte ceiling.  Checked after the fee
        # gate so an obviously-oversized tx can't burn signature-
        # verification CPU.
        ok, reason = self._validate_authority_tx_sizes(
            getattr(block, "authority_txs", []),
        )
        if not ok:
            return False, reason
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
            # Thread block height so FEE_INCLUDES_SIGNATURE_HEIGHT gate
            # applies to consensus verification.
            if not verify_transaction(
                tx, public_key, current_height=block.header.block_number,
            ):
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: Invalid signature"

            if tx.timestamp <= 0:
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: Transaction must have a valid timestamp"
            # L3: Enforce timestamp drift for txs within blocks (not just standalone)
            if tx.timestamp > _time.time() + MAX_TIMESTAMP_DRIFT:
                return False, f"Invalid tx {tx.tx_hash.hex()[:16]}: Timestamp too far in future"
            # Message timestamp trust: a tx cannot claim to have been sent
            # AFTER the block that includes it.  Without this, a proposer
            # can forward-date individual messages (up to MAX_TIMESTAMP_DRIFT)
            # inside a block stamped at MTP time, making the message log
            # look like it arrived at a different wall-clock than the block.
            # For a chain that sells "trusted timestamps" as a feature, the
            # tx ≤ block bound is the basic sanity check readers rely on.
            if tx.timestamp > block.header.timestamp:
                return False, (
                    f"Invalid tx {tx.tx_hash.hex()[:16]}: tx.timestamp "
                    f"{tx.timestamp} > block.timestamp "
                    f"{block.header.timestamp}"
                )

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

            if not verify_transfer_transaction(
                ttx, verifying_pubkey,
                current_height=block.header.block_number,
            ):
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

        # Per-block new-account cap — second line of defense beyond the
        # NEW_ACCOUNT_FEE surcharge.  Count brand-new recipients funded
        # by this block (deduped via pending_new_account_created, so
        # intra-block pipelining to the same recipient counts once).
        # Enforced as a HARD consensus rule: all nodes arrive at the
        # same count by using the same _recipient_is_new helper.
        if len(pending_new_account_created) > MAX_NEW_ACCOUNTS_PER_BLOCK:
            return False, (
                f"Block creates {len(pending_new_account_created)} new accounts, "
                f"exceeding MAX_NEW_ACCOUNTS_PER_BLOCK cap "
                f"of {MAX_NEW_ACCOUNTS_PER_BLOCK} per block"
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
        #
        # H5: drop any unstake whose entity is also the offender of a
        # SlashTransaction in the same block — the apply path pre-empts
        # it (see _apply_block_state's unstake loop), so the validator
        # must not pipeline its nonce/balance or state diverges.
        _slashed_offenders_vb = {
            stx.evidence.offender_id for stx in block.slash_transactions
        }
        for utx in getattr(block, "unstake_transactions", []):
            if utx.entity_id in _slashed_offenders_vb:
                continue
            ok, reason = self._validate_unstake_tx_in_block(
                utx, pending_nonces, pending_balance_spent,
            )
            if not ok:
                return False, f"Invalid unstake tx: {reason}"

        # Custody-proof hygiene + cryptographic validation.  Matches
        # the state_root_checkpoint hygiene pattern: non-challenge
        # blocks MUST carry an empty list.  On a challenge block the
        # proofs are verified against the challenge's target block —
        # which is derived from the parent block's hash (known at this
        # point: the parent is already in self.chain).
        valid, reason = self._validate_custody_proofs(block, latest)
        if not valid:
            return False, reason

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
            current_height=self.height + 1,
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
        if authority_pk is None or not verify_unstake_transaction(
            utx, authority_pk, current_height=self.height + 1,
        ):
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
        if not verifier(
            gtx, self.public_keys[sender], current_height=self.height + 1,
        ):
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

        # Per-block count caps — same early rejection as validate_block.
        ok, reason = self._validate_block_list_counts(block)
        if not ok:
            return False, reason

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

        # Merkle root via the canonical tx-hash builder — single source
        # of truth so this fork-path validator stays in lockstep with
        # the primary validator (validate_block) and pos.create_block.
        # The prior hand-rolled list here was missing finality_votes,
        # custody_proofs, censorship_evidence_txs,
        # bogus_rejection_evidence_txs, and the archive_proof_bundle
        # hash — so any block carrying those variants was spuriously
        # rejected when re-validated via the fork path.
        tx_hashes = canonical_block_tx_hashes(block)
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
            # Thread block height so FEE_INCLUDES_SIGNATURE_HEIGHT gate
            # applies to consensus verification.
            if not verify_transaction(
                tx, pk, current_height=block.header.block_number,
            ):
                return False, f"Invalid signature in tx {tx.tx_hash.hex()[:16]}"

        for ttx in block.transfer_transactions:
            if ttx.entity_id not in self.public_keys:
                return False, f"Unknown sender in transfer {ttx.tx_hash.hex()[:16]}"
            pk = self.public_keys[ttx.entity_id]
            if not verify_transfer_transaction(
                ttx, pk, current_height=block.header.block_number,
            ):
                return False, f"Invalid signature in transfer {ttx.tx_hash.hex()[:16]}"

        # Per-block new-account cap — mirrors validate_block.  Count
        # brand-new recipients with intra-block pipelining so the count
        # matches across all validation entry points.
        pending_new_account_created_sa: set[bytes] = set()
        for ttx in block.transfer_transactions:
            if self._recipient_is_new(
                ttx.recipient_id,
                pending_new_account_created=pending_new_account_created_sa,
            ):
                pending_new_account_created_sa.add(ttx.recipient_id)
        if len(pending_new_account_created_sa) > MAX_NEW_ACCOUNTS_PER_BLOCK:
            return False, (
                f"Block creates {len(pending_new_account_created_sa)} new accounts, "
                f"exceeding MAX_NEW_ACCOUNTS_PER_BLOCK cap "
                f"of {MAX_NEW_ACCOUNTS_PER_BLOCK} per block"
            )

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
            # R6-A: mirror apply_key_rotation's key_history update so
            # the block-replay path (used during normal block apply and
            # reorg replay) also records the rotation.
            self._record_key_history(atx.entity_id, atx.new_public_key)
            self.key_rotation_counts[atx.entity_id] = atx.rotation_number + 1
            # New Merkle tree = independent leaf namespace, so reset.
            self.leaf_watermarks[atx.entity_id] = 0
            # WHY: mirrors apply_key_rotation (the RPC path) so the
            # KEY_ROTATION_COOLDOWN_BLOCKS check fires for rotations
            # applied via blocks too.  Without this update, the block-
            # apply path silently forgot the cooldown — meaning any
            # rotation included in a block (i.e. every rotation on the
            # live network, since authority txs propagate through blocks)
            # left last_height empty and `validate_key_rotation` saw
            # `elapsed = height - (-COOLDOWN) = height + COOLDOWN` and
            # accepted a follow-up rotation immediately.  Also restores
            # the cooldown after a reorg: _reset_state clears the map,
            # and replay through this path rebuilds it (R6-B).
            self.key_rotation_last_height[atx.entity_id] = self.height
            if self.db is not None:
                self.db.set_public_key(atx.entity_id, atx.new_public_key)
                if hasattr(self.db, "set_leaf_watermark"):
                    self.db.set_leaf_watermark(atx.entity_id, 0)
                if hasattr(self.db, "set_key_rotation_count"):
                    self.db.set_key_rotation_count(
                        atx.entity_id, self.key_rotation_counts[atx.entity_id],
                    )
        elif cls_name == "SetReceiptSubtreeRootTransaction":
            ok, _ = self.validate_set_receipt_subtree_root(atx)
            if not ok:
                return
            if not self.supply.pay_fee_with_burn(
                atx.entity_id, proposer_id, atx.fee, base_fee,
            ):
                logger.error(
                    f"SetReceiptSubtreeRoot fee payment failed (fee "
                    f"{atx.fee} vs base_fee {base_fee}) — skipping"
                )
                return
            self.receipt_subtree_roots[atx.entity_id] = atx.root_public_key
            if self.db is not None and hasattr(
                self.db, "set_receipt_subtree_root",
            ):
                self.db.set_receipt_subtree_root(
                    atx.entity_id, atx.root_public_key,
                )
            # Nonce-free; signature consumed a leaf in the COLD tree —
            # deliberately do NOT bump the hot-key watermark, matching
            # Revoke.
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
            self._record_key_history(tx.entity_id, tx.sender_pubkey)
            self.nonces.setdefault(tx.entity_id, 0)
            self._assign_entity_index(tx.entity_id)
            self._record_tree_height(tx.entity_id, tx.signature)
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

    # Fractional-accounting scale for divestment debt.  1 whole token =
    # _DIVESTMENT_SCALE fractional units.  10**9 gives ~1 part per
    # billion precision — more than enough to drain any divestible
    # amount cleanly over a 210K-block window without float arithmetic.
    _DIVESTMENT_SCALE: int = 10 ** 9

    def _apply_treasury_rebase(self, block_height: int) -> None:
        """Burn TREASURY_REBASE_BURN_AMOUNT from the treasury at activation.

        Fires exactly once, at ``block_height == TREASURY_REBASE_HEIGHT``.
        All other heights are no-ops (both pre- and post-activation).

        Idempotent: an adjacent re-apply at the same height is guarded
        by ``self.supply.treasury_rebase_applied``.  The flag is
        snapshotted for reorg safety — a reorged-out rebase block
        correctly un-burns on rollback via the supply-level snapshot
        of total_supply / total_burned / balances plus the flag reset.

        Motivation: the 1B→140M GENESIS_SUPPLY rebase left
        TREASURY_ALLOCATION = 40M (~28.6% of supply) which, combined
        with seed-divestment routing ~23.5M more to treasury, would
        leave ~91% of post-bootstrap circulating supply in a
        governance-captured pool.  Burning 33M at activation returns
        the treasury to ~5% of supply.
        """
        from messagechain.config import (
            TREASURY_REBASE_HEIGHT,
            TREASURY_REBASE_BURN_AMOUNT,
        )
        if block_height != TREASURY_REBASE_HEIGHT:
            return
        if self.supply.treasury_rebase_applied:
            return
        # If the treasury somehow cannot cover the burn (e.g. operator
        # has mis-set the placeholder activation height to a point
        # deep in chain history where the treasury has already been
        # drained by governance), burn_from_treasury returns False.
        # We log and DO NOT set the applied flag — the failure mode
        # stays observable rather than silent.
        ok = self.supply.burn_from_treasury(TREASURY_REBASE_BURN_AMOUNT)
        if not ok:
            logger.error(
                "Treasury rebase burn at height %d failed: treasury "
                "balance insufficient.  Chain state may drift from "
                "peers that applied the burn earlier.",
                block_height,
            )
            return
        self.supply.treasury_rebase_applied = True

    def _apply_seed_divestment(self, block_height: int) -> None:
        """Forcibly divest the founder's stake DOWN TO the retain floor.

        Non-discretionary, always-on schedule.  Between SEED_DIVESTMENT_START
        (exclusive) and SEED_DIVESTMENT_END (inclusive), each block drains
        a linear portion of the DIVESTIBLE amount.  The burn / treasury
        split is activation-gated (see
        ``messagechain.config.get_seed_divestment_params``): pre-retune
        it is 75/25 against a 1M floor; post-retune it is 95/5 against
        a 20M floor.  Outside that window this is a no-op.

        Divestible = max(0, initial_seed_stake - retain_floor(block_height)).
        Only the excess above the floor is subject to divestment; the
        founder keeps at least retain_floor tokens of stake permanently
        through protocol enforcement.  They can voluntarily unstake via
        a normal UnstakeTransaction post-END.

        **Fractional accounting**: the OLD formula
        `per_block = initial // window` silently floored to 0 for any
        seed whose divestible amount was smaller than the window length
        (210,384 blocks), producing a silent no-op for small stakes.
        The fix: maintain a per-seed integer debt dict at SCALE = 10**9
        fractional units; each block add `(divestible * SCALE) // window`
        to debt; when debt >= SCALE, drain `debt // SCALE` whole tokens
        and keep the remainder.  Integer-only arithmetic (consensus-safe)
        that correctly drains tiny amounts over the full window.

        Snapshot is taken once at the first divestment block from the
        live staked balance so replay is deterministic (every node that
        re-applies that block captures the same value).  Stored in
        `self.seed_initial_stakes` (the reference) and
        `self.seed_divestment_debt` (the running fractional remainder);
        both round-trip through _snapshot_memory_state for reorg safety
        and through the state-snapshot root for state-sync parity.

        Called from `_apply_block_state` after all tx-driven stake moves
        so the divestment operates on the post-tx staked balance.  Any
        integer-rounding remainder in the per-block burn/treasury split
        accrues to burn (cleaner: smaller supply).  Stake is clamped at
        the floor — once a seed's stake hits the floor no further
        tokens move regardless of the schedule.
        """
        from messagechain.config import (
            SEED_DIVESTMENT_START_HEIGHT,
            SEED_DIVESTMENT_END_HEIGHT,
            TREASURY_ENTITY_ID,
            get_seed_divestment_params,
        )
        if block_height <= SEED_DIVESTMENT_START_HEIGHT:
            return
        if block_height > SEED_DIVESTMENT_END_HEIGHT:
            return
        if not self.seed_entity_ids:
            return
        window = SEED_DIVESTMENT_END_HEIGHT - SEED_DIVESTMENT_START_HEIGHT
        assert window > 0, "divestment window must be positive"

        # Hard-fork-gated parameters (SEED_DIVESTMENT_RETUNE_HEIGHT):
        # pre-activation the legacy (floor=1M, burn=75%, treasury=25%)
        # values apply byte-for-byte; post-activation the retune
        # (floor=20M, burn=95%, treasury=5%) values apply.  The sim
        # path in compute_post_state_root reads the same helper so sim
        # and apply stay in lockstep at every height.
        retain_floor, _burn_bps, treasury_bps = get_seed_divestment_params(
            block_height,
        )

        SCALE = self._DIVESTMENT_SCALE

        for eid in self.seed_entity_ids:
            # First-block snapshot: capture the seed's then-current stake
            # once, so subsequent blocks decrement by a flat per-block
            # amount instead of rebasing against the decayed stake.
            if eid not in self.seed_initial_stakes:
                self.seed_initial_stakes[eid] = self.supply.get_staked(eid)
            initial = self.seed_initial_stakes[eid]
            if initial <= retain_floor:
                # Nothing divestible — a tiny-stake seed keeps its full
                # balance.  Explicit early-exit so no fractional debt
                # accrues for this seed.
                continue

            divestible = initial - retain_floor
            current_stake = self.supply.get_staked(eid)
            if current_stake <= retain_floor:
                # Current stake already at/below floor — freeze.  This
                # handles external shocks (slashing, unstaking) that
                # pushed stake below the floor mid-window.
                continue

            # Fractional debt: drift forward by divestible/window.
            per_block_scaled = (divestible * SCALE) // window
            debt = self.seed_divestment_debt.get(eid, 0) + per_block_scaled
            whole = debt // SCALE
            if whole <= 0:
                # Fractional-only step — carry the accumulator forward
                # unchanged; no whole tokens to drain yet.
                self.seed_divestment_debt[eid] = debt
                continue

            # Clamp: never drain below the floor, even if cumulative
            # fractional drift would overshoot by a token.
            max_drainable = current_stake - retain_floor
            divest = min(whole, max_drainable)
            if divest <= 0:
                # Floor hit this block — keep the fractional remainder
                # AND the whole tokens we couldn't drain, so they're
                # still on the schedule for the next block.
                self.seed_divestment_debt[eid] = debt
                continue

            # Only subtract the whole tokens we actually drained from the
            # debt accumulator.  Using `whole * SCALE` here (as earlier
            # versions did) silently strands `whole - divest` tokens when
            # the floor clamp trims `divest` below `whole` — typically
            # triggered by a slashing event mid-window that drops
            # current_stake close to the floor.  Use `divest * SCALE` so
            # the undrained remainder rolls over to the next block and
            # the full divestible schedule is conserved regardless of
            # slashing.
            self.seed_divestment_debt[eid] = debt - divest * SCALE

            # Split: treasury gets the activation-gated bps share;
            # burn gets the remainder so any integer-rounding remainder
            # always favors burn — smaller supply is the cleaner
            # invariant.
            treasury_share = divest * treasury_bps // 10_000
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

        # Reset the per-block fee-burn ticker so this block's
        # pay_fee_with_burn calls accumulate cleanly.  Read back at
        # end-of-block to redirect ARCHIVE_BURN_REDIRECT_PCT into the
        # archive reward pool.  See docs/proof-of-custody-archive-
        # rewards.md.
        self.supply.fee_burn_this_block = 0

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
                self.supply.total_burned += escrow_burned
            self.supply.slash_validator(stx.evidence.offender_id, stx.submitter_id)
            self.slashed_validators.add(stx.evidence.offender_id)
            # Reputation reset: same policy as apply_slash_transaction;
            # a slashed validator forfeits accumulated reputation.
            self.reputation.pop(stx.evidence.offender_id, None)
            self.slash_sig_counts[stx.submitter_id] = (
                self.slash_sig_counts.get(stx.submitter_id, 0) + 1
            )
            self._bump_watermark(stx.submitter_id, stx.signature.leaf_index)

        # Observe: any pending censorship-evidence whose receipted tx
        # just landed above is voided.  Runs BEFORE evidence-tx
        # admission in the same block so a tx+evidence included
        # together does not land as a pending entry and get slashed
        # later — the block that includes the tx proves there was no
        # censorship.  Voided entries go into processor.processed to
        # prevent re-submission.
        self.censorship_processor.observe_block(block)

        # Admit newly-submitted CensorshipEvidenceTx.  Validator block
        # verification has already run validate_censorship_evidence_tx
        # on each entry; we still defensively re-check here so the
        # apply path never slashes on an unverified claim.
        for etx in getattr(block, "censorship_evidence_txs", []):
            ok, reason = self.validate_censorship_evidence_tx(
                etx, chain_height=block.header.block_number,
            )
            if not ok:
                logger.warning(
                    f"CensorshipEvidenceTx {etx.tx_hash.hex()[:16]} rejected at "
                    f"apply-time: {reason}"
                )
                continue
            if not self.supply.pay_fee_with_burn(
                etx.submitter_id, proposer_id, etx.fee, current_base_fee,
            ):
                logger.error(
                    f"CensorshipEvidenceTx {etx.tx_hash.hex()[:16]} fee payment "
                    f"failed — skipping"
                )
                continue
            admitted = self.censorship_processor.submit(
                evidence_hash=etx.evidence_hash,
                offender_id=etx.offender_id,
                tx_hash=etx.message_tx.tx_hash,
                admitted_height=block.header.block_number,
                evidence_tx_hash=etx.tx_hash,
            )
            if not admitted:
                logger.warning(
                    f"CensorshipEvidenceTx {etx.tx_hash.hex()[:16]} already "
                    f"pending/processed — fee charged but no new admission"
                )
            # Consume submitter's WOTS+ leaf.
            self._bump_watermark(etx.submitter_id, etx.signature.leaf_index)

        # Bogus-rejection evidence — one-phase apply.  For each etx:
        #   1. Re-run admission gate (validate_bogus_rejection_evidence_tx).
        #   2. If accepted, hand to processor.process(); processor decides
        #      slashable/honest/non-slashable-reason and mutates state
        #      (slash + record processed).
        #   3. On honest-rejection (apply-time refusal): NO fee, NO
        #      watermark bump — the evidence_tx is rejected as if it
        #      never landed.
        #   4. On every other admitted outcome (slashed OR non-slashable
        #      reason code): fee paid + watermark bumped + processed.
        for etx in getattr(block, "bogus_rejection_evidence_txs", []):
            ok, reason = self.validate_bogus_rejection_evidence_tx(etx)
            if not ok:
                logger.warning(
                    f"BogusRejectionEvidenceTx {etx.tx_hash.hex()[:16]} "
                    f"rejected at apply-time: {reason}"
                )
                continue
            result = self.bogus_rejection_processor.process(etx, self)
            if not result.accepted:
                # Honest rejection or already-processed — no fee, no
                # watermark bump.  The evidence_tx is rejected entirely.
                logger.info(
                    f"BogusRejectionEvidenceTx {etx.tx_hash.hex()[:16]} "
                    f"refused at apply-time: {result.reason}"
                )
                continue
            if not self.supply.pay_fee_with_burn(
                etx.submitter_id, proposer_id, etx.fee, current_base_fee,
            ):
                logger.error(
                    f"BogusRejectionEvidenceTx {etx.tx_hash.hex()[:16]} fee "
                    f"payment failed — skipping (state may drift)"
                )
                continue
            self._bump_watermark(etx.submitter_id, etx.signature.leaf_index)
            if result.slashed:
                logger.info(
                    f"BOGUS-REJECTION-SLASHED validator "
                    f"{result.offender_id.hex()[:16]}: "
                    f"stake_burned={result.slash_amount}, "
                    f"evidence={etx.evidence_hash.hex()[:16]}"
                )

        # Apply authority transactions (SetAuthorityKey / Revoke / KeyRotation).
        # These all carry block-level state changes that previously only
        # applied on the node receiving the RPC — committing them through
        # the block pipeline is what makes the hot/cold split, emergency
        # revoke, and key rotation consensus-visible across all peers.
        #
        # M4: iterate in CANONICAL order (Revoke before SetAuthorityKey)
        # so a block that contains both for the same entity always flips
        # revoked first and ignores the hot-key-signed Set.  Iterating in
        # the proposer's listed order is nondeterministic and lets a
        # compromised hot key race the cold-key holder.
        for atx in _canonicalize_authority_txs(
            getattr(block, "authority_txs", []),
        ):
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
                self._record_key_history(stx.entity_id, stx.sender_pubkey)
                self.nonces.setdefault(stx.entity_id, 0)
                self._assign_entity_index(stx.entity_id)
                # Record tree_height on first-spend stake install.
                self._record_tree_height(stx.entity_id, stx.signature)
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
        #
        # H5: if this block also carries a SlashTransaction for the same
        # entity, the slash loop above has already wiped that entity's
        # stake AND pending_unstakes.  Running the unstake afterwards
        # would charge a fee for a tx that can no longer have any
        # effect — a silent fee-burn against a doomed transaction, plus
        # a nonce bump that diverges from what validators expect.
        # Drop such unstakes entirely before the apply loop; validate_
        # block and compute_post_state_root mirror the same skip so
        # state_root stays consistent across the pipeline.
        slashed_offenders_this_block = {
            stx.evidence.offender_id for stx in block.slash_transactions
        }
        for utx in getattr(block, "unstake_transactions", []):
            if utx.entity_id in slashed_offenders_this_block:
                # Pre-empted by a same-block slash.  No fee, no nonce
                # bump, no watermark bump — the tx is as if it had
                # never been included.
                continue
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

        # Treasury rebase (hard fork, once-per-chain at activation
        # height).  Runs after seed divestment: a same-block divestment
        # step that routes treasury_share into the treasury does so
        # BEFORE the burn, so the burn sees the post-divestment
        # treasury balance.  This keeps the simulation path in
        # compute_post_state_root (which mirrors this ordering) and the
        # apply path byte-consistent.
        self._apply_treasury_rebase(block.header.block_number)

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

        # Select the committee that will actually be paid.  Pre-activation:
        # committee sized implicitly by the pool (at 1 token/slot) — this
        # caused the BLOCK_REWARD_FLOOR=4 / attester_pool=3 / committee=3
        # decentralization failure.  Post-activation: committee sized by
        # consensus policy (ATTESTER_COMMITTEE_TARGET_SIZE), pool divided
        # pro-rata in mint_block_reward.  Seeds are excluded during the
        # first half of bootstrap (see attester_committee.py); selection
        # weight blends uniform and stake-weighted by bootstrap_progress.
        from messagechain.consensus.attester_committee import (
            ATTESTER_REWARD_PER_SLOT,
            select_attester_committee,
        )
        from messagechain.config import (
            PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR,
            ATTESTER_REWARD_SPLIT_HEIGHT,
            ATTESTER_COMMITTEE_TARGET_SIZE,
        )
        block_reward = self.supply.calculate_block_reward(block.header.block_number)
        attester_pool_tokens = block_reward - (
            block_reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
        )
        if block.header.block_number >= ATTESTER_REWARD_SPLIT_HEIGHT:
            committee_size = ATTESTER_COMMITTEE_TARGET_SIZE
        else:
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

        # Archive-duty reward withhold (iteration 3b-iii).  For every
        # entity that just received a mint credit, read their miss
        # counter and divert withhold_pct(miss)% of their reward into
        # the archive_reward_pool.  Bootstrap-exempt validators skip
        # this (withhold_pct returns 0 via the zero-miss default for
        # exempt validators — grace is enforced upstream at
        # _apply_archive_duty; counters never increment inside grace).
        # This keeps the withhold hot path simple: zero-miss = zero
        # withhold, no branching on grace here.
        #
        # Withheld tokens leave the recipient's balance and enter the
        # archive_reward_pool scalar.  total_supply is UNCHANGED (just
        # a reassignment between circulating balance and pool).  The
        # `result` dict is rewritten so downstream escrow tracking
        # sees the net amount; otherwise the escrow release later
        # would try to unlock tokens the recipient never actually
        # received.
        from messagechain.consensus.archive_duty import (
            is_bootstrap_exempt,
            withhold_pct,
        )
        _withhold_adjustments: dict[bytes, int] = {}
        for _recipient, _gross in (
            [(proposer_id, result["proposer_reward"])]
            + list(result["attestor_rewards"].items())
        ):
            if _gross <= 0:
                continue
            # Defense-in-depth: never withhold from a bootstrap-exempt
            # validator.  By invariant (compute_miss_updates skips
            # exempt validators), their miss counter is 0 and the
            # branch below would pass through anyway — this guard
            # makes the property explicit at the mutation site.
            if is_bootstrap_exempt(
                entity_id=_recipient,
                current_block=block.header.block_number,
                validator_first_active_block=(
                    self.validator_first_active_block
                ),
            ):
                continue
            _miss = self.validator_archive_misses.get(_recipient, 0)
            _pct = withhold_pct(_miss)
            if _pct <= 0:
                continue
            _withheld = _gross * _pct // 100
            if _withheld <= 0:
                continue
            # Move tokens from recipient balance → archive pool.
            self.supply.balances[_recipient] = (
                self.supply.balances.get(_recipient, 0) - _withheld
            )
            self.archive_reward_pool += _withheld
            # Accumulate per-recipient adjustment so we can patch
            # `result` with net amounts below.
            _withhold_adjustments[_recipient] = (
                _withhold_adjustments.get(_recipient, 0) + _withheld
            )
        if _withhold_adjustments:
            if proposer_id in _withhold_adjustments:
                result["proposer_reward"] -= _withhold_adjustments[proposer_id]
            for _eid, _adj in _withhold_adjustments.items():
                if _eid in result["attestor_rewards"]:
                    result["attestor_rewards"][_eid] -= _adj

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

        # Proof-of-custody archive rewards — redirect a fraction of
        # this block's fee-burn into the archive reward pool, and pay
        # rewards to any valid custody proofs against the challenge
        # block.  Runs AFTER all fee-bearing txs so the pool captures
        # the true post-block burn amount, and BEFORE update_base_fee
        # so the next-block base fee reflects the accounting as
        # committed.
        self._apply_archive_rewards(block)

        # Archive-custody DUTY layer (iteration 3b-ii): track first-
        # active blocks, capture challenge-block snapshots, and close
        # epochs.  Must run AFTER _apply_archive_rewards so the
        # bundles applied in this block (if any) are visible when we
        # close an epoch, and AFTER any stake-moving ops so the
        # active-set snapshot reflects post-stake state.
        self._apply_archive_duty(block)

        # Mature any censorship-evidence whose maturity window has
        # elapsed without the receipted tx landing on-chain.  Runs
        # AFTER tx/evidence application so a same-block evidence
        # cannot mature before its counter-proof (the tx landing) has
        # had a chance to void it.  Each matured entry is a slash:
        # burn CENSORSHIP_SLASH_BPS of the offender's stake and record
        # the evidence_hash in _processed_evidence so the dedupe
        # pipeline prevents re-submission.
        matured = self.censorship_processor.mature(
            block.header.block_number,
        )
        for m in matured:
            self._apply_censorship_slash(m)

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

    def _apply_archive_rewards(self, block: Block):
        """Redirect fee-burn into archive pool + pay custody-proof rewards.

        Two steps, in order:

          1. Redirect: take ARCHIVE_BURN_REDIRECT_PCT of this block's
             fee_burn_this_block; add it to archive_reward_pool;
             subtract it from total_burned and add it back to
             total_supply (those tokens are moving from "burned" to
             "held in pool," not destroyed).  Reset the ticker.
          2. Payout: if this is a challenge block, verify any custody
             proofs in the block body (future field) against the
             challenge's target height and pay the FCFS winners from
             the pool.

        Custody-proof application is a no-op today: no block field
        carries proofs yet.  The pool-funding half is the load-
        bearing consensus change for v1 — it establishes the money
        stream that makes the later proof-submission pipeline
        possible.  Balance is committed to the state snapshot root
        via storage.state_snapshot so a bootstrapping node sees the
        same scalar as a replaying node.
        """
        from messagechain.consensus.archive_challenge import split_burn_for_pool

        fee_burn = self.supply.fee_burn_this_block
        if fee_burn > 0:
            pool_add, _burn_keep = split_burn_for_pool(fee_burn)
            if pool_add > 0:
                # Move tokens from "burned" back into circulation (the
                # pool).  total_supply rises by pool_add because those
                # tokens are once again held somewhere, but they aren't
                # in any per-entity balance yet — they sit in the
                # consensus-visible archive_reward_pool scalar.
                self.supply.total_burned -= pool_add
                self.supply.total_supply += pool_add
                self.archive_reward_pool += pool_add
        # Reset regardless — next block's burn accumulates from zero.
        self.supply.fee_burn_this_block = 0

        # Payout step.  Non-challenge blocks always carry an empty
        # custody_proofs list (validate_block enforces the hygiene rule),
        # so proofs is non-empty here only on a challenge block that
        # also validated against the challenge's target block.
        proofs = getattr(block, "custody_proofs", None) or []
        if proofs:
            from messagechain.consensus.archive_challenge import (
                ArchiveRewardPool,
                apply_archive_rewards,
            )
            # Wrap the scalar pool in the primitive's dataclass so we
            # reuse its try_pay / cap logic exactly — prevents drift
            # between the sim (compute_post_state_root) and the apply
            # path.  After payout we write the leftover back.
            wrapper = ArchiveRewardPool(balance=self.archive_reward_pool)
            # Resolve the challenge target using the parent block's
            # hash — same derivation validate_block used.  parent is
            # the last block in self.chain BEFORE this block is
            # appended (add_block appends after state apply).
            parent = self.chain[-1]
            expected_block_hash = proofs[0].target_block_hash
            # Defensive: if validate_block ran before us, every proof
            # already agrees on target_block_hash — but take it from
            # the first proof rather than re-resolving the challenge,
            # so a pool caller that applies an already-validated block
            # doesn't redundantly recompute compute_challenge here.
            result = apply_archive_rewards(
                proofs=proofs,
                pool=wrapper,
                expected_block_hash=expected_block_hash,
            )
            # Credit every paid prover.  Tokens move from the pool
            # into circulating balances — pool was already counted in
            # total_supply when it was funded, so no supply change.
            for payout in result.payouts:
                self.supply.balances[payout.prover_id] = (
                    self.supply.balances.get(payout.prover_id, 0)
                    + payout.amount
                )
            self.archive_reward_pool = wrapper.balance
            if result.total_paid > 0:
                logger.info(
                    f"ARCHIVE REWARDS: block #{block.header.block_number} "
                    f"paid {result.total_paid} tokens to "
                    f"{len(result.payouts)} provers "
                    f"(pool remaining: {self.archive_reward_pool})"
                )

    def _apply_archive_duty(self, block: Block):
        """Track first-active blocks, capture challenge snapshots, and
        close epochs.

        Three jobs, in order:
          1. Track first-active: for every validator currently above
             VALIDATOR_MIN_STAKE that we haven't seen before, record
             this block's height as their first-active.  Never advances
             an existing entry — a validator cycling below threshold
             and re-entering keeps their original first-active so they
             don't pick up a fresh bootstrap grace window on every
             stake cycle.
          2. Epoch close: if a snapshot is open and this block is at
             or past its submission-window end, walk bundles from the
             window, compute miss updates, fold into
             validator_archive_misses, and clear the snapshot.  Must
             run BEFORE snapshot capture so a block that is BOTH epoch
             close and next challenge (possible only if window ==
             interval) closes the old epoch first.
          3. Snapshot capture: if this is a challenge block (height %
             ARCHIVE_CHALLENGE_INTERVAL == 0, height > 0), materialize
             an ActiveValidatorSnapshot with current staked validators
             + K derived challenge heights.

        Deliberately ignores the reward-withhold path — that ships in
        iteration 3b-iii along with state-snapshot persistence.
        """
        from messagechain.config import (
            ARCHIVE_CHALLENGE_K,
            ARCHIVE_SUBMISSION_WINDOW,
            VALIDATOR_MIN_STAKE,
            is_archive_challenge_block,
        )
        from messagechain.consensus.archive_challenge import compute_challenges
        from messagechain.consensus.archive_duty import (
            ActiveValidatorSnapshot,
            compute_miss_updates,
        )

        height = block.header.block_number

        # 1. Track first-active block for any validator we haven't
        #    seen above threshold yet.
        for eid, amt in self.supply.staked.items():
            if amt < VALIDATOR_MIN_STAKE:
                continue
            if eid in self.validator_first_active_block:
                continue
            self.validator_first_active_block[eid] = height

        # 2. Close an open epoch if the window has elapsed.
        snap = self.archive_active_snapshot
        if (
            snap is not None
            and height >= snap.challenge_block + ARCHIVE_SUBMISSION_WINDOW
        ):
            # Walk the chain for bundles committed in
            # [challenge_block, challenge_block + window).  Include
            # the challenge block itself (it may carry bundles too).
            # self.chain contains every block including this one
            # (add_block appended it before state apply in some
            # paths; in others apply runs first).  Guard both.
            window_start = snap.challenge_block
            window_end = snap.challenge_block + ARCHIVE_SUBMISSION_WINDOW
            bundles = []
            for b in self.chain:
                bn = b.header.block_number
                if bn < window_start or bn >= window_end:
                    continue
                bundle = getattr(b, "archive_proof_bundle", None)
                if bundle is not None:
                    bundles.append(bundle)
            # Also include the current block's bundle when the window
            # end lies exactly on this block's height — propose paths
            # run apply before append, so self.chain[-1] may not yet
            # include `block`.
            if self.chain and self.chain[-1] is not block:
                bundle_here = getattr(block, "archive_proof_bundle", None)
                if bundle_here is not None and window_start <= height < window_end:
                    bundles.append(bundle_here)

            new_misses = compute_miss_updates(
                snapshot=snap,
                bundles_in_window=bundles,
                current_misses=self.validator_archive_misses,
                current_block=height,
                validator_first_active_block=(
                    self.validator_first_active_block
                ),
            )
            self.validator_archive_misses = new_misses
            self.archive_active_snapshot = None

        # 3. Capture a new snapshot at a challenge block.
        if is_archive_challenge_block(height):
            active_set = frozenset(
                eid for eid, amt in self.supply.staked.items()
                if amt >= VALIDATOR_MIN_STAKE
            )
            if active_set:
                challenges = compute_challenges(
                    block.block_hash, height, k=ARCHIVE_CHALLENGE_K,
                )
                heights = tuple(int(c.target_height) for c in challenges)
                self.archive_active_snapshot = ActiveValidatorSnapshot(
                    challenge_block=height,
                    active_set=active_set,
                    challenge_heights=heights,
                )

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

        Note on MAX_NEW_ACCOUNTS_PER_BLOCK: the cap is enforced on
        transfer txs in validate_block.  Treasury spends that credit
        brand-new accounts are rate-limited by governance itself (weeks
        of 2/3-supermajority voting per spend), so they do NOT share a
        per-block counter with transfers.  Each treasury spend still
        burns NEW_ACCOUNT_FEE from the treasury when it credits a new
        account (see execute_treasury_spend).
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

        # Phase 2: auto-execute binding treasury spends whose window has closed.
        # M5: when multiple treasury spends close in the same block, process
        # them in a deterministic order (hex-sorted proposal_id) so the
        # in-block balance re-check is reproducible across nodes.  Each
        # execute_treasury_spend re-reads get_balance(TREASURY_ENTITY_ID)
        # at call time, so prior debits in this loop are visible — the
        # second spend sees the post-first-debit treasury and overdrafts
        # predictably instead of racing.
        closed_spends = [
            (pid, state) for pid, state in tracker.proposals.items()
            if isinstance(state.proposal, TreasurySpendTransaction)
            and current_block - state.created_at_block > GOVERNANCE_VOTING_WINDOW
        ]
        closed_spends.sort(key=lambda kv: kv[0])  # proposal_id bytes-sorted
        for pid, state in closed_spends:
            tracker.execute_treasury_spend(
                state.proposal, self.supply, current_block=current_block,
                is_new_account=self._recipient_is_new,
            )

        # Phase 3: prune
        tracker.prune_closed_proposals(current_block)

    def _apply_mainnet_genesis_state(self, block: Block) -> tuple[bool, str]:
        """Reconstruct mainnet post-bootstrap state from block 0 alone.

        The founder's launch flow did `initialize_genesis +
        bootstrap_seed_local` — block 0 was minted, then off-block
        direct-state mutations applied (register pubkey, self-authority-
        key, stake 95M).  A joining validator's IBD must
        reproduce those mutations exactly, else its pre-block-1 state
        diverges from the founder's and block 1's state_root rejects.

        The founder's public key is extracted from block 0's proposer
        signature via Merkle-auth-path reconstruction.  Applying the
        canonical _MAINNET_FOUNDER_LIQUID / _MAINNET_FOUNDER_STAKE
        constants then reproduces the exact post-bootstrap state.  Any
        drift from the founder's actual parameters surfaces as a
        state_root mismatch at block 1 — constants are self-verifying.

        Called from add_block's synced-genesis branch after the
        PINNED_GENESIS_HASH check passes.  Only runs when the pinned
        hash is the mainnet hash (testnet/devnet keep the existing
        snapshot/tarball workflow).
        """
        import messagechain.config as _cfg
        sig = block.header.proposer_signature
        if sig is None:
            return False, "Genesis block has no proposer signature"

        # Step 1: extract founder pubkey from the block-0 signature.
        founder_pubkey = compute_root_from_signature(sig)
        if founder_pubkey is None:
            return False, "Block 0 signature is structurally malformed"

        # Step 2: verify the extracted pubkey matches the header's
        # proposer_id — if derive_entity_id(pubkey) != proposer_id, we
        # extracted the wrong root (malformed or manipulated sig).
        from messagechain.identity.identity import derive_entity_id
        if derive_entity_id(founder_pubkey) != block.header.proposer_id:
            return False, (
                "Block 0 signature's derived pubkey does not match "
                "the header proposer_id — block is malformed"
            )

        # Step 3: verify block 0's signature is actually valid under
        # the derived pubkey.  Extracting the root from auth_path is
        # arithmetic; this is the cryptographic authentication.
        from messagechain.core.block import _hash as _block_hash
        header_hash = _block_hash(block.header.signable_data())
        if not verify_signature(header_hash, sig, founder_pubkey):
            return False, "Block 0 signature is invalid under derived pubkey"

        founder_eid = block.header.proposer_id
        # Defense in depth: the pinned block-0 hash already authenticates
        # the chain, but also cross-check that the founder's entity_id
        # matches a hardcoded mainnet pin.  This traps any future edit
        # to _MAINNET_GENESIS_HASH that forgets to update the allocation
        # constants, and limits the attack surface of the synced-
        # reconstruction path to a single cryptographically-pinned
        # identity.
        expected_eid = getattr(_cfg, "_MAINNET_FOUNDER_ENTITY_ID", None)
        if expected_eid is not None and founder_eid != expected_eid:
            return False, (
                "Block 0 proposer_id does not match pinned "
                "_MAINNET_FOUNDER_ENTITY_ID — config drift or malicious peer"
            )
        tree_height = len(sig.auth_path)

        # ── initialize_genesis-equivalent mutations ───────────────────
        self.chain.append(block)
        self._block_by_hash[block.block_hash] = block

        self.public_keys[founder_eid] = founder_pubkey
        self._record_key_history(founder_eid, founder_pubkey)
        self.nonces[founder_eid] = 0
        self._set_tree_height_explicit(founder_eid, tree_height)
        self._assign_entity_index(founder_eid)
        self.proposer_sig_counts[founder_eid] = 1
        self._bump_watermark(founder_eid, sig.leaf_index)

        # Founder gets the full 100M in liquid initially; bootstrap
        # below then converts 95M of that into stake.
        self.supply.balances[founder_eid] = (
            self.supply.balances.get(founder_eid, 0)
            + _cfg._MAINNET_FOUNDER_TOTAL
        )
        self.supply.balances[_cfg.TREASURY_ENTITY_ID] = (
            self.supply.balances.get(_cfg.TREASURY_ENTITY_ID, 0)
            + _cfg.TREASURY_ALLOCATION
        )
        self._assign_entity_index(_cfg.TREASURY_ENTITY_ID)

        # Seed set: founder is the only seed (treasury is excluded).
        self.seed_entity_ids = frozenset({founder_eid})

        self.fork_choice.add_tip(block.block_hash, 0, 0)

        # Pin empty stake snapshot at block 0 — matches the founder's
        # node, where _record_stake_snapshot(0) runs inside
        # initialize_genesis BEFORE bootstrap_seed_local applies the
        # 95M stake.
        self._record_stake_snapshot(0)

        # ── bootstrap_seed_local-equivalent mutations ─────────────────
        # The founder's launch script ran bootstrap_seed_local between
        # initialize_genesis and the first server start.  On mainnet,
        # its three steps reduce to a single net state change:
        #
        #   Step 1 (register):           no-op — already installed by
        #                                initialize_genesis above.
        #   Step 2 (set_authority_key):  SKIPPED on mainnet because the
        #                                launch script passes
        #                                cold_authority_pubkey = hot pubkey,
        #                                and get_authority_key's fallback
        #                                already returns the hot pubkey —
        #                                they test equal, so the tx never
        #                                runs, no fee burn, no nonce bump.
        #   Step 3 (stake):              moves 95M from liquid to staked.
        #
        # The net effect is just the stake.  authority_keys stays empty
        # (the fallback in get_authority_key makes this transparent).
        # Cannot fail: we just credited founder_eid with TOTAL (100M) and
        # STAKE (95M) is strictly less.  A failure here means a config
        # invariant is violated AND we have already mutated self.chain /
        # public_keys / balances — leaving state half-built.  Raise
        # rather than return False so the node halts loudly instead of
        # silently corrupting.
        if not self.supply.stake(founder_eid, _cfg._MAINNET_FOUNDER_STAKE):
            raise RuntimeError(
                "BUG: _apply_mainnet_genesis_state stake step failed "
                "despite canonical TOTAL >= STAKE invariant — refusing "
                "to continue with half-built genesis state"
            )

        # Rebuild the state tree so compute_current_state_root reflects
        # the fully-populated post-bootstrap state.
        self._rebuild_state_tree()

        # Persist atomically.  A SIGKILL between store_block and
        # _persist_state (e.g., OOM killer, power loss, operator kill -9)
        # would otherwise leave block 0 on disk with no founder state —
        # val-2 restarts into height=1 with empty public_keys/balances
        # and every subsequent block 1 fails state_root verification
        # forever, with no clear repair path short of `rm -rf data-dir`.
        if self.db is not None:
            self.db.begin_transaction()
            try:
                self.db.store_block(block, state=self)
                self.db.add_chain_tip(block.block_hash, 0, 0)
                self._persist_state()
                self.db.commit_transaction()
            except BaseException:
                self.db.rollback_transaction()
                raise

        # Drain any orphans that were waiting on block 0.  During IBD,
        # val-2 often receives block 1+ before block 0 and they land in
        # the orphan pool (add_block orphan branch); without this drain
        # the node stalls until a peer happens to resend them.
        self._process_orphans(block.block_hash)

        return True, "Genesis block reconstructed from block 0 alone"

    def add_block(self, block: Block) -> tuple[bool, str]:
        """Validate and append a block, updating state (fees + inflation)."""
        # ── Weak-subjectivity checkpoint gate ───────────────────────────
        # Universal long-range-attack defense: if this block's height is
        # checkpointed and its hash doesn't match, reject.  Lives here
        # (not only in sync.py) so ANNOUNCE_BLOCK / RESPONSE_BLOCK /
        # reorg-replay all inherit the gate.  The network layer turns
        # this "Checkpoint violation..." return into an
        # OFFENSE_CHECKPOINT_VIOLATION against the offending peer; the
        # Blockchain itself is peer-agnostic so it just reports the fact.
        if self._trusted_checkpoints:
            bn = block.header.block_number
            expected = self._trusted_checkpoints.get(bn)
            if expected is not None and block.block_hash != expected:
                return False, (
                    f"Checkpoint violation at height {bn}: got "
                    f"{block.block_hash.hex()[:16]}... expected "
                    f"{expected.hex()[:16]}..."
                )

        if self.height == 0:
            # Validate genesis block structure
            if block.header.block_number != 0:
                # We have no chain yet but the gossiping peer is on the
                # real network producing blocks.  This is exactly what
                # joining validators see during IBD: the peer's current
                # tip arrives before we have block 0.  Store as orphan
                # (parent unknown) so node.py recognises it as a benign
                # "I'm behind" signal rather than invalid-block-ban.
                # IBD triggered elsewhere will fetch block 0 and drain
                # the orphan pool.
                if len(self.orphan_pool) < MAX_ORPHAN_BLOCKS:
                    self.orphan_pool[block.block_hash] = block
                return False, (
                    f"Orphan block — chain empty, received block "
                    f"{block.header.block_number}; need IBD to block 0"
                )
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
            # Synced-genesis reconstruction: if this is the mainnet
            # block 0 arriving via P2P (e.g., a fresh val-2 onboarding),
            # reproduce the founder's post-bootstrap state using the
            # canonical allocation constants so val-2's pre-block-1
            # state matches the founder's.  Without this, block 1's
            # state_root check rejects because val-2 has no founder
            # pubkey / stake / authority installed.
            is_mainnet_genesis = (
                pinned is not None
                and pinned == getattr(_cfg, "_MAINNET_GENESIS_HASH", None)
            )
            if is_mainnet_genesis:
                ok, reason = self._apply_mainnet_genesis_state(block)
                if not ok:
                    return False, reason
                return True, reason
            self.chain.append(block)
            self._block_by_hash[block.block_hash] = block
            self.fork_choice.add_tip(block.block_hash, 0, 0)
            if self.db is not None:
                self.db.store_block(block, state=self)
                self.db.add_chain_tip(block.block_hash, 0, 0)
            # Drain orphans waiting on block 0 — see _apply_mainnet_genesis_state.
            self._process_orphans(block.block_hash)
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
                    custody_proofs=getattr(block, "custody_proofs", []),
                    proposer_signature_leaf_index=proposer_sig_leaf,
                    censorship_evidence_txs=getattr(
                        block, "censorship_evidence_txs", [],
                    ),
                    bogus_rejection_evidence_txs=getattr(
                        block, "bogus_rejection_evidence_txs", [],
                    ),
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
        """Walk back from block to genesis, summing stake weights.

        Genesis is stored with cumulative weight 0 in the additive
        add_block path (see initialize_genesis's add_tip call), so this
        walk-based recomputation must stop at genesis WITHOUT adding
        its weight — otherwise forks computed via this path disagree
        with the canonical chain's stored cumulative weight and can
        trigger spurious equal-weight reorgs under the hash tiebreak.

        Each ancestor's weight must be computed against the stake map
        that was pinned at its height, not the live `supply.staked`
        dict.  After any stake change (stake tx, unstake, slash) the
        live dict diverges from the per-block state, so using it here
        makes the walk-back value disagree with the additive cumulative
        stored in fork_choice.tips — which under the lex-smaller-hash
        tiebreak can force a spurious reorg.
        """
        weight = 0
        current = block
        depth = 0
        while current and depth < MAX_REORG_DEPTH + 10:
            if current.header.prev_hash == b"\x00" * 32:
                break
            pinned = self._stake_snapshots.get(current.header.block_number)
            if pinned is None:
                # Snapshot unavailable (bootstrap edge, unapplied fork
                # block, or ancient pruned state) — fall back to live
                # stake.  Logged at debug because on a healthy chain
                # this only fires for the fork-head block itself.
                logger.debug(
                    "stake snapshot missing for block #%d — falling back "
                    "to live supply.staked for fork-weight calculation",
                    current.header.block_number,
                )
                stakes = self.supply.staked
            else:
                stakes = pinned
            weight += compute_block_stake_weight(current, stakes)
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
        # Cooldown tracking for KEY_ROTATION_COOLDOWN_BLOCKS enforcement
        # (iter 6 H2).  In-memory only; resets to empty on restart,
        # which is a deliberate trade-off: cheap, doesn't require a DB
        # schema change, and restart timing isn't attacker-controllable.
        self.key_rotation_last_height = {}
        # R6-A: key_history is in-memory state that replay rebuilds
        # via _record_key_history at every install / rotation site.
        self.key_history = {}
        self.public_keys = {}
        # slashed_validators is deliberately NOT cleared here — it is a
        # security ratchet, like revoked_entities and leaf_watermarks.
        # Once an equivocation is detected on any fork, the punishment
        # is permanent; clearing it would allow slash evasion via reorg.
        # _processed_evidence (also not cleared) stays consistent.
        self.reputation = {}
        self._immature_rewards = []
        # Archive-custody duty state (iteration 3b-ii).  All three
        # pieces rebuild deterministically from chain replay — miss
        # counters accumulate via _apply_archive_duty's epoch-close
        # walks; first-active blocks re-record on the first staked
        # observation; the open snapshot is freshly captured at the
        # next challenge block.  Clearing here mirrors every other
        # replay-deterministic in-memory field above.
        self.archive_active_snapshot = None
        self.validator_archive_misses = {}
        self.validator_first_active_block = {}
        # Reset first-divestment stake reference.  This is NOT a security
        # ratchet — it's the "stake at first observed divestment" anchor
        # used to measure drain debt.  On a reorg that rolls past the
        # first-divestment block, the anchor from the old fork is stale:
        # replay will re-capture the correct canonical-chain anchor via
        # the same first-write-wins logic that set it originally.  Not
        # clearing it leaves the joiner permanently reading an orphaned
        # reference and miscalculating debt.
        self.seed_initial_stakes = {}
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
        # Reset inactivity-leak stall counter.  Pair with the finality
        # tracker: reorg replay rebuilds finality from scratch, so the
        # "blocks since finality" counter must also restart from 0.
        # Leaving it stale lets replay stack a fresh leak window on top
        # of the old one — if finality stalls again after the merge,
        # honest validators take a SECOND quadratic inactivity-leak
        # penalty for the same outage.
        self.blocks_since_last_finalization = 0

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
            # Tree heights ride alongside public_keys: a reorg that
            # removes a first-spend pubkey install must also remove the
            # corresponding tree_height binding, otherwise a later
            # re-install (possibly with a different height) would be
            # blocked by a stale entry.  Set-once semantics only apply
            # within a single canonical chain history.
            "wots_tree_heights": dict(self.wots_tree_heights),
            "message_counts": dict(self.entity_message_count),
            "proposer_sig_counts": dict(self.proposer_sig_counts),
            "attestation_sig_counts": dict(self.attestation_sig_counts),
            "slash_sig_counts": dict(self.slash_sig_counts),
            "key_rotation_counts": dict(self.key_rotation_counts),
            # R6-A: key_history must roll back with the chain so slash
            # verification uses the historical key relative to the
            # canonical chain, not a rolled-back fork's history.
            "key_history": {
                eid: list(entries) for eid, entries in self.key_history.items()
            },
            # R6-B: Cooldown tracking (KEY_ROTATION_COOLDOWN_BLOCKS, iter 6 H2).
            # Snapshotted so a failed-reorg rollback restores the pre-reorg
            # cooldown state — otherwise the rollback would leave whatever
            # mid-reorg replay produced, silently letting the attacker
            # retry the rotation that tripped the rollback.  Paired with
            # the _apply_authority_tx update that rebuilds this map
            # during the successful-reorg replay path.
            "key_rotation_last_height": dict(self.key_rotation_last_height),
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
            # Treasury rebase (hard fork) — "already-applied" flag is
            # part of in-memory supply state.  A reorg that undoes the
            # rebase block MUST reset this flag so the canonical replay
            # re-fires the burn.  The accompanying balance/total_supply
            # rewind is already captured above.
            "treasury_rebase_applied": self.supply.treasury_rebase_applied,
            # Treasury per-epoch spend-rate cap bookkeeping — reorg
            # rollback restores the rolling-window state so a
            # cap-approved spend in the re-orged chain gets the same
            # epoch accounting on replay.
            "treasury_spend_epoch_start": (
                self.supply._treasury_spend_epoch_start
            ),
            "treasury_spend_debited_this_epoch": (
                self.supply._treasury_spend_debited_this_epoch
            ),
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
            # post-reorg stake value on replay.  Also persisted in the
            # state-snapshot blob and the snapshot-root commitment (see
            # messagechain/storage/state_snapshot.py) so state-synced
            # nodes inherit the same reference values.
            "seed_initial_stakes": dict(self.seed_initial_stakes),
            # Seed divestment fractional debt: reorg-safe rewind of the
            # per-seed fractional remainder.  Same consensus criticality
            # as seed_initial_stakes — a silent rewind of debt that does
            # not rewind stake would cause double-counted drains on
            # replay.
            "seed_divestment_debt": dict(self.seed_divestment_debt),
            # Reputation drives lottery winner selection (reputation_lottery.py)
            # which pays real rewards from inflation.  A reorg that advanced
            # reputation on a forked branch must roll it back, or two nodes
            # will disagree on later lottery winners -> different balance
            # state -> consensus fork.
            "reputation": dict(self.reputation),
            # Entity-index assignments are chain-local.  A reorged-out block
            # that registered a new entity must also roll back that
            # registration; otherwise _next_entity_index races ahead of what
            # the canonical chain reflects, and the next registered entity
            # lands at a different index than on peer nodes that never saw
            # the reorged block.  The compact wire form embeds these
            # indices, so divergence silently corrupts tx_hash agreement
            # for any tx that references the affected entities.
            "entity_id_to_index": dict(self.entity_id_to_index),
            "next_entity_index": self._next_entity_index,
            # Attestation-layer finality + escrow are also mutated by
            # _apply_block_state.  If a block passes structural validation
            # but its declared state_root disagrees with ours, add_block
            # rolls back via _restore_memory_snapshot — without these
            # fields the rollback leaves finality/escrow carrying
            # mutations from the rejected block.  deepcopy because both
            # carry nested dicts/sets.
            "finality": copy.deepcopy(self.finality),
            "escrow": copy.deepcopy(self._escrow),
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
        # Treasury rebase flag — default False so older snapshots
        # (pre-fork) restore cleanly with the rebase not yet applied.
        self.supply.treasury_rebase_applied = snapshot.get(
            "treasury_rebase_applied", False,
        )
        # Treasury spend-rate cap rolling window.  Defaults match the
        # __init__ sentinels so pre-fork snapshots restore to a
        # pristine cap state.
        self.supply._treasury_spend_epoch_start = snapshot.get(
            "treasury_spend_epoch_start", -1,
        )
        self.supply._treasury_spend_debited_this_epoch = snapshot.get(
            "treasury_spend_debited_this_epoch", 0,
        )
        self.base_fee = self.supply.base_fee
        self.nonces = snapshot["nonces"]
        self.public_keys = snapshot["public_keys"]
        # Tree heights are paired with public_keys in the snapshot so
        # a reorged-out first-spend install cleanly removes both.  Older
        # snapshots that predate this field restore to an empty dict,
        # which matches a freshly-initialized Blockchain.
        self.wots_tree_heights = dict(snapshot.get("wots_tree_heights", {}))
        self.entity_message_count = snapshot["message_counts"]
        self.proposer_sig_counts = snapshot.get("proposer_sig_counts", {})
        self.attestation_sig_counts = snapshot.get("attestation_sig_counts", {})
        self.slash_sig_counts = snapshot.get("slash_sig_counts", {})
        self.key_rotation_counts = snapshot.get("key_rotation_counts", {})
        self.key_history = {
            eid: list(entries)
            for eid, entries in snapshot.get("key_history", {}).items()
        }
        # Cooldown tracking for KEY_ROTATION_COOLDOWN_BLOCKS — default
        # to empty so pre-field snapshots restore to a pristine map
        # (matches a freshly-initialised Blockchain).  See the snapshot
        # comment for the reorg-rollback rationale (R6-B).
        self.key_rotation_last_height = dict(
            snapshot.get("key_rotation_last_height", {}),
        )
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
        self.seed_divestment_debt = dict(
            snapshot.get("seed_divestment_debt", {})
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
        # Reputation must roll back with the block state it was earned on.
        # See the snapshot comment above for the fork rationale.  Default
        # to empty so pre-field snapshots from older chain.db files still
        # round-trip.
        self.reputation = dict(snapshot.get("reputation", {}))
        # Entity-index registry is chain-local bookkeeping; a reorg that
        # removed the block that allocated an index must also reclaim
        # that slot.  Rebuild the reverse map from the restored forward
        # map so the two stay in sync.
        if "entity_id_to_index" in snapshot:
            self.entity_id_to_index = dict(snapshot["entity_id_to_index"])
            self.entity_index_to_id = {
                idx: eid for eid, idx in self.entity_id_to_index.items()
            }
            self._next_entity_index = int(snapshot.get(
                "next_entity_index", max(self.entity_id_to_index.values(), default=0) + 1,
            ))
        # Finality tracker + escrow carry same-block-only mutations that
        # must be reverted when the containing block's state_root fails
        # validation.  Default to fresh instances when absent (pre-field
        # snapshot), since that matches an uninitialised chain.
        if "finality" in snapshot:
            self.finality = copy.deepcopy(snapshot["finality"])
        if "escrow" in snapshot:
            self._escrow = copy.deepcopy(snapshot["escrow"])

    def get_wots_tree_height(self, entity_id: bytes) -> int | None:
        """Return the WOTS+ Merkle tree height recorded for `entity_id`.

        Returns None if the entity has never had its pubkey installed on
        chain.  The server uses this at startup to reconstruct the exact
        same keypair (same entity_id derivation) from the private key,
        rather than trusting `config.MERKLE_TREE_HEIGHT` — a mismatch
        between the height used at creation and the height used at
        restart would silently derive a different public key and make
        the node unable to sign for its own wallet.
        """
        return self.wots_tree_heights.get(entity_id)

    def _record_tree_height(self, entity_id: bytes, signature) -> None:
        """Record the WOTS+ tree_height derived from a signature's auth_path.

        Idempotent: once an entity has a tree_height recorded, this never
        overwrites.  The auth_path length is the canonical, signature-
        included commitment to tree height (a WOTS+ signature's Merkle
        authentication path has exactly `tree_height` siblings).

        Called from every pubkey-install site (genesis, first-spend
        Transfer / Stake, _install_pubkey_direct) so the height is
        captured at the same moment the entity becomes known on chain.
        """
        if entity_id in self.wots_tree_heights:
            return
        try:
            height = len(signature.auth_path)
        except AttributeError:
            return
        self.wots_tree_heights[entity_id] = height
        if self.db is not None and hasattr(self.db, "set_wots_tree_height"):
            self.db.set_wots_tree_height(entity_id, height)

    def _set_tree_height_explicit(self, entity_id: bytes, height: int) -> None:
        """Record a tree_height directly (used at genesis where the entity
        object is available and we take the authoritative value from
        its KeyPair rather than a signature's auth_path).
        """
        if entity_id in self.wots_tree_heights:
            return
        self.wots_tree_heights[entity_id] = int(height)
        if self.db is not None and hasattr(self.db, "set_wots_tree_height"):
            self.db.set_wots_tree_height(entity_id, int(height))

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
        # Liveness signal: `seconds_since_last_block` lets a cron'd
        # `messagechain status` page if the chain has stalled (e.g.,
        # BLOCK_TIME_TARGET * 3 without a new block = something is
        # wrong).  Computed from wall-clock NOW on the server; a big
        # clock-skewed client query will see a slightly-off number but
        # the sign (stalled vs advancing) is always correct.
        import time as _time
        latest_ts = (
            self.chain[-1].header.timestamp if self.chain else None
        )
        seconds_since_last = (
            int(_time.time() - latest_ts) if latest_ts is not None else None
        )
        return {
            "height": self.height,
            "latest_block_hash": self.chain[-1].block_hash.hex() if self.chain else None,
            # state_root of the tip — consumed by operators cutting a
            # weak-subjectivity checkpoint (see `messagechain cut-checkpoint`).
            # Already derivable from the chain, so no new information is
            # leaked; just saves the caller a full get_block round trip.
            "state_root": (
                self.chain[-1].header.state_root.hex() if self.chain else None
            ),
            "latest_block_timestamp": latest_ts,
            "seconds_since_last_block": seconds_since_last,
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
