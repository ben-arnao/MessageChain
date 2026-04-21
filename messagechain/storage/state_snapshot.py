"""
Deterministic serialization of full chain state for bootstrap-speed sync.

A new full node / validator joining the chain in year 100 cannot afford
to replay 100 years of history.  Instead, archive nodes publish a signed
*state snapshot* every STATE_CHECKPOINT_INTERVAL blocks: a deterministic
byte-blob representation of the complete chain state at block height X,
from which a new node can reconstruct the state without replaying
earlier blocks.  This module is the serialization/deserialization side
of that mechanism; the consensus-layer signatures that turn a snapshot
into a verified checkpoint live in messagechain/consensus/state_checkpoint.py.

**The chain itself remains permanent** — no pruning, no history deletion.
Archive nodes keep everything.  Snapshots exist purely to let new nodes
skip the replay cost of ancient history.

Design goals:

1. **Determinism**: same state → same bytes → same hash.  Every new-node
   bootstrap must produce the identical state-commitment that the rest
   of the network expects.  Achieved by:
     - sorted iteration on every bytes-keyed dict (no dict-iteration
       ordering leakage),
     - fixed big-endian integer widths (struct.pack(">...")),
     - a version byte leading the blob (future format upgrades via
       governance, without cross-version ambiguity).

2. **Stdlib only**: uses hashlib + struct + built-in types.  Nothing
   here should ever pull in a third-party dep.

3. **Bounded decoder**: the deserializer caps input size at
   MAX_STATE_SNAPSHOT_BYTES so a malicious peer cannot DoS a
   bootstrapping node with a multi-GB blob.

Snapshot contents — everything the blockchain carries in memory that a
fresh node needs to resume participation:

    - balances       entity_id → balance (integer tokens)
    - nonces         entity_id → next-expected nonce
    - staked         entity_id → active stake
    - public_keys    entity_id → 32-byte public key blob
    - authority_keys entity_id → cold/authority key (variable-length)
    - leaf_watermarks entity_id → next-safe WOTS+ leaf index
    - key_rotation_counts entity_id → how many rotations have happened
    - revoked_entities   set of entity_ids with emergency-revoked hot keys
    - slashed_validators set of entity_ids that have been slashed
    - entity_id_to_index bidirectional registry (for compact wire form)
    - treasury_balance   convenience — also inside balances but pulled out
    - total_supply       global inflation counter
    - total_minted       global minted count
    - total_fees_collected  global fee sink (for audit)
    - total_burned       global burned counter (EIP-1559 base-fee burn)
    - base_fee           current base fee
    - finalized_checkpoints  (block_number -> block_hash) finality records
    - seed_initial_stakes   seed_id → stake captured at first divestment
                            block (H = SEED_DIVESTMENT_START + 1).  Drives
                            the flat per-block divestment decrement for
                            the entire window.  MUST be in the snapshot
                            root: two state-synced nodes that disagree on
                            this dict fork silently at the next divestment
                            block because each recomputes per_block from
                            its own (post-divestment) stake reference.
    - seed_divestment_debt  seed_id → per-seed fractional remainder
                            (integer debt at SCALE = 10**9 per whole
                            token) for the partial-divestment-to-floor
                            schedule.  MUST be in the snapshot root for
                            the same reason as seed_initial_stakes: a
                            stale debt value produces a different whole-
                            token drain at the next divestment block.

The snapshot root (`compute_state_root`) is a Merkle tree over sorted
(section_tag, key, value_hash) entries, where each section_tag is a fixed
bytes prefix (b"bal", b"non", etc.).  Section tags prevent cross-section
hash collisions: a balance of value V for entity E cannot be confused
with a stake of value V for entity E.

Consensus note: this root is DISTINCT from the per-entity SparseMerkleTree
root that lives in BlockHeader.state_root.  The header's root covers
only per-entity fields (balances/nonces/stake/keys/rotations/revoke/slash).
The snapshot root covers those AND the global fields (treasury, supply,
base fee, finalized checkpoints).  The bootstrap flow:
    1. Verify checkpoint.state_root == compute_snapshot_root(snap)
    2. Install the snapshot
    3. After install, check that the per-entity portion agrees with
       checkpoint_block.header.state_root — this ties the snapshot to
       the chain's existing header-level commitment.
"""

import hashlib
import struct
from typing import Any

from messagechain.config import (
    HASH_ALGO,
    MAX_STATE_SNAPSHOT_BYTES as _MAX_DEFAULT,
    STATE_ROOT_VERSION as _STATE_ROOT_VERSION,
)

# Re-exported so callers don't need to import from both places.
# v2: added seed_divestment_debt (partial-divestment-to-floor schedule).
# v3: added archive_reward_pool (proof-of-custody archive rewards).  Single
#     scalar balance that participates in the snapshot root so bootstrapping
#     nodes see the same value as replaying nodes.
# v4: added censorship-evidence pending/processed maps +
#     receipt_subtree_roots (attestable-submission-receipts wiring).
#     Canonical section order for encode + root-hash: archive_reward_pool
#     (under _TAG_GLOBAL) first, then pending, processed, and receipt
#     subtree roots.
# v5: added bogus_rejection_processed (one-phase slashing for
#     SignedRejection — closes the receipt-less censorship gap).
#     Trails the v4 sections in the binary layout; pre-v5 snapshots
#     decode with an empty processed set under deserialize_state's
#     setdefault path.
STATE_SNAPSHOT_VERSION = 5  # wire format version for encode/decode
STATE_ROOT_VERSION = _STATE_ROOT_VERSION
MAX_STATE_SNAPSHOT_BYTES = _MAX_DEFAULT


# Section tags — deterministic prefixes used when hashing a (key, value)
# pair into the snapshot Merkle tree.  NEVER change or reorder these
# without bumping STATE_ROOT_VERSION: every validator computing a root
# depends on the same tag bytes.
_TAG_BALANCE = b"bal"
_TAG_NONCE = b"non"
_TAG_STAKE = b"stk"
_TAG_PUBKEY = b"pub"
_TAG_AUTHORITY = b"auth"
_TAG_LEAF_WATERMARK = b"lwm"
_TAG_ROTATION = b"rot"
_TAG_REVOKED = b"rev"
_TAG_SLASHED = b"slh"
_TAG_ENTITY_INDEX = b"eidx"
_TAG_FINALIZED = b"fin"
_TAG_GLOBAL = b"glb"
# seed_initial_stakes — consensus-visible dict[seed_id → initial_stake].
# Captured once per seed at the first divestment block and used as the
# denominator reference for the flat per-block unbond through END.  Not
# covered by any other section, so it needs its own tag — otherwise two
# state-synced nodes can silently disagree on the per-block divestment
# amount and fork at the next divestment block.
_TAG_SEED_INIT_STAKES = b"seed_init"
# seed_divestment_debt — consensus-visible dict[seed_id → scaled debt
# (fractional units)].  Per-seed running fractional remainder for the
# partial-divestment-to-floor schedule.  Must participate in the
# snapshot root: a state-synced node that installs with a stale debt
# value computes a different whole-token drain at its next divestment
# block than a replaying node.  Same consensus criticality as
# seed_initial_stakes.
_TAG_SEED_DIVEST_DEBT = b"seed_debt"
# Pending censorship-evidence keyed by evidence_hash; value hash
# covers (offender_id || tx_hash || admitted_height).  Pending set
# MUST live in the snapshot root so two state-synced nodes agree on
# which evidences are mid-maturity — otherwise one node would slash a
# validator the other doesn't, and consensus forks silently.
_TAG_CENSORSHIP_PENDING = b"cpend"
# Processed censorship-evidence set: every evidence_hash that has
# ever been matured OR voided.  Participates in the root so a
# cold-booted node inherits the full dedupe set and a re-submission of
# an already-used evidence is rejected identically on every node.
_TAG_CENSORSHIP_PROCESSED = b"cproc"
# Per-validator receipt-subtree root public keys.  Used by
# validate_censorship_evidence_tx to cross-check that a receipt was
# signed with the issuer's currently-registered subtree root.  Must
# participate in the state root because two nodes that disagreed on
# an issuer's root would accept/reject the same evidence differently.
_TAG_RECEIPT_ROOT = b"rrk"
# Processed bogus-rejection-evidence set: every evidence_hash that has
# ever been applied (slashed OR admitted-no-slash).  One-phase, no
# pending counterpart — bogusness is decided at apply-time so there
# is nothing to age in.  Participates in the snapshot root for the
# same dedupe-determinism reason as _TAG_CENSORSHIP_PROCESSED.
_TAG_BOGUS_REJECTION_PROCESSED = b"brproc"

# Global-field keys — stable strings under _TAG_GLOBAL.
_GLOBAL_TOTAL_SUPPLY = b"total_supply"
_GLOBAL_TOTAL_MINTED = b"total_minted"
_GLOBAL_TOTAL_FEES = b"total_fees_collected"
_GLOBAL_TOTAL_BURNED = b"total_burned"
_GLOBAL_BASE_FEE = b"base_fee"
_GLOBAL_NEXT_ENTITY_INDEX = b"next_entity_index"
# Proof-of-custody archive reward pool balance.  See
# docs/proof-of-custody-archive-rewards.md and
# messagechain/consensus/archive_challenge.py.  Single scalar; lives
# under _TAG_GLOBAL so it shares the root-commitment path with other
# supply-level counters.  MUST participate in the snapshot root for
# consensus reasons: two state-synced nodes that disagree on the pool
# balance silently fork at the next challenge block (different payout
# amounts flow into different balances).
_GLOBAL_ARCHIVE_REWARD_POOL = b"archive_reward_pool"


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def serialize_state(blockchain) -> dict:
    """Extract the full chain-state dict from a live Blockchain.

    Returns a plain-Python dict (no references to the live chain) so the
    result is safe to cache, hash, transmit, and re-install.  Does NOT
    allocate the binary blob — call encode_snapshot for that.
    """
    # Copy by value so downstream mutation cannot leak back into the chain.
    return {
        "version": STATE_SNAPSHOT_VERSION,
        "balances": dict(blockchain.supply.balances),
        "nonces": dict(blockchain.nonces),
        "staked": dict(blockchain.supply.staked),
        "public_keys": dict(blockchain.public_keys),
        "authority_keys": dict(blockchain.authority_keys),
        "leaf_watermarks": dict(blockchain.leaf_watermarks),
        "key_rotation_counts": dict(blockchain.key_rotation_counts),
        "revoked_entities": set(blockchain.revoked_entities),
        "slashed_validators": set(blockchain.slashed_validators),
        "entity_id_to_index": dict(blockchain.entity_id_to_index),
        "next_entity_index": blockchain._next_entity_index,
        "total_supply": blockchain.supply.total_supply,
        "total_minted": blockchain.supply.total_minted,
        "total_fees_collected": blockchain.supply.total_fees_collected,
        "total_burned": getattr(blockchain.supply, "total_burned", 0),
        "base_fee": blockchain.supply.base_fee,
        "finalized_checkpoints": dict(
            blockchain.finalized_checkpoints.finalized_by_height
        ),
        # Seed divestment reference — see _TAG_SEED_INIT_STAKES docstring.
        "seed_initial_stakes": dict(
            getattr(blockchain, "seed_initial_stakes", {})
        ),
        # Seed divestment fractional debt — see _TAG_SEED_DIVEST_DEBT
        # docstring.  Per-seed running fractional remainder driving the
        # partial-divestment-to-floor schedule; must participate in the
        # snapshot root for state-sync parity with replaying nodes.
        "seed_divestment_debt": dict(
            getattr(blockchain, "seed_divestment_debt", {})
        ),
        # Archive reward pool — proof-of-custody rewards scalar.
        # See messagechain/consensus/archive_challenge.py.  Exposed as
        # a plain scalar int; absence defaults to 0 (fresh chain or
        # pre-archive-rewards replay).
        "archive_reward_pool": int(
            getattr(blockchain, "archive_reward_pool", 0)
        ),
        # Censorship-evidence processor state.  `pending` maps
        # evidence_hash -> (offender_id, tx_hash, admitted_height,
        # evidence_tx_hash) serialized into a single flat bytes
        # value for snapshot-root hashing; `processed` is the set of
        # evidence_hashes already matured/voided.  See
        # consensus.censorship_evidence.CensorshipEvidenceProcessor.
        "censorship_pending": _pending_to_bytes_dict(
            getattr(blockchain, "censorship_processor", None),
        ),
        "censorship_processed": _processor_processed(
            getattr(blockchain, "censorship_processor", None),
        ),
        # Receipt-subtree roots.  entity_id -> 32-byte root pubkey.
        "receipt_subtree_roots": dict(
            getattr(blockchain, "receipt_subtree_roots", {})
        ),
        # Bogus-rejection processor — set of evidence_hashes that have
        # ever been applied (slashed OR admitted-no-slash).  No pending
        # counterpart: bogusness is decided immediately at apply-time.
        "bogus_rejection_processed": _bogus_rejection_processed(
            getattr(blockchain, "bogus_rejection_processor", None),
        ),
    }


def _bogus_rejection_processed(processor) -> set:
    if processor is None:
        return set()
    return set(processor.processed)


def _pending_to_bytes_dict(processor) -> dict:
    """Serialize processor.pending into a bytes-keyed, bytes-valued
    dict suitable for the standard section encoder.  Value layout:
        32 offender_id || 32 tx_hash || u64 admitted_height ||
        32 evidence_tx_hash
    """
    out: dict[bytes, bytes] = {}
    if processor is None:
        return out
    for ev_hash, entry in processor.pending.items():
        payload = (
            entry.offender_id
            + entry.tx_hash
            + struct.pack(">Q", int(entry.admitted_height))
            + entry.evidence_tx_hash
        )
        out[ev_hash] = payload
    return out


def _processor_processed(processor) -> set:
    if processor is None:
        return set()
    return set(processor.processed)


def _bytes_dict_to_pending(d: dict):
    """Inverse of _pending_to_bytes_dict.  Returns an iterable of
    (evidence_hash, offender_id, tx_hash, admitted_height,
    evidence_tx_hash) tuples.  Raises ValueError on a malformed entry.
    """
    out = []
    for ev_hash, payload in d.items():
        if len(payload) != 32 + 32 + 8 + 32:
            raise ValueError(
                f"pending censorship entry has wrong length: "
                f"{len(payload)} (expected 104)"
            )
        offender_id = payload[0:32]
        tx_hash = payload[32:64]
        admitted_height = struct.unpack_from(">Q", payload, 64)[0]
        evidence_tx_hash = payload[72:104]
        out.append((ev_hash, offender_id, tx_hash, admitted_height, evidence_tx_hash))
    return out


def deserialize_state(snapshot: dict) -> dict:
    """Validate a snapshot dict and return a sanitized copy.

    This is mostly a type-normalizer: any ints that arrive as-str (e.g.,
    from a JSON round-trip) get coerced back, and keys that arrived as
    hex strings get coerced back to bytes.  Accepts both in-memory dicts
    (already correctly typed) and blob-decoded dicts.
    """
    if not isinstance(snapshot, dict):
        raise ValueError("state snapshot must be a dict")
    version = snapshot.get("version", STATE_SNAPSHOT_VERSION)
    # Accept any version from 1..STATE_SNAPSHOT_VERSION — older
    # in-memory dicts default their missing sections via setdefault
    # below, and binary decode has its own strict version check in
    # decode_snapshot.  This lets test helpers that hand-build v2
    # snapshot dicts continue to work after a wire-format bump.
    if not isinstance(version, int) or version < 1 or version > STATE_SNAPSHOT_VERSION:
        raise ValueError(
            f"Unsupported snapshot version {version} "
            f"(current = {STATE_SNAPSHOT_VERSION})"
        )
    # We accept the dict as-is here — the canonical source is encode/decode.
    out = dict(snapshot)
    out.setdefault("balances", {})
    out.setdefault("nonces", {})
    out.setdefault("staked", {})
    out.setdefault("public_keys", {})
    out.setdefault("authority_keys", {})
    out.setdefault("leaf_watermarks", {})
    out.setdefault("key_rotation_counts", {})
    out.setdefault("revoked_entities", set())
    out.setdefault("slashed_validators", set())
    out.setdefault("entity_id_to_index", {})
    out.setdefault("next_entity_index", 1)
    out.setdefault("total_supply", 0)
    out.setdefault("total_minted", 0)
    out.setdefault("total_fees_collected", 0)
    out.setdefault("total_burned", 0)
    out.setdefault("base_fee", 0)
    out.setdefault("finalized_checkpoints", {})
    # Default to empty dict for pre-divestment snapshots and for any
    # legacy in-memory dict that predates the field.  Binary decode
    # always populates this, so the default only matters for callers
    # that hand-build snapshot dicts.
    out.setdefault("seed_initial_stakes", {})
    # Default to empty dict for pre-v2 snapshots (wire format prior to
    # seed_divestment_debt).  A migrating chain starts debt-free — see
    # Blockchain.seed_divestment_debt init comment for the one-block
    # timing note on migration.
    out.setdefault("seed_divestment_debt", {})
    # Default to 0 for pre-archive-rewards snapshots (archive reward
    # pool was not present).  A fresh chain starts with an empty pool;
    # the first funded block credits it from the redirected burn.
    out.setdefault("archive_reward_pool", 0)
    # Pre-v4 snapshots lack the censorship-evidence sections.  A
    # migrating chain starts with empty pending/processed/roots —
    # acceptable since censorship-evidence wiring was introduced
    # specifically at this wire-version bump.
    out.setdefault("censorship_pending", {})
    out.setdefault("censorship_processed", set())
    out.setdefault("receipt_subtree_roots", {})
    # Pre-v5 snapshots lack the bogus-rejection processed set.  A
    # migrating chain starts with an empty processed set — acceptable
    # because the slashing path was introduced specifically at this
    # wire-version bump and no historical block carries
    # BogusRejectionEvidenceTx that needs deduping.
    out.setdefault("bogus_rejection_processed", set())
    return out


# ── Merkle root computation ──────────────────────────────────────────

def _entries_for_section(tag: bytes, items) -> list[bytes]:
    """Build sorted (tag || key || value_hash) leaves for a section."""
    leaves: list[bytes] = []
    if isinstance(items, dict):
        for key in sorted(items.keys()):
            val = items[key]
            leaves.append(_h(tag + _encode_key(key) + _encode_val(val)))
    elif isinstance(items, (set, frozenset)):
        for key in sorted(items):
            # Set membership encoded with an empty value (presence alone).
            leaves.append(_h(tag + _encode_key(key) + b""))
    else:
        raise TypeError(f"Unsupported section type: {type(items).__name__}")
    return leaves


def _encode_key(key) -> bytes:
    if isinstance(key, bytes):
        return struct.pack(">I", len(key)) + key
    if isinstance(key, int):
        # 8-byte big-endian for int-keyed dicts (e.g., finalized_by_height)
        return struct.pack(">Q", key)
    raise TypeError(f"Unsupported key type: {type(key).__name__}")


def _encode_val(val) -> bytes:
    if isinstance(val, bytes):
        return struct.pack(">I", len(val)) + val
    if isinstance(val, bool):
        # bool is-a int in Python; split first.
        return b"\x01" if val else b"\x00"
    if isinstance(val, int):
        # Q accommodates supply-level quantities; larger ints would signal
        # a bug and should surface as OverflowError from struct.
        return struct.pack(">Q", val)
    raise TypeError(f"Unsupported value type: {type(val).__name__}")


def _merkle(leaves: list[bytes]) -> bytes:
    """Deterministic Merkle root with tagged nodes (domain-separation).

    - 0x00 prefix on leaves
    - 0x01 prefix on internal nodes
    - odd layers padded with a fixed sentinel hash (NOT duplicated last
      element, to prevent CVE-2012-2459-style second-preimage attacks)
    """
    if not leaves:
        return _h(b"empty_snapshot_section")
    layer = [_h(b"\x00" + leaf) for leaf in leaves]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(_h(b"\x02" + b"snapshot_sentinel"))
        layer = [
            _h(b"\x01" + layer[i] + layer[i + 1])
            for i in range(0, len(layer), 2)
        ]
    return layer[0]


def compute_state_root(snapshot: dict) -> bytes:
    """Canonical state-root commitment over a snapshot dict.

    Deterministic: same dict → same 32-byte root.  Structure is a
    two-level Merkle tree: per-section leaves → section roots → overall
    root.  The section-root layer uses a fixed ORDER of tags (sorted by
    tag bytes) so a new tag inserted in a future version must be
    appended via STATE_ROOT_VERSION bump.
    """
    snap = deserialize_state(snapshot)

    section_roots: dict[bytes, bytes] = {
        _TAG_BALANCE: _merkle(_entries_for_section(
            _TAG_BALANCE, snap["balances"])),
        _TAG_NONCE: _merkle(_entries_for_section(
            _TAG_NONCE, snap["nonces"])),
        _TAG_STAKE: _merkle(_entries_for_section(
            _TAG_STAKE, snap["staked"])),
        _TAG_PUBKEY: _merkle(_entries_for_section(
            _TAG_PUBKEY, snap["public_keys"])),
        _TAG_AUTHORITY: _merkle(_entries_for_section(
            _TAG_AUTHORITY, snap["authority_keys"])),
        _TAG_LEAF_WATERMARK: _merkle(_entries_for_section(
            _TAG_LEAF_WATERMARK, snap["leaf_watermarks"])),
        _TAG_ROTATION: _merkle(_entries_for_section(
            _TAG_ROTATION, snap["key_rotation_counts"])),
        _TAG_REVOKED: _merkle(_entries_for_section(
            _TAG_REVOKED, snap["revoked_entities"])),
        _TAG_SLASHED: _merkle(_entries_for_section(
            _TAG_SLASHED, snap["slashed_validators"])),
        _TAG_ENTITY_INDEX: _merkle(_entries_for_section(
            _TAG_ENTITY_INDEX, {
                eid: idx for eid, idx in snap["entity_id_to_index"].items()
            })),
        _TAG_FINALIZED: _merkle(_entries_for_section(
            _TAG_FINALIZED, snap["finalized_checkpoints"])),
        # Seed divestment reference dict.  MUST participate in the
        # snapshot root: two state-synced nodes that agreed on every
        # other section but disagreed on seed_initial_stakes would
        # silently fork at the next divestment block because the
        # per-block decrement is `initial_stake / WINDOW`, computed
        # from this exact dict.
        _TAG_SEED_INIT_STAKES: _merkle(_entries_for_section(
            _TAG_SEED_INIT_STAKES, snap["seed_initial_stakes"])),
        # Seed divestment fractional debt.  Same consensus criticality
        # as _TAG_SEED_INIT_STAKES: a node that disagreed on this dict
        # would compute a different whole-token drain at the next
        # divestment block and silently fork until END.
        _TAG_SEED_DIVEST_DEBT: _merkle(_entries_for_section(
            _TAG_SEED_DIVEST_DEBT, snap["seed_divestment_debt"])),
        # Pending censorship-evidence.  Values are variable-length
        # bytes blobs encoding (offender_id || tx_hash || admitted_height
        # || evidence_tx_hash) — see _pending_to_bytes_dict.  Every
        # node computing the state root must agree bit-for-bit on this
        # section or a mature() call would slash on one node but not
        # another.
        _TAG_CENSORSHIP_PENDING: _merkle(_entries_for_section(
            _TAG_CENSORSHIP_PENDING, snap["censorship_pending"])),
        # Processed censorship-evidence set — the double-slash defense.
        _TAG_CENSORSHIP_PROCESSED: _merkle(_entries_for_section(
            _TAG_CENSORSHIP_PROCESSED, snap["censorship_processed"])),
        # Receipt-subtree roots.  Per-validator 32-byte pubkeys that
        # identify the subtree used for receipt signatures.  The
        # validate_censorship_evidence_tx path checks a candidate
        # receipt's embedded root against this dict — any disagreement
        # here forks on admission.
        _TAG_RECEIPT_ROOT: _merkle(_entries_for_section(
            _TAG_RECEIPT_ROOT, snap["receipt_subtree_roots"])),
        # Bogus-rejection processed set — the double-slash defense.
        # One section, no pending counterpart (apply-time decision).
        _TAG_BOGUS_REJECTION_PROCESSED: _merkle(_entries_for_section(
            _TAG_BOGUS_REJECTION_PROCESSED,
            snap["bogus_rejection_processed"])),
        _TAG_GLOBAL: _merkle(_entries_for_section(
            _TAG_GLOBAL, {
                _GLOBAL_TOTAL_SUPPLY: snap["total_supply"],
                _GLOBAL_TOTAL_MINTED: snap["total_minted"],
                _GLOBAL_TOTAL_FEES: snap["total_fees_collected"],
                _GLOBAL_TOTAL_BURNED: snap["total_burned"],
                _GLOBAL_BASE_FEE: snap["base_fee"],
                _GLOBAL_NEXT_ENTITY_INDEX: snap["next_entity_index"],
                # v3: archive reward pool balance participates in the
                # root so bootstrapping nodes see the same scalar as
                # replaying nodes.  A bootstrapper that inherits a
                # stale pool would compute different payout amounts at
                # the next challenge block and silently fork.
                _GLOBAL_ARCHIVE_REWARD_POOL: snap["archive_reward_pool"],
            })),
    }

    # Top-level: deterministic tag order + version byte + section roots.
    top_leaves = [
        _h(tag + section_roots[tag]) for tag in sorted(section_roots.keys())
    ]
    root = _merkle(top_leaves)
    # Bind the state-root version so an implementation upgrade cannot
    # produce a colliding root across schemes.
    return _h(
        b"state_snapshot_root_v"
        + struct.pack(">B", STATE_ROOT_VERSION)
        + root
    )


# ── Binary encode / decode ───────────────────────────────────────────

def _encode_bytes_int_dict(d: dict) -> bytes:
    out = bytearray()
    out += struct.pack(">I", len(d))
    for key in sorted(d.keys()):
        assert isinstance(key, bytes), f"expected bytes key, got {type(key)}"
        out += struct.pack(">I", len(key)) + key
        out += struct.pack(">Q", int(d[key]))
    return bytes(out)


def _decode_bytes_int_dict(blob: bytes, off: int) -> tuple[dict, int]:
    (n,) = struct.unpack_from(">I", blob, off)
    off += 4
    out: dict[bytes, int] = {}
    for _ in range(n):
        (klen,) = struct.unpack_from(">I", blob, off)
        off += 4
        key = bytes(blob[off:off + klen])
        off += klen
        (val,) = struct.unpack_from(">Q", blob, off)
        off += 8
        out[key] = val
    return out, off


def _encode_bytes_bytes_dict(d: dict) -> bytes:
    out = bytearray()
    out += struct.pack(">I", len(d))
    for key in sorted(d.keys()):
        assert isinstance(key, bytes)
        val = d[key]
        if not isinstance(val, (bytes, bytearray)):
            raise TypeError(f"expected bytes value, got {type(val).__name__}")
        out += struct.pack(">I", len(key)) + key
        out += struct.pack(">I", len(val)) + bytes(val)
    return bytes(out)


def _decode_bytes_bytes_dict(blob: bytes, off: int) -> tuple[dict, int]:
    (n,) = struct.unpack_from(">I", blob, off)
    off += 4
    out: dict[bytes, bytes] = {}
    for _ in range(n):
        (klen,) = struct.unpack_from(">I", blob, off)
        off += 4
        key = bytes(blob[off:off + klen])
        off += klen
        (vlen,) = struct.unpack_from(">I", blob, off)
        off += 4
        val = bytes(blob[off:off + vlen])
        off += vlen
        out[key] = val
    return out, off


def _encode_bytes_set(s) -> bytes:
    out = bytearray()
    out += struct.pack(">I", len(s))
    for key in sorted(s):
        assert isinstance(key, bytes)
        out += struct.pack(">I", len(key)) + key
    return bytes(out)


def _decode_bytes_set(blob: bytes, off: int) -> tuple[set, int]:
    (n,) = struct.unpack_from(">I", blob, off)
    off += 4
    out: set = set()
    for _ in range(n):
        (klen,) = struct.unpack_from(">I", blob, off)
        off += 4
        key = bytes(blob[off:off + klen])
        off += klen
        out.add(key)
    return out, off


def _encode_int_bytes_dict(d: dict) -> bytes:
    out = bytearray()
    out += struct.pack(">I", len(d))
    for key in sorted(d.keys()):
        assert isinstance(key, int)
        val = d[key]
        out += struct.pack(">Q", key)
        out += struct.pack(">I", len(val)) + val
    return bytes(out)


def _decode_int_bytes_dict(blob: bytes, off: int) -> tuple[dict, int]:
    (n,) = struct.unpack_from(">I", blob, off)
    off += 4
    out: dict[int, bytes] = {}
    for _ in range(n):
        (key,) = struct.unpack_from(">Q", blob, off)
        off += 8
        (vlen,) = struct.unpack_from(">I", blob, off)
        off += 4
        val = bytes(blob[off:off + vlen])
        off += vlen
        out[key] = val
    return out, off


def encode_snapshot(snap: dict) -> bytes:
    """Deterministic binary encoding of a snapshot dict.

    Wire format (every integer is big-endian; lengths are u32; values in
    the int-keyed sections use u64; version is u8):

        u8  version
        <bytes→int  dict>   balances
        <bytes→int  dict>   nonces
        <bytes→int  dict>   staked
        <bytes→bytes dict>  public_keys
        <bytes→bytes dict>  authority_keys
        <bytes→int  dict>   leaf_watermarks
        <bytes→int  dict>   key_rotation_counts
        <bytes set>         revoked_entities
        <bytes set>         slashed_validators
        <bytes→int  dict>   entity_id_to_index
        u64                 next_entity_index
        u64                 total_supply
        u64                 total_minted
        u64                 total_fees_collected
        u64                 total_burned
        u64                 base_fee
        <int→bytes dict>    finalized_checkpoints
        <bytes→int  dict>   seed_initial_stakes
        <bytes→int  dict>   seed_divestment_debt   (v2+)
        u64                 archive_reward_pool    (v3+)
        <bytes→bytes dict>  censorship_pending     (v4+)
        <bytes set>         censorship_processed   (v4+)
        <bytes→bytes dict>  receipt_subtree_roots  (v4+)
        <bytes set>         bogus_rejection_processed (v5+)
    """
    snap = deserialize_state(snap)
    out = bytearray()
    out += struct.pack(">B", STATE_SNAPSHOT_VERSION)
    out += _encode_bytes_int_dict(snap["balances"])
    out += _encode_bytes_int_dict(snap["nonces"])
    out += _encode_bytes_int_dict(snap["staked"])
    out += _encode_bytes_bytes_dict(snap["public_keys"])
    out += _encode_bytes_bytes_dict(snap["authority_keys"])
    out += _encode_bytes_int_dict(snap["leaf_watermarks"])
    out += _encode_bytes_int_dict(snap["key_rotation_counts"])
    out += _encode_bytes_set(snap["revoked_entities"])
    out += _encode_bytes_set(snap["slashed_validators"])
    out += _encode_bytes_int_dict(snap["entity_id_to_index"])
    out += struct.pack(">Q", int(snap["next_entity_index"]))
    out += struct.pack(">Q", int(snap["total_supply"]))
    out += struct.pack(">Q", int(snap["total_minted"]))
    out += struct.pack(">Q", int(snap["total_fees_collected"]))
    out += struct.pack(">Q", int(snap["total_burned"]))
    out += struct.pack(">Q", int(snap["base_fee"]))
    out += _encode_int_bytes_dict(snap["finalized_checkpoints"])
    # Seed divestment reference — bytes→int dict, sorted keys, matches
    # the canonical encoding used elsewhere for entity-keyed int dicts.
    out += _encode_bytes_int_dict(snap["seed_initial_stakes"])
    # Seed divestment fractional debt — bytes→int dict with scaled
    # fractional units (SCALE = 10**9 per whole token).  Debt is
    # always < 2 * SCALE at block boundaries (each block adds a small
    # fraction; drain removes whole tokens), so u64 is ample.
    out += _encode_bytes_int_dict(snap["seed_divestment_debt"])
    # v3: archive reward pool balance (proof-of-custody archive rewards).
    # Bounded above by total_supply, so u64 is ample.
    out += struct.pack(">Q", int(snap["archive_reward_pool"]))
    # v4: censorship-evidence + receipt-subtree sections.  Canonical
    # order (matches compute_state_root and decode_snapshot): pending,
    # processed, then receipt_subtree_roots — appended AFTER the v3
    # archive_reward_pool u64 so a v3 blob remains a prefix of a v4
    # blob up to the end of v3's final field.  (Version byte still
    # bumps, so decode cannot confuse the two — this invariant is
    # purely for the reader's mental model.)
    out += _encode_bytes_bytes_dict(snap["censorship_pending"])
    out += _encode_bytes_set(snap["censorship_processed"])
    out += _encode_bytes_bytes_dict(snap["receipt_subtree_roots"])
    # v5: bogus-rejection processed set, trailing the v4 sections.  No
    # pending counterpart — apply-time decision.
    out += _encode_bytes_set(snap["bogus_rejection_processed"])
    return bytes(out)


def decode_snapshot(blob: bytes, max_bytes: int | None = None) -> dict:
    """Deterministic binary decoder with size cap.

    Raises ValueError for:
      * blob size > max_bytes (default MAX_STATE_SNAPSHOT_BYTES)
      * unknown version byte
      * truncated / trailing-bytes input
    """
    cap = max_bytes if max_bytes is not None else MAX_STATE_SNAPSHOT_BYTES
    if len(blob) > cap:
        raise ValueError(
            f"snapshot blob too large: {len(blob)} bytes > cap {cap}"
        )
    if len(blob) < 1:
        raise ValueError("snapshot blob too short")
    version = blob[0]
    if version != STATE_SNAPSHOT_VERSION:
        raise ValueError(
            f"Unsupported snapshot version {version} "
            f"(current = {STATE_SNAPSHOT_VERSION})"
        )
    off = 1
    balances, off = _decode_bytes_int_dict(blob, off)
    nonces, off = _decode_bytes_int_dict(blob, off)
    staked, off = _decode_bytes_int_dict(blob, off)
    public_keys, off = _decode_bytes_bytes_dict(blob, off)
    authority_keys, off = _decode_bytes_bytes_dict(blob, off)
    leaf_watermarks, off = _decode_bytes_int_dict(blob, off)
    key_rotation_counts, off = _decode_bytes_int_dict(blob, off)
    revoked_entities, off = _decode_bytes_set(blob, off)
    slashed_validators, off = _decode_bytes_set(blob, off)
    entity_id_to_index, off = _decode_bytes_int_dict(blob, off)
    (next_entity_index,) = struct.unpack_from(">Q", blob, off)
    off += 8
    (total_supply,) = struct.unpack_from(">Q", blob, off)
    off += 8
    (total_minted,) = struct.unpack_from(">Q", blob, off)
    off += 8
    (total_fees_collected,) = struct.unpack_from(">Q", blob, off)
    off += 8
    (total_burned,) = struct.unpack_from(">Q", blob, off)
    off += 8
    (base_fee,) = struct.unpack_from(">Q", blob, off)
    off += 8
    finalized_checkpoints, off = _decode_int_bytes_dict(blob, off)
    seed_initial_stakes, off = _decode_bytes_int_dict(blob, off)
    # v2+: seed_divestment_debt.  Always present on v2+ blobs.
    seed_divestment_debt, off = _decode_bytes_int_dict(blob, off)
    # v3+: archive_reward_pool (single scalar, u64).  Always present on
    # v3+ blobs; decode strictly — absent byte means truncated input.
    (archive_reward_pool,) = struct.unpack_from(">Q", blob, off)
    off += 8
    # v4+: censorship-evidence + receipt-subtree roots, in canonical
    # order: pending, processed, receipt_subtree_roots.  Must match
    # encode_snapshot's ordering exactly.
    censorship_pending, off = _decode_bytes_bytes_dict(blob, off)
    censorship_processed, off = _decode_bytes_set(blob, off)
    receipt_subtree_roots, off = _decode_bytes_bytes_dict(blob, off)
    # v5+: bogus-rejection processed set.  Always present on v5+ blobs.
    bogus_rejection_processed, off = _decode_bytes_set(blob, off)
    if off != len(blob):
        raise ValueError(
            f"snapshot blob has trailing bytes "
            f"(consumed {off}, total {len(blob)})"
        )
    return {
        "version": STATE_SNAPSHOT_VERSION,
        "balances": balances,
        "nonces": nonces,
        "staked": staked,
        "public_keys": public_keys,
        "authority_keys": authority_keys,
        "leaf_watermarks": leaf_watermarks,
        "key_rotation_counts": key_rotation_counts,
        "revoked_entities": revoked_entities,
        "slashed_validators": slashed_validators,
        "entity_id_to_index": entity_id_to_index,
        "next_entity_index": next_entity_index,
        "total_supply": total_supply,
        "total_minted": total_minted,
        "total_fees_collected": total_fees_collected,
        "total_burned": total_burned,
        "base_fee": base_fee,
        "finalized_checkpoints": finalized_checkpoints,
        "seed_initial_stakes": seed_initial_stakes,
        "seed_divestment_debt": seed_divestment_debt,
        "archive_reward_pool": archive_reward_pool,
        "censorship_pending": censorship_pending,
        "censorship_processed": censorship_processed,
        "receipt_subtree_roots": receipt_subtree_roots,
        "bogus_rejection_processed": bogus_rejection_processed,
    }
