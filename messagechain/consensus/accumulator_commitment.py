"""Phase 3 accumulator commitment — consensus-enforced determinism for
in-memory accumulators that aren't in the entity SMT.

Background: ``compute_current_state_root`` historically committed
only to the entity SMT (balances/staked/nonces/etc.) plus the
reaction_state contribution post-REACT_TX_HEIGHT.  Every OTHER
in-memory accumulator (per-validator counters, reward queues,
activation flags, supply scalars, …) was OUTSIDE state_root, so two
nodes could silently drift on those accumulators without consensus
catching it.  Drift surfaced only when an accumulator value fed into
a future block's apply path and changed an SMT input.

Phase 3 closes that surface: at and after
``ACCUMULATOR_COMMITMENT_HEIGHT`` the canonical state root mixes in
a deterministic hash of every consensus-affecting accumulator the
chain currently tracks.  Any node whose accumulators diverge from
peers computes a different state root, every subsequent block fails
validation, and the chain stops -- which is precisely the
"drift breaks consensus immediately" property we want.

The hard fork is one-way: pre-activation blocks commit only to the
entity SMT (preserves historical block round-trips); post-activation
blocks commit to entity SMT + accumulator commitment.  The activation
gate is structurally identical to the REACT_TX_HEIGHT gate already in
``compute_current_state_root``.

# Scope of the commitment

The commitment covers the SIMPLE-typed accumulators that drift
silently today.  Custom objects (``EscrowLedger``, ``FinalityTracker``,
``RatchetState``, ``ReactionState``) and floats (``bootstrap_ratchet
_max``) are deliberately EXCLUDED from the first cut -- their
canonical serialization is harder (custom encoders required; floats
are bit-flaky across CPU FPUs).  A future hard fork can extend the
commitment to cover them once their canonical forms are defined.

What's in:

* Activation flags (booleans): treasury_rebase_applied,
  supply_reconciliation_applied, supply_reconciliation_fix_applied,
  grandfather_applied, treasury_rebase_applied,
  rolling_fee_burn_seeded, dormancy_backfill_applied,
  supply_reconciliation_v3_applied (if present), …
* Supply scalars (ints): total_supply, total_minted,
  total_fees_collected, total_burned, base_fee, lottery_prize_pool,
  attester_epoch_earnings_start, _treasury_spend_epoch_start,
  _treasury_spend_debited_this_epoch, blocks_since_last_finalization,
  next_entity_index, …
* Per-validator counters (dict[bytes, int]):
  attestation_sig_counts, proposer_sig_counts, slash_sig_counts,
  slash_offense_counts, reputation, validator_archive_misses,
  validator_first_active_block, validator_archive_success_streak,
  attester_coverage_misses, key_rotation_counts,
  key_rotation_last_height, attester_epoch_earnings,
  seed_initial_stakes, seed_divestment_debt, wots_tree_heights,
  message_counts, entity_id_to_index, …
* Set: registered_validators
* Receipt-subtree roots: dict[bytes, bytes] +
  past_receipt_subtree_roots dict[bytes, set[bytes]]
* Lists: rolling_fee_burn (list[tuple[int, int]]),
  immature_rewards (list of tuples)
* Key history: dict[bytes, list[tuple[int, bytes]]]

What's out (future hard fork):

* bootstrap_ratchet_max (float)
* escrow (custom EscrowLedger object)
* finality (custom FinalityTracker object)
* reaction_state (custom ReactionState object — already in
  entity_root post-REACT_TX_HEIGHT via state_root_contribution; not
  doubly committed here)
* processed_evidence (set of variable-shape evidence hashes — needs
  canonical evidence-hash spec)
* pending_unstakes (dict[bytes, list of complex objects])

# Canonical encoding

Simple recursive encoder.  Each type gets a 1-byte type tag, then
its bytes:

  0x00  None
  0x01  False
  0x02  True
  0x03  int (8-byte signed big-endian)
  0x05  bytes (4-byte length + bytes)
  0x06  str (4-byte length + utf-8 bytes)
  0x07  dict (4-byte count + (k, v) pairs sorted by encoded key)
  0x08  set/frozenset (4-byte count + elements sorted by encoding)
  0x09  list (4-byte count + elements in order)
  0x0a  tuple (4-byte count + elements in order)

ALL containers sort their iteration deterministically -- dicts by
encoded key, sets by encoded element.  No Python iteration-order
dependency, no PYTHONHASHSEED dependency.  Integers are signed
big-endian so negative defaults (-1 sentinels) round-trip.

Floats are NOT supported -- explicit ``TypeError`` raised.  That
forces the caller to handle floats explicitly (skip or quantize)
rather than silently committing a value that might differ in the
last bit across CPUs.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any


# Type tags -- bumping any of these is a hard fork.  Pinned values
# rather than ``enum`` so a stray reorder of constants can't
# silently change the wire format.
_T_NONE = b"\x00"
_T_FALSE = b"\x01"
_T_TRUE = b"\x02"
_T_INT = b"\x03"
# 0x04 reserved (was going to be float; explicitly unsupported)
_T_BYTES = b"\x05"
_T_STR = b"\x06"
_T_DICT = b"\x07"
_T_SET = b"\x08"
_T_LIST = b"\x09"
_T_TUPLE = b"\x0a"


# Domain separator for the commitment hash.  Bumping breaks
# consensus.  Versioned so a future commitment format change can be
# distinguished from a v1 commitment without re-encoding the
# accumulators.
_COMMITMENT_DOMAIN = b"mc_accumulator_commit_v1"


def canon_encode(obj: Any) -> bytes:
    """Recursively encode ``obj`` to a canonical byte string.

    Deterministic: same input bytes produce same output bytes on
    every node, regardless of Python version, PYTHONHASHSEED, or
    dict-insertion order.  Containers sort their elements before
    encoding (dicts by encoded key, sets by encoded element) so
    iteration order is not part of the serialization.

    Supported leaf types: None, bool, int, bytes, str.
    Supported containers: dict, set, frozenset, list, tuple.
    Floats raise ``TypeError`` -- they're not safe in consensus
    state (last-bit precision varies across CPU FPUs).

    Negative ints and ints larger than ``2**63 - 1`` raise
    ``OverflowError`` because the encoding uses a fixed signed
    8-byte format.  In practice every consensus-state int in the
    codebase fits in int64; if a new field doesn't, the type would
    need to be widened explicitly (and that's a hard fork too).
    """
    if obj is None:
        return _T_NONE
    if obj is False:  # before int because bool is subclass of int
        return _T_FALSE
    if obj is True:
        return _T_TRUE
    if isinstance(obj, int):
        return _T_INT + struct.pack(">q", obj)
    if isinstance(obj, float):
        raise TypeError(
            "floats are not supported in the canonical encoding "
            "(last-bit precision varies across CPU FPUs and "
            "would break consensus); quantize to int or skip"
        )
    if isinstance(obj, bytes):
        return _T_BYTES + struct.pack(">I", len(obj)) + obj
    if isinstance(obj, bytearray):
        b = bytes(obj)
        return _T_BYTES + struct.pack(">I", len(b)) + b
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _T_STR + struct.pack(">I", len(b)) + b
    if isinstance(obj, dict):
        items = sorted(
            ((canon_encode(k), canon_encode(v)) for k, v in obj.items()),
            key=lambda kv: kv[0],
        )
        out = _T_DICT + struct.pack(">I", len(items))
        for k_enc, v_enc in items:
            out += k_enc + v_enc
        return out
    if isinstance(obj, (set, frozenset)):
        items = sorted(canon_encode(x) for x in obj)
        out = _T_SET + struct.pack(">I", len(items))
        for x_enc in items:
            out += x_enc
        return out
    if isinstance(obj, list):
        out = _T_LIST + struct.pack(">I", len(obj))
        for x in obj:
            out += canon_encode(x)
        return out
    if isinstance(obj, tuple):
        out = _T_TUPLE + struct.pack(">I", len(obj))
        for x in obj:
            out += canon_encode(x)
        return out
    raise TypeError(
        f"can't canonically encode {type(obj).__name__!s} "
        f"(value={obj!r}); add explicit handling in "
        "accumulator_commitment.canon_encode or omit from the "
        "commitment list"
    )


# The fixed ordered list of (commitment-key, value-extractor) pairs
# that contribute to the accumulator commitment.  Order is
# load-bearing: any change is a hard fork.  The list is split into
# (a) blockchain-level fields and (b) supply-tracker fields.
#
# Each extractor is a callable ``(blockchain) -> any`` that returns
# the field's current value, or a sentinel default if the field is
# missing on a pre-fork chain (so a fresh launch that hasn't yet
# touched the field still produces a stable commitment).
#
# Custom objects (EscrowLedger, FinalityTracker, RatchetState,
# ReactionState) and floats (bootstrap_ratchet_max) are NOT here --
# they're out of scope for the v1 commitment.

_COMMITTED_FIELDS: tuple[tuple[str, str, str], ...] = (
    # (commitment_key, source, attribute) where source is "supply"
    # or "blockchain".  Sorted alphabetically by commitment_key so
    # adding new fields appends without reordering.
    ("attestation_sig_counts", "blockchain", "attestation_sig_counts"),
    ("attester_coverage_misses", "blockchain", "attester_coverage_misses"),
    ("attester_epoch_earnings", "supply", "attester_epoch_earnings"),
    ("attester_epoch_earnings_start", "supply", "attester_epoch_earnings_start"),
    ("base_fee", "supply", "base_fee"),
    ("blocks_since_last_finalization", "blockchain", "blocks_since_last_finalization"),
    ("dormancy_backfill_applied", "supply", "dormancy_backfill_applied"),
    ("entity_id_to_index", "blockchain", "entity_id_to_index"),
    ("entity_message_count", "blockchain", "entity_message_count"),
    ("grandfather_applied", "supply", "grandfather_applied"),
    ("immature_rewards", "blockchain", "_immature_rewards"),
    ("key_history", "blockchain", "key_history"),
    ("key_rotation_counts", "blockchain", "key_rotation_counts"),
    ("key_rotation_last_height", "blockchain", "key_rotation_last_height"),
    ("lottery_prize_pool", "supply", "lottery_prize_pool"),
    ("next_entity_index", "blockchain", "_next_entity_index"),
    ("past_receipt_subtree_roots", "blockchain", "past_receipt_subtree_roots"),
    ("proposer_sig_counts", "blockchain", "proposer_sig_counts"),
    ("receipt_subtree_roots", "blockchain", "receipt_subtree_roots"),
    ("registered_validators", "supply", "registered_validators"),
    ("reputation", "blockchain", "reputation"),
    ("rolling_fee_burn", "supply", "rolling_fee_burn"),
    ("rolling_fee_burn_seeded", "supply", "rolling_fee_burn_seeded"),
    ("seed_divestment_debt", "blockchain", "seed_divestment_debt"),
    ("seed_initial_stakes", "blockchain", "seed_initial_stakes"),
    ("slash_offense_counts", "blockchain", "slash_offense_counts"),
    ("slash_sig_counts", "blockchain", "slash_sig_counts"),
    ("supply_reconciliation_applied", "supply", "supply_reconciliation_applied"),
    ("supply_reconciliation_fix_applied", "supply", "supply_reconciliation_fix_applied"),
    ("total_burned", "supply", "total_burned"),
    ("total_fees_collected", "supply", "total_fees_collected"),
    ("total_minted", "supply", "total_minted"),
    ("total_supply", "supply", "total_supply"),
    ("treasury_rebase_applied", "supply", "treasury_rebase_applied"),
    ("treasury_spend_debited_this_epoch", "supply", "_treasury_spend_debited_this_epoch"),
    ("treasury_spend_epoch_start", "supply", "_treasury_spend_epoch_start"),
    ("validator_archive_misses", "blockchain", "validator_archive_misses"),
    ("validator_archive_success_streak", "blockchain", "validator_archive_success_streak"),
    ("validator_first_active_block", "blockchain", "validator_first_active_block"),
    ("wots_tree_heights", "blockchain", "wots_tree_heights"),
)


def compute_accumulator_root(blockchain) -> bytes:
    """Compute the canonical 32-byte commitment to all consensus-
    visible accumulators on ``blockchain``.

    Mixed into ``state_root`` at and after
    ``ACCUMULATOR_COMMITMENT_HEIGHT`` so any drift between two nodes
    produces different state_roots and fails consensus immediately.

    Deterministic across nodes: every field is converted to a
    canonical byte string via ``canon_encode`` before hashing.  No
    iteration-order dependency, no PYTHONHASHSEED dependency, no
    float precision dependency.

    The full set of committed fields is the ``_COMMITTED_FIELDS``
    table -- explicit, ordered, single source of truth.  Adding a
    field is a hard fork (changes the hash on every existing chain).
    """
    # Build the canonical accumulator-state dict in fixed order.
    # We use an explicit list-of-pairs rather than a dict so the
    # commitment-key ordering is the table's order, not Python
    # dict-insertion order.  Sorted in the table.
    encoded_pairs = []
    for commit_key, source, attr_name in _COMMITTED_FIELDS:
        if source == "supply":
            value = getattr(blockchain.supply, attr_name, None)
        elif source == "blockchain":
            value = getattr(blockchain, attr_name, None)
        else:
            raise ValueError(
                f"bad source {source!r} in _COMMITTED_FIELDS entry "
                f"for {commit_key}"
            )
        encoded_pairs.append(
            canon_encode(commit_key) + canon_encode(value)
        )
    # Hash with domain separator.  Length-prefix the pair count for
    # clarity in extending to new fields.
    h = hashlib.sha256()
    h.update(_COMMITMENT_DOMAIN)
    h.update(struct.pack(">I", len(encoded_pairs)))
    for pair_bytes in encoded_pairs:
        h.update(pair_bytes)
    return h.digest()
