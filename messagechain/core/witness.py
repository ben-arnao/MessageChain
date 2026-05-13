"""
Witness separation — split block storage into state-transition data and
witness data (WOTS signatures + Merkle auth paths).

After a block is FINALIZED (2/3 stake signed), signatures serve only
auditability, not consensus safety.  Separating them lets full nodes
carry witness data only for recent/unfinalized blocks, while witness-
archive nodes carry everything.  Nothing is ever deleted — every byte
persists somewhere forever.

Key design property: tx_hash is computed from _signable_data() which
EXCLUDES the signature, so stripping witnesses preserves tx_hash exactly.
No SegWit-style txid/wtxid split is needed.

Two witness-root forms live in this module — DO NOT confuse them in new
code:

  * `compute_witness_root(transactions)` — LEGACY single-slot form.  Only
    folds the `transactions` (SLOT_TX_MESSAGE) signatures, with a flat
    leaf rule (`HASH(sig.canonical_bytes())`) and no domain separation.
    Retained ONLY for back-compat with existing tests and historical
    fixtures; it is NOT the consensus-binding root.  Never wire this
    into a new code path; never compare its output to `header.witness_root`
    on a post-activation block.

  * `compute_block_witness_root(block)` — CANONICAL multi-slot form.
    Walks every signed body slot via `enumerate_block_signatures` with
    domain-separated leaves (slot_id + item_index baked into each leaf
    hash) and tagged Merkle internals.  This is what
    `header.witness_root` commits to from
    `WITNESS_ROOT_ACTIVATION_HEIGHT` onward, and what every new
    strip/attach, peer-fetch, or audit path MUST verify against.

The two functions are NOT byte-equivalent on the same input.  Mixing
them silently produces a chain-halting bug; the module-level constant
domain tags below (`_WITNESS_*_TAG`) exist precisely so the two trees
are computationally distinguishable.
"""

import dataclasses
import hashlib
import struct
from messagechain.config import HASH_ALGO
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import Signature
from messagechain.crypto.hashing import default_hash


def _hash(data: bytes) -> bytes:
    return default_hash(data)


def is_witness_separation_active(height: int) -> bool:
    """Return True iff witness auto-separation is active at ``height``.

    Two-part gate:
      1. ``WITNESS_AUTO_SEPARATION_ENABLED`` — operator-facing kill
         switch.  Set to False at runtime to suspend new separation
         work (already-stripped blocks stay stripped).
      2. ``height >= WITNESS_AUTO_SEPARATION_HEIGHT`` — hard fork
         activation.  Pre-fork blocks (``block_number < FORK_HEIGHT``)
         are never eligible, even after the fork activates — the chain
         committed to their inline encoding and replay determinism
         requires those bytes to stay inline forever.

    Imported lazily so test-time monkey-patches of the config module
    take effect without a re-import dance.
    """
    import messagechain.config as _cfg
    if not getattr(_cfg, "WITNESS_AUTO_SEPARATION_ENABLED", False):
        return False
    fork_h = getattr(_cfg, "WITNESS_AUTO_SEPARATION_HEIGHT", 0)
    return height >= fork_h


# Sentinel signature for witness-stripped transactions.  Empty lists +
# empty bytes so the Signature dataclass is structurally valid but
# trivially distinguishable from a real WOTS+ signature.
WITNESS_STRIPPED_SENTINEL = Signature(
    wots_signature=[],
    leaf_index=0,
    auth_path=[],
    wots_public_key=b"",
    wots_public_seed=b"",
)


def compute_witness_root(transactions: list) -> bytes:
    """Compute Merkle root over all transaction witness data.

    Each transaction contributes one leaf: the hash of its signature's
    canonical bytes.  For blocks with no transactions, returns SHA256(b"").

    The witness_root is included in BlockHeader.signable_data() so the
    block_hash commits to witnesses even when they are stored separately.

    Legacy form: only commits to MessageTransaction signatures.  Retained
    for backward compatibility with existing tests and external callers.
    The CONSENSUS-BINDING form is `compute_block_witness_root(block)` —
    that one walks every signed body slot, not just `transactions`.  The
    two functions are NOT byte-equivalent on the same input; never compare
    a legacy root to a block root.
    """
    if not transactions:
        return default_hash(b"")

    leaves = []
    for tx in transactions:
        sig_bytes = tx.signature.canonical_bytes() if tx.signature else b""
        leaves.append(_hash(sig_bytes))

    # Build Merkle tree over leaves (same structure as tx Merkle root)
    layer = list(leaves)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(_hash(b"\x02witness_sentinel"))
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = _hash(layer[i] + layer[i + 1])
            next_layer.append(combined)
        layer = next_layer

    return layer[0]


# ── Block-level witness root (v1, all signed body slots) ─────────────
#
# The consensus-binding witness commitment.  Walks every signed body slot
# in canonical order and folds each Signature into a Merkle root, with
# each leaf domain-separated by (slot_id, item_index, sig.canonical_bytes).
#
# Why per-leaf slot+index domain separation:
#   * slot_id prevents a relayer from moving a signature between slots
#     (e.g., grafting a transfer-tx sig into a message-tx slot) — even
#     though the canonical_bytes would be identical, the leaf hash differs.
#   * item_index prevents within-slot reordering — again even though
#     canonical_bytes is identical, the position changes the leaf.
#   * Both fields are committed independently of the underlying body
#     merkle_root, so witness_root is a defense-in-depth commitment that
#     a malformed block fails BOTH roots.
#
# Slot IDs are stable consensus constants — never reorder, never repurpose.
# A new signed body slot gets a NEW unused id; deleted slots leave their
# id permanently retired.

# Domain tags for leaf and internal nodes — distinct from any other
# tagged-hash use in this codebase to prevent cross-tree collision.
_WITNESS_LEAF_TAG = b"\x03witness-leaf-v1"
_WITNESS_INTERNAL_TAG = b"\x04witness-int-v1"
_WITNESS_PAD_TAG = b"\x05witness-pad-v1"
_WITNESS_EMPTY_TAG = b"\x06witness-empty-v1"

# Stable per-slot domain bytes.  See enumerate_block_signatures for the
# slot-to-attribute mapping.  Bytes 0x01..0x10 are reserved for the
# initial signed-body surface; future slots take 0x11+.
SLOT_TX_MESSAGE = 0x01
SLOT_TX_TRANSFER = 0x02
SLOT_TX_STAKE = 0x03
SLOT_TX_UNSTAKE = 0x04
SLOT_TX_GOVERNANCE = 0x05
SLOT_TX_AUTHORITY = 0x06
SLOT_TX_REACTION = 0x07
SLOT_FINALITY_VOTE = 0x08
SLOT_SLASH_TX = 0x09
SLOT_ATTESTATION = 0x0A
SLOT_VALIDATOR_SIG = 0x0B
SLOT_CUSTODY_PROOF = 0x0C
SLOT_INCLUSION_LIST = 0x0D
SLOT_CENSORSHIP_EVIDENCE = 0x0E
SLOT_BOGUS_REJECT_EVIDENCE = 0x0F
SLOT_INCLUSION_VIOLATION_EVIDENCE = 0x10
SLOT_NON_RESPONSE_EVIDENCE = 0x11


def _safe_signature(obj) -> Signature | None:
    """Extract `.signature` from `obj` if present and structurally a Signature.

    Tolerant of test fixtures where signature may be None or absent;
    returns None in those cases so they simply contribute no leaf.
    """
    sig = getattr(obj, "signature", None)
    if isinstance(sig, Signature):
        return sig
    return None


# ── Canonical signed-slot registry ───────────────────────────────────
#
# Single source of truth for every signed-body slot in a Block.  Three
# call sites depend on it — ``enumerate_block_signatures`` (drives the
# consensus-binding witness_root), ``strip_block_witnesses`` (sentinels
# every signed slot for the auto-separation sweep), and the v1 witness
# blob codec (``get_block_witness_data`` / ``attach_block_witnesses``,
# routes WOTS+ bytes to/from the chaindb side table).  All three walk
# the same table so a new signed slot only needs ONE row here to plug
# into the entire strip/attach/witness-root surface — no parallel
# explicit lists to forget to update.  Pre-r53 #1 the strip and blob
# codec each maintained their own (wrong) tx-only list; the registry
# is the abstraction the audit demanded.
#
# Tuple shape: (slot_id, attribute_name, is_singleton).  ``is_singleton``
# distinguishes the one optional scalar slot (``inclusion_list``) from
# the per-list slots; the strip and blob codec both honor the
# distinction.  Order matches the historical
# ``enumerate_block_signatures`` emit sequence and is consensus-binding
# — reordering changes witness_root.
#
# SLOT_VALIDATOR_SIG (0x0B) is deliberately omitted: validator_signatures
# are post-sign signatures over ``block_hash`` and are not folded into
# witness_root by design.  See ``enumerate_block_signatures`` docstring.
_SIGNED_BLOCK_SLOTS: list[tuple[int, str, bool]] = [
    (SLOT_TX_MESSAGE,                   "transactions",                          False),
    (SLOT_TX_TRANSFER,                  "transfer_transactions",                 False),
    (SLOT_TX_STAKE,                     "stake_transactions",                    False),
    (SLOT_TX_UNSTAKE,                   "unstake_transactions",                  False),
    (SLOT_TX_GOVERNANCE,                "governance_txs",                        False),
    (SLOT_TX_AUTHORITY,                 "authority_txs",                         False),
    (SLOT_TX_REACTION,                  "react_transactions",                    False),
    (SLOT_FINALITY_VOTE,                "finality_votes",                        False),
    (SLOT_SLASH_TX,                     "slash_transactions",                    False),
    (SLOT_ATTESTATION,                  "attestations",                          False),
    (SLOT_CUSTODY_PROOF,                "custody_proofs",                        False),
    (SLOT_INCLUSION_LIST,               "inclusion_list",                        True),
    (SLOT_CENSORSHIP_EVIDENCE,          "censorship_evidence_txs",               False),
    (SLOT_BOGUS_REJECT_EVIDENCE,        "bogus_rejection_evidence_txs",          False),
    (SLOT_INCLUSION_VIOLATION_EVIDENCE, "inclusion_list_violation_evidence_txs", False),
    (SLOT_NON_RESPONSE_EVIDENCE,        "non_response_evidence_txs",             False),
]


# Fast lookup from slot_id → (attr_name, is_singleton) for the attach
# decoder's item-routing step.  Built once at module import; never
# mutated.
_SLOT_ID_TO_ATTR: dict[int, tuple[str, bool]] = {
    slot_id: (attr_name, is_singleton)
    for slot_id, attr_name, is_singleton in _SIGNED_BLOCK_SLOTS
}


def enumerate_block_signatures(block) -> list[tuple[int, int, Signature]]:
    """Walk a block in canonical order, yielding (slot_id, index, signature).

    Iteration order is fixed and consensus-binding:
        1. Slots are visited in the order defined by ``_SIGNED_BLOCK_SLOTS``.
        2. Within a slot, items appear in their stored list order.
        3. Items whose `.signature` is None or absent contribute nothing.

    This is the order `compute_block_witness_root` commits to.  Reordering
    items within a list, swapping items between slots, or omitting an
    item all change the resulting root.

    Excluded by design — `validator_signatures` (slot 0x0B):
        These are appended by validators AFTER the proposer signs the
        header, so they are not present at witness_root computation time.
        Each validator_signature is itself a signature over `block_hash`,
        which already commits to witness_root + everything else — so
        per-sig integrity is preserved without folding them in.  The
        SLOT_VALIDATOR_SIG constant stays defined and reserved so a
        future iteration can adopt it for a separate post-sign
        commitment if needed.
    """
    out: list[tuple[int, int, Signature]] = []

    for slot_id, attr_name, is_singleton in _SIGNED_BLOCK_SLOTS:
        if is_singleton:
            # Optional scalar slot (inclusion_list).  getattr with None
            # default keeps duck-typed block-likes that omit the
            # attribute working without raising.
            obj = getattr(block, attr_name, None)
            if obj is None:
                continue
            sig = _safe_signature(obj)
            if sig is not None:
                out.append((slot_id, 0, sig))
        else:
            # getattr with [] default — tolerant of duck-typed block-likes
            # (e.g. the SimpleNamespace pos.create_block builds before the
            # real Block exists) that may not carry every slot attribute.
            # Treats a missing attribute as an empty list, NOT as a fatal
            # error: the proposer simply has no items in that slot.
            items = getattr(block, attr_name, None) or []
            for i, item in enumerate(items):
                sig = _safe_signature(item)
                if sig is not None:
                    out.append((slot_id, i, sig))

    return out


def _witness_leaf_hash(slot_id: int, item_index: int, sig: Signature) -> bytes:
    return _hash(
        _WITNESS_LEAF_TAG
        + struct.pack(">B", slot_id)
        + struct.pack(">I", item_index)
        + sig.canonical_bytes()
    )


def _build_witness_merkle(leaves: list[bytes]) -> bytes:
    """Fold pre-hashed leaves into a Merkle root.

    Empty leaf set returns a distinguishable sentinel — never collides
    with the legacy-form empty root (`default_hash(b"")`) nor with the
    all-zero default of `header.witness_root`.
    """
    if not leaves:
        return _hash(_WITNESS_EMPTY_TAG)
    layer = list(leaves)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(_hash(_WITNESS_PAD_TAG))
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(
                _hash(_WITNESS_INTERNAL_TAG + layer[i] + layer[i + 1])
            )
        layer = next_layer
    return layer[0]


def compute_block_witness_root(block) -> bytes:
    """Consensus-binding witness Merkle root for a block.

    Walks every signed body slot via `enumerate_block_signatures`, builds
    a domain-separated leaf per signature, folds into one Merkle root.

    Once activation lands (B-2), block builders set
    `header.witness_root = compute_block_witness_root(block)` before
    signing and validators reject blocks where the recomputed root
    disagrees with the carried header field.

    Returns the empty-block sentinel when no slot contains a signature.
    The sentinel is distinct from `b"\\x00" * 32` (the field default) so
    a builder that forgets to populate witness_root never accidentally
    produces a valid empty-body witness commitment.
    """
    leaves = [
        _witness_leaf_hash(slot, idx, sig)
        for (slot, idx, sig) in enumerate_block_signatures(block)
    ]
    return _build_witness_merkle(leaves)


def tx_has_witness(tx: MessageTransaction) -> bool:
    """Check if a transaction has witness data (non-sentinel signature)."""
    if tx.signature is None:
        return False
    if not tx.signature.wots_signature and not tx.signature.wots_public_key:
        return False
    return True


def strip_tx_witness(tx: MessageTransaction) -> MessageTransaction:
    """Return a copy of the transaction with its signature stripped.

    Preserves tx_hash (which excludes the signature by design) and
    EVERY other MessageTransaction field — version / compression_flag
    / prev / sender_pubkey / community_id / poll_options / vote_target
    / witness_hash.  The stripped tx carries the sentinel signature.

    Built on ``dataclasses.replace`` so every future MessageTransaction
    field auto-survives the round-trip.  An explicit field list froze
    the strip contract at the pre-Tier-10 set; ``ChainDB.strip_finalized_witnesses``
    writes ``stripped.to_bytes()`` back into ``blocks.data``, so any
    field not copied here is silently erased from primary block storage
    on the next sweep past WITNESS_AUTO_SEPARATION_HEIGHT.  That
    directly violates the "your message can never be deleted"
    permanence anchor for every Tier 5+ optional field — exactly the
    defect form the sibling ``strip_block_witnesses`` docstring already
    calls out ("listing slots one-by-one was the defect form").
    """
    return dataclasses.replace(
        tx,
        signature=Signature([], 0, [], b"", b""),
    )


def get_tx_witness_data(tx: MessageTransaction) -> bytes:
    """Serialize a transaction's witness data (signature) for separate storage."""
    return tx.signature.to_bytes()


def attach_tx_witness(stripped_tx: MessageTransaction, witness_data: bytes) -> MessageTransaction:
    """Reattach witness data to a stripped transaction.

    Inverse of ``strip_tx_witness``.  Built on ``dataclasses.replace``
    so every non-signature field is preserved verbatim — same
    anti-field-list discipline ``strip_tx_witness`` uses.
    """
    sig = Signature.from_bytes(witness_data)
    return dataclasses.replace(stripped_tx, signature=sig)


def _sentinel_signature() -> Signature:
    """Return the strip-sentinel: a Signature object with all empty fields.

    Structurally valid (the dataclass accepts it) but trivially
    distinguishable from any real WOTS+ signature.  Used by every site
    that needs to clear a slot item's signature in lockstep — strip
    plus any future "set to placeholder before reattach" sites — so the
    sentinel shape stays consistent.
    """
    return Signature([], 0, [], b"", b"")


def _replace_slot_item_signature(item):
    """Return ``dataclasses.replace(item, signature=sentinel)`` if
    ``item`` is a dataclass carrying a Signature, else ``item`` unchanged.

    Centralised so strip + the v1 attach blob codec produce the exact
    same sentinel shape per item; an item that doesn't carry a
    Signature (no ``.signature`` attribute, or attribute is None) flows
    through untouched.
    """
    sig = getattr(item, "signature", None)
    if not isinstance(sig, Signature):
        return item
    return dataclasses.replace(item, signature=_sentinel_signature())


def strip_block_witnesses(block) -> "Block":
    """Return a new Block with EVERY signed-slot signature stripped.

    Walks the canonical ``_SIGNED_BLOCK_SLOTS`` registry and replaces
    each item's signature with the strip sentinel.  Pre-r53 #1 this
    only iterated ``block.transactions`` — attestations, transfer /
    stake / unstake / governance / authority / reaction txs,
    finality_votes, slash, custody, inclusion_list, and all four
    evidence kinds kept their ~2.7 KB WOTS+ signatures inline in
    primary ``blocks.data`` forever despite the auto-separation sweep
    being live.  Routing through the central slot registry guarantees
    every signed-body slot inherits the strip discipline by
    construction; a new signed slot only needs to register itself in
    ``_SIGNED_BLOCK_SLOTS`` and the strip + blob codec + witness_root
    all pick it up.

    The witness_root in the header is preserved — it was computed from
    the original witnesses before stripping.  The block_hash changes
    because the block is reconstructed, but the header data (including
    witness_root) remains identical, so the block_hash still matches.
    """
    import copy

    # Build per-slot override dict.  Slots with no signed items in the
    # input block are omitted from the dict so ``dataclasses.replace``
    # carries them through unchanged.
    overrides: dict = {}
    for slot_id, attr_name, is_singleton in _SIGNED_BLOCK_SLOTS:
        if is_singleton:
            obj = getattr(block, attr_name, None)
            if obj is None:
                continue
            sig = getattr(obj, "signature", None)
            if isinstance(sig, Signature):
                overrides[attr_name] = _replace_slot_item_signature(obj)
            # else: singleton lacks a Signature — pass through unchanged.
        else:
            items = getattr(block, attr_name, None)
            if not items:
                continue
            new_items = [_replace_slot_item_signature(item) for item in items]
            overrides[attr_name] = new_items

    # Deep-copy header so callers that hold the original block see no
    # mutation; ``replace()`` carries every non-overridden Block field
    # through unchanged.
    stripped_block = dataclasses.replace(
        block,
        header=copy.deepcopy(block.header),
        block_hash=b"",
        **overrides,
    )
    # block_hash is header-derived, so it should match the original.
    stripped_block.block_hash = stripped_block._compute_hash()
    return stripped_block


# v1 blob format magic + version.  See ``get_block_witness_data`` /
# ``attach_block_witnesses`` for the wire shape.  Choice of 0xFF as
# the magic byte: the legacy blob format starts with the high byte of
# ``u32 tx_count``, which is 0x00 for any plausible tx_count (< 16M),
# so 0xFF can never collide on the first byte and autodetect is
# trivial.
_WITNESS_BLOB_MAGIC = 0xFF
_WITNESS_BLOB_VERSION_V1 = 0x01


def get_block_witness_data(block) -> bytes:
    """Serialize EVERY signed-slot signature from a block.

    v1 format:
        magic (1B = 0xFF) | version (1B = 0x01) | entry_count (u32 BE)
        per entry: slot_id (1B) | item_index (u32 BE)
                 | sig_len (u32 BE) | sig_bytes

    Walks the canonical ``_SIGNED_BLOCK_SLOTS`` registry via
    ``enumerate_block_signatures`` so the witness blob covers every
    slot the strip path sentinels.  Pre-r53 #1 only packed
    ``transactions`` — the round-trip was a tautology for non-tx slots
    because the strip also left those slots intact, and the audit
    promise that "every signed-body witness moves to the side table"
    held only for messages.

    The magic-byte prefix makes the new format autodetectable by
    ``attach_block_witnesses``; legacy on-disk blobs (which start with
    ``u32 tx_count`` and thus 0x00 high byte) still decode via the
    legacy path so a node upgrading past r53 #1 doesn't brick on its
    own historical ``block_witnesses`` side table.
    """
    entries = enumerate_block_signatures(block)
    parts: list[bytes] = [
        bytes([_WITNESS_BLOB_MAGIC, _WITNESS_BLOB_VERSION_V1]),
        struct.pack(">I", len(entries)),
    ]
    for slot_id, item_index, sig in entries:
        sig_bytes = sig.to_bytes()
        parts.append(bytes([slot_id]))
        parts.append(struct.pack(">I", item_index))
        parts.append(struct.pack(">I", len(sig_bytes)))
        parts.append(sig_bytes)
    return b"".join(parts)


class WitnessRootMismatchError(Exception):
    """Raised when a reattached block's recomputed witness_root does not
    match the committed `header.witness_root`.

    This is the integrity anchor for the strip/attach surface — without
    it, disk corruption, an attacker with archive-node write access, or
    a future B-3 peer-fetch path could substitute fabricated WOTS+ blobs
    that deserialize cleanly while the unmodified header (and therefore
    the block_hash) still verifies.

    Carries enough context for a chaindb caller to log actionably:
    `block_number` to find the bad row, `expected_root` (the value the
    proposer signed in the header), and `actual_root` (what was
    recomputed from the blob actually returned).
    """

    def __init__(
        self,
        block_number: int,
        expected_root: bytes,
        actual_root: bytes,
    ):
        self.block_number = block_number
        self.expected_root = expected_root
        self.actual_root = actual_root
        super().__init__(
            f"witness_root mismatch on reattach at block {block_number}: "
            f"expected {expected_root.hex()}, got {actual_root.hex()}"
        )


def _attach_block_witnesses_legacy(stripped_block, witness_data: bytes):
    """Legacy decoder: ``u32 tx_count | per-tx (u32 sig_len | sig_bytes)``.

    Covers blocks that were stripped pre-r53 #1 and stored in
    ``block_witnesses`` under the old tx-only blob shape.  Non-tx slots
    on those rows were never sentineled on the ``blocks.data`` side
    either, so they carry their real signatures inline and the stripped
    block flows through unchanged on those slots.
    """
    offset = 0
    tx_count = struct.unpack_from(">I", witness_data, offset)[0]
    offset += 4

    if tx_count != len(stripped_block.transactions):
        raise ValueError(
            f"Witness data tx count {tx_count} != block tx count "
            f"{len(stripped_block.transactions)}"
        )

    restored_txs = []
    for tx in stripped_block.transactions:
        w_len = struct.unpack_from(">I", witness_data, offset)[0]
        offset += 4
        w_bytes = witness_data[offset:offset + w_len]
        offset += w_len
        restored_txs.append(attach_tx_witness(tx, w_bytes))

    return dataclasses.replace(
        stripped_block,
        transactions=restored_txs,
    )


def _attach_block_witnesses_v1(stripped_block, witness_data: bytes):
    """v1 decoder: every signed slot routed back to its named attribute.

    Walks the wire entries in stored order; each entry carries an
    explicit (slot_id, item_index) so the decoder can route the
    signature back to its origin slot regardless of pack order.  Builds
    one override dict per slot attribute and applies all overrides via
    a single ``dataclasses.replace`` at the end so non-touched slots
    pass through unchanged.
    """
    # Skip past magic + version (2 bytes); entry_count follows.
    offset = 2
    entry_count = struct.unpack_from(">I", witness_data, offset)[0]
    offset += 4

    # Build per-attribute working copies of the slot item lists (and
    # the singleton).  Only attrs with at least one entry in the blob
    # get reconstructed; the rest stay on the stripped_block as-is.
    per_attr_items: dict[str, list] = {}
    per_attr_singleton: dict[str, object] = {}

    for _ in range(entry_count):
        slot_id = witness_data[offset]
        offset += 1
        item_index = struct.unpack_from(">I", witness_data, offset)[0]
        offset += 4
        sig_len = struct.unpack_from(">I", witness_data, offset)[0]
        offset += 4
        sig_bytes = witness_data[offset:offset + sig_len]
        offset += sig_len

        slot_meta = _SLOT_ID_TO_ATTR.get(slot_id)
        if slot_meta is None:
            # Unknown slot from a future fork — skip rather than fail.
            # Pre-fix the decoder would have crashed on any unfamiliar
            # byte; tolerant skip lets a downgraded node still decode
            # a forward-version blob enough to read its known slots.
            continue
        attr_name, is_singleton = slot_meta

        if is_singleton:
            base_obj = getattr(stripped_block, attr_name, None)
            if base_obj is None:
                continue
            per_attr_singleton[attr_name] = attach_tx_witness(
                base_obj, sig_bytes,
            ) if hasattr(base_obj, "signature") else base_obj
        else:
            if attr_name not in per_attr_items:
                # Snapshot the stripped block's current list — we'll
                # mutate it via index assignment.
                base_items = getattr(stripped_block, attr_name, None) or []
                per_attr_items[attr_name] = list(base_items)
            items = per_attr_items[attr_name]
            if item_index >= len(items):
                raise ValueError(
                    f"witness blob slot 0x{slot_id:02x} index {item_index} "
                    f"out of range for {attr_name} (len={len(items)})",
                )
            items[item_index] = attach_tx_witness(items[item_index], sig_bytes)

    overrides: dict = {}
    overrides.update(per_attr_items)
    overrides.update(per_attr_singleton)

    return dataclasses.replace(stripped_block, **overrides)


def attach_block_witnesses(stripped_block, witness_data: bytes):
    """Reattach witness data to a stripped block, verifying integrity.

    Two on-disk blob formats are autodetected from the first byte:

      * v1 (r53 #1+, leading byte == 0xFF): every signed-body slot
        round-trips.  Routes each signature back to its (slot, item)
        origin via the canonical slot registry.

      * Legacy (leading byte != 0xFF, i.e. ``u32 tx_count`` high byte
        which is 0x00 for any plausible count): pre-r53 #1 shape, only
        ``transactions`` were packed.  Non-tx slot signatures were
        never stripped on the corresponding ``blocks.data`` row, so
        they flow through from the stripped block unchanged.

    Post-activation (block_number >= WITNESS_ROOT_ACTIVATION_HEIGHT):
        Re-derives `compute_block_witness_root(restored)` and asserts
        equality with `restored.header.witness_root`.  Mismatch raises
        `WitnessRootMismatchError` — never silently returns a tampered
        block.  Works for either blob shape because the recomputed
        root depends on the FINAL signatures on the restored block,
        not on the blob byte layout.

    Pre-activation (block_number < WITNESS_ROOT_ACTIVATION_HEIGHT):
        The header field is the all-zero default by design (the
        commitment was not yet enforced when the block was produced),
        so verification is skipped — enforcing would reject every
        historical block on chain today.

    The activation gate matches `pos.create_block` (which only
    populates the field post-activation) and `Blockchain.validate_block`
    (which only checks it post-activation); all three must agree or a
    block accepted at validate-time could fail reattach later.
    """
    from messagechain.config import WITNESS_ROOT_ACTIVATION_HEIGHT
    import copy

    if len(witness_data) == 0:
        raise ValueError("witness blob is empty")

    if witness_data[0] == _WITNESS_BLOB_MAGIC:
        if len(witness_data) < 2 or witness_data[1] != _WITNESS_BLOB_VERSION_V1:
            raise ValueError(
                f"unknown witness blob version: magic=0x{witness_data[0]:02x}, "
                f"got version byte 0x{witness_data[1]:02x} (only v1=0x01 is supported)",
            )
        restored = _attach_block_witnesses_v1(stripped_block, witness_data)
    else:
        restored = _attach_block_witnesses_legacy(stripped_block, witness_data)

    # Deep-copy header so any downstream mutation by the caller does
    # not bleed back into the stripped_block (same discipline strip
    # uses).  Reset block_hash and recompute so the post-attach hash
    # is derived from the actually-carried fields.
    restored = dataclasses.replace(
        restored,
        header=copy.deepcopy(restored.header),
        block_hash=b"",
    )
    header = restored.header
    restored.block_hash = restored._compute_hash()

    # Self-verify post-activation.  The header is unmodified by
    # stripping, so `restored.header.witness_root` is the value the
    # proposer signed; any divergence means the witness blob was
    # tampered (or corrupted) between strip and attach.
    if header.block_number >= WITNESS_ROOT_ACTIVATION_HEIGHT:
        actual_root = compute_block_witness_root(restored)
        if actual_root != header.witness_root:
            raise WitnessRootMismatchError(
                block_number=header.block_number,
                expected_root=header.witness_root,
                actual_root=actual_root,
            )

    return restored
