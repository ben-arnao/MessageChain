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


def enumerate_block_signatures(block) -> list[tuple[int, int, Signature]]:
    """Walk a block in canonical order, yielding (slot_id, index, signature).

    Iteration order is fixed and consensus-binding:
        1. Slots are visited in SLOT_* numeric order defined above.
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

    def _emit(slot_id: int, attr_name: str, sig_extractor):
        # getattr with [] default — tolerant of duck-typed block-likes
        # (e.g. the SimpleNamespace pos.create_block builds before the
        # real Block exists) that may not carry every slot attribute.
        # Treats a missing attribute as an empty list, NOT as a fatal
        # error: the proposer simply has no items in that slot.
        items = getattr(block, attr_name, None) or []
        for i, item in enumerate(items):
            sig = sig_extractor(item)
            if sig is not None:
                out.append((slot_id, i, sig))

    _emit(SLOT_TX_MESSAGE, "transactions", _safe_signature)
    _emit(SLOT_TX_TRANSFER, "transfer_transactions", _safe_signature)
    _emit(SLOT_TX_STAKE, "stake_transactions", _safe_signature)
    _emit(SLOT_TX_UNSTAKE, "unstake_transactions", _safe_signature)
    _emit(SLOT_TX_GOVERNANCE, "governance_txs", _safe_signature)
    _emit(SLOT_TX_AUTHORITY, "authority_txs", _safe_signature)
    _emit(SLOT_TX_REACTION, "react_transactions", _safe_signature)
    _emit(SLOT_FINALITY_VOTE, "finality_votes", _safe_signature)
    _emit(SLOT_SLASH_TX, "slash_transactions", _safe_signature)
    _emit(SLOT_ATTESTATION, "attestations", _safe_signature)

    # SLOT_VALIDATOR_SIG (0x0B) deliberately skipped — see docstring.

    _emit(SLOT_CUSTODY_PROOF, "custody_proofs", _safe_signature)

    inclusion_list = getattr(block, "inclusion_list", None)
    if inclusion_list is not None:
        sig = _safe_signature(inclusion_list)
        if sig is not None:
            out.append((SLOT_INCLUSION_LIST, 0, sig))

    _emit(SLOT_CENSORSHIP_EVIDENCE, "censorship_evidence_txs", _safe_signature)
    _emit(SLOT_BOGUS_REJECT_EVIDENCE, "bogus_rejection_evidence_txs", _safe_signature)
    _emit(
        SLOT_INCLUSION_VIOLATION_EVIDENCE,
        "inclusion_list_violation_evidence_txs",
        _safe_signature,
    )
    _emit(
        SLOT_NON_RESPONSE_EVIDENCE,
        "non_response_evidence_txs",
        _safe_signature,
    )

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


def strip_block_witnesses(block) -> "Block":
    """Return a new Block with all tx signatures stripped.

    The witness_root in the header is preserved — it was computed from
    the original witnesses before stripping.  The block_hash changes
    because the block is reconstructed, but the header data (including
    witness_root) remains identical, so the block_hash still matches.

    Every signed-body slot the block carries MUST round-trip through
    this function — the witness_root commitment folds in leaves from
    every slot ``enumerate_block_signatures`` walks (reactions, custody
    proofs, inclusion list, the four evidence kinds, ...), so any slot
    silently dropped here means the stripped block recomputes a
    different witness_root post-activation and ``attach_block_witnesses``
    raises ``WitnessRootMismatchError`` on every read.  We use
    ``dataclasses.replace`` rather than an explicit field list so future
    block-shape additions inherit the correct strip semantics
    automatically — listing slots one-by-one was the defect form.
    """
    import copy
    import dataclasses

    stripped_txs = [strip_tx_witness(tx) for tx in block.transactions]

    # Deep-copy header so callers that hold the original block see no
    # mutation; replace() carries every other Block field through
    # unchanged so reactions / custody / inclusion list / evidence
    # slots are preserved alongside the slots we explicitly override.
    stripped_block = dataclasses.replace(
        block,
        header=copy.deepcopy(block.header),
        transactions=stripped_txs,
        block_hash=b"",
    )
    # block_hash is header-derived, so it should match the original.
    stripped_block.block_hash = stripped_block._compute_hash()
    return stripped_block


def get_block_witness_data(block) -> bytes:
    """Serialize all witness data from a block for separate storage.

    Format: u32 tx_count | for each tx: u32 witness_len | witness_bytes
    """
    parts = [struct.pack(">I", len(block.transactions))]
    for tx in block.transactions:
        w = get_tx_witness_data(tx)
        parts.append(struct.pack(">I", len(w)))
        parts.append(w)
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


def attach_block_witnesses(stripped_block, witness_data: bytes):
    """Reattach witness data to a stripped block, verifying integrity.

    Post-activation (block_number >= WITNESS_ROOT_ACTIVATION_HEIGHT):
        Re-derives `compute_block_witness_root(restored)` and asserts
        equality with `restored.header.witness_root`.  Mismatch raises
        `WitnessRootMismatchError` — never silently returns a tampered
        block.

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
    import dataclasses

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

    # Replace carries every Block field through unchanged — reactions,
    # custody proofs, inclusion list, and the four evidence kinds all
    # contribute leaves to ``compute_block_witness_root``, so dropping
    # any of them here would make the post-activation witness_root
    # check below fire on legitimate reattach.  Same defect class as
    # the strip path's previous explicit-field-list form.
    restored = dataclasses.replace(
        stripped_block,
        header=copy.deepcopy(stripped_block.header),
        transactions=restored_txs,
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
