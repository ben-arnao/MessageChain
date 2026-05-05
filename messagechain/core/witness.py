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
"""

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

    Preserves tx_hash (which excludes the signature by design) and all
    other fields.  The stripped tx carries the sentinel signature.
    """
    return MessageTransaction(
        entity_id=tx.entity_id,
        message=tx.message,
        timestamp=tx.timestamp,
        nonce=tx.nonce,
        fee=tx.fee,
        signature=Signature([], 0, [], b"", b""),
        version=tx.version,
        compression_flag=tx.compression_flag,
        tx_hash=tx.tx_hash,
        witness_hash=tx.witness_hash,
    )


def get_tx_witness_data(tx: MessageTransaction) -> bytes:
    """Serialize a transaction's witness data (signature) for separate storage."""
    return tx.signature.to_bytes()


def attach_tx_witness(stripped_tx: MessageTransaction, witness_data: bytes) -> MessageTransaction:
    """Reattach witness data to a stripped transaction."""
    sig = Signature.from_bytes(witness_data)
    return MessageTransaction(
        entity_id=stripped_tx.entity_id,
        message=stripped_tx.message,
        timestamp=stripped_tx.timestamp,
        nonce=stripped_tx.nonce,
        fee=stripped_tx.fee,
        signature=sig,
        version=stripped_tx.version,
        compression_flag=stripped_tx.compression_flag,
        tx_hash=stripped_tx.tx_hash,
        witness_hash=stripped_tx.witness_hash,
    )


def strip_block_witnesses(block) -> "Block":
    """Return a new Block with all tx signatures stripped.

    The witness_root in the header is preserved — it was computed from
    the original witnesses before stripping.  The block_hash changes
    because the block is reconstructed, but the header data (including
    witness_root) remains identical, so the block_hash still matches.
    """
    from messagechain.core.block import Block, BlockHeader
    import copy

    stripped_txs = [strip_tx_witness(tx) for tx in block.transactions]

    # Deep copy header to avoid mutating original
    header = copy.deepcopy(block.header)

    stripped_block = Block(
        header=header,
        transactions=stripped_txs,
        validator_signatures=block.validator_signatures,
        slash_transactions=block.slash_transactions,
        attestations=block.attestations,
        transfer_transactions=block.transfer_transactions,
        governance_txs=block.governance_txs,
        authority_txs=block.authority_txs,
        stake_transactions=block.stake_transactions,
        unstake_transactions=block.unstake_transactions,
        finality_votes=block.finality_votes,
    )
    # block_hash is header-derived, so it should match the original
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


def verify_witness_data(witness_data: bytes, expected_root: bytes) -> bool:
    """Verify a serialized witness blob matches a committed witness_root.

    This is the integrity anchor for any flow that fetches witnesses
    from a peer (or reads them from a side-table after separation):
    the blob is only trusted if re-hashing it reproduces the
    witness_root already committed in the header (which is itself
    covered by the block_hash and the proposer signature).

    Recomputes the Merkle tree using the same leaf rule as
    compute_witness_root — leaf = HASH(signature.canonical_bytes()).
    The blob format is the one produced by get_block_witness_data.

    Returns True iff the recomputed root equals expected_root.  Any
    structural error in the blob returns False (not raises) — this
    function is called on untrusted input from peers and must not
    crash on malformed data.
    """
    try:
        offset = 0
        tx_count = struct.unpack_from(">I", witness_data, offset)[0]
        offset += 4

        if tx_count == 0:
            return expected_root == default_hash(b"")

        leaves = []
        for _ in range(tx_count):
            w_len = struct.unpack_from(">I", witness_data, offset)[0]
            offset += 4
            w_bytes = witness_data[offset:offset + w_len]
            if len(w_bytes) != w_len:
                return False
            offset += w_len

            # Decode and re-canonicalize.  The blob uses Signature.to_bytes
            # (compact storage form); witness_root uses canonical_bytes
            # (deterministic serialization with length prefixes).  They
            # are not the same byte string, so we must round-trip through
            # the Signature object to re-derive the canonical form.
            sig = Signature.from_bytes(w_bytes)
            leaves.append(_hash(sig.canonical_bytes()))

        if offset != len(witness_data):
            return False

        layer = list(leaves)
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(_hash(b"\x02witness_sentinel"))
            next_layer = []
            for i in range(0, len(layer), 2):
                next_layer.append(_hash(layer[i] + layer[i + 1]))
            layer = next_layer

        return layer[0] == expected_root
    except (struct.error, ValueError, IndexError):
        return False


def attach_block_witnesses(stripped_block, witness_data: bytes):
    """Reattach witness data to a stripped block."""
    from messagechain.core.block import Block
    import copy

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

    header = copy.deepcopy(stripped_block.header)

    restored = Block(
        header=header,
        transactions=restored_txs,
        validator_signatures=stripped_block.validator_signatures,
        slash_transactions=stripped_block.slash_transactions,
        attestations=stripped_block.attestations,
        transfer_transactions=stripped_block.transfer_transactions,
        governance_txs=stripped_block.governance_txs,
        authority_txs=stripped_block.authority_txs,
        stake_transactions=stripped_block.stake_transactions,
        unstake_transactions=stripped_block.unstake_transactions,
        finality_votes=stripped_block.finality_votes,
    )
    restored.block_hash = restored._compute_hash()
    return restored
