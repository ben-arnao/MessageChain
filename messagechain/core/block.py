"""
Block structure for MessageChain.

Each block contains a set of message transactions, linked to the previous
block via hash chaining. The Merkle root of all transaction hashes enables
efficient verification of transaction inclusion.
"""

import hashlib
import struct
import time
import json
from dataclasses import dataclass, field
from messagechain.config import (
    HASH_ALGO, HASH_VERSION_CURRENT,
    BLOCK_SERIALIZATION_VERSION,
    BLOCK_SERIALIZATION_VERSION_V1,
    BLOCK_SERIALIZATION_VERSION_V2,
    validate_block_serialization_version,
)
from messagechain.consensus.validator_versions import (
    CURRENT_VALIDATOR_VERSION,
    UNSIGNALLED as VALIDATOR_VERSION_UNSIGNALLED,
)
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.hashing import default_hash
from messagechain.crypto.keys import Signature

# Account count at which compute_state_root starts logging a scaling
# warning. See compute_state_root's docstring for context.
STATE_ROOT_WARN_THRESHOLD = 100_000


def _hash(data: bytes) -> bytes:
    return default_hash(data)


def _encode_optional_bundle(bundle) -> bytes:
    """Wire encoding for Block.archive_proof_bundle (optional scalar).

    Absent case is the hot path (non-challenge blocks pay only one
    byte).  Present case prefixes the canonical-bytes blob with a u32
    length so the decoder can skip past it without knowing the bundle's
    internal layout.
    """
    import struct as _struct
    if bundle is None:
        return b"\x00"
    blob = bundle.to_bytes()
    return b"\x01" + _struct.pack(">I", len(blob)) + blob


def _decode_optional_bundle(data: bytes, off: int):
    """Inverse of _encode_optional_bundle.  Returns (bundle, new_off).
    """
    import struct as _struct
    if off >= len(data):
        raise ValueError("Block blob truncated at archive_proof_bundle flag")
    flag = data[off]; off += 1
    if flag == 0:
        return None, off
    if flag != 1:
        raise ValueError(
            f"archive_proof_bundle flag must be 0 or 1, got {flag}"
        )
    if off + 4 > len(data):
        raise ValueError("Block blob truncated at archive_proof_bundle length")
    blob_len = _struct.unpack_from(">I", data, off)[0]; off += 4
    if off + blob_len > len(data):
        raise ValueError("Block blob truncated at archive_proof_bundle body")
    from messagechain.consensus.archive_challenge import ArchiveProofBundle
    bundle = ArchiveProofBundle.from_bytes(bytes(data[off:off + blob_len]))
    off += blob_len
    return bundle, off


def _encode_optional_inclusion_list(lst) -> bytes:
    """Wire encoding for Block.inclusion_list (optional scalar).

    Same shape as _encode_optional_bundle: 1 byte presence flag, then
    u32 length + canonical blob when present.  Hot path on blocks
    without an inclusion list pays the single zero byte.
    """
    import struct as _struct
    if lst is None:
        return b"\x00"
    blob = lst.to_bytes()
    return b"\x01" + _struct.pack(">I", len(blob)) + blob


def _decode_optional_inclusion_list(data: bytes, off: int):
    """Inverse of _encode_optional_inclusion_list.  Returns (lst, new_off)."""
    import struct as _struct
    if off >= len(data):
        raise ValueError("Block blob truncated at inclusion_list flag")
    flag = data[off]; off += 1
    if flag == 0:
        return None, off
    if flag != 1:
        raise ValueError(
            f"inclusion_list flag must be 0 or 1, got {flag}"
        )
    if off + 4 > len(data):
        raise ValueError("Block blob truncated at inclusion_list length")
    blob_len = _struct.unpack_from(">I", data, off)[0]; off += 4
    if off + blob_len > len(data):
        raise ValueError("Block blob truncated at inclusion_list body")
    from messagechain.consensus.inclusion_list import InclusionList
    lst = InclusionList.from_bytes(bytes(data[off:off + blob_len]))
    off += blob_len
    return lst, off


def _encode_acks_observed(acks: list) -> bytes:
    """Wire encoding for Block.acks_observed_this_block.

    Each entry is a full signed ``SubmissionAck`` so a proposer must
    PROVE discharge (signature verifies under the target validator's
    registered receipt-subtree root), not just claim it by echoing a
    request_hash any gossip observer could compute.

    Layout: u32 count followed by N × (u32 ack_blob_len + ack_blob).
    Canonical-form enforcement (sort by request_hash ascending, no
    duplicate request_hash, per-block cap) lives in ``validate_block``.
    """
    import struct as _struct
    from messagechain.consensus.witness_submission import SubmissionAck
    out = bytearray(_struct.pack(">I", len(acks)))
    for ack in acks:
        if not isinstance(ack, SubmissionAck):
            raise TypeError(
                f"ack entry must be SubmissionAck, got {type(ack).__name__}"
            )
        blob = ack.to_bytes()
        out += _struct.pack(">I", len(blob))
        out += blob
    return bytes(out)


def _decode_acks_observed(data: bytes, off: int):
    """Inverse of _encode_acks_observed.  Returns (acks, new_off).

    Each entry decodes as a full ``SubmissionAck`` -- the decoded ack's
    hash integrity is verified inside SubmissionAck.from_bytes; caller
    must still run signature + root-binding checks at validate time.
    """
    import struct as _struct
    from messagechain.consensus.witness_submission import SubmissionAck
    if off + 4 > len(data):
        raise ValueError("Block blob truncated at acks_observed count")
    n = _struct.unpack_from(">I", data, off)[0]; off += 4
    acks: list = []
    for _ in range(n):
        if off + 4 > len(data):
            raise ValueError(
                "Block blob truncated at acks_observed entry length"
            )
        blob_len = _struct.unpack_from(">I", data, off)[0]; off += 4
        if off + blob_len > len(data):
            raise ValueError(
                "Block blob truncated mid-acks_observed entry"
            )
        acks.append(SubmissionAck.from_bytes(bytes(data[off:off + blob_len])))
        off += blob_len
    return acks, off


def compute_merkle_root(tx_hashes: list[bytes]) -> bytes:
    """Compute Merkle root from a list of transaction hashes.

    Uses tagged internal nodes (prefixed with 0x01) and tagged leaf nodes
    (prefixed with 0x00) to prevent second-preimage attacks via
    duplicate-last-element padding (CVE-2012-2459). Odd-length layers
    are padded with a sentinel value rather than duplicating the last
    element, so [A, B, C] and [A, B, C, C] produce different roots.
    """
    if not tx_hashes:
        return _hash(b"empty")

    # Tag leaves with 0x00 prefix for domain separation
    layer = [_hash(b"\x00" + h) for h in tx_hashes]

    while len(layer) > 1:
        # Pad odd layers with a sentinel (not a duplicate)
        if len(layer) % 2 == 1:
            layer.append(_hash(b"\x02sentinel"))
        next_layer = []
        for i in range(0, len(layer), 2):
            # Tag internal nodes with 0x01 prefix
            combined = _hash(b"\x01" + layer[i] + layer[i + 1])
            next_layer.append(combined)
        layer = next_layer

    return layer[0]


def canonical_block_tx_hashes(block) -> list[bytes]:
    """Return the ordered list of tx hashes that feed the block merkle root.

    Single source of truth for the four call sites that used to
    independently rebuild this list:
      * consensus.pos.create_block   (proposer side)
      * core.blockchain.validate_block
      * core.blockchain.validate_block_standalone   (fork path)
      * core.spv.generate_merkle_proof              (SPV proof builder)

    Drift between these bit an SPV-correctness bug (proofs built from
    only 2 of the 10+ tx variants) AND a fork-validator consensus
    disagreement (merkle recompute used 6 of 10+ variants, so any
    block carrying finality_votes / custody_proofs / censorship /
    bogus-rejection evidence was spuriously rejected when re-validated
    via the fork path).  Routing every caller through this helper
    means a future tx-variant addition only has to update one place.

    Order is load-bearing — it matches the legacy on-chain merkle
    roots, so this function MUST NOT reorder existing entries.  Append-
    only for new variants.

    The archive_proof_bundle hash is auto-derived from custody_proofs
    when they exist (not read from `block.archive_proof_bundle`), so
    the proposer and the validator agree on the bundle commitment
    regardless of whether the proposer assembled the bundle eagerly or
    left it for the helper to derive.
    """
    # getattr with default-[] so a Block variant that hasn't populated
    # an attribute (tests, forward-compat) doesn't KeyError here.
    msg_txs      = list(getattr(block, "transactions", []) or [])
    xfer_txs     = list(getattr(block, "transfer_transactions", []) or [])
    slash_txs    = list(getattr(block, "slash_transactions", []) or [])
    gov_txs      = list(getattr(block, "governance_txs", []) or [])
    auth_txs     = list(getattr(block, "authority_txs", []) or [])
    stake_txs    = list(getattr(block, "stake_transactions", []) or [])
    unstake_txs  = list(getattr(block, "unstake_transactions", []) or [])
    fin_votes    = list(getattr(block, "finality_votes", []) or [])
    cust_proofs  = list(getattr(block, "custody_proofs", []) or [])
    cens_txs     = list(getattr(block, "censorship_evidence_txs", []) or [])
    bogus_txs    = list(getattr(block, "bogus_rejection_evidence_txs", []) or [])
    ilv_txs      = list(
        getattr(block, "inclusion_list_violation_evidence_txs", []) or []
    )
    inclusion_list_obj = getattr(block, "inclusion_list", None)
    acks_observed = list(
        getattr(block, "acks_observed_this_block", []) or []
    )

    out: list[bytes] = []
    out.extend(tx.tx_hash for tx in msg_txs)
    out.extend(tx.tx_hash for tx in xfer_txs)
    out.extend(tx.tx_hash for tx in slash_txs)
    out.extend(tx.tx_hash for tx in gov_txs)
    out.extend(tx.tx_hash for tx in auth_txs)
    out.extend(tx.tx_hash for tx in stake_txs)
    out.extend(tx.tx_hash for tx in unstake_txs)
    # Finality votes commit via consensus_hash() (not tx_hash — they
    # aren't transactions).  Binding via consensus_hash ensures a
    # relayer cannot strip or rewrite a vote without invalidating
    # the proposer's signature.
    out.extend(v.consensus_hash() for v in fin_votes)
    # CustodyProof commits via its identity hash for the same reason.
    out.extend(p.tx_hash for p in cust_proofs)
    out.extend(tx.tx_hash for tx in cens_txs)
    out.extend(tx.tx_hash for tx in bogus_txs)
    # InclusionListViolationEvidenceTx commits via tx_hash.  Order
    # follows the wire-format slot order — append-only, never reorder.
    out.extend(tx.tx_hash for tx in ilv_txs)
    # The InclusionList itself (the consensus-objective forced-inclusion
    # commitment) commits via its list_hash.  At most one per block, so
    # contribute exactly one hash on populated blocks and zero
    # otherwise.  Folding it into the merkle_root means a byzantine
    # relayer cannot strip or swap the list without invalidating the
    # proposer's header signature — same hygiene as every other
    # block-body type.
    if inclusion_list_obj is not None:
        out.append(inclusion_list_obj.list_hash)

    # acks_observed_this_block: every observed SubmissionAck contributes
    # its ``ack_hash`` so a relayer cannot strip or mutate the list
    # without invalidating the proposer's signature (same hygiene as
    # every other block-body type).  Append in the on-wire canonical
    # order (sorted by ack.request_hash ascending) so two nodes building
    # the same merkle root from the same multiset of acks land on the
    # same value.
    out.extend(
        a.ack_hash
        for a in sorted(acks_observed, key=lambda x: x.request_hash)
    )

    # Archive-proof bundle (aggregated custody commitment) — derived,
    # not read from the block's optional bundle slot, so the proposer
    # cannot smuggle a mismatched bundle past the merkle check.  When
    # cust_proofs is empty there's nothing to commit to, so no hash is
    # appended.
    if cust_proofs:
        # Lazy import to avoid a consensus<->core import cycle.
        from messagechain.consensus.archive_challenge import (
            ArchiveProofBundle as _ArchiveProofBundle,
        )
        out.append(_ArchiveProofBundle.from_proofs(cust_proofs).tx_hash)

    return out


def _deserialize_authority_tx(data: dict):
    """Rehydrate an authority-related transaction by its "type" tag.

    Authority txs are consensus-visible operations on an entity's key
    material: set-authority-key (promote cold key), revoke (emergency
    kill-switch), and key-rotation (leaf-exhaustion recovery). They
    share a block slot so peers learn about key-state changes through
    the same gossip path as message and transfer txs.
    """
    from messagechain.core.authority_key import SetAuthorityKeyTransaction
    from messagechain.core.emergency_revoke import RevokeTransaction
    from messagechain.core.key_rotation import KeyRotationTransaction
    from messagechain.core.receipt_subtree_root import (
        SetReceiptSubtreeRootTransaction,
    )
    from messagechain.core.release_announce import (
        ReleaseAnnounceTransaction,
    )
    tag = data.get("type")
    if tag == "set_authority_key":
        return SetAuthorityKeyTransaction.deserialize(data)
    if tag == "revoke":
        return RevokeTransaction.deserialize(data)
    if tag == "key_rotation":
        return KeyRotationTransaction.deserialize(data)
    if tag == "set_receipt_subtree_root":
        return SetReceiptSubtreeRootTransaction.deserialize(data)
    if tag == "release_announce":
        return ReleaseAnnounceTransaction.deserialize(data)
    raise ValueError(f"Unknown authority tx type: {tag!r}")


def _deserialize_governance_tx(data: dict):
    """Rehydrate a governance transaction based on its "type" tag.

    Delegates to the concrete class's deserialize method so hash/signature
    integrity checks run the same way they would for a standalone tx.
    """
    from messagechain.governance.governance import (
        ProposalTransaction, VoteTransaction,
        TreasurySpendTransaction,
    )
    tag = data.get("type")
    if tag == "governance_proposal":
        return ProposalTransaction.deserialize(data)
    if tag == "governance_vote":
        return VoteTransaction.deserialize(data)
    if tag == "treasury_spend":
        return TreasurySpendTransaction.deserialize(data)
    raise ValueError(f"Unknown governance tx type: {tag!r}")


def compute_state_root(
    balances: dict[bytes, int],
    nonces: dict[bytes, int],
    staked: dict[bytes, int],
    *,
    authority_keys: dict[bytes, bytes] | None = None,
    public_keys: dict[bytes, bytes] | None = None,
    leaf_watermarks: dict[bytes, int] | None = None,
    key_rotation_counts: dict[bytes, int] | None = None,
    revoked_entities: "set[bytes] | frozenset[bytes] | None" = None,
    slashed_validators: "set[bytes] | frozenset[bytes] | None" = None,
) -> bytes:
    """Compute a Merkle commitment to the full account state.

    Thin wrapper over messagechain.core.state_tree.compute_state_root.
    The real implementation is a Sparse Merkle Tree (O(TREE_DEPTH)
    per update, replacing the earlier O(N log N) full rebuild).

    Prefer `Blockchain.state_tree.root()` in hot paths — this function
    builds a fresh tree from scratch every call. It exists for callers
    that only have dicts in hand (tests, one-shot light-client
    commitments) and for backward compatibility with import sites that
    already reference `block.compute_state_root`.
    """
    # Lazy import to avoid a circular dependency with state_tree which
    # needs nothing from block.py — keeps the module graph acyclic.
    from messagechain.core.state_tree import compute_state_root as _impl
    return _impl(
        balances, nonces, staked,
        authority_keys=authority_keys,
        public_keys=public_keys,
        leaf_watermarks=leaf_watermarks,
        key_rotation_counts=key_rotation_counts,
        revoked_entities=revoked_entities,
        slashed_validators=slashed_validators,
    )


@dataclass
class BlockHeader:
    version: int
    block_number: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: float
    proposer_id: bytes
    state_root: bytes = b"\x00" * 32  # Merkle root of account state
    witness_root: bytes = b"\x00" * 32  # Merkle root over tx witness data (sigs + auth paths)
    randao_mix: bytes = b"\x00" * 32  # accumulated RANDAO entropy (post-sign derived)
    proposer_signature: Signature | None = None
    # Crypto-agility: identifies the hash algorithm used for this block's
    # block_hash (over the header) and tx_root. Carried on every header so a
    # governance proposal can widen the accepted set for a future scheme
    # without a chain reset.  See config.HASH_VERSION_* and
    # validate_hash_version.
    hash_version: int = HASH_VERSION_CURRENT
    # Inclusion attestation: Merkle root of proposer's mempool tx hashes
    # at proposal time.  Committed via signable_data so the proposer's
    # block signature covers it transitively — no separate snapshot sig.
    mempool_snapshot_root: bytes = b"\x00" * 32
    # On-chain periodic state-root checkpoint — see
    # config.CHECKPOINT_INTERVAL / is_state_root_checkpoint_block.  Zero
    # on non-checkpoint blocks; at a checkpoint height, commits to the
    # full snapshot root (storage.state_snapshot.compute_state_root)
    # over the post-application state.  Lets a future joiner trust a
    # finalized checkpoint block's header as ground-truth for a matching
    # state-snapshot download, without downloading full history.
    # Archive operators still retain every block — this is purely a
    # sync UX affordance.
    state_root_checkpoint: bytes = b"\x00" * 32
    # Validator version signalling (Fork 1, audit finding #2): a uint16
    # stamping the proposer's running release.  Carried only in V2
    # block serialization; V1 blocks decode with this field set to
    # UNSIGNALLED (0).  Future forks (Fork 2 = the active-set liveness
    # fallback) consume this field as their activation gate.  Default
    # to UNSIGNALLED so test fixtures and pre-Fork-1 historical blocks
    # round-trip cleanly; the block producer overrides to
    # CURRENT_VALIDATOR_VERSION on every freshly-built block.
    validator_version: int = VALIDATOR_VERSION_UNSIGNALLED

    def _ser_version_for_height(self) -> int:
        """Pick the wire-format version for a block at this height.

        Pre-VERSION_SIGNALING_HEIGHT blocks were originally serialized
        and signed under V1.  Re-hashing them under V2 (which would
        append a 2-byte validator_version field to signable_data) would
        give a different block_hash than the network agreed on, which
        breaks the prev-hash chain and the proposer signature stored on
        disk.  So this header self-selects V1 for any height below the
        fork activation; post-activation, V2.

        The block envelope (Block.to_bytes/from_bytes) carries the
        ser_version explicitly in its leading byte so re-encoded historic
        blocks emit the same V1 they were originally produced under.
        Same for the proposer signature: signable_data() must commit to
        the SAME bytes the proposer originally signed.
        """
        from messagechain.config import VERSION_SIGNALING_HEIGHT
        if self.block_number >= VERSION_SIGNALING_HEIGHT:
            return BLOCK_SERIALIZATION_VERSION_V2
        return BLOCK_SERIALIZATION_VERSION_V1

    def signable_data(self, ser_version: int | None = None) -> bytes:
        # NOTE: randao_mix is intentionally NOT included here. It is derived
        # from the proposer signature (which is itself over signable_data),
        # so including it would create a circular dependency. The randao_mix
        # is bound to the block via _compute_hash() instead.
        #
        # hash_version is committed here so the header hash itself is
        # tamper-evident against a version swap: flipping the byte changes
        # the hash, breaking the prev_hash chain and the proposer signature.
        # state_root_checkpoint is bound into signable_data so the
        # proposer's signature covers it transitively — a relay that
        # mutates the checkpoint field in transit invalidates the
        # signature and the block is rejected.  Zero on non-checkpoint
        # heights (the common case), so the field contributes no
        # entropy there and the hash stays identical to a checkpoint-
        # field-less legacy header whose trailing bytes were 32 zeros.
        # validator_version is committed into signable_data only on
        # V2 wire format so V1 blocks (the entire pre-Fork-1 chain
        # history) keep their existing hash and the proposer signature
        # over them remains valid.  At V2, the field is appended to
        # the end so the prefix is byte-identical to V1 -- this is
        # not a load-bearing property (the ser_version is committed by
        # the block envelope) but it keeps the diff minimal.
        if ser_version is None:
            ser_version = self._ser_version_for_height()
        base = (
            struct.pack(">I", self.version)
            + struct.pack(">B", self.hash_version)
            + struct.pack(">Q", self.block_number)
            + self.prev_hash
            + self.merkle_root
            + self.state_root
            + self.witness_root
            + struct.pack(">Q", int(self.timestamp))
            + self.proposer_id
            + self.mempool_snapshot_root
            + self.state_root_checkpoint
        )
        if ser_version == BLOCK_SERIALIZATION_VERSION_V2:
            return base + struct.pack(">H", self.validator_version)
        return base

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "hash_version": self.hash_version,
            "block_number": self.block_number,
            "prev_hash": self.prev_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "state_root": self.state_root.hex(),
            "witness_root": self.witness_root.hex(),
            "timestamp": self.timestamp,
            "proposer_id": self.proposer_id.hex(),
            "randao_mix": self.randao_mix.hex(),
            "mempool_snapshot_root": self.mempool_snapshot_root.hex(),
            "state_root_checkpoint": self.state_root_checkpoint.hex(),
            "validator_version": self.validator_version,
            "proposer_signature": self.proposer_signature.serialize() if self.proposer_signature else None,
        }

    def to_bytes(self, ser_version: int | None = None) -> bytes:
        """Compact binary encoding for storage/wire.

        Layout (V2; V1 omits the trailing validator_version field):
            u32  version
            u8   hash_version        <- crypto-agility register
            u64  block_number
            32   prev_hash
            32   merkle_root
            32   state_root
            32   witness_root        <- Merkle root over tx witness data
            f64  timestamp
            32   proposer_id
            32   randao_mix
            32   mempool_snapshot_root   <- retired (always zero on new blocks; retained for historical block compat)
            32   state_root_checkpoint   <- periodic snapshot commitment
            u16  validator_version       <- V2 ONLY (Fork 1 -- audit finding #2)
            u32  sig_blob_len  (0 = no proposer signature)
            N    sig_blob

        hash_version sits right after `version` so a header blob is
        unambiguously one flavor of hash commitment end-to-end -- a
        validator's decoder reads the version before any 32-byte hash
        field and can dispatch when multiple schemes are active.

        state_root_checkpoint trails mempool_snapshot_root so the field
        order here matches the signable_data() layout exactly, keeping
        the wire-format and the signed-payload layout aligned.

        validator_version is appended only when ser_version is V2.  The
        block envelope (Block.to_bytes) carries the ser_version in its
        leading byte and threads it down here, so the same BlockHeader
        instance can serialize cleanly under either format -- which is
        what lets a node running new code re-emit the entire pre-Fork-1
        chain history under V1 if it ever needs to.
        """
        if ser_version is None:
            ser_version = self._ser_version_for_height()
        if self.proposer_signature is None:
            sig_blob = b""
        else:
            sig_blob = self.proposer_signature.to_bytes()
        parts = [
            struct.pack(">I", self.version),
            struct.pack(">B", self.hash_version),
            struct.pack(">Q", self.block_number),
            self.prev_hash,
            self.merkle_root,
            self.state_root,
            self.witness_root,
            struct.pack(">d", float(self.timestamp)),
            self.proposer_id,
            self.randao_mix,
            self.mempool_snapshot_root,
            self.state_root_checkpoint,
        ]
        if ser_version == BLOCK_SERIALIZATION_VERSION_V2:
            parts.append(struct.pack(">H", self.validator_version))
        parts.append(struct.pack(">I", len(sig_blob)))
        parts.append(sig_blob)
        return b"".join(parts)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        ser_version: int | None = None,
    ) -> "BlockHeader":
        off = 0
        # When the caller hasn't pinned a ser_version (e.g. tests calling
        # BlockHeader.from_bytes(blob) directly without going through the
        # Block envelope), peek at the block_number to decide V1 vs V2.
        # Layout puts block_number at offset 4+1=5: after u32 version and
        # u8 hash_version.  Self-describing via block_number is safe
        # because block_number is committed inside signable_data() and
        # any forgery breaks the proposer signature.
        if ser_version is None:
            from messagechain.config import VERSION_SIGNALING_HEIGHT
            if len(data) < 4 + 1 + 8:
                # Not enough bytes to even peek; fall through to V1
                # so the regular truncation error fires below.
                ser_version = BLOCK_SERIALIZATION_VERSION_V1
            else:
                peeked_block_number = struct.unpack_from(">Q", data, 4 + 1)[0]
                if peeked_block_number >= VERSION_SIGNALING_HEIGHT:
                    ser_version = BLOCK_SERIALIZATION_VERSION_V2
                else:
                    ser_version = BLOCK_SERIALIZATION_VERSION_V1
        # +1 byte for the u8 hash_version field (crypto agility).
        # +32 bytes for the witness_root field.
        # +32 bytes for the mempool_snapshot_root field.
        # +32 bytes for the state_root_checkpoint field (see
        # config.CHECKPOINT_INTERVAL) -- zero on non-checkpoint heights
        # so the minimum stays 32 bytes regardless of whether the block
        # is a checkpoint.
        # +2 bytes for the V2-only validator_version field (Fork 1).
        expected_min = 4 + 1 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 32 + 32 + 32 + 4
        if ser_version == BLOCK_SERIALIZATION_VERSION_V2:
            expected_min += 2
        if len(data) < expected_min:
            raise ValueError("BlockHeader blob too short")
        version = struct.unpack_from(">I", data, off)[0]; off += 4
        hash_version = struct.unpack_from(">B", data, off)[0]; off += 1
        # Reject unknown hash versions at decode time so a malformed blob
        # never reaches validate_block.  The consensus-layer check is still
        # the primary gate; this one cuts off DoS via spray-and-pray blobs.
        from messagechain.config import validate_hash_version
        ok, reason = validate_hash_version(hash_version)
        if not ok:
            raise ValueError(f"Invalid block header: {reason}")
        block_number = struct.unpack_from(">Q", data, off)[0]; off += 8
        prev_hash = bytes(data[off:off + 32]); off += 32
        merkle_root = bytes(data[off:off + 32]); off += 32
        state_root = bytes(data[off:off + 32]); off += 32
        witness_root = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        proposer_id = bytes(data[off:off + 32]); off += 32
        randao_mix = bytes(data[off:off + 32]); off += 32
        mempool_snapshot_root = bytes(data[off:off + 32]); off += 32
        state_root_checkpoint = bytes(data[off:off + 32]); off += 32
        if ser_version == BLOCK_SERIALIZATION_VERSION_V2:
            validator_version = struct.unpack_from(">H", data, off)[0]; off += 2
        else:
            # V1 (legacy): no validator_version on the wire.  Default to
            # UNSIGNALLED so future gates that read this field can
            # distinguish "pre-Fork-1 historical block" (no signal) from
            # "modern block whose proposer chose not to signal" (which
            # can't happen -- the producer always stamps a real value).
            validator_version = VALIDATOR_VERSION_UNSIGNALLED
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len > len(data):
            raise ValueError("BlockHeader truncated at signature")
        if sig_len == 0:
            proposer_signature = None
        else:
            proposer_signature = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        if off != len(data):
            raise ValueError("BlockHeader has trailing bytes")
        return cls(
            version=version, block_number=block_number,
            prev_hash=prev_hash, merkle_root=merkle_root,
            state_root=state_root, witness_root=witness_root,
            timestamp=timestamp,
            proposer_id=proposer_id, randao_mix=randao_mix,
            proposer_signature=proposer_signature,
            hash_version=hash_version,
            mempool_snapshot_root=mempool_snapshot_root,
            state_root_checkpoint=state_root_checkpoint,
            validator_version=validator_version,
        )

    @classmethod
    def deserialize(cls, data: dict) -> "BlockHeader":
        # Default missing hash_version to HASH_VERSION_CURRENT so pre-
        # migration dicts round-trip cleanly; a present-but-unknown value
        # falls through to validate_block's consensus check and is rejected
        # there with a human-readable reason.
        #
        # state_root_checkpoint defaults to 32 zero bytes when absent so
        # pre-checkpoint-field dicts round-trip cleanly.  Non-checkpoint
        # blocks always carry the zero value anyway, so the default
        # produces the identical header the producer intended — not a
        # silent format change.
        return cls(
            version=data["version"],
            block_number=data["block_number"],
            prev_hash=bytes.fromhex(data["prev_hash"]),
            merkle_root=bytes.fromhex(data["merkle_root"]),
            timestamp=data["timestamp"],
            proposer_id=bytes.fromhex(data["proposer_id"]),
            state_root=bytes.fromhex(data["state_root"]) if data.get("state_root") else b"\x00" * 32,
            witness_root=bytes.fromhex(data["witness_root"]) if data.get("witness_root") else b"\x00" * 32,
            randao_mix=bytes.fromhex(data["randao_mix"]) if data.get("randao_mix") else b"\x00" * 32,
            proposer_signature=Signature.deserialize(data["proposer_signature"]) if data.get("proposer_signature") else None,
            hash_version=data.get("hash_version", HASH_VERSION_CURRENT),
            mempool_snapshot_root=bytes.fromhex(data["mempool_snapshot_root"]) if data.get("mempool_snapshot_root") else b"\x00" * 32,
            state_root_checkpoint=bytes.fromhex(data["state_root_checkpoint"]) if data.get("state_root_checkpoint") else b"\x00" * 32,
            # Pre-Fork-1 dicts have no validator_version key; default to
            # UNSIGNALLED so existing on-disk JSON round-trips cleanly.
            validator_version=data.get(
                "validator_version", VALIDATOR_VERSION_UNSIGNALLED,
            ),
        )


@dataclass
class Block:
    header: BlockHeader
    transactions: list[MessageTransaction]
    validator_signatures: list[tuple[bytes, Signature]] = field(default_factory=list)
    slash_transactions: list = field(default_factory=list)  # list[SlashTransaction]
    attestations: list = field(default_factory=list)  # list[Attestation] for parent block
    transfer_transactions: list = field(default_factory=list)  # list[TransferTransaction]
    # On-chain governance traffic: proposals, votes, and treasury-spend
    # proposals.  Each carries a "type" tag in its serialized form that
    # the block pipeline dispatches on.
    governance_txs: list = field(default_factory=list)
    # Authority-key traffic: SetAuthorityKey (hot -> cold promotion), Revoke
    # (emergency kill-switch, signed by cold), KeyRotation (leaf-exhaustion
    # migration). Block-included so every peer applies the same state
    # transitions — without this, a SetAuthorityKey or Revoke on one node
    # would never propagate to the rest of the network, defeating the
    # security model entirely.
    authority_txs: list = field(default_factory=list)
    # On-chain staking traffic: StakeTransaction locks a validator's liquid
    # tokens as stake.  Block-included so every peer agrees on the validator
    # set — previously the RPC path queued these in server-local state and
    # they never propagated, breaking consensus on who can propose/attest.
    stake_transactions: list = field(default_factory=list)
    # Unstake txs are on-chain because unbonding releases stake weight
    # deterministically across all peers — the validator set must agree
    # on who is unbonding and when.  Same block-pipeline shape as
    # stake_transactions but dispatched to supply.unstake on apply.
    unstake_transactions: list = field(default_factory=list)
    # (The explicit RegistrationTransaction field was removed in the
    # receive-to-exist refactor.  An entity now enters chain state
    # implicitly when it first RECEIVES a transfer, and its pubkey is
    # installed during its FIRST outgoing transfer via the
    # `TransferTransaction.sender_pubkey` reveal.  Removing the field
    # is a consensus-format change — blocks produced by pre-refactor
    # nodes cannot round-trip through the new decoder.)
    # Long-range-attack defense: FinalityVotes signed by validators
    # that commit to a specific block hash at a specific height.  When
    # >= 2/3 of stake has signed votes for a block and those votes
    # have been included in any later block, the target block becomes
    # FINALIZED — no subsequent reorg may revert it regardless of
    # stake weight.  Proposers that include votes earn a small bounty
    # from treasury (FINALITY_VOTE_INCLUSION_REWARD).  Defense is
    # additive to the existing attestation-layer finality and
    # persists across restart, so a cold-booted node inherits the
    # chain's irreversibility commitments.
    finality_votes: list = field(default_factory=list)  # list[FinalityVote]
    # Proof-of-Custody archive-reward proofs.  Non-empty ONLY on
    # challenge blocks (heights satisfying is_archive_challenge_block
    # in messagechain.config).  Every entry's .tx_hash is folded into
    # merkle_root so a byzantine relayer cannot strip or mutate proofs
    # in transit — the hygiene pattern mirrors slash_transactions and
    # finality_votes.  See messagechain.consensus.archive_challenge.
    custody_proofs: list = field(default_factory=list)  # list[CustodyProof]
    # Censorship-evidence txs: first-class block slot so every peer
    # processes the same admissions.  An evidence tx carries a signed
    # submission receipt + the receipted MessageTransaction; when
    # admitted, the CensorshipEvidenceProcessor marks it pending and
    # begins a maturity countdown.  See
    # messagechain.consensus.censorship_evidence.
    censorship_evidence_txs: list = field(default_factory=list)
    # Bogus-rejection evidence txs: first-class block slot, distinct
    # from censorship_evidence_txs.  An entry carries a SignedRejection
    # + the rejected MessageTransaction; the chain re-verifies the
    # tx's signature against its on-chain pubkey and (for the
    # currently-slashable subset of reason codes) immediately slashes
    # the issuer if the rejection was bogus.  One-phase, no maturity
    # window — see messagechain.consensus.bogus_rejection_evidence.
    bogus_rejection_evidence_txs: list = field(default_factory=list)
    # Inclusion-list violation evidence txs: first-class block slot.
    # An entry carries the full InclusionList that mandated a tx + the
    # omitted tx_hash + the accused proposer's height + entity_id.  At
    # admission, the chain slashes the proposer
    # INCLUSION_VIOLATION_SLASH_BPS of stake (burned, no finder reward)
    # via process_inclusion_list_violation.  Double-slash defence via
    # InclusionListProcessor.processed_violations (keyed by
    # (list_hash, tx_hash, proposer_id) — list_hash participates so
    # two overlapping lists that both mandated a tx each get their
    # own slash on omission).
    # See messagechain.consensus.inclusion_list.
    inclusion_list_violation_evidence_txs: list = field(default_factory=list)
    # The InclusionList PUBLISHED at this height, applying forward to
    # the next INCLUSION_LIST_WINDOW blocks.  At most one per block.
    # None on the common path; populated only when the proposer has
    # collected >= 2/3 of attester-stake's mempool reports for at least
    # one tx_hash.  list_hash folds into merkle_root via
    # canonical_block_tx_hashes so a relayer cannot strip or mutate the
    # list in transit.  See messagechain.consensus.inclusion_list.
    inclusion_list: object = None  # Optional[InclusionList]
    # Aggregated commitment to this epoch's archive-custody participants.
    # Auto-derived from custody_proofs when left as None on construction
    # (see __post_init__) so proposers and tests that only populate
    # custody_proofs inherit a consistent bundle for free.  When
    # custody_proofs is empty this field stays None — nothing to commit
    # to.  Tx_hash folds into merkle_root (same hygiene as every other
    # block-body type) so a relayer cannot strip or mutate the bundle
    # without invalidating the proposer's signature.  Lives apart from
    # custody_proofs because a future pruning iteration will strip the
    # full proofs after the submission window closes while keeping the
    # bundle permanently — the bundle is the post-pruning residue that
    # late joiners can still use to audit "validator X was credited in
    # epoch E."
    archive_proof_bundle: object = None  # Optional[ArchiveProofBundle]
    # Witness-ack aggregation: list of 32-byte `request_hash`es whose
    # corresponding SubmissionAck the proposer observed in their local
    # WitnessObservationStore.  Validators apply each entry by writing
    # `(request_hash, block.height)` into `Blockchain.witness_ack_registry`
    # so a later NonResponseEvidenceTx for the same request_hash is
    # rejected (the obligation was met).
    #
    # Soft-vote semantics: the receiving validator is NOT required to
    # have observed the same ack locally — proposer mempool views are
    # subjective, and a mismatch would otherwise fork the chain.  A
    # request_hash with no corresponding outstanding obligation is also
    # acceptable (could be a stale ack a witness saw but the chain
    # already aged out).
    #
    # Wire format: u32 count followed by N × 32-byte request_hash.
    # Canonical ordering: sorted by raw bytes ascending; duplicates
    # rejected by `validate_block` so the on-wire form is unambiguous.
    # Cap at MAX_ACKS_PER_BLOCK to keep block bandwidth bounded.
    # Folded into `merkle_root` via `canonical_block_tx_hashes` so a
    # relayer cannot strip or mutate the list in transit without
    # invalidating the proposer's signature.
    acks_observed_this_block: list = field(default_factory=list)
    block_hash: bytes = b""

    def __post_init__(self):
        # Auto-derive the bundle from custody_proofs on the common path
        # where a proposer only populated custody_proofs.  Explicit
        # bundles (incl. deliberately wrong ones from adversarial tests)
        # are left alone; block validation enforces the derivation rule
        # downstream.
        if self.archive_proof_bundle is None and self.custody_proofs:
            from messagechain.consensus.archive_challenge import (
                ArchiveProofBundle,
            )
            self.archive_proof_bundle = ArchiveProofBundle.from_proofs(
                self.custody_proofs,
            )
        if not self.block_hash:
            self.block_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        # Bind both signable_data and randao_mix into block_hash. randao_mix
        # is derived from the proposer signature post-signing, so it cannot
        # live in signable_data, but it must still be tamper-evident.
        return _hash(self.header.signable_data() + self.header.randao_mix)

    def serialize(self) -> dict:
        result = {
            "header": self.header.serialize(),
            "transactions": [tx.serialize() for tx in self.transactions],
            "validator_signatures": [
                {"entity_id": eid.hex(), "signature": sig.serialize()}
                for eid, sig in self.validator_signatures
            ],
            "block_hash": self.block_hash.hex(),
        }
        if self.slash_transactions:
            result["slash_transactions"] = [tx.serialize() for tx in self.slash_transactions]
        if self.attestations:
            result["attestations"] = [att.serialize() for att in self.attestations]
        if self.transfer_transactions:
            result["transfer_transactions"] = [tx.serialize() for tx in self.transfer_transactions]
        if self.governance_txs:
            result["governance_txs"] = [tx.serialize() for tx in self.governance_txs]
        if self.authority_txs:
            result["authority_txs"] = [tx.serialize() for tx in self.authority_txs]
        if self.stake_transactions:
            result["stake_transactions"] = [tx.serialize() for tx in self.stake_transactions]
        if self.unstake_transactions:
            result["unstake_transactions"] = [tx.serialize() for tx in self.unstake_transactions]
        if self.finality_votes:
            result["finality_votes"] = [v.serialize() for v in self.finality_votes]
        if self.custody_proofs:
            result["custody_proofs"] = [p.serialize() for p in self.custody_proofs]
        if self.censorship_evidence_txs:
            result["censorship_evidence_txs"] = [
                tx.serialize() for tx in self.censorship_evidence_txs
            ]
        if self.bogus_rejection_evidence_txs:
            result["bogus_rejection_evidence_txs"] = [
                tx.serialize() for tx in self.bogus_rejection_evidence_txs
            ]
        if self.inclusion_list_violation_evidence_txs:
            result["inclusion_list_violation_evidence_txs"] = [
                tx.serialize()
                for tx in self.inclusion_list_violation_evidence_txs
            ]
        if self.inclusion_list is not None:
            result["inclusion_list"] = self.inclusion_list.serialize()
        if self.acks_observed_this_block:
            # Each entry is a full SubmissionAck so the proposer must
            # PROVE discharge (signature verifies under the target
            # validator's registered receipt-subtree root).  Serialized
            # via SubmissionAck.serialize() -- a dict shape, not raw
            # hex, so the cross-chain wire stays self-describing.  Empty
            # list omitted entirely.
            result["acks_observed_this_block"] = [
                ack.serialize() for ack in self.acks_observed_this_block
            ]
        if self.archive_proof_bundle is not None:
            # Serialized as hex of canonical bytes — a scalar blob, not
            # a list; the bundle is a single aggregated commitment per
            # block rather than a collection.
            result["archive_proof_bundle"] = (
                self.archive_proof_bundle.to_bytes().hex()
            )
        return result

    def to_bytes(self, state=None) -> bytes:
        """Compact binary encoding for storage/wire.

        Every tx-list field is length-prefixed — empty lists contribute
        exactly 4 bytes (a zero count) regardless of whether the
        corresponding dict-format serialize() would have omitted them.
        This keeps the decoder straight-line and avoids an optional-field
        bitmap.

        Authority and governance tx lists carry polymorphic tx types,
        so each element in those lists is prefixed with a 1-byte
        discriminator (see _encode_authority_tx / _encode_governance_tx).

        Layout:
            header_blob_len  (u32)  + header_blob
            tx_count         (u32)  + N x (tx_len u32 + tx_blob)
            vsig_count       (u32)  + N x (32 entity_id + sig_len u32 + sig_blob)
            slash_count      (u32)  + N x (slash_len u32 + slash_blob)
            att_count        (u32)  + N x (att_len u32 + att_blob)
            xfer_count       (u32)  + N x (xfer_len u32 + xfer_blob)
            gov_count        (u32)  + N x (u8 kind + gov_len u32 + gov_blob)
            auth_count       (u32)  + N x (u8 kind + auth_len u32 + auth_blob)
            stake_count      (u32)  + N x (stake_len u32 + stake_blob)
            unstake_count    (u32)  + N x (unstake_len u32 + unstake_blob)
            fvote_count      (u32)  + N x (fvote_len u32 + fvote_blob)
            cproof_count     (u32)  + N x (cproof_len u32 + cproof_blob)
            cev_count        (u32)  + N x (cev_len u32 + cev_blob)
            brev_count       (u32)  + N x (brev_len u32 + brev_blob)
            bundle_flag      (u8, 0=absent 1=present) + [bundle_len u32 + bundle_blob]
            32               block_hash

        (The `reg_count`/registration-tx block slot was removed with
        the receive-to-exist refactor — new entities enter state
        implicitly via Transfer txs, so there is no RegistrationTransaction
        type on the wire anymore.  This is a consensus-format change.)

        `state` is threaded down to each child tx's `to_bytes(state)`
        so the varint-index compact form is emitted when an entity
        registry is available.  Without state, child txs emit the
        legacy 32-byte-id form.
        """
        from messagechain.consensus.slashing import SlashTransaction
        from messagechain.consensus.attestation import Attestation
        from messagechain.core.transfer import TransferTransaction
        from messagechain.core.staking import (
            StakeTransaction, UnstakeTransaction,
        )
        from messagechain.core.authority_key import SetAuthorityKeyTransaction
        from messagechain.core.emergency_revoke import RevokeTransaction
        from messagechain.core.key_rotation import KeyRotationTransaction
        from messagechain.core.receipt_subtree_root import (
            SetReceiptSubtreeRootTransaction,
        )
        from messagechain.core.release_announce import (
            ReleaseAnnounceTransaction,
        )
        from messagechain.governance.governance import (
            ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
        )

        def _tx_bytes(item):
            # Every participating tx type now accepts an optional state
            # arg; fall back to the no-arg form for any legacy types
            # that don't yet take one (slash txs carry no entity_id at
            # top level — they nest evidence that is block-internal).
            try:
                return item.to_bytes(state=state)
            except TypeError:
                return item.to_bytes()

        def enc_list(items):
            parts = [struct.pack(">I", len(items))]
            for item in items:
                b = _tx_bytes(item)
                parts.append(struct.pack(">I", len(b)))
                parts.append(b)
            return b"".join(parts)

        def enc_vsigs():
            parts = [struct.pack(">I", len(self.validator_signatures))]
            for eid, sig in self.validator_signatures:
                sb = sig.to_bytes()
                parts.append(eid)
                parts.append(struct.pack(">I", len(sb)))
                parts.append(sb)
            return b"".join(parts)

        def enc_authority():
            parts = [struct.pack(">I", len(self.authority_txs))]
            for t in self.authority_txs:
                if isinstance(t, SetAuthorityKeyTransaction):
                    kind = 0
                elif isinstance(t, RevokeTransaction):
                    kind = 1
                elif isinstance(t, KeyRotationTransaction):
                    kind = 2
                elif isinstance(t, SetReceiptSubtreeRootTransaction):
                    # kind=3: appended to the authority-tx union.  Old
                    # blocks (all kind in {0,1,2}) still deserialize
                    # unchanged — the union is additive.  A NEW block
                    # carrying kind=3 cannot be parsed by pre-receipt-
                    # bootstrap binaries; that is flagged as a
                    # consensus-format change in the commit message.
                    kind = 3
                elif isinstance(t, ReleaseAnnounceTransaction):
                    # kind=4: threshold multi-sig release manifest.
                    # Append-only union extension — same hard-fork
                    # caveat as kind=3.
                    kind = 4
                else:
                    raise ValueError(f"Unknown authority tx: {type(t).__name__}")
                b = _tx_bytes(t)
                parts.append(struct.pack(">B", kind))
                parts.append(struct.pack(">I", len(b)))
                parts.append(b)
            return b"".join(parts)

        def enc_governance():
            parts = [struct.pack(">I", len(self.governance_txs))]
            for t in self.governance_txs:
                if isinstance(t, ProposalTransaction):
                    kind = 0
                elif isinstance(t, VoteTransaction):
                    kind = 1
                elif isinstance(t, TreasurySpendTransaction):
                    kind = 2
                else:
                    raise ValueError(f"Unknown governance tx: {type(t).__name__}")
                b = _tx_bytes(t)
                parts.append(struct.pack(">B", kind))
                parts.append(struct.pack(">I", len(b)))
                parts.append(b)
            return b"".join(parts)

        # Block envelope and header agree on the wire format: the
        # leading byte below stamps the SAME ser_version the header
        # self-selected from its block_number (V1 below
        # VERSION_SIGNALING_HEIGHT, V2 at/above), so the validator_version
        # field appears (V2) or is omitted (V1) consistently end-to-end.
        # Re-serializing a historical V1 block remains lossless because
        # the header self-selects V1 for those heights and V1 codec
        # writes no validator_version field.
        block_ser_version = self.header._ser_version_for_height()
        header_blob = self.header.to_bytes(block_ser_version)
        return b"".join([
            # Leading u8 wire-format version — see
            # config.BLOCK_SERIALIZATION_VERSION.  Lets a future
            # governance proposal bump the binary layout without
            # silently invalidating existing chain data.  Decoder
            # rejects unknown values at parse time with a clear
            # error rather than letting a layout change surface as
            # a cryptic hash mismatch further down the pipeline.
            struct.pack(">B", block_ser_version),
            struct.pack(">I", len(header_blob)),
            header_blob,
            enc_list(self.transactions),
            enc_vsigs(),
            enc_list(self.slash_transactions),
            enc_list(self.attestations),
            enc_list(self.transfer_transactions),
            enc_governance(),
            enc_authority(),
            enc_list(self.stake_transactions),
            enc_list(self.unstake_transactions),
            enc_list(self.finality_votes),
            # custody_proofs trails finality_votes — CustodyProof is
            # the newest participating type.  Empty list encodes as a
            # single u32 zero, so non-challenge blocks pay only the 4-
            # byte header.
            enc_list(self.custody_proofs),
            # censorship_evidence_txs appended after custody_proofs in
            # the combined wire layout (archive-rewards + submission-
            # receipts).  Empty list is a single u32 zero on blocks
            # without evidence traffic.
            enc_list(self.censorship_evidence_txs),
            # bogus_rejection_evidence_txs trails censorship_evidence_txs
            # — newest participating tx type.  Empty list is a single u32
            # zero on blocks without evidence traffic.  This is a
            # consensus-format change; pre-bogus-rejection binaries
            # cannot decode blocks emitted with this slot populated.
            enc_list(self.bogus_rejection_evidence_txs),
            # inclusion_list_violation_evidence_txs trails the bogus-
            # rejection slot — newest tx type.  Empty list pays a
            # single u32 zero.  Consensus-format change: pre-inclusion-
            # list binaries cannot decode blocks emitted with this slot
            # populated.
            enc_list(self.inclusion_list_violation_evidence_txs),
            # inclusion_list — optional scalar, hot-path empty case is
            # one zero byte.  Trails the violation-evidence slot so the
            # decoder reads tx lists before any optional scalars (a
            # convention shared with archive_proof_bundle).
            _encode_optional_inclusion_list(self.inclusion_list),
            # archive_proof_bundle is optional — 1 byte presence flag
            # then u32 length + blob when present.  Absent on blocks
            # without custody_proofs (the common case) so non-challenge
            # blocks only pay the single presence byte.  This is a
            # consensus-format change; pre-bundle binaries cannot
            # decode blocks from the bundle-aware code path.
            _encode_optional_bundle(self.archive_proof_bundle),
            # acks_observed_this_block — strictly appended after
            # archive_proof_bundle so a pre-witnessed-submission blob
            # is a strict prefix of a post-feature blob (modulo the
            # block_hash trailer).  Empty list pays exactly 4 bytes
            # (a u32 zero count) on the hot path, since the vast
            # majority of blocks carry no observed acks.  Consensus-
            # format change: pre-feature binaries cannot decode blocks
            # with this slot populated.
            _encode_acks_observed(self.acks_observed_this_block),
            self.block_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "Block":
        from messagechain.consensus.slashing import SlashTransaction
        from messagechain.consensus.attestation import Attestation
        from messagechain.core.transfer import TransferTransaction
        from messagechain.core.staking import (
            StakeTransaction, UnstakeTransaction,
        )
        from messagechain.core.authority_key import SetAuthorityKeyTransaction
        from messagechain.core.emergency_revoke import RevokeTransaction
        from messagechain.core.key_rotation import KeyRotationTransaction
        from messagechain.core.receipt_subtree_root import (
            SetReceiptSubtreeRootTransaction,
        )
        from messagechain.core.release_announce import (
            ReleaseAnnounceTransaction,
        )
        from messagechain.governance.governance import (
            ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
        )

        off = 0

        def take(n):
            nonlocal off
            if off + n > len(data):
                raise ValueError("Block blob truncated")
            b = bytes(data[off:off + n])
            off += n
            return b

        def take_u32():
            nonlocal off
            if off + 4 > len(data):
                raise ValueError("Block blob truncated at u32")
            v = struct.unpack_from(">I", data, off)[0]
            off += 4
            return v

        def take_u8():
            nonlocal off
            if off + 1 > len(data):
                raise ValueError("Block blob truncated at u8")
            v = struct.unpack_from(">B", data, off)[0]
            off += 1
            return v

        def dec_list(klass):
            n = take_u32()
            out = []
            for _ in range(n):
                ln = take_u32()
                blob = take(ln)
                # Every participating tx type now accepts an optional
                # state kw; legacy types (e.g., SlashTransaction) don't
                # need it and fall through to the no-kw path.
                try:
                    out.append(klass.from_bytes(blob, state=state))
                except TypeError:
                    out.append(klass.from_bytes(blob))
            return out

        # Wire-format gate: a leading u8 marks the binary layout version.
        # Unknown values are rejected at the parse boundary with a clear
        # error so a future layout change doesn't surface as a cryptic
        # hash mismatch further down.  See config.BLOCK_SERIALIZATION_VERSION.
        ser_version = take_u8()
        ok, reason = validate_block_serialization_version(ser_version)
        if not ok:
            raise ValueError(f"Block: {reason}")

        header_len = take_u32()
        # Pass the envelope's ser_version down so the header decoder
        # knows whether to expect the trailing validator_version field.
        header = BlockHeader.from_bytes(take(header_len), ser_version=ser_version)

        txs = dec_list(MessageTransaction)

        # validator_signatures: count | [32 eid + u32 sig_len + sig]
        vsig_count = take_u32()
        val_sigs = []
        for _ in range(vsig_count):
            eid = take(32)
            sig_len = take_u32()
            sig = Signature.from_bytes(take(sig_len))
            val_sigs.append((eid, sig))

        slash_txs = dec_list(SlashTransaction)
        attestations = dec_list(Attestation)
        transfer_txs = dec_list(TransferTransaction)

        def _call_from_bytes(klass, blob):
            try:
                return klass.from_bytes(blob, state=state)
            except TypeError:
                return klass.from_bytes(blob)

        # Governance txs with 1-byte kind discriminator
        gov_count = take_u32()
        gov_classes = (
            ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
        )
        governance_txs = []
        for _ in range(gov_count):
            kind = take_u8()
            if kind >= len(gov_classes):
                raise ValueError(f"Unknown governance tx kind: {kind}")
            ln = take_u32()
            governance_txs.append(
                _call_from_bytes(gov_classes[kind], take(ln))
            )

        # Authority txs with 1-byte kind discriminator.
        # kind 0: SetAuthorityKey, kind 1: Revoke, kind 2: KeyRotation,
        # kind 3: SetReceiptSubtreeRoot (appended — older binaries reject
        # kind=3 with a clear "Unknown authority tx kind" error).
        # kind 4: ReleaseAnnounce (threshold multi-sig manifest; same
        # hard-fork caveat as kind=3 — pre-release-announce binaries
        # cannot decode blocks with this slot populated).
        auth_count = take_u32()
        auth_classes = (
            SetAuthorityKeyTransaction, RevokeTransaction,
            KeyRotationTransaction, SetReceiptSubtreeRootTransaction,
            ReleaseAnnounceTransaction,
        )
        authority_txs = []
        for _ in range(auth_count):
            kind = take_u8()
            if kind >= len(auth_classes):
                raise ValueError(f"Unknown authority tx kind: {kind}")
            ln = take_u32()
            authority_txs.append(
                _call_from_bytes(auth_classes[kind], take(ln))
            )

        stake_txs = dec_list(StakeTransaction)
        unstake_txs = dec_list(UnstakeTransaction)

        # Finality votes.  The receive-to-exist refactor removed the
        # registration_transactions list from the binary block layout,
        # so finality_votes now sits directly after unstake_transactions.
        # Pre-refactor blobs cannot round-trip through this decoder (the
        # first u32 here reads what used to be the registration count)
        # — that's a deliberate consensus-format hard break: a node
        # carrying pre-refactor blocks must resync from a peer running
        # the new code.
        from messagechain.consensus.finality import FinalityVote
        finality_votes = dec_list(FinalityVote)

        # CustodyProofs — archive-reward proofs.  Non-challenge blocks
        # decode an empty list; validate_block enforces the hygiene
        # rule that only challenge blocks may carry non-empty proofs.
        from messagechain.consensus.archive_challenge import CustodyProof
        custody_proofs = dec_list(CustodyProof)

        # Censorship-evidence txs.  Always present on post-wiring blobs;
        # pre-wiring blobs had this slot absent, but the pre-launch
        # hard reset (see CLAUDE.md — wire-format breakage is OK)
        # means no legacy blobs cross this decoder.
        from messagechain.consensus.censorship_evidence import (
            CensorshipEvidenceTx,
        )
        censorship_evidence_txs = dec_list(CensorshipEvidenceTx)

        # Bogus-rejection evidence txs — appended after the censorship
        # evidence slot.  Same wire-format-breakage caveat: a hard fork
        # introduces this slot and pre-fork binaries cannot decode
        # post-fork blobs.
        from messagechain.consensus.bogus_rejection_evidence import (
            BogusRejectionEvidenceTx,
        )
        bogus_rejection_evidence_txs = dec_list(BogusRejectionEvidenceTx)

        # Inclusion-list violation evidence txs — appended after the
        # bogus-rejection slot.  Same hard-fork caveat: pre-inclusion-
        # list binaries cannot decode blocks with this slot populated.
        from messagechain.consensus.inclusion_list import (
            InclusionListViolationEvidenceTx,
        )
        inclusion_list_violation_evidence_txs = dec_list(
            InclusionListViolationEvidenceTx,
        )

        # Inclusion list — optional scalar, hot path on regular blocks
        # is a single zero byte.  Decoded through the shared optional-
        # inclusion-list helper.  Trails the violation-evidence slot so
        # tx-list decoding completes before any optional scalars.
        inclusion_list_obj, off = _decode_optional_inclusion_list(data, off)

        # Archive-proof bundle — optional scalar, hot path on non-
        # challenge blocks is a single zero byte.  Decoded through the
        # shared optional-bundle helper so the wire format is
        # consistent with `to_bytes`.
        archive_proof_bundle, off = _decode_optional_bundle(data, off)

        # acks_observed_this_block — appended after archive_proof_bundle.
        # Strict 32-bytes-per-entry shape; canonical-form rules
        # (sorted, no duplicates, count <= MAX_ACKS_PER_BLOCK) are
        # enforced at validate_block time, not here.
        acks_observed_this_block, off = _decode_acks_observed(data, off)

        declared_hash = take(32)
        if off != len(data):
            raise ValueError("Block blob has trailing bytes")

        block = cls(
            header=header, transactions=txs,
            validator_signatures=val_sigs,
            slash_transactions=slash_txs,
            attestations=attestations,
            transfer_transactions=transfer_txs,
            governance_txs=governance_txs,
            authority_txs=authority_txs,
            stake_transactions=stake_txs,
            unstake_transactions=unstake_txs,
            finality_votes=finality_votes,
            custody_proofs=custody_proofs,
            censorship_evidence_txs=censorship_evidence_txs,
            bogus_rejection_evidence_txs=bogus_rejection_evidence_txs,
            inclusion_list_violation_evidence_txs=(
                inclusion_list_violation_evidence_txs
            ),
            inclusion_list=inclusion_list_obj,
            archive_proof_bundle=archive_proof_bundle,
            acks_observed_this_block=acks_observed_this_block,
        )
        expected_hash = block._compute_hash()
        if expected_hash != declared_hash:
            raise ValueError(
                f"Block hash mismatch: declared {declared_hash.hex()[:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return block

    @classmethod
    def deserialize(cls, data: dict) -> "Block":
        header = BlockHeader.deserialize(data["header"])
        txs = [MessageTransaction.deserialize(t) for t in data["transactions"]]
        val_sigs = [
            (bytes.fromhex(vs["entity_id"]), Signature.deserialize(vs["signature"]))
            for vs in data.get("validator_signatures", [])
        ]
        # Lazy import to avoid circular dependency
        slash_txs = []
        if data.get("slash_transactions"):
            from messagechain.consensus.slashing import SlashTransaction
            slash_txs = [SlashTransaction.deserialize(s) for s in data["slash_transactions"]]
        attestations = []
        if data.get("attestations"):
            from messagechain.consensus.attestation import Attestation
            attestations = [Attestation.deserialize(a) for a in data["attestations"]]
        transfer_txs = []
        if data.get("transfer_transactions"):
            from messagechain.core.transfer import TransferTransaction
            transfer_txs = [TransferTransaction.deserialize(t) for t in data["transfer_transactions"]]
        governance_txs = []
        if data.get("governance_txs"):
            governance_txs = [_deserialize_governance_tx(g) for g in data["governance_txs"]]
        authority_txs = []
        if data.get("authority_txs"):
            authority_txs = [_deserialize_authority_tx(a) for a in data["authority_txs"]]
        stake_txs = []
        if data.get("stake_transactions"):
            from messagechain.core.staking import StakeTransaction
            stake_txs = [StakeTransaction.deserialize(s) for s in data["stake_transactions"]]
        unstake_txs = []
        if data.get("unstake_transactions"):
            from messagechain.core.staking import UnstakeTransaction
            unstake_txs = [UnstakeTransaction.deserialize(s) for s in data["unstake_transactions"]]
        finality_votes = []
        if data.get("finality_votes"):
            from messagechain.consensus.finality import FinalityVote
            finality_votes = [
                FinalityVote.deserialize(v) for v in data["finality_votes"]
            ]
        custody_proofs = []
        if data.get("custody_proofs"):
            from messagechain.consensus.archive_challenge import CustodyProof
            custody_proofs = [
                CustodyProof.deserialize(p) for p in data["custody_proofs"]
            ]
        censorship_evidence_txs = []
        if data.get("censorship_evidence_txs"):
            from messagechain.consensus.censorship_evidence import (
                CensorshipEvidenceTx,
            )
            censorship_evidence_txs = [
                CensorshipEvidenceTx.deserialize(e)
                for e in data["censorship_evidence_txs"]
            ]
        bogus_rejection_evidence_txs = []
        if data.get("bogus_rejection_evidence_txs"):
            from messagechain.consensus.bogus_rejection_evidence import (
                BogusRejectionEvidenceTx,
            )
            bogus_rejection_evidence_txs = [
                BogusRejectionEvidenceTx.deserialize(e)
                for e in data["bogus_rejection_evidence_txs"]
            ]
        inclusion_list_violation_evidence_txs = []
        if data.get("inclusion_list_violation_evidence_txs"):
            from messagechain.consensus.inclusion_list import (
                InclusionListViolationEvidenceTx,
            )
            inclusion_list_violation_evidence_txs = [
                InclusionListViolationEvidenceTx.deserialize(e)
                for e in data["inclusion_list_violation_evidence_txs"]
            ]
        inclusion_list_obj = None
        if data.get("inclusion_list"):
            from messagechain.consensus.inclusion_list import InclusionList
            inclusion_list_obj = InclusionList.deserialize(data["inclusion_list"])
        archive_proof_bundle = None
        if data.get("archive_proof_bundle"):
            from messagechain.consensus.archive_challenge import (
                ArchiveProofBundle,
            )
            archive_proof_bundle = ArchiveProofBundle.from_bytes(
                bytes.fromhex(data["archive_proof_bundle"]),
            )
        acks_observed_this_block = []
        if data.get("acks_observed_this_block"):
            from messagechain.consensus.witness_submission import (
                SubmissionAck,
            )
            acks_observed_this_block = [
                SubmissionAck.deserialize(d)
                for d in data["acks_observed_this_block"]
            ]
        block = cls(header=header, transactions=txs, validator_signatures=val_sigs,
                    slash_transactions=slash_txs, attestations=attestations,
                    transfer_transactions=transfer_txs, governance_txs=governance_txs,
                    authority_txs=authority_txs, stake_transactions=stake_txs,
                    unstake_transactions=unstake_txs,
                    finality_votes=finality_votes,
                    custody_proofs=custody_proofs,
                    censorship_evidence_txs=censorship_evidence_txs,
                    bogus_rejection_evidence_txs=bogus_rejection_evidence_txs,
                    inclusion_list_violation_evidence_txs=(
                        inclusion_list_violation_evidence_txs
                    ),
                    inclusion_list=inclusion_list_obj,
                    archive_proof_bundle=archive_proof_bundle,
                    acks_observed_this_block=acks_observed_this_block)
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = block._compute_hash()
        declared_hash = bytes.fromhex(data["block_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"Block hash mismatch: declared {data['block_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return block


def create_genesis_block(proposer_entity) -> Block:
    """Create the genesis block (block 0) with no transactions."""
    # Genesis pins hash_version explicitly even though it's the dataclass
    # default — the intent is that future readers of this function see that
    # genesis is crypto-versioned, not that we accidentally got the current
    # scheme by omitting the field.
    header = BlockHeader(
        version=1,
        hash_version=HASH_VERSION_CURRENT,
        block_number=0,
        prev_hash=b"\x00" * 32,
        merkle_root=_hash(b"genesis"),
        timestamp=int(time.time()),
        proposer_id=proposer_entity.entity_id,
    )

    # Sign the genesis block
    header_hash = _hash(header.signable_data())
    header.proposer_signature = proposer_entity.keypair.sign(header_hash)

    block = Block(header=header, transactions=[])
    block.block_hash = block._compute_hash()
    return block
