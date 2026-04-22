"""Proof-of-custody archive rewards — consensus module.

See `docs/proof-of-custody-archive-rewards.md` for the authoritative
design.  Summary:

    * Every ARCHIVE_CHALLENGE_INTERVAL blocks the chain seeds a VRF-
      style challenge over its own block hash, selecting a random
      historical height `h` and a random tx index within that block.

    * Any node that actually holds block h can submit a CustodyProof
      — header of h, the sampled tx bytes, and a Merkle inclusion
      path against h's merkle_root.  Nothing in the proof depends on
      the submitter's identity being registered; open submission.

    * The first ARCHIVE_PROOFS_PER_CHALLENGE valid proofs per
      challenge are paid ARCHIVE_REWARD tokens each from an
      ArchiveRewardPool.  FCFS — spec's v1 preference (winner-take-
      all would select for fastest, not most reliable).

    * Pool is funded by redirecting ARCHIVE_BURN_REDIRECT_PCT (25%)
      of the EIP-1559 base-fee burn stream.  Remaining 75% still
      burns.  Pool balance is part of the state snapshot root so
      bootstrapping nodes see the same scalar as replaying nodes.

Design choices this module locks in (open-question resolution from
spec):

    1. Open submission — any entity may submit.  Simpler than an
       operator-registration gate; slashing for non-response is
       explicitly out of scope for v1.
    2. FCFS payout — `apply_archive_rewards` honors submission order,
       which is the proposer's listed order in the block.
    3. Random-indexed tx bytes — `leaf_idx = challenge_seed mod
       num_txs`.  Empty blocks degrade to header-only custody.
    4. No witness-archive reward stream — deferred.

The module is deliberately stateless apart from the small
ArchiveRewardPool scalar; the larger chain wiring (funding the pool
from burns, reading proofs out of a block body, applying rewards at
challenge cadence) lives in `Blockchain._apply_block_state`.

Security posture:
    * Proofs never inspect message content.  A proof of custody is
      a Merkle-inclusion proof against a header the chain already
      committed to — forging one is equivalent to finding a SHA3-256
      collision.
    * The challenge seed is derived from the BLOCK HASH, which
      commits to every tx the proposer picked.  A grinding proposer
      cannot shift the target without also reshuffling every piece
      of block content they already care about (fees, attestations,
      randao).  Not a practical attack surface.
    * No content-based admission rules: a valid proof proves
      custody, period.  Never rejects on message/tx semantics.
      Aligns with CLAUDE.md principle #2 (permanence, no content-
      based filters).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Iterable, Optional

from messagechain.config import (
    ARCHIVE_AGE_SKEW_FRACTION,
    ARCHIVE_BURN_REDIRECT_PCT,
    ARCHIVE_CHALLENGE_INTERVAL,
    ARCHIVE_CHALLENGE_K,
    ARCHIVE_PROOFS_PER_CHALLENGE,
    ARCHIVE_REWARD,
    ARCHIVE_SUBMISSION_WINDOW,
    ARCHIVE_CHALLENGE_VERSION,
    HASH_ALGO,
)


# Domain tag for the challenge seed — prevents cross-protocol preimage
# collision with any other derivation over a block hash.  The spec's
# exact string.
_CHALLENGE_DOMAIN_TAG = b"archive-challenge"


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# ── Challenge derivation ──────────────────────────────────────────────


@dataclass(frozen=True)
class ArchiveChallenge:
    """The challenge the chain issues at a challenge block.

    Fields:
        target_height: past block height a custody proof must target.
        target_leaf_seed: unreduced seed; verifiers compute the actual
                         leaf index as `target_leaf_seed mod num_txs_at_h`
                         since they need to know num_txs to reduce it.
                         Keeps this module independent of the target
                         block itself — callers resolve num_txs when
                         they look the block up.
    """
    target_height: int
    target_leaf_seed: int


def compute_challenge(block_hash: bytes, block_number: int) -> ArchiveChallenge:
    """Derive the (single) challenge for the given block.

    Historical single-challenge API preserved for callers that don't
    yet know about multi-height sampling.  Exactly equivalent to
    `compute_challenges(block_hash, block_number, k=1)[0]` — the K=1
    index-0 derivation is the same primitive so no behavior divergence.

    `block_number` is B (the block issuing the challenge).  The target
    height is a uniformly-distributed integer in `[0, B)` — i.e., any
    historical block including genesis.  `block_hash` is the hash of B
    itself; since the block hash commits to the proposer's choices
    (and is signed under it), the challenge is unforgeable once the
    block is published.

    Raises:
        ValueError: block_number <= 0.  There is no historical block
        to challenge at height 0 — nothing to hold.
    """
    return compute_challenges(block_hash, block_number, k=1)[0]


def compute_challenges(
    block_hash: bytes,
    block_number: int,
    k: int = ARCHIVE_CHALLENGE_K,
) -> list[ArchiveChallenge]:
    """Derive K distinct challenges per challenge block.

    Each challenge targets an independently-seeded historical height;
    seeds are derived as `H(block_hash || "archive-challenge" || i)`
    for `i` in `[0, K)`, so the per-index domain separation keeps the
    K seeds pairwise-independent without needing a separate RNG.

    Returned heights are usually K pairwise-distinct values, but the
    protocol tolerates accidental collisions (probability K^2/(2B) —
    negligible for K=3 and any meaningful B).  A collision means the
    same historical height is challenged twice; duty enforcement
    treats that as one credit, since a second proof for the same
    (prover, height) is rejected by the bundle.  Accepting the
    theoretical collision keeps the derivation stateless and
    byte-identical across nodes.

    Raises:
        ValueError: k <= 0, block_number <= 0, or block_hash not 32B.
    """
    if k <= 0:
        raise ValueError(f"k must be positive, got {k}")
    if block_number <= 0:
        raise ValueError(
            f"Cannot issue an archive challenge at height {block_number}: "
            "no historical blocks to challenge"
        )
    if not isinstance(block_hash, (bytes, bytearray)) or len(block_hash) != 32:
        raise ValueError(
            f"block_hash must be 32 bytes, got {len(block_hash)}"
        )

    # Age-skew split: the FIRST (k+1)//2 challenges sample uniformly
    # across all history [0, block_number); the REMAINING k - (k+1)//2
    # challenges sample only within the oldest ARCHIVE_AGE_SKEW_FRACTION
    # of history [0, age_bucket).  This forces validators to actually
    # retain ancient blocks — the data least incentivized to hold —
    # because a pruner keeping only recent blocks fails every
    # age-skewed challenge deterministically.
    #
    # (k+1)//2 biases toward uniform when K is odd so the single-
    # challenge case (K=1) stays full-range — the compute_challenge
    # wrapper relies on this, and broad-coverage sampling is the
    # sensible default when only one challenge is drawn.
    #
    # Graceful degradation at small B (bootstrap era): if the age
    # bucket would be zero-sized, fall back to full-range sampling
    # for the skewed half.  Math: max(1, floor(B * fraction)).  At
    # B = 1 this means the sole block is always the target, which
    # is fine — any validator claiming to hold the chain must hold
    # block 0.
    uniform_count = (k + 1) // 2
    age_bucket = max(1, int(block_number * ARCHIVE_AGE_SKEW_FRACTION))
    challenges: list[ArchiveChallenge] = []
    for i in range(k):
        # Per-index domain separation.  u32 suffix lets K scale to ~4B
        # before encoding collapses — far beyond any plausible tuning.
        index_tag = struct.pack(">I", i)
        seed = _h(bytes(block_hash) + _CHALLENGE_DOMAIN_TAG + index_tag)
        seed_int = int.from_bytes(seed, "big")
        # First half uniform over all history; second half confined
        # to the oldest age_bucket blocks.
        modulus = block_number if i < uniform_count else age_bucket
        challenges.append(ArchiveChallenge(
            target_height=seed_int % modulus,
            target_leaf_seed=seed_int,
        ))
    return challenges


def is_within_submission_window(
    challenge_block_number: int,
    current_block_number: int,
) -> bool:
    """Is it still time for proofs targeting `challenge_block_number`?

    The window is [challenge_block_number, challenge_block_number +
    ARCHIVE_SUBMISSION_WINDOW).  Proofs submitted outside this range
    are stale and MUST be rejected by consensus so an operator cannot
    retroactively claim rewards after the chain has moved on.
    """
    if current_block_number < challenge_block_number:
        return False
    return (current_block_number - challenge_block_number) < ARCHIVE_SUBMISSION_WINDOW


# ── Custody proof ─────────────────────────────────────────────────────


@dataclass
class CustodyProof:
    """A signed claim of custody over a historical block.

    Iteration 3f: proof now carries `public_key` + `signature` and
    requires `prover_id == derive_entity_id(public_key)`.  Closes the
    swap-prover-id attack where a gossip eavesdropper could intercept
    Alice's proof, change the prover_id field to their own, and
    claim the reward — Merkle math verified fine (path is prover-id-
    independent), but the reward redirected.  A valid signature bound
    to the embedded pubkey makes that attack impossible without
    Alice's private key.

    Fields:
        prover_id:           32-byte entity ID = derive_entity_id(
                             public_key).  Enforced at construction
                             and verification.
        public_key:          the prover's WOTS+ Merkle-tree root key.
                             Embedded so verifiers don't need to
                             look up chain state — this is what lets
                             non-validator hobbyist archivists
                             participate without prior registration.
        signature:           WOTS+ signature over signing_material()
                             produced by the prover's KeyPair.  Uses
                             one WOTS+ leaf per proof.
        target_height:       height the prover claims to hold.
        target_block_hash:   block hash of that height (32 bytes).
                             Included in signing material so the
                             proof is bound to a specific target —
                             cross-epoch replay fails when the
                             challenge picks a different target.
        header_bytes:        raw header bytes — verifier rehashes to
                             check against target_block_hash.
        merkle_root:         the tx merkle root as stated by the
                             prover; verifier must agree with header.
        tx_index:            index of the sampled tx within the block,
                             or None for empty blocks (header-only
                             custody).
        tx_bytes:            raw bytes of the sampled tx (b"" for
                             empty-block proofs).
        merkle_path:         sibling hashes leading from the sampled
                             tx's leaf to merkle_root.  Empty for
                             empty-block proofs.
        merkle_layer_sizes:  per-layer counts so the verifier knows
                             when sentinel padding was applied at each
                             level.  Mirrors the padding rule from
                             core.block.compute_merkle_root.

    What signing does NOT close:
        * Sybil via N freshly-generated keypairs.  Each fresh keypair
          has a distinct prover_id and competes fairly; Sybil cost is
          O(N × key-gen-cost + N × per-leaf-sign).
        * Fetch-on-demand: an attacker who reads public block data
          from gossip can build valid proofs without storing history.
          This is structurally unclosable without latency-bounded
          peer-to-peer challenges — out of scope for this iteration.
    """
    prover_id: bytes
    target_height: int
    target_block_hash: bytes
    header_bytes: bytes
    merkle_root: bytes
    tx_index: Optional[int]
    tx_bytes: bytes
    merkle_path: list[bytes] = field(default_factory=list)
    merkle_layer_sizes: list[int] = field(default_factory=list)
    public_key: bytes = b""
    # Signature is Optional[Signature]; typed loosely here to avoid
    # circular imports.  A proof with signature=None is STRUCTURALLY
    # valid (for round-trip decode paths and test helpers that stage
    # proofs before signing) but will FAIL verify_custody_proof.
    signature: object = None

    def serialize(self) -> dict:
        return {
            "version": ARCHIVE_CHALLENGE_VERSION,
            "prover_id": self.prover_id.hex(),
            "target_height": self.target_height,
            "target_block_hash": self.target_block_hash.hex(),
            "header_bytes": self.header_bytes.hex(),
            "merkle_root": self.merkle_root.hex(),
            "tx_index": self.tx_index,
            "tx_bytes": self.tx_bytes.hex(),
            "merkle_path": [h.hex() for h in self.merkle_path],
            "merkle_layer_sizes": list(self.merkle_layer_sizes),
            "public_key": self.public_key.hex(),
            "signature": (
                self.signature.serialize() if self.signature is not None else None
            ),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "CustodyProof":
        sig_data = data.get("signature")
        signature = None
        if sig_data is not None:
            from messagechain.crypto.keys import Signature
            signature = Signature.deserialize(sig_data)
        return cls(
            prover_id=bytes.fromhex(data["prover_id"]),
            target_height=int(data["target_height"]),
            target_block_hash=bytes.fromhex(data["target_block_hash"]),
            header_bytes=bytes.fromhex(data["header_bytes"]),
            merkle_root=bytes.fromhex(data["merkle_root"]),
            tx_index=data.get("tx_index"),
            tx_bytes=bytes.fromhex(data["tx_bytes"]),
            merkle_path=[bytes.fromhex(x) for x in data.get("merkle_path", [])],
            merkle_layer_sizes=list(data.get("merkle_layer_sizes", [])),
            public_key=bytes.fromhex(data.get("public_key", "")),
            signature=signature,
        )

    def signing_material(self) -> bytes:
        """Bytes the signature MUST cover — everything except the
        signature itself.

        Includes public_key so an attacker can't swap keys without
        invalidating the signature.  Includes prover_id so the
        swap-prover-id attack is closed.  Includes target_block_hash
        so a proof can't be replayed against a different target.
        Includes the Merkle data so any in-flight tamper of proof
        fields breaks the signature.
        """
        import struct as _struct
        parts = [
            _struct.pack(">I", len(self.public_key)),
            self.public_key,
            self.prover_id,
            _struct.pack(">Q", self.target_height),
            self.target_block_hash,
            _struct.pack(">I", len(self.header_bytes)),
            self.header_bytes,
            self.merkle_root,
            # tx_index uses a sentinel -1 for the empty-block case so
            # None and 0 never collide in the commitment.
            _struct.pack(">q", -1 if self.tx_index is None else int(self.tx_index)),
            _struct.pack(">I", len(self.tx_bytes)),
            self.tx_bytes,
            _struct.pack(">I", len(self.merkle_path)),
        ]
        parts.extend(self.merkle_path)
        parts.append(_struct.pack(">I", len(self.merkle_layer_sizes)))
        for n in self.merkle_layer_sizes:
            parts.append(_struct.pack(">Q", int(n)))
        return b"".join(parts)

    def canonical_bytes(self) -> bytes:
        """Full byte encoding including the signature — this is what
        block.merkle_root commits to so a relayer cannot strip the
        signature in transit.  tx_hash = H(canonical_bytes).
        """
        import struct as _struct
        base = self.signing_material()
        if self.signature is None:
            # Empty-signature sentinel.  Round-trips cleanly; but
            # verify_custody_proof rejects such proofs, so the only
            # callers that see this shape are constructors staging a
            # proof before signing it and test helpers that never
            # call verify.
            return base + _struct.pack(">I", 0)
        sig_blob = self.signature.to_bytes()
        return base + _struct.pack(">I", len(sig_blob)) + sig_blob

    @property
    def tx_hash(self) -> bytes:
        """Commitment leaf for block.merkle_root.

        Uniform name with every other block-embedded type so
        merkle-root construction loops over `.tx_hash` on each leaf
        without caring about the underlying type.
        """
        return _h(self.canonical_bytes())

    def to_bytes(self, state=None) -> bytes:
        """Compact binary encoding matching canonical_bytes.

        Block.to_bytes length-prefixes this blob via its generic
        enc_list helper, so no self-length header is needed here.
        """
        return self.canonical_bytes()

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "CustodyProof":
        """Decode a CustodyProof from its canonical_bytes form.

        Layout (iter 3f): pubkey_len u32 + pubkey || prover_id(32)
        || target_height(u64) || target_block_hash(32) || hdr_len(u32)
        + hdr || merkle_root(32) || tx_index(i64) || tx_len(u32) + tx
        || path_count(u32) + path_count × 32B || ls_count(u32) +
        ls_count × u64 || sig_len(u32) + sig_blob.
        """
        import struct as _struct
        off = 0
        if len(data) < 4:
            raise ValueError("CustodyProof blob too short for pubkey_len")
        pk_len = _struct.unpack_from(">I", data, off)[0]; off += 4
        if off + pk_len > len(data):
            raise ValueError("CustodyProof truncated at public_key")
        public_key = bytes(data[off:off + pk_len]); off += pk_len
        if off + 32 + 8 + 32 + 4 > len(data):
            raise ValueError("CustodyProof blob too short after pubkey")
        prover_id = bytes(data[off:off + 32]); off += 32
        target_height = _struct.unpack_from(">Q", data, off)[0]; off += 8
        target_block_hash = bytes(data[off:off + 32]); off += 32
        hdr_len = _struct.unpack_from(">I", data, off)[0]; off += 4
        if off + hdr_len > len(data):
            raise ValueError("CustodyProof truncated at header_bytes")
        header_bytes = bytes(data[off:off + hdr_len]); off += hdr_len
        if off + 32 + 8 + 4 > len(data):
            raise ValueError("CustodyProof truncated at merkle_root")
        merkle_root = bytes(data[off:off + 32]); off += 32
        tx_idx_raw = _struct.unpack_from(">q", data, off)[0]; off += 8
        tx_index = None if tx_idx_raw < 0 else int(tx_idx_raw)
        tx_len = _struct.unpack_from(">I", data, off)[0]; off += 4
        if off + tx_len + 4 > len(data):
            raise ValueError("CustodyProof truncated at tx_bytes")
        tx_bytes = bytes(data[off:off + tx_len]); off += tx_len
        path_count = _struct.unpack_from(">I", data, off)[0]; off += 4
        merkle_path: list[bytes] = []
        for _ in range(path_count):
            if off + 32 > len(data):
                raise ValueError("CustodyProof truncated in merkle_path")
            merkle_path.append(bytes(data[off:off + 32]))
            off += 32
        if off + 4 > len(data):
            raise ValueError("CustodyProof truncated at layer_sizes count")
        ls_count = _struct.unpack_from(">I", data, off)[0]; off += 4
        merkle_layer_sizes: list[int] = []
        for _ in range(ls_count):
            if off + 8 > len(data):
                raise ValueError("CustodyProof truncated in layer_sizes")
            merkle_layer_sizes.append(_struct.unpack_from(">Q", data, off)[0])
            off += 8
        if off + 4 > len(data):
            raise ValueError("CustodyProof truncated at signature length")
        sig_len = _struct.unpack_from(">I", data, off)[0]; off += 4
        signature = None
        if sig_len > 0:
            if off + sig_len > len(data):
                raise ValueError("CustodyProof truncated in signature")
            from messagechain.crypto.keys import Signature
            signature = Signature.from_bytes(bytes(data[off:off + sig_len]))
            off += sig_len
        if off != len(data):
            raise ValueError("CustodyProof has trailing bytes")
        return cls(
            prover_id=prover_id,
            target_height=target_height,
            target_block_hash=target_block_hash,
            header_bytes=header_bytes,
            merkle_root=merkle_root,
            tx_index=tx_index,
            tx_bytes=tx_bytes,
            merkle_path=merkle_path,
            merkle_layer_sizes=merkle_layer_sizes,
            public_key=public_key,
            signature=signature,
        )


# ── Merkle path construction + verification ──────────────────────────
#
# The block-layer Merkle tree (core.block.compute_merkle_root) uses
# tagged internal/leaf nodes (0x00 leaf, 0x01 internal) and a sentinel
# pad for odd layers.  We must reproduce its exact shape here, or
# consensus-level paths won't verify.


def _leaf_hash(tx_hash: bytes) -> bytes:
    return _h(b"\x00" + tx_hash)


def _internal_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _sentinel_hash() -> bytes:
    return _h(b"\x02sentinel")


def _build_path(
    tx_hashes: list[bytes], target_index: int,
) -> tuple[list[bytes], list[int]]:
    """Return (siblings, layer_sizes) for the given leaf index.

    `siblings` is the list of sibling hashes from the leaf level up.
    `layer_sizes` records the element count at each level BEFORE
    padding — the verifier uses it to know whether a sibling slot was
    filled by a real sibling or by the sentinel pad.
    """
    if not tx_hashes:
        raise ValueError("Cannot build path for empty tx list")
    if not (0 <= target_index < len(tx_hashes)):
        raise ValueError(
            f"target_index {target_index} out of range for "
            f"{len(tx_hashes)} txs"
        )
    layer = [_leaf_hash(h) for h in tx_hashes]
    siblings: list[bytes] = []
    layer_sizes: list[int] = [len(layer)]
    idx = target_index
    while len(layer) > 1:
        # Match the padding rule from core.block.compute_merkle_root:
        # odd layers get a sentinel-hash appended.
        padded = list(layer)
        if len(padded) % 2 == 1:
            padded.append(_sentinel_hash())
        sibling_idx = idx ^ 1  # flip low bit: 0<->1, 2<->3, ...
        siblings.append(padded[sibling_idx])
        next_layer = [
            _internal_hash(padded[i], padded[i + 1])
            for i in range(0, len(padded), 2)
        ]
        layer = next_layer
        layer_sizes.append(len(layer))
        idx //= 2
    return siblings, layer_sizes


def _replay_merkle(
    leaf_hash: bytes,
    leaf_index: int,
    siblings: list[bytes],
    layer_sizes: list[int],
) -> bytes:
    """Recompute the Merkle root from a leaf hash + path.

    Mirrors _build_path's shape: at each level, if the size was odd
    the verifier treats the last slot as sentinel-padded.  A proof
    that lies about layer_sizes will fail because an honest verifier
    uses the size carried by the proof to walk the path — and whichever
    shape the proof claims, the resulting root must equal the header's
    merkle_root.  A lying size that happens to round-trip means the
    prover is claiming a different shape for the original block, which
    would not match the actual data the chain committed to.
    """
    if len(layer_sizes) < 1:
        return leaf_hash
    # The first entry in layer_sizes is the leaf-level count.  It MUST
    # match the number of levels we'll walk (one sibling per internal
    # step); the number of siblings should equal layer_sizes count
    # above the leaf level.
    if len(siblings) != len(layer_sizes) - 1:
        raise ValueError(
            f"sibling count {len(siblings)} != layer count "
            f"{len(layer_sizes) - 1}"
        )
    current = leaf_hash
    idx = leaf_index
    for level, sibling in enumerate(siblings):
        # Left child: idx even, right child: idx odd.
        if idx % 2 == 0:
            current = _internal_hash(current, sibling)
        else:
            current = _internal_hash(sibling, current)
        idx //= 2
    return current


def build_custody_proof(
    *,
    entity=None,
    prover_id: Optional[bytes] = None,
    target_height: int,
    target_block_hash: bytes,
    header_bytes: bytes,
    merkle_root: bytes,
    tx_index: Optional[int],
    tx_bytes: bytes,
    all_tx_hashes: list[bytes],
) -> CustodyProof:
    """Construct a CustodyProof over the given block contents.

    Iteration 3f: takes an `entity` (Entity instance with a KeyPair)
    and produces a SIGNED proof.  The caller's `entity.keypair` is
    consumed for one WOTS+ signature.  `prover_id` is derived
    deterministically from `entity.keypair.public_key`.

    Legacy mode (entity=None, prover_id=<bytes>): produces an UNSIGNED
    proof with the supplied prover_id and empty public_key.  Retained
    only for unit tests that exercise the Merkle-path mechanics
    without needing the signature layer; such proofs FAIL
    verify_custody_proof (which rejects missing signatures).  Chain
    code paths MUST pass `entity=` — never `prover_id=`.

    Caller supplies the full tx-hash list (so we can compute the
    Merkle path) plus the specific tx the prover is surrendering.  The
    caller is assumed to have the data — this routine doesn't verify
    it came from the claimed block; that's what `verify_custody_proof`
    is for.
    """
    # Resolve prover_id + public_key from whichever mode the caller chose.
    if entity is not None:
        from messagechain.identity.identity import derive_entity_id
        public_key = bytes(entity.keypair.public_key)
        resolved_prover_id = derive_entity_id(public_key)
        if prover_id is not None and bytes(prover_id) != resolved_prover_id:
            raise ValueError(
                "prover_id passed alongside entity must match "
                "derive_entity_id(entity.keypair.public_key)"
            )
    else:
        if prover_id is None:
            raise ValueError(
                "build_custody_proof requires either `entity` (signed mode) "
                "or `prover_id` (legacy unsigned mode)"
            )
        if not isinstance(prover_id, (bytes, bytearray)) or len(prover_id) != 32:
            raise ValueError("prover_id must be 32 bytes")
        resolved_prover_id = bytes(prover_id)
        public_key = b""

    # Empty-block case: header-only custody.  No Merkle path, no tx.
    if not all_tx_hashes:
        if tx_index is not None or tx_bytes:
            raise ValueError(
                "Empty block requires tx_index=None and tx_bytes=b''"
            )
        merkle_path = []
        layer_sizes = [0]
        final_tx_index = None
        final_tx_bytes = b""
    else:
        if tx_index is None:
            raise ValueError("Non-empty block requires tx_index")
        if not (0 <= tx_index < len(all_tx_hashes)):
            raise ValueError(
                f"tx_index {tx_index} out of range for "
                f"{len(all_tx_hashes)} txs"
            )
        # Sanity check — tx_hash must match hashed tx_bytes
        if _h(bytes(tx_bytes)) != all_tx_hashes[tx_index]:
            raise ValueError(
                "tx_bytes hash does not match all_tx_hashes[tx_index] — "
                "inconsistent caller input"
            )
        siblings, computed_layer_sizes = _build_path(
            all_tx_hashes, tx_index,
        )
        merkle_path = [bytes(s) for s in siblings]
        layer_sizes = list(computed_layer_sizes)
        final_tx_index = int(tx_index)
        final_tx_bytes = bytes(tx_bytes)

    proof = CustodyProof(
        prover_id=resolved_prover_id,
        target_height=int(target_height),
        target_block_hash=bytes(target_block_hash),
        header_bytes=bytes(header_bytes),
        merkle_root=bytes(merkle_root),
        tx_index=final_tx_index,
        tx_bytes=final_tx_bytes,
        merkle_path=merkle_path,
        merkle_layer_sizes=layer_sizes,
        public_key=public_key,
        signature=None,
    )
    # Signed mode: sign signing_material and attach.
    if entity is not None:
        sig_hash = _h(proof.signing_material())
        proof.signature = entity.keypair.sign(sig_hash)
    return proof


def verify_custody_proof(
    proof: CustodyProof,
    *,
    expected_block_hash: bytes,
) -> tuple[bool, str]:
    """Verify a CustodyProof against a known block hash.

    `expected_block_hash` is the hash of the target block as seen by
    the chain (the caller looks it up from local archive).  The proof
    must:

        1. Hash-match: _h(header_bytes) == expected_block_hash.
           This binds the entire header — including merkle_root — to
           the chain's recorded identity for the block.
        2. Self-consistency: proof.merkle_root must equal the
           merkle_root as decoded from header_bytes.  We don't fully
           decode the header here (stay independent of BlockHeader's
           binary layout), but we do require prover to set
           merkle_root consistent with header_bytes' hash path.  The
           real tie is step 3.
        3. Merkle inclusion: the sampled tx hashes to the leaf, the
           path + layer sizes reconstruct back to proof.merkle_root.
           Empty-block proofs skip this by definition.
        4. Target height / id match: proof.target_block_hash must
           equal expected_block_hash — a proof claiming height H
           against the real block at H but with a different block
           hash is rejected.  Prevents stale-header attacks (e.g.,
           uncle or reorged sibling).

    Returns (ok, reason).  `reason` is a short log-friendly string
    describing why the proof was rejected.
    """
    # Step 0 — basic shape
    if not isinstance(proof.prover_id, (bytes, bytearray)) or len(proof.prover_id) != 32:
        return False, "prover_id must be 32 bytes"
    if len(expected_block_hash) != 32:
        return False, "expected_block_hash must be 32 bytes"
    if proof.target_block_hash != expected_block_hash:
        return False, "proof.target_block_hash does not match chain's block hash"

    # Step 0b — signature + pubkey binding (iter 3f).  Closes the
    # swap-prover-id attack: an attacker who modifies prover_id
    # without also re-signing produces a proof whose signature fails
    # to verify against the declared public_key, OR whose prover_id
    # no longer matches derive_entity_id(public_key).  Either way,
    # rejected.
    from messagechain.identity.identity import derive_entity_id
    from messagechain.crypto.keys import Signature, verify_signature
    if not isinstance(proof.public_key, (bytes, bytearray)) or not proof.public_key:
        return False, "public_key is empty (unsigned legacy proof)"
    if proof.signature is None or not isinstance(proof.signature, Signature):
        return False, "signature is missing"
    if derive_entity_id(proof.public_key) != proof.prover_id:
        return False, "prover_id does not match derive_entity_id(public_key)"
    sig_hash = _h(proof.signing_material())
    if not verify_signature(sig_hash, proof.signature, proof.public_key):
        return False, "signature does not verify against public_key"

    # Step 1 — rehash header bytes
    if _h(proof.header_bytes) != expected_block_hash:
        return False, "header_bytes does not hash to target_block_hash"

    # Step 3 — Merkle inclusion (empty-block case degrades to header-only)
    if proof.tx_index is None:
        # Empty block proof: no Merkle check to run, but tx_bytes must
        # also be empty and merkle_path must be empty.
        if proof.tx_bytes or proof.merkle_path:
            return False, "empty-block proof must have empty tx_bytes and path"
        return True, "ok (empty-block custody)"

    # Non-empty path: rebuild root from leaf.
    leaf = _leaf_hash(_h(proof.tx_bytes))
    try:
        reconstructed_root = _replay_merkle(
            leaf_hash=leaf,
            leaf_index=proof.tx_index,
            siblings=proof.merkle_path,
            layer_sizes=proof.merkle_layer_sizes,
        )
    except ValueError as e:
        return False, f"merkle path malformed: {e}"

    if reconstructed_root != proof.merkle_root:
        return False, "reconstructed merkle root mismatch — forged path or tx"

    return True, "ok"


# ── ArchiveRewardPool ────────────────────────────────────────────────


@dataclass
class ArchiveRewardPool:
    """Single scalar on-chain balance, fed by burn redirection.

    Intentionally a dumb value: all policy lives in
    `apply_archive_rewards` / the live blockchain.  Non-negative
    invariant is enforced at mutation time.

    Permanence-aligned: balance carries forward forever.  Never
    expires.  When try_pay finds the pool empty it returns 0 and the
    chain emits no reward that block — graceful degradation, no
    mint-to-cover.  Matches CLAUDE.md principle #2.
    """
    balance: int = 0

    def fund(self, amount: int) -> None:
        if amount < 0:
            raise ValueError(f"fund amount must be non-negative, got {amount}")
        self.balance += amount

    def try_pay(self, reward: int) -> int:
        """Attempt to pay `reward` out of the pool.

        Returns the actual amount paid.  If the pool has less than
        `reward` available, pays the remainder and zeroes the pool —
        this is the "graceful degradation" rule: the chain never mints
        to cover, but a partial reward is preferable to full skip when
        someone already did the custody work.
        """
        if reward < 0:
            raise ValueError("reward must be non-negative")
        if self.balance <= 0:
            return 0
        paid = min(reward, self.balance)
        self.balance -= paid
        return paid


def split_burn_for_pool(amount: int) -> tuple[int, int]:
    """Split a would-be-burned amount into (pool_add, burn_keep).

    Uses integer floor — a small burn rounds down to 0 pool_add,
    which is the safe bias (pool is never over-credited; rounding
    loss stays in burn).

    Returns exactly (pool_add, burn_keep) such that the two sum to
    `amount`.  Never over-credits the pool.
    """
    if amount < 0:
        raise ValueError(f"amount must be non-negative, got {amount}")
    pool_add = amount * ARCHIVE_BURN_REDIRECT_PCT // 100
    burn_keep = amount - pool_add
    return pool_add, burn_keep


# ── Reward application (FCFS over valid proofs) ──────────────────────


@dataclass
class ArchiveRewardResult:
    """Outcome of applying archive rewards for one challenge.

    Carries a list of (prover_id, reward_amount) pairs plus the total
    paid.  Intended to be written to chain logs (for audit) and to
    update per-entity balances in the live supply tracker.
    """
    payouts: list["_Payout"] = field(default_factory=list)
    total_paid: int = 0
    rejected: list[str] = field(default_factory=list)  # reasons, for logging


@dataclass
class _Payout:
    prover_id: bytes
    amount: int


def apply_archive_rewards(
    *,
    proofs: Iterable[CustodyProof],
    pool: ArchiveRewardPool,
    expected_block_hash: bytes,
    selection_seed: Optional[bytes] = None,
    reward_amount: int = ARCHIVE_REWARD,
    max_payouts: int = ARCHIVE_PROOFS_PER_CHALLENGE,
) -> ArchiveRewardResult:
    """Pay up to `max_payouts` rewards from `pool`.

    Iteration 3e change: selection is a DETERMINISTIC UNIFORM SHUFFLE
    over the valid, deduplicated proofs — not strict FCFS as before.
    This neutralizes the fast-connection advantage that made paid
    archival a winner-take-all race for industrial operators.  Every
    valid submitter has equal odds of making the cap, regardless of
    where they appear in the proposer's listed order.

    `selection_seed` (32 bytes) drives the shuffle; callers pass the
    parent block's randao mix or an equivalent consensus-deterministic
    value.  If None, falls back to submission-order (backward-compat
    for tests + modules that hand a list directly without a seed;
    live-chain callers in blockchain.py always pass a seed).

    Rules retained from prior iteration:
      * One payout per unique prover_id per challenge (Sybil cap).
      * Pool-exhaustion is graceful: remaining proofs marked rejected.
      * No mutation outside the pool scalar — caller splices payouts.
    """
    import hashlib as _hashlib
    import struct as _struct

    # First pass: filter to valid, unique proofs (consistent with the
    # old FCFS semantics for dedup — first occurrence of a prover_id
    # wins the de-dup).  Collect as a list so we can shuffle.
    result = ArchiveRewardResult()
    valid_proofs: list[CustodyProof] = []
    seen_provers: set[bytes] = set()
    for proof in proofs:
        ok, reason = verify_custody_proof(
            proof, expected_block_hash=expected_block_hash,
        )
        if not ok:
            result.rejected.append(reason)
            continue
        if proof.prover_id in seen_provers:
            result.rejected.append("duplicate prover")
            continue
        seen_provers.add(proof.prover_id)
        valid_proofs.append(proof)

    # Deterministic shuffle.  Seed-keyed sort by
    # H(seed || prover_id) — every node with the same seed + input
    # set produces the same ordering.  This is the Fisher-Yates
    # equivalent for a small list without needing per-element
    # randomness bytes.
    if selection_seed is not None and valid_proofs:
        def _shuffle_key(p: CustodyProof) -> bytes:
            return _hashlib.new(HASH_ALGO, selection_seed + p.prover_id).digest()
        valid_proofs = sorted(valid_proofs, key=_shuffle_key)

    # Pay out up to cap; stop on pool exhaustion.
    for proof in valid_proofs:
        if len(result.payouts) >= max_payouts:
            break
        paid = pool.try_pay(reward_amount)
        if paid <= 0:
            result.rejected.append("pool exhausted")
            break
        result.payouts.append(_Payout(prover_id=proof.prover_id, amount=paid))
        result.total_paid += paid

    return result


# ── ArchiveProofBundle: aggregated per-epoch commitment ──────────────
#
# Each challenge epoch collects one CustodyProof per participating
# validator.  Stored naively that is O(validators × proof_size) on-chain
# forever — bloat the ledger cannot afford on a 1000-year horizon.  The
# bundle commits to the set of (entity_id, proof_tx_hash) pairs via a
# single Merkle root, with participants sorted deterministically so two
# nodes seeing the same proof set always compute the same root.
#
# Tree shape: same binary-Merkle-with-sentinel-padding pattern as the
# tx-merkle tree, but with a distinct domain byte (0x10/0x11/0x12) so a
# path built against the tx tree can never be replayed against the
# bundle tree — defense-in-depth against tag-collision attacks.
#
# What this structure enables (downstream iterations, not yet built):
#   * Duty-coupled rewards: consensus can check `bundle.contains(v)` for
#     each active validator v; absentees take a reward-withhold.
#   * Post-finality pruning: the full proof bodies can be stripped once
#     the submission window closes; the bundle root alone suffices to
#     answer "was validator v credited in epoch E" for any v that kept
#     its own submitted CustodyProof.
#   * Late-joiner audit: a validator that disputes its absentee status
#     can re-submit its original proof + a membership path and have
#     consensus cryptographically acknowledge it.


def _bundle_leaf_hash(
    entity_id: bytes, target_height: int, proof_tx_hash: bytes,
) -> bytes:
    """Leaf = H(0x10 || entity_id || u64-BE(target_height) || proof_tx_hash).

    Includes target_height so the same validator's K proofs at K
    distinct heights produce K distinct leaves — the multi-height
    sampling property.  A single leaf still binds exactly one proof
    of custody for one (validator, height) pair; collisions across
    pairs require a SHA3-256 preimage collision.

    Distinct domain byte (0x10) from the tx-merkle tree's 0x00 leaf
    tag so path replay across trees is impossible even when inputs
    happen to collide.
    """
    return _h(
        b"\x10" + entity_id + struct.pack(">Q", int(target_height))
        + proof_tx_hash
    )


def _bundle_internal_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x11" + left + right)


def _bundle_sentinel_hash() -> bytes:
    return _h(b"\x12bundle-sentinel")


def _bundle_empty_root() -> bytes:
    """Sentinel root for an epoch with zero participants.

    Must be deterministic and must not collide with either:
        * the tx-merkle empty-root (_h(b"empty") in block.py), which
          would let someone smuggle a tx-tree root into a bundle slot;
        * the hash of empty bytes, which is the most obvious accidental
          collision source.
    """
    return _h(b"\x13archive-bundle-empty")


def _bundle_build_root(leaf_hashes: list[bytes]) -> bytes:
    """Fold a list of already-hashed leaves into a Merkle root.

    Same odd-layer-pad rule as _build_path above.
    """
    if not leaf_hashes:
        return _bundle_empty_root()
    layer = list(leaf_hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(_bundle_sentinel_hash())
        layer = [
            _bundle_internal_hash(layer[i], layer[i + 1])
            for i in range(0, len(layer), 2)
        ]
    return layer[0]


def _bundle_build_path(
    leaf_hashes: list[bytes], target_index: int,
) -> tuple[list[bytes], list[int]]:
    """Siblings + layer sizes for a membership proof in the bundle tree.
    """
    if not leaf_hashes:
        raise ValueError("Cannot build membership path in an empty bundle")
    if not (0 <= target_index < len(leaf_hashes)):
        raise ValueError(
            f"target_index {target_index} out of range for "
            f"{len(leaf_hashes)} leaves"
        )
    layer = list(leaf_hashes)
    siblings: list[bytes] = []
    layer_sizes: list[int] = [len(layer)]
    idx = target_index
    while len(layer) > 1:
        padded = list(layer)
        if len(padded) % 2 == 1:
            padded.append(_bundle_sentinel_hash())
        sibling_idx = idx ^ 1
        siblings.append(padded[sibling_idx])
        layer = [
            _bundle_internal_hash(padded[i], padded[i + 1])
            for i in range(0, len(padded), 2)
        ]
        layer_sizes.append(len(layer))
        idx //= 2
    return siblings, layer_sizes


def _bundle_replay(
    leaf_hash: bytes,
    leaf_index: int,
    siblings: list[bytes],
) -> bytes:
    """Reconstruct the bundle root from a leaf + sibling path."""
    current = leaf_hash
    idx = leaf_index
    for sibling in siblings:
        if idx % 2 == 0:
            current = _bundle_internal_hash(current, sibling)
        else:
            current = _bundle_internal_hash(sibling, current)
        idx //= 2
    return current


@dataclass
class ArchiveProofBundle:
    """Aggregated commitment over a single challenge epoch's proofs.

    Fields are intentionally minimal — everything else is derivable
    from `participants` + the corresponding leaf hashes.  The root is
    cached because recomputing it is the hot path for verifiers.

    Construction goes through `from_proofs` (sorts + deduplicates +
    computes root).  Direct construction is allowed but the caller is
    then responsible for invariant preservation.
    """

    participants: list[bytes] = field(default_factory=list)
    leaf_hashes: list[bytes] = field(default_factory=list)
    root: bytes = field(default_factory=_bundle_empty_root)

    @property
    def participant_count(self) -> int:
        return len(self.participants)

    @property
    def tx_hash(self) -> bytes:
        """Block-level commitment identity — same pattern every other
        block-body member uses.  `_h(canonical_bytes)` binds the whole
        bundle (root, participants, leaves) so folding this into the
        block's merkle_root prevents a relayer from stripping or
        mutating the bundle in transit.
        """
        return _h(self.to_bytes())

    # ── construction ────────────────────────────────────────────────

    @classmethod
    def from_proofs(cls, proofs: Iterable[CustodyProof]) -> "ArchiveProofBundle":
        """Build a bundle from a set of validated CustodyProofs.

        Caller must have already verified each proof — bundle commits
        to whatever it's handed.  Duplicate (prover_id, target_height)
        pairs are a hard error: a validator submits exactly one proof
        per (epoch, challenged height), and two distinct proofs for
        the same pair means we cannot tell which is canonical.  Same
        prover at DIFFERENT heights is legal — that's the multi-height
        sampling path.
        """
        proofs = list(proofs)
        if not proofs:
            return cls(
                participants=[],
                leaf_hashes=[],
                root=_bundle_empty_root(),
            )

        # Sort by (prover_id, target_height) so every node computes
        # the same root regardless of submission / gossip order.
        proofs_sorted = sorted(
            proofs, key=lambda p: (p.prover_id, int(p.target_height)),
        )

        # Reject duplicate (prover_id, target_height) pairs.
        seen: set[tuple[bytes, int]] = set()
        for p in proofs_sorted:
            key = (p.prover_id, int(p.target_height))
            if key in seen:
                raise ValueError(
                    f"duplicate (prover_id, target_height) in bundle: "
                    f"({p.prover_id.hex()}, {p.target_height})"
                )
            seen.add(key)

        participants = [
            (p.prover_id, int(p.target_height)) for p in proofs_sorted
        ]
        leaf_hashes = [
            _bundle_leaf_hash(p.prover_id, int(p.target_height), p.tx_hash)
            for p in proofs_sorted
        ]
        root = _bundle_build_root(leaf_hashes)
        return cls(
            participants=participants,
            leaf_hashes=leaf_hashes,
            root=root,
        )

    # ── membership queries ──────────────────────────────────────────

    def contains(self, entity_id: bytes, target_height: int) -> bool:
        """Binary-search for (entity_id, target_height) in participants.

        The (entity_id, target_height) granularity matches the leaf
        identity — the duty layer uses this to check each of the K
        challenged heights for each active validator.
        """
        if not self.participants:
            return False
        try:
            self._index_of(entity_id, target_height)
            return True
        except ValueError:
            return False

    def _index_of(self, entity_id: bytes, target_height: int) -> int:
        key = (entity_id, int(target_height))
        lo, hi = 0, len(self.participants) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.participants[mid] == key:
                return mid
            if self.participants[mid] < key:
                lo = mid + 1
            else:
                hi = mid - 1
        raise ValueError(
            f"(entity_id={entity_id.hex()}, target_height={target_height}) "
            "not a participant in this bundle"
        )

    def build_membership_proof(
        self, entity_id: bytes, target_height: int,
    ) -> dict:
        """Construct a Merkle inclusion proof for (entity_id, target_height).

        Returns a dict carrying the leaf index, sibling path, and
        per-layer sizes — the same shape the tx-merkle verifier uses.
        Useful in downstream iterations where a validator disputes an
        absentee marking at a specific challenge height.
        """
        idx = self._index_of(entity_id, target_height)
        siblings, layer_sizes = _bundle_build_path(self.leaf_hashes, idx)
        return {
            "leaf_index": idx,
            "siblings": siblings,
            "layer_sizes": layer_sizes,
        }

    @staticmethod
    def verify_membership(
        *,
        root: bytes,
        entity_id: bytes,
        target_height: int,
        proof_tx_hash: bytes,
        membership_proof: dict,
    ) -> bool:
        """Verify (entity_id, target_height, proof_tx_hash) was committed
        under `root`.

        Caller supplies `root` from chain state and the tuple they
        claim was in the bundle; the function recomputes the leaf and
        replays the path.  target_height binds to the leaf so a proof
        built for height H cannot be replayed at a different height.
        """
        try:
            idx = int(membership_proof["leaf_index"])
            siblings = list(membership_proof["siblings"])
        except (KeyError, TypeError, ValueError):
            return False
        leaf = _bundle_leaf_hash(entity_id, int(target_height), proof_tx_hash)
        reconstructed = _bundle_replay(leaf, idx, siblings)
        return reconstructed == root

    # ── canonical serialization ─────────────────────────────────────

    def to_bytes(self) -> bytes:
        """Stable wire format:
            count (u32)
         || root (32B)
         || count × (entity_id (32B) || target_height (u64 BE) || leaf (32B))

        target_height is part of each participant record so a decoder
        can reconstruct the leaf from known inputs and so the duty
        layer can enumerate the (prover, height) credit set without
        re-deriving from leaves.

        Deliberately does NOT include the full CustodyProof bodies;
        those live in the block body during the submission window and
        may be pruned afterward.  The bundle is the post-pruning
        residue.
        """
        import struct as _struct
        parts = [
            _struct.pack(">I", len(self.participants)),
            self.root,
        ]
        for (eid, height), leaf in zip(self.participants, self.leaf_hashes):
            if len(eid) != 32:
                raise ValueError(
                    f"participant entity_id must be 32 bytes, got {len(eid)}"
                )
            if len(leaf) != 32:
                raise ValueError(
                    f"leaf hash must be 32 bytes, got {len(leaf)}"
                )
            parts.append(eid)
            parts.append(_struct.pack(">Q", int(height)))
            parts.append(leaf)
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ArchiveProofBundle":
        import struct as _struct
        if len(data) < 4 + 32:
            raise ValueError("ArchiveProofBundle blob too short for header")
        count = _struct.unpack_from(">I", data, 0)[0]
        root = bytes(data[4:36])
        # Per-record size is 32 (entity_id) + 8 (height) + 32 (leaf) = 72.
        expected_len = 4 + 32 + count * (32 + 8 + 32)
        if len(data) != expected_len:
            raise ValueError(
                f"ArchiveProofBundle length mismatch: expected {expected_len} "
                f"bytes for {count} participants, got {len(data)}"
            )
        participants: list[tuple[bytes, int]] = []
        leaf_hashes: list[bytes] = []
        off = 36
        prev_key: Optional[tuple[bytes, int]] = None
        for _ in range(count):
            eid = bytes(data[off:off + 32]); off += 32
            height = _struct.unpack_from(">Q", data, off)[0]; off += 8
            leaf = bytes(data[off:off + 32]); off += 32
            key = (eid, height)
            # Sort invariant: on decode, reject out-of-order pairs so a
            # malicious relayer can't resubmit the same set in a
            # different order and trick a naive consumer.  Order is
            # (entity_id, target_height) ascending.
            if prev_key is not None and key <= prev_key:
                raise ValueError(
                    "ArchiveProofBundle participants not strictly sorted"
                )
            participants.append(key)
            leaf_hashes.append(leaf)
            prev_key = key
        # Recompute root from leaves and verify it matches the carried
        # root — the carried root is advisory; consensus trusts the
        # recomputation.
        recomputed = _bundle_build_root(leaf_hashes)
        if recomputed != root:
            raise ValueError(
                "ArchiveProofBundle carried root does not match recomputed root"
            )
        return cls(
            participants=participants,
            leaf_hashes=leaf_hashes,
            root=root,
        )
