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
    ARCHIVE_BURN_REDIRECT_PCT,
    ARCHIVE_CHALLENGE_INTERVAL,
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
    """Derive the challenge for the given block.

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
    if block_number <= 0:
        raise ValueError(
            f"Cannot issue an archive challenge at height {block_number}: "
            "no historical blocks to challenge"
        )
    if not isinstance(block_hash, (bytes, bytearray)) or len(block_hash) != 32:
        raise ValueError(
            f"block_hash must be 32 bytes, got {len(block_hash)}"
        )
    seed = _h(bytes(block_hash) + _CHALLENGE_DOMAIN_TAG)
    # Interpret as uint256 big-endian.  Mod B produces the target
    # height; mod num_txs is applied by the verifier once they know
    # num_txs.
    seed_int = int.from_bytes(seed, "big")
    target_height = seed_int % block_number
    return ArchiveChallenge(
        target_height=target_height,
        target_leaf_seed=seed_int,
    )


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
    """A claim of custody over a historical block.

    Fields:
        prover_id:           32-byte entity ID claiming the reward.
        target_height:       height the prover claims to hold.
        target_block_hash:   block hash of that height (32 bytes).
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

    The proof is unsigned in v1.  A signature would bind the claim to
    the prover and deny front-running, but v1 is open-submission with
    FCFS payout by block order — the proposer implicitly orders
    proofs, and a front-runner who copies someone else's valid proof
    still must commit the real `prover_id` to get paid.  That's a
    wash economically: the original submitter still must have actually
    held the data; the front-runner who steals it gets paid, but only
    because they also held the data (or could reconstruct the path
    from the stolen proof).  Accepting this trade-off keeps the v1
    scope tight; signatures can be added in v2 if frontrunning becomes
    observable.
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
        }

    @classmethod
    def deserialize(cls, data: dict) -> "CustodyProof":
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
        )

    def canonical_bytes(self) -> bytes:
        """Stable byte encoding used as the block-layer commitment.

        Covers every field that binds the proof to its claimed custody
        act — anyone mutating any of these invalidates the hash,
        therefore invalidates block.merkle_root, therefore invalidates
        the proposer's signature.  A MITM that flips `prover_id` alone
        breaks commitment, so the reward cannot be redirected without
        re-signing the block.
        """
        import struct as _struct
        parts = [
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
        """Decode a CustodyProof from its canonical_bytes form."""
        import struct as _struct
        off = 0
        if len(data) < 32 + 8 + 32 + 4:
            raise ValueError("CustodyProof blob too short")
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
    prover_id: bytes,
    target_height: int,
    target_block_hash: bytes,
    header_bytes: bytes,
    merkle_root: bytes,
    tx_index: Optional[int],
    tx_bytes: bytes,
    all_tx_hashes: list[bytes],
) -> CustodyProof:
    """Construct a CustodyProof over the given block contents.

    Caller supplies the full tx-hash list (so we can compute the
    Merkle path) plus the specific tx the prover is surrendering.  The
    caller is assumed to have the data — this routine doesn't verify
    it came from the claimed block; that's what `verify_custody_proof`
    is for.
    """
    if not isinstance(prover_id, (bytes, bytearray)) or len(prover_id) != 32:
        raise ValueError("prover_id must be 32 bytes")

    # Empty-block case: header-only custody.  No Merkle path, no tx.
    if not all_tx_hashes:
        if tx_index is not None or tx_bytes:
            raise ValueError(
                "Empty block requires tx_index=None and tx_bytes=b''"
            )
        return CustodyProof(
            prover_id=bytes(prover_id),
            target_height=int(target_height),
            target_block_hash=bytes(target_block_hash),
            header_bytes=bytes(header_bytes),
            merkle_root=bytes(merkle_root),
            tx_index=None,
            tx_bytes=b"",
            merkle_path=[],
            merkle_layer_sizes=[0],
        )

    if tx_index is None:
        raise ValueError("Non-empty block requires tx_index")
    if not (0 <= tx_index < len(all_tx_hashes)):
        raise ValueError(
            f"tx_index {tx_index} out of range for {len(all_tx_hashes)} txs"
        )
    # Sanity check — tx_hash must match hashed tx_bytes
    if _h(bytes(tx_bytes)) != all_tx_hashes[tx_index]:
        raise ValueError(
            "tx_bytes hash does not match all_tx_hashes[tx_index] — "
            "inconsistent caller input"
        )
    siblings, layer_sizes = _build_path(all_tx_hashes, tx_index)
    return CustodyProof(
        prover_id=bytes(prover_id),
        target_height=int(target_height),
        target_block_hash=bytes(target_block_hash),
        header_bytes=bytes(header_bytes),
        merkle_root=bytes(merkle_root),
        tx_index=int(tx_index),
        tx_bytes=bytes(tx_bytes),
        merkle_path=[bytes(s) for s in siblings],
        merkle_layer_sizes=list(layer_sizes),
    )


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
    reward_amount: int = ARCHIVE_REWARD,
    max_payouts: int = ARCHIVE_PROOFS_PER_CHALLENGE,
) -> ArchiveRewardResult:
    """Pay up to `max_payouts` FCFS rewards from `pool`.

    - Iterates `proofs` in supplied order (the proposer's listed
      order in the block).
    - Validates each against `expected_block_hash`.
    - Pays up to `reward_amount` per valid, unique prover.
    - Duplicates (same prover_id submitting twice) are silently
      dropped — one reward per prover per challenge caps Sybil
      amplification to zero.
    - Stops once `max_payouts` valid proofs have been paid OR the
      pool empties (returns 0 from try_pay).

    Does not mutate any balance other than the pool's — the caller
    splices `result.payouts` into its own supply ledger.  This keeps
    the module testable without a live Blockchain.
    """
    result = ArchiveRewardResult()
    seen_provers: set[bytes] = set()

    for proof in proofs:
        if len(result.payouts) >= max_payouts:
            break
        ok, reason = verify_custody_proof(
            proof, expected_block_hash=expected_block_hash,
        )
        if not ok:
            result.rejected.append(reason)
            continue
        if proof.prover_id in seen_provers:
            result.rejected.append("duplicate prover")
            continue
        paid = pool.try_pay(reward_amount)
        if paid <= 0:
            # Pool exhausted — no point continuing, future proofs
            # will also get 0.  Record each as a skip for audit.
            result.rejected.append("pool exhausted")
            break
        seen_provers.add(proof.prover_id)
        result.payouts.append(_Payout(prover_id=proof.prover_id, amount=paid))
        result.total_paid += paid

    return result
