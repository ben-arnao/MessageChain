"""Quorum-signed inclusion lists — consensus-objective forced inclusion.

Background
==========

MessageChain's first censorship-resistance lever, `forced_inclusion.py`,
is attester-subjective: each attester looks at its OWN mempool, picks
the top-N by fee, and soft-votes against proposers that omit those txs
without a structural excuse.  That defense is mempool-local and
slashing-free.  A coordinated minority of validators (up to 1/3 of
stake) can refuse to attest against a censoring proposer — the block
still finalizes, and no one is punished on-chain.

Quorum-signed inclusion lists close the gap.  The list is
CONSENSUS-OBJECTIVE: every node can verify from the on-chain
attestations that >= INCLUSION_LIST_QUORUM_BPS of stake independently
saw each tx_hash for at least INCLUSION_LIST_WAIT_BLOCKS blocks.  An
InclusionList published in block N applies forward to blocks
N+1..N+INCLUSION_LIST_WINDOW; a proposer in that window that omits a
mandated tx without a structural excuse is SLASHED via
`InclusionListViolationEvidenceTx` for INCLUSION_VIOLATION_SLASH_BPS of
their stake (burned, no finder reward — matches the posture of the
existing evidence-tx slashing paths).

Design choice: Option A (attester-gossiped mempool reports)
============================================================

Each attester periodically gossips an `AttesterMempoolReport` committing
to the set of tx_hashes its mempool has held for at least
INCLUSION_LIST_WAIT_BLOCKS.  Reports are signed, carry a domain-
separated tag (``mc-attester-mempool-report-v1``), and are bundled
inside the `InclusionList` they justify.

The proposer of block N:

  * Collects reports whose ``report_height`` sits inside
    ``[N - INCLUSION_LIST_WAIT_BLOCKS, N - 1]``.
  * Intersects them stake-weighted: every tx_hash that appears in
    reports totalling at least INCLUSION_LIST_QUORUM_BPS of stake
    becomes an entry.
  * Publishes the aggregated `InclusionList` in their block.

Reports themselves are NOT individually slashable — only the final
aggregated list is consensus-binding.  This keeps the attacker surface
small: a validator lying in a single gossip report accomplishes
nothing on its own because their report is one of many weighted inputs,
and even the full list is not directly slashable — it only MANDATES
downstream behaviour (include the listed txs).  The enforcement arc is
intentionally one-way: a list can force inclusion but cannot punish
the inputs that built it.

Option B (attesters individually sign the proposed list after the
proposer drafts it) was considered and rejected — it needs an extra
gossip round, and its benefit (committing to a proposer-chosen list
rather than a reporter-computed one) is neutralised by the fact that
the proposer is already free to omit reports; the 2/3 weighting is
what matters, and that property is already achieved by Option A.

Processor
=========

`InclusionListProcessor` tracks:

  * `active_lists`: publish_height → InclusionList.  A list is
    "active" while the current block height is within its forward
    window.  Block validation reads this map to decide whether the
    current block carries a valid excuse or has committed censorship.
  * `processed_violations`: set[(list_hash, tx_hash, proposer_id)].
    Every violation slash applied is recorded here so a second
    evidence against the same (list, tx, proposer) triple cannot
    re-slash.  list_hash is part of the key because two overlapping
    inclusion lists can both mandate the same tx: omitting that tx
    while BOTH lists are active is two violations, not one.

Both fields participate in the state-snapshot root so every node
reaches identical slashing outcomes after replay.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Iterable, Optional

from messagechain.config import (
    HASH_ALGO, CHAIN_ID, SIG_VERSION_CURRENT,
    INCLUSION_LIST_WAIT_BLOCKS,
    INCLUSION_LIST_WINDOW,
    INCLUSION_LIST_QUORUM_BPS,
    MAX_INCLUSION_LIST_ENTRIES,
    INCLUSION_VIOLATION_SLASH_BPS,
    INCLUSION_LIST_VERSION,
    MIN_FEE,
    validate_inclusion_list_version,
)
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.crypto.hashing import default_hash


# Domain tags — MUST differ so a signature over one type can never be
# replayed as a signature over another.  Verify-time code reads the
# constants below (never inlines the string) so a typo during a future
# refactor is caught by the import chain, not silently at verify time.
ATTESTER_MEMPOOL_REPORT_DOMAIN_TAG = b"mc-attester-mempool-report-v1"
INCLUSION_LIST_DOMAIN_TAG = b"mc-inclusion-list-v1"
INCLUSION_LIST_VIOLATION_DOMAIN_TAG = b"mc-inclusion-list-violation-v1"


def _h(data: bytes) -> bytes:
    return default_hash(data)


# ─────────────────────────────────────────────────────────────────────
# AttesterMempoolReport
# ─────────────────────────────────────────────────────────────────────

@dataclass
class AttesterMempoolReport:
    """One attester's signed commitment: "at block report_height, my
    mempool has been holding these tx_hashes for at least
    INCLUSION_LIST_WAIT_BLOCKS."

    Canonical form: tx_hashes are sorted bytewise before signing.  Two
    attesters with the same semantic set produce byte-identical
    signable_data regardless of insertion order, keeping the quorum
    tally stable across gossip paths.
    """
    reporter_id: bytes
    report_height: int
    tx_hashes: list[bytes]
    signature: Signature

    def __post_init__(self):
        # Canonicalise immediately so callers observing the dataclass
        # fields see the same ordering used by signing and verification.
        self.tx_hashes = sorted(self.tx_hashes)

    def _signable_data(self) -> bytes:
        sig_version = getattr(
            self.signature, "sig_version", SIG_VERSION_CURRENT,
        )
        # tx_hashes are sorted at __post_init__; concatenate without a
        # length byte per hash (all hashes are HASH_ALGO-sized).  Prefix
        # with u32 count so a relayer cannot silently append a hash.
        body = struct.pack(">I", len(self.tx_hashes))
        for tx_hash in self.tx_hashes:
            if len(tx_hash) != 32:
                raise ValueError(
                    f"tx_hash must be 32 bytes, got {len(tx_hash)}"
                )
            body += tx_hash
        return b"".join([
            CHAIN_ID,
            ATTESTER_MEMPOOL_REPORT_DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.reporter_id,
            struct.pack(">Q", int(self.report_height)),
            body,
        ])

    def serialize(self) -> dict:
        return {
            "reporter_id": self.reporter_id.hex(),
            "report_height": self.report_height,
            "tx_hashes": [h.hex() for h in self.tx_hashes],
            "signature": self.signature.serialize(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "AttesterMempoolReport":
        return cls(
            reporter_id=bytes.fromhex(data["reporter_id"]),
            report_height=int(data["report_height"]),
            tx_hashes=[bytes.fromhex(h) for h in data["tx_hashes"]],
            signature=Signature.deserialize(data["signature"]),
        )

    def to_bytes(self) -> bytes:
        sig_blob = self.signature.to_bytes()
        parts = [
            self.reporter_id,
            struct.pack(">Q", int(self.report_height)),
            struct.pack(">I", len(self.tx_hashes)),
        ]
        parts.extend(self.tx_hashes)
        parts.append(struct.pack(">I", len(sig_blob)))
        parts.append(sig_blob)
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "AttesterMempoolReport":
        off = 0
        if len(data) < 32 + 8 + 4 + 4:
            raise ValueError("AttesterMempoolReport blob too short")
        reporter_id = bytes(data[off:off + 32]); off += 32
        report_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        n = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + 32 * n + 4 > len(data):
            raise ValueError("AttesterMempoolReport truncated at tx_hashes")
        tx_hashes = []
        for _ in range(n):
            tx_hashes.append(bytes(data[off:off + 32])); off += 32
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len > len(data):
            raise ValueError("AttesterMempoolReport truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        if off != len(data):
            raise ValueError("AttesterMempoolReport has trailing bytes")
        return cls(
            reporter_id=reporter_id,
            report_height=report_height,
            tx_hashes=tx_hashes,
            signature=sig,
        )


def build_attester_mempool_report(
    reporter_entity,
    report_height: int,
    tx_hashes: list[bytes],
) -> AttesterMempoolReport:
    """Build + sign an AttesterMempoolReport in one step.

    Consumes one WOTS+ leaf from reporter_entity.keypair.  Reports are
    gossiped out-of-band and aggregated by the proposer — they never
    appear in the chain on their own; the leaf they burn is the only
    per-report overhead visible to the network.
    """
    placeholder = Signature([], 0, [], b"", b"")
    report = AttesterMempoolReport(
        reporter_id=reporter_entity.entity_id,
        report_height=report_height,
        tx_hashes=list(tx_hashes),
        signature=placeholder,
    )
    msg_hash = _h(report._signable_data())
    report.signature = reporter_entity.keypair.sign(msg_hash)
    return report


def verify_attester_mempool_report(
    report: AttesterMempoolReport,
    reporter_public_key: bytes,
) -> bool:
    """Verify the signature of a report under its reporter's pubkey."""
    msg_hash = _h(report._signable_data())
    return verify_signature(msg_hash, report.signature, reporter_public_key)


# ─────────────────────────────────────────────────────────────────────
# InclusionList — aggregated, quorum-backed commitment
# ─────────────────────────────────────────────────────────────────────

@dataclass
class InclusionListEntry:
    tx_hash: bytes
    first_seen_height: int

    def serialize(self) -> dict:
        return {
            "tx_hash": self.tx_hash.hex(),
            "first_seen_height": self.first_seen_height,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "InclusionListEntry":
        return cls(
            tx_hash=bytes.fromhex(data["tx_hash"]),
            first_seen_height=int(data["first_seen_height"]),
        )


@dataclass
class InclusionList:
    """Consensus-binding commitment to a set of tx_hashes that >= 2/3 of
    stake reported having held for >= INCLUSION_LIST_WAIT_BLOCKS.

    Proposers within [publish_height+1, publish_height+window_blocks]
    MUST include every listed tx, or attach a structural excuse.  After
    expiry, missed txs produce slashable
    InclusionListViolationEvidenceTx traffic.

    `list_hash` commits to the sorted entries + publish_height + window
    but NOT to the quorum_attestation.  Two otherwise-identical lists
    whose witness sets differ in composition still share one identity
    — which is what we want: dedupe and downstream references key on
    the commitment, not the proof.
    """
    publish_height: int
    window_blocks: int
    entries: list[InclusionListEntry]
    quorum_attestation: list[AttesterMempoolReport]
    version: int = INCLUSION_LIST_VERSION
    list_hash: bytes = b""

    def __post_init__(self):
        # Compute the identity hash from the entries AS-PROVIDED.  We
        # deliberately do NOT auto-sort: validation must be able to
        # detect a hand-crafted list whose entries are out of canonical
        # order (`verify_inclusion_list_quorum` checks the strictly-
        # increasing invariant).  Aggregation helpers sort their inputs
        # before constructing, so well-formed paths are unaffected.
        if not self.list_hash:
            self.list_hash = self._compute_hash()

    def _canonical_commit_bytes(self) -> bytes:
        """Canonical bytes for list_hash.

        Commits to: version, publish_height, window_blocks, the sorted
        entries (tx_hash | first_seen_height each).  Does NOT commit to
        the quorum_attestation — that's the witness, not the commitment.
        """
        parts = [
            INCLUSION_LIST_DOMAIN_TAG,
            struct.pack(">B", self.version),
            struct.pack(">Q", int(self.publish_height)),
            struct.pack(">I", int(self.window_blocks)),
            struct.pack(">I", len(self.entries)),
        ]
        for e in self.entries:
            parts.append(e.tx_hash)
            parts.append(struct.pack(">Q", int(e.first_seen_height)))
        return b"".join(parts)

    def _compute_hash(self) -> bytes:
        return _h(self._canonical_commit_bytes())

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "publish_height": self.publish_height,
            "window_blocks": self.window_blocks,
            "entries": [e.serialize() for e in self.entries],
            "quorum_attestation": [
                r.serialize() for r in self.quorum_attestation
            ],
            "list_hash": self.list_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "InclusionList":
        version = int(data.get("version", INCLUSION_LIST_VERSION))
        ok, reason = validate_inclusion_list_version(version)
        if not ok:
            raise ValueError(f"InclusionList: {reason}")
        lst = cls(
            publish_height=int(data["publish_height"]),
            window_blocks=int(data["window_blocks"]),
            entries=[
                InclusionListEntry.deserialize(e) for e in data["entries"]
            ],
            quorum_attestation=[
                AttesterMempoolReport.deserialize(r)
                for r in data["quorum_attestation"]
            ],
            version=version,
        )
        declared = bytes.fromhex(data["list_hash"])
        if declared != lst.list_hash:
            raise ValueError(
                f"InclusionList hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {lst.list_hash.hex()[:16]}"
            )
        return lst

    def to_bytes(self) -> bytes:
        parts = [
            struct.pack(">B", self.version),
            struct.pack(">Q", int(self.publish_height)),
            struct.pack(">I", int(self.window_blocks)),
            struct.pack(">I", len(self.entries)),
        ]
        for e in self.entries:
            parts.append(e.tx_hash)
            parts.append(struct.pack(">Q", int(e.first_seen_height)))
        parts.append(struct.pack(">I", len(self.quorum_attestation)))
        for r in self.quorum_attestation:
            blob = r.to_bytes()
            parts.append(struct.pack(">I", len(blob)))
            parts.append(blob)
        parts.append(self.list_hash)
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "InclusionList":
        off = 0
        if len(data) < 1 + 8 + 4 + 4 + 4 + 32:
            raise ValueError("InclusionList blob too short")
        version = struct.unpack_from(">B", data, off)[0]; off += 1
        ok, reason = validate_inclusion_list_version(version)
        if not ok:
            raise ValueError(f"InclusionList: {reason}")
        publish_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        window_blocks = struct.unpack_from(">I", data, off)[0]; off += 4
        n_entries = struct.unpack_from(">I", data, off)[0]; off += 4
        entries = []
        for _ in range(n_entries):
            if off + 32 + 8 > len(data):
                raise ValueError("InclusionList truncated at entries")
            tx_hash = bytes(data[off:off + 32]); off += 32
            first_seen = struct.unpack_from(">Q", data, off)[0]; off += 8
            entries.append(InclusionListEntry(
                tx_hash=tx_hash, first_seen_height=first_seen,
            ))
        n_reports = struct.unpack_from(">I", data, off)[0]; off += 4
        reports = []
        for _ in range(n_reports):
            if off + 4 > len(data):
                raise ValueError(
                    "InclusionList truncated at quorum_attestation"
                )
            r_len = struct.unpack_from(">I", data, off)[0]; off += 4
            if off + r_len > len(data):
                raise ValueError("InclusionList truncated inside report blob")
            reports.append(
                AttesterMempoolReport.from_bytes(bytes(data[off:off + r_len]))
            )
            off += r_len
        if off + 32 > len(data):
            raise ValueError("InclusionList truncated at list_hash")
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("InclusionList has trailing bytes")
        lst = cls(
            publish_height=publish_height,
            window_blocks=window_blocks,
            entries=entries,
            quorum_attestation=reports,
            version=version,
        )
        if lst.list_hash != declared:
            raise ValueError(
                f"InclusionList hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {lst.list_hash.hex()[:16]}"
            )
        return lst


def aggregate_inclusion_list(
    reports: Iterable[AttesterMempoolReport],
    stakes: dict[bytes, int],
    publish_height: int,
    window_blocks: int = INCLUSION_LIST_WINDOW,
) -> InclusionList:
    """Construct an InclusionList by stake-weighted aggregation.

    Every tx_hash that appears in reports totalling at least
    INCLUSION_LIST_QUORUM_BPS of the TOTAL staked weight (sum of
    `stakes.values()`) becomes an entry.  first_seen_height is the
    minimum report_height across reports that contributed.

    Callers are responsible for pre-filtering reports to those from
    currently-valid signers over an accepted window — aggregate() does
    not re-verify signatures, because callers with chain state can do
    that once per report rather than re-hashing here.  The returned
    list's quorum_attestation bundles the supplied reports verbatim so
    block validators can re-verify end-to-end.
    """
    reports = list(reports)
    total_stake = sum(stakes.values())
    if total_stake <= 0:
        return InclusionList(
            publish_height=publish_height,
            window_blocks=window_blocks,
            entries=[],
            quorum_attestation=reports,
        )
    # Per-tx_hash: cumulative signer stake + min first_seen_height.
    tallies: dict[bytes, tuple[int, int]] = {}
    # Deduplicate reporter contributions — the same reporter's second
    # report at a later height must not double-count.  Keep the most
    # recent one (highest report_height) but cap influence to one voice
    # per reporter by tracking counted_reporters per tx_hash.
    counted_per_tx: dict[bytes, set[bytes]] = {}
    for r in reports:
        stake = stakes.get(r.reporter_id, 0)
        if stake <= 0:
            continue
        for tx_hash in r.tx_hashes:
            seen = counted_per_tx.setdefault(tx_hash, set())
            if r.reporter_id in seen:
                # Already counted this reporter for this tx; keep the
                # MIN first_seen_height across their reports.
                cur_stake, cur_fsh = tallies[tx_hash]
                tallies[tx_hash] = (
                    cur_stake, min(cur_fsh, r.report_height),
                )
                continue
            seen.add(r.reporter_id)
            if tx_hash in tallies:
                cur_stake, cur_fsh = tallies[tx_hash]
                tallies[tx_hash] = (
                    cur_stake + stake, min(cur_fsh, r.report_height),
                )
            else:
                tallies[tx_hash] = (stake, r.report_height)
    # Threshold check: stake * 10_000 >= total_stake * QUORUM_BPS.
    entries = [
        InclusionListEntry(tx_hash=tx_h, first_seen_height=fsh)
        for tx_h, (s, fsh) in tallies.items()
        if s * 10_000 >= total_stake * INCLUSION_LIST_QUORUM_BPS
    ]
    entries.sort(key=lambda e: e.tx_hash)
    # Apply the per-list cap: even under a massive quorum, never emit
    # more entries than MAX_INCLUSION_LIST_ENTRIES.  Chooses the
    # entries sorted bytewise — same tiebreaker as validation.
    if len(entries) > MAX_INCLUSION_LIST_ENTRIES:
        entries = entries[:MAX_INCLUSION_LIST_ENTRIES]
    return InclusionList(
        publish_height=publish_height,
        window_blocks=window_blocks,
        entries=entries,
        quorum_attestation=reports,
    )


def verify_inclusion_list_quorum(
    lst: InclusionList,
    stakes: dict[bytes, int],
    public_keys: dict[bytes, bytes],
) -> tuple[bool, str]:
    """Verify the list's entries are each backed by >= 2/3 stake AND
    the witness bundle is well-formed.

    Checks, in order:
      * version is accepted
      * window_blocks == INCLUSION_LIST_WINDOW (no proposer tampering
        with the forward window)
      * entries are in canonical order and deduplicated
      * entry count <= MAX_INCLUSION_LIST_ENTRIES
      * every quorum_attestation report is from a known signer
        (non-zero stake + registered pubkey) AND its signature
        verifies AND its report_height falls in
        [publish_height - INCLUSION_LIST_WAIT_BLOCKS, publish_height - 1]
      * for each entry: stake-weighted sum of reports containing
        entry.tx_hash >= INCLUSION_LIST_QUORUM_BPS of total stake
      * entry.first_seen_height >= publish_height - INCLUSION_LIST_WAIT_BLOCKS

    Returns (True, "OK") on success; (False, reason) on failure.
    """
    ok, reason = validate_inclusion_list_version(lst.version)
    if not ok:
        return False, reason
    if lst.window_blocks != INCLUSION_LIST_WINDOW:
        return False, (
            f"window_blocks must equal INCLUSION_LIST_WINDOW "
            f"({INCLUSION_LIST_WINDOW}), got {lst.window_blocks}"
        )
    if len(lst.entries) > MAX_INCLUSION_LIST_ENTRIES:
        return False, (
            f"entries {len(lst.entries)} exceed cap "
            f"{MAX_INCLUSION_LIST_ENTRIES}"
        )
    # Canonical sort + dedup check: entries must be strictly increasing
    # by tx_hash.  "strictly" catches duplicate-tx-hash attempts.
    prev_hash: Optional[bytes] = None
    seen_hashes: set[bytes] = set()
    for e in lst.entries:
        if prev_hash is not None and e.tx_hash <= prev_hash:
            return False, (
                "entries must be sorted by tx_hash with no duplicates"
            )
        if e.tx_hash in seen_hashes:
            return False, "duplicate tx_hash in entries"
        seen_hashes.add(e.tx_hash)
        prev_hash = e.tx_hash

    total_stake = sum(stakes.values())
    if total_stake <= 0:
        return False, "total stake is zero"
    # Per-report validation + per-tx tallies.
    min_ok_height = lst.publish_height - INCLUSION_LIST_WAIT_BLOCKS
    max_ok_height = lst.publish_height - 1
    tallies: dict[bytes, int] = {}
    first_seen_min: dict[bytes, int] = {}
    counted: dict[bytes, set[bytes]] = {}
    for r in lst.quorum_attestation:
        if r.report_height < min_ok_height or r.report_height > max_ok_height:
            # Reports outside the window contribute nothing — skip but
            # don't fail the whole list.  An adversarial proposer that
            # pads the bundle with stale reports gains nothing.
            continue
        stake = stakes.get(r.reporter_id, 0)
        if stake <= 0:
            continue  # unknown / unstaked reporter contributes nothing
        pk = public_keys.get(r.reporter_id)
        if pk is None:
            continue  # no on-chain pubkey to verify against
        if not verify_attester_mempool_report(r, pk):
            return False, (
                f"invalid signature on attester report from "
                f"{r.reporter_id.hex()[:16]}"
            )
        for tx_hash in r.tx_hashes:
            seen = counted.setdefault(tx_hash, set())
            if r.reporter_id in seen:
                fsh = first_seen_min.get(tx_hash, r.report_height)
                first_seen_min[tx_hash] = min(fsh, r.report_height)
                continue
            seen.add(r.reporter_id)
            tallies[tx_hash] = tallies.get(tx_hash, 0) + stake
            fsh = first_seen_min.get(tx_hash, r.report_height)
            first_seen_min[tx_hash] = min(fsh, r.report_height)

    # Per-entry checks: bounds first (so a hand-crafted "stale" claim
    # is rejected with an "aged" reason regardless of whether the
    # tally even reaches the quorum), then quorum tally.
    for e in lst.entries:
        # Entry's declared first_seen_height must be consistent with
        # the window AND not tighter than what the reports support.
        if e.first_seen_height < min_ok_height:
            return False, (
                f"entry {e.tx_hash.hex()[:16]} first_seen_height "
                f"{e.first_seen_height} predates the wait window "
                f"(min {min_ok_height}).  Badly-aged report claim."
            )
        if e.first_seen_height > max_ok_height:
            return False, (
                f"entry {e.tx_hash.hex()[:16]} first_seen_height "
                f"{e.first_seen_height} exceeds publish_height - 1 "
                f"({max_ok_height}).  Badly-aged forward claim."
            )
        s = tallies.get(e.tx_hash, 0)
        if s * 10_000 < total_stake * INCLUSION_LIST_QUORUM_BPS:
            return False, (
                f"entry {e.tx_hash.hex()[:16]} falls short of "
                f"{INCLUSION_LIST_QUORUM_BPS}bps quorum "
                f"(got {s * 10_000 // max(total_stake, 1)}bps)"
            )
        reported = first_seen_min.get(e.tx_hash)
        if reported is not None and e.first_seen_height > reported:
            return False, (
                f"entry {e.tx_hash.hex()[:16]} first_seen_height "
                f"{e.first_seen_height} is older than any supporting "
                f"report (min report_height {reported})"
            )

    return True, "OK"


# ─────────────────────────────────────────────────────────────────────
# Processor — lifecycle + snapshot
# ─────────────────────────────────────────────────────────────────────

@dataclass
class InclusionViolation:
    """Result of processor.expire(): one tx_hash that a proposer failed
    to include during an active window, with the accused proposers.

    The (list_hash, tx_hash, proposer_id) triple is the dedup key for
    `processed_violations` — a single violation-evidence tx slashes
    exactly one proposer, so the same missed-tx can in principle ground
    multiple evidences (one per accused proposer, one per list that
    mandated it), each limited once by the dedupe.
    """
    list_hash: bytes
    tx_hash: bytes
    accused_proposers: list[bytes]


class InclusionListProcessor:
    """Tracks active lists and violation bookkeeping.

    Design mirror of `CensorshipEvidenceProcessor`.  `active_lists` is
    analogous to `pending`; `processed_violations` to `processed`.  Both
    are snapshot-serialised so every node reaches identical outcomes.
    """

    def __init__(self):
        # publish_height → InclusionList.  Multiple lists can be active
        # simultaneously when WINDOW > 1 block's gap between
        # publications.
        self.active_lists: dict[int, InclusionList] = {}
        # Per-list, per-tx_hash: the set of heights at which the tx
        # landed on-chain.  Block validation + expiry both read this.
        # Keyed by (list_hash, tx_hash).
        self.inclusions_seen: dict[tuple[bytes, bytes], list[int]] = {}
        # Per-list, per-height: the proposer that was in charge at that
        # height.  Filled by observe_block().  Keyed by list_hash for
        # expiry accounting.
        self.proposers_by_height: dict[bytes, dict[int, bytes]] = {}
        # Double-slash defence.  One (list_hash, tx_hash, proposer_id)
        # triple may be slashed at most once across the chain's whole
        # history.  list_hash participates so a proposer who omitted
        # the same tx from two overlapping lists is slashed once per
        # list, not once total.
        self.processed_violations: set[tuple[bytes, bytes, bytes]] = set()

    # ── Active-window queries ──────────────────────────────────────────

    def register(
        self,
        inclusion_list: InclusionList,
        current_height: int,
    ) -> None:
        """Add a newly-published list to the active set.

        Idempotent: re-registering the same list is a no-op.
        `current_height` MUST equal inclusion_list.publish_height — the
        check is defensive only (callers already know this) but must
        survive ``python -O`` (which strips ``assert``), so we raise
        ``ChainIntegrityError`` instead.
        """
        from messagechain.core.blockchain import ChainIntegrityError
        if current_height != inclusion_list.publish_height:
            raise ChainIntegrityError(
                f"register height mismatch: {current_height} vs "
                f"{inclusion_list.publish_height}"
            )
        self.active_lists.setdefault(
            inclusion_list.publish_height, inclusion_list,
        )
        self.proposers_by_height.setdefault(inclusion_list.list_hash, {})

    def active_lists_at_height(self, height: int) -> list[InclusionList]:
        """Return every list whose forward window covers `height`.

        The window of a list published at N is [N+1, N+window_blocks].
        """
        out = []
        for ph, lst in self.active_lists.items():
            if ph < height <= ph + lst.window_blocks:
                out.append(lst)
        return out

    # ── Apply-time observations ───────────────────────────────────────

    def observe_block(self, block) -> None:
        """Record every list-mandated tx_hash that appeared in `block`
        AND record the proposer of `block` against every currently-
        active list.

        The block's proposer_id is used verbatim — no deeper introspection
        needed.  The proposers_by_height map is what expire() consults
        when it emits violation records.
        """
        height = getattr(block.header, "block_number", None)
        if height is None:
            return
        proposer_id = getattr(block.header, "proposer_id", b"")
        # Gather tx_hashes the block included (MessageTransactions +
        # transfer_transactions — both are user-payable slots that a
        # list might reference).
        seen_tx_hashes: set[bytes] = set()
        for tx in getattr(block, "transactions", []) or []:
            seen_tx_hashes.add(tx.tx_hash)
        for tx in getattr(block, "transfer_transactions", []) or []:
            seen_tx_hashes.add(tx.tx_hash)

        for ph, lst in list(self.active_lists.items()):
            # Only observe blocks inside the forward window.
            if not (ph < height <= ph + lst.window_blocks):
                continue
            # Record proposer for this (list, height).
            self.proposers_by_height.setdefault(lst.list_hash, {})[height] = (
                proposer_id
            )
            for e in lst.entries:
                if e.tx_hash in seen_tx_hashes:
                    self.inclusions_seen.setdefault(
                        (lst.list_hash, e.tx_hash), [],
                    ).append(height)

    # ── Expiry ────────────────────────────────────────────────────────

    def expire(
        self,
        current_height: int,
        proposers_by_height: Optional[dict[int, bytes]] = None,
    ) -> list[InclusionViolation]:
        """Drop lists whose forward window has closed AND emit
        InclusionViolation records for missed txs.

        `proposers_by_height`: optional override, used by tests that
        don't run the full block pipeline.  When None, the processor's
        own per-list proposers_by_height (populated by observe_block)
        is consulted instead.

        Returns the list of violations to feed to any slashing / audit
        path.  Does NOT apply slashes itself — that's the caller's
        responsibility (matching the CensorshipEvidenceProcessor.mature
        shape).
        """
        violations: list[InclusionViolation] = []
        to_remove: list[int] = []
        for ph, lst in self.active_lists.items():
            # Window closed iff current_height > ph + window_blocks.
            if current_height <= ph + lst.window_blocks:
                continue
            to_remove.append(ph)
            # Collect per-list accused-proposer map.
            if proposers_by_height is not None:
                accused_map = proposers_by_height
            else:
                accused_map = self.proposers_by_height.get(
                    lst.list_hash, {},
                )
            # Every entry that never saw an inclusion-observation is a
            # violation.
            for e in lst.entries:
                if self.inclusions_seen.get((lst.list_hash, e.tx_hash)):
                    continue
                # Every proposer that sat inside the window is accused.
                accused = [
                    accused_map[h]
                    for h in sorted(accused_map.keys())
                    if ph < h <= ph + lst.window_blocks
                ]
                # Deduplicate: the same proposer may have produced
                # multiple blocks in the window.
                dedup: list[bytes] = []
                seen: set[bytes] = set()
                for p in accused:
                    if p in seen:
                        continue
                    seen.add(p)
                    dedup.append(p)
                violations.append(InclusionViolation(
                    list_hash=lst.list_hash,
                    tx_hash=e.tx_hash,
                    accused_proposers=dedup,
                ))
        # Drop expired entries.
        for ph in to_remove:
            lst = self.active_lists.pop(ph, None)
            if lst is not None:
                # Clean up the per-list bookkeeping too — keeps the
                # snapshot tight.  processed_violations persists.
                self.proposers_by_height.pop(lst.list_hash, None)
                for e in lst.entries:
                    self.inclusions_seen.pop((lst.list_hash, e.tx_hash), None)
        return violations

    # ── Double-slash defence ──────────────────────────────────────────

    def has_processed(
        self, list_hash: bytes, tx_hash: bytes, proposer_id: bytes,
    ) -> bool:
        return (list_hash, tx_hash, proposer_id) in self.processed_violations

    # ── Snapshot serialisation ────────────────────────────────────────

    def snapshot_dict(self) -> dict:
        """Deterministic dict form for state-snapshot inclusion.

        Uses hex-encoded keys / values so the JSON-friendly shape
        matches the other processors.
        """
        return {
            "active_lists": {
                ph: lst.serialize() for ph, lst in self.active_lists.items()
            },
            "inclusions_seen": {
                lst_hash.hex() + "|" + tx_hash.hex(): heights
                for (lst_hash, tx_hash), heights
                in self.inclusions_seen.items()
            },
            "proposers_by_height": {
                lst_hash.hex(): {
                    str(h): pid.hex() for h, pid in m.items()
                }
                for lst_hash, m in self.proposers_by_height.items()
            },
            "processed_violations": sorted(
                [lh.hex() + "|" + tx.hex() + "|" + pid.hex()
                 for (lh, tx, pid) in self.processed_violations]
            ),
        }

    def load_snapshot_dict(self, data: dict) -> None:
        self.active_lists = {
            int(ph): InclusionList.deserialize(entry)
            for ph, entry in data.get("active_lists", {}).items()
        }
        ins: dict[tuple[bytes, bytes], list[int]] = {}
        for compound, heights in data.get("inclusions_seen", {}).items():
            lst_hex, tx_hex = compound.split("|", 1)
            ins[(bytes.fromhex(lst_hex), bytes.fromhex(tx_hex))] = [
                int(h) for h in heights
            ]
        self.inclusions_seen = ins
        pbh: dict[bytes, dict[int, bytes]] = {}
        for lst_hex, m in data.get("proposers_by_height", {}).items():
            pbh[bytes.fromhex(lst_hex)] = {
                int(h): bytes.fromhex(pid) for h, pid in m.items()
            }
        self.proposers_by_height = pbh
        pv: set[tuple[bytes, bytes, bytes]] = set()
        for compound in data.get("processed_violations", []):
            parts = compound.split("|")
            if len(parts) != 3:
                raise ValueError(
                    "processed_violations entry must be "
                    "'list_hash|tx_hash|proposer_id' hex triple, "
                    f"got {len(parts)} parts"
                )
            lh_hex, tx_hex, pid_hex = parts
            pv.add((
                bytes.fromhex(lh_hex),
                bytes.fromhex(tx_hex),
                bytes.fromhex(pid_hex),
            ))
        self.processed_violations = pv


# ─────────────────────────────────────────────────────────────────────
# InclusionListViolationEvidenceTx
# ─────────────────────────────────────────────────────────────────────

@dataclass
class InclusionListViolationEvidenceTx:
    """Evidence tx that names a proposer who failed to include a
    list-mandated tx during an active window.

    Wire layout mirrors CensorshipEvidenceTx / BogusRejectionEvidenceTx
    for consistency.  The evidence_hash = H(domain | list_hash |
    tx_hash | accused_proposer_id | accused_height), keyed so two
    submissions against the same (list, tx, proposer) collide and the
    second is dropped as already-processed.
    """
    inclusion_list: InclusionList
    omitted_tx_hash: bytes
    accused_proposer_id: bytes
    accused_height: int
    submitter_id: bytes
    timestamp: int
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    @property
    def offender_id(self) -> bytes:
        return self.accused_proposer_id

    @property
    def evidence_hash(self) -> bytes:
        return _h(
            INCLUSION_LIST_VIOLATION_DOMAIN_TAG
            + self.inclusion_list.list_hash
            + self.omitted_tx_hash
            + self.accused_proposer_id
            + struct.pack(">Q", int(self.accused_height))
        )

    def affected_entities(self) -> set[bytes]:
        """Apply path debits the submitter's fee + bumps their
        leaf_watermark; on accepted slash the accused proposer's stake
        is burned in the same block.  Both mutate in the admission
        block.  See CLAUDE.md canonical registry contract.
        """
        return {self.submitter_id, self.accused_proposer_id}

    def _signable_data(self) -> bytes:
        sig_version = getattr(
            self.signature, "sig_version", SIG_VERSION_CURRENT,
        )
        return b"".join([
            CHAIN_ID,
            INCLUSION_LIST_VIOLATION_DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.inclusion_list.list_hash,
            self.omitted_tx_hash,
            self.accused_proposer_id,
            struct.pack(">Q", int(self.accused_height)),
            self.submitter_id,
            struct.pack(">Q", int(self.timestamp)),
            struct.pack(">Q", int(self.fee)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "inclusion_list_violation_evidence",
            "inclusion_list": self.inclusion_list.serialize(),
            "omitted_tx_hash": self.omitted_tx_hash.hex(),
            "accused_proposer_id": self.accused_proposer_id.hex(),
            "accused_height": self.accused_height,
            "submitter_id": self.submitter_id.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(
        cls, data: dict,
    ) -> "InclusionListViolationEvidenceTx":
        tx = cls(
            inclusion_list=InclusionList.deserialize(data["inclusion_list"]),
            omitted_tx_hash=bytes.fromhex(data["omitted_tx_hash"]),
            accused_proposer_id=bytes.fromhex(data["accused_proposer_id"]),
            accused_height=int(data["accused_height"]),
            submitter_id=bytes.fromhex(data["submitter_id"]),
            timestamp=int(data["timestamp"]),
            fee=int(data["fee"]),
            signature=Signature.deserialize(data["signature"]),
        )
        declared = bytes.fromhex(data["tx_hash"])
        if declared != tx.tx_hash:
            raise ValueError(
                f"InclusionListViolationEvidenceTx hash mismatch"
            )
        return tx

    def to_bytes(self, state=None) -> bytes:
        lst_blob = self.inclusion_list.to_bytes()
        sig_blob = self.signature.to_bytes()
        return b"".join([
            struct.pack(">I", len(lst_blob)),
            lst_blob,
            self.omitted_tx_hash,
            self.accused_proposer_id,
            struct.pack(">Q", int(self.accused_height)),
            self.submitter_id,
            struct.pack(">Q", int(self.timestamp)),
            struct.pack(">Q", int(self.fee)),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(
        cls, data: bytes, state=None,
    ) -> "InclusionListViolationEvidenceTx":
        off = 0
        min_len = 4 + 32 + 32 + 8 + 32 + 8 + 8 + 4 + 32
        if len(data) < min_len:
            raise ValueError(
                "InclusionListViolationEvidenceTx blob too short"
            )
        lst_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + lst_len > len(data):
            raise ValueError(
                "InclusionListViolationEvidenceTx truncated at inclusion_list"
            )
        lst = InclusionList.from_bytes(bytes(data[off:off + lst_len]))
        off += lst_len
        omitted_tx_hash = bytes(data[off:off + 32]); off += 32
        accused_id = bytes(data[off:off + 32]); off += 32
        accused_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        submitter_id = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">Q", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError(
                "InclusionListViolationEvidenceTx truncated at sig/hash"
            )
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError(
                "InclusionListViolationEvidenceTx has trailing bytes"
            )
        tx = cls(
            inclusion_list=lst,
            omitted_tx_hash=omitted_tx_hash,
            accused_proposer_id=accused_id,
            accused_height=accused_height,
            submitter_id=submitter_id,
            timestamp=timestamp,
            fee=fee,
            signature=sig,
        )
        if tx.tx_hash != declared:
            raise ValueError(
                f"InclusionListViolationEvidenceTx hash mismatch: "
                f"declared {declared.hex()[:16]}, computed "
                f"{tx.tx_hash.hex()[:16]}"
            )
        return tx


def verify_inclusion_list_violation_evidence_tx(
    tx: InclusionListViolationEvidenceTx,
    submitter_public_key: bytes,
) -> tuple[bool, str]:
    """Stateless verification of an InclusionListViolationEvidenceTx.

    Checks:
      * omitted_tx_hash is actually named in inclusion_list.entries
      * fee >= MIN_FEE
      * submitter signature verifies under submitter_public_key

    Does NOT verify the quorum attestation (that's chain-state-dependent
    — the blockchain admission path does it) and does NOT verify the
    accused proposer actually missed the tx (same reason).
    """
    entry_hashes = {e.tx_hash for e in tx.inclusion_list.entries}
    if tx.omitted_tx_hash not in entry_hashes:
        return False, "omitted_tx_hash not in inclusion_list entries"
    if tx.fee < MIN_FEE:
        return False, f"fee below MIN_FEE ({MIN_FEE})"
    if len(submitter_public_key) != 32:
        return False, "submitter public key must be 32 bytes"
    msg_hash = _h(tx._signable_data())
    if not verify_signature(msg_hash, tx.signature, submitter_public_key):
        return False, "invalid submitter signature"
    return True, "Valid"


# ─────────────────────────────────────────────────────────────────────
# Slashing helpers
# ─────────────────────────────────────────────────────────────────────

def compute_violation_slash_amount(stake: int) -> int:
    """INCLUSION_VIOLATION_SLASH_BPS of stake, integer-math.

    Matches the shape of censorship_evidence.compute_slash_amount so
    call sites can swap in either without surprise.
    """
    if stake <= 0:
        return 0
    return (stake * INCLUSION_VIOLATION_SLASH_BPS) // 10_000


@dataclass
class InclusionViolationResult:
    """Three terminal states mirror BogusRejectionResult:

      * accepted=True, slashed=True   — violation confirmed; offender's
        stake burned by `slash_amount`; (list_hash, tx_hash, proposer_id)
        recorded in processor.processed_violations.
      * accepted=False, slashed=False — evidence already processed OR
        violation refuted (tx actually landed, list expired earlier
        and was already reconciled).  Caller MUST NOT charge fee.
    """
    accepted: bool
    slashed: bool
    offender_id: bytes = b""
    slash_amount: int = 0
    reason: str = ""


def process_inclusion_list_violation(
    etx: InclusionListViolationEvidenceTx,
    blockchain,
    current_height: int | None = None,
) -> InclusionViolationResult:
    """Apply a violation evidence: slash the accused if still eligible.

    Called at block-apply time by the Blockchain wiring.  Mirrors
    `BogusRejectionProcessor.process` in spirit — one-phase, immediate
    decision from chain state.

    Decision rules:
      * If (list_hash, omitted_tx_hash, accused_proposer_id) is already
        in `processed_violations` → reject (double-slash defence).
      * Slash the offender's stake; burn the tokens.
      * Record the (list_hash, tx_hash, proposer_id) in
        processed_violations.

    Severity policy:
      * Pre-Tier-24 (``HONESTY_CURVE_RATE_HEIGHT``): flat
        ``INCLUSION_VIOLATION_SLASH_BPS`` rate via
        ``compute_violation_slash_amount`` — historical replay
        byte-identical to pre-fork behavior.
      * Post-Tier-24: route through ``slashing_severity`` with
        ``OffenseKind.INCLUSION_LIST_VIOLATION`` and
        ``Unambiguity.UNAMBIGUOUS``.  An inclusion-list violation
        is unambiguous because the proposer demonstrably failed to
        include a tx the list mandated — there's no honest restart-
        crash explanation.  Track-record relief still applies for a
        first offense from a long-tenured validator (UNAMBIGUOUS_
        FIRST_PCT band, default 50%).  Repeat violations escalate
        to 100%.

    The dedupe key includes list_hash because two overlapping lists
    can mandate the same tx; omitting that tx while both are active
    is two violations, not one.  Keyed at 3-tuple (not 4-tuple with
    accused_height) because the height range is implied by the list's
    window — two evidences for the same (list, tx, proposer) at
    different heights are true duplicates.

    ``current_height`` is required for the post-Tier-24 path; callers
    that omit it (legacy / older tests) fall back to the flat-BPS
    semantics, which is byte-identical to the pre-fork behavior so
    no historical replay diverges.
    """
    proc = blockchain.inclusion_list_processor
    key = (
        etx.inclusion_list.list_hash,
        etx.omitted_tx_hash,
        etx.accused_proposer_id,
    )
    if key in proc.processed_violations:
        return InclusionViolationResult(
            accepted=False, slashed=False,
            reason="violation already processed (double-slash defence)",
        )
    current_stake = blockchain.supply.staked.get(
        etx.accused_proposer_id, 0,
    )
    # Tier 24: route through honesty curve when active.  Below
    # activation: legacy flat-BPS path (byte-for-byte preserved).
    use_curve = False
    if current_height is not None:
        from messagechain.config import HONESTY_CURVE_RATE_HEIGHT
        use_curve = current_height >= HONESTY_CURVE_RATE_HEIGHT
    if use_curve:
        from messagechain.consensus.honesty_curve import (
            OffenseKind,
            Unambiguity,
            slashing_severity,
        )
        # Tier 30 honest-operator insurance: a single missed include
        # is plausibly honest mempool churn, NOT proof of intent.
        # Reclassify first offenses as AMBIGUOUS — only repeat
        # patterns (slash_offense_counts ≥ 1) escalate to UNAMBIGUOUS.
        # Pre-Tier-30 callers fall through to the legacy UNAMBIGUOUS-
        # first-offense classification.
        from messagechain.config import (
            HONESTY_CURVE_INSURANCE_HEIGHT as _T30_H,
        )
        if current_height >= _T30_H:
            prior = blockchain.slash_offense_counts.get(
                etx.accused_proposer_id, 0,
            ) if hasattr(blockchain, "slash_offense_counts") else 0
            if prior >= 1:
                _unamb = Unambiguity.UNAMBIGUOUS
            else:
                _unamb = Unambiguity.AMBIGUOUS
        else:
            _unamb = Unambiguity.UNAMBIGUOUS
        sev_pct = slashing_severity(
            etx.accused_proposer_id,
            OffenseKind.INCLUSION_LIST_VIOLATION,
            _unamb,
            blockchain,
        )
        slash_amount = (current_stake * sev_pct) // 100
    else:
        slash_amount = compute_violation_slash_amount(current_stake)
    if slash_amount > 0:
        blockchain.supply.staked[etx.accused_proposer_id] = (
            current_stake - slash_amount
        )
        blockchain.supply.total_supply -= slash_amount
        blockchain.supply.total_burned += slash_amount
        # Tier 24: increment offense counter so the curve sees this
        # violation in subsequent severity calls (escalation +
        # rate-factor erosion both read it).  Pre-curve path skips
        # the bump to keep historical replay byte-identical.  Route
        # through the `_bump_slash_offense_count` chokepoint when
        # available so the chaindb mirror picks up the bump and a
        # cold-restarted node grades the next violation identically
        # to uprestarted peers (without persistence the dict resets
        # to empty on restart, and `slashing_severity` returns a
        # different `slash_pct` → state_root diverges → chain split).
        # Fall back to direct dict mutation on stripped-down test
        # stubs that lack the chokepoint method.
        if use_curve and hasattr(blockchain, "slash_offense_counts"):
            if hasattr(blockchain, "_bump_slash_offense_count"):
                blockchain._bump_slash_offense_count(
                    etx.accused_proposer_id,
                )
            else:
                cur = blockchain.slash_offense_counts.get(
                    etx.accused_proposer_id, 0,
                )
                blockchain.slash_offense_counts[etx.accused_proposer_id] = (
                    cur + 1
                )
    proc.processed_violations.add(key)
    return InclusionViolationResult(
        accepted=True, slashed=True,
        offender_id=etx.accused_proposer_id,
        slash_amount=slash_amount,
        reason="inclusion-list violation: slashed",
    )
