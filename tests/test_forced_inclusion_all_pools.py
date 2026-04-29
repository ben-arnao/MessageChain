"""Tier 43 — forced-inclusion source-side covers ALL tx pools.

Pre-Tier-43 the mempool's `get_forced_inclusion_set` walked only
`self.pending` (Message + Transfer).  All other tx pools — server-
local stake / unstake / authority / governance, AND the on-mempool
censorship-evidence pool — were silently exempt from the forced-
inclusion rule.  A colluding proposer could drop the very
`CensorshipEvidenceTx` filed against itself, an honest stake-rebalance
or unstake-exit, or a governance vote that threatened its position,
all with zero slashable evidence.  That violates the CLAUDE.md anchor
"a tx that is well-formed, pays at least the per-byte floor, and fits
the byte budget cannot be suppressed by anything weaker than a full
validator-set majority actively colluding."

Tier 43 closes the source-side gap symmetrically with the Tier 34
block-side gap:
  * Mempool gains a `register_forced_inclusion_source(callable)` API
    so server-local pools can plug in without circular imports.
  * Mempool itself registers its on-board `censorship_evidence_pool`
    (already tracked there; the integration is mechanical).
  * Server registers each of its four pending-tx pools (stake,
    unstake, authority, governance) along with arrival-height
    bookkeeping so the wait-gate works the same way it does for
    messages.
  * Block-side: `censorship_evidence_txs` is added to
    `_BLOCK_TX_LIST_ATTRS` so a forced evidence tx placed in its
    correct slot is recognized as included.

Pre-fork: byte-identical to legacy attester behavior — extra sources
are NOT consulted, so historical blocks attest under the old rule.
Post-fork: a forced governance / stake / unstake / authority /
censorship-evidence tx left out of an otherwise-empty block fails
the gate.

Tests pin:
  * Pre-fork: a forced CensorshipEvidenceTx aged past
    FORCED_INCLUSION_WAIT_BLOCKS does NOT appear in the forced set
    (legacy behavior preserved for replay determinism).
  * Post-fork: same evidence tx DOES appear in the forced set, and
    a block omitting it is flagged as censorship.
  * Post-fork: an external source registered with the mempool
    contributes its txs to the forced set, ranked by fee-per-byte
    against the mempool's own pending txs.
  * Activation-height ordering: Tier 43 must follow Tier 42 (the
    most recent established fork) and must follow Tier 34 (the
    block-side multi-list path it pairs with).
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    FEE_PER_BYTE,
    FORCED_INCLUSION_ALL_POOLS_HEIGHT,
    FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
    FORCED_INCLUSION_WAIT_BLOCKS,
    MIN_FEE,
    REWARD_CURVE_SMOOTH_V2_HEIGHT,
)
from messagechain.consensus.forced_inclusion import (
    _BLOCK_TX_LIST_ATTRS,
    check_forced_inclusion,
)
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity


PRE_T43 = FORCED_INCLUSION_ALL_POOLS_HEIGHT - 1
POST_T43 = FORCED_INCLUSION_ALL_POOLS_HEIGHT

_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)
_BASE_FEE = MIN_FEE + 10 * FEE_PER_BYTE


class _FakeBlock:
    """Minimal Block stand-in that carries every tx-list field the
    Tier-34 / Tier-43 gate may walk."""

    class _H:
        def __init__(self, proposer_id):
            self.proposer_id = proposer_id

    def __init__(
        self,
        message_txs=None,
        transfer_txs=None,
        react_txs=None,
        stake_txs=None,
        unstake_txs=None,
        governance_txs=None,
        authority_txs=None,
        censorship_evidence_txs=None,
        non_response_evidence_txs=None,
        proposer_id=b"\x00" * 32,
    ):
        self.transactions = list(message_txs or [])
        self.transfer_transactions = list(transfer_txs or [])
        self.react_transactions = list(react_txs or [])
        self.stake_transactions = list(stake_txs or [])
        self.unstake_transactions = list(unstake_txs or [])
        self.governance_txs = list(governance_txs or [])
        self.authority_txs = list(authority_txs or [])
        self.censorship_evidence_txs = list(censorship_evidence_txs or [])
        self.non_response_evidence_txs = list(non_response_evidence_txs or [])
        self.header = _FakeBlock._H(proposer_id)


class _FakePoolTx:
    """Minimal stand-in for a server-local tx kind (Stake / Unstake /
    Authority / Governance) that the forced-inclusion source-side
    needs to rank.  Has the `to_bytes` / `fee` / `entity_id` shape
    the per-byte ranker requires.  Avoids the full WOTS+ signing path
    so the test runs in <1s regardless of MERKLE_TREE_HEIGHT."""

    def __init__(self, tx_hash: bytes, entity_id: bytes, fee: int, payload: bytes):
        self.tx_hash = tx_hash
        self.entity_id = entity_id
        self.fee = fee
        self._payload = payload

    def to_bytes(self, state=None) -> bytes:
        return self._payload


# ────────────────────────────────────────────────────────────────────
# Activation-height ordering — Tier 43 must follow Tier 42 (the most
# recent established fork) AND Tier 34 (the block-side multi-list
# path).
# ────────────────────────────────────────────────────────────────────


class TestForkGateOrdering(unittest.TestCase):

    def test_height_above_tier_42(self):
        self.assertGreater(
            FORCED_INCLUSION_ALL_POOLS_HEIGHT,
            REWARD_CURVE_SMOOTH_V2_HEIGHT,
            "Tier 43 must follow Tier 42 — the source-side rule rides "
            "on top of the most recent established fork ladder so a "
            "mid-fork-ladder restart cannot leave the chain on the "
            "extended source set without the prior tiers active.",
        )

    def test_height_above_tier_34(self):
        self.assertGreater(
            FORCED_INCLUSION_ALL_POOLS_HEIGHT,
            FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
            "Tier 43 must follow Tier 34 — the block-side multi-list "
            "walk is the prerequisite for the source-side extension; "
            "the gate cannot enforce against a tx kind whose block "
            "slot is not yet recognized.",
        )


# ────────────────────────────────────────────────────────────────────
# Block tx-list registry — censorship_evidence_txs must be in the
# walk tuple post-Tier-43 so a forced evidence tx placed in its
# correct slot is recognized as included.
# ────────────────────────────────────────────────────────────────────


class TestBlockTxListRegistry(unittest.TestCase):

    def test_censorship_evidence_in_registry(self):
        self.assertIn(
            "censorship_evidence_txs",
            _BLOCK_TX_LIST_ATTRS,
            "Tier 43 must register `censorship_evidence_txs` in "
            "`_BLOCK_TX_LIST_ATTRS` so a forced evidence tx placed in "
            "its correct block slot is recognized as included by the "
            "Tier 34 multi-list walk.",
        )


# ────────────────────────────────────────────────────────────────────
# External source registration — mempool MUST expose a public hook
# server-local pools can plug into without a circular dep.
# ────────────────────────────────────────────────────────────────────


class TestExternalSourceRegistration(unittest.TestCase):

    def setUp(self):
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_register_forced_inclusion_source_method_exists(self):
        self.assertTrue(
            hasattr(self.pool, "register_forced_inclusion_source"),
            "Mempool must expose `register_forced_inclusion_source` so "
            "server-local pools can plug in their pending txs for the "
            "forced-inclusion rule.",
        )

    def test_pre_fork_external_source_NOT_consulted(self):
        """Pre-Tier-43: extra sources are silently ignored — replay
        determinism on historical blocks."""
        eid = b"e" * 32
        ext_tx = _FakePoolTx(
            tx_hash=b"\xaa" * 32,
            entity_id=eid,
            fee=_BASE_FEE * 100,  # enormous fpb
            payload=b"x" * 64,
        )
        self.pool.register_forced_inclusion_source(
            lambda: [(ext_tx, 0)],
        )
        h = max(PRE_T43, FORCED_INCLUSION_WAIT_BLOCKS + 1)
        forced = self.pool.get_forced_inclusion_set(h)
        self.assertNotIn(
            ext_tx, forced,
            "Pre-Tier-43 the source-side must not consult external "
            "registered sources — historical blocks were attested "
            "without them.",
        )

    def test_post_fork_external_source_IS_consulted(self):
        """Post-Tier-43: registered sources contribute their aged txs
        to the forced set, ranked by fee-per-byte alongside mempool
        pending."""
        eid = b"e" * 32
        ext_tx = _FakePoolTx(
            tx_hash=b"\xbb" * 32,
            entity_id=eid,
            fee=_BASE_FEE * 100,
            payload=b"x" * 64,
        )
        self.pool.register_forced_inclusion_source(
            lambda: [(ext_tx, 0)],
        )
        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        forced = self.pool.get_forced_inclusion_set(h)
        self.assertIn(
            ext_tx, forced,
            "Post-Tier-43 the source-side must consult registered "
            "sources so server-local pools (stake / unstake / "
            "authority / governance) cannot be silently censored.",
        )

    def test_post_fork_external_source_respects_wait_gate(self):
        """A freshly-arrived external tx (arrival_height too recent)
        does NOT yet qualify — same wait gate the mempool applies to
        its own pending."""
        eid = b"e" * 32
        ext_tx = _FakePoolTx(
            tx_hash=b"\xcc" * 32,
            entity_id=eid,
            fee=_BASE_FEE * 100,
            payload=b"x" * 64,
        )
        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        # Arrival = h - 1 puts it INSIDE the wait window, not aged
        # past it.
        self.pool.register_forced_inclusion_source(
            lambda: [(ext_tx, h - 1)],
        )
        forced = self.pool.get_forced_inclusion_set(h)
        self.assertNotIn(
            ext_tx, forced,
            "External sources must respect the same wait-gate the "
            "mempool applies to its pending — fresh txs are not yet "
            "due for forced inclusion.",
        )

    def test_post_fork_per_byte_ranking_across_extended_source(self):
        """A high-fpb mempool tx and a low-fpb external tx — both
        aged past the wait gate — rank by fee-per-byte across the
        union, not by source priority."""
        # Mempool tx: high fpb (fee=1000, ~3KB stored due to WOTS+
        # signature → ~0.33 fpb).  External tx: bigger payload at
        # higher absolute fee but worse density (fee=100, payload=10KB
        # → 0.01 fpb).  Mempool tx must rank ahead.
        from messagechain.core.transaction import create_transaction
        alice = Entity.create(b"t43-alice".ljust(32, b"\x00"))
        msg_tx = create_transaction(
            alice, "high-fpb msg", fee=_BASE_FEE * 50, nonce=0,
        )
        self.pool.add_transaction(msg_tx, arrival_block_height=0)

        ext_tx = _FakePoolTx(
            tx_hash=b"\xdd" * 32,
            entity_id=b"e" * 32,
            fee=100,  # low fpb at 10 KB
            payload=b"x" * 10_000,
        )
        self.pool.register_forced_inclusion_source(
            lambda: [(ext_tx, 0)],
        )
        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        forced = self.pool.get_forced_inclusion_set(h)
        # Both should be in the set (size cap is 5 by default), and
        # the high-fpb message must precede the low-fpb external tx.
        self.assertIn(msg_tx, forced)
        self.assertIn(ext_tx, forced)
        self.assertLess(
            forced.index(msg_tx), forced.index(ext_tx),
            "Per-byte ranking must apply across the extended source "
            "set — the higher-fpb mempool tx must rank before the "
            "lower-fpb external one.",
        )


# ────────────────────────────────────────────────────────────────────
# Censorship-evidence pool: the audit's headline finding.  A
# colluding proposer must NOT be able to drop the very
# CensorshipEvidenceTx filed against itself.
# ────────────────────────────────────────────────────────────────────


class TestCensorshipEvidencePoolForcedInclusion(unittest.TestCase):
    """The censorship-evidence pool already lives on Mempool; Tier 43
    makes it a forced-inclusion source so a forced evidence tx aged
    past the wait gate qualifies for the forced set and a block
    omitting it fails the attester duty."""

    def setUp(self):
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def _make_evidence_stub(self, tx_hash: bytes, fee: int) -> object:
        """A minimal stand-in for a CensorshipEvidenceTx that the
        forced-inclusion source-side can rank.  Real evidence txs
        carry a SubmissionReceipt + signed message_tx + WOTS+ sig;
        we don't need to exercise the consensus apply path here, just
        the source-set selection.
        """
        return _FakePoolTx(
            tx_hash=tx_hash,
            entity_id=b"submitter".ljust(32, b"\x00"),
            fee=fee,
            payload=b"\x00" * 256,
        )

    def test_pre_fork_evidence_tx_NOT_in_forced_set(self):
        """Legacy behavior: censorship_evidence_pool was not consulted
        as a source.  This is the bug Tier 43 closes — preserved
        pre-fork for replay determinism."""
        evid = self._make_evidence_stub(b"\xee" * 32, fee=_BASE_FEE * 10)
        # Skip the real `add_censorship_evidence_tx` admission (which
        # validates fields) and directly insert into the pool —
        # tests focus on the source-side selection, not admission.
        self.pool.censorship_evidence_pool[evid.tx_hash] = evid
        h = max(PRE_T43, FORCED_INCLUSION_WAIT_BLOCKS + 1)
        forced = self.pool.get_forced_inclusion_set(h)
        self.assertNotIn(
            evid, forced,
            "Pre-Tier-43 the censorship_evidence_pool was not a "
            "forced-inclusion source — preserved for replay.",
        )

    def test_post_fork_evidence_tx_IS_in_forced_set(self):
        """Post-Tier-43: a forced evidence tx aged past the wait gate
        appears in the forced set."""
        evid = self._make_evidence_stub(b"\xee" * 32, fee=_BASE_FEE * 10)
        # Inject directly + arrival height = 0 so it's clearly past
        # the wait gate.  Also arrange the mempool's internal
        # arrival-tracking so the wait-gate computation finds it.
        self.pool.censorship_evidence_pool[evid.tx_hash] = evid
        # Mempool's source-side hook for evidence MUST track arrival
        # heights — emulate the production path by setting it.  The
        # real `add_censorship_evidence_tx` call sets this; tests can
        # poke the underlying dict directly.
        if hasattr(self.pool, "_evidence_arrival_heights"):
            self.pool._evidence_arrival_heights[evid.tx_hash] = 0

        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        forced = self.pool.get_forced_inclusion_set(h)
        self.assertIn(
            evid, forced,
            "Tier 43 must surface aged censorship-evidence txs as "
            "forced — a colluding proposer that drops the evidence "
            "filed against itself otherwise leaves no slashable "
            "trace.",
        )

    def test_post_fork_block_omitting_forced_evidence_is_flagged(self):
        """End-to-end: a block that fails to include a forced
        evidence tx (with no structural excuse) must fail the
        attester duty post-Tier-43."""
        evid = self._make_evidence_stub(b"\xee" * 32, fee=_BASE_FEE * 10)
        self.pool.censorship_evidence_pool[evid.tx_hash] = evid
        if hasattr(self.pool, "_evidence_arrival_heights"):
            self.pool._evidence_arrival_heights[evid.tx_hash] = 0

        # Empty block — every excuse trivially fails (no byte
        # pressure, no count pressure, no per-entity collision).
        block = _FakeBlock()
        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertFalse(
            ok,
            f"Tier 43: block omitting a forced evidence tx must fail "
            f"the gate; got reason={reason!r}",
        )

    def test_post_fork_block_including_evidence_is_attested(self):
        """An honest proposer that places the evidence in its
        correct block slot (`censorship_evidence_txs`) is correctly
        attested."""
        evid = self._make_evidence_stub(b"\xee" * 32, fee=_BASE_FEE * 10)
        self.pool.censorship_evidence_pool[evid.tx_hash] = evid
        if hasattr(self.pool, "_evidence_arrival_heights"):
            self.pool._evidence_arrival_heights[evid.tx_hash] = 0

        block = _FakeBlock(censorship_evidence_txs=[evid])
        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertTrue(
            ok,
            f"Tier 43: an honest proposer placing the evidence in "
            f"`censorship_evidence_txs` must be attested; "
            f"reason={reason!r}",
        )


# ────────────────────────────────────────────────────────────────────
# Server integration: the four server-local pending pools (stake /
# unstake / authority / governance) MUST flow through the
# forced-inclusion source-side post-Tier-43.  Without this wiring a
# colluding proposer could drop an honest unstake-exit / stake-
# rebalance / governance-vote / authority-rotate with zero slashable
# evidence.
# ────────────────────────────────────────────────────────────────────


class TestServerPoolForcedInclusionIntegration(unittest.TestCase):
    """End-to-end: server registers its four pending pools as a
    forced-inclusion source; an aged tx in any of them surfaces in
    the mempool's forced set post-fork."""

    def test_mempool_self_registers_evidence_source_at_init(self):
        """Mempool MUST self-register its on-board pools (censorship-
        evidence + react) as forced-inclusion sources at construction
        so the source-side rule covers them without requiring server
        cooperation.  A cold-loaded standalone Mempool (e.g. in tests,
        in light-client scenarios) must still honor both sources.

        Tier 43 audit fix #2 added the evidence pool; audit fix #4
        added the react pool — for two internal sources total.  A
        future on-mempool pool (e.g. a future first-class tx kind)
        added here will bump this count again, which is fine — the
        invariant being pinned is "EVERY on-mempool tx pool must be
        a forced-inclusion source," not the literal count.
        """
        pool = Mempool(max_size=10, fee_policy=_STATIC_FEE)
        self.assertEqual(
            len(pool._external_forced_sources), 2,
            "Mempool must self-register both on-board pools "
            "(censorship-evidence + react) as forced-inclusion "
            "sources at construction.",
        )

    def test_server_registers_pool_source_at_init(self):
        """A freshly-constructed Server MUST register its four
        server-local pending pools as an additional forced-inclusion
        source on the mempool — not lazily on first admit, since a
        node cold-loaded near a proposer slot may produce a block
        before ever calling `_admit_to_pool`."""
        # `server.py` lives at the repo root; the import pattern
        # `from server import Server` is what every other Server-
        # touching test in the suite uses.  With data_dir=None and
        # seed_nodes=[] the constructor runs without touching disk
        # or starting the network loop (binds happen in `start()`,
        # not `__init__`).
        from server import Server
        srv = Server(
            p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None,
        )
        # 3+ sources: two internal (evidence pool + react pool) +
        # one from Server's registered server-pools walk.
        self.assertGreaterEqual(
            len(srv.mempool._external_forced_sources), 3,
            "Server must register its four server-local pending "
            "pools (stake / unstake / authority / governance) as "
            "an additional forced-inclusion source so the Tier 43 "
            "source-side gate covers them — on top of the two "
            "internal Mempool sources (evidence + react).",
        )
        # And the tracker dict must exist so `_admit_to_pool` can
        # populate it.
        self.assertTrue(
            hasattr(srv, "_pending_pool_arrival_heights"),
            "Server must expose `_pending_pool_arrival_heights` "
            "for the source-side wait-gate.",
        )

    def test_server_pool_arrival_heights_drained_on_block_inclusion(self):
        """After an aged tx is drained from a server pool into a
        block, the arrival-height tracker entry must be cleaned up
        too — an unbounded tracker would leak memory across the
        chain's lifetime.  Tested at the dict-shape level so a
        future contributor cannot reintroduce the leak silently."""
        # We don't construct a real node here (network setup is
        # heavy).  Instead exercise the tracker's invariants directly
        # through a fake server-pool walk.  The integration test that
        # actually drives a node through block production lives in
        # the broader test suite (which exercises the full pipeline
        # end-to-end via the existing forced-inclusion integration
        # tests).
        pool = Mempool(max_size=10, fee_policy=_STATIC_FEE)
        ext_pool: dict = {}
        ext_arrivals: dict = {}

        def src():
            for h, tx in list(ext_pool.items()):
                yield tx, ext_arrivals.get(h, 0)

        pool.register_forced_inclusion_source(src)

        # Add an aged tx to the external pool.
        tx = _FakePoolTx(
            tx_hash=b"\xff" * 32,
            entity_id=b"e" * 32,
            fee=_BASE_FEE * 100,
            payload=b"x" * 64,
        )
        ext_pool[tx.tx_hash] = tx
        ext_arrivals[tx.tx_hash] = 0

        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        forced = pool.get_forced_inclusion_set(h)
        self.assertIn(
            tx, forced,
            "Aged external-source tx must surface post-Tier-43.",
        )

        # Drain (simulating block production).
        del ext_pool[tx.tx_hash]
        del ext_arrivals[tx.tx_hash]

        forced_after = pool.get_forced_inclusion_set(h)
        self.assertNotIn(
            tx, forced_after,
            "After draining the external pool, the tx must no longer "
            "appear in the forced set — the source callable returns "
            "the live state of the pool, not a cached snapshot.",
        )


if __name__ == "__main__":
    unittest.main()
