"""Tier 43 — forced-inclusion source-side covers `mempool.react_pool`.

Tier 43 (1.42.0) registered stake / unstake / authority / governance
plus the censorship-evidence pool as forced-inclusion sources, but
React votes — which live in the separate `mempool.react_pool` (NOT
`pending`) — were left out.  The block-side `_BLOCK_TX_LIST_ATTRS`
already covers `react_transactions`, so block validation handles
react slots; only the source-side fan-out was missing.

Result before this fix: a colluding majority could drop arbitrarily-
high-fpb React votes (Tier 17 trust signals) without leaving a
slashable witness — directly enabling the canonical CLAUDE.md threat
example: *"a corporation pressuring validators to suppress negative
reviews of its products."* On MessageChain, "negative reviews" are
React vote-down txs.

This file pins:
  * Pre-fork: react txs are NOT consulted as a forced-inclusion
    source (legacy replay determinism).
  * Post-fork: an aged react tx in `react_pool` surfaces in the
    forced set, and a block omitting it fails the gate.
  * Arrival-height teardown on every removal path
    (`remove_react_transactions`, full-pool fee-density eviction).
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    FEE_PER_BYTE,
    FORCED_INCLUSION_ALL_POOLS_HEIGHT,
    FORCED_INCLUSION_WAIT_BLOCKS,
    MIN_FEE,
)
from messagechain.consensus.forced_inclusion import check_forced_inclusion
from messagechain.core.mempool import Mempool
from messagechain.economics.dynamic_fee import DynamicFeePolicy


PRE_T43 = FORCED_INCLUSION_ALL_POOLS_HEIGHT - 1
POST_T43 = FORCED_INCLUSION_ALL_POOLS_HEIGHT

_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)
_BASE_FEE = MIN_FEE + 10 * FEE_PER_BYTE


class _FakeReactTx:
    """Minimal stand-in for a ReactTransaction.

    `voter_id` is the per-entity-cap key the forced-inclusion gate
    falls back to via `_entity_id_of`.  `to_bytes` / `fee` / `tx_hash`
    are the per-byte ranker's required surface.  No WOTS+ signing
    path — keeps the test sub-second regardless of the conftest's
    Merkle tree height.
    """

    def __init__(
        self,
        tx_hash: bytes,
        voter_id: bytes,
        fee: int,
        payload: bytes = b"\x00" * 256,
    ):
        self.tx_hash = tx_hash
        self.voter_id = voter_id
        self.fee = fee
        self._payload = payload

    def to_bytes(self, state=None) -> bytes:
        return self._payload


class _FakeBlock:
    """Minimal Block stand-in covering every tx-list field the gate
    walks.  Mirrors `_FakeBlock` from `test_forced_inclusion_all_pools`
    — defined locally to avoid a cross-test import."""

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


class TestReactPoolForcedInclusion(unittest.TestCase):
    """Source-side: an aged React tx in `react_pool` must surface in
    the forced set post-Tier-43, and a block omitting it must fail
    the attester duty.  Pre-fork: legacy "react never forced" preserved
    for byte-identical replay."""

    def setUp(self):
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def _stub(self, tx_hash: bytes, fee: int = _BASE_FEE * 10) -> _FakeReactTx:
        return _FakeReactTx(
            tx_hash=tx_hash,
            voter_id=b"voter".ljust(32, b"\x00"),
            fee=fee,
        )

    # ── Pre-fork: byte-identical replay (react NOT a source) ─────────

    def test_pre_fork_react_tx_NOT_in_forced_set(self):
        """Pre-Tier-43 the react_pool was not consulted — preserved
        for replay determinism on historical blocks."""
        rtx = self._stub(b"\xa1" * 32)
        # Inject directly + arrival height = 0 so it's clearly past
        # the wait gate (the source side, not admission, is what we
        # test).
        self.pool.react_pool[rtx.tx_hash] = rtx
        if hasattr(self.pool, "_react_pool_arrival_heights"):
            self.pool._react_pool_arrival_heights[rtx.tx_hash] = 0

        h = max(PRE_T43, FORCED_INCLUSION_WAIT_BLOCKS + 1)
        forced = self.pool.get_forced_inclusion_set(h)
        self.assertNotIn(
            rtx, forced,
            "Pre-Tier-43 the react_pool must NOT be a forced-inclusion "
            "source — historical blocks were attested without it.",
        )

    # ── Post-fork: the headline fix ─────────────────────────────────

    def test_post_fork_react_tx_IS_in_forced_set(self):
        """Post-Tier-43 an aged react tx surfaces in the forced set —
        the central fix this branch lands."""
        rtx = self._stub(b"\xa2" * 32)
        self.pool.react_pool[rtx.tx_hash] = rtx
        # Test relies on the implementation pre-populating the arrival
        # tracker on the admission path.  Set it directly so this test
        # focuses on the source-side selection.
        self.assertTrue(
            hasattr(self.pool, "_react_pool_arrival_heights"),
            "Mempool must expose `_react_pool_arrival_heights` so the "
            "react-pool source-side can apply the same wait-gate the "
            "messages pool uses.",
        )
        self.pool._react_pool_arrival_heights[rtx.tx_hash] = 0

        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        forced = self.pool.get_forced_inclusion_set(h)
        self.assertIn(
            rtx, forced,
            "Tier 43 must surface aged react txs as forced — the "
            "canonical CLAUDE.md threat: a colluding majority "
            "suppressing negative-review votes (React DOWN txs).",
        )

    def test_post_fork_block_omitting_forced_react_is_flagged(self):
        """End-to-end: a block omitting a forced react tx (no
        structural excuse) must fail the attester duty post-Tier-43."""
        rtx = self._stub(b"\xa3" * 32)
        self.pool.react_pool[rtx.tx_hash] = rtx
        self.pool._react_pool_arrival_heights[rtx.tx_hash] = 0

        # Empty block — every excuse trivially fails (no byte
        # pressure, no count pressure, no per-entity collision).
        block = _FakeBlock()
        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertFalse(
            ok,
            f"Tier 43: block omitting a forced react tx must fail the "
            f"gate; got reason={reason!r}",
        )

    def test_post_fork_block_including_react_is_attested(self):
        """An honest proposer that places the react in its correct
        block slot (`react_transactions`) is correctly attested."""
        rtx = self._stub(b"\xa4" * 32)
        self.pool.react_pool[rtx.tx_hash] = rtx
        self.pool._react_pool_arrival_heights[rtx.tx_hash] = 0

        block = _FakeBlock(react_txs=[rtx])
        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertTrue(
            ok,
            f"Tier 43: an honest proposer placing the react in "
            f"`react_transactions` must be attested; reason={reason!r}",
        )

    # ── Wait-gate: a fresh react tx is not yet forced ───────────────

    def test_post_fork_react_tx_respects_wait_gate(self):
        """A freshly-arrived react tx (arrival inside the wait window)
        does NOT yet qualify — same wait gate the mempool applies to
        its own pending pool."""
        rtx = self._stub(b"\xa5" * 32)
        self.pool.react_pool[rtx.tx_hash] = rtx

        h = POST_T43 + FORCED_INCLUSION_WAIT_BLOCKS + 5
        # Arrival = h - 1 → still inside the wait window, not aged
        # past it.
        self.pool._react_pool_arrival_heights[rtx.tx_hash] = h - 1

        forced = self.pool.get_forced_inclusion_set(h)
        self.assertNotIn(
            rtx, forced,
            "React-pool source-side must respect the same wait-gate "
            "the messages pool applies — fresh txs are not yet due "
            "for forced inclusion.",
        )


class TestReactPoolArrivalHeightsTeardown(unittest.TestCase):
    """The arrival-height tracker MUST be torn down on every removal
    path so it cannot leak across the chain's lifetime.  Leak audit
    flags this as a real pre-activation hygiene point — an unbounded
    tracker would also break consensus determinism if a stale entry
    misclassifies a re-arrived tx as 'aged from genesis'."""

    def setUp(self):
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def _stub(self, tx_hash: bytes, fee: int = _BASE_FEE * 10) -> _FakeReactTx:
        return _FakeReactTx(
            tx_hash=tx_hash,
            voter_id=b"voter".ljust(32, b"\x00"),
            fee=fee,
        )

    def test_admission_populates_arrival_heights(self):
        """`add_react_transaction` must populate the arrival-tracker
        so the source-side wait-gate can find it."""
        rtx = self._stub(b"\xb1" * 32)
        ok = self.pool.add_react_transaction(rtx)
        self.assertTrue(ok, "react admission should succeed for a fresh tx")
        self.assertIn(
            rtx.tx_hash, self.pool._react_pool_arrival_heights,
            "add_react_transaction must populate `_react_pool_arrival_heights`",
        )

    def test_remove_react_transactions_drops_arrival_heights(self):
        """`remove_react_transactions` (called on block-include drain)
        must pop the arrival-tracker entry too — leaving stale entries
        leaks memory and risks misclassifying a re-arrived tx as aged."""
        rtx = self._stub(b"\xb2" * 32)
        self.pool.add_react_transaction(rtx)
        self.assertIn(rtx.tx_hash, self.pool._react_pool_arrival_heights)

        self.pool.remove_react_transactions([rtx.tx_hash])
        self.assertNotIn(
            rtx.tx_hash, self.pool._react_pool_arrival_heights,
            "remove_react_transactions must drop arrival-tracker entry",
        )

    def test_full_pool_eviction_drops_arrival_heights(self):
        """The full-pool fee-density eviction path
        (`add_react_transaction` when `react_pool` is at capacity)
        must also drop the evicted tx's arrival-tracker entry."""
        # Tighten the cap so two inserts trigger the eviction path.
        self.pool.react_pool_max_size = 1

        low = _FakeReactTx(
            tx_hash=b"\xb3" * 32,
            voter_id=b"voter".ljust(32, b"\x00"),
            fee=_BASE_FEE * 1,  # low density
        )
        self.assertTrue(self.pool.add_react_transaction(low))
        self.assertIn(low.tx_hash, self.pool._react_pool_arrival_heights)

        high = _FakeReactTx(
            tx_hash=b"\xb4" * 32,
            voter_id=b"voter".ljust(32, b"\x00"),
            fee=_BASE_FEE * 1000,  # high density evicts the low one
        )
        self.assertTrue(self.pool.add_react_transaction(high))

        # The evicted (low) tx's tracker entry must be gone.
        self.assertNotIn(
            low.tx_hash, self.pool._react_pool_arrival_heights,
            "Full-pool eviction must drop the evicted tx's arrival-"
            "tracker entry — otherwise the tracker leaks unboundedly.",
        )
        # And the freshly-admitted high tx's entry must be present.
        self.assertIn(
            high.tx_hash, self.pool._react_pool_arrival_heights,
            "Full-pool eviction insert must populate the new entry.",
        )

    def test_mempool_self_registers_two_internal_sources(self):
        """Mempool must self-register exactly TWO internal forced-
        inclusion sources at construction: the censorship-evidence
        pool (Tier 43 audit fix #2) and the react pool (this fix).
        A cold-loaded standalone Mempool (e.g. light client / test
        harness) must honor both without server cooperation."""
        pool = Mempool(max_size=10, fee_policy=_STATIC_FEE)
        self.assertEqual(
            len(pool._external_forced_sources), 2,
            "Mempool must self-register both the evidence pool AND "
            "the react pool as forced-inclusion sources at "
            "construction.",
        )


if __name__ == "__main__":
    unittest.main()
