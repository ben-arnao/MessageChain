"""Mempool slash / censorship-evidence pools admit by fee-per-byte.

Audit r49 #3.  Pre-fix three mempool-resident pools admitted FIFO and
refused any new entry when full:

* ``slash_pool``       (``add_slash_transaction``)
* ``censorship_evidence_pool`` (``add_censorship_evidence_tx``)
* ``finality_pool``    (``add_finality_vote``)

Selectors returned ``list(pool.values())`` — insertion order, no
density sort.  A flooder paying the floor fee could fill any of these
pools at trivial cost and crowd out higher-density legitimate entries,
silently disarming the slashing-evidence pipeline that the CLAUDE.md
collective-defense anchor depends on.

This is the exact defect the 1.76.1 ship-list fix closed for the
server-side ``_pending_*_txs`` pools but never reached for the
mempool-resident pools.  Audit r49 explicitly scoped sibling closure
here.

Two fee-bearing pools (``slash_pool`` and ``censorship_evidence_pool``)
get full fee-per-byte admit-with-eviction + density-sorted selection
via a shared chokepoint.  The fee-less ``finality_pool`` (FinalityVote
carries no fee — it earns the proposer the inclusion reward instead)
gets oldest-by-arrival eviction so a saturated validator-set scenario
still has liveness, but the flooder-paying-floor attack does not apply
there (an attacker has no way to forge a signed vote without a real
validator key).
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from messagechain.config import MIN_FEE
from messagechain.core.mempool import Mempool


@dataclass
class _StubSlashTx:
    """Duck-typed slash-tx stub for pool-admission tests.

    The mempool admit path consults ``tx_hash`` (dedupe key), ``fee``
    (floor check + density numerator), and ``to_bytes()`` (density
    denominator).  Nothing else is touched on the admission path, so
    a real SlashTransaction (with WOTS+ keygen cost) is unnecessary.
    """
    tx_hash: bytes
    fee: int
    payload_len: int = 100

    def to_bytes(self) -> bytes:
        return b"\x00" * self.payload_len


@dataclass
class _StubCensorshipTx:
    tx_hash: bytes
    fee: int
    submitter_id: bytes = b"\x42" * 32
    payload_len: int = 100

    def to_bytes(self, state=None, chain_height: int | None = None) -> bytes:
        return b"\x00" * self.payload_len


@dataclass
class _StubFinalityVote:
    signer_entity_id: bytes
    target_block_hash: bytes
    target_block_number: int
    signed_at_height: int
    _consensus_hash: bytes

    def consensus_hash(self) -> bytes:
        return self._consensus_hash


def _h(i: int) -> bytes:
    return i.to_bytes(32, "big")


class TestSlashPoolDensityAdmit(unittest.TestCase):

    def test_high_density_evicts_low_density_when_full(self):
        pool = Mempool(max_size=10, tx_ttl=60)
        pool.slash_pool_max_size = 3

        # Fill with three low-density entries at the floor.
        low_a = _StubSlashTx(tx_hash=_h(1), fee=MIN_FEE, payload_len=100)
        low_b = _StubSlashTx(tx_hash=_h(2), fee=MIN_FEE, payload_len=100)
        low_c = _StubSlashTx(tx_hash=_h(3), fee=MIN_FEE, payload_len=100)
        self.assertTrue(pool.add_slash_transaction(low_a))
        self.assertTrue(pool.add_slash_transaction(low_b))
        self.assertTrue(pool.add_slash_transaction(low_c))

        # Incoming high-density entry (10x fee at same byte cost).
        high = _StubSlashTx(tx_hash=_h(99), fee=MIN_FEE * 10, payload_len=100)

        # Pre-fix: pool full ⇒ refused.  Post-fix: density-evict the
        # lowest-density existing entry and admit.
        self.assertTrue(pool.add_slash_transaction(high))

        # One of the low-density entries was evicted; the high entry
        # is present.
        txs = pool.get_slash_transactions()
        hashes = {t.tx_hash for t in txs}
        self.assertIn(high.tx_hash, hashes)
        self.assertEqual(len(txs), 3)
        # And the high-density entry comes first in canonical
        # selection order.
        self.assertEqual(txs[0].tx_hash, high.tx_hash)

    def test_lower_density_refused_when_full(self):
        pool = Mempool(max_size=10, tx_ttl=60)
        pool.slash_pool_max_size = 2

        existing = _StubSlashTx(tx_hash=_h(1), fee=MIN_FEE * 10, payload_len=100)
        also = _StubSlashTx(tx_hash=_h(2), fee=MIN_FEE * 10, payload_len=100)
        self.assertTrue(pool.add_slash_transaction(existing))
        self.assertTrue(pool.add_slash_transaction(also))

        # Floor-fee flooder against a high-density pool — must be
        # refused.  Pre-fix the same call was also refused (FIFO);
        # post-fix the density check actively rejects strictly-lower
        # density rather than relying on FIFO.
        floor = _StubSlashTx(tx_hash=_h(99), fee=MIN_FEE, payload_len=100)
        self.assertFalse(pool.add_slash_transaction(floor))

        self.assertEqual(len(pool.get_slash_transactions()), 2)

    def test_dedup_still_works(self):
        pool = Mempool(max_size=10, tx_ttl=60)
        pool.slash_pool_max_size = 5
        a = _StubSlashTx(tx_hash=_h(1), fee=MIN_FEE * 5)
        self.assertTrue(pool.add_slash_transaction(a))
        # Same tx_hash ⇒ False, no double-insert.
        self.assertFalse(pool.add_slash_transaction(a))
        self.assertEqual(len(pool.get_slash_transactions()), 1)


class TestCensorshipEvidencePoolDensityAdmit(unittest.TestCase):

    def test_high_density_evicts_low_density_when_full(self):
        pool = Mempool(max_size=10, tx_ttl=60)
        pool.censorship_evidence_pool_max_size = 3

        low_a = _StubCensorshipTx(tx_hash=_h(10), fee=MIN_FEE)
        low_b = _StubCensorshipTx(tx_hash=_h(11), fee=MIN_FEE)
        low_c = _StubCensorshipTx(tx_hash=_h(12), fee=MIN_FEE)
        self.assertTrue(pool.add_censorship_evidence_tx(
            low_a, arrival_block_height=1,
        ))
        self.assertTrue(pool.add_censorship_evidence_tx(
            low_b, arrival_block_height=2,
        ))
        self.assertTrue(pool.add_censorship_evidence_tx(
            low_c, arrival_block_height=3,
        ))

        high = _StubCensorshipTx(tx_hash=_h(99), fee=MIN_FEE * 10)
        # Pre-fix: refused (pool full).  Post-fix: density-evict + admit.
        self.assertTrue(pool.add_censorship_evidence_tx(
            high, arrival_block_height=4,
        ))

        txs = pool.get_censorship_evidence_txs()
        hashes = {t.tx_hash for t in txs}
        self.assertIn(high.tx_hash, hashes)
        self.assertEqual(len(txs), 3)
        # High-density entry comes first in selection order.
        self.assertEqual(txs[0].tx_hash, high.tx_hash)

    def test_eviction_clears_arrival_height_map(self):
        """The evicted entry's arrival-height bookkeeping must be
        torn down so forced-inclusion source walks don't reference
        stale rows."""
        pool = Mempool(max_size=10, tx_ttl=60)
        pool.censorship_evidence_pool_max_size = 2

        a = _StubCensorshipTx(tx_hash=_h(20), fee=MIN_FEE)
        b = _StubCensorshipTx(tx_hash=_h(21), fee=MIN_FEE)
        self.assertTrue(pool.add_censorship_evidence_tx(
            a, arrival_block_height=10,
        ))
        self.assertTrue(pool.add_censorship_evidence_tx(
            b, arrival_block_height=11,
        ))

        high = _StubCensorshipTx(tx_hash=_h(99), fee=MIN_FEE * 100)
        self.assertTrue(pool.add_censorship_evidence_tx(
            high, arrival_block_height=12,
        ))

        # The evicted hash is no longer in the arrival-heights map.
        evicted_hash = next(
            h for h in {a.tx_hash, b.tx_hash}
            if h not in {t.tx_hash for t in pool.get_censorship_evidence_txs()}
        )
        self.assertNotIn(evicted_hash, pool._evidence_arrival_heights)

    def test_below_floor_rejected(self):
        """The pre-existing MIN_FEE admission gate is preserved —
        density eviction does not let a sub-floor tx in."""
        pool = Mempool(max_size=10, tx_ttl=60)
        pool.censorship_evidence_pool_max_size = 3

        sub_floor = _StubCensorshipTx(tx_hash=_h(30), fee=MIN_FEE - 1)
        self.assertFalse(pool.add_censorship_evidence_tx(
            sub_floor, arrival_block_height=1,
        ))
        self.assertEqual(len(pool.get_censorship_evidence_txs()), 0)


class TestFinalityPoolOldestEviction(unittest.TestCase):
    """FinalityVote carries no fee — the flooder-pays-floor attack
    does not apply (a vote requires a real validator key).  But
    the strict-FIFO refusal-when-full breaks liveness if the
    validator set saturates the cap; switch to oldest-by-
    signed_at_height eviction so newest votes always land."""

    def test_oldest_evicted_when_full(self):
        pool = Mempool(max_size=10, tx_ttl=60)
        pool.finality_pool_max_size = 3

        v1 = _StubFinalityVote(
            signer_entity_id=_h(1), target_block_hash=_h(100),
            target_block_number=100, signed_at_height=100,
            _consensus_hash=_h(1001),
        )
        v2 = _StubFinalityVote(
            signer_entity_id=_h(2), target_block_hash=_h(100),
            target_block_number=100, signed_at_height=101,
            _consensus_hash=_h(1002),
        )
        v3 = _StubFinalityVote(
            signer_entity_id=_h(3), target_block_hash=_h(100),
            target_block_number=100, signed_at_height=102,
            _consensus_hash=_h(1003),
        )
        self.assertTrue(pool.add_finality_vote(v1))
        self.assertTrue(pool.add_finality_vote(v2))
        self.assertTrue(pool.add_finality_vote(v3))

        # New vote at signed_at_height=200 — oldest (v1) must be evicted.
        v4 = _StubFinalityVote(
            signer_entity_id=_h(4), target_block_hash=_h(200),
            target_block_number=200, signed_at_height=200,
            _consensus_hash=_h(2000),
        )
        self.assertTrue(pool.add_finality_vote(v4))

        keys = {vote.consensus_hash() for vote in pool.get_finality_votes()}
        self.assertNotIn(v1.consensus_hash(), keys)
        self.assertIn(v4.consensus_hash(), keys)
        self.assertEqual(len(keys), 3)


if __name__ == "__main__":
    unittest.main()
