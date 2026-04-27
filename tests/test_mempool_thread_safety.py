"""Thread-safety regression tests for ``messagechain.core.mempool.Mempool``.

The 1.28.3 ``asyncio.to_thread`` shift moved RPC submission AND block
production off the asyncio loop and onto worker threads.  The mempool
itself has historically had no internal locking, and most reads
iterate or sort ``self.pending``.  Concurrent mutators on other worker
threads can therefore raise

    RuntimeError: dictionary changed size during iteration

inside ``get_transactions`` / ``get_transactions_with_entity_cap`` /
``get_forced_inclusion_set`` and waste the proposer's slot.  An
attacker dribbling submits during a target validator's slot can
intermittently kill block production with no slashable evidence.

These tests exercise the concurrency surface directly.  Test #2 is
the headline regression and must FAIL on origin/main and PASS on
this branch.
"""

from __future__ import annotations

import threading
import time
import unittest

from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.identity.identity import Entity
from tests import register_entity_for_test  # noqa: F401  (alignment with other tests)


# ─────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────


def _make_entity(seed_tag: bytes) -> Entity:
    """Create a fresh entity with a deterministic seed.

    Conftest already pins ``MERKLE_TREE_HEIGHT=4`` so this is cheap
    (16 leaves) and fits the per-entity-cap limit on the mempool's
    pending tx count from any one entity.
    """
    # Place the unique tag at the START so distinct tags always produce
    # distinct 32-byte seeds (a fixed-length suffix would otherwise
    # truncate the tag and collapse multiple "entities" into one).
    seed = (seed_tag + b"-mempool-thread-safety----------")[:32]
    if len(seed) < 32:
        seed = seed.ljust(32, b"-")
    return Entity.create(seed)


def _make_signed_tx(entity: Entity, message: str, fee: int, nonce: int):
    """Sign a fresh MessageTransaction; advances entity.keypair._next_leaf."""
    return create_transaction(entity, message, fee=fee, nonce=nonce)


# ─────────────────────────────────────────────────────────────────────
# 1) Concurrent inserts
# ─────────────────────────────────────────────────────────────────────


class TestConcurrentInsertsDontCorruptState(unittest.TestCase):
    """N threads each call add_transaction with distinct fresh txs.

    With the mempool size cap and the per-sender ancestor cap
    (``MEMPOOL_MAX_ANCESTORS``) we can't safely flood from a single
    entity, so we mint one entity per thread and submit one tx per
    entity — every successful insert is unambiguously distinct.
    """

    def test_concurrent_inserts_dont_corrupt_state(self):
        n_threads = 16
        mempool = Mempool(max_size=4096)
        entities = [_make_entity(f"e{i}".encode()) for i in range(n_threads)]
        results: list[bool] = [False] * n_threads
        barrier = threading.Barrier(n_threads)

        def worker(idx: int) -> None:
            barrier.wait()
            tx = _make_signed_tx(entities[idx], f"msg-{idx}", fee=1500, nonce=0)
            results[idx] = mempool.add_transaction(tx)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        n_admitted = sum(1 for r in results if r)
        self.assertEqual(
            n_admitted,
            n_threads,
            "all distinct, well-formed txs should have been admitted",
        )
        self.assertEqual(len(mempool.pending), n_admitted)
        self.assertEqual(mempool.size, n_admitted)


# ─────────────────────────────────────────────────────────────────────
# 2) HEADLINE — block production iteration vs. concurrent inserts
# ─────────────────────────────────────────────────────────────────────


class TestBlockProductionIterationSafe(unittest.TestCase):
    """One reader iterating ``pending`` while another thread mutates it.

    On origin/main this races and CPython raises
    ``RuntimeError: dictionary changed size during iteration`` from
    inside ``sorted(self.pending.values(), ...)`` in
    ``get_transactions``.  After the lock is added, the iteration
    sees a stable snapshot and never raises.
    """

    def test_block_production_iteration_does_not_crash_under_concurrent_inserts(self):
        # Pre-populate the mempool so each get_transactions call iterates
        # a sizable dict (longer iteration → wider race window).  We need
        # `pending` to be populated enough that sorted(.values()) takes
        # measurable time relative to a single dict mutation.
        mempool = Mempool(max_size=4096)
        # Mint a pool of pre-signed txs from many distinct entities so
        # the writer thread doesn't have to do expensive Entity.create
        # work in its hot loop — every writer iteration is a pure
        # mempool mutation, maximizing the time fraction spent inside
        # the dict.
        pre_entities = [_make_entity(f"hot{i}".encode()) for i in range(64)]
        pre_txs = [
            _make_signed_tx(pre_entities[i], f"hot-{i}", fee=1500, nonce=0)
            for i in range(64)
        ]
        # Pre-populate with most of them so iteration has bulk to chew on.
        for tx in pre_txs[:48]:
            self.assertTrue(mempool.add_transaction(tx))

        # The remaining txs are the writer's "rotating" set: it adds
        # them, then removes them, in a tight loop.
        churn_txs = pre_txs[48:]

        stop = threading.Event()
        errors: list[BaseException] = []

        def reader() -> None:
            try:
                while not stop.is_set():
                    # The three iterating reads are all real block-
                    # production code paths on the proposer.
                    mempool.get_transactions(max_count=1024)
                    mempool.get_transactions_with_entity_cap(max_count=1024)
                    mempool.get_forced_inclusion_set(current_block_height=10_000)
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        def writer() -> None:
            try:
                while not stop.is_set():
                    for tx in churn_txs:
                        if stop.is_set():
                            return
                        # add → remove → add → remove …  Both
                        # mutations are exactly the operations that
                        # can change the dict size mid-iteration in
                        # the reader thread.
                        mempool.add_transaction(tx)
                        mempool.remove_transactions([tx.tx_hash])
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        # Multiple readers AND writers widen the race window so the
        # test fails reliably on origin/main.
        readers = [threading.Thread(target=reader) for _ in range(3)]
        writers = [threading.Thread(target=writer) for _ in range(3)]
        for t in readers + writers:
            t.start()
        time.sleep(2.0)
        stop.set()
        for t in readers + writers:
            t.join(timeout=5.0)

        self.assertFalse(
            errors,
            "no exceptions should be raised during concurrent mempool "
            "reads/writes; got: " + repr(errors),
        )


# ─────────────────────────────────────────────────────────────────────
# 3) Concurrent leaf-reuse check
# ─────────────────────────────────────────────────────────────────────


class TestConcurrentLeafReuseCheck(unittest.TestCase):
    """Two threads simultaneously submit txs that share a leaf index.

    The leaf-reuse check at lines 153-156 reads ``self.pending``, then
    inserts.  Without a lock, two threads can both pass the check and
    both insert — at which point the proposer's block fails block
    validation (entity-leaf dedupe).  With the lock, exactly one wins
    and the other is rejected.
    """

    def test_concurrent_leaf_reuse_check_prevents_double_insert(self):
        mempool = Mempool(max_size=4096)
        entity = _make_entity(b"leaf-reuse")

        # Sign tx A at leaf 0.
        tx_a = _make_signed_tx(entity, "msg-A", fee=1500, nonce=0)
        # Rewind the leaf cursor and sign tx B with a different nonce —
        # different tx_hash, but same (entity_id, leaf_index=0).  This
        # is exactly the "two rapid sends from same wallet observing
        # same watermark" race the leaf-reuse guard exists to catch.
        entity.keypair._next_leaf = 0
        tx_b = _make_signed_tx(entity, "msg-B", fee=1600, nonce=1)
        self.assertEqual(tx_a.signature.leaf_index, tx_b.signature.leaf_index)
        self.assertNotEqual(tx_a.tx_hash, tx_b.tx_hash)

        results: list[bool | None] = [None, None]
        barrier = threading.Barrier(2)

        def worker(idx: int, tx) -> None:
            barrier.wait()
            results[idx] = mempool.add_transaction(tx)

        ta = threading.Thread(target=worker, args=(0, tx_a))
        tb = threading.Thread(target=worker, args=(1, tx_b))
        # Repeat several times — a single trial may not always race.
        # We only need to demonstrate that the invariant holds on
        # every trial: at most one of (tx_a, tx_b) is admitted.  We
        # reset mempool between trials.
        for trial in range(50):
            mempool = Mempool(max_size=4096)
            results = [None, None]
            barrier = threading.Barrier(2)
            ta = threading.Thread(target=worker, args=(0, tx_a))
            tb = threading.Thread(target=worker, args=(1, tx_b))
            ta.start()
            tb.start()
            ta.join()
            tb.join()
            n_admitted = sum(1 for r in results if r)
            self.assertLessEqual(
                n_admitted,
                1,
                f"trial {trial}: both leaf-reuse txs were admitted "
                f"(results={results})",
            )
            self.assertEqual(
                len(mempool.pending),
                n_admitted,
                f"trial {trial}: pending size != admitted count",
            )


# ─────────────────────────────────────────────────────────────────────
# 4) Snapshot consistency from get_transactions
# ─────────────────────────────────────────────────────────────────────


class TestGetTransactionsConsistentSnapshot(unittest.TestCase):
    """get_transactions never returns a mid-mutation torn read.

    Every tx in the returned list must, at minimum, have *been* in
    the mempool at the moment of the call.  Without a lock, the
    sorted() call on .values() can interleave with a removal and
    surface a tx that was concurrently popped — though the actual
    failure mode upstream is the size-change RuntimeError.  This
    test exercises the same path with looser invariants.
    """

    def test_get_transactions_returns_consistent_snapshot(self):
        mempool = Mempool(max_size=4096)
        entities = [_make_entity(f"snap{i}".encode()) for i in range(8)]
        # Pre-populate.
        seeded_hashes: set[bytes] = set()
        for ent in entities:
            tx = _make_signed_tx(ent, "snap-msg", fee=1500, nonce=0)
            self.assertTrue(mempool.add_transaction(tx))
            seeded_hashes.add(tx.tx_hash)

        stop = threading.Event()
        errors: list[BaseException] = []

        def churner(idx: int) -> None:
            try:
                ent = _make_entity(f"churn{idx}".encode())
                while not stop.is_set():
                    tx = _make_signed_tx(ent, "churn", fee=1500, nonce=0)
                    if mempool.add_transaction(tx):
                        mempool.remove_transactions([tx.tx_hash])
                    # Re-sign requires bumping a leaf; cheap at height=4
                    # but bounded by num_leaves=16.  Reset so we don't
                    # exhaust the keypair mid-test.
                    ent.keypair._next_leaf = 0
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        def reader() -> None:
            try:
                while not stop.is_set():
                    snap = mempool.get_transactions(max_count=1024)
                    # Every returned tx must be a real, structurally
                    # complete MessageTransaction — never None, never a
                    # half-constructed entry.
                    for tx in snap:
                        self.assertIsNotNone(tx.tx_hash)
                        self.assertIsNotNone(tx.entity_id)
            except BaseException as exc:
                errors.append(exc)

        ts = [threading.Thread(target=churner, args=(i,)) for i in range(3)]
        rs = [threading.Thread(target=reader) for _ in range(2)]
        for t in ts + rs:
            t.start()
        time.sleep(1.5)
        stop.set()
        for t in ts + rs:
            t.join(timeout=5.0)

        self.assertFalse(errors, f"errors during concurrent snapshot reads: {errors!r}")


# ─────────────────────────────────────────────────────────────────────
# 5) No deadlock under load
# ─────────────────────────────────────────────────────────────────────


class TestNoDeadlockUnderLoad(unittest.TestCase):
    """High-concurrency mix of read + write paths must keep making
    progress (i.e. the lock is reentrant-safe and no method holds it
    across an external call that could cycle back into the mempool).
    """

    def test_no_deadlock_under_load(self):
        mempool = Mempool(max_size=4096)
        seed_entity = _make_entity(b"dead-seed")
        for i in range(3):
            tx = _make_signed_tx(seed_entity, f"dl-seed-{i}", fee=1500, nonce=i)
            self.assertTrue(mempool.add_transaction(tx))

        stop = threading.Event()
        progress: dict[str, int] = {"adds": 0, "reads": 0, "removes": 0, "expires": 0}
        progress_lock = threading.Lock()
        errors: list[BaseException] = []

        def adder(tag: int) -> None:
            try:
                ent = _make_entity(f"dla{tag}".encode())
                while not stop.is_set():
                    tx = _make_signed_tx(ent, "dla", fee=1500, nonce=0)
                    mempool.add_transaction(tx)
                    with progress_lock:
                        progress["adds"] += 1
                    mempool.remove_transactions([tx.tx_hash])
                    ent.keypair._next_leaf = 0
            except BaseException as exc:
                errors.append(exc)

        def reader() -> None:
            try:
                while not stop.is_set():
                    mempool.get_transactions(1024)
                    mempool.get_transactions_with_entity_cap(1024)
                    mempool.get_forced_inclusion_set(10_000)
                    mempool.get_fee_estimate(message_bytes=128)
                    mempool.get_pending_nonce(b"nobody-here", 0)
                    with progress_lock:
                        progress["reads"] += 1
            except BaseException as exc:
                errors.append(exc)

        def expirer() -> None:
            try:
                while not stop.is_set():
                    mempool.expire_transactions()
                    with progress_lock:
                        progress["expires"] += 1
            except BaseException as exc:
                errors.append(exc)

        threads = (
            [threading.Thread(target=adder, args=(i,)) for i in range(3)]
            + [threading.Thread(target=reader) for _ in range(3)]
            + [threading.Thread(target=expirer)]
        )
        for t in threads:
            t.start()

        # Liveness check: sample progress after 1.5s and again after 3s.
        time.sleep(1.5)
        with progress_lock:
            mid = dict(progress)
        time.sleep(1.5)
        with progress_lock:
            end = dict(progress)
        stop.set()
        for t in threads:
            t.join(timeout=5.0)

        self.assertFalse(errors, f"errors during deadlock test: {errors!r}")
        # Every thread group must have made forward progress between
        # the mid and end samples.  If the lock were held across an
        # external call that re-enters the mempool, at least one of
        # these counters would freeze.
        self.assertGreater(end["adds"], mid["adds"], "adders made no progress")
        self.assertGreater(end["reads"], mid["reads"], "readers made no progress")
        self.assertGreater(
            end["expires"], mid["expires"], "expirer made no progress"
        )


# ─────────────────────────────────────────────────────────────────────
# 6) Serial behaviour preserved
# ─────────────────────────────────────────────────────────────────────


class TestSerialBehaviourUnchanged(unittest.TestCase):
    """Single-threaded sanity: existing mempool semantics are preserved.

    Adding a lock must not change ordering, RBF behaviour, eviction,
    or any observable serial property.
    """

    def test_basic_admission_and_size(self):
        mempool = Mempool(max_size=8)
        entities = [_make_entity(f"ser{i}".encode()) for i in range(5)]
        for ent in entities:
            tx = _make_signed_tx(ent, "serial", fee=1500, nonce=0)
            self.assertTrue(mempool.add_transaction(tx))
        self.assertEqual(mempool.size, 5)

    def test_dedupe_on_repeat_hash(self):
        mempool = Mempool(max_size=8)
        ent = _make_entity(b"dedupe")
        tx = _make_signed_tx(ent, "dup", fee=1500, nonce=0)
        self.assertTrue(mempool.add_transaction(tx))
        self.assertFalse(mempool.add_transaction(tx))
        self.assertEqual(mempool.size, 1)

    def test_get_transactions_orders_by_fee_per_byte(self):
        mempool = Mempool(max_size=8)
        ent_lo = _make_entity(b"orderlo")
        ent_hi = _make_entity(b"orderhi")
        # Same payload length → fee strictly determines fee-per-byte.
        tx_lo = _make_signed_tx(ent_lo, "ranking_msg", fee=1500, nonce=0)
        tx_hi = _make_signed_tx(ent_hi, "ranking_msg", fee=9000, nonce=0)
        self.assertTrue(mempool.add_transaction(tx_lo))
        self.assertTrue(mempool.add_transaction(tx_hi))
        out = mempool.get_transactions(max_count=10)
        self.assertEqual([t.tx_hash for t in out], [tx_hi.tx_hash, tx_lo.tx_hash])

    def test_remove_transactions_decrements_sender_count(self):
        mempool = Mempool(max_size=8)
        ent = _make_entity(b"rm")
        tx = _make_signed_tx(ent, "rmmsg", fee=1500, nonce=0)
        self.assertTrue(mempool.add_transaction(tx))
        self.assertEqual(mempool._sender_counts[ent.entity_id], 1)
        mempool.remove_transactions([tx.tx_hash])
        self.assertEqual(mempool.size, 0)
        self.assertNotIn(ent.entity_id, mempool._sender_counts)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
