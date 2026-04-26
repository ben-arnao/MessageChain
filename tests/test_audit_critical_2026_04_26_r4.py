"""Critical-severity audit fixes — round 4 (2026-04-26).

Two CRITICALs (plus one bundled latent fix):

1. **SubmissionServer never receives `receipt_issuer`** — server.py:4405
   constructs `SubmissionServer(...)` and omits the `receipt_issuer=`
   kwarg.  Every `if receipt_issuer is not None:` branch in
   `submit_transaction_to_mempool` falls through, so the public HTTPS
   endpoint silently issues NO receipts / acks / rejections.  The
   entire censorship-evidence pipeline (the headline structural defense
   against the project's primary adversary) is dead in production.
   Fix: pass `receipt_issuer=server.receipt_issuer` in the constructor
   call.

2. **Reorg leaves stale `key_rotation_last_height` rows on disk** —
   `restore_state_snapshot` wipes 11 mirror tables but not the v18
   `key_rotation_last_height` table.  Any entity that rotated only on
   the losing fork retains its stale (higher) row; cold restart re-
   hydrates it; the cold node then enforces a different rotation
   cooldown than the warm cluster, and the snapshot-root commitment
   for `_TAG_KEY_ROTATION_LAST_HEIGHT` diverges -> silent consensus
   split at the next checkpoint block.  Same defect class as the
   round-2 `entity_id_to_index` reorg leak.  Fix: add `DELETE FROM
   key_rotation_last_height` to the wipe list.

3. **(Bundled with #1) `KeyPair.sign` is not thread-safe** — concurrent
   calls can both read the same `_next_leaf` before either advances it,
   producing two WOTS+ signatures over different message hashes under
   the same one-time leaf -- mathematically reveals the leaf's WOTS+
   private key.  Currently dormant because of #1 (no concurrent issuer
   calls), but #1's fix would expose it to parallel HTTPS submissions.
   MUST land in the same change so #1 doesn't open a worse hole.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
import unittest

from messagechain.crypto.keys import KeyPair
from messagechain.storage.chaindb import ChainDB


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1 — SubmissionServer must be constructed with receipt_issuer
# ─────────────────────────────────────────────────────────────────────

class TestSubmissionServerWiredWithReceiptIssuer(unittest.TestCase):
    """The production server-startup code path MUST pass
    `receipt_issuer=server.receipt_issuer` to SubmissionServer.  The
    constructor accepts the kwarg; omitting it silently disables the
    censorship-evidence pipeline.

    This is a structural test on the server.py source -- the
    alternative (booting a full server in-process) is too invasive.
    """

    def test_submission_server_construction_passes_receipt_issuer(self):
        # Locate server.py at the repo root.  The test runs from the
        # tests/ directory inside whichever worktree we're in.
        server_path = os.path.normpath(
            os.path.join(
                os.path.dirname(__file__), "..", "server.py",
            )
        )
        self.assertTrue(
            os.path.exists(server_path),
            f"server.py not found at {server_path}",
        )
        with open(server_path, encoding="utf-8") as f:
            src = f.read()

        # Find every SubmissionServer(...) construction.  Must contain
        # at least one call that passes a receipt_issuer kwarg.  Match
        # the call across any reasonable amount of whitespace +
        # parameters before the closing paren.
        constructions = list(re.finditer(
            r"SubmissionServer\s*\(", src,
        ))
        self.assertTrue(
            constructions,
            "No SubmissionServer(...) construction found in server.py",
        )
        for m in constructions:
            # Walk forward to the matching close paren, balancing nested
            # parens (e.g. lambdas as kwarg defaults).
            depth = 1
            i = m.end()
            while i < len(src) and depth > 0:
                if src[i] == "(":
                    depth += 1
                elif src[i] == ")":
                    depth -= 1
                i += 1
            call_body = src[m.end():i - 1]
            self.assertIn(
                "receipt_issuer=", call_body,
                f"SubmissionServer construction at offset {m.start()} "
                f"omits receipt_issuer= kwarg.  Without it, the public "
                f"HTTPS endpoint silently issues NO receipts / acks / "
                f"rejections -- the entire censorship-evidence pipeline "
                f"is dead in production.  Construction body was:\n"
                f"{call_body}",
            )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1.5 — KeyPair.sign must be thread-safe
# ─────────────────────────────────────────────────────────────────────

class TestKeyPairSignIsThreadSafe(unittest.TestCase):
    """Concurrent `sign()` calls on the same KeyPair MUST return
    distinct leaf_index values.  Pre-fix, two threads racing the
    `leaf_idx = self._next_leaf` read could both observe the same N,
    each produce a Signature using leaf N, and broadcast them -- two
    WOTS+ signatures over different message hashes under the same
    one-time leaf mathematically reveals the WOTS+ private key for
    that leaf.

    The receipt-subtree keypair (used for receipts / acks /
    rejections) is the most exposed: every HTTPS submission landing on
    a ThreadingMixIn server triggers a sign() call.
    """

    def test_keypair_sign_acquires_lock_to_serialize_leaf_advance(self):
        """Structural assertion: `KeyPair` must expose a `_sign_lock`
        attribute (or equivalent threading primitive) that `sign()`
        acquires around the read-modify-write of `_next_leaf`.

        The race is real but its narrow window (a few CPython
        bytecodes between LOAD_ATTR(_next_leaf) and STORE_ATTR(
        _next_leaf)) makes pure concurrent `sign()` calls a poor
        observability surface for unit testing.  Locking it at the
        primitive level is the durable defense.
        """
        seed = b"r4-lock-attr-seed-32bytes!!!!!!!"
        kp = KeyPair.generate(seed, height=4)
        self.assertTrue(
            hasattr(kp, "_sign_lock"),
            "KeyPair MUST expose a `_sign_lock` (threading.Lock) so "
            "the read-modify-write of _next_leaf is atomic.  Without "
            "it, two HTTPS handlers that race into "
            "ReceiptIssuer.issue() can each consume the same WOTS+ "
            "leaf -- mathematically reveals the leaf's private key.",
        )
        # Confirm it's a usable lock object (acquire/release contract).
        self.assertTrue(callable(getattr(kp._sign_lock, "acquire", None)))
        self.assertTrue(callable(getattr(kp._sign_lock, "release", None)))

    def test_concurrent_sign_calls_do_not_share_leaf_index(self):
        """Behavioural test: many threads racing into sign() must
        each consume a distinct leaf.  Combined with the structural
        `_sign_lock` test above, this regresses both that the lock
        EXISTS and that sign() actually USES it (a fix that adds the
        attribute but forgets to wrap the read-modify-write would
        pass the structural test and fail this one).
        """
        seed = b"r4-thread-safety-seed-32bytes!!!"
        kp = KeyPair.generate(seed, height=4)  # 16 leaves

        n_threads = 8
        msg = b"\x00" * 32
        results: list[int] = []
        results_lock = threading.Lock()
        errors: list[Exception] = []
        barrier = threading.Barrier(n_threads)

        def worker():
            try:
                barrier.wait()
                sig = kp.sign(msg)
                with results_lock:
                    results.append(sig.leaf_index)
            except Exception as e:
                with results_lock:
                    errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if errors:
            raise errors[0]
        self.assertEqual(
            len(set(results)), n_threads,
            f"Concurrent sign() produced DUPLICATE leaf_index values: "
            f"{sorted(results)}.  Two signatures at the same leaf "
            f"reveal the WOTS+ private key.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2 — restore_state_snapshot must wipe key_rotation_last_height
# ─────────────────────────────────────────────────────────────────────

class TestReorgWipesKeyRotationLastHeight(unittest.TestCase):
    """Reorg via `restore_state_snapshot` MUST clear all chaindb mirror
    tables that are part of the reorg-rebuildable state.  v18 added
    a `key_rotation_last_height` mirror table (set on every applied
    rotation) but the reorg DELETE list was not updated.  Any entity
    that rotated only on the losing fork keeps its stale (higher)
    block_height row on disk.  After a cold restart, the warm cluster
    enforces the canonical-replay cooldown while the cold node
    enforces the stale one -- the snapshot-root commitment for
    `_TAG_KEY_ROTATION_LAST_HEIGHT` diverges -> silent consensus
    fork at the next checkpoint block.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="mc-r4-rotleak-")
        self.db = ChainDB(db_path=os.path.join(self.tmpdir, "chain.db"))

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _minimal_snapshot(self) -> dict:
        """The smallest snapshot dict restore_state_snapshot accepts.
        Mirrors the shape produced by `serialize_state_snapshot` for
        an entirely-empty chain."""
        return {
            "balances": {},
            "staked": {},
            "nonces": {},
            "public_keys": {},
            "message_counts": {},
            "proposer_sig_counts": {},
            "authority_keys": {},
            "pending_unstakes": {},
            "key_history": {},
            "reputation": {},
            "stake_snapshots": {},
            "total_supply": 0,
            "total_minted": 0,
            "total_fees_collected": 0,
        }

    def test_reorg_clears_stale_rotation_height_rows(self):
        # Seed the table with rows that represent rotations on a fork
        # we're about to reorg out of.
        self.db.set_key_rotation_last_height(b"\x11" * 32, 1234)
        self.db.set_key_rotation_last_height(b"\x22" * 32, 5678)
        self.db.flush_state()

        before = self.db.get_all_key_rotation_last_height()
        self.assertEqual(
            before,
            {b"\x11" * 32: 1234, b"\x22" * 32: 5678},
            "test setup: rows must be visible before reorg",
        )

        # Restore from a minimal snapshot (no key_rotation_last_height
        # field -- because the canonical chain replay rebuilds it from
        # block applies, not from the snapshot dict).
        self.db.restore_state_snapshot(self._minimal_snapshot())

        after = self.db.get_all_key_rotation_last_height()
        self.assertEqual(
            after, {},
            "restore_state_snapshot MUST wipe the "
            "key_rotation_last_height mirror -- otherwise stale rows "
            "from a losing fork survive across reorg + cold restart "
            "and cause silent consensus divergence at the next "
            "checkpoint block.",
        )


if __name__ == "__main__":
    unittest.main()
