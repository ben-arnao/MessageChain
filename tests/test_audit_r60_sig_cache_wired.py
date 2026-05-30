"""Audit r60 #2 -- ``SignatureCache`` was allocated + invalidated on
every reorg but ``lookup`` / ``store`` were never called.  Every
WOTS+ verify ran the full ~67 hash-chain walk regardless of whether
the SAME (msg_hash, sig, root_pk) triple had just been validated by
another layer (mempool admission -> block validation -> reorg
replay -> EquivocationWatcher observation).

CLAUDE.md anchors at risk:
  * Security principle #1 -- a duplicate-verify DoS amplification
    that raises the cost of being an honest validator under any
    sustained peer flood of replayed valid txs.
  * Hobbyist full-node accessibility -- the same verify work on
    every layer multiplies CPU cost on commodity hardware, making
    full-archival operation more expensive than it has to be.
  * Validator-collusion defence -- raising the cost of honesty
    asymmetrically benefits a colluding minority that can dump
    cheap-to-construct (but expensive-to-verify) gossip onto
    honest peers.

The fix routes ``lookup`` / ``store`` through the SINGLE
``verify_signature`` chokepoint in ``messagechain.crypto.keys``, so
every caller benefits without per-site edits and the existing
``Blockchain.sig_cache.invalidate()`` calls become meaningful again.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from messagechain.crypto.keys import KeyPair, verify_signature
from messagechain.crypto.sig_cache import SignatureCache, get_global_cache


class SigCacheWiredIntoVerifySignature(unittest.TestCase):
    """The cache MUST be consulted by ``verify_signature`` and
    repeated verifies on the same triple MUST short-circuit through
    the cache rather than re-running the full WOTS+ + Merkle walk.
    """

    @classmethod
    def setUpClass(cls):
        # One keypair, one message, one signature.  Tree height is
        # pinned low in conftest so KeyPair.generate is fast; we
        # only need a single sig so the cost is bounded regardless.
        cls.kp = KeyPair.generate(seed=b"audit-r60-sig-cache-test-seed")
        cls.msg = b"\xab" * 32
        cls.sig = cls.kp.sign(cls.msg)

    def setUp(self):
        # Fresh cache per test so prior tests' positive hits don't
        # spoof a wired path that isn't actually wired.  We don't
        # touch the global singleton; we monkey-patch
        # ``get_global_cache`` to return a per-test cache.
        self._test_cache = SignatureCache(max_size=1024)

    def test_first_verify_misses_then_stores(self):
        """A fresh cache + fresh triple: lookup returns None, the
        full verify runs, and store is called with True so the
        next caller short-circuits."""
        with patch(
            "messagechain.crypto.sig_cache.get_global_cache",
            return_value=self._test_cache,
        ):
            self.assertEqual(len(self._test_cache), 0)
            ok = verify_signature(self.msg, self.sig, self.kp.public_key)
            self.assertTrue(ok)
            # Positive result was stored.
            self.assertEqual(len(self._test_cache), 1)

    def test_second_verify_short_circuits_via_cache(self):
        """After a positive verify, the same triple's verify MUST
        hit the cache.  We assert the short-circuit by spying on
        ``wots_verify`` (the expensive step the cache is meant to
        skip) -- a cache HIT means wots_verify is NOT invoked.
        """
        with patch(
            "messagechain.crypto.sig_cache.get_global_cache",
            return_value=self._test_cache,
        ):
            ok1 = verify_signature(self.msg, self.sig, self.kp.public_key)
            self.assertTrue(ok1)
            with patch(
                "messagechain.crypto.keys.wots_verify",
            ) as spy_wots:
                ok2 = verify_signature(
                    self.msg, self.sig, self.kp.public_key,
                )
                self.assertTrue(ok2)
                # The wired path MUST short-circuit before the
                # WOTS+ chain walk.  Without the wiring, wots_verify
                # is unconditionally called.
                spy_wots.assert_not_called()

    def test_negative_result_not_cached(self):
        """A failed verify must NOT be stored -- caching negatives
        would let a transient verifier disagreement become
        permanent.  Mutate the signature so verify returns False,
        then confirm cache is empty.  This mirrors the existing
        ``SignatureCache.store`` contract (only positive results
        cached) but exercises it through the wired chokepoint.
        """
        with patch(
            "messagechain.crypto.sig_cache.get_global_cache",
            return_value=self._test_cache,
        ):
            # Tamper with one WOTS+ chunk so the sig fails verify.
            bad_sig = type(self.sig)(
                wots_signature=[b"\x00" * 32] * len(self.sig.wots_signature),
                leaf_index=self.sig.leaf_index,
                auth_path=list(self.sig.auth_path),
                wots_public_key=self.sig.wots_public_key,
                wots_public_seed=self.sig.wots_public_seed,
                sig_version=self.sig.sig_version,
            )
            ok = verify_signature(
                self.msg, bad_sig, self.kp.public_key,
            )
            self.assertFalse(ok)
            # The cache must NOT have absorbed the negative result.
            self.assertEqual(len(self._test_cache), 0)

    def test_invalidate_drops_cached_hit(self):
        """The existing ``invalidate()`` call on reorg now has
        meaning: after invalidate, a cached hit must MISS and the
        full verify re-runs.  This is what gives the chain a clean
        slate after a fork switch."""
        with patch(
            "messagechain.crypto.sig_cache.get_global_cache",
            return_value=self._test_cache,
        ):
            ok1 = verify_signature(self.msg, self.sig, self.kp.public_key)
            self.assertTrue(ok1)
            self.assertEqual(len(self._test_cache), 1)
            self._test_cache.invalidate()
            self.assertEqual(len(self._test_cache), 0)
            # After invalidate, the second verify must re-run wots_verify.
            with patch(
                "messagechain.crypto.keys.wots_verify",
                wraps=__import__(
                    "messagechain.crypto.hash_sig",
                    fromlist=["wots_verify"],
                ).wots_verify,
            ) as spy_wots:
                ok2 = verify_signature(
                    self.msg, self.sig, self.kp.public_key,
                )
                self.assertTrue(ok2)
                spy_wots.assert_called_once()


if __name__ == "__main__":
    unittest.main()
