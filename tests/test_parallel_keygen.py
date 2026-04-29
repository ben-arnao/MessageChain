"""Tests for parallel WOTS+ leaf derivation during keygen.

Each WOTS+ leaf is independent of every other leaf, so the O(2^height)
keygen splits cleanly across worker processes.  At production validator
height (h=20, ~1M leaves) serial keygen is ~90 min on a typical VM;
8-way parallelization brings it to ~10-15 min.  At personal-wallet
height (h=16, ~65k leaves) it shrinks single-thread minutes to seconds.

Anchor invariants:

  1. **Determinism across worker counts.**  The Merkle root is a pure
     function of (seed, height) — the worker count must not change it,
     or signatures generated under one configuration would not verify
     against the public key recorded under another.
  2. **Spawn-overhead threshold.**  Multiprocessing on Windows uses
     ``spawn`` (re-imports the whole module per worker), which costs
     1-2 seconds of startup per worker.  Below ``KEYGEN_PARALLEL_MIN_LEAVES``
     the serial path beats the parallel path; the threshold gate
     prevents tiny trees from paying that overhead.
  3. **KEYGEN_WORKERS=1 forces serial.**  The test conftest pins this
     to 1 so the suite stays deterministic and avoids spawn overhead
     on every keygen.  This test verifies that the gate actually skips
     the ``multiprocessing.Pool`` call on count=1.

Test sizing: heights are kept small (h≤8) so even a 2-worker spawn is
bearable inside a 30s pytest-timeout window.  ``KEYGEN_PARALLEL_MIN_LEAVES``
is patched to a tiny value so the parallel path is reachable from
those small heights.
"""

import unittest
from unittest import mock

import messagechain.config
from messagechain.crypto.keys import KeyPair


# Use h=6 (64 leaves) for parallel-path tests: large enough that splitting
# across workers exercises real combine logic, small enough that 2-worker
# spawn + work fits well under the 30s pytest timeout on Windows.
_PARALLEL_HEIGHT = 6
_PARALLEL_THRESHOLD = 8  # leaves; below the test height so parallel actually fires
_PARALLEL_WORKERS = 2     # minimal worker count that still tests partition logic


class TestParallelKeygenDeterminism(unittest.TestCase):
    """Same seed must produce the same Merkle root regardless of how
    many worker processes derive the leaves.  Without this, the public
    key recorded on chain under one machine's CPU count would differ
    from what the same wallet computes on another machine."""

    def test_serial_and_parallel_produce_same_root(self):
        seed = b"deterministic-keygen".ljust(32, b"\x00")
        # Serial baseline (KEYGEN_WORKERS=1 guarantees no Pool path).
        with mock.patch.object(messagechain.config, "KEYGEN_WORKERS", 1):
            kp_serial = KeyPair.generate(seed, height=_PARALLEL_HEIGHT)
        # Parallel.
        with mock.patch.multiple(
            messagechain.config,
            KEYGEN_WORKERS=_PARALLEL_WORKERS,
            KEYGEN_PARALLEL_MIN_LEAVES=_PARALLEL_THRESHOLD,
        ):
            kp_parallel = KeyPair.generate(seed, height=_PARALLEL_HEIGHT)
        self.assertEqual(
            kp_serial.public_key, kp_parallel.public_key,
            "Parallel and serial keygen produced different Merkle roots — "
            "a worker-count change must NOT alter the public key.",
        )


class TestParallelKeygenThresholdGate(unittest.TestCase):
    """Below ``KEYGEN_PARALLEL_MIN_LEAVES`` the parallel path must NOT
    be taken — subprocess spawn overhead would dominate.  This test
    proves the gate exists by patching ``multiprocessing.Pool`` and
    asserting it's never instantiated for sub-threshold trees."""

    def test_small_tree_skips_multiprocessing_pool(self):
        seed = b"sub-threshold-tree".ljust(32, b"\x00")
        # h=4 = 16 leaves — well below the production threshold of 16384.
        with mock.patch("multiprocessing.Pool") as mock_pool:
            with mock.patch.object(
                messagechain.config, "KEYGEN_WORKERS", 8,
            ):
                KeyPair.generate(seed, height=4)
        mock_pool.assert_not_called()


class TestKeygenWorkersOneIsSerial(unittest.TestCase):
    """``KEYGEN_WORKERS=1`` (the test conftest pin) must force the
    serial path even at heights above the parallel threshold."""

    def test_workers_one_skips_pool(self):
        seed = b"workers-one-serial".ljust(32, b"\x00")
        with mock.patch("multiprocessing.Pool") as mock_pool:
            with mock.patch.multiple(
                messagechain.config,
                KEYGEN_WORKERS=1,
                KEYGEN_PARALLEL_MIN_LEAVES=_PARALLEL_THRESHOLD,
            ):
                KeyPair.generate(seed, height=_PARALLEL_HEIGHT)
        mock_pool.assert_not_called()


class TestParallelKeygenSignVerify(unittest.TestCase):
    """End-to-end: a keypair built in parallel must sign and verify
    just like a serial one.  Catches bugs where the parallel path
    produces a 'plausible' root that doesn't actually correspond to
    the leaves being signed under."""

    def test_parallel_keypair_signs_and_verifies(self):
        from messagechain.crypto.hash_sig import _hash
        from messagechain.crypto.keys import verify_signature
        seed = b"parallel-sign-verify".ljust(32, b"\x00")
        with mock.patch.multiple(
            messagechain.config,
            KEYGEN_WORKERS=_PARALLEL_WORKERS,
            KEYGEN_PARALLEL_MIN_LEAVES=_PARALLEL_THRESHOLD,
        ):
            kp = KeyPair.generate(seed, height=_PARALLEL_HEIGHT)
        msg = _hash(b"first message after parallel keygen")
        sig = kp.sign(msg)
        self.assertTrue(
            verify_signature(msg, sig, kp.public_key),
            "Signature from parallel-built keypair failed verification — "
            "the parallel root does not match the leaves it claims to cover.",
        )


if __name__ == "__main__":
    unittest.main()
