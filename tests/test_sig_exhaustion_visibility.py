"""
Tests for WOTS+ signature-exhaustion visibility.

Two user-facing guards against the "silently brick your funds" footgun
that results from running out of one-time signatures before rotating:

 1. A `--sigs-remaining` CLI flag on `messagechain account` that prints
    "Signatures remaining: <left> / <total> (<pct>% used)" so a
    non-technical user can check their runway without running a node.

 2. Node-level WARNING logs emitted from KeyPair.sign() at 80% and 95%
    usage, once per threshold per process run, so operators notice on
    their existing log pipeline before exhaustion rather than after.
"""

import io
import logging
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from messagechain.crypto import keys as keys_module
from messagechain.crypto.keys import KeyPair


# Tiny tree so the usage-percent math is observable:
#   height=4 → 16 leaves, 80% → leaf #13, 95% → leaf #16
# height=5 → 32 leaves, 80% threshold at 26, 95% at 31
# We pick height=5 so we can cross both thresholds cleanly with
# integer leaf counts.
_TREE_HEIGHT = 5
_SEED = b"\x42" * 32


def _fresh_keypair(height: int = _TREE_HEIGHT, seed: bytes = _SEED) -> KeyPair:
    """Build a small tree and reset the module-level warned state."""
    keys_module._warned_thresholds.clear()
    return KeyPair.generate(seed, height=height)


class TestSignatureExhaustionWarnings(unittest.TestCase):
    """KeyPair.sign() emits WARNING-level logs once per threshold."""

    def setUp(self):
        # Ensure every test starts with an empty warned-set so thresholds
        # are observable.  The module-level set is intentionally process-
        # scoped in production (once-per-run semantics).
        keys_module._warned_thresholds.clear()

    def _sign_n(self, kp: KeyPair, n: int) -> None:
        """Sign n times with dummy message hashes."""
        for i in range(n):
            msg = (b"m" + i.to_bytes(8, "big")).ljust(32, b"\x00")
            kp.sign(msg)

    def test_no_warning_below_80_percent(self):
        """Signing below the 80% threshold must NOT emit any warnings.

        32-leaf tree: 25 signatures = 78.1% used — just under the floor.
        """
        kp = _fresh_keypair()  # 32 leaves
        with self.assertLogs(keys_module.__name__, level="WARNING") as cm:
            self._sign_n(kp, 25)
            # assertLogs requires at least one record, so emit a sentinel
            # at INFO level we don't care about.
            logging.getLogger(keys_module.__name__).warning("__sentinel__")
        warning_lines = [r for r in cm.records
                         if r.levelno == logging.WARNING
                         and "__sentinel__" not in r.getMessage()]
        self.assertEqual(warning_lines, [],
                         "no WOTS+ exhaustion warnings should fire under 80%")

    def test_warning_fires_at_80_percent(self):
        """Crossing 80% emits exactly one WARNING mentioning the threshold."""
        kp = _fresh_keypair()  # 32 leaves → 80% at 26 signatures
        with self.assertLogs(keys_module.__name__, level="WARNING") as cm:
            self._sign_n(kp, 26)
        msgs = [r.getMessage() for r in cm.records if r.levelno == logging.WARNING]
        self.assertEqual(len(msgs), 1, f"expected one 80% warning, got: {msgs}")
        self.assertIn("80", msgs[0])

    def test_warning_fires_once_per_threshold(self):
        """Additional signatures past 80% must NOT re-emit the warning."""
        kp = _fresh_keypair()  # 32 leaves
        # First sign to cross 80% — one warning expected.
        with self.assertLogs(keys_module.__name__, level="WARNING") as cm1:
            self._sign_n(kp, 26)
        self.assertEqual(
            len([r for r in cm1.records if r.levelno == logging.WARNING]), 1)

        # Now keep signing but don't cross 95% — no new warning.
        # 95% of 32 is 30.4, so leaf 30 crosses it; stop at leaf 29.
        with self.assertLogs(keys_module.__name__, level="WARNING") as cm2:
            self._sign_n(kp, 3)  # 26..29 inclusive → 28, 29 are post-80%
            logging.getLogger(keys_module.__name__).warning("__sentinel__")
        real = [r.getMessage() for r in cm2.records
                if r.levelno == logging.WARNING
                and "__sentinel__" not in r.getMessage()]
        self.assertEqual(real, [], f"80% warning must not repeat, got: {real}")

    def test_warning_fires_at_95_percent(self):
        """Crossing 95% emits a second distinct WARNING."""
        kp = _fresh_keypair()  # 32 leaves → 95% at 31 (31/32 = 96.875%)
        with self.assertLogs(keys_module.__name__, level="WARNING") as cm:
            self._sign_n(kp, 31)
        warnings = [r.getMessage() for r in cm.records if r.levelno == logging.WARNING]
        # Must have fired both 80% and 95% across the 31 signatures.
        self.assertEqual(len(warnings), 2,
                         f"expected 80% + 95% warnings, got: {warnings}")
        self.assertTrue(any("95" in m for m in warnings),
                        f"no 95% warning in: {warnings}")

    def test_thresholds_are_per_keypair_root(self):
        """Two different keypairs warn independently (different entities)."""
        # Different seeds → different Merkle roots → independent counters.
        kp_a = _fresh_keypair(seed=b"\x01" * 32)
        kp_b = KeyPair.generate(b"\x02" * 32, height=_TREE_HEIGHT)

        # Sign kp_a past 80% — fires once for kp_a.
        with self.assertLogs(keys_module.__name__, level="WARNING") as cm1:
            for i in range(26):
                msg = (b"a" + i.to_bytes(8, "big")).ljust(32, b"\x00")
                kp_a.sign(msg)
        self.assertEqual(
            len([r for r in cm1.records if r.levelno == logging.WARNING]), 1)

        # kp_b is a different key → it should ALSO fire when it crosses
        # 80%, not be suppressed by kp_a's earlier warning.
        with self.assertLogs(keys_module.__name__, level="WARNING") as cm2:
            for i in range(26):
                msg = (b"b" + i.to_bytes(8, "big")).ljust(32, b"\x00")
                kp_b.sign(msg)
        self.assertEqual(
            len([r for r in cm2.records if r.levelno == logging.WARNING]), 1,
            "kp_b must warn independently of kp_a")


class TestSigsRemainingCLIFlag(unittest.TestCase):
    """The `messagechain account --sigs-remaining` flag prints a summary
    of one-time-signature capacity to stdout, using only local keypair
    state (no RPC required — a user who's locked out still needs this)."""

    def test_parser_accepts_flag(self):
        """Parser accepts --sigs-remaining on the account subcommand."""
        from messagechain.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["account", "--sigs-remaining"])
        self.assertEqual(args.command, "account")
        self.assertTrue(args.sigs_remaining)

    def test_parser_default_false(self):
        """Without the flag, sigs_remaining defaults to False."""
        from messagechain.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["account"])
        self.assertFalse(args.sigs_remaining)

    def test_cmd_account_prints_sigs_remaining(self):
        """cmd_account with --sigs-remaining prints the usage summary
        without contacting the server."""
        import argparse
        from messagechain.cli import cmd_account

        # Stub the password prompt so no stdin interaction happens.
        fake_priv = b"\x11" * 32
        args = argparse.Namespace(
            command="account",
            sigs_remaining=True,
            server=None,
        )

        buf = io.StringIO()
        # Patch Entity.create so we don't run a full keygen in the test
        # (height=20 would be prohibitive).  We inject a tiny tree.
        with patch("messagechain.cli._collect_private_key", return_value=fake_priv), \
             patch("messagechain.identity.identity.MERKLE_TREE_HEIGHT", _TREE_HEIGHT), \
             patch("messagechain.config.MERKLE_TREE_HEIGHT", _TREE_HEIGHT), \
             redirect_stdout(buf):
            cmd_account(args)

        out = buf.getvalue()
        self.assertIn("Signatures remaining", out)
        # 32 total leaves, 0 used — should report 32 / 32, 0% used.
        self.assertIn("32", out)
        self.assertIn("0", out)
        self.assertIn("%", out)


if __name__ == "__main__":
    unittest.main()
