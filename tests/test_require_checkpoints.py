"""Tests for strict checkpoint requirement in production mode.

Security: A new node without checkpoints is vulnerable to long-range PoS
attacks. Production/mainnet mode must fail loudly if no checkpoints are
available. Devnet/testnet mode can remain lenient.
"""

import json
import os
import tempfile
import unittest

import messagechain.config as config
from messagechain.consensus.checkpoint import (
    WeakSubjectivityCheckpoint,
    load_checkpoints_file,
)


class TestRequireCheckpointsConfig(unittest.TestCase):
    """REQUIRE_CHECKPOINTS defaults to True (secure by default)."""

    def test_default_is_true(self):
        # tests/__init__.py overrides to False for test convenience;
        # verify the production source defaults to True when the env var
        # MESSAGECHAIN_REQUIRE_CHECKPOINTS is unset.
        import os
        import subprocess
        import sys
        env = {k: v for k, v in os.environ.items()
               if k != "MESSAGECHAIN_REQUIRE_CHECKPOINTS"}
        # Run a subprocess with the env var unset and no tests/__init__.py
        # side effects (invoke messagechain.config directly).
        result = subprocess.run(
            [sys.executable, "-c",
             "import messagechain.config as c; print(c.REQUIRE_CHECKPOINTS)"],
            env=env, capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), "True")

    def test_tests_override_to_false(self):
        # Confirm that the test harness overrides to False so tests don't
        # need checkpoint files.
        self.assertFalse(config.REQUIRE_CHECKPOINTS)


class TestStrictCheckpointLoading(unittest.TestCase):
    """Production mode (REQUIRE_CHECKPOINTS=True) must raise on empty results."""

    def test_missing_file_strict_raises(self):
        """strict=True + missing file => ValueError."""
        with self.assertRaises(ValueError) as ctx:
            load_checkpoints_file("/nonexistent/checkpoints.json", strict=True)
        self.assertIn("vulnerable", str(ctx.exception).lower())

    def test_empty_array_strict_raises(self):
        """strict=True + file contains [] => ValueError."""
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "checkpoints.json")
            with open(path, "w") as f:
                json.dump([], f)
            with self.assertRaises(ValueError) as ctx:
                load_checkpoints_file(path, strict=True)
            self.assertIn("empty", str(ctx.exception).lower())

    def test_valid_checkpoints_strict_succeeds(self):
        """strict=True + valid checkpoints => loads normally."""
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "checkpoints.json")
            cp = WeakSubjectivityCheckpoint(
                block_number=1000,
                block_hash=b"\xaa" * 32,
                state_root=b"\xbb" * 32,
            )
            with open(path, "w") as f:
                json.dump([cp.serialize()], f)
            result = load_checkpoints_file(path, strict=True)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].block_number, 1000)


class TestLenientCheckpointLoading(unittest.TestCase):
    """Devnet mode (strict=False) remains lenient — empty list on failure."""

    def test_missing_file_lenient_returns_empty(self):
        result = load_checkpoints_file("/nonexistent/checkpoints.json", strict=False)
        self.assertEqual(result, [])

    def test_empty_array_lenient_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "checkpoints.json")
            with open(path, "w") as f:
                json.dump([], f)
            result = load_checkpoints_file(path, strict=False)
            self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
