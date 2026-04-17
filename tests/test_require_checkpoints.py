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
        # verify the production source still declares True.
        import ast
        import messagechain.config as _cfg_mod
        src_path = _cfg_mod.__file__
        with open(src_path) as f:
            tree = ast.parse(f.read())
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "REQUIRE_CHECKPOINTS":
                        # The default value in source must be True
                        self.assertIsInstance(node.value, ast.Constant)
                        self.assertTrue(node.value.value)
                        found = True
        self.assertTrue(found, "REQUIRE_CHECKPOINTS not found in config.py source")

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
