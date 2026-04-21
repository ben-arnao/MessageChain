"""Strict-by-default behaviour of load_checkpoints_file.

A node that silently starts without weak-subjectivity anchors is
vulnerable to long-range PoS attacks.  The default must therefore be
strict: missing or malformed checkpoint files raise instead of being
silently swallowed.  Callers that deliberately tolerate missing files
(tests, ephemeral dev nodes) must opt out with strict=False.
"""

import json
import os
import tempfile
import unittest

from messagechain.consensus.checkpoint import load_checkpoints_file


class TestCheckpointStrictDefault(unittest.TestCase):
    def test_missing_file_raises_by_default(self):
        # No strict kwarg → must raise.  A silent empty list would let a
        # fresh node sync without an anchor.
        with self.assertRaises((FileNotFoundError, ValueError)):
            load_checkpoints_file("/nonexistent/path/cp.json")

    def test_explicit_permissive_missing_file_returns_empty(self):
        # Explicit opt-out stays available for test fixtures and
        # ephemeral dev nodes.
        result = load_checkpoints_file(
            "/nonexistent/path/cp.json", strict=False,
        )
        self.assertEqual(result, [])

    def test_malformed_json_raises_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "checkpoints.json")
            with open(path, "w") as f:
                f.write("{{{ not valid json")
            with self.assertRaises((json.JSONDecodeError, ValueError)):
                load_checkpoints_file(path)


if __name__ == "__main__":
    unittest.main()
