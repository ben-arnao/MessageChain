"""Tests for the checkpoint cutter RPC + CLI.

The cutter is the operator-side tool that turns a running node's current
state into a signed-by-release-channel `WeakSubjectivityCheckpoint` JSON
object.  Nothing here touches consensus — it's a read-only RPC field +
a CLI subcommand that pipes through `load_checkpoints_file`.

Scope (TDD-first):
  1. get_chain_info exposes state_root (hex string, 32 bytes).
  2. A new get_checkpoint_at_height RPC returns (block_number, block_hash,
     state_root) for any in-chain height — needed for --height.
  3. Cutting at tip round-trips through load_checkpoints_file.
  4. Cutting at a specific (non-tip) height round-trips.
  5. --append mode deduplicates by block_number.
  6. Stdout mode emits a single JSON object (not wrapped in an array).
  7. A checkpoints.json produced by the cutter unblocks a node whose
     height would otherwise trip the REQUIRE_CHECKPOINTS guard.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.consensus.checkpoint import (
    WeakSubjectivityCheckpoint,
    load_checkpoints_file,
    validate_checkpoint,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _make_chain(num_blocks: int = 3):
    """Build a small chain with `num_blocks` proposer-produced blocks."""
    chain = Blockchain()
    alice = Entity.create(b"alice_cutter" + b"\x00" * 20)
    chain.initialize_genesis(alice)
    consensus = ProofOfStake()
    for _ in range(num_blocks):
        block = chain.propose_block(consensus, alice, [])
        ok, reason = chain.add_block(block)
        assert ok, f"add_block failed: {reason}"
    return chain, alice


# ─── 1. get_chain_info RPC exposes state_root ─────────────────────────

class TestGetChainInfoExposesStateRoot(unittest.TestCase):
    """The RPC surface must include state_root so a cutter (or any
    external verifier) can build a checkpoint without scraping an
    internal blockchain object."""

    def test_state_root_field_is_present(self):
        chain, _ = _make_chain()
        info = chain.get_chain_info()
        self.assertIn("state_root", info)

    def test_state_root_is_hex_of_correct_length(self):
        chain, _ = _make_chain()
        info = chain.get_chain_info()
        state_root_hex = info["state_root"]
        self.assertIsInstance(state_root_hex, str)
        # 32-byte state root → 64 hex characters.
        self.assertEqual(len(state_root_hex), 64)
        # Round-trip through bytes.fromhex to confirm it's valid hex.
        raw = bytes.fromhex(state_root_hex)
        self.assertEqual(len(raw), 32)

    def test_state_root_matches_latest_block_header(self):
        chain, _ = _make_chain()
        info = chain.get_chain_info()
        expected = chain.chain[-1].header.state_root.hex()
        self.assertEqual(info["state_root"], expected)

    def test_empty_chain_state_root_is_none(self):
        """Before genesis, state_root is None — not 64 zero bytes.
        (Consistent with existing latest_block_hash handling.)"""
        chain = Blockchain()
        info = chain.get_chain_info()
        self.assertIsNone(info["state_root"])


# ─── 2. get_checkpoint_at_height RPC ──────────────────────────────────

class TestGetCheckpointAtHeightRPC(unittest.TestCase):
    """A dedicated minimal RPC that returns exactly the fields a
    checkpoint needs, for any in-chain height.  Intentionally narrower
    than get_block_by_hash — only (block_number, block_hash, state_root)
    so the wire payload stays tiny."""

    def setUp(self):
        from server import Server
        self.chain, _ = _make_chain(num_blocks=4)
        self.server = Server.__new__(Server)
        self.server.blockchain = self.chain

    def test_returns_block_hash_and_state_root(self):
        from server import Server
        result = Server._rpc_get_checkpoint_at_height(
            self.server, {"height": 2},
        )
        self.assertTrue(result["ok"])
        data = result["result"]
        self.assertEqual(data["block_number"], 2)
        self.assertEqual(data["block_hash"], self.chain.get_block(2).block_hash.hex())
        self.assertEqual(data["state_root"], self.chain.get_block(2).header.state_root.hex())

    def test_height_beyond_tip_returns_error(self):
        from server import Server
        result = Server._rpc_get_checkpoint_at_height(
            self.server, {"height": 9999},
        )
        self.assertFalse(result["ok"])

    def test_negative_height_returns_error(self):
        from server import Server
        result = Server._rpc_get_checkpoint_at_height(
            self.server, {"height": -1},
        )
        self.assertFalse(result["ok"])

    def test_missing_height_returns_error(self):
        from server import Server
        result = Server._rpc_get_checkpoint_at_height(self.server, {})
        self.assertFalse(result["ok"])


# ─── 3. & 4. Cut at tip / at specific height round-trips through loader ─

class _FakeRPC:
    """Dispatch table standing in for a running server's _process_rpc.
    Tests inject this via `patch('messagechain.cli.rpc_call', ...)`."""

    def __init__(self, chain):
        self.chain = chain

    def __call__(self, host, port, method, params):
        from server import Server
        fake_server = Server.__new__(Server)
        fake_server.blockchain = self.chain
        if method == "get_chain_info":
            info = self.chain.get_chain_info()
            # Production adds sync_status here; tests don't need it.
            return {"ok": True, "result": info}
        elif method == "get_checkpoint_at_height":
            return Server._rpc_get_checkpoint_at_height(fake_server, params)
        else:
            return {"ok": False, "error": f"unknown method: {method}"}


class TestCutCheckpointAtTipRoundTrip(unittest.TestCase):
    """Cutting at tip then feeding the output file through
    load_checkpoints_file must produce a checkpoint that validates
    against the same chain."""

    def test_cut_tip_to_file_validates(self):
        from messagechain.cli import cmd_cut_checkpoint
        chain, _ = _make_chain(num_blocks=3)
        tip_height = chain.height - 1

        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "checkpoints.json")
            args = _mk_args(server="127.0.0.1:9334", out=out)
            with patch("client.rpc_call", _FakeRPC(chain)):
                cmd_cut_checkpoint(args)

            cps = load_checkpoints_file(out, strict=True)
            self.assertEqual(len(cps), 1)
            cp = cps[0]
            self.assertEqual(cp.block_number, tip_height)
            self.assertTrue(validate_checkpoint(chain, cp))


class TestCutCheckpointAtHeightRoundTrip(unittest.TestCase):
    """Cutting at a specific (non-tip) height round-trips through
    load_checkpoints_file and matches the chain at that height."""

    def test_cut_at_specific_height(self):
        from messagechain.cli import cmd_cut_checkpoint
        chain, _ = _make_chain(num_blocks=5)
        target_height = 2  # Not the tip.

        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "checkpoints.json")
            args = _mk_args(
                server="127.0.0.1:9334", height=target_height, out=out,
            )
            with patch("client.rpc_call", _FakeRPC(chain)):
                cmd_cut_checkpoint(args)

            cps = load_checkpoints_file(out, strict=True)
            self.assertEqual(len(cps), 1)
            cp = cps[0]
            self.assertEqual(cp.block_number, target_height)
            self.assertTrue(validate_checkpoint(chain, cp))


# ─── 5. --append deduplicates by block_number ─────────────────────────

class TestAppendModeDedupes(unittest.TestCase):
    """Running the cutter twice at the same height with --append must
    leave the file with one entry, not two."""

    def test_append_same_height_twice_dedupes(self):
        from messagechain.cli import cmd_cut_checkpoint
        chain, _ = _make_chain(num_blocks=4)
        target_height = chain.height - 1

        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "checkpoints.json")
            args = _mk_args(
                server="127.0.0.1:9334", height=target_height, out=out,
                append=True,
            )
            with patch("client.rpc_call", _FakeRPC(chain)):
                cmd_cut_checkpoint(args)
                cmd_cut_checkpoint(args)  # second run — should dedupe.

            cps = load_checkpoints_file(out, strict=True)
            self.assertEqual(len(cps), 1)
            self.assertEqual(cps[0].block_number, target_height)

    def test_append_different_heights_keeps_both(self):
        from messagechain.cli import cmd_cut_checkpoint
        chain, _ = _make_chain(num_blocks=5)

        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "checkpoints.json")
            with patch("client.rpc_call", _FakeRPC(chain)):
                cmd_cut_checkpoint(_mk_args(
                    server="127.0.0.1:9334", height=1, out=out, append=True,
                ))
                cmd_cut_checkpoint(_mk_args(
                    server="127.0.0.1:9334", height=3, out=out, append=True,
                ))

            cps = load_checkpoints_file(out, strict=True)
            heights = sorted(cp.block_number for cp in cps)
            self.assertEqual(heights, [1, 3])


# ─── 6. Stdout mode — single object, not an array ─────────────────────

class TestStdoutModeSingleObject(unittest.TestCase):
    """Without --out, the cutter prints one JSON object on stdout (not
    wrapped in an array).  Keeps the pipe-friendly form distinct from
    the file form, which must be an array to satisfy load_checkpoints_file."""

    def test_stdout_is_single_object(self):
        from messagechain.cli import cmd_cut_checkpoint
        chain, _ = _make_chain(num_blocks=2)
        tip = chain.height - 1

        buf = io.StringIO()
        with patch("client.rpc_call", _FakeRPC(chain)):
            with redirect_stdout(buf):
                cmd_cut_checkpoint(_mk_args(server="127.0.0.1:9334"))

        parsed = json.loads(buf.getvalue().strip())
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed["block_number"], tip)
        self.assertIn("block_hash", parsed)
        self.assertIn("state_root", parsed)


# ─── 7. Cutter output unblocks a strict-mode node ─────────────────────

class TestCutterOutputSatisfiesStrictLoader(unittest.TestCase):
    """Demonstrates end-to-end: the file the cutter writes is accepted
    by load_checkpoints_file(..., strict=True), which is the gate a
    production node hits when REQUIRE_CHECKPOINTS=True and the chain
    is past the bootstrap window."""

    def test_cutter_output_accepted_in_strict_mode(self):
        from messagechain.cli import cmd_cut_checkpoint
        chain, _ = _make_chain(num_blocks=3)

        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "checkpoints.json")
            with patch("client.rpc_call", _FakeRPC(chain)):
                cmd_cut_checkpoint(_mk_args(server="127.0.0.1:9334", out=out))

            # strict=True is what a production node uses when
            # REQUIRE_CHECKPOINTS=True — this must not raise.
            cps = load_checkpoints_file(out, strict=True)
            self.assertGreaterEqual(len(cps), 1)
            # And every checkpoint must validate against the chain.
            for cp in cps:
                self.assertTrue(validate_checkpoint(chain, cp))


# ─── Helpers ──────────────────────────────────────────────────────────

def _mk_args(*, server, height=None, out=None, append=False):
    """Build a fake argparse.Namespace the CLI handler expects."""
    import argparse
    return argparse.Namespace(
        command="cut-checkpoint", verbose=False,
        server=server, height=height, out=out, append=append,
    )


# ─── 8. Failure modes propagate non-zero exit ─────────────────────────

class TestCutCheckpointFailureExits(unittest.TestCase):
    """RPC failure (unreachable server, unknown error) must exit non-zero
    so scripts don't silently accept a stale checkpoint file."""

    def test_rpc_failure_exits_nonzero(self):
        from messagechain.cli import cmd_cut_checkpoint
        def _boom(host, port, method, params):
            return {"ok": False, "error": "could not connect"}
        with patch("client.rpc_call", _boom):
            with self.assertRaises(SystemExit) as ctx:
                cmd_cut_checkpoint(_mk_args(server="127.0.0.1:9334"))
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
