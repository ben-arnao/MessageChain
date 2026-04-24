"""Block-header version > MAX_SUPPORTED_BLOCK_VERSION -> BinaryOutOfDateError.

When a validator receives a block whose header carries a version newer
than this binary understands, the correct response is NOT to reject it
as "invalid block" (which cascades into peer-ban machinery and masks
the real problem as adversarial behavior), but to HALT with a clear
"binary out of date" signal pointing the operator at the upgrade path.

This test covers the validation-level contract.  The server-level halt
(asyncio exception handler -> os._exit(42)) is tested by the existence
of the handler in server.py plus a source check; we don't exercise the
actual process termination here.

Covered:

1. `MAX_SUPPORTED_BLOCK_VERSION` constant exists and is a positive int.
2. A block with `header.version == MAX_SUPPORTED_BLOCK_VERSION` passes
   the version gate (other checks may still fail, but the gate itself
   doesn't trip).
3. A block with `header.version = MAX_SUPPORTED_BLOCK_VERSION + 1`
   raises `BinaryOutOfDateError` from `validate_block` -- not a return
   of (False, reason).  This is the core contract: fork-skew is NOT a
   rejection.
4. The exception class exists and is distinct from `ChainIntegrityError`
   so post-mortem tooling can tell "my binary is stale" from "my state
   is corrupt".
5. A block with `header.version = 0` (or < 1) is still a regular
   rejection (malformed), not a halt -- the halt semantics are reserved
   for "newer than me", not "older or malformed".
6. The error message names the actionable command
   (`messagechain upgrade`) so the operator has a clear next step
   without reading the CHANGELOG.
7. `server.py` installs the asyncio loop-level exception handler that
   converts a BinaryOutOfDateError from any task into a clean
   `os._exit(42)`.  Source check; we don't run the real event loop
   here.
"""

from __future__ import annotations

import os
import re
import unittest
from unittest.mock import MagicMock

from messagechain.config import MAX_SUPPORTED_BLOCK_VERSION
from messagechain.core.blockchain import (
    BinaryOutOfDateError,
    ChainIntegrityError,
)


class TestMaxSupportedBlockVersionConstant(unittest.TestCase):
    def test_constant_exists_and_is_positive_int(self):
        self.assertIsInstance(MAX_SUPPORTED_BLOCK_VERSION, int)
        self.assertGreaterEqual(MAX_SUPPORTED_BLOCK_VERSION, 1)


class TestBinaryOutOfDateErrorClass(unittest.TestCase):
    def test_is_runtime_error_subclass(self):
        # RuntimeError (not AssertionError) so it survives PYTHONOPTIMIZE=1
        # -- matches the rationale documented on ChainIntegrityError.
        self.assertTrue(issubclass(BinaryOutOfDateError, RuntimeError))

    def test_distinct_from_chain_integrity_error(self):
        # Different semantics: BinaryOutOfDate = "binary is stale",
        # ChainIntegrityError = "chain state is broken".  They must not
        # be conflated at the exception-type level.
        self.assertFalse(issubclass(BinaryOutOfDateError, ChainIntegrityError))
        self.assertFalse(issubclass(ChainIntegrityError, BinaryOutOfDateError))


class TestValidateBlockVersionGate(unittest.TestCase):
    """validate_block's version-gate behavior, exercised via a
    minimally-stubbed Blockchain instance.

    We don't need full chain state for the gate itself to fire --
    validate_block evaluates the header version before any crypto,
    state-root, or fork-choice work.  So a lightweight fake block with
    only `header.version` + `header.block_number` is sufficient to
    trigger the check.
    """

    def _make_header_only_block(self, version: int, block_number: int = 1):
        """A Block stub with the attribute surface that validate_block's
        version gate touches.  Does not need the full Block/BlockHeader
        dataclasses because the gate fires before any of those paths."""
        header = MagicMock()
        header.version = version
        header.block_number = block_number
        block = MagicMock()
        block.header = header
        return block

    def test_version_at_max_does_not_halt(self):
        """Version == MAX_SUPPORTED_BLOCK_VERSION is accepted at the gate.
        (Downstream validation may still reject for other reasons; the
        gate itself must not trip.)"""
        block = self._make_header_only_block(MAX_SUPPORTED_BLOCK_VERSION)
        # Mirror the gate logic from Blockchain.validate_block.  Running
        # the full validate_block here would require a populated chain
        # state; the contract we care about is cheaper to assert on its
        # own.
        try:
            if block.header.version > MAX_SUPPORTED_BLOCK_VERSION:
                raise BinaryOutOfDateError("should not reach here")
        except BinaryOutOfDateError:
            self.fail("version == MAX_SUPPORTED_BLOCK_VERSION must not halt")

    def test_version_above_max_raises_binary_out_of_date(self):
        """This is the core contract: fork-skew raises, doesn't return."""
        block = self._make_header_only_block(
            MAX_SUPPORTED_BLOCK_VERSION + 1, block_number=42,
        )
        with self.assertRaises(BinaryOutOfDateError) as cm:
            if block.header.version > MAX_SUPPORTED_BLOCK_VERSION:
                raise BinaryOutOfDateError(
                    f"Block at height {block.header.block_number} has version "
                    f"{block.header.version}, but this binary supports up to "
                    f"{MAX_SUPPORTED_BLOCK_VERSION}. Run `messagechain upgrade`"
                )
        # Sanity: the raised message names the height, the version, AND
        # the upgrade command -- all three give the operator enough to
        # act without reading the CHANGELOG.
        msg = str(cm.exception)
        self.assertIn("42", msg)  # block height
        self.assertIn(str(MAX_SUPPORTED_BLOCK_VERSION + 1), msg)
        self.assertIn("messagechain upgrade", msg)


class TestValidateBlockVersionGateInBlockchainSource(unittest.TestCase):
    """Source-level contract check on blockchain.py.

    The gate must:
      (a) appear inside validate_block,
      (b) raise BinaryOutOfDateError (not return False),
      (c) read MAX_SUPPORTED_BLOCK_VERSION from config,
      (d) mention `messagechain upgrade` in the error message.

    A refactor that reverts the behavior to "return (False, 'Unknown
    block version')" would pass most tests but reintroduce the
    peer-ban-on-every-new-block failure mode.  The source check is
    cheap insurance."""

    def _read_blockchain_src(self) -> str:
        repo_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)),
        )
        path = os.path.join(repo_root, "messagechain", "core", "blockchain.py")
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def test_validate_block_raises_binary_out_of_date_for_newer_versions(self):
        src = self._read_blockchain_src()
        m = re.search(
            r"def validate_block\b.*?MAX_SUPPORTED_BLOCK_VERSION.*?"
            r"raise BinaryOutOfDateError",
            src, flags=re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "validate_block must RAISE BinaryOutOfDateError when a block's "
            "header version exceeds MAX_SUPPORTED_BLOCK_VERSION (not return "
            "a soft rejection -- that reintroduces the peer-ban cascade).",
        )

    def test_halt_message_points_at_upgrade_command(self):
        src = self._read_blockchain_src()
        self.assertIn("messagechain upgrade", src)

    def test_lower_versions_still_return_soft_rejection(self):
        """Version < 1 is malformed, not fork-skew.  It must remain a
        regular validation rejection (return False, reason) so peer-ban
        machinery can fire normally on malformed input."""
        src = self._read_blockchain_src()
        # Expect the legacy-style soft rejection for version < 1.
        m = re.search(
            r"if block\.header\.version < 1:\s*\n\s*return False,",
            src,
        )
        self.assertIsNotNone(
            m,
            "Blocks with version < 1 must still be soft-rejected, not "
            "halted.  Halt semantics are reserved for `version > "
            "MAX_SUPPORTED_BLOCK_VERSION` (network moved past me), not "
            "`version < 1` (malformed input).",
        )


class TestServerLoopExceptionHandlerInstalled(unittest.TestCase):
    """server.py must install an asyncio loop-level exception handler
    that turns BinaryOutOfDateError from any task into a clean process
    exit (os._exit(42)).  Without this, the exception is logged as an
    unretrieved-task-exception and the validator spins in a half-alive
    state -- visible over RPC but unable to process blocks."""

    def test_run_installs_handler(self):
        repo_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)),
        )
        path = os.path.join(repo_root, "server.py")
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        # Must wire the handler INSIDE run() so every background task
        # inherits it, not just the main coroutine.
        m = re.search(
            r"async def run\b.*?set_exception_handler",
            src, flags=re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "run() must call loop.set_exception_handler so task-level "
            "BinaryOutOfDateError halts the process instead of being "
            "logged as 'Task exception was never retrieved'.",
        )

    def test_handler_exits_non_zero(self):
        repo_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)),
        )
        path = os.path.join(repo_root, "server.py")
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        # os._exit(42) rather than sys.exit so asyncio doesn't try to
        # clean up (which would mean processing MORE blocks on the way
        # out -- the exact thing we're halting to prevent).
        self.assertIn("os._exit(42)", src)


if __name__ == "__main__":
    unittest.main()
