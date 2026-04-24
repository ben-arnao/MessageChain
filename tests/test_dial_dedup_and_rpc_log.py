"""Dial dedup + RPC clean-close log-level demotion.

Two followups on the 2026-04-24 P2P resiliency work:

1. On live mainnet after the ghost-peer + maintenance-loop fix, v1
   showed TWO inbound entries from v2 (different ephemeral ports) for
   the same remote validator.  Root cause: startup seed loop and the
   maintenance tick can both race a dial for the same (host, port)
   before either completes — the `self.peers[addr].is_connected` guard
   checks state but not "already dialing".  Fix: track an in-flight
   set and short-circuit re-entry.

2. The RPC handler logs `RPC error: 0 bytes read on a total of 4
   expected bytes` at ERROR every time a TCP probe (GCP health check)
   opens and closes without sending the 4-byte length prefix.  Fills
   the journal and masks real errors during incident triage.  Fix:
   clean close before any bytes arrive is a normal client termination,
   not an error — demote to DEBUG.  All other RPC exceptions stay ERROR.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import messagechain.config as cfg


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _mk_server(data_dir: str, seed_nodes=None):
    import server as server_mod
    s = server_mod.Server(
        p2p_port=29880, rpc_port=29881, seed_nodes=seed_nodes or [],
        data_dir=data_dir,
    )
    return s


class TestConcurrentDialDedup(unittest.TestCase):
    """A second `_connect_to_peer(host, port)` issued while the first
    call is still inside asyncio.open_connection must short-circuit —
    otherwise the seed-startup loop and the maintenance tick race and
    leave duplicate TCP sockets in self.peers."""

    def test_second_call_noops_while_first_is_in_flight(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            open_calls = 0
            first_started = asyncio.Event()
            allow_open_to_complete = asyncio.Event()

            async def fake_open_connection(host, port, **kwargs):
                nonlocal open_calls
                open_calls += 1
                first_started.set()
                await allow_open_to_complete.wait()
                reader = MagicMock()
                writer = MagicMock()
                writer.close = MagicMock()
                writer.get_extra_info = lambda key: None
                writer.write = MagicMock()
                writer.drain = AsyncMock()
                return reader, writer

            async def drive():
                with patch("asyncio.open_connection",
                           side_effect=fake_open_connection), \
                     patch("server.read_message",
                           new=AsyncMock(return_value=None)), \
                     patch("server.write_message",
                           new=AsyncMock()), \
                     patch.object(cfg, "P2P_TLS_ENABLED", False):
                    t1 = asyncio.create_task(s._connect_to_peer("10.0.0.5", 19333))
                    await first_started.wait()
                    # Second dial kicked off while first is still inside
                    # asyncio.open_connection (hasn't set self.peers[addr]
                    # yet).  With the dedup guard this must no-op.
                    t2 = asyncio.create_task(s._connect_to_peer("10.0.0.5", 19333))
                    # Yield to let t2 proceed through its early-return check.
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)
                    allow_open_to_complete.set()
                    await asyncio.gather(t1, t2)

            _run(drive())
            self.assertEqual(
                open_calls, 1,
                f"expected exactly 1 open_connection call (dedup), got {open_calls}",
            )


class TestRpcCleanCloseLogsAtDebug(unittest.TestCase):
    """A TCP probe that opens and closes without sending the 4-byte
    length prefix is a normal client termination, not an error.  The
    RPC handler must log this at DEBUG, not ERROR, so the journal
    stays readable during incident triage."""

    def test_incomplete_read_of_length_prefix_is_debug(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            # Reader that raises IncompleteReadError before any bytes
            # arrive — exactly what a probe close looks like.
            reader = MagicMock()

            async def _bad_read(n):
                raise asyncio.IncompleteReadError(partial=b"", expected=n)

            reader.readexactly = _bad_read

            writer = MagicMock()
            writer.close = MagicMock()
            writer.get_extra_info = lambda key: ("10.0.0.42", 50000) if key == "peername" else None
            writer.write = MagicMock()
            writer.drain = AsyncMock()

            async def drive():
                with patch.object(s, "rpc_rate_limiter") as rl:
                    rl.check.return_value = True
                    with self.assertLogs("messagechain.server", level="DEBUG") as cap:
                        await s._handle_rpc_connection(reader, writer)
                return cap

            cap = _run(drive())
            # No ERROR messages from the clean close.
            errors = [r for r in cap.records if r.levelname == "ERROR"]
            self.assertEqual(
                errors, [],
                f"a clean probe-close must not log at ERROR; got: "
                f"{[r.getMessage() for r in errors]}",
            )

    def test_real_rpc_error_still_logs_at_error(self):
        """Guardrail: the demotion must be targeted.  A malformed
        payload (e.g. body readexactly fails mid-stream) is a real
        error and must stay at ERROR."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            # First readexactly (length prefix) succeeds with a valid
            # 4-byte length; second (body) raises a non-Incomplete
            # exception that surfaces as a true failure.
            state = {"call": 0}
            import struct as _struct

            async def _read(n):
                state["call"] += 1
                if state["call"] == 1:
                    return _struct.pack(">I", 10)  # claim 10-byte body
                raise ConnectionResetError("wire went away mid-body")

            reader = MagicMock()
            reader.readexactly = _read

            writer = MagicMock()
            writer.close = MagicMock()
            writer.get_extra_info = lambda key: ("10.0.0.43", 50001) if key == "peername" else None
            writer.write = MagicMock()
            writer.drain = AsyncMock()

            async def drive():
                with patch.object(s, "rpc_rate_limiter") as rl:
                    rl.check.return_value = True
                    with self.assertLogs("messagechain.server", level="DEBUG") as cap:
                        await s._handle_rpc_connection(reader, writer)
                return cap

            cap = _run(drive())
            errors = [r for r in cap.records if r.levelname == "ERROR"]
            self.assertTrue(
                errors,
                "a ConnectionResetError mid-body IS a real RPC failure "
                "and must still log at ERROR",
            )


if __name__ == "__main__":
    unittest.main()
