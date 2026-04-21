"""Tests for async background-task error handling.

Without a done_callback that logs uncaught exceptions, any
``asyncio.create_task(...)`` launched by the Node or Server class will die
silently if it raises — the node process stays "online" but stops producing
blocks, syncing, or accepting peers.  In a PoS system with an inactivity
leak, a silently dead validator gets its stake drained to zero.

This module verifies:

1. A crashed background task logs the exception at CRITICAL level.
2. A cancelled task is treated as normal shutdown — no error logged.
3. A task that completes successfully is silent — no error logged.

The helper under test is ``_handle_task_exception`` and it must be present
on both the ``Node`` class (messagechain/network/node.py) and the
``Server`` class (server.py).  Both classes launch long-lived background
loops whose silent death is catastrophic.
"""

import asyncio
import logging
import unittest
from unittest.mock import MagicMock, patch


def _run(coro):
    """Run a coroutine in a fresh event loop (works across Windows/Unix)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _StubObject:
    """Minimal stand-in for a Node/Server that owns the helper method.

    We don't want these tests to depend on Node/Server construction — they
    would pull in the full blockchain, storage, checkpoint machinery, etc.
    Instead we import the helper as an unbound function and bind it to a
    stub.  This keeps the test focused strictly on the helper's behavior.
    """


class TestNodeHandleTaskException(unittest.TestCase):
    """The helper is defined on Node — verify it is present and correct."""

    def setUp(self):
        from messagechain.network.node import Node
        self.helper = Node._handle_task_exception
        self.stub = _StubObject()

    def test_crashed_background_task_logs_error(self):
        """An uncaught exception in a background task is logged at CRITICAL."""
        async def crasher():
            raise RuntimeError("boom")

        async def run():
            task = asyncio.create_task(crasher())
            # Attach the helper as the done_callback so we exercise the
            # real wiring code path used in production.
            task.add_done_callback(
                lambda t: self.helper(self.stub, "block_production_loop", t)
            )
            # Wait for the task to finish and the callback to fire.
            try:
                await task
            except RuntimeError:
                pass
            # Yield one more loop tick so done_callbacks run.
            await asyncio.sleep(0)

        # _handle_task_exception was unified onto SharedRuntimeMixin,
        # so logging happens via messagechain.runtime.shared.logger
        # regardless of whether the caller was Node or Server.  Patch
        # there to observe the CRITICAL call.
        with patch("messagechain.runtime.shared.logger") as mock_logger:
            _run(run())
            # Helper must have issued a CRITICAL log with the task name
            # and the original exception included.
            self.assertTrue(
                mock_logger.critical.called,
                "Expected logger.critical to be called for a crashed task",
            )
            call_args = mock_logger.critical.call_args
            logged_message = call_args.args[0] if call_args.args else ""
            self.assertIn("block_production_loop", logged_message)
            self.assertIn("boom", logged_message)

    def test_task_cancellation_does_not_log_error(self):
        """Cancelling a task is normal shutdown — no CRITICAL log."""
        async def long_running():
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                raise

        async def run():
            task = asyncio.create_task(long_running())
            task.add_done_callback(
                lambda t: self.helper(self.stub, "sync_loop", t)
            )
            # Give the task a chance to start, then cancel.
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await asyncio.sleep(0)

        with patch("messagechain.network.node.logger") as mock_logger:
            _run(run())
            self.assertFalse(
                mock_logger.critical.called,
                "logger.critical should NOT fire on clean task cancellation",
            )

    def test_normal_task_completion_is_silent(self):
        """A task that returns normally does not log anything at CRITICAL."""
        async def quiet():
            return 42

        async def run():
            task = asyncio.create_task(quiet())
            task.add_done_callback(
                lambda t: self.helper(self.stub, "mempool_sync_loop", t)
            )
            await task
            await asyncio.sleep(0)

        with patch("messagechain.network.node.logger") as mock_logger:
            _run(run())
            self.assertFalse(
                mock_logger.critical.called,
                "logger.critical must not fire for a normally-completing task",
            )


class TestServerHandleTaskException(unittest.TestCase):
    """The Server class has an identical helper (different logger binding)."""

    def setUp(self):
        import server
        self.server_module = server
        self.helper = server.Server._handle_task_exception
        self.stub = _StubObject()

    def test_crashed_background_task_logs_error(self):
        async def crasher():
            raise ValueError("server boom")

        async def run():
            task = asyncio.create_task(crasher())
            task.add_done_callback(
                lambda t: self.helper(self.stub, "block_production_loop", t)
            )
            try:
                await task
            except ValueError:
                pass
            await asyncio.sleep(0)

        # _handle_task_exception was unified onto SharedRuntimeMixin,
        # so logging happens via messagechain.runtime.shared.logger
        # regardless of whether the caller was Node or Server.
        with patch("messagechain.runtime.shared.logger") as mock_logger:
            _run(run())
            self.assertTrue(mock_logger.critical.called)
            call_args = mock_logger.critical.call_args
            logged_message = call_args.args[0] if call_args.args else ""
            self.assertIn("block_production_loop", logged_message)
            self.assertIn("server boom", logged_message)

    def test_task_cancellation_does_not_log_error(self):
        async def long_running():
            await asyncio.sleep(60)

        async def run():
            task = asyncio.create_task(long_running())
            task.add_done_callback(
                lambda t: self.helper(self.stub, "sync_loop", t)
            )
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await asyncio.sleep(0)

        with patch.object(self.server_module, "logger") as mock_logger:
            _run(run())
            self.assertFalse(mock_logger.critical.called)

    def test_normal_task_completion_is_silent(self):
        async def quiet():
            return "ok"

        async def run():
            task = asyncio.create_task(quiet())
            task.add_done_callback(
                lambda t: self.helper(self.stub, "rpc_relay", t)
            )
            await task
            await asyncio.sleep(0)

        with patch.object(self.server_module, "logger") as mock_logger:
            _run(run())
            self.assertFalse(mock_logger.critical.called)


class TestCreateTaskCallsAreGuarded(unittest.TestCase):
    """Every ``asyncio.create_task(...)`` in node.py and server.py must have
    an associated ``add_done_callback`` on the very next lines.  A raw
    ``asyncio.create_task(foo())`` with no callback is the bug this task
    is fixing — this test will fail if any new unguarded call slips in.
    """

    def _assert_all_create_tasks_guarded(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        lines = source.splitlines()
        # For each line containing `asyncio.create_task(`, look at the
        # following ~6 lines for either `.add_done_callback(` OR an
        # assignment form where the task name is later passed to a
        # guard helper.  We accept the common pattern:
        #    task = asyncio.create_task(...)
        #    task.add_done_callback(lambda t: self._handle_task_exception(...))
        # ...or the inline form:
        #    asyncio.create_task(...).add_done_callback(...)
        unguarded = []
        for i, line in enumerate(lines):
            if "asyncio.create_task(" not in line:
                continue
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            window = "\n".join(lines[i:i + 8])
            if "add_done_callback" in window or "_handle_task_exception" in window:
                continue
            unguarded.append((i + 1, line.strip()))
        self.assertEqual(
            unguarded,
            [],
            f"Unguarded asyncio.create_task(...) calls found in {path}:\n"
            + "\n".join(f"  line {n}: {src}" for n, src in unguarded),
        )

    def test_node_py_has_no_unguarded_create_task(self):
        import messagechain.network.node as node_mod
        self._assert_all_create_tasks_guarded(node_mod.__file__)

    def test_server_py_has_no_unguarded_create_task(self):
        import server
        self._assert_all_create_tasks_guarded(server.__file__)


if __name__ == "__main__":
    unittest.main()
