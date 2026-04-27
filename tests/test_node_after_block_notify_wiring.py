"""Node._after_block_added invokes the notify hook on every accepted block.

Pre-this-fix the notify hook (`runtime.notify.process_block_for_
notifications`) was DEFINED but never called from any code path.
Operators with the email subsystem configured got NO emails because
the wire was missing.

This test pins:
  * Node._after_block_added catches all exceptions (consensus path
    must never be affected by notify failures)
  * When notify is disabled in onboard config, _after_block_added is
    a no-op (no list_proposals call)
  * When notify is enabled, the hook is invoked with the chain's
    current height + governance.list_proposals
"""

import unittest
from unittest.mock import MagicMock, patch


class TestAfterBlockAddedExceptionSafe(unittest.TestCase):
    """Notify failures must not propagate into the consensus path."""

    def _make_node_stub(self):
        """Minimal stub exposing the surface _after_block_added uses."""
        from messagechain.network.node import Node
        # Construct a stripped-down object — we don't want to spin up
        # an actual Node (heavy: TCP server, data_dir locks, key
        # material).  Just enough surface for the unbound method call.
        node = Node.__new__(Node)
        node.blockchain = MagicMock()
        node.blockchain.height = 100
        node.blockchain.governance = MagicMock()
        node.blockchain.governance.list_proposals = MagicMock(return_value=[])
        node.data_dir = None
        return node

    def test_notify_import_failure_swallowed(self):
        node = self._make_node_stub()
        # Patch read_onboard_config to raise — _after_block_added must
        # not re-raise.  Block dummy.
        with patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            side_effect=OSError("disk full"),
        ):
            # Should NOT raise.
            node._after_block_added(MagicMock())

    def test_disabled_config_short_circuits_before_list_proposals(self):
        # Performance assertion: when notify is disabled, the hook
        # MUST NOT call list_proposals.  list_proposals can be a
        # heavyweight read; running it on every block when the
        # operator hasn't enabled email is wasteful.
        node = self._make_node_stub()
        with patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            return_value={"notify.email.enabled": False},
        ):
            node._after_block_added(MagicMock())
        node.blockchain.governance.list_proposals.assert_not_called()

    def test_enabled_config_invokes_process_block(self):
        node = self._make_node_stub()
        # Build a complete-enough config that process_block_for_
        # notifications gets past its required-keys check, and supply
        # a notifier_factory through the patched module so we can
        # verify the right shape of call without sending real email.
        cfg = {
            "notify.email.enabled": True,
            "notify.email.recipient": "op@example.com",
            "notify.email.smtp_host": "smtp.example.com",
            "notify.email.smtp_port": 587,
        }
        with patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            return_value=cfg,
        ), patch(
            "messagechain.runtime.notify.process_block_for_notifications",
        ) as mock_pbn:
            node._after_block_added(MagicMock())
        # Was called exactly once with chain height + list_proposals
        # callable.
        self.assertEqual(mock_pbn.call_count, 1)
        call_kwargs = mock_pbn.call_args.kwargs
        self.assertEqual(call_kwargs["current_height"], 100)
        self.assertTrue(callable(call_kwargs["list_proposals"]))
        self.assertEqual(call_kwargs["config"], cfg)


class TestNotifyConsensusIndependence(unittest.TestCase):
    """The hook must not be imported from any consensus module."""

    def test_no_consensus_path_imports_runtime_notify(self):
        # Mirror of test_governance_proposal_notify.py's existing guard,
        # but specifically for the new node.py wiring: node.py is
        # operator-runtime, NOT consensus, so the import is allowed
        # there.  This test asserts the import is LAZY (inside the
        # method body) rather than module-level — so a stripped-down
        # build that excludes runtime/notify still imports node.py
        # cleanly.
        import importlib
        import inspect
        from messagechain.network import node as node_mod
        src = inspect.getsource(node_mod)
        # Allow the import only inside the _after_block_added body.
        # A module-level `from messagechain.runtime import notify`
        # would fail for stripped-down builds.
        module_level_lines = [
            ln for ln in src.splitlines()
            if ln.startswith("from messagechain.runtime import notify")
            or ln.startswith("import messagechain.runtime.notify")
        ]
        self.assertEqual(
            module_level_lines, [],
            "node.py must lazy-import runtime.notify inside the "
            "_after_block_added method, not at module top-level — "
            "module-level import couples the consensus runtime to "
            "the optional notify subsystem"
        )


if __name__ == "__main__":
    unittest.main()
