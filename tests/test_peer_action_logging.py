"""PEER_ACTION log line on every mutating RPC.

`_process_rpc` emits a single audit-log line per action method
received from a remote IP. Operators wire this to a GCP
log-based alert policy so they get notified when any peer
submits a tx / stake / governance action against their node.

Read-only methods (get_chain_info, get_peers, etc.) are
intentionally silent -- status-check polling on a validator
would otherwise drown real peer actions in the alert stream.

Covered:

1. Source check: the log line exists in server.py's
   `_process_rpc`, emitted via the module logger, guarded on
   both method-in-action-table and non-empty client_ip. The
   source check is a cheap regression gate against a future
   refactor silently dropping the line -- which would disable
   GCP alerting without any test failing.
2. Action-method whitelist coverage: every method registered
   in `_RPC_METHOD_COST` is an action method, so every one
   of them emits PEER_ACTION. Assertion is indirect (the
   gate uses the dict), but we cover the contract by asserting
   the gate reads from that dict.
"""

from __future__ import annotations

import os
import re
import unittest


def _read_server_src() -> str:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "server.py"), "r", encoding="utf-8") as f:
        return f.read()


class TestPeerActionLoggingInProcessRpc(unittest.TestCase):
    def test_peer_action_line_emitted_in_process_rpc(self):
        src = _read_server_src()
        # The prefix must be exactly "PEER_ACTION" and must appear in
        # the _process_rpc body (before the dispatch if-ladder).
        m = re.search(
            r'def _process_rpc\b.*?PEER_ACTION.*?if method == "submit_transaction"',
            src,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "PEER_ACTION log line must appear inside _process_rpc, "
            "before the dispatch if-ladder. A refactor that moved "
            "the emission elsewhere (or removed it) would silently "
            "disable GCP peer-action alerting.",
        )

    def test_peer_action_line_gated_on_action_method(self):
        src = _read_server_src()
        # The gate must read from _RPC_METHOD_COST (not a hardcoded
        # list) so adding a new action method to the cost table
        # automatically enrolls it in the audit log.
        m = re.search(
            r"if method in _RPC_METHOD_COST and client_ip:\s*\n"
            r'\s*logger\.info\(f["\']PEER_ACTION ',
            src,
        )
        self.assertIsNotNone(
            m,
            "PEER_ACTION emission must be gated on "
            "`method in _RPC_METHOD_COST and client_ip`. Hard-coding "
            "the whitelist would drift from the rate-limiter cost "
            "table -- new action methods would be added to one and "
            "not the other.",
        )

    def test_peer_action_emission_uses_client_ip_and_method(self):
        """The log line format is the contract GCP alerting reads.
        Keeping it stable across refactors prevents silent alert
        breakage."""
        src = _read_server_src()
        # Format: `PEER_ACTION client={client_ip} action={method}`
        self.assertIn("PEER_ACTION client=", src)
        self.assertIn("action=", src)

    def test_cheap_methods_not_in_cost_table(self):
        """Regression gate: if a cheap read method is ever added to
        _RPC_METHOD_COST (even accidentally, e.g. copy-paste), it
        would start emitting PEER_ACTION on every status poll and
        drown real peer actions in the alert stream. Assert the
        dict is tightly scoped to mutating methods."""
        import server
        cost_table = server._RPC_METHOD_COST
        forbidden = {
            "get_chain_info",
            "get_entity",
            "get_peers",
            "get_mempool",
            "get_validators",
            "get_block",
            "status",
            "ping",
        }
        leaked = forbidden & cost_table.keys()
        self.assertFalse(
            leaked,
            f"read-only methods must not be in _RPC_METHOD_COST "
            f"(they would spam the PEER_ACTION audit log): {leaked}",
        )


if __name__ == "__main__":
    unittest.main()
