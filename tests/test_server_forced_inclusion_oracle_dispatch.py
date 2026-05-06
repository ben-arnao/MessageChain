"""Source-level pin: `server.py:_maybe_attest_accepted_block` wires
its forced-inclusion `is_includable` callback through
`Blockchain.validate_forced_includable_tx`, not the message-only
`Blockchain.validate_transaction`.

Twin of the node-side pin at
``tests/test_forced_inclusion_includable_per_kind.py::TestNodeIsIncludableSourcePin``.
The r25 fix wired the dispatcher into ``messagechain/network/node.py``
but the parallel attester duty in ``server.py`` (the runtime
production validators actually run via ``from server import Server``,
see ``messagechain/cli.py::cmd_run_validator``) was missed.  Pre-fix,
every non-message forced tx (Transfer, Vote, Proposal, KeyRotation,
SetAuthorityKey, CensorshipEvidence, NonResponseEvidence, Slash)
returned ``(False, ...)`` from the message-only ``validate_transaction``
oracle, the gate triggered excuse #4 ("no longer includable"), and
honest server-running validators silently still attested YES on the
suppressing block — re-opening the exact mainnet attack surface
Tier 34/43 + the r25 fix claimed to close.

CLAUDE.md anchor: "a tx that is well-formed, pays at least the per-byte
floor, and fits the byte budget cannot be suppressed by anything weaker
than a full validator-set majority actively colluding."  Pre-fix the
suppression took one proposer with no slashable trail.
"""

from __future__ import annotations

import inspect
import unittest


class TestServerIsIncludableSourcePin(unittest.TestCase):
    def test_server_attest_uses_per_kind_dispatcher(self):
        import server as server_mod

        # Inspect the bound method on Server so the test stays robust
        # against future renames of the wrapping helper.
        meth = getattr(server_mod.Server, "_maybe_attest_accepted_block", None)
        self.assertIsNotNone(
            meth,
            "Server._maybe_attest_accepted_block must exist — it is "
            "the production attester duty for validators running via "
            "`from server import Server`.",
        )
        src = inspect.getsource(meth)

        self.assertIn(
            "validate_forced_includable_tx", src,
            "server.py:_maybe_attest_accepted_block must wire its "
            "is_includable callback through "
            "Blockchain.validate_forced_includable_tx — wiring it "
            "directly through the message-only validate_transaction "
            "silently disables the Tier 34/43 multi-list censorship "
            "gate for every non-message tx kind on the production "
            "validator runtime.",
        )

        # Negative pin: the bug shape was a bare validate_transaction
        # call inside the same _is_includable closure.  Catch any
        # future regression that re-introduces it.
        self.assertNotIn(
            "blockchain.validate_transaction(tx)", src,
            "server.py:_maybe_attest_accepted_block must NOT call "
            "Blockchain.validate_transaction from the is_includable "
            "callback — it is hard-coded to MessageTransaction "
            "semantics and silently rejects every non-message forced "
            "tx kind.  Use validate_forced_includable_tx instead.",
        )


if __name__ == "__main__":
    unittest.main()
