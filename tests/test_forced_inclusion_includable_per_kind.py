"""Audit r25 #1 — forced-inclusion `_is_includable` callback dispatches per
tx kind, not via the message-only `validate_transaction`.

Tier 34 / Tier 43 brought non-message tx kinds (Transfer, Vote, Proposal,
SetAuthorityKey, CensorshipEvidence, ...) under the attester-enforced
forced-inclusion gate.  The gate uses an `is_includable(tx)` callback as
the proposer-time validity oracle (excuse #4: "tx is no longer
includable").  The pre-fix wiring on the production node was:

    def _is_includable(tx) -> bool:
        ok, _reason = self.blockchain.validate_transaction(tx)
        return ok

`validate_transaction` is hard-coded to MessageTransaction semantics —
reads `tx.message`, calls the message-only `verify_transaction`, etc.
Every non-message forced tx therefore returned False (or raised
AttributeError → False), and the gate excused the omission as
"no longer includable" — silently re-opening the exact attack surface
Tier 34/43 claimed to close.  CLAUDE.md anchor:

    "a tx that is well-formed, pays at least the per-byte floor, and
    fits the byte budget cannot be suppressed by anything weaker than
    a full validator-set majority actively colluding."

Pre-fix a single colluding proposer could drop ANY non-message forced
tx (governance Vote, Transfer, Authority change, censorship evidence,
...) without producing slashable evidence.

Fix: `Blockchain.validate_forced_includable_tx(tx)` dispatches per-kind
to the right validator.  Tx kinds without a stateful re-validator
(Stake / Unstake / Governance / React) return (True, ...) — the gate's
purpose is to EXCUSE omissions where state moved on, not to authorize
them, so the conservative default for "no stateful check available"
is "still valid" (forces the proposer to include or face the censorship
vote).  `node.py:_maybe_attest_accepted_block` routes its
`_is_includable` through this dispatcher.
"""

from __future__ import annotations

import unittest

from messagechain.config import MIN_FEE
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity

from tests import register_entity_for_test


class TestValidateForcedIncludableTxDispatch(unittest.TestCase):
    """`Blockchain.validate_forced_includable_tx` routes per-kind."""

    def setUp(self):
        self.chain = Blockchain()
        self.alice = Entity.create(b"r25-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"r25-bob".ljust(32, b"\x00"))
        register_entity_for_test(self.chain, self.alice)
        register_entity_for_test(self.chain, self.bob)
        # Fund alice so transfers validate.
        self.chain.supply.balances[self.alice.entity_id] = 10_000_000

    # ── Public dispatcher exists ────────────────────────────────────────
    def test_dispatcher_method_exists(self):
        """The new dispatcher is a public method on Blockchain."""
        self.assertTrue(
            hasattr(self.chain, "validate_forced_includable_tx"),
            "Blockchain must expose validate_forced_includable_tx — the "
            "single chokepoint for forced-inclusion's is_includable",
        )
        self.assertTrue(callable(self.chain.validate_forced_includable_tx))

    # ── MessageTransaction routes to validate_transaction ───────────────
    def test_message_tx_routes_to_validate_transaction(self):
        """MessageTransaction goes through validate_transaction — same
        result for a valid tx."""
        msg_tx = create_transaction(
            self.alice, "hello", fee=10_000, nonce=0,
        )
        ok, _reason = self.chain.validate_forced_includable_tx(msg_tx)
        legacy_ok, _legacy_reason = self.chain.validate_transaction(msg_tx)
        self.assertEqual(ok, legacy_ok)
        self.assertTrue(ok, "fresh valid message tx must validate")

    # ── TransferTransaction MUST NOT fall through validate_transaction ──
    def test_transfer_tx_does_not_route_to_message_validator(self):
        """Pre-fix bug shape: a TransferTransaction passed to
        `validate_transaction` returned False (or raised).  The
        dispatcher MUST route to `validate_transfer_transaction` so a
        valid forced transfer is recognized as still-includable."""
        xfer = create_transfer_transaction(
            self.alice, self.bob.entity_id,
            amount=1_000, nonce=0, fee=10_000,
        )
        ok, reason = self.chain.validate_forced_includable_tx(xfer)
        self.assertTrue(
            ok,
            f"valid forced transfer must be is_includable=True — pre-fix "
            f"bug returned False (reason: {reason})",
        )
        # Cross-check the per-kind validator agrees independently.
        per_kind_ok, _ = self.chain.validate_transfer_transaction(xfer)
        self.assertTrue(per_kind_ok)

    def test_transfer_tx_routing_independent_of_message_validator(self):
        """A transfer that is INVALID at the transfer-validator level
        (insufficient balance) must be reported as not-includable —
        proving the dispatcher actually consulted the right validator,
        not just defaulted True."""
        # Drain alice's balance below the transfer amount.
        self.chain.supply.balances[self.alice.entity_id] = 0
        xfer = create_transfer_transaction(
            self.alice, self.bob.entity_id,
            amount=1_000, nonce=0, fee=10_000,
        )
        ok, reason = self.chain.validate_forced_includable_tx(xfer)
        self.assertFalse(
            ok,
            f"underfunded transfer must NOT be is_includable=True; "
            f"got True (reason: {reason})",
        )

    # ── Kinds without a stateful re-validator default to True ───────────
    def test_unrecognized_tx_kind_defaults_to_includable(self):
        """An unrecognized forced tx kind defaults to includable — the
        gate's purpose is to EXCUSE omissions, not authorize them.
        Without a stateful check, the safe default is "still valid"
        (forces the proposer to include or face the censorship vote)."""
        class _UnknownTx:
            tx_hash = b"\xff" * 32
            fee = MIN_FEE

        ok, _reason = self.chain.validate_forced_includable_tx(_UnknownTx())
        self.assertTrue(
            ok,
            "unrecognized tx kind must default to is_includable=True so "
            "the forced-inclusion gate forces the proposer to include "
            "rather than excusing the omission",
        )


class TestNodeIsIncludableSourcePin(unittest.TestCase):
    """Source-level pin: `node.py:_maybe_attest_accepted_block` wires
    `_is_includable` through `validate_forced_includable_tx`, not
    directly through `validate_transaction`.  Without this, the wrapping
    in node.py drifts back to the bug-shape on the next refactor."""

    def test_node_attest_uses_per_kind_dispatcher(self):
        import inspect
        from messagechain.network import node as node_mod

        src = inspect.getsource(node_mod._maybe_attest_accepted_block) \
            if hasattr(node_mod, "_maybe_attest_accepted_block") \
            else inspect.getsource(node_mod)

        self.assertIn(
            "validate_forced_includable_tx", src,
            "node.py:_maybe_attest_accepted_block must wire its "
            "is_includable callback through "
            "Blockchain.validate_forced_includable_tx — wiring it "
            "directly through validate_transaction silently disables "
            "the Tier 34/43 multi-list censorship gate for every "
            "non-message tx kind.",
        )


if __name__ == "__main__":
    unittest.main()
