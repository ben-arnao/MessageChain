"""Pin: ``auto_fee._transfer_floor`` for the new-recipient branch
matches the literal consensus rule
``MIN_FEE + NEW_ACCOUNT_FEE`` enforced by
``Blockchain.verify_transfer_transaction`` and
``_validate_transfer_in_block``.

Pre-fix the wallet helper computed
``_non_message_flat_floor(current_height) + NEW_ACCOUNT_FEE`` —
which post-Tier-49 (UNIFIED_FEE_FLOOR_HEIGHT) collapses to
``MARKET_FEE_FLOOR + NEW_ACCOUNT_FEE = 1 + 1000 = 1001``.  The
consensus rule, however, has no Tier 49 height gate on the
new-account branch and remains a flat literal
``MIN_FEE + NEW_ACCOUNT_FEE = 100 + 1000 = 1100``.  Result: every
auto-fee CLI/wallet transfer to a never-seen recipient post-Tier-49
underbid the chain by 99 tokens and was silently rejected — the
canonical "send money to a new account" flow is broken on every
mainnet node from the Tier 49 activation height onward.

CLAUDE.md anchors:

  * "Auto-fee defaults adjust to fit this model.  When the fee model
    shifts, every auto-fee path shifts with it -- don't leave a tx
    kind defaulting to a stale flat fee while others auto-bid by
    density."

  * "Token-as-tradable-asset quality bar -- wallet/transfer/balance
    code held to mainstream-asset standards."  A wallet quoting a
    fee the chain rejects on every new-recipient transfer fails
    that bar squarely.

The fix realigns the wallet quote with the consensus literal
(no consensus rule change, no fork).  The source-level pin below
catches any future drift in either direction:

  * If the consensus rule moves to a unified Tier-49 floor for the
    new-account branch as well, the source-level pin trips and the
    wallet quote must update in lockstep.

  * If the wallet quote drifts back to the unified floor before the
    consensus does, the numeric pin trips first.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain.config import (
    MIN_FEE,
    NEW_ACCOUNT_FEE,
    UNIFIED_FEE_FLOOR_HEIGHT,
)
from messagechain.economics.auto_fee import _transfer_floor, tx_floor


CONSENSUS_NEW_ACCOUNT_TRANSFER_FLOOR = MIN_FEE + NEW_ACCOUNT_FEE


class TestTransferFloorNewAccountMatchesConsensus(unittest.TestCase):
    """Wallet quote matches the chain's required floor for the
    new-recipient branch at every height."""

    def test_post_tier_49_height_uses_consensus_literal(self):
        """Post-Tier-49 the wallet must NOT collapse the new-account
        floor to MARKET_FEE_FLOOR + NEW_ACCOUNT_FEE.  The consensus
        rule has no Tier 49 gate on the new-account branch."""
        h = UNIFIED_FEE_FLOOR_HEIGHT + 1
        floor = _transfer_floor(current_height=h, recipient_is_new=True)
        self.assertEqual(
            floor, CONSENSUS_NEW_ACCOUNT_TRANSFER_FLOOR,
            f"Post-Tier-49 wallet quote for new-recipient transfer "
            f"must equal MIN_FEE + NEW_ACCOUNT_FEE "
            f"({CONSENSUS_NEW_ACCOUNT_TRANSFER_FLOOR}); got {floor}.  "
            f"The chain validator at "
            f"`Blockchain.verify_transfer_transaction` and "
            f"`_validate_transfer_in_block` hard-code that literal "
            f"with no UNIFIED_FEE_FLOOR_HEIGHT gate, so the wallet "
            f"must mirror it or every new-recipient transfer is "
            f"silently rejected post-Tier-49.",
        )

    def test_pre_tier_49_height_also_matches_consensus_literal(self):
        """Pre-Tier-49 the wallet quote already matched the
        consensus rule (MIN_FEE happens to equal the pre-Tier-49
        flat floor); pin that this stays true so no refactor flips
        either side independently."""
        h = max(0, UNIFIED_FEE_FLOOR_HEIGHT - 100)
        floor = _transfer_floor(current_height=h, recipient_is_new=True)
        self.assertEqual(floor, CONSENSUS_NEW_ACCOUNT_TRANSFER_FLOOR)

    def test_height_none_falls_back_to_consensus_literal(self):
        """``current_height=None`` should pick the conservative path —
        which here is the consensus literal, since the new-account
        floor is height-invariant."""
        floor = _transfer_floor(current_height=None, recipient_is_new=True)
        self.assertEqual(floor, CONSENSUS_NEW_ACCOUNT_TRANSFER_FLOOR)

    def test_tx_floor_dispatcher_routes_consistently(self):
        """The public ``tx_floor`` entry point must propagate
        ``recipient_is_new`` to the same literal floor — not just
        the private helper.  Lift catches any future dispatch-shape
        refactor that drops the kwarg silently."""
        h = UNIFIED_FEE_FLOOR_HEIGHT + 1
        floor = tx_floor(
            "transfer",
            current_height=h,
            recipient_is_new=True,
        )
        self.assertEqual(floor, CONSENSUS_NEW_ACCOUNT_TRANSFER_FLOOR)


class TestConsensusRuleSourceLevelPin(unittest.TestCase):
    """Source-level guard: if the chain ever migrates the
    new-account branch to a unified Tier-49 floor, this test trips
    and forces the wallet quote to update in lockstep.

    The pin is deliberately textual rather than executing the
    validator — running the validator end-to-end requires a
    constructed Blockchain + signed tx + balanced sender, which
    bloats the test for no benefit beyond what the pin already
    captures.  The bug shape was a literal ``MIN_FEE + NEW_ACCOUNT_FEE``
    in two sites; pinning the literal is the cheapest way to catch
    drift in either direction.
    """

    def test_blockchain_carries_min_fee_plus_new_account_literal(self):
        from messagechain.core import blockchain as blockchain_mod

        src = inspect.getsource(blockchain_mod)
        self.assertIn(
            "MIN_FEE + NEW_ACCOUNT_FEE", src,
            "Blockchain must carry the literal MIN_FEE + NEW_ACCOUNT_FEE "
            "as the new-account transfer floor.  If this expression has "
            "been migrated to a unified Tier-49 floor (e.g. "
            "_non_message_flat_floor + NEW_ACCOUNT_FEE), the wallet "
            "quote in auto_fee._transfer_floor must update in lockstep "
            "or every new-recipient transfer post-fork-N will silently "
            "round wrong.",
        )


if __name__ == "__main__":
    unittest.main()
