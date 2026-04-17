"""Hardening tests for the proposer reward cap.

Background
----------
`SupplyTracker.mint_block_reward` caps the proposer's combined take
(proposer share + committee slot if they're on the committee) at
`PROPOSER_REWARD_CAP`.  With the default constants
(`BLOCK_REWARD=16, PROPOSER_REWARD_NUMERATOR=1,
PROPOSER_REWARD_DENOMINATOR=4, PROPOSER_REWARD_CAP=4`) the proposer
share is exactly 4, which equals the cap — so the "proposer share
alone exceeds cap" edge is never triggered in production today.

But the original implementation had a latent bug: if governance ever
changed numerator/denominator/cap such that
`proposer_share > effective_cap`, the code would silently over-mint
tokens and violate conservation of supply.  These tests lock in the
fix: `proposer_share` is trimmed to the cap, and the over-mint goes
to the treasury.

Invariant under test
--------------------
For every scenario:

    delta_proposer_balance
  + sum(delta_other_attester_balances)
  + delta_treasury_balance
  == block_reward_for_height

(Supply tracker's `total_supply` must increase by exactly
`block_reward_for_height` — no over-mint, no phantom burn.)
"""

import unittest
from unittest.mock import patch

from messagechain.economics import inflation as inflation_module
from messagechain.economics.inflation import SupplyTracker
from messagechain.consensus.attester_committee import ATTESTER_REWARD_PER_SLOT
from messagechain.config import (
    BLOCK_REWARD,
    PROPOSER_REWARD_NUMERATOR,
    PROPOSER_REWARD_DENOMINATOR,
    PROPOSER_REWARD_CAP,
    TREASURY_ENTITY_ID,
)


def _with_overrides(numerator, denominator, cap):
    """Patch the inflation module's reward constants for a test."""
    return patch.multiple(
        inflation_module,
        PROPOSER_REWARD_NUMERATOR=numerator,
        PROPOSER_REWARD_DENOMINATOR=denominator,
        PROPOSER_REWARD_CAP=cap,
    )


class TestProposerShareAloneExceedsCap(unittest.TestCase):
    """If governance ever sets proposer_share > cap, we must trim it."""

    def test_proposer_share_capped_when_exceeds_alone_no_committee(self):
        """With share=8 and cap=3 and no committee, proposer gets exactly cap."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        # Override: share = 16 * 1 / 2 = 8, cap = 3
        # No committee → the "no committee" branch already handles this,
        # but we test it explicitly for completeness.
        with _with_overrides(numerator=1, denominator=2, cap=3):
            result = supply.mint_block_reward(proposer, block_height=0)

        self.assertEqual(result["proposer_reward"], 3)
        self.assertEqual(supply.balances[proposer], 3)
        self.assertEqual(
            supply.balances[TREASURY_ENTITY_ID],
            BLOCK_REWARD - 3,
        )

    def test_proposer_share_capped_when_exceeds_alone_with_committee(self):
        """Share=4, cap=3, proposer in committee → proposer gets exactly 3."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        other = b"a" * 32
        supply.balances[proposer] = 0
        supply.balances[other] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        # BLOCK_REWARD=16; share = 16 * 1 / 4 = 4; cap = 3
        # proposer on committee → total = share(4) + slot(1) = 5 > cap(3)
        # After clawing back slot: share alone (4) still > cap (3) → trim to 3.
        with _with_overrides(numerator=1, denominator=4, cap=3):
            result = supply.mint_block_reward(
                proposer,
                block_height=0,
                attester_committee=[proposer, other],
            )

        # Proposer net delta = exactly the cap.
        self.assertEqual(supply.balances[proposer], 3)
        # The proposer's attestor reward entry must be zeroed.
        self.assertEqual(result["attestor_rewards"].get(proposer, 0), 0)
        # Other attester still earns the flat slot.
        self.assertEqual(supply.balances[other], ATTESTER_REWARD_PER_SLOT)
        # Conservation: proposer(3) + other(1) + treasury = 16.
        self.assertEqual(
            supply.balances[proposer]
            + supply.balances[other]
            + supply.balances[TREASURY_ENTITY_ID],
            BLOCK_REWARD,
        )

    def test_proposer_share_capped_when_exceeds_alone_no_proposer_in_committee(self):
        """Share=8, cap=3, proposer NOT in committee → still cap share to 3."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        a1 = b"a" * 32
        a2 = b"b" * 32
        supply.balances[proposer] = 0
        supply.balances[a1] = 0
        supply.balances[a2] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        # share = 16 * 1 / 2 = 8; cap = 3
        # proposer NOT in committee → att_reward for proposer = 0.
        # proposer_total = 8 > cap(3). Clawback is a no-op. Share must
        # then be trimmed from 8 to 3.
        with _with_overrides(numerator=1, denominator=2, cap=3):
            result = supply.mint_block_reward(
                proposer,
                block_height=0,
                attester_committee=[a1, a2],
            )

        self.assertEqual(supply.balances[proposer], 3)
        self.assertEqual(supply.balances[a1], ATTESTER_REWARD_PER_SLOT)
        self.assertEqual(supply.balances[a2], ATTESTER_REWARD_PER_SLOT)
        # Conservation.
        self.assertEqual(
            supply.balances[proposer]
            + supply.balances[a1]
            + supply.balances[a2]
            + supply.balances[TREASURY_ENTITY_ID],
            BLOCK_REWARD,
        )


class TestConservationUnderAllCapScenarios(unittest.TestCase):
    """Conservation of supply: delta_balances == block_reward always."""

    def _run_scenario(
        self,
        *,
        numerator,
        denominator,
        cap,
        committee_factory,
        bootstrap=False,
    ):
        """Run mint_block_reward under overridden constants and check
        conservation.

        `committee_factory(proposer, others)` returns the committee
        list (may include proposer).
        """
        supply = SupplyTracker()
        proposer = b"p" * 32
        others = [bytes([i]) * 32 for i in range(1, 5)]
        for eid in [proposer, *others, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        committee = committee_factory(proposer, others)
        supply_before = supply.total_supply
        balances_before = {
            eid: supply.balances.get(eid, 0)
            for eid in [proposer, *others, TREASURY_ENTITY_ID]
        }

        with _with_overrides(
            numerator=numerator, denominator=denominator, cap=cap,
        ):
            result = supply.mint_block_reward(
                proposer,
                block_height=0,
                attester_committee=committee,
                bootstrap=bootstrap,
            )

        reward = result["total_reward"]
        # Supply increases by exactly the block reward.
        self.assertEqual(supply.total_supply, supply_before + reward)

        # Sum of per-entity balance deltas == reward.
        delta_sum = sum(
            supply.balances.get(eid, 0) - balances_before[eid]
            for eid in [proposer, *others, TREASURY_ENTITY_ID]
        )
        self.assertEqual(
            delta_sum, reward,
            f"conservation violated: deltas={delta_sum}, reward={reward}, "
            f"config=(num={numerator}, den={denominator}, cap={cap})",
        )

        # Proposer never gets more than the effective cap.
        effective_cap = reward if bootstrap else cap
        proposer_delta = (
            supply.balances.get(proposer, 0) - balances_before[proposer]
        )
        self.assertLessEqual(proposer_delta, effective_cap)

    def test_conservation_no_cap_hit(self):
        """Default-ish config where share < cap and no cap trimming needed."""
        self._run_scenario(
            numerator=1,
            denominator=4,
            cap=10,
            committee_factory=lambda p, o: [o[0], o[1], o[2]],
        )

    def test_conservation_cap_hit_att_clawback_only(self):
        """Default config: share==cap==4, proposer in committee (needs clawback)."""
        self._run_scenario(
            numerator=1,
            denominator=4,
            cap=4,
            committee_factory=lambda p, o: [p, o[0], o[1]],
        )

    def test_conservation_cap_hit_proposer_share_trim(self):
        """Share=4 > cap=3, proposer in committee → trim share after clawback."""
        self._run_scenario(
            numerator=1,
            denominator=4,
            cap=3,
            committee_factory=lambda p, o: [p, o[0], o[1]],
        )

    def test_conservation_cap_hit_proposer_not_in_committee_trim(self):
        """Share=8 > cap=3, proposer NOT in committee → clawback no-op, then trim."""
        self._run_scenario(
            numerator=1,
            denominator=2,
            cap=3,
            committee_factory=lambda p, o: [o[0], o[1], o[2]],
        )

    def test_conservation_cap_hit_share_way_above_cap(self):
        """Share=16 (entire reward), cap=1 → trim share all the way to 1."""
        self._run_scenario(
            numerator=1,
            denominator=1,
            cap=1,
            committee_factory=lambda p, o: [],
        )

    def test_conservation_bootstrap_mode(self):
        """Bootstrap mode: effective_cap = reward, so no cap hit ever."""
        self._run_scenario(
            numerator=1,
            denominator=4,
            cap=3,  # would bite in non-bootstrap, but ignored here
            committee_factory=lambda p, o: [p, o[0]],
            bootstrap=True,
        )

    def test_conservation_cap_hit_exact_boundary(self):
        """share == cap and proposer in committee — overage is just the slot."""
        self._run_scenario(
            numerator=1,
            denominator=4,
            cap=4,
            committee_factory=lambda p, o: [p],
        )


class TestNoRegressionWithDefaultConstants(unittest.TestCase):
    """Behavior with default production constants must be unchanged."""

    def test_no_committee_default(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        result = supply.mint_block_reward(proposer, block_height=0)

        # Default: proposer gets the cap (4), treasury gets the rest (12).
        self.assertEqual(result["proposer_reward"], PROPOSER_REWARD_CAP)
        self.assertEqual(
            result["treasury_excess"], BLOCK_REWARD - PROPOSER_REWARD_CAP,
        )
        self.assertEqual(supply.balances[proposer], PROPOSER_REWARD_CAP)
        self.assertEqual(
            supply.balances[TREASURY_ENTITY_ID],
            BLOCK_REWARD - PROPOSER_REWARD_CAP,
        )

    def test_with_committee_proposer_included_default(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        other = b"a" * 32
        supply.balances[proposer] = 0
        supply.balances[other] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=0,
            attester_committee=[proposer, other],
        )

        # Default: share=4=cap. Proposer on committee triggers cap hit
        # on slot clawback path: proposer_total = 4+1 = 5 > 4.
        # After clawback: share(4) == cap(4), no further trim.
        # Net: proposer = 4, other = 1, treasury = 16 - 4 - 1 = 11.
        self.assertEqual(supply.balances[proposer], PROPOSER_REWARD_CAP)
        self.assertEqual(supply.balances[other], ATTESTER_REWARD_PER_SLOT)
        self.assertEqual(
            supply.balances[proposer]
            + supply.balances[other]
            + supply.balances[TREASURY_ENTITY_ID],
            BLOCK_REWARD,
        )
        self.assertEqual(result["attestor_rewards"].get(proposer, 0), 0)
        self.assertEqual(
            result["attestor_rewards"].get(other, 0),
            ATTESTER_REWARD_PER_SLOT,
        )

    def test_with_committee_proposer_excluded_default(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        a1 = b"a" * 32
        a2 = b"b" * 32
        supply.balances[proposer] = 0
        supply.balances[a1] = 0
        supply.balances[a2] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        supply.mint_block_reward(
            proposer,
            block_height=0,
            attester_committee=[a1, a2],
        )

        # share=4, cap=4, proposer not on committee → no cap hit.
        # proposer gets 4, each attester gets 1, treasury = 16-4-2 = 10.
        self.assertEqual(supply.balances[proposer], PROPOSER_REWARD_CAP)
        self.assertEqual(supply.balances[a1], ATTESTER_REWARD_PER_SLOT)
        self.assertEqual(supply.balances[a2], ATTESTER_REWARD_PER_SLOT)
        self.assertEqual(
            supply.balances[TREASURY_ENTITY_ID],
            BLOCK_REWARD
            - PROPOSER_REWARD_CAP
            - 2 * ATTESTER_REWARD_PER_SLOT,
        )


if __name__ == "__main__":
    unittest.main()
