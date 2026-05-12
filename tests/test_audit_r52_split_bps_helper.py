"""Audit r52 finding 3 — Tier 73 deferred a shared ``_split_bps`` helper.

Tier 73 (r51 #3, activation height ``ATTESTER_FEE_MIN_UNIT_HEIGHT``)
clamped the attester-share integer-divide to a minimum of 1 token when
the base_fee was small enough that ``base_fee * 5000 // 10_000`` rounded
to zero.  The CHANGELOG explicitly named the deferred wider abstraction:

    "Sibling defect-shape DEFERRED (scope-bounded for this round): the
     wider abstraction calls for a shared ``_split_bps(amount, bps,
     denom=10_000, min_unit=1)`` helper to catch every future
     ``bps // 10_000`` site that could round to zero under a realistic
     minimum."

The next site that bites the same shape is ``proposer_share`` in
``SupplyTracker.mint_block_reward``:

    proposer_share = reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
                   = reward * 1 // 4

At ``reward in {1, 2, 3}`` the proposer share silently rounds to zero
and the entire reward funds the attester pool.  The dormancy-controller
(post-Tier-47) is *designed* to emit small per-block issuance when
``active_supply`` is close to ``TARGET`` -- so the small-reward regime
is the steady-state, not a corner case.  Pillar at risk: "Perpetual
security via fees, not issuance" + "Stable active supply".

Tier 74 (this commit) lands two changes:
  1. ``_split_bps(amount, num, den, *, min_unit=1, gate=False)`` -- the
     deferred shared helper.  Pure function, no consensus impact.
     When ``gate=False`` it returns ``amount * num // den`` byte-
     identically to legacy integer-floor.  When ``gate=True`` it
     clamps to ``min_unit`` whenever a positive ``amount`` would
     otherwise round to zero, never exceeding the input ``amount``.
  2. ``PROPOSER_SHARE_MIN_UNIT_HEIGHT`` -- new activation height
     gating two consensus-visible sites in ``mint_block_reward``:
     ``proposer_share`` and ``effective_cap``.  Pre-fork byte-
     identical to legacy at every (reward, ...) combination so
     historical-block replay matches.

Tier 73's attester-fee clamp is refactored to call ``_split_bps`` too
-- byte-identical behavior on both sides of every fork (gate=False
pre-Tier-73; gate=True post-Tier-73 inputs).  This proves the helper
generalizes the existing site rather than diverging from it.
"""

from __future__ import annotations

import unittest

import messagechain.config as _cfg
from messagechain.economics.inflation import _split_bps, SupplyTracker


class SplitBpsHelperPureMath(unittest.TestCase):
    """Pin the pure-function behavior of the shared helper.  These cases
    are what every future ``bps // den`` site relies on -- regressing
    them re-opens the silent-round-to-zero defect class."""

    def test_legacy_floor_when_gate_off(self):
        # Pre-fork (gate=False) the helper MUST be byte-identical to
        # the floor-divide expression at every input.  This is what
        # preserves historical-block replay.
        for amount in range(0, 17):
            for num, den in [(1, 4), (5000, 10_000), (7, 13)]:
                expected = amount * num // den
                got = _split_bps(amount, num, den, gate=False)
                self.assertEqual(
                    got, expected,
                    f"_split_bps({amount}, {num}, {den}, gate=False) "
                    f"= {got} != legacy floor {expected}",
                )

    def test_gate_on_zero_amount_returns_zero(self):
        # The clamp must NOT manufacture credit from thin air.  At
        # amount=0 (off-chain audit / test paths with no fee), gate=True
        # MUST still return 0 -- mirrors Tier 73's ``base_fee > 0``
        # guard, lifted into the helper itself.
        self.assertEqual(_split_bps(0, 5000, 10_000, gate=True), 0)
        self.assertEqual(_split_bps(0, 1, 4, gate=True), 0)

    def test_gate_on_positive_amount_clamps_to_min_unit(self):
        # Tier 73 surface: base_fee=1, num=5000, den=10_000 -> floor=0
        # -> clamp=1.
        self.assertEqual(_split_bps(1, 5000, 10_000, gate=True), 1)
        # Tier 74 surface: reward<4 with the 1/4 split -> floor=0 ->
        # clamp=1.  Multiple reward values all clamp to 1.
        self.assertEqual(_split_bps(1, 1, 4, gate=True), 1)
        self.assertEqual(_split_bps(2, 1, 4, gate=True), 1)
        self.assertEqual(_split_bps(3, 1, 4, gate=True), 1)

    def test_gate_on_does_not_exceed_input_amount(self):
        # At amount=1 with num=1, den=4, gated, the clamp returns 1 --
        # which equals the input amount, NOT exceeds it.  Burns the
        # other 0 tokens (everything routed to the clamped share).
        # This invariant is what keeps supply conservation intact.
        for amount in range(1, 5):
            got = _split_bps(amount, 1, 4, gate=True, min_unit=10)
            self.assertLessEqual(
                got, amount,
                f"_split_bps must never exceed input amount; got "
                f"{got} for amount={amount}",
            )

    def test_gate_no_op_when_floor_already_nonzero(self):
        # At amount=4, num=1, den=4 the floor=1 already.  Gated, the
        # clamp returns the floor unchanged.  At amount=5+ the floor=1,
        # same result.  This is the no-op zone of the clamp.
        self.assertEqual(_split_bps(4, 1, 4, gate=True), 1)
        self.assertEqual(_split_bps(8, 1, 4, gate=True), 2)
        self.assertEqual(_split_bps(16, 1, 4, gate=True), 4)
        # And on the Tier 73 site:
        self.assertEqual(_split_bps(2, 5000, 10_000, gate=True), 1)
        self.assertEqual(_split_bps(4, 5000, 10_000, gate=True), 2)


class ProposerShareTier74Activation(unittest.TestCase):
    """Tier 74 consensus gate: at heights >= PROPOSER_SHARE_MIN_UNIT_HEIGHT,
    ``proposer_share`` clamps to a minimum of 1 token when the integer
    floor would silently round to zero.  Pre-fork byte-identical to
    legacy.

    Surface tested via ``mint_block_reward`` -- the chokepoint both
    paths route through.  Bypasses the full Blockchain so the test
    runs in milliseconds while still pinning the consensus-visible
    distribution.
    """

    def _supply_at(self, reward):
        # SupplyTracker takes no constructor args -- the default
        # GENESIS_SUPPLY is plenty for a single-block mint scenario.
        s = SupplyTracker()
        s.calculate_block_reward = lambda h: reward  # type: ignore[method-assign]
        return s

    def test_proposer_share_rounds_to_zero_pre_tier74(self):
        """The defect the fix exists to close: pre-fork ``proposer_share``
        silently rounds to 0 at reward<4 and the WHOLE issuance funds
        the attester pool / burns to the byte-budget excess.  This
        test pins the legacy behavior so the fix's height-gated
        activation is unambiguous."""
        pre_fork_height = _cfg.PROPOSER_CAP_HALVING_HEIGHT + 1
        # Must be PRE Tier 74.
        self.assertLess(
            pre_fork_height,
            _cfg.PROPOSER_SHARE_MIN_UNIT_HEIGHT,
            "Tier 74 activation height must be strictly above the "
            "pre-fork test height -- otherwise this test is meaningless.",
        )
        proposer = b"\x01" * 32
        for reward in (1, 2, 3):
            s = self._supply_at(reward)
            r = s.mint_block_reward(
                proposer, pre_fork_height,
                attester_committee=[b"\xaa" * 32, b"\xbb" * 32],
            )
            self.assertEqual(
                r["proposer_reward"], 0,
                f"pre-fork proposer_reward at reward={reward} must "
                f"be 0 (the defect); got {r['proposer_reward']}",
            )

    def test_proposer_share_clamps_to_one_post_tier74(self):
        """Post-fork at reward in {1, 2, 3} the proposer earns 1 token
        and the attester pool absorbs the rest.  Supply conservation
        preserved (no silent leak / no manufactured tokens)."""
        post_fork_height = _cfg.PROPOSER_SHARE_MIN_UNIT_HEIGHT + 1
        proposer = b"\x01" * 32
        for reward in (1, 2, 3):
            s = self._supply_at(reward)
            r = s.mint_block_reward(
                proposer, post_fork_height,
                attester_committee=[b"\xaa" * 32, b"\xbb" * 32],
            )
            self.assertEqual(
                r["proposer_reward"], 1,
                f"post-fork proposer_reward at reward={reward} must "
                f"clamp to 1; got {r['proposer_reward']}",
            )
            # Distributed total = proposer + attester slots + burn +
            # treasury_excess must equal reward (no manufactured tokens
            # or silent leaks).
            distributed = (
                r["proposer_reward"]
                + r["total_attestor_reward"]
                + r["treasury_excess"]
                + r["burned"]
            )
            self.assertEqual(
                distributed, reward,
                f"supply conservation violated at reward={reward}: "
                f"distributed={distributed} != reward={reward}",
            )

    def test_proposer_share_unchanged_at_reward_ge_four(self):
        """Post-fork at reward>=4 the integer-floor already yields a
        positive proposer_share; the clamp is a no-op.  Byte-identical
        to legacy on this branch."""
        post_fork_height = _cfg.PROPOSER_SHARE_MIN_UNIT_HEIGHT + 1
        proposer = b"\x01" * 32
        for reward in (4, 8, 16):
            s = self._supply_at(reward)
            r = s.mint_block_reward(
                proposer, post_fork_height,
                attester_committee=[b"\xaa" * 32, b"\xbb" * 32],
            )
            expected = reward // 4  # legacy floor
            self.assertEqual(
                r["proposer_reward"], expected,
                f"post-fork proposer_reward at reward={reward} must "
                f"equal legacy floor {expected}; got "
                f"{r['proposer_reward']} (clamp leaked into no-op zone)",
            )


class Tier73AttesterShareStillCorrectAfterRefactor(unittest.TestCase):
    """The Tier 73 attester-fee clamp is refactored to call ``_split_bps``.
    The refactor MUST be byte-identical to the pre-refactor behavior at
    every input on both sides of the Tier 73 activation -- otherwise
    historical-block replay breaks for the post-Tier-73 cohort.

    Surfaced via ``pay_fee_with_burn``, the chokepoint pre-r51 #3
    already routed both sim and apply paths through.
    """

    def test_pre_tier73_attester_share_is_floor_divide(self):
        """At heights below ``ATTESTER_FEE_MIN_UNIT_HEIGHT`` (but
        post-``ATTESTER_FEE_FUNDING_HEIGHT``), the attester share is
        ``base_fee * ATTESTER_FEE_SHARE_BPS // 10_000`` byte-identical
        to legacy.  At base_fee=1 that's 0 (the pre-Tier-73 defect)."""
        s = SupplyTracker()
        sender = b"\x01" * 32
        proposer = b"\x02" * 32
        s.balances[sender] = 10
        pre_tier73 = _cfg.ATTESTER_FEE_MIN_UNIT_HEIGHT - 1
        self.assertGreaterEqual(
            pre_tier73, _cfg.ATTESTER_FEE_FUNDING_HEIGHT,
            "Tier 73 must sit above ATTESTER_FEE_FUNDING_HEIGHT for "
            "this test to be meaningful.",
        )
        ok = s.pay_fee_with_burn(
            sender, proposer, fee=1, base_fee=1, block_height=pre_tier73,
        )
        self.assertTrue(ok)
        # Pre-fork: attester_fee_pool_this_block = 0 (the defect).
        self.assertEqual(s.attester_fee_pool_this_block, 0)

    def test_post_tier73_attester_share_clamps_to_one(self):
        """At heights >= ``ATTESTER_FEE_MIN_UNIT_HEIGHT``, base_fee=1
        clamps the attester share to 1 token (the Tier 73 fix).
        Refactor through ``_split_bps`` preserves this."""
        s = SupplyTracker()
        sender = b"\x01" * 32
        proposer = b"\x02" * 32
        s.balances[sender] = 10
        post_tier73 = _cfg.ATTESTER_FEE_MIN_UNIT_HEIGHT + 1
        ok = s.pay_fee_with_burn(
            sender, proposer, fee=1, base_fee=1, block_height=post_tier73,
        )
        self.assertTrue(ok)
        # Post-fork: attester_fee_pool_this_block = 1 (Tier 73 clamp).
        self.assertEqual(s.attester_fee_pool_this_block, 1)


class HeightOrderingAnchored(unittest.TestCase):
    """The new tier MUST sit strictly above Tier 73 -- consecutive
    economics retunes get their own cohort so operators absorb each
    in its own upgrade cycle.  Mirrors the Tier 70 -> 71 -> 73 runway
    discipline."""

    def test_tier74_sits_above_tier73(self):
        self.assertGreater(
            _cfg.PROPOSER_SHARE_MIN_UNIT_HEIGHT,
            _cfg.ATTESTER_FEE_MIN_UNIT_HEIGHT,
            "Tier 74 PROPOSER_SHARE_MIN_UNIT_HEIGHT must follow "
            "Tier 73 ATTESTER_FEE_MIN_UNIT_HEIGHT in activation order",
        )


if __name__ == "__main__":
    unittest.main()
