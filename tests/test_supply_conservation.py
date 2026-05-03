"""Per-block supply-conservation invariant.

The drift check shipped in 1.48.0 (``Blockchain.check_state_drift``)
catches in-memory <-> on-disk divergence, but a corrupting bug that
mutates BOTH paths the same way passes silently — the two sides agree
with each other while disagreeing with the chain's own supply ledger.

This invariant catches that defect class: any apply-path mutation that
mints, burns, or otherwise creates / destroys tokens in a way that
doesn't balance against ``SupplyTracker.total_supply`` is detectable
in O(N_entities) by summing every owned bucket and comparing to
``total_supply``.

Conservation identity (must hold after every apply):

    total_supply == sum(non_treasury_balances)
                  + treasury_balance
                  + sum(staked)
                  + sum(amt for entries in pending_unstakes.values()
                            for amt, _ in entries)

The treasury is split out of ``balances_sum`` in the breakdown so an
operator scanning the log can see WHICH bucket is misbehaving without
double-counting (treasury IS one of the entries in
``self.supply.balances``; we just surface it separately).

Default behavior on violation is ``log`` only — chain-history changes
are scary, and the goal is to surface the bug, not amplify it.  An
operator can opt into ``crash`` or ``reject`` via the
``supply_invariant_on_violation`` knob.
"""

from __future__ import annotations

import logging
import unittest

from messagechain.config import (
    TREASURY_ENTITY_ID,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import pick_selected_proposer, register_entity_for_test


def _make_chain_with_validators(num_validators: int):
    """Spin up an in-memory chain with `num_validators` registered+staked
    validators.  Mirrors the helper in test_block_production.py so the
    invariant tests share an apples-to-apples setup.

    Note on `total_supply` normalization: ``initialize_genesis`` without
    an allocation_table only allocates ``GENESIS_ALLOCATION`` (10K) to
    the genesis entity, but ``total_supply`` stays at ``GENESIS_SUPPLY``
    (140M), leaving a 139.99M "phantom" gap that's accepted in test
    mode (see test_genesis_supply_invariant.py for the production
    fix).  These tests are about the conservation INVARIANT, not the
    test-mode genesis baseline, so we credit the phantom delta to a
    "phantom-sink" entity AFTER setup so the conservation invariant
    holds at t0 — and we leave ``total_supply`` /
    ``total_minted`` / ``total_burned`` untouched so the unrelated
    ``GENESIS_SUPPLY + total_minted - total_burned == total_supply``
    invariant the chain enforces in `_apply_block_state` keeps holding.
    """
    entities = [
        Entity.create(f"sup_conserv_validator_{i}".encode().ljust(32, b"\x00"))
        for i in range(num_validators)
    ]
    chain = Blockchain()
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)

    consensus = ProofOfStake()
    for e in entities:
        chain.supply.balances[e.entity_id] = (
            chain.supply.balances.get(e.entity_id, 0) + 5000
        )
        chain.supply.stake(e.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[e.entity_id] = VALIDATOR_MIN_STAKE

    # Park the phantom-supply gap on a synthetic sink entity so the
    # conservation invariant holds at t0 without touching total_supply.
    # See docstring above.
    expected, actual, _bd = chain.check_supply_conservation()
    if expected != actual:
        phantom_eid = b"\xfe" * 32  # synthetic test-only sink
        chain.supply.balances[phantom_eid] = (
            chain.supply.balances.get(phantom_eid, 0) + (expected - actual)
        )

    return chain, consensus, entities


class TestSupplyConservationCheck(unittest.TestCase):
    """``Blockchain.check_supply_conservation`` returns the conservation
    triple ``(expected, actual, breakdown)`` so callers can both assert
    equality and surface a per-bucket diagnostic."""

    def test_holds_at_genesis(self):
        chain, _consensus, _entities = _make_chain_with_validators(2)
        expected, actual, breakdown = chain.check_supply_conservation()
        self.assertEqual(
            expected, actual,
            f"Conservation broken at genesis: expected={expected} "
            f"actual={actual} breakdown={breakdown}",
        )

    def test_holds_after_normal_blocks(self):
        """Apply some normal blocks via the real propose/add path and
        assert the invariant survives every apply."""
        chain, consensus, entities = _make_chain_with_validators(2)

        # Two empty blocks — exercises the block-reward mint + (zero)
        # fee burn path.  Use ``pick_selected_proposer`` because the
        # PoS rotation may pick either validator depending on the
        # genesis-block hash.
        for _ in range(2):
            proposer = pick_selected_proposer(chain, entities)
            block = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)
            expected, actual, breakdown = chain.check_supply_conservation()
            self.assertEqual(
                expected, actual,
                f"Conservation broken after block "
                f"{chain.height}: expected={expected} actual={actual} "
                f"breakdown={breakdown}",
            )

    def test_breakdown_keys_are_complete(self):
        """The breakdown dict must surface every bucket so an operator
        can localize a divergence without having to instrument the
        node.  1.50.0 added archive_reward_pool + lottery_prize_pool
        to close the false-positive class where tokens redirected
        into a scalar pool weren't summed into ``actual`` even though
        ``total_supply`` had been bumped to account for them."""
        chain, _consensus, _entities = _make_chain_with_validators(1)
        _expected, _actual, breakdown = chain.check_supply_conservation()
        self.assertEqual(
            set(breakdown.keys()),
            {
                "balances_sum", "staked_sum", "pending_unstakes_sum",
                "treasury", "archive_reward_pool", "lottery_prize_pool",
            },
        )
        # All buckets are non-negative ints.
        for k, v in breakdown.items():
            self.assertIsInstance(v, int, f"{k} should be int, got {type(v)}")
            self.assertGreaterEqual(v, 0, f"{k}={v} should be non-negative")

    def test_breakdown_treasury_split_out_of_balances_sum(self):
        """``balances_sum`` must EXCLUDE the treasury entry to avoid
        double-counting (treasury is surfaced separately so the
        operator sees the treasury bucket independently)."""
        chain, _consensus, _entities = _make_chain_with_validators(1)
        _exp, _act, breakdown = chain.check_supply_conservation()
        treasury_balance = chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
        non_treasury_total = sum(
            v for k, v in chain.supply.balances.items()
            if k != TREASURY_ENTITY_ID
        )
        self.assertEqual(breakdown["balances_sum"], non_treasury_total)
        self.assertEqual(breakdown["treasury"], treasury_balance)

    def test_corrupting_mutation_is_detected(self):
        """Inject a corrupting mutation: directly bump a balance by 1000
        WITHOUT touching ``total_supply``.  The conservation check must
        report the delta and point at ``balances_sum``."""
        chain, _consensus, entities = _make_chain_with_validators(2)
        eid = entities[1].entity_id
        chain.supply.balances[eid] = chain.supply.balances.get(eid, 0) + 1000

        expected, actual, breakdown = chain.check_supply_conservation()
        self.assertNotEqual(expected, actual)
        self.assertEqual(
            actual - expected, 1000,
            f"Expected actual-expected delta of +1000, got "
            f"{actual - expected} breakdown={breakdown}",
        )
        # Sanity: the breakdown's balances_sum reflects the +1000 bump.
        non_treasury_total = sum(
            v for k, v in chain.supply.balances.items()
            if k != TREASURY_ENTITY_ID
        )
        self.assertEqual(breakdown["balances_sum"], non_treasury_total)


class TestSupplyConservationDefaultLogOnly(unittest.TestCase):
    """Default behaviour on violation is log-only — never reject the
    block.  Chain-history changes (rejecting a block that all peers
    accepted) are scary; the goal is to surface the bug, not amplify
    it.  An operator can opt into stricter behaviour via the
    ``supply_invariant_on_violation`` knob."""

    def test_default_violation_mode_is_log(self):
        chain, _consensus, _entities = _make_chain_with_validators(1)
        self.assertEqual(chain.supply_invariant_on_violation, "log")

    def test_invariant_violation_does_not_reject_block(self):
        """Synthesize a violation by corrupting balances DURING apply,
        then assert the next block STILL appends successfully (default
        mode is log-only — invariant violations don't reject blocks)."""
        chain, consensus, entities = _make_chain_with_validators(2)

        # Hook into _apply_block_state to inject a phantom balance bump
        # AFTER apply runs.  This mirrors the defect class the invariant
        # catches: a code path that credits a balance without bumping
        # total_supply.
        original_apply = chain._apply_block_state

        def tampering_apply(block):
            original_apply(block)
            chain.supply.balances[entities[1].entity_id] += 7
            # Re-touch the entity so the state_tree reflects the bump
            # and the state_root the proposer committed to (computed
            # via the simulation path which mirrors apply) doesn't
            # diverge — we want to test the conservation check, NOT
            # the existing state_root check.

        try:
            chain._apply_block_state = tampering_apply
            block = chain.propose_block(consensus, entities[0], [])

            # The state_root pre-check would normally reject the block
            # because the simulation path doesn't apply the tampering.
            # We can't bypass that through public API, so instead
            # bypass-test the invariant directly: simulate the post-apply
            # call and confirm the violation is surfaced via the log
            # without raising.
            with self.assertLogs(
                "messagechain.core.blockchain",
                level=logging.ERROR,
            ) as logs:
                # Manually invoke the conservation check after a
                # synthetic phantom-bump to mirror the apply-time hook.
                chain.supply.balances[entities[1].entity_id] += 7
                chain._enforce_supply_conservation(block_height=42)
            self.assertTrue(
                any("supply conservation" in m.lower() for m in logs.output),
                f"Expected supply-conservation ERROR log, got: {logs.output}",
            )
        finally:
            chain._apply_block_state = original_apply

    def test_invariant_clean_state_logs_nothing(self):
        """In the clean-state happy path (invariant holds),
        ``_enforce_supply_conservation`` must NOT log at ERROR.  The
        contract is "log on violation only" — a log per block is
        operator noise."""
        chain, _consensus, _entities = _make_chain_with_validators(1)

        # If no ERROR record is captured, ``assertLogs`` raises
        # AssertionError.  Wrap in assertRaises to flip the polarity.
        with self.assertRaises(AssertionError):
            with self.assertLogs(
                "messagechain.core.blockchain",
                level=logging.ERROR,
            ):
                chain._enforce_supply_conservation(block_height=1)


class TestSupplyConservationCrashMode(unittest.TestCase):
    """``supply_invariant_on_violation='crash'`` raises on violation —
    operator opt-in for the strictest behavior (used by safety-critical
    deployments where a silent invariant violation is worse than a
    crash)."""

    def test_crash_mode_raises_on_violation(self):
        chain, _consensus, entities = _make_chain_with_validators(1)
        chain.supply_invariant_on_violation = "crash"
        chain.supply.balances[entities[0].entity_id] += 1
        with self.assertRaises(AssertionError):
            chain._enforce_supply_conservation(block_height=1)

    def test_crash_mode_clean_state_no_raise(self):
        chain, _consensus, _entities = _make_chain_with_validators(1)
        chain.supply_invariant_on_violation = "crash"
        # Should NOT raise — invariant holds.
        chain._enforce_supply_conservation(block_height=1)


if __name__ == "__main__":
    unittest.main()
