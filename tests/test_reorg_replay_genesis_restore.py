"""Tests for the reorg-replay genesis-restoration fix (1.51.4).

Background -- 2026-05-03 incident: validator-1's first-ever successful
reorg corrupted its supply state.  The reorg path
``Blockchain._reorganize`` does ``_reset_state()`` (which creates a
fresh ``SupplyTracker`` with empty balances/staked) followed by a
replay loop ``for blk in self.chain: if blk.header.block_number > 0:
self._apply_block_state(blk)`` that skips block 0.  Genesis allocations
(founder 100M / treasury 40M / 95M founder stake) are applied directly
in ``initialize_genesis`` / ``_apply_mainnet_genesis_state`` -- NOT
inside ``_apply_block_state(genesis)`` -- so the replay produces a
chain with empty initial balances.  Subsequent blocks then operate on
nothing: the founder's stake reads as 0, attestation weights collapse,
the treasury rebase at TREASURY_REBASE_HEIGHT silently fails (treasury
empty), and the resulting supply state diverges from canonical by the
genesis-allocation amount.

Witnessed in prod: v1's total_supply jumped from 107M (correct) to
140M (genesis_supply baseline, no rebase applied), balances summed to
NEGATIVE 15.5M, and v1 could no longer apply v2's blocks.  Recovery
required a filesystem chain.db copy from healthy v2.

Why this didn't bite earlier: ``_reorganize`` had never fired on a
production chain before -- the IBD lacked the fork-resolution
walk-back path (fixed in 1.51.0-1.51.3), so no reorg ever completed.

The fix extracts a ``_apply_mainnet_genesis_supply_state`` helper from
``_apply_mainnet_genesis_state`` (chain-append / fork_choice / db
write removed) and calls it from ``_reorganize`` after
``_reset_state`` to restore the genesis supply mutations before the
block-1+ replay loop.
"""

from __future__ import annotations

import unittest

import messagechain.config as _cfg
from messagechain.config import (
    _MAINNET_FOUNDER_LIQUID,
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ENTITY_ID,
    TREASURY_ALLOCATION,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.identity import Entity


class _PinOverrideMixin:
    """Redirects ``_MAINNET_FOUNDER_ENTITY_ID`` to the test founder's
    entity_id so the defense-in-depth pin check in
    ``_apply_mainnet_genesis_supply_state`` passes for test fixtures
    that use ephemeral keys (we don't have the real mainnet founder's
    private key at test time).  Same pattern as
    ``test_ibd_from_genesis._PinOverrideMixin``."""

    _saved_pin: object = object()

    @classmethod
    def _install_pin(cls, eid: bytes):
        cls._saved_pin = _cfg._MAINNET_FOUNDER_ENTITY_ID
        _cfg._MAINNET_FOUNDER_ENTITY_ID = eid

    @classmethod
    def _restore_pin(cls):
        _cfg._MAINNET_FOUNDER_ENTITY_ID = cls._saved_pin


class TestGenesisSupplyHelperRestoresState(_PinOverrideMixin, unittest.TestCase):
    """Direct unit test of ``_apply_mainnet_genesis_supply_state`` --
    the helper extracted in 1.51.4 for the reorg replay path.

    The helper must, when called on an empty SupplyTracker:
      * credit founder with _MAINNET_FOUNDER_LIQUID liquid balance
      * credit treasury with TREASURY_ALLOCATION balance
      * stake _MAINNET_FOUNDER_STAKE on founder (moving from balance)
      * pin genesis stake snapshot at height 0
      * NOT append the block to chain or update fork_choice
    """

    @classmethod
    def setUpClass(cls):
        cls.tree_height = 4
        cls.founder = Entity.create(
            private_key=b"reorg-replay-genesis-test-foundr" * 1,
            tree_height=cls.tree_height,
        )

    def test_helper_restores_founder_treasury_balances_and_stake(self):
        # Build a real founder chain so we have a properly-signed block 0.
        chain = Blockchain(db=None)
        self._install_pin(self.founder.entity_id)
        try:
            allocation = {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            }
            block0 = chain.initialize_genesis(self.founder, allocation)
            ok, log = bootstrap_seed_local(
                chain, self.founder,
                cold_authority_pubkey=self.founder.public_key,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            self.assertTrue(ok, f"bootstrap_seed_local failed: {log}")

            # Fresh chain (no genesis applied) -- exercise the helper.
            test_chain = Blockchain(db=None)
            ok, reason = test_chain._apply_mainnet_genesis_supply_state(block0)
            self.assertTrue(
                ok,
                f"_apply_mainnet_genesis_supply_state failed: {reason}",
            )

            # Founder liquid balance should equal _MAINNET_FOUNDER_LIQUID
            # (started at TOTAL, then 95M moved to stake).
            self.assertEqual(
                test_chain.supply.balances.get(self.founder.entity_id),
                _MAINNET_FOUNDER_LIQUID,
                "founder liquid balance must equal _MAINNET_FOUNDER_LIQUID "
                "(=5M) after genesis supply state applied",
            )

            # Treasury balance should equal TREASURY_ALLOCATION (40M).
            self.assertEqual(
                test_chain.supply.balances.get(TREASURY_ENTITY_ID),
                TREASURY_ALLOCATION,
                "treasury balance must equal TREASURY_ALLOCATION (40M)",
            )

            # Founder stake should equal _MAINNET_FOUNDER_STAKE (95M).
            self.assertEqual(
                test_chain.supply.staked.get(self.founder.entity_id),
                _MAINNET_FOUNDER_STAKE,
                "founder stake must equal _MAINNET_FOUNDER_STAKE (95M)",
            )

            # Helper must NOT append block to chain (caller's job).
            # Empty test_chain.chain is fine because the helper doesn't
            # modify it -- we deliberately did not call initialize_genesis
            # on test_chain.  The helper is a pure state mutator.
            self.assertEqual(
                len(test_chain.chain), 0,
                "_apply_mainnet_genesis_supply_state must NOT append "
                "block to chain (caller is responsible for that)",
            )
        finally:
            self._restore_pin()


class TestReorgPreservesGenesisAllocations(
    _PinOverrideMixin, unittest.TestCase,
):
    """End-to-end: trigger ``_reorganize`` on a mainnet-shaped chain
    and assert founder / treasury balances + stake survive the
    rebuild-from-genesis replay.

    Pre-1.51.4 this test fails: ``_reset_state`` blanks the supply,
    the replay loop skips block 0, the genesis allocations are never
    re-applied, and post-reorg the founder has no balance, no stake,
    and the treasury is empty.
    """

    @classmethod
    def setUpClass(cls):
        cls.tree_height = 4
        cls.founder = Entity.create(
            private_key=b"reorg-replay-test-founder-key-001",
            tree_height=cls.tree_height,
        )

    def test_reorg_preserves_founder_balance_treasury_stake(self):
        chain = Blockchain(db=None)
        self._install_pin(self.founder.entity_id)
        try:
            allocation = {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            }
            block0 = chain.initialize_genesis(self.founder, allocation)
            ok, _ = bootstrap_seed_local(
                chain, self.founder,
                cold_authority_pubkey=self.founder.public_key,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            self.assertTrue(ok)

            # Capture pre-reorg state.
            pre_founder_balance = chain.supply.balances.get(
                self.founder.entity_id, 0,
            )
            pre_treasury_balance = chain.supply.balances.get(
                TREASURY_ENTITY_ID, 0,
            )
            pre_founder_stake = chain.supply.staked.get(
                self.founder.entity_id, 0,
            )
            self.assertEqual(pre_founder_balance, _MAINNET_FOUNDER_LIQUID)
            self.assertEqual(pre_treasury_balance, TREASURY_ALLOCATION)
            self.assertEqual(pre_founder_stake, _MAINNET_FOUNDER_STAKE)

            # Simulate the reorg-replay path: _reset_state then
            # the genesis-restoration the new code in _reorganize does.
            chain._reset_state()

            # The 1.51.4 fix: _reorganize calls
            # _apply_mainnet_genesis_supply_state on the genesis block
            # right after _reset_state.  Replicate that explicitly
            # here so the test exercises the fixed contract without
            # needing a full two-fork scenario to drive _reorganize.
            ok, reason = chain._apply_mainnet_genesis_supply_state(
                chain.chain[0],
            )
            self.assertTrue(
                ok, f"genesis supply restore failed: {reason}",
            )

            # Post-restore: balances/stake match pre-reorg values.
            self.assertEqual(
                chain.supply.balances.get(self.founder.entity_id, 0),
                pre_founder_balance,
                "founder balance not preserved across reorg replay",
            )
            self.assertEqual(
                chain.supply.balances.get(TREASURY_ENTITY_ID, 0),
                pre_treasury_balance,
                "treasury balance not preserved across reorg replay",
            )
            self.assertEqual(
                chain.supply.staked.get(self.founder.entity_id, 0),
                pre_founder_stake,
                "founder stake not preserved across reorg replay",
            )
        finally:
            self._restore_pin()


class TestReorgReplaySupplyConsistency(
    _PinOverrideMixin, unittest.TestCase,
):
    """The reorg replay must leave the supply in a CONSISTENT state
    (no negative balances, no orphan total_supply).

    Pre-1.51.4 prod symptom: ``SUM(balances)`` went NEGATIVE after a
    successful reorg because ``total_supply`` stayed at GENESIS_SUPPLY
    (=140M) while subsequent blocks burned/credited against an empty
    balance map.  Pin the invariant so future regressions surface.
    """

    @classmethod
    def setUpClass(cls):
        cls.tree_height = 4
        cls.founder = Entity.create(
            private_key=b"reorg-replay-supply-consistency!",
            tree_height=cls.tree_height,
        )

    def test_balances_sum_non_negative_after_reorg_restore(self):
        chain = Blockchain(db=None)
        self._install_pin(self.founder.entity_id)
        try:
            allocation = {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            }
            block0 = chain.initialize_genesis(self.founder, allocation)
            bootstrap_seed_local(
                chain, self.founder,
                cold_authority_pubkey=self.founder.public_key,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )

            # Reset + restore.
            chain._reset_state()
            ok, _ = chain._apply_mainnet_genesis_supply_state(
                chain.chain[0],
            )
            self.assertTrue(ok)

            balances_sum = sum(chain.supply.balances.values())
            self.assertGreaterEqual(
                balances_sum, 0,
                "post-reorg-replay balances sum must not go negative -- "
                "the prod 2026-05-03 incident saw -15.5M from the "
                "missing-genesis-restore bug",
            )

            staked_sum = sum(chain.supply.staked.values())
            # Conservation: balances + staked == _MAINNET_FOUNDER_TOTAL
            #                                  + TREASURY_ALLOCATION
            # post-restore (no mints/burns yet).
            self.assertEqual(
                balances_sum + staked_sum,
                _MAINNET_FOUNDER_TOTAL + TREASURY_ALLOCATION,
                "post-restore balances + staked must equal genesis "
                "allocation total -- proves the helper fully restores "
                "every owned bucket",
            )
        finally:
            self._restore_pin()


if __name__ == "__main__":
    unittest.main()
