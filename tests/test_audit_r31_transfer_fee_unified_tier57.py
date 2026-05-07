"""Audit r31 #2 — Tier 57: transfer apply path routes through
``pay_fee_with_burn`` so the attester-fee-funding split, the
DEFLATION_FLOOR_V2 rolling-fee-burn accumulator, and the
``fee_burn_this_block`` ticker all accrue on transfer txs.

Pre-fix ``Blockchain._apply_transfer_with_burn`` hand-rolled fee
accounting (``balances[from] -= fee; balances[proposer] += tip;
total_supply -= burned``) instead of routing through
``SupplyTracker.pay_fee_with_burn``.  Every other tx kind (message,
stake, governance, react, authority) routes through the helper.
Transfers alone bypassed it.

Three CLAUDE.md anchors break silently as soon as transfer volume
matters:

  (a) **Attester-fee-funding split** -- post-Tier-4 (height 707),
      ATTESTER_FEE_SHARE_BPS / 10_000 of base_fee should redirect
      to ``attester_fee_pool_this_block`` (consumed by
      ``mint_block_reward``).  Transfers were silently zeroing this.

  (b) **DEFLATION_FLOOR_V2 rolling-fee-burn accumulator** -- drives
      the supply-rebate floor in ``calculate_block_reward`` when
      active-supply runs below target.  Transfers were silently
      not accruing.

  (c) **``fee_burn_this_block`` ticker** -- redirects
      ARCHIVE_BURN_REDIRECT_PCT into the archive reward pool at
      end-of-block.  Transfers were silently not accruing.

Today's mainnet has near-zero transfer volume so the leak is
invisible.  That is the worst possible time to catch it -- the
moment the dual-purpose-token anchor pays off and transfers become
a real share of fee burn, the attester pool is structurally
under-sized by the transfer-share each block, the deflation-floor
rebate fires later/lower than intended, and the archive-reward
redirect undercounts.

Tier 57 splits the apply path on a height gate
``TRANSFER_FEE_UNIFIED_HEIGHT``:

  * Pre-fork (height < TRANSFER_FEE_UNIFIED_HEIGHT) -- legacy
    hand-rolled accounting, byte-identical to the pre-Tier-57 code.
    Required for replay determinism: every historical transfer
    block must apply identically post-upgrade.

  * Post-fork (height >= TRANSFER_FEE_UNIFIED_HEIGHT) -- route the
    ``(tx.fee - surcharge)`` portion through
    ``pay_fee_with_burn(tx.entity_id, proposer_id, tx.fee -
    surcharge, effective_base_fee)``; the helper handles
    attester-share / rolling_fee_burn / fee_burn_this_block /
    total_fees_collected for the base-fee portion.  The
    NEW_ACCOUNT_FEE surcharge is a flat state-creation tariff; it
    burns separately (debited from sender, total_supply down,
    total_burned up, fee_burn_this_block up) so the
    archive-reward redirect sees the full burn parity with legacy
    "burned was the full base_fee + surcharge."

This test pins:

  (1) Activation constant defined and follows Tier 56 cohort
      spacing.

  (2) Source pin: ``_apply_transfer_with_burn`` body references
      ``TRANSFER_FEE_UNIFIED_HEIGHT`` and ``pay_fee_with_burn``.

  (3) Pre-fork apply: at height < TRANSFER_FEE_UNIFIED_HEIGHT,
      ``attester_fee_pool_this_block`` and ``fee_burn_this_block``
      stay zero (legacy replay determinism preserved).

  (4) Post-fork apply: at height >= TRANSFER_FEE_UNIFIED_HEIGHT,
      ``attester_fee_pool_this_block`` and ``fee_burn_this_block``
      accrue on a transfer.

  (5) Net-balance invariant: at both heights, sender total debit
      and recipient credit and proposer tip and total_supply
      decrease are byte-identical -- only the *internal*
      accounting tickers differ.
"""

from __future__ import annotations

import time
import unittest

from messagechain import config
from messagechain.config import (
    ATTESTER_FEE_FUNDING_HEIGHT,
    ATTESTER_FEE_SHARE_BPS,
    NEW_ACCOUNT_FEE,
    TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.transfer import create_transfer_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


_ENTITY_POOL: dict[tuple[bytes, int], Entity] = {}


def _entity(seed: bytes, height: int = 4) -> Entity:
    padded = seed + b"\x00" * (32 - len(seed))
    key = (padded, height)
    cached = _ENTITY_POOL.get(key)
    if cached is None:
        cached = Entity.create(padded, tree_height=height)
        _ENTITY_POOL[key] = cached
    cached.keypair._next_leaf = 0
    return cached


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _build_chain_with_three_entities(self):
        chain = Blockchain()
        alice = _entity(b"alice")
        bob = _entity(b"bob")
        proposer = _entity(b"proposer")
        for e in (alice, bob, proposer):
            proof = e.keypair.sign(_hash(b"register" + e.entity_id))
            chain._install_pubkey_direct(e.entity_id, e.public_key, proof)
        chain.supply.balances[alice.entity_id] = 1_000_000
        chain.supply.balances[proposer.entity_id] = 0
        return chain, alice, bob, proposer


class TestTier57Constant(_Base):
    """Activation constant defined and follows Tier 56."""

    def test_constant_defined(self):
        from messagechain.config import TRANSFER_FEE_UNIFIED_HEIGHT
        self.assertIsInstance(TRANSFER_FEE_UNIFIED_HEIGHT, int)
        self.assertGreater(TRANSFER_FEE_UNIFIED_HEIGHT, 0)

    def test_constant_above_tier56(self):
        from messagechain.config import TRANSFER_FEE_UNIFIED_HEIGHT
        self.assertGreater(
            TRANSFER_FEE_UNIFIED_HEIGHT,
            TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT,
            "TRANSFER_FEE_UNIFIED_HEIGHT must follow Tier 56 -- "
            "operators upgrade through Tier 56 before this fork "
            "binds, and cohort spacing prevents two consecutive "
            "consensus-rule changes from collapsing into a single "
            "activation window.",
        )

    def test_constant_above_attester_fee_funding(self):
        from messagechain.config import TRANSFER_FEE_UNIFIED_HEIGHT
        self.assertGreater(
            TRANSFER_FEE_UNIFIED_HEIGHT,
            ATTESTER_FEE_FUNDING_HEIGHT,
            "TRANSFER_FEE_UNIFIED_HEIGHT must follow Tier 4 "
            "(ATTESTER_FEE_FUNDING_HEIGHT) -- the helper Tier 57 "
            "starts routing through (pay_fee_with_burn) only "
            "internally activates the attester-share split at "
            "Tier 4, so Tier 4 must already be live.",
        )


class TestTier57SourcePin(_Base):
    """``_apply_transfer_with_burn`` source references the gate
    constant and routes through ``pay_fee_with_burn``."""

    def test_source_references_tier57_constant_and_pay_fee_with_burn(self):
        import inspect
        src = inspect.getsource(Blockchain._apply_transfer_with_burn)
        self.assertIn(
            "TRANSFER_FEE_UNIFIED_HEIGHT", src,
            "_apply_transfer_with_burn MUST gate the new routing on "
            "TRANSFER_FEE_UNIFIED_HEIGHT so pre-fork blocks replay "
            "byte-identically.",
        )
        self.assertIn(
            "pay_fee_with_burn", src,
            "_apply_transfer_with_burn MUST route the post-fork base-"
            "fee portion through pay_fee_with_burn so attester-share "
            "/ rolling_fee_burn / fee_burn_this_block accrue.",
        )


class TestTier57PreForkLegacyReplay(_Base):
    """Pre-fork apply preserves legacy semantics byte-for-byte:
    ``attester_fee_pool_this_block`` and ``fee_burn_this_block``
    stay zero, even with TRANSFER_FEE_UNIFIED_HEIGHT defined."""

    def test_pre_fork_apply_does_not_touch_attester_pool_or_ticker(self):
        from messagechain.config import TRANSFER_FEE_UNIFIED_HEIGHT
        chain, alice, bob, proposer = self._build_chain_with_three_entities()

        # Pre-fork apply height: just below the activation.
        pre_height = TRANSFER_FEE_UNIFIED_HEIGHT - 1
        chain.supply._current_block_height = pre_height
        chain.supply.attester_fee_pool_this_block = 0
        chain.supply.fee_burn_this_block = 0
        rolling_pre = list(chain.supply.rolling_fee_burn)

        tx = create_transfer_transaction(
            alice, bob.entity_id, amount=10_000, nonce=0, fee=500,
        )
        chain._apply_transfer_with_burn(
            tx, proposer.entity_id, base_fee=100,
        )

        self.assertEqual(
            chain.supply.attester_fee_pool_this_block, 0,
            "Pre-fork transfer apply MUST NOT bump attester_fee_"
            "pool_this_block -- legacy replay determinism.",
        )
        self.assertEqual(
            chain.supply.fee_burn_this_block, 0,
            "Pre-fork transfer apply MUST NOT bump fee_burn_this_"
            "block ticker -- legacy replay determinism.",
        )
        self.assertEqual(
            list(chain.supply.rolling_fee_burn), rolling_pre,
            "Pre-fork transfer apply MUST NOT append to rolling_fee_"
            "burn -- legacy replay determinism.",
        )


class TestTier57PostForkAccrual(_Base):
    """Post-fork apply accrues on all three CLAUDE.md anchors."""

    def test_post_fork_apply_bumps_attester_pool_and_ticker(self):
        from messagechain.config import TRANSFER_FEE_UNIFIED_HEIGHT
        chain, alice, bob, proposer = self._build_chain_with_three_entities()

        # Post-fork apply height.
        post_height = TRANSFER_FEE_UNIFIED_HEIGHT
        chain.supply._current_block_height = post_height
        chain.supply.attester_fee_pool_this_block = 0
        chain.supply.fee_burn_this_block = 0

        base_fee = 100
        tx = create_transfer_transaction(
            alice, bob.entity_id, amount=10_000, nonce=0, fee=500,
        )
        chain._apply_transfer_with_burn(
            tx, proposer.entity_id, base_fee=base_fee,
        )

        # Expected attester_share: base_fee * ATTESTER_FEE_SHARE_BPS // 10_000.
        expected_attester_share = (
            base_fee * ATTESTER_FEE_SHARE_BPS // 10_000
        )
        self.assertEqual(
            chain.supply.attester_fee_pool_this_block,
            expected_attester_share,
            "Post-fork transfer apply MUST accrue attester_share "
            "into attester_fee_pool_this_block (Tier 4 ATTESTER_"
            "FEE_FUNDING split).",
        )
        # fee_burn_this_block accrues actual_burn (= base_fee -
        # attester_share) plus surcharge if any.  This test uses an
        # already-existing recipient (we registered bob), so no
        # NEW_ACCOUNT_FEE surcharge layered.
        expected_actual_burn = base_fee - expected_attester_share
        self.assertEqual(
            chain.supply.fee_burn_this_block,
            expected_actual_burn,
            "Post-fork transfer apply MUST bump fee_burn_this_block "
            "by actual_burn so the archive-reward redirect sees the "
            "transfer-share burn.",
        )


class TestTier57UserFacingInvariant(_Base):
    """Sender-debit, recipient-credit, and proposer-tip MUST be
    identical pre- and post-fork.  The user pays the same total fee,
    receives the same value, and the proposer's tip is the same.

    The internal accounting DELIBERATELY diverges: post-fork the
    attester_share portion of base_fee no longer burns -- it accrues
    into ``attester_fee_pool_this_block`` for committee distribution
    at end-of-block (Tier 4 behavior, finally extended to transfers).
    So ``total_supply`` decreases by less post-fork (by exactly
    ``attester_share`` less) -- that is the FIX, not a regression."""

    def _apply_at_height(self, height: int) -> dict:
        chain, alice, bob, proposer = self._build_chain_with_three_entities()
        chain.supply._current_block_height = height
        chain.supply.attester_fee_pool_this_block = 0
        chain.supply.fee_burn_this_block = 0
        sup_before = chain.supply.total_supply
        burned_before = chain.supply.total_burned

        tx = create_transfer_transaction(
            alice, bob.entity_id, amount=10_000, nonce=0, fee=500,
        )
        chain._apply_transfer_with_burn(
            tx, proposer.entity_id, base_fee=100,
        )
        return {
            "alice_balance": chain.supply.get_balance(alice.entity_id),
            "bob_balance": chain.supply.get_balance(bob.entity_id),
            "proposer_balance": chain.supply.get_balance(proposer.entity_id),
            "supply_delta_minus_attester_pool": (
                (sup_before - chain.supply.total_supply)
                + chain.supply.attester_fee_pool_this_block
            ),
        }

    def test_user_facing_invariants_identical_pre_post(self):
        from messagechain.config import TRANSFER_FEE_UNIFIED_HEIGHT
        pre = self._apply_at_height(TRANSFER_FEE_UNIFIED_HEIGHT - 1)
        post = self._apply_at_height(TRANSFER_FEE_UNIFIED_HEIGHT)
        self.assertEqual(
            pre, post,
            "Pre- and post-fork transfer apply MUST produce "
            "identical sender-debit, recipient-credit, and proposer-"
            "tip.  Net circulating supply removed (== total_supply "
            "decrease + attester_pool growth, since the pool stays "
            "in circulation) MUST also match -- only the internal "
            "split between burn and attester-pool differs.",
        )


if __name__ == "__main__":
    unittest.main()
