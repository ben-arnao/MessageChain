"""Tier 49 — unified fee floor across non-message tx types.

Pre-Tier-49 admission for transfer / stake / unstake enforced
``tx.fee >= max(MIN_FEE, MARKET_FEE_FLOOR) = max(100, 1) = 100``,
while message-tx admission used the Tier-16 ``MARKET_FEE_FLOOR=1``
directly — same fee model, 100x different floor across tx kinds.
That violates the CLAUDE.md fee-model anchor "Every tx type the chain
accepts ... follows this same fee model.  Don't carve out per-type
fee logic" and structurally crowds messages out of the mempool at the
floor: a transfer at 96 stored bytes paying 100 tokens is fee-per-byte
1.04, while a message at ~280 bytes paying 1 token is fee-per-byte
0.0036, so fee-per-byte ranking always evicts messages first.

At/after ``UNIFIED_FEE_FLOOR_HEIGHT`` the protocol baseline collapses
to ``MARKET_FEE_FLOOR=1`` for transfer / stake / unstake admission,
matching reaction (Tier 18) and message (Tier 16).  Type-specific
surcharges that legitimately bind above the protocol floor
(``NEW_ACCOUNT_FEE`` on transfer, ``KEY_ROTATION_FEE``,
``GOVERNANCE_PROPOSAL_FEE``, ...) are unaffected — they layer on top
of the unified floor at their respective callsites.

Pre-fork heights replay byte-identically because every historical
transfer / stake / unstake on chain paid >= MIN_FEE=100 anyway —
the verifier admits everything it admitted before; only new low-fee
txs become acceptable post-fork.
"""
from __future__ import annotations

import os
import time
import unittest

from messagechain.config import (
    MARKET_FEE_FLOOR,
    MIN_FEE,
    UNIFIED_FEE_FLOOR_HEIGHT,
    WITNESS_ROOT_ACTIVATION_HEIGHT,
)
from messagechain.core.staking import (
    create_stake_transaction,
    create_unstake_transaction,
    verify_stake_transaction,
    verify_unstake_transaction,
)
from messagechain.core.transfer import (
    create_transfer_transaction,
    verify_transfer_transaction,
)
from messagechain.identity.identity import Entity


# ── Activation gate sanity ──────────────────────────────────────────


class TestActivationHeightOrdering(unittest.TestCase):
    def test_unified_fee_floor_above_witness_root_tier(self):
        # Tier 49 must follow Tier 48 — operators upgrade through the
        # existing fork band before this admission-rule change binds.
        self.assertGreater(
            UNIFIED_FEE_FLOOR_HEIGHT, WITNESS_ROOT_ACTIVATION_HEIGHT
        )

    def test_market_fee_floor_strictly_below_min_fee(self):
        # The whole point of Tier 49 — there's a meaningful gap between
        # the unified protocol floor (MARKET_FEE_FLOOR=1) and the
        # legacy non-message floor (MIN_FEE=100) that needed closing.
        self.assertLess(MARKET_FEE_FLOOR, MIN_FEE)


# ── Verifier: pre-fork rejects sub-MIN_FEE, post-fork accepts ───────


def _entity():
    return Entity.create(os.urandom(32))


class TestTransferUnifiedFloor(unittest.TestCase):
    def test_pre_fork_rejects_below_min_fee(self):
        sender = _entity()
        recipient = _entity()
        tx = create_transfer_transaction(
            sender, recipient.entity_id, amount=100, nonce=1,
            fee=MARKET_FEE_FLOOR,  # 1 token — below MIN_FEE=100
            include_pubkey=True,
        )
        # Admitted at a pre-Tier-49 height: legacy MIN_FEE=100 binds.
        self.assertFalse(
            verify_transfer_transaction(
                tx, sender.public_key,
                current_height=UNIFIED_FEE_FLOOR_HEIGHT - 1,
            ),
            "pre-fork transfer at fee=MARKET_FEE_FLOOR must be rejected",
        )

    def test_post_fork_accepts_at_market_fee_floor(self):
        sender = _entity()
        recipient = _entity()
        tx = create_transfer_transaction(
            sender, recipient.entity_id, amount=100, nonce=1,
            fee=MARKET_FEE_FLOOR,
            include_pubkey=True,
        )
        self.assertTrue(
            verify_transfer_transaction(
                tx, sender.public_key,
                current_height=UNIFIED_FEE_FLOOR_HEIGHT,
            ),
            "post-fork transfer at fee=MARKET_FEE_FLOOR must be accepted",
        )

    def test_post_fork_rejects_below_market_fee_floor(self):
        # Zero-fee path stays closed — MARKET_FEE_FLOOR=1 is still the
        # spam-gate floor, and no path may round under it.
        sender = _entity()
        recipient = _entity()
        tx = create_transfer_transaction(
            sender, recipient.entity_id, amount=100, nonce=1,
            fee=0,
            include_pubkey=True,
        )
        self.assertFalse(
            verify_transfer_transaction(
                tx, sender.public_key,
                current_height=UNIFIED_FEE_FLOOR_HEIGHT,
            ),
            "post-fork transfer at fee=0 must remain rejected",
        )

    def test_pre_fork_history_replays_byte_identically(self):
        # Every historical transfer paid >= MIN_FEE=100, so a tx at
        # the legacy floor must still be admitted under both pre- and
        # post-fork rules.  Tier 49 is strictly relaxing — never tightening.
        sender = _entity()
        recipient = _entity()
        tx = create_transfer_transaction(
            sender, recipient.entity_id, amount=100, nonce=1,
            fee=MIN_FEE,
            include_pubkey=True,
        )
        for height in (
            UNIFIED_FEE_FLOOR_HEIGHT - 1,
            UNIFIED_FEE_FLOOR_HEIGHT,
            UNIFIED_FEE_FLOOR_HEIGHT + 100,
        ):
            self.assertTrue(
                verify_transfer_transaction(
                    tx, sender.public_key, current_height=height,
                ),
                f"transfer at MIN_FEE must remain admissible at height={height}",
            )


class TestStakeUnstakeUnifiedFloor(unittest.TestCase):
    def test_stake_pre_fork_rejects_below_min_fee(self):
        ent = _entity()
        tx = create_stake_transaction(
            ent, amount=10_000, nonce=1, fee=MARKET_FEE_FLOOR,
            include_pubkey=True,
        )
        self.assertFalse(
            verify_stake_transaction(
                tx, ent.public_key,
                current_height=UNIFIED_FEE_FLOOR_HEIGHT - 1,
                min_stake_override=10_000,
            ),
            "pre-fork stake at fee=MARKET_FEE_FLOOR must be rejected",
        )

    def test_stake_post_fork_accepts_at_market_fee_floor(self):
        ent = _entity()
        tx = create_stake_transaction(
            ent, amount=10_000, nonce=1, fee=MARKET_FEE_FLOOR,
            include_pubkey=True,
        )
        self.assertTrue(
            verify_stake_transaction(
                tx, ent.public_key,
                current_height=UNIFIED_FEE_FLOOR_HEIGHT,
                min_stake_override=10_000,
            ),
            "post-fork stake at fee=MARKET_FEE_FLOOR must be accepted",
        )

    def test_unstake_pre_fork_rejects_below_min_fee(self):
        ent = _entity()
        tx = create_unstake_transaction(
            ent, amount=1_000, nonce=2, fee=MARKET_FEE_FLOOR,
        )
        self.assertFalse(
            verify_unstake_transaction(
                tx, ent.public_key,
                current_height=UNIFIED_FEE_FLOOR_HEIGHT - 1,
            ),
            "pre-fork unstake at fee=MARKET_FEE_FLOOR must be rejected",
        )

    def test_unstake_post_fork_accepts_at_market_fee_floor(self):
        ent = _entity()
        tx = create_unstake_transaction(
            ent, amount=1_000, nonce=2, fee=MARKET_FEE_FLOOR,
        )
        self.assertTrue(
            verify_unstake_transaction(
                tx, ent.public_key,
                current_height=UNIFIED_FEE_FLOOR_HEIGHT,
            ),
            "post-fork unstake at fee=MARKET_FEE_FLOOR must be accepted",
        )


# ── auto_fee mirrors the verifier rule ──────────────────────────────


class TestAutoFeeMirrorsUnifiedFloor(unittest.TestCase):
    """The wallet/CLI auto-fee path (`messagechain.economics.auto_fee`)
    must quote at the same floor the verifier admits at.  Any drift
    re-introduces the 100x over-quote the agent surfaced — the auto-fee
    anchor explicitly says "any wallet/CLI helper that picks a fee for
    the user computes a target fee-per-byte from current mempool
    conditions and multiplies by the tx's stored byte count.  When the
    fee model shifts, every auto-fee path shifts with it"."""

    def test_transfer_floor_quotes_at_market_fee_floor_post_fork(self):
        from messagechain.economics.auto_fee import _transfer_floor
        # Existing-recipient (no NEW_ACCOUNT_FEE surcharge): the bare
        # protocol floor must collapse to MARKET_FEE_FLOOR.
        self.assertEqual(
            _transfer_floor(
                current_height=UNIFIED_FEE_FLOOR_HEIGHT,
                recipient_is_new=False,
            ),
            MARKET_FEE_FLOOR,
        )

    def test_transfer_floor_quotes_at_min_fee_pre_fork(self):
        from messagechain.economics.auto_fee import _transfer_floor
        self.assertEqual(
            _transfer_floor(
                current_height=UNIFIED_FEE_FLOOR_HEIGHT - 1,
                recipient_is_new=False,
            ),
            MIN_FEE,
        )

    def test_stake_floor_quotes_at_market_fee_floor_post_fork(self):
        from messagechain.economics.auto_fee import _stake_floor
        self.assertEqual(
            _stake_floor(current_height=UNIFIED_FEE_FLOOR_HEIGHT),
            MARKET_FEE_FLOOR,
        )

    def test_unstake_floor_quotes_at_market_fee_floor_post_fork(self):
        from messagechain.economics.auto_fee import _unstake_floor
        self.assertEqual(
            _unstake_floor(current_height=UNIFIED_FEE_FLOOR_HEIGHT),
            MARKET_FEE_FLOOR,
        )

    def test_transfer_new_account_surcharge_layers_on_top(self):
        # NEW_ACCOUNT_FEE is a type-specific surcharge that binds above
        # the protocol floor — Tier 49 collapses the floor but the
        # surcharge is unaffected.
        from messagechain.config import NEW_ACCOUNT_FEE
        from messagechain.economics.auto_fee import _transfer_floor
        post_fork = _transfer_floor(
            current_height=UNIFIED_FEE_FLOOR_HEIGHT,
            recipient_is_new=True,
        )
        self.assertEqual(post_fork, MARKET_FEE_FLOOR + NEW_ACCOUNT_FEE)


if __name__ == "__main__":
    unittest.main()
