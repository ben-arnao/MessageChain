"""Tier 64 -- per-entity cap on the forced-inclusion FORCED SET.

Pre-fix: ``Mempool.get_forced_inclusion_set`` ranks qualifying txs by
``(-fee_per_byte, arrival_height, tx_hash)`` and slices the top
``FORCED_INCLUSION_SET_SIZE`` -- with NO per-entity cap on the source
set itself.  Tier 37's per-entity cap fix
(``FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT``) tightens excuse #3 on the
*proposer-validator* axis, but the *attester-side* forced source set
this fix governs has no equivalent guard.

Concrete attack: a colluding cartel pays a high stake-weighted entity
to flood the mempool with N high-fpb txs from a single ``entity_id``
(or the cartel's own entity).  After ``FORCED_INCLUSION_WAIT_BLOCKS``
those N txs occupy the top ``FORCED_INCLUSION_SET_SIZE`` slots,
evicting the censored victim's lower-fpb tx from the forced set
entirely.  The cartel proposer can then exclude the victim without
triggering excuse #3 (the block-level
``MAX_TXS_PER_ENTITY_PER_BLOCK = 3`` cap binds in the proposer's
output but NOT in the attester's *forced source* set), and without
triggering excuse #1 (block byte budget) -- the censored tx is simply
not in the forced set anymore.

CLAUDE.md anchor at risk: "a tx that is well-formed, pays at least
the per-byte floor, and fits the byte budget cannot be suppressed by
anything weaker than a full validator-set majority actively colluding
AND willing to absorb the slashing risk that exposed collusion
produces."  Pre-fix the cartel pays only a small per-displaced-tx
premium for a high-fpb flood -- well below the slashing risk
threshold the anchor calls for.

Tier 64 fix: post-activation
``get_forced_inclusion_set`` walks the sorted qualifying list and
applies a per-entity cap of ``MAX_TXS_PER_ENTITY_PER_BLOCK = 3`` (the
same cap the block validator already enforces in proposer output, so
forcing more than 3 from one entity per block is meaningless --
beyond that count the proposer literally cannot fit them).  Pre-fork
the legacy uncapped path runs byte-identically so historical attester
votes replay byte-identically.

Soft-fork: the forced source set is per-attester local state, not
consensus-relevant block content.  Different attesters can see
different mempool views and the soft-vote aggregation handles
divergence; the rule change rolls in via height-gated cohort spacing
matching the Tier 49-63 pattern.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    FEE_PER_BYTE,
    FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT,
    FORCED_INCLUSION_SET_SIZE,
    FORCED_INCLUSION_WAIT_BLOCKS,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
    MIN_FEE,
    STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT,
)
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity


_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)
_BASE_FEE = MIN_FEE + 10 * FEE_PER_BYTE


def _make_tx(entity: Entity, fee: int, nonce: int):
    return create_transaction(entity, f"msg {nonce}", fee=fee, nonce=nonce)


class TestActivationConstantOrdering(unittest.TestCase):
    """Tier 64 activates above the most-recent prior tier (63)."""

    def test_height_above_tier_63(self):
        self.assertGreater(
            FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT,
            STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT,
        )

    def test_cohort_spacing_matches_tier_pattern(self):
        gap = (
            FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
            - STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT
        )
        self.assertGreaterEqual(gap, 50)


class TestPreForkUncappedFlood(unittest.TestCase):
    """Pre-fork (height < activation) the forced source set must NOT
    apply the per-entity cap -- legacy attester votes replay byte-
    identically.  A single-entity flood of high-fpb txs occupies all
    FORCED_INCLUSION_SET_SIZE slots exactly as before the fix."""

    def setUp(self):
        self.whale = Entity.create(b"whale-priv-key".ljust(32, b"\x00"))
        # Boost per_sender_limit to allow more than the default 5
        # same-entity txs into the pool, so the test exercises the cap
        # even if FORCED_INCLUSION_SET_SIZE moves.
        self.pool = Mempool(
            max_size=200, per_sender_limit=20, fee_policy=_STATIC_FEE,
        )

    def test_pre_fork_flood_fills_all_forced_slots_from_one_entity(self):
        # Whale flood: many high-fpb same-entity txs.
        n_flood = FORCED_INCLUSION_SET_SIZE + 3
        for i in range(n_flood):
            tx = _make_tx(
                self.whale, fee=_BASE_FEE + 5_000 + i, nonce=i,
            )
            self.pool.add_transaction(tx, arrival_block_height=10)
        current = FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT - 1
        # Sanity: current is past the wait window
        self.assertGreater(
            current - 10, FORCED_INCLUSION_WAIT_BLOCKS,
        )
        forced = self.pool.get_forced_inclusion_set(current)
        # Pre-fork: ALL forced slots come from the whale.
        self.assertEqual(len(forced), FORCED_INCLUSION_SET_SIZE)
        whale_id = self.whale.entity_id
        self.assertTrue(
            all(tx.entity_id == whale_id for tx in forced),
            "pre-fork forced set must legacy-allow same-entity fill of "
            "every slot",
        )


class TestPostForkPerEntityCapBinds(unittest.TestCase):
    """Post-fork (height >= activation) a single-entity flood is capped
    to MAX_TXS_PER_ENTITY_PER_BLOCK of FORCED_INCLUSION_SET_SIZE slots,
    leaving room for other entities' lower-fpb txs to reach the forced
    set.  Closes the cartel-flood-evicts-victim attack surface."""

    def setUp(self):
        self.whale = Entity.create(b"whale-cap".ljust(32, b"\x00"))
        self.victim = Entity.create(b"victim-cap".ljust(32, b"\x00"))
        self.pool = Mempool(
            max_size=200, per_sender_limit=20, fee_policy=_STATIC_FEE,
        )

    def test_post_fork_caps_single_entity_at_max_txs_per_block(self):
        # Whale flood: many same-entity high-fpb txs.
        for i in range(FORCED_INCLUSION_SET_SIZE + 3):
            tx = _make_tx(
                self.whale, fee=_BASE_FEE + 5_000 + i, nonce=i,
            )
            self.pool.add_transaction(tx, arrival_block_height=10)
        # Victim's single lower-fpb tx in the same wait window.
        victim_tx = _make_tx(self.victim, fee=_BASE_FEE + 100, nonce=0)
        self.pool.add_transaction(victim_tx, arrival_block_height=10)

        current = FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
        forced = self.pool.get_forced_inclusion_set(current)

        # Cap binds: at most MAX_TXS_PER_ENTITY_PER_BLOCK from the whale.
        whale_id = self.whale.entity_id
        whale_count = sum(1 for tx in forced if tx.entity_id == whale_id)
        self.assertLessEqual(
            whale_count, MAX_TXS_PER_ENTITY_PER_BLOCK,
            f"post-fork forced set must cap whale flood at "
            f"MAX_TXS_PER_ENTITY_PER_BLOCK={MAX_TXS_PER_ENTITY_PER_BLOCK}; "
            f"got {whale_count}",
        )

    def test_post_fork_victim_reaches_forced_set(self):
        """The freed slots after capping must be filled by the next-
        ranked txs from OTHER entities -- specifically, a censored
        victim's tx that pre-fork would have been evicted entirely."""
        for i in range(FORCED_INCLUSION_SET_SIZE + 3):
            tx = _make_tx(
                self.whale, fee=_BASE_FEE + 5_000 + i, nonce=i,
            )
            self.pool.add_transaction(tx, arrival_block_height=10)
        victim_tx = _make_tx(self.victim, fee=_BASE_FEE + 100, nonce=0)
        self.pool.add_transaction(victim_tx, arrival_block_height=10)

        current = FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
        forced = self.pool.get_forced_inclusion_set(current)

        forced_hashes = {tx.tx_hash for tx in forced}
        self.assertIn(
            victim_tx.tx_hash, forced_hashes,
            "post-fork: lower-fpb victim tx from a non-flooding entity "
            "must reach the forced set once the per-entity cap frees "
            "slots from the whale flood",
        )


class TestPostForkHealthyMixUnaffected(unittest.TestCase):
    """A healthy mix of one-tx-per-entity at varying fpb is below the
    cap on every entity -- the post-fork rule must produce the same
    forced set as the pre-fork rule for this case."""

    def setUp(self):
        self.entities = [
            Entity.create(f"healthy-{i}".encode().ljust(32, b"\x00"))
            for i in range(FORCED_INCLUSION_SET_SIZE + 3)
        ]
        self.pool = Mempool(
            max_size=200, per_sender_limit=20, fee_policy=_STATIC_FEE,
        )
        for i, e in enumerate(self.entities):
            tx = _make_tx(e, fee=_BASE_FEE + i * 200, nonce=0)
            self.pool.add_transaction(tx, arrival_block_height=10)

    def test_healthy_mix_post_fork_equals_pre_fork(self):
        current_post = FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
        current_pre = FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT - 1
        forced_post = self.pool.get_forced_inclusion_set(current_post)
        forced_pre = self.pool.get_forced_inclusion_set(current_pre)
        self.assertEqual(
            [tx.tx_hash for tx in forced_post],
            [tx.tx_hash for tx in forced_pre],
            "healthy multi-entity mix must produce the same forced set "
            "pre-fork and post-fork (no entity is over the cap)",
        )


if __name__ == "__main__":
    unittest.main()
