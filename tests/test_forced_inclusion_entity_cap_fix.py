"""Tier 37 — forced-inclusion entity-cap excuse no longer accepts a
same-entity lower-fpb fill.

Pre-Tier-37 the gate's excuse #3 ("entity already at
MAX_TXS_PER_ENTITY_PER_BLOCK") counted EVERY tx the proposer included
from the forced tx's entity toward the cap — including same-entity
txs at LOWER fee-per-byte than the forced tx itself.  A colluding
proposer with multiple pending lower-fpb txs from a single victim
entity at sequential nonces could include those (filling the entity
quota) and then "excuse" the higher-fpb forced tx of the same entity
under excuse #3.  Because nonces must be sequential the forced tx IS
the next includable nonce after the fill — it always fits
structurally, the cap was an artifact of the proposer's own selection,
and the slashing risk on the inclusion-list-abuse surface collapsed
to zero.  This breaks the CLAUDE.md anchor that "a tx that is
well-formed, pays at least the per-byte floor, and fits the byte
budget cannot be suppressed by anything weaker than a full validator-
set majority actively colluding."

Tier 37 tightens excuse #3: when evaluating the cap for a forced tx,
same-entity block txs whose fee-per-byte is STRICTLY LOWER than the
forced tx's fee-per-byte do NOT count toward the cap.  Equivalent
phrasing: the cap binds only on same-entity block txs the proposer
*could not* have replaced with the forced tx without lowering revenue
density — anything LESS-dense than the forced tx is the proposer's
own selection artifact, not a real reason to skip.

Pre-fork: byte-identical to legacy excuse-#3 logic for replay
determinism.  Post-fork: the same-entity lower-fpb fill is no longer
a valid excuse.

Tests pin:
  * Pre-fork: a colluding block that fills MAX_TXS_PER_ENTITY_PER_BLOCK
    with lower-fpb txs from the victim and omits a higher-fpb forced
    tx of the same entity is wrongly ACCEPTED (legacy bug — preserved
    for replay determinism).
  * Post-fork: the same block is correctly REJECTED with a
    censorship-omission reason.
  * Post-fork: an HONEST block that fills the cap with same-entity
    txs at >= the forced tx's fpb is still excused (the rule does not
    over-fire on legitimate full-quota cases).
  * Activation-height ordering: Tier 37 must follow Tier 36.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    ATTESTER_DYNAMIC_COMMITTEE_HEIGHT,
    FEE_PER_BYTE,
    FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
    FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT,
    FORCED_INCLUSION_WAIT_BLOCKS,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
    MIN_FEE,
)
from messagechain.consensus.forced_inclusion import check_forced_inclusion
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity


PRE_T37 = FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT - 1
POST_T37 = FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT

# Tier 37 must land above Tier 34 (the multi-list path is the
# prerequisite — pre-Tier-34 the gate doesn't enforce excuse #3 against
# anything except message-only blocks, so the cap-fix only adds value
# on top of the multi-list semantics).
_LOW_FEE = MIN_FEE + 10 * FEE_PER_BYTE  # ~130 — above floor, low fpb
_HIGH_FEE = _LOW_FEE * 50                # 50× — clearly higher fpb

_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)


def _make_msg(entity: Entity, fee: int, nonce: int):
    return create_transaction(entity, f"msg {nonce}", fee=fee, nonce=nonce)


class _FakeBlock:
    """Minimal Block stand-in carrying every tx-list field the gate
    walks under the Tier-34 multi-list path.  Avoids the full Block
    apparatus a real Blockchain block requires."""

    class _H:
        def __init__(self, proposer_id):
            self.proposer_id = proposer_id

    def __init__(
        self,
        message_txs=None,
        transfer_txs=None,
        proposer_id=b"\x00" * 32,
    ):
        self.transactions = list(message_txs or [])
        self.transfer_transactions = list(transfer_txs or [])
        self.react_transactions = []
        self.stake_transactions = []
        self.unstake_transactions = []
        self.governance_txs = []
        self.authority_txs = []
        self.non_response_evidence_txs = []
        self.header = _FakeBlock._H(proposer_id)


# ────────────────────────────────────────────────────────────────────
# Activation-height ordering — Tier 37 must follow Tier 36 with the
# standard runway buffer so callers between the two heights see the
# legacy excuse-#3 path.
# ────────────────────────────────────────────────────────────────────


class TestForkGateOrdering(unittest.TestCase):

    def test_height_above_tier_36(self):
        self.assertGreater(
            FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT,
            ATTESTER_DYNAMIC_COMMITTEE_HEIGHT,
            "Tier 37 must follow Tier 36 — single coordinated upgrade "
            "window above the most recent established fork.",
        )

    def test_height_above_tier_34(self):
        # The cap-fix rides on top of the Tier 34 multi-list path; the
        # legacy message-only path doesn't implement excuse #3 against
        # transfer blocks at all, so the cap-fix is only meaningful at
        # heights where multi-list enforcement is active.
        self.assertGreater(
            FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT,
            FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
            "Tier 37 must follow Tier 34 — the cap-fix tightens the "
            "excuse on the multi-list gate; that gate must already be "
            "live by the time the new rule activates.",
        )


# ────────────────────────────────────────────────────────────────────
# Same-entity lower-fpb fill attack — the core bug.
# ────────────────────────────────────────────────────────────────────


class TestSameEntityLowerFpbFill(unittest.TestCase):
    """A colluding proposer fills the per-entity cap with same-entity
    lower-fpb txs at sequential nonces and tries to excuse a higher-fpb
    forced tx of the same entity under excuse #3 ("entity at cap").
    Pre-fork: accepted.  Post-fork: rejected."""

    def setUp(self):
        # Single victim entity.  Alice's lower-fpb txs at nonces
        # 0..MAX_TXS_PER_ENTITY_PER_BLOCK-1 fill the proposer's quota;
        # her HIGH-fpb forced tx sits at the next nonce
        # (MAX_TXS_PER_ENTITY_PER_BLOCK) and is the one being censored.
        self.alice = Entity.create(b"t37-alice".ljust(32, b"\x00"))

        # The high-fpb forced tx — must age past WAIT_BLOCKS to qualify.
        self.forced_tx = _make_msg(
            self.alice, fee=_HIGH_FEE,
            nonce=MAX_TXS_PER_ENTITY_PER_BLOCK,
        )

        # The lower-fpb fill — sequential nonces 0..N-1.  These do NOT
        # need to be in the mempool; the proposer just includes them in
        # the block as part of the collusion strategy.
        self.fill_txs = [
            _make_msg(self.alice, fee=_LOW_FEE, nonce=n)
            for n in range(MAX_TXS_PER_ENTITY_PER_BLOCK)
        ]

        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)
        # Arrival at height 0 → ages past FORCED_INCLUSION_WAIT_BLOCKS
        # for any current_height >= WAIT + 1.
        self.pool.add_transaction(self.forced_tx, arrival_block_height=0)

    def _check_at(self, height):
        block = _FakeBlock(message_txs=self.fill_txs)
        return check_forced_inclusion(block, self.pool, height)

    def test_pre_fork_accepts_collusion(self):
        """Pre-Tier-37: legacy excuse #3 fires — Alice already has 3
        block txs (the lower-fpb fill), so the gate excuses the omitted
        higher-fpb forced tx as "entity at cap."  This is the bug —
        accepted for replay determinism, fixed at the fork height."""
        # Sit pre-Tier-37 but post-Tier-34 so the multi-list gate is
        # active (excuse #3 applies in the right code path).
        h = max(PRE_T37, FORCED_INCLUSION_WAIT_BLOCKS + 1)
        self.assertGreaterEqual(
            h, FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
            "Pre-fork test must run at a height where Tier 34's multi-"
            "list path is active so excuse #3 dispatches in the path "
            "the fix targets.",
        )
        ok, reason = self._check_at(h)
        self.assertTrue(
            ok,
            f"Pre-Tier-37 the gate must (wrongly) accept the lower-fpb "
            f"fill collusion under legacy excuse #3 for replay "
            f"determinism: reason={reason!r}",
        )

    def test_post_fork_rejects_collusion(self):
        """Post-Tier-37: same-entity lower-fpb txs in the block do NOT
        count toward the cap when evaluating excuse #3 for the forced
        tx, so the excuse fails and the block is correctly flagged as
        omitting a forced tx."""
        h = POST_T37 + 5
        ok, reason = self._check_at(h)
        self.assertFalse(
            ok,
            f"Tier 37 must reject the lower-fpb fill collusion — the "
            f"forced tx's higher-fpb means same-entity lower-fpb fill "
            f"cannot legitimately exhaust the cap: reason={reason!r}",
        )


# ────────────────────────────────────────────────────────────────────
# Honest full-quota case — the rule must NOT over-fire when the
# proposer fills the entity cap with same-entity txs at >= the forced
# tx's fpb.  In that case the cap really is exhausted and the forced
# tx legitimately can't fit — excuse #3 should still apply.
# ────────────────────────────────────────────────────────────────────


class TestHonestFullQuotaStillExcused(unittest.TestCase):
    """When same-entity block txs are at >= the forced tx's fpb, the
    cap is genuinely exhausted and excuse #3 must still fire — the
    proposer chose higher-density txs and the forced tx is the one that
    legitimately gets bumped."""

    def setUp(self):
        self.alice = Entity.create(b"t37b-alice".ljust(32, b"\x00"))
        # Forced tx at LOWER fpb than the proposer's same-entity fill.
        self.forced_tx = _make_msg(
            self.alice, fee=_LOW_FEE,
            nonce=MAX_TXS_PER_ENTITY_PER_BLOCK,
        )
        self.fill_txs = [
            _make_msg(self.alice, fee=_HIGH_FEE, nonce=n)
            for n in range(MAX_TXS_PER_ENTITY_PER_BLOCK)
        ]
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)
        self.pool.add_transaction(self.forced_tx, arrival_block_height=0)

    def test_post_fork_excuses_higher_fpb_fill(self):
        """Post-Tier-37: a block where Alice's quota is filled with
        HIGHER-fpb same-entity txs legitimately excuses a LOWER-fpb
        forced tx of the same entity — the proposer maximized revenue
        density honestly and the forced tx is the one that doesn't
        fit."""
        block = _FakeBlock(message_txs=self.fill_txs)
        h = POST_T37 + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertTrue(
            ok,
            f"Tier 37 must NOT over-fire on honest higher-fpb fills — "
            f"the cap really is exhausted by same-entity higher-density "
            f"txs the proposer correctly preferred: reason={reason!r}",
        )


# ────────────────────────────────────────────────────────────────────
# Cross-entity full-quota — orthogonal to the cap-fix.  The rule
# changes ONLY how same-entity block txs count; other entities' txs
# in the block are unaffected.  A block whose total tx count fills
# MAX_TXS_PER_BLOCK (excuse #2) or whose byte budget is exhausted
# (excuse #1) still gets those excuses post-fork.
# ────────────────────────────────────────────────────────────────────


class TestCrossEntityCapUnchanged(unittest.TestCase):
    """A different entity's block txs do not count toward the forced
    tx's entity-cap tally, pre- or post-fork.  This test pins that
    Tier 37 doesn't accidentally widen the cap interpretation."""

    def setUp(self):
        self.alice = Entity.create(b"t37c-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"t37c-bob".ljust(32, b"\x00"))
        # Alice has a forced tx at nonce 0 with HIGH fpb.
        self.forced_tx = _make_msg(self.alice, fee=_HIGH_FEE, nonce=0)
        # Bob has MAX_TXS_PER_ENTITY_PER_BLOCK low-fpb message txs the
        # proposer included — these should NOT count toward Alice's cap.
        self.bob_fill = [
            _make_msg(self.bob, fee=_LOW_FEE, nonce=n)
            for n in range(MAX_TXS_PER_ENTITY_PER_BLOCK)
        ]
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)
        self.pool.add_transaction(self.forced_tx, arrival_block_height=0)

    def test_post_fork_other_entity_fill_does_not_excuse_alice(self):
        block = _FakeBlock(message_txs=self.bob_fill)
        h = POST_T37 + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertFalse(
            ok,
            f"Tier 37 must still reject when a different entity's fill "
            f"lets Alice's forced tx be censored — cross-entity txs do "
            f"not interact with Alice's cap: reason={reason!r}",
        )


if __name__ == "__main__":
    unittest.main()
