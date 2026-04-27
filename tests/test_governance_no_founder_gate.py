"""Lock-in: governance is purely stake-weighted; no founder-only gates.

CLAUDE.md anchors that "governance is founder-led during bootstrap,
transitioning to community governance later" — but in code there is
NO special founder authority on proposals or voting.  Founder
influence comes ENTIRELY from stake share: founder owns the bulk of
genesis stake, so during bootstrap the founder can pass or block
proposals through ordinary stake-weighted majority.  As validators
stake in and the founder's share dilutes, that influence smoothly
decays to "any other validator" with no flag flip, no scheduled
handoff event, no special migration tx.

This file locks in that property: anyone can submit, anyone can vote,
weights come from stake snapshot at proposal creation.  If a future
change accidentally introduces a founder-only admission gate or
founder-bonus weight, these tests fail.

Lock-in scope (this file):
  * Non-founder proposal admission works (no proposer-identity gate)
  * Non-founder vote registration works (no voter-identity gate)
  * Tally weight is exactly stake; non-founder with more stake
    outweighs founder with less stake
  * Source-grep guard: governance/governance.py does not reference
    the founder constants — a defensive structural assert that
    catches any future re-introduction of identity-based gating
"""

import pathlib
import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.governance.governance import (
    GovernanceTracker,
    create_proposal,
    create_vote,
)
from messagechain.identity.identity import Entity


class TestNoFounderGateOnAdmission(unittest.TestCase):
    """Proposal admission must not check proposer identity against the founder."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(b"nfg-founder".ljust(32, b"\x00"))
        cls.alice = Entity.create(b"nfg-alice".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.founder, self.alice):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.founder)
        # Both have stake.  Alice is NOT the founder; admission should
        # work identically for both.
        for e in (self.founder, self.alice):
            self.chain.supply.balances[e.entity_id] = 1_000_000
            self.chain.public_keys[e.entity_id] = e.public_key
            self.chain.supply.staked[e.entity_id] = 10_000

    def test_non_founder_can_submit_proposal(self):
        gt = GovernanceTracker()
        tx = create_proposal(self.alice, "Alice proposes", "D")
        admitted = gt.add_proposal(tx, block_height=1, supply_tracker=self.chain.supply)
        self.assertTrue(
            admitted,
            "A non-founder proposal must be admitted exactly the same as "
            "a founder proposal — there is NO founder-only gate at the "
            "governance layer (admission is fee-and-cap-bounded only).",
        )
        self.assertIn(tx.proposal_id, gt.proposals)

    def test_founder_and_non_founder_admitted_symmetrically(self):
        gt = GovernanceTracker()
        tx_founder = create_proposal(self.founder, "Founder", "D1")
        tx_alice = create_proposal(self.alice, "Alice", "D2")
        ok_f = gt.add_proposal(tx_founder, 1, self.chain.supply)
        ok_a = gt.add_proposal(tx_alice, 2, self.chain.supply)
        self.assertTrue(ok_f and ok_a)
        # Both proposals carry stake_snapshot of the SAME electorate —
        # admission produced identical state-shape regardless of
        # proposer identity.
        s_f = gt.proposals[tx_founder.proposal_id].stake_snapshot
        s_a = gt.proposals[tx_alice.proposal_id].stake_snapshot
        self.assertEqual(s_f, s_a)


class TestNoFounderGateOnVoting(unittest.TestCase):
    """Vote registration must not check voter identity against the founder."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(b"nfg-v-founder".ljust(32, b"\x00"))
        cls.alice = Entity.create(b"nfg-v-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"nfg-v-bob".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.founder, self.alice, self.bob):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.founder)
        for e in (self.founder, self.alice, self.bob):
            self.chain.supply.balances[e.entity_id] = 1_000_000
            self.chain.public_keys[e.entity_id] = e.public_key
            self.chain.supply.staked[e.entity_id] = 10_000

    def test_non_founder_vote_accepted(self):
        gt = GovernanceTracker()
        tx = create_proposal(self.founder, "Vote-target", "D")
        gt.add_proposal(tx, 1, self.chain.supply)
        vote = create_vote(self.alice, tx.proposal_id, True)
        self.assertTrue(
            gt.add_vote(vote, current_block=2),
            "A non-founder vote from a snapshot-eligible staker must be "
            "accepted on equal footing with a founder vote.",
        )

    def test_founder_silence_does_not_count_as_yes(self):
        # If admission/voting had a "founder yes by default" gate, a
        # founder-silent proposal with a single non-founder no-vote
        # would still tally with founder weight on yes.  Asserting
        # the inverse: founder silence keeps founder weight in the
        # silent-electorate bucket, where it counts as "no" for
        # supermajority purposes.
        gt = GovernanceTracker()
        tx = create_proposal(self.alice, "Anti-founder ask", "D")
        gt.add_proposal(tx, 1, self.chain.supply)
        # Only Bob votes — yes with his 10_000 stake.  Founder + Alice
        # silent.  Tally: yes = 10_000, no = 0, but total_eligible =
        # 30_000 (all three stakers in snapshot).
        gt.add_vote(create_vote(self.bob, tx.proposal_id, True), 2)
        yes, no, parti, eligible = gt.tally(tx.proposal_id)
        self.assertEqual(yes, 10_000)
        self.assertEqual(no, 0)
        self.assertEqual(parti, 10_000)
        self.assertEqual(eligible, 30_000)
        # Strict 2/3 supermajority is yes * 3 > eligible * 2 ⇒
        # 30_000 > 60_000 → False.  Founder silence does NOT
        # auto-bump yes weight.
        self.assertFalse(yes * 3 > eligible * 2)


class TestStakeProportionalWeight(unittest.TestCase):
    """Vote weight comes from stake snapshot, not from founder identity."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(b"nfg-w-founder".ljust(32, b"\x00"))
        cls.alice = Entity.create(b"nfg-w-alice".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.founder, self.alice):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.founder)
        # Alice has 10× the stake the founder does.  If governance had
        # ANY founder-bonus weighting, this would scramble the relative
        # ordering.  Pure stake-proportional weight means Alice
        # outweighs the founder 10:1 in the tally.
        self.chain.supply.balances[self.founder.entity_id] = 1_000_000
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.public_keys[self.founder.entity_id] = (
            self.founder.public_key
        )
        self.chain.public_keys[self.alice.entity_id] = self.alice.public_key
        self.chain.supply.staked[self.founder.entity_id] = 10_000
        self.chain.supply.staked[self.alice.entity_id] = 100_000

    def test_non_founder_with_more_stake_outweighs_founder(self):
        gt = GovernanceTracker()
        tx = create_proposal(self.alice, "Outweigh test", "D")
        gt.add_proposal(tx, 1, self.chain.supply)
        # Founder votes no, Alice votes yes.  If the protocol had any
        # founder weighting, founder's 10_000 stake might block (or
        # equal) Alice's 100_000.  Pure stake-proportional means Alice
        # wins decisively.
        gt.add_vote(create_vote(self.founder, tx.proposal_id, False), 2)
        gt.add_vote(create_vote(self.alice, tx.proposal_id, True), 3)
        yes, no, _parti, eligible = gt.tally(tx.proposal_id)
        self.assertEqual(yes, 100_000)
        self.assertEqual(no, 10_000)
        # Yes/no ratio is exactly the stake ratio — no founder bonus,
        # no founder penalty, identity is irrelevant.
        self.assertEqual(yes, 10 * no)
        # Alice's vote alone clears strict 2/3 of total eligible
        # (110_000): 100_000 * 3 = 300_000 > 110_000 * 2 = 220_000.
        self.assertTrue(yes * 3 > eligible * 2)


class TestSourceLevelGuard(unittest.TestCase):
    """Defensive structural assert: governance/ does not reference founder."""

    def test_governance_module_does_not_reference_founder_identity(self):
        # If a future change adds a founder-only gate, it would almost
        # certainly need to import `_MAINNET_FOUNDER_ENTITY_ID` (or a
        # similarly-named constant) into the governance layer.  Catch
        # that at the source level so it's flagged loudly in tests
        # before consensus drifts.
        gov_dir = (
            pathlib.Path(__file__).resolve().parent.parent
            / "messagechain"
            / "governance"
        )
        offending: list[tuple[str, int, str]] = []
        for py in sorted(gov_dir.rglob("*.py")):
            for i, line in enumerate(
                py.read_text(encoding="utf-8").splitlines(), 1,
            ):
                # Match identity-based gates only — comments/docstrings
                # mentioning "founder" prose are fine.  We're after
                # IMPORTS or COMPARISONS against the founder constant.
                lowered = line.lower()
                if (
                    "_mainnet_founder" in lowered
                    or "founder_entity_id" in lowered
                ):
                    offending.append((py.name, i, line.rstrip()))
        self.assertEqual(
            offending, [],
            "governance/ must not reference the founder identity — "
            "doing so introduces an identity-based gate that breaks "
            "the stake-proportional anchor.  Found references:\n"
            + "\n".join(f"  {f}:{i}  {ln}" for f, i, ln in offending),
        )


if __name__ == "__main__":
    unittest.main()
