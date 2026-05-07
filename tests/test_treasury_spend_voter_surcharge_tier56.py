"""
Tier 56 — TreasurySpendTransaction proposers pay VOTER_REWARD_SURCHARGE.

Audit r30 #3 — pre-fork ``Blockchain._validate_governance_tx`` required
``fee + VOTER_REWARD_SURCHARGE`` for ``ProposalTransaction`` only; the
``TreasurySpendTransaction`` branch fell through with ``required = fee``.
The apply path tried to debit the surcharge for both classes, but
without a corresponding validation gate a treasury-spend proposer with
exactly ``fee`` balance silently escrowed ``voter_reward_pool=0`` --
voters did the work of evaluating the proposal and got paid nothing.

Treasury spends are arguably the *most* economically consequential
governance class (they actually move treasury funds, vs. advisory
proposals that don't move money).  CLAUDE.md anchor: "voters who cast
a vote during the window receive a reward funded out of the proposal
fee — the proposer pays the voters they're asking to evaluate the
proposal."  Pre-fix the most-money-moving proposal class was exempt
from the rule.

Tier 56 makes the surcharge mandatory for both ``ProposalTransaction``
and ``TreasurySpendTransaction`` post-activation: validation rejects a
treasury-spend whose proposer cannot afford ``fee + SURCHARGE``; apply
debits the surcharge into ``voter_reward_pool`` symmetrically with
the existing proposal path.

This test pins:

  (1) Activation constant ``TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT`` is
      defined and follows Tier 55.

  (2) Pre-fork validation: TreasurySpend with fee-only balance admits
      (legacy replay determinism preserved -- the looser rule is the
      pre-fork ground truth).

  (3) Post-fork validation: TreasurySpend with fee-only balance
      REJECTS ("Insufficient balance for fee + surcharge").

  (4) Post-fork apply: TreasurySpend with fee + surcharge balance
      escrows ``voter_reward_pool == VOTER_REWARD_SURCHARGE`` so
      ``finalize_voter_rewards`` can pay voters at close.
"""

import time
import unittest

from messagechain import config
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.hash_sig import _hash
from messagechain.governance.governance import (
    create_treasury_spend_proposal,
    proposal_fee_floor,
)
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

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(
            entity.entity_id, entity.public_key, proof,
        )


class TestActivationHeightConstant(_Base):
    def test_constant_present_and_above_tier_55(self):
        self.assertTrue(
            hasattr(config, "TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT"),
            "TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT must be defined; "
            "Tier 56 hard-fork gate.",
        )
        self.assertGreater(
            config.TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT,
            config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT,
            "Tier 56 must follow Tier 55 -- operators upgrade through "
            "Tier 55 before this consensus-rule change binds.",
        )


class TestValidationGate(_Base):
    """``_validate_governance_tx`` is the admission gate.  Pre-Tier-56:
    TreasurySpend requires only ``fee``.  Post-Tier-56: requires
    ``fee + VOTER_REWARD_SURCHARGE``."""

    def _make_treasury_spend(self, proposer, current_height=None):
        # Build a minimal TreasurySpend.  Description bytes don't
        # matter for the validation gate -- it only checks signature +
        # affordability.
        tx = create_treasury_spend_proposal(
            proposer,
            recipient_id=proposer.entity_id,
            amount=1,
            title="audit-r30",
            description="audit-r30-test",
            current_height=current_height,
        )
        return tx

    def _set_height(self, chain, target_height):
        """Push Blockchain.height to target_height by appending sentinels.

        ``Blockchain.height`` returns ``len(self.chain)``; mirror the
        helper used in test_authority_key_rebind_cold_signature.py."""
        while chain.height < target_height:
            chain.chain.append(object())

    def test_pre_fork_treasury_spend_fee_only_admits(self):
        """Pre-Tier-56: a treasury-spend proposer with exactly the
        proposal fee in balance must validate -- legacy replay
        determinism."""
        chain = Blockchain()
        proposer = _entity(b"prop-pre-fork")
        self._register(chain, proposer)

        # Push chain height to a value below the Tier 56 activation.
        target = config.TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT - 2
        self._set_height(chain, target)

        tx = self._make_treasury_spend(proposer, current_height=target)
        # Just enough for fee, no surcharge.
        chain.supply.balances[proposer.entity_id] = tx.fee

        ok, err = chain._validate_governance_tx(tx)
        self.assertTrue(
            ok,
            f"Pre-Tier-56 treasury-spend with fee-only balance must "
            f"validate (legacy behavior).  err={err!r}",
        )

    def test_post_fork_treasury_spend_fee_only_rejects(self):
        """Post-Tier-56: a treasury-spend proposer with exactly the
        proposal fee in balance MUST be rejected."""
        chain = Blockchain()
        proposer = _entity(b"prop-post-fork-bad")
        self._register(chain, proposer)

        target = config.TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT
        self._set_height(chain, target)

        tx = self._make_treasury_spend(proposer, current_height=target)
        chain.supply.balances[proposer.entity_id] = tx.fee

        ok, err = chain._validate_governance_tx(tx)
        self.assertFalse(
            ok,
            "Post-Tier-56 treasury-spend without surcharge balance "
            "must be rejected at admission.",
        )
        self.assertIn(
            "balance", err.lower(),
            "Rejection reason must reference balance / fee shortfall.",
        )

    def test_post_fork_treasury_spend_with_surcharge_admits(self):
        """Post-Tier-56: a treasury-spend proposer with fee+surcharge
        balance must validate."""
        chain = Blockchain()
        proposer = _entity(b"prop-post-fork-ok")
        self._register(chain, proposer)

        target = config.TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT
        self._set_height(chain, target)

        tx = self._make_treasury_spend(proposer, current_height=target)
        chain.supply.balances[proposer.entity_id] = (
            tx.fee + config.VOTER_REWARD_SURCHARGE
        )

        ok, err = chain._validate_governance_tx(tx)
        self.assertTrue(
            ok,
            f"Post-Tier-56 treasury-spend with fee+surcharge balance "
            f"must admit.  err={err!r}",
        )


class TestApplyPathEscrowSymmetric(_Base):
    """Post-Tier-56: when a TreasurySpend is applied, its
    ``voter_reward_pool`` must equal ``VOTER_REWARD_SURCHARGE`` --
    voters get paid identically to ProposalTransaction voters."""

    def _set_height(self, chain, target_height):
        while chain.height < target_height:
            chain.chain.append(object())

    def test_post_fork_apply_escrows_surcharge_for_treasury_spend(self):
        """End-to-end through ``_apply_governance_block``: a Tier-56
        TreasurySpend with fee+surcharge balance lands with
        ``voter_reward_pool == SURCHARGE`` on the proposal state."""
        from messagechain.core.block import Block
        from messagechain.core.block import BlockHeader

        chain = Blockchain()
        proposer = _entity(b"prop-apply-test")
        self._register(chain, proposer)

        # Stake the proposer so add_proposal sees a non-empty
        # stake_snapshot (otherwise total_eligible_stake = 0 and the
        # tally branches don't exercise the escrow path).
        chain.supply.staked[proposer.entity_id] = 1_000_000

        # Push chain to post-Tier-56 height.
        target = config.TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT
        self._set_height(chain, target)

        tx = create_treasury_spend_proposal(
            proposer,
            recipient_id=proposer.entity_id,
            amount=1,
            title="audit-r30",
            description="audit-r30-apply",
            current_height=target,
        )

        # Balance: fee + surcharge + a little headroom for any
        # incidental debits.
        chain.supply.balances[proposer.entity_id] = (
            tx.fee + config.VOTER_REWARD_SURCHARGE + 10
        )

        # Hand-construct a minimal Block carrying just this gov tx.
        header = BlockHeader(
            version=2,
            block_number=target + 1,
            prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32,
            timestamp=int(time.time()),
            proposer_id=proposer.entity_id,
        )
        block = Block(header=header, transactions=[])
        block.governance_txs = [tx]

        # Apply just the governance block phase.  This is the path
        # under test; we don't need full add_block here.
        chain._apply_governance_block(block)

        # Verify escrow.  After apply, the treasury-spend must be in
        # tracker.proposals with voter_reward_pool == SURCHARGE.
        self.assertIsNotNone(chain.governance, "tracker not present")
        state = chain.governance.proposals.get(tx.proposal_id)
        self.assertIsNotNone(
            state,
            "TreasurySpend must land in tracker.proposals after apply.",
        )
        self.assertEqual(
            state.voter_reward_pool,
            config.VOTER_REWARD_SURCHARGE,
            "Post-Tier-56 TreasurySpend must escrow the full surcharge "
            "into voter_reward_pool so finalize_voter_rewards has a "
            "non-zero pool to distribute -- the whole point of the "
            "fork.",
        )


if __name__ == "__main__":
    unittest.main()
