"""Slashing (stage 4) burns accumulated escrow, not just stake.

The existing `SupplyTracker.slash_validator` burns stake + pending
unstakes.  This stage extends the Blockchain-level slashing paths
(apply_slash_transaction and the slash_transactions loop in
_apply_block_state) to also burn the offender's escrow balance
before the stake burn.

Rationale from the design math: escrow is the slashable window for
bootstrap-era rewards.  A validator who equivocates during bootstrap
must forfeit the full accumulated escrow; otherwise the deterrent
collapses (they keep the illicit earnings, lose only the stake which
was near-zero during free-entry).
"""

import time
import unittest

from messagechain.config import TREASURY_ENTITY_ID
from messagechain.consensus.slashing import (
    AttestationSlashingEvidence,
    SlashTransaction,
    create_slash_transaction,
)
from messagechain.consensus.attestation import create_attestation
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=4)


def _register(chain: Blockchain, entity: Entity):
    import hashlib
    from messagechain.config import HASH_ALGO
    h = hashlib.new(HASH_ALGO, b"register" + entity.entity_id).digest()
    proof = entity.keypair.sign(h)
    chain.register_entity(entity.entity_id, entity.public_key, proof)


class TestSlashBurnsEscrow(unittest.TestCase):
    """apply_slash_transaction burns stake AND escrow."""

    def _setup_offender_with_escrow(self, escrow_amount: int = 50):
        """Build a chain, an offender with stake and escrowed rewards,
        and a submitter ready to file evidence.
        """
        alice = _entity(b"alice-slash")
        offender = _entity(b"offender-slash")
        submitter = _entity(b"submitter-slash")
        chain = Blockchain()
        chain.initialize_genesis(alice, allocation_table={
            TREASURY_ENTITY_ID: 1_000_000,
            alice.entity_id: 1_000_000,
        })
        _register(chain, offender)
        _register(chain, submitter)
        chain.supply.balances[offender.entity_id] = 10_000
        chain.supply.balances[submitter.entity_id] = 10_000
        # Offender has some stake to slash.
        chain.supply.stake(offender.entity_id, 500)
        # Offender also has escrow-held attester rewards.
        chain._escrow.add(
            entity_id=offender.entity_id,
            amount=escrow_amount,
            earned_at=chain.height,
            unlock_at=chain.height + 10_000,  # far in the future
        )
        # Balance reflects the escrow (tokens were credited at mint
        # time).  Simulate that here by also adding to balance.
        chain.supply.balances[offender.entity_id] += escrow_amount
        chain.supply.total_supply += escrow_amount
        return chain, offender, submitter

    def _build_double_attestation_evidence(self, offender: Entity):
        """Build valid equivocation evidence: two attestations at the
        same height for different blocks, both signed by offender."""
        block_hash_a = b"\xa1" * 32
        block_hash_b = b"\xa2" * 32
        height = 1
        att_a = create_attestation(offender, block_hash_a, height)
        att_b = create_attestation(offender, block_hash_b, height)
        return AttestationSlashingEvidence(
            offender_id=offender.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

    def test_slash_burns_escrow(self):
        chain, offender, submitter = self._setup_offender_with_escrow(
            escrow_amount=50,
        )
        self.assertEqual(chain.get_escrowed_balance(offender.entity_id), 50)

        evidence = self._build_double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)

        ok, reason = chain.apply_slash_transaction(tx, proposer_id=submitter.entity_id)
        self.assertTrue(ok, reason)

        # Escrow is now empty — fully burned.
        self.assertEqual(chain.get_escrowed_balance(offender.entity_id), 0)

    def test_slash_reduces_total_supply_by_escrow_amount(self):
        chain, offender, submitter = self._setup_offender_with_escrow(
            escrow_amount=100,
        )
        supply_before = chain.supply.total_supply
        # Also capture stake (it gets burned too).
        stake_before = chain.supply.get_staked(offender.entity_id)

        evidence = self._build_double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)
        chain.apply_slash_transaction(tx, proposer_id=submitter.entity_id)

        supply_after = chain.supply.total_supply
        # Supply dropped by (escrow + burned-stake-portion + burned-fee-base)
        self.assertLess(supply_after, supply_before - 100)  # >= escrow burned
        # At minimum, escrow_burned = 100 is reflected in supply drop
        self.assertLessEqual(
            supply_after, supply_before - 100 - (stake_before // 2),
        )

    def test_slash_reduces_offender_balance_by_escrow_amount(self):
        chain, offender, submitter = self._setup_offender_with_escrow(
            escrow_amount=50,
        )
        balance_before = chain.supply.get_balance(offender.entity_id)
        evidence = self._build_double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)
        chain.apply_slash_transaction(tx, proposer_id=submitter.entity_id)

        balance_after = chain.supply.get_balance(offender.entity_id)
        # Balance dropped by at least the escrow amount (stake was
        # already separated from balance, so stake-burn doesn't
        # further reduce balance).
        self.assertLessEqual(balance_after, balance_before - 50)

    def test_slash_with_no_escrow_still_works(self):
        """Offender with stake but no escrow — legacy path.  Must not
        accidentally break the no-escrow case when extending slashing."""
        alice = _entity(b"alice-ne")
        offender = _entity(b"offender-ne")
        submitter = _entity(b"submitter-ne")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        _register(chain, offender)
        _register(chain, submitter)
        chain.supply.balances[offender.entity_id] = 10_000
        chain.supply.balances[submitter.entity_id] = 10_000
        chain.supply.stake(offender.entity_id, 500)

        evidence = self._build_double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)
        ok, reason = chain.apply_slash_transaction(tx, proposer_id=submitter.entity_id)
        self.assertTrue(ok, reason)
        self.assertIn(offender.entity_id, chain.slashed_validators)

    def test_slash_idempotency_prevents_double_burn(self):
        """Re-submitting the same evidence must be rejected (existing
        `_processed_evidence` mechanism), so escrow can't be burned
        twice by re-submitting the same bundle."""
        chain, offender, submitter = self._setup_offender_with_escrow(
            escrow_amount=40,
        )
        evidence = self._build_double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)

        ok1, _ = chain.apply_slash_transaction(tx, proposer_id=submitter.entity_id)
        self.assertTrue(ok1)

        ok2, reason = chain.apply_slash_transaction(tx, proposer_id=submitter.entity_id)
        self.assertFalse(ok2)
        self.assertIn("already", reason.lower())


if __name__ == "__main__":
    unittest.main()
