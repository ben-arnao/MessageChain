"""Slash must succeed even after the offender unstaked.

Security finding #3 — unstake-during-evidence race.

An offender who equivocates can try to escape the 100% slash penalty
by immediately submitting a SetUnstakeTransaction, pushing their
entire active stake into the unbonding queue.  The unbonding queue
matures over UNBONDING_PERIOD blocks (~7 days), but
validate_slash_transaction was checking `supply.get_staked()`, which
only counts active stake — not pending unstakes.  Result: once the
offender drained active stake to zero the slash was rejected as
"Offender has no stake to slash", even though the underlying
slash_validator path would happily burn the unbonding balance.

The evidence TTL (`max(UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS)`)
already claims the evidence stays valid throughout the unbonding
window, so the validation check has to honor that claim.
"""

import unittest

from messagechain.config import TREASURY_ENTITY_ID
from messagechain.consensus.attestation import create_attestation
from messagechain.consensus.slashing import (
    AttestationSlashingEvidence,
    create_slash_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=4)


def _register(chain: Blockchain, entity: Entity):
    import hashlib
    from messagechain.config import HASH_ALGO
    h = hashlib.new(HASH_ALGO, b"register" + entity.entity_id).digest()
    proof = entity.keypair.sign(h)
    chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


def _double_attestation_evidence(offender: Entity) -> AttestationSlashingEvidence:
    """Valid equivocation evidence: two attestations at same height."""
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


class TestSlashUnstakeRace(unittest.TestCase):

    def _setup(self, stake_amount: int = 500):
        alice = _entity(b"alice-race")
        offender = _entity(b"offender-race")
        submitter = _entity(b"submitter-race")
        chain = Blockchain()
        chain.initialize_genesis(alice, allocation_table={
            TREASURY_ENTITY_ID: 1_000_000,
            alice.entity_id: 1_000_000,
        })
        _register(chain, offender)
        _register(chain, submitter)
        chain.supply.balances[offender.entity_id] = 10_000
        chain.supply.balances[submitter.entity_id] = 10_000
        chain.supply.stake(offender.entity_id, stake_amount)
        return chain, offender, submitter

    def test_slash_succeeds_while_offender_is_fully_unbonding(self):
        """All stake in the unbonding queue — slash must still land."""
        chain, offender, submitter = self._setup(stake_amount=500)

        # Offender races: moves entire stake into unbonding queue.
        # After this, get_staked() == 0 but get_pending_unstake() == 500.
        ok = chain.supply.unstake(
            offender.entity_id, 500,
            current_block=chain.height,
            bootstrap_ended=False,
        )
        self.assertTrue(ok)
        self.assertEqual(chain.supply.get_staked(offender.entity_id), 0)
        self.assertEqual(chain.supply.get_pending_unstake(offender.entity_id), 500)

        # Evidence for an offense committed BEFORE the unstake is now
        # submitted.  It must still be accepted.
        evidence = _double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)
        applied, reason = chain.apply_slash_transaction(
            tx, proposer_id=submitter.entity_id,
        )
        self.assertTrue(applied, f"slash was rejected: {reason}")

        # The unbonding stake was destroyed, not released.
        self.assertEqual(chain.supply.get_pending_unstake(offender.entity_id), 0)
        self.assertIn(offender.entity_id, chain.slashed_validators)

    def test_validate_accepts_offender_with_only_unbonding_stake(self):
        """Direct validation-level assertion — the check we actually
        fixed must return True, not 'no stake to slash'."""
        chain, offender, submitter = self._setup(stake_amount=500)
        chain.supply.unstake(
            offender.entity_id, 500,
            current_block=chain.height,
            bootstrap_ended=False,
        )
        evidence = _double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)
        ok, reason = chain.validate_slash_transaction(tx)
        self.assertTrue(ok, f"validation rejected: {reason}")

    def test_slash_still_rejected_when_no_stake_and_no_unbonding(self):
        """Regression guard: entity with zero stake AND zero unbonding
        is still rejected — we widened the window, not removed it."""
        chain, offender, submitter = self._setup(stake_amount=500)
        # Unstake AND let the window mature so the tokens move back to
        # balance and pending_unstakes drains.
        chain.supply.unstake(
            offender.entity_id, 500,
            current_block=chain.height,
            bootstrap_ended=False,
        )
        # Jump far past UNBONDING_PERIOD.
        from messagechain.config import UNBONDING_PERIOD
        chain.supply.process_pending_unstakes(chain.height + UNBONDING_PERIOD + 1)
        self.assertEqual(chain.supply.get_staked(offender.entity_id), 0)
        self.assertEqual(chain.supply.get_pending_unstake(offender.entity_id), 0)

        evidence = _double_attestation_evidence(offender)
        tx = create_slash_transaction(submitter, evidence, fee=100)
        ok, reason = chain.validate_slash_transaction(tx)
        self.assertFalse(ok)
        self.assertIn("no stake", reason.lower())


if __name__ == "__main__":
    unittest.main()
