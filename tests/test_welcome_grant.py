"""Tests for the welcome grant: new users get a small allocation from
the treasury upon registration so they can afford their first message.

This removes the "chicken and egg" bootstrap problem where a brand new
user with 0 tokens cannot pay the fee to post anything.
"""

import os
import unittest

from messagechain.config import (
    TREASURY_ENTITY_ID, TREASURY_ALLOCATION, WELCOME_GRANT,
    DEFAULT_GENESIS_ALLOCATIONS,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


def _register_new_entity(bc: Blockchain) -> Entity:
    key = os.urandom(32)
    entity = Entity.create(key)
    proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
    ok, msg = bc.register_entity(entity.entity_id, entity.public_key, proof)
    assert ok, msg
    return entity


class TestWelcomeGrant(unittest.TestCase):
    def setUp(self):
        self.bc = Blockchain()
        self.genesis = Entity.create(os.urandom(32))
        # Fund treasury so welcome grants can actually be paid out
        self.bc.initialize_genesis(
            self.genesis,
            allocation_table=dict(DEFAULT_GENESIS_ALLOCATIONS),
        )

    def test_welcome_grant_constant_is_positive(self):
        """The welcome grant must be >= the minimum fee so the user can
        actually send their first message."""
        from messagechain.config import MIN_FEE
        self.assertGreaterEqual(WELCOME_GRANT, MIN_FEE)

    def test_new_entity_receives_welcome_grant(self):
        """A registered entity should start with WELCOME_GRANT tokens."""
        entity = _register_new_entity(self.bc)
        self.assertEqual(
            self.bc.supply.get_balance(entity.entity_id),
            WELCOME_GRANT,
        )

    def test_treasury_debited_by_welcome_grant(self):
        """Welcome grant funds must come from the treasury."""
        treasury_before = self.bc.supply.get_balance(TREASURY_ENTITY_ID)
        _register_new_entity(self.bc)
        treasury_after = self.bc.supply.get_balance(TREASURY_ENTITY_ID)
        self.assertEqual(treasury_before - treasury_after, WELCOME_GRANT)

    def test_welcome_grant_does_not_exceed_treasury(self):
        """If treasury cannot cover the grant, the entity is registered
        with 0 balance rather than failing registration or going negative."""
        # Drain the treasury by simulating many grants
        # Use direct balance manipulation for test speed
        self.bc.supply.balances[TREASURY_ENTITY_ID] = 0

        entity = _register_new_entity(self.bc)
        # Registration still succeeds
        self.assertIn(entity.entity_id, self.bc.public_keys)
        # But balance is 0 (no grant possible)
        self.assertEqual(self.bc.supply.get_balance(entity.entity_id), 0)
        self.assertEqual(self.bc.supply.get_balance(TREASURY_ENTITY_ID), 0)

    def test_partial_grant_when_treasury_low(self):
        """If treasury has less than WELCOME_GRANT but nonzero, grant all of it."""
        partial = WELCOME_GRANT - 1
        self.bc.supply.balances[TREASURY_ENTITY_ID] = partial

        entity = _register_new_entity(self.bc)
        self.assertEqual(self.bc.supply.get_balance(entity.entity_id), partial)
        self.assertEqual(self.bc.supply.get_balance(TREASURY_ENTITY_ID), 0)

    def test_each_entity_grants_once(self):
        """Two registrations debit the treasury twice."""
        treasury_before = self.bc.supply.get_balance(TREASURY_ENTITY_ID)
        _register_new_entity(self.bc)
        _register_new_entity(self.bc)
        treasury_after = self.bc.supply.get_balance(TREASURY_ENTITY_ID)
        self.assertEqual(treasury_before - treasury_after, WELCOME_GRANT * 2)


if __name__ == "__main__":
    unittest.main()
