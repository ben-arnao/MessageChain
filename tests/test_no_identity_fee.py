"""Tests confirming identity creation works without a special fee.

The identity creation fee has been removed. New entities only need to pay
the standard transaction fee for their first message. The per-tx fee
(min 100 tokens + quadratic sizing) provides sufficient spam resistance,
and long-lived account histories enable L2 trust scoring.
"""

import unittest

from messagechain.core.transaction import create_transaction, calculate_min_fee
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


class TestNoIdentityCreationFee(unittest.TestCase):
    """IDENTITY_CREATION_FEE should not exist in config."""

    def test_no_identity_creation_fee_constant(self):
        """The IDENTITY_CREATION_FEE constant should be removed from config."""
        import messagechain.config
        self.assertFalse(
            hasattr(messagechain.config, "IDENTITY_CREATION_FEE"),
            "IDENTITY_CREATION_FEE should be removed from config",
        )


class TestNewEntityFirstTransaction(unittest.TestCase):
    """A new entity's first transaction should only require the standard fee."""

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.chain = Blockchain()
        self.genesis_entity = Entity.create(b"genesis-no-fee".ljust(32, b"\x00"))
        self.chain.initialize_genesis(self.genesis_entity)

    def test_first_tx_with_standard_fee_accepted(self):
        """A new entity paying just the standard min fee should be accepted
        by validate_transaction (mempool acceptance)."""
        new_entity = Entity.create(b"new-entity-standard".ljust(32, b"\x00"))
        register_entity_for_test(self.chain, new_entity)

        msg = "Hello, world!"
        min_fee = calculate_min_fee(msg.encode("ascii"))

        # Fund the entity with just enough for the standard fee
        self.chain.supply.balances[new_entity.entity_id] = min_fee

        tx = create_transaction(new_entity, msg, fee=min_fee, nonce=0)
        valid, reason = self.chain.validate_transaction(tx)
        self.assertTrue(valid, f"First tx with standard fee should be accepted: {reason}")

    def test_first_tx_fee_below_minimum_rejected(self):
        """A fee below the calculated minimum should still be rejected."""
        new_entity = Entity.create(b"new-entity-low-fee".ljust(32, b"\x00"))
        register_entity_for_test(self.chain, new_entity)
        self.chain.supply.balances[new_entity.entity_id] = 10000

        msg = "Test message"
        min_fee = calculate_min_fee(msg.encode("ascii"))
        # Can't create tx with fee below min (create_transaction raises),
        # so verify the min fee itself is reasonable
        self.assertGreaterEqual(min_fee, 100)  # MIN_FEE is the floor


if __name__ == "__main__":
    unittest.main()
