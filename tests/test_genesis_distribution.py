"""Tests for genesis token distribution.

The genesis block must allocate tokens to the genesis entity so that
staking and the fee market can bootstrap without requiring external
token distribution.
"""

import unittest
from messagechain.identity.biometrics import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.config import GENESIS_ALLOCATION


class TestGenesisDistribution(unittest.TestCase):
    def test_genesis_entity_receives_allocation(self):
        """The genesis entity receives GENESIS_ALLOCATION tokens."""
        alice = Entity.create(b"alice-private-key")
        chain = Blockchain()
        chain.initialize_genesis(alice)

        balance = chain.supply.get_balance(alice.entity_id)
        self.assertEqual(balance, GENESIS_ALLOCATION)

    def test_genesis_allocation_is_meaningful(self):
        """GENESIS_ALLOCATION is large enough to stake and transact."""
        from messagechain.config import VALIDATOR_MIN_STAKE
        self.assertGreaterEqual(GENESIS_ALLOCATION, VALIDATOR_MIN_STAKE * 10)

    def test_total_supply_accounts_for_allocation(self):
        """Total supply includes the genesis allocation."""
        alice = Entity.create(b"alice-private-key")
        chain = Blockchain()
        chain.initialize_genesis(alice)

        # Total supply should still be GENESIS_SUPPLY (allocation comes from it)
        from messagechain.config import GENESIS_SUPPLY
        self.assertEqual(chain.supply.total_supply, GENESIS_SUPPLY)

    def test_non_genesis_entities_start_with_zero(self):
        """Entities registered after genesis start with zero balance."""
        alice = Entity.create(b"alice-private-key")
        bob = Entity.create(b"bob-private-key")
        chain = Blockchain()
        chain.initialize_genesis(alice)

        import hashlib
        from messagechain.config import HASH_ALGO
        msg = hashlib.new(HASH_ALGO, b"register" + bob.entity_id).digest()
        proof = bob.keypair.sign(msg)
        chain.register_entity(bob.entity_id, bob.public_key, registration_proof=proof)

        self.assertEqual(chain.supply.get_balance(bob.entity_id), 0)


if __name__ == "__main__":
    unittest.main()
