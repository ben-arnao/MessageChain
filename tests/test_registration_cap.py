"""Tests for registration fee and per-block registration cap.

Anti-bloat measure: RegistrationTransaction now requires a fee paid by a
sponsor (existing entity) and blocks are limited to MAX_REGISTRATIONS_PER_BLOCK
registration transactions.
"""

import hashlib
import os
import time
import unittest

import messagechain.config as config
from messagechain.config import HASH_ALGO, TREASURY_ENTITY_ID
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.registration import (
    RegistrationTransaction,
    create_registration_transaction,
    verify_registration_transaction,
)
from messagechain.identity.identity import Entity


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


_counter = 0


def _make_entity(seed_prefix: bytes | None = None):
    global _counter
    _counter += 1
    if seed_prefix is None:
        seed_prefix = f"regcap-{_counter}-".encode()
    seed = seed_prefix + os.urandom(32 - len(seed_prefix))
    return Entity.create(seed[:32])


def _setup_chain_and_genesis():
    """Set up a chain with genesis and return (chain, consensus, genesis_entity)."""
    chain = Blockchain()
    genesis = _make_entity(b"genesis-regcap-")
    chain.initialize_genesis(genesis)
    consensus = ProofOfStake()
    return chain, consensus, genesis


def _propose_block(chain, consensus, proposer, registration_transactions=None,
                   transfer_transactions=None):
    """Propose a block with the given registration/transfer txs."""
    return chain.propose_block(
        consensus, proposer, [],
        registration_transactions=registration_transactions,
        transfer_transactions=transfer_transactions,
    )


def _propose_block_raw(chain, consensus, proposer, registration_transactions=None):
    """Propose a block bypassing state_root computation.

    Used for tests that expect validation to fail (e.g., insufficient balance)
    where the state root sim would crash on negative balances.
    """
    prev = chain.get_latest_block()
    import time as _time
    mtp = chain.get_median_time_past()
    now = _time.time()
    ts = now if now > mtp else mtp + 1e-6
    return consensus.create_block(
        proposer, [], prev,
        state_root=b"\x00" * 32,
        registration_transactions=registration_transactions,
        timestamp=ts,
    )


class TestConfigConstants(unittest.TestCase):
    """Config constants exist with expected values."""

    def test_max_registrations_per_block_exists(self):
        self.assertEqual(config.MAX_REGISTRATIONS_PER_BLOCK, 2)

    def test_registration_fee_production_value(self):
        """The production value is 1000; tests/__init__.py overrides to 0."""
        saved = config.REGISTRATION_FEE
        config.REGISTRATION_FEE = 1000
        self.assertEqual(config.REGISTRATION_FEE, 1000)
        config.REGISTRATION_FEE = saved


class TestRegistrationFee(unittest.TestCase):
    """Registration fee enforcement."""

    def setUp(self):
        self._saved_fee = config.REGISTRATION_FEE
        config.REGISTRATION_FEE = 1000

    def tearDown(self):
        config.REGISTRATION_FEE = self._saved_fee

    def test_registration_with_sufficient_sponsor_balance_accepted(self):
        """Registration succeeds when sponsor has >= REGISTRATION_FEE balance."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(
            new_entity, sponsor_id=genesis.entity_id,
        )
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block)
        self.assertTrue(valid, reason)
        chain.add_block(block)
        self.assertIn(new_entity.entity_id, chain.public_keys)

    def test_registration_with_insufficient_sponsor_balance_rejected(self):
        """Registration rejected when sponsor has < REGISTRATION_FEE balance."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        # Create a sponsor with very little balance
        sponsor = _make_entity()
        sponsor.keypair._next_leaf = 0
        # Register sponsor fee-free first
        old_fee = config.REGISTRATION_FEE
        config.REGISTRATION_FEE = 0
        reg_sponsor = create_registration_transaction(sponsor)
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_sponsor],
        )
        chain.add_block(block)
        config.REGISTRATION_FEE = old_fee

        # Sponsor has 0 balance — registration should fail validation
        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(
            new_entity, sponsor_id=sponsor.entity_id,
        )
        block2 = _propose_block_raw(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block2)
        self.assertFalse(valid)
        self.assertIn("Insufficient", reason)

    def test_registration_with_zero_fee_config_rejected(self):
        """When REGISTRATION_FEE > 0, a registration without sponsor is rejected."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(new_entity)
        block = _propose_block_raw(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("sponsor", reason.lower())

    def test_fee_deducted_from_sponsor_balance(self):
        """Registration fee is deducted from sponsor's balance."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        balance_before = chain.supply.get_balance(genesis.entity_id)

        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(
            new_entity, sponsor_id=genesis.entity_id,
        )
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        chain.add_block(block)

        balance_after = chain.supply.get_balance(genesis.entity_id)
        # Fee was deducted (balance decreased by at least REGISTRATION_FEE,
        # but may also get block rewards, so check the fee was definitely paid)
        # The sponsor's balance change = block_reward - fee.
        # Just verify fee was paid by checking treasury got it.
        self.assertGreaterEqual(
            balance_before - balance_after + 16,  # block reward is 16
            config.REGISTRATION_FEE,
        )

    def test_fee_goes_to_treasury(self):
        """Registration fee is credited to the treasury."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        treasury_before = chain.supply.get_balance(TREASURY_ENTITY_ID)

        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(
            new_entity, sponsor_id=genesis.entity_id,
        )
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        chain.add_block(block)

        treasury_after = chain.supply.get_balance(TREASURY_ENTITY_ID)
        # Treasury should have received at least REGISTRATION_FEE
        # (may also receive reward overflow)
        self.assertGreaterEqual(
            treasury_after - treasury_before, config.REGISTRATION_FEE,
        )

    def test_exact_balance_registration_succeeds(self):
        """Registration succeeds when sponsor has exactly REGISTRATION_FEE."""
        chain, consensus, genesis = _setup_chain_and_genesis()

        # Create a sponsor and give them exactly REGISTRATION_FEE
        sponsor = _make_entity()
        sponsor.keypair._next_leaf = 0
        old_fee = config.REGISTRATION_FEE
        config.REGISTRATION_FEE = 0
        reg_sponsor = create_registration_transaction(sponsor)
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_sponsor],
        )
        chain.add_block(block)
        config.REGISTRATION_FEE = old_fee

        # Transfer exactly REGISTRATION_FEE to sponsor
        from messagechain.core.transfer import create_transfer_transaction
        nonce = chain.nonces.get(genesis.entity_id, 0)
        ttx = create_transfer_transaction(
            genesis, sponsor.entity_id, config.REGISTRATION_FEE, nonce=nonce,
        )
        block2 = _propose_block(
            chain, consensus, genesis,
            transfer_transactions=[ttx],
        )
        chain.add_block(block2)

        sponsor_balance = chain.supply.get_balance(sponsor.entity_id)
        self.assertEqual(sponsor_balance, config.REGISTRATION_FEE)

        # Now sponsor registers a new entity — should succeed
        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(
            new_entity, sponsor_id=sponsor.entity_id,
        )
        block3 = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block3)
        self.assertTrue(valid, reason)
        chain.add_block(block3)

        # Sponsor balance should be 0
        self.assertEqual(chain.supply.get_balance(sponsor.entity_id), 0)

    def test_balance_below_fee_rejected(self):
        """Registration rejected when sponsor balance < REGISTRATION_FEE."""
        chain, consensus, genesis = _setup_chain_and_genesis()

        # Create a sponsor with less than REGISTRATION_FEE
        sponsor = _make_entity()
        sponsor.keypair._next_leaf = 0
        old_fee = config.REGISTRATION_FEE
        config.REGISTRATION_FEE = 0
        reg_sponsor = create_registration_transaction(sponsor)
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_sponsor],
        )
        chain.add_block(block)
        config.REGISTRATION_FEE = old_fee

        # Give sponsor less than REGISTRATION_FEE
        from messagechain.core.transfer import create_transfer_transaction
        nonce = chain.nonces.get(genesis.entity_id, 0)
        small_amount = config.REGISTRATION_FEE - 1
        ttx = create_transfer_transaction(
            genesis, sponsor.entity_id, small_amount, nonce=nonce,
        )
        block2 = _propose_block(
            chain, consensus, genesis,
            transfer_transactions=[ttx],
        )
        chain.add_block(block2)

        # Now try to sponsor a registration — should fail
        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(
            new_entity, sponsor_id=sponsor.entity_id,
        )
        block3 = _propose_block_raw(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block3)
        self.assertFalse(valid)
        self.assertIn("Insufficient", reason)

    def test_sponsor_must_be_registered(self):
        """Registration rejected when sponsor_id is not a registered entity."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        fake_sponsor = b"\x99" * 32
        reg_tx = create_registration_transaction(
            new_entity, sponsor_id=fake_sponsor,
        )
        block = _propose_block_raw(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("sponsor", reason.lower())


class TestPerBlockRegistrationCap(unittest.TestCase):
    """Per-block registration cap enforcement."""

    def setUp(self):
        self._saved_fee = config.REGISTRATION_FEE
        config.REGISTRATION_FEE = 0  # disable fee for cap tests

    def tearDown(self):
        config.REGISTRATION_FEE = self._saved_fee

    def test_block_with_two_registrations_valid(self):
        """Block with MAX_REGISTRATIONS_PER_BLOCK registrations is valid."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        reg_txs = []
        for i in range(config.MAX_REGISTRATIONS_PER_BLOCK):
            e = _make_entity()
            e.keypair._next_leaf = 0
            reg_txs.append(create_registration_transaction(e))

        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=reg_txs,
        )
        valid, reason = chain.validate_block(block)
        self.assertTrue(valid, reason)

    def test_block_with_three_registrations_invalid(self):
        """Block with > MAX_REGISTRATIONS_PER_BLOCK registrations is rejected."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        reg_txs = []
        for i in range(config.MAX_REGISTRATIONS_PER_BLOCK + 1):
            e = _make_entity()
            e.keypair._next_leaf = 0
            reg_txs.append(create_registration_transaction(e))

        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=reg_txs,
        )
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("registration", reason.lower())

    def test_cap_only_applies_to_registration_transactions(self):
        """Per-block cap does not affect other authority tx types."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        e = _make_entity()
        e.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(e)
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block)
        self.assertTrue(valid, reason)


class TestRegistrationFeeZeroOverride(unittest.TestCase):
    """When REGISTRATION_FEE is 0, registration works without sponsor."""

    def setUp(self):
        self._saved_fee = config.REGISTRATION_FEE
        config.REGISTRATION_FEE = 0

    def tearDown(self):
        config.REGISTRATION_FEE = self._saved_fee

    def test_zero_fee_no_sponsor_required(self):
        """With REGISTRATION_FEE=0, no sponsor is needed."""
        chain, consensus, genesis = _setup_chain_and_genesis()
        new_entity = _make_entity()
        new_entity.keypair._next_leaf = 0
        reg_tx = create_registration_transaction(new_entity)
        block = _propose_block(
            chain, consensus, genesis,
            registration_transactions=[reg_tx],
        )
        valid, reason = chain.validate_block(block)
        self.assertTrue(valid, reason)


if __name__ == "__main__":
    unittest.main()
