"""
Security audit: pay_fee_with_burn() return value must be checked.

CRITICAL BUG: pay_fee_with_burn() returns False when fee < base_fee or
the sender can't afford the fee, but NO caller checks the return value.
This means state changes (authority key updates, staking, key rotations,
governance votes) get applied even when the fee payment fails —
effectively free transactions.

These tests verify:
1. Block validation rejects txs with fee < base_fee (Part 1)
2. Apply methods check pay_fee_with_burn return value (Part 2)
3. Happy path still works when fee >= base_fee
"""

import os
import time
import unittest

from messagechain import config
from messagechain.config import (
    MIN_FEE, BASE_FEE_INITIAL, MIN_TIP,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import MessageTransaction
from messagechain.identity.identity import Entity
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _setup_chain_and_proposer():
    """Create a chain with a registered, funded, staked proposer + genesis."""
    chain = Blockchain()
    consensus = ProofOfStake()
    proposer = _entity(b"proposer")
    proof = proposer.keypair.sign(_hash(b"register" + proposer.entity_id))
    chain._install_pubkey_direct(proposer.entity_id, proposer.public_key, proof)
    chain.supply.balances[proposer.entity_id] = 200_000_000
    chain.supply.staked[proposer.entity_id] = 100_000_000
    chain.initialize_genesis(proposer)
    consensus.register_validator(proposer.entity_id, stake_amount=100_000_000)
    return chain, consensus, proposer


def _register_entity(chain, entity, balance=10_000_000):
    """Register and fund an entity on the chain."""
    proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
    chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)
    chain.supply.balances[entity.entity_id] = balance


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height


class TestBaseFeeValidationInBlock(_Base):
    """Part 1: validate_block must reject txs with fee < base_fee.

    NOTE: We set base_fee to a high value (e.g. 1000) and use a fee that
    passes the per-tx-type minimum fee check (e.g. calculate_min_fee) but
    is still below base_fee. This isolates the base_fee check.
    """

    # Use a fee above any per-tx minimum but below the elevated base_fee.
    ELEVATED_BASE_FEE = 1000
    # Fee that passes tx-level validation but < ELEVATED_BASE_FEE.
    BELOW_BASE_FEE = 200

    def _make_message_tx(self, entity, nonce, fee):
        """Create a signed message transaction."""
        tx = MessageTransaction(
            entity_id=entity.entity_id,
            message=b"hi",  # short message so min_fee stays low
            fee=fee,
            nonce=nonce,
            timestamp=time.time(),
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = entity.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx

    def test_message_tx_rejected_when_fee_below_base_fee(self):
        """A message tx with fee < base_fee must be rejected by validate_block."""
        chain, consensus, proposer = _setup_chain_and_proposer()
        sender = _entity(b"sender1")
        _register_entity(chain, sender)

        chain.supply.base_fee = self.ELEVATED_BASE_FEE

        # Fee passes min_fee for a tiny message but is below base_fee
        tx = self._make_message_tx(sender, nonce=0, fee=self.BELOW_BASE_FEE)

        block = chain.propose_block(consensus, proposer, [tx])
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid, f"Block should be rejected but got: {reason}")
        self.assertIn("base_fee", reason.lower())

    def test_transfer_tx_rejected_when_fee_below_base_fee(self):
        """A transfer tx with fee < base_fee must be rejected by validate_block."""
        from messagechain.core.transfer import create_transfer_transaction
        chain, consensus, proposer = _setup_chain_and_proposer()
        sender = _entity(b"sender2")
        recipient = _entity(b"recip2")
        _register_entity(chain, sender)
        _register_entity(chain, recipient)

        chain.supply.base_fee = self.ELEVATED_BASE_FEE

        ttx = create_transfer_transaction(
            sender, recipient.entity_id, amount=100, nonce=0,
            fee=self.BELOW_BASE_FEE,
        )

        block = chain.propose_block(
            consensus, proposer, [],
            transfer_transactions=[ttx],
        )
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid, f"Block should be rejected but got: {reason}")
        self.assertIn("base_fee", reason.lower())

    def test_set_authority_key_tx_rejected_when_fee_below_base_fee(self):
        """SetAuthorityKey tx with fee < base_fee must be rejected."""
        from messagechain.core.authority_key import (
            create_set_authority_key_transaction,
        )
        chain, consensus, proposer = _setup_chain_and_proposer()
        hot = _entity(b"hotkey3")
        cold = _entity(b"coldkey3")
        _register_entity(chain, hot)

        chain.supply.base_fee = self.ELEVATED_BASE_FEE

        atx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0,
            fee=self.BELOW_BASE_FEE,
        )

        block = chain.propose_block(
            consensus, proposer, [],
            authority_txs=[atx],
        )
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid, f"Block should be rejected but got: {reason}")
        self.assertIn("base_fee", reason.lower())

    def test_stake_tx_rejected_when_fee_below_base_fee(self):
        """Stake tx with fee < base_fee must be rejected."""
        from messagechain.core.staking import create_stake_transaction
        chain, consensus, proposer = _setup_chain_and_proposer()
        staker = _entity(b"staker4")
        _register_entity(chain, staker, balance=10_000_000)

        chain.supply.base_fee = self.ELEVATED_BASE_FEE

        stx = create_stake_transaction(
            staker, amount=1000, fee=self.BELOW_BASE_FEE, nonce=0,
        )

        block = chain.propose_block(
            consensus, proposer, [],
            stake_transactions=[stx],
        )
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid, f"Block should be rejected but got: {reason}")
        self.assertIn("base_fee", reason.lower())

    def test_governance_vote_rejected_when_fee_below_base_fee(self):
        """Governance vote with fee < base_fee must be rejected."""
        from messagechain.governance.governance import create_vote
        chain, consensus, proposer = _setup_chain_and_proposer()
        voter = _entity(b"voter5")
        _register_entity(chain, voter)

        chain.supply.base_fee = self.ELEVATED_BASE_FEE

        vote = create_vote(
            voter, b"\x01" * 32, approve=True, fee=self.BELOW_BASE_FEE,
        )

        block = chain.propose_block(
            consensus, proposer, [],
            governance_txs=[vote],
        )
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid, f"Block should be rejected but got: {reason}")
        self.assertIn("base_fee", reason.lower())

    def test_dynamic_base_fee_rise_rejects_old_fee_txs(self):
        """When base_fee rises above MIN_FEE, txs at old fee are rejected."""
        chain, consensus, proposer = _setup_chain_and_proposer()
        sender = _entity(b"sender6")
        _register_entity(chain, sender)

        # Simulate base_fee increase
        chain.supply.base_fee = 500

        # TX with fee 200 (passes min_fee for short msg, but < base_fee 500)
        tx = self._make_message_tx(sender, nonce=0, fee=200)
        block = chain.propose_block(consensus, proposer, [tx])
        valid, reason = chain.validate_block(block)
        self.assertFalse(valid, f"Block should be rejected but got: {reason}")
        self.assertIn("base_fee", reason.lower())


class TestHappyPathWithBaseFee(_Base):
    """Fee >= base_fee should still work correctly."""

    def _make_message_tx(self, entity, nonce, fee):
        """Create a signed message transaction."""
        tx = MessageTransaction(
            entity_id=entity.entity_id,
            message=b"hi",  # short message, low min_fee
            fee=fee,
            nonce=nonce,
            timestamp=time.time(),
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = entity.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx

    def test_message_tx_accepted_when_fee_meets_base_fee(self):
        """Message tx with fee >= base_fee should pass validation."""
        chain, consensus, proposer = _setup_chain_and_proposer()
        sender = _entity(b"happy1")
        _register_entity(chain, sender)

        from messagechain.core.transaction import calculate_min_fee
        msg_min_fee = calculate_min_fee(b"hi")
        # Fee must satisfy both: >= base_fee AND >= calculate_min_fee
        fee = max(chain.supply.base_fee, msg_min_fee) + MIN_TIP
        tx = self._make_message_tx(sender, nonce=0, fee=fee)

        block = chain.propose_block(consensus, proposer, [tx])
        valid, reason = chain.validate_block(block)
        self.assertTrue(valid, f"Valid block rejected: {reason}")

    def test_message_tx_accepted_when_base_fee_elevated(self):
        """Even with elevated base_fee, txs meeting it should succeed."""
        chain, consensus, proposer = _setup_chain_and_proposer()
        sender = _entity(b"happy2")
        _register_entity(chain, sender)

        chain.supply.base_fee = 500
        from messagechain.core.transaction import calculate_min_fee
        msg_min_fee = calculate_min_fee(b"hi")
        fee = max(chain.supply.base_fee, msg_min_fee) + MIN_TIP  # 501

        tx = self._make_message_tx(sender, nonce=0, fee=fee)

        block = chain.propose_block(consensus, proposer, [tx])
        valid, reason = chain.validate_block(block)
        self.assertTrue(valid, f"Valid block rejected: {reason}")


class TestApplyMethodsCheckFeeReturn(_Base):
    """Part 2: apply methods must not apply state changes when fee payment fails."""

    def test_apply_set_authority_key_fails_on_fee_failure(self):
        """apply_set_authority_key must return failure when fee < base_fee."""
        from messagechain.core.authority_key import (
            create_set_authority_key_transaction,
        )
        chain, _, proposer = _setup_chain_and_proposer()
        hot = _entity(b"hotA")
        cold = _entity(b"coldA")
        _register_entity(chain, hot)

        # Fee 200 passes the MIN_FEE check but is below base_fee 1000
        chain.supply.base_fee = 1000

        atx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=200,
        )

        ok, reason = chain.apply_set_authority_key(atx, proposer.entity_id)
        self.assertFalse(ok, "Should fail when fee < base_fee")
        # Authority key must NOT have been updated
        self.assertNotEqual(
            chain.authority_keys.get(hot.entity_id), cold.public_key,
            "State must not change when fee payment fails",
        )

    def test_apply_key_rotation_fails_on_fee_failure(self):
        """apply_key_rotation must return failure when fee < base_fee."""
        from messagechain.core.key_rotation import (
            create_key_rotation, derive_rotated_keypair,
        )
        from messagechain.config import KEY_ROTATION_FEE
        chain, _, proposer = _setup_chain_and_proposer()
        entity = _entity(b"rotateB")
        _register_entity(chain, entity)

        # Set base_fee much higher than KEY_ROTATION_FEE
        chain.supply.base_fee = max(KEY_ROTATION_FEE, MIN_FEE) * 10

        new_kp = derive_rotated_keypair(entity.keypair, rotation_number=0)
        rtx = create_key_rotation(
            entity, new_kp, rotation_number=0,
            fee=KEY_ROTATION_FEE,  # below base_fee
        )

        ok, reason = chain.apply_key_rotation(rtx, proposer.entity_id)
        self.assertFalse(ok, "Should fail when fee < base_fee")
        # Public key must NOT have been updated
        self.assertEqual(
            chain.public_keys[entity.entity_id], entity.public_key,
            "State must not change when fee payment fails",
        )

    def test_apply_block_state_skips_message_tx_on_fee_failure(self):
        """_apply_block_state must not apply nonce/state when pay_fee_with_burn fails."""
        chain, consensus, proposer = _setup_chain_and_proposer()
        sender = _entity(b"senderC")
        _register_entity(chain, sender)

        initial_nonce = chain.nonces.get(sender.entity_id, 0)

        # Raise base_fee so fee payment will fail
        chain.supply.base_fee = 1000

        tx = MessageTransaction(
            entity_id=sender.entity_id,
            message=b"hi",
            fee=200,  # above min_fee for short msg, below base_fee 1000
            nonce=0,
            timestamp=time.time(),
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = sender.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()

        # Build a block (bypassing validation to test defense-in-depth)
        block = chain.propose_block(consensus, proposer, [tx])

        # Apply the block state directly (simulating a pre-validated block)
        chain._apply_block_state(block)

        # The sender's nonce should NOT have advanced if fee failed
        final_nonce = chain.nonces.get(sender.entity_id, 0)
        self.assertEqual(
            final_nonce, initial_nonce,
            "Nonce must not advance when pay_fee_with_burn fails "
            "(defense-in-depth in _apply_block_state)",
        )


if __name__ == "__main__":
    unittest.main()
