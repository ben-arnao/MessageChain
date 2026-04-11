"""
Security audit fixes — Opus 4.6 security review.

Tests for issues identified in the comprehensive security audit cross-referenced
with Bitcoin Core patterns. Each test corresponds to a specific vulnerability
and verifies the fix is in place.
"""

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
import time
import unittest

from messagechain.config import (
    CHAIN_ID,
    HASH_ALGO,
    MAX_TIMESTAMP_DRIFT,
    MERKLE_TREE_HEIGHT,
    MIN_FEE,
    UNBONDING_PERIOD,
    VALIDATOR_MIN_STAKE,
    WOTS_KEY_CHAINS,
)
from messagechain.crypto.keys import KeyPair, Signature, verify_signature
from messagechain.crypto.hash_sig import wots_verify


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# ============================================================================
# Issue #2: Timing side-channel in Merkle root verification
# ============================================================================

class TestMerkleRootConstantTime(unittest.TestCase):
    """keys.py:180 must use hmac.compare_digest, not ==."""

    def test_verify_uses_constant_time_compare(self):
        import inspect
        from messagechain.crypto import keys
        source = inspect.getsource(keys.verify_signature)
        # The verify function must use compare_digest for the root check
        self.assertIn("compare_digest", source,
                      "verify_signature must use hmac.compare_digest for root check")

    def test_invalid_root_rejected(self):
        """Sanity: a signature against a wrong root still fails cleanly."""
        kp = KeyPair.generate(seed=b"x" * 32)
        msg_hash = _hash(b"hello")
        sig = kp.sign(msg_hash)
        self.assertTrue(verify_signature(msg_hash, sig, kp.public_key))
        wrong_root = bytes(32)
        self.assertFalse(verify_signature(msg_hash, sig, wrong_root))


# ============================================================================
# Issue #4: Off-by-one in leaf index bounds check
# ============================================================================

class TestLeafIndexBounds(unittest.TestCase):
    """keys.py:117 — leaf_index == num_leaves must be rejected."""

    def test_advance_to_num_leaves_rejected(self):
        kp = KeyPair.generate(seed=b"y" * 32)
        # Valid range is [0, num_leaves). Equal to num_leaves is invalid.
        with self.assertRaises(RuntimeError):
            kp.advance_to_leaf(kp.num_leaves)

    def test_advance_past_num_leaves_rejected(self):
        kp = KeyPair.generate(seed=b"y" * 32)
        with self.assertRaises(RuntimeError):
            kp.advance_to_leaf(kp.num_leaves + 1)

    def test_advance_to_last_valid_leaf_ok(self):
        kp = KeyPair.generate(seed=b"y" * 32)
        # num_leaves - 1 is the last valid index
        kp.advance_to_leaf(kp.num_leaves - 1)


# ============================================================================
# Issue #3 / #8: Signature size and auth_path length validation
# ============================================================================

class TestSignatureValidation(unittest.TestCase):
    """Malformed signatures must be rejected cleanly, not cause exceptions."""

    def setUp(self):
        self.kp = KeyPair.generate(seed=b"z" * 32)
        self.msg_hash = _hash(b"test")
        self.sig = self.kp.sign(self.msg_hash)

    def test_truncated_wots_signature_rejected(self):
        bad = Signature(
            wots_signature=self.sig.wots_signature[:-1],  # missing one element
            leaf_index=self.sig.leaf_index,
            auth_path=self.sig.auth_path,
            wots_public_key=self.sig.wots_public_key,
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))

    def test_extended_wots_signature_rejected(self):
        bad = Signature(
            wots_signature=self.sig.wots_signature + [b"\x00" * 32],
            leaf_index=self.sig.leaf_index,
            auth_path=self.sig.auth_path,
            wots_public_key=self.sig.wots_public_key,
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))

    def test_wrong_size_wots_element_rejected(self):
        bad_sig_parts = list(self.sig.wots_signature)
        bad_sig_parts[0] = b"\x00" * 16  # wrong length
        bad = Signature(
            wots_signature=bad_sig_parts,
            leaf_index=self.sig.leaf_index,
            auth_path=self.sig.auth_path,
            wots_public_key=self.sig.wots_public_key,
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))

    def test_truncated_auth_path_rejected(self):
        bad = Signature(
            wots_signature=self.sig.wots_signature,
            leaf_index=self.sig.leaf_index,
            auth_path=self.sig.auth_path[:-1],  # one level short
            wots_public_key=self.sig.wots_public_key,
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))

    def test_extended_auth_path_rejected(self):
        bad = Signature(
            wots_signature=self.sig.wots_signature,
            leaf_index=self.sig.leaf_index,
            auth_path=self.sig.auth_path + [b"\x00" * 32],
            wots_public_key=self.sig.wots_public_key,
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))

    def test_out_of_range_leaf_index_rejected(self):
        bad = Signature(
            wots_signature=self.sig.wots_signature,
            leaf_index=self.kp.num_leaves,  # out of range
            auth_path=self.sig.auth_path,
            wots_public_key=self.sig.wots_public_key,
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))

    def test_negative_leaf_index_rejected(self):
        bad = Signature(
            wots_signature=self.sig.wots_signature,
            leaf_index=-1,
            auth_path=self.sig.auth_path,
            wots_public_key=self.sig.wots_public_key,
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))

    def test_wrong_size_public_key_rejected(self):
        bad = Signature(
            wots_signature=self.sig.wots_signature,
            leaf_index=self.sig.leaf_index,
            auth_path=self.sig.auth_path,
            wots_public_key=b"\x00" * 16,  # wrong size
            wots_public_seed=self.sig.wots_public_seed,
        )
        self.assertFalse(verify_signature(self.msg_hash, bad, self.kp.public_key))


# ============================================================================
# Issue #9: wots_verify input validation
# ============================================================================

class TestWotsVerifyInputValidation(unittest.TestCase):
    """wots_verify must return False for malformed input, not raise IndexError."""

    def test_short_signature_list_returns_false(self):
        self.assertFalse(wots_verify(b"\x00" * 32, [], b"\x00" * 32, b"\x00" * 32))

    def test_wrong_length_msg_hash_returns_false(self):
        sig = [b"\x00" * 32] * WOTS_KEY_CHAINS
        self.assertFalse(wots_verify(b"\x00" * 16, sig, b"\x00" * 32, b"\x00" * 32))

    def test_wrong_length_pubkey_returns_false(self):
        sig = [b"\x00" * 32] * WOTS_KEY_CHAINS
        self.assertFalse(wots_verify(b"\x00" * 32, sig, b"\x00" * 16, b"\x00" * 32))

    def test_wrong_length_sig_element_returns_false(self):
        sig = [b"\x00" * 16] * WOTS_KEY_CHAINS
        self.assertFalse(wots_verify(b"\x00" * 32, sig, b"\x00" * 32, b"\x00" * 32))


# ============================================================================
# Issue #1: Attestation signature validation
# ============================================================================

class TestAttestationSignatureRequired(unittest.TestCase):
    """pos.py must reject attestations if their public key is unavailable."""

    def test_unsigned_attestation_not_counted(self):
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.consensus.attestation import Attestation
        from messagechain.core.block import Block, BlockHeader

        pos = ProofOfStake()
        vid_a = b"a" * 32
        vid_b = b"b" * 32
        pos.register_validator(vid_a, 1000)
        pos.register_validator(vid_b, 1000)

        # Forge an attestation without signature verification possible
        att = Attestation(
            validator_id=vid_a,
            block_hash=b"x" * 32,
            block_number=1,
            signature=None,  # no signature
        )
        header = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32, timestamp=time.time(),
            proposer_id=vid_b, state_root=b"\x00" * 32,
        )
        block = Block(header=header, transactions=[], attestations=[att])

        # With NO public keys dict provided, attestation must be rejected — not silently counted
        result = pos.validate_block_attestations(block, public_keys=None)
        # The 2/3 check on 2000 total stake requires >=1334 attested.
        # The fake attestation is for 1000 stake. If counted, would fail consensus anyway.
        # Test more directly: public_keys={} (empty dict, vid_a not in it)
        result2 = pos.validate_block_attestations(block, public_keys={})
        # Whether or not consensus is reached, the untrusted attestation must not be counted.
        # We verify via a stronger scenario: 3 validators, attacker forges one to cross threshold.
        pos2 = ProofOfStake()
        pos2.register_validator(vid_a, 1000)
        pos2.register_validator(vid_b, 1000)
        vid_c = b"c" * 32
        pos2.register_validator(vid_c, 1000)
        # Attacker forges attestation from vid_a AND vid_b with no sigs — 2000/3000 = 66.6%
        att1 = Attestation(validator_id=vid_a, block_hash=b"x" * 32, block_number=1, signature=None)
        att2 = Attestation(validator_id=vid_b, block_hash=b"x" * 32, block_number=1, signature=None)
        block2 = Block(
            header=BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x00" * 32, timestamp=time.time(),
                proposer_id=vid_c, state_root=b"\x00" * 32,
            ),
            transactions=[],
            attestations=[att1, att2],
        )
        # Without public keys, this MUST fail consensus (don't silently accept).
        self.assertFalse(pos2.validate_block_attestations(block2, public_keys={}))


# ============================================================================
# Issue #12 / #14: Uniform timestamp validation
# ============================================================================

class TestTimestampValidation(unittest.TestCase):
    """All transaction types must validate timestamp > 0 and drift."""

    def _sign_stake(self, entity, *, timestamp, amount=VALIDATOR_MIN_STAKE, nonce=0, fee=MIN_FEE):
        from messagechain.core.staking import StakeTransaction
        from messagechain.crypto.keys import Signature
        tx = StakeTransaction(
            entity_id=entity.entity_id,
            amount=amount,
            nonce=nonce,
            timestamp=timestamp,
            fee=fee,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = entity.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx

    def _sign_unstake(self, entity, *, timestamp, amount=100, nonce=0, fee=MIN_FEE):
        from messagechain.core.staking import UnstakeTransaction
        from messagechain.crypto.keys import Signature
        tx = UnstakeTransaction(
            entity_id=entity.entity_id,
            amount=amount,
            nonce=nonce,
            timestamp=timestamp,
            fee=fee,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = entity.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx

    def _sign_transfer(self, sender, recipient, *, timestamp, amount=100, nonce=0, fee=MIN_FEE):
        from messagechain.core.transfer import TransferTransaction
        from messagechain.crypto.keys import Signature
        tx = TransferTransaction(
            entity_id=sender.entity_id,
            recipient_id=recipient.entity_id,
            amount=amount,
            nonce=nonce,
            timestamp=timestamp,
            fee=fee,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = sender.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx

    def _sign_key_rotation(self, entity, *, timestamp, new_public_key=None, fee=1000, rotation_number=0):
        from messagechain.core.key_rotation import KeyRotationTransaction
        from messagechain.crypto.keys import Signature
        if new_public_key is None:
            new_public_key = b"Z" * 32
        tx = KeyRotationTransaction(
            entity_id=entity.entity_id,
            old_public_key=entity.public_key,
            new_public_key=new_public_key,
            rotation_number=rotation_number,
            timestamp=timestamp,
            fee=fee,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = entity.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx

    def test_transfer_zero_timestamp_rejected(self):
        from messagechain.core.transfer import verify_transfer_transaction
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"a".ljust(32, b"\x00") * 32)
        bob = Entity.create(b"b".ljust(32, b"\x00") * 32)
        tx = self._sign_transfer(alice, bob, timestamp=0)
        self.assertFalse(verify_transfer_transaction(tx, alice.public_key))

    def test_stake_zero_timestamp_rejected(self):
        from messagechain.core.staking import verify_stake_transaction
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"a".ljust(32, b"\x00") * 32)
        tx = self._sign_stake(alice, timestamp=0)
        self.assertFalse(verify_stake_transaction(tx, alice.public_key))

    def test_stake_future_timestamp_rejected(self):
        from messagechain.core.staking import verify_stake_transaction
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"a".ljust(32, b"\x00") * 32)
        tx = self._sign_stake(alice, timestamp=time.time() + MAX_TIMESTAMP_DRIFT + 1000)
        self.assertFalse(verify_stake_transaction(tx, alice.public_key))

    def test_unstake_zero_timestamp_rejected(self):
        from messagechain.core.staking import verify_unstake_transaction
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"a".ljust(32, b"\x00") * 32)
        tx = self._sign_unstake(alice, timestamp=0)
        self.assertFalse(verify_unstake_transaction(tx, alice.public_key))

    def test_key_rotation_zero_timestamp_rejected(self):
        from messagechain.core.key_rotation import verify_key_rotation
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"a".ljust(32, b"\x00") * 32)
        tx = self._sign_key_rotation(alice, timestamp=0)
        self.assertFalse(verify_key_rotation(tx, alice.public_key))


# ============================================================================
# Issue #19: Minimum private key entropy
# ============================================================================

class TestPrivateKeyMinEntropy(unittest.TestCase):
    def test_short_key_rejected(self):
        from messagechain.identity.identity import Entity
        # A truly short key (< 32 bytes) must be rejected.
        with self.assertRaises(ValueError):
            Entity.create(b"short")  # 5 bytes, below minimum

    def test_empty_key_rejected(self):
        from messagechain.identity.identity import Entity
        with self.assertRaises(ValueError):
            Entity.create(b"")

    def test_32_byte_key_accepted(self):
        from messagechain.identity.identity import Entity
        Entity.create(os.urandom(32))


# ============================================================================
# Issue #18: secure randomness for relay privacy
# ============================================================================

class TestRelayPrivacyRandomness(unittest.TestCase):
    def test_uses_secure_randomness(self):
        import inspect
        from messagechain.network import relay_privacy
        source = inspect.getsource(relay_privacy)
        # Must not import the unsafe random module at the top level
        self.assertNotIn("import random", source,
                         "relay_privacy.py must not use Python's random module")


# ============================================================================
# Issue #17: MessageType enum validation
# ============================================================================

class TestMessageTypeEnumValidation(unittest.TestCase):
    def test_invalid_message_type_rejected(self):
        from messagechain.network.protocol import NetworkMessage
        with self.assertRaises((ValueError, KeyError)):
            NetworkMessage.deserialize({"type": "not_a_real_type", "payload": {}})

    def test_missing_type_rejected(self):
        from messagechain.network.protocol import NetworkMessage
        with self.assertRaises((ValueError, KeyError)):
            NetworkMessage.deserialize({"payload": {}})


# ============================================================================
# Issue #15: JSON depth check happens during parsing, not after
# ============================================================================

class TestJsonDepthStreaming(unittest.TestCase):
    def test_deeply_nested_rejected(self):
        from messagechain.validation import safe_json_loads
        # Build 1000-level nested JSON
        payload = "{" * 1000 + '"x": 1' + "}" * 1000
        with self.assertRaises(ValueError):
            safe_json_loads(payload, max_depth=32)


# ============================================================================
# Issue #5: Slashing covers pending unstakes (lookback window == unbonding)
# ============================================================================

class TestSlashingCoversPendingUnstakes(unittest.TestCase):
    """A validator who unstakes after committing an offense must still be
    slashable for the full UNBONDING_PERIOD window."""

    def test_pending_unstake_slashable(self):
        from messagechain.economics.inflation import SupplyTracker
        vid = b"v" * 32
        finder = b"f" * 32
        supply = SupplyTracker()
        supply.balances[vid] = 5000
        self.assertTrue(supply.stake(vid, 1000))
        # Immediately unstake — tokens go to pending_unstakes
        self.assertTrue(supply.unstake(vid, 1000, current_block=100))
        self.assertEqual(supply.get_staked(vid), 0)
        self.assertEqual(supply.get_pending_unstake(vid), 1000)
        # Slash must still capture the pending 1000
        total_slashed, _ = supply.slash_validator(vid, finder)
        self.assertEqual(total_slashed, 1000)
        self.assertEqual(supply.get_pending_unstake(vid), 0)


# ============================================================================
# Issue #7: Slashing state persistence
# ============================================================================

class TestSlashingStatePersistence(unittest.TestCase):
    def test_slashed_validators_persisted_across_restart(self):
        from messagechain.storage.chaindb import ChainDB
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "chain.db")
            db = ChainDB(db_path)
            vid = b"v" * 32
            db.set_slashed(vid)
            self.assertIn(vid, db.get_slashed_validators())
            db.close()

            db2 = ChainDB(db_path)
            self.assertIn(vid, db2.get_slashed_validators())
            db2.close()

    def test_processed_evidence_persisted_across_restart(self):
        from messagechain.storage.chaindb import ChainDB
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "chain.db")
            db = ChainDB(db_path)
            evidence_hash = b"e" * 32
            db.mark_evidence_processed(evidence_hash)
            self.assertTrue(db.is_evidence_processed(evidence_hash))
            db.close()

            db2 = ChainDB(db_path)
            self.assertTrue(db2.is_evidence_processed(evidence_hash))
            db2.close()


if __name__ == "__main__":
    unittest.main()
