"""Tests for crypto-agility version fields.

These fields carry no dispatch logic yet — the runtime only knows SHA-256
and WOTS_W16_K64. What the tests pin down is the FIELD EXISTENCE and the
CONSENSUS GATE, so that when a future hash or signature scheme ships, the
chain can activate it via governance without a hard fork that abandons
history.

See CLAUDE.md Principle #3 (long-term thinking on the 100–1000 year scale):
SHA-256 will break someday. Adding 1 byte per block + 1 byte per signature
now is a trivial cost; retrofitting later would require a chain-resetting
hard fork that loses every historical transaction.
"""

import time
import unittest

from messagechain.config import (
    HASH_VERSION_CURRENT, HASH_VERSION_SHA256,
    SIG_VERSION_CURRENT, SIG_VERSION_WOTS_W16_K64,
)
from messagechain.core.block import BlockHeader, Block, create_genesis_block
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity

from tests import register_entity_for_test


class TestCryptoAgilityConstants(unittest.TestCase):
    """Version constants exist and carry the expected defaults."""

    def test_hash_version_sha256_is_one(self):
        self.assertEqual(HASH_VERSION_SHA256, 1)

    def test_hash_version_current_is_sha256(self):
        self.assertEqual(HASH_VERSION_CURRENT, HASH_VERSION_SHA256)

    def test_sig_version_wots_w16_k64_is_one(self):
        self.assertEqual(SIG_VERSION_WOTS_W16_K64, 1)

    def test_sig_version_current_is_wots(self):
        self.assertEqual(SIG_VERSION_CURRENT, SIG_VERSION_WOTS_W16_K64)


class TestBlockHeaderHashVersion(unittest.TestCase):
    """BlockHeader carries hash_version and commits it to the header hash."""

    def _make_header(self, **overrides) -> BlockHeader:
        kwargs = dict(
            version=1,
            block_number=7,
            prev_hash=b"\x11" * 32,
            merkle_root=b"\x22" * 32,
            timestamp=1_700_000_000.0,
            proposer_id=b"\x33" * 32,
        )
        kwargs.update(overrides)
        return BlockHeader(**kwargs)

    def test_default_hash_version_is_current(self):
        hdr = self._make_header()
        self.assertEqual(hdr.hash_version, HASH_VERSION_CURRENT)

    def test_signable_data_commits_hash_version(self):
        hdr_v1 = self._make_header(hash_version=1)
        hdr_v2 = self._make_header(hash_version=2)
        # Different hash_version must produce different signable bytes,
        # otherwise an upgrade cannot be signaled safely.
        self.assertNotEqual(hdr_v1.signable_data(), hdr_v2.signable_data())

    def test_binary_round_trip_preserves_hash_version(self):
        hdr = self._make_header(hash_version=1)
        blob = hdr.to_bytes()
        restored = BlockHeader.from_bytes(blob)
        self.assertEqual(restored.hash_version, 1)

    def test_dict_round_trip_preserves_hash_version(self):
        hdr = self._make_header(hash_version=1)
        restored = BlockHeader.deserialize(hdr.serialize())
        self.assertEqual(restored.hash_version, 1)


class TestSignatureSigVersion(unittest.TestCase):
    """Signature carries sig_version and round-trips it through all encodings."""

    def _sig(self, **overrides) -> Signature:
        kwargs = dict(
            wots_signature=[],
            leaf_index=0,
            auth_path=[],
            wots_public_key=b"",
            wots_public_seed=b"",
        )
        kwargs.update(overrides)
        return Signature(**kwargs)

    def test_default_sig_version_is_current(self):
        sig = self._sig()
        self.assertEqual(sig.sig_version, SIG_VERSION_CURRENT)

    def test_new_signatures_from_keypair_carry_current_version(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        msg_hash = b"\x00" * 32
        sig = entity.keypair.sign(msg_hash)
        self.assertEqual(sig.sig_version, SIG_VERSION_CURRENT)

    def test_binary_round_trip_preserves_sig_version(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        sig = entity.keypair.sign(b"\x00" * 32)
        restored = Signature.from_bytes(sig.to_bytes())
        self.assertEqual(restored.sig_version, sig.sig_version)

    def test_dict_round_trip_preserves_sig_version(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        sig = entity.keypair.sign(b"\x00" * 32)
        restored = Signature.deserialize(sig.serialize())
        self.assertEqual(restored.sig_version, sig.sig_version)

    def test_unknown_sig_version_rejected_by_binary_decoder(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        sig = entity.keypair.sign(b"\x00" * 32)
        sig.sig_version = 2  # unknown/future version
        blob = sig.to_bytes()
        with self.assertRaises(ValueError):
            Signature.from_bytes(blob)

    def test_zero_sig_version_rejected_by_binary_decoder(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        sig = entity.keypair.sign(b"\x00" * 32)
        sig.sig_version = 0  # reserved/invalid
        blob = sig.to_bytes()
        with self.assertRaises(ValueError):
            Signature.from_bytes(blob)

    def test_unknown_sig_version_rejected_by_dict_decoder(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        sig = entity.keypair.sign(b"\x00" * 32)
        sig.sig_version = 99
        data = sig.serialize()
        with self.assertRaises(ValueError):
            Signature.deserialize(data)


class TestTxSigVersionCommitment(unittest.TestCase):
    """Transaction _signable_data commits sig_version so tx_hash is tamper-evident."""

    def test_tx_hash_covers_sig_version(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        tx = create_transaction(entity, "hello", fee=10_000, nonce=0)
        original_hash = tx.tx_hash
        tx.signature.sig_version = 2  # flip version
        new_hash = tx._compute_hash()
        self.assertNotEqual(
            original_hash, new_hash,
            "tx_hash must commit to sig_version so a version swap is detectable",
        )


class TestValidateCryptoVersionGate(unittest.TestCase):
    """Blocks and transactions with unknown crypto versions are rejected."""

    def _setup_chain(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        genesis_entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        chain.initialize_genesis(genesis_entity)
        return chain, genesis_entity

    def test_genesis_block_has_hash_version_one(self):
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        genesis = create_genesis_block(entity)
        self.assertEqual(genesis.header.hash_version, HASH_VERSION_CURRENT)

    def test_block_with_unknown_hash_version_rejected(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        genesis_entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        chain.initialize_genesis(genesis_entity)

        # Manually construct a block with hash_version=2 (unknown).
        parent = chain.get_latest_block()
        hdr = BlockHeader(
            version=1,
            block_number=parent.header.block_number + 1,
            prev_hash=parent.block_hash,
            merkle_root=b"\x00" * 32,
            timestamp=time.time() + 1,
            proposer_id=genesis_entity.entity_id,
            hash_version=2,
        )
        msg_hash = hdr.signable_data()
        import hashlib
        from messagechain.config import HASH_ALGO
        hdr.proposer_signature = genesis_entity.keypair.sign(
            hashlib.new(HASH_ALGO, msg_hash).digest()
        )
        block = Block(header=hdr, transactions=[])

        valid, reason = chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("hash version", reason.lower())

    def test_block_with_zero_hash_version_rejected(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        genesis_entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        chain.initialize_genesis(genesis_entity)

        parent = chain.get_latest_block()
        hdr = BlockHeader(
            version=1,
            block_number=parent.header.block_number + 1,
            prev_hash=parent.block_hash,
            merkle_root=b"\x00" * 32,
            timestamp=time.time() + 1,
            proposer_id=genesis_entity.entity_id,
            hash_version=0,
        )
        import hashlib
        from messagechain.config import HASH_ALGO
        hdr.proposer_signature = genesis_entity.keypair.sign(
            hashlib.new(HASH_ALGO, hdr.signable_data()).digest()
        )
        block = Block(header=hdr, transactions=[])

        valid, reason = chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("hash version", reason.lower())

    def test_tx_with_unknown_sig_version_rejected(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        genesis_entity = Entity.create(b"crypto-agility-genesis-key-32byte")
        chain.initialize_genesis(genesis_entity)

        # Register an entity that can actually send a tx (distinct key
        # from genesis so entity_ids don't collide).
        user = Entity.create(b"crypto-agility-user-key-32-bytes!")
        register_entity_for_test(chain, user)
        # Give the user some balance so the fee check doesn't eclipse our sig
        # version check.
        chain.supply.balances[user.entity_id] = 1_000_000

        tx = create_transaction(user, "hi", fee=10_000, nonce=0)
        # Tamper after signing: flip the version on the signature.  Normally
        # this would also invalidate the tx hash commitment; we re-compute it
        # so the gate fires on VERSION, not on HASH_MISMATCH.
        tx.signature.sig_version = 2
        tx.tx_hash = tx._compute_hash()

        valid, reason = chain.validate_transaction(tx)
        self.assertFalse(valid)
        # Either an explicit version reject or the signature failing to
        # verify under the new version bytes — both prove the gate fired.
        self.assertTrue(
            "sig" in reason.lower() and (
                "version" in reason.lower() or "signature" in reason.lower()
            ),
            f"Expected sig-version or signature rejection, got: {reason}",
        )


class TestSignatureBinaryExtended(unittest.TestCase):
    """Binary encoding carries sig_version as an extended-trailing u8."""

    def test_truncated_blob_without_sig_version_rejected(self):
        # A real signature's blob includes a u8 sig_version at the end.
        # Truncating the trailing byte simulates a pre-migration blob or
        # a malicious truncation — either must be rejected, never silently
        # accepted as a valid sig with an implied sig_version.
        entity = Entity.create(b"crypto-agility-test-key-32bytes!")
        sig = entity.keypair.sign(b"\x00" * 32)
        blob = sig.to_bytes()
        truncated = blob[:-1]
        with self.assertRaises(ValueError):
            Signature.from_bytes(truncated)


if __name__ == "__main__":
    unittest.main()
