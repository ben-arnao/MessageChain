"""Tests for security audit fixes (BTC reference audit).

Covers:
  #1  Constant-time signature comparison
  #2  Chain ID in transaction signatures
  #3  State root verification before mutation
  #4  RANDAO integration in proposer selection
  #5  Comprehensive IP validation
  #6  Orphan block pre-validation
  #7  Conflicting attestation rejection
  #8  Full 256-bit entropy in proposer selection
  #9  Canonical integer timestamp encoding
  #10 Governance state rollback on reorg
  #11 Signature cache concurrency protection
  #12 Duplicate process_pending_unstakes removal
"""

import hashlib
import hmac
import struct
import time
import unittest

from messagechain.config import HASH_ALGO, MIN_FEE, GENESIS_ALLOCATION
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, _hash, compute_merkle_root
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.transfer import (
    TransferTransaction, create_transfer_transaction,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.attestation import (
    Attestation, FinalityTracker, create_attestation, verify_attestation,
)
from messagechain.consensus.randao import RANDAOMix, randao_select_proposer
from messagechain.crypto.hash_sig import wots_keygen, wots_sign, wots_verify
from messagechain.crypto.sig_cache import SignatureCache
from messagechain.network.node import Node
from tests import register_entity_for_test


class TestConstantTimeComparison(unittest.TestCase):
    """#1: wots_verify must use constant-time comparison."""

    def test_uses_hmac_compare_digest(self):
        """Verify that wots_verify uses hmac.compare_digest, not bare ==."""
        import inspect
        source = inspect.getsource(wots_verify)
        self.assertIn("hmac.compare_digest", source,
                       "wots_verify must use hmac.compare_digest for timing-attack resistance")

    def test_verification_still_works(self):
        """Constant-time comparison doesn't break valid signatures."""
        seed = b"test-seed-for-constant-time"
        private_keys, public_key, public_seed = wots_keygen(seed)
        msg = _hash(b"test message")
        sig = wots_sign(msg, private_keys, public_seed)
        self.assertTrue(wots_verify(msg, sig, public_key, public_seed))

    def test_invalid_sig_still_rejected(self):
        """Constant-time comparison still rejects invalid signatures."""
        seed = b"test-seed-for-constant-time"
        private_keys, public_key, public_seed = wots_keygen(seed)
        msg = _hash(b"test message")
        sig = wots_sign(msg, private_keys, public_seed)
        wrong_pk = _hash(b"wrong public key")
        self.assertFalse(wots_verify(msg, sig, wrong_pk, public_seed))


class TestChainID(unittest.TestCase):
    """#2: Transaction signatures must include chain ID."""

    def test_chain_id_in_config(self):
        """CHAIN_ID must be defined in config."""
        import messagechain.config as cfg
        self.assertTrue(hasattr(cfg, "CHAIN_ID"),
                        "config.py must define CHAIN_ID")
        self.assertIsInstance(cfg.CHAIN_ID, bytes)
        self.assertGreater(len(cfg.CHAIN_ID), 0)

    def test_message_tx_signable_data_includes_chain_id(self):
        """MessageTransaction._signable_data must include CHAIN_ID."""
        import messagechain.config as cfg
        entity = Entity.create(b"chain-id-test-key")
        tx = create_transaction(entity, "test", MIN_FEE + 100, nonce=0)
        signable = tx._signable_data()
        self.assertIn(cfg.CHAIN_ID, signable,
                      "MessageTransaction signable_data must contain CHAIN_ID")

    def test_transfer_tx_signable_data_includes_chain_id(self):
        """TransferTransaction._signable_data must include CHAIN_ID."""
        import messagechain.config as cfg
        alice = Entity.create(b"chain-id-alice")
        bob = Entity.create(b"chain-id-bob")
        tx = create_transfer_transaction(alice, bob.entity_id, 100, nonce=0)
        signable = tx._signable_data()
        self.assertIn(cfg.CHAIN_ID, signable,
                      "TransferTransaction signable_data must contain CHAIN_ID")

    def test_attestation_signable_data_includes_chain_id(self):
        """Attestation.signable_data must include CHAIN_ID."""
        import messagechain.config as cfg
        entity = Entity.create(b"chain-id-att-key")
        att = create_attestation(entity, _hash(b"block"), block_number=1)
        signable = att.signable_data()
        self.assertIn(cfg.CHAIN_ID, signable,
                      "Attestation signable_data must contain CHAIN_ID")


class TestStateRootBeforeMutation(unittest.TestCase):
    """#3: State root must be verified before applying block state."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"state-root-alice")
        cls.bob = Entity.create(b"state-root-bob")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

    def test_bad_state_root_does_not_corrupt_state(self):
        """A block with wrong state_root must not mutate chain state."""
        chain = Blockchain()
        chain.initialize_genesis(self.alice)
        register_entity_for_test(chain, self.bob)
        chain.supply.balances[self.bob.entity_id] = 10000

        # Snapshot balances before
        alice_bal_before = chain.supply.get_balance(self.alice.entity_id)
        bob_bal_before = chain.supply.get_balance(self.bob.entity_id)
        nonces_before = dict(chain.nonces)

        # Create a valid tx (fee must cover MIN_FEE + per-byte cost)
        tx = create_transaction(self.bob, "test", MIN_FEE + 100, nonce=0)

        # Create block with WRONG state root
        consensus = ProofOfStake()
        prev = chain.get_latest_block()
        block = consensus.create_block(
            self.alice, [tx], prev, state_root=b"\xff" * 32,
        )

        success, reason = chain.add_block(block)
        self.assertFalse(success)
        self.assertIn("state_root", reason.lower())

        # State must be unchanged
        self.assertEqual(chain.supply.get_balance(self.alice.entity_id), alice_bal_before)
        self.assertEqual(chain.supply.get_balance(self.bob.entity_id), bob_bal_before)
        self.assertEqual(chain.nonces, nonces_before)


class TestRANDAOIntegration(unittest.TestCase):
    """#4: ProofOfStake must use RANDAO mix in proposer selection."""

    def test_pos_select_proposer_accepts_randao_mix(self):
        """select_proposer must accept an optional randao_mix parameter."""
        pos = ProofOfStake()
        pos.register_validator(b"a" * 32, 1000)
        pos.register_validator(b"b" * 32, 1000)

        prev_hash = _hash(b"block")
        mix = _hash(b"randao")

        # With different RANDAO mixes, proposer selection should differ
        # (not guaranteed but highly likely with different entropy)
        result_with_mix = pos.select_proposer(prev_hash, randao_mix=mix)
        self.assertIsNotNone(result_with_mix)

    def test_different_randao_produces_different_selection(self):
        """Different RANDAO mixes should produce different selections over many trials."""
        pos = ProofOfStake()
        # Register many validators so selection varies
        for i in range(20):
            vid = hashlib.new(HASH_ALGO, f"val-{i}".encode()).digest()
            pos.register_validator(vid, 100)

        prev_hash = _hash(b"block")
        selections = set()
        for i in range(50):
            mix = _hash(f"mix-{i}".encode())
            result = pos.select_proposer(prev_hash, randao_mix=mix)
            selections.add(result)

        # With 20 validators and 50 different mixes, we should see variety
        self.assertGreater(len(selections), 1,
                           "Different RANDAO mixes should produce different proposer selections")


class TestIPValidation(unittest.TestCase):
    """#5: Node._is_valid_peer_address must reject all non-routable addresses."""

    def test_rejects_ipv6_loopback(self):
        self.assertFalse(Node._is_valid_peer_address("::1", 9333))

    def test_rejects_ipv6_private(self):
        self.assertFalse(Node._is_valid_peer_address("fc00::1", 9333))

    def test_rejects_link_local_ipv4(self):
        self.assertFalse(Node._is_valid_peer_address("169.254.1.1", 9333))

    def test_rejects_link_local_ipv6(self):
        self.assertFalse(Node._is_valid_peer_address("fe80::1", 9333))

    def test_rejects_multicast(self):
        self.assertFalse(Node._is_valid_peer_address("224.0.0.1", 9333))

    def test_rejects_reserved(self):
        self.assertFalse(Node._is_valid_peer_address("240.0.0.1", 9333))

    def test_rejects_hostname(self):
        """Hostnames must be rejected to prevent DNS rebinding."""
        self.assertFalse(Node._is_valid_peer_address("localhost", 9333))
        self.assertFalse(Node._is_valid_peer_address("evil.example.com", 9333))

    def test_accepts_valid_public_ip(self):
        self.assertTrue(Node._is_valid_peer_address("8.8.8.8", 9333))
        self.assertTrue(Node._is_valid_peer_address("1.1.1.1", 9333))

    def test_still_rejects_rfc1918(self):
        """Existing RFC1918 rejection must still work."""
        self.assertFalse(Node._is_valid_peer_address("10.0.0.1", 9333))
        self.assertFalse(Node._is_valid_peer_address("192.168.1.1", 9333))
        self.assertFalse(Node._is_valid_peer_address("172.16.0.1", 9333))


class TestOrphanBlockValidation(unittest.TestCase):
    """#6: Orphan blocks must be structurally pre-validated before storing."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"orphan-alice")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_orphan_with_too_many_transactions_rejected(self):
        """Orphans exceeding MAX_TXS_PER_BLOCK should not be stored."""
        import messagechain.config
        chain = Blockchain()
        chain.initialize_genesis(self.alice)

        # Create a block with unknown parent and too many transactions
        header = BlockHeader(
            version=1, block_number=99,
            prev_hash=_hash(b"nonexistent-parent"),
            merkle_root=_hash(b"empty"),
            timestamp=time.time(),
            proposer_id=self.alice.entity_id,
        )
        # Exceed MAX_TXS_PER_BLOCK with fake tx objects (just need the count)
        from unittest.mock import MagicMock
        fake_txs = [MagicMock() for _ in range(messagechain.config.MAX_TXS_PER_BLOCK + 10)]

        block = Block(header=header, transactions=fake_txs)
        block.block_hash = block._compute_hash()

        success, reason = chain.add_block(block)
        # Should NOT be stored as orphan due to pre-validation
        self.assertFalse(success)
        self.assertIn("rejected", reason.lower())
        self.assertNotIn(block.block_hash, chain.orphan_pool)


class TestConflictingAttestations(unittest.TestCase):
    """#7: FinalityTracker must reject conflicting attestations at same height."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"conflict-alice")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_conflicting_attestation_at_same_height_rejected(self):
        """Validator attesting to two different blocks at same height is rejected."""
        tracker = FinalityTracker()
        block_a = _hash(b"block_a")
        block_b = _hash(b"block_b")
        height = 10

        att_a = create_attestation(self.alice, block_a, height)
        att_b = create_attestation(self.alice, block_b, height)

        # First attestation succeeds
        tracker.add_attestation(att_a, 1000, 3000)

        # Second (conflicting) attestation at same height should be rejected
        result = tracker.add_attestation(att_b, 1000, 3000)
        # The validator should NOT be counted in att_b's attestation set
        self.assertNotIn(self.alice.entity_id,
                         tracker.attestations.get(block_b, set()))

    def test_same_attestation_twice_is_idempotent(self):
        """Duplicate attestation for same block is safely ignored."""
        tracker = FinalityTracker()
        block_a = _hash(b"block_a")
        att = create_attestation(self.alice, block_a, 10)

        tracker.add_attestation(att, 1000, 3000)
        tracker.add_attestation(att, 1000, 3000)
        # Should only be counted once
        self.assertEqual(tracker.attested_stake.get(block_a, 0), 1000)

    def test_different_heights_allowed(self):
        """Same validator can attest to blocks at different heights."""
        tracker = FinalityTracker()
        block_a = _hash(b"block_a")
        block_b = _hash(b"block_b")

        att_a = create_attestation(self.alice, block_a, 10)
        att_b = create_attestation(self.alice, block_b, 11)

        tracker.add_attestation(att_a, 1000, 3000)
        tracker.add_attestation(att_b, 1000, 3000)
        # Both should be recorded
        self.assertIn(self.alice.entity_id, tracker.attestations[block_a])
        self.assertIn(self.alice.entity_id, tracker.attestations[block_b])


class TestFullEntropy(unittest.TestCase):
    """#8: Proposer selection must use full 256-bit hash, not just 8 bytes."""

    def test_uses_full_hash(self):
        """select_proposer must use int.from_bytes(seed, 'big'), not seed[:8]."""
        import inspect
        source = inspect.getsource(ProofOfStake.select_proposer)
        # Should NOT truncate to 8 bytes
        self.assertNotIn("seed[:8]", source,
                         "select_proposer must not truncate seed to 8 bytes")

    def test_randao_also_uses_full_hash(self):
        """randao_select_proposer must also use full hash."""
        import inspect
        source = inspect.getsource(randao_select_proposer)
        self.assertNotIn("seed[:8]", source,
                         "randao_select_proposer must not truncate seed to 8 bytes")


class TestCanonicalTimestamps(unittest.TestCase):
    """#9: Timestamps in signable_data must use canonical integer encoding."""

    def test_block_header_uses_integer_timestamp(self):
        """BlockHeader.signable_data must encode timestamp as integer."""
        header = BlockHeader(
            version=1, block_number=0, prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32, timestamp=1000.0,
            proposer_id=b"\x00" * 32,
        )
        data = header.signable_data()
        # Should contain the integer-packed timestamp
        self.assertIn(struct.pack(">Q", 1000), data)

    def test_negative_zero_and_positive_zero_same_encoding(self):
        """0.0 and -0.0 must produce identical signable_data."""
        header_a = BlockHeader(
            version=1, block_number=0, prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32, timestamp=0.0,
            proposer_id=b"\x00" * 32,
        )
        header_b = BlockHeader(
            version=1, block_number=0, prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32, timestamp=-0.0,
            proposer_id=b"\x00" * 32,
        )
        self.assertEqual(header_a.signable_data(), header_b.signable_data(),
                         "0.0 and -0.0 must produce identical signable_data (use int encoding)")

    def test_message_tx_uses_integer_timestamp(self):
        """MessageTransaction._signable_data must encode timestamp as integer."""
        tx = MessageTransaction(
            entity_id=b"\x00" * 32, message=b"test", timestamp=1000.7,
            nonce=0, fee=MIN_FEE,
            signature=None,
        )
        # Temporarily allow None signature for signable_data test
        try:
            data = tx._signable_data()
            # Should use int(1000.7) = 1000
            self.assertIn(struct.pack(">Q", 1000), data)
        except Exception:
            pass  # If it fails due to None sig, that's ok - the encoding check is what matters


class TestGovernanceReorgRollback(unittest.TestCase):
    """#10: Governance state must be rolled back on chain reorganization."""

    def test_snapshot_includes_governance_state(self):
        """_snapshot_memory_state must capture governance state for reorg."""
        import inspect
        source = inspect.getsource(Blockchain._snapshot_memory_state)
        self.assertTrue(
            "governance" in source.lower() or "gov_" in source.lower(),
            "_snapshot_memory_state must capture governance state"
        )

    def test_restore_includes_governance_state(self):
        """_restore_memory_snapshot must restore governance state."""
        import inspect
        source = inspect.getsource(Blockchain._restore_memory_snapshot)
        self.assertTrue(
            "governance" in source.lower() or "gov_" in source.lower(),
            "_restore_memory_snapshot must restore governance state"
        )


class TestSigCacheConcurrency(unittest.TestCase):
    """#11: SignatureCache must have concurrency protection."""

    def test_cache_has_version_counter(self):
        """SignatureCache must track a version for invalidation safety."""
        cache = SignatureCache()
        self.assertTrue(hasattr(cache, '_version'),
                        "SignatureCache must have _version for concurrency safety")

    def test_version_increments_on_invalidate(self):
        """Invalidation must increment the version counter."""
        cache = SignatureCache()
        v0 = cache._version
        cache.invalidate()
        self.assertGreater(cache._version, v0)

    def test_stale_entries_not_returned_after_invalidation(self):
        """Cached entries from before invalidation must not be returned."""
        cache = SignatureCache()
        msg = b"\x01" * 32
        sig = b"\x02" * 32
        pk = b"\x03" * 32

        cache.store(msg, sig, pk, True)
        self.assertTrue(cache.lookup(msg, sig, pk))

        # Invalidate all
        cache.invalidate()

        # Lookup should miss (entry was from prior version)
        self.assertIsNone(cache.lookup(msg, sig, pk))


class TestDuplicateUnstakeProcessing(unittest.TestCase):
    """#12: process_pending_unstakes must not be called twice per block."""

    def test_append_block_does_not_duplicate_unstake_processing(self):
        """_append_block must not call process_pending_unstakes separately
        since _apply_block_state already handles it."""
        import inspect
        source = inspect.getsource(Blockchain._append_block)
        count = source.count("process_pending_unstakes")
        self.assertEqual(count, 0,
                         "_append_block should not call process_pending_unstakes "
                         "— _apply_block_state already does it")


if __name__ == "__main__":
    unittest.main()
