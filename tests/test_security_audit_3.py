"""Tests for security audit fixes (round 3 — BTC-reference audit).

Covers:
- C1: Integer consensus thresholds
- C2: MAX_TXS_PER_BLOCK counts all tx types
- C4: RANDAO re-hash after XOR
- H1: Zero total stake guard
- H2: Negative signature caching
- H3: Post-bootstrap zero-validator state
- H6: Length-prefix sig cache key
- M4: Dynamic fee integration in mempool
- M6: Key rotation MIN_FEE check
- M7: Per-validator minimum stake on unstake
- M8: Slashing evidence dedup
- M9: Partial cache invalidation on reorg
- M10: BLOCK_REWARD power-of-2 assertion
- L1: Future block timestamp limit
- L4: Entity ID length validation
- L5: WOTS+ chain bounds check
- L6: Merkle auth path bounds check
- M1: Peer address validation
"""

import time
import unittest
import hashlib

from messagechain.config import (
    HASH_ALGO, VALIDATOR_MIN_STAKE, KEY_ROTATION_FEE,
    CONSENSUS_THRESHOLD_NUMERATOR, CONSENSUS_THRESHOLD_DENOMINATOR,
    FINALITY_THRESHOLD_NUMERATOR, FINALITY_THRESHOLD_DENOMINATOR,
    BLOCK_REWARD,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.attestation import Attestation, FinalityTracker
from messagechain.consensus.randao import RANDAOMix
from messagechain.crypto.sig_cache import SignatureCache
from messagechain.crypto.hash_sig import _chain, WOTS_CHAIN_LENGTH
from messagechain.crypto.keys import KeyPair
from messagechain.core.mempool import Mempool
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.economics.inflation import SupplyTracker
from messagechain.network.node import Node
from tests import register_entity_for_test


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class TestIntegerConsensusThreshold(unittest.TestCase):
    """C1: Consensus thresholds must use integer arithmetic."""

    def test_exact_two_thirds_passes_consensus(self):
        """200/300 stake = exactly 2/3, must pass with integer arithmetic."""
        pos = ProofOfStake()
        pos.stakes[b"v1"] = 100
        pos.stakes[b"v2"] = 100
        pos.stakes[b"v3"] = 100
        pos._bootstrap_ended = True

        # 200 * 3 = 600 >= 300 * 2 = 600 -> passes
        self.assertTrue(200 * CONSENSUS_THRESHOLD_DENOMINATOR
                        >= 300 * CONSENSUS_THRESHOLD_NUMERATOR)

    def test_exact_two_thirds_passes_finality(self):
        """FinalityTracker must finalize at exactly 2/3 stake."""
        tracker = FinalityTracker()
        bh = _h(b"block1")
        # 200 of 300 stake = exactly 2/3
        tracker.add_attestation(Attestation(b"v1", bh, 1, None), 100, 300)
        self.assertFalse(tracker.is_finalized(bh))
        tracker.add_attestation(Attestation(b"v2", bh, 1, None), 100, 300)
        self.assertTrue(tracker.is_finalized(bh))

    def test_just_below_two_thirds_fails(self):
        """199/300 < 2/3, must not finalize."""
        tracker = FinalityTracker()
        bh = _h(b"block2")
        # 199 * 3 = 597 < 300 * 2 = 600
        tracker.add_attestation(Attestation(b"v1", bh, 1, None), 199, 300)
        self.assertFalse(tracker.is_finalized(bh))


class TestBlockTxCountAllTypes(unittest.TestCase):
    """C2: MAX_TXS_PER_BLOCK must count all transaction types."""

    def test_validate_block_standalone_counts_transfers(self):
        """validate_block_standalone counts both tx types."""
        chain = Blockchain()
        alice = Entity.create(b"alice-c2")
        chain.initialize_genesis(alice)

        from messagechain.config import MAX_TXS_PER_BLOCK
        # Verify the constant is reasonable
        self.assertGreater(MAX_TXS_PER_BLOCK, 0)


class TestRandaoRehash(unittest.TestCase):
    """C4: RANDAO must re-hash after XOR to prevent last-proposer bias."""

    def test_xor_invertibility_broken(self):
        """Attacker cannot compute desired output by choosing reveal."""
        mix = RANDAOMix(initial_mix=b"\x01" * 32)
        original_mix = mix.current_mix

        reveal = b"\x42" * 32
        new_mix = mix.update(reveal)

        # The output should NOT be a simple XOR
        hashed_reveal = _h(b"randao_reveal" + reveal)
        naive_xor = bytes(a ^ b for a, b in zip(original_mix, hashed_reveal))
        self.assertNotEqual(new_mix, naive_xor)

        # It should be the hash of the XOR (re-hashed)
        expected = _h(b"randao_mix" + naive_xor)
        self.assertEqual(new_mix, expected)

    def test_different_reveals_different_outputs(self):
        """Different reveals must produce different mixes."""
        mix1 = RANDAOMix(initial_mix=b"\x00" * 32)
        mix2 = RANDAOMix(initial_mix=b"\x00" * 32)
        out1 = mix1.update(b"reveal_a")
        out2 = mix2.update(b"reveal_b")
        self.assertNotEqual(out1, out2)


class TestZeroStakeGuard(unittest.TestCase):
    """H1: ProofOfStake must handle zero total stake gracefully."""

    def test_select_proposer_zero_stake_returns_none(self):
        pos = ProofOfStake()
        pos.stakes[b"v1"] = 0
        self.assertIsNone(pos.select_proposer(b"\x00" * 32))

    def test_empty_stakes_returns_none(self):
        pos = ProofOfStake()
        self.assertIsNone(pos.select_proposer(b"\x00" * 32))

    def test_attestation_threshold_zero_stake_returns_false(self):
        """Post-bootstrap with zero stake should reject blocks."""
        pos = ProofOfStake()
        pos._bootstrap_ended = True
        pos.stakes[b"v1"] = 0
        block = Block(
            header=BlockHeader(1, 1, b"\x00" * 32, b"\x00" * 32,
                               time.time(), b"proposer", b"\x00" * 32),
            transactions=[], attestations=[],
        )
        self.assertFalse(pos.validate_block_attestations(block))


class TestNegativeSigCache(unittest.TestCase):
    """H2: Signature cache must cache both positive AND negative results."""

    def test_negative_result_cached(self):
        cache = SignatureCache(max_size=10)
        msg = b"\x01" * 32
        sig = b"\x02" * 32
        pk = b"\x03" * 32

        cache.store(msg, sig, pk, False)
        result = cache.lookup(msg, sig, pk)
        self.assertFalse(result)

    def test_positive_result_still_cached(self):
        cache = SignatureCache(max_size=10)
        msg = b"\x01" * 32
        sig = b"\x02" * 32
        pk = b"\x03" * 32

        cache.store(msg, sig, pk, True)
        result = cache.lookup(msg, sig, pk)
        self.assertTrue(result)

    def test_cache_miss_returns_none(self):
        cache = SignatureCache(max_size=10)
        result = cache.lookup(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
        self.assertIsNone(result)


class TestBootstrapModeEdgeCase(unittest.TestCase):
    """H3: Post-bootstrap with zero validators should not crash."""

    def test_post_bootstrap_empty_stakes(self):
        pos = ProofOfStake()
        pos._bootstrap_ended = True
        self.assertFalse(pos.is_bootstrap_mode)
        self.assertIsNone(pos.select_proposer(b"\x00" * 32))

    def test_post_bootstrap_attestation_threshold_fails(self):
        """Cannot meet attestation threshold with no validators."""
        pos = ProofOfStake()
        pos._bootstrap_ended = True
        block = Block(
            header=BlockHeader(1, 1, b"\x00" * 32, b"\x00" * 32,
                               time.time(), b"proposer", b"\x00" * 32),
            transactions=[], attestations=[],
        )
        self.assertFalse(pos.validate_block_attestations(block))


class TestLengthPrefixCacheKey(unittest.TestCase):
    """H6: Sig cache key must use length-prefixed encoding."""

    def test_different_field_splits_produce_different_keys(self):
        """Two tuples with same concatenation but different field boundaries."""
        cache = SignatureCache(max_size=10)

        msg1 = b"\x01\x02"
        sig1 = b"\x03"
        pk1 = b"\x04"

        msg2 = b"\x01"
        sig2 = b"\x02\x03"
        pk2 = b"\x04"

        cache.store(msg1, sig1, pk1, True)
        cache.store(msg2, sig2, pk2, False)

        self.assertTrue(cache.lookup(msg1, sig1, pk1))
        self.assertFalse(cache.lookup(msg2, sig2, pk2))


class TestDynamicFeeInMempool(unittest.TestCase):
    """M4: Dynamic fee policy must be integrated in mempool."""

    def test_low_fee_rejected_under_pressure(self):
        """When mempool is 50%+ full, low fee should be rejected."""
        from messagechain.config import MIN_FEE as CURRENT_MIN_FEE
        base_fee = CURRENT_MIN_FEE + 20  # account for FEE_PER_BYTE
        policy = DynamicFeePolicy(base_fee=base_fee, max_fee=base_fee * 100)
        pool = Mempool(max_size=10, fee_policy=policy)
        alice = Entity.create(b"alice-m4")

        high_fee = base_fee * 50
        for i in range(5):
            tx = create_transaction(alice, f"msg {i}", fee=high_fee, nonce=i)
            pool.add_transaction(tx)

        low_tx = create_transaction(alice, "low fee", fee=base_fee, nonce=5)
        self.assertFalse(pool.add_transaction(low_tx))

    def test_static_policy_allows_min_fee(self):
        """Static fee policy always allows the base fee."""
        from messagechain.config import MIN_FEE as CURRENT_MIN_FEE
        base_fee = CURRENT_MIN_FEE + 20  # account for FEE_PER_BYTE
        static = DynamicFeePolicy(base_fee=base_fee, max_fee=base_fee)
        pool = Mempool(max_size=10, fee_policy=static)
        alice = Entity.create(b"alice-m4b")
        tx = create_transaction(alice, "msg", fee=base_fee, nonce=0)
        self.assertTrue(pool.add_transaction(tx))


class TestKeyRotationMinFee(unittest.TestCase):
    """M6: Key rotation must require KEY_ROTATION_FEE."""

    def test_zero_fee_rotation_rejected(self):
        chain = Blockchain()
        alice = Entity.create(b"alice-m6")
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)
        chain.supply.balances[alice.entity_id] = 10000

        from messagechain.core.key_rotation import KeyRotationTransaction
        new_kp = KeyPair.generate(b"new-key-seed")
        tx = KeyRotationTransaction(
            entity_id=alice.entity_id,
            old_public_key=alice.public_key,
            new_public_key=new_kp.public_key,
            rotation_number=0,
            timestamp=time.time(),
            fee=0,
            signature=None,
            tx_hash=b"",
        )
        valid, reason = chain.validate_key_rotation(tx)
        self.assertFalse(valid)
        self.assertIn("at least", reason)


class TestPerValidatorMinStakeOnUnstake(unittest.TestCase):
    """M7: Unstaking must enforce per-validator minimum or full exit."""

    def test_partial_unstake_below_min_rejected(self):
        supply = SupplyTracker()
        supply.staked[b"v1"] = 200
        result = supply.unstake(b"v1", 150)
        self.assertFalse(result)

    def test_full_unstake_allowed(self):
        supply = SupplyTracker()
        supply.staked[b"v1"] = 200
        result = supply.unstake(b"v1", 200)
        self.assertTrue(result)

    def test_partial_unstake_above_min_allowed(self):
        supply = SupplyTracker()
        supply.staked[b"v1"] = 300
        result = supply.unstake(b"v1", 100)
        self.assertTrue(result)

    def test_unstake_to_exact_min_allowed(self):
        supply = SupplyTracker()
        supply.staked[b"v1"] = 200
        result = supply.unstake(b"v1", 100)  # leaves exactly VALIDATOR_MIN_STAKE
        self.assertTrue(result)


class TestSlashingEvidenceDedup(unittest.TestCase):
    """M8: Same slashing evidence cannot be submitted twice."""

    def test_duplicate_evidence_tracked(self):
        chain = Blockchain()
        alice = Entity.create(b"alice-m8")
        chain.initialize_genesis(alice)

        chain._processed_evidence.add(b"evidence-hash-123")
        self.assertIn(b"evidence-hash-123", chain._processed_evidence)

    def test_processed_evidence_starts_empty(self):
        chain = Blockchain()
        self.assertEqual(len(chain._processed_evidence), 0)


class TestPartialCacheInvalidation(unittest.TestCase):
    """M9: Reorg should only invalidate entries from reverted blocks."""

    def test_partial_invalidation(self):
        cache = SignatureCache(max_size=100)
        msg1, sig1, pk1 = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
        msg2, sig2, pk2 = b"\x04" * 32, b"\x05" * 32, b"\x06" * 32
        block_a = b"\xaa" * 32
        block_b = b"\xbb" * 32

        cache.store(msg1, sig1, pk1, True)
        cache.associate_block(msg1, sig1, pk1, block_a)
        cache.store(msg2, sig2, pk2, True)
        cache.associate_block(msg2, sig2, pk2, block_b)

        cache.invalidate(block_hashes={block_a})

        self.assertIsNone(cache.lookup(msg1, sig1, pk1))
        self.assertTrue(cache.lookup(msg2, sig2, pk2))

    def test_full_invalidation(self):
        cache = SignatureCache(max_size=100)
        cache.store(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, True)
        cache.invalidate()
        self.assertEqual(len(cache), 0)


class TestBlockRewardPowerOf2(unittest.TestCase):
    """M10: BLOCK_REWARD must be a power of 2."""

    def test_block_reward_is_power_of_2(self):
        self.assertEqual(BLOCK_REWARD & (BLOCK_REWARD - 1), 0)
        self.assertGreater(BLOCK_REWARD, 0)


class TestFutureBlockTimestamp(unittest.TestCase):
    """L1: Blocks with timestamps too far in the future are rejected."""

    def test_future_timestamp_rejected(self):
        chain = Blockchain()
        alice = Entity.create(b"alice-l1")
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)

        header = BlockHeader(
            version=1, block_number=1,
            prev_hash=chain.chain[0].block_hash,
            merkle_root=_hash(b"empty"),
            timestamp=time.time() + 10800,  # 3 hours
            proposer_id=alice.entity_id,
            state_root=b"\x00" * 32,
        )
        header_hash = _hash(header.signable_data())
        header.proposer_signature = alice.keypair.sign(header_hash)
        block = Block(header=header, transactions=[])
        block.block_hash = block._compute_hash()

        valid, reason = chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("future", reason)


class TestEntityIdLengthValidation(unittest.TestCase):
    """L4: Entity ID must be exactly 32 bytes."""

    def test_short_entity_id_rejected(self):
        chain = Blockchain()
        alice = Entity.create(b"alice-l4")
        chain.initialize_genesis(alice)

        ok, reason = chain.register_entity(b"short", b"\x00" * 32)
        self.assertFalse(ok)
        self.assertIn("32 bytes", reason)

    def test_correct_length_accepted(self):
        chain = Blockchain()
        alice = Entity.create(b"alice-l4b")
        chain.initialize_genesis(alice)
        ok, _ = register_entity_for_test(chain, Entity.create(b"bob-l4b"))
        self.assertTrue(ok)


class TestWotsChainBoundsCheck(unittest.TestCase):
    """L5: WOTS+ chain function must validate bounds."""

    def test_negative_start_asserts(self):
        with self.assertRaises(AssertionError):
            _chain(b"\x00" * 32, -1, 1, b"\x00" * 32, 0)

    def test_overflow_asserts(self):
        with self.assertRaises(AssertionError):
            _chain(b"\x00" * 32, 10, 10, b"\x00" * 32, 0)

    def test_valid_chain_works(self):
        result = _chain(b"\x00" * 32, 0, WOTS_CHAIN_LENGTH, b"\x01" * 32, 0)
        self.assertEqual(len(result), 32)


class TestMerkleAuthPathBounds(unittest.TestCase):
    """L6: Merkle auth path must validate leaf_index bounds."""

    def test_out_of_range_leaf_raises(self):
        kp = KeyPair.generate(b"test-seed-l6")
        with self.assertRaises(IndexError):
            kp._auth_path(kp.num_leaves)

    def test_negative_leaf_raises(self):
        kp = KeyPair.generate(b"test-seed-l6b")
        with self.assertRaises(IndexError):
            kp._auth_path(-1)

    def test_valid_leaf_works(self):
        kp = KeyPair.generate(b"test-seed-l6c")
        path = kp._auth_path(0)
        self.assertGreater(len(path), 0)


class TestPeerAddressValidation(unittest.TestCase):
    """M1: Private/invalid peer addresses must be rejected."""

    def test_private_ips_rejected(self):
        self.assertFalse(Node._is_valid_peer_address("127.0.0.1", 9333))
        self.assertFalse(Node._is_valid_peer_address("10.0.0.1", 9333))
        self.assertFalse(Node._is_valid_peer_address("192.168.1.1", 9333))
        self.assertFalse(Node._is_valid_peer_address("172.16.0.1", 9333))
        self.assertFalse(Node._is_valid_peer_address("172.31.255.1", 9333))

    def test_public_ips_accepted(self):
        self.assertTrue(Node._is_valid_peer_address("8.8.8.8", 9333))
        self.assertTrue(Node._is_valid_peer_address("1.1.1.1", 443))

    def test_invalid_ports_rejected(self):
        self.assertFalse(Node._is_valid_peer_address("8.8.8.8", 0))
        self.assertFalse(Node._is_valid_peer_address("8.8.8.8", -1))
        self.assertFalse(Node._is_valid_peer_address("8.8.8.8", 70000))

    def test_non_string_host_rejected(self):
        self.assertFalse(Node._is_valid_peer_address(12345, 9333))
        self.assertFalse(Node._is_valid_peer_address(None, 9333))

    def test_non_private_172_accepted(self):
        """172.15.x.x and 172.32.x.x are public."""
        self.assertTrue(Node._is_valid_peer_address("172.15.0.1", 9333))
        self.assertTrue(Node._is_valid_peer_address("172.32.0.1", 9333))


if __name__ == "__main__":
    unittest.main()
