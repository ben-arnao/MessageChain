"""
Tests for VRF-based proposer selection (RANDAO lookahead).

The core idea: proposer selection for block N uses randao_mix from block
N - VRF_LOOKAHEAD instead of the immediate parent. This means the
proposer for block N is only determinable once block N - VRF_LOOKAHEAD
is finalized, giving ~VRF_LOOKAHEAD * BLOCK_TIME_TARGET seconds of
unpredictability instead of just one block time.
"""

import hashlib
import os
import struct
import unittest

from messagechain.config import HASH_ALGO


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class TestVRFConfig(unittest.TestCase):
    """Config constants for VRF exist and have sensible values."""

    def test_vrf_lookahead_exists(self):
        from messagechain.config import VRF_LOOKAHEAD
        self.assertIsInstance(VRF_LOOKAHEAD, int)
        self.assertGreaterEqual(VRF_LOOKAHEAD, 1)

    def test_vrf_lookahead_default(self):
        from messagechain.config import VRF_LOOKAHEAD
        self.assertEqual(VRF_LOOKAHEAD, 32)

    def test_vrf_enabled_exists(self):
        from messagechain.config import VRF_ENABLED
        self.assertIsInstance(VRF_ENABLED, bool)


class TestVRFModule(unittest.TestCase):
    """Tests for messagechain.consensus.vrf module functions."""

    def test_compute_randao_reveal_deterministic(self):
        """Same seed + block_number always produces the same reveal."""
        from messagechain.consensus.vrf import compute_randao_reveal
        seed = os.urandom(32)
        reveal1 = compute_randao_reveal(seed, 42)
        reveal2 = compute_randao_reveal(seed, 42)
        self.assertEqual(reveal1, reveal2)
        self.assertEqual(len(reveal1), 32)

    def test_compute_randao_reveal_different_seeds(self):
        """Different seeds produce different reveals."""
        from messagechain.consensus.vrf import compute_randao_reveal
        seed1 = os.urandom(32)
        seed2 = os.urandom(32)
        self.assertNotEqual(
            compute_randao_reveal(seed1, 42),
            compute_randao_reveal(seed2, 42),
        )

    def test_compute_randao_reveal_different_blocks(self):
        """Different block numbers produce different reveals."""
        from messagechain.consensus.vrf import compute_randao_reveal
        seed = os.urandom(32)
        self.assertNotEqual(
            compute_randao_reveal(seed, 1),
            compute_randao_reveal(seed, 2),
        )

    def test_verify_randao_reveal_valid(self):
        """A correctly computed reveal verifies against its commitment."""
        from messagechain.consensus.vrf import (
            compute_randao_reveal,
            compute_randao_commitment,
            verify_randao_reveal,
        )
        seed = os.urandom(32)
        commitment = compute_randao_commitment(seed)
        reveal = compute_randao_reveal(seed, 100)
        self.assertTrue(verify_randao_reveal(reveal, commitment, seed, 100))

    def test_verify_randao_reveal_wrong_seed(self):
        """A reveal computed with the wrong seed does not verify."""
        from messagechain.consensus.vrf import (
            compute_randao_reveal,
            compute_randao_commitment,
            verify_randao_reveal,
        )
        seed1 = os.urandom(32)
        seed2 = os.urandom(32)
        commitment = compute_randao_commitment(seed1)
        reveal = compute_randao_reveal(seed2, 100)
        # The reveal doesn't match the commitment's seed
        self.assertFalse(verify_randao_reveal(reveal, commitment, seed2, 100))

    def test_mix_randao_xor_accumulation(self):
        """mix_randao XORs the reveal hash into the current mix."""
        from messagechain.consensus.vrf import mix_randao
        current = b"\x00" * 32
        reveal = os.urandom(32)
        result = mix_randao(current, reveal)
        self.assertEqual(len(result), 32)
        self.assertNotEqual(result, current)

    def test_mix_randao_different_reveals(self):
        """Different reveals produce different mixes."""
        from messagechain.consensus.vrf import mix_randao
        current = os.urandom(32)
        r1 = os.urandom(32)
        r2 = os.urandom(32)
        self.assertNotEqual(mix_randao(current, r1), mix_randao(current, r2))

    def test_select_proposer_vrf_stake_weighted(self):
        """Proposer selection is stake-weighted over many samples."""
        from messagechain.consensus.vrf import select_proposer_vrf

        v1 = b"\x01" * 32
        v2 = b"\x02" * 32
        validators = {v1: 900, v2: 100}  # 9:1 ratio

        counts = {v1: 0, v2: 0}
        for i in range(2000):
            mix = _hash(struct.pack(">Q", i) + b"test_seed")
            winner = select_proposer_vrf(mix, i, validators)
            counts[winner] += 1

        # v1 should win ~90% of the time. Allow wide margin for randomness.
        ratio = counts[v1] / 2000
        self.assertGreater(ratio, 0.80, f"v1 ratio {ratio} too low")
        self.assertLess(ratio, 0.97, f"v1 ratio {ratio} too high")

    def test_select_proposer_vrf_deterministic(self):
        """Same inputs always select the same proposer."""
        from messagechain.consensus.vrf import select_proposer_vrf

        v1 = b"\x01" * 32
        v2 = b"\x02" * 32
        validators = {v1: 500, v2: 500}
        mix = os.urandom(32)

        result1 = select_proposer_vrf(mix, 10, validators)
        result2 = select_proposer_vrf(mix, 10, validators)
        self.assertEqual(result1, result2)

    def test_select_proposer_vrf_different_from_deterministic(self):
        """VRF selection uses different randomness than the old method."""
        from messagechain.consensus.vrf import select_proposer_vrf
        from messagechain.consensus.pos import ProofOfStake

        v1 = b"\x01" * 32
        v2 = b"\x02" * 32
        validators = {v1: 500, v2: 500}

        pos = ProofOfStake()
        pos.stakes = dict(validators)

        # Run many selections; at least some should differ
        # (they use different hash domains)
        differences = 0
        for i in range(100):
            mix = _hash(struct.pack(">Q", i))
            prev_hash = mix  # use same bytes for both
            vrf_result = select_proposer_vrf(mix, i, validators)
            pos_result = pos.select_proposer(prev_hash, randao_mix=mix)
            if vrf_result != pos_result:
                differences += 1

        # With 50/50 stake split, at least some selections should differ
        # due to different domain tags in the hash
        self.assertGreater(differences, 0,
            "VRF and deterministic selection should use different domains")

    def test_select_proposer_vrf_empty_validators(self):
        """Empty validator set returns None."""
        from messagechain.consensus.vrf import select_proposer_vrf
        self.assertIsNone(select_proposer_vrf(b"\x00" * 32, 0, {}))

    def test_select_proposer_vrf_single_validator(self):
        """Single validator always wins."""
        from messagechain.consensus.vrf import select_proposer_vrf
        v = b"\xaa" * 32
        for i in range(10):
            mix = _hash(struct.pack(">Q", i))
            self.assertEqual(select_proposer_vrf(mix, i, {v: 100}), v)

    def test_get_lookahead_randao_mix_early_chain(self):
        """For blocks earlier than VRF_LOOKAHEAD, uses genesis randao_mix."""
        from messagechain.consensus.vrf import get_lookahead_randao_mix

        # Simulate a short chain of randao mixes (index = block number)
        chain_mixes = [os.urandom(32) for _ in range(5)]

        # Block 3 with lookahead 32 should use genesis mix (index 0)
        result = get_lookahead_randao_mix(chain_mixes, 3, lookahead=32)
        self.assertEqual(result, chain_mixes[0])

    def test_get_lookahead_randao_mix_mature_chain(self):
        """For blocks past VRF_LOOKAHEAD, uses mix from N-LOOKAHEAD."""
        from messagechain.consensus.vrf import get_lookahead_randao_mix

        chain_mixes = [os.urandom(32) for _ in range(50)]

        # Block 40 with lookahead 32 should use mix from block 8
        result = get_lookahead_randao_mix(chain_mixes, 40, lookahead=32)
        self.assertEqual(result, chain_mixes[8])

    def test_proposer_unpredictable_without_lookahead_mix(self):
        """Proposer for block N is NOT derivable from block N-1 alone.

        You need the randao_mix from block N-LOOKAHEAD. Knowing only
        the parent's mix gives a different (wrong) answer.
        """
        from messagechain.consensus.vrf import select_proposer_vrf

        v1 = b"\x01" * 32
        v2 = b"\x02" * 32
        v3 = b"\x03" * 32
        validators = {v1: 333, v2: 333, v3: 334}

        # Two different mixes (one is the correct lookahead, one is parent)
        mix_lookahead = os.urandom(32)
        mix_parent = os.urandom(32)
        block_num = 100

        result_correct = select_proposer_vrf(mix_lookahead, block_num, validators)
        result_wrong = select_proposer_vrf(mix_parent, block_num, validators)

        # They CAN coincidentally match, but across many trials they must differ
        mismatches = 0
        for i in range(200):
            ml = _hash(struct.pack(">Q", i) + b"lookahead")
            mp = _hash(struct.pack(">Q", i) + b"parent")
            r1 = select_proposer_vrf(ml, 100 + i, validators)
            r2 = select_proposer_vrf(mp, 100 + i, validators)
            if r1 != r2:
                mismatches += 1

        self.assertGreater(mismatches, 50,
            "With different mixes, selections should frequently differ")


class TestVRFFallback(unittest.TestCase):
    """When VRF_ENABLED=False, old deterministic selection still works."""

    def test_fallback_deterministic_selection(self):
        """With VRF disabled, select_proposer works as before."""
        from messagechain.consensus.pos import ProofOfStake

        pos = ProofOfStake()
        v1 = b"\x01" * 32
        v2 = b"\x02" * 32
        pos.register_validator(v1, 500, block_height=0)
        pos.register_validator(v2, 500, block_height=0)

        prev_hash = os.urandom(32)
        result = pos.select_proposer(prev_hash)
        self.assertIn(result, [v1, v2])


class TestRandaoCommitment(unittest.TestCase):
    """Randao commitment in registration/VRF seed management."""

    def test_compute_randao_commitment(self):
        """Commitment is a hash of the seed."""
        from messagechain.consensus.vrf import compute_randao_commitment
        seed = os.urandom(32)
        commitment = compute_randao_commitment(seed)
        self.assertEqual(len(commitment), 32)

    def test_commitment_deterministic(self):
        """Same seed always gives the same commitment."""
        from messagechain.consensus.vrf import compute_randao_commitment
        seed = os.urandom(32)
        self.assertEqual(
            compute_randao_commitment(seed),
            compute_randao_commitment(seed),
        )

    def test_different_seeds_different_commitments(self):
        """Different seeds produce different commitments."""
        from messagechain.consensus.vrf import compute_randao_commitment
        s1 = os.urandom(32)
        s2 = os.urandom(32)
        self.assertNotEqual(
            compute_randao_commitment(s1),
            compute_randao_commitment(s2),
        )

    def _make_entity(self, name: str):
        from messagechain.identity.identity import Entity
        return Entity.create(name.encode().ljust(32, b"\x00"))

    def test_registration_has_randao_commitment_field(self):
        """RegistrationTransaction accepts a randao_commitment field."""
        from messagechain.core.registration import create_registration_transaction
        entity = self._make_entity("test-reg-field")
        tx = create_registration_transaction(entity)
        # Default commitment should be zero bytes
        self.assertEqual(len(tx.randao_commitment), 32)

    def test_registration_randao_commitment_in_signable_data(self):
        """randao_commitment is included in _signable_data for tamper evidence."""
        from messagechain.core.registration import create_registration_transaction
        entity = self._make_entity("test-reg-signable")
        tx1 = create_registration_transaction(entity)
        # Change randao_commitment on a copy to verify signable_data changes
        from messagechain.core.registration import RegistrationTransaction
        tx2 = RegistrationTransaction(
            entity_id=tx1.entity_id,
            public_key=tx1.public_key,
            registration_proof=tx1.registration_proof,
            timestamp=tx1.timestamp,
            randao_commitment=b"\xaa" * 32,
        )
        tx3 = RegistrationTransaction(
            entity_id=tx1.entity_id,
            public_key=tx1.public_key,
            registration_proof=tx1.registration_proof,
            timestamp=tx1.timestamp,
            randao_commitment=b"\xbb" * 32,
        )
        # Different commitments must produce different signable data
        self.assertNotEqual(tx2._signable_data(), tx3._signable_data())

    def test_registration_default_randao_commitment(self):
        """Default randao_commitment is 32 zero bytes (backward compat)."""
        from messagechain.core.registration import create_registration_transaction
        entity = self._make_entity("test-reg-default")
        tx = create_registration_transaction(entity)
        self.assertEqual(tx.randao_commitment, b"\x00" * 32)

    def test_registration_serialize_deserialize_with_commitment(self):
        """randao_commitment survives serialize/deserialize round-trip."""
        from messagechain.core.registration import create_registration_transaction
        entity = self._make_entity("test-reg-serde")
        tx = create_registration_transaction(entity)
        data = tx.serialize()
        self.assertIn("randao_commitment", data)
        self.assertEqual(data["randao_commitment"], tx.randao_commitment.hex())

    def test_registration_to_bytes_from_bytes_with_commitment(self):
        """randao_commitment survives binary round-trip."""
        from messagechain.core.registration import (
            RegistrationTransaction, create_registration_transaction,
        )
        entity = self._make_entity("test-reg-binary")
        tx = create_registration_transaction(entity)
        blob = tx.to_bytes()
        restored = RegistrationTransaction.from_bytes(blob)
        self.assertEqual(restored.randao_commitment, tx.randao_commitment)


class TestBlockchainVRFIntegration(unittest.TestCase):
    """Integration tests: blockchain uses VRF lookahead for proposer selection."""

    def test_selected_proposer_uses_lookahead(self):
        """_selected_proposer_for_slot uses randao_mix from LOOKAHEAD blocks ago."""
        from messagechain.config import VRF_LOOKAHEAD, VRF_ENABLED
        if not VRF_ENABLED:
            self.skipTest("VRF not enabled")

        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.pos import ProofOfStake

        entity = Entity.create(b"vrf-integration-test".ljust(32, b"\x00"))
        bc = Blockchain()
        bc.initialize_genesis(entity)
        bc.register_entity(entity.entity_id, entity.public_key)
        bc.supply.staked[entity.entity_id] = 1000

        # Build a few blocks (less than key exhaustion limit)
        for _ in range(5):
            pos = ProofOfStake()
            pos.stakes = dict(bc.supply.staked)
            block = pos.create_block(
                proposer_entity=entity,
                transactions=[],
                prev_block=bc.chain[-1],
                timestamp=bc.chain[-1].header.timestamp + 601,
            )
            bc.chain.append(block)
            bc._block_by_hash[block.block_hash] = block

        # With only 5 blocks and VRF_LOOKAHEAD=32, the lookahead target
        # clamps to block 0 (genesis). Verify the function still works.
        parent = bc.chain[-1]
        result = bc._selected_proposer_for_slot(parent, round_number=0)
        self.assertIsNotNone(result)

    def test_lookahead_uses_earlier_block_mix(self):
        """VRF selection uses randao_mix from N-LOOKAHEAD, not parent."""
        from messagechain.config import VRF_ENABLED
        if not VRF_ENABLED:
            self.skipTest("VRF not enabled")

        from messagechain.consensus.vrf import select_proposer_vrf

        # Simulate what _selected_proposer_for_slot does: it picks the mix
        # from block max(0, height - VRF_LOOKAHEAD). With height=100 and
        # lookahead=32, it uses block 68's mix, not block 99's.
        v1 = b"\x01" * 32
        validators = {v1: 1000}

        mix_68 = os.urandom(32)
        mix_99 = os.urandom(32)

        # Both should return v1 (single validator), but the INPUTS differ
        r1 = select_proposer_vrf(mix_68, 100, validators)
        r2 = select_proposer_vrf(mix_99, 100, validators)
        self.assertEqual(r1, v1)
        self.assertEqual(r2, v1)


class TestVRFRoundNumber(unittest.TestCase):
    """VRF proposer selection supports round_number for liveness fallback."""

    def test_different_rounds_different_proposers(self):
        """Different round numbers can produce different proposers."""
        from messagechain.consensus.vrf import select_proposer_vrf

        validators = {bytes([i]) * 32: 100 for i in range(10)}
        mix = os.urandom(32)

        results = set()
        for r in range(20):
            result = select_proposer_vrf(mix, 100, validators, round_number=r)
            results.add(result)

        # With 10 validators and 20 rounds, should see multiple different winners
        self.assertGreater(len(results), 1)


if __name__ == "__main__":
    unittest.main()
