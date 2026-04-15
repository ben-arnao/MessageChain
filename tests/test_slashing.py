"""Tests for the slashing mechanism."""

import unittest
import time
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, _hash, compute_merkle_root, compute_state_root
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.slashing import (
    SlashingEvidence,
    SlashTransaction,
    create_slash_transaction,
    verify_slashing_evidence,
)
from messagechain.config import SLASH_FINDER_REWARD_PCT
from tests import register_entity_for_test, pick_selected_proposer


def _make_conflicting_headers(proposer_entity, prev_block):
    """Helper: create two different block headers at the same height, both signed."""
    block_num = prev_block.header.block_number + 1

    header_a = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"empty"),
        timestamp=time.time(),
        proposer_id=proposer_entity.entity_id,
    )
    hash_a = _hash(header_a.signable_data())
    header_a.proposer_signature = proposer_entity.keypair.sign(hash_a)

    header_b = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"different_content"),
        timestamp=time.time() + 1,  # different timestamp -> different signable data
        proposer_id=proposer_entity.entity_id,
    )
    hash_b = _hash(header_b.signable_data())
    header_b.proposer_signature = proposer_entity.keypair.sign(hash_b)

    return header_a, header_b


class TestSlashingEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000

    def test_valid_double_sign_detected(self):
        """Two different blocks at same height by same proposer = valid evidence."""
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )

        valid, reason = verify_slashing_evidence(evidence, self.alice.public_key)
        self.assertTrue(valid, reason)

    def test_different_heights_rejected(self):
        """Headers at different heights are not double-signing."""
        prev = self.chain.get_latest_block()
        header_a = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"empty"),
            timestamp=time.time(), proposer_id=self.alice.entity_id,
        )
        hash_a = _hash(header_a.signable_data())
        header_a.proposer_signature = self.alice.keypair.sign(hash_a)

        header_b = BlockHeader(
            version=1, block_number=2,  # different height
            prev_hash=prev.block_hash, merkle_root=_hash(b"empty"),
            timestamp=time.time(), proposer_id=self.alice.entity_id,
        )
        hash_b = _hash(header_b.signable_data())
        header_b.proposer_signature = self.alice.keypair.sign(hash_b)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        valid, reason = verify_slashing_evidence(evidence, self.alice.public_key)
        self.assertFalse(valid)
        self.assertIn("different heights", reason)

    def test_different_proposers_rejected(self):
        """Headers from different proposers are not evidence against one validator."""
        prev = self.chain.get_latest_block()
        header_a = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"a"),
            timestamp=time.time(), proposer_id=self.alice.entity_id,
        )
        hash_a = _hash(header_a.signable_data())
        header_a.proposer_signature = self.alice.keypair.sign(hash_a)

        header_b = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"b"),
            timestamp=time.time(), proposer_id=self.bob.entity_id,  # different proposer
        )
        hash_b = _hash(header_b.signable_data())
        header_b.proposer_signature = self.bob.keypair.sign(hash_b)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        valid, reason = verify_slashing_evidence(evidence, self.alice.public_key)
        self.assertFalse(valid)
        self.assertIn("proposer", reason)

    def test_identical_headers_rejected(self):
        """Two identical headers are not conflicting."""
        prev = self.chain.get_latest_block()
        header = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"empty"),
            timestamp=1000.0, proposer_id=self.alice.entity_id,
        )
        hash_val = _hash(header.signable_data())
        header.proposer_signature = self.alice.keypair.sign(hash_val)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header,
            header_b=header,  # same header
        )
        valid, reason = verify_slashing_evidence(evidence, self.alice.public_key)
        self.assertFalse(valid)
        self.assertIn("identical", reason)

    def test_missing_signature_rejected(self):
        """Headers without signatures cannot be valid evidence."""
        prev = self.chain.get_latest_block()
        header_a = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"a"),
            timestamp=time.time(), proposer_id=self.alice.entity_id,
        )
        # No signature set
        header_b = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"b"),
            timestamp=time.time(), proposer_id=self.alice.entity_id,
        )

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        valid, reason = verify_slashing_evidence(evidence, self.alice.public_key)
        self.assertFalse(valid)
        self.assertIn("no signature", reason)

    def test_evidence_serialization_roundtrip(self):
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        data = evidence.serialize()
        restored = SlashingEvidence.deserialize(data)
        self.assertEqual(restored.offender_id, evidence.offender_id)
        self.assertEqual(restored.evidence_hash, evidence.evidence_hash)


class TestSlashTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.carol)
        register_entity_for_test(self.chain, self.alice)
        register_entity_for_test(self.chain, self.bob)
        # Fund entities
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.chain.supply.balances[self.carol.entity_id] = 10000
        # Alice stakes as a validator
        self.chain.supply.stake(self.alice.entity_id, 1000)

    def test_slash_removes_stake(self):
        """Slashing burns the offender's entire stake."""
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )

        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        proposer_id = self.carol.entity_id

        success, msg = self.chain.apply_slash_transaction(slash_tx, proposer_id)
        self.assertTrue(success, msg)
        self.assertEqual(self.chain.supply.get_staked(self.alice.entity_id), 0)

    def test_finder_reward_paid(self):
        """Submitter receives finder's reward (10% of slashed stake)."""
        bob_balance_before = self.chain.supply.get_balance(self.bob.entity_id)
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        self.chain.apply_slash_transaction(slash_tx, self.carol.entity_id)

        bob_balance_after = self.chain.supply.get_balance(self.bob.entity_id)
        expected_reward = 1000 * SLASH_FINDER_REWARD_PCT // 100  # 100
        # Bob gains reward but pays fee
        self.assertEqual(bob_balance_after, bob_balance_before + expected_reward - 1500)

    def test_burned_tokens_reduce_supply(self):
        """90% of slashed stake is burned, reducing total supply."""
        supply_before = self.chain.supply.total_supply
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        self.chain.apply_slash_transaction(slash_tx, self.carol.entity_id)

        burned_stake = 1000 - (1000 * SLASH_FINDER_REWARD_PCT // 100)  # 900
        # Slash fee also burns base_fee via EIP-1559
        base_fee = self.chain.supply.base_fee
        self.assertEqual(
            self.chain.supply.total_supply,
            supply_before - burned_stake - base_fee,
        )

    def test_duplicate_slash_rejected(self):
        """Same validator cannot be slashed twice."""
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        self.chain.apply_slash_transaction(slash_tx, self.carol.entity_id)

        # Second attempt with new evidence (different headers but same offender)
        header_c, header_d = _make_conflicting_headers(self.alice, prev)
        evidence2 = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_c,
            header_b=header_d,
        )
        slash_tx2 = create_slash_transaction(self.bob, evidence2, fee=1500)
        success, msg = self.chain.apply_slash_transaction(slash_tx2, self.carol.entity_id)
        self.assertFalse(success)
        self.assertIn("already slashed", msg)

    def test_no_stake_rejected(self):
        """Cannot slash a validator with no stake."""
        prev = self.chain.get_latest_block()
        # Bob has no stake
        header_a = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"a"),
            timestamp=time.time(), proposer_id=self.bob.entity_id,
        )
        hash_a = _hash(header_a.signable_data())
        header_a.proposer_signature = self.bob.keypair.sign(hash_a)

        header_b = BlockHeader(
            version=1, block_number=1,
            prev_hash=prev.block_hash, merkle_root=_hash(b"b"),
            timestamp=time.time() + 1, proposer_id=self.bob.entity_id,
        )
        hash_b = _hash(header_b.signable_data())
        header_b.proposer_signature = self.bob.keypair.sign(hash_b)

        evidence = SlashingEvidence(
            offender_id=self.bob.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.carol, evidence, fee=1500)
        success, msg = self.chain.apply_slash_transaction(slash_tx, self.carol.entity_id)
        self.assertFalse(success)
        self.assertIn("no stake", msg)

    def test_slash_in_block(self):
        """Slash transactions included in blocks are applied correctly."""
        # Stake carol too so strict proposer validation has a choice.
        # With two staked validators, we use the deterministically-selected
        # one as proposer, not the offender (alice).
        self.chain.supply.stake(self.carol.entity_id, 1000)

        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)

        # Create a block that includes the slash transaction.
        # Must compute the correct state_root that accounts for slash effects.
        consensus = ProofOfStake()
        prev = self.chain.get_latest_block()
        block_height = prev.header.block_number + 1

        # Pick the deterministically-selected proposer
        proposer_entity = pick_selected_proposer(self.chain, [self.alice, self.bob, self.carol])
        proposer_id = proposer_entity.entity_id

        # Simulate state after slash tx + block reward (with EIP-1559 burn)
        sim_balances = dict(self.chain.supply.balances)
        sim_nonces = dict(self.chain.nonces)
        sim_staked = dict(self.chain.supply.staked)
        current_base_fee = self.chain.supply.base_fee
        # Slash tx fee: bob pays fee, base_fee is burned, tip to proposer
        tip = slash_tx.fee - current_base_fee
        sim_balances[slash_tx.submitter_id] -= slash_tx.fee
        sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + tip
        # Slash: alice stake (1000) -> 0, finder reward to bob
        slashed_amount = sim_staked.get(self.alice.entity_id, 0)
        finder_reward = slashed_amount * SLASH_FINDER_REWARD_PCT // 100
        sim_staked[self.alice.entity_id] = 0
        sim_balances[slash_tx.submitter_id] = sim_balances.get(slash_tx.submitter_id, 0) + finder_reward
        # Block reward to proposer (no attestors)
        from messagechain.config import PROPOSER_REWARD_CAP, TREASURY_ENTITY_ID
        reward = self.chain.supply.calculate_block_reward(block_height)
        is_bootstrap = not any(s > 0 for s in sim_staked.values())
        effective_cap = reward if is_bootstrap else PROPOSER_REWARD_CAP
        proposer_reward = min(reward, effective_cap)
        treasury_excess = reward - proposer_reward
        sim_balances[proposer_id] = sim_balances.get(proposer_id, 0) + proposer_reward
        if treasury_excess > 0:
            sim_balances[TREASURY_ENTITY_ID] = sim_balances.get(TREASURY_ENTITY_ID, 0) + treasury_excess
        # State root now commits to authority fields too; pass them
        # through from the live chain (slashing doesn't mutate keys or
        # revoke state).  Leaf watermarks advance on EVERY signature the
        # block carries: slash-tx submitter sig, proposer block sig, and
        # any attestation sigs.  Pre-bump sim watermarks for each so the
        # sim matches what _apply_block_state will do.
        sim_wm = dict(self.chain.leaf_watermarks)

        def _bump(eid, leaf_index):
            nxt = leaf_index + 1
            if nxt > sim_wm.get(eid, 0):
                sim_wm[eid] = nxt

        _bump(slash_tx.submitter_id, slash_tx.signature.leaf_index)
        # Proposer's block signature will consume their keypair's next
        # leaf — peek before the block is signed.
        _bump(proposer_id, proposer_entity.keypair._next_leaf)
        state_root = compute_state_root(
            sim_balances, sim_nonces, sim_staked,
            authority_keys=self.chain.authority_keys,
            public_keys=self.chain.public_keys,
            leaf_watermarks=sim_wm,
            key_rotation_counts=self.chain.key_rotation_counts,
            revoked_entities=self.chain.revoked_entities,
        )

        # Slash txs are now committed in the merkle_root, so they must be
        # passed at construction time — post-hoc attachment would break
        # the merkle_root / proposer_signature invariant.
        block = consensus.create_block(
            proposer_entity, [], prev, state_root=state_root,
            slash_transactions=[slash_tx],
        )

        success, msg = self.chain.add_block(block)
        self.assertTrue(success, msg)
        self.assertEqual(self.chain.supply.get_staked(self.alice.entity_id), 0)
        self.assertIn(self.alice.entity_id, self.chain.slashed_validators)

    def test_slash_tx_serialization_roundtrip(self):
        """Slash transaction survives serialization/deserialization."""
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)

        data = slash_tx.serialize()
        restored = SlashTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, slash_tx.tx_hash)
        self.assertEqual(restored.submitter_id, slash_tx.submitter_id)
        self.assertEqual(restored.evidence.offender_id, self.alice.entity_id)

    def test_block_with_slash_serialization(self):
        """Block containing slash transactions serializes correctly."""
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)

        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)

        consensus = ProofOfStake()
        block = consensus.create_block(self.carol, [], prev)
        block.slash_transactions = [slash_tx]

        data = block.serialize()
        restored = Block.deserialize(data)
        self.assertEqual(len(restored.slash_transactions), 1)
        self.assertEqual(
            restored.slash_transactions[0].evidence.offender_id,
            self.alice.entity_id,
        )


if __name__ == "__main__":
    unittest.main()
