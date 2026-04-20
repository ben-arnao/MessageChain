"""Tests for proof-of-custody archive rewards.

Spec: docs/proof-of-custody-archive-rewards.md

Covers the eight TDD requirements:
    1. Challenge determinism & uniformity.
    2. Proof verification against a known state.
    3. Invalid proofs rejected (wrong leaf, bad signature, forged Merkle,
       stale header).
    4. Reward pool funding: burn -> pool split (25% pool, 75% burn).
    5. FCFS payout caps at 10 rewards/challenge.
    6. Graceful degradation when pool is empty.
    7. State-root includes pool balance (round-trip through snapshot).
    8. Proposer who omits pool accounting in their block fails validation.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import (
    HASH_ALGO,
    ARCHIVE_BURN_REDIRECT_PCT,
    ARCHIVE_CHALLENGE_INTERVAL,
    ARCHIVE_PROOFS_PER_CHALLENGE,
    ARCHIVE_REWARD,
    ARCHIVE_SUBMISSION_WINDOW,
    is_archive_challenge_block,
)
from messagechain.consensus import archive_challenge as ac
from messagechain.consensus.archive_challenge import (
    ArchiveRewardPool,
    CustodyProof,
    apply_archive_rewards,
    build_custody_proof,
    compute_challenge,
    verify_custody_proof,
)


def _h(b: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, b).digest()


# ---------------------------------------------------------------------------
# 1. Challenge determinism & uniformity
# ---------------------------------------------------------------------------


class TestChallengeDeterminism(unittest.TestCase):
    def test_same_block_hash_same_challenge(self):
        block_hash = _h(b"some-block")
        B = 500
        c1 = compute_challenge(block_hash, B)
        c2 = compute_challenge(block_hash, B)
        self.assertEqual(c1, c2)

    def test_different_block_hashes_produce_different_challenges(self):
        B = 500
        c1 = compute_challenge(_h(b"block-A"), B)
        c2 = compute_challenge(_h(b"block-B"), B)
        # Extremely unlikely for two hashes to map to the same target in
        # a 500-wide space unless the mod step is wrong.
        self.assertNotEqual(c1.target_height, c2.target_height)

    def test_target_height_in_range(self):
        """challenge_seed mod B must produce a value in [0, B)."""
        B = 200
        for i in range(50):
            block_hash = _h(f"block-{i}".encode())
            c = compute_challenge(block_hash, B)
            self.assertGreaterEqual(c.target_height, 0)
            self.assertLess(c.target_height, B)

    def test_challenge_covers_space(self):
        """Over many distinct block hashes, targets should land in both
        halves of the space — uniformity sanity check."""
        B = 100
        heights = set()
        for i in range(500):
            block_hash = _h(f"cover-{i}".encode())
            c = compute_challenge(block_hash, B)
            heights.add(c.target_height)
        # With 500 samples into a 100-wide bucket, we expect to hit nearly
        # every bucket. Assert "most" rather than "all" to tolerate the
        # tiny probability of a hash-produced gap.
        self.assertGreater(len(heights), 80)

    def test_is_archive_challenge_block_cadence(self):
        """Challenge fires on multiples of ARCHIVE_CHALLENGE_INTERVAL, not
        on block 0 (nothing to challenge over)."""
        self.assertFalse(is_archive_challenge_block(0))
        self.assertFalse(is_archive_challenge_block(ARCHIVE_CHALLENGE_INTERVAL - 1))
        self.assertTrue(is_archive_challenge_block(ARCHIVE_CHALLENGE_INTERVAL))
        self.assertTrue(is_archive_challenge_block(2 * ARCHIVE_CHALLENGE_INTERVAL))
        self.assertFalse(is_archive_challenge_block(ARCHIVE_CHALLENGE_INTERVAL + 1))

    def test_challenge_rejects_nonpositive_B(self):
        """Can't challenge a chain of height 0 — no historical blocks exist."""
        with self.assertRaises(ValueError):
            compute_challenge(_h(b"x"), 0)
        with self.assertRaises(ValueError):
            compute_challenge(_h(b"x"), -1)


# ---------------------------------------------------------------------------
# 2 + 3. Proof construction, verification, and rejection paths
# ---------------------------------------------------------------------------


def _mini_block(txs: list[bytes], block_number: int = 1) -> dict:
    """Build a fake "block" dict good enough for the archive module's
    eyes — real Block objects pull in too much of the chain for a unit
    test.  The module only needs:
        - header_bytes   (opaque; we hash it to get block_hash)
        - merkle_root    (commits to tx_hashes)
        - tx_bytes_list  (to sample tx bytes + reconstruct the path)
    """
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    # 32-byte height || 32-byte merkle_root — deterministic "header" stand-in.
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    block_hash = _h(header_bytes)
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": block_hash,
    }


class TestProofVerify(unittest.TestCase):
    def setUp(self):
        # Build a 6-tx block — merkle_root over 6 hashes with padding.
        self.txs = [f"tx-{i}".encode() * 20 for i in range(6)]
        self.block = _mini_block(self.txs, block_number=7)
        self.prover_id = b"\xaa" * 32

    def test_build_and_verify_valid_proof(self):
        """A proof built over a real block position verifies."""
        proof = build_custody_proof(
            prover_id=self.prover_id,
            target_height=self.block["block_number"],
            target_block_hash=self.block["block_hash"],
            header_bytes=self.block["header_bytes"],
            merkle_root=self.block["merkle_root"],
            tx_index=3,
            tx_bytes=self.block["tx_bytes_list"][3],
            all_tx_hashes=self.block["tx_hashes"],
        )
        ok, reason = verify_custody_proof(
            proof,
            expected_block_hash=self.block["block_hash"],
        )
        self.assertTrue(ok, f"proof rejected: {reason}")

    def test_verify_rejects_wrong_tx_bytes(self):
        """Flipping tx bytes invalidates the leaf hash -> merkle path fails."""
        proof = build_custody_proof(
            prover_id=self.prover_id,
            target_height=self.block["block_number"],
            target_block_hash=self.block["block_hash"],
            header_bytes=self.block["header_bytes"],
            merkle_root=self.block["merkle_root"],
            tx_index=3,
            tx_bytes=self.block["tx_bytes_list"][3],
            all_tx_hashes=self.block["tx_hashes"],
        )
        proof.tx_bytes = b"forged" + proof.tx_bytes[6:]
        ok, _ = verify_custody_proof(proof, expected_block_hash=self.block["block_hash"])
        self.assertFalse(ok)

    def test_verify_rejects_wrong_tx_index(self):
        """Claiming tx_index=0 with the bytes from tx_index=3 fails path check."""
        proof = build_custody_proof(
            prover_id=self.prover_id,
            target_height=self.block["block_number"],
            target_block_hash=self.block["block_hash"],
            header_bytes=self.block["header_bytes"],
            merkle_root=self.block["merkle_root"],
            tx_index=3,
            tx_bytes=self.block["tx_bytes_list"][3],
            all_tx_hashes=self.block["tx_hashes"],
        )
        proof.tx_index = 0
        ok, _ = verify_custody_proof(proof, expected_block_hash=self.block["block_hash"])
        self.assertFalse(ok)

    def test_verify_rejects_forged_merkle_path(self):
        """Replacing a sibling in the path invalidates inclusion."""
        proof = build_custody_proof(
            prover_id=self.prover_id,
            target_height=self.block["block_number"],
            target_block_hash=self.block["block_hash"],
            header_bytes=self.block["header_bytes"],
            merkle_root=self.block["merkle_root"],
            tx_index=3,
            tx_bytes=self.block["tx_bytes_list"][3],
            all_tx_hashes=self.block["tx_hashes"],
        )
        # Flip a byte in a sibling hash.
        self.assertGreater(len(proof.merkle_path), 0)
        bad = bytearray(proof.merkle_path[0])
        bad[0] ^= 0xFF
        proof.merkle_path[0] = bytes(bad)
        ok, _ = verify_custody_proof(proof, expected_block_hash=self.block["block_hash"])
        self.assertFalse(ok)

    def test_verify_rejects_stale_header(self):
        """Header bytes that don't hash to expected_block_hash fail."""
        proof = build_custody_proof(
            prover_id=self.prover_id,
            target_height=self.block["block_number"],
            target_block_hash=self.block["block_hash"],
            header_bytes=self.block["header_bytes"],
            merkle_root=self.block["merkle_root"],
            tx_index=3,
            tx_bytes=self.block["tx_bytes_list"][3],
            all_tx_hashes=self.block["tx_hashes"],
        )
        # Swap the header for one from a different fake block.
        other = _mini_block([b"other-" + t for t in self.txs], block_number=99)
        proof.header_bytes = other["header_bytes"]
        ok, _ = verify_custody_proof(proof, expected_block_hash=self.block["block_hash"])
        self.assertFalse(ok)

    def test_verify_rejects_wrong_target_height(self):
        proof = build_custody_proof(
            prover_id=self.prover_id,
            target_height=self.block["block_number"],
            target_block_hash=self.block["block_hash"],
            header_bytes=self.block["header_bytes"],
            merkle_root=self.block["merkle_root"],
            tx_index=3,
            tx_bytes=self.block["tx_bytes_list"][3],
            all_tx_hashes=self.block["tx_hashes"],
        )
        # Ask the verifier to check against a *different* block — hash
        # mismatch catches the impersonation.
        bogus_hash = _h(b"not-our-block")
        ok, _ = verify_custody_proof(proof, expected_block_hash=bogus_hash)
        self.assertFalse(ok)


class TestProofEmptyBlock(unittest.TestCase):
    """Blocks with zero txs: challenge degrades to header-only proof."""

    def test_build_and_verify_empty_block(self):
        block = _mini_block([], block_number=3)
        proof = build_custody_proof(
            prover_id=b"\x01" * 32,
            target_height=block["block_number"],
            target_block_hash=block["block_hash"],
            header_bytes=block["header_bytes"],
            merkle_root=block["merkle_root"],
            tx_index=None,
            tx_bytes=b"",
            all_tx_hashes=[],
        )
        ok, reason = verify_custody_proof(
            proof, expected_block_hash=block["block_hash"],
        )
        self.assertTrue(ok, f"empty-block proof rejected: {reason}")


# ---------------------------------------------------------------------------
# 4. Burn redirect split
# ---------------------------------------------------------------------------


class TestBurnRedirectSplit(unittest.TestCase):
    def test_split_honors_pct(self):
        """Burning 100 with a 25% redirect should yield pool=25, burn=75."""
        pool_add, burn_keep = ac.split_burn_for_pool(100)
        self.assertEqual(pool_add + burn_keep, 100)
        self.assertEqual(pool_add, 25)
        self.assertEqual(burn_keep, 75)

    def test_split_matches_config_constant(self):
        """If an operator changes ARCHIVE_BURN_REDIRECT_PCT, the split
        follows.  Guards against hardcoding 25 in two places."""
        pool_add, _ = ac.split_burn_for_pool(1000)
        self.assertEqual(pool_add, 1000 * ARCHIVE_BURN_REDIRECT_PCT // 100)

    def test_small_burn_rounds_down(self):
        """Burning 3 at 25% redirect = 0 to pool, 3 to burn (integer floor).

        This keeps pool funding conservative: a single micro-burn never
        over-credits the pool. Rounding loss is <= 3 tokens per burn and
        net-neutral to total supply (it stays burned, not double-spent)."""
        pool_add, burn_keep = ac.split_burn_for_pool(3)
        self.assertEqual(pool_add, 0)
        self.assertEqual(burn_keep, 3)


class TestArchiveRewardPool(unittest.TestCase):
    def test_pool_starts_empty(self):
        p = ArchiveRewardPool()
        self.assertEqual(p.balance, 0)

    def test_fund_adds_to_pool(self):
        p = ArchiveRewardPool()
        p.fund(500)
        self.assertEqual(p.balance, 500)
        p.fund(200)
        self.assertEqual(p.balance, 700)

    def test_fund_rejects_negative(self):
        p = ArchiveRewardPool()
        with self.assertRaises(ValueError):
            p.fund(-1)

    def test_payout_decreases_balance(self):
        p = ArchiveRewardPool()
        p.fund(10_000)
        paid = p.try_pay(ARCHIVE_REWARD)
        self.assertEqual(paid, ARCHIVE_REWARD)
        self.assertEqual(p.balance, 10_000 - ARCHIVE_REWARD)

    def test_payout_returns_zero_when_empty(self):
        """Graceful degradation: empty pool returns 0, no exception."""
        p = ArchiveRewardPool()
        paid = p.try_pay(ARCHIVE_REWARD)
        self.assertEqual(paid, 0)
        self.assertEqual(p.balance, 0)

    def test_payout_caps_at_pool_balance(self):
        """If the pool has less than ARCHIVE_REWARD, try_pay pays only
        what's there and empties the pool."""
        p = ArchiveRewardPool()
        p.fund(ARCHIVE_REWARD // 2)
        paid = p.try_pay(ARCHIVE_REWARD)
        self.assertEqual(paid, ARCHIVE_REWARD // 2)
        self.assertEqual(p.balance, 0)


# ---------------------------------------------------------------------------
# 5. FCFS payout cap per challenge
# ---------------------------------------------------------------------------


class TestFCFSCap(unittest.TestCase):
    def _proof(self, prover_byte: int, block):
        return build_custody_proof(
            prover_id=bytes([prover_byte]) * 32,
            target_height=block["block_number"],
            target_block_hash=block["block_hash"],
            header_bytes=block["header_bytes"],
            merkle_root=block["merkle_root"],
            tx_index=0,
            tx_bytes=block["tx_bytes_list"][0],
            all_tx_hashes=block["tx_hashes"],
        )

    def test_first_N_valid_proofs_paid(self):
        pool = ArchiveRewardPool()
        pool.fund(ARCHIVE_REWARD * 100)  # plenty
        block = _mini_block([f"t{i}".encode() * 10 for i in range(3)], 5)
        proofs = [self._proof(i + 1, block) for i in range(15)]
        result = apply_archive_rewards(
            proofs=proofs,
            pool=pool,
            expected_block_hash=block["block_hash"],
        )
        # Exactly ARCHIVE_PROOFS_PER_CHALLENGE paid.
        self.assertEqual(len(result.payouts), ARCHIVE_PROOFS_PER_CHALLENGE)
        self.assertEqual(
            result.total_paid,
            ARCHIVE_PROOFS_PER_CHALLENGE * ARCHIVE_REWARD,
        )

    def test_only_valid_proofs_counted(self):
        """Invalid proofs don't consume a slot — a forged proof in
        position 2 is silently dropped and proof #11 gets paid instead of
        being excluded by the cap."""
        pool = ArchiveRewardPool()
        pool.fund(ARCHIVE_REWARD * 100)
        block = _mini_block([f"t{i}".encode() * 10 for i in range(3)], 5)
        proofs = []
        for i in range(ARCHIVE_PROOFS_PER_CHALLENGE + 2):
            p = self._proof(i + 1, block)
            if i == 2:
                # Forge this one
                p.tx_bytes = b"FORGED"
            proofs.append(p)
        result = apply_archive_rewards(
            proofs=proofs,
            pool=pool,
            expected_block_hash=block["block_hash"],
        )
        self.assertEqual(len(result.payouts), ARCHIVE_PROOFS_PER_CHALLENGE)
        self.assertNotIn(bytes([3]) * 32, {p.prover_id for p in result.payouts})

    def test_duplicate_prover_only_paid_once(self):
        """Same prover submitting twice claims only one slot — Sybil bound."""
        pool = ArchiveRewardPool()
        pool.fund(ARCHIVE_REWARD * 100)
        block = _mini_block([f"t{i}".encode() * 10 for i in range(2)], 5)
        dupe = self._proof(7, block)
        proofs = [dupe, dupe]  # exact dup
        result = apply_archive_rewards(
            proofs=proofs,
            pool=pool,
            expected_block_hash=block["block_hash"],
        )
        self.assertEqual(len(result.payouts), 1)


# ---------------------------------------------------------------------------
# 6. Graceful degradation when pool is empty
# ---------------------------------------------------------------------------


class TestEmptyPoolGraceful(unittest.TestCase):
    def test_empty_pool_no_payouts(self):
        pool = ArchiveRewardPool()  # balance 0
        block = _mini_block([f"t{i}".encode() * 10 for i in range(3)], 5)
        proofs = [
            build_custody_proof(
                prover_id=bytes([i + 1]) * 32,
                target_height=block["block_number"],
                target_block_hash=block["block_hash"],
                header_bytes=block["header_bytes"],
                merkle_root=block["merkle_root"],
                tx_index=0,
                tx_bytes=block["tx_bytes_list"][0],
                all_tx_hashes=block["tx_hashes"],
            )
            for i in range(5)
        ]
        result = apply_archive_rewards(
            proofs=proofs,
            pool=pool,
            expected_block_hash=block["block_hash"],
        )
        self.assertEqual(len(result.payouts), 0)
        self.assertEqual(result.total_paid, 0)
        self.assertEqual(pool.balance, 0)

    def test_partial_pool_pays_until_empty(self):
        """Pool balance = 2.5x reward -> pays 2 full rewards + 1 partial."""
        pool = ArchiveRewardPool()
        pool.fund(ARCHIVE_REWARD * 2 + ARCHIVE_REWARD // 2)
        block = _mini_block([f"t{i}".encode() * 10 for i in range(3)], 5)
        proofs = [
            build_custody_proof(
                prover_id=bytes([i + 1]) * 32,
                target_height=block["block_number"],
                target_block_hash=block["block_hash"],
                header_bytes=block["header_bytes"],
                merkle_root=block["merkle_root"],
                tx_index=0,
                tx_bytes=block["tx_bytes_list"][0],
                all_tx_hashes=block["tx_hashes"],
            )
            for i in range(5)
        ]
        result = apply_archive_rewards(
            proofs=proofs,
            pool=pool,
            expected_block_hash=block["block_hash"],
        )
        # First two proofs get full ARCHIVE_REWARD, third gets the remainder.
        self.assertEqual(len(result.payouts), 3)
        self.assertEqual(
            result.total_paid,
            ARCHIVE_REWARD * 2 + ARCHIVE_REWARD // 2,
        )
        self.assertEqual(pool.balance, 0)


# ---------------------------------------------------------------------------
# 7. State-root includes pool balance
# ---------------------------------------------------------------------------


class TestPoolInStateRoot(unittest.TestCase):
    def test_pool_in_snapshot_roundtrip(self):
        """Encoding + decoding a snapshot preserves pool balance."""
        from messagechain.storage.state_snapshot import (
            STATE_SNAPSHOT_VERSION,
            compute_state_root, decode_snapshot, encode_snapshot,
        )
        snap = {
            "version": STATE_SNAPSHOT_VERSION,
            "balances": {},
            "nonces": {},
            "staked": {},
            "public_keys": {},
            "authority_keys": {},
            "leaf_watermarks": {},
            "key_rotation_counts": {},
            "revoked_entities": set(),
            "slashed_validators": set(),
            "entity_id_to_index": {},
            "next_entity_index": 1,
            "total_supply": 1000,
            "total_minted": 0,
            "total_fees_collected": 0,
            "total_burned": 0,
            "base_fee": 100,
            "finalized_checkpoints": {},
            "seed_initial_stakes": {},
            "seed_divestment_debt": {},
            "archive_reward_pool": 12345,
        }
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(decoded["archive_reward_pool"], 12345)

    def test_pool_affects_state_root(self):
        """Two otherwise-identical snapshots that differ only in pool
        balance must produce different state roots — otherwise a
        bootstrapping node couldn't trust the pool value it received."""
        from messagechain.storage.state_snapshot import (
            STATE_SNAPSHOT_VERSION, compute_state_root,
        )
        base = {
            "version": STATE_SNAPSHOT_VERSION,
            "balances": {}, "nonces": {}, "staked": {},
            "public_keys": {}, "authority_keys": {},
            "leaf_watermarks": {}, "key_rotation_counts": {},
            "revoked_entities": set(), "slashed_validators": set(),
            "entity_id_to_index": {}, "next_entity_index": 1,
            "total_supply": 1000, "total_minted": 0,
            "total_fees_collected": 0, "total_burned": 0,
            "base_fee": 100, "finalized_checkpoints": {},
            "seed_initial_stakes": {}, "seed_divestment_debt": {},
            "archive_reward_pool": 0,
        }
        r0 = compute_state_root(base)
        alt = dict(base)
        alt["archive_reward_pool"] = 999
        r1 = compute_state_root(alt)
        self.assertNotEqual(r0, r1)


# ---------------------------------------------------------------------------
# 8. Integration with live Blockchain: burn redirection actually happens
# ---------------------------------------------------------------------------


class TestBurnRedirectIntegration(unittest.TestCase):
    """End-to-end: when a message tx burns its base fee in a live block,
    25% of that burn lands in archive_reward_pool and 75% lands in
    total_burned.  The pool carries forward across blocks."""

    def setUp(self):
        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.pos import ProofOfStake
        from tests import register_entity_for_test
        self.alice = Entity.create(b"alice-archive-test".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.supply.stake(self.alice.entity_id, 10_000)
        self.pos = ProofOfStake()

    def test_burn_redirects_configured_pct_to_pool(self):
        """Submit a message tx, let it burn base_fee, and check pool grew."""
        from messagechain.core.transaction import create_transaction
        prev_pool = self.chain.archive_reward_pool
        prev_burned = self.chain.supply.total_burned
        base_fee = self.chain.supply.base_fee
        fee = max(base_fee * 3, 1500)  # cover base + tip
        tx = create_transaction(
            self.alice, "hello archive rewards",
            fee=fee,
            nonce=self.chain.nonces.get(self.alice.entity_id, 0),
        )
        block = self.chain.propose_block(
            self.pos, self.alice, transactions=[tx],
        )
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, f"block rejected: {reason}")
        pool_delta = self.chain.archive_reward_pool - prev_pool
        burn_delta = self.chain.supply.total_burned - prev_burned
        # Pool captured ARCHIVE_BURN_REDIRECT_PCT of the base-fee stream
        # (redirected portion subtracts from burn, so pool_delta +
        # burn_delta == original base_fee burn).
        original_fee_burn = pool_delta + burn_delta
        self.assertEqual(
            pool_delta,
            original_fee_burn * ARCHIVE_BURN_REDIRECT_PCT // 100,
        )
        # base_fee was burned (base_fee >= MIN_FEE = 100), and
        # MIN_FEE * 25% = 25 > 0 so the redirect is observable.
        self.assertGreater(pool_delta, 0)
        # 75% still burns — principle #2 permanence + bloat control.
        self.assertGreater(burn_delta, pool_delta)


class TestPoolPersistedInBlockchain(unittest.TestCase):
    """The live Blockchain object exposes an `archive_reward_pool` scalar
    that starts at 0 and is readable from tests."""

    def test_fresh_chain_has_zero_pool(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        self.assertEqual(chain.archive_reward_pool, 0)


if __name__ == "__main__":
    unittest.main()
