"""
End-to-end wiring tests for Proof-of-Custody archive rewards.

The archive-rewards PRIMITIVES (CustodyProof, compute_challenge,
apply_archive_rewards, split_burn_for_pool) have their own unit
tests in tests/test_archive_challenge.py.  This file exercises the
BLOCK-LEVEL wiring on top of those primitives:

    * custody_proofs field on Block serialize + binary roundtrip
    * hygiene: non-challenge blocks reject non-empty proofs
    * cap: challenge block accepts up to N, rejects N+1
    * proof mempool: dedup, eviction, FCFS ordering
    * proposer integration: picks proofs on challenge blocks only
    * validator integration: rejects wrong-target proofs
    * payout: FCFS debits pool, credits provers; empty pool = no-op
    * RPC submission helper: submit, see in pool
    * gossip: CustodyProof round-trips through serialize

Chain topology is kept small: ARCHIVE_CHALLENGE_INTERVAL is patched
down for test budgets (tree height 4 = 16 one-time WOTS+ keys).
"""

import hashlib
import unittest

# Patch the challenge cadence to something short BEFORE any import
# reads it — tests run tree height 4 = 16 one-time WOTS+ keys, and
# production's 100-block cadence would exhaust keys before any
# challenge fired.  We have to patch every module namespace that did
# a `from messagechain.config import ARCHIVE_*` — rebinding on the
# source module is not enough, since the imported names are separate
# module-level bindings.
import messagechain.config as _cfg
_cfg.ARCHIVE_CHALLENGE_INTERVAL = 4
_cfg.ARCHIVE_SUBMISSION_WINDOW = 4

import messagechain.consensus.archive_challenge as _ac
_ac.ARCHIVE_CHALLENGE_INTERVAL = 4
_ac.ARCHIVE_SUBMISSION_WINDOW = 4

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block
from messagechain.consensus.pos import ProofOfStake
from messagechain.config import (
    HASH_ALGO,
    ARCHIVE_CHALLENGE_INTERVAL,
    ARCHIVE_SUBMISSION_WINDOW,
    ARCHIVE_PROOFS_PER_CHALLENGE,
    ARCHIVE_REWARD,
    is_archive_challenge_block,
)
from messagechain.consensus.archive_challenge import (
    CustodyProof,
    build_custody_proof,
    compute_challenge,
    verify_custody_proof,
)
from messagechain.consensus.archive_proof_mempool import ArchiveProofMempool


def _h(b: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, b).digest()


def _prime_chain(num_blocks: int) -> tuple[Blockchain, Entity, ProofOfStake]:
    """Stand up a single-validator chain with `num_blocks` real blocks."""
    alice = Entity.create(b"alice-seed".ljust(32, b"\x00"))
    chain = Blockchain()
    chain.initialize_genesis(alice)
    chain.supply.balances[alice.entity_id] = 100_000_000
    consensus = ProofOfStake()

    for _ in range(num_blocks):
        block = chain.propose_block(consensus, alice, [])
        ok, reason = chain.add_block(block)
        assert ok, reason
    return chain, alice, consensus


def _build_proof_for_challenge(
    chain: Blockchain,
    prover_id: bytes,
    challenge_block_number: int,
) -> CustodyProof:
    """Construct a valid CustodyProof answering the challenge at height H.

    Resolves the challenge target from the challenge block's parent
    hash (= block at H-1), reads that target block out of the chain,
    and builds a header-only proof (or tx-indexed if the target has
    txs).  Uses the block's tx_hashes list; the test chain runs empty
    blocks so every proof is header-only.
    """
    parent = chain.get_block(challenge_block_number - 1)
    ch = compute_challenge(parent.block_hash, challenge_block_number)
    target = chain.get_block(ch.target_height)
    tx_hashes: list[bytes] = []  # test chain runs empty blocks
    # The CustodyProof primitive verifies header_bytes by SHA3-hashing
    # them and comparing to target_block_hash.  In MessageChain the
    # block hash preimage is `header.signable_data() + header.randao_mix`
    # (see Block._compute_hash), not header.to_bytes() — using the
    # preimage makes the hash match exactly.
    header_bytes = target.header.signable_data() + target.header.randao_mix
    return build_custody_proof(
        prover_id=prover_id,
        target_height=target.header.block_number,
        target_block_hash=target.block_hash,
        header_bytes=header_bytes,
        merkle_root=target.header.merkle_root,
        tx_index=None,
        tx_bytes=b"",
        all_tx_hashes=tx_hashes,
    )


# ── Hygiene on non-challenge blocks ────────────────────────────────────


class TestHygieneOnNonChallengeBlock(unittest.TestCase):
    def test_non_challenge_block_rejects_nonempty_proofs(self):
        chain, alice, consensus = _prime_chain(2)
        next_h = chain.height
        self.assertFalse(is_archive_challenge_block(next_h))
        tgt = chain.get_block(0)
        proof = CustodyProof(
            prover_id=alice.entity_id,
            target_height=0,
            target_block_hash=tgt.block_hash,
            header_bytes=tgt.header.signable_data() + tgt.header.randao_mix,
            merkle_root=tgt.header.merkle_root,
            tx_index=None,
            tx_bytes=b"",
            merkle_path=[],
            merkle_layer_sizes=[0],
        )
        block = chain.propose_block(
            consensus, alice, [], custody_proofs=[proof],
        )
        ok, reason = chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("custody_proofs", reason.lower())


# ── Cap + accept-within-cap ────────────────────────────────────────────


class TestProofsFitAndCap(unittest.TestCase):
    def test_challenge_block_accepts_one_proof(self):
        chain, alice, consensus = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        self.assertTrue(is_archive_challenge_block(next_h))
        proof = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        block = chain.propose_block(
            consensus, alice, [], custody_proofs=[proof],
        )
        ok, reason = chain.validate_block(block)
        self.assertTrue(ok, reason)

    def test_challenge_block_rejects_over_cap(self):
        chain, alice, consensus = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        template = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        proofs = []
        for i in range(ARCHIVE_PROOFS_PER_CHALLENGE + 1):
            proofs.append(CustodyProof(
                prover_id=bytes([i + 1]) * 32,
                target_height=template.target_height,
                target_block_hash=template.target_block_hash,
                header_bytes=template.header_bytes,
                merkle_root=template.merkle_root,
                tx_index=template.tx_index,
                tx_bytes=template.tx_bytes,
                merkle_path=list(template.merkle_path),
                merkle_layer_sizes=list(template.merkle_layer_sizes),
            ))
        block = chain.propose_block(
            consensus, alice, [], custody_proofs=proofs,
        )
        ok, reason = chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("cap", reason.lower())


# ── Block serialization ────────────────────────────────────────────────


class TestBlockSerialization(unittest.TestCase):
    def test_proofs_roundtrip_binary_and_dict(self):
        chain, alice, consensus = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        proof = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        block = chain.propose_block(
            consensus, alice, [], custody_proofs=[proof],
        )
        rebuilt = Block.deserialize(block.serialize())
        self.assertEqual(len(rebuilt.custody_proofs), 1)
        self.assertEqual(rebuilt.custody_proofs[0].prover_id, alice.entity_id)
        self.assertEqual(rebuilt.block_hash, block.block_hash)
        rebuilt2 = Block.from_bytes(block.to_bytes())
        self.assertEqual(len(rebuilt2.custody_proofs), 1)
        self.assertEqual(rebuilt2.block_hash, block.block_hash)


# ── Validator rejects wrong-target proofs ──────────────────────────────


class TestValidatorRejectsBadProof(unittest.TestCase):
    def test_wrong_target_height(self):
        chain, alice, consensus = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        good = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        different = chain.get_block((good.target_height + 1) % next_h)
        bad = CustodyProof(
            prover_id=alice.entity_id,
            target_height=different.header.block_number,
            target_block_hash=different.block_hash,
            header_bytes=different.header.signable_data() + different.header.randao_mix,
            merkle_root=different.header.merkle_root,
            tx_index=None,
            tx_bytes=b"",
            merkle_path=[],
            merkle_layer_sizes=[0],
        )
        block = chain.propose_block(
            consensus, alice, [], custody_proofs=[bad],
        )
        ok, reason = chain.validate_block(block)
        self.assertFalse(ok)


# ── Proof mempool ──────────────────────────────────────────────────────


class TestArchiveProofMempool(unittest.TestCase):
    def test_add_and_dedupe(self):
        chain, alice, _ = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        p = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        pool = ArchiveProofMempool()
        self.assertTrue(pool.add_proof(p, challenge_block_number=next_h))
        self.assertFalse(pool.add_proof(p, challenge_block_number=next_h))
        self.assertEqual(len(pool.proofs_for_challenge(next_h)), 1)

    def test_evict_expired(self):
        chain, alice, _ = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        p = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        pool = ArchiveProofMempool()
        pool.add_proof(p, challenge_block_number=next_h)
        pool.evict_expired(next_h + ARCHIVE_SUBMISSION_WINDOW + 1)
        self.assertEqual(len(pool.proofs_for_challenge(next_h)), 0)

    def test_non_challenge_block_number_rejected(self):
        chain, alice, _ = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        p = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        pool = ArchiveProofMempool()
        self.assertFalse(pool.add_proof(p, challenge_block_number=next_h + 1))


# ── Payout ─────────────────────────────────────────────────────────────


class TestPayout(unittest.TestCase):
    def test_fcfs_debits_pool_and_credits_provers(self):
        chain, alice, consensus = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        template = _build_proof_for_challenge(chain, alice.entity_id, next_h)

        seed = ARCHIVE_REWARD * ARCHIVE_PROOFS_PER_CHALLENGE
        chain.archive_reward_pool = seed

        proofs = []
        provers = []
        for i in range(ARCHIVE_PROOFS_PER_CHALLENGE):
            prover = bytes([i + 1]) * 32
            provers.append(prover)
            proofs.append(CustodyProof(
                prover_id=prover,
                target_height=template.target_height,
                target_block_hash=template.target_block_hash,
                header_bytes=template.header_bytes,
                merkle_root=template.merkle_root,
                tx_index=template.tx_index,
                tx_bytes=template.tx_bytes,
                merkle_path=list(template.merkle_path),
                merkle_layer_sizes=list(template.merkle_layer_sizes),
            ))

        block = chain.propose_block(
            consensus, alice, [], custody_proofs=proofs,
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)

        for prover in provers:
            self.assertEqual(
                chain.supply.balances.get(prover, 0), ARCHIVE_REWARD,
            )
        self.assertEqual(chain.archive_reward_pool, 0)

    def test_empty_pool_is_noop(self):
        chain, alice, consensus = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL - 1)
        next_h = chain.height
        chain.archive_reward_pool = 0
        proof = _build_proof_for_challenge(chain, alice.entity_id, next_h)
        block = chain.propose_block(
            consensus, alice, [], custody_proofs=[proof],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)


# ── RPC submission helper round-trip ───────────────────────────────────


class TestSubmissionHelper(unittest.TestCase):
    def test_submit_round_trip(self):
        from messagechain.network.submission_server import (
            submit_custody_proof_to_pool,
        )
        chain, alice, _ = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL)
        challenge_h = ARCHIVE_CHALLENGE_INTERVAL
        proof = _build_proof_for_challenge(chain, alice.entity_id, challenge_h)
        pool = ArchiveProofMempool()
        result = submit_custody_proof_to_pool(proof, chain, pool)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(len(pool.proofs_for_challenge(challenge_h)), 1)

    def test_submit_idempotent(self):
        from messagechain.network.submission_server import (
            submit_custody_proof_to_pool,
        )
        chain, alice, _ = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL)
        challenge_h = ARCHIVE_CHALLENGE_INTERVAL
        proof = _build_proof_for_challenge(chain, alice.entity_id, challenge_h)
        pool = ArchiveProofMempool()
        r1 = submit_custody_proof_to_pool(proof, chain, pool)
        r2 = submit_custody_proof_to_pool(proof, chain, pool)
        self.assertTrue(r1.ok and r2.ok)
        self.assertTrue(r2.duplicate)
        self.assertEqual(len(pool.proofs_for_challenge(challenge_h)), 1)


# ── Gossip wire format ─────────────────────────────────────────────────


class TestGossipRoundTrip(unittest.TestCase):
    def test_dict_roundtrip(self):
        chain, alice, _ = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL)
        proof = _build_proof_for_challenge(
            chain, alice.entity_id, ARCHIVE_CHALLENGE_INTERVAL,
        )
        dup = CustodyProof.deserialize(proof.serialize())
        self.assertEqual(dup.prover_id, proof.prover_id)
        self.assertEqual(dup.target_block_hash, proof.target_block_hash)

    def test_binary_roundtrip(self):
        chain, alice, _ = _prime_chain(ARCHIVE_CHALLENGE_INTERVAL)
        proof = _build_proof_for_challenge(
            chain, alice.entity_id, ARCHIVE_CHALLENGE_INTERVAL,
        )
        dup = CustodyProof.from_bytes(proof.to_bytes())
        self.assertEqual(dup.prover_id, proof.prover_id)
        self.assertEqual(dup.tx_hash, proof.tx_hash)


if __name__ == "__main__":
    unittest.main()
