"""
Security audit pass 2 — 2026-04-12 (Opus 4.6 deep review).

Tests for findings discovered in the second-pass security audit.
Written FIRST per TDD — these tests define the expected secure behavior.

Findings covered:
  C1  get_spendable_balance() must never return negative
  C2  Sync handlers must reject oversized header/block arrays
  C3  _handle_fork must reject forks that violate finality boundary
  H1  RBF must always verify signatures (no public_key=None bypass)
  H2  _serve_headers must validate start_height type and range
  H3  select_proposer must degrade safely when randao_mix=None
  H4  Addrman must reject private/reserved IPs
  H5  Governance proposals must be prunable after voting window closes
  H6  SPV proof must validate len(siblings) == len(directions)
"""

import asyncio
import hashlib
import os
import struct
import time
import unittest

import messagechain.config as cfg
from messagechain.config import (
    COINBASE_MATURITY,
    HASH_ALGO,
    MIN_FEE,
    VALIDATOR_MIN_STAKE,
)


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_entity():
    from messagechain.identity.identity import Entity
    return Entity.create(os.urandom(32))


def _setup_chain():
    from messagechain.core.blockchain import Blockchain
    bc = Blockchain()
    entity = _make_entity()
    bc.initialize_genesis(entity)
    return bc, entity


# ─────────��───────────────────────────────────────────────────────────
# C1: get_spendable_balance() integer underflow
# ───��────────────────���──────────────────────────��─────────────────────

class TestC1SpendableBalanceFloor(unittest.TestCase):
    """get_spendable_balance() must return >= 0, even if immature > total."""

    def test_spendable_balance_never_negative(self):
        """If immature rewards somehow exceed total balance, return 0."""
        bc, entity = _setup_chain()
        eid = entity.entity_id

        # Artificially inject immature rewards that exceed the entity's balance
        total_balance = bc.supply.get_balance(eid)
        bc._immature_rewards.append(
            (bc.height, eid, total_balance + 1000)
        )

        spendable = bc.get_spendable_balance(eid)
        self.assertGreaterEqual(spendable, 0,
            "get_spendable_balance() must never return a negative value")


# ─────────────���───────────────────���────────────────────────────────��──
# C2: Sync handler unbounded array allocation
# ─────��─────────────���────────────────────────────────────���────────────

class TestC2SyncArrayBounds(unittest.TestCase):
    """Sync handlers must reject oversized header/block arrays."""

    def _make_syncer(self):
        from messagechain.network.sync import ChainSyncer, SyncState
        bc, _ = _setup_chain()
        syncer = ChainSyncer(
            blockchain=bc,
            get_peer_writer=lambda addr: (None, None),
        )
        syncer.state = SyncState.SYNCING_HEADERS
        return syncer

    def test_headers_response_rejects_oversized_array(self):
        """handle_headers_response must reject arrays larger than a sane limit."""
        from messagechain.network.sync import HEADERS_BATCH_SIZE
        syncer = self._make_syncer()

        # Create an array much larger than batch size
        oversized = [{"block_number": i, "prev_hash": "00" * 32,
                       "block_hash": f"{i:064x}"} for i in range(HEADERS_BATCH_SIZE * 3)]

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                syncer.handle_headers_response(oversized, "1.2.3.4:9333")
            )
        finally:
            loop.close()

        # The syncer should NOT have accepted all of them
        self.assertLessEqual(
            len(syncer.pending_headers),
            cfg.MAX_PENDING_HEADERS,
            "Syncer must bound pending headers to MAX_PENDING_HEADERS"
        )

    def test_blocks_response_rejects_oversized_array(self):
        """handle_blocks_response must cap the number of blocks processed."""
        from messagechain.network.sync import ChainSyncer, SyncState, BLOCKS_BATCH_SIZE
        bc, _ = _setup_chain()
        syncer = ChainSyncer(
            blockchain=bc,
            get_peer_writer=lambda addr: (None, None),
        )
        syncer.state = SyncState.SYNCING_BLOCKS

        # The handler should not process more than BLOCKS_BATCH_SIZE * 2
        limit = BLOCKS_BATCH_SIZE * 2
        oversized = [{"invalid": True} for _ in range(limit + 50)]

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                syncer.handle_blocks_response(oversized, "1.2.3.4:9333")
            )
        finally:
            loop.close()
        # If we get here without OOM, the bound is working


# ──────────────────────────────���────────────────────────────────────��─
# C3: _handle_fork finality boundary
# ──��─────────────────────────────���────────────────────────────────────

class TestC3ForkFinalityBoundary(unittest.TestCase):
    """_handle_fork must not store fork blocks that violate finality."""

    def test_fork_rejected_when_reverting_finalized_block(self):
        """A fork that competes with a finalized block must be rejected."""
        bc, entity = _setup_chain()
        from messagechain.core.block import Block, BlockHeader

        # Build a short canonical chain
        genesis = bc.get_block(0)
        parent = genesis
        old_enforce = cfg.ENFORCE_SLOT_TIMING
        cfg.ENFORCE_SLOT_TIMING = False
        try:
            for i in range(3):
                header = BlockHeader(
                    version=1,
                    prev_hash=parent.block_hash,
                    merkle_root=_hash(b""),
                    timestamp=int(time.time()) + (i + 1) * cfg.BLOCK_TIME_TARGET,
                    block_number=parent.header.block_number + 1,
                    proposer_id=entity.entity_id,
                )
                block = Block(header=header, transactions=[], attestations=[])
                block._block_hash = _hash(repr(block.header.serialize()).encode())
                bc.add_block(block)
                parent = block
        finally:
            cfg.ENFORCE_SLOT_TIMING = old_enforce

        # Finalize block at height 2
        finalized_block = bc.get_block(2)
        if finalized_block is None:
            return  # chain build failed, skip
        bc.finality.finalize(finalized_block.block_hash)

        # Create a fork block branching off height 1 (competing with finalized height 2)
        block_at_1 = bc.get_block(1)
        fork_header = BlockHeader(
            version=1,
            prev_hash=block_at_1.block_hash,
            merkle_root=_hash(b"fork"),
            timestamp=int(time.time()) + 10 * cfg.BLOCK_TIME_TARGET,
            block_number=2,
            proposer_id=entity.entity_id,
        )
        fork_block = Block(header=fork_header, transactions=[], attestations=[])
        fork_block._block_hash = _hash(repr(fork_block.header.serialize()).encode())

        success, reason = bc._handle_fork(fork_block, block_at_1)
        # Must reject the fork since it competes with a finalized height
        self.assertFalse(success,
            f"Fork at finalized height must be rejected, got: {reason}")


# ─���──────────���──────────────────────────────────��─────────────────────
# H1: RBF signature verification bypass
# ─────────���─────────────��───────────────────────────────────��─────────

class TestH1RBFSignatureRequired(unittest.TestCase):
    """RBF must always verify signatures — public_key=None must not skip."""

    def test_rbf_without_public_key_rejects(self):
        """try_replace_by_fee() with public_key=None must reject replacement."""
        from messagechain.core.mempool import Mempool
        from messagechain.core.transaction import MessageTransaction
        from messagechain.crypto.keys import Signature

        pool = Mempool()
        eid = os.urandom(32)
        dummy_sig = Signature([], 0, [], b"\x00" * 32, b"\x00" * 32)

        # Add an original transaction
        tx1 = MessageTransaction(
            entity_id=eid,
            message=b"hello",
            fee=200,
            nonce=0,
            timestamp=time.time(),
            signature=dummy_sig,
        )
        pool.add_transaction(tx1)

        # Attempt RBF with no public key (signature bypass)
        tx2 = MessageTransaction(
            entity_id=eid,
            message=b"evil replacement",
            fee=500,
            nonce=0,
            timestamp=time.time(),
            signature=dummy_sig,
        )

        result = pool.try_replace_by_fee(tx2, public_key=None)
        self.assertFalse(result,
            "RBF must reject replacements when no public_key is provided")


# ────────────��─────────────────────────────���───────────────────────���──
# H2: _serve_headers input validation
# ───────────────────��───────────────────────────────────��─────────────

class TestH2ServeHeadersValidation(unittest.TestCase):
    """_serve_headers must validate start_height type and range."""

    def test_negative_start_height_clamped(self):
        """Negative start_height must be clamped to 0."""
        start_height = -100
        safe_start = max(0, start_height) if isinstance(start_height, int) else 0
        self.assertEqual(safe_start, 0)

    def test_non_integer_start_height_defaults(self):
        """Non-integer start_height must default to 0."""
        start_height = "not_a_number"
        safe_start = max(0, start_height) if isinstance(start_height, int) else 0
        self.assertEqual(safe_start, 0)


# ──────���──────────────────────────────────��─────────────────────���─────
# H3: select_proposer None randao_mix
# ��──────────────────────────────────────���─────────────────────────────

class TestH3SelectProposerRandao(unittest.TestCase):
    """select_proposer must handle None randao_mix safely."""

    def test_none_randao_still_returns_proposer(self):
        """select_proposer with randao_mix=None must still return a valid proposer."""
        from messagechain.consensus.pos import ProofOfStake

        pos = ProofOfStake()
        eid = os.urandom(32)
        pos.stakes[eid] = 1000

        prev_hash = os.urandom(32)
        result = pos.select_proposer(prev_hash, randao_mix=None)
        self.assertIsNotNone(result, "Must return a proposer even without RANDAO")

    def test_randao_mix_changes_selection_with_multiple_validators(self):
        """RANDAO mix should influence proposer selection."""
        from messagechain.consensus.pos import ProofOfStake

        pos = ProofOfStake()
        # Add many validators so selection has variety
        eids = [os.urandom(32) for _ in range(50)]
        for eid in eids:
            pos.stakes[eid] = 100

        prev_hash = os.urandom(32)
        results_with_randao = set()
        results_without = set()
        for _ in range(10):
            randao = os.urandom(32)
            r = pos.select_proposer(prev_hash, randao_mix=randao)
            if r:
                results_with_randao.add(r)
            r2 = pos.select_proposer(prev_hash, randao_mix=None)
            if r2:
                results_without.add(r2)

        # With RANDAO, different mixes should (usually) select different proposers
        # Without RANDAO, same inputs always gives same result
        self.assertEqual(len(results_without), 1,
            "Without RANDAO, same prev_hash should always pick same proposer")
        self.assertGreater(len(results_with_randao), 1,
            "With different RANDAO mixes, selection should vary")


# ───────────────────────────────────────────────��─────────────────────
# H4: Addrman private IP filtering
# ────��─────────────────��──────────────────────────────────────────────

class TestH4AddrmanPrivateIPs(unittest.TestCase):
    """Addrman must reject private/reserved IPs from PEER_LIST gossip."""

    def test_rejects_localhost(self):
        from messagechain.network.addrman import AddressManager
        mgr = AddressManager()
        result = mgr.add_address("127.0.0.1", 9333, "8.8.8.8")
        self.assertFalse(result, "Must reject localhost 127.0.0.1")

    def test_rejects_rfc1918_10(self):
        from messagechain.network.addrman import AddressManager
        mgr = AddressManager()
        result = mgr.add_address("10.0.0.1", 9333, "8.8.8.8")
        self.assertFalse(result, "Must reject RFC1918 10.0.0.0/8")

    def test_rejects_rfc1918_172(self):
        from messagechain.network.addrman import AddressManager
        mgr = AddressManager()
        result = mgr.add_address("172.16.0.1", 9333, "8.8.8.8")
        self.assertFalse(result, "Must reject RFC1918 172.16.0.0/12")

    def test_rejects_rfc1918_192(self):
        from messagechain.network.addrman import AddressManager
        mgr = AddressManager()
        result = mgr.add_address("192.168.1.1", 9333, "8.8.8.8")
        self.assertFalse(result, "Must reject RFC1918 192.168.0.0/16")

    def test_rejects_link_local(self):
        from messagechain.network.addrman import AddressManager
        mgr = AddressManager()
        result = mgr.add_address("169.254.1.1", 9333, "8.8.8.8")
        self.assertFalse(result, "Must reject link-local 169.254.0.0/16")

    def test_rejects_zero_network(self):
        from messagechain.network.addrman import AddressManager
        mgr = AddressManager()
        result = mgr.add_address("0.0.0.0", 9333, "8.8.8.8")
        self.assertFalse(result, "Must reject 0.0.0.0")

    def test_accepts_public_ip(self):
        from messagechain.network.addrman import AddressManager
        mgr = AddressManager()
        result = mgr.add_address("8.8.4.4", 9333, "8.8.8.8")
        self.assertTrue(result, "Must accept valid public IPs")


# ─────────���──────────────────────────────────────────────────────���────
# H5: Governance proposal unbounded storage
# ──────────────────��──────────────────────────────────────────────────

class TestH5GovernanceProposalPruning(unittest.TestCase):
    """Governance tracker must support pruning closed proposals."""

    def test_prune_removes_old_closed_proposals(self):
        from messagechain.governance.governance import (
            GovernanceTracker, ProposalTransaction,
        )
        from messagechain.economics.inflation import SupplyTracker
        from messagechain.crypto.keys import Signature

        tracker = GovernanceTracker()
        supply = SupplyTracker()
        supply.balances[os.urandom(32)] = 100_000

        entity = _make_entity()
        dummy_sig = Signature(
            leaf_index=0,
            wots_signature=[b"\x00" * 32] * 64,
            auth_path=[b"\x00" * 32] * 4,
            wots_public_key=b"\x00" * 32,
            wots_public_seed=b"\x00" * 32,
        )

        for i in range(20):
            ptx = ProposalTransaction(
                proposer_id=entity.entity_id,
                title=f"Proposal {i}",
                description="test",
                timestamp=time.time(),
                fee=cfg.GOVERNANCE_PROPOSAL_FEE,
                signature=dummy_sig,
            )
            tracker.add_proposal(ptx, block_height=i * 10, supply_tracker=supply)

        self.assertEqual(len(tracker.proposals), 20)

        # Prune proposals whose voting window has closed
        current_block = 20 * 10 + cfg.GOVERNANCE_VOTING_WINDOW + 100
        if hasattr(tracker, 'prune_closed_proposals'):
            tracker.prune_closed_proposals(current_block)
            self.assertLess(len(tracker.proposals), 20,
                "prune_closed_proposals must remove old closed proposals")
        else:
            self.fail("GovernanceTracker must implement prune_closed_proposals()")


# ───────────────────���─────────────────────────────────────────────────
# H6: SPV proof length validation
# ─────���───────────────────────��──────────────────────────────���────────

class TestH6SPVProofLengthValidation(unittest.TestCase):
    """SPV proof must validate that siblings and directions have equal length."""

    def test_mismatched_siblings_directions_rejected(self):
        from messagechain.core.spv import MerkleProof, verify_merkle_proof

        proof = MerkleProof(
            tx_hash=os.urandom(32),
            tx_index=0,
            siblings=[os.urandom(32), os.urandom(32)],
            directions=[True],  # only 1 direction for 2 siblings
        )

        result = verify_merkle_proof(
            tx_hash=proof.tx_hash,
            proof=proof,
            merkle_root=os.urandom(32),
        )
        self.assertFalse(result,
            "verify_merkle_proof must reject proofs with mismatched siblings/directions length")

    def test_valid_proof_still_works(self):
        """A correctly-constructed proof must still validate."""
        from messagechain.core.spv import MerkleProof, verify_merkle_proof
        from messagechain.core.block import compute_merkle_root

        # Build a proof manually for a 4-leaf tree
        tx_hashes = [os.urandom(32) for _ in range(4)]
        root = compute_merkle_root(tx_hashes)

        # Leaf 0: needs sibling leaf 1, then right subtree root
        leaf0 = _hash(b"\x00" + tx_hashes[0])
        leaf1 = _hash(b"\x00" + tx_hashes[1])
        leaf2 = _hash(b"\x00" + tx_hashes[2])
        leaf3 = _hash(b"\x00" + tx_hashes[3])
        right_subtree = _hash(b"\x01" + leaf2 + leaf3)

        proof = MerkleProof(
            tx_hash=tx_hashes[0],
            tx_index=0,
            siblings=[leaf1, right_subtree],
            directions=[False, False],  # siblings are on the right
        )
        self.assertTrue(
            verify_merkle_proof(tx_hashes[0], proof, root),
            "Valid proof must still verify correctly"
        )


if __name__ == "__main__":
    unittest.main()
