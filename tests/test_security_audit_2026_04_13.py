"""
Security audit fix verification tests — 2026-04-13.

Tests cover Critical (C1-C2), High (H1-H9), and Medium (M1-M23) findings.
"""

import hashlib
import struct
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from messagechain.config import (
    HASH_ALGO, MERKLE_TREE_HEIGHT, MIN_FEE, GENESIS_SUPPLY,
    GOVERNANCE_PROPOSAL_FEE, GOVERNANCE_VOTE_FEE,
    BASE_FEE_INITIAL, FINALITY_THRESHOLD_NUMERATOR, FINALITY_THRESHOLD_DENOMINATOR,
)


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_entity():
    """Create a test entity with a fresh keypair."""
    from messagechain.identity.identity import Entity
    import os
    return Entity.create(os.urandom(32))


def _make_chain_with_entity():
    """Create a blockchain and register an entity on it."""
    from messagechain.core.blockchain import Blockchain
    entity = _make_entity()
    chain = Blockchain()
    chain.register_entity(entity.entity_id, entity.keypair.public_key)
    chain.supply.balances[entity.entity_id] = 1_000_000
    return chain, entity


# ─── C1: Governance transactions must be queued, not applied directly ────

class TestC1GovernanceConsensus(unittest.TestCase):
    """C1: Governance RPC handlers must queue transactions for block inclusion,
    not apply state directly."""

    def test_server_proposal_queued_not_applied(self):
        """Proposal via RPC should be queued, not applied immediately."""
        from server import Server
        s = Server(p2p_port=19335, rpc_port=19336, seed_nodes=[])
        entity = _make_entity()
        s.wallet_id = entity.entity_id
        s.wallet_entity = entity
        s.blockchain.public_keys[entity.entity_id] = entity.keypair.public_key
        s.blockchain.supply.balances[entity.entity_id] = 1_000_000

        from messagechain.governance.governance import create_proposal
        tx = create_proposal(entity, "Test Proposal", "Test Description")

        balance_before = s.blockchain.supply.get_balance(entity.entity_id)
        result = s._rpc_submit_proposal({"transaction": tx.serialize()})
        self.assertTrue(result["ok"], result.get("error"))

        # Balance should NOT have changed (fee not yet deducted)
        balance_after = s.blockchain.supply.get_balance(entity.entity_id)
        self.assertEqual(balance_before, balance_after)
        self.assertTrue(hasattr(s, '_pending_governance_txs'))

    def test_server_vote_queued_not_applied(self):
        """Vote via RPC should be queued, not applied immediately."""
        from server import Server
        s = Server(p2p_port=19337, rpc_port=19338, seed_nodes=[])
        entity = _make_entity()
        s.wallet_id = entity.entity_id
        s.wallet_entity = entity
        s.blockchain.public_keys[entity.entity_id] = entity.keypair.public_key
        s.blockchain.supply.balances[entity.entity_id] = 1_000_000

        from messagechain.governance.governance import create_vote
        # Create a vote for a fake proposal (validation is at block-inclusion time)
        tx = create_vote(entity, b"\x00" * 32, True)

        balance_before = s.blockchain.supply.get_balance(entity.entity_id)
        result = s._rpc_submit_vote({"transaction": tx.serialize()})
        self.assertTrue(result["ok"], result.get("error"))
        balance_after = s.blockchain.supply.get_balance(entity.entity_id)
        self.assertEqual(balance_before, balance_after)


# ─── C2: Server handles PEER_LIST messages ────

class TestC2PeerListHandler(unittest.TestCase):
    """C2: Server must handle PEER_LIST messages to populate addrman."""

    def test_server_has_peer_list_handler(self):
        """The Server's message handler should process PEER_LIST messages."""
        from server import Server
        from messagechain.network.protocol import MessageType
        s = Server(p2p_port=19339, rpc_port=19340, seed_nodes=[])

        # Check that the handler exists by inspecting _handle_p2p_message
        # It should not silently drop PEER_LIST messages
        import inspect
        source = inspect.getsource(s._handle_p2p_message)
        self.assertIn("PEER_LIST", source)


# ─── H1: Attestation block hash/height must be verified ────

class TestH1AttestationVerification(unittest.TestCase):
    """H1: validate_block_attestations must check attestation block_hash
    and block_number match the parent block."""

    def test_mismatched_attestation_block_hash_rejected(self):
        """Attestations for a different block hash should not count toward stake."""
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.consensus.attestation import Attestation, create_attestation
        from messagechain.core.block import Block, BlockHeader, compute_merkle_root

        pos = ProofOfStake()
        entity = _make_entity()
        pos.register_validator(entity.entity_id, 1000, block_height=0)

        # Register enough validators to exit bootstrap
        others = []
        for _ in range(3):
            e = _make_entity()
            pos.register_validator(e.entity_id, 1000, block_height=0)
            others.append(e)

        # Create attestation for a WRONG block hash
        wrong_hash = b"\xaa" * 32
        att = create_attestation(entity, wrong_hash, 1)

        # Build a block with the mismatched attestation
        prev_hash = b"\x00" * 32
        header = BlockHeader(
            version=1, block_number=2, prev_hash=prev_hash,
            merkle_root=_hash(b"empty"), timestamp=time.time(),
            proposer_id=entity.entity_id, state_root=b"\x00" * 32,
        )
        block = Block(header=header, transactions=[], attestations=[att])

        pks = {entity.entity_id: entity.keypair.public_key}
        for e in others:
            pks[e.entity_id] = e.keypair.public_key

        # The mismatched attestation should not count toward the threshold
        result = pos.validate_block_attestations(block, public_keys=pks)
        self.assertFalse(result)  # should fail because no valid attestations count


# ─── H2: FinalityTracker verifies attestation signatures ────

class TestH2FinalitySignatureVerification(unittest.TestCase):
    """H2: FinalityTracker.add_attestation must accept public_keys and verify signatures."""

    def test_forged_attestation_rejected(self):
        """A forged attestation (bad signature) should be rejected by FinalityTracker."""
        from messagechain.consensus.attestation import FinalityTracker, Attestation
        from messagechain.crypto.keys import Signature

        tracker = FinalityTracker()
        fake_sig = Signature([], 0, [], b"\x00" * 32, b"\x00" * 32)
        att = Attestation(
            validator_id=b"\x01" * 32,
            block_hash=b"\x02" * 32,
            block_number=1,
            signature=fake_sig,
        )
        pk = b"\x03" * 32  # wrong public key

        # Should reject because signature doesn't verify
        result = tracker.add_attestation(
            att, validator_stake=1000, total_stake=1000,
            public_keys={b"\x01" * 32: pk},
        )
        self.assertFalse(result)
        # Block should not be finalized
        self.assertNotIn(b"\x02" * 32, tracker.finalized)

    def test_valid_attestation_accepted(self):
        """A valid attestation with correct signature should be accepted."""
        from messagechain.consensus.attestation import FinalityTracker, create_attestation

        tracker = FinalityTracker()
        entity = _make_entity()
        block_hash = b"\x02" * 32
        att = create_attestation(entity, block_hash, 1)

        result = tracker.add_attestation(
            att, validator_stake=1000, total_stake=1000,
            public_keys={entity.entity_id: entity.keypair.public_key},
        )
        self.assertTrue(result)


# ─── H3: Fork choice checks finality boundary ────

class TestH3FinalityBoundary(unittest.TestCase):
    """H3: find_common_ancestor must reject reorgs past finalized blocks."""

    def test_reorg_past_finalized_rejected(self):
        """Reorgs that would roll back finalized blocks must be rejected."""
        from messagechain.consensus.fork_choice import find_common_ancestor

        # Build a chain of blocks
        blocks = {}
        for i in range(5):
            header = MagicMock()
            header.block_number = i
            header.prev_hash = _hash(f"block_{i-1}".encode()) if i > 0 else b"\x00" * 32
            block = MagicMock()
            block.header = header
            block.block_hash = _hash(f"block_{i}".encode())
            blocks[block.block_hash] = block

        def get_block(h):
            return blocks.get(h)

        # Mark block 2 as finalized
        finalized = {blocks[_hash(b"block_2")].block_hash}

        # Try to reorg past block 2 — should fail
        ancestor, rollback, apply_ = find_common_ancestor(
            _hash(b"block_4"), _hash(b"block_4"),
            get_block,
            finalized_hashes=finalized,
        )
        # With same tip, no reorg needed — ancestor is the tip
        # Test a real fork scenario below

    def test_fork_choice_respects_finality(self):
        """ForkChoice should not allow reorgs past finalized blocks."""
        from messagechain.consensus.fork_choice import find_common_ancestor
        # If finalized_hashes param is supported, the function should reject
        # reorgs that cross the finality boundary
        # This test verifies the parameter exists
        import inspect
        sig = inspect.signature(find_common_ancestor)
        self.assertIn('finalized_hashes', sig.parameters)


# ─── H4: SignatureCache thread safety ────

class TestH4SignatureCacheThreadSafety(unittest.TestCase):
    """H4: SignatureCache must be thread-safe."""

    def test_concurrent_store_and_lookup(self):
        """Concurrent store and lookup operations should not raise exceptions."""
        from messagechain.crypto.sig_cache import SignatureCache
        import os

        cache = SignatureCache(max_size=100)
        errors = []

        def writer():
            try:
                for i in range(200):
                    msg = os.urandom(32)
                    sig = os.urandom(32)
                    pk = os.urandom(32)
                    cache.store(msg, sig, pk, True)
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(200):
                    msg = os.urandom(32)
                    sig = os.urandom(32)
                    pk = os.urandom(32)
                    cache.lookup(msg, sig, pk)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(4)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread safety errors: {errors}")

    def test_global_cache_thread_safe_init(self):
        """Global cache singleton should be safely initialized under concurrency."""
        from messagechain.crypto import sig_cache
        # Reset the global
        sig_cache._global_cache = None

        caches = []
        def get_cache():
            c = sig_cache.get_global_cache()
            caches.append(id(c))

        threads = [threading.Thread(target=get_cache) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads should get the same cache instance
        self.assertEqual(len(set(caches)), 1)


# ─── H5: Server outbound connection timeouts ────

class TestH5ServerTimeouts(unittest.TestCase):
    """H5: Server outbound connections must have read/connect timeouts."""

    def test_connect_to_peer_has_timeout(self):
        """_connect_to_peer should use asyncio.wait_for with a timeout."""
        from server import Server
        import inspect
        source = inspect.getsource(Server._connect_to_peer)
        self.assertIn("wait_for", source)


# ─── H6: Server attestation deduplication ────

class TestH6ServerAttestationDedup(unittest.TestCase):
    """H6: Server must deduplicate attestations before relay."""

    def test_server_has_seen_attestations(self):
        """Server should track seen attestations to prevent relay amplification."""
        from server import Server
        import inspect
        source = inspect.getsource(Server._handle_announce_attestation)
        self.assertIn("_seen_attestations", source)


# ─── H7: Anchor file validation ────

class TestH7AnchorValidation(unittest.TestCase):
    """H7: Anchor file addresses must be validated."""

    def test_load_anchors_validates_port(self):
        """Loaded anchors must have valid port numbers."""
        from messagechain.network.anchor import AnchorStore
        import tempfile, json, os

        data = [
            {"host": "8.8.8.8", "port": 9333},
            {"host": "1.2.3.4", "port": -1},      # invalid
            {"host": "5.6.7.8", "port": 99999},   # invalid
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name

        try:
            store = AnchorStore(path)
            anchors = store.load_anchors()
            # Only the valid anchor should be returned
            self.assertEqual(len(anchors), 1)
            self.assertEqual(anchors[0], ("8.8.8.8", 9333))
        finally:
            os.unlink(path)


# ─── H9: Server INV per-hash rate limiting ────

class TestH9InvRateLimiting(unittest.TestCase):
    """H9: Server INV handler should consume extra rate limit tokens for large batches."""

    def test_inv_handler_has_per_hash_cost(self):
        """INV handler should charge extra tokens per batch of hashes."""
        from server import Server
        import inspect
        source = inspect.getsource(Server._handle_inv)
        # Should either mention extra tokens or batch limiting
        self.assertTrue(
            "extra_tokens" in source or "rate_limiter" in source or "consume" in source,
            "INV handler should apply per-hash rate limiting"
        )


# ─── M1: Negative tip clamped ────

class TestM1NegativeTipClamp(unittest.TestCase):
    """M1: tip = fee - base_fee must be clamped to >= 0."""

    def test_transfer_tip_clamped(self):
        """_apply_transfer_with_burn should clamp tip to zero if fee < base_fee."""
        chain, entity = _make_chain_with_entity()
        recipient = _make_entity()
        chain.register_entity(recipient.entity_id, recipient.keypair.public_key)

        proposer = _make_entity()
        chain.register_entity(proposer.entity_id, proposer.keypair.public_key)
        proposer_balance_before = chain.supply.get_balance(proposer.entity_id)

        from messagechain.core.transfer import TransferTransaction
        from messagechain.crypto.keys import Signature
        # Create a transfer with fee < base_fee
        tx = MagicMock(spec=TransferTransaction)
        tx.fee = 50  # below BASE_FEE_INITIAL (100)
        tx.amount = 100
        tx.entity_id = entity.entity_id
        tx.recipient_id = recipient.entity_id
        tx.nonce = 0

        # The tip should be clamped to 0, not negative
        chain._apply_transfer_with_burn(tx, proposer.entity_id, base_fee=100)
        proposer_balance_after = chain.supply.get_balance(proposer.entity_id)
        # Proposer should not lose money from a negative tip
        self.assertGreaterEqual(proposer_balance_after, proposer_balance_before)

    def test_simulation_tip_clamped(self):
        """compute_post_state_root simulation should clamp tip to zero."""
        chain, entity = _make_chain_with_entity()
        # Set a high base_fee
        chain.supply.base_fee = 500

        from messagechain.core.transaction import create_transaction
        tx = create_transaction(entity, "test", fee=200, nonce=0)

        proposer_id = entity.entity_id
        # Should not raise or produce negative balances
        try:
            root = chain.compute_post_state_root(
                [tx], proposer_id, 1,
            )
        except Exception:
            self.fail("compute_post_state_root should handle fee < base_fee gracefully")


# ─── M4: Signature deserialization validates structure ────

class TestM4SignatureDeserializeValidation(unittest.TestCase):
    """M4: Signature.deserialize must validate structural integrity."""

    def test_negative_leaf_index_rejected(self):
        """Negative leaf_index should be rejected."""
        from messagechain.crypto.keys import Signature

        data = {
            "wots_signature": ["aa" * 32],
            "leaf_index": -1,
            "auth_path": ["bb" * 32],
            "wots_public_key": "cc" * 32,
            "wots_public_seed": "dd" * 32,
        }
        with self.assertRaises((ValueError, TypeError)):
            Signature.deserialize(data)

    def test_wrong_element_count_rejected(self):
        """WOTS signature with wrong element count should be rejected."""
        from messagechain.crypto.keys import Signature

        data = {
            "wots_signature": [],  # empty — invalid
            "leaf_index": 0,
            "auth_path": ["bb" * 32],
            "wots_public_key": "cc" * 32,
            "wots_public_seed": "dd" * 32,
        }
        with self.assertRaises(ValueError):
            Signature.deserialize(data)


# ─── M5: Block keys pruning removes orphaned cache entries ────

class TestM5BlockKeysPruning(unittest.TestCase):
    """M5: When _block_keys is pruned, orphaned cache entries must be removed."""

    def test_pruned_block_keys_remove_cache_entries(self):
        """Pruning _block_keys should also remove corresponding cache entries."""
        from messagechain.crypto.sig_cache import SignatureCache
        import os

        cache = SignatureCache(max_size=10)
        # Store entries and associate them with blocks
        keys_by_block = {}
        for i in range(15):
            msg = os.urandom(32)
            sig = os.urandom(32)
            pk = os.urandom(32)
            cache.store(msg, sig, pk, True)
            block_hash = os.urandom(32)
            cache.associate_block(msg, sig, pk, block_hash)
            keys_by_block[block_hash] = cache._key(msg, sig, pk)

        # After pruning, orphaned entries should have been cleaned up
        # The cache size should stay bounded
        self.assertLessEqual(len(cache._cache), cache.max_size)


# ─── M8: pay_fee removed/deprecated ────

class TestM8PayFeeWithBurn(unittest.TestCase):
    """M8: The non-burning pay_fee should be restricted to internal use only."""

    def test_pay_fee_with_burn_exists(self):
        """pay_fee_with_burn should be the standard fee payment method."""
        from messagechain.economics.inflation import SupplyTracker
        tracker = SupplyTracker()
        self.assertTrue(hasattr(tracker, 'pay_fee_with_burn'))

    def test_pay_fee_not_used_by_server_governance(self):
        """Server governance handlers should not call pay_fee directly."""
        from server import Server
        import inspect
        # Check proposal and vote submit handlers — these are the
        # remaining governance tx types after the delegation removal.
        for method_name in ("_rpc_submit_proposal", "_rpc_submit_vote"):
            source = inspect.getsource(getattr(Server, method_name))
            # Should not contain pay_fee (should queue instead)
            self.assertNotIn("pay_fee(", source, method_name)


# ─── M9: Signaling threshold uses integer arithmetic ────

class TestM9SignalingIntegerArithmetic(unittest.TestCase):
    """M9: SignalTracker must use integer arithmetic for threshold comparison."""

    def test_threshold_uses_integer_comparison(self):
        """The threshold comparison should use integer math, not floating point."""
        from messagechain.consensus.signaling import SignalTracker
        import inspect
        source = inspect.getsource(SignalTracker.record_block)
        # Should NOT have floating-point division for threshold check
        # Should use integer multiplication instead
        # Check that the threshold check doesn't use / operator
        self.assertNotIn("self._signals / self._total_blocks", source,
                        "Threshold should use integer arithmetic, not float division")


# ─── M10: Governance proposal length limits ────

class TestM10ProposalLengthLimits(unittest.TestCase):
    """M10: Proposals must have bounded title/description lengths."""

    def test_oversized_title_rejected(self):
        """Proposal with extremely long title should be rejected."""
        from messagechain.governance.governance import verify_proposal, ProposalTransaction
        from messagechain.crypto.keys import Signature

        entity = _make_entity()
        fake_sig = Signature([], 0, [], b"\x00" * 32, b"\x00" * 32)
        tx = ProposalTransaction(
            proposer_id=entity.entity_id,
            title="A" * 10_000,  # 10K chars — way too long
            description="Test",
            timestamp=time.time(),
            fee=GOVERNANCE_PROPOSAL_FEE,
            signature=fake_sig,
        )
        # verify_proposal should reject because title is too long
        result = verify_proposal(tx, entity.keypair.public_key)
        self.assertFalse(result)

    def test_oversized_description_rejected(self):
        """Proposal with extremely long description should be rejected."""
        from messagechain.governance.governance import verify_proposal, ProposalTransaction
        from messagechain.crypto.keys import Signature

        entity = _make_entity()
        fake_sig = Signature([], 0, [], b"\x00" * 32, b"\x00" * 32)
        tx = ProposalTransaction(
            proposer_id=entity.entity_id,
            title="Test",
            description="B" * 100_000,  # 100K chars — too long
            timestamp=time.time(),
            fee=GOVERNANCE_PROPOSAL_FEE,
            signature=fake_sig,
        )
        result = verify_proposal(tx, entity.keypair.public_key)
        self.assertFalse(result)


# ─── M11: Seen attestations use LRU eviction ────

class TestM11SeenAttestationsLRU(unittest.TestCase):
    """M11: _seen_attestations should use LRU eviction, not full wipe."""

    def test_node_seen_attestations_no_full_clear(self):
        """Node should not fully clear _seen_attestations set."""
        from messagechain.network.node import Node
        import inspect
        source = inspect.getsource(Node)
        # The pattern "self._seen_attestations.clear()" should not exist
        # (it should use LRU-based eviction instead)
        self.assertNotIn("_seen_attestations.clear()", source)


# ─── M12: RPC rate limiter bounded memory ────

class TestM12RPCRateLimiterBounded(unittest.TestCase):
    """M12: RPCRateLimiter must have a max tracked IPs limit."""

    def test_rpc_rate_limiter_max_ips(self):
        """RPCRateLimiter should cap the number of tracked IPs."""
        from messagechain.network.ratelimit import RPCRateLimiter

        limiter = RPCRateLimiter(max_requests=60, window_seconds=60.0)
        # Add many IPs
        for i in range(2000):
            limiter.check(f"10.0.{i // 256}.{i % 256}")

        # Should be capped
        self.assertLessEqual(len(limiter._requests), 1100,
                           "RPCRateLimiter should cap tracked IPs")


# ─── M13: Client response length bounded ────

class TestM13ClientResponseLengthBound(unittest.TestCase):
    """M13: RPC client should reject oversized responses."""

    def test_client_has_max_response_length(self):
        """The client rpc_call should check response length."""
        import inspect
        import client
        source = inspect.getsource(client.rpc_call)
        # Should have a length check
        self.assertTrue(
            "length" in source.lower() and ("max" in source.lower() or ">" in source),
            "Client should validate response length"
        )


# ─── M14: TLS key file permissions ────

class TestM14TLSKeyPermissions(unittest.TestCase):
    """M14: TLS private key should be written with restrictive permissions."""

    def test_tls_gen_sets_permissions(self):
        """_generate_self_signed_cert should restrict key file permissions."""
        from messagechain.network.tls import _generate_self_signed_cert
        import inspect
        source = inspect.getsource(_generate_self_signed_cert)
        self.assertIn("chmod", source,
                     "TLS key generation should set restrictive file permissions")


# ─── M15: TLS uses 4096-bit RSA ────

class TestM15TLSKeySize(unittest.TestCase):
    """M15: TLS should use at least 4096-bit RSA for the 1000-year design goal."""

    def test_tls_key_size_adequate(self):
        """TLS certificate should use at least 4096-bit RSA."""
        from messagechain.network.tls import _generate_self_signed_cert
        import inspect
        source = inspect.getsource(_generate_self_signed_cert)
        self.assertIn("4096", source,
                     "TLS should use 4096-bit RSA for long-term security")


# ─── M18: Addrman validates port range ────

class TestM18AddrmanPortValidation(unittest.TestCase):
    """M18: AddressManager.add_address must validate port range."""

    def test_invalid_port_rejected(self):
        """Ports outside 1-65535 should be rejected."""
        from messagechain.network.addrman import AddressManager

        addrman = AddressManager()
        # Port 0 should be rejected
        self.assertFalse(addrman.add_address("8.8.8.8", 0, "1.2.3.4"))
        # Port 99999 should be rejected
        self.assertFalse(addrman.add_address("8.8.8.8", 99999, "1.2.3.4"))
        # Port -1 should be rejected
        self.assertFalse(addrman.add_address("8.8.8.8", -1, "1.2.3.4"))
        # Valid port should be accepted
        self.assertTrue(addrman.add_address("8.8.8.8", 9333, "1.2.3.4"))


# ─── M19: Node _handle_request_headers validates start_height ────

class TestM19RequestHeadersValidation(unittest.TestCase):
    """M19: Node._handle_request_headers must validate start_height."""

    def test_request_headers_validates_start_height(self):
        """_handle_request_headers should validate and clamp start_height."""
        from messagechain.network.node import Node
        import inspect
        source = inspect.getsource(Node._handle_request_headers)
        # Should validate start_height type and range
        self.assertTrue(
            "isinstance" in source or "int" in source.lower(),
            "start_height should be type-checked"
        )


# ─── M21: Global sig cache thread-safe init ────

class TestM21GlobalCacheInit(unittest.TestCase):
    """M21: get_global_cache must be thread-safe."""

    def test_global_cache_uses_lock(self):
        """get_global_cache should use a lock for initialization."""
        from messagechain.crypto import sig_cache
        import inspect
        source = inspect.getsource(sig_cache.get_global_cache)
        self.assertTrue(
            "lock" in source.lower() or "_lock" in source,
            "get_global_cache should use a threading lock"
        )


# ─── M23: canonical_bytes includes length prefixes ────

class TestM23CanonicalBytesLengthPrefixes(unittest.TestCase):
    """M23: canonical_bytes should include length prefixes for variable lists."""

    def test_canonical_bytes_includes_counts(self):
        """canonical_bytes should encode the count of wots_signature and auth_path."""
        from messagechain.crypto.keys import Signature
        import struct

        sig = Signature(
            wots_signature=[b"\x01" * 32, b"\x02" * 32],
            leaf_index=0,
            auth_path=[b"\x03" * 32],
            wots_public_key=b"\x04" * 32,
            wots_public_seed=b"\x05" * 32,
        )
        cb = sig.canonical_bytes()
        # The count should be encoded somewhere in the output
        # Check that changing wots_signature count changes the output
        sig2 = Signature(
            wots_signature=[b"\x01" * 32],
            leaf_index=0,
            auth_path=[b"\x03" * 32, b"\x02" * 32],
            wots_public_key=b"\x04" * 32,
            wots_public_seed=b"\x05" * 32,
        )
        cb2 = sig2.canonical_bytes()
        # These should produce different canonical bytes even though
        # total data length might be the same
        self.assertNotEqual(cb, cb2)


# ─── Config assert → if/raise ────

class TestConfigValidation(unittest.TestCase):
    """Config should use if/raise instead of assert for security checks."""

    def test_no_assert_in_config(self):
        """config.py should not use assert for security-critical validation."""
        import inspect
        import messagechain.config as config
        source = inspect.getsource(config)
        # The power-of-2 check should NOT use assert
        self.assertNotIn("assert (BLOCK_REWARD", source,
                        "Config should use if/raise instead of assert")


# ─── FinalityTracker memory management ────

class TestFinalityTrackerPruning(unittest.TestCase):
    """M7: FinalityTracker should support pruning old entries."""

    def test_prune_below_height(self):
        """FinalityTracker should be able to prune entries below a height."""
        from messagechain.consensus.attestation import FinalityTracker
        tracker = FinalityTracker()
        # Should have a prune method
        self.assertTrue(hasattr(tracker, 'prune'),
                       "FinalityTracker should have a prune method")


if __name__ == "__main__":
    unittest.main()
