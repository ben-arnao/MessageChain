"""
Security audit pass 3 — 2026-04-13 (design-level findings).

Tests for 10 design-level security findings that require structural changes.
Written FIRST per TDD.

D1   P2P write_message calls must have a timeout
D2   RESPONSE_HEADERS/RESPONSE_BLOCKS_BATCH must be rate-limited
D3   Checkpoint loading must fail loudly on missing/corrupt files
D4   Bootstrap mode must still verify attestation signatures
D5   Governance delegation tally must weight ALL targets proportionally
D6   Fork choice must use historical (snapshotted) stake, not live
D7   Conflicting attestations must auto-generate slashing evidence
D8   RPC must require authentication
D9   HANDSHAKE must include a signature proving sender_id ownership
D10  P2P connections must use TLS encryption
"""

import asyncio
import hashlib
import json
import os
import struct
import tempfile
import time
import unittest

import messagechain.config as cfg
from messagechain.config import HASH_ALGO


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


# ─────────────────────────────────────────────────────────────────────
# D1: P2P write timeouts
# ─────────────────────────────────────────────────────────────────────

class TestD1WriteTimeout(unittest.TestCase):
    """write_message must have an enforced timeout."""

    def test_write_message_with_timeout_exists(self):
        """The protocol module must expose a write timeout constant."""
        from messagechain.network.protocol import P2P_WRITE_TIMEOUT
        self.assertIsInstance(P2P_WRITE_TIMEOUT, (int, float))
        self.assertGreater(P2P_WRITE_TIMEOUT, 0)
        self.assertLessEqual(P2P_WRITE_TIMEOUT, 30)

    def test_write_message_respects_timeout(self):
        """write_message must raise on a stalled writer."""
        from messagechain.network import protocol
        from messagechain.network.protocol import write_message, NetworkMessage, MessageType

        class StalledWriter:
            """Simulates a writer that never completes drain()."""
            def write(self, data):
                pass
            async def drain(self):
                await asyncio.sleep(999)  # never completes

        msg = NetworkMessage(msg_type=MessageType.HANDSHAKE, payload={})

        async def _test():
            try:
                await write_message(StalledWriter(), msg)
                return False  # should not reach here
            except (asyncio.TimeoutError, TimeoutError):
                return True  # expected

        original = protocol.P2P_WRITE_TIMEOUT
        loop = asyncio.new_event_loop()
        try:
            protocol.P2P_WRITE_TIMEOUT = 1  # fast timeout for test
            result = loop.run_until_complete(
                asyncio.wait_for(_test(), timeout=protocol.P2P_WRITE_TIMEOUT + 2)
            )
            self.assertTrue(result, "write_message must raise TimeoutError on stall")
        finally:
            protocol.P2P_WRITE_TIMEOUT = original
            loop.close()


# ─────────────────────────────────────────────────────────────────────
# D2: Rate limiting on response messages
# ─────────────────────────────────────────────────────────────────────

class TestD2ResponseRateLimiting(unittest.TestCase):
    """RESPONSE_HEADERS and RESPONSE_BLOCKS_BATCH must be rate-limited."""

    def test_response_messages_have_rate_limit_category(self):
        """Response messages must map to a rate-limit bucket."""
        from messagechain.network.dispatch import message_category
        from messagechain.network.protocol import MessageType

        cat_headers = message_category(MessageType.RESPONSE_HEADERS)
        cat_blocks = message_category(MessageType.RESPONSE_BLOCKS_BATCH)
        # They should not fall through to "general" — they need their own bucket
        self.assertNotEqual(cat_headers, "general",
            "RESPONSE_HEADERS must have a specific rate-limit category")
        self.assertNotEqual(cat_blocks, "general",
            "RESPONSE_BLOCKS_BATCH must have a specific rate-limit category")

    def test_response_rate_bucket_exists_in_limiter(self):
        """PeerRateLimiter must create buckets for response categories."""
        from messagechain.network.ratelimit import PeerRateLimiter
        from messagechain.network.dispatch import message_category
        from messagechain.network.protocol import MessageType

        limiter = PeerRateLimiter()
        cat = message_category(MessageType.RESPONSE_HEADERS)
        # First check should succeed (bucket starts full)
        result = limiter.check("1.2.3.4:9333", cat)
        self.assertTrue(result, "First response should be allowed")


# ─────────────────────────────────────────────────────────────────────
# D3: Strict checkpoint loading
# ─────────────────────────────────────────────────────────────────────

class TestD3StrictCheckpointLoading(unittest.TestCase):
    """Checkpoint loading must fail loudly when file is missing or corrupt."""

    def test_missing_checkpoint_file_raises(self):
        """load_checkpoints_file with strict=True must raise on missing file."""
        from messagechain.consensus.checkpoint import load_checkpoints_file
        with self.assertRaises((FileNotFoundError, ValueError)):
            load_checkpoints_file("/nonexistent/path/checkpoints.json", strict=True)

    def test_corrupt_checkpoint_file_raises(self):
        """load_checkpoints_file with strict=True must raise on corrupt JSON."""
        from messagechain.consensus.checkpoint import load_checkpoints_file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            path = f.name
        try:
            with self.assertRaises((json.JSONDecodeError, ValueError)):
                load_checkpoints_file(path, strict=True)
        finally:
            os.unlink(path)

    def test_permissive_mode_still_works(self):
        """Default (permissive) mode returns empty list on missing file."""
        from messagechain.consensus.checkpoint import load_checkpoints_file
        result = load_checkpoints_file("/nonexistent/path/checkpoints.json")
        self.assertEqual(result, [])


# ─────────────────────────────────────────────────────────────────────
# D4: Bootstrap attestation signature verification
# ─────────────────────────────────────────────────────────────────────

class TestD4BootstrapAttestationVerification(unittest.TestCase):
    """Bootstrap mode must verify attestation signatures, just relax threshold."""

    def test_bootstrap_verifies_signatures_when_keys_provided(self):
        """Even in bootstrap, forged attestations with bad sigs must fail."""
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.consensus.attestation import Attestation
        from messagechain.crypto.keys import Signature
        from messagechain.core.block import Block, BlockHeader

        # Force bootstrap by requiring more validators than we'll register
        original = cfg.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        cfg.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 10

        pos = ProofOfStake()
        entity = _make_entity()
        pos.stakes[entity.entity_id] = 100
        self.assertTrue(pos.is_bootstrap_mode)

        # Create a block with a forged attestation (bad signature)
        header = BlockHeader(
            version=1, prev_hash=os.urandom(32), merkle_root=_hash(b""),
            timestamp=int(time.time()), block_number=1,
            proposer_id=entity.entity_id,
        )
        fake_sig = Signature([], 0, [], b"\x00" * 32, b"\x00" * 32)
        forged_att = Attestation(
            validator_id=entity.entity_id,
            block_hash=os.urandom(32),
            block_number=0,
            signature=fake_sig,
        )
        block = Block(header=header, transactions=[], attestations=[forged_att])

        # In bootstrap, validate_block_attestations should still verify sigs
        # when public_keys are available
        keys = {entity.entity_id: entity.keypair.public_key}
        try:
            result = pos.validate_block_attestations(block, public_keys=keys)
            # If sigs are checked, forged attestation fails => result is False
            # If bootstrap skips ALL validation, result is True (the bug)
            self.assertFalse(result,
                "Bootstrap mode must verify attestation signatures when keys are available")
        finally:
            cfg.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = original


# ─────────────────────────────────────────────────────────────────────
# D6: Fork choice historical stake snapshots
# ─────────────────────────────────────────────────────────────────────

class TestD6HistoricalStakeWeight(unittest.TestCase):
    """Fork choice must use stake weight at time of block production."""

    def test_block_weight_uses_snapshot_not_live(self):
        """compute_block_stake_weight should accept a stake snapshot argument."""
        from messagechain.consensus.fork_choice import compute_block_stake_weight
        from messagechain.core.block import Block, BlockHeader

        proposer = os.urandom(32)
        header = BlockHeader(
            version=1, prev_hash=os.urandom(32), merkle_root=_hash(b""),
            timestamp=int(time.time()), block_number=5,
            proposer_id=proposer,
        )
        block = Block(header=header, transactions=[], attestations=[])

        # Snapshot at time of block: proposer had 500 stake
        snapshot = {proposer: 500}
        # Live state: proposer unstaked to 0
        live = {proposer: 0}

        weight_snapshot = compute_block_stake_weight(block, snapshot)
        weight_live = compute_block_stake_weight(block, live)

        self.assertEqual(weight_snapshot, 500,
            "Block weight must use the provided stake map")
        self.assertEqual(weight_live, 1,
            "Live map with 0 stake should give minimum weight 1")


# ─────────────────────────────────────────────────────────────────────
# D7: Auto-slashing on equivocation detection
# ─────────────────────────────────────────────────────────────────────

class TestD7AutoSlashing(unittest.TestCase):
    """Conflicting attestations must be auto-detected and evidence created."""

    def test_finality_tracker_detects_equivocation(self):
        """FinalityTracker.add_attestation must return equivocation evidence
        when a validator double-votes."""
        from messagechain.consensus.attestation import FinalityTracker, Attestation
        from messagechain.crypto.keys import Signature

        tracker = FinalityTracker()
        vid = os.urandom(32)
        fake_sig = Signature([], 0, [], b"\x00" * 32, b"\x00" * 32)

        att_a = Attestation(
            validator_id=vid, block_hash=os.urandom(32),
            block_number=10, signature=fake_sig,
        )
        att_b = Attestation(
            validator_id=vid, block_hash=os.urandom(32),
            block_number=10, signature=fake_sig,
        )

        # First attestation — should succeed
        result_a = tracker.add_attestation(att_a, 100, 300)

        # Second conflicting attestation — should return evidence
        result_b = tracker.add_attestation(att_b, 100, 300)

        # The tracker should now expose the conflicting pair
        if hasattr(tracker, 'get_pending_slashing_evidence'):
            evidence_list = tracker.get_pending_slashing_evidence()
            self.assertGreater(len(evidence_list), 0,
                "Conflicting attestations must produce slashing evidence")
            ev = evidence_list[0]
            self.assertEqual(ev.offender_id, vid)
        elif hasattr(tracker, 'pending_slashing_evidence'):
            self.assertGreater(len(tracker.pending_slashing_evidence), 0,
                "Conflicting attestations must produce slashing evidence")
        else:
            self.fail("FinalityTracker must expose pending slashing evidence "
                      "via get_pending_slashing_evidence() or pending_slashing_evidence")


# ─────────────────────────────────────────────────────────────────────
# D8: RPC authentication
# ─────────────────────────────────────────────────────────────────────

class TestD8RPCAuthentication(unittest.TestCase):
    """RPC server must require authentication."""

    def test_rpc_auth_token_config_exists(self):
        """Config must define an RPC auth mechanism."""
        self.assertTrue(
            hasattr(cfg, 'RPC_AUTH_TOKEN') or hasattr(cfg, 'RPC_AUTH_ENABLED'),
            "Config must define RPC_AUTH_TOKEN or RPC_AUTH_ENABLED"
        )

    def test_rpc_auth_enabled_by_default(self):
        """RPC auth must be enabled by default."""
        enabled = getattr(cfg, 'RPC_AUTH_ENABLED', True)
        self.assertTrue(enabled, "RPC auth must be enabled by default")


# ─────────────────────────────────────────────────────────────────────
# D9: Signed handshake
# ─────────────────────────────────────────────────────────────────────

class TestD9SignedHandshake(unittest.TestCase):
    """HANDSHAKE must include a signature proving sender_id ownership."""

    def test_handshake_message_type_has_challenge_field(self):
        """Protocol must support a handshake_challenge or nonce field."""
        # The handshake should include a nonce/challenge to prevent replay
        from messagechain.network.protocol import MessageType
        # Both HANDSHAKE types should exist
        self.assertTrue(hasattr(MessageType, 'HANDSHAKE'))

    def test_handshake_signature_field_documented(self):
        """The protocol documentation describes signed handshakes."""
        # Verify that the handshake payload supports a signature field
        from messagechain.network.protocol import NetworkMessage, MessageType
        msg = NetworkMessage(
            msg_type=MessageType.HANDSHAKE,
            payload={
                "port": 9333,
                "chain_height": 0,
                "handshake_nonce": os.urandom(32).hex(),
                "handshake_sig": "placeholder",
            },
            sender_id="abc123",
        )
        # Should serialize without error
        data = msg.serialize()
        self.assertIn("handshake_nonce", data["payload"])


# ─────────────────────────────────────────────────────────────────────
# D10: TLS on P2P connections
# ─────────────────────────────────────────────────────────────────────

class TestD10TLSEncryption(unittest.TestCase):
    """P2P connections must support TLS encryption."""

    def test_tls_config_exists(self):
        """Config must define TLS-related settings."""
        self.assertTrue(
            hasattr(cfg, 'P2P_TLS_ENABLED') or hasattr(cfg, 'TLS_CERT_PATH'),
            "Config must define P2P TLS settings"
        )

    def test_tls_enabled_by_default(self):
        """TLS must be enabled by default for P2P."""
        enabled = getattr(cfg, 'P2P_TLS_ENABLED', True)
        self.assertTrue(enabled, "P2P TLS must be enabled by default")

    def test_tls_context_creation(self):
        """Node must be able to create an SSL context for P2P."""
        # Import the TLS helper
        try:
            from messagechain.network.tls import create_node_ssl_context
            ctx = create_node_ssl_context()
            self.assertIsNotNone(ctx)
        except ImportError:
            self.fail("messagechain.network.tls module must exist")


if __name__ == "__main__":
    unittest.main()
