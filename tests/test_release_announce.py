"""
Tests for ReleaseAnnounceTransaction.

A threshold multi-sig'd release manifest broadcast on-chain to signal
"new node/validator release available."  No auto-apply: this iteration
only covers the tx type, signature verification, block wiring, and
the monotonic write into `Blockchain.latest_release_manifest`.  Nodes
are expected to surface the manifest to operators out of band; the
protocol never runs or fetches the announced binaries itself.

The signing set is a hardcoded tuple of WOTS+ Merkle-root public keys
in `config.RELEASE_KEY_ROOTS`.  Threshold is 3-of-5 (RELEASE_THRESHOLD)
once the real roots are seeded via a hard fork; the default is an
empty tuple so this iteration is inert on mainnet until seeding.

Test setup creates 5 Entity fixtures at module import and monkey-
patches them into config.RELEASE_KEY_ROOTS during setUp — the same
pattern other config-mutating tests use (see test_authority_key.py).
"""

import time
import unittest

from messagechain import config
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.core.release_announce import (
    ReleaseAnnounceTransaction,
    create_release_announce_transaction,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(
        seed + b"\x00" * (32 - len(seed)), tree_height=height,
    )


# Build the signer fixtures once — WOTS+ keygen at h=6 is cheap (~ms)
# but reused across many tests, so hoist it to module level.
_SIGNERS = [
    _entity(b"release-signer-%d" % i) for i in range(5)
]
_SIGNER_ROOTS = tuple(s.public_key for s in _SIGNERS)


def _make_binary_hashes():
    """Canonical binary_hashes map used across the happy-path tests."""
    return {
        "linux-x86_64": _hash(b"linux-bin-1.0.0"),
        "darwin-arm64": _hash(b"darwin-bin-1.0.0"),
    }


class _Base(unittest.TestCase):
    """Common fixture: install RELEASE_KEY_ROOTS for the duration of the test."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6
        self._orig_roots = config.RELEASE_KEY_ROOTS
        config.RELEASE_KEY_ROOTS = _SIGNER_ROOTS
        self._orig_threshold = config.RELEASE_THRESHOLD
        config.RELEASE_THRESHOLD = 3

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height
        config.RELEASE_KEY_ROOTS = self._orig_roots
        config.RELEASE_THRESHOLD = self._orig_threshold


class TestReleaseAnnounceRoundtrip(_Base):

    def test_roundtrip_to_bytes_from_bytes(self):
        """to_bytes → from_bytes preserves every field and tx_hash."""
        tx = create_release_announce_transaction(
            version="1.2.3",
            binary_hashes=_make_binary_hashes(),
            min_activation_height=100,
            release_notes_uri="https://releases.messagechain.org/1.2.3",
            severity=1,
            nonce=b"\x11" * 16,
            signers=[(0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2])],
        )
        blob = tx.to_bytes()
        restored = ReleaseAnnounceTransaction.from_bytes(blob)
        self.assertEqual(restored.version, tx.version)
        self.assertEqual(restored.binary_hashes, tx.binary_hashes)
        self.assertEqual(restored.min_activation_height, tx.min_activation_height)
        self.assertEqual(restored.release_notes_uri, tx.release_notes_uri)
        self.assertEqual(restored.severity, tx.severity)
        self.assertEqual(restored.nonce, tx.nonce)
        self.assertEqual(restored.signer_indices, tx.signer_indices)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        # Signatures survive the round-trip too.
        self.assertEqual(len(restored.signatures), len(tx.signatures))
        for a, b in zip(restored.signatures, tx.signatures):
            self.assertEqual(a.canonical_bytes(), b.canonical_bytes())

    def test_roundtrip_none_min_activation_height(self):
        """Optional min_activation_height=None survives serialization."""
        tx = create_release_announce_transaction(
            version="2.0.0",
            binary_hashes={"linux-x86_64": b"\x42" * 32},
            min_activation_height=None,
            release_notes_uri="",
            severity=0,
            nonce=b"\x00" * 16,
            signers=[(0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2])],
        )
        blob = tx.to_bytes()
        restored = ReleaseAnnounceTransaction.from_bytes(blob)
        self.assertIsNone(restored.min_activation_height)


class TestReleaseAnnounceVerify(_Base):

    def _build(self, signer_specs=None, **overrides):
        base = dict(
            version="1.0.0",
            binary_hashes=_make_binary_hashes(),
            min_activation_height=None,
            release_notes_uri="https://releases.messagechain.org/1.0.0",
            severity=0,
            nonce=b"\x01" * 16,
            signers=signer_specs or [
                (0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2]),
            ],
        )
        base.update(overrides)
        return create_release_announce_transaction(**base)

    def test_threshold_met_verifies(self):
        tx = self._build()
        self.assertTrue(tx.verify())

    def test_threshold_not_met_fails(self):
        """Below RELEASE_THRESHOLD (= 3) signatures must fail."""
        tx = self._build(signer_specs=[(0, _SIGNERS[0]), (1, _SIGNERS[1])])
        self.assertFalse(tx.verify())

    def test_signer_index_out_of_range_fails(self):
        """An index >= len(RELEASE_KEY_ROOTS) must cause verify to fail."""
        tx = self._build(signer_specs=[
            (0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2]),
        ])
        # Swap one of the indices to an out-of-range value post-construction.
        tx.signer_indices[2] = 99
        tx.tx_hash = tx._compute_hash()
        self.assertFalse(tx.verify())

    def test_duplicate_signer_indices_do_not_count(self):
        """Same signer submitting twice must not count toward threshold."""
        tx = self._build(signer_specs=[
            (0, _SIGNERS[0]), (0, _SIGNERS[0]), (0, _SIGNERS[0]),
        ])
        # Three signatures are present but all from index 0 — unique count
        # is 1, below threshold of 3.
        self.assertFalse(tx.verify())

    def test_tampered_version_fails(self):
        tx = self._build()
        tx.version = "9.9.9"
        # Do NOT recompute tx_hash here — a verifier recomputes from the
        # fields and compares signatures; tampering the field without
        # re-signing must fail.
        self.assertFalse(tx.verify())

    def test_tampered_binary_hash_fails(self):
        tx = self._build()
        new_hashes = dict(tx.binary_hashes)
        next(iter(new_hashes))  # any key
        for k in list(new_hashes):
            new_hashes[k] = b"\xff" * 32
            break
        tx.binary_hashes = new_hashes
        self.assertFalse(tx.verify())

    def test_tampered_nonce_fails(self):
        tx = self._build()
        tx.nonce = b"\xaa" * 16
        self.assertFalse(tx.verify())

    def test_domain_separation_tag(self):
        """Signing a different domain tag must not verify under release_announce."""
        tx = self._build()
        # Hand-roll a signable blob with a DIFFERENT tag and sign THAT.
        # Rebuild the tx with those signatures — verify must fail because
        # its own `_signable_data()` uses the correct "release_announce"
        # tag, so the signatures won't verify.
        import struct
        from messagechain.config import CHAIN_ID, SIG_VERSION_CURRENT
        evil_data = (
            CHAIN_ID
            + b"some_other_domain"
            + struct.pack(">B", SIG_VERSION_CURRENT)
            + tx._signable_body()
        )
        msg_hash = _hash(evil_data)
        evil_sigs = [s.keypair.sign(msg_hash) for s in _SIGNERS[:3]]
        tx.signatures = evil_sigs
        self.assertFalse(tx.verify())

    def test_wrong_sig_version_fails(self):
        tx = self._build()
        # Poke an unaccepted sig_version into one of the signatures.
        tx.signatures[0].sig_version = 99
        self.assertFalse(tx.verify())


class TestReleaseAnnounceBlockWiring(_Base):
    """Integration: a block carrying a valid manifest updates chain state."""

    def _register_proposer(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(
            entity.entity_id, entity.public_key, proof,
        )

    def test_valid_manifest_sets_latest_release_manifest(self):
        """add_block(valid) → blockchain.latest_release_manifest is populated."""
        chain = Blockchain()
        proposer = _entity(b"proposer")
        self._register_proposer(chain, proposer)

        # Sanity: starts None.
        self.assertIsNone(chain.latest_release_manifest)

        tx = create_release_announce_transaction(
            version="1.0.0",
            binary_hashes=_make_binary_hashes(),
            min_activation_height=None,
            release_notes_uri="",
            severity=0,
            nonce=b"\x02" * 16,
            signers=[(0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2])],
        )
        # Apply directly via the authority-tx dispatcher so we don't need
        # to pull in the full block-validation pipeline (header sig,
        # merkle, state root).  This exercises the branch we added.
        chain._apply_authority_tx(tx, proposer_id=proposer.entity_id, base_fee=0)
        self.assertIsNotNone(chain.latest_release_manifest)
        self.assertEqual(chain.latest_release_manifest.version, "1.0.0")

    def test_invalid_manifest_does_not_update_state(self):
        """Apply path skips an invalid manifest; `latest_release_manifest` stays None."""
        chain = Blockchain()
        # Build a tx then mutate it so verify() returns False.
        tx = create_release_announce_transaction(
            version="1.0.0",
            binary_hashes=_make_binary_hashes(),
            min_activation_height=None,
            release_notes_uri="",
            severity=0,
            nonce=b"\x03" * 16,
            signers=[(0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2])],
        )
        tx.version = "0.0.1"  # tamper without re-signing
        self.assertFalse(tx.verify())
        # Fire the apply path — must be a no-op.
        chain._apply_authority_tx(tx, proposer_id=b"\x00" * 32, base_fee=0)
        self.assertIsNone(chain.latest_release_manifest)

    def test_monotonic_guard_older_does_not_overwrite_newer(self):
        """A release with a lexicographically smaller version must not clobber."""
        chain = Blockchain()
        newer = create_release_announce_transaction(
            version="2.0.0",
            binary_hashes=_make_binary_hashes(),
            min_activation_height=None,
            release_notes_uri="",
            severity=0,
            nonce=b"\x04" * 16,
            signers=[(0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2])],
        )
        chain._apply_authority_tx(newer, proposer_id=b"\x00" * 32, base_fee=0)
        self.assertEqual(chain.latest_release_manifest.version, "2.0.0")

        older = create_release_announce_transaction(
            version="1.0.0",
            binary_hashes=_make_binary_hashes(),
            min_activation_height=None,
            release_notes_uri="",
            severity=0,
            nonce=b"\x05" * 16,
            signers=[(0, _SIGNERS[3]), (1, _SIGNERS[4]), (2, _SIGNERS[2])],
        )
        chain._apply_authority_tx(older, proposer_id=b"\x00" * 32, base_fee=0)
        # Newer stays put.
        self.assertEqual(chain.latest_release_manifest.version, "2.0.0")

    def test_block_deserialization_dispatches_release_announce(self):
        """Block.from_bytes recognizes the ReleaseAnnounce authority kind."""
        tx = create_release_announce_transaction(
            version="1.0.0",
            binary_hashes=_make_binary_hashes(),
            min_activation_height=None,
            release_notes_uri="",
            severity=0,
            nonce=b"\x06" * 16,
            signers=[(0, _SIGNERS[0]), (1, _SIGNERS[1]), (2, _SIGNERS[2])],
        )
        proposer = _entity(b"proposer")

        # Build a minimal block whose tx_hash/merkle_root/block_hash are
        # consistent — we only need to prove the binary round-trip for
        # the authority-tx slot.  Use the existing helpers so any
        # future changes to the block wire format are picked up
        # automatically by this test.
        from messagechain.core.block import (
            canonical_block_tx_hashes, compute_merkle_root,
        )
        block = Block(
            header=BlockHeader(
                version=1,
                block_number=0,
                prev_hash=b"\x00" * 32,
                merkle_root=b"\x00" * 32,
                timestamp=time.time(),
                proposer_id=proposer.entity_id,
            ),
            transactions=[],
            authority_txs=[tx],
        )
        block.header.merkle_root = compute_merkle_root(
            canonical_block_tx_hashes(block),
        )
        block.block_hash = block._compute_hash()

        blob = block.to_bytes()
        restored = Block.from_bytes(blob)
        self.assertEqual(len(restored.authority_txs), 1)
        self.assertIsInstance(
            restored.authority_txs[0], ReleaseAnnounceTransaction,
        )
        self.assertEqual(restored.authority_txs[0].version, "1.0.0")


if __name__ == "__main__":
    unittest.main()
