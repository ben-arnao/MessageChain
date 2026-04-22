"""Tests for iteration 3f: signed custody proofs.

Closes the front-running / prover-id-swap vulnerability identified in
the post-3e audit.  Pre-3f, a gossip eavesdropper could:

    1. Read a valid CustodyProof from Alice in the gossip layer.
    2. Modify the in-flight bytes to replace `prover_id` with the
       attacker's ID.
    3. Re-submit the altered proof.  All Merkle math still verifies
       (the path doesn't depend on prover_id).  Reward flows to the
       attacker's prover_id instead of Alice's.

The fix binds the proof cryptographically to a specific keyholder:

    * CustodyProof gains `public_key` + `signature` fields.
    * prover_id MUST equal derive_entity_id(public_key).
    * The signature must verify over the signing material
      (everything except the signature itself) using the embedded
      public_key.

With these bindings an attacker cannot modify prover_id without also
re-signing — which requires the original prover's private key.  An
attacker generating their own keypair becomes a separate valid
submitter competing fairly in the deterministic lottery from 3e; they
have not stolen anyone's submission.

Secondary defense: the signing material includes `target_block_hash`,
so a proof from epoch N cannot be replayed in any epoch that
challenges a different historical block (which is almost all of
them).
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import HASH_ALGO
from messagechain.consensus.archive_challenge import (
    CustodyProof,
    build_custody_proof,
    verify_custody_proof,
)
from messagechain.identity.identity import Entity, derive_entity_id


# Module-scoped entity pool — WOTS+ key generation is the expensive
# setup, so create a few entities once and reuse across tests via
# leaf-index allocation.
_ENTITY_POOL: list[Entity] = []


def _entity(i: int) -> Entity:
    while len(_ENTITY_POOL) <= i:
        seed = f"signed-proofs-{len(_ENTITY_POOL)}".encode().ljust(32, b"\x00")
        _ENTITY_POOL.append(Entity.create(seed))
    return _ENTITY_POOL[i]


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _mini_block(txs: list[bytes], block_number: int = 1) -> dict:
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": _h(header_bytes),
    }


def _make_signed(entity: Entity, block: dict, tx_index: int = 0):
    return build_custody_proof(
        entity=entity,
        target_height=block["block_number"],
        target_block_hash=block["block_hash"],
        header_bytes=block["header_bytes"],
        merkle_root=block["merkle_root"],
        tx_index=tx_index,
        tx_bytes=block["tx_bytes_list"][tx_index],
        all_tx_hashes=block["tx_hashes"],
    )


# ---------------------------------------------------------------------------
# 1. Signed proof verifies; prover_id is derived from public_key.
# ---------------------------------------------------------------------------


class TestSignedProofHappyPath(unittest.TestCase):
    def test_prover_id_derived_from_pubkey(self):
        """After iter 3f, build_custody_proof takes an Entity and
        produces a proof where prover_id = derive_entity_id(pubkey).
        The old arbitrary-bytes prover_id is gone."""
        block = _mini_block([b"tx-0" * 10], 5)
        alice = _entity(0)
        proof = _make_signed(alice, block)
        self.assertEqual(
            proof.prover_id, derive_entity_id(alice.keypair.public_key),
        )

    def test_valid_signed_proof_verifies(self):
        block = _mini_block([b"tx-0" * 10, b"tx-1" * 10], 7)
        alice = _entity(1)
        proof = _make_signed(alice, block, tx_index=1)
        ok, reason = verify_custody_proof(
            proof, expected_block_hash=block["block_hash"],
        )
        self.assertTrue(ok, f"valid signed proof rejected: {reason}")

    def test_public_key_is_embedded(self):
        """The verifier doesn't need to look the pubkey up from chain
        state — it's carried in the proof itself.  This is what lets
        non-validator hobbyist archivists participate without prior
        on-chain registration."""
        block = _mini_block([b"tx-0" * 10], 5)
        alice = _entity(2)
        proof = _make_signed(alice, block)
        self.assertTrue(hasattr(proof, "public_key"))
        self.assertEqual(proof.public_key, alice.keypair.public_key)


# ---------------------------------------------------------------------------
# 2. Swap-prover-id attack is closed.
# ---------------------------------------------------------------------------


class TestProverIdSwapClosed(unittest.TestCase):
    def test_swapped_prover_id_rejected(self):
        """Eve intercepts Alice's proof in gossip and swaps
        prover_id to her own.  Merkle math still verifies.  Signature
        does NOT verify against the new prover_id -- rejected."""
        block = _mini_block([b"tx-0" * 10, b"tx-1" * 10], 5)
        alice = _entity(3)
        eve = _entity(4)
        proof = _make_signed(alice, block)
        # Tamper: swap prover_id to Eve's ID.  Leave signature + pubkey
        # untouched (the stolen-proof scenario).
        proof.prover_id = derive_entity_id(eve.keypair.public_key)
        ok, _ = verify_custody_proof(
            proof, expected_block_hash=block["block_hash"],
        )
        self.assertFalse(
            ok, "swap-prover-id attack must be rejected at verification",
        )

    def test_pubkey_mismatch_rejected(self):
        """If prover_id doesn't equal derive_entity_id(public_key), the
        proof is malformed — attacker can't hide by claiming a
        non-derived prover_id."""
        block = _mini_block([b"tx-0" * 10], 5)
        alice = _entity(5)
        proof = _make_signed(alice, block)
        # Tamper prover_id to a value that doesn't match pubkey.
        proof.prover_id = b"\xFF" * 32
        ok, _ = verify_custody_proof(
            proof, expected_block_hash=block["block_hash"],
        )
        self.assertFalse(ok)

    def test_swap_pubkey_without_resigning_rejected(self):
        """Eve swaps BOTH prover_id and pubkey to her own, leaving the
        signature from Alice.  Signature now fails to verify against
        Eve's pubkey — rejected.  (For Eve to submit validly, she'd
        need to resign with her own key, which makes her a legitimate
        co-submitter, not a thief.)"""
        block = _mini_block([b"tx-0" * 10], 5)
        alice = _entity(6)
        eve = _entity(7)
        proof = _make_signed(alice, block)
        proof.prover_id = derive_entity_id(eve.keypair.public_key)
        proof.public_key = eve.keypair.public_key
        # Leave Alice's signature in place.
        ok, _ = verify_custody_proof(
            proof, expected_block_hash=block["block_hash"],
        )
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# 3. Tamper-resistance on every signed field.
# ---------------------------------------------------------------------------


class TestTamperResistance(unittest.TestCase):
    def test_tampered_tx_index_rejected(self):
        """Modifying tx_index breaks the signature (signing material
        includes tx_index).  This is defense-in-depth: even if an
        attacker found a way to forge Merkle math, the signature is
        a second lock."""
        block = _mini_block(
            [b"tx-0" * 10, b"tx-1" * 10, b"tx-2" * 10], 5,
        )
        alice = _entity(8)
        proof = _make_signed(alice, block, tx_index=1)
        proof.tx_index = 2  # tamper
        ok, _ = verify_custody_proof(
            proof, expected_block_hash=block["block_hash"],
        )
        self.assertFalse(ok)

    def test_tampered_target_height_rejected(self):
        """target_height is in the signing material so a cross-epoch
        replay attempt that rewrites target_height fails."""
        block = _mini_block([b"tx-0" * 10], 5)
        alice = _entity(9)
        proof = _make_signed(alice, block)
        proof.target_height = 999  # tamper
        ok, _ = verify_custody_proof(
            proof, expected_block_hash=block["block_hash"],
        )
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# 4. Serialization round-trip preserves signature + pubkey.
# ---------------------------------------------------------------------------


class TestSerializationRoundtrip(unittest.TestCase):
    def test_dict_roundtrip(self):
        block = _mini_block([b"tx-0" * 10, b"tx-1" * 10], 7)
        alice = _entity(10)
        original = _make_signed(alice, block, tx_index=0)
        data = original.serialize()
        restored = CustodyProof.deserialize(data)
        self.assertEqual(restored.public_key, original.public_key)
        self.assertEqual(restored.prover_id, original.prover_id)
        # Restored proof still verifies.
        ok, _ = verify_custody_proof(
            restored, expected_block_hash=block["block_hash"],
        )
        self.assertTrue(ok)

    def test_binary_roundtrip(self):
        block = _mini_block([b"tx-0" * 10, b"tx-1" * 10], 7)
        alice = _entity(11)
        original = _make_signed(alice, block, tx_index=1)
        blob = original.to_bytes()
        restored = CustodyProof.from_bytes(blob)
        self.assertEqual(restored.public_key, original.public_key)
        self.assertEqual(restored.prover_id, original.prover_id)
        ok, _ = verify_custody_proof(
            restored, expected_block_hash=block["block_hash"],
        )
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
