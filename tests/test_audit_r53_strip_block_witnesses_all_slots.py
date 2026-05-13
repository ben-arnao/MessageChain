"""
Regression for audit r53 #1.

``strip_block_witnesses`` + ``get_block_witness_data`` +
``attach_block_witnesses`` MUST round-trip witnesses for EVERY signed
slot in the block, not just ``block.transactions``.  Pre-fix the strip
path only iterated ``block.transactions``, so attestations / transfers
/ stake / unstake / governance / authority / reactions / finality_votes
/ slash / custody / inclusion-list / the four evidence kinds kept their
~2.7 KB WOTS+ signatures inline in primary ``blocks.data`` forever
despite the auto-separation sweep claiming to be active — every node
running past ``WITNESS_AUTO_SEPARATION_HEIGHT`` silently bled the
storage-saving anchor for 90%+ of the witness mass it claimed to
strip.

The sibling ``strip_block_witnesses`` docstring already calls out
listing slots one-by-one as the defect form ("listing slots one-by-one
was the defect form"); the function itself was the named defect form
until r53 #1 routed it through ``enumerate_block_signatures`` and the
shared per-slot table so future signed-body additions auto-survive by
construction.
"""

import copy
import dataclasses
import struct
import unittest

from messagechain.consensus.attestation import Attestation
from messagechain.core.block import (
    Block,
    BlockHeader,
    _hash,
    compute_merkle_root,
)
from messagechain.core.transaction import create_transaction
from messagechain.core.witness import (
    WITNESS_STRIPPED_SENTINEL,
    attach_block_witnesses,
    compute_witness_root,
    get_block_witness_data,
    strip_block_witnesses,
    strip_tx_witness,
)
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _make_block_with_attestation():
    """Block with a message tx AND a non-tx signed slot (attestation).

    Same entity signs both for fixture simplicity; the strip/attach
    path does not key on signer identity.
    """
    entity = Entity.create(b"\x11" * 32)

    tx = create_transaction(entity, "hello", fee=10_000, nonce=0)

    att_signable = (
        b"chain-id-fixture"
        + b"attestation"
        + entity.entity_id
        + b"\x00" * 32
        + struct.pack(">Q", 0)
    )
    att_sig = entity.keypair.sign(_hash(att_signable))
    attestation = Attestation(
        validator_id=entity.entity_id,
        block_hash=b"\x00" * 32,
        block_number=0,
        signature=att_sig,
    )

    merkle_root = compute_merkle_root([tx.tx_hash])
    header = BlockHeader(
        version=1,
        block_number=1,
        prev_hash=b"\x00" * 32,
        merkle_root=merkle_root,
        timestamp=1.0,
        proposer_id=entity.entity_id,
    )
    header.witness_root = compute_witness_root([tx])
    header.proposer_signature = entity.keypair.sign(_hash(header.signable_data()))

    block = Block(header=header, transactions=[tx], attestations=[attestation])
    block.block_hash = block._compute_hash()
    return block


class TestStripStripsEverySignedSlot(unittest.TestCase):
    """``strip_block_witnesses`` must sentinel every signed slot, not
    just ``transactions``."""

    def test_attestation_signature_is_stripped(self):
        block = _make_block_with_attestation()
        original_att_canonical = block.attestations[0].signature.canonical_bytes()

        stripped = strip_block_witnesses(block)

        att_sig = stripped.attestations[0].signature
        # Sentinel shape: empty list components and empty pubkey bytes.
        self.assertEqual(att_sig.wots_signature, [])
        self.assertEqual(att_sig.auth_path, [])
        self.assertEqual(att_sig.wots_public_key, b"")
        # Defense against false-pass: the original was not sentinel-shaped.
        self.assertNotEqual(
            original_att_canonical, att_sig.canonical_bytes(),
            "fixture is broken — attestation was already sentinel pre-strip",
        )

    def test_message_tx_signature_is_stripped(self):
        block = _make_block_with_attestation()
        original_tx_canonical = block.transactions[0].signature.canonical_bytes()

        stripped = strip_block_witnesses(block)

        tx_sig = stripped.transactions[0].signature
        self.assertEqual(tx_sig.wots_signature, [])
        self.assertEqual(tx_sig.wots_public_key, b"")
        self.assertNotEqual(original_tx_canonical, tx_sig.canonical_bytes())


class TestWitnessRoundTripCoversEverySlot(unittest.TestCase):
    """``get_block_witness_data`` + ``attach_block_witnesses`` must
    round-trip every signed slot's signature exactly."""

    def test_attestation_signature_restored_via_round_trip(self):
        block = _make_block_with_attestation()
        original_att_canonical = block.attestations[0].signature.canonical_bytes()

        witness_blob = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        restored = attach_block_witnesses(stripped, witness_blob)

        self.assertEqual(
            restored.attestations[0].signature.canonical_bytes(),
            original_att_canonical,
        )

    def test_tx_signature_restored_via_round_trip(self):
        block = _make_block_with_attestation()
        original_tx_canonical = block.transactions[0].signature.canonical_bytes()

        witness_blob = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        restored = attach_block_witnesses(stripped, witness_blob)

        self.assertEqual(
            restored.transactions[0].signature.canonical_bytes(),
            original_tx_canonical,
        )


class TestStripActuallyShrinksBlockStorage(unittest.TestCase):
    """Pre-fix, the attestation's ~2.7 KB signature stayed inline in
    ``blocks.data`` after strip; the auto-separation sweep claimed to
    move every signed-body witness to the side table but only moved
    transactions.  Post-fix, the stripped block must shrink by more
    than the tx signature's contribution — proving non-tx slots are
    also being touched."""

    def test_strip_shrinks_block_by_more_than_tx_witness_alone(self):
        block = _make_block_with_attestation()
        tx_sig_size = len(block.transactions[0].signature.to_bytes())
        att_sig_size = len(block.attestations[0].signature.to_bytes())

        full_size = len(block.to_bytes())
        stripped = strip_block_witnesses(block)
        stripped_size = len(stripped.to_bytes())

        # The bytes the strip removed from primary storage must
        # exceed the tx witness alone by at least most of the
        # attestation witness.  Using 0.5 * att_sig_size as a
        # conservative bound to absorb encoding overhead.
        delta = full_size - stripped_size
        self.assertGreater(
            delta,
            tx_sig_size + att_sig_size // 2,
            f"strip removed only {delta} B from primary storage "
            f"(tx_sig={tx_sig_size}, att_sig={att_sig_size}) — "
            f"non-tx witness still inline post-strip",
        )


class TestLegacyWitnessBlobStillDecodes(unittest.TestCase):
    """Backward-compat anchor: blocks already stripped on disk
    pre-fix carry a legacy witness blob (``u32 tx_count | per-tx u32
    sig_len | sig_bytes``).  The post-fix reader MUST still decode
    them, otherwise every node bricks on its own historical
    block_witnesses side table the moment it upgrades past r53 #1."""

    def test_legacy_blob_format_round_trips(self):
        block = _make_block_with_attestation()

        # Simulate the pre-fix on-disk shape: only ``transactions``
        # got sentineled; ``attestations`` retained its inline sig.
        legacy_stripped_txs = [strip_tx_witness(tx) for tx in block.transactions]
        legacy_stripped = dataclasses.replace(
            block,
            header=copy.deepcopy(block.header),
            transactions=legacy_stripped_txs,
            block_hash=b"",
        )
        legacy_stripped.block_hash = legacy_stripped._compute_hash()

        # Reproduce the legacy ``get_block_witness_data`` format byte-for-byte.
        tx_sig_bytes = block.transactions[0].signature.to_bytes()
        legacy_blob = (
            struct.pack(">I", 1)
            + struct.pack(">I", len(tx_sig_bytes))
            + tx_sig_bytes
        )

        restored = attach_block_witnesses(legacy_stripped, legacy_blob)
        # Tx sig restored from the blob.
        self.assertEqual(
            restored.transactions[0].signature.canonical_bytes(),
            block.transactions[0].signature.canonical_bytes(),
        )
        # Attestation sig left untouched (it was inline, not in the blob).
        self.assertEqual(
            restored.attestations[0].signature.canonical_bytes(),
            block.attestations[0].signature.canonical_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
