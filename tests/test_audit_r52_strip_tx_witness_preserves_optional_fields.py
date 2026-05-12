"""Audit r52 finding 1 — ``strip_tx_witness`` / ``attach_tx_witness`` MUST
preserve every MessageTransaction field except ``signature``.

Pre-fix the helpers in ``messagechain/core/witness.py`` rebuilt the
stripped/reattached tx by hand-listing fields, which froze the strip
contract at the pre-Tier-10 field set.  Every Tier 5+ optional field
silently fell on the floor:

    * ``prev``           (v2  — reply / threading pointer)
    * ``sender_pubkey``  (v3  — first-spend pubkey install)
    * ``community_id``   (v5  — Reddit-style topic handle)
    * ``poll_options``   (v6  — structured poll's option list)
    * ``vote_target``    (v6  — structured vote's (poll, index))

``ChainDB.strip_finalized_witnesses`` calls ``strip_block_witnesses`` →
``strip_tx_witness`` and writes the stripped bytes BACK into
``blocks.data``.  ``WITNESS_AUTO_SEPARATION_HEIGHT`` is well under live
mainnet tip, so the sweep actively runs against finalized blocks
producing the corruption on the canonical block table — directly
violating the "your message can never be deleted" permanence anchor for
every Tier 5+ payload that ages past ``WITNESS_RETENTION_BLOCKS``
past finality.

The companion ``strip_block_witnesses`` ten lines below the defective
``strip_tx_witness`` already uses ``dataclasses.replace`` and its
docstring explicitly says "listing slots one-by-one was the defect
form" — ``strip_tx_witness`` was the named defect form on the sibling
function.  The fix routes both helpers through ``dataclasses.replace``
so every future MessageTransaction field auto-survives the round-trip.
"""

from __future__ import annotations

import os
import unittest

from messagechain.core.transaction import (
    MessageTransaction,
    TX_VERSION_COMMUNITY_ID,
    TX_VERSION_FIRST_SEND_PUBKEY,
    TX_VERSION_POLL,
    TX_VERSION_PREV_POINTER,
    create_transaction,
)
from messagechain.core.witness import (
    attach_tx_witness,
    get_tx_witness_data,
    strip_block_witnesses,
    strip_tx_witness,
)
from messagechain.identity.identity import Entity


def _entity():
    return Entity.create(os.urandom(32))


class StripTxWitnessPreservesOptionalFields(unittest.TestCase):
    """Every optional MessageTransaction field a tx version may carry MUST
    survive ``strip_tx_witness`` and the inverse ``attach_tx_witness``
    round-trip.

    The test deliberately exercises ONE field per case so a future
    regression (e.g. a Tier-10 optional field added but the strip
    helper not updated) surfaces as a precise failure rather than a
    single "round-trip broken" verdict that doesn't say where.
    """

    def _assert_round_trip(self, tx: MessageTransaction) -> None:
        """Strip → assert all non-signature fields preserved →
        re-attach the original signature blob → assert recovered."""
        original_sig_blob = get_tx_witness_data(tx)
        stripped = strip_tx_witness(tx)

        # signature is sentinel (no wots material) on the stripped form
        self.assertFalse(stripped.signature.wots_signature)
        self.assertFalse(stripped.signature.wots_public_key)

        # every other tx-shape field is preserved verbatim
        self.assertEqual(stripped.entity_id, tx.entity_id)
        self.assertEqual(stripped.message, tx.message)
        self.assertEqual(stripped.timestamp, tx.timestamp)
        self.assertEqual(stripped.nonce, tx.nonce)
        self.assertEqual(stripped.fee, tx.fee)
        self.assertEqual(stripped.version, tx.version)
        self.assertEqual(stripped.compression_flag, tx.compression_flag)
        self.assertEqual(stripped.prev, tx.prev)
        self.assertEqual(stripped.sender_pubkey, tx.sender_pubkey)
        self.assertEqual(stripped.community_id, tx.community_id)
        self.assertEqual(stripped.poll_options, tx.poll_options)
        self.assertEqual(stripped.vote_target, tx.vote_target)
        self.assertEqual(stripped.tx_hash, tx.tx_hash)
        self.assertEqual(stripped.witness_hash, tx.witness_hash)

        # Re-attach restores the original verbatim.
        reattached = attach_tx_witness(stripped, original_sig_blob)
        self.assertEqual(reattached.signature.wots_signature, tx.signature.wots_signature)
        self.assertEqual(reattached.signature.wots_public_key, tx.signature.wots_public_key)
        self.assertEqual(reattached.signature.sig_version, tx.signature.sig_version)
        self.assertEqual(reattached.prev, tx.prev)
        self.assertEqual(reattached.sender_pubkey, tx.sender_pubkey)
        self.assertEqual(reattached.community_id, tx.community_id)
        self.assertEqual(reattached.poll_options, tx.poll_options)
        self.assertEqual(reattached.vote_target, tx.vote_target)

    def test_v2_prev_pointer_preserved(self):
        entity = _entity()
        prev_target = b"\xab" * 32
        tx = create_transaction(entity, "reply body", 10_000, 1, prev=prev_target)
        self.assertEqual(tx.version, TX_VERSION_PREV_POINTER)
        self.assertEqual(tx.prev, prev_target)
        self._assert_round_trip(tx)

    def test_v3_sender_pubkey_install_preserved(self):
        entity = _entity()
        tx = create_transaction(entity, "first message", 10_000, 0, include_pubkey=True)
        self.assertGreaterEqual(tx.version, TX_VERSION_FIRST_SEND_PUBKEY)
        self.assertTrue(tx.sender_pubkey)
        self._assert_round_trip(tx)

    def test_v5_community_id_preserved(self):
        entity = _entity()
        tx = create_transaction(entity, "tagged post", 10_000, 2, community_id="mc-dev")
        self.assertGreaterEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertEqual(tx.community_id, "mc-dev")
        self._assert_round_trip(tx)

    def test_v6_poll_options_preserved(self):
        entity = _entity()
        tx = create_transaction(
            entity, "favourite colour?", 10_000, 3,
            poll_options=("red", "green", "blue"),
        )
        self.assertEqual(tx.version, TX_VERSION_POLL)
        self.assertEqual(tx.poll_options, ("red", "green", "blue"))
        self._assert_round_trip(tx)

    def test_v6_vote_target_preserved(self):
        entity = _entity()
        poll_txid = b"\xcd" * 32
        tx = create_transaction(
            entity, "", 10_000, 4,
            vote_target=(poll_txid, 1),
        )
        self.assertEqual(tx.version, TX_VERSION_POLL)
        self.assertEqual(tx.vote_target, (poll_txid, 1))
        self._assert_round_trip(tx)


class StripTxWitnessOnDiskRoundTrip(unittest.TestCase):
    """The headline finding: ``strip_finalized_witnesses`` writes the
    stripped ``Block.to_bytes()`` back into ``blocks.data``, so the
    on-disk round-trip is what actually breaks permanence.  This test
    locks the property at the serialization layer where the bug bit
    production.

    A v6 poll with options round-tripped through:
        original → strip_block_witnesses → to_bytes → from_bytes
    must still expose ``poll_options`` after the from_bytes deserialize.
    Pre-fix it did not.
    """

    def test_v6_poll_survives_strip_then_to_bytes_then_from_bytes(self):
        entity = _entity()
        poll_tx = create_transaction(
            entity, "favourite colour?", 10_000, 0,
            poll_options=("red", "green", "blue"),
        )
        self.assertEqual(poll_tx.poll_options, ("red", "green", "blue"))

        from messagechain.core.block import Block, BlockHeader, compute_merkle_root
        from messagechain.config import WITNESS_ROOT_ACTIVATION_HEIGHT
        from messagechain.core.witness import compute_block_witness_root

        block_number = max(WITNESS_ROOT_ACTIVATION_HEIGHT, 1) + 1
        merkle_root = compute_merkle_root([poll_tx.tx_hash])
        header = BlockHeader(
            version=1,
            block_number=block_number,
            prev_hash=b"\x00" * 32,
            merkle_root=merkle_root,
            state_root=b"\x00" * 32,
            timestamp=1700000000.0,
            proposer_id=poll_tx.entity_id,
            witness_root=b"\x00" * 32,
        )
        block = Block(header=header, transactions=[poll_tx])
        block.header.witness_root = compute_block_witness_root(block)
        block.block_hash = block._compute_hash()

        # Strip → re-serialize → deserialize (the production path).
        stripped = strip_block_witnesses(block)
        stripped_bytes = stripped.to_bytes()
        recovered = Block.from_bytes(stripped_bytes)

        # The poll options MUST survive the on-disk round-trip.  Pre-fix
        # this was the production-active bug: the stripped on-disk form
        # silently emitted v6 without the poll_options block, so the
        # deserialized tx returned poll_options=None.
        self.assertEqual(len(recovered.transactions), 1)
        recovered_tx = recovered.transactions[0]
        self.assertEqual(recovered_tx.version, TX_VERSION_POLL)
        self.assertEqual(recovered_tx.poll_options, ("red", "green", "blue"))


if __name__ == "__main__":
    unittest.main()
