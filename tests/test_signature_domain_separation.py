"""Explicit domain-separation tags in per-tx signable_data.

An audit of the 15 signature schemes found that 12 of them commit an
explicit byte-string domain tag (e.g., ``b"transfer"``, ``b"attestation"``,
``b"stake"``) to the start of their signable_data, right after CHAIN_ID.
This prevents cross-type signature replay: a signature intended as a
transfer cannot be reinterpreted as, say, a stake unbonding request in a
future version that happens to land on the same byte layout.

Three tx types were missing this hardening pre-launch:

* MessageTransaction
* KeyRotationTransaction
* SlashTransaction

These tests pin the tag in place. If a future refactor reorders fields
and drops the tag, the assertions below fail loudly.
"""

import time
import unittest

from messagechain.config import CHAIN_ID
from messagechain.consensus.slashing import (
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.key_rotation import (
    create_key_rotation,
    derive_rotated_keypair,
    verify_key_rotation,
)
from messagechain.core.transaction import create_transaction, verify_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity


def _make_conflicting_headers(proposer_entity, block_number: int = 1):
    """Two different signed headers at the same height — minimum slash evidence."""
    header_a = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=b"\x00" * 32,
        merkle_root=_hash(b"a"),
        timestamp=time.time(),
        proposer_id=proposer_entity.entity_id,
    )
    header_a.proposer_signature = proposer_entity.keypair.sign(
        _hash(header_a.signable_data())
    )

    header_b = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=b"\x00" * 32,
        merkle_root=_hash(b"b"),
        timestamp=time.time() + 1,
        proposer_id=proposer_entity.entity_id,
    )
    header_b.proposer_signature = proposer_entity.keypair.sign(
        _hash(header_b.signable_data())
    )
    return header_a, header_b


class TestSignatureDomainSeparation(unittest.TestCase):
    """Each tx type commits its own domain tag right after CHAIN_ID."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-domain-sep".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-domain-sep".ljust(32, b"\x00"))

    def setUp(self):
        # Reset WOTS+ leaf counters so each test signs from a fresh tree.
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

    # --- Domain tag presence --------------------------------------------

    def test_message_tx_signature_includes_domain_tag(self):
        """MessageTransaction._signable_data() commits b\"message\" right after CHAIN_ID."""
        tx = create_transaction(self.alice, "hello world", fee=1000, nonce=0)
        signable = tx._signable_data()
        tag = b"message"
        self.assertEqual(
            signable[: len(CHAIN_ID)], CHAIN_ID,
            "signable_data must start with CHAIN_ID",
        )
        self.assertEqual(
            signable[len(CHAIN_ID): len(CHAIN_ID) + len(tag)], tag,
            "MessageTransaction must commit b\"message\" domain tag right after CHAIN_ID",
        )

    def test_key_rotation_signature_includes_domain_tag(self):
        """KeyRotationTransaction commits b\"key_rotation\" right after CHAIN_ID."""
        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)
        signable = tx._signable_data()
        tag = b"key_rotation"
        self.assertEqual(signable[: len(CHAIN_ID)], CHAIN_ID)
        self.assertEqual(
            signable[len(CHAIN_ID): len(CHAIN_ID) + len(tag)], tag,
            "KeyRotationTransaction must commit b\"key_rotation\" domain tag",
        )

    def test_slash_signature_includes_domain_tag(self):
        """SlashTransaction commits b\"slash\" right after CHAIN_ID."""
        header_a, header_b = _make_conflicting_headers(self.alice)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        signable = slash_tx._signable_data()
        tag = b"slash"
        self.assertEqual(signable[: len(CHAIN_ID)], CHAIN_ID)
        self.assertEqual(
            signable[len(CHAIN_ID): len(CHAIN_ID) + len(tag)], tag,
            "SlashTransaction must commit b\"slash\" domain tag",
        )

    # --- Cross-domain replay prevention ---------------------------------

    def test_message_tx_signature_differs_from_transfer_sig(self):
        """Different tx types must diverge in signable_data immediately after CHAIN_ID.

        A hypothetical attacker who got a MessageTransaction signature on
        some bytes cannot repurpose that signature as a TransferTransaction
        — the byte prefixes diverge at the domain tag, so the two hashes
        never collide even if field layouts overlap in a future version.
        """
        # Build a message tx.
        msg_tx = create_transaction(self.alice, "hi", fee=1000, nonce=0)
        msg_signable = msg_tx._signable_data()

        # Build a transfer with roughly similar parameters.
        transfer_tx = create_transfer_transaction(
            self.alice, self.bob.entity_id, amount=1, nonce=0
        )
        transfer_signable = transfer_tx._signable_data()

        # Both share CHAIN_ID, then diverge.
        common_prefix_len = len(CHAIN_ID)
        self.assertEqual(
            msg_signable[:common_prefix_len],
            transfer_signable[:common_prefix_len],
            "both tx types must start with CHAIN_ID",
        )
        # The very next byte (start of the domain tag) must differ.
        self.assertNotEqual(
            msg_signable[common_prefix_len:common_prefix_len + 1],
            transfer_signable[common_prefix_len:common_prefix_len + 1],
            "domain tags must diverge immediately after CHAIN_ID",
        )

    # --- Round-trip sign/verify regression ------------------------------

    def test_round_trip_sign_verify_message(self):
        """Signing + verifying a MessageTransaction still works with the new tag."""
        tx = create_transaction(self.alice, "regression check", fee=2000, nonce=0)
        self.assertTrue(verify_transaction(tx, self.alice.public_key))

    def test_round_trip_sign_verify_key_rotation(self):
        """Signing + verifying a KeyRotationTransaction still works."""
        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)
        self.assertTrue(verify_key_rotation(tx, self.alice.public_key))

    def test_round_trip_sign_verify_slash(self):
        """Signing + verifying a SlashTransaction's submitter signature still works.

        The SlashTransaction signature covers submitter authorship of the
        evidence (for finder-reward attribution). We re-verify it directly
        using the same hash construction create_slash_transaction uses.
        """
        from messagechain.crypto.keys import verify_signature

        header_a, header_b = _make_conflicting_headers(self.alice)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        msg_hash = _hash(slash_tx._signable_data())
        self.assertTrue(
            verify_signature(msg_hash, slash_tx.signature, self.bob.public_key)
        )


if __name__ == "__main__":
    unittest.main()
