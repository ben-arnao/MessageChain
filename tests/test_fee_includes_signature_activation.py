"""Tests for finding #7 — fee must cover signature/witness bytes after activation.

Before FEE_INCLUDES_SIGNATURE_HEIGHT the legacy rule applies: fee must cover
only the canonical message bytes.  At/after the activation height, fee must
cover (message_bytes + signature_bytes) — otherwise an attacker can flood
chain storage with WOTS+ signatures (~2 KB each) paying only the tiny
payload fee, breaking the fee-only anti-spam guarantee.

Callers that verify a tx without chain context (current_height=None) must
keep getting the legacy rule — isolated tests, relay-layer signature sanity
checks, and similar non-consensus call sites should not regress.
"""

import unittest

from messagechain.config import FEE_INCLUDES_SIGNATURE_HEIGHT, MIN_FEE
from messagechain.core.transaction import (
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


class TestCalculateMinFeeSignatureBytes(unittest.TestCase):
    """calculate_min_fee exposes an optional signature_bytes knob."""

    def test_legacy_default_matches_old_result(self):
        msg = b"hello world"
        legacy = calculate_min_fee(msg)
        # signature_bytes defaulted to 0 preserves the legacy number bit-exact.
        self.assertEqual(calculate_min_fee(msg, signature_bytes=0), legacy)

    def test_zero_signature_bytes_matches_message_only(self):
        """Explicit signature_bytes=0 keeps the message-only formula."""
        msg = b"short"
        self.assertEqual(
            calculate_min_fee(msg, signature_bytes=0),
            calculate_min_fee(msg),
        )

    def test_positive_signature_bytes_strictly_greater(self):
        msg = b"hello world"
        base = calculate_min_fee(msg)
        with_sig = calculate_min_fee(msg, signature_bytes=2048)
        self.assertGreater(with_sig, base)

    def test_fee_prices_combined_size(self):
        """signature_bytes > 0 prices the (msg+sig) sum under the same formula."""
        msg = b"hi"
        combined = calculate_min_fee(msg + b"\x00" * 500)
        metered = calculate_min_fee(msg, signature_bytes=500)
        self.assertEqual(combined, metered)


class TestVerifyTransactionActivationGate(unittest.TestCase):
    """verify_transaction honors FEE_INCLUDES_SIGNATURE_HEIGHT."""

    def setUp(self):
        self.alice = Entity.create(b"alice-fee-sig-activation".ljust(32, b"\x00"))
        # A short incompressible message — stored bytes == plaintext, so
        # fee math is easy to reason about.
        self.msg = "hi friend"
        msg_bytes = self.msg.encode("ascii")
        self.msg_min = calculate_min_fee(msg_bytes)
        self.tx = create_transaction(
            self.alice, self.msg, fee=self.msg_min, nonce=0,
        )
        self.sig_len = len(self.tx.signature.to_bytes())
        self.pubkey = self.alice.keypair.public_key

    def test_A_pre_activation_message_only_fee_passes(self):
        """Pre-activation the legacy message-only fee is sufficient."""
        self.assertGreater(FEE_INCLUDES_SIGNATURE_HEIGHT, 0)
        pre_height = FEE_INCLUDES_SIGNATURE_HEIGHT - 1
        self.assertTrue(
            verify_transaction(self.tx, self.pubkey, current_height=pre_height),
        )

    def test_B_post_activation_message_only_fee_fails(self):
        """At/after activation the old fee no longer covers sig bytes."""
        self.assertFalse(
            verify_transaction(
                self.tx, self.pubkey,
                current_height=FEE_INCLUDES_SIGNATURE_HEIGHT,
            ),
        )

    def test_C_post_activation_full_fee_passes(self):
        """Funding (message_bytes + signature_bytes) clears the new rule."""
        full_min = calculate_min_fee(
            self.tx.message, signature_bytes=self.sig_len,
        )
        tx = create_transaction(
            self.alice, self.msg, fee=full_min, nonce=0,
        )
        # Signature length is deterministic for a given MERKLE_TREE_HEIGHT /
        # scheme, so the freshly signed tx has the same sig size we funded.
        self.assertEqual(len(tx.signature.to_bytes()), self.sig_len)
        self.assertTrue(
            verify_transaction(
                tx, self.pubkey,
                current_height=FEE_INCLUDES_SIGNATURE_HEIGHT,
            ),
        )
        # And well above activation too.
        self.assertTrue(
            verify_transaction(
                tx, self.pubkey,
                current_height=FEE_INCLUDES_SIGNATURE_HEIGHT + 10_000,
            ),
        )

    def test_E_no_chain_height_context_uses_legacy_rule(self):
        """current_height=None is the legacy rule — message-only fee passes."""
        self.assertTrue(
            verify_transaction(self.tx, self.pubkey, current_height=None),
        )
        # Default argument (no kwarg) must also fall back to legacy.
        self.assertTrue(verify_transaction(self.tx, self.pubkey))


if __name__ == "__main__":
    unittest.main()
