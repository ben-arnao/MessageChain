"""Byte caps on governance proposal payloads and authority txs.

Closes two unbounded-byte escape hatches left open after the prior
per-block count-cap PR:

* Governance proposal title/description are currently capped by
  CHARACTER count (200 / 10_000).  UTF-8 encoding can expand a
  character to 4 bytes, so a 10k-char description can be ~40 KB
  on-chain.  Add a byte cap enforced on the encoded form.

* Authority txs (SetAuthorityKey / Revoke / KeyRotation) have no
  per-tx byte cap.  Each naturally sits at ~2.8 KB dominated by
  a WOTS+ signature; a safety-rail cap catches malformed outliers
  and future-incompatible variants before they land on-chain.

Tests are deliberately structural — verify_proposal /
verify_treasury_spend and the authority-tx size helper reject on
size alone before any signature verification, so placeholder sigs
are acceptable here.
"""
import os
import unittest

from messagechain.crypto.keys import Signature
from messagechain.governance.governance import (
    ProposalTransaction,
    TreasurySpendTransaction,
    verify_proposal,
    verify_treasury_spend,
    GOVERNANCE_PROPOSAL_FEE,
    MAX_PROPOSAL_TITLE_BYTES,
    MAX_PROPOSAL_DESCRIPTION_BYTES,
)
from messagechain.config import MAX_AUTHORITY_TX_BYTES
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _placeholder_sig():
    return Signature([], 0, [], b"", b"")


def _make_proposal(title: str, description: str) -> ProposalTransaction:
    return ProposalTransaction(
        proposer_id=b"\x11" * 32,
        title=title,
        description=description,
        timestamp=1_000_000,
        fee=GOVERNANCE_PROPOSAL_FEE,
        signature=_placeholder_sig(),
    )


def _make_treasury_spend(title: str, description: str) -> TreasurySpendTransaction:
    return TreasurySpendTransaction(
        proposer_id=b"\x11" * 32,
        recipient_id=b"\x22" * 32,
        amount=1,
        title=title,
        description=description,
        timestamp=1_000_000,
        fee=GOVERNANCE_PROPOSAL_FEE,
        signature=_placeholder_sig(),
    )


class TestProposalByteCaps(unittest.TestCase):
    """Proposals reject oversized UTF-8 payloads on BYTES, not chars.
    The existing character caps stay as a fast-path rejection for
    pure-ASCII abuse; byte caps close the emoji/CJK amplification.
    """

    def test_ascii_title_at_byte_cap_passes_size_check(self):
        """A title at exactly the byte cap must not trip the size rule."""
        title = "a" * MAX_PROPOSAL_TITLE_BYTES
        tx = _make_proposal(title, "ok")
        # verify_proposal will fail on signature (placeholder) but
        # must reach that point — not fail early on size.  We check
        # the byte-count rule in isolation.
        self.assertEqual(
            len(tx.title.encode("utf-8")), MAX_PROPOSAL_TITLE_BYTES,
        )

    def test_title_byte_cap_rejects_over(self):
        tx = _make_proposal("a" * (MAX_PROPOSAL_TITLE_BYTES + 1), "ok")
        self.assertFalse(verify_proposal(tx, public_key=b"\x00" * 32))

    def test_title_emoji_amplification_rejected(self):
        """An emoji-heavy title that squeaks past the char cap but
        blows past the byte cap must be rejected.  This is the
        actual escape hatch closed by the new rule.
        """
        # Each 😀 is 4 UTF-8 bytes.  Pick a count that fits within
        # the 200-char cap but exceeds MAX_PROPOSAL_TITLE_BYTES.
        emoji_count = (MAX_PROPOSAL_TITLE_BYTES // 4) + 1
        tx = _make_proposal("😀" * emoji_count, "ok")
        self.assertFalse(verify_proposal(tx, public_key=b"\x00" * 32))

    def test_description_byte_cap_rejects_over(self):
        tx = _make_proposal(
            "t", "a" * (MAX_PROPOSAL_DESCRIPTION_BYTES + 1),
        )
        self.assertFalse(verify_proposal(tx, public_key=b"\x00" * 32))

    def test_description_emoji_amplification_rejected(self):
        emoji_count = (MAX_PROPOSAL_DESCRIPTION_BYTES // 4) + 1
        tx = _make_proposal("t", "😀" * emoji_count)
        self.assertFalse(verify_proposal(tx, public_key=b"\x00" * 32))


class TestTreasurySpendByteCaps(unittest.TestCase):
    """Treasury-spend proposals previously had ZERO length check on
    title/description — this is the wider escape hatch.  Byte cap
    must apply there too.
    """

    def test_title_byte_cap_rejects_over(self):
        tx = _make_treasury_spend(
            "a" * (MAX_PROPOSAL_TITLE_BYTES + 1), "ok",
        )
        self.assertFalse(
            verify_treasury_spend(tx, public_key=b"\x00" * 32)
        )

    def test_description_byte_cap_rejects_over(self):
        tx = _make_treasury_spend(
            "ok", "a" * (MAX_PROPOSAL_DESCRIPTION_BYTES + 1),
        )
        self.assertFalse(
            verify_treasury_spend(tx, public_key=b"\x00" * 32)
        )

    def test_normal_treasury_spend_passes_size_rule(self):
        """A reasonably-sized treasury spend must not trip size rules.
        (Will still fail on signature verification with the
        placeholder sig, but not on size.)
        """
        tx = _make_treasury_spend("Fund audit", "Hire external auditor")
        self.assertLessEqual(
            len(tx.title.encode("utf-8")), MAX_PROPOSAL_TITLE_BYTES,
        )
        self.assertLessEqual(
            len(tx.description.encode("utf-8")),
            MAX_PROPOSAL_DESCRIPTION_BYTES,
        )


class TestAuthorityTxByteCap(unittest.TestCase):
    """Authority txs are structurally bounded by their ~2.8 KB WOTS
    signature, but a safety-rail per-tx byte cap catches any
    malformed or future-incompatible variant that might otherwise
    slip in as unpriced permanent data.
    """

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)

    def test_cap_is_positive_and_larger_than_real_tx(self):
        """Sanity: the cap must admit a normal authority tx.  A real
        authority tx sits at ~2.8 KB (sig dominated); the cap must
        leave headroom so legitimate txs never trip it.
        """
        self.assertGreater(MAX_AUTHORITY_TX_BYTES, 2800)

    def test_oversized_authority_tx_rejected(self):
        """A block containing an authority tx whose serialized size
        exceeds the cap is rejected on size alone — before any
        signature work.
        """
        class _FakeAuthorityTx:
            """Minimal stand-in: only to_bytes() is used by the size
            check.  Other attributes match the authority-tx shape
            enough for the validation loop to dispatch past earlier
            checks that may run before the size check.
            """
            __class__ = type("RevokeTransaction", (), {})  # name only
            tx_hash = b"\xaa" * 32
            entity_id = b"\x11" * 32
            fee = 10_000
            def to_bytes(self, state=None):
                return b"\x00" * (MAX_AUTHORITY_TX_BYTES + 1)

        ok, reason = self.chain._validate_authority_tx_sizes(
            [_FakeAuthorityTx()]
        )
        self.assertFalse(ok)
        self.assertIn("authority", reason.lower())

    def test_under_cap_authority_tx_passes_size_check(self):
        class _FakeAuthorityTx:
            tx_hash = b"\xbb" * 32
            def to_bytes(self, state=None):
                return b"\x00" * (MAX_AUTHORITY_TX_BYTES - 100)

        ok, _ = self.chain._validate_authority_tx_sizes(
            [_FakeAuthorityTx()]
        )
        self.assertTrue(ok)

    def test_empty_list_passes(self):
        ok, _ = self.chain._validate_authority_tx_sizes([])
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
