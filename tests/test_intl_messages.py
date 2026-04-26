"""Tier 12: international (UTF-8) message bodies.

Pre-INTL_MESSAGE_HEIGHT: messages MUST be printable ASCII (32-126).
Post-INTL_MESSAGE_HEIGHT: messages MUST be NFC-normalized UTF-8 whose
codepoints fall under General_Category L*/M*/N*/P*/Zs, plus a narrow
allowlist of format characters required for script shaping (ZWJ/ZWNJ).
Bidi override characters are explicitly rejected.

The structural-category whitelist (rather than a script allowlist) is
deliberate: any future Unicode script lands in L/M/N automatically and
becomes valid without a config change, and the chain never makes a
discretionary "this language counts, that one doesn't" decision.
"""

import unittest
import unicodedata

from messagechain import config
from messagechain.core.transaction import (
    _validate_message,
    create_transaction,
    verify_transaction,
    MAX_MESSAGE_CHARS,
)
from messagechain.identity.identity import Entity


_ENTITY_COUNTER = [0]


def _new_entity():
    # Tests use deterministic per-call seeds — same pattern as
    # test_acks_observed_block_field.  conftest pins MERKLE_TREE_HEIGHT=4
    # so each create is fast.
    _ENTITY_COUNTER[0] += 1
    seed = f"intl-test-{_ENTITY_COUNTER[0]}".encode().ljust(32, b"\x00")
    return Entity.create(seed)


class TestValidateMessagePreFork(unittest.TestCase):
    """Pre-INTL_MESSAGE_HEIGHT behavior must be unchanged: ASCII only."""

    def setUp(self):
        self.height = config.INTL_MESSAGE_HEIGHT - 1

    def test_pure_ascii_accepted(self):
        ok, _ = _validate_message("hello world", current_height=self.height)
        self.assertTrue(ok)

    def test_latin_with_diacritics_rejected(self):
        ok, reason = _validate_message("café", current_height=self.height)
        self.assertFalse(ok)
        self.assertIn("ASCII", reason)

    def test_cyrillic_rejected(self):
        ok, reason = _validate_message("Привет", current_height=self.height)
        self.assertFalse(ok)

    def test_emoji_rejected(self):
        ok, reason = _validate_message("hi 😀", current_height=self.height)
        self.assertFalse(ok)

    def test_legacy_no_height_uses_ascii_path(self):
        # Callers without chain context get the conservative ASCII rule
        # — matches the existing legacy behavior of every other pre-fork
        # height-gated check in the codebase.
        ok, _ = _validate_message("hello", current_height=None)
        self.assertTrue(ok)
        ok, _ = _validate_message("café", current_height=None)
        self.assertFalse(ok)


class TestValidateMessagePostFork(unittest.TestCase):
    """Post-INTL_MESSAGE_HEIGHT: UTF-8 NFC + L/M/N/P/Zs."""

    def setUp(self):
        self.height = config.INTL_MESSAGE_HEIGHT

    def test_pure_ascii_still_accepted(self):
        ok, _ = _validate_message("hello world", current_height=self.height)
        self.assertTrue(ok)

    def test_latin_diacritics_accepted(self):
        for s in ("café", "naïve", "señor", "Zürich", "Tiếng Việt"):
            ok, reason = _validate_message(s, current_height=self.height)
            self.assertTrue(ok, f"{s!r} rejected: {reason}")

    def test_cyrillic_accepted(self):
        ok, _ = _validate_message("Привет, мир", current_height=self.height)
        self.assertTrue(ok)

    def test_arabic_accepted(self):
        # Arabic word for "freedom" — the canonical "audience the chain
        # claims to serve writes in this script" example.
        ok, reason = _validate_message("آزادی", current_height=self.height)
        self.assertTrue(ok, f"rejected: {reason}")

    def test_cjk_accepted(self):
        for s in ("你好", "こんにちは", "안녕하세요"):
            ok, reason = _validate_message(s, current_height=self.height)
            self.assertTrue(ok, f"{s!r} rejected: {reason}")

    def test_devanagari_accepted(self):
        ok, _ = _validate_message("नमस्ते", current_height=self.height)
        self.assertTrue(ok)

    def test_hebrew_thai_greek_accepted(self):
        for s in ("שלום", "สวัสดี", "Γειά"):
            ok, reason = _validate_message(s, current_height=self.height)
            self.assertTrue(ok, f"{s!r} rejected: {reason}")

    def test_emoji_rejected(self):
        for emoji in ("😀", "🔥", "❤️", "👨‍👩‍👧"):
            ok, reason = _validate_message(emoji, current_height=self.height)
            self.assertFalse(ok, f"{emoji!r} accepted but should be rejected")

    def test_math_and_decorative_symbols_rejected(self):
        for s in ("∑", "∞", "★", "→", "☮"):
            ok, _ = _validate_message(s, current_height=self.height)
            self.assertFalse(ok, f"{s!r} accepted but should be rejected")

    def test_currency_symbols_rejected(self):
        # Sc category — explicit reject (matches user spec: "no glyphs,
        # symbols, emojis, beyond what is just language characters").
        # Note: "$" is U+0024, General_Category Sc — pre-fork it sat
        # inside the printable-ASCII window; post-fork the structural
        # rule rejects it.  Documented behavior shift.
        for s in ("€", "¥", "₹", "£"):
            ok, _ = _validate_message(s, current_height=self.height)
            self.assertFalse(ok, f"{s!r} accepted but should be rejected")

    def test_bidi_overrides_rejected(self):
        # U+202E RIGHT-TO-LEFT OVERRIDE — classic spoofing vector.
        # All bidi override / isolate chars in the explicit blocklist:
        for cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                   0x2066, 0x2067, 0x2068, 0x2069):
            s = "abc" + chr(cp) + "def"
            ok, reason = _validate_message(s, current_height=self.height)
            self.assertFalse(ok, f"U+{cp:04X} accepted but is a bidi override")

    def test_zwj_zwnj_allowed(self):
        # ZWNJ (U+200C) needed for Persian/Hindi correct rendering.
        # ZWJ (U+200D) needed for Arabic ligatures, Indic conjuncts.
        zwnj = "می" + chr(0x200C) + "خواهم"  # Persian "I want", with ZWNJ
        zwj = "क्ष"  # Devanagari conjunct using inherent virama, often ZWJ-mediated
        for s in (zwnj, zwj, "a" + chr(0x200D) + "b"):
            ok, reason = _validate_message(s, current_height=self.height)
            self.assertTrue(ok, f"{s!r} rejected: {reason}")

    def test_control_chars_rejected(self):
        # Newline/tab/null all rejected — single-line messages only.
        for cp in (0x00, 0x07, 0x09, 0x0A, 0x0D, 0x1F):
            s = "hi" + chr(cp)
            ok, _ = _validate_message(s, current_height=self.height)
            self.assertFalse(ok, f"control U+{cp:04X} accepted")

    def test_other_format_chars_rejected(self):
        # Cf category beyond the ZWJ/ZWNJ allowlist — e.g. U+200E LRM,
        # U+200F RLM (lighter cousins of bidi overrides), U+FEFF BOM.
        # Reject these too; they're invisible-in-text spoofing surfaces.
        for cp in (0x200E, 0x200F, 0xFEFF, 0x2061):
            s = "a" + chr(cp) + "b"
            ok, _ = _validate_message(s, current_height=self.height)
            self.assertFalse(ok, f"format U+{cp:04X} accepted")

    def test_private_use_and_unassigned_rejected(self):
        # PUA codepoints (U+E000-F8FF) — by definition non-language.
        ok, _ = _validate_message("a" + chr(0xE000), current_height=self.height)
        self.assertFalse(ok)

    def test_byte_cap_enforced(self):
        # MAX_MESSAGE_CHARS = 1024 is now a UTF-8-byte cap on plaintext.
        # 1024 ASCII chars = 1024 bytes — boundary still passes.
        ok, _ = _validate_message("a" * MAX_MESSAGE_CHARS, current_height=self.height)
        self.assertTrue(ok)
        ok, _ = _validate_message(
            "a" * (MAX_MESSAGE_CHARS + 1), current_height=self.height
        )
        self.assertFalse(ok)
        # Chinese: each char = 3 UTF-8 bytes.  341 chars = 1023 bytes ✓,
        # 342 chars = 1026 bytes ✗.  Confirms cap binds on bytes, not codepoints.
        ok, _ = _validate_message("中" * 341, current_height=self.height)
        self.assertTrue(ok)
        ok, _ = _validate_message("中" * 342, current_height=self.height)
        self.assertFalse(ok)

    def test_nfc_required(self):
        # "é" has two encodings: U+00E9 (composed, NFC) or U+0065 + U+0301
        # (decomposed, NFD).  Only NFC accepted — without this rule two
        # visibly-identical messages produce different tx_hashes, breaking
        # dedup, prev-pointer references, and feed equality checks.
        nfc_form = "café"
        nfd_form = unicodedata.normalize("NFD", nfc_form)
        self.assertNotEqual(nfc_form, nfd_form)  # sanity
        ok, _ = _validate_message(nfc_form, current_height=self.height)
        self.assertTrue(ok)
        ok, reason = _validate_message(nfd_form, current_height=self.height)
        self.assertFalse(ok)
        self.assertIn("NFC", reason)


class TestActivationGateOnTransactionCreate(unittest.TestCase):
    """create_transaction must reject non-ASCII pre-fork."""

    def test_pre_fork_rejects_utf8(self):
        e = _new_entity()
        with self.assertRaises(ValueError):
            create_transaction(
                e, "café", fee=10_000, nonce=0,
                current_height=config.INTL_MESSAGE_HEIGHT - 1,
            )

    def test_post_fork_accepts_utf8(self):
        e = _new_entity()
        tx = create_transaction(
            e, "café", fee=10_000, nonce=0,
            current_height=config.INTL_MESSAGE_HEIGHT,
        )
        self.assertEqual(tx.plaintext.decode("utf-8"), "café")


class TestActivationGateOnVerify(unittest.TestCase):
    """verify_transaction must hard-gate the post-fork validator on
    chain height — a v1 tx whose plaintext bytes happen to be UTF-8
    multi-byte sequences must NOT pass at heights < INTL_MESSAGE_HEIGHT.

    This is the consensus-critical part of the change: a misbehaving
    or malicious sender that crafts a tx with non-ASCII bytes pre-fork
    would otherwise drift the chain across the activation point in a
    way that not all replayers would agree on.
    """

    def test_pre_fork_rejects_non_ascii_bytes(self):
        # Build a tx at the post-fork height (so creation succeeds with
        # UTF-8), then verify it under a pre-fork height — chain must
        # reject because the activation gate hasn't fired yet.
        e = _new_entity()
        tx = create_transaction(
            e, "café", fee=10_000, nonce=0,
            current_height=config.INTL_MESSAGE_HEIGHT,
        )
        ok = verify_transaction(
            tx, e.public_key,
            current_height=config.INTL_MESSAGE_HEIGHT - 1,
        )
        self.assertFalse(ok)

    def test_post_fork_accepts_utf8(self):
        e = _new_entity()
        tx = create_transaction(
            e, "Привет, мир", fee=10_000, nonce=0,
            current_height=config.INTL_MESSAGE_HEIGHT,
        )
        ok = verify_transaction(
            tx, e.public_key,
            current_height=config.INTL_MESSAGE_HEIGHT,
        )
        self.assertTrue(ok)

    def test_post_fork_rejects_emoji(self):
        # Emoji are blocked by the create_transaction validator, so to
        # exercise the verify-side defense we bypass the create path
        # and construct the tx directly with raw UTF-8 bytes — the
        # threat model is a malicious sender on the wire bypassing any
        # client-side filter.
        from messagechain.core.transaction import (
            MessageTransaction, calculate_min_fee,
        )
        from messagechain.core.compression import encode_payload
        from messagechain.crypto.hashing import default_hash
        from messagechain.crypto.keys import Signature

        e = _new_entity()
        plaintext = "hi 😀".encode("utf-8")
        stored, flag = encode_payload(plaintext)
        fee = calculate_min_fee(
            stored, current_height=config.INTL_MESSAGE_HEIGHT
        )
        tx = MessageTransaction(
            entity_id=e.entity_id,
            message=stored,
            timestamp=int(__import__("time").time()),
            nonce=0,
            fee=fee,
            signature=Signature([], 0, [], b"", b""),
            version=1,
            compression_flag=flag,
        )
        # Sign so verify gets past the signature step and reaches the
        # plaintext content gate.
        msg_hash = default_hash(tx._signable_data())
        tx.signature = e.keypair.sign(msg_hash)
        tx.tx_hash = tx._compute_hash()

        ok = verify_transaction(
            tx, e.keypair.public_key,
            current_height=config.INTL_MESSAGE_HEIGHT,
        )
        self.assertFalse(ok)


class TestForkOrderingInvariant(unittest.TestCase):
    """INTL_MESSAGE_HEIGHT must follow FIRST_SEND_PUBKEY_HEIGHT to keep
    the bootstrap-compressed schedule in order."""

    def test_intl_after_first_send(self):
        self.assertGreater(
            config.INTL_MESSAGE_HEIGHT, config.FIRST_SEND_PUBKEY_HEIGHT
        )


if __name__ == "__main__":
    unittest.main()
