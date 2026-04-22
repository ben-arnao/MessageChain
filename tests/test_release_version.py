"""
Tests for messagechain.core.release_version — strict semver parsing and
ordering helpers used by the release-manifest monotonic guard.

Why this module exists: the original monotonic guard in blockchain.py
used plain Python `<=` on version strings, which breaks at every
9 -> 10 digit boundary (e.g. "0.10.0" < "0.9.0" under string compare).
That is a silent-data-loss bug: the tx is block-valid but the state
slot is not advanced.  This helper provides a narrow, stdlib-only
parser + comparator so the guard can be tight and deterministic.

Intentionally NOT a general semver library: we only need what the
chain needs, the project forbids external deps, and a 1000-year chain
benefits from a tiny well-tested helper over a vendored library.
"""

import unittest

from messagechain.core.release_version import (
    parse_release_version,
    release_version_is_strictly_newer,
)


class TestParseReleaseVersion(unittest.TestCase):

    # ─── Valid inputs ────────────────────────────────────────────
    def test_zero_version(self):
        self.assertEqual(parse_release_version("0.0.0"), (0, 0, 0, None))

    def test_simple_triple(self):
        self.assertEqual(parse_release_version("1.2.3"), (1, 2, 3, None))

    def test_nine_to_ten_boundary_minor(self):
        # THE bug: "0.10.0" under string compare < "0.9.0".  The parser
        # must treat 10 > 9 as integers.
        self.assertEqual(parse_release_version("0.10.0"), (0, 10, 0, None))

    def test_major_greater_than_ten(self):
        self.assertEqual(parse_release_version("10.0.0"), (10, 0, 0, None))

    def test_patch_nines(self):
        self.assertEqual(parse_release_version("0.9.9"), (0, 9, 9, None))

    def test_prerelease_rc(self):
        self.assertEqual(
            parse_release_version("1.2.3-rc1"), (1, 2, 3, "rc1"),
        )

    def test_prerelease_with_dots(self):
        self.assertEqual(
            parse_release_version("1.2.3-alpha.1"),
            (1, 2, 3, "alpha.1"),
        )

    def test_prerelease_single_digit(self):
        self.assertEqual(
            parse_release_version("0.0.0-0"), (0, 0, 0, "0"),
        )

    # ─── Rejections ──────────────────────────────────────────────
    def test_empty_string_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("")

    def test_only_two_parts_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.2")

    def test_four_parts_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.2.3.4")

    def test_leading_zero_rejected(self):
        # "01.0.0" is a strict-semver no-go.  Also catches sneaky
        # attacker-crafted tags like "01.2.3" that parse "the same"
        # under loose regexes but are non-canonical.
        with self.assertRaises(ValueError):
            parse_release_version("01.0.0")

    def test_leading_zero_minor_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.02.0")

    def test_leading_zero_patch_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.0.02")

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.-1.0")

    def test_empty_prerelease_tag_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.2.3-")

    def test_space_in_prerelease_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.2.3- ")

    def test_non_alnum_in_prerelease_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.2.3-rc!")

    def test_non_ascii_rejected(self):
        # Cyrillic lookalike digits — critical sanity for a long-horizon
        # chain where an attacker might try to smuggle a "version" that
        # parses under one locale but not another.
        with self.assertRaises(ValueError):
            parse_release_version("1.2.\u0661")  # arabic-indic 1

    def test_null_byte_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.2.3\x00")

    def test_trailing_whitespace_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version("1.2.3 ")

    def test_leading_whitespace_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version(" 1.2.3")

    def test_absurdly_long_rejected(self):
        # Cap at 64 chars — anything longer is almost certainly a DoS
        # or a smuggled blob, not a real release tag.
        with self.assertRaises(ValueError):
            parse_release_version("1." + "2" * 65 + ".3")

    def test_bare_plus_build_metadata_rejected(self):
        # We intentionally don't support build metadata (`+...`).  If
        # someone slips "1.2.3+build42" in, reject — simpler is better.
        with self.assertRaises(ValueError):
            parse_release_version("1.2.3+build42")

    def test_v_prefix_rejected(self):
        # Many taggers use "v1.2.3", but our wire format is strict.
        # The operator-facing CLI can strip the `v`; the protocol
        # layer should not guess.
        with self.assertRaises(ValueError):
            parse_release_version("v1.2.3")

    def test_non_string_rejected(self):
        with self.assertRaises(ValueError):
            parse_release_version(123)  # type: ignore[arg-type]


class TestReleaseVersionOrdering(unittest.TestCase):

    def test_nine_to_ten_minor_bump(self):
        # Regression for the lex-compare bug.
        self.assertTrue(release_version_is_strictly_newer("0.10.0", "0.9.0"))
        self.assertFalse(release_version_is_strictly_newer("0.9.0", "0.10.0"))

    def test_major_rollover(self):
        self.assertTrue(release_version_is_strictly_newer("2.0.0", "1.99.99"))
        self.assertFalse(release_version_is_strictly_newer("1.99.99", "2.0.0"))

    def test_minor_rollover(self):
        self.assertTrue(release_version_is_strictly_newer("1.1.0", "1.0.999"))

    def test_patch_bump(self):
        self.assertTrue(release_version_is_strictly_newer("1.0.1", "1.0.0"))

    def test_equal_is_not_strictly_newer(self):
        self.assertFalse(release_version_is_strictly_newer("1.2.3", "1.2.3"))

    def test_release_beats_prerelease_same_core(self):
        # 0.2.0 > 0.2.0-rc1: a proper release supersedes an rc with
        # the same core.
        self.assertTrue(release_version_is_strictly_newer("0.2.0", "0.2.0-rc1"))
        self.assertFalse(
            release_version_is_strictly_newer("0.2.0-rc1", "0.2.0"),
        )

    def test_prerelease_lex_order(self):
        # Documented simplification: prereleases compare by lex of the
        # tag.  "rc2" > "rc1".
        self.assertTrue(
            release_version_is_strictly_newer("0.2.0-rc2", "0.2.0-rc1"),
        )
        self.assertFalse(
            release_version_is_strictly_newer("0.2.0-rc1", "0.2.0-rc2"),
        )
        self.assertFalse(
            release_version_is_strictly_newer("0.2.0-rc1", "0.2.0-rc1"),
        )

    def test_both_sides_fail_to_parse_returns_false(self):
        self.assertFalse(release_version_is_strictly_newer("garbage", "nope"))

    def test_candidate_fails_to_parse_returns_false(self):
        self.assertFalse(release_version_is_strictly_newer("01.0.0", "0.1.0"))

    def test_current_fails_to_parse_returns_false(self):
        # Even if the candidate is "newer in some sense", an unparseable
        # current is ambiguous — the comparator refuses to speak.
        self.assertFalse(release_version_is_strictly_newer("1.0.0", "garbage"))

    def test_fuzz_adversarial_inputs_do_not_crash(self):
        # The comparator must never raise — it returns False on
        # anything it doesn't understand.
        adversarial = [
            "", "1", "1.2", "1.2.3.4", "01.0.0", "1.-1.0",
            "1.2.3-", "1.2.3 ", "1.2.3-rc!", "1.2.3\x00",
            "v1.2.3", "1.2.3+build", "\x00\x00\x00",
            "1." + "2" * 128 + ".3", "nan.nan.nan",
        ]
        for a in adversarial:
            for b in adversarial:
                # Should never raise.
                self.assertIsInstance(
                    release_version_is_strictly_newer(a, b), bool,
                )


if __name__ == "__main__":
    unittest.main()
