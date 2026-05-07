"""Audit r31 #3 -- README §1 (Generate a private key) instructed
the user to back up the WRONG artifact.

Pre-fix README:

    messagechain generate-key    # write the printed hex on paper, 2–3 copies
    messagechain verify-key      # re-type to confirm the backup

But ``cmd_generate_key``'s actual output (cli.py:5108-5119) prints
the 24-word BIP-39 phrase as the primary backup ("write these down
IN ORDER", "the phrase will NOT be shown again") and labels hex
only as "alternative."  ``verify-key`` and the README's own §5
("Back up your wallet") describe the 24-word phrase as canonical.

Every new user follows the README in order, transcribes a 64-char
hex string, and only learns later that the protocol-blessed
backup is a different artifact.  A user who *only* writes the hex
has a valid backup -- but missed the entire reason ``generate-key``
was redesigned to show the phrase first: the BIP-39 checksum
catches single-word transcription errors when they re-type it on
recovery, while the hex form has no typo protection at all.

CLAUDE.md anchors at risk:
  - Principle #3 (Simplicity): the simplest first-step instruction
    should not steer users toward the worse-of-two backup forms.
  - Lost-keys-permanent: any backup-loss footgun on the very first
    command of every new user is the highest-stakes UX defect on
    the chain.
  - Mission target users (dissidents / AI-spam refugees): both
    populations are heavily non-English-speaking; the BIP-39
    word list and checksum are the recovery affordance the chain
    actively builds for them.

Fix: update the inline comment and the supporting paragraph so
step 1 names the 24-word phrase as the artifact to back up, with
the hex form mentioned only as a fallback.

This test pins:
  (1) The §1 inline instruction names "phrase" or "24 words" --
      not "hex" -- as the artifact to write on paper.
  (2) The §1 paragraph explains the BIP-39 checksum advantage so
      a reader understands WHY the phrase is preferred over hex.
"""

from __future__ import annotations

import pathlib
import re
import unittest


def _readme_text() -> str:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    readme = repo_root / "README.md"
    return readme.read_text(encoding="utf-8")


def _step1_block(readme: str) -> str:
    """Extract the §1 'Generate a private key' block: from the
    heading line through the next ``###`` heading."""
    pat = re.compile(
        r"### 1\. Generate a private key.*?(?=\n### )",
        re.DOTALL,
    )
    m = pat.search(readme)
    if m is None:
        raise AssertionError(
            "README §1 (Generate a private key) section heading not "
            "found.  Either the heading was renamed (in which case "
            "this test's regex needs an update) or the section was "
            "removed (which would itself be a regression)."
        )
    return m.group(0)


class TestReadmeStep1NamesPhraseNotHex(unittest.TestCase):
    """README §1's inline instruction should name the 24-word phrase
    as the artifact to back up, NOT the hex form."""

    def test_step1_does_not_instruct_writing_hex(self):
        block = _step1_block(_readme_text())
        # The buggy phrasing was: ``write the printed hex on paper``.
        # That exact phrase, or any "write ... hex" instruction in
        # §1, is the regression.
        self.assertNotRegex(
            block,
            r"write[^.\n]*hex[^.\n]*paper",
            "README §1 MUST NOT instruct users to write the printed "
            "hex on paper -- generate-key prints the 24-word BIP-39 "
            "phrase as the primary backup.  The hex form has no "
            "typo-detection checksum.",
        )

    def test_step1_names_phrase_or_24_words(self):
        block = _step1_block(_readme_text())
        self.assertRegex(
            block,
            r"(?i)24[ -]word|recovery phrase|phrase",
            "README §1 MUST name the 24-word phrase (or 'recovery "
            "phrase') as the artifact to back up.  This is the "
            "primary output of generate-key; the hex form is only "
            "labeled 'alternative.'",
        )


class TestReadmeStep1ExplainsBip39Advantage(unittest.TestCase):
    """README §1 should explain why the phrase is preferred over the
    hex -- the BIP-39 checksum catches single-word transcription
    errors when the user re-types on recovery, the hex form has no
    such protection.  Without the why, a user who 'just prefers'
    a shorter backup will pick the hex form and lose error
    protection without realizing it."""

    def test_step1_mentions_checksum_or_typo_protection(self):
        block = _step1_block(_readme_text())
        self.assertRegex(
            block,
            r"(?i)checksum|typo|transcription",
            "README §1 should explain that the phrase has built-in "
            "typo protection (the BIP-39 checksum) so a reader "
            "understands why phrase > hex.  Without this they may "
            "still pick the hex form for brevity and lose recovery "
            "safety.",
        )


if __name__ == "__main__":
    unittest.main()
