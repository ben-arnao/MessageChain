"""scripts/install-validator.sh embeds a copy of the SSH allowed-signers
list that ``messagechain upgrade`` uses to verify release tags.  Both
must stay in lockstep -- a divergence either lets the bootstrap script
accept tags that the upgrade CLI rejects (silent downgrade of trust)
or vice-versa (operator-confusing failures).  This test reads the
heredoc out of the bash script and asserts byte-for-byte equality
against ``messagechain.release_signers.ALLOWED_SIGNERS``.

If you rotated the release signer, update both files in the same
commit; this test is the trip-wire that catches the missed half.
"""
import os
import unittest

from messagechain.release_signers import ALLOWED_SIGNERS


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT_PATH = os.path.join(REPO_ROOT, "scripts", "install-validator.sh")

# Heredoc markers used in install-validator.sh.  If these are renamed,
# update them here too -- failure mode is the parity check looking
# for a delimiter that no longer exists, not a silent pass.
START_MARKER = "<<'PINNED_SIGNERS_EOF'"
END_MARKER = "PINNED_SIGNERS_EOF"


def _extract_pinned_signers(script_text: str) -> str:
    """Return the bytes between START_MARKER and END_MARKER as a
    string.  Raises if either marker is missing -- a structural
    failure the test should fail loudly on, not skip past.
    """
    # Find the line ending in START_MARKER (it's part of `read ... <<'EOF'`).
    lines = script_text.splitlines()
    start_idx = None
    for i, line in enumerate(lines):
        if START_MARKER in line:
            start_idx = i + 1
            break
    if start_idx is None:
        raise AssertionError(
            f"start marker {START_MARKER!r} not found in {SCRIPT_PATH}"
        )
    end_idx = None
    for j in range(start_idx, len(lines)):
        # End marker is on its own line, with no leading whitespace
        # (heredoc closing delimiter requirement).
        if lines[j] == END_MARKER:
            end_idx = j
            break
    if end_idx is None:
        raise AssertionError(
            f"end marker {END_MARKER!r} not found in {SCRIPT_PATH}"
        )
    # Heredoc body, joined with \n, plus the implicit trailing newline
    # the printf '%s\n' in the script adds back at use time.  This is
    # what makes the comparison meaningful against ALLOWED_SIGNERS,
    # which itself ends in \n (Python b"""\n...\n""" form).
    return "\n".join(lines[start_idx:end_idx]) + "\n"


class TestInstallValidatorSignersParity(unittest.TestCase):
    def test_script_pinned_signers_match_release_signers_module(self):
        with open(SCRIPT_PATH, "rb") as fh:
            script_text = fh.read().decode("utf-8")
        pinned = _extract_pinned_signers(script_text)
        self.assertEqual(
            pinned.encode("utf-8"),
            ALLOWED_SIGNERS,
            "scripts/install-validator.sh PINNED_ALLOWED_SIGNERS heredoc "
            "diverged from messagechain.release_signers.ALLOWED_SIGNERS. "
            "Update both in the same commit when rotating signers.",
        )


if __name__ == "__main__":
    unittest.main()
