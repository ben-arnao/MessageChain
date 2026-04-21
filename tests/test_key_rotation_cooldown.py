"""Iter 6 H2: KEY_ROTATION_COOLDOWN_BLOCKS enforcement.

Without a cooldown, a funded attacker can rotate every block (each
rotation costs KEY_ROTATION_FEE), churning chain state and erasing
forensic traceability of recent slashable behavior.  144-block
cooldown (~1 day at BLOCK_TIME_TARGET=600s) bounds spam to 365/yr —
economically irrational for legitimate use, lethal for spam.
"""

from __future__ import annotations

import unittest

from messagechain.config import KEY_ROTATION_COOLDOWN_BLOCKS


class TestKeyRotationCooldown(unittest.TestCase):

    def test_cooldown_constant_is_reasonable(self):
        # Not an attack vector but a sanity pin: zero cooldown is a bug.
        self.assertGreater(KEY_ROTATION_COOLDOWN_BLOCKS, 0)
        # Shouldn't be more than ~1 week either; operators need ability
        # to emergency-rotate on suspected key compromise.
        self.assertLess(KEY_ROTATION_COOLDOWN_BLOCKS, 1008)

    def test_cooldown_check_present_in_validate(self):
        """Pin the call site; regresssion if someone drops the cooldown
        check without explicitly removing the constant."""
        import pathlib
        repo = pathlib.Path(__file__).resolve().parent.parent
        src = (repo / "messagechain" / "core" / "blockchain.py").read_text(encoding="utf-8")
        # Both the import and the enforcement must be present.
        self.assertIn("KEY_ROTATION_COOLDOWN_BLOCKS", src)
        self.assertIn("key_rotation_last_height", src)


if __name__ == "__main__":
    unittest.main()
