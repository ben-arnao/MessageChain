"""Version validators must use explicit acceptance sets.

Iter-4 design review finding: CLAUDE.md principle #3 (crypto agility)
requires that every signature/hash/wire-format version be migratable
via hard fork.  The SIG_VERSION validator already uses
_ACCEPTED_SIG_VERSIONS: frozenset[int] so that widening acceptance
during a migration window is a one-line data change.

The parallel validators (block serialization, tx serialization,
receipt version) were hard-coded to a single value.  A future
governance widen-and-accept upgrade would require editing the
validator function body, which is riskier than editing a frozenset
literal:

  - Literal:  _ACCEPTED_RECEIPT_VERSIONS = frozenset({1, 2})
  - Function: change the `if version != current:` logic each time

These tests pin the frozensets into existence so future contributors
don't "simplify" them back to the equality pattern.
"""

from __future__ import annotations

import unittest

import messagechain.config as cfg


class TestVersionValidatorAcceptanceSets(unittest.TestCase):

    def test_accepted_receipt_versions_exists_and_contains_current(self):
        self.assertTrue(
            hasattr(cfg, "_ACCEPTED_RECEIPT_VERSIONS"),
            "_ACCEPTED_RECEIPT_VERSIONS frozenset is required",
        )
        self.assertIsInstance(cfg._ACCEPTED_RECEIPT_VERSIONS, frozenset)
        self.assertIn(cfg.RECEIPT_VERSION, cfg._ACCEPTED_RECEIPT_VERSIONS)

    def test_accepted_block_serialization_versions_exists_and_contains_current(self):
        self.assertTrue(hasattr(cfg, "_ACCEPTED_BLOCK_SERIALIZATION_VERSIONS"))
        self.assertIsInstance(cfg._ACCEPTED_BLOCK_SERIALIZATION_VERSIONS, frozenset)
        self.assertIn(cfg.BLOCK_SERIALIZATION_VERSION, cfg._ACCEPTED_BLOCK_SERIALIZATION_VERSIONS)

    def test_accepted_tx_serialization_versions_exists_and_contains_current(self):
        self.assertTrue(hasattr(cfg, "_ACCEPTED_TX_SERIALIZATION_VERSIONS"))
        self.assertIsInstance(cfg._ACCEPTED_TX_SERIALIZATION_VERSIONS, frozenset)
        self.assertIn(cfg.TX_SERIALIZATION_VERSION, cfg._ACCEPTED_TX_SERIALIZATION_VERSIONS)

    def test_receipt_validator_uses_set_membership(self):
        # A future RECEIPT_VERSION=2 rollout ships by ADDING 2 to the
        # frozenset, not by editing the validator body.  We prove the
        # validator respects extended sets by monkeypatching one in.
        original = cfg._ACCEPTED_RECEIPT_VERSIONS
        try:
            cfg._ACCEPTED_RECEIPT_VERSIONS = frozenset({1, 99})
            ok, _ = cfg.validate_receipt_version(99)
            self.assertTrue(ok, "validator must read the frozenset, not a literal")
            ok, _ = cfg.validate_receipt_version(1)
            self.assertTrue(ok, "current version must still validate")
            ok, _ = cfg.validate_receipt_version(42)
            self.assertFalse(ok, "unknown versions still rejected")
        finally:
            cfg._ACCEPTED_RECEIPT_VERSIONS = original

    def test_block_validator_uses_set_membership(self):
        original = cfg._ACCEPTED_BLOCK_SERIALIZATION_VERSIONS
        try:
            cfg._ACCEPTED_BLOCK_SERIALIZATION_VERSIONS = frozenset({1, 99})
            ok, _ = cfg.validate_block_serialization_version(99)
            self.assertTrue(ok)
            ok, _ = cfg.validate_block_serialization_version(42)
            self.assertFalse(ok)
        finally:
            cfg._ACCEPTED_BLOCK_SERIALIZATION_VERSIONS = original

    def test_tx_validator_uses_set_membership(self):
        original = cfg._ACCEPTED_TX_SERIALIZATION_VERSIONS
        try:
            cfg._ACCEPTED_TX_SERIALIZATION_VERSIONS = frozenset({1, 99})
            ok, _ = cfg.validate_tx_serialization_version(99)
            self.assertTrue(ok)
            ok, _ = cfg.validate_tx_serialization_version(42)
            self.assertFalse(ok)
        finally:
            cfg._ACCEPTED_TX_SERIALIZATION_VERSIONS = original


if __name__ == "__main__":
    unittest.main()
