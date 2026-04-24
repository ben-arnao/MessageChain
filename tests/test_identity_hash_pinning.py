"""
Invariant tests for the identity-hash pinning.

Before the fix, `derive_entity_id` and `_derive_signing_seed` both
called `default_hash`, which dispatches through `HASH_VERSION_CURRENT`.
The instant a governance proposal bumped the current hash version,
every existing account's computed entity_id AND every existing
user's signing seed would change — silently orphaning every on-chain
balance and breaking every user's ability to sign for their own
account.  For a chain designed to run 100–1000 years and rotate its
hash family at least once along the way, that is a blocker.

The pin moves both derivations to `hash_v(..., IDENTITY_HASH_VERSION)`
where `IDENTITY_HASH_VERSION` is a separate register frozen at
genesis.  These tests prove the bindings are now byte-stable under a
simulated `HASH_VERSION_CURRENT` rotation.

Treasury ID is pinned via the same principle, but spelled out as a
bare "sha3_256" string literal so a future ``HASH_ALGO`` edit can't
silently move the 40M-token treasury to a different address either.
"""

import hashlib
import unittest
from unittest.mock import patch

import messagechain.config as cfg
import messagechain.crypto.hashing as hashing
from messagechain.identity.identity import (
    derive_entity_id,
    _derive_signing_seed,
)


class TestIdentityHashPinning(unittest.TestCase):
    """Identity derivations must return identical bytes before and after
    a (simulated) HASH_VERSION_CURRENT rotation.  That is exactly the
    migration path CLAUDE.md advertises — if it silently moves every
    account to a new address, the agility story is broken."""

    def test_entity_id_stable_across_hash_version_bump(self):
        pk = bytes(range(32))
        baseline = derive_entity_id(pk)

        with patch.object(cfg, "HASH_VERSION_CURRENT", 99), \
             patch.dict(hashing._ALGO_BY_VERSION, {99: "blake2b"}):
            # Sanity: default_hash IS now producing a different digest.
            # (If this assertion fails, the simulation isn't reaching
            # the dispatcher and the later identity check is vacuous.)
            from messagechain.crypto.hashing import default_hash
            self.assertNotEqual(
                default_hash(b"probe"),
                hashlib.new("sha3_256", b"probe").digest(),
            )
            # And yet entity_id MUST stay identical — that's the pin.
            rotated = derive_entity_id(pk)
            self.assertEqual(baseline, rotated)

    def test_signing_seed_stable_across_hash_version_bump(self):
        sk = bytes(range(32, 64))
        baseline = _derive_signing_seed(sk)

        with patch.object(cfg, "HASH_VERSION_CURRENT", 99), \
             patch.dict(hashing._ALGO_BY_VERSION, {99: "blake2b"}):
            rotated = _derive_signing_seed(sk)
            self.assertEqual(baseline, rotated)

    def test_identity_hash_version_constant_defined(self):
        """The pin is an explicit register, not an accidental literal."""
        self.assertTrue(hasattr(cfg, "IDENTITY_HASH_VERSION"))
        self.assertEqual(cfg.IDENTITY_HASH_VERSION, cfg.HASH_VERSION_SHA256)

    def test_entity_id_equals_pinned_sha3_256(self):
        """Concrete vector: derive_entity_id must byte-equal an inline
        SHA3-256 computation — so any future hash switcheroo shows up
        as a test failure, not a consensus fork."""
        pk = b"\x11" * 32
        expected = hashlib.new(
            "sha3_256", b"entity_id" + pk,
        ).digest()
        self.assertEqual(derive_entity_id(pk), expected)

    def test_signing_seed_equals_pinned_sha3_256(self):
        sk = b"\x22" * 32
        expected = hashlib.new(
            "sha3_256", b"signing_seed" + sk,
        ).digest()
        self.assertEqual(_derive_signing_seed(sk), expected)


class TestTreasuryIdPinning(unittest.TestCase):
    """TREASURY_ENTITY_ID is a 32-byte address derived once at import.
    Its hash-family spelling must be a bare string literal, NOT a
    reference to ``HASH_ALGO`` or any dispatcher register — otherwise
    a future edit to those constants silently relocates 40M tokens to
    an unowned address."""

    def test_treasury_id_is_sha3_256_of_fixed_domain_tag(self):
        expected = hashlib.new(
            "sha3_256", b"messagechain-treasury-v1",
        ).digest()
        self.assertEqual(cfg.TREASURY_ENTITY_ID, expected)

    def test_treasury_id_unaffected_by_hash_version_dispatcher(self):
        """Even if a future governance bump rotates
        HASH_VERSION_CURRENT, TREASURY_ENTITY_ID is already bound at
        module import and stays fixed."""
        baseline = cfg.TREASURY_ENTITY_ID
        with patch.object(cfg, "HASH_VERSION_CURRENT", 99), \
             patch.dict(hashing._ALGO_BY_VERSION, {99: "blake2b"}):
            self.assertEqual(cfg.TREASURY_ENTITY_ID, baseline)


if __name__ == "__main__":
    unittest.main()
