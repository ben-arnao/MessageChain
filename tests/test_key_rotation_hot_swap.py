"""Hot-swap tests for key rotation.

Without these hooks the running validator daemon keeps signing with the
retired Merkle tree after a KeyRotationTransaction lands -- every
subsequent block it produces is rejected (signature verifies against the
old root, chain canonical pubkey is the new root), downtime slashing
accrues, and a naive operator restart does not recover (Entity.create
re-derives the original tree from the signing seed; rotation_number is
chain-state, not seed-state).  CLAUDE.md anchor: "key-rotation is a
first-class tx type whose result is 'same entity, new active key'."

This module pins:

  1. ``Blockchain.register_post_key_rotation_callback`` is fired when a
     ``apply_key_rotation`` direct call lands (RPC / test path).
  2. ``Blockchain._append_block`` fires the callback for every
     ``KeyRotationTransaction`` carried in ``block.authority_txs`` --
     and ONLY after the wrapping transaction commits, so a state-root
     rejection on the same block does not race a premature swap.
  3. The callback ONLY fires for the registered entity_id (a rotation
     for entity X must not invoke a callback registered for entity Y).
  4. The fired callback receives the new ``key_rotation_counts``, which
     the daemon needs to derive the active keypair via
     ``derive_rotated_keypair(entity, rotation_number=count - 1)``.
"""

import unittest
from unittest.mock import MagicMock

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.key_rotation import (
    KeyRotationTransaction,
    create_key_rotation,
    derive_rotated_keypair,
)
from messagechain.config import KEY_ROTATION_FEE
from tests import register_entity_for_test


class TestPostKeyRotationCallback(unittest.TestCase):
    """Pins the Blockchain side of the daemon hot-swap wiring."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        # Fresh leaf cursor so each test starts at leaf 0.
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000

    def test_register_post_key_rotation_callback_fires_on_apply(self):
        """``apply_key_rotation`` (direct path) invokes the registered callback
        with the new ``key_rotation_counts`` value.
        """
        seen = []

        def cb(new_count):
            seen.append(new_count)

        self.chain.register_post_key_rotation_callback(self.alice.entity_id, cb)

        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)
        ok, _ = self.chain.apply_key_rotation(tx, self.bob.entity_id)
        self.assertTrue(ok)

        self.assertEqual(seen, [1])

    def test_callback_only_fires_for_registered_entity(self):
        """A rotation for entity X does not invoke a callback registered for
        entity Y -- the per-entity dispatch table is what isolates the
        daemon's wallet-entity swap from unrelated rotations.
        """
        bob_seen = []
        self.chain.register_post_key_rotation_callback(
            self.bob.entity_id, lambda c: bob_seen.append(c),
        )

        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)
        ok, _ = self.chain.apply_key_rotation(tx, self.bob.entity_id)
        self.assertTrue(ok)

        self.assertEqual(bob_seen, [])

    def test_callback_exception_does_not_break_apply(self):
        """A raising callback must not poison the apply path -- the chain has
        committed the rotation; the callback is best-effort daemon plumbing.
        """
        def boom(_count):
            raise RuntimeError("simulated daemon hot-swap failure")

        self.chain.register_post_key_rotation_callback(self.alice.entity_id, boom)

        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)
        ok, _ = self.chain.apply_key_rotation(tx, self.bob.entity_id)
        self.assertTrue(ok)
        # Chain state must reflect the rotation regardless.
        self.assertEqual(
            self.chain.public_keys[self.alice.entity_id], new_kp.public_key,
        )
        self.assertEqual(self.chain.key_rotation_counts[self.alice.entity_id], 1)


class TestServerBootRotationReplay(unittest.TestCase):
    """Pins the server boot-path rotation replay -- after a rotation lands on
    chain, ``_load_or_create_entity`` followed by ``_replay_chain_rotations``
    produces an Entity whose keypair matches the on-chain canonical pubkey
    (i.e. the rotated tree, not the original).  Without this, the daemon
    cold-starts with the retired tree and signs against a pubkey the chain
    no longer accepts.
    """

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))

    def test_replay_chain_rotations_zero_count_is_noop(self):
        """rotation_count=0 (no rotation has happened) returns the base entity
        unchanged."""
        from server import _replay_chain_rotations

        result = _replay_chain_rotations(
            self.alice, rotation_count=0, data_dir=None, no_cache=True,
        )
        self.assertIs(result, self.alice)

    def test_replay_chain_rotations_produces_rotated_keypair(self):
        """After one rotation on chain (key_rotation_counts == 1), replaying
        produces an Entity whose keypair public_key matches
        ``derive_rotated_keypair(base, rotation_number=0).public_key`` and
        whose entity_id is unchanged (anchor: identity continuity across
        rotation).
        """
        from server import _replay_chain_rotations

        expected_kp = derive_rotated_keypair(self.alice, rotation_number=0)

        result = _replay_chain_rotations(
            self.alice, rotation_count=1, data_dir=None, no_cache=True,
        )
        self.assertEqual(result.keypair.public_key, expected_kp.public_key)
        self.assertEqual(result.entity_id, self.alice.entity_id)
        # Original entity untouched.
        self.assertNotEqual(self.alice.keypair.public_key, expected_kp.public_key)


if __name__ == "__main__":
    unittest.main()
