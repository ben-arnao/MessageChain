"""
State root must commit to ALL per-entity chain state, not just
(balance, nonce, stake).

Before this was fixed, two honest nodes could disagree on:
  - who has been revoked
  - what each entity's cold authority key is
  - what each entity's signing (hot) public key is after a rotation
  - where each entity's WOTS+ leaf watermark sits
  - how many rotations an entity has done

...and still produce matching state_roots, because the SparseMerkleTree
leaf only hashed balance/nonce/stake.

That breaks the core guarantee of a state commitment: "if your root
matches mine, we agree on state."  Every field below is part of
consensus-critical state, so every field must be inside the leaf hash.
"""

import unittest

from messagechain import config
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def _twin_chains(self, seed: bytes):
        """Return two fresh chains each registered with a freshly-built
        Entity from the same seed.  Using two Entity instances (rather
        than sharing one) keeps both keypairs' internal leaf cursors in
        lockstep — otherwise registering the same object twice would
        consume different leaves on each chain and diverge baseline
        watermarks before the test even starts.

        Returns (chain_a, chain_b, entity_a, entity_b); the two entities
        have identical public keys and entity_ids, so the callsite can
        use entity_a.entity_id as a shared handle.
        """
        entity_a = _entity(seed)
        entity_b = _entity(seed)
        assert entity_a.entity_id == entity_b.entity_id
        a = Blockchain()
        b = Blockchain()
        self._register(a, entity_a)
        self._register(b, entity_b)
        root_a = a.compute_current_state_root()
        root_b = b.compute_current_state_root()
        self.assertEqual(
            root_a, root_b,
            "baseline roots must match; test setup is broken otherwise",
        )
        return a, b, entity_a


class TestStateRootCoversRevocation(_Base):
    def test_revoked_entity_changes_state_root(self):
        a, b, alice = self._twin_chains(b"alice-rev")
        a.revoked_entities.add(alice.entity_id)
        # _touch_state is how mutations propagate to the tree; call it so
        # the test measures commitment coverage, not propagation timing.
        a._touch_state({alice.entity_id})
        self.assertNotEqual(
            a.compute_current_state_root(),
            b.compute_current_state_root(),
            "state_root must differ when revoked_entities differs",
        )


class TestStateRootCoversAuthorityKey(_Base):
    def test_authority_key_change_changes_state_root(self):
        a, b, alice = self._twin_chains(b"alice-ak")
        a.authority_keys[alice.entity_id] = b"\x11" * 32
        a._touch_state({alice.entity_id})
        self.assertNotEqual(
            a.compute_current_state_root(),
            b.compute_current_state_root(),
            "state_root must differ when authority_keys differs",
        )


class TestStateRootCoversPublicKey(_Base):
    def test_public_key_rotation_changes_state_root(self):
        a, b, alice = self._twin_chains(b"alice-pk")
        a.public_keys[alice.entity_id] = b"\x22" * 32
        a._touch_state({alice.entity_id})
        self.assertNotEqual(
            a.compute_current_state_root(),
            b.compute_current_state_root(),
            "state_root must differ when public_keys differs",
        )


class TestStateRootCoversLeafWatermark(_Base):
    def test_watermark_advance_changes_state_root(self):
        a, b, alice = self._twin_chains(b"alice-wm")
        a.leaf_watermarks[alice.entity_id] = 5
        a._touch_state({alice.entity_id})
        self.assertNotEqual(
            a.compute_current_state_root(),
            b.compute_current_state_root(),
            "state_root must differ when leaf_watermarks differs",
        )


class TestStateRootCoversRotationCount(_Base):
    def test_rotation_count_changes_state_root(self):
        a, b, alice = self._twin_chains(b"alice-rc")
        a.key_rotation_counts[alice.entity_id] = 3
        a._touch_state({alice.entity_id})
        self.assertNotEqual(
            a.compute_current_state_root(),
            b.compute_current_state_root(),
            "state_root must differ when key_rotation_counts differs",
        )


class TestStateRootCoversSlashed(_Base):
    """slashed_validators must be inside the leaf commitment for the
    same reason revoked_entities is: the "already slashed" guard in
    apply_slash_transaction reads from this set, so two nodes with
    diverging sets could accept/reject the same double-slash tx
    differently.  Rare in practice (reorg restores it properly), but
    the invariant "state_root pins down all consensus-critical state"
    must not depend on that.
    """

    def test_slashed_entity_changes_state_root(self):
        a, b, alice = self._twin_chains(b"alice-sl")
        a.slashed_validators.add(alice.entity_id)
        a._touch_state({alice.entity_id})
        self.assertNotEqual(
            a.compute_current_state_root(),
            b.compute_current_state_root(),
            "state_root must differ when slashed_validators differs",
        )


if __name__ == "__main__":
    unittest.main()
