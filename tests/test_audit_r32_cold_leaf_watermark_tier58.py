"""Audit r32 #1 -- Cold authority key has NO chain-state WOTS+ leaf
watermark.

Pre-fix: ``Blockchain._validate_unstake_tx_in_block`` and
``validate_revoke`` verified signature / nonce / balance but NEVER
checked any cold-key leaf watermark.  ``apply_revoke`` and the
unstake apply path bumped the HOT-key watermark only when
``authority_pk == signing_pk``; cold-key-promoted entities never got
a watermark advance.  ``validate_set_authority_key``'s Tier-46
cold counter-signature check verified the cold sig but did NOT track
its leaf usage either.

Concrete bite (twin of audit r31 #1 cross-pool fix on the cold-key
side): an operator pre-signs an offline emergency revoke at
cold-key leaf=N (the documented hardening pattern in
``messagechain/core/emergency_revoke.py`` docstring lines 21-30),
then later signs an unstake / set-authority-key / fresh revoke at
the SAME cold-key leaf=N.  Both txs admit and apply.  Anyone
observing both signatures recovers the WOTS+ one-time secret for
that leaf and forges arbitrary cold-key signatures.

Tier 58 closes the gap: a new ``cold_leaf_watermarks`` dict keyed by
cold-pubkey bytes tracks the highest leaf consumed by any
cold-key-signed tx.  Validation at and above
``COLD_LEAF_WATERMARK_HEIGHT`` rejects any tx whose
cold-sig leaf_index is below the watermark.  Apply bumps the
watermark identically to the hot-key path.

Pre-fork blocks replay byte-identically -- the new check only fires
at and above the activation height.
"""

from __future__ import annotations

import time
import unittest

from messagechain import config
from messagechain.config import (
    AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT,
    COLD_LEAF_WATERMARK_HEIGHT,
    REVOKE_TX_WINDOW_HEIGHT,
)
from messagechain.core.authority_key import (
    create_set_authority_key_rebind_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.emergency_revoke import create_revoke_transaction
from messagechain.core.staking import create_unstake_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


_ENTITY_POOL: dict[tuple[bytes, int], Entity] = {}


def _entity(seed: bytes, height: int = 4) -> Entity:
    """Module-cached entity factory; h=4 is enough for these tests."""
    padded = seed + b"\x00" * (32 - len(seed))
    key = (padded, height)
    cached = _ENTITY_POOL.get(key)
    if cached is None:
        cached = Entity.create(padded, tree_height=height)
        _ENTITY_POOL[key] = cached
    cached.keypair._next_leaf = 0
    return cached


def _pin_chain_height(chain: Blockchain, target_height: int):
    """Advance ``Blockchain.height`` to ``target_height`` by appending
    placeholder objects.  Mirrors helpers in other tier-gate tests.
    """
    while chain.height < target_height:
        chain.chain.append(object())


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain: Blockchain, entity: Entity) -> bool:
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        ok, _ = chain._install_pubkey_direct(
            entity.entity_id, entity.public_key, proof,
        )
        return ok


class TestActivationHeightConstant(unittest.TestCase):
    """Source pin: ``COLD_LEAF_WATERMARK_HEIGHT`` exists and is strictly
    above Tier 57 (``TRANSFER_FEE_UNIFIED_HEIGHT = 2100``)."""

    def test_constant_present_and_above_tier_57(self):
        from messagechain.config import (
            COLD_LEAF_WATERMARK_HEIGHT,
            TRANSFER_FEE_UNIFIED_HEIGHT,
        )
        self.assertGreater(
            COLD_LEAF_WATERMARK_HEIGHT,
            TRANSFER_FEE_UNIFIED_HEIGHT,
            "Tier 58 (COLD_LEAF_WATERMARK_HEIGHT) must follow Tier 57 "
            "so operators upgrade through Tier 57 before this admission-"
            "rule change binds, and so consensus-rule changes don't "
            "collapse into a single activation window.",
        )


class TestColdWatermarkDictExists(unittest.TestCase):
    """Source pin: Blockchain MUST initialize a ``cold_leaf_watermarks``
    dict.  Without this dict, the watermark check has nothing to look
    up against."""

    def test_blockchain_has_cold_leaf_watermarks(self):
        chain = Blockchain()
        self.assertTrue(
            hasattr(chain, "cold_leaf_watermarks"),
            "Blockchain MUST initialize self.cold_leaf_watermarks "
            "(dict[cold_pubkey_bytes, int]) for the Tier 58 check to "
            "have anywhere to read from.",
        )
        self.assertIsInstance(chain.cold_leaf_watermarks, dict)
        self.assertEqual(
            chain.cold_leaf_watermarks, {},
            "cold_leaf_watermarks MUST start empty -- entities with no "
            "prior cold-key txs have no watermark and any leaf is "
            "admissible (chain has no record yet).",
        )


class TestRevokeBumpsColdWatermarkPostFork(_Base):
    """Behavioral pin: a Revoke admitted post-Tier-58 MUST advance
    ``cold_leaf_watermarks[authority_pk]`` past the consumed leaf.
    Without this bump a second revoke / unstake / set-authority at the
    same cold-leaf would land and leak WOTS+ secret material."""

    def test_revoke_apply_bumps_cold_watermark(self):
        chain = Blockchain()
        alice = _entity(b"alice")
        self._register(chain, alice)
        chain.supply.balances[alice.entity_id] = 100_000

        # Promote a separate cold key.
        cold = _entity(b"alice_cold")
        chain.authority_keys[alice.entity_id] = cold.public_key

        _pin_chain_height(chain, COLD_LEAF_WATERMARK_HEIGHT)

        # Build a revoke signed by the cold key, in the windowed form
        # required at and above REVOKE_TX_WINDOW_HEIGHT.
        chain_h = chain.height + 1
        revoke = create_revoke_transaction(
            signer=cold,  # signs with cold.keypair
            entity_id=alice.entity_id,
            fee=100,
            valid_from_height=chain_h,
            valid_to_height=chain_h + 1000,
        )
        before = chain.cold_leaf_watermarks.get(cold.public_key, 0)
        ok, reason = chain.apply_revoke(revoke, proposer_id=alice.entity_id)
        self.assertTrue(ok, reason)
        after = chain.cold_leaf_watermarks.get(cold.public_key, 0)
        self.assertGreater(
            after, before,
            "apply_revoke MUST bump cold_leaf_watermarks[cold_pk] past "
            "the consumed leaf when chain_h >= COLD_LEAF_WATERMARK_HEIGHT.",
        )
        self.assertGreater(
            after, revoke.signature.leaf_index,
            "Watermark MUST be strictly greater than the consumed "
            "leaf_index (next-safe leaf, not the just-used one).",
        )


class TestRevokeRejectsReusedColdLeafPostFork(_Base):
    """Behavioral pin: post-Tier-58, two distinct cold-key-signed txs
    that share the same cold-leaf MUST NOT both pass admission.  The
    second one must be rejected before its signature lands on the
    public wire.  This is the core leak-prevention property: any two
    signatures at the same WOTS+ leaf reveal one-time-key secret
    material to anyone who observes both."""

    def test_unstake_at_used_revoke_cold_leaf_rejected(self):
        chain = Blockchain()
        alice = _entity(b"alice")
        self._register(chain, alice)
        chain.supply.balances[alice.entity_id] = 100_000
        chain.supply.staked[alice.entity_id] = 50_000

        # Promote separate cold key.
        cold = _entity(b"alice_cold")
        chain.authority_keys[alice.entity_id] = cold.public_key

        _pin_chain_height(chain, COLD_LEAF_WATERMARK_HEIGHT)

        # First cold-key tx: consume cold-leaf 0 with a revoke.
        chain_h = chain.height + 1
        revoke = create_revoke_transaction(
            signer=cold,
            entity_id=alice.entity_id,
            fee=100,
            valid_from_height=chain_h,
            valid_to_height=chain_h + 1000,
        )
        used_leaf = revoke.signature.leaf_index
        ok, _ = chain.apply_revoke(revoke, proposer_id=alice.entity_id)
        self.assertTrue(ok)
        # Un-revoke for the second-tx test (we want to exercise the
        # cold-leaf check, not the "already revoked" gate).
        chain.revoked_entities.discard(alice.entity_id)

        # Now build an unstake from the SAME cold key at the SAME leaf.
        # Rewind cold's local cursor so the next sign reuses the leaf
        # that the revoke already burned.
        cold.keypair._next_leaf = used_leaf

        unstake = create_unstake_transaction(
            entity=alice,
            amount=10_000,
            nonce=chain.nonces.get(alice.entity_id, 0),
            fee=100,
            signing_keypair=cold.keypair,
        )
        self.assertEqual(
            unstake.signature.leaf_index, used_leaf,
            "Test setup error: unstake should be at the same cold-leaf "
            "as the revoke we just applied.",
        )

        # The cold-leaf watermark gate MUST refuse the unstake at
        # admission time.
        ok, reason = chain._validate_unstake_tx_in_block(
            unstake,
            pending_nonces={},
            pending_balance_spent={},
        )
        self.assertFalse(
            ok,
            "_validate_unstake_tx_in_block MUST reject an unstake at a "
            "cold-leaf already consumed by a prior cold-key-signed tx "
            "(revoke / unstake / set-authority cold-counter-sig). "
            f"Got ok={ok}, reason={reason!r}",
        )
        self.assertIn(
            "leaf",
            reason.lower(),
            "Rejection reason MUST mention the leaf-reuse defect so the "
            "operator can diagnose: cold-key cursor desync, NOT a "
            "consensus state mismatch.",
        )


class TestPreForkBypass(_Base):
    """Replay determinism: pre-fork (height < COLD_LEAF_WATERMARK_HEIGHT)
    the new check MUST NOT fire.  Every historical block whose
    Revoke / Unstake / SetAuthorityKey was accepted by the legacy
    rules MUST continue to be accepted post-upgrade so historical
    re-validation is byte-identical."""

    def test_pre_fork_revoke_does_not_check_cold_watermark(self):
        chain = Blockchain()
        alice = _entity(b"alice")
        self._register(chain, alice)
        chain.supply.balances[alice.entity_id] = 100_000

        cold = _entity(b"alice_cold")
        chain.authority_keys[alice.entity_id] = cold.public_key

        # Pre-Tier-58: pin BELOW activation height.
        _pin_chain_height(chain, COLD_LEAF_WATERMARK_HEIGHT - 10)

        # Pre-seed the watermark: even with a "consumed" leaf in the
        # dict, pre-fork validation MUST ignore it.
        chain.cold_leaf_watermarks[cold.public_key] = 100

        chain_h = chain.height + 1
        revoke = create_revoke_transaction(
            signer=cold,
            entity_id=alice.entity_id,
            fee=100,
            valid_from_height=chain_h,
            valid_to_height=chain_h + 1000,
        )
        # leaf_index is 0 (much less than the seeded watermark of 100),
        # but pre-fork the check is bypassed.
        ok, reason = chain.validate_revoke(revoke)
        self.assertTrue(
            ok,
            f"Pre-Tier-58 validate_revoke MUST NOT consult "
            f"cold_leaf_watermarks (legacy bypass for replay "
            f"determinism). Got ok={ok}, reason={reason!r}",
        )


class TestSetAuthorityKeyColdCounterSigBumpsColdWatermark(_Base):
    """Behavioral pin: a Tier-46 SetAuthorityKey rebind carries a
    cold counter-signature signed by the EXISTING cold key.  Post-
    Tier-58 the cold counter-sig's leaf MUST also bump
    cold_leaf_watermarks[old_cold_pk] -- the same cold key whose
    leaf was consumed.  Without this bump an operator who pre-signs
    an offline rebind at cold-leaf=N could later sign a revoke at
    the same cold-leaf=N from the same cold key, leaking the
    secret on the second wire-broadcast."""

    def test_apply_set_authority_key_rebind_bumps_old_cold_watermark(self):
        chain = Blockchain()
        alice = _entity(b"alice")
        self._register(chain, alice)
        chain.supply.balances[alice.entity_id] = 100_000

        # Install an existing cold key (this is the "rebind" path).
        old_cold = _entity(b"alice_cold_v1")
        chain.authority_keys[alice.entity_id] = old_cold.public_key

        # Pin chain past Tier-46 and Tier-58.
        target = max(
            AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT,
            COLD_LEAF_WATERMARK_HEIGHT,
        ) + 1
        _pin_chain_height(chain, target)

        new_cold = _entity(b"alice_cold_v2")
        # Tx is signed with the hot key (alice) plus a cold counter-
        # signature from the OLD cold key (old_cold).
        tx = create_set_authority_key_rebind_transaction(
            entity=alice,
            new_authority_key=new_cold.public_key,
            nonce=chain.nonces.get(alice.entity_id, 0),
            fee=100,
            existing_cold_keypair=old_cold.keypair,
        )
        used_cold_leaf = tx.cold_signature.leaf_index

        before = chain.cold_leaf_watermarks.get(old_cold.public_key, 0)
        ok, reason = chain.apply_set_authority_key(
            tx, proposer_id=alice.entity_id,
        )
        self.assertTrue(ok, reason)
        after = chain.cold_leaf_watermarks.get(old_cold.public_key, 0)
        self.assertGreater(
            after, before,
            "apply_set_authority_key MUST bump "
            "cold_leaf_watermarks[old_cold_pk] when the cold "
            "counter-signature is present and chain_h >= "
            "COLD_LEAF_WATERMARK_HEIGHT.",
        )
        self.assertGreater(
            after, used_cold_leaf,
            "Watermark MUST be strictly greater than the consumed "
            "cold-counter-sig leaf_index.",
        )


if __name__ == "__main__":
    unittest.main()
