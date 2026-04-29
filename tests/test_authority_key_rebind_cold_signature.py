"""
Tier 46 — SetAuthorityKey rebind requires cold-key counter-signature.

Threat model: a 24/7 online validator's hot signing key is the most
exposed surface in the entire validator's key material. The whole
purpose of the cold authority key (introduced earlier in the project)
was to keep destructive operations behind a key that NEVER touches the
running server. But until Tier 46 the SetAuthorityKey transaction
itself was signed only by the hot key. An attacker who steals the hot
key could broadcast SetAuthorityKey(new_authority_key=ATTACKER_COLD)
and inherit the cold-key role. The legitimate operator could no longer
revoke (revoke is signed by the now-attacker cold key) or unstake. The
"cold key" defense was therefore equivalent to the hot key in
practice.

Fix: at AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT and above, a
SetAuthorityKey tx that *re-binds* an already-installed authority key
MUST carry a second signature, verified under the EXISTING cold key.
First-time install (when no authority key has ever been installed) is
unchanged — that path is the bootstrap, and the user is authenticating
"as themselves" with the only key they have. Pre-fork blocks verify
byte-identically as before.
"""

import time
import unittest
from unittest.mock import patch

from messagechain import config
from messagechain.core.authority_key import (
    SetAuthorityKeyTransaction,
    create_set_authority_key_transaction,
    verify_set_authority_key_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _pin_chain_height(chain: Blockchain, target_height: int):
    """Push ``Blockchain.height`` to ``target_height`` by appending
    placeholder objects to ``chain.chain``.

    ``Blockchain.height`` is a read-only property that returns
    ``len(self.chain)`` so we cannot assign to it directly. The
    activation-gate validation reads ``self.height + 1`` as the
    "current chain height", so a target of ``N`` here means "the next
    block goes at height N+1".  Mirrors the helper in
    ``test_revoke_tx_window_bound``.
    """
    while chain.height < target_height:
        chain.chain.append(object())


class TestActivationHeightConstant(unittest.TestCase):
    """The activation height constant must exist and follow the
    cohort-spacing convention (>= Tier 45 + 700)."""

    def test_constant_present_and_above_tier_45(self):
        self.assertTrue(
            hasattr(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT"),
            "Tier 46 must define AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT in config",
        )
        # Comfortable runway above Tier 45 (PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT).
        self.assertGreaterEqual(
            config.AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT,
            config.PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT + 700,
        )


class TestPreForkUnchanged(unittest.TestCase):
    """Below the activation height, a SetAuthorityKey signed by the hot
    key only is still accepted, EVEN when an authority key is already
    installed. Replay determinism for historical blocks demands this."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def test_pre_fork_first_install_accepted(self):
        # Push activation height well above the chain so we are
        # guaranteed pre-fork at chain.height ≈ 100.
        with patch.object(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT", 1_000_000):
            chain = Blockchain()
            _pin_chain_height(chain, 100)
            hot = _entity(b"validator-hot")
            cold = _entity(b"validator-cold")
            self._register(chain, hot)
            chain.supply.balances[hot.entity_id] = 10_000

            tx = create_set_authority_key_transaction(
                hot, new_authority_key=cold.public_key, nonce=0, fee=500,
            )
            ok, reason = chain.validate_set_authority_key(tx)
            self.assertTrue(ok, reason)

    def test_pre_fork_rebind_with_hot_key_only_accepted(self):
        """Pre-fork legacy behavior: a rebind signed only by the hot key
        still applies. Required for replay determinism on historical
        blocks."""
        with patch.object(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT", 1_000_000):
            chain = Blockchain()
            _pin_chain_height(chain, 100)
            hot = _entity(b"validator-hot")
            cold1 = _entity(b"validator-cold-1")
            cold2 = _entity(b"validator-cold-2")
            self._register(chain, hot)
            chain.supply.balances[hot.entity_id] = 10_000

            # First install
            tx1 = create_set_authority_key_transaction(
                hot, new_authority_key=cold1.public_key, nonce=0, fee=500,
            )
            ok, _ = chain.apply_set_authority_key(tx1, proposer_id=hot.entity_id)
            self.assertTrue(ok)
            # cold1 is now bound

            # Rebind to cold2 with HOT key only — must be accepted PRE-fork.
            tx2 = create_set_authority_key_transaction(
                hot, new_authority_key=cold2.public_key, nonce=1, fee=500,
            )
            ok, reason = chain.validate_set_authority_key(tx2)
            self.assertTrue(ok, reason)


class TestPostForkFirstInstall(unittest.TestCase):
    """At/above the activation height, the first install path
    (authority_keys[entity_id] not yet set) is UNCHANGED — hot-key only.
    This is the bootstrap path; user has no cold key yet to counter-sign with."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def test_post_fork_first_install_hot_only_accepted(self):
        # Pin activation low so chain.height ≈ 200 is guaranteed post-fork.
        with patch.object(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT", 100):
            chain = Blockchain()
            _pin_chain_height(chain, 200)
            hot = _entity(b"validator-hot")
            cold = _entity(b"validator-cold")
            self._register(chain, hot)
            chain.supply.balances[hot.entity_id] = 10_000

            # First-time install: authority_keys[hot.entity_id] is not set.
            self.assertNotIn(hot.entity_id, chain.authority_keys)
            tx = create_set_authority_key_transaction(
                hot, new_authority_key=cold.public_key, nonce=0, fee=500,
            )
            ok, reason = chain.validate_set_authority_key(tx)
            self.assertTrue(ok, reason)


class TestPostForkRebindRequiresColdSignature(unittest.TestCase):
    """At/above the activation height, a rebind (authority key already
    installed) MUST carry a valid cold-key counter-signature."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def _make_chain_with_cold_installed(self, hot, cold, *, post_fork_height):
        """Build a chain at ``post_fork_height`` with ``cold`` already
        promoted as ``hot``'s authority key.

        We install the cold key by writing directly to chain state
        (rather than running a SetAuthorityKey first) so the test stays
        focused on the post-fork rebind validation path and doesn't
        need to juggle the activation height during install.
        """
        chain = Blockchain()
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 10_000
        # Bypass the apply path so we don't need to coordinate the
        # activation gate vs. install-vs-rebind ordering in the test.
        chain.authority_keys[hot.entity_id] = cold.public_key
        # Bump nonce to reflect the install we're simulating.
        chain.nonces[hot.entity_id] = 1
        _pin_chain_height(chain, post_fork_height)
        return chain

    def test_rebind_with_hot_key_only_REJECTED(self):
        """The whole point of the fix: a stolen-hot-key attacker cannot
        rebind authority unilaterally."""
        with patch.object(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT", 100):
            hot = _entity(b"validator-hot")
            cold1 = _entity(b"validator-cold-1")
            cold2_attacker = _entity(b"validator-cold-attacker")
            chain = self._make_chain_with_cold_installed(
                hot, cold1, post_fork_height=200,
            )

            # Attacker (with stolen hot key) attempts to rebind to their cold key.
            # Constructed with the legacy hot-only helper — no cold counter-sig.
            tx = create_set_authority_key_transaction(
                hot, new_authority_key=cold2_attacker.public_key, nonce=1, fee=500,
            )
            ok, reason = chain.validate_set_authority_key(tx)
            self.assertFalse(ok, "rebind without cold counter-sig must be rejected")
            # Reason should mention cold / counter / authority — not a generic error.
            self.assertTrue(
                any(s in reason.lower() for s in ("cold", "counter", "authority")),
                f"rejection reason should reference the missing cold counter-sig, got: {reason!r}",
            )

    def test_rebind_with_valid_cold_counter_sig_ACCEPTED(self):
        """The legitimate path: operator signs with hot AND with the
        existing cold key. Both signatures verify, rebind applies."""
        from messagechain.core.authority_key import (
            create_set_authority_key_rebind_transaction,
        )
        with patch.object(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT", 100):
            hot = _entity(b"validator-hot")
            cold1 = _entity(b"validator-cold-1")
            cold2 = _entity(b"validator-cold-2")
            chain = self._make_chain_with_cold_installed(
                hot, cold1, post_fork_height=200,
            )

            tx = create_set_authority_key_rebind_transaction(
                hot,
                new_authority_key=cold2.public_key,
                nonce=1,
                fee=500,
                existing_cold_keypair=cold1.keypair,
            )
            ok, reason = chain.validate_set_authority_key(tx)
            self.assertTrue(ok, reason)

    def test_rebind_with_wrong_cold_counter_sig_REJECTED(self):
        """An attacker who stole hot AND knows SOME cold key cannot just
        attach the wrong cold key's counter-sig."""
        from messagechain.core.authority_key import (
            create_set_authority_key_rebind_transaction,
        )
        with patch.object(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT", 100):
            hot = _entity(b"validator-hot")
            cold1 = _entity(b"validator-cold-1")  # legitimate, currently installed
            cold_wrong = _entity(b"validator-cold-different")
            cold2_attacker = _entity(b"validator-cold-attacker")
            chain = self._make_chain_with_cold_installed(
                hot, cold1, post_fork_height=200,
            )

            # Attacker has hot + the WRONG cold key, attempts rebind.
            tx = create_set_authority_key_rebind_transaction(
                hot,
                new_authority_key=cold2_attacker.public_key,
                nonce=1,
                fee=500,
                existing_cold_keypair=cold_wrong.keypair,
            )
            ok, reason = chain.validate_set_authority_key(tx)
            self.assertFalse(
                ok,
                "rebind with cold counter-sig under WRONG cold key must be rejected",
            )

    def test_rebind_with_forged_cold_counter_sig_REJECTED(self):
        """A counter-signature that is structurally a Signature but
        signs the wrong message (or has any other forgery shape) must
        not verify under the installed cold key."""
        from messagechain.core.authority_key import (
            create_set_authority_key_rebind_transaction,
        )
        with patch.object(config, "AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT", 100):
            hot = _entity(b"validator-hot")
            cold1 = _entity(b"validator-cold-1")
            cold2 = _entity(b"validator-cold-2")
            chain = self._make_chain_with_cold_installed(
                hot, cold1, post_fork_height=200,
            )

            # Build the legitimate rebind, then swap in a counter-sig over a
            # different message — verifies under cold1 against THAT message,
            # but not against this tx's signable bytes.
            tx = create_set_authority_key_rebind_transaction(
                hot,
                new_authority_key=cold2.public_key,
                nonce=1,
                fee=500,
                existing_cold_keypair=cold1.keypair,
            )
            # Forge: replace cold counter-sig with a sig over arbitrary bytes.
            tx.cold_signature = cold1.keypair.sign(_hash(b"some-other-payload"))
            # tx_hash MUST commit to cold_signature for the forged sig to even
            # round-trip; recompute so the tx_hash check passes and we exercise
            # the signature-mismatch failure path, not a hash-mismatch one.
            tx.tx_hash = tx._compute_hash()

            ok, reason = chain.validate_set_authority_key(tx)
            self.assertFalse(
                ok,
                "rebind with forged (wrong-message) cold counter-sig must be rejected",
            )


class TestWireFormatRoundTrip(unittest.TestCase):
    """The new cold-signature field must round-trip through both the
    binary (to_bytes/from_bytes) and dict (serialize/deserialize) wire
    formats. Pre-fork (legacy, no cold sig) blobs must round-trip
    byte-identically to before, so historical blocks replay deterministically."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_legacy_blob_roundtrip_unchanged(self):
        hot = _entity(b"hot-rt")
        cold = _entity(b"cold-rt")
        tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        # Round-trip through binary
        blob = tx.to_bytes()
        rt = SetAuthorityKeyTransaction.from_bytes(blob)
        self.assertEqual(rt.entity_id, tx.entity_id)
        self.assertEqual(rt.new_authority_key, tx.new_authority_key)
        self.assertEqual(rt.nonce, tx.nonce)
        self.assertEqual(rt.fee, tx.fee)
        self.assertEqual(rt.tx_hash, tx.tx_hash)
        # Legacy form has no cold signature.
        self.assertFalse(rt.has_cold_signature())

        # Round-trip through dict
        d = tx.serialize()
        rt2 = SetAuthorityKeyTransaction.deserialize(d)
        self.assertEqual(rt2.tx_hash, tx.tx_hash)
        self.assertFalse(rt2.has_cold_signature())

    def test_cold_signed_blob_roundtrip(self):
        from messagechain.core.authority_key import (
            create_set_authority_key_rebind_transaction,
        )
        hot = _entity(b"hot-rt2")
        cold1 = _entity(b"cold-rt-existing")
        cold2 = _entity(b"cold-rt-new")
        tx = create_set_authority_key_rebind_transaction(
            hot,
            new_authority_key=cold2.public_key,
            nonce=1,
            fee=500,
            existing_cold_keypair=cold1.keypair,
        )
        self.assertTrue(tx.has_cold_signature())

        # Binary round-trip
        blob = tx.to_bytes()
        rt = SetAuthorityKeyTransaction.from_bytes(blob)
        self.assertTrue(rt.has_cold_signature())
        self.assertEqual(rt.tx_hash, tx.tx_hash)
        self.assertEqual(
            rt.cold_signature.canonical_bytes(),
            tx.cold_signature.canonical_bytes(),
        )

        # Dict round-trip
        d = tx.serialize()
        rt2 = SetAuthorityKeyTransaction.deserialize(d)
        self.assertTrue(rt2.has_cold_signature())
        self.assertEqual(rt2.tx_hash, tx.tx_hash)
        self.assertEqual(
            rt2.cold_signature.canonical_bytes(),
            tx.cold_signature.canonical_bytes(),
        )

    def test_pre_fork_legacy_bytes_byte_identical(self):
        """A legacy SetAuthorityKey tx (no cold counter-sig) serialized
        with the post-fork code must be byte-identical to the pre-fork
        encoding — i.e. no extra trailer bytes appear when the cold sig
        is absent. Replay determinism on historical blocks demands it."""
        hot = _entity(b"hot-bid")
        cold = _entity(b"cold-bid")
        tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        sig_blob = tx.signature.to_bytes()
        # Legacy layout: ENT entity_ref(33) | 32 new_authority_key |
        # u64 nonce | f64 timestamp | u64 fee | u32 sig_len | sig | 32 tx_hash
        # entity_ref is 1-byte tag + 32-byte raw id when no entity index = 33.
        expected_len = 33 + 32 + 8 + 8 + 8 + 4 + len(sig_blob) + 32
        self.assertEqual(
            len(tx.to_bytes()),
            expected_len,
            "legacy SetAuthorityKey blob must contain no extra trailer bytes "
            "(byte-for-byte identical to pre-fork encoding)",
        )


if __name__ == "__main__":
    unittest.main()
