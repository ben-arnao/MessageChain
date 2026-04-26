"""Tests for ReactTransaction — user-trust + message-react votes (Tier 17).

Covers:
* tx creation, signing, signable-data canonicalisation
* encode / decode round-trips (dict serialise + binary to_bytes)
* hash determinism + tamper evidence (sig_version, flags, target, choice)
* validation rules (self-trust rejection, reserved-bit rejection, choice
  range, fee floor, activation-height gate)
* signature verify path (good key, wrong key, tampered bytes)
* ReactionState apply semantics: one-vote-per-(voter,target), change-of-
  vote delta math, clear retraction, replay determinism, target-type
  separation between user-trust and message-score aggregates
"""

import struct
import time
import unittest

from messagechain.config import (
    REACT_TX_HEIGHT,
    REACT_CHOICE_CLEAR,
    REACT_CHOICE_UP,
    REACT_CHOICE_DOWN,
    REACT_TARGET_MESSAGE,
    REACT_TARGET_USER,
    SIG_VERSION_CURRENT,
)
from messagechain.identity.identity import Entity


def _msg_target() -> bytes:
    """Stand-in 32-byte tx_hash for a message-react target."""
    return b"\x42" * 32


class TestReactTransactionCreation(unittest.TestCase):
    """Basic create/sign behaviour of ReactTransaction."""

    @classmethod
    def setUpClass(cls):
        cls.voter = Entity.create(b"voter_key".ljust(32, b"\x00"))
        cls.target_user = Entity.create(b"target_user_key".ljust(32, b"\x00"))

    def test_create_user_trust_up(self):
        from messagechain.core.reaction import create_react_transaction
        tx = create_react_transaction(
            self.voter,
            target=self.target_user.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        self.assertEqual(tx.voter_id, self.voter.entity_id)
        self.assertEqual(tx.target, self.target_user.entity_id)
        self.assertTrue(tx.target_is_user)
        self.assertEqual(tx.choice, REACT_CHOICE_UP)
        self.assertEqual(tx.nonce, 0)
        self.assertGreater(tx.fee, 0)
        self.assertEqual(len(tx.tx_hash), 32)

    def test_create_message_react_down(self):
        from messagechain.core.reaction import create_react_transaction
        tx = create_react_transaction(
            self.voter,
            target=_msg_target(),
            target_is_user=False,
            choice=REACT_CHOICE_DOWN,
            nonce=1,
        )
        self.assertFalse(tx.target_is_user)
        self.assertEqual(tx.choice, REACT_CHOICE_DOWN)

    def test_create_clear_retracts(self):
        from messagechain.core.reaction import create_react_transaction
        tx = create_react_transaction(
            self.voter,
            target=self.target_user.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_CLEAR,
            nonce=2,
        )
        self.assertEqual(tx.choice, REACT_CHOICE_CLEAR)

    def test_self_trust_rejected_at_create(self):
        """Voting on yourself as a user-trust target is rejected at create."""
        from messagechain.core.reaction import create_react_transaction
        with self.assertRaises(ValueError):
            create_react_transaction(
                self.voter,
                target=self.voter.entity_id,
                target_is_user=True,
                choice=REACT_CHOICE_UP,
                nonce=0,
            )

    def test_self_react_on_message_allowed(self):
        """A user can react to their own message — only user-trust self-vote is barred."""
        from messagechain.core.reaction import create_react_transaction
        tx = create_react_transaction(
            self.voter,
            target=_msg_target(),
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=3,
        )
        self.assertEqual(tx.target, _msg_target())

    def test_invalid_choice_rejected(self):
        from messagechain.core.reaction import create_react_transaction
        with self.assertRaises(ValueError):
            create_react_transaction(
                self.voter,
                target=_msg_target(),
                target_is_user=False,
                choice=3,  # reserved, must reject
                nonce=0,
            )

    def test_invalid_target_length_rejected(self):
        from messagechain.core.reaction import create_react_transaction
        with self.assertRaises(ValueError):
            create_react_transaction(
                self.voter,
                target=b"\x00" * 16,  # not 32 bytes
                target_is_user=False,
                choice=REACT_CHOICE_UP,
                nonce=0,
            )


class TestReactTransactionHash(unittest.TestCase):
    """tx_hash determinism + sensitivity to every signed field."""

    @classmethod
    def setUpClass(cls):
        cls.voter = Entity.create(b"voter_h_key".ljust(32, b"\x00"))
        cls.target = Entity.create(b"target_h_key".ljust(32, b"\x00"))

    def _make(self, **overrides):
        from messagechain.core.reaction import create_react_transaction
        kw = dict(
            entity=self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        kw.update(overrides)
        entity = kw.pop("entity")
        return create_react_transaction(entity, **kw)

    def test_hash_deterministic(self):
        tx1 = self._make()
        tx2 = self._make()
        # Different signatures (non-deterministic leaf consumption)
        # would still produce the same tx_hash since signature bytes
        # are not in _signable_data — but the leaf index IS, via
        # sig_version.  Same-leaf, same-signed-fields ⇒ same hash.
        # We can't easily reproduce the same WOTS+ leaf twice; instead,
        # check that recomputing the hash off the same fields is
        # idempotent.
        self.assertEqual(tx1._compute_hash(), tx1.tx_hash)
        self.assertEqual(tx2._compute_hash(), tx2.tx_hash)

    def test_hash_sensitive_to_choice(self):
        tx_up = self._make(choice=REACT_CHOICE_UP)
        tx_down = self._make(choice=REACT_CHOICE_DOWN)
        self.assertNotEqual(tx_up.tx_hash, tx_down.tx_hash)

    def test_hash_sensitive_to_target_type_bit(self):
        """Flipping target_is_user with the same 32-byte target must change the hash."""
        from messagechain.core.reaction import ReactTransaction
        from messagechain.crypto.keys import Signature
        # Construct two unsigned txs with identical 32-byte target but
        # different target_type bits — verify hashes diverge.
        target = b"\x77" * 32
        sig = Signature([], 0, [], b"", b"")
        tx_msg = ReactTransaction(
            voter_id=self.voter.entity_id,
            target=target,
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=0,
            timestamp=1700000000.0,
            fee=10,
            signature=sig,
        )
        tx_user = ReactTransaction(
            voter_id=self.voter.entity_id,
            target=target,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
            timestamp=1700000000.0,
            fee=10,
            signature=sig,
        )
        self.assertNotEqual(tx_msg.tx_hash, tx_user.tx_hash)

    def test_hash_sensitive_to_voter(self):
        other = Entity.create(b"other_voter".ljust(32, b"\x00"))
        tx1 = self._make()
        from messagechain.core.reaction import create_react_transaction
        tx2 = create_react_transaction(
            other,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        self.assertNotEqual(tx1.tx_hash, tx2.tx_hash)

    def test_hash_sensitive_to_target(self):
        tx1 = self._make()
        other_target = Entity.create(b"other_target".ljust(32, b"\x00"))
        tx2 = self._make(target=other_target.entity_id)
        self.assertNotEqual(tx1.tx_hash, tx2.tx_hash)

    def test_hash_sensitive_to_nonce(self):
        tx1 = self._make(nonce=0)
        tx2 = self._make(nonce=1)
        self.assertNotEqual(tx1.tx_hash, tx2.tx_hash)

    def test_sig_version_committed_into_hash(self):
        """sig_version is part of _signable_data — different sig_version → different hash."""
        from messagechain.core.reaction import ReactTransaction
        from messagechain.crypto.keys import Signature
        sig_a = Signature([], 0, [], b"", b"", sig_version=1)
        sig_b = Signature([], 0, [], b"", b"", sig_version=2)
        common = dict(
            voter_id=self.voter.entity_id,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
            timestamp=1700000000.0,
            fee=10,
        )
        tx_a = ReactTransaction(signature=sig_a, **common)
        tx_b = ReactTransaction(signature=sig_b, **common)
        self.assertNotEqual(tx_a.tx_hash, tx_b.tx_hash)


class TestReactTransactionVerify(unittest.TestCase):
    """Signature verification end-to-end."""

    @classmethod
    def setUpClass(cls):
        cls.voter = Entity.create(b"verify_voter".ljust(32, b"\x00"))
        cls.other = Entity.create(b"verify_other".ljust(32, b"\x00"))

    def test_verify_ok_with_correct_key(self):
        from messagechain.core.reaction import (
            create_react_transaction, verify_react_transaction,
        )
        tx = create_react_transaction(
            self.voter,
            target=_msg_target(),
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        self.assertTrue(verify_react_transaction(
            tx, self.voter.public_key, current_height=REACT_TX_HEIGHT,
        ))

    def test_verify_fails_with_wrong_key(self):
        from messagechain.core.reaction import (
            create_react_transaction, verify_react_transaction,
        )
        tx = create_react_transaction(
            self.voter,
            target=_msg_target(),
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        self.assertFalse(verify_react_transaction(
            tx, self.other.public_key, current_height=REACT_TX_HEIGHT,
        ))

    def test_verify_rejects_pre_activation(self):
        """A ReactTx must not be admitted at heights below REACT_TX_HEIGHT."""
        from messagechain.core.reaction import (
            create_react_transaction, verify_react_transaction,
        )
        tx = create_react_transaction(
            self.voter,
            target=_msg_target(),
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        self.assertFalse(verify_react_transaction(
            tx, self.voter.public_key, current_height=REACT_TX_HEIGHT - 1,
        ))

    def test_verify_rejects_low_fee(self):
        from messagechain.core.reaction import (
            create_react_transaction, verify_react_transaction,
        )
        tx = create_react_transaction(
            self.voter,
            target=_msg_target(),
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        # Tamper fee to zero and re-hash so the structural shape stays
        # consistent; verify should still reject on the fee floor.
        tx.fee = 0
        tx.tx_hash = tx._compute_hash()
        self.assertFalse(verify_react_transaction(
            tx, self.voter.public_key, current_height=REACT_TX_HEIGHT,
        ))

    def test_verify_rejects_self_trust(self):
        """User-target == voter must be rejected by verify (defence in depth)."""
        from messagechain.core.reaction import (
            ReactTransaction, verify_react_transaction,
        )
        # Construct a self-trust tx by hand (bypassing the create-time
        # guard) to assert the verifier independently rejects it.
        tx = ReactTransaction(
            voter_id=self.voter.entity_id,
            target=self.voter.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
            timestamp=time.time(),
            fee=10,
            signature=self.voter.keypair.sign(b"\x00" * 32),
        )
        self.assertFalse(verify_react_transaction(
            tx, self.voter.public_key, current_height=REACT_TX_HEIGHT,
        ))

    def test_verify_rejects_reserved_choice(self):
        """choice == 3 (binary 11) is the reserved bit pattern — verifier defence-in-depth.

        Constructed by hand bypassing _compute_hash (which rejects choice=3 at
        pack time) so the test exercises the verifier's own canon-form gate
        — the second-layer defence in case a future code path skipped the
        _pack_flags guard.
        """
        from messagechain.core.reaction import ReactTransaction, verify_react_transaction
        tx = ReactTransaction.__new__(ReactTransaction)
        tx.voter_id = self.voter.entity_id
        tx.target = _msg_target()
        tx.target_is_user = False
        tx.choice = 3  # reserved
        tx.nonce = 0
        tx.timestamp = time.time()
        tx.fee = 10
        tx.signature = self.voter.keypair.sign(b"\x00" * 32)
        tx.tx_hash = b"\x00" * 32  # bypass _compute_hash (which rejects choice=3)
        self.assertFalse(verify_react_transaction(
            tx, self.voter.public_key, current_height=REACT_TX_HEIGHT,
        ))


class TestReactTransactionEncoding(unittest.TestCase):
    """Round-trip encoding through serialize / deserialize and to_bytes / from_bytes."""

    @classmethod
    def setUpClass(cls):
        cls.voter = Entity.create(b"enc_voter".ljust(32, b"\x00"))
        cls.target = Entity.create(b"enc_target".ljust(32, b"\x00"))

    def _make(self, **overrides):
        from messagechain.core.reaction import create_react_transaction
        kw = dict(
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
        )
        kw.update(overrides)
        return create_react_transaction(self.voter, **kw)

    def test_dict_roundtrip(self):
        from messagechain.core.reaction import ReactTransaction
        tx = self._make()
        d = tx.serialize()
        restored = ReactTransaction.deserialize(d)
        self.assertEqual(restored.voter_id, tx.voter_id)
        self.assertEqual(restored.target, tx.target)
        self.assertEqual(restored.target_is_user, tx.target_is_user)
        self.assertEqual(restored.choice, tx.choice)
        self.assertEqual(restored.nonce, tx.nonce)
        self.assertEqual(restored.fee, tx.fee)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_bytes_roundtrip_message_target(self):
        from messagechain.core.reaction import ReactTransaction
        tx = self._make(target=_msg_target(), target_is_user=False)
        blob = tx.to_bytes()
        restored = ReactTransaction.from_bytes(blob)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.target_is_user, False)
        self.assertEqual(restored.choice, tx.choice)

    def test_bytes_roundtrip_user_target(self):
        from messagechain.core.reaction import ReactTransaction
        tx = self._make()
        blob = tx.to_bytes()
        restored = ReactTransaction.from_bytes(blob)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertTrue(restored.target_is_user)

    def test_bytes_truncated_rejected(self):
        from messagechain.core.reaction import ReactTransaction
        tx = self._make()
        blob = tx.to_bytes()
        with self.assertRaises(ValueError):
            ReactTransaction.from_bytes(blob[:20])

    def test_bytes_trailing_garbage_rejected(self):
        from messagechain.core.reaction import ReactTransaction
        tx = self._make()
        blob = tx.to_bytes()
        with self.assertRaises(ValueError):
            ReactTransaction.from_bytes(blob + b"\x99")

    def test_bytes_hash_mismatch_rejected(self):
        """Tampering any signed byte must surface as a tx_hash mismatch."""
        from messagechain.core.reaction import ReactTransaction
        tx = self._make()
        blob = bytearray(tx.to_bytes())
        # Flip a bit inside the choice/flags region (right after voter_ref +
        # 32 bytes target).  Locate it precisely from the encoded form:
        # u8 ser_ver | ENT(>=1B) | 32 target | 1 flags | ...
        # Search for the choice byte by reading the structure.  We don't
        # know the exact varint length of voter_ref, so flip the LAST
        # byte of the tx_hash trailer instead — that always invalidates
        # the declared-hash check.
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            ReactTransaction.from_bytes(bytes(blob))


class TestReactTransactionFlagsByte(unittest.TestCase):
    """The flags byte packs target_type + choice + reserved bits."""

    @classmethod
    def setUpClass(cls):
        cls.voter = Entity.create(b"flags_voter".ljust(32, b"\x00"))

    def test_flags_pack_unpack(self):
        from messagechain.core.reaction import _pack_flags, _unpack_flags
        for tu in (False, True):
            for c in (REACT_CHOICE_CLEAR, REACT_CHOICE_UP, REACT_CHOICE_DOWN):
                f = _pack_flags(target_is_user=tu, choice=c)
                self.assertEqual(_unpack_flags(f), (tu, c))

    def test_unpack_rejects_reserved_choice(self):
        from messagechain.core.reaction import _unpack_flags
        # bit1-2 = 11 → reserved
        flags = (1 << 1) | (1 << 2)
        with self.assertRaises(ValueError):
            _unpack_flags(flags)

    def test_unpack_rejects_high_bits_set(self):
        from messagechain.core.reaction import _unpack_flags
        # Any of bits 3-7 set must be rejected so the byte is canonical.
        for bit in range(3, 8):
            with self.assertRaises(ValueError):
                _unpack_flags(1 << bit)


class TestReactionStateApply(unittest.TestCase):
    """ReactionState applies vote deltas correctly (the foolproof aggregator)."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice_react".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob_react".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol_react".ljust(32, b"\x00"))

    def setUp(self):
        from messagechain.core.reaction import ReactionState
        self.state = ReactionState()

    def _vote(self, voter, target, *, target_is_user, choice, nonce=0):
        from messagechain.core.reaction import create_react_transaction
        return create_react_transaction(
            voter,
            target=target,
            target_is_user=target_is_user,
            choice=choice,
            nonce=nonce,
        )

    def test_user_trust_up(self):
        tx = self._vote(self.alice, self.bob.entity_id,
                        target_is_user=True, choice=REACT_CHOICE_UP)
        self.state.apply(tx)
        self.assertEqual(self.state.user_trust_score(self.bob.entity_id), 1)
        self.assertEqual(self.state.user_trust_score(self.alice.entity_id), 0)

    def test_user_trust_down(self):
        tx = self._vote(self.alice, self.bob.entity_id,
                        target_is_user=True, choice=REACT_CHOICE_DOWN)
        self.state.apply(tx)
        self.assertEqual(self.state.user_trust_score(self.bob.entity_id), -1)

    def test_one_voter_one_target_one_count(self):
        """Replaying the same vote twice does NOT double the score."""
        tx = self._vote(self.alice, self.bob.entity_id,
                        target_is_user=True, choice=REACT_CHOICE_UP)
        self.state.apply(tx)
        # Second apply of the SAME (voter, target, choice) is a no-op
        # (it would have the same tx_hash and be rejected by mempool
        # dedup; here we assert the state path is also idempotent).
        self.state.apply(tx)
        self.assertEqual(self.state.user_trust_score(self.bob.entity_id), 1)

    def test_change_of_vote_up_to_down(self):
        """Switching from UP to DOWN moves the score by -2 (delta = -1 - +1)."""
        up = self._vote(self.alice, self.bob.entity_id,
                        target_is_user=True, choice=REACT_CHOICE_UP, nonce=0)
        down = self._vote(self.alice, self.bob.entity_id,
                          target_is_user=True, choice=REACT_CHOICE_DOWN, nonce=1)
        self.state.apply(up)
        self.state.apply(down)
        self.assertEqual(self.state.user_trust_score(self.bob.entity_id), -1)

    def test_change_of_vote_clear_retracts(self):
        """CLEAR after UP returns the score to 0 contribution from this voter."""
        up = self._vote(self.alice, self.bob.entity_id,
                        target_is_user=True, choice=REACT_CHOICE_UP, nonce=0)
        clear = self._vote(self.alice, self.bob.entity_id,
                           target_is_user=True, choice=REACT_CHOICE_CLEAR, nonce=1)
        self.state.apply(up)
        self.state.apply(clear)
        self.assertEqual(self.state.user_trust_score(self.bob.entity_id), 0)
        # The (voter, target) entry is removed entirely on CLEAR.
        self.assertNotIn(
            (self.alice.entity_id, self.bob.entity_id),
            self.state.choices,
        )

    def test_two_voters_aggregate(self):
        """Distinct voters' votes are independent and sum cleanly."""
        a = self._vote(self.alice, self.bob.entity_id,
                       target_is_user=True, choice=REACT_CHOICE_UP)
        c = self._vote(self.carol, self.bob.entity_id,
                       target_is_user=True, choice=REACT_CHOICE_UP)
        self.state.apply(a)
        self.state.apply(c)
        self.assertEqual(self.state.user_trust_score(self.bob.entity_id), 2)

    def test_message_score_isolated_from_user_trust(self):
        """A user-trust vote on entity X does NOT spill into message-score for X-shaped tx_hash."""
        # Entity ID and message tx_hash are both 32 bytes.  Even if a
        # 32-byte value happens to collide with an entity_id, the
        # target_is_user bit isolates the two aggregates.
        target = self.bob.entity_id  # used as a tx_hash too, by coincidence
        ut = self._vote(self.alice, target, target_is_user=True,
                        choice=REACT_CHOICE_UP, nonce=0)
        ms = self._vote(self.alice, target, target_is_user=False,
                        choice=REACT_CHOICE_UP, nonce=1)
        self.state.apply(ut)
        self.state.apply(ms)
        self.assertEqual(self.state.user_trust_score(target), 1)
        self.assertEqual(self.state.message_score(target), 1)
        # Two distinct (voter, target, target_type) keys → two entries.
        self.assertEqual(len(self.state.choices), 2)

    def test_replay_determinism(self):
        """Applying a sequence in order produces a deterministic state — same scores
        whatever the iteration order of internal dicts."""
        seq = [
            self._vote(self.alice, self.bob.entity_id,
                       target_is_user=True, choice=REACT_CHOICE_UP, nonce=0),
            self._vote(self.alice, self.bob.entity_id,
                       target_is_user=True, choice=REACT_CHOICE_DOWN, nonce=1),
            self._vote(self.carol, self.bob.entity_id,
                       target_is_user=True, choice=REACT_CHOICE_UP, nonce=0),
            self._vote(self.alice, self.bob.entity_id,
                       target_is_user=True, choice=REACT_CHOICE_CLEAR, nonce=2),
        ]
        from messagechain.core.reaction import ReactionState
        s1 = ReactionState()
        s2 = ReactionState()
        for tx in seq:
            s1.apply(tx)
        for tx in seq:
            s2.apply(tx)
        self.assertEqual(s1.user_trust_score(self.bob.entity_id),
                         s2.user_trust_score(self.bob.entity_id))
        self.assertEqual(s1.user_trust_score(self.bob.entity_id), 1)


class TestReactionStateSerialize(unittest.TestCase):
    """ReactionState round-trips through serialize / deserialize bit-for-bit."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"sa_alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"sa_bob".ljust(32, b"\x00"))

    def test_serialize_empty(self):
        from messagechain.core.reaction import ReactionState
        s = ReactionState()
        d = s.serialize()
        restored = ReactionState.deserialize(d)
        self.assertEqual(restored.choices, {})
        self.assertEqual(restored.user_trust_score(self.alice.entity_id), 0)

    def test_serialize_roundtrip(self):
        from messagechain.core.reaction import (
            ReactionState, create_react_transaction,
        )
        s = ReactionState()
        s.apply(create_react_transaction(
            self.alice, target=self.bob.entity_id,
            target_is_user=True, choice=REACT_CHOICE_UP, nonce=0,
        ))
        s.apply(create_react_transaction(
            self.alice, target=_msg_target(),
            target_is_user=False, choice=REACT_CHOICE_DOWN, nonce=1,
        ))
        d = s.serialize()
        restored = ReactionState.deserialize(d)
        self.assertEqual(restored.user_trust_score(self.bob.entity_id), 1)
        self.assertEqual(restored.message_score(_msg_target()), -1)
        self.assertEqual(set(restored.choices.keys()), set(s.choices.keys()))


if __name__ == "__main__":
    unittest.main()
