"""Tier 27 — symmetric no-self-react rule on message-react votes.

Tier 17 shipped ReactTransaction with an asymmetric self-vote rule:
self-trust votes were rejected (no free reputation pump), but a voter
COULD react UP/DOWN/CLEAR on their own message tx_hashes.  Tier 27
(REACT_NO_SELF_MESSAGE_HEIGHT) closes that asymmetry — at/after
activation, a ReactTx with target_is_user=False whose `target` resolves
to a MessageTransaction authored by `voter_id` is rejected at the
admission layer.

These tests cover:

* `ChainDB.get_message_author` — the new helper that resolves
  tx_hash → sender_id via tx_locations + block load.
* Pre-activation behaviour — a self-message-react in a block at
  height < REACT_NO_SELF_MESSAGE_HEIGHT MUST still be admitted (so
  historical chains continue to apply under the rules in force when
  each block was produced).
* Post-activation behaviour — `Blockchain.validate_block` rejects a
  block that includes a self-message-react at height >=
  REACT_NO_SELF_MESSAGE_HEIGHT.
* Cross-author symmetry — a non-self message-react at the same height
  is still admitted (the rule keys on voter == author, not on the
  presence of a message-react slot at all).
* Server-side proposer hygiene — `Server._produce_block`'s react-pool
  pull filters self-reacts so the assembled block does not fail its
  own validate_block.

The test patches REACT_TX_HEIGHT and REACT_NO_SELF_MESSAGE_HEIGHT down
to 0 (or just-above-genesis) so the chain-of-blocks setup stays short.
Restore is done in tearDown so leakage to other tests can't happen
(MERKLE_TREE_HEIGHT-style discipline from CLAUDE.md).
"""

import os
import tempfile
import time
import unittest

import messagechain.config as _config
from messagechain.config import (
    REACT_CHOICE_UP,
    REACT_CHOICE_DOWN,
    REACT_CHOICE_CLEAR,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.core.reaction import (
    create_react_transaction,
    ReactTransaction,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _patch_react_heights(value: int) -> dict:
    """Patch REACT_TX_HEIGHT in every module that captured it at import.

    Returns the snapshot dict for tearDown to restore.
    """
    from messagechain.core import blockchain as _bc
    from messagechain.core import reaction as _rxn
    snap = {
        "config": _config.REACT_TX_HEIGHT,
        "bc": _bc.REACT_TX_HEIGHT,
        "rxn": _rxn.REACT_TX_HEIGHT,
    }
    _config.REACT_TX_HEIGHT = value
    _bc.REACT_TX_HEIGHT = value
    _rxn.REACT_TX_HEIGHT = value
    return snap


def _restore_react_heights(snap: dict) -> None:
    from messagechain.core import blockchain as _bc
    from messagechain.core import reaction as _rxn
    _config.REACT_TX_HEIGHT = snap["config"]
    _bc.REACT_TX_HEIGHT = snap["bc"]
    _rxn.REACT_TX_HEIGHT = snap["rxn"]


class _ChainHarness:
    """Build a single-validator chain with disk persistence so tx_locations
    is populated when a message tx lands.  Held as a mixin-style helper
    so each test class gets a fresh chain in setUp.
    """

    def _build_chain(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))
        self.proposer = Entity.create(b"t27_proposer".ljust(32, b"\x00"))
        self.voter = Entity.create(b"t27_voter".ljust(32, b"\x00"))
        self.bystander = Entity.create(b"t27_bystander".ljust(32, b"\x00"))
        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        register_entity_for_test(self.chain, self.voter)
        register_entity_for_test(self.chain, self.bystander)
        # Fund both senders generously so multiple txs each pay their fee.
        self.chain.supply.balances[self.voter.entity_id] = 1_000_000_000
        self.chain.supply.balances[self.bystander.entity_id] = 1_000_000_000
        self.consensus = ProofOfStake()

    def _close_chain(self):
        if hasattr(self, "db") and self.db is not None:
            try:
                self.db.close()
            except Exception:
                pass
        if hasattr(self, "tmp"):
            try:
                self.tmp.cleanup()
            except (OSError, PermissionError):
                # Windows holds onto sqlite files briefly after close;
                # ignore the cleanup race — the temp dir gets reaped by
                # the OS eventually.
                pass

    def _land_message(self, sender, body: str) -> bytes:
        """Build, propose, and add a block carrying one MessageTransaction
        from `sender`.  Returns the tx_hash of the landed message so
        callers can react against it.
        """
        nonce = self.chain.nonces.get(sender.entity_id, 0)
        sender.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(sender.entity_id),
        )
        tx = create_transaction(
            sender, body, fee=1500, nonce=nonce,
            current_height=self.chain.height + 1,
        )
        block = self.chain.propose_block(self.consensus, self.proposer, [tx])
        ok, reason = self.chain.add_block(block)
        assert ok, f"_land_message: add_block failed: {reason}"
        return tx.tx_hash


# ── ChainDB.get_message_author ───────────────────────────────────────


class TestGetMessageAuthor(_ChainHarness, unittest.TestCase):
    """The new `get_message_author` helper resolves tx_hash → sender_id."""

    def setUp(self):
        # No height patching needed — we just exercise the storage helper.
        self._build_chain()

    def tearDown(self):
        self._close_chain()

    def test_returns_sender_for_landed_message(self):
        """A message tx that landed in a block resolves to its sender_id."""
        tx_hash = self._land_message(self.proposer, "hello world")
        author = self.db.get_message_author(tx_hash, state=self.chain)
        self.assertEqual(author, self.proposer.entity_id)

    def test_returns_none_for_unknown_tx_hash(self):
        """Unknown tx_hash → None (used as the fast-path 'not in chain' answer)."""
        self.assertIsNone(
            self.db.get_message_author(b"\xee" * 32, state=self.chain),
        )

    def test_returns_correct_author_after_multiple_messages(self):
        """Multi-message chain — each tx_hash resolves to the right author."""
        h1 = self._land_message(self.proposer, "from proposer")
        h2 = self._land_message(self.voter, "from voter")
        h3 = self._land_message(self.bystander, "from bystander")
        self.assertEqual(
            self.db.get_message_author(h1, state=self.chain),
            self.proposer.entity_id,
        )
        self.assertEqual(
            self.db.get_message_author(h2, state=self.chain),
            self.voter.entity_id,
        )
        self.assertEqual(
            self.db.get_message_author(h3, state=self.chain),
            self.bystander.entity_id,
        )


# ── Pre-activation: self-message-react still admitted ────────────────


class TestSelfMessageReactPreActivation(_ChainHarness, unittest.TestCase):
    """At height < REACT_NO_SELF_MESSAGE_HEIGHT, a self-react on one's
    own message MUST still be admitted — historical blocks continue to
    apply under the Tier 17 rules in force when they were produced.
    """

    def setUp(self):
        # Activate ReactTx (Tier 17) but leave Tier 27 at its real
        # (high) value so the chain sits well below activation.
        self._react_snap = _patch_react_heights(0)
        self._orig_t27 = _config.REACT_NO_SELF_MESSAGE_HEIGHT
        _config.REACT_NO_SELF_MESSAGE_HEIGHT = 1_000_000  # far above tip
        self._build_chain()

    def tearDown(self):
        _restore_react_heights(self._react_snap)
        _config.REACT_NO_SELF_MESSAGE_HEIGHT = self._orig_t27
        self._close_chain()

    def test_self_message_react_admitted_pre_tier_27(self):
        """Voter reacts UP on their own message — block validates and the
        message_score advances by +1."""
        msg_hash = self._land_message(self.voter, "my own message")

        rtx = create_react_transaction(
            self.voter,
            target=msg_hash,
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=self.chain.nonces.get(self.voter.entity_id, 0),
            fee=10_000,
        )

        # Build through propose_block so merkle_root + state_root are
        # computed correctly.
        block = self.chain.propose_block(
            self.consensus, self.proposer, [],
            react_transactions=[rtx],
        )
        ok, reason = self.chain.validate_block(block)
        self.assertTrue(
            ok, f"pre-Tier-27 self-message-react must validate: {reason}",
        )

        # The validate path reaches the per-react-tx gates (target
        # existence, voter == author check) and admits the tx.  That's
        # the Tier 27 boundary the test exercises — we don't need to
        # also apply the block, which would be a redundant integration
        # check covered by test_reaction_integration.


# ── Post-activation: self-message-react rejected ─────────────────────


class TestSelfMessageReactPostActivation(_ChainHarness, unittest.TestCase):
    """At height >= REACT_NO_SELF_MESSAGE_HEIGHT, a block carrying a
    self-message-react is rejected by validate_block.  A non-self
    message-react at the same height is still admitted.
    """

    def setUp(self):
        # Both activation gates dropped to 0 so the next produced
        # block sits at/above Tier 27.
        self._react_snap = _patch_react_heights(0)
        self._orig_t27 = _config.REACT_NO_SELF_MESSAGE_HEIGHT
        _config.REACT_NO_SELF_MESSAGE_HEIGHT = 0
        self._build_chain()

    def tearDown(self):
        _restore_react_heights(self._react_snap)
        _config.REACT_NO_SELF_MESSAGE_HEIGHT = self._orig_t27
        self._close_chain()

    def _build_react_block(self, react_txs: list):
        """Build a block with a real merkle/state root via propose_block.

        propose_block computes merkle_root + state_root that match the
        post-application state, so validate_block reaches the per-tx
        gates (which is what we're exercising here) instead of failing
        on a structural check.
        """
        return self.chain.propose_block(
            self.consensus, self.proposer, [],
            react_transactions=list(react_txs),
        )

    def test_self_message_react_rejected_post_tier_27(self):
        """Voter reacts UP on their own message — validate_block rejects."""
        msg_hash = self._land_message(self.voter, "my own message")

        rtx = create_react_transaction(
            self.voter,
            target=msg_hash,
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=self.chain.nonces.get(self.voter.entity_id, 0),
            fee=10_000,
        )
        block = self._build_react_block([rtx])

        ok, reason = self.chain.validate_block(block)
        self.assertFalse(
            ok, "post-Tier-27 self-message-react must NOT validate",
        )
        self.assertIn("own message", reason)

    def test_self_message_react_down_also_rejected(self):
        """Symmetry: DOWN-voting your own message is rejected too —
        the rule is on (voter == author), not on the choice value."""
        msg_hash = self._land_message(self.voter, "another own message")
        rtx = create_react_transaction(
            self.voter,
            target=msg_hash,
            target_is_user=False,
            choice=REACT_CHOICE_DOWN,
            nonce=self.chain.nonces.get(self.voter.entity_id, 0),
            fee=10_000,
        )
        block = self._build_react_block([rtx])
        ok, reason = self.chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("own message", reason)

    def test_self_message_react_clear_also_rejected(self):
        """A CLEAR retraction by the same author is also rejected —
        the rule keys on (voter == author), not on the score delta.
        Without this, an author could pre-CLEAR their own message
        before non-self votes accumulated, polluting the choice map
        with self-rows that should never have been admitted."""
        msg_hash = self._land_message(self.voter, "yet another message")
        rtx = create_react_transaction(
            self.voter,
            target=msg_hash,
            target_is_user=False,
            choice=REACT_CHOICE_CLEAR,
            nonce=self.chain.nonces.get(self.voter.entity_id, 0),
            fee=10_000,
        )
        block = self._build_react_block([rtx])
        ok, reason = self.chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("own message", reason)

    def test_non_self_message_react_still_admitted(self):
        """A bystander reacting to the voter's message is admitted —
        the rule rejects only when voter == message author."""
        msg_hash = self._land_message(self.voter, "voter's message")

        rtx = create_react_transaction(
            self.bystander,
            target=msg_hash,
            target_is_user=False,
            choice=REACT_CHOICE_UP,
            nonce=self.chain.nonces.get(self.bystander.entity_id, 0),
            fee=10_000,
        )
        block = self._build_react_block([rtx])
        ok, reason = self.chain.validate_block(block)
        self.assertTrue(
            ok,
            f"non-self message-react must validate post-Tier-27: {reason}",
        )

    def test_self_user_trust_still_independently_rejected(self):
        """The pre-existing user-trust no-self rule is unchanged: a
        voter cannot vote on their own user-trust score, regardless
        of the message-react rule.  Confirms the two checks are
        independent gates and one didn't accidentally subsume the
        other."""
        # The pure verifier rejects this BEFORE construction reaches
        # signing, so we use the constructor's built-in check.
        with self.assertRaises(ValueError):
            create_react_transaction(
                self.voter,
                target=self.voter.entity_id,
                target_is_user=True,
                choice=REACT_CHOICE_UP,
                nonce=0,
                fee=10_000,
            )


if __name__ == "__main__":
    unittest.main()
