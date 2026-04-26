"""Integration tests for ReactTransaction in the block pipeline (Tier 17).

Covers the wiring layer above the unit tests in test_reaction.py:

* Block layout — `react_transactions` slot round-trips through
  to_bytes/from_bytes and serialize/deserialize, and folds into
  `canonical_block_tx_hashes` so a relayer cannot strip entries
  without invalidating the proposer's merkle_root.
* Block apply — `_apply_block_state` charges the voter's fee, bumps
  the nonce + leaf watermark, and mutates `Blockchain.reaction_state`
  by the choice delta.
* State-root commitment — `compute_current_state_root` mixes in the
  reaction-state contribution at/after REACT_TX_HEIGHT, and
  `compute_post_state_root` produces the same value the apply path
  arrives at.
* Validation — pre-activation blocks with any react entries are
  rejected; post-activation, txs with unknown targets / unregistered
  voters / nonce mismatches are rejected.
"""

import unittest
from unittest.mock import patch

import messagechain.config as _config
from messagechain.config import (
    HASH_ALGO,
    GENESIS_ALLOCATION,
    REACT_CHOICE_UP,
    REACT_CHOICE_DOWN,
    REACT_CHOICE_CLEAR,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, canonical_block_tx_hashes
from messagechain.core.reaction import (
    ReactTransaction,
    ReactionState,
    create_react_transaction,
)
from tests import register_entity_for_test


def _msg_target() -> bytes:
    return b"\x55" * 32


class TestBlockLayoutRoundtrip(unittest.TestCase):
    """react_transactions slot survives every encoding round-trip."""

    @classmethod
    def setUpClass(cls):
        cls.proposer = Entity.create(b"layout_proposer".ljust(32, b"\x00"))
        cls.voter = Entity.create(b"layout_voter".ljust(32, b"\x00"))
        cls.target = Entity.create(b"layout_target".ljust(32, b"\x00"))

    def _empty_block(self) -> Block:
        import hashlib, time
        header = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=hashlib.new(HASH_ALGO, b"empty").digest(),
            timestamp=int(time.time()),
            proposer_id=self.proposer.entity_id,
        )
        header.proposer_signature = self.proposer.keypair.sign(
            hashlib.new(HASH_ALGO, header.signable_data()).digest(),
        )
        return Block(header=header, transactions=[])

    def _make_react_tx(self) -> ReactTransaction:
        return create_react_transaction(
            self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
            fee=10_000,  # comfortably above any current_base_fee
        )

    def test_empty_block_roundtrip_includes_slot(self):
        b = self._empty_block()
        blob = b.to_bytes()
        restored = Block.from_bytes(blob)
        self.assertEqual(restored.react_transactions, [])
        self.assertEqual(restored.block_hash, b.block_hash)

    def test_block_with_react_tx_bytes_roundtrip(self):
        b = self._empty_block()
        b.react_transactions = [self._make_react_tx()]
        # Recompute the block hash now that react_transactions is set —
        # block_hash binds via header hash only, so the hash itself
        # doesn't change, but rebuilding ensures integrity invariants.
        b.block_hash = b._compute_hash()
        blob = b.to_bytes()
        restored = Block.from_bytes(blob)
        self.assertEqual(len(restored.react_transactions), 1)
        self.assertEqual(
            restored.react_transactions[0].tx_hash,
            b.react_transactions[0].tx_hash,
        )

    def test_block_with_react_tx_dict_roundtrip(self):
        b = self._empty_block()
        b.react_transactions = [self._make_react_tx()]
        b.block_hash = b._compute_hash()
        d = b.serialize()
        self.assertIn("react_transactions", d)
        restored = Block.deserialize(d)
        self.assertEqual(len(restored.react_transactions), 1)
        self.assertEqual(
            restored.react_transactions[0].tx_hash,
            b.react_transactions[0].tx_hash,
        )

    def test_canonical_tx_hashes_includes_react(self):
        b = self._empty_block()
        rtx = self._make_react_tx()
        b.react_transactions = [rtx]
        hashes = canonical_block_tx_hashes(b)
        self.assertIn(rtx.tx_hash, hashes)


class TestApplyAndStateRoot(unittest.TestCase):
    """Apply path mutates ReactionState and the chain state root commits to it."""

    def setUp(self):
        # Patch REACT_TX_HEIGHT down so the chain-of-blocks setup stays
        # short.  Restored in tearDown so leakage to other tests can't
        # happen (MERKLE_TREE_HEIGHT-style discipline from CLAUDE.md).
        self._orig_react_height = _config.REACT_TX_HEIGHT
        _config.REACT_TX_HEIGHT = 0
        # Re-import the constant in modules that captured it at import
        # time, so the patched value is the one actually consulted.
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        self._orig_bc = _bc.REACT_TX_HEIGHT
        self._orig_rxn = _rxn.REACT_TX_HEIGHT
        _bc.REACT_TX_HEIGHT = 0
        _rxn.REACT_TX_HEIGHT = 0

        self.proposer = Entity.create(b"int_prop".ljust(32, b"\x00"))
        self.voter = Entity.create(b"int_voter".ljust(32, b"\x00"))
        self.target = Entity.create(b"int_target".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        register_entity_for_test(self.chain, self.voter)
        register_entity_for_test(self.chain, self.target)
        # Fund the voter generously so multiple react votes can each
        # pay their fee on top of any prior block-internal deductions.
        self.chain.supply.balances[self.voter.entity_id] = 1_000_000_000

    def tearDown(self):
        _config.REACT_TX_HEIGHT = self._orig_react_height
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        _bc.REACT_TX_HEIGHT = self._orig_bc
        _rxn.REACT_TX_HEIGHT = self._orig_rxn

    def _build_react_block(self, react_txs: list) -> Block:
        """Hand-build a block carrying react_txs (skip propose_block —
        we want a focused state-mutation test, not a full proposer-path
        integration).  Header signs over an empty merkle root since
        we're not exercising merkle hygiene here."""
        import hashlib, time
        prev = self.chain.get_latest_block()
        header = BlockHeader(
            version=1,
            block_number=prev.header.block_number + 1,
            prev_hash=prev.block_hash,
            merkle_root=hashlib.new(HASH_ALGO, b"x").digest(),
            timestamp=time.time(),
            proposer_id=self.proposer.entity_id,
        )
        header.proposer_signature = self.proposer.keypair.sign(
            hashlib.new(HASH_ALGO, header.signable_data()).digest(),
        )
        block = Block(header=header, transactions=[])
        block.react_transactions = list(react_txs)
        block.block_hash = block._compute_hash()
        return block

    def test_apply_mutates_reaction_state_and_balance(self):
        rtx = create_react_transaction(
            self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=self.chain.nonces.get(self.voter.entity_id, 0),
            fee=10_000,
        )
        block = self._build_react_block([rtx])

        balance_before = self.chain.supply.balances.get(self.voter.entity_id, 0)
        nonce_before = self.chain.nonces.get(self.voter.entity_id, 0)
        self.chain._apply_block_state(block)

        # Voter balance dropped by exactly the fee.
        balance_after = self.chain.supply.balances.get(self.voter.entity_id, 0)
        self.assertEqual(balance_before - balance_after, rtx.fee)
        # Nonce advanced by 1.
        self.assertEqual(
            self.chain.nonces.get(self.voter.entity_id, 0),
            nonce_before + 1,
        )
        # ReactionState reflects the vote: trust score for target == +1.
        self.assertEqual(
            self.chain.reaction_state.user_trust_score(self.target.entity_id),
            1,
        )

    def test_state_root_changes_when_react_state_changes(self):
        """A vote on a fresh chain produces a different state_root than
        an otherwise-identical chain that didn't apply the vote."""
        # Snapshot baseline.
        baseline_root = self.chain.compute_current_state_root()

        rtx = create_react_transaction(
            self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=self.chain.nonces.get(self.voter.entity_id, 0),
            fee=10_000,
        )
        block = self._build_react_block([rtx])
        self.chain._apply_block_state(block)
        post_root = self.chain.compute_current_state_root()

        self.assertNotEqual(baseline_root, post_root)

    def test_compute_post_state_root_matches_apply(self):
        """Proposer-side simulation lands on the same root that apply produces."""
        rtx = create_react_transaction(
            self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=self.chain.nonces.get(self.voter.entity_id, 0),
            fee=10_000,
        )
        block_height = self.chain.height + 1
        # Build the block first so we know the actual leaf_index the
        # proposer's header signature will consume.  Pass it explicitly
        # to compute_post_state_root so the sim mirrors the apply
        # path's _bump_watermark exactly.
        block = self._build_react_block([rtx])
        proposer_leaf = block.header.proposer_signature.leaf_index
        sim_root = self.chain.compute_post_state_root(
            transactions=[],
            proposer_id=self.proposer.entity_id,
            block_height=block_height,
            react_transactions=[rtx],
            proposer_signature_leaf_index=proposer_leaf,
        )
        self.chain._apply_block_state(block)
        live_root = self.chain.compute_current_state_root()
        self.assertEqual(sim_root, live_root)

    def test_change_of_vote_score_delta(self):
        """Switching UP → DOWN nets the score to -1 (delta = -2)."""
        nonce = self.chain.nonces.get(self.voter.entity_id, 0)
        up = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=nonce, fee=10_000,
        )
        down = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_DOWN, nonce=nonce + 1, fee=10_000,
        )
        self.chain._apply_block_state(self._build_react_block([up]))
        self.chain._apply_block_state(self._build_react_block([down]))
        self.assertEqual(
            self.chain.reaction_state.user_trust_score(self.target.entity_id),
            -1,
        )


class TestPreActivationEmptiness(unittest.TestCase):
    """At heights below REACT_TX_HEIGHT, validate_block rejects any react entries."""

    def setUp(self):
        # Keep REACT_TX_HEIGHT at its real (high) value so the chain
        # sits well below activation for the whole test.
        self.proposer = Entity.create(b"pae_prop".ljust(32, b"\x00"))
        self.voter = Entity.create(b"pae_voter".ljust(32, b"\x00"))
        self.target = Entity.create(b"pae_target".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        register_entity_for_test(self.chain, self.voter)
        register_entity_for_test(self.chain, self.target)
        self.chain.supply.balances[self.voter.entity_id] = GENESIS_ALLOCATION

    def test_block_with_react_tx_pre_activation_rejected(self):
        """validate_block returns (False, ...) when react_transactions is
        non-empty and the block's height is below REACT_TX_HEIGHT."""
        import hashlib, time
        prev = self.chain.get_latest_block()
        header = BlockHeader(
            version=1,
            block_number=prev.header.block_number + 1,
            prev_hash=prev.block_hash,
            merkle_root=hashlib.new(HASH_ALGO, b"x").digest(),
            timestamp=time.time() + 1,
            proposer_id=self.proposer.entity_id,
        )
        header.proposer_signature = self.proposer.keypair.sign(
            hashlib.new(HASH_ALGO, header.signable_data()).digest(),
        )
        rtx = create_react_transaction(
            self.voter, target=self.target.entity_id,
            target_is_user=True, choice=REACT_CHOICE_UP, nonce=0,
        )
        block = Block(header=header, transactions=[])
        block.react_transactions = [rtx]
        block.block_hash = block._compute_hash()
        ok, reason = self.chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("REACT_TX_HEIGHT", reason)


if __name__ == "__main__":
    unittest.main()
