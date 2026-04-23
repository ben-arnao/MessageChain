"""``compute_post_state_root`` uses the incremental SMT journal path.

The old implementation closed by calling ``compute_state_root(sim_*)``,
which builds a fresh ``SparseMerkleTree`` from scratch.  For an account
table with N entries that pays O(N * TREE_DEPTH) = O(N * 256) hash
operations every propose and every validate — independent of how many
accounts the block actually touched.  The incremental tree sitting on
``self.state_tree`` already tracks the current-state commitment, so the
right move is to drive it under a journal: mutate the entries the sim
changed, read the root, roll back.  That makes the cost O(K * 256) for
K=touched-this-block instead of O(N * 256).

These tests pin three properties of the rewire:

1. The returned root equals what the block's ``_apply_block_state``
   followed by ``self.state_tree.root()`` produces.  A byte-for-byte
   mismatch is a consensus fork, so we check many tx shapes.

2. After ``compute_post_state_root`` returns, the chain's live
   ``state_tree`` — its committed root AND its internal node dict AND
   its account table — is bit-identical to what it was at entry.
   Proves the journal rollback cleans up perfectly.

3. ``compute_post_state_root`` does NOT invoke the O(N) full-rebuild
   ``compute_state_root`` helper.  The rebuild function stays in the
   tree for test/fallback callers, but the production hot path must
   not touch it.
"""

from __future__ import annotations

import unittest

from messagechain.config import VALIDATOR_MIN_STAKE
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


def _fresh_chain(num_validators: int = 3):
    """Staked, funded, 1-block-deep chain with `num_validators` validators."""
    entities = [
        Entity.create(f"smt_val_{i}".encode().ljust(32, b"\x00"))
        for i in range(num_validators)
    ]
    chain = Blockchain()
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)
    consensus = ProofOfStake()
    for e in entities:
        chain.supply.balances[e.entity_id] = (
            chain.supply.balances.get(e.entity_id, 0) + 100_000
        )
        chain.supply.stake(e.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[e.entity_id] = VALIDATOR_MIN_STAKE
    # Sync state tree with the direct dict edits so incremental compare
    # sees the correct "before" state.
    chain._rebuild_state_tree()
    return chain, consensus, entities


def _snapshot_tree(chain: Blockchain) -> tuple[bytes, dict, dict]:
    """Capture enough of the state_tree to prove a later call did not
    permanently mutate it.  Root + node map + account table is the full
    persistent surface of ``SparseMerkleTree``."""
    return (
        chain.state_tree.root(),
        dict(chain.state_tree._nodes),
        dict(chain.state_tree._accounts),
    )


class TestComputePostStateRootCorrectness(unittest.TestCase):
    """The root returned by compute_post_state_root must equal the root
    produced by actually applying the block."""

    def test_matches_apply_then_root_on_empty_block(self):
        chain, consensus, entities = _fresh_chain(num_validators=2)
        proposer = pick_selected_proposer(chain, entities)

        sim_root = chain.compute_post_state_root(
            [], proposer.entity_id, chain.height + 1,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )

        block = chain.propose_block(consensus, proposer, [])
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(sim_root, chain.state_tree.root())

    def test_matches_apply_then_root_with_one_message_tx(self):
        chain, consensus, entities = _fresh_chain(num_validators=3)
        proposer = pick_selected_proposer(chain, entities)
        sender = entities[1] if entities[1] is not proposer else entities[2]

        tx = create_transaction(
            sender,
            "smt-consensus-check",
            fee=5000,
            nonce=chain.nonces.get(sender.entity_id, 0),
        )

        sim_root = chain.compute_post_state_root(
            [tx], proposer.entity_id, chain.height + 1,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )

        block = chain.propose_block(consensus, proposer, [tx])
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(sim_root, chain.state_tree.root())

    def test_matches_apply_then_root_with_multiple_txs(self):
        chain, consensus, entities = _fresh_chain(num_validators=4)
        proposer = pick_selected_proposer(chain, entities)
        senders = [e for e in entities if e is not proposer][:2]

        txs = []
        for i, s in enumerate(senders):
            txs.append(create_transaction(
                s,
                f"multi-tx-{i}",
                fee=5000,
                nonce=chain.nonces.get(s.entity_id, 0),
            ))

        sim_root = chain.compute_post_state_root(
            txs, proposer.entity_id, chain.height + 1,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )

        block = chain.propose_block(consensus, proposer, txs)
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(sim_root, chain.state_tree.root())


class TestComputePostStateRootSideEffects(unittest.TestCase):
    """The chain's live state_tree must be bit-identical after the call."""

    def test_empty_block_leaves_tree_untouched(self):
        chain, _, entities = _fresh_chain(num_validators=2)
        proposer = entities[0]
        before = _snapshot_tree(chain)

        chain.compute_post_state_root(
            [], proposer.entity_id, chain.height + 1,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )

        after = _snapshot_tree(chain)
        self.assertEqual(before[0], after[0], "root drifted")
        self.assertEqual(before[1], after[1], "node dict drifted")
        self.assertEqual(before[2], after[2], "account table drifted")

    def test_non_empty_block_leaves_tree_untouched(self):
        chain, _, entities = _fresh_chain(num_validators=3)
        proposer = entities[0]
        sender = entities[1]
        tx = create_transaction(
            sender,
            "no-side-effects-pls",
            fee=5000,
            nonce=chain.nonces.get(sender.entity_id, 0),
        )
        before = _snapshot_tree(chain)

        chain.compute_post_state_root(
            [tx], proposer.entity_id, chain.height + 1,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )

        after = _snapshot_tree(chain)
        self.assertEqual(before[0], after[0])
        self.assertEqual(before[1], after[1])
        self.assertEqual(before[2], after[2])

    def test_repeated_calls_are_idempotent(self):
        """Calling compute_post_state_root twice in a row must return
        the same root both times — the tree must not accumulate drift."""
        chain, _, entities = _fresh_chain(num_validators=2)
        proposer = entities[0]
        sender = entities[1]
        tx = create_transaction(
            sender,
            "idem",
            fee=5000,
            nonce=chain.nonces.get(sender.entity_id, 0),
        )
        first = chain.compute_post_state_root(
            [tx], proposer.entity_id, chain.height + 1,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )
        second = chain.compute_post_state_root(
            [tx], proposer.entity_id, chain.height + 1,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )
        self.assertEqual(first, second)


class TestComputePostStateRootDoesNotFullRebuild(unittest.TestCase):
    """The rewrite's scaling property: compute_post_state_root must NOT
    call the O(N * TREE_DEPTH) full-rebuild helper.  We monkey-patch the
    helper to raise on invocation; the production hot path must go
    through the incremental journal."""

    def test_no_full_rebuild_on_propose_path(self):
        import messagechain.core.state_tree as st_mod
        import messagechain.core.block as block_mod
        chain, consensus, entities = _fresh_chain(num_validators=2)
        proposer = entities[0]

        calls = {"n": 0}

        def _should_not_fire(*args, **kwargs):
            calls["n"] += 1
            raise AssertionError(
                "compute_state_root (full rebuild) was called from the "
                "propose/validate hot path — the incremental journal "
                "rewire is supposed to replace it."
            )

        # Monkey-patch both import surfaces that the hot path might
        # hit (state_tree.compute_state_root is the real impl; block.
        # compute_state_root is the thin wrapper imported at top of
        # blockchain.py).
        orig_st = st_mod.compute_state_root
        orig_block = block_mod.compute_state_root
        st_mod.compute_state_root = _should_not_fire
        block_mod.compute_state_root = _should_not_fire
        try:
            chain.compute_post_state_root(
                [], proposer.entity_id, chain.height + 1,
                proposer_signature_leaf_index=proposer.keypair._next_leaf,
            )
        finally:
            st_mod.compute_state_root = orig_st
            block_mod.compute_state_root = orig_block

        self.assertEqual(calls["n"], 0)


if __name__ == "__main__":
    unittest.main()
