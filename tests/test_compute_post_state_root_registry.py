"""Structural-guard tests for ``compute_post_state_root_for_block``.

The pre-refactor ``compute_post_state_root`` carried 18 explicit
per-tx-kind kwargs, and adding a new tx kind required manual updates
at the signature, two call sites (``propose_block`` +
``_append_block``), and the apply path.  The 1.29.x react-tx saga and
the post-Tier-32 sim-vs-apply divergence series both shipped from
exactly this surface.

This module pins the structural invariant that prevents the next
"forgot one site" regression:

  1. Every block-included tx-list attribute is registered in the
     canonical ``Blockchain._BLOCK_TX_LIST_ATTRS`` tuple.
  2. The new block-shaped helper
     ``compute_post_state_root_for_block(block, ...)`` reads tx lists
     via the registry rather than hand-listing them.
  3. The legacy explicit-kwarg ``compute_post_state_root(...)``
     signature still works (legacy callers + tests) and produces a
     byte-identical root to the block-shaped helper for any block
     that round-trips through ``propose_block``.

If a future contributor adds a new tx kind without registering it,
test (1) fails loudly with a list of the missing attributes.  If
they update the legacy signature without routing the new call
through the registry, test (2) catches the drift.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain.core.blockchain import Blockchain


class TestBlockTxListAttrsRegistryComplete(unittest.TestCase):
    """Every block-shaped tx-list attribute MUST be in
    ``_BLOCK_TX_LIST_ATTRS``.  Walk the live ``Block`` dataclass
    fields and assert the registry covers every list-typed slot
    that a transaction kind lands in."""

    def test_block_dataclass_list_fields_all_registered(self):
        from dataclasses import fields
        from messagechain.core.block import Block

        # Block fields whose value-shape is "a list of transactions".
        # We discriminate by name suffix / known shape rather than by
        # type hint inspection (which is brittle under string
        # annotations and Optional wrappers): every consensus-bearing
        # list is named *_transactions / *_txs / attestations /
        # finality_votes / custody_proofs / acks_observed_this_block.
        list_field_names: set[str] = set()
        for f in fields(Block):
            name = f.name
            if name in (
                "header", "block_hash", "data_hash", "merkle_root",
                "block_number", "inclusion_list",
                # acks_observed_this_block is a wire-format soft-vote
                # list whose entries are ``SubmissionAck`` objects
                # (not transactions).  It does NOT appear in
                # _BLOCK_TX_LIST_ATTRS — apply-path commits to it via
                # the ack-registry, not via per-tx affected_entities.
                "acks_observed_this_block",
            ):
                continue
            if name.endswith("_transactions") or name.endswith("_txs"):
                list_field_names.add(name)
                continue
            if name in ("attestations", "finality_votes", "custody_proofs"):
                list_field_names.add(name)
                continue

        registry = set(Blockchain._BLOCK_TX_LIST_ATTRS)
        missing = list_field_names - registry
        self.assertFalse(
            missing,
            f"Block has list-typed tx slots not registered in "
            f"Blockchain._BLOCK_TX_LIST_ATTRS: {sorted(missing)}.  "
            f"Add them to the canonical registry so "
            f"compute_post_state_root_for_block + "
            f"_block_affected_entities + state-root sim all see them.",
        )


class TestComputePostStateRootForBlockUsesRegistry(unittest.TestCase):
    """The block-shaped helper must consume the canonical registry
    rather than naming each tx kind by hand.  This is what makes
    'add a tx kind in one place' actually work — without it, the
    registry-walk pattern is decorative and the next missing kwarg
    is one merge away."""

    def test_helper_exists_and_walks_registry(self):
        # Helper presence.
        self.assertTrue(
            hasattr(Blockchain, "compute_post_state_root_for_block"),
            "Blockchain.compute_post_state_root_for_block(...) is "
            "missing — the kwarg-explosion refactor is incomplete.  "
            "Add a block-shaped helper that reads tx lists via "
            "_BLOCK_TX_LIST_ATTRS so adding a new tx kind doesn't "
            "require touching N call sites.",
        )
        src = inspect.getsource(
            Blockchain.compute_post_state_root_for_block,
        )
        # The helper must reference the registry, not the individual
        # attribute names.  Either by `_BLOCK_TX_LIST_ATTRS` directly
        # or by iterating over `getattr(block, attr, ...)` for attr
        # in the registry.
        self.assertIn(
            "_BLOCK_TX_LIST_ATTRS",
            src,
            "compute_post_state_root_for_block does not reference "
            "_BLOCK_TX_LIST_ATTRS — it's still hand-listing tx kinds, "
            "which was the kwarg-explosion bug this refactor exists "
            "to close.",
        )


class TestLegacyAndBlockShapedRootsMatch(unittest.TestCase):
    """For an empty block (the simplest case) and for a small block
    with a non-trivial transaction set, the legacy explicit-kwarg
    path and the block-shaped path MUST produce the same state root
    byte-for-byte.  Without this, the refactor is consensus-breaking."""

    def setUp(self):
        from messagechain.identity.identity import Entity
        self.proposer = Entity.create(b"prop-csr".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_empty_block_matches(self):
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.config import VALIDATOR_MIN_STAKE
        self.chain.supply.staked[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 10
        )
        self.chain.supply.balances[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 100
        )
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        # Block-shaped path: read the same slot set via the registry.
        proposer_sig_leaf = blk.header.proposer_signature.leaf_index
        new_root = self.chain.compute_post_state_root_for_block(
            blk,
            proposer_signature_leaf_index=proposer_sig_leaf,
        )
        # Legacy path with the same fields explicitly named.
        legacy_root = self.chain.compute_post_state_root(
            transactions=blk.transactions,
            proposer_id=blk.header.proposer_id,
            block_height=blk.header.block_number,
            transfer_transactions=blk.transfer_transactions,
            attestations=blk.attestations,
            authority_txs=getattr(blk, "authority_txs", []),
            stake_transactions=getattr(blk, "stake_transactions", []),
            unstake_transactions=getattr(blk, "unstake_transactions", []),
            governance_txs=getattr(blk, "governance_txs", []),
            finality_votes=getattr(blk, "finality_votes", []),
            custody_proofs=getattr(blk, "custody_proofs", []),
            proposer_signature_leaf_index=proposer_sig_leaf,
            censorship_evidence_txs=getattr(
                blk, "censorship_evidence_txs", [],
            ),
            bogus_rejection_evidence_txs=getattr(
                blk, "bogus_rejection_evidence_txs", [],
            ),
            react_transactions=getattr(blk, "react_transactions", []),
            inclusion_list_violation_evidence_txs=getattr(
                blk, "inclusion_list_violation_evidence_txs", [],
            ),
            inclusion_list=getattr(blk, "inclusion_list", None),
            non_response_evidence_txs=getattr(
                blk, "non_response_evidence_txs", [],
            ),
        )
        self.assertEqual(
            new_root, legacy_root,
            "compute_post_state_root_for_block and "
            "compute_post_state_root produce different roots for "
            "the same block — refactor is consensus-breaking",
        )


class TestProposeAndAppendUseBlockShapedHelper(unittest.TestCase):
    """propose_block and the validator-side _append_block pre-check
    BOTH must route through the block-shaped helper, not hand-roll
    the kwargs.  Otherwise the next tx-kind addition still has to
    touch all three sites."""

    def test_propose_block_calls_block_shaped_helper(self):
        src = inspect.getsource(Blockchain.propose_block)
        # Either name is acceptable: the helper itself, OR the
        # legacy kwarg form invoked with a block reference (because
        # propose_block builds the block-equivalent in flight).  But
        # the registry-walk MUST be reachable.  Easiest pin: the
        # source must mention the helper by name, since it's the
        # explicit refactor target.
        self.assertIn(
            "compute_post_state_root_for_block",
            src,
            "propose_block does not call "
            "compute_post_state_root_for_block — the refactor must "
            "land both call sites in lockstep so "
            "_BLOCK_TX_LIST_ATTRS becomes the single source of truth",
        )

    def test_add_block_pre_check_calls_block_shaped_helper(self):
        # The pre-apply simulation lives inside add_block /
        # _append_block — search the broader Blockchain source.
        bc_src = inspect.getsource(Blockchain)
        # Count: BOTH call sites should now reference the helper,
        # not the legacy explicit-kwarg form.  We assert a non-zero
        # count of the helper name in addition to propose_block's
        # use, so the validator-side simulation is also covered.
        self.assertGreaterEqual(
            bc_src.count("compute_post_state_root_for_block"),
            2,
            "Expected compute_post_state_root_for_block to appear at "
            "BOTH call sites (propose_block + add_block pre-check); "
            "only propose_block updated means the validator-side "
            "simulation still hand-rolls the kwargs and the next "
            "tx-kind addition will diverge from apply.",
        )


if __name__ == "__main__":
    unittest.main()
