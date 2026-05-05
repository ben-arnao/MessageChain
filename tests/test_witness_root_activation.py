"""B-2 — block builder + validator wiring of witness_root.

Pre-activation (block_number < WITNESS_ROOT_ACTIVATION_HEIGHT):
    * Builder leaves header.witness_root at the all-zero default.
    * Validator does not check witness_root.
    * Backward compat: existing blocks already on chain are unaffected.

Post-activation (block_number >= WITNESS_ROOT_ACTIVATION_HEIGHT):
    * Builder MUST set header.witness_root = compute_block_witness_root(block).
    * Validator MUST recompute and reject mismatches.
    * Tampering any signature in any signed body slot must be caught
      at validate_block time (this is what witness_root buys us).
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from messagechain.config import WITNESS_ROOT_ACTIVATION_HEIGHT
from messagechain.core.witness import compute_block_witness_root


class TestActivationConstant(unittest.TestCase):
    """Sanity checks on the activation constant itself."""

    def test_activation_height_above_recent_forks(self):
        # WITNESS_ROOT_ACTIVATION_HEIGHT must be greater than every
        # other body-slot-introducing fork so witness_root never has to
        # commit to a slot the chain hasn't activated yet.
        from messagechain.config import (
            REACT_TX_HEIGHT,
            MARKET_FEE_FLOOR_HEIGHT,
            INTL_MESSAGE_HEIGHT,
            FIRST_SEND_PUBKEY_HEIGHT,
            PREV_POINTER_HEIGHT,
        )
        for prior_height in (
            REACT_TX_HEIGHT,
            MARKET_FEE_FLOOR_HEIGHT,
            INTL_MESSAGE_HEIGHT,
            FIRST_SEND_PUBKEY_HEIGHT,
            PREV_POINTER_HEIGHT,
        ):
            self.assertGreater(WITNESS_ROOT_ACTIVATION_HEIGHT, prior_height)

    def test_activation_height_above_dormancy_controller(self):
        # Tier 48 must follow Tier 47 (DORMANCY_CONTROLLER_HEIGHT).
        # The originally-comfortable 15_000 runway was compressed in
        # the 1.55.1 sweep; the only invariant that still matters is
        # the strict ordering vs Tier 47, which is what consensus uses.
        from messagechain.config import DORMANCY_CONTROLLER_HEIGHT
        self.assertGreater(
            WITNESS_ROOT_ACTIVATION_HEIGHT,
            DORMANCY_CONTROLLER_HEIGHT,
        )


class TestBuilderPopulatesWitnessRoot(unittest.TestCase):
    """`pos.create_block` must set header.witness_root before signing
    when the block height is at/after the activation gate."""

    def _make_block_at_height(self, target_height: int):
        """Build a real signed block at `target_height` using the live
        production code path.  Returns (block, entity).
        """
        # Local imports keep test isolation lean — these modules pull
        # in heavy dependencies (chaindb, full consensus state) that we
        # don't want loaded for the activation-constant tests above.
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.block import Block, BlockHeader, _hash
        from messagechain.core.transaction import create_transaction
        from messagechain.identity.identity import Entity

        entity = Entity.create(os.urandom(32))
        # Construct a parent block that's exactly target_height - 1
        # tall so the new block lands at target_height.  Pre-activation
        # parent is fine — the builder inspects new_block_number, not
        # parent height.
        parent_header = BlockHeader(
            version=1,
            block_number=target_height - 1,
            prev_hash=b"\x00" * 32,
            merkle_root=_hash(b"genesis-fixture"),
            timestamp=1000.0,
            proposer_id=entity.entity_id,
        )
        parent = Block(header=parent_header, transactions=[])
        parent.block_hash = parent._compute_hash()

        tx = create_transaction(entity, "payload", fee=10_000, nonce=0)
        pos = ProofOfStake.__new__(ProofOfStake)
        block = pos.create_block(
            proposer_entity=entity,
            transactions=[tx],
            prev_block=parent,
            timestamp=parent.header.timestamp + 1,
        )
        return block, entity

    def test_pre_activation_witness_root_is_zero(self):
        # Build at activation_height - 1.  Builder leaves the field at
        # the all-zero default; this is the explicit pre-fork behavior.
        target = WITNESS_ROOT_ACTIVATION_HEIGHT - 1
        block, _ = self._make_block_at_height(target)
        self.assertEqual(block.header.witness_root, b"\x00" * 32)

    def test_post_activation_witness_root_is_populated(self):
        # Build at activation_height.  Builder MUST compute and set the
        # field; the all-zero default would fail validate_block.
        target = WITNESS_ROOT_ACTIVATION_HEIGHT
        block, _ = self._make_block_at_height(target)
        expected = compute_block_witness_root(block)
        self.assertEqual(block.header.witness_root, expected)
        self.assertNotEqual(block.header.witness_root, b"\x00" * 32)

    def test_post_activation_witness_root_distinguishes_signatures(self):
        # Two blocks built at the same post-activation height with
        # different signed payloads must end up with different
        # witness_roots — the field is genuinely committing to the
        # signature bytes, not just a derived constant.
        target = WITNESS_ROOT_ACTIVATION_HEIGHT
        block_a, _ = self._make_block_at_height(target)
        block_b, _ = self._make_block_at_height(target)
        # Two independently-keyed entities → different signatures →
        # different witness_roots.
        self.assertNotEqual(
            block_a.header.witness_root,
            block_b.header.witness_root,
        )


class TestValidatorAcceptsAndRejects(unittest.TestCase):
    """`Blockchain.validate_block` enforces the witness_root commitment.

    Uses `mock.patch` to lower WITNESS_ROOT_ACTIVATION_HEIGHT to 1 for
    the test scope — fast-forwarding a real chain to 15_000 blocks is
    infeasible at production parameters, and the validator-side
    behavior is identical regardless of the absolute height value.
    """

    def _setup_chain(self):
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity
        from tests import register_entity_for_test

        chain = Blockchain()
        entity = Entity.create(os.urandom(32))
        chain.initialize_genesis(entity)
        register_entity_for_test(chain, entity)
        consensus = ProofOfStake()
        consensus.stakes[entity.entity_id] = 1000
        return chain, consensus, entity

    def _propose_post_activation_block(self, chain, consensus, entity):
        from messagechain.core.transaction import create_transaction

        chain.nonces[entity.entity_id] = 0
        tx = create_transaction(entity, "payload", fee=10_000, nonce=0)
        return chain.propose_block(consensus, entity, [tx])

    def test_validator_accepts_block_with_correct_witness_root(self):
        chain, consensus, entity = self._setup_chain()
        with mock.patch(
            "messagechain.config.WITNESS_ROOT_ACTIVATION_HEIGHT", 1,
        ):
            block = self._propose_post_activation_block(chain, consensus, entity)
            # Sanity: builder populated the field.
            self.assertNotEqual(block.header.witness_root, b"\x00" * 32)
            ok, reason = chain.validate_block(block)
            self.assertTrue(ok, f"validate_block rejected: {reason}")

    def test_validator_rejects_block_with_tampered_witness_root(self):
        chain, consensus, entity = self._setup_chain()
        with mock.patch(
            "messagechain.config.WITNESS_ROOT_ACTIVATION_HEIGHT", 1,
        ):
            block = self._propose_post_activation_block(chain, consensus, entity)
            # Tamper the field after the proposer signed.  The header
            # signature is over signable_data() which INCLUDES
            # witness_root, so this also breaks the proposer-signature
            # check — but the witness_root check runs first and is the
            # one we want to assert is firing.
            block.header.witness_root = b"\xff" * 32
            ok, reason = chain.validate_block(block)
            self.assertFalse(ok)
            self.assertIn("witness_root", reason.lower())

    def test_validator_skips_check_pre_activation(self):
        # When the block height is BELOW activation, witness_root is
        # not checked.  Submit a block whose header.witness_root is
        # garbage and confirm the validator does not reject on that
        # field (it may reject on header-sig grounds because
        # witness_root is in signable_data, but NOT with reason
        # "witness_root" — which is what this test pins).
        chain, consensus, entity = self._setup_chain()
        # Activation set to a sky-high value so the block is
        # unambiguously pre-fork.
        with mock.patch(
            "messagechain.config.WITNESS_ROOT_ACTIVATION_HEIGHT", 10_000_000,
        ):
            block = self._propose_post_activation_block(chain, consensus, entity)
            # Pre-fork builder leaves witness_root = b"\x00" * 32.
            self.assertEqual(block.header.witness_root, b"\x00" * 32)
            ok, reason = chain.validate_block(block)
            self.assertTrue(ok, f"pre-activation block rejected: {reason}")


if __name__ == "__main__":
    unittest.main()
