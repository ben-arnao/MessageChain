"""Tier-39 — Submission-ack backdating defense.

A coerced/colluding target validator could sign a SubmissionAck whose
``commit_height`` was set to any past height (e.g.
``earliest_observation_height - 1``).  When a colluding proposer
embedded that ack in ``block.acks_observed_this_block``, the chain's
``witness_ack_registry`` recorded ``ack.commit_height`` verbatim, and
the non-response apply gate then saw
``ack_h <= earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS``: the
silent-drop censorship was excused.  Two-validator collusion sufficed
to escape the witness-non-response slashing arm of the validator-
collusion defense.

Tier 39 lands two complementary defenses, both gated on
``ACK_BACKDATING_DEFENSE_HEIGHT``:

  1. ``_validate_acks_observed_this_block`` rejects an ack whose
     ``commit_height`` is in the future (``> block.header.block_number``)
     or too far in the past (``block.header.block_number -
     commit_height > WITNESS_RESPONSE_DEADLINE_BLOCKS +
     ACK_INCLUSION_GRACE``).

  2. The apply path stores ``block.header.block_number`` (the height the
     chain first OBSERVED the ack via inclusion) in
     ``witness_ack_registry``, not ``ack.commit_height``.  This removes
     issuer control over the deadline reference entirely — the only
     way to discharge an obligation is to land the ack on chain inside
     the deadline window.

Pre-activation: byte-identical replay (the registry continues to
store ``ack.commit_height`` and the bounds check is skipped) so
historical mainnet blocks reapply byte-for-byte.

Post-activation: the bound + the registry-source change together close
the backdating gap.
"""

from __future__ import annotations

import hashlib
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
)
from messagechain.identity.identity import Entity
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.witness_submission import (
    SubmissionAck,
    ACK_ADMITTED,
)
from messagechain.crypto.keys import KeyPair, Signature


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _receipt_subtree_kp(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(seed=b"receipt-subtree-" + seed_tag, height=height)


def _make_signed_ack(
    issuer: Entity,
    issuer_subtree_kp: KeyPair,
    request_hash: bytes,
    commit_height: int,
    action_code: int = ACK_ADMITTED,
) -> SubmissionAck:
    ack = SubmissionAck(
        request_hash=request_hash,
        issuer_id=issuer.entity_id,
        issuer_root_public_key=issuer_subtree_kp.public_key,
        action_code=action_code,
        commit_height=commit_height,
        signature=Signature([], 0, [], b"", b""),
    )
    msg_hash = hashlib.new(HASH_ALGO, ack._signable_data()).digest()
    ack.signature = issuer_subtree_kp.sign(msg_hash)
    ack.ack_hash = ack._compute_hash()
    return ack


class _AckDefenseHarness(unittest.TestCase):
    """Spin up a chain + a registered ack issuer and let the subclass
    configure the activation height."""

    # Per-test override of the activation gate.  Tests for the
    # pre-activation legacy path raise this above the block height
    # they exercise; tests for the post-activation behavior lower it.
    activation_height: int | None = None

    def setUp(self):
        from messagechain.config import VALIDATOR_MIN_STAKE
        # Shrink production-sized window/grace so we mine ~5 blocks
        # instead of ~25 to exercise the same bound — this turns
        # 16s/test into ~3s without changing the rule under test.
        # MERKLE_TREE_HEIGHT then only needs 4 leaves (conftest default).
        import messagechain.config as _cfg
        self._orig_window = _cfg.WITNESS_RESPONSE_DEADLINE_BLOCKS
        self._orig_grace = _cfg.ACK_INCLUSION_GRACE
        _cfg.WITNESS_RESPONSE_DEADLINE_BLOCKS = 2
        _cfg.ACK_INCLUSION_GRACE = 1
        # Patch the local-module re-import too (this file imported
        # WITNESS_RESPONSE_DEADLINE_BLOCKS at top-level).
        import tests.test_ack_backdating_defense as _self_mod
        self._orig_local_window = _self_mod.WITNESS_RESPONSE_DEADLINE_BLOCKS
        _self_mod.WITNESS_RESPONSE_DEADLINE_BLOCKS = 2
        # Conftest-pinned MERKLE_TREE_HEIGHT (4 → 16 leaves) is enough
        # for the proposer's worst-case sign count under the shrunk window.
        self._patches: list = []
        if self.activation_height is not None:
            self._orig_height = _cfg.ACK_BACKDATING_DEFENSE_HEIGHT
            _cfg.ACK_BACKDATING_DEFENSE_HEIGHT = self.activation_height

        self.proposer = Entity.create(b"prop-bd".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        self.chain.supply.staked[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 10
        )
        self.chain.supply.balances[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 100
        )
        self.issuer = Entity.create(b"issuer-bd".ljust(32, b"\x00"))
        self.issuer.keypair._next_leaf = 0
        register_entity_for_test(self.chain, self.issuer)
        self.issuer_kp = _receipt_subtree_kp(b"bd")
        self.chain.receipt_subtree_roots[self.issuer.entity_id] = (
            self.issuer_kp.public_key
        )

    def tearDown(self):
        import messagechain.config as _cfg
        _cfg.WITNESS_RESPONSE_DEADLINE_BLOCKS = self._orig_window
        _cfg.ACK_INCLUSION_GRACE = self._orig_grace
        import tests.test_ack_backdating_defense as _self_mod
        _self_mod.WITNESS_RESPONSE_DEADLINE_BLOCKS = self._orig_local_window
        if self.activation_height is not None:
            _cfg.ACK_BACKDATING_DEFENSE_HEIGHT = self._orig_height

    def _propose_and_inject(self, acks: list, block_height: int | None = None):
        """Build a block via propose_block with the test's adversarial
        ack list passed straight in.  ``propose_block`` is responsible
        for populating the merkle root + state-root commitments; we
        let it do that with the adversarial list in place so any
        rejection comes from the block-level rule under test, not from
        a stale merkle root caused by post-construction mutation."""
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        return self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
            acks_observed_this_block=list(acks),
        )


class TestAckBackdatingPostActivation(_AckDefenseHarness):
    """Activation-on. Block height 1 ≥ activation 1 → new rules apply."""

    activation_height = 1

    def test_future_commit_height_rejected(self):
        # Block is at height 1; ack claims commit_height = 100 (future).
        ack = _make_signed_ack(
            self.issuer, self.issuer_kp, _h(b"future"), commit_height=100,
        )
        blk = self._propose_and_inject([ack])
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok, "future commit_height must be rejected")
        self.assertIn("commit_height", reason.lower())

    def test_too_old_commit_height_rejected(self):
        # Advance the chain to a height comfortably past the deadline +
        # grace so we can construct an ack whose commit_height is more
        # than DEADLINE + GRACE blocks behind the inclusion height.
        from messagechain.config import (
            ACK_INCLUSION_GRACE,
            VALIDATOR_MIN_STAKE,
        )
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        # Mine empty blocks until block height is well past the bound.
        for _ in range(WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 5):
            blk = self.chain.propose_block(
                consensus=consensus,
                proposer_entity=self.proposer,
                transactions=[],
                acks_observed_this_block=[],
            )
            ok, reason = self.chain.add_block(blk)
            self.assertTrue(ok, reason)
        # Now try to land an ack whose commit_height is older than
        # current_height - (DEADLINE + GRACE).
        current = self.chain.get_latest_block().header.block_number
        too_old = current - (
            WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 1
        )
        ack = _make_signed_ack(
            self.issuer, self.issuer_kp, _h(b"too-old"),
            commit_height=too_old,
        )
        blk = self._propose_and_inject([ack])
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok, "too-old commit_height must be rejected")
        self.assertIn("commit_height", reason.lower())

    def test_in_window_commit_height_accepted_and_uses_inclusion_height(self):
        """An ack whose commit_height is in-window passes validation, AND
        the registry stores the INCLUSION height (block.header.block_number),
        not the issuer-claimed commit_height."""
        ack = _make_signed_ack(
            self.issuer, self.issuer_kp, _h(b"valid"), commit_height=1,
        )
        blk = self._propose_and_inject([ack])
        ok, reason = self.chain.validate_block(blk)
        self.assertTrue(ok, reason)
        ok, reason = self.chain.add_block(blk)
        self.assertTrue(ok, reason)
        # Post-activation: registry stores the block's inclusion height
        # (1), not the ack's claimed commit_height (also 1 here, but the
        # pre-vs-post test below makes the distinction concrete).
        self.assertEqual(
            self.chain.witness_ack_registry[ack.request_hash],
            blk.header.block_number,
        )

    def test_registry_uses_inclusion_height_not_commit_height(self):
        """Construct an ack whose commit_height (legitimately in-window
        but EARLIER than the block height) demonstrates that the
        registry stores the inclusion height — the chain's first
        observation — rather than the issuer's signed commit_height."""
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        # Mine 3 empty blocks first so we land the ack at height 4 with
        # a commit_height = 1 (in-window: 4 - 1 = 3 < DEADLINE + GRACE).
        for _ in range(3):
            blk = self.chain.propose_block(
                consensus=consensus,
                proposer_entity=self.proposer,
                transactions=[],
                acks_observed_this_block=[],
            )
            ok, reason = self.chain.add_block(blk)
            self.assertTrue(ok, reason)
        ack = _make_signed_ack(
            self.issuer, self.issuer_kp, _h(b"reg-uses-inc"),
            commit_height=1,
        )
        blk = self._propose_and_inject([ack])
        # Sanity: the block is being landed at a strictly later height.
        self.assertGreater(blk.header.block_number, ack.commit_height)
        ok, reason = self.chain.validate_block(blk)
        self.assertTrue(ok, reason)
        ok, reason = self.chain.add_block(blk)
        self.assertTrue(ok, reason)
        # Post-fix: stored height is the INCLUSION height, not the
        # issuer-claimed commit_height.
        self.assertEqual(
            self.chain.witness_ack_registry[ack.request_hash],
            blk.header.block_number,
        )
        self.assertNotEqual(
            self.chain.witness_ack_registry[ack.request_hash],
            ack.commit_height,
        )


class TestAckBackdatingPreActivation(_AckDefenseHarness):
    """Activation-off. Block height 1 < activation 10**9 → legacy path."""

    activation_height = 10**9

    def test_legacy_registry_stores_commit_height(self):
        """Pre-fork: the chain still records ``ack.commit_height`` in
        the registry (byte-identical replay for historical blocks)."""
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        # Mine 3 empty blocks so the ack lands at a strictly later
        # height than its commit_height.
        for _ in range(3):
            blk = self.chain.propose_block(
                consensus=consensus,
                proposer_entity=self.proposer,
                transactions=[],
                acks_observed_this_block=[],
            )
            ok, reason = self.chain.add_block(blk)
            self.assertTrue(ok, reason)
        ack = _make_signed_ack(
            self.issuer, self.issuer_kp, _h(b"legacy"),
            commit_height=1,
        )
        blk = self._propose_and_inject([ack])
        ok, reason = self.chain.validate_block(blk)
        self.assertTrue(ok, reason)
        ok, reason = self.chain.add_block(blk)
        self.assertTrue(ok, reason)
        # Pre-fork: registry stores the issuer's commit_height verbatim.
        self.assertEqual(
            self.chain.witness_ack_registry[ack.request_hash],
            ack.commit_height,
        )
        self.assertNotEqual(
            self.chain.witness_ack_registry[ack.request_hash],
            blk.header.block_number,
        )


class TestAckBackdatingNonResponseEvidenceTeeth(_AckDefenseHarness):
    """The real-world scenario: a coerced validator backdates the ack
    so the non-response evidence tx admits as 'obligation met'.  Post-
    activation, the registry stores the inclusion height instead, so
    the same evidence still slashes (or, equivalently, is no longer
    excused as obligation-met)."""

    activation_height = 1

    def test_backdated_ack_does_not_excuse_late_inclusion(self):
        """Mine N blocks where N > DEADLINE.  Land an ack that claims
        commit_height = 0 (the earliest possible past height) at the
        late tip.  The bound rejects it immediately — the issuer cannot
        smuggle a 'discharged' marker into the registry by lying about
        when they signed."""
        from messagechain.config import (
            ACK_INCLUSION_GRACE,
            VALIDATOR_MIN_STAKE,
        )
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        # Drive the tip forward a lot, far past the bound.
        n_blocks = WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 10
        for _ in range(n_blocks):
            blk = self.chain.propose_block(
                consensus=consensus,
                proposer_entity=self.proposer,
                transactions=[],
                acks_observed_this_block=[],
            )
            ok, reason = self.chain.add_block(blk)
            self.assertTrue(ok, reason)
        # Ack that claims a backdated commit_height of 0 — pre-fix this
        # would have looked "in window" relative to a freshly-recorded
        # observation at height earliest_obs.
        ack = _make_signed_ack(
            self.issuer, self.issuer_kp, _h(b"backdate-attack"),
            commit_height=0,
        )
        blk = self._propose_and_inject([ack])
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok, "backdated ack must be rejected at the bound")


if __name__ == "__main__":
    unittest.main()
