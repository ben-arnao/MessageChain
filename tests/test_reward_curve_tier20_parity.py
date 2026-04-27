"""Tier 20 apply/sim parity at the block-add level.

The mint_block_reward (apply path) and the equivalent reward
distribution simulated inside compute_post_state_root (sim path) MUST
produce identical post-block balances at every height — otherwise
add_block rejects the block with a state_root mismatch.

Tier 20 introduces a new code path on both sides; this file exercises
the parity at activation by lowering REWARD_CURVE_HEIGHT to a value
reachable in a one-block test.  The default activation height (15_000)
is too far above genesis for a fast unit test, but the apply/sim
parity property is height-independent — patching the constant lets
the test run in milliseconds while still exercising the curve in both
paths.

If apply and sim diverge here, ``chain.add_block`` returns False with
a state_root-related rejection reason — that's the entire point of the
test.  Conversely a green run proves the two code paths produce
byte-identical state at the same inputs.
"""

import unittest
from unittest.mock import patch

from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.identity.identity import Entity
from tests import pick_selected_proposer, register_entity_for_test


class TestApplySimParityAtTier20(unittest.TestCase):
    """add_block at a Tier-20-active height must succeed (apply == sim)."""

    def _build_chain(self):
        """Fresh chain with alice as the dominant staker (proposer) +
        bob as a smaller secondary staker so the committee has
        multiple entities for mint_block_reward to credit."""
        alice = Entity.create(b"parity-alice".ljust(32, b"\x00"))
        bob = Entity.create(b"parity-bob".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, bob)
        # Stake distribution must keep alice as the lottery-favored
        # proposer (initialize_genesis stakes her).  Bob gets a
        # smaller stake — enough to register as an attester but not
        # enough to displace alice from the proposer schedule.  Both
        # land in different reward-curve bands (alice large band,
        # bob small/mid depending on share) so the post-fork
        # multiplier is exercised in both apply and sim.
        chain.supply.balances[bob.entity_id] = 1_000_000
        chain.supply.staked[bob.entity_id] = 1_000  # small relative to alice's genesis stake
        return alice, bob, chain

    def test_block_at_activation_height_applies_cleanly(self):
        # Patch both binding sites: inflation.py reads REWARD_CURVE_
        # HEIGHT from its own module-level binding (imported once at
        # module load); blockchain.py re-imports from messagechain.
        # config inside the function body each call.  Patch both so
        # apply and sim observe the same activation.
        #
        # Patched value of 1 means the very first non-genesis block
        # (height 1) is at activation — apply and sim both go through
        # the post-Tier-20 code path on that block.
        with patch(
            "messagechain.economics.inflation.REWARD_CURVE_HEIGHT", 1,
        ), patch(
            "messagechain.config.REWARD_CURVE_HEIGHT", 1,
        ):
            alice, bob, chain = self._build_chain()
            consensus = ProofOfStake()

            proposer = pick_selected_proposer(chain, [alice, bob])
            nonce = chain.nonces.get(proposer.entity_id, 0)
            tx = create_transaction(
                proposer, "tier-20 mint", fee=1500, nonce=nonce,
            )
            prev = chain.get_latest_block()
            block_height = prev.header.block_number + 1
            state_root = chain.compute_post_state_root(
                [tx], proposer.entity_id, block_height,
            )
            block = consensus.create_block(
                proposer, [tx], prev, state_root=state_root,
            )

            success, reason = chain.add_block(block)
            self.assertTrue(
                success,
                f"Tier 20 block must apply cleanly (apply==sim parity). "
                f"reason: {reason}",
            )

    def test_multiple_post_activation_blocks_apply_cleanly(self):
        # Add several post-activation blocks back-to-back.  Any
        # apply/sim drift accumulates as state_root mismatch on the
        # very next block — surface it loudly.  Use the
        # deterministically-scheduled proposer per block so the
        # proposer-schedule check stays orthogonal to the curve
        # under test.
        with patch(
            "messagechain.economics.inflation.REWARD_CURVE_HEIGHT", 1,
        ), patch(
            "messagechain.config.REWARD_CURVE_HEIGHT", 1,
        ):
            alice, bob, chain = self._build_chain()
            consensus = ProofOfStake()

            for i in range(3):
                proposer = pick_selected_proposer(chain, [alice, bob])
                nonce = chain.nonces.get(proposer.entity_id, 0)
                tx = create_transaction(
                    proposer, f"post-activation block {i}",
                    fee=1500, nonce=nonce,
                )
                prev = chain.get_latest_block()
                bh = prev.header.block_number + 1
                state_root = chain.compute_post_state_root(
                    [tx], proposer.entity_id, bh,
                )
                block = consensus.create_block(
                    proposer, [tx], prev, state_root=state_root,
                )
                success, reason = chain.add_block(block)
                self.assertTrue(
                    success,
                    f"Block {i} (height {bh}) failed apply==sim parity: "
                    f"{reason}",
                )


if __name__ == "__main__":
    unittest.main()
