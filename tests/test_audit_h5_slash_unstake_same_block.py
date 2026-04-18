"""
Regression test for audit finding H5.

When a block contains BOTH an UnstakeTransaction and a SlashTransaction
targeting the same entity, the unstake is a no-op by the time apply
runs (slash_validator zeros the entity's staked balance and wipes its
pending_unstakes), but the entity still pays the unstake fee and its
nonce is still bumped.  The unstake fee is charged on a transaction
that can never take effect — a silent fee burn with no corresponding
state change, and a subtle consensus hazard because the nonce drift
diverges from the block proposer's expectation.

The fix: before the apply loop, drop any UnstakeTransaction whose
entity_id appears as a slashed offender_id in the SAME block.  The
unstake fee is never charged and the nonce never advances.  Slash
continues to run normally, and its burn accounting already covers
any stake the entity held regardless of whether an unstake ran.

Token-conservation invariant checked here:
  sum(balances) + total_staked + total_pending_unstakes + total_burned
  == genesis_supply + total_minted

Before the fix this holds (tokens are accounted), BUT the unstaker is
charged a fee for a tx that produced no effect.  After the fix, the
doomed unstake is dropped entirely — fee unpaid, nonce unbumped.
"""

import time
import unittest

from messagechain import config
from messagechain.consensus.slashing import (
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.core.staking import UnstakeTransaction
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


def _make_unstake(signer, entity_id, amount, nonce, fee):
    tx = UnstakeTransaction(
        entity_id=entity_id,
        amount=amount,
        nonce=nonce,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
    )
    tx.signature = signer.keypair.sign(_hash(tx._signable_data()))
    tx.tx_hash = tx._compute_hash()
    return tx


def _conflicting_headers(proposer, prev_block):
    """Two headers at the same height by the same proposer = double-sign."""
    block_num = prev_block.header.block_number + 1
    hdr_a = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"a"),
        timestamp=time.time(),
        proposer_id=proposer.entity_id,
    )
    hdr_a.proposer_signature = proposer.keypair.sign(_hash(hdr_a.signable_data()))
    hdr_b = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"b"),
        timestamp=time.time() + 1,
        proposer_id=proposer.entity_id,
    )
    hdr_b.proposer_signature = proposer.keypair.sign(_hash(hdr_b.signable_data()))
    return hdr_a, hdr_b


class TestH5SlashPreemptsUnstakeInSameBlock(unittest.TestCase):
    """H5: slash must pre-empt an unstake of the same entity in the same block."""

    def setUp(self):
        self.alice = _entity(b"h5-alice")   # offender (stakes + tries to unstake)
        self.bob = _entity(b"h5-bob")       # slash submitter
        self.carol = _entity(b"h5-carol")   # block proposer

        self.chain = Blockchain()
        self.chain.initialize_genesis(self.carol)
        register_entity_for_test(self.chain, self.alice)
        register_entity_for_test(self.chain, self.bob)
        # Fund
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000
        # Alice stakes
        self.chain.supply.stake(self.alice.entity_id, 1_000)

    def _make_block_with_slash_and_unstake(
        self, unstake_amount=500, unstake_fee=None, slash_fee=1_500,
    ):
        """Hand-build a block carrying a slash tx + unstake tx for alice.

        We call `_apply_block_state` directly to exercise the apply path
        without the state_root/merkle_root/proposer_sig overhead.
        """
        if unstake_fee is None:
            unstake_fee = max(500, self.chain.supply.base_fee)
        prev = self.chain.get_latest_block()

        hdr_a, hdr_b = _conflicting_headers(self.alice, prev)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=hdr_a, header_b=hdr_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=slash_fee)

        # Alice's current nonce drives the unstake nonce.
        alice_nonce = self.chain.nonces.get(self.alice.entity_id, 0)
        unstake_tx = _make_unstake(
            self.alice, self.alice.entity_id,
            amount=unstake_amount, nonce=alice_nonce, fee=unstake_fee,
        )

        header = BlockHeader(
            version=1,
            block_number=prev.header.block_number + 1,
            prev_hash=prev.block_hash,
            merkle_root=_hash(b"h5-test"),
            timestamp=time.time(),
            proposer_id=self.carol.entity_id,
        )
        header.proposer_signature = self.carol.keypair.sign(
            _hash(header.signable_data()),
        )
        block = Block(
            header=header,
            transactions=[],
            slash_transactions=[slash_tx],
            unstake_transactions=[unstake_tx],
        )
        return block, slash_tx, unstake_tx

    def _live_tokens(self):
        """Tokens still alive on-chain (balances + staked + pending).

        Invariant: live tokens == total_supply.  Every burn path must
        subtract from total_supply; if slash silently loses tokens
        (wipes pending_unstakes without zeroing total_supply), this
        identity breaks.
        """
        bal = sum(self.chain.supply.balances.values())
        staked = sum(self.chain.supply.staked.values())
        pending = sum(
            amt for lst in self.chain.supply.pending_unstakes.values()
            for amt, _ in lst
        )
        return bal + staked + pending

    def test_unstake_dropped_when_slash_targets_same_entity(self):
        """The unstake must NOT apply when a same-block slash preempts it.

        Concretely:
          - Alice's balance must NOT be charged the unstake fee.
          - Alice's nonce must NOT be bumped by the unstake.
          - Alice's stake is still slashed (by the SlashTransaction).
        """
        alice_bal_before = self.chain.supply.get_balance(self.alice.entity_id)
        alice_nonce_before = self.chain.nonces.get(self.alice.entity_id, 0)
        alice_stake_before = self.chain.supply.get_staked(self.alice.entity_id)
        self.assertEqual(alice_stake_before, 1_000)

        block, slash_tx, unstake_tx = self._make_block_with_slash_and_unstake(
            unstake_amount=500, slash_fee=1_500,
        )

        # Direct apply — bypasses state_root/merkle machinery so the
        # test focuses purely on the apply-order conflict.
        self.chain._apply_block_state(block)

        # Slash must have run fully.
        self.assertEqual(
            self.chain.supply.get_staked(self.alice.entity_id), 0,
            "Slash did not zero the offender's stake",
        )
        self.assertIn(self.alice.entity_id, self.chain.slashed_validators)

        # The doomed unstake must have been dropped — no fee, no nonce bump.
        alice_bal_after = self.chain.supply.get_balance(self.alice.entity_id)
        alice_nonce_after = self.chain.nonces.get(self.alice.entity_id, 0)
        self.assertEqual(
            alice_bal_after, alice_bal_before,
            "Unstake fee was charged even though slash pre-empted the "
            "unstake — H5 is present (fee charged for a no-op tx)",
        )
        self.assertEqual(
            alice_nonce_after, alice_nonce_before,
            "Unstake nonce bump applied even though the unstake had no "
            "effect — H5 is present (silent nonce drift)",
        )

        # Alice has nothing pending — slash burned the stake, and the
        # unstake was dropped before it could seed pending_unstakes.
        self.assertEqual(
            self.chain.supply.get_pending_unstake(self.alice.entity_id), 0,
        )

    def test_token_conservation_holds_with_slash_plus_unstake(self):
        """Across a slash+unstake block, no tokens vanish from the ledger.

        The audit finding H5 calls this the "audit trail" property: every
        change in live tokens (balances + staked + pending) must be
        accounted for by a mint or a burn.  We assert the delta-form
        identity:

            Δlive == Δtotal_supply

        which holds iff every destruction path is routed through
        total_supply -= burned and every creation path through +minted.
        """
        from messagechain.config import SLASH_FINDER_REWARD_PCT

        live_before = self._live_tokens()
        supply_before = self.chain.supply.total_supply

        block, slash_tx, _ = self._make_block_with_slash_and_unstake(
            unstake_amount=500, slash_fee=1_500,
        )
        self.chain._apply_block_state(block)

        live_delta = self._live_tokens() - live_before
        supply_delta = self.chain.supply.total_supply - supply_before

        self.assertEqual(
            live_delta, supply_delta,
            "Token conservation broken — change in live tokens did not "
            "match change in total_supply after slash+unstake in same "
            "block (audit trail diverged)",
        )

        # Finder reward: bob got it.  (Sanity: bob's balance moved in a
        # predictable direction.)
        expected_finder = 1_000 * SLASH_FINDER_REWARD_PCT // 100
        # bob paid fee, got finder reward.  Net: +finder - slash_fee.
        bob_bal = self.chain.supply.get_balance(self.bob.entity_id)
        self.assertEqual(bob_bal, 10_000 + expected_finder - 1_500)


if __name__ == "__main__":
    unittest.main()
