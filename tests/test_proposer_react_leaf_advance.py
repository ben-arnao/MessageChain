"""
Regression test for the proposer-side leaf-advance bug, symmetric to the
1.29.3 validator-side fix.

Bug: `Blockchain.propose_block`'s leaf-advance loop walks the proposer's
own message / transfer / slash / governance / authority / stake / unstake
txs and advances `keypair._next_leaf` past each tx's leaf BEFORE reading
`expected_proposer_leaf` (which determines the committed state_root).
The list omitted `react_transactions` — so when an honest proposer signed
a ReactTransaction earlier, then reloaded their keypair (e.g. systemd
restart) and `_next_leaf` reset to the on-chain watermark without the
unconfirmed react's bump, the proposer would commit a state_root computed
against a stale leaf-watermark.

When the same block is then validated, `_apply_block_state` writes the
correct post-apply leaf_watermark for the react and the simulated
state_root computed by the validator's `compute_post_state_root`
diverges from the committed one — the block self-rejects with
"Invalid state_root — state commitment mismatch".

Headline test: simulate the keypair reload, propose a block carrying the
proposer's own pre-signed ReactTransaction, assert the resulting block
validates successfully against an honest validator's `_append_block`.

The 1.29.3 fix corrected this on the validator side (`_append_block`
now passes `react_transactions` to `compute_post_state_root`); this is
the symmetric one-line fix on the proposer side.
"""

import hashlib
import os
import tempfile
import time
import unittest

import messagechain.config as _config
from messagechain.config import (
    HASH_ALGO,
    REACT_CHOICE_UP,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.reaction import (
    REACT_FEE_FLOOR,
    create_react_transaction,
)
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _patch_react_heights(value: int) -> dict:
    """Drop REACT_TX_HEIGHT to `value` in every module that captured it.

    Mirror of the helper in test_react_no_self_message_tier27.py — react
    behaviour rides on capturing the constant at import time, so a single
    config edit isn't enough.
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


class TestProposerReactLeafAdvance(unittest.TestCase):
    """Proposer's leaf-advance loop must include react_transactions so
    a self-react in the proposed block doesn't poison expected_proposer_leaf.
    """

    def setUp(self):
        # Drop ReactTx activation so any height >= 1 sees the rule.
        self._react_snap = _patch_react_heights(0)

        self.tmp = tempfile.TemporaryDirectory()
        self.db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))
        self.proposer = Entity.create(
            b"proposer_react_leaf_test".ljust(32, b"\x00"),
        )
        self.bystander = Entity.create(
            b"bystander_react_leaf".ljust(32, b"\x00"),
        )
        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        register_entity_for_test(self.chain, self.bystander)
        # Fund the proposer well above any react fee floor.
        self.chain.supply.balances[self.proposer.entity_id] = (
            self.chain.supply.balances.get(self.proposer.entity_id, 0)
            + 10_000_000
        )
        # Stake & register as a validator so propose_block + add_block
        # accept this entity as the slot leader.
        self.chain.supply.stake(self.proposer.entity_id, VALIDATOR_MIN_STAKE)
        self.consensus = ProofOfStake()
        self.consensus.stakes[self.proposer.entity_id] = VALIDATOR_MIN_STAKE

    def tearDown(self):
        _restore_react_heights(self._react_snap)
        try:
            self.db.close()
        except Exception:
            pass
        try:
            self.tmp.cleanup()
        except (OSError, PermissionError):
            # Windows sqlite cleanup race — leave the tempdir to OS reaper.
            pass

    def _sign_self_react_tx(self):
        """Build a ReactTransaction the proposer signs against the bystander.

        target_is_user=True (user-trust) avoids needing a landed message
        whose tx_hash is the target — keeps the test focused on the
        leaf-advance path in propose_block.
        """
        nonce = self.chain.nonces.get(self.proposer.entity_id, 0)
        return create_react_transaction(
            self.proposer,
            target=self.bystander.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=nonce,
            fee=max(REACT_FEE_FLOOR * 100, 10_000),
        )

    def test_proposer_with_pending_react_after_keypair_reload_no_state_root_mismatch(self):
        """Headline regression: propose_block must advance _next_leaf past
        any react_transactions the proposer signed before computing
        expected_proposer_leaf.  Without the fix, the committed state_root
        is computed against the stale leaf watermark and add_block rejects
        the block with a state-commitment mismatch.
        """
        # Proposer signs the react first (this would normally flow through
        # mempool / gossip).  The signature consumes a leaf.
        rtx = self._sign_self_react_tx()
        rtx_leaf = rtx.signature.leaf_index

        # Simulate keypair reload: _next_leaf rewinds back to the tx's leaf
        # as if the keypair was reconstructed from the on-chain watermark
        # (which lags the unconfirmed react).
        self.proposer.keypair._next_leaf = rtx_leaf

        block = self.chain.propose_block(
            self.consensus, self.proposer, [],
            react_transactions=[rtx],
        )

        # add_block exercises the validator-side _append_block path,
        # which re-simulates compute_post_state_root and rejects on
        # state_root mismatch.  This is exactly the production failure
        # mode and the assertion that fails on origin/main.
        success, reason = self.chain.add_block(block)
        self.assertTrue(
            success,
            f"Block with proposer's own react tx must validate; got: {reason}",
        )

        # The proposer's header signature must use a leaf STRICTLY AFTER
        # the react tx's leaf — that's the mechanical invariant the
        # leaf-advance loop is supposed to guarantee.
        self.assertGreater(
            block.header.proposer_signature.leaf_index,
            rtx_leaf,
            "Proposer signature must use a leaf after the react tx's leaf",
        )

    def test_proposer_without_react_unchanged(self):
        """Sanity check: a proposer with NO react in the tx list still
        produces a block that validates.  Confirms the fix doesn't disturb
        the no-react path.
        """
        block = self.chain.propose_block(
            self.consensus, self.proposer, [],
        )
        success, reason = self.chain.add_block(block)
        self.assertTrue(success, f"Empty block must validate: {reason}")

    def test_proposer_react_leaf_index_advances(self):
        """Direct assertion: when a react tx authored by the proposer is
        included, _next_leaf is advanced past that tx's leaf BEFORE
        the proposer signs the block header — so the header signature
        sits on a fresh leaf and expected_proposer_leaf reflects it.
        """
        rtx = self._sign_self_react_tx()
        rtx_leaf = rtx.signature.leaf_index

        # Roll the in-memory counter back to the react's leaf.
        self.proposer.keypair._next_leaf = rtx_leaf

        # propose_block should advance _next_leaf past rtx_leaf as part
        # of its proposer-leaf hygiene.  After it returns, the keypair's
        # _next_leaf must be > rtx_leaf (the proposer header signature
        # consumed at least one leaf above).
        block = self.chain.propose_block(
            self.consensus, self.proposer, [],
            react_transactions=[rtx],
        )

        self.assertGreater(
            self.proposer.keypair._next_leaf,
            rtx_leaf,
            "Proposer keypair _next_leaf must advance past the react tx's leaf",
        )
        # And the block's header signature must land on a leaf > rtx_leaf.
        self.assertGreater(
            block.header.proposer_signature.leaf_index,
            rtx_leaf,
        )


if __name__ == "__main__":
    unittest.main()
