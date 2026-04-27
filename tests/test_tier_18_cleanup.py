"""Tier 18 cleanup: three real-concern fixes.

* Fix 1 — `MAX_BLOCK_TOTAL_BYTES = 200_000` binds under 2-lane
  congestion (was 300_000, only bound under 3-lane).
* Fix 2 — `Mempool.add_react_transaction` admits at MARKET_FEE_FLOOR
  (was MIN_FEE), aligning with the consensus-side floor that Tier 18
  Gap 5 already collapsed to MARKET_FEE_FLOOR.
* Fix 3 — `pos.create_block` enforces the unified byte budget at
  block-build time so a proposer cannot construct a post-Tier-18
  block that validators would reject.  Trim policy: drop the lowest
  fee-density entry across Message + Transfer + React lanes until
  the block fits.
"""

import os
import tempfile
import time
import unittest

import messagechain.config as _config
from messagechain.config import (
    HASH_ALGO,
    MARKET_FEE_FLOOR,
    REACT_CHOICE_UP,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader
from messagechain.core.mempool import Mempool
from messagechain.core.reaction import create_react_transaction
from tests import register_entity_for_test


# ── Fix 1: tightened MAX_BLOCK_TOTAL_BYTES ──────────────────────────


class TestUnifiedBudgetTighter(unittest.TestCase):
    """200_000 is the right size: fits 1-lane-full, binds under 2-lane."""

    def test_value_is_200k(self):
        self.assertEqual(_config.MAX_BLOCK_TOTAL_BYTES, 200_000)

    def test_accommodates_legacy_message_budget(self):
        """Pure-message blocks at the legacy per-kind cap still fit."""
        self.assertGreaterEqual(
            _config.MAX_BLOCK_TOTAL_BYTES,
            _config.MAX_BLOCK_MESSAGE_BYTES,
        )


# ── Fix 2: mempool admission floor aligned with consensus ───────────


class TestReactPoolFloorAlignsWithMarket(unittest.TestCase):
    """`add_react_transaction` accepts down to MARKET_FEE_FLOOR (=1)."""

    @classmethod
    def setUpClass(cls):
        cls.voter = Entity.create(b"cleanup_voter".ljust(32, b"\x00"))
        cls.target = Entity.create(b"cleanup_target".ljust(32, b"\x00"))

    def setUp(self):
        self.mp = Mempool()

    def test_admits_market_floor_fee(self):
        """A fee-1 tx admits even though it's well below the legacy MIN_FEE."""
        tx = create_react_transaction(
            self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
            fee=MARKET_FEE_FLOOR,
        )
        self.assertTrue(self.mp.add_react_transaction(tx))

    def test_rejects_below_market_floor(self):
        """fee=0 still rejects (the no-zero-fee invariant)."""
        tx = create_react_transaction(
            self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=0,
            fee=0,
        )
        self.assertFalse(self.mp.add_react_transaction(tx))


# ── Fix 3: proposer-side unified-budget trim ────────────────────────


class TestProposerUnifiedBudgetTrim(unittest.TestCase):
    """`pos.create_block` post-Tier-18 trims tx lists to fit MAX_BLOCK_TOTAL_BYTES."""

    def setUp(self):
        # Push activation down + shrink budget so a small handful of
        # txs trips the cap.  Restore in tearDown.
        self._orig_t18 = _config.TIER_18_HEIGHT
        self._orig_react = _config.REACT_TX_HEIGHT
        self._orig_max_total = _config.MAX_BLOCK_TOTAL_BYTES
        _config.TIER_18_HEIGHT = 0
        _config.REACT_TX_HEIGHT = 0
        _config.MAX_BLOCK_TOTAL_BYTES = 5_000  # 1-2 react txs fit; 3+ don't
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        self._orig_bc_react = _bc.REACT_TX_HEIGHT
        self._orig_rxn_react = _rxn.REACT_TX_HEIGHT
        _bc.REACT_TX_HEIGHT = 0
        _rxn.REACT_TX_HEIGHT = 0

        self.proposer = Entity.create(b"trim_prop".ljust(32, b"\x00"))
        self.voter = Entity.create(b"trim_voter".ljust(32, b"\x00"))
        self.target = Entity.create(b"trim_target".ljust(32, b"\x00"))
        self.tmp = tempfile.TemporaryDirectory()

        from messagechain.storage.chaindb import ChainDB
        db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))
        self.chain = Blockchain(db=db)
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        register_entity_for_test(self.chain, self.voter)
        register_entity_for_test(self.chain, self.target)
        self.chain.supply.balances[self.voter.entity_id] = 1_000_000_000

    def tearDown(self):
        _config.TIER_18_HEIGHT = self._orig_t18
        _config.REACT_TX_HEIGHT = self._orig_react
        _config.MAX_BLOCK_TOTAL_BYTES = self._orig_max_total
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        _bc.REACT_TX_HEIGHT = self._orig_bc_react
        _rxn.REACT_TX_HEIGHT = self._orig_rxn_react
        if self.chain.db is not None:
            self.chain.db.close()
        try:
            self.tmp.cleanup()
        except (OSError, PermissionError):
            pass

    def test_proposer_trims_to_fit_unified_budget(self):
        """Three react txs total > 5 KB; create_block trims the lowest-fee
        entry first so the resulting block fits MAX_BLOCK_TOTAL_BYTES."""
        from messagechain.consensus.pos import ProofOfStake
        nonce = self.chain.nonces.get(self.voter.entity_id, 0)
        rtxs = [
            create_react_transaction(
                self.voter, target=self.target.entity_id,
                target_is_user=True, choice=REACT_CHOICE_UP,
                nonce=nonce + i,
                # Stagger fees so the trim has a clear lowest-density
                # victim: the fee=10 tx should be dropped first.
                fee=10 if i == 0 else 1_000,
            )
            for i in range(3)
        ]
        prev = self.chain.get_latest_block()
        consensus = ProofOfStake()
        block = consensus.create_block(
            self.proposer, [], prev,
            react_transactions=rtxs,
        )
        # Verify total bytes <= MAX_BLOCK_TOTAL_BYTES.
        total = sum(len(t.to_bytes()) for t in block.react_transactions)
        self.assertLessEqual(total, _config.MAX_BLOCK_TOTAL_BYTES)
        # The lowest-fee tx (the fee=10 one) should have been dropped;
        # the higher-fee survivors remain.
        kept_hashes = {t.tx_hash for t in block.react_transactions}
        self.assertNotIn(rtxs[0].tx_hash, kept_hashes)


if __name__ == "__main__":
    unittest.main()
