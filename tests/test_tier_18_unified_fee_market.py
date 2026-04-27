"""Tier 18: unified fee market across Message + Transfer + React.

Covers the four coordinated changes:

* Gap 1 — `react_pool` admits with fee-density eviction (a higher-
  fee/byte tx displaces the lowest-density pending entry when full).
* Gap 5 — `REACT_FEE_FLOOR` retires at TIER_18_HEIGHT; admission floor
  collapses to `MARKET_FEE_FLOOR=1`.  Pre-fork blocks still see the
  legacy floor.
* Gap 4 — EIP-1559 controller's fullness signal counts react_transactions
  at and after TIER_18_HEIGHT.
* Gap 2/3 — `validate_block` rejects post-Tier-18 blocks whose
  combined Message + Transfer + React serialized bytes exceed
  `MAX_BLOCK_TOTAL_BYTES`.
"""

import os
import tempfile
import time
import unittest

import messagechain.config as _config
from messagechain.config import (
    HASH_ALGO,
    GENESIS_ALLOCATION,
    REACT_CHOICE_UP,
    MARKET_FEE_FLOOR,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader
from messagechain.core.mempool import Mempool
from messagechain.core.reaction import (
    REACT_FEE_FLOOR,
    create_react_transaction,
    verify_react_transaction,
)
from tests import register_entity_for_test


def _msg_target() -> bytes:
    return b"\xcc" * 32


# ── Gap 1: fee-density eviction in react_pool ───────────────────────


class TestReactPoolFeeDensityEviction(unittest.TestCase):
    """At capacity, a higher fee-density ReactTx displaces the lowest-density entry."""

    def setUp(self):
        self.voter = Entity.create(b"t18_v_pool".ljust(32, b"\x00"))
        self.target = Entity.create(b"t18_t_pool".ljust(32, b"\x00"))
        self.mp = Mempool()
        self.mp.react_pool_max_size = 2

    def _rtx(self, nonce, fee):
        return create_react_transaction(
            self.voter,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=nonce,
            fee=fee,
        )

    def test_higher_fee_evicts_lowest_when_full(self):
        low = self._rtx(nonce=0, fee=200)
        mid = self._rtx(nonce=1, fee=500)
        self.assertTrue(self.mp.add_react_transaction(low))
        self.assertTrue(self.mp.add_react_transaction(mid))
        # Pool is now full at size=2.  A higher-fee tx should displace
        # `low`.
        high = self._rtx(nonce=2, fee=1_000)
        self.assertTrue(self.mp.add_react_transaction(high))
        present = {tx.tx_hash for tx in self.mp.get_react_transactions()}
        self.assertIn(high.tx_hash, present)
        self.assertIn(mid.tx_hash, present)
        self.assertNotIn(low.tx_hash, present)

    def test_lower_fee_rejected_when_full(self):
        big1 = self._rtx(nonce=0, fee=1_000)
        big2 = self._rtx(nonce=1, fee=1_500)
        self.assertTrue(self.mp.add_react_transaction(big1))
        self.assertTrue(self.mp.add_react_transaction(big2))
        cheap = self._rtx(nonce=2, fee=100)
        self.assertFalse(self.mp.add_react_transaction(cheap))

    def test_get_returns_density_sorted(self):
        """`get_react_transactions` returns highest fee-density first."""
        self.mp.react_pool_max_size = 4
        a = self._rtx(nonce=0, fee=200)
        b = self._rtx(nonce=1, fee=1_000)
        c = self._rtx(nonce=2, fee=500)
        self.mp.add_react_transaction(a)
        self.mp.add_react_transaction(b)
        self.mp.add_react_transaction(c)
        ordered = self.mp.get_react_transactions()
        # Same byte size across all three (sig dominates), so density
        # ordering matches absolute-fee ordering.
        self.assertEqual([t.fee for t in ordered], [1_000, 500, 200])


# ── Gap 5: REACT_FEE_FLOOR retires at TIER_18_HEIGHT ────────────────


class TestReactFeeFloorRetirement(unittest.TestCase):
    """Post-Tier-18 ReactTx admission uses MARKET_FEE_FLOOR; pre-fork uses REACT_FEE_FLOOR."""

    @classmethod
    def setUpClass(cls):
        cls.voter = Entity.create(b"t18_v_floor".ljust(32, b"\x00"))
        cls.target = Entity.create(b"t18_t_floor".ljust(32, b"\x00"))

    def test_pre_tier_18_rejects_low_fee(self):
        """Below TIER_18_HEIGHT, fee < REACT_FEE_FLOOR (=10) is rejected."""
        # Build a tx with fee just below the legacy floor.
        tx = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=REACT_FEE_FLOOR - 1,
        )
        # At REACT_TX_HEIGHT (Tier 17 active, Tier 18 not yet) the
        # legacy floor applies — verify rejects.
        self.assertFalse(verify_react_transaction(
            tx, self.voter.public_key,
            current_height=_config.REACT_TX_HEIGHT,
        ))

    def test_post_tier_18_accepts_market_floor_fee(self):
        """At/after TIER_18_HEIGHT, fee >= MARKET_FEE_FLOOR (=1) admits."""
        tx = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=MARKET_FEE_FLOOR,
        )
        self.assertTrue(verify_react_transaction(
            tx, self.voter.public_key,
            current_height=_config.TIER_18_HEIGHT,
        ))


# ── Gap 4 + 2/3: in-chain integration at TIER_18_HEIGHT ─────────────


class TestUnifiedBudgetAndControllerSignal(unittest.TestCase):
    """validate_block enforces unified byte budget; controller counts react."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Push the activation height down to 0 so any test block is
        # already post-fork.  Restore in tearDown to keep leakage out
        # of other tests (CLAUDE.md MERKLE_TREE_HEIGHT-style discipline).
        self._orig_t18 = _config.TIER_18_HEIGHT
        self._orig_react = _config.REACT_TX_HEIGHT
        _config.TIER_18_HEIGHT = 0
        _config.REACT_TX_HEIGHT = 0
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        self._orig_bc_react = _bc.REACT_TX_HEIGHT
        self._orig_rxn_react = _rxn.REACT_TX_HEIGHT
        _bc.REACT_TX_HEIGHT = 0
        _rxn.REACT_TX_HEIGHT = 0
        # Shrink the unified budget so we can exercise overflow with a
        # small handful of txs instead of building 100+ KB blocks in a
        # unit test.
        self._orig_max_total = _config.MAX_BLOCK_TOTAL_BYTES
        _config.MAX_BLOCK_TOTAL_BYTES = 5_000

        self.proposer = Entity.create(b"t18_prop".ljust(32, b"\x00"))
        self.voter = Entity.create(b"t18_voter".ljust(32, b"\x00"))
        self.target = Entity.create(b"t18_target".ljust(32, b"\x00"))

    def tearDown(self):
        _config.TIER_18_HEIGHT = self._orig_t18
        _config.REACT_TX_HEIGHT = self._orig_react
        _config.MAX_BLOCK_TOTAL_BYTES = self._orig_max_total
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        _bc.REACT_TX_HEIGHT = self._orig_bc_react
        _rxn.REACT_TX_HEIGHT = self._orig_rxn_react
        if hasattr(self, "chain") and self.chain.db is not None:
            self.chain.db.close()
        try:
            self.tmp.cleanup()
        except (OSError, PermissionError):
            pass

    def _build_chain(self) -> Blockchain:
        from messagechain.storage.chaindb import ChainDB
        db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))
        chain = Blockchain(db=db)
        chain.initialize_genesis(self.proposer)
        register_entity_for_test(chain, self.proposer)
        register_entity_for_test(chain, self.voter)
        register_entity_for_test(chain, self.target)
        chain.supply.balances[self.voter.entity_id] = 1_000_000_000
        self.chain = chain
        return chain

    def _build_react_block(self, react_txs: list) -> Block:
        import hashlib
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
        block = Block(header=header, transactions=[])
        block.react_transactions = list(react_txs)
        block.block_hash = block._compute_hash()
        return block

    def test_unified_budget_rejects_oversized_block(self):
        """A block whose combined React bytes exceed MAX_BLOCK_TOTAL_BYTES rejects."""
        chain = self._build_chain()
        # Each React tx is ~2.7 KB (WOTS+ witness dominates).  With
        # MAX_BLOCK_TOTAL_BYTES = 5 000 in setUp, two txs already
        # blow the budget.
        nonce = chain.nonces.get(self.voter.entity_id, 0)
        rtxs = [
            create_react_transaction(
                self.voter, target=self.target.entity_id, target_is_user=True,
                choice=REACT_CHOICE_UP, nonce=nonce + i, fee=10_000,
            )
            for i in range(3)
        ]
        block = self._build_react_block(rtxs)
        ok, reason = chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("Tier-18 unified budget", reason)

    def test_unified_budget_admits_under_cap(self):
        """A single-React-tx block is well under the 5 KB cap."""
        chain = self._build_chain()
        # Put MAX_BLOCK_TOTAL_BYTES back high enough for a single tx
        # to admit under the rest of validate_block (we're only
        # exercising the unified-budget gate here, not full block
        # admission with merkle_root etc.).
        _config.MAX_BLOCK_TOTAL_BYTES = 100_000
        nonce = chain.nonces.get(self.voter.entity_id, 0)
        rtx = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=nonce, fee=10_000,
        )
        block = self._build_react_block([rtx])
        ok, reason = chain.validate_block(block)
        # The block likely fails on merkle_root (we didn't fold the
        # react tx hash), but it must NOT fail on the unified-budget
        # gate.  Assert the specific reason isn't budget-related.
        if not ok:
            self.assertNotIn("unified budget", reason)

    def test_controller_counts_react_in_fullness_signal(self):
        """Tier 18: applying a block with react txs bumps the EIP-1559 signal."""
        chain = self._build_chain()
        baseline_total = (
            len(chain.get_latest_block().transactions)
            + len(chain.get_latest_block().transfer_transactions)
        )
        # The controller signal is computed inside _apply_block_state.
        # Construct a block carrying react txs and apply via the
        # internal hook; assert update_base_fee receives the inflated
        # count.
        nonce = chain.nonces.get(self.voter.entity_id, 0)
        rtxs = [
            create_react_transaction(
                self.voter, target=self.target.entity_id, target_is_user=True,
                choice=REACT_CHOICE_UP, nonce=nonce + i, fee=10_000,
            )
            for i in range(3)
        ]
        block = self._build_react_block(rtxs)

        seen = []
        orig = chain.supply.update_base_fee
        def spy(parent_tx_count, current_height=None):
            seen.append(parent_tx_count)
            return orig(parent_tx_count, current_height)
        chain.supply.update_base_fee = spy
        try:
            chain._apply_block_state(block)
        finally:
            chain.supply.update_base_fee = orig
        self.assertGreater(len(seen), 0)
        # Post-Tier-18: signal must include the 3 react txs.  Absent
        # the Gap-4 fix, `parent_tx_count` would be just message+
        # transfer (= 0 here), missing the react contribution
        # entirely.
        self.assertEqual(seen[0], baseline_total + 3)


if __name__ == "__main__":
    unittest.main()
