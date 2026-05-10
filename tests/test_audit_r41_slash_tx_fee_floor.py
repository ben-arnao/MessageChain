"""Watchers compute a slash-tx fee that clears validator admission.

Audit r41 root cause (mainnet stall, ~9h): the equivocation watcher
in ``messagechain/consensus/equivocation_watcher.py`` and the
finality-double-vote drain in ``messagechain/network/node.py`` both
built slash txs with ``fee = supply.base_fee``.  At quiet mempool
``base_fee`` decays to ``MARKET_FEE_FLOOR=1``.  But
``Blockchain.validate_slash_transaction`` calls
``enforce_signature_aware_min_fee(..., flat_floor=MIN_FEE)`` and rejects
any fee below ``MIN_FEE=100``.  Net effect: an under-priced slash tx
admitted to the mempool but every block-proposer that included it
failed block validation -- chain wedged at the height where the
equivocation was first detected.

These tests pin the permanent fix:

  1. ``compute_slash_tx_min_fee(current_height, signature_bytes)``
     returns the smallest fee that clears
     ``enforce_signature_aware_min_fee`` at that height -- i.e. the
     ``MIN_FEE`` floor at today's regime, the ``MIN_FEE_POST_FLAT``
     floor in the legacy Tier-7..Tier-16 window, and the signature-
     aware bump in the older ``FEE_INCLUDES_SIGNATURE_HEIGHT``..
     ``FLAT_FEE_HEIGHT`` window.

  2. ``EquivocationWatcher._emit_slash`` produces a slash tx whose
     fee clears ``validate_slash_transaction`` admission EVEN WHEN
     ``supply.base_fee == MARKET_FEE_FLOOR == 1`` (the failing case).

  3. ``_emit_pending_finality_slashes`` produces a slash tx whose fee
     clears ``validate_slash_transaction`` admission under the same
     ``base_fee == 1`` precondition.
"""

import os
import tempfile
import time
import unittest

from messagechain.config import (
    FEE_INCLUDES_SIGNATURE_HEIGHT,
    FLAT_FEE_HEIGHT,
    MARKET_FEE_FLOOR,
    MARKET_FEE_FLOOR_HEIGHT,
    MIN_FEE,
    MIN_FEE_POST_FLAT,
    TREASURY_ENTITY_ID,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.equivocation_watcher import EquivocationWatcher
from messagechain.consensus.finality import (
    FinalityDoubleVoteEvidence,
    FinalityVote,
    create_finality_vote,
)
from messagechain.consensus.slashing import compute_slash_tx_min_fee
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _make_signed_header(proposer_entity, prev_block, merkle_seed, t_offset=0.0):
    block_num = prev_block.header.block_number + 1
    header = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(merkle_seed),
        timestamp=time.time() + t_offset,
        proposer_id=proposer_entity.entity_id,
    )
    header.proposer_signature = proposer_entity.keypair.sign(
        _hash(header.signable_data())
    )
    return header


class TestComputeSlashTxMinFee(unittest.TestCase):
    """Helper returns the validator's actual admission floor at every regime."""

    def test_returns_min_fee_at_market_floor_regime(self):
        # Today's mainnet regime: every height past MARKET_FEE_FLOOR_HEIGHT
        # binds on flat_floor=MIN_FEE because MARKET_FEE_FLOOR=1 < MIN_FEE.
        for h in (
            MARKET_FEE_FLOOR_HEIGHT,
            MARKET_FEE_FLOOR_HEIGHT + 1,
            10_000,
            10_000_000,
        ):
            self.assertEqual(
                compute_slash_tx_min_fee(h), MIN_FEE,
                f"market-floor regime at h={h} must return MIN_FEE",
            )

    def test_returns_post_flat_floor_in_flat_fee_window(self):
        # Legacy [FLAT_FEE_HEIGHT, MARKET_FEE_FLOOR_HEIGHT) window:
        # validator gates on max(MIN_FEE, MIN_FEE_POST_FLAT) = MIN_FEE_POST_FLAT.
        if FLAT_FEE_HEIGHT < MARKET_FEE_FLOOR_HEIGHT:
            mid = (FLAT_FEE_HEIGHT + MARKET_FEE_FLOOR_HEIGHT) // 2
            self.assertEqual(
                compute_slash_tx_min_fee(mid),
                max(MIN_FEE, MIN_FEE_POST_FLAT),
            )

    def test_returns_min_fee_pre_signature_window(self):
        # Pre-FEE_INCLUDES_SIGNATURE_HEIGHT: just the flat floor (MIN_FEE).
        if FEE_INCLUDES_SIGNATURE_HEIGHT > 0:
            self.assertEqual(
                compute_slash_tx_min_fee(0), MIN_FEE,
            )
            self.assertEqual(
                compute_slash_tx_min_fee(FEE_INCLUDES_SIGNATURE_HEIGHT - 1),
                MIN_FEE,
            )

    def test_none_height_returns_min_fee_floor(self):
        # current_height is None on contexts that don't have a chain
        # height yet -- fall back to the safe MIN_FEE floor.
        self.assertEqual(compute_slash_tx_min_fee(None), MIN_FEE)

    def test_helper_is_at_least_min_fee_at_every_height(self):
        # Belt-and-suspenders: across the activation ladder, the helper
        # NEVER returns a value below MIN_FEE.  This is the property that
        # keeps slash txs from getting rejected at the validator's
        # ``tx_fee < flat_floor=MIN_FEE`` first-line check.
        for h in (0, 100, FEE_INCLUDES_SIGNATURE_HEIGHT,
                  FLAT_FEE_HEIGHT, MARKET_FEE_FLOOR_HEIGHT,
                  MARKET_FEE_FLOOR_HEIGHT + 10_000):
            self.assertGreaterEqual(
                compute_slash_tx_min_fee(h), MIN_FEE,
                f"helper returned below MIN_FEE at h={h}",
            )


class _WatcherFixture(unittest.TestCase):
    """Shared setup mirroring tests/test_equivocation_watcher.py."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-r41-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)

        self.alice = Entity.create(b"alice-r41".ljust(32, b"\x00"))
        self.offender = Entity.create(b"offender-r41".ljust(32, b"\x00"))
        self.finder = Entity.create(b"finder-r41".ljust(32, b"\x00"))

        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.alice,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.alice.entity_id: 1_000_000,
            },
        )
        register_entity_for_test(self.chain, self.offender)
        register_entity_for_test(self.chain, self.finder)
        self.chain.supply.balances[self.offender.entity_id] = 10_000
        self.chain.supply.balances[self.finder.entity_id] = 10_000
        self.chain.supply.stake(self.offender.entity_id, VALIDATOR_MIN_STAKE)

        self.mempool = Mempool()
        self.watcher = EquivocationWatcher(
            chaindb=self.db,
            blockchain=self.chain,
            mempool=self.mempool,
            submitter_entity=self.finder,
        )

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestEquivocationWatcherFeeAtMarketFloor(_WatcherFixture):
    """Pin: watcher's slash tx admits even with base_fee=1."""

    def test_emit_slash_fee_clears_admission_at_base_fee_one(self):
        # Reproduce the audit r41 stall precondition: market base_fee
        # has decayed to MARKET_FEE_FLOOR=1 (quiet mempool).
        self.chain.supply.base_fee = MARKET_FEE_FLOOR
        self.assertEqual(self.chain.supply.base_fee, 1)

        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.offender, prev, b"A")
        header_b = _make_signed_header(self.offender, prev, b"B", t_offset=1.0)

        self.watcher.observe_block_header(header_a)
        self.watcher.observe_block_header(header_b)

        self.assertEqual(
            len(self.mempool.slash_pool), 1,
            "Watcher must emit a SlashTransaction on double-proposal",
        )
        stx = next(iter(self.mempool.slash_pool.values()))

        # Pre-fix: stx.fee == 1 and validate_slash_transaction would
        # return (False, "Fee 1 below signature-aware minimum at height ...").
        # Post-fix: fee >= MIN_FEE so admission passes.
        self.assertGreaterEqual(
            stx.fee, MIN_FEE,
            "Slash-tx fee must be >= MIN_FEE to clear admission "
            "(audit r41 mainnet stall root cause)",
        )

        ok, reason = self.chain.validate_slash_transaction(stx)
        self.assertTrue(
            ok,
            f"Watcher's slash tx must clear validate_slash_transaction "
            f"with base_fee=1 -- got rejection: {reason}",
        )

    def test_emit_slash_fee_tracks_high_base_fee_when_market_busy(self):
        # When base_fee rises above MIN_FEE (busy mempool), the watcher
        # must track it -- pay_fee_with_burn rejects below base_fee.
        # The fix is max(base_fee, admission_floor), not min().
        self.chain.supply.base_fee = MIN_FEE * 50  # 5000
        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.offender, prev, b"X")
        header_b = _make_signed_header(self.offender, prev, b"Y", t_offset=1.0)

        self.watcher.observe_block_header(header_a)
        self.watcher.observe_block_header(header_b)

        stx = next(iter(self.mempool.slash_pool.values()))
        self.assertGreaterEqual(
            stx.fee, MIN_FEE * 50,
            "Slash-tx fee must clear current base_fee in busy markets",
        )


class TestPendingFinalitySlashesFeeAtMarketFloor(unittest.TestCase):
    """Pin the FinalityVote-double-vote drain (network/node.py) the
    same way: must produce a fee that clears admission with base_fee=1.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-r41-fdv-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)
        self.alice = Entity.create(b"alice-r41-fdv".ljust(32, b"\x00"))
        self.offender = Entity.create(b"offender-r41-fdv".ljust(32, b"\x00"))
        self.finder = Entity.create(b"finder-r41-fdv".ljust(32, b"\x00"))
        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.alice,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.alice.entity_id: 1_000_000,
            },
        )
        register_entity_for_test(self.chain, self.offender)
        register_entity_for_test(self.chain, self.finder)
        self.chain.supply.balances[self.finder.entity_id] = 10_000
        self.chain.supply.stake(
            self.offender.entity_id, VALIDATOR_MIN_STAKE,
        )
        self.mempool = Mempool()

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build_finality_double_vote_evidence(self):
        # Two finality votes by the offender at the same height for
        # different block hashes — the canonical double-finality-vote
        # equivocation pattern.
        signing_height = self.chain.height
        target_height = signing_height + 1
        vote_a = create_finality_vote(
            self.offender, b"A" * 32, target_height, signing_height,
        )
        vote_b = create_finality_vote(
            self.offender, b"B" * 32, target_height, signing_height,
        )
        return FinalityDoubleVoteEvidence(
            offender_id=self.offender.entity_id,
            vote_a=vote_a,
            vote_b=vote_b,
        )

    def test_drain_emits_slash_tx_admissible_at_base_fee_one(self):
        from messagechain.network.node import (
            _emit_pending_finality_slashes,
        )
        # Reproduce audit r41 precondition.
        self.chain.supply.base_fee = MARKET_FEE_FLOOR

        # Stash a real evidence in the blockchain's pending list so the
        # drain function picks it up.
        evidence = self._build_finality_double_vote_evidence()
        self.chain._pending_finality_slashes = [evidence]

        _emit_pending_finality_slashes(
            blockchain=self.chain,
            entity=self.finder,
            mempool=self.mempool,
        )

        self.assertEqual(
            len(self.mempool.slash_pool), 1,
            "FinalityDoubleVote drain must emit a slash tx",
        )
        stx = next(iter(self.mempool.slash_pool.values()))
        self.assertGreaterEqual(
            stx.fee, MIN_FEE,
            "FinalityDoubleVote slash tx must clear MIN_FEE admission "
            "floor (audit r41 stall — same defect class as the block-"
            "equivocation watcher).",
        )


if __name__ == "__main__":
    unittest.main()
