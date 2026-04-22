"""Tests for the attester-pool fee-funding hard fork.

Background
----------
Latent economic failure in the shipped code: post-
ATTESTER_REWARD_SPLIT_HEIGHT the attester_pool is divided pro-rata
across the full ATTESTER_COMMITTEE_TARGET_SIZE committee.  With
BLOCK_REWARD=16 the attester_pool is 12, 128-member committee gets
per_slot = 12 // 128 = 0 → every attester earns exactly zero per
block.  At floor (reward=4, pool=3) it's still 0.  The consensus-
critical attestation work is uncompensated.

Fix: redirect half of the base-fee BURN into the attester pool.  At
MIN_FEE=100 and a full block of 10 txs, that's 500 tokens → 128
slots ≈ 4 tokens/slot.  Real reward, scales with traffic.

Implementation:
  * `pay_fee_with_burn` splits base_fee into attester_share and
    actual_burn post-activation.  Only actual_burn hits total_burned
    / total_supply.  attester_share accrues into a per-block
    accumulator (`SupplyTracker.attester_fee_pool_this_block`).
  * `mint_block_reward` reads the accumulator and adds it to the
    issuance-side attester_pool before pro-rata division.
  * The accumulator resets to 0 at start-of-block so it never leaks
    between blocks.

Pre-activation: accumulator always 0; behavior byte-for-byte
identical to the legacy code.
"""

import unittest
from unittest.mock import patch

from messagechain.economics.inflation import SupplyTracker
from messagechain.consensus.attester_committee import ATTESTER_REWARD_PER_SLOT
from messagechain.config import (
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    PROPOSER_REWARD_NUMERATOR,
    PROPOSER_REWARD_DENOMINATOR,
    ATTESTER_REWARD_SPLIT_HEIGHT,
    ATTESTER_FEE_SHARE_BPS,
    ATTESTER_FEE_FUNDING_HEIGHT,
    GENESIS_SUPPLY,
    TREASURY_ENTITY_ID,
    MIN_FEE,
)


# ATTESTER_FEE_FUNDING_HEIGHT >= ATTESTER_REWARD_SPLIT_HEIGHT is the
# intended operator deployment order; these unit tests validate both
# heights together so the accumulator is exercised against the pro-
# rata committee path.
PRE_ACTIVATION_HEIGHT = max(0, ATTESTER_FEE_FUNDING_HEIGHT - 1)
POST_ACTIVATION_HEIGHT = max(
    ATTESTER_FEE_FUNDING_HEIGHT, ATTESTER_REWARD_SPLIT_HEIGHT,
)


def _make_committee(n: int) -> list[bytes]:
    """Deterministic list of n distinct 32-byte IDs distinct from the
    0x70 ('p') proposer used throughout this file.  We draw from a
    256-byte keyspace that explicitly skips 0x70."""
    out = []
    i = 0
    while len(out) < n:
        b = (i + 0x10) & 0xFF
        if b == 0x70:  # collides with proposer b"p" * 32
            i += 1
            continue
        out.append(bytes([b]) * 32)
        i += 1
    return out


class TestAccumulatorField(unittest.TestCase):
    """The per-block accumulator exists, starts at 0, and is documented."""

    def test_accumulator_initialized_to_zero(self):
        supply = SupplyTracker()
        self.assertEqual(supply.attester_fee_pool_this_block, 0)


class TestPreActivationBehaviorPreserved(unittest.TestCase):
    """Pre-activation: accumulator never accrues, burn is 100% base_fee.

    Byte-for-byte-identical invariant — if the fork never fires, the
    chain reproduces the same balance deltas as the legacy code."""

    def test_pre_activation_fee_burn_fully_burned(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        supply.balances[sender] = 10_000
        supply.balances[proposer] = 0

        base_fee = 100
        fee = 150  # tip = 50
        ok = supply.pay_fee_with_burn(
            sender, proposer, fee, base_fee,
            block_height=PRE_ACTIVATION_HEIGHT,
        )
        self.assertTrue(ok)

        # 100% of base_fee hits the burn totals, 0 goes to the pool.
        self.assertEqual(supply.total_burned, 100)
        self.assertEqual(supply.attester_fee_pool_this_block, 0)
        # Tip path unchanged.
        self.assertEqual(supply.balances[proposer], 50)

    def test_pre_activation_mint_does_not_read_accumulator(self):
        """Even if somehow the accumulator is nonzero pre-activation
        (should never happen), mint_block_reward doesn't add it to the
        pool — the gate is on block_height."""
        supply = SupplyTracker()
        supply.attester_fee_pool_this_block = 999  # sanity: force nonzero
        proposer = b"p" * 32
        committee = _make_committee(12)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )
        # Legacy attester_pool=12; 12 paid 1 each; accumulator ignored.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)
        # result total reflects mint-side issuance only.
        self.assertEqual(result["total_attestor_reward"], 12)


class TestPayFeeWithBurnSplit(unittest.TestCase):
    """Post-activation: pay_fee_with_burn routes half of base_fee to
    the per-block accumulator instead of burning it."""

    def test_post_activation_split_50_50(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        supply.balances[sender] = 10_000
        supply.balances[proposer] = 0

        base_fee = 100
        fee = 150  # tip = 50
        ok = supply.pay_fee_with_burn(
            sender, proposer, fee, base_fee,
            block_height=POST_ACTIVATION_HEIGHT,
        )
        self.assertTrue(ok)

        # ATTESTER_FEE_SHARE_BPS = 5000 → 50 tokens to pool, 50 burned.
        attester_share = base_fee * ATTESTER_FEE_SHARE_BPS // 10_000
        actual_burn = base_fee - attester_share
        self.assertEqual(supply.total_burned, actual_burn)
        self.assertEqual(
            supply.attester_fee_pool_this_block, attester_share,
        )
        # fee_burn_this_block mirror tracks the actual burn as well
        # (downstream archive-reward redirect runs on actual_burn).
        self.assertEqual(supply.fee_burn_this_block, actual_burn)
        # Tip path unchanged — proposer still gets fee - base_fee.
        self.assertEqual(supply.balances[proposer], 50)

    def test_multiple_fees_accumulate(self):
        """Multiple pay_fee_with_burn calls in the same block add up in
        the accumulator; the apply-path mint consumes the sum."""
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        supply.balances[sender] = 10_000

        base_fee = 100
        for _ in range(10):
            supply.pay_fee_with_burn(
                sender, proposer, base_fee + 50, base_fee,
                block_height=POST_ACTIVATION_HEIGHT,
            )

        # 10 txs × 50 tokens share each = 500 in the pool.
        self.assertEqual(supply.attester_fee_pool_this_block, 500)
        # 10 × 50 = 500 burned.
        self.assertEqual(supply.total_burned, 500)

    def test_underpaid_fee_does_not_touch_accumulator(self):
        """Rejected fee (< base_fee) returns False without mutating
        anything — mirrors the pre-activation reject path."""
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        supply.balances[sender] = 1000

        ok = supply.pay_fee_with_burn(
            sender, proposer, fee=50, base_fee=100,
            block_height=POST_ACTIVATION_HEIGHT,
        )
        self.assertFalse(ok)
        self.assertEqual(supply.attester_fee_pool_this_block, 0)
        self.assertEqual(supply.total_burned, 0)
        # Sender balance unchanged.
        self.assertEqual(supply.balances[sender], 1000)


class TestMintBlockRewardConsumesAccumulator(unittest.TestCase):
    """Post-activation mint_block_reward reads the per-block accumulator
    and adds it to the attester_pool before pro-rata division."""

    def test_accumulator_added_to_pool(self):
        """128-member committee, accumulator = 500:
        attester_pool = 12 + 500 = 512; per_slot = 512 // 128 = 4.
        """
        supply = SupplyTracker()
        supply.attester_fee_pool_this_block = 500
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        # Per-slot = (12 + 500) // 128 = 4.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 4)
        self.assertEqual(result["total_attestor_reward"], 4 * 128)

    def test_zero_fees_accumulator_still_zero(self):
        """Post-activation with 0 txs: accumulator = 0, so per_slot is
        back to the underfunded case (12 // 128 = 0, pool burns).
        Fees aren't magic — this is what we're fixing, but at 0 fee-
        volume it still underfunds.  Test pins this explicitly so a
        future change that double-counts the accumulator can't hide."""
        supply = SupplyTracker()
        supply.attester_fee_pool_this_block = 0
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        self.assertEqual(len(committee), 128)
        self.assertEqual(result["total_attestor_reward"], 0,
                         f"total_attestor_reward={result['total_attestor_reward']}")
        for i, eid in enumerate(committee):
            self.assertEqual(supply.balances[eid], 0,
                             f"committee[{i}] balance={supply.balances[eid]}")
        # Whole attester_pool (12) burns.
        self.assertEqual(result["burned"], 12)

    def test_accumulator_drained_to_pool_no_leak(self):
        """After mint_block_reward consumes the accumulator it resets to
        0 so the next block starts clean.  Prevents double-spending the
        same fees across two blocks on replay."""
        supply = SupplyTracker()
        supply.attester_fee_pool_this_block = 500
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        self.assertEqual(supply.attester_fee_pool_this_block, 0)

    def test_accumulator_ignored_pre_activation(self):
        """Even if the accumulator is nonzero before the fork fires,
        mint_block_reward's gate keeps the legacy path byte-for-byte
        identical."""
        supply = SupplyTracker()
        supply.attester_fee_pool_this_block = 99
        proposer = b"p" * 32
        committee = _make_committee(12)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)
        self.assertEqual(result["total_attestor_reward"], 12)


class TestActivationBoundary(unittest.TestCase):
    """Fork gate is inclusive at ATTESTER_FEE_FUNDING_HEIGHT."""

    def test_height_one_below_activation_fee_fully_burned(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        supply.balances[sender] = 1000

        supply.pay_fee_with_burn(
            sender, proposer, 150, 100,
            block_height=ATTESTER_FEE_FUNDING_HEIGHT - 1,
        )
        self.assertEqual(supply.total_burned, 100)
        self.assertEqual(supply.attester_fee_pool_this_block, 0)

    def test_height_at_activation_splits(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        supply.balances[sender] = 1000

        supply.pay_fee_with_burn(
            sender, proposer, 150, 100,
            block_height=ATTESTER_FEE_FUNDING_HEIGHT,
        )
        self.assertEqual(supply.total_burned, 50)
        self.assertEqual(supply.attester_fee_pool_this_block, 50)


class TestSupplyInvariantAcrossFork(unittest.TestCase):
    """total_supply == GENESIS_SUPPLY + total_minted - total_burned must
    hold end-to-end across every fee + mint cycle."""

    def _check_invariant(self, supply: SupplyTracker):
        self.assertEqual(
            supply.total_supply,
            GENESIS_SUPPLY + supply.total_minted - supply.total_burned,
        )

    def test_invariant_holds_post_activation(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        committee = _make_committee(128)
        supply.balances[sender] = 100_000
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances.setdefault(eid, 0)

        # Fees that accumulate into the pool.
        for _ in range(10):
            supply.pay_fee_with_burn(
                sender, proposer, 150, 100,
                block_height=POST_ACTIVATION_HEIGHT,
            )
        # Mint consumes the accumulator and drains into attesters.
        supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )
        self._check_invariant(supply)

    def test_invariant_holds_pre_activation(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        proposer = b"p" * 32
        committee = _make_committee(12)
        supply.balances[sender] = 100_000
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances.setdefault(eid, 0)

        for _ in range(10):
            supply.pay_fee_with_burn(
                sender, proposer, 150, 100,
                block_height=PRE_ACTIVATION_HEIGHT,
            )
        supply.mint_block_reward(
            proposer,
            block_height=PRE_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )
        self._check_invariant(supply)


class TestSimApplyLockstep(unittest.TestCase):
    """The per-block accumulator is consensus-visible (it affects
    attester balances, which commit to state_root).  The sim path in
    compute_post_state_root must track a matching sim_attester_fee_pool
    so that the committed state_root matches the apply-path outcome.

    Uses a real Blockchain to exercise both paths.
    """

    def setUp(self):
        # Deferred imports so test module can be collected even if the
        # chain requires fixtures.
        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.transaction import create_transaction
        from tests import register_entity_for_test, pick_selected_proposer

        self._Entity = Entity
        self._Blockchain = Blockchain
        self._ProofOfStake = ProofOfStake
        self._create_transaction = create_transaction
        self._register = register_entity_for_test
        self._pick = pick_selected_proposer

    def _patch_heights(self, at_height: int):
        """Patch both FF heights so they fire at `at_height`.  Heights
        are read via `from messagechain.config import X` at module-load
        time in a few places; patch both the module-level and the
        local bindings to keep them in lockstep."""
        import messagechain.config as _mcfg
        self._orig_aff = _mcfg.ATTESTER_FEE_FUNDING_HEIGHT
        self._orig_ars = _mcfg.ATTESTER_REWARD_SPLIT_HEIGHT
        _mcfg.ATTESTER_FEE_FUNDING_HEIGHT = at_height
        _mcfg.ATTESTER_REWARD_SPLIT_HEIGHT = at_height
        import messagechain.core.blockchain as _bc
        self._orig_bc_ars = getattr(_bc, "ATTESTER_REWARD_SPLIT_HEIGHT", None)
        if hasattr(_bc, "ATTESTER_REWARD_SPLIT_HEIGHT"):
            _bc.ATTESTER_REWARD_SPLIT_HEIGHT = at_height
        import messagechain.economics.inflation as _infl
        self._orig_infl_ars = getattr(_infl, "ATTESTER_REWARD_SPLIT_HEIGHT", None)
        if hasattr(_infl, "ATTESTER_REWARD_SPLIT_HEIGHT"):
            _infl.ATTESTER_REWARD_SPLIT_HEIGHT = at_height

    def _restore_heights(self):
        import messagechain.config as _mcfg
        _mcfg.ATTESTER_FEE_FUNDING_HEIGHT = self._orig_aff
        _mcfg.ATTESTER_REWARD_SPLIT_HEIGHT = self._orig_ars
        import messagechain.core.blockchain as _bc
        if self._orig_bc_ars is not None:
            _bc.ATTESTER_REWARD_SPLIT_HEIGHT = self._orig_bc_ars
        import messagechain.economics.inflation as _infl
        if self._orig_infl_ars is not None:
            _infl.ATTESTER_REWARD_SPLIT_HEIGHT = self._orig_infl_ars

    def test_full_chain_accumulator_resets_between_blocks(self):
        """Build two consecutive blocks with fee-paying txs; assert the
        accumulator returns to 0 at the start of every block apply."""
        self._patch_heights(at_height=1)
        try:
            alice = self._Entity.create(b"alice-fee-acc".ljust(32, b"\x00"))
            bob = self._Entity.create(b"bob-fee-acc".ljust(32, b"\x00"))
            chain = self._Blockchain()
            chain.initialize_genesis(alice)
            self._register(chain, bob)
            chain.supply.balances[alice.entity_id] = 1_000_000
            chain.supply.balances[bob.entity_id] = 1_000_000
            consensus = self._ProofOfStake()

            for _ in range(2):
                proposer = self._pick(chain, [alice, bob])
                # Whoever is proposer — post-activation fees fund their
                # own accumulator path through mint.
                other = bob if proposer.entity_id == alice.entity_id else alice
                tx = self._create_transaction(
                    other, "hi",
                    fee=chain.supply.base_fee + 50,
                    nonce=chain.nonces.get(other.entity_id, 0),
                )
                block = chain.propose_block(consensus, proposer, [tx])
                ok, reason = chain.add_block(block)
                self.assertTrue(ok, reason)
                # After apply the accumulator must have been consumed.
                self.assertEqual(chain.supply.attester_fee_pool_this_block, 0)
        finally:
            self._restore_heights()

    def test_sim_apply_state_root_matches_post_activation(self):
        """propose_block computes the post-state root via the sim path
        and embeds it in the header; add_block then runs the apply
        path and verifies the committed root.  A mismatch rejects the
        block.  This is the strongest sim/apply lockstep check —
        exercises the full pipeline with post-activation fee-funding
        accumulator.  If the sim forgot to accumulate or the apply
        path does something the sim doesn't mirror, the assertion on
        add_block fails here."""
        self._patch_heights(at_height=1)
        try:
            alice = self._Entity.create(b"alice-sim-apply".ljust(32, b"\x00"))
            bob = self._Entity.create(b"bob-sim-apply".ljust(32, b"\x00"))
            chain = self._Blockchain()
            chain.initialize_genesis(alice)
            self._register(chain, bob)
            chain.supply.balances[alice.entity_id] = 1_000_000
            chain.supply.balances[bob.entity_id] = 1_000_000
            consensus = self._ProofOfStake()

            # Post-activation block bundling three message txs.
            proposer = self._pick(chain, [alice, bob])
            other = bob if proposer.entity_id == alice.entity_id else alice
            base = chain.supply.base_fee
            txs = []
            for i in range(3):
                txs.append(self._create_transaction(
                    other, f"msg-{i}",
                    fee=base + 50,
                    nonce=chain.nonces.get(other.entity_id, 0) + i,
                ))

            block = chain.propose_block(consensus, proposer, txs)
            ok, reason = chain.add_block(block)
            # If the sim_attester_fee_pool mirror diverged from the
            # apply accumulator, the post-state state_root would
            # mismatch here and add_block would reject.  Passing
            # means lockstep is intact.
            self.assertTrue(ok, reason)
        finally:
            self._restore_heights()


if __name__ == "__main__":
    unittest.main()
