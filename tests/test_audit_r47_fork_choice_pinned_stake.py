"""Audit r47 #1 -- fork-choice cumulative weight stored at apply time
must be sourced from the same dict as the per-block pinned stake
snapshot, not from live ``self.supply.staked``.

The canonical apply path in ``Blockchain.add_block`` does:

    block_weight = compute_block_stake_weight(block, self.supply.staked)
    ...                                            # tip stored
    self._process_attestations(block, self.supply.staked)
    self._record_stake_snapshot(block.header.block_number)

Walk-back cumulative-weight computations
(``_compute_cumulative_weight`` / ``_compute_full_cumulative_weight``)
read ``self._stake_snapshots`` -- the pinned, per-block-keyed
snapshot.  As long as nothing between the weight-compute call and
the pin call mutates ``supply.staked``, the stored value and the
walk-back value agree.

Today ``_process_attestations`` happens not to mutate
``supply.staked``, so the two values coincide on the live mainnet.
But the SHAPE of the bookkeeping -- "compute against live, pin
later" -- is the same defect-shape that audit r46 #1 just closed
for the attestation finality denominator.  Any future refactor that
introduces a mutation between line 15097 and line 15111 (slashing
on attestation processing, witness-tier post-finality stake
adjustments, etc.) would silently produce two values that disagree
and -- under the lex-smaller-hash tie-break -- a fork that should
have lost wins a spurious reorg.

Abstraction fix: ``Blockchain._pinned_stake_at(block_number)`` is the
single chokepoint every cumulative-weight call site routes through.
``add_block`` pins the snapshot BEFORE computing weight so weight is
sourced from the just-pinned dict; ``_compute_cumulative_weight``
and ``_compute_full_cumulative_weight`` replace their inline pinned-
with-live-fallback patterns with the same helper.
"""

from __future__ import annotations

import hashlib
import inspect
import time
import unittest

from messagechain.config import HASH_ALGO
from messagechain.consensus.fork_choice import compute_block_stake_weight
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _entity(name: str) -> Entity:
    return Entity.create(f"{name}-privkey".encode().ljust(32, b"\x00"))


def _bootstrap_chain(proposer_stake: int = 100):
    alice = _entity("r47-alice")
    bob = _entity("r47-bob")
    chain = Blockchain()
    chain.initialize_genesis(alice)
    register_entity_for_test(chain, bob)
    chain.supply.balances[alice.entity_id] = 1_000_000
    chain.supply.balances[bob.entity_id] = 1_000_000
    chain.supply.staked[alice.entity_id] = proposer_stake
    pos = ProofOfStake()
    pos.register_validator(alice.entity_id, stake_amount=proposer_stake)
    return chain, alice, bob, pos


class TestPinnedStakeHelperContract(unittest.TestCase):
    """Unit tests on the new ``Blockchain._pinned_stake_at`` helper."""

    def test_helper_exists(self):
        chain = Blockchain()
        self.assertTrue(
            hasattr(chain, "_pinned_stake_at"),
            "Blockchain must expose _pinned_stake_at(block_number) as the "
            "single chokepoint for the stake-dict read in every cumulative-"
            "weight call site.  Without it, future call sites can silently "
            "drift back to live supply.staked.",
        )

    def test_helper_returns_pinned_when_available(self):
        chain, alice, bob, pos = _bootstrap_chain(proposer_stake=100)
        tx0 = create_transaction(bob, "m0", fee=1500, nonce=0)
        b1 = chain.propose_block(pos, alice, [tx0])
        self.assertTrue(chain.add_block(b1)[0])

        # Force a divergence between pinned and live AFTER block 1 has
        # been added.  The helper must return the PINNED value.
        chain.supply.staked[alice.entity_id] = 999

        pinned = chain._pinned_stake_at(1)
        self.assertEqual(
            pinned.get(alice.entity_id), 100,
            "Helper must return the pinned snapshot value (100), not "
            "the post-add live mutation (999).",
        )

    def test_helper_falls_back_to_live_when_pin_missing(self):
        """Snapshot-pruned era (pre-snapshot-mirror cold restart, or
        bootstrap edge): no pin exists at the requested height.  The
        helper falls back to live ``supply.staked`` so existing walk-
        back behavior on long historical chains continues to work."""
        chain, alice, _bob, _pos = _bootstrap_chain(proposer_stake=100)

        # No block applied at height 42 -> no pin recorded there.
        self.assertNotIn(42, chain._stake_snapshots)
        fallback = chain._pinned_stake_at(42)
        self.assertEqual(
            fallback.get(alice.entity_id),
            chain.supply.staked.get(alice.entity_id),
            "Missing-pin fallback must return live supply.staked so the "
            "snapshot-pruned-era walk-back semantics are preserved.",
        )


class TestAddBlockPinSnapshotBeforeWeight(unittest.TestCase):
    """The canonical ``add_block`` path must pin the per-block snapshot
    BEFORE computing fork-choice weight, so the stored value cannot
    diverge from the snapshot even if a future refactor introduces a
    mutation between the two operations."""

    def test_append_block_source_does_not_read_live_supply_staked_for_weight(self):
        """Structural: the canonical-extension path
        ``Blockchain._append_block`` must not call
        ``compute_block_stake_weight(block, self.supply.staked)``
        directly -- that pattern reads live state and is the audit
        r47 #1 defect.  It must route through the new
        ``_pinned_stake_at`` helper instead."""
        src = inspect.getsource(Blockchain._append_block)
        self.assertNotIn(
            "compute_block_stake_weight(block, self.supply.staked)", src,
            "_append_block must not read live self.supply.staked when "
            "computing fork-choice weight -- the value must be sourced "
            "from the just-pinned _stake_snapshots dict via "
            "_pinned_stake_at(block.header.block_number).",
        )
        self.assertIn(
            "_pinned_stake_at", src,
            "_append_block must route the weight read through the "
            "_pinned_stake_at helper.",
        )

    def test_stored_weight_robust_to_mutation_between_weight_and_pin(self):
        """Behavioral: simulate a future refactor where
        ``_process_attestations`` (called between weight-compute and
        snapshot-pin on the live code path) mutates ``supply.staked``.
        With the fix, the snapshot is pinned BEFORE the weight compute
        so the stored cumulative weight matches the snapshot.  Without
        the fix, walk-back recompute disagrees with the stored value
        and the fork-choice tie-break can pick the wrong tip."""
        chain, alice, bob, pos = _bootstrap_chain(proposer_stake=100)

        # Monkey-patch _process_attestations to inject a hostile
        # supply.staked mutation between the weight-compute and the
        # snapshot-pin in add_block.  This stands in for any future
        # code (slashing on attestation, witness-tier accounting,
        # etc.) that touches the stake dict in that window.
        original = chain._process_attestations

        def hostile_patched(block, stakes):
            original(block, stakes)
            # Drift: pretend the post-attestation-processing code
            # decided the proposer should have a different stake.
            chain.supply.staked[alice.entity_id] = 777

        chain._process_attestations = hostile_patched  # type: ignore[assignment]

        tx0 = create_transaction(bob, "m0", fee=1500, nonce=0)
        b1 = chain.propose_block(pos, alice, [tx0])
        ok, reason = chain.add_block(b1)
        self.assertTrue(ok, reason)

        stored = chain.fork_choice.tips[b1.block_hash][1]
        recomputed = chain._compute_cumulative_weight(b1)
        self.assertEqual(
            stored, recomputed,
            f"Cumulative weight stored in fork_choice.tips at apply "
            f"time must equal walk-back recomputation, regardless of "
            f"any post-weight mutation of supply.staked "
            f"(stored={stored}, recomputed={recomputed}).  The fix is "
            f"to pin the snapshot BEFORE computing weight, so both "
            f"reads use the same dict.",
        )


class TestWalkBackRoutesThroughHelper(unittest.TestCase):
    """Structural: ``_compute_cumulative_weight`` and
    ``_compute_full_cumulative_weight`` must route the per-block stake
    read through ``_pinned_stake_at`` rather than re-implementing the
    pinned-with-live-fallback pattern inline.  Parallel implementations
    of the same logic are how the live-vs-pinned distinction recurs
    across audit rounds (r46 attestation path, this round fork-weight
    path)."""

    def test_compute_cumulative_weight_uses_helper(self):
        src = inspect.getsource(Blockchain._compute_cumulative_weight)
        self.assertIn(
            "_pinned_stake_at", src,
            "_compute_cumulative_weight must route the per-block stake "
            "read through Blockchain._pinned_stake_at -- the single "
            "chokepoint for pinned-vs-live resolution.",
        )

    def test_compute_full_cumulative_weight_uses_helper(self):
        src = inspect.getsource(Blockchain._compute_full_cumulative_weight)
        self.assertIn(
            "_pinned_stake_at", src,
            "_compute_full_cumulative_weight must route the per-block "
            "stake read through Blockchain._pinned_stake_at.",
        )


if __name__ == "__main__":
    unittest.main()
