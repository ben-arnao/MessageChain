"""Matured censorship slash MUST refresh the offender's state_tree leaf.

The canonical contract (see ``_touch_state`` docstring): any code path
that mutates per-entity state inside the leaf commitment (balance,
nonce, stake, ...) must end in a ``_touch_state`` call so the
SparseMerkleTree reflects the live dicts at block-end.  The block-level
sweep ``_block_affected_entities`` collects per-tx ``affected_entities()``
contributions to feed that call — but ``CensorshipEvidenceTx.
affected_entities()`` returns only ``{submitter_id}``, with the comment
"the offender will be touched at maturity by a non-evidence sweep there".
No such sweep exists.  ``_apply_censorship_slash`` mutates
``supply.staked[offender_id]`` (and the pending-unstake queue, off-leaf)
without ever calling ``_touch_state({offender_id})``.

The bug is masked today because ``compute_current_state_root`` calls
``_rebuild_state_tree`` which is a full walk of live dicts and silently
patches the leaf back into sync.  But the canonical incremental
contract — every mutation either calls ``_touch_state`` directly or
ships an ``affected_entities()`` registration that the block sweep
reads — is violated.  A future optimization that trusts the tree
without the rebuild (the docstring on ``compute_current_state_root``
explicitly flags this as a follow-up) would silently fork the chain on
the first matured censorship where ``offender_id != proposer_id``.

Two complementary tests pin the fix:

  * ``test_apply_censorship_slash_refreshes_offender_leaf`` — the direct
    contract test.  After the apply, ``state_tree.get(offender)``
    reflects the new ``supply.staked[offender]`` without any
    ``compute_current_state_root`` call interleaved.

  * ``test_burn_slash_proportional_structural_guard`` — the structural
    guard.  ``SupplyTracker.burn_slash_proportional`` accepts an
    optional ``blockchain`` arg and refreshes the offender leaf itself
    when threaded through.  Existing call sites whose
    ``affected_entities()`` already covers the offender (IL violation,
    bogus rejection, non-response) layer the guard as a no-op double-
    refresh; the new censorship call site relies on the guard for the
    first refresh.  Future call sites cannot reintroduce the same gap
    without the guard catching it.

The brief's CLAUDE.md "validator collusion" anchor is upstream: the
chain-stall surface a colluding-then-detected validator could trigger
by getting censorship evidence to mature against an offender other than
the proposer is exactly the kind of liveness regression a slash-pathway
fix must close in the same patch.  Pre-fix the slash applies but the
block self-rejects on state_root mismatch under any incremental-trust
implementation; post-fix the slash applies AND every peer (including a
strict-incremental peer) reaches the same root.
"""

from __future__ import annotations

import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import (
    CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT,
    HASH_ALGO,
    HONESTY_CURVE_INSURANCE_HEIGHT,
)
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _force_chain_height(chain, h):
    return patch.object(
        Blockchain, "height", new=property(lambda _: h),
    )


def _make_chain():
    """Two-validator chain: submitter (proposer) + accused offender.

    The seeding pattern mirrors ``test_censorship_slash_pending_unstake``:
    register both entities, seed balances and staked amount.  We then
    sync the state_tree once via ``_touch_state`` so the leaves reflect
    the seeded stake — without this priming, the leaves start with
    stake=0 and any post-apply diff is dwarfed by the seed-vs-zero gap.
    """
    submitter = Entity.create(b"slash-touch-submitter".ljust(32, b"\x00"))
    accused = Entity.create(b"slash-touch-accused".ljust(32, b"\x00"))
    chain = Blockchain()
    chain.initialize_genesis(submitter)
    register_entity_for_test(chain, accused)
    for v in (submitter, accused):
        chain.supply.balances[v.entity_id] = 10_000_000
        chain.supply.staked[v.entity_id] = 1_000_000
    # Sync the tree to the seeded state — the test starts from a
    # consistent baseline so post-apply divergence is exactly the bug.
    chain._touch_state({submitter.entity_id, accused.entity_id})
    return chain, submitter, accused


def _matured(offender_id, staked_at_admission, tag=b""):
    return SimpleNamespace(
        offender_id=offender_id,
        staked_at_admission=staked_at_admission,
        evidence_hash=_h(b"matured-touch-" + tag + offender_id),
    )


class TestCensorshipSlashTouchesOffenderLeaf(unittest.TestCase):
    """Direct path: ``_apply_censorship_slash`` MUST refresh the
    offender's state_tree leaf so the incremental contract holds."""

    def test_apply_censorship_slash_refreshes_offender_leaf(self):
        chain, submitter, accused = _make_chain()
        # Park HALF of stake in pending so the slash genuinely changes
        # ``staked`` (Tier 31+ proportional drain hits both buckets).
        chain.supply.staked[accused.entity_id] = 500_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (500_000, 99_999),
        ]
        # Re-touch so the leaf reflects the post-seed staked value.
        chain._touch_state({accused.entity_id})
        leaf_before = chain.state_tree.get(accused.entity_id)
        self.assertIsNotNone(leaf_before)
        # Sanity: leaf's stake field matches live dict.
        self.assertEqual(
            leaf_before[2], chain.supply.staked[accused.entity_id],
        )

        admission_basis = 500_000 + 500_000  # = 1_000_000
        with _force_chain_height(chain, CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT):
            chain._apply_censorship_slash(
                _matured(accused.entity_id, admission_basis, b"refresh"),
            )

        live_staked_after = chain.supply.staked.get(accused.entity_id, 0)
        leaf_after = chain.state_tree.get(accused.entity_id)
        self.assertIsNotNone(leaf_after)

        # The slash must have reduced staked.
        self.assertLess(
            live_staked_after, leaf_before[2],
            "Sanity: the censorship slash must reduce live staked.",
        )

        # The contract: the state_tree leaf MUST reflect the new
        # staked value.  Pre-fix the leaf is stale (matches
        # leaf_before[2], the pre-slash value); post-fix it matches
        # live_staked_after.
        self.assertEqual(
            leaf_after[2], live_staked_after,
            "state_tree leaf MUST be refreshed after _apply_censorship_slash "
            "— the canonical _touch_state contract requires every leaf "
            "mutation to be mirrored into the tree before block-end.",
        )

    def test_apply_censorship_slash_invokes_touch_state_on_offender(self):
        """Direct hook test: the apply path actually calls
        ``_touch_state({offender_id})`` (or equivalent) at least once.

        Pinned independently of the leaf-equality test above so a
        future refactor that replaces ``_touch_state`` with a different
        per-entity refresh primitive still has to refresh the offender.
        """
        chain, submitter, accused = _make_chain()
        chain.supply.staked[accused.entity_id] = 500_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (500_000, 99_999),
        ]
        chain._touch_state({accused.entity_id})

        observed_calls: list[set[bytes]] = []
        original_touch = chain._touch_state

        def _spy(entity_ids):
            observed_calls.append(set(entity_ids))
            return original_touch(entity_ids)

        chain._touch_state = _spy
        try:
            with _force_chain_height(
                chain, CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT,
            ):
                chain._apply_censorship_slash(
                    _matured(accused.entity_id, 1_000_000, b"spy"),
                )
        finally:
            chain._touch_state = original_touch

        offender_seen = any(
            accused.entity_id in call for call in observed_calls
        )
        self.assertTrue(
            offender_seen,
            "_apply_censorship_slash MUST call _touch_state with the "
            "offender_id at least once after burning stake — otherwise "
            f"observed calls were {observed_calls!r}",
        )


class TestBurnSlashProportionalStructuralGuard(unittest.TestCase):
    """Structural guard: ``burn_slash_proportional`` accepts an
    optional ``blockchain`` arg and refreshes the offender leaf when
    threaded through.  Future call sites that forget to refresh the
    offender separately are protected by this in-band sweep."""

    def test_burn_with_blockchain_refreshes_offender_leaf(self):
        """When ``blockchain`` is passed, the helper itself refreshes
        the offender's state_tree leaf — even if the caller forgets.
        Validates that a future call site cannot silently regress to
        the censorship-evidence bug shape."""
        chain, submitter, accused = _make_chain()
        chain.supply.staked[accused.entity_id] = 600_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (400_000, 99_999),
        ]
        chain._touch_state({accused.entity_id})
        leaf_before = chain.state_tree.get(accused.entity_id)
        # Pre-call sanity: the leaf reflects pre-burn staked.
        self.assertEqual(leaf_before[2], 600_000)

        # Call burn_slash_proportional WITHOUT any subsequent
        # _touch_state on the offender — the guard must refresh the
        # leaf itself when ``blockchain`` is threaded through.
        burned = chain.supply.burn_slash_proportional(
            accused.entity_id, slash_pct=20,
            blockchain=chain,
        )
        self.assertGreater(burned, 0)

        live_staked = chain.supply.staked.get(accused.entity_id, 0)
        leaf_after = chain.state_tree.get(accused.entity_id)
        self.assertEqual(
            leaf_after[2], live_staked,
            "burn_slash_proportional(blockchain=chain) MUST refresh "
            "the offender's state_tree leaf — the structural guard "
            "for forgotten _touch_state calls.",
        )

    def test_burn_without_blockchain_is_backward_compatible(self):
        """Existing callers that don't yet pass ``blockchain`` see no
        behavioral change — the helper still burns and returns the
        slashed amount, just without the in-band leaf refresh.

        Pinned because the audit-mandated guard MUST be additive: an
        unconverted call site (test stub, future helper) must keep
        compiling and burning correctly.  The guard's value is purely
        in surfacing the missing refresh when ``blockchain`` IS passed
        and ``_touch_state`` is wired up.
        """
        chain, submitter, accused = _make_chain()
        chain.supply.staked[accused.entity_id] = 600_000
        # No blockchain arg — legacy call shape.
        burned = chain.supply.burn_slash_proportional(
            accused.entity_id, slash_pct=10,
        )
        self.assertGreater(burned, 0)
        # supply.staked moved.
        self.assertEqual(
            chain.supply.staked[accused.entity_id], 600_000 - burned,
        )


class TestExistingCallSitesRegression(unittest.TestCase):
    """Regression coverage: the IL-violation, bogus-rejection, and
    non-response apply paths already cover the offender via their
    ``affected_entities()`` returns, so the structural guard is a
    no-op double-refresh on those.  Pinned here so a future refactor
    that flips the guard's contract (assert-style instead of refresh-
    style) doesn't accidentally break the existing-callers no-op
    promise.
    """

    def test_burn_with_blockchain_is_idempotent_when_leaf_already_fresh(self):
        chain, submitter, accused = _make_chain()
        chain.supply.staked[accused.entity_id] = 800_000
        chain._touch_state({accused.entity_id})
        # Caller refreshes the leaf themselves first, mirroring the
        # IL-violation path's affected_entities-driven sweep.
        chain._touch_state({accused.entity_id})
        burned = chain.supply.burn_slash_proportional(
            accused.entity_id, slash_pct=15,
            blockchain=chain,
        )
        # Second refresh inside the helper is a no-op — the leaf
        # already matches the post-burn live staked value.
        live_staked = chain.supply.staked.get(accused.entity_id, 0)
        leaf_after = chain.state_tree.get(accused.entity_id)
        self.assertEqual(leaf_after[2], live_staked)
        self.assertEqual(burned, 800_000 * 15 // 100)


if __name__ == "__main__":
    unittest.main()
