"""Sim/apply state-root parity property test.

This test exists to prevent the recurring "apply-time state mutation
missing from the sim mirror" defect class.  In the 24h before this
test was written we shipped TWO bugs of exactly this shape:

  * **1.46.0** — `consensus.select_proposer` (producer side) disagreed
    with `Blockchain._selected_proposer_for_slot` (validator side):
    proposer divergence wedged the chain whenever the two paths picked
    different leaves.

  * **1.47.0** — `compute_post_state_root` did not model
    `process_pending_unstakes`, so at the unstake-release block the
    sim root omitted the +amount credit, the producer committed the
    wrong root into the header, and `_append_block`'s post-apply
    check ("Invalid state_root — state commitment mismatch") wedged
    the chain forever at the release height.

The comment at `messagechain/core/blockchain.py:12247` ("Pre-check:
simulate the block's state transition without mutating ... the
simulation and the real apply path run different code and any drift
between them should be caught by the post-apply check") explicitly
names this defect class.  The post-apply check catches it, but only
on the validator that already accepted the wrong-rooted block — and
on every other node that re-derives the same wrong root.  In the
worst case (single-validator chain) the chain wedges forever.

This test pins the invariant directly: for every apply-time mutation
we know about, the sim path's `compute_post_state_root_for_block`
result MUST equal the live state root produced by `_apply_block_state`
on the same starting state.  Each scenario is a separate test method
so a single sim/apply divergence shows exactly which mutation type
lacks a sim mirror.

Scenarios are paired off into:

  * **passing** — apply-time mutation is mirrored in the sim today;
    parity holds.  Failures here are regressions.

  * **expectedFailure** — apply-time mutation is NOT mirrored in the
    sim today; parity is known-broken.  Each `@unittest.expectedFailure`
    carries a TODO with the specific surface that needs a sim mirror.
    A future PR that adds the missing sim path will see the test go
    from xfail to xpass; flip the decorator (or remove it) at that
    point.  Until then, the xfail keeps the suite green while
    documenting the work remaining.

Pattern, per scenario:
  1. Build a small chain (helper: ``_make_chain_with_validators``).
  2. Build / inject the candidate state for the scenario (e.g. queue a
     pending_unstake whose release_block matches the next height).
  3. Build the candidate block via ``propose_block`` — ensures all the
     header-level fields (proposer, randao_mix, state_root) are set
     consistently with the producer-side path.
  4. Snapshot in-memory state via ``_snapshot_memory_state``.
  5. Run the sim: ``compute_post_state_root_for_block(candidate)``.
  6. Restore the snapshot.
  7. Run apply: ``_apply_block_state(candidate)`` then
     ``_touch_state(_block_affected_entities(candidate))`` then
     ``compute_current_state_root()``.
  8. Restore the snapshot again so the chain object is reusable.
  9. Assert sim_root == apply_root.

Step 3 builds the block through ``propose_block`` rather than hand-
constructing a stub block because we want the candidate to look
exactly like what a real producer ships — same proposer signature,
same merkle root, same timestamp logic.  The sim and apply paths in
this test then both run against that real-shaped candidate.
"""

from __future__ import annotations

import time
import unittest

from messagechain import config
from messagechain.config import (
    BLOCK_TIME_TARGET,
    HASH_ALGO,
    MIN_FEE,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.slashing import (
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.core.key_rotation import (
    create_key_rotation,
    derive_rotated_keypair,
)
from messagechain.core.transaction import create_transaction
from messagechain.identity.identity import Entity

from tests import pick_selected_proposer, register_entity_for_test


# ─────────────────────────────────────────────────────────────────────
# Test fixtures
# ─────────────────────────────────────────────────────────────────────


def _make_chain_with_validators(num_validators: int):
    """Build a chain with `num_validators` registered+staked validators.

    Mirrors the helper in ``tests/test_block_production.py`` — kept
    local here so the parity test stays self-contained and we can
    tune funding without coupling.
    """
    entities = [
        Entity.create(f"parity_validator_{i}".encode().ljust(32, b"\x00"))
        for i in range(num_validators)
    ]
    chain = Blockchain()
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)

    consensus = ProofOfStake()
    for e in entities:
        chain.supply.balances[e.entity_id] = (
            chain.supply.balances.get(e.entity_id, 0) + 5_000_000
        )
        chain.supply.stake(e.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[e.entity_id] = VALIDATOR_MIN_STAKE
    return chain, consensus, entities


def _build_a_real_block(chain, consensus, entities):
    """Land one real block past genesis so subsequent candidate blocks
    aren't subject to the special bootstrap path.

    Several of the parity scenarios are sensitive to the height-1
    bootstrap shape (e.g. attester pool isn't credited, validator
    set is still being warmed).  Producing one plain block first
    moves us into the steady-state path that the bug-driving live-
    chain mainnet conditions actually exercise.
    """
    proposer = pick_selected_proposer(chain, entities)
    block = chain.propose_block(consensus, proposer, [])
    ok, reason = chain.add_block(block)
    if not ok:
        raise AssertionError(f"warmup block failed: {reason}")


def _sim_root_for_block(chain, block):
    """Compute the sim's predicted post-state root for `block`.

    Wraps the block-shaped helper that the production validator-side
    pre-check uses (see `Blockchain._append_block`).
    """
    proposer_sig_leaf = (
        block.header.proposer_signature.leaf_index
        if block.header.proposer_signature is not None
        else None
    )
    return chain.compute_post_state_root_for_block(
        block,
        proposer_signature_leaf_index=proposer_sig_leaf,
    )


def _apply_root_for_block(chain, block):
    """Apply `block` to chain state and return the resulting live root.

    Mirrors the apply-side path inside ``_append_block``: apply state
    changes, refresh affected state-tree leaves, then read the live
    state root.
    """
    chain._apply_block_state(block)
    chain._touch_state(chain._block_affected_entities(block))
    return chain.compute_current_state_root()


# ─────────────────────────────────────────────────────────────────────
# Base class: snapshot/restore-aware parity assertion
# ─────────────────────────────────────────────────────────────────────


class _ParityBase(unittest.TestCase):
    """Shared scaffolding for sim/apply parity tests.

    Each scenario:

      1. Calls `self._setup_scenario()` to build the chain and prepare
         any pending state (queued unstake, slash evidence, etc.).
      2. Builds the candidate block.
      3. Calls `self._assert_parity(chain, candidate)` which does the
         snapshot / sim / restore / apply / compare dance.
    """

    def _assert_parity(self, chain: Blockchain, candidate: Block) -> None:
        """Snapshot, run sim, restore, run apply, compare.

        On apply, we also run `_touch_state` to refresh the SMT — the
        apply path in `_append_block` does this before reading
        `compute_current_state_root`, so the parity comparison must
        too.  Without `_touch_state` the SMT is stale and the live
        root reflects pre-block state, masking the divergence we
        care about.
        """
        snapshot = chain._snapshot_memory_state()

        sim_root = _sim_root_for_block(chain, candidate)

        # Restore between sim and apply so the apply path runs from
        # the same starting state the sim measured against.  The sim
        # does NOT mutate state itself, but restoring here also
        # protects against any future drift in that contract.
        chain._restore_memory_snapshot(snapshot)
        chain._rebuild_state_tree()

        apply_root = _apply_root_for_block(chain, candidate)

        # Restore so the chain is reusable for any follow-up assertions.
        chain._restore_memory_snapshot(snapshot)
        chain._rebuild_state_tree()

        self.assertEqual(
            sim_root,
            apply_root,
            "sim/apply state-root divergence — apply-time mutation "
            "in this block is not mirrored in compute_post_state_root.  "
            "This is the same defect class as 1.46.0 (proposer "
            "divergence) and 1.47.0 (unstake-release divergence): "
            "without a sim mirror, the producer commits the wrong "
            "state_root and the chain wedges at this height.",
        )


# ─────────────────────────────────────────────────────────────────────
# Scenario 1: plain block (no special txs).  Baseline — must pass.
# ─────────────────────────────────────────────────────────────────────


class TestPlainBlockParity(_ParityBase):
    def test_empty_block_sim_matches_apply(self):
        """An empty block (no txs, no special slots) is the trivial
        parity case.  If this fails, the parity scaffolding itself
        is broken and every subsequent scenario is meaningless."""
        chain, consensus, entities = _make_chain_with_validators(2)
        _build_a_real_block(chain, consensus, entities)

        proposer = pick_selected_proposer(chain, entities)
        candidate = chain.propose_block(consensus, proposer, [])
        self._assert_parity(chain, candidate)


# ─────────────────────────────────────────────────────────────────────
# Scenario 2: unstake-release block.  Was the 1.47.0 wedge.  Mirrored.
# ─────────────────────────────────────────────────────────────────────


class TestUnstakeReleaseParity(_ParityBase):
    def test_unstake_release_block_sim_matches_apply(self):
        """Mirrors `TestStrictProposerValidation.
        test_compute_post_state_root_mirrors_unstake_release` but as
        a direct sim==apply assertion.  Pre-1.47.0 the sim never
        walked `pending_unstakes` at the release height and this
        diverged."""
        chain, consensus, entities = _make_chain_with_validators(2)
        _build_a_real_block(chain, consensus, entities)

        parent = chain.get_latest_block()
        target_height = parent.header.block_number + 1
        target = entities[1].entity_id
        chain.supply.balances.setdefault(target, 0)
        chain.supply.pending_unstakes.setdefault(target, []).append(
            (25_000_000, target_height),
        )

        proposer = pick_selected_proposer(chain, entities)
        candidate = chain.propose_block(consensus, proposer, [])
        self._assert_parity(chain, candidate)


# ─────────────────────────────────────────────────────────────────────
# Scenario 3: slashing block.  Sim does NOT model slashing today
# (see _append_block:12247).  Expected to fail until a sim mirror
# is added; the slashing path in production short-circuits the sim
# pre-check entirely (`if not block.slash_transactions`).
# ─────────────────────────────────────────────────────────────────────


def _conflicting_headers(proposer, prev_block):
    """Two headers at the same height by the same proposer = double-sign."""
    block_num = prev_block.header.block_number + 1
    hdr_a = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"slash-a"),
        timestamp=time.time(),
        proposer_id=proposer.entity_id,
    )
    hdr_a.proposer_signature = proposer.keypair.sign(
        _hash(hdr_a.signable_data()),
    )
    hdr_b = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"slash-b"),
        timestamp=time.time() + 1,
        proposer_id=proposer.entity_id,
    )
    hdr_b.proposer_signature = proposer.keypair.sign(
        _hash(hdr_b.signable_data()),
    )
    return hdr_a, hdr_b


class TestSlashingBlockParity(_ParityBase):
    def test_slash_block_sim_matches_apply(self):
        """``compute_post_state_root`` mirrors the apply-time slashing
        mutations: fee burn + tip credit (pay_fee_with_burn), stake
        burn (slash_validator), finder reward to the submitter, and
        the ``slashed_validators`` set add on a 100% slash.  Closes
        the long-standing short-circuit in ``_append_block`` that
        skipped the sim pre-check whenever ``block.slash_transactions``
        was non-empty.
        """
        chain, consensus, entities = _make_chain_with_validators(3)
        _build_a_real_block(chain, consensus, entities)

        # Use entities[2] as the offender, entities[1] as the slasher.
        offender, slasher = entities[2], entities[1]
        prev = chain.get_latest_block()
        hdr_a, hdr_b = _conflicting_headers(offender, prev)
        evidence = SlashingEvidence(
            offender_id=offender.entity_id,
            header_a=hdr_a, header_b=hdr_b,
        )
        slash_tx = create_slash_transaction(slasher, evidence, fee=1_500)

        proposer = pick_selected_proposer(chain, entities)
        candidate = chain.propose_block(
            consensus, proposer, transactions=[],
            slash_transactions=[slash_tx],
        )
        self._assert_parity(chain, candidate)


# ─────────────────────────────────────────────────────────────────────
# Scenario 4: inactivity-leak block (inclusion list with entries).
# `_apply_inclusion_list_coverage_leak` runs in apply when
# `block.inclusion_list` is non-empty — sim mirrors this at the
# `# ── Inclusion-list coverage-divergence leak: mirror apply ──`
# block (see compute_post_state_root ~line 6480).  Must pass.
# ─────────────────────────────────────────────────────────────────────


class TestInclusionListCoverageLeakParity(_ParityBase):
    def test_inclusion_list_with_entries_sim_matches_apply(self):
        """Mirror exists in the sim at compute_post_state_root's
        inclusion-list block (~line 6480).  This is the regression
        guard for that mirror — flipping any of:
          * the sim's `_apply_cov_leak` invocation
          * the apply path's `_apply_inclusion_list_coverage_leak`
          * the activation gate / version check
        without keeping the other side in sync trips this test.

        Building a coverage-failing inclusion list end-to-end is
        elaborate; the parity invariant here is just that whatever
        mutation apply does, sim does the same.  We use a minimal
        InclusionList with one entry and an empty quorum_attestation
        — apply's coverage-leak loop drains stake from any active
        attester whose attestation didn't cover the entry, which is
        all of them when quorum_attestation is empty.
        """
        from messagechain.consensus.inclusion_list import (
            InclusionList,
            InclusionListEntry,
        )

        chain, consensus, entities = _make_chain_with_validators(3)
        _build_a_real_block(chain, consensus, entities)

        target_tx_hash = _hash(b"parity-inclusion-target")
        il = InclusionList(
            publish_height=chain.height,
            window_blocks=8,
            entries=[
                InclusionListEntry(
                    tx_hash=target_tx_hash,
                    first_seen_height=chain.height,
                ),
            ],
            quorum_attestation=[],
        )

        proposer = pick_selected_proposer(chain, entities)
        candidate = chain.propose_block(
            consensus, proposer, transactions=[], inclusion_list=il,
        )
        self._assert_parity(chain, candidate)


# ─────────────────────────────────────────────────────────────────────
# Scenario 5: key-rotation tx in authority_txs.  Sim mirrors via
# sim_rotation_counts / sim_public_keys / sim_leaf_watermarks (see
# compute_post_state_root ~line 4523).  Must pass.
# ─────────────────────────────────────────────────────────────────────


class TestKeyRotationParity(_ParityBase):
    def test_key_rotation_block_sim_matches_apply(self):
        """A KeyRotationTransaction in authority_txs mutates
        public_keys, key_rotation_counts, key_rotation_last_height
        and leaf_watermarks on apply.  Sim mirrors via the
        sim_rotation_counts / sim_public_keys / sim_leaf_watermarks
        bookkeeping in compute_post_state_root.
        """
        chain, consensus, entities = _make_chain_with_validators(2)
        _build_a_real_block(chain, consensus, entities)

        # Pick a non-proposer entity (rotating the proposer's own key
        # in the same block they sign breaks the proposer-signature
        # leaf accounting — orthogonal hazard, not under test here).
        proposer = pick_selected_proposer(chain, entities)
        rotator = next(e for e in entities if e.entity_id != proposer.entity_id)

        new_kp = derive_rotated_keypair(rotator, rotation_number=0)
        rot_tx = create_key_rotation(rotator, new_kp, rotation_number=0)

        candidate = chain.propose_block(
            consensus, proposer, transactions=[],
            authority_txs=[rot_tx],
        )
        self._assert_parity(chain, candidate)


# ─────────────────────────────────────────────────────────────────────
# Scenario 6: SetAuthorityKey tx in authority_txs.  Sim mirrors via
# sim_authority_keys.  Must pass.
# ─────────────────────────────────────────────────────────────────────


class TestSetAuthorityKeyParity(_ParityBase):
    def test_set_authority_key_block_sim_matches_apply(self):
        """A SetAuthorityKeyTransaction in authority_txs mutates
        authority_keys on apply (and charges a fee).  Sim mirrors
        via sim_authority_keys."""
        chain, consensus, entities = _make_chain_with_validators(2)
        _build_a_real_block(chain, consensus, entities)

        proposer = pick_selected_proposer(chain, entities)
        promoter = next(
            e for e in entities if e.entity_id != proposer.entity_id
        )
        cold = Entity.create(b"parity-cold-key".ljust(32, b"\x00"))

        nonce = chain.nonces.get(promoter.entity_id, 0)
        set_tx = create_set_authority_key_transaction(
            promoter, new_authority_key=cold.public_key,
            nonce=nonce, fee=500,
        )

        candidate = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[set_tx],
        )
        self._assert_parity(chain, candidate)


# ─────────────────────────────────────────────────────────────────────
# Scenario 7: attester-fee-funding-active block (post
# ATTESTER_FEE_FUNDING_HEIGHT).  Sim mirrors via the
# `_attester_fee_pool_active` / sim_attester_fee_pool accumulator
# (see compute_post_state_root ~line 4544).  Must pass.
# ─────────────────────────────────────────────────────────────────────


class TestAttesterFeeFundingParity(_ParityBase):
    def test_attester_fee_funded_block_sim_matches_apply(self):
        """At/after ATTESTER_FEE_FUNDING_HEIGHT, every fee-bearing tx
        diverts a base-fee share into the per-block attester pool,
        which is then mixed into the proposer/attester reward split
        at mint time.  Sim mirrors this via sim_attester_fee_pool.

        We synthesize the activation by patching the height down to
        the chain's current height — the apply path reads
        `block.header.block_number` for the gate, and the sim reads
        `block_height`, so dropping the activation height makes both
        sides take the post-activation branch on the same block.
        """
        chain, consensus, entities = _make_chain_with_validators(2)
        _build_a_real_block(chain, consensus, entities)

        # Funded sender (entities[1]) sends a message paying a fee
        # large enough to actually move the attester pool.  Use the
        # proposer as recipient so sender/proposer are distinct.
        proposer = pick_selected_proposer(chain, entities)
        sender = next(
            e for e in entities if e.entity_id != proposer.entity_id
        )

        nonce = chain.nonces.get(sender.entity_id, 0)
        msg_tx = create_transaction(
            sender, "parity-fee-funding", MIN_FEE + 1_000, nonce=nonce,
        )

        # Force the activation gate to fire on this block by patching
        # the height down.  Restore in tearDown via try/finally.
        original_height = config.ATTESTER_FEE_FUNDING_HEIGHT
        try:
            # Activate at or before the candidate's block_number.
            config.ATTESTER_FEE_FUNDING_HEIGHT = 0
            candidate = chain.propose_block(
                consensus, proposer, transactions=[msg_tx],
            )
            self._assert_parity(chain, candidate)
        finally:
            config.ATTESTER_FEE_FUNDING_HEIGHT = original_height


if __name__ == "__main__":
    unittest.main()
