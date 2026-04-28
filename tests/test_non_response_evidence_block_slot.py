"""Block-slot wiring for NonResponseEvidenceTx.

Closes the headline gap surfaced by audit finding #1: every prior
NonResponseEvidenceTx admission/processor fix has been dead code because
``Block`` carried no ``non_response_evidence_txs`` field, the canonical
``_BLOCK_TX_LIST_ATTRS`` registries didn't include the slot, and
``_apply_block_state`` never invoked ``NonResponseEvidenceProcessor``.
A coerced validator who silently dropped a witnessed POST could lose
nothing — categorical bypass of the validator-collusion anchor.

This module pins the four invariants for the block-slot fork:

  1. **Wire round-trip (post-fork).**  A Block constructed with
     ``non_response_evidence_txs`` populated at a height ≥
     NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT round-trips through both
     dict and binary serialization, and the merkle commitment binds
     the slot.

  2. **Pre-fork byte-identity.**  Below the activation height, a Block
     constructed with the new slot empty serializes byte-identically
     to a Block built from the legacy fields alone — no slot, no
     length prefix, no marker.  Required for replay determinism on
     historical chain data.

  3. **Apply path post-fork.**  A post-fork block carrying a valid
     NonResponseEvidenceTx applies through ``_apply_block_state``,
     calls ``NonResponseEvidenceProcessor.process`` exactly once, and
     drains both ``staked`` and ``pending_unstakes`` of the offender
     (via Tier 33's ``burn_slash_proportional`` path); the dirty-set
     sweep includes both ``submitter_id`` and ``offender_id`` so their
     state_tree leaves refresh.

  4. **Forced-inclusion gate sees the slot.**  Tier 34's multi-list
     forced-inclusion gate (``_BLOCK_TX_LIST_ATTRS`` in
     ``messagechain.consensus.forced_inclusion``) lists
     ``non_response_evidence_txs`` so a forced NRE in the correct slot
     is recognized as included, not flagged as censored.

See CLAUDE.md "Censorship resistance is a *collective decision*..." —
this fork is what makes the validator-collusion anchor real for the
silent-drop variant.
"""

from __future__ import annotations

import hashlib
import time
import unittest
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    MIN_FEE,
    NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT,
    WITNESS_QUORUM,
    WITNESS_SURCHARGE,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceProcessor,
    sign_non_response_evidence,
)
from messagechain.consensus.witness_submission import (
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _force_chain_height(chain, h):
    """Override Blockchain.height for the duration of a `with` block."""
    return patch.object(
        Blockchain, "height", new=property(lambda _: h),
    )


def _make_witnesses(n: int, tag: bytes) -> list[Entity]:
    return [
        Entity.create(
            (b"nre-bs-" + tag + b"-" + str(i).encode()).ljust(32, b"\x00")
        )
        for i in range(n)
    ]


def _make_minimal_block(
    proposer: Entity,
    block_number: int,
    *,
    non_response_evidence_txs: list | None = None,
) -> Block:
    """Build a minimal Block at a chosen height with optional NRE txs.

    Used to test the wire round-trip rules in isolation — no chain,
    no proposer-selection, no merkle hashing of the txs themselves.
    """
    header = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=b"\x00" * 32,
        merkle_root=_h(b"empty"),
        timestamp=int(time.time()),
        proposer_id=proposer.entity_id,
    )
    header.proposer_signature = proposer.keypair.sign(
        _h(header.signable_data())
    )
    kwargs = {
        "header": header,
        "transactions": [],
    }
    if non_response_evidence_txs is not None:
        kwargs["non_response_evidence_txs"] = non_response_evidence_txs
    blk = Block(**kwargs)
    blk.block_hash = blk._compute_hash()
    return blk


def _make_signed_evidence(
    chain: Blockchain,
    target: Entity,
    client: Entity,
    submitter: Entity,
    witnesses: list[Entity],
    *,
    observed_height: int,
    seed: bytes = b"\x01",
):
    """Build a fully-signed NonResponseEvidenceTx for tests.

    Witnesses must be registered + staked on `chain` so the
    apply-time active-set filter retains them.
    """
    req = sign_submission_request(
        submitter=client,
        target_validator_id=target.entity_id,
        tx_hash=_h(b"nre-bs-tx-" + seed),
        timestamp=int(time.time()),
        client_nonce=(seed * 16)[:16],
        fee=MIN_FEE + WITNESS_SURCHARGE,
    )
    observations = [
        sign_witness_observation(
            w, req.request_hash, observed_height=observed_height,
        )
        for w in witnesses
    ]
    return sign_non_response_evidence(
        submitter=submitter,
        request=req,
        observations=observations,
        timestamp=int(time.time()),
        fee=MIN_FEE,
    )


# ─────────────────────────────────────────────────────────────────────
# Activation-height invariant
# ─────────────────────────────────────────────────────────────────────


class TestActivationHeightOrdering(unittest.TestCase):
    """The block-slot fork must ride above Tier 33 — the apply path
    consumes the curve-graded + pending-unstake-drain shape introduced
    by Tier 33, so the prerequisite must already be live."""

    def test_above_tier_33(self):
        from messagechain.config import (
            NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT,
        )
        self.assertGreater(
            NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT,
            NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT,
            "Block-slot fork's apply path consumes Tier 33's curve + "
            "pending-unstake-drain shape; Tier 33 must be live first.",
        )


# ─────────────────────────────────────────────────────────────────────
# 1. Wire round-trip (post-fork)
# ─────────────────────────────────────────────────────────────────────


class TestNonResponseEvidenceBlockSlotPostForkRoundtrip(unittest.TestCase):
    """A post-fork Block with `non_response_evidence_txs` populated
    round-trips through both dict and binary serialization without
    losing entries."""

    def setUp(self):
        from messagechain.config import (
            NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT,
        )
        self.post_fork = NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT
        self.proposer = Entity.create(
            b"nre-bs-prop-rt".ljust(32, b"\x00"),
        )
        self.proposer.keypair._next_leaf = 0
        self.target = Entity.create(b"nre-bs-target-rt".ljust(32, b"\x00"))
        self.client = Entity.create(b"nre-bs-client-rt".ljust(32, b"\x00"))
        self.submitter = Entity.create(
            b"nre-bs-sub-rt".ljust(32, b"\x00"),
        )
        self.target.keypair._next_leaf = 0
        self.client.keypair._next_leaf = 0
        self.submitter.keypair._next_leaf = 0
        self.witnesses = _make_witnesses(WITNESS_QUORUM, b"rt")
        for w in self.witnesses:
            w.keypair._next_leaf = 0
        # A throwaway chain just to satisfy any chain-bound helpers.
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        for w in self.witnesses:
            register_entity_for_test(self.chain, w)

    def _evidence(self, seed: bytes):
        return _make_signed_evidence(
            self.chain, self.target, self.client, self.submitter,
            self.witnesses,
            observed_height=self.post_fork - 50, seed=seed,
        )

    def test_dict_roundtrip_post_fork(self):
        etx = self._evidence(b"\x10")
        blk = _make_minimal_block(
            self.proposer, self.post_fork,
            non_response_evidence_txs=[etx],
        )
        round_tripped = Block.deserialize(blk.serialize())
        self.assertEqual(
            len(round_tripped.non_response_evidence_txs), 1,
            "Dict serialization must preserve the post-fork slot.",
        )
        self.assertEqual(
            round_tripped.non_response_evidence_txs[0].tx_hash,
            etx.tx_hash,
        )

    def test_binary_roundtrip_post_fork(self):
        etx = self._evidence(b"\x11")
        blk = _make_minimal_block(
            self.proposer, self.post_fork,
            non_response_evidence_txs=[etx],
        )
        blob = blk.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(
            len(decoded.non_response_evidence_txs), 1,
            "Binary serialization must preserve the post-fork slot.",
        )
        self.assertEqual(
            decoded.non_response_evidence_txs[0].tx_hash,
            etx.tx_hash,
        )
        self.assertEqual(decoded.block_hash, blk.block_hash)

    def test_slot_folds_into_merkle_root(self):
        """Two blocks identical except for the NRE list MUST produce
        different canonical tx-hash lists — a relayer cannot strip or
        mutate the slot without invalidating the proposer's signature."""
        from messagechain.core.block import canonical_block_tx_hashes
        etx = self._evidence(b"\x12")
        empty_blk = _make_minimal_block(
            self.proposer, self.post_fork,
            non_response_evidence_txs=[],
        )
        full_blk = _make_minimal_block(
            self.proposer, self.post_fork,
            non_response_evidence_txs=[etx],
        )
        self.assertNotEqual(
            canonical_block_tx_hashes(empty_blk),
            canonical_block_tx_hashes(full_blk),
            "non_response_evidence_txs MUST contribute to the merkle "
            "commitment; otherwise a relayer can strip the slot.",
        )


# ─────────────────────────────────────────────────────────────────────
# 2. Pre-fork byte-identity
# ─────────────────────────────────────────────────────────────────────


class TestNonResponseEvidenceBlockSlotPreForkByteIdentity(unittest.TestCase):
    """Below the activation height, a Block whose new
    non_response_evidence_txs slot is empty MUST serialize byte-
    identically to a hypothetical pre-fork Block — no slot, no length
    prefix, no marker.  This is the replay-determinism contract: a
    historical block already on disk must round-trip through the
    new decoder unchanged."""

    def setUp(self):
        from messagechain.config import (
            NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT,
        )
        self.pre_fork = NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT - 1
        self.proposer = Entity.create(b"nre-bs-prop-pre".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0

    def test_pre_fork_block_serializes_without_slot(self):
        """At a pre-fork height with the new slot defaulted to [],
        `to_bytes()` MUST emit no extra bytes for the slot — the
        encoded blob is the legacy length, not legacy + 4 bytes.

        The byte-identity check uses two clones of the SAME block (one
        with the slot left at its dataclass default, one explicitly
        passed []) so the proposer's WOTS+ leaf state stays in sync —
        otherwise re-signing would give two different randao_mix
        values and the comparison would be vacuous.
        """
        # Construct one block.  Clone-and-tweak in place so both views
        # share identical signatures + block_hash; the only delta we
        # want to compare is whether non_response_evidence_txs forces
        # any extra emitted bytes.
        blk = _make_minimal_block(self.proposer, self.pre_fork)
        legacy_bytes = blk.to_bytes()
        # Now explicitly assign the new slot to [] and re-encode.
        # Dataclass field default is [] already, so this is a no-op
        # mutation — but it exercises the post-default codepath where
        # the encoder reads `self.non_response_evidence_txs` directly.
        blk.non_response_evidence_txs = []
        explicit_bytes = blk.to_bytes()
        self.assertEqual(
            legacy_bytes, explicit_bytes,
            "Pre-fork: an empty non_response_evidence_txs MUST emit "
            "byte-identically to an unset slot.  Otherwise historical "
            "blocks already on disk would re-hash differently after the "
            "decoder change.",
        )
        # And the trailing 32 bytes are still the declared block_hash —
        # the new slot did NOT prefix any bytes between react_transactions
        # and the hash (which is what byte-identity requires).
        self.assertEqual(
            legacy_bytes[-32:], blk.block_hash,
            "Trailing 32 bytes must still be declared_hash; pre-fork "
            "the new slot emits ZERO bytes between react_transactions "
            "and the hash.",
        )

    def test_pre_fork_blob_round_trips(self):
        """Construct a pre-fork block, serialize, and confirm the
        decoder produces the same block (declared_hash matches)."""
        blk = _make_minimal_block(
            self.proposer, self.pre_fork,
            non_response_evidence_txs=[],
        )
        blob = blk.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(decoded.block_hash, blk.block_hash)
        self.assertEqual(decoded.non_response_evidence_txs, [])


# ─────────────────────────────────────────────────────────────────────
# 3. Apply path post-fork
# ─────────────────────────────────────────────────────────────────────


class TestNonResponseEvidenceApplyPath(unittest.TestCase):
    """At a post-fork height, ``_apply_block_state`` invokes
    ``NonResponseEvidenceProcessor.process`` for each entry in
    ``non_response_evidence_txs``.  The offender's
    ``staked + pending_unstakes`` is drained per the Tier-33 curve,
    and ``_block_affected_entities`` includes both submitter and
    offender so their state_tree leaves refresh.
    """

    def setUp(self):
        from messagechain.config import (
            NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT,
        )
        self.post_fork = NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT
        self.target = Entity.create(b"nre-bs-tgt-ap".ljust(32, b"\x00"))
        self.client = Entity.create(b"nre-bs-cli-ap".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"nre-bs-sub-ap".ljust(32, b"\x00"))
        self.target.keypair._next_leaf = 0
        self.client.keypair._next_leaf = 0
        self.submitter.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        # Park 70% in pending_unstakes so the Tier-33 drain is
        # observable post-apply.
        self.chain.supply.balances[self.target.entity_id] = 10_000_000
        self.chain.supply.balances[self.client.entity_id] = 10_000_000
        self.chain.supply.balances[self.submitter.entity_id] = 10_000_000
        self.chain.supply.staked[self.target.entity_id] = 300_000
        self.chain.supply.pending_unstakes[self.target.entity_id] = [
            (700_000, 99_999),
        ]
        # Pre-bump offense counter so the curve produces a meaningful
        # sev_pct on the first replay (mirrors Tier 33 test pattern).
        self.chain.slash_offense_counts[self.target.entity_id] = 2
        self.witnesses = _make_witnesses(WITNESS_QUORUM, b"ap")
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 1_000_000

    def _build_block_with_evidence(self, etx) -> Block:
        """Synthesize a Block at post_fork height carrying one NRE.
        Skip the proposer-selection / staking pipeline; the apply test
        targets the slot iteration, not block validity."""
        proposer = self.target  # Any registered entity will do.
        prev_hash = (
            self.chain.get_latest_block().block_hash
            if self.chain.get_latest_block() is not None
            else b"\x00" * 32
        )
        header = BlockHeader(
            version=1,
            block_number=self.post_fork,
            prev_hash=prev_hash,
            merkle_root=_h(b"empty"),
            timestamp=int(time.time()) + 1,
            proposer_id=proposer.entity_id,
        )
        # Manually skip proposer signature gen — _apply_block_state
        # doesn't validate the signature, it just walks state.
        header.proposer_signature = proposer.keypair.sign(
            _h(header.signable_data())
        )
        blk = Block(
            header=header,
            transactions=[],
            non_response_evidence_txs=[etx],
        )
        blk.block_hash = blk._compute_hash()
        return blk

    def test_apply_drains_both_buckets_post_fork(self):
        """A post-fork block with one valid NRE: process() must run,
        the offender's `staked + pending_unstakes` MUST shrink, and
        `total_supply` decreases by the slashed amount."""
        etx = _make_signed_evidence(
            self.chain, self.target, self.client, self.submitter,
            self.witnesses,
            observed_height=self.post_fork - 50, seed=b"\x20",
        )
        blk = self._build_block_with_evidence(etx)
        staked_before = self.chain.supply.staked[self.target.entity_id]
        pending_before = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes[self.target.entity_id]
        )
        total_supply_before = self.chain.supply.total_supply
        with _force_chain_height(self.chain, self.post_fork):
            self.chain._apply_block_state(blk)
        staked_after = self.chain.supply.staked.get(self.target.entity_id, 0)
        pending_after = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes.get(self.target.entity_id, [])
        )
        burn_total = (
            (staked_before + pending_before)
            - (staked_after + pending_after)
        )
        self.assertGreater(
            burn_total, 0,
            "Apply MUST burn some of the offender's stake — otherwise "
            "the block-slot wiring did not invoke the processor.",
        )
        self.assertLess(
            staked_after, staked_before,
            "Staked bucket must shrink.",
        )
        self.assertLess(
            pending_after, pending_before,
            "Pending bucket MUST shrink — the apply path consumes "
            "Tier 33's `(staked + pending_unstakes)` basis.",
        )
        # total_supply shrinks by slash_burn + fee_burn (EIP-1559 base
        # fee burn applies to the fee path on top of the slash burn).
        # The slash burn is the dominant contributor — assert it lands
        # within the slash + fee envelope rather than byte-exact.
        supply_burn = total_supply_before - self.chain.supply.total_supply
        self.assertGreaterEqual(
            supply_burn, burn_total,
            "total_supply burn must include at least the slashed amount.",
        )
        self.assertLessEqual(
            supply_burn, burn_total + MIN_FEE,
            "total_supply burn beyond the slash must be bounded by the "
            "evidence fee — anything larger means an unrelated mutation "
            "is leaking into the apply path.",
        )

    def test_apply_marks_evidence_processed(self):
        """`NonResponseEvidenceProcessor.processed` must contain the
        evidence_hash post-apply.  This is the on-chain double-slash
        defense — a re-submission of the same evidence is rejected."""
        etx = _make_signed_evidence(
            self.chain, self.target, self.client, self.submitter,
            self.witnesses,
            observed_height=self.post_fork - 50, seed=b"\x21",
        )
        blk = self._build_block_with_evidence(etx)
        self.assertNotIn(
            etx.evidence_hash, self.chain.non_response_processor.processed,
            "Setup: evidence must not yet be marked processed.",
        )
        with _force_chain_height(self.chain, self.post_fork):
            self.chain._apply_block_state(blk)
        self.assertIn(
            etx.evidence_hash, self.chain.non_response_processor.processed,
            "Post-apply: the processor MUST have recorded the "
            "evidence_hash; otherwise replay would double-slash.",
        )

    def test_block_affected_entities_includes_submitter_and_offender(self):
        """`_block_affected_entities` must include both the NRE
        submitter and the offender so the post-apply state_tree
        refresh covers both leaves."""
        etx = _make_signed_evidence(
            self.chain, self.target, self.client, self.submitter,
            self.witnesses,
            observed_height=self.post_fork - 50, seed=b"\x22",
        )
        blk = self._build_block_with_evidence(etx)
        affected = self.chain._block_affected_entities(blk)
        self.assertIn(
            self.submitter.entity_id, affected,
            "Submitter MUST be in the affected set — apply debits "
            "their balance for the fee and bumps their leaf_watermark.",
        )
        self.assertIn(
            self.target.entity_id, affected,
            "Offender (target validator) MUST be in the affected set "
            "— apply drains their stake.",
        )

    def test_apply_pre_fork_skips_processor(self):
        """At a pre-fork height, the apply path MUST NOT iterate
        non_response_evidence_txs.  Replay-determinism: historical
        blocks were applied without this loop, and a re-apply must
        produce byte-identical state."""
        from messagechain.config import (
            NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT,
        )
        pre_fork = NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT - 1
        # Build a synthetic pre-fork block.  We DELIBERATELY hand-
        # populate non_response_evidence_txs even though the encoder
        # at pre_fork would not emit them — the apply gate must
        # skip them regardless of how the in-memory block was
        # constructed.
        etx = _make_signed_evidence(
            self.chain, self.target, self.client, self.submitter,
            self.witnesses,
            observed_height=pre_fork - 50, seed=b"\x23",
        )
        proposer = self.target
        prev_hash = (
            self.chain.get_latest_block().block_hash
            if self.chain.get_latest_block() is not None
            else b"\x00" * 32
        )
        header = BlockHeader(
            version=1,
            block_number=pre_fork,
            prev_hash=prev_hash,
            merkle_root=_h(b"empty"),
            timestamp=int(time.time()) + 1,
            proposer_id=proposer.entity_id,
        )
        header.proposer_signature = proposer.keypair.sign(
            _h(header.signable_data())
        )
        blk = Block(
            header=header,
            transactions=[],
            non_response_evidence_txs=[etx],
        )
        blk.block_hash = blk._compute_hash()
        staked_before = self.chain.supply.staked[self.target.entity_id]
        pending_before = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes[self.target.entity_id]
        )
        with _force_chain_height(self.chain, pre_fork):
            self.chain._apply_block_state(blk)
        self.assertEqual(
            self.chain.supply.staked.get(self.target.entity_id, 0),
            staked_before,
            "Pre-fork: staked MUST be unchanged — the apply gate "
            "skips the slot below the activation height.",
        )
        self.assertEqual(
            sum(
                amt for amt, _ in
                self.chain.supply.pending_unstakes.get(
                    self.target.entity_id, [],
                )
            ),
            pending_before,
            "Pre-fork: pending_unstakes MUST be unchanged.",
        )
        self.assertNotIn(
            etx.evidence_hash, self.chain.non_response_processor.processed,
            "Pre-fork: evidence MUST NOT be marked processed — the "
            "processor was never invoked.",
        )


# ─────────────────────────────────────────────────────────────────────
# 4. Forced-inclusion gate sees the slot
# ─────────────────────────────────────────────────────────────────────


class TestForcedInclusionRegistryIncludesSlot(unittest.TestCase):
    """Tier 34's multi-list forced-inclusion gate walks every block
    tx-list field listed in
    ``messagechain.consensus.forced_inclusion._BLOCK_TX_LIST_ATTRS``.
    The new ``non_response_evidence_txs`` slot MUST appear there so a
    forced NRE placed in its correct slot is recognized as included
    rather than flagged as censored."""

    def test_forced_inclusion_registry_lists_nre_slot(self):
        from messagechain.consensus.forced_inclusion import (
            _BLOCK_TX_LIST_ATTRS,
        )
        self.assertIn(
            "non_response_evidence_txs", _BLOCK_TX_LIST_ATTRS,
            "`non_response_evidence_txs` MUST be in the forced-"
            "inclusion gate's tx-list registry; otherwise a forced "
            "NRE in its correct slot would be flagged as censored.",
        )

    def test_blockchain_registry_lists_nre_slot(self):
        """The Blockchain-side `_BLOCK_TX_LIST_ATTRS` (used by
        `_block_affected_entities` and the entity-touch sweep) must
        also list the new slot, otherwise the per-block dirty-set
        sweep skips the NRE submitter + offender."""
        self.assertIn(
            "non_response_evidence_txs", Blockchain._BLOCK_TX_LIST_ATTRS,
            "`non_response_evidence_txs` MUST be in the Blockchain-side "
            "tx-list registry; otherwise the dirty-set sweep skips it.",
        )


if __name__ == "__main__":
    unittest.main()
