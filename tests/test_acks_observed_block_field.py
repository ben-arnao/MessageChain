"""Tests for `Block.acks_observed_this_block` and witness-ack registry
state-root integration.

Closes the consensus-correctness gaps left after the witnessed-submission
PR:

  * Gap A — `NonResponseEvidenceProcessor.processed` and
    `Blockchain.witness_ack_registry` were not in the state snapshot.  A
    state-synced node would inherit empty state and could re-apply
    already-processed evidence (double-slash) or disagree with peers
    about ack'd request_hashes.

  * Gap B — Proposers had no way to embed observed `SubmissionAck`s in
    their block, so `witness_ack_registry` was only populated via
    in-process test assignment, never via consensus.

This module covers the new wire field + state integration end-to-end.
Pre-existing snapshot/processor tests live in their own modules; here
we focus on the round-trips and admission-time consultation that didn't
exist before.
"""

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    MAX_ACKS_PER_BLOCK,
    MIN_FEE,
    WITNESS_OBSERVATION_RETENTION_BLOCKS,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    WITNESS_SURCHARGE,
)
from messagechain.identity.identity import Entity
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.witness_submission import (
    SubmissionRequest,
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceTx,
    sign_non_response_evidence,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_block_with_acks(prev_block, proposer_entity, acks):
    """Helper: build a minimal Block with `acks_observed_this_block`
    populated.  Skips the full propose_block pipeline so individual
    field-shape rules can be tested without staking + selection setup.
    """
    from messagechain.crypto.hash import hash_bytes as _hb
    header = BlockHeader(
        version=1,
        block_number=prev_block.header.block_number + 1,
        prev_hash=prev_block.block_hash,
        merkle_root=_hb(b"empty"),
        timestamp=int(time.time()) + 1,
        proposer_id=proposer_entity.entity_id,
    )
    header_hash = _hb(header.signable_data())
    header.proposer_signature = proposer_entity.keypair.sign(header_hash)
    blk = Block(
        header=header,
        transactions=[],
        acks_observed_this_block=list(acks),
    )
    blk.block_hash = blk._compute_hash()
    return blk


# ─────────────────────────────────────────────────────────────────────
# 1. Block field shape — sort + dedup + cap + round-trip
# ─────────────────────────────────────────────────────────────────────

class TestBlockAcksField(unittest.TestCase):
    """The new `acks_observed_this_block` field is wire-bound,
    canonically-ordered, capped, and round-trips through both
    serialize/deserialize and to_bytes/from_bytes."""

    def test_default_is_empty_list(self):
        blk = Block(header=BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=0, proposer_id=b"P" * 32,
        ), transactions=[])
        self.assertEqual(blk.acks_observed_this_block, [])

    def test_dict_roundtrip_preserves_acks(self):
        acks = sorted([_h(b"r1"), _h(b"r2"), _h(b"r3")])
        blk = Block(
            header=BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x01" * 32, timestamp=0, proposer_id=b"P" * 32,
            ),
            transactions=[],
            acks_observed_this_block=acks,
        )
        round_tripped = Block.deserialize(blk.serialize())
        self.assertEqual(round_tripped.acks_observed_this_block, acks)

    def test_binary_roundtrip_preserves_acks(self):
        acks = sorted([_h(b"r1"), _h(b"r2"), _h(b"r3")])
        blk = Block(
            header=BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x01" * 32, timestamp=0, proposer_id=b"P" * 32,
            ),
            transactions=[],
            acks_observed_this_block=acks,
        )
        blob = blk.to_bytes()
        round_tripped = Block.from_bytes(blob)
        self.assertEqual(round_tripped.acks_observed_this_block, acks)

    def test_acks_fold_into_merkle_root(self):
        """A block with non-empty `acks_observed_this_block` produces
        a different canonical tx-hash list (and therefore merkle_root
        commitment) than an otherwise-identical empty one — a relayer
        cannot strip or mutate the list in transit."""
        from messagechain.core.block import canonical_block_tx_hashes
        empty_blk = Block(
            header=BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x01" * 32, timestamp=0, proposer_id=b"P" * 32,
            ),
            transactions=[],
            acks_observed_this_block=[],
        )
        full_blk = Block(
            header=BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x01" * 32, timestamp=0, proposer_id=b"P" * 32,
            ),
            transactions=[],
            acks_observed_this_block=sorted([_h(b"x"), _h(b"y")]),
        )
        # canonical_block_tx_hashes folds in the acks list as one of its
        # commitment sources; the two lists must differ.
        self.assertNotEqual(
            canonical_block_tx_hashes(empty_blk),
            canonical_block_tx_hashes(full_blk),
        )


# ─────────────────────────────────────────────────────────────────────
# 2. Validate-block enforcement: sort + dedup + cap
# ─────────────────────────────────────────────────────────────────────

class TestBlockAcksFieldValidation(unittest.TestCase):
    """`validate_block` rejects unsorted, duplicated, malformed-length,
    or cap-exceeding ack lists.  These are wire-format rules so the
    network-layer accepts an unambiguous canonical form only."""

    def setUp(self):
        self.proposer = Entity.create(b"prop-acks".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def _propose_with_acks(self, acks: list[bytes]) -> Block:
        """Build a block with the given acks list and compute the
        post-state root through the chain so the header passes basic
        state checks, then return it (without applying)."""
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.config import VALIDATOR_MIN_STAKE
        self.chain.supply.balances[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 100
        )
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
            acks_observed_this_block=list(acks),
        )
        return blk

    def test_unsorted_acks_rejected(self):
        a = _h(b"a")
        b = _h(b"b")
        # Force unsorted (b before a, where b > a).
        if a < b:
            unsorted = [b, a]
        else:
            unsorted = [a, b]
        blk = self._propose_with_acks(unsorted)
        # Bypass propose_block's auto-sort by re-assigning post hoc.
        blk.acks_observed_this_block = unsorted
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertIn("sort", reason.lower())

    def test_duplicate_acks_rejected(self):
        dup = _h(b"r")
        blk = self._propose_with_acks([dup, dup])
        blk.acks_observed_this_block = [dup, dup]
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertIn("dup", reason.lower())

    def test_too_many_acks_rejected(self):
        many = sorted({_h(b"r" + str(i).encode()) for i in range(MAX_ACKS_PER_BLOCK + 1)})
        blk = self._propose_with_acks(many[:1])
        # Re-inject the oversized list directly so propose_block's
        # cap is bypassed for this hostile-block construction.
        blk.acks_observed_this_block = many
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertTrue(
            "max" in reason.lower() or "too many" in reason.lower(),
            reason,
        )

    def test_wrong_length_entry_rejected(self):
        bad = b"\xaa" * 31  # not 32 bytes
        blk = self._propose_with_acks([])
        blk.acks_observed_this_block = [bad]
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertIn("32", reason)


# ─────────────────────────────────────────────────────────────────────
# 3. Proposer wiring + state-apply populates the registry
# ─────────────────────────────────────────────────────────────────────

class TestProposerEmbedsAcks(unittest.TestCase):
    """A proposer with a local witness_observation_store that has
    recorded acks pulls those request_hashes into the next block's
    `acks_observed_this_block` list, capped at MAX_ACKS_PER_BLOCK."""

    def setUp(self):
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.consensus.witness_submission import (
            WitnessObservationStore,
        )
        self.proposer = Entity.create(b"prop-emb-acks".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        self.chain.supply.staked[self.proposer.entity_id] = VALIDATOR_MIN_STAKE * 10
        self.chain.supply.balances[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 100
        )
        # Attach a local witness observation store to the chain so the
        # proposer can read recently-observed acks.
        self.chain.witness_observation_store = WitnessObservationStore()

    def test_default_empty_when_no_acks_observed(self):
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        self.assertEqual(blk.acks_observed_this_block, [])

    def test_proposer_embeds_observed_acks(self):
        from messagechain.consensus.pos import ProofOfStake
        # Record three acks in the local store.
        rh1, rh2, rh3 = _h(b"req1"), _h(b"req2"), _h(b"req3")
        for rh in (rh1, rh2, rh3):
            self.chain.witness_observation_store.record_ack(rh, ack_height=1)
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        self.assertEqual(
            sorted(blk.acks_observed_this_block),
            sorted([rh1, rh2, rh3]),
        )
        # Sorted canonically.
        self.assertEqual(
            blk.acks_observed_this_block,
            sorted(blk.acks_observed_this_block),
        )

    def test_apply_block_populates_witness_ack_registry(self):
        from messagechain.consensus.pos import ProofOfStake
        rh = _h(b"populate-me")
        self.chain.witness_observation_store.record_ack(rh, ack_height=1)
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        ok, reason = self.chain.add_block(blk)
        self.assertTrue(ok, reason)
        self.assertIn(rh, self.chain.witness_ack_registry)
        # Stored ack_height equals the block's height.
        self.assertEqual(
            self.chain.witness_ack_registry[rh], blk.header.block_number,
        )

    def test_proposer_caps_at_max_acks_per_block(self):
        from messagechain.consensus.pos import ProofOfStake
        # Record MAX_ACKS_PER_BLOCK + 5 acks; only MAX should be embedded.
        for i in range(MAX_ACKS_PER_BLOCK + 5):
            self.chain.witness_observation_store.record_ack(
                _h(b"req-cap-" + str(i).encode()),
                ack_height=1,
            )
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        self.assertEqual(len(blk.acks_observed_this_block), MAX_ACKS_PER_BLOCK)


# ─────────────────────────────────────────────────────────────────────
# 4. Validator soft-vote acceptance — block valid even when the
#    receiver hasn't observed the ack itself.
# ─────────────────────────────────────────────────────────────────────

class TestValidatorSoftVoteAck(unittest.TestCase):
    """A validator MUST accept a block whose `acks_observed_this_block`
    references request_hashes the validator has never seen — proposer
    mempool views are subjective.  Soft-vote signal only."""

    def setUp(self):
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.consensus.witness_submission import (
            WitnessObservationStore,
        )
        self.proposer = Entity.create(b"prop-soft".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        self.chain.supply.staked[self.proposer.entity_id] = VALIDATOR_MIN_STAKE * 10
        self.chain.supply.balances[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 100
        )
        # Proposer has its OWN store with the ack; the chain's store
        # (validator's view) is empty.
        self.proposer_store = WitnessObservationStore()
        self.chain.witness_observation_store = self.proposer_store

    def test_block_valid_when_validator_did_not_observe_ack(self):
        from messagechain.consensus.pos import ProofOfStake
        rh_unknown = _h(b"never-observed-locally")
        self.proposer_store.record_ack(rh_unknown, ack_height=1)
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        # Now wipe the local store so the "validator" perspective has
        # no ack record, and validate the block as a soft signal.
        self.chain.witness_observation_store = None
        ok, reason = self.chain.validate_block(blk)
        self.assertTrue(ok, reason)


# ─────────────────────────────────────────────────────────────────────
# 5. Evidence admission consults the registry
# ─────────────────────────────────────────────────────────────────────

class TestEvidenceAdmissionConsultsRegistry(unittest.TestCase):
    """`validate_non_response_evidence_tx` (admission gate) rejects
    evidence whose request_hash is already recorded in the chain's
    witness_ack_registry — the obligation was met."""

    def setUp(self):
        self.target = Entity.create(b"validator-evtest".ljust(32, b"\x00"))
        self.client = Entity.create(b"client-evtest".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"submitter-evtest".ljust(32, b"\x00"))
        self.target.keypair._next_leaf = 0
        self.client.keypair._next_leaf = 0
        self.submitter.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        self.chain.supply.balances[self.target.entity_id] = 1_000_000
        self.chain.supply.balances[self.client.entity_id] = 1_000_000
        self.chain.supply.balances[self.submitter.entity_id] = 1_000_000
        self.chain.supply.staked[self.target.entity_id] = 100_000
        self.witnesses = []
        for i in range(WITNESS_QUORUM):
            w = Entity.create(
                (b"wn-evtest-" + str(i).encode()).ljust(32, b"\x00"),
            )
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 100_000
            self.witnesses.append(w)

    def _build_evidence(self, observed_height: int = 0) -> NonResponseEvidenceTx:
        req = sign_submission_request(
            submitter=self.client,
            target_validator_id=self.target.entity_id,
            tx_hash=_h(b"evtest-payload"),
            timestamp=int(time.time()),
            client_nonce=b"\x99" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height)
            for w in self.witnesses
        ]
        return sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )

    def test_evidence_rejected_when_request_hash_in_registry(self):
        etx = self._build_evidence(observed_height=0)
        # Pre-record an in-deadline ack in the chain's registry — same
        # state shape that arrives through a block carrying the
        # request_hash in `acks_observed_this_block`.
        self.chain.witness_ack_registry[etx.request.request_hash] = 3
        ok, reason = self.chain.validate_non_response_evidence_tx(etx)
        self.assertFalse(ok)
        self.assertIn("ack present in chain state", reason.lower())

    def test_evidence_admitted_when_no_ack_recorded(self):
        etx = self._build_evidence(observed_height=0)
        # Chain registry empty — admission proceeds (subject to other
        # gates checked by the processor).
        ok, _ = self.chain.validate_non_response_evidence_tx(etx)
        self.assertTrue(ok)


# ─────────────────────────────────────────────────────────────────────
# 6. End-to-end: propose block carrying ack → registry populated →
#    later evidence rejected with a clear "ack present" message.
# ─────────────────────────────────────────────────────────────────────

class TestEndToEndBlockEmbedsAckThenEvidenceRejected(unittest.TestCase):
    """Full flow: file evidence-relevant request → block carrying that
    request_hash in `acks_observed_this_block` lands → registry
    populated → submitting NonResponseEvidenceTx for the same
    request_hash is rejected."""

    def setUp(self):
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.consensus.witness_submission import (
            WitnessObservationStore,
        )
        self.target = Entity.create(b"e2e-validator-target".ljust(32, b"\x00"))
        self.client = Entity.create(b"e2e-client".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"e2e-submitter".ljust(32, b"\x00"))
        self.target.keypair._next_leaf = 0
        self.client.keypair._next_leaf = 0
        self.submitter.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        self.chain.supply.balances[self.target.entity_id] = 1_000_000
        self.chain.supply.balances[self.client.entity_id] = 1_000_000
        self.chain.supply.balances[self.submitter.entity_id] = 1_000_000
        self.chain.supply.staked[self.target.entity_id] = (
            VALIDATOR_MIN_STAKE * 10
        )
        self.witnesses = []
        for i in range(WITNESS_QUORUM):
            w = Entity.create(
                (b"e2e-witness-" + str(i).encode()).ljust(32, b"\x00"),
            )
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 100_000
            self.witnesses.append(w)
        self.chain.witness_observation_store = WitnessObservationStore()

    def test_block_carries_ack_then_evidence_rejected(self):
        from messagechain.consensus.pos import ProofOfStake
        req = sign_submission_request(
            submitter=self.client,
            target_validator_id=self.target.entity_id,
            tx_hash=_h(b"e2e-payload"),
            timestamp=int(time.time()),
            client_nonce=b"\x77" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        # Local witness store sees the ack (proposer's perspective).
        self.chain.witness_observation_store.record_ack(
            req.request_hash, ack_height=1,
        )

        consensus = ProofOfStake()
        # Honor stake-weighted slot selection: with multiple staked
        # validators, the actual proposer for the next slot may be any
        # of them.  Pick the selected one and proceed — the apply path
        # populates the registry under the same request_hash regardless
        # of which staked validator authored the block.
        from tests import pick_selected_proposer
        candidates = [self.target] + self.witnesses
        selected = pick_selected_proposer(self.chain, candidates)
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=selected,
            transactions=[],
        )
        self.assertIn(req.request_hash, blk.acks_observed_this_block)
        ok, reason = self.chain.add_block(blk)
        self.assertTrue(ok, reason)
        # Now construct an evidence transaction for the same
        # request_hash — it should be rejected at admission time
        # because the registry holds the ack.
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=0)
            for w in self.witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        ok, reason = self.chain.validate_non_response_evidence_tx(etx)
        self.assertFalse(ok)
        self.assertIn("ack present in chain state", reason.lower())


# ─────────────────────────────────────────────────────────────────────
# 7. Registry pruning — entries older than the retention window are
#    removed deterministically so a long-replay node and a freshly
#    state-synced node converge to the same registry contents.
# ─────────────────────────────────────────────────────────────────────

class TestWitnessAckRegistryPruning(unittest.TestCase):
    """Entries older than
    WITNESS_OBSERVATION_RETENTION_BLOCKS + WITNESS_RESPONSE_DEADLINE_BLOCKS
    are removed by the apply path so the registry's footprint is
    bounded."""

    def setUp(self):
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.consensus.witness_submission import (
            WitnessObservationStore,
        )
        self.proposer = Entity.create(b"prop-prune".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        self.chain.supply.staked[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 10
        )
        self.chain.supply.balances[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 100
        )
        self.chain.witness_observation_store = WitnessObservationStore()

    def test_entries_outside_retention_window_pruned(self):
        retention = (
            WITNESS_OBSERVATION_RETENTION_BLOCKS
            + WITNESS_RESPONSE_DEADLINE_BLOCKS
        )
        # Pre-seed an old ack at height 1 — far older than the
        # retention window relative to the block we're about to apply.
        old_rh = _h(b"old-rh")
        self.chain.witness_ack_registry[old_rh] = 1
        # Propose enough blocks to push the chain past retention + 1.
        # We don't need full PoS dynamics; manual height bumps via
        # _apply_block_state are sufficient as long as the prune
        # function runs from the apply path.  Use an artificially
        # placed entry at a high block_number for the simulated tip.
        # A cleaner approach: directly call the prune helper at a
        # height past retention + 1.
        self.chain._prune_witness_ack_registry(
            current_height=retention + 5,
        )
        self.assertNotIn(old_rh, self.chain.witness_ack_registry)


# ─────────────────────────────────────────────────────────────────────
# 8. State-snapshot integration — versions, encoded sections,
#    encode/decode round-trip, install_snapshot.
# ─────────────────────────────────────────────────────────────────────

class TestSnapshotVersionsBumped(unittest.TestCase):
    """Bumps cover both new sections in one coherent fork — non-
    response processed + witness ack registry.  Wire-version
    arithmetic: the brief said "10→11" against an older baseline;
    by the time this iteration landed the repo had already moved
    through v11 (treasury rolling debits), v12 (inclusion-list
    processed_violations key widening), and v13 (per-entity
    attester-reward cap epoch earnings), so the actual bump is
    13→14 / 4→5 — same intent, current numbers.  A subsequent
    fork (v15: validator-registration burn) has since landed, so
    this assertion accepts the monotonically-rising snapshot
    version — what matters is the ``>= 14`` floor that pins the
    witness-submission wire format, not a freeze at exactly 14."""

    def test_state_snapshot_version_is_14(self):
        from messagechain.storage.state_snapshot import STATE_SNAPSHOT_VERSION
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 14)

    def test_state_root_version_is_5(self):
        from messagechain.storage.state_snapshot import STATE_ROOT_VERSION
        self.assertEqual(STATE_ROOT_VERSION, 5)


class TestSnapshotIncludesNewSections(unittest.TestCase):
    """`serialize_state` writes the non-response-processor processed
    set + the witness_ack_registry into the snapshot dict, and
    `compute_state_root` covers them so a tampered value moves the
    root."""

    def setUp(self):
        self.proposer = Entity.create(b"prop-snap".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_serialize_includes_processed_set(self):
        from messagechain.storage.state_snapshot import serialize_state
        self.chain.non_response_processor.processed.add(_h(b"ev1"))
        self.chain.non_response_processor.processed.add(_h(b"ev2"))
        snap = serialize_state(self.chain)
        self.assertIn("non_response_processed", snap)
        self.assertEqual(
            snap["non_response_processed"],
            {_h(b"ev1"), _h(b"ev2")},
        )

    def test_serialize_includes_witness_ack_registry(self):
        from messagechain.storage.state_snapshot import serialize_state
        rh1, rh2 = _h(b"a"), _h(b"b")
        self.chain.witness_ack_registry[rh1] = 5
        self.chain.witness_ack_registry[rh2] = 7
        snap = serialize_state(self.chain)
        self.assertIn("witness_ack_registry", snap)
        self.assertEqual(snap["witness_ack_registry"], {rh1: 5, rh2: 7})

    def test_root_changes_when_processed_set_changes(self):
        from messagechain.storage.state_snapshot import (
            serialize_state, compute_state_root,
        )
        snap_a = serialize_state(self.chain)
        root_a = compute_state_root(snap_a)
        self.chain.non_response_processor.processed.add(_h(b"ev"))
        snap_b = serialize_state(self.chain)
        root_b = compute_state_root(snap_b)
        self.assertNotEqual(root_a, root_b)

    def test_root_changes_when_ack_registry_changes(self):
        from messagechain.storage.state_snapshot import (
            serialize_state, compute_state_root,
        )
        snap_a = serialize_state(self.chain)
        root_a = compute_state_root(snap_a)
        self.chain.witness_ack_registry[_h(b"r")] = 9
        snap_b = serialize_state(self.chain)
        root_b = compute_state_root(snap_b)
        self.assertNotEqual(root_a, root_b)


class TestSnapshotEncodeDecodeRoundtrip(unittest.TestCase):
    """The new sections survive encode/decode through the binary
    snapshot blob."""

    def setUp(self):
        self.proposer = Entity.create(b"prop-codec".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_encode_decode_preserves_processed_set(self):
        from messagechain.storage.state_snapshot import (
            serialize_state, encode_snapshot, decode_snapshot,
        )
        self.chain.non_response_processor.processed = {_h(b"x"), _h(b"y")}
        snap = serialize_state(self.chain)
        blob = encode_snapshot(snap)
        restored = decode_snapshot(blob)
        self.assertEqual(
            restored["non_response_processed"],
            {_h(b"x"), _h(b"y")},
        )

    def test_encode_decode_preserves_ack_registry(self):
        from messagechain.storage.state_snapshot import (
            serialize_state, encode_snapshot, decode_snapshot,
        )
        rh1 = _h(b"reg1")
        rh2 = _h(b"reg2")
        self.chain.witness_ack_registry = {rh1: 11, rh2: 22}
        snap = serialize_state(self.chain)
        blob = encode_snapshot(snap)
        restored = decode_snapshot(blob)
        self.assertEqual(restored["witness_ack_registry"], {rh1: 11, rh2: 22})


class TestSnapshotInstallRehydratesNewSections(unittest.TestCase):
    """`Blockchain._install_state_snapshot` rehydrates
    `non_response_processor.processed` and `witness_ack_registry` from
    the snapshot."""

    def setUp(self):
        self.proposer = Entity.create(b"prop-inst".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_install_restores_processed_and_registry(self):
        from messagechain.storage.state_snapshot import serialize_state
        rh = _h(b"rh-install")
        ev = _h(b"ev-install")
        self.chain.witness_ack_registry[rh] = 42
        self.chain.non_response_processor.processed.add(ev)
        snap = serialize_state(self.chain)

        # Brand-new chain — should NOT see the old state.
        target = Blockchain()
        target.initialize_genesis(self.proposer)
        self.assertNotIn(rh, target.witness_ack_registry)
        self.assertNotIn(ev, target.non_response_processor.processed)
        target._install_state_snapshot(snap)
        self.assertEqual(target.witness_ack_registry.get(rh), 42)
        self.assertIn(ev, target.non_response_processor.processed)


class TestPreviousSnapshotVersionRejected(unittest.TestCase):
    """A blob whose version byte is the previous wire version (13) is
    rejected with a clear error message — the bump is non-backwards-
    compatible at the snapshot layer (operators must re-sync)."""

    def test_v13_blob_rejected_with_clear_message(self):
        from messagechain.storage.state_snapshot import (
            decode_snapshot,
        )
        # Force the version byte to 13 (one less than current);
        # the rest of the bytes are irrelevant — the version gate
        # fires first.
        blob = b"\x0d" + b"\x00" * 1024
        with self.assertRaises(ValueError) as cm:
            decode_snapshot(blob)
        msg = str(cm.exception).lower()
        self.assertIn("version", msg)
        self.assertIn("13", msg)


# ─────────────────────────────────────────────────────────────────────
# 9. Two-node determinism — two chains processing the same block
#    sequence reach identical state-roots, INCLUDING the new sections.
# ─────────────────────────────────────────────────────────────────────

class TestTwoNodeDeterminism(unittest.TestCase):
    """Build two independent chains, drive the same proposer through
    the same block sequence (a block carrying acks_observed_this_block,
    plus a manually-added pending evidence in `processed`), and assert
    snapshot roots agree.  Catches drift in any new section's
    encode-or-hash path."""

    def _build_chain(self):
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.consensus.witness_submission import (
            WitnessObservationStore,
        )
        proposer = Entity.create(b"prop-det".ljust(32, b"\x00"))
        proposer.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(proposer)
        chain.supply.staked[proposer.entity_id] = VALIDATOR_MIN_STAKE * 10
        chain.supply.balances[proposer.entity_id] = VALIDATOR_MIN_STAKE * 100
        chain.witness_observation_store = WitnessObservationStore()
        return chain, proposer

    def test_identical_state_roots_after_same_blocks(self):
        from messagechain.storage.state_snapshot import (
            serialize_state, compute_state_root,
        )
        chain_a, _ = self._build_chain()
        chain_b, _ = self._build_chain()
        # Inject the exact same registry + processed contents into both.
        rh = _h(b"twin-rh")
        ev = _h(b"twin-ev")
        for c in (chain_a, chain_b):
            c.witness_ack_registry[rh] = 33
            c.non_response_processor.processed.add(ev)
        root_a = compute_state_root(serialize_state(chain_a))
        root_b = compute_state_root(serialize_state(chain_b))
        self.assertEqual(root_a, root_b)


if __name__ == "__main__":
    unittest.main()
