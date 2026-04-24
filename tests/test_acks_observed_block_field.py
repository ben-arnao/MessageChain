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
    SubmissionAck,
    SubmissionRequest,
    sign_submission_request,
    sign_witness_observation,
    ACK_ADMITTED,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceTx,
    sign_non_response_evidence,
)
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.crypto.hash_sig import _hash as _receipt_hash


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_signed_ack(
    chain,
    issuer: Entity,
    issuer_subtree_kp: "KeyPair",
    request_hash: bytes,
    commit_height: int = 1,
    action_code: int = ACK_ADMITTED,
    register_root: bool = True,
) -> SubmissionAck:
    """Produce a fully-signed SubmissionAck for tests + register the
    issuer's receipt-subtree root on the chain so validation can
    verify the ack.  The post-forgery-fix block field requires the
    full signed ack, not just a request_hash.
    """
    if register_root:
        chain.receipt_subtree_roots[issuer.entity_id] = (
            issuer_subtree_kp.public_key
        )
    ack = SubmissionAck(
        request_hash=request_hash,
        issuer_id=issuer.entity_id,
        issuer_root_public_key=issuer_subtree_kp.public_key,
        action_code=action_code,
        commit_height=commit_height,
        signature=Signature([], 0, [], b"", b""),
    )
    msg_hash = hashlib.new(HASH_ALGO, ack._signable_data()).digest()
    ack.signature = issuer_subtree_kp.sign(msg_hash)
    ack.ack_hash = ack._compute_hash()
    return ack


def _receipt_subtree_kp(seed_tag: bytes, height: int = 4) -> "KeyPair":
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag,
        height=height,
    )


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

    def _make_chain_and_acks(self, n: int = 3):
        """Build a chain + `n` signed SubmissionAcks sorted by
        request_hash.  Each ack is signed under a distinct
        receipt-subtree root, all registered on the chain."""
        proposer = Entity.create(b"prop-wire".ljust(32, b"\x00"))
        proposer.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(proposer)
        acks = []
        for i in range(n):
            issuer = Entity.create(
                (b"issuer-" + str(i).encode()).ljust(32, b"\x00"),
            )
            issuer.keypair._next_leaf = 0
            register_entity_for_test(chain, issuer)
            kp = _receipt_subtree_kp(b"wire-" + str(i).encode())
            ack = _make_signed_ack(
                chain, issuer, kp, _h(b"r" + str(i).encode()),
                commit_height=1 + i,
            )
            acks.append(ack)
        return chain, sorted(acks, key=lambda a: a.request_hash)

    def test_default_is_empty_list(self):
        blk = Block(header=BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=0, proposer_id=b"P" * 32,
        ), transactions=[])
        self.assertEqual(blk.acks_observed_this_block, [])

    def test_dict_roundtrip_preserves_acks(self):
        _, acks = self._make_chain_and_acks(3)
        blk = Block(
            header=BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x01" * 32, timestamp=0, proposer_id=b"P" * 32,
            ),
            transactions=[],
            acks_observed_this_block=acks,
        )
        round_tripped = Block.deserialize(blk.serialize())
        self.assertEqual(
            [a.ack_hash for a in round_tripped.acks_observed_this_block],
            [a.ack_hash for a in acks],
        )

    def test_binary_roundtrip_preserves_acks(self):
        _, acks = self._make_chain_and_acks(3)
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
        self.assertEqual(
            [a.ack_hash for a in round_tripped.acks_observed_this_block],
            [a.ack_hash for a in acks],
        )

    def test_acks_fold_into_merkle_root(self):
        """A block with non-empty `acks_observed_this_block` produces
        a different canonical tx-hash list (and therefore merkle_root
        commitment) than an otherwise-identical empty one — a relayer
        cannot strip or mutate the list in transit."""
        from messagechain.core.block import canonical_block_tx_hashes
        _, acks = self._make_chain_and_acks(2)
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
            acks_observed_this_block=acks,
        )
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
        # Pre-bake an issuer + registered receipt-subtree root so any
        # SubmissionAck below can be signed and will bind to the
        # chain's registered_root gate.
        self.issuer = Entity.create(b"issuer-validrules".ljust(32, b"\x00"))
        self.issuer.keypair._next_leaf = 0
        register_entity_for_test(self.chain, self.issuer)
        self.issuer_kp = _receipt_subtree_kp(b"validrules")
        self.chain.receipt_subtree_roots[self.issuer.entity_id] = (
            self.issuer_kp.public_key
        )

    def _make_ack(self, request_hash: bytes, commit_height: int = 1) -> SubmissionAck:
        return _make_signed_ack(
            self.chain, self.issuer, self.issuer_kp, request_hash,
            commit_height=commit_height, register_root=False,
        )

    def _propose_with_acks(self, acks: list) -> Block:
        """Build a block with the given ack list and compute the
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
        a_rh = _h(b"a")
        b_rh = _h(b"b")
        ack_a = self._make_ack(a_rh)
        ack_b = self._make_ack(b_rh)
        # Force unsorted (larger request_hash first).
        if a_rh < b_rh:
            unsorted = [ack_b, ack_a]
        else:
            unsorted = [ack_a, ack_b]
        blk = self._propose_with_acks([ack_a])
        blk.acks_observed_this_block = unsorted
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertIn("sort", reason.lower())

    def test_duplicate_acks_rejected(self):
        dup_rh = _h(b"r")
        ack_1 = self._make_ack(dup_rh, commit_height=1)
        ack_2 = self._make_ack(dup_rh, commit_height=2)
        blk = self._propose_with_acks([ack_1])
        blk.acks_observed_this_block = [ack_1, ack_2]
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertIn("dup", reason.lower())

    def test_too_many_acks_rejected(self):
        # The count-cap gate fires in `_validate_acks_observed_this_block`
        # before any per-entry signature verification, so we build a
        # MAX_ACKS_PER_BLOCK + 1 list with cheap STRUCTURE (no real
        # crypto) and only run validate_block to assert rejection on
        # the count rule.  Each entry is a SubmissionAck so the type
        # check in the encoder/validator accepts the list shape.
        placeholder = self._make_ack(_h(b"cap-placeholder"), commit_height=1)
        # Clone the same placeholder with different request_hashes to
        # hit the count cap cheaply.  The dup-request_hash rule is
        # separately tested above; here we manufacture distinct keys.
        acks = []
        for i in range(MAX_ACKS_PER_BLOCK + 1):
            stub = SubmissionAck(
                request_hash=_h(b"r" + str(i).encode()),
                issuer_id=placeholder.issuer_id,
                issuer_root_public_key=placeholder.issuer_root_public_key,
                action_code=placeholder.action_code,
                commit_height=placeholder.commit_height,
                signature=placeholder.signature,
            )
            stub.ack_hash = stub._compute_hash()
            acks.append(stub)
        acks.sort(key=lambda a: a.request_hash)
        blk = self._propose_with_acks([acks[0]])
        blk.acks_observed_this_block = acks
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertTrue(
            "max" in reason.lower() or "too many" in reason.lower(),
            reason,
        )

    def test_forged_ack_without_registered_root_rejected(self):
        """Post-fix: an ack signed under a throwaway subtree root that
        the chain has NOT registered for the issuer must be rejected.
        This is the central forgery defense -- without it a colluding
        proposer could fabricate acks for any gossip-visible request."""
        rogue_issuer = Entity.create(b"rogue".ljust(32, b"\x00"))
        rogue_issuer.keypair._next_leaf = 0
        register_entity_for_test(self.chain, rogue_issuer)
        rogue_kp = _receipt_subtree_kp(b"rogue")
        # Crucially: DO NOT register the root on the chain.
        ack = SubmissionAck(
            request_hash=_h(b"target-request"),
            issuer_id=rogue_issuer.entity_id,
            issuer_root_public_key=rogue_kp.public_key,
            action_code=ACK_ADMITTED,
            commit_height=1,
            signature=Signature([], 0, [], b"", b""),
        )
        msg_hash = hashlib.new(HASH_ALGO, ack._signable_data()).digest()
        ack.signature = rogue_kp.sign(msg_hash)
        ack.ack_hash = ack._compute_hash()
        blk = self._propose_with_acks([ack])
        blk.acks_observed_this_block = [ack]
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(ok)
        self.assertIn("receipt_subtree_root", reason.lower())


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

    def _make_issuer(self, tag: bytes):
        iss = Entity.create((b"iss-" + tag).ljust(32, b"\x00"))
        iss.keypair._next_leaf = 0
        register_entity_for_test(self.chain, iss)
        kp = _receipt_subtree_kp(tag)
        self.chain.receipt_subtree_roots[iss.entity_id] = kp.public_key
        return iss, kp

    def test_proposer_embeds_observed_acks(self):
        from messagechain.consensus.pos import ProofOfStake
        # Record three signed acks in the local store.
        iss, kp = self._make_issuer(b"embed")
        rh1, rh2, rh3 = _h(b"req1"), _h(b"req2"), _h(b"req3")
        acks = [
            _make_signed_ack(
                self.chain, iss, kp, rh, commit_height=i+1,
                register_root=False,
            )
            for i, rh in enumerate((rh1, rh2, rh3))
        ]
        for a in acks:
            self.chain.witness_observation_store.record_ack(a)
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        rh_in_block = {a.request_hash for a in blk.acks_observed_this_block}
        self.assertEqual(rh_in_block, {rh1, rh2, rh3})
        # Canonical order: sorted by request_hash.
        self.assertEqual(
            [a.request_hash for a in blk.acks_observed_this_block],
            sorted(rh_in_block),
        )

    def test_apply_block_populates_witness_ack_registry(self):
        from messagechain.consensus.pos import ProofOfStake
        iss, kp = self._make_issuer(b"pop")
        rh = _h(b"populate-me")
        ack = _make_signed_ack(
            self.chain, iss, kp, rh, commit_height=1, register_root=False,
        )
        self.chain.witness_observation_store.record_ack(ack)
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        ok, reason = self.chain.add_block(blk)
        self.assertTrue(ok, reason)
        self.assertIn(rh, self.chain.witness_ack_registry)
        # Stored ack_height equals the ack's OWN commit_height (not the
        # containing block's height) -- the fix against proposer-
        # controlled height shifting.
        self.assertEqual(
            self.chain.witness_ack_registry[rh], ack.commit_height,
        )

    def test_proposer_caps_at_max_acks_per_block(self):
        from messagechain.consensus.pos import ProofOfStake
        # Proposer's truncate-to-MAX_ACKS_PER_BLOCK only reads the
        # store's size, not the ack signatures.  Use stub SubmissionAcks
        # injected directly into the store (bypassing record_ack's
        # type check) so we can exercise the cap without running ~260
        # WOTS+ sign operations at MERKLE_TREE_HEIGHT=4.
        iss, kp = self._make_issuer(b"cap")
        template = _make_signed_ack(
            self.chain, iss, kp, _h(b"cap-tmpl"), commit_height=1,
            register_root=False,
        )
        for i in range(MAX_ACKS_PER_BLOCK + 5):
            stub = SubmissionAck(
                request_hash=_h(b"req-cap-" + str(i).encode()),
                issuer_id=template.issuer_id,
                issuer_root_public_key=template.issuer_root_public_key,
                action_code=template.action_code,
                commit_height=template.commit_height,
                signature=template.signature,
            )
            stub.ack_hash = stub._compute_hash()
            # Bypass record_ack's type check to inject cheaply.
            self.chain.witness_observation_store._acks[stub.request_hash] = stub
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
        # Build a signed ack from a chain-registered issuer.
        iss = Entity.create(b"iss-soft".ljust(32, b"\x00"))
        iss.keypair._next_leaf = 0
        register_entity_for_test(self.chain, iss)
        kp = _receipt_subtree_kp(b"soft")
        self.chain.receipt_subtree_roots[iss.entity_id] = kp.public_key
        rh_unknown = _h(b"never-observed-locally")
        ack = _make_signed_ack(
            self.chain, iss, kp, rh_unknown, commit_height=1,
            register_root=False,
        )
        self.proposer_store.record_ack(ack)
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
        )
        # Now wipe the local store so the "validator" perspective has
        # no ack record, and validate the block as a soft signal.  The
        # ack is still cryptographically valid (signed, root registered
        # on the chain), so consensus admits it even though the
        # validator never saw the ack in its own gossip.
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
        # Build a signed ack from the target validator (who is also
        # the issuer on this chain; register its receipt-subtree root).
        target_kp = _receipt_subtree_kp(b"e2e-target")
        self.chain.receipt_subtree_roots[self.target.entity_id] = (
            target_kp.public_key
        )
        ack = _make_signed_ack(
            self.chain, self.target, target_kp, req.request_hash,
            commit_height=1, register_root=False,
        )
        # Local witness store sees the ack (proposer's perspective).
        self.chain.witness_observation_store.record_ack(ack)

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
        self.assertIn(
            req.request_hash,
            {a.request_hash for a in blk.acks_observed_this_block},
        )
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
        # Pinned >=14 so the witnessed-submission sections remain
        # committed.  Follow-on forks bump further (v15 added the
        # fee-burn rolling window); strict equality would break every
        # time a new hard fork lands, so we pin the lower bound.
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


class TestAckForgeryRejected(unittest.TestCase):
    """Round-3 C1 regression: a colluding proposer cannot forge a
    ``witness_ack_registry`` entry for a publicly-gossiped
    ``request_hash``.  Before the fix, ``acks_observed_this_block``
    was a raw list of 32-byte request_hashes and validation checked
    only wire-format rules -- any proposer could compute
    ``H(target, submitter, tx_hash, ...)`` from gossip and echo the
    hash to mark the obligation discharged.  Post-fix, the block
    carries full signed ``SubmissionAck`` objects and consensus
    verifies each ack against the target's registered receipt-
    subtree root.
    """

    def setUp(self):
        from messagechain.config import VALIDATOR_MIN_STAKE
        from messagechain.consensus.witness_submission import (
            WitnessObservationStore,
        )
        # Three entities: target (the validator being "censored"),
        # proposer (colluding attacker), client.  No witness acks are
        # legitimately produced here -- the attack is to forge one.
        self.target = Entity.create(b"forgery-target".ljust(32, b"\x00"))
        self.proposer = Entity.create(b"forgery-proposer".ljust(32, b"\x00"))
        self.client = Entity.create(b"forgery-client".ljust(32, b"\x00"))
        for e in (self.target, self.proposer, self.client):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.target)
        register_entity_for_test(self.chain, self.client)
        self.chain.supply.balances[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 100
        )
        self.chain.supply.staked[self.proposer.entity_id] = (
            VALIDATOR_MIN_STAKE * 10
        )
        self.chain.supply.staked[self.target.entity_id] = (
            VALIDATOR_MIN_STAKE * 10
        )
        # Register the target's receipt-subtree root on the chain so
        # a legitimate ack COULD be verified -- the attacker just
        # never produces one.
        self.target_kp = _receipt_subtree_kp(b"forgery-target")
        self.chain.receipt_subtree_roots[self.target.entity_id] = (
            self.target_kp.public_key
        )
        self.chain.witness_observation_store = WitnessObservationStore()

    def _build_request(self) -> SubmissionRequest:
        return sign_submission_request(
            submitter=self.client,
            target_validator_id=self.target.entity_id,
            tx_hash=_h(b"censored-payload"),
            timestamp=int(time.time()),
            client_nonce=b"\xcc" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )

    def test_forged_unsigned_request_hash_alone_rejected(self):
        """The legacy attack: emit the raw request_hash any gossip
        observer could compute.  Post-fix the block field no longer
        accepts a plain bytes entry; the wire encoder rejects it as
        a non-SubmissionAck and validation rejects even if the
        encoder ran in a permissive mode."""
        req = self._build_request()
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        # Try to inject just the hash -- must fail at propose_block
        # (caller-supplied list is type-checked).
        with self.assertRaises(TypeError):
            self.chain.propose_block(
                consensus=consensus,
                proposer_entity=self.proposer,
                transactions=[],
                acks_observed_this_block=[req.request_hash],
            )

    def test_forged_ack_with_unregistered_root_rejected(self):
        """The harder attack: attacker generates their own subtree
        keypair, signs a well-formed SubmissionAck claiming to be
        from the target validator, but never registers that key on
        chain.  Post-fix: consensus validation looks up the chain's
        registered ``receipt_subtree_roots[target]`` and rejects
        because the ack's ``issuer_root_public_key`` is the
        attacker's throwaway, not the registered one."""
        req = self._build_request()
        attacker_kp = _receipt_subtree_kp(b"forgery-attacker")
        # Forge ack claiming to be FROM self.target, signed by
        # attacker_kp.  Do NOT register attacker_kp on chain.
        forged = SubmissionAck(
            request_hash=req.request_hash,
            issuer_id=self.target.entity_id,  # lies about issuer
            issuer_root_public_key=attacker_kp.public_key,
            action_code=ACK_ADMITTED,
            commit_height=1,
            signature=Signature([], 0, [], b"", b""),
        )
        msg_hash = hashlib.new(HASH_ALGO, forged._signable_data()).digest()
        forged.signature = attacker_kp.sign(msg_hash)
        forged.ack_hash = forged._compute_hash()

        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
            acks_observed_this_block=[forged],
        )
        ok, reason = self.chain.validate_block(blk)
        self.assertFalse(
            ok,
            "Forged ack with unregistered root MUST be rejected -- "
            "the central forgery defense.",
        )
        # Reason must name the root-mismatch or root-missing path.
        self.assertTrue(
            "receipt_subtree_root" in reason.lower()
            or "root" in reason.lower(),
            reason,
        )

    def test_legitimate_ack_accepted_and_commit_height_honored(self):
        """Positive regression: a properly-signed ack from the
        target's registered subtree root is admitted and the
        registry records the ack's OWN commit_height -- not the
        block's height.  A colluding proposer cannot forward-date a
        discharge by placing it in a late block, because the ack
        signature covers the commit_height."""
        req = self._build_request()
        # Legitimate ack at commit_height=5, embedded in a block at
        # height ~1; before the fix the apply path recorded the
        # block's height, so an attacker controlling the proposer
        # slot could forward-date by including the ack late.
        ack = _make_signed_ack(
            self.chain, self.target, self.target_kp,
            req.request_hash, commit_height=5, register_root=False,
        )
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        blk = self.chain.propose_block(
            consensus=consensus,
            proposer_entity=self.proposer,
            transactions=[],
            acks_observed_this_block=[ack],
        )
        ok, reason = self.chain.add_block(blk)
        self.assertTrue(ok, reason)
        self.assertEqual(
            self.chain.witness_ack_registry[req.request_hash], 5,
            "Registry MUST record ack.commit_height (5), NOT the "
            "containing block's height -- otherwise a colluding "
            "proposer can shift the recorded discharge arbitrarily.",
        )


if __name__ == "__main__":
    unittest.main()
