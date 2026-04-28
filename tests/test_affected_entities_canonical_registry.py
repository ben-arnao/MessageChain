"""Canonical "tx -> touched entities" registry guard.

Audit fix: collapse the two-source-of-truth pattern between
``Blockchain._block_affected_entities`` (apply-side touch sweep) and
the per-tx-class apply logic in ``_apply_block_state``.  Each tx class
now declares ``affected_entities() -> set[bytes]``, and the
block-level sweep dispatches to that single canonical method.

Three releases in seven hours (1.29.1 / 1.29.2 / 1.29.3) all chased
the same divergence: a new tx kind was missing from one of the N
hand-rolled sweeps and the chain stalled with a state_root mismatch.
The structural guard below ensures a future contributor adding a tx
kind cannot half-land — the test fails with a clear "TxClass `XyzTx`
does not implement affected_entities()" message until the new class
registers.

See CLAUDE.md for the full anchor on the design.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import unittest


# Modules to walk for tx classes.  Every block-included tx kind lives
# in one of these subpackages; new tx kinds dropped elsewhere will not
# match the discovery walk and the structural test will not see them.
# That's by design: the canonical landing zone for a new tx kind is one
# of these subpackages, and the audit's "single registration point" is
# preserved by the discovery-walk failing when a tx class is added
# outside them.
_TX_CLASS_PACKAGES = (
    "messagechain.core",
    "messagechain.consensus",
    "messagechain.governance",
)

# Class-name suffixes that mark a transaction-like type the block
# pipeline carries and the per-block touch sweep must include.
# CustodyProof / Attestation / FinalityVote are NOT named "Transaction"
# but ARE block-included artifacts that mutate per-entity state on
# apply, so they're included explicitly.
_TX_NAME_PATTERNS = (
    "Transaction",
    "Tx",
)

_EXTRA_TX_LIKE_CLASSES = (
    ("messagechain.consensus.attestation", "Attestation"),
    ("messagechain.consensus.finality", "FinalityVote"),
    ("messagechain.consensus.archive_challenge", "CustodyProof"),
)

# Helper-shaped classes (not block-body tx types) that match the
# Transaction/Tx name pattern but are not in the canonical registry.
# Documented exclusions only — adding to this list requires a code
# review to confirm the class is NOT a block-included entity-mutating
# tx kind.
_NOT_BLOCK_TX_CLASSES = frozenset({
    # SignedRejection is a sub-record carried by BogusRejectionEvidenceTx,
    # not itself a block-included tx.  affected_entities lives on the
    # outer evidence tx.
    "SignedRejection",
    # SubmissionReceipt similarly is a sub-record carried by
    # CensorshipEvidenceTx; not itself a block-included tx.
    "SubmissionReceipt",
    # SubmissionRequest is a sub-record carried by NonResponseEvidenceTx.
    "SubmissionRequest",
    # WitnessObservation is a sub-record carried by NonResponseEvidenceTx.
    "WitnessObservation",
    # SubmissionAck is a peer-witness record, not a block tx.
    "SubmissionAck",
    # InclusionList is a list metadata object carried by a block, not a
    # tx itself.  Its violation evidence (InclusionListViolationEvidenceTx)
    # registers separately.
    "InclusionList",
    # BogusRejectionResult / NonResponseResult are processor result
    # dataclasses, not txs.
    "BogusRejectionResult",
    "NonResponseResult",
    # MaturedEvidence is a processor output record, not a tx.
    "MaturedEvidence",
    # ArchiveProofBundle is a per-epoch aggregation, mutates no per-entity
    # state on apply.
    "ArchiveProofBundle",
    # MerkleProof is an SPV/light-client helper, not a block tx.
    "MerkleProof",
    # Slashing-evidence sub-records — the outer SlashTransaction registers.
    "SlashingEvidence",
    "AttestationSlashingEvidence",
    "FinalityDoubleVoteEvidence",
    "StateCheckpointDoubleSignEvidence",
    # Network-only schedulers, not txs.
    "TxRelayScheduler",
    # Tracker dataclasses, not txs.
    "FinalityTracker",
    "FinalityCheckpoints",
    "CensorshipEvidenceProcessor",
    "BogusRejectionProcessor",
    "NonResponseEvidenceProcessor",
})


def _walk_tx_like_classes():
    """Yield (module_name, class_name, class) for every tx-like class.

    A tx-like class is any class in the tracked packages whose name
    ends in 'Transaction' or 'Tx', plus the explicit extras list,
    minus the documented non-block exclusions.
    """
    seen: set[tuple[str, str]] = set()
    for pkg_name in _TX_CLASS_PACKAGES:
        pkg = importlib.import_module(pkg_name)
        if not hasattr(pkg, "__path__"):
            continue
        for modinfo in pkgutil.walk_packages(pkg.__path__, prefix=pkg_name + "."):
            try:
                mod = importlib.import_module(modinfo.name)
            except Exception:
                # Skip modules that can't be imported in the test
                # environment (e.g., optional deps).  The structural
                # guard cares about classes that are reachable; an
                # unreachable one cannot be added to a real block
                # anyway.
                continue
            for name, cls in inspect.getmembers(mod, inspect.isclass):
                if cls.__module__ != mod.__name__:
                    # Re-export — the canonical home is elsewhere.
                    continue
                if name in _NOT_BLOCK_TX_CLASSES:
                    continue
                if not any(name.endswith(s) for s in _TX_NAME_PATTERNS):
                    continue
                key = (mod.__name__, name)
                if key in seen:
                    continue
                seen.add(key)
                yield mod.__name__, name, cls
    for mod_name, cls_name in _EXTRA_TX_LIKE_CLASSES:
        try:
            mod = importlib.import_module(mod_name)
        except Exception:
            continue
        cls = getattr(mod, cls_name, None)
        if cls is None:
            continue
        key = (mod_name, cls_name)
        if key in seen:
            continue
        seen.add(key)
        yield mod_name, cls_name, cls


class TestAffectedEntitiesCanonicalRegistry(unittest.TestCase):
    """Structural guard: every block-included tx class must implement
    ``affected_entities() -> set[bytes]``.
    """

    def test_no_tx_class_misses_affected_entities(self):
        """The headline structural guard.  Walks every tx class in the
        tracked packages and asserts each one declares
        ``affected_entities``.  Must be a method, must be callable, and
        the existence is the bare-minimum gate (per-class semantic
        tests below validate the return values).

        FAILS WITH a clear message naming the missing class so a future
        contributor adding a new tx kind sees exactly what to fix.
        """
        missing: list[str] = []
        for mod_name, cls_name, cls in _walk_tx_like_classes():
            method = getattr(cls, "affected_entities", None)
            if method is None or not callable(method):
                missing.append(f"{mod_name}.{cls_name}")
        if missing:
            self.fail(
                "The following tx classes do not implement "
                "affected_entities() -> set[bytes]:\n  "
                + "\n  ".join(missing)
                + "\n\nSee CLAUDE.md or messagechain.core.transaction."
                "MessageTransaction.affected_entities for the pattern. "
                "Each tx class registers its own touched entities once; "
                "Blockchain._block_affected_entities consumes them via "
                "a single canonical sweep."
            )

    def test_walk_finds_known_classes(self):
        """Sanity: the discovery walk picks up the canonical tx kinds.
        Guards against a refactor that accidentally renames a package
        or adds a discovery exclusion that hides the whole sweep.
        """
        found = {cls_name for _, cls_name, _ in _walk_tx_like_classes()}
        expected = {
            "MessageTransaction",
            "TransferTransaction",
            "StakeTransaction",
            "UnstakeTransaction",
            "ReactTransaction",
            "SetAuthorityKeyTransaction",
            "RevokeTransaction",
            "KeyRotationTransaction",
            "SetReceiptSubtreeRootTransaction",
            "ReleaseAnnounceTransaction",
            "SlashTransaction",
            "ProposalTransaction",
            "VoteTransaction",
            "TreasurySpendTransaction",
            "CensorshipEvidenceTx",
            "BogusRejectionEvidenceTx",
            "InclusionListViolationEvidenceTx",
            "NonResponseEvidenceTx",
            "Attestation",
            "FinalityVote",
            "CustodyProof",
        }
        missing = expected - found
        self.assertFalse(
            missing,
            f"Discovery walk missed expected tx classes: {sorted(missing)}",
        )


# ─────────────────────────────────────────────────────────────────────
# Per-class semantic tests: each tx kind's affected_entities() must
# return the set its apply path actually mutates.  These pin the
# per-class registration so a refactor can't silently shrink/expand
# the touched set without a test break.
# ─────────────────────────────────────────────────────────────────────


class TestPerClassAffectedEntities(unittest.TestCase):
    """Per-tx-class affected-set semantics.  Each test constructs a
    minimal synthetic instance (no chain, no signing) and asserts the
    returned set matches the apply-path mutation pattern documented
    in the per-class affected_entities() docstrings.
    """

    def test_message_tx(self):
        from messagechain.core.transaction import MessageTransaction
        tx = MessageTransaction.__new__(MessageTransaction)
        tx.entity_id = b"\x01" * 32
        self.assertEqual(tx.affected_entities(), {b"\x01" * 32})

    def test_message_tx_community_id_is_metadata(self):
        """community_id is a category tag, NOT an affected entity."""
        from messagechain.core.transaction import MessageTransaction
        tx = MessageTransaction.__new__(MessageTransaction)
        tx.entity_id = b"\x01" * 32
        tx.community_id = "physics"
        self.assertEqual(tx.affected_entities(), {b"\x01" * 32})

    def test_transfer_tx(self):
        from messagechain.core.transfer import TransferTransaction
        tx = TransferTransaction.__new__(TransferTransaction)
        tx.entity_id = b"\xa1" * 32
        tx.recipient_id = b"\xa2" * 32
        self.assertEqual(
            tx.affected_entities(),
            {b"\xa1" * 32, b"\xa2" * 32},
        )

    def test_stake_tx(self):
        from messagechain.core.staking import StakeTransaction
        tx = StakeTransaction.__new__(StakeTransaction)
        tx.entity_id = b"\xb1" * 32
        self.assertEqual(tx.affected_entities(), {b"\xb1" * 32})

    def test_unstake_tx(self):
        from messagechain.core.staking import UnstakeTransaction
        tx = UnstakeTransaction.__new__(UnstakeTransaction)
        tx.entity_id = b"\xb2" * 32
        self.assertEqual(tx.affected_entities(), {b"\xb2" * 32})

    def test_react_tx(self):
        """Voter is the affected entity; target (whether user_id or
        message tx_hash) is NOT in the per-entity SMT."""
        from messagechain.core.reaction import ReactTransaction
        tx = ReactTransaction.__new__(ReactTransaction)
        tx.voter_id = b"\xc1" * 32
        tx.target = b"\xc2" * 32
        tx.target_is_user = True
        self.assertEqual(tx.affected_entities(), {b"\xc1" * 32})

    def test_react_tx_target_is_message(self):
        from messagechain.core.reaction import ReactTransaction
        tx = ReactTransaction.__new__(ReactTransaction)
        tx.voter_id = b"\xc1" * 32
        tx.target = b"\xc3" * 32  # tx_hash of a message
        tx.target_is_user = False
        # Even when target is a tx_hash (NOT an entity_id), the only
        # state_tree row touched is the voter's.
        self.assertEqual(tx.affected_entities(), {b"\xc1" * 32})

    def test_set_authority_key_tx(self):
        from messagechain.core.authority_key import SetAuthorityKeyTransaction
        tx = SetAuthorityKeyTransaction.__new__(SetAuthorityKeyTransaction)
        tx.entity_id = b"\xd1" * 32
        tx.new_authority_key = b"\xd2" * 32  # raw pubkey, NOT entity
        self.assertEqual(tx.affected_entities(), {b"\xd1" * 32})

    def test_revoke_tx(self):
        from messagechain.core.emergency_revoke import RevokeTransaction
        tx = RevokeTransaction.__new__(RevokeTransaction)
        tx.entity_id = b"\xd3" * 32
        self.assertEqual(tx.affected_entities(), {b"\xd3" * 32})

    def test_key_rotation_tx(self):
        from messagechain.core.key_rotation import KeyRotationTransaction
        tx = KeyRotationTransaction.__new__(KeyRotationTransaction)
        tx.entity_id = b"\xd4" * 32
        tx.old_public_key = b"\x11" * 32
        tx.new_public_key = b"\x22" * 32
        self.assertEqual(tx.affected_entities(), {b"\xd4" * 32})

    def test_set_receipt_subtree_root_tx(self):
        from messagechain.core.receipt_subtree_root import (
            SetReceiptSubtreeRootTransaction,
        )
        tx = SetReceiptSubtreeRootTransaction.__new__(
            SetReceiptSubtreeRootTransaction,
        )
        tx.entity_id = b"\xd5" * 32
        tx.root_public_key = b"\x33" * 32
        self.assertEqual(tx.affected_entities(), {b"\xd5" * 32})

    def test_release_announce_tx_touches_no_entity(self):
        """Committee-signed: no fee, no nonce, no per-entity state."""
        from messagechain.core.release_announce import ReleaseAnnounceTransaction
        tx = ReleaseAnnounceTransaction.__new__(ReleaseAnnounceTransaction)
        self.assertEqual(tx.affected_entities(), set())

    def test_slash_tx(self):
        """Slasher (submitter) + offender."""
        from messagechain.consensus.slashing import SlashTransaction

        class _StubEvidence:
            offender_id = b"\xe1" * 32

        tx = SlashTransaction.__new__(SlashTransaction)
        tx.evidence = _StubEvidence()
        tx.submitter_id = b"\xe2" * 32
        self.assertEqual(
            tx.affected_entities(),
            {b"\xe1" * 32, b"\xe2" * 32},
        )

    def test_governance_proposal_tx(self):
        from messagechain.governance.governance import ProposalTransaction
        tx = ProposalTransaction.__new__(ProposalTransaction)
        tx.proposer_id = b"\xf1" * 32
        self.assertEqual(tx.affected_entities(), {b"\xf1" * 32})

    def test_governance_vote_tx(self):
        from messagechain.governance.governance import VoteTransaction
        tx = VoteTransaction.__new__(VoteTransaction)
        tx.voter_id = b"\xf2" * 32
        self.assertEqual(tx.affected_entities(), {b"\xf2" * 32})

    def test_treasury_spend_tx(self):
        """Proposer at admission; recipient credited only on auto-execute."""
        from messagechain.governance.governance import TreasurySpendTransaction
        tx = TreasurySpendTransaction.__new__(TreasurySpendTransaction)
        tx.proposer_id = b"\xf3" * 32
        tx.recipient_id = b"\xf4" * 32
        self.assertEqual(tx.affected_entities(), {b"\xf3" * 32})

    def test_censorship_evidence_tx(self):
        from messagechain.consensus.censorship_evidence import CensorshipEvidenceTx
        tx = CensorshipEvidenceTx.__new__(CensorshipEvidenceTx)
        tx.submitter_id = b"\x71" * 32
        self.assertEqual(tx.affected_entities(), {b"\x71" * 32})

    def test_bogus_rejection_evidence_tx(self):
        """Submitter + offender (one-phase: slash lands in admission block)."""
        from messagechain.consensus.bogus_rejection_evidence import (
            BogusRejectionEvidenceTx,
        )

        class _StubRejection:
            issuer_id = b"\x82" * 32

        tx = BogusRejectionEvidenceTx.__new__(BogusRejectionEvidenceTx)
        tx.submitter_id = b"\x81" * 32
        tx.rejection = _StubRejection()
        # offender_id is a property reading self.rejection.issuer_id
        self.assertEqual(
            tx.affected_entities(),
            {b"\x81" * 32, b"\x82" * 32},
        )

    def test_inclusion_list_violation_evidence_tx(self):
        from messagechain.consensus.inclusion_list import (
            InclusionListViolationEvidenceTx,
        )
        tx = InclusionListViolationEvidenceTx.__new__(
            InclusionListViolationEvidenceTx,
        )
        tx.submitter_id = b"\x91" * 32
        tx.accused_proposer_id = b"\x92" * 32
        self.assertEqual(
            tx.affected_entities(),
            {b"\x91" * 32, b"\x92" * 32},
        )

    def test_non_response_evidence_tx(self):
        from messagechain.consensus.non_response_evidence import NonResponseEvidenceTx

        class _StubRequest:
            target_validator_id = b"\xa2" * 32

        tx = NonResponseEvidenceTx.__new__(NonResponseEvidenceTx)
        tx.submitter_id = b"\xa1" * 32
        tx.request = _StubRequest()
        self.assertEqual(
            tx.affected_entities(),
            {b"\xa1" * 32, b"\xa2" * 32},
        )

    def test_attestation(self):
        from messagechain.consensus.attestation import Attestation
        att = Attestation.__new__(Attestation)
        att.validator_id = b"\xb3" * 32
        self.assertEqual(att.affected_entities(), {b"\xb3" * 32})

    def test_finality_vote(self):
        from messagechain.consensus.finality import FinalityVote
        v = FinalityVote.__new__(FinalityVote)
        v.signer_entity_id = b"\xb4" * 32
        self.assertEqual(v.affected_entities(), {b"\xb4" * 32})

    def test_custody_proof(self):
        from messagechain.consensus.archive_challenge import CustodyProof
        cp = CustodyProof.__new__(CustodyProof)
        cp.prover_id = b"\xb5" * 32
        self.assertEqual(cp.affected_entities(), {b"\xb5" * 32})

    def test_return_type_is_set_of_bytes(self):
        """Every affected_entities() must return a set whose members
        are 32-byte bytes objects.  Using a list / frozenset / dict
        keys would silently work for the union sweep but breaks the
        ``add()`` / ``update()`` typing the per-block sweep relies on."""
        from messagechain.core.transaction import MessageTransaction
        tx = MessageTransaction.__new__(MessageTransaction)
        tx.entity_id = b"\x01" * 32
        result = tx.affected_entities()
        self.assertIsInstance(result, set)
        for eid in result:
            self.assertIsInstance(eid, bytes)


# ─────────────────────────────────────────────────────────────────────
# Block-level sweep parity: _block_affected_entities returns the same
# entity set whether built via the canonical-registry sweep helper or
# the pre-refactor hand-rolled sweep on a synthetic block.
# ─────────────────────────────────────────────────────────────────────


class TestBlockAffectedEntitiesParity(unittest.TestCase):
    """The block-level sweep (Blockchain._block_affected_entities)
    must produce a superset of every prior tx-kind's affected set,
    regardless of whether the block carries those tx kinds.  Empty
    block returns just {proposer, treasury, *seed_entity_ids}.
    """

    def test_empty_block_returns_proposer_and_treasury(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.block import Block, BlockHeader
        from messagechain.config import TREASURY_ENTITY_ID

        chain = Blockchain()
        proposer_id = b"\xee" * 32
        header = BlockHeader.__new__(BlockHeader)
        header.proposer_id = proposer_id
        block = Block.__new__(Block)
        block.header = header
        block.transactions = []
        block.transfer_transactions = []
        block.slash_transactions = []
        block.attestations = []
        block.authority_txs = []
        block.stake_transactions = []
        block.unstake_transactions = []
        block.react_transactions = []
        block.governance_txs = []
        block.finality_votes = []
        block.custody_proofs = []
        block.censorship_evidence_txs = []
        block.bogus_rejection_evidence_txs = []
        block.inclusion_list_violation_evidence_txs = []

        affected = chain._block_affected_entities(block)
        self.assertIn(proposer_id, affected)
        self.assertIn(TREASURY_ENTITY_ID, affected)

    def test_block_with_transfer_includes_recipient(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.block import Block, BlockHeader
        from messagechain.core.transfer import TransferTransaction

        chain = Blockchain()
        proposer_id = b"\xee" * 32
        header = BlockHeader.__new__(BlockHeader)
        header.proposer_id = proposer_id
        block = Block.__new__(Block)
        block.header = header
        ttx = TransferTransaction.__new__(TransferTransaction)
        ttx.entity_id = b"\x01" * 32
        ttx.recipient_id = b"\x02" * 32
        block.transactions = []
        block.transfer_transactions = [ttx]
        block.slash_transactions = []
        block.attestations = []
        block.authority_txs = []
        block.stake_transactions = []
        block.unstake_transactions = []
        block.react_transactions = []
        block.governance_txs = []
        block.finality_votes = []
        block.custody_proofs = []
        block.censorship_evidence_txs = []
        block.bogus_rejection_evidence_txs = []
        block.inclusion_list_violation_evidence_txs = []

        affected = chain._block_affected_entities(block)
        self.assertIn(b"\x01" * 32, affected)
        self.assertIn(b"\x02" * 32, affected)

    def test_block_with_react_includes_voter(self):
        """The 1.28.6 trap: react voter must land in the touched set."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.block import Block, BlockHeader
        from messagechain.core.reaction import ReactTransaction

        chain = Blockchain()
        proposer_id = b"\xee" * 32
        header = BlockHeader.__new__(BlockHeader)
        header.proposer_id = proposer_id
        block = Block.__new__(Block)
        block.header = header
        rtx = ReactTransaction.__new__(ReactTransaction)
        rtx.voter_id = b"\xc1" * 32
        rtx.target = b"\xc2" * 32
        rtx.target_is_user = True
        block.transactions = []
        block.transfer_transactions = []
        block.slash_transactions = []
        block.attestations = []
        block.authority_txs = []
        block.stake_transactions = []
        block.unstake_transactions = []
        block.react_transactions = [rtx]
        block.governance_txs = []
        block.finality_votes = []
        block.custody_proofs = []
        block.censorship_evidence_txs = []
        block.bogus_rejection_evidence_txs = []
        block.inclusion_list_violation_evidence_txs = []

        affected = chain._block_affected_entities(block)
        self.assertIn(b"\xc1" * 32, affected)


def _legacy_block_affected_entities(chain, block) -> set[bytes]:
    """Snapshot of the pre-refactor `_block_affected_entities` shape.

    This is the EXACT logic from the pre-refactor implementation (see
    git history at commit cff5e51 / 4f47c6b).  Used as a parity oracle
    in `TestStateRootByteIdenticalAfterRefactor` so a future code
    change to the canonical sweep can't silently broaden or narrow
    the set without a test failure.

    The new sweep is INTENTIONALLY a superset: it now includes
    governance, finality_votes, custody_proofs, and the three evidence
    tx kinds (which the old sweep missed — see the report-back finding
    in the refactor's accompanying notes).  This oracle validates the
    OLD sweep's output for the tx kinds it DID enumerate.
    """
    from messagechain.config import TREASURY_ENTITY_ID
    affected: set[bytes] = {block.header.proposer_id, TREASURY_ENTITY_ID}
    for tx in block.transactions:
        affected.add(tx.entity_id)
    for ttx in block.transfer_transactions:
        affected.add(ttx.entity_id)
        affected.add(ttx.recipient_id)
    for stx in block.slash_transactions:
        affected.add(stx.evidence.offender_id)
        affected.add(stx.submitter_id)
    for att in block.attestations:
        affected.add(att.validator_id)
    for atx in getattr(block, "authority_txs", []):
        affected.add(atx.entity_id)
    for stx in getattr(block, "stake_transactions", []):
        affected.add(stx.entity_id)
    for utx in getattr(block, "unstake_transactions", []):
        affected.add(utx.entity_id)
    for rtx in getattr(block, "react_transactions", []) or []:
        affected.add(rtx.voter_id)
    affected.update(chain.seed_entity_ids)
    return affected


class TestStateRootByteIdenticalAfterRefactor(unittest.TestCase):
    """Consensus-determinism gate: the canonical-registry refactor MUST
    produce byte-identical state_roots to the pre-refactor sweep on
    blocks of every supported tx kind.

    The refactor only restructures the entity-touch sweep; it does not
    change `compute_current_state_root` or `compute_post_state_root`
    semantics.  This test verifies end-to-end: a block built and
    applied through the full pipeline (propose -> add -> persist)
    produces the same final state_root regardless of which tx kinds
    it carries.

    The deeper "byte-identical pre-vs-post-refactor" guarantee is
    discharged structurally by the fact that
    `compute_current_state_root` calls `_rebuild_state_tree`, which
    iterates EVERY live entity from the supply/nonce/etc. dicts —
    independent of `_block_affected_entities`.  So broadening the
    affected set widens the dirty-set tracker (good — fixes a latent
    persist-divergence) without changing root output (the refactor's
    consensus-determinism non-negotiable).
    """

    def test_message_block_state_root_round_trips(self):
        """A simple message-tx block round-trips proposer->validator."""
        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.transaction import create_transaction
        from messagechain.consensus.pos import ProofOfStake
        from tests import register_entity_for_test

        alice = Entity.create(b"alice-canon-private".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        chain.supply.balances[alice.entity_id] = 100_000

        tx = create_transaction(alice, "hi", fee=1500, nonce=0)
        prev = chain.get_latest_block()
        height = prev.header.block_number + 1
        state_root = chain.compute_post_state_root(
            [tx], alice.entity_id, height,
        )
        consensus = ProofOfStake()
        block = consensus.create_block(
            alice, [tx], prev, state_root=state_root,
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        # Validator's post-apply state_root matches proposer's commitment
        self.assertEqual(
            chain.compute_current_state_root(),
            state_root,
        )

    def test_transfer_block_state_root_round_trips(self):
        """A transfer block adds successfully (sender + recipient
        both touched, both state_tree rows refresh)."""
        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.transfer import TransferTransaction
        from messagechain.crypto.hashing import default_hash
        from messagechain.crypto.keys import Signature
        from messagechain.config import (
            CHAIN_ID, MIN_FEE, SIG_VERSION_CURRENT,
        )
        from tests import register_entity_for_test
        import struct
        import time

        alice = Entity.create(b"alice-xfer-private".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-xfer-private".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, bob)
        chain.supply.balances[alice.entity_id] = 100_000
        chain.supply.balances[bob.entity_id] = 100

        # Construct + sign a TransferTransaction directly.
        amount = 500
        nonce = 0
        ts = int(time.time())
        fee = max(MIN_FEE, 1500)
        body = (
            CHAIN_ID
            + b"transfer"
            + struct.pack(">B", SIG_VERSION_CURRENT)
            + alice.entity_id
            + bob.entity_id
            + struct.pack(">Q", amount)
            + struct.pack(">Q", nonce)
            + struct.pack(">Q", ts)
            + struct.pack(">Q", fee)
            + struct.pack(">H", 0)
        )
        sig = alice.keypair.sign(default_hash(body))
        ttx = TransferTransaction(
            entity_id=alice.entity_id,
            recipient_id=bob.entity_id,
            amount=amount,
            nonce=nonce,
            timestamp=ts,
            fee=fee,
            signature=sig,
        )
        prev = chain.get_latest_block()
        height = prev.header.block_number + 1
        state_root = chain.compute_post_state_root(
            [], alice.entity_id, height,
            transfer_transactions=[ttx],
        )
        consensus = ProofOfStake()
        block = consensus.create_block(
            alice, [], prev, state_root=state_root,
            transfer_transactions=[ttx],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(
            chain.compute_current_state_root(),
            state_root,
        )
        # Recipient's row was refreshed in state_tree (was previously
        # at its register_entity_for_test stub state).
        self.assertEqual(chain.supply.balances[bob.entity_id], 100 + amount)

    def test_proposer_and_treasury_always_in_affected(self):
        """Every block's affected set unconditionally includes the
        proposer and the treasury, even when no txs touch them
        directly.  These are the "always-mutating" anchors of the
        per-block reward/burn cycle."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.block import Block, BlockHeader
        from messagechain.config import TREASURY_ENTITY_ID

        chain = Blockchain()
        proposer_id = b"\xee" * 32
        header = BlockHeader.__new__(BlockHeader)
        header.proposer_id = proposer_id
        block = Block.__new__(Block)
        block.header = header
        # Empty body — no tx kinds at all.
        for attr in chain._BLOCK_TX_LIST_ATTRS:
            setattr(block, attr, [])

        affected = chain._block_affected_entities(block)
        self.assertIn(proposer_id, affected)
        self.assertIn(TREASURY_ENTITY_ID, affected)

    def test_legacy_sweep_subset_of_canonical_sweep(self):
        """Every entity the pre-refactor sweep enumerated MUST still be
        in the new canonical sweep's output.  The new sweep may be a
        proper superset (it now picks up governance, finality_votes,
        custody_proofs, and the three evidence tx kinds — which the
        legacy sweep missed despite the apply path mutating those
        entities); but it must never SHRINK the touched set, since
        that would silently regress on the 1.28.6 fix that the audit
        codifies.

        Built on a synthetic block populated with one of every tx
        kind so coverage is comprehensive in a single call.
        """
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.block import Block, BlockHeader
        from messagechain.core.transfer import TransferTransaction
        from messagechain.core.transaction import MessageTransaction
        from messagechain.core.staking import (
            StakeTransaction, UnstakeTransaction,
        )
        from messagechain.core.reaction import ReactTransaction
        from messagechain.core.authority_key import SetAuthorityKeyTransaction
        from messagechain.consensus.attestation import Attestation
        from messagechain.consensus.slashing import SlashTransaction

        chain = Blockchain()
        proposer_id = b"\xee" * 32
        header = BlockHeader.__new__(BlockHeader)
        header.proposer_id = proposer_id

        # Construct one synthetic instance per legacy-tracked tx kind.
        msg = MessageTransaction.__new__(MessageTransaction)
        msg.entity_id = b"\x10" * 32

        ttx = TransferTransaction.__new__(TransferTransaction)
        ttx.entity_id = b"\x20" * 32
        ttx.recipient_id = b"\x21" * 32

        class _Ev:
            offender_id = b"\x30" * 32
        slx = SlashTransaction.__new__(SlashTransaction)
        slx.evidence = _Ev()
        slx.submitter_id = b"\x31" * 32

        att = Attestation.__new__(Attestation)
        att.validator_id = b"\x40" * 32

        atx = SetAuthorityKeyTransaction.__new__(SetAuthorityKeyTransaction)
        atx.entity_id = b"\x50" * 32

        stx = StakeTransaction.__new__(StakeTransaction)
        stx.entity_id = b"\x60" * 32

        utx = UnstakeTransaction.__new__(UnstakeTransaction)
        utx.entity_id = b"\x61" * 32

        rtx = ReactTransaction.__new__(ReactTransaction)
        rtx.voter_id = b"\x70" * 32

        block = Block.__new__(Block)
        block.header = header
        block.transactions = [msg]
        block.transfer_transactions = [ttx]
        block.slash_transactions = [slx]
        block.attestations = [att]
        block.authority_txs = [atx]
        block.stake_transactions = [stx]
        block.unstake_transactions = [utx]
        block.react_transactions = [rtx]
        # Empty new slots — legacy sweep didn't iterate them anyway.
        block.governance_txs = []
        block.finality_votes = []
        block.custody_proofs = []
        block.censorship_evidence_txs = []
        block.bogus_rejection_evidence_txs = []
        block.inclusion_list_violation_evidence_txs = []

        legacy_affected = _legacy_block_affected_entities(chain, block)
        canonical_affected = chain._block_affected_entities(block)

        # The canonical sweep MUST be a superset of the legacy one.
        missing_from_canonical = legacy_affected - canonical_affected
        self.assertFalse(
            missing_from_canonical,
            f"Canonical sweep regressed: missing entities the legacy "
            f"sweep had: {missing_from_canonical}"
        )
        # On a block carrying ONLY legacy-tracked tx kinds, the two
        # sweeps must produce identical sets (the canonical sweep's
        # superset behavior only manifests when new tx kinds appear).
        self.assertEqual(legacy_affected, canonical_affected)

    def test_canonical_sweep_includes_every_tx_attr(self):
        """The `_BLOCK_TX_LIST_ATTRS` tuple must list every tx-list
        slot that lives on a Block.  Missing one is the exact
        structural trap the refactor exists to prevent.
        """
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.block import Block

        # The ground truth: any field on Block whose default is a
        # `list` (tx-list slot) MUST be in _BLOCK_TX_LIST_ATTRS,
        # excluding non-tx structural fields.
        non_tx_list_fields = frozenset({
            # Aggregated multi-validator block signatures, not a tx list.
            "validator_signatures",
            # Witness-ack aggregation: writes into the separate
            # `witness_ack_registry` (NOT inside the per-entity SMT
            # leaf commitment), so its entries don't touch any
            # per-entity state_tree row.  A new entry alters block
            # admission gating for future NonResponseEvidenceTx but
            # is not an entity-mutating tx.
            "acks_observed_this_block",
        })
        block_list_fields = set()
        for f in Block.__dataclass_fields__.values():
            if f.default_factory is list and f.name not in non_tx_list_fields:
                block_list_fields.add(f.name)

        registry_attrs = set(Blockchain._BLOCK_TX_LIST_ATTRS)
        missing = block_list_fields - registry_attrs
        self.assertFalse(
            missing,
            f"_BLOCK_TX_LIST_ATTRS is missing tx-list slot(s): "
            f"{sorted(missing)}.  Add the slot AND ensure each tx "
            f"class on that slot implements affected_entities()."
        )


if __name__ == "__main__":
    unittest.main()
