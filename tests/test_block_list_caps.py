"""Per-block count caps on consensus-included lists.

The fee market only prices user-submitted mempool traffic.  Consensus-
path lists (attestations, validator_signatures, governance_txs,
authority_txs, censorship_evidence_txs) are inserted by the proposer
directly and bypass fee pressure.  Without hard count caps, a
byzantine proposer can stuff a block with unbounded, unpriced,
permanent data.

Pattern mirrors MAX_FINALITY_VOTES_PER_BLOCK (already enforced in
_validate_finality_votes): count rejection BEFORE any cryptographic
verification, so placeholder objects are acceptable for the count
test.  See test_finality.TestFinalityVoteValidation.
test_too_many_votes_rejected for the reference style.
"""
import unittest
from types import SimpleNamespace

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.pos import ProofOfStake
from messagechain.config import (
    MAX_ATTESTATIONS_PER_BLOCK,
    MAX_VALIDATOR_SIGNATURES_PER_BLOCK,
    MAX_GOVERNANCE_TXS_PER_BLOCK,
    MAX_AUTHORITY_TXS_PER_BLOCK,
    MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK,
)
from tests import register_entity_for_test


def _fake_block(**lists):
    """Build a SimpleNamespace that quacks like a Block for count checks.

    All consensus-list attributes default to empty lists; callers
    override only the list under test.  header is a minimal stub with
    the fields the count helper touches.
    """
    defaults = dict(
        attestations=[],
        validator_signatures=[],
        governance_txs=[],
        authority_txs=[],
        censorship_evidence_txs=[],
        custody_proofs=[],
        finality_votes=[],
        transactions=[],
        transfer_transactions=[],
        slash_transactions=[],
        stake_transactions=[],
        unstake_transactions=[],
    )
    defaults.update(lists)
    return SimpleNamespace(
        header=SimpleNamespace(block_number=1, prev_hash=b"\x00" * 32),
        **defaults,
    )


class TestBlockListCaps(unittest.TestCase):
    """A block exceeding any per-list cap is rejected before any
    signature work.  Placeholder objects are fine because rejection
    happens on count alone.
    """

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.consensus = ProofOfStake()

    # ── Attestations ──────────────────────────────────────────────
    def test_too_many_attestations_rejected(self):
        block = _fake_block(
            attestations=[object()] * (MAX_ATTESTATIONS_PER_BLOCK + 1),
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("attestations", reason.lower())

    def test_at_cap_attestations_ok(self):
        block = _fake_block(
            attestations=[object()] * MAX_ATTESTATIONS_PER_BLOCK,
        )
        ok, _ = self.chain._validate_block_list_counts(block)
        self.assertTrue(ok)

    # ── Validator signatures ──────────────────────────────────────
    def test_too_many_validator_signatures_rejected(self):
        block = _fake_block(
            validator_signatures=[object()] * (
                MAX_VALIDATOR_SIGNATURES_PER_BLOCK + 1
            ),
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("validator_signatures", reason.lower())

    # ── Governance txs ────────────────────────────────────────────
    def test_too_many_governance_txs_rejected(self):
        block = _fake_block(
            governance_txs=[object()] * (MAX_GOVERNANCE_TXS_PER_BLOCK + 1),
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("governance", reason.lower())

    # ── Authority txs ─────────────────────────────────────────────
    def test_too_many_authority_txs_rejected(self):
        block = _fake_block(
            authority_txs=[object()] * (MAX_AUTHORITY_TXS_PER_BLOCK + 1),
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("authority", reason.lower())

    # ── Censorship-evidence txs ───────────────────────────────────
    def test_too_many_censorship_evidence_rejected(self):
        block = _fake_block(
            censorship_evidence_txs=[object()] * (
                MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK + 1
            ),
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("censorship", reason.lower())

    # ── Empty block passes all count checks ───────────────────────
    def test_empty_block_ok(self):
        ok, _ = self.chain._validate_block_list_counts(_fake_block())
        self.assertTrue(ok)


class TestCapConstantsSane(unittest.TestCase):
    """Caps must be positive integers.  This is a guard against a
    future edit accidentally setting one to zero or None.
    """

    def test_caps_are_positive_ints(self):
        for name, value in [
            ("MAX_ATTESTATIONS_PER_BLOCK", MAX_ATTESTATIONS_PER_BLOCK),
            ("MAX_VALIDATOR_SIGNATURES_PER_BLOCK",
             MAX_VALIDATOR_SIGNATURES_PER_BLOCK),
            ("MAX_GOVERNANCE_TXS_PER_BLOCK",
             MAX_GOVERNANCE_TXS_PER_BLOCK),
            ("MAX_AUTHORITY_TXS_PER_BLOCK",
             MAX_AUTHORITY_TXS_PER_BLOCK),
            ("MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK",
             MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK),
        ]:
            self.assertIsInstance(value, int, name)
            self.assertGreater(value, 0, name)


if __name__ == "__main__":
    unittest.main()
