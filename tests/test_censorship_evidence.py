"""Tests for censorship evidence — verify, challenge, slash-fire.

Covers:
  * `verify_censorship_evidence` accepts well-formed evidence and
    rejects every known misuse.
  * Stale evidence (past EVIDENCE_EXPIRY_BLOCKS) is rejected.
  * Premature evidence (before grace window ends) is rejected.
  * Evidence for a tx that IS in the grace-window blocks is rejected
    (proof-by-inclusion — the validator already complied).
  * Forged receipts (bad signature) are rejected at the receipt-verify
    stage.
  * Self-indicting evidence: if the user has the tx but it was never
    gossiped, the validator can defend itself by including the tx in
    its own block within the challenge window — tested by showing
    an inclusion-in-window block voids the evidence.
  * Evidence submission itself pays a fee (bounded spam).
  * `compute_slash_amount` returns the documented bps fraction.
"""

import hashlib
import os
import unittest

from messagechain.config import (
    CENSORSHIP_GRACE_BLOCKS,
    CENSORSHIP_SLASH_BPS,
    EVIDENCE_CHALLENGE_BLOCKS,
    EVIDENCE_EXPIRY_BLOCKS,
    EVIDENCE_SUBMISSION_FEE,
    HASH_ALGO,
    SUBMISSION_FEE,
)
from messagechain.consensus.censorship_evidence import (
    CensorshipEvidenceProcessor,
    CensorshipEvidenceTx,
    PendingEvidence,
    compute_slash_amount,
    create_censorship_evidence_tx,
    verify_censorship_evidence,
)
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import (
    SubmissionReceipt,
    sign_receipt,
)


def _sha(tag: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, tag).digest()


class _FakeBlock:
    """Tiny shim for blocks in the window — only `.transactions` matters."""

    def __init__(self, height: int, transactions):
        class _Hdr:
            block_number = height
        self.header = _Hdr()
        self.transactions = list(transactions)


def _make_submitter():
    # Small height to keep test fast.
    return Entity.create(b"submitter".ljust(32, b"\x00"), tree_height=4)


def _make_tx(sender: Entity, nonce: int, fee: int = 300) -> object:
    msg = f"hello-{nonce}"
    return create_transaction(sender, msg, fee=fee, nonce=nonce)


class ComputeSlashAmountTest(unittest.TestCase):
    def test_ten_percent(self):
        self.assertEqual(compute_slash_amount(1_000_000), 100_000)

    def test_zero_stake(self):
        self.assertEqual(compute_slash_amount(0), 0)
        self.assertEqual(compute_slash_amount(-5), 0)

    def test_floor_division_never_overpays(self):
        # 9999 * 1000 / 10000 = 999.9 → floor to 999
        self.assertEqual(compute_slash_amount(9999), 999)

    def test_bps_matches_config(self):
        # Sanity: config says 10% (1000 bps).
        self.assertEqual(CENSORSHIP_SLASH_BPS, 1000)


class EvidenceVerifyTest(unittest.TestCase):
    def setUp(self):
        # Dedicated receipt tree for the accused validator.
        self.receipt_seed = os.urandom(32)
        self.receipt_kp = KeyPair(self.receipt_seed, height=4)
        self.receipt_root = self.receipt_kp.public_key
        # Validator's block-signing identity (separate tree).
        self.validator_kp = KeyPair(os.urandom(32), height=4)
        self.validator_pubkey = self.validator_kp.public_key
        # User submitting evidence.
        self.user = _make_submitter()
        # A tx the user tried to submit and that the validator allegedly
        # dropped — a MessageTransaction signed with MERKLE_TREE_HEIGHT=4.
        self.censored_tx = _make_tx(self.user, nonce=0)

    def _fresh_receipt(self, height: int = 10) -> SubmissionReceipt:
        return sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=self.censored_tx.tx_hash,
            validator_pubkey=self.validator_pubkey,
            received_at_height=height,
            submission_fee_paid=SUBMISSION_FEE,
        )

    def test_valid_evidence_accepted(self):
        r = self._fresh_receipt(height=10)
        ev = create_censorship_evidence_tx(self.user, r, self.censored_tx)
        # 5 empty blocks in the grace window [11..16].
        blocks = [_FakeBlock(h, []) for h in range(11, 17)]
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=10 + CENSORSHIP_GRACE_BLOCKS + 1,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=blocks,
        )
        self.assertTrue(ok, reason)

    def test_premature_rejected(self):
        r = self._fresh_receipt(height=10)
        ev = create_censorship_evidence_tx(self.user, r, self.censored_tx)
        # current_height still inside grace window
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=10 + CENSORSHIP_GRACE_BLOCKS,  # == window_end, not >
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok)
        self.assertIn("premature", reason)

    def test_stale_rejected(self):
        r = self._fresh_receipt(height=0)
        ev = create_censorship_evidence_tx(self.user, r, self.censored_tx)
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=EVIDENCE_EXPIRY_BLOCKS + 1,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok)
        self.assertIn("stale", reason)

    def test_forged_receipt_bad_signature_rejected(self):
        r = self._fresh_receipt(height=10)
        ev = create_censorship_evidence_tx(self.user, r, self.censored_tx)
        # Verify against an UNRELATED root — sig won't match.
        wrong_root = KeyPair(os.urandom(32), height=4).public_key
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=10 + CENSORSHIP_GRACE_BLOCKS + 1,
            receipt_tree_root=wrong_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_hash_mismatch_rejected(self):
        """Receipt for one tx, supplied tx is a DIFFERENT tx."""
        r = self._fresh_receipt(height=10)
        other_tx = _make_tx(self.user, nonce=1)
        ev = CensorshipEvidenceTx(
            receipt=r,
            tx=other_tx,  # hash mismatch
            submitter_id=self.user.entity_id,
            timestamp=0,
            fee=EVIDENCE_SUBMISSION_FEE,
            signature=self.user.keypair.sign(_sha(b"x")),
        )
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=10 + CENSORSHIP_GRACE_BLOCKS + 1,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok)
        self.assertIn("does not match", reason)

    def test_tx_included_in_window_voids_evidence(self):
        """If the tx appears in any block of the window, evidence fails.

        This is the self-indicting case: the accused validator (or some
        other proposer) did include the tx.  No censorship to slash.
        """
        r = self._fresh_receipt(height=10)
        ev = create_censorship_evidence_tx(self.user, r, self.censored_tx)
        # Block at height 12 includes the tx.
        blocks = [
            _FakeBlock(11, []),
            _FakeBlock(12, [self.censored_tx]),
            _FakeBlock(13, []),
        ]
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=10 + CENSORSHIP_GRACE_BLOCKS + 1,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=blocks,
        )
        self.assertFalse(ok)
        self.assertIn("included", reason)

    def test_fee_below_minimum_rejected(self):
        r = self._fresh_receipt(height=10)
        ev = CensorshipEvidenceTx(
            receipt=r,
            tx=self.censored_tx,
            submitter_id=self.user.entity_id,
            timestamp=0,
            fee=0,  # < EVIDENCE_SUBMISSION_FEE
            signature=self.user.keypair.sign(_sha(b"any")),
        )
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=10 + CENSORSHIP_GRACE_BLOCKS + 1,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok)
        self.assertIn("fee", reason)

    def test_replay_rejected(self):
        r = self._fresh_receipt(height=10)
        ev = create_censorship_evidence_tx(self.user, r, self.censored_tx)
        processed = {self.censored_tx.tx_hash}
        ok, reason = verify_censorship_evidence(
            ev,
            current_height=10 + CENSORSHIP_GRACE_BLOCKS + 1,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
            already_processed=processed,
        )
        self.assertFalse(ok)
        self.assertIn("already", reason)


class EvidenceSerializationTest(unittest.TestCase):
    def setUp(self):
        self.kp = KeyPair(os.urandom(32), height=4)
        self.user = _make_submitter()
        self.tx = _make_tx(self.user, nonce=0)
        self.receipt = sign_receipt(
            keypair=self.kp,
            tx_hash=self.tx.tx_hash,
            validator_pubkey=_sha(b"vpub"),
            received_at_height=7,
            submission_fee_paid=SUBMISSION_FEE,
        )
        self.ev = create_censorship_evidence_tx(self.user, self.receipt, self.tx)

    def test_dict_roundtrip(self):
        raw = self.ev.serialize()
        rebuilt = CensorshipEvidenceTx.deserialize(raw)
        self.assertEqual(rebuilt.tx_hash, self.ev.tx_hash)
        self.assertEqual(rebuilt.fee, self.ev.fee)
        self.assertEqual(rebuilt.receipt.tx_hash, self.receipt.tx_hash)
        self.assertEqual(rebuilt.tx.tx_hash, self.tx.tx_hash)

    def test_binary_roundtrip(self):
        blob = self.ev.to_bytes()
        rebuilt = CensorshipEvidenceTx.from_bytes(blob)
        self.assertEqual(rebuilt.tx_hash, self.ev.tx_hash)


class TwoPhaseSlashingTest(unittest.TestCase):
    """Two-phase slashing: evidence → challenge window → slash or void.

    These tests are the heart of the censorship-evidence mechanism.
    The challenge window is the ONE thing we must not break: get it
    wrong and either (a) griefing becomes possible or (b) real
    censorship goes unpunished.
    """

    def setUp(self):
        self.receipt_kp = KeyPair(os.urandom(32), height=4)
        self.receipt_root = self.receipt_kp.public_key
        self.validator_pubkey = _sha(b"validator")
        self.user = _make_submitter()
        self.tx = _make_tx(self.user, nonce=0)
        self.receipt = sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=self.tx.tx_hash,
            validator_pubkey=self.validator_pubkey,
            received_at_height=10,
            submission_fee_paid=SUBMISSION_FEE,
        )
        self.evidence = create_censorship_evidence_tx(
            self.user, self.receipt, self.tx,
        )

    def test_submit_then_mature_fires(self):
        """Happy path: evidence is submitted, nothing happens in the
        challenge window, slash fires on mature()."""
        proc = CensorshipEvidenceProcessor()
        # Evidence submitted at height 20 (safely past grace window end 16).
        ok, reason = proc.submit(
            self.evidence,
            current_height=20,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertTrue(ok, reason)
        self.assertIn(self.receipt.tx_hash, proc.pending)

        # Still inside the challenge window — no maturation.
        inside = proc.mature(current_height=20 + EVIDENCE_CHALLENGE_BLOCKS)
        self.assertEqual(inside, [])
        self.assertIn(self.receipt.tx_hash, proc.pending)

        # One past the deadline — matures.
        matured = proc.mature(current_height=20 + EVIDENCE_CHALLENGE_BLOCKS + 1)
        self.assertEqual(len(matured), 1)
        self.assertEqual(matured[0].evidence.receipt.tx_hash, self.receipt.tx_hash)
        # Removed from pending.
        self.assertNotIn(self.receipt.tx_hash, proc.pending)
        self.assertTrue(proc.is_matured(self.receipt.tx_hash))

    def test_challenge_window_inclusion_voids_evidence(self):
        """Accused validator defends by producing a block containing the tx.

        This is the griefing defense: if the user withheld the tx from
        gossip and sprang a receipt-as-trap, the validator can
        unilaterally defeat the attack by now-including the tx.
        """
        proc = CensorshipEvidenceProcessor()
        ok, _ = proc.submit(
            self.evidence,
            current_height=20,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertTrue(ok)

        # Somewhere in the window, a block is produced including the tx.
        defense_block = _FakeBlock(50, [self.tx])
        voided = proc.observe_block(defense_block)
        self.assertEqual(voided, [self.receipt.tx_hash])
        # Pending emptied; recorded as voided.
        self.assertNotIn(self.receipt.tx_hash, proc.pending)
        self.assertTrue(proc.is_voided(self.receipt.tx_hash))

        # Mature() sweeps nothing; slash never fires.
        matured = proc.mature(current_height=20 + EVIDENCE_CHALLENGE_BLOCKS + 1)
        self.assertEqual(matured, [])
        self.assertFalse(proc.is_matured(self.receipt.tx_hash))

    def test_slash_amount_applied_on_mature(self):
        """Mature evidence drives a 10%-of-stake burn at the caller level."""
        proc = CensorshipEvidenceProcessor()
        proc.submit(
            self.evidence,
            current_height=20,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        matured = proc.mature(
            current_height=20 + EVIDENCE_CHALLENGE_BLOCKS + 1,
        )
        self.assertEqual(len(matured), 1)
        # Simulate the caller's slash step.
        validator_stake = 1_000_000
        to_burn = compute_slash_amount(validator_stake)
        self.assertEqual(to_burn, 100_000)  # 10.00%
        remaining = validator_stake - to_burn
        self.assertEqual(remaining, 900_000)

    def test_replay_prevention(self):
        """The same receipt cannot be reused to file a second evidence."""
        proc = CensorshipEvidenceProcessor()
        ok, _ = proc.submit(
            self.evidence,
            current_height=20,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertTrue(ok)
        # Second submission of the same receipt-backed evidence.
        ok2, reason = proc.submit(
            self.evidence,
            current_height=21,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok2)
        self.assertIn("already", reason)

    def test_voided_replay_still_blocked(self):
        """Once voided, the receipt may not be re-filed (prevents re-attempts)."""
        proc = CensorshipEvidenceProcessor()
        proc.submit(
            self.evidence,
            current_height=20,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        proc.observe_block(_FakeBlock(22, [self.tx]))
        self.assertTrue(proc.is_voided(self.receipt.tx_hash))
        ok, reason = proc.submit(
            self.evidence,
            current_height=30,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok)
        self.assertIn("already", reason)

    def test_self_indicting_evidence_voided_by_own_inclusion(self):
        """Spec security analysis: if the user held the tx back from
        gossip, the accused validator's OWN block can still void.

        Concretely: the user submits to validator V, V signs a receipt,
        the user never gossips the tx to anyone else.  V can now
        produce a block itself containing the tx during the challenge
        window.  Evidence must void.
        """
        proc = CensorshipEvidenceProcessor()
        proc.submit(
            self.evidence,
            current_height=20,
            receipt_tree_root=self.receipt_root,
            blocks_in_window=[],
        )
        # Mid-challenge-window, validator produces its own block with tx.
        own_block = _FakeBlock(21, [self.tx])
        voided = proc.observe_block(own_block)
        self.assertEqual(voided, [self.receipt.tx_hash])
        # No slash on mature.
        matured = proc.mature(20 + EVIDENCE_CHALLENGE_BLOCKS + 1)
        self.assertEqual(matured, [])

    def test_forged_receipt_rejected_at_submit(self):
        """Bad signature → submit fails, nothing queued."""
        proc = CensorshipEvidenceProcessor()
        wrong_root = KeyPair(os.urandom(32), height=4).public_key
        ok, reason = proc.submit(
            self.evidence,
            current_height=20,
            receipt_tree_root=wrong_root,
            blocks_in_window=[],
        )
        self.assertFalse(ok)
        self.assertEqual(len(proc.pending), 0)


class StakeSlashIntegrationTest(unittest.TestCase):
    """End-to-end: mature evidence + SupplyTracker burn yields the
    spec-declared 10% stake reduction with tokens burned (not paid)."""

    def test_burn_reduces_stake_and_supply(self):
        from messagechain.economics.inflation import SupplyTracker

        supply = SupplyTracker()
        validator_id = _sha(b"validator-entity")
        supply.staked[validator_id] = 1_000_000
        # SupplyTracker must know about the stake as part of total supply
        # for the net-inflation invariant; our test only cares about the
        # stake field and the burn accounting.
        total_supply_before = supply.total_supply
        total_burned_before = supply.total_burned

        burn_amount = compute_slash_amount(supply.staked[validator_id])
        self.assertEqual(burn_amount, 100_000)

        # Apply the burn manually (as the Blockchain layer would).
        supply.staked[validator_id] -= burn_amount
        supply.total_supply -= burn_amount
        supply.total_burned += burn_amount

        self.assertEqual(supply.staked[validator_id], 900_000)
        self.assertEqual(supply.total_supply, total_supply_before - burn_amount)
        self.assertEqual(supply.total_burned, total_burned_before + burn_amount)


class ChallengeWindowConstants(unittest.TestCase):
    """Sanity on the spec-declared constants."""

    def test_grace(self):
        self.assertEqual(CENSORSHIP_GRACE_BLOCKS, 6)

    def test_challenge(self):
        self.assertEqual(EVIDENCE_CHALLENGE_BLOCKS, 14_400)

    def test_expiry(self):
        self.assertEqual(EVIDENCE_EXPIRY_BLOCKS, 10_000)


if __name__ == "__main__":
    unittest.main()
