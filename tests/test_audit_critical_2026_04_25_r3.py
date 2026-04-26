"""Critical-severity audit fixes — round 3 (2026-04-25).

Four CRITICAL issues:

1. **Censorship-evidence loses `staked_at_admission` on disk persist.**
   `Blockchain._persist_state` calls
   `db.set_pending_censorship_evidence(...)` with 5 positional args; the
   underlying chaindb method accepts 6 with the 6th defaulting to 0.
   Every flush silently writes `staked_at_admission=0`.  After ANY cold
   restart, `mature()` reads back zero and the slash penalty is
   computed against zero stake — the slash is silently nullified.
   Fix: pass `entry.staked_at_admission` to the call.

2. **Attestation slashing evadable by single key rotation.**
   `_evidence_block_number` for `AttestationSlashingEvidence` returns
   the TARGET height; `_public_key_at_height(target)` returns only the
   pre-rotation key K1.  An equivocator who rotates to K2 between
   conflicting attestations evades the slash because
   verify_attestation(att_b, K1) fails.  Fix: change the slash
   verifiers to take a LIST of candidate public keys (built from
   key_history + current pubkey), and accept the evidence if EACH
   attestation verifies under SOME candidate key.

3+4. **ProposalTransaction & TreasurySpendTransaction `_signable_data`
   length-prefix collision.**  Same defect class as the message-tx v4
   hard fork: variable-length `title`/`description`/`reference_hash`
   concatenated raw with no length prefixes.  Fix: hard fork at
   `GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT` (Tier 15) introduces v2
   governance txs whose `_signable_data` length-prefixes every
   variable-length field.  Pre-activation v2 admission is rejected;
   v1 byte-for-byte unchanged for historical replay.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import tempfile
import unittest
from unittest.mock import MagicMock

import messagechain.config as config
from tests import register_entity_for_test
from messagechain.config import HASH_ALGO, VALIDATOR_MIN_STAKE
from messagechain.consensus.attestation import (
    Attestation,
    create_attestation,
)
from messagechain.consensus.slashing import (
    AttestationSlashingEvidence,
    SlashTransaction,
    verify_attestation_slashing_evidence,
)
from messagechain.consensus.censorship_evidence import (
    CensorshipEvidenceProcessor,
    _PendingEvidence,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.governance.governance import (
    ProposalTransaction,
    TreasurySpendTransaction,
)
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1 — censorship-evidence staked_at_admission persistence
# ─────────────────────────────────────────────────────────────────────

class TestCensorshipEvidenceStakedAtAdmissionPersists(unittest.TestCase):
    """`_persist_state` MUST pass `staked_at_admission` to the chaindb
    setter.  Pre-fix every flush wrote zero, silently nullifying the
    slash on cold restart.
    """

    def test_persist_passes_staked_at_admission_to_chaindb(self):
        """Spy on db.set_pending_censorship_evidence; verify the value
        of staked_at_admission is forwarded (positional or kwarg)."""
        alice = Entity.create(b"r3-cev-persist".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        chain.censorship_processor.submit(
            evidence_hash=b"\x11" * 32,
            offender_id=b"\x22" * 32,
            tx_hash=b"\x33" * 32,
            admitted_height=42,
            evidence_tx_hash=b"\x44" * 32,
            staked_at_admission=987654321,
        )
        # Stub a db that records every set_pending_censorship_evidence call.
        captured = []
        class _DBStub:
            def __init__(self):
                pass
            def set_pending_censorship_evidence(self, *args, **kwargs):
                captured.append((args, kwargs))
            def __getattr__(self, name):
                # No-op every other persistence helper -- _persist_state
                # touches dozens of tables.
                return lambda *a, **kw: None
        chain.db = _DBStub()
        chain._persist_state()
        # Find the call for our admitted evidence.
        rows = [
            (a, kw) for (a, kw) in captured
            if (a and a[0] == b"\x11" * 32) or kw.get("evidence_hash") == b"\x11" * 32
        ]
        self.assertEqual(
            len(rows), 1,
            "exactly one persist call per pending entry expected",
        )
        a, kw = rows[0]
        # Reconstruct the staked_at_admission value (positional-arg index 5
        # under the current chaindb signature, OR kwarg).
        staked = kw.get("staked_at_admission")
        if staked is None and len(a) >= 6:
            staked = a[5]
        self.assertEqual(
            staked, 987654321,
            "staked_at_admission MUST be forwarded to chaindb -- pre-fix "
            "the kwarg defaulted to 0, silently nullifying the slash on "
            "cold restart",
        )

    def test_round_trip_through_real_chaindb_preserves_stake(self):
        """End-to-end: persist a pending evidence with staked=12345,
        close + reopen the DB, verify the in-memory processor sees
        staked_at_admission=12345 (not 0)."""
        tmpdir = tempfile.mkdtemp(prefix="mc-r3-cev-")
        try:
            alice = Entity.create(b"r3-cev-rt".ljust(32, b"\x00"))
            db = ChainDB(db_path=os.path.join(tmpdir, "chain.db"))
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)
            chain.censorship_processor.submit(
                evidence_hash=b"\xaa" * 32,
                offender_id=b"\xbb" * 32,
                tx_hash=b"\xcc" * 32,
                admitted_height=7,
                evidence_tx_hash=b"\xdd" * 32,
                staked_at_admission=12345,
            )
            chain._persist_state()
            db_path = db.db_path
            db.close()

            # Reopen and rehydrate.
            db2 = ChainDB(db_path=db_path)
            try:
                rows = db2.get_all_pending_censorship_evidence()
                self.assertIn(b"\xaa" * 32, rows)
                payload = rows[b"\xaa" * 32]
                self.assertEqual(
                    payload[4], 12345,
                    f"staked_at_admission lost on persist -- got {payload[4]}",
                )
            finally:
                db2.close()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2 — attestation slashing survives key rotation
# ─────────────────────────────────────────────────────────────────────

class TestAttestationSlashingResistsKeyRotation(unittest.TestCase):
    """A double-attestation that spans a key rotation MUST still
    slash.  Pre-fix the slasher resolved the offender's pubkey at the
    target height (returns pre-rotation K1); verify_attestation(att_b,
    K1) failed because att_b was signed with the post-rotation K2 ->
    evidence dismissed.
    """

    def test_verify_accepts_when_each_attestation_matches_a_candidate_key(self):
        """The new verifier MUST accept evidence iff att_a verifies
        under SOME candidate key AND att_b verifies under SOME
        (possibly different) candidate key."""
        # Two distinct keypairs -- represent K1 (pre-rotation) and
        # K2 (post-rotation) for the SAME entity_id.
        e1 = Entity.create(b"r3-attslash-k1".ljust(32, b"\x00"))
        e2 = Entity.create(b"r3-attslash-k2".ljust(32, b"\x00"))
        offender_id = e1.entity_id  # same logical entity (slashing keys to it)

        # att_a signed with K1.
        att_a = create_attestation(e1, b"\xa1" * 32, block_number=10)
        # att_b: same target height, DIFFERENT block_hash, signed with K2.
        # We must construct it with the correct validator_id so the
        # equivocation check passes (validator_id == offender_id).
        att_b_unsigned = Attestation(
            validator_id=offender_id,
            block_hash=b"\xb2" * 32,
            block_number=10,
            signature=Signature([], 0, [], b"", b""),
        )
        from messagechain.consensus.attestation import _hash as _ahash
        msg_hash = _ahash(att_b_unsigned.signable_data())
        att_b_unsigned.signature = e2.keypair.sign(msg_hash)
        att_b = att_b_unsigned

        evidence = AttestationSlashingEvidence(
            offender_id=offender_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

        # Pre-fix call (single-key) under K1: rejects (att_b doesn't verify).
        ok_single, _ = verify_attestation_slashing_evidence(
            evidence, e1.public_key,
        )
        self.assertFalse(
            ok_single,
            "Sanity check: pre-fix single-key call must reject "
            "the rotation-laundered evidence",
        )

        # Post-fix call (multi-key) accepts: att_a under K1, att_b under K2.
        ok_multi, reason = verify_attestation_slashing_evidence(
            evidence, [e1.public_key, e2.public_key],
        )
        self.assertTrue(
            ok_multi,
            f"Multi-key verifier MUST accept rotation-laundered "
            f"evidence (reason: {reason})",
        )

    def test_verify_rejects_when_no_candidate_key_validates(self):
        """Negative path: a forged att_b signed by a key that's NOT
        in the candidate list must fail."""
        e1 = Entity.create(b"r3-attslash-honest".ljust(32, b"\x00"))
        e2 = Entity.create(b"r3-attslash-honest2".ljust(32, b"\x00"))
        e_attacker = Entity.create(b"r3-attslash-attk".ljust(32, b"\x00"))
        offender_id = e1.entity_id

        att_a = create_attestation(e1, b"\xa1" * 32, block_number=10)
        att_b_unsigned = Attestation(
            validator_id=offender_id,
            block_hash=b"\xb2" * 32,
            block_number=10,
            signature=Signature([], 0, [], b"", b""),
        )
        from messagechain.consensus.attestation import _hash as _ahash
        att_b_unsigned.signature = e_attacker.keypair.sign(
            _ahash(att_b_unsigned.signable_data()),
        )
        evidence = AttestationSlashingEvidence(
            offender_id=offender_id,
            attestation_a=att_a,
            attestation_b=att_b_unsigned,
        )
        # Candidates K1 + K2 do NOT include the attacker's key; reject.
        ok, _ = verify_attestation_slashing_evidence(
            evidence, [e1.public_key, e2.public_key],
        )
        self.assertFalse(
            ok,
            "att_b signed by an outside key not in the offender's key "
            "history must NOT slash",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #3 + #4 — governance signable-data length prefix (v2 hard fork)
# ─────────────────────────────────────────────────────────────────────

class TestGovernanceLengthPrefixHardFork(unittest.TestCase):
    """v2 governance txs MUST length-prefix every variable-length
    field in `_signable_data` so a relay cannot rewrite the human-
    readable text of an approved proposal.  v1 stays byte-for-byte
    unchanged for historical replay.
    """

    def test_governance_tx_length_prefix_height_constant_exists(self):
        self.assertTrue(
            hasattr(config, "GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT"),
            "GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT activation constant "
            "must be defined (Tier 15)",
        )
        self.assertGreater(
            config.GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT, 0,
        )

    def test_proposal_v2_signable_data_includes_length_prefixes(self):
        from messagechain.governance.governance import (
            GOVERNANCE_TX_VERSION_LENGTH_PREFIX,
        )
        e = Entity.create(b"r3-gov-prop-v2".ljust(32, b"\x00"))
        title = "Title with variable length"
        desc = "Some description text that varies"
        p = ProposalTransaction(
            proposer_id=e.entity_id,
            title=title,
            description=desc,
            reference_hash=b"\x77" * 32,
            timestamp=1.0,
            fee=10_000,
            signature=Signature([], 0, [], b"", b""),
            version=GOVERNANCE_TX_VERSION_LENGTH_PREFIX,
        )
        sd = p._signable_data()
        # Length prefixes must precede each variable-length field.
        title_b = title.encode("utf-8")
        desc_b = desc.encode("utf-8")
        self.assertIn(struct.pack(">H", len(title_b)) + title_b, sd)
        self.assertIn(struct.pack(">I", len(desc_b)) + desc_b, sd)
        self.assertIn(
            struct.pack(">B", len(p.reference_hash)) + p.reference_hash, sd,
        )

    def test_proposal_v1_signable_data_unchanged(self):
        """v1 _signable_data must remain byte-for-byte the same as
        before the fix -- historical replay determinism."""
        e = Entity.create(b"r3-gov-prop-v1".ljust(32, b"\x00"))
        p = ProposalTransaction(
            proposer_id=e.entity_id,
            title="T",
            description="D",
            reference_hash=b"",
            timestamp=1.0,
            fee=10_000,
            signature=Signature([], 0, [], b"", b""),
        )
        # v1 is the default version; expected legacy form has NO length
        # prefixes -- title/description concatenated raw.
        sd = p._signable_data()
        self.assertIn(b"T" + b"D", sd)
        # Length-prefix bytes (0x00 0x01 0x54) MUST NOT appear before
        # the title in v1.
        self.assertNotIn(struct.pack(">H", 1) + b"T", sd)

    def test_proposal_v1_v2_compute_different_tx_hashes(self):
        from messagechain.governance.governance import (
            GOVERNANCE_TX_VERSION_LENGTH_PREFIX,
        )
        e = Entity.create(b"r3-gov-prop-h".ljust(32, b"\x00"))
        common = dict(
            proposer_id=e.entity_id,
            title="Same",
            description="Same",
            reference_hash=b"",
            timestamp=1.0,
            fee=10_000,
            signature=Signature([], 0, [], b"", b""),
        )
        p1 = ProposalTransaction(**common)
        p2 = ProposalTransaction(
            **common, version=GOVERNANCE_TX_VERSION_LENGTH_PREFIX,
        )
        self.assertNotEqual(p1._compute_hash(), p2._compute_hash())

    def test_treasury_spend_v2_signable_data_includes_length_prefixes(self):
        from messagechain.governance.governance import (
            GOVERNANCE_TX_VERSION_LENGTH_PREFIX,
        )
        e = Entity.create(b"r3-gov-ts-v2".ljust(32, b"\x00"))
        title = "Pay 100 to Alice"
        desc = "For services rendered"
        ts = TreasurySpendTransaction(
            proposer_id=e.entity_id,
            recipient_id=b"\x99" * 32,
            amount=100,
            title=title,
            description=desc,
            timestamp=1.0,
            fee=10_000,
            signature=Signature([], 0, [], b"", b""),
            version=GOVERNANCE_TX_VERSION_LENGTH_PREFIX,
        )
        sd = ts._signable_data()
        title_b = title.encode("utf-8")
        desc_b = desc.encode("utf-8")
        self.assertIn(struct.pack(">H", len(title_b)) + title_b, sd)
        self.assertIn(struct.pack(">I", len(desc_b)) + desc_b, sd)

    def test_treasury_spend_v1_signable_data_unchanged(self):
        e = Entity.create(b"r3-gov-ts-v1".ljust(32, b"\x00"))
        ts = TreasurySpendTransaction(
            proposer_id=e.entity_id,
            recipient_id=b"\x88" * 32,
            amount=42,
            title="A",
            description="B",
            timestamp=1.0,
            fee=10_000,
            signature=Signature([], 0, [], b"", b""),
        )
        sd = ts._signable_data()
        self.assertIn(b"A" + b"B", sd)
        self.assertNotIn(struct.pack(">H", 1) + b"A", sd)


if __name__ == "__main__":
    unittest.main()
