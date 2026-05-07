"""Tier 63 — wire ``StateCheckpointDoubleSignEvidence`` into the
slashing pipeline.

Pre-fix: ``StateCheckpointDoubleSignEvidence`` and
``verify_state_checkpoint_double_sign_evidence`` exist in
``messagechain/consensus/state_checkpoint.py`` and the docstring claims
"Penalty: 100% stake + full escrow burn, same as double-proposal /
double-attestation / double-finality-vote."  But the slashing pipeline
only dispatches kinds 0/1/2 (block / attestation / finality-vote);
``OffenseKind`` has no entry for state-checkpoint double-sign;
``Blockchain.validate_slash_transaction`` has no branch for it; and
``SlashTransaction.{to,from}_bytes`` rejects kind=3.  The documented
slashable offense was therefore unenforceable.

A validator that signs two distinct ``state_root`` values for the same
``block_number`` is fragmenting bootstrap-from-checkpoint sync — new
nodes adopting the snapshot would land in different states.  The
adversary class is validator collusion (long-range / weak-subjectivity
attack).  The CLAUDE.md anchors the fix protects: Mission ("permanent
ledger" + bootstrap survivability), honest-operator-insurance
(deliberate misbehavior is catastrophically slashed; this evidence
shape is UNAMBIGUOUS — there is no benign drift between two distinct
snapshot roots).

This is a hard fork at ``STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT``:
post-fork the new evidence kind admits and applies at 100% (UNAMBIGUOUS
on first-and-short-tenure / on any repeat); pre-fork the gate refuses
admission so historical blocks never carried a kind=3 slash tx and
replay byte-identically.
"""

from __future__ import annotations

import struct
import unittest

from messagechain.config import (
    LOTTERY_DETERMINISTIC_HEIGHT,
    STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT,
)
from messagechain.consensus.honesty_curve import (
    OffenseKind,
    Unambiguity,
)
from messagechain.consensus.state_checkpoint import (
    StateCheckpoint,
    StateCheckpointDoubleSignEvidence,
    create_state_checkpoint_signature,
    verify_state_checkpoint_double_sign_evidence,
)
from messagechain.consensus.slashing import (
    SlashTransaction,
    create_slash_transaction,
)
from messagechain.core.block import _hash
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


class TestActivationConstantOrdering(unittest.TestCase):
    """Tier 63 activates above the most-recent prior tier (62)."""

    def test_height_above_tier_62(self):
        self.assertGreater(
            STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT,
            LOTTERY_DETERMINISTIC_HEIGHT,
        )

    def test_cohort_spacing_matches_tier_pattern(self):
        # ~50-block cohort spacing matches Tier 49-62 pattern.
        gap = STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT - LOTTERY_DETERMINISTIC_HEIGHT
        self.assertGreaterEqual(gap, 50)


class TestOffenseKindEnum(unittest.TestCase):
    """OffenseKind exposes a stable name for state-checkpoint double-sign."""

    def test_state_checkpoint_double_sign_kind_exists(self):
        self.assertTrue(hasattr(OffenseKind, "STATE_CHECKPOINT_DOUBLE_SIGN"))

    def test_kind_value_is_stable(self):
        # Value used in serialization / debug repr — must not rename.
        self.assertEqual(
            OffenseKind.STATE_CHECKPOINT_DOUBLE_SIGN.value,
            "state_checkpoint_double_sign",
        )


# ── Shared evidence builder ──────────────────────────────────────────


def _build_double_sign_evidence(
    offender: Entity,
    block_number: int = 100,
) -> StateCheckpointDoubleSignEvidence:
    """Construct a self-verifying double-sign evidence object.

    Two checkpoints at the same block_number with different state_roots
    (different block_hash too — a deliberate-Byzantine equivocation
    where the offender chose two parallel post-states).
    """
    cp_a = StateCheckpoint(
        block_number=block_number,
        block_hash=_hash(b"block_hash_a"),
        state_root=_hash(b"state_root_a"),
    )
    cp_b = StateCheckpoint(
        block_number=block_number,
        block_hash=_hash(b"block_hash_b"),
        state_root=_hash(b"state_root_b"),
    )
    sig_a = create_state_checkpoint_signature(offender, cp_a)
    sig_b = create_state_checkpoint_signature(offender, cp_b)
    return StateCheckpointDoubleSignEvidence(
        offender_id=offender.entity_id,
        checkpoint_a=cp_a,
        signature_a=sig_a,
        checkpoint_b=cp_b,
        signature_b=sig_b,
    )


class TestEvidenceVerifies(unittest.TestCase):
    """Sanity: the evidence object self-verifies under the offender's key."""

    @classmethod
    def setUpClass(cls):
        cls.bob = Entity.create(b"r36-bob".ljust(32, b"\x00"))

    def setUp(self):
        self.bob.keypair._next_leaf = 0

    def test_self_verifying(self):
        ev = _build_double_sign_evidence(self.bob, block_number=100)
        ok, reason = verify_state_checkpoint_double_sign_evidence(
            ev, self.bob.public_key,
        )
        self.assertTrue(ok, reason)


class TestSlashTransactionRoundTrip(unittest.TestCase):
    """SlashTransaction(kind=3, StateCheckpointDoubleSignEvidence) must
    round-trip through both wire (to_bytes/from_bytes) and dict
    (serialize/deserialize) encodings.  Pre-fix from_bytes raised
    'Unknown slash evidence kind: 3'."""

    @classmethod
    def setUpClass(cls):
        cls.bob = Entity.create(b"r36-bob-rt".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"r36-carol-rt".ljust(32, b"\x00"))

    def setUp(self):
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0

    def test_binary_roundtrip(self):
        ev = _build_double_sign_evidence(self.bob, block_number=200)
        slash_tx = create_slash_transaction(self.carol, ev, fee=1500)
        blob = slash_tx.to_bytes()
        # First byte must be the new kind=3 discriminator.
        self.assertEqual(struct.unpack_from(">B", blob, 0)[0], 3)
        restored = SlashTransaction.from_bytes(blob)
        self.assertEqual(restored.tx_hash, slash_tx.tx_hash)
        self.assertIsInstance(restored.evidence, StateCheckpointDoubleSignEvidence)
        self.assertEqual(
            restored.evidence.evidence_hash, ev.evidence_hash,
        )

    def test_dict_roundtrip(self):
        ev = _build_double_sign_evidence(self.bob, block_number=210)
        slash_tx = create_slash_transaction(self.carol, ev, fee=1500)
        restored = SlashTransaction.deserialize(slash_tx.serialize())
        self.assertEqual(restored.tx_hash, slash_tx.tx_hash)
        self.assertIsInstance(restored.evidence, StateCheckpointDoubleSignEvidence)


class TestEvidenceBlockNumber(unittest.TestCase):
    """``Blockchain._evidence_block_number`` must extract the height
    from a StateCheckpointDoubleSignEvidence (uses checkpoint_a)."""

    @classmethod
    def setUpClass(cls):
        cls.bob = Entity.create(b"r36-bob-en".ljust(32, b"\x00"))

    def setUp(self):
        self.bob.keypair._next_leaf = 0

    def test_returns_checkpoint_a_block_number(self):
        ev = _build_double_sign_evidence(self.bob, block_number=777)
        self.assertEqual(Blockchain._evidence_block_number(ev), 777)


# ── Apply-path tests need a funded chain ─────────────────────────────


class _ChainTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"r36-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"r36-bob-ap".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"r36-carol-ap".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.chain.supply.balances[self.bob.entity_id] = 100_000
        self.chain.supply.balances[self.carol.entity_id] = 100_000
        self.chain.supply.stake(self.alice.entity_id, 10_000)
        self.chain.supply.stake(self.bob.entity_id, 10_000)
        self.chain.supply.stake(self.carol.entity_id, 10_000)


class TestComputeSlashPctUnambiguous(_ChainTestBase):
    """A state-checkpoint double-sign is UNAMBIGUOUS by design.

    There is no benign single-restart shape that would produce two
    distinct ``state_root`` values for the same block height — the
    snapshot root is a function of the deterministically-replayed chain
    state.  Two distinct values means the offender deliberately chose
    two parallel post-states.  Severity grades to 100% on first offense
    against a fresh-tenure validator and 100% on any repeat (matches
    the FINALITY_DOUBLE_VOTE / ATTESTATION_DOUBLE_VOTE shape).
    """

    def test_first_offense_fresh_tenure_is_full_slash(self):
        ev = _build_double_sign_evidence(self.bob, block_number=100)
        slash_tx = create_slash_transaction(self.carol, ev, fee=1500)
        # Pass an explicit current_height >= the gate to exercise the
        # Tier-63 dispatch.  slashing_severity's UNAMBIGUOUS branch
        # reads only prior + track from blockchain state, NOT chain
        # height -- a fresh validator (track=0 < THRESHOLD) triggers
        # the "treat as deliberate" return-100 path independent of
        # chain.height, which is what we assert here.
        pct = self.chain._compute_slash_pct(
            slash_tx, STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT + 1,
        )
        self.assertEqual(pct, 100)


class TestPreForkAdmissionRejected(_ChainTestBase):
    """At chain heights below the activation gate, validate_slash_transaction
    must REFUSE a kind=3 slash tx.  Otherwise the new admission rule
    leaks back into pre-fork blocks and breaks deterministic replay.
    """

    def test_pre_fork_height_rejects_with_explicit_reason(self):
        ev = _build_double_sign_evidence(self.bob, block_number=100)
        slash_tx = create_slash_transaction(self.carol, ev, fee=1500)
        ok, reason = self.chain.validate_slash_transaction(
            slash_tx,
            chain_height=STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT - 1,
        )
        self.assertFalse(ok)
        # Reason must name the gate so the operator knows it's a
        # height-gated admission, not malformed evidence.
        self.assertIn("Tier 63", reason)


class TestPostForkApplySlash(_ChainTestBase):
    """At chain heights >= the activation gate, the full slash path
    runs: validate accepts, apply burns 100% of the offender's stake
    (UNAMBIGUOUS first-offense / fresh-tenure on Tier 23 curve), and
    the offender lands in ``slashed_validators``.

    apply_slash_transaction reads ``self.height`` (a property derived
    from len(self.chain)) for both the validate-fallback and the
    severity gate.  Building a real chain to height >= 2400 is
    infeasible in a unit test, so we monkey-patch the activation gate
    down to 0 for the duration of the test -- consistent with the
    test_finality.py setUpModule pattern for the
    FINALITY_REWARD_FROM_ISSUANCE_HEIGHT gate.
    """

    def setUp(self):
        super().setUp()
        import messagechain.config as _mcfg
        self._orig_gate = _mcfg.STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT
        _mcfg.STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT = 0

    def tearDown(self):
        import messagechain.config as _mcfg
        _mcfg.STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT = self._orig_gate

    def test_post_fork_apply_100pct_slash(self):
        bob_stake_before = self.chain.supply.get_staked(self.bob.entity_id)
        self.assertGreater(bob_stake_before, 0)
        ev = _build_double_sign_evidence(self.bob, block_number=100)
        slash_tx = create_slash_transaction(self.carol, ev, fee=1500)

        # Validate (gate is open via the setUp override).
        ok, reason = self.chain.validate_slash_transaction(slash_tx)
        self.assertTrue(ok, reason)

        # Apply.  At chain.height=1 the legacy pre-Tier-23 path runs
        # (HONESTY_CURVE_HEIGHT=720), which returns SLASH_PENALTY_PCT=
        # 100 for any double-sign offense.  Post-Tier-23 the curve
        # itself ALSO returns 100 for UNAMBIGUOUS+fresh-tenure, so
        # behavior is consistent across the gate.
        success, msg = self.chain.apply_slash_transaction(
            slash_tx, self.alice.entity_id,
        )
        self.assertTrue(success, msg)
        self.assertEqual(self.chain.supply.get_staked(self.bob.entity_id), 0)
        self.assertIn(self.bob.entity_id, self.chain.slashed_validators)


class TestVerifyEvidenceFailsAtValidate(_ChainTestBase):
    """If the two checkpoints have identical state_roots, the underlying
    verifier rejects (no equivocation took place).  validate_slash_transaction
    must surface that as 'Invalid evidence', not silently apply.
    """

    def test_identical_state_roots_rejected_as_invalid_evidence(self):
        cp_a = StateCheckpoint(
            block_number=100,
            block_hash=_hash(b"hash_a"),
            state_root=_hash(b"same_state_root"),
        )
        cp_b = StateCheckpoint(
            block_number=100,
            block_hash=_hash(b"hash_b"),
            state_root=_hash(b"same_state_root"),  # identical
        )
        sig_a = create_state_checkpoint_signature(self.bob, cp_a)
        sig_b = create_state_checkpoint_signature(self.bob, cp_b)
        ev = StateCheckpointDoubleSignEvidence(
            offender_id=self.bob.entity_id,
            checkpoint_a=cp_a,
            signature_a=sig_a,
            checkpoint_b=cp_b,
            signature_b=sig_b,
        )
        slash_tx = create_slash_transaction(self.carol, ev, fee=1500)
        ok, reason = self.chain.validate_slash_transaction(
            slash_tx,
            chain_height=STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT + 1,
        )
        self.assertFalse(ok)
        self.assertIn("Invalid evidence", reason)


if __name__ == "__main__":
    unittest.main()
