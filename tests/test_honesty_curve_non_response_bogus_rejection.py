"""Tier 30 sibling: honesty-curve insurance for the remaining two
flat-BPS soft-slash paths.

CLAUDE.md anchors "honest operators are insured against accidents" —
catastrophic burns are reserved for unambiguous, intentional protocol
violations.  Tier 30 (commit ``a2db85c``) routed the censorship-slash
and IL-violation paths through ``slashing_severity``.  Two siblings
were missed:

  * ``compute_non_response_slash_amount`` /
    ``NonResponseEvidenceProcessor.process`` burned a flat
    WITNESS_NON_RESPONSE_SLASH_BPS (5%) on every first offense, so a
    long-tenured validator that dropped one witnessed submission
    under transient packet loss paid the same as a deliberate
    silent-drop censoring node.
  * ``BogusRejectionProcessor.process`` burned a flat
    CENSORSHIP_SLASH_BPS (10%) on every bogus REJECT_INVALID_SIG, so
    a borderline rejection that raced a fee-rule fork edge cost the
    issuer the same as deliberate forged-rejection censorship.

Both paths now route through the curve at/above
``HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT`` (Tier 30 sibling fork).
Pre-fork: byte-identical to the legacy flat-BPS computation.
Post-fork: ``OffenseKind.WITNESS_NON_RESPONSE`` and
``OffenseKind.BOGUS_REJECTION`` flow through ``slashing_severity``
with ``Unambiguity.AMBIGUOUS`` on first offense; subsequent offenses
escalate via ``slash_offense_counts`` (the curve's existing
repeat-offense ramp).
"""

from __future__ import annotations

import hashlib
import time
import unittest
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import (
    CENSORSHIP_SLASH_BPS,
    HASH_ALGO,
    HONESTY_CURVE_INSURANCE_HEIGHT,
    HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT,
    HONESTY_CURVE_RATE_HEIGHT,
    HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
    MIN_FEE,
    WITNESS_NON_RESPONSE_SLASH_BPS,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    WITNESS_SURCHARGE,
)
from messagechain.network.submission_receipt import REJECT_INVALID_SIG
from messagechain.consensus.bogus_rejection_evidence import (
    BogusRejectionEvidenceTx,
    BogusRejectionProcessor,
)
from messagechain.consensus.censorship_evidence import (
    compute_slash_amount as compute_bogus_slash_amount,
)
from messagechain.consensus.honesty_curve import OffenseKind
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceProcessor,
    compute_non_response_slash_amount,
    sign_non_response_evidence,
)
from messagechain.consensus.witness_submission import (
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import ReceiptIssuer


PRE = HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT - 1
POST = HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _force_chain_height(chain, h):
    return patch.object(
        Blockchain, "height", new=property(lambda _: h),
    )


# ────────────────────────────────────────────────────────────────────
# Curve-shape tests: enum entries exist and grade as expected.
# ────────────────────────────────────────────────────────────────────


class TestOffenseKindEntries(unittest.TestCase):
    """Both new OffenseKind entries must be defined."""

    def test_witness_non_response_in_offense_kind(self):
        self.assertTrue(hasattr(OffenseKind, "WITNESS_NON_RESPONSE"))

    def test_bogus_rejection_in_offense_kind(self):
        self.assertTrue(hasattr(OffenseKind, "BOGUS_REJECTION"))


# ────────────────────────────────────────────────────────────────────
# NonResponseEvidenceProcessor: routing + classification + escalation.
# ────────────────────────────────────────────────────────────────────


def _make_witnesses(n: int, tag: bytes) -> list[Entity]:
    return [
        Entity.create(
            (b"wn-" + tag + b"-" + str(i).encode()).ljust(32, b"\x00")
        )
        for i in range(n)
    ]


class TestNonResponseHonestyCurve(unittest.TestCase):
    """compute_non_response_slash_amount + processor.process must route
    through slashing_severity post-fork."""

    def setUp(self):
        self.target = Entity.create(b"nr-target".ljust(32, b"\x00"))
        self.client = Entity.create(b"nr-client".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"nr-submitter".ljust(32, b"\x00"))
        self.target.keypair._next_leaf = 0
        self.client.keypair._next_leaf = 0
        self.submitter.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        self.chain.supply.balances[self.target.entity_id] = 10_000_000
        self.chain.supply.balances[self.client.entity_id] = 10_000_000
        self.chain.supply.balances[self.submitter.entity_id] = 10_000_000
        self.chain.supply.staked[self.target.entity_id] = 1_000_000

        self.witnesses = _make_witnesses(WITNESS_QUORUM, b"crv")
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 1_000_000

    def _make_evidence(self, observed_height: int, seed: bytes):
        req = sign_submission_request(
            submitter=self.client,
            target_validator_id=self.target.entity_id,
            tx_hash=_h(b"nr-tx-" + seed),
            timestamp=int(time.time()),
            client_nonce=(seed * 16)[:16],
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        observations = [
            sign_witness_observation(
                w, req.request_hash, observed_height=observed_height,
            )
            for w in self.witnesses
        ]
        return sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )

    def test_pre_activation_flat_5pct_unchanged(self):
        """Below HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT: byte-identical
        to legacy flat WITNESS_NON_RESPONSE_SLASH_BPS (5%)."""
        # Long track record so the AMBIGUOUS curve would compress the
        # slash if it were active; pre-activation we expect flat 5%.
        self.chain.proposer_sig_counts[self.target.entity_id] = 1_000
        self.chain.reputation[self.target.entity_id] = 5_000

        etx = self._make_evidence(observed_height=0, seed=b"pre")
        proc = NonResponseEvidenceProcessor()
        # current_height stays low — well below the fork gate.
        current_height = WITNESS_RESPONSE_DEADLINE_BLOCKS + 5
        self.assertLess(current_height, PRE)
        stake_before = self.chain.supply.staked[self.target.entity_id]
        with _force_chain_height(self.chain, current_height):
            result = proc.process(etx, self.chain, current_height)
        self.assertTrue(result.slashed, result.reason)
        self.assertEqual(
            result.slash_amount,
            compute_non_response_slash_amount(stake_before),
            "Pre-fork: legacy flat WITNESS_NON_RESPONSE_SLASH_BPS path "
            "must be byte-identical.",
        )

    def test_post_activation_long_tenured_first_offense_uses_curve(self):
        """Post-fork: a long-tenured first offense must NOT burn flat
        5% — it routes through the AMBIGUOUS band."""
        self.chain.proposer_sig_counts[self.target.entity_id] = 1_000
        self.chain.reputation[self.target.entity_id] = 5_000

        etx = self._make_evidence(observed_height=POST - 50, seed=b"post1")
        proc = NonResponseEvidenceProcessor()
        stake_before = self.chain.supply.staked[self.target.entity_id]
        flat_legacy = compute_non_response_slash_amount(stake_before)
        with _force_chain_height(self.chain, POST):
            result = proc.process(etx, self.chain, POST)
        self.assertTrue(result.slashed, result.reason)
        self.assertLess(
            result.slash_amount, flat_legacy,
            "Post-fork long-tenured first offense must burn LESS than "
            "the legacy flat 5%.  A perfect-record validator may even "
            "land on the Tier 24 amnesty path (0%); that's the "
            "anchored insurance behavior.",
        )

    def test_post_activation_repeat_offense_escalates(self):
        """Repeat offenses bite — the curve's repeat-multiplier
        escalation stays active."""
        # Modest record — clears HONEST_TRACK_THRESHOLD, well below
        # AMNESTY_TRACK_THRESHOLD, so first offense gets relief but
        # escalation has headroom.
        self.chain.proposer_sig_counts[self.target.entity_id] = 30
        self.chain.reputation[self.target.entity_id] = 50

        proc = NonResponseEvidenceProcessor()
        # First offense.
        etx1 = self._make_evidence(observed_height=POST - 50, seed=b"r1")
        stake_before_1 = self.chain.supply.staked[self.target.entity_id]
        with _force_chain_height(self.chain, POST):
            result1 = proc.process(etx1, self.chain, POST)
        self.assertTrue(result1.slashed, result1.reason)
        burn_1 = result1.slash_amount

        # Second offense — distinct request_hash so dedupe doesn't
        # reject it.
        etx2 = self._make_evidence(observed_height=POST - 50, seed=b"r2")
        stake_before_2 = self.chain.supply.staked[self.target.entity_id]
        with _force_chain_height(self.chain, POST):
            result2 = proc.process(etx2, self.chain, POST)
        self.assertTrue(result2.slashed, result2.reason)
        burn_2 = result2.slash_amount

        pct_1 = burn_1 * 100 / max(1, stake_before_1)
        pct_2 = burn_2 * 100 / max(1, stake_before_2)
        self.assertGreaterEqual(
            pct_2, pct_1,
            "Tier 30 sibling escalation: a second offense must burn "
            "at least as large a fraction of stake as the first.",
        )

    def test_post_activation_repeated_low_history_offender_punished_hard(self):
        """A repeated offender with thin track record must still get
        bitten — the goal is fairness, not blanket leniency."""
        # No track record + several priors — exactly the
        # "newcomer who's actually misbehaving" pattern the curve is
        # designed to catch.
        self.chain.slash_offense_counts[self.target.entity_id] = 5

        etx = self._make_evidence(observed_height=POST - 50, seed=b"hard")
        proc = NonResponseEvidenceProcessor()
        stake_before = self.chain.supply.staked[self.target.entity_id]
        flat_legacy = compute_non_response_slash_amount(stake_before)
        with _force_chain_height(self.chain, POST):
            result = proc.process(etx, self.chain, POST)
        self.assertTrue(result.slashed, result.reason)
        # With multiple priors and no track record relief, the curve's
        # base × (1 + multiplier × prior) ramp should make the burn
        # at least as large as the legacy flat 5%.  Critically: the
        # validator is NOT getting the AMBIGUOUS-band relief here.
        self.assertGreaterEqual(
            result.slash_amount, flat_legacy,
            "Thin-history repeat offender must NOT escape with a "
            "smaller burn than the legacy flat 5% — the curve has to "
            "bite harder for repeated bad behavior.",
        )

    def test_post_activation_bumps_slash_offense_counts(self):
        """Successful slash must increment slash_offense_counts so the
        curve's repeat-offense ramp engages on the next offense."""
        etx = self._make_evidence(observed_height=POST - 50, seed=b"bump")
        proc = NonResponseEvidenceProcessor()
        before = self.chain.slash_offense_counts.get(
            self.target.entity_id, 0,
        )
        with _force_chain_height(self.chain, POST):
            result = proc.process(etx, self.chain, POST)
        self.assertTrue(result.slashed, result.reason)
        after = self.chain.slash_offense_counts.get(
            self.target.entity_id, 0,
        )
        self.assertEqual(
            after, before + 1,
            "Post-fork slash must bump slash_offense_counts so future "
            "offenses escalate via the curve.",
        )

    def test_pre_activation_does_not_bump_slash_offense_counts(self):
        """Pre-fork: legacy path is byte-identical, including no
        slash_offense_counts mutation (the legacy flat-BPS path didn't
        touch it)."""
        etx = self._make_evidence(observed_height=0, seed=b"prebump")
        proc = NonResponseEvidenceProcessor()
        before = self.chain.slash_offense_counts.get(
            self.target.entity_id, 0,
        )
        current_height = WITNESS_RESPONSE_DEADLINE_BLOCKS + 5
        with _force_chain_height(self.chain, current_height):
            proc.process(etx, self.chain, current_height)
        after = self.chain.slash_offense_counts.get(
            self.target.entity_id, 0,
        )
        self.assertEqual(after, before)


# ────────────────────────────────────────────────────────────────────
# BogusRejectionProcessor: routing + classification + escalation.
# ────────────────────────────────────────────────────────────────────


class TestBogusRejectionHonestyCurve(unittest.TestCase):
    """BogusRejectionProcessor.process must route through
    slashing_severity post-fork."""

    def setUp(self):
        self.alice = Entity.create(b"br-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"br-bob".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10_000_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000_000
        self.chain.supply.staked[self.alice.entity_id] = 1_000_000

        self.alice_receipt_kp = KeyPair.generate(
            seed=b"receipt-subtree-br-alice",
            height=4,
        )
        self.chain.receipt_subtree_roots[self.alice.entity_id] = (
            self.alice_receipt_kp.public_key
        )

    def _make_rejection(self, mtx, reason_code):
        issuer = ReceiptIssuer(
            self.alice.entity_id,
            self.alice_receipt_kp,
            height_fn=lambda: self.chain.height,
        )
        return issuer.issue_rejection(mtx.tx_hash, reason_code)

    def _sign_evidence(self, submitter, rej, mtx, fee=MIN_FEE):
        ts = int(time.time())
        placeholder = Signature([], 0, [], b"", b"")
        tx = BogusRejectionEvidenceTx(
            rejection=rej,
            message_tx=mtx,
            submitter_id=submitter.entity_id,
            timestamp=ts,
            fee=fee,
            signature=placeholder,
        )
        msg_hash = _h(tx._signable_data())
        sig = submitter.keypair.sign(msg_hash)
        return BogusRejectionEvidenceTx(
            rejection=rej,
            message_tx=mtx,
            submitter_id=submitter.entity_id,
            timestamp=ts,
            fee=fee,
            signature=sig,
        )

    def test_pre_activation_flat_10pct_unchanged(self):
        """Below the fork gate: byte-identical to legacy flat
        CENSORSHIP_SLASH_BPS (10%) burn."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 1_000
        self.chain.reputation[self.alice.entity_id] = 5_000

        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        stake_before = self.chain.supply.staked[self.alice.entity_id]
        proc = BogusRejectionProcessor()
        # block_height stays low — below the fork gate.
        block_height = self.chain.height + 1
        self.assertLess(block_height, PRE)
        with _force_chain_height(self.chain, block_height):
            result = proc.process(
                etx, self.chain, block_height=block_height,
            )
        self.assertTrue(result.slashed, result.reason)
        self.assertEqual(
            result.slash_amount,
            compute_bogus_slash_amount(stake_before),
            "Pre-fork: legacy flat CENSORSHIP_SLASH_BPS path must be "
            "byte-identical.",
        )

    def test_post_activation_long_tenured_first_offense_uses_curve(self):
        """Post-fork: a long-tenured first bogus rejection must NOT
        burn flat 10% — it routes through the AMBIGUOUS band."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 1_000
        self.chain.reputation[self.alice.entity_id] = 5_000

        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        stake_before = self.chain.supply.staked[self.alice.entity_id]
        flat_legacy = compute_bogus_slash_amount(stake_before)
        proc = BogusRejectionProcessor()
        with _force_chain_height(self.chain, POST):
            result = proc.process(etx, self.chain, block_height=POST)
        self.assertTrue(result.slashed, result.reason)
        self.assertLess(
            result.slash_amount, flat_legacy,
            "Post-fork long-tenured first offense must burn LESS than "
            "the legacy flat 10%.  A perfect-record validator may even "
            "hit the Tier 24 amnesty path (0%).",
        )

    def test_post_activation_repeat_offense_escalates(self):
        """A second bogus rejection must escalate via the curve."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 30
        self.chain.reputation[self.alice.entity_id] = 50

        proc = BogusRejectionProcessor()
        # First offense.
        mtx1 = create_transaction(self.bob, "hi-1", MIN_FEE + 100, nonce=0)
        rej1 = self._make_rejection(mtx1, REJECT_INVALID_SIG)
        etx1 = self._sign_evidence(self.bob, rej1, mtx1)
        stake_before_1 = self.chain.supply.staked[self.alice.entity_id]
        with _force_chain_height(self.chain, POST):
            result1 = proc.process(etx1, self.chain, block_height=POST)
        self.assertTrue(result1.slashed, result1.reason)
        burn_1 = result1.slash_amount

        # Second offense — different message_tx + rejection so the
        # evidence_hash dedupe doesn't reject it.
        mtx2 = create_transaction(self.bob, "hi-2", MIN_FEE + 100, nonce=1)
        rej2 = self._make_rejection(mtx2, REJECT_INVALID_SIG)
        etx2 = self._sign_evidence(self.bob, rej2, mtx2)
        stake_before_2 = self.chain.supply.staked[self.alice.entity_id]
        with _force_chain_height(self.chain, POST):
            result2 = proc.process(etx2, self.chain, block_height=POST)
        self.assertTrue(result2.slashed, result2.reason)
        burn_2 = result2.slash_amount

        pct_1 = burn_1 * 100 / max(1, stake_before_1)
        pct_2 = burn_2 * 100 / max(1, stake_before_2)
        self.assertGreaterEqual(
            pct_2, pct_1,
            "Tier 30 sibling escalation: a second bogus-rejection "
            "offense must burn at least as large a fraction of stake "
            "as the first.",
        )

    def test_post_activation_repeated_low_history_offender_punished_hard(self):
        """A repeated low-history offender must still be punished —
        no blanket leniency."""
        self.chain.slash_offense_counts[self.alice.entity_id] = 5

        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        stake_before = self.chain.supply.staked[self.alice.entity_id]
        flat_legacy = compute_bogus_slash_amount(stake_before)
        proc = BogusRejectionProcessor()
        with _force_chain_height(self.chain, POST):
            result = proc.process(etx, self.chain, block_height=POST)
        self.assertTrue(result.slashed, result.reason)
        self.assertGreaterEqual(
            result.slash_amount, flat_legacy,
            "Thin-history repeat offender must NOT escape with a "
            "smaller burn than the legacy flat 10%.",
        )

    def test_post_activation_bumps_slash_offense_counts(self):
        """Successful slash must increment slash_offense_counts."""
        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        proc = BogusRejectionProcessor()
        before = self.chain.slash_offense_counts.get(
            self.alice.entity_id, 0,
        )
        with _force_chain_height(self.chain, POST):
            result = proc.process(etx, self.chain, block_height=POST)
        self.assertTrue(result.slashed, result.reason)
        after = self.chain.slash_offense_counts.get(
            self.alice.entity_id, 0,
        )
        self.assertEqual(
            after, before + 1,
            "Post-fork bogus-rejection slash must bump "
            "slash_offense_counts.",
        )

    def test_pre_activation_does_not_bump_slash_offense_counts(self):
        """Pre-fork: legacy path is byte-identical (no counter bump)."""
        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        proc = BogusRejectionProcessor()
        before = self.chain.slash_offense_counts.get(
            self.alice.entity_id, 0,
        )
        block_height = self.chain.height + 1
        with _force_chain_height(self.chain, block_height):
            proc.process(etx, self.chain, block_height=block_height)
        after = self.chain.slash_offense_counts.get(
            self.alice.entity_id, 0,
        )
        self.assertEqual(after, before)


# ────────────────────────────────────────────────────────────────────
# Fork-gate height ordering invariant.
# ────────────────────────────────────────────────────────────────────


class TestForkGateOrdering(unittest.TestCase):
    """The new fork gate must sit above the prior Tier 30 gate so the
    coordination order is unambiguous on replay."""

    def test_height_above_tier_30(self):
        self.assertGreater(
            HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT,
            HONESTY_CURVE_INSURANCE_HEIGHT,
        )

    def test_height_above_rate_height(self):
        # The curve's rate component (Tier 24) must already be active
        # so slash_offense_counts is being maintained when the new
        # fork lands.
        self.assertGreater(
            HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT,
            HONESTY_CURVE_RATE_HEIGHT,
        )


if __name__ == "__main__":
    unittest.main()
