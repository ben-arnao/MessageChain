"""Tier 33 — non-response + bogus-rejection slash drains pending_unstakes.

Tier 31 (1.34.0) widened the slash basis on `_apply_censorship_slash`
and `process_inclusion_list_violation` from `staked` only to `(staked +
pending_unstakes)`, closing the censor-then-unstake evasion: a coerced
or colluding validator could censor a high-fee-per-byte tx, immediately
submit an unstake, and ride out the unbonding queue
(EVIDENCE_MATURITY_BLOCKS ~ 2.7h vs UNBONDING_PERIOD > 14 days) with
≥ 90% of the would-be slashed stake intact.

Tier 32 (1.34.0 sibling) routed the witness-non-response and
bogus-rejection apply paths through the honesty curve — but those two
paths still drained `staked` only.  The same evasion still worked
against silent-drop censorship and bogus-REJECT_INVALID_SIG
censorship: drop the witnessed submission (or sign the forged
rejection), unstake, and the slash hit a tiny remainder while the rest
released at unbond maturity.

Tier 33 closes both, mirroring Tier 31 exactly: route the apply through
``burn_slash_proportional`` so the slash bites both buckets
proportionally.

Tests pin:
  * Pre-Tier-33: pending_unstakes UNTOUCHED on both apply paths.
  * Post-Tier-33: pending_unstakes drained proportionally on both
    paths.
  * Post-Tier-33: the unstake-then-misbehave evasion fails — most of
    the would-be-slashed stake is destroyed even when 90% has already
    moved to pending.
"""

from __future__ import annotations

import hashlib
import time
import unittest
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT,
    MIN_FEE,
    NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    WITNESS_SURCHARGE,
)
from messagechain.network.submission_receipt import REJECT_INVALID_SIG
from messagechain.consensus.bogus_rejection_evidence import (
    BogusRejectionEvidenceTx,
    BogusRejectionProcessor,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceProcessor,
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


PRE_T33 = NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT - 1
POST_T33 = NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _force_chain_height(chain, h):
    return patch.object(
        Blockchain, "height", new=property(lambda _: h),
    )


# ────────────────────────────────────────────────────────────────────
# Activation height ordering invariant.
# ────────────────────────────────────────────────────────────────────


class TestForkGateOrdering(unittest.TestCase):
    """Tier 33 must ride above Tier 32 — the curve's sev_pct must
    already be the well-defined output the new path consumes."""

    def test_height_above_tier_32(self):
        self.assertGreater(
            NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT,
            HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT,
            "Tier 33 widens the slash basis for the same two paths Tier "
            "32 routed through the curve; the curve must already be "
            "live so sev_pct is well-defined when Tier 33 dispatches.",
        )


# ────────────────────────────────────────────────────────────────────
# Non-response apply path — Tier 33 pending-unstake drain.
# ────────────────────────────────────────────────────────────────────


def _make_witnesses(n: int, tag: bytes) -> list[Entity]:
    return [
        Entity.create(
            (b"t33-nr-" + tag + b"-" + str(i).encode()).ljust(32, b"\x00")
        )
        for i in range(n)
    ]


class TestNonResponsePendingDrain(unittest.TestCase):
    """NonResponseEvidenceProcessor.process must drain pending_unstakes
    post-Tier-33 and leave it untouched pre-Tier-33."""

    def setUp(self):
        self.target = Entity.create(b"t33-nr-target".ljust(32, b"\x00"))
        self.client = Entity.create(b"t33-nr-client".ljust(32, b"\x00"))
        self.submitter = Entity.create(
            b"t33-nr-submitter".ljust(32, b"\x00")
        )
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
        # Default 1M stake; tests override staked + pending to exercise
        # the evasion shape.
        self.chain.supply.staked[self.target.entity_id] = 1_000_000
        # Force the curve's repeat-multiplier ramp by pre-bumping the
        # offense counter — otherwise first-offense AMBIGUOUS lands at
        # ~5% × 1M = 50K which is below typical post-unstake staked
        # caps and the evasion-vs-no-evasion gap is hidden.  This
        # mirrors the threat model from CLAUDE.md: a colluding
        # validator with priors who continues to violate.
        self.chain.slash_offense_counts[self.target.entity_id] = 2

        self.witnesses = _make_witnesses(WITNESS_QUORUM, b"pd")
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 1_000_000

    def _make_evidence(self, observed_height: int, seed: bytes):
        req = sign_submission_request(
            submitter=self.client,
            target_validator_id=self.target.entity_id,
            tx_hash=_h(b"t33-nr-tx-" + seed),
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

    def test_pre_tier33_pending_unstakes_untouched(self):
        """Below Tier 33 (curve graded but stake-only basis):
        pending_unstakes MUST stay frozen — replay determinism."""
        # Park 70% of stake in pending_unstakes — the evasion shape.
        self.chain.supply.staked[self.target.entity_id] = 300_000
        self.chain.supply.pending_unstakes[self.target.entity_id] = [
            (700_000, 99_999),
        ]
        pending_before = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes[self.target.entity_id]
        )

        etx = self._make_evidence(observed_height=PRE_T33 - 50, seed=b"pre")
        proc = NonResponseEvidenceProcessor()
        with _force_chain_height(self.chain, PRE_T33):
            result = proc.process(etx, self.chain, PRE_T33)
        self.assertTrue(result.slashed, result.reason)
        pending_after = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes.get(self.target.entity_id, [])
        )
        self.assertEqual(
            pending_after, pending_before,
            "Pre-Tier-33: pending_unstakes MUST be untouched — replay "
            "byte-identity vs Tier 32-only behavior.",
        )

    def test_post_tier33_drains_both_buckets(self):
        """At/above Tier 33: pending_unstakes drained alongside
        `staked`, proportionally to bucket balance."""
        self.chain.supply.staked[self.target.entity_id] = 300_000
        self.chain.supply.pending_unstakes[self.target.entity_id] = [
            (700_000, 99_999),
        ]
        staked_before = self.chain.supply.staked[self.target.entity_id]
        pending_before = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes[self.target.entity_id]
        )
        total_supply_before = self.chain.supply.total_supply

        etx = self._make_evidence(
            observed_height=POST_T33 - 50, seed=b"post",
        )
        proc = NonResponseEvidenceProcessor()
        with _force_chain_height(self.chain, POST_T33):
            result = proc.process(etx, self.chain, POST_T33)
        self.assertTrue(result.slashed, result.reason)

        staked_after = self.chain.supply.staked.get(self.target.entity_id, 0)
        pending_after = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes.get(self.target.entity_id, [])
        )
        burn_total = (
            (staked_before + pending_before)
            - (staked_after + pending_after)
        )
        self.assertGreater(burn_total, 0, "Slash must actually burn stake.")
        self.assertLess(
            staked_after, staked_before,
            "Staked must shrink.",
        )
        self.assertLess(
            pending_after, pending_before,
            "Pending MUST also shrink — the censor-then-unstake evasion "
            "is what Tier 33 closes.",
        )
        self.assertEqual(
            total_supply_before - self.chain.supply.total_supply,
            burn_total,
            "total_supply must shrink by exactly the slashed amount.",
        )

    def test_post_tier33_unstake_then_drop_evasion_fails(self):
        """Headline scenario: a target validator silently drops the
        witnessed submission, then unstakes 90% before evidence
        matures.  Pre-Tier-33 the slash hit only the 10% that remained
        in `staked`; post-Tier-33 the slash hits the (staked + pending)
        basis as if the unstake had never happened."""
        # Realistic evasion split: 10% staked, 90% pending.
        self.chain.supply.staked[self.target.entity_id] = 100_000
        self.chain.supply.pending_unstakes[self.target.entity_id] = [
            (900_000, 99_999),
        ]
        # Compute the would-be slash if pending were ignored: capped at
        # current staked.  Compute the actual post-Tier-33 slash and
        # confirm it materially exceeds the pre-Tier-33 cap.
        staked_only_cap = self.chain.supply.staked[self.target.entity_id]

        etx = self._make_evidence(
            observed_height=POST_T33 - 50, seed=b"evasion",
        )
        proc = NonResponseEvidenceProcessor()
        with _force_chain_height(self.chain, POST_T33):
            result = proc.process(etx, self.chain, POST_T33)
        self.assertTrue(result.slashed, result.reason)

        # The pending bucket MUST be partially drained — without that,
        # 90% of the offender's would-be slash escaped.
        pending_after = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes.get(self.target.entity_id, [])
        )
        pending_burn = 900_000 - pending_after
        self.assertGreater(
            pending_burn, 0,
            "Tier 33 anchor: pending bucket must be partially drained "
            "to defeat the unstake-evasion attack.",
        )
        # Total burn must exceed what the legacy stake-only cap would
        # have allowed (a sub-T33 node could not have burned more than
        # staked_only_cap).  Tier 33's whole point is to break that
        # cap.
        self.assertGreater(
            result.slash_amount, staked_only_cap,
            "Total Tier-33 slash must exceed the legacy staked-only "
            "cap — that's the entire point of widening the basis.",
        )


# ────────────────────────────────────────────────────────────────────
# Bogus-rejection apply path — Tier 33 pending-unstake drain.
# ────────────────────────────────────────────────────────────────────


class TestBogusRejectionPendingDrain(unittest.TestCase):
    """BogusRejectionProcessor.process must drain pending_unstakes
    post-Tier-33 and leave it untouched pre-Tier-33."""

    def setUp(self):
        self.alice = Entity.create(b"t33-br-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"t33-br-bob".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10_000_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000_000
        self.chain.supply.staked[self.alice.entity_id] = 1_000_000
        # Pre-bump the offense counter so the curve produces a
        # non-trivial sev_pct on first-offense replay; otherwise the
        # base 5% × 1M = 50K is below typical evasion-shape staked
        # caps and the test cannot distinguish drained-from-pending
        # vs not.
        self.chain.slash_offense_counts[self.alice.entity_id] = 2

        self.alice_receipt_kp = KeyPair.generate(
            seed=b"receipt-subtree-t33-br-alice",
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

    def test_pre_tier33_pending_unstakes_untouched(self):
        """Below Tier 33: pending_unstakes MUST stay frozen — replay
        determinism vs the Tier 32-only path."""
        self.chain.supply.staked[self.alice.entity_id] = 300_000
        self.chain.supply.pending_unstakes[self.alice.entity_id] = [
            (700_000, 99_999),
        ]
        pending_before = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes[self.alice.entity_id]
        )

        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        proc = BogusRejectionProcessor()
        with _force_chain_height(self.chain, PRE_T33):
            result = proc.process(etx, self.chain, block_height=PRE_T33)
        self.assertTrue(result.slashed, result.reason)
        pending_after = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes.get(self.alice.entity_id, [])
        )
        self.assertEqual(
            pending_after, pending_before,
            "Pre-Tier-33: pending_unstakes MUST be untouched.",
        )

    def test_post_tier33_drains_both_buckets(self):
        """At/above Tier 33: bogus-rejection slash drains both
        buckets."""
        self.chain.supply.staked[self.alice.entity_id] = 300_000
        self.chain.supply.pending_unstakes[self.alice.entity_id] = [
            (700_000, 99_999),
        ]
        staked_before = self.chain.supply.staked[self.alice.entity_id]
        pending_before = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes[self.alice.entity_id]
        )
        total_supply_before = self.chain.supply.total_supply

        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        proc = BogusRejectionProcessor()
        with _force_chain_height(self.chain, POST_T33):
            result = proc.process(etx, self.chain, block_height=POST_T33)
        self.assertTrue(result.slashed, result.reason)

        staked_after = self.chain.supply.staked.get(self.alice.entity_id, 0)
        pending_after = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes.get(self.alice.entity_id, [])
        )
        burn_total = (
            (staked_before + pending_before)
            - (staked_after + pending_after)
        )
        self.assertGreater(burn_total, 0)
        self.assertLess(staked_after, staked_before)
        self.assertLess(
            pending_after, pending_before,
            "Pending MUST be drained — Tier 33 closes the unstake "
            "evasion on bogus-rejection censorship.",
        )
        self.assertEqual(
            total_supply_before - self.chain.supply.total_supply,
            burn_total,
        )

    def test_post_tier33_unstake_then_forge_evasion_fails(self):
        """Realistic evasion: forge a REJECT_INVALID_SIG on a victim's
        tx, then unstake 90% before evidence matures.  Post-Tier-33
        the burn must exceed the legacy staked-only cap."""
        self.chain.supply.staked[self.alice.entity_id] = 100_000
        self.chain.supply.pending_unstakes[self.alice.entity_id] = [
            (900_000, 99_999),
        ]
        staked_only_cap = self.chain.supply.staked[self.alice.entity_id]

        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = self._sign_evidence(self.bob, rej, mtx)
        proc = BogusRejectionProcessor()
        with _force_chain_height(self.chain, POST_T33):
            result = proc.process(etx, self.chain, block_height=POST_T33)
        self.assertTrue(result.slashed, result.reason)

        pending_after = sum(
            amt for amt, _ in
            self.chain.supply.pending_unstakes.get(self.alice.entity_id, [])
        )
        pending_burn = 900_000 - pending_after
        self.assertGreater(
            pending_burn, 0,
            "Pending bucket must be drained to defeat unstake-evasion.",
        )
        self.assertGreater(
            result.slash_amount, staked_only_cap,
            "Total Tier-33 slash must exceed the legacy staked-only "
            "cap — Tier 33 widens the basis precisely to break that cap.",
        )


if __name__ == "__main__":
    unittest.main()
