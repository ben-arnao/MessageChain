"""Audit r56 #1 — Tier 78 retroactive-evidence stake-pin defense.

Closes the sock-puppet collusion vector where an attacker who freshly
stakes ``WITNESS_QUORUM`` puppet validators TODAY can sign retroactive
``WitnessObservation``s for a past ``observed_height`` at which they
were NOT in the active set, and drive a NonResponseEvidenceTx through
admission against a victim.  The same shape applies to InclusionList
quorum verification: a recent-stake attacker could inflate per-entry
stake support by counting stake that wasn't present when the report
was signed.

Tier 78 routes both retroactive checks through the pinned stake
snapshot at the relevant past height instead of the live
``supply.staked`` map.  Pre-fork the legacy current-stake read runs
unchanged for replay determinism.

CLAUDE.md anchors at risk pre-fix:
  * "Collective censorship-resistance" — fabricated slashable
    evidence against honest validators erodes the structural defense
    even though the consensus rule against equivocation is correct.
  * "Honest operators are insured" — a long-tenured operator with no
    malicious intent could be slashed by an attacker who freshly
    staked sock-puppets minutes before submitting evidence.
"""

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    MIN_FEE,
    WITNESS_SURCHARGE,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    VALIDATOR_MIN_STAKE,
    RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT,
    PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT,
    INCLUSION_LIST_WAIT_BLOCKS,
    INCLUSION_LIST_QUORUM_BPS,
)
from messagechain.identity.identity import Entity
from messagechain.consensus.witness_submission import (
    SubmissionRequest,
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceTx,
    NonResponseEvidenceProcessor,
    sign_non_response_evidence,
)
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    build_attester_mempool_report,
    verify_inclusion_list_quorum,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_request(client: Entity, target_id: bytes,
                  nonce_seed: bytes = b"\x01") -> SubmissionRequest:
    return sign_submission_request(
        submitter=client,
        target_validator_id=target_id,
        tx_hash=_h(b"r56-payload-" + nonce_seed),
        timestamp=int(time.time()),
        client_nonce=(nonce_seed * 16)[:16],
        fee=MIN_FEE + WITNESS_SURCHARGE,
    )


class TestTier78Ordering(unittest.TestCase):
    """Constraint test pinning Tier 78 cohort spacing."""

    def test_tier78_follows_tier77(self):
        self.assertGreater(
            RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT,
            PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT,
            "Tier 78 retroactive-evidence stake pin must follow Tier 77 "
            "to preserve the cohort cadence operators absorb each fork in",
        )


class TestStakeAtHeightHelper(unittest.TestCase):
    """The new ``_stake_at_height`` chokepoint reads the pinned snapshot
    and is strict on miss (returns 0 — fail-safe to "not staked")."""

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.genesis = Entity.create(b"genesis-r56-helper".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.genesis)

    def test_returns_snapshot_value_when_pinned(self):
        eid = b"E" * 32
        self.chain._stake_snapshots[100] = {eid: 555_000}
        self.assertEqual(self.chain._stake_at_height(eid, 100), 555_000)

    def test_returns_zero_on_snapshot_miss(self):
        # Snapshot unavailable for height 200 — strict fail-safe to 0.
        self.assertEqual(self.chain._stake_at_height(b"M" * 32, 200), 0)

    def test_returns_zero_for_unknown_entity_in_snapshot(self):
        self.chain._stake_snapshots[42] = {b"X" * 32: 1_000_000}
        self.assertEqual(self.chain._stake_at_height(b"Y" * 32, 42), 0)

    def test_distinguishable_from_pinned_stake_at_live_fallback(self):
        # _pinned_stake_at falls back to live supply.staked on miss; the
        # new helper does NOT (returns 0 explicitly). This asymmetry is
        # load-bearing: retroactive evidence must NOT count fresh stake.
        live_id = b"L" * 32
        self.chain.supply.staked[live_id] = 999_999
        # No snapshot for height 50.
        self.assertEqual(self.chain._stake_at_height(live_id, 50), 0)
        # ...but _pinned_stake_at returns the live map.
        self.assertEqual(
            self.chain._pinned_stake_at(50).get(live_id, 0),
            999_999,
        )


class TestNonResponsePreForkLegacy(unittest.TestCase):
    """Pre-fork (current_height < RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT)
    the witness active-set filter reads live ``supply.staked``, byte-
    identical to legacy."""

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.target = Entity.create(b"v-pre-target".ljust(32, b"\x00"))
        self.client = Entity.create(b"v-pre-client".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"v-pre-submit".ljust(32, b"\x00"))
        for e in (self.target, self.client, self.submitter):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        self.chain.supply.balances[self.target.entity_id] = 1_000_000
        self.chain.supply.staked[self.target.entity_id] = 100_000
        self.witnesses = [
            Entity.create((b"v-pre-w" + str(i).encode()).ljust(32, b"\x00"))
            for i in range(WITNESS_QUORUM)
        ]
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            # Witnesses currently staked.
            self.chain.supply.staked[w.entity_id] = VALIDATOR_MIN_STAKE

    def test_pre_fork_uses_current_stake(self):
        # observed_height is far in the past, and we pin NO snapshot for
        # it. Pre-fork, only the CURRENT staked map matters — witnesses
        # are staked now, so the evidence should still pass active-set
        # filter and slash.
        req = _make_request(self.client, self.target.entity_id, b"\x77")
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=5)
            for w in self.witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        proc = NonResponseEvidenceProcessor()
        # current_height < Tier 78 activation
        pre_fork_h = RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT - 100
        self.assertGreater(
            pre_fork_h, 5 + WITNESS_RESPONSE_DEADLINE_BLOCKS,
            "test prerequisite",
        )
        result = proc.process(etx, self.chain, pre_fork_h)
        self.assertTrue(result.accepted, result.reason)
        self.assertTrue(result.slashed, result.reason)


class TestNonResponsePostForkPinnedSnapshot(unittest.TestCase):
    """Post-fork (current_height >= RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT)
    the witness active-set filter reads the pinned snapshot AT the
    witness's observed_height, NOT the current live map."""

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.target = Entity.create(b"v-post-target".ljust(32, b"\x00"))
        self.client = Entity.create(b"v-post-client".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"v-post-submit".ljust(32, b"\x00"))
        for e in (self.target, self.client, self.submitter):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        self.chain.supply.balances[self.target.entity_id] = 1_000_000
        self.chain.supply.staked[self.target.entity_id] = 100_000
        self.witnesses = [
            Entity.create((b"v-post-w" + str(i).encode()).ljust(32, b"\x00"))
            for i in range(WITNESS_QUORUM)
        ]
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)

    def test_post_fork_rejects_retroactive_sock_puppet_stake(self):
        # The attack: witnesses have CURRENT stake (sock-puppets staked
        # today) but at observed_height H_past their stake was 0.  Pre-
        # fork the live read admits them; post-fork the pinned-snapshot
        # read at H_past correctly rejects.
        observed_height = 5
        # Snapshot pinned at observed_height shows witnesses NOT yet
        # staked.
        self.chain._stake_snapshots[observed_height] = {
            self.target.entity_id: 100_000,
            # ...no witness entries — they hadn't staked yet.
        }
        # NOW (current chain state) the witnesses ARE staked (the
        # attacker's sock-puppets).
        for w in self.witnesses:
            self.chain.supply.staked[w.entity_id] = VALIDATOR_MIN_STAKE
        req = _make_request(self.client, self.target.entity_id, b"\x88")
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height)
            for w in self.witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        proc = NonResponseEvidenceProcessor()
        # current_height >= Tier 78 activation
        post_fork_h = RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT + 100
        result = proc.process(etx, self.chain, post_fork_h)
        # Active-set filter drops every witness (stake-at-observed = 0)
        # → < QUORUM remain → admission rejects.
        self.assertFalse(result.accepted, result.reason)
        self.assertFalse(result.slashed, result.reason)
        self.assertTrue(
            "quorum" in result.reason.lower()
            or "active" in result.reason.lower(),
            result.reason,
        )

    def test_post_fork_admits_legitimate_witness_staked_at_observed_height(self):
        # The legitimate path: witnesses ARE staked at observed_height
        # in the pinned snapshot — admission proceeds.
        observed_height = 7
        snap = {self.target.entity_id: 100_000}
        for w in self.witnesses:
            snap[w.entity_id] = VALIDATOR_MIN_STAKE
            # Witnesses also still staked today — typical case.
            self.chain.supply.staked[w.entity_id] = VALIDATOR_MIN_STAKE
        self.chain._stake_snapshots[observed_height] = snap
        req = _make_request(self.client, self.target.entity_id, b"\x99")
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height)
            for w in self.witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        proc = NonResponseEvidenceProcessor()
        post_fork_h = RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT + 100
        result = proc.process(etx, self.chain, post_fork_h)
        self.assertTrue(result.accepted, result.reason)
        self.assertTrue(result.slashed, result.reason)


class TestInclusionListVerifyStakePin(unittest.TestCase):
    """``_validate_inclusion_list_quorum`` post-fork sources the stake
    map from the snapshot pinned at ``publish_height - 1``, not from
    live ``supply.staked``.  Closes the recent-stake-attacker shape of
    the same defect."""

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.genesis = Entity.create(b"il-r56-genesis".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.genesis)
        # Four reporters; we'll vary their stake at publish_height-1 vs.
        # the live map to exercise the gate.
        self.reporters = [
            Entity.create((b"il-r56-r" + str(i).encode()).ljust(32, b"\x00"))
            for i in range(4)
        ]
        for r in self.reporters:
            r.keypair._next_leaf = 0
            register_entity_for_test(self.chain, r)

    def _build_il(self, publish_height: int, tx_hash: bytes,
                  reporter_stake: int) -> InclusionList:
        # All four reporters sign reports for tx_hash; with equal stake
        # each, all four contribute → 100% support, well over the
        # 2/3 quorum threshold.
        report_height = publish_height - 1
        reports = []
        for r in self.reporters:
            rep = build_attester_mempool_report(
                reporter_entity=r,
                tx_hashes=[tx_hash],
                report_height=report_height,
            )
            reports.append(rep)
        return InclusionList(
            publish_height=publish_height,
            window_blocks=4,  # INCLUSION_LIST_WINDOW
            entries=[InclusionListEntry(
                tx_hash=tx_hash, first_seen_height=report_height,
            )],
            quorum_attestation=reports,
        )

    def test_post_fork_uses_pinned_snapshot_at_publish_minus_one(self):
        publish_height = RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT + 50
        tx_h = _h(b"r56-il-tx-post")
        # Live supply.staked: reporters have NO stake (sock-puppet model
        # — they'd cheat by signing reports without being staked).
        for r in self.reporters:
            # Live state: NOT staked.
            self.chain.supply.staked.pop(r.entity_id, None)
        # Pinned snapshot at publish_height-1: reporters ARE legitimately
        # staked.  Production path: this is what `_validate_inclusion_
        # list_quorum` should consult post-fork.
        snap = {r.entity_id: VALIDATOR_MIN_STAKE for r in self.reporters}
        self.chain._stake_snapshots[publish_height - 1] = snap
        # Build a block with publish_height matching our scenario.
        from messagechain.core.block import Block, BlockHeader
        il = self._build_il(publish_height, tx_h, VALIDATOR_MIN_STAKE)
        block = Block(
            header=BlockHeader(
                version=2,
                block_number=publish_height,
                prev_hash=b"\x00" * 32,
                merkle_root=b"\x00" * 32,
                timestamp=float(int(time.time())),
                proposer_id=self.genesis.entity_id,
            ),
            transactions=[],
            attestations=[],
            inclusion_list=il,
        )
        ok, reason = self.chain._validate_inclusion_list_quorum(block)
        self.assertTrue(ok, reason)

    def test_post_fork_rejects_il_signed_by_unstaked_reporters_at_pin_height(self):
        publish_height = RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT + 60
        tx_h = _h(b"r56-il-tx-rej")
        # Live supply.staked: reporters appear staked (the sock-puppet
        # vector — staked today, hoping the verifier reads live state).
        for r in self.reporters:
            self.chain.supply.staked[r.entity_id] = VALIDATOR_MIN_STAKE
        # Pinned snapshot at publish_height-1: reporters NOT yet staked.
        self.chain._stake_snapshots[publish_height - 1] = {}
        from messagechain.core.block import Block, BlockHeader
        il = self._build_il(publish_height, tx_h, VALIDATOR_MIN_STAKE)
        block = Block(
            header=BlockHeader(
                version=2,
                block_number=publish_height,
                prev_hash=b"\x00" * 32,
                merkle_root=b"\x00" * 32,
                timestamp=float(int(time.time())),
                proposer_id=self.genesis.entity_id,
            ),
            transactions=[],
            attestations=[],
            inclusion_list=il,
        )
        ok, reason = self.chain._validate_inclusion_list_quorum(block)
        self.assertFalse(ok, reason)
        self.assertIn("inclusion list", reason.lower())


if __name__ == "__main__":
    unittest.main()
