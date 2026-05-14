"""Audit r58 #1 (security top-1) -- three slashing / inclusion
re-verify paths still read ``public_keys.get(entity_id)`` (single
CURRENT key) while the existing ``_verify_signer_at_height``
multi-key chokepoint (audit r50 #2) covers only Attestation +
FinalityVote validation / gossip.

A colluding entity that rotates between observation-time and
apply-time silently invalidates the verify, defeating the chain's
headline censorship-resistance defense.  ``KEY_ROTATION_COOLDOWN
_BLOCKS = 144`` is short enough to make the timing trivial.

CLAUDE.md anchors at risk:
  * Collective censorship-resistance (slashable evidence is the
    structural defense against validator collusion; rotation-bypass
    silently launders the slash).
  * Honest-operator insurance (an honest reporter / witness who
    rotates legitimately should not have their on-chain action
    silently dropped).
  * Crypto-agility (rotation is the mechanism via which signature
    schemes migrate; "future identity-adjacent features must
    preserve the 'one live key at a time' invariant" -- preserving
    identity means in-flight signed messages from prior keys must
    remain verifiable).

Tier 80 (activation height ``MULTI_KEY_RE_VERIFY_HEIGHT = 22500``)
routes the three sites through the multi-key candidate set:

  * pre-fork: legacy single-current-key behaviour  (byte-identical
    to historical replay)
  * post-fork: try every key the entity ever held + the current
    key, accept if ANY matches; on InclusionList, a report whose
    sig fails all candidates is DROPPED (fail-soft) rather than
    failing the whole list

Adding a new signed-re-verify site that builds its own candidate
set instead of routing through ``Blockchain._candidate_keys_for``
reintroduces the same defect class by definition.
"""

from __future__ import annotations

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO, MIN_FEE,
    WITNESS_SURCHARGE,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    INCLUSION_LIST_WINDOW,
    MULTI_KEY_RE_VERIFY_HEIGHT,
    SLASHABLE_BASIS_AT_ADMISSION_HEIGHT,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import (
    create_transaction, MessageTransaction,
)
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    build_attester_mempool_report,
    aggregate_inclusion_list,
    verify_inclusion_list_quorum,
)
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
from messagechain.consensus.bogus_rejection_evidence import (
    BogusRejectionEvidenceTx,
    BogusRejectionProcessor,
)
from messagechain.network.submission_receipt import (
    ReceiptIssuer, REJECT_INVALID_SIG,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _install_rotated_state(
    chain: Blockchain, eid: bytes,
    old_pk: bytes, new_pk: bytes,
    old_installed_at: int, new_installed_at: int,
) -> None:
    """Same pattern as test_audit_r50_signed_at_height_verify --
    install K_old in history at ``old_installed_at``, K_new in history
    AND public_keys at ``new_installed_at``, simulating that the
    entity rotated keys on chain after signing under K_old."""
    chain.public_keys[eid] = new_pk
    chain.key_history[eid] = [
        (old_installed_at, old_pk),
        (new_installed_at, new_pk),
    ]


class TestTier80HeightConstant(unittest.TestCase):
    """The activation height MUST sit strictly above Tier 79 with the
    anchored ~13.9-day cohort spacing.  A regression here means the
    fork rolls out alongside (or before) an unrelated cohort, which
    operators absorb as a single upgrade -- exactly what cohort
    spacing exists to prevent."""

    def test_constant_exists_and_follows_tier_79(self):
        self.assertEqual(MULTI_KEY_RE_VERIFY_HEIGHT, 22500)
        self.assertGreater(
            MULTI_KEY_RE_VERIFY_HEIGHT,
            SLASHABLE_BASIS_AT_ADMISSION_HEIGHT,
        )
        self.assertEqual(
            MULTI_KEY_RE_VERIFY_HEIGHT
            - SLASHABLE_BASIS_AT_ADMISSION_HEIGHT,
            2000,
            "Tier 80 must follow Tier 79 by 2000 blocks (~13.9 days)",
        )


class TestCandidateKeysHelperExists(unittest.TestCase):
    """Single chokepoint -- adding a new signed-re-verify site that
    constructs its own candidate set instead of calling
    ``_candidate_keys_for`` reintroduces the audit r58 #1 defect by
    definition.  The pin is structural."""

    def test_blockchain_exposes_candidate_keys_for(self):
        self.assertTrue(
            hasattr(Blockchain, "_candidate_keys_for"),
            "Blockchain must expose _candidate_keys_for as the single "
            "chokepoint for multi-key re-verify (audit r58 #1).",
        )

    def test_returns_history_plus_current_deduped(self):
        chain = Blockchain()
        a = Entity.create(b"r58-cand-a".ljust(32, b"\x00"))
        b = Entity.create(b"r58-cand-b".ljust(32, b"\x00"))
        eid = a.entity_id
        _install_rotated_state(
            chain, eid,
            old_pk=a.public_key, new_pk=b.public_key,
            old_installed_at=0, new_installed_at=5,
        )
        cands = chain._candidate_keys_for(eid)
        self.assertIn(a.public_key, cands)
        self.assertIn(b.public_key, cands)
        # Idempotent dedup: re-running gives same result.
        cands2 = chain._candidate_keys_for(eid)
        self.assertEqual(cands, cands2)

    def test_returns_empty_for_unknown_entity(self):
        chain = Blockchain()
        unknown = Entity.create(b"r58-cand-unk".ljust(32, b"\x00")).entity_id
        self.assertEqual(chain._candidate_keys_for(unknown), [])


class TestInclusionListMultiKeyVerify(unittest.TestCase):
    """Behavioural pin for site #1: an InclusionList whose reporter
    signed under K_old before rotating must verify under multi-key
    (post-fork) and fail under single-current-key (pre-fork)."""

    def _build_quorum_list_with_rotating_reporter(self):
        # Build with 4 validators: v_rot signed report under K_old,
        # then rotated to K_new on chain.  v_a / v_b / v_c never
        # rotated.  Four reporters chosen so that dropping the bad-sig
        # one still leaves 3/4 = 75% > INCLUSION_LIST_QUORUM_BPS (66.67%).
        v_rot_old = Entity.create(b"r58-il-rot-old".ljust(32, b"\x00"))
        v_rot_new = Entity.create(b"r58-il-rot-new".ljust(32, b"\x00"))
        v_a = Entity.create(b"r58-il-va".ljust(32, b"\x00"))
        v_b = Entity.create(b"r58-il-vb".ljust(32, b"\x00"))
        v_c = Entity.create(b"r58-il-vc".ljust(32, b"\x00"))

        # The reporter that's about to rotate uses entity_id of v_rot_old
        # (their identity), but signs the report with K_old.
        target_tx = _h(b"r58-il-target-tx")
        reports = [
            build_attester_mempool_report(
                v_rot_old, report_height=10, tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                v_a, report_height=10, tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                v_b, report_height=10, tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                v_c, report_height=10, tx_hashes=[target_tx],
            ),
        ]
        stakes = {
            v_rot_old.entity_id: 1_000_000,
            v_a.entity_id: 1_000_000,
            v_b.entity_id: 1_000_000,
            v_c.entity_id: 1_000_000,
        }
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        return (
            lst, stakes, v_rot_old, v_rot_new, v_a, v_b, v_c,
        )

    def test_legacy_single_key_rejects_after_rotation(self):
        (
            lst, stakes, v_rot_old, v_rot_new, v_a, v_b, v_c,
        ) = self._build_quorum_list_with_rotating_reporter()
        # Pre-fork public_keys map: v_rot_old has rotated to K_new on
        # chain (legacy verifier sees only the new key for that eid).
        public_keys = {
            v_rot_old.entity_id: v_rot_new.public_key,  # rotated
            v_a.entity_id: v_a.public_key,
            v_b.entity_id: v_b.public_key,
            v_c.entity_id: v_c.public_key,
        }
        ok, reason = verify_inclusion_list_quorum(
            lst, stakes=stakes, public_keys=public_keys,
        )
        # Legacy path: whole-list reject on bad sig.
        self.assertFalse(
            ok,
            "Pre-fork: a rotation-affected report must fail the "
            "legacy single-current-key check (byte-identical replay)",
        )
        self.assertIn("invalid signature", reason.lower())

    def test_multi_key_accepts_rotated_reporter_post_fork(self):
        (
            lst, stakes, v_rot_old, v_rot_new, v_a, v_b, v_c,
        ) = self._build_quorum_list_with_rotating_reporter()
        chain = Blockchain()
        # On-chain: v_rot_old's entity rotated K_old -> K_new at h=11.
        _install_rotated_state(
            chain, v_rot_old.entity_id,
            old_pk=v_rot_old.public_key,
            new_pk=v_rot_new.public_key,
            old_installed_at=0, new_installed_at=11,
        )
        # Plain registrations for the non-rotating reporters.
        chain.public_keys[v_a.entity_id] = v_a.public_key
        chain.public_keys[v_b.entity_id] = v_b.public_key
        chain.public_keys[v_c.entity_id] = v_c.public_key

        ok, reason = verify_inclusion_list_quorum(
            lst,
            stakes=stakes,
            public_keys=chain.public_keys,
            signer_resolver=chain._candidate_keys_for,
        )
        self.assertTrue(
            ok,
            f"Post-fork: multi-key candidate set MUST accept a report "
            f"whose signer rotated between report_height and "
            f"publish_height (got: {reason})",
        )

    def test_multi_key_drops_bad_sig_report_fail_soft(self):
        """If a report's sig fails every candidate, the report is
        DROPPED (fail-soft) -- the rest of the bundle keeps tallying.
        Without fail-soft, a single malformed report still kills the
        whole list."""
        (
            lst, stakes, v_rot_old, v_rot_new, v_a, v_b, v_c,
        ) = self._build_quorum_list_with_rotating_reporter()
        chain = Blockchain()
        # v_rot_old has NO key history at all -- multi-key resolver
        # returns empty.  Other two reporters are healthy.
        chain.public_keys[v_a.entity_id] = v_a.public_key
        chain.public_keys[v_b.entity_id] = v_b.public_key
        chain.public_keys[v_c.entity_id] = v_c.public_key
        # v_rot_old not registered: signer_resolver returns [] for it.

        ok, reason = verify_inclusion_list_quorum(
            lst,
            stakes=stakes,
            public_keys=chain.public_keys,
            signer_resolver=chain._candidate_keys_for,
        )
        # v_rot_old's report dropped (no candidate keys); v_a + v_b
        # still provide stake-weighted quorum 2/3.
        self.assertTrue(
            ok,
            f"Post-fork: a bad-sig / unknown-reporter report MUST be "
            f"dropped fail-soft so the remaining reports can tally "
            f"to quorum (got: {reason})",
        )


class TestBogusRejectionMultiKeyVerify(unittest.TestCase):
    """Behavioural pin for site #3: a BogusRejection over a
    message_tx signed under the sender's K_old before they rotated
    must still slash the lying validator post-fork."""

    def _make_receipt_subtree_keypair(self, seed_tag: bytes) -> KeyPair:
        return KeyPair.generate(
            seed=b"r58-rcp-" + seed_tag, height=4,
        )

    def _sign_evidence(
        self, submitter, rejection, message_tx,
    ) -> BogusRejectionEvidenceTx:
        placeholder = Signature([], 0, [], b"", b"")
        tx = BogusRejectionEvidenceTx(
            rejection=rejection,
            message_tx=message_tx,
            submitter_id=submitter.entity_id,
            timestamp=int(time.time()),
            fee=MIN_FEE,
            signature=placeholder,
        )
        msg_hash = _h(tx._signable_data())
        tx.signature = submitter.keypair.sign(msg_hash)
        tx.tx_hash = tx._compute_hash()
        return tx

    def test_legacy_single_key_treats_rotated_sender_as_honest_rejection(self):
        """Pre-fork: when the sender rotated, the legacy single-current-
        key recheck of the message_tx fails -- the lying validator
        escapes slashing.  This is the defect the post-fork branch
        closes; documented here for byte-identical replay."""
        validator = Entity.create(b"r58-br-val".ljust(32, b"\x00"))
        sender_old = Entity.create(b"r58-br-sold".ljust(32, b"\x00"))
        sender_new = Entity.create(b"r58-br-snew".ljust(32, b"\x00"))
        validator.keypair._next_leaf = 0
        sender_old.keypair._next_leaf = 0

        chain = Blockchain()
        chain.initialize_genesis(validator)
        # Sender's identity = entity_id of sender_old; signs a real
        # message_tx with K_old, then rotates to K_new on chain.
        register_entity_for_test(chain, sender_old)
        chain.supply.balances[validator.entity_id] = 1_000_000
        chain.supply.balances[sender_old.entity_id] = 1_000_000
        chain.supply.staked[validator.entity_id] = 100_000

        rcp_kp = self._make_receipt_subtree_keypair(b"legacy")
        chain.receipt_subtree_roots[validator.entity_id] = rcp_kp.public_key

        # Sender signs message_tx with K_old.
        mtx = create_transaction(sender_old, "hi", MIN_FEE + 100, nonce=0)
        # Then rotates on chain (force the rotation into state).
        _install_rotated_state(
            chain, sender_old.entity_id,
            old_pk=sender_old.public_key,
            new_pk=sender_new.public_key,
            old_installed_at=0, new_installed_at=chain.height + 1,
        )

        # Validator lies: REJECT_INVALID_SIG on a valid message_tx.
        issuer = ReceiptIssuer(
            validator.entity_id, rcp_kp,
            height_fn=lambda: chain.height,
        )
        rej = issuer.issue_rejection(mtx.tx_hash, REJECT_INVALID_SIG)
        etx = self._sign_evidence(sender_old, rej, mtx)

        proc = BogusRejectionProcessor()
        # Pre-fork block_height (below Tier 80 activation):
        pre_fork_h = MULTI_KEY_RE_VERIFY_HEIGHT - 1
        result = proc.process(etx, chain, block_height=pre_fork_h)
        self.assertFalse(
            result.slashed,
            "Pre-fork (legacy single-current-key path) MUST NOT slash "
            "-- documents the defect's byte-identical legacy behaviour",
        )
        self.assertIn("honest rejection", result.reason.lower())

    def test_post_fork_multi_key_slashes_lying_validator(self):
        """Post-fork: same scenario, multi-key recheck finds the
        message_tx verifies under K_old (in history), refutes the
        REJECT_INVALID_SIG, slashes the validator."""
        validator = Entity.create(b"r58-br-val2".ljust(32, b"\x00"))
        sender_old = Entity.create(b"r58-br-sold2".ljust(32, b"\x00"))
        sender_new = Entity.create(b"r58-br-snew2".ljust(32, b"\x00"))
        validator.keypair._next_leaf = 0
        sender_old.keypair._next_leaf = 0

        chain = Blockchain()
        chain.initialize_genesis(validator)
        register_entity_for_test(chain, sender_old)
        chain.supply.balances[validator.entity_id] = 1_000_000
        chain.supply.balances[sender_old.entity_id] = 1_000_000
        chain.supply.staked[validator.entity_id] = 100_000

        rcp_kp = self._make_receipt_subtree_keypair(b"postfork")
        chain.receipt_subtree_roots[validator.entity_id] = rcp_kp.public_key

        mtx = create_transaction(sender_old, "hi", MIN_FEE + 100, nonce=0)
        _install_rotated_state(
            chain, sender_old.entity_id,
            old_pk=sender_old.public_key,
            new_pk=sender_new.public_key,
            old_installed_at=0, new_installed_at=chain.height + 1,
        )

        issuer = ReceiptIssuer(
            validator.entity_id, rcp_kp,
            height_fn=lambda: chain.height,
        )
        rej = issuer.issue_rejection(mtx.tx_hash, REJECT_INVALID_SIG)
        etx = self._sign_evidence(sender_old, rej, mtx)

        proc = BogusRejectionProcessor()
        post_fork_h = MULTI_KEY_RE_VERIFY_HEIGHT + 1
        result = proc.process(etx, chain, block_height=post_fork_h)
        self.assertTrue(
            result.slashed,
            f"Post-fork: multi-key recheck MUST verify the message_tx "
            f"under K_old (in history) and slash the lying validator "
            f"(got reason: {result.reason})",
        )
        self.assertEqual(result.offender_id, validator.entity_id)


class TestNonResponseEvidenceMultiKeyVerify(unittest.TestCase):
    """Behavioural pin for site #2: NRE process() must accept witness
    observations signed under K_old after the witness rotated."""

    def _make_request(
        self, client: Entity, target_id: bytes,
        nonce_seed: bytes = b"\x01",
    ) -> SubmissionRequest:
        return sign_submission_request(
            submitter=client,
            target_validator_id=target_id,
            tx_hash=_h(b"r58-nre-tx-" + nonce_seed),
            timestamp=int(time.time()),
            client_nonce=(nonce_seed * 16)[:16],
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )

    def _setup_chain_with_rotating_witness(self):
        target = Entity.create(b"r58-nre-target".ljust(32, b"\x00"))
        client = Entity.create(b"r58-nre-client".ljust(32, b"\x00"))
        submitter = Entity.create(b"r58-nre-submit".ljust(32, b"\x00"))
        target.keypair._next_leaf = 0
        client.keypair._next_leaf = 0
        submitter.keypair._next_leaf = 0

        chain = Blockchain()
        chain.initialize_genesis(target)
        register_entity_for_test(chain, client)
        register_entity_for_test(chain, submitter)
        chain.supply.balances[target.entity_id] = 1_000_000
        chain.supply.balances[client.entity_id] = 1_000_000
        chain.supply.balances[submitter.entity_id] = 1_000_000
        chain.supply.staked[target.entity_id] = 100_000

        # WITNESS_QUORUM witnesses; the first one will rotate.
        witnesses = []
        for i in range(WITNESS_QUORUM):
            w = Entity.create(
                (b"r58-nre-w" + str(i).encode()).ljust(32, b"\x00"),
            )
            w.keypair._next_leaf = 0
            register_entity_for_test(chain, w)
            chain.supply.staked[w.entity_id] = 100_000
            witnesses.append(w)
        # Tier 78 active-set check reads ``_stake_snapshots[observed_
        # height]`` post-fork.  Pin a snapshot at chain.height (the
        # observed_height every witness will sign for) so the
        # retroactive active-set gate finds every witness.
        chain._stake_snapshots[chain.height] = {
            w.entity_id: 100_000 for w in witnesses
        }
        # The "new key" the first witness rotates into.
        w0_new = Entity.create(b"r58-nre-w0-new".ljust(32, b"\x00"))
        return chain, target, client, submitter, witnesses, w0_new

    def test_legacy_single_key_drops_rotated_witness(self):
        """Pre-fork: a witness who rotates between observed_height
        and apply-time has their observation silently dropped --
        bringing the quorum count below WITNESS_QUORUM and dismissing
        the slash.  Documents the byte-identical legacy behaviour."""
        (
            chain, target, client, submitter, witnesses, w0_new,
        ) = self._setup_chain_with_rotating_witness()
        observed_height = chain.height  # all witness obs signed here

        observations = [
            sign_witness_observation(w, _h(b"req"), observed_height)
            for w in witnesses
        ]
        # Build a real request matching the obs (request_hash).
        req = self._make_request(client, target.entity_id)
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height)
            for w in witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )

        # First witness now rotates to w0_new (legacy verifier sees
        # only the new key for that entity).
        w0 = witnesses[0]
        _install_rotated_state(
            chain, w0.entity_id,
            old_pk=w0.public_key, new_pk=w0_new.public_key,
            old_installed_at=observed_height,
            new_installed_at=observed_height + 1,
        )

        proc = NonResponseEvidenceProcessor()
        pre_fork_h = MULTI_KEY_RE_VERIFY_HEIGHT - 1
        # observed_height + deadline + a little headroom, but still
        # below Tier-80 activation.  We need
        # observed_height + WITNESS_RESPONSE_DEADLINE_BLOCKS
        # < pre_fork_h, which is true since observed_height=0 and
        # the deadline is small (~8 blocks).
        self.assertLess(
            observed_height + WITNESS_RESPONSE_DEADLINE_BLOCKS,
            pre_fork_h,
            "Setup invariant: deadline must have passed at pre_fork_h",
        )
        result = proc.process(etx, chain, current_height=pre_fork_h)
        # WITNESS_QUORUM is typically 2; rotating one witness drops
        # valid count to WITNESS_QUORUM - 1 < quorum.
        self.assertFalse(
            result.accepted,
            "Pre-fork: a rotated witness's obs is silently dropped, "
            "quorum should fall short",
        )
        self.assertIn("quorum", result.reason.lower())

    def test_post_fork_multi_key_accepts_rotated_witness(self):
        """Post-fork: multi-key recheck verifies the obs under K_old
        (in history), keeps quorum, slashes the target."""
        (
            chain, target, client, submitter, witnesses, w0_new,
        ) = self._setup_chain_with_rotating_witness()
        observed_height = chain.height

        req = self._make_request(client, target.entity_id)
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height)
            for w in witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )

        w0 = witnesses[0]
        _install_rotated_state(
            chain, w0.entity_id,
            old_pk=w0.public_key, new_pk=w0_new.public_key,
            old_installed_at=observed_height,
            new_installed_at=observed_height + 1,
        )

        proc = NonResponseEvidenceProcessor()
        post_fork_h = MULTI_KEY_RE_VERIFY_HEIGHT + 1
        result = proc.process(etx, chain, current_height=post_fork_h)
        self.assertTrue(
            result.accepted,
            f"Post-fork: multi-key recheck MUST accept rotated "
            f"witness's obs (got reason: {result.reason})",
        )
        self.assertTrue(result.slashed, result.reason)
        self.assertEqual(result.offender_id, target.entity_id)


if __name__ == "__main__":
    unittest.main()
