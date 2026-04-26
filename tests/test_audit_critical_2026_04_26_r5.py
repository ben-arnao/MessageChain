"""Critical-severity audit fixes — round 5 (2026-04-26).

Eight CRITICALs surfaced by the round-5 audit, all addressed in this
commit:

1. SubmissionServer constructed without witness_observation_store --
   the obs_ok gate short-circuits to True for any 32-byte header,
   leaving only the per-IP ack budget which is botnet-bypassable.
   Fix: instantiate a store and pass it through.

2. _rpc_submit_transaction inlines its own validate+add path,
   bypassing receipt_issuer entirely.  RPC submissions get NO
   receipts/acks/rejections.  Fix: route through
   submit_transaction_to_mempool.

3. receipt_subtree_roots leaks across reorg (in-memory + on-disk).
   Same defect class as round-4 key_rotation_last_height leak.
   Fix: clear in _reset_state, wipe in restore_state_snapshot,
   capture in _snapshot_memory_state.

4. SetReceiptSubtreeRoot rotation invalidates ALL outstanding
   receipts/rejections (single-valued root, no history).  A coerced
   validator pre-emptively wipes evidence with one cold-key tx.
   Fix: keep history of past roots; receipt validation accepts ANY
   historical root.

5. Slashed-this-block validators' finality votes still count toward
   2/3.  Fix: skip survivors whose signer_entity_id is in
   slashed_validators (which has been updated by same-block slash
   apply, but BEFORE finality-vote apply).

6. Empty-entries inclusion list bypasses ALL quorum_attestation
   validation -- permanent on-chain ballast at zero fee.  Fix:
   require quorum_attestation to be empty when entries is empty.

7. v1 + v2 governance proposal pair on identical text creates two
   distinct proposal_ids, splitting votes.  Fix: post-Tier-15
   activation reject v1 governance tx admission.

8. Slow-loris on submission HTTPS / public-feed servers -- no
   socket read timeout.  Fix: set request handler timeout.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import tempfile
import threading
import unittest

import messagechain.config as config
from tests import register_entity_for_test
from messagechain.config import (
    GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT,
    HASH_ALGO,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.attestation import create_attestation
from messagechain.consensus.finality import (
    FinalityVote,
    create_finality_vote,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.governance.governance import (
    GOVERNANCE_TX_VERSION_LENGTH_PREFIX,
    GOVERNANCE_TX_VERSION_V1,
    ProposalTransaction,
    TreasurySpendTransaction,
    verify_proposal,
    verify_treasury_spend,
)
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1 — SubmissionServer must be constructed with witness_observation_store
# ─────────────────────────────────────────────────────────────────────

class TestSubmissionServerWiredWithWitnessObservationStore(unittest.TestCase):
    """server.py production wiring MUST pass `witness_observation_store=`
    to SubmissionServer.  Without it, the `obs_ok` gate short-circuits
    to True for ANY 32-byte X-MC-Witnessed-Submission header value;
    the per-IP ack budget alone is botnet-bypassable, draining the
    65k-leaf receipt subtree in hours and silently disabling the
    censorship-evidence pipeline."""

    def test_submission_server_construction_passes_witness_observation_store(self):
        server_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "server.py")
        )
        with open(server_path, encoding="utf-8") as f:
            src = f.read()
        for m in re.finditer(r"SubmissionServer\s*\(", src):
            depth = 1
            i = m.end()
            while i < len(src) and depth > 0:
                if src[i] == "(":
                    depth += 1
                elif src[i] == ")":
                    depth -= 1
                i += 1
            call_body = src[m.end():i - 1]
            self.assertIn(
                "witness_observation_store=", call_body,
                "SubmissionServer construction MUST pass "
                "`witness_observation_store=`.  Without it the "
                "`obs_ok` gate short-circuits to True and a botnet "
                "spamming X-MC-Witnessed-Submission drains the 65k-"
                "leaf receipt subtree in hours.",
            )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2 — RPC submit_transaction must route through receipt issuer
# ─────────────────────────────────────────────────────────────────────

class TestRpcSubmitTransactionRoutesThroughHelper(unittest.TestCase):
    """`_rpc_submit_transaction` must call `submit_transaction_to_mempool`
    (which threads receipt_issuer through), NOT inline its own
    validate+add path that bypasses every defense the helper provides.
    """

    def test_rpc_submit_transaction_calls_helper(self):
        server_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "server.py")
        )
        with open(server_path, encoding="utf-8") as f:
            src = f.read()
        m = re.search(
            r"def\s+_rpc_submit_transaction\s*\([^)]*\)\s*->\s*[^:]+:",
            src,
        )
        self.assertIsNotNone(
            m, "_rpc_submit_transaction not found in server.py"
        )
        # Walk forward until the next top-level `def ` (4-space indent).
        body_start = m.end()
        body_end_match = re.search(r"\n    def\s", src[body_start:])
        body = src[body_start: body_start + (
            body_end_match.start() if body_end_match else len(src) - body_start
        )]
        self.assertIn(
            "submit_transaction_to_mempool", body,
            "_rpc_submit_transaction MUST route through "
            "submit_transaction_to_mempool so RPC submissions get the "
            "same receipt-issuance defense as HTTPS submissions.  "
            "Otherwise an attacker who spams via RPC bypasses the "
            "censorship-evidence pipeline entirely.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #3 — receipt_subtree_roots reorg leak
# ─────────────────────────────────────────────────────────────────────

class TestReceiptSubtreeRootsReorgWipe(unittest.TestCase):
    """`restore_state_snapshot` MUST wipe the `receipt_subtree_roots`
    chaindb mirror so a reorg doesn't leave stale rows that cause a
    cold-restarted peer to enforce a different evidence-validation
    gate than the warm cluster."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="mc-r5-rsr-")
        self.db = ChainDB(db_path=os.path.join(self.tmpdir, "chain.db"))

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _minimal_snapshot(self) -> dict:
        return {
            "balances": {}, "staked": {}, "nonces": {}, "public_keys": {},
            "message_counts": {}, "proposer_sig_counts": {},
            "authority_keys": {}, "pending_unstakes": {},
            "key_history": {}, "reputation": {}, "stake_snapshots": {},
            "total_supply": 0, "total_minted": 0,
            "total_fees_collected": 0,
        }

    def test_reorg_clears_stale_receipt_subtree_root_rows(self):
        self.db.set_receipt_subtree_root(b"\x11" * 32, b"\xaa" * 32)
        self.db.set_receipt_subtree_root(b"\x22" * 32, b"\xbb" * 32)
        self.db.flush_state()
        self.assertEqual(
            self.db.get_all_receipt_subtree_roots(),
            {b"\x11" * 32: b"\xaa" * 32, b"\x22" * 32: b"\xbb" * 32},
        )
        self.db.restore_state_snapshot(self._minimal_snapshot())
        self.assertEqual(
            self.db.get_all_receipt_subtree_roots(), {},
            "restore_state_snapshot MUST wipe the "
            "receipt_subtree_roots mirror.  Stale rows from a losing "
            "fork survive across reorg + cold restart and produce "
            "consensus divergence on every censorship-evidence slash "
            "decision.",
        )


class TestReceiptSubtreeRootsResetStateClearsMemory(unittest.TestCase):
    """`Blockchain._reset_state` (called on reorg) MUST clear the
    in-memory `receipt_subtree_roots` map, mirroring the chaindb wipe
    introduced for #3.  Without this, the in-memory map keeps the
    losing-fork roots even after the chaindb mirror is wiped, until
    the canonical-chain replay overwrites them (which doesn't happen
    if no SetReceiptSubtreeRoot exists on the canonical fork)."""

    def test_reset_state_clears_receipt_subtree_roots(self):
        alice = Entity.create(b"r5-rst-alice".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        # Plant a stale root.
        chain.receipt_subtree_roots[b"\x42" * 32] = b"\x99" * 32
        chain._reset_state()
        self.assertNotIn(
            b"\x42" * 32, chain.receipt_subtree_roots,
            "_reset_state MUST clear receipt_subtree_roots; otherwise "
            "the in-memory map keeps losing-fork roots after a reorg.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #4 — SetReceiptSubtreeRoot rotation must keep history of past roots
# ─────────────────────────────────────────────────────────────────────

class TestPastReceiptSubtreeRoots(unittest.TestCase):
    """When a validator rotates their receipt subtree via
    SetReceiptSubtreeRoot, receipts issued under the OLD root must
    remain validatable.  Without this, a coerced validator wipes ALL
    in-flight evidence by issuing a single rotation tx."""

    def test_past_receipt_subtree_roots_attribute_exists(self):
        alice = Entity.create(b"r5-past-alice".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        self.assertTrue(
            hasattr(chain, "past_receipt_subtree_roots"),
            "Blockchain MUST expose past_receipt_subtree_roots dict so "
            "old-root receipts remain admissible after a rotation.",
        )

    def test_old_root_remains_in_history_after_overwrite(self):
        from messagechain.core.blockchain import Blockchain
        alice = Entity.create(b"r5-past-h".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid = b"\x55" * 32
        old_root = b"\xa1" * 32
        new_root = b"\xa2" * 32
        # Manually stage the rotation by mutating state directly --
        # exercises the history-maintenance helper without going
        # through the full SetReceiptSubtreeRoot apply path.
        chain._record_receipt_subtree_root(eid, old_root)
        chain._record_receipt_subtree_root(eid, new_root)
        self.assertEqual(chain.receipt_subtree_roots.get(eid), new_root)
        history = chain.past_receipt_subtree_roots.get(eid, set())
        self.assertIn(
            old_root, history,
            "Past root MUST remain accessible for receipt validation "
            "after rotation.",
        )

    def test_validates_receipt_under_historical_root(self):
        """`receipt_root_admissible(eid, root)` MUST accept the
        current root OR any past root for that entity."""
        alice = Entity.create(b"r5-past-v".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid = b"\x66" * 32
        r1 = b"\xb1" * 32
        r2 = b"\xb2" * 32
        chain._record_receipt_subtree_root(eid, r1)
        chain._record_receipt_subtree_root(eid, r2)
        self.assertTrue(chain.receipt_root_admissible(eid, r1))
        self.assertTrue(chain.receipt_root_admissible(eid, r2))
        self.assertFalse(chain.receipt_root_admissible(eid, b"\x00" * 32))
        self.assertFalse(
            chain.receipt_root_admissible(b"\x77" * 32, r1),
            "An entity that never registered any root must reject all "
            "receipts.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #5 — slashed-this-block voters excluded from finality
# ─────────────────────────────────────────────────────────────────────

class TestSlashedThisBlockExcludedFromFinality(unittest.TestCase):
    """`_apply_finality_votes` MUST skip votes from validators in
    `slashed_validators`.  Same-block slash adds the offender to the
    set BEFORE finality-vote apply runs, so the equivocator's own
    vote shouldn't count toward the 2/3 finalization in the very
    block where they're being burned."""

    def test_slashed_validator_vote_does_not_mint_or_finalize(self):
        from types import SimpleNamespace
        alice = Entity.create(b"r5-slash-alice".ljust(32, b"\x00"))
        bob = Entity.create(b"r5-slash-bob".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        chain.public_keys[bob.entity_id] = bob.public_key
        # Mark bob as slashed (simulates slash apply running first).
        chain.slashed_validators.add(bob.entity_id)
        # Build a fake vote from bob.
        vote = FinalityVote(
            signer_entity_id=bob.entity_id,
            target_block_hash=b"\x77" * 32,
            target_block_number=1,
            signed_at_height=1,
            signature=Signature([], 0, [], b"", b""),
        )
        height = max(
            config.FINALITY_VOTE_CAP_HEIGHT,
            config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
        ) + 1
        block = SimpleNamespace(
            finality_votes=[vote],
            header=SimpleNamespace(block_number=height),
        )
        minted_before = chain.supply.total_minted
        chain._apply_finality_votes(block, alice.entity_id)
        minted_after = chain.supply.total_minted
        self.assertEqual(
            minted_after, minted_before,
            "A slashed validator's finality vote MUST NOT mint a "
            "reward.  Otherwise a coordinated proposer can finalize "
            "via stake that consensus has already declared malicious.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #6 — empty-entries inclusion list must reject non-empty quorum
# ─────────────────────────────────────────────────────────────────────

class TestEmptyEntriesInclusionListRejectsQuorum(unittest.TestCase):
    """If `block.inclusion_list.entries == []` then
    `quorum_attestation` MUST also be empty.  Without this, a
    proposer attaches arbitrarily large quorum_attestation reports
    (each with unbounded tx_hashes) at zero fee -- permanent on-chain
    ballast that bypasses MAX_BLOCK_MESSAGE_BYTES."""

    def test_empty_entries_with_nonempty_quorum_rejected(self):
        from types import SimpleNamespace
        from messagechain.consensus.inclusion_list import (
            AttesterMempoolReport, InclusionList,
        )
        alice = Entity.create(b"r5-emp-il".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        block_number = chain.height + 1
        # Forge a giant quorum_attestation list with an empty entries.
        garbage_report = AttesterMempoolReport(
            reporter_id=b"\x00" * 32,
            report_height=block_number - 1,
            tx_hashes=[b"\x00" * 32] * 1000,
            signature=Signature([], 0, [], b"", b""),
        )
        lst = InclusionList(
            publish_height=block_number,
            window_blocks=config.INCLUSION_LIST_WINDOW,
            entries=[],  # empty entries -- the bypass
            quorum_attestation=[garbage_report],
        )
        block = SimpleNamespace(
            inclusion_list=lst,
            header=SimpleNamespace(block_number=block_number),
        )
        ok, reason = chain._validate_inclusion_list_quorum(block)
        self.assertFalse(
            ok,
            "An empty-entries inclusion_list with non-empty "
            "quorum_attestation MUST be rejected -- otherwise it's a "
            "free-bytes ballast vector.",
        )

    def test_empty_entries_with_empty_quorum_passes(self):
        """Regression: the canonical empty-list shape (entries AND
        quorum_attestation both empty) stays accepted as a no-op."""
        from types import SimpleNamespace
        from messagechain.consensus.inclusion_list import InclusionList
        alice = Entity.create(b"r5-emp-il-clean".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        block_number = chain.height + 1
        lst = InclusionList(
            publish_height=block_number,
            window_blocks=config.INCLUSION_LIST_WINDOW,
            entries=[],
            quorum_attestation=[],
        )
        block = SimpleNamespace(
            inclusion_list=lst,
            header=SimpleNamespace(block_number=block_number),
        )
        ok, reason = chain._validate_inclusion_list_quorum(block)
        self.assertTrue(ok, reason)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #7 — governance v1 admission rejected post-Tier-15 activation
# ─────────────────────────────────────────────────────────────────────

class TestGovernanceV1RejectedPostActivation(unittest.TestCase):
    """Post-GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT activation, v1
    governance txs MUST be rejected at admission.  Otherwise a
    proposer can submit BOTH a v1 and a v2 form of the SAME logical
    proposal -- different tx_hashes create two distinct proposal_ids,
    splitting honest votes; for treasury-spend, both can execute and
    debit the treasury twice for the same logical spend."""

    def _v1_proposal(self):
        from messagechain.governance.governance import _hash as _ghash
        e = Entity.create(b"r5-gov-v1-rej".ljust(32, b"\x00"))
        tx = ProposalTransaction(
            proposer_id=e.entity_id,
            title="Title",
            description="Description",
            timestamp=1.0,
            fee=10_000,
            signature=Signature([], 0, [], b"", b""),
            reference_hash=b"",
            version=GOVERNANCE_TX_VERSION_V1,
        )
        # Sign so the post-activation rejection isolates the version
        # gate (not the signature check).
        tx.signature = e.keypair.sign(_ghash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx, e

    def test_v1_proposal_rejected_at_post_activation_height(self):
        tx, e = self._v1_proposal()
        ok = verify_proposal(
            tx, e.public_key,
            current_height=GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT + 1,
        )
        self.assertFalse(
            ok,
            "v1 ProposalTransaction MUST be rejected at admission "
            "post-Tier-15.  Otherwise v1+v2 vote-splitting attack "
            "stays open.",
        )

    def test_v1_proposal_accepted_pre_activation_height(self):
        """Regression: v1 still admissible BEFORE the activation
        height (historical replay determinism)."""
        tx, e = self._v1_proposal()
        if GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT > 0:
            ok = verify_proposal(
                tx, e.public_key,
                current_height=GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT - 1,
            )
            self.assertTrue(
                ok,
                "v1 ProposalTransaction MUST remain admissible "
                "pre-activation (historical replay).",
            )

    def test_v1_treasury_spend_rejected_at_post_activation_height(self):
        from messagechain.governance.governance import _hash as _ghash
        e = Entity.create(b"r5-gov-v1-ts-rej".ljust(32, b"\x00"))
        tx = TreasurySpendTransaction(
            proposer_id=e.entity_id,
            recipient_id=b"\x88" * 32,
            amount=42,
            title="Pay",
            description="For services",
            timestamp=1.0,
            fee=10_000,
            signature=Signature([], 0, [], b"", b""),
            version=GOVERNANCE_TX_VERSION_V1,
        )
        tx.signature = e.keypair.sign(_ghash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        ok = verify_treasury_spend(
            tx, e.public_key,
            current_height=GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT + 1,
        )
        self.assertFalse(
            ok,
            "v1 TreasurySpendTransaction MUST be rejected at admission "
            "post-Tier-15 -- treasury double-spend via v1+v2 must be "
            "structurally impossible.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #8 — socket read timeout on submission/feed/faucet HTTP servers
# ─────────────────────────────────────────────────────────────────────

class TestHttpHandlersHaveReadTimeout(unittest.TestCase):
    """The submission HTTPS handler and the public-feed HTTP handler
    MUST set a non-None socket read timeout.  Without it, a slow-
    loris attack pins thousands of validator threads (one per stalled
    TCP connection)."""

    def test_submission_handler_has_timeout(self):
        from messagechain.network.submission_server import _SubmissionHandler
        # `BaseHTTPRequestHandler.timeout` is the per-connection read
        # timeout.  None means "block forever" -- the slow-loris hole.
        self.assertIsNotNone(
            _SubmissionHandler.timeout,
            "_SubmissionHandler MUST set a non-None timeout to defend "
            "against slow-loris attacks.",
        )

    def test_feed_handler_has_timeout(self):
        from messagechain.network.public_feed_server import _FeedHandler
        self.assertIsNotNone(
            _FeedHandler.timeout,
            "_FeedHandler MUST set a non-None timeout to defend "
            "against slow-loris attacks.",
        )


if __name__ == "__main__":
    unittest.main()
