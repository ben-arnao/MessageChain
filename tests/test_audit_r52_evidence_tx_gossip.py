"""Audit r52 finding 2 — every signed evidence tx admitted via RPC MUST
flow through a unified validate -> admit -> gossip chokepoint.

Pre-fix ``_rpc_submit_censorship_evidence`` (server.py) admitted to the
mempool's censorship-evidence pool but NEVER called
``_schedule_pending_tx_gossip``.  Every other non-message tx pool admit
(stake / unstake / authority / governance) DID call gossip, so the
omission was a verify-by-inspection regression invisible at unit-test
scope.  The docstring even claimed "gossiped peers see the same tx via
the P2P pending-tx relay" -- the claim was false.

Impact (CLAUDE.md primary adversary: validator collusion):  a user
detecting a coerced validator dropping their receipted tx files
evidence into the coerced validator's own mempool (or any small full-
node mempool); the evidence never propagates to honest proposers.  On
restart / reorg / pool eviction it's silently lost.  The whole
censorship-evidence pipeline -- the chain's primary collusion
deterrent -- had a single-point-of-failure injection edge.

The fix routes ``_rpc_submit_censorship_evidence`` through a unified
``_rpc_submit_evidence`` chokepoint that runs:
    validate_*_evidence_tx -> cross-pool leaf check
    -> mempool.add_*_evidence_tx -> _schedule_pending_tx_gossip
and adds a "censorship_evidence" branch to
``_handle_announce_pending_tx`` so a peer hearing the gossip admits the
same tx to its own pool.

The chokepoint is parameterised over (kind, tx_cls, validate_fn,
admit_fn) so the BogusRejection / NonResponse evidence kinds slot in
the moment their mempool pools land -- documented as the follow-up.

This test pins:
    1. _rpc_submit_evidence helper exists and routes through gossip.
    2. _rpc_submit_censorship_evidence calls it (no path admits to
       pool without scheduling gossip).
    3. _handle_announce_pending_tx admits a peer-gossiped CE into
       this node's pool.
    4. The chokepoint signature (kind, tx_cls, validate_fn, admit_fn)
       is the shape every future evidence kind plugs into.
"""
from __future__ import annotations

import inspect
import unittest
from unittest import mock

import server


class EvidenceSubmissionChokepointExists(unittest.TestCase):
    """The audit's structural fix is to extract a shared chokepoint so a
    future BR/NR RPC wiring can't accidentally regress the gossip.
    Locking the chokepoint's existence + signature is what makes the
    abstraction load-bearing rather than aspirational.
    """

    def test_chokepoint_helper_exists_on_server(self):
        """The chokepoint helper ``_rpc_submit_evidence`` must exist as
        an attribute of ``Server``.  A missing chokepoint = a return to
        the per-handler-copy-paste shape the audit flagged."""
        self.assertTrue(
            hasattr(server.Server, "_rpc_submit_evidence"),
            "_rpc_submit_evidence chokepoint missing on Server -- "
            "the audit-r52 fix extracts it precisely to prevent a new "
            "evidence kind from regressing the gossip call.",
        )

    def test_chokepoint_takes_dispatch_parameters(self):
        """The chokepoint signature must take parameters that let a
        single helper cover CE/BR/NR/... without per-handler bespoke
        wiring.  At minimum: a `kind` discriminator (used as the gossip
        topic and the error-string namespace) and a callable
        validate/admit pair."""
        sig = inspect.signature(server.Server._rpc_submit_evidence)
        param_names = list(sig.parameters.keys())
        # self, params, kind, ...; allow free arrangement past those.
        self.assertIn("kind", param_names)
        # Either explicit validate/admit callables, or a dispatch table.
        self.assertTrue(
            any(p in param_names for p in (
                "validate_fn", "admit_fn", "tx_cls", "dispatch",
            )),
            "chokepoint must parameterise the per-kind callables -- "
            "without that, the helper is a chokepoint in name only.",
        )


class CensorshipEvidenceSubmitGossipsAfterAdmit(unittest.TestCase):
    """Locks the SEC1 fix: every successful CE admit path schedules
    pending-tx gossip.  Pre-fix the gossip call was simply absent;
    post-fix it lives inside the shared chokepoint.

    Build a Server that mocks the costly bits (blockchain validator +
    mempool admit) so the test exercises ONLY the chokepoint's flow:
    validate -> admit -> gossip.  Bypassing the WOTS+ verify lets the
    test run in milliseconds while still pinning the structural
    property the audit ranked.
    """

    def _fake_server(self):
        """Construct a Server stub with the chokepoint dependencies
        mocked.  We don't need a real chain to assert the chokepoint
        routes validate -> admit -> gossip correctly."""
        srv = server.Server.__new__(server.Server)
        srv.blockchain = mock.MagicMock()
        srv.blockchain.height = 100
        srv.blockchain.public_keys = {b"submitter": b"pk"}
        srv.blockchain.validate_censorship_evidence_tx = mock.MagicMock(
            return_value=(True, None),
        )
        srv.mempool = mock.MagicMock()
        srv.mempool.add_censorship_evidence_tx = mock.MagicMock(
            return_value=True,
        )
        srv._check_leaf_across_all_pools = mock.MagicMock(return_value=True)
        srv._schedule_pending_tx_gossip = mock.MagicMock()
        return srv

    def test_successful_ce_admit_schedules_gossip(self):
        srv = self._fake_server()
        tx = mock.MagicMock()
        tx.tx_hash = b"\xab" * 32
        tx.evidence_hash = b"\xcd" * 32
        tx.offender_id = b"\x01" * 32
        tx.submitter_id = b"submitter"
        tx.fee = 100
        with mock.patch(
            "messagechain.consensus.censorship_evidence.CensorshipEvidenceTx"
        ) as MockTxCls:
            MockTxCls.deserialize = mock.MagicMock(return_value=tx)
            result = srv._rpc_submit_censorship_evidence(
                {"transaction": {}},
            )
        self.assertTrue(result["ok"], result)
        srv._schedule_pending_tx_gossip.assert_called_once()
        gossip_args, _ = srv._schedule_pending_tx_gossip.call_args
        self.assertEqual(
            gossip_args[0], "censorship_evidence",
            "chokepoint must use the canonical 'censorship_evidence' "
            "kind string -- matches the branch in "
            "_handle_announce_pending_tx so a peer that hears the "
            "gossip admits to the same pool.",
        )
        self.assertIs(gossip_args[1], tx)

    def test_validate_failure_does_not_schedule_gossip(self):
        srv = self._fake_server()
        srv.blockchain.validate_censorship_evidence_tx = mock.MagicMock(
            return_value=(False, "stale evidence"),
        )
        tx = mock.MagicMock()
        tx.tx_hash = b"\xab" * 32
        with mock.patch(
            "messagechain.consensus.censorship_evidence.CensorshipEvidenceTx"
        ) as MockTxCls:
            MockTxCls.deserialize = mock.MagicMock(return_value=tx)
            result = srv._rpc_submit_censorship_evidence(
                {"transaction": {}},
            )
        self.assertFalse(result["ok"])
        srv._schedule_pending_tx_gossip.assert_not_called()

    def test_pool_full_does_not_schedule_gossip(self):
        srv = self._fake_server()
        srv.mempool.add_censorship_evidence_tx = mock.MagicMock(
            return_value=False,
        )
        tx = mock.MagicMock()
        tx.tx_hash = b"\xab" * 32
        tx.submitter_id = b"submitter"
        with mock.patch(
            "messagechain.consensus.censorship_evidence.CensorshipEvidenceTx"
        ) as MockTxCls:
            MockTxCls.deserialize = mock.MagicMock(return_value=tx)
            result = srv._rpc_submit_censorship_evidence(
                {"transaction": {}},
            )
        self.assertFalse(result["ok"])
        srv._schedule_pending_tx_gossip.assert_not_called()


class PeerGossipedCensorshipEvidenceIsAdmitted(unittest.TestCase):
    """The companion property to "admit -> gossip": peers that hear the
    gossip must admit to their OWN pool, otherwise gossip reaches the
    edge of the network without seeding the relays.

    Pre-fix ``_handle_announce_pending_tx`` had no "censorship_evidence"
    branch -- the gossip topic was effectively dark, so even after
    SEC1's gossip-call fix the gossip would arrive and be silently
    dropped at every peer.  The branch is the other half of the SEC1
    fix; this test pins its existence.
    """

    def test_handle_announce_pending_tx_branches_on_censorship_evidence_kind(self):
        """At minimum a "censorship_evidence" branch must exist in
        ``_handle_announce_pending_tx``.  The structural check inspects
        the function source -- a behaviour mock would need a full peer
        / rate-limiter / ban-manager scaffold to cover the same
        property."""
        src = inspect.getsource(server.Server._handle_announce_pending_tx)
        self.assertIn(
            '"censorship_evidence"',
            src,
            "missing 'censorship_evidence' branch in "
            "_handle_announce_pending_tx -- gossiped CE txs are "
            "silently dropped at every peer without this branch.",
        )


if __name__ == "__main__":
    unittest.main()
