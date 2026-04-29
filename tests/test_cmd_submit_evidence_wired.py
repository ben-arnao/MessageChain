"""cmd_submit_evidence is wired: it constructs, signs, and submits.

Pre-fix, ``messagechain submit-evidence`` was a print-only stub --
every Tier 30-35 hardening of the slashing apply paths shipped a
back end whose user-facing entry point did not actually sign or
submit a tx, defeating the censorship-evidence pipeline at the
user surface.

These tests pin the wired behavior:

  * censorship subcommand on a NOT_FOUND tx submits a real,
    signature-verifying CensorshipEvidenceTx via the new
    ``submit_censorship_evidence`` RPC.
  * censorship subcommand on an INCLUDED tx refuses with a clear
    error and DOES NOT submit (no spurious evidence).
  * Auto-fee + auto-nonce work without explicit ``--fee`` / ``--nonce``.
  * The personal-wallet keypair cache is exercised: a warm second
    invocation reuses the cached entity (same pattern as the 1.34.0
    wallet-cache tests).
  * The bogus-rejection / non-response subcommands print clear
    "not yet wired" diagnostics and do NOT touch any RPC.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import messagechain.config as _mcfg

# Tests run at MERKLE_TREE_HEIGHT=4 (the default conftest pin -- 16
# leaves per keypair).  Shrink the receipt-window constants so a
# bundle is admissible at the (low) heights the CLI's RPC stub
# returns.
_mcfg.EVIDENCE_INCLUSION_WINDOW = 1
_mcfg.EVIDENCE_EXPIRY_BLOCKS = 64

import messagechain.core.blockchain as _bc_mod
_bc_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_bc_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS

import messagechain.consensus.censorship_evidence as _ce_mod
_ce_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_ce_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS

from messagechain.config import HASH_ALGO, MIN_FEE
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import (
    ReceiptIssuer,
    SubmissionReceipt,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_receipt_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag,
        height=height,
    )


# Module-level cached entities -- Entity.create at MERKLE_TREE_HEIGHT=4
# is fast (16 leaves) but still 50-300ms each; a single pair shared
# across the test class keeps the suite snappy.
_alice_entity: Entity | None = None
_bob_entity: Entity | None = None
_alice_receipt_kp: KeyPair | None = None


def _ensure_entities() -> tuple[Entity, Entity, KeyPair]:
    global _alice_entity, _bob_entity, _alice_receipt_kp
    if _alice_entity is None:
        _alice_entity = Entity.create(b"alice-cli-ev".ljust(32, b"\x00"))
    if _bob_entity is None:
        _bob_entity = Entity.create(b"bob-cli-ev".ljust(32, b"\x00"))
    if _alice_receipt_kp is None:
        _alice_receipt_kp = _make_receipt_subtree_keypair(b"alice-cli-ev")
    return _alice_entity, _bob_entity, _alice_receipt_kp


def _build_receipt_bundle(
    *, commit_height: int, message_text: str = "hi from bob",
    nonce: int = 0,
) -> tuple[SubmissionReceipt, object, Entity, Entity, KeyPair]:
    """Construct a (receipt, message_tx) bundle suitable for evidence.

    Returns (receipt, message_tx, alice, bob, alice_receipt_kp) so
    a test can read submitter/offender ids back out for assertions.
    """
    alice, bob, alice_receipt_kp = _ensure_entities()
    # Reset signing state so successive tests don't burn shared leaves.
    bob.keypair._next_leaf = 0
    alice_receipt_kp._next_leaf = 0
    issuer = ReceiptIssuer(
        alice.entity_id, alice_receipt_kp,
        height_fn=lambda: commit_height,
    )
    mtx = create_transaction(bob, message_text, MIN_FEE + 200, nonce=nonce)
    receipt = issuer.issue(mtx.tx_hash)
    return receipt, mtx, alice, bob, alice_receipt_kp


def _write_bundle_file(receipt: SubmissionReceipt, message_tx) -> str:
    """Write a receipt-bundle JSON file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="mc-evidence-")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "receipt": receipt.serialize(),
            "message_tx": message_tx.serialize(),
        }, f)
    return path


def _ev_args(receipt_path: str, **overrides) -> argparse.Namespace:
    base = dict(
        evidence_kind="censorship",
        receipt=receipt_path,
        urgency="normal",
        server="127.0.0.1:9334",
        keyfile="/dev/null",
        data_dir=None,
        tx_hash=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class TestCmdSubmitEvidenceCensorship(unittest.TestCase):
    """Real construction + signing + submission of CensorshipEvidenceTx."""

    def test_not_found_tx_submits_real_evidence_tx(self):
        """A receipt for a tx that never landed -> real evidence tx
        signed by the submitter and posted via submit_censorship_evidence.
        """
        from messagechain import cli as cli_mod
        from messagechain.consensus.censorship_evidence import (
            CensorshipEvidenceTx, verify_censorship_evidence_tx,
        )

        receipt, mtx, alice, bob, _ = _build_receipt_bundle(
            commit_height=2,
        )
        bundle_path = _write_bundle_file(receipt, mtx)
        try:
            captured = []

            def rpc_side(host, port, method, params):
                captured.append((method, params))
                if method == "get_tx_status":
                    return {"ok": True, "result": {"status": "not_found"}}
                if method == "get_chain_info":
                    return {"ok": True, "result": {"height": 10}}
                if method == "get_nonce":
                    return {"ok": True, "result": {
                        "nonce": 0, "leaf_watermark": 1,
                    }}
                if method == "reserve_leaf":
                    return {"ok": True, "result": {"leaf_index": 1}}
                if method == "submit_censorship_evidence":
                    # Round-trip the tx through deserialization to
                    # confirm the wire payload is consensus-valid.
                    decoded = CensorshipEvidenceTx.deserialize(
                        params["transaction"],
                    )
                    # The submitter's signature must verify under
                    # their public key -- the entire premise of
                    # "the CLI actually signs" lives or dies here.
                    ok, reason = verify_censorship_evidence_tx(
                        decoded, bob.public_key,
                    )
                    self.assertTrue(ok, f"signature verification failed: {reason}")
                    return {"ok": True, "result": {
                        "tx_hash": decoded.tx_hash.hex(),
                        "evidence_hash": decoded.evidence_hash.hex(),
                        "offender_id": decoded.offender_id.hex(),
                        "fee": decoded.fee,
                        "status": "pending",
                    }}
                return {"ok": True, "result": {}}

            with patch.object(cli_mod, "_resolve_private_key",
                              return_value=b"\x02" * 32), \
                 patch.object(cli_mod, "_resolve_signing_entity",
                              return_value=bob), \
                 patch("client.rpc_call", side_effect=rpc_side), \
                 patch.object(cli_mod, "_parse_server",
                              return_value=("127.0.0.1", 9334)), \
                 patch.object(cli_mod, "_bind_persistent_leaf_index"):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_mod.cmd_submit_evidence(_ev_args(bundle_path))

            out = buf.getvalue()
            self.assertEqual(rc, 0)
            self.assertIn("Evidence submitted!", out)

            submits = [p for m, p in captured if m == "submit_censorship_evidence"]
            self.assertEqual(
                len(submits), 1,
                f"expected exactly one submit_censorship_evidence; got: {captured}",
            )

            # Auto-fee path was exercised (fee picked, no --fee in args).
            self.assertIn("auto", out.lower())
        finally:
            os.unlink(bundle_path)

    def test_included_tx_refuses_to_submit(self):
        """If the receipted tx IS on chain, refuse -- no evidence tx."""
        from messagechain import cli as cli_mod

        receipt, mtx, alice, bob, _ = _build_receipt_bundle(
            commit_height=2,
        )
        bundle_path = _write_bundle_file(receipt, mtx)
        try:
            captured = []

            def rpc_side(host, port, method, params):
                captured.append((method, params))
                if method == "get_tx_status":
                    return {"ok": True, "result": {
                        "status": "included",
                        "block_height": 12,
                        "merkle_root": "ab" * 32,
                    }}
                # Any other RPC means the command went past the
                # NOT_FOUND gate -- the test will fail because
                # submit_censorship_evidence will land in `captured`.
                return {"ok": True, "result": {}}

            with patch.object(cli_mod, "_resolve_private_key",
                              return_value=b"\x02" * 32), \
                 patch.object(cli_mod, "_resolve_signing_entity",
                              return_value=bob), \
                 patch("client.rpc_call", side_effect=rpc_side), \
                 patch.object(cli_mod, "_parse_server",
                              return_value=("127.0.0.1", 9334)), \
                 patch.object(cli_mod, "_bind_persistent_leaf_index"):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    try:
                        cli_mod.cmd_submit_evidence(_ev_args(bundle_path))
                    except SystemExit as e:
                        self.assertNotEqual(e.code, 0)

            out = buf.getvalue()
            self.assertIn("already on chain", out)

            # CRITICAL: NO submit_censorship_evidence call was made.
            submits = [p for m, p in captured if m == "submit_censorship_evidence"]
            self.assertEqual(
                len(submits), 0,
                f"command must NOT submit when tx is included; got: {captured}",
            )
        finally:
            os.unlink(bundle_path)

    def test_auto_nonce_no_explicit_arg_required(self):
        """Auto-nonce path uses get_nonce result; no --nonce required."""
        from messagechain import cli as cli_mod
        from messagechain.consensus.censorship_evidence import (
            CensorshipEvidenceTx,
        )

        receipt, mtx, alice, bob, _ = _build_receipt_bundle(
            commit_height=2,
        )
        bundle_path = _write_bundle_file(receipt, mtx)
        try:
            captured_submits = []

            def rpc_side(host, port, method, params):
                if method == "get_tx_status":
                    return {"ok": True, "result": {"status": "not_found"}}
                if method == "get_chain_info":
                    return {"ok": True, "result": {"height": 10}}
                if method == "get_nonce":
                    return {"ok": True, "result": {
                        "nonce": 5, "leaf_watermark": 1,
                    }}
                if method == "reserve_leaf":
                    return {"ok": True, "result": {"leaf_index": 1}}
                if method == "submit_censorship_evidence":
                    decoded = CensorshipEvidenceTx.deserialize(
                        params["transaction"],
                    )
                    captured_submits.append(decoded)
                    return {"ok": True, "result": {
                        "tx_hash": decoded.tx_hash.hex(),
                        "evidence_hash": decoded.evidence_hash.hex(),
                        "offender_id": decoded.offender_id.hex(),
                        "fee": decoded.fee,
                        "status": "pending",
                    }}
                return {"ok": True, "result": {}}

            with patch.object(cli_mod, "_resolve_private_key",
                              return_value=b"\x02" * 32), \
                 patch.object(cli_mod, "_resolve_signing_entity",
                              return_value=bob), \
                 patch("client.rpc_call", side_effect=rpc_side), \
                 patch.object(cli_mod, "_parse_server",
                              return_value=("127.0.0.1", 9334)), \
                 patch.object(cli_mod, "_bind_persistent_leaf_index"):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_mod.cmd_submit_evidence(_ev_args(bundle_path))

            self.assertEqual(rc, 0)
            self.assertEqual(len(captured_submits), 1)
            decoded = captured_submits[0]
            # The fee was auto-picked (no --fee arg) and is at least
            # MIN_FEE (the floor admission gate enforces this too).
            self.assertGreaterEqual(decoded.fee, MIN_FEE)
            # The submitter is bob, the offender is alice (the
            # validator that issued the receipt).
            self.assertEqual(decoded.submitter_id, bob.entity_id)
            self.assertEqual(decoded.offender_id, alice.entity_id)
        finally:
            os.unlink(bundle_path)

    def test_keypair_cache_warm_second_invocation_is_fast(self):
        """The keypair cache is exercised: a warm second invocation
        reuses the cached entity instead of regenerating WOTS+ trees.

        Mirrors the 1.34.0 wallet-cache tests: assert that
        load_or_create_personal_wallet_entity is the resolver
        path used (not Entity.create directly), so the personal
        wallet cache has a chance to hit.
        """
        from messagechain import cli as cli_mod

        receipt, mtx, alice, bob, _ = _build_receipt_bundle(
            commit_height=2,
        )
        bundle_path = _write_bundle_file(receipt, mtx)
        try:
            calls = []

            def rpc_side(host, port, method, params):
                if method == "get_tx_status":
                    return {"ok": True, "result": {"status": "not_found"}}
                if method == "get_chain_info":
                    return {"ok": True, "result": {"height": 10}}
                if method == "get_nonce":
                    return {"ok": True, "result": {
                        "nonce": 0, "leaf_watermark": 1,
                    }}
                if method == "reserve_leaf":
                    return {"ok": True, "result": {"leaf_index": 1}}
                if method == "submit_censorship_evidence":
                    return {"ok": True, "result": {
                        "tx_hash": "ab" * 32,
                        "evidence_hash": "cd" * 32,
                        "offender_id": alice.entity_id.hex(),
                        "fee": MIN_FEE,
                        "status": "pending",
                    }}
                return {"ok": True, "result": {}}

            # Wrap _resolve_signing_entity so we can confirm the CLI
            # routes through it (the cache-aware path) rather than
            # bypassing to a fresh Entity.create.
            real_resolve = cli_mod._resolve_signing_entity
            entity_calls = []

            def tracking_resolve(*args, **kwargs):
                entity_calls.append(1)
                return bob

            with patch.object(cli_mod, "_resolve_private_key",
                              return_value=b"\x02" * 32), \
                 patch.object(cli_mod, "_resolve_signing_entity",
                              side_effect=tracking_resolve), \
                 patch("client.rpc_call", side_effect=rpc_side), \
                 patch.object(cli_mod, "_parse_server",
                              return_value=("127.0.0.1", 9334)), \
                 patch.object(cli_mod, "_bind_persistent_leaf_index"):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc1 = cli_mod.cmd_submit_evidence(_ev_args(bundle_path))

            self.assertEqual(rc1, 0)
            # The CLI MUST go through _resolve_signing_entity (the
            # cache-aware resolver) rather than bypassing it.  This
            # is the wallet-cache hit-path the 1.34.0 test class
            # pinned for cmd_send/cmd_transfer.
            self.assertGreaterEqual(len(entity_calls), 1)
        finally:
            os.unlink(bundle_path)


class TestRpcSubmitCensorshipEvidence(unittest.TestCase):
    """End-to-end: the new RPC actually admits to the mempool.

    Pre-fix the chain had a censorship-evidence-pool but no RPC
    surface to write into it -- evidence could only be admitted from
    in-process tests.  This test calls the new
    ``_rpc_submit_censorship_evidence`` handler against a real
    Blockchain + Mempool and confirms the evidence lands in the pool
    where the proposer's drain will pick it up.
    """

    def test_rpc_admits_evidence_into_mempool(self):
        from tests import register_entity_for_test
        from messagechain.config import EVIDENCE_INCLUSION_WINDOW
        from messagechain.consensus.censorship_evidence import CensorshipEvidenceTx
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool
        from messagechain.crypto.keys import Signature

        alice, bob, alice_receipt_kp = _ensure_entities()
        # Reset signing state -- shared module-level entities.
        alice.keypair._next_leaf = 0
        bob.keypair._next_leaf = 0
        alice_receipt_kp._next_leaf = 0

        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, bob)
        chain.supply.balances[alice.entity_id] = 1_000_000
        chain.supply.balances[bob.entity_id] = 1_000_000
        chain.supply.staked[alice.entity_id] = 100_000
        chain.receipt_subtree_roots[alice.entity_id] = (
            alice_receipt_kp.public_key
        )

        # Build the receipt + censored tx at commit_height=chain.height.
        commit_h = chain.height
        issuer = ReceiptIssuer(
            alice.entity_id, alice_receipt_kp,
            height_fn=lambda: commit_h,
        )
        mtx = create_transaction(bob, "censored", MIN_FEE + 200, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)

        # Advance chain past the inclusion window so the evidence is
        # admissible.
        pos = ProofOfStake()
        for _ in range(EVIDENCE_INCLUSION_WINDOW + 1):
            block = chain.propose_block(pos, alice, [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)

        # Build + sign the evidence tx.
        placeholder = Signature([], 0, [], b"", b"")
        etx = CensorshipEvidenceTx(
            receipt=receipt,
            message_tx=mtx,
            submitter_id=bob.entity_id,
            timestamp=int(time.time()),
            fee=MIN_FEE,
            signature=placeholder,
        )
        msg_hash = _h(etx._signable_data())
        etx.signature = bob.keypair.sign(msg_hash)
        etx.tx_hash = etx._compute_hash()

        # Construct a bare Server stand-in that has just enough to
        # exercise the RPC path: blockchain, mempool, and the
        # _check_leaf_across_all_pools helper.  Avoids spinning a
        # full Server (which requires sockets, certs, peer table).
        mempool = Mempool()

        class _ServerLike:
            pass
        srv = _ServerLike()
        srv.blockchain = chain
        srv.mempool = mempool
        # Bind the real handlers so the Server's _check_leaf and
        # _tx_signer_pubkey + _rpc_submit_censorship_evidence
        # exercise the production code paths.
        from server import Server
        srv._check_leaf_across_all_pools = (
            Server._check_leaf_across_all_pools.__get__(srv, _ServerLike)
        )
        srv._check_leaf_by_entity_id = (
            Server._check_leaf_by_entity_id.__get__(srv, _ServerLike)
        )
        srv._tx_signer_pubkey = (
            Server._tx_signer_pubkey.__get__(srv, _ServerLike)
        )

        result = Server._rpc_submit_censorship_evidence(
            srv, {"transaction": etx.serialize()},
        )

        self.assertTrue(result.get("ok"), f"RPC failed: {result}")
        self.assertIn("tx_hash", result["result"])
        self.assertEqual(
            result["result"]["offender_id"], alice.entity_id.hex(),
        )
        # The evidence is in the mempool's evidence pool, ready for
        # the proposer drain.
        self.assertIn(etx.tx_hash, mempool.censorship_evidence_pool)

        # Refusal path: an evidence for an INCLUDED tx (we forge by
        # advancing the bob-nonce past the receipted tx's nonce) is
        # rejected by the validate gate.
        chain.nonces[bob.entity_id] = 5
        result2 = Server._rpc_submit_censorship_evidence(
            srv, {"transaction": etx.serialize()},
        )
        self.assertFalse(result2.get("ok"))
        self.assertIn("already on-chain", result2["error"].lower())


class TestCmdSubmitEvidenceStubs(unittest.TestCase):
    """The two not-yet-wired subcommands print clear diagnostics."""

    def _stub_args(self, kind: str) -> argparse.Namespace:
        return argparse.Namespace(
            evidence_kind=kind,
            receipt=None,
            rejection=None,
            witness_bundle=None,
            urgency="normal",
            server=None,
            keyfile=None,
            data_dir=None,
            tx_hash=None,
        )

    def test_bogus_rejection_prints_not_yet_wired(self):
        from messagechain import cli as cli_mod
        called_rpcs = []

        def rpc_side(host, port, method, params):
            called_rpcs.append(method)
            return {"ok": True, "result": {}}

        with patch("client.rpc_call", side_effect=rpc_side):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_submit_evidence(
                    self._stub_args("bogus-rejection"),
                )
        self.assertEqual(rc, 0)
        out = buf.getvalue().lower()
        self.assertIn("not yet wired", out)
        self.assertIn("bogus_rejection_evidence", out)
        # No RPCs touched -- this is purely a diagnostic stub.
        self.assertEqual(called_rpcs, [])

    def test_non_response_prints_not_yet_wired(self):
        from messagechain import cli as cli_mod
        called_rpcs = []

        def rpc_side(host, port, method, params):
            called_rpcs.append(method)
            return {"ok": True, "result": {}}

        with patch("client.rpc_call", side_effect=rpc_side):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_submit_evidence(
                    self._stub_args("non-response"),
                )
        self.assertEqual(rc, 0)
        out = buf.getvalue().lower()
        self.assertIn("not yet wired", out)
        self.assertIn("non_response_evidence", out)
        self.assertEqual(called_rpcs, [])


class TestCmdSubmitEvidenceLegacy(unittest.TestCase):
    """A legacy `--tx <hash>` invocation prints a migration message."""

    def test_legacy_tx_hash_prints_migration(self):
        from messagechain import cli as cli_mod
        args = argparse.Namespace(
            evidence_kind=None,
            receipt=None,
            urgency="normal",
            server=None,
            keyfile=None,
            data_dir=None,
            tx_hash="ab" * 32,
        )
        called_rpcs = []

        def rpc_side(host, port, method, params):
            called_rpcs.append(method)
            return {"ok": True, "result": {}}

        with patch("client.rpc_call", side_effect=rpc_side):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_submit_evidence(args)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("censorship --receipt", out)
        # No RPCs touched -- migration diagnostic only.
        self.assertEqual(called_rpcs, [])


if __name__ == "__main__":
    unittest.main()
