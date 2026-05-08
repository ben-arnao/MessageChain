"""Audit r38 #3 -- Mempool censorship-evidence admission gate verifies sig.

Closes the defense-in-depth gap on
``Mempool.add_censorship_evidence_tx``: the admission gate checked
only ``tx_hash`` dedup, pool capacity, and ``tx.fee >= MIN_FEE``;
there was NO call to ``verify_censorship_evidence_tx`` /
``validate_censorship_evidence_tx`` at insert time.

Today's only LIVE caller (``server._rpc_submit_censorship_evidence``)
runs ``Blockchain.validate_censorship_evidence_tx`` BEFORE admitting,
so no live exploit exists.  But the pool is gossiped as a forced-
inclusion external source via
``Mempool._external_forced_sources``, and the round-10 governance
gossip fix (``server._handle_announce_pending_tx`` governance
branch) is the cautionary tale of exactly this defect class:
admission gate trusted a single caller path; a future contributor
added a gossip-relay path; the new path forgot to validate; flooders
poisoned the pool until the verify-before-admit pattern was lifted
into the gate itself.

CLAUDE.md anchor at risk: "any deviation from pure fee-per-byte
selection requires a coordinated majority -- exactly the surface
where slashable evidence is supposed to bite."  The censorship-
evidence pool IS that slashable-evidence layer.  If a future caller
adds a gossip-relay path and forgets to validate, the pool can be
free-flooded at one MIN_FEE per slot, junk evidence competes for
forced-inclusion slots against legitimate censored-tx evidence, and
the slashable-evidence layer's evidentiary cost collapses to free.

Fix: add an OPTIONAL ``submitter_public_key_lookup: Callable[[bytes],
bytes | None]`` kwarg to ``add_censorship_evidence_tx``.  When
provided, run ``verify_censorship_evidence_tx`` against the
resolved submitter pubkey BEFORE inserting; reject (return False)
on bad signature, missing pubkey, or any verifier failure.  Live
callers (server.py RPC; any future gossip-relay path) wire the
chain's ``public_keys`` lookup; legacy/test callers can omit the
kwarg for back-compat.

This is admission-gate hardening, not a consensus rule change --
the apply-time path already validates fully via
``validate_censorship_evidence_tx``.  No fork required.

Tests:
  1. Back-compat: legacy callers (no lookup) admit unchanged.
  2. With lookup: valid signed evidence admits.
  3. With lookup: forged/tampered submitter signature is REJECTED
     at the admission gate (no insert).
  4. With lookup: unknown submitter (lookup returns None) is
     REJECTED.
  5. With lookup: receipt/message_tx hash mismatch is REJECTED at
     the admission gate (already a verifier check; this test pins
     the gate actually runs the verifier).
  6. Rejected admissions do NOT mutate pool size (no half-insert).
  7. server.py RPC continues to wire the lookup so the chain's
     public_keys is consulted at admission time post-fix.
"""

from __future__ import annotations

import hashlib
import time
import unittest

import messagechain.config as _mcfg
_mcfg.EVIDENCE_INCLUSION_WINDOW = 4
_mcfg.EVIDENCE_MATURITY_BLOCKS = 2
_mcfg.EVIDENCE_EXPIRY_BLOCKS = 64
import messagechain.core.blockchain as _bc_mod
_bc_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_bc_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS
import messagechain.consensus.censorship_evidence as _ce_mod
_ce_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_ce_mod.EVIDENCE_MATURITY_BLOCKS = _mcfg.EVIDENCE_MATURITY_BLOCKS
_ce_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS

from messagechain.config import HASH_ALGO, MIN_FEE
from messagechain.consensus.censorship_evidence import CensorshipEvidenceTx
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import (
    ReceiptIssuer, SubmissionReceipt,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


def _receipt_subtree(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag, height=height,
    )


def _sign_evidence_tx(
    submitter: Entity,
    receipt: SubmissionReceipt,
    message_tx,
    fee: int = MIN_FEE,
) -> CensorshipEvidenceTx:
    placeholder = Signature([], 0, [], b"", b"")
    tx = CensorshipEvidenceTx(
        receipt=receipt,
        message_tx=message_tx,
        submitter_id=submitter.entity_id,
        timestamp=int(time.time()),
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


class TestAddCensorshipEvidenceVerifyHook(unittest.TestCase):

    def setUp(self):
        self.issuer = _entity(b"r38-ce-issuer")
        self.submitter = _entity(b"r38-ce-sub")
        self.recipient = _entity(b"r38-ce-recipient")
        self.subtree_kp = _receipt_subtree(b"r38-ce-sub")
        receipt_issuer = ReceiptIssuer(
            self.issuer.entity_id, self.subtree_kp,
        )
        # Build a real receipted tx + matching evidence.
        self.mtx = create_transaction(
            self.recipient, "msg-r38-ce", MIN_FEE + 100, nonce=0,
        )
        self.receipt = receipt_issuer.issue(self.mtx.tx_hash)
        self.etx = _sign_evidence_tx(
            self.submitter, self.receipt, self.mtx, fee=MIN_FEE,
        )

    def _lookup_returning(self, submitter_id_to_pk: dict[bytes, bytes]):
        """Return a public-key-lookup callable backed by a fixed dict."""
        return lambda eid: submitter_id_to_pk.get(eid)

    # ── Back-compat: no-lookup path admits unchanged ──────────

    def test_legacy_no_lookup_admits_unchanged(self):
        """Existing callers passing no lookup MUST keep working --
        the mempool is one of ~65 in-process test fixtures that build
        evidence txs without ever caring about a chain pubkey
        registry.  Defense-in-depth doesn't break back-compat."""
        mp = Mempool()
        ok = mp.add_censorship_evidence_tx(self.etx)
        self.assertTrue(ok)
        self.assertEqual(len(mp.get_censorship_evidence_txs()), 1)

    # ── With-lookup path: valid signed evidence admits ────────

    def test_lookup_admits_valid_signed_evidence(self):
        mp = Mempool()
        lookup = self._lookup_returning({
            self.submitter.entity_id: self.submitter.public_key,
        })
        ok = mp.add_censorship_evidence_tx(
            self.etx, submitter_public_key_lookup=lookup,
        )
        self.assertTrue(
            ok,
            "Valid signed evidence MUST admit when the lookup "
            "returns the correct submitter pubkey.",
        )
        self.assertEqual(len(mp.get_censorship_evidence_txs()), 1)

    # ── With-lookup path: forged sig REJECTED at the gate ─────

    def test_lookup_rejects_forged_submitter_signature(self):
        """A forged tx that has a valid wire shape but a bad
        submitter signature MUST be rejected at the admission gate
        when the lookup is provided.  Pre-fix this admitted because
        the gate did not run the verifier."""
        mp = Mempool()
        # Re-key the lookup to a DIFFERENT entity's pubkey so the
        # signature-verify path returns False.  This simulates the
        # "submitter_id claims one identity but the signature was
        # produced by another" forgery shape.
        intruder = _entity(b"r38-ce-intruder")
        lookup = self._lookup_returning({
            self.submitter.entity_id: intruder.public_key,
        })
        ok = mp.add_censorship_evidence_tx(
            self.etx, submitter_public_key_lookup=lookup,
        )
        self.assertFalse(
            ok,
            "Forged-signature evidence MUST be rejected at the "
            "admission gate when the lookup is provided -- this is "
            "the gossip-pool-poisoning defense the fix lands.",
        )
        self.assertEqual(
            len(mp.get_censorship_evidence_txs()), 0,
            "Rejected admission MUST NOT mutate pool size (no "
            "half-insert).",
        )

    def test_lookup_rejects_unknown_submitter(self):
        """If the chain has no pubkey for the submitter, the
        evidence cannot be cryptographically attributed -- reject."""
        mp = Mempool()
        lookup = self._lookup_returning({})  # nothing registered
        ok = mp.add_censorship_evidence_tx(
            self.etx, submitter_public_key_lookup=lookup,
        )
        self.assertFalse(ok)
        self.assertEqual(len(mp.get_censorship_evidence_txs()), 0)

    # ── With-lookup path: receipt/message_tx pair mismatch REJECTED ──

    def test_lookup_rejects_receipt_message_tx_pair_mismatch(self):
        """The verifier rejects a receipt whose tx_hash does not
        match the embedded message_tx.tx_hash.  The admission gate
        with the lookup MUST run the verifier and propagate this
        rejection."""
        mp = Mempool()
        # Build evidence whose receipt is for a DIFFERENT tx_hash
        # than the embedded message_tx.
        wrong_receipt_issuer = ReceiptIssuer(
            self.issuer.entity_id, self.subtree_kp,
        )
        wrong_tx = create_transaction(
            self.recipient, "wrong-tx", MIN_FEE + 50, nonce=1,
        )
        wrong_receipt = wrong_receipt_issuer.issue(wrong_tx.tx_hash)
        bad_etx = _sign_evidence_tx(
            self.submitter, wrong_receipt, self.mtx, fee=MIN_FEE,
        )
        lookup = self._lookup_returning({
            self.submitter.entity_id: self.submitter.public_key,
        })
        ok = mp.add_censorship_evidence_tx(
            bad_etx, submitter_public_key_lookup=lookup,
        )
        self.assertFalse(ok)
        self.assertEqual(len(mp.get_censorship_evidence_txs()), 0)

    # ── Pool size invariant under rejection bursts ────────────

    def test_pool_size_unchanged_under_rejection_burst(self):
        """Hammer the gate with N forged txs; the pool stays empty.
        This is the gossip-pool-poisoning shape the fix is meant
        to prevent at scale."""
        mp = Mempool()
        intruder = _entity(b"r38-ce-burst-intruder")
        lookup = self._lookup_returning({
            self.submitter.entity_id: intruder.public_key,
        })
        for _ in range(10):
            mp.add_censorship_evidence_tx(
                self.etx, submitter_public_key_lookup=lookup,
            )
        self.assertEqual(
            len(mp.get_censorship_evidence_txs()), 0,
            "Pool MUST remain empty under rejection burst -- forged "
            "evidence cannot occupy slots that legitimate evidence "
            "would otherwise consume.",
        )


class TestServerRpcWiresLookup(unittest.TestCase):
    """server.py's `_rpc_submit_censorship_evidence` MUST pass the
    chain pubkey lookup into `add_censorship_evidence_tx` so the
    admission-gate verifier runs even on the live RPC path.  Without
    the wire-up, the new defense-in-depth guard is dormant."""

    def test_rpc_call_site_passes_submitter_public_key_lookup(self):
        import re
        from pathlib import Path
        src_path = Path(__file__).parent.parent / "server.py"
        src = src_path.read_text(encoding="utf-8")
        # Find the add_censorship_evidence_tx call inside
        # _rpc_submit_censorship_evidence and confirm it threads
        # `submitter_public_key_lookup=`.
        rpc_block = re.search(
            r"def _rpc_submit_censorship_evidence\(.*?(?=\n    def |\Z)",
            src, re.DOTALL,
        )
        self.assertIsNotNone(
            rpc_block,
            "Could not locate _rpc_submit_censorship_evidence in "
            "server.py -- has the function been renamed or moved?",
        )
        block = rpc_block.group(0)
        call = re.search(
            r"add_censorship_evidence_tx\s*\((?P<args>.*?)\)",
            block, re.DOTALL,
        )
        self.assertIsNotNone(
            call,
            "Could not find add_censorship_evidence_tx call inside "
            "_rpc_submit_censorship_evidence.",
        )
        self.assertIn(
            "submitter_public_key_lookup=", call.group("args"),
            "_rpc_submit_censorship_evidence MUST pass "
            "submitter_public_key_lookup= so the admission-gate "
            "verifier runs on the live RPC path.  Without the "
            "wire-up the defense-in-depth guard is dormant.",
        )


if __name__ == "__main__":
    unittest.main()
