"""``_rpc_submit_censorship_evidence`` admits with the chain height.

Pre-fix the RPC handler called
``self.mempool.add_censorship_evidence_tx(tx)`` with no
``arrival_block_height=`` kwarg.  The mempool defaulted the missing
kwarg to 0 (see ``Mempool.add_censorship_evidence_tx`` in
``messagechain/core/mempool.py``).  Source-side forced-inclusion gate
then sees ``current_height - 0 >= FORCED_INCLUSION_WAIT_BLOCKS`` for
the *next* block proposed -- the wait gate is bypassed entirely on
freshly-arrived evidence.

CLAUDE.md anchor: "a tx that is well-formed, pays at least the
per-byte floor, and fits the byte budget cannot be suppressed by
anything weaker than a full validator-set majority actively
colluding."  The censorship-evidence pipeline is the slashing teeth
that backs that anchor; an attacker who can flush evidence into the
forced-inclusion path with no aging dilutes the gate's purpose to
zero.

The fix mirrors the React pool's ingest at
``messagechain/network/submission_server.py:901-902`` -- pass
``arrival_block_height=blockchain.height`` so the gate distinguishes
fresh evidence (just arrived) from aged evidence (waited the gate's
wait window).

This test pins the wiring against the same minimal Server-stand-in
harness that ``tests/test_cmd_submit_evidence_wired.py`` uses for
the same RPC path.
"""

from __future__ import annotations

import hashlib
import time
import unittest

import messagechain.config as _mcfg

# Tests run at MERKLE_TREE_HEIGHT=4 (conftest pin -- 16 leaves per
# keypair).  Shrink the receipt-window constants so a bundle is
# admissible at the (low) heights we drive the chain to.
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
from messagechain.crypto.keys import KeyPair, Signature
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


# Module-level cached entities -- low-height keygen still costs 50-300ms.
_alice: Entity | None = None
_bob: Entity | None = None
_alice_receipt_kp: KeyPair | None = None


def _ensure_entities() -> tuple[Entity, Entity, KeyPair]:
    global _alice, _bob, _alice_receipt_kp
    if _alice is None:
        _alice = Entity.create(b"alice-rpc-arrival".ljust(32, b"\x00"))
    if _bob is None:
        _bob = Entity.create(b"bob-rpc-arrival".ljust(32, b"\x00"))
    if _alice_receipt_kp is None:
        _alice_receipt_kp = _make_receipt_subtree_keypair(b"alice-rpc-arrival")
    return _alice, _bob, _alice_receipt_kp


class TestRpcSubmitCensorshipEvidenceArrivalHeight(unittest.TestCase):
    def test_arrival_height_matches_chain_height(self):
        """After ``_rpc_submit_censorship_evidence`` admits the tx, the
        mempool's ``_evidence_arrival_heights[tx_hash]`` must equal
        ``chain.height`` -- the same wiring the React pool got at Tier 43.

        Without this, the source-side forced-inclusion gate sees a stale
        zero and forces the next proposer to include the freshly-arrived
        evidence with no aging delay -- bypassing
        ``FORCED_INCLUSION_WAIT_BLOCKS`` on every CensorshipEvidenceTx the
        RPC accepts.
        """
        from tests import register_entity_for_test
        from messagechain.config import EVIDENCE_INCLUSION_WINDOW
        from messagechain.consensus.censorship_evidence import (
            CensorshipEvidenceTx,
        )
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool

        alice, bob, alice_receipt_kp = _ensure_entities()
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

        commit_h = chain.height
        issuer = ReceiptIssuer(
            alice.entity_id, alice_receipt_kp,
            height_fn=lambda: commit_h,
        )
        mtx = create_transaction(bob, "censored", MIN_FEE + 200, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)

        pos = ProofOfStake()
        for _ in range(EVIDENCE_INCLUSION_WINDOW + 1):
            block = chain.propose_block(pos, alice, [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)

        # The chain is now well past genesis -- this is the height the
        # RPC handler should record as the evidence's arrival.
        height_at_admit = chain.height
        self.assertGreater(
            height_at_admit, 0,
            "Test setup: chain must have advanced past genesis "
            "for the arrival-height check to mean anything",
        )

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

        mempool = Mempool()

        class _ServerLike:
            pass
        srv = _ServerLike()
        srv.blockchain = chain
        srv.mempool = mempool
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
        self.assertIn(etx.tx_hash, mempool.censorship_evidence_pool)

        # The defect: pre-fix this map held 0 for the freshly-admitted
        # tx because the RPC didn't pass arrival_block_height.  Post-fix
        # it must hold the chain's height at admit time.
        recorded = mempool._evidence_arrival_heights.get(etx.tx_hash)
        self.assertIsNotNone(
            recorded,
            "Mempool must record an arrival height for the admitted "
            "evidence tx",
        )
        self.assertEqual(
            recorded, height_at_admit,
            f"Evidence arrival height must be the chain height at "
            f"admit ({height_at_admit}); the RPC handler is dropping "
            f"the kwarg and the mempool defaulted it to {recorded}, "
            f"which collapses the source-side forced-inclusion wait "
            f"gate to zero.",
        )


if __name__ == "__main__":
    unittest.main()
