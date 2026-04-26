"""Critical-severity audit fixes — round 2 (2026-04-25).

Four CRITICAL issues found in round 2 of the security audit:

1. **FinalityVote replay-mints inflation.**
   `_apply_finality_votes` mints `FINALITY_VOTE_INCLUSION_REWARD` per
   vote in the loop without checking whether the vote's leaf has
   already been consumed in an earlier block.  A malicious proposer
   pulls already-applied finality votes from gossip and re-includes
   them — every re-inclusion mints another `FINALITY_VOTE_INCLUSION_REWARD`
   to the proposer with no on-chain ceiling beyond the per-block cap.
   Fix: skip mint + checkpoint update when the vote's leaf_index lies
   below the signer's current chain-historic watermark.

2. **MessageTransaction `_signable_data` length-prefix collision.**
   Pre-fix `_signable_data` concatenates `self.message` raw with no
   length prefix; the optional prev/pubkey trailers have variable
   lengths.  An attacker who induces a victim to sign carefully-
   structured bytes can re-encode the same signed bytes into a
   *different* parsed `MessageTransaction` (alt message length, alt
   ts/nonce/fee/prev), producing the same `tx_hash` and a still-valid
   signature.  Mempool dedup then displaces the victim's intended tx
   with the attacker's content.  Fix: hard-fork to `TX_VERSION_LENGTH_PREFIX`
   (v4) which prefixes `len(message)` into `_signable_data`.  Pre-
   activation: legacy v1/v2/v3 paths preserved byte-for-byte.

3. **Witness-submission ack drains receipt-subtree leaves.**
   `_maybe_issue_ack` in submission_server.py issues a SubmissionAck
   (burning one WOTS+ leaf from the receipt subtree) per HTTP request
   that carries the `X-MC-Witnessed-Submission` header — with no
   per-IP budget AND no check that the claimed `request_hash` was
   actually observed via gossip.  An attacker spamming random 32-byte
   header values from a /24 drains all 65,536 receipt-subtree leaves
   in minutes.  Once drained, the entire censorship-evidence pipeline
   collapses silently.  Fix: dedicated per-IP ack budget (mirrors the
   rejection-budget pattern), AND a witness-observation-store gate so
   only requests this validator actually witnessed via gossip are
   ack-eligible.

4. **`_rpc_reserve_leaf` exhausts validator hot key with no auth.**
   The `reserve_leaf` RPC advances and persists the validator's
   wallet keypair `_next_leaf` counter on every call.  It is NOT in
   `_ADMIN_RPC_METHODS`, so any caller that reaches the RPC port can
   drain the WOTS+ tree, halting block production until an emergency
   cold-key rotation.  Fix: add to `_ADMIN_RPC_METHODS`.
"""

from __future__ import annotations

import hashlib
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

import messagechain.config as config
from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.finality import FinalityVote
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import (
    MessageTransaction,
    TX_VERSION_FIRST_SEND_PUBKEY,
    create_transaction,
)
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1 — FinalityVote replay-mint protection
# ─────────────────────────────────────────────────────────────────────

def _fake_finality_vote(
    signer_id: bytes, target_hash: bytes, target_num: int,
    leaf_index: int = 0,
) -> FinalityVote:
    """Build a placeholder FinalityVote — apply path reads only
    signer_entity_id, target_block_hash, target_block_number, and
    signature.leaf_index.  No signature verification runs in
    _apply_finality_votes (validation already passed)."""
    return FinalityVote(
        signer_entity_id=signer_id,
        target_block_hash=target_hash,
        target_block_number=target_num,
        signed_at_height=target_num,
        signature=Signature([], leaf_index, [], b"", b""),
    )


class TestFinalityVoteReplayMintProtection(unittest.TestCase):
    """The apply path must NOT mint a second time for a vote whose
    leaf has already been consumed (any earlier block).  Without
    this defense, a proposer can pull already-applied votes from
    gossip and re-include them indefinitely up to
    FINALITY_VOTE_MAX_AGE_BLOCKS, harvesting
    FINALITY_VOTE_INCLUSION_REWARD per replay.
    """

    def setUp(self):
        self.alice = Entity.create(b"r2-replay-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"r2-replay-bob".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.public_keys[self.bob.entity_id] = self.bob.public_key
        # Pretend a past target block exists.
        self.target_hash = b"\x77" * 32
        self.target_num = 1
        # Use a height past activation so the post-fork direct-mint
        # path is the one under test.  Pre-fork (legacy treasury path)
        # has the same defect but at lower severity (treasury-bounded
        # rather than uncapped mint).
        self.height = max(
            config.FINALITY_VOTE_CAP_HEIGHT,
            config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
        ) + 1

    def _apply_block_with_vote(self, leaf_index: int):
        vote = _fake_finality_vote(
            self.bob.entity_id, self.target_hash, self.target_num,
            leaf_index=leaf_index,
        )
        fake = SimpleNamespace(
            finality_votes=[vote],
            header=SimpleNamespace(block_number=self.height),
        )
        self.chain._apply_finality_votes(fake, self.alice.entity_id)

    def test_replayed_vote_does_not_double_mint(self):
        """Apply leaf=5 twice; second application must mint zero."""
        minted_before_first = self.chain.supply.total_minted
        self._apply_block_with_vote(leaf_index=5)
        minted_after_first = self.chain.supply.total_minted
        first_mint = minted_after_first - minted_before_first
        self.assertEqual(
            first_mint, config.FINALITY_VOTE_INCLUSION_REWARD,
            "first inclusion of a fresh leaf must mint the reward",
        )

        # Replay the SAME vote at the same leaf index in another block.
        # Watermark was bumped to leaf+1 = 6 by the first apply.  This
        # second inclusion's leaf_index=5 < watermark=6 — must skip.
        self._apply_block_with_vote(leaf_index=5)
        minted_after_replay = self.chain.supply.total_minted
        replay_mint = minted_after_replay - minted_after_first
        self.assertEqual(
            replay_mint, 0,
            "a replayed finality vote (already-consumed leaf) must "
            "NOT mint a second reward — replay-mint is a free-mint "
            "primitive",
        )

    def test_fresh_leaf_after_replay_still_mints(self):
        """A NEW vote at a higher leaf must mint normally even after
        a replay attempt at a lower leaf was rejected.  Confirms the
        guard rejects replays without breaking legitimate progress."""
        self._apply_block_with_vote(leaf_index=3)  # mint #1
        self._apply_block_with_vote(leaf_index=3)  # replay → no mint
        minted_before = self.chain.supply.total_minted
        self._apply_block_with_vote(leaf_index=10)  # fresh → mint
        delta = self.chain.supply.total_minted - minted_before
        self.assertEqual(delta, config.FINALITY_VOTE_INCLUSION_REWARD)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2 — MessageTransaction length-prefix hard fork
# ─────────────────────────────────────────────────────────────────────

class TestMessageTransactionLengthPrefix(unittest.TestCase):
    """Post-activation, MessageTransaction signable_data must commit
    to the message length so two byte-strings that parse to different
    (message, ts, nonce, fee, prev, pk) tuples cannot collide on
    tx_hash.  Defect class: same as the M23 length-prefix fix already
    applied to Signature.canonical_bytes and the binary-hashes blob.
    """

    def test_v4_constant_exists(self):
        from messagechain.core.transaction import TX_VERSION_LENGTH_PREFIX
        self.assertEqual(TX_VERSION_LENGTH_PREFIX, 4)

    def test_v4_signable_data_includes_message_length(self):
        """v4 signable_data MUST contain `struct.pack(">H", len(msg))`
        immediately preceding the message bytes.  v3 signable_data
        does NOT (preserved for historical replay)."""
        from messagechain.core.transaction import TX_VERSION_LENGTH_PREFIX
        e = Entity.create(b"r2-lenprefix-e".ljust(32, b"\x00"))
        msg = b"hello world!"
        tx_v3 = MessageTransaction(
            entity_id=e.entity_id,
            message=msg,
            timestamp=1.0,
            nonce=0,
            fee=100,
            signature=Signature([], 0, [], b"", b""),
            version=TX_VERSION_FIRST_SEND_PUBKEY,
            compression_flag=0,
        )
        tx_v4 = MessageTransaction(
            entity_id=e.entity_id,
            message=msg,
            timestamp=1.0,
            nonce=0,
            fee=100,
            signature=Signature([], 0, [], b"", b""),
            version=TX_VERSION_LENGTH_PREFIX,
            compression_flag=0,
        )
        sd_v3 = tx_v3._signable_data()
        sd_v4 = tx_v4._signable_data()
        # v4 must be exactly 2 bytes longer (the >H prefix).
        self.assertEqual(
            len(sd_v4), len(sd_v3) + 2,
            "v4 signable_data must be 2 bytes longer (message_len prefix)",
        )
        # The 2-byte prefix must be present and equal len(msg) big-endian.
        self.assertIn(struct.pack(">H", len(msg)) + msg, sd_v4)

    def test_v3_and_v4_compute_different_tx_hashes(self):
        """Same fields, different version → different tx_hash.  The
        version byte and the new length-prefix together change the
        hash, isolating v3-historical txs from any v4 collisions."""
        from messagechain.core.transaction import TX_VERSION_LENGTH_PREFIX
        e = Entity.create(b"r2-lenprefix-h".ljust(32, b"\x00"))
        msg = b"same content"
        common = dict(
            entity_id=e.entity_id, message=msg, timestamp=1.0,
            nonce=0, fee=100,
            signature=Signature([], 0, [], b"", b""),
            compression_flag=0,
        )
        tx_v3 = MessageTransaction(version=TX_VERSION_FIRST_SEND_PUBKEY, **common)
        tx_v4 = MessageTransaction(version=TX_VERSION_LENGTH_PREFIX, **common)
        self.assertNotEqual(tx_v3._compute_hash(), tx_v4._compute_hash())

    def test_v4_rejected_pre_activation(self):
        """v4 admission requires current_height >= MESSAGE_TX_LENGTH_PREFIX_HEIGHT."""
        from messagechain.core.transaction import (
            TX_VERSION_LENGTH_PREFIX, verify_transaction,
        )
        from messagechain.config import MESSAGE_TX_LENGTH_PREFIX_HEIGHT
        e = Entity.create(b"r2-lenprefix-pre".ljust(32, b"\x00"))
        # Build a real v4 tx (signed properly).
        tx = MessageTransaction(
            entity_id=e.entity_id, message=b"pre-activation v4",
            timestamp=1.0, nonce=0, fee=100,
            signature=Signature([], 0, [], b"", b""),
            version=TX_VERSION_LENGTH_PREFIX, compression_flag=0,
        )
        tx.signature = e.keypair.sign(tx._compute_hash())
        tx.tx_hash = tx._compute_hash()
        # Height strictly below activation must reject.
        if MESSAGE_TX_LENGTH_PREFIX_HEIGHT > 0:
            ok = verify_transaction(
                tx, e.public_key,
                current_height=MESSAGE_TX_LENGTH_PREFIX_HEIGHT - 1,
            )
            self.assertFalse(
                ok, "v4 must not be admissible before activation height"
            )

    def test_v4_accepted_post_activation(self):
        """A signed v4 tx with current_height >= activation must verify."""
        from messagechain.core.transaction import (
            TX_VERSION_LENGTH_PREFIX, verify_transaction,
        )
        from messagechain.config import MESSAGE_TX_LENGTH_PREFIX_HEIGHT
        e = Entity.create(b"r2-lenprefix-post".ljust(32, b"\x00"))
        tx = MessageTransaction(
            entity_id=e.entity_id, message=b"post-activation v4",
            timestamp=1.0, nonce=0, fee=100,
            signature=Signature([], 0, [], b"", b""),
            version=TX_VERSION_LENGTH_PREFIX, compression_flag=0,
        )
        msg_hash = tx._compute_hash()
        tx.signature = e.keypair.sign(msg_hash)
        tx.tx_hash = msg_hash
        ok = verify_transaction(
            tx, e.public_key,
            current_height=MESSAGE_TX_LENGTH_PREFIX_HEIGHT,
        )
        self.assertTrue(ok, "v4 must verify at/after activation height")

    def test_v4_wire_round_trip(self):
        """v4 to_bytes / from_bytes round-trip is lossless and
        recomputes the same tx_hash."""
        from messagechain.core.transaction import TX_VERSION_LENGTH_PREFIX
        e = Entity.create(b"r2-lenprefix-rt".ljust(32, b"\x00"))
        tx = MessageTransaction(
            entity_id=e.entity_id, message=b"wire round trip",
            timestamp=1.0, nonce=0, fee=100,
            signature=Signature([], 0, [], b"", b""),
            version=TX_VERSION_LENGTH_PREFIX, compression_flag=0,
        )
        tx.signature = e.keypair.sign(tx._compute_hash())
        tx.tx_hash = tx._compute_hash()
        wire = tx.to_bytes()
        decoded = MessageTransaction.from_bytes(wire)
        self.assertEqual(decoded.version, TX_VERSION_LENGTH_PREFIX)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.message, tx.message)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #3 — witness-submission ack budget + observation gate
# ─────────────────────────────────────────────────────────────────────

class TestWitnessAckBudget(unittest.TestCase):
    """Per-IP ack budget mirrors the rejection-budget pattern.  Each
    SubmissionAck consumes a one-time-use WOTS+ leaf from the receipt
    subtree (RECEIPT_SUBTREE_HEIGHT=16 → 65k total).  Without a budget,
    one /24 attacker drains the whole subtree in minutes — collapsing
    the entire censorship-evidence pipeline.
    """

    def setUp(self):
        from messagechain.network.submission_server import _HandlerContext
        # Build a minimal context — we only exercise the budget API,
        # not the submission flow.
        self.ctx = _HandlerContext(
            blockchain=MagicMock(), mempool=MagicMock(),
            relay_callback=None,
        )

    def test_ack_budget_check_method_exists(self):
        self.assertTrue(
            hasattr(self.ctx, "ack_budget_check"),
            "_HandlerContext must expose ack_budget_check(ip) — the "
            "dedicated per-IP budget for SubmissionAck issuance",
        )

    def test_ack_budget_eventually_returns_false(self):
        """Burst tokens drain to False — the bucket has a real ceiling."""
        ip = "10.0.0.42"
        # Drain the burst.  After SUBMISSION_ACK_BURST consecutive
        # rapid calls there must be at least one False return; the
        # exact burst+rate values live in config so we just bound the
        # loop generously.
        results = [self.ctx.ack_budget_check(ip) for _ in range(200)]
        self.assertIn(
            False, results,
            "ack_budget_check must eventually return False under "
            "sustained spam — otherwise the budget doesn't exist",
        )


class TestSubmitTransactionAckGate(unittest.TestCase):
    """`submit_transaction_to_mempool` must accept an `ack_allowed`
    kwarg and skip ack issuance when it's False.  This is what the
    HTTP handler uses to enforce the per-IP ack budget + witness-
    observation-store gate."""

    def setUp(self):
        from messagechain.network.submission_receipt import ReceiptIssuer
        self.alice = Entity.create(b"r2-ackgate-alice".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.mempool = Mempool()
        # Real ReceiptIssuer would burn a WOTS+ leaf per ack.  Use a
        # MagicMock so we can assert call counts without touching keys.
        self.receipt_issuer = MagicMock(spec=ReceiptIssuer)
        ack_obj = MagicMock()
        ack_obj.to_bytes.return_value = b"\xaa" * 64
        self.receipt_issuer.issue_ack.return_value = ack_obj

    def _make_tx(self):
        return create_transaction(
            self.alice, "ack-gate-test", nonce=0, fee=10_000,
            current_height=self.chain.height + 1,
        )

    def test_ack_skipped_when_ack_allowed_false(self):
        """When ack_allowed=False, witnessed_request_hash is ignored
        and no leaf is burned."""
        from messagechain.network.submission_server import (
            submit_transaction_to_mempool,
        )
        tx = self._make_tx()
        request_hash = b"\x33" * 32
        result = submit_transaction_to_mempool(
            tx, self.chain, self.mempool,
            receipt_issuer=self.receipt_issuer,
            witnessed_request_hash=request_hash,
            ack_allowed=False,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.ack_hex, "")
        self.receipt_issuer.issue_ack.assert_not_called()

    def test_ack_issued_when_ack_allowed_true(self):
        """Default behaviour (ack_allowed=True) preserves the existing
        ack-on-witnessed-submission semantics."""
        from messagechain.network.submission_server import (
            submit_transaction_to_mempool,
        )
        tx = self._make_tx()
        request_hash = b"\x33" * 32
        result = submit_transaction_to_mempool(
            tx, self.chain, self.mempool,
            receipt_issuer=self.receipt_issuer,
            witnessed_request_hash=request_hash,
            ack_allowed=True,
        )
        self.assertTrue(result.ok)
        self.assertNotEqual(result.ack_hex, "")
        self.receipt_issuer.issue_ack.assert_called_once()


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #4 — reserve_leaf must require admin auth
# ─────────────────────────────────────────────────────────────────────

class TestReserveLeafIsAdminGated(unittest.TestCase):
    """`reserve_leaf` advances and persists the validator's hot-key
    `_next_leaf` counter.  Without admin auth, any caller that
    reaches the RPC port can drain the WOTS+ tree, halting block
    production until an emergency cold-key rotation.  Lock the
    invariant at the constant level so a future refactor that
    inadvertently removes it gets caught here."""

    def test_reserve_leaf_in_admin_method_set(self):
        from server import _ADMIN_RPC_METHODS
        self.assertIn(
            "reserve_leaf", _ADMIN_RPC_METHODS,
            "reserve_leaf advances the validator's hot key — it MUST "
            "be admin-gated.  Otherwise any caller reaching the RPC "
            "port (default 127.0.0.1, but commonly fronted via reverse "
            "proxy / SSH tunnel / LAN exposure) can exhaust the WOTS+ "
            "tree and halt block production.",
        )


if __name__ == "__main__":
    unittest.main()
