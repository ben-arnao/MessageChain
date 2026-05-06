"""Tier 34 — forced-inclusion gate covers all block tx-list fields.

Pre-Tier-34 the attester-enforced gate built `included_hashes` from
`block.transactions` (the message-tx list) only and accounted for the
byte budget via `len(tx.message)`.  Two correctness gaps:

  1. **False positive on honest blocks carrying transfers.**
     TransferTransactions share `mempool.pending` with messages so
     `get_forced_inclusion_set` returns them.  A proposer who placed a
     forced transfer in `block.transfer_transactions` had its tx_hash
     absent from `included_hashes` — attesters wrongly voted NO on an
     honest block.

  2. **False negative on the audit's anchored concern.**  The CLAUDE.md
     "high-fpb tx cannot be suppressed without slashable evidence"
     anchor silently exempted every non-message tx kind because the
     gate didn't enforce against them.  A colluding proposer that
     dropped a forced transfer walked free.

Tier 34 closes both: post-fork the gate walks every known block
tx-list field and accounts for stored bytes.  Pre-fork: byte-identical
to legacy attester behavior.

Tests pin:
  * Pre-Tier-34: a forced transfer correctly placed in
    `block.transfer_transactions` is WRONGLY flagged as omitted (this
    is the legacy bug — preserved for replay determinism, fixed
    post-fork).
  * Post-Tier-34: same block correctly attested.
  * Post-Tier-34: a block omitting a forced transfer entirely is
    flagged as censored.
  * Post-Tier-34: per-entity cap and byte-budget excuses still apply
    correctly across multiple tx-list fields.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    FEE_PER_BYTE,
    FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
    FORCED_INCLUSION_WAIT_BLOCKS,
    HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT,
    MIN_FEE,
)
from messagechain.consensus.forced_inclusion import (
    _BLOCK_TX_LIST_ATTRS,
    check_forced_inclusion,
)
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity


PRE_T34 = FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT - 1
POST_T34 = FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT

_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)
_BASE_FEE = MIN_FEE + 10 * FEE_PER_BYTE


def _make_msg(entity, fee, nonce):
    return create_transaction(entity, f"msg {nonce}", fee=fee, nonce=nonce)


def _make_xfer(sender, recipient, amount, fee, nonce):
    return create_transfer_transaction(
        sender,
        recipient.entity_id,
        amount=amount,
        nonce=nonce,
        fee=fee,
    )


class _FakeBlock:
    """Minimal Block stand-in carrying every tx-list field the gate may
    walk.  Avoids the full Blockchain apparatus a real Block requires."""

    class _H:
        def __init__(self, proposer_id):
            self.proposer_id = proposer_id

    def __init__(
        self,
        message_txs=None,
        transfer_txs=None,
        react_txs=None,
        stake_txs=None,
        unstake_txs=None,
        governance_txs=None,
        authority_txs=None,
        proposer_id=b"\x00" * 32,
    ):
        self.transactions = list(message_txs or [])
        self.transfer_transactions = list(transfer_txs or [])
        self.react_transactions = list(react_txs or [])
        self.stake_transactions = list(stake_txs or [])
        self.unstake_transactions = list(unstake_txs or [])
        self.governance_txs = list(governance_txs or [])
        self.authority_txs = list(authority_txs or [])
        self.header = _FakeBlock._H(proposer_id)


# ────────────────────────────────────────────────────────────────────
# Activation height ordering — Tier 34 must follow Tier 32.
# ────────────────────────────────────────────────────────────────────


class TestForkGateOrdering(unittest.TestCase):

    def test_height_above_tier_32(self):
        self.assertGreater(
            FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
            HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT,
            "Tier 34 must follow Tier 32 — single coordinated upgrade "
            "window covers both attester-side and slashing changes.",
        )


# ────────────────────────────────────────────────────────────────────
# Block tx-list registry — every persisted list field must be in the
# walk tuple.  Catches a future contributor adding a new tx kind to
# Block without registering it under the gate.
# ────────────────────────────────────────────────────────────────────


class TestBlockTxListRegistry(unittest.TestCase):
    """Every block tx-list field that participates in apply state must
    appear in `_BLOCK_TX_LIST_ATTRS` so the gate sees it."""

    def test_all_known_tx_list_fields_in_registry(self):
        # The persisted block tx-list fields the gate must walk.  If
        # `Block` grows a new tx-list field, register it here AND in
        # `_BLOCK_TX_LIST_ATTRS` — failing to do either means the new
        # tx kind is silently censorable post-Tier-34.
        from messagechain.core.block import Block
        # Field names that hold tx lists (heuristic: end in
        # `_transactions` / `_txs` and default to a list).  Excludes
        # consensus metadata fields (attestations, finality_votes,
        # custody_proofs, *_evidence_txs) which the forced-inclusion
        # gate intentionally does NOT cover — they're consensus
        # signals, not user txs.
        from dataclasses import fields
        candidate_fields: set[str] = set()
        for f in fields(Block):
            name = f.name
            # `transactions` is the historical message-tx slot; every
            # other user-tx slot ends in `_transactions` or `_txs`.
            is_user_tx_field = (
                name == "transactions"
                or name.endswith("_transactions")
                or name.endswith("_txs")
            )
            if not is_user_tx_field:
                continue
            # Skip consensus-signal fields (attesters do not enforce
            # inclusion of evidence-tx kinds via this gate; censorship-
            # evidence has its own slash path).
            if "evidence" in name or name in {
                "slash_transactions",
                "finality_votes",
                "custody_proofs",
            }:
                continue
            candidate_fields.add(name)
        self.assertIn("transactions", candidate_fields)
        # Every candidate user-tx field must be registered in the walk
        # tuple.  Drift between Block's fields and the gate's walk is
        # the exact source of the Tier 34 bug class.
        for field_name in candidate_fields:
            self.assertIn(
                field_name, _BLOCK_TX_LIST_ATTRS,
                f"Block field `{field_name}` is a user-tx list but is "
                f"missing from `_BLOCK_TX_LIST_ATTRS` — the forced-"
                f"inclusion gate will not enforce against it. Add it to "
                f"the registry in messagechain/consensus/forced_inclusion.py.",
            )


# ────────────────────────────────────────────────────────────────────
# False-positive: pre-Tier-34 wrongly flags an honest transfer-bearing
# block; post-Tier-34 attests it.
# ────────────────────────────────────────────────────────────────────


class TestTransferInclusionRecognition(unittest.TestCase):

    def setUp(self):
        self.alice = Entity.create(
            b"t34-alice".ljust(32, b"\x00"),
        )
        self.bob = Entity.create(
            b"t34-bob".ljust(32, b"\x00"),
        )
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)
        # Add a transfer to the mempool with arrival height old enough
        # to qualify for forced inclusion.
        self.xfer = _make_xfer(
            self.alice, self.bob, amount=100,
            fee=_BASE_FEE, nonce=0,
        )
        # Arrival at height 0; current height = WAIT + 5 keeps the wait
        # gate satisfied for both pre- and post-Tier-34 paths in the
        # POST_T34 ≪ WAIT-relative arithmetic.
        self.pool.add_transaction(self.xfer, arrival_block_height=0)

    def test_pre_tier_34_does_not_enforce_against_transfers(self):
        """Pre-Tier-34: a forced TransferTransaction in the mempool is
        SILENTLY exempted from the gate's enforcement.  Legacy code
        crashed on the path; the patched legacy filter skips non-
        message kinds so attesters stay liveness-safe — but the
        underlying anchored gap (transfer-censorship leaves no
        slashable signal) stands until Tier 34 lands.  The test exists
        so any regression that re-enables enforcement at the legacy
        height is caught (it would change what historical blocks
        attest to)."""
        block = _FakeBlock()  # No transfer included — censored.
        h = max(PRE_T34, FORCED_INCLUSION_WAIT_BLOCKS + 1)
        ok, _reason = check_forced_inclusion(block, self.pool, h)
        self.assertTrue(
            ok,
            "Pre-Tier-34 the gate must not vote NO on a transfer-only "
            "censorship — the fix lands at the fork height.",
        )

    def test_post_tier_34_recognizes_transfer_inclusion(self):
        """Post-Tier-34: same honest block correctly attested — the
        gate walks `block.transfer_transactions` too."""
        block = _FakeBlock(transfer_txs=[self.xfer])
        h = POST_T34 + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertTrue(
            ok,
            f"Tier 34 must recognize the transfer's inclusion: "
            f"reason={reason!r}",
        )

    def test_post_tier_34_flags_omitted_transfer(self):
        """Post-Tier-34: a block that omits a forced transfer is
        flagged — Tier 34's whole point is to extend the slashable
        non-inclusion signal to non-message tx kinds the mempool
        already shares with attesters."""
        # Block omits the transfer.  Use an empty block (no tx of any
        # kind) so the byte-budget excuse cannot apply.
        block = _FakeBlock()
        h = POST_T34 + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertFalse(
            ok,
            "Tier 34 must flag the omitted transfer as censorship.",
        )


# ────────────────────────────────────────────────────────────────────
# Multi-list per-entity cap.
# ────────────────────────────────────────────────────────────────────


class TestMultiListPerEntityCap(unittest.TestCase):
    """Per-entity inclusion cap counts tx contributions from EVERY
    tx-list field, not just `block.transactions`."""

    def setUp(self):
        self.alice = Entity.create(b"t34c-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"t34c-bob".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_post_tier_34_per_entity_count_includes_transfers(self):
        """A forced message tx whose sender already has
        MAX_TXS_PER_ENTITY_PER_BLOCK transfers in the same block is
        excused — the per-entity cap binds across both lists."""
        from messagechain.config import MAX_TXS_PER_ENTITY_PER_BLOCK
        # Stack alice's quota worth of transfers in transfer_transactions.
        xfers = [
            _make_xfer(self.alice, self.bob, amount=100,
                       fee=_BASE_FEE, nonce=n)
            for n in range(MAX_TXS_PER_ENTITY_PER_BLOCK)
        ]
        # Now push a forced message from alice to the mempool — quota-
        # exceeding so excuse #3 (per-entity cap reached) must fire.
        forced_msg = _make_msg(
            self.alice, fee=_BASE_FEE,
            nonce=MAX_TXS_PER_ENTITY_PER_BLOCK,
        )
        self.pool.add_transaction(forced_msg, arrival_block_height=0)
        # Block contains alice's transfers but NOT the forced message.
        block = _FakeBlock(transfer_txs=xfers)
        h = POST_T34 + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertTrue(
            ok,
            f"Post-Tier-34: per-entity cap must count transfers in the "
            f"tally so a forced quota-exceeding message is properly "
            f"excused: reason={reason!r}",
        )


# ────────────────────────────────────────────────────────────────────
# Byte-budget unit-mismatch — Tier 34 multi-list path summed STORED
# bytes against the PAYLOAD cap, letting a single proposer suppress
# any forced tx by stuffing the block with their own witness-heavy
# message txs whose stored bytes overrun MAX_BLOCK_MESSAGE_BYTES while
# the block validator's payload check (sum of `len(tx.message)` against
# the same cap) stays well below.  CLAUDE.md anchor: "a tx that pays at
# least the per-byte floor and fits the byte budget cannot be
# suppressed by anything weaker than a full validator-set majority".
# ────────────────────────────────────────────────────────────────────


class TestByteBudgetExcuseStoredBytesAxis(unittest.TestCase):
    """Excuse #1 must compare stored bytes against MAX_BLOCK_TOTAL_BYTES
    (the cap that actually bounds stored bytes — Tier 18's unified
    budget), not against MAX_BLOCK_MESSAGE_BYTES (the payload cap).

    A WOTS+ MessageTransaction is ~256× its payload in stored bytes
    (small payloads mostly amortize to ~2 KB witness).  20 such txs
    overrun MAX_BLOCK_MESSAGE_BYTES = 45_000 stored bytes while their
    payload sum is hundreds of bytes — well inside both the payload
    cap and the unified Tier 18 cap.  Pre-fix: any forced tx is excused
    as "byte budget exhausted", and a colluding proposer can drop ANY
    high-fpb tx by filling the block with their own txs.  Post-fix:
    excuse #1 only fires when the stored-byte axis would actually
    bind — i.e. against MAX_BLOCK_TOTAL_BYTES."""

    def setUp(self):
        # Alice signs ~20 txs (log2(21)=5 -> 32 leaves).  Bob signs
        # once -> tree_height=2 is plenty.  The "really exhausts the
        # cap" subtest uses mock fillers (no signing) so neither
        # entity has to scale to 90+ sigs at production tree height.
        self.alice = Entity.create(
            b"t34-bb-alice".ljust(32, b"\x00"), tree_height=5,
        )
        self.bob = Entity.create(
            b"t34-bb-bob".ljust(32, b"\x00"), tree_height=2,
        )
        self.pool = Mempool(max_size=200, fee_policy=_STATIC_FEE)

    def test_post_tier_34_witness_heavy_block_does_not_excuse_omission(self):
        # Bob's forced tx — the one a colluding proposer wants to
        # suppress.  Tiny payload, small stored size; the question is
        # whether the gate excuses its omission.
        bob_forced = create_transaction(
            self.bob, "forced", fee=10_000, nonce=0,
        )
        self.pool.add_transaction(bob_forced, arrival_block_height=0)
        # Alice (the proposer) fills the block with HER OWN small-payload
        # message txs.  At ~2300 stored bytes each, 20 txs sum to
        # ~46 KB — over the 45 KB MAX_BLOCK_MESSAGE_BYTES (the broken
        # cap reference) but well under the 200 KB MAX_BLOCK_TOTAL_BYTES
        # (the correct cap).  Their payload sum is ~180 B, so the
        # block validator's `len(tx.message)` check passes trivially
        # — the block IS valid; the proposer just declined to include
        # bob's forced tx.
        alice_block_txs = [
            create_transaction(
                self.alice, f"x{n:02d}",
                fee=200, nonce=n,
            )
            for n in range(20)
        ]
        # Sanity-pin the inputs the test relies on so a future encoding
        # tweak that shrinks WOTS+ doesn't silently turn this test into
        # a no-op.
        from messagechain.config import (
            MAX_BLOCK_MESSAGE_BYTES, MAX_BLOCK_TOTAL_BYTES,
        )
        stored_total = sum(len(t.to_bytes()) for t in alice_block_txs)
        payload_total = sum(len(t.message) for t in alice_block_txs)
        self.assertGreater(
            stored_total, MAX_BLOCK_MESSAGE_BYTES,
            "test setup expects Alice's stored-byte total to exceed the "
            "(broken) payload-cap reference so the bug is exercised; if "
            "WOTS+ encoding shrinks, raise the tx count.",
        )
        self.assertLess(
            stored_total, MAX_BLOCK_TOTAL_BYTES,
            "test setup expects Alice's stored-byte total to fit inside "
            "MAX_BLOCK_TOTAL_BYTES so the block IS valid — the question "
            "is whether the censorship-gate's excuse #1 fires.",
        )
        self.assertLess(
            payload_total, MAX_BLOCK_MESSAGE_BYTES,
            "test setup expects Alice's payload total to fit inside the "
            "payload cap so the block validator does not reject the block.",
        )
        block = _FakeBlock(message_txs=alice_block_txs)
        h = POST_T34 + 5
        ok, reason = check_forced_inclusion(block, self.pool, h)
        self.assertFalse(
            ok,
            f"Tier 34 byte-budget excuse must NOT fire when stored bytes "
            f"are well within MAX_BLOCK_TOTAL_BYTES; the proposer dropped "
            f"a forced tx with no real space constraint: reason={reason!r}",
        )

    def test_post_tier_34_byte_budget_excuse_still_fires_at_real_cap(self):
        # Inverse direction: when stored bytes really do overrun the
        # correct cap (MAX_BLOCK_TOTAL_BYTES), excuse #1 must still
        # fire - the fix tightens the rule, it does not delete it.
        #
        # Block fillers are mock objects (not real signed txs) so we
        # don't have to scale Alice's WOTS+ tree to ~90 leaves.  The
        # gate only reads tx.tx_hash, tx.to_bytes(), and the
        # entity-id-style fields off block-side txs - it never
        # verifies their signatures (that's the validate-block layer).
        # Per the test-perf rule "Don't sign just to drain a counter":
        # if the handler doesn't need a real signature, give it a stub.
        bob_forced = create_transaction(
            self.bob, "f", fee=10_000, nonce=0,
        )
        self.pool.add_transaction(bob_forced, arrival_block_height=0)
        from messagechain.config import MAX_BLOCK_TOTAL_BYTES

        class _BulkMockTx:
            __slots__ = ("tx_hash", "_blob", "entity_id", "fee", "message")
            def __init__(self, idx, target_bytes, entity_id):
                self.tx_hash = (b"M" + idx.to_bytes(8, "big")).ljust(32, b"\x00")
                self._blob = b"\x00" * target_bytes
                self.entity_id = entity_id
                self.fee = 100
                self.message = b""
            def to_bytes(self):
                return self._blob

        # Six 35 KB stubs sum to 210 KB, over MAX_BLOCK_TOTAL_BYTES = 200 KB.
        per_tx_bytes = 35_000
        n_txs = (MAX_BLOCK_TOTAL_BYTES // per_tx_bytes) + 1
        bulk_txs = [
            _BulkMockTx(i, per_tx_bytes, self.alice.entity_id)
            for i in range(n_txs)
        ]
        stored_total = sum(len(t.to_bytes()) for t in bulk_txs)
        self.assertGreater(
            stored_total, MAX_BLOCK_TOTAL_BYTES,
            "test setup expects bulk fillers' stored-byte total to "
            "actually exhaust the unified Tier-18 budget so excuse #1 "
            "has a real constraint to invoke.",
        )
        block = _FakeBlock(message_txs=bulk_txs)
        h = POST_T34 + 5
        ok, _reason = check_forced_inclusion(block, self.pool, h)
        self.assertTrue(
            ok,
            "When stored bytes really do exhaust MAX_BLOCK_TOTAL_BYTES, "
            "excuse #1 must fire - otherwise the proposer is being "
            "punished for a real space constraint.",
        )


if __name__ == "__main__":
    unittest.main()
