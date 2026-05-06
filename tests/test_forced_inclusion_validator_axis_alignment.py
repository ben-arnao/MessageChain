"""Audit r26 #1 — forced-inclusion gate must tally on the SAME axes the
block validator's caps actually enforce.

Pre-fix the multi-list gate (Tier 34) walked every kind in
``_BLOCK_TX_LIST_ATTRS`` (9 fields, including stake / unstake /
governance / authority / non-response-evidence / censorship-evidence)
when computing ``used_bytes``, ``used_count``, and ``entity_counts``.
The block validator's Tier-18 unified-budget check at
``blockchain.validate_block`` only sums message + transfer + react
bytes; the per-entity cap is message-only.

Net effect: a single colluding proposer could legitimately pack their
own stake / governance / authority / evidence txs into the block until
the gate's tally tripped excuse #1 (byte budget) or excuse #3
(per-entity cap) — and the block remained fully valid because the
validator's caps stayed unbroken.  The gate excused the omission of
the forced tx; CLAUDE.md anchor "a tx that pays at least the per-byte
floor and fits the byte budget cannot be suppressed by anything weaker
than a full validator-set majority" became unenforced for any forced
tx whenever any non-validator-counted kind was present in volume.

The fix aligns the gate's tally axes with the validator's:

  * ``used_bytes`` and ``used_count`` sum only kinds the Tier-18 budget
    accounts for (message + transfer + react).
  * ``entity_counts`` and the Tier 37 ``entity_block_txs`` count only
    message txs (the validator's per-entity cap is message-only).
  * Excuse #3 only applies when the forced tx itself is a message —
    for non-message forced txs the validator never enforces a
    per-entity cap, so no per-entity-cap-based excuse can legitimately
    apply.
  * ``included_hashes`` continues to walk every kind in
    ``_BLOCK_TX_LIST_ATTRS`` — that's the Tier 34 recognition fix
    (a forced tx placed in its correct kind-slot is still recognized
    as included).

Soft-fix: attester-side check only, no consensus rule change at the
block validator.  ``check_forced_inclusion`` is called only by
attester-vote paths (`should_attest_block` -> attestation), never by
``validate_block`` or by ``validate_censorship_evidence_tx``; past
attester votes are already cast and the change does not perturb
chain state determinism.  Two-validator coordinated upgrade.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    FEE_PER_BYTE,
    FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_BLOCK_TOTAL_BYTES,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
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


POST_T34 = FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT + 5
_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)
_BASE_FEE = MIN_FEE + 50 * FEE_PER_BYTE


class _FakeBlock:
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
        non_response_evidence_txs=None,
        censorship_evidence_txs=None,
        proposer_id=b"\x00" * 32,
    ):
        self.transactions = list(message_txs or [])
        self.transfer_transactions = list(transfer_txs or [])
        self.react_transactions = list(react_txs or [])
        self.stake_transactions = list(stake_txs or [])
        self.unstake_transactions = list(unstake_txs or [])
        self.governance_txs = list(governance_txs or [])
        self.authority_txs = list(authority_txs or [])
        self.non_response_evidence_txs = list(non_response_evidence_txs or [])
        self.censorship_evidence_txs = list(censorship_evidence_txs or [])
        self.header = _FakeBlock._H(proposer_id)


class _BulkBytesTx:
    """Stub block-side tx that just contributes a chosen byte count.

    The gate reads ``tx_hash`` (uniqueness inside ``included_hashes``),
    ``to_bytes()`` (for the byte-budget tally), the entity-id-style
    fields (for per-entity tally) and ``fee`` (for the Tier 37
    fpb-aware comparison).  No signature, no nonce — block validation
    happens elsewhere, the gate never verifies signatures.
    """
    __slots__ = ("tx_hash", "_blob", "entity_id", "fee", "message")

    def __init__(self, idx, target_bytes, entity_id, prefix=b"S"):
        self.tx_hash = (prefix + idx.to_bytes(8, "big")).ljust(32, b"\x00")
        self._blob = b"\x00" * target_bytes
        self.entity_id = entity_id
        self.fee = 100
        self.message = b""

    def to_bytes(self):
        return self._blob


# ────────────────────────────────────────────────────────────────────
# Excuse #1 (byte budget) must align with the validator's Tier-18 cap
# kind-set: only message + transfer + react contribute.  A colluding
# proposer cannot inflate ``used_bytes`` by stuffing the block with
# stake / governance / authority / evidence txs the validator's
# unified-budget check ignores.
# ────────────────────────────────────────────────────────────────────


class TestByteBudgetKindSetAlignment(unittest.TestCase):

    def setUp(self):
        self.alice = Entity.create(b"r26-byte-alice".ljust(32, b"\x00"), tree_height=2)
        self.bob = Entity.create(b"r26-byte-bob".ljust(32, b"\x00"), tree_height=2)
        self.pool = Mempool(max_size=200, fee_policy=_STATIC_FEE)

    def test_governance_authority_bytes_do_not_inflate_excuse_one(self):
        """Padding the block with governance / authority / stake byte
        mass — kinds the validator's Tier-18 unified-budget check
        ignores — must NOT trip excuse #1 (byte cap exhausted) for a
        forced message tx the proposer omitted.

        Pre-fix the gate summed every kind in ``_BLOCK_TX_LIST_ATTRS``.
        Six 35 KB stubs in ``governance_txs`` + ``authority_txs`` push
        gate-pre-fix ``used_bytes`` > ``MAX_BLOCK_TOTAL_BYTES``,
        excusing the omission.  The block validator's Tier-18 sum
        ignores these kinds entirely, so the block IS valid — there
        is no real space constraint on the forced tx.
        """
        # Bob's forced message — small stored size, far below cap.
        bob_forced = create_transaction(self.bob, "f", fee=10_000, nonce=0)
        self.pool.add_transaction(bob_forced, arrival_block_height=0)

        # Pad the block with non-validator-counted kinds.
        per_tx = 35_000
        n = (MAX_BLOCK_TOTAL_BYTES // per_tx) + 1  # 6 -> 210 KB > 200 KB cap
        gov_pads = [
            _BulkBytesTx(i, per_tx, self.alice.entity_id, prefix=b"G")
            for i in range(n // 2 + 1)
        ]
        auth_pads = [
            _BulkBytesTx(i, per_tx, self.alice.entity_id, prefix=b"A")
            for i in range(n - len(gov_pads))
        ]
        # Sanity-pin: validator's Tier-18-counted axis (message +
        # transfer + react) is empty -> well under cap; gate's pre-fix
        # axis (all kinds) is over cap.
        validator_counted_total = 0  # block has no message/transfer/react
        gate_pre_fix_total = sum(len(t.to_bytes()) for t in gov_pads + auth_pads)
        self.assertLess(
            validator_counted_total, MAX_BLOCK_TOTAL_BYTES,
            "test setup expects validator-counted bytes well under cap",
        )
        self.assertGreater(
            gate_pre_fix_total, MAX_BLOCK_TOTAL_BYTES,
            "test setup expects pre-fix gate total to exceed cap so the "
            "buggy excuse #1 path is exercised",
        )

        block = _FakeBlock(governance_txs=gov_pads, authority_txs=auth_pads)
        ok, reason = check_forced_inclusion(block, self.pool, POST_T34)
        self.assertFalse(
            ok,
            f"Validator's Tier-18 budget ignores governance / authority "
            f"bytes; the gate must NOT excuse the omission of a forced "
            f"message tx on byte-cap grounds when the validator-counted "
            f"axis is well under cap.  reason={reason!r}",
        )

    def test_real_message_bytes_still_trip_excuse_one(self):
        """Inverse: when MESSAGE bytes (a kind the validator's Tier-18
        budget DOES count) really do exhaust ``MAX_BLOCK_TOTAL_BYTES``,
        excuse #1 must still fire.  The fix tightens the rule, it does
        not delete it.
        """
        bob_forced = create_transaction(self.bob, "f", fee=10_000, nonce=0)
        self.pool.add_transaction(bob_forced, arrival_block_height=0)
        per_tx = 35_000
        n = (MAX_BLOCK_TOTAL_BYTES // per_tx) + 1
        msg_pads = [
            _BulkBytesTx(i, per_tx, self.alice.entity_id, prefix=b"M")
            for i in range(n)
        ]
        block = _FakeBlock(message_txs=msg_pads)
        ok, _reason = check_forced_inclusion(block, self.pool, POST_T34)
        self.assertTrue(
            ok,
            "When validator-counted bytes really do exhaust the cap, "
            "excuse #1 must still fire — otherwise the proposer is being "
            "punished for a real space constraint.",
        )


# ────────────────────────────────────────────────────────────────────
# Excuse #3 (per-entity cap) must align with the validator's
# message-only cap.  A colluding proposer cannot use same-entity
# transfer / governance volume to excuse omission of a same-entity
# forced message tx.
# ────────────────────────────────────────────────────────────────────


class TestPerEntityCapMessageOnlyAlignment(unittest.TestCase):

    def setUp(self):
        self.alice = Entity.create(
            b"r26-cap-alice".ljust(32, b"\x00"),
            # Alice signs MAX_TXS_PER_ENTITY_PER_BLOCK transfers + a
            # forced message: total ~quota+1 sigs.  ceil(log2(quota+2))
            # leaves; tree_height=5 -> 32 leaves covers the realistic
            # quota of 10.
            tree_height=5,
        )
        self.bob = Entity.create(b"r26-cap-bob".ljust(32, b"\x00"), tree_height=2)
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_same_entity_transfers_do_not_excuse_omission_of_forced_message(self):
        """The validator's per-entity cap (``MAX_TXS_PER_ENTITY_PER_BLOCK``)
        is enforced ONLY against ``block.transactions`` (message txs).
        A colluding proposer who fills alice's slot with quota-worth of
        transfers cannot use that volume to excuse omitting alice's
        forced message — alice's *message* count in the block is 0,
        well under the cap, and the validator would have admitted the
        forced message just fine.
        """
        # Stack alice's quota worth of transfers — these don't count
        # toward the validator's message-only per-entity cap.
        xfers = [
            create_transfer_transaction(
                self.alice, self.bob.entity_id,
                amount=100, nonce=n, fee=_BASE_FEE,
            )
            for n in range(MAX_TXS_PER_ENTITY_PER_BLOCK)
        ]
        # Forced message from alice — quota-exceeding only against the
        # gate's pre-fix multi-list count, not the validator's message-
        # only count.
        forced_msg = create_transaction(
            self.alice, "f", fee=_BASE_FEE,
            nonce=MAX_TXS_PER_ENTITY_PER_BLOCK,
        )
        self.pool.add_transaction(forced_msg, arrival_block_height=0)

        block = _FakeBlock(transfer_txs=xfers)  # forced message OMITTED
        ok, reason = check_forced_inclusion(block, self.pool, POST_T34)
        self.assertFalse(
            ok,
            f"Per-entity cap is message-only at the validator; transfers "
            f"in the block cannot legitimately excuse omitting a forced "
            f"message of the same sender.  reason={reason!r}",
        )

    def test_real_message_quota_still_excuses_forced_message(self):
        """Inverse: when alice already has the per-entity-cap-many
        message txs in the block, excuse #3 must still fire — the fix
        narrows the kind-set the gate counts, not the rule itself.
        """
        msgs = [
            create_transaction(
                self.alice, f"m{n}",
                fee=_BASE_FEE, nonce=n,
            )
            for n in range(MAX_TXS_PER_ENTITY_PER_BLOCK)
        ]
        forced_msg = create_transaction(
            self.alice, "f", fee=_BASE_FEE,
            nonce=MAX_TXS_PER_ENTITY_PER_BLOCK,
        )
        self.pool.add_transaction(forced_msg, arrival_block_height=0)

        block = _FakeBlock(message_txs=msgs)
        ok, _reason = check_forced_inclusion(block, self.pool, POST_T34)
        self.assertTrue(
            ok,
            "When alice's MESSAGE count in the block is at quota, excuse "
            "#3 must still excuse the proposer's omission of a further "
            "forced message — that's the validator's binding constraint.",
        )


# ────────────────────────────────────────────────────────────────────
# Excuse #3 cannot apply to non-message forced txs at all — the
# validator has no per-entity cap on transfer / governance / etc.
# ────────────────────────────────────────────────────────────────────


class TestPerEntityCapDoesNotApplyToNonMessageForced(unittest.TestCase):

    def setUp(self):
        self.alice = Entity.create(
            b"r26-nm-alice".ljust(32, b"\x00"), tree_height=5,
        )
        self.bob = Entity.create(b"r26-nm-bob".ljust(32, b"\x00"), tree_height=2)
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_forced_transfer_is_not_excused_by_same_entity_message_quota(self):
        """A forced TRANSFER tx of alice is not excusable on
        per-entity-cap grounds even if alice already has the cap-many
        messages in the block — the validator never per-entity-caps
        transfers, so the gate must not invent a constraint that does
        not exist."""
        # Alice fills her message quota in the block.
        msgs = [
            create_transaction(
                self.alice, f"m{n}",
                fee=_BASE_FEE, nonce=n,
            )
            for n in range(MAX_TXS_PER_ENTITY_PER_BLOCK)
        ]
        # Forced TRANSFER from alice — pre-fix the gate would count
        # alice's message contributions toward the per-entity cap and
        # excuse the omission.
        forced_xfer = create_transfer_transaction(
            self.alice, self.bob.entity_id,
            amount=100, nonce=MAX_TXS_PER_ENTITY_PER_BLOCK + 100,
            fee=_BASE_FEE,
        )
        # Use add_transaction with the transfer (the consensus mempool
        # holds both messages and transfers in `pending`).
        self.pool.add_transaction(forced_xfer, arrival_block_height=0)

        block = _FakeBlock(message_txs=msgs)  # forced transfer OMITTED
        ok, reason = check_forced_inclusion(block, self.pool, POST_T34)
        self.assertFalse(
            ok,
            f"Forced transfer must not be excused on per-entity-cap "
            f"grounds; the validator has no per-entity cap on transfers, "
            f"so the gate's excuse #3 cannot legitimately fire for a "
            f"non-message forced tx.  reason={reason!r}",
        )


# ────────────────────────────────────────────────────────────────────
# Tx-count cap (excuse #2) must align with the validator's tx-count
# cap kind-set: only message + transfer + react.  A block of 200
# governance_txs cannot trip the gate's excuse #2 if the validator's
# tx-count check would also pass (it does — governance is excluded).
# ────────────────────────────────────────────────────────────────────


class TestTxCountCapAlignment(unittest.TestCase):

    def setUp(self):
        self.alice = Entity.create(b"r26-cnt-alice".ljust(32, b"\x00"), tree_height=2)
        self.bob = Entity.create(b"r26-cnt-bob".ljust(32, b"\x00"), tree_height=2)
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_non_validator_kinds_do_not_consume_count_quota(self):
        """A flock of stake / governance / authority txs cannot
        legitimately trip excuse #2 (count quota exhausted) — the
        validator's tx-count check ignores those kinds, so a forced
        message would have fit by tx-count too."""
        from messagechain.config import MAX_TXS_PER_BLOCK

        bob_forced = create_transaction(self.bob, "f", fee=10_000, nonce=0)
        self.pool.add_transaction(bob_forced, arrival_block_height=0)

        # Many small stake/gov stubs — pre-fix gate counts each one
        # toward used_count; validator's count cap ignores them all.
        # MAX_TXS_PER_BLOCK + 1 stubs makes the pre-fix path saturate.
        n_pads = MAX_TXS_PER_BLOCK + 1
        stake_pads = [
            _BulkBytesTx(i, 64, self.alice.entity_id, prefix=b"S")
            for i in range(n_pads // 2)
        ]
        gov_pads = [
            _BulkBytesTx(i, 64, self.alice.entity_id, prefix=b"V")
            for i in range(n_pads - len(stake_pads))
        ]
        block = _FakeBlock(stake_txs=stake_pads, governance_txs=gov_pads)
        ok, reason = check_forced_inclusion(block, self.pool, POST_T34)
        self.assertFalse(
            ok,
            f"Validator's tx-count cap ignores stake / governance kinds; "
            f"gate must not invent excuse #2 against them.  reason={reason!r}",
        )


# ────────────────────────────────────────────────────────────────────
# Source-level pin: the validator-budget kind-set must remain a strict
# subset of `_BLOCK_TX_LIST_ATTRS`, and must include exactly the kinds
# the block validator's Tier-18 cap accounts for.  Drift here is the
# exact bug class this fix closes.
# ────────────────────────────────────────────────────────────────────


class TestValidatorBudgetKindSetSourcePin(unittest.TestCase):

    def test_validator_budget_attrs_export_exists(self):
        """The fix introduces a single source-of-truth tuple for the
        kinds the validator's byte/count caps account for.  A future
        contributor adding a new validator-counted kind must add it
        here in one place."""
        from messagechain.consensus import forced_inclusion as fi
        self.assertTrue(
            hasattr(fi, "_VALIDATOR_BUDGET_ATTRS"),
            "Fix must export `_VALIDATOR_BUDGET_ATTRS` as the single "
            "source-of-truth for the validator-counted kind-set.",
        )

    def test_validator_budget_attrs_is_subset_of_all_block_tx_lists(self):
        """Every validator-budget kind must also be in the gate's full
        walk tuple — the gate must recognize inclusion of forced txs
        in every kind-slot, even if it only TALLIES against the
        validator's narrower set."""
        from messagechain.consensus.forced_inclusion import (
            _VALIDATOR_BUDGET_ATTRS,
        )
        for attr in _VALIDATOR_BUDGET_ATTRS:
            self.assertIn(
                attr, _BLOCK_TX_LIST_ATTRS,
                f"`{attr}` is in the validator-budget set but not in "
                f"`_BLOCK_TX_LIST_ATTRS` — inclusion-recognition would "
                f"miss this kind-slot.",
            )

    def test_validator_budget_attrs_matches_tier_18_validator_kinds(self):
        """The validator's Tier-18 unified-budget check at
        ``blockchain.validate_block`` sums message + transfer + react.
        The source-of-truth tuple must match that exact set."""
        from messagechain.consensus.forced_inclusion import (
            _VALIDATOR_BUDGET_ATTRS,
        )
        self.assertEqual(
            tuple(_VALIDATOR_BUDGET_ATTRS),
            (
                "transactions",
                "transfer_transactions",
                "react_transactions",
            ),
            "If the validator's Tier-18 cap kind-set changes, this "
            "tuple must be updated in lock-step.  Drift here is the "
            "audit r26 #1 bug class.",
        )


if __name__ == "__main__":
    unittest.main()
