"""Critical-severity audit fixes — round 6 (2026-04-26).

Three CRITICAL issues, all the same root cause: the v1.14.0 round-5
fix for `past_receipt_subtree_roots` (rotation no longer wipes
outstanding evidence) has multiple integration gaps that effectively
disable the fix in production.

#1 — Block-apply path (`_apply_authority_tx` -> `SetReceiptSubtreeRoot`)
inlines the live-root overwrite WITHOUT routing through
`_record_receipt_subtree_root`, so the past-roots history is NEVER
populated on consensus replay.  The `apply_set_receipt_subtree_root`
helper that DOES use `_record_...` is dead production code (only
tests call it).  A coerced validator who has issued thousands of
receipts under R1 publishes one cold-key SetReceiptSubtreeRoot(R2)
in a block; on every honest peer, R1 is now inadmissible — the v1.14.0
defense doesn't run.

#2 — `_snapshot_memory_state` / `_restore_memory_snapshot` omit
`receipt_subtree_roots` and `past_receipt_subtree_roots`.  A bad-
state-root block whose apply path mutates the maps gets caught by
the state-root check and rolled back, but the snapshot didn't
capture these fields, so the in-memory maps keep the rejected-
block mutations.

#3 — `past_receipt_subtree_roots` not committed to the state-snapshot
root.  Two state-synced nodes that observed different rotation
histories produce the same `state_root` but disagree on
`receipt_root_admissible` -> fork on the next contested
CensorshipEvidence.

All three converge on the same problem: the rotation-history map is
not properly threaded through the chain's persistence + snapshot
machinery.
"""

from __future__ import annotations

import unittest

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.storage.state_snapshot import (
    encode_snapshot, decode_snapshot, serialize_state, compute_state_root,
)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1 — _apply_authority_tx must populate past_receipt_subtree_roots
# ─────────────────────────────────────────────────────────────────────

class TestApplyAuthorityTxPopulatesPastRoots(unittest.TestCase):
    """When a SetReceiptSubtreeRoot tx is applied via the block-apply
    dispatcher (`_apply_authority_tx`), the OLD root MUST land in
    `past_receipt_subtree_roots` so subsequent receipt validation
    can still admit receipts issued under it.  Pre-fix the
    dispatcher inlined the overwrite and bypassed
    `_record_receipt_subtree_root`, leaving the rotation-history
    map empty -> the v1.14.0 defense was non-functional in
    production.
    """

    def test_apply_authority_tx_records_past_root_after_rotation(self):
        from messagechain.core.receipt_subtree_root import (
            SetReceiptSubtreeRootTransaction,
            create_set_receipt_subtree_root_transaction,
        )
        alice = Entity.create(b"r6-apply-past-alice".ljust(32, b"\x00"))
        # Use a separate cold key so SetReceiptSubtreeRoot is signed
        # under it (apply path validates signature).
        cold = Entity.create(b"r6-apply-past-cold".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        # Promote cold as alice's authority key.
        chain.authority_keys[alice.entity_id] = cold.public_key
        # Fund alice so the SetReceiptSubtreeRoot fee can be paid.
        chain.supply.balances[alice.entity_id] = 100_000

        # First rotation: install root R1.
        r1 = b"\xa1" * 32
        tx1 = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=r1,
            authority_signer=cold,
            fee=100,
        )
        chain._apply_authority_tx(tx1, proposer_id=alice.entity_id, base_fee=0)
        self.assertEqual(chain.receipt_subtree_roots.get(alice.entity_id), r1)
        # First install -- no prior root, so past_roots may be empty.

        # Second rotation: install root R2.  R1 MUST land in past_roots.
        r2 = b"\xa2" * 32
        tx2 = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=r2,
            authority_signer=cold,
            fee=100,
        )
        chain._apply_authority_tx(tx2, proposer_id=alice.entity_id, base_fee=0)

        self.assertEqual(chain.receipt_subtree_roots.get(alice.entity_id), r2)
        history = chain.past_receipt_subtree_roots.get(alice.entity_id, set())
        self.assertIn(
            r1, history,
            "Block-apply path MUST route through _record_receipt_subtree_root "
            "so the OLD root lands in past_receipt_subtree_roots.  Otherwise "
            "the v1.14.0 rotation-evidence-wipe defense is dead in "
            "production -- a coerced validator wipes all outstanding "
            "censorship evidence with one rotation tx.",
        )
        # Also confirm receipt_root_admissible accepts R1 under the
        # new root (the whole point of the history).
        self.assertTrue(
            chain.receipt_root_admissible(alice.entity_id, r1),
            "After rotation R1 -> R2, receipts signed under R1 must "
            "remain admissible.",
        )
        self.assertTrue(
            chain.receipt_root_admissible(alice.entity_id, r2),
            "After rotation R1 -> R2, receipts signed under R2 must "
            "be admissible.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2 — snapshot/restore round-trip for receipt-root maps
# ─────────────────────────────────────────────────────────────────────

class TestSnapshotMemoryStateCapturesReceiptRoots(unittest.TestCase):
    """`_snapshot_memory_state` must capture both `receipt_subtree_roots`
    AND `past_receipt_subtree_roots` so a failed-state-root rollback
    via `_restore_memory_snapshot` reverts any mutations the rejected
    block made to either map.  Without this, an attacker who submits
    a bad-state-root block whose apply-path mutated the live map gets
    a permanent attacker-injected root on the rolled-back node."""

    def test_snapshot_includes_both_receipt_root_maps(self):
        alice = Entity.create(b"r6-snap-alice".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid = b"\x77" * 32
        chain.receipt_subtree_roots[eid] = b"\xb1" * 32
        chain.past_receipt_subtree_roots[eid] = {b"\xa1" * 32, b"\xa2" * 32}
        snap = chain._snapshot_memory_state()
        self.assertIn(
            "receipt_subtree_roots", snap,
            "snapshot MUST include receipt_subtree_roots",
        )
        self.assertIn(
            "past_receipt_subtree_roots", snap,
            "snapshot MUST include past_receipt_subtree_roots",
        )
        self.assertEqual(snap["receipt_subtree_roots"][eid], b"\xb1" * 32)
        self.assertEqual(
            snap["past_receipt_subtree_roots"][eid],
            {b"\xa1" * 32, b"\xa2" * 32},
        )

    def test_restore_reverts_mutations_to_receipt_root_maps(self):
        alice = Entity.create(b"r6-snap-restore".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid = b"\x88" * 32
        # Pre-block state: live root R_honest, no history.
        chain.receipt_subtree_roots[eid] = b"\xb1" * 32
        chain.past_receipt_subtree_roots[eid] = set()
        snap = chain._snapshot_memory_state()
        # Simulate a rejected block that mutated both maps.
        chain.receipt_subtree_roots[eid] = b"\xc9" * 32  # attacker root
        chain.past_receipt_subtree_roots[eid] = {b"\xb1" * 32}
        chain._restore_memory_snapshot(snap)
        self.assertEqual(
            chain.receipt_subtree_roots.get(eid), b"\xb1" * 32,
            "Rollback MUST restore the pre-block live root.",
        )
        self.assertEqual(
            chain.past_receipt_subtree_roots.get(eid, set()), set(),
            "Rollback MUST restore the pre-block history (empty here).",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #3 — past_receipt_subtree_roots in state-snapshot root commitment
# ─────────────────────────────────────────────────────────────────────

class TestStateSnapshotIncludesPastRoots(unittest.TestCase):
    """The state-snapshot root MUST commit to
    `past_receipt_subtree_roots`.  Otherwise two state-synced nodes
    that observed different rotation histories produce the same
    `state_root` but disagree on which receipts are admissible ->
    fork on first contested CensorshipEvidence.  Verified by the
    encode/decode round-trip (round-trip safety) AND by the
    `compute_state_root` divergence test (any difference in the
    history must produce different roots)."""

    def test_serialize_state_extracts_past_receipt_subtree_roots(self):
        alice = Entity.create(b"r6-ss-extract".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid = b"\x55" * 32
        chain.past_receipt_subtree_roots[eid] = {b"\xa1" * 32}
        snap = serialize_state(chain)
        self.assertIn(
            "past_receipt_subtree_roots", snap,
            "serialize_state MUST extract past_receipt_subtree_roots "
            "for state-snapshot root commitment.",
        )
        self.assertEqual(
            snap["past_receipt_subtree_roots"][eid], {b"\xa1" * 32},
        )

    def test_encode_decode_round_trip_preserves_past_roots(self):
        from messagechain.storage.state_snapshot import deserialize_state
        # Build a snapshot with non-trivial past_receipt_subtree_roots.
        alice = Entity.create(b"r6-ss-rt".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid_a = b"\x33" * 32
        eid_b = b"\x44" * 32
        chain.past_receipt_subtree_roots[eid_a] = {b"\x01" * 32, b"\x02" * 32}
        chain.past_receipt_subtree_roots[eid_b] = {b"\x03" * 32}
        snap = serialize_state(chain)
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        decoded = deserialize_state(decoded)
        self.assertEqual(
            decoded["past_receipt_subtree_roots"][eid_a],
            {b"\x01" * 32, b"\x02" * 32},
        )
        self.assertEqual(
            decoded["past_receipt_subtree_roots"][eid_b],
            {b"\x03" * 32},
        )

    def test_state_root_diverges_when_past_roots_differ(self):
        """Two snapshots identical except for past_receipt_subtree_roots
        MUST produce DIFFERENT state roots."""
        alice = Entity.create(b"r6-ss-div".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        snap_a = serialize_state(chain)
        snap_b = serialize_state(chain)
        # Inject a past-root entry into b only.
        snap_b["past_receipt_subtree_roots"] = {b"\x99" * 32: {b"\xee" * 32}}
        snap_a["past_receipt_subtree_roots"] = {}
        root_a = compute_state_root(snap_a)
        root_b = compute_state_root(snap_b)
        self.assertNotEqual(
            root_a, root_b,
            "State-snapshot root MUST commit to past_receipt_subtree_roots "
            "or two state-synced nodes with different rotation histories "
            "agree on root but disagree on receipt admissibility -> "
            "silent fork on first contested CensorshipEvidence.",
        )


if __name__ == "__main__":
    unittest.main()
