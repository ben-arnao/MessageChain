"""Tests for iteration 3h: Sybil binding via registration requirement.

Closes concern #2 from the post-3g audit: after 3f's signed proofs,
an attacker could still generate N fake keypairs and occupy N lottery
slots at trivial cost (keygen + 1 signature per proof).  Marginal
Sybil cost was near-zero.

The fix ties prover_id to an on-chain-registered entity: a proof's
`prover_id` must appear in `chain.public_keys` (i.e., the entity has
done at least one on-chain transfer / tx that revealed its pubkey).
An attacker creating N fake identities must now fund N transfers —
each costing at least MIN_FEE tokens — which imposes a real economic
cost per Sybil identity.

What this closes:
    * Cheap unbounded Sybil: cost scales with fee × N instead of
      near-zero × N.
    * Keypairs generated solely for archive-reward harvesting: they
      can't collect unless pre-registered.

What this does NOT close:
    * Fetch-on-demand: a registered attacker still can win lottery
      slots without local storage.  That's concern #1, unaffected.
    * A wealthy attacker who funds many registrations: still
      bounded by their willingness to pay fees.  Raises the bar,
      not an absolute floor.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import (
    ARCHIVE_REWARD,
    ARCHIVE_PROOFS_PER_CHALLENGE,
    HASH_ALGO,
)
from messagechain.consensus.archive_challenge import (
    ArchiveRewardPool,
    apply_archive_rewards,
    build_custody_proof,
)


_ENTITY_POOL: list = []


def _entity(i: int):
    """Tree_height=1 — tests build one proof per entity, so 2 leaves is
    ample.  This keeps WOTS+ keygen to a single keypair per entity,
    which dominates runtime when the Sybil test builds 60 entities."""
    from messagechain.identity.identity import Entity
    while len(_ENTITY_POOL) <= i:
        seed = f"sybil-{len(_ENTITY_POOL)}".encode().ljust(32, b"\x00")
        _ENTITY_POOL.append(Entity.create(seed, tree_height=1))
    return _ENTITY_POOL[i]


def _h(b: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, b).digest()


def _mini_block(txs, block_number=1):
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": _h(header_bytes),
    }


def _proof(entity_idx: int, block):
    return build_custody_proof(
        entity=_entity(entity_idx),
        target_height=block["block_number"],
        target_block_hash=block["block_hash"],
        header_bytes=block["header_bytes"],
        merkle_root=block["merkle_root"],
        tx_index=0,
        tx_bytes=block["tx_bytes_list"][0],
        all_tx_hashes=block["tx_hashes"],
    )


# ---------------------------------------------------------------------------
# 1. Registered-only filter
# ---------------------------------------------------------------------------


class TestRegistrationFilter(unittest.TestCase):
    def setUp(self):
        self.block = _mini_block([b"tx-0" * 10, b"tx-1" * 10], 5)
        self.pool = ArchiveRewardPool()
        self.pool.fund(ARCHIVE_REWARD * 100)

    def test_all_proofs_from_registered_provers_pay_out(self):
        """All proofs whose prover_id is in the registered set get
        paid (when cap and pool allow).  Baseline — registration
        doesn't break honest operation."""
        proofs = [_proof(i, self.block) for i in range(5)]
        registered = {p.prover_id for p in proofs}
        result = apply_archive_rewards(
            proofs=proofs,
            pool=self.pool,
            expected_block_hash=self.block["block_hash"],
            registered_provers=registered,
        )
        self.assertEqual(len(result.payouts), 5)

    def test_unregistered_provers_rejected(self):
        """Proofs from prover_ids NOT in the registered set are
        rejected before payout — this is the Sybil binding."""
        registered_proof = _proof(10, self.block)
        sybil_proofs = [_proof(i + 100, self.block) for i in range(5)]
        registered = {registered_proof.prover_id}
        all_proofs = [registered_proof] + sybil_proofs
        result = apply_archive_rewards(
            proofs=all_proofs,
            pool=self.pool,
            expected_block_hash=self.block["block_hash"],
            registered_provers=registered,
        )
        # Only the registered proof pays.
        self.assertEqual(len(result.payouts), 1)
        self.assertEqual(result.payouts[0].prover_id, registered_proof.prover_id)
        # Sybil submissions appear in the rejected list.
        self.assertGreaterEqual(
            len(result.rejected), 5,
            "every Sybil submission should be recorded as rejected",
        )

    def test_none_registration_set_permits_all(self):
        """Backward compat: when registered_provers=None (not passed),
        the check is skipped.  Retained for unit tests that don't
        care about registration; live-chain callers always pass a set.
        """
        proofs = [_proof(i + 200, self.block) for i in range(3)]
        result = apply_archive_rewards(
            proofs=proofs,
            pool=self.pool,
            expected_block_hash=self.block["block_hash"],
            registered_provers=None,
        )
        self.assertEqual(len(result.payouts), 3)

    def test_empty_registration_set_rejects_all(self):
        """Empty set = nobody registered yet = nobody paid.  Covers
        the bootstrap-era case before any on-chain activity."""
        proofs = [_proof(i + 300, self.block) for i in range(3)]
        result = apply_archive_rewards(
            proofs=proofs,
            pool=self.pool,
            expected_block_hash=self.block["block_hash"],
            registered_provers=set(),
        )
        self.assertEqual(len(result.payouts), 0)


# ---------------------------------------------------------------------------
# 2. Sybil attack scenario: registration dominates the attack bound
# ---------------------------------------------------------------------------


class TestSybilBounded(unittest.TestCase):
    def test_unregistered_sybil_wins_zero_slots(self):
        """Concrete Sybil scenario: attacker generates 50 fresh
        keypairs and submits 50 proofs.  None are registered on-chain.
        Legitimate 10 submitters are registered.  Only the registered
        10 can win — attacker's 50 slots are zero-weight in the
        lottery.

        This is the intended effect: Sybil capacity is now strictly
        capped at the attacker's willingness to spend real tokens on
        registration transactions, not by the number of keys they can
        generate for free."""
        block = _mini_block([b"tx-0" * 10], 5)
        pool = ArchiveRewardPool()
        pool.fund(ARCHIVE_REWARD * 100)

        legit = [_proof(i + 400, block) for i in range(10)]
        sybil = [_proof(i + 500, block) for i in range(50)]
        registered = {p.prover_id for p in legit}
        result = apply_archive_rewards(
            proofs=legit + sybil,
            pool=pool,
            expected_block_hash=block["block_hash"],
            registered_provers=registered,
            max_payouts=20,  # plenty of slots to reveal the attack bound
        )
        # Every paid slot belongs to a legit submitter.
        for payout in result.payouts:
            self.assertIn(payout.prover_id, registered)
        # Cap bound: all 10 legit submitters paid; Sybil gets nothing.
        self.assertEqual(len(result.payouts), 10)


if __name__ == "__main__":
    unittest.main()
