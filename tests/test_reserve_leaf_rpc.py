"""Tests for the reserve_leaf RPC + matching block-sign serialization.

Co-residency motivation: when an operator runs `messagechain transfer`
on the same host as the validator daemon and both signers share one
entity (the wallet), each has an independent view of WOTS+ next-leaf.
Without coordination, both can pick the same leaf — two signatures at
one leaf mathematically reveal the private key.

`reserve_leaf` gives the CLI an atomic, server-mediated leaf so the
daemon's block-production counter is guaranteed to skip the leaf the
CLI is about to sign at.  These tests pin the contract:

  1. A matching-entity reserve advances the server's in-memory
     _next_leaf AND persists the advance (so a crash-restart skips
     the reserved leaf).
  2. Repeated reserves hand out distinct leaves.
  3. Non-matching-entity reserves return a hint but do NOT advance
     the wallet keypair (off-host signer case — we don't own their
     keypair, so we can't burn a leaf on their behalf).
  4. The chain watermark acts as a floor: if the chain has seen
     leaf=N but the in-memory counter lags at <N (impossible under
     normal ops, but possible after a snapshot restore or manual DB
     rollback), reserve_leaf returns N, not the stale counter.
  5. Exhausted trees return an error instead of handing out an OOB leaf.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain import config
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from messagechain.config import LEAF_INDEX_FILENAME


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _ReserveLeafBase(unittest.TestCase):

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_server_with_wallet(self, entity: Entity, chain: Blockchain = None):
        """Build a minimally-viable Server stub wired to an entity + chain.

        Uses Server.__new__ to skip the heavy __init__ (network listeners,
        disk setup).  We only touch _rpc_reserve_leaf, which needs
        self.blockchain / self.wallet_entity / self.wallet_id / the leaf
        lock — nothing else.
        """
        from server import Server
        import threading
        srv = Server.__new__(Server)
        srv.blockchain = chain if chain is not None else Blockchain()
        srv.wallet_entity = entity
        srv.wallet_id = entity.entity_id
        srv._wallet_leaf_lock = threading.Lock()
        return srv


class TestReserveLeafMatchingEntity(_ReserveLeafBase):
    """Reserves on the server's own wallet advance the in-memory counter."""

    def test_first_reserve_returns_zero(self):
        alice = _entity(b"reserve-match-alice")
        srv = self._make_server_with_wallet(alice)

        resp = srv._rpc_reserve_leaf({"entity_id": alice.entity_id.hex()})

        self.assertTrue(resp["ok"])
        self.assertEqual(resp["result"]["leaf_index"], 0)
        self.assertTrue(resp["result"]["reserved"])
        # In-memory counter advanced past the reserved leaf
        self.assertEqual(alice.keypair._next_leaf, 1)

    def test_successive_reserves_hand_out_distinct_leaves(self):
        alice = _entity(b"reserve-match-distinct")
        srv = self._make_server_with_wallet(alice)

        leaves = []
        for _ in range(5):
            resp = srv._rpc_reserve_leaf({"entity_id": alice.entity_id.hex()})
            self.assertTrue(resp["ok"])
            self.assertTrue(resp["result"]["reserved"])
            leaves.append(resp["result"]["leaf_index"])

        self.assertEqual(leaves, [0, 1, 2, 3, 4])
        self.assertEqual(len(set(leaves)), len(leaves))
        self.assertEqual(alice.keypair._next_leaf, 5)

    def test_reserve_persists_advance_to_disk(self):
        """A reserved leaf survives a crash-restart via leaf_index.json."""
        alice = _entity(b"reserve-persist-alice")
        leaf_path = os.path.join(self._tmpdir, LEAF_INDEX_FILENAME)
        alice.keypair.leaf_index_path = leaf_path

        srv = self._make_server_with_wallet(alice)
        resp = srv._rpc_reserve_leaf({"entity_id": alice.entity_id.hex()})
        self.assertTrue(resp["ok"])
        reserved = resp["result"]["leaf_index"]

        # Simulate a crash + restart: build a fresh keypair from the same
        # seed and re-bind the leaf-index path.  load_leaf_index must lift
        # the in-memory counter past the reserved leaf.
        fresh = _entity(b"reserve-persist-alice")
        fresh.keypair.leaf_index_path = leaf_path
        fresh.keypair.load_leaf_index(leaf_path)
        self.assertGreater(fresh.keypair._next_leaf, reserved)


class TestReserveLeafOffHostSigner(_ReserveLeafBase):
    """Reserves for a non-wallet entity return a hint without side effects."""

    def test_reserve_for_stranger_does_not_advance_wallet(self):
        alice = _entity(b"reserve-offhost-alice")
        bob = _entity(b"reserve-offhost-bob")
        srv = self._make_server_with_wallet(alice)

        alice_leaf_before = alice.keypair._next_leaf
        resp = srv._rpc_reserve_leaf({"entity_id": bob.entity_id.hex()})

        self.assertTrue(resp["ok"])
        self.assertFalse(resp["result"]["reserved"])
        # The alice keypair (the wallet) is untouched — we didn't own
        # bob's keypair, so we couldn't (and must not) burn alice's leaf.
        self.assertEqual(alice.keypair._next_leaf, alice_leaf_before)

    def test_reserve_for_stranger_returns_chain_watermark_hint(self):
        alice = _entity(b"reserve-hint-alice")
        bob = _entity(b"reserve-hint-bob")
        srv = self._make_server_with_wallet(alice)
        # Chain has never seen bob → watermark is 0, returned as hint.
        resp = srv._rpc_reserve_leaf({"entity_id": bob.entity_id.hex()})
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["result"]["leaf_index"], 0)


class TestReserveLeafChainWatermarkFloor(_ReserveLeafBase):
    """Chain watermark is a floor even if in-memory counter lags."""

    def test_watermark_above_in_memory_wins(self):
        alice = _entity(b"reserve-watermark-alice")
        chain = Blockchain()

        # Simulate chain state having observed a much higher leaf than
        # the in-memory counter tracks.  Real-world trigger: snapshot
        # restore before the keypair is warmed back up.
        chain.leaf_watermarks = {alice.entity_id: 10}
        srv = self._make_server_with_wallet(alice, chain=chain)

        # In-memory counter is still 0 — but the chain has seen 10.
        self.assertEqual(alice.keypair._next_leaf, 0)

        resp = srv._rpc_reserve_leaf({"entity_id": alice.entity_id.hex()})
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["result"]["leaf_index"], 10)
        self.assertEqual(alice.keypair._next_leaf, 11)


class TestReserveLeafExhaustion(_ReserveLeafBase):
    """Tree exhaustion surfaces a hard error instead of OOB leaf."""

    def test_exhausted_tree_errors(self):
        alice = _entity(b"reserve-exhaust-alice", height=3)  # 2**3 = 8 leaves
        # advance_to_leaf() forbids reaching num_leaves (that's the OOB
        # guard); write the counter directly to simulate a tree whose
        # last leaf has already been consumed.  This is the state the
        # handler is meant to refuse.
        alice.keypair._next_leaf = alice.keypair.num_leaves
        srv = self._make_server_with_wallet(alice)

        resp = srv._rpc_reserve_leaf({"entity_id": alice.entity_id.hex()})
        self.assertFalse(resp["ok"])
        self.assertIn("exhausted", resp["error"].lower())


class TestReserveLeafInvalidInput(_ReserveLeafBase):
    """Missing / malformed entity_id must error, not crash."""

    def test_missing_entity_id_errors(self):
        alice = _entity(b"reserve-invalid-alice")
        srv = self._make_server_with_wallet(alice)
        resp = srv._rpc_reserve_leaf({})
        self.assertFalse(resp["ok"])
        self.assertIn("entity_id", resp["error"].lower())

    def test_short_entity_id_errors(self):
        alice = _entity(b"reserve-invalid-alice")
        srv = self._make_server_with_wallet(alice)
        resp = srv._rpc_reserve_leaf({"entity_id": "deadbeef"})
        self.assertFalse(resp["ok"])
        self.assertIn("entity_id", resp["error"].lower())


if __name__ == "__main__":
    unittest.main()
