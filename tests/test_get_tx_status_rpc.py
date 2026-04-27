"""RPC: get_tx_status returns inclusion-status metadata for a tx_hash.

Backs the `messagechain receipt <tx_hash>` CLI.  The RPC has three
response shapes, distinguished by `status`:

  * "included"  — tx is in a block; result carries block_height,
                  block_hash, tx_index, attesters, threshold flags,
                  and an inclusion proof against the block's
                  merkle_root.
  * "pending"   — tx is in mempool but not yet in a block; result
                  surfaces blocks_waited so the CLI can print the
                  submit-evidence escalation.
  * "not_found" — tx is in neither.  The receipt CLI uses this to
                  print the three-cause diagnostic.

Tests exercise the dispatch layer directly without spinning up a
real network.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock


class _FakeFinality:
    def __init__(self, attesters=None, attested_stake=0):
        self.attestations = {}
        if attesters is not None:
            for bh, validator_set in attesters.items():
                self.attestations[bh] = set(validator_set)
        self.attested_stake = {}


class _FakeMempool:
    def __init__(self, pending=None, react=None, slash=None,
                 cens=None, finality=None, orphan=None):
        self.pending = dict(pending or {})
        self.react_pool = dict(react or {})
        self.slash_pool = dict(slash or {})
        self.censorship_evidence_pool = dict(cens or {})
        self.finality_pool = dict(finality or {})
        self.orphan_pool = dict(orphan or {})


class _FakeBlock:
    def __init__(self, block_hash, header, txs, attestations=None):
        self.block_hash = block_hash
        self.header = header
        self.transactions = txs
        self.transfer_transactions = []
        self.slash_transactions = []
        self.governance_txs = []
        self.authority_txs = []
        self.stake_transactions = []
        self.unstake_transactions = []
        self.finality_votes = []
        self.custody_proofs = []
        self.censorship_evidence_txs = []
        self.bogus_rejection_evidence_txs = []
        self.attestations = attestations or []


class _FakeBlockHeader:
    def __init__(self, merkle_root, block_number, timestamp=0,
                 state_root=b"\x00" * 32):
        self.merkle_root = merkle_root
        self.block_number = block_number
        self.timestamp = timestamp
        self.state_root = state_root


class _FakeTx:
    def __init__(self, tx_hash):
        self.tx_hash = tx_hash


class _FakeBlockchain:
    def __init__(self, height=10, db=None, finality=None,
                 chain=None, staked=None):
        self.height = height
        self.db = db
        self.finality = finality or _FakeFinality()
        self.chain = chain or []
        self.supply = MagicMock()
        self.supply.staked = staked or {}

    def get_block(self, idx):
        if 0 <= idx < len(self.chain):
            return self.chain[idx]
        return None


class _FakeChainDB:
    def __init__(self, locations=None):
        self.locations = locations or {}

    def get_tx_location(self, tx_hash):
        return self.locations.get(tx_hash)


class TestGetTxStatusRPC(unittest.TestCase):

    def setUp(self):
        from server import Server
        self.server = Server.__new__(Server)

    def _request(self, tx_hash_hex):
        return {"params": {"tx_hash": tx_hash_hex}}

    def test_included_tx_returns_full_metadata(self):
        """A tx that landed in block N has its block_height, attesters,
        and merkle proof in the response."""
        from server import Server

        # Build a chain with two blocks: block 0 (genesis-like, holding tx)
        # and block 1 (carries attestations FOR block 0 — that's where
        # parent attestations live).
        tx_hash = bytes(range(32))
        tx_hash_hex = tx_hash.hex()

        block_0 = _FakeBlock(
            block_hash=b"\xa0" * 32,
            header=_FakeBlockHeader(
                merkle_root=b"\xff" * 32, block_number=0, timestamp=1000,
            ),
            txs=[_FakeTx(tx_hash)],
        )
        # Attestations on block 0 live in block 1.
        att_a = MagicMock()
        att_a.validator_id = b"\x01" * 32
        att_a.block_hash = block_0.block_hash
        att_b = MagicMock()
        att_b.validator_id = b"\x02" * 32
        att_b.block_hash = block_0.block_hash
        block_1 = _FakeBlock(
            block_hash=b"\xb0" * 32,
            header=_FakeBlockHeader(
                merkle_root=b"\xee" * 32, block_number=1, timestamp=1600,
            ),
            txs=[],
            attestations=[att_a, att_b],
        )

        finality = _FakeFinality(
            attesters={block_0.block_hash: {b"\x01" * 32, b"\x02" * 32}},
        )
        finality.attested_stake[block_0.block_hash] = 800
        db = _FakeChainDB(locations={tx_hash: (0, 0)})
        bc = _FakeBlockchain(
            height=2, db=db, finality=finality,
            chain=[block_0, block_1],
            staked={b"\x01" * 32: 400, b"\x02" * 32: 400, b"\x03" * 32: 200},
        )
        self.server.blockchain = bc
        self.server.mempool = _FakeMempool()

        result = Server._rpc_get_tx_status(
            self.server, {"tx_hash": tx_hash_hex},
        )

        self.assertTrue(result["ok"], f"got: {result}")
        r = result["result"]
        self.assertEqual(r["status"], "included")
        self.assertEqual(r["block_height"], 0)
        self.assertEqual(r["tx_index"], 0)
        self.assertEqual(r["block_hash"], (b"\xa0" * 32).hex())
        self.assertEqual(r["merkle_root"], (b"\xff" * 32).hex())
        # Two attesters, total stake 1000, attesting stake 800 -> 80% > 2/3.
        self.assertEqual(r["attesters"], 2)
        self.assertTrue(r["finality_threshold_met"])
        self.assertEqual(r["finality_numerator"], 2)
        self.assertEqual(r["finality_denominator"], 3)
        self.assertEqual(r["total_stake"], 1000)
        self.assertEqual(r["attesting_stake"], 800)
        # Inclusion proof.
        self.assertIn("merkle_proof", r)
        self.assertEqual(r["merkle_proof"]["tx_hash"], tx_hash_hex)
        self.assertEqual(r["merkle_proof"]["tx_index"], 0)

    def test_pending_tx_in_mempool(self):
        from server import Server
        tx_hash = b"\xcd" * 32
        tx_hash_hex = tx_hash.hex()

        db = _FakeChainDB(locations={})
        bc = _FakeBlockchain(height=10, db=db)
        self.server.blockchain = bc
        self.server.mempool = _FakeMempool(pending={tx_hash: _FakeTx(tx_hash)})

        result = Server._rpc_get_tx_status(
            self.server, {"tx_hash": tx_hash_hex},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"]["status"], "pending")
        self.assertTrue(result["result"]["in_mempool"])

    def test_not_found_returns_status_not_found(self):
        from server import Server
        tx_hash = b"\xee" * 32
        tx_hash_hex = tx_hash.hex()

        db = _FakeChainDB(locations={})
        bc = _FakeBlockchain(height=10, db=db)
        self.server.blockchain = bc
        self.server.mempool = _FakeMempool()

        result = Server._rpc_get_tx_status(
            self.server, {"tx_hash": tx_hash_hex},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"]["status"], "not_found")

    def test_invalid_hex_param_returns_error(self):
        from server import Server
        self.server.blockchain = _FakeBlockchain()
        self.server.mempool = _FakeMempool()

        result = Server._rpc_get_tx_status(
            self.server, {"tx_hash": "not-hex"},
        )
        self.assertFalse(result["ok"])

    def test_missing_tx_hash_param_returns_error(self):
        from server import Server
        self.server.blockchain = _FakeBlockchain()
        self.server.mempool = _FakeMempool()

        result = Server._rpc_get_tx_status(self.server, {})
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
