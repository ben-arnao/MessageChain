"""get_nonce RPC must return the mempool-aware next nonce.

Observed on mainnet 2026-04-25 during a stake-rebalance: client A
submitted set-authority-key (consuming nonce N), then client A
fetched get_nonce while the set-authority-key was still in the
mempool. get_nonce returned the chain-state nonce N (the OLD
"next") instead of N+1 (the actual "next available"). The CLI
signed a transfer at nonce N and got rejected at submission with
"Invalid nonce: expected N+1, got N", because submission validates
against _get_pending_nonce_all_pools, which IS mempool-aware. The
rejection persists until the pending tx lands in a block — a
~10-minute wedge for any operator scripting consecutive ops.

The fix routes the get_nonce RPC through _get_pending_nonce_all_pools
so the read and write paths agree. This regression test proves the
contract: a fresh tx in any pending pool must move get_nonce's
result to the next nonce, not stay stuck at the chain-state value.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock


class TestGetNonceMempoolAware(unittest.TestCase):

    def setUp(self):
        from messagechain import config
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        from messagechain import config
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _make_server(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool
        from messagechain.identity.identity import Entity

        entity = Entity.create(
            b"get-nonce-mempool-test" + b"\x00" * 10, tree_height=6,
        )
        chain = Blockchain()
        chain.initialize_genesis(entity)
        chain.supply.balances[entity.entity_id] = 1_000_000

        server = MagicMock()
        server.blockchain = chain
        server.mempool = Mempool()
        server._pending_stake_txs = {}
        server._pending_unstake_txs = {}
        server._pending_authority_txs = {}
        server._pending_governance_txs = {}

        return server, entity

    def _call_get_nonce_rpc(self, srv, entity_id_hex):
        """Drive the same code path as the live RPC dispatch.

        Server._process_rpc is the async dispatcher; route the
        synthetic request through it so the test exercises the
        actual elif method == "get_nonce" branch (rather than
        copying that branch's logic into the test).
        """
        import asyncio
        import server as server_module
        Server = server_module.Server
        srv._get_pending_nonce_all_pools = (
            lambda eid: Server._get_pending_nonce_all_pools(srv, eid)
        )
        request = {
            "method": "get_nonce",
            "params": {"entity_id": entity_id_hex},
        }
        return asyncio.run(Server._process_rpc(srv, request, ""))

    def test_get_nonce_returns_chain_nonce_when_mempool_empty(self):
        srv, entity = self._make_server()
        srv.blockchain.nonces[entity.entity_id] = 7
        resp = self._call_get_nonce_rpc(srv, entity.entity_id_hex)
        self.assertTrue(resp.get("ok"), resp)
        self.assertEqual(resp["result"]["nonce"], 7,
            "Empty mempool: get_nonce must equal the chain-state nonce.")

    def test_get_nonce_advances_when_stake_pending(self):
        from messagechain.core.staking import create_stake_transaction
        from messagechain.config import MIN_FEE

        srv, entity = self._make_server()
        srv.blockchain.nonces[entity.entity_id] = 0

        baseline = self._call_get_nonce_rpc(srv, entity.entity_id_hex)
        self.assertEqual(baseline["result"]["nonce"], 0)

        # Inject a pending stake tx at nonce 0 (the next chain nonce).
        # After this, get_nonce must report 1, NOT 0 — otherwise the
        # next tx would sign at nonce 0 and be rejected at submission.
        stake_tx = create_stake_transaction(
            entity, amount=10_000, nonce=0, fee=MIN_FEE,
        )
        srv._pending_stake_txs[stake_tx.tx_hash] = stake_tx

        resp = self._call_get_nonce_rpc(srv, entity.entity_id_hex)
        self.assertTrue(resp.get("ok"), resp)
        self.assertEqual(
            resp["result"]["nonce"], 1,
            "Pending stake tx at nonce 0 must advance get_nonce to 1. "
            "Without this, consecutive ops collide on the same nonce "
            "and the second one is rejected at submission with "
            "'Invalid nonce: expected 1, got 0' until the first lands.",
        )

    def test_get_nonce_advances_when_unstake_pending(self):
        from messagechain.core.staking import (
            create_stake_transaction, create_unstake_transaction,
        )
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.config import MIN_FEE

        srv, entity = self._make_server()

        # Land a stake first so the entity has staked balance to unstake.
        stx = create_stake_transaction(
            entity, amount=100_000, nonce=0, fee=MIN_FEE,
        )
        consensus = ProofOfStake()
        block = srv.blockchain.propose_block(
            consensus, entity, [], stake_transactions=[stx],
        )
        ok, reason = srv.blockchain.add_block(block)
        self.assertTrue(ok, reason)

        # Chain nonce should now be 1 (stake at 0 consumed, stake itself
        # advances entity nonce by 1). get_nonce returns 1 with empty pool.
        baseline = self._call_get_nonce_rpc(srv, entity.entity_id_hex)
        self.assertEqual(baseline["result"]["nonce"], 1)

        # Inject pending unstake at nonce 1.
        utx = create_unstake_transaction(
            entity, amount=10_000, nonce=1, fee=MIN_FEE,
        )
        srv._pending_unstake_txs[utx.tx_hash] = utx

        resp = self._call_get_nonce_rpc(srv, entity.entity_id_hex)
        self.assertEqual(
            resp["result"]["nonce"], 2,
            "Pending unstake at nonce 1 must advance get_nonce to 2.",
        )


if __name__ == "__main__":
    unittest.main()
