"""Audit r31 #1 -- cross-pool WOTS+ leaf-reuse admission gap.

Pre-fix `Server._check_leaf_across_all_pools` scanned every server-side
pool (`_pending_{stake,unstake,authority,governance}_txs`) plus
`mempool.react_pool`, but NOT `mempool.pending` (which holds both
messages and transfers).  Plus the RPC admission paths for messages
(`_rpc_submit_transaction`) and transfers (`_rpc_submit_transfer`)
both routed straight through `submit_transaction_to_mempool` without
ever calling `_check_leaf_across_all_pools` themselves.

Concrete bite: a message tx admits to `mempool.pending` at leaf=N.
A subsequent stake / unstake / authority / governance / react tx at
leaf=N from the same signer calls `_check_leaf_across_all_pools` --
which scans server-side pools but NOT `mempool.pending` -- finds no
collision, admits.  Both signed objects now carry the same WOTS+
leaf; the second signature publishes enough one-time-key preimages
for any observer to forge an arbitrary signature at that leaf.

Block-level dedupe (`Blockchain.validate_block`) catches the in-block
collision and rejects the proposer's block -- but the leaked secret
is already on the gossip surface; the forged sig can be raced into a
different proposer's mempool before the legitimate watermark
advances.

Twin-of-twin of the round-12 react_pool fix (which closed the same
class for ReactTransaction): same defect class on the OTHER side
of the cross-pool boundary.

The fix has three pieces, all source-pinned here:

1. `_check_leaf_across_all_pools` extended to scan `mempool.pending`
   in BOTH the signer-keyed (default) and entity-id-keyed (legacy
   call shape) branches.

2. `_rpc_submit_transaction` (message path) calls
   `_check_leaf_across_all_pools(tx)` before mempool admission.

3. `_rpc_submit_transfer` (transfer path) calls
   `_check_leaf_across_all_pools(tx)` before mempool admission.
"""

from __future__ import annotations

import time
import unittest

from messagechain import config
from messagechain.core.transaction import (
    MessageTransaction, create_transaction,
)
from messagechain.core.staking import (
    UnstakeTransaction, create_stake_transaction,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_server():
    from server import Server
    return Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


class TestCheckLeafAcrossPoolsScansMempoolPending(_Base):
    """Source pin: `_check_leaf_across_all_pools` MUST scan
    `mempool.pending` in both the signer-keyed (default) and
    entity-id-keyed (legacy) branches.  Without this, a message or
    transfer in mempool.pending at leaf=N does not collide with a
    pending stake / unstake / authority / governance tx at leaf=N
    from the same signer -- WOTS+ secret leaks on the cross-pool
    second signature."""

    def test_source_includes_mempool_pending(self):
        import inspect
        from server import Server
        src = inspect.getsource(Server._check_leaf_across_all_pools)
        self.assertIn(
            "mempool.pending", src,
            "_check_leaf_across_all_pools MUST scan mempool.pending so "
            "a cross-pool collision between a mempool tx (message or "
            "transfer) and a pending server-side tx (stake / unstake / "
            "authority / governance) is rejected at admission.",
        )


class TestRpcSubmitTransactionCallsCrossPoolCheck(_Base):
    """Source pin: `_rpc_submit_transaction` MUST call
    `_check_leaf_across_all_pools(tx)` before mempool admission, so
    a message tx at leaf=N collides with a pending stake / unstake /
    authority / governance / react tx at leaf=N.  Mempool's internal
    dedupe only catches same-pool collisions; cross-pool needs the
    server-side check."""

    def test_source_calls_cross_pool_check(self):
        import inspect
        from server import Server
        src = inspect.getsource(Server._rpc_submit_transaction)
        self.assertIn(
            "_check_leaf_across_all_pools", src,
            "_rpc_submit_transaction MUST call "
            "_check_leaf_across_all_pools before submit_transaction_to_"
            "mempool.  Pre-fix the message path skipped the cross-pool "
            "dedupe, leaving a WOTS+ leak primitive against any signer "
            "that has a pending stake/unstake/authority/governance tx.",
        )


class TestRpcSubmitTransferCallsCrossPoolCheck(_Base):
    """Source pin: `_rpc_submit_transfer` MUST call
    `_check_leaf_across_all_pools(tx)` before mempool admission.
    Same defect class on the transfer path as on the message path."""

    def test_source_calls_cross_pool_check(self):
        import inspect
        from server import Server
        src = inspect.getsource(Server._rpc_submit_transfer)
        self.assertIn(
            "_check_leaf_across_all_pools", src,
            "_rpc_submit_transfer MUST call "
            "_check_leaf_across_all_pools before submit_transaction_to_"
            "mempool.  Pre-fix the transfer path skipped the cross-pool "
            "dedupe, leaving a WOTS+ leak primitive against any signer "
            "that has a pending stake/unstake/authority/governance tx.",
        )


class TestMempoolMessageCollidesWithStakePending(_Base):
    """Behavioral pin: a message tx already in `mempool.pending` at
    leaf=N MUST cause `_check_leaf_across_all_pools(stake_tx)` for a
    stake tx at the same leaf to return False -- the second tx is the
    one that would leak WOTS+ secret material on the gossip surface,
    so admission must refuse it."""

    def test_pending_message_blocks_stake_at_same_leaf(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 100_000

        # Build a real signed message tx (uses leaf 0 by default).
        msg_tx = create_transaction(
            entity=alice, message="hello", nonce=0, fee=500,
        )
        msg_leaf = msg_tx.signature.leaf_index

        # Park the message in mempool.pending exactly as a successful
        # admission would.  Skips fee/rate-limit checks -- we are
        # exercising the cross-pool dedupe in isolation.
        srv.mempool.pending[msg_tx.tx_hash] = msg_tx

        # Now build a stake tx at the SAME leaf from the SAME signer.
        # advance_to_leaf rewinds the in-memory _next_leaf so the next
        # sign reuses the leaf the message tx already burned.
        alice.keypair._next_leaf = msg_leaf

        stake = create_stake_transaction(
            alice, amount=100, nonce=1, fee=500,
        )
        self.assertEqual(
            stake.signature.leaf_index, msg_leaf,
            "Test setup error: stake tx should be at the same leaf as "
            "the parked message tx.",
        )

        # The cross-pool dedupe MUST refuse the stake tx -- a pending
        # message at the same leaf is the WOTS+ collision precondition.
        self.assertFalse(
            srv._check_leaf_across_all_pools(stake),
            "Cross-pool dedupe MUST reject a stake tx at the same leaf "
            "as a pending message tx in mempool.pending -- two distinct "
            "signed payloads at the same WOTS+ leaf leak one-time-key "
            "secret material.",
        )


if __name__ == "__main__":
    unittest.main()
