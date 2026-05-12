"""Regression: server.py's ANNOUNCE_BLOCK gossip-receiver path must
evict confirmed TransferTransactions from mempool, not just messages.

Bug: at ``server.py:5252`` the post-apply mempool sweep was
``[tx.tx_hash for tx in block.transactions]`` — only the
MessageTransactions in the block.  ``mempool.pending`` holds BOTH
messages AND transfers (since ``submit_transaction_to_mempool``
dispatches on tx class), so the confirmed transfers stayed pending
on this node's view.  Next proposal re-picked them via
``get_transactions_with_entity_cap``, the resulting block failed
``add_block`` with "Invalid transfer ...: Invalid nonce: expected
N+1, got N", and the proposer wedged itself into re-proposing the
same stale block every slot.

Bite: surfaced during the Tier 72 mainnet demo (1.79.1).  Faucet
drips from validator-2 landed in validator-2's local block, then
validator-2 saw validator-1 gossip-back the same block via
ANNOUNCE_BLOCK.  Validator-2's gossip-receiver path stripped only
the message txs from mempool; the confirmed transfer stayed.  Next
slot's proposal included the stale transfer, validation failed,
the proposer kept retrying.  Chain produced ~6 blocks of 0-tx
"inactivity leak only" while a 300-token faucet drip sat in
mempool indefinitely.

Property tested: after the mempool sweep that follows a successful
``add_block`` from a gossiped peer block, every tx kind included
in the block must be gone from ``mempool.pending``.
"""

from __future__ import annotations

import unittest


class TestGossipBlockTransferEviction(unittest.TestCase):
    """Pins the property at the mempool API surface: a combined
    sweep of message + transfer tx_hashes leaves no entries from
    either kind behind.
    """

    def test_mempool_remove_strips_both_kinds(self):
        from messagechain.core.mempool import Mempool

        m = Mempool()

        class _FakeTx:
            def __init__(self, tx_hash, entity_id, nonce, message=b"x", fee=10):
                self.tx_hash = tx_hash
                self.entity_id = entity_id
                self.nonce = nonce
                self.message = message
                self.fee = fee
                self.timestamp = 0
                self.signature = None

        # Two "messages" + two "transfers", all in the same pending dict.
        message_a = _FakeTx(b"\x01" * 32, b"e" * 32, nonce=0)
        message_b = _FakeTx(b"\x02" * 32, b"e" * 32, nonce=1)
        transfer_a = _FakeTx(b"\x03" * 32, b"f" * 32, nonce=0)
        transfer_b = _FakeTx(b"\x04" * 32, b"f" * 32, nonce=1)

        # Directly populate ``pending`` (bypasses the class dispatch
        # in add_transaction which would reject the fake objects --
        # we're testing the eviction primitive, not admission).
        with m._lock:
            for tx in (message_a, message_b, transfer_a, transfer_b):
                m.pending[tx.tx_hash] = tx
                m._sender_counts[tx.entity_id] += 1

        self.assertEqual(len(m.pending), 4)

        # Simulate the fixed gossip-receiver sweep: message hashes
        # PLUS transfer hashes from the block.
        block_message_hashes = [message_a.tx_hash, message_b.tx_hash]
        block_transfer_hashes = [transfer_a.tx_hash, transfer_b.tx_hash]
        m.remove_transactions(block_message_hashes + block_transfer_hashes)

        self.assertEqual(
            len(m.pending), 0,
            "after a combined sweep, neither messages nor transfers "
            "from the block should remain in mempool.pending",
        )

    def test_mempool_remove_messages_only_leaves_transfers_behind(self):
        # Pin the BUG behavior so the regression catches a future
        # revert: stripping only message hashes from the block leaves
        # the transfers stranded in mempool.pending.
        from messagechain.core.mempool import Mempool

        m = Mempool()

        class _FakeTx:
            def __init__(self, tx_hash, entity_id, nonce, message=b"x", fee=10):
                self.tx_hash = tx_hash
                self.entity_id = entity_id
                self.nonce = nonce
                self.message = message
                self.fee = fee
                self.timestamp = 0
                self.signature = None

        message_a = _FakeTx(b"\x01" * 32, b"e" * 32, nonce=0)
        transfer_a = _FakeTx(b"\x03" * 32, b"f" * 32, nonce=0)

        with m._lock:
            m.pending[message_a.tx_hash] = message_a
            m.pending[transfer_a.tx_hash] = transfer_a
            m._sender_counts[message_a.entity_id] += 1
            m._sender_counts[transfer_a.entity_id] += 1

        # Bug shape: strip ONLY block.transactions (messages).
        m.remove_transactions([message_a.tx_hash])

        # The transfer remains stranded -- this is what the fix
        # eliminates by also passing block.transfer_transactions
        # through the sweep at server.py:5252.
        self.assertNotIn(message_a.tx_hash, m.pending)
        self.assertIn(transfer_a.tx_hash, m.pending)


class TestServerGossipBlockReceiverPathFix(unittest.TestCase):
    """Source-level pin: the gossip-receiver path in
    ``server.py:_handle_message``'s ANNOUNCE_BLOCK branch must include
    ``block.transfer_transactions`` in the mempool sweep.
    """

    def test_announce_block_handler_sweeps_transfers(self):
        import inspect
        import server

        # Locate the ANNOUNCE_BLOCK arm in the handler source.  We
        # grep over the raw source rather than runtime-patch the
        # method because the path is async + nested.
        # The fix lives in server._handle_p2p_message; we just need
        # to see the right two lines together in the source.
        src = inspect.getsource(server.Server._handle_p2p_message)
        # The sweep MUST reference both block.transactions AND
        # block.transfer_transactions in the same call.
        # Find the `if success:` branch right after `add_block(block,
        # source_peer=address)` and confirm transfer_transactions
        # appears between it and the next `self._after_block_added`.
        marker_add = "self.blockchain.add_block(block, source_peer=address)"
        marker_after = "self._after_block_added(block)"
        self.assertIn(marker_add, src)
        self.assertIn(marker_after, src)
        idx_add = src.index(marker_add)
        idx_after = src.index(marker_after, idx_add)
        slice_ = src[idx_add:idx_after]
        self.assertIn("block.transactions", slice_)
        self.assertIn(
            "block.transfer_transactions", slice_,
            "ANNOUNCE_BLOCK gossip-receiver path must sweep both "
            "message txs AND transfer txs from mempool after a "
            "successful add_block — see server.py:5252",
        )


if __name__ == "__main__":
    unittest.main()
