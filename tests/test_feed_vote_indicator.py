"""
Tests for the per-message UP/DOWN vote counts emitted by
`Blockchain.get_recent_messages`, used by the public feed UI to
render the vote indicator.

The method is read-only and only touches `self.chain` +
`self.reaction_state.choices`, so we instantiate a bare Blockchain
and inject those two fields directly — no need to spin up the full
Entity / signing / mempool stack just to verify aggregation.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from messagechain.config import (
    REACT_CHOICE_DOWN,
    REACT_CHOICE_UP,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.reaction import ReactionState


def _eid(seed: int) -> bytes:
    return seed.to_bytes(32, "big")


def _txh(seed: int) -> bytes:
    return (seed + 0xC0DE).to_bytes(32, "big")


def _msg_tx(entity, ts, tx_hash, plaintext=b"hi", prev=None):
    return SimpleNamespace(
        entity_id=entity,
        timestamp=ts,
        tx_hash=tx_hash,
        plaintext=plaintext,
        prev=prev,
    )


def _block(block_number, txs):
    return SimpleNamespace(
        header=SimpleNamespace(block_number=block_number),
        transactions=list(txs),
    )


def _make_chain(blocks, choices):
    chain = Blockchain.__new__(Blockchain)
    chain.chain = list(blocks)
    chain.reaction_state = ReactionState()
    chain.reaction_state.choices = dict(choices)
    return chain


class TestRecentMessagesVoteCounts(unittest.TestCase):
    def test_no_votes_yields_zero_counts_and_null_pct(self):
        author = _eid(1)
        h = _txh(1)
        chain = _make_chain(
            blocks=[_block(1, [_msg_tx(author, 100.0, h)])],
            choices={},
        )
        msgs = Blockchain.get_recent_messages(chain, 10)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["ups"], 0)
        self.assertEqual(msgs[0]["downs"], 0)
        self.assertIsNone(msgs[0]["up_pct"])

    def test_ups_and_downs_aggregated_from_reaction_state(self):
        author = _eid(2)
        h = _txh(2)
        v1, v2, v3, v4 = _eid(10), _eid(11), _eid(12), _eid(13)
        choices = {
            (v1, h, False): REACT_CHOICE_UP,
            (v2, h, False): REACT_CHOICE_UP,
            (v3, h, False): REACT_CHOICE_UP,
            (v4, h, False): REACT_CHOICE_DOWN,
        }
        chain = _make_chain(
            blocks=[_block(1, [_msg_tx(author, 100.0, h)])],
            choices=choices,
        )
        msg = Blockchain.get_recent_messages(chain, 10)[0]
        self.assertEqual(msg["ups"], 3)
        self.assertEqual(msg["downs"], 1)
        self.assertAlmostEqual(msg["up_pct"], 75.0)

    def test_user_trust_votes_do_not_pollute_message_counts(self):
        # A user-trust vote (target_is_user=True) on the AUTHOR must
        # not be miscounted as a vote on the author's MESSAGE, even
        # when the entity_id and tx_hash happen to collide.
        author = _eid(3)
        h = _txh(3)
        voter = _eid(20)
        choices = {
            (voter, author, True): REACT_CHOICE_UP,   # user-trust, ignored
            (voter, h, False): REACT_CHOICE_UP,        # message react, counted
        }
        chain = _make_chain(
            blocks=[_block(1, [_msg_tx(author, 100.0, h)])],
            choices=choices,
        )
        msg = Blockchain.get_recent_messages(chain, 10)[0]
        self.assertEqual(msg["ups"], 1)
        self.assertEqual(msg["downs"], 0)

    def test_per_message_isolation(self):
        # Two messages in the same block; each gets its own counts.
        author = _eid(4)
        h_a = _txh(40)
        h_b = _txh(41)
        v1, v2 = _eid(50), _eid(51)
        choices = {
            (v1, h_a, False): REACT_CHOICE_UP,
            (v2, h_a, False): REACT_CHOICE_DOWN,
            (v1, h_b, False): REACT_CHOICE_UP,
        }
        chain = _make_chain(
            blocks=[_block(
                1,
                [_msg_tx(author, 100.0, h_a),
                 _msg_tx(author, 101.0, h_b)],
            )],
            choices=choices,
        )
        msgs = Blockchain.get_recent_messages(chain, 10)
        # Newest first: h_b emitted before h_a.
        by_hash = {m["tx_hash"]: m for m in msgs}
        self.assertEqual(by_hash[h_a.hex()]["ups"], 1)
        self.assertEqual(by_hash[h_a.hex()]["downs"], 1)
        self.assertAlmostEqual(by_hash[h_a.hex()]["up_pct"], 50.0)
        self.assertEqual(by_hash[h_b.hex()]["ups"], 1)
        self.assertEqual(by_hash[h_b.hex()]["downs"], 0)
        self.assertAlmostEqual(by_hash[h_b.hex()]["up_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
