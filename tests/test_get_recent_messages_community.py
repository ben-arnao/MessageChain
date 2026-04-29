"""
Tests for the `community_id` field surface in
``Blockchain.get_recent_messages``.

Tier 25 added a `community_id` ASCII handle to the message
transaction, but the public-feed RPC dict the web UI reads went on
returning only the legacy fields — so a message with a community
handle stored on chain renders identically to a no-community
message.  These tests pin the JSON contract so the handle reaches
the web feed and the CLI `read` listing.

The method touches only `self.chain` + `self.reaction_state.choices`,
so we instantiate a bare Blockchain and inject those fields directly
(same pattern as test_feed_vote_indicator).
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from messagechain.core.blockchain import Blockchain
from messagechain.core.reaction import ReactionState


def _eid(seed: int) -> bytes:
    return seed.to_bytes(32, "big")


def _txh(seed: int) -> bytes:
    return (seed + 0xC0DE).to_bytes(32, "big")


def _msg_tx(entity, ts, tx_hash, plaintext=b"hi", prev=None, community_id=None):
    return SimpleNamespace(
        entity_id=entity,
        timestamp=ts,
        tx_hash=tx_hash,
        plaintext=plaintext,
        prev=prev,
        community_id=community_id,
    )


def _block(block_number, txs):
    return SimpleNamespace(
        header=SimpleNamespace(block_number=block_number),
        transactions=list(txs),
    )


def _make_chain(blocks, choices=None):
    chain = Blockchain.__new__(Blockchain)
    chain.chain = list(blocks)
    chain.reaction_state = ReactionState()
    chain.reaction_state.choices = dict(choices or {})
    return chain


class TestRecentMessagesCommunityId(unittest.TestCase):
    def test_message_with_community_id_surfaces_in_dict(self):
        author = _eid(1)
        h = _txh(1)
        chain = _make_chain(
            blocks=[
                _block(7, [
                    _msg_tx(
                        author, 100.0, h,
                        plaintext=b"art post",
                        community_id="art",
                    ),
                ]),
            ],
        )
        msgs = Blockchain.get_recent_messages(chain, 10)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["community_id"], "art")

    def test_message_without_community_id_omits_field(self):
        """No community_id on the tx → no `community_id` key in the
        dict.  Mirrors how `prev` is omitted when absent.  Keeps the
        wire form lean and prevents `null` ambiguity in JSON for
        clients that distinguish "missing" from "explicit null"."""
        author = _eid(2)
        h = _txh(2)
        chain = _make_chain(
            blocks=[_block(1, [_msg_tx(author, 200.0, h)])],
        )
        msgs = Blockchain.get_recent_messages(chain, 10)
        self.assertEqual(len(msgs), 1)
        self.assertNotIn("community_id", msgs[0])

    def test_message_with_explicit_none_community_id_omits_field(self):
        """A tx with `community_id = None` (the dataclass default)
        must NOT emit a `community_id` key with a null value."""
        author = _eid(3)
        h = _txh(3)
        chain = _make_chain(
            blocks=[
                _block(1, [
                    _msg_tx(author, 300.0, h, community_id=None),
                ]),
            ],
        )
        msgs = Blockchain.get_recent_messages(chain, 10)
        self.assertEqual(len(msgs), 1)
        self.assertNotIn("community_id", msgs[0])


if __name__ == "__main__":
    unittest.main()
