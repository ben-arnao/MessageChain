"""Server-side wiring of the ``ANNOUNCE_FINALITY_VOTE`` gossip handler.

Pre-fix (audit r20 #1): the production ``server.py:Server`` class
dispatches every gossip ``MessageType.*`` *except* ``ANNOUNCE_FINALITY_
VOTE``.  ``messagechain/network/node.py:Node`` has the dispatch and the
full ``_handle_announce_finality_vote`` method (deserialize, verify,
feed the fork-emergency detector via ``observe_finality_vote``, pool
into mempool's ``finality_pool``, relay), but Node is never
instantiated by any production code path.  Net effect on mainnet
today:

* ``FinalityCheckpoints.add_vote`` only fires on votes folded into
  already-applied blocks, never on free gossip -- so a divergent
  supermajority cannot be detected before honest validators have
  already extended the wrong tip with their own attestations.
* The 1.57.0 ``_pending_finality_slashes`` accumulator that
  ``_after_block_added`` drains is empty by construction (votes never
  arrive) -- the FinalityVote-layer auto-slasher has no input.
* Server's ``_try_produce_block_sync`` never drained finality votes
  from mempool either, so even if a Node-side peer relayed votes that
  Server pooled, Server's proposed blocks wouldn't carry them.

This test pins:

  1. ``Server._handle_announce_finality_vote`` exists and is async.
  2. The message-router dispatches ``ANNOUNCE_FINALITY_VOTE`` to that
     handler.
  3. The handler verifies the vote, calls
     ``blockchain.observe_finality_vote`` (so the fork-emergency
     detector receives free-gossiped votes), and pools the vote via
     ``mempool.add_finality_vote`` for inclusion in the next block.
  4. ``_try_produce_block_sync`` drains pooled finality votes via
     ``mempool.get_finality_votes`` and threads them into
     ``blockchain.propose_block`` as ``finality_votes=...``.

Without all four, the slashing-evidence backbone CLAUDE.md anchors as
the deterrent for validator collusion is dead code on the production
runtime.
"""

import asyncio
import inspect
import tempfile
import unittest
from unittest.mock import patch

from messagechain import config
from messagechain.consensus.finality import (
    FinalityVote,
    create_finality_vote,
)
from messagechain.identity.identity import Entity
from messagechain.network.protocol import MessageType, NetworkMessage
from tests import register_entity_for_test


def _entity(seed: bytes, height: int = 4) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_server(data_dir):
    from server import Server
    return Server(
        p2p_port=0, rpc_port=0, seed_nodes=[],
        data_dir=data_dir,
    )


def _teardown_server(srv):
    db = getattr(srv, "db", None)
    if db is not None and hasattr(db, "close"):
        try:
            db.close()
        except Exception:
            pass
    if srv._data_dir_lock is not None:
        try:
            srv._data_dir_lock.__exit__(None, None, None)
        except Exception:
            pass


class _FakePeer:
    address = "1.2.3.4:1234"
    is_connected = True
    writer = None

    def touch(self):
        return None


class ServerFinalityVoteGossipHandlerTest(unittest.TestCase):
    """Pre-fix Server had no ``_handle_announce_finality_vote`` method
    at all.  Post-fix the method exists, verifies the vote, feeds the
    fork-emergency detector, pools, and relays.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = self._tmp.name
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4
        self.srv = _build_server(self.data_dir)
        # The signer needs to be registered + have a public key on
        # chain so the handler's signer-known + sig-verify gates pass.
        self.signer = _entity(b"fv-signer")
        self.srv.blockchain.initialize_genesis(self.signer)
        register_entity_for_test(self.srv.blockchain, self.signer)
        self.srv.set_wallet_entity(self.signer)

    def tearDown(self):
        _teardown_server(self.srv)
        self._tmp.cleanup()
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _signed_vote(self, target_hash: bytes, target_num: int) -> FinalityVote:
        """Real WOTS+-signed FinalityVote so the handler's verify
        gate accepts it.  Caller controls target so we can also build
        the conflicting twin for double-vote tests later if needed.
        """
        return create_finality_vote(
            self.signer,
            target_block_hash=target_hash,
            target_block_number=target_num,
            signed_at_height=target_num,
        )

    def test_handler_method_exists_and_is_async(self):
        self.assertTrue(
            hasattr(self.srv, "_handle_announce_finality_vote"),
            "Server must expose _handle_announce_finality_vote -- the "
            "production runtime, not Node, is the path that needs the "
            "FinalityVote gossip feed for the fork-emergency detector "
            "and the FinalityVote-layer auto-slasher.",
        )
        self.assertTrue(
            inspect.iscoroutinefunction(self.srv._handle_announce_finality_vote),
            "_handle_announce_finality_vote must be async (mirrors the "
            "Node-side handler so the message-router can await it).",
        )

    def test_handler_observes_and_pools_a_valid_vote(self):
        vote = self._signed_vote(b"\xaa" * 32, target_num=1)

        observe_calls = []
        orig_observe = self.srv.blockchain.observe_finality_vote

        def _spy_observe(v):
            observe_calls.append(v)
            return orig_observe(v)
        self.srv.blockchain.observe_finality_vote = _spy_observe

        async def _run():
            # Skip the network broadcast — the test only cares about
            # observe + pool.  _broadcast is patched to a no-op.
            with patch.object(self.srv, "_broadcast", new=_async_noop):
                await self.srv._handle_announce_finality_vote(
                    vote.serialize(), _FakePeer(),
                )
        asyncio.run(_run())

        self.assertEqual(
            len(observe_calls), 1,
            "post-fix _handle_announce_finality_vote MUST call "
            "blockchain.observe_finality_vote -- the fork-emergency "
            "detector's only feed for free-gossiped votes (votes "
            "embedded in already-applied blocks are too late to halt "
            "an honest validator from extending the wrong tip).",
        )
        pool_keys = [
            v.consensus_hash() for v in self.srv.mempool.get_finality_votes()
        ]
        self.assertIn(
            vote.consensus_hash(), pool_keys,
            "validated finality votes must enter mempool.finality_pool "
            "so the next proposed block carries them (this is the "
            "incentive path that pays the inclusion reward and earns "
            "the chain its 2/3-stake commitment toward finality).",
        )

    def test_handler_rejects_unknown_signer_without_pooling(self):
        """A vote signed by an entity with no on-chain pubkey must be
        dropped (unknown signer == cannot verify)."""
        rogue = _entity(b"rogue-signer")
        # Do NOT register: rogue stays absent from public_keys.
        vote = create_finality_vote(
            rogue,
            target_block_hash=b"\xbb" * 32,
            target_block_number=1,
            signed_at_height=1,
        )

        async def _run():
            with patch.object(self.srv, "_broadcast", new=_async_noop):
                await self.srv._handle_announce_finality_vote(
                    vote.serialize(), _FakePeer(),
                )
        asyncio.run(_run())

        self.assertEqual(
            self.srv.mempool.get_finality_votes(), [],
            "vote from unregistered signer must NOT pool -- otherwise "
            "an attacker could flood the finality_pool with votes the "
            "verifier would later reject.",
        )

    def test_message_router_dispatches_announce_finality_vote(self):
        """The on-the-wire MessageType.ANNOUNCE_FINALITY_VOTE must be
        routed to ``_handle_announce_finality_vote``.  Without this
        dispatch case, every gossiped vote is logged as
        ``unhandled_msg_type`` and the source peer accrues a
        protocol-violation offense -- which both drops the vote AND
        scores honest peers as malicious.
        """
        vote = self._signed_vote(b"\xcc" * 32, target_num=1)
        msg = NetworkMessage(
            msg_type=MessageType.ANNOUNCE_FINALITY_VOTE,
            payload=vote.serialize(),
            sender_id="00" * 16,
        )

        handler_calls = []
        orig = self.srv._handle_announce_finality_vote

        async def _spy(payload, peer):
            handler_calls.append((payload, peer))
            return await orig(payload, peer)
        self.srv._handle_announce_finality_vote = _spy

        async def _run():
            with patch.object(self.srv, "_broadcast", new=_async_noop):
                await self.srv._handle_p2p_message(msg, _FakePeer())
        asyncio.run(_run())

        self.assertEqual(
            len(handler_calls), 1,
            "_handle_p2p_message must dispatch ANNOUNCE_FINALITY_VOTE to "
            "_handle_announce_finality_vote -- pre-fix Server had no "
            "case for this MessageType so every vote was treated as "
            "unhandled and the source peer got a "
            "protocol-violation strike.",
        )


class ServerProposeBlockDrainsFinalityVotesTest(unittest.TestCase):
    """Even if gossip-pooled votes arrive correctly, Server's
    block-production path must drain them into the proposed block via
    ``propose_block(... finality_votes=...)``.  Pre-fix Server's
    propose_block call (server.py around line 4216) omitted the
    ``finality_votes`` kwarg, so pooled votes sat unmineable forever
    on Server-only deployments -- defeating the inclusion-reward
    incentive that drives validators to gossip-collect votes in the
    first place.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = self._tmp.name
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        self._tmp.cleanup()
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_propose_block_call_passes_finality_votes_kwarg(self):
        """Inspect the source of ``_try_produce_block_sync`` and
        assert it threads ``finality_votes=`` into ``propose_block``.
        Source-level pin keeps the wiring decision visible to anyone
        editing the proposer path -- without this kwarg the block
        carries no finality votes regardless of mempool contents.
        """
        from server import Server
        src = inspect.getsource(Server._try_produce_block_sync)
        self.assertIn(
            "finality_votes=", src,
            "_try_produce_block_sync must thread finality_votes into "
            "propose_block (Twin of network/node.py:_try_produce_block "
            "where the same kwarg is already wired).",
        )
        self.assertIn(
            "get_finality_votes(", src,
            "_try_produce_block_sync must drain "
            "mempool.get_finality_votes() so gossip-collected votes "
            "actually flow into the next proposed block.",
        )


async def _async_noop(*args, **kwargs):
    return None


if __name__ == "__main__":
    unittest.main()
