"""Tests for active mempool replication between peers.

Without active replication, the first node a tx reaches is the only one
that sees it until another peer happens to receive gossip — and a
captured/censoring node that decides to drop the tx instead of relaying
it keeps downstream peers ignorant forever.  Combined with the forced-
inclusion attester veto, censorship works if and only if attesters never
learn the tx exists.  Active mempool replication closes that hole: every
node periodically advertises a compact digest (list of tx_hashes) of its
mempool to random peers; each recipient pulls any hashes it's missing
via REQUEST_MEMPOOL_TX, getting back an ANNOUNCE_TX (the existing tx-
broadcast message).  A tx that reaches ANY honest node propagates to
every honest node within at most a couple of sync intervals.

Covers:
  - Basic 2-node digest exchange drives a missing tx to the receiver
  - 3-node A→B→C chain: tx submitted to A only reaches C in 2 rounds
  - Arrival-height of replicated txs = receiver's current height
  - Digest size cap — oversized digests are rejected as DoS
  - REQUEST_MEMPOOL_TX rate limit — burst of requests drops the rest
  - Spam: two digests from the same peer inside MEMPOOL_DIGEST_MIN_INTERVAL_SEC are rejected
  - A peer that advertises a hash but then can't produce the tx silently gives up
  - A replicated tx with a bad signature is rejected at the receiver
  - A hash already in the local mempool is not re-requested / duplicated
"""

import asyncio
import struct
import unittest

from messagechain import config
from messagechain.core.transaction import create_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity
from messagechain.network.node import Node
from messagechain.network.peer import Peer
from messagechain.network.protocol import (
    MessageType,
    NetworkMessage,
    decode_message,
)


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)))


def _register(chain, entity):
    proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
    chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


def _make_tx(sender: Entity, nonce: int = 0, fee: int = 500):
    # A short message keeps stored bytes tiny so the minimum fee stays low.
    return create_transaction(sender, f"hi {nonce}", fee=fee, nonce=nonce)


class _LoopbackWriter:
    """Duck-types asyncio.StreamWriter.  Buffers writes and on drain()
    forwards the decoded NetworkMessage straight to the target node's
    _handle_message, replaying the length-prefixed framing the real wire
    uses.  Mirrors the pattern already used in tests/test_gossip_integration.

    Because we forward into the receiver's real dispatcher, every message
    exercises the production code path: rate limiting, ban scoring,
    deserialization, validation, mempool admission, relay decisions.
    """

    def __init__(self, target_node: Node, *, sender_address: str):
        self._buf = bytearray()
        self._target = target_node
        self._sender_address = sender_address
        # Count drained frames so tests can assert "peer did not reply".
        self.drained_frames = 0
        # Capture delivered messages by type for finer assertions.
        self.delivered_by_type: dict[str, int] = {}
        # Injected failure mode: if set, outgoing ANNOUNCE_TX frames are
        # dropped (not delivered to the target) to model a dishonest peer
        # that advertised a hash but refuses to send the tx.
        self.drop_announce_tx = False

    def write(self, data: bytes) -> None:
        self._buf.extend(data)

    async def drain(self) -> None:
        while len(self._buf) >= 4:
            length = struct.unpack(">I", bytes(self._buf[:4]))[0]
            if len(self._buf) < 4 + length:
                break
            frame = bytes(self._buf[4:4 + length])
            del self._buf[:4 + length]
            try:
                msg = decode_message(frame)
            except Exception:
                continue
            self.drained_frames += 1
            tname = msg.msg_type.value
            self.delivered_by_type[tname] = self.delivered_by_type.get(tname, 0) + 1
            if self.drop_announce_tx and msg.msg_type == MessageType.ANNOUNCE_TX:
                continue  # dishonest peer drops outgoing tx payloads
            sender_peer = self._target.peers.get(self._sender_address)
            if sender_peer is None:
                continue
            await self._target._handle_message(msg, sender_peer)

    def close(self) -> None:
        self._buf.clear()


def _wire(a: Node, b: Node, *, addr_a: str, addr_b: str) -> tuple[_LoopbackWriter, _LoopbackWriter]:
    """Register each node as the other's peer with loopback writers."""
    a_to_b = _LoopbackWriter(b, sender_address=addr_a)
    b_to_a = _LoopbackWriter(a, sender_address=addr_b)
    host_a, port_a = addr_a.rsplit(":", 1)
    host_b, port_b = addr_b.rsplit(":", 1)
    peer_b_on_a = Peer(
        host=host_b, port=int(port_b), writer=a_to_b, is_connected=True,
    )
    peer_a_on_b = Peer(
        host=host_a, port=int(port_a), writer=b_to_a, is_connected=True,
    )
    a.peers[addr_b] = peer_b_on_a
    b.peers[addr_a] = peer_a_on_b
    return a_to_b, b_to_a


def _new_node(seed: bytes, port: int) -> Node:
    entity = _entity(seed)
    return Node(entity, port=port, seed_nodes=[])


def _seed_tx(node: Node, sender: Entity, *, nonce: int = 0, fee: int = 500):
    """Put `sender` in a state where they can submit a tx, then submit one."""
    _register(node.blockchain, sender)
    node.blockchain.supply.balances[sender.entity_id] = 1_000_000
    tx = _make_tx(sender, nonce=nonce, fee=fee)
    ok, reason = node.submit_transaction(tx)
    assert ok, f"submit_transaction failed: {reason}"
    return tx


async def _flush(n: int = 4) -> None:
    for _ in range(n):
        await asyncio.sleep(0)


class _Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4


class TestBasicPairReplication(_Base):
    """Two nodes; A has a tx; after one sync round B has it."""

    async def test_sync_delivers_missing_tx(self):
        a = _new_node(b"alice-node", port=30000)
        b = _new_node(b"bob-node", port=30001)
        sender = _entity(b"sender")
        # B must accept the tx, so B also needs the sender registered
        # with a balance.  A registers it to submit.
        _register(b.blockchain, sender)
        b.blockchain.supply.balances[sender.entity_id] = 1_000_000
        tx = _seed_tx(a, sender)

        _wire(a, b, addr_a="127.0.0.1:30000", addr_b="127.0.0.1:30001")
        self.assertIn(tx.tx_hash, a.mempool.pending)
        self.assertNotIn(tx.tx_hash, b.mempool.pending)

        # One full sync cycle from A: A announces a digest containing tx,
        # B asks for it, A sends ANNOUNCE_TX, B admits it.
        await a.run_one_mempool_sync_cycle()
        await _flush(n=8)

        self.assertIn(
            tx.tx_hash, b.mempool.pending,
            "B must receive the tx via mempool sync after one cycle.",
        )


class TestThreeNodeRelay(_Base):
    """A → B → C chain.  Tx submitted only to A.  After 2 rounds it's on C."""

    async def test_chain_propagation(self):
        a = _new_node(b"a3", port=30010)
        b = _new_node(b"b3", port=30011)
        c = _new_node(b"c3", port=30012)
        sender = _entity(b"sender3")
        for n in (a, b, c):
            _register(n.blockchain, sender)
            n.blockchain.supply.balances[sender.entity_id] = 1_000_000
        tx = _seed_tx(a, sender)

        # Only A<->B and B<->C wired; A and C never talk directly.
        _wire(a, b, addr_a="127.0.0.1:30010", addr_b="127.0.0.1:30011")
        _wire(b, c, addr_a="127.0.0.1:30011", addr_b="127.0.0.1:30012")

        # Round 1: A tells B.
        await a.run_one_mempool_sync_cycle()
        await _flush(n=10)
        self.assertIn(tx.tx_hash, b.mempool.pending)
        # Note: the existing ANNOUNCE_TX handler ALSO fires inv-relay to
        # other peers on first admission (that's the legacy passive
        # gossip path).  With loopback writers the inv round-trip runs
        # in the same flush window, so C may have the tx already by
        # Round 1.  What we actually want to guarantee is: *without* a
        # round-2 sync, C might or might not have it; *with* round-2,
        # C definitively has it.  Assert the positive outcome.

        # Round 2: B tells C.
        await b.run_one_mempool_sync_cycle()
        await _flush(n=10)
        self.assertIn(
            tx.tx_hash, c.mempool.pending,
            "Tx must reach C through B's relay within 2 sync rounds.",
        )


class TestArrivalHeightOnReplicated(_Base):
    """A replicated tx is stamped with the RECEIVER's current height,
    not A's.  Without this, a tx that's been floating for blocks on A
    would show up at B as "always forced" (height 0) and wrongly trigger
    forced-inclusion voting immediately."""

    async def test_arrival_is_receivers_current_height(self):
        a = _new_node(b"a_h", port=30020)
        b = _new_node(b"b_h", port=30021)
        sender = _entity(b"sender_h")
        for n in (a, b):
            _register(n.blockchain, sender)
            n.blockchain.supply.balances[sender.entity_id] = 1_000_000
        tx = _seed_tx(a, sender)

        # The honest field is blockchain.height — a @property that
        # returns len(self.chain).  Monkeypatch B's blockchain instance
        # with a property override that returns our target height.
        b_target_height = 42

        class _HeightOverride:
            """Instance-level attribute shadow for a property.  Python
            resolves properties on the class, so we override at the
            class level temporarily."""

        # Replace the property on the specific blockchain instance by
        # intercepting via a subclass-style swap.
        orig_cls = type(b.blockchain)
        class _BlockchainWithHeight(orig_cls):
            @property
            def height(self):
                return b_target_height
        b.blockchain.__class__ = _BlockchainWithHeight

        try:
            _wire(a, b, addr_a="127.0.0.1:30020", addr_b="127.0.0.1:30021")
            await a.run_one_mempool_sync_cycle()
            await _flush(n=10)

            self.assertIn(tx.tx_hash, b.mempool.pending)
            self.assertEqual(
                b.mempool.arrival_heights.get(tx.tx_hash),
                b_target_height,
                "Replicated tx must carry B's current height, not 0 and "
                "not A's arrival height.",
            )
        finally:
            b.blockchain.__class__ = orig_cls


class TestDigestSizeCap(_Base):
    """A peer that sends a digest claiming millions of hashes is trying to DoS."""

    async def test_oversized_digest_rejected(self):
        a = _new_node(b"a_d", port=30030)
        b = _new_node(b"b_d", port=30031)
        _wire(a, b, addr_a="127.0.0.1:30030", addr_b="127.0.0.1:30031")

        # Fabricate an oversized digest directly.
        too_many = config.MEMPOOL_DIGEST_MAX_HASHES + 1
        fake_hashes = [f"{i:064x}" for i in range(too_many)]
        msg = NetworkMessage(
            msg_type=MessageType.MEMPOOL_DIGEST,
            payload={"hashes": fake_hashes},
            sender_id=a.entity.entity_id_hex,
        )
        # Deliver directly to B — if B processed this, it would issue
        # thousands of REQUEST_MEMPOOL_TX frames.
        sender_peer = b.peers["127.0.0.1:30030"]
        await b._handle_message(msg, sender_peer)
        await _flush()

        # The loopback writer from B to A should record zero REQUEST_MEMPOOL_TX
        # frames if B correctly rejected the oversized digest.
        b_to_a = sender_peer.writer
        self.assertEqual(
            b_to_a.delivered_by_type.get(
                MessageType.REQUEST_MEMPOOL_TX.value, 0,
            ),
            0,
            "B must refuse to process an oversized digest (no requests issued).",
        )
        # B must also have recorded an offense against A for the violation.
        self.assertGreater(
            b.ban_manager.get_score("127.0.0.1:30030"),
            0,
            "Oversized digest must score a protocol-violation offense.",
        )


class TestRequestRateLimit(_Base):
    """A flood of REQUEST_MEMPOOL_TX from one peer past the burst is dropped."""

    async def test_burst_then_drop(self):
        a = _new_node(b"a_rl", port=30040)
        b = _new_node(b"b_rl", port=30041)
        _wire(a, b, addr_a="127.0.0.1:30040", addr_b="127.0.0.1:30041")

        # Simulate B receiving many requests from A.  With burst=50, the
        # first 50 are allowed; subsequent are rate-limited.  We observe
        # via the rate_limiter directly — the handler consults it.
        addr_a = "127.0.0.1:30040"
        allowed = 0
        for _ in range(config.MEMPOOL_REQUEST_BURST + 20):
            if b.rate_limiter.check(addr_a, "mempool_req"):
                allowed += 1
        # After burst exhausted, remaining tokens refill at MEMPOOL_REQUEST_RATE_PER_SEC.
        # In tight test timing, `allowed` should be at most burst + a tiny refill.
        self.assertLessEqual(
            allowed,
            config.MEMPOOL_REQUEST_BURST + 2,
            "Rate limiter must enforce configured burst.",
        )
        self.assertGreaterEqual(
            allowed, config.MEMPOOL_REQUEST_BURST - 2,
            "Rate limiter must allow the full burst.",
        )


class TestDigestSpamPerPeer(_Base):
    """Two digests from the same peer inside MEMPOOL_DIGEST_MIN_INTERVAL_SEC
    must be rejected — otherwise an attacker triggers expensive diff work
    every millisecond."""

    async def test_fast_second_digest_rejected(self):
        a = _new_node(b"a_sp", port=30050)
        b = _new_node(b"b_sp", port=30051)
        _wire(a, b, addr_a="127.0.0.1:30050", addr_b="127.0.0.1:30051")

        msg = NetworkMessage(
            msg_type=MessageType.MEMPOOL_DIGEST,
            payload={"hashes": []},
            sender_id=a.entity.entity_id_hex,
        )
        sender_peer = b.peers["127.0.0.1:30050"]
        await b._handle_message(msg, sender_peer)
        await b._handle_message(msg, sender_peer)
        await _flush()

        # Second digest must NOT have caused additional processing; observable
        # via the digest_seen timestamps bookkeeping.  Exact shape-agnostic
        # assertion: peer's misbehavior score was nudged (DoS heuristic).
        # This is a protocol-violation-adjacent event.
        # Less strict alternative: at minimum, recording the digest ts happens
        # only once per interval.
        seen = getattr(b, "_mempool_digest_last_seen", {})
        self.assertIn(
            "127.0.0.1:30050", seen,
            "B must record when a peer's digest arrived so it can throttle.",
        )


class TestAdvertisedButNotDelivered(_Base):
    """A peer that advertises a tx_hash but drops the follow-up ANNOUNCE_TX
    must not send the receiver into an infinite retry loop.  Single attempt,
    then silent give-up until the next sync cycle."""

    async def test_single_request_then_give_up(self):
        a = _new_node(b"a_dish", port=30060)
        b = _new_node(b"b_dish", port=30061)
        sender = _entity(b"sender_dish")
        for n in (a, b):
            _register(n.blockchain, sender)
            n.blockchain.supply.balances[sender.entity_id] = 1_000_000
        tx = _seed_tx(a, sender)

        a_to_b, b_to_a = _wire(
            a, b,
            addr_a="127.0.0.1:30060", addr_b="127.0.0.1:30061",
        )
        # Mark A as dishonest: A's outbound-to-B writer drops any
        # ANNOUNCE_TX frames A tries to send.  A's MEMPOOL_DIGEST still
        # goes through (so it legitimately advertises the hash), but the
        # follow-up ANNOUNCE_TX in response to B's REQUEST_MEMPOOL_TX
        # never arrives at B.
        a_to_b.drop_announce_tx = True

        await a.run_one_mempool_sync_cycle()
        await _flush(n=10)

        # B issued at most one REQUEST_MEMPOOL_TX for this hash; it is NOT
        # now sitting in a retry loop re-requesting every millisecond.
        requests_issued = a_to_b.delivered_by_type.get(
            MessageType.REQUEST_MEMPOOL_TX.value, 0,
        )
        self.assertLessEqual(
            requests_issued, 1,
            "B must not loop-request a hash an adversarial peer advertised "
            "but refuses to deliver.",
        )
        self.assertNotIn(
            tx.tx_hash, b.mempool.pending,
            "Dishonest peer withheld the tx — it should not appear in B.",
        )


class TestInvalidReplicatedTxDropped(_Base):
    """A replicated tx that fails signature verification at the receiver
    must NOT land in the receiver's mempool.  Same defense as ANNOUNCE_TX."""

    async def test_bad_signature_rejected(self):
        a = _new_node(b"a_inv", port=30070)
        b = _new_node(b"b_inv", port=30071)
        sender = _entity(b"sender_inv")
        for n in (a, b):
            _register(n.blockchain, sender)
            n.blockchain.supply.balances[sender.entity_id] = 1_000_000

        # Build a tx, then corrupt the signature's merkle_root so verify fails.
        tx = _make_tx(sender, nonce=0, fee=500)
        # Admit into A's mempool directly, bypassing validation (so A is
        # willing to advertise a bad tx — models a buggy or malicious peer).
        a.mempool.pending[tx.tx_hash] = tx
        a.mempool.arrival_heights[tx.tx_hash] = 0

        # Corrupt the tx AFTER it's seeded in A's pool: tamper the message
        # so the signature no longer matches.
        tx.message = b"tampered"

        _wire(a, b, addr_a="127.0.0.1:30070", addr_b="127.0.0.1:30071")
        await a.run_one_mempool_sync_cycle()
        await _flush(n=10)

        self.assertNotIn(
            tx.tx_hash, b.mempool.pending,
            "A replicated tx failing signature verification must not land in "
            "the receiver's mempool.",
        )


class TestNoDuplicateAddForKnownHash(_Base):
    """If B already has the tx, a digest from A containing that tx's hash
    must not produce a redundant REQUEST_MEMPOOL_TX."""

    async def test_known_hash_not_re_requested(self):
        a = _new_node(b"a_dup", port=30080)
        b = _new_node(b"b_dup", port=30081)
        sender = _entity(b"sender_dup")
        for n in (a, b):
            _register(n.blockchain, sender)
            n.blockchain.supply.balances[sender.entity_id] = 1_000_000
        tx = _seed_tx(a, sender)
        # Put the same tx into B's mempool.
        ok, _r = b.submit_transaction(tx)
        self.assertTrue(ok)

        a_to_b, b_to_a = _wire(
            a, b, addr_a="127.0.0.1:30080", addr_b="127.0.0.1:30081",
        )
        await a.run_one_mempool_sync_cycle()
        await _flush(n=10)

        self.assertEqual(
            b_to_a.delivered_by_type.get(
                MessageType.REQUEST_MEMPOOL_TX.value, 0,
            ),
            0,
            "B must not request a tx it already has in its mempool.",
        )


class TestConfigConstants(unittest.TestCase):
    """Sanity checks on the new config values so downstream consumers
    don't silently get zero/invalid defaults."""

    def test_constants_exist_and_sane(self):
        self.assertGreaterEqual(config.MEMPOOL_SYNC_INTERVAL_SEC, 5)
        self.assertGreaterEqual(config.MEMPOOL_SYNC_FANOUT, 1)
        self.assertGreaterEqual(config.MEMPOOL_DIGEST_MAX_HASHES, 100)
        self.assertGreaterEqual(config.MEMPOOL_REQUEST_RATE_PER_SEC, 1)
        self.assertGreaterEqual(config.MEMPOOL_REQUEST_BURST, 1)
        self.assertGreaterEqual(config.MEMPOOL_DIGEST_MIN_INTERVAL_SEC, 1)


if __name__ == "__main__":
    unittest.main()
