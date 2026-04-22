"""
Announce-handler offense scoring on malformed / overrate gossip.

Four signed-announce handlers live on Node:
  - _handle_announce_attestation
  - _handle_announce_finality_vote
  - _handle_announce_custody_proof
  - _handle_announce_slash

Each accepts a gossiped payload and must:
  (a) score the peer OFFENSE_PROTOCOL_VIOLATION when `.deserialize(...)`
      fails (a peer sending garbage that can't be parsed is misbehaving;
      without scoring they just drain rate-limit tokens forever).
  (b) still accept well-formed payloads (regression guard).
  (c) map to the dedicated `signed_announce` rate-limit bucket, not the
      wider `general` bucket — each of these carries a WOTS+-class
      signature whose parse+verify cost makes `general`'s 30/s permissive
      enough to be a CPU DoS vector.

Test (c) is not directly exercised against live WOTS+ verification
(expensive in-test); instead we assert the dispatch mapping via
message_category and that the bucket exists in PeerRateLimiter.  The
combined guarantee is:
    rate-limit(signed_announce) → dispatch → deserialize(try/except) →
    OFFENSE_PROTOCOL_VIOLATION on malformed.

A flooding peer therefore either hits the rate-limit gate (tighter
bucket → scored under OFFENSE_RATE_LIMIT) OR hits the deserialize gate
(scored under OFFENSE_PROTOCOL_VIOLATION).  No code path consumes
CPU-for-free.
"""

import asyncio
import unittest

# NB: Node / Peer are deliberately NOT imported at module level.
# `messagechain.network.node` binds `REQUIRE_CHECKPOINTS` from
# `messagechain.config` AT IMPORT TIME; if unittest-discover happens
# to import this test file before `tests/__init__.py` has flipped the
# value to False for devnet tests, every Node(...) call in this suite
# raises "No weak-subjectivity checkpoints loaded".  Pattern copied
# from other Node-using tests (e.g. test_btc_gap_fixes_2026_04_followup)
# which import Node inside each test helper for the same reason.

# The other imports below do NOT transitively load node.py, so they
# can safely live at module level.
from messagechain.network.protocol import MessageType
from messagechain.network.dispatch import message_category
from messagechain.network.ratelimit import (
    PeerRateLimiter,
    RATE_SIGNED_ANNOUNCE,
    RATE_GENERAL,
)
from messagechain.consensus.attestation import create_attestation
from messagechain.core.block import _hash


# ── Shared helpers ──


def _make_node(port: int, seed: bytes):
    from messagechain.identity.identity import Entity
    from messagechain.network.node import Node
    entity = Entity.create(seed.ljust(32, b"\x00"))
    return Node(entity, port=port, seed_nodes=[])


def _peer(addr: str = "10.9.8.7:9333"):
    from messagechain.network.peer import Peer
    host, _, port_s = addr.partition(":")
    return Peer(host=host, port=int(port_s), is_connected=True)


def _run(coro):
    return asyncio.run(coro)


# ── Test A: malformed payloads score OFFENSE_PROTOCOL_VIOLATION ──


class TestMalformedAnnouncePayloadScoresPeer(unittest.TestCase):
    """Each of the four announce handlers must record an offense when
    `.deserialize(...)` fails on a malformed payload.  Otherwise a
    flooding attacker can drain rate-limit tokens with cheap garbage
    without ever accumulating ban score."""

    def test_attestation_malformed_scores_peer(self):
        node = _make_node(port=19701, seed=b"att_malformed")
        peer = _peer("10.9.8.1:9333")
        _run(node._handle_announce_attestation({}, peer))
        self.assertGreater(
            node.ban_manager.get_score(peer.address), 0,
            "Malformed attestation payload must score the peer.",
        )

    def test_finality_vote_malformed_scores_peer(self):
        node = _make_node(port=19702, seed=b"fv_malformed")
        peer = _peer("10.9.8.2:9333")
        _run(node._handle_announce_finality_vote({}, peer))
        self.assertGreater(
            node.ban_manager.get_score(peer.address), 0,
            "Malformed finality-vote payload must score the peer.",
        )

    def test_custody_proof_malformed_scores_peer(self):
        node = _make_node(port=19703, seed=b"cp_malformed")
        peer = _peer("10.9.8.3:9333")
        _run(node._handle_announce_custody_proof({}, peer))
        self.assertGreater(
            node.ban_manager.get_score(peer.address), 0,
            "Malformed custody-proof payload must score the peer.",
        )

    def test_slash_malformed_scores_peer(self):
        node = _make_node(port=19704, seed=b"sl_malformed")
        peer = _peer("10.9.8.4:9333")
        _run(node._handle_announce_slash({}, peer))
        self.assertGreater(
            node.ban_manager.get_score(peer.address), 0,
            "Malformed slash payload must score the peer.",
        )


# ── Test B: well-formed attestation still processes normally ──


class TestWellFormedAttestationStillProcesses(unittest.TestCase):
    """Regression guard: a well-formed, correctly signed attestation
    from a registered validator at a known block must NOT score an
    offense against the relayer — it should be recorded in the finality
    tracker and relayed.  Without this guard, an overly eager
    offense-on-error refactor could regress honest gossip."""

    def test_good_attestation_no_offense(self):
        from tests import register_entity_for_test
        from messagechain.identity.identity import Entity

        node = _make_node(port=19710, seed=b"att_good")
        relayer = _peer("10.9.7.1:9333")

        # Register a validator in chain state; an attestation from an
        # unknown validator is silently dropped before sig verification,
        # but we want to ride the full happy path.
        validator = Entity.create(b"attester".ljust(32, b"\x00"))
        register_entity_for_test(node.blockchain, validator)

        block_hash = _hash(b"happy_path_block")
        att = create_attestation(validator, block_hash, block_number=1)

        _run(node._handle_announce_attestation(att.serialize(), relayer))

        self.assertEqual(
            node.ban_manager.get_score(relayer.address), 0,
            "Well-formed attestation must not score the relayer.",
        )


# ── Test C: malformed flood accumulates offenses faster than rate-limit cost ──


class TestMalformedFloodAccumulatesOffenses(unittest.TestCase):
    """A peer that repeatedly sends malformed payloads must accumulate
    OFFENSE_PROTOCOL_VIOLATION (10 pts each) faster than pure
    OFFENSE_RATE_LIMIT (5 pts each) alone would.  This closes the gap
    where an attacker could spam invalid payloads indefinitely, paying
    only rate-limit tokens for cheap garbage.

    We go straight through the handler (bypassing the outer rate-limit
    gate) because that outer gate is the separate defense; the handler-
    level guarantee under test is: every malformed payload that REACHES
    the handler costs the peer a protocol-violation point."""

    def test_repeated_malformed_attestations_accumulate(self):
        node = _make_node(port=19720, seed=b"flood_att")
        peer = _peer("10.9.6.1:9333")

        # Fire 5 malformed payloads — each should record 10 pts.
        for _ in range(5):
            _run(node._handle_announce_attestation({}, peer))

        score = node.ban_manager.get_score(peer.address)
        # 5 × OFFENSE_PROTOCOL_VIOLATION (10) = 50, which exceeds
        # 5 × OFFENSE_RATE_LIMIT (5) = 25.  The exact comparison:
        # score MUST be at the protocol-violation scale, not the
        # rate-limit scale.
        self.assertGreaterEqual(
            score, 50,
            f"Expected ≥50 pts from 5 malformed attestations, got {score}",
        )

    def test_mixed_handlers_flood_accumulates(self):
        """A peer that alternates malformed types across all four
        handlers should accumulate offenses across each handler, not
        only the first one it touches."""
        node = _make_node(port=19721, seed=b"flood_mix")
        peer = _peer("10.9.6.2:9333")

        _run(node._handle_announce_attestation({}, peer))
        _run(node._handle_announce_finality_vote({}, peer))
        _run(node._handle_announce_custody_proof({}, peer))
        _run(node._handle_announce_slash({}, peer))

        score = node.ban_manager.get_score(peer.address)
        # 4 × OFFENSE_PROTOCOL_VIOLATION (10 each) = 40.
        self.assertGreaterEqual(
            score, 40,
            f"Expected ≥40 pts from 4 mixed malformed payloads, got {score}",
        )


# ── Test D: signed-announce types map to the dedicated tight bucket ──


class TestSignedAnnounceRateLimitBucket(unittest.TestCase):
    """The four announce types carry WOTS+-class signatures that the
    receiver must parse and verify; the `general` bucket (30/s, burst
    100) is too permissive for that workload.  These types must route
    to `signed_announce` — a tighter bucket sized for
    event-per-epoch-scale gossip traffic."""

    def test_attestation_routes_to_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_ATTESTATION),
            "signed_announce",
        )

    def test_finality_vote_routes_to_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_FINALITY_VOTE),
            "signed_announce",
        )

    def test_custody_proof_routes_to_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_CUSTODY_PROOF),
            "signed_announce",
        )

    def test_slash_routes_to_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_SLASH),
            "signed_announce",
        )

    def test_signed_announce_tighter_than_general(self):
        """Sanity: the new bucket is strictly tighter than `general`,
        otherwise adding it is pointless.  Compares token rate; burst
        is expected to be smaller too but rate is the DoS-relevant knob
        because sustained flooding is what we defend against."""
        self.assertLess(
            RATE_SIGNED_ANNOUNCE[0], RATE_GENERAL[0],
            "signed_announce rate must be tighter than general.",
        )

    def test_rate_limiter_allocates_signed_announce_bucket(self):
        rl = PeerRateLimiter()
        # First-call ensures the bucket exists and is initialized full.
        self.assertTrue(rl.check("1.2.3.4:9333", "signed_announce"))


if __name__ == "__main__":
    unittest.main()
