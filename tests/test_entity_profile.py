"""
Tests for the entity-profile aggregator (messagechain.network.entity_profile)
and the /v1/entity HTTP endpoint exposed by the public feed server.

The aggregator only reads from a Blockchain-shaped object (chain,
supply, reaction_state, public_keys), so we duck-type the chain with
SimpleNamespace blocks and a small stub SupplyTracker.  Real
ReactionState is used so the choice-aggregation arithmetic is
exercised end-to-end.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from types import SimpleNamespace

from messagechain.core.reaction import (
    REACT_CHOICE_DOWN,
    REACT_CHOICE_UP,
    ReactionState,
)
from messagechain.network.entity_profile import compute_entity_profile
from messagechain.network.public_feed_server import PublicFeedServer


# Override genesis supply per stub-chain so tests exercise the
# spend-pct math against an easy-to-eyeball base.  Real config
# value (140M) is irrelevant to the aggregator's correctness.
STUB_GENESIS_SUPPLY = 100_000


def _eid(seed: int) -> bytes:
    return seed.to_bytes(32, "big")


def _txh(seed: int) -> bytes:
    return (seed + 0xC0DE).to_bytes(32, "big")


def _msg(entity, ts, fee, tx_hash):
    return SimpleNamespace(
        entity_id=entity,
        timestamp=ts,
        fee=fee,
        tx_hash=tx_hash,
    )


def _transfer(sender, recipient, amount, fee):
    return SimpleNamespace(
        entity_id=sender,
        recipient_id=recipient,
        amount=amount,
        fee=fee,
    )


# Aggregator dispatches on type(gtx).__name__ rather than isinstance,
# so a tiny no-op class with the right name is enough to look like the
# real governance tx for these tests.
class ProposalTransaction:
    def __init__(self, proposer, fee):
        self.proposer_id = proposer
        self.fee = fee


class VoteTransaction:
    def __init__(self, voter, fee):
        self.voter_id = voter
        self.fee = fee


def _proposal(proposer, fee):
    return ProposalTransaction(proposer, fee)


def _vote(voter, fee):
    return VoteTransaction(voter, fee)


def _block(
    *,
    block_number,
    timestamp,
    proposer,
    txs=(),
    transfers=(),
    reacts=(),
    governance=(),
    stakes=(),
    unstakes=(),
):
    return SimpleNamespace(
        header=SimpleNamespace(
            block_number=block_number,
            timestamp=timestamp,
            proposer_id=proposer,
        ),
        transactions=list(txs),
        transfer_transactions=list(transfers),
        react_transactions=list(reacts),
        governance_txs=list(governance),
        stake_transactions=list(stakes),
        unstake_transactions=list(unstakes),
    )


class _StubSupply:
    """Reproduces the pieces of SupplyTracker the aggregator touches."""

    GENESIS_SUPPLY = STUB_GENESIS_SUPPLY

    def __init__(self):
        self.balances: dict[bytes, int] = {}
        self.staked: dict[bytes, int] = {}
        self.pending_unstakes: dict[bytes, list[tuple[int, int]]] = {}

    def get_balance(self, eid: bytes) -> int:
        return self.balances.get(eid, 0)

    def get_staked(self, eid: bytes) -> int:
        return self.staked.get(eid, 0)

    def calculate_block_reward(self, height: int) -> int:
        # Constant per-block reward keeps the arithmetic in tests
        # readable; the real SupplyTracker uses a halving schedule
        # but the aggregator just sums what it returns.
        return 1_000


class _StubChain:
    def __init__(self, blocks=None):
        self.chain = list(blocks or [])
        self.supply = _StubSupply()
        self.reaction_state = ReactionState()
        self.public_keys: dict[bytes, bytes] = {}

    @property
    def height(self) -> int:
        return self.chain[-1].header.block_number if self.chain else 0


# ── Aggregator unit tests ───────────────────────────────────────────


class TestComputeEntityProfile(unittest.TestCase):
    def test_unknown_entity_returns_zeros_and_exists_false(self):
        chain = _StubChain()
        profile = compute_entity_profile(chain, _eid(1))
        self.assertFalse(profile["exists"])
        self.assertEqual(profile["balance"], 0)
        self.assertEqual(profile["staked"], 0)
        self.assertEqual(profile["messages"]["total"], 0)
        self.assertIsNone(profile["user_since"])
        self.assertIsNone(profile["stake_pct_of_funds"])
        self.assertEqual(profile["supply_spent_pct_cumulative"], 0.0)
        self.assertIsNone(profile["reputation"]["rate_pct"])
        self.assertIsNone(profile["post_score"]["rate_pct"])
        self.assertEqual(profile["post_score"]["distinct_upvoters"], 0)
        # react_majority_alignment is gone — not in the new contract.
        self.assertNotIn("react_majority_alignment", profile)

    def test_funds_and_stake_pct(self):
        chain = _StubChain()
        eid = _eid(2)
        chain.supply.balances[eid] = 600
        chain.supply.staked[eid] = 300
        chain.supply.pending_unstakes[eid] = [(100, 50)]
        chain.public_keys[eid] = b"\x00" * 32
        profile = compute_entity_profile(chain, eid)
        self.assertTrue(profile["exists"])
        self.assertEqual(profile["balance"], 600)
        self.assertEqual(profile["staked"], 300)
        self.assertEqual(profile["pending_unstake"], 100)
        self.assertEqual(profile["total_funds"], 1000)
        self.assertAlmostEqual(profile["stake_pct_of_funds"], 30.0)

    def test_message_counts_first_last_and_user_since(self):
        eid = _eid(3)
        other = _eid(4)
        b1 = _block(
            block_number=10, timestamp=1000.0, proposer=other,
            txs=[_msg(eid, 999.0, 50, _txh(1))],
        )
        b2 = _block(
            block_number=11, timestamp=1100.0, proposer=other,
            txs=[
                _msg(other, 1090.0, 50, _txh(2)),
                _msg(eid, 1099.0, 75, _txh(3)),
            ],
        )
        chain = _StubChain([b1, b2])
        profile = compute_entity_profile(chain, eid)
        self.assertEqual(profile["messages"]["total"], 2)
        self.assertEqual(profile["messages"]["first_post_block"], 10)
        self.assertEqual(profile["messages"]["last_post_block"], 11)
        self.assertEqual(profile["messages"]["first_post_timestamp"], 999.0)
        self.assertEqual(profile["messages"]["last_post_timestamp"], 1099.0)
        # user_since == earliest block where eid appeared in any role.
        self.assertEqual(profile["user_since"]["block_number"], 10)
        # Fees aggregated across both messages.
        self.assertEqual(profile["fees_paid"], 125)

    def test_block_proposer_credits_rewards(self):
        eid = _eid(5)
        blocks = [
            _block(block_number=1, timestamp=10.0, proposer=eid),
            _block(block_number=2, timestamp=20.0, proposer=_eid(99)),
            _block(block_number=3, timestamp=30.0, proposer=eid),
        ]
        chain = _StubChain(blocks)
        profile = compute_entity_profile(chain, eid)
        self.assertEqual(profile["rewards"]["blocks_proposed"], 2)
        # Stub reward = 1_000 per block, two blocks proposed.
        self.assertEqual(profile["rewards"]["estimated_block_rewards"], 2_000)
        # Earliest activity is block 1 (proposing it).
        self.assertEqual(profile["user_since"]["block_number"], 1)

    def test_governance_proposals_and_votes_aggregated(self):
        eid = _eid(6)
        b = _block(
            block_number=5, timestamp=500.0, proposer=_eid(99),
            governance=[
                _proposal(eid, 200),
                _proposal(_eid(7), 200),
                _vote(eid, 30),
                _vote(eid, 30),
                _vote(_eid(8), 30),
            ],
        )
        chain = _StubChain([b])
        profile = compute_entity_profile(chain, eid)
        self.assertEqual(profile["governance"]["proposals_made"], 1)
        self.assertEqual(profile["governance"]["votes_cast"], 2)
        # Proposal fee + 2 vote fees attributed to fees_paid.
        self.assertEqual(profile["fees_paid"], 200 + 30 + 30)

    def test_transfers_sent_received(self):
        eid = _eid(9)
        peer = _eid(10)
        b = _block(
            block_number=2, timestamp=200.0, proposer=_eid(99),
            transfers=[
                _transfer(eid, peer, 100, 5),
                _transfer(peer, eid, 200, 5),
            ],
        )
        chain = _StubChain([b])
        profile = compute_entity_profile(chain, eid)
        self.assertEqual(profile["transfers"]["sent"], 1)
        self.assertEqual(profile["transfers"]["received"], 1)
        # Only the SENT transfer's fee counts toward fees_paid.
        self.assertEqual(profile["fees_paid"], 5)

    def test_reputation_rate_and_post_distinct_upvoters(self):
        author = _eid(20)
        liker_a = _eid(21)
        liker_b = _eid(22)
        liker_c = _eid(23)
        hater = _eid(24)
        msg_h1 = _txh(50)
        msg_h2 = _txh(51)
        b = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            txs=[
                _msg(author, 50.0, 10, msg_h1),
                _msg(author, 60.0, 10, msg_h2),
            ],
        )
        chain = _StubChain([b])
        rs = chain.reaction_state
        # Profile-level: 3 ups, 1 down → score +2, rate 75%.
        rs.choices[(liker_a, author, True)] = REACT_CHOICE_UP
        rs.choices[(liker_b, author, True)] = REACT_CHOICE_UP
        rs.choices[(liker_c, author, True)] = REACT_CHOICE_UP
        rs.choices[(hater, author, True)] = REACT_CHOICE_DOWN
        rs._user_trust_score[author] = 2
        # Posts: liker_a upvotes both posts (counts once toward
        # distinct upvoters), liker_b upvotes msg_h1, hater downvotes
        # msg_h1.  Distinct post-upvoters = {liker_a, liker_b} = 2.
        # post_ups=3, post_downs=1 → rate 75%.
        rs.choices[(liker_a, msg_h1, False)] = REACT_CHOICE_UP
        rs.choices[(liker_a, msg_h2, False)] = REACT_CHOICE_UP
        rs.choices[(liker_b, msg_h1, False)] = REACT_CHOICE_UP
        rs.choices[(hater, msg_h1, False)] = REACT_CHOICE_DOWN
        rs._message_score[msg_h1] = 1
        rs._message_score[msg_h2] = 1

        profile = compute_entity_profile(chain, author)

        rep = profile["reputation"]
        self.assertEqual(rep["score"], 2)
        self.assertEqual(rep["ups_received"], 3)
        self.assertEqual(rep["downs_received"], 1)
        self.assertAlmostEqual(rep["rate_pct"], 75.0)

        ps = profile["post_score"]
        self.assertEqual(ps["total"], 2)
        self.assertEqual(ps["ups_received"], 3)
        self.assertEqual(ps["downs_received"], 1)
        self.assertEqual(ps["distinct_upvoters"], 2)
        self.assertAlmostEqual(ps["rate_pct"], 75.0)

    def test_supply_spent_pct_cumulative_fees_and_transfers(self):
        # Genesis supply 100_000, block reward 1_000/block.
        # Block 1 supply (after mint) = 101_000.
        #   message fee 100 → 100/101_000 * 100 ≈ 0.0990099%
        # Block 2 supply (after mint) = 102_000.
        #   transfer amount 500 + fee 50 = 550 → 550/102_000 * 100
        #     ≈ 0.5392157%
        # Total ≈ 0.6382256%.
        eid = _eid(40)
        peer = _eid(41)
        b1 = _block(
            block_number=1, timestamp=10.0, proposer=_eid(99),
            txs=[_msg(eid, 9.0, 100, _txh(1))],
        )
        b2 = _block(
            block_number=2, timestamp=20.0, proposer=_eid(99),
            transfers=[_transfer(eid, peer, 500, 50)],
        )
        chain = _StubChain([b1, b2])
        profile = compute_entity_profile(chain, eid)
        expected = (
            100.0 * 100 / (STUB_GENESIS_SUPPLY + 1_000)
            + 100.0 * (500 + 50) / (STUB_GENESIS_SUPPLY + 2_000)
        )
        self.assertAlmostEqual(
            profile["supply_spent_pct_cumulative"],
            expected,
            places=9,
        )

    def test_supply_spent_pct_zero_for_inactive_entity(self):
        eid = _eid(42)
        b1 = _block(
            block_number=1, timestamp=10.0, proposer=_eid(99),
            txs=[_msg(_eid(99), 9.0, 100, _txh(1))],
        )
        chain = _StubChain([b1])
        profile = compute_entity_profile(chain, eid)
        self.assertEqual(profile["supply_spent_pct_cumulative"], 0.0)

    def test_invalid_entity_id_raises(self):
        with self.assertRaises(ValueError):
            compute_entity_profile(_StubChain(), b"too-short")


# ── HTTP endpoint integration ───────────────────────────────────────


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestEntityEndpoint(unittest.TestCase):
    def setUp(self):
        eid = _eid(7)
        self.eid = eid
        b = _block(
            block_number=1, timestamp=1_700_000_000.0, proposer=eid,
            txs=[_msg(eid, 1_700_000_000.0, 42, _txh(1))],
        )
        chain = _StubChain([b])
        chain.supply.balances[eid] = 555
        port = _find_free_port()
        self.server = PublicFeedServer(
            blockchain=chain, port=port, bind="127.0.0.1",
        )
        self.server.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            self.server.stop()
            raise RuntimeError("PublicFeedServer never came up")
        self.port = port

    def tearDown(self):
        self.server.stop()

    def _get(self, path: str):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_v1_entity_returns_profile(self):
        status, _h, body = self._get(f"/v1/entity?id={self.eid.hex()}")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["height"], 1)
        prof = data["profile"]
        self.assertEqual(prof["entity_id"], self.eid.hex())
        self.assertTrue(prof["exists"])
        self.assertEqual(prof["balance"], 555)
        self.assertEqual(prof["messages"]["total"], 1)
        self.assertEqual(prof["rewards"]["blocks_proposed"], 1)
        # New contract: no react_majority_alignment, but supply spent
        # and rate fields are present.
        self.assertNotIn("react_majority_alignment", prof)
        self.assertIn("supply_spent_pct_cumulative", prof)
        self.assertIn("rate_pct", prof["reputation"])
        self.assertIn("rate_pct", prof["post_score"])
        self.assertIn("distinct_upvoters", prof["post_score"])

    def test_v1_entity_rejects_bad_hex(self):
        status, _h, body = self._get("/v1/entity?id=nothex")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertFalse(data["ok"])

    def test_v1_entity_missing_id(self):
        status, _h, _body = self._get("/v1/entity")
        self.assertEqual(status, 400)

    def test_e_path_serves_entity_html(self):
        status, headers, body = self._get(f"/e/{self.eid.hex()}")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        # Page is the bundled entity.html — check for an identifying
        # marker so we know we hit the right file.
        self.assertIn(b"entity profile", body)


if __name__ == "__main__":
    unittest.main()
