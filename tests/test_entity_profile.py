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

    def test_reputation_and_post_score_from_reaction_state(self):
        author = _eid(20)
        liker = _eid(21)
        hater = _eid(22)
        msg_h = _txh(50)
        b = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            txs=[_msg(author, 50.0, 10, msg_h)],
        )
        chain = _StubChain([b])
        rs = chain.reaction_state
        # 2 ups, 1 down on author's user-trust → reputation = +1.
        rs.choices[(liker, author, True)] = REACT_CHOICE_UP
        rs.choices[(_eid(23), author, True)] = REACT_CHOICE_UP
        rs.choices[(hater, author, True)] = REACT_CHOICE_DOWN
        rs._user_trust_score[author] = 1
        # On the message: 1 up, 0 down → post score = +1.
        rs.choices[(liker, msg_h, False)] = REACT_CHOICE_UP
        rs._message_score[msg_h] = 1

        profile = compute_entity_profile(chain, author)
        self.assertEqual(profile["reputation"]["score"], 1)
        self.assertEqual(profile["reputation"]["ups_received"], 2)
        self.assertEqual(profile["reputation"]["downs_received"], 1)
        self.assertEqual(profile["post_score"]["total"], 1)
        self.assertEqual(profile["post_score"]["ups_received"], 1)
        self.assertEqual(profile["post_score"]["downs_received"], 0)

    def test_react_majority_alignment_user_and_post_levels(self):
        voter = _eid(30)
        # Two user-trust targets:
        #   target_a aggregate +5  (voter went UP → matches)
        #   target_b aggregate -3  (voter went UP → MIS-matches)
        # One post target:
        #   msg aggregate +1 (voter went UP → matches)
        # Tie target excluded from denominator:
        #   target_c aggregate 0 (voter went UP → not counted)
        chain = _StubChain()
        rs = chain.reaction_state
        target_a = _eid(31)
        target_b = _eid(32)
        target_c = _eid(33)
        msg = _txh(40)
        rs.choices[(voter, target_a, True)] = REACT_CHOICE_UP
        rs.choices[(voter, target_b, True)] = REACT_CHOICE_UP
        rs.choices[(voter, target_c, True)] = REACT_CHOICE_UP
        rs.choices[(voter, msg, False)] = REACT_CHOICE_UP
        rs._user_trust_score[target_a] = 5
        rs._user_trust_score[target_b] = -3
        # target_c omitted from aggregate map → score 0 (tie).
        rs._message_score[msg] = 1

        profile = compute_entity_profile(chain, voter)
        ul = profile["react_majority_alignment"]["user_level"]
        pl = profile["react_majority_alignment"]["post_level"]
        # 2 user votes counted (target_c excluded), 1 matched.
        self.assertEqual(ul["votes"], 2)
        self.assertEqual(ul["with_majority"], 1)
        self.assertAlmostEqual(ul["pct"], 50.0)
        self.assertEqual(pl["votes"], 1)
        self.assertEqual(pl["with_majority"], 1)
        self.assertAlmostEqual(pl["pct"], 100.0)

    def test_react_majority_pct_is_none_with_no_votes(self):
        chain = _StubChain()
        profile = compute_entity_profile(chain, _eid(99))
        self.assertIsNone(
            profile["react_majority_alignment"]["user_level"]["pct"]
        )
        self.assertIsNone(
            profile["react_majority_alignment"]["post_level"]["pct"]
        )

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
