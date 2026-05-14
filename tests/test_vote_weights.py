"""
Tests for the vote-weight snapshot helper + weighted-up-rate aggregator
(messagechain.core.vote_weights).

This is a UI-layer module: it walks a Blockchain-shaped object to record,
for each (voter, target, target_is_user) entry in ReactionState, the
voter's reconstructed balance / cumulative-spend / age at the height the
LATEST non-CLEAR React tx was applied.  The aggregator then computes
four weighted UP-rate percentages alongside the existing simple rate.

We duck-type the chain with the same SimpleNamespace pattern the
entity-profile tests use.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from messagechain.config import (
    REACT_CHOICE_CLEAR,
    REACT_CHOICE_DOWN,
    REACT_CHOICE_UP,
)
from messagechain.core.reaction import ReactionState
from messagechain.core.vote_weights import (
    compute_vote_weight_snapshots,
    weighted_up_rates,
)
from messagechain.network.entity_profile import compute_entity_profile


STUB_GENESIS_SUPPLY = 100_000


def _eid(seed: int) -> bytes:
    return seed.to_bytes(32, "big")


def _txh(seed: int) -> bytes:
    return (seed + 0xC0DE).to_bytes(32, "big")


def _msg(entity, ts, fee, tx_hash):
    return SimpleNamespace(
        entity_id=entity, timestamp=ts, fee=fee, tx_hash=tx_hash,
    )


def _transfer(sender, recipient, amount, fee):
    return SimpleNamespace(
        entity_id=sender, recipient_id=recipient,
        amount=amount, fee=fee,
    )


def _react(voter, target, target_is_user, choice, fee=10):
    return SimpleNamespace(
        voter_id=voter, target=target, target_is_user=target_is_user,
        choice=choice, fee=fee,
    )


def _block(
    *,
    block_number, timestamp, proposer,
    txs=(), transfers=(), reacts=(),
    governance=(), stakes=(), unstakes=(),
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
    GENESIS_SUPPLY = STUB_GENESIS_SUPPLY

    def __init__(self):
        self.balances: dict[bytes, int] = {}
        self.staked: dict[bytes, int] = {}
        self.pending_unstakes: dict[bytes, list[tuple[int, int]]] = {}

    def get_balance(self, eid):
        return self.balances.get(eid, 0)

    def get_staked(self, eid):
        return self.staked.get(eid, 0)

    def calculate_block_reward(self, height):
        return 1_000


class _StubChain:
    def __init__(self, blocks=None):
        self.chain = list(blocks or [])
        self.supply = _StubSupply()
        self.reaction_state = ReactionState()
        self.public_keys: dict[bytes, bytes] = {}

    @property
    def height(self):
        return self.chain[-1].header.block_number if self.chain else 0


# ── snapshot helper ─────────────────────────────────────────────────


class TestComputeVoteWeightSnapshots(unittest.TestCase):
    def test_empty_chain_returns_empty_map(self):
        self.assertEqual(compute_vote_weight_snapshots(_StubChain()), {})

    def test_chain_with_no_react_txs_returns_empty_map(self):
        eid = _eid(1)
        chain = _StubChain([
            _block(
                block_number=1, timestamp=100.0, proposer=eid,
                txs=[_msg(eid, 99.0, 10, _txh(1))],
            ),
        ])
        self.assertEqual(compute_vote_weight_snapshots(chain), {})

    def test_single_up_vote_records_snapshot_keyed_by_voter_target(self):
        voter = _eid(1)
        target = _eid(2)
        # Pre-block to establish voter's first-seen timestamp.
        b1 = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            txs=[_msg(voter, 99.0, 10, _txh(1))],
        )
        # React tx in a later block.
        b2 = _block(
            block_number=2, timestamp=200.0, proposer=_eid(99),
            reacts=[_react(voter, target, True, REACT_CHOICE_UP, fee=10)],
        )
        snaps = compute_vote_weight_snapshots(_StubChain([b1, b2]))
        key = (voter, target, True)
        self.assertIn(key, snaps)
        snap = snaps[key]
        self.assertEqual(snap["vote_block"], 2)
        self.assertEqual(snap["vote_ts"], 200.0)
        # Voter was first seen at ts=100.0; vote at ts=200.0 → 100s age.
        self.assertAlmostEqual(snap["age_sec_at_vote"], 100.0)
        # Voter has spent 20 tokens total (10 in b1, 10 in b2) by vote time.
        # Block 1 supply (after mint) = 101_000 → 10/101_000.
        # Block 2 supply (after mint) = 102_000 → 10/102_000.
        expected_spend = (
            100.0 * 10 / (STUB_GENESIS_SUPPLY + 1_000)
            + 100.0 * 10 / (STUB_GENESIS_SUPPLY + 2_000)
        )
        self.assertAlmostEqual(snap["spend_pct_at_vote"], expected_spend)
        # Balance reconstruction: voter paid 10+10 in fees, never
        # received any credit, so reconstructed balance is 0
        # (clamped — true value would be -20).
        self.assertEqual(snap["balance_at_vote"], 0)

    def test_balance_reconstruction_tracks_transfer_in_and_out(self):
        voter = _eid(10)
        peer = _eid(11)
        target = _eid(12)
        # Block 1: peer transfers 500 to voter.
        b1 = _block(
            block_number=1, timestamp=10.0, proposer=_eid(99),
            transfers=[_transfer(peer, voter, 500, 5)],
        )
        # Block 2: voter casts a react.
        b2 = _block(
            block_number=2, timestamp=20.0, proposer=_eid(99),
            reacts=[_react(voter, target, False, REACT_CHOICE_UP, fee=10)],
        )
        # Block 3: voter sends 100 to peer with fee 5. Balance after = 500-10-100-5 = 385.
        b3 = _block(
            block_number=3, timestamp=30.0, proposer=_eid(99),
            transfers=[_transfer(voter, peer, 100, 5)],
        )
        snaps = compute_vote_weight_snapshots(_StubChain([b1, b2, b3]))
        snap = snaps[(voter, target, False)]
        # At vote time (end of block 2): voter received 500, paid 10
        # react fee → balance 490.  Later block 3 outflows don't
        # retroactively change vote-time snapshot.
        self.assertEqual(snap["balance_at_vote"], 490)

    def test_clear_choice_removes_prior_snapshot(self):
        voter = _eid(1)
        target = _eid(2)
        b1 = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            reacts=[_react(voter, target, True, REACT_CHOICE_UP)],
        )
        b2 = _block(
            block_number=2, timestamp=200.0, proposer=_eid(99),
            reacts=[_react(voter, target, True, REACT_CHOICE_CLEAR)],
        )
        snaps = compute_vote_weight_snapshots(_StubChain([b1, b2]))
        self.assertNotIn((voter, target, True), snaps)

    def test_subsequent_vote_overwrites_snapshot(self):
        voter = _eid(1)
        target = _eid(2)
        b1 = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            reacts=[_react(voter, target, True, REACT_CHOICE_UP, fee=10)],
        )
        b2 = _block(
            block_number=2, timestamp=200.0, proposer=_eid(99),
            reacts=[_react(voter, target, True, REACT_CHOICE_DOWN, fee=10)],
        )
        snaps = compute_vote_weight_snapshots(_StubChain([b1, b2]))
        snap = snaps[(voter, target, True)]
        # Should reflect the LATER vote (block 2), not the earlier one.
        self.assertEqual(snap["vote_block"], 2)
        self.assertEqual(snap["vote_ts"], 200.0)

    def test_message_react_keyed_separately_from_user_trust(self):
        voter = _eid(1)
        author = _eid(2)
        msg_hash = _txh(50)
        b = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            reacts=[
                _react(voter, author, True, REACT_CHOICE_UP),
                _react(voter, msg_hash, False, REACT_CHOICE_UP),
            ],
        )
        snaps = compute_vote_weight_snapshots(_StubChain([b]))
        self.assertIn((voter, author, True), snaps)
        self.assertIn((voter, msg_hash, False), snaps)

    def test_proposer_block_reward_credits_balance_for_vote_time_snapshot(self):
        voter = _eid(1)
        target = _eid(2)
        # Voter proposes block 1 (reward 1000) then reacts in block 2.
        b1 = _block(block_number=1, timestamp=10.0, proposer=voter)
        b2 = _block(
            block_number=2, timestamp=20.0, proposer=_eid(99),
            reacts=[_react(voter, target, True, REACT_CHOICE_UP, fee=10)],
        )
        snaps = compute_vote_weight_snapshots(_StubChain([b1, b2]))
        snap = snaps[(voter, target, True)]
        # Block 1 reward = 1000 credited, then 10 react fee debited.
        self.assertEqual(snap["balance_at_vote"], 990)


# ── weighted-up-rate aggregator ─────────────────────────────────────


class TestWeightedUpRates(unittest.TestCase):
    def _snap(self, balance, spend_pct, age_sec):
        return {
            "balance_at_vote": balance,
            "spend_pct_at_vote": spend_pct,
            "age_sec_at_vote": age_sec,
        }

    def test_empty_iterable_returns_none(self):
        self.assertIsNone(weighted_up_rates([]))

    def test_all_up_returns_100_pct_on_each_axis(self):
        votes = [
            (REACT_CHOICE_UP, self._snap(100, 1.0, 1000.0)),
            (REACT_CHOICE_UP, self._snap(200, 2.0, 2000.0)),
        ]
        result = weighted_up_rates(votes)
        self.assertAlmostEqual(result["by_balance_pct"], 100.0)
        self.assertAlmostEqual(result["by_spend_pct"], 100.0)
        self.assertAlmostEqual(result["by_age_pct"], 100.0)
        self.assertAlmostEqual(result["by_rep_pct"], 100.0)

    def test_balance_weighted_skews_with_voter_balance(self):
        # Alice (balance 100) upvotes, Bob (balance 900) downvotes.
        # Simple rate would be 50%; balance-weighted = 100/1000 = 10%.
        votes = [
            (REACT_CHOICE_UP, self._snap(100, 1.0, 1000.0)),
            (REACT_CHOICE_DOWN, self._snap(900, 1.0, 1000.0)),
        ]
        result = weighted_up_rates(votes)
        self.assertAlmostEqual(result["by_balance_pct"], 10.0)
        # spend_pct and age_sec equal across both voters → 50% on those.
        self.assertAlmostEqual(result["by_spend_pct"], 50.0)
        self.assertAlmostEqual(result["by_age_pct"], 50.0)

    def test_axis_with_zero_total_weight_returns_none_for_that_axis(self):
        # Both voters have zero balance — balance-weighted has no signal.
        votes = [
            (REACT_CHOICE_UP, self._snap(0, 1.0, 1000.0)),
            (REACT_CHOICE_DOWN, self._snap(0, 2.0, 2000.0)),
        ]
        result = weighted_up_rates(votes)
        self.assertIsNone(result["by_balance_pct"])
        # Other axes still have signal.
        self.assertIsNotNone(result["by_spend_pct"])
        self.assertIsNotNone(result["by_age_pct"])

    def test_rep_axis_is_age_times_spend_product(self):
        # Voter A: age 1000, spend 1.0 → rep weight 1000.
        # Voter B: age 100, spend 10.0 → rep weight 1000.
        # Equal rep weight → 50% rep-weighted regardless of which side voted.
        votes = [
            (REACT_CHOICE_UP, self._snap(1, 1.0, 1000.0)),
            (REACT_CHOICE_DOWN, self._snap(1, 10.0, 100.0)),
        ]
        result = weighted_up_rates(votes)
        self.assertAlmostEqual(result["by_rep_pct"], 50.0)
        # Now skew: voter A's rep weight becomes much higher.
        votes2 = [
            (REACT_CHOICE_UP, self._snap(1, 10.0, 1000.0)),  # rep 10_000
            (REACT_CHOICE_DOWN, self._snap(1, 1.0, 100.0)),  # rep 100
        ]
        result2 = weighted_up_rates(votes2)
        # 10_000 / (10_000 + 100) ≈ 99.0%
        self.assertAlmostEqual(result2["by_rep_pct"], 100.0 * 10_000 / 10_100)


# ── integration: weighted_rates surface on /v1/entity ───────────────


class TestEntityProfileWeightedRates(unittest.TestCase):
    def test_reputation_and_post_score_carry_weighted_rates(self):
        author = _eid(20)
        liker = _eid(21)  # heavy voter (1000 balance)
        hater = _eid(22)  # light voter (10 balance)
        msg_hash = _txh(50)

        # Block 1: peer transfers funds to liker and hater so balance
        # reconstruction has something to track at vote time.
        peer = _eid(99)
        b1 = _block(
            block_number=1, timestamp=100.0, proposer=peer,
            transfers=[
                _transfer(peer, liker, 1_000, 5),
                _transfer(peer, hater, 10, 5),
            ],
        )
        # Block 2: author posts a message.
        b2 = _block(
            block_number=2, timestamp=200.0, proposer=peer,
            txs=[_msg(author, 199.0, 10, msg_hash)],
        )
        # Block 3: liker upvotes both author (user-trust) AND the
        # message; hater downvotes both.
        b3 = _block(
            block_number=3, timestamp=300.0, proposer=peer,
            reacts=[
                _react(liker, author, True, REACT_CHOICE_UP, fee=5),
                _react(hater, author, True, REACT_CHOICE_DOWN, fee=5),
                _react(liker, msg_hash, False, REACT_CHOICE_UP, fee=5),
                _react(hater, msg_hash, False, REACT_CHOICE_DOWN, fee=5),
            ],
        )
        chain = _StubChain([b1, b2, b3])
        rs = chain.reaction_state
        rs.choices[(liker, author, True)] = REACT_CHOICE_UP
        rs.choices[(hater, author, True)] = REACT_CHOICE_DOWN
        rs.choices[(liker, msg_hash, False)] = REACT_CHOICE_UP
        rs.choices[(hater, msg_hash, False)] = REACT_CHOICE_DOWN
        rs._user_trust_score[author] = 0
        rs._message_score[msg_hash] = 0

        profile = compute_entity_profile(chain, author)

        # Simple rates are 50% (1 up / 1 down on each).
        self.assertAlmostEqual(profile["reputation"]["rate_pct"], 50.0)
        self.assertAlmostEqual(profile["post_score"]["rate_pct"], 50.0)

        # Both sections now carry weighted_rates.
        for section_key in ("reputation", "post_score"):
            wr = profile[section_key].get("weighted_rates")
            self.assertIsNotNone(wr, f"{section_key} missing weighted_rates")
            for axis in (
                "by_balance_pct", "by_spend_pct", "by_age_pct", "by_rep_pct",
            ):
                self.assertIn(axis, wr)
            # Liker has ~1000 balance, hater ~10 → balance-weighted UP
            # rate skews heavily toward liker (UP). Should be > 90%.
            self.assertGreater(wr["by_balance_pct"], 90.0)

    def test_no_votes_yields_none_weighted_rates(self):
        author = _eid(1)
        b = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            txs=[_msg(author, 99.0, 10, _txh(1))],
        )
        chain = _StubChain([b])
        profile = compute_entity_profile(chain, author)
        self.assertIsNone(profile["reputation"].get("weighted_rates"))
        self.assertIsNone(profile["post_score"].get("weighted_rates"))


# ── integration: per-message weighted_rates on recent-messages JSON ─


class TestRecentMessagesWeightedRates(unittest.TestCase):
    def test_recent_messages_carry_weighted_rates(self):
        from messagechain.core.blockchain import Blockchain

        author = _eid(1)
        liker = _eid(2)
        hater = _eid(3)
        msg_hash = _txh(1)
        peer = _eid(99)
        # Establish balance disparity: liker gets 1000, hater gets 10.
        b1 = _block(
            block_number=1, timestamp=100.0, proposer=peer,
            transfers=[
                _transfer(peer, liker, 1_000, 5),
                _transfer(peer, hater, 10, 5),
            ],
        )
        # Author posts.
        msg_tx = SimpleNamespace(
            entity_id=author, timestamp=199.0, fee=10,
            tx_hash=msg_hash, plaintext=b"hi",
        )
        b2 = _block(
            block_number=2, timestamp=200.0, proposer=peer,
            txs=[msg_tx],
        )
        # Votes: liker UP, hater DOWN.
        b3 = _block(
            block_number=3, timestamp=300.0, proposer=peer,
            reacts=[
                _react(liker, msg_hash, False, REACT_CHOICE_UP, fee=5),
                _react(hater, msg_hash, False, REACT_CHOICE_DOWN, fee=5),
            ],
        )
        chain = _StubChain([b1, b2, b3])
        chain.reaction_state.choices[(liker, msg_hash, False)] = REACT_CHOICE_UP
        chain.reaction_state.choices[(hater, msg_hash, False)] = REACT_CHOICE_DOWN
        chain.reaction_state._message_score[msg_hash] = 0

        # Bind the unbound get_recent_messages method to our stub chain.
        msgs = Blockchain.get_recent_messages(chain, 10)
        self.assertEqual(len(msgs), 1)
        m = msgs[0]
        self.assertEqual(m["ups"], 1)
        self.assertEqual(m["downs"], 1)
        self.assertAlmostEqual(m["up_pct"], 50.0)
        self.assertIn("weighted_rates", m)
        wr = m["weighted_rates"]
        for axis in (
            "by_balance_pct", "by_spend_pct", "by_age_pct", "by_rep_pct",
        ):
            self.assertIn(axis, wr)
        # Liker's balance (≈1000) dwarfs hater's (≈10) → UP-weighted >> 50%.
        self.assertGreater(wr["by_balance_pct"], 90.0)

    def test_recent_messages_omits_weighted_rates_when_no_votes(self):
        from messagechain.core.blockchain import Blockchain

        author = _eid(1)
        msg_tx = SimpleNamespace(
            entity_id=author, timestamp=99.0, fee=10,
            tx_hash=_txh(1), plaintext=b"hi",
        )
        b = _block(
            block_number=1, timestamp=100.0, proposer=_eid(99),
            txs=[msg_tx],
        )
        chain = _StubChain([b])
        msgs = Blockchain.get_recent_messages(chain, 10)
        self.assertEqual(len(msgs), 1)
        self.assertNotIn("weighted_rates", msgs[0])


if __name__ == "__main__":
    unittest.main()
