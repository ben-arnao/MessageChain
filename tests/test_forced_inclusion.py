"""Tests for censorship-resistance forced-inclusion consensus rule.

A proposer that quietly drops long-waited, high-fee txs from otherwise
valid blocks is censoring.  The defense is attester-enforced: every
attester independently computes "txs in my mempool that have waited >= K
blocks, ranked by fee" and votes NO on a block that drops any of those
without a valid excuse (block byte budget exhausted, invalid tx, wrong
nonce, etc.).

Because each node sees its own mempool, we cannot hard-fail blocks in
validate_block — a node that never saw the allegedly-censored tx would
wrongly reject a valid block.  Enforcement is therefore soft, through
attestation voting.  A block needs 2/3 of stake attesting; if 1/3 of
honest stake sees the censorship the block fails finality.
"""

import unittest

from messagechain.config import (
    FEE_PER_BYTE,
    FORCED_INCLUSION_SET_SIZE,
    FORCED_INCLUSION_WAIT_BLOCKS,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_TXS_PER_BLOCK,
    MIN_FEE,
)
from messagechain.consensus.forced_inclusion import (
    check_forced_inclusion,
    should_attest_block,
)
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity


# Static fee policy — forced-inclusion tests don't exercise fee dynamics
_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)

# Helper fee: higher than the floor so many per-entity txs pass the
# per-sender ancestor limit heuristic when we stack them
_BASE_FEE = MIN_FEE + 10 * FEE_PER_BYTE  # good-sized budget for "msg N"


def _make_tx(entity: Entity, fee: int, nonce: int) -> "MessageTransaction":
    return create_transaction(entity, f"msg {nonce}", fee=fee, nonce=nonce)


class _FakeBlock:
    """Minimal stand-in for the Block dataclass.

    The forced-inclusion checker only reads `transactions` and
    `header.proposer_id` from the block.  Avoids the full keypair /
    state-root apparatus Block() requires via Blockchain.
    """

    class _H:
        def __init__(self, proposer_id: bytes):
            self.proposer_id = proposer_id

    def __init__(self, txs, proposer_id: bytes = b"\x00" * 32):
        self.transactions = list(txs)
        self.header = _FakeBlock._H(proposer_id)


class TestMempoolArrivalTracking(unittest.TestCase):
    """Mempool remembers the block height at which each tx arrived."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_add_with_block_height_tracks_arrival(self):
        tx = _make_tx(self.alice, fee=_BASE_FEE, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=10)
        self.assertEqual(self.pool.arrival_heights[tx.tx_hash], 10)

    def test_add_without_block_height_defaults_to_zero(self):
        """Legacy callers — no height means the tx has 'always been here'.

        A height of 0 means the tx qualifies for forced inclusion immediately
        (current - K >= 0 for all K since tx was seen at height 0).
        """
        tx = _make_tx(self.alice, fee=_BASE_FEE, nonce=0)
        self.pool.add_transaction(tx)
        self.assertEqual(self.pool.arrival_heights[tx.tx_hash], 0)

    def test_remove_also_clears_arrival(self):
        tx = _make_tx(self.alice, fee=_BASE_FEE, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=5)
        self.pool.remove_transactions([tx.tx_hash])
        self.assertNotIn(tx.tx_hash, self.pool.arrival_heights)


class TestForcedInclusionSet(unittest.TestCase):
    """Mempool.get_forced_inclusion_set returns the top-N long-waited txs."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        self.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_short_waited_txs_do_not_qualify(self):
        """Tx that arrived <= K-1 blocks ago is not yet forced."""
        tx = _make_tx(self.alice, fee=_BASE_FEE + 1000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=10)
        # current = 10 + (K-1) — still not waited long enough
        current = 10 + (FORCED_INCLUSION_WAIT_BLOCKS - 1)
        forced = self.pool.get_forced_inclusion_set(current)
        self.assertEqual(forced, [])

    def test_long_waited_tx_qualifies(self):
        tx = _make_tx(self.alice, fee=_BASE_FEE + 1000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=10)
        current = 10 + FORCED_INCLUSION_WAIT_BLOCKS
        forced = self.pool.get_forced_inclusion_set(current)
        self.assertEqual([t.tx_hash for t in forced], [tx.tx_hash])

    def test_top_n_by_fee_descending(self):
        """Only the top N highest-fee qualifying txs are forced."""
        entities = [self.alice, self.bob, self.carol]
        txs = []
        # Need more than FORCED_INCLUSION_SET_SIZE qualifying txs with
        # distinct fees to exercise the top-N cut.
        count = FORCED_INCLUSION_SET_SIZE + 3
        # Create N+3 entities so per-sender limit doesn't apply
        extras = []
        for i in range(count):
            e = Entity.create(f"entity-{i}-private-key".encode().ljust(32, b"\x00"))
            extras.append(e)
            tx = _make_tx(e, fee=_BASE_FEE + i * 100, nonce=0)
            self.pool.add_transaction(tx, arrival_block_height=0)
            txs.append(tx)

        current = FORCED_INCLUSION_WAIT_BLOCKS
        forced = self.pool.get_forced_inclusion_set(current)
        self.assertEqual(len(forced), FORCED_INCLUSION_SET_SIZE)
        # Top N = highest fees.  Fees go 0, 100, 200, ..., so top N are
        # the last N entries.
        expected = sorted(txs, key=lambda t: t.fee, reverse=True)[:FORCED_INCLUSION_SET_SIZE]
        self.assertEqual(
            {t.tx_hash for t in forced},
            {t.tx_hash for t in expected},
        )

    def test_tiebreak_by_arrival_height_then_hash(self):
        """Equal fee → earlier arrival ranks higher; equal fee+arrival → hash."""
        a = _make_tx(self.alice, fee=_BASE_FEE, nonce=0)
        b = _make_tx(self.bob, fee=_BASE_FEE, nonce=0)
        # Bob arrives earlier than Alice
        self.pool.add_transaction(a, arrival_block_height=10)
        self.pool.add_transaction(b, arrival_block_height=5)
        current = 10 + FORCED_INCLUSION_WAIT_BLOCKS
        forced = self.pool.get_forced_inclusion_set(current)
        self.assertEqual(forced[0].tx_hash, b.tx_hash, "earlier-arrival should rank first")


class TestAttesterAcceptsGoodBlock(unittest.TestCase):
    """Attester accepts a block that honors its forced-inclusion list."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_empty_mempool_always_accepts(self):
        """No forced set → attester accepts unconditionally."""
        block = _FakeBlock(txs=[])
        ok, reason = check_forced_inclusion(block, self.pool, current_block_height=100)
        self.assertTrue(ok, reason)

    def test_proposer_includes_forced_tx(self):
        tx = _make_tx(self.alice, fee=_BASE_FEE + 5000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=0)
        block = _FakeBlock(txs=[tx])
        ok, reason = check_forced_inclusion(
            block, self.pool, current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertTrue(ok, reason)

    def test_low_fee_tx_not_in_top_n_not_forced(self):
        """Tx below the top-N fee cutoff is not required to be included."""
        # Make N+1 qualifying txs; drop the lowest-fee one
        txs = []
        for i in range(FORCED_INCLUSION_SET_SIZE + 1):
            e = Entity.create(
                f"entity-low-{i}-priv-key".encode().ljust(32, b"\x00")
            )
            tx = _make_tx(e, fee=_BASE_FEE + i * 100, nonce=0)
            self.pool.add_transaction(tx, arrival_block_height=0)
            txs.append(tx)

        # Block includes everything EXCEPT the lowest-fee tx (index 0)
        block = _FakeBlock(txs=txs[1:])
        ok, reason = check_forced_inclusion(
            block, self.pool, current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertTrue(ok, reason)

    def test_short_waited_tx_not_forced(self):
        """Tx that hasn't waited K blocks imposes no duty."""
        tx = _make_tx(self.alice, fee=_BASE_FEE + 5000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=10)
        block = _FakeBlock(txs=[])  # proposer omits it
        # Not yet K blocks old
        ok, reason = check_forced_inclusion(
            block, self.pool,
            current_block_height=10 + FORCED_INCLUSION_WAIT_BLOCKS - 1,
        )
        self.assertTrue(ok, reason)


class TestAttesterRejectsCensorship(unittest.TestCase):
    """Attester votes NO on a block that drops long-waited, high-fee txs."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_proposer_omits_forced_tx_without_excuse(self):
        """High-fee, long-waited tx missing from block → attester vetoes."""
        tx = _make_tx(self.alice, fee=_BASE_FEE + 5000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=0)
        # Block contains nothing — bucketed censorship
        block = _FakeBlock(txs=[])
        ok, reason = check_forced_inclusion(
            block, self.pool, current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertFalse(ok)
        self.assertIn("forced", reason.lower())

    def test_should_attest_block_returns_false_on_censorship(self):
        tx = _make_tx(self.alice, fee=_BASE_FEE + 5000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=0)
        block = _FakeBlock(txs=[])
        self.assertFalse(
            should_attest_block(
                block, self.pool,
                current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
            )
        )

    def test_should_attest_block_returns_true_when_clean(self):
        tx = _make_tx(self.alice, fee=_BASE_FEE + 5000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=0)
        block = _FakeBlock(txs=[tx])
        self.assertTrue(
            should_attest_block(
                block, self.pool,
                current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
            )
        )


class TestValidExcuses(unittest.TestCase):
    """Legitimate reasons a proposer may omit a forced-inclusion tx."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_byte_budget_exhausted_is_valid_excuse(self):
        """If the block already packs MAX_BLOCK_MESSAGE_BYTES, omitting a
        forced tx that wouldn't fit is NOT censorship."""
        # Create txs that together fill ~MAX_BLOCK_MESSAGE_BYTES
        entities = [
            Entity.create(f"entity-big-{i}-priv".encode().ljust(32, b"\x00"))
            for i in range(5)
        ]
        # Each message ~2400 bytes → 5 of them = 12000 > 10000 budget
        big_msg = "x" * 240  # 240 bytes; create enough big ones
        block_txs = []
        total_bytes = 0
        for i, e in enumerate(entities):
            # Use a big-ish fee so these outrank the "censored" tx
            fee_for_msg = MIN_FEE + 240 * FEE_PER_BYTE + (240 * 240 * 2) // 1000 + 10_000
            tx = create_transaction(e, big_msg, fee=fee_for_msg, nonce=0)
            self.pool.add_transaction(tx, arrival_block_height=0)
            if total_bytes + len(tx.message) <= MAX_BLOCK_MESSAGE_BYTES:
                block_txs.append(tx)
                total_bytes += len(tx.message)

        # A forced-inclusion tx that arrives but whose fee is lower than
        # the big txs; it wouldn't fit anyway given budget exhaustion
        low_fee_tx = create_transaction(
            self.alice, big_msg,
            fee=MIN_FEE + 240 * FEE_PER_BYTE + (240 * 240 * 2) // 1000,
            nonce=0,
        )
        self.pool.add_transaction(low_fee_tx, arrival_block_height=0)

        block = _FakeBlock(txs=block_txs)
        # Should still pass — byte budget is legitimately exhausted
        ok, reason = check_forced_inclusion(
            block, self.pool, current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertTrue(ok, f"byte budget exhausted is valid excuse: {reason}")

    def test_tx_count_cap_reached_is_valid_excuse(self):
        """MAX_TXS_PER_BLOCK txs included → no room for more."""
        entities = [
            Entity.create(f"entity-count-{i}-priv".encode().ljust(32, b"\x00"))
            for i in range(MAX_TXS_PER_BLOCK)
        ]
        block_txs = []
        # Put high-fee txs in the pool and the block
        for i, e in enumerate(entities):
            tx = _make_tx(e, fee=_BASE_FEE + 10_000 + i, nonce=0)
            self.pool.add_transaction(tx, arrival_block_height=0)
            block_txs.append(tx)

        # An extra low-fee forced tx wouldn't fit anyway
        late = _make_tx(self.alice, fee=_BASE_FEE + 100, nonce=0)
        self.pool.add_transaction(late, arrival_block_height=0)

        block = _FakeBlock(txs=block_txs)
        ok, reason = check_forced_inclusion(
            block, self.pool, current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertTrue(ok, reason)


class TestInvalidTxExcuse(unittest.TestCase):
    """A tx that has become un-includable (nonce/balance/signature) is a valid excuse."""

    def setUp(self):
        self.alice = Entity.create(b"alice-priv-key".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_nonce_mismatch_tx_is_valid_excuse(self):
        """Attester passes an is_includable callback; tx flagged not includable
        is accepted as legitimately excluded."""
        tx = _make_tx(self.alice, fee=_BASE_FEE + 5_000, nonce=42)
        self.pool.add_transaction(tx, arrival_block_height=0)

        def is_includable(t):
            # Pretend the chain moved on: tx.nonce is no longer the
            # expected nonce for this sender
            return t.nonce != 42

        block = _FakeBlock(txs=[])  # proposer excluded the stale tx
        ok, reason = check_forced_inclusion(
            block, self.pool,
            current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
            is_includable=is_includable,
        )
        self.assertTrue(ok, reason)

    def test_includable_check_still_catches_real_censorship(self):
        """If the tx IS includable, omitting it is still censorship."""
        tx = _make_tx(self.alice, fee=_BASE_FEE + 5_000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=0)

        def always_includable(t):
            return True

        block = _FakeBlock(txs=[])
        ok, reason = check_forced_inclusion(
            block, self.pool,
            current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
            is_includable=always_includable,
        )
        self.assertFalse(ok, reason)


class TestProposerCannotCrowdOutOthers(unittest.TestCase):
    """Proposer-self-flood attack: proposer submits many high-fee txs of its own
    to crowd out other users.  Forced-inclusion applies to ALL txs — the
    proposer's own include-only strategy does not count as 'excuse'."""

    def setUp(self):
        self.proposer = Entity.create(b"proposer-priv-key".ljust(32, b"\x00"))
        self.victim = Entity.create(b"victim-priv-key".ljust(32, b"\x00"))
        self.pool = Mempool(max_size=200, fee_policy=_STATIC_FEE)

    def test_proposer_cannot_censor_equal_fee_victim(self):
        """Victim's forced tx shares the top-N rank — must be included."""
        # Victim's tx: long-waited, high-fee
        v_tx = _make_tx(self.victim, fee=_BASE_FEE + 5_000, nonce=0)
        self.pool.add_transaction(v_tx, arrival_block_height=0)
        # Proposer's own tx: SAME fee tier, qualifies alongside victim
        p_tx = _make_tx(self.proposer, fee=_BASE_FEE + 5_000, nonce=0)
        self.pool.add_transaction(p_tx, arrival_block_height=1)

        # Block contains only the proposer's tx, not victim's
        block = _FakeBlock(
            txs=[p_tx], proposer_id=self.proposer.entity_id,
        )
        ok, reason = check_forced_inclusion(
            block, self.pool,
            current_block_height=FORCED_INCLUSION_WAIT_BLOCKS + 1,
        )
        self.assertFalse(ok, "proposer's own tx is not an excuse to drop victim")


class TestQuorumRejectsCensoredBlock(unittest.TestCase):
    """Multiple attesters independently detect censorship and veto the block."""

    def setUp(self):
        # Three attester nodes, each with its own mempool.  All three
        # saw the censored tx, so all three reach the same forced-inclusion
        # conclusion independently.
        self.victim = Entity.create(b"victim-priv-key".ljust(32, b"\x00"))
        self.pools = [
            Mempool(max_size=100, fee_policy=_STATIC_FEE) for _ in range(3)
        ]

    def test_all_honest_attesters_reject_independently(self):
        victim_tx = _make_tx(self.victim, fee=_BASE_FEE + 5_000, nonce=0)
        # Each attester has the tx in its own mempool
        for pool in self.pools:
            pool.add_transaction(victim_tx, arrival_block_height=0)

        block = _FakeBlock(txs=[])  # proposer censored victim
        votes = [
            should_attest_block(
                block, pool,
                current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
            )
            for pool in self.pools
        ]
        # All three vote NO — block fails 2/3 quorum trivially
        self.assertEqual(votes, [False, False, False])

    def test_attester_that_never_saw_tx_defaults_to_accept(self):
        """An attester with an empty mempool sees no duty and accepts.

        This is the subjectivity-tolerance point: if only the censoring
        proposer and a minority of the network saw a tx, that minority
        won't be enough to veto alone — but forced inclusion is not
        meant to protect unseen txs, only txs that have propagated.
        """
        block = _FakeBlock(txs=[])
        # Pool is empty — attester has nothing to force
        self.assertTrue(
            should_attest_block(
                block, self.pools[0],
                current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
            )
        )


if __name__ == "__main__":
    unittest.main()
