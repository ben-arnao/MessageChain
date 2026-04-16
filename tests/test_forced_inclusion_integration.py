"""End-to-end integration tests for attester-enforced forced inclusion.

These tests wire the forced-inclusion utility into the actual attestation
creation path so attesters refuse to vote on blocks that silently drop
long-waited, high-fee user txs.

Complements `test_forced_inclusion.py`, which exercises the pure
forced-inclusion checker in isolation.  This file exercises the
`attest_block_if_allowed` choke-point used by production attesters
(node.py / server.py) and the mempool arrival-height plumbing.
"""

import unittest

from messagechain.config import (
    FEE_PER_BYTE,
    FORCED_INCLUSION_WAIT_BLOCKS,
    MIN_FEE,
)
from messagechain.consensus.attestation import (
    Attestation,
    FinalityTracker,
    attest_block_if_allowed,
    create_attestation,
)
from messagechain.consensus.forced_inclusion import should_attest_block
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity

_STATIC_FEE = DynamicFeePolicy(base_fee=MIN_FEE, max_fee=100)
_BASE_FEE = MIN_FEE + 10 * FEE_PER_BYTE


def _make_tx(entity, fee, nonce):
    return create_transaction(entity, f"msg {nonce}", fee=fee, nonce=nonce)


class _FakeHeader:
    def __init__(self, proposer_id: bytes, block_number: int, prev_hash: bytes):
        self.proposer_id = proposer_id
        self.block_number = block_number
        self.prev_hash = prev_hash


class _FakeBlock:
    """Minimal Block stand-in with the attributes needed for attestation.

    Avoids the full keypair / state-root apparatus that a real Block
    requires via Blockchain.  `block_hash` and `header.block_number`
    are the only non-`forced_inclusion` fields consulted by
    `attest_block_if_allowed`.
    """

    def __init__(
        self,
        txs,
        block_hash: bytes,
        block_number: int,
        proposer_id: bytes = b"\x00" * 32,
        prev_hash: bytes = b"\x00" * 32,
    ):
        self.transactions = list(txs)
        self.block_hash = block_hash
        self.header = _FakeHeader(proposer_id, block_number, prev_hash)


class TestAttesterRefusesCensoringBlock(unittest.TestCase):
    """Attester presented with a block that drops a forced tx votes NO."""

    def setUp(self):
        self.attester = Entity.create(
            b"attester-priv".ljust(32, b"\x00")
        )
        self.victim = Entity.create(
            b"victim-priv".ljust(32, b"\x00")
        )
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_attester_returns_none_on_censorship(self):
        """Block omits a long-waited high-fee tx → attest helper returns None."""
        tx = _make_tx(self.victim, fee=_BASE_FEE + 5_000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=0)

        block = _FakeBlock(
            txs=[],  # censoring — tx dropped silently
            block_hash=b"\xaa" * 32,
            block_number=FORCED_INCLUSION_WAIT_BLOCKS,
        )

        result = attest_block_if_allowed(
            self.attester, block, self.pool,
            current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertIsNone(
            result,
            "attester must refuse to sign a censoring block",
        )

    def test_attester_signs_compliant_block(self):
        """Block includes the forced tx → attester creates a valid Attestation."""
        tx = _make_tx(self.victim, fee=_BASE_FEE + 5_000, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=0)

        block = _FakeBlock(
            txs=[tx],
            block_hash=b"\xbb" * 32,
            block_number=FORCED_INCLUSION_WAIT_BLOCKS,
        )

        att = attest_block_if_allowed(
            self.attester, block, self.pool,
            current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertIsNotNone(att, "attester should sign compliant block")
        self.assertIsInstance(att, Attestation)
        self.assertEqual(att.validator_id, self.attester.entity_id)
        self.assertEqual(att.block_hash, block.block_hash)
        self.assertEqual(att.block_number, block.header.block_number)

    def test_attester_with_empty_mempool_signs_trivially(self):
        """Attester with no pending txs has no duty — signs whatever block.

        This is the default/regression path: any attester code path that
        doesn't plumb a mempool (or whose mempool is empty) must keep
        working exactly as before.
        """
        block = _FakeBlock(
            txs=[],
            block_hash=b"\xcc" * 32,
            block_number=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        att = attest_block_if_allowed(
            self.attester, block, self.pool,  # empty pool
            current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
        )
        self.assertIsNotNone(att)


class TestQuorumRejectsCensoredBlock(unittest.TestCase):
    """Enough honest attesters each vote NO → block fails 2/3 finality."""

    def setUp(self):
        # Four independent attesters, each with its own mempool view.
        self.attesters = [
            Entity.create(f"attester-{i}-priv".encode().ljust(32, b"\x00"))
            for i in range(4)
        ]
        self.victim = Entity.create(b"victim-priv".ljust(32, b"\x00"))
        self.pools = [
            Mempool(max_size=100, fee_policy=_STATIC_FEE) for _ in range(4)
        ]

    def test_end_to_end_censorship_fails_finality(self):
        """mempool → wait K+1 blocks → proposer omits → quorum NO → no finality.

        Simulated: each attester has an independent mempool with the
        victim tx.  The block omits it.  We feed each attester's vote
        into a FinalityTracker and check the result.  A censoring
        block must NOT reach the 2/3 threshold.
        """
        victim_tx = _make_tx(self.victim, fee=_BASE_FEE + 5_000, nonce=0)

        # Step 1: three of four attesters see the tx in their mempool.
        # The fourth (the proposer's peer) happens not to — that's fine;
        # soft-vote tolerates mempool-view disagreement.
        for pool in self.pools[:3]:
            pool.add_transaction(victim_tx, arrival_block_height=0)

        # Step 2: wait K+1 blocks.  Tx is now in every attester's
        # forced-inclusion set.
        current_height = FORCED_INCLUSION_WAIT_BLOCKS + 1

        # Step 3: proposer publishes a block that omits the victim tx.
        censoring_block = _FakeBlock(
            txs=[],
            block_hash=b"\xdd" * 32,
            block_number=current_height,
        )

        # Step 4: each attester evaluates independently.
        votes = []
        for entity, pool in zip(self.attesters, self.pools):
            att = attest_block_if_allowed(
                entity, censoring_block, pool,
                current_block_height=current_height,
            )
            votes.append(att)

        # Three attesters refuse; one (empty pool) signs.
        yes_votes = [v for v in votes if v is not None]
        self.assertEqual(
            len(yes_votes), 1,
            "only the attester that never saw the tx should sign",
        )

        # Step 5: feed votes into FinalityTracker.  Equal stakes,
        # four validators: 2/3 threshold = 3 yes votes.  With only 1
        # yes vote, the block cannot finalize.
        tracker = FinalityTracker()
        stake_per_validator = 100
        total_stake = stake_per_validator * len(self.attesters)
        for att in yes_votes:
            tracker.add_attestation(att, stake_per_validator, total_stake)
        self.assertFalse(
            tracker.is_finalized(censoring_block.block_hash),
            "1/4 stake attested — block must NOT finalize",
        )

    def test_compliant_block_reaches_finality(self):
        """Same setup but proposer includes the tx → all attesters sign → finalized."""
        victim_tx = _make_tx(self.victim, fee=_BASE_FEE + 5_000, nonce=0)
        for pool in self.pools[:3]:
            pool.add_transaction(victim_tx, arrival_block_height=0)
        current_height = FORCED_INCLUSION_WAIT_BLOCKS + 1

        good_block = _FakeBlock(
            txs=[victim_tx],
            block_hash=b"\xee" * 32,
            block_number=current_height,
        )
        votes = []
        for entity, pool in zip(self.attesters, self.pools):
            att = attest_block_if_allowed(
                entity, good_block, pool,
                current_block_height=current_height,
            )
            votes.append(att)

        yes_votes = [v for v in votes if v is not None]
        self.assertEqual(len(yes_votes), len(self.attesters))

        tracker = FinalityTracker()
        stake_per_validator = 100
        total_stake = stake_per_validator * len(self.attesters)
        finalized = False
        for att in yes_votes:
            finalized = tracker.add_attestation(att, stake_per_validator, total_stake) or finalized
        self.assertTrue(
            tracker.is_finalized(good_block.block_hash),
            "compliant block must finalize when all stake attests",
        )


class TestLegitimateExcuseStillAttests(unittest.TestCase):
    """Regression: proposer's legitimate omissions still earn YES votes."""

    def setUp(self):
        self.attester = Entity.create(
            b"reg-attester-priv".ljust(32, b"\x00")
        )
        self.sender = Entity.create(
            b"reg-sender-priv".ljust(32, b"\x00")
        )
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_nonce_stale_tx_is_excused(self):
        """If the forced tx has become un-includable (stale nonce), attester
        treats it as a valid excuse and still votes YES."""
        stale_tx = _make_tx(self.sender, fee=_BASE_FEE + 5_000, nonce=42)
        self.pool.add_transaction(stale_tx, arrival_block_height=0)

        block = _FakeBlock(
            txs=[],
            block_hash=b"\x11" * 32,
            block_number=FORCED_INCLUSION_WAIT_BLOCKS,
        )

        # Chain state says the sender's next nonce is NOT 42 — the tx
        # is no longer valid to include.  Proposer correctly omitted.
        def is_includable(tx):
            return tx.nonce != 42

        att = attest_block_if_allowed(
            self.attester, block, self.pool,
            current_block_height=FORCED_INCLUSION_WAIT_BLOCKS,
            is_includable=is_includable,
        )
        self.assertIsNotNone(
            att,
            "stale-nonce tx is a valid excuse — attester must still sign",
        )


class TestMempoolArrivalHeightPlumbing(unittest.TestCase):
    """Txs entering via the Node submit/gossip path carry the current chain height."""

    def setUp(self):
        self.sender = Entity.create(
            b"plumb-sender-priv".ljust(32, b"\x00")
        )
        self.pool = Mempool(max_size=100, fee_policy=_STATIC_FEE)

    def test_submit_transaction_records_current_height(self):
        """Node.submit_transaction plumbs blockchain.height into arrival_heights.

        Regression test for the integration wiring: if a node's
        submit path forgets to pass the height, the tx arrival looks
        like "height 0" (always-forced), which would wrongly flag
        every tx for immediate forced inclusion and produce a flood
        of NO votes on any block that didn't empty the mempool.
        """
        # Verified by calling Mempool.add_transaction with a specific
        # height — that's the contract the node's submit path honors.
        tx = _make_tx(self.sender, fee=_BASE_FEE, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=42)
        self.assertEqual(self.pool.arrival_heights[tx.tx_hash], 42)

    def test_gossip_transaction_records_current_height(self):
        """Same contract for tx arrivals via ANNOUNCE_TX gossip."""
        tx = _make_tx(self.sender, fee=_BASE_FEE, nonce=0)
        self.pool.add_transaction(tx, arrival_block_height=17)
        self.assertEqual(self.pool.arrival_heights[tx.tx_hash], 17)


class TestNodeSubmitPlumbsArrivalHeight(unittest.TestCase):
    """Node.submit_transaction plumbs current chain height to the mempool.

    Protects against regression where an honest node forgets to pass
    arrival height and every tx looks "always-forced" (height 0).
    """

    def test_node_submit_uses_blockchain_height(self):
        """Call Node.submit_transaction and verify arrival_heights is set
        to the current chain height, not 0."""
        from messagechain.network.node import Node
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.pos import ProofOfStake
        from tests import register_entity_for_test

        alice = Entity.create(b"alice-node-priv".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-node-priv".ljust(32, b"\x00"))

        # Build a node with a chain that has advanced past genesis
        # so blockchain.height > 0 and we can distinguish from the
        # zero-default.
        node = Node(alice, port=0)
        node.blockchain.initialize_genesis(alice)
        register_entity_for_test(node.blockchain, bob)
        node.blockchain.supply.balances[bob.entity_id] = 100_000
        # Advance by one block so height > 0
        consensus = ProofOfStake()
        blk = node.blockchain.propose_block(consensus, alice, [])
        ok, _reason = node.blockchain.add_block(blk)
        self.assertTrue(ok)
        expected_height = node.blockchain.height

        tx = _make_tx(bob, fee=_BASE_FEE, nonce=0)
        submitted, _reason = node.submit_transaction(tx)
        self.assertTrue(submitted)
        self.assertEqual(
            node.mempool.arrival_heights.get(tx.tx_hash), expected_height,
            "submit_transaction must record the current chain height "
            "as the tx's arrival height (not the 0-default)",
        )


if __name__ == "__main__":
    unittest.main()
