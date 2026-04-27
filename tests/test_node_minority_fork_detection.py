"""Auto-resync from minority fork — detection logic.

CLAUDE.md anchor: "a node that ends up on a minority/unintentional
fork must auto-resync to the canonical chain with no manual state
surgery on the operator side, and must not accumulate slashable
evidence solely from being briefly on the wrong tip."

The recovery half (syncer + ForkChoice) already exists.  The
detection half — figuring out we're on the wrong tip — was missing:
the existing trigger ``peer_height > our_height`` only fires when
we're behind by ≥ 1 block, never for the same-height-different-
hash case.

This test pins ``Node._minority_fork_likely`` behavior:
  * Returns False when we have < 2 corroborating peers (refuses to
    sync on a single peer's word — outlier defense).
  * Returns True when a strict majority of at-or-above peers report
    higher cumulative_weight at our same height.
  * Returns False when the heavier-weight peers are below us.
  * Returns False when our weight matches or exceeds peer weights.
"""

import unittest
from unittest.mock import MagicMock

from messagechain.network.sync import PeerSyncInfo


class _NodeStub:
    """Minimal Node-shaped object for the unbound _minority_fork_likely call."""
    def __init__(self, our_height: int, our_weight: int):
        self.blockchain = MagicMock()
        self.blockchain.height = our_height
        self._our_weight = our_weight
        self.syncer = MagicMock()
        self.syncer.peer_heights = {}

    def _current_cumulative_weight(self) -> int:
        return self._our_weight

    def add_peer(self, addr: str, height: int, weight: int):
        self.syncer.peer_heights[addr] = PeerSyncInfo(
            peer_address=addr, chain_height=height,
            best_block_hash="", cumulative_weight=weight,
        )


def _detect(node) -> bool:
    """Bind _minority_fork_likely from the real Node class to the stub."""
    from messagechain.network.node import Node
    return Node._minority_fork_likely(node)


class TestMinorityForkDetection(unittest.TestCase):

    def test_no_peers_returns_false(self):
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        self.assertFalse(_detect(node))

    def test_single_disagreeing_peer_does_not_trigger(self):
        # One peer at our height with HIGHER weight is not enough —
        # outlier defense.  Min peer count for trigger = 2.
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=2_000_000)
        self.assertFalse(_detect(node))

    def test_majority_heavier_peers_at_same_height_triggers(self):
        # Two peers at our height with strictly higher weight → strict
        # majority of the at-or-above set → trigger.
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=2_000_000)
        node.add_peer("p2", height=100, weight=2_500_000)
        self.assertTrue(_detect(node))

    def test_split_vote_does_not_trigger(self):
        # 1 heavier, 1 lighter — not a strict majority (count must
        # be > total//2; total=2 → need >1, so 2 needed).
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=2_000_000)
        node.add_peer("p2", height=100, weight=500_000)
        self.assertFalse(_detect(node))

    def test_three_peers_two_heavier_triggers(self):
        # 2 of 3 heavier → strict majority (2 > 3//2 = 1) → trigger.
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=2_000_000)
        node.add_peer("p2", height=100, weight=2_500_000)
        node.add_peer("p3", height=100, weight=500_000)
        self.assertTrue(_detect(node))

    def test_peers_below_us_not_counted(self):
        # Peers at chain_height < our_height are NOT in the
        # corroboration set.  Even if one of them claims absurd
        # cumulative_weight, the candidate set is empty.
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=99, weight=99_999_999_999)
        node.add_peer("p2", height=98, weight=99_999_999_999)
        self.assertFalse(_detect(node))

    def test_equal_weight_peers_do_not_trigger(self):
        # Peers at same height + same weight — no fork divergence
        # signal.  We're on the same tip as them.
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=1_000_000)
        node.add_peer("p2", height=100, weight=1_000_000)
        self.assertFalse(_detect(node))

    def test_peers_strictly_ahead_count_too(self):
        # The detection set includes peers at HIGHER heights — those
        # also indicate we're behind, in which case the existing
        # peer_height > our_height trigger would fire.  Detection
        # method is conservative-OR with the height-based trigger;
        # a tie-break at our height is what's specifically being
        # caught here.
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=105, weight=2_000_000)
        node.add_peer("p2", height=110, weight=2_500_000)
        self.assertTrue(_detect(node))


if __name__ == "__main__":
    unittest.main()
