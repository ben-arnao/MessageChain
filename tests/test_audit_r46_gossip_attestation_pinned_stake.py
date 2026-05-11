"""Audit r46 #1 — gossip-ingress attestation handler corrupts the
FinalityTracker stake denominator by reading LIVE `supply.staked`
instead of the pinned-at-target-height snapshot.

The consensus apply path (`Blockchain._process_attestations`) already
reads `self._stake_snapshots.get(target_block)` and skips the finality
update when the pin is missing — see
``test_attestation_no_live_fallback.py``.  But two parallel paths in
``messagechain/network/node.py`` ALSO call
``self.blockchain.finality.add_attestation`` and were reading live
stake:

  1. ``_handle_announce_attestation`` (gossip ingress, line 1767-1772)
     — reads ``supply.get_staked(att.validator_id)`` + ``sum(
     supply.staked.values())`` and feeds those to the same
     ``add_attestation`` accumulator the apply path uses.  Dedup is
     keyed ``(vid, height, hash)``, so whichever path arrives first
     wins the stake contribution.  During stake-churn windows two
     honest peers can reach different ``is_finalized()`` answers and
     fork on reorg-rejection.

  2. The local-broadcast path (when this node attests its OWN block,
     line 1695-1700) — same defect, same live-stake read.

Adversary: validator collusion (CLAUDE.md adversary #1).  The
2-validator mainnet is amplified by small-set arithmetic — any peer
holding minority stake can trigger divergent finalization across
the network during a stake-churn window.

Abstraction fix: a single helper
``Blockchain.resolve_pinned_attestation_stake(att)`` is the chokepoint
both the apply path and the network-layer paths now route through.
Returns ``(validator_stake, total_stake)`` from the pinned snapshot
at ``att.block_number``, or ``None`` if no pin exists (peer hasn't
applied the target block yet).  Adding a new caller in the future
can't silently drift back to live stake — the helper is the only way
to compute the stake denominator used in finality accounting.
"""

from __future__ import annotations

import unittest

from messagechain import config
from messagechain.consensus.attestation import (
    Attestation,
    create_attestation,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestResolvePinnedAttestationStakeHelper(unittest.TestCase):
    """Unit tests on the new ``Blockchain.resolve_pinned_attestation_stake``
    helper.  This is the single source of truth all callers route through.
    """

    @classmethod
    def setUpClass(cls):
        cls.alice = _entity(b"r46-helper-alice")
        cls.bob = _entity(b"r46-helper-bob")
        cls.carol = _entity(b"r46-helper-carol")

    def setUp(self):
        from messagechain.config import TREASURY_ENTITY_ID

        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000
        self.chain.supply.balances[self.carol.entity_id] = 10_000
        self.chain.supply.balances.setdefault(TREASURY_ENTITY_ID, 0)
        self.chain.supply.balances[TREASURY_ENTITY_ID] += 10_000
        self.chain.supply.stake(self.alice.entity_id, 2_000)
        self.chain.supply.stake(self.bob.entity_id, 500)
        self.chain.supply.stake(self.carol.entity_id, 500)
        self.consensus = ProofOfStake()

    def test_helper_exists_and_returns_pinned_tuple(self):
        """The helper exists on Blockchain and returns the pinned
        (validator_stake, total_stake) at the attestation's target
        height — NOT a read of live ``supply.staked``."""
        self.assertTrue(
            hasattr(self.chain, "resolve_pinned_attestation_stake"),
            "Blockchain must expose resolve_pinned_attestation_stake() "
            "as the single chokepoint for stake-denominator reads in "
            "finality accounting.",
        )

        proposer = pick_selected_proposer(
            self.chain, [self.alice, self.bob, self.carol],
        )
        block1 = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)
        self.assertIn(1, self.chain._stake_snapshots)

        att = create_attestation(
            self.alice, block1.block_hash, block1.header.block_number,
        )

        resolved = self.chain.resolve_pinned_attestation_stake(att)
        self.assertIsNotNone(resolved)
        validator_stake, total_stake = resolved
        # Pinned at height 1: alice=2000, bob=500, carol=500 -> total 3000.
        self.assertEqual(validator_stake, 2_000)
        self.assertEqual(total_stake, 3_000)

    def test_helper_returns_none_when_pin_missing(self):
        """Helper returns ``None`` for attestations whose target height
        has no pinned snapshot — the caller must skip the finality
        update rather than fall back to live stake (the divergence
        trap)."""
        proposer = pick_selected_proposer(
            self.chain, [self.alice, self.bob, self.carol],
        )
        block1 = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)

        att = create_attestation(
            self.alice, block1.block_hash, block1.header.block_number,
        )

        # Drop the pin (simulates cold-restart past the mirror window,
        # snapshot-mirror corruption, or a peer that hasn't applied
        # this target height yet).
        del self.chain._stake_snapshots[1]

        resolved = self.chain.resolve_pinned_attestation_stake(att)
        self.assertIsNone(
            resolved,
            "When the pinned snapshot is missing for att.block_number, "
            "the helper MUST return None so callers can skip the "
            "finality update — falling back to live supply.staked would "
            "produce arrival-order-dependent is_finalized() decisions "
            "across peers.",
        )

    def test_helper_ignores_live_stake_drift(self):
        """The whole point: even if live stake has drifted away from
        the pinned snapshot, the helper returns PINNED values.  This
        is the contract that prevents peer-divergent finality."""
        proposer = pick_selected_proposer(
            self.chain, [self.alice, self.bob, self.carol],
        )
        block1 = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)

        att = create_attestation(
            self.alice, block1.block_hash, block1.header.block_number,
        )

        # Heavy stake churn AFTER block 1 was pinned.  Alice doubles
        # her stake; bob drops to zero.  Live supply.staked is now
        # {alice: 4000, bob: 0, carol: 500} -> total 4500.  Pinned at
        # height 1 stays {alice: 2000, bob: 500, carol: 500} -> 3000.
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.stake(self.alice.entity_id, 2_000)  # alice now 4000
        self.chain.supply.unstake(self.bob.entity_id, 500)    # bob now 0

        resolved = self.chain.resolve_pinned_attestation_stake(att)
        self.assertIsNotNone(resolved)
        validator_stake, total_stake = resolved
        # Pinned values, NOT live.  This is the consensus-correct
        # denominator every peer must agree on.
        self.assertEqual(
            validator_stake, 2_000,
            "Helper MUST return pinned stake (2000), not live (4000).",
        )
        self.assertEqual(
            total_stake, 3_000,
            "Helper MUST return pinned total (3000), not live (4500).",
        )


class TestGossipIngressUsesPinnedStake(unittest.TestCase):
    """Structural: the gossip-ingress handler and the local-broadcast
    path in ``messagechain/network/node.py`` MUST route through the
    Blockchain helper, not call ``supply.get_staked`` / ``supply.staked
    .values()`` directly when computing the stake denominator for
    ``finality.add_attestation``.

    Structural test rather than a full Node-instantiation test because
    Node setup is heavyweight (TLS, ban manager, peer selector, addr
    manager, anchor store, data-dir lock, ...) and the
    consensus-determinism-of-the-helper contract is unit-tested above.
    What we're pinning here is that the call sites can't silently
    drift back to live stake.
    """

    def _read_node_source(self) -> str:
        import inspect
        import messagechain.network.node as node_mod
        return inspect.getsource(node_mod)

    def test_handle_announce_attestation_routes_through_helper(self):
        """The gossip-ingress handler body must call the new helper
        and must NOT call supply.get_staked / supply.staked.values()
        directly for the stake-denominator read."""
        import inspect
        from messagechain.network.node import Node
        src = inspect.getsource(Node._handle_announce_attestation)
        self.assertIn(
            "resolve_pinned_attestation_stake", src,
            "_handle_announce_attestation must route the stake-"
            "denominator read through Blockchain.resolve_pinned_"
            "attestation_stake.",
        )
        # The bad reads must NOT remain in the handler body.
        self.assertNotIn(
            "supply.get_staked(att.validator_id)", src,
            "_handle_announce_attestation must NOT read live "
            "supply.get_staked(att.validator_id) — that's the bug.",
        )
        self.assertNotIn(
            "sum(self.blockchain.supply.staked.values())", src,
            "_handle_announce_attestation must NOT read live "
            "sum(supply.staked.values()) — that's the bug.",
        )

    def test_local_broadcast_path_routes_through_helper(self):
        """The local-attestation-broadcast path (when this node
        attests its own block) has the same defect class — it ALSO
        calls finality.add_attestation with live-read stake.  Same
        fix: route through the helper."""
        src = self._read_node_source()
        # The defective reads should not appear anywhere in node.py
        # alongside an ``add_attestation`` call.  Easiest way to pin
        # the absence: the live-stake patterns should not appear in
        # the whole file (both the gossip path and the local-
        # broadcast path were the only readers).
        self.assertNotIn(
            "self.blockchain.supply.get_staked(self.entity.entity_id)\n"
            "        total_stake = sum(self.blockchain.supply.staked.values())",
            src,
            "node.py local-broadcast path must route through "
            "Blockchain.resolve_pinned_attestation_stake, not read "
            "live supply.staked.",
        )

    def test_blockchain_apply_path_routes_through_helper(self):
        """Defensive: the apply path (`_process_attestations`) is
        already consensus-correct, but should also call the helper
        rather than open-coding the pinned-snapshot lookup.  This is
        what makes the abstraction load-bearing — there's one place to
        get this wrong, not two.
        """
        import inspect
        src = inspect.getsource(Blockchain._process_attestations)
        self.assertIn(
            "resolve_pinned_attestation_stake", src,
            "_process_attestations must route the stake-denominator "
            "read through Blockchain.resolve_pinned_attestation_stake "
            "so the apply path and the network-layer paths can't "
            "drift apart.",
        )


if __name__ == "__main__":
    unittest.main()
