"""Fork-emergency auto-recovery — closes the half-built recovery path.

Pre-fix: ``FORK_EMERGENCY_AUTO_RECOVERY`` was referenced in docstrings
(``messagechain/consensus/fork_emergency.py``,
``messagechain/core/blockchain.py:398``) and in the validator
auto-halt warning message, but the symbol was never defined in
``config.py`` and no rewind code path existed. CLAUDE.md anchors:

  > a node that ends up on a minority/unintentional fork must
  > auto-resync to the canonical chain with no manual state surgery
  > on the operator side, and must not accumulate slashable evidence
  > solely from being briefly on the wrong tip.

Validator auto-flip on a quorum-signal bug would weaponize the bug
into network-wide chain abandonment, so the recovery path is
deliberately full-node-only AND opt-in (default ``False``). This test
file pins the four contracts the wiring must satisfy:

  1. ``FORK_EMERGENCY_AUTO_RECOVERY`` exists in config and defaults
     to ``False`` (cautious-by-default).
  2. ``Blockchain.attempt_fork_emergency_recovery()`` rewinds the
     local chain to the height before the lowest active emergency,
     clearing the detector's flags so the syncer re-fetches forward.
  3. The recovery refuses to cross finality — a fork emergency that
     spans finalized blocks is a deeper consensus problem operator
     surgery (and slashing-evidence) must handle, not an automatic
     rewind.
  4. With no active emergency / emergency at-or-beyond tip / emergency
     at genesis, the method is a safe no-op.
"""

import unittest

from messagechain.consensus.fork_emergency import ForkEmergency
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


class ForkEmergencyAutoRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"fork-rec-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"fork-rec-bob".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"fork-rec-carol".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000
        self.chain.supply.balances[self.carol.entity_id] = 10_000
        self.chain.supply.stake(self.alice.entity_id, 1_000)
        self.chain.supply.stake(self.bob.entity_id, 1_000)
        self.chain.supply.stake(self.carol.entity_id, 1_000)
        self.consensus = ProofOfStake()

    def _all(self):
        return [self.alice, self.bob, self.carol]

    def _propose_block(self):
        proposer = pick_selected_proposer(self.chain, self._all())
        block = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        return block

    def _inject_emergency(self, height: int, supermajority_hash: bytes):
        """Synthesize an emergency state without going through the
        observe-vote machinery — keeps the test focused on the recovery
        contract."""
        det = self.chain.fork_emergency_detector
        local_hash = (
            self.chain.chain[height].block_hash
            if 0 <= height < len(self.chain.chain)
            else None
        )
        det._emergencies[height] = ForkEmergency(
            height=height,
            supermajority_hash=supermajority_hash,
            local_hash=local_hash,
            attested_stake=2_000,
            total_stake=3_000,
        )

    # ── 1. config flag ────────────────────────────────────────────────

    def test_config_flag_exists_and_defaults_false(self):
        from messagechain import config
        self.assertTrue(
            hasattr(config, "FORK_EMERGENCY_AUTO_RECOVERY"),
            "FORK_EMERGENCY_AUTO_RECOVERY must be defined in "
            "messagechain.config — referenced by docstrings in "
            "fork_emergency.py and blockchain.py since 1.55.x",
        )
        self.assertFalse(
            config.FORK_EMERGENCY_AUTO_RECOVERY,
            "default must be False — auto-flip on a quorum-signal "
            "bug would weaponize the bug into network-wide chain "
            "abandonment; opt-in only",
        )

    # ── 2. happy path: rewind clears emergency ────────────────────────

    def test_rewind_to_pre_emergency_height_clears_flags(self):
        # Build a 5-block chain. Inject an emergency at height 2 with a
        # divergent supermajority hash. Recovery should rewind to
        # height 1 and clear the emergency.
        self._propose_block()  # height 1
        self._propose_block()  # height 2
        self._propose_block()  # height 3
        self._propose_block()  # height 4
        self._propose_block()  # height 5
        self.assertEqual(len(self.chain.chain), 6)  # genesis + 5

        divergent = b"\xee" * 32
        self._inject_emergency(height=2, supermajority_hash=divergent)
        self.assertTrue(self.chain.fork_emergency_detector.is_in_emergency())

        ok, reason = self.chain.attempt_fork_emergency_recovery()
        self.assertTrue(ok, reason)
        # Tip is now height 1 (= emergency.height - 1); blocks 2..5
        # were rolled back so the syncer re-fetches the canonical chain.
        self.assertEqual(len(self.chain.chain), 2)  # genesis + height 1
        self.assertFalse(
            self.chain.fork_emergency_detector.is_in_emergency()
        )

    # ── 3. finality is the hard floor on auto-recovery ────────────────

    def test_refuses_to_cross_finality(self):
        # Propose a block, then emulate it being finalized via
        # FinalityCheckpoints. Recovery must refuse rather than rewind
        # past it — finality is the protocol-level commitment we will
        # not retract automatically; this case requires manual review.
        block1 = self._propose_block()
        self._propose_block()
        self._propose_block()

        # Pin block1 as finalized via the persistent-finality layer.
        self.chain.finalized_checkpoints.finalized_hashes.add(
            block1.block_hash
        )
        self.chain.finalized_checkpoints.finalized_by_height[
            block1.header.block_number
        ] = block1.block_hash

        divergent = b"\xee" * 32
        self._inject_emergency(height=1, supermajority_hash=divergent)

        chain_len_before = len(self.chain.chain)
        ok, reason = self.chain.attempt_fork_emergency_recovery()
        self.assertFalse(ok)
        self.assertIn("finaliz", reason.lower())
        # Chain is unchanged — operator must investigate manually.
        self.assertEqual(len(self.chain.chain), chain_len_before)
        # Emergency flag remains so the validator stays halted until
        # manually cleared.
        self.assertTrue(
            self.chain.fork_emergency_detector.is_in_emergency()
        )

    # ── 4. safe no-ops ────────────────────────────────────────────────

    def test_no_op_when_no_emergency(self):
        self._propose_block()
        self._propose_block()
        chain_len_before = len(self.chain.chain)
        ok, reason = self.chain.attempt_fork_emergency_recovery()
        self.assertFalse(ok)
        self.assertIn("no active", reason.lower())
        self.assertEqual(len(self.chain.chain), chain_len_before)

    def test_no_op_when_emergency_at_or_beyond_tip(self):
        # If the supermajority signed a block at a height we don't
        # have yet, normal sync handles it — no rewind needed.
        self._propose_block()
        self._propose_block()
        divergent = b"\xee" * 32
        self._inject_emergency(
            height=len(self.chain.chain) + 5,
            supermajority_hash=divergent,
        )
        chain_len_before = len(self.chain.chain)
        ok, reason = self.chain.attempt_fork_emergency_recovery()
        self.assertFalse(ok)
        self.assertEqual(len(self.chain.chain), chain_len_before)

    def test_no_op_when_emergency_at_genesis(self):
        # Cannot rewind below genesis — block 0 is the chain identity.
        self._propose_block()
        divergent = b"\xee" * 32
        self._inject_emergency(height=0, supermajority_hash=divergent)
        chain_len_before = len(self.chain.chain)
        ok, reason = self.chain.attempt_fork_emergency_recovery()
        self.assertFalse(ok)
        self.assertEqual(len(self.chain.chain), chain_len_before)


if __name__ == "__main__":
    unittest.main()
