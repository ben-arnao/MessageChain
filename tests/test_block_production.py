"""
Tests for the block production fixes:

#1 Round-based proposer rotation (liveness when validator is offline)
#2 RANDAO mix wired into proposer selection (grinding resistance)
#3 Empty-block heartbeat (chain doesn't halt with empty mempool)
#4 Slot-based scheduling (shared clock across nodes)
#5 Shared block_producer module (no duplication between server.py / node.py)
#6 Bootstrap threshold (chain doesn't exit bootstrap with 1 validator)
"""

import time
import unittest

import messagechain.config
from messagechain.config import HASH_ALGO, BLOCK_TIME_TARGET, VALIDATOR_MIN_STAKE
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.mempool import Mempool
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.randao import derive_randao_mix
from messagechain.consensus import block_producer
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _make_chain_with_validators(num_validators: int):
    """Create a chain with `num_validators` registered+staked validators."""
    entities = [
        Entity.create(f"validator_{i}_key".encode().ljust(32, b"\x00"))
        for i in range(num_validators)
    ]
    chain = Blockchain()
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)

    consensus = ProofOfStake()
    for e in entities:
        chain.supply.balances[e.entity_id] = chain.supply.balances.get(e.entity_id, 0) + 5000
        chain.supply.stake(e.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[e.entity_id] = VALIDATOR_MIN_STAKE
    return chain, consensus, entities


# ─── #2: RANDAO is wired into the actual block path ─────────────────

class TestRandaoIntegration(unittest.TestCase):
    """The RANDAO machinery must actually feed into proposer selection
    via the chain's stored mix — not just exist as dead test code."""

    def test_block_header_carries_randao_mix(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        block = chain.propose_block(consensus, entities[0], [])
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        # randao_mix must be derived (non-zero) and bound to the parent's mix
        self.assertNotEqual(block.header.randao_mix, b"\x00" * 32)

    def test_randao_mix_is_chained_block_to_block(self):
        """Each block's randao_mix must depend on the parent's mix."""
        chain, consensus, entities = _make_chain_with_validators(1)
        b1 = chain.propose_block(consensus, entities[0], [])
        chain.add_block(b1)
        b2 = chain.propose_block(consensus, entities[0], [])
        chain.add_block(b2)
        self.assertNotEqual(b1.header.randao_mix, b2.header.randao_mix)

    def test_randao_mismatch_rejected(self):
        """A block whose randao_mix wasn't derived from parent + signature
        must be rejected by validate_block."""
        chain, consensus, entities = _make_chain_with_validators(1)
        block = chain.propose_block(consensus, entities[0], [])
        # Tamper: set a wrong randao_mix
        block.header.randao_mix = b"\xff" * 32
        block.block_hash = block._compute_hash()
        ok, reason = chain.add_block(block)
        self.assertFalse(ok)
        self.assertIn("randao", reason.lower())

    def test_select_proposer_uses_randao_mix(self):
        """select_proposer must produce different results for different
        randao_mix values when there are enough validators."""
        consensus = ProofOfStake()
        # Create distinct validator IDs deterministically
        for i in range(20):
            consensus.stakes[bytes([i]) * 32] = 100

        prev = b"\x42" * 32
        seen = set()
        for i in range(10):
            mix = _hash(f"mix_{i}".encode())
            seen.add(consensus.select_proposer(prev, randao_mix=mix))
        self.assertGreater(len(seen), 1, "different randao mixes must produce different proposers")


# ─── #1: Round-based proposer rotation ──────────────────────────────

class TestRoundRotation(unittest.TestCase):
    """A different round_number must produce a different proposer
    (with sufficient validators), so an offline round-0 proposer can be
    bypassed by waiting for round 1."""

    def test_round_number_changes_proposer_selection(self):
        consensus = ProofOfStake()
        for i in range(20):
            consensus.stakes[bytes([i]) * 32] = 100

        prev = b"\x07" * 32
        mix = _hash(b"some_mix")
        seen = set()
        for r in range(10):
            seen.add(consensus.select_proposer(prev, randao_mix=mix, round_number=r))
        self.assertGreater(len(seen), 1, "round rotation must reach different validators")

    def test_round_zero_is_default_when_unspecified(self):
        consensus = ProofOfStake()
        for i in range(10):
            consensus.stakes[bytes([i]) * 32] = 100
        prev = b"\xab" * 32
        a = consensus.select_proposer(prev)
        b = consensus.select_proposer(prev, round_number=0)
        self.assertEqual(a, b)


# ─── #4: Slot-based scheduling ──────────────────────────────────────

class TestSlotScheduling(unittest.TestCase):
    """compute_slot must align to parent.timestamp + BLOCK_TIME_TARGET
    rather than a per-node local timer."""

    def test_slot_not_due_before_block_time_target(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        latest = chain.get_latest_block()
        # Just after parent: definitely not due
        slot = block_producer.compute_slot(latest, now=latest.header.timestamp + 1)
        self.assertFalse(slot.is_due)
        self.assertEqual(slot.round_number, 0)

    def test_slot_due_at_block_time_target(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        latest = chain.get_latest_block()
        slot = block_producer.compute_slot(latest, now=latest.header.timestamp + BLOCK_TIME_TARGET)
        self.assertTrue(slot.is_due)
        self.assertEqual(slot.round_number, 0)

    def test_round_advances_after_each_block_time_target(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        latest = chain.get_latest_block()
        # 2.5 slot windows after the parent's slot start → round 2
        now = latest.header.timestamp + BLOCK_TIME_TARGET * 3 + 1
        slot = block_producer.compute_slot(latest, now=now)
        self.assertTrue(slot.is_due)
        self.assertEqual(slot.round_number, 2)

    def test_should_propose_returns_false_before_slot(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        latest = chain.get_latest_block()
        ok, _r, reason = block_producer.should_propose(
            chain, consensus, entities[0].entity_id,
            now=latest.header.timestamp + 1,
        )
        self.assertFalse(ok)
        self.assertIn("not due", reason)

    def test_should_propose_returns_true_when_selected_at_slot(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        latest = chain.get_latest_block()
        ok, _r, _reason = block_producer.should_propose(
            chain, consensus, entities[0].entity_id,
            now=latest.header.timestamp + BLOCK_TIME_TARGET + 1,
        )
        self.assertTrue(ok)


# ─── #3: Empty-block heartbeat ──────────────────────────────────────

class TestEmptyBlockHeartbeat(unittest.TestCase):
    """The chain must produce blocks even when the mempool is empty,
    so attestations + finality + block-denominated timers continue."""

    def test_empty_block_is_valid(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        block = chain.propose_block(consensus, entities[0], [])
        self.assertEqual(len(block.transactions), 0)
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_chain_advances_through_empty_blocks(self):
        chain, consensus, entities = _make_chain_with_validators(1)
        starting_height = chain.height
        for _ in range(5):
            block = chain.propose_block(consensus, entities[0], [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)
        self.assertEqual(chain.height, starting_height + 5)


# ─── #5: Shared block_producer helper ───────────────────────────────

class TestSharedProducerHelper(unittest.TestCase):
    """Both server.py and network/node.py must call into the shared
    helper rather than duplicating timing/rotation logic."""

    def test_node_imports_block_producer(self):
        import messagechain.network.node as node_mod
        import inspect
        src = inspect.getsource(node_mod.Node._block_production_loop)
        self.assertIn("block_producer", src)

    def test_server_imports_block_producer(self):
        import server as server_mod
        import inspect
        src = inspect.getsource(server_mod.Server._block_production_loop)
        self.assertIn("block_producer", src)


# ─── #6: Bootstrap exit threshold ───────────────────────────────────

class TestBootstrapThreshold(unittest.TestCase):
    """The chain must not exit bootstrap mode with a single validator —
    that would create an immediate single point of failure."""

    def test_single_validator_stays_in_bootstrap_when_threshold_high(self):
        original = messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        try:
            messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 4
            consensus = ProofOfStake()
            consensus.register_validator(b"\x01" * 32, 1000)
            self.assertTrue(consensus.is_bootstrap_mode,
                            "1 validator must not exit a 4-validator threshold")
        finally:
            messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = original

    def test_threshold_validators_exits_bootstrap(self):
        original = messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        try:
            messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 4
            consensus = ProofOfStake()
            for i in range(4):
                consensus.register_validator(bytes([i]) * 32, 1000)
            self.assertFalse(consensus.is_bootstrap_mode,
                             "4 validators must exit the 4-validator threshold")
        finally:
            messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = original

    def test_bootstrap_exit_is_one_way(self):
        """Once we exit bootstrap, removing validators must not put us back."""
        original = messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        try:
            messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 4
            consensus = ProofOfStake()
            for i in range(4):
                consensus.register_validator(bytes([i]) * 32, 1000)
            self.assertFalse(consensus.is_bootstrap_mode)
            for i in range(3):
                consensus.remove_validator(bytes([i]) * 32)
            # Still out of bootstrap (one-way flag)
            self.assertFalse(consensus.is_bootstrap_mode)
        finally:
            messagechain.config.MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = original


# ─── Strict proposer validation in validate_block ───────────────────

class TestStrictProposerValidation(unittest.TestCase):
    """validate_block must reject a block whose proposer_id is not the
    deterministically-selected one for the slot.

    Without this check, any registered validator could claim to be the
    proposer for any slot, making the round rotation fix inert — an
    attacker with valid keys could steal blocks, censor honest proposers
    by racing them, and defeat the RANDAO leaf-consumption cost."""

    def test_wrong_proposer_rejected(self):
        """A block proposed by a registered validator who isn't the
        selected proposer must be rejected."""
        chain, consensus, entities = _make_chain_with_validators(3)

        latest = chain.get_latest_block()
        selected_id = chain._selected_proposer_for_slot(latest, round_number=0)
        self.assertIsNotNone(selected_id)

        # Find a validator who is NOT the selected one
        wrong_proposer = next(e for e in entities if e.entity_id != selected_id)

        block = consensus.create_block(wrong_proposer, [], latest)
        ok, reason = chain.add_block(block)
        self.assertFalse(ok)
        self.assertIn("Wrong proposer", reason)

    def test_selected_proposer_accepted(self):
        """A block proposed by the deterministically-selected proposer
        must validate cleanly."""
        from tests import pick_selected_proposer
        chain, consensus, entities = _make_chain_with_validators(3)

        proposer = pick_selected_proposer(chain, entities)
        block = chain.propose_block(consensus, proposer, [])
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_round_rotation_allows_alternate_proposer(self):
        """After rounds elapse, a *different* validator must be able to
        propose. This is the liveness escape hatch: if the round-0 proposer
        is offline, the round-1 proposer can step in once BLOCK_TIME_TARGET
        seconds have elapsed past the slot start.

        Checks that _selected_proposer_for_slot returns a different entity
        at higher rounds when there's enough validator diversity."""
        chain, consensus, entities = _make_chain_with_validators(5)
        latest = chain.get_latest_block()

        seen = set()
        for r in range(10):
            selected = chain._selected_proposer_for_slot(latest, round_number=r)
            if selected:
                seen.add(selected)
        self.assertGreater(len(seen), 1,
                           "round rotation must reach different validators with 5 staked")

    def test_no_enforcement_in_bootstrap(self):
        """When no one has staked, any registered proposer is allowed."""
        entities = [
            Entity.create(f"boot_{i}_key".encode().ljust(32, b"\x00"))
            for i in range(3)
        ]
        chain = Blockchain()
        chain.initialize_genesis(entities[0])
        for e in entities[1:]:
            register_entity_for_test(chain, e)
        # NOT staking anyone → bootstrap mode, no enforcement
        consensus = ProofOfStake()

        # Any of the registered entities can propose (propose_block computes
        # the correct state_root automatically).
        for proposer in entities:
            block = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, f"bootstrap must allow {proposer.entity_id.hex()[:8]}: {reason}")

    def test_early_timestamp_rejected_with_enforcement_on(self):
        """When ENFORCE_SLOT_TIMING is True, a block with a timestamp less
        than BLOCK_TIME_TARGET after the parent must be rejected."""
        original = messagechain.config.ENFORCE_SLOT_TIMING
        try:
            messagechain.config.ENFORCE_SLOT_TIMING = True
            chain, consensus, entities = _make_chain_with_validators(1)
            latest = chain.get_latest_block()
            proposer = entities[0]  # only one staked, so always selected

            # Propose with a timestamp just after the parent (way too early)
            block = consensus.create_block(
                proposer, [], latest,
                state_root=chain.compute_post_state_root([], proposer.entity_id, 1),
                timestamp=latest.header.timestamp + 1,
            )
            ok, reason = chain.add_block(block)
            self.assertFalse(ok)
            self.assertIn("too early", reason.lower())
        finally:
            messagechain.config.ENFORCE_SLOT_TIMING = original

    def test_on_time_timestamp_accepted_with_enforcement_on(self):
        """Block timestamped at parent + BLOCK_TIME_TARGET must be accepted."""
        original = messagechain.config.ENFORCE_SLOT_TIMING
        try:
            messagechain.config.ENFORCE_SLOT_TIMING = True
            chain, consensus, entities = _make_chain_with_validators(1)
            latest = chain.get_latest_block()
            proposer = entities[0]

            block = consensus.create_block(
                proposer, [], latest,
                state_root=chain.compute_post_state_root([], proposer.entity_id, 1),
                timestamp=latest.header.timestamp + BLOCK_TIME_TARGET + 1,
            )
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)
        finally:
            messagechain.config.ENFORCE_SLOT_TIMING = original


# ─── M6: RANDAO grinding stake floor ────────────────────────────────

class TestGrindingStakeFloor(unittest.TestCase):
    """Audit finding M6: RANDAO grinding must be economically bounded by
    stake. A low-stake validator can re-sign the block header (consuming
    WOTS+ leaves) to grind the randao_mix for favorable future proposer
    selection.  The per-grind cost (a WOTS+ leaf) is only de-minimis
    relative to the expected grinding payoff if the validator's stake
    is small enough that grinding ROI > 0.

    `should_propose` must therefore refuse to let a sub-VALIDATOR_MIN_STAKE
    validator propose even if the raw `consensus.select_proposer`
    function picked them (consensus.select_proposer has no min-stake
    filter — it is a pure stake-weighted lottery).  This stops grinding
    at the eligibility gate: no propose, no signature, no mix contribution.
    """

    def test_one_token_validator_cannot_propose(self):
        """A validator with 1 token (well below VALIDATOR_MIN_STAKE=100)
        must NOT be allowed to propose, even if they are the only
        registered validator and `consensus.select_proposer` picks them."""
        entity = Entity.create(b"low_stake_validator_key".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(entity)

        # Register validator with only 1 token — far below
        # VALIDATOR_MIN_STAKE (100) and below any reasonable grinding
        # cost floor.
        consensus = ProofOfStake()
        consensus.stakes[entity.entity_id] = 1  # bypass register_validator's
                                                # own min-stake check
        chain.supply.balances[entity.entity_id] = 1000
        chain.supply.stake(entity.entity_id, 1)

        latest = chain.get_latest_block()

        # Sanity: consensus.select_proposer (no min-stake filter) WILL
        # pick this validator — it is the only staker.
        selected = consensus.select_proposer(
            latest.block_hash,
            randao_mix=latest.header.randao_mix,
            round_number=0,
        )
        self.assertEqual(selected, entity.entity_id,
                         "raw stake-weighted lottery should pick the only staker")

        # But should_propose MUST refuse — the validator's stake is
        # below the grinding-resistance floor.
        ok, _round, reason = block_producer.should_propose(
            chain, consensus, entity.entity_id,
            now=latest.header.timestamp + BLOCK_TIME_TARGET + 1,
        )
        self.assertFalse(ok,
            f"1-token validator must not be allowed to propose "
            f"(grinding ROI would be positive); got reason={reason!r}")
        self.assertIn("stake", reason.lower())

    def test_validator_at_min_stake_can_propose(self):
        """A validator who meets VALIDATOR_MIN_STAKE remains eligible —
        this is the baseline case that must still work after the fix."""
        chain, consensus, entities = _make_chain_with_validators(1)
        latest = chain.get_latest_block()
        ok, _round, _reason = block_producer.should_propose(
            chain, consensus, entities[0].entity_id,
            now=latest.header.timestamp + BLOCK_TIME_TARGET + 1,
        )
        self.assertTrue(ok)

    def test_below_min_stake_validator_not_eligible_at_any_round(self):
        """The min-stake floor applies across ALL rounds — otherwise a
        grinder can simply wait for a later round to bypass it."""
        entity = Entity.create(b"low_stake_validator_key_2".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(entity)
        consensus = ProofOfStake()
        consensus.stakes[entity.entity_id] = 5  # sub-minimum
        chain.supply.balances[entity.entity_id] = 1000
        chain.supply.stake(entity.entity_id, 5)

        latest = chain.get_latest_block()
        for r in range(10):
            now = latest.header.timestamp + BLOCK_TIME_TARGET * (r + 1) + 1
            ok, _round, _reason = block_producer.should_propose(
                chain, consensus, entity.entity_id, now=now,
            )
            self.assertFalse(ok,
                f"1-token validator must not propose at any round, "
                f"but got ok=True at round {r}")


if __name__ == "__main__":
    unittest.main()
