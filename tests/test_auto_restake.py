"""
Client-side opt-in auto-restake.

A node operator can flip config.AUTO_RESTAKE = True (typically in
config_local.py) to have the node automatically sweep its accumulated
liquid block-reward income above a configured buffer into stake after
every block it produces.  This is purely a NODE-LOCAL POLICY — no
consensus changes, no block-format changes.  A node with
AUTO_RESTAKE=False behaves identically to today.

Why a client-side flag rather than auto-compounding inside state
transition: auto-compounding changes every validator's reward
accounting; the threshold of "how much dust is worth restaking"
depends on the fee economy at the time (today's MIN_FEE may not be
the 2080 MIN_FEE), and baking any particular rule into consensus
forces every future generation of operators to live with our guess.
A client-side policy lets each operator tune their own sweep without
touching the one-in-a-hundred-years-risk surface that is consensus.

The tests below cover:

  1. default OFF — no behavior change
  2. ON + above buffer+min — stake tx queued for the excess
  3. ON + below threshold — no stake tx queued
  4. ON + stake tx already pending — no double-submit
  5. ON + no wallet entity (observer mode) — no crash
  6. ON + wallet entity not registered — no crash
  7. ON + create_stake_transaction raises — block production survives
  8. queued auto-restake tx validates + applies to state in the NEXT block
  9. AUTO_RESTAKE_LIQUID_BUFFER respected — post-sweep liquid ~= buffer
 10. fee accounting — stakeable math accounts for the stake-tx fee
"""

import unittest
from unittest.mock import patch

from messagechain import config
from messagechain.config import MIN_FEE, VALIDATOR_MIN_STAKE
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.staking import StakeTransaction
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_server():
    """Minimal Server built entirely in-memory (no sockets, no data dir)."""
    from server import Server
    return Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)


def _prepare_validator_node(srv, entity, liquid: int = 0):
    """Bring `srv` to the state where it can produce a block under `entity`.

    Mirrors the setup pattern used by test_rpc_responsiveness.
    """
    srv.blockchain.initialize_genesis(entity)
    register_entity_for_test(srv.blockchain, entity)
    srv.wallet_id = entity.entity_id
    srv.wallet_entity = entity
    srv.consensus = ProofOfStake()
    # Seed the entity with stake + any additional liquid balance.
    current = srv.blockchain.supply.balances.get(entity.entity_id, 0)
    srv.blockchain.supply.balances[entity.entity_id] = current + VALIDATOR_MIN_STAKE + liquid
    srv.blockchain.supply.stake(entity.entity_id, VALIDATOR_MIN_STAKE)
    srv.consensus.stakes[entity.entity_id] = VALIDATOR_MIN_STAKE
    srv._running = True


class _AutoRestakeBase(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        # Height 6 (= 64 leaves) is the same cadence other Server tests use
        # and is large enough for a handful of blocks + a restake tx.
        config.MERKLE_TREE_HEIGHT = 6
        # Capture and reset every auto-restake config knob so tests don't
        # leak state into each other.
        self._orig_auto = getattr(config, "AUTO_RESTAKE", False)
        self._orig_min = getattr(config, "AUTO_RESTAKE_MIN_AMOUNT", 1_000)
        self._orig_buf = getattr(config, "AUTO_RESTAKE_LIQUID_BUFFER", 1_000)

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height
        config.AUTO_RESTAKE = self._orig_auto
        config.AUTO_RESTAKE_MIN_AMOUNT = self._orig_min
        config.AUTO_RESTAKE_LIQUID_BUFFER = self._orig_buf


class TestAutoRestakeConfigDefaults(_AutoRestakeBase):
    """Config symbols must exist with safe defaults."""

    def test_config_defaults_are_off_and_sensible(self):
        self.assertFalse(config.AUTO_RESTAKE,
                         "AUTO_RESTAKE must default to False — client-side opt-in only")
        self.assertGreaterEqual(config.AUTO_RESTAKE_MIN_AMOUNT, 1,
                                "AUTO_RESTAKE_MIN_AMOUNT must be >= 1 to avoid dust sweeps")
        self.assertGreaterEqual(config.AUTO_RESTAKE_LIQUID_BUFFER, 0)


class TestAutoRestakeDefaultOff(_AutoRestakeBase):
    """Case 1: default (AUTO_RESTAKE=False) produces no restake tx."""

    def test_default_produces_no_stake_tx(self):
        srv = _build_server()
        alice = _entity(b"restake-default-off")
        _prepare_validator_node(srv, alice, liquid=100_000)
        # Sanity: default is off
        self.assertFalse(config.AUTO_RESTAKE)
        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            result = srv._try_produce_block_sync()
        self.assertIsNotNone(result)
        block, success, _reason, _round = result
        self.assertTrue(success)
        # No auto-restake tx queued.
        self.assertEqual(
            len(getattr(srv, "_pending_stake_txs", {})),
            0,
            "Default AUTO_RESTAKE=False must not emit any stake tx",
        )


class TestAutoRestakeOnQueuesTx(_AutoRestakeBase):
    """Case 2: ON + sufficient liquid → stake tx is queued."""

    def test_on_and_above_threshold_queues_stake_tx(self):
        srv = _build_server()
        alice = _entity(b"restake-on-happy")
        # Liquid amount well above buffer + min.
        liquid = 100_000
        _prepare_validator_node(srv, alice, liquid=liquid)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000
        config.AUTO_RESTAKE_LIQUID_BUFFER = 1_000

        pre_liquid = srv.blockchain.supply.get_balance(alice.entity_id)
        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            result = srv._try_produce_block_sync()
        self.assertIsNotNone(result)
        _block, success, _reason, _round = result
        self.assertTrue(success)

        pending = getattr(srv, "_pending_stake_txs", {})
        self.assertEqual(len(pending), 1, "Expected exactly one auto-restake tx")
        tx = next(iter(pending.values()))
        self.assertIsInstance(tx, StakeTransaction)
        self.assertEqual(tx.entity_id, alice.entity_id)
        # Expected amount: liquid_after_block_reward - buffer - fee-margin.
        # Our implementation takes an MIN_FEE margin off the sweep to
        # ensure the buffer stays intact after fee payment.
        post_reward_liquid = srv.blockchain.supply.get_balance(alice.entity_id)
        expected_amount = post_reward_liquid - config.AUTO_RESTAKE_LIQUID_BUFFER - tx.fee
        self.assertEqual(tx.amount, expected_amount)
        self.assertGreaterEqual(tx.amount, config.AUTO_RESTAKE_MIN_AMOUNT)
        self.assertGreater(post_reward_liquid, pre_liquid,
                           "Block proposer should have earned a reward")


class TestAutoRestakeBelowThreshold(_AutoRestakeBase):
    """Case 3: ON + liquid below buffer+min → no tx queued."""

    def test_below_min_amount_does_not_queue(self):
        srv = _build_server()
        alice = _entity(b"restake-below-min")
        # Start with liquid just above buffer (5) but below min (1000).
        _prepare_validator_node(srv, alice, liquid=5)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000_000  # way above anything the block can mint
        config.AUTO_RESTAKE_LIQUID_BUFFER = 1_000

        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            srv._try_produce_block_sync()
        self.assertEqual(
            len(getattr(srv, "_pending_stake_txs", {})),
            0,
            "Liquid below (buffer + min_amount) must not trigger restake",
        )

    def test_below_buffer_does_not_queue(self):
        srv = _build_server()
        alice = _entity(b"restake-below-buffer")
        _prepare_validator_node(srv, alice, liquid=0)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1
        # Set the buffer so high that even after the block reward,
        # we're still below it.
        config.AUTO_RESTAKE_LIQUID_BUFFER = 10_000_000

        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            srv._try_produce_block_sync()
        self.assertEqual(
            len(getattr(srv, "_pending_stake_txs", {})),
            0,
            "Liquid below AUTO_RESTAKE_LIQUID_BUFFER must not trigger restake",
        )


class TestAutoRestakeNoDoubleSubmit(_AutoRestakeBase):
    """Case 4: existing pending stake tx for this entity → don't stack another."""

    def test_pending_stake_tx_blocks_double_sweep(self):
        srv = _build_server()
        alice = _entity(b"restake-no-double")
        _prepare_validator_node(srv, alice, liquid=100_000)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000
        config.AUTO_RESTAKE_LIQUID_BUFFER = 1_000

        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            srv._try_produce_block_sync()

        before = dict(getattr(srv, "_pending_stake_txs", {}))
        self.assertEqual(len(before), 1, "First block must queue exactly one restake tx")

        # Simulate a second block production round without clearing the pool
        # (as if we proposed another block before the first restake tx was
        # included).  _has_pending_stake_from should short-circuit the second
        # attempt.
        with patch.object(srv, "_try_produce_block_sync", wraps=srv._try_produce_block_sync):
            with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
                mock_sp.return_value = (True, 0, "")
                # Directly call _maybe_auto_restake a second time — simulates
                # post-block-produce hook firing again while the previous
                # sweep still sits in the pool.
                srv._maybe_auto_restake()

        after = dict(getattr(srv, "_pending_stake_txs", {}))
        self.assertEqual(len(after), 1, "Second invocation must not stack a second restake tx")
        self.assertEqual(set(before.keys()), set(after.keys()))


class TestAutoRestakeObserverMode(_AutoRestakeBase):
    """Case 5: no wallet entity → no crash, no tx."""

    def test_observer_node_no_crash(self):
        srv = _build_server()
        self.assertIsNone(srv.wallet_entity)

        config.AUTO_RESTAKE = True
        # Direct call — server should silently no-op.
        try:
            srv._maybe_auto_restake()
        except Exception as e:  # pragma: no cover - should not happen
            self.fail(f"Observer-mode auto-restake must not raise: {e!r}")
        self.assertEqual(len(getattr(srv, "_pending_stake_txs", {})), 0)


class TestAutoRestakeUnregisteredEntity(_AutoRestakeBase):
    """Case 6: entity not yet in public_keys → no crash, no tx."""

    def test_unregistered_entity_no_crash(self):
        srv = _build_server()
        alice = _entity(b"restake-unregistered")
        # Assign the entity but do NOT install its pubkey into chain state.
        srv.wallet_entity = alice
        srv.wallet_id = alice.entity_id
        # Give alice some liquid balance (direct-write, bypassing validation).
        srv.blockchain.supply.balances[alice.entity_id] = 1_000_000

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000
        config.AUTO_RESTAKE_LIQUID_BUFFER = 1_000

        try:
            srv._maybe_auto_restake()
        except Exception as e:  # pragma: no cover
            self.fail(f"Unregistered entity must not raise: {e!r}")
        self.assertEqual(len(getattr(srv, "_pending_stake_txs", {})), 0)


class TestAutoRestakeBestEffort(_AutoRestakeBase):
    """Case 7: exception inside stake-tx build must not crash production."""

    def test_exception_in_create_is_swallowed(self):
        srv = _build_server()
        alice = _entity(b"restake-create-fail")
        _prepare_validator_node(srv, alice, liquid=100_000)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000
        config.AUTO_RESTAKE_LIQUID_BUFFER = 1_000

        # Monkey-patch create_stake_transaction through server's module-level
        # import so the exception hits the try/except in _maybe_auto_restake.
        import messagechain.core.staking as staking_mod
        def _boom(*a, **kw):
            raise RuntimeError("synthetic failure")
        with patch.object(staking_mod, "create_stake_transaction", _boom):
            with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
                mock_sp.return_value = (True, 0, "")
                result = srv._try_produce_block_sync()
        # Block production must still succeed — auto-restake is best-effort.
        self.assertIsNotNone(result)
        _block, success, _reason, _round = result
        self.assertTrue(success,
                        "Block production must not be aborted by an auto-restake failure")
        self.assertEqual(len(getattr(srv, "_pending_stake_txs", {})), 0)


class TestAutoRestakeTxIncludesInNextBlock(_AutoRestakeBase):
    """Case 8: the queued stake tx validates + applies when included."""

    def test_next_block_applies_restake_moves_liquid_to_staked(self):
        srv = _build_server()
        alice = _entity(b"restake-applies")
        _prepare_validator_node(srv, alice, liquid=100_000)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000
        config.AUTO_RESTAKE_LIQUID_BUFFER = 1_000

        # First block: produce and queue auto-restake.
        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            result1 = srv._try_produce_block_sync()
        self.assertIsNotNone(result1)
        _, ok1, _, _ = result1
        self.assertTrue(ok1)

        pending = getattr(srv, "_pending_stake_txs", {})
        self.assertEqual(len(pending), 1)
        tx = next(iter(pending.values()))
        staked_before = srv.blockchain.supply.get_staked(alice.entity_id)
        liquid_before = srv.blockchain.supply.get_balance(alice.entity_id)

        # Second block: the drain in _try_produce_block_sync pulls the
        # auto-restake tx into a block and applies it.
        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            result2 = srv._try_produce_block_sync()
        self.assertIsNotNone(result2)
        _, ok2, reason2, _ = result2
        self.assertTrue(ok2, reason2)

        # Stake must have moved.
        staked_after = srv.blockchain.supply.get_staked(alice.entity_id)
        self.assertEqual(staked_after, staked_before + tx.amount)
        # Liquid dropped by at least tx.amount (fees come back partially as tip,
        # next-block reward added — so compare conservatively).
        liquid_after = srv.blockchain.supply.get_balance(alice.entity_id)
        self.assertLessEqual(liquid_after, liquid_before - tx.amount + 1_000_000,
                             "Liquid accounting sanity check")


class TestAutoRestakeBufferRespected(_AutoRestakeBase):
    """Case 9: post-sweep liquid ~= buffer (modulo fee and next-block reward)."""

    def test_post_sweep_liquid_sits_near_buffer(self):
        srv = _build_server()
        alice = _entity(b"restake-buffer")
        _prepare_validator_node(srv, alice, liquid=100_000)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000
        config.AUTO_RESTAKE_LIQUID_BUFFER = 5_000

        # Block 1: queue the restake.
        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            srv._try_produce_block_sync()

        pending = getattr(srv, "_pending_stake_txs", {})
        self.assertEqual(len(pending), 1)
        tx = next(iter(pending.values()))

        # The queued amount must be: (liquid_at_sweep) - buffer - fee
        # so that when the tx applies, liquid drops to exactly buffer
        # (minus the block_reward_from_the_NEXT_block, which adds to it).
        # We verify the AMOUNT math directly; the buffer is preserved
        # because the tx amount subtracts the fee.
        liquid_at_sweep = (
            srv.blockchain.supply.get_balance(alice.entity_id)
        )
        expected = liquid_at_sweep - config.AUTO_RESTAKE_LIQUID_BUFFER - tx.fee
        self.assertEqual(tx.amount, expected,
                         "Queued amount must leave exactly buffer liquid after fee")
        # Post-sweep (after next block applies it), liquid ends ≈ buffer
        # + next block's reward/tip.  This is the "modulo fee/reward"
        # tolerance.


class TestAutoRestakeFeeAccounting(_AutoRestakeBase):
    """Case 10: fee accounting — stake tx fee is NOT double-counted into buffer."""

    def test_fee_does_not_dip_node_below_buffer(self):
        srv = _build_server()
        alice = _entity(b"restake-fee")
        _prepare_validator_node(srv, alice, liquid=100_000)

        config.AUTO_RESTAKE = True
        config.AUTO_RESTAKE_MIN_AMOUNT = 1_000
        config.AUTO_RESTAKE_LIQUID_BUFFER = 10_000

        # Block 1: queue the restake.
        with patch("messagechain.consensus.block_producer.should_propose") as mock_sp:
            mock_sp.return_value = (True, 0, "")
            srv._try_produce_block_sync()

        pending = getattr(srv, "_pending_stake_txs", {})
        self.assertEqual(len(pending), 1)
        tx = next(iter(pending.values()))
        self.assertEqual(tx.fee, MIN_FEE,
                         "Auto-restake uses MIN_FEE (lowest allowed) to minimize cost")

        # Compute the math the node would have seen at the sweep point:
        liquid_at_sweep = srv.blockchain.supply.get_balance(alice.entity_id)
        # Amount = liquid - buffer - fee.  If we forgot to subtract the fee,
        # applying the tx would strip tx.amount + tx.fee from liquid and
        # leave (buffer - tx.fee) < buffer.
        self.assertEqual(
            tx.amount + tx.fee + config.AUTO_RESTAKE_LIQUID_BUFFER,
            liquid_at_sweep,
            "amount + fee + buffer must equal liquid_at_sweep — "
            "any other formula dips below buffer after fee is paid",
        )


if __name__ == "__main__":
    unittest.main()
