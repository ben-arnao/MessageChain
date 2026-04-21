"""seed_initial_stakes must survive state-snapshot encode/decode.

The bug this test file closes (discovered during pre-launch audit):

    Blockchain.seed_initial_stakes is a dict[bytes, int] captured ONCE
    at the first divestment block (H = SEED_DIVESTMENT_START + 1) from
    the then-current per-seed stake.  Every subsequent divestment block
    decrements staked by `initial / WINDOW` until END.

    The dict is correctly included in _snapshot_memory_state (for
    reorg-safe rollback), but until this fix was NOT persisted by
    encode_snapshot / decode_snapshot / compute_state_root (the
    snapshot commitment used by state-checkpoint fast-sync).

    Consequence: a node that state-syncs from a checkpoint at height
    H where START < H < END would install an empty seed_initial_stakes.
    The next divestment block re-captures the *post-divestment* stake
    as the "initial" reference, so its per-block decrement diverges
    from replaying nodes — a silent consensus fork persisting the
    entire divestment window.

    This is the canonical "consensus-visible state field not yet in
    the snapshot commitment" bug.  Security-critical and load-bearing
    even though the fast-sync path is not yet wired into the mainnet
    launch: a single state-synced node hitting the next divestment
    block would fork itself off the canonical chain until END.

These tests exercise the fix end-to-end: the dict round-trips through
encode_snapshot/decode_snapshot, _install_state_snapshot restores it,
and two chains (one replaying, one state-synced) stay in lockstep
across divestment blocks.
"""

import unittest

import messagechain.config as config
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import (
    bootstrap_seed_local,
    build_launch_allocation,
    RECOMMENDED_STAKE_PER_SEED,
)
from messagechain.identity.identity import Entity
from messagechain.storage.state_snapshot import (
    serialize_state,
    deserialize_state,
    encode_snapshot,
    decode_snapshot,
    compute_state_root as compute_snapshot_root,
)


# Legacy-schedule coverage: push SEED_DIVESTMENT_RETUNE_HEIGHT past this
# file's simulated range so pre-retune params apply throughout.
_ORIG_RETUNE_HEIGHT = config.SEED_DIVESTMENT_RETUNE_HEIGHT


def setUpModule():
    config.SEED_DIVESTMENT_RETUNE_HEIGHT = 10 ** 9


def tearDownModule():
    config.SEED_DIVESTMENT_RETUNE_HEIGHT = _ORIG_RETUNE_HEIGHT


TREASURY = config.TREASURY_ENTITY_ID
START = config.SEED_DIVESTMENT_START_HEIGHT
END = config.SEED_DIVESTMENT_END_HEIGHT
WINDOW = END - START


def _entity(tag: bytes) -> Entity:
    return Entity.create(tag.ljust(32, b"\x00"))


def _bootstrapped_chain() -> tuple[Blockchain, Entity, Entity]:
    """Build a single-seed chain with RECOMMENDED_STAKE_PER_SEED locked."""
    seed = _entity(b"div-snap-seed")
    cold = _entity(b"div-snap-cold")
    allocation = build_launch_allocation([seed.entity_id])
    chain = Blockchain()
    chain.initialize_genesis(seed, allocation_table=allocation)
    ok, log = bootstrap_seed_local(
        chain, seed,
        cold_authority_pubkey=cold.public_key,
        stake_amount=RECOMMENDED_STAKE_PER_SEED,
    )
    assert ok, "\n".join(log)
    return chain, seed, cold


def _advance_divestment(chain: Blockchain, start_h: int, end_h: int) -> None:
    """Apply divestment steps for heights [start_h, end_h] inclusive."""
    for h in range(start_h, end_h + 1):
        chain._apply_seed_divestment(h)


class TestSeedInitialStakesRoundTrip(unittest.TestCase):
    """encode_snapshot / decode_snapshot must preserve seed_initial_stakes."""

    def test_serialize_state_includes_seed_initial_stakes(self):
        """serialize_state pulls seed_initial_stakes into the dict."""
        chain, seed, _ = _bootstrapped_chain()
        # Before any divestment: dict is empty but the key must still exist.
        snap = serialize_state(chain)
        self.assertIn("seed_initial_stakes", snap)
        self.assertEqual(snap["seed_initial_stakes"], {})

        # After first divestment: seed's initial stake is captured.
        chain._apply_seed_divestment(START + 1)
        snap = serialize_state(chain)
        self.assertIn("seed_initial_stakes", snap)
        self.assertEqual(
            snap["seed_initial_stakes"][seed.entity_id],
            RECOMMENDED_STAKE_PER_SEED,
        )

    def test_deserialize_state_default_empty_dict(self):
        """A snapshot missing the field defaults to an empty dict."""
        from messagechain.storage.state_snapshot import STATE_SNAPSHOT_VERSION
        snap = deserialize_state({"version": STATE_SNAPSHOT_VERSION})
        self.assertIn("seed_initial_stakes", snap)
        self.assertEqual(snap["seed_initial_stakes"], {})
        # seed_divestment_debt also defaults empty for pre-v2 callers.
        self.assertIn("seed_divestment_debt", snap)
        self.assertEqual(snap["seed_divestment_debt"], {})

    def test_encode_decode_round_trip_empty(self):
        """Pre-divestment: dict is empty and still round-trips."""
        chain, _seed, _ = _bootstrapped_chain()
        snap = serialize_state(chain)
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(decoded["seed_initial_stakes"], {})

    def test_encode_decode_round_trip_post_capture(self):
        """After first divestment block: dict round-trips with the captured value."""
        chain, seed, _ = _bootstrapped_chain()
        _advance_divestment(chain, START + 1, START + 10)
        snap = serialize_state(chain)
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(
            decoded["seed_initial_stakes"][seed.entity_id],
            RECOMMENDED_STAKE_PER_SEED,
        )

    def test_determinism_same_state_same_bytes(self):
        """Two serializations of the same state encode byte-identically."""
        chain, _seed, _ = _bootstrapped_chain()
        _advance_divestment(chain, START + 1, START + 50)
        blob1 = encode_snapshot(serialize_state(chain))
        blob2 = encode_snapshot(serialize_state(chain))
        self.assertEqual(blob1, blob2)


class TestStateRootCommitsToSeedInitialStakes(unittest.TestCase):
    """The snapshot state-root MUST cover seed_initial_stakes.

    Otherwise two nodes can silently disagree on the dict without a
    root mismatch — exactly the silent-fork scenario.  A change to the
    dict must change the root.
    """

    def test_root_changes_when_seed_initial_stakes_changes(self):
        chain, seed, _ = _bootstrapped_chain()
        chain._apply_seed_divestment(START + 1)
        snap = serialize_state(chain)
        root_before = compute_snapshot_root(snap)

        # Mutate the dict only (keep the rest of state byte-equal) — the
        # root must change.
        mutated = dict(snap)
        mutated["seed_initial_stakes"] = dict(snap["seed_initial_stakes"])
        mutated["seed_initial_stakes"][seed.entity_id] = (
            mutated["seed_initial_stakes"][seed.entity_id] + 1
        )
        root_after = compute_snapshot_root(mutated)

        self.assertNotEqual(
            root_before, root_after,
            "snapshot state root does NOT commit to seed_initial_stakes — "
            "silent consensus fork risk across state-sync boundary",
        )

    def test_root_changes_when_seed_key_added(self):
        """Adding an entry to seed_initial_stakes must move the root."""
        chain, _seed, _ = _bootstrapped_chain()
        snap = serialize_state(chain)
        # Baseline: empty dict.
        root_empty = compute_snapshot_root(snap)

        mutated = dict(snap)
        mutated["seed_initial_stakes"] = {b"\xAB" * 32: 12345}
        root_with_entry = compute_snapshot_root(mutated)
        self.assertNotEqual(root_empty, root_with_entry)


class TestInstallStateSnapshotRestoresDict(unittest.TestCase):
    """_install_state_snapshot must populate blockchain.seed_initial_stakes."""

    def test_install_populates_dict(self):
        chain_a, seed, _ = _bootstrapped_chain()
        _advance_divestment(chain_a, START + 1, START + 10)
        snap_a = serialize_state(chain_a)
        blob = encode_snapshot(snap_a)
        decoded = decode_snapshot(blob)

        # Fresh chain: install decoded snapshot directly.  Don't go
        # through bootstrap_from_checkpoint (which needs full
        # signature/block machinery) — _install_state_snapshot is the
        # pure state-reconstruction step we want to exercise.
        chain_b = Blockchain()
        # Seeds are pinned in initialize_genesis; for the install path
        # the caller is expected to already know them (they are part of
        # the per-block header fields — block 0 of the recent_blocks
        # chain or prior agreement).  For this test we replicate the
        # pinning so the advance path below exercises divestment.
        chain_b.seed_entity_ids = frozenset(chain_a.seed_entity_ids)
        chain_b._install_state_snapshot(decoded)

        self.assertEqual(
            chain_b.seed_initial_stakes,
            chain_a.seed_initial_stakes,
        )
        self.assertEqual(
            chain_b.seed_initial_stakes[seed.entity_id],
            RECOMMENDED_STAKE_PER_SEED,
        )


class TestReplayVsStateSyncLockstep(unittest.TestCase):
    """The consensus-fork regression test.

    Build chain A, advance past the first divestment block, snapshot it,
    rebuild chain B from the snapshot.  Then run both chains through
    the same divestment schedule.  Their staked/total_supply/treasury
    must stay byte-equal for every block in the window.

    Before the fix: chain B has an empty seed_initial_stakes on install;
    its next divestment block re-captures from the *post-divestment*
    stake and decrements by a smaller per-block value, diverging from
    A immediately at the next divestment block.

    After the fix: the dict round-trips through the snapshot and both
    chains agree at every step.
    """

    def _install_into_fresh(self, chain_a):
        snap = serialize_state(chain_a)
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        chain_b = Blockchain()
        chain_b.seed_entity_ids = frozenset(chain_a.seed_entity_ids)
        chain_b._install_state_snapshot(decoded)
        return chain_b

    def _assert_states_equal(self, a, b, seed_id):
        self.assertEqual(
            a.supply.get_staked(seed_id), b.supply.get_staked(seed_id),
        )
        self.assertEqual(a.supply.total_supply, b.supply.total_supply)
        self.assertEqual(
            a.supply.get_balance(TREASURY), b.supply.get_balance(TREASURY),
        )
        self.assertEqual(a.seed_initial_stakes, b.seed_initial_stakes)

    def test_snapshot_mid_divestment_then_one_more_block(self):
        """Snapshot at START+10, advance both by one divestment block, states match."""
        chain_a, seed, _ = _bootstrapped_chain()
        _advance_divestment(chain_a, START + 1, START + 10)
        chain_b = self._install_into_fresh(chain_a)

        # Both chains take the next divestment block.
        h = START + 11
        chain_a._apply_seed_divestment(h)
        chain_b._apply_seed_divestment(h)
        self._assert_states_equal(chain_a, chain_b, seed.entity_id)

    def test_snapshot_mid_divestment_advance_100_more_blocks(self):
        """100 more divestment blocks stay in lockstep."""
        chain_a, seed, _ = _bootstrapped_chain()
        _advance_divestment(chain_a, START + 1, START + 10)
        chain_b = self._install_into_fresh(chain_a)

        for h in range(START + 11, START + 111):
            chain_a._apply_seed_divestment(h)
            chain_b._apply_seed_divestment(h)
            self._assert_states_equal(chain_a, chain_b, seed.entity_id)

    def test_snapshot_before_first_capture(self):
        """Snapshot at H=START (pre-capture).  Both chains independently
        capture the same initial stake on their next divestment step."""
        chain_a, seed, _ = _bootstrapped_chain()
        # Pre-capture: no divestment has fired yet.
        self.assertEqual(chain_a.seed_initial_stakes, {})
        chain_b = self._install_into_fresh(chain_a)
        self.assertEqual(chain_b.seed_initial_stakes, {})

        # Now both advance to the first divestment block independently.
        chain_a._apply_seed_divestment(START + 1)
        chain_b._apply_seed_divestment(START + 1)

        # Each chain independently captured the same initial stake
        # because they started from identical per-seed staked balances.
        self.assertEqual(
            chain_a.seed_initial_stakes, chain_b.seed_initial_stakes,
        )
        self._assert_states_equal(chain_a, chain_b, seed.entity_id)

    def test_snapshot_after_divestment_complete(self):
        """Snapshot taken AFTER END: dict is fully populated, stake at floor."""
        from messagechain.config import SEED_DIVESTMENT_RETAIN_FLOOR
        chain_a, seed, _ = _bootstrapped_chain()
        _advance_divestment(chain_a, START + 1, END)
        # Sanity: stake ≈ FLOOR (within 1 token of fractional-accounting
        # residual — see _apply_seed_divestment docstring).
        residual = chain_a.supply.get_staked(seed.entity_id)
        self.assertGreaterEqual(residual, SEED_DIVESTMENT_RETAIN_FLOOR)
        self.assertLess(residual, SEED_DIVESTMENT_RETAIN_FLOOR + 2)
        self.assertEqual(
            chain_a.seed_initial_stakes[seed.entity_id],
            RECOMMENDED_STAKE_PER_SEED,
        )

        chain_b = self._install_into_fresh(chain_a)
        self.assertEqual(
            chain_b.seed_initial_stakes, chain_a.seed_initial_stakes,
        )
        self._assert_states_equal(chain_a, chain_b, seed.entity_id)

        # Post-END steps are no-ops on both chains.
        for h in (END + 1, END + 100, 400_000):
            chain_a._apply_seed_divestment(h)
            chain_b._apply_seed_divestment(h)
            self._assert_states_equal(chain_a, chain_b, seed.entity_id)


if __name__ == "__main__":
    unittest.main()
