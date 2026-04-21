"""Integration tests for archive-duty state-machine wiring.

Iteration 3b-ii: bolts the archive_duty primitives (3b-i) onto
Blockchain.  Specifically:

    * On block apply, track each validator's first-active block so
      bootstrap grace knows who's newly-onboarded.
    * When a challenge block lands (height % ARCHIVE_CHALLENGE_INTERVAL
      == 0, height > 0), capture the ActiveValidatorSnapshot from
      current supply.staked + compute_challenges().
    * When the submission window closes (height == snapshot.challenge_block
      + ARCHIVE_SUBMISSION_WINDOW), walk the bundles committed in the
      intervening blocks, run compute_miss_updates, fold into
      validator_archive_misses, and clear the snapshot.

Deliberately NOT in scope this iteration:
    * State-snapshot/state-root persistence for the new fields (lands
      together with reward-path withhold in 3b-iii so both changes
      can share a snapshot version bump).
    * Actual reward withholding.  Miss counters are observable but
      don't reduce any validator's payout yet.
"""

from __future__ import annotations

import unittest

import messagechain.config as _cfg
from messagechain.config import VALIDATOR_MIN_STAKE
from messagechain.consensus.archive_duty import ActiveValidatorSnapshot


# Shrink the challenge cadence for the duration of this module so
# multi-epoch integration tests fit in the test-profile WOTS+ leaf
# budget.  is_archive_challenge_block and _apply_archive_duty both
# read through messagechain.config at call time, so monkey-patching
# the module-level constants here flows through transparently.
#
# Original values restored in tearDownModule so this module does not
# contaminate downstream test discovery order.
_SAVED: dict = {}
_TEST_INTERVAL = 5
_TEST_WINDOW = 2


def setUpModule():
    # Capture the SITTING values at fixture-run time, not at module-
    # import time.  Other test modules (notably
    # test_archive_rewards_wiring) patch these same constants during
    # their own imports; tearing down to module-import-time values
    # clobbers their setup and fails their tests when they run after
    # ours.  Capturing inside setUpModule restores whatever was there
    # just before we ran, preserving sibling patches.
    _SAVED["cfg_interval"] = _cfg.ARCHIVE_CHALLENGE_INTERVAL
    _SAVED["cfg_window"] = _cfg.ARCHIVE_SUBMISSION_WINDOW
    _SAVED["cfg_grace"] = _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS
    grace_epochs = (
        _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS
        // max(_cfg.ARCHIVE_CHALLENGE_INTERVAL, 1)
    )
    _cfg.ARCHIVE_CHALLENGE_INTERVAL = _TEST_INTERVAL
    _cfg.ARCHIVE_SUBMISSION_WINDOW = _TEST_WINDOW
    _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS = grace_epochs * _TEST_INTERVAL
    # archive_challenge.py has its own module-level binding of the
    # same constants (from messagechain.config import ...).
    # test_archive_rewards_wiring patches this twin binding at its
    # import too; we do the same, then restore on tear-down.
    import messagechain.consensus.archive_challenge as _ac
    _SAVED["ac_interval"] = _ac.ARCHIVE_CHALLENGE_INTERVAL
    _SAVED["ac_window"] = _ac.ARCHIVE_SUBMISSION_WINDOW
    _ac.ARCHIVE_CHALLENGE_INTERVAL = _TEST_INTERVAL
    _ac.ARCHIVE_SUBMISSION_WINDOW = _TEST_WINDOW


def tearDownModule():
    _cfg.ARCHIVE_CHALLENGE_INTERVAL = _SAVED["cfg_interval"]
    _cfg.ARCHIVE_SUBMISSION_WINDOW = _SAVED["cfg_window"]
    _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS = _SAVED["cfg_grace"]
    import messagechain.consensus.archive_challenge as _ac
    _ac.ARCHIVE_CHALLENGE_INTERVAL = _SAVED["ac_interval"]
    _ac.ARCHIVE_SUBMISSION_WINDOW = _SAVED["ac_window"]


# Use the patched values throughout the tests so constants stay in
# sync with whatever setUpModule installed.
ARCHIVE_CHALLENGE_INTERVAL = _TEST_INTERVAL
ARCHIVE_SUBMISSION_WINDOW = _TEST_WINDOW


def _fresh_chain_with_validators(validator_count: int = 3):
    """Build a live Blockchain with N funded + staked validators.

    Returns (chain, validators_list, pos) — validators[0] is the
    genesis proposer (seed) and is the one we usually propose with.
    """
    from messagechain.identity.identity import Entity
    from messagechain.core.blockchain import Blockchain
    from messagechain.consensus.pos import ProofOfStake
    validators = [
        Entity.create(f"duty-v{i}".encode().ljust(32, b"\x00"))
        for i in range(validator_count)
    ]
    chain = Blockchain()
    chain.initialize_genesis(validators[0])
    # Register non-seed validators' pubkeys directly — simpler than
    # driving first-spend transfers through the full gate, and every
    # other test that needs multiple validators does the same.
    for v in validators:
        chain.public_keys[v.entity_id] = v.keypair.public_key
        chain.supply.balances[v.entity_id] = 10_000_000
        chain.supply.stake(v.entity_id, VALIDATOR_MIN_STAKE * 10)
    pos = ProofOfStake()
    return chain, validators, pos


def _propose_empty(chain, validators, pos):
    """Propose + apply an empty block from the chain-selected proposer.

    Auto-selects whichever validator is due this slot — round-robin /
    stake-weighted selection changes per slot, so tests need to ask
    the chain rather than hardcoding one entity.
    """
    latest = chain.chain[-1]
    selected_id = chain._selected_proposer_for_slot(latest, round_number=0)
    proposer = next(
        v for v in validators if v.entity_id == selected_id
    )
    block = chain.propose_block(pos, proposer, transactions=[])
    ok, reason = chain.add_block(block)
    assert ok, f"block rejected: {reason}"
    return block


def _advance_to_height(chain, validators, pos, target_height):
    """Fill blocks until chain's latest height == target_height."""
    while chain.chain[-1].header.block_number < target_height:
        _propose_empty(chain, validators, pos)


# ---------------------------------------------------------------------------
# 1. First-active-block tracking
# ---------------------------------------------------------------------------


class TestFirstActiveTracking(unittest.TestCase):
    def test_first_active_recorded_for_genesis_validators(self):
        """All validators with stake at genesis are tracked with
        first_active_block = 0 (or the first block we observe them).
        """
        chain, vals, pos = _fresh_chain_with_validators(3)
        # Drive one block so the apply pipeline observes them.
        _propose_empty(chain, vals, pos)
        for v in vals:
            self.assertIn(v.entity_id, chain.validator_first_active_block)

    def test_first_active_does_not_advance_on_subsequent_blocks(self):
        """Once recorded, the first_active block stays fixed — a
        long-tenured validator must not have their age reset by
        activity in later blocks.
        """
        chain, vals, pos = _fresh_chain_with_validators(2)
        _propose_empty(chain, vals, pos)
        first = dict(chain.validator_first_active_block)
        for _ in range(5):
            _propose_empty(chain, vals, pos)
        self.assertEqual(chain.validator_first_active_block, first)


# ---------------------------------------------------------------------------
# 2. Snapshot captured at challenge block
# ---------------------------------------------------------------------------


class TestSnapshotCapture(unittest.TestCase):
    def test_no_snapshot_before_first_challenge_block(self):
        """Blocks [1, ARCHIVE_CHALLENGE_INTERVAL) leave
        archive_active_snapshot at None — no challenge has fired yet.
        """
        chain, vals, pos = _fresh_chain_with_validators(2)
        _propose_empty(chain, vals, pos)
        self.assertIsNone(chain.archive_active_snapshot)

    def test_snapshot_captured_at_challenge_block(self):
        """When height lands on ARCHIVE_CHALLENGE_INTERVAL, a snapshot
        materializes carrying the current active set and K challenge
        heights.
        """
        chain, vals, pos = _fresh_chain_with_validators(2)
        _advance_to_height(chain, vals, pos, ARCHIVE_CHALLENGE_INTERVAL)
        snap = chain.archive_active_snapshot
        self.assertIsNotNone(snap)
        self.assertIsInstance(snap, ActiveValidatorSnapshot)
        self.assertEqual(snap.challenge_block, ARCHIVE_CHALLENGE_INTERVAL)
        self.assertGreater(len(snap.active_set), 0)
        self.assertGreater(len(snap.challenge_heights), 0)

    def test_snapshot_active_set_matches_staked_validators(self):
        """The active set captured must be exactly the staked
        validators at the challenge block (those >= VALIDATOR_MIN_STAKE).
        """
        chain, vals, pos = _fresh_chain_with_validators(3)
        _advance_to_height(chain, vals, pos, ARCHIVE_CHALLENGE_INTERVAL)
        expected = {
            eid for eid, amt in chain.supply.staked.items()
            if amt >= VALIDATOR_MIN_STAKE
        }
        self.assertEqual(set(chain.archive_active_snapshot.active_set), expected)


# ---------------------------------------------------------------------------
# 3. Epoch-close processing updates miss counter
# ---------------------------------------------------------------------------


class TestEpochClose(unittest.TestCase):
    def test_snapshot_cleared_after_submission_window(self):
        """Once height reaches challenge_block + ARCHIVE_SUBMISSION_WINDOW,
        the epoch-close processing runs and clears archive_active_snapshot
        (ready for the next challenge).
        """
        chain, vals, pos = _fresh_chain_with_validators(2)
        _advance_to_height(chain, vals, pos, ARCHIVE_CHALLENGE_INTERVAL)
        self.assertIsNotNone(chain.archive_active_snapshot)
        # Drive past the submission window.
        _advance_to_height(
            chain, vals, pos,
            ARCHIVE_CHALLENGE_INTERVAL + ARCHIVE_SUBMISSION_WINDOW,
        )
        self.assertIsNone(chain.archive_active_snapshot)

    def test_no_submissions_increments_misses_for_non_bootstrap(self):
        """A validator in the active set who is PAST the bootstrap
        grace window and submits no bundles during the window has
        their miss counter incremented at epoch close.
        """
        chain, vals, pos = _fresh_chain_with_validators(2)
        # Manually age the validators so grace is exhausted by the
        # time the first epoch closes.  first_active_block is set on
        # the first block that observes them; force it to a negative
        # age by overriding — the tracking dict is public state here.
        _propose_empty(chain, vals, pos)
        for v in vals:
            chain.validator_first_active_block[v.entity_id] = -1_000_000
        # Drive through a full challenge epoch (C..C+WINDOW).  No
        # custody proofs are included in any block, so every active
        # validator should be marked missed.
        _advance_to_height(
            chain, vals, pos,
            ARCHIVE_CHALLENGE_INTERVAL + ARCHIVE_SUBMISSION_WINDOW,
        )
        for v in vals:
            self.assertEqual(
                chain.validator_archive_misses.get(v.entity_id, 0),
                1,
                f"validator {v.entity_id.hex()[:8]} should have "
                "miss count 1 after one unserved epoch",
            )

    def test_bootstrap_grace_shields_new_validators(self):
        """Validators still in bootstrap grace accrue zero misses even
        with no submissions.  This is the design's concession to new
        operators that haven't had time to sync full history yet.
        """
        chain, vals, pos = _fresh_chain_with_validators(2)
        # Don't override first_active_block — validators enter at
        # genesis (first_active <= 1), and the grace window is 10 *
        # ARCHIVE_CHALLENGE_INTERVAL which covers the first epoch
        # boundary by construction.
        _advance_to_height(
            chain, vals, pos,
            ARCHIVE_CHALLENGE_INTERVAL + ARCHIVE_SUBMISSION_WINDOW,
        )
        for v in vals:
            self.assertEqual(
                chain.validator_archive_misses.get(v.entity_id, 0),
                0,
                f"validator {v.entity_id.hex()[:8]} should be "
                "bootstrap-exempt during its first epoch",
            )


# ---------------------------------------------------------------------------
# 4. Successive epochs accumulate
# ---------------------------------------------------------------------------


class TestAcrossEpochs(unittest.TestCase):
    def test_misses_accumulate_over_multiple_epochs(self):
        """Three consecutive empty epochs with aged-past-grace
        validators should produce miss_count == 3 for each — this is
        what drives the graduated reward withhold in 3b-iii.
        """
        chain, vals, pos = _fresh_chain_with_validators(2)
        _propose_empty(chain, vals, pos)
        for v in vals:
            chain.validator_first_active_block[v.entity_id] = -1_000_000
        # Three complete epochs.
        for epoch in range(1, 4):
            target = epoch * ARCHIVE_CHALLENGE_INTERVAL + ARCHIVE_SUBMISSION_WINDOW
            _advance_to_height(chain, vals, pos, target)
        for v in vals:
            self.assertEqual(
                chain.validator_archive_misses.get(v.entity_id, 0),
                3,
                f"validator {v.entity_id.hex()[:8]} should have "
                "miss count 3 after three unserved epochs",
            )


if __name__ == "__main__":
    unittest.main()
