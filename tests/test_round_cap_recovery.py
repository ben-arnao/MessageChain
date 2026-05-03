"""Regression: a chain that has been stalled for an extreme number of
rounds must still be able to produce and accept the next block.

Background: ``MAX_PROPOSER_FALLBACK_ROUNDS`` historically conflated two
different concerns:

  1. Grinding defense — bound how many fallback rounds a malicious
     proposer can claim past the parent by inflating ``block.timestamp``.
  2. Recovery time — implicitly cap how long a stall the chain can
     self-heal from once a fix lands (because the natural producer-side
     timestamp on the recovery block computes a ``round_number``
     proportional to the wall-clock gap from the stale parent).

The grinding concern is already fully covered by ``MAX_BLOCK_FUTURE_DRIFT``
plus the ``block.timestamp >= parent.timestamp + BLOCK_TIME_TARGET`` rule:
the maximum extra round a malicious proposer can claim above what an
honest proposer would claim is ``MAX_BLOCK_FUTURE_DRIFT / BLOCK_TIME_TARGET
= 120 / 600 = 0`` rounds. A separate per-block round cap therefore adds
zero grinding defense but DOES bound recovery — every stall longer than
``cap × BLOCK_TIME_TARGET`` becomes self-perpetuating because the
producer's first natural recovery block gets rejected as
"timestamp-skew slot hijacking".

History of the cap drift:
  * 1.0 — cap = 5  (covered "missed a few slots", insufficient for stalls)
  * 1.26.2 — cap raised to 100 after a ~2h chain-stall
  * 1.47.1 — cap raised to 10_000 after the 1309 stall (24h+, counter at ~157)

Each raise was reactive. This test pins the property the cap drift was
chasing — long stalls must self-heal — so future changes can preserve
the property without a third re-raise.
"""

from __future__ import annotations

import unittest

import messagechain.config
from messagechain.config import BLOCK_TIME_TARGET
from messagechain.consensus.pos import ProofOfStake
from tests import pick_selected_proposer
from tests.test_block_production import _make_chain_with_validators


class TestRoundCapRecovery(unittest.TestCase):
    """After a long stall, the chain must accept the next legitimate block.

    Sets a parent timestamp 100_000 BLOCK_TIME_TARGET windows in the past
    (≈ 700 days at 600s blocks, beyond any plausible operational stall)
    and asserts the natural recovery block proposed and validated against
    that parent is accepted. Pre-fix this fails with "Proposer round N
    exceeds cap".
    """

    def setUp(self):
        # Force ENFORCE_SLOT_TIMING on so the round-cap rule (and the
        # min-gap rule it lives next to) actually fires. The test suite
        # otherwise pins this False to allow synthetic block construction.
        self._prior_enforce = messagechain.config.ENFORCE_SLOT_TIMING
        messagechain.config.ENFORCE_SLOT_TIMING = True

    def tearDown(self):
        messagechain.config.ENFORCE_SLOT_TIMING = self._prior_enforce

    def test_long_stall_recovery_block_accepted(self):
        chain, consensus, entities = _make_chain_with_validators(2)

        # Anchor the parent 100_000 slot windows in the past — well beyond
        # the historical 10_000 cap. This is the recovery scenario: the
        # chain has been quiet for a very long time and the next honest
        # producer's natural ``timestamp = now`` choice computes a huge
        # round_number relative to the stale parent.
        latest = chain.get_latest_block()
        from unittest.mock import patch
        import time as _time
        simulated_now = _time.time()
        latest.header.timestamp = simulated_now - BLOCK_TIME_TARGET * 100_000

        proposer = pick_selected_proposer(chain, entities)

        # The recovery block's timestamp is "now" — exactly what an honest
        # validator coming back online after a stall would pick. The
        # ts_gap from parent is ~100_000 × BLOCK_TIME_TARGET, which under
        # the legacy 10_000 cap rejects with "Proposer round N exceeds cap".
        with patch("time.time", return_value=simulated_now), \
             patch(
                 "messagechain.core.blockchain._time.time",
                 return_value=simulated_now,
             ):
            block = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(block)

        self.assertTrue(
            ok,
            f"Long-stall recovery block must be accepted; got rejection: "
            f"{reason}. The round-cap should not bound recovery time — "
            f"grinding defense is covered by MAX_BLOCK_FUTURE_DRIFT.",
        )


if __name__ == "__main__":
    unittest.main()
