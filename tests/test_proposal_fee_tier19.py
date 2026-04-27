"""Tier 19: proposal fee tightening + per-byte surcharge.

Tier 19 closes the size-amortization gap that let a max-sized proposal
pay <0.5 fee/byte (less than a typical message under any congestion).
Three coordinated levers, height-gated at PROPOSAL_FEE_TIER19_HEIGHT:

  1. Flat floor: GOVERNANCE_PROPOSAL_FEE 10_000 → 100_000.
  2. Per-byte surcharge: 50 tokens × payload_bytes (locks fee/byte).
  3. Tightened byte caps: title 400 → 200, description 20_000 → 2_000.

Tests cover:
  * Helper math (proposal_payload_bytes, proposal_fee_floor)
  * Pre-fork admission unchanged (legacy floor + legacy caps still admit)
  * Post-fork rejection of legacy-floor txs (10_000 below new floor)
  * Post-fork admission of correctly-priced txs (100_000 + 50*p)
  * Post-fork tightened byte caps reject between-old-and-new sizes
  * Symmetry: TreasurySpendTransaction follows the same rules
  * Per-byte invariant: post-fork fee/byte exceeds typical message
    fee/byte across the entire admissible payload range
"""

import unittest

from messagechain import config
from messagechain.config import (
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_PROPOSAL_FEE_TIER19,
    GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19,
    MARKET_FEE_FLOOR,
    MAX_PROPOSAL_TITLE_BYTES_TIER19,
    MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19,
    PROPOSAL_FEE_TIER19_HEIGHT,
)
from messagechain.governance.governance import (
    MAX_PROPOSAL_TITLE_BYTES,
    MAX_PROPOSAL_DESCRIPTION_BYTES,
    create_proposal,
    create_treasury_spend_proposal,
    proposal_fee_floor,
    proposal_payload_bytes,
    verify_proposal,
    verify_treasury_spend,
)
from messagechain.identity.identity import Entity


PRE = PROPOSAL_FEE_TIER19_HEIGHT - 1
POST = PROPOSAL_FEE_TIER19_HEIGHT


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


class TestHelpers(unittest.TestCase):
    """Helper-function math is the foundation everything else builds on."""

    def test_payload_bytes_counts_title_description_reference(self):
        alice = _entity(b"helper")
        alice.keypair._next_leaf = 0
        ref = b"\xAB" * 32
        tx = create_proposal(
            alice, "title", "description", reference_hash=ref, fee=10_000,
        )
        # 5 (title) + 11 (description) + 32 (reference_hash) = 48
        self.assertEqual(proposal_payload_bytes(tx), 5 + 11 + 32)

    def test_payload_bytes_treasury_spend_no_reference_field(self):
        alice = _entity(b"helper-tsp")
        alice.keypair._next_leaf = 0
        tx = create_treasury_spend_proposal(
            alice, recipient_id=b"\x42" * 32, amount=1,
            title="t", description="dd", fee=10_000,
        )
        # TreasurySpendTransaction has no reference_hash field; the
        # helper's getattr fallback must contribute 0 bytes.
        self.assertEqual(proposal_payload_bytes(tx), 1 + 2)

    def test_payload_bytes_utf8_emoji_amplification(self):
        alice = _entity(b"helper-emoji")
        alice.keypair._next_leaf = 0
        # "😀" is 4 UTF-8 bytes and 1 character.  The surcharge prices
        # bytes, not characters -- the whole point is to make the
        # emoji-amplification escape hatch carry its own weight.
        tx = create_proposal(alice, "😀", "😀😀", fee=10_000)
        self.assertEqual(proposal_payload_bytes(tx), 4 + 8)

    def test_floor_pre_fork_is_legacy_flat(self):
        self.assertEqual(proposal_fee_floor(0, PRE), GOVERNANCE_PROPOSAL_FEE)
        self.assertEqual(
            proposal_fee_floor(2_000, PRE), GOVERNANCE_PROPOSAL_FEE,
        )
        # Unknown height (None) also falls through to legacy.
        self.assertEqual(proposal_fee_floor(2_000, None), GOVERNANCE_PROPOSAL_FEE)

    def test_floor_post_fork_is_flat_plus_per_byte(self):
        self.assertEqual(
            proposal_fee_floor(0, POST), GOVERNANCE_PROPOSAL_FEE_TIER19,
        )
        self.assertEqual(
            proposal_fee_floor(100, POST),
            GOVERNANCE_PROPOSAL_FEE_TIER19
            + GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 * 100,
        )
        # Max-sized post-fork payload (~200 + 2000 + 32 ref).
        max_p = (
            MAX_PROPOSAL_TITLE_BYTES_TIER19
            + MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19
            + 32
        )
        expected = (
            GOVERNANCE_PROPOSAL_FEE_TIER19
            + GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 * max_p
        )
        self.assertEqual(proposal_fee_floor(max_p, POST), expected)


class TestPreForkAdmissionUnchanged(unittest.TestCase):
    """Pre-Tier-19: legacy floor + legacy caps still apply.

    Historical blocks must replay byte-for-byte under the rule that
    was current at their height, so anything that was admissible
    pre-fork must remain admissible at any height < the fork.
    """

    @classmethod
    def setUpClass(cls):
        cls.alice = _entity(b"prefork")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_legacy_flat_floor_admits_pre_fork(self):
        tx = create_proposal(
            self.alice, "t", "d", fee=GOVERNANCE_PROPOSAL_FEE,
            current_height=PRE,
        )
        self.assertTrue(
            verify_proposal(tx, self.alice.public_key, current_height=PRE),
        )

    def test_legacy_max_description_admits_pre_fork(self):
        # 10_000-char ASCII description (= 10_000 bytes) -- right at
        # the legacy MAX_PROPOSAL_DESCRIPTION_LENGTH char cap, well
        # under the 20_000-byte cap, but 5x the new Tier-19 byte cap.
        # Pre-fork: legal under both caps, fee=10_000 sufficient.
        long_desc = "a" * 10_000
        tx = create_proposal(
            self.alice, "t", long_desc,
            fee=GOVERNANCE_PROPOSAL_FEE, current_height=PRE,
        )
        self.assertTrue(
            verify_proposal(tx, self.alice.public_key, current_height=PRE),
        )

    def test_legacy_max_title_admits_pre_fork(self):
        # 200-char title at exactly the legacy length cap, fits inside
        # the legacy 400-byte cap.
        title = "a" * 200
        tx = create_proposal(
            self.alice, title, "ok",
            fee=GOVERNANCE_PROPOSAL_FEE, current_height=PRE,
        )
        self.assertTrue(
            verify_proposal(tx, self.alice.public_key, current_height=PRE),
        )


class TestPostForkFeeFloor(unittest.TestCase):
    """Post-Tier-19: flat floor raised to 100_000 + per-byte surcharge."""

    @classmethod
    def setUpClass(cls):
        cls.alice = _entity(b"postfork-fee")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_legacy_flat_floor_rejected_post_fork(self):
        # 10_000-fee tx that was fine pre-fork must be rejected post-fork.
        tx = create_proposal(
            self.alice, "t", "d",
            fee=GOVERNANCE_PROPOSAL_FEE, current_height=POST,
        )
        self.assertFalse(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )

    def test_new_flat_floor_admits_post_fork(self):
        # Auto-fee (None) computes the post-fork floor for us.
        tx = create_proposal(
            self.alice, "t", "d", fee=None, current_height=POST,
        )
        self.assertTrue(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )

    def test_one_below_new_floor_rejected(self):
        # Compute the exact required floor and submit at floor-1.
        title, desc = "t", "d"
        payload = (
            len(title.encode("utf-8")) + len(desc.encode("utf-8"))
        )
        floor = proposal_fee_floor(payload, POST)
        tx = create_proposal(
            self.alice, title, desc, fee=floor - 1, current_height=POST,
        )
        self.assertFalse(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )

    def test_per_byte_surcharge_scales_with_size(self):
        # A larger proposal must require strictly more fee than a
        # smaller one -- this is the per-byte surcharge biting.
        small_payload = 10
        large_payload = 1_000
        self.assertGreater(
            proposal_fee_floor(large_payload, POST),
            proposal_fee_floor(small_payload, POST),
        )
        # Specifically: difference equals 50 × byte difference.
        delta = (
            proposal_fee_floor(large_payload, POST)
            - proposal_fee_floor(small_payload, POST)
        )
        self.assertEqual(
            delta,
            GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19
            * (large_payload - small_payload),
        )


class TestPostForkByteCaps(unittest.TestCase):
    """Post-Tier-19: tightened title/description byte caps."""

    @classmethod
    def setUpClass(cls):
        cls.alice = _entity(b"postfork-caps")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def _fee_for(self, title: str, description: str) -> int:
        # Sized to comfortably exceed the post-fork floor so we can
        # isolate byte-cap rejections from fee-floor rejections.
        return proposal_fee_floor(
            len(title.encode("utf-8")) + len(description.encode("utf-8")),
            POST,
        )

    def test_title_at_new_byte_cap_admits(self):
        # 50 emojis × 4 bytes = 200 bytes (exactly the new cap), 50
        # chars (under the 200-char length cap).
        title = "😀" * 50
        desc = "ok"
        tx = create_proposal(
            self.alice, title, desc,
            fee=self._fee_for(title, desc), current_height=POST,
        )
        self.assertTrue(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )

    def test_title_one_byte_over_new_cap_rejected(self):
        # 51 emojis × 4 bytes = 204 bytes (over the 200-byte cap), 51
        # chars (still under the 200-char cap, so we isolate the
        # byte-cap rejection from the char-length rejection).
        title = "😀" * 51
        desc = "ok"
        tx = create_proposal(
            self.alice, title, desc,
            fee=self._fee_for(title, desc), current_height=POST,
        )
        self.assertFalse(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )

    def test_description_at_new_byte_cap_admits(self):
        title = "t"
        desc = "😀" * 500  # 2000 bytes, 500 chars
        tx = create_proposal(
            self.alice, title, desc,
            fee=self._fee_for(title, desc), current_height=POST,
        )
        self.assertTrue(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )

    def test_description_over_new_byte_cap_rejected(self):
        title = "t"
        desc = "😀" * 501  # 2004 bytes, 501 chars
        tx = create_proposal(
            self.alice, title, desc,
            fee=self._fee_for(title, desc), current_height=POST,
        )
        self.assertFalse(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )

    def test_legacy_admissible_description_rejected_post_fork(self):
        # 10_000-byte ASCII description: legal pre-fork (right at the
        # legacy char cap, well under the legacy 20_000 byte cap), 5x
        # over the new Tier-19 byte cap.  We pay the post-fork fee
        # floor for this size so the failure is provably the byte
        # cap, not the floor.
        title = "t"
        desc = "a" * 10_000
        tx = create_proposal(
            self.alice, title, desc,
            fee=self._fee_for(title, desc), current_height=POST,
        )
        self.assertFalse(
            verify_proposal(tx, self.alice.public_key, current_height=POST),
        )


class TestTreasurySpendSymmetry(unittest.TestCase):
    """TreasurySpendTransaction follows the same Tier 19 rules."""

    @classmethod
    def setUpClass(cls):
        cls.alice = _entity(b"tsp-tier19")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def _mk(self, title: str, description: str, fee: int | None,
            current_height: int):
        return create_treasury_spend_proposal(
            self.alice, recipient_id=b"\x42" * 32, amount=1_000,
            title=title, description=description, fee=fee,
            current_height=current_height,
        )

    def test_pre_fork_legacy_floor_admits(self):
        tx = self._mk("t", "d", GOVERNANCE_PROPOSAL_FEE, current_height=PRE)
        self.assertTrue(
            verify_treasury_spend(
                tx, self.alice.public_key, current_height=PRE,
            ),
        )

    def test_post_fork_legacy_floor_rejected(self):
        tx = self._mk("t", "d", GOVERNANCE_PROPOSAL_FEE, current_height=POST)
        self.assertFalse(
            verify_treasury_spend(
                tx, self.alice.public_key, current_height=POST,
            ),
        )

    def test_post_fork_new_floor_admits(self):
        tx = self._mk("t", "d", fee=None, current_height=POST)
        self.assertTrue(
            verify_treasury_spend(
                tx, self.alice.public_key, current_height=POST,
            ),
        )

    def test_post_fork_tightened_description_cap(self):
        title = "t"
        # Sit at byte cap + 1 via emoji so we isolate the byte rule.
        desc = "😀" * 501  # 2004 bytes
        floor = proposal_fee_floor(
            len(title.encode("utf-8")) + len(desc.encode("utf-8")),
            POST,
        )
        tx = self._mk(title, desc, fee=floor, current_height=POST)
        self.assertFalse(
            verify_treasury_spend(
                tx, self.alice.public_key, current_height=POST,
            ),
        )


class TestPerByteInvariant(unittest.TestCase):
    """The whole point: post-fork proposal fee/byte > typical message
    fee/byte across the entire admissible payload range.

    Typical message floor is MARKET_FEE_FLOOR = 1 token (flat,
    regardless of size, post-Tier-16); under congestion the EIP-1559
    base fee multiplies, but the protocol floor everyone always
    competes against starts at 1.
    """

    def test_floor_per_byte_exceeds_market_floor_at_max_size(self):
        max_p = (
            MAX_PROPOSAL_TITLE_BYTES_TIER19
            + MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19
            + 32
        )
        floor = proposal_fee_floor(max_p, POST)
        # Worst case for the invariant is the max-sized proposal
        # because that's where the flat floor amortizes thinnest.
        self.assertGreater(floor / max_p, MARKET_FEE_FLOOR)
        # And by a comfortable multiple (>10x) so that even modest
        # base-fee inflation on the message side keeps the ordering.
        self.assertGreater(floor / max_p, 10 * MARKET_FEE_FLOOR)

    def test_floor_per_byte_dominates_at_small_size(self):
        # Tiny payload: per-byte cost is dominated by the flat floor,
        # which gives the largest fee/byte ratio (best case for the
        # invariant).
        small_p = 2  # title="t", description="d"
        floor = proposal_fee_floor(small_p, POST)
        self.assertGreater(floor / small_p, 1_000 * MARKET_FEE_FLOOR)

    def test_floor_per_byte_monotone_decreasing_in_size(self):
        # Sanity: amortization makes per-byte cost shrink as size
        # grows (the flat term dilutes), but the per-byte surcharge
        # ensures it never crosses below MARKET_FEE_FLOOR.
        sizes = [10, 100, 500, 1_000, 2_000]
        per_byte = [proposal_fee_floor(s, POST) / s for s in sizes]
        for i in range(len(per_byte) - 1):
            self.assertGreater(per_byte[i], per_byte[i + 1])
        # Tail still well above MARKET_FEE_FLOOR.
        self.assertGreater(per_byte[-1], 10 * MARKET_FEE_FLOOR)


class TestForkOrdering(unittest.TestCase):
    """Tier 19 must activate strictly after Tier 17 and inside the
    bootstrap window -- both are config-load-time asserts, but a
    runtime sanity test catches any future edit that downgrades the
    ordering without re-running the import asserts.
    """

    def test_tier19_after_tier17(self):
        self.assertGreater(
            config.PROPOSAL_FEE_TIER19_HEIGHT,
            config.REACT_TX_HEIGHT,
        )

    def test_tier19_before_bootstrap_end(self):
        from messagechain.consensus.bootstrap_gradient import (
            BOOTSTRAP_END_HEIGHT,
        )
        self.assertLess(
            config.PROPOSAL_FEE_TIER19_HEIGHT, BOOTSTRAP_END_HEIGHT,
        )

    def test_tier19_byte_caps_tighten_legacy(self):
        self.assertLessEqual(
            MAX_PROPOSAL_TITLE_BYTES_TIER19, MAX_PROPOSAL_TITLE_BYTES,
        )
        self.assertLessEqual(
            MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19,
            MAX_PROPOSAL_DESCRIPTION_BYTES,
        )

    def test_tier19_floor_raises_legacy(self):
        self.assertGreater(
            GOVERNANCE_PROPOSAL_FEE_TIER19, GOVERNANCE_PROPOSAL_FEE,
        )


if __name__ == "__main__":
    unittest.main()
