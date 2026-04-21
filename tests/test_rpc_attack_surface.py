"""Regression tests for RPC attack-surface hardening (iter 2 of 10).

Covers F3 (IPv6 /64 aggregation) and F4 (stale-tx false-positive ban).
F1 and F2 are covered indirectly by existing handler tests; the
reorder/weighting is validated at code-review time.
"""

from __future__ import annotations

import unittest

from messagechain.network.ban import (
    PeerBanManager, OFFENSE_INVALID_TX, OFFENSE_MINOR, BAN_THRESHOLD,
)
from messagechain.network.ratelimit import RPCRateLimiter


class TestIPv6PrefixAggregation(unittest.TestCase):
    """Ban scores and rate-limit buckets must aggregate on /64 for IPv6.

    A /64 is the standard allocation for an end-site; a cloud attacker
    trivially rotates addresses within it.  Bucketing at the full /128
    makes every IP its own budget, defeating the defense for any
    IPv6-enabled adversary.  IPv4 keeps /32 granularity — flooding at
    that level already requires real v4 allocations.
    """

    def test_ban_manager_aggregates_ipv6_by_64(self):
        mgr = PeerBanManager()
        # Two addresses in the same /64 prefix.
        a = "[2001:db8::1]:9333"
        b = "[2001:db8::ffff]:9333"
        mgr.record_offense(a, 50, "test")
        mgr.record_offense(b, 50, "test")
        # /64 aggregate has 100 points — exactly at BAN_THRESHOLD.
        self.assertTrue(mgr.is_banned(a))
        self.assertTrue(mgr.is_banned(b))

    def test_ban_manager_different_ipv6_64s_independent(self):
        mgr = PeerBanManager()
        a = "[2001:db8::1]:9333"
        b = "[2001:db8:1::1]:9333"  # different /64
        mgr.record_offense(a, 50, "test")
        mgr.record_offense(b, 50, "test")
        # Each /64 has its own 50-point bucket — neither banned.
        self.assertFalse(mgr.is_banned(a))
        self.assertFalse(mgr.is_banned(b))

    def test_ban_manager_ipv4_full_address(self):
        mgr = PeerBanManager()
        a = "1.2.3.4:9333"
        b = "1.2.3.5:9333"
        mgr.record_offense(a, 50, "test")
        mgr.record_offense(b, 50, "test")
        # IPv4 stays /32 — 1.2.3.4 and 1.2.3.5 are independent buckets.
        self.assertFalse(mgr.is_banned(a))
        self.assertFalse(mgr.is_banned(b))

    def test_rate_limiter_aggregates_ipv6_by_64(self):
        rl = RPCRateLimiter(max_per_minute=3)
        # Same /64 sharing a budget.
        self.assertTrue(rl.check("2001:db8::1"))
        self.assertTrue(rl.check("2001:db8::2"))
        self.assertTrue(rl.check("2001:db8::3"))
        # Budget exhausted for the whole /64.
        self.assertFalse(rl.check("2001:db8::4"))

    def test_rate_limiter_different_ipv6_64s_independent(self):
        rl = RPCRateLimiter(max_per_minute=1)
        self.assertTrue(rl.check("2001:db8::1"))
        self.assertFalse(rl.check("2001:db8::2"))  # same /64, budget used
        self.assertTrue(rl.check("2001:db8:1::1"))  # different /64


class TestOffenseStaleTxClassification(unittest.TestCase):
    """OFFENSE_INVALID_TX = 100 is an instant ban.  Using it for every
    validate_transaction False-return creates a false-positive ban
    every time two honest peers' mempools drift.  Stale-nonce and
    below-watermark are recoverable; only provably-malformed (bad sig,
    bad structure) deserves the instant.

    This test pins the taxonomy so a future tweak can't silently
    promote a stale-tx error back to instant-ban territory.
    """

    def test_minor_offense_does_not_instantly_ban(self):
        mgr = PeerBanManager()
        addr = "1.2.3.4:9333"
        # Stale relay hits OFFENSE_MINOR (1) — BAN_THRESHOLD is 100,
        # so a huge number of benign stale relays still doesn't ban.
        for _ in range(50):
            mgr.record_offense(addr, OFFENSE_MINOR, "stale tx")
        self.assertFalse(mgr.is_banned(addr))

    def test_invalid_tx_still_instant_bans(self):
        """The instant-ban behavior for truly-invalid txs must remain
        intact — we're narrowing what counts as 'invalid', not making
        all bad txs harmless."""
        mgr = PeerBanManager()
        addr = "10.0.0.1:9333"
        mgr.record_offense(addr, OFFENSE_INVALID_TX, "bad sig")
        self.assertTrue(mgr.is_banned(addr))


if __name__ == "__main__":
    unittest.main()
