"""IPv6 bucketing alignment between addrman and ban (R2-#5).

addrman previously grouped IPv6 peers by /48 while the ban manager masked
to /64. A sybil attacker with a single /48 could rotate across /64s within
it to share one addrman per-source bucket while defeating ban aggregation
across the same range. Aligning both to /64 matches Bitcoin Core's
established bucketing and closes the sybil gap.
"""

import ipaddress
import unittest

from messagechain.network.addrman import AddressManager, _network_group
from messagechain.network.ban import _normalize_ip_for_bucket
from messagechain.config import ADDRMAN_MAX_PER_SOURCE


class TestIPv6NetworkGroupAt64(unittest.TestCase):
    """addrman._network_group buckets IPv6 by /64, not /48."""

    def test_same_64_shares_group(self):
        # Both addresses are in 2001:db8:1:2::/64 — same /64 bucket.
        a = _network_group("2001:db8:1:2::1")
        b = _network_group("2001:db8:1:2::ffff")
        self.assertEqual(a, b)

    def test_different_64_within_same_48_differs(self):
        # Same /48 (2001:db8:1::/48) but different /64s. Under the old
        # /48 bucketing these collided; under /64 they must not.
        a = _network_group("2001:db8:1:2::1")
        b = _network_group("2001:db8:1:3::1")
        self.assertNotEqual(a, b)


class TestPerSourceBudgetNotSharedAcross64(unittest.TestCase):
    """Two source IPs in distinct /64s (same /48) must have independent
    per-source add budgets. Under the old /48 grouping they would share
    one ADDRMAN_MAX_PER_SOURCE budget."""

    def test_distinct_64s_get_distinct_budgets(self):
        am = AddressManager(secret_key=b"\x00" * 32)
        src_a = "2001:db8:1:2::1"  # /64 = 2001:db8:1:2
        src_b = "2001:db8:1:3::1"  # /64 = 2001:db8:1:3 (different /64, same /48)

        # Saturate source A's budget with public addresses.
        # Use distinct public /64s for the *advertised* addresses so the
        # new-table bucket doesn't fill before the per-source cap trips.
        added_a = 0
        for i in range(ADDRMAN_MAX_PER_SOURCE):
            # Vary the /64 of the advertised address (not the source).
            ip = f"2a00:1450:{i:x}::1"
            if am.add_address(ip, 9333, src_a):
                added_a += 1
        # Source A should be at its cap — next add from src_a is rejected.
        self.assertFalse(
            am.add_address("2a00:1450:ffff::1", 9333, src_a),
            "source A should be capped",
        )

        # Source B is a different /64 — its budget must be independent.
        ok = am.add_address("2a01:4f8:1::1", 9333, src_b)
        self.assertTrue(
            ok,
            "distinct /64 source must have its own per-source budget",
        )


class TestAddrmanAndBanAgreeOnIPv6Grouping(unittest.TestCase):
    """Both modules must agree that two addresses in the same /64 are
    'one peer group' and two in different /64s are not."""

    def _addrs_in_same_64(self):
        return ("2001:db8:1:2::1", "2001:db8:1:2::ffff")

    def _addrs_in_different_64(self):
        return ("2001:db8:1:2::1", "2001:db8:1:3::1")

    def test_same_64_aggregated_by_both(self):
        a, b = self._addrs_in_same_64()
        # addrman: same group string.
        self.assertEqual(_network_group(a), _network_group(b))
        # ban: same /64 network.
        self.assertEqual(_normalize_ip_for_bucket(a), _normalize_ip_for_bucket(b))

    def test_different_64_split_by_both(self):
        a, b = self._addrs_in_different_64()
        # addrman: different group strings.
        self.assertNotEqual(_network_group(a), _network_group(b))
        # ban: different /64 networks.
        self.assertNotEqual(
            _normalize_ip_for_bucket(a),
            _normalize_ip_for_bucket(b),
        )

    def test_grouping_consistent_shape_for_ipv6(self):
        # Sanity: for any pair of IPv6 addresses, addrman's "same group"
        # verdict matches ban's "same bucket" verdict. This is the
        # load-bearing invariant the fix establishes.
        pairs = [
            ("2001:db8:1:2::1", "2001:db8:1:2::2"),      # same /64
            ("2001:db8:1:2::1", "2001:db8:1:3::1"),      # different /64, same /48
            ("2001:db8:1:2::1", "2001:db8:2:2::1"),      # different /48
            ("2a00:1450::1", "2a00:1450::2"),            # same /64 (::/64)
        ]
        for a, b in pairs:
            addrman_same = _network_group(a) == _network_group(b)
            ban_same = (
                _normalize_ip_for_bucket(a) == _normalize_ip_for_bucket(b)
            )
            self.assertEqual(
                addrman_same,
                ban_same,
                f"addrman/ban disagree on ({a}, {b}): "
                f"addrman_same={addrman_same} ban_same={ban_same}",
            )


if __name__ == "__main__":
    unittest.main()
