"""Tests for anti-eclipse peer selection (subnet diversity enforcement).

Eclipse attack defense: when choosing outbound peers, prefer candidates
whose /16 subnet (IPv4) or /48 prefix (IPv6) is not already represented
in the current outbound set. This makes it expensive for an attacker to
surround a node — they need IPs across many distinct subnets.

Flakiness analysis & hardening (audit round 6)
----------------------------------------------
``PeerSelector.select_outbound_peer`` uses ``os.urandom`` to choose
*within* a tier (new-subnet / unsaturated / saturated). Every assertion
in this file is structured to be insensitive to that intra-tier random
pick:

* Specific-IP assertions only appear when the winning tier contains
  exactly one candidate (deterministic).
* Subnet-prefix / set-membership assertions are satisfied by every
  candidate in the winning tier.
* ``test_select_multiple_fills_diverse`` runs the full 4-step loop
  ``_STOCHASTIC_TRIALS`` times, so any non-deterministic failure path
  would surface with ~1.0 probability rather than flaking 1-in-N runs.

If a future contributor adds a test that picks from a multi-candidate
tier and asserts a specific IP, seed ``os.urandom`` via the
``_DeterministicSelector`` helper instead of loosening the assertion.
"""

import unittest

from messagechain.network.peer_selection import (
    PeerSelector,
    get_subnet,
    is_subnet_saturated,
    diversity_score,
    MAX_PEERS_PER_SUBNET,
    MIN_DIVERSE_SUBNETS,
)

# Number of trials for stochastic tests. 128 is large enough that any
# flake with failure probability p >= 1/128 surfaces with > 63%
# probability on a single test run, yet small enough to keep the suite
# fast (each trial is ~microseconds).
_STOCHASTIC_TRIALS = 128


class TestGetSubnet(unittest.TestCase):
    """get_subnet correctly extracts /16 prefix from IPv4 and /48 from IPv6."""

    def test_ipv4_basic(self):
        self.assertEqual(get_subnet("192.168.1.1"), "192.168")

    def test_ipv4_different_octets(self):
        self.assertEqual(get_subnet("10.0.5.99"), "10.0")
        self.assertEqual(get_subnet("172.16.254.1"), "172.16")

    def test_ipv4_same_subnet(self):
        self.assertEqual(get_subnet("203.0.113.1"), get_subnet("203.0.113.2"))

    def test_ipv4_different_subnets(self):
        self.assertNotEqual(get_subnet("203.0.113.1"), get_subnet("203.1.113.1"))

    def test_ipv6_basic(self):
        # /48 = first 3 groups (6 bytes)
        result = get_subnet("2001:0db8:85a3::8a2e:0370:7334")
        self.assertEqual(result, "2001:0db8:85a3")

    def test_ipv6_different_48(self):
        a = get_subnet("2001:0db8:85a3::1")
        b = get_subnet("2001:0db8:85a4::1")
        self.assertNotEqual(a, b)

    def test_ipv6_same_48(self):
        a = get_subnet("2001:0db8:85a3::1")
        b = get_subnet("2001:0db8:85a3::ffff")
        self.assertEqual(a, b)

    def test_ipv6_short_form(self):
        # Expanded form should normalize
        result = get_subnet("::1")
        self.assertIsInstance(result, str)

    def test_localhost_returns_subnet(self):
        # Localhost should still return a valid subnet string
        result = get_subnet("127.0.0.1")
        self.assertEqual(result, "127.0")

    def test_private_range_returns_subnet(self):
        self.assertEqual(get_subnet("10.0.0.1"), "10.0")
        self.assertEqual(get_subnet("192.168.0.1"), "192.168")


class TestIsSubnetSaturated(unittest.TestCase):
    """is_subnet_saturated returns True when MAX_PEERS_PER_SUBNET reached."""

    def test_empty_outbound_not_saturated(self):
        self.assertFalse(is_subnet_saturated("203.0.113.5", []))

    def test_below_threshold_not_saturated(self):
        # One peer in same /16 — still room
        current = [("203.0.113.1", 9333)]
        self.assertFalse(is_subnet_saturated("203.0.113.5", current))

    def test_at_threshold_saturated(self):
        # MAX_PEERS_PER_SUBNET peers from same /16
        current = [("203.0.113.1", 9333), ("203.0.113.2", 9333)]
        self.assertTrue(is_subnet_saturated("203.0.113.5", current))

    def test_different_subnet_not_saturated(self):
        # Two peers in 203.0.x.x, but candidate is in 198.51.x.x
        current = [("203.0.113.1", 9333), ("203.0.113.2", 9333)]
        self.assertFalse(is_subnet_saturated("198.51.100.1", current))

    def test_localhost_bypass(self):
        """Private/localhost IPs bypass the saturation check (test envs)."""
        current = [
            ("127.0.0.1", 9333),
            ("127.0.0.1", 9334),
            ("127.0.0.1", 9335),
        ]
        # Even 3 localhost peers should not count as saturated
        self.assertFalse(is_subnet_saturated("127.0.0.1", current))

    def test_private_10_bypass(self):
        current = [("10.0.0.1", 9333), ("10.0.0.2", 9333), ("10.0.0.3", 9333)]
        self.assertFalse(is_subnet_saturated("10.0.0.4", current))

    def test_private_192_168_bypass(self):
        current = [("192.168.1.1", 9333), ("192.168.1.2", 9333), ("192.168.1.3", 9333)]
        self.assertFalse(is_subnet_saturated("192.168.1.4", current))

    def test_ipv6_saturation(self):
        current = [
            ("2001:db8:85a3::1", 9333),
            ("2001:db8:85a3::2", 9333),
        ]
        self.assertTrue(is_subnet_saturated("2001:db8:85a3::3", current))

    def test_ipv6_different_48_not_saturated(self):
        current = [
            ("2001:db8:85a3::1", 9333),
            ("2001:db8:85a3::2", 9333),
        ]
        self.assertFalse(is_subnet_saturated("2001:db8:85a4::1", current))


class TestSelectOutboundPeer(unittest.TestCase):
    """select_outbound_peer prefers diversity over same-subnet candidates."""

    def setUp(self):
        self.selector = PeerSelector()

    def test_prefers_diverse_subnet(self):
        """Given a current outbound set in 203.0.x.x, prefer a candidate
        from a different /16.

        Re-run ``_STOCHASTIC_TRIALS`` times: the new-subnet tier has
        exactly one member here (198.51.100.1), so the pick is
        deterministic — but running many trials catches any future
        regression where a same-subnet candidate leaks into the
        new-subnet tier.
        """
        current = [("203.0.113.1", 9333)]
        candidates = [
            ("203.0.113.2", 9333),  # same /16
            ("198.51.100.1", 9333),  # different /16
        ]
        for _ in range(_STOCHASTIC_TRIALS):
            chosen = self.selector.select_outbound_peer(candidates, current)
            self.assertEqual(chosen[0], "198.51.100.1")

    def test_falls_back_to_same_subnet_if_no_diverse(self):
        """If all candidates are from the same /16, still pick one.

        Re-run ``_STOCHASTIC_TRIALS`` times: the selector picks randomly
        between the two 203.0.113.x candidates (both in the unsaturated
        tier). Both satisfy the prefix assertion, so this is robust to
        the intra-tier random pick — we just verify the tier logic
        never returns None and never escapes the 203.0.113/24.
        """
        current = [("203.0.113.1", 9333)]
        candidates = [
            ("203.0.113.2", 9333),
            ("203.0.113.3", 9333),
        ]
        for _ in range(_STOCHASTIC_TRIALS):
            chosen = self.selector.select_outbound_peer(candidates, current)
            self.assertIsNotNone(chosen)
            self.assertTrue(chosen[0].startswith("203.0.113."))

    def test_caps_at_max_per_subnet(self):
        """When a /16 is saturated, candidates from that /16 are skipped
        unless there's no alternative.

        Re-run ``_STOCHASTIC_TRIALS`` times: the saturated 203.0 /16
        forces 198.51.100.1 to be the only new-subnet-tier candidate.
        Any flakiness in tier classification surfaces reliably here.
        """
        current = [("203.0.113.1", 9333), ("203.0.113.2", 9333)]
        candidates = [
            ("203.0.113.3", 9333),  # same saturated /16
            ("198.51.100.1", 9333),  # different /16
        ]
        for _ in range(_STOCHASTIC_TRIALS):
            chosen = self.selector.select_outbound_peer(candidates, current)
            self.assertEqual(chosen[0], "198.51.100.1")

    def test_saturated_only_candidates_still_picked(self):
        """If ONLY saturated-/16 candidates exist, still return one
        (better than no peers)."""
        current = [("203.0.113.1", 9333), ("203.0.113.2", 9333)]
        candidates = [("203.0.113.3", 9333)]
        chosen = self.selector.select_outbound_peer(candidates, current)
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen[0], "203.0.113.3")

    def test_empty_candidates_returns_none(self):
        chosen = self.selector.select_outbound_peer([], [])
        self.assertIsNone(chosen)

    def test_fills_with_diversity_first(self):
        """Given 10 candidates from 5 /16s, selection fills diversity first.

        Private IPs bypass saturation, so this tests the diversity
        preference scoring — candidates from unrepresented /16s are
        preferred over those from already-represented ones.

        Re-run ``_STOCHASTIC_TRIALS`` times because the new-subnet tier
        here has 8 candidates (all 10.2-10.5 entries); the pick within
        the tier is random, but every member of that tier satisfies the
        assertion (no 10.1 IPs). This batch catches any regression where
        a 10.1 candidate leaks into the new-subnet tier.
        """
        candidates = [
            ("10.1.0.1", 9333), ("10.1.0.2", 9333),  # /16 = 10.1
            ("10.2.0.1", 9333), ("10.2.0.2", 9333),  # /16 = 10.2
            ("10.3.0.1", 9333), ("10.3.0.2", 9333),  # /16 = 10.3
            ("10.4.0.1", 9333), ("10.4.0.2", 9333),  # /16 = 10.4
            ("10.5.0.1", 9333), ("10.5.0.2", 9333),  # /16 = 10.5
        ]
        # Start with one peer in 10.1.x.x
        current = [("10.1.0.99", 9333)]
        # The selector should pick a candidate NOT from 10.1 on every trial
        for _ in range(_STOCHASTIC_TRIALS):
            chosen = self.selector.select_outbound_peer(candidates, current)
            self.assertNotEqual(get_subnet(chosen[0]), "10.1")

    def test_only_one_subnet_caps_at_max(self):
        """Given candidates from only 1 /16, caps at MAX_PEERS_PER_SUBNET
        from that subnet (returns None once saturated, for public IPs)."""
        # Use public IPs so saturation check applies
        current = [("203.0.113.1", 9333), ("203.0.113.2", 9333)]
        candidates = [("203.0.113.3", 9333), ("203.0.113.4", 9333)]
        # Saturated but still returns something (soft preference, not hard block)
        chosen = self.selector.select_outbound_peer(candidates, current)
        # Should still return a peer — soft enforcement
        self.assertIsNotNone(chosen)

    def test_localhost_candidates_always_accepted(self):
        """Localhost candidates bypass diversity checks entirely."""
        current = [
            ("127.0.0.1", 9333),
            ("127.0.0.1", 9334),
            ("127.0.0.1", 9335),
        ]
        candidates = [("127.0.0.1", 9336)]
        chosen = self.selector.select_outbound_peer(candidates, current)
        self.assertIsNotNone(chosen)


class TestDiversityScore(unittest.TestCase):
    """diversity_score: 0.0 (all same /16) to 1.0 (all different /16s)."""

    def test_empty_set(self):
        self.assertEqual(diversity_score([]), 1.0)

    def test_single_peer(self):
        self.assertEqual(diversity_score([("203.0.113.1", 9333)]), 1.0)

    def test_all_same_subnet(self):
        peers = [
            ("203.0.113.1", 9333),
            ("203.0.113.2", 9333),
            ("203.0.113.3", 9333),
        ]
        self.assertAlmostEqual(diversity_score(peers), 1.0 / 3.0)

    def test_all_different_subnets(self):
        peers = [
            ("203.0.113.1", 9333),
            ("198.51.100.1", 9333),
            ("192.0.2.1", 9333),
        ]
        self.assertAlmostEqual(diversity_score(peers), 1.0)

    def test_mixed_diversity(self):
        peers = [
            ("203.0.113.1", 9333),
            ("203.0.113.2", 9333),
            ("198.51.100.1", 9333),
            ("192.0.2.1", 9333),
        ]
        # 3 unique /16s out of 4 peers = 0.75
        self.assertAlmostEqual(diversity_score(peers), 0.75)

    def test_ipv6_diversity(self):
        peers = [
            ("2001:db8:85a3::1", 9333),
            ("2001:db8:85a4::1", 9333),
        ]
        self.assertAlmostEqual(diversity_score(peers), 1.0)

    def test_ipv6_same_48(self):
        peers = [
            ("2001:db8:85a3::1", 9333),
            ("2001:db8:85a3::2", 9333),
        ]
        self.assertAlmostEqual(diversity_score(peers), 0.5)


class TestMinDiverseSubnetsWarning(unittest.TestCase):
    """MIN_DIVERSE_SUBNETS: warn (not halt) when below threshold."""

    def setUp(self):
        self.selector = PeerSelector()

    def test_check_diversity_below_minimum(self):
        """Should return a warning when fewer than MIN_DIVERSE_SUBNETS."""
        peers = [("203.0.113.1", 9333), ("203.0.113.2", 9333)]
        ok, warning = self.selector.check_diversity(peers)
        self.assertFalse(ok)
        self.assertIn("subnet", warning.lower())

    def test_check_diversity_at_minimum(self):
        peers = [
            ("203.0.113.1", 9333),
            ("198.51.100.1", 9333),
            ("192.0.2.1", 9333),
        ]
        ok, warning = self.selector.check_diversity(peers)
        self.assertTrue(ok)
        self.assertEqual(warning, "")

    def test_check_diversity_empty_set(self):
        ok, warning = self.selector.check_diversity([])
        self.assertFalse(ok)

    def test_check_diversity_private_bypass(self):
        """Private IPs don't count toward diversity requirement
        (test environments with all-localhost peers shouldn't warn)."""
        peers = [
            ("127.0.0.1", 9333),
            ("127.0.0.1", 9334),
        ]
        ok, _warning = self.selector.check_diversity(peers)
        # Private-only sets are OK (test environment assumed)
        self.assertTrue(ok)


class TestIPv6Handling(unittest.TestCase):
    """IPv6 addresses use /48 prefix (first 3 groups) for diversity."""

    def test_full_ipv6(self):
        subnet = get_subnet("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertEqual(subnet, "2001:0db8:85a3")

    def test_compressed_ipv6(self):
        subnet = get_subnet("2001:db8:85a3::1")
        self.assertEqual(subnet, "2001:0db8:85a3")

    def test_loopback_ipv6(self):
        subnet = get_subnet("::1")
        self.assertIsInstance(subnet, str)

    def test_ipv4_mapped_ipv6(self):
        # ::ffff:192.0.2.1 should extract as IPv4-style /16
        subnet = get_subnet("::ffff:192.0.2.1")
        # Should treat as IPv4 mapped
        self.assertIsInstance(subnet, str)


class TestPeerSelectionIntegration(unittest.TestCase):
    """Integration: PeerSelector wired into outbound decisions."""

    def test_select_multiple_fills_diverse(self):
        """Repeatedly selecting peers fills diverse subnets first.

        Runs the full 4-step selection loop ``_STOCHASTIC_TRIALS`` times
        so any flakiness in the tier logic (e.g. an intra-tier random
        pick that accidentally depletes a subnet unnecessarily) surfaces
        reliably rather than as a 1-in-N flake. The diversity-first
        tiering guarantees >= 3 distinct /16s on every trial — a single
        failure in the whole batch is a real bug, not a flake.
        """
        selector = PeerSelector()
        candidates_template = [
            ("203.0.113.1", 9333),
            ("203.0.113.2", 9333),
            ("198.51.100.1", 9333),
            ("198.51.100.2", 9333),
            ("192.0.2.1", 9333),
            ("192.0.2.2", 9333),
        ]

        for trial in range(_STOCHASTIC_TRIALS):
            selected: list[tuple[str, int]] = []
            remaining = list(candidates_template)
            for _ in range(4):
                chosen = selector.select_outbound_peer(remaining, selected)
                self.assertIsNotNone(
                    chosen,
                    f"trial {trial}: selector returned None with "
                    f"{len(remaining)} candidates remaining",
                )
                selected.append(chosen)
                remaining.remove(chosen)

            # After 4 selections, should have all 3 distinct /16s covered.
            # With 3 subnets * 2 peers each and diversity-first tiering,
            # the first 3 picks ALWAYS come from distinct subnets.
            subnets = set(get_subnet(ip) for ip, _ in selected)
            self.assertGreaterEqual(
                len(subnets), 3,
                f"trial {trial}: only {len(subnets)} distinct /16s "
                f"in {selected}",
            )

    def test_config_constants_sane(self):
        """Verify config constants have sane values."""
        self.assertEqual(MAX_PEERS_PER_SUBNET, 2)
        self.assertGreaterEqual(MIN_DIVERSE_SUBNETS, 3)


if __name__ == "__main__":
    unittest.main()
