"""Tests for the protocol version activation framework."""

import unittest
from messagechain.core.versioning import (
    ProtocolVersion,
    PROTOCOL_VERSIONS,
    get_active_version,
    is_feature_active,
)


class TestProtocolVersioning(unittest.TestCase):
    def test_version_1_active_at_genesis(self):
        """Version 1 is active from block 0."""
        version = get_active_version(0)
        self.assertEqual(version.version, 1)

    def test_version_active_at_activation_height(self):
        """A version becomes active at its activation height."""
        # Version 1 activates at 0
        v = get_active_version(0)
        self.assertEqual(v.version, 1)

    def test_version_lookup_returns_latest_active(self):
        """For a given block, the highest activated version is returned."""
        # At block 0, only v1 is active
        v = get_active_version(0)
        self.assertEqual(v.version, 1)

        # At a very high block, still v1 (only version defined so far)
        v = get_active_version(999999999)
        self.assertEqual(v.version, 1)

    def test_protocol_versions_sorted(self):
        """PROTOCOL_VERSIONS must be sorted by activation height."""
        heights = [v.activation_height for v in PROTOCOL_VERSIONS]
        self.assertEqual(heights, sorted(heights))

    def test_feature_active_check(self):
        """is_feature_active returns True for features in the active version."""
        # v1 should have the "unbonding_period" feature (we're adding it)
        active = is_feature_active("base_protocol", 0)
        self.assertTrue(active)

    def test_feature_not_active(self):
        """is_feature_active returns False for unknown features."""
        active = is_feature_active("nonexistent_feature_xyz", 0)
        self.assertFalse(active)

    def test_version_has_required_fields(self):
        """Each ProtocolVersion has version, activation_height, and features."""
        for pv in PROTOCOL_VERSIONS:
            self.assertIsInstance(pv.version, int)
            self.assertIsInstance(pv.activation_height, int)
            self.assertIsInstance(pv.features, list)
            self.assertGreater(pv.version, 0)


if __name__ == "__main__":
    unittest.main()
