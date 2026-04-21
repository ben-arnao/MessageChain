"""Config is the authoritative knob source.

Regression tripwire for iter-5 finding C1: BAN_THRESHOLD, BAN_DURATION,
DECAY_INTERVAL, MAX_TRACKED_PEERS were once duplicated in both
messagechain/config.py and messagechain/network/ban.py, with ban.py
shadowing the config values.  An operator tuning config_local.py to
harden peer policing silently got zero behavior change.  Fix was to
make ban.py import from config.  This test pins the invariant.
"""

from __future__ import annotations

import unittest

from messagechain import config
from messagechain.network import ban


class TestConfigSingleSource(unittest.TestCase):

    def test_ban_constants_come_from_config(self):
        # Identity check: same object in memory, not just equal value.
        # If ban.py redefines the constant (as it used to), these would
        # be equal by value but distinct objects — and a config_local.py
        # override wouldn't propagate.
        self.assertIs(ban.BAN_THRESHOLD, config.BAN_THRESHOLD)
        self.assertIs(ban.BAN_DURATION, config.BAN_DURATION)
        self.assertIs(ban.DECAY_INTERVAL, config.DECAY_INTERVAL)
        self.assertIs(ban.MAX_TRACKED_PEERS, config.MAX_TRACKED_PEERS)

    def test_peer_read_timeout_exists(self):
        # Iter 5 H3: the 300-second peer read idle timeout was a magic
        # literal scattered across server.py + network/node.py (4 sites).
        # Now centralized as PEER_READ_TIMEOUT in config.
        self.assertTrue(hasattr(config, "PEER_READ_TIMEOUT"))
        self.assertIsInstance(config.PEER_READ_TIMEOUT, int)
        self.assertGreater(config.PEER_READ_TIMEOUT, 0)


if __name__ == "__main__":
    unittest.main()
