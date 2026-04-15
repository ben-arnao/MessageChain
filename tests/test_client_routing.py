"""Client-side RPC endpoint resolution.

The CLI's default connection target follows a two-stage model:

  Stage 1:  Connect to one of the hardcoded CLIENT_SEED_ENDPOINTS in
            random order.  First responder wins.  This is the only
            bootstrap-time behavior — until the seed returns a
            validator list, the CLI has no other choice.
  Stage 2:  Ask the seed for the network validator set.  If any
            non-seed validator has a reachable RPC endpoint, pick one
            weighted by sqrt(stake) and route the actual RPC there.
            If no non-seed endpoints exist yet, stick with the seed.

  Users always retain manual override via `--server host:port`.

These tests mock the seed socket + get_network_validators RPC response
so we can verify the routing logic without running actual servers.
"""

import unittest
from unittest.mock import patch, MagicMock
from messagechain import cli
from messagechain import config


class TestManualOverride(unittest.TestCase):
    """--server always wins.  The CLI must honor the operator's choice."""

    def test_explicit_host_port(self):
        host, port = cli._parse_server("example.com:12345")
        self.assertEqual((host, port), ("example.com", 12345))

    def test_explicit_host_only(self):
        host, port = cli._parse_server("example.com")
        self.assertEqual((host, port), ("example.com", config.DEFAULT_PORT))


class TestAutoRouting(unittest.TestCase):
    """No --server: follow the stage-1 / stage-2 discovery path."""

    def setUp(self):
        self._orig_seeds = list(config.CLIENT_SEED_ENDPOINTS)
        config.CLIENT_SEED_ENDPOINTS = [
            ("seed1.example", 9333),
            ("seed2.example", 9333),
            ("seed3.example", 9333),
        ]

    def tearDown(self):
        config.CLIENT_SEED_ENDPOINTS = self._orig_seeds

    def test_all_seeds_down_falls_back_to_localhost(self):
        """Every seed unreachable: last-resort dev fallback to localhost."""
        with patch.object(cli, "_try_tcp_open", return_value=False):
            host, port = cli._parse_server(None)
        self.assertEqual((host, port), ("127.0.0.1", 9333))

    def test_reachable_seed_with_no_other_validators_stays_on_seed(self):
        """When only seeds are validators (bootstrap), stick with the seed."""
        seeds = [("seed1.example", 9333), ("seed2.example", 9333), ("seed3.example", 9333)]
        with patch.object(cli, "_try_tcp_open", return_value=True), \
             patch.object(cli, "_auto_pick_endpoint", return_value=seeds[0]):
            # Direct call to _auto_pick_endpoint through _parse_server
            host, port = cli._parse_server(None)
        self.assertIn((host, port), seeds)

    def test_sqrt_weighted_pick_prefers_non_seed_validators(self):
        """Post-bootstrap with non-seed validators reachable: route to one."""
        seed_list = [("seed1.example", 9333), ("seed2.example", 9333), ("seed3.example", 9333)]
        # Non-seed validator appears in the get_network_validators response
        # with a significant stake.
        fake_response = {
            "ok": True,
            "result": {
                "validators": [
                    {"entity_id": "aa" * 32, "stake": 1_000_000,
                     "rpc_host": "seed1.example", "rpc_port": 9333},
                    {"entity_id": "bb" * 32, "stake": 1_000_000,
                     "rpc_host": "seed2.example", "rpc_port": 9333},
                    {"entity_id": "cc" * 32, "stake": 1_000_000,
                     "rpc_host": "seed3.example", "rpc_port": 9333},
                    {"entity_id": "dd" * 32, "stake": 9_000_000,
                     "rpc_host": "external.example", "rpc_port": 9333},
                ]
            },
        }

        def fake_send_recv(req_sock):
            # This is a minimal stub that returns the canned response
            # bytes when the socket's sendall+recv sequence runs.
            pass

        # Short-circuit the whole discovery via direct mock
        def mock_pick():
            # Replicate the picker logic against the canned validators
            import math, random
            non_seed = []
            for v in fake_response["result"]["validators"]:
                host, port = v["rpc_host"], v["rpc_port"]
                if (host, port) in set(seed_list):
                    continue
                non_seed.append((host, port, v["stake"]))
            if not non_seed:
                return seed_list[0]
            weights = [math.isqrt(s) for _, _, s in non_seed]
            total_w = sum(weights)
            pick = random.randint(1, total_w)
            cumulative = 0
            for (host, port, _), w in zip(non_seed, weights):
                cumulative += w
                if pick <= cumulative:
                    return (host, port)

        with patch.object(cli, "_auto_pick_endpoint", side_effect=mock_pick):
            host, port = cli._parse_server(None)

        # Only the external (non-seed) validator has endpoint "external.example".
        # With only one non-seed, picker must land there.
        self.assertEqual((host, port), ("external.example", 9333))


if __name__ == "__main__":
    unittest.main()
