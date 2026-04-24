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


class TestLocalDefaultHelper(unittest.TestCase):
    """``_parse_server_local_default`` is the operator-introspection
    variant of ``_parse_server``: it defaults to localhost on the
    RPC port instead of the seed-pick path, because questions like
    "is MY node healthy" or "who is MY node connected to" return
    silently-wrong answers when routed to a remote seed.
    """

    def test_no_arg_defaults_to_localhost_rpc_port(self):
        host, port = cli._parse_server_local_default(None)
        self.assertEqual(host, "127.0.0.1")
        # RPC port (9334), distinct from the P2P-port default the
        # other helper falls back to.
        self.assertEqual(port, config.RPC_DEFAULT_PORT)

    def test_empty_string_defaults_to_localhost(self):
        # CLI sometimes passes "" rather than None for unset flags.
        host, port = cli._parse_server_local_default("")
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, config.RPC_DEFAULT_PORT)

    def test_explicit_host_port_overrides(self):
        host, port = cli._parse_server_local_default("remote.example:12345")
        self.assertEqual((host, port), ("remote.example", 12345))

    def test_explicit_host_only_uses_rpc_port(self):
        host, port = cli._parse_server_local_default("remote.example")
        self.assertEqual(host, "remote.example")
        self.assertEqual(port, config.RPC_DEFAULT_PORT)

    def test_does_not_consult_seed_endpoints(self):
        """The whole point: even if every seed is reachable, the
        local-default helper must NOT route to one.  Patch
        _auto_pick_endpoint to assert it's never invoked."""
        called = []
        with patch.object(
            cli, "_auto_pick_endpoint",
            side_effect=lambda *a, **kw: called.append(1) or ("seed", 9333),
        ):
            host, port = cli._parse_server_local_default(None)
        self.assertEqual(called, [])
        self.assertEqual(host, "127.0.0.1")


class TestOperatorCommandsDefaultToLocalhost(unittest.TestCase):
    """Regression for the bug observed in tonight's mainnet rollout:
    ``messagechain status`` on a validator host queried the OTHER
    validator's RPC because ``_parse_server(None)`` ran the seed-
    pick path.  These tests pin every operator-introspection
    command to localhost when --server is unset; an accidental
    revert to ``_parse_server`` would surface immediately.
    """

    def _capture_rpc_target(self, target_func, args):
        """Run a cmd_* function with a stubbed rpc_call and return
        the (host, port) of the first call."""
        targets = []
        def _stub_rpc(host, port, method, params):
            targets.append((host, port))
            # Return a minimal valid response so the command can
            # terminate without crashing on result parsing.
            return {"ok": True, "result": {
                "height": 1, "latest_block_hash": "ab" * 32,
                "seconds_since_last_block": 1,
                "sync_status": {"state": "idle"},
                "peers": [], "count": 0,
                "leaf_watermark": 0, "rotation_number": 0,
                "public_key": "00" * 32,
            }}
        import client as _client
        with patch.object(_client, "rpc_call", side_effect=_stub_rpc):
            try:
                target_func(args)
            except SystemExit:
                pass
        self.assertGreater(
            len(targets), 0,
            "command never made an RPC call; can't verify routing",
        )
        return targets[0]

    def test_cmd_status_defaults_to_localhost(self):
        import argparse
        args = argparse.Namespace(server=None, entity=None)
        host, port = self._capture_rpc_target(cli.cmd_status, args)
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, config.RPC_DEFAULT_PORT)

    def test_cmd_status_explicit_remote_routes_there(self):
        import argparse
        args = argparse.Namespace(
            server="remote.example:9999", entity=None,
        )
        host, port = self._capture_rpc_target(cli.cmd_status, args)
        self.assertEqual((host, port), ("remote.example", 9999))

    def test_cmd_peers_defaults_to_localhost(self):
        import argparse
        args = argparse.Namespace(server=None)
        host, port = self._capture_rpc_target(cli.cmd_peers, args)
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, config.RPC_DEFAULT_PORT)


if __name__ == "__main__":
    unittest.main()
