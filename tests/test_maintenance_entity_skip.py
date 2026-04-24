"""Maintenance loop must not re-dial a seed we already peer with.

Background — observed on live mainnet after the 1.5.1 entity-level
dedup rollout:

v1's surviving session to v2 is outbound (tiebreaker kept the
lower-entity-id dialer). v2's surviving session to v1 is the
mirror inbound — keyed by v1's ephemeral source port.

v2's seed list still has `(v1_host, 9333)`. The maintenance tick
scans seeds, looks up `"v1_host:9333"` in `self.peers`, finds
nothing (the inbound is keyed on the ephemeral port), and re-dials
v1 every 30s. Each redial completes TLS+HANDSHAKE and then gets
closed by v1's entity-level dedup. Cosmetically the journal shows
one dedup message every 30s; at n=100 validators this churn goes
quadratic.

Fix: store the remote's advertised listen port from the HANDSHAKE
payload, and skip seed dials already covered by an existing live
session with the same `(host, advertised_port)`.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock

from messagechain.network.peer import Peer


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _mk_server(data_dir: str, seed_nodes):
    import server as server_mod
    return server_mod.Server(
        p2p_port=29992, rpc_port=29993,
        seed_nodes=seed_nodes, data_dir=data_dir,
    )


def _mk_inbound_peer(host: str, ephemeral_port: int, entity_id: str,
                     advertised_port: int) -> Peer:
    writer = MagicMock()
    writer.close = MagicMock()
    writer.get_extra_info = lambda key: None
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    return Peer(
        host=host, port=ephemeral_port,
        reader=MagicMock(), writer=writer,
        is_connected=True,
        direction="inbound",
        entity_id=entity_id,
        advertised_port=advertised_port,
    )


class TestMaintenanceSkipsCoveredSeeds(unittest.TestCase):

    def test_skips_redial_when_inbound_advertises_seed_port(self):
        """Seed = (host, 9333); existing inbound peer advertises
        (host, 9333). Maintenance tick must NOT launch a redial."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td, seed_nodes=[("10.0.0.9", 9333)])
            s.wallet_id = bytes.fromhex("bb" * 32)
            # Inbound from remote's ephemeral port 54321; remote
            # advertised its own listen port (9333) in the HANDSHAKE.
            inbound = _mk_inbound_peer(
                "10.0.0.9", 54321, "aa" * 32, advertised_port=9333,
            )
            s.peers[inbound.address] = inbound

            async def drive():
                dials = []

                async def fake_connect(host, port):
                    dials.append((host, port))

                s._connect_to_peer = fake_connect  # type: ignore[assignment]
                await s._peer_maintenance_tick()
                # Give any spawned task a chance to run so we can
                # observe it (there shouldn't be one).
                await asyncio.sleep(0)
                return dials

            dials = _run(drive())
            self.assertEqual(
                dials, [],
                f"maintenance tick must not redial a seed already "
                f"covered by an inbound peer; got {dials}",
            )

    def test_redials_when_no_matching_peer_exists(self):
        """Sanity guardrail: without a matching advertised_port, the
        maintenance tick still dials. This confirms the skip is
        gated on the specific (host, advertised_port) match, not a
        blanket 'any peer on this host' check."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td, seed_nodes=[("10.0.0.9", 9333)])
            s.wallet_id = bytes.fromhex("bb" * 32)
            # Inbound exists but advertised a DIFFERENT listen port —
            # not the same logical endpoint as the seed.
            inbound = _mk_inbound_peer(
                "10.0.0.9", 54321, "aa" * 32, advertised_port=19333,
            )
            s.peers[inbound.address] = inbound

            async def drive():
                dials = []

                async def fake_connect(host, port):
                    dials.append((host, port))

                s._connect_to_peer = fake_connect  # type: ignore[assignment]
                await s._peer_maintenance_tick()
                await asyncio.sleep(0)
                return dials

            dials = _run(drive())
            self.assertEqual(dials, [("10.0.0.9", 9333)])

    def test_redials_when_advertised_peer_is_disconnected(self):
        """A stale Peer with is_connected=False must not gate the
        redial — the maintenance loop's whole job is to recover
        from dropped sessions."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td, seed_nodes=[("10.0.0.9", 9333)])
            s.wallet_id = bytes.fromhex("bb" * 32)
            inbound = _mk_inbound_peer(
                "10.0.0.9", 54321, "aa" * 32, advertised_port=9333,
            )
            inbound.is_connected = False
            s.peers[inbound.address] = inbound

            async def drive():
                dials = []

                async def fake_connect(host, port):
                    dials.append((host, port))

                s._connect_to_peer = fake_connect  # type: ignore[assignment]
                await s._peer_maintenance_tick()
                await asyncio.sleep(0)
                return dials

            dials = _run(drive())
            self.assertEqual(dials, [("10.0.0.9", 9333)])

    def test_redials_when_peer_has_no_entity_id_yet(self):
        """A peer mid-handshake (entity_id still empty) doesn't
        prove a live session with anyone — must not block redial."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td, seed_nodes=[("10.0.0.9", 9333)])
            s.wallet_id = bytes.fromhex("bb" * 32)
            inbound = _mk_inbound_peer(
                "10.0.0.9", 54321, entity_id="", advertised_port=9333,
            )
            s.peers[inbound.address] = inbound

            async def drive():
                dials = []

                async def fake_connect(host, port):
                    dials.append((host, port))

                s._connect_to_peer = fake_connect  # type: ignore[assignment]
                await s._peer_maintenance_tick()
                await asyncio.sleep(0)
                return dials

            dials = _run(drive())
            self.assertEqual(dials, [("10.0.0.9", 9333)])


class TestAdvertisedPortPopulation(unittest.TestCase):
    """Guardrail: advertised_port defaults to 0 and only gets set
    from a valid HANDSHAKE payload. A peer that sends no `port` or
    an invalid one keeps the default, so the maintenance-loop skip
    won't false-positive on malformed peers."""

    def test_default_is_zero(self):
        p = Peer(host="10.0.0.9", port=9333)
        self.assertEqual(p.advertised_port, 0)


if __name__ == "__main__":
    unittest.main()
