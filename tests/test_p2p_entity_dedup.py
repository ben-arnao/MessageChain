"""Entity-level dedup of concurrent peer sessions.

Observed on live mainnet 2026-04-24 after 1.5.0 rollout: each validator
listed TWO sockets to the same remote entity — one inbound (remote's
dial-in on an ephemeral source port) plus one outbound (local dial to
the remote's listen port).  The existing address-level dial dedup
(self._connecting, keyed on "host:port") doesn't catch this because
the two sockets have different host:port tuples.

Fix: after the HANDSHAKE completes and the remote's entity_id is
known, scan self.peers for any OTHER live session to the same entity.
If found, apply a symmetric tiebreaker so both ends drop the same
socket and converge to exactly one session per peer pair.

Tiebreaker:
  keep the session where the LOWER entity_id is the outbound dialer.
  (Both ends apply the rule; both end up dropping the same socket.)
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


def _mk_server(data_dir: str):
    import server as server_mod
    return server_mod.Server(
        p2p_port=29990, rpc_port=29991, seed_nodes=[],
        data_dir=data_dir,
    )


def _mk_peer(host: str, port: int, entity_id: str, direction: str) -> Peer:
    writer = MagicMock()
    writer.close = MagicMock()
    writer.get_extra_info = lambda key: None
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    return Peer(
        host=host, port=port,
        reader=MagicMock(), writer=writer,
        is_connected=True,
        direction=direction,
        entity_id=entity_id,
    )


# Hex ordering: "aa..." < "bb..." < "cc...".  We use these so the
# tiebreaker's outcome is obvious from the names.
REMOTE_LO = "aa" * 32   # lower than LOCAL
LOCAL_MID = "bb" * 32   # self.wallet_id in all tests
REMOTE_HI = "cc" * 32   # higher than LOCAL


class TestEntityDedup(unittest.TestCase):
    """Given two live sessions to the same remote entity, the server
    must drop exactly one per the deterministic tiebreaker."""

    def test_we_are_lower_we_keep_outbound_drop_inbound(self):
        """Our id < remote id → we are the outbound-dialer side of the
        surviving connection.  Close the inbound."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            s.wallet_id = bytes.fromhex(LOCAL_MID)  # "bb..."
            remote = REMOTE_HI                      # "cc..." — higher

            inbound = _mk_peer("10.0.0.9", 54321, remote, "inbound")
            outbound = _mk_peer("10.0.0.9", 9333, remote, "outbound")
            s.peers[inbound.address] = inbound
            s.peers[outbound.address] = outbound

            # Simulate: we just processed the HANDSHAKE that set
            # inbound.entity_id (the "second to arrive" side).
            s._dedup_entity_sessions(inbound)

            self.assertIn(outbound.address, s.peers)
            self.assertTrue(outbound.is_connected)
            self.assertNotIn(inbound.address, s.peers)
            self.assertFalse(inbound.is_connected)
            inbound.writer.close.assert_called_once()

    def test_we_are_higher_we_keep_inbound_drop_outbound(self):
        """Our id > remote id → the remote is the outbound-dialer of
        the surviving connection; our inbound survives.  Close our
        outbound."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            s.wallet_id = bytes.fromhex(LOCAL_MID)  # "bb..."
            remote = REMOTE_LO                      # "aa..." — lower

            inbound = _mk_peer("10.0.0.9", 54321, remote, "inbound")
            outbound = _mk_peer("10.0.0.9", 9333, remote, "outbound")
            s.peers[inbound.address] = inbound
            s.peers[outbound.address] = outbound

            # "Second to arrive" is the outbound's echo in this race.
            s._dedup_entity_sessions(outbound)

            self.assertIn(inbound.address, s.peers)
            self.assertTrue(inbound.is_connected)
            self.assertNotIn(outbound.address, s.peers)
            self.assertFalse(outbound.is_connected)
            outbound.writer.close.assert_called_once()

    def test_symmetric_both_ends_drop_same_tcp_connection(self):
        """Stand up the decisions both ends would make for the same
        pair and verify they drop symmetric sockets: concretely, the
        TCP connection dialed by the HIGHER entity dies on both ends."""
        # Lower side: my id "aa...", remote "bb...".  Keep outbound.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s_lo = _mk_server(td)
            s_lo.wallet_id = bytes.fromhex(REMOTE_LO)  # "aa..."
            higher = LOCAL_MID                         # "bb..."
            in_lo = _mk_peer("10.0.0.9", 54321, higher, "inbound")
            out_lo = _mk_peer("10.0.0.9", 9333, higher, "outbound")
            s_lo.peers[in_lo.address] = in_lo
            s_lo.peers[out_lo.address] = out_lo
            s_lo._dedup_entity_sessions(in_lo)

        # Higher side: my id "bb...", remote "aa...".  Keep inbound.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s_hi = _mk_server(td)
            s_hi.wallet_id = bytes.fromhex(LOCAL_MID)  # "bb..."
            lower = REMOTE_LO                          # "aa..."
            in_hi = _mk_peer("10.0.0.9", 54321, lower, "inbound")
            out_hi = _mk_peer("10.0.0.9", 9333, lower, "outbound")
            s_hi.peers[in_hi.address] = in_hi
            s_hi.peers[out_hi.address] = out_hi
            s_hi._dedup_entity_sessions(in_hi)

        # Lower side kept its outbound (its dial is the survivor).
        self.assertTrue(out_lo.is_connected)
        self.assertFalse(in_lo.is_connected)
        # Higher side kept its inbound (the lower-side's dial terminates here).
        self.assertTrue(in_hi.is_connected)
        self.assertFalse(out_hi.is_connected)
        # Together: the "lower → higher" TCP connection survives on both ends,
        # the "higher → lower" connection dies on both ends. Symmetric.

    def test_no_duplicate_is_a_noop(self):
        """Solo session: dedup must not touch anything."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            s.wallet_id = bytes.fromhex(LOCAL_MID)
            only = _mk_peer("10.0.0.9", 9333, REMOTE_HI, "outbound")
            s.peers[only.address] = only

            s._dedup_entity_sessions(only)

            self.assertIn(only.address, s.peers)
            self.assertTrue(only.is_connected)
            only.writer.close.assert_not_called()

    def test_skips_other_entity_ids(self):
        """A peer with a DIFFERENT entity_id is not a duplicate."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            s.wallet_id = bytes.fromhex(LOCAL_MID)
            p1 = _mk_peer("10.0.0.9", 9333, REMOTE_HI, "outbound")
            p2 = _mk_peer("10.0.0.8", 9333, REMOTE_LO, "outbound")
            s.peers[p1.address] = p1
            s.peers[p2.address] = p2

            s._dedup_entity_sessions(p1)

            # Both remain — different entities.
            self.assertTrue(p1.is_connected)
            self.assertTrue(p2.is_connected)

    def test_skips_disconnected_duplicates(self):
        """A stale Peer with is_connected=False shouldn't force the
        new session to close — it's already gone."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            s.wallet_id = bytes.fromhex(LOCAL_MID)
            # Tiebreaker would otherwise say drop the outbound, but
            # the "duplicate" is dead — so we keep the live one.
            stale = _mk_peer("10.0.0.9", 54321, REMOTE_LO, "inbound")
            stale.is_connected = False
            fresh = _mk_peer("10.0.0.9", 9333, REMOTE_LO, "outbound")
            s.peers[stale.address] = stale
            s.peers[fresh.address] = fresh

            s._dedup_entity_sessions(fresh)

            self.assertTrue(fresh.is_connected)
            fresh.writer.close.assert_not_called()

    def test_noop_when_wallet_id_missing(self):
        """Pre-set-wallet Server must not crash on dedup."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            s.wallet_id = None
            p = _mk_peer("10.0.0.9", 9333, REMOTE_HI, "outbound")
            s.peers[p.address] = p
            # Must not raise.
            s._dedup_entity_sessions(p)
            self.assertTrue(p.is_connected)


if __name__ == "__main__":
    unittest.main()
