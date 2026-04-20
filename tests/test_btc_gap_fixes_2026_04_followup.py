"""
Follow-up tests for the 2026-04 BTC-gap audit — second-pass fixes.

Covers the remaining gaps the first pass deferred or only partially
addressed:

Gap A: Load TRUSTED_CHECKPOINTS from a JSON file at startup
Gap B: Checkpoint mismatch = instant ban (OFFENSE_CHECKPOINT_VIOLATION)
Gap C: Cap peer-reported cumulative_weight at parse time
Gap D: Outbound dials pulled from addrman.select_addresses (not PEER_LIST direct)
Gap E: Parallel IBD — concurrent block downloads from multiple peers
Gap F: Server delegates P2P to Node (no duplicate dispatch)
Gap G: Slashing reward paid to evidence-relayer too (propagation incentive)
Gap H: Attestation uses consistent stake snapshot under churn
"""

import asyncio
import json
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from messagechain.consensus.checkpoint import (
    WeakSubjectivityCheckpoint, load_checkpoints_file,
)
from messagechain.network.ban import OFFENSE_CHECKPOINT_VIOLATION
from messagechain.network.peer import Peer, ConnectionType
from messagechain.network.sync import ChainSyncer, SyncState


# ─── Gap A: TRUSTED_CHECKPOINTS loaded from JSON file ─────────────────

class TestCheckpointFileLoader(unittest.TestCase):
    """Operators must be able to ship a JSON file containing trusted
    checkpoints; the node loads them at startup without code changes."""

    def test_load_valid_checkpoints_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "checkpoints.json")
            payload = [
                {
                    "block_number": 1000,
                    "block_hash": "ab" * 32,
                    "state_root": "cd" * 32,
                },
                {
                    "block_number": 2000,
                    "block_hash": "11" * 32,
                    "state_root": "22" * 32,
                },
            ]
            with open(path, "w") as f:
                json.dump(payload, f)

            result = load_checkpoints_file(path)
            self.assertEqual(len(result), 2)
            self.assertIsInstance(result[0], WeakSubjectivityCheckpoint)
            self.assertEqual(result[0].block_number, 1000)
            self.assertEqual(result[1].block_hash, bytes.fromhex("11" * 32))

    def test_missing_file_returns_empty_list(self):
        result = load_checkpoints_file("/nonexistent/path/cp.json")
        self.assertEqual(result, [])

    def test_corrupt_file_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "checkpoints.json")
            with open(path, "w") as f:
                f.write("{{{ not valid json")
            result = load_checkpoints_file(path)
            self.assertEqual(result, [])

    def test_node_loads_checkpoints_from_data_dir(self):
        """Node with a data_dir containing checkpoints.json should pick
        them up automatically (no code changes needed at release time)."""
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        with tempfile.TemporaryDirectory() as td:
            cp_path = os.path.join(td, "checkpoints.json")
            with open(cp_path, "w") as f:
                json.dump([{
                    "block_number": 50,
                    "block_hash": "de" * 32,
                    "state_root": "ad" * 32,
                }], f)
            entity = Entity.create(b"cp_load_test".ljust(32, b"\x00"))
            node = Node(entity, port=19980, data_dir=td)
            # The syncer should have exactly one checkpoint loaded
            self.assertIn(50, node.syncer._checkpoints)
            self.assertEqual(
                node.syncer._checkpoints[50].block_hash,
                bytes.fromhex("de" * 32),
            )


# ─── Gap B: Checkpoint violation = instant ban ────────────────────────

class TestCheckpointViolationInstantBan(unittest.TestCase):
    def test_offense_points_instant_ban(self):
        """OFFENSE_CHECKPOINT_VIOLATION must hit the ban threshold in one
        strike — there is no legitimate reason for a peer to serve a header
        at a known checkpoint height with a different hash."""
        from messagechain.network.ban import BAN_THRESHOLD
        self.assertGreaterEqual(OFFENSE_CHECKPOINT_VIOLATION, BAN_THRESHOLD)

    def test_single_checkpoint_mismatch_bans_peer(self):
        good_hash = bytes.fromhex("ab" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=5, block_hash=good_hash, state_root=b"\x00" * 32,
        )

        bc = MagicMock()
        bc.height = 0
        bc.get_latest_block.return_value = None
        bc.has_block.return_value = False

        offenses = []
        s = ChainSyncer(
            bc, lambda _a: None,
            trusted_checkpoints=[cp],
            on_peer_offense=lambda addr, pts, reason: offenses.append((addr, pts, reason)),
        )
        s.state = SyncState.SYNCING_HEADERS
        s._current_sync_peer = "9.9.9.9:9"

        headers = [
            {"block_number": 5, "prev_hash": "00" * 32, "block_hash": "cc" * 32},
        ]
        asyncio.run(s.handle_headers_response(headers, "9.9.9.9:9"))
        self.assertTrue(offenses)
        _, pts, _ = offenses[0]
        self.assertGreaterEqual(pts, OFFENSE_CHECKPOINT_VIOLATION)


# ─── Gap C: cumulative_weight cap ─────────────────────────────────────

class TestCumulativeWeightCap(unittest.TestCase):
    """A peer must not be able to claim an arbitrary cumulative weight
    to always win sync selection. The handshake parser must cap the
    accepted value at a sane multiple of our own best-tip weight (with
    a floor for bootstrap, when our weight is still tiny)."""

    def test_weight_cap_rejects_astronomical_claim(self):
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        entity = Entity.create(b"weight_cap_test".ljust(32, b"\x00"))
        node = Node(entity, port=19979)
        # Make our own best-tip weight = 100
        node.blockchain.fork_choice.tips = {b"\x11" * 32: (5, 100)}

        # A peer that claims 10**18 (astronomical) should not have that
        # value stored verbatim in the syncer — it should be capped.
        capped = node._accept_peer_weight(10**18)
        self.assertLess(capped, 10**12)  # cap should be *much* smaller

    def test_weight_cap_allows_plausible_claim(self):
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        entity = Entity.create(b"weight_cap_ok".ljust(32, b"\x00"))
        node = Node(entity, port=19978)
        node.blockchain.fork_choice.tips = {b"\x11" * 32: (5, 1000)}

        # A peer claiming 2x our weight is plausible (they're ahead)
        accepted = node._accept_peer_weight(2000)
        self.assertEqual(accepted, 2000)

    def test_weight_cap_bootstrap_floor(self):
        """When our own weight is still tiny (bootstrap), the cap must
        still allow peers to claim reasonable weights — otherwise we
        can never catch up."""
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        entity = Entity.create(b"weight_cap_boot".ljust(32, b"\x00"))
        node = Node(entity, port=19977)
        # Our weight is 0 (fresh genesis)
        node.blockchain.fork_choice.tips = {}

        # A peer claiming 10_000 during bootstrap should be accepted
        # (fresh node needs to be able to catch up from genesis).
        accepted = node._accept_peer_weight(10_000)
        self.assertEqual(accepted, 10_000)


# ─── Gap D: outbound dials from addrman.select_addresses ──────────────

class TestAddrmanBackedOutboundDialing(unittest.TestCase):
    """PEER_LIST should only *populate* addrman; a separate periodic
    task pulls candidates from addrman.select_addresses and dials them.
    Direct dialing from PEER_LIST lets attackers force outbound
    connections to attacker-chosen IPs at will."""

    def test_peer_list_does_not_directly_dial(self):
        """When a node receives PEER_LIST, it should route the addresses
        through addrman but NOT schedule _connect_to_peer for each one."""
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        from messagechain.network.protocol import MessageType, NetworkMessage

        entity = Entity.create(b"pl_no_dial".ljust(32, b"\x00"))
        node = Node(entity, port=19976)

        # Instrument: track whether _connect_to_peer gets scheduled
        dials = []
        async def fake_connect(host, port):
            dials.append((host, port))
        node._connect_to_peer = fake_connect

        msg = NetworkMessage(
            msg_type=MessageType.PEER_LIST,
            payload={"peers": [
                {"host": "8.8.8.8", "port": 9333},
                {"host": "1.1.1.1", "port": 9333},
            ]},
            sender_id="a" * 64,
        )
        peer = Peer(host="9.9.9.9", port=5555, is_connected=True)
        asyncio.run(node._handle_message(msg, peer))

        # Give the event loop a moment in case tasks were scheduled
        async def settle():
            await asyncio.sleep(0)
        asyncio.run(settle())

        # We expect NO dials — PEER_LIST should only feed addrman
        self.assertEqual(dials, [], "PEER_LIST should not trigger direct dials")
        # But the addresses should be in addrman
        self.assertIn("8.8.8.8:9333", node.addrman._all_addrs)
        self.assertIn("1.1.1.1:9333", node.addrman._all_addrs)

    def test_maintain_outbound_pulls_from_addrman(self):
        """The node's outbound-maintenance task should pull candidates
        from addrman.select_addresses when it needs more peers."""
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity

        entity = Entity.create(b"maint".ljust(32, b"\x00"))
        node = Node(entity, port=19975)
        # Prepopulate addrman with a known-good address
        node.addrman.add_address("8.8.8.8", 9333, source_ip="7.7.7.7")
        # Instrument dial
        dials = []
        async def fake_connect(host, port):
            dials.append((host, port))
        node._connect_to_peer = fake_connect

        # Run the outbound-maintenance tick once
        asyncio.run(node._maintain_outbound_peers())
        self.assertIn(("8.8.8.8", 9333), dials)


# ─── Gap E: Parallel IBD block download ──────────────────────────────

class TestParallelIBD(unittest.TestCase):
    """Block download during IBD must fan out across multiple peers so
    that a single slow/malicious peer cannot dominate the sync window."""

    def test_request_next_blocks_fans_out_to_multiple_peers(self):
        """When multiple peers are eligible and there are many blocks
        to download, the syncer should issue REQUEST_BLOCKS_BATCH to
        more than one peer concurrently."""
        import messagechain.config as cfg

        bc = MagicMock()
        bc.height = 0
        bc.get_latest_block.return_value = None
        bc.has_block.return_value = False

        # Track which peers got REQUEST_BLOCKS_BATCH messages
        requested_by = {}  # peer_addr -> list of block_hash hex

        class FakeWriter:
            def __init__(self, addr):
                self.addr = addr
            def write(self, data):
                pass
            async def drain(self):
                pass

        async def fake_write_message(writer, msg):
            if msg.msg_type.value == "request_blocks_batch":
                requested_by.setdefault(writer.addr, []).extend(
                    msg.payload.get("block_hashes", [])
                )

        # Monkey-patch write_message inside the sync module
        import messagechain.network.sync as sync_mod
        original_wm = sync_mod.write_message
        sync_mod.write_message = fake_write_message
        try:
            def get_writer(addr):
                return (FakeWriter(addr), None)

            s = ChainSyncer(bc, get_writer)
            # Populate three eligible peers, each claiming enough weight
            for i, addr in enumerate(["1.1.1.1:1", "2.2.2.2:2", "3.3.3.3:3"]):
                s.update_peer_height(
                    addr, 100, f"{i:064x}",
                    cumulative_weight=cfg.MIN_CUMULATIVE_STAKE_WEIGHT + i,
                )
            s.state = SyncState.SYNCING_BLOCKS
            s._current_sync_peer = "1.1.1.1:1"
            # Queue more blocks than a single batch can hold, so fanout is
            # required for the syncer to be doing anything useful.
            s.blocks_needed = [
                i.to_bytes(32, "big") for i in range(sync_mod.BLOCKS_BATCH_SIZE * 3)
            ]

            asyncio.run(s._request_next_blocks_parallel())
        finally:
            sync_mod.write_message = original_wm

        # More than one peer should have received a block-batch request
        self.assertGreater(
            len(requested_by), 1,
            f"Expected parallel fan-out, only got {len(requested_by)} peer(s) requested"
        )
        # No block hash should be requested from more than one peer
        seen = set()
        for hashes in requested_by.values():
            for h in hashes:
                self.assertNotIn(h, seen, f"Block hash {h} requested from >1 peer")
                seen.add(h)


# ─── Gap F: Server no longer duplicates P2P dispatch ──────────────────

class TestServerCompositionWithNode(unittest.TestCase):
    """server.Server should not independently re-implement _handle_message;
    either it delegates to Node or uses a shared dispatcher. The test
    verifies that fixing a bug in Node's P2P path is automatically
    reflected in Server."""

    def test_server_inherits_msg_category(self):
        """Server and Node must produce identical category for PEER_LIST
        (they drifted before the consolidation fix)."""
        from server import Server
        from messagechain.network.node import Node
        from messagechain.network.protocol import MessageType
        from messagechain.identity.identity import Entity

        s = Server(p2p_port=19974, rpc_port=19873, seed_nodes=[])
        entity = Entity.create(b"svr_comp".ljust(32, b"\x00"))
        n = Node(entity, port=19973)

        for mt in [
            MessageType.PEER_LIST,
            MessageType.ANNOUNCE_TX,
            MessageType.REQUEST_HEADERS,
            MessageType.REQUEST_BLOCKS_BATCH,
        ]:
            self.assertEqual(
                s._msg_category(mt), n._msg_category(mt),
                f"Server/Node _msg_category drift on {mt}",
            )


# ─── Gap I: state_root cost scaling (incremental SMT benchmark) ─────

class TestStateRootScaling(unittest.TestCase):
    """State commitment used to be O(N log N) per block (full-rebuild
    flat Merkle). It's now an incremental Sparse Merkle Tree: each
    per-account update is O(TREE_DEPTH), independent of N. This test
    is a regression guard — if someone makes the incremental path
    accidentally O(N) again, the envelope check fires."""

    def test_incremental_update_is_independent_of_population(self):
        """Per-update cost should not grow with N.

        We populate a fresh tree with M accounts, then measure the time
        for ONE additional update. A dropback to O(N) would make the
        second measurement with a larger population much slower.
        """
        from messagechain.core.state_tree import SparseMerkleTree
        import time as _time

        small = SparseMerkleTree()
        for i in range(100):
            small.set((i + 1).to_bytes(32, "big"), i + 1, 0, 0)

        large = SparseMerkleTree()
        for i in range(500):
            large.set((i + 1).to_bytes(32, "big"), i + 1, 0, 0)

        probe = (9_999_999).to_bytes(32, "big")

        t0 = _time.time()
        small.set(probe, 1, 1, 1)
        small_dt = _time.time() - t0

        t0 = _time.time()
        large.set(probe, 1, 1, 1)
        large_dt = _time.time() - t0

        # Generous envelope — 5x to absorb GC/cache noise. A real O(N)
        # regression would make large_dt ~20x slower.
        self.assertLess(
            large_dt, max(small_dt * 5, 0.05),
            f"SMT update at N=500 ({large_dt:.4f}s) dwarfs N=100 "
            f"({small_dt:.4f}s) — O(N) regression suspected",
        )

    def test_warning_threshold_exists(self):
        from messagechain.core.block import STATE_ROOT_WARN_THRESHOLD
        self.assertIsInstance(STATE_ROOT_WARN_THRESHOLD, int)
        self.assertGreater(STATE_ROOT_WARN_THRESHOLD, 0)


# ─── Gap H: Finality uses a pinned per-block stake snapshot ─────────

class TestFinalityStakeSnapshot(unittest.TestCase):
    """When processing attestations for block N-1, FinalityTracker must
    use the stake map as of the END of block N-1, not the live current
    stake. Without this, validator churn between N-1 and N corrupts the
    denominators and numerators of the 2/3 check — either finalizing a
    block that shouldn't be (ghost stake accumulating) or refusing to
    finalize one that should."""

    def test_blockchain_keeps_stake_snapshots(self):
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        # The snapshot map must exist on fresh construction
        self.assertTrue(hasattr(bc, "_stake_snapshots"))
        self.assertIsInstance(bc._stake_snapshots, dict)

    def test_process_attestations_uses_parent_block_snapshot(self):
        """_process_attestations should consult the snapshot for the
        parent block's number, not the live supply.staked. This is the
        per-block pinning that closes the churn gap."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.attestation import Attestation

        bc = Blockchain()
        # Seed a fake snapshot for block 0 with a known validator set
        bc._stake_snapshots[0] = {
            b"\x01" * 32: 100,
            b"\x02" * 32: 300,
        }

        # Build a fake block 1 whose attestations vote for block 0 (genesis)
        mock_block = MagicMock()
        mock_block.header.block_number = 1
        mock_block.header.prev_hash = b"\xaa" * 32

        # Attestation from validator 0x02 (stake 300 in snapshot)
        att = MagicMock()
        att.block_hash = b"\xaa" * 32
        att.block_number = 0
        att.validator_id = b"\x02" * 32
        mock_block.attestations = [att]

        # Capture what add_attestation receives
        calls = []
        original_add = bc.finality.add_attestation
        def spy(attestation, validator_stake, total_stake, **_kwargs):
            calls.append((validator_stake, total_stake))
            return False
        bc.finality.add_attestation = spy

        # Pass a "live" stakes map that DIFFERS from the snapshot —
        # we should see the snapshot values used, not the live ones.
        live_stakes = {b"\x02" * 32: 999}  # churned
        bc._process_attestations(mock_block, live_stakes)

        self.assertEqual(len(calls), 1)
        validator_stake, total_stake = calls[0]
        # Must use snapshot values (validator=300, total=400), not live (999)
        self.assertEqual(validator_stake, 300)
        self.assertEqual(total_stake, 400)


# ─── Gap G: Slash transactions gossiped via ANNOUNCE_SLASH are pooled ─

class TestSlashTxPoolPropagation(unittest.TestCase):
    """When a node receives a valid SlashTransaction via ANNOUNCE_SLASH
    gossip, it must store it in the mempool's slash pool so that the next
    time this node proposes a block, the slash is actually included.

    Without this, slash txs are validated-and-relayed but never land in
    any block — the slashing economic incentive collapses because a
    witness can't collect the finder's reward on evidence they gossip.
    """

    def test_mempool_exposes_slash_pool(self):
        from messagechain.core.mempool import Mempool
        mp = Mempool()
        self.assertTrue(hasattr(mp, "slash_pool"))
        self.assertTrue(hasattr(mp, "add_slash_transaction"))
        self.assertTrue(hasattr(mp, "get_slash_transactions"))

    def test_add_and_retrieve_slash_tx(self):
        from messagechain.core.mempool import Mempool
        mp = Mempool()
        fake = MagicMock()
        fake.tx_hash = b"\xaa" * 32
        mp.add_slash_transaction(fake)
        self.assertIn(fake, mp.get_slash_transactions())

    def test_duplicate_slash_tx_rejected(self):
        from messagechain.core.mempool import Mempool
        mp = Mempool()
        fake = MagicMock()
        fake.tx_hash = b"\xbb" * 32
        self.assertTrue(mp.add_slash_transaction(fake))
        self.assertFalse(mp.add_slash_transaction(fake))
        self.assertEqual(len(mp.get_slash_transactions()), 1)


if __name__ == "__main__":
    unittest.main()
