"""
P2P Node for MessageChain.

Each node runs a TCP server, connects to peers, and participates in
block production and transaction gossip. Fully decentralized - no
special nodes or central coordination.

Now supports:
- Persistent storage (survives restarts)
- Fork choice (handles competing chain tips)
- IBD (Initial Block Download) for new nodes joining the network
- Peer misbehavior scoring & banning
- Per-peer rate limiting
- inv/getdata transaction relay (BTC-style)
"""

import asyncio
import logging
import os
import time
from collections import OrderedDict
from messagechain.config import (
    DEFAULT_PORT, SEED_NODES, MAX_PEERS, MAX_TXS_PER_BLOCK,
    SEEN_TX_CACHE_SIZE, TRUSTED_CHECKPOINTS, REQUIRE_CHECKPOINTS,
    OUTBOUND_BLOCK_RELAY_ONLY_SLOTS, OUTBOUND_FULL_RELAY_SLOTS,
    MEMPOOL_SYNC_INTERVAL_SEC, MEMPOOL_SYNC_FANOUT,
    MEMPOOL_DIGEST_MAX_HASHES, MEMPOOL_DIGEST_MIN_INTERVAL_SEC,
    MAX_BLOCK_HEX_SIZE, validate_block_hex_size,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.block import Block
from messagechain.core.transaction import MessageTransaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.network.protocol import (
    MessageType, NetworkMessage, read_message, write_message
)
from messagechain.consensus.checkpoint import (
    WeakSubjectivityCheckpoint, load_checkpoints_file,
)
from messagechain.network.peer import Peer, ConnectionType
from messagechain.network.addrman import AddressManager
from messagechain.network.anchor import AnchorStore
from messagechain.network.sync import ChainSyncer
from messagechain.network.peer_selection import PeerSelector
from messagechain.network.tls import (
    CertificatePinStore,
    create_client_ssl_context,
    create_node_ssl_context,
    verify_peer_certificate,
)

# Plausibility cap on peer-reported cumulative weight. A peer can legitimately
# be ahead of us, but not by more than this multiplier — otherwise they're
# probably lying to hijack sync selection. Floor ensures a bootstrapping
# node with zero weight can still accept a neighbor claiming reasonable
# progress.
PEER_WEIGHT_CAP_MULTIPLIER = 4      # accept up to 4x our own weight
PEER_WEIGHT_CAP_FLOOR = 1_000_000   # but always allow at least this much
# Cap the number of ANNOUNCE_TX responses per GETDATA request to prevent
# bandwidth amplification (one small GETDATA should not trigger 500 full txs).
MAX_GETDATA_RESPONSES = 50
# Cadence of the outbound-maintenance task — dials missing slots from addrman.
OUTBOUND_MAINTAIN_INTERVAL = 30     # seconds
from messagechain.consensus.attestation import (
    Attestation, attest_block_if_allowed, verify_attestation,
)
from messagechain.consensus.slashing import (
    SlashTransaction, verify_slashing_evidence, verify_attestation_slashing_evidence,
    SlashingEvidence, AttestationSlashingEvidence,
)
from messagechain.consensus.finality import (
    FinalityVote, verify_finality_vote,
)
from messagechain.network.ban import (
    PeerBanManager, OFFENSE_INVALID_BLOCK, OFFENSE_INVALID_TX,
    OFFENSE_INVALID_HEADERS, OFFENSE_UNREQUESTED_DATA,
    OFFENSE_PROTOCOL_VIOLATION, OFFENSE_RATE_LIMIT,
)
from messagechain.network.ratelimit import PeerRateLimiter
from messagechain.network.eviction import PeerEvictionProtector
from messagechain.validation import parse_hex

logger = logging.getLogger(__name__)


class Node:
    """A full MessageChain network node."""

    def __init__(self, entity: Entity, port: int = DEFAULT_PORT,
                 seed_nodes: list[tuple[str, int]] | None = None,
                 db=None, data_dir: str | None = None):
        self.entity = entity
        self.port = port
        self.seed_nodes = seed_nodes or SEED_NODES
        self.data_dir = data_dir
        self.blockchain = Blockchain(db=db)
        self.mempool = Mempool()
        self.consensus = ProofOfStake()
        self.peers: dict[str, Peer] = {}
        self._server = None
        self._running = False

        # Network protection — must exist before syncer so the offense
        # callback can reference ban_manager.
        self.ban_manager = PeerBanManager()
        self.rate_limiter = PeerRateLimiter()
        self.eviction_protector = PeerEvictionProtector()

        # Sybil-resistant address manager (formerly dead code — now wired)
        self.addrman = AddressManager()

        # Anti-eclipse: subnet-diversity-aware outbound peer selector.
        # Gates _maintain_outbound_peers so outbound slots fill with IPs
        # from diverse /16 subnets, making eclipse attacks expensive.
        self.peer_selector = PeerSelector()

        # Persistent anchor store — reloaded at startup, saved at shutdown.
        # Anchors survive node restarts to defeat eclipse-on-reboot attacks.
        anchor_path = (
            os.path.join(data_dir, "anchors.json")
            if data_dir
            else os.path.join(os.getcwd(), "anchors.json")
        )
        self.anchor_store = AnchorStore(anchor_path)

        # TOFU certificate pin store — records SHA-256 fingerprints of
        # peer TLS certs on first sight and detects changes on reconnect.
        # Defense-in-depth against TLS-layer MITM (application-layer signed
        # handshakes handle peer identity, but a MITM on the transport
        # could still tamper with framing/backpressure). Persists under
        # data_dir when provided; otherwise in-memory only.
        pin_path = (
            os.path.join(data_dir, "peer_pins.json") if data_dir else None
        )
        self.pin_store = CertificatePinStore(pin_path)
        # __init__ already loads if the file exists; keep an explicit call
        # for defensive clarity and so tests can round-trip save/load.
        self.pin_store.load()

        # TLS server certificate — the P2P listener needs a cert/key pair
        # so `asyncio.start_server(..., ssl=...)` can actually encrypt the
        # transport.  The cert is persistent under data_dir so the
        # fingerprint that peers TOFU-pin on first sight keeps matching on
        # restart.  Generated lazily: the _first_ Node startup on this
        # data_dir creates the pair; every subsequent start reuses it.
        #
        # The design uses TLS for ENCRYPTION ONLY — peer identity is
        # handled at the application layer via signed handshakes.  So a
        # self-signed cert is the right choice (no CA involved), and the
        # matching client context has verify_mode=CERT_NONE.  TOFU pinning
        # (above) is the identity check on top of TLS-level encryption.
        if data_dir is not None:
            self._server_cert_path = os.path.join(data_dir, "p2p_cert.pem")
            self._server_key_path = os.path.join(data_dir, "p2p_key.pem")
        else:
            # No data_dir: stash certs under a per-entity temp path so a
            # restarted in-memory node still reuses the same cert (avoids
            # needlessly invalidating TOFU pins that remote peers may
            # already hold for us).
            import tempfile as _tempfile
            _tmp_base = os.path.join(
                _tempfile.gettempdir(),
                f"messagechain-{self.entity.entity_id_hex[:16]}",
            )
            os.makedirs(_tmp_base, exist_ok=True)
            self._server_cert_path = os.path.join(_tmp_base, "p2p_cert.pem")
            self._server_key_path = os.path.join(_tmp_base, "p2p_key.pem")
        # Only materialize the cert when TLS is actually enabled.  Keeps
        # TLS-disabled devnets from paying the (small but real) RSA-keygen
        # cost on every Node construction.
        from messagechain import config as _cfg
        if getattr(_cfg, "P2P_TLS_ENABLED", True):
            if not (os.path.exists(self._server_cert_path)
                    and os.path.exists(self._server_key_path)):
                from messagechain.network.tls import _generate_self_signed_cert
                _generate_self_signed_cert(
                    self._server_cert_path, self._server_key_path,
                )

        # IBD / sync — receives trusted checkpoints + a misbehavior callback
        # so checkpoint violations and stalls are actually penalized.
        # Checkpoints come from two sources:
        #   1. A JSON file (checkpoints.json) in data_dir — ship alongside
        #      the release, or distribute out-of-band to operators.
        #   2. The TRUSTED_CHECKPOINTS config tuple (embedded at build).
        # File entries override config entries on block_number collision.
        checkpoints = list(TRUSTED_CHECKPOINTS)
        if data_dir:
            cp_path = os.path.join(data_dir, "checkpoints.json")
            file_cps = load_checkpoints_file(cp_path)
            # Replace any config entry with a file entry at the same height
            by_height = {cp.block_number: cp for cp in checkpoints}
            for cp in file_cps:
                by_height[cp.block_number] = cp
            checkpoints = list(by_height.values())

        if REQUIRE_CHECKPOINTS and not checkpoints:
            raise RuntimeError(
                "No weak-subjectivity checkpoints loaded (TRUSTED_CHECKPOINTS "
                "is empty and no checkpoints.json found). A node without "
                "checkpoints is vulnerable to long-range PoS attacks. Set "
                "REQUIRE_CHECKPOINTS=False only for devnet/testnet."
            )

        self.syncer = ChainSyncer(
            self.blockchain,
            self._get_peer_writer,
            trusted_checkpoints=checkpoints,
            on_peer_offense=self._on_sync_offense,
        )

        # inv/getdata: track recently seen tx hashes (avoid re-requesting)
        self._seen_txs: OrderedDict = OrderedDict()

        # Active mempool replication — anti-censorship.  Tracks:
        #   _mempool_digest_last_seen[peer_addr] = timestamp of last
        #       MEMPOOL_DIGEST received from that peer, used to enforce
        #       MEMPOOL_DIGEST_MIN_INTERVAL_SEC (rejects digest spam).
        #   _mempool_requested_hashes[peer_addr] = set of tx_hash_hex
        #       we asked for from this peer in the CURRENT sync cycle.
        #       When we advertise a hash and the peer doesn't deliver,
        #       we do NOT re-request — silent give-up until a future
        #       cycle advertises it again.  The set is cleared when a
        #       new digest arrives from the peer.
        self._mempool_digest_last_seen: dict[str, float] = {}
        self._mempool_requested_hashes: dict[str, set] = {}

    def _on_sync_offense(self, peer_address: str, points: int, reason: str):
        """Callback invoked by ChainSyncer for sync-time misbehavior."""
        self.ban_manager.record_offense(peer_address, points, reason)

    def _handle_task_exception(self, task_name: str, task: asyncio.Task) -> None:
        """Log uncaught exceptions from background tasks so they don't die silently.

        Without this callback, an exception escaping a ``create_task``-launched
        coroutine is swallowed by asyncio's default handler at garbage-collection
        time. The task dies, the node keeps running as a zombie (listening but
        not producing blocks or syncing), and in a PoS system with an inactivity
        leak, the operator's stake gets slowly drained to zero before anyone
        notices. Loud CRITICAL logging is the minimum viable alarm.
        """
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        logger.critical(
            f"Background task {task_name} crashed: {exc!r}",
            exc_info=(type(exc), exc, exc.__traceback__),
        )

    def _current_cumulative_weight(self) -> int:
        """Our node's best-tip cumulative stake weight, for handshakes."""
        best = self.blockchain.fork_choice.get_best_tip()
        return best[2] if best else 0

    def _accept_peer_weight(self, claimed: int) -> int:
        """Sanity-cap a peer-reported cumulative weight before trusting it.

        Without a cap, a malicious peer can claim INT_MAX to always win
        sync-peer selection; the stall penalty eventually catches them,
        but each lie costs ~SYNC_STALE_TIMEOUT seconds of wasted IBD.
        We bound the accepted value at max(floor, k * our_weight) so a
        fresh node can still catch up from near-zero weight, but can't
        be tricked into picking an attacker who claims astronomical
        progress. The weak-subjectivity checkpoint is the real defense;
        this is belt-and-suspenders for when checkpoints haven't yet
        been crossed.
        """
        if not isinstance(claimed, int) or claimed < 0:
            return 0
        cap = max(
            PEER_WEIGHT_CAP_FLOOR,
            self._current_cumulative_weight() * PEER_WEIGHT_CAP_MULTIPLIER,
        )
        return min(claimed, cap)

    async def _maintain_outbound_peers(self):
        """Single tick of outbound-slot maintenance.

        Pulls candidates from addrman.select_addresses and uses the
        PeerSelector to pick the most diversity-improving candidate.
        This is what *actually* gates outbound connection decisions —
        PEER_LIST only populates addrman, it does not control who we
        dial. An attacker flooding PEER_LIST therefore cannot force us
        to connect to attacker-chosen IPs; at worst it pollutes addrman,
        where Sybil bucketing and per-source caps constrain the damage.

        Anti-eclipse: the PeerSelector prefers candidates whose /16
        subnet is NOT already represented in the current outbound set.
        An attacker needs IPs across many /16s to fill all our slots.
        """
        needed = MAX_PEERS - sum(1 for p in self.peers.values() if p.is_connected)
        if needed <= 0:
            return

        # Build current outbound set for diversity scoring
        current_outbound = [
            (p.host, p.port) for p in self.peers.values()
            if p.is_connected
        ]

        # Log diversity warning if below minimum (advisory only)
        ok, warning = self.peer_selector.check_diversity(current_outbound)
        if not ok and warning:
            logger.warning(warning)

        # Pull more candidates than needed — PeerSelector will rank them
        raw_candidates = self.addrman.select_addresses(needed * 3)

        # Filter out already-connected and banned
        eligible = []
        for host, port in raw_candidates:
            addr = f"{host}:{port}"
            if addr in self.peers and self.peers[addr].is_connected:
                continue
            if self.ban_manager.is_banned(addr):
                continue
            eligible.append((host, port))

        # Use PeerSelector to pick diversity-improving peers one at a time
        connected = 0
        while eligible and connected < needed:
            chosen = self.peer_selector.select_outbound_peer(
                eligible, current_outbound,
            )
            if chosen is None:
                break
            eligible.remove(chosen)
            host, port = chosen
            await self._connect_to_peer(host, port)
            current_outbound.append(chosen)
            connected += 1

    async def _outbound_maintenance_loop(self):
        """Periodic background task that refills outbound slots."""
        while self._running:
            try:
                await self._maintain_outbound_peers()
            except Exception as e:
                logger.debug(f"Outbound maintenance tick failed: {e}")
            await asyncio.sleep(OUTBOUND_MAINTAIN_INTERVAL)

    def _next_connection_type(self) -> ConnectionType:
        """Decide the ConnectionType for the next outbound slot.

        Mixes block-relay-only slots with full-relay slots so that a partial
        eclipse can't block our view of blocks. Block-relay-only peers do
        not relay transactions, which also defeats topology inference via
        tx-relay timing analysis (BTC PR #15759).
        """
        full_relay_count = sum(
            1 for p in self.peers.values()
            if p.is_connected and p.connection_type == ConnectionType.FULL_RELAY
        )
        block_only_count = sum(
            1 for p in self.peers.values()
            if p.is_connected and p.connection_type == ConnectionType.BLOCK_RELAY_ONLY
        )
        if full_relay_count < OUTBOUND_FULL_RELAY_SLOTS:
            return ConnectionType.FULL_RELAY
        if block_only_count < OUTBOUND_BLOCK_RELAY_ONLY_SLOTS:
            return ConnectionType.BLOCK_RELAY_ONLY
        return ConnectionType.FULL_RELAY

    def _track_seen_tx(self, tx_hash_hex: str):
        """Mark a tx hash as seen (LRU bounded)."""
        if tx_hash_hex in self._seen_txs:
            self._seen_txs.move_to_end(tx_hash_hex)
            return
        if len(self._seen_txs) >= SEEN_TX_CACHE_SIZE:
            self._seen_txs.popitem(last=False)
        self._seen_txs[tx_hash_hex] = True

    def _get_peer_writer(self, address: str):
        """Get writer for a peer by address. Used by ChainSyncer."""
        peer = self.peers.get(address)
        if peer and peer.is_connected and peer.writer:
            return (peer.writer, peer)
        return None

    async def start(self):
        """Start the node: initialize chain, start server, connect to peers."""
        logger.info(f"Starting node on port {self.port}")
        logger.info(f"Entity ID: {self.entity.entity_id_hex}")

        # Initialize genesis if this is a fresh chain
        if self.blockchain.height == 0:
            genesis = self.blockchain.initialize_genesis(self.entity)
            logger.info(f"Genesis block created: {genesis.block_hash.hex()[:16]}")
        else:
            logger.info(f"Loaded chain from storage: height={self.blockchain.height}")

        # Start TCP server.  When P2P_TLS_ENABLED is on we wrap the listener
        # with a server SSL context so the actual wire is encrypted — this
        # is what finally gives `writer.get_extra_info("ssl_object")` a real
        # TLS session for the TOFU pin-store verification to inspect
        # (previously dormant).
        from messagechain import config as _cfg
        server_ssl = None
        if getattr(_cfg, "P2P_TLS_ENABLED", True):
            server_ssl = create_node_ssl_context(
                cert_path=self._server_cert_path,
                key_path=self._server_key_path,
            )
        self._server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port, ssl=server_ssl,
        )
        self._running = True
        logger.info(f"Listening on port {self.port}")

        # Reconnect to anchor peers from last session FIRST — this is the
        # restart-time eclipse defense. Anchors are known-good peers we
        # previously held block-relay-only connections to; connecting to
        # them before touching addrman or seeds makes it much harder for
        # an attacker to isolate us across a restart (BTC PR #17428).
        for host, port in self.anchor_store.load_anchors():
            if port != self.port:
                t = asyncio.create_task(self._connect_to_peer(host, port))
                t.add_done_callback(
                    lambda x: self._handle_task_exception("connect_to_peer(anchor)", x)
                )

        # Connect to seed nodes
        for host, port in self.seed_nodes:
            if port != self.port:  # don't connect to self
                t = asyncio.create_task(self._connect_to_peer(host, port))
                t.add_done_callback(
                    lambda x: self._handle_task_exception("connect_to_peer(seed)", x)
                )

        # Start block production loop
        t = asyncio.create_task(self._block_production_loop())
        t.add_done_callback(
            lambda x: self._handle_task_exception("block_production_loop", x)
        )

        # Start sync check loop
        t = asyncio.create_task(self._sync_loop())
        t.add_done_callback(
            lambda x: self._handle_task_exception("sync_loop", x)
        )

        # Start outbound-slot maintenance — pulls candidates from addrman
        # and fills open outbound slots. This is the only path that dials
        # peers discovered via gossip, so PEER_LIST flooding cannot force
        # direct connections to attacker-chosen IPs.
        t = asyncio.create_task(self._outbound_maintenance_loop())
        t.add_done_callback(
            lambda x: self._handle_task_exception("outbound_maintenance_loop", x)
        )

        # Start the active mempool-replication loop — periodically sends
        # a compact digest to a random subset of peers so a tx that
        # reaches ANY honest node propagates to every honest node within
        # one sync interval (anti-censorship; see MEMPOOL_DIGEST docstring).
        t = asyncio.create_task(self._mempool_sync_loop())
        t.add_done_callback(
            lambda x: self._handle_task_exception("mempool_sync_loop", x)
        )

    async def stop(self):
        self._running = False
        # Persist current block-relay-only peers as anchors for next startup.
        # We save BLOCK_RELAY_ONLY connections specifically because tx-relay
        # peers leak information that could be used for eclipse targeting.
        anchors = [
            (p.host, p.port)
            for p in self.peers.values()
            if p.is_connected and p.connection_type == ConnectionType.BLOCK_RELAY_ONLY
        ][:OUTBOUND_BLOCK_RELAY_ONLY_SLOTS]
        if anchors:
            self.anchor_store.save_anchors(anchors)
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(self, reader, writer):
        """Handle an incoming peer connection.

        Read loop is wrapped in asyncio.wait_for with PEER_READ_TIMEOUT to
        prevent slow-loris style peer-slot exhaustion attacks where a peer
        opens a connection and simply never sends data. A peer that stays
        silent for longer than the timeout is disconnected.
        """
        from messagechain.config import HANDSHAKE_TIMEOUT
        addr = writer.get_extra_info("peername")
        address = f"{addr[0]}:{addr[1]}"
        logger.info(f"Incoming connection from {address}")

        # Check ban before accepting
        if self.ban_manager.is_banned(address):
            logger.info(f"Rejected banned peer {address}")
            writer.close()
            return

        # Enforce MAX_PEERS with eviction. If full, try to evict the worst
        # existing peer; if no eviction candidate, reject the newcomer.
        connected_count = sum(1 for p in self.peers.values() if p.is_connected)
        if connected_count >= MAX_PEERS:
            victim = self.eviction_protector.select_eviction_candidate()
            if victim and victim in self.peers:
                logger.info(f"Evicting peer {victim} to make room for {address}")
                old = self.peers[victim]
                old.is_connected = False
                if old.writer:
                    old.writer.close()
                self.eviction_protector.remove_peer(victim)
            else:
                logger.debug(f"Rejecting inbound peer {address}: at MAX_PEERS ({MAX_PEERS}), no eviction candidate")
                writer.close()
                return

        peer = Peer(host=addr[0], port=addr[1], reader=reader, writer=writer, is_connected=True)
        self.eviction_protector.register_peer(address)

        # Long-lived idle timeout for an established peer. Handshake must
        # arrive within HANDSHAKE_TIMEOUT; regular traffic after that is
        # checked against a more generous idle window so that well-behaved
        # peers aren't disconnected during quiet periods.
        first_message = True
        try:
            while self._running:
                timeout = HANDSHAKE_TIMEOUT if first_message else 300
                try:
                    msg = await asyncio.wait_for(read_message(reader), timeout=timeout)
                except asyncio.TimeoutError:
                    logger.debug(f"Peer {address} timed out after {timeout}s")
                    break
                if msg is None:
                    break
                first_message = False
                await self._handle_message(msg, peer)
        except Exception as e:
            logger.debug(f"Connection error with {address}: {e}")
        finally:
            peer.is_connected = False
            self.rate_limiter.remove_peer(address)
            self.eviction_protector.remove_peer(address)
            self._mempool_digest_last_seen.pop(address, None)
            self._mempool_requested_hashes.pop(address, None)
            writer.close()

    def _verify_and_pin_peer_tls(self, writer, host: str, port: int) -> bool:
        """Apply TOFU certificate pinning to an outbound connection.

        Returns True when:
          - the connection is not TLS-wrapped (plain TCP; no cert to pin), OR
          - the peer's cert fingerprint is first-seen (records a pin), OR
          - the peer's cert fingerprint matches the stored pin.

        Returns False when the peer presents a DIFFERENT cert than the one
        previously pinned for (host, port) — a possible MITM.  On first
        pin, persists the updated pin store to disk (best-effort).

        Defense-in-depth: the blockchain already authenticates peer
        identity via the signed application-layer HANDSHAKE.  This
        catches active network-layer MITM that swaps the TLS cert while
        letting the blockchain handshake pass through intact.
        """
        # asyncio's writer.get_extra_info returns None when the transport
        # is not SSL-wrapped.  In that (current) case we skip pinning
        # entirely — there is no TLS identity to pin — but we still
        # return True so the caller proceeds with the plain-TCP connection.
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
        except Exception:
            ssl_obj = None
        if ssl_obj is None:
            return True

        had_pin = self.pin_store.get(host, port) is not None
        ok = verify_peer_certificate(ssl_obj, host, port, self.pin_store)
        if ok and not had_pin:
            # First-seen: TOFU just recorded a new pin.  Persist so
            # subsequent restarts still catch a mid-lifecycle MITM.
            try:
                self.pin_store.save()
            except Exception as e:
                logger.debug(f"Failed to save pin store for {host}:{port}: {e}")
        elif not ok:
            # Cert changed — loud warning.  We don't auto-ban: TLS cert
            # rotation is legitimate for long-lived peers, and a ban here
            # would tempt operators to disable the check entirely.  The
            # caller closes the connection; re-pinning requires explicit
            # operator action (clear_pin).
            logger.warning(
                f"TLS pin mismatch for peer {host}:{port} — possible MITM. "
                f"Closing connection; run clear_pin({host!r}, {port}) to "
                f"accept a rotated certificate."
            )
        return ok

    async def _connect_to_peer(self, host: str, port: int):
        """Connect to a peer node."""
        addr = f"{host}:{port}"
        if addr in self.peers and self.peers[addr].is_connected:
            return

        # Don't connect to banned peers
        if self.ban_manager.is_banned(addr):
            logger.debug(f"Skipping banned peer {addr}")
            return

        from messagechain.config import HANDSHAKE_TIMEOUT
        from messagechain import config as _cfg
        client_ssl = (
            create_client_ssl_context()
            if getattr(_cfg, "P2P_TLS_ENABLED", True)
            else None
        )
        try:
            # Bound the initial TCP connect so an unreachable host doesn't
            # hang the event loop forever.  When TLS is enabled, `ssl=` is
            # a real SSLContext; asyncio negotiates the handshake as part
            # of open_connection so the returned writer already carries
            # the TLS session that `_verify_and_pin_peer_tls` then inspects.
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=client_ssl),
                timeout=HANDSHAKE_TIMEOUT,
            )
            # TOFU pin check runs right after the transport is up. When
            # TLS is active this verifies the peer's cert matches the
            # first-seen fingerprint (or pins it on first sight). When
            # the transport is plain TCP this is a no-op returning True.
            if not self._verify_and_pin_peer_tls(writer, host, port):
                writer.close()
                return

            # Decide what kind of outbound peer this is (full-relay vs
            # block-relay-only) based on how many slots are already filled.
            conn_type = self._next_connection_type()
            peer = Peer(
                host=host, port=port, reader=reader, writer=writer,
                is_connected=True, connection_type=conn_type,
            )
            self.peers[addr] = peer
            peer.touch()

            # Send handshake with our chain height + cumulative stake weight.
            # Cumulative weight is the PoS analog of Bitcoin's chainwork and is
            # what ChainSyncer uses (via MIN_CUMULATIVE_STAKE_WEIGHT) to pick
            # a sync peer.
            latest = self.blockchain.get_latest_block()
            handshake = NetworkMessage(
                msg_type=MessageType.HANDSHAKE,
                payload={
                    "port": self.port,
                    "chain_height": self.blockchain.height,
                    "best_block_hash": latest.block_hash.hex() if latest else "",
                    "cumulative_weight": self._current_cumulative_weight(),
                },
                sender_id=self.entity.entity_id_hex,
            )
            await write_message(writer, handshake)

            # Listen for messages with a bounded idle timeout
            first_message = True
            while self._running and peer.is_connected:
                timeout = HANDSHAKE_TIMEOUT if first_message else 300
                try:
                    msg = await asyncio.wait_for(read_message(reader), timeout=timeout)
                except asyncio.TimeoutError:
                    logger.debug(f"Outbound peer {addr} timed out after {timeout}s")
                    break
                if msg is None:
                    break
                first_message = False
                await self._handle_message(msg, peer)

        except asyncio.TimeoutError:
            logger.debug(f"Connect to {addr} timed out")
        except Exception as e:
            logger.debug(f"Failed to connect to {addr}: {e}")

    async def _handle_message(self, msg: NetworkMessage, peer: Peer):
        """Dispatch incoming network messages with ban/rate-limit checks."""
        peer.touch()
        address = peer.address

        # ── Ban check ──
        if self.ban_manager.is_banned(address):
            peer.is_connected = False
            return

        # ── Rate limit check ──
        category = self._msg_category(msg.msg_type)
        if not self.rate_limiter.check(address, category):
            # Rate limited — record minor offense
            self.ban_manager.record_offense(address, OFFENSE_RATE_LIMIT, f"rate_limit:{category}")
            logger.debug(f"Rate limited {address} on {category}")
            return

        # ── Message dispatch ──

        if msg.msg_type == MessageType.HANDSHAKE:
            # M2: Validate handshake payload before use
            sender_id = msg.sender_id
            if not isinstance(sender_id, str) or len(sender_id) < 16:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_sender_id"
                )
                return
            peer_height = msg.payload.get("chain_height", 0)
            if not isinstance(peer_height, int) or peer_height < 0:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_chain_height"
                )
                return
            best_hash = msg.payload.get("best_block_hash", "")
            if not isinstance(best_hash, str):
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_best_hash"
                )
                return
            peer_weight_raw = msg.payload.get("cumulative_weight", 0)
            if not isinstance(peer_weight_raw, int) or peer_weight_raw < 0:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_cumulative_weight"
                )
                return
            # Sanity-cap the claim — see _accept_peer_weight.
            peer_weight = self._accept_peer_weight(peer_weight_raw)

            peer.entity_id = sender_id
            self.peers[peer.address] = peer
            logger.info(f"Handshake from {peer.address} (entity: {sender_id[:16]})")

            # Track peer's chain height AND cumulative weight for sync decisions.
            # The weight is consulted by get_best_sync_peer against
            # MIN_CUMULATIVE_STAKE_WEIGHT — without it the long-range-attack
            # gate is a no-op.
            self.syncer.update_peer_height(
                peer.address, peer_height, best_hash,
                cumulative_weight=peer_weight,
            )

            # If peer is ahead, initiate sync
            if peer_height > self.blockchain.height and not self.syncer.is_syncing:
                t = asyncio.create_task(self.syncer.start_sync())
                t.add_done_callback(
                    lambda x: self._handle_task_exception("syncer.start_sync", x)
                )

        elif msg.msg_type == MessageType.INV:
            await self._handle_inv(msg.payload, peer)

        elif msg.msg_type == MessageType.GETDATA:
            await self._handle_getdata(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_TX:
            try:
                tx = MessageTransaction.deserialize(msg.payload)
            except Exception:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_tx_data"
                )
                return
            tx_hash_hex = tx.tx_hash.hex()

            # Already seen?
            if tx_hash_hex in self._seen_txs:
                return

            valid, reason = self.blockchain.validate_transaction(tx)
            if valid:
                self._track_seen_tx(tx_hash_hex)
                # Plumb current chain height so the forced-inclusion rule
                # can measure how long this tx waits before it joins the
                # "must-include-or-justify" top-N set.  Omitting this
                # would leave arrival at 0 (legacy default = "always been
                # here"), trivially qualifying every new tx for forced
                # inclusion on its first block.
                self.mempool.add_transaction(
                    tx, arrival_block_height=self.blockchain.height,
                )
                logger.info(f"Received valid tx {tx_hash_hex[:16]}")
                # Relay via inv to other peers
                await self._relay_tx_inv([tx_hash_hex], exclude=address)
            else:
                # Invalid transaction — penalize peer
                self.ban_manager.record_offense(address, OFFENSE_INVALID_TX, f"invalid_tx:{reason}")

        elif msg.msg_type == MessageType.ANNOUNCE_BLOCK:
            try:
                block_hex = msg.payload.get("block")
                if not validate_block_hex_size(block_hex):
                    raise ValueError("ANNOUNCE_BLOCK payload missing/oversized 'block' hex string")
                block = Block.from_bytes(bytes.fromhex(block_hex))
            except Exception:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_block_data"
                )
                return
            success, reason = self.blockchain.add_block(block)
            if success:
                # Remove included txs from mempool (all transaction types)
                all_tx_hashes = (
                    [tx.tx_hash for tx in block.transactions]
                    + [tx.tx_hash for tx in block.transfer_transactions]
                )
                self.mempool.remove_transactions(all_tx_hashes)
                logger.info(f"Added block #{block.header.block_number} ({reason})")
                # Attester duty: if we're a registered validator, cast a
                # vote on the accepted block — but only if it honors our
                # forced-inclusion list (censorship resistance).  A silent
                # omission of a top-N long-waited tx yields None here; we
                # skip the broadcast in that case so the block fails 2/3
                # finality if enough honest attesters concur.
                await self._maybe_attest_accepted_block(block)
                # Gossip to other peers
                await self._broadcast(msg, exclude=peer.address)
            else:
                # Invalid block — penalize peer
                self.ban_manager.record_offense(address, OFFENSE_INVALID_BLOCK, f"invalid_block:{reason}")

        elif msg.msg_type == MessageType.REQUEST_CHAIN_HEIGHT:
            latest = self.blockchain.get_latest_block()
            response = NetworkMessage(
                msg_type=MessageType.RESPONSE_CHAIN_HEIGHT,
                payload={
                    "height": self.blockchain.height,
                    "best_block_hash": latest.block_hash.hex() if latest else "",
                    "cumulative_weight": self._current_cumulative_weight(),
                },
                sender_id=self.entity.entity_id_hex,
            )
            if peer.writer:
                await write_message(peer.writer, response)

        elif msg.msg_type == MessageType.RESPONSE_CHAIN_HEIGHT:
            height = msg.payload.get("height", 0)
            best_hash = msg.payload.get("best_block_hash", "")
            weight_raw = msg.payload.get("cumulative_weight", 0)
            weight = self._accept_peer_weight(weight_raw)
            self.syncer.update_peer_height(
                peer.address, height, best_hash, cumulative_weight=weight,
            )

        elif msg.msg_type == MessageType.PEER_LIST:
            # PEER_LIST only populates addrman — it does NOT schedule
            # outbound dials directly. Dialing decisions are owned by the
            # _outbound_maintenance_loop, which pulls candidates from
            # addrman.select_addresses. This prevents an attacker from
            # forcing our outbound connections to attacker-chosen IPs
            # simply by flooding PEER_LIST. Even after addrman.add_address
            # Sybil bucketing accepts a malicious entry, Bucket selection +
            # tried-table preference make it unlikely to be picked.
            source_ip = peer.host or address.rsplit(":", 1)[0]
            for p_info in msg.payload.get("peers", []):
                host = p_info.get("host", "")
                port = p_info.get("port", 0)
                # M1: Validate peer addresses — reject private/invalid IPs
                if not self._is_valid_peer_address(host, port):
                    continue
                self.addrman.add_address(host, port, source_ip)

        # ── IBD / Sync Protocol Messages ──────────────────────────

        elif msg.msg_type == MessageType.REQUEST_HEADERS:
            await self._handle_request_headers(msg.payload, peer)

        elif msg.msg_type == MessageType.RESPONSE_HEADERS:
            await self.syncer.handle_headers_response(
                msg.payload.get("headers", []), peer.address
            )

        elif msg.msg_type == MessageType.REQUEST_BLOCKS_BATCH:
            await self._handle_request_blocks_batch(msg.payload, peer)

        elif msg.msg_type == MessageType.RESPONSE_BLOCKS_BATCH:
            await self.syncer.handle_blocks_response(
                msg.payload.get("blocks", []), peer.address
            )

        elif msg.msg_type == MessageType.REQUEST_BLOCK:
            await self._handle_request_block(msg.payload, peer)

        elif msg.msg_type == MessageType.RESPONSE_BLOCK:
            block_data = msg.payload.get("block")
            if block_data:
                try:
                    if not validate_block_hex_size(block_data):
                        raise ValueError("RESPONSE_BLOCK 'block' must be hex string within size limit")
                    block = Block.from_bytes(bytes.fromhex(block_data))
                except Exception:
                    self.ban_manager.record_offense(
                        address, OFFENSE_PROTOCOL_VIOLATION, "invalid_response_block"
                    )
                    return
                self.blockchain.add_block(block)

        elif msg.msg_type == MessageType.ANNOUNCE_ATTESTATION:
            await self._handle_announce_attestation(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_SLASH:
            await self._handle_announce_slash(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_FINALITY_VOTE:
            await self._handle_announce_finality_vote(msg.payload, peer)

        elif msg.msg_type == MessageType.MEMPOOL_DIGEST:
            await self._handle_mempool_digest(msg.payload, peer)

        elif msg.msg_type == MessageType.REQUEST_MEMPOOL_TX:
            await self._handle_request_mempool_tx(msg.payload, peer)

    @staticmethod
    def _is_valid_peer_address(host: str, port) -> bool:
        """Reject non-routable IPs and out-of-range ports (eclipse resistance).

        Uses ipaddress module for comprehensive validation covering IPv4, IPv6,
        private, loopback, multicast, link-local, and reserved ranges.
        Rejects hostnames entirely to prevent DNS rebinding attacks.
        """
        import ipaddress
        if not isinstance(host, str) or not isinstance(port, int):
            return False
        if not (1 <= port <= 65535):
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False  # Not a valid IP — reject hostnames
        if ip.is_private:
            return False
        if ip.is_loopback:
            return False
        if ip.is_multicast:
            return False
        if ip.is_link_local:
            return False
        if ip.is_reserved:
            return False
        if ip.is_unspecified:
            return False
        return True

    def _msg_category(self, msg_type: MessageType) -> str:
        """Map message type to rate limit category.

        Delegates to the shared dispatch module so Node and Server can
        never drift on rate-limit policy (they did in the past).
        """
        from messagechain.network.dispatch import message_category
        return message_category(msg_type)

    # ── inv/getdata relay ──────────────────────────────────────────

    async def _handle_inv(self, payload: dict, peer: Peer):
        """Handle INV message: peer announces tx hashes they have."""
        tx_hashes = payload.get("tx_hashes", [])
        if len(tx_hashes) > 500:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "inv_too_large"
            )
            return

        # M3: Rate-limit by hash count, not just message count.
        # Each batch of 50 hashes costs one extra rate-limit token.
        extra_tokens = len(tx_hashes) // 50
        for _ in range(extra_tokens):
            if not self.rate_limiter.check(peer.address, "tx"):
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_RATE_LIMIT, "inv_hash_flood"
                )
                return

        # Request any tx hashes we haven't seen
        needed = []
        for h in tx_hashes:
            tx_hash_bytes = parse_hex(h)
            if tx_hash_bytes is None:
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_hex_in_inv"
                )
                return
            if h not in self._seen_txs:
                if tx_hash_bytes not in self.mempool.pending:
                    needed.append(h)
            # Mark that this peer knows about this tx
            peer.known_txs.add(h)

        if needed:
            getdata = NetworkMessage(
                msg_type=MessageType.GETDATA,
                payload={"tx_hashes": needed},
                sender_id=self.entity.entity_id_hex,
            )
            if peer.writer:
                await write_message(peer.writer, getdata)

    async def _handle_getdata(self, payload: dict, peer: Peer):
        """Handle GETDATA message: peer requests full transactions by hash."""
        tx_hashes = payload.get("tx_hashes", [])
        if len(tx_hashes) > 500:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "getdata_too_large"
            )
            return

        sent = 0
        for h in tx_hashes:
            tx_hash_bytes = parse_hex(h)
            if tx_hash_bytes is None:
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_hex_in_getdata"
                )
                return
            tx = self.mempool.pending.get(tx_hash_bytes)
            if tx:
                if sent >= MAX_GETDATA_RESPONSES:
                    break
                msg = NetworkMessage(
                    msg_type=MessageType.ANNOUNCE_TX,
                    payload=tx.serialize(),
                    sender_id=self.entity.entity_id_hex,
                )
                if peer.writer:
                    await write_message(peer.writer, msg)
                peer.known_txs.add(h)
                sent += 1

    async def _relay_tx_inv(self, tx_hash_hexes: list[str], exclude: str = ""):
        """Relay transaction hashes via INV to peers that don't know them yet."""
        for addr, peer in self.peers.items():
            if addr == exclude or not peer.is_connected or not peer.writer:
                continue
            # Only send hashes this peer hasn't seen
            new_hashes = [h for h in tx_hash_hexes if h not in peer.known_txs]
            if not new_hashes:
                continue
            inv = NetworkMessage(
                msg_type=MessageType.INV,
                payload={"tx_hashes": new_hashes},
                sender_id=self.entity.entity_id_hex,
            )
            try:
                await write_message(peer.writer, inv)
                for h in new_hashes:
                    peer.known_txs.add(h)
            except Exception:
                peer.is_connected = False

    # ── Attestation and slash handlers ─────────────────────────────

    async def _maybe_attest_accepted_block(self, block):
        """Cast an attestation for a freshly-accepted block if we're a
        registered validator AND the block honors our forced-inclusion
        duty.

        Silence (no attestation broadcast) is the NO vote in the soft-
        vote censorship-resistance model — if enough honest stake
        declines, the block fails the 2/3 finality quorum.

        The `is_includable` callback hands `forced_inclusion` a
        proposer-time validity oracle: a tx whose nonce has moved on
        (or whose sender lacks balance, or whose signature no longer
        verifies) is a valid excuse for omission.  We delegate to the
        blockchain's own validate_transaction so the attester and the
        proposer agree on what "includable right now" means.
        """
        # Only registered validators attest.  A node that hasn't
        # staked has no vote to cast.
        if self.entity.entity_id not in self.blockchain.public_keys:
            return
        if self.entity.entity_id not in self.consensus.stakes:
            return

        def _is_includable(tx) -> bool:
            ok, _reason = self.blockchain.validate_transaction(tx)
            return ok

        att = attest_block_if_allowed(
            self.entity,
            block,
            self.mempool,
            current_block_height=block.header.block_number,
            is_includable=_is_includable,
        )
        if att is None:
            logger.warning(
                f"Refusing to attest block #{block.header.block_number}: "
                f"forced-inclusion duty violated (censorship suspected)"
            )
            return

        # Record our own attestation locally (we won't see it on the
        # gossip path) and broadcast.
        validator_stake = self.blockchain.supply.get_staked(self.entity.entity_id)
        total_stake = sum(self.blockchain.supply.staked.values())
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        self.blockchain.finality.add_attestation(
            att, validator_stake, total_stake,
            min_validator_count=MIN_VALIDATORS_TO_EXIT_BOOTSTRAP,
        )

        msg = NetworkMessage(
            msg_type=MessageType.ANNOUNCE_ATTESTATION,
            payload=att.serialize(),
            sender_id=self.entity.entity_id_hex,
        )
        await self._broadcast(msg)

    async def _handle_announce_attestation(self, payload: dict, peer: Peer):
        """Handle an incoming attestation gossip message.

        Validates the attestation signature and records it in the finality
        tracker. Then relays to other peers.
        """
        try:
            att = Attestation.deserialize(payload)
        except Exception:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_attestation_data"
            )
            return

        # Deduplicate: skip if already seen (prevents gossip amplification
        # and redundant expensive signature verification)
        att_key = (att.validator_id, att.block_number, att.block_hash)
        if not hasattr(self, '_seen_attestations'):
            self._seen_attestations: OrderedDict = OrderedDict()
        if att_key in self._seen_attestations:
            return
        # M11: LRU eviction instead of full wipe to prevent replay window
        if len(self._seen_attestations) >= 50_000:
            for _ in range(12_500):
                self._seen_attestations.popitem(last=False)
        self._seen_attestations[att_key] = True

        # Verify the attesting validator is known
        if att.validator_id not in self.blockchain.public_keys:
            return

        # Verify signature
        pk = self.blockchain.public_keys[att.validator_id]
        if not verify_attestation(att, pk):
            self.ban_manager.record_offense(
                peer.address, OFFENSE_INVALID_TX, "invalid_attestation_sig"
            )
            return

        # Record in finality tracker.  Finality safety floor: the active
        # set must meet the minimum validator count regardless of
        # bootstrap_progress — 2/3 of tiny stake is not finality.
        # (Historical name: see config comment.)
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        validator_stake = self.blockchain.supply.get_staked(att.validator_id)
        total_stake = sum(self.blockchain.supply.staked.values())
        self.blockchain.finality.add_attestation(
            att, validator_stake, total_stake,
            min_validator_count=MIN_VALIDATORS_TO_EXIT_BOOTSTRAP,
        )

        logger.debug(f"Received attestation from {att.validator_id.hex()[:16]} for block #{att.block_number}")

        # Relay to other peers
        relay_msg = NetworkMessage(
            msg_type=MessageType.ANNOUNCE_ATTESTATION,
            payload=payload,
            sender_id=self.entity.entity_id_hex,
        )
        await self._broadcast(relay_msg, exclude=peer.address)

    async def _handle_announce_finality_vote(self, payload: dict, peer: Peer):
        """Handle incoming FinalityVote gossip.

        Validates the vote, stores it in the mempool's finality_pool
        so the next time this node proposes a block it collects the
        FINALITY_VOTE_INCLUSION_REWARD, and relays to other peers.
        Matches the ANNOUNCE_SLASH handler shape — the pool step is
        what makes the bounty mechanism actually incentivize inclusion
        rather than having gossip-forever-never-included votes.
        """
        try:
            vote = FinalityVote.deserialize(payload)
        except Exception:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION,
                "invalid_finality_vote_data",
            )
            return

        # Signer must be known and not revoked/slashed
        if vote.signer_entity_id not in self.blockchain.public_keys:
            return
        if vote.signer_entity_id in self.blockchain.revoked_entities:
            return
        if vote.signer_entity_id in self.blockchain.slashed_validators:
            return

        pk = self.blockchain.public_keys[vote.signer_entity_id]
        if not verify_finality_vote(vote, pk):
            self.ban_manager.record_offense(
                peer.address, OFFENSE_INVALID_TX, "invalid_finality_vote_sig",
            )
            return

        added = self.mempool.add_finality_vote(vote)

        if added:
            relay_msg = NetworkMessage(
                msg_type=MessageType.ANNOUNCE_FINALITY_VOTE,
                payload=payload,
                sender_id=self.entity.entity_id_hex,
            )
            await self._broadcast(relay_msg, exclude=peer.address)

    async def _handle_announce_slash(self, payload: dict, peer: Peer):
        """Handle incoming slashing evidence gossip.

        Validates the evidence, stores it in the mempool's slash pool so
        that the next time this node proposes a block the slash is
        actually included, and relays to other peers. Without the pool
        step, slash txs were being validated and gossiped forever but
        never landing in any block — breaking the finder's-reward
        incentive that makes third-party slashing viable at all.
        """
        try:
            slash_tx = SlashTransaction.deserialize(payload)
        except Exception:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_slash_data"
            )
            return

        # Validate the slash transaction
        valid, reason = self.blockchain.validate_slash_transaction(slash_tx)
        if not valid:
            logger.debug(f"Invalid slash evidence from {peer.address}: {reason}")
            return

        logger.info(
            f"Received valid slashing evidence against "
            f"{slash_tx.evidence.offender_id.hex()[:16]}"
        )

        # Pool it for inclusion in our next block
        added = self.mempool.add_slash_transaction(slash_tx)

        # Relay to other peers only on first sight to avoid gossip loops
        if added:
            relay_msg = NetworkMessage(
                msg_type=MessageType.ANNOUNCE_SLASH,
                payload=payload,
                sender_id=self.entity.entity_id_hex,
            )
            await self._broadcast(relay_msg, exclude=peer.address)

    # ── Active mempool replication (anti-censorship) ──────────────

    async def _handle_mempool_digest(self, payload: dict, peer: Peer):
        """Handle an incoming MEMPOOL_DIGEST from a peer.

        Reads `hashes` (list of hex tx_hash strings representing the
        peer's current mempool), diffs against our local mempool, and
        issues a single REQUEST_MEMPOOL_TX for the missing hashes.

        DoS guards:
          1. Size cap — reject any digest with > MEMPOOL_DIGEST_MAX_HASHES
             entries.  A legitimate node's digest is bounded by the cap
             enforced on our own outgoing digest; a peer claiming more
             is trying to amplify our work.
          2. Per-peer interval throttle — reject any second digest from
             the same peer inside MEMPOOL_DIGEST_MIN_INTERVAL_SEC.  Digest
             diffing is O(N) on both sides, so without this a spam peer
             could saturate our event loop.
        """
        import time as _time

        hashes = payload.get("hashes", [])
        if not isinstance(hashes, list):
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "digest_not_list",
            )
            return

        if len(hashes) > MEMPOOL_DIGEST_MAX_HASHES:
            # A peer that advertises more hashes than we would ever send
            # is either buggy or hostile.  Reject and score.
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "digest_too_large",
            )
            return

        # Per-peer interval throttle.  Record the arrival time even when
        # we reject the content so the next arrival also sees a fresh
        # timestamp (locks an attacker into steady-state no matter what).
        now = _time.time()
        last = self._mempool_digest_last_seen.get(peer.address)
        self._mempool_digest_last_seen[peer.address] = now
        if last is not None and (now - last) < MEMPOOL_DIGEST_MIN_INTERVAL_SEC:
            # Silently drop — no offense score; honest peers might retry
            # on a tight schedule during catch-up.
            return

        # A fresh digest — clear our "requested-in-this-cycle" set so we
        # are willing to ask for hashes that the peer re-advertises.
        self._mempool_requested_hashes[peer.address] = set()

        # Compute the set of hashes we don't already have.  Also skip
        # anything we've already requested from this peer (can't happen
        # now since we just cleared, but belt-and-suspenders for future
        # refactors that might interleave).
        needed: list[str] = []
        for h in hashes:
            if not isinstance(h, str):
                # Malformed entry — whole digest is suspect, score.
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "digest_non_str_hash",
                )
                return
            tx_hash_bytes = parse_hex(h)
            if tx_hash_bytes is None or len(tx_hash_bytes) != 32:
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "digest_bad_hash",
                )
                return
            if tx_hash_bytes in self.mempool.pending:
                continue
            needed.append(h)
            self._mempool_requested_hashes[peer.address].add(h)

        if not needed:
            return

        # Cap the request size to the digest cap — a hostile digest that
        # snuck through the size gate (should not happen) still can't
        # explode our outgoing frame.
        needed = needed[:MEMPOOL_DIGEST_MAX_HASHES]
        req = NetworkMessage(
            msg_type=MessageType.REQUEST_MEMPOOL_TX,
            payload={"hashes": needed},
            sender_id=self.entity.entity_id_hex,
        )
        if peer.writer:
            try:
                await write_message(peer.writer, req)
            except Exception:
                peer.is_connected = False

    async def _handle_request_mempool_tx(self, payload: dict, peer: Peer):
        """Handle a peer's REQUEST_MEMPOOL_TX: for each hash we have in
        our mempool, respond with the full tx as ANNOUNCE_TX (reusing
        the existing tx-broadcast path — one code path, no duplication).
        Hashes we don't have are silently dropped (no error amplification)."""
        hashes = payload.get("hashes", [])
        if not isinstance(hashes, list):
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "req_mempool_not_list",
            )
            return
        if len(hashes) > MEMPOOL_DIGEST_MAX_HASHES:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "req_mempool_too_large",
            )
            return

        for h in hashes:
            if not isinstance(h, str):
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "req_mempool_non_str",
                )
                return
            tx_hash_bytes = parse_hex(h)
            if tx_hash_bytes is None or len(tx_hash_bytes) != 32:
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "req_mempool_bad_hash",
                )
                return
            tx = self.mempool.pending.get(tx_hash_bytes)
            if tx is None:
                # Silent drop — peer asked for something we don't have.
                # Don't penalize (could be a race with our own eviction).
                continue
            msg = NetworkMessage(
                msg_type=MessageType.ANNOUNCE_TX,
                payload=tx.serialize(),
                sender_id=self.entity.entity_id_hex,
            )
            if peer.writer:
                try:
                    await write_message(peer.writer, msg)
                    peer.known_txs.add(h)
                except Exception:
                    peer.is_connected = False
                    return

    def _build_mempool_digest_payload(self) -> dict:
        """Build the outgoing MEMPOOL_DIGEST payload: sorted tx_hashes,
        capped at MEMPOOL_DIGEST_MAX_HASHES.

        Deterministic sort on hex encoding keeps the digest stable across
        reorderings and makes diffing cheaper on the receiver (though the
        receiver uses a dict lookup, so strict sort is not required for
        correctness — only for predictable framing)."""
        hashes = sorted(h.hex() for h in self.mempool.pending.keys())
        if len(hashes) > MEMPOOL_DIGEST_MAX_HASHES:
            # An honest node's mempool should never grow past this cap
            # (MEMPOOL_MAX_SIZE <= 5000 by default), but in case config
            # drifts, truncate rather than send an oversized frame.
            hashes = hashes[:MEMPOOL_DIGEST_MAX_HASHES]
        return {"hashes": hashes}

    def _select_mempool_sync_peers(self) -> list[Peer]:
        """Pick up to MEMPOOL_SYNC_FANOUT connected peers for one sync cycle.

        Uses os.urandom for unpredictability — an attacker trying to
        figure out which peer saw our digest shouldn't be able to
        predict it.  The choice is uniform over the connected peer set;
        in practice this mixes full-relay and block-relay-only peers
        equally, which is what we want for anti-censorship: even a peer
        that doesn't normally relay txs should still gossip digests so
        honest mempools converge.
        """
        connected = [p for p in self.peers.values()
                     if p.is_connected and p.writer is not None]
        if not connected:
            return []
        fanout = min(MEMPOOL_SYNC_FANOUT, len(connected))
        # Shuffle using os.urandom for cryptographic randomness
        # (we care about peer-selection privacy — see eviction.py for
        # the same pattern).
        chosen: list[Peer] = []
        remaining = list(connected)
        for _ in range(fanout):
            idx = int.from_bytes(os.urandom(4), "big") % len(remaining)
            chosen.append(remaining.pop(idx))
        return chosen

    async def run_one_mempool_sync_cycle(self) -> int:
        """Fire one round of active mempool replication.

        Builds a digest of our current mempool and sends it to up to
        MEMPOOL_SYNC_FANOUT randomly-selected connected peers.  Each
        recipient will pull the hashes it's missing via REQUEST_MEMPOOL_TX.

        Returns the number of peers the digest was sent to — used by
        tests and diagnostic RPC endpoints.  Callable from a background
        tick loop (see _mempool_sync_loop) OR directly by tests that
        want deterministic per-cycle behavior.

        Design note: this is an active push of a compact advertisement,
        NOT a passive response.  That's the whole anti-censorship story:
        a captured node can drop an incoming tx, but it can't prevent
        honest peers from advertising their mempools to each other.  A
        tx that reached ANY honest node eventually reaches every honest
        node that's within MEMPOOL_SYNC_FANOUT hops over a few cycles.
        """
        peers = self._select_mempool_sync_peers()
        if not peers:
            return 0

        payload = self._build_mempool_digest_payload()
        msg = NetworkMessage(
            msg_type=MessageType.MEMPOOL_DIGEST,
            payload=payload,
            sender_id=self.entity.entity_id_hex,
        )
        sent = 0
        for p in peers:
            try:
                await write_message(p.writer, msg)
                sent += 1
            except Exception:
                p.is_connected = False
        return sent

    async def _mempool_sync_loop(self):
        """Background task: fire run_one_mempool_sync_cycle every
        MEMPOOL_SYNC_INTERVAL_SEC.  Starts after a small random jitter
        so freshly-booted nodes don't synchronize their digest bursts."""
        # Jitter: uniform [0, MEMPOOL_SYNC_INTERVAL_SEC) so node restarts
        # don't produce a thundering-herd digest flood.
        jitter = int.from_bytes(os.urandom(2), "big") % MEMPOOL_SYNC_INTERVAL_SEC
        await asyncio.sleep(jitter)
        while self._running:
            try:
                await self.run_one_mempool_sync_cycle()
            except Exception as e:
                logger.debug(f"Mempool sync cycle failed: {e}")
            await asyncio.sleep(MEMPOOL_SYNC_INTERVAL_SEC)

    # ── Existing handlers ─────────────────────────────────────────

    async def _handle_request_headers(self, payload: dict, peer: Peer):
        """Serve headers to a syncing peer."""
        start_height = payload.get("start_height", 0)
        # M19: Validate start_height type and range
        if not isinstance(start_height, int) or start_height < 0:
            start_height = 0
        start_height = min(start_height, self.blockchain.height + 1)
        count = min(payload.get("count", 100), 500)  # cap at 500

        headers = []
        for i in range(start_height, start_height + count):
            block = self.blockchain.get_block(i)
            if block is None:
                break
            headers.append({
                **block.header.serialize(),
                "block_hash": block.block_hash.hex(),
            })

        response = NetworkMessage(
            msg_type=MessageType.RESPONSE_HEADERS,
            payload={"headers": headers},
            sender_id=self.entity.entity_id_hex,
        )
        if peer.writer:
            await write_message(peer.writer, response)

    async def _handle_request_blocks_batch(self, payload: dict, peer: Peer):
        """Serve full blocks to a syncing peer.

        Blocks travel as hex-encoded binary payload strings
        (`blocks: [<hex>, ...]`) rather than the old nested-dict form —
        the binary blob is ~2x smaller before hex encoding, and
        eliminating JSON field names saves another ~30%.  JSON is still
        the envelope so diagnostic tools (wireshark, pretty-print) stay
        usable; only the block body is opaque.
        """
        block_hashes = payload.get("block_hashes", [])
        blocks_hex = []
        for hash_hex in block_hashes[:50]:  # cap at 50 blocks per batch
            bh = parse_hex(hash_hex)
            if bh is None:
                continue
            block = self.blockchain.get_block_by_hash(bh)
            if block:
                blocks_hex.append(block.to_bytes().hex())

        response = NetworkMessage(
            msg_type=MessageType.RESPONSE_BLOCKS_BATCH,
            payload={"blocks": blocks_hex},
            sender_id=self.entity.entity_id_hex,
        )
        if peer.writer:
            await write_message(peer.writer, response)

    async def _handle_request_block(self, payload: dict, peer: Peer):
        """Serve a single block by hash or number.

        Responds with `{"block": <hex>}` (hex-encoded binary bytes) or
        `{"block": None}` if not found.  See _handle_request_blocks_batch
        for the rationale behind the binary wire format.
        """
        block = None
        if "block_hash" in payload:
            bh = parse_hex(payload["block_hash"])
            if bh is not None:
                block = self.blockchain.get_block_by_hash(bh)
        elif "block_number" in payload:
            block = self.blockchain.get_block(payload["block_number"])

        response = NetworkMessage(
            msg_type=MessageType.RESPONSE_BLOCK,
            payload={"block": block.to_bytes().hex() if block else None},
            sender_id=self.entity.entity_id_hex,
        )
        if peer.writer:
            await write_message(peer.writer, response)

    async def _broadcast(self, msg: NetworkMessage, exclude: str = ""):
        """Broadcast a message to all connected peers."""
        for addr, peer in self.peers.items():
            if addr != exclude and peer.is_connected and peer.writer:
                try:
                    await write_message(peer.writer, msg)
                except Exception:
                    peer.is_connected = False

    async def broadcast_transaction(self, tx: MessageTransaction):
        """Broadcast a transaction to the network via inv/getdata relay."""
        tx_hash_hex = tx.tx_hash.hex()
        self._track_seen_tx(tx_hash_hex)
        # Send inv (not the full tx) to all peers
        await self._relay_tx_inv([tx_hash_hex])

    async def _block_production_loop(self):
        """Slot-aligned block production with round-based proposer rotation.

        Uses the shared block_producer helper so timing/rotation/RANDAO
        logic stays in lockstep with server.py's loop. See
        messagechain/consensus/block_producer.py for the timing model.
        """
        from messagechain.consensus import block_producer

        # Small startup delay so node finishes init before first attempt
        await asyncio.sleep(1)

        while self._running:
            try:
                await self._try_produce_block()
            except Exception:
                logger.exception("Block production iteration failed")

            sleep_seconds = block_producer.next_wake_seconds(self.blockchain)
            await asyncio.sleep(sleep_seconds)

    async def _try_produce_block(self):
        """One iteration of block production. Build and broadcast if we
        are the selected proposer for the current slot+round."""
        from messagechain.consensus import block_producer

        # Don't produce blocks while syncing
        if self.syncer.is_syncing:
            return

        ok, round_number, _reason = block_producer.should_propose(
            self.blockchain, self.consensus, self.entity.entity_id,
        )
        if not ok:
            return

        # Build and broadcast block. Empty mempool is fine — empty blocks
        # serve as heartbeat and carry attestations for the parent.
        txs = self.mempool.get_transactions_with_entity_cap(MAX_TXS_PER_BLOCK)
        # Pull any pending slash transactions received via ANNOUNCE_SLASH
        # gossip. Including them is the path by which third-party witnesses
        # collect the finder's reward — without this, slash txs relayed by
        # a non-proposer witness never land in any block.
        slash_txs = self.mempool.get_slash_transactions()
        # Pull any pending FinalityVotes received via
        # ANNOUNCE_FINALITY_VOTE gossip.  Same pattern as slash txs:
        # inclusion earns the proposer FINALITY_VOTE_INCLUSION_REWARD
        # per vote from treasury, and the votes contribute toward the
        # 2/3-stake commitment that finalizes their target block.
        from messagechain.config import MAX_FINALITY_VOTES_PER_BLOCK
        fin_votes = self.mempool.get_finality_votes(MAX_FINALITY_VOTES_PER_BLOCK)
        block = self.blockchain.propose_block(
            self.consensus, self.entity, txs,
            slash_transactions=slash_txs,
            finality_votes=fin_votes,
        )

        success, reason = self.blockchain.add_block(block)
        if success:
            if txs:
                self.mempool.remove_transactions([tx.tx_hash for tx in txs])
            if slash_txs:
                self.mempool.remove_slash_transactions(
                    [s.tx_hash for s in slash_txs]
                )
            if fin_votes:
                self.mempool.remove_finality_votes(
                    [v.consensus_hash() for v in fin_votes]
                )
            logger.info(
                f"Proposed block #{block.header.block_number} with {len(txs)} txs "
                f"(round {round_number})"
            )

            msg = NetworkMessage(
                msg_type=MessageType.ANNOUNCE_BLOCK,
                payload={"block": block.to_bytes().hex()},
                sender_id=self.entity.entity_id_hex,
            )
            await self._broadcast(msg)
        else:
            logger.warning(f"Failed to add proposed block: {reason}")
            if block_producer.is_clock_skew_reason(reason):
                logger.warning(
                    "This may indicate your system clock is out of sync. "
                    "Check your OS time settings."
                )

    async def _sync_loop(self):
        """Periodically check if we need to sync and handle stale syncs."""
        while self._running:
            await asyncio.sleep(10)

            # Check for stale sync
            await self.syncer.check_sync_stale()

            # Cleanup expired bans, stale rate limit buckets, and old mempool txs
            self.ban_manager.cleanup_expired()
            self.rate_limiter.cleanup_stale()
            self.mempool.expire_transactions()

            # Periodically ask peers for their height
            if not self.syncer.is_syncing:
                for addr, peer in list(self.peers.items()):
                    if peer.is_connected and peer.writer:
                        try:
                            msg = NetworkMessage(
                                msg_type=MessageType.REQUEST_CHAIN_HEIGHT,
                                payload={},
                                sender_id=self.entity.entity_id_hex,
                            )
                            await write_message(peer.writer, msg)
                        except Exception:
                            pass

                # Start sync if needed
                if self.syncer.needs_sync():
                    await self.syncer.start_sync()

    def submit_transaction(self, tx: MessageTransaction) -> tuple[bool, str]:
        """Submit a transaction to this node (local API)."""
        valid, reason = self.blockchain.validate_transaction(tx)
        if not valid:
            return False, reason
        # Record arrival at the current chain height so the forced-
        # inclusion rule can measure wait time.  See the gossip path
        # comment above for the rationale against defaulting to 0.
        self.mempool.add_transaction(
            tx, arrival_block_height=self.blockchain.height,
        )
        return True, "Transaction accepted"
