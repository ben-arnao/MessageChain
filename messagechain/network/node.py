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
import time
from collections import OrderedDict
from messagechain.config import (
    DEFAULT_PORT, SEED_NODES, MAX_PEERS, BLOCK_TIME_TARGET, MAX_TXS_PER_BLOCK,
    SEEN_TX_CACHE_SIZE,
)
from messagechain.identity.biometrics import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.block import Block
from messagechain.core.transaction import MessageTransaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.network.protocol import (
    MessageType, NetworkMessage, read_message, write_message
)
from messagechain.network.peer import Peer
from messagechain.network.sync import ChainSyncer
from messagechain.consensus.attestation import Attestation, verify_attestation
from messagechain.consensus.slashing import (
    SlashTransaction, verify_slashing_evidence, verify_attestation_slashing_evidence,
    SlashingEvidence, AttestationSlashingEvidence,
)
from messagechain.network.ban import (
    PeerBanManager, OFFENSE_INVALID_BLOCK, OFFENSE_INVALID_TX,
    OFFENSE_INVALID_HEADERS, OFFENSE_UNREQUESTED_DATA,
    OFFENSE_PROTOCOL_VIOLATION, OFFENSE_RATE_LIMIT,
)
from messagechain.network.ratelimit import PeerRateLimiter

logger = logging.getLogger(__name__)


class Node:
    """A full MessageChain network node."""

    def __init__(self, entity: Entity, port: int = DEFAULT_PORT,
                 seed_nodes: list[tuple[str, int]] | None = None,
                 db=None):
        self.entity = entity
        self.port = port
        self.seed_nodes = seed_nodes or SEED_NODES
        self.blockchain = Blockchain(db=db)
        self.mempool = Mempool()
        self.consensus = ProofOfStake()
        self.peers: dict[str, Peer] = {}
        self._server = None
        self._running = False

        # IBD / sync
        self.syncer = ChainSyncer(self.blockchain, self._get_peer_writer)

        # Network protection
        self.ban_manager = PeerBanManager()
        self.rate_limiter = PeerRateLimiter()

        # inv/getdata: track recently seen tx hashes (avoid re-requesting)
        self._seen_txs: OrderedDict = OrderedDict()

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

        # Start TCP server
        self._server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port
        )
        self._running = True
        logger.info(f"Listening on port {self.port}")

        # Connect to seed nodes
        for host, port in self.seed_nodes:
            if port != self.port:  # don't connect to self
                asyncio.create_task(self._connect_to_peer(host, port))

        # Start block production loop
        asyncio.create_task(self._block_production_loop())

        # Start sync check loop
        asyncio.create_task(self._sync_loop())

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(self, reader, writer):
        """Handle an incoming peer connection."""
        addr = writer.get_extra_info("peername")
        address = f"{addr[0]}:{addr[1]}"
        logger.info(f"Incoming connection from {address}")

        # Check ban before accepting
        if self.ban_manager.is_banned(address):
            logger.info(f"Rejected banned peer {address}")
            writer.close()
            return

        peer = Peer(host=addr[0], port=addr[1], reader=reader, writer=writer, is_connected=True)

        try:
            while self._running:
                msg = await read_message(reader)
                if msg is None:
                    break
                await self._handle_message(msg, peer)
        except Exception as e:
            logger.debug(f"Connection error with {address}: {e}")
        finally:
            peer.is_connected = False
            self.rate_limiter.remove_peer(address)
            writer.close()

    async def _connect_to_peer(self, host: str, port: int):
        """Connect to a peer node."""
        addr = f"{host}:{port}"
        if addr in self.peers and self.peers[addr].is_connected:
            return

        # Don't connect to banned peers
        if self.ban_manager.is_banned(addr):
            logger.debug(f"Skipping banned peer {addr}")
            return

        try:
            reader, writer = await asyncio.open_connection(host, port)
            peer = Peer(host=host, port=port, reader=reader, writer=writer, is_connected=True)
            self.peers[addr] = peer
            peer.touch()

            # Send handshake with our chain height (for sync)
            latest = self.blockchain.get_latest_block()
            handshake = NetworkMessage(
                msg_type=MessageType.HANDSHAKE,
                payload={
                    "port": self.port,
                    "chain_height": self.blockchain.height,
                    "best_block_hash": latest.block_hash.hex() if latest else "",
                },
                sender_id=self.entity.entity_id_hex,
            )
            await write_message(writer, handshake)

            # Listen for messages
            while self._running and peer.is_connected:
                msg = await read_message(reader)
                if msg is None:
                    break
                await self._handle_message(msg, peer)

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
            peer.entity_id = msg.sender_id
            self.peers[peer.address] = peer
            logger.info(f"Handshake from {peer.address} (entity: {msg.sender_id[:16]})")

            # Track peer's chain height for sync decisions
            peer_height = msg.payload.get("chain_height", 0)
            best_hash = msg.payload.get("best_block_hash", "")
            self.syncer.update_peer_height(peer.address, peer_height, best_hash)

            # If peer is ahead, initiate sync
            if peer_height > self.blockchain.height and not self.syncer.is_syncing:
                asyncio.create_task(self.syncer.start_sync())

        elif msg.msg_type == MessageType.INV:
            await self._handle_inv(msg.payload, peer)

        elif msg.msg_type == MessageType.GETDATA:
            await self._handle_getdata(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_TX:
            tx = MessageTransaction.deserialize(msg.payload)
            tx_hash_hex = tx.tx_hash.hex()

            # Already seen?
            if tx_hash_hex in self._seen_txs:
                return

            valid, reason = self.blockchain.validate_transaction(tx)
            if valid:
                self._track_seen_tx(tx_hash_hex)
                self.mempool.add_transaction(tx)
                logger.info(f"Received valid tx {tx_hash_hex[:16]}")
                # Relay via inv to other peers
                await self._relay_tx_inv([tx_hash_hex], exclude=address)
            else:
                # Invalid transaction — penalize peer
                self.ban_manager.record_offense(address, OFFENSE_INVALID_TX, f"invalid_tx:{reason}")

        elif msg.msg_type == MessageType.ANNOUNCE_BLOCK:
            block = Block.deserialize(msg.payload)
            success, reason = self.blockchain.add_block(block)
            if success:
                # Remove included txs from mempool
                self.mempool.remove_transactions([tx.tx_hash for tx in block.transactions])
                logger.info(f"Added block #{block.header.block_number} ({reason})")
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
                },
                sender_id=self.entity.entity_id_hex,
            )
            if peer.writer:
                await write_message(peer.writer, response)

        elif msg.msg_type == MessageType.RESPONSE_CHAIN_HEIGHT:
            height = msg.payload.get("height", 0)
            best_hash = msg.payload.get("best_block_hash", "")
            self.syncer.update_peer_height(peer.address, height, best_hash)

        elif msg.msg_type == MessageType.PEER_LIST:
            for p_info in msg.payload.get("peers", []):
                addr = f"{p_info['host']}:{p_info['port']}"
                if addr not in self.peers and len(self.peers) < MAX_PEERS:
                    if not self.ban_manager.is_banned(addr):
                        asyncio.create_task(self._connect_to_peer(p_info["host"], p_info["port"]))

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
                block = Block.deserialize(block_data)
                self.blockchain.add_block(block)

        elif msg.msg_type == MessageType.ANNOUNCE_ATTESTATION:
            await self._handle_announce_attestation(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_SLASH:
            await self._handle_announce_slash(msg.payload, peer)

    def _msg_category(self, msg_type: MessageType) -> str:
        """Map message type to rate limit category."""
        if msg_type in (MessageType.ANNOUNCE_TX, MessageType.INV, MessageType.GETDATA):
            return "tx"
        if msg_type in (MessageType.REQUEST_BLOCK, MessageType.REQUEST_BLOCKS_BATCH):
            return "block_req"
        if msg_type == MessageType.REQUEST_HEADERS:
            return "headers_req"
        return "general"

    # ── inv/getdata relay ──────────────────────────────────────────

    async def _handle_inv(self, payload: dict, peer: Peer):
        """Handle INV message: peer announces tx hashes they have."""
        tx_hashes = payload.get("tx_hashes", [])
        if len(tx_hashes) > 500:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "inv_too_large"
            )
            return

        # Request any tx hashes we haven't seen
        needed = []
        for h in tx_hashes:
            if h not in self._seen_txs:
                tx_hash_bytes = bytes.fromhex(h)
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

        for h in tx_hashes:
            tx_hash_bytes = bytes.fromhex(h)
            tx = self.mempool.pending.get(tx_hash_bytes)
            if tx:
                msg = NetworkMessage(
                    msg_type=MessageType.ANNOUNCE_TX,
                    payload=tx.serialize(),
                    sender_id=self.entity.entity_id_hex,
                )
                if peer.writer:
                    await write_message(peer.writer, msg)
                peer.known_txs.add(h)

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

        # Record in finality tracker
        validator_stake = self.blockchain.supply.get_staked(att.validator_id)
        total_stake = sum(self.blockchain.supply.staked.values())
        self.blockchain.finality.add_attestation(att, validator_stake, total_stake)

        logger.debug(f"Received attestation from {att.validator_id.hex()[:16]} for block #{att.block_number}")

        # Relay to other peers
        relay_msg = NetworkMessage(
            msg_type=MessageType.ANNOUNCE_ATTESTATION,
            payload=payload,
            sender_id=self.entity.entity_id_hex,
        )
        await self._broadcast(relay_msg, exclude=peer.address)

    async def _handle_announce_slash(self, payload: dict, peer: Peer):
        """Handle incoming slashing evidence gossip.

        Validates the evidence and submits it as a slash transaction if valid.
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

        logger.info(f"Received valid slashing evidence against {slash_tx.evidence.offender_id.hex()[:16]}")

        # Relay to other peers
        relay_msg = NetworkMessage(
            msg_type=MessageType.ANNOUNCE_SLASH,
            payload=payload,
            sender_id=self.entity.entity_id_hex,
        )
        await self._broadcast(relay_msg, exclude=peer.address)

    # ── Existing handlers ─────────────────────────────────────────

    async def _handle_request_headers(self, payload: dict, peer: Peer):
        """Serve headers to a syncing peer."""
        start_height = payload.get("start_height", 0)
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
        """Serve full blocks to a syncing peer."""
        block_hashes = payload.get("block_hashes", [])
        blocks = []
        for hash_hex in block_hashes[:50]:  # cap at 50 blocks per batch
            block = self.blockchain.get_block_by_hash(bytes.fromhex(hash_hex))
            if block:
                blocks.append(block.serialize())

        response = NetworkMessage(
            msg_type=MessageType.RESPONSE_BLOCKS_BATCH,
            payload={"blocks": blocks},
            sender_id=self.entity.entity_id_hex,
        )
        if peer.writer:
            await write_message(peer.writer, response)

    async def _handle_request_block(self, payload: dict, peer: Peer):
        """Serve a single block by hash or number."""
        block = None
        if "block_hash" in payload:
            block = self.blockchain.get_block_by_hash(bytes.fromhex(payload["block_hash"]))
        elif "block_number" in payload:
            block = self.blockchain.get_block(payload["block_number"])

        response = NetworkMessage(
            msg_type=MessageType.RESPONSE_BLOCK,
            payload={"block": block.serialize() if block else None},
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
        """Periodically propose blocks if selected as proposer."""
        while self._running:
            await asyncio.sleep(BLOCK_TIME_TARGET)

            # Don't produce blocks while syncing
            if self.syncer.is_syncing:
                continue

            if self.mempool.size == 0:
                continue

            latest = self.blockchain.get_latest_block()
            if latest is None:
                continue

            # Check if we're the selected proposer
            proposer = self.consensus.select_proposer(latest.block_hash)
            if proposer is None or proposer != self.entity.entity_id:
                # If no validators registered, allow any node to propose (bootstrap)
                if self.consensus.validator_count > 0:
                    continue

            # Create and broadcast block (with correct post-state root)
            txs = self.mempool.get_transactions(MAX_TXS_PER_BLOCK)
            block = self.blockchain.propose_block(self.consensus, self.entity, txs)

            success, reason = self.blockchain.add_block(block)
            if success:
                self.mempool.remove_transactions([tx.tx_hash for tx in txs])
                logger.info(f"Proposed block #{block.header.block_number} with {len(txs)} txs")

                msg = NetworkMessage(
                    msg_type=MessageType.ANNOUNCE_BLOCK,
                    payload=block.serialize(),
                    sender_id=self.entity.entity_id_hex,
                )
                await self._broadcast(msg)

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
        self.mempool.add_transaction(tx)
        return True, "Transaction accepted"
