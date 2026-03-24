"""
P2P Node for MessageChain.

Each node runs a TCP server, connects to peers, and participates in
block production and transaction gossip. Fully decentralized - no
special nodes or central coordination.
"""

import asyncio
import logging
import time
from messagechain.config import DEFAULT_PORT, SEED_NODES, MAX_PEERS, BLOCK_TIME_TARGET, MAX_TXS_PER_BLOCK
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

logger = logging.getLogger(__name__)


class Node:
    """A full MessageChain network node."""

    def __init__(self, entity: Entity, port: int = DEFAULT_PORT,
                 seed_nodes: list[tuple[str, int]] | None = None):
        self.entity = entity
        self.port = port
        self.seed_nodes = seed_nodes or SEED_NODES
        self.blockchain = Blockchain()
        self.mempool = Mempool()
        self.consensus = ProofOfStake()
        self.peers: dict[str, Peer] = {}
        self._server = None
        self._running = False

    async def start(self):
        """Start the node: initialize chain, start server, connect to peers."""
        logger.info(f"Starting node on port {self.port}")
        logger.info(f"Entity ID: {self.entity.entity_id_hex}")

        # Initialize genesis if this is a fresh chain
        if self.blockchain.height == 0:
            genesis = self.blockchain.initialize_genesis(self.entity)
            logger.info(f"Genesis block created: {genesis.block_hash.hex()[:16]}")

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

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(self, reader, writer):
        """Handle an incoming peer connection."""
        addr = writer.get_extra_info("peername")
        logger.info(f"Incoming connection from {addr}")

        peer = Peer(host=addr[0], port=addr[1], reader=reader, writer=writer, is_connected=True)

        try:
            while self._running:
                msg = await read_message(reader)
                if msg is None:
                    break
                await self._handle_message(msg, peer)
        except Exception as e:
            logger.debug(f"Connection error with {addr}: {e}")
        finally:
            peer.is_connected = False
            writer.close()

    async def _connect_to_peer(self, host: str, port: int):
        """Connect to a peer node."""
        addr = f"{host}:{port}"
        if addr in self.peers and self.peers[addr].is_connected:
            return

        try:
            reader, writer = await asyncio.open_connection(host, port)
            peer = Peer(host=host, port=port, reader=reader, writer=writer, is_connected=True)
            self.peers[addr] = peer
            peer.touch()

            # Send handshake
            handshake = NetworkMessage(
                msg_type=MessageType.HANDSHAKE,
                payload={
                    "port": self.port,
                    "chain_height": self.blockchain.height,
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
        """Dispatch incoming network messages."""
        peer.touch()

        if msg.msg_type == MessageType.HANDSHAKE:
            peer.entity_id = msg.sender_id
            self.peers[peer.address] = peer
            logger.info(f"Handshake from {peer.address} (entity: {msg.sender_id[:16]})")

        elif msg.msg_type == MessageType.ANNOUNCE_TX:
            tx = MessageTransaction.deserialize(msg.payload)
            valid, reason = self.blockchain.validate_transaction(tx)
            if valid:
                self.mempool.add_transaction(tx)
                logger.info(f"Received valid tx {tx.tx_hash.hex()[:16]}")

        elif msg.msg_type == MessageType.ANNOUNCE_BLOCK:
            block = Block.deserialize(msg.payload)
            success, reason = self.blockchain.add_block(block)
            if success:
                # Remove included txs from mempool
                self.mempool.remove_transactions([tx.tx_hash for tx in block.transactions])
                logger.info(f"Added block #{block.header.block_number}")
                # Gossip to other peers
                await self._broadcast(msg, exclude=peer.address)

        elif msg.msg_type == MessageType.REQUEST_CHAIN_HEIGHT:
            response = NetworkMessage(
                msg_type=MessageType.RESPONSE_CHAIN_HEIGHT,
                payload={"height": self.blockchain.height},
                sender_id=self.entity.entity_id_hex,
            )
            if peer.writer:
                await write_message(peer.writer, response)

        elif msg.msg_type == MessageType.PEER_LIST:
            for p_info in msg.payload.get("peers", []):
                addr = f"{p_info['host']}:{p_info['port']}"
                if addr not in self.peers and len(self.peers) < MAX_PEERS:
                    asyncio.create_task(self._connect_to_peer(p_info["host"], p_info["port"]))

    async def _broadcast(self, msg: NetworkMessage, exclude: str = ""):
        """Broadcast a message to all connected peers."""
        for addr, peer in self.peers.items():
            if addr != exclude and peer.is_connected and peer.writer:
                try:
                    await write_message(peer.writer, msg)
                except Exception:
                    peer.is_connected = False

    async def broadcast_transaction(self, tx: MessageTransaction):
        """Broadcast a transaction to the network."""
        msg = NetworkMessage(
            msg_type=MessageType.ANNOUNCE_TX,
            payload=tx.serialize(),
            sender_id=self.entity.entity_id_hex,
        )
        await self._broadcast(msg)

    async def _block_production_loop(self):
        """Periodically propose blocks if selected as proposer."""
        while self._running:
            await asyncio.sleep(BLOCK_TIME_TARGET)

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

            # Create and broadcast block
            txs = self.mempool.get_transactions(MAX_TXS_PER_BLOCK)
            block = self.consensus.create_block(self.entity, txs, latest)

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

    def submit_transaction(self, tx: MessageTransaction) -> tuple[bool, str]:
        """Submit a transaction to this node (local API)."""
        valid, reason = self.blockchain.validate_transaction(tx)
        if not valid:
            return False, reason
        self.mempool.add_transaction(tx)
        return True, "Transaction accepted"
