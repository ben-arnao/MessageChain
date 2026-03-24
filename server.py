#!/usr/bin/env python3
"""
MessageChain Server

Plug-and-play blockchain node. Start it up, give it a wallet ID, and it runs
in the background — processing transactions, producing blocks, and depositing
fees into your wallet.

Usage:
    python server.py
    python server.py --port 9333 --rpc-port 9334
    python server.py --seed 192.168.1.10:9333
"""

import argparse
import asyncio
import json
import logging
import struct
import time

from messagechain.config import (
    DEFAULT_PORT, BLOCK_TIME_TARGET, MAX_TXS_PER_BLOCK, INITIAL_ENTITY_GRANT,
)
from messagechain.identity.biometrics import Entity, BiometricType
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, compute_merkle_root, BlockHeader
from messagechain.core.transaction import MessageTransaction, create_transaction, verify_transaction
from messagechain.core.mempool import Mempool
from messagechain.consensus.pos import ProofOfStake
from messagechain.economics.inflation import SupplyTracker
from messagechain.crypto.keys import verify_signature
from messagechain.network.protocol import (
    MessageType, NetworkMessage, read_message, write_message,
)
from messagechain.network.peer import Peer

import hashlib
from messagechain.config import HASH_ALGO

logger = logging.getLogger("messagechain.server")


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class Server:
    """MessageChain full node with RPC interface for clients."""

    def __init__(self, p2p_port: int, rpc_port: int, seed_nodes: list[tuple[str, int]]):
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.seed_nodes = seed_nodes

        self.blockchain = Blockchain()
        self.mempool = Mempool()
        self.consensus = ProofOfStake()
        self.peers: dict[str, Peer] = {}

        self.wallet_id: bytes | None = None  # the entity_id that earns fees
        self._running = False

    def set_wallet(self, wallet_id_hex: str):
        """Set which wallet receives block rewards and fees."""
        self.wallet_id = bytes.fromhex(wallet_id_hex)
        if self.wallet_id not in self.blockchain.public_keys:
            logger.warning("Wallet not yet registered on chain — will earn rewards once registered")

    async def start(self):
        """Start P2P server, RPC server, and block production."""
        # Initialize genesis if fresh chain
        if self.blockchain.height == 0:
            # Create a bootstrap entity for genesis block
            bootstrap = Entity.create(b"genesis-dna", b"genesis-finger", b"genesis-iris")
            self.blockchain.initialize_genesis(bootstrap)
            logger.info(f"Genesis block created")

        self._running = True

        # Start P2P server
        p2p_server = await asyncio.start_server(
            self._handle_p2p_connection, "0.0.0.0", self.p2p_port
        )
        logger.info(f"P2P listening on port {self.p2p_port}")

        # Start RPC server (for client commands)
        rpc_server = await asyncio.start_server(
            self._handle_rpc_connection, "127.0.0.1", self.rpc_port
        )
        logger.info(f"RPC listening on port {self.rpc_port}")

        # Connect to seed nodes
        for host, port in self.seed_nodes:
            asyncio.create_task(self._connect_to_peer(host, port))

        # Start block production
        asyncio.create_task(self._block_production_loop())

        print(f"Server running. P2P={self.p2p_port} RPC={self.rpc_port}")
        print(f"Wallet: {self.wallet_id.hex() if self.wallet_id else 'NOT SET'}")
        print("Press Ctrl+C to stop.\n")

    async def stop(self):
        self._running = False

    # ── RPC Handler (client interface) ──────────────────────────────

    async def _handle_rpc_connection(self, reader, writer):
        """Handle a client RPC request."""
        try:
            length_bytes = await reader.readexactly(4)
            length = struct.unpack(">I", length_bytes)[0]
            if length > 10_000_000:
                writer.close()
                return
            data = await reader.readexactly(length)
            request = json.loads(data.decode("utf-8"))

            response = await self._process_rpc(request)

            resp_bytes = json.dumps(response).encode("utf-8")
            writer.write(struct.pack(">I", len(resp_bytes)))
            writer.write(resp_bytes)
            await writer.drain()
        except Exception as e:
            logger.error(f"RPC error: {e}")
        finally:
            writer.close()

    async def _process_rpc(self, request: dict) -> dict:
        """Process a single RPC request from a client."""
        method = request.get("method", "")

        if method == "register_entity":
            return self._rpc_register_entity(request["params"])

        elif method == "submit_transaction":
            return self._rpc_submit_transaction(request["params"])

        elif method == "get_entity":
            return self._rpc_get_entity(request["params"])

        elif method == "get_chain_info":
            return {"ok": True, "result": self.blockchain.get_chain_info()}

        elif method == "get_fee_estimate":
            return {"ok": True, "result": {"fee_estimate": self.mempool.get_fee_estimate()}}

        elif method == "get_nonce":
            entity_id = bytes.fromhex(request["params"]["entity_id"])
            nonce = self.blockchain.nonces.get(entity_id, 0)
            return {"ok": True, "result": {"nonce": nonce}}

        else:
            return {"ok": False, "error": f"Unknown method: {method}"}

    def _rpc_register_entity(self, params: dict) -> dict:
        """Register a new entity from client-provided biometric data."""
        try:
            entity = Entity.create(
                dna_data=bytes.fromhex(params["dna_hex"]),
                fingerprint_data=bytes.fromhex(params["fingerprint_hex"]),
                iris_data=bytes.fromhex(params["iris_hex"]),
            )
            success, msg = self.blockchain.register_entity(entity)
            if success:
                return {
                    "ok": True,
                    "result": {
                        "entity_id": entity.entity_id_hex,
                        "public_key": entity.public_key.hex(),
                        "message": msg,
                        "initial_balance": INITIAL_ENTITY_GRANT,
                    },
                }
            else:
                return {"ok": False, "error": msg}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _rpc_submit_transaction(self, params: dict) -> dict:
        """Accept a signed transaction from a client."""
        try:
            tx = MessageTransaction.deserialize(params["transaction"])
            valid, reason = self.blockchain.validate_transaction(tx)
            if not valid:
                return {"ok": False, "error": reason}
            self.mempool.add_transaction(tx)

            # Gossip to peers
            asyncio.create_task(self._broadcast_tx(tx))

            return {
                "ok": True,
                "result": {
                    "tx_hash": tx.tx_hash.hex(),
                    "fee": tx.fee,
                    "message": "Transaction accepted into mempool",
                },
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _rpc_get_entity(self, params: dict) -> dict:
        entity_id = bytes.fromhex(params["entity_id"])
        if entity_id not in self.blockchain.public_keys:
            return {"ok": False, "error": "Entity not found"}
        return {"ok": True, "result": self.blockchain.get_entity_stats(entity_id)}

    # ── Block Production ────────────────────────────────────────────

    async def _block_production_loop(self):
        """Produce blocks on a timer. Fees + rewards go to the configured wallet."""
        while self._running:
            await asyncio.sleep(BLOCK_TIME_TARGET)

            if self.mempool.size == 0:
                continue

            if self.wallet_id is None or self.wallet_id not in self.blockchain.public_keys:
                continue

            latest = self.blockchain.get_latest_block()
            if latest is None:
                continue

            # Check if we're the proposer (or bootstrap mode)
            proposer = self.consensus.select_proposer(latest.block_hash)
            if proposer is not None and proposer != self.wallet_id:
                if self.consensus.validator_count > 0:
                    continue

            # Build block from highest-fee transactions
            txs = self.mempool.get_transactions(MAX_TXS_PER_BLOCK)
            if not txs:
                continue

            # We need the wallet entity's keypair to sign the block.
            # In a real system, the server would have the validator's signing key.
            # For this prototype, we create a lightweight signing proxy.
            tx_hashes = [tx.tx_hash for tx in txs]
            merkle_root = compute_merkle_root(tx_hashes)

            header = BlockHeader(
                version=1,
                block_number=latest.header.block_number + 1,
                prev_hash=latest.block_hash,
                merkle_root=merkle_root,
                timestamp=time.time(),
                proposer_id=self.wallet_id,
            )

            # Note: In production, the server would hold a validator signing key.
            # For the prototype, blocks without proposer signatures are accepted
            # during bootstrap (no registered validators).
            block = Block(header=header, transactions=txs)
            block.block_hash = block._compute_hash()

            success, reason = self.blockchain.add_block(block)
            if success:
                self.mempool.remove_transactions([tx.tx_hash for tx in txs])
                total_fees = sum(tx.fee for tx in txs)
                balance = self.blockchain.supply.get_balance(self.wallet_id)
                logger.info(
                    f"Block #{block.header.block_number} | "
                    f"{len(txs)} txs | fees: {total_fees} | "
                    f"reward: {self.blockchain.supply.calculate_block_reward(block.header.block_number)} | "
                    f"wallet balance: {balance}"
                )
                await self._broadcast_block(block)

    # ── P2P Network ─────────────────────────────────────────────────

    async def _handle_p2p_connection(self, reader, writer):
        addr = writer.get_extra_info("peername")
        peer = Peer(host=addr[0], port=addr[1], reader=reader, writer=writer, is_connected=True)
        try:
            while self._running:
                msg = await read_message(reader)
                if msg is None:
                    break
                await self._handle_p2p_message(msg, peer)
        except Exception:
            pass
        finally:
            peer.is_connected = False
            writer.close()

    async def _connect_to_peer(self, host: str, port: int):
        addr = f"{host}:{port}"
        if addr in self.peers and self.peers[addr].is_connected:
            return
        try:
            reader, writer = await asyncio.open_connection(host, port)
            peer = Peer(host=host, port=port, reader=reader, writer=writer, is_connected=True)
            self.peers[addr] = peer
            handshake = NetworkMessage(
                msg_type=MessageType.HANDSHAKE,
                payload={"port": self.p2p_port, "chain_height": self.blockchain.height},
                sender_id=self.wallet_id.hex() if self.wallet_id else "",
            )
            await write_message(writer, handshake)
            while self._running and peer.is_connected:
                msg = await read_message(reader)
                if msg is None:
                    break
                await self._handle_p2p_message(msg, peer)
        except Exception as e:
            logger.debug(f"Peer connection failed {addr}: {e}")

    async def _handle_p2p_message(self, msg: NetworkMessage, peer: Peer):
        peer.touch()
        if msg.msg_type == MessageType.HANDSHAKE:
            peer.entity_id = msg.sender_id
            self.peers[peer.address] = peer
        elif msg.msg_type == MessageType.ANNOUNCE_TX:
            tx = MessageTransaction.deserialize(msg.payload)
            valid, _ = self.blockchain.validate_transaction(tx)
            if valid:
                self.mempool.add_transaction(tx)
        elif msg.msg_type == MessageType.ANNOUNCE_BLOCK:
            block = Block.deserialize(msg.payload)
            success, _ = self.blockchain.add_block(block)
            if success:
                self.mempool.remove_transactions([tx.tx_hash for tx in block.transactions])

    async def _broadcast_tx(self, tx: MessageTransaction):
        msg = NetworkMessage(MessageType.ANNOUNCE_TX, tx.serialize())
        await self._broadcast(msg)

    async def _broadcast_block(self, block: Block):
        msg = NetworkMessage(MessageType.ANNOUNCE_BLOCK, block.serialize())
        await self._broadcast(msg)

    async def _broadcast(self, msg: NetworkMessage):
        for addr, peer in self.peers.items():
            if peer.is_connected and peer.writer:
                try:
                    await write_message(peer.writer, msg)
                except Exception:
                    peer.is_connected = False


async def run(args):
    seed_nodes = []
    if args.seed:
        for s in args.seed:
            host, port = s.split(":")
            seed_nodes.append((host, int(port)))

    server = Server(
        p2p_port=args.port,
        rpc_port=args.rpc_port,
        seed_nodes=seed_nodes,
    )

    # Ask for wallet ID
    wallet_id = args.wallet
    if not wallet_id:
        print("Enter your wallet ID (entity_id hex) to receive block rewards and fees.")
        print("If you don't have one yet, use: python client.py create-account")
        print("You can also press Enter to run without a wallet (no rewards).\n")
        wallet_id = input("Wallet ID: ").strip()

    if wallet_id:
        server.set_wallet(wallet_id)

    await server.start()

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        await server.stop()


def main():
    parser = argparse.ArgumentParser(description="MessageChain Server")
    parser.add_argument("--port", type=int, default=9333, help="P2P port (default: 9333)")
    parser.add_argument("--rpc-port", type=int, default=9334, help="RPC port for clients (default: 9334)")
    parser.add_argument("--seed", nargs="*", help="Seed nodes (host:port)")
    parser.add_argument("--wallet", type=str, help="Wallet ID hex (skip interactive prompt)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
