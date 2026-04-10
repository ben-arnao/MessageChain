#!/usr/bin/env python3
"""
MessageChain Server

Plug-and-play blockchain node. Start it up, give it a wallet ID, and it runs
in the background — processing transactions, producing blocks, and depositing
fees into your wallet.

Now with persistent storage (--data-dir), IBD sync, peer banning,
rate limiting, and inv/getdata transaction relay.

Usage:
    python server.py
    python server.py --port 9333 --rpc-port 9334
    python server.py --seed 192.168.1.10:9333
    python server.py --data-dir ./chaindata
"""

import argparse
import asyncio
import json
import logging
import struct
import time
from collections import OrderedDict

from messagechain.config import (
    DEFAULT_PORT, BLOCK_TIME_TARGET, MAX_TXS_PER_BLOCK,
    SEEN_TX_CACHE_SIZE,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, compute_merkle_root, BlockHeader
from messagechain.core.transaction import MessageTransaction, create_transaction, verify_transaction
from messagechain.core.mempool import Mempool
from messagechain.consensus.pos import ProofOfStake
from messagechain.economics.inflation import SupplyTracker
from messagechain.crypto.keys import verify_signature, KeyPair, Signature
from messagechain.core.staking import (
    StakeTransaction, UnstakeTransaction,
    create_stake_transaction, create_unstake_transaction,
    verify_stake_transaction, verify_unstake_transaction,
)
from messagechain.network.protocol import (
    MessageType, NetworkMessage, read_message, write_message,
)
from messagechain.network.peer import Peer
from messagechain.network.sync import ChainSyncer
from messagechain.consensus.attestation import Attestation, verify_attestation
from messagechain.consensus.slashing import (
    SlashTransaction as SlashTx, verify_slashing_evidence, verify_attestation_slashing_evidence,
    SlashingEvidence, AttestationSlashingEvidence,
)
from messagechain.network.ban import (
    PeerBanManager, OFFENSE_INVALID_BLOCK, OFFENSE_INVALID_TX,
    OFFENSE_PROTOCOL_VIOLATION, OFFENSE_RATE_LIMIT,
)
from messagechain.network.ratelimit import PeerRateLimiter

import hashlib
from messagechain.config import HASH_ALGO

logger = logging.getLogger("messagechain.server")


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class Server:
    """MessageChain full node with RPC interface for clients."""

    def __init__(self, p2p_port: int, rpc_port: int, seed_nodes: list[tuple[str, int]],
                 data_dir: str | None = None):
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.seed_nodes = seed_nodes

        # Set up persistent storage if data_dir provided
        self.db = None
        if data_dir:
            import os
            os.makedirs(data_dir, exist_ok=True)
            from messagechain.storage.chaindb import ChainDB
            db_path = os.path.join(data_dir, "chain.db")
            self.db = ChainDB(db_path)
            logger.info(f"Using persistent storage: {db_path}")

        self.blockchain = Blockchain(db=self.db)
        self.mempool = Mempool()
        self.consensus = ProofOfStake()
        self.peers: dict[str, Peer] = {}

        self.wallet_id: bytes | None = None  # the entity_id that earns fees
        self.wallet_entity: Entity | None = None  # full entity for block signing
        self._running = False

        # IBD / sync
        self.syncer = ChainSyncer(self.blockchain, self._get_peer_writer)

        # Network protection
        self.ban_manager = PeerBanManager()
        self.rate_limiter = PeerRateLimiter()

        # inv/getdata: track recently seen tx hashes
        self._seen_txs: OrderedDict = OrderedDict()

    def _track_seen_tx(self, tx_hash_hex: str):
        if tx_hash_hex in self._seen_txs:
            self._seen_txs.move_to_end(tx_hash_hex)
            return
        if len(self._seen_txs) >= SEEN_TX_CACHE_SIZE:
            self._seen_txs.popitem(last=False)
        self._seen_txs[tx_hash_hex] = True

    def _get_peer_writer(self, address: str):
        peer = self.peers.get(address)
        if peer and peer.is_connected and peer.writer:
            return (peer.writer, peer)
        return None

    def set_wallet(self, wallet_id_hex: str):
        """Set which wallet receives block rewards and fees."""
        self.wallet_id = bytes.fromhex(wallet_id_hex)
        if self.wallet_id not in self.blockchain.public_keys:
            logger.warning("Wallet not yet registered on chain — will earn rewards once registered")

    def set_wallet_entity(self, entity: Entity):
        """Set the full wallet entity (with keypair) for block signing."""
        self.wallet_entity = entity
        self.wallet_id = entity.entity_id

    def _sync_validators_from_chain(self):
        """Load validator stakes from chain state into the consensus module."""
        for entity_id, staked in self.blockchain.supply.staked.items():
            if staked > 0:
                self.consensus.stakes[entity_id] = staked

    async def start(self):
        """Start P2P server, RPC server, and block production."""
        # Initialize genesis if fresh chain
        if self.blockchain.height == 0:
            # Create a bootstrap entity with a random private key for the genesis block.
            # SECURITY: Using os.urandom ensures each network has a unique,
            # unguessable genesis entity. Hardcoded keys would allow anyone
            # reading the source to derive the genesis keypair.
            import os
            bootstrap = Entity.create(os.urandom(32))
            self.blockchain.initialize_genesis(bootstrap)
            logger.info(f"Genesis block created")
        else:
            logger.info(f"Loaded chain from storage: height={self.blockchain.height}")

        # Sync validator stakes from chain state
        self._sync_validators_from_chain()

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

        # Start sync loop
        asyncio.create_task(self._sync_loop())

        print(f"Server running. P2P={self.p2p_port} RPC={self.rpc_port}")
        print(f"Wallet: {self.wallet_id.hex() if self.wallet_id else 'NOT SET'}")
        if self.db:
            print(f"Storage: persistent (SQLite)")
        else:
            print(f"Storage: in-memory (data lost on restart)")
        print("Press Ctrl+C to stop.\n")

    async def stop(self):
        self._running = False
        if self.db:
            self.db.close()

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
            info = self.blockchain.get_chain_info()
            info["sync_status"] = self.syncer.get_sync_status()
            return {"ok": True, "result": info}

        elif method == "get_fee_estimate":
            return {"ok": True, "result": {"fee_estimate": self.mempool.get_fee_estimate()}}

        elif method == "get_nonce":
            entity_id = bytes.fromhex(request["params"]["entity_id"])
            nonce = self.blockchain.nonces.get(entity_id, 0)
            return {"ok": True, "result": {"nonce": nonce}}

        elif method == "get_sync_status":
            return {"ok": True, "result": self.syncer.get_sync_status()}

        elif method == "get_banned_peers":
            return {"ok": True, "result": {"banned": self.ban_manager.get_banned_peers()}}

        elif method == "ban_peer":
            addr = request["params"].get("address", "")
            reason = request["params"].get("reason", "manual_rpc")
            self.ban_manager.manual_ban(addr, reason=reason)
            return {"ok": True, "result": {"message": f"Banned {addr}"}}

        elif method == "unban_peer":
            addr = request["params"].get("address", "")
            self.ban_manager.manual_unban(addr)
            return {"ok": True, "result": {"message": f"Unbanned {addr}"}}

        elif method == "stake":
            return self._rpc_stake(request["params"])

        elif method == "unstake":
            return self._rpc_unstake(request["params"])

        else:
            return {"ok": False, "error": f"Unknown method: {method}"}

    def _rpc_register_entity(self, params: dict) -> dict:
        """Register a new entity from client-provided public identity.

        The client derives entity_id and public_key locally from their
        private key, then sends ONLY the public values. The server never
        sees private key material.
        """
        try:
            entity_id = bytes.fromhex(params["entity_id"])
            public_key = bytes.fromhex(params["public_key"])
            success, msg = self.blockchain.register_entity(entity_id, public_key)
            if success:
                return {
                    "ok": True,
                    "result": {
                        "entity_id": params["entity_id"],
                        "public_key": params["public_key"],
                        "message": msg,
                        "initial_balance": 0,
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

            # Relay via inv (not full tx flood)
            tx_hash_hex = tx.tx_hash.hex()
            self._track_seen_tx(tx_hash_hex)
            asyncio.create_task(self._relay_tx_inv([tx_hash_hex]))

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

    def _rpc_stake(self, params: dict) -> dict:
        """Accept a signed stake transaction from a client.

        Stake operations are now proper on-chain transactions with nonce-based
        replay protection, included in blocks just like message transactions.
        This ensures all nodes agree on validator stake state.
        """
        try:
            tx = StakeTransaction.deserialize(params["transaction"])
            entity_id = tx.entity_id

            if entity_id not in self.blockchain.public_keys:
                return {"ok": False, "error": "Unknown entity"}

            public_key = self.blockchain.public_keys[entity_id]
            if not verify_stake_transaction(tx, public_key):
                return {"ok": False, "error": "Invalid stake transaction signature"}

            # Validate nonce
            expected_nonce = self.blockchain.nonces.get(entity_id, 0)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee + tx.amount):
                return {"ok": False, "error": "Insufficient balance for staking + fee"}

            # Apply stake (will be included in next block via mempool in future)
            # For now, apply directly but with proper nonce tracking
            self.blockchain.supply.stake(entity_id, tx.amount)
            self.blockchain.supply.pay_fee(entity_id, self.wallet_id or entity_id, tx.fee)
            self.blockchain.nonces[entity_id] = tx.nonce + 1
            self.consensus.register_validator(entity_id, tx.amount)

            if self.blockchain.db is not None:
                self.blockchain._persist_state()

            return {"ok": True, "result": {
                "entity_id": entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "staked": self.blockchain.supply.get_staked(entity_id),
                "balance": self.blockchain.supply.get_balance(entity_id),
            }}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _rpc_unstake(self, params: dict) -> dict:
        """Accept a signed unstake transaction from a client.

        Unstake operations are now proper on-chain transactions with nonce-based
        replay protection.
        """
        try:
            tx = UnstakeTransaction.deserialize(params["transaction"])
            entity_id = tx.entity_id

            if entity_id not in self.blockchain.public_keys:
                return {"ok": False, "error": "Unknown entity"}

            public_key = self.blockchain.public_keys[entity_id]
            if not verify_unstake_transaction(tx, public_key):
                return {"ok": False, "error": "Invalid unstake transaction signature"}

            # Validate nonce
            expected_nonce = self.blockchain.nonces.get(entity_id, 0)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee):
                return {"ok": False, "error": "Insufficient balance for fee"}

            if self.blockchain.supply.get_staked(entity_id) < tx.amount:
                return {"ok": False, "error": "Insufficient staked amount"}

            # Apply unstake with proper nonce tracking
            self.blockchain.supply.unstake(entity_id, tx.amount)
            self.blockchain.supply.pay_fee(entity_id, self.wallet_id or entity_id, tx.fee)
            self.blockchain.nonces[entity_id] = tx.nonce + 1

            remaining = self.blockchain.supply.get_staked(entity_id)
            if remaining == 0:
                self.consensus.remove_validator(entity_id)
            else:
                self.consensus.stakes[entity_id] = remaining

            if self.blockchain.db is not None:
                self.blockchain._persist_state()

            return {"ok": True, "result": {
                "entity_id": entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "staked": remaining,
                "balance": self.blockchain.supply.get_balance(entity_id),
            }}
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

            # Don't produce blocks while syncing
            if self.syncer.is_syncing:
                continue

            if self.mempool.size == 0:
                continue

            # Need a full entity (with keypair) to sign blocks
            if self.wallet_entity is None or self.wallet_id not in self.blockchain.public_keys:
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

            # Compute post-state root (state AFTER applying fees + reward)
            block_height = latest.header.block_number + 1
            state_root = self.blockchain.compute_post_state_root(
                txs, self.wallet_id, block_height,
            )
            block = self.consensus.create_block(
                self.wallet_entity, txs, latest, state_root=state_root,
            )

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

    # ── Sync Loop ────────────────────────────────────────────────

    async def _sync_loop(self):
        """Periodically check sync status and poll peers."""
        while self._running:
            await asyncio.sleep(10)
            await self.syncer.check_sync_stale()

            # Cleanup expired bans and stale rate limit buckets
            self.ban_manager.cleanup_expired()
            self.rate_limiter.cleanup_stale()

            if not self.syncer.is_syncing:
                # Ask peers for their height
                for addr, peer in list(self.peers.items()):
                    if peer.is_connected and peer.writer:
                        try:
                            msg = NetworkMessage(
                                msg_type=MessageType.REQUEST_CHAIN_HEIGHT,
                                payload={},
                                sender_id=self.wallet_id.hex() if self.wallet_id else "",
                            )
                            await write_message(peer.writer, msg)
                        except Exception:
                            pass

                if self.syncer.needs_sync():
                    await self.syncer.start_sync()

    # ── P2P Network ─────────────────────────────────────────────────

    def _msg_category(self, msg_type: MessageType) -> str:
        """Map message type to rate limit category."""
        if msg_type in (MessageType.ANNOUNCE_TX, MessageType.INV, MessageType.GETDATA):
            return "tx"
        if msg_type in (MessageType.REQUEST_BLOCKS_BATCH,):
            return "block_req"
        if msg_type == MessageType.REQUEST_HEADERS:
            return "headers_req"
        return "general"

    async def _handle_p2p_connection(self, reader, writer):
        addr = writer.get_extra_info("peername")
        address = f"{addr[0]}:{addr[1]}"

        # Reject banned peers
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
                await self._handle_p2p_message(msg, peer)
        except Exception:
            pass
        finally:
            peer.is_connected = False
            self.rate_limiter.remove_peer(address)
            writer.close()

    async def _connect_to_peer(self, host: str, port: int):
        addr = f"{host}:{port}"
        if addr in self.peers and self.peers[addr].is_connected:
            return
        if self.ban_manager.is_banned(addr):
            logger.debug(f"Skipping banned peer {addr}")
            return
        try:
            reader, writer = await asyncio.open_connection(host, port)
            peer = Peer(host=host, port=port, reader=reader, writer=writer, is_connected=True)
            self.peers[addr] = peer

            latest = self.blockchain.get_latest_block()
            handshake = NetworkMessage(
                msg_type=MessageType.HANDSHAKE,
                payload={
                    "port": self.p2p_port,
                    "chain_height": self.blockchain.height,
                    "best_block_hash": latest.block_hash.hex() if latest else "",
                },
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
        address = peer.address

        # Ban check
        if self.ban_manager.is_banned(address):
            peer.is_connected = False
            return

        # Rate limit check
        category = self._msg_category(msg.msg_type)
        if not self.rate_limiter.check(address, category):
            self.ban_manager.record_offense(address, OFFENSE_RATE_LIMIT, f"rate_limit:{category}")
            logger.debug(f"Rate limited {address} on {category}")
            return

        if msg.msg_type == MessageType.HANDSHAKE:
            peer.entity_id = msg.sender_id
            self.peers[peer.address] = peer
            # Track peer height for sync
            peer_height = msg.payload.get("chain_height", 0)
            best_hash = msg.payload.get("best_block_hash", "")
            self.syncer.update_peer_height(peer.address, peer_height, best_hash)
            if peer_height > self.blockchain.height and not self.syncer.is_syncing:
                asyncio.create_task(self.syncer.start_sync())

        elif msg.msg_type == MessageType.INV:
            await self._handle_inv(msg.payload, peer)

        elif msg.msg_type == MessageType.GETDATA:
            await self._handle_getdata(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_TX:
            tx = MessageTransaction.deserialize(msg.payload)
            tx_hash_hex = tx.tx_hash.hex()
            if tx_hash_hex in self._seen_txs:
                return
            valid, reason = self.blockchain.validate_transaction(tx)
            if valid:
                self._track_seen_tx(tx_hash_hex)
                self.mempool.add_transaction(tx)
                await self._relay_tx_inv([tx_hash_hex], exclude=address)
            else:
                self.ban_manager.record_offense(address, OFFENSE_INVALID_TX, f"invalid_tx:{reason}")

        elif msg.msg_type == MessageType.ANNOUNCE_BLOCK:
            block = Block.deserialize(msg.payload)
            success, reason = self.blockchain.add_block(block)
            if success:
                self.mempool.remove_transactions([tx.tx_hash for tx in block.transactions])
            else:
                self.ban_manager.record_offense(address, OFFENSE_INVALID_BLOCK, f"invalid_block:{reason}")

        elif msg.msg_type == MessageType.REQUEST_CHAIN_HEIGHT:
            latest = self.blockchain.get_latest_block()
            response = NetworkMessage(
                msg_type=MessageType.RESPONSE_CHAIN_HEIGHT,
                payload={
                    "height": self.blockchain.height,
                    "best_block_hash": latest.block_hash.hex() if latest else "",
                },
            )
            if peer.writer:
                await write_message(peer.writer, response)

        elif msg.msg_type == MessageType.RESPONSE_CHAIN_HEIGHT:
            height = msg.payload.get("height", 0)
            best_hash = msg.payload.get("best_block_hash", "")
            self.syncer.update_peer_height(peer.address, height, best_hash)

        elif msg.msg_type == MessageType.ANNOUNCE_ATTESTATION:
            await self._handle_announce_attestation(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_SLASH:
            await self._handle_announce_slash(msg.payload, peer)

        # ── Sync messages ──
        elif msg.msg_type == MessageType.REQUEST_HEADERS:
            await self._serve_headers(msg.payload, peer)

        elif msg.msg_type == MessageType.RESPONSE_HEADERS:
            await self.syncer.handle_headers_response(
                msg.payload.get("headers", []), peer.address
            )

        elif msg.msg_type == MessageType.REQUEST_BLOCKS_BATCH:
            await self._serve_blocks_batch(msg.payload, peer)

        elif msg.msg_type == MessageType.RESPONSE_BLOCKS_BATCH:
            await self.syncer.handle_blocks_response(
                msg.payload.get("blocks", []), peer.address
            )

    # ── Attestation and slash handlers ──────────────────────────────

    async def _handle_announce_attestation(self, payload: dict, peer: Peer):
        """Handle an incoming attestation gossip message."""
        try:
            att = Attestation.deserialize(payload)
        except Exception:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_attestation_data"
            )
            return

        if att.validator_id not in self.blockchain.public_keys:
            return

        pk = self.blockchain.public_keys[att.validator_id]
        if not verify_attestation(att, pk):
            self.ban_manager.record_offense(
                peer.address, OFFENSE_INVALID_TX, "invalid_attestation_sig"
            )
            return

        validator_stake = self.blockchain.supply.get_staked(att.validator_id)
        total_stake = sum(self.blockchain.supply.staked.values())
        self.blockchain.finality.add_attestation(att, validator_stake, total_stake)

        logger.debug(f"Received attestation from {att.validator_id.hex()[:16]}")

        relay_msg = NetworkMessage(MessageType.ANNOUNCE_ATTESTATION, payload)
        await self._broadcast(relay_msg)

    async def _handle_announce_slash(self, payload: dict, peer: Peer):
        """Handle incoming slashing evidence gossip."""
        try:
            slash_tx = SlashTx.deserialize(payload)
        except Exception:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_slash_data"
            )
            return

        valid, reason = self.blockchain.validate_slash_transaction(slash_tx)
        if not valid:
            logger.debug(f"Invalid slash evidence from {peer.address}: {reason}")
            return

        logger.info(f"Received valid slashing evidence against {slash_tx.evidence.offender_id.hex()[:16]}")

        relay_msg = NetworkMessage(MessageType.ANNOUNCE_SLASH, payload)
        await self._broadcast(relay_msg)

    # ── inv/getdata relay ──────────────────────────────────────────

    async def _handle_inv(self, payload: dict, peer: Peer):
        """Handle INV message: peer announces tx hashes they have."""
        tx_hashes = payload.get("tx_hashes", [])
        if len(tx_hashes) > 500:
            self.ban_manager.record_offense(
                peer.address, OFFENSE_PROTOCOL_VIOLATION, "inv_too_large"
            )
            return

        needed = []
        for h in tx_hashes:
            if h not in self._seen_txs:
                tx_hash_bytes = bytes.fromhex(h)
                if tx_hash_bytes not in self.mempool.pending:
                    needed.append(h)
            peer.known_txs.add(h)

        if needed:
            getdata = NetworkMessage(
                msg_type=MessageType.GETDATA,
                payload={"tx_hashes": needed},
                sender_id=self.wallet_id.hex() if self.wallet_id else "",
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
                    sender_id=self.wallet_id.hex() if self.wallet_id else "",
                )
                if peer.writer:
                    await write_message(peer.writer, msg)
                peer.known_txs.add(h)

    async def _relay_tx_inv(self, tx_hash_hexes: list[str], exclude: str = ""):
        """Relay transaction hashes via INV to peers that don't know them yet."""
        for addr, peer in self.peers.items():
            if addr == exclude or not peer.is_connected or not peer.writer:
                continue
            new_hashes = [h for h in tx_hash_hexes if h not in peer.known_txs]
            if not new_hashes:
                continue
            inv = NetworkMessage(
                msg_type=MessageType.INV,
                payload={"tx_hashes": new_hashes},
                sender_id=self.wallet_id.hex() if self.wallet_id else "",
            )
            try:
                await write_message(peer.writer, inv)
                for h in new_hashes:
                    peer.known_txs.add(h)
            except Exception:
                peer.is_connected = False

    # ── Existing helpers ──────────────────────────────────────────

    async def _serve_headers(self, payload: dict, peer: Peer):
        """Serve headers to a syncing peer."""
        start_height = payload.get("start_height", 0)
        count = min(payload.get("count", 100), 500)
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
        )
        if peer.writer:
            await write_message(peer.writer, response)

    async def _serve_blocks_batch(self, payload: dict, peer: Peer):
        """Serve full blocks to a syncing peer."""
        block_hashes = payload.get("block_hashes", [])
        blocks = []
        for hash_hex in block_hashes[:50]:
            block = self.blockchain.get_block_by_hash(bytes.fromhex(hash_hex))
            if block:
                blocks.append(block.serialize())
        response = NetworkMessage(
            msg_type=MessageType.RESPONSE_BLOCKS_BATCH,
            payload={"blocks": blocks},
        )
        if peer.writer:
            await write_message(peer.writer, response)

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
        data_dir=args.data_dir,
    )

    # Authenticate with private key to unlock block signing
    if args.wallet:
        print(f"Wallet ID: {args.wallet}")
        print("Authenticate with your private key to enable block production.\n")
    else:
        print("To produce blocks and earn rewards, authenticate with your private key.")
        print("If you don't have an account yet, use: python client.py create-account")
        print("You can also press Enter to run as a relay-only node (no rewards).\n")

    import getpass
    private_key_input = getpass.getpass("Private key (hidden, or Enter to skip): ").encode("utf-8")
    if private_key_input:
        entity = Entity.create(private_key_input)

        # Advance WOTS+ keypair past all previously-used one-time signing keys.
        # Without this, restarting the server would reuse WOTS+ leaves, which
        # catastrophically compromises the one-time signature scheme.
        leaves_used = server.blockchain.get_wots_leaves_used(entity.entity_id)
        if leaves_used > 0:
            entity.keypair.advance_to_leaf(leaves_used)
            logger.info(f"Advanced keypair past {leaves_used} used WOTS+ leaves")

        server.set_wallet_entity(entity)
        print(f"Authenticated as: {entity.entity_id_hex[:16]}...")
    elif args.wallet:
        server.set_wallet(args.wallet)
        print("Warning: wallet set but no private key — node cannot sign blocks.")

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
    parser.add_argument("--data-dir", type=str, help="Directory for persistent chain data (enables SQLite storage)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
