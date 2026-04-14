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
import hmac
import json
import logging
import os
import struct
import time
from collections import OrderedDict

from messagechain.config import (
    DEFAULT_PORT, MAX_TXS_PER_BLOCK,
    SEEN_TX_CACHE_SIZE, TRUSTED_CHECKPOINTS,
    OUTBOUND_FULL_RELAY_SLOTS, OUTBOUND_BLOCK_RELAY_ONLY_SLOTS,
    HANDSHAKE_TIMEOUT, MAX_PEERS,
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
from messagechain.core.transfer import (
    TransferTransaction, verify_transfer_transaction,
)
from messagechain.network.protocol import (
    MessageType, NetworkMessage, read_message, write_message,
)
from messagechain.consensus.checkpoint import load_checkpoints_file
from messagechain.network.peer import Peer, ConnectionType
from messagechain.network.addrman import AddressManager
from messagechain.network.anchor import AnchorStore
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
from messagechain.validation import parse_hex, sanitize_error, safe_json_loads
from messagechain.network.ratelimit import RPCRateLimiter

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

        # Network protection — must exist before syncer for the offense callback
        self.ban_manager = PeerBanManager()
        self.rate_limiter = PeerRateLimiter()

        # Sybil-resistant address manager (was previously dead code)
        self.addrman = AddressManager()

        # Persistent anchor peers — survive restarts to defeat reboot-time
        # eclipse attacks (BTC PR #17428).
        import os as _os
        anchor_path = (
            _os.path.join(data_dir, "anchors.json")
            if data_dir
            else _os.path.join(_os.getcwd(), "anchors.json")
        )
        self.anchor_store = AnchorStore(anchor_path)

        # IBD / sync — checkpoints come from data_dir/checkpoints.json
        # (operator-shipped) plus the TRUSTED_CHECKPOINTS config.
        checkpoints = list(TRUSTED_CHECKPOINTS)
        if data_dir:
            cp_path = _os.path.join(data_dir, "checkpoints.json")
            file_cps = load_checkpoints_file(cp_path)
            by_height = {cp.block_number: cp for cp in checkpoints}
            for cp in file_cps:
                by_height[cp.block_number] = cp
            checkpoints = list(by_height.values())
        self.syncer = ChainSyncer(
            self.blockchain,
            self._get_peer_writer,
            trusted_checkpoints=checkpoints,
            on_peer_offense=self._on_sync_offense,
        )

        # RPC rate limiting
        self.rpc_rate_limiter = RPCRateLimiter(max_requests=60, window_seconds=60.0)

        # RPC authentication — generate a random token if none configured.
        # Any RPC client must include {"auth": "<token>"} in requests.
        from messagechain.config import RPC_AUTH_ENABLED, RPC_AUTH_TOKEN
        self.rpc_auth_enabled = RPC_AUTH_ENABLED
        if RPC_AUTH_ENABLED:
            import os as _rng
            self.rpc_auth_token = RPC_AUTH_TOKEN or _rng.urandom(32).hex()
            logger.info(f"RPC auth enabled. Token: {self.rpc_auth_token[:8]}...")

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

    def _on_sync_offense(self, peer_address: str, points: int, reason: str):
        """Callback for sync-time misbehavior (checkpoint mismatch, stall)."""
        self.ban_manager.record_offense(peer_address, points, reason)

    def _current_cumulative_weight(self) -> int:
        """Our best-tip cumulative stake weight, for handshakes."""
        best = self.blockchain.fork_choice.get_best_tip()
        return best[2] if best else 0

    def _accept_peer_weight(self, claimed: int) -> int:
        """Sanity-cap a peer-reported cumulative weight. See Node._accept_peer_weight."""
        from messagechain.network.node import (
            PEER_WEIGHT_CAP_MULTIPLIER, PEER_WEIGHT_CAP_FLOOR,
        )
        if not isinstance(claimed, int) or claimed < 0:
            return 0
        cap = max(
            PEER_WEIGHT_CAP_FLOOR,
            self._current_cumulative_weight() * PEER_WEIGHT_CAP_MULTIPLIER,
        )
        return min(claimed, cap)

    def _next_connection_type(self) -> ConnectionType:
        """Decide the ConnectionType for the next outbound slot."""
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
            if self.wallet_entity is not None:
                # Use the operator's entity as genesis — they get the genesis allocation
                # and become the first validator.
                self.blockchain.initialize_genesis(self.wallet_entity)
                logger.info(
                    f"Genesis block created (genesis entity: "
                    f"{self.wallet_entity.entity_id.hex()[:16]}...)"
                )
            else:
                # Relay-only node with no chain data — cannot create genesis without
                # a keypair to sign the genesis block.  Must sync from a seed node.
                logger.info("No chain data and no wallet — will sync genesis from peers")
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

        # Reconnect to anchor peers first (restart-time eclipse defense)
        for host, port in self.anchor_store.load_anchors():
            asyncio.create_task(self._connect_to_peer(host, port))

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
        # Persist block-relay-only peers as anchors for next startup
        anchors = [
            (p.host, p.port)
            for p in self.peers.values()
            if p.is_connected and p.connection_type == ConnectionType.BLOCK_RELAY_ONLY
        ][:OUTBOUND_BLOCK_RELAY_ONLY_SLOTS]
        if anchors:
            self.anchor_store.save_anchors(anchors)
        if self.db:
            self.db.close()

    # ── RPC Handler (client interface) ──────────────────────────────

    async def _handle_rpc_connection(self, reader, writer):
        """Handle a client RPC request."""
        try:
            # Rate limit by client IP
            addr = writer.get_extra_info("peername")
            client_ip = addr[0] if addr else "unknown"
            if not self.rpc_rate_limiter.check(client_ip):
                resp = json.dumps({"ok": False, "error": "Rate limited"}).encode("utf-8")
                writer.write(struct.pack(">I", len(resp)))
                writer.write(resp)
                await writer.drain()
                return

            length_bytes = await reader.readexactly(4)
            length = struct.unpack(">I", length_bytes)[0]
            if length > 1_000_000:  # 1MB limit (reduced from 10MB)
                writer.close()
                return
            data = await reader.readexactly(length)
            request = safe_json_loads(data.decode("utf-8"), max_depth=16)

            # RPC authentication — constant-time comparison to prevent timing attacks
            if self.rpc_auth_enabled:
                token = request.get("auth", "")
                if not isinstance(token, str) or not hmac.compare_digest(
                    token.encode(), self.rpc_auth_token.encode()
                ):
                    resp = json.dumps({"ok": False, "error": "Authentication required"}).encode("utf-8")
                    writer.write(struct.pack(">I", len(resp)))
                    writer.write(resp)
                    await writer.drain()
                    return

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
            entity_id = parse_hex(request["params"].get("entity_id", ""))
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id hex"}
            nonce = self.blockchain.nonces.get(entity_id, 0)
            watermark = self.blockchain.get_leaf_watermark(entity_id)
            # Return both together so clients only need one roundtrip to
            # safely position their WOTS+ keypair before signing. The
            # leaf watermark is the authoritative source of truth for
            # "next safe leaf index" — the nonce is not, because some
            # operations (registration, block production, attestations)
            # consume leaves without incrementing the nonce.
            return {"ok": True, "result": {"nonce": nonce, "leaf_watermark": watermark}}

        elif method == "get_leaf_watermark":
            entity_id = parse_hex(request["params"].get("entity_id", ""))
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id hex"}
            watermark = self.blockchain.get_leaf_watermark(entity_id)
            return {"ok": True, "result": {"leaf_watermark": watermark}}

        elif method == "get_authority_key":
            entity_id = parse_hex(request["params"].get("entity_id", ""))
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id hex"}
            ak = self.blockchain.get_authority_key(entity_id)
            return {"ok": True, "result": {
                "authority_key": ak.hex() if ak else None,
            }}

        elif method == "set_authority_key":
            return self._rpc_set_authority_key(request["params"])

        elif method == "emergency_revoke":
            return self._rpc_emergency_revoke(request["params"])

        elif method == "is_revoked":
            entity_id = parse_hex(request["params"].get("entity_id", ""))
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id hex"}
            return {"ok": True, "result": {"revoked": self.blockchain.is_revoked(entity_id)}}

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

        elif method == "submit_transfer":
            return self._rpc_submit_transfer(request["params"])

        elif method == "submit_delegation":
            return self._rpc_submit_delegation(request["params"])

        elif method == "submit_proposal":
            return self._rpc_submit_proposal(request["params"])

        elif method == "submit_vote":
            return self._rpc_submit_vote(request["params"])

        elif method == "get_messages":
            count = request.get("params", {}).get("count", 10)
            count = min(count, 100)  # cap to prevent abuse
            messages = self.blockchain.get_recent_messages(count)
            return {"ok": True, "result": {"messages": messages}}

        else:
            return {"ok": False, "error": f"Unknown method: {method}"}

    def _rpc_register_entity(self, params: dict) -> dict:
        """Register a new entity from client-provided public identity.

        The client derives entity_id and public_key locally from their
        private key, then sends the public values plus a registration proof
        (signature over SHA3-256("register" || entity_id)). The server
        never sees private key material.
        """
        try:
            from messagechain.crypto.keys import Signature
            entity_id = parse_hex(params.get("entity_id", ""))
            public_key = parse_hex(params.get("public_key", ""))
            if entity_id is None or public_key is None:
                return {"ok": False, "error": "Invalid hex in entity_id or public_key"}

            proof_data = params.get("registration_proof")
            proof = None
            if proof_data is not None:
                proof = Signature.deserialize(proof_data)

            success, msg = self.blockchain.register_entity(entity_id, public_key, registration_proof=proof)
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
            return {"ok": False, "error": sanitize_error(str(e))}

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
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_stake(self, params: dict) -> dict:
        """Accept a signed stake transaction from a client.

        Validates the transaction and queues it for inclusion in the next
        block. State is only mutated when the block containing this
        transaction is produced and validated — never directly from RPC.
        This ensures all nodes agree on validator stake state.
        """
        try:
            tx = StakeTransaction.deserialize(params["transaction"])
            entity_id = tx.entity_id

            if entity_id not in self.blockchain.public_keys:
                return {"ok": False, "error": "Unknown entity"}

            public_key = self.blockchain.public_keys[entity_id]
            if not verify_stake_transaction(tx, public_key, block_height=self.blockchain.height):
                return {"ok": False, "error": "Invalid stake transaction signature"}

            # Validate nonce
            expected_nonce = self.blockchain.nonces.get(entity_id, 0)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if tx.signature.leaf_index < self.blockchain.get_leaf_watermark(entity_id):
                return {"ok": False, "error": "WOTS+ leaf already consumed — leaf reuse rejected"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee + tx.amount):
                return {"ok": False, "error": "Insufficient balance for staking + fee"}

            # Queue for block inclusion — do NOT mutate state directly.
            # State changes only happen when a block containing this tx is
            # produced and validated, ensuring all peers see the same state.
            if not hasattr(self, '_pending_stake_txs'):
                self._pending_stake_txs = {}
            self._pending_stake_txs[tx.tx_hash] = tx

            return {"ok": True, "result": {
                "entity_id": entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_unstake(self, params: dict) -> dict:
        """Accept a signed unstake transaction from a client.

        Validates the transaction and queues it for inclusion in the next
        block. State is only mutated when the block containing this
        transaction is produced and validated — never directly from RPC.
        """
        try:
            tx = UnstakeTransaction.deserialize(params["transaction"])
            entity_id = tx.entity_id

            if entity_id not in self.blockchain.public_keys:
                return {"ok": False, "error": "Unknown entity"}

            # Unstake is an authority-gated operation: it requires the cold
            # authority key, not the hot signing key. If the entity has not
            # promoted a separate cold key, authority_key == signing key and
            # this resolves to the same behavior as before.
            authority_key = self.blockchain.get_authority_key(entity_id)
            if not verify_unstake_transaction(tx, authority_key):
                return {"ok": False, "error": "Invalid unstake signature — unstake must be signed by the authority (cold) key"}

            # Validate nonce
            expected_nonce = self.blockchain.nonces.get(entity_id, 0)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if tx.signature.leaf_index < self.blockchain.get_leaf_watermark(entity_id):
                return {"ok": False, "error": "WOTS+ leaf already consumed — leaf reuse rejected"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee):
                return {"ok": False, "error": "Insufficient balance for fee"}

            if self.blockchain.supply.get_staked(entity_id) < tx.amount:
                return {"ok": False, "error": "Insufficient staked amount"}

            # Queue for block inclusion — do NOT mutate state directly.
            if not hasattr(self, '_pending_unstake_txs'):
                self._pending_unstake_txs = {}
            self._pending_unstake_txs[tx.tx_hash] = tx

            return {"ok": True, "result": {
                "entity_id": entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_set_authority_key(self, params: dict) -> dict:
        """Accept a SetAuthorityKey transaction, promoting a cold key for the entity.

        Applied to state immediately (not queued via the block pipeline)
        because there is no stake-weight or ordering-dependent side effect —
        the only change is a dictionary field in chain state, protected by
        the signing-key signature on the tx itself.
        """
        try:
            from messagechain.core.authority_key import SetAuthorityKeyTransaction
            tx = SetAuthorityKeyTransaction.deserialize(params["transaction"])
            proposer_id = parse_hex(params.get("proposer_id", "")) or tx.entity_id
            ok, reason = self.blockchain.apply_set_authority_key(tx, proposer_id)
            if not ok:
                return {"ok": False, "error": reason}
            # Persist authority-keys table so the change survives restart.
            if self.blockchain.db is not None and hasattr(self.blockchain.db, 'set_authority_key'):
                self.blockchain.db.set_authority_key(tx.entity_id, tx.new_authority_key)
                self.blockchain.db.flush_state()
            return {"ok": True, "result": {
                "entity_id": tx.entity_id.hex(),
                "authority_key": tx.new_authority_key.hex(),
                "tx_hash": tx.tx_hash.hex(),
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_emergency_revoke(self, params: dict) -> dict:
        """Apply an emergency RevokeTransaction signed by the cold authority key.

        Applied immediately to chain state (same as SetAuthorityKey) rather
        than queued — a validator operator has declared the hot key
        compromised, and every second the revoke stays pending is another
        second the attacker can sign blocks.
        """
        try:
            from messagechain.core.emergency_revoke import RevokeTransaction
            tx = RevokeTransaction.deserialize(params["transaction"])
            proposer_id = parse_hex(params.get("proposer_id", "")) or tx.entity_id
            ok, reason = self.blockchain.apply_revoke(tx, proposer_id)
            if not ok:
                return {"ok": False, "error": reason}
            return {"ok": True, "result": {
                "entity_id": tx.entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "revoked": True,
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_submit_delegation(self, params: dict) -> dict:
        """Accept a signed delegation transaction from a client.

        Validates the transaction and queues it for inclusion in the next
        block. State is only mutated when the block containing this
        transaction is produced and validated — never directly from RPC.
        """
        try:
            from messagechain.governance.governance import (
                DelegateTransaction, verify_delegation,
            )
            tx = DelegateTransaction.deserialize(params["transaction"])
            entity_id = tx.delegator_id

            if entity_id not in self.blockchain.public_keys:
                return {"ok": False, "error": "Entity not registered"}

            public_key = self.blockchain.public_keys[entity_id]
            if not verify_delegation(tx, public_key):
                return {"ok": False, "error": "Invalid delegation transaction"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee):
                return {"ok": False, "error": "Insufficient balance for fee"}

            # Queue for block inclusion — do NOT mutate state directly.
            if not hasattr(self, '_pending_governance_txs'):
                self._pending_governance_txs = {}
            self._pending_governance_txs[tx.tx_hash] = tx

            targets_info = [
                {"delegate_id": did.hex(), "pct": pct}
                for did, pct in tx.targets
            ]
            return {"ok": True, "result": {
                "entity_id": entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "targets": targets_info,
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_submit_proposal(self, params: dict) -> dict:
        """Accept a signed governance proposal from a client.

        Validates the transaction and queues it for inclusion in the next
        block. State is only mutated when the block containing this
        transaction is produced and validated — never directly from RPC.
        """
        try:
            from messagechain.governance.governance import (
                ProposalTransaction, verify_proposal,
            )
            tx = ProposalTransaction.deserialize(params["transaction"])
            entity_id = tx.proposer_id

            if entity_id not in self.blockchain.public_keys:
                return {"ok": False, "error": "Entity not registered"}

            public_key = self.blockchain.public_keys[entity_id]
            if not verify_proposal(tx, public_key):
                return {"ok": False, "error": "Invalid proposal transaction"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee):
                return {"ok": False, "error": "Insufficient balance for fee"}

            # Queue for block inclusion — do NOT mutate state directly.
            if not hasattr(self, '_pending_governance_txs'):
                self._pending_governance_txs = {}
            self._pending_governance_txs[tx.tx_hash] = tx

            return {"ok": True, "result": {
                "proposal_id": tx.proposal_id.hex(),
                "title": tx.title,
                "fee": tx.fee,
                "tx_hash": tx.tx_hash.hex(),
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_submit_vote(self, params: dict) -> dict:
        """Accept a signed governance vote from a client.

        Validates the transaction and queues it for inclusion in the next
        block. State is only mutated when the block containing this
        transaction is produced and validated — never directly from RPC.
        """
        try:
            from messagechain.governance.governance import (
                VoteTransaction, verify_vote,
            )
            tx = VoteTransaction.deserialize(params["transaction"])
            entity_id = tx.voter_id

            if entity_id not in self.blockchain.public_keys:
                return {"ok": False, "error": "Entity not registered"}

            public_key = self.blockchain.public_keys[entity_id]
            if not verify_vote(tx, public_key):
                return {"ok": False, "error": "Invalid vote transaction"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee):
                return {"ok": False, "error": "Insufficient balance for fee"}

            # Queue for block inclusion — do NOT mutate state directly.
            if not hasattr(self, '_pending_governance_txs'):
                self._pending_governance_txs = {}
            self._pending_governance_txs[tx.tx_hash] = tx

            return {"ok": True, "result": {
                "tx_hash": tx.tx_hash.hex(),
                "proposal_id": tx.proposal_id.hex(),
                "approve": tx.approve,
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_submit_transfer(self, params: dict) -> dict:
        """Accept a signed transfer transaction from a client."""
        try:
            tx = TransferTransaction.deserialize(params["transaction"])
            valid, reason = self.blockchain.validate_transfer_transaction(tx)
            if not valid:
                return {"ok": False, "error": reason}
            self.mempool.add_transaction(tx)

            tx_hash_hex = tx.tx_hash.hex()
            self._track_seen_tx(tx_hash_hex)
            asyncio.create_task(self._relay_tx_inv([tx_hash_hex]))

            return {
                "ok": True,
                "result": {
                    "tx_hash": tx.tx_hash.hex(),
                    "amount": tx.amount,
                    "fee": tx.fee,
                    "message": "Transfer accepted into mempool",
                },
            }
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_get_entity(self, params: dict) -> dict:
        entity_id = parse_hex(params.get("entity_id", ""))
        if entity_id is None:
            return {"ok": False, "error": "Invalid entity_id hex"}
        if entity_id not in self.blockchain.public_keys:
            return {"ok": False, "error": "Entity not found"}
        return {"ok": True, "result": self.blockchain.get_entity_stats(entity_id)}

    # ── Block Production ────────────────────────────────────────────

    async def _block_production_loop(self):
        """Slot-aligned block production. Fees + rewards go to the configured wallet.

        Shares timing/rotation/RANDAO logic with messagechain/network/node.py
        via messagechain.consensus.block_producer so the two implementations
        cannot drift.
        """
        from messagechain.consensus import block_producer

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

        if self.syncer.is_syncing:
            return

        # Need a full entity (with keypair) to sign blocks
        if self.wallet_entity is None or self.wallet_id not in self.blockchain.public_keys:
            return

        ok, round_number, _reason = block_producer.should_propose(
            self.blockchain, self.consensus, self.wallet_id,
        )
        if not ok:
            return

        # Build the block. Empty mempool is fine — empty blocks carry
        # attestations and advance block-denominated timers.
        all_pending = self.mempool.get_transactions(MAX_TXS_PER_BLOCK)
        txs = [t for t in all_pending if isinstance(t, MessageTransaction)]
        transfer_txs = [t for t in all_pending if isinstance(t, TransferTransaction)]
        slash_txs = self.mempool.get_slash_transactions()

        block = self.blockchain.propose_block(
            self.consensus, self.wallet_entity, txs,
            transfer_transactions=transfer_txs,
            slash_transactions=slash_txs,
        )

        success, reason = self.blockchain.add_block(block)
        if success:
            if all_pending:
                self.mempool.remove_transactions([tx.tx_hash for tx in all_pending])
            if slash_txs:
                self.mempool.remove_slash_transactions(
                    [s.tx_hash for s in slash_txs]
                )
            total_fees = sum(tx.fee for tx in all_pending)
            balance = self.blockchain.supply.get_balance(self.wallet_id)
            logger.info(
                f"Block #{block.header.block_number} | "
                f"{len(txs)} txs | fees: {total_fees} | round: {round_number} | "
                f"reward: {self.blockchain.supply.calculate_block_reward(block.header.block_number)} | "
                f"wallet balance: {balance}"
            )
            await self._broadcast_block(block)
        else:
            logger.warning(f"Failed to add proposed block: {reason}")
            if block_producer.is_clock_skew_reason(reason):
                logger.warning(
                    "This may indicate your system clock is out of sync. "
                    "Check your OS time settings."
                )

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
        """Map message type to rate limit category.

        Delegates to the shared dispatch module so Node and Server can
        never drift on rate-limit policy (they did in the past).
        """
        from messagechain.network.dispatch import message_category
        return message_category(msg_type)

    async def _handle_p2p_connection(self, reader, writer):
        addr = writer.get_extra_info("peername")
        address = f"{addr[0]}:{addr[1]}"

        # Reject banned peers
        if self.ban_manager.is_banned(address):
            logger.info(f"Rejected banned peer {address}")
            writer.close()
            return

        # H4: MAX_PEERS enforcement — reject if at capacity
        connected_count = sum(1 for p in self.peers.values() if p.is_connected)
        if connected_count >= MAX_PEERS:
            logger.debug(f"Rejecting inbound peer {address}: at MAX_PEERS ({MAX_PEERS})")
            writer.close()
            return

        peer = Peer(host=addr[0], port=addr[1], reader=reader, writer=writer, is_connected=True)
        # C10: timeout on reads to prevent slow-loris DoS
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
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=HANDSHAKE_TIMEOUT,
            )
            conn_type = self._next_connection_type()
            peer = Peer(
                host=host, port=port, reader=reader, writer=writer,
                is_connected=True, connection_type=conn_type,
            )
            self.peers[addr] = peer

            latest = self.blockchain.get_latest_block()
            handshake = NetworkMessage(
                msg_type=MessageType.HANDSHAKE,
                payload={
                    "port": self.p2p_port,
                    "chain_height": self.blockchain.height,
                    "best_block_hash": latest.block_hash.hex() if latest else "",
                    "cumulative_weight": self._current_cumulative_weight(),
                },
                sender_id=self.wallet_id.hex() if self.wallet_id else "",
            )
            await write_message(writer, handshake)
            while self._running and peer.is_connected:
                try:
                    msg = await asyncio.wait_for(read_message(reader), timeout=300)
                except asyncio.TimeoutError:
                    logger.debug(f"Peer {addr} read timed out")
                    break
                if msg is None:
                    break
                await self._handle_p2p_message(msg, peer)
        except asyncio.TimeoutError:
            logger.debug(f"Peer connection timed out {addr}")
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
            # H3: Basic handshake validation
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

            peer.entity_id = sender_id
            self.peers[peer.address] = peer
            # Track peer height AND cumulative weight for sync
            best_hash = msg.payload.get("best_block_hash", "")
            peer_weight_raw = msg.payload.get("cumulative_weight", 0)
            if not isinstance(peer_weight_raw, int) or peer_weight_raw < 0:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_cumulative_weight"
                )
                return
            peer_weight = self._accept_peer_weight(peer_weight_raw)
            self.syncer.update_peer_height(
                peer.address, peer_height, best_hash,
                cumulative_weight=peer_weight,
            )
            if peer_height > self.blockchain.height and not self.syncer.is_syncing:
                asyncio.create_task(self.syncer.start_sync())

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
            try:
                block = Block.deserialize(msg.payload)
            except Exception:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_block_data"
                )
                return
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
                    "cumulative_weight": self._current_cumulative_weight(),
                },
            )
            if peer.writer:
                await write_message(peer.writer, response)

        elif msg.msg_type == MessageType.RESPONSE_CHAIN_HEIGHT:
            height = msg.payload.get("height", 0)
            best_hash = msg.payload.get("best_block_hash", "")
            weight = self._accept_peer_weight(msg.payload.get("cumulative_weight", 0))
            self.syncer.update_peer_height(
                peer.address, height, best_hash, cumulative_weight=weight,
            )

        elif msg.msg_type == MessageType.PEER_LIST:
            # C2: Populate addrman from peer gossip
            addresses = msg.payload.get("addresses", [])
            for entry in addresses[:1000]:
                host = entry.get("host", "")
                port = entry.get("port", 0)
                if isinstance(host, str) and isinstance(port, int):
                    if 1 <= port <= 65535:
                        self.addrman.add_address(host, port, peer.host)

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

        # H6: Deduplicate — skip if already seen (prevents gossip amplification
        # and redundant expensive signature verification)
        att_key = (att.validator_id, att.block_number, att.block_hash)
        if not hasattr(self, '_seen_attestations'):
            self._seen_attestations: OrderedDict = OrderedDict()
        if att_key in self._seen_attestations:
            return
        # LRU eviction instead of full wipe (M11 pattern)
        if len(self._seen_attestations) >= 50_000:
            # Evict oldest 25%
            for _ in range(12_500):
                self._seen_attestations.popitem(last=False)
        self._seen_attestations[att_key] = True

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
        self.blockchain.finality.add_attestation(
            att, validator_stake, total_stake,
            public_keys=self.blockchain.public_keys,
        )

        logger.debug(f"Received attestation from {att.validator_id.hex()[:16]}")

        relay_msg = NetworkMessage(MessageType.ANNOUNCE_ATTESTATION, payload)
        await self._broadcast(relay_msg)

    async def _handle_announce_slash(self, payload: dict, peer: Peer):
        """Handle incoming slashing evidence gossip.

        Pools the slash tx so this node includes it in its next proposed
        block, then relays to peers (only on first sight, to avoid loops).
        """
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

        logger.info(
            f"Received valid slashing evidence against "
            f"{slash_tx.evidence.offender_id.hex()[:16]}"
        )

        added = self.mempool.add_slash_transaction(slash_tx)
        if added:
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

        # H9: Per-hash rate limiting — consume extra tokens for large batches
        extra_tokens = len(tx_hashes) // 50
        if extra_tokens > 0:
            ip = self.rate_limiter._get_ip(peer.address)
            self.rate_limiter._ensure_buckets(ip)
            bucket = self.rate_limiter._buckets[ip].get("tx")
            if bucket and not bucket.consume(extra_tokens):
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_RATE_LIMIT, "inv_hash_flood"
                )
                return

        needed = []
        for h in tx_hashes:
            if h not in self._seen_txs:
                try:
                    tx_hash_bytes = bytes.fromhex(h)
                except (ValueError, TypeError):
                    self.ban_manager.record_offense(
                        peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_inv_hash"
                    )
                    return
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
            try:
                tx_hash_bytes = bytes.fromhex(h)
            except (ValueError, TypeError):
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_getdata_hash"
                )
                return
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
        if not isinstance(start_height, int) or start_height < 0:
            start_height = 0
        # Clamp to current chain height to avoid pointless iteration
        start_height = min(start_height, self.blockchain.height + 1)
        count = payload.get("count", 100)
        if not isinstance(count, int) or count < 0:
            count = 0
        count = min(count, 500)
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
            try:
                block_hash_bytes = bytes.fromhex(hash_hex)
            except (ValueError, TypeError):
                self.ban_manager.record_offense(
                    peer.address, OFFENSE_PROTOCOL_VIOLATION, "invalid_block_hash_hex"
                )
                return
            block = self.blockchain.get_block_by_hash(block_hash_bytes)
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
