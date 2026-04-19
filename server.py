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
import hashlib as _hashlib
import sys
import hmac
import json
import logging
import os
import struct
import time
from collections import OrderedDict

from messagechain.config import (
    DEFAULT_PORT, MAX_TXS_PER_BLOCK,
    SEEN_TX_CACHE_SIZE, TRUSTED_CHECKPOINTS, REQUIRE_CHECKPOINTS,
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
from messagechain.consensus.attestation import (
    Attestation, attest_block_if_allowed, verify_attestation,
)
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
from messagechain.validation import (
    parse_hex, sanitize_error, safe_json_loads,
    is_valid_peer_address as _is_valid_peer_address,
)
from messagechain.network.ratelimit import RPCRateLimiter

logger = logging.getLogger("messagechain.server")

# RPC methods that require the operator's auth token (RPC_AUTH_TOKEN).
# Everything else is public — tx submissions are already gated by the
# WOTS+ signature on the tx itself, so no auth is needed there.  This
# split lets a public validator accept remote signed txs while still
# protecting operational commands (ban_peer, etc.) from unauthorized
# callers.
_ADMIN_RPC_METHODS = frozenset({
    "ban_peer",
    "unban_peer",
    "get_banned_peers",
})


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# ---------------------------------------------------------------------------
# Keypair disk cache — eliminates costly WOTS+ Merkle-tree regeneration on
# restart.  The keypair is deterministic (same private key + tree height
# always yields the same tree), so the cached result is safe to reuse.
#
# On-disk format:
#     [4 B magic "MCKC"] [32 B HMAC-SHA3-256] [JSON payload]
#
# The HMAC is keyed on the validator's private key.  Any tamper — byte
# flip, swapped file, stale format — fails authentication and the
# cache is treated as corrupt (deleted, regenerated).  This replaced an
# earlier pickle-based cache: pickle.load on an attacker-planted file
# is arbitrary code execution as the validator user, the worst
# possible blast radius for a file sitting next to hot-key material.
# ---------------------------------------------------------------------------


def _keypair_cache_path(private_key: bytes, tree_height: int, data_dir: str) -> str:
    """Return the filesystem path for a cached keypair.

    The filename embeds a truncated SHA3-256 digest of (private_key ||
    tree_height) so that different keys or heights never collide, and the
    raw private key never appears in the filename.
    """
    h = _hashlib.sha3_256(private_key + tree_height.to_bytes(4, "big")).hexdigest()[:16]
    return os.path.join(data_dir, f"keypair_cache_{h}.bin")


def _merkle_cache_path(private_key: bytes, tree_height: int, data_dir: str) -> str:
    """Filesystem path for the Merkle node cache (one per keypair).

    Separate from the keypair cache so old installations that lack the
    node cache can still load via the slow path.  Filename embeds the
    same private-key-dependent digest + height so rotating a key produces
    a new filename and the old cache is orphaned (then cleanable).
    """
    h = _hashlib.sha3_256(private_key + tree_height.to_bytes(4, "big")).hexdigest()[:16]
    return os.path.join(data_dir, f"merkle_cache_{h}.bin")


_CACHE_MAGIC = b"MCKC"  # MessageChain Keypair Cache (HMAC-authenticated)
_CACHE_FORMAT_VERSION = 1
_HMAC_SIZE = 32
_CACHE_HMAC_DOMAIN = b"messagechain-keypair-cache-v1|"


def _keypair_cache_mac_key(private_key: bytes) -> bytes:
    """Derive the HMAC key used to authenticate the cache payload.

    Domain-separated from any other use of the private key so that a
    future reuse of the key in a different context cannot produce a
    matching MAC.
    """
    return _hashlib.sha3_256(_CACHE_HMAC_DOMAIN + private_key).digest()


def _encode_keypair_cache(
    entity: Entity, private_key: bytes, tree_height: int
) -> bytes:
    payload_obj = {
        "version": _CACHE_FORMAT_VERSION,
        "tree_height": tree_height,
        "public_key": entity.keypair.public_key.hex(),
        "entity_id": entity.entity_id.hex(),
    }
    payload = json.dumps(
        payload_obj, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    mac = hmac.new(
        _keypair_cache_mac_key(private_key), payload, _hashlib.sha3_256
    ).digest()
    return _CACHE_MAGIC + mac + payload


def _decode_keypair_cache(
    data: bytes, private_key: bytes, tree_height: int
) -> "Entity | None":
    """Return a reconstructed Entity, or None for any malformed / unauthenticated blob.

    Every rejection path returns None silently: the caller deletes the
    file and regenerates.  No partial or differential information
    leaks from the loader.
    """
    header_len = len(_CACHE_MAGIC) + _HMAC_SIZE
    if len(data) < header_len:
        return None
    if not data.startswith(_CACHE_MAGIC):
        return None
    mac = data[len(_CACHE_MAGIC):header_len]
    payload = data[header_len:]
    expected = hmac.new(
        _keypair_cache_mac_key(private_key), payload, _hashlib.sha3_256
    ).digest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("version") != _CACHE_FORMAT_VERSION:
        return None
    if obj.get("tree_height") != tree_height:
        return None
    try:
        public_key = bytes.fromhex(obj["public_key"])
        entity_id = bytes.fromhex(obj["entity_id"])
    except (KeyError, ValueError, TypeError):
        return None
    if len(public_key) != 32 or len(entity_id) != 32:
        return None

    from messagechain.identity.identity import (
        _derive_signing_seed, derive_entity_id,
    )
    # Cross-check: even after the HMAC passes, the entity_id stored in
    # the payload must match what derive_entity_id(public_key) would
    # produce.  Cheap and catches any future format drift between the
    # two fields.
    if derive_entity_id(public_key) != entity_id:
        return None
    seed = _derive_signing_seed(private_key)
    keypair = KeyPair._from_trusted_root(seed, tree_height, public_key)
    return Entity(entity_id=entity_id, keypair=keypair, _seed=seed)


def _bind_leaf_index_path(entity: Entity, data_dir: str | None) -> None:
    """Attach the persistent leaf-index file to *entity*'s keypair.

    When *data_dir* is None (ephemeral / in-memory mode), the attribute
    stays None and sign() skips the write-ahead step — preserving existing
    test behavior.

    When a path is available, we bind it AND immediately load any
    previously-persisted counter so a restarted validator cannot reuse a
    WOTS+ leaf.  load_leaf_index refuses to move the counter backwards, so
    it's safe to call even when the in-memory _next_leaf is already ahead
    (for example, because advance_to_leaf() ran first based on the on-chain
    leaf watermark).
    """
    if data_dir is None:
        return
    from messagechain.config import LEAF_INDEX_FILENAME
    path = os.path.join(data_dir, LEAF_INDEX_FILENAME)
    entity.keypair.leaf_index_path = path
    entity.keypair.load_leaf_index(path)


def _load_or_create_entity(
    private_key: bytes,
    tree_height: int,
    data_dir: str | None,
    *,
    no_cache: bool = False,
) -> Entity:
    """Create an Entity, using a disk cache when possible.

    If *data_dir* is ``None`` or *no_cache* is ``True``, the cache is
    bypassed and the entity is created fresh every time.

    When *data_dir* is set, the entity's keypair is also bound to a
    persistent leaf-index file at ``<data_dir>/leaf_index.json`` so the
    WOTS+ one-time-key invariant survives restarts.
    """
    use_cache = data_dir is not None and not no_cache

    if use_cache:
        cache_file = _keypair_cache_path(private_key, tree_height, data_dir)

        # Cache hit path: read + HMAC-verify.  Any failure — missing
        # file, short read, wrong magic, bad MAC, malformed JSON,
        # wrong format version, tree-height mismatch — results in
        # delete-and-regenerate.  This is the pickle-safe replacement
        # for the previous pickle.load path: a planted pickle blob
        # fails the HMAC check and is dropped instead of executed.
        if os.path.exists(cache_file):
            entity = None
            try:
                with open(cache_file, "rb") as f:
                    blob = f.read()
                entity = _decode_keypair_cache(blob, private_key, tree_height)
            except OSError:
                entity = None
            if entity is not None:
                logger.info("Loaded keypair from cache %s", cache_file)
                _bind_leaf_index_path(entity, data_dir)
                return entity
            logger.warning(
                "Corrupt or unauthenticated keypair cache %s — deleting "
                "and regenerating",
                cache_file,
            )
            try:
                os.remove(cache_file)
            except OSError:
                pass

    # Fresh keygen
    entity = Entity.create(private_key, tree_height=tree_height)

    if use_cache:
        try:
            blob = _encode_keypair_cache(entity, private_key, tree_height)
            # Atomic write: serialize to a temp file, fsync, chmod, then
            # rename into place.  Guarantees a reader never sees a
            # truncated blob (which would fail the HMAC check and cause
            # a pointless regeneration on every subsequent restart).
            tmp_file = cache_file + ".tmp"
            with open(tmp_file, "wb") as f:
                f.write(blob)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            try:
                os.chmod(tmp_file, 0o600)
            except OSError:
                pass
            os.replace(tmp_file, cache_file)
            logger.info("Saved keypair cache to %s", cache_file)
        except OSError:
            logger.warning("Could not write keypair cache to %s", cache_file)

    _bind_leaf_index_path(entity, data_dir)
    _attach_merkle_node_cache(entity, private_key, tree_height, data_dir, no_cache)
    return entity


def _attach_merkle_node_cache(
    entity: Entity,
    private_key: bytes,
    tree_height: int,
    data_dir: str | None,
    no_cache: bool,
) -> None:
    """Load (or build + persist) the Merkle node cache and attach it to
    the entity's keypair.  Cache makes sign()'s auth-path step O(height)
    instead of O(2^height).

    On any failure (missing dir, disk error, corrupt blob, root mismatch)
    this silently leaves the keypair to use the slow seed-recomputation
    path — signatures stay correct, just slow.  The server stays
    functional even if the cache is unavailable.
    """
    from messagechain.crypto.merkle_cache import MerkleNodeCache

    if data_dir is None or no_cache:
        return
    cache_path = _merkle_cache_path(private_key, tree_height, data_dir)

    # The cache must be built over the SAME seed that KeyPair uses
    # internally, which is derived from private_key via Entity.create →
    # _derive_signing_seed (not the raw private_key).  entity.keypair
    # already holds this derived seed.  Passing private_key straight
    # through would produce a tree with a different root and the post-
    # build equality check would (correctly) refuse to attach the cache.
    tree_seed = entity.keypair._seed

    # Try load.
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                blob = f.read()
            cache = MerkleNodeCache.from_bytes(blob, private_key, tree_height)
        except OSError:
            cache = None
        if cache is not None and cache.root() == entity.keypair.public_key:
            entity.keypair._node_cache = cache
            logger.info("Loaded Merkle node cache from %s", cache_path)
            return
        # Any mismatch (corrupt, tampered, wrong root, wrong key) → drop.
        if cache is None:
            logger.warning(
                "Corrupt or unauthenticated Merkle cache %s — deleting "
                "and rebuilding", cache_path,
            )
        else:
            logger.warning(
                "Merkle cache root mismatch %s (key rotated?) — deleting "
                "and rebuilding", cache_path,
            )
        try:
            os.remove(cache_path)
        except OSError:
            pass

    # Build fresh.  This re-derives every leaf once — expensive for
    # height >= 20 but the keypair cache path just did the same work.
    # Future improvement: let KeyPair.__init__ populate a fresh cache
    # during keygen so we don't do it twice.
    logger.info(
        "Building Merkle node cache for height=%d (one-time cost)",
        tree_height,
    )
    try:
        cache = MerkleNodeCache.build_from_seed(tree_seed, tree_height)
    except Exception as e:
        logger.warning("Merkle cache build failed: %s", e)
        return

    # Defensive: the cache's root MUST equal the keypair's root.  If it
    # doesn't, the two computed the tree differently — never trust the
    # cache for signing in that case.
    if cache.root() != entity.keypair.public_key:
        logger.error(
            "Merkle cache root mismatch after build — refusing to attach",
        )
        return

    entity.keypair._node_cache = cache

    # Persist.
    try:
        blob = cache.to_bytes(private_key)
        tmp_file = cache_path + ".tmp"
        with open(tmp_file, "wb") as f:
            f.write(blob)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        try:
            os.chmod(tmp_file, 0o600)
        except OSError:
            pass
        os.replace(tmp_file, cache_path)
        logger.info(
            "Saved Merkle node cache (%.1f MB) to %s",
            len(blob) / 1024 / 1024, cache_path,
        )
    except OSError:
        logger.warning("Could not write Merkle cache to %s", cache_path)


class Server:
    """MessageChain full node with RPC interface for clients."""

    def __init__(self, p2p_port: int, rpc_port: int, seed_nodes: list[tuple[str, int]],
                 data_dir: str | None = None, rpc_bind: str = "127.0.0.1"):
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.rpc_bind = rpc_bind
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
        if REQUIRE_CHECKPOINTS and not checkpoints:
            # Young chains (< 1000 blocks) have nothing meaningful to
            # checkpoint against.  Auto-waive the requirement with a
            # warning instead of crashing — the long-range attack vector
            # is effectively theoretical when the chain is this fresh.
            # Once the chain matures past 1000 blocks, operators MUST
            # ship checkpoints or explicitly set REQUIRE_CHECKPOINTS=False.
            if self.blockchain.height < 1000:
                logger.warning(
                    "No weak-subjectivity checkpoints loaded but chain is "
                    "young (height=%d < 1000) — proceeding without. "
                    "Ship checkpoints before the chain crosses block 1000.",
                    self.blockchain.height,
                )
            else:
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

        # RPC rate limiting.  60 req/min was too tight for real workflows —
        # a typical session is balance -> nonce -> estimate_fee -> submit
        # (4 calls), and batched scripts hit the cap fast.  300/min (5/sec)
        # still bounds a single attacker's throughput well below what the
        # async event loop can handle while leaving headroom for legitimate
        # clients.  DoS protection is primarily the per-tx signature cost
        # and the rate limiter is a secondary guard.
        self.rpc_rate_limiter = RPCRateLimiter(max_requests=300, window_seconds=60.0)

        # RPC authentication — generate a random token if none configured.
        # Any RPC client must include {"auth": "<token>"} in requests.
        from messagechain.config import RPC_AUTH_ENABLED, RPC_AUTH_TOKEN
        self.rpc_auth_enabled = RPC_AUTH_ENABLED
        if RPC_AUTH_ENABLED:
            import os as _rng
            self.rpc_auth_token = RPC_AUTH_TOKEN or _rng.urandom(32).hex()
            self._log_rpc_auth_status()

        # inv/getdata: track recently seen tx hashes
        self._seen_txs: OrderedDict = OrderedDict()

    def _log_rpc_auth_status(self):
        # Never log any portion of the token. Operators retrieve it via
        # the configured RPC_AUTH_TOKEN env var or the keyfile, not logs.
        logger.info("RPC auth enabled")

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

    def _handle_task_exception(self, task_name: str, task: asyncio.Task) -> None:
        """Log uncaught exceptions from background tasks so they don't die silently.

        Without this callback, an exception escaping a ``create_task``-launched
        coroutine is swallowed by asyncio's default handler. The task dies, the
        server keeps running as a zombie (listening but not producing blocks or
        syncing), and in a PoS system with an inactivity leak, the operator's
        stake gets slowly drained to zero before anyone notices. Loud CRITICAL
        logging is the minimum viable alarm.
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
        # Announce the network identity loudly before any peer I/O.  If an
        # operator ever sees "NETWORK=testnet" in the logs of what they
        # thought was a mainnet validator, they spot the misconfiguration
        # before it matters.  The hex prefix of the pin lets them
        # cross-check against the canonical block-0 hash.
        import messagechain.config as _cfg
        _pin = getattr(_cfg, "PINNED_GENESIS_HASH", None)
        logger.info(
            "NETWORK=%s  pinned_genesis=%s",
            getattr(_cfg, "NETWORK_NAME", "<unset>"),
            _pin.hex()[:16] + "..." if _pin is not None else "<none>",
        )

        # Initialize genesis if fresh chain
        if self.blockchain.height == 0:
            pinned = _pin
            if pinned is not None:
                # Network has a pinned canonical genesis — this node must
                # sync block 0 from peers, not mint locally.  Only the
                # original founder who produced the pinned block is
                # allowed to call initialize_genesis, and that founder
                # does so via the dedicated launch_single_validator.py
                # runbook script, not via server auto-mint.  A newcomer
                # who reached this branch with a wallet set would have
                # their auto-mint rejected at blockchain.py anyway; we
                # short-circuit here to give them a clean relay-only start.
                logger.info(
                    "Genesis hash pinned by project config — will sync from peers"
                )
            elif self.wallet_entity is not None:
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

        # Start RPC server (for client commands).  Default bind is
        # 127.0.0.1 so a locally-running CLI is the only reachable client
        # and the box can't be hit by arbitrary internet traffic on the
        # RPC port.  Public-facing validators that want to accept remote
        # signed transactions pass --rpc-bind 0.0.0.0 at startup.
        rpc_server = await asyncio.start_server(
            self._handle_rpc_connection, self.rpc_bind, self.rpc_port
        )
        logger.info(f"RPC listening on {self.rpc_bind}:{self.rpc_port}")

        # Reconnect to anchor peers first (restart-time eclipse defense)
        for host, port in self.anchor_store.load_anchors():
            t = asyncio.create_task(self._connect_to_peer(host, port))
            t.add_done_callback(
                lambda x: self._handle_task_exception("connect_to_peer(anchor)", x)
            )

        # Connect to seed nodes
        for host, port in self.seed_nodes:
            t = asyncio.create_task(self._connect_to_peer(host, port))
            t.add_done_callback(
                lambda x: self._handle_task_exception("connect_to_peer(seed)", x)
            )

        # Start block production
        t = asyncio.create_task(self._block_production_loop())
        t.add_done_callback(
            lambda x: self._handle_task_exception("block_production_loop", x)
        )

        # Start sync loop
        t = asyncio.create_task(self._sync_loop())
        t.add_done_callback(
            lambda x: self._handle_task_exception("sync_loop", x)
        )

        logger.info(f"Server running. P2P={self.p2p_port} RPC={self.rpc_port}")
        logger.info(f"Wallet: {self.wallet_id.hex() if self.wallet_id else 'NOT SET'}")
        if self.db:
            logger.info("Storage: persistent (SQLite)")
        else:
            logger.info("Storage: in-memory (data lost on restart)")

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

            # Wrap readexactly in wait_for so a slow-loris client can't
            # pin this handler open forever.  30s is generous for a 4-byte
            # length prefix and whatever body fits in 1MB over a normal
            # network; anything slower is either broken or adversarial.
            # Without the timeout, an attacker opens a connection, drips
            # 1 byte every 60s, and consumes an event-loop slot indefinitely.
            try:
                length_bytes = await asyncio.wait_for(
                    reader.readexactly(4), timeout=30,
                )
                length = struct.unpack(">I", length_bytes)[0]
                if length > 1_000_000:  # 1MB limit (reduced from 10MB)
                    writer.close()
                    return
                data = await asyncio.wait_for(
                    reader.readexactly(length), timeout=30,
                )
            except asyncio.TimeoutError:
                writer.close()
                return
            request = safe_json_loads(data.decode("utf-8"), max_depth=16)

            # RPC authentication — only admin methods (ban_peer, unban_peer,
            # etc.) require the token.  Public methods (submit_transaction,
            # get_entity, etc.) are always accessible, since their state
            # mutations are already gated by WOTS+ signatures on the
            # transactions themselves.  This lets a public-facing validator
            # accept signed txs from anyone without also exposing admin ops.
            method = request.get("method", "")
            if self.rpc_auth_enabled and method in _ADMIN_RPC_METHODS:
                token = request.get("auth", "")
                if not isinstance(token, str) or not hmac.compare_digest(
                    token.encode(), self.rpc_auth_token.encode()
                ):
                    resp = json.dumps({"ok": False, "error": "Authentication required for admin method"}).encode("utf-8")
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
        # Any method that reaches a `request["params"]`-style access below
        # would KeyError if `params` is missing, bubbling up to the outer
        # except in _handle_rpc_connection as a bare connection close with
        # no response body.  Validate once here so every client gets a
        # clean structured error instead of a reset.
        if "params" not in request or not isinstance(request.get("params"), dict):
            request["params"] = {}

        if method == "submit_transaction":
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

        elif method == "rotate_key":
            return self._rpc_rotate_key(request["params"])

        elif method == "get_key_status":
            entity_id = parse_hex(request["params"].get("entity_id", ""))
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id hex"}
            # Current on-chain public key + rotation count + watermark together
            # tell a client how far through its current tree it is.
            return {"ok": True, "result": {
                "public_key": self.blockchain.public_keys.get(entity_id, b"").hex(),
                "rotation_number": self.blockchain.key_rotation_counts.get(entity_id, 0),
                "leaf_watermark": self.blockchain.get_leaf_watermark(entity_id),
            }}

        elif method == "get_sync_status":
            return {"ok": True, "result": self.syncer.get_sync_status()}

        elif method == "get_banned_peers":
            return {"ok": True, "result": {"banned": self.ban_manager.get_banned_peers()}}

        elif method == "ban_peer":
            addr = request["params"].get("address", "")
            reason = request["params"].get("reason", "manual_rpc")
            if not _is_valid_peer_address(addr):
                return {"ok": False, "error": "Invalid peer address (expected 'host:port')"}
            self.ban_manager.manual_ban(addr, reason=reason)
            return {"ok": True, "result": {"message": f"Banned {addr}"}}

        elif method == "unban_peer":
            addr = request["params"].get("address", "")
            if not _is_valid_peer_address(addr):
                return {"ok": False, "error": "Invalid peer address (expected 'host:port')"}
            self.ban_manager.manual_unban(addr)
            return {"ok": True, "result": {"message": f"Unbanned {addr}"}}

        elif method == "stake":
            return self._rpc_stake(request["params"])

        elif method == "unstake":
            return self._rpc_unstake(request["params"])

        elif method == "submit_transfer":
            return self._rpc_submit_transfer(request["params"])

        elif method == "submit_proposal":
            return self._rpc_submit_proposal(request["params"])

        elif method == "submit_vote":
            return self._rpc_submit_vote(request["params"])

        elif method == "get_messages":
            raw = request.get("params", {}).get("count", 10)
            # Coerce + clamp: a bare `min(count, 100)` neither rejected
            # non-integers (TypeError downstream) nor guarded negative /
            # zero values (caller could starve the reader thread).
            try:
                count = int(raw)
            except (TypeError, ValueError):
                return {"ok": False, "error": "Invalid count (expected integer)"}
            count = max(1, min(count, 100))
            messages = self.blockchain.get_recent_messages(count)
            return {"ok": True, "result": {"messages": messages}}

        elif method == "list_proposals":
            # Cap response size — a chain with thousands of proposals would
            # otherwise let any unauthenticated caller trigger a megabyte+
            # JSON serialization per RPC.  500 is large enough for any
            # realistic governance workload and small enough to keep
            # response time + bandwidth bounded.
            proposals = self.blockchain.governance.list_proposals(self.blockchain.height)
            truncated = len(proposals) > 500
            return {
                "ok": True,
                "result": {
                    "proposals": proposals[:500],
                    "truncated": truncated,
                    "total": len(proposals),
                },
            }

        elif method == "list_validators":
            # Same response-size cap rationale as list_proposals.  The
            # mainnet validator set will grow over time; without a cap the
            # whole set is serialized on every call.
            vals = self.blockchain.list_validators()
            truncated = len(vals) > 500
            return {
                "ok": True,
                "result": {
                    "validators": vals[:500],
                    "truncated": truncated,
                    "total": len(vals),
                },
            }

        elif method == "get_network_validators":
            return {"ok": True, "result": self._rpc_get_network_validators()}

        elif method == "estimate_fee":
            return self._rpc_estimate_fee(request.get("params", {}))

        else:
            return {"ok": False, "error": f"Unknown method: {method}"}

    def _rpc_submit_transaction(self, params: dict) -> dict:
        """Accept a signed transaction from a client."""
        try:
            tx = MessageTransaction.deserialize(params["transaction"])
            # Compute pending nonce across ALL pools so users can submit
            # sequential txs of any type (message, transfer, stake) without
            # waiting for each to be mined.
            pending_nonce = self._get_pending_nonce_all_pools(tx.entity_id)
            valid, reason = self.blockchain.validate_transaction(
                tx, expected_nonce=pending_nonce,
            )
            if not valid:
                return {"ok": False, "error": reason}
            # Record arrival height for the forced-inclusion rule.  Without
            # this, txs default to height 0 which makes them "always-
            # forced" — an attester that never updates arrival heights
            # would wrongly flag every new tx for immediate forced
            # inclusion and vote NO on every non-draining block.
            self.mempool.add_transaction(
                tx, arrival_block_height=self.blockchain.height,
            )

            # Relay via inv (not full tx flood)
            tx_hash_hex = tx.tx_hash.hex()
            self._track_seen_tx(tx_hash_hex)
            t = asyncio.create_task(self._relay_tx_inv([tx_hash_hex]))
            t.add_done_callback(
                lambda x: self._handle_task_exception("relay_tx_inv", x)
            )

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

            # Validate nonce — use pending nonce so consecutive submissions
            # are accepted without waiting for block inclusion.
            expected_nonce = self._get_pending_nonce_all_pools(entity_id)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if tx.signature.leaf_index < self.blockchain.get_leaf_watermark(entity_id):
                return {"ok": False, "error": "WOTS+ leaf already consumed — leaf reuse rejected"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee + tx.amount):
                return {"ok": False, "error": "Insufficient balance for staking + fee"}

            if not self._check_leaf_across_all_pools(tx):
                return {"ok": False, "error": "WOTS+ leaf already used by another pending tx — leaf reuse rejected"}

            # Queue for block inclusion — do NOT mutate state directly.
            # State changes only happen when a block containing this tx is
            # produced and validated, ensuring all peers see the same state.
            if not self._admit_to_pool("_pending_stake_txs", tx):
                return {"ok": False, "error": "Stake pool full — raise fee to evict a lower-priced pending tx"}
            self._schedule_pending_tx_gossip("stake", tx)

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

            # Validate nonce — use pending nonce so consecutive submissions
            # are accepted without waiting for block inclusion.
            expected_nonce = self._get_pending_nonce_all_pools(entity_id)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if tx.signature.leaf_index < self.blockchain.get_leaf_watermark(entity_id):
                return {"ok": False, "error": "WOTS+ leaf already consumed — leaf reuse rejected"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee):
                return {"ok": False, "error": "Insufficient balance for fee"}

            if self.blockchain.supply.get_staked(entity_id) < tx.amount:
                return {"ok": False, "error": "Insufficient staked amount"}

            if not self._check_leaf_across_all_pools(tx):
                return {"ok": False, "error": "WOTS+ leaf already used by another pending tx — leaf reuse rejected"}

            # Queue for block inclusion — do NOT mutate state directly.
            if not self._admit_to_pool("_pending_unstake_txs", tx):
                return {"ok": False, "error": "Unstake pool full — raise fee to evict a lower-priced pending tx"}
            self._schedule_pending_tx_gossip("unstake", tx)

            return {"ok": True, "result": {
                "entity_id": entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _sweep_stale_pending_txs(self) -> int:
        """Drop pool entries that can no longer land in a block.

        A pending tx becomes permanently unmineable if the entity's
        current chain nonce has moved past it, the sender is revoked,
        the signature leaf is below the current watermark, or the tx
        is older than PENDING_TX_TTL seconds.  Without this sweep, junk
        accumulates (protected by the pool-cap eviction policy because
        it often has high fees) and pushes legitimate new txs out.

        Returns the total number of entries dropped across all pools.
        Safe to call frequently — O(pool entries) which is bounded by
        PENDING_POOL_MAX_SIZE × number of pools.
        """
        from messagechain.config import PENDING_TX_TTL
        import time as _time

        now = _time.time()
        dropped = 0

        def _signer_id(tx):
            for attr in (
                "entity_id", "proposer_id", "voter_id", "submitter_id",
            ):
                eid = getattr(tx, attr, None)
                if eid is not None:
                    return eid
            return None

        def _is_stale(tx) -> bool:
            eid = _signer_id(tx)
            if eid is None:
                return True  # can't identify sender — drop

            # Revoked sender: any pending tx they signed with the hot
            # key is doomed.  RevokeTransaction targets an entity_id
            # that the authority key signs over; if the target is
            # already in revoked_entities the revoke is redundant.
            if eid in self.blockchain.revoked_entities:
                return True

            # Timestamp expiry — tx.timestamp is a float seconds.
            ts = getattr(tx, "timestamp", None)
            if ts is not None and now - ts > PENDING_TX_TTL:
                return True

            # Leaf below watermark — signature leaf_index already
            # consumed, tx can never pass validate_block.  Only applies
            # to txs that live in the HOT leaf namespace (entity_id
            # keyed).  Cold-signed txs (Revoke, Unstake when a
            # separate cold key exists) use a different watermark so
            # we skip the check for them.
            sig = getattr(tx, "signature", None)
            cls_name = tx.__class__.__name__
            is_cold_signed = (
                cls_name == "RevokeTransaction"
                or (
                    cls_name == "UnstakeTransaction"
                    and self.blockchain.get_authority_key(eid)
                    != self.blockchain.public_keys.get(eid)
                )
            )
            if sig is not None and not is_cold_signed:
                wm = self.blockchain.leaf_watermarks.get(eid, 0)
                if sig.leaf_index < wm:
                    return True

            # Nonce-stale — only for txs that carry a nonce.  Revoke
            # is nonce-free and handled above.
            tx_nonce = getattr(tx, "nonce", None)
            if tx_nonce is not None:
                chain_nonce = self.blockchain.nonces.get(eid, 0)
                if tx_nonce < chain_nonce:
                    return True

            return False

        for pool_attr in (
            "_pending_stake_txs", "_pending_unstake_txs",
            "_pending_authority_txs", "_pending_governance_txs",
        ):
            pool = getattr(self, pool_attr, None)
            if not pool:
                continue
            for h in [
                h for h, tx in pool.items() if _is_stale(tx)
            ]:
                del pool[h]
                dropped += 1
        return dropped

    def _get_pending_nonce_all_pools(self, entity_id: bytes) -> int:
        """Compute the next expected nonce for an entity across all pools.

        Scans the mempool AND the server-local pending pools (stake,
        unstake, authority, governance) so that consecutive submissions
        of any tx type use sequential nonces without waiting for block
        inclusion.
        """
        on_chain_nonce = self.blockchain.nonces.get(entity_id, 0)
        # Start from mempool's view (covers message + transfer txs).
        best = self.mempool.get_pending_nonce(entity_id, on_chain_nonce)
        # Extend with server-local pools.
        for pool_attr in (
            "_pending_stake_txs", "_pending_unstake_txs",
            "_pending_authority_txs", "_pending_governance_txs",
        ):
            pool = getattr(self, pool_attr, None)
            if not pool:
                continue
            for tx in pool.values():
                eid = getattr(tx, "entity_id", None)
                tx_nonce = getattr(tx, "nonce", None)
                if eid == entity_id and tx_nonce is not None and tx_nonce >= on_chain_nonce:
                    if tx_nonce + 1 > best:
                        best = tx_nonce + 1
        return best

    def _admit_to_pool(self, pool_attr: str, tx) -> bool:
        """Insert `tx` into a capped per-type pending pool with fee-based
        eviction, mirroring Mempool's admission policy.

        Returns True if the tx landed.  Returns False when the pool is
        full AND the incoming fee does not beat the lowest-fee pending
        tx — caller surfaces this as "pool full, raise your fee".

        Uniform across every non-message-tx pool so an attacker can't
        fill any single pool with cheap junk: they'd have to keep
        raising fees to maintain position.
        """
        from messagechain.config import PENDING_POOL_MAX_SIZE
        pool = getattr(self, pool_attr, None)
        if pool is None:
            pool = {}
            setattr(self, pool_attr, pool)
        if tx.tx_hash in pool:
            return True  # idempotent re-admit

        # Aggregate cap across ALL pending pools.  Without this, an attacker
        # can fill each pool individually for a total 4×PENDING_POOL_MAX_SIZE
        # memory footprint.  Count sitewide pending txs and refuse admission
        # if we're above the global cap unless incoming fee beats the global
        # lowest.
        _GLOBAL_CAP = PENDING_POOL_MAX_SIZE * 2  # 2x per-pool, not 4x
        all_pool_attrs = (
            "_pending_stake_txs", "_pending_unstake_txs",
            "_pending_authority_txs", "_pending_governance_txs",
            "_pending_registration_txs",
        )
        total_pending = 0
        global_min: tuple | None = None  # (fee, pool_attr, tx_hash)
        for attr in all_pool_attrs:
            p = getattr(self, attr, None)
            if not p:
                continue
            total_pending += len(p)
            for th, t in p.items():
                f = getattr(t, "fee", 0)
                if global_min is None or f < global_min[0]:
                    global_min = (f, attr, th)

        incoming_fee = getattr(tx, "fee", 0)

        if total_pending >= _GLOBAL_CAP:
            # At global cap — only accept if incoming beats the sitewide min.
            if global_min is None or incoming_fee <= global_min[0]:
                return False
            # Evict the sitewide min from its origin pool.
            _, ev_attr, ev_hash = global_min
            ev_pool = getattr(self, ev_attr, None)
            if ev_pool is not None and ev_hash in ev_pool:
                del ev_pool[ev_hash]

        if len(pool) >= PENDING_POOL_MAX_SIZE:
            min_tx = min(
                pool.values(),
                key=lambda t: getattr(t, "fee", 0),
            )
            if incoming_fee <= getattr(min_tx, "fee", 0):
                return False
            del pool[min_tx.tx_hash]
        pool[tx.tx_hash] = tx
        return True

    def _has_pending_stake_from(self, entity_id: bytes) -> bool:
        """Return True iff any pending stake tx in the local pool belongs
        to `entity_id`.

        Cheap guard that prevents auto-restake from stacking two sweep
        txs for the same entity when a second block fires before the
        first sweep was included.  A second stake tx with the same
        nonce would be rejected anyway (mempool nonce gate), but
        skipping at the source avoids pointless WOTS+ leaf consumption.
        """
        pool = getattr(self, "_pending_stake_txs", {}) or {}
        for tx in pool.values():
            if getattr(tx, "entity_id", None) == entity_id:
                return True
        return False

    def _maybe_auto_restake(self):
        """Node-local opt-in policy: convert surplus liquid into stake.

        Called after a successful `add_block` in `_try_produce_block_sync`.
        When config.AUTO_RESTAKE is off (the default), this is a no-op —
        a node that never flips the flag behaves identically to today.

        When enabled, the node sweeps its own liquid balance above
        AUTO_RESTAKE_LIQUID_BUFFER into a new StakeTransaction, but only
        if the amount after reserving the stake-tx fee clears
        AUTO_RESTAKE_MIN_AMOUNT.  The tx is admitted via the same
        `_admit_to_pool` path real RPC clients use, so every mempool
        invariant (nonce ordering, rate limiting, leaf dedupe, pool cap)
        still applies.

        Safety:
          * Never crashes block production — all exceptions are logged
            and swallowed.  Auto-restake is a convenience feature, not
            a correctness requirement.
          * Never double-submits — `_has_pending_stake_from` short-
            circuits when a sweep is already queued for this entity.
          * Never touches entities that aren't our own — the handle
            `self.wallet_entity` is the only key we can sign under.
          * Never builds a tx for an unregistered entity — the chain
            would reject it and we'd waste a WOTS+ leaf.
        """
        try:
            # Re-read config on every call so tests and operators can flip
            # the flag at runtime without restarting.
            from messagechain import config as _cfg
            if not getattr(_cfg, "AUTO_RESTAKE", False):
                return
            if self.wallet_entity is None:
                return  # observer mode — nothing to sign with
            eid = self.wallet_entity.entity_id
            if eid not in self.blockchain.public_keys:
                # Entity not yet registered — attempting a stake would be
                # rejected by the chain anyway.  Wait until first-spend
                # registration has happened.
                return
            if self._has_pending_stake_from(eid):
                return  # sweep already queued; don't stack another

            liquid = self.blockchain.supply.get_balance(eid)
            buffer_amt = getattr(_cfg, "AUTO_RESTAKE_LIQUID_BUFFER", 1_000)
            min_amt = getattr(_cfg, "AUTO_RESTAKE_MIN_AMOUNT", 1_000)
            fee = _cfg.MIN_FEE

            # Reserve fee on top of buffer — paying the stake tx's fee must
            # not push liquid below buffer after the tx applies.
            stakeable = liquid - buffer_amt - fee
            if stakeable < min_amt:
                return
            # VALIDATOR_MIN_STAKE applies to the tx amount, not to the
            # delta over existing stake.  If our sweep would be below the
            # min-stake floor, skip — a lower-value sweep would be
            # rejected at block apply time.
            if stakeable < _cfg.VALIDATOR_MIN_STAKE:
                return

            from messagechain.core.staking import create_stake_transaction
            nonce = self._get_pending_nonce_all_pools(eid)
            tx = create_stake_transaction(
                self.wallet_entity,
                amount=stakeable,
                nonce=nonce,
                fee=fee,
            )
            ok = self._admit_to_pool("_pending_stake_txs", tx)
            if ok:
                logger.info(
                    "AUTO_RESTAKE: queued stake tx for %d tokens "
                    "(kept %d liquid buffer, fee %d)",
                    stakeable, buffer_amt, fee,
                )
            else:
                logger.warning(
                    "AUTO_RESTAKE: pool full, sweep of %d tokens refused",
                    stakeable,
                )
        except Exception as e:
            # Broad except is intentional: a buggy sweep must NEVER take
            # down block production.  Log and move on — the operator can
            # inspect logs; the chain keeps running.
            logger.warning("AUTO_RESTAKE: sweep failed: %r", e)

    def _tx_signer_pubkey(self, tx) -> bytes | None:
        """Return the public key that `tx`'s signature verifies under.

        This is the correct dedupe key for WOTS+ leaf reuse: two
        signatures share a leaf namespace only when they were produced
        by the same key.  For hot-signed txs (message, transfer, stake,
        SetAuthorityKey, KeyRotation, governance) that's the entity's
        public_key.  For cold-key-gated txs (unstake, revoke) it's the
        authority_key — which may be identical to the public_key when
        no cold key has been promoted, or may be a totally different
        key in its own leaf namespace.

        Returning None means "can't resolve" — caller should skip this
        tx rather than fall back to a potentially-wrong key comparison.
        """
        # Cold-key-gated paths first: authority_key is the signer even
        # when it differs from the hot signing key.
        cls_name = tx.__class__.__name__
        if cls_name in ("RevokeTransaction", "UnstakeTransaction"):
            eid = getattr(tx, "entity_id", None)
            if eid is None:
                return None
            return self.blockchain.get_authority_key(eid)

        # Everything else signs with the entity's hot public_key.  Each
        # tx type names its sender field differently; try the common
        # ones in order of specificity.
        for attr in (
            "entity_id", "proposer_id", "voter_id", "submitter_id",
        ):
            eid = getattr(tx, attr, None)
            if eid is not None:
                return self.blockchain.public_keys.get(eid)
        return None

    def _check_leaf_across_all_pools(
        self, incoming_tx, leaf_index: int | None = None,
    ) -> bool:
        """Return True if no currently-pending tx shares this signer key
        and leaf_index with the incoming one.

        The dedupe key is (signer_public_key, leaf_index) — not
        (entity_id, leaf_index), because cold-key-signed txs (unstake,
        revoke) live in a different leaf namespace from hot-key-signed
        txs on the same entity.  Using entity_id would fire false
        positives when a hot-key tx and a cold-key tx happen to pick
        the same leaf_index, which is fine because they're in different
        trees.

        Backwards-compat: callers may pass a raw (entity_id_bytes,
        leaf_index) pair instead of a tx object — in that case we fall
        back to the entity_id-keyed comparison.  This keeps older call
        sites working while new ones (and the gossip receiver) get the
        stronger signer-key-based check.
        """
        if isinstance(incoming_tx, (bytes, bytearray)):
            # Legacy call shape: (entity_id, leaf_index).
            return self._check_leaf_by_entity_id(incoming_tx, leaf_index)

        incoming_signer = self._tx_signer_pubkey(incoming_tx)
        incoming_leaf = incoming_tx.signature.leaf_index
        if incoming_signer is None:
            # Unknown key — can't dedupe safely.  Reject to fail closed.
            return False

        for pool_attr in (
            "_pending_stake_txs", "_pending_unstake_txs",
            "_pending_authority_txs", "_pending_governance_txs",
        ):
            pool = getattr(self, pool_attr, {})
            for existing in pool.values():
                sig = getattr(existing, "signature", None)
                if sig is None:
                    continue
                existing_signer = self._tx_signer_pubkey(existing)
                if existing_signer is None:
                    continue
                if (
                    existing_signer == incoming_signer
                    and sig.leaf_index == incoming_leaf
                ):
                    return False
        # Mempool's internal guard covers message and transfer txs and
        # is already signer-agnostic (same-entity hot-only).
        return True

    def _check_leaf_by_entity_id(
        self, entity_id: bytes, leaf_index: int,
    ) -> bool:
        """Legacy entity-id-based dedupe path kept for call sites that
        don't have a tx object in hand.  Conservatively scans every
        pool for a matching (entity_id, leaf_index) pair regardless of
        whether the signer is hot or cold."""
        for pool_attr in (
            "_pending_stake_txs", "_pending_unstake_txs",
            "_pending_authority_txs", "_pending_governance_txs",
        ):
            pool = getattr(self, pool_attr, {})
            for existing in pool.values():
                sig = getattr(existing, "signature", None)
                for attr in (
                    "entity_id", "proposer_id", "voter_id", "submitter_id",
                ):
                    eid = getattr(existing, attr, None)
                    if eid is not None:
                        break
                if sig is None or eid is None:
                    continue
                if eid == entity_id and sig.leaf_index == leaf_index:
                    return False
        return True
        return True

    def _queue_authority_tx(self, tx, *, validate_fn) -> tuple[bool, str]:
        """Shared admission path for SetAuthorityKey / Revoke / KeyRotation.

        Validates the tx against current chain state (so mempool rejection
        gives a clear error), enqueues it for the next block, and gossips
        it to peers so a non-proposing receiver doesn't strand the tx.
        """
        ok, reason = validate_fn(tx)
        if not ok:
            return False, reason
        if not self._check_leaf_across_all_pools(tx):
            return False, "WOTS+ leaf already used by another pending tx — leaf reuse rejected"
        if not self._admit_to_pool("_pending_authority_txs", tx):
            return False, "Authority-tx pool full — raise fee to evict a lower-priced pending tx"
        self._schedule_pending_tx_gossip("authority", tx)
        return True, "queued"

    def _rpc_set_authority_key(self, params: dict) -> dict:
        """Accept a SetAuthorityKey transaction, promoting a cold key for the entity.

        Queued for block inclusion — the state change (cold-key binding)
        must be consensus-visible across every peer, otherwise an attacker
        who later compromises the hot key can unstake via any node that
        hasn't seen the promotion.
        """
        try:
            from messagechain.core.authority_key import SetAuthorityKeyTransaction
            tx = SetAuthorityKeyTransaction.deserialize(params["transaction"])
            ok, reason = self._queue_authority_tx(
                tx, validate_fn=self.blockchain.validate_set_authority_key,
            )
            if not ok:
                return {"ok": False, "error": reason}
            return {"ok": True, "result": {
                "entity_id": tx.entity_id.hex(),
                "authority_key": tx.new_authority_key.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_rotate_key(self, params: dict) -> dict:
        """Accept a KeyRotationTransaction for block-pipeline inclusion.

        Must be block-included so every peer updates its public_key
        mapping in lockstep — otherwise the owner's signatures under the
        new key would be rejected by peers still holding the old key.
        """
        try:
            from messagechain.core.key_rotation import KeyRotationTransaction
            tx = KeyRotationTransaction.deserialize(params["transaction"])
            ok, reason = self._queue_authority_tx(
                tx, validate_fn=self.blockchain.validate_key_rotation,
            )
            if not ok:
                return {"ok": False, "error": reason}
            return {"ok": True, "result": {
                "entity_id": tx.entity_id.hex(),
                "new_public_key": tx.new_public_key.hex(),
                "rotation_number": tx.rotation_number,
                "tx_hash": tx.tx_hash.hex(),
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_emergency_revoke(self, params: dict) -> dict:
        """Accept an emergency RevokeTransaction signed by the cold authority key.

        Queued for the next block. Without block-level propagation a
        revoke on one node would leave the compromised validator free
        to keep proposing blocks that other peers happily accept —
        the whole point of the kill-switch is network-wide effect.
        """
        try:
            from messagechain.core.emergency_revoke import RevokeTransaction
            tx = RevokeTransaction.deserialize(params["transaction"])
            ok, reason = self._queue_authority_tx(
                tx, validate_fn=self.blockchain.validate_revoke,
            )
            if not ok:
                return {"ok": False, "error": reason}
            return {"ok": True, "result": {
                "entity_id": tx.entity_id.hex(),
                "tx_hash": tx.tx_hash.hex(),
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

            if not self._check_leaf_across_all_pools(tx):
                return {"ok": False, "error": "WOTS+ leaf already used by another pending tx — leaf reuse rejected"}

            # Queue for block inclusion — do NOT mutate state directly.
            if not self._admit_to_pool("_pending_governance_txs", tx):
                return {"ok": False, "error": "Governance pool full — raise fee to evict a lower-priced pending tx"}
            self._schedule_pending_tx_gossip("governance", tx)

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

            if not self._check_leaf_across_all_pools(tx):
                return {"ok": False, "error": "WOTS+ leaf already used by another pending tx — leaf reuse rejected"}

            # Queue for block inclusion — do NOT mutate state directly.
            if not self._admit_to_pool("_pending_governance_txs", tx):
                return {"ok": False, "error": "Governance pool full — raise fee to evict a lower-priced pending tx"}
            self._schedule_pending_tx_gossip("governance", tx)

            return {"ok": True, "result": {
                "tx_hash": tx.tx_hash.hex(),
                "proposal_id": tx.proposal_id.hex(),
                "approve": tx.approve,
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_estimate_fee(self, params: dict) -> dict:
        """Price a prospective message or transfer without submitting.

        Returns:
          - min_fee: protocol floor (size-based for messages, MIN_FEE +
            NEW_ACCOUNT_FEE for transfers to brand-new recipients, else
            MIN_FEE).
          - mempool_fee: median of pending-tx fees (demand signal).
          - recommended_fee: max(min_fee, mempool_fee) — safe to submit now.
          - recipient_is_new (transfers only): True iff the target
            `recipient_id` does not yet exist on chain, so the client can
            display "+NEW_ACCOUNT_FEE surcharge (burned)" if it wants.

        For `kind=message`, the size curve dominates on long messages.
        For `kind=transfer`, pass `recipient_id` (hex) to get a surcharge-
        inclusive estimate when the recipient has no on-chain state yet.
        Omit `recipient_id` (or supply an invalid hex) to fall back to the
        legacy estimate that assumes an existing recipient.
        """
        from messagechain.core.transaction import calculate_min_fee
        from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE, MAX_MESSAGE_CHARS
        kind = params.get("kind", "message")
        recipient_is_new = False
        if kind == "message":
            msg = params.get("message", "")
            if not isinstance(msg, str):
                return {"ok": False, "error": "message must be a string"}
            if len(msg) > MAX_MESSAGE_CHARS:
                return {"ok": False, "error": f"Message exceeds {MAX_MESSAGE_CHARS} chars"}
            min_fee = calculate_min_fee(msg.encode("utf-8"))
        elif kind == "transfer":
            min_fee = MIN_FEE
            # Optional recipient_id: if provided and the recipient has no
            # on-chain state, the chain will require a NEW_ACCOUNT_FEE
            # surcharge on apply, so surface it here.
            recipient_id_hex = params.get("recipient_id")
            if recipient_id_hex:
                recipient_id = parse_hex(recipient_id_hex)
                if recipient_id is not None:
                    if self.blockchain._recipient_is_new(recipient_id):
                        recipient_is_new = True
                        min_fee += NEW_ACCOUNT_FEE
        else:
            return {"ok": False, "error": f"Unknown fee kind: {kind}"}

        mempool_fee = self.mempool.get_fee_estimate()
        result = {
            "min_fee": min_fee,
            "mempool_fee": mempool_fee,
            "recommended_fee": max(min_fee, mempool_fee),
            "recipient_is_new": recipient_is_new,
        }
        return {"ok": True, "result": result}

    def _rpc_submit_transfer(self, params: dict) -> dict:
        """Accept a signed transfer transaction from a client."""
        try:
            tx = TransferTransaction.deserialize(params["transaction"])
            # Pending nonce scans all pools (message + transfer + stake +
            # unstake + governance) so sequential tx of any type work.
            pending_nonce = self._get_pending_nonce_all_pools(tx.entity_id)
            valid, reason = self.blockchain.validate_transfer_transaction(
                tx, expected_nonce=pending_nonce,
            )
            if not valid:
                return {"ok": False, "error": reason}
            # Record arrival height — see _rpc_submit_transaction for rationale.
            self.mempool.add_transaction(
                tx, arrival_block_height=self.blockchain.height,
            )

            tx_hash_hex = tx.tx_hash.hex()
            self._track_seen_tx(tx_hash_hex)
            t = asyncio.create_task(self._relay_tx_inv([tx_hash_hex]))
            t.add_done_callback(
                lambda x: self._handle_task_exception("relay_tx_inv", x)
            )

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

    def _rpc_get_network_validators(self) -> dict:
        """Return validators with their client-reachable RPC endpoints.

        Joins on-chain stake data (validator_id + stake amount) with the
        server's live peer map (peer.entity_id -> peer.host:peer.port).
        Used by CLI clients to discover non-seed validators and route
        subsequent calls via sqrt(stake)-weighted random selection once
        the network has post-bootstrap participation.

        Validators with no currently-connected peer entry are returned
        without an endpoint — clients cannot route to them directly,
        but they still appear in the total stake denominator.

        Design note: IPs live in server memory (and optionally addrman),
        NOT on chain.  list_validators deliberately omits endpoints to
        keep targeting data off the permanent record; this RPC surfaces
        it only to actively-connected clients.
        """
        # Build peer.entity_id -> (host, port) map from currently-tracked peers
        peer_endpoints: dict[str, tuple[str, int]] = {}
        for peer in self.peers.values():
            if getattr(peer, "entity_id", None):
                # Peer port from handshake payload might differ from connection
                # port; prefer the advertised port when known.
                peer_endpoints[peer.entity_id] = (peer.host, peer.port)

        rows = self.blockchain.list_validators()
        for row in rows:
            endpoint = peer_endpoints.get(row.get("entity_id"))
            row["rpc_host"] = endpoint[0] if endpoint else None
            row["rpc_port"] = endpoint[1] if endpoint else None
        return {"validators": rows}

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

    def _try_produce_block_sync(self):
        """CPU-bound block production (runs in thread pool).

        Returns (block, success, reason, round_number) if a block was
        proposed, or None if this node should not propose right now.
        All CPU-heavy work (WOTS+ signing, state root, validation) lives
        here so it can run off the event loop via asyncio.to_thread().
        """
        from messagechain.consensus import block_producer

        if self.syncer.is_syncing:
            return None

        # Need a full entity (with keypair) to sign blocks
        if self.wallet_entity is None or self.wallet_id not in self.blockchain.public_keys:
            return None

        ok, round_number, _reason = block_producer.should_propose(
            self.blockchain, self.consensus, self.wallet_id,
        )
        if not ok:
            return None

        # Build the block. Empty mempool is fine — empty blocks carry
        # attestations and advance block-denominated timers.
        all_pending = self.mempool.get_transactions_with_entity_cap(MAX_TXS_PER_BLOCK)
        txs = [t for t in all_pending if isinstance(t, MessageTransaction)]
        transfer_txs = [t for t in all_pending if isinstance(t, TransferTransaction)]
        slash_txs = self.mempool.get_slash_transactions()
        # Drain pending authority txs (SetAuthorityKey / Revoke / KeyRotation)
        # into this block.  Queued by their respective RPC handlers; applied
        # through _apply_block_state so every peer processing the block
        # reaches the same authority-state result.  Without this drain,
        # the hot/cold split and emergency revoke would only take effect on
        # the single node that received the RPC.
        # Sweep stale/unmineable pending txs before draining.  Catches
        # nonce-passed, revoked-sender, leaf-burned, and expired entries
        # so they don't ride along into a block (where they'd fail
        # validate_block and either drop the whole block or force a
        # per-tx reject in the apply loop).
        self._sweep_stale_pending_txs()
        pending_authority = getattr(self, "_pending_authority_txs", {})
        authority_txs = list(pending_authority.values())
        # Pull staged stake + governance txs submitted via RPC.  Without
        # these being included, `messagechain stake` and every governance
        # submission would be silently dropped — the server accepts them
        # into _pending_* dicts but nothing would ever include them in a
        # block, so chain state never mutates.  Cap at MAX_TXS_PER_BLOCK
        # each to keep block size bounded.
        pending_stake = getattr(self, "_pending_stake_txs", {})
        stake_txs = list(pending_stake.values())[:MAX_TXS_PER_BLOCK]
        pending_unstake = getattr(self, "_pending_unstake_txs", {})
        unstake_txs = list(pending_unstake.values())[:MAX_TXS_PER_BLOCK]
        pending_gov = getattr(self, "_pending_governance_txs", {})
        governance_txs = list(pending_gov.values())[:MAX_TXS_PER_BLOCK]

        block = self.blockchain.propose_block(
            self.consensus, self.wallet_entity, txs,
            transfer_transactions=transfer_txs,
            slash_transactions=slash_txs,
            authority_txs=authority_txs,
            stake_transactions=stake_txs,
            unstake_transactions=unstake_txs,
            governance_txs=governance_txs,
        )

        success, reason = self.blockchain.add_block(block)
        if success:
            if all_pending:
                self.mempool.remove_transactions([tx.tx_hash for tx in all_pending])
            if slash_txs:
                self.mempool.remove_slash_transactions(
                    [s.tx_hash for s in slash_txs]
                )
            if authority_txs:
                for ah in [a.tx_hash for a in authority_txs]:
                    pending_authority.pop(ah, None)
            if stake_txs:
                for sh in [s.tx_hash for s in stake_txs]:
                    pending_stake.pop(sh, None)
            if unstake_txs:
                for uh in [u.tx_hash for u in unstake_txs]:
                    pending_unstake.pop(uh, None)
            if governance_txs:
                for gh in [g.tx_hash for g in governance_txs]:
                    pending_gov.pop(gh, None)
            total_fees = sum(tx.fee for tx in all_pending)
            balance = self.blockchain.supply.get_balance(self.wallet_id)
            logger.info(
                f"Block #{block.header.block_number} | "
                f"{len(txs)} txs | fees: {total_fees} | round: {round_number} | "
                f"reward: {self.blockchain.supply.calculate_block_reward(block.header.block_number)} | "
                f"wallet balance: {balance}"
            )
            # Opt-in auto-restake — sweep liquid rewards back into stake
            # if the operator has enabled it.  Runs AFTER add_block so the
            # reward the proposer just earned is already credited to
            # liquid balance.  Any failure is logged and swallowed: block
            # production must never abort because a restake sweep
            # misbehaved (this is best-effort, opt-in operator convenience).
            self._maybe_auto_restake()
        else:
            if block_producer.is_clock_skew_reason(reason):
                logger.warning(
                    f"Failed to add proposed block: {reason}. "
                    "This may indicate your system clock is out of sync. "
                    "Check your OS time settings."
                )
            else:
                logger.warning(f"Failed to add proposed block: {reason}")

        return (block, success, reason, round_number)

    async def _try_produce_block(self):
        """One iteration of block production. Offloads CPU-bound work
        (WOTS+ signing, state root, validation) to a thread pool so
        the asyncio event loop stays responsive for RPC handlers."""

        result = await asyncio.to_thread(self._try_produce_block_sync)
        if result is None:
            return

        block, success, reason, round_number = result
        if success:
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
            if tx_hash_hex in self._seen_txs:
                return
            pending_nonce = self._get_pending_nonce_all_pools(tx.entity_id)
            valid, reason = self.blockchain.validate_transaction(
                tx, expected_nonce=pending_nonce,
            )
            if valid:
                self._track_seen_tx(tx_hash_hex)
                # Record arrival height — see _rpc_submit_transaction for rationale.
                self.mempool.add_transaction(
                    tx, arrival_block_height=self.blockchain.height,
                )
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
                # Attester duty: vote on the accepted block, but only if
                # it honors our forced-inclusion list (censorship
                # resistance).  Silent omission of a top-N long-waited
                # tx means we skip the broadcast — block fails 2/3
                # finality if enough honest attesters concur.
                await self._maybe_attest_accepted_block(block)
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

        elif msg.msg_type == MessageType.ANNOUNCE_PENDING_TX:
            self._handle_announce_pending_tx(msg.payload, peer)

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

    async def _maybe_attest_accepted_block(self, block):
        """Cast an attestation for a freshly-accepted block if we're a
        registered validator AND the block honors our forced-inclusion
        duty.  Silence (no broadcast) is the soft NO vote.

        Mirrors network/node.py — both the library-mode Node and the
        server entry point must enforce the forced-inclusion duty
        identically, so any attester code path refuses to sign a block
        that drops a top-N long-waited tx from our local mempool.
        """
        if self.wallet_entity is None:
            return
        if self.wallet_id not in self.blockchain.public_keys:
            return
        if self.wallet_id not in self.consensus.stakes:
            return

        def _is_includable(tx) -> bool:
            ok, _reason = self.blockchain.validate_transaction(tx)
            return ok

        att = attest_block_if_allowed(
            self.wallet_entity,
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

        # Record locally (we won't see our own attestation on gossip)
        # and broadcast.
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        validator_stake = self.blockchain.supply.get_staked(self.wallet_id)
        total_stake = sum(self.blockchain.supply.staked.values())
        self.blockchain.finality.add_attestation(
            att, validator_stake, total_stake,
            public_keys=self.blockchain.public_keys,
            min_validator_count=MIN_VALIDATORS_TO_EXIT_BOOTSTRAP,
        )

        msg = NetworkMessage(
            msg_type=MessageType.ANNOUNCE_ATTESTATION,
            payload=att.serialize(),
        )
        await self._broadcast(msg)

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

    def _handle_announce_pending_tx(self, payload: dict, peer) -> None:
        """Receive a non-message tx gossiped by a peer; validate + queue.

        The peer's admission path already did the fast local-state checks;
        we redo them ourselves because we don't trust peers.  Dedupe by
        tx_hash and leaf so a gossiped tx doesn't re-broadcast forever.

        Rate-limited per-peer under the "pending_tx" category: a flooder
        is cheaply dropped before the expensive signature-verify path,
        and their ban score bumps so repeated abuse earns a disconnect.
        """
        try:
            # Rate-limit BEFORE any deserialization / signature verify —
            # those are the costly operations we want to protect from spam.
            peer_address = getattr(peer, "address", None)
            if peer_address and not self.rate_limiter.check(
                peer_address, "pending_tx",
            ):
                self.ban_manager.record_offense(
                    peer_address,
                    OFFENSE_RATE_LIMIT,
                    "pending_tx_rate_limit",
                )
                return
            kind = payload.get("kind")
            tx_data = payload.get("tx")
            if not isinstance(kind, str) or not isinstance(tx_data, dict):
                if peer_address:
                    self.ban_manager.record_offense(
                        peer_address,
                        OFFENSE_PROTOCOL_VIOLATION,
                        "pending_tx_malformed",
                    )
                return
            if kind == "authority":
                from messagechain.core.block import _deserialize_authority_tx
                tx = _deserialize_authority_tx(tx_data)
                cls_name = tx.__class__.__name__
                if cls_name == "SetAuthorityKeyTransaction":
                    ok, _ = self.blockchain.validate_set_authority_key(tx)
                elif cls_name == "RevokeTransaction":
                    ok, _ = self.blockchain.validate_revoke(tx)
                elif cls_name == "KeyRotationTransaction":
                    ok, _ = self.blockchain.validate_key_rotation(tx)
                else:
                    return
                if not ok:
                    return
                if not self._check_leaf_across_all_pools(tx):
                    return
                if not self._admit_to_pool("_pending_authority_txs", tx):
                    return
            elif kind == "stake":
                from messagechain.core.staking import (
                    StakeTransaction, verify_stake_transaction,
                )
                tx = StakeTransaction.deserialize(tx_data)
                pk = self.blockchain.public_keys.get(tx.entity_id)
                if pk is None or not verify_stake_transaction(
                    tx, pk, block_height=self.blockchain.height,
                ):
                    return
                if not self._check_leaf_across_all_pools(tx):
                    return
                if not self._admit_to_pool("_pending_stake_txs", tx):
                    return
            elif kind == "unstake":
                from messagechain.core.staking import (
                    UnstakeTransaction, verify_unstake_transaction,
                )
                tx = UnstakeTransaction.deserialize(tx_data)
                authority_pk = self.blockchain.get_authority_key(tx.entity_id)
                if authority_pk is None or not verify_unstake_transaction(
                    tx, authority_pk,
                ):
                    return
                if not self._check_leaf_across_all_pools(tx):
                    return
                if not self._admit_to_pool("_pending_unstake_txs", tx):
                    return
            elif kind == "governance":
                from messagechain.core.block import _deserialize_governance_tx
                tx = _deserialize_governance_tx(tx_data)
                signer_id = (
                    getattr(tx, "proposer_id", None)
                    or getattr(tx, "voter_id", None)
                )
                if signer_id is None or signer_id not in self.blockchain.public_keys:
                    return
                if not self._check_leaf_across_all_pools(tx):
                    return
                if not self._admit_to_pool("_pending_governance_txs", tx):
                    return
            else:
                return
            # Relay to other peers (best-effort).  Gossip is idempotent —
            # peers that already have the tx will drop it via the
            # tx_hash-seen guards above.
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._broadcast(
                    NetworkMessage(MessageType.ANNOUNCE_PENDING_TX, payload),
                ))
            except RuntimeError:
                pass
        except Exception as e:
            logger.debug(f"rejected malformed gossip pending tx: {e}")

    async def _broadcast_block(self, block: Block):
        msg = NetworkMessage(MessageType.ANNOUNCE_BLOCK, block.serialize())
        await self._broadcast(msg)

    def _schedule_pending_tx_gossip(self, kind: str, tx) -> None:
        """Fire-and-forget gossip of a newly-admitted non-message tx.

        Non-message txs (stake / unstake / authority / governance) land in
        per-type pending pools on the node that received the RPC.  Without
        gossip, they only make it into a block if THAT node happens to be
        the next proposer.  Broadcasting to peers lets any proposer pick
        them up, bounding the "stuck in one node's pool" window to the
        network-wide gossip latency rather than a full block-time.
        """
        try:
            msg = NetworkMessage(
                MessageType.ANNOUNCE_PENDING_TX,
                {"kind": kind, "tx": tx.serialize()},
            )
        except Exception as e:
            logger.debug(f"could not serialize pending tx for gossip: {e}")
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no async context — likely a unit test; nothing to do
        loop.create_task(self._broadcast(msg))

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
        rpc_bind=args.rpc_bind,
    )

    # Authenticate with private key to unlock block signing.  Two paths:
    #   * --keyfile: read the hex-encoded key from a 0600 file.  Required
    #     for unattended (systemd, Docker) operation where no tty exists.
    #   * Interactive: getpass prompts for the key.  Default.
    private_key_input: bytes = b""
    if args.keyfile:
        with open(args.keyfile) as _kf:
            hex_key = _kf.read().strip()
        try:
            private_key_input = bytes.fromhex(hex_key)
        except ValueError as e:
            logger.error(f"keyfile {args.keyfile} does not contain valid hex: {e}")
            sys.exit(1)
        logger.info(f"Loaded private key from {args.keyfile}")
    else:
        if args.wallet:
            logger.info(f"Wallet ID: {args.wallet}")
            print("Authenticate with your private key to enable block production.\n")
        else:
            print("To produce blocks and earn rewards, authenticate with your private key.")
            print("If you don't have an account yet, use: python client.py create-account")
            print("You can also press Enter to run as a relay-only node (no rewards).\n")

        import getpass
        private_key_input = getpass.getpass(
            "Private key (hidden, or Enter to skip): "
        ).encode("utf-8")

    if private_key_input:
        from messagechain.config import MERKLE_TREE_HEIGHT as _config_th
        # Prefer the tree_height recorded in chain state over the global
        # config default.  The stored value is the authoritative binding:
        # the entity_id derived from this private key was computed with
        # THAT height, so re-deriving the keypair with anything else
        # silently produces a different public key (and hence a
        # different entity_id) — the node would then be unable to sign
        # for its own wallet.  Chain state wins whenever we can identify
        # the operator's wallet entity; config is the fallback for a
        # brand-new node with no prior state.
        _resolved_th: int | None = None
        if args.wallet:
            try:
                wallet_id_bytes = bytes.fromhex(args.wallet)
                _resolved_th = server.blockchain.get_wots_tree_height(
                    wallet_id_bytes,
                )
            except ValueError:
                logger.warning(
                    "--wallet %s is not valid hex; falling back to config",
                    args.wallet,
                )
        if _resolved_th is None:
            _resolved_th = _config_th
            logger.info(
                "Using config MERKLE_TREE_HEIGHT=%d for keypair generation",
                _resolved_th,
            )
        else:
            logger.info(
                "Using chain-state WOTS+ tree_height=%d for wallet %s",
                _resolved_th, args.wallet[:16] if args.wallet else "?",
            )
        entity = _load_or_create_entity(
            private_key_input,
            _resolved_th,
            args.data_dir,
            no_cache=getattr(args, "no_keypair_cache", False),
        )

        # Advance WOTS+ keypair past all previously-used one-time signing keys.
        # Without this, restarting the server would reuse WOTS+ leaves, which
        # catastrophically compromises the one-time signature scheme.
        leaves_used = server.blockchain.get_wots_leaves_used(entity.entity_id)
        if leaves_used > 0:
            entity.keypair.advance_to_leaf(leaves_used)
            logger.info(f"Advanced keypair past {leaves_used} used WOTS+ leaves")

        server.set_wallet_entity(entity)
        logger.info(f"Authenticated as: {entity.entity_id_hex[:16]}...")
    elif args.wallet:
        server.set_wallet(args.wallet)
        logger.warning("Wallet set but no private key — node cannot sign blocks.")

    await server.start()

    submission_server = None
    if args.submission_port is not None:
        from messagechain.network.submission_server import SubmissionServer

        def _relay_tx(tx):
            # Schedule gossip relay on the main event loop.  Called
            # from the HTTP handler thread — use run_coroutine_threadsafe.
            try:
                server._track_seen_tx(tx.tx_hash.hex())
                loop = asyncio.get_event_loop()
                asyncio.run_coroutine_threadsafe(
                    server._relay_tx_inv([tx.tx_hash.hex()]), loop,
                )
            except Exception:
                logger.exception("submission relay failed")

        submission_server = SubmissionServer(
            blockchain=server.blockchain,
            mempool=server.mempool,
            cert_path=args.submission_cert,
            key_path=args.submission_key,
            port=args.submission_port,
            bind=args.submission_bind,
            relay_callback=_relay_tx,
        )
        submission_server.start()
        logger.info(
            "Public HTTPS submission endpoint active on %s:%d",
            args.submission_bind, args.submission_port,
        )

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down")
        if submission_server is not None:
            submission_server.stop()
        await server.stop()


def main():
    parser = argparse.ArgumentParser(description="MessageChain Server")
    parser.add_argument("--port", type=int, default=9333, help="P2P port (default: 9333)")
    parser.add_argument("--rpc-port", type=int, default=9334, help="RPC port for clients (default: 9334)")
    parser.add_argument(
        "--rpc-bind", type=str, default="127.0.0.1",
        help="RPC bind address (default: 127.0.0.1). Use 0.0.0.0 for a "
             "public validator accepting remote signed transactions.",
    )
    parser.add_argument(
        "--keyfile", type=str, default=None,
        help="Path to a file containing the hex-encoded private key.  "
             "Required for unattended (systemd, Docker) operation.  "
             "File should be 0600 and owned by the service user.",
    )
    parser.add_argument("--seed", nargs="*", help="Seed nodes (host:port)")
    parser.add_argument("--wallet", type=str, help="Wallet ID hex (skip interactive prompt)")
    parser.add_argument("--data-dir", type=str, help="Directory for persistent chain data (enables SQLite storage)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument(
        "--no-keypair-cache", action="store_true", default=False,
        help="Disable on-disk keypair caching. Forces full WOTS+ tree "
             "regeneration on every restart.",
    )
    # --- Censorship-resistance HTTPS submission endpoint (opt-in) ---
    # Off by default.  Set --submission-port (typ. 8443) AND supply
    # --submission-cert + --submission-key to expose a public POST
    # /v1/submit endpoint that accepts binary-serialized signed
    # transactions over TLS.  See messagechain/network/submission_server.py.
    parser.add_argument(
        "--submission-port", type=int, default=None,
        help="If set, start a public HTTPS transaction-submission server "
             "on this port. Requires --submission-cert and --submission-key.",
    )
    parser.add_argument(
        "--submission-cert", type=str, default=None,
        help="Path to TLS certificate (PEM) for the submission server. "
             "Required when --submission-port is set.",
    )
    parser.add_argument(
        "--submission-key", type=str, default=None,
        help="Path to TLS private key (PEM) for the submission server. "
             "Required when --submission-port is set.",
    )
    parser.add_argument(
        "--submission-bind", type=str, default="0.0.0.0",
        help="Bind address for the submission server (default: 0.0.0.0 — "
             "this endpoint is intentionally public).",
    )
    args = parser.parse_args()

    if args.submission_port is not None:
        if not args.submission_cert or not args.submission_key:
            parser.error(
                "--submission-port requires --submission-cert and "
                "--submission-key (TLS is mandatory for the submission "
                "endpoint; plaintext HTTP is not supported).",
            )

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")

    # Log the active deployment profile (MESSAGECHAIN_PROFILE) so operators
    # can confirm at a glance whether the node is running production-strict
    # defaults or the prototype bootstrap bundle. Helps catch silent
    # misconfiguration — e.g., a VM that inherited the wrong profile env.
    from messagechain.config import active_profile
    _profile = active_profile()
    if _profile == "prototype":
        logger.info(
            "Active profile: prototype (bootstrap-phase defaults: 30s blocks, "
            "MERKLE_TREE_HEIGHT=16, checkpoints waived, RPC auth disabled). "
            "Set MESSAGECHAIN_PROFILE=production for strict defaults."
        )
    else:
        logger.info("Active profile: production (strict defaults)")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
