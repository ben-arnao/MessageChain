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
    HANDSHAKE_TIMEOUT, PEER_READ_TIMEOUT, MAX_PEERS,
    PEER_MAINTENANCE_INTERVAL,
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
    enable_tcp_keepalive,
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
    PeerBanManager, OFFENSE_INVALID_BLOCK, OFFENSE_INVALID_TX, OFFENSE_MINOR,
    OFFENSE_PROTOCOL_VIOLATION, OFFENSE_RATE_LIMIT,
)
from messagechain.network.ratelimit import PeerRateLimiter

import hashlib
from messagechain.config import HASH_ALGO
from messagechain import __version__
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
    # reserve_leaf advances and persists the validator's wallet
    # keypair `_next_leaf` counter -- the WOTS+ tree has at most
    # 2^MERKLE_TREE_HEIGHT one-time leaves and once exhausted, the
    # validator can no longer sign blocks until an emergency cold-key
    # rotation.  The original "no auth" rationale (tx submissions are
    # already gated by WOTS+ sigs on the txs themselves) does NOT
    # apply here: this RPC consumes the validator's OWN key without
    # any ownership proof.  Any caller reaching the RPC port (default
    # 127.0.0.1, but commonly fronted via reverse proxy / SSH tunnel /
    # LAN exposure / container misconfiguration) can drain the tree
    # in hours from one IP, instantly with concurrent IPs.  The local
    # CLI must now thread the configured RPC_AUTH_TOKEN through
    # _reserve_leaf_via_rpc.
    "reserve_leaf",
})


# ── RPC cost schedule ───────────────────────────────────────────────
#
# The rate limiter is a shared 300-token/min-per-IP budget
# (max_requests=300, window=60s).  Before this wiring, EVERY method
# charged 1 token: `submit_transaction` (WOTS+ verify, ~50ms CPU)
# cost the same as `get_chain_info` (dict lookup, microseconds).
# An attacker flooding submit_transaction burned real CPU at
# negligible rate-limit cost.
#
# Two tiers (cheap, expensive) intentionally — three tiers adds
# operator-facing tunable surface without a correspondingly clear
# attack model.  Add RPC_COST_MEDIUM later if a specific handler
# proves to need it, rather than pre-allocating knobs.
#
# With max_requests=300 and RPC_COST_EXPENSIVE=20, an attacker
# flooding submit_transaction is rate-limited at 15 reqs/min
# (300/20) instead of 300 — a 20x reduction in CPU burn before
# the limiter kicks in.  Legitimate validator operations (stake,
# rotate_key, etc.) are rare enough that 15/min per IP is plenty.
RPC_COST_CHEAP = 1      # dict lookups, status queries, list endpoints
RPC_COST_EXPENSIVE = 20  # WOTS+ verify, tx deserialize + validate

# Method → cost.  Absent keys default to RPC_COST_CHEAP at dispatch
# time (keeps the table focused on what's actually expensive).  Every
# method whose body runs a WOTS+ signature verify — directly or via
# a helper like `_queue_authority_tx` that calls `validate_*` under
# the hood — belongs here.
_RPC_METHOD_COST: dict[str, int] = {
    # Direct WOTS+ verify + deserialize.
    "submit_transaction": RPC_COST_EXPENSIVE,
    "submit_transfer": RPC_COST_EXPENSIVE,
    # Authority/stake/governance paths — all run WOTS+ verify.
    "stake": RPC_COST_EXPENSIVE,
    "unstake": RPC_COST_EXPENSIVE,
    "submit_proposal": RPC_COST_EXPENSIVE,
    "submit_vote": RPC_COST_EXPENSIVE,
    "rotate_key": RPC_COST_EXPENSIVE,
    "set_authority_key": RPC_COST_EXPENSIVE,
    "emergency_revoke": RPC_COST_EXPENSIVE,
    "set_receipt_subtree_root": RPC_COST_EXPENSIVE,
    # Tier 17 ReactTransaction: deserialize + WOTS+ verify on submit;
    # the get_* reads are cheap and use the dispatch default.
    "submit_react": RPC_COST_EXPENSIVE,
}


# ── Release-manifest notification ─────────────────────────────────
#
# When the chain accepts a `ReleaseAnnounceTransaction`, the manifest
# is stored at `blockchain.latest_release_manifest`.  Operators have
# no visibility into that by default — this helper surfaces it at
# node startup so an operator sees "UPDATE AVAILABLE" in journald /
# stdout without having to poll the chain themselves.
#
# Severity mapping is documented in release_announce.py:
#   0 = normal    (routine release, log at WARNING if mismatched)
#   1 = security  (log at ERROR)
#   2 = emergency (log at ERROR)
#
# This is notification only — no auto-download, no consensus gating,
# no verification against any local binary.  Keeping the protocol
# layer free of "run this code" surface is intentional; see
# CLAUDE.md "No external dependencies in protocol".

_RELEASE_SEVERITY_LABELS = {0: "normal", 1: "security", 2: "emergency"}


def log_release_status(logger_, blockchain, current_version: str) -> None:
    """Log the state of `blockchain.latest_release_manifest`.

    Semver-aware since the fix to the lex-compare silent-data-loss bug
    (see messagechain.core.release_version):

    - No manifest on chain: silent (no log line).
    - Both versions parse AND manifest is strictly newer: UPDATE
      AVAILABLE at WARNING (severity 0) or ERROR (severity >= 1).
    - Both versions parse AND they're equal: single INFO line
      confirming the operator is running the latest announced release.
    - Both versions parse AND the node is ahead of the manifest:
      INFO "ahead of the latest announced release" line (the typical
      "dev build newer than last release" case).
    - Either version fails to parse: fall back to strict string
      inequality and emit the original UPDATE AVAILABLE log.  This is
      the safety net — a parser edge case must never silence a real
      update signal.

    Pure function of its inputs — easy to unit-test via assertLogs.
    """
    manifest = getattr(blockchain, "latest_release_manifest", None)
    if manifest is None:
        return

    manifest_version = manifest.version

    # Try the semver-aware path first.  If either side fails to parse,
    # `parse_release_version` raises ValueError and we drop into the
    # legacy string-inequality fallback below.
    from messagechain.core.release_version import parse_release_version
    both_parse = True
    try:
        parse_release_version(manifest_version)
        parse_release_version(current_version)
    except (ValueError, TypeError):
        both_parse = False

    if both_parse:
        from messagechain.core.release_version import (
            release_version_is_strictly_newer,
        )
        if manifest_version == current_version:
            logger_.info(
                "Running latest announced release v%s", current_version,
            )
            return
        if release_version_is_strictly_newer(
            current_version, manifest_version,
        ):
            # Dev build ahead of the last announced release.
            logger_.info(
                "Node v%s is ahead of the latest announced release v%s "
                "(no action needed)",
                current_version, manifest_version,
            )
            return
        # Else: manifest is strictly newer — fall through to emit the
        # UPDATE AVAILABLE line.
    else:
        # Unparseable version on at least one side — fall back to
        # strict string inequality.  If they happen to match as
        # strings, treat that as "running latest"; otherwise emit the
        # legacy UPDATE AVAILABLE line so the operator isn't left in
        # the dark.
        if manifest_version == current_version:
            logger_.info(
                "Running latest announced release v%s", current_version,
            )
            return
        # Fall through to emit the legacy UPDATE AVAILABLE line.

    label = _RELEASE_SEVERITY_LABELS.get(
        int(manifest.severity), f"severity-{int(manifest.severity)}",
    )
    num_signers = len(manifest.signer_indices)

    # Build the message in two halves: a fixed prefix, then an
    # optional activation-height clause inserted before the release-
    # notes tail.  Using explicit concatenation (not an f-string with
    # a conditional) keeps the output stable for log-scraping.
    prefix = (
        f"UPDATE AVAILABLE: v{manifest_version} "
        f"(running v{current_version}, severity={label}, "
        f"signed by {num_signers} release keys)"
    )
    if manifest.min_activation_height is not None:
        prefix += f", activation height {int(manifest.min_activation_height)}"
    msg = f"{prefix}. Release notes: {manifest.release_notes_uri}"

    if int(manifest.severity) >= 1:
        logger_.error(msg)
    else:
        logger_.warning(msg)


def _is_stale_tx_reason(reason: str) -> bool:
    """Classify a validate_transaction rejection as "stale" (peer's
    mempool view lags) vs "invalid" (peer is lying or buggy).

    Stale = recoverable on next sync; honest peers see this during
    normal partition-recovery overlap.  Instant-banning on stale
    causes a cascading ban storm across a recovering network.

    Invalid = cryptographic or structural fail; no honest cause.

    Keep this conservative: when unsure, treat as INVALID (instant ban).
    The list must track the reason strings used in
    messagechain.core.blockchain.validate_transaction.
    """
    if not isinstance(reason, str):
        return False
    lower = reason.lower()
    stale_markers = (
        "invalid nonce",              # stale-nonce drift during recovery
        "already consumed",           # leaf watermark below current
        "leaf reuse rejected",
        "timestamp is >",             # future-dated by a slow clock
        "insufficient spendable",     # balance drifted, retry after sync
    )
    return any(m in lower for m in stale_markers)


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


def attach_height_sign_guard(entity: Entity, data_dir: str | None) -> None:
    """Attach a persistent same-height-sign guard to *entity*.

    The guard is the disk-durable "I have already signed at height
    N" ratchet that ``messagechain/consensus/{pos,attestation,
    finality}.py`` consult via
    ``getattr(entity, "height_sign_guard", None)``.  Without it, an
    honest validator that crashes mid-propagate -- signs block N,
    partially gossips, restarts -- builds a byte-different second
    header (``timestamp`` and ``merkle_root`` move with mempool
    churn) and signs N a SECOND time.  Two valid signatures on
    byte-different headers at the same height = slashable
    equivocation evidence, full stake wipe.  The guard refuses the
    second sign before the signature is produced, so no slashable
    bytes ever escape the process.

    State file: ``<data_dir>/height_guard.json``.  When *data_dir*
    is None (ephemeral / test fixture), the guard is skipped and
    the consensus-layer ``getattr`` falls through to None -- same
    behavior as before this fix, which is correct for code paths
    that don't run a real validator (relay-only nodes, faucets,
    receipt-subtree bootstrap).

    Idempotent: re-calling on an entity that already has a guard
    re-loads from disk (safe -- guards never move backwards).
    """
    if data_dir is None:
        return
    from messagechain.consensus.height_guard import HeightSignGuard
    guard_path = os.path.join(data_dir, "height_guard.json")
    entity.height_sign_guard = HeightSignGuard.load_or_create(guard_path)


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
                attach_height_sign_guard(entity, data_dir)
                _attach_merkle_node_cache(
                    entity, private_key, tree_height, data_dir, no_cache,
                )
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
    attach_height_sign_guard(entity, data_dir)
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


# ---------------------------------------------------------------------------
# Receipt-subtree keypair generation + cache.
#
# The submission-receipt pipeline (messagechain.network.submission_receipt)
# requires a validator to sign receipts with a WOTS+ keypair that is
# SEPARATE from the block-signing keypair — otherwise receipt traffic burns
# leaves that the proposer needs for block production, and a DoS attacker
# who spams the submission endpoint can effectively exhaust the validator's
# block-signing tree.
#
# This module builds that separate subtree, caches it on disk (same
# HMAC-authenticated pattern as the block-signing keypair cache), and
# binds it to a DEDICATED leaf-index file so receipt leaves and
# block-signing leaves NEVER collide.  Sharing a leaf-index file would
# silently let a receipt sign at leaf 5 AND a block sign at leaf 5 —
# even though the trees are different, the cross-service bookkeeping
# would conflate "next leaf to use" for two independent consumers and
# misorder them into a crash.  They're isolated on purpose.
#
# CRITICAL security invariant: the receipt subtree's SEED is derived
# from the validator's private key by HASHING WITH A DIFFERENT DOMAIN
# TAG than the block-signing seed.  Identical private key → identical
# block-signing seed; adding the dedicated domain tag yields a seed
# with no algebraic relationship to the block-signing tree — so no
# leaf from one tree can ever collide with a leaf from the other.
# ---------------------------------------------------------------------------

_RECEIPT_SEED_DOMAIN = b"mc-receipt-subtree-seed-v1|"
_RECEIPT_LEAF_INDEX_FILENAME = "receipt_leaf_index.json"


def _derive_receipt_subtree_seed(private_key: bytes) -> bytes:
    """Derive the receipt subtree's seed from the validator's private key.

    Domain-separated from _derive_signing_seed (which produces the
    block-signing seed) so the two trees are cryptographically
    independent.  A 32-byte digest is fed to KeyPair — same shape as
    every other seed in the codebase.
    """
    return _hashlib.sha3_256(_RECEIPT_SEED_DOMAIN + private_key).digest()


def _receipt_keypair_cache_path(
    private_key: bytes, entity_id: bytes, tree_height: int, data_dir: str,
) -> str:
    """Filesystem path for the cached receipt-subtree keypair.

    Filename pattern: `receipt_keypair_cache_<entity_id_prefix>.bin`.
    Operators eyeballing the data dir can tell at a glance which cache
    belongs to which validator.  entity_id is derived from the public
    key which derives from the private key, so a per-key cache is
    uniquely identified by the entity-id prefix in any sane setup.
    Tamper resistance comes from the HMAC inside the file (keyed on
    private_key), not the filename.
    """
    prefix = entity_id.hex()[:16]
    return os.path.join(data_dir, f"receipt_keypair_cache_{prefix}.bin")


_RECEIPT_CACHE_MAGIC = b"MCRC"  # MessageChain Receipt Cache
_RECEIPT_CACHE_FORMAT_VERSION = 1
_RECEIPT_CACHE_HMAC_DOMAIN = b"messagechain-receipt-keypair-cache-v1|"


def _receipt_cache_mac_key(private_key: bytes) -> bytes:
    return _hashlib.sha3_256(
        _RECEIPT_CACHE_HMAC_DOMAIN + private_key
    ).digest()


def _encode_receipt_keypair_cache(
    keypair, private_key: bytes, tree_height: int,
) -> bytes:
    payload_obj = {
        "version": _RECEIPT_CACHE_FORMAT_VERSION,
        "tree_height": tree_height,
        "public_key": keypair.public_key.hex(),
    }
    payload = json.dumps(
        payload_obj, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    mac = hmac.new(
        _receipt_cache_mac_key(private_key), payload, _hashlib.sha3_256,
    ).digest()
    return _RECEIPT_CACHE_MAGIC + mac + payload


def _decode_receipt_keypair_cache(
    data: bytes, private_key: bytes, tree_height: int,
):
    """Return a KeyPair reconstructed from a trusted cache blob, or None.

    Mirrors _decode_keypair_cache's fail-silent policy: any rejection
    (wrong magic, bad MAC, malformed JSON, wrong version or height)
    returns None so the caller deletes and regenerates.
    """
    header_len = len(_RECEIPT_CACHE_MAGIC) + _HMAC_SIZE
    if len(data) < header_len:
        return None
    if not data.startswith(_RECEIPT_CACHE_MAGIC):
        return None
    mac = data[len(_RECEIPT_CACHE_MAGIC):header_len]
    payload = data[header_len:]
    expected = hmac.new(
        _receipt_cache_mac_key(private_key), payload, _hashlib.sha3_256,
    ).digest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("version") != _RECEIPT_CACHE_FORMAT_VERSION:
        return None
    if obj.get("tree_height") != tree_height:
        return None
    try:
        public_key = bytes.fromhex(obj["public_key"])
    except (KeyError, ValueError, TypeError):
        return None
    if len(public_key) != 32:
        return None
    seed = _derive_receipt_subtree_seed(private_key)
    return KeyPair._from_trusted_root(seed, tree_height, public_key)


def _load_or_create_receipt_subtree_keypair(
    private_key: bytes,
    tree_height: int,
    entity_id: bytes,
    data_dir: str | None,
    *,
    no_cache: bool = False,
    progress_every: int = 65_536,
):
    """Return a KeyPair for the receipt subtree, generating if needed.

    The keypair is deterministic in private_key + tree_height, so a
    restart reuses the exact same subtree (same root) when the cache
    is available.  At the current RECEIPT_SUBTREE_HEIGHT=16 setting,
    fresh-boot keygen derives 65k leaves in seconds.  An earlier
    h=24 setting was reduced after on-VM measurements showed ~36 hours
    of blocking startup keygen.

    The returned KeyPair has its leaf_index_path bound to a DEDICATED
    file (`receipt_leaf_index.json`) that block-signing NEVER touches.
    This is load-bearing: sharing a leaf-index file between the two
    signers would let one service's sign() silently consume the
    other's next leaf, forcing a leaf-index skip that looks like
    leaf-reuse on restart.
    """
    seed = _derive_receipt_subtree_seed(private_key)
    use_cache = data_dir is not None and not no_cache
    keypair = None

    if use_cache:
        cache_file = _receipt_keypair_cache_path(
            private_key, entity_id, tree_height, data_dir,
        )
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "rb") as f:
                    blob = f.read()
                keypair = _decode_receipt_keypair_cache(
                    blob, private_key, tree_height,
                )
            except OSError:
                keypair = None
            if keypair is not None:
                logger.info(
                    "Loaded receipt-subtree keypair from cache %s",
                    cache_file,
                )
            else:
                logger.warning(
                    "Corrupt or unauthenticated receipt-subtree cache %s — "
                    "deleting and regenerating", cache_file,
                )
                try:
                    os.remove(cache_file)
                except OSError:
                    pass

    if keypair is None:
        logger.info(
            "Generating receipt-subtree keypair at height=%d "
            "(this takes minutes — cached on success)",
            tree_height,
        )
        _progress_counter = {"n": 0}

        def _progress(leaf_idx: int):
            _progress_counter["n"] = leaf_idx
            if leaf_idx and leaf_idx % progress_every == 0:
                logger.info(
                    "receipt-subtree keygen progress: %d / %d leaves",
                    leaf_idx, 1 << tree_height,
                )

        keypair = KeyPair.generate(
            seed, height=tree_height, progress=_progress,
        )
        logger.info(
            "Generated receipt-subtree keypair: root=%s",
            keypair.public_key.hex()[:16] + "...",
        )

        if use_cache:
            try:
                blob = _encode_receipt_keypair_cache(
                    keypair, private_key, tree_height,
                )
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
                logger.info(
                    "Saved receipt-subtree keypair cache to %s", cache_file,
                )
            except OSError:
                logger.warning(
                    "Could not write receipt-subtree cache to %s",
                    cache_file,
                )

    # Bind a DEDICATED leaf-index file.  NEVER share with block signing —
    # the two signers track independent "next leaf to use" counters and
    # conflating them causes silent crashes / apparent leaf reuse.
    if data_dir is not None:
        leaf_path = os.path.join(data_dir, _RECEIPT_LEAF_INDEX_FILENAME)
        keypair.leaf_index_path = leaf_path
        keypair.load_leaf_index(leaf_path)

    return keypair


def _bootstrap_receipt_subtree(
    server,
    *,
    private_key: bytes,
    entity,
    data_dir: str | None,
    no_cache: bool = False,
) -> None:
    """Boot-time hook: build the receipt subtree, bind it to the server,
    and auto-submit SetReceiptSubtreeRoot if chain state is out of date.

    Idempotent across restarts:
      * Fresh node: subtree is generated, cached, ReceiptIssuer
        installed, tx submitted.
      * Warm restart with matching on-chain root: subtree is loaded
        from cache, ReceiptIssuer installed, NO tx submitted (no-op).
      * Warm restart after key rotation: regeneration happens, new
        root lands on-chain via SetReceiptSubtreeRoot (replaces old).

    Cold-key-unavailable case: the tx must be signed by the
    authority (cold) key.  If the authority key registered in chain
    state for this entity differs from the operator's hot signing key
    (the standard hot/cold split), we DO NOT have the cold key on
    disk and CANNOT sign the registration tx here.  Log a clear
    warning + instructions and let service start proceed — the
    operator submits the tx manually from their cold environment.
    """
    from messagechain.config import RECEIPT_SUBTREE_HEIGHT
    from messagechain.core.receipt_subtree_root import (
        create_set_receipt_subtree_root_transaction,
    )
    from messagechain.network.submission_receipt import ReceiptIssuer

    if not private_key:
        logger.info(
            "Receipt subtree bootstrap skipped: no private key available "
            "(relay-only node)."
        )
        return

    # Build (or load cached) receipt-subtree keypair.
    receipt_keypair = _load_or_create_receipt_subtree_keypair(
        private_key=private_key,
        tree_height=RECEIPT_SUBTREE_HEIGHT,
        entity_id=entity.entity_id,
        data_dir=data_dir,
        no_cache=no_cache,
    )

    local_root = receipt_keypair.public_key

    # Install the ReceiptIssuer on the server so the submission-RPC
    # endpoint can issue receipts for admitted txs.  The
    # height_fn closure lets the issuer stamp the live chain height
    # without needing a direct Blockchain reference.
    server.receipt_issuer = ReceiptIssuer(
        issuer_id=entity.entity_id,
        subtree_keypair=receipt_keypair,
        height_fn=lambda: server.blockchain.height,
    )

    # Install a WitnessObservationStore on the server so the public
    # submission endpoint's `obs_ok` gate has a real backing store.
    # Without this, the gate short-circuits to True for any 32-byte
    # X-MC-Witnessed-Submission header value, and a botnet (1000-IP
    # rotation) drains the 65k-leaf receipt subtree in hours via
    # the per-IP ack budget alone -- silently disabling the entire
    # censorship-evidence pipeline.
    #
    # The store starts empty.  Until the gossip-handler wiring for
    # SubmissionRequest publishes observations into it, the only
    # ack-eligible request_hashes will be ones recorded by other
    # code paths -- effectively the witnessed-submission ack flow
    # is dormant pending that wiring.  This is the safe-by-default
    # posture: deny ack issuance when we have no record of the
    # request, instead of allowing it for any 32-byte string.
    from messagechain.consensus.witness_submission import (
        WitnessObservationStore,
    )
    server.witness_observation_store = WitnessObservationStore()
    logger.info(
        "Receipt issuer installed: entity=%s root=%s",
        entity.entity_id_hex[:16],
        local_root.hex()[:16] + "...",
    )

    # Check against chain state: if the registered root already
    # matches the locally-generated tree's root, we're done — do NOT
    # resubmit (idempotent on restart).
    registered_root = server.blockchain.receipt_subtree_roots.get(
        entity.entity_id,
    )
    if registered_root == local_root:
        logger.info(
            "Receipt-subtree root already registered on-chain — no tx needed"
        )
        return

    # Mismatch (or never registered).  We need to submit a
    # SetReceiptSubtreeRoot tx signed by the AUTHORITY key.  If the
    # authority key matches the local signing public key (default
    # single-key model), we can sign locally.  If it's been promoted
    # to a separate cold key, we do NOT have it on disk here — log
    # instructions and let service start proceed.
    authority_pk = server.blockchain.get_authority_key(entity.entity_id)
    if authority_pk is None:
        # Entity not yet registered on chain.  Nothing to do on the
        # auto-register path — the first message/transfer from this
        # entity registers it implicitly (receive-to-exist), and a
        # subsequent boot will re-enter this branch.
        logger.info(
            "Entity not yet on-chain; receipt-subtree root registration "
            "deferred until entity is registered."
        )
        return

    if authority_pk != entity.public_key:
        # Cold key is not on this host.  Print actionable instructions
        # and continue — the operator can submit the tx from their cold
        # environment using the CLI path.
        logger.warning(
            "Receipt-subtree root NOT registered on-chain, but the "
            "authority (cold) key for this validator differs from the "
            "local signing key — cannot auto-submit.\n"
            "  entity_id:        %s\n"
            "  local root:       %s\n"
            "  currently on-chain: %s\n"
            "ACTION: from a host with the cold key, run\n"
            "  messagechain set-receipt-subtree-root \\\n"
            "      --keyfile <cold-key-path> \\\n"
            "      --server <this-validator-host>:9334 \\\n"
            "      --yes\n"
            "The CLI fetches the local root via get_local_receipt_root, "
            "signs the tx with the cold key, and broadcasts via the "
            "set_receipt_subtree_root RPC.  Until this lands, receipts "
            "issued by this validator will fail verification at "
            "evidence-admission time.",
            entity.entity_id_hex[:16],
            local_root.hex()[:16] + "...",
            registered_root.hex()[:16] + "..." if registered_root else "<none>",
        )
        return

    # Single-key model: hot signing key IS the authority key.  We can
    # sign and submit directly.  Use the blockchain's own admission
    # path so the tx goes through the same mempool / gossip plumbing
    # as any other authority tx.
    try:
        tx = create_set_receipt_subtree_root_transaction(
            entity_id=entity.entity_id,
            root_public_key=local_root,
            authority_signer=entity,
        )
        ok, reason = server._queue_authority_tx(
            tx,
            validate_fn=server.blockchain.validate_set_receipt_subtree_root,
        )
        if ok:
            logger.info(
                "Queued SetReceiptSubtreeRoot tx %s for block inclusion "
                "(root=%s)",
                tx.tx_hash.hex()[:16],
                local_root.hex()[:16] + "...",
            )
        else:
            logger.warning(
                "SetReceiptSubtreeRoot auto-queue rejected: %s — operator "
                "may need to submit manually.",
                reason,
            )
    except Exception:
        logger.exception(
            "Failed to build/queue SetReceiptSubtreeRoot tx — operator "
            "can submit manually later."
        )


from messagechain.runtime.shared import SharedRuntimeMixin


class Server(SharedRuntimeMixin):
    """MessageChain full node with RPC interface for clients."""

    def __init__(self, p2p_port: int, rpc_port: int, seed_nodes: list[tuple[str, int]],
                 data_dir: str | None = None, rpc_bind: str = "127.0.0.1"):
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.rpc_bind = rpc_bind
        self.seed_nodes = seed_nodes
        # Kept so the P2P listener / outbound connector can place the
        # self-signed TLS cert under a persistent path (mirrors
        # messagechain/network/node.py).  None => ephemeral tempdir.
        self.data_dir = data_dir

        # R12-#1: acquire an exclusive OS-level lock on data_dir BEFORE
        # opening any keyfile / DB.  Two processes sharing a data_dir
        # would both load the same WOTS+ keypair cache and sign
        # different payloads at identical leaf indices — leaf reuse in
        # a one-time-signature scheme leaks the private key outright
        # (and for a validator, forks consensus).  The lock is held for
        # the process lifetime; clean shutdown releases it in stop().
        # Tests that legitimately spin up multiple servers on the same
        # tempdir set MESSAGECHAIN_SKIP_DATA_DIR_LOCK=1.
        self._data_dir_lock = None
        if data_dir:
            import os
            os.makedirs(data_dir, exist_ok=True)
            from messagechain.storage.data_dir_lock import DataDirLock
            self._data_dir_lock = DataDirLock(data_dir)
            self._data_dir_lock.__enter__()

        # Set up persistent storage if data_dir provided
        self.db = None
        if data_dir:
            import os
            from messagechain.storage.chaindb import ChainDB
            db_path = os.path.join(data_dir, "chain.db")
            self.db = ChainDB(db_path)
            logger.info(f"Using persistent storage: {db_path}")

        self.blockchain = Blockchain(db=self.db)
        self.mempool = Mempool()
        self.consensus = ProofOfStake()
        self.peers: dict[str, Peer] = {}
        # In-flight outbound dials, keyed by "host:port".  A Peer only
        # lands in self.peers after asyncio.open_connection returns;
        # without this set the startup seed loop and the maintenance
        # tick race during that window and produce two sockets for
        # the same remote.  Observed on live mainnet 2026-04-24.
        self._connecting: set[str] = set()

        self.wallet_id: bytes | None = None  # the entity_id that earns fees
        self.wallet_entity: Entity | None = None  # full entity for block signing
        # Serializes read-and-advance of wallet_entity.keypair._next_leaf
        # across (a) block-production sign() calls running in the thread
        # pool via asyncio.to_thread and (b) reserve_leaf RPC handlers
        # running on the event loop thread.  Without this lock, an
        # operator CLI transfer could read the same _next_leaf value
        # that the block producer is about to consume — two WOTS+
        # signatures at the same leaf mathematically reveal the private
        # key, so the lock is a correctness guard, not an optimization.
        import threading as _threading_wl
        self._wallet_leaf_lock = _threading_wl.Lock()
        self.receipt_issuer = None  # ReceiptIssuer for submission receipts
        # Per-IP receipt-subtree leaf-budget tracker, shared across
        # the RPC `_rpc_submit_transaction` path AND (when wired) the
        # public HTTPS SubmissionServer.  The same instance MUST flow
        # to both surfaces so an attacker can't split traffic across
        # HTTPS+RPC and drain the per-IP burst twice.  Constructed
        # eagerly because RPC is always-on; the HTTPS SubmissionServer
        # is opt-in and reads this through on construction.
        from messagechain.network.submission_server import (
            ReceiptBudgetTracker,
        )
        self.receipt_budget_tracker = ReceiptBudgetTracker()
        # Per-IP last-warning timestamps so the budget-exhaustion
        # warning log doesn't spam — one warning per IP per minute is
        # plenty signal for the operator without filling the journal
        # under sustained drain attempts.
        self._receipt_budget_warn_last: dict[str, float] = {}
        self._running = False

        # Network protection — must exist before syncer for the offense callback.
        # Ban state persists under data_dir so bans survive restarts; a peer
        # banned just before an OOM kill or maintenance reboot used to
        # reconnect fresh. Alongside anchors.json / peer_pins.json.
        import os as _os_ban
        _ban_path = (
            _os_ban.path.join(data_dir, "ban_scores.json")
            if data_dir
            else None
        )
        self.ban_manager = PeerBanManager(persistence_path=_ban_path)
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
            # WHY: check existence first so absence falls back to the
            # embedded TRUSTED_CHECKPOINTS tuple; if the operator did
            # ship a file, validate it strictly (malformed → raise).
            if _os.path.exists(cp_path):
                file_cps = load_checkpoints_file(cp_path, strict=True)
                by_height = {cp.block_number: cp for cp in checkpoints}
                for cp in file_cps:
                    by_height[cp.block_number] = cp
                checkpoints = list(by_height.values())
        if REQUIRE_CHECKPOINTS and not checkpoints:
            # Auto-waive threshold: previously 1000 blocks (~1 week at 600s).
            # A new community validator cloning the repo after the chain
            # crossed 1000 blocks would fail to start with a confusing
            # RuntimeError, and public launch was imminent.  Bumped to
            # 105_192 (~2 years, matches BOOTSTRAP_END_HEIGHT) so a fresh
            # community clone works throughout the bootstrap window.
            # Before the chain crosses this, the release process must
            # bake signed checkpoints into config.TRUSTED_CHECKPOINTS
            # (or deploy a checkpoints.json).  Long-range attack surface
            # is genuinely theoretical during bootstrap — the single
            # validator is also the single keyholder.
            _WAIVE_THRESHOLD = 105_192
            if self.blockchain.height < _WAIVE_THRESHOLD:
                logger.warning(
                    "No weak-subjectivity checkpoints loaded but chain is "
                    "in bootstrap window (height=%d < %d) — proceeding "
                    "without.  Ship signed checkpoints via a release update "
                    "before the chain crosses block %d.",
                    self.blockchain.height, _WAIVE_THRESHOLD, _WAIVE_THRESHOLD,
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
        # R2-#6: mirror the checkpoint set onto Blockchain so the gate
        # guards every block-entry path (announce/response/reorg), not
        # only IBD header batches.
        self.blockchain.set_trusted_checkpoints(checkpoints)

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
        # Operators can pin a stable token across restarts by setting
        # MESSAGECHAIN_RPC_AUTH_TOKEN; otherwise a fresh random token is
        # generated per startup (and must be retrieved from the keyfile).
        from messagechain.config import RPC_AUTH_ENABLED, RPC_AUTH_TOKEN
        self.rpc_auth_enabled = RPC_AUTH_ENABLED
        if RPC_AUTH_ENABLED:
            import os as _rng
            if RPC_AUTH_TOKEN:
                self.rpc_auth_token = RPC_AUTH_TOKEN
                self._rpc_auth_token_source = "env"
                if len(RPC_AUTH_TOKEN) < 16:
                    # Short tokens are dangerous — warn but accept
                    # (operator discretion).  Never log the value itself.
                    logger.warning(
                        "RPC auth token from env is shorter than 16 "
                        "characters (%d); accepting on operator "
                        "discretion but this is weak.",
                        len(RPC_AUTH_TOKEN),
                    )
            else:
                self.rpc_auth_token = _rng.urandom(32).hex()
                self._rpc_auth_token_source = "generated"
            self._log_rpc_auth_status()

        # inv/getdata: track recently seen tx hashes
        self._seen_txs: OrderedDict = OrderedDict()

    def _log_rpc_auth_status(self):
        # Never log any portion of the token. Operators retrieve it via
        # the configured RPC_AUTH_TOKEN env var or the keyfile, not logs.
        source = getattr(self, "_rpc_auth_token_source", "generated")
        if source == "env":
            logger.info("RPC auth enabled (token loaded from env)")
        else:
            logger.info("RPC auth enabled (token generated)")

    # _track_seen_tx, _get_peer_writer, _on_sync_offense,
    # _handle_task_exception, _current_cumulative_weight,
    # _next_connection_type now live on SharedRuntimeMixin.

    def _accept_peer_weight(self, claimed: int) -> int:
        """Sanity-cap a peer-reported cumulative weight. See Node._accept_peer_weight.

        NOT on the shared mixin: this implementation has drifted from
        node.py's version (server.py is more defensive — sanitizes
        non-int / negative claims before capping).  Reconciliation is
        logged as a B-small follow-up; for now both copies stay.
        """
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

    def _schedule_coro_threadsafe(self, coro, label: str):
        """Schedule a coroutine on the main event loop from any thread.

        Falls back to asyncio.create_task when called from inside the
        main loop's thread (the typical RPC path).  Returns the
        scheduled task/future so callers can attach exception loggers
        if they care; most don't.

        Without this, RPC handlers like _rpc_submit_transfer that fan
        out to gossip via asyncio.create_task crash with "no running
        event loop" the moment they are invoked from a worker thread
        (the public-feed faucet is the canonical case).  The mempool
        admission has already succeeded by that point, so the tx will
        eventually propagate via passive mempool sync, but the RPC
        return value lies as "Internal error" and the caller cannot
        distinguish failure from success.
        """
        loop = getattr(self, "_main_loop", None)
        if loop is None:
            # start() has not run yet; can't schedule.  Drop on the
            # floor -- this only happens during teardown / very early
            # boot, neither of which run faucet RPCs.
            return None
        try:
            in_loop_thread = asyncio.get_running_loop() is loop
        except RuntimeError:
            in_loop_thread = False
        if in_loop_thread:
            t = asyncio.create_task(coro)
            t.add_done_callback(
                lambda x: self._handle_task_exception(label, x)
            )
            return t
        # Cross-thread path: schedule on the main loop and let it
        # log any exception via the same handler.
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        fut.add_done_callback(
            lambda f: self._handle_task_exception(label, f)
        )
        return fut

    async def start(self):
        """Start P2P server, RPC server, and block production."""
        # Capture the main event loop so RPC handlers invoked from
        # OTHER threads (e.g. the public-feed faucet running in
        # PublicFeedServer's worker pool) can schedule async tasks
        # via run_coroutine_threadsafe instead of asyncio.create_task,
        # which only works inside the loop's own thread.  Without
        # this, threaded callers hit "no running event loop" the
        # moment a handler tries to gossip the tx -- observed on
        # mainnet 2026-04-26 when the 1.8.0 faucet's first drip
        # came back as "Internal error" even though the mempool
        # admission had already succeeded.
        self._main_loop = asyncio.get_running_loop()

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

        # Start P2P server.  When P2P_TLS_ENABLED is on we wrap the
        # listener with a server SSL context so the wire is actually
        # encrypted — previously server.py's listener was plain TCP
        # despite config.P2P_TLS_ENABLED=True, silently breaking the
        # config promise.  Mirrors messagechain/network/node.py:443
        # which already did this correctly.  The cert is lazily
        # generated under data_dir (or a per-entity tempdir if
        # data_dir is None) so restarts reuse the same fingerprint
        # and the eventual TOFU pin stays stable.
        from messagechain import config as _cfg
        from messagechain.network.tls import create_node_ssl_context
        p2p_server_ssl = None
        if getattr(_cfg, "P2P_TLS_ENABLED", True):
            p2p_server_ssl = create_node_ssl_context(data_dir=self.data_dir)
        p2p_server = await asyncio.start_server(
            self._handle_p2p_connection, "0.0.0.0", self.p2p_port,
            ssl=p2p_server_ssl,
        )
        logger.info(
            f"P2P listening on port {self.p2p_port} "
            f"({'TLS' if p2p_server_ssl else 'plain'})"
        )

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

        # Peer maintenance: re-dial dropped seeds.  Without this, a
        # dead seed connection never heals and the node stays solo.
        t = asyncio.create_task(self._peer_maintenance_loop())
        t.add_done_callback(
            lambda x: self._handle_task_exception("peer_maintenance_loop", x)
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

        # Surface any on-chain release manifest to the operator BEFORE
        # the "Server running" line so "UPDATE AVAILABLE" sits next to
        # the other startup-identity lines in journald, rather than
        # buried below the long-running log stream.  Silent when no
        # manifest is recorded.
        try:
            from messagechain import __version__ as _mc_version
            log_release_status(logger, self.blockchain, _mc_version)
        except Exception as e:
            # Never let a notification bug block node startup — the
            # release helper is non-critical operator UX.
            logger.warning(f"Release status check failed: {e}")

        logger.info(f"Server running. P2P={self.p2p_port} RPC={self.rpc_port}")
        # Log only the first 16 hex chars — full entity_id is sensitive
        # operator metadata (identifies the validator in journald / log
        # aggregation).  The truncated prefix is enough to correlate
        # across this node's logs; the full id is available via
        # `messagechain account` when needed.
        if self.wallet_id:
            logger.info(f"Wallet: {self.wallet_id.hex()[:16]}...")
        else:
            logger.info("Wallet: NOT SET")
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
        # Release the data_dir lock LAST — after chaindb is closed and
        # all keyfile writes have flushed.  Releasing earlier would
        # open a window where a second starter could acquire the lock
        # while our shutdown is still persisting state.
        if self._data_dir_lock is not None:
            self._data_dir_lock.__exit__(None, None, None)
            self._data_dir_lock = None

    # ── RPC Handler (client interface) ──────────────────────────────

    async def _handle_rpc_connection(self, reader, writer):
        """Handle a client RPC request."""
        try:
            # Rate limit by client IP
            addr = writer.get_extra_info("peername")
            client_ip = addr[0] if addr else "unknown"
            # Outer connection-level check — explicit cost=1 so this
            # gate catches cheap-request floods (300/min).  A second,
            # method-specific cost is charged inside `_process_rpc`
            # after the method name is known; expensive methods like
            # submit_transaction charge RPC_COST_EXPENSIVE there so
            # an attacker burning CPU on WOTS+ verify is rate-limited
            # at ~15 reqs/min instead of ~300.
            if not self.rpc_rate_limiter.check(client_ip, cost=RPC_COST_CHEAP):
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
            # Parse the request body with depth-bounded JSON.  Separate
            # try/except (from the outer handler) so that a malformed
            # request gets a structured `{"ok": False, "error": ...}`
            # response instead of a silent socket close — honest clients
            # with a typo or a misencoded payload see WHY their request
            # failed.  The error message is bounded (no raw input echo)
            # so we don't open a reflection vector.  Iter-3 adversarial
            # probe surfaced this: `echo '{bad json' | socat` got an EOF
            # with no reason, and a client debugging their integration
            # had nothing to go on.
            try:
                request = safe_json_loads(data.decode("utf-8"), max_depth=16)
            except (ValueError, UnicodeDecodeError) as e:
                resp = json.dumps({
                    "ok": False,
                    "error": f"Invalid JSON request: {str(e)[:120]}",
                }).encode("utf-8")
                writer.write(struct.pack(">I", len(resp)))
                writer.write(resp)
                await writer.drain()
                return

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

            response = await self._process_rpc(request, client_ip=client_ip)

            resp_bytes = json.dumps(response).encode("utf-8")
            writer.write(struct.pack(">I", len(resp_bytes)))
            writer.write(resp_bytes)
            await writer.drain()
        except asyncio.IncompleteReadError as e:
            # A client (or TCP health probe) closed the connection
            # before sending the full 4-byte length prefix — benign
            # and expected on GCE where the load balancer dials then
            # immediately closes.  Demoted to DEBUG so the journal
            # stays readable during incident triage.  Mid-body
            # IncompleteRead is still DEBUG for the same reason.
            logger.debug(f"RPC client closed early: {e}")
        except Exception as e:
            logger.error(f"RPC error: {e}")
        finally:
            writer.close()

    async def _process_rpc(self, request: dict, client_ip: str = "") -> dict:
        """Process a single RPC request from a client.

        `client_ip` is the peer IP from the TCP connection.  When
        present, we charge a method-specific cost against the rate
        limiter (`_RPC_METHOD_COST`) BEFORE dispatching — so expensive
        methods (WOTS+ verify) consume more of the per-IP budget than
        cheap ones (dict lookups).  When empty (unit-test harnesses
        that call `_process_rpc` directly without a socket), the
        per-method charge is skipped — the outer `_handle_rpc_connection`
        has no test coverage in those cases so there's nothing to
        defend against.
        """
        method = request.get("method", "")
        # Any method that reaches a `request["params"]`-style access below
        # would KeyError if `params` is missing, bubbling up to the outer
        # except in _handle_rpc_connection as a bare connection close with
        # no response body.  Validate once here so every client gets a
        # clean structured error instead of a reset.
        if "params" not in request or not isinstance(request.get("params"), dict):
            request["params"] = {}

        # Method-cost rate-limit gate.  Only applies when we have a
        # real `client_ip` (production path).  The outer handler
        # already charged RPC_COST_CHEAP=1; this adds `cost - 1` more
        # tokens for expensive methods so a submit_transaction flood
        # burns ~20 tokens/call instead of ~1.  We charge the FULL
        # method cost here (not a delta) because each charge is an
        # independent allow/deny decision — if the budget is at 299
        # and the method costs 20, we want to reject cleanly rather
        # than let the first token through and then get short.
        if client_ip:
            method_cost = _RPC_METHOD_COST.get(method, RPC_COST_CHEAP)
            if method_cost > RPC_COST_CHEAP and not self.rpc_rate_limiter.check(
                client_ip, cost=method_cost,
            ):
                return {
                    "ok": False,
                    "error": f"Rate limited: method '{method}' exceeds budget",
                }

        if method == "submit_transaction":
            # Run the synchronous submit handler in the asyncio thread
            # pool.  The handler internally calls
            # receipt_issuer.issue() which performs a WOTS+ sign and
            # waits up to 30s on a cross-process file lock — both
            # CPU-bound and I/O-blocking.  Calling it inline blocks
            # the entire asyncio event loop for the duration, freezing
            # every other RPC handler and peer-message dispatch.  Under
            # a client retry-loop the lock contention compounds and
            # the validator becomes globally unresponsive.  to_thread
            # isolates the blocking work; the event loop stays
            # available for concurrent reads + peer traffic.
            #
            # `client_ip` is threaded through so the handler can gate
            # `request_receipt` against the per-IP receipt-subtree
            # leaf budget — see the receipt-budget gate inside
            # `_rpc_submit_transaction` for the threat model.
            return await asyncio.to_thread(
                self._rpc_submit_transaction, request["params"],
                client_ip,
            )

        elif method == "get_entity":
            return self._rpc_get_entity(request["params"])

        elif method == "get_chain_info":
            info = self.blockchain.get_chain_info()
            info["sync_status"] = self.syncer.get_sync_status()
            return {"ok": True, "result": info}

        elif method == "get_latest_release":
            return self._rpc_get_latest_release(request["params"])

        elif method == "get_fee_estimate":
            # Optional ``message_bytes`` lets callers get a size-aware
            # absolute-fee estimate (median fee-per-byte × size, floored
            # at MARKET_FEE_FLOOR).  Omitted/zero → returns the floor.
            mb_raw = request.get("params", {}).get("message_bytes", 0)
            try:
                mb = int(mb_raw)
            except (TypeError, ValueError):
                mb = 0
            return {"ok": True, "result": {
                "fee_estimate": self.mempool.get_fee_estimate(message_bytes=mb)
            }}

        elif method == "get_nonce":
            entity_id = parse_hex(request["params"].get("entity_id", ""), expected_len=32)
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id (must be 32 bytes hex)"}
            # Use the mempool-aware computation so consecutive client
            # submissions don't collide with their own still-pending txs.
            # Submission validation gates on _get_pending_nonce_all_pools
            # too (see _rpc_submit_transaction / _rpc_stake / _rpc_unstake),
            # so this RPC must agree — otherwise a client that fetches
            # the chain-only nonce, signs, and submits while a prior tx
            # is still in mempool gets "Invalid nonce: expected N+1, got N"
            # rejections that only clear when the pending tx lands.
            nonce = self._get_pending_nonce_all_pools(entity_id)
            watermark = self.blockchain.get_leaf_watermark(entity_id)
            # Return both together so clients only need one roundtrip to
            # safely position their WOTS+ keypair before signing. The
            # leaf watermark is the authoritative source of truth for
            # "next safe leaf index" — the nonce is not, because some
            # operations (registration, block production, attestations)
            # consume leaves without incrementing the nonce.
            return {"ok": True, "result": {"nonce": nonce, "leaf_watermark": watermark}}

        elif method == "get_leaf_watermark":
            entity_id = parse_hex(request["params"].get("entity_id", ""), expected_len=32)
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id (must be 32 bytes hex)"}
            watermark = self.blockchain.get_leaf_watermark(entity_id)
            return {"ok": True, "result": {"leaf_watermark": watermark}}

        elif method == "get_authority_key":
            entity_id = parse_hex(request["params"].get("entity_id", ""), expected_len=32)
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id (must be 32 bytes hex)"}
            ak = self.blockchain.get_authority_key(entity_id)
            return {"ok": True, "result": {
                "authority_key": ak.hex() if ak else None,
            }}

        elif method == "set_authority_key":
            return self._rpc_set_authority_key(request["params"])

        elif method == "emergency_revoke":
            return self._rpc_emergency_revoke(request["params"])

        elif method == "set_receipt_subtree_root":
            return self._rpc_set_receipt_subtree_root(request["params"])

        elif method == "get_local_receipt_root":
            return self._rpc_get_local_receipt_root(request["params"])

        elif method == "is_revoked":
            entity_id = parse_hex(request["params"].get("entity_id", ""), expected_len=32)
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id (must be 32 bytes hex)"}
            return {"ok": True, "result": {"revoked": self.blockchain.is_revoked(entity_id)}}

        elif method == "rotate_key":
            return self._rpc_rotate_key(request["params"])

        elif method == "get_key_status":
            entity_id = parse_hex(request["params"].get("entity_id", ""), expected_len=32)
            if entity_id is None:
                return {"ok": False, "error": "Invalid entity_id (must be 32 bytes hex)"}
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
            # Same to_thread isolation as submit_transaction — the
            # submit path may sign a SubmissionReceipt synchronously.
            # client_ip threaded through so the receipt-budget gate
            # fires on the transfer surface too (per-IP cap shared
            # with the message and react surfaces).
            return await asyncio.to_thread(
                self._rpc_submit_transfer, request["params"],
                client_ip,
            )

        elif method == "submit_react":
            # Same to_thread isolation as submit_transaction.  ReactTx
            # admission verifies WOTS+ signatures, which is CPU-bound;
            # keeping it off the event loop preserves RPC liveness for
            # other clients (and for our own block-production peer
            # gossip) while the verify runs.
            return await asyncio.to_thread(
                self._rpc_submit_react, request["params"],
                client_ip,
            )

        elif method == "get_user_trust":
            return self._rpc_get_user_trust(request["params"])

        elif method == "get_message_score":
            return self._rpc_get_message_score(request["params"])

        elif method == "reserve_leaf":
            return self._rpc_reserve_leaf(request["params"])

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
            params = request.get("params", {}) or {}
            voter_id_hex = params.get("voter_id")
            voter_id_bytes: bytes | None = None
            if isinstance(voter_id_hex, str) and voter_id_hex:
                try:
                    voter_id_bytes = bytes.fromhex(voter_id_hex)
                except ValueError:
                    return {"ok": False, "error": "Invalid voter_id (expected hex)"}
            proposals = self.blockchain.governance.list_proposals(
                self.blockchain.height, voter_id=voter_id_bytes,
            )
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

        elif method == "get_peers":
            return self._rpc_get_peers()

        elif method == "get_checkpoint_at_height":
            return self._rpc_get_checkpoint_at_height(request["params"])

        elif method == "estimate_fee":
            return self._rpc_estimate_fee(request.get("params", {}))

        elif method == "get_tx_status":
            return self._rpc_get_tx_status(request.get("params", {}))

        else:
            return {"ok": False, "error": f"Unknown method: {method}"}

    def _resolve_rpc_receipt_issuer(
        self, params: dict, client_ip: str,
    ):
        """Pick the right `receipt_issuer` for this RPC submission.

        Centralized here so every RPC submit path (message, transfer,
        react) gets the same per-IP receipt-budget gate the audit
        (2026-04-27) requires.  Without a gate the RPC `request_receipt`
        opt-in lets a single attacker IP drain the 65k-leaf
        RECEIPT_SUBTREE in ~3 days, silently collapsing the
        censorship-evidence pipeline.

        Logic mirrors the HTTPS `_should_request_rejection` shape:
          * `request_receipt` false / unset           -> None (no leaf)
          * tracker missing / empty client_ip         -> issuer
            (test/legacy paths bypass the gate; production always
            constructs the tracker in Server.__init__ and threads
            client_ip from _process_rpc)
          * `rejection_budget_check(ip)` returns True -> issuer
            (token consumed, leaf will be issued)
          * `rejection_budget_check(ip)` returns False -> None +
            rate-limited warning log (silent downgrade — submission
            still processes, client just doesn't get a receipt)

        The bucket is shared with the HTTPS surface so an attacker
        can't split traffic across HTTPS+RPC and drain twice.
        """
        if not params.get("request_receipt"):
            return None
        budget_tracker = getattr(self, "receipt_budget_tracker", None)
        if budget_tracker is None or not client_ip:
            return self.receipt_issuer
        if budget_tracker.rejection_budget_check(client_ip):
            return self.receipt_issuer
        self._maybe_warn_receipt_budget_exhausted(client_ip)
        return None

    def _maybe_warn_receipt_budget_exhausted(self, client_ip: str) -> None:
        """Log a warning when an IP's receipt budget kicks in.

        Rate-limited per-IP at one warning per minute so a sustained
        drain attempt doesn't fill the journal.  The warning lets the
        operator correlate complaints from receipted clients with
        upstream budget events without grepping submission logs.

        Defensive against `Server.__new__` test paths that skip
        `__init__`: if the dict isn't there, lazy-initialize it.
        """
        import time as _t
        if not hasattr(self, "_receipt_budget_warn_last"):
            self._receipt_budget_warn_last = {}
        now = _t.time()
        last = self._receipt_budget_warn_last.get(client_ip, 0.0)
        if now - last < 60.0:
            return
        self._receipt_budget_warn_last[client_ip] = now
        logger.warning(
            "receipt-budget exhausted for client_ip=%s; submissions "
            "still processing without receipt.  See "
            "messagechain/network/submission_server.py "
            "ReceiptBudgetTracker for context.",
            client_ip,
        )

    def _rpc_submit_transaction(self, params: dict, client_ip: str = "") -> dict:
        """Accept a signed transaction from a client.

        Routes through `submit_transaction_to_mempool` (the same
        helper the public HTTPS endpoint uses) so RPC submissions
        get the SAME censorship-evidence defense as HTTPS
        submissions.  The helper threads the validator's
        receipt_issuer through, so the client receives a signed
        SubmissionReceipt they can later weaponize as
        CensorshipEvidenceTx if the receipted tx fails to land
        on-chain within EVIDENCE_INCLUSION_WINDOW.

        Pre-fix this path inlined its own validate+add and never
        consulted the issuer -- a coerced validator that fronts
        only RPC (or whose RPC port leaks via reverse proxy / SSH
        tunnel) admitted-and-dropped txs with zero on-chain
        accountability, defeating the entire censorship-evidence
        pipeline for the RPC surface.

        `client_ip` (default ""): peer IP from the TCP connection,
        threaded in by `_process_rpc`.  Used to gate the
        `request_receipt` opt-in receipt-on-success path against the
        per-IP receipt-subtree leaf budget so an attacker over RPC
        cannot drain the validator's RECEIPT_SUBTREE (65k leaves at
        height 16) by spamming receipted submissions from a single
        IP.  Empty `client_ip` (test harnesses calling the handler
        directly with no socket) skips the gate.
        """
        try:
            from messagechain.network.submission_server import (
                submit_transaction_to_mempool,
            )
            tx = MessageTransaction.deserialize(params["transaction"])
            # Receipt issuance is OPT-IN per submission via the
            # x-mc-receipt parameter.  The default path skips the
            # receipt subtree entirely so submission stays fast even
            # if the receipt-subtree leaf-cursor lock is held by
            # another in-flight sign.  Pre-fix, every submit
            # synchronously waited up to 30s on that lock — a single
            # contention event froze every other submit on the
            # validator.  Censorship-evidence clients that need a
            # receipt can opt in by setting `request_receipt: true`
            # in the submission params.
            #
            # Per-IP budget gate (audit 2026-04-27): the HTTPS surface
            # protects its receipt-subtree via a dedicated rejection-
            # budget bucket; the RPC surface used to skip the gate
            # entirely.  An attacker over RPC could burn ~21k leaves
            # /day from one IP and drain the 65k-leaf subtree in 3
            # days, silently collapsing the entire censorship-evidence
            # pipeline.  `_resolve_rpc_receipt_issuer` consults the
            # SAME shared tracker the HTTPS context uses (so cross-
            # surface drain is also closed) and returns None on
            # exhaustion — submission still processes, the client
            # just doesn't get a receipt and no leaf burns.
            issuer = self._resolve_rpc_receipt_issuer(params, client_ip)
            result = submit_transaction_to_mempool(
                tx, self.blockchain, self.mempool,
                receipt_issuer=issuer,
            )
            if not result.ok:
                return {"ok": False, "error": result.error}
            # Relay via inv (not full tx flood).  Uses the
            # threadsafe scheduler so the same handler works whether
            # called from the asyncio RPC dispatch (typical) or from
            # a worker thread (faucet path).
            tx_hash_hex = tx.tx_hash.hex()
            self._track_seen_tx(tx_hash_hex)
            self._schedule_coro_threadsafe(
                self._relay_tx_inv([tx_hash_hex]), "relay_tx_inv",
            )
            payload = {
                "tx_hash": tx.tx_hash.hex(),
                "fee": tx.fee,
                "message": (
                    "Transaction accepted into mempool (duplicate)"
                    if result.duplicate
                    else "Transaction accepted into mempool"
                ),
            }
            # Surface the signed receipt in the response when the
            # validator issued one, so RPC clients can weaponize it
            # as CensorshipEvidenceTx exactly like HTTPS clients can.
            if result.receipt_hex:
                payload["receipt"] = result.receipt_hex
            return {"ok": True, "result": payload}
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

            # Order matters: run cheap nonce/leaf/balance checks BEFORE
            # the expensive WOTS+ verify.  An attacker flooding malformed
            # stake txs otherwise burns a full verify cycle per
            # attempt; with reordering, they waste only a dict lookup.
            # Mirrors the order in blockchain.validate_transaction.
            expected_nonce = self._get_pending_nonce_all_pools(entity_id)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if tx.signature.leaf_index < self.blockchain.get_leaf_watermark(entity_id):
                return {"ok": False, "error": "WOTS+ leaf already consumed - leaf reuse rejected"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee + tx.amount):
                return {"ok": False, "error": "Insufficient balance for staking + fee"}

            if not self._check_leaf_across_all_pools(tx):
                return {"ok": False, "error": "WOTS+ leaf already used by another pending tx - leaf reuse rejected"}

            # Cheap gates passed; now run the expensive WOTS+ verify.
            public_key = self.blockchain.public_keys[entity_id]
            if not verify_stake_transaction(
                tx, public_key,
                block_height=self.blockchain.height,
                current_height=self.blockchain.height + 1,
            ):
                return {"ok": False, "error": "Invalid stake transaction signature"}

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

            # Cheap gates before expensive WOTS+ verify (same hardening
            # as _rpc_stake).  Validate nonce via pending so consecutive
            # submissions are accepted without waiting for block inclusion.
            expected_nonce = self._get_pending_nonce_all_pools(entity_id)
            if tx.nonce != expected_nonce:
                return {"ok": False, "error": f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"}

            if tx.signature.leaf_index < self.blockchain.get_leaf_watermark(entity_id):
                return {"ok": False, "error": "WOTS+ leaf already consumed - leaf reuse rejected"}

            if not self.blockchain.supply.can_afford_fee(entity_id, tx.fee):
                return {"ok": False, "error": "Insufficient balance for fee"}

            if self.blockchain.supply.get_staked(entity_id) < tx.amount:
                return {"ok": False, "error": "Insufficient staked amount"}

            if not self._check_leaf_across_all_pools(tx):
                return {"ok": False, "error": "WOTS+ leaf already used by another pending tx - leaf reuse rejected"}

            # Cheap gates passed; run the expensive authority-key verify.
            # Unstake is an authority-gated operation: requires the cold
            # authority key.  If the entity has not promoted a separate
            # cold key, authority_key == signing key.
            authority_key = self.blockchain.get_authority_key(entity_id)
            if not verify_unstake_transaction(tx, authority_key):
                return {"ok": False, "error": "Invalid unstake signature - unstake must be signed by the authority (cold) key"}

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
            # keyed).  Cold-signed txs use the cold key's own leaf
            # namespace — nothing to do with the entity's hot-key
            # watermark — so skip the check for them.
            #
            # SetReceiptSubtreeRootTransaction is ALWAYS cold-signed
            # (the cold-key gate is the whole point — a compromised
            # hot key must not be able to swap the receipting
            # identity).  Without this carve-out, the cold key's leaf
            # 0/1/2/etc. is compared against the validator entity's
            # hot-key watermark (often in the hundreds after sustained
            # block production) and the tx is silently swept every
            # proposal round, never landing.  Observed on mainnet
            # 2026-04-25 when registering validator-2's receipt root
            # post cold-key promotion.
            sig = getattr(tx, "signature", None)
            cls_name = tx.__class__.__name__
            is_cold_signed = (
                cls_name == "RevokeTransaction"
                or cls_name == "SetReceiptSubtreeRootTransaction"
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
        # Tier 17 react pool — keyed on tx_hash with `voter_id`/`nonce`
        # fields, not entity_id.  Without this scan a user submitting
        # back-to-back ReactTxs would reuse a nonce and the second
        # one would be rejected at admission.
        react_pool = getattr(self.mempool, "react_pool", None) or {}
        for rtx in react_pool.values():
            if (
                getattr(rtx, "voter_id", None) == entity_id
                and rtx.nonce >= on_chain_nonce
                and rtx.nonce + 1 > best
            ):
                best = rtx.nonce + 1
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
            # rejected at block apply time.  Hard-fork-gated via
            # `get_validator_min_stake` so post-activation we sweep at
            # the raised 10_000 floor (or skip if liquid is insufficient).
            apply_height = self.blockchain.height + 1
            if stakeable < _cfg.get_validator_min_stake(apply_height):
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

    def _maybe_notify_governance_proposals(self) -> None:
        """Best-effort: email the operator if a new open proposal landed.

        Called after each successful add_block.  Operator-runtime path
        ONLY — consensus state never depends on the outcome of this
        call.  Behavior:
          * No-op when notify.email.enabled is unset / false.
          * No-op when SMTP credentials are missing.
          * Idempotent: each proposal_id is emailed at most once across
            restarts (state lives in <data_dir>/notify_state.json).
          * Swallows ALL exceptions — block production must never abort
            because the email subsystem misbehaved.
        """
        try:
            from messagechain.runtime import notify as _notify
            from messagechain.runtime import onboarding as _ob
            cfg = _ob.read_onboard_config()
            if not cfg.get("notify.email.enabled"):
                return  # cheap fast-path; avoid any further work
            state_path = _notify.default_state_path(self.data_dir)
            current_height = self.blockchain.height
            _notify.process_block_for_notifications(
                current_height=current_height,
                list_proposals=lambda: (
                    self.blockchain.governance.list_proposals(current_height)
                ),
                config=cfg,
                state_path=state_path,
            )
        except Exception as e:
            logger.warning(
                "notify: governance-proposal hook failed (%s); "
                "consensus unaffected",
                type(e).__name__,
            )

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
        # Round-12: scan the react pool too.  Pre-fix the cross-pool
        # dedupe didn't include react_pool, so a wallet bug or attacker
        # could land a Transfer-then-React (or Message-then-React) at
        # the same WOTS+ leaf -- the second sig leaks the one-time-key
        # secret for that leaf, letting any observer forge arbitrary
        # signatures.  Mirrors the in-block sweep added in
        # blockchain.py and the per-tx watermark gate added to
        # _validate_react_tx_in_block.
        react_pool = getattr(self.mempool, "react_pool", None) or {}
        for existing in react_pool.values():
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
        # Round-12: include the react pool in the legacy
        # entity-id-keyed sweep too -- same defect class as the
        # signer-keyed path above.
        react_pool = getattr(self.mempool, "react_pool", None) or {}
        for existing in react_pool.values():
            sig = getattr(existing, "signature", None)
            eid = getattr(existing, "voter_id", None)
            if sig is None or eid is None:
                continue
            if eid == entity_id and sig.leaf_index == leaf_index:
                return False
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

    def _rpc_set_receipt_subtree_root(self, params: dict) -> dict:
        """Accept a SetReceiptSubtreeRoot tx signed by the cold authority key.

        Registers (or rotates) this validator's receipt-subtree root
        public key in chain state.  Without this mapping, submission
        receipts are unverifiable — the whole censorship-evidence
        pipeline collapses.  Cold-key gated so a compromised hot key
        cannot swap out the receipting identity mid-flight.
        """
        try:
            from messagechain.core.receipt_subtree_root import (
                SetReceiptSubtreeRootTransaction,
            )
            tx = SetReceiptSubtreeRootTransaction.deserialize(
                params["transaction"],
            )
            ok, reason = self._queue_authority_tx(
                tx,
                validate_fn=self.blockchain.validate_set_receipt_subtree_root,
            )
            if not ok:
                return {"ok": False, "error": reason}
            return {"ok": True, "result": {
                "entity_id": tx.entity_id.hex(),
                "root_public_key": tx.root_public_key.hex(),
                "tx_hash": tx.tx_hash.hex(),
                "status": "pending — will be included in next block",
            }}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_get_local_receipt_root(self, _params: dict) -> dict:
        """Return this validator's locally-derived receipt-subtree root.

        Operators in the hot/cold split need this value to build a
        SetReceiptSubtreeRoot tx with the cold key from a separate
        machine — without it they would have to scrape the root out of
        boot logs or the cache file. The root is a public commitment
        that's about to be written on-chain anyway, so no auth is
        required.

        Returns `{"installed": False}` on a relay-only node (no receipt
        issuer).
        """
        issuer = getattr(self, "receipt_issuer", None)
        if issuer is None:
            return {"ok": True, "result": {"installed": False}}
        local_root = issuer.subtree_keypair.public_key
        registered = self.blockchain.receipt_subtree_roots.get(
            issuer.issuer_id,
        )
        return {"ok": True, "result": {
            "installed": True,
            "entity_id": issuer.issuer_id.hex(),
            "root_public_key": local_root.hex(),
            "registered_root": registered.hex() if registered else None,
            "registration_needed": registered != local_root,
        }}

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
            # Thread the prospective inclusion height so mempool
            # admission applies the same rule as block validation
            # (Tier 15 length-prefix gate, Tier 19 fee floor and
            # tightened byte caps).  Without this, a tx that meets
            # the legacy floor but fails the post-fork rule would sit
            # in the pool only to be rejected at block time -- wasted
            # work and a confusing failure mode for clients.
            if not verify_proposal(
                tx, public_key,
                current_height=self.blockchain.height + 1,
            ):
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
            # Thread inclusion height so mempool admission matches
            # block validation (R5-A signature-aware fee floor).
            if not verify_vote(
                tx, public_key,
                current_height=self.blockchain.height + 1,
            ):
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
        """Price a prospective tx of any kind without submitting.

        Single source of truth for fee quotes spanning every tx kind
        (`message`, `transfer`, `stake`, `unstake`, `react`, `propose`,
        `vote`, `rotate-key`).  Replaces the prior message+transfer-
        only path; the unified surface mirrors the unified auto-fee
        helper in `messagechain.economics.auto_fee` so a CLI quote and
        a CLI submission compute the same number.

        Returns:
          - min_fee: protocol admission floor at the live tip height.
          - mempool_fee: percentile estimate at `target_blocks` rung,
            multiplied by stored bytes (for kinds where density ranks).
          - recommended_fee: max(min_fee, mempool_fee).
          - tx_type / urgency / target_blocks / stored_bytes /
            fee_per_byte: breakdown fields for the CLI to display.
          - recipient_is_new (transfers only): surfaced for
            NEW_ACCOUNT_FEE awareness.

        Pass `target_blocks` (1 / 3 / 10 typical) to drive the
        percentile rung; omit for the legacy median behavior.
        """
        from messagechain.core.transaction import calculate_min_fee
        from messagechain.config import (
            MIN_FEE, NEW_ACCOUNT_FEE, MAX_MESSAGE_CHARS,
            FEE_INCLUDES_SIGNATURE_HEIGHT,
        )
        from messagechain.economics.auto_fee import (
            TX_TYPES, tx_floor, stored_size_for,
        )

        kind = params.get("kind", "message")
        if kind not in TX_TYPES:
            return {"ok": False, "error": f"Unknown fee kind: {kind}"}

        target_height = self.blockchain.height + 1
        target_blocks = int(params.get("target_blocks", 3) or 3)
        urgency = params.get("urgency", "normal")
        recipient_is_new = False
        stored_bytes = 0
        message_bytes = 0  # for the mempool size-aware estimator
        payload_bytes = 0

        if kind == "message":
            msg = params.get("message", "")
            if not isinstance(msg, str):
                return {"ok": False, "error": "message must be a string"}
            if len(msg) > MAX_MESSAGE_CHARS:
                return {"ok": False, "error": f"Message exceeds {MAX_MESSAGE_CHARS} chars"}
            msg_bytes = msg.encode("utf-8")
            message_bytes = len(msg_bytes)
            stored_bytes = stored_size_for(
                "message", message_bytes=message_bytes,
            )
            # Live admission rule mirrors the legacy path so a quote
            # never under-prices vs what a submit will face.  Pre-Tier-16
            # signature-aware pricing is still respected if requested.
            sig_bytes = params.get("signature_bytes")
            if (
                target_height >= FEE_INCLUDES_SIGNATURE_HEIGHT
                and isinstance(sig_bytes, int)
                and sig_bytes > 0
            ):
                min_fee = calculate_min_fee(
                    msg_bytes, signature_bytes=sig_bytes,
                    current_height=target_height,
                )
            else:
                min_fee = calculate_min_fee(
                    msg_bytes, current_height=target_height,
                )
        elif kind == "transfer":
            recipient_id_hex = params.get("recipient_id")
            if recipient_id_hex:
                recipient_id = parse_hex(recipient_id_hex, expected_len=32)
                if recipient_id is not None:
                    if self.blockchain._recipient_is_new(recipient_id):
                        recipient_is_new = True
            min_fee = tx_floor(
                "transfer",
                current_height=target_height,
                recipient_is_new=recipient_is_new,
            )
            stored_bytes = stored_size_for("transfer")
        elif kind == "propose":
            payload_bytes = int(params.get("payload_bytes", 0) or 0)
            min_fee = tx_floor(
                "propose",
                payload_bytes=payload_bytes,
                current_height=target_height,
            )
            stored_bytes = stored_size_for("propose", payload_bytes=payload_bytes)
        elif kind in ("stake", "unstake", "react", "vote", "rotate-key"):
            min_fee = tx_floor(kind, current_height=target_height)
            stored_bytes = stored_size_for(kind)
        else:
            # TX_TYPES gate above already filtered, but be defensive.
            return {"ok": False, "error": f"Unknown fee kind: {kind}"}

        # Drive the mempool percentile estimator at the urgency-derived
        # rung.  For kinds where density doesn't apply (no stored bytes,
        # or the kind isn't in the mempool's pending pool), the
        # estimator returns the floor and the type-specific min_fee
        # binds.
        try:
            mempool_fee = self.mempool.get_fee_estimate(
                message_bytes=message_bytes, target_blocks=target_blocks,
            )
        except TypeError:
            # Older mempool implementations without target_blocks.
            mempool_fee = self.mempool.get_fee_estimate(
                message_bytes=message_bytes,
            )

        recommended = max(int(min_fee), int(mempool_fee))
        fee_per_byte = (
            recommended / stored_bytes if stored_bytes > 0 else 0
        )
        result = {
            "tx_type": kind,
            "urgency": urgency,
            "target_blocks": target_blocks,
            "stored_bytes": stored_bytes,
            "fee_per_byte": fee_per_byte,
            "min_fee": min_fee,
            "mempool_fee": mempool_fee,
            "recommended_fee": recommended,
            "recipient_is_new": recipient_is_new,
        }
        return {"ok": True, "result": result}

    def _rpc_reserve_leaf(self, params: dict) -> dict:
        """Atomically reserve the next WOTS+ leaf for a co-resident signer.

        Co-resident operator flow:
          1. CLI (cmd_transfer / cmd_stake) runs on the same host as the
             validator daemon and signs with the same entity the daemon
             block-signs with.
          2. CLI calls reserve_leaf before signing.
          3. Server picks `leaf = max(in-memory _next_leaf, chain watermark)`,
             advances its in-memory _next_leaf to leaf+1 (and persists the
             leaf index if a path is wired), returns leaf.
          4. CLI signs at leaf; submits tx via the usual RPC path.
          5. The daemon's next block sign will NOT collide — its own
             _next_leaf was already bumped past `leaf` in step 3.

        If the caller's entity_id doesn't match this daemon's wallet,
        no reservation is possible — we return the current chain
        watermark as a hint so the caller can still use the legacy
        watermark-only path (off-host signers never had coordination
        and this RPC doesn't regress them).

        Returns {'leaf_index': int, 'reserved': bool} where `reserved`
        is True iff the daemon actually advanced its counter.
        """
        entity_id = parse_hex(params.get("entity_id", ""), expected_len=32)
        if entity_id is None:
            return {"ok": False, "error": "Invalid entity_id (must be 32 bytes hex)"}

        chain_watermark = self.blockchain.get_leaf_watermark(entity_id)

        # Off-host / third-party signer case: we don't hold their keypair,
        # so we cannot burn a leaf on their behalf.  Return the watermark
        # as a hint and let the caller fall back to legacy semantics.
        if (
            self.wallet_entity is None
            or self.wallet_id is None
            or entity_id != self.wallet_id
        ):
            return {
                "ok": True,
                "result": {
                    "leaf_index": chain_watermark,
                    "reserved": False,
                },
            }

        # Co-resident signer: serialize with block production via the
        # shared lock.  max() takes the later of (our in-memory counter,
        # chain-visible watermark) so a CLI tx signed at leaf L that is
        # still in the mempool — not yet folded into the chain watermark
        # but already persisted to _next_leaf via this RPC — won't be
        # handed out again to a second concurrent reserve_leaf caller.
        with self._wallet_leaf_lock:
            kp = self.wallet_entity.keypair
            leaf = max(kp._next_leaf, chain_watermark)
            if leaf >= kp.num_leaves:
                return {
                    "ok": False,
                    "error": (
                        f"WOTS+ tree exhausted (leaf {leaf} >= "
                        f"{kp.num_leaves}).  Rotate the key before signing."
                    ),
                }
            try:
                kp.advance_to_leaf(leaf + 1)
                # Persist the advance so a crash-reboot skips the reserved
                # leaf even if the caller never submits the tx.  Burning a
                # leaf without a corresponding sign is cheap; reusing one
                # is catastrophic.
                if kp.leaf_index_path is not None:
                    kp.persist_leaf_index(kp.leaf_index_path)
            except Exception as e:
                return {"ok": False, "error": sanitize_error(str(e))}

        return {
            "ok": True,
            "result": {
                "leaf_index": leaf,
                "reserved": True,
            },
        }

    def _rpc_submit_transfer(self, params: dict, client_ip: str = "") -> dict:
        """Accept a signed transfer transaction from a client.

        Routes through `submit_transaction_to_mempool` (which dispatches
        on `tx.__class__`) so transfers get the SAME censorship-evidence
        defenses as messages: opt-in SubmissionReceipt on admission, and
        the validator-bound proof of admission the user can later file
        as a CensorshipEvidenceTx if the transfer is silently dropped.

        Pre-fix this path inlined its own validate+add and never
        consulted `self.receipt_issuer` — a coerced validator who admits
        the transfer then drops it left ZERO on-chain evidence, despite
        CLAUDE.md anchoring transfer as a "first-class, fully supported
        tx type" held to "mainstream-asset quality bars."  Post-fix the
        user holds a signed receipt the moment admission completes.

        `client_ip` threads the per-IP receipt-budget gate (audit
        2026-04-27) so an attacker can't drain the receipt subtree by
        spamming `request_receipt: True` transfers from one IP — same
        defense as `_rpc_submit_transaction`.
        """
        try:
            from messagechain.network.submission_server import (
                submit_transaction_to_mempool,
            )
            tx = TransferTransaction.deserialize(params["transaction"])
            # Pending nonce scans all pools (message + transfer + stake +
            # unstake + governance + react) so sequential tx of any type
            # work.  Threaded into the central helper via the
            # pending_nonce kwarg.
            pending_nonce = self._get_pending_nonce_all_pools(tx.entity_id)
            issuer = self._resolve_rpc_receipt_issuer(params, client_ip)
            result = submit_transaction_to_mempool(
                tx, self.blockchain, self.mempool,
                receipt_issuer=issuer,
                pending_nonce=pending_nonce,
            )
            if not result.ok:
                return {"ok": False, "error": result.error}

            tx_hash_hex = tx.tx_hash.hex()
            self._track_seen_tx(tx_hash_hex)
            self._schedule_coro_threadsafe(
                self._relay_tx_inv([tx_hash_hex]), "relay_tx_inv",
            )

            payload = {
                "tx_hash": tx.tx_hash.hex(),
                "amount": tx.amount,
                "fee": tx.fee,
                "message": (
                    "Transfer accepted into mempool (duplicate)"
                    if result.duplicate
                    else "Transfer accepted into mempool"
                ),
            }
            # Surface the signed receipt in the response when the
            # validator issued one — the user holds this as their
            # CensorshipEvidenceTx weapon if the transfer is later
            # dropped.
            if result.receipt_hex:
                payload["receipt"] = result.receipt_hex
            return {"ok": True, "result": payload}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_submit_react(self, params: dict, client_ip: str = "") -> dict:
        """Accept a signed ReactTransaction (Tier 17) into the mempool.

        Routes through `submit_transaction_to_mempool` (which dispatches
        on `tx.__class__`) so React votes get the SAME censorship-
        evidence defenses as messages and transfers: opt-in
        SubmissionReceipt on admission.  Pre-fix this path inlined its
        own validate+add and never consulted `self.receipt_issuer` —
        a coerced validator dropping DOWN votes on a target it favors
        left zero on-chain accountability.

        Cross-pool WOTS+ leaf dedupe stays in the RPC handler (it's
        a Server-instance check that scans pending stake/unstake/
        authority/governance pools the helper has no access to);
        every other gate is delegated to the helper so the audit
        surface stays consolidated.

        `client_ip` threads the per-IP receipt-budget gate (audit
        2026-04-27) so an attacker can't drain the receipt subtree by
        spamming `request_receipt: True` react votes from one IP.
        """
        try:
            from messagechain.core.reaction import ReactTransaction
            from messagechain.network.submission_server import (
                submit_transaction_to_mempool,
            )
            tx = ReactTransaction.deserialize(params["transaction"])

            # Voter existence is pre-checked here so an unknown signer
            # gets a clean "voter is not a registered entity" error
            # instead of the cross-pool leaf-check firing first (it
            # fails closed when it can't resolve a signer pubkey, which
            # would surface as a confusing leaf-reuse error to a wallet
            # that simply hasn't registered yet).  The helper repeats
            # this check for the gossip / non-RPC ingress paths.
            if tx.voter_id not in self.blockchain.public_keys:
                return {
                    "ok": False,
                    "error": "voter is not a registered entity",
                }

            # Round-12: cross-pool WOTS+ leaf dedupe stays at the RPC
            # boundary because it scans Server-instance-local pending
            # pools (stake, unstake, authority, governance) the helper
            # has no handle on.  Without this an attacker (or buggy
            # wallet) could submit a Transfer at leaf N then a React
            # at leaf N -- both pass, both apply in the same block, the
            # WOTS+ leaf secret leaks from the two signatures, and any
            # observer can forge a third tx under that leaf.
            if not self._check_leaf_across_all_pools(tx):
                return {
                    "ok": False,
                    "error": (
                        "WOTS+ leaf already used by another pending tx "
                        "-- leaf reuse rejected"
                    ),
                }

            # Pending nonce scans all pools so a voter's interleaved
            # transfer / message / react submissions all see sequential
            # nonces.  Threaded into the central helper.
            pending_nonce = self._get_pending_nonce_all_pools(tx.voter_id)
            issuer = self._resolve_rpc_receipt_issuer(params, client_ip)
            result = submit_transaction_to_mempool(
                tx, self.blockchain, self.mempool,
                receipt_issuer=issuer,
                pending_nonce=pending_nonce,
            )
            if not result.ok:
                return {"ok": False, "error": result.error}

            payload = {
                "tx_hash": tx.tx_hash.hex(),
                "voter_id": tx.voter_id.hex(),
                "target": tx.target.hex(),
                "target_is_user": tx.target_is_user,
                "choice": tx.choice,
                "fee": tx.fee,
                "message": (
                    "ReactTransaction accepted into mempool (duplicate)"
                    if result.duplicate
                    else "ReactTransaction accepted into mempool"
                ),
            }
            if result.receipt_hex:
                payload["receipt"] = result.receipt_hex
            return {"ok": True, "result": payload}
        except Exception as e:
            return {"ok": False, "error": sanitize_error(str(e))}

    def _rpc_get_user_trust(self, params: dict) -> dict:
        """Return the on-chain user-trust score for a target entity.

        Score is the sum of UP (+1) and DOWN (-1) votes from every
        voter at the current chain tip.  Cheap read against
        `Blockchain.reaction_state` — no signature work, no replay.
        Light clients can verify the answer against the chain state
        root post-Tier-17 (the score is committed via
        `_mix_state_roots`).
        """
        entity_id = parse_hex(params.get("entity_id", ""), expected_len=32)
        if entity_id is None:
            return {
                "ok": False,
                "error": "Invalid entity_id (must be 32 bytes hex)",
            }
        score = self.blockchain.reaction_state.user_trust_score(entity_id)
        return {
            "ok": True,
            "result": {
                "entity_id": entity_id.hex(),
                "trust_score": score,
            },
        }

    def _rpc_get_message_score(self, params: dict) -> dict:
        """Return the on-chain net reaction score for a message tx_hash."""
        tx_hash = parse_hex(params.get("tx_hash", ""), expected_len=32)
        if tx_hash is None:
            return {
                "ok": False,
                "error": "Invalid tx_hash (must be 32 bytes hex)",
            }
        score = self.blockchain.reaction_state.message_score(tx_hash)
        return {
            "ok": True,
            "result": {
                "tx_hash": tx_hash.hex(),
                "score": score,
            },
        }

    def _rpc_get_entity(self, params: dict) -> dict:
        entity_id = parse_hex(params.get("entity_id", ""), expected_len=32)
        if entity_id is None:
            return {"ok": False, "error": "Invalid entity_id (must be 32 bytes hex)"}
        pubkey_registered = entity_id in self.blockchain.public_keys
        balance = self.blockchain.supply.get_balance(entity_id)
        # Receive-to-exist: an entity can hold a balance before its
        # pubkey is installed (the pubkey is revealed by the first
        # outgoing transfer).  Previously get_entity returned "Entity
        # not found" for these, wrongly suggesting the balance was
        # lost (observed 2026-04-24 mainnet smoke test).  Now return
        # the partial info with pubkey_registered=False so operators
        # and integrators can distinguish "has balance but key not
        # yet revealed" from "truly unknown entity".  The ok=False
        # path is preserved for the truly-unknown case, so existing
        # not-found checks keep working.
        if not pubkey_registered and balance == 0:
            return {"ok": False, "error": "Entity not found"}
        result = self.blockchain.get_entity_stats(entity_id)
        result["pubkey_registered"] = pubkey_registered
        return {"ok": True, "result": result}

    def _rpc_get_latest_release(self, params: dict) -> dict:
        """Return the current on-chain release manifest, if any.

        Cheap read: a dict build over a handful of already-deserialized
        fields.  No signature verify — the manifest was verified when
        the block containing it was applied.  Classified as
        RPC_COST_CHEAP at the _RPC_METHOD_COST layer (absent => cheap
        default), same as `get_chain_info`.

        Shape:
            {
              "current_node_version": "<__version__>",
              "latest_manifest": null | { ... },
              "update_available": bool,   # True iff the chain has a
                                          # manifest AND its version
                                          # string differs from ours.
            }
        """
        from messagechain import __version__ as current_version
        from messagechain import config as _cfg

        manifest = getattr(self.blockchain, "latest_release_manifest", None)
        if manifest is None:
            return {
                "ok": True,
                "result": {
                    "current_node_version": current_version,
                    "latest_manifest": None,
                    "update_available": False,
                },
            }

        severity_label = _RELEASE_SEVERITY_LABELS.get(
            int(manifest.severity),
            f"severity-{int(manifest.severity)}",
        )
        latest = {
            "version": manifest.version,
            "severity": int(manifest.severity),
            "severity_label": severity_label,
            # Lowercase hex — .hex() already returns lowercase, but be
            # explicit for the contract.
            "binary_hashes": {
                k: v.hex().lower() for k, v in manifest.binary_hashes.items()
            },
            "min_activation_height": manifest.min_activation_height,
            "release_notes_uri": manifest.release_notes_uri,
            "signer_indices": list(manifest.signer_indices),
            "num_signers": len(manifest.signer_indices),
            "threshold": int(_cfg.RELEASE_THRESHOLD),
            "nonce_hex": manifest.nonce.hex().lower(),
        }
        # Semver-aware update_available — consistent with
        # log_release_status().  If either side fails to parse, fall
        # back to strict string inequality so a parser edge case
        # never silences a real update signal.
        from messagechain.core.release_version import (
            parse_release_version,
            release_version_is_strictly_newer,
        )
        try:
            parse_release_version(manifest.version)
            parse_release_version(current_version)
            update_available = release_version_is_strictly_newer(
                manifest.version, current_version,
            )
        except (ValueError, TypeError):
            update_available = manifest.version != current_version
        return {
            "ok": True,
            "result": {
                "current_node_version": current_version,
                "latest_manifest": latest,
                "update_available": update_available,
            },
        }

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

    def _rpc_get_peers(self) -> dict:
        """List every Peer object currently tracked by this node.

        Observability-only.  Returns per-peer: address, direction,
        connection type, height last reported in handshake, seconds
        connected, entity_id (if the handshake completed), and a
        boolean `connected` flag (a peer object can linger after its
        socket dies — surfacing that lets an operator see churn).
        Sorted by address for stable CLI output.

        Design note: entity_id lives in peer memory only if the peer
        sent it in their handshake.  Empty string is rendered as-is
        so clients can distinguish "no id" from "id = all zeroes".
        """
        import time as _time_rpc
        now = _time_rpc.time()
        rows: list[dict] = []
        for _addr, peer in sorted(self.peers.items()):
            connected_at = getattr(peer, "connected_at", 0.0) or 0.0
            seconds_connected = (
                int(now - connected_at) if connected_at > 0 else 0
            )
            try:
                conn_type = peer.connection_type.value
            except AttributeError:
                conn_type = str(peer.connection_type)
            rows.append({
                "address": peer.address,
                "direction": getattr(peer, "direction", "inbound"),
                "connection_type": conn_type,
                "connected": bool(peer.is_connected),
                "connected_at": int(connected_at),
                "seconds_connected": seconds_connected,
                "height": int(getattr(peer, "peer_height", 0) or 0),
                "version": str(getattr(peer, "peer_version", "") or ""),
                "entity_id": getattr(peer, "entity_id", "") or "",
                # "plain" | "tls".  getattr fallback guards against a
                # Peer instance that predates the field (unit-test
                # monkeypatches, forwards-compat).
                "transport": getattr(peer, "transport", "plain") or "plain",
            })
        return {"ok": True, "result": {"peers": rows, "count": len(rows)}}

    def _rpc_get_checkpoint_at_height(self, params: dict) -> dict:
        """Return (block_number, block_hash, state_root) for an in-chain
        height.  Exactly the fields a WeakSubjectivityCheckpoint needs —
        no more, no less.  Read-only; leaks nothing not already derivable
        from the chain.  Backs `messagechain cut-checkpoint --height N`.
        """
        height = params.get("height")
        if height is None:
            return {"ok": False, "error": "missing required param: height"}
        if not isinstance(height, int) or isinstance(height, bool):
            return {"ok": False, "error": "height must be an integer"}
        if height < 0:
            return {"ok": False, "error": f"height must be >= 0 (got {height})"}
        block = self.blockchain.get_block(height)
        if block is None:
            return {
                "ok": False,
                "error": f"no block at height {height} (chain tip is {self.blockchain.height - 1})",
            }
        return {"ok": True, "result": {
            "block_number": height,
            "block_hash": block.block_hash.hex(),
            "state_root": block.header.state_root.hex(),
        }}

    def _rpc_get_tx_status(self, params: dict) -> dict:
        """Inclusion status for a tx_hash — backs `messagechain receipt`.

        The receipt CLI is the user-visible surface that names the
        slashing-backed permanence guarantee.  After `messagechain send`
        a user gets a tx hash and ten minutes of nothing; this RPC is
        what lets the CLI distinguish:

          * INCLUDED  — tx is in a block.  Returns block_height,
                        block_hash, tx_index, attester count, attesting
                        stake / total stake, the 2/3 threshold flag,
                        and a Merkle inclusion proof against the block
                        header's merkle_root.
          * PENDING   — tx is in mempool but not yet in a block.
                        Returns in_mempool=True so the CLI can prompt
                        for the submit-evidence escalation if waited
                        long enough.
          * NOT_FOUND — tx is in neither.  CLI prints the three-cause
                        diagnostic ('never submitted' / 'collusion' /
                        'malformed').

        Read-only, content-neutral.  Leaks nothing not already
        derivable from chain state — every inclusion is public anyway.
        """
        tx_hash_hex = params.get("tx_hash")
        if not tx_hash_hex:
            return {"ok": False, "error": "missing required param: tx_hash"}
        tx_hash = parse_hex(tx_hash_hex, expected_len=32)
        if tx_hash is None:
            return {"ok": False, "error": "Invalid tx_hash (must be 32 bytes hex)"}

        # 1. Has the tx landed on-chain?  Use the persistent index built
        #    by chaindb.index_tx_locations — O(1) lookup.  If the chaindb
        #    isn't wired up (test fixture / pre-index migration), fall
        #    back to a scan.
        location = None
        if getattr(self.blockchain, "db", None) is not None:
            try:
                location = self.blockchain.db.get_tx_location(tx_hash)
            except Exception:
                location = None

        if location is None:
            # Fallback: linear scan.  Bounded by chain length; only
            # taken on test fixtures with no DB or as a safety net.
            for height_idx, blk in enumerate(getattr(self.blockchain, "chain", [])):
                for tx in getattr(blk, "transactions", []) or []:
                    if getattr(tx, "tx_hash", None) == tx_hash:
                        location = (height_idx, 0)
                        break
                if location is not None:
                    break

        if location is not None:
            return self._build_included_status(tx_hash, location)

        # 2. Pending in mempool?
        mempool = self.mempool
        in_mempool = False
        if mempool is not None:
            if tx_hash in getattr(mempool, "pending", {}):
                in_mempool = True
            elif tx_hash in (getattr(mempool, "react_pool", {}) or {}):
                in_mempool = True
            elif tx_hash in (getattr(mempool, "slash_pool", {}) or {}):
                in_mempool = True
            elif tx_hash in (getattr(mempool, "censorship_evidence_pool", {}) or {}):
                in_mempool = True
            elif tx_hash in (getattr(mempool, "orphan_pool", {}) or {}):
                in_mempool = True

        if in_mempool:
            return {"ok": True, "result": {
                "status": "pending",
                "in_mempool": True,
                "current_height": int(self.blockchain.height),
            }}

        # 3. Not found anywhere we can see.
        return {"ok": True, "result": {"status": "not_found"}}

    def _build_included_status(self, tx_hash: bytes, location: tuple) -> dict:
        """Helper: assemble the full INCLUDED-status response.

        Split out so the dispatch path stays readable; also lets the
        included path stay testable in isolation.
        """
        from messagechain.config import (
            FINALITY_THRESHOLD_NUMERATOR, FINALITY_THRESHOLD_DENOMINATOR,
        )
        block_height, _legacy_index = location
        block = self.blockchain.get_block(block_height)
        if block is None:
            # Index claims a block but we can't load it — treat as
            # not_found rather than crashing.  This shouldn't happen on
            # a healthy chain but is defensible against migration races.
            return {"ok": True, "result": {"status": "not_found"}}

        # Compute the canonical tx_index in the merkle ordering — this
        # is the index the inclusion proof must use, NOT the on-disk
        # tx_locations.tx_index (which records the per-variant order).
        from messagechain.core.block import canonical_block_tx_hashes
        canonical_hashes = canonical_block_tx_hashes(block)
        try:
            canonical_index = canonical_hashes.index(tx_hash)
        except ValueError:
            # The tx is recorded as in this block but isn't in the
            # merkle inputs — schema drift or a non-MessageTransaction
            # tx.  Surface what we can without a proof.
            canonical_index = None

        # Build the inclusion proof against the block header's
        # merkle_root.  Skipped for txs we couldn't locate in the
        # canonical ordering above.
        proof_dict = None
        if canonical_index is not None:
            try:
                from messagechain.core.spv import generate_merkle_proof
                proof = generate_merkle_proof(block, canonical_index)
                proof_dict = proof.serialize()
            except Exception:
                proof_dict = None

        # Attester count + attesting stake.  Pull from the chain's
        # FinalityTracker — the same source the consensus layer uses
        # to decide finality.  This means a "permanent" verdict in the
        # CLI exactly tracks consensus-layer finality, not some
        # secondary heuristic.
        block_hash = block.block_hash
        finality = getattr(self.blockchain, "finality", None)
        attester_set = set()
        attesting_stake = 0
        if finality is not None:
            attester_set = set(getattr(finality, "attestations", {}).get(block_hash, set()))
            attesting_stake = int(
                getattr(finality, "attested_stake", {}).get(block_hash, 0)
            )

        staked = dict(getattr(self.blockchain.supply, "staked", {}) or {})
        total_stake = sum(int(v) for v in staked.values())
        # Total validator count = staked validators with non-zero
        # stake (the committee a 2/3 threshold is measured against).
        total_validators = sum(1 for v in staked.values() if int(v) > 0)
        threshold_met = (
            total_stake > 0
            and attesting_stake * FINALITY_THRESHOLD_DENOMINATOR
            >= total_stake * FINALITY_THRESHOLD_NUMERATOR
        )

        result = {
            "status": "included",
            "block_height": int(block_height),
            "block_hash": block_hash.hex(),
            "tx_index": int(canonical_index) if canonical_index is not None else -1,
            "merkle_root": block.header.merkle_root.hex(),
            "block_timestamp": int(block.header.timestamp),
            "current_height": int(self.blockchain.height),
            "attesters": len(attester_set),
            "total_validators": int(total_validators),
            "attesting_stake": int(attesting_stake),
            "total_stake": int(total_stake),
            "finality_threshold_met": bool(threshold_met),
            "finality_numerator": int(FINALITY_THRESHOLD_NUMERATOR),
            "finality_denominator": int(FINALITY_THRESHOLD_DENOMINATOR),
        }
        if proof_dict is not None:
            result["merkle_proof"] = proof_dict
        return {"ok": True, "result": result}

    # ── Block Production ────────────────────────────────────────────
    # _block_production_loop now lives on SharedRuntimeMixin.

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

        # Leaf-reuse defence after snapshot restore.
        # If any known peer has a higher chain height than us, our local
        # view is stale.  Producing a block with leaf N could collide with
        # a signature we produced on the version of the chain we rolled
        # back — catastrophic for a WOTS+ one-time key.  Refuse to
        # produce until IBD catches us up.  At N=0 peers (bootstrap-phase
        # single-validator mainnet), this guard is a no-op — we
        # produce normally.  As soon as peers exist, we respect their
        # view before signing.
        if self.syncer.needs_sync():
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
        # Tier 17: drain react pool only at/after activation height.
        # Pre-activation a populated react slot would be rejected by
        # validate_block, so don't even ask the mempool for entries.
        from messagechain.config import (
            REACT_TX_HEIGHT as _REACT_H,
            REACT_NO_SELF_MESSAGE_HEIGHT as _REACT_NO_SELF_H,
        )
        next_height = self.blockchain.height + 1
        if next_height >= _REACT_H:
            react_txs = self.mempool.get_react_transactions(
                max_count=MAX_TXS_PER_BLOCK,
            )
            # Tier 27: drop self-reacts on own messages before block
            # assembly so a stale mempool entry from before activation
            # does not poison an otherwise-valid block.  validate_block
            # enforces the same rule — this is proposer-side hygiene
            # so we never produce a block we'd reject.
            if (
                next_height >= _REACT_NO_SELF_H
                and self.blockchain.db is not None
                and react_txs
            ):
                _filtered = []
                for _rtx in react_txs:
                    if not _rtx.target_is_user:
                        _author = self.blockchain.db.get_message_author(
                            _rtx.target, state=self.blockchain,
                        )
                        if _author is not None and _author == _rtx.voter_id:
                            continue
                    _filtered.append(_rtx)
                react_txs = _filtered
        else:
            react_txs = []
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

        # Serialize block sign with reserve_leaf RPC via the same lock
        # — see _rpc_reserve_leaf / self._wallet_leaf_lock for the full
        # rationale.  Without this, an operator CLI running on the same
        # host can race the block producer for the same _next_leaf.
        with self._wallet_leaf_lock:
            block = self.blockchain.propose_block(
                self.consensus, self.wallet_entity, txs,
                transfer_transactions=transfer_txs,
                slash_transactions=slash_txs,
                authority_txs=authority_txs,
                stake_transactions=stake_txs,
                unstake_transactions=unstake_txs,
                governance_txs=governance_txs,
                react_transactions=react_txs,
            )

        success, reason = self.blockchain.add_block(block)
        if success:
            if all_pending:
                self.mempool.remove_transactions([tx.tx_hash for tx in all_pending])
            if slash_txs:
                self.mempool.remove_slash_transactions(
                    [s.tx_hash for s in slash_txs]
                )
            if react_txs:
                self.mempool.remove_react_transactions(
                    [r.tx_hash for r in react_txs]
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
            # Opt-in governance-proposal email notify (operator-runtime
            # only; never affects consensus).  Reads onboard.toml each
            # call so flags can be flipped without restart.
            self._maybe_notify_governance_proposals()
        else:
            # add_block rejected our own candidate.  Roll back the
            # height-guard floor reservation so a future legitimate
            # proposal at this height isn't blocked.  Without rollback
            # the floor stays at ``block.header.block_number`` and
            # every subsequent attempt at the same height fails with
            # HeightAlreadySignedError — the chain-stall shape the
            # 2026-04-27 incident exposed at heights 671/672.
            #
            # Rollback runs inside the same wallet-leaf lock as the
            # propose+sign that placed the reservation, so a
            # concurrent operator CLI signing on this wallet cannot
            # race the rollback to a stale view of the floor.
            wallet_guard = getattr(self.wallet_entity, "height_sign_guard", None)
            if wallet_guard is not None:
                with self._wallet_leaf_lock:
                    try:
                        wallet_guard.rollback_block_sign(
                            block.header.block_number,
                        )
                    except Exception:
                        # Rollback durability failure — log loudly,
                        # let the existing rejection-warning surface
                        # below.  An operator who sees both will know
                        # the floor may be poisoned and can investigate.
                        logger.exception(
                            "rollback_block_sign(%d) failed after "
                            "add_block rejection — floor may remain "
                            "poisoned",
                            block.header.block_number,
                        )
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
                        except Exception as e:
                            # Write failures usually mean the peer went
                            # away.  Mark disconnected so the next
                            # maintenance sweep prunes them; logged at
                            # debug for operator diagnosability without
                            # spamming on routine peer churn.
                            logger.debug(
                                f"height-request write to {addr} "
                                f"failed: {e}"
                            )
                            peer.is_connected = False

                if self.syncer.needs_sync():
                    await self.syncer.start_sync()

    # ── P2P Network ─────────────────────────────────────────────────
    # _msg_category now lives on SharedRuntimeMixin.

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

        # Symmetric with outbound: enable SO_KEEPALIVE on the accepted
        # socket so the server notices silent idle drops (GCP VPC
        # cross-zone NAT) without waiting for PEER_READ_TIMEOUT.
        enable_tcp_keepalive(writer)

        # "tls" iff asyncio.start_server was bound with an SSLContext —
        # writer's extra_info carries the negotiated session.  Honest
        # observability; matches the pattern in network/node.py.
        transport = "tls" if writer.get_extra_info("ssl_object") else "plain"
        import time as _time_peer
        peer = Peer(
            host=addr[0], port=addr[1], reader=reader, writer=writer,
            is_connected=True,
            direction="inbound",
            connected_at=_time_peer.time(),
            transport=transport,
        )
        # C10: timeout on reads to prevent slow-loris DoS
        first_message = True
        try:
            while self._running:
                timeout = HANDSHAKE_TIMEOUT if first_message else PEER_READ_TIMEOUT
                try:
                    msg = await asyncio.wait_for(read_message(reader), timeout=timeout)
                except asyncio.TimeoutError:
                    logger.debug(f"Peer {address} timed out after {timeout}s")
                    break
                if msg is None:
                    break
                first_message = False
                await self._handle_p2p_message(msg, peer)
        except Exception as e:
            # Any exception in the P2P handler loop is either a protocol
            # violation by the peer or an internal bug.  Log at debug so
            # operators debugging flaky peers can trace it; the finally
            # block below handles the connection cleanup.
            logger.debug(
                f"P2P handler loop for {address} exited with exception: {e}"
            )
        finally:
            peer.is_connected = False
            # Evict the Peer entry so reconnects from the same remote
            # on a fresh ephemeral port don't accumulate as zombies.
            # The HANDSHAKE handler keyed this peer by peer.address; if
            # the handshake never completed, there's nothing to remove.
            self.peers.pop(peer.address, None)
            self.rate_limiter.remove_peer(address)
            writer.close()

    async def _connect_to_peer(self, host: str, port: int):
        addr = f"{host}:{port}"
        if addr in self.peers and self.peers[addr].is_connected:
            return
        # Dedup concurrent dials: a second call while the first is
        # still inside asyncio.open_connection must no-op, or the
        # seed loop and the maintenance tick produce duplicate sockets.
        if addr in self._connecting:
            return
        if self.ban_manager.is_banned(addr):
            logger.debug(f"Skipping banned peer {addr}")
            return
        self._connecting.add(addr)
        # Match the listener's TLS setting on the outbound side.  Both
        # peers of a TLS-enabled connection must negotiate TLS or the
        # handshake fails — this is the outbound half of the fix at
        # start() above.
        from messagechain import config as _cfg
        from messagechain.network.tls import create_client_ssl_context
        client_ssl = (
            create_client_ssl_context()
            if getattr(_cfg, "P2P_TLS_ENABLED", True)
            else None
        )
        peer = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=client_ssl),
                timeout=HANDSHAKE_TIMEOUT,
            )
            # SO_KEEPALIVE keeps cross-zone GCP VPC NAT mappings alive
            # and surfaces dead sockets in ~2 min instead of hanging on
            # readexactly until PEER_READ_TIMEOUT (5 min).  Paired with
            # the maintenance loop, dropped seed links self-heal.
            enable_tcp_keepalive(writer)
            conn_type = self._next_connection_type()
            transport = "tls" if client_ssl is not None else "plain"
            import time as _time_peer
            peer = Peer(
                host=host, port=port, reader=reader, writer=writer,
                is_connected=True, connection_type=conn_type,
                direction="outbound",
                connected_at=_time_peer.time(),
                transport=transport,
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
                    "version": __version__,
                },
                sender_id=self.wallet_id.hex() if self.wallet_id else "",
            )
            await write_message(writer, handshake)
            peer.handshake_sent = True
            while self._running and peer.is_connected:
                try:
                    msg = await asyncio.wait_for(read_message(reader), timeout=PEER_READ_TIMEOUT)
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
        finally:
            # Mirror the inbound handler's cleanup: flip is_connected so
            # the maintenance loop (and get_peers observability) see an
            # honest state, drop the rate-limit bucket, and close the
            # socket.  Without this, a dead outbound lingers with
            # is_connected=True forever and blocks reconnect.
            self._connecting.discard(addr)
            if peer is not None:
                peer.is_connected = False
            # Symmetric with the inbound handler: drop the entry so
            # the maintenance tick sees a clean slate on re-dial
            # instead of hitting the "already in self.peers" guard
            # against a long-dead Peer object.
            self.peers.pop(addr, None)
            self.rate_limiter.remove_peer(addr)
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    async def _peer_maintenance_tick(self):
        """Single pass of the seed-reconnect scan.  Broken out from the
        loop so tests can exercise the logic deterministically without
        juggling asyncio.sleep."""
        for host, port in list(self.seed_nodes):
            addr = f"{host}:{port}"
            existing = self.peers.get(addr)
            if existing is not None and existing.is_connected:
                continue
            # If an inbound peer is already handshook and advertises
            # this exact (host, listen_port), the seed is already
            # reachable via that session. Re-dialing just burns a
            # TLS handshake and gets closed by entity-level dedup
            # 30 seconds later — avoid the churn.
            if any(
                p.is_connected
                and p.entity_id
                and p.host == host
                and p.advertised_port == port
                for p in self.peers.values()
            ):
                continue
            if self.ban_manager.is_banned(addr):
                continue
            t = asyncio.create_task(self._connect_to_peer(host, port))
            t.add_done_callback(
                lambda x: self._handle_task_exception(
                    "connect_to_peer(maintenance)", x
                )
            )

    async def _peer_maintenance_loop(self):
        """Reconnect dropped seed peers every PEER_MAINTENANCE_INTERVAL.

        Seeds are connected once at startup; without this loop, a single
        dropped connection (silent NAT timeout, peer restart, transient
        blip) leaves the node permanently unpeered.  Combined with the
        finally-block cleanup in _connect_to_peer, a dead outbound now
        flips is_connected=False and this loop re-dials on the next tick.
        """
        while self._running:
            try:
                await self._peer_maintenance_tick()
            except Exception as e:
                logger.debug(f"Peer maintenance tick failed: {e}")
            await asyncio.sleep(PEER_MAINTENANCE_INTERVAL)

    def _dedup_entity_sessions(self, peer: Peer) -> Peer | None:
        """If another live session exists with the same remote entity,
        pick one to close via a symmetric tiebreaker. Returns the Peer
        that was closed (may be `peer` itself or the duplicate), or
        None if no duplicate was found.

        Tiebreaker: keep the session where the LOWER entity_id is the
        outbound dialer. Both ends apply the same rule against the
        same pair of ids, so both ends drop the same TCP connection
        and the network converges to one session per peer.
        """
        if not peer.entity_id or not self.wallet_id:
            return None
        my_id_hex = self.wallet_id.hex()
        for other in list(self.peers.values()):
            if other is peer:
                continue
            if other.entity_id != peer.entity_id:
                continue
            if not other.is_connected:
                continue
            i_am_lower = my_id_hex < peer.entity_id
            # Surviving session: direction matches "who is the lower-id
            # side" — if I'm lower, my outbound survives; if I'm higher,
            # my inbound survives.
            new_survives = (peer.direction == "outbound") == i_am_lower
            drop = peer if not new_survives else other
            logger.info(
                "p2p dedup: closing duplicate %s session to entity %s",
                drop.direction, peer.entity_id[:16],
            )
            drop.is_connected = False
            self.peers.pop(drop.address, None)
            try:
                drop.writer.close()
            except Exception:
                pass
            return drop
        return None

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
            # Mirror the handshake-reported height onto the peer object
            # so the get_peers RPC can surface it.  The ChainSyncer
            # tracks peer heights for sync decisions via a separate
            # path; this field is observability-only.
            peer.peer_height = peer_height
            peer.peer_version = str(msg.payload.get("version", "") or "unknown")
            # Remember the remote's advertised listen port so the
            # maintenance loop can match this session against a seed
            # entry at (peer.host, advertised_port). Without this,
            # an inbound peer looks like "something at an ephemeral
            # source port" to the seed-dial scan and the maintenance
            # tick re-dials the listen port every interval — each
            # redial completing handshake just to get closed by the
            # entity-level dedup. Validate before storing so a
            # misbehaving peer can't poison the maintenance scan.
            advertised = msg.payload.get("port")
            if isinstance(advertised, int) and 0 < advertised < 65536:
                peer.advertised_port = advertised
            self.peers[peer.address] = peer
            # Entity-level dedup: when two validators dial each other
            # simultaneously, each ends up with both an inbound and an
            # outbound session to the same remote entity. Apply a
            # symmetric tiebreaker so both ends close the same TCP
            # connection and converge to one session per pair.
            if self._dedup_entity_sessions(peer) is peer:
                # We decided to drop THIS session — stop processing the
                # rest of the HANDSHAKE (no sync kick, no echo) and let
                # the finally block close the socket.
                peer.is_connected = False
                return
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

            # Echo our HANDSHAKE back to an inbound peer so its Peer
            # record can populate entity/height/version. The sync path
            # only needs the one-way HANDSHAKE (update_peer_height above),
            # but without the echo the CLI on the dialer side shows
            # Entity=(none) / Height=0 / Version=unknown forever.
            # handshake_sent guards against re-echo on reconnect.
            if (
                getattr(peer, "direction", "inbound") == "inbound"
                and not getattr(peer, "handshake_sent", False)
            ):
                latest_local = self.blockchain.get_latest_block()
                reply = NetworkMessage(
                    msg_type=MessageType.HANDSHAKE,
                    payload={
                        "port": self.p2p_port,
                        "chain_height": self.blockchain.height,
                        "best_block_hash": (
                            latest_local.block_hash.hex() if latest_local else ""
                        ),
                        "cumulative_weight": self._current_cumulative_weight(),
                        "version": __version__,
                    },
                    sender_id=self.wallet_id.hex() if self.wallet_id else "",
                )
                try:
                    await write_message(peer.writer, reply)
                    try:
                        peer.handshake_sent = True
                    except AttributeError:
                        pass
                except Exception as e:
                    logger.debug(
                        f"Failed to echo handshake to {peer.address}: {e}"
                    )

        elif msg.msg_type == MessageType.INV:
            await self._handle_inv(msg.payload, peer)

        elif msg.msg_type == MessageType.GETDATA:
            await self._handle_getdata(msg.payload, peer)

        elif msg.msg_type == MessageType.ANNOUNCE_TX:
            # ANNOUNCE_TX carries either a MessageTransaction payload or
            # a TransferTransaction payload — both land in the shared
            # mempool and both are legitimate gossip targets.  Pre-fix,
            # this handler only deserialized MessageTransaction, so a
            # transfer announced by an off-host submitter (CLI on a peer
            # node) failed to parse, got scored as invalid_tx_data, and
            # never reached the block producer's mempool.  Dispatch on
            # the `type` discriminator that TransferTransaction.serialize
            # writes into the dict.
            payload = msg.payload
            tx_type = payload.get("type") if isinstance(payload, dict) else None
            is_transfer = tx_type == "transfer"
            try:
                if is_transfer:
                    tx = TransferTransaction.deserialize(payload)
                else:
                    tx = MessageTransaction.deserialize(payload)
            except Exception:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_tx_data"
                )
                return
            tx_hash_hex = tx.tx_hash.hex()
            if tx_hash_hex in self._seen_txs:
                return
            pending_nonce = self._get_pending_nonce_all_pools(tx.entity_id)
            # Route validation through the type-specific validator —
            # validate_transaction only understands MessageTransaction
            # and will reject transfers for structural reasons that
            # would look like malice (missing fields, etc.).
            if is_transfer:
                valid, reason = self.blockchain.validate_transfer_transaction(
                    tx, expected_nonce=pending_nonce,
                )
            else:
                valid, reason = self.blockchain.validate_transaction(
                    tx, expected_nonce=pending_nonce,
                )
            if valid:
                self._track_seen_tx(tx_hash_hex)
                # Record arrival height - see _rpc_submit_transaction for rationale.
                self.mempool.add_transaction(
                    tx, arrival_block_height=self.blockchain.height,
                )
                await self._relay_tx_inv([tx_hash_hex], exclude=address)
            else:
                # Differentiate "peer is lying / malicious" from "peer's
                # mempool drifted during normal partition recovery".  A
                # stale-but-structurally-valid tx (nonce below pending,
                # leaf below watermark) deserves OFFENSE_MINOR at most;
                # instant-banning on those causes honest peers to ban
                # each other during normal catch-up.  Only cryptographic
                # or structural fail is a true "invalid tx".
                if _is_stale_tx_reason(reason):
                    self.ban_manager.record_offense(
                        address, OFFENSE_MINOR, f"stale_tx:{reason}",
                    )
                else:
                    self.ban_manager.record_offense(
                        address, OFFENSE_INVALID_TX, f"invalid_tx:{reason}",
                    )

        elif msg.msg_type == MessageType.ANNOUNCE_BLOCK:
            try:
                block = Block.deserialize(msg.payload)
            except Exception:
                self.ban_manager.record_offense(
                    address, OFFENSE_PROTOCOL_VIOLATION, "invalid_block_data"
                )
                return
            success, reason = self.blockchain.add_block(block, source_peer=address)
            self._drain_orphan_flood_offenses()
            if success:
                self.mempool.remove_transactions([tx.tx_hash for tx in block.transactions])
                # Attester duty: vote on the accepted block, but only if
                # it honors our forced-inclusion list (censorship
                # resistance).  Silent omission of a top-N long-waited
                # tx means we skip the broadcast — block fails 2/3
                # finality if enough honest attesters concur.
                await self._maybe_attest_accepted_block(block)
                # Operator-runtime email notification path (opt-in;
                # never affects consensus).  See cmd-doc on
                # _maybe_notify_governance_proposals for guarantees.
                self._maybe_notify_governance_proposals()
            else:
                # Orderly-flow rejections (orphan / already-known) are
                # not peer misbehaviour — they mean we're behind or
                # caught up.  Only ban for genuinely invalid blocks.
                # Twin of the same fix in messagechain/network/node.py.
                reason_lower = reason.lower()
                benign_prefixes = ("orphan", "block already known")
                if not any(reason_lower.startswith(p) for p in benign_prefixes):
                    self.ban_manager.record_offense(
                        address, OFFENSE_INVALID_BLOCK, f"invalid_block:{reason}",
                    )

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
                # Wire format is hex-encoded binary (Block.to_bytes().hex()):
                # matches sync.py and messagechain/network/node.py's
                # _handle_request_blocks_batch.  Earlier this code used
                # block.serialize() (nested dict) which no receiver reads
                # today — silent IBD failure for any joining validator.
                blocks.append(block.to_bytes().hex())
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
                    current_height=self.blockchain.height + 1,
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
                # Round-10 fix: verify the signature before admitting.
                # Pre-fix this branch only checked that signer_id was a
                # registered entity -- ANY peer could craft a
                # ProposalTx / VoteTx / TreasurySpendTx with a forged
                # signer_id (any registered entity) and the validator
                # would admit it to `_pending_governance_txs` and
                # rebroadcast.  When the validator next became
                # proposer it packed the forged tx into its block;
                # `validate_block` then rejected the block at
                # `_validate_governance_tx_in_block` (sig fails) -->
                # the proposer wasted its slot, produced no block,
                # and accrued inactivity penalties.  Sustained flood
                # across rotated peers prevents block production
                # indefinitely on a 2-validator chain.  Mirrors the
                # verify-before-admit pattern of the stake / unstake
                # / authority branches above, using the same helper
                # the consensus-time validator already trusts.
                ok, _ = self.blockchain._validate_governance_tx(tx)
                if not ok:
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

    def _drain_orphan_flood_offenses(self) -> None:
        """Turn Blockchain's accumulated orphan-flood counts into ban offenses.

        Mirrors messagechain.network.node._drain_orphan_flood_offenses.
        Blockchain is peer-agnostic and just increments a counter when a
        peer exceeds MAX_ORPHAN_BLOCKS_PER_PEER or hits a full pool; the
        network layer owns the ban manager and converts those events into
        OFFENSE_PROTOCOL_VIOLATION hits here.
        """
        flood_map = getattr(self.blockchain, "orphan_flood_peers", None)
        if not flood_map:
            return
        for addr, count in list(flood_map.items()):
            for _ in range(count):
                self.ban_manager.record_offense(
                    addr, OFFENSE_PROTOCOL_VIOLATION, "orphan_pool_flood",
                )
        flood_map.clear()

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
        # Snapshot the peer dict before awaiting.  write_message is async,
        # so another coroutine can add/remove peers mid-loop, raising
        # RuntimeError: dictionary changed size during iteration.  Twin
        # of the same fix in messagechain/network/node.py._broadcast.
        snapshot = list(self.peers.items())
        for addr, peer in snapshot:
            if peer.is_connected and peer.writer:
                try:
                    await write_message(peer.writer, msg)
                except Exception as e:
                    # Broadcast write failure means the peer went away.
                    # Mark disconnected for maintenance-sweep cleanup; log
                    # at debug for diagnosability without spam.
                    logger.debug(
                        f"broadcast write to {addr} failed: {e}"
                    )
                    peer.is_connected = False


async def run(args):
    # Binary-out-of-date halt handler.  Installed as an asyncio loop-level
    # exception hook so BinaryOutOfDateError raised from any task (P2P
    # receive, block production, sync, orphan-retry) terminates the
    # process with a single clear message instead of being silently logged
    # as "Task exception was never retrieved" and leaving the validator
    # spinning in a half-alive state.  Uses os._exit(42) to bypass the
    # asyncio cleanup dance -- the validator is deliberately being killed
    # because it can no longer validate incoming blocks; a graceful
    # shutdown would try to process more blocks on the way out, which is
    # the exact thing we're trying to stop.
    from messagechain.core.blockchain import BinaryOutOfDateError
    def _binary_version_exception_handler(loop, context):
        exc = context.get("exception")
        if isinstance(exc, BinaryOutOfDateError):
            import os as _os, sys as _sys
            msg = str(exc)
            _sys.stderr.write("=" * 72 + "\n")
            _sys.stderr.write("BINARY OUT OF DATE -- HALTING\n")
            _sys.stderr.write(msg + "\n")
            _sys.stderr.write("=" * 72 + "\n")
            _sys.stderr.flush()
            logger.critical("BINARY OUT OF DATE: %s", msg)
            for h in list(logger.handlers):
                try:
                    h.flush()
                except Exception:
                    pass
            _os._exit(42)
        loop.default_exception_handler(context)
    asyncio.get_running_loop().set_exception_handler(
        _binary_version_exception_handler,
    )

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
        # Permission audit: on POSIX, refuse to read a keyfile that's
        # group- or world-accessible.  Catches the classic `cp keyfile
        # /etc/messagechain/keyfile` without chmod 0400 — the file lands
        # at the VM's umask (typically 0644) and anyone on the box can
        # exfiltrate the private key.  Windows stat lacks this bit
        # structure; skip the check there (Windows is not a production
        # validator target).
        try:
            # lstat (not stat) so a symlink to a world-readable file
            # doesn't pass the check just because the symlink itself is
            # 0777 (symlink modes are not meaningful — os.stat would
            # follow to the target).  Require the configured path to be
            # a real regular file owned by the service user.
            _st = os.lstat(args.keyfile)
            import stat as _stat_mod
            if _stat_mod.S_ISLNK(_st.st_mode):
                logger.error(
                    f"keyfile {args.keyfile} is a symbolic link; refuse "
                    f"to follow it.  Copy the target to the canonical "
                    f"location and chmod 0400."
                )
                sys.exit(1)
            if hasattr(os, "geteuid"):
                if _st.st_mode & 0o077:
                    logger.error(
                        f"keyfile {args.keyfile} has unsafe permissions "
                        f"(mode={_st.st_mode & 0o777:o}); expected 0400.  "
                        f"Run: chmod 0400 {args.keyfile}"
                    )
                    sys.exit(1)
                if _st.st_uid != os.geteuid():
                    logger.error(
                        f"keyfile {args.keyfile} is owned by uid {_st.st_uid}, "
                        f"not the running uid {os.geteuid()}.  Run: "
                        f"chown $(id -u) {args.keyfile}"
                    )
                    sys.exit(1)
        except FileNotFoundError:
            logger.error(f"keyfile {args.keyfile} not found")
            sys.exit(1)
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

        # Receipt-subtree bootstrap (attestable submission receipts).
        # On first boot, generate a dedicated WOTS+ subtree for signing
        # submission receipts.  Cached on disk so subsequent restarts
        # reuse the same tree.  If the generated root does not match
        # what chain state has registered for this entity, submit a
        # SetReceiptSubtreeRoot tx to bring chain state into agreement.
        # Without this, the receipt_subtree_roots map in state stays
        # empty and no validator can issue verifiable receipts — the
        # censorship-evidence pipeline collapses to plumbing with no
        # power plug.
        try:
            _bootstrap_receipt_subtree(
                server,
                private_key=private_key_input,
                entity=entity,
                data_dir=args.data_dir,
                no_cache=getattr(args, "no_keypair_cache", False),
            )
        except Exception:
            # Receipt bootstrap is best-effort at boot.  If it fails
            # here (e.g. cold-key unavailable, disk full, cache corrupt),
            # log the exception and let the node continue to start —
            # operators can fix and re-run; the chain is not at risk
            # just because receipts aren't issuable today.  Blocking
            # service start on this would turn a recoverable setup
            # issue into a liveness incident.
            logger.exception(
                "Receipt-subtree bootstrap failed — node will continue, "
                "but submission receipts will not be issuable until "
                "SetReceiptSubtreeRoot is submitted by an operator."
            )
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
            # Wire the validator's receipt issuer through so the public
            # HTTPS endpoint can issue SubmissionReceipt /
            # SubmissionAck / SignedRejection on demand.  Without this
            # the entire censorship-evidence pipeline silently
            # disabled itself: every `if receipt_issuer is not None:`
            # branch in submit_transaction_to_mempool fell through,
            # so a coerced validator could admit-and-drop / lie-about-
            # rejection / silently-TCP-drop honest submissions with
            # zero on-chain evidence trail.  The headline structural
            # defense against the project's primary adversary
            # (validator collusion, per CLAUDE.md) only functions
            # when this kwarg is passed.  KeyPair.sign carries an
            # internal lock so concurrent ThreadingMixIn handlers
            # cannot race the receipt subtree's _next_leaf counter
            # into a double-leaf-consumption WOTS+ key disclosure.
            receipt_issuer=server.receipt_issuer,
            # Wire the WitnessObservationStore so the `obs_ok` ack-
            # issuance gate has a real backing store.  Without this,
            # the gate short-circuits to True for any 32-byte
            # X-MC-Witnessed-Submission header value and a botnet
            # drains the 65k-leaf receipt subtree in hours via the
            # per-IP ack budget alone -- silently collapsing the
            # censorship-evidence pipeline.  See the install site
            # near server.py:947 for the full rationale; the store
            # starts empty (no gossip handler is wired yet), so the
            # safe-by-default posture denies ack issuance for any
            # request_hash this validator hasn't observed via
            # gossip.
            witness_observation_store=getattr(
                server, "witness_observation_store", None,
            ),
            # Share the receipt-subtree budget tracker with the RPC
            # surface so an attacker can't split traffic across
            # HTTPS+RPC and drain the per-IP burst twice.  The Server
            # constructs this eagerly in __init__; passing it through
            # here keeps both surfaces consulting one set of buckets.
            budget_tracker=server.receipt_budget_tracker,
        )
        submission_server.start()
        logger.info(
            "Public HTTPS submission endpoint active on %s:%d",
            args.submission_bind, args.submission_port,
        )

    public_feed_server = None
    if args.public_feed_port is not None:
        from messagechain.network.public_feed_server import PublicFeedServer

        # Optional cold-start faucet.  Requires --public-feed-port
        # to expose the /faucet POST handler.  When --faucet-keyfile
        # is unset the feed stays read-only.
        faucet_state = None
        if getattr(args, "faucet_keyfile", None):
            faucet_state = _build_faucet(server, args.faucet_keyfile)

        public_feed_server = PublicFeedServer(
            blockchain=server.blockchain,
            port=args.public_feed_port,
            bind=args.public_feed_bind,
            faucet=faucet_state,
        )
        public_feed_server.start()
        logger.info(
            "Public feed active on http://%s:%d/  (front with Caddy/Cloudflare for TLS)",
            args.public_feed_bind, args.public_feed_port,
        )
        if faucet_state is not None:
            logger.info(
                "Faucet active: drip=%d window_cap=%d",
                faucet_state.drip_amount,
                faucet_state.window_cap,
            )

    # Graceful shutdown: SIGTERM from systemd `systemctl stop` must run
    # the same cleanup path as Ctrl-C.  Without this, Python's default
    # SIGTERM action is immediate exit — server.stop() never runs, the
    # SQLite connection closes abruptly, and any leaf_index the node
    # consumed mid-block-production is silently burned with no block
    # ever broadcast.  Signal handlers aren't supported on Windows'
    # asyncio event loop, so catch that cleanly.
    import signal
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_shutdown(sig_name: str):
        logger.info(f"Received {sig_name}, shutting down gracefully")
        shutdown_event.set()

    for _sig_name, _sig in (("SIGTERM", signal.SIGTERM), ("SIGINT", signal.SIGINT)):
        try:
            loop.add_signal_handler(_sig, _request_shutdown, _sig_name)
        except (NotImplementedError, RuntimeError):
            # Windows asyncio doesn't support add_signal_handler — fall
            # back to KeyboardInterrupt for SIGINT and skip SIGTERM
            # (Windows systemd is not a supported deployment target).
            pass

    try:
        await shutdown_event.wait()
    except KeyboardInterrupt:
        # Windows fallback: Ctrl-C arrives as KeyboardInterrupt.
        pass

    logger.info("Shutting down")
    if submission_server is not None:
        submission_server.stop()
    if public_feed_server is not None:
        public_feed_server.stop()
    await server.stop()


def _build_faucet(server, keyfile_path: str):
    """Load the faucet wallet, install it, and return a FaucetState.

    Side effect: keypair is generated (or loaded from cache) at the
    chain-recorded tree height for this entity if known, otherwise
    16 (=65,536 leaves -- ample for years of bootstrap drips, ~10-20
    min cold keygen, instant warm restarts via the keypair cache).

    The build/submit callbacks close over the faucet entity, the
    chain, and the in-process mempool/RPC plumbing.  They do NOT
    do an outbound RPC roundtrip -- the faucet runs in the same
    Python process as the validator, so the cheapest correct path
    is to call _rpc_submit_transfer directly.
    """
    from messagechain.core.transfer import create_transfer_transaction
    from messagechain.identity.identity import Entity
    from messagechain.network.faucet import FaucetState, FAUCET_DRIP
    from messagechain.config import MIN_FEE_POST_FLAT, NEW_ACCOUNT_FEE

    # Read the daemon-format keyfile (raw 64-char hex, no checksum)
    # the same way the main --keyfile loader does at server startup.
    # Operator workflow: scripts/generate_faucet_key.py produces the
    # paper-backup format and pushes raw hex to a deploy-time secret
    # store; the systemd unit drops just the raw hex into /dev/shm.
    with open(keyfile_path) as _kf:
        hex_key = _kf.read().strip()
    try:
        private_key = bytes.fromhex(hex_key)
    except ValueError as e:
        raise SystemExit(
            f"--faucet-keyfile {keyfile_path} does not contain valid hex: {e}"
        )
    if len(private_key) != 32:
        raise SystemExit(
            f"--faucet-keyfile {keyfile_path} must be exactly 64 hex chars "
            f"(got {len(hex_key)})"
        )

    chain = server.blockchain
    # Resolve the entity's recorded WOTS+ tree height if it has any
    # chain history; fall back to 16.  Mirrors the same lookup the
    # main wallet does via --wallet.
    probe_entity_id = Entity.create(private_key, tree_height=4).entity_id
    stored_height = None
    if hasattr(chain, "get_wots_tree_height"):
        try:
            stored_height = chain.get_wots_tree_height(probe_entity_id)
        except Exception:
            stored_height = None
    tree_height = stored_height if stored_height is not None else 16

    data_dir = getattr(server, "data_dir", None)
    entity = _load_or_create_entity(
        private_key, tree_height, data_dir,
        no_cache=getattr(server, "no_keypair_cache", False),
    )
    logger.info(
        "Faucet wallet loaded: entity=%s tree_height=%d",
        entity.entity_id_hex[:16], tree_height,
    )

    # Track whether the faucet's hot pubkey is already installed on
    # chain.  Set on first successful drip so subsequent transfers
    # skip the (rejected) repeat-pubkey path.  Bootstrap from current
    # chain state so a restart after one drip does not re-include.
    pubkey_installed = entity.entity_id in chain.public_keys

    def build_tx(recipient_bytes: bytes) -> dict:
        nonlocal pubkey_installed
        # Re-check chain state every time -- handles the case where
        # the chain advanced and installed our pubkey via someone
        # else's transfer between drips.
        if not pubkey_installed:
            pubkey_installed = entity.entity_id in chain.public_keys

        # Advance the keypair past the chain-recorded watermark so a
        # cold restart between drips does not retry a burned leaf.
        wm = 0
        if hasattr(chain, "get_leaf_watermark"):
            try:
                wm = chain.get_leaf_watermark(entity.entity_id) or 0
            except Exception:
                wm = 0
        if wm > entity.keypair._next_leaf:
            entity.keypair.advance_to_leaf(wm)

        # Mirror cmd_transfer's pattern: use server's pending-nonce
        # helper so back-to-back drips inside one block window pick
        # up sequential nonces without waiting for inclusion.
        nonce = server._get_pending_nonce_all_pools(entity.entity_id)
        # Faucet recipients are brand-new wallets BY DEFINITION (the
        # whole point is to fund first-time-on-chain users), so every
        # transfer pays the NEW_ACCOUNT_FEE surcharge on top of the
        # base floor.  Without this addition, the chain rejects every
        # drip with "Transfer to brand-new recipient requires fee >=
        # 1100".  Pre-paying the surcharge unconditionally is correct
        # even on the rare path where the recipient already exists --
        # the chain just keeps the extra as additional fee paid; it
        # does not over-debit.
        fee = MIN_FEE_POST_FLAT + NEW_ACCOUNT_FEE
        tx = create_transfer_transaction(
            entity,
            recipient_id=recipient_bytes,
            amount=FAUCET_DRIP,
            nonce=nonce,
            fee=fee,
            include_pubkey=not pubkey_installed,
        )
        # Optimistically flip the flag so two near-simultaneous
        # build_tx calls do not both set include_pubkey=True (the
        # second would be rejected).  FaucetState.try_drip's lock
        # serializes us here, so this is safe.
        if not pubkey_installed:
            pubkey_installed = True
        return tx.serialize()

    def submit_tx(tx_dict: dict) -> tuple[bool, str]:
        # In-process RPC equivalent: hits the same code path the
        # external `submit_transfer` JSON-RPC method does.
        resp = server._rpc_submit_transfer({"transaction": tx_dict})
        if resp.get("ok"):
            return True, ""
        return False, str(resp.get("error", "unknown"))

    return FaucetState(
        submit_callback=submit_tx,
        build_tx_callback=build_tx,
    )


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
    # --- Public read-only feed (opt-in) ---
    # Off by default.  Set --public-feed-port (typ. 8080) to expose a
    # GET-only HTTP endpoint serving recent on-chain messages plus a
    # bundled HTML viewer.  Plain HTTP — operators should front this
    # with Caddy/Cloudflare for TLS.  See
    # messagechain/network/public_feed_server.py.
    parser.add_argument(
        "--public-feed-port", type=int, default=None,
        help="If set, start a public read-only HTTP feed on this port "
             "serving GET /v1/latest (newest messages), GET /v1/info "
             "(chain height), and GET / (bundled HTML viewer). Plain "
             "HTTP — front with Caddy/Cloudflare for TLS.",
    )
    parser.add_argument(
        "--public-feed-bind", type=str, default="127.0.0.1",
        help="Bind address for the public feed (default: 127.0.0.1). "
             "Typically bound to localhost and fronted by a reverse proxy; "
             "use 0.0.0.0 only if exposing directly to the public internet.",
    )
    # --- Cold-start funding faucet (opt-in, requires --public-feed-port) ---
    # Off by default.  When set, the validator loads a separate WOTS+
    # wallet from --faucet-keyfile and exposes a POST /faucet endpoint
    # on the public feed server.  Each request drips a small fixed
    # amount to the requested address, gated by per-IP, per-address,
    # and daily-aggregate rate limits (see messagechain/network/faucet.py).
    # Closes the receive-to-exist cold-start gap: a fresh user with
    # a freshly-generated keyfile cannot send their first message
    # without prior on-chain balance, and there is no other allocation
    # path during bootstrap.  Operator funds the faucet wallet out-of-
    # band with a one-time transfer; refill is manual.
    parser.add_argument(
        "--faucet-keyfile", type=str, default=None,
        help="Path to a hex-checksummed private-key file for the cold-"
             "start faucet wallet.  When set AND --public-feed-port is "
             "also set, the public feed exposes POST /faucet for "
             "operator-funded drips to fresh user wallets.  "
             "Generate with scripts/generate_faucet_key.py.  See "
             "messagechain/network/faucet.py for rate-limit details.",
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

    # Log the fee-includes-signature activation height so operators can
    # confirm at boot which coordinated-fork height this node is running.
    # Silent divergence at activation is a consensus-forking bug; a boot-
    # time log line is a cheap way to catch a mis-set
    # MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT before it matters.
    from messagechain.config import FEE_INCLUDES_SIGNATURE_HEIGHT
    logger.info(
        "FEE_INCLUDES_SIGNATURE_HEIGHT activation: %d "
        "(override via MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT)",
        FEE_INCLUDES_SIGNATURE_HEIGHT,
    )

    # Binary-out-of-date halt gate.  The loop-level hook inside `run()`
    # handles the common path (BinaryOutOfDateError raised from an
    # asyncio task -- e.g., P2P receive or block production).  This
    # outer try/except is the backstop for the rarer case where it
    # fires synchronously, outside of any task (e.g., startup chain
    # replay from disk).  Both paths exit non-zero with code 42 so the
    # operator + systemd see the same halt signal.
    from messagechain.core.blockchain import BinaryOutOfDateError
    try:
        asyncio.run(run(args))
    except BinaryOutOfDateError as e:
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.write("BINARY OUT OF DATE -- HALTING\n")
        sys.stderr.write(str(e) + "\n")
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.flush()
        logger.critical("BINARY OUT OF DATE: %s", str(e))
        sys.exit(42)


if __name__ == "__main__":
    main()
