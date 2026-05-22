"""Shared HMAC-authenticated WOTS+ keypair cache.

The daemon (``server.py``) and the personal-wallet CLI both need to
avoid regenerating a 2^height-leaf WOTS+ Merkle tree on every restart /
invocation -- at the production height that's a ~20-30 minute wedge per
call.  This module is the single source of truth for the cache file
format so both call sites cannot drift out of sync.

On-disk layout:

    [4 B magic = b"MCKC"] [32 B HMAC-SHA3-256] [JSON payload]

The HMAC is keyed on a domain-separated derivation of the user's
private key, so:

  * Tampering with the file (byte flip, swapped blob, planted pickle,
    stale format) fails authentication -> caller deletes + regenerates.
  * A copied cache file on a host with a different private key fails
    authentication -> no cross-key contamination.
  * A stolen cache file alone is useless without the seed phrase.

The JSON payload carries only ``public_key`` + ``entity_id`` + a
format version + the tree height -- i.e. exactly the data needed to
reconstruct the keypair via ``KeyPair._from_trusted_root`` without
re-running the O(2^height) leaf derivation.  Everything secret stays
in the seed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Optional

from messagechain.identity.identity import Entity
from messagechain.crypto.keys import KeyPair


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

CACHE_MAGIC = b"MCKC"  # MessageChain Keypair Cache (HMAC-authenticated)
CACHE_FORMAT_VERSION = 1
HMAC_SIZE = 32
CACHE_HMAC_DOMAIN = b"messagechain-keypair-cache-v1|"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def keypair_cache_path(private_key: bytes, tree_height: int, data_dir: str) -> str:
    """Filesystem path for a daemon (data-dir-rooted) keypair cache.

    The filename embeds a truncated SHA3-256 digest of
    ``private_key || tree_height`` so that different keys or heights
    never collide and the raw private key never appears in the path.
    """
    h = hashlib.sha3_256(private_key + tree_height.to_bytes(4, "big")).hexdigest()[:16]
    return os.path.join(data_dir, f"keypair_cache_{h}.bin")


def personal_wallet_cache_dir() -> str:
    """Cache root for personal-wallet (no-data-dir CLI) flow.

    Lives under the user's home directory so it survives across CLI
    invocations and never lands in the operator's daemon data_dir.
    Created lazily by ``personal_wallet_cache_path`` callers.
    """
    return str(Path.home() / ".messagechain" / "wallet_cache")


def personal_wallet_cache_path(private_key: bytes, tree_height: int) -> str:
    """Filesystem path for the personal-wallet keypair cache.

    Same flat / digest-keyed layout as the daemon path
    (``keypair_cache_path``) so the on-disk shape is identical and
    the daemon's HMAC encode / decode helpers work unchanged.
    """
    return keypair_cache_path(private_key, tree_height, personal_wallet_cache_dir())


# ---------------------------------------------------------------------------
# Encode / decode (HMAC-authenticated)
# ---------------------------------------------------------------------------


def _cache_mac_key(private_key: bytes) -> bytes:
    """Domain-separated HMAC key used to authenticate the cache payload."""
    return hashlib.sha3_256(CACHE_HMAC_DOMAIN + private_key).digest()


def encode_keypair_cache(
    entity: Entity, private_key: bytes, tree_height: int,
) -> bytes:
    """Serialize *entity* into the on-disk cache format."""
    payload_obj = {
        "version": CACHE_FORMAT_VERSION,
        "tree_height": tree_height,
        "public_key": entity.keypair.public_key.hex(),
        "entity_id": entity.entity_id.hex(),
    }
    payload = json.dumps(
        payload_obj, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    mac = hmac.new(
        _cache_mac_key(private_key), payload, hashlib.sha3_256,
    ).digest()
    return CACHE_MAGIC + mac + payload


def decode_keypair_cache(
    data: bytes, private_key: bytes, tree_height: int,
) -> Optional[Entity]:
    """Reconstruct an Entity from cached bytes, or None on any failure.

    Every rejection path returns None silently -- the caller deletes the
    file and regenerates.  No partial / differential information leaks
    from the loader; an attacker who can plant a file cannot distinguish
    "wrong magic" from "wrong MAC" from "wrong tree height" via the API.
    """
    header_len = len(CACHE_MAGIC) + HMAC_SIZE
    if len(data) < header_len:
        return None
    if not data.startswith(CACHE_MAGIC):
        return None
    mac = data[len(CACHE_MAGIC):header_len]
    payload = data[header_len:]
    expected = hmac.new(
        _cache_mac_key(private_key), payload, hashlib.sha3_256,
    ).digest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("version") != CACHE_FORMAT_VERSION:
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


# ---------------------------------------------------------------------------
# Personal-wallet entry point
# ---------------------------------------------------------------------------


def _atomic_write(path: str, blob: bytes) -> None:
    """Write *blob* to *path* via tmp + rename.  Best-effort fsync + chmod 600."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def load_or_create_personal_wallet_entity(
    private_key: bytes,
    *,
    tree_height: Optional[int] = None,
    progress=None,
) -> Entity:
    """Return an Entity, using ``~/.messagechain/wallet_cache/`` when possible.

    Cache hit (HMAC-verified): ~milliseconds -- reuses the on-disk root.
    Cache miss / corrupt / different height: full ``Entity.create`` then
    write the cache.

    The cache is transparent: callers never need to opt in or pass a
    flag.  A stolen cache file alone is useless without the private key
    that derived it (HMAC-authenticated; payload is verified before any
    bytes are trusted).

    Leaf-watermark advancement is handled by the CLI's
    ``_bind_persistent_leaf_index`` helper, which max()'s the on-disk
    cursor with the chain watermark BEFORE signing -- so restoring a
    cached keypair and then advancing to the current chain leaf is
    correct even if the cache was written long before the most recent
    sign.

    When ``tree_height`` is omitted, the resolver scans the cache
    directory for any prior wallet at the candidate heights -- the
    new wallet default first (cheap fast-keygen path), then the
    legacy validator default (back-compat for wallets generated
    before the default was lowered).  This prevents a default change
    from silently regenerating a different public key for the same
    seed and orphaning the user's on-chain identity.

    ``progress`` is an optional per-leaf callback forwarded to
    ``Entity.create`` ONLY on the cache-miss keygen path.  Cache hits
    return without invoking the callback (the slow path is what
    needs feedback, not the fast path).  The CLI installs
    ``_make_progress_reporter`` here so cold-wallet first signing
    commands show a bar identical to ``generate-key`` instead of
    looking frozen for minutes.
    """
    if tree_height is not None:
        return _load_or_create_at_height(
            private_key, tree_height, progress=progress,
        )

    # No explicit height: probe the cache at both the new wallet default
    # AND the historical validator default.  This keeps existing wallets
    # (cached at the validator default before the lowered wallet default
    # shipped) bound to their on-chain identity instead of silently
    # regenerating at a different height -- which would produce a
    # different public key, a different entity_id, and orphan the
    # account.  Both checks are cheap (file existence + HMAC verify on
    # hit); the slow Entity.create path only runs if no cache file
    # exists at any candidate height.
    from messagechain.config import (
        WALLET_DEFAULT_TREE_HEIGHT, MERKLE_TREE_HEIGHT,
    )
    # Probe the demo-account height (10) first since cache HIT there is
    # the fast common path for the messagechain.org Create Account flow
    # -- without h=10 in the candidate list, a /wallet/login that pastes
    # a Create Account .key would miss the cache at h=16 + h=20, then
    # fall back to a multi-minute Entity.create at the production height
    # AND produce the wrong entity_id (different root per height).
    # File-existence + HMAC verify on hit is cheap, so adding extra
    # probe candidates is essentially free on the cache-hit fast path.
    DEMO_ACCOUNT_HEIGHT = 10
    candidate_heights = []
    for h in (DEMO_ACCOUNT_HEIGHT, WALLET_DEFAULT_TREE_HEIGHT, MERKLE_TREE_HEIGHT):
        if h not in candidate_heights:
            candidate_heights.append(h)
    for h in candidate_heights:
        cache_path = personal_wallet_cache_path(private_key, h)
        if not os.path.exists(cache_path):
            continue
        try:
            with open(cache_path, "rb") as f:
                blob = f.read()
            entity = decode_keypair_cache(blob, private_key, h)
        except OSError:
            entity = None
        if entity is not None:
            logger.info(
                "Loaded personal-wallet keypair from cache %s (h=%d)",
                cache_path, h,
            )
            return entity
    # No cache hit at any candidate height -- fall back to the historical
    # validator-default height (``MERKLE_TREE_HEIGHT``).  The lowered
    # ``WALLET_DEFAULT_TREE_HEIGHT`` is opt-in via ``cmd_generate_key``,
    # which writes its cache at the new height so the probe above finds
    # it on subsequent calls.  Defaulting the cache-miss path to the
    # lower height would silently bind a DIFFERENT identity for any
    # wallet whose owner ran a CLI command before ever running
    # ``generate-key`` (e.g. importing an existing seed via verify-key
    # on a fresh machine, or any test that constructs an Entity at the
    # historical default and then drives a CLI command through this
    # resolver).
    return _load_or_create_at_height(
        private_key, MERKLE_TREE_HEIGHT, progress=progress,
    )


def _load_or_create_at_height(
    private_key: bytes, tree_height: int, *, progress=None,
) -> Entity:
    """Cache-or-generate at a single specific tree height."""
    cache_path = personal_wallet_cache_path(private_key, tree_height)
    cache_dir = os.path.dirname(cache_path)

    # Cache-hit path.
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                blob = f.read()
            entity = decode_keypair_cache(blob, private_key, tree_height)
        except OSError:
            entity = None
        if entity is not None:
            logger.info("Loaded personal-wallet keypair from cache %s", cache_path)
            return entity
        logger.warning(
            "Corrupt or unauthenticated personal-wallet keypair cache %s "
            "-- deleting and regenerating",
            cache_path,
        )
        try:
            os.remove(cache_path)
        except OSError:
            pass

    # Fresh keygen -- slow path.  ``progress`` (when present) is the
    # per-leaf callback the CLI uses to drive the cold-wallet
    # progress bar.  ``Entity.create`` already accepts the kwarg and
    # forwards it to ``KeyPair.generate``.
    entity = Entity.create(
        private_key, tree_height=tree_height, progress=progress,
    )

    # Write the cache for next time.  Best-effort: a permission error,
    # full disk, or unserializable entity (test mocks, malformed
    # keypair) must NOT crash the CLI; the user just pays the keygen
    # cost again on the next run.  We swallow Exception broadly here
    # because the cache is purely a UX optimization -- never trade a
    # working command for a cache-write failure.
    try:
        os.makedirs(cache_dir, exist_ok=True)
        blob = encode_keypair_cache(entity, private_key, tree_height)
        _atomic_write(cache_path, blob)
        logger.info("Saved personal-wallet keypair cache to %s", cache_path)
    except Exception:  # noqa: BLE001 -- see comment above
        logger.warning(
            "Could not write personal-wallet keypair cache to %s", cache_path,
        )

    return entity
