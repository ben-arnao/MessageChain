"""
Signature verification cache for MessageChain.

WOTS+ signature verification is expensive (many hash chain computations).
This cache prevents redundant verification of the same (message, signature,
pubkey) tuple — critical for DoS resistance since the same transaction
may be verified multiple times (mempool admission, block validation, reorg replay).

Design inspired by Bitcoin Core's CSignatureCache (CuckooCache-based).
"""

import hashlib
import os
import struct
from collections import OrderedDict
from messagechain.config import HASH_ALGO

# Default max cache entries — each entry is ~96 bytes (key) + overhead
DEFAULT_CACHE_SIZE = 50_000


class SignatureCache:
    """LRU-bounded cache of signature verification results.

    Stores hash(nonce || len||msg_hash || len||sig_hash || len||pub_key) -> bool.
    Both positive and negative results are cached to prevent DoS via
    repeated invalid signature submissions.

    The per-instance `_nonce` randomizes cache keys across nodes so that a
    collision set precomputed against one node cannot be replayed against
    another. Matches Bitcoin Core's CSignatureCache approach (randomized
    per-process key on startup, never exposed to the network).
    """

    def __init__(self, max_size: int = DEFAULT_CACHE_SIZE):
        self.max_size = max_size
        self._cache: OrderedDict[bytes, tuple[bool, int]] = OrderedDict()
        # block_hash -> list of cache keys, for partial invalidation on reorg
        self._block_keys: dict[bytes, list[bytes]] = {}
        # Monotonic version counter — incremented on invalidation.
        # Entries cached at a prior version are treated as misses.
        self._version: int = 0
        # Per-instance random nonce. 32 bytes — wide enough that a hash
        # collision precomputation against a random node is infeasible.
        self._nonce: bytes = os.urandom(32)

    def _key(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes) -> bytes:
        """Compute a unique cache key from the verification triple.

        Uses length-prefixed encoding to prevent ambiguous concatenation
        (e.g., different field-boundary splits hashing to the same key)
        and a per-instance nonce so cache keys are not portable across
        SignatureCache instances (precomputation resistance).
        """
        return hashlib.new(
            HASH_ALGO,
            self._nonce
            + struct.pack(">I", len(msg_hash)) + msg_hash
            + struct.pack(">I", len(sig_hash)) + sig_hash
            + struct.pack(">I", len(pub_key)) + pub_key,
        ).digest()

    def lookup(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes) -> bool | None:
        """Check if a verification result is cached. Returns None on miss."""
        key = self._key(msg_hash, sig_hash, pub_key)
        if key in self._cache:
            result, cached_version = self._cache[key]
            if cached_version == self._version:
                self._cache.move_to_end(key)
                return result
            # Stale entry from prior version — treat as miss
            del self._cache[key]
        return None

    def store(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes, result: bool):
        """Store a verification result in the cache.

        Caches both positive and negative results. Negative caching prevents
        DoS via repeated submission of invalid signatures that are expensive
        to verify (WOTS+ hash chains).
        """
        key = self._key(msg_hash, sig_hash, pub_key)
        if key in self._cache:
            self._cache.move_to_end(key)
            return
        if len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        self._cache[key] = (result, self._version)

    def invalidate(self, block_hashes: set[bytes] | None = None):
        """Invalidate cache entries.

        If block_hashes is provided, only entries associated with those blocks
        are removed (partial invalidation for shallow reorgs). Otherwise, the
        entire cache is cleared.
        """
        if block_hashes is None:
            # Full invalidation: clear everything and bump version.
            # Version bump ensures any concurrent lookups in progress
            # won't return stale results from the prior epoch.
            self._cache.clear()
            self._block_keys.clear()
            self._version += 1
        else:
            # Partial invalidation: only remove entries for specific blocks.
            # No version bump needed — unaffected entries remain valid.
            for bh in block_hashes:
                for key in self._block_keys.pop(bh, []):
                    self._cache.pop(key, None)

    def associate_block(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes, block_hash: bytes):
        """Associate a cached entry with a block for partial invalidation."""
        key = self._key(msg_hash, sig_hash, pub_key)
        if block_hash not in self._block_keys:
            self._block_keys[block_hash] = []
        self._block_keys[block_hash].append(key)

    def __len__(self) -> int:
        return len(self._cache)


# Global singleton
_global_cache: SignatureCache | None = None


def get_global_cache() -> SignatureCache:
    """Get or create the global signature cache."""
    global _global_cache
    if _global_cache is None:
        _global_cache = SignatureCache()
    return _global_cache
