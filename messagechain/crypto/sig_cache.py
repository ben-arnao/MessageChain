"""
Signature verification cache for MessageChain.

WOTS+ signature verification is expensive (many hash chain computations).
This cache prevents redundant verification of the same (message, signature,
pubkey) tuple — critical for DoS resistance since the same transaction
may be verified multiple times (mempool admission, block validation, reorg replay).

Design inspired by Bitcoin Core's CSignatureCache (CuckooCache-based).
"""

import hashlib
from collections import OrderedDict
from messagechain.config import HASH_ALGO

# Default max cache entries — each entry is ~96 bytes (key) + overhead
DEFAULT_CACHE_SIZE = 50_000


def _cache_key(msg_hash: bytes, sig_hash: bytes, pub_key: bytes) -> bytes:
    """Compute a unique cache key from the verification triple.

    Uses length-prefixed encoding to prevent ambiguous concatenation
    (e.g., different field-boundary splits hashing to the same key).
    """
    import struct
    return hashlib.new(
        HASH_ALGO,
        struct.pack(">I", len(msg_hash)) + msg_hash
        + struct.pack(">I", len(sig_hash)) + sig_hash
        + struct.pack(">I", len(pub_key)) + pub_key,
    ).digest()


class SignatureCache:
    """LRU-bounded cache of signature verification results.

    Stores hash(len||msg_hash || len||sig_hash || len||pub_key) -> bool.
    Both positive and negative results are cached to prevent DoS via
    repeated invalid signature submissions.
    """

    def __init__(self, max_size: int = DEFAULT_CACHE_SIZE):
        self.max_size = max_size
        self._cache: OrderedDict[bytes, bool] = OrderedDict()
        # block_hash -> list of cache keys, for partial invalidation on reorg
        self._block_keys: dict[bytes, list[bytes]] = {}

    def lookup(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes) -> bool | None:
        """Check if a verification result is cached. Returns None on miss."""
        key = _cache_key(msg_hash, sig_hash, pub_key)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def store(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes, result: bool):
        """Store a verification result in the cache.

        Caches both positive and negative results. Negative caching prevents
        DoS via repeated submission of invalid signatures that are expensive
        to verify (WOTS+ hash chains).
        """
        key = _cache_key(msg_hash, sig_hash, pub_key)
        if key in self._cache:
            self._cache.move_to_end(key)
            return
        if len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        self._cache[key] = result

    def invalidate(self, block_hashes: set[bytes] | None = None):
        """Invalidate cache entries.

        If block_hashes is provided, only entries associated with those blocks
        are removed (partial invalidation for shallow reorgs). Otherwise, the
        entire cache is cleared.
        """
        if block_hashes is None:
            self._cache.clear()
            self._block_keys.clear()
            return
        for bh in block_hashes:
            for key in self._block_keys.pop(bh, []):
                self._cache.pop(key, None)

    def associate_block(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes, block_hash: bytes):
        """Associate a cached entry with a block for partial invalidation."""
        key = _cache_key(msg_hash, sig_hash, pub_key)
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
