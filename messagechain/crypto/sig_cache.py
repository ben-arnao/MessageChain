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
    """Compute a unique cache key from the verification triple."""
    return hashlib.new(HASH_ALGO, msg_hash + sig_hash + pub_key).digest()


class SignatureCache:
    """LRU-bounded cache of signature verification results.

    Stores hash(msg_hash || sig_hash || pub_key) -> bool.
    Only positive results are cached (a failed verification might
    be retried with corrected data).
    """

    def __init__(self, max_size: int = DEFAULT_CACHE_SIZE):
        self.max_size = max_size
        self._cache: OrderedDict[bytes, bool] = OrderedDict()

    def lookup(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes) -> bool | None:
        """Check if a verification result is cached. Returns None on miss."""
        key = _cache_key(msg_hash, sig_hash, pub_key)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def store(self, msg_hash: bytes, sig_hash: bytes, pub_key: bytes, result: bool):
        """Store a verification result in the cache."""
        if not result:
            return  # only cache positive results
        key = _cache_key(msg_hash, sig_hash, pub_key)
        if key in self._cache:
            self._cache.move_to_end(key)
            return
        if len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        self._cache[key] = result

    def invalidate(self):
        """Clear the entire cache (e.g., after a reorg)."""
        self._cache.clear()

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
