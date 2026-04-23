"""
Versioned hash dispatcher — the single point through which every
consensus-critical hash in the codebase flows.

Rationale
=========
`HASH_VERSION_CURRENT` has lived on block headers since day one as a
"carry-only register" that a future governance proposal could bump to
widen the accepted hash family.  But the dispatch side was missing:
every hashing module defined its own `_hash = hashlib.new(HASH_ALGO, …)`
wrapper, fossilizing SHA3-256 at ~50 call sites.  When SHA3 eventually
weakens (the chain is designed for a 100-1000 year horizon; the file
CLAUDE.md pegs "50 years? 200?"), widening the accept set in
config.validate_hash_version would no longer be enough — every call
site would need an edit, exactly the "logic edit vs data edit"
anti-pattern the crypto-agility registers were introduced to avoid.

This module centralizes the dispatch.  A future hash migration is a
data edit here: add the new version → algorithm row, bump
HASH_VERSION_CURRENT in config.py, widen
_ACCEPTED_HASH_VERSIONS in validate_hash_version.  No call site
changes required.

Usage
=====
- `default_hash(data)` — hash at the current protocol version.  Use
  this everywhere you would have written `hashlib.new(HASH_ALGO, data)
  .digest()`.  Module-local `_hash(data)` helpers should thin-wrap
  this so existing call sites stay identical.
- `hash_v(data, hash_version)` — explicit version dispatch.  Use this
  when you are verifying stored / historical data that committed its
  own `hash_version` byte (e.g. a block header whose `hash_version`
  may differ from `HASH_VERSION_CURRENT` during a migration window).

Only the dispatch table lives here — the version constants themselves
remain in config.py (the single source of truth for all version
registers).  This module is deliberately a leaf: it does not import
config at module scope, so config.py can call `default_hash` from
constants that are computed at import time without a circular import.
"""

import hashlib


# Every accepted hash version maps to the algorithm name `hashlib.new`
# understands.  Widening this dict is the only edit required when a
# governance proposal activates a new hash family — callers stay
# untouched because they dispatch through hash_v / default_hash.
#
# Version 0 is reserved as the uninitialized / truncated sentinel, so
# we never associate it with a real algorithm.
#
# Keys are the integer values in config.HASH_VERSION_* — duplicated
# here as bare literals to keep this module import-cycle-free.  The
# test suite (test_hash_dispatch.py) pins the mapping to the config
# constants so a drift between the two locations is caught
# immediately rather than at the next fork.
_ALGO_BY_VERSION: dict[int, str] = {
    1: "sha3_256",  # HASH_VERSION_SHA256 in config.py
}


def hash_v(data: bytes, hash_version: int) -> bytes:
    """Hash `data` under the specified protocol hash version.

    Callers that know which version produced a blob (block.header.
    hash_version, a stored receipt's hash_version byte, etc.) pass it
    explicitly so the verifier uses the same primitive the signer
    committed to.  An unknown version raises ValueError — no silent
    fallback to "current", which would allow a downgrade attack in a
    migration window where two versions are both accepted.
    """
    algo = _ALGO_BY_VERSION.get(hash_version)
    if algo is None:
        raise ValueError(
            f"Unknown hash_version {hash_version} "
            f"(accepted = {sorted(_ALGO_BY_VERSION)})"
        )
    return hashlib.new(algo, data).digest()


def default_hash(data: bytes) -> bytes:
    """Hash `data` under the protocol's current hash version.

    This is the right default for any call site that is producing a
    new hash (signing a tx, computing a block header's block_hash,
    deriving an entity_id).  Historical verification paths should
    prefer `hash_v(data, stored_version)` so they stay correct across
    a version bump.

    The HASH_VERSION_CURRENT import is lazy so this module stays a
    leaf that config.py itself can call during its own import.
    """
    from messagechain.config import HASH_VERSION_CURRENT
    return hash_v(data, HASH_VERSION_CURRENT)
