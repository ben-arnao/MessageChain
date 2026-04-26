"""Validator version signaling registry.

Each release of the validator binary is assigned a monotonically
increasing 16-bit identifier.  Block proposers stamp their version
into the block header so peers can tell which consensus rules the
proposer was running, and so future forks can refuse to activate
until enough validators have signaled support for the new rules.

This is the foundation laid by Fork 1 (audit finding #2).  Fork 2
(the active-set liveness fallback, audit finding #1) consumes it as
its activation gate -- the leak math will not engage at its fork
height unless at least MIN_VERSIONED_VALIDATORS proposers have
already signaled MIN_VALIDATOR_VERSION_FOR_FORK[fork_2_height].

## Why a uint16 monotonic counter, not a SemVer string

A uint16 mapped 1:1 to release tags is unambiguous on the wire (no
parsing rules to disagree on), 50x cheaper than a string, and easy to
compare with `>=`.  The mapping back to the human-readable release
tag lives in REGISTRY below, so binary version 7 always corresponds
to exactly one shipped release.

Reserved: 0 means "unsignalled" (pre-Fork-1 blocks; legacy V1 wire
format).  Validators MUST treat 0 as "no signal" and never as "any
acceptable version" -- otherwise a downgrade attack flipping the
field to 0 would silently bypass any future activation gate.

## Adding a new entry

Each release that ships a new consensus-relevant version bumps
CURRENT_VALIDATOR_VERSION and appends a row to REGISTRY.  Never
remove rows -- old binaries reading new blocks need to recognize
the version even if they cannot interpret it.

## Why this is not in config.py

`config.py` is already 3000+ lines.  Validator versions have a
narrow, well-defined surface area, and they grow append-only with
each release.  Keeping them in their own module makes the
"add a row, bump a constant" workflow a one-file change.
"""

from __future__ import annotations

from typing import Final


# Sentinel: pre-Fork-1 blocks carry no validator_version field.
# When a header is decoded from V1 wire format, validator_version
# defaults to UNSIGNALLED.  Code that compares against this constant
# should treat it as "no signal" -- never as "matches any version."
UNSIGNALLED: Final[int] = 0


# Append-only mapping from validator_version to (release_tag, notes).
# `release_tag` is the GitHub tag that shipped this version (canonical
# format `vX.Y.Z-mainnet`).  `notes` is a one-line description for
# human readers; not consumed by code.
REGISTRY: Final[dict[int, tuple[str, str]]] = {
    UNSIGNALLED: (
        "(legacy)",
        "Pre-Fork-1 blocks; no version field on the wire.",
    ),
    1: (
        "v1.10.0-mainnet",
        "First release stamping validator_version into block headers. "
        "Fork-1 activation: introduces V2 block serialization carrying "
        "the new field; no consensus-rule changes yet.",
    ),
}


# The version this binary stamps into blocks it produces.  Bump in
# lockstep with __version__ on every release that ships consensus-
# relevant changes.  See REGISTRY for the value -> tag mapping.
CURRENT_VALIDATOR_VERSION: Final[int] = 1


def is_known_version(version: int) -> bool:
    """Has this binary ever heard of `version`?

    Useful for emitting better diagnostics ("the proposer is running a
    newer release than I am, you should upgrade") rather than just
    "unknown version, refusing block."  Future forks may still accept
    blocks proposed by unknown future versions if the consensus rules
    are unchanged at this height.
    """
    return version in REGISTRY


def describe_version(version: int) -> str:
    """Human-readable label for a validator_version, for log lines.

    Returns either the release tag (e.g. "v1.10.0-mainnet") or
    "<unknown vN>" for versions not in the registry.
    """
    if version in REGISTRY:
        tag, _notes = REGISTRY[version]
        return tag
    return f"<unknown v{version}>"
