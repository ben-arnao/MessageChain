"""
Strict semver parsing and ordering for release manifests.

Why this exists: the monotonic guard on `latest_release_manifest` used
to be `incoming.version > stored.version` as a plain Python string
comparison.  That breaks at every 9 -> 10 digit boundary
(`"0.10.0" < "0.9.0"` under string compare), which silently
swallowed legitimate releases — the tx was still accepted into the
block (verify passed), but the state slot was not advanced, and
operators saw no "update available" signal.

This module provides a tiny stdlib-only parser + comparator so every
site that cares about release ordering (the consensus apply branch,
the boot-log, the `get_latest_release` RPC) agrees on the semantics.

Scope and simplifications — chosen deliberately for a 1000-year chain:

- Accept strictly `MAJOR.MINOR.PATCH` or
  `MAJOR.MINOR.PATCH-PRERELEASE`.  No build metadata (`+...`), no
  `v` prefix, no whitespace.
- MAJOR/MINOR/PATCH are non-negative decimal integers with no leading
  zeros (except `0` itself).
- PRERELEASE is `[A-Za-z0-9.]+` (ASCII only) and compared by
  lexicographic string order between same-core versions — we do NOT
  implement semver's dot-segment prerelease rules.  Release signers
  control the prerelease tag and can avoid ambiguous names (rc1 / rc2 /
  rc10-under-lex is an edge they agree to avoid).
- 64-char inner cap on the raw input as a DoS / sanity bound.  The
  outer serialization path has its own smaller cap
  (`RELEASE_ANNOUNCE_VERSION_MAX_LEN`); this inner cap is belt-and-
  suspenders for any call site that reaches the parser with an
  unclamped string.

No external deps — stdlib only.  (`packaging`, `semver`, and friends
are explicitly off-limits per CLAUDE.md "no external dependencies in
protocol".)
"""

from __future__ import annotations

import string
from typing import Optional, Tuple

# Inner cap.  Longer tags are almost certainly malformed or malicious —
# a real semver string for a release we'd actually ship is under 30
# chars.  The outer serialization bound is the primary gate; this is
# defense in depth.
_MAX_LEN = 64

_PRERELEASE_ALPHABET = set(string.ascii_letters + string.digits + ".")
_NUMERIC_ALPHABET = set(string.digits)


def _parse_numeric_segment(seg: str) -> int:
    """Strict non-negative decimal integer, no leading zero except '0'."""
    if not seg:
        raise ValueError("empty numeric segment")
    if not all(ch in _NUMERIC_ALPHABET for ch in seg):
        raise ValueError(f"non-decimal char in numeric segment: {seg!r}")
    if len(seg) > 1 and seg[0] == "0":
        raise ValueError(f"leading zero in numeric segment: {seg!r}")
    return int(seg)


def parse_release_version(
    s: str,
) -> Tuple[int, int, int, Optional[str]]:
    """Parse a release-version string into (major, minor, patch, prerelease).

    Accepts strictly:
        MAJOR.MINOR.PATCH
        MAJOR.MINOR.PATCH-PRERELEASE

    See module docstring for the full rule-set.  Raises ``ValueError``
    on any parse failure.
    """
    if not isinstance(s, str):
        raise ValueError(f"version must be str, got {type(s).__name__}")
    if not s:
        raise ValueError("empty version string")
    if len(s) > _MAX_LEN:
        raise ValueError(f"version string too long: {len(s)} > {_MAX_LEN}")
    # ASCII-only is a hard rule — a cyrillic lookalike digit or a
    # null byte must not slip through.
    try:
        s.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"non-ASCII in version string: {exc}")
    if any(ch.isspace() or ch == "\x00" for ch in s):
        raise ValueError(f"whitespace or null in version string: {s!r}")

    # Split off the prerelease first — the core is always exactly
    # three dot-separated integers.
    if "-" in s:
        core, _, pre = s.partition("-")
        if not pre:
            raise ValueError("empty prerelease tag")
        if not all(ch in _PRERELEASE_ALPHABET for ch in pre):
            raise ValueError(f"invalid chars in prerelease: {pre!r}")
        # Disallow a leading/trailing dot or a double dot in the
        # prerelease — still simple, but catches obvious garbage.
        if pre.startswith(".") or pre.endswith(".") or ".." in pre:
            raise ValueError(f"malformed prerelease dot layout: {pre!r}")
    else:
        core = s
        pre = None

    # "+build" metadata is not supported — reject explicitly so a
    # signer who includes it learns fast.
    if "+" in core or (pre is not None and "+" in pre):
        raise ValueError("build metadata ('+...') not supported")

    parts = core.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"expected MAJOR.MINOR.PATCH (3 parts), got {len(parts)}: {s!r}",
        )
    major = _parse_numeric_segment(parts[0])
    minor = _parse_numeric_segment(parts[1])
    patch = _parse_numeric_segment(parts[2])
    return (major, minor, patch, pre)


def release_version_is_strictly_newer(candidate: str, current: str) -> bool:
    """True iff both parse AND ``candidate`` sorts strictly after ``current``.

    Ordering:
    - Compare (major, minor, patch) as integer tuples.
    - If those are equal, a version with no prerelease is newer than
      one with a prerelease (so ``0.2.0 > 0.2.0-rc1``).
    - If both have prereleases, compare them by lexicographic string
      order of the prerelease tag.  (Documented simplification — see
      module docstring.)

    If either side fails to parse, returns False.  The comparator
    never raises; that keeps every call site safe to wrap without
    try/except clutter.
    """
    try:
        cand = parse_release_version(candidate)
        curr = parse_release_version(current)
    except (ValueError, TypeError):
        return False

    cand_core = cand[:3]
    curr_core = curr[:3]
    if cand_core != curr_core:
        return cand_core > curr_core

    # Same core triple — prerelease rules decide.
    cand_pre = cand[3]
    curr_pre = curr[3]
    if cand_pre is None and curr_pre is None:
        return False  # exactly equal
    if cand_pre is None and curr_pre is not None:
        return True   # "0.2.0" > "0.2.0-rc1"
    if cand_pre is not None and curr_pre is None:
        return False  # "0.2.0-rc1" < "0.2.0"
    # Both have prereleases — lex compare (documented simplification).
    return cand_pre > curr_pre  # type: ignore[operator]
