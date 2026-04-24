"""DNS-TXT seed discovery. No new pypi deps.

TXT record format (per domain, whitespace-separated pairs):
    "host=1.2.3.4 port=9333"

Unparseable entries are silently ignored; a missing resolver, unreachable
DNS server, or empty TXT set all resolve to an empty list. Callers should
merge the result with the hardcoded SEED_NODES rather than replace it.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Iterable


def _parse_txt_record(record: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    # Strip surrounding quotes that `dig` emits on TXT records.
    s = record.strip()
    if s.startswith("\"") and s.endswith("\""):
        s = s[1:-1]
    # Multiple whitespace-joined chunks per record supported.
    host: str | None = None
    port: int | None = None
    for token in s.split():
        if "=" not in token:
            continue
        k, _, v = token.partition("=")
        k = k.strip().lower()
        v = v.strip().strip("\"")
        if k == "host":
            host = v
        elif k == "port":
            try:
                port = int(v)
            except ValueError:
                port = None
        if host and port:
            out.append((host, port))
            host, port = None, None
    return out


def _query_dig(domain: str, timeout: float) -> list[str]:
    if not shutil.which("dig"):
        return []
    try:
        r = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    return lines


def discover_dns_seeds(
    domains: Iterable[str],
    timeout: float = 3.0,
    *,
    resolver=None,
) -> list[tuple[str, int]]:
    """Return a deduped list of (host, port) entries from TXT records.

    `resolver(domain, timeout) -> list[str]` is injected for tests so the
    call never hits real DNS. Default uses `dig +short`; on hosts without
    dig we return an empty list rather than raising.
    """
    found: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    fn = resolver or _query_dig
    for domain in domains:
        try:
            records = fn(domain, timeout)
        except Exception:
            continue
        if not records:
            continue
        for rec in records:
            try:
                parsed = _parse_txt_record(rec)
            except Exception:
                continue
            for entry in parsed:
                if entry in seen:
                    continue
                seen.add(entry)
                found.append(entry)
    return found
