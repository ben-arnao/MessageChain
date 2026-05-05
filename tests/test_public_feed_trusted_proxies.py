"""
Tests for the public-feed server's trusted-proxy / X-Forwarded-For
parsing.

Threat: when fronted by a reverse proxy (Caddy on the live messagechain.org
deployment), the public-feed server sees every request as originating
from the proxy's loopback IP.  Without an X-Forwarded-For (XFF) parse,
all per-IP rate-limit buckets — public-feed, faucet per-/24, quickpost,
PeerRateLimiter — collapse onto a single bucket and a single attacker
can drain the operator-funded faucet wallet at the (PoW * window-cap)
rate while crowding legitimate visitors out of the shared bucket.

Defense: a strict allowlist of trusted proxy CIDRs.  When the socket
peer falls inside a trusted CIDR, the server honors the rightmost
token of the X-Forwarded-For header as the real client IP.  When the
socket peer is NOT in the allowlist, the header is ignored entirely
(textbook OWASP rule — never trust headers from arbitrary inbound).
The default is an empty allowlist, preserving pre-fix behavior.

These are unit tests against the pure parsing helper rather than full
socket round-trips: the helper has the security-load-bearing logic and
testing it in isolation keeps the test suite fast.
"""

from __future__ import annotations

import ipaddress
import unittest

from messagechain.network.public_feed_server import (
    _resolve_client_ip,
    _parse_trusted_proxies,
)


def _cidrs(*specs: str):
    return _parse_trusted_proxies(",".join(specs)) if specs else []


class ResolveClientIPTests(unittest.TestCase):
    """The pure helper that derives the attributable client IP."""

    def test_header_from_trusted_proxy_uses_real_ip(self):
        # Caddy on loopback forwards the real visitor IP via XFF.
        trusted = _cidrs("127.0.0.1/32")
        headers = {"X-Forwarded-For": "203.0.113.7"}
        self.assertEqual(
            _resolve_client_ip("127.0.0.1", headers, trusted),
            "203.0.113.7",
        )

    def test_header_from_untrusted_source_is_ignored(self):
        # An arbitrary public peer claims a forwarded header.  The
        # allowlist does NOT cover this peer, so the header MUST be
        # ignored and the socket address used.  This is the OWASP
        # "never trust client-supplied identity headers" rule.
        trusted = _cidrs("127.0.0.1/32")
        headers = {"X-Forwarded-For": "203.0.113.7"}
        self.assertEqual(
            _resolve_client_ip("198.51.100.50", headers, trusted),
            "198.51.100.50",
        )

    def test_header_absent_falls_back_to_socket(self):
        # No XFF header at all — even a trusted proxy's request must
        # fall back to the socket peer.  (Should not crash, should not
        # treat absent-header as "unattributable".)
        trusted = _cidrs("127.0.0.1/32")
        headers = {}
        self.assertEqual(
            _resolve_client_ip("127.0.0.1", headers, trusted),
            "127.0.0.1",
        )

    def test_malformed_header_from_trusted_proxy_is_unattributable(self):
        # A trusted proxy forwards a syntactically invalid IP.  The
        # bucket key must NOT collapse to the proxy's loopback, the
        # socket peer, or some other shared identifier — those would
        # let an attacker rejoin the legitimate-traffic bucket by
        # sending garbage.  Instead the resolver returns a sentinel
        # bucket label so malformed traffic shares with itself only.
        trusted = _cidrs("127.0.0.1/32")
        for bad in ["", "   ", "not-an-ip", "999.999.999.999", "::g"]:
            with self.subTest(bad=bad):
                resolved = _resolve_client_ip(
                    "127.0.0.1", {"X-Forwarded-For": bad}, trusted,
                )
                self.assertNotEqual(resolved, "127.0.0.1")
                self.assertNotEqual(resolved, bad)
                # All malformed inputs share the SAME bucket so they
                # can't dilute each other away from the rate limit.
                self.assertEqual(
                    resolved,
                    _resolve_client_ip(
                        "127.0.0.1",
                        {"X-Forwarded-For": "different garbage"},
                        trusted,
                    ),
                )

    def test_empty_allowlist_ignores_header_even_from_loopback(self):
        # Default posture: --trusted-proxies unset means trust nobody.
        # Even a request from 127.0.0.1 with a header must ignore it.
        headers = {"X-Forwarded-For": "203.0.113.7"}
        self.assertEqual(
            _resolve_client_ip("127.0.0.1", headers, []),
            "127.0.0.1",
        )

    def test_rightmost_token_is_used(self):
        # XFF is a comma-separated list left-to-right of the chain;
        # the rightmost entry is the IP the trusted proxy directly
        # accepted the connection from (the only one we can vouch for).
        # Earlier entries are attacker-controlled and untrusted.
        trusted = _cidrs("127.0.0.1/32")
        headers = {
            "X-Forwarded-For": "10.0.0.1, 192.0.2.5, 203.0.113.7",
        }
        self.assertEqual(
            _resolve_client_ip("127.0.0.1", headers, trusted),
            "203.0.113.7",
        )

    def test_ipv6_socket_and_ipv6_cidr(self):
        # Make sure IPv6 plumbing works end-to-end: trusted CIDR is
        # IPv6, socket peer is IPv6, forwarded IP is IPv6.
        trusted = _cidrs("::1/128")
        headers = {"X-Forwarded-For": "2001:db8::42"}
        self.assertEqual(
            _resolve_client_ip("::1", headers, trusted),
            "2001:db8::42",
        )

    def test_forwarded_header_for_token(self):
        # RFC 7239 Forwarded: for=<ip>.  Optional support — when XFF
        # is missing but Forwarded is present from a trusted proxy,
        # honor the rightmost for= token.
        trusted = _cidrs("127.0.0.1/32")
        headers = {"Forwarded": 'for=203.0.113.7'}
        self.assertEqual(
            _resolve_client_ip("127.0.0.1", headers, trusted),
            "203.0.113.7",
        )


class ParseTrustedProxiesTests(unittest.TestCase):
    """The CLI string -> [ip_network] parser."""

    def test_empty_string_yields_empty_list(self):
        self.assertEqual(_parse_trusted_proxies(""), [])
        self.assertEqual(_parse_trusted_proxies(None), [])

    def test_single_cidr(self):
        result = _parse_trusted_proxies("127.0.0.1/32")
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0],
            ipaddress.ip_network("127.0.0.1/32"),
        )

    def test_comma_separated_cidrs(self):
        result = _parse_trusted_proxies("127.0.0.1/32, 10.0.0.0/8, ::1/128")
        self.assertEqual(len(result), 3)

    def test_bare_ip_treated_as_host_cidr(self):
        # Operator convenience: "127.0.0.1" without /32 should still
        # work — `ip_network("127.0.0.1")` already does this for IPv4.
        result = _parse_trusted_proxies("127.0.0.1")
        self.assertEqual(
            result[0],
            ipaddress.ip_network("127.0.0.1/32"),
        )

    def test_invalid_cidr_raises(self):
        # Garbage in --trusted-proxies should fail loudly at startup
        # rather than silently degrade to "trust nobody" (which would
        # mask a config typo on the operator).
        with self.assertRaises(ValueError):
            _parse_trusted_proxies("not-a-cidr")


if __name__ == "__main__":
    unittest.main()
