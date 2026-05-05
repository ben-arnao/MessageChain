"""Memory-DoS hardening for FaucetState._ip_last_drip.

The dict that tracks "last drip per /24-or-IPv6-address" was unbounded:
every successful drip wrote `cidr -> timestamp` and never cleaned up.
For IPv6 the cidr key is the FULL address (the /24 collapse is IPv4-only),
so an attacker on a /48 allocation (~2**80 addresses, trivial to enumerate)
could drive unbounded growth — at ~50 bytes/entry, 10M entries is ~500 MB
plus GC stalls long enough to miss attestation slots, billing the inactivity
penalty to the honest operator.

These tests pin the fix:
  1. Expired entries (older than ip_cooldown_sec) are evicted on each drip —
     they're already behavioral no-ops, just memory.
  2. A hard ceiling FAUCET_IP_LAST_DRIP_MAX caps the dict size; oldest entries
     (by timestamp) are dropped when the ceiling is exceeded — defense against
     an attacker spinning new IPv6s faster than entries can expire.
  3. IPv6 enumeration cannot blow past the cap.
  4. Eviction never resets a still-active cooldown (the user-facing semantics
     of "you already drip'd within the cooldown window — wait" survive).
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from messagechain.network.faucet import (
    FAUCET_DRIP,
    FAUCET_IP_LAST_DRIP_MAX,
    FaucetState,
)


def _mk_state(
    window_cap: int = 1_000_000,
    drip_amount: int = FAUCET_DRIP,
    pow_difficulty: int = 1,
    ip_cooldown_sec: int = 900,
):
    submits: list[dict] = []

    def submit_cb(tx_dict):
        submits.append(tx_dict)
        return True, ""

    def build_cb(recipient_bytes):
        return {
            "tx_hash": ("a" * 60) + recipient_bytes[:2].hex(),
            "amount": drip_amount,
        }

    st = FaucetState(
        submit_callback=submit_cb,
        build_tx_callback=build_cb,
        drip_amount=drip_amount,
        window_cap=window_cap,
        pow_difficulty=pow_difficulty,
        ip_cooldown_sec=ip_cooldown_sec,
    )
    return st, submits


class TestExpiredEviction(unittest.TestCase):
    """Once `ip_cooldown_sec` has elapsed an entry is a behavioral no-op
    (a fresh drip from the same cidr would be allowed); a follow-up drip
    must remove it from the dict so it stops costing memory."""

    def test_expired_entry_is_removed_on_next_drip(self):
        st, _ = _mk_state(ip_cooldown_sec=10)
        t0 = 1_000_000.0

        with patch("messagechain.network.faucet.time.time", return_value=t0):
            r1 = st.drip_for_quickpost("1.2.3.4", b"\x11" * 32)
        self.assertTrue(r1.ok, r1.error)
        self.assertIn("1.2.3.0/24", st._ip_last_drip)

        # Jump well past the cooldown.  A drip from a totally different
        # /24 should sweep the now-stale 1.2.3.0/24 entry.
        with patch(
            "messagechain.network.faucet.time.time",
            return_value=t0 + 100.0,
        ):
            r2 = st.drip_for_quickpost("9.9.9.9", b"\x22" * 32)
        self.assertTrue(r2.ok, r2.error)

        self.assertNotIn(
            "1.2.3.0/24", st._ip_last_drip,
            "expired cooldown entry must be evicted on the next drip",
        )
        self.assertIn("9.9.9.0/24", st._ip_last_drip)

    def test_active_cooldown_entry_is_not_evicted(self):
        """Eviction must not silently let a still-cooldown'd cidr
        re-drip.  The user-facing rate-limit semantics survive."""
        st, _ = _mk_state(ip_cooldown_sec=900)
        t0 = 1_000_000.0

        with patch("messagechain.network.faucet.time.time", return_value=t0):
            r1 = st.drip_for_quickpost("1.2.3.4", b"\x11" * 32)
        self.assertTrue(r1.ok, r1.error)

        # 60s in -- cooldown is far from over.  Another drip from a
        # different /24 must not evict the live 1.2.3.0/24 entry.
        with patch(
            "messagechain.network.faucet.time.time",
            return_value=t0 + 60.0,
        ):
            r2 = st.drip_for_quickpost("9.9.9.9", b"\x22" * 32)
            self.assertTrue(r2.ok, r2.error)

            # And the cooldown must STILL fire for 1.2.3.0/24.
            r3 = st.drip_for_quickpost("1.2.3.5", b"\x33" * 32)
            self.assertFalse(r3.ok)
            self.assertIn("network", r3.error.lower())

        self.assertIn("1.2.3.0/24", st._ip_last_drip)


class TestHardCeiling(unittest.TestCase):
    """Even if attacker beats expiry by spinning fresh IPs faster than
    the cooldown elapses, the absolute size is bounded."""

    def test_size_bounded_after_drip_when_overstuffed(self):
        # Patch the cap small so the test runs fast; defense logic is
        # cap-value-agnostic.
        small_cap = 128
        with patch(
            "messagechain.network.faucet.FAUCET_IP_LAST_DRIP_MAX",
            small_cap,
        ):
            st, _ = _mk_state(ip_cooldown_sec=900)
            t0 = 1_000_000.0

            # Stuff WAY past the cap with synthetic entries (skip PoW
            # path entirely — we're testing the eviction loop, not the
            # gate).  Stagger timestamps so the "drop oldest" tiebreak
            # is determinate.
            overstuff = small_cap + 50
            for i in range(overstuff):
                st._ip_last_drip[f"synthetic-{i:08x}"] = t0 - 100.0 + i

            # All entries are "fresh" (within cooldown), so
            # expired-eviction alone won't help — only the hard-ceiling
            # pass should fire.
            with patch(
                "messagechain.network.faucet.time.time",
                return_value=t0 + 200.0,
            ):
                r = st.drip_for_quickpost("250.250.250.250", b"\x44" * 32)
            self.assertTrue(r.ok, r.error)

            self.assertLessEqual(
                len(st._ip_last_drip), small_cap,
                f"_ip_last_drip must be capped at {small_cap}; "
                f"saw {len(st._ip_last_drip)}",
            )

    def test_oldest_entries_dropped_first_under_ceiling(self):
        """The hard-ceiling pass drops by ascending timestamp, so the
        most-recent entries (the ones whose cooldown is still
        meaningful) survive."""
        small_cap = 128
        with patch(
            "messagechain.network.faucet.FAUCET_IP_LAST_DRIP_MAX",
            small_cap,
        ):
            st, _ = _mk_state(ip_cooldown_sec=900)
            t0 = 1_000_000.0

            overstuff = small_cap + 50
            for i in range(overstuff):
                st._ip_last_drip[f"victim-{i:08x}"] = t0 + i

            # Stay within cooldown so the hard-ceiling pass does the
            # work (rather than expired-eviction sweeping everything).
            with patch(
                "messagechain.network.faucet.time.time",
                return_value=t0 + overstuff + 1.0,
            ):
                r = st.drip_for_quickpost("8.8.8.8", b"\x55" * 32)
            self.assertTrue(r.ok, r.error)

            self.assertLessEqual(len(st._ip_last_drip), small_cap)

            # The newest-timestamp entries (high indices) must survive;
            # the oldest (low indices) must be gone.  The drip itself
            # also wrote a fresh entry whose timestamp is t0+overstuff+1
            # — newest of all — so it must be present too.
            self.assertIn("8.8.8.0/24", st._ip_last_drip)
            self.assertNotIn("victim-00000000", st._ip_last_drip)
            # The just-below-overstuff index should have survived (it's
            # one of the youngest entries).
            self.assertIn(
                f"victim-{(overstuff - 1):08x}", st._ip_last_drip,
            )


class TestIPv6Enumeration(unittest.TestCase):
    """The original threat: IPv6 cidr is the FULL address, so an attacker
    on a /48 (~2**80 addresses) can spin a fresh 'cidr' per request.
    The cap must hold even when every drip uses a fresh IPv6."""

    def test_ipv6_enum_within_cooldown_does_not_blow_cap(self):
        # Patch the module-level cap WAY down so the test can prove
        # the bound holds without simulating 65k+ drips (which would
        # blow the per-test 30s timeout — sorting the full dict on
        # each over-cap drip is intentionally O(N log N) per pass).
        # The defense logic doesn't care about the absolute cap value.
        small_cap = 64
        with patch(
            "messagechain.network.faucet.FAUCET_IP_LAST_DRIP_MAX",
            small_cap,
        ):
            st, _ = _mk_state(ip_cooldown_sec=900)
            t0 = 1_000_000.0

            # Simulate N drips from N distinct IPv6 addresses (so each
            # gets its own cidr key).  Stay strictly inside the cooldown
            # window so expired-eviction alone CAN'T save us — only the
            # hard ceiling can.  Use 4x the cap so the cap pass has to
            # fire repeatedly.
            n = small_cap * 4

            with patch("messagechain.network.faucet.time.time") as fake_time:
                for i in range(n):
                    fake_time.return_value = t0 + i * 0.001
                    ipv6 = f"2001:db8::{i:x}"
                    recipient = (i.to_bytes(4, "big") + b"\x00" * 28)
                    r = st.drip_for_quickpost(ipv6, recipient)
                    self.assertTrue(r.ok, r.error)

            self.assertLessEqual(
                len(st._ip_last_drip), small_cap,
                f"IPv6 enumeration drove dict to {len(st._ip_last_drip)} > "
                f"patched cap {small_cap}",
            )


class TestCooldownStillEnforced(unittest.TestCase):
    """End-to-end paranoia: the hardening must not weaken the
    user-facing cooldown rule."""

    def test_within_cooldown_rejection_survives_eviction(self):
        st, _ = _mk_state(ip_cooldown_sec=900)
        t0 = 1_000_000.0

        with patch("messagechain.network.faucet.time.time", return_value=t0):
            r1 = st.drip_for_quickpost("1.2.3.4", b"\x11" * 32)
        self.assertTrue(r1.ok)

        # Generate enough additional traffic to trigger several
        # eviction passes — but stay within the cooldown window so
        # 1.2.3.0/24's entry must still keep the user out.
        with patch("messagechain.network.faucet.time.time") as fake_time:
            for i in range(50):
                fake_time.return_value = t0 + 5.0 + i * 0.01
                # Burn cidrs we don't care about preserving.
                st.drip_for_quickpost(
                    f"2001:db8:cafe::{i:x}",
                    (i.to_bytes(4, "big") + b"\xaa" * 28),
                )

            # Same /24 as r1, still inside the 900s cooldown — must reject.
            fake_time.return_value = t0 + 60.0
            r2 = st.drip_for_quickpost("1.2.3.99", b"\x22" * 32)
            self.assertFalse(r2.ok)
            self.assertIn("network", r2.error.lower())


if __name__ == "__main__":
    unittest.main()
