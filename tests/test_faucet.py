"""Cold-start faucet: rate-limit logic + /faucet HTTP boundary.

The faucet exists to close the receive-to-exist cold-start gap for
fresh user wallets. These tests pin three things:

  1. The three-layer rate limit (per-/24 IP, per-address, daily cap)
     fires in the right order with the right error messages.
  2. State commits inside the lock so two concurrent requests cannot
     squeeze past the daily cap.
  3. The HTTP boundary correctly maps results into 200 / 4xx
     responses and surfaces the same error strings.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
import unittest
from unittest.mock import MagicMock

from messagechain.network.faucet import (
    FAUCET_DRIP,
    FaucetState,
    _ip_cidr_24,
    _utc_day,
)


def _mk_state(daily_cap: int = 5, drip_amount: int = FAUCET_DRIP):
    """Build a FaucetState with stub callbacks that always succeed."""
    submits: list[dict] = []

    def submit_cb(tx_dict):
        submits.append(tx_dict)
        return True, ""

    def build_cb(recipient_bytes):
        return {
            "tx_hash": ("a" * 60) + recipient_bytes[:2].hex(),
            "amount": drip_amount,
        }

    return FaucetState(
        submit_callback=submit_cb,
        build_tx_callback=build_cb,
        drip_amount=drip_amount,
        daily_cap=daily_cap,
    ), submits


class TestRateLimitOrdering(unittest.TestCase):

    def test_invalid_address_short_circuits_before_lock(self):
        st, submits = _mk_state()
        r = st.try_drip("1.2.3.4", "not-hex")
        self.assertFalse(r.ok)
        self.assertIn("hex", r.error.lower())
        self.assertEqual(submits, [],
            "must not call submit on malformed address")

    def test_wrong_length_address_rejected(self):
        st, _ = _mk_state()
        r = st.try_drip("1.2.3.4", "ab" * 16)  # 32-char hex => 16 bytes
        self.assertFalse(r.ok)
        self.assertIn("32 bytes", r.error)

    def test_first_drip_succeeds_and_decrements_counter(self):
        st, submits = _mk_state(daily_cap=10)
        r = st.try_drip("1.2.3.4", "ab" * 32)
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.amount, FAUCET_DRIP)
        self.assertEqual(r.remaining_today, 9)
        self.assertEqual(len(submits), 1)

    def test_address_re_request_blocked(self):
        st, submits = _mk_state(daily_cap=10)
        addr = "ab" * 32
        st.try_drip("1.2.3.4", addr)
        # Different IP, same address -> still blocked (one per address).
        r = st.try_drip("5.6.7.8", addr)
        self.assertFalse(r.ok)
        self.assertIn("already received", r.error)
        self.assertEqual(len(submits), 1,
            "second drip must not call submit")

    def test_per_24_ip_cooldown_blocks_neighbor_in_same_cidr(self):
        """1.2.3.4 and 1.2.3.99 share the /24, so the second drip
        is rejected with the cooldown message even though the address
        is different.
        """
        st, _ = _mk_state(daily_cap=10)
        st.try_drip("1.2.3.4", "ab" * 32)
        r = st.try_drip("1.2.3.99", "cd" * 32)
        self.assertFalse(r.ok)
        self.assertIn("network", r.error.lower())
        self.assertIn("/24", r.error)

    def test_different_24_ip_is_allowed(self):
        st, submits = _mk_state(daily_cap=10)
        st.try_drip("1.2.3.4", "ab" * 32)
        r = st.try_drip("1.2.4.4", "cd" * 32)
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(submits), 2)

    def test_daily_cap_hard_stop(self):
        st, submits = _mk_state(daily_cap=2)
        # Three drips from three different /24s + addresses; third
        # must hit the cap.
        st.try_drip("10.0.1.1", "11" * 32)
        st.try_drip("10.0.2.1", "22" * 32)
        r = st.try_drip("10.0.3.1", "33" * 32)
        self.assertFalse(r.ok)
        self.assertIn("daily faucet cap", r.error)
        self.assertEqual(r.remaining_today, 0)
        self.assertEqual(len(submits), 2,
            "submit must not run after cap is hit")

    def test_submit_failure_does_not_consume_quota(self):
        """If the chain rejects the tx, the per-IP cooldown / cap /
        per-address record must NOT be marked -- otherwise a
        transient validator hiccup permanently locks out the user.
        """
        def submit_cb(tx_dict):
            return False, "Insufficient balance"

        def build_cb(recipient_bytes):
            return {"tx_hash": "a" * 64, "amount": FAUCET_DRIP}

        st = FaucetState(
            submit_callback=submit_cb,
            build_tx_callback=build_cb,
            daily_cap=5,
        )
        addr = "ab" * 32
        r = st.try_drip("1.2.3.4", addr)
        self.assertFalse(r.ok)
        self.assertIn("Insufficient balance", r.error)
        # Same address must be retryable after the failure.
        # Replace submit with a success path and try again.
        st.submit_callback = lambda tx: (True, "")
        r2 = st.try_drip("1.2.3.4", addr)
        self.assertTrue(r2.ok,
            "after a submit failure, a retry must be allowed")
        self.assertEqual(r2.remaining_today, 4)


class TestConcurrentDrips(unittest.TestCase):

    def test_no_overshoot_under_burst(self):
        """20 simultaneous threads requesting drips on a daily_cap=5
        faucet must yield exactly 5 successes -- the lock must
        serialize check + commit so the cap is never exceeded.
        """
        st, submits = _mk_state(daily_cap=5)

        results = []
        addr_seq = [bytes([i]) * 32 for i in range(20)]
        ip_seq = [f"10.{i}.0.1" for i in range(20)]

        def worker(i):
            r = st.try_drip(ip_seq[i], addr_seq[i].hex())
            results.append(r.ok)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = sum(1 for ok in results if ok)
        self.assertEqual(successes, 5,
            f"daily cap of 5 must yield exactly 5 successes "
            f"under 20-way burst; got {successes}")
        self.assertEqual(len(submits), 5)


class TestUtcDayRollover(unittest.TestCase):

    def test_counter_resets_at_utc_day_boundary(self):
        st, _ = _mk_state(daily_cap=2)
        # Pretend we are partway through day D with the cap exhausted.
        st._day = _utc_day(time.time())
        st._drips_today = 2
        self.assertEqual(st.remaining_today(), 0)

        # Force the day forward by mutating _day; remaining_today()
        # internally reads time.time() so we cannot drive that, but
        # we can simulate a subsequent caller from "tomorrow" by
        # calling the locked reset directly.
        st._day -= 1  # make stored day "yesterday"
        self.assertEqual(st.remaining_today(), 2,
            "counter must reset when stored day != today")


class TestIpCidr24Helper(unittest.TestCase):

    def test_v4_strips_last_octet(self):
        self.assertEqual(_ip_cidr_24("1.2.3.4"), "1.2.3.0/24")
        self.assertEqual(_ip_cidr_24("10.0.0.255"), "10.0.0.0/24")

    def test_v6_falls_through_unchanged(self):
        self.assertEqual(_ip_cidr_24("2001:db8::1"), "2001:db8::1")

    def test_garbage_falls_through(self):
        self.assertEqual(_ip_cidr_24("not-an-ip"), "not-an-ip")


class TestFaucetHTTPEndpoint(unittest.TestCase):
    """Spin up a real PublicFeedServer with a stub FaucetState and
    exercise POST /faucet over HTTP. Pins the response shape, status
    codes, and rate-limit-error mapping.
    """

    @classmethod
    def setUpClass(cls):
        from messagechain.network.public_feed_server import PublicFeedServer

        cls.state, cls.submits = _mk_state(daily_cap=3)

        # PublicFeedServer needs a blockchain; stub the bare attrs
        # _serve_info and the rate-limiter touch. _serve_latest is
        # not exercised by these tests so chain.get_recent_messages
        # is not called.
        chain = MagicMock()
        chain.height = 100
        chain.chain = []

        cls.feed = PublicFeedServer(
            blockchain=chain,
            port=0,  # ephemeral port
            bind="127.0.0.1",
            faucet=cls.state,
        )
        cls.feed.start()
        # When port=0, the kernel assigns one; read it back.
        cls.port = cls.feed._httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.feed.stop()

    def _post_faucet(self, body):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(
                "POST", "/faucet",
                body=json.dumps(body),
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

    def test_post_with_valid_address_returns_200_and_tx_hash(self):
        status, body = self._post_faucet({"address": "ee" * 32})
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("ok"))
        self.assertIn("tx_hash", body)
        self.assertEqual(body["amount"], FAUCET_DRIP)

    def test_post_with_invalid_address_returns_400(self):
        status, body = self._post_faucet({"address": "nope"})
        self.assertEqual(status, 400, body)
        self.assertFalse(body["ok"])
        self.assertIn("hex", body["error"].lower())

    def test_post_with_missing_address_field(self):
        status, body = self._post_faucet({})
        # Empty string -> "must be 64 hex" -> 400
        self.assertEqual(status, 400, body)
        self.assertFalse(body["ok"])

    def test_post_with_malformed_json_returns_400(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(
                "POST", "/faucet",
                body="not-json",
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            status = resp.status
            body = json.loads(resp.read() or b"{}")
        finally:
            conn.close()
        self.assertEqual(status, 400)
        self.assertIn("invalid JSON", body["error"])


if __name__ == "__main__":
    unittest.main()
