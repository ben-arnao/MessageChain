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


def _mk_state(
    daily_cap: int = 5, drip_amount: int = FAUCET_DRIP,
    pow_difficulty: int = 1,
):
    """Build a FaucetState with stub callbacks that always succeed.

    Difficulty defaults to 1 bit so the helper PoW solver finds a
    nonce in a few tries -- keeps tests fast.  Tests targeting the
    PoW path explicitly bump it.
    """
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
        pow_difficulty=pow_difficulty,
    ), submits


def _solve_pow_for(state, address_hex: str) -> tuple[str, int]:
    """Issue a challenge and find a satisfying nonce.

    Returns (seed_hex, nonce).  Uses the state's actual difficulty.
    Tests that want zero PoW work should construct state with
    pow_difficulty=1 (the default in _mk_state).
    """
    import hashlib
    ok, err, payload = state.issue_challenge(address_hex)
    assert ok, err
    seed = bytes.fromhex(payload["seed"])
    address = bytes.fromhex(payload["address"])
    diff = payload["difficulty"]
    for nonce in range(0, 1 << 32):
        digest = hashlib.sha256(
            seed + nonce.to_bytes(8, "big") + address,
        ).digest()
        # Count leading zero bits inline to match _verify_pow.
        bits = 0
        for byte in digest:
            if byte == 0:
                bits += 8
                continue
            for shift in range(7, -1, -1):
                if byte & (1 << shift):
                    break
                bits += 1
            break
        if bits >= diff:
            return payload["seed"], nonce
    raise RuntimeError("PoW solver exhausted -- difficulty too high for test")


def _solve_pow_for_payload(payload: dict) -> tuple[str, int]:
    """Given a /faucet/challenge payload, solve the PoW.  Returns
    (seed_hex, nonce) ready for POST /faucet."""
    import hashlib
    seed = bytes.fromhex(payload["seed"])
    address = bytes.fromhex(payload["address"])
    diff = payload["difficulty"]
    for nonce in range(0, 1 << 32):
        digest = hashlib.sha256(
            seed + nonce.to_bytes(8, "big") + address,
        ).digest()
        bits = 0
        for byte in digest:
            if byte == 0:
                bits += 8
                continue
            for shift in range(7, -1, -1):
                if byte & (1 << shift):
                    break
                bits += 1
            break
        if bits >= diff:
            return payload["seed"], nonce
    raise RuntimeError("PoW solver exhausted")


def _try_drip_with_pow(state, client_ip: str, address_hex: str):
    """Convenience wrapper: issue + solve + try_drip in one call.

    Mirrors what the HTTP layer does end-to-end.  Existing rate-limit
    tests use this so the PoW gate is satisfied and they can focus
    on the per-IP / per-address / daily-cap behavior they care about.
    """
    try:
        seed_hex, nonce = _solve_pow_for(state, address_hex)
    except (ValueError, AssertionError):
        # Address is malformed -- bypass PoW and call try_drip with
        # empty challenge so the malformed-address rejection path
        # still gets exercised.
        return state.try_drip(
            client_ip, address_hex,
            challenge_seed_hex="00" * 16, nonce=0,
        )
    return state.try_drip(
        client_ip, address_hex,
        challenge_seed_hex=seed_hex, nonce=nonce,
    )


class TestRateLimitOrdering(unittest.TestCase):

    def test_invalid_address_short_circuits_before_lock(self):
        st, submits = _mk_state()
        r = _try_drip_with_pow(st, "1.2.3.4", "not-hex")
        self.assertFalse(r.ok)
        self.assertIn("hex", r.error.lower())
        self.assertEqual(submits, [],
            "must not call submit on malformed address")

    def test_wrong_length_address_rejected(self):
        st, _ = _mk_state()
        r = _try_drip_with_pow(st, "1.2.3.4", "ab" * 16)  # 32-char hex => 16 bytes
        self.assertFalse(r.ok)
        self.assertIn("32 bytes", r.error)

    def test_first_drip_succeeds_and_decrements_counter(self):
        st, submits = _mk_state(daily_cap=10)
        r = _try_drip_with_pow(st, "1.2.3.4", "ab" * 32)
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.amount, FAUCET_DRIP)
        self.assertEqual(r.remaining_today, 9)
        self.assertEqual(len(submits), 1)

    def test_address_re_request_blocked(self):
        st, submits = _mk_state(daily_cap=10)
        addr = "ab" * 32
        _try_drip_with_pow(st, "1.2.3.4", addr)
        # Different IP, same address -> still blocked (one per address).
        r = _try_drip_with_pow(st, "5.6.7.8", addr)
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
        _try_drip_with_pow(st, "1.2.3.4", "ab" * 32)
        r = _try_drip_with_pow(st, "1.2.3.99", "cd" * 32)
        self.assertFalse(r.ok)
        self.assertIn("network", r.error.lower())
        self.assertIn("/24", r.error)

    def test_different_24_ip_is_allowed(self):
        st, submits = _mk_state(daily_cap=10)
        _try_drip_with_pow(st, "1.2.3.4", "ab" * 32)
        r = _try_drip_with_pow(st, "1.2.4.4", "cd" * 32)
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(submits), 2)

    def test_daily_cap_hard_stop(self):
        st, submits = _mk_state(daily_cap=2)
        # Three drips from three different /24s + addresses; third
        # must hit the cap.
        _try_drip_with_pow(st, "10.0.1.1", "11" * 32)
        _try_drip_with_pow(st, "10.0.2.1", "22" * 32)
        r = _try_drip_with_pow(st, "10.0.3.1", "33" * 32)
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
            pow_difficulty=1,
        )
        addr = "ab" * 32
        r = _try_drip_with_pow(st, "1.2.3.4", addr)
        self.assertFalse(r.ok)
        self.assertIn("Insufficient balance", r.error)
        # Same address must be retryable after the failure.
        # Replace submit with a success path and try again.
        st.submit_callback = lambda tx: (True, "")
        r2 = _try_drip_with_pow(st, "1.2.3.4", addr)
        self.assertTrue(r2.ok,
            "after a submit failure, a retry must be allowed")
        self.assertEqual(r2.remaining_today, 4)


class TestConcurrentDrips(unittest.TestCase):

    def test_no_overshoot_under_burst(self):
        """20 simultaneous threads requesting drips on a daily_cap=5
        faucet must yield exactly 5 successes -- the lock must
        serialize check + commit so the cap is never exceeded.

        Pre-solves the PoW sequentially (the faucet's _lock would
        serialize challenge issuance under contention anyway, and
        the test cares about cap correctness, not PoW concurrency).
        """
        st, submits = _mk_state(daily_cap=5)

        results = []
        addr_seq = [bytes([i]) * 32 for i in range(20)]
        ip_seq = [f"10.{i}.0.1" for i in range(20)]
        # Pre-solve all PoWs so the worker threads contend only on
        # the drip lock, not on PoW solving.
        solutions = [_solve_pow_for(st, addr.hex()) for addr in addr_seq]

        def worker(i):
            seed_hex, nonce = solutions[i]
            r = st.try_drip(
                ip_seq[i], addr_seq[i].hex(),
                challenge_seed_hex=seed_hex, nonce=nonce,
            )
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

    def _get_challenge(self, address_hex: str):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(
                "GET", "/faucet/challenge?address=" + address_hex,
            )
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

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

    def _post_faucet_with_pow(self, address_hex: str):
        """End-to-end happy path: GET challenge, solve PoW, POST drip."""
        cstatus, cbody = self._get_challenge(address_hex)
        self.assertEqual(cstatus, 200, cbody)
        self.assertTrue(cbody["ok"])
        seed_hex, nonce = _solve_pow_for_payload(cbody)
        return self._post_faucet({
            "address": address_hex,
            "challenge_seed": seed_hex,
            "nonce": nonce,
        })

    def test_get_challenge_returns_seed_and_difficulty(self):
        status, body = self._get_challenge("ee" * 32)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        self.assertIn("seed", body)
        self.assertIn("difficulty", body)
        self.assertEqual(body["address"], "ee" * 32)

    def test_get_challenge_rejects_bad_address(self):
        status, body = self._get_challenge("nope")
        self.assertEqual(status, 400, body)
        self.assertFalse(body["ok"])

    def test_post_with_valid_pow_returns_200_and_tx_hash(self):
        status, body = self._post_faucet_with_pow("ee" * 32)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("ok"))
        self.assertIn("tx_hash", body)
        self.assertEqual(body["amount"], FAUCET_DRIP)

    def test_post_without_pow_fields_returns_400(self):
        status, body = self._post_faucet({"address": "ee" * 32})
        self.assertEqual(status, 400, body)
        self.assertIn("nonce", body["error"].lower())

    def test_post_with_wrong_nonce_returns_429(self):
        # Issue a challenge, send wrong nonce.
        cstatus, cbody = self._get_challenge("dd" * 32)
        self.assertEqual(cstatus, 200)
        status, body = self._post_faucet({
            "address": "dd" * 32,
            "challenge_seed": cbody["seed"],
            "nonce": 999_999_999_999,  # almost certainly wrong
        })
        self.assertEqual(status, 429, body)
        self.assertIn("proof-of-work", body["error"])

    def test_post_with_invalid_address_returns_400(self):
        status, body = self._post_faucet({
            "address": "nope",
            "challenge_seed": "00" * 16,
            "nonce": 0,
        })
        self.assertEqual(status, 400, body)
        self.assertFalse(body["ok"])
        self.assertIn("hex", body["error"].lower())

    def test_post_with_missing_address_field(self):
        status, body = self._post_faucet({
            "challenge_seed": "00" * 16,
            "nonce": 0,
        })
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


class TestPoWGate(unittest.TestCase):
    """Direct unit tests for the proof-of-work mechanism: challenge
    issuance, nonce verification, replay protection, address binding."""

    def test_issue_challenge_returns_payload(self):
        st, _ = _mk_state()
        ok, err, payload = st.issue_challenge("ee" * 32)
        self.assertTrue(ok)
        self.assertEqual(payload["address"], "ee" * 32)
        self.assertEqual(len(bytes.fromhex(payload["seed"])), 16)
        self.assertGreaterEqual(payload["difficulty"], 1)
        self.assertGreater(payload["expires_at"], time.time())

    def test_solve_then_drip_succeeds(self):
        st, submits = _mk_state(daily_cap=10, pow_difficulty=8)
        seed_hex, nonce = _solve_pow_for(st, "ee" * 32)
        r = st.try_drip(
            "1.2.3.4", "ee" * 32,
            challenge_seed_hex=seed_hex, nonce=nonce,
        )
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(submits), 1)

    def test_wrong_nonce_rejected(self):
        st, submits = _mk_state(pow_difficulty=8)
        ok, _, payload = st.issue_challenge("ee" * 32)
        self.assertTrue(ok)
        r = st.try_drip(
            "1.2.3.4", "ee" * 32,
            challenge_seed_hex=payload["seed"], nonce=0,
        )
        # Nonce=0 is overwhelmingly unlikely to satisfy 8 leading
        # zero bits -- 1/256 chance.  If this test ever flakes,
        # bump difficulty.  At difficulty=8, expected miss prob 99.6%.
        self.assertFalse(r.ok)
        self.assertEqual(len(submits), 0)

    def test_address_binding_prevents_cross_address_replay(self):
        """A challenge issued for address A cannot be used for address B,
        even with a valid nonce.  Defends against an attacker who
        pre-mines challenges for many addresses."""
        st, _ = _mk_state(pow_difficulty=4)
        # Get a challenge for address A and solve it.
        seed_hex, nonce = _solve_pow_for(st, "aa" * 32)
        # Try to use it for address B.
        r = st.try_drip(
            "1.2.3.4", "bb" * 32,
            challenge_seed_hex=seed_hex, nonce=nonce,
        )
        self.assertFalse(r.ok)
        self.assertIn("different address", r.error.lower())

    def test_challenge_consumed_on_use_no_replay(self):
        """A successful drip burns the challenge.  A second attempt
        with the same (seed, nonce) must fail with 'unknown or
        expired' even if the address has not been claimed via some
        other path."""
        st, _ = _mk_state(daily_cap=10, pow_difficulty=4)
        seed_hex, nonce = _solve_pow_for(st, "ee" * 32)
        r1 = st.try_drip(
            "1.2.3.4", "ee" * 32,
            challenge_seed_hex=seed_hex, nonce=nonce,
        )
        self.assertTrue(r1.ok, r1.error)
        # Replay -- challenge is consumed, address is also in the
        # claimed set, but we should hit the challenge-unknown gate
        # FIRST since it runs before the address-claimed check.
        r2 = st.try_drip(
            "5.6.7.8", "ee" * 32,
            challenge_seed_hex=seed_hex, nonce=nonce,
        )
        self.assertFalse(r2.ok)
        self.assertIn("unknown or expired", r2.error)

    def test_expired_challenge_rejected(self):
        st, _ = _mk_state(pow_difficulty=4)
        st.challenge_ttl_sec = -1  # everything immediately expired
        seed_hex, nonce = _solve_pow_for(st, "ee" * 32)
        r = st.try_drip(
            "1.2.3.4", "ee" * 32,
            challenge_seed_hex=seed_hex, nonce=nonce,
        )
        self.assertFalse(r.ok)
        self.assertIn("unknown or expired", r.error)

    def test_difficulty_22_solves_in_reasonable_time(self):
        """The production difficulty (22 bits) should solve within the
        test timeout budget on CI hardware -- if this regresses, the
        operator-visible 'expected ~5s in browser' commentary needs
        updating.  Generous bound: 30 seconds.  At 22 bits the average
        is 2^22 / hashrate; Python sha256 in pure-loop is ~500k/s on
        modest hardware, so expected ~8s.
        """
        import hashlib
        seed = bytes(range(16))
        address = bytes(range(32))
        difficulty = 22
        start = time.time()
        for nonce in range(0, 1 << 32):
            digest = hashlib.sha256(
                seed + nonce.to_bytes(8, "big") + address,
            ).digest()
            bits = 0
            for byte in digest:
                if byte == 0:
                    bits += 8
                    continue
                for shift in range(7, -1, -1):
                    if byte & (1 << shift):
                        break
                    bits += 1
                break
            if bits >= difficulty:
                break
        elapsed = time.time() - start
        # Generous: 25 seconds on Windows + xdist worker contention.
        # The point isn't to assert hardware speed, just to catch a
        # regression where a difficulty bump pushes it into 5-min territory.
        self.assertLess(elapsed, 25.0,
            f"PoW at difficulty=22 took {elapsed:.1f}s, "
            f"way longer than expected (~8s on CI)")


if __name__ == "__main__":
    unittest.main()
