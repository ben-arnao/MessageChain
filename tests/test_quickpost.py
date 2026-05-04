"""Quickpost: server-assisted "try it" message-send flow.

Pins three things:

  1. The PoW gate (bound to sha256(message)) accepts a correct nonce
     and rejects a wrong one.
  2. A successful try_quickpost generates a fresh keypair, drips it
     via the shared faucet rate-limit machinery, and queues the
     message for later submission.
  3. The watcher submits the queued message exactly once after the
     drip confirms (is_drip_confirmed flips True), and drops jobs
     that age past the configured TTL.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import threading
import time
import unittest
from unittest.mock import MagicMock

from messagechain.network.faucet import (
    FAUCET_DRIP,
    FaucetState,
)
from messagechain.network.quickpost import (
    QUICKPOST_MAX_PENDING_JOBS,
    QuickpostState,
    _QuickpostJob,
)


def _mk_faucet(window_cap: int = 5):
    """A FaucetState with stub callbacks suitable for quickpost tests.

    Quickpost calls FaucetState.drip_for_quickpost (no PoW), so
    `pow_difficulty` is irrelevant here — the field is unused on this
    code path.
    """
    submits: list[dict] = []

    def submit_cb(tx_dict):
        submits.append(tx_dict)
        return True, ""

    def build_cb(recipient_bytes):
        return {
            "tx_hash": "drip_" + recipient_bytes[:4].hex(),
            "amount": FAUCET_DRIP,
        }

    return FaucetState(
        submit_callback=submit_cb,
        build_tx_callback=build_cb,
        window_cap=window_cap,
        pow_difficulty=1,
    ), submits


class _StubEntity:
    """Minimal stand-in for messagechain.identity.identity.Entity.

    We only need enough surface area for QuickpostState's bookkeeping
    (entity_id) and for the test assertions to inspect what the
    submit_message_callback received.
    """
    def __init__(self, entity_id: bytes):
        self.entity_id = entity_id


def _mk_quickpost(
    *,
    window_cap: int = 5,
    pow_difficulty: int = 1,
    poll_interval_sec: int = 0,  # tick-driven from the test
    job_max_age_sec: int = 60,
):
    """Build a QuickpostState wired to a stub faucet + stub callbacks."""
    faucet, drip_submits = _mk_faucet(window_cap=window_cap)

    keygen_calls: list[bytes] = []
    submit_calls: list[tuple[bytes, str]] = []
    confirmed_ids: set[bytes] = set()
    submit_should_raise: list[Exception] = []

    def keygen():
        # Deterministic-but-unique entity_id per call so multiple
        # quickposts in one test don't collide.
        eid = bytes([len(keygen_calls)]) + bytes(31)
        keygen_calls.append(eid)
        priv = bytes([0xAA] * 32)
        return _StubEntity(eid), priv

    def submit_message(entity, message: str) -> str:
        if submit_should_raise:
            raise submit_should_raise.pop(0)
        submit_calls.append((entity.entity_id, message))
        return "msg_" + entity.entity_id[:2].hex()

    def is_drip_confirmed(entity_id: bytes) -> bool:
        return entity_id in confirmed_ids

    state = QuickpostState(
        faucet=faucet,
        keygen_callback=keygen,
        submit_message_callback=submit_message,
        is_drip_confirmed=is_drip_confirmed,
        pow_difficulty=pow_difficulty,
        poll_interval_sec=poll_interval_sec,
        job_max_age_sec=job_max_age_sec,
    )
    return state, faucet, {
        "drip_submits": drip_submits,
        "keygen_calls": keygen_calls,
        "submit_calls": submit_calls,
        "confirmed_ids": confirmed_ids,
        "submit_should_raise": submit_should_raise,
    }


def _solve_pow(seed_hex: str, message: str, difficulty: int) -> int:
    """Find a nonce satisfying sha256(seed || nonce_be_8 || sha256(msg))."""
    seed = bytes.fromhex(seed_hex)
    msg_hash = hashlib.sha256(message.encode("utf-8")).digest()
    for nonce in range(0, 1 << 32):
        digest = hashlib.sha256(seed + nonce.to_bytes(8, "big") + msg_hash).digest()
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
            return nonce
    raise RuntimeError("PoW solver exhausted")


def _do_quickpost(state, client_ip: str, message: str) -> "QuickpostResult":
    """End-to-end happy-path helper: issue → solve → try_quickpost."""
    ok, err, payload = state.issue_challenge()
    assert ok, err
    nonce = _solve_pow(payload["seed"], message, payload["difficulty"])
    return state.try_quickpost(
        client_ip, message,
        challenge_seed_hex=payload["seed"], nonce=nonce,
    )


class TestPowGate(unittest.TestCase):

    def test_correct_pow_succeeds_and_queues_job(self):
        state, faucet, env = _mk_quickpost()
        result = _do_quickpost(state, "1.2.3.4", "hello chain")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(len(result.entity_id_hex), 64)
        self.assertEqual(len(result.private_key_hex), 64)
        self.assertEqual(result.drip_tx_hash[:5], "drip_")
        self.assertEqual(state.pending_job_count(), 1)
        # Drip went through the faucet path.
        self.assertEqual(len(env["drip_submits"]), 1)

    def test_wrong_nonce_rejected_does_not_keygen_or_drip(self):
        state, faucet, env = _mk_quickpost(pow_difficulty=8)
        ok, err, payload = state.issue_challenge()
        self.assertTrue(ok)
        # Find a nonce that DOES NOT satisfy 8 leading zero bits.
        seed = bytes.fromhex(payload["seed"])
        msg_hash = hashlib.sha256(b"hi").digest()
        bad_nonce = None
        for n in range(256):
            digest = hashlib.sha256(seed + n.to_bytes(8, "big") + msg_hash).digest()
            if digest[0] != 0:  # at least one leading-byte bit set
                bad_nonce = n
                break
        self.assertIsNotNone(bad_nonce)
        result = state.try_quickpost(
            "1.2.3.4", "hi",
            challenge_seed_hex=payload["seed"], nonce=bad_nonce,
        )
        self.assertFalse(result.ok)
        self.assertIn("proof-of-work", result.error)
        self.assertEqual(env["keygen_calls"], [])
        self.assertEqual(len(env["drip_submits"]), 0)

    def test_replayed_challenge_rejected(self):
        state, faucet, env = _mk_quickpost()
        ok, err, payload = state.issue_challenge()
        self.assertTrue(ok)
        nonce = _solve_pow(payload["seed"], "msg", payload["difficulty"])
        r1 = state.try_quickpost(
            "1.2.3.4", "msg",
            challenge_seed_hex=payload["seed"], nonce=nonce,
        )
        self.assertTrue(r1.ok, r1.error)
        # Replay with same seed: challenge consumed, should fail.
        r2 = state.try_quickpost(
            "1.2.4.4", "msg",
            challenge_seed_hex=payload["seed"], nonce=nonce,
        )
        self.assertFalse(r2.ok)
        self.assertIn("challenge unknown", r2.error)

    def test_pow_bound_to_message_so_substituted_message_rejected(self):
        state, faucet, env = _mk_quickpost(pow_difficulty=8)
        ok, err, payload = state.issue_challenge()
        self.assertTrue(ok)
        # Solve PoW for "original" — the nonce is bound to that message.
        nonce = _solve_pow(payload["seed"], "original", payload["difficulty"])
        # Substitute a different message; PoW should no longer verify.
        result = state.try_quickpost(
            "1.2.3.4", "tampered",
            challenge_seed_hex=payload["seed"], nonce=nonce,
        )
        self.assertFalse(result.ok)
        self.assertIn("proof-of-work", result.error)


class TestMessageInputValidation(unittest.TestCase):

    def test_empty_message_rejected(self):
        state, _, env = _mk_quickpost()
        ok, _, payload = state.issue_challenge()
        result = state.try_quickpost(
            "1.2.3.4", "   ",
            challenge_seed_hex=payload["seed"], nonce=0,
        )
        self.assertFalse(result.ok)
        self.assertIn("empty", result.error)
        # Failure path BEFORE PoW must not consume the challenge.
        with state._lock:
            self.assertEqual(len(state._pending_challenges), 1)

    def test_oversize_message_rejected(self):
        state, _, env = _mk_quickpost()
        ok, _, payload = state.issue_challenge()
        big = "x" * 2048
        result = state.try_quickpost(
            "1.2.3.4", big,
            challenge_seed_hex=payload["seed"], nonce=0,
        )
        self.assertFalse(result.ok)
        self.assertIn("max", result.error)


class TestRateLimitSharedWithFaucet(unittest.TestCase):
    """Quickpost drips count against the SAME per-window cap as
    /faucet drips, since they share the operator wallet.
    """

    def test_quickpost_drip_decrements_faucet_window(self):
        state, faucet, env = _mk_quickpost(window_cap=2)
        self.assertEqual(faucet.remaining_window(), 2)
        r = _do_quickpost(state, "1.2.3.4", "msg one")
        self.assertTrue(r.ok, r.error)
        self.assertEqual(faucet.remaining_window(), 1)

    def test_quickpost_blocked_by_faucet_cap_exhausted(self):
        state, faucet, env = _mk_quickpost(window_cap=1)
        r1 = _do_quickpost(state, "1.2.3.4", "first")
        self.assertTrue(r1.ok)
        # Second quickpost from a DIFFERENT /24 — should still hit the
        # cap because window_cap=1 and the first drip used it up.
        r2 = _do_quickpost(state, "5.6.7.8", "second")
        self.assertFalse(r2.ok)
        self.assertIn("window cap", r2.error)
        self.assertEqual(r2.remaining_window, 0)
        # Failed drip should NOT have queued a job.
        self.assertEqual(state.pending_job_count(), 1,
            "first quickpost queued; second's failure leaves count at 1")

    def test_quickpost_blocked_by_per_24_ip_cooldown(self):
        state, faucet, env = _mk_quickpost(window_cap=5)
        r1 = _do_quickpost(state, "1.2.3.4", "msg one")
        self.assertTrue(r1.ok)
        # Same /24, fresh challenge / nonce — should be blocked by cooldown.
        r2 = _do_quickpost(state, "1.2.3.99", "msg two")
        self.assertFalse(r2.ok)
        self.assertIn("network", r2.error.lower())


class TestWatcherTick(unittest.TestCase):

    def test_tick_does_nothing_until_drip_confirms(self):
        state, _, env = _mk_quickpost()
        r = _do_quickpost(state, "1.2.3.4", "patient")
        self.assertTrue(r.ok)
        # First tick — drip is NOT confirmed, message must NOT submit.
        state._tick()
        self.assertEqual(env["submit_calls"], [])
        self.assertEqual(state.pending_job_count(), 1)

    def test_tick_submits_after_drip_confirms_and_dequeues(self):
        state, _, env = _mk_quickpost()
        r = _do_quickpost(state, "1.2.3.4", "ready now")
        self.assertTrue(r.ok)
        env["confirmed_ids"].add(bytes.fromhex(r.entity_id_hex))
        state._tick()
        self.assertEqual(len(env["submit_calls"]), 1)
        self.assertEqual(env["submit_calls"][0][1], "ready now")
        self.assertEqual(state.pending_job_count(), 0)

    def test_tick_retries_after_submit_failure(self):
        state, _, env = _mk_quickpost()
        r = _do_quickpost(state, "1.2.3.4", "retryable")
        self.assertTrue(r.ok)
        eid = bytes.fromhex(r.entity_id_hex)
        env["confirmed_ids"].add(eid)
        # First tick raises — job stays in queue.
        env["submit_should_raise"].append(RuntimeError("transient mempool"))
        state._tick()
        self.assertEqual(env["submit_calls"], [])
        self.assertEqual(state.pending_job_count(), 1)
        # Second tick succeeds — job is dequeued.
        state._tick()
        self.assertEqual(len(env["submit_calls"]), 1)
        self.assertEqual(state.pending_job_count(), 0)

    def test_tick_drops_stale_jobs_past_max_age(self):
        # job_max_age_sec=0 => every tick treats every job as stale.
        state, _, env = _mk_quickpost(job_max_age_sec=0)
        r = _do_quickpost(state, "1.2.3.4", "abandon-me")
        self.assertTrue(r.ok)
        self.assertEqual(state.pending_job_count(), 1)
        # Force the enqueue time backwards so the age check fires.
        with state._lock:
            for job in state._pending_jobs:
                job.enqueued_at -= 10
        state._tick()
        self.assertEqual(state.pending_job_count(), 0)
        self.assertEqual(env["submit_calls"], [],
            "stale jobs are dropped without submission")


class TestPendingJobBound(unittest.TestCase):

    def test_pending_queue_full_rejects_new_quickpost(self):
        state, _, env = _mk_quickpost(window_cap=99)
        # Pre-fill the queue at the cap by injecting fake jobs.  (We
        # can't go through _do_quickpost because the drip path would
        # consume rate-limit slots and we want to isolate the queue
        # cap.)
        with state._lock:
            for i in range(QUICKPOST_MAX_PENDING_JOBS):
                state._pending_jobs.append(_QuickpostJob(
                    entity=_StubEntity(bytes([i % 256] * 32)),
                    message="placeholder",
                    drip_tx_hash="x",
                    enqueued_at=time.time(),
                ))
        # Now try a real quickpost — the queue-cap check inside
        # try_quickpost must reject it.
        ok, err, payload = state.issue_challenge()
        self.assertTrue(ok)
        nonce = _solve_pow(payload["seed"], "blocked", payload["difficulty"])
        r = state.try_quickpost(
            "1.2.3.4", "blocked",
            challenge_seed_hex=payload["seed"], nonce=nonce,
        )
        self.assertFalse(r.ok)
        self.assertIn("pending", r.error.lower())
        # Importantly: the drip path was NOT invoked (no rate-limit slot
        # was burned for a request that we couldn't queue).
        self.assertEqual(len(env["drip_submits"]), 0)


class TestQuickpostHTTPEndpoint(unittest.TestCase):
    """Spin up a real PublicFeedServer with a stub QuickpostState and
    exercise GET /quickpost/challenge + POST /quickpost over HTTP.
    """

    @classmethod
    def setUpClass(cls):
        from messagechain.network.public_feed_server import PublicFeedServer

        cls.state, cls.faucet, cls.env = _mk_quickpost(window_cap=5)

        chain = MagicMock()
        chain.height = 100
        chain.chain = []

        cls.feed = PublicFeedServer(
            blockchain=chain,
            port=0,
            bind="127.0.0.1",
            faucet=cls.faucet,
            quickpost=cls.state,
        )
        cls.feed.start()
        cls.port = cls.feed._httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.feed.stop()

    def setUp(self):
        with self.state._lock:
            self.state._pending_challenges.clear()
            self.state._pending_jobs.clear()
        with self.faucet._lock:
            self.faucet._ip_last_drip.clear()
            self.faucet._pending_challenges.clear()
            self.faucet._drips_window = 0
            self.faucet._window = 0
        self.env["drip_submits"].clear()
        self.env["keygen_calls"].clear()
        self.env["submit_calls"].clear()
        self.env["confirmed_ids"].clear()

    def _get_challenge(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/quickpost/challenge")
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

    def _post_quickpost(self, body):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(
                "POST", "/quickpost",
                body=json.dumps(body),
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

    def test_get_challenge_returns_seed_no_address_binding(self):
        status, body = self._get_challenge()
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        self.assertIn("seed", body)
        self.assertIn("difficulty", body)
        # Quickpost challenges are address-less by design.
        self.assertNotIn("address", body)

    def test_post_with_valid_pow_returns_keypair_and_tx(self):
        cstatus, cbody = self._get_challenge()
        self.assertEqual(cstatus, 200)
        nonce = _solve_pow(cbody["seed"], "hi from http", cbody["difficulty"])
        status, body = self._post_quickpost({
            "message": "hi from http",
            "challenge_seed": cbody["seed"],
            "nonce": nonce,
        })
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("ok"))
        self.assertEqual(len(body["entity_id"]), 64)
        self.assertEqual(len(body["private_key"]), 64)
        self.assertIn("drip_tx_hash", body)

    def test_post_without_nonce_returns_400(self):
        status, body = self._post_quickpost({"message": "hi"})
        self.assertEqual(status, 400, body)
        self.assertIn("nonce", body["error"].lower())

    def test_post_with_malformed_json_returns_400(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(
                "POST", "/quickpost",
                body="not-json",
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            status = resp.status
            body = json.loads(resp.read() or b"{}")
        finally:
            conn.close()
        self.assertEqual(status, 400, body)
        self.assertFalse(body["ok"])

    def test_v1_info_advertises_quickpost_enabled(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/v1/info")
            resp = conn.getresponse()
            status = resp.status
            body = json.loads(resp.read() or b"{}")
        finally:
            conn.close()
        self.assertEqual(status, 200)
        self.assertTrue(body.get("quickpost_enabled"))


if __name__ == "__main__":
    unittest.main()
