"""Regression: ``/wallet/create-account`` MUST write the personal-
wallet keypair cache so a subsequent ``/wallet/login`` with the same
private key is a sub-millisecond cache hit, AND ``/wallet/login``
MUST honor an optional ``tree_height`` hint in the JSON body so a
Create Account keyfile (h=10) can sign in without falling back to
the production-height keygen.

Observed bug (2026-05-22): a user signed in with their freshly-
downloaded ``.key`` file from Create Account.  The /wallet/login
handler called ``_resolve_signing_entity(pk, args=None)`` which
fell through to ``load_or_create_personal_wallet_entity`` with no
height hint, probed the cache at h=16 + h=20 (both miss -- Create
Account had only run ``Entity.create`` without writing a cache),
then fell back to a full ``Entity.create`` at the production height
(``MERKLE_TREE_HEIGHT`` = 20) -- several minutes of keygen in pure
Python on the small validator VM, AND the resulting entity_id is
DIFFERENT from the on-chain Create Account wallet (the WOTS+ root
depends on tree height).  Net effect: sign-in hangs for minutes,
then signs the user into an empty wallet, not their funded one.

Two-part fix:

  1. Create Account routes through
     ``load_or_create_personal_wallet_entity`` (which writes the
     cache as a side-effect) instead of bare ``Entity.create``.
     Subsequent sign-ins on the same server land in the cache
     immediately.

  2. /wallet/login accepts ``tree_height`` in the JSON body.  The
     SPA parses ``# Tree height: N`` from an uploaded .key file's
     comment header and passes it; the server skips the candidate-
     height probe and goes straight to that height (cache hit ms;
     cache miss ~1s for h=10).

The SPA-side parsing of the .key comment header is a static-asset
change with no Python surface area, so this test covers (1) +
(2) by exercising the server handlers directly.  The SPA wiring
itself is covered by the page deploy + a manual smoke test.
"""

import http.client
import json
import os
import secrets
import socket
import tempfile
import time
import unittest
from unittest import mock

from messagechain.network.local_wallet_server import (
    LocalWalletServer,
    DEMO_ACCOUNT_TREE_HEIGHT,
)


def _find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_listen(port: int, deadline: float = 2.0) -> None:
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"LocalWalletServer never came up on {port}")


def _post(port: int, path: str, body: dict, extra_headers=None):
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request("POST", path, body=json.dumps(body), headers=headers)
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read() or b"{}")
    finally:
        conn.close()


class _StubChain:
    height = 1
    def get_chain_info(self): return {"height": self.height}


class _RecordingFaucet:
    """Records drips so the create-account handler can succeed without a
    real validator RPC.  Returns synthetic tx hashes."""
    def __init__(self):
        self.calls = []
    def drip_for_quickpost(self, ip, recipient_bytes):
        from messagechain.network.faucet import FaucetDripResult
        self.calls.append({"ip": ip, "recipient": bytes(recipient_bytes)})
        return FaucetDripResult(
            ok=True, tx_hash="ab" * 32, remaining_window=10,
        )


class TestCreateAccountWritesKeypairCache(unittest.TestCase):
    """Item #1 from the 2026-05-22 fix: Create Account MUST write the
    keypair_cache so the subsequent sign-in is fast.
    """

    def setUp(self):
        # Sandbox HOME so the personal-wallet cache writes land in a
        # test-private directory instead of polluting the dev's real
        # ~/.messagechain/wallet_cache/.
        self._home = tempfile.mkdtemp(prefix="mc-create-account-cache-")
        self._env = mock.patch.dict(
            os.environ, {"HOME": self._home, "USERPROFILE": self._home}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        import shutil
        shutil.rmtree(self._home, ignore_errors=True)

    def test_create_account_writes_personal_wallet_keypair_cache(self):
        """After /wallet/create-account succeeds, the personal-wallet
        cache file for the newly-minted PK at DEMO_ACCOUNT_TREE_HEIGHT
        MUST exist on disk.

        Without this, a follow-up sign-in by the same PK probes the
        cache at h=16 + h=20 (both miss), then falls back to a
        multi-minute h=20 keygen -- catastrophic UX AND wrong
        entity_id.
        """
        from messagechain.identity.keypair_cache import (
            personal_wallet_cache_path,
        )

        port = _find_free_port()
        srv = LocalWalletServer(
            blockchain=_StubChain(), port=port,
            bind="127.0.0.1", public_mode=True,
        )
        srv.faucet = _RecordingFaucet()
        srv.start()
        _wait_for_listen(port)
        self.addCleanup(srv.stop)

        status, body = _post(
            port, "/wallet/create-account", {"duration_sec": 3600},
        )
        self.assertEqual(status, 200, msg=body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["tree_height"], DEMO_ACCOUNT_TREE_HEIGHT)

        # The cache file MUST exist for the freshly-minted PK at h=10.
        pk = bytes.fromhex(body["private_key_hex"])
        cache_path = personal_wallet_cache_path(pk, DEMO_ACCOUNT_TREE_HEIGHT)
        self.assertTrue(
            os.path.exists(cache_path),
            "Create Account did not write the personal-wallet keypair "
            f"cache file at {cache_path}.  Without the write, a "
            "subsequent /wallet/login for this PK would probe the "
            "cache at h=16 + h=20 (both miss) and fall back to a "
            "multi-minute h=20 keygen -- the bug this fix addresses.",
        )

    def test_post_create_account_signin_is_a_cache_hit(self):
        """End-to-end: Create Account, then /wallet/login with the
        same PK.  The sign-in MUST resolve to a cache hit at h=10
        (the entity_id MUST match the create-account response).

        We don't time the sign-in (test runners are noisy) but we
        DO assert the entity_id matches -- a missed cache that
        fell through to an h=20 keygen would produce a DIFFERENT
        entity_id, and the assertion catches that exactly.
        """
        port = _find_free_port()
        srv = LocalWalletServer(
            blockchain=_StubChain(), port=port,
            bind="127.0.0.1", public_mode=True,
        )
        srv.faucet = _RecordingFaucet()
        srv.start()
        _wait_for_listen(port)
        self.addCleanup(srv.stop)

        st, ca = _post(port, "/wallet/create-account", {"duration_sec": 3600})
        self.assertEqual(st, 200, msg=ca)
        original_eid = ca["entity_id"]

        st, login = _post(port, "/wallet/login", {
            "value": ca["private_key_hex"],
            "duration_sec": 3600,
            # No tree_height hint -- the server should still resolve
            # to the right entity because the cache write above made
            # the h=10 probe hit.
        })
        self.assertEqual(st, 200, msg=login)
        self.assertEqual(
            login["entity_id"], original_eid,
            "/wallet/login resolved to a different entity_id than "
            "Create Account just produced -- the cache miss fell "
            "through to a different-height keygen (the exact bug "
            "the cache-write fix addresses).",
        )


class TestSigninHonorsTreeHeightHint(unittest.TestCase):
    """Item #2 from the 2026-05-22 fix: /wallet/login MUST honor an
    optional `tree_height` hint, so a paste-hex sign-in by a user who
    knows their wallet's tree height (parsed from the .key comment
    header by the SPA) skips the candidate-probe + fallback-keygen
    path entirely.
    """

    def setUp(self):
        self._home = tempfile.mkdtemp(prefix="mc-signin-hint-")
        self._env = mock.patch.dict(
            os.environ, {"HOME": self._home, "USERPROFILE": self._home}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        import shutil
        shutil.rmtree(self._home, ignore_errors=True)

    def test_login_with_tree_height_hint_picks_that_height(self):
        """A /wallet/login that passes ``tree_height: 4`` MUST build
        an entity at h=4 and return that entity_id -- proving the
        hint short-circuited the default candidate-probe path
        (which would have probed h=16 / h=20).

        h=4 is used in the test (cheap to derive at 16 leaves) but
        the production path is identical at h=10.
        """
        # First, mint an entity at h=4 directly so we know the target
        # entity_id the hint should produce.
        from messagechain.identity.identity import Entity
        pk = secrets.token_bytes(32)
        expected_entity = Entity.create(pk, tree_height=4)
        expected_eid = expected_entity.entity_id_hex

        port = _find_free_port()
        srv = LocalWalletServer(
            blockchain=_StubChain(), port=port,
            bind="127.0.0.1", public_mode=True,
        )
        srv.start()
        _wait_for_listen(port)
        self.addCleanup(srv.stop)

        st, login = _post(port, "/wallet/login", {
            "value": pk.hex(),
            "duration_sec": 3600,
            "tree_height": 4,
        })
        self.assertEqual(st, 200, msg=login)
        self.assertEqual(
            login["entity_id"], expected_eid,
            "/wallet/login ignored the tree_height hint -- it built "
            "an entity at the default candidate height instead of "
            "the requested h=4.",
        )

    def test_login_rejects_absurd_tree_height_hint(self):
        """A garbage tree_height value (negative, way out of range,
        non-int) MUST be ignored, not crash.  The handler falls back
        to the no-hint path -- which may still be slow on the
        production WALLET_DEFAULT_TREE_HEIGHT, but never blows up.
        """
        pk = secrets.token_bytes(32)
        port = _find_free_port()
        srv = LocalWalletServer(
            blockchain=_StubChain(), port=port,
            bind="127.0.0.1", public_mode=True,
        )
        srv.start()
        _wait_for_listen(port)
        self.addCleanup(srv.stop)

        # Out-of-range and garbage values must NOT cause a 5xx; they
        # should be silently ignored and the no-hint path used.  We
        # only assert non-5xx + that an entity_id comes back (the
        # specific entity_id depends on the candidate-probe height).
        for bad in (-1, 0, 1, 99, "not a number", [], {"x": 1}):
            with self.subTest(bad=bad):
                # Hint a small fallback height so the no-hint path
                # itself doesn't hang the test; we only care that the
                # garbage value is rejected without exception.
                st, body = _post(port, "/wallet/login", {
                    "value": pk.hex(),
                    "duration_sec": 60,
                    "tree_height": bad,
                    # Belt-and-suspenders: include a valid fallback
                    # via a second key.  Actually -- we WANT the
                    # garbage hint to fall through to the default
                    # probe, so don't add a second hint.  Cap test
                    # time by patching WALLET_DEFAULT_TREE_HEIGHT to
                    # something small if needed.
                })
                # Either accepted (used default probe) or rejected
                # with a 4xx for an unrelated reason.  Must not 5xx.
                self.assertLess(
                    st, 500,
                    f"tree_height={bad!r} produced HTTP {st}: {body}",
                )


class TestCacheProbeIncludesDemoHeight(unittest.TestCase):
    """Item #3 from the 2026-05-22 fix: the no-hint path's candidate-
    height probe in ``load_or_create_personal_wallet_entity`` MUST
    include h=10 so a paste-hex sign-in by someone who has previously
    Create-Account'd on this server gets a cache hit even WITHOUT the
    SPA's tree-height hint.
    """

    def setUp(self):
        self._home = tempfile.mkdtemp(prefix="mc-probe-h10-")
        self._env = mock.patch.dict(
            os.environ, {"HOME": self._home, "USERPROFILE": self._home}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        import shutil
        shutil.rmtree(self._home, ignore_errors=True)

    def test_no_hint_resolver_hits_h10_cache_when_present(self):
        """Seed an h=10 cache entry, then call the resolver with no
        height hint.  It MUST return the cached h=10 entity, not
        regenerate at h=16 / h=20.
        """
        from messagechain.identity.keypair_cache import (
            load_or_create_personal_wallet_entity,
            personal_wallet_cache_path,
        )

        pk = secrets.token_bytes(32)
        # Warm the cache at h=10.
        warmed = load_or_create_personal_wallet_entity(pk, tree_height=10)
        cache_path_h10 = personal_wallet_cache_path(pk, 10)
        self.assertTrue(os.path.exists(cache_path_h10))

        # Resolver call WITHOUT a tree_height hint MUST find the
        # h=10 cache and return the same entity.
        resolved = load_or_create_personal_wallet_entity(pk)
        self.assertEqual(
            resolved.entity_id_hex, warmed.entity_id_hex,
            "Resolver did not find the h=10 cache when called with "
            "no hint -- it built a fresh entity at a different "
            "height, producing a different entity_id.  This is the "
            "exact bug the demo-height probe addresses.",
        )


if __name__ == "__main__":
    unittest.main()
