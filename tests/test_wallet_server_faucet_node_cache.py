"""Regression: ``build_wallet_server_faucet`` MUST attach a Merkle node
cache to the faucet wallet before returning.

Without the cache the faucet's per-drip ``sign()`` recomputes the entire
auth path from scratch on every call (~2^(h-1) leaf derivations).  At
the production faucet tree height (h=16) that's ~20 seconds per drip on
a modest VM.  During that 20s sign() holds the per-wallet leaf-cursor
file lock, which:

  * Hangs every subsequent ``/wallet/create-account`` request behind it
    (each one also needs the lock to record its faucet drip).
  * Stalls validator block production -- the daemon's hot wallet shares
    the same leaf-index lock file when co-resident in the same
    ``--data-dir``, so its own ``sign()`` for the next block waits 30s,
    times out, and the block-production iteration fails.

Both effects were observed in production on 2026-05-18 (chain stalled
~40 min, every Create Account request timing out at 180s) and are
prevented by attaching the cache: with it sign() drops to O(height) =
microseconds and the lock is held for that long, not for tens of
seconds.

The test asserts that the public faucet builder calls
``attach_node_cache`` with the correct data_dir + tree_height after
loading the faucet entity.  It does NOT depend on cache build / load
internals (those are covered by tests in
``tests/test_merkle_node_cache.py``); it specifically guards the wiring
that was missing before this fix.
"""

import os
import secrets
import tempfile
import unittest
from unittest import mock

from messagechain.network import local_wallet_server as lws


def _fake_rpc_with_tree_height(h: int):
    """Return an rpc_caller stand-in that reports the faucet entity at
    tree_height=h via ``get_entity``, so the builder skips the default
    of 16 (which would force a slow keygen in the test)."""
    def _call(method, params):
        if method == "get_entity":
            return {"ok": True, "result": {"tree_height": h}}
        return {"ok": False, "error": "unmocked: " + method}
    return _call


class TestWalletServerFaucetAttachesNodeCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-faucet-cache-test-")
        # Sandbox HOME so load_or_create_personal_wallet_entity's
        # ~/.messagechain/wallet_cache/ writes stay out of the dev's
        # real home directory.  conftest already does this at the
        # session level but a per-test setup is cheap insurance.
        self._home = tempfile.mkdtemp(prefix="mc-faucet-cache-home-")
        self._env_patch = mock.patch.dict(
            os.environ, {"HOME": self._home, "USERPROFILE": self._home}
        )
        self._env_patch.start()

        priv = secrets.token_bytes(32)
        self.keyfile = os.path.join(self.tmp, "faucet.key")
        with open(self.keyfile, "w") as f:
            f.write(priv.hex())

    def tearDown(self):
        self._env_patch.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self._home, ignore_errors=True)

    def test_attach_node_cache_called_with_data_dir_and_height(self):
        """When data_dir is set, the builder MUST attach a node cache.

        Tree-height pinned at h=2 (4 leaves) via the fake RPC so the
        build is trivially fast — the test isn't timing the cache, just
        verifying the call happens.
        """
        spy_calls = []

        def spy_attach(entity, private_key, tree_height, data_dir, *,
                       no_cache=False):
            spy_calls.append({
                "entity_id_hex": entity.entity_id_hex,
                "tree_height": tree_height,
                "data_dir": data_dir,
                "no_cache": no_cache,
                "had_seed": getattr(entity.keypair, "_seed", None) is not None,
            })

        # Patch on the merkle_cache module — the wallet UI faucet
        # builder does a local `from messagechain.crypto.merkle_cache
        # import attach_node_cache` per call, so this is what it sees.
        with mock.patch(
            "messagechain.crypto.merkle_cache.attach_node_cache",
            spy_attach,
        ):
            lws.build_wallet_server_faucet(
                self.keyfile,
                _fake_rpc_with_tree_height(2),
                data_dir=self.tmp,
            )

        self.assertEqual(
            len(spy_calls), 1,
            f"attach_node_cache called {len(spy_calls)}x; expected 1.  "
            "If 0: someone removed the wiring in "
            "build_wallet_server_faucet and the faucet is back on the "
            "slow auth-path recomputation, which will re-stall production.",
        )
        call = spy_calls[0]
        self.assertEqual(call["tree_height"], 2)
        self.assertEqual(call["data_dir"], self.tmp)
        self.assertFalse(call["no_cache"])
        # Defense: the entity passed in MUST have a _seed (the cache
        # builder uses it as the tree-derivation source -- the daemon's
        # _attach_merkle_node_cache makes the same assumption).
        self.assertTrue(call["had_seed"])

    def test_no_attach_when_data_dir_is_none(self):
        """When data_dir is None, no on-disk cache exists.  The builder
        still calls ``attach_node_cache`` but the helper itself early-
        returns on the None branch (its docstring contract).  Asserting
        the call happens documents the contract: the wiring is always
        present, the helper decides what to do.
        """
        spy_calls = []

        def spy_attach(entity, private_key, tree_height, data_dir, *,
                       no_cache=False):
            spy_calls.append(data_dir)

        with mock.patch(
            "messagechain.crypto.merkle_cache.attach_node_cache",
            spy_attach,
        ):
            lws.build_wallet_server_faucet(
                self.keyfile,
                _fake_rpc_with_tree_height(2),
                data_dir=None,
            )

        self.assertEqual(len(spy_calls), 1)
        self.assertIsNone(spy_calls[0])


if __name__ == "__main__":
    unittest.main()
