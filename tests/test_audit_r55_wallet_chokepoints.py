"""Audit r55 #1 -- wallet UI bypasses every chokepoint the CLI unified onto.

Three sub-defects share one root abstraction: the LocalWalletServer's
``/wallet/*`` signing routes (shipped 1.82.0) take the path-of-least-
resistance where every CLI signing command has a hardened guard:

  (a) ``op_unstake`` signs with the hot key even when the entity has set
      a SetAuthorityKey to a separate cold key.  The chain rejects the
      tx (cold-key required for post-SAK unstake), but the WOTS+ leaf
      has already advanced -- a wallet-token-holder can drive
      ``POST /wallet/unstake`` in a loop and exhaust the entity's
      one-time leaves with zero on-chain progress.  Fix-the-abstraction:
      a generic ``_require_hot_signable_via_rpc`` chokepoint every cold-
      key-gated wallet op routes through BEFORE leaf reservation.

  (b) The SPA hard-codes ``fee: 100`` for every ``react()`` call against
      a post-Tier-18 floor of 1 -- 100x silent overpay on every click.
      The auto-fee chokepoint every CLI signing command unified onto
      (`_resolve_fee_with_server_floor`) was not extended to the SPA's
      reaction button.  Fix: drop the hard-code to the actual floor.

  (c) ``/wallet/me`` returns the raw 64-hex ``entity_id`` only, so the
      Identity tab displays the typo-prone hex form.  The CLI's
      ``cmd_account`` explicitly tells users to share the checksummed
      ``mc1...`` form; the SPA never had it.  Fix: surface the encoded
      address in the /wallet/me response so the UI can render the
      mainstream-asset checksummed form.

All three sub-fixes are soft (no consensus rule change, no wire-format
change, no fork).  The structural guarantee these tests pin is that
the wallet UI cannot regress back into bypassing chokepoints CLI
commands rely on.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace


def _make_dummy_entity():
    """Build a SimpleNamespace shaped like Entity for unit-test
    consumption of wallet_ops.  Real WOTS+ keygen is too slow for a
    cold-key-check unit test that never actually signs anything."""
    eid = bytes(range(32))
    pub = b"\xab" * 32
    keypair = SimpleNamespace(
        public_key=pub,
        sign=lambda _msg: b"\x00" * 64,
    )
    return SimpleNamespace(
        entity_id=eid,
        entity_id_hex=eid.hex(),
        public_key=pub,
        keypair=keypair,
    )


def _make_fake_rpc(handlers):
    def _call(method, params):
        if method not in handlers:
            raise NotImplementedError(f"fake_rpc: no handler for {method!r}")
        return handlers[method](params)
    return _call


class TestRequireHotSignableHelper(unittest.TestCase):
    """The chokepoint helper that gates every cold-key-gated wallet op.

    Three regimes, one helper:
      - no cold authority set (None) -> proceed
      - cold authority matches the loaded hot key -> proceed
      - cold authority differs from the loaded hot key -> refuse

    Transient RPC failures fall through to proceed: the cold-key check
    is a courtesy guard, not a hard prerequisite.  Stranding a user on
    a transient ``get_authority_key`` failure would be a different kind
    of footgun than the one this helper exists to close.
    """

    def test_no_cold_authority_proceeds(self):
        from messagechain.network.wallet_ops import (
            _require_hot_signable_via_rpc,
        )
        entity = _make_dummy_entity()
        rpc = _make_fake_rpc({
            "get_authority_key": lambda p: {
                "ok": True, "result": {"authority_key": None},
            },
        })
        ok, err = _require_hot_signable_via_rpc(rpc, entity, kind="unstake")
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_cold_authority_matches_hot_proceeds(self):
        from messagechain.network.wallet_ops import (
            _require_hot_signable_via_rpc,
        )
        entity = _make_dummy_entity()
        rpc = _make_fake_rpc({
            "get_authority_key": lambda p: {
                "ok": True,
                "result": {"authority_key": entity.public_key.hex()},
            },
        })
        ok, err = _require_hot_signable_via_rpc(rpc, entity, kind="unstake")
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_cold_authority_differs_refuses(self):
        from messagechain.network.wallet_ops import (
            _require_hot_signable_via_rpc,
        )
        entity = _make_dummy_entity()
        rpc = _make_fake_rpc({
            "get_authority_key": lambda p: {
                "ok": True,
                "result": {"authority_key": "ff" * 32},
            },
        })
        ok, err = _require_hot_signable_via_rpc(rpc, entity, kind="unstake")
        self.assertFalse(ok)
        # Refusal must carry an error_dict shaped like every other
        # wallet_ops failure: {"ok": False, "error": "..."} so the HTTP
        # boundary maps it through _send_op_result.
        self.assertIsInstance(err, dict)
        self.assertFalse(err["ok"])
        self.assertIn("cold", err["error"].lower())
        # Error mentions the kind so the user sees WHICH op was blocked.
        self.assertIn("unstake", err["error"].lower())

    def test_rpc_unreachable_falls_through(self):
        """A transient ``get_authority_key`` failure must not strand the
        user.  The helper is defense-in-depth, not a hard prerequisite."""
        from messagechain.network.wallet_ops import (
            _require_hot_signable_via_rpc,
        )
        entity = _make_dummy_entity()

        def _raises(method, params):
            raise ConnectionError("validator down")

        ok, err = _require_hot_signable_via_rpc(
            _raises, entity, kind="unstake",
        )
        self.assertTrue(ok)
        self.assertIsNone(err)


class TestOpUnstakeColdKeyChokepoint(unittest.TestCase):
    """The cold-key footgun closure on op_unstake.

    Behavioural pin: when the entity has a different cold authority key
    set, ``op_unstake`` returns ``{"ok": False, ...}`` and NEVER reaches
    leaf reservation or submission.  This is what closes the leaf-burn
    DoS: a wallet-token-holder calling /wallet/unstake in a loop on an
    entity with a cold authority cannot exhaust the WOTS+ tree."""

    def test_refuses_and_does_not_reserve_or_submit(self):
        from messagechain.network.wallet_ops import op_unstake

        side_effects = {"reserve_leaf_called": False, "unstake_called": False}

        def _rpc(method, params):
            if method == "get_nonce":
                return {
                    "ok": True,
                    "result": {"nonce": 0, "leaf_watermark": 0},
                }
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 0}}
            if method == "get_authority_key":
                return {
                    "ok": True,
                    "result": {"authority_key": "ff" * 32},
                }
            if method == "reserve_leaf":
                side_effects["reserve_leaf_called"] = True
                return {"ok": False, "error": "n/a"}
            if method == "unstake":
                side_effects["unstake_called"] = True
                return {"ok": True, "result": {"tx_hash": "00" * 32}}
            raise NotImplementedError(method)

        entity = _make_dummy_entity()
        result = op_unstake(
            entity, _rpc, amount=500, fee=100, data_dir=None,
        )
        self.assertFalse(result["ok"])
        self.assertIn("cold", result["error"].lower())
        # No leaf reservation, no submission attempt.  Without this
        # property the cold-key surface is a leaf-exhaustion DoS.
        self.assertFalse(side_effects["reserve_leaf_called"])
        self.assertFalse(side_effects["unstake_called"])


class TestWalletMeReturnsCheckummedAddress(unittest.TestCase):
    """/wallet/me must surface the mc1...-encoded address alongside the
    raw entity_id so the Identity tab can render the typo-protected
    form (the CLI's `cmd_account` already tells users to share that
    shape -- the wallet UI was the surface that displayed only raw hex).

    Tested at the wallet_server HTTP boundary: spin a real server, call
    /wallet/me, assert the response carries the encoded address that
    decode_address verifies back to the same entity_id."""

    def test_loaded_entity_returns_encoded_address(self):
        import http.client
        import json
        import socket
        import time
        from messagechain.network.local_wallet_server import LocalWalletServer
        from messagechain.identity.address import (
            encode_address, decode_address,
        )

        # Build a tiny stub chain object (matches _StubChain from
        # tests/test_local_wallet_server.py).
        last = SimpleNamespace(header=SimpleNamespace(timestamp=1_700_000_000.0))
        chain = SimpleNamespace(height=0, chain=[last], get_recent_messages=lambda c: [])

        eid_hex = "ab" * 32
        fake_entity = SimpleNamespace(
            entity_id_hex=eid_hex,
            entity_id=bytes.fromhex(eid_hex),
            keypair=SimpleNamespace(num_leaves=1024, _next_leaf=0),
        )

        def _rpc(method, params):
            if method == "get_entity":
                return {
                    "ok": True,
                    "result": {
                        "entity_id": p_safe(params),
                        "balance": 9001,
                        "stake": 100,
                        "pubkey_registered": True,
                    },
                }
            raise NotImplementedError(method)

        def p_safe(params):
            return params.get("entity_id", "")

        # Find free port + spin server.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        srv = LocalWalletServer(
            blockchain=chain, port=port, bind="127.0.0.1",
            entity=fake_entity, rpc_caller=_rpc,
        )
        srv.start()
        try:
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.02)

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request(
                "GET", "/wallet/me",
                headers={"Authorization": f"Bearer {srv.token}"},
            )
            resp = conn.getresponse()
            status = resp.status
            body = json.loads(resp.read())
            conn.close()
        finally:
            srv.stop()

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        # The new contract field.
        self.assertIn("address", body)
        self.assertEqual(
            body["address"], encode_address(fake_entity.entity_id),
        )
        # Round-trip: the address decodes back to the same entity_id.
        self.assertEqual(decode_address(body["address"]), fake_entity.entity_id)

    def test_read_only_mode_returns_address_none(self):
        """Shape consistency: the read-only-mode response includes
        ``address: None`` so the UI's address-rendering code can switch
        on presence without falling into a key-missing branch."""
        import http.client
        import json
        import socket
        import time
        from messagechain.network.local_wallet_server import LocalWalletServer

        last = SimpleNamespace(header=SimpleNamespace(timestamp=1_700_000_000.0))
        chain = SimpleNamespace(height=0, chain=[last], get_recent_messages=lambda c: [])

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        srv = LocalWalletServer(blockchain=chain, port=port, bind="127.0.0.1")
        srv.start()
        try:
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.02)

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request(
                "GET", "/wallet/me",
                headers={"Authorization": f"Bearer {srv.token}"},
            )
            resp = conn.getresponse()
            body = json.loads(resp.read())
            conn.close()
        finally:
            srv.stop()

        self.assertEqual(body["mode"], "read-only")
        self.assertIn("address", body)
        self.assertIsNone(body["address"])


class TestReactSpaDoesNotHardcodeFee100(unittest.TestCase):
    """Structural pin: the SPA's react() function must not hard-code a
    fee value above the protocol floor.  100 against a Tier 18+ floor
    of 1 is a 100x silent overpay every click; the regression would
    re-open if a future edit reintroduces the old fee:100 hard-code.

    The right structural shape is "the react() body does not contain
    a literal fee value greater than 1".  We grep the SPA bundle and
    assert."""

    def test_react_function_does_not_hardcode_overpay_fee(self):
        import re
        from pathlib import Path

        spa = Path(__file__).resolve().parent.parent / (
            "messagechain/static/wallet/index.html"
        )
        text = spa.read_text(encoding="utf-8")

        # Locate the react(targetHex, choice) function body.
        m = re.search(
            r"async\s+function\s+react\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}\n",
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "react() function not found in static/wallet/index.html -- "
            "if the SPA was refactored, update this structural pin.",
        )
        body = m.group("body")
        # No hard-coded fee:100 / fee :100 / fee :  100 etc.  A fee
        # value coming from a user input or an auto-fee computation is
        # fine -- the pin is on the literal 100 overpay regression.
        self.assertNotRegex(
            body, r"fee\s*:\s*100\b",
            "react() body contains a hard-coded fee:100.  Post-Tier-18 "
            "the MARKET_FEE_FLOOR is 1; 100 is a 100x silent overpay "
            "every click.  Drop to the actual floor or wire it through "
            "/wallet/estimate-fee.",
        )


if __name__ == "__main__":
    unittest.main()
