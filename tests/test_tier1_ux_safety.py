"""Tier-1 UX-safety fixes.

Three small, high-value fixes surfaced during the 2026-04-24 mainnet
smoke test:

1. `cmd_transfer --to` accepts raw 64-hex entity_ids with no typo
   protection.  A single mistyped character sends to an unrecoverable
   address.  Default should require the `mc1…` checksummed form; raw
   hex must be explicit opt-in.

2. `get_entity` returns `{"ok": False, "error": "Entity not found"}`
   for entities that hold a balance but have no public key registered
   yet (a consequence of the "receive-to-exist" model).  Operators
   and integrators hit this and incorrectly conclude the balance is
   lost.  Balance-only entities must return partial info with a
   `pubkey_registered: False` flag.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestTransferRawHexOptIn(unittest.TestCase):
    """cmd_transfer must refuse raw-hex --to by default.  A user who
    genuinely wants the raw form has to pass --allow-raw-hex-address,
    which also prints a clear reminder that the mc1… checksum layer
    is being bypassed."""

    def test_raw_hex_to_rejected_by_default(self):
        from messagechain import cli as cli_mod

        args = argparse.Namespace(
            to="7394379ff55463798d36d1e48511f2df1f6c3435764c03bd7797a28b0b0e746f",
            amount=100,
            fee=None,
            server="127.0.0.1:9334",
            keyfile="/dev/null",
            data_dir=None,
            allow_raw_hex_address=False,
        )
        with patch("client.rpc_call") as rpc:
            rpc.return_value = {"ok": True, "result": {}}
            with self.assertRaises(SystemExit) as cm:
                cli_mod.cmd_transfer(args)
            self.assertNotEqual(
                cm.exception.code, 0,
                "cmd_transfer must sys.exit nonzero when --to is raw "
                "hex and --allow-raw-hex-address was not passed",
            )

    def test_mc1_address_accepted(self):
        """The mc1… checksummed form passes through without needing
        the opt-in flag — it carries its own typo protection."""
        from messagechain import cli as cli_mod
        from messagechain.identity.address import encode_address

        eid = bytes.fromhex(
            "7394379ff55463798d36d1e48511f2df1f6c3435764c03bd7797a28b0b0e746f"
        )
        checksummed = encode_address(eid)

        args = argparse.Namespace(
            to=checksummed,
            amount=100,
            fee=None,
            server="127.0.0.1:9334",
            keyfile="/dev/null",
            data_dir=None,
            allow_raw_hex_address=False,
        )

        # Short-circuit beyond the address-format check by raising a
        # tagged exception from rpc_call — we only care that the raw-
        # hex gate didn't fire.
        class SentinelExit(Exception):
            pass

        with patch("client.rpc_call", side_effect=SentinelExit), \
             patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32):
            with self.assertRaises((SentinelExit, SystemExit)) as cm:
                cli_mod.cmd_transfer(args)
            # Any SystemExit other than 0 with a raw-hex error would
            # mean the gate fired — we want to confirm it did NOT.
            if isinstance(cm.exception, SystemExit):
                # SystemExit(0) is acceptable (some other branch); the
                # only thing we reject is the raw-hex gate message.
                self.assertNotEqual(
                    cm.exception.code, 2,
                    "mc1… form must not trip the raw-hex safety gate",
                )

    def test_raw_hex_with_explicit_flag_proceeds(self):
        from messagechain import cli as cli_mod

        args = argparse.Namespace(
            to="7394379ff55463798d36d1e48511f2df1f6c3435764c03bd7797a28b0b0e746f",
            amount=100,
            fee=None,
            server="127.0.0.1:9334",
            keyfile="/dev/null",
            data_dir=None,
            allow_raw_hex_address=True,
        )

        class SentinelExit(Exception):
            pass

        with patch("client.rpc_call", side_effect=SentinelExit), \
             patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32):
            # With the flag, we should proceed past the gate and hit
            # the rpc_call (which raises our sentinel).  If the gate
            # fired, we'd see SystemExit(2) instead.
            with self.assertRaises((SentinelExit, SystemExit)) as cm:
                cli_mod.cmd_transfer(args)
            if isinstance(cm.exception, SystemExit):
                self.assertNotEqual(
                    cm.exception.code, 2,
                    "raw hex with --allow-raw-hex-address must NOT "
                    "trip the safety gate",
                )


class TestGetEntityReturnsBalanceOnlyInfo(unittest.TestCase):
    """Balance-only entities (received a transfer, never signed) must
    be queryable via get_entity.  Previously they returned 'Entity not
    found' which wrongly suggested the balance was lost."""

    def test_balance_only_entity_returns_partial_info(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            import server as server_mod
            s = server_mod.Server(
                p2p_port=29900, rpc_port=29901, seed_nodes=[],
                data_dir=td,
            )

            # Simulate a balance-only entity: in supply but not in
            # public_keys.
            eid = bytes.fromhex(
                "7394379ff55463798d36d1e48511f2df1f6c3435764c03bd7797a28b0b0e746f"
            )
            s.blockchain.supply.balances[eid] = 2000

            resp = s._rpc_get_entity({"entity_id": eid.hex()})
            self.assertTrue(
                resp.get("ok"),
                f"balance-only entity must be queryable; got {resp}",
            )
            r = resp["result"]
            self.assertEqual(r["balance"], 2000)
            self.assertEqual(
                r.get("pubkey_registered"), False,
                "result must flag pubkey_registered=False so callers "
                "can distinguish 'has balance but unknown key' from "
                "'fully registered'",
            )

    def test_fully_unknown_entity_still_returns_not_found(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            import server as server_mod
            s = server_mod.Server(
                p2p_port=29902, rpc_port=29903, seed_nodes=[],
                data_dir=td,
            )
            # Entity never touched by anything on-chain.
            unknown = bytes(32)
            resp = s._rpc_get_entity({"entity_id": unknown.hex()})
            self.assertFalse(
                resp.get("ok", True),
                "truly-unknown entity must still return ok=False so "
                "integrations that depended on that signal keep "
                "working",
            )

    def test_pubkey_registered_entity_has_flag_true(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            import server as server_mod
            s = server_mod.Server(
                p2p_port=29904, rpc_port=29905, seed_nodes=[],
                data_dir=td,
            )
            eid = bytes.fromhex(
                "a" * 64,
            )
            # Simulate a fully-registered entity: pubkey installed.
            s.blockchain.public_keys[eid] = b"\x00" * 32
            s.blockchain.supply.balances[eid] = 1000

            resp = s._rpc_get_entity({"entity_id": eid.hex()})
            self.assertTrue(resp.get("ok"))
            self.assertEqual(
                resp["result"].get("pubkey_registered"), True,
                "fully-registered entity must report pubkey_registered=True",
            )


if __name__ == "__main__":
    unittest.main()
