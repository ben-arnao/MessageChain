"""
cmd_unstake must accept --cold-keyfile and sign with the cold authority key.

Audit r30 #1 — every operator who follows the recommended cold-authority
hardening (`messagechain set-authority-key`) is then UNABLE to unstake
from the CLI.  cmd_unstake unconditionally signs the UnstakeTransaction
with the hot key (`_resolve_signing_entity(...).keypair`); the chain's
admission gate at Blockchain._validate_unstake_tx_in_block hard-rejects
with "Unstake must be signed by the authority (cold) key. The hot
signing key cannot authorize withdrawal."  Funds aren't lost (operator
can build a cold-signed tx by hand) but the documented retirement
path is broken on the documented hardened setup.

This test pins three properties:

  (1) create_unstake_transaction accepts an optional `signing_keypair`
      parameter.  When provided, the tx carries the validator's
      entity_id but the signature is produced by `signing_keypair`,
      not by `entity.keypair`.  Default (None) preserves the legacy
      hot-key shape exactly.

  (2) Round-trip: a tx built with `signing_keypair=cold.keypair`
      verifies against `cold.public_key` and FAILS verification
      against the hot pubkey.  Symmetric for the legacy default.

  (3) Chain admission: a cold-authority-installed entity has its
      hot-signed unstake rejected by Blockchain._validate_unstake_tx_in_block
      (existing behavior) AND its cold-signed unstake accepted (new
      path -- the only way for hardened operators to retire).
"""

import time
import unittest

from messagechain import config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.staking import (
    UnstakeTransaction,
    create_unstake_transaction,
    verify_unstake_transaction,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


_ENTITY_POOL: dict[tuple[bytes, int], Entity] = {}


def _entity(seed: bytes, height: int = 4) -> Entity:
    """Module-cached entity factory; h=4 covers worst-case sign count."""
    padded = seed + b"\x00" * (32 - len(seed))
    key = (padded, height)
    cached = _ENTITY_POOL.get(key)
    if cached is None:
        cached = Entity.create(padded, tree_height=height)
        _ENTITY_POOL[key] = cached
    cached.keypair._next_leaf = 0
    return cached


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height


class TestCreateUnstakeWithSigningKeypair(_Base):
    """create_unstake_transaction(signing_keypair=...) — the helper API
    the CLI's --cold-keyfile path threads through."""

    def test_signing_keypair_overrides_entity_keypair(self):
        hot = _entity(b"validator-hot")
        cold = _entity(b"validator-cold")

        tx = create_unstake_transaction(
            hot, amount=100, nonce=0, fee=1,
            signing_keypair=cold.keypair,
        )

        # Validator entity_id (hot's), cold-key signature.
        self.assertEqual(tx.entity_id, hot.entity_id)
        # Round-trip: verifies against cold pubkey, NOT hot pubkey.
        # current_height past the Tier 49 unified-fee-floor activation so
        # fee=1 admits (MARKET_FEE_FLOOR=1).
        self.assertTrue(verify_unstake_transaction(
            tx, cold.public_key, current_height=5000,
        ))
        self.assertFalse(verify_unstake_transaction(
            tx, hot.public_key, current_height=5000,
        ))

    def test_default_keypair_legacy_shape(self):
        """Back-compat: omitting signing_keypair preserves the legacy
        hot-key signing path byte-for-byte.  Critical for every
        non-hardened entity (no cold authority installed)."""
        hot = _entity(b"validator-hot-legacy")

        tx = create_unstake_transaction(hot, amount=50, nonce=0, fee=1)

        self.assertEqual(tx.entity_id, hot.entity_id)
        self.assertTrue(verify_unstake_transaction(
            tx, hot.public_key, current_height=5000,
        ))


class TestChainAdmissionWithColdAuthority(_Base):
    """End-to-end: a cold-authority-installed entity rejects a
    hot-signed unstake (existing behavior) and accepts a cold-signed
    unstake (new path)."""

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(
            entity.entity_id, entity.public_key, proof,
        )

    def test_cold_authority_installed_only_cold_unstake_admits(self):
        chain = Blockchain()
        # Pre-fund + register hot validator
        hot = _entity(b"hot-cold-test")
        cold = _entity(b"cold-cold-test")
        attacker_cold = _entity(b"attacker-cold-test")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 10_000_000
        chain.supply.staked[hot.entity_id] = 5_000_000

        # Promote cold authority key.  The chain stores the cold pubkey
        # under hot.entity_id.  fee=MIN_FEE keeps the SetAuthorityKey
        # admissible at chain.height=0 (pre-Tier-49 unified-floor era).
        from messagechain.config import MIN_FEE
        sak = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=MIN_FEE,
        )
        ok, err = chain.apply_set_authority_key(sak, proposer_id=hot.entity_id)
        self.assertTrue(ok, f"set-authority-key apply failed: {err}")

        # 1) Hot-signed unstake — rejected (existing chain behavior).
        hot_signed = create_unstake_transaction(
            hot, amount=100, nonce=1, fee=MIN_FEE,
        )
        ok, err = chain._validate_unstake_tx_in_block(
            hot_signed,
            pending_nonces={},
            pending_balance_spent={},
        )
        self.assertFalse(
            ok,
            "Hot-signed unstake must be rejected when cold authority "
            "is installed (existing chain rule).",
        )
        self.assertIn("(cold) key", err)

        # 2) Wrong-cold-key unstake — rejected.  Catches the case where
        #    operator points --cold-keyfile at the wrong file.
        wrong_signed = create_unstake_transaction(
            hot, amount=100, nonce=1, fee=MIN_FEE,
            signing_keypair=attacker_cold.keypair,
        )
        ok, err = chain._validate_unstake_tx_in_block(
            wrong_signed,
            pending_nonces={},
            pending_balance_spent={},
        )
        self.assertFalse(
            ok,
            "Unstake signed by a non-authority cold key must be "
            "rejected.",
        )

        # 3) Correct-cold-key unstake — accepted (new CLI path).
        cold_signed = create_unstake_transaction(
            hot, amount=100, nonce=1, fee=MIN_FEE,
            signing_keypair=cold.keypair,
        )
        ok, err = chain._validate_unstake_tx_in_block(
            cold_signed,
            pending_nonces={},
            pending_balance_spent={},
        )
        self.assertTrue(
            ok,
            f"Cold-signed unstake must be accepted by the validator. "
            f"err={err!r}",
        )


class TestCliUnstakeColdKeyfile(_Base):
    """cmd_unstake CLI behavior:

    * When the entity has a cold authority installed and --cold-keyfile
      is missing, refuse to submit (don't waste hot-keygen wait or
      send a tx the chain will reject).
    * When --cold-keyfile is provided, the helper passes the cold
      keypair through to create_unstake_transaction so the resulting
      tx is signed by the cold key.
    """

    def test_unstake_refuses_when_cold_authority_set_and_no_cold_keyfile(self):
        """Pre-flight gate: detect cold-authority install via the
        get_authority_key RPC, refuse to sign with hot.  Better UX
        than letting the chain reject the tx after the user waits
        through fee estimation + leaf-bind."""
        from unittest.mock import patch
        import argparse
        from messagechain import cli as cli_mod

        hot = _entity(b"cli-hot-refuse")
        cold = _entity(b"cli-cold-refuse")

        args = argparse.Namespace(
            amount=100,
            fee=1,
            server="127.0.0.1:9334",
            yes=True,
            keyfile="/dev/null",
            data_dir=None,
            urgency="normal",
            cold_keyfile=None,
            cold_leaf=0,
        )

        rpc_called = {"unstake": 0}

        def rpc_side(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 5000}}
            if method == "estimate_fee":
                return {"ok": True, "result": {"mempool_fee": 1}}
            if method == "get_authority_key":
                # Cold authority installed: pubkey != hot's pubkey.
                return {"ok": True, "result": {
                    "authority_key": cold.public_key.hex(),
                }}
            if method == "unstake":
                rpc_called["unstake"] += 1
                return {"ok": True, "result": {
                    "tx_hash": "00" * 32,
                    "status": "pending",
                }}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_resolve_signing_entity",
                          return_value=hot), \
             patch.object(cli_mod, "_bind_persistent_leaf_index"), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)), \
             patch("client.rpc_call", side_effect=rpc_side):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.cmd_unstake(args)

        self.assertNotEqual(
            cm.exception.code, 0,
            "cmd_unstake must exit non-zero when cold authority is "
            "installed but --cold-keyfile is not provided.",
        )
        self.assertEqual(
            rpc_called["unstake"], 0,
            "cmd_unstake must NOT broadcast an unstake the chain will "
            "reject — refuse pre-broadcast, save the operator the "
            "round-trip.",
        )

    def test_unstake_with_cold_keyfile_signs_with_cold_keypair(self):
        """Happy path: --cold-keyfile loads the cold entity, the tx
        is signed by cold.keypair (not hot.keypair), and the resulting
        tx round-trips against cold.public_key."""
        import os
        import tempfile
        from unittest.mock import patch
        import argparse
        from messagechain import cli as cli_mod

        hot = _entity(b"cli-hot-happy")
        cold_seed = b"cli-cold-happy" + b"\x00" * 18  # 32 bytes
        cold = _entity(cold_seed)

        # Write the cold seed to a tempfile (CLI loads it via Entity.create).
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, suffix="-cold-key",
        ) as f:
            f.write(cold_seed)
            cold_path = f.name
        self.addCleanup(os.unlink, cold_path)

        args = argparse.Namespace(
            amount=100,
            fee=1,
            server="127.0.0.1:9334",
            yes=True,
            keyfile="/dev/null",
            data_dir=None,
            urgency="normal",
            cold_keyfile=cold_path,
            cold_leaf=0,
        )

        captured = {"tx": None}

        def rpc_side(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 7, "leaf_watermark": 0}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 5000}}
            if method == "estimate_fee":
                return {"ok": True, "result": {"mempool_fee": 1}}
            if method == "get_authority_key":
                return {"ok": True, "result": {
                    "authority_key": cold.public_key.hex(),
                }}
            if method == "unstake":
                # Capture the serialized tx so we can verify the signature.
                from messagechain.core.staking import UnstakeTransaction
                captured["tx"] = UnstakeTransaction.deserialize(
                    params["transaction"],
                )
                return {"ok": True, "result": {
                    "tx_hash": "00" * 32,
                    "status": "pending",
                }}
            return {"ok": True, "result": {}}

        # Reset cold leaf cursor so the test can sign deterministically.
        cold.keypair._next_leaf = 0

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_resolve_signing_entity",
                          return_value=hot), \
             patch.object(cli_mod, "_bind_persistent_leaf_index"), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)), \
             patch("client.rpc_call", side_effect=rpc_side):
            cli_mod.cmd_unstake(args)

        tx = captured["tx"]
        self.assertIsNotNone(
            tx,
            "cmd_unstake must broadcast an unstake when --cold-keyfile "
            "is provided and matches the on-chain authority key.",
        )
        self.assertEqual(tx.entity_id, hot.entity_id)
        # The signature must verify against the cold pubkey, NOT the hot.
        # current_height past the Tier 49 unified-fee-floor activation
        # so fee=1 admits (matches the CLI's fake height=5000).
        self.assertTrue(
            verify_unstake_transaction(
                tx, cold.public_key, current_height=5000,
            ),
            "cmd_unstake with --cold-keyfile must produce a tx signed "
            "by the cold key.",
        )
        self.assertFalse(
            verify_unstake_transaction(
                tx, hot.public_key, current_height=5000,
            ),
            "cmd_unstake with --cold-keyfile must NOT produce a tx "
            "signed by the hot key.",
        )


if __name__ == "__main__":
    unittest.main()
