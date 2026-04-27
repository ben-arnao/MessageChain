"""Tests for the chain-height window bound on RevokeTransaction.

Audit finding (verbatim, ledger-impacting):

    Pre-signed RevokeTransaction is replayable forever -- captured
    signed hex = unilateral validator kill.

The revoke tx is intentionally nonce-free so an operator can pre-sign
it on paper / air-gapped media and broadcast later under duress.  But
without ANY chain-state element in the signed payload, that hex is a
permanent bearer broadcast token.  Anyone who later recovers a leaked
backup, photo, or USB stick -- insider, coerced operator, thief --
can broadcast the un-aged revoke and force the target validator into
the 7-day unbonding queue.  With only two operator validators on
mainnet, simultaneously firing both pre-signed revokes halts
consensus.

Fix (Tier 26): every revoke signed at or after REVOKE_TX_WINDOW_HEIGHT
commits to a chain-height window [valid_from_height, valid_to_height]
inside the signable bytes.  Outside that window the signature does
not validate and the revoke is rejected.  An operator re-signs every
quarter (~13140 blocks ≈ 90 days at 600 s/block); an attacker who
recovers a stale hex finds it past its expiry and inert.

The window IS the signed payload -- an attacker cannot extend it
without the cold key (test 6 below).

Pre-fork (height < REVOKE_TX_WINDOW_HEIGHT) the legacy un-windowed
encoding is still accepted, so historical replay is preserved.
"""

import argparse
import io
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from messagechain import cli, config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.emergency_revoke import (
    RevokeTransaction,
    create_revoke_transaction,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


# Deterministic 32-byte seed for the CLI tests (matches
# test_emergency_revoke_offline.py's _TEST_PRIVKEY convention).
_TEST_PRIVKEY = bytes(range(32))


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_signed_revoke(
    cold: Entity,
    target_id: bytes,
    fee: int = 500,
    valid_from_height: int | None = None,
    valid_to_height: int | None = None,
) -> RevokeTransaction:
    """Build + sign a revoke under the given cold key.

    Pre-fork callers leave both heights as None to match the legacy
    encoding.  Post-fork callers must pass both.
    """
    tx = RevokeTransaction(
        entity_id=target_id,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
        valid_from_height=valid_from_height,
        valid_to_height=valid_to_height,
    )
    tx.signature = cold.keypair.sign(_hash(tx._signable_data()))
    tx.tx_hash = tx._compute_hash()
    return tx


class _ChainBase(unittest.TestCase):
    """Shared chain + cold/hot setup: a ready-to-revoke validator."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _make_chain(self, *, chain_height: int):
        """Build a fresh chain pinned at a given height, with hot+cold
        registered and balance funded for a 500-token revoke fee.
        """
        chain = Blockchain()
        hot = _entity(b"validator-hot")
        cold = _entity(b"validator-cold")

        proof = hot.keypair.sign(_hash(b"register" + hot.entity_id))
        chain._install_pubkey_direct(hot.entity_id, hot.public_key, proof)
        chain.supply.balances[hot.entity_id] = 10_000
        chain.supply.staked[hot.entity_id] = 5_000

        # Promote cold key.
        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        chain.apply_set_authority_key(set_tx, proposer_id=hot.entity_id)

        # Pin the chain's reported height.  Blockchain.height is a
        # read-only property derived from len(self.chain), so we
        # extend the chain with placeholder objects (the same trick
        # other tests use, see test_audit_critical_2026_04_26_r9.py).
        # validate_revoke reads self.height + 1 as the validation
        # height, so we get exactly chain_height.
        for _ in range(chain_height - len(chain.chain)):
            chain.chain.append(object())
        return chain, hot, cold


# ─── 1. Pre-fork: legacy un-windowed revoke still accepted ────────────────
class TestPreForkLegacyRevokeAccepted(_ChainBase):

    def test_pre_fork_revoke_accepted_without_window(self):
        """At height < REVOKE_TX_WINDOW_HEIGHT, a revoke with no
        valid_from/valid_to fields validates exactly as before --
        historical replay is preserved.
        """
        # Pin fork height above the chain so we are guaranteed pre-fork.
        with patch.object(config, "REVOKE_TX_WINDOW_HEIGHT", 1_000_000):
            chain, hot, cold = self._make_chain(chain_height=100)
            self.assertLess(chain.height + 1, config.REVOKE_TX_WINDOW_HEIGHT)

            tx = _build_signed_revoke(
                cold, hot.entity_id,
                valid_from_height=None, valid_to_height=None,
            )
            ok, reason = chain.validate_revoke(tx)
            self.assertTrue(ok, reason)


# ─── 2. Post-fork: legacy un-windowed revoke is rejected ─────────────────
class TestPostForkLegacyRevokeRejected(_ChainBase):

    def test_post_fork_revoke_rejected_without_window(self):
        """At/above REVOKE_TX_WINDOW_HEIGHT, a revoke with no window
        fields fails validation.  This is the wedge that closes the
        bearer-replay attack on hexes that were signed legacy-style.
        """
        with patch.object(config, "REVOKE_TX_WINDOW_HEIGHT", 100):
            chain, hot, cold = self._make_chain(chain_height=200)
            self.assertGreaterEqual(
                chain.height + 1, config.REVOKE_TX_WINDOW_HEIGHT,
            )

            tx = _build_signed_revoke(
                cold, hot.entity_id,
                valid_from_height=None, valid_to_height=None,
            )
            ok, reason = chain.validate_revoke(tx)
            self.assertFalse(ok)
            self.assertTrue(
                "window" in reason.lower() or "expired" in reason.lower(),
                f"expected window/expiry rejection, got: {reason!r}",
            )


# ─── 3-5. Post-fork: window enforcement on validate_revoke ────────────────
class TestPostForkWindowEnforcement(_ChainBase):

    def test_post_fork_revoke_accepted_within_window(self):
        """current_height ∈ [valid_from, valid_to] -> tx validates."""
        with patch.object(config, "REVOKE_TX_WINDOW_HEIGHT", 100):
            chain, hot, cold = self._make_chain(chain_height=500)
            current = chain.height + 1  # what validate_revoke sees
            tx = _build_signed_revoke(
                cold, hot.entity_id,
                valid_from_height=current - 50,
                valid_to_height=current + 50,
            )
            ok, reason = chain.validate_revoke(tx)
            self.assertTrue(ok, reason)

    def test_post_fork_revoke_rejected_before_window(self):
        """current_height < valid_from -> tx fails (operator pre-signed
        for a window that has not started yet, e.g. typo).
        """
        with patch.object(config, "REVOKE_TX_WINDOW_HEIGHT", 100):
            chain, hot, cold = self._make_chain(chain_height=500)
            current = chain.height + 1
            tx = _build_signed_revoke(
                cold, hot.entity_id,
                valid_from_height=current + 10,
                valid_to_height=current + 100,
            )
            ok, reason = chain.validate_revoke(tx)
            self.assertFalse(ok)
            self.assertIn("window", reason.lower())

    def test_post_fork_revoke_rejected_after_window(self):
        """The headline test: current_height > valid_to -> tx fails.

        This is the bearer-replay closure.  An old leaked hex whose
        valid_to is in the past CANNOT be broadcast for effect.
        """
        with patch.object(config, "REVOKE_TX_WINDOW_HEIGHT", 100):
            chain, hot, cold = self._make_chain(chain_height=500)
            # Signed long ago: window 200..300, but chain is at 501.
            tx = _build_signed_revoke(
                cold, hot.entity_id,
                valid_from_height=200,
                valid_to_height=300,
            )
            ok, reason = chain.validate_revoke(tx)
            self.assertFalse(ok)
            self.assertTrue(
                "window" in reason.lower() or "expired" in reason.lower(),
                f"expected expiry rejection, got: {reason!r}",
            )


# ─── 6. Window is signed: attacker cannot extend it ──────────────────────
class TestSignatureCommitsToWindow(_ChainBase):

    def test_signature_does_not_validate_with_modified_window(self):
        """If an attacker captures a signed revoke and tries to extend
        valid_to to a later height (so the leaked hex becomes "fresh"
        again), the on-the-wire bytes disagree with what the signature
        was computed over -- verification fails.
        """
        with patch.object(config, "REVOKE_TX_WINDOW_HEIGHT", 100):
            chain, hot, cold = self._make_chain(chain_height=500)
            current = chain.height + 1
            # Operator originally signed for window [current-50, current+10].
            tx = _build_signed_revoke(
                cold, hot.entity_id,
                valid_from_height=current - 50,
                valid_to_height=current + 10,
            )
            # Sanity: the original tx validates inside its window.
            ok, _ = chain.validate_revoke(tx)
            self.assertTrue(ok)

            # Attacker grabs the bytes off paper, mutates valid_to_height
            # to push the expiry far into the future, but cannot re-sign.
            tampered = RevokeTransaction(
                entity_id=tx.entity_id,
                timestamp=tx.timestamp,
                fee=tx.fee,
                signature=tx.signature,
                valid_from_height=tx.valid_from_height,
                valid_to_height=tx.valid_to_height + 100_000,
            )
            ok, reason = chain.validate_revoke(tampered)
            self.assertFalse(ok)
            self.assertIn("signature", reason.lower())


# ─── 7-8. CLI surface: --print-only emits the window in the summary ──────
def _args(**kw):
    """Mirror tests/test_emergency_revoke_offline.py's _args helper."""
    ns = argparse.Namespace(
        keyfile=None,
        server="127.0.0.1:9334",
        fee=None,
        yes=False,
        print_only=False,
        tx_hex=None,
        tx_file=None,
        valid_for_blocks=None,
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _run_print_only(args):
    """Run cmd_emergency_revoke with stdout captured, no RPC, no input."""
    rpc_calls = []

    def _rpc(host, port, method, params=None):
        rpc_calls.append((method, params))
        return {"ok": False, "error": "should not reach RPC in print-only"}

    buf = io.StringIO()
    exit_code = None
    try:
        with patch(
            "builtins.input",
            side_effect=AssertionError("input should not be called"),
        ), patch(
            "messagechain.cli._resolve_private_key",
            return_value=_TEST_PRIVKEY,
        ), patch("client.rpc_call", side_effect=_rpc), redirect_stdout(buf):
            cli.cmd_emergency_revoke(args)
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0

    return exit_code, buf.getvalue(), rpc_calls


def _extract_hex_blob(stdout: str) -> str:
    for line in stdout.splitlines():
        s = line.strip()
        if len(s) > 100 and all(c in "0123456789abcdef" for c in s):
            return s
    raise AssertionError(f"no hex blob in stdout:\n{stdout}")


class TestCLIWindowSurface(unittest.TestCase):

    def test_cli_print_only_includes_window_in_human_readable_output(self):
        """Operators need to know when their stored hex expires --
        print BOTH valid_from and valid_to in the summary."""
        args = _args(entity_id="aa" * 32, print_only=True)
        exit_code, stdout, _ = _run_print_only(args)
        self.assertIn(exit_code, (None, 0))

        tx_hex = _extract_hex_blob(stdout)
        tx = RevokeTransaction.from_bytes(bytes.fromhex(tx_hex))

        # The tx must carry both window endpoints (post-fork format).
        self.assertIsNotNone(tx.valid_from_height)
        self.assertIsNotNone(tx.valid_to_height)

        # And the human summary must surface them so the operator
        # knows the re-sign deadline without parsing hex by hand.
        self.assertIn(str(tx.valid_from_height), stdout)
        self.assertIn(str(tx.valid_to_height), stdout)

    def test_cli_default_window_is_90_days(self):
        """Default --valid-for-blocks is 13140 (~90 days at 600 s/block).

        90 days is enough that an operator's quarterly key-handling
        ritual (touch the cold key, re-sign, replace the offline copy)
        keeps the kill-switch fresh, and short enough that a hex
        leaked today expires within a quarter -- the bearer-replay
        window is bounded.
        """
        args = _args(entity_id="bb" * 32, print_only=True)
        _, stdout, _ = _run_print_only(args)
        tx = RevokeTransaction.from_bytes(
            bytes.fromhex(_extract_hex_blob(stdout)),
        )
        self.assertEqual(
            tx.valid_to_height - tx.valid_from_height, 13_140,
        )


if __name__ == "__main__":
    unittest.main()
