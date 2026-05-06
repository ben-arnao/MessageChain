"""``_resolve_private_key`` personal-wallet auto-pickup gate.

Surfaced by audit r24 top-3 #2.  1.58.1 made ``_resolve_private_key``
auto-pick a keyfile from ``onboard.toml`` or ``default_keyfile()``
whenever no ``--keyfile`` was passed.  The fix correctly closes the
``sudo … stake/unstake/rotate-key`` getpass cliff -- but it applies
to **every** signing command including ``send``, ``transfer``,
``react``, ``propose``, ``vote``.  Concrete failure modes:

  * ``sudo messagechain transfer --to mc1… --amount 50`` from a
    validator host silently drains validator balance and signs with
    the validator identity.
  * ``sudo messagechain send "hi"`` increments the validator's
    WOTS+ leaf cursor for personal messages, accelerating mandatory
    key-rotation.
  * The on-chain ``entity_id`` of every casual sudo-message is the
    validator's, not a personal wallet.

The fix gates auto-pickup on a ``personal_wallet=True`` flag.  When
the auto-picked path matches the validator hot-key default
(``/etc/messagechain/keyfile`` for root), personal-wallet commands
fall through to the interactive prompt instead of silently using
the validator key.  Validator-state commands (stake/unstake/
rotate-key/etc.) are unaffected -- the 1.58.1 cliff-fix still
applies for them, because that's exactly the persona the cliff-fix
was for.

Anchored in CLAUDE.md "Honest operators are insured against
accidents" -- the fix preserves the cliff-close win where it's
correct (validator-state ops on a validator host) and refuses it
where it's a footgun (personal-wallet ops on a validator host).
"""

import os
import tempfile
import unittest
from unittest import mock

from messagechain import cli


# Realistic keyfile content: 64-hex secret matching the V2 raw-hex
# format the validator daemon writes.  Must round-trip through
# ``_load_key_from_file(accept_raw_hex=True)``.
_VALIDATOR_RAW_HEX = "ab" * 32  # 64 hex chars
_PERSONAL_CHECKSUMMED = "personal-keyfile-content"


class _StubArgs:
    """Minimal namespace mimicking argparse Namespace for the resolver."""

    def __init__(self, keyfile=None, data_dir=None):
        self.keyfile = keyfile
        self.data_dir = data_dir


class TestPersonalWalletGate(unittest.TestCase):
    """When ``personal_wallet=True`` the resolver MUST refuse to
    auto-pick the validator hot-key default and fall through to the
    interactive prompt instead.
    """

    def setUp(self):
        # Two keyfile paths matching the production layout:
        #   * validator hot-key at ``default_keyfile()``-as-root
        #   * personal keyfile at an explicit path
        self.tmpdir = tempfile.mkdtemp(prefix="mc-personal-gate-")
        self.validator_path = os.path.join(self.tmpdir, "etc-messagechain-keyfile")
        with open(self.validator_path, "w") as f:
            f.write(_VALIDATOR_RAW_HEX)
        self.personal_path = os.path.join(self.tmpdir, "personal.keyfile")
        with open(self.personal_path, "w") as f:
            f.write(_PERSONAL_CHECKSUMMED)

    def test_personal_wallet_true_refuses_validator_default_via_default_keyfile(self):
        # default_keyfile() resolves to the validator hot-key path.
        # The resolver must NOT auto-pick it under
        # personal_wallet=True; it must fall through to the prompt.
        with mock.patch.object(
            cli, "_collect_private_key", return_value="prompted-key",
        ) as collect, mock.patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            return_value={},
        ), mock.patch(
            "messagechain.runtime.onboarding.default_keyfile",
            return_value=self.validator_path,
        ):
            result = cli._resolve_private_key(
                _StubArgs(), personal_wallet=True,
            )
        self.assertEqual(result, "prompted-key")
        collect.assert_called_once()

    def test_personal_wallet_true_refuses_validator_default_via_onboard_toml(self):
        # onboard.toml's "keyfile" can also point at the validator
        # hot-key path -- the gate must catch that too.
        with mock.patch.object(
            cli, "_collect_private_key", return_value="prompted-key",
        ) as collect, mock.patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            return_value={"keyfile": self.validator_path},
        ), mock.patch(
            "messagechain.runtime.onboarding.default_keyfile",
            return_value="/nonexistent",
        ):
            result = cli._resolve_private_key(
                _StubArgs(), personal_wallet=True,
            )
        self.assertEqual(result, "prompted-key")
        collect.assert_called_once()

    def test_personal_wallet_true_accepts_explicit_keyfile_pointing_at_validator(self):
        # Explicit ``--keyfile /etc/messagechain/keyfile`` is the
        # operator's stated intent.  The gate must NOT override
        # explicit choice -- only auto-pickup is gated.
        with mock.patch.object(
            cli, "_load_key_from_file", return_value="explicit-validator-key",
        ) as loader:
            result = cli._resolve_private_key(
                _StubArgs(keyfile=self.validator_path, data_dir=self.tmpdir),
                personal_wallet=True,
            )
        self.assertEqual(result, "explicit-validator-key")
        loader.assert_called_once()

    def test_personal_wallet_true_auto_picks_personal_keyfile(self):
        # When the auto-pick resolves to a NON-validator keyfile path
        # (e.g. a per-user keyfile, NOT the root default), personal-
        # wallet commands SHOULD still auto-pick it.  The gate is
        # specific to the validator hot-key default, not blanket.
        with mock.patch.object(
            cli, "_load_key_from_file", return_value="personal-key",
        ) as loader, mock.patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            return_value={"keyfile": self.personal_path},
        ), mock.patch(
            "messagechain.runtime.onboarding.default_keyfile",
            return_value="/nonexistent",
        ):
            result = cli._resolve_private_key(
                _StubArgs(), personal_wallet=True,
            )
        self.assertEqual(result, "personal-key")
        loader.assert_called_once()

    def test_personal_wallet_false_preserves_1_58_1_cliff_close(self):
        # Validator-state commands (the 1.58.1 cliff-close persona)
        # MUST keep auto-picking the validator hot-key.  This pins
        # the regression direction: the personal-wallet gate must
        # not affect the default behavior.
        with mock.patch.object(
            cli, "_load_key_from_file", return_value="validator-hot-key",
        ) as loader, mock.patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            return_value={},
        ), mock.patch(
            "messagechain.runtime.onboarding.default_keyfile",
            return_value=self.validator_path,
        ):
            # personal_wallet=False is the default; pass explicitly
            # for clarity.
            result = cli._resolve_private_key(
                _StubArgs(), personal_wallet=False,
            )
        self.assertEqual(result, "validator-hot-key")
        loader.assert_called_once()

    def test_personal_wallet_default_unspecified_preserves_1_58_1_behavior(self):
        # Defensive: callers that pre-date the gate (or third-party
        # callers) MUST get the 1.58.1 behavior.  ``personal_wallet``
        # default must be False.
        with mock.patch.object(
            cli, "_load_key_from_file", return_value="validator-hot-key",
        ) as loader, mock.patch(
            "messagechain.runtime.onboarding.read_onboard_config",
            return_value={},
        ), mock.patch(
            "messagechain.runtime.onboarding.default_keyfile",
            return_value=self.validator_path,
        ):
            result = cli._resolve_private_key(_StubArgs())
        self.assertEqual(result, "validator-hot-key")
        loader.assert_called_once()


class TestPersonalWalletCallSitesOptIn(unittest.TestCase):
    """The five HARD-GATE personal-wallet command handlers must opt
    into ``personal_wallet=True``.  Source-level pin: a future PR
    that drops the flag from any of these sites should fail this
    test.
    """

    HARD_GATE_HANDLERS = (
        "cmd_send",
        "cmd_transfer",
        "cmd_react",
        "cmd_propose",
        "cmd_vote",
    )

    def test_hard_gate_handlers_pass_personal_wallet_true(self):
        # Read the cli.py source and confirm each hard-gate handler
        # contains ``_resolve_private_key(args, personal_wallet=True)``
        # (or equivalent kwarg form).  Source-level test rather than
        # run-handler test -- running each handler end-to-end has
        # heavy fixture cost (mempool / state / RPC), and the
        # invariant we're pinning is purely a call-site property.
        import inspect
        src = inspect.getsource(cli)
        for handler_name in self.HARD_GATE_HANDLERS:
            handler = getattr(cli, handler_name)
            handler_src = inspect.getsource(handler)
            # Must have at least one `_resolve_private_key(...)` call
            # in the handler.
            self.assertIn(
                "_resolve_private_key(",
                handler_src,
                f"{handler_name} should call _resolve_private_key",
            )
            # Every such call in this handler must pass
            # ``personal_wallet=True``.  We do a coarse check: at
            # least one call site in the handler carries the flag.
            # (No hard-gate handler currently has multiple call
            # sites; if that changes, tighten the assertion.)
            self.assertIn(
                "personal_wallet=True",
                handler_src,
                f"{handler_name} must pass personal_wallet=True to "
                f"_resolve_private_key",
            )


if __name__ == "__main__":
    unittest.main()
