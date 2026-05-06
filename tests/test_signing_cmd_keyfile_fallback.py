"""Regression: ``_resolve_private_key`` must auto-pick up a keyfile
from ``onboard.toml`` (or ``default_keyfile()``) when the operator
did not pass ``--keyfile`` explicitly.

Same defect class as the 1.57.3 ``data_dir`` auto-fallback fix
(commit 27853bf): every signing command (``send``, ``transfer``,
``stake``, ``unstake``, ``rotate-key``, ``propose``, ``vote``, …)
routes private-key resolution through ``_resolve_private_key``, which
pre-fix only honoured ``args.keyfile`` and otherwise fell straight
through to ``_collect_private_key`` — an interactive ``getpass``
prompt for the 24-word recovery phrase.

Operator path (CLAUDE.md "Run a validator"):

  $ messagechain init
       └─ writes /etc/messagechain/keyfile (raw 64-hex)
       └─ writes /etc/messagechain/onboard.toml carrying both
          ``data_dir`` AND ``keyfile``
  $ messagechain stake --amount 200
       └─ pre-fix: prompts for 24-word phrase via getpass under
          ``sudo -u messagechain``, which strips the env and is
          fragile under piped-stdin (gcloud compute ssh + sudo).
          Operators commonly hit "no recovery phrase entered" or
          worse, type the phrase into a piped session that may be
          captured by a parent shell.
       └─ post-fix: silently loads the keyfile init wrote, prints a
          one-liner naming the path so the operator sees where the
          secret was sourced.

Sender path (CLAUDE.md "first message"):

  $ messagechain generate-key      # prints a key, no file written
  $ messagechain send "hi"
       └─ pre-fix: re-prompts for the 24-word phrase on every send.
       └─ post-fix: if ``~/.messagechain/keyfile`` exists, auto-loads.
          The personal-wallet user has to opt in by writing the file
          themselves (or via ``init``); no implicit creation.

Anchored in CLAUDE.md:
  * Principle #3 (Simplicity): "Smart-defaults coverage.  Any place
    a user must pick a value the system could pick correctly is a
    defect."
  * "Honest operators are insured against accidents."  Routing the
    24-word phrase through ``sudo``-stripped piped stdin is an
    operator-error pit the system can avoid.

The fix lives in ``_resolve_private_key``: after the explicit-flag
check, fall back to (1) ``onboard.toml.keyfile`` if the file exists,
then (2) ``default_keyfile()`` if THAT file exists.  Only on neither
do we prompt.  Operator's explicit ``--keyfile`` always wins.

These tests pin the fall-through order, the personal-wallet no-op,
and the explicit-flag override.  They MUST fail on current main and
pass after the fix.
"""

from __future__ import annotations

import argparse
import os
import tempfile
import unittest

from messagechain import cli as cli_mod
from messagechain.identity.key_encoding import encode_private_key
from messagechain.runtime import onboarding


def _write_keyfile_checksummed(key_bytes: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".key")
    os.close(fd)
    with open(path, "w") as f:
        f.write(encode_private_key(key_bytes))
    return path


def _write_keyfile_raw_hex(key_bytes: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".key")
    os.close(fd)
    with open(path, "w") as f:
        f.write(key_bytes.hex())
    return path


class TestKeyfileAutoPickupFromOnboardToml(unittest.TestCase):
    """When ``args.keyfile`` is None, ``_resolve_private_key`` MUST
    consult ``onboard.toml.keyfile`` before falling through to the
    interactive prompt."""

    def setUp(self):
        self._tempfiles: list[str] = []

    def tearDown(self):
        for p in self._tempfiles:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _track(self, path: str) -> str:
        self._tempfiles.append(path)
        return path

    def test_loads_keyfile_named_by_onboard_toml(self):
        key = b"\x11" * 32
        kf = self._track(_write_keyfile_checksummed(key))
        # Pretend onboard.toml is the source of truth.
        original_read = onboarding.read_onboard_config
        try:
            onboarding.read_onboard_config = lambda path=None: {
                "keyfile": kf,
                "data_dir": "",
            }
            args = argparse.Namespace(keyfile=None, data_dir=None)
            # Sentinel: if the function falls through to the interactive
            # prompt it would call _collect_private_key — replace that
            # with a poison so the test fails loudly rather than hanging
            # on stdin.
            original_collect = cli_mod._collect_private_key
            cli_mod._collect_private_key = lambda: self.fail(
                "auto-pickup must NOT fall through to the interactive "
                "prompt when onboard.toml carries a valid keyfile",
            )
            try:
                resolved = cli_mod._resolve_private_key(args)
            finally:
                cli_mod._collect_private_key = original_collect
        finally:
            onboarding.read_onboard_config = original_read
        self.assertEqual(resolved, key)

    def test_loads_raw_hex_keyfile_when_data_dir_set(self):
        # Validator-path: onboard.toml carries both data_dir AND keyfile;
        # the daemon writes the keyfile in raw 64-hex form (no checksum
        # wrapper) so the CLI must accept that on the auto-pickup path
        # exactly as it does for explicit --keyfile.
        key = b"\x22" * 32
        kf = self._track(_write_keyfile_raw_hex(key))
        original_read = onboarding.read_onboard_config
        try:
            onboarding.read_onboard_config = lambda path=None: {
                "keyfile": kf,
                "data_dir": "/var/lib/messagechain",
            }
            args = argparse.Namespace(
                keyfile=None,
                data_dir="/var/lib/messagechain",
            )
            original_collect = cli_mod._collect_private_key
            cli_mod._collect_private_key = lambda: self.fail(
                "raw-hex keyfile auto-pickup must work when data_dir is set",
            )
            try:
                resolved = cli_mod._resolve_private_key(args)
            finally:
                cli_mod._collect_private_key = original_collect
        finally:
            onboarding.read_onboard_config = original_read
        self.assertEqual(resolved, key)

    def test_explicit_keyfile_overrides_onboard_toml(self):
        # Operator's --keyfile MUST always win.  This is the same
        # invariant test_signing_cmd_data_dir_fallback pins for data_dir.
        explicit_key = b"\x33" * 32
        explicit_kf = self._track(_write_keyfile_checksummed(explicit_key))
        cfg_key = b"\x44" * 32
        cfg_kf = self._track(_write_keyfile_checksummed(cfg_key))
        original_read = onboarding.read_onboard_config
        try:
            onboarding.read_onboard_config = lambda path=None: {
                "keyfile": cfg_kf,
                "data_dir": "",
            }
            args = argparse.Namespace(
                keyfile=explicit_kf,
                data_dir=None,
            )
            resolved = cli_mod._resolve_private_key(args)
        finally:
            onboarding.read_onboard_config = original_read
        self.assertEqual(resolved, explicit_key)

    def test_missing_onboard_keyfile_falls_through_to_default_keyfile(self):
        # onboard.toml has no keyfile entry; default_keyfile() exists →
        # auto-pickup should use it.  Sandbox HOME (conftest already
        # does this) means default_keyfile() resolves under the test
        # tempdir.
        default_path = onboarding.default_keyfile()
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
        key = b"\x55" * 32
        with open(default_path, "w") as f:
            f.write(encode_private_key(key))
        try:
            original_read = onboarding.read_onboard_config
            try:
                onboarding.read_onboard_config = lambda path=None: {
                    "keyfile": "",
                    "data_dir": "",
                }
                args = argparse.Namespace(keyfile=None, data_dir=None)
                original_collect = cli_mod._collect_private_key
                cli_mod._collect_private_key = lambda: self.fail(
                    "default_keyfile() exists; auto-pickup must use it "
                    "rather than prompting interactively",
                )
                try:
                    resolved = cli_mod._resolve_private_key(args)
                finally:
                    cli_mod._collect_private_key = original_collect
            finally:
                onboarding.read_onboard_config = original_read
        finally:
            try:
                os.unlink(default_path)
            except OSError:
                pass
        self.assertEqual(resolved, key)

    def test_no_keyfile_anywhere_falls_through_to_prompt(self):
        # Personal-wallet path with neither onboard.toml.keyfile nor
        # default_keyfile() on disk — auto-pickup is a no-op and the
        # function falls through to the interactive prompt, preserving
        # the existing behavior for users who haven't opted into a
        # keyfile.
        default_path = onboarding.default_keyfile()
        # Make sure no default keyfile exists.
        if os.path.exists(default_path):
            os.unlink(default_path)
        original_read = onboarding.read_onboard_config
        try:
            onboarding.read_onboard_config = lambda path=None: {
                "keyfile": "",
                "data_dir": "",
            }
            args = argparse.Namespace(keyfile=None, data_dir=None)
            sentinel_key = b"\x66" * 32
            original_collect = cli_mod._collect_private_key
            cli_mod._collect_private_key = lambda: sentinel_key
            try:
                resolved = cli_mod._resolve_private_key(args)
            finally:
                cli_mod._collect_private_key = original_collect
        finally:
            onboarding.read_onboard_config = original_read
        self.assertEqual(
            resolved, sentinel_key,
            "When no keyfile is auto-discoverable the function MUST "
            "fall through to the interactive prompt unchanged.",
        )

    def test_onboard_keyfile_path_pointing_at_missing_file_falls_through(self):
        # Defensive: onboard.toml names a keyfile, but the file is gone
        # (operator deleted it, manual move, etc.).  Falling through to
        # default_keyfile()-or-prompt is correct — silently loading
        # something else is a footgun.
        kf = self._track(_write_keyfile_checksummed(b"\x77" * 32))
        os.unlink(kf)  # Now the path is dangling.
        # Take care to also remove any leftover default keyfile.
        default_path = onboarding.default_keyfile()
        if os.path.exists(default_path):
            os.unlink(default_path)
        original_read = onboarding.read_onboard_config
        try:
            onboarding.read_onboard_config = lambda path=None: {
                "keyfile": kf,
                "data_dir": "",
            }
            args = argparse.Namespace(keyfile=None, data_dir=None)
            sentinel_key = b"\x88" * 32
            original_collect = cli_mod._collect_private_key
            cli_mod._collect_private_key = lambda: sentinel_key
            try:
                resolved = cli_mod._resolve_private_key(args)
            finally:
                cli_mod._collect_private_key = original_collect
        finally:
            onboarding.read_onboard_config = original_read
        self.assertEqual(resolved, sentinel_key)


if __name__ == "__main__":
    unittest.main()
