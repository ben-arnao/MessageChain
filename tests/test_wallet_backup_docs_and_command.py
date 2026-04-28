"""Wallet backup ergonomics: silent leaf-cursor bind + backup-wallet CLI.

The original audit closed a silent self-slash trap by printing a
"back up your leaf cursor or you'll be slashed" stderr hint on first
cursor create.  That hint has since been retired: every signing
surface now routes through ``_bind_persistent_leaf_index`` with a
chain-fetched watermark, and the keypair's monotonic
``advance_to_leaf`` recovers the high-water mark from chain state on
any fresh restore (lost laptop, OS reinstall, cursor-file deletion).
For online wallets the cursor is regenerable cache, not security-
critical user-managed state, and the README's wallet-backup section
now treats the 24-word recovery phrase as the sole backup artifact
the user is asked to record.

These tests pin down the resulting invariants:

1. ``_bind_persistent_leaf_index`` does NOT emit the old
   slash-fear stderr nag on first cursor create -- that wording has
   been retired, and reintroducing it would contradict the README.
2. Subsequent calls (file already present) are also silent.
3. ``messagechain backup-wallet`` still works for the offline-
   signing power-user workflow: tarball the keyfile + the matching
   leaves/<entity_id_hex>.idx into a single archive, fail clean if
   either input is missing, default the output path to a dated,
   entity-id-keyed name.
"""

from __future__ import annotations

import argparse
import datetime
import io
import os
import re
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# (B) CLI hint on first leaf-cursor create
# ---------------------------------------------------------------------------


class _FakeKeypair:
    """Minimal KeyPair stand-in compatible with _bind_persistent_leaf_index."""

    def __init__(self) -> None:
        self.num_leaves = 16
        self._next_leaf = 0
        self.leaf_index_path: str | None = None

    def load_leaf_index(self, path: str) -> None:
        # No on-disk state in these tests; cursor stays at 0.
        return None

    def advance_to_leaf(self, leaf_index: int) -> None:
        if int(leaf_index) > self._next_leaf:
            self._next_leaf = int(leaf_index)

    def persist_leaf_index(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write('{"next_leaf": 0}')


class TestFirstBindIsSilent(unittest.TestCase):
    """First-time bind must NOT emit the retired slash-fear stderr nag.

    The chain-watermark backstop in ``_bind_persistent_leaf_index``
    (``advance_to_leaf(chain_leaf)``) recovers the high-water mark
    from chain state on any fresh restore, so the cursor file is
    regenerable cache for online wallets.  Reintroducing the
    "back this up or you'll be slashed" message would contradict the
    seed-phrase-only backup model the README now documents.
    """

    def test_first_bind_does_not_print_slash_nag(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as fake_home:
            entity_hex = "aa" * 32
            entity = MagicMock()
            entity.entity_id_hex = entity_hex
            entity.keypair = _FakeKeypair()

            buf = io.StringIO()
            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                with redirect_stderr(buf):
                    cli_mod._bind_persistent_leaf_index(
                        entity, chain_leaf=0, data_dir=None,
                    )

            err = buf.getvalue().lower()
            self.assertNotIn("back this up", err)
            self.assertNotIn("slashing", err)
            self.assertNotIn("risk slashing", err)


class TestSubsequentBindIsSilent(unittest.TestCase):
    """Subsequent binds (file already present) must also stay silent."""

    def test_subsequent_bind_persistent_leaf_index_silent(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as fake_home:
            entity_hex = "bb" * 32

            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                e1 = MagicMock()
                e1.entity_id_hex = entity_hex
                e1.keypair = _FakeKeypair()
                first_buf = io.StringIO()
                with redirect_stderr(first_buf):
                    path = cli_mod._bind_persistent_leaf_index(
                        e1, chain_leaf=0, data_dir=None,
                    )
                # Materialize the file the way a real sign() would.
                e1.keypair.persist_leaf_index(str(path))
                self.assertTrue(os.path.exists(str(path)))

                # Second call -- file already exists, must be silent.
                e2 = MagicMock()
                e2.entity_id_hex = entity_hex
                e2.keypair = _FakeKeypair()
                second_buf = io.StringIO()
                with redirect_stderr(second_buf):
                    cli_mod._bind_persistent_leaf_index(
                        e2, chain_leaf=0, data_dir=None,
                    )

            self.assertNotIn(
                "back this up", second_buf.getvalue().lower(),
                "subsequent binds must not print any backup nag",
            )


# ---------------------------------------------------------------------------
# (C) backup-wallet CLI command
# ---------------------------------------------------------------------------


def _make_args(**kwargs) -> argparse.Namespace:
    """Build an argparse.Namespace with the fields cmd_backup_wallet reads."""
    base = dict(
        keyfile=None,
        leaves=None,
        output=None,
        entity_id=None,
        data_dir=None,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


class TestBackupWalletCreatesTarball(unittest.TestCase):
    """Happy path: keyfile + leaf-cursor exist -> command writes a
    .tar.gz at the requested --output path containing both files."""

    def test_backup_wallet_command_creates_tarball(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            keyfile = os.path.join(workdir, "keyfile")
            with open(keyfile, "w") as f:
                f.write("a" * 64)  # placeholder hex contents

            entity_hex = "cc" * 32
            leaves_dir = os.path.join(workdir, "home", ".messagechain", "leaves")
            os.makedirs(leaves_dir, exist_ok=True)
            leaves_path = os.path.join(leaves_dir, f"{entity_hex}.idx")
            with open(leaves_path, "w") as f:
                f.write('{"next_leaf": 7}')

            output = os.path.join(workdir, "wallet-backup.tar.gz")

            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                output=output,
                entity_id=entity_hex,
            )

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc = cli_mod.cmd_backup_wallet(args)

            self.assertIn(rc, (None, 0))
            self.assertTrue(os.path.exists(output))
            self.assertGreater(os.path.getsize(output), 0)

            with tarfile.open(output, "r:gz") as tf:
                names = tf.getnames()

            # Both files must be present.  Don't pin exact archive
            # paths -- just assert each input's basename is reachable.
            self.assertTrue(
                any(os.path.basename(keyfile) in n for n in names),
                f"keyfile not in archive: {names!r}",
            )
            self.assertTrue(
                any(f"{entity_hex}.idx" in n for n in names),
                f"leaf cursor not in archive: {names!r}",
            )

            # User feedback names the output path + entity + offline tip.
            out = stdout_buf.getvalue()
            self.assertIn(output, out)
            self.assertIn(entity_hex, out)
            self.assertIn("offline", out.lower())


class TestBackupWalletFailsOnMissingKeyfile(unittest.TestCase):
    """Missing keyfile -> clean error naming the missing file, no partial archive."""

    def test_backup_wallet_command_fails_on_missing_keyfile(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            keyfile = os.path.join(workdir, "does-not-exist.key")  # absent
            entity_hex = "dd" * 32
            leaves_path = os.path.join(workdir, f"{entity_hex}.idx")
            with open(leaves_path, "w") as f:
                f.write("{}")

            output = os.path.join(workdir, "out.tar.gz")
            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                output=output,
                entity_id=entity_hex,
            )

            buf = io.StringIO()
            err_buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(err_buf):
                rc = cli_mod.cmd_backup_wallet(args)

            combined = buf.getvalue() + err_buf.getvalue()
            self.assertNotEqual(rc, 0, "missing keyfile must produce non-zero exit")
            self.assertIn(keyfile, combined)
            self.assertFalse(
                os.path.exists(output),
                "no partial tarball must be produced on error",
            )


class TestBackupWalletFailsOnMissingLeaves(unittest.TestCase):
    """Missing leaf cursor -> clean error naming the missing file, no partial archive."""

    def test_backup_wallet_command_fails_on_missing_leaves(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            keyfile = os.path.join(workdir, "keyfile")
            with open(keyfile, "w") as f:
                f.write("a" * 64)

            entity_hex = "ee" * 32
            leaves_path = os.path.join(workdir, f"{entity_hex}.idx")  # absent

            output = os.path.join(workdir, "out.tar.gz")
            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                output=output,
                entity_id=entity_hex,
            )

            buf = io.StringIO()
            err_buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(err_buf):
                rc = cli_mod.cmd_backup_wallet(args)

            combined = buf.getvalue() + err_buf.getvalue()
            self.assertNotEqual(rc, 0, "missing leaves must produce non-zero exit")
            self.assertIn(leaves_path, combined)
            self.assertFalse(
                os.path.exists(output),
                "no partial tarball must be produced on error",
            )


class TestBackupWalletDefaultOutputPath(unittest.TestCase):
    """No --output -> default path is
    ``<entity_id_hex>-wallet-backup-<YYYYMMDD>.tar.gz`` in CWD."""

    def test_backup_wallet_default_output_path_format(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            keyfile = os.path.join(workdir, "keyfile")
            with open(keyfile, "w") as f:
                f.write("a" * 64)

            entity_hex = "ff" * 32
            leaves_path = os.path.join(workdir, f"{entity_hex}.idx")
            with open(leaves_path, "w") as f:
                f.write('{"next_leaf": 0}')

            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                output=None,
                entity_id=entity_hex,
            )

            cwd_before = os.getcwd()
            try:
                os.chdir(workdir)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_mod.cmd_backup_wallet(args)
            finally:
                os.chdir(cwd_before)

            self.assertIn(rc, (None, 0))

            # The file must exist in the working directory and match the
            # expected pattern.
            today = datetime.date.today().strftime("%Y%m%d")
            expected_name = f"{entity_hex}-wallet-backup-{today}.tar.gz"
            expected_path = os.path.join(workdir, expected_name)
            self.assertTrue(
                os.path.exists(expected_path),
                f"expected default-named tarball {expected_name} not found "
                f"in {workdir!r}; saw {os.listdir(workdir)!r}",
            )

            # Pattern check (regression against silent format drift).
            self.assertRegex(
                expected_name,
                r"^[0-9a-f]{64}-wallet-backup-\d{8}\.tar\.gz$",
            )


if __name__ == "__main__":
    unittest.main()
