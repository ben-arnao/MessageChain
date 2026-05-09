"""Audit r39 #2 -- backup-wallet must include receipt_leaf_index.json.

Pre-fix ``cmd_backup_wallet`` packed the keyfile plus the block-
signing leaf cursor only.  The receipt-signing subtree's leaf cursor
(``<data_dir>/receipt_leaf_index.json``) was silently omitted even
though README.md:300-326 names it as one of the three security-
critical files an operator MUST back up, and the documented manual
``tar`` example at README.md:339 includes it.

Concrete operator harm: a diligent validator who reads the README,
runs ``messagechain backup-wallet``, and trusts the resulting
tarball as a "complete" wallet backup will, on disk-loss restore,
re-sign already-burned WOTS+ leaves on the receipt subtree --
producing equivocation evidence on chain.  Pre-Tier-20 the per-
offense penalty was 100% stake; post-Tier-20 the geometric soft-
slash compounds ``(1 - 0.05)^N`` toward total stake loss as each
re-used leaf surfaces a distinct equivocation event.  Operator did
exactly what the documentation said; tool dropped the load-bearing
file.

CLAUDE.md anchor at risk: "Honest, well-configured nodes should
rarely if ever be slashed under normal operation -- design slashing
rules so the false-positive rate on honest operators is very low."
A backup tool that drops one of the two leaf-cursor files turns the
official "back up your wallet" command into a stake-loss trap on
restore.

Fix: extend ``cmd_backup_wallet`` to default the receipt-leaf path
from the resolved ``data_dir`` (mirrors how the existing
``--leaves`` argument default-resolves from the entity id) and
include the file in the tarball when present on disk.  Adds a
new ``--receipt-leaves PATH`` argument for explicit override and a
``--no-receipt-leaves`` opt-out for non-receipt-issuing validators
that want the silent path; the opt-out prints a warning so the
operator sees the choice.

Tests:
  1. Receipt-leaf cursor at ``<data_dir>/receipt_leaf_index.json``
     is included in the tarball by default (the pre-fix
     omission case -- this is the regression pin).
  2. Explicit ``--receipt-leaves PATH`` overrides the default and
     is included.
  3. When the receipt-leaf cursor is absent on disk (validator
     does NOT issue receipts), the tarball is still produced
     without error -- backwards-compatible for non-receipt-issuing
     validators.
  4. ``--no-receipt-leaves`` opts out cleanly (with a warning),
     leaving the receipt cursor file out of the tarball even when
     present on disk.
"""

from __future__ import annotations

import argparse
import io
import os
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout


_RECEIPT_LEAF_INDEX_FILENAME = "receipt_leaf_index.json"


def _make_args(**kwargs) -> argparse.Namespace:
    """Build an argparse.Namespace with every field cmd_backup_wallet reads."""
    base = dict(
        keyfile=None,
        leaves=None,
        receipt_leaves=None,
        no_receipt_leaves=False,
        output=None,
        entity_id=None,
        data_dir=None,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


def _setup_keyfile_and_leaves(workdir: str, entity_hex: str):
    """Build keyfile + block-signing leaves cursor in workdir.  Returns
    (keyfile_path, leaves_path)."""
    keyfile = os.path.join(workdir, "keyfile")
    with open(keyfile, "w") as f:
        f.write("a" * 64)
    leaves_dir = os.path.join(workdir, "leaves-home")
    os.makedirs(leaves_dir, exist_ok=True)
    leaves_path = os.path.join(leaves_dir, f"{entity_hex}.idx")
    with open(leaves_path, "w") as f:
        f.write('{"next_leaf": 7}')
    return keyfile, leaves_path


# ─────────────────────────────────────────────────────────────────────


class TestReceiptLeafIncludedByDefault(unittest.TestCase):
    """Pre-fix the official ``backup-wallet`` command silently dropped
    ``<data_dir>/receipt_leaf_index.json`` -- a security-critical
    file the README explicitly names.  Post-fix the command must
    pick the file up from the resolved ``data_dir`` and include it."""

    def test_receipt_leaf_index_landed_in_tarball(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            entity_hex = "11" * 32
            keyfile, leaves_path = _setup_keyfile_and_leaves(
                workdir, entity_hex,
            )
            data_dir = os.path.join(workdir, "data")
            os.makedirs(data_dir, exist_ok=True)
            receipt_leaf_path = os.path.join(
                data_dir, _RECEIPT_LEAF_INDEX_FILENAME,
            )
            with open(receipt_leaf_path, "w") as f:
                f.write('{"next_leaf": 3}')

            output = os.path.join(workdir, "wallet-backup.tar.gz")
            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                output=output,
                entity_id=entity_hex,
                data_dir=data_dir,
            )
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc = cli_mod.cmd_backup_wallet(args)
            self.assertIn(rc, (None, 0))
            self.assertTrue(os.path.exists(output))
            with tarfile.open(output, "r:gz") as tf:
                names = tf.getnames()
            self.assertTrue(
                any(_RECEIPT_LEAF_INDEX_FILENAME in n for n in names),
                "receipt_leaf_index.json MUST be in the backup tarball "
                "when present on disk -- the pre-fix command silently "
                "omitted it, leading to receipt-subtree equivocation "
                "slashes on disk-loss restore.  Got names: "
                f"{names!r}",
            )


class TestExplicitReceiptLeavesFlag(unittest.TestCase):
    """``--receipt-leaves PATH`` must override the default location and
    use the explicit path."""

    def test_explicit_receipt_leaves_flag_used(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            entity_hex = "22" * 32
            keyfile, leaves_path = _setup_keyfile_and_leaves(
                workdir, entity_hex,
            )
            # Receipt-leaf NOT under default data_dir -- forces
            # exercise of the explicit-flag override.
            explicit_receipt = os.path.join(
                workdir, "out-of-band-receipt.json",
            )
            with open(explicit_receipt, "w") as f:
                f.write('{"next_leaf": 9}')

            output = os.path.join(workdir, "wallet-backup.tar.gz")
            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                receipt_leaves=explicit_receipt,
                output=output,
                entity_id=entity_hex,
            )
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc = cli_mod.cmd_backup_wallet(args)
            self.assertIn(rc, (None, 0))
            with tarfile.open(output, "r:gz") as tf:
                names = tf.getnames()
            self.assertTrue(
                any(os.path.basename(explicit_receipt) in n for n in names),
                "Explicit --receipt-leaves PATH MUST be honored.  "
                f"Got names: {names!r}",
            )


class TestReceiptLeafAbsentIsNotAnError(unittest.TestCase):
    """Validators that do NOT issue receipts have no
    ``receipt_leaf_index.json`` on disk.  The backup command must
    produce a clean tarball without the receipt cursor in that case
    (no error, no synthetic file, just absent from the archive)."""

    def test_no_receipt_file_on_disk_no_error(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            entity_hex = "33" * 32
            keyfile, leaves_path = _setup_keyfile_and_leaves(
                workdir, entity_hex,
            )
            # data_dir exists but receipt_leaf_index.json does NOT.
            data_dir = os.path.join(workdir, "data")
            os.makedirs(data_dir, exist_ok=True)

            output = os.path.join(workdir, "wallet-backup.tar.gz")
            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                output=output,
                entity_id=entity_hex,
                data_dir=data_dir,
            )
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc = cli_mod.cmd_backup_wallet(args)
            self.assertIn(rc, (None, 0))
            self.assertTrue(os.path.exists(output))
            with tarfile.open(output, "r:gz") as tf:
                names = tf.getnames()
            # No receipt cursor in archive (correct -- file did not
            # exist on disk), but block-signing cursor IS there.
            self.assertFalse(
                any(_RECEIPT_LEAF_INDEX_FILENAME in n for n in names),
                "When receipt_leaf_index.json is absent on disk the "
                "backup tarball MUST NOT synthesize one.  Got names: "
                f"{names!r}",
            )
            self.assertTrue(
                any(f"{entity_hex}.idx" in n for n in names),
                "Block-signing leaf cursor MUST still be in the "
                f"tarball.  Got names: {names!r}",
            )


class TestExplicitNoReceiptLeavesOptOut(unittest.TestCase):
    """Operator who explicitly passes ``--no-receipt-leaves`` opts out
    of the receipt-leaf default-resolution.  Must produce a tarball
    without the receipt cursor AND emit a warning so the operator
    sees the choice (defends against accidental opt-out)."""

    def test_explicit_no_receipt_leaves_omits_and_warns(self) -> None:
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as workdir:
            entity_hex = "44" * 32
            keyfile, leaves_path = _setup_keyfile_and_leaves(
                workdir, entity_hex,
            )
            data_dir = os.path.join(workdir, "data")
            os.makedirs(data_dir, exist_ok=True)
            receipt_leaf_path = os.path.join(
                data_dir, _RECEIPT_LEAF_INDEX_FILENAME,
            )
            with open(receipt_leaf_path, "w") as f:
                f.write('{"next_leaf": 3}')

            output = os.path.join(workdir, "wallet-backup.tar.gz")
            args = _make_args(
                keyfile=keyfile,
                leaves=leaves_path,
                no_receipt_leaves=True,
                output=output,
                entity_id=entity_hex,
                data_dir=data_dir,
            )
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                rc = cli_mod.cmd_backup_wallet(args)
            self.assertIn(rc, (None, 0))
            with tarfile.open(output, "r:gz") as tf:
                names = tf.getnames()
            self.assertFalse(
                any(_RECEIPT_LEAF_INDEX_FILENAME in n for n in names),
                "--no-receipt-leaves MUST omit the receipt cursor from "
                f"the tarball.  Got names: {names!r}",
            )
            combined = stdout_buf.getvalue() + stderr_buf.getvalue()
            self.assertIn(
                "receipt", combined.lower(),
                "Opting out of receipt-leaf inclusion MUST emit a "
                "visible warning naming the receipt cursor so the "
                "operator does not silently produce an incomplete "
                f"backup.  Got output: {combined!r}",
            )


# ─────────────────────────────────────────────────────────────────────
# Parser surface: the new flags must be registered.
# ─────────────────────────────────────────────────────────────────────


class TestParserRegistersNewFlags(unittest.TestCase):
    """The argparse subparser for ``backup-wallet`` must register both
    ``--receipt-leaves`` and ``--no-receipt-leaves`` so callers can
    invoke them from the CLI."""

    def test_backup_wallet_parser_registers_receipt_leaves_flags(self):
        from messagechain import cli as cli_mod

        parser = cli_mod.build_parser()
        args = parser.parse_args([
            "backup-wallet",
            "--keyfile", "/tmp/x.key",
            "--receipt-leaves", "/tmp/x-receipt.json",
        ])
        self.assertEqual(args.receipt_leaves, "/tmp/x-receipt.json")
        self.assertFalse(getattr(args, "no_receipt_leaves", True))

        args2 = parser.parse_args([
            "backup-wallet",
            "--keyfile", "/tmp/x.key",
            "--no-receipt-leaves",
        ])
        self.assertTrue(args2.no_receipt_leaves)


if __name__ == "__main__":
    unittest.main()
