"""Per-wallet leaf-index persistence in CLI signing commands.

Audit finding (trust-foundation hotfix): `messagechain send`,
`transfer`, `stake`, `unstake`, `propose`, `vote`, `rotate-key`,
`set-authority-key`, `emergency-revoke`, etc. used to advance the
WOTS+ leaf cursor only via the chain watermark and throw the
advanced cursor away on process exit.  Two consecutive CLI
invocations against the same node (or two nodes mid-gossip) saw
the same chain watermark and signed two different bytes at the
same WOTS+ leaf -- mathematical disclosure of the WOTS+ private
key for that leaf, slashable equivocation evidence, full stake
wipe.

The fix wires every signing CLI command into the same persist-
before-sign primitive the daemon uses (`KeyPair.persist_leaf_index`
+ `load_leaf_index`).  The on-disk cursor is keyed by entity_id
under `~/.messagechain/leaves/<entity_hex>.idx`, falling back to
`<data-dir>/leaf_index.json` when --data-dir is set so the
operator path stays byte-identical to today.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch


# ── _resolve_leaf_index_path -----------------------------------------------

class TestResolveLeafIndexPath(unittest.TestCase):
    """Path resolution: home-dir default + --data-dir operator path."""

    def test_default_path_is_home_dotmessagechain(self):
        from messagechain import cli as cli_mod

        entity_hex = "ab" * 32
        with tempfile.TemporaryDirectory() as fake_home:
            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                p = cli_mod._resolve_leaf_index_path(entity_hex)
            self.assertEqual(
                str(p),
                os.path.join(fake_home, ".messagechain", "leaves", f"{entity_hex}.idx"),
            )

    def test_operator_data_dir_path_unchanged(self):
        """When --data-dir is set, the cursor file is at
        `<data_dir>/leaf_index.json` -- the same path the daemon's
        leaf-index persistence uses today.  This keeps the operator/
        validator path byte-for-byte identical to before this fix.
        """
        from messagechain import cli as cli_mod
        from messagechain.config import LEAF_INDEX_FILENAME

        entity_hex = "cd" * 32
        with tempfile.TemporaryDirectory() as data_dir:
            p = cli_mod._resolve_leaf_index_path(entity_hex, data_dir=data_dir)
            self.assertEqual(str(p), os.path.join(data_dir, LEAF_INDEX_FILENAME))


# ── helpers ---------------------------------------------------------------

class _FakeKeypair:
    """Minimal KeyPair stand-in that records leaf_index_path / load /
    advance / persist in the same order a real KeyPair would do them.

    The real KeyPair.sign carries the persist-before-sign ratchet, so
    we don't need to call sign() in these tests -- the test guarantees
    are about what the CLI writes to disk BEFORE a sign would happen.
    """

    def __init__(self, num_leaves: int = 1024):
        self.num_leaves = num_leaves
        self._next_leaf = 0
        self.leaf_index_path: str | None = None
        self._load_calls: list[str] = []
        self._advance_calls: list[int] = []

    def load_leaf_index(self, path: str) -> None:
        # Mirror real KeyPair behavior: never move backwards; load
        # higher disk values into _next_leaf.
        self._load_calls.append(path)
        try:
            with open(path, "r") as f:
                data = json.load(f)
            stored = int(data.get("next_leaf", 0))
            if stored > self._next_leaf:
                self._next_leaf = stored
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

    def advance_to_leaf(self, leaf_index: int) -> None:
        self._advance_calls.append(int(leaf_index))
        if leaf_index > self._next_leaf:
            self._next_leaf = leaf_index

    def persist_leaf_index(self, path: str) -> None:
        # Mirror real persist: tmp + replace.
        path = str(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"next_leaf": self._next_leaf}, f)
        os.replace(tmp, path)


def _bind_and_advance(cli_mod, entity, *, chain_leaf: int, data_dir: str | None):
    """Run the CLI helper that binds the on-disk cursor + advances.

    The fix exposes this as a single helper so every signing
    command's wiring is one line + a leaf-watermark fetch.  The
    helper returns the resolved path so tests can assert on it.
    """
    return cli_mod._bind_persistent_leaf_index(
        entity, chain_leaf=chain_leaf, data_dir=data_dir,
    )


# ── two-send-same-process: cursor advances on disk -------------------------

class TestTwoConsecutiveSendsAdvanceCursor(unittest.TestCase):
    """A single process performing two sequential signs must end up
    with the on-disk cursor reflecting BOTH leaves consumed."""

    def test_two_consecutive_sends_advance_leaf_watermark_on_disk(self):
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as fake_home:
            entity_hex = "11" * 32
            entity = MagicMock()
            entity.entity_id_hex = entity_hex
            entity.keypair = _FakeKeypair()

            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                # First sign at chain watermark 0 -- cursor advances
                # to 1 on disk via persist after the simulated sign.
                path = _bind_and_advance(
                    cli_mod, entity, chain_leaf=0, data_dir=None,
                )
                entity.keypair._next_leaf = 1  # simulate sign() advancing
                entity.keypair.persist_leaf_index(path)

                # Second sign in same process at the SAME chain watermark
                # (the chain hasn't ingested the first tx yet).  The
                # disk cursor MUST take precedence so we sign at leaf 1,
                # not 0.
                entity2 = MagicMock()
                entity2.entity_id_hex = entity_hex
                entity2.keypair = _FakeKeypair()
                _bind_and_advance(
                    cli_mod, entity2, chain_leaf=0, data_dir=None,
                )

            self.assertEqual(
                entity2.keypair._next_leaf, 1,
                "second send must see the first send's persisted cursor",
            )


class TestTwoConsecutiveSendsAcrossProcesses(unittest.TestCase):
    """Across simulated process restarts the cursor must persist."""

    def test_two_consecutive_sends_across_separate_processes_do_not_reuse_leaf(self):
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as fake_home:
            entity_hex = "22" * 32

            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                # === Process 1 ===
                e1 = MagicMock()
                e1.entity_id_hex = entity_hex
                e1.keypair = _FakeKeypair()
                path1 = _bind_and_advance(
                    cli_mod, e1, chain_leaf=0, data_dir=None,
                )
                e1.keypair._next_leaf = 1
                e1.keypair.persist_leaf_index(path1)
                # process exits; in-memory state lost.

                # === Process 2 ===
                e2 = MagicMock()
                e2.entity_id_hex = entity_hex
                e2.keypair = _FakeKeypair()
                # Chain watermark hasn't advanced yet -- the new
                # process MUST still see leaf 1 from disk.
                _bind_and_advance(
                    cli_mod, e2, chain_leaf=0, data_dir=None,
                )

            self.assertEqual(
                e2.keypair._next_leaf, 1,
                "fresh process must NOT reuse the leaf the previous process burned",
            )


# ── chain-watermark-vs-disk semantics --------------------------------------

class TestChainWatermarkAheadOfDisk(unittest.TestCase):
    """Disk cursor at 5, chain at 7 (the chain has ingested signed
    txs from another machine).  The signer must advance to 7 and
    re-persist."""

    def test_chain_watermark_ahead_of_disk_advances_disk(self):
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as fake_home:
            entity_hex = "33" * 32

            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                # Pre-seed the disk cursor at 5.
                resolver_path = cli_mod._resolve_leaf_index_path(entity_hex)
                os.makedirs(resolver_path.parent, exist_ok=True)
                with open(resolver_path, "w") as f:
                    json.dump({"next_leaf": 5}, f)

                e = MagicMock()
                e.entity_id_hex = entity_hex
                e.keypair = _FakeKeypair()
                _bind_and_advance(
                    cli_mod, e, chain_leaf=7, data_dir=None,
                )

                self.assertGreaterEqual(
                    e.keypair._next_leaf, 7,
                    "chain watermark ahead of disk must drive cursor forward",
                )

                # Simulate the sign() persist-before-sign step.
                e.keypair.persist_leaf_index(str(resolver_path))
                with open(resolver_path) as f:
                    on_disk = json.load(f)["next_leaf"]
                self.assertGreaterEqual(on_disk, 7)


class TestDiskCursorAheadOfChain(unittest.TestCase):
    """Disk cursor at 9 (recent same-machine sign not yet gossiped),
    chain at 5.  Disk must take precedence -- signing at leaf 5
    would reuse a leaf already burned by the prior local sign."""

    def test_disk_cursor_ahead_of_chain_takes_precedence(self):
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as fake_home:
            entity_hex = "44" * 32

            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                resolver_path = cli_mod._resolve_leaf_index_path(entity_hex)
                os.makedirs(resolver_path.parent, exist_ok=True)
                with open(resolver_path, "w") as f:
                    json.dump({"next_leaf": 9}, f)

                e = MagicMock()
                e.entity_id_hex = entity_hex
                e.keypair = _FakeKeypair()
                _bind_and_advance(
                    cli_mod, e, chain_leaf=5, data_dir=None,
                )

                # The signer MUST have advanced past 9, NOT to 5.
                self.assertGreaterEqual(e.keypair._next_leaf, 9)
                self.assertNotEqual(
                    e.keypair._next_leaf, 5,
                    "disk-ahead-of-chain case must NOT regress to chain watermark",
                )


# ── operator path unchanged ------------------------------------------------

class TestOperatorDataDirPathUnchanged(unittest.TestCase):
    """When --data-dir is set, the cursor file is at
    `<data_dir>/leaf_index.json` exactly as today."""

    def test_operator_data_dir_path_unchanged(self):
        from messagechain import cli as cli_mod
        from messagechain.config import LEAF_INDEX_FILENAME

        with tempfile.TemporaryDirectory() as data_dir:
            entity_hex = "55" * 32
            e = MagicMock()
            e.entity_id_hex = entity_hex
            e.keypair = _FakeKeypair()

            path = _bind_and_advance(
                cli_mod, e, chain_leaf=0, data_dir=data_dir,
            )

            self.assertEqual(
                str(path), os.path.join(data_dir, LEAF_INDEX_FILENAME),
                "operator path must remain at <data_dir>/leaf_index.json",
            )

            self.assertEqual(
                e.keypair.leaf_index_path,
                os.path.join(data_dir, LEAF_INDEX_FILENAME),
                "operator path must wire leaf_index_path through to KeyPair",
            )


# ── home dir is used when no --data-dir ------------------------------------

class TestHomeDirIsUsedByDefault(unittest.TestCase):
    """No --data-dir -> path is under ~/.messagechain/leaves/."""

    def test_no_data_dir_uses_home_messagechain_leaves(self):
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory() as fake_home:
            entity_hex = "66" * 32
            e = MagicMock()
            e.entity_id_hex = entity_hex
            e.keypair = _FakeKeypair()

            with patch("pathlib.Path.home", return_value=Path(fake_home)):
                path = _bind_and_advance(
                    cli_mod, e, chain_leaf=0, data_dir=None,
                )

            expected = os.path.join(
                fake_home, ".messagechain", "leaves", f"{entity_hex}.idx",
            )
            self.assertEqual(str(path), expected)
            # Parent directory must exist after the call (so persist
            # doesn't fail with ENOENT on first sign).
            self.assertTrue(
                os.path.isdir(os.path.dirname(expected)),
                "parent of cursor file must be created for first sign",
            )


if __name__ == "__main__":
    unittest.main()
