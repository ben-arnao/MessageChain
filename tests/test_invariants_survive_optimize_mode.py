"""Consensus invariants must survive ``python -O`` / PYTHONOPTIMIZE=1.

Python strips ``assert`` statements at runtime when the interpreter is
started with ``-O`` (or when ``PYTHONOPTIMIZE`` is set).  Any consensus
invariant written as ``assert`` silently becomes a no-op under those
modes, so a validator running the node with optimization enabled could
advance a chain past a corrupted invariant (e.g. R8 supply conservation)
and commit garbage to the state root.

This is release-blocker **RB-2**: replace ``assert`` with explicit
``if not cond: raise ChainIntegrityError(...)`` on every consensus-
critical check.  The tests below guard against regression:

* **Test A (subprocess, -O mode)** — Boot a fresh Python interpreter
  with ``-O``, trigger the supply-invariant violation, and assert the
  process exits non-zero with ``ChainIntegrityError`` in stderr.  Proves
  the check survives optimization.

* **Test B (positive regression, normal mode)** — Build and advance a
  valid chain; the invariant must NOT raise.  Rules out false positives
  from the new check.

* **Test C (discovery + allowlist)** — Scan the in-scope modules for any
  lingering ``assert`` statements and compare against an allowlist.
  Any new assert in a consensus-critical file must either be converted
  or explicitly allowlisted with a rationale, so future edits don't
  reintroduce the class of bug.

Scope files (audited by Test C):
  * messagechain/core/blockchain.py
  * messagechain/consensus/*.py
  * messagechain/storage/*.py
  * messagechain/economics/*.py
  * messagechain/governance/governance.py
  * messagechain/core/*.py
"""

from __future__ import annotations

import ast
import os
import pathlib
import subprocess
import sys
import textwrap
import unittest


# ── Allowlist: asserts that are safe to strip under -O ─────────────────
#
# Each entry is (relative_path, line_number, rationale).  An allowlisted
# assert must be:
#   * Type-narrowing (``assert isinstance(x, T)``) — idiomatic shim for
#     type checkers; the code will still TypeError on wrong input.
#   * Dev-only (inside ``if __name__ == '__main__'`` blocks, test
#     fixtures, etc.).
#
# Consensus-critical asserts MUST NOT be allowlisted — they must be
# converted to ``raise ChainIntegrityError(...)`` (or equivalent).
_ASSERT_ALLOWLIST: set[tuple[str, int]] = set()


def _repo_root() -> pathlib.Path:
    """Return the repo root (parent of ``tests/``)."""
    return pathlib.Path(__file__).resolve().parent.parent


def _scope_files() -> list[pathlib.Path]:
    """Enumerate every file whose asserts Test C scans."""
    root = _repo_root()
    files: list[pathlib.Path] = []
    # messagechain/core/*.py
    for p in sorted((root / "messagechain" / "core").glob("*.py")):
        files.append(p)
    # messagechain/consensus/*.py
    for p in sorted((root / "messagechain" / "consensus").glob("*.py")):
        files.append(p)
    # messagechain/storage/*.py
    for p in sorted((root / "messagechain" / "storage").glob("*.py")):
        files.append(p)
    # messagechain/economics/*.py
    for p in sorted((root / "messagechain" / "economics").glob("*.py")):
        files.append(p)
    gov = root / "messagechain" / "governance" / "governance.py"
    if gov.exists():
        files.append(gov)
    return files


def _find_asserts(path: pathlib.Path) -> list[int]:
    """Return 1-indexed line numbers of every ``assert`` in ``path``.

    Uses the ``ast`` module so we do not catch ``assert`` appearing
    inside strings or comments.
    """
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src)
    except SyntaxError:  # pragma: no cover
        return []
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            lines.append(node.lineno)
    return sorted(lines)


class TestSupplyInvariantSurvivesOptimize(unittest.TestCase):
    """Test A — supply invariant fires under ``python -O``.

    We spawn a subprocess with ``-O`` and a tiny script that bumps
    ``total_supply`` past the invariant, then applies a block.  Under
    ``assert``, the check would be stripped and the script would exit
    cleanly; under ``raise ChainIntegrityError``, the process exits with
    a non-zero status and the exception class appears in stderr.
    """

    def _run_subprocess(self, optimize: bool) -> subprocess.CompletedProcess:
        # We reuse the existing ``_make_chain_with_seeds`` test helper
        # from ``test_supply_invariant.py`` so the chain-setup logic
        # stays in exactly one place — any future change to the helper
        # (stake amounts, PoS wiring, etc.) flows through here too.
        script = textwrap.dedent(
            """
            import sys
            import tests  # patch config (short merkle, devnet, etc.)
            from tests.test_supply_invariant import _make_chain_with_seeds
            from tests import pick_selected_proposer
            from messagechain.core.blockchain import ChainIntegrityError

            chain, seeds, consensus = _make_chain_with_seeds()

            # Inject the drift: bump total_supply without total_minted
            # (the R8-#2 class of bug).  A correctly-implemented invariant
            # must fire at end of _apply_block_state regardless of
            # optimization level.
            chain.supply.total_supply += 7

            proposer = pick_selected_proposer(chain, seeds)
            blk = chain.propose_block(consensus, proposer, [])
            try:
                chain._apply_block_state(blk)
            except ChainIntegrityError as exc:
                print("CAUGHT:ChainIntegrityError:" + str(exc))
                sys.exit(42)
            # Reached here only if the invariant did NOT fire.  Under
            # ``-O``, a plain ``assert`` would hit this branch and exit 0
            # — the regression we are guarding against.
            print("NO-RAISE")
            sys.exit(0)
            """
        )
        argv = [sys.executable]
        if optimize:
            argv.append("-O")
        argv += ["-c", script]
        env = dict(os.environ)
        env.pop("PYTHONOPTIMIZE", None)
        # Make sure the child can import ``tests`` (which patches config)
        # and ``messagechain``.
        env["PYTHONPATH"] = (
            str(_repo_root()) + os.pathsep + env.get("PYTHONPATH", "")
        )
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            cwd=str(_repo_root()),
        )

    def test_fires_under_normal_mode(self):
        proc = self._run_subprocess(optimize=False)
        self.assertEqual(
            proc.returncode, 42,
            msg=(
                f"expected ChainIntegrityError (exit 42), got "
                f"returncode={proc.returncode}\n"
                f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
            ),
        )
        self.assertIn("CAUGHT:ChainIntegrityError", proc.stdout)

    def test_fires_under_dash_O(self):
        """Under ``-O``, an ``assert``-based check would silently pass.

        This test proves the invariant is an explicit ``raise``, not an
        ``assert``, because it MUST fire even with ``-O``.
        """
        proc = self._run_subprocess(optimize=True)
        self.assertEqual(
            proc.returncode, 42,
            msg=(
                "Supply invariant did NOT fire under -O — it is probably "
                "still an ``assert`` statement, which Python strips "
                "under optimization, silently skipping the check.\n"
                f"returncode={proc.returncode}\n"
                f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
            ),
        )
        self.assertIn("CAUGHT:ChainIntegrityError", proc.stdout)


class TestValidChainAdvancesCleanly(unittest.TestCase):
    """Test B — positive regression.

    A clean chain that has not been tampered with must advance through
    several blocks without the supply invariant firing.  Rules out any
    false-positive from the new ``ChainIntegrityError`` path.
    """

    def test_clean_chain_advances_without_raising(self):
        from tests import pick_selected_proposer
        from tests.test_supply_invariant import _make_chain_with_seeds
        from messagechain.config import GENESIS_SUPPLY

        chain, seeds, consensus = _make_chain_with_seeds()

        # Advance several blocks.  Each ends in _apply_block_state which
        # now runs the R8 supply invariant via explicit raise — must not
        # fire on a clean chain.
        for _ in range(5):
            proposer = pick_selected_proposer(chain, seeds)
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, f"add_block failed: {reason}")

        self.assertEqual(
            chain.supply.total_supply,
            GENESIS_SUPPLY
            + chain.supply.total_minted
            - chain.supply.total_burned,
        )


class TestNoLingeringAssertsInScope(unittest.TestCase):
    """Test C — allowlist for remaining ``assert`` statements.

    Walk every in-scope file, list every ``assert`` via ``ast``, and
    compare against ``_ASSERT_ALLOWLIST``.  An un-allowlisted assert in
    a consensus-critical file is a regression: either convert it to
    ``raise ChainIntegrityError(...)`` or add it to the allowlist with
    a one-line rationale explaining why stripping under ``-O`` is safe.
    """

    def test_no_unallowlisted_asserts(self):
        root = _repo_root()
        offenders: list[tuple[str, int, str]] = []
        for path in _scope_files():
            rel = path.relative_to(root).as_posix()
            for lineno in _find_asserts(path):
                if (rel, lineno) in _ASSERT_ALLOWLIST:
                    continue
                # Grab the line text for the error message.
                line_text = path.read_text(
                    encoding="utf-8"
                ).splitlines()[lineno - 1].strip()
                offenders.append((rel, lineno, line_text))
        if offenders:
            lines = "\n".join(
                f"  {p}:{n}: {t}" for p, n, t in offenders
            )
            self.fail(
                "Found un-allowlisted ``assert`` statements in "
                "consensus-critical files.  Each must either be "
                "converted to ``raise ChainIntegrityError(...)`` (so it "
                "survives ``python -O``) or allowlisted in "
                "_ASSERT_ALLOWLIST with a rationale:\n" + lines
            )

    def test_allowlist_entries_still_exist(self):
        """Allowlist entries that drift are a silent maintenance hazard.

        If a file is edited and an allowlisted assert moves or gets
        deleted, the allowlist silently points at the wrong line.
        Require that every allowlist line number actually contains an
        ``assert`` in the current file.
        """
        root = _repo_root()
        stale: list[tuple[str, int]] = []
        for rel, lineno in _ASSERT_ALLOWLIST:
            path = root / rel
            if not path.exists():
                stale.append((rel, lineno))
                continue
            if lineno not in _find_asserts(path):
                stale.append((rel, lineno))
        if stale:
            lines = "\n".join(f"  {p}:{n}" for p, n in stale)
            self.fail(
                "Allowlist entries no longer match an ``assert`` in "
                "the source file — update _ASSERT_ALLOWLIST:\n" + lines
            )


if __name__ == "__main__":
    unittest.main()
