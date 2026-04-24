"""Release-hygiene regression tests.

Covers two release-blocker fixes:

* RB-1: ``messagechain.__version__`` must agree with the canonical
  version declared in ``pyproject.toml`` (PEP 621).  A drift here means
  a ``pip install messagechain`` would report a different runtime
  ``__version__`` than the installed distribution version.

* RB-10: ``messagechain/cli.py`` ``_collect_private_key`` had two
  identical back-to-back ``except InvalidKeyFormatError`` handlers,
  the second of which was unreachable dead code.  This test walks the
  CLI module AST and asserts the function has exactly one such handler.
"""

import ast
import os
import re
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_pyproject_version() -> str:
    """Return the ``[project].version`` string from pyproject.toml.

    Uses ``tomllib`` when available (py311+); otherwise falls back to
    a minimal regex, since pyproject.toml has a very stable shape and
    we only need this one field.
    """
    path = os.path.join(REPO_ROOT, "pyproject.toml")
    try:
        import tomllib  # type: ignore[import-not-found]

        with open(path, "rb") as f:
            data = tomllib.load(f)
        return data["project"]["version"]
    except ModuleNotFoundError:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        # Match a `version = "X.Y.Z"` line inside the [project] table.
        # pyproject.toml is simple enough that a regex is fine for a test.
        m = re.search(
            r"^\s*version\s*=\s*\"([^\"]+)\"\s*$",
            text,
            re.MULTILINE,
        )
        if not m:
            raise AssertionError(
                "Could not locate `version = \"...\"` in pyproject.toml"
            )
        return m.group(1)


class TestPackageVersionMatchesPyproject(unittest.TestCase):
    """RB-1: runtime ``__version__`` must match pyproject.toml."""

    def test_versions_agree(self):
        import messagechain

        declared = _read_pyproject_version()
        self.assertEqual(
            messagechain.__version__,
            declared,
            msg=(
                "messagechain.__version__ ({!r}) does not match "
                "pyproject.toml [project].version ({!r}). "
                "pyproject.toml is canonical per PEP 621."
            ).format(messagechain.__version__, declared),
        )


class TestCollectPrivateKeyHasSingleInvalidKeyFormatHandler(unittest.TestCase):
    """RB-10: no duplicate ``except InvalidKeyFormatError`` handler."""

    def _find_function(self, tree, name):
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return node
        return None

    def test_exactly_one_handler(self):
        cli_path = os.path.join(REPO_ROOT, "messagechain", "cli.py")
        with open(cli_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=cli_path)

        fn = self._find_function(tree, "_collect_private_key")
        self.assertIsNotNone(
            fn, "Could not locate _collect_private_key in messagechain/cli.py"
        )

        # Count `except InvalidKeyFormatError` handlers anywhere inside
        # the function body (covers nested try blocks too).
        count = 0
        for node in ast.walk(fn):
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                # node.type may be a Name or an Attribute / Tuple.
                exc = node.type
                if isinstance(exc, ast.Name) and exc.id == "InvalidKeyFormatError":
                    count += 1
                elif isinstance(exc, ast.Tuple):
                    for elt in exc.elts:
                        if (
                            isinstance(elt, ast.Name)
                            and elt.id == "InvalidKeyFormatError"
                        ):
                            count += 1

        self.assertEqual(
            count,
            1,
            msg=(
                "_collect_private_key should have exactly one "
                "`except InvalidKeyFormatError` handler; found {}. "
                "A duplicate handler is unreachable dead code."
            ).format(count),
        )


class TestNoDeadDocsCrossRefsInPublicSource(unittest.TestCase):
    """RB-11: public source code must not cross-reference `docs/*.md`.

    `docs/` is gitignored per CLAUDE.md repo-hygiene — every file under
    it is operator-local and invisible on a public clone.  Scattering
    ``See docs/X.md for the authoritative design`` pointers through
    public modules trains readers that such cross-references are
    broken by default, which is a professional-polish failure for a
    project whose pitch is 'anyone can audit the protocol'.

    This test is a regression gate: the next contributor to write
    ``# See docs/Y.md`` fails CI and is prompted to redirect the
    pointer at the public source of truth (a sibling module's
    docstring) or drop the cross-reference entirely.

    Scoped to `messagechain/` source — .gitignore itself legitimately
    carries `docs/` as a pattern, and the operator-only tests under
    `tests/test_audit_fixes_iter_34_38.py` correctly gate their
    `docs/` access on `_DOCS_PRESENT`.  Those paths are exempt.
    """

    def test_no_docs_md_refs_in_messagechain_package(self):
        pkg_root = os.path.join(REPO_ROOT, "messagechain")
        pattern = re.compile(r"docs/[A-Za-z0-9_\-]+\.md")
        offenders: list[str] = []
        for dirpath, _dirnames, filenames in os.walk(pkg_root):
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dirpath, fn)
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()
                if pattern.search(text):
                    rel = os.path.relpath(path, REPO_ROOT)
                    offenders.append(rel)
        self.assertEqual(
            offenders,
            [],
            msg=(
                "Public source code cross-references `docs/*.md` — the "
                "`docs/` directory is gitignored, so these pointers "
                "resolve to 404 on any public clone. Redirect the "
                "reference at the corresponding public source of truth "
                "(a module docstring) or drop it. Offenders: {}"
            ).format(offenders),
        )


if __name__ == "__main__":
    unittest.main()
