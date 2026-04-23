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


if __name__ == "__main__":
    unittest.main()
