"""CLI source must stay ASCII-only.

Rationale: argparse help strings eventually hit stdout/stderr, and on
Windows (default cp1252 console encoding) any character outside that
codepage raises UnicodeEncodeError mid-print — which aborts
`messagechain stake --help` (or any other subcommand whose help
contains a non-ASCII char).  The community validator onboarding pitch
tells users to run exactly that; a --help crash is a first-impression
killer.

This test locks down the invariant by scanning the raw source.
Em-dashes, ellipses, arrows, box-drawing, etc. must be spelled out in
ASCII (`-`, `...`, `->`, `-`, etc.).  Regression tripwire: any future
commit that reintroduces a Unicode character fails CI locally.
"""

from __future__ import annotations

import pathlib
import unittest


class TestCLIAsciiOnly(unittest.TestCase):

    def test_cli_source_is_ascii(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        src = (repo / "messagechain" / "cli.py").read_text(encoding="utf-8")
        bad = [
            (i, ch, ord(ch))
            for i, ch in enumerate(src)
            if ord(ch) > 127
        ]
        if bad:
            # Locate by line for the error message.
            lines = src.splitlines()
            offenders: list[str] = []
            cursor = 0
            for lineno, line in enumerate(lines, 1):
                line_end = cursor + len(line) + 1  # +1 for newline
                for i, ch, cp in bad:
                    if cursor <= i < line_end and len(offenders) < 5:
                        offenders.append(
                            f"line {lineno} U+{cp:04X}: {line.strip()[:80]}"
                        )
                cursor = line_end
            self.fail(
                "messagechain/cli.py contains non-ASCII characters that "
                "will crash argparse --help on Windows cp1252 consoles:\n"
                + "\n".join(offenders)
            )


if __name__ == "__main__":
    unittest.main()
