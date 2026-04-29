"""
Tests for the richer `messagechain read` CLI output.

Pre-fix `cmd_read` printed only `[timestamp] entity_id_short...` plus
the message body — even though the `get_messages` RPC already returns
`tx_hash`, optional `prev`, vote counts, and (post-Tier 25)
`community_id`.  The web feed renders those; the CLI shouldn't lag
behind.

The CLI patch surfaces:
  * tx_hash  — short 12-char prefix (lets a user copy/paste into
               `messagechain receipt`).
  * prev →   — when the message has a predecessor pointer.
  * [community-id] chip — when the message carries a community handle.
  * vote totals — `▲N ▼N` when at least one vote has been cast.

Optional `--community-id` and `--by-address` flags filter the feed
locally on the client side.  Server-side filtering would require
schema-extending the `get_messages` RPC; client-side keeps the
change scoped to the CLI surface.
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


def _args(**overrides):
    base = dict(
        last=10,
        server="127.0.0.1:9334",
        community_id=None,
        by_address=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _drive_cmd_read(args, messages):
    """Run cmd_read with rpc_call stubbed to return `messages`.
    Returns the captured stdout."""
    from messagechain import cli as cli_mod

    def rpc_side(host, port, method, params):
        if method == "get_messages":
            return {"ok": True, "result": {"messages": list(messages)}}
        return {"ok": True, "result": {}}

    buf = io.StringIO()
    with patch("client.rpc_call", side_effect=rpc_side):
        with redirect_stdout(buf):
            cli_mod.cmd_read(args)
    return buf.getvalue()


def _msg(**overrides):
    base = dict(
        message="hello",
        entity_id="ab" * 32,
        timestamp=1_700_000_000,
        tx_hash="cd" * 32,
        block_number=5,
        ups=0,
        downs=0,
        up_pct=None,
    )
    base.update(overrides)
    return base


class TestReadShowsTxHash(unittest.TestCase):
    def test_short_tx_hash_in_output(self):
        msgs = [_msg(tx_hash="abcdef0123456789" + "00" * 24)]
        out = _drive_cmd_read(_args(), msgs)
        # First 12 chars of the tx hash should appear so the user can
        # paste into `messagechain receipt`.
        self.assertIn("abcdef012345", out)

    def test_tx_hash_label_present(self):
        msgs = [_msg(tx_hash="ff" * 32)]
        out = _drive_cmd_read(_args(), msgs)
        self.assertIn("tx", out.lower())


class TestReadShowsPrevPointer(unittest.TestCase):
    def test_prev_arrow_when_pointer_present(self):
        msgs = [_msg(prev="ee" * 32)]
        out = _drive_cmd_read(_args(), msgs)
        # ASCII "->" arrow; cli.py source is ASCII-only so the unicode
        # right-arrow can't appear in the print path.
        self.assertIn("->", out)
        self.assertIn("prev", out.lower())
        # Short hex of the prev pointer.
        self.assertIn("eeeeeeeeeeee", out)

    def test_no_prev_arrow_when_pointer_absent(self):
        msgs = [_msg()]
        out = _drive_cmd_read(_args(), msgs)
        self.assertNotIn("prev ->", out)


class TestReadShowsCommunityChip(unittest.TestCase):
    def test_community_chip_when_present(self):
        msgs = [_msg(community_id="art")]
        out = _drive_cmd_read(_args(), msgs)
        self.assertIn("[art]", out)

    def test_no_chip_when_community_absent(self):
        msgs = [_msg()]
        out = _drive_cmd_read(_args(), msgs)
        # Must not invent an empty `[]` chip when the field is absent.
        self.assertNotIn("[]", out)


class TestReadShowsVoteTotals(unittest.TestCase):
    def test_vote_totals_when_votes_cast(self):
        msgs = [_msg(ups=5, downs=2, up_pct=71.4)]
        out = _drive_cmd_read(_args(), msgs)
        # Render up + down counts in some readable form.
        self.assertIn("5", out)
        self.assertIn("2", out)
        # ASCII "up"/"down" labels — the web feed uses unicode glyphs
        # but cli.py source is held to ASCII-only by test_cli_ascii_only.
        self.assertIn("up", out.lower())
        self.assertIn("down", out.lower())

    def test_no_vote_block_when_zero_votes(self):
        msgs = [_msg(ups=0, downs=0)]
        out = _drive_cmd_read(_args(), msgs)
        # Don't print a noisy "up 0 down 0" line for messages with no votes.
        self.assertNotIn("up 0", out)
        self.assertNotIn("down 0", out)


class TestReadFilterFlags(unittest.TestCase):
    def test_filter_by_community_id(self):
        msgs = [
            _msg(message="art post", community_id="art", tx_hash="11" * 32),
            _msg(message="music post", community_id="music", tx_hash="22" * 32),
        ]
        out = _drive_cmd_read(_args(community_id="art"), msgs)
        self.assertIn("art post", out)
        self.assertNotIn("music post", out)

    def test_filter_by_address_hex(self):
        msgs = [
            _msg(message="alpha", entity_id="aa" * 32, tx_hash="11" * 32),
            _msg(message="beta", entity_id="bb" * 32, tx_hash="22" * 32),
        ]
        out = _drive_cmd_read(_args(by_address="aa" * 32), msgs)
        self.assertIn("alpha", out)
        self.assertNotIn("beta", out)


if __name__ == "__main__":
    unittest.main()
