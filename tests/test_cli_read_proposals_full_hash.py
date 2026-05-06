"""Pin: ``messagechain read`` and ``messagechain proposals`` print
the full 64-hex tx_hash / proposal_id so a CLI-only user can copy
it into ``react`` / ``vote`` / ``receipt`` / ``submit-evidence``
without leaving the CLI.

Pre-fix, ``cmd_read`` truncated the tx_hash to 12 chars on the
header line; ``cmd_proposals`` truncated the proposal_id to 16
chars.  ``cmd_react`` and ``cmd_vote`` both hard-reject anything
other than the full 64-hex form (cli.py:4881 for react,
parse_hex(..., expected_len=32) for vote).  The CLI could not
complete the canonical "browse the feed, upvote one / vote on a
proposal" loop on its own — every CLI user had to round-trip
through the web feed at messagechain.org to recover the full hash.

CLAUDE.md positioning anchors:

  * "Decentralized reddit/twitter core" framing — the CLI is one of
    the public surfaces this framing has to land on, and a feed
    where you can read but cannot react / vote without leaving the
    CLI is not actually social.

  * Principle #3 (Simplicity) — any place a user must perform an
    extra round-trip to compose the next command is a UX gap.

The fix preserves the truncated visual chip on the header line so
human-scanning the feed still works, and adds a second indented
line carrying the full hash so triple-click + paste recovers the
full 64-hex form.  Same shape applied to ``cmd_proposals``.
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


# ── cmd_read drivers / fixtures ─────────────────────────────────────


def _read_args(**overrides):
    base = dict(
        last=10,
        server="127.0.0.1:9334",
        community_id=None,
        by_address=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


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


def _drive_cmd_read(args, messages):
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


# ── cmd_proposals drivers / fixtures ────────────────────────────────


def _proposals_args(**overrides):
    base = dict(server="127.0.0.1:9334")
    base.update(overrides)
    return argparse.Namespace(**base)


def _proposal(**overrides):
    base = dict(
        proposal_id="aa" * 32,
        proposer_id="bb" * 32,
        title="raise the floor",
        status="open",
        vote_count=2,
        yes_weight=1000,
        total_eligible=2500,
        blocks_remaining=42,
    )
    base.update(overrides)
    return base


def _drive_cmd_proposals(args, proposals):
    from messagechain import cli as cli_mod

    def rpc_side(host, port, method, params):
        if method == "list_proposals":
            return {"ok": True, "result": {"proposals": list(proposals)}}
        return {"ok": True, "result": {}}

    buf = io.StringIO()
    with patch("client.rpc_call", side_effect=rpc_side):
        with redirect_stdout(buf):
            cli_mod.cmd_proposals(args)
    return buf.getvalue()


# ── Tests ───────────────────────────────────────────────────────────


class TestReadFullTxHashCopyable(unittest.TestCase):
    def test_full_tx_hash_present_for_copy_paste(self):
        full = "ab12cd34" + "ef56" * 14  # 64 hex chars
        self.assertEqual(len(full), 64)
        msgs = [_msg(tx_hash=full)]
        out = _drive_cmd_read(_read_args(), msgs)
        self.assertIn(
            full, out,
            "messagechain read must surface the FULL 64-char tx_hash "
            "somewhere in the per-message output so a CLI user can "
            "copy it into `messagechain react --target <tx>` / "
            "`messagechain receipt <tx>` / "
            "`messagechain submit-evidence censorship --receipt <bundle>` "
            "without round-tripping through the web feed.  Pre-fix "
            "the CLI showed only the truncated 12-char prefix and "
            "react / receipt / submit-evidence all reject anything "
            "other than the full 64-hex form.",
        )

    def test_full_tx_hash_appears_only_once_per_message(self):
        full = "11" * 32  # 64 hex chars
        msgs = [_msg(tx_hash=full)]
        out = _drive_cmd_read(_read_args(), msgs)
        # The full form must appear at least once.  Don't pin
        # exactly-once — if a future format wants to redundantly
        # carry the hash on multiple lines that's fine, but a single
        #-message output should not surface the full hash three or
        # more times either (cosmetic).
        self.assertGreaterEqual(out.count(full), 1)
        self.assertLessEqual(
            out.count(full), 2,
            "Full tx_hash should appear at most twice per message "
            "(visible chip + a copy-paste line).  More than that is "
            "noise.",
        )


class TestReadFullPrevHashCopyable(unittest.TestCase):
    def test_full_prev_hash_present_when_pointer_set(self):
        prev_full = "fe" * 32
        msgs = [_msg(prev=prev_full, tx_hash="01" * 32)]
        out = _drive_cmd_read(_read_args(), msgs)
        self.assertIn(
            prev_full, out,
            "When a message carries a `prev` pointer, the FULL 64-char "
            "prev hash must appear so the user can compose `react "
            "--target <prev>` / `receipt <prev>` against the parent "
            "message in a thread without round-tripping through the "
            "web feed.",
        )


class TestProposalsFullProposalIdCopyable(unittest.TestCase):
    def test_full_proposal_id_present_for_copy_paste(self):
        full = "9a" * 32  # 64 hex chars
        proposals = [_proposal(proposal_id=full)]
        out = _drive_cmd_proposals(_proposals_args(), proposals)
        self.assertIn(
            full, out,
            "messagechain proposals must surface the FULL 64-char "
            "proposal_id so a CLI user can copy it into "
            "`messagechain vote --proposal <id>` without round-tripping "
            "through the web feed.  Pre-fix the CLI showed only the "
            "truncated 16-char prefix and `vote --proposal` rejects "
            "anything other than the full form.",
        )


if __name__ == "__main__":
    unittest.main()
