"""Audit r54 finding 2 -- WOTS+ leaf-reuse RPC reservation chokepoint.

Pre-fix only ``cmd_send`` / ``cmd_transfer`` / ``cmd_stake`` /
``cmd_submit_evidence`` (4 commands) called ``_reserve_leaf_via_rpc`` --
the server-side atomic primitive that closes the cross-process CLI-vs-
daemon race window.  The other ~10 signing commands (``cmd_unstake``,
``cmd_set_authority_key``, ``cmd_rotate_key``, ``cmd_emergency_revoke``,
``cmd_set_receipt_subtree_root``, ``cmd_propose``, ``cmd_vote``,
``cmd_react``, ``cmd_bootstrap_seed``, ``cmd_send_multi_submit``) only
bound the on-disk cursor against the chain watermark -- no RPC
reservation.  Same parallel-paths defect-shape audit r46 #3 closed for
``cmd_send_multi_submit`` (keyfile + first-spend probe), still present
on the leaf-reservation discipline.

The fix introduces a single ``_resolve_signing_leaf`` chokepoint every
signing command routes through.  Bypassing it re-opens the audit r46 #3
defect on whichever new command sidesteps the helper -- the structural
guard below pins this by grepping the cli.py source for any call to
``_bind_persistent_leaf_index`` and asserting it's either inside a
helper definition (one of the chokepoints) or immediately preceded by
``_resolve_signing_leaf`` / ``_reserve_leaf_via_rpc``.

Bite this defect closes: an operator running ``rotate-key`` or
``unstake`` on a typical co-resident validator host could collide with
the daemon's own signing loop -- two WOTS+ signatures at the same leaf
disclose the leaf's private chunks (100% slash on detection).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest.mock import patch

# Helper signature pin -- exists at module scope, used by every
# signing command.
import messagechain.cli as _cli


CLI_PATH = Path(_cli.__file__)


class SigningLeafChokepointExists(unittest.TestCase):
    """Pin the helper's existence and shape so a future refactor can't
    silently drop it."""

    def test_helper_is_defined(self):
        self.assertTrue(
            hasattr(_cli, "_resolve_signing_leaf"),
            "cli._resolve_signing_leaf must exist -- single chokepoint "
            "for WOTS+ leaf reservation across every CLI signing "
            "command.",
        )

    def test_helper_returns_rpc_leaf_when_available(self):
        # When _reserve_leaf_via_rpc returns a real int, the helper
        # MUST return that exact int (the server's atomic reservation
        # wins -- not the fallback).
        class _StubEntity:
            entity_id_hex = "ab" * 32

            class _kp:
                @staticmethod
                def load_leaf_index(_p):
                    pass

                @staticmethod
                def advance_to_leaf(_n):
                    pass

                leaf_index_path = None

            keypair = _kp

        with patch(
            "messagechain.cli._reserve_leaf_via_rpc", return_value=42,
        ):
            with patch(
                "messagechain.cli._bind_persistent_leaf_index",
                return_value=None,
            ) as bind:
                leaf = _cli._resolve_signing_leaf(
                    "localhost", 9000, _StubEntity(),
                    data_dir=None, watermark_fallback=7,
                )
        self.assertEqual(
            leaf, 42,
            "When the server's atomic reservation returns 42, the "
            "helper MUST return 42 (not the fallback 7).  Otherwise "
            "the CLI signs at a stale watermark and the daemon's next "
            "block sign at the reserved leaf collides.",
        )
        bind.assert_called_once()

    def test_helper_falls_back_to_watermark_when_rpc_unavailable(self):
        # _reserve_leaf_via_rpc returns None when the server doesn't
        # implement the RPC (older daemon, no daemon running).  The
        # helper MUST fall back to watermark_fallback so the signing
        # path still gets the chain-watermark safety floor.
        class _StubEntity:
            entity_id_hex = "cd" * 32

            class _kp:
                @staticmethod
                def load_leaf_index(_p):
                    pass

                @staticmethod
                def advance_to_leaf(_n):
                    pass

                leaf_index_path = None

            keypair = _kp

        with patch(
            "messagechain.cli._reserve_leaf_via_rpc", return_value=None,
        ):
            with patch(
                "messagechain.cli._bind_persistent_leaf_index",
                return_value=None,
            ) as bind:
                leaf = _cli._resolve_signing_leaf(
                    "localhost", 9000, _StubEntity(),
                    data_dir=None, watermark_fallback=99,
                )
        self.assertEqual(
            leaf, 99,
            "RPC unavailable: helper must fall back to "
            "watermark_fallback so single-process flow still picks the "
            "correct safety floor.",
        )
        bind.assert_called_once()
        # The bind call must use the resolved leaf (99 in this case),
        # NOT some other value -- the on-disk cursor floor and the
        # signing leaf must agree.
        kwargs = bind.call_args.kwargs
        self.assertEqual(
            int(kwargs.get("chain_leaf", -1)), 99,
            "_bind_persistent_leaf_index must receive the resolved "
            "leaf as chain_leaf.",
        )


class SigningLeafChokepointWidespread(unittest.TestCase):
    """Source-level pin: every CLI signing command that previously
    called ``_bind_persistent_leaf_index`` directly must now route
    through ``_resolve_signing_leaf`` (or call
    ``_reserve_leaf_via_rpc`` itself first, which is the older
    pattern the helper subsumes).

    This is the structural guard against re-introducing the defect:
    a new signing command added in the future that calls
    ``_bind_persistent_leaf_index`` without the chokepoint
    reservation re-opens the cross-process race window.  The check
    runs against the live cli.py source so a copy-paste-driven
    regression is caught at test time, not at slash time.
    """

    def setUp(self):
        self.source = CLI_PATH.read_text(encoding="utf-8")

    def test_helper_is_referenced_by_signing_commands(self):
        # The helper must be CALLED somewhere outside its own
        # definition -- otherwise it shipped dead.  At minimum it
        # should be referenced by ~10 sites (~6 listed in audit r54
        # plus cmd_send_multi_submit/bootstrap_seed/etc.).
        ref_count = self.source.count("_resolve_signing_leaf(")
        # 1 self-reference inside the def line, plus N call sites.
        # Require at least 6 call sites (covers the 6 commands the
        # audit explicitly named: unstake, rotate-key, react, propose,
        # vote, set-authority-key).
        self.assertGreaterEqual(
            ref_count, 1 + 6,
            f"_resolve_signing_leaf has only {ref_count} references "
            f"in cli.py -- expected the definition plus >= 6 call "
            f"sites (cmd_unstake, cmd_rotate_key, cmd_react, "
            f"cmd_propose, cmd_vote, cmd_set_authority_key all need "
            f"to route through it).",
        )

    def test_no_bare_bind_without_rpc_reservation_in_command_bodies(self):
        """No remaining call to ``_bind_persistent_leaf_index`` from a
        ``cmd_*`` function body without a matching chokepoint
        reservation (either ``_resolve_signing_leaf`` or
        ``_reserve_leaf_via_rpc``) above it.

        Carve-outs: the helper definitions themselves
        (``_bind_persistent_leaf_index``, ``_resolve_signing_leaf``)
        contain the bare call; that's correct.  The cold-keyfile path
        in ``cmd_unstake`` and ``cmd_set_receipt_subtree_root`` binds
        the cold-key cursor directly (no RPC reserves the cold key --
        it's not the validator's hot key); that's correct.
        """
        # Split the file into functions (top-level ``def`` blocks).
        funcs = re.split(r"(?m)^def\s+", self.source)
        # First element is everything before the first def; skip.
        offenders = []
        for fn_text in funcs[1:]:
            head_match = re.match(r"([\w_]+)\s*\(", fn_text)
            if not head_match:
                continue
            fn_name = head_match.group(1)
            if not fn_name.startswith("cmd_"):
                continue
            # Find every _bind_persistent_leaf_index call within this
            # function body.
            for m in re.finditer(
                r"_bind_persistent_leaf_index\s*\(", fn_text,
            ):
                # Look backward in the same function body for a
                # chokepoint reservation reference.  Either
                # ``_resolve_signing_leaf`` or ``_reserve_leaf_via_rpc``
                # within ~80 lines above the bind call counts.
                head = fn_text[: m.start()]
                # Carve-outs: cold-key paths bind directly (the cold
                # key is operator-held, not RPC-managed).
                lines_above = head.splitlines()[-80:]
                window = "\n".join(lines_above)
                window_lower = window.lower()
                if (
                    "_resolve_signing_leaf(" in window
                    or "_reserve_leaf_via_rpc(" in window
                    # Cold-key paths bind the cold-key cursor directly.
                    # Cold keys are operator-held, not validator-daemon-
                    # managed, so the CLI-vs-daemon race window the
                    # chokepoint defends does not apply.  Detect via:
                    #   - explicit ``cold_leaf`` arg (cmd_unstake hot-
                    #     bypass path + cmd_set_receipt_subtree_root)
                    #   - explicit ``cold-key`` comment marker
                    #     (cmd_emergency_revoke)
                    or "cold_leaf" in window
                    or "cold-key cross-process" in window_lower
                ):
                    continue
                offenders.append(fn_name)
        self.assertEqual(
            sorted(set(offenders)), [],
            f"CLI signing commands still call _bind_persistent_leaf_index "
            f"without a chokepoint reservation: {sorted(set(offenders))}. "
            f"Each must route through _resolve_signing_leaf (or call "
            f"_reserve_leaf_via_rpc first) so the cross-process WOTS+ "
            f"leaf-reuse race window is closed.",
        )


if __name__ == "__main__":
    unittest.main()
