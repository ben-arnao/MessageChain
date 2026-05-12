"""
Tests for audit r48 #3 — every signing CLI command must resolve its
submission fee through the server's live admission floor, not a stale
local-computed constant.

Pre-fix only ``cmd_transfer`` (audit r45 #2) consulted ``server_min_fee``.
Every other signing command -- ``cmd_send``, ``cmd_react``, ``cmd_stake``,
``cmd_unstake``, ``cmd_propose``, ``cmd_vote``, ``cmd_rotate_key``,
``cmd_send_multi_submit`` -- either validated explicit ``--fee`` against
a local constant (``calculate_min_fee``, ``KEY_ROTATION_FEE``,
``GOVERNANCE_VOTE_FEE``, ``proposal_fee_floor``) or skipped the floor
check entirely.

The recurrence-pattern audit r45 #2 closed for transfer is the
abstraction this round generalises across every signing command via
``_resolve_fee_with_server_floor``.

CLAUDE.md anchors at risk pre-fix:
  * Dual-purpose-token / mainstream-asset quality bar — wallet,
    transfer, stake, and governance code held to mainstream-asset
    standards.
  * "When the fee model shifts, every auto-fee path shifts with it
    -- don't leave a tx kind defaulting to a stale flat fee while
    others auto-bid by density."
"""

import inspect
import unittest

from messagechain import cli


class TestResolveFeeWithServerFloorHelper(unittest.TestCase):
    """The helper exists and is referenced from every non-transfer
    signing command."""

    def test_helper_is_defined(self):
        self.assertTrue(
            hasattr(cli, "_resolve_fee_with_server_floor"),
            "cli must export _resolve_fee_with_server_floor for "
            "every signing command to share.",
        )
        fn = cli._resolve_fee_with_server_floor
        sig = inspect.signature(fn)
        # The helper should take the kind, host, port, args, plus
        # optional estimate-payload / auto-fee-kwarg extras.
        params = sig.parameters
        self.assertIn("kind", params)
        self.assertIn("host", params)
        self.assertIn("port", params)
        self.assertIn("args", params)


class TestSigningCommandsUseHelper(unittest.TestCase):
    """Structural: every non-transfer signing command must route its
    fee-resolution path through ``_resolve_fee_with_server_floor``.

    This is the abstraction-over-symptom check: a future signing
    command added without going through this helper would re-introduce
    the audit r48 #3 defect.
    """

    SIGNING_COMMANDS = [
        "cmd_send",
        "cmd_react",
        "cmd_stake",
        "cmd_unstake",
        "cmd_propose",
        "cmd_vote",
        "cmd_rotate_key",
        "cmd_send_multi_submit",
    ]

    def test_every_signing_command_calls_helper(self):
        for name in self.SIGNING_COMMANDS:
            fn = getattr(cli, name, None)
            self.assertIsNotNone(
                fn, f"cli has no command function named {name!r}",
            )
            src = inspect.getsource(fn)
            self.assertIn(
                "_resolve_fee_with_server_floor", src,
                f"{name} does not route through "
                "_resolve_fee_with_server_floor — explicit --fee "
                "validation will use a stale local constant instead "
                "of the server's live floor (audit r48 #3).",
            )


class TestNoStaleLocalConstantFeeCompare(unittest.TestCase):
    """The legacy ``fee < local_min`` / ``fee < KEY_ROTATION_FEE`` /
    ``fee < GOVERNANCE_VOTE_FEE`` / etc. compares — the exact code
    shapes audit r48 #3 flagged — must be gone from the signing
    commands.  ``fee < server_min_fee`` is the only acceptable shape;
    it lives inside the helper.
    """

    def test_no_stale_local_constant_compare_in_signing_commands(self):
        bad_patterns_per_cmd = {
            "cmd_send": ["fee < local_min"],
            "cmd_rotate_key": ["fee < KEY_ROTATION_FEE"],
            "cmd_vote": ["fee < GOVERNANCE_VOTE_FEE"],
        }
        for name, patterns in bad_patterns_per_cmd.items():
            fn = getattr(cli, name)
            src = inspect.getsource(fn)
            for pat in patterns:
                self.assertNotIn(
                    pat, src,
                    f"{name} still compares explicit --fee against "
                    f"a stale local constant ({pat!r}). Use the "
                    "server's live floor via "
                    "_resolve_fee_with_server_floor instead.",
                )


if __name__ == "__main__":
    unittest.main()
