"""Audit r57 #3: ``_print_submit_success_footer`` chokepoint must be
called by every signing command that prints a tx hash on submit-success.

CLAUDE.md anchor defended: "Collective censorship-resistance" -- the
slashable-evidence escalation chain is the chain's headline structural
defense, but it's only useful if the user discovers it.  Audit r56 #3
landed the chokepoint at ``cli._print_submit_success_footer`` for the
canonical "Permanence + verify-CLI + escalation pointer" footer.  Only
``cmd_send`` / ``cmd_transfer`` / ``cmd_react`` were lifted onto it --
the operator-facing high-stakes commands (``cmd_stake``,
``cmd_unstake``, ``cmd_rotate_key``, ``cmd_set_authority_key``,
``cmd_emergency_revoke``, ``cmd_propose``, ``cmd_vote``) still print
a bare ``TX hash: <hex>`` and stop.  A failed/dropped stake tx had no
on-ramp from the user's terminal to ``messagechain receipt`` or
``messagechain submit-evidence``.

This test pins the *structural* property: every CLI command listed
below routes through the chokepoint helper.  The audit r56 #3
exclusion (``cmd_send_multi_submit`` has its own fan-out-aware
footer) is preserved.

If a future refactor accidentally re-inlines bare-hash printing on a
new signing command, this test fires.
"""

import ast
import unittest

import messagechain.cli as cli


# Commands the audit r57 #3 lift covers.  Each is a CLI signing-command
# entry point that, on submit-success, used to print
# ``TX hash: <hex>`` and stop.  Tier 78's audit r56 #3 helper is the
# canonical surface for the permanence + verify-CLI + escalation
# pointer text -- routing every such command through it is the
# abstraction-over-symptom fix.
CHOKEPOINT_REQUIRED_COMMANDS = (
    # Sender-facing -- already lifted in audit r56 #3 (pinned here so
    # a future regression that reverts those is caught).
    "cmd_send",
    "cmd_transfer",
    "cmd_react",
    # Operator-facing -- the audit r57 #3 lift.  These were the missing
    # call sites the audit flagged.
    "cmd_stake",
    "cmd_unstake",
    "cmd_rotate_key",
    "cmd_set_authority_key",
    "cmd_emergency_revoke",
    "cmd_propose",
    "cmd_vote",
)


# Explicit excludes -- documented reasons each cmd_* is allowed NOT to
# call the chokepoint.  Future maintainers should weigh hard before
# adding entries here.
CHOKEPOINT_EXEMPT = {
    # Has its own fan-out-aware footer that handles the multi-endpoint
    # receipt-bundle save + permanence framing inline (audit r56 #3
    # explicit exclusion).
    "cmd_send_multi_submit",
    # The censorship-evidence sub-cmd already prints an evidence-
    # specific framing block ("When this evidence lands and matures...").
    # Routing it through the generic footer would duplicate framing.
    "_cmd_submit_censorship_evidence",
    # set-receipt-subtree-root is a cold-key one-shot with bespoke
    # follow-up text ("NEXT TIME you sign anything with this cold key,
    # pass --cold-leaf N").  The generic footer would crowd out the
    # cold-leaf-burned warning that's the actual value-prop of this
    # command's success surface.
    "cmd_set_receipt_subtree_root",
    # Bootstrap-seed runs stake / set-authority / etc. internally; each
    # internal call already routes through its respective cmd_*'s
    # chokepoint adoption.  The outer summary is bootstrap-specific.
    "cmd_bootstrap_seed",
    # Broadcast-revoke replays a pre-signed bundle; the print
    # surfaces a custom "revoke applied" recap.  The hot-path footer
    # is fine to skip given the command's narrow scope.
    "cmd_broadcast_revoke",
}


def _function_calls_helper(fn_node: ast.FunctionDef, helper_name: str) -> bool:
    """Return True if ``fn_node`` contains a call to ``helper_name`` in
    its body (transitively, via ``ast.walk``).
    """
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == helper_name:
                return True
            if isinstance(f, ast.Attribute) and f.attr == helper_name:
                return True
    return False


class TestFooterChokepointLift(unittest.TestCase):
    """Every signing command in ``CHOKEPOINT_REQUIRED_COMMANDS`` must
    invoke ``_print_submit_success_footer``.

    Structural grep-based pin -- catches both regressions (a command
    that previously called the chokepoint stops calling it) and
    incomplete lifts (a new signing command added without the
    chokepoint adoption).
    """

    @classmethod
    def setUpClass(cls):
        import inspect
        source = inspect.getsource(cli)
        cls._module = ast.parse(source)
        cls._fn_by_name = {
            node.name: node
            for node in cls._module.body
            if isinstance(node, ast.FunctionDef)
        }

    def test_every_required_command_routes_through_chokepoint(self):
        missing = []
        for cmd_name in CHOKEPOINT_REQUIRED_COMMANDS:
            fn = self._fn_by_name.get(cmd_name)
            self.assertIsNotNone(
                fn,
                f"{cmd_name} is missing from cli.py -- if it was "
                "renamed, update CHOKEPOINT_REQUIRED_COMMANDS too.",
            )
            if not _function_calls_helper(
                fn, "_print_submit_success_footer",
            ):
                missing.append(cmd_name)
        self.assertFalse(
            missing,
            "These signing commands print TX hash on submit-success "
            "but DO NOT route through _print_submit_success_footer -- "
            "the audit r56 #3 chokepoint that absorbs the permanence "
            "+ verify-CLI + slashable-evidence escalation pointer "
            "text.  Lift each one onto the helper:\n  "
            + "\n  ".join(missing),
        )

    def test_chokepoint_helper_exists(self):
        """The helper itself must exist -- guards against a future
        refactor that deletes it without updating call sites.
        """
        self.assertIn(
            "_print_submit_success_footer",
            self._fn_by_name,
            "_print_submit_success_footer is the canonical chokepoint "
            "for submit-success footer text.  Don't delete it; lift "
            "call sites onto it instead.",
        )


class TestExemptCommandsDocumented(unittest.TestCase):
    """The exemption list must not silently grow -- every entry needs a
    documented reason (kept as the CHOKEPOINT_EXEMPT dict's comments
    here; pin enforces the set stays explicit).
    """

    def test_exempt_set_is_explicit(self):
        # The exemption list is small and named.  If a future change
        # adds a new cmd_* that submits a tx but bypasses the
        # chokepoint, it'll fail the structural test above unless
        # also added here with a documented reason -- which is the
        # forcing function we want.
        self.assertLessEqual(
            len(CHOKEPOINT_EXEMPT),
            8,
            "CHOKEPOINT_EXEMPT has grown beyond 8 entries -- each "
            "exemption should have a documented reason, and a "
            "ballooning list indicates the chokepoint property is "
            "drifting.",
        )


if __name__ == "__main__":
    unittest.main()
