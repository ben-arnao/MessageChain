"""Regression: ``resolve_defaults`` must propagate ``data_dir`` from
``onboard.toml`` into signing commands when the operator did not pass
``--data-dir`` explicitly.

Same defect class as the 1.57.0 rotate-key-if-needed timer fix
(commit c724327): ``cmd_stake`` / ``cmd_unstake`` / ``cmd_rotate_key``
all read ``getattr(args, "data_dir", None)`` and pass it directly to
``_bind_persistent_leaf_index``, which uses it as the leaf-cursor
location.  When ``args.data_dir`` is None the cursor lands at the
per-user fallback ``~/.messagechain/leaves/<entity>.idx`` while the
running validator daemon persists to ``<onboard.data_dir>/leaf_index.json``.
Two cursors with no fsync handshake → cross-process WOTS+ leaf reuse →
equivocation evidence on chain → 100% slash on detection (or geometric
soft-slash post-Tier-20).

This is the README's exact validator-bootstrap path.  Step 3 of
"Run a validator" is `messagechain stake --amount 200` with no
``--data-dir``.  Same disaster slot the rotate-key-if-needed timer fix
prevented; previously left open on the manual signing path.

Anchored in CLAUDE.md:
  - "Honest operators are insured against accidents."  Manual
    invocation of a signing command on a validator host MUST NOT
    re-open a slashable equivocation window.
  - "Smart-defaults coverage.  Any place a user must pick a value
    the system could pick correctly is a defect."

The fix lives in ``cli.resolve_defaults``: for the known set of
signing commands, if ``args.data_dir`` is None and ``onboard.toml``
carries a ``data_dir`` key, fill it in.  Operator's explicit
``--data-dir`` always wins.

These tests MUST fail on current main and pass after the fix.
"""

from __future__ import annotations

import argparse

import pytest

from messagechain import cli as cli_mod
from messagechain.runtime import onboarding


SIGNING_COMMANDS = ("stake", "unstake", "rotate-key")


@pytest.fixture
def fake_onboard(monkeypatch):
    """Default fixture: onboard.toml carries a data_dir."""
    def _read(path=None):
        return {
            "entity_id_hex": "ab" * 32,
            "data_dir": "/var/lib/messagechain",
        }
    monkeypatch.setattr(onboarding, "read_onboard_config", _read)


@pytest.mark.parametrize("cmd", SIGNING_COMMANDS)
def test_signing_cmd_data_dir_falls_back_to_onboard_toml(
    fake_onboard, cmd,
):
    """For each signing command the operator launches manually,
    ``resolve_defaults`` MUST fill ``args.data_dir`` from onboard.toml
    when the operator did not pass ``--data-dir``.  Pre-fix the manual
    path leaks the leaf cursor to the per-user fallback while the
    daemon persists to ``<onboard.data_dir>/leaf_index.json`` —
    exactly the cross-process WOTS+ leaf-reuse window the
    rotate-key-if-needed fix closed for the timer."""
    args = argparse.Namespace(command=cmd, data_dir=None)
    cli_mod.resolve_defaults(args)
    assert args.data_dir == "/var/lib/messagechain", (
        f"{cmd}: args.data_dir MUST fall back to onboard.toml "
        "data_dir when --data-dir is unset.  Without this, the "
        "manual signing path on a validator host re-opens the "
        "WOTS+ leaf-reuse equivocation window."
    )


@pytest.mark.parametrize("cmd", SIGNING_COMMANDS)
def test_explicit_data_dir_arg_overrides_onboard_toml(fake_onboard, cmd):
    """Explicit ``--data-dir`` MUST always win over onboard.toml.
    Operator who passes ``--data-dir /foo`` deliberately is opting
    out of the daemon-coresident path (e.g., test rig, alternative
    cursor location)."""
    args = argparse.Namespace(command=cmd, data_dir="/explicit/override")
    cli_mod.resolve_defaults(args)
    assert args.data_dir == "/explicit/override", (
        f"{cmd}: explicit --data-dir MUST override onboard.toml fallback."
    )


@pytest.mark.parametrize("cmd", SIGNING_COMMANDS)
def test_no_onboard_toml_keeps_data_dir_none(monkeypatch, cmd):
    """Personal-wallet path (no onboard.toml, or onboard.toml without
    a data_dir key): fallback is a no-op, args.data_dir stays None,
    leaf cursor uses ``~/.messagechain/leaves/<entity>.idx``."""
    monkeypatch.setattr(
        onboarding, "read_onboard_config", lambda path=None: {},
    )
    args = argparse.Namespace(command=cmd, data_dir=None)
    cli_mod.resolve_defaults(args)
    assert args.data_dir is None, (
        f"{cmd}: empty onboard.toml MUST leave args.data_dir as None "
        "so personal-wallet path stays on the per-user fallback."
    )


def test_non_signing_cmd_not_affected(fake_onboard):
    """A command without a ``--data-dir`` flag in its parser doesn't
    have the attribute.  ``resolve_defaults`` MUST NOT inject it on
    commands that aren't in the signing set — otherwise downstream
    code that treats data_dir presence as a marker would get a
    surprise value from onboard.toml.

    Concretely we use a chain-state read command (``info``) — it
    has no data_dir attribute on the namespace.
    """
    args = argparse.Namespace(command="info")
    cli_mod.resolve_defaults(args)
    assert not hasattr(args, "data_dir") or args.data_dir is None, (
        "Non-signing command MUST NOT have data_dir injected from "
        "onboard.toml — only signing commands route through "
        "_bind_persistent_leaf_index and need the daemon-coresident "
        "cursor."
    )


def test_start_command_default_unaffected(fake_onboard):
    """``start`` already has its own data_dir default
    (``~/.messagechain/chaindata``).  The signing-command fallback
    must NOT inject onboard.toml data_dir for ``start`` — that would
    quietly reroute the daemon's chaindata location, which the
    operator explicitly specified at install time."""
    args = argparse.Namespace(command="start", data_dir=None)
    cli_mod.resolve_defaults(args)
    # start's own default fires when args.data_dir is None.
    import os
    expected = os.path.join(
        os.path.expanduser("~"), ".messagechain", "chaindata",
    )
    assert args.data_dir == expected, (
        f"start: data_dir must keep the existing per-user default "
        f"({expected}), not the onboard.toml signing-command fallback."
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
