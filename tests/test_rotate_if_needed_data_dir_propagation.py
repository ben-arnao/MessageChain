"""Regression: ``cmd_rotate_key_if_needed`` must propagate ``data_dir``
from ``onboard.toml`` into the synthesised ``Namespace`` it hands to
``cmd_rotate_key``.

Pre-fix the timer command built ``Namespace(server, yes, fee, keyfile)``
with no ``data_dir`` field, so ``cmd_rotate_key`` read
``getattr(args, "data_dir", None) -> None``.  The leaf-cursor resolver
(_resolve_leaf_index_path) then routed the timer's WOTS+ cursor to
``~/.messagechain/leaves/<entity>.idx`` while the running validator
daemon kept persisting to ``<data_dir>/leaf_index.json``.  Two cursors,
no fsync handshake — the timer would re-sign at a leaf the daemon had
already burned, producing equivocation evidence on chain.  The
``_reserve_leaf_via_rpc`` best-effort fallback is the ONLY thing that
prevented the slash, and it silently returns None on transient RPC
errors and on older daemons.

This test asserts the timer-side Namespace carries the cfg-derived
``data_dir`` into ``cmd_rotate_key`` so the leaf cursor used by the
unattended timer matches the daemon's cursor exactly.
"""

import argparse
import sys
import types

import pytest

from messagechain import cli as cli_mod
from messagechain.runtime import onboarding


def test_timer_namespace_includes_data_dir(monkeypatch):
    captured = {}

    def fake_cmd_rotate_key(ns):
        captured["data_dir"] = getattr(ns, "data_dir", "<missing>")
        captured["keyfile"] = getattr(ns, "keyfile", None)
        captured["server"] = getattr(ns, "server", None)
        captured["yes"] = getattr(ns, "yes", None)

    def fake_read_onboard_config(path=None):
        return {
            "entity_id_hex": "ab" * 32,
            "data_dir": "/var/lib/messagechain",
            "keyfile": "/etc/messagechain/keyfile",
        }

    def fake_rpc_call(host, port, method, params):
        if method == "get_leaf_watermark":
            return {"ok": True, "result": {"leaf_watermark": 1 << 19}}
        if method == "get_entity":
            return {"ok": True, "result": {"tree_height": 20}}
        if method == "get_authority_key":
            return {
                "ok": True,
                "result": {"authority_pubkey": None, "public_key": None},
            }
        return {"ok": True, "result": {}}

    def fake_run_rotate_if_needed(
        *, watermark_fetcher, has_cold_authority_key, tree_height,
        rotate_impl, printer=print,
    ):
        rotate_impl()
        return 0

    monkeypatch.setattr(onboarding, "read_onboard_config", fake_read_onboard_config)
    monkeypatch.setattr(onboarding, "run_rotate_if_needed", fake_run_rotate_if_needed)
    import client as client_mod
    monkeypatch.setattr(client_mod, "rpc_call", fake_rpc_call)
    monkeypatch.setattr(cli_mod, "cmd_rotate_key", fake_cmd_rotate_key)

    args = argparse.Namespace(server=None, keyfile=None)
    with pytest.raises(SystemExit) as exc:
        cli_mod.cmd_rotate_key_if_needed(args)
    assert exc.value.code == 0

    assert captured["data_dir"] == "/var/lib/messagechain", (
        "cmd_rotate_key_if_needed must propagate data_dir from "
        "onboard.toml into the cmd_rotate_key Namespace; got "
        f"{captured.get('data_dir')!r}"
    )
    assert captured["keyfile"] == "/etc/messagechain/keyfile"


def test_timer_namespace_data_dir_path_matches_daemon_cursor(monkeypatch, tmp_path):
    """Tighter end-to-end assertion: the path resolver invoked with the
    timer-synthesised data_dir must produce the daemon's
    ``<data_dir>/leaf_index.json`` path, not the per-user fallback at
    ``~/.messagechain/leaves/<entity>.idx``.
    """
    daemon_data_dir = str(tmp_path / "var-lib-messagechain")

    captured = {}

    def fake_cmd_rotate_key(ns):
        from messagechain.config import LEAF_INDEX_FILENAME
        from pathlib import Path
        ddir = getattr(ns, "data_dir", None)
        captured["resolved_path"] = (
            Path(ddir) / LEAF_INDEX_FILENAME if ddir else None
        )

    def fake_read_onboard_config(path=None):
        return {
            "entity_id_hex": "cd" * 32,
            "data_dir": daemon_data_dir,
            "keyfile": "/etc/messagechain/keyfile",
        }

    def fake_rpc_call(host, port, method, params):
        if method == "get_leaf_watermark":
            return {"ok": True, "result": {"leaf_watermark": 1 << 19}}
        if method == "get_entity":
            return {"ok": True, "result": {"tree_height": 20}}
        if method == "get_authority_key":
            return {
                "ok": True,
                "result": {"authority_pubkey": None, "public_key": None},
            }
        return {"ok": True, "result": {}}

    def fake_run_rotate_if_needed(
        *, watermark_fetcher, has_cold_authority_key, tree_height,
        rotate_impl, printer=print,
    ):
        rotate_impl()
        return 0

    monkeypatch.setattr(onboarding, "read_onboard_config", fake_read_onboard_config)
    monkeypatch.setattr(onboarding, "run_rotate_if_needed", fake_run_rotate_if_needed)
    import client as client_mod
    monkeypatch.setattr(client_mod, "rpc_call", fake_rpc_call)
    monkeypatch.setattr(cli_mod, "cmd_rotate_key", fake_cmd_rotate_key)

    args = argparse.Namespace(server=None, keyfile=None)
    with pytest.raises(SystemExit) as exc:
        cli_mod.cmd_rotate_key_if_needed(args)
    assert exc.value.code == 0

    from messagechain.config import LEAF_INDEX_FILENAME
    from pathlib import Path
    expected = Path(daemon_data_dir) / LEAF_INDEX_FILENAME
    assert captured["resolved_path"] == expected, (
        f"timer's leaf cursor path {captured['resolved_path']} must "
        f"equal the daemon's cursor path {expected}; pre-fix the timer "
        "routed to the per-user fallback ~/.messagechain/leaves/<entity>.idx"
    )
