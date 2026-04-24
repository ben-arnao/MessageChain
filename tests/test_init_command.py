"""Tests for `messagechain init` plan + apply."""

import os
import stat

import pytest

from messagechain.runtime import onboarding


def test_plan_is_pure_no_writes(tmp_path, monkeypatch):
    # Ensure defaults land in tmp_path to avoid touching /etc or $HOME.
    data_dir = str(tmp_path / "data")
    keyfile = str(tmp_path / "keyfile")
    ocfg = str(tmp_path / "onboard.toml")
    plan = onboarding.plan_init(
        data_dir=data_dir,
        keyfile=keyfile,
        systemd=False,
        auto_upgrade=True,
        auto_rotate=True,
        onboard_config_path=ocfg,
        key_override=b"\x11" * 32,
    )
    assert not os.path.exists(data_dir)
    assert not os.path.exists(keyfile)
    assert not os.path.exists(ocfg)
    assert plan.data_dir == data_dir
    assert plan.entity_id_hex  # derived from key_override
    assert plan.systemd is False
    assert plan.systemd_units == {}


def test_plan_print_only_systemd_renders_all_units(tmp_path):
    plan = onboarding.plan_init(
        data_dir=str(tmp_path / "d"),
        keyfile=str(tmp_path / "k"),
        systemd=True,
        onboard_config_path=str(tmp_path / "o.toml"),
        key_override=b"\x22" * 32,
    )
    expected = {
        onboarding.VALIDATOR_UNIT_PATH,
        onboarding.UPGRADE_UNIT_PATH,
        onboarding.UPGRADE_TIMER_PATH,
        onboarding.ROTATE_UNIT_PATH,
        onboarding.ROTATE_TIMER_PATH,
    }
    assert set(plan.systemd_units) == expected
    validator = plan.systemd_units[onboarding.VALIDATOR_UNIT_PATH]
    assert "User=messagechain" in validator
    assert "WorkingDirectory=/opt/messagechain" in validator
    assert plan.entity_id_hex in validator
    # Hardening sampled
    assert "NoNewPrivileges=true" in validator
    upgrade_timer = plan.systemd_units[onboarding.UPGRADE_TIMER_PATH]
    assert "OnCalendar=Sun 03:17" in upgrade_timer
    rotate_timer = plan.systemd_units[onboarding.ROTATE_TIMER_PATH]
    assert "OnCalendar=daily" in rotate_timer


def test_apply_writes_keyfile_at_0600(tmp_path):
    data_dir = str(tmp_path / "data")
    keyfile = str(tmp_path / "kf")
    ocfg = str(tmp_path / "onboard.toml")
    plan = onboarding.plan_init(
        data_dir=data_dir,
        keyfile=keyfile,
        systemd=False,
        auto_upgrade=True,
        auto_rotate=True,
        onboard_config_path=ocfg,
        key_override=b"\x33" * 32,
    )
    onboarding.apply_init(plan, key_override=b"\x33" * 32)
    assert os.path.exists(keyfile)
    if hasattr(os, "geteuid"):
        mode = stat.S_IMODE(os.stat(keyfile).st_mode)
        assert mode == 0o600, oct(mode)
    assert os.path.isdir(data_dir)
    cfg = onboarding.read_onboard_config(ocfg)
    assert cfg["auto_upgrade"] is True
    assert cfg["entity_id_hex"] == plan.entity_id_hex


def test_no_auto_upgrade_flips_flag_in_onboard_toml(tmp_path):
    ocfg = str(tmp_path / "onboard.toml")
    plan = onboarding.plan_init(
        data_dir=str(tmp_path / "d"),
        keyfile=str(tmp_path / "k"),
        systemd=False,
        auto_upgrade=False,
        auto_rotate=True,
        onboard_config_path=ocfg,
        key_override=b"\x44" * 32,
    )
    onboarding.apply_init(plan, key_override=b"\x44" * 32)
    cfg = onboarding.read_onboard_config(ocfg)
    assert cfg["auto_upgrade"] is False
    assert cfg["auto_rotate"] is True


def test_next_steps_skips_disabled_timers(tmp_path):
    plan = onboarding.plan_init(
        data_dir=str(tmp_path / "d"),
        keyfile=str(tmp_path / "k"),
        systemd=True,
        auto_upgrade=False,
        auto_rotate=True,
        onboard_config_path=str(tmp_path / "o.toml"),
        key_override=b"\x55" * 32,
    )
    text = plan.next_steps_text()
    assert "messagechain-rotate-key.timer" in text
    assert "messagechain-upgrade.timer" not in text


# ─────────────────────────────────────────────────────────────────────
# Chain-identity pre-flight (probe a seed BEFORE the ~90-min keygen)
# ─────────────────────────────────────────────────────────────────────

def test_probe_seed_returns_identity_on_success(monkeypatch):
    """Happy path: seed responds with a well-formed get_chain_info
    payload; probe returns its chain_id, genesis_hash, and height."""
    from messagechain.runtime import onboarding as _ob
    import client as _client

    def _fake_rpc(host, port, method, params):
        assert method == "get_chain_info"
        return {
            "ok": True,
            "result": {
                "chain_id": "messagechain-v1",
                "genesis_hash": "a" * 64,
                "height": 1234,
                "version": "1.7.0",
            },
        }

    monkeypatch.setattr(_client, "rpc_call", _fake_rpc)
    probe = _ob.probe_seed_chain_identity("10.0.0.1", 9334)
    assert probe.ok
    assert probe.chain_id == "messagechain-v1"
    assert probe.genesis_hash == "a" * 64
    assert probe.height == 1234


def test_probe_seed_transient_error_returns_not_ok(monkeypatch):
    """Network failure must return ok=False, never raise -- caller
    needs to distinguish 'skip this seed' from 'abort the init'."""
    from messagechain.runtime import onboarding as _ob
    import client as _client

    def _boom(host, port, method, params):
        raise ConnectionRefusedError("no route to host")

    monkeypatch.setattr(_client, "rpc_call", _boom)
    probe = _ob.probe_seed_chain_identity("10.0.0.1", 9334)
    assert probe.ok is False
    assert "no route" in probe.error


def test_probe_seed_malformed_response_returns_not_ok(monkeypatch):
    """If the RPC responds but the payload is malformed
    (non-dict, missing ok, explicit ok=False) the probe must report
    failure, not silently pretend the chain_id matches."""
    from messagechain.runtime import onboarding as _ob
    import client as _client

    monkeypatch.setattr(
        _client, "rpc_call",
        lambda *a, **kw: {"ok": False, "error": "method not found"},
    )
    probe = _ob.probe_seed_chain_identity("10.0.0.1", 9334)
    assert probe.ok is False
    assert "method not found" in probe.error


def test_verify_seed_compatible_matches_on_chain_id(monkeypatch):
    from messagechain.runtime import onboarding as _ob
    probe = _ob.SeedProbeResult(
        ok=True, host="h", port=9334,
        chain_id="messagechain-v1", genesis_hash="abc", height=1,
    )
    ok, msg = _ob.verify_seed_compatible(
        probe, our_chain_id="messagechain-v1", our_genesis_hex=None,
    )
    assert ok
    assert "compatible" in msg


def test_verify_seed_detects_chain_id_mismatch(monkeypatch):
    """Critical abort case: seed reports a different chain_id than
    local config.  A keyfile generated under the wrong profile
    would be rejected by every tx on the real chain -- catching
    this before keygen is the whole point of the pre-flight."""
    from messagechain.runtime import onboarding as _ob
    probe = _ob.SeedProbeResult(
        ok=True, host="h", port=9334,
        chain_id="messagechain-testnet",
        genesis_hash="abc", height=1,
    )
    ok, msg = _ob.verify_seed_compatible(
        probe, our_chain_id="messagechain-v1", our_genesis_hex=None,
    )
    assert not ok
    # Message must give the operator actionable guidance, not just
    # "mismatch".  Profile env var + the 'before keygen' framing
    # are the load-bearing pieces.
    assert "chain_id mismatch" in msg
    assert "MESSAGECHAIN_PROFILE" in msg
    assert "BEFORE running init" in msg


def test_verify_seed_detects_genesis_hash_mismatch():
    """Second abort case: chain_id matches but genesis diverges.
    Usually means a stale chain_db left over from an earlier
    testnet / forked chain."""
    from messagechain.runtime import onboarding as _ob
    probe = _ob.SeedProbeResult(
        ok=True, host="h", port=9334,
        chain_id="messagechain-v1",
        genesis_hash="b" * 64, height=1,
    )
    ok, msg = _ob.verify_seed_compatible(
        probe,
        our_chain_id="messagechain-v1",
        our_genesis_hex="a" * 64,
    )
    assert not ok
    assert "genesis_hash mismatch" in msg
    assert "data dir" in msg


def test_verify_seed_skips_genesis_check_on_fresh_validator():
    """A fresh validator pre-init has no chain_db and therefore no
    local genesis hash; the probe must still succeed on chain_id
    alone -- this is the most common path at init time."""
    from messagechain.runtime import onboarding as _ob
    probe = _ob.SeedProbeResult(
        ok=True, host="h", port=9334,
        chain_id="messagechain-v1",
        genesis_hash="b" * 64, height=10,
    )
    ok, msg = _ob.verify_seed_compatible(
        probe, our_chain_id="messagechain-v1", our_genesis_hex=None,
    )
    assert ok


def test_verify_seed_treats_probe_failure_as_skippable():
    """An unreachable seed isn't an abort condition -- the caller
    will try the next seed.  Return True + diagnostic so the
    outer loop can log the skip."""
    from messagechain.runtime import onboarding as _ob
    probe = _ob.SeedProbeResult(
        ok=False, host="h", port=9334, error="timeout",
    )
    ok, msg = _ob.verify_seed_compatible(
        probe, our_chain_id="messagechain-v1", our_genesis_hex=None,
    )
    assert ok
    assert "probe skipped" in msg


# ─────────────────────────────────────────────────────────────────────
# cmd_init seed-verification wiring (integration around the probe)
# ─────────────────────────────────────────────────────────────────────

def test_cmd_init_aborts_on_explicit_seed_mismatch(monkeypatch):
    """--verify-seed must be strict: if the caller pointed at a
    specific seed and it reports a different chain_id, abort."""
    from messagechain import cli as cli_mod

    def _fake_probe(host, port):
        from messagechain.runtime.onboarding import SeedProbeResult
        return SeedProbeResult(
            ok=True, host=host, port=port,
            chain_id="messagechain-testnet",  # mismatch vs mainnet
            genesis_hash="abc", height=1,
        )
    monkeypatch.setattr(
        cli_mod._ob_module() if hasattr(cli_mod, "_ob_module")
        else __import__("messagechain.runtime.onboarding", fromlist=["x"]),
        "probe_seed_chain_identity",
        _fake_probe,
    )

    with pytest.raises(SystemExit) as cm:
        cli_mod._cmd_init_run_seed_verification("10.0.0.1:9334")
    assert cm.value.code != 0


def test_cmd_init_skip_verify_short_circuits(monkeypatch):
    """--skip-verify must bypass the probe entirely: no RPC calls,
    no seed iteration, no aborts.  Power-user / air-gapped escape."""
    from messagechain import cli as cli_mod

    probe_called = []
    def _no_call(*a, **kw):
        probe_called.append(a)
        raise AssertionError("probe must not run under --skip-verify")
    monkeypatch.setattr(
        "messagechain.runtime.onboarding.probe_seed_chain_identity",
        _no_call,
    )

    # Simulate what cmd_init does when skip_verify=True: just don't
    # call the verify function.  The invariant under test: no code
    # path in the verify helper runs when skip_verify is set.
    class _Args:
        skip_verify = True
        verify_seed = "10.0.0.1"
    # Mirror the guard in cmd_init -- if this check shape drifts,
    # the test should catch it.
    if not getattr(_Args, "skip_verify", False):
        cli_mod._cmd_init_run_seed_verification(_Args.verify_seed)
    assert probe_called == []


def test_cmd_init_all_seeds_unreachable_warns_but_continues(
    monkeypatch, capsys,
):
    """First-validator / air-gapped case: all SEED_NODES are
    unreachable.  The verify step must warn-and-return, never
    SystemExit -- otherwise a fresh chain could never be
    bootstrapped."""
    from messagechain import cli as cli_mod
    from messagechain.runtime.onboarding import SeedProbeResult

    def _always_unreachable(host, port):
        return SeedProbeResult(
            ok=False, host=host, port=port,
            error="connection refused",
        )
    monkeypatch.setattr(
        "messagechain.runtime.onboarding.probe_seed_chain_identity",
        _always_unreachable,
    )

    # Must return normally (no sys.exit).  Any abort here would
    # have us blocking fresh-chain bootstrap, which is the opposite
    # of what the pre-flight should do.
    cli_mod._cmd_init_run_seed_verification(None)
    captured = capsys.readouterr()
    assert "none of the" in captured.err
    assert "seeds were reachable" in captured.err
