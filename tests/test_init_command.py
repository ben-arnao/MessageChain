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
