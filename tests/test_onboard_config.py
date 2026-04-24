"""Round-trip + edit tests for onboard.toml."""

import os
import tempfile

import pytest

from messagechain.runtime import onboarding


def test_read_missing_returns_defaults(tmp_path):
    cfg = onboarding.read_onboard_config(str(tmp_path / "nope.toml"))
    assert cfg["auto_upgrade"] is True
    assert cfg["auto_rotate"] is True
    assert cfg["data_dir"] == ""
    assert cfg["keyfile"] == ""
    assert cfg["entity_id_hex"] == ""


def test_roundtrip_write_read(tmp_path):
    path = str(tmp_path / "onboard.toml")
    onboarding.write_onboard_config(path, {
        "auto_upgrade": False,
        "auto_rotate": True,
        "data_dir": "/var/lib/messagechain",
        "keyfile": "/etc/messagechain/keyfile",
        "entity_id_hex": "deadbeef" * 8,
    })
    cfg = onboarding.read_onboard_config(path)
    assert cfg["auto_upgrade"] is False
    assert cfg["auto_rotate"] is True
    assert cfg["data_dir"] == "/var/lib/messagechain"
    assert cfg["keyfile"] == "/etc/messagechain/keyfile"
    assert cfg["entity_id_hex"] == "deadbeef" * 8


def test_config_set_updates_single_key(tmp_path):
    path = str(tmp_path / "onboard.toml")
    onboarding.write_onboard_config(path, {"auto_upgrade": True})
    onboarding.config_set("auto_upgrade", "false", path=path)
    cfg = onboarding.read_onboard_config(path)
    assert cfg["auto_upgrade"] is False


def test_config_set_unknown_key_raises(tmp_path):
    path = str(tmp_path / "onboard.toml")
    with pytest.raises(KeyError):
        onboarding.config_set("bogus", "x", path=path)


def test_config_get_unknown_key_raises(tmp_path):
    with pytest.raises(KeyError):
        onboarding.config_get("bogus")


def test_env_var_overrides_search_path(tmp_path, monkeypatch):
    custom = str(tmp_path / "custom.toml")
    onboarding.write_onboard_config(custom, {"auto_rotate": False})
    monkeypatch.setenv(onboarding.ENV_ONBOARD_CONFIG, custom)
    resolved = onboarding.resolve_onboard_config_path()
    assert resolved == custom
    cfg = onboarding.read_onboard_config()
    assert cfg["auto_rotate"] is False
