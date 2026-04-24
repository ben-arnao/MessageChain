"""Tests for the `doctor` preflight runner."""

import os
import stat
from collections import namedtuple

import pytest

from messagechain.runtime import onboarding


_Usage = namedtuple("_Usage", "total used free")


def _mk_keyfile(path, mode=0o600):
    with open(path, "w") as f:
        f.write("a" * 72)
    os.chmod(path, mode)


def test_doctor_green_all_checks_pass(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    keyfile = tmp_path / "kf"
    _mk_keyfile(str(keyfile))

    cfg = {
        "auto_upgrade": False,
        "auto_rotate": False,
        "data_dir": str(data_dir),
        "keyfile": str(keyfile),
        "entity_id_hex": "",
    }
    worst, checks = onboarding.run_doctor(
        cfg,
        seeds=[("127.0.0.1", 1)],
        bind_fn=lambda port: (True, ""),
        connect_fn=lambda host, port: True,
        disk_usage_fn=lambda p: _Usage(100 * 2**30, 0, 50 * 2**30),
    )
    if worst != 0:
        # Surface what failed for debuggability.
        for c in checks:
            if c.level > 0:
                print(c.label, c.status, c.detail)
    # On POSIX with correct perms this should be green; on Windows the
    # keyfile mode check may warn — accept 0 or 1, never 2.
    assert worst <= 1, [
        (c.label, c.level, c.status, c.detail) for c in checks if c.level == 2
    ]


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX-only perm check")
def test_doctor_fails_on_bad_keyfile_perms(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    keyfile = tmp_path / "kf"
    _mk_keyfile(str(keyfile), mode=0o644)

    cfg = {
        "auto_upgrade": False, "auto_rotate": False,
        "data_dir": str(data_dir), "keyfile": str(keyfile),
        "entity_id_hex": "",
    }
    worst, checks = onboarding.run_doctor(
        cfg,
        seeds=[("127.0.0.1", 1)],
        bind_fn=lambda port: (True, ""),
        connect_fn=lambda host, port: True,
        disk_usage_fn=lambda p: _Usage(100 * 2**30, 0, 50 * 2**30),
    )
    assert worst == 2
    kf_checks = [c for c in checks if c.label == "keyfile"]
    assert kf_checks and kf_checks[0].level == 2


def test_doctor_warns_on_low_disk(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    keyfile = tmp_path / "kf"
    _mk_keyfile(str(keyfile))

    cfg = {
        "auto_upgrade": False, "auto_rotate": False,
        "data_dir": str(data_dir), "keyfile": str(keyfile),
        "entity_id_hex": "",
    }
    worst, checks = onboarding.run_doctor(
        cfg,
        seeds=[("127.0.0.1", 1)],
        bind_fn=lambda port: (True, ""),
        connect_fn=lambda host, port: True,
        # 4 GB free → warn (<5), not fail (<2).
        disk_usage_fn=lambda p: _Usage(10 * 2**30, 0, 4 * 2**30),
    )
    disk_checks = [c for c in checks if c.label == "disk free"]
    assert disk_checks and disk_checks[0].level == 1
    assert worst >= 1


def test_doctor_fails_on_unreachable_seeds(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    keyfile = tmp_path / "kf"
    _mk_keyfile(str(keyfile))

    cfg = {
        "auto_upgrade": False, "auto_rotate": False,
        "data_dir": str(data_dir), "keyfile": str(keyfile),
        "entity_id_hex": "",
    }
    worst, checks = onboarding.run_doctor(
        cfg,
        seeds=[("127.0.0.1", 1), ("127.0.0.2", 2)],
        bind_fn=lambda port: (True, ""),
        connect_fn=lambda host, port: False,
        disk_usage_fn=lambda p: _Usage(100 * 2**30, 0, 50 * 2**30),
    )
    seed_checks = [c for c in checks if c.label == "seeds"]
    assert seed_checks and seed_checks[0].level == 2
    assert worst == 2
