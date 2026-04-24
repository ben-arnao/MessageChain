"""Tests for the upgrade flow — mocks git + pip + health check."""

import pytest

from messagechain.runtime import onboarding


def test_parse_version_tag_good_cases():
    assert onboarding._parse_version_tag("v1.2.3-mainnet") == (1, 2, 3)
    assert onboarding._parse_version_tag("v0.0.1-mainnet") == (0, 0, 1)


def test_parse_version_tag_rejects_non_mainnet():
    assert onboarding._parse_version_tag("v1.2.3-testnet") is None
    assert onboarding._parse_version_tag("v1.2-mainnet") is None
    assert onboarding._parse_version_tag("") is None
    assert onboarding._parse_version_tag("random") is None


def test_resolve_latest_tag_from_api_picks_highest():
    data = [
        {"tag_name": "v1.0.0-mainnet"},
        {"tag_name": "v1.2.2-mainnet"},
        {"tag_name": "v1.1.5-mainnet"},
        {"tag_name": "v2.0.0-testnet"},
        {"tag_name": "v1.3.0-rc1"},
    ]
    assert onboarding.resolve_latest_tag_from_api(data) == "v1.2.2-mainnet"


def test_resolve_latest_tag_from_api_ignores_drafts():
    data = [
        {"tag_name": "v2.0.0-mainnet", "draft": True},
        {"tag_name": "v1.5.0-mainnet", "prerelease": True},
        {"tag_name": "v1.2.0-mainnet"},
    ]
    assert onboarding.resolve_latest_tag_from_api(data) == "v1.2.0-mainnet"


def test_upgrade_noop_when_already_latest():
    output = []
    rc = onboarding.run_upgrade(
        installed_version="1.2.3",
        latest_tag_fetcher=lambda: "v1.2.3-mainnet",
        shell_runner=lambda cmd: 0,
        health_check=lambda: True,
        printer=output.append,
    )
    assert rc == 0
    assert any("already up to date" in s for s in output)


def test_upgrade_noop_even_when_installed_is_newer():
    output = []
    rc = onboarding.run_upgrade(
        installed_version="1.3.0",
        latest_tag_fetcher=lambda: "v1.2.3-mainnet",
        shell_runner=lambda cmd: 0,
        health_check=lambda: True,
        printer=output.append,
    )
    assert rc == 0


def test_upgrade_rollback_on_health_check_failure():
    calls = []
    health_calls = [False]  # first post-restart fails

    def runner(cmd):
        calls.append(cmd)
        return 0

    def health():
        return False

    rc = onboarding.run_upgrade(
        installed_version="1.2.2",
        latest_tag_fetcher=lambda: "v1.2.3-mainnet",
        shell_runner=runner,
        health_check=health,
        printer=lambda *a, **k: None,
    )
    assert rc == 2
    # Must contain a checkout of target then a rollback checkout of previous.
    checkouts = [c for c in calls if c[:2] == ["git", "checkout"]]
    assert len(checkouts) >= 2
    assert checkouts[0] == ["git", "checkout", "v1.2.3-mainnet"]
    assert checkouts[-1] == ["git", "checkout", "v1.2.2-mainnet"]


def test_upgrade_tag_override_skips_fetcher():
    output = []
    rc = onboarding.run_upgrade(
        installed_version="1.2.3",
        latest_tag_fetcher=lambda: (_ for _ in ()).throw(RuntimeError("should not run")),
        tag_override="v1.2.3-mainnet",
        shell_runner=lambda cmd: 0,
        health_check=lambda: True,
        printer=output.append,
    )
    assert rc == 0


def test_upgrade_shell_step_failure_stops_flow():
    calls = []

    def runner(cmd):
        calls.append(cmd)
        return 0 if cmd[0] == "git" and cmd[1] in ("fetch", "stash") else 5

    rc = onboarding.run_upgrade(
        installed_version="1.2.2",
        latest_tag_fetcher=lambda: "v1.2.3-mainnet",
        shell_runner=runner,
        health_check=lambda: True,
        printer=lambda *a, **k: None,
    )
    assert rc == 5
