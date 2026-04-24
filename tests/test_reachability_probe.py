"""Tests for the start-time reachability probe."""

import pytest

from messagechain.runtime import onboarding


def test_skip_via_env_var(monkeypatch):
    monkeypatch.setenv(onboarding.ENV_SKIP_REACHABILITY, "1")
    level, detail = onboarding.run_reachability_probe(9333)
    assert level == 0
    assert "skipped" in detail


def test_clean_pass_when_connect_succeeds(monkeypatch):
    monkeypatch.delenv(onboarding.ENV_SKIP_REACHABILITY, raising=False)
    level, detail = onboarding.run_reachability_probe(
        9333,
        external_ip_fetcher=lambda: "203.0.113.1",
        tcp_connector=lambda host, port: True,
    )
    assert level == 0
    assert "203.0.113.1:9333" in detail


def test_failure_when_connect_fails(monkeypatch):
    monkeypatch.delenv(onboarding.ENV_SKIP_REACHABILITY, raising=False)
    level, detail = onboarding.run_reachability_probe(
        9333,
        external_ip_fetcher=lambda: "203.0.113.1",
        tcp_connector=lambda host, port: False,
    )
    assert level == 2
    assert "unreachable" in detail.lower()


def test_warn_when_ip_lookup_fails(monkeypatch):
    monkeypatch.delenv(onboarding.ENV_SKIP_REACHABILITY, raising=False)

    def boom():
        raise RuntimeError("no network")

    level, detail = onboarding.run_reachability_probe(
        9333,
        external_ip_fetcher=boom,
        tcp_connector=lambda host, port: True,
    )
    assert level == 1


def test_warn_when_ip_lookup_returns_empty(monkeypatch):
    monkeypatch.delenv(onboarding.ENV_SKIP_REACHABILITY, raising=False)
    level, _detail = onboarding.run_reachability_probe(
        9333,
        external_ip_fetcher=lambda: "",
        tcp_connector=lambda host, port: True,
    )
    assert level == 1
