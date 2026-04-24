"""Tests for rotate-key-if-needed watermark-based auto-rotation."""

import pytest

from messagechain.runtime import onboarding


def test_noop_below_80_percent():
    output = []
    calls = []
    rc = onboarding.run_rotate_if_needed(
        watermark_fetcher=lambda: 1,  # 1/16 = ~6%
        has_cold_authority_key=False,
        tree_height=4,
        rotate_impl=lambda: calls.append("rotate"),
        printer=output.append,
    )
    assert rc == 0
    assert calls == []
    assert any("no-op" in s for s in output)


def test_approaching_threshold_between_80_and_95():
    output = []
    calls = []
    # 13/16 = 81.25%
    rc = onboarding.run_rotate_if_needed(
        watermark_fetcher=lambda: 13,
        has_cold_authority_key=False,
        tree_height=4,
        rotate_impl=lambda: calls.append("rotate"),
        printer=output.append,
    )
    assert rc == 0
    assert calls == []
    assert any("approaching" in s for s in output)


def test_rotates_at_or_above_95_percent():
    output = []
    calls = []
    # 16/16 = 100% (above 95%)
    rc = onboarding.run_rotate_if_needed(
        watermark_fetcher=lambda: 16,
        has_cold_authority_key=False,
        tree_height=4,
        rotate_impl=lambda: calls.append("rotate"),
        printer=output.append,
    )
    assert rc == 0
    assert calls == ["rotate"]


def test_cold_key_blocks_auto_rotate():
    output = []
    calls = []
    rc = onboarding.run_rotate_if_needed(
        watermark_fetcher=lambda: 16,
        has_cold_authority_key=True,
        tree_height=4,
        rotate_impl=lambda: calls.append("rotate"),
        printer=output.append,
    )
    assert rc == 0
    assert calls == []
    assert any("Cold authority key" in s for s in output)


def test_fetcher_exception_surfaces_as_exit_1():
    output = []

    def boom():
        raise RuntimeError("rpc down")

    rc = onboarding.run_rotate_if_needed(
        watermark_fetcher=boom,
        has_cold_authority_key=False,
        tree_height=4,
        rotate_impl=None,
        printer=output.append,
    )
    assert rc == 1


def test_rotate_impl_exception_surfaces_as_exit_1():
    def bad_rotate():
        raise RuntimeError("rotate failed")

    rc = onboarding.run_rotate_if_needed(
        watermark_fetcher=lambda: 16,
        has_cold_authority_key=False,
        tree_height=4,
        rotate_impl=bad_rotate,
        printer=lambda *a, **k: None,
    )
    assert rc == 1


def test_compute_watermark_pct_handles_small_trees():
    assert onboarding.compute_watermark_pct(0, 4) == 0.0
    assert onboarding.compute_watermark_pct(8, 4) == 0.5
    assert onboarding.compute_watermark_pct(16, 4) == 1.0
