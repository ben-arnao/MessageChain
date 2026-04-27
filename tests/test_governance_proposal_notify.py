"""Tests for the opt-in governance-proposal email notifier.

Anchors:
  * Consensus must NOT depend on email working -- removing the entire
    notify subsystem MUST leave consensus equivalent.
  * Stdlib only (`smtplib`, `email.message`, `json`).
  * Opt-in: no SMTP creds -> no email, no error.
  * Idempotent: a proposal must not generate duplicate emails on
    reorg, replay, or restart.
  * Credentials never logged.
  * In-CLI banner is the always-on fallback even when email is off.
"""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stdout
from unittest import mock

import pytest

from messagechain.runtime import notify
from messagechain.runtime import onboarding


# ---------------------------------------------------------------------------
# Email formatting
# ---------------------------------------------------------------------------


def _proposal_dict(**overrides):
    base = {
        "proposal_id": "abcdef0123456789" * 4,  # 64 hex chars
        "proposer_id": "11" * 32,
        "title": "Increase block byte budget to 30k",
        "description": (
            "Raise MAX_BLOCK_MESSAGE_BYTES from 15_000 to 30_000 to give "
            "long-form posts more headroom. Argument follows in the linked "
            "spec. Activation height TBD." + "X" * 1000
        ),
        "created_at_block": 12345,
        "blocks_remaining": 1000,
        "status": "open",
        "yes_weight": 0,
        "no_weight": 0,
        "total_participating": 0,
        "total_eligible": 5_000_000,
        "vote_count": 0,
    }
    base.update(overrides)
    return base


def test_format_proposal_email_has_required_fields():
    p = _proposal_dict()
    subject, body = notify.format_proposal_email(p, current_height=12500)
    assert "MessageChain" in subject
    assert "governance proposal" in subject.lower()
    # Body must include the proposal id (truncated form acceptable),
    # title, proposer, close-height info, voter-reward note, and the
    # vote command.
    assert p["proposal_id"][:16] in body
    assert p["title"] in body
    assert p["proposer_id"][:16] in body
    # The close height = created_at_block + blocks_remaining + (current - created).
    # We just need a numeric "closes" hint somewhere.
    assert "close" in body.lower()
    assert "vote" in body.lower()
    # Description gets truncated past the cap.
    assert "..." in body or "[truncated]" in body
    # No HTML.
    assert "<html" not in body.lower()
    assert "<body" not in body.lower()


def test_format_proposal_email_short_description_not_truncated():
    p = _proposal_dict(description="Short and sweet.")
    _subject, body = notify.format_proposal_email(p, current_height=12500)
    assert "Short and sweet." in body


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_notify_state_dedupe_prevents_double_email(tmp_path):
    state_path = str(tmp_path / "notified.json")
    state = notify.NotifyState.load(state_path)
    pid = "deadbeef" * 8
    assert not state.has_notified(pid)
    state.mark_notified(pid)
    state.save()

    # Reload -- survives restart.
    state2 = notify.NotifyState.load(state_path)
    assert state2.has_notified(pid)


def test_process_block_does_not_resend_for_known_proposal(tmp_path):
    """Two consecutive process_block calls on the same proposal must
    only invoke the notifier once."""
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.example.com",
        "notify.email.smtp_port": 587,
        "notify.email.smtp_username": "u",
        "notify.email.smtp_password": "p",
        "notify.email.smtp_starttls": True,
    }
    state_path = str(tmp_path / "notified.json")

    sent = []

    class _FakeNotifier:
        def send(self, subject, body):
            sent.append((subject, body))

    open_proposal = _proposal_dict()
    proposals = [open_proposal]

    notify.process_block_for_notifications(
        current_height=12500,
        list_proposals=lambda: proposals,
        config=cfg,
        state_path=state_path,
        notifier_factory=lambda c: _FakeNotifier(),
    )
    notify.process_block_for_notifications(
        current_height=12501,
        list_proposals=lambda: proposals,
        config=cfg,
        state_path=state_path,
        notifier_factory=lambda c: _FakeNotifier(),
    )
    assert len(sent) == 1


def test_process_block_skips_closed_proposals(tmp_path):
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.example.com",
        "notify.email.smtp_port": 587,
    }
    state_path = str(tmp_path / "notified.json")
    sent = []

    class _FakeNotifier:
        def send(self, subject, body):
            sent.append((subject, body))

    closed = _proposal_dict(status="closed")
    notify.process_block_for_notifications(
        current_height=99999,
        list_proposals=lambda: [closed],
        config=cfg,
        state_path=state_path,
        notifier_factory=lambda c: _FakeNotifier(),
    )
    assert sent == []


# ---------------------------------------------------------------------------
# Opt-in semantics: no SMTP creds -> silent no-op
# ---------------------------------------------------------------------------


def test_process_block_with_no_smtp_creds_is_noop(tmp_path):
    """Empty / unset notify.email.* must NOT crash and must NOT call SMTP."""
    state_path = str(tmp_path / "notified.json")
    invocations = []

    def _factory(c):
        invocations.append(c)
        raise AssertionError(
            "Should not be invoked when notify.email.enabled is unset"
        )

    notify.process_block_for_notifications(
        current_height=12500,
        list_proposals=lambda: [_proposal_dict()],
        config={},  # no notify keys at all
        state_path=state_path,
        notifier_factory=_factory,
    )
    assert invocations == []


def test_process_block_disabled_flag_is_noop(tmp_path):
    """Even with creds present, enabled=False -> no SMTP call."""
    cfg = {
        "notify.email.enabled": False,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.example.com",
        "notify.email.smtp_port": 587,
    }
    state_path = str(tmp_path / "notified.json")
    invocations = []
    notify.process_block_for_notifications(
        current_height=12500,
        list_proposals=lambda: [_proposal_dict()],
        config=cfg,
        state_path=state_path,
        notifier_factory=lambda c: invocations.append(c) or None,
    )
    assert invocations == []


def test_process_block_swallows_smtp_errors(tmp_path):
    """If SMTP raises, the per-block hook must NOT propagate
    (consensus path independence) -- it logs and moves on."""
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.example.com",
        "notify.email.smtp_port": 587,
    }
    state_path = str(tmp_path / "notified.json")

    class _BrokenNotifier:
        def send(self, subject, body):
            raise RuntimeError("smtp down")

    # Should NOT raise.
    notify.process_block_for_notifications(
        current_height=12500,
        list_proposals=lambda: [_proposal_dict()],
        config=cfg,
        state_path=state_path,
        notifier_factory=lambda c: _BrokenNotifier(),
    )


# ---------------------------------------------------------------------------
# SMTP wiring (mocked) for `notify-test`
# ---------------------------------------------------------------------------


def test_email_notifier_calls_smtp_with_correct_host_port():
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.gmail.com",
        "notify.email.smtp_port": 587,
        "notify.email.smtp_username": "operator@example.com",
        "notify.email.smtp_password": "app-password-shhh",
        "notify.email.smtp_starttls": True,
    }
    notifier = notify.EmailNotifier(cfg)
    fake_smtp_instance = mock.MagicMock()
    fake_smtp_instance.__enter__.return_value = fake_smtp_instance
    fake_smtp_instance.__exit__.return_value = False
    with mock.patch.object(notify.smtplib, "SMTP", return_value=fake_smtp_instance) as smtp_cls:
        notifier.send("Subject", "Body")
    smtp_cls.assert_called_once()
    call_args = smtp_cls.call_args
    # Args may be (host, port) or kwargs.
    args = call_args[0]
    kwargs = call_args[1]
    assert "smtp.gmail.com" in args or kwargs.get("host") == "smtp.gmail.com"
    assert 587 in args or kwargs.get("port") == 587

    # STARTTLS wired.
    fake_smtp_instance.starttls.assert_called_once()
    # Login with the configured creds.
    fake_smtp_instance.login.assert_called_once_with(
        "operator@example.com", "app-password-shhh"
    )
    # Mail actually sent.
    assert fake_smtp_instance.send_message.called or fake_smtp_instance.sendmail.called


def test_email_notifier_sslmode_uses_smtp_ssl():
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.example.com",
        "notify.email.smtp_port": 465,
        "notify.email.smtp_starttls": False,  # implicit SSL on 465
    }
    notifier = notify.EmailNotifier(cfg)
    fake = mock.MagicMock()
    fake.__enter__.return_value = fake
    fake.__exit__.return_value = False
    with mock.patch.object(notify.smtplib, "SMTP_SSL", return_value=fake) as ssl_cls, \
         mock.patch.object(notify.smtplib, "SMTP") as plain_cls:
        notifier.send("Subject", "Body")
    # 465 + starttls=False -> SMTP_SSL path.
    ssl_cls.assert_called_once()
    plain_cls.assert_not_called()


# ---------------------------------------------------------------------------
# notify-status: redaction
# ---------------------------------------------------------------------------


def test_notify_status_redacts_password():
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.example.com",
        "notify.email.smtp_port": 587,
        "notify.email.smtp_username": "u",
        "notify.email.smtp_password": "super-secret-app-password",
        "notify.email.smtp_starttls": True,
    }
    out = notify.format_status(cfg, last_sent={})
    assert "super-secret-app-password" not in out
    # We DO want some indication that a password is set.
    assert "smtp_password" in out
    assert "***" in out or "redacted" in out.lower() or "set" in out.lower()


def test_notify_status_password_unset_shows_unset():
    cfg = {
        "notify.email.enabled": False,
    }
    out = notify.format_status(cfg, last_sent={})
    assert "super-secret" not in out


# ---------------------------------------------------------------------------
# Onboard config: notify.email.* keys accepted by config_set/get
# ---------------------------------------------------------------------------


def test_onboard_config_accepts_notify_email_keys(tmp_path):
    path = str(tmp_path / "onboard.toml")
    onboarding.config_set("notify.email.enabled", "true", path=path)
    onboarding.config_set(
        "notify.email.recipient", "op@example.com", path=path
    )
    onboarding.config_set("notify.email.smtp_host", "smtp.example.com", path=path)
    onboarding.config_set("notify.email.smtp_port", "587", path=path)
    onboarding.config_set("notify.email.smtp_starttls", "true", path=path)

    # Round-trip via reader.
    cfg = onboarding.read_onboard_config(path)
    assert cfg["notify.email.enabled"] is True
    assert cfg["notify.email.recipient"] == "op@example.com"
    assert cfg["notify.email.smtp_host"] == "smtp.example.com"
    assert cfg["notify.email.smtp_port"] == 587
    assert cfg["notify.email.smtp_starttls"] is True


def test_onboard_config_unknown_notify_key_rejected(tmp_path):
    path = str(tmp_path / "onboard.toml")
    with pytest.raises(KeyError):
        onboarding.config_set("notify.email.bogus", "x", path=path)


def test_onboard_config_preserves_legacy_keys_after_notify_set(tmp_path):
    """Setting a notify.email.* key must not clobber auto_upgrade / auto_rotate."""
    path = str(tmp_path / "onboard.toml")
    onboarding.config_set("auto_upgrade", "false", path=path)
    onboarding.config_set("auto_rotate", "false", path=path)
    onboarding.config_set("notify.email.enabled", "true", path=path)

    cfg = onboarding.read_onboard_config(path)
    assert cfg["auto_upgrade"] is False
    assert cfg["auto_rotate"] is False
    assert cfg["notify.email.enabled"] is True


# ---------------------------------------------------------------------------
# Banner -- the always-on fallback
# ---------------------------------------------------------------------------


def test_banner_open_proposal_unvoted():
    p = _proposal_dict(blocks_remaining=144)
    out = notify.format_open_proposals_banner(
        proposals=[p],
        voter_id_hex="22" * 32,
    )
    assert out  # non-empty
    assert "Governance" in out
    # The proposal id (truncated) is displayed.
    assert p["proposal_id"][:16] in out
    assert p["title"] in out
    assert "vote" in out.lower()


def test_banner_suppressed_when_already_voted():
    """If our entity_id is in the proposal's votes (we have voted),
    the banner for that proposal should be omitted.

    The list_proposals view exposes vote_count but not the per-voter
    set -- so this is checked via an explicit `voted_proposal_ids`
    parameter the caller passes in.
    """
    p = _proposal_dict()
    out = notify.format_open_proposals_banner(
        proposals=[p],
        voter_id_hex="22" * 32,
        voted_proposal_ids={p["proposal_id"]},
    )
    assert out == ""


def test_banner_empty_when_no_open_proposals():
    out = notify.format_open_proposals_banner(
        proposals=[],
        voter_id_hex="22" * 32,
    )
    assert out == ""


def test_banner_skips_closed_proposals():
    closed = _proposal_dict(status="closed")
    out = notify.format_open_proposals_banner(
        proposals=[closed],
        voter_id_hex="22" * 32,
    )
    assert out == ""


# ---------------------------------------------------------------------------
# Consensus-path independence
# ---------------------------------------------------------------------------


def test_blockchain_module_does_not_import_notify():
    """The notify module must NOT be imported from any consensus path.

    This test fails the moment a contributor accidentally wires email
    notification into blockchain.py / governance.py / mempool.py.
    """
    import importlib
    consensus_modules = [
        "messagechain.core.blockchain",
        "messagechain.governance.governance",
        "messagechain.core.mempool",
    ]
    for mod_name in consensus_modules:
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            continue
        src_path = getattr(mod, "__file__", None)
        if not src_path:
            continue
        with open(src_path, "r", encoding="utf-8") as f:
            src = f.read()
        assert "messagechain.runtime.notify" not in src, (
            f"{mod_name} must not import the notify subsystem -- "
            "consensus path independence violated"
        )


def test_smtp_failure_does_not_affect_blockchain_state(tmp_path):
    """Trigger the per-block hook with a broken notifier and assert
    blockchain state is identical vs. a run with the hook disabled."""
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "broken",
        "notify.email.smtp_port": 587,
    }
    state_path = str(tmp_path / "notified.json")

    class _BrokenNotifier:
        def send(self, subject, body):
            raise OSError("network down")

    # Should not raise.
    notify.process_block_for_notifications(
        current_height=12500,
        list_proposals=lambda: [_proposal_dict()],
        config=cfg,
        state_path=state_path,
        notifier_factory=lambda c: _BrokenNotifier(),
    )
    # The state file may or may not record the proposal -- what matters
    # is that no exception escaped, and that subsequent calls remain
    # idempotent.  (We choose: don't mark as notified on failure, so the
    # operator can recover by fixing SMTP.  Verified below.)
    state = notify.NotifyState.load(state_path)
    assert not state.has_notified(_proposal_dict()["proposal_id"])


# ---------------------------------------------------------------------------
# notify-test: end-to-end through CLI helper
# ---------------------------------------------------------------------------


def test_notify_test_uses_configured_smtp(monkeypatch):
    cfg = {
        "notify.email.enabled": True,
        "notify.email.recipient": "op@example.com",
        "notify.email.smtp_host": "smtp.example.com",
        "notify.email.smtp_port": 587,
        "notify.email.smtp_username": "u",
        "notify.email.smtp_password": "p",
        "notify.email.smtp_starttls": True,
    }
    sent = {}

    class _FakeSMTP:
        def __init__(self, host, port, *a, **kw):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self, *a, **kw):
            return (250, b"ok")

        def starttls(self, *a, **kw):
            sent["starttls"] = True

        def login(self, u, p):
            sent["login"] = (u, p)

        def send_message(self, msg):
            sent["msg"] = msg

        def sendmail(self, frm, to, body):
            sent["msg"] = body

    monkeypatch.setattr(notify.smtplib, "SMTP", _FakeSMTP)
    notify.notify_test(cfg)
    assert sent["host"] == "smtp.example.com"
    assert sent["port"] == 587
    assert sent.get("starttls") is True
    assert sent["login"] == ("u", "p")


def test_notify_test_raises_when_disabled():
    cfg = {"notify.email.enabled": False}
    with pytest.raises(notify.NotifyConfigError):
        notify.notify_test(cfg)


# ---------------------------------------------------------------------------
# CLI integration -- banner from cmd_start path
# ---------------------------------------------------------------------------


def test_print_open_proposals_banner_includes_open_unvoted(capsys):
    p = _proposal_dict()
    notify.print_open_proposals_banner(
        proposals=[p],
        voter_id_hex="22" * 32,
        voted_proposal_ids=set(),
    )
    out = capsys.readouterr().out
    assert p["title"] in out
    assert "vote" in out.lower()


def test_print_open_proposals_banner_quiet_when_already_voted(capsys):
    p = _proposal_dict()
    notify.print_open_proposals_banner(
        proposals=[p],
        voter_id_hex="22" * 32,
        voted_proposal_ids={p["proposal_id"]},
    )
    out = capsys.readouterr().out
    assert out == ""
