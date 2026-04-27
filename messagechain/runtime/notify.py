"""Opt-in email notifier for governance proposals.

This module is *operator-runtime only*. It is NEVER imported from any
consensus path (`messagechain.core.*`, `messagechain.governance.*`,
`messagechain.network.*`); the `tests/test_governance_proposal_notify.py`
suite asserts the absence of such imports. If a future contributor
needs to wire a notification into a consensus path, they MUST instead
emit a hook the runtime can listen on, never call into this module.

Why: the chain MUST keep producing blocks even if SMTP is down,
misconfigured, or the operator forgot to set credentials. Email is a
convenience layer on top of `list_proposals` -- never a precondition
for it.

Stdlib-only: `smtplib` and `email.message` are the entire SMTP surface
this module relies on. No third-party dependencies, ever (CLAUDE.md
"no external dependencies in protocol" -- we follow the same bar for
operator runtime code so the deployment surface stays small).
"""

from __future__ import annotations

import json
import logging
import os
import smtplib  # stdlib
import threading
import time
from dataclasses import dataclass, field
from email.message import EmailMessage  # stdlib
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config keys (mirrored in onboarding._ALLOWED_NOTIFY_EMAIL_KEYS)
# ---------------------------------------------------------------------------

NOTIFY_EMAIL_ENABLED = "notify.email.enabled"
NOTIFY_EMAIL_RECIPIENT = "notify.email.recipient"
NOTIFY_EMAIL_SMTP_HOST = "notify.email.smtp_host"
NOTIFY_EMAIL_SMTP_PORT = "notify.email.smtp_port"
NOTIFY_EMAIL_SMTP_USERNAME = "notify.email.smtp_username"
NOTIFY_EMAIL_SMTP_PASSWORD = "notify.email.smtp_password"
NOTIFY_EMAIL_SMTP_STARTTLS = "notify.email.smtp_starttls"

NOTIFY_EMAIL_KEYS = (
    NOTIFY_EMAIL_ENABLED,
    NOTIFY_EMAIL_RECIPIENT,
    NOTIFY_EMAIL_SMTP_HOST,
    NOTIFY_EMAIL_SMTP_PORT,
    NOTIFY_EMAIL_SMTP_USERNAME,
    NOTIFY_EMAIL_SMTP_PASSWORD,
    NOTIFY_EMAIL_SMTP_STARTTLS,
)

# Bool-coerced + int-coerced subsets -- used by onboarding.config_set so a
# CLI string ("true", "587") gets turned into the right Python type at
# write time, before it lands in the toml.
NOTIFY_EMAIL_BOOL_KEYS = frozenset({
    NOTIFY_EMAIL_ENABLED,
    NOTIFY_EMAIL_SMTP_STARTTLS,
})
NOTIFY_EMAIL_INT_KEYS = frozenset({
    NOTIFY_EMAIL_SMTP_PORT,
})

DEFAULT_NOTIFY_EMAIL_PORT = 587
# Shrunk to keep the email body well under typical mail-server line-length
# / size limits without truncating the *full* description, which can be
# up to MAX_PROPOSAL_DESCRIPTION_LENGTH (10 KiB).  Operators who want
# the full text can hit `messagechain proposals` on the chain.
DESCRIPTION_PREVIEW_CHARS = 500


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class NotifyConfigError(ValueError):
    """Raised when notify config is incomplete or inconsistent."""


# ---------------------------------------------------------------------------
# Notify state -- persisted "already notified for" set
# ---------------------------------------------------------------------------


def default_state_path(data_dir: str | None = None) -> str:
    """Return the on-disk path for the notified-proposals state file.

    Lives next to the validator data dir so it shares the same backup
    surface as the rest of the operator's local state.  Removing it is
    a safe no-op apart from re-sending notifications for currently-open
    proposals.
    """
    if data_dir:
        return os.path.join(data_dir, "notify_state.json")
    return os.path.join(
        os.path.expanduser("~"), ".messagechain", "notify_state.json"
    )


@dataclass
class NotifyState:
    """Persists which proposal_ids we've already emailed for.

    The set is unbounded in principle, but proposals are pruned from
    the chain after GOVERNANCE_VOTING_WINDOW blocks, so the set
    grows only as fast as `governance proposals x time on chain`.
    Even at one proposal per day for a century that's ~36k entries
    (~3 MB JSON) -- fine for an operator-local state file.
    """
    path: str
    notified: set[str] = field(default_factory=set)
    last_sent: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def load(cls, path: str) -> "NotifyState":
        if not path or not os.path.exists(path):
            return cls(path=path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(
                "notify state at %s unreadable (%s); starting empty", path, e,
            )
            return cls(path=path)
        notified = set(data.get("notified") or [])
        last_sent = dict(data.get("last_sent") or {})
        return cls(path=path, notified=notified, last_sent=last_sent)

    def has_notified(self, proposal_id_hex: str) -> bool:
        return proposal_id_hex in self.notified

    def mark_notified(self, proposal_id_hex: str) -> None:
        with self._lock:
            self.notified.add(proposal_id_hex)
            self.last_sent[proposal_id_hex] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            )

    def save(self) -> None:
        if not self.path:
            return
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = self.path + ".tmp"
        with self._lock:
            payload = {
                "notified": sorted(self.notified),
                "last_sent": dict(self.last_sent),
            }
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _is_email_enabled(cfg: dict) -> bool:
    return bool(cfg.get(NOTIFY_EMAIL_ENABLED, False))


def _required_smtp_keys_present(cfg: dict) -> bool:
    return bool(
        cfg.get(NOTIFY_EMAIL_RECIPIENT)
        and cfg.get(NOTIFY_EMAIL_SMTP_HOST)
        and cfg.get(NOTIFY_EMAIL_SMTP_PORT)
    )


# ---------------------------------------------------------------------------
# Email formatting
# ---------------------------------------------------------------------------


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "...[truncated]"


def format_proposal_email(
    proposal: dict, current_height: int,
) -> tuple[str, str]:
    """Return (subject, plain-text body) for a governance proposal.

    The body is intentionally plain text -- no HTML, no MIME-multipart,
    no images.  Mail clients render it identically regardless of the
    operator's email infrastructure, and there's no scope for a
    rendering-exploit if a malicious proposer crafts a hostile title.
    """
    proposal_id = str(proposal.get("proposal_id", ""))
    title = str(proposal.get("title", "(untitled)"))
    proposer = str(proposal.get("proposer_id", "(unknown)"))
    description = str(proposal.get("description", ""))
    created_block = int(proposal.get("created_at_block") or 0)
    blocks_remaining = int(proposal.get("blocks_remaining") or 0)
    close_height = current_height + blocks_remaining

    # Approximate close time in human-readable form.  Block cadence is a
    # tuning constant on this chain; reading config here would couple us
    # to consensus, which we explicitly do not want.  Fall back to "in
    # ~N blocks" -- the operator knows the cadence.
    close_estimate = f"in ~{blocks_remaining} blocks"

    description_preview = _truncate(description, DESCRIPTION_PREVIEW_CHARS)

    subject = (
        f"MessageChain governance proposal open -- your vote is needed "
        f"(#{proposal_id[:16]})"
    )

    voter_reward_hint = (
        "Voter reward (paid from proposal fee, distributed pro-rata "
        "to yes-voters at close): see `messagechain proposals` for "
        "current pool size."
    )

    lines = [
        f"Proposal #{proposal_id[:16]}: {title}",
        f"Proposed at block {created_block} by entity {proposer[:16]}...",
        f"Voting window closes at block {close_height} ({close_estimate}).",
        "",
        description_preview,
        "",
        voter_reward_hint,
        "",
        "To vote:",
        f"  messagechain vote --proposal {proposal_id} --yes",
        f"  messagechain vote --proposal {proposal_id} --no",
        "",
        "To see all open proposals:",
        "  messagechain proposals",
    ]
    return subject, "\n".join(lines)


# ---------------------------------------------------------------------------
# EmailNotifier -- thin SMTP wrapper
# ---------------------------------------------------------------------------


class EmailNotifier:
    """SMTP wrapper that sends a single message per `send()` call.

    Intentionally not a long-lived connection -- proposal-open emails
    are infrequent (governance windows are days long), so the cost of
    a fresh SMTP handshake per send is irrelevant compared to the
    code simplicity.
    """

    def __init__(self, cfg: dict):
        self.cfg = dict(cfg)
        if not _required_smtp_keys_present(self.cfg):
            raise NotifyConfigError(
                "notify.email.{recipient,smtp_host,smtp_port} all required "
                "for EmailNotifier"
            )
        self.host = str(self.cfg[NOTIFY_EMAIL_SMTP_HOST])
        self.port = int(self.cfg[NOTIFY_EMAIL_SMTP_PORT])
        self.username = self.cfg.get(NOTIFY_EMAIL_SMTP_USERNAME)
        self.password = self.cfg.get(NOTIFY_EMAIL_SMTP_PASSWORD)
        self.starttls = bool(self.cfg.get(NOTIFY_EMAIL_SMTP_STARTTLS, True))
        self.recipient = str(self.cfg[NOTIFY_EMAIL_RECIPIENT])
        self.sender = (
            self.cfg.get(NOTIFY_EMAIL_SMTP_USERNAME) or self.recipient
        )

    def _build_message(self, subject: str, body: str) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg.set_content(body)
        return msg

    def send(self, subject: str, body: str) -> None:
        """Connect, optionally STARTTLS, login, send, quit. Synchronous."""
        message = self._build_message(subject, body)
        # Implicit-SSL ports (465) historically don't accept STARTTLS;
        # operators who set port 465 + starttls=False want the SMTP_SSL
        # path.  Everything else (587 with starttls=True is the standard
        # submission profile) goes through plain SMTP + STARTTLS.
        use_ssl = (not self.starttls) and self.port == 465
        if use_ssl:
            with smtplib.SMTP_SSL(self.host, self.port, timeout=30) as conn:
                if self.username and self.password:
                    conn.login(self.username, self.password)
                conn.send_message(message)
        else:
            with smtplib.SMTP(self.host, self.port, timeout=30) as conn:
                conn.ehlo()
                if self.starttls:
                    conn.starttls()
                    conn.ehlo()
                if self.username and self.password:
                    conn.login(self.username, self.password)
                conn.send_message(message)


# ---------------------------------------------------------------------------
# Per-block hook
# ---------------------------------------------------------------------------


def _default_notifier_factory(cfg: dict) -> EmailNotifier:
    return EmailNotifier(cfg)


def process_block_for_notifications(
    *,
    current_height: int,
    list_proposals: Callable[[], Iterable[dict]],
    config: dict,
    state_path: str,
    notifier_factory: Callable[[dict], Any] | None = None,
) -> None:
    """Idempotently emit notifications for newly-seen open proposals.

    Designed to be called from the operator runtime AFTER each
    successful `add_block`.  Never raises -- if SMTP is broken, we log
    and move on so consensus is unaffected.

    Idempotency model:
      * On success, the proposal_id is added to the persisted set
        and saved.
      * On failure (SMTP error, factory failure), the id is NOT
        marked.  Next block tick retries -- bounded because closed
        proposals are ignored, so the retry window is at most
        GOVERNANCE_VOTING_WINDOW blocks.
    """
    if not _is_email_enabled(config):
        return
    if not _required_smtp_keys_present(config):
        # Opt-in: missing creds is silent. The CLI command
        # `notify-test` is the surface that yells about misconfig.
        return

    try:
        proposals = list(list_proposals() or [])
    except Exception:
        logger.exception("notify: list_proposals failed; skipping")
        return

    state = NotifyState.load(state_path)
    factory = notifier_factory or _default_notifier_factory

    sent_any = False
    for p in proposals:
        if str(p.get("status", "")).lower() != "open":
            continue
        pid = str(p.get("proposal_id", ""))
        if not pid:
            continue
        if state.has_notified(pid):
            continue
        try:
            notifier = factory(config)
            subject, body = format_proposal_email(p, current_height)
            notifier.send(subject, body)
        except Exception as e:
            # Log redacted -- do NOT include cfg or password in the
            # log line. The exception class + recipient is enough to
            # diagnose without leaking secrets.
            logger.warning(
                "notify: email send failed for proposal %s (%s); "
                "will retry next block",
                pid[:16], type(e).__name__,
            )
            continue
        state.mark_notified(pid)
        sent_any = True

    if sent_any:
        try:
            state.save()
        except OSError as e:
            logger.warning("notify: state save failed (%s)", e)


# ---------------------------------------------------------------------------
# CLI helpers -- notify-test and notify-status
# ---------------------------------------------------------------------------


def notify_test(cfg: dict) -> None:
    """Send a one-shot test email using the configured SMTP creds.

    Raises NotifyConfigError if the config is incomplete or disabled.
    Lets SMTP exceptions propagate so the CLI can show the operator
    why the configuration doesn't work yet (this is opposite to the
    per-block path, which silently retries).
    """
    if not _is_email_enabled(cfg):
        raise NotifyConfigError(
            f"{NOTIFY_EMAIL_ENABLED} is not true. Enable with: "
            f"messagechain config set {NOTIFY_EMAIL_ENABLED} true"
        )
    if not _required_smtp_keys_present(cfg):
        raise NotifyConfigError(
            "Missing required SMTP config. Required keys: "
            f"{NOTIFY_EMAIL_RECIPIENT}, {NOTIFY_EMAIL_SMTP_HOST}, "
            f"{NOTIFY_EMAIL_SMTP_PORT}"
        )
    notifier = EmailNotifier(cfg)
    subject = "MessageChain notify-test -- config OK"
    body = (
        "This is a one-shot test email from `messagechain notify-test`.\n"
        "If you're reading this in your inbox, governance-proposal "
        "notifications are wired correctly.\n"
        "\n"
        "If you DON'T want these emails, run:\n"
        f"  messagechain config set {NOTIFY_EMAIL_ENABLED} false\n"
    )
    notifier.send(subject, body)


def format_status(cfg: dict, last_sent: dict | None = None) -> str:
    """Return a human-readable status block. Password is redacted.

    The last_sent dict (if provided) maps proposal_id -> ISO timestamp
    of the last email we sent for it; used to give operators a
    "yes, the subsystem is firing" signal at a glance.
    """
    last_sent = last_sent or {}
    enabled = bool(cfg.get(NOTIFY_EMAIL_ENABLED, False))
    recipient = cfg.get(NOTIFY_EMAIL_RECIPIENT) or "(unset)"
    host = cfg.get(NOTIFY_EMAIL_SMTP_HOST) or "(unset)"
    port = cfg.get(NOTIFY_EMAIL_SMTP_PORT) or "(unset)"
    username = cfg.get(NOTIFY_EMAIL_SMTP_USERNAME) or "(unset)"
    password_set = bool(cfg.get(NOTIFY_EMAIL_SMTP_PASSWORD))
    starttls = bool(cfg.get(NOTIFY_EMAIL_SMTP_STARTTLS, True))

    lines = [
        "=== messagechain notify-status ===",
        f"  notify.email.enabled       = {enabled}",
        f"  notify.email.recipient     = {recipient}",
        f"  notify.email.smtp_host     = {host}",
        f"  notify.email.smtp_port     = {port}",
        f"  notify.email.smtp_username = {username}",
        # Password redacted at all costs.
        (
            f"  notify.email.smtp_password = (set, redacted ***)"
            if password_set
            else f"  notify.email.smtp_password = (unset)"
        ),
        f"  notify.email.smtp_starttls = {starttls}",
        "",
    ]
    if last_sent:
        lines.append("  Last sent timestamps (most-recent 10):")
        items = sorted(
            last_sent.items(), key=lambda kv: kv[1], reverse=True
        )[:10]
        for pid, ts in items:
            lines.append(f"    {pid[:16]}...  {ts}")
    else:
        lines.append("  No notifications sent yet.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Banner -- the always-on fallback (works without SMTP)
# ---------------------------------------------------------------------------


def format_open_proposals_banner(
    *,
    proposals: Iterable[dict],
    voter_id_hex: str,
    voted_proposal_ids: set[str] | None = None,
) -> str:
    """Return a multi-line banner string, or "" if nothing to surface.

    Filters: status=="open" AND proposal_id not in voted_proposal_ids.
    The caller decides what set to pass for `voted_proposal_ids`; in
    the cmd_start path that's the per-entity vote set fetched from
    the local node, in tests it's whatever the test wants.
    """
    voted_proposal_ids = set(voted_proposal_ids or set())
    open_unvoted = [
        p for p in proposals
        if str(p.get("status", "")).lower() == "open"
        and str(p.get("proposal_id", "")) not in voted_proposal_ids
    ]
    if not open_unvoted:
        return ""

    bar = "=" * 64
    lines = [
        bar,
        f"  [!] Governance: {len(open_unvoted)} open "
        f"proposal{'s' if len(open_unvoted) != 1 else ''} -- "
        f"your vote is needed",
    ]
    for p in open_unvoted:
        pid = str(p.get("proposal_id", ""))
        title = str(p.get("title", "(untitled)"))
        blocks_remaining = int(p.get("blocks_remaining") or 0)
        lines.append(
            f"    #{pid[:16]}...: {title} (closes in ~{blocks_remaining} blocks)"
        )
        lines.append(
            f"    To vote: messagechain vote --proposal {pid} --yes|--no"
        )
    lines.append(bar)
    return "\n".join(lines)


def print_open_proposals_banner(
    *,
    proposals: Iterable[dict],
    voter_id_hex: str,
    voted_proposal_ids: set[str] | None = None,
    printer: Callable[[str], None] = print,
) -> None:
    text = format_open_proposals_banner(
        proposals=proposals,
        voter_id_hex=voter_id_hex,
        voted_proposal_ids=voted_proposal_ids,
    )
    if text:
        printer(text)
