"""
Public HTTPS transaction-submission endpoint.

Censorship-resistance design: any client on the public internet can
POST a signed MessageTransaction (binary-serialized) to any validator's
HTTPS endpoint, bypassing local mempool dependence.  If a client's
local peers drop their tx, they can still reach the chain by going
direct to a validator.

Security posture:
  * TLS mandatory — no plaintext fallback.  Operator supplies cert and
    key via CLI (Let's Encrypt, self-signed, whatever they trust).
  * Per-source-IP token bucket: `SUBMISSION_RATE_LIMIT_PER_SEC` /
    `SUBMISSION_BURST` tokens.  Every request (accepted or rejected)
    burns a token — a spammer can't skip the quota by sending garbage.
  * Body-size cap: `MAX_SUBMISSION_BODY_BYTES` (16KB).  Larger than
    any real tx but small enough to prevent memory exhaustion via
    chunked uploads.
  * Single endpoint, single method: `POST /v1/submit`.  Anything else
    returns 404 / 405.  Nothing that reads server state is exposed
    here — no balance lookups, no block queries.  This is a write-only
    ingress, on purpose.
  * No authentication — submission is a write-only channel for signed
    data; the signature IS the auth.  Anyone can submit; only valid
    txs land in the mempool.

The server runs in a background daemon thread and can be stopped
cleanly from the main process.  It sits alongside — not inside — the
main P2P/RPC server so a submission-endpoint bug can never corrupt
the P2P socket or the RPC socket.

Stdlib-only: `http.server.ThreadingHTTPServer`, `ssl.SSLContext`.  No
new pip deps.  Long-term durability beats framework sugar.
"""

from __future__ import annotations

import http.server
import logging
import socket
import socketserver
import ssl
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from messagechain.config import (
    MAX_SUBMISSION_BODY_BYTES,
    SUBMISSION_ACK_BURST,
    SUBMISSION_ACK_RATE_LIMIT_PER_SEC,
    SUBMISSION_BURST,
    SUBMISSION_FEE,
    SUBMISSION_RATE_LIMIT_PER_SEC,
    SUBMISSION_REJECTION_BURST,
    SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC,
)
from messagechain.core.transaction import MessageTransaction
from messagechain.network.ratelimit import TokenBucket
from messagechain.network.submission_receipt import (
    ReceiptIssuer,
    SubmissionReceipt,
    SignedRejection,
    REJECT_INVALID_SIG,
    REJECT_INVALID_NONCE,
    REJECT_FEE_TOO_LOW,
    REJECT_MEMPOOL_FULL,
    REJECT_REVOKED_KEY,
    REJECT_MALFORMED,
    REJECT_OTHER,
)


logger = logging.getLogger("messagechain.submission")


__all__ = [
    "ReceiptIssuer",
    "SubmissionServer",
    "SubmissionResult",
    "submit_transaction_to_mempool",
    "submit_custody_proof_to_pool",
]


@dataclass
class SubmissionResult:
    """Outcome of injecting a tx into the local mempool.

    Separate from HTTP status so the helper is usable from non-HTTP
    callers (tests, future RPC clients).

    If the submission was accepted AND the server has a
    ReceiptIssuer configured, `receipt_hex` carries the signed
    SubmissionReceipt the validator commits to (hex-encoded binary
    form, so it round-trips unambiguously into a CensorshipEvidenceTx
    without re-serialization risk).  Clients can hold this receipt
    and, if the tx isn't included within EVIDENCE_INCLUSION_WINDOW
    blocks, file evidence to trigger a partial slash of the validator.
    """
    ok: bool
    tx_hash: bytes = b""
    error: str = ""
    # True iff the tx was already in the mempool — the HTTP layer
    # treats this as success (200) for idempotency.
    duplicate: bool = False
    # Receipt bytes (hex) when issued.  Populated only when the
    # server-side ReceiptIssuer is configured AND the tx was
    # newly admitted (no receipt on duplicate — a retry must not
    # consume a fresh leaf from the receipt subtree).
    receipt_hex: str = ""
    # Signed-rejection bytes (hex) when issued.  Populated only when:
    #   * the server-side ReceiptIssuer is configured,
    #   * the client opted in via the X-MC-Request-Receipt header,
    #   * validation FAILED (ok == False).
    # Otherwise empty so the default leaf-budget posture is unchanged
    # — a misbehaving client cannot drain the issuer's receipt subtree
    # by spamming garbage txs without setting the opt-in header.
    rejection_hex: str = ""
    # SubmissionAck bytes (hex) when issued.  Populated only when the
    # client opts in via X-MC-Witnessed-Submission: <hex(request_hash)>
    # AND the server-side ReceiptIssuer is configured.  The ack
    # commits the validator to having received and processed the
    # request_hash; if the validator silently dropped the request
    # instead, peers who saw the witness gossip can submit a
    # NonResponseEvidenceTx and slash the validator.
    #
    # Issued for BOTH success (ACK_ADMITTED) AND failure (ACK_REJECTED)
    # paths because the threat being closed is the silent-drop, not
    # the lie — a validator that returns ACK_REJECTED honestly
    # commits to having seen the request, which is what the witness
    # path needs.
    ack_hex: str = ""


def _rejection_code_for_validate_reason(reason: str) -> int:
    """Map a `validate_transaction` failure string to a REJECT_* code.

    String-matching is fragile, but the canonical reasons that
    validate_transaction returns are stable and documented; the
    mapping table here is the only place that knows about them.  Any
    unmatched reason falls through to REJECT_OTHER so a future
    validation path that emits a new string still lands a verifiable
    rejection (just with the catch-all code).
    """
    r = reason.lower()
    if "signature" in r or "sig version" in r:
        return REJECT_INVALID_SIG
    if "nonce" in r:
        return REJECT_INVALID_NONCE
    if "fee" in r or "balance" in r:
        # "Insufficient spendable balance for fee of N" maps to
        # REJECT_FEE_TOO_LOW (the user couldn't pay the fee).
        return REJECT_FEE_TOO_LOW
    if "leaf" in r:
        # WOTS+ leaf reuse — there is no perfect REJECT_* for this;
        # it's a malformed-replay scenario.  REJECT_MALFORMED is the
        # closest fit until a dedicated code is added.
        return REJECT_MALFORMED
    if "unknown entity" in r or "register" in r:
        # An unknown signer cannot be slashed for REJECT_INVALID_SIG
        # via this path (no on-chain pubkey to refute), but the
        # rejection itself is honest under REJECT_OTHER.
        return REJECT_OTHER
    if "timestamp" in r or "future" in r:
        return REJECT_MALFORMED
    return REJECT_OTHER


def _rejection_code_for_mempool_reason(reason: str) -> int:
    """Map a mempool refusal into a REJECT_* code.  See helper above."""
    r = reason.lower()
    if "fee" in r:
        return REJECT_FEE_TOO_LOW
    if "cap" in r or "rate" in r or "full" in r:
        return REJECT_MEMPOOL_FULL
    return REJECT_OTHER


def _should_request_rejection(ctx, client_ip: str, header_set: bool) -> bool:
    """Decide whether this request gets a SignedRejection on failure.

    Silent-downgrade policy: if the client set X-MC-Request-Receipt
    but the per-IP rejection budget is exhausted, return False.
    The submission still processes; the client just doesn't get a
    signed proof of rejection.  Protects the receipt-subtree's
    finite leaf budget from drain-via-bad-sig-spam while keeping
    honest slash-evidence issuance flowing at the configured
    rejection rate.

    Header NOT set → always False regardless of budget.
    Header set + budget available → True (consumes one token).
    Header set + budget exhausted → False (no token consumed
    because rejection_budget_check already returned False).
    """
    if not header_set:
        return False
    return bool(ctx.rejection_budget_check(client_ip))


def submit_transaction_to_mempool(
    tx: MessageTransaction,
    blockchain,
    mempool,
    receipt_issuer: Optional[ReceiptIssuer] = None,
    request_rejection: bool = False,
    witnessed_request_hash: Optional[bytes] = None,
    ack_allowed: bool = True,
) -> SubmissionResult:
    """Validate `tx` against chain state and inject into `mempool`.

    Mirrors the Server._rpc_submit_transaction ingress path so
    forced-inclusion arrival tracking stays consistent across ingress
    points (local RPC, P2P gossip, public HTTPS submission).

    `receipt_issuer` (optional): if provided, a SubmissionReceipt is
    issued on fresh admission and returned via result.receipt_hex.
    No receipt is issued on duplicate admission (retries do not
    consume a new leaf from the issuer's subtree).  Content-neutral:
    the issuer has NO discretion to refuse receipts for
    already-accepted txs.

    `request_rejection` (default False): when True AND `receipt_issuer`
    is provided, a SignedRejection is issued for any validation failure
    and returned via result.rejection_hex.  Default False so the
    receipt-subtree leaf budget is NOT burned on the default path —
    a misbehaving client must explicitly opt in (the HTTP handler
    threads through the X-MC-Request-Receipt header) to make the
    validator pay a leaf for a failed submission.  This closes the
    leaf-amplification attack vector.

    A SignedRejection commits the validator to the failure reason; if
    the rejection is provably bogus (e.g., REJECT_INVALID_SIG against
    a tx whose signature actually verifies), the validator is slashable
    via BogusRejectionEvidenceTx — closes the receipt-less censorship
    gap where a coerced validator answers honest submissions with a lie.
    """
    # Helper — issue a SubmissionAck iff the caller passed a
    # witnessed_request_hash AND the server has a ReceiptIssuer
    # AND the caller-side per-IP / observation-store gate has not
    # short-circuited via `ack_allowed=False`.
    #
    # The `ack_allowed` gate exists because every ack burns a one-
    # time-use WOTS+ leaf from the receipt subtree (RECEIPT_SUBTREE_HEIGHT
    # = 16 → 65k leaves total).  Pre-fix this helper had no rate cap
    # and accepted any 32-byte header value (no binding to any prior
    # gossiped SubmissionRequest), so an attacker spamming HTTP POSTs
    # with random `X-MC-Witnessed-Submission` values from a /24 could
    # drain the entire subtree in minutes -- collapsing the censorship-
    # evidence pipeline silently.  The HTTP handler now precomputes
    # `ack_allowed` from the dedicated per-IP ack bucket and (when
    # configured) the WitnessObservationStore, and threads it through.
    # Best-effort: a broken issuer must NOT change the validation
    # outcome.  See witness_submission.SubmissionAck for semantics.
    def _maybe_issue_ack(action_code_int: int) -> str:
        if not ack_allowed:
            return ""
        if witnessed_request_hash is None or receipt_issuer is None:
            return ""
        if len(witnessed_request_hash) != 32:
            return ""
        try:
            from messagechain.consensus.witness_submission import (
                ACK_ADMITTED, ACK_REJECTED,
            )
            ack = receipt_issuer.issue_ack(
                witnessed_request_hash, action_code_int,
            )
            return ack.to_bytes().hex()
        except Exception:
            logger.exception("ack issuance failed")
            return ""

    # Idempotency: if the tx is already in the pool, treat as success.
    # No new receipt is issued — the client already got one on first
    # submission, and re-issuing would burn a fresh subtree leaf per
    # retry, giving a network retry loop an amplification path against
    # the issuer's leaf budget.
    #
    # Acks ARE issued on duplicate witnessed submissions: the client's
    # opt-in ack request is independent of the receipt-leaf budget
    # (it's already paying WITNESS_SURCHARGE on top of the normal
    # fee, and the witness path explicitly requires a fresh ack per
    # request_hash).  Without this, a re-tried witnessed submission
    # would silently fail to discharge the witness obligation.
    if tx.tx_hash in mempool.pending:
        from messagechain.consensus.witness_submission import ACK_ADMITTED
        return SubmissionResult(
            ok=True, tx_hash=tx.tx_hash, duplicate=True,
            ack_hex=_maybe_issue_ack(ACK_ADMITTED),
        )

    def _maybe_issue_rejection(
        reason: str,
        code: int,
    ) -> str:
        """Issue a SignedRejection iff opted in + issuer configured.

        Broad-except: a broken issuer must NOT change the failure
        reason or fail-open the validation; the failure stays a
        failure with a clear `error` set, the rejection_hex is just
        empty in that case.
        """
        if not request_rejection or receipt_issuer is None:
            return ""
        try:
            rej = receipt_issuer.issue_rejection(tx.tx_hash, code)
            return rej.to_bytes().hex()
        except Exception:
            logger.exception("rejection issuance failed for %s", reason)
            return ""

    on_chain_nonce = blockchain.nonces.get(tx.entity_id, 0)
    pending_nonce = mempool.get_pending_nonce(tx.entity_id, on_chain_nonce)
    valid, reason = blockchain.validate_transaction(
        tx, expected_nonce=pending_nonce,
    )
    if not valid:
        from messagechain.consensus.witness_submission import ACK_REJECTED
        return SubmissionResult(
            ok=False, error=reason,
            rejection_hex=_maybe_issue_rejection(
                reason, _rejection_code_for_validate_reason(reason),
            ),
            ack_hex=_maybe_issue_ack(ACK_REJECTED),
        )

    # Record arrival height so forced-inclusion "tx waited N blocks"
    # logic measures from the moment this node actually saw it.
    added = mempool.add_transaction(
        tx, arrival_block_height=blockchain.height,
    )
    if not added:
        # Mempool refused (e.g. per-sender cap, duplicate leaf, fee
        # under dynamic minimum).  If the tx still ended up pending
        # this call, treat as duplicate success; otherwise reject.
        if tx.tx_hash in mempool.pending:
            from messagechain.consensus.witness_submission import ACK_ADMITTED
            return SubmissionResult(
                ok=True, tx_hash=tx.tx_hash, duplicate=True,
                ack_hex=_maybe_issue_ack(ACK_ADMITTED),
            )
        mempool_reason = "Mempool rejected transaction (rate / fee / cap)"
        from messagechain.consensus.witness_submission import ACK_REJECTED
        return SubmissionResult(
            ok=False, error=mempool_reason,
            rejection_hex=_maybe_issue_rejection(
                mempool_reason,
                _rejection_code_for_mempool_reason(mempool_reason),
            ),
            ack_hex=_maybe_issue_ack(ACK_REJECTED),
        )

    # Content-neutral receipt issuance.  No blocklists, no
    # size-based refusal — if the mempool accepted the tx, the
    # validator MUST commit to having seen it, on pain of
    # censorship-evidence slashing if the tx is not eventually
    # included.
    receipt_hex = ""
    if receipt_issuer is not None:
        try:
            receipt = receipt_issuer.issue(tx.tx_hash)
            receipt_hex = receipt.to_bytes().hex()
        except Exception:
            # A broken issuer must NOT block submission success —
            # the tx is already in the mempool and the client's
            # best response is to proceed without a receipt.
            logger.exception("receipt issuance failed")

    from messagechain.consensus.witness_submission import ACK_ADMITTED
    return SubmissionResult(
        ok=True, tx_hash=tx.tx_hash, receipt_hex=receipt_hex,
        ack_hex=_maybe_issue_ack(ACK_ADMITTED),
    )


def submit_custody_proof_to_pool(
    proof,
    blockchain,
    proof_pool,
    *,
    challenge_block_number: int | None = None,
) -> SubmissionResult:
    """Validate and inject a CustodyProof into the archive-proof mempool.

    Mirrors `submit_transaction_to_mempool` in shape: a single ingress
    helper reusable by HTTP, RPC, and gossip code paths so acceptance
    semantics never drift across surfaces.

    Steps (cheap-first to limit CPU burn on a flood):
      1. Resolve the target challenge.  Callers that know the intended
         challenge block number pass it explicitly; callers that don't
         (e.g., a gossip relay) get it derived from the proof's
         target_height via the chain's challenge schedule.
      2. Reject if the submission window has closed.
      3. Look up the target block locally.  Its block_hash is the
         challenge's expected_block_hash — absent means the node is
         out of sync; drop but do not ban.
      4. Full verify_custody_proof (merkle + header rehash).
      5. Insert into the pool keyed by (challenge, prover_id).

    No prover signature in v1 (see archive_challenge module docstring).
    """
    from messagechain.config import (
        ARCHIVE_CHALLENGE_INTERVAL,
        is_archive_challenge_block,
    )
    from messagechain.consensus.archive_challenge import (
        compute_challenge,
        is_within_submission_window,
        verify_custody_proof,
    )
    # Use a stable ID for the return value so callers can key on
    # "did this proof land?".  Proof hash covers every binding field.
    proof_id = getattr(proof, "tx_hash", b"")

    # Resolve the challenge.  If the caller didn't supply one, pick
    # the most-recent challenge whose target is proof.target_height.
    current = blockchain.height - 1 if blockchain.height > 0 else 0
    if challenge_block_number is None:
        # Derive the most recent challenge block whose target could
        # match.  We walk from `current` down by intervals until the
        # computed target matches proof.target_height.  Bounded by
        # ARCHIVE_SUBMISSION_WINDOW / ARCHIVE_CHALLENGE_INTERVAL — a
        # handful of iterations at most.
        from messagechain.config import ARCHIVE_SUBMISSION_WINDOW
        challenge_block_number = None
        max_lookback = ARCHIVE_SUBMISSION_WINDOW // max(ARCHIVE_CHALLENGE_INTERVAL, 1) + 2
        h = (current // ARCHIVE_CHALLENGE_INTERVAL) * ARCHIVE_CHALLENGE_INTERVAL
        for _ in range(max_lookback + 1):
            if h <= 0 or not is_archive_challenge_block(h):
                h -= ARCHIVE_CHALLENGE_INTERVAL
                continue
            parent = blockchain.get_block(h - 1)
            if parent is None:
                h -= ARCHIVE_CHALLENGE_INTERVAL
                continue
            ch = compute_challenge(parent.block_hash, h)
            if ch.target_height == proof.target_height:
                challenge_block_number = h
                break
            h -= ARCHIVE_CHALLENGE_INTERVAL
        if challenge_block_number is None:
            return SubmissionResult(
                ok=False, tx_hash=proof_id,
                error="no active challenge matches proof target_height",
            )

    if not is_archive_challenge_block(challenge_block_number):
        return SubmissionResult(
            ok=False, tx_hash=proof_id,
            error="challenge_block_number is not a challenge height",
        )
    if not is_within_submission_window(challenge_block_number, current):
        return SubmissionResult(
            ok=False, tx_hash=proof_id,
            error="submission window closed",
        )

    # Resolve the target block from local archive.
    target_block = blockchain.get_block(proof.target_height)
    if target_block is None:
        return SubmissionResult(
            ok=False, tx_hash=proof_id,
            error="target block unknown locally",
        )
    expected_block_hash = target_block.block_hash
    if proof.target_block_hash != expected_block_hash:
        return SubmissionResult(
            ok=False, tx_hash=proof_id,
            error="proof target_block_hash does not match chain's block hash",
        )

    ok, reason = verify_custody_proof(
        proof, expected_block_hash=expected_block_hash,
    )
    if not ok:
        return SubmissionResult(ok=False, tx_hash=proof_id, error=reason)

    # Idempotent: same proof re-submitted is a success.
    key = (challenge_block_number, bytes(proof.prover_id))
    if key in proof_pool:
        return SubmissionResult(
            ok=True, tx_hash=proof_id, duplicate=True,
        )
    added = proof_pool.add_proof(
        proof, challenge_block_number=challenge_block_number,
    )
    if not added:
        # Race: another thread added it between the contains-check
        # and add_proof.  Still a success.
        return SubmissionResult(
            ok=True, tx_hash=proof_id, duplicate=True,
        )
    return SubmissionResult(ok=True, tx_hash=proof_id)


class _SubmissionHandler(http.server.BaseHTTPRequestHandler):
    """Per-request handler.

    Attributes injected by `SubmissionServer` via the server instance:
        server._submission_context: `_HandlerContext`
    """

    # Keep log output quiet; we log security-relevant events explicitly.
    def log_message(self, fmt, *args):
        return

    def _client_ip(self) -> str:
        # client_address is (host, port); host may be 'localhost'.
        return self.client_address[0]

    def _header_truthy(self, name: str) -> bool:
        """Treat any non-empty, non-zero header value as opt-in true.

        Accepts "1", "true", "yes" (case-insensitive).  Empty / "0" /
        "false" / missing all read as False.  Lenient on purpose so a
        client library that emits any reasonable truthy value works.
        """
        v = (self.headers.get(name) or "").strip().lower()
        return v not in ("", "0", "false", "no")

    def _reject(self, status: int, message: str):
        body = message.encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _ok(self, body_bytes: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body_bytes)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # Block every method except POST so a scanner probing /v1/submit
    # with GET can't leak implementation details in a default error page.
    def do_GET(self):
        self._reject(405, "Method Not Allowed")

    def do_PUT(self):
        self._reject(405, "Method Not Allowed")

    def do_DELETE(self):
        self._reject(405, "Method Not Allowed")

    def do_PATCH(self):
        self._reject(405, "Method Not Allowed")

    def do_HEAD(self):
        self._reject(405, "Method Not Allowed")

    def do_POST(self):
        ctx = self.server._submission_context

        # Path gate — two supported endpoints, both write-only:
        #   /v1/submit                — signed MessageTransaction
        #   /v1/submit-custody-proof  — unsigned CustodyProof (v1)
        if self.path == "/v1/submit-custody-proof":
            self._handle_custody_proof_submit(ctx)
            return
        if self.path != "/v1/submit":
            self._reject(404, "Not Found")
            return

        # Rate limit FIRST — before allocating any buffers or parsing
        # headers.  An unlimited attacker can't exhaust memory if we
        # refuse them before read().
        if not ctx.rate_limit_check(self._client_ip()):
            self._reject(429, "Too Many Requests")
            return

        # Content-Type gate.  Reject anything that isn't
        # application/octet-stream — a browser form POST or JSON body
        # is not a signed tx and should be told so explicitly.
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/octet-stream":
            self._reject(415, "Unsupported Media Type — use application/octet-stream")
            return

        # Size gate.  Content-Length is advisory, but if the client
        # claims too much, don't even bother reading.
        try:
            declared_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._reject(400, "Invalid Content-Length")
            return
        if declared_length < 0 or declared_length > MAX_SUBMISSION_BODY_BYTES:
            self._reject(413, f"Payload too large (max {MAX_SUBMISSION_BODY_BYTES} bytes)")
            return

        # Read at most MAX_SUBMISSION_BODY_BYTES + 1 to catch
        # Content-Length liars.
        to_read = min(declared_length, MAX_SUBMISSION_BODY_BYTES)
        try:
            body = self.rfile.read(to_read)
        except (ConnectionResetError, OSError):
            return
        if len(body) > MAX_SUBMISSION_BODY_BYTES:
            self._reject(413, "Payload too large")
            return

        # Decode.  A decode failure is NOT eligible for a SignedRejection
        # — the body wasn't a valid tx, so there is no tx_hash to commit
        # the rejection to.  Always plain text, regardless of header.
        try:
            tx = MessageTransaction.from_bytes(body)
        except Exception as e:
            logger.debug("submission decode failed from %s: %s", self._client_ip(), e)
            self._reject(400, "Invalid transaction encoding")
            return

        # Opt-in rejection: clients that want a SignedRejection on
        # validation failure must set X-MC-Request-Receipt: 1 (any
        # truthy value).  The dedicated rejection budget (see
        # SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC in config) caps how
        # often this endpoint will burn a receipt-subtree leaf per IP
        # — an attacker setting the header and spamming bad sigs to
        # drain the subtree is now rate-limited to a trickle.  When
        # the budget is exhausted we silently drop the opt-in: the
        # submission still processes normally, the client just gets a
        # plain 400 without a signed-rejection payload.
        header_set = self._header_truthy("X-MC-Request-Receipt")
        request_rejection = _should_request_rejection(
            ctx, self._client_ip(), header_set,
        )

        # Opt-in WITNESSED submission: if the client passes
        # `X-MC-Witnessed-Submission: <hex(request_hash)>`, the server
        # MUST issue a SubmissionAck (admitted or rejected) that
        # commits the validator to having received the request.
        # Without this, a coerced validator could simply hang up the
        # TCP connection and leave no on-chain evidence; with it, the
        # client (and any witnesses who saw the gossip) holds a
        # signed proof of receipt that's slashable if it's ever
        # contradicted by a NonResponseEvidenceTx.
        #
        # The header value is the hex-encoded 32-byte request_hash
        # bound by the client's separately-gossiped SubmissionRequest.
        # Malformed values are silently ignored (the submission still
        # processes; the client just doesn't get an ack).  Witnessed
        # submission costs WITNESS_SURCHARGE on top of the normal fee
        # — the fee floor is enforced by validate_submission_request
        # at the gossip layer, not here.
        witnessed_request_hash: Optional[bytes] = None
        raw_hdr = (self.headers.get("X-MC-Witnessed-Submission") or "").strip()
        if raw_hdr:
            try:
                candidate = bytes.fromhex(raw_hdr)
                if len(candidate) == 32:
                    witnessed_request_hash = candidate
            except ValueError:
                witnessed_request_hash = None

        # Compute the ack-issuance gate.  Two conditions must hold for
        # the validator to burn a receipt-subtree leaf on behalf of a
        # witnessed-submission ack:
        #
        #   1. Per-IP ack budget allows it.  Without this, an attacker
        #      spamming the X-MC-Witnessed-Submission header from a /24
        #      drains all 65k receipt-subtree leaves in minutes,
        #      collapsing the censorship-evidence pipeline silently.
        #   2. (When a WitnessObservationStore is configured) the
        #      claimed request_hash must have been observed by THIS
        #      validator via gossip.  The header's value is supposed
        #      to be the request_hash bound by the client's separately
        #      gossiped SubmissionRequest -- a header value that this
        #      node never witnessed via gossip is, by definition, not
        #      a real witnessed request, and ack-ing it lets an
        #      attacker forge ack issuance for arbitrary 32-byte
        #      strings.  When no store is configured (RPC test paths,
        #      bare server contexts) we fall through and rely on the
        #      budget alone.
        #
        # Both gates are computed BEFORE submit() so the budget token
        # is consumed atomically with the decision to issue (mirror
        # of _should_request_rejection).
        ack_allowed = False
        if witnessed_request_hash is not None:
            budget_ok = ctx.ack_budget_check(self._client_ip())
            obs_ok = (
                ctx.witness_observation_store is None
                or ctx.witness_observation_store.get_observation_height(
                    witnessed_request_hash,
                ) is not None
            )
            ack_allowed = budget_ok and obs_ok

        # Inject via the shared helper (same semantics as RPC ingress).
        result = ctx.submit(
            tx, request_rejection=request_rejection,
            witnessed_request_hash=witnessed_request_hash,
            ack_allowed=ack_allowed,
        )

        # Defense-in-depth: if an ack was issued, fan it out to peers
        # via the ack_relay_callback.  Client already has the bytes
        # over HTTPS, but gossiping them ensures honest witnesses
        # learn of the discharge even if the validator silently drops
        # the HTTPS response.  Best-effort; never blocks the response.
        if result.ack_hex and ctx.ack_relay_callback is not None:
            try:
                ctx.ack_relay_callback(bytes.fromhex(result.ack_hex))
            except Exception:  # noqa: BLE001 — relay is best-effort
                logger.exception("ack relay hook raised")
        if not result.ok:
            if result.rejection_hex or result.ack_hex:
                # JSON 400 with optional signed-rejection and/or ack
                # blobs.  Hex-encoded binary so the client can forward
                # the same bytes into a BogusRejectionEvidenceTx
                # (rejection) or treat as proof of receipt (ack)
                # without any re-serialization risk.  Status stays
                # 400 — the tx was rejected; the extra payloads are
                # for accountability, not success.
                parts: list[bytes] = [
                    b'{"ok":false,"error":"',
                    result.error.replace('"', "'").encode("utf-8"),
                    b'"',
                ]
                if result.rejection_hex:
                    parts.append(b',"rejection":"')
                    parts.append(result.rejection_hex.encode("ascii"))
                    parts.append(b'"')
                if result.ack_hex:
                    parts.append(b',"ack":"')
                    parts.append(result.ack_hex.encode("ascii"))
                    parts.append(b'"')
                parts.append(b'}')
                resp = b"".join(parts)
                self.send_response(400)
                self.send_header(
                    "Content-Type", "application/json; charset=utf-8",
                )
                self.send_header("Content-Length", str(len(resp)))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(resp)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            self._reject(400, f"Rejected: {result.error}")
            return

        # Optional relay hook — fire-and-forget; errors in relay must
        # never cause an accepted tx to look rejected to the caller.
        if ctx.relay_callback is not None and not result.duplicate:
            try:
                ctx.relay_callback(tx)
            except Exception:  # noqa: BLE001 — relay is best-effort
                logger.exception("submission relay hook raised")

        # JSON body.  Include receipt iff the server-side issuer
        # produced one — clients that don't care about censorship
        # evidence can ignore the extra field, clients that do hold
        # onto it for EVIDENCE_INCLUSION_WINDOW blocks.  Sending the
        # hex-encoded binary blob (not a dict) because it's the
        # authoritative wire format that CensorshipEvidenceTx expects
        # — the client can forward the same bytes later without any
        # re-serialization risk.  Same shape used for the witnessed-
        # submission ack blob (NonResponseEvidenceTx consumes it).
        parts: list[bytes] = [
            b'{"ok":true,"tx_hash":"',
            tx.tx_hash.hex().encode("ascii"),
            b'"',
        ]
        if result.receipt_hex:
            parts.append(b',"receipt":"')
            parts.append(result.receipt_hex.encode("ascii"))
            parts.append(b'"')
        if result.ack_hex:
            parts.append(b',"ack":"')
            parts.append(result.ack_hex.encode("ascii"))
            parts.append(b'"')
        parts.append(b'}')
        resp = b"".join(parts)
        self._ok(resp)

    def _handle_custody_proof_submit(self, ctx):
        """POST /v1/submit-custody-proof — accept a CustodyProof blob.

        Same wire contract as /v1/submit: rate-limit, size gate, binary
        body (proof.to_bytes()), 200 with a receipt-style JSON on
        acceptance.  On success the proof lives in ctx.proof_pool and
        the next challenge-block proposer will pick it up (FCFS, up to
        ARCHIVE_PROOFS_PER_CHALLENGE).

        No proof pool on the server means the endpoint is disabled —
        a 404 keeps operators who don't want archive-proof ingress
        from accidentally exposing an unused surface.

        Optional `?challenge=<int>` query arg lets a client pin which
        challenge the proof answers; otherwise the helper infers it
        from proof.target_height.
        """
        if ctx.proof_pool is None:
            self._reject(404, "Not Found")
            return

        if not ctx.rate_limit_check(self._client_ip()):
            self._reject(429, "Too Many Requests")
            return

        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/octet-stream":
            self._reject(415, "Unsupported Media Type — use application/octet-stream")
            return

        try:
            declared_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._reject(400, "Invalid Content-Length")
            return
        if declared_length < 0 or declared_length > MAX_SUBMISSION_BODY_BYTES:
            self._reject(413, f"Payload too large (max {MAX_SUBMISSION_BODY_BYTES} bytes)")
            return

        to_read = min(declared_length, MAX_SUBMISSION_BODY_BYTES)
        try:
            body = self.rfile.read(to_read)
        except (ConnectionResetError, OSError):
            return
        if len(body) > MAX_SUBMISSION_BODY_BYTES:
            self._reject(413, "Payload too large")
            return

        from messagechain.consensus.archive_challenge import CustodyProof
        try:
            proof = CustodyProof.from_bytes(body)
        except Exception as e:
            logger.debug(
                "custody proof decode failed from %s: %s",
                self._client_ip(), e,
            )
            self._reject(400, "Invalid custody proof encoding")
            return

        result = ctx.submit_proof(proof)
        if not result.ok:
            self._reject(400, f"Rejected: {result.error}")
            return

        if ctx.proof_relay_callback is not None and not result.duplicate:
            try:
                ctx.proof_relay_callback(proof)
            except Exception:  # noqa: BLE001 — relay is best-effort
                logger.exception("custody proof relay hook raised")

        resp = (
            b'{"ok":true,"proof_hash":"'
            + result.tx_hash.hex().encode("ascii") + b'"}'
        )
        self._ok(resp)


class _HandlerContext:
    """Shared state for all handlers on a single SubmissionServer.

    Holds the chain, mempool, rate-limiter buckets, and an optional
    relay callback.  The handler reads these via
    `self.server._submission_context`.
    """

    def __init__(
        self,
        blockchain,
        mempool,
        relay_callback: Optional[Callable[[MessageTransaction], None]],
        receipt_issuer: Optional[ReceiptIssuer] = None,
        proof_pool=None,
        proof_relay_callback=None,
        ack_relay_callback=None,
        witness_observation_store=None,
    ):
        self.blockchain = blockchain
        self.mempool = mempool
        self.relay_callback = relay_callback
        # Optional ack-gossip hook.  When the server issues a
        # SubmissionAck, this callback is invoked with the raw ack
        # bytes so peers can mark the witness obligation discharged
        # via the witness gossip topic.  Defense in depth: the
        # client has the ack over HTTPS already, but a censoring
        # validator could silently drop the response — gossiping the
        # ack to peers means honest witnesses learn of the discharge
        # even when the response is dropped.
        self.ack_relay_callback = ack_relay_callback
        # Optional WitnessObservationStore.  When the server receives
        # a SubmissionRequest gossip blob (NOT addressed to itself),
        # it records the (request_hash, observed_height) so the local
        # node can later sign a WitnessObservation if the deadline
        # passes without a corresponding ack.
        self.witness_observation_store = witness_observation_store
        # Optional ReceiptIssuer — see submission_receipt.ReceiptIssuer.
        # When set, every fresh admission returns a signed receipt the
        # client can later weaponize as CensorshipEvidenceTx if the
        # receipted tx doesn't land on-chain within EVIDENCE_INCLUSION_WINDOW.
        self.receipt_issuer = receipt_issuer
        # Optional archive-proof mempool + gossip hook.  Operators who
        # don't participate in archive rewards leave these None; the
        # /v1/submit-custody-proof endpoint returns 404 in that case.
        self.proof_pool = proof_pool
        self.proof_relay_callback = proof_relay_callback
        self._buckets: dict[str, TokenBucket] = {}
        self._last_active: dict[str, float] = {}
        self._buckets_lock = threading.Lock()
        # Dedicated per-IP budget for X-MC-Request-Receipt=1 submissions.
        # Each exhaustion-via-bad-sig-spam rejection would otherwise
        # burn a leaf from the RECEIPT_SUBTREE (65k one-time keys at
        # height 16).  Sharing the base submission bucket means one
        # attacker IP could drain the subtree in hours.  Dedicated
        # bucket keeps honest slash-evidence issuance flowing at a
        # slow rate while closing the leaf-drain vector.
        self._rejection_buckets: dict[str, TokenBucket] = {}
        # Dedicated per-IP budget for the X-MC-Witnessed-Submission
        # opt-in path.  Every SubmissionAck consumes one WOTS+ leaf
        # from the SAME receipt subtree as receipts and rejections.
        # Pre-fix the ack path had no per-IP budget AND no binding
        # to a prior gossiped SubmissionRequest -- an attacker
        # spamming HTTP POSTs with random 32-byte header values
        # from a /24 drained all 65k leaves in minutes, after which
        # the entire censorship-evidence pipeline (receipts,
        # rejections, acks) collapsed silently because every issuance
        # path shares the subtree.  Sized so honest opt-in flows
        # (which paid WITNESS_SURCHARGE at the gossip layer) always
        # get an ack while any IP-flood attacker hits the ceiling
        # within seconds.
        self._ack_buckets: dict[str, TokenBucket] = {}
        # Cap the dict to prevent an attacker rotating IPs from
        # exhausting memory with one-shot buckets.
        self._max_tracked_ips = 4096

    def rate_limit_check(self, ip: str) -> bool:
        """Consume one token from `ip`'s bucket; return True iff allowed."""
        import time as _time
        with self._buckets_lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                # If we're at the cap, first evict inactive buckets,
                # then fall back to LRU eviction of the oldest active IP.
                if len(self._buckets) >= self._max_tracked_ips:
                    self._evict_inactive_locked()
                    if len(self._buckets) >= self._max_tracked_ips:
                        self._evict_lru_locked()
                    if len(self._buckets) >= self._max_tracked_ips:
                        return False
                bucket = TokenBucket(
                    rate=SUBMISSION_RATE_LIMIT_PER_SEC,
                    max_tokens=SUBMISSION_BURST,
                )
                self._buckets[ip] = bucket
            self._last_active[ip] = _time.time()
            return bucket.consume()

    def rejection_budget_check(self, ip: str) -> bool:
        """Consume one token from `ip`'s REJECTION bucket; True iff allowed.

        Separate from rate_limit_check — exhausting the rejection
        budget does NOT block the underlying submission, it only
        prevents a SignedRejection from being issued for that request.
        See the SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC comment in
        config.py for the rationale (receipt-subtree leaf drain).
        """
        import time as _time
        with self._buckets_lock:
            bucket = self._rejection_buckets.get(ip)
            if bucket is None:
                if len(self._rejection_buckets) >= self._max_tracked_ips:
                    # Inactive/LRU eviction on the rejection dict.
                    # Inline, mirrors the base-bucket logic above but
                    # scoped to self._rejection_buckets.
                    to_drop = []
                    for _ip, _b in self._rejection_buckets.items():
                        _b._refill()
                        if _b.tokens >= _b.max_tokens:
                            to_drop.append(_ip)
                    for _ip in to_drop:
                        del self._rejection_buckets[_ip]
                    if len(self._rejection_buckets) >= self._max_tracked_ips:
                        # LRU by last_active (shared with the base
                        # bucket — we reuse the same timestamps).
                        oldest_ip = min(
                            self._rejection_buckets,
                            key=lambda k: self._last_active.get(k, 0.0),
                        )
                        del self._rejection_buckets[oldest_ip]
                    if len(self._rejection_buckets) >= self._max_tracked_ips:
                        return False
                bucket = TokenBucket(
                    rate=SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC,
                    max_tokens=SUBMISSION_REJECTION_BURST,
                )
                self._rejection_buckets[ip] = bucket
            self._last_active[ip] = _time.time()
            return bucket.consume()

    def ack_budget_check(self, ip: str) -> bool:
        """Consume one token from `ip`'s ACK bucket; True iff allowed.

        Separate from rate_limit_check and rejection_budget_check.
        Each SubmissionAck consumes a WOTS+ leaf from the validator's
        receipt subtree -- without a dedicated cap, an attacker
        spamming `X-MC-Witnessed-Submission` headers from a /24 drains
        the whole subtree in minutes.  Exhausting the ack budget
        does NOT block the underlying submission -- it only prevents
        an ack from being issued for that request.  The HTTP handler
        then passes `ack_allowed=False` to submit_transaction_to_mempool
        so the submission still processes; the witnessed-submission
        client just doesn't get a signed ack back.
        """
        import time as _time
        with self._buckets_lock:
            bucket = self._ack_buckets.get(ip)
            if bucket is None:
                if len(self._ack_buckets) >= self._max_tracked_ips:
                    # Inactive eviction.
                    to_drop = []
                    for _ip, _b in self._ack_buckets.items():
                        _b._refill()
                        if _b.tokens >= _b.max_tokens:
                            to_drop.append(_ip)
                    for _ip in to_drop:
                        del self._ack_buckets[_ip]
                    if len(self._ack_buckets) >= self._max_tracked_ips:
                        # LRU by last_active (shared timestamps).
                        oldest_ip = min(
                            self._ack_buckets,
                            key=lambda k: self._last_active.get(k, 0.0),
                        )
                        del self._ack_buckets[oldest_ip]
                    if len(self._ack_buckets) >= self._max_tracked_ips:
                        return False
                bucket = TokenBucket(
                    rate=SUBMISSION_ACK_RATE_LIMIT_PER_SEC,
                    max_tokens=SUBMISSION_ACK_BURST,
                )
                self._ack_buckets[ip] = bucket
            self._last_active[ip] = _time.time()
            return bucket.consume()

    def _evict_inactive_locked(self):
        """Drop buckets that are fully refilled (peer hasn't posted in a while)."""
        to_drop = []
        for ip, bucket in self._buckets.items():
            bucket._refill()
            if bucket.tokens >= bucket.max_tokens:
                to_drop.append(ip)
        for ip in to_drop:
            del self._buckets[ip]
            self._last_active.pop(ip, None)

    def _evict_lru_locked(self):
        """Evict the least-recently-active IP to make room for a new one."""
        if not self._last_active:
            return
        oldest_ip = min(self._last_active, key=self._last_active.get)
        self._buckets.pop(oldest_ip, None)
        self._last_active.pop(oldest_ip, None)

    def submit(
        self,
        tx: MessageTransaction,
        request_rejection: bool = False,
        witnessed_request_hash: Optional[bytes] = None,
        ack_allowed: bool = True,
    ) -> SubmissionResult:
        return submit_transaction_to_mempool(
            tx, self.blockchain, self.mempool,
            receipt_issuer=self.receipt_issuer,
            request_rejection=request_rejection,
            witnessed_request_hash=witnessed_request_hash,
            ack_allowed=ack_allowed,
        )

    def submit_proof(self, proof) -> SubmissionResult:
        """Shared ingress for CustodyProof.  Returns SubmissionResult."""
        if self.proof_pool is None:
            return SubmissionResult(ok=False, error="proof pool not configured")
        return submit_custody_proof_to_pool(
            proof, self.blockchain, self.proof_pool,
        )


class _ThreadingHTTPSServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """HTTPS server with threaded request handling.

    Wraps the listening socket in TLS.  Daemon threads so a shutdown
    doesn't wait on in-flight requests.
    """
    daemon_threads = True
    allow_reuse_address = True


class SubmissionServer:
    """Public HTTPS transaction-submission endpoint.

    Lifecycle:
        >>> s = SubmissionServer(chain, mempool, cert, key, port=8443)
        >>> s.start()          # spawns background thread
        >>> ...                # serve requests
        >>> s.stop()           # clean shutdown

    `relay_callback`, if provided, is called once per accepted tx with
    the `MessageTransaction` instance.  The server wraps the call in a
    broad except so a broken hook never surfaces as a client-visible
    error.  Pass a function that schedules a gossip relay on the main
    server's event loop; keep it fast (it runs on the HTTP handler
    thread).
    """

    def __init__(
        self,
        blockchain,
        mempool,
        cert_path: str,
        key_path: str,
        port: int,
        bind: str = "0.0.0.0",
        relay_callback: Optional[Callable[[MessageTransaction], None]] = None,
        receipt_issuer: Optional[ReceiptIssuer] = None,
        proof_pool=None,
        proof_relay_callback=None,
        ack_relay_callback: Optional[Callable[[bytes], None]] = None,
        witness_observation_store=None,
    ):
        self.blockchain = blockchain
        self.mempool = mempool
        self.cert_path = cert_path
        self.key_path = key_path
        self.port = port
        self.bind = bind
        self.relay_callback = relay_callback
        # Optional ReceiptIssuer — see submission_receipt.ReceiptIssuer.
        # When set, every fresh admission returns a signed receipt the
        # client can later weaponize as CensorshipEvidenceTx if the
        # receipted tx doesn't land on-chain within EVIDENCE_INCLUSION_WINDOW.
        self.receipt_issuer = receipt_issuer
        # Optional archive-proof mempool + gossip hook.  Operators who
        # don't participate in archive rewards leave these None; the
        # /v1/submit-custody-proof endpoint is disabled in that case.
        self.proof_pool = proof_pool
        self.proof_relay_callback = proof_relay_callback
        # Optional ack-gossip hook + witness observation store — see
        # _HandlerContext for semantics.  Operators who do NOT want to
        # participate in witnessed submission leave these None; the
        # X-MC-Witnessed-Submission header is silently no-op'd in that
        # case (the submission still processes; the client just gets
        # no ack).
        self.ack_relay_callback = ack_relay_callback
        self.witness_observation_store = witness_observation_store
        self._httpd: Optional[_ThreadingHTTPSServer] = None
        self._thread: Optional[threading.Thread] = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Server-side TLS context with sensible defaults.

        Uses the stdlib default-modern cipher list.  No client certs —
        this endpoint's caller is anonymous by design.  TLSv1.2+; the
        default Python stdlib rejects TLSv1.0/1.1 on modern builds.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        # Disable old protocols explicitly.  Python's default already
        # excludes them on recent builds, but being explicit is cheap
        # and survives future python-version downgrades.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def start(self):
        """Bind the socket, start the server thread.  Non-blocking."""
        if self._thread is not None:
            raise RuntimeError("SubmissionServer already started")

        handler_cls = _SubmissionHandler

        self._httpd = _ThreadingHTTPSServer(
            (self.bind, self.port), handler_cls,
        )
        # Attach shared context before wrapping — handlers read it off
        # the server instance.
        self._httpd._submission_context = _HandlerContext(
            blockchain=self.blockchain,
            mempool=self.mempool,
            relay_callback=self.relay_callback,
            receipt_issuer=self.receipt_issuer,
            proof_pool=self.proof_pool,
            proof_relay_callback=self.proof_relay_callback,
            ack_relay_callback=self.ack_relay_callback,
            witness_observation_store=self.witness_observation_store,
        )
        ssl_context = self._build_ssl_context()
        self._httpd.socket = ssl_context.wrap_socket(
            self._httpd.socket, server_side=True,
        )

        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name=f"mc-submission-{self.port}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Submission server listening on https://%s:%d/v1/submit",
            self.bind, self.port,
        )

    def stop(self, timeout: float = 5.0):
        """Signal shutdown and wait for the thread to exit."""
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
        except Exception:  # noqa: BLE001 — server may already be dead
            pass
        try:
            self._httpd.server_close()
        except Exception:  # noqa: BLE001
            pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._httpd = None
        self._thread = None

    @property
    def address(self) -> tuple[str, int]:
        """(bind, port) — handy for tests that pick a free port."""
        return (self.bind, self.port)
