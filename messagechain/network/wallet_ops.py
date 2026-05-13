"""
Sign-and-submit helpers used by LocalWalletServer's /wallet/* routes.

Each ``op_*`` function wraps the same core flow:

    1. RPC ``get_nonce`` for the entity (mempool-aware)
    2. RPC ``reserve_leaf`` (best-effort; falls back to leaf_watermark
       from the get_nonce response when the validator does not expose
       the reserve_leaf RPC)
    3. ``_bind_persistent_leaf_index`` -- attach the per-wallet on-disk
       leaf cursor BEFORE signing.  This is the cross-process WOTS+
       leaf-reuse defense: every signing surface (CLI, wallet UI) MUST
       share the same cursor file, or two surfaces signing back-to-back
       on the same wallet will burn the same one-time leaf and produce
       slashable equivocation evidence on chain.
    4. Build the tx via the appropriate ``create_X_transaction`` factory
       (these factories sign internally via ``entity.keypair.sign``).
    5. RPC ``submit_X`` with the serialized tx hex.

Failure modes consistently shaped: every helper returns
``{"ok": True, "result": {...}}`` or ``{"ok": False, "error": "..."}``
so the wallet server's HTTP handlers are thin JSON-to-call wrappers.

This module deliberately does NOT replicate the CLI's
human-readable progress prints, the receipt-bundle persistence, the
first-spend pubkey auto-detection, or the auto-fee urgency rungs.  The
wallet UI is for the "I want to post / transfer / stake" 80% case, and
those affordances either belong in the UI layer (fee preview via
/wallet/estimate-fee) or are operator-tier (receipt bundles for
censorship-evidence escalation belong in the CLI's `submit-evidence`
flow, not in a clickable surface).
"""

from __future__ import annotations

import logging
from typing import Callable, Optional


logger = logging.getLogger("messagechain.wallet_ops")


__all__ = [
    "op_send_message",
    "op_transfer",
    "op_stake",
    "op_unstake",
    "op_react",
    "op_estimate_fee",
]


def _safe_rpc(rpc_caller: Callable, method: str, params: dict):
    """Run an RPC call; return (ok, payload).  ConnectionError /
    socket-level failures map to ok=False so the caller can shape a
    503-style response without leaking exception class to the browser."""
    try:
        return True, rpc_caller(method, params)
    except Exception as e:
        logger.warning("wallet_ops RPC %s failed: %s", method, type(e).__name__)
        return False, {
            "ok": False,
            "error": f"RPC {method} unreachable: {type(e).__name__}",
        }


def _resolve_nonce_and_tip(rpc_caller: Callable, entity_id_hex: str):
    """Pull nonce + chain-tip + watermark for a tx build.

    Returns (ok, payload).  Leaf reservation + persistent-cursor bind
    is NOT done here -- that is the caller's job, and it MUST go
    through ``cli._resolve_signing_leaf_via_caller`` so wallet ops
    share the audit r54 #2 chokepoint with every CLI signing command.

    ``payload`` shape on success:
        {"nonce": int, "watermark": int, "tip": int | None}
    """
    ok, nonce_resp = _safe_rpc(
        rpc_caller, "get_nonce", {"entity_id": entity_id_hex},
    )
    if not ok:
        return False, nonce_resp
    if not nonce_resp.get("ok"):
        return False, nonce_resp
    nonce = nonce_resp["result"]["nonce"]
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)

    # Optional tip pull -- create_transaction wants current_height for
    # height-aware fee floor / version selection.  Use get_chain_info;
    # fall back to None so the legacy floor is used (always conservative).
    ok_t, info_resp = _safe_rpc(rpc_caller, "get_chain_info", {})
    tip = None
    if ok_t and info_resp.get("ok"):
        tip = (info_resp.get("result") or {}).get("height")

    return True, {"nonce": nonce, "watermark": watermark, "tip": tip}


def op_send_message(
    entity,
    rpc_caller: Callable,
    *,
    message: str,
    fee: int,
    prev: Optional[bytes] = None,
    community_id: Optional[str] = None,
    poll_options: Optional[tuple] = None,
    vote_target: Optional[tuple] = None,
    include_pubkey: bool = False,
    data_dir: Optional[str] = None,
) -> dict:
    """Build, sign, and submit a message transaction.

    Mirrors cmd_send's core pipeline but stripped of the CLI's
    print/progress affordances.  Returns:

        {"ok": True, "result": {"tx_hash": "...", "fee": <int>}}

    on success, or ``{"ok": False, "error": "..."}`` on any failure
    (validation, RPC unreachable, validator rejection)."""
    from messagechain.core.transaction import create_transaction
    from messagechain.cli import _resolve_signing_leaf_via_caller

    if not isinstance(message, str) or not message.strip():
        return {"ok": False, "error": "message must be a non-empty string"}
    if not isinstance(fee, int) or fee < 0:
        return {"ok": False, "error": "fee must be a non-negative integer"}

    entity_id_hex = entity.entity_id_hex

    ok, ctx = _resolve_nonce_and_tip(rpc_caller, entity_id_hex)
    if not ok:
        return ctx

    # Atomic leaf reservation + persistent cursor bind -- the audit
    # r54 #2 chokepoint that EVERY signing surface (CLI + wallet UI)
    # MUST route through.  A wallet-side signing path that built its
    # own leaf-resolution would re-open the cross-process WOTS+ leaf-
    # reuse race window the CLI side already closes -- 100% slash on
    # detection of equivocation evidence.
    _resolve_signing_leaf_via_caller(
        rpc_caller, entity,
        data_dir=data_dir,
        watermark_fallback=ctx["watermark"],
    )

    try:
        tx = create_transaction(
            entity,
            message,
            fee=fee,
            nonce=ctx["nonce"],
            current_height=ctx["tip"],
            prev=prev,
            include_pubkey=include_pubkey,
            community_id=community_id,
            poll_options=poll_options,
            vote_target=vote_target,
        )
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    ok_s, submit_resp = _safe_rpc(
        rpc_caller, "submit_transaction", {"transaction": tx.serialize()},
    )
    if not ok_s:
        return submit_resp
    if not submit_resp.get("ok"):
        return submit_resp
    result = submit_resp.get("result") or {}
    return {
        "ok": True,
        "result": {
            "tx_hash": result.get("tx_hash") or tx.tx_hash.hex(),
            "fee": fee,
        },
    }


def op_transfer(
    entity,
    rpc_caller: Callable,
    *,
    recipient: bytes,
    amount: int,
    fee: int,
    include_pubkey: bool = False,
    data_dir: Optional[str] = None,
) -> dict:
    """Build, sign, submit a transfer transaction."""
    from messagechain.core.transfer import create_transfer_transaction
    from messagechain.cli import _resolve_signing_leaf_via_caller

    if not isinstance(recipient, (bytes, bytearray)) or len(recipient) != 32:
        return {"ok": False, "error": "recipient must be 32 bytes"}
    if not isinstance(amount, int) or amount <= 0:
        return {"ok": False, "error": "amount must be a positive integer"}
    if not isinstance(fee, int) or fee < 0:
        return {"ok": False, "error": "fee must be a non-negative integer"}
    if entity.entity_id == bytes(recipient):
        return {"ok": False, "error": "cannot transfer to yourself"}

    ok, ctx = _resolve_nonce_and_tip(rpc_caller, entity.entity_id_hex)
    if not ok:
        return ctx

    _resolve_signing_leaf_via_caller(
        rpc_caller, entity,
        data_dir=data_dir,
        watermark_fallback=ctx["watermark"],
    )

    try:
        tx = create_transfer_transaction(
            entity, bytes(recipient), amount, ctx["nonce"],
            fee=fee, include_pubkey=include_pubkey,
        )
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    ok_s, submit_resp = _safe_rpc(
        rpc_caller, "submit_transfer", {"transaction": tx.serialize()},
    )
    if not ok_s:
        return submit_resp
    if not submit_resp.get("ok"):
        return submit_resp
    return {"ok": True, "result": {
        "tx_hash": tx.tx_hash.hex(), "amount": amount, "fee": fee,
    }}


def op_stake(
    entity,
    rpc_caller: Callable,
    *,
    amount: int,
    fee: int,
    include_pubkey: bool = False,
    data_dir: Optional[str] = None,
) -> dict:
    """Build, sign, submit a stake transaction."""
    from messagechain.core.staking import create_stake_transaction
    from messagechain.cli import _resolve_signing_leaf_via_caller

    if not isinstance(amount, int) or amount <= 0:
        return {"ok": False, "error": "amount must be a positive integer"}
    if not isinstance(fee, int) or fee < 0:
        return {"ok": False, "error": "fee must be a non-negative integer"}

    ok, ctx = _resolve_nonce_and_tip(rpc_caller, entity.entity_id_hex)
    if not ok:
        return ctx

    _resolve_signing_leaf_via_caller(
        rpc_caller, entity,
        data_dir=data_dir,
        watermark_fallback=ctx["watermark"],
    )

    try:
        tx = create_stake_transaction(
            entity, amount, ctx["nonce"], fee=fee,
            include_pubkey=include_pubkey,
        )
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    ok_s, submit_resp = _safe_rpc(
        rpc_caller, "stake", {"transaction": tx.serialize()},
    )
    if not ok_s:
        return submit_resp
    if not submit_resp.get("ok"):
        return submit_resp
    return {"ok": True, "result": {
        "tx_hash": tx.tx_hash.hex(), "amount": amount, "fee": fee,
    }}


def op_unstake(
    entity,
    rpc_caller: Callable,
    *,
    amount: int,
    fee: int,
    data_dir: Optional[str] = None,
) -> dict:
    """Build, sign, submit an unstake transaction.

    Hot-key path only.  Cold-authority unstake (post-SetAuthorityKey)
    requires the offline cold key, which the wallet UI does NOT load
    -- power users must run cmd_unstake on the CLI with --cold-keyfile
    for that case.  See cli.py cmd_unstake for the full rationale."""
    from messagechain.core.staking import create_unstake_transaction
    from messagechain.cli import _resolve_signing_leaf_via_caller

    if not isinstance(amount, int) or amount <= 0:
        return {"ok": False, "error": "amount must be a positive integer"}
    if not isinstance(fee, int) or fee < 0:
        return {"ok": False, "error": "fee must be a non-negative integer"}

    ok, ctx = _resolve_nonce_and_tip(rpc_caller, entity.entity_id_hex)
    if not ok:
        return ctx

    _resolve_signing_leaf_via_caller(
        rpc_caller, entity,
        data_dir=data_dir,
        watermark_fallback=ctx["watermark"],
    )

    try:
        tx = create_unstake_transaction(
            entity, amount, ctx["nonce"], fee=fee,
        )
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    ok_s, submit_resp = _safe_rpc(
        rpc_caller, "unstake", {"transaction": tx.serialize()},
    )
    if not ok_s:
        return submit_resp
    if not submit_resp.get("ok"):
        return submit_resp
    return {"ok": True, "result": {
        "tx_hash": tx.tx_hash.hex(), "amount": amount, "fee": fee,
    }}


def op_react(
    entity,
    rpc_caller: Callable,
    *,
    target: bytes,
    target_is_user: bool,
    choice: int,
    fee: int,
    data_dir: Optional[str] = None,
) -> dict:
    """Build, sign, submit a react transaction.

    ``target_is_user``: True for entity-trust votes (target is a 32B
    entity_id), False for message-quality votes (target is a 32B
    tx_hash).  ``choice``: messagechain.core.reaction.REACT_CHOICE_*
    -- CLEAR=0, UP=1, DOWN=2 in the current wire."""
    from messagechain.core.reaction import create_react_transaction
    from messagechain.cli import _resolve_signing_leaf_via_caller

    if not isinstance(target, (bytes, bytearray)) or len(target) != 32:
        return {"ok": False, "error": "target must be 32 bytes"}
    if not isinstance(choice, int):
        return {"ok": False, "error": "choice must be an integer"}
    if not isinstance(fee, int) or fee < 0:
        return {"ok": False, "error": "fee must be a non-negative integer"}

    ok, ctx = _resolve_nonce_and_tip(rpc_caller, entity.entity_id_hex)
    if not ok:
        return ctx

    _resolve_signing_leaf_via_caller(
        rpc_caller, entity,
        data_dir=data_dir,
        watermark_fallback=ctx["watermark"],
    )

    try:
        tx = create_react_transaction(
            entity,
            target=bytes(target),
            target_is_user=bool(target_is_user),
            choice=choice,
            nonce=ctx["nonce"],
            fee=fee,
        )
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    ok_s, submit_resp = _safe_rpc(
        rpc_caller, "submit_react", {"transaction": tx.serialize()},
    )
    if not ok_s:
        return submit_resp
    if not submit_resp.get("ok"):
        return submit_resp
    return {"ok": True, "result": {
        "tx_hash": tx.tx_hash.hex(),
        "target": bytes(target).hex(),
        "choice": choice,
        "fee": fee,
    }}


def op_estimate_fee(
    rpc_caller: Callable,
    *,
    message_bytes: int = 0,
) -> dict:
    """Return the validator's current fee estimate.

    Pure RPC pass-through; surfaced as a wallet route so the UI can
    render a "this will cost ~X tokens" line in the composer before
    the user commits to signing."""
    if not isinstance(message_bytes, int) or message_bytes < 0:
        return {"ok": False, "error": "message_bytes must be a non-negative integer"}
    ok, resp = _safe_rpc(
        rpc_caller, "get_fee_estimate", {"message_bytes": message_bytes},
    )
    if not ok:
        return resp
    return resp
