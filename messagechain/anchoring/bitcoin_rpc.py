"""Thin Bitcoin Core JSON-RPC client — stdlib only (urllib.request).

This module handles the HTTP transport for talking to a local Bitcoin Core
node. It does NOT parse Bitcoin-specific data structures; that is the job
of bitcoin_anchor.py.

Security note: the RPC credentials are the operator's responsibility.
This client sends them in HTTP Basic auth over localhost. Do NOT point
this at a remote Bitcoin node without TLS.
"""

import json
import urllib.request


def bitcoin_rpc_call(
    rpc_url: str,
    method: str,
    params: list | None = None,
    *,
    rpc_user: str = "",
    rpc_password: str = "",
) -> dict:
    """Make a JSON-RPC call to Bitcoin Core.

    Returns the parsed JSON response dict.  Raises on transport errors.
    The caller is responsible for checking response["error"].

    Args:
        rpc_url: Full URL, e.g. "http://localhost:8332"
        method: RPC method name, e.g. "sendrawtransaction"
        params: Positional parameters for the RPC call
        rpc_user: Bitcoin Core RPC username (from bitcoin.conf)
        rpc_password: Bitcoin Core RPC password (from bitcoin.conf)
    """
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "messagechain-anchor",
        "method": method,
        "params": params or [],
    }).encode("utf-8")

    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    # Add Basic auth if credentials are provided
    if rpc_user or rpc_password:
        import base64
        credentials = base64.b64encode(
            f"{rpc_user}:{rpc_password}".encode()
        ).decode()
        req.add_header("Authorization", f"Basic {credentials}")

    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))
