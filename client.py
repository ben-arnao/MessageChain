#!/usr/bin/env python3
"""
MessageChain Client

Two commands:
    python client.py create-account    # Register with your private key
    python client.py send-message      # Post a message to the chain

That's it.
"""

import argparse
import json
import socket
import struct
import sys
import getpass

from messagechain.config import MAX_MESSAGE_CHARS
from messagechain.identity.identity import Entity
from messagechain.core.transaction import create_transaction
from messagechain.validation import safe_json_loads


def rpc_call(
    host: str, port: int, method: str, params: dict,
    auth: str | None = None,
) -> dict:
    """Send an RPC request to the server and return the response.

    `auth`: optional admin-method auth token.  When omitted, the
    `MESSAGECHAIN_RPC_AUTH_TOKEN` env var is consulted -- this lets a
    co-resident CLI invocation (operator on the same host as the
    daemon) inherit the same secret the daemon was started with
    without forcing every call site to thread it through.  The
    server only checks the token for methods in `_ADMIN_RPC_METHODS`,
    so an unset token only matters when calling those methods.
    """
    import os as _os
    if auth is None:
        auth = _os.environ.get("MESSAGECHAIN_RPC_AUTH_TOKEN") or None
    payload = {"method": method, "params": params}
    if auth is not None:
        payload["auth"] = auth
    request = json.dumps(payload).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
        sock.sendall(struct.pack(">I", len(request)))
        sock.sendall(request)

        # Read response
        length_bytes = _recv_exact(sock, 4)
        length = struct.unpack(">I", length_bytes)[0]
        # M13: Reject oversized responses to prevent memory exhaustion
        MAX_RESPONSE_LENGTH = 10_000_000  # 10 MB
        if length > MAX_RESPONSE_LENGTH:
            raise ValueError(f"Response too large: {length} bytes (max {MAX_RESPONSE_LENGTH})")
        data = _recv_exact(sock, length)
        return safe_json_loads(data.decode("utf-8"), max_depth=32)
    finally:
        sock.close()


def _recv_exact(sock, n):
    """Receive exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def collect_private_key() -> bytes:
    """
    Collect private key from the user.

    The private key is the sole credential:
    - It deterministically derives the signing keypair
    - The entity ID (wallet address) is derived from the public key

    In production, the private key never leaves the local device.
    """
    print("Enter your private key.")
    print("Your private key is your identity — guard it carefully.\n")

    private_key = getpass.getpass("Private key (hidden): ").encode("utf-8")

    if not private_key:
        print("Error: Private key is required.")
        sys.exit(1)

    return private_key


def cmd_create_account(args):
    """Derive an account locally.

    Receive-to-exist model: no on-chain registration step.  The account
    appears on chain the first time someone sends it a transfer; the
    first outgoing transfer from it reveals the pubkey automatically.
    """
    print("=== Create Account ===\n")

    private_key = collect_private_key()

    entity = Entity.create(private_key)
    print(f"\nAccount derived from your private key.")
    print(f"  Entity ID:  {entity.entity_id_hex}")
    print()
    print("Your account will appear on chain when someone first sends")
    print("you tokens.  Your first outgoing transfer will reveal your")
    print("public key to the chain automatically.")
    print("Your private key is your sole credential. Never share it.")


def cmd_send_message(args):
    """Send a message to the chain."""
    print("=== Send Message ===\n")

    # Get message
    message = args.message
    if not message:
        print(f"Enter your message ({MAX_MESSAGE_CHARS} characters max):")
        message = input("> ").strip()
    if not message:
        print("Error: Message cannot be empty.")
        sys.exit(1)

    char_count = len(message)
    if char_count > MAX_MESSAGE_CHARS:
        print(f"Error: Message is {char_count} characters (max {MAX_MESSAGE_CHARS}).")
        sys.exit(1)

    # Collect private key to sign
    print("\nAuthenticate with your private key to sign this message.")
    private_key = collect_private_key()

    # Reconstruct entity from private key
    entity = Entity.create(private_key)
    print(f"\nSigning as: {entity.entity_id_hex[:16]}...")

    # Get current nonce from server (also used to advance WOTS+ leaf index)
    nonce_resp = rpc_call(args.host, args.rpc_port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]


    # Get fee estimate — pass our message's stored byte count so the
    # server returns a size-aware suggested fee (median fee-per-byte ×
    # bytes), matching the proposer's selection priority.
    fee = args.fee
    if not fee:
        est_resp = rpc_call(args.host, args.rpc_port, "get_fee_estimate", {
            "message_bytes": len(message.encode("utf-8")),
        })
        suggested = est_resp["result"]["fee_estimate"] if est_resp.get("ok") else 1
        print(f"Suggested fee: {suggested} tokens (higher = faster inclusion)")
        fee_input = input(f"Fee [{suggested}]: ").strip()
        fee = int(fee_input) if fee_input else suggested

    # Optional --prev pointer: parse & validate before we burn a
    # WOTS+ leaf on signing.  The server will re-validate strict-prev
    # against the chain, but catching malformed input here avoids a
    # doomed signature + rejection round-trip.
    prev_bytes = None
    if getattr(args, "prev", None):
        prev_hex = args.prev.strip()
        if len(prev_hex) != 64:
            print(
                f"Error: --prev must be exactly 64 hex chars "
                f"(got {len(prev_hex)})."
            )
            sys.exit(1)
        try:
            prev_bytes = bytes.fromhex(prev_hex)
        except ValueError:
            print("Error: --prev is not valid hex.")
            sys.exit(1)

    # Create and sign transaction locally
    tx = create_transaction(
        entity, message, fee=fee, nonce=nonce, prev=prev_bytes,
    )

    # Submit to server
    print(f"Submitting transaction...")
    response = rpc_call(args.host, args.rpc_port, "submit_transaction", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nMessage sent!")
        print(f"  TX hash: {result['tx_hash']}")
        print(f"  Fee:     {result['fee']} tokens")
        print(f"  Chars:   {char_count}")
        print(f"  Status:  {result['message']}")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_transfer(args):
    """Transfer tokens to another entity."""
    from messagechain.core.transfer import create_transfer_transaction

    print("=== Transfer Tokens ===\n")
    private_key = collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nSending as: {entity.entity_id_hex[:16]}...")

    nonce_resp = rpc_call(args.host, args.rpc_port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    # Position keypair past every leaf the chain has ever seen from this
    # entity — nonce alone is insufficient because block/attestation/
    # registration signatures also consume leaves without a nonce bump.
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

    from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE
    recipient_id = bytes.fromhex(args.to)

    # Ask the server whether this recipient is brand-new, so we bundle
    # the NEW_ACCOUNT_FEE surcharge by default when needed (otherwise
    # the validator rejects the tx with "new-account surcharge required").
    est_resp = rpc_call(args.host, args.rpc_port, "estimate_fee", {
        "kind": "transfer",
        "recipient_id": args.to,
    })
    recipient_is_new = False
    server_min_fee = MIN_FEE
    if est_resp.get("ok"):
        r = est_resp["result"]
        recipient_is_new = bool(r.get("recipient_is_new", False))
        server_min_fee = int(r.get("min_fee", MIN_FEE))

    required_floor = max(MIN_FEE, server_min_fee)
    fee = args.fee if args.fee else required_floor
    if fee < required_floor:
        if recipient_is_new:
            print(
                f"Error: fee {fee} is below required {required_floor} "
                f"(MIN_FEE {MIN_FEE} + NEW_ACCOUNT_FEE {NEW_ACCOUNT_FEE})."
            )
        else:
            print(f"Error: fee {fee} is below MIN_FEE {MIN_FEE}.")
        sys.exit(1)
    tx = create_transfer_transaction(entity, recipient_id, args.amount, nonce=nonce, fee=fee)

    if recipient_is_new:
        print(
            f"Transferring to a brand-new account — "
            f"+{NEW_ACCOUNT_FEE} NEW_ACCOUNT_FEE surcharge (burned)"
        )
    print(f"Transferring {args.amount} tokens to {args.to[:16]}... (fee: {fee})")
    response = rpc_call(args.host, args.rpc_port, "submit_transfer", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nTransfer submitted!")
        print(f"  TX hash: {result['tx_hash']}")
        print(f"  Amount:  {result['amount']} tokens")
        print(f"  Fee:     {result['fee']} tokens")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_balance(args):
    """Check account balance."""
    print("=== Account Balance ===\n")
    private_key = collect_private_key()
    entity = Entity.create(private_key)

    response = rpc_call(args.host, args.rpc_port, "get_entity", {
        "entity_id": entity.entity_id_hex,
    })

    if response.get("ok"):
        info = response["result"]
        print(f"  Entity ID:       {info['entity_id']}")
        print(f"  Balance:         {info['balance']} tokens")
        print(f"  Staked:          {info['staked']} tokens")
        print(f"  Messages posted: {info['messages_posted']}")
        print(f"  Nonce:           {info['nonce']}")
    else:
        print(f"\nError: {response.get('error')}")
        sys.exit(1)


def cmd_stake(args):
    """Stake tokens to become a validator."""
    from messagechain.core.staking import create_stake_transaction

    print("=== Stake Tokens ===\n")
    private_key = collect_private_key()
    entity = Entity.create(private_key)

    nonce_resp = rpc_call(args.host, args.rpc_port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    # Position keypair past every leaf the chain has ever seen from this
    # entity — nonce alone is insufficient because block/attestation/
    # registration signatures also consume leaves without a nonce bump.
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

    fee = args.fee if args.fee else 1
    tx = create_stake_transaction(entity, args.amount, nonce=nonce, fee=fee)

    response = rpc_call(args.host, args.rpc_port, "stake", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nStake submitted!")
        print(f"  TX hash: {result['tx_hash']}")
        print(f"  Staked:  {result['staked']} tokens")
        print(f"  Balance: {result['balance']} tokens")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_unstake(args):
    """Unstake tokens."""
    from messagechain.core.staking import create_unstake_transaction

    print("=== Unstake Tokens ===\n")
    private_key = collect_private_key()
    entity = Entity.create(private_key)

    nonce_resp = rpc_call(args.host, args.rpc_port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    # Position keypair past every leaf the chain has ever seen from this
    # entity — nonce alone is insufficient because block/attestation/
    # registration signatures also consume leaves without a nonce bump.
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

    fee = args.fee if args.fee else 1
    tx = create_unstake_transaction(entity, args.amount, nonce=nonce, fee=fee)

    response = rpc_call(args.host, args.rpc_port, "unstake", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nUnstake submitted!")
        print(f"  TX hash: {result['tx_hash']}")
        print(f"  Staked:  {result['staked']} tokens")
        print(f"  Balance: {result['balance']} tokens")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_generate_key(_args):
    """Generate a new cryptographically random private key."""
    import os
    key = os.urandom(32)
    print("=== Key Generated ===\n")
    print(f"  Private key: {key.hex()}")
    print(f"\n  WARNING: Save this key securely. It is your sole credential.")
    print("  Anyone with this key controls your account. There is no recovery.")
    print("  This key will NOT be shown again.")


def cmd_read(args):
    """Read recent messages from the chain."""
    response = rpc_call(args.host, args.rpc_port, "get_messages", {"count": args.last})

    if response.get("ok"):
        messages = response["result"]["messages"]
        if not messages:
            print("No messages on chain yet.")
            return

        print(f"=== Recent Messages ({len(messages)}) ===\n")
        for msg in messages:
            import datetime
            ts = datetime.datetime.fromtimestamp(msg["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            entity = msg["entity_id"][:16]
            print(f"  [{ts}] {entity}...")
            print(f"  {msg['message']}")
            print()
    else:
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="MessageChain Client",
        usage="client.py {create-account,send-message,transfer,balance,stake,unstake,generate-key,read} [options]",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--rpc-port", type=int, default=9334, help="Server RPC port (default: 9334)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # create-account
    subparsers.add_parser("create-account", help="Register a new account")

    # send-message
    send_parser = subparsers.add_parser("send-message", help="Send a message to the chain")
    send_parser.add_argument("-m", "--message", type=str, help="Message text (or enter interactively)")
    send_parser.add_argument("-f", "--fee", type=int, help="Transaction fee (or enter interactively)")
    send_parser.add_argument(
        "--prev",
        type=str,
        help=(
            "Optional tx_hash (64 hex chars) this message references as "
            "its predecessor — e.g. a reply, or the previous chunk of a "
            "longer chained document.  The referenced tx must already be "
            "on-chain in a strictly earlier block.  Adds 33 stored bytes "
            "to the fee basis but does NOT count against the 1024-char cap."
        ),
    )

    # transfer
    transfer_parser = subparsers.add_parser("transfer", help="Transfer tokens to another entity")
    transfer_parser.add_argument("--to", required=True, help="Recipient entity ID (hex)")
    transfer_parser.add_argument("--amount", type=int, required=True, help="Amount to transfer")
    transfer_parser.add_argument("-f", "--fee", type=int, help="Transaction fee")

    # balance
    subparsers.add_parser("balance", help="Check your account balance")

    # stake
    stake_parser = subparsers.add_parser("stake", help="Stake tokens to become a validator")
    stake_parser.add_argument("--amount", type=int, required=True, help="Amount to stake")
    stake_parser.add_argument("-f", "--fee", type=int, help="Transaction fee")

    # unstake
    unstake_parser = subparsers.add_parser("unstake", help="Unstake tokens")
    unstake_parser.add_argument("--amount", type=int, required=True, help="Amount to unstake")
    unstake_parser.add_argument("-f", "--fee", type=int, help="Transaction fee")

    # generate-key
    subparsers.add_parser("generate-key", help="Generate a new private key")

    # read
    read_parser = subparsers.add_parser("read", help="Read recent messages from the chain")
    read_parser.add_argument("--last", type=int, default=10, help="Number of messages (default: 10)")

    args = parser.parse_args()

    commands = {
        "create-account": cmd_create_account,
        "send-message": cmd_send_message,
        "transfer": cmd_transfer,
        "balance": cmd_balance,
        "stake": cmd_stake,
        "unstake": cmd_unstake,
        "generate-key": cmd_generate_key,
        "read": cmd_read,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
