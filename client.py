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

from messagechain.identity.biometrics import Entity
from messagechain.core.transaction import create_transaction


def rpc_call(host: str, port: int, method: str, params: dict) -> dict:
    """Send an RPC request to the server and return the response."""
    request = json.dumps({"method": method, "params": params}).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
        sock.sendall(struct.pack(">I", len(request)))
        sock.sendall(request)

        # Read response
        length_bytes = _recv_exact(sock, 4)
        length = struct.unpack(">I", length_bytes)[0]
        data = _recv_exact(sock, length)
        return json.loads(data.decode("utf-8"))
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
    """Create a new account on the chain."""
    print("=== Create Account ===\n")

    private_key = collect_private_key()

    # Derive entity locally — private key material stays on this device.
    entity = Entity.create(private_key)
    print(f"\nYour entity ID: {entity.entity_id_hex}")

    # Send ONLY the public entity_id and public_key to the server.
    # Private key never leaves the client.
    print(f"Registering with server at {args.host}:{args.rpc_port}...")
    response = rpc_call(args.host, args.rpc_port, "register_entity", {
        "entity_id": entity.entity_id_hex,
        "public_key": entity.public_key.hex(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nAccount created!")
        print(f"  Entity ID:       {result['entity_id']}")
        print(f"  Public key:      {result['public_key'][:32]}...")
        print(f"  Initial balance: {result['initial_balance']} tokens")
        print(f"\nSave your entity ID — this is your wallet address.")
        print("Your private key is your sole credential. Never share it.")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_send_message(args):
    """Send a message to the chain."""
    print("=== Send Message ===\n")

    # Get message
    message = args.message
    if not message:
        print("Enter your message (280 characters max):")
        message = input("> ").strip()
    if not message:
        print("Error: Message cannot be empty.")
        sys.exit(1)

    char_count = len(message)
    if char_count > 280:
        print(f"Error: Message is {char_count} characters (max 280).")
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

    # Advance keypair past already-used one-time keys to prevent WOTS+ reuse.
    # The nonce equals the number of signatures already made, so we skip that many leaves.
    # +1 accounts for the genesis block signature if this entity proposed it.
    entity.keypair.advance_to_leaf(nonce)

    # Get fee estimate
    fee = args.fee
    if not fee:
        est_resp = rpc_call(args.host, args.rpc_port, "get_fee_estimate", {})
        suggested = est_resp["result"]["fee_estimate"] if est_resp.get("ok") else 5
        print(f"Suggested fee: {suggested} tokens (higher = faster inclusion)")
        fee_input = input(f"Fee [{suggested}]: ").strip()
        fee = int(fee_input) if fee_input else suggested

    # Create and sign transaction locally
    tx = create_transaction(entity, message, fee=fee, nonce=nonce)

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


def main():
    parser = argparse.ArgumentParser(
        description="MessageChain Client",
        usage="client.py {create-account,send-message} [options]",
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

    args = parser.parse_args()

    if args.command == "create-account":
        cmd_create_account(args)
    elif args.command == "send-message":
        cmd_send_message(args)


if __name__ == "__main__":
    main()
