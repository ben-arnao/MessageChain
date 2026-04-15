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

from messagechain.identity.identity import Entity
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
        # M13: Reject oversized responses to prevent memory exhaustion
        MAX_RESPONSE_LENGTH = 10_000_000  # 10 MB
        if length > MAX_RESPONSE_LENGTH:
            raise ValueError(f"Response too large: {length} bytes (max {MAX_RESPONSE_LENGTH})")
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
    from messagechain.crypto.hash_sig import _hash

    print("=== Create Account ===\n")

    private_key = collect_private_key()

    # Derive entity locally — private key material stays on this device.
    entity = Entity.create(private_key)
    print(f"\nYour entity ID: {entity.entity_id_hex}")

    # Sign registration proof to demonstrate key ownership.
    proof_msg = _hash(b"register" + entity.entity_id)
    proof = entity.keypair.sign(proof_msg)

    # Send public identity + proof to the server.
    # Private key never leaves the client.
    print(f"Registering with server at {args.host}:{args.rpc_port}...")
    response = rpc_call(args.host, args.rpc_port, "register_entity", {
        "entity_id": entity.entity_id_hex,
        "public_key": entity.public_key.hex(),
        "registration_proof": proof.serialize(),
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

    from messagechain.config import MIN_FEE
    fee = args.fee if args.fee else MIN_FEE
    if fee < MIN_FEE:
        print(f"Error: fee {fee} is below MIN_FEE {MIN_FEE}.")
        sys.exit(1)
    recipient_id = bytes.fromhex(args.to)
    tx = create_transfer_transaction(entity, recipient_id, args.amount, nonce=nonce, fee=fee)

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
