"""
Unified CLI for MessageChain.

    messagechain start              # Run a node (relay-only)
    messagechain start --mine       # Run a node and produce blocks
    messagechain account            # Create an account
    messagechain send "Hello!"      # Send a message
    messagechain demo               # Run local demo
    messagechain info               # Show chain info
"""

import argparse
import asyncio
import getpass
import logging
import os
import sys

from messagechain.config import DEFAULT_PORT


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="messagechain",
        description="MessageChain — decentralized, quantum-resistant messaging",
        usage="messagechain <command> [options]",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Verbose logging"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- start ---
    start = sub.add_parser(
        "start",
        help="Start a node",
        description="Start a MessageChain node. Relay-only by default.",
    )
    start.add_argument(
        "--mine", action="store_true",
        help="Produce blocks and earn rewards (requires private key)",
    )
    start.add_argument("--port", type=int, default=9333, help="P2P port (default: 9333)")
    start.add_argument("--rpc-port", type=int, default=9334, help="RPC port (default: 9334)")
    start.add_argument("--seed", nargs="*", help="Seed nodes (host:port)")
    start.add_argument("--data-dir", type=str, default=None, help="Chain data directory")

    # --- account ---
    account = sub.add_parser(
        "account",
        help="Create an account",
        description="Create a new account. Use --public-key and --proof for cold storage registration.",
    )
    account.add_argument(
        "--public-key", type=str, default=None,
        help="Register using a public key (hex) instead of entering a private key.",
    )
    account.add_argument(
        "--proof", type=str, default=None,
        help="Registration proof file (from sign-registration). Required with --public-key.",
    )
    account.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )

    # --- send ---
    send = sub.add_parser(
        "send",
        help="Send a message",
        description="Send a message to the chain (280 chars max).",
    )
    send.add_argument("message", type=str, help="Message text (280 chars max)")
    send.add_argument(
        "--fee", type=int, default=None,
        help="Transaction fee (auto-detected if omitted)",
    )
    send.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )

    # --- transfer ---
    transfer = sub.add_parser(
        "transfer",
        help="Send tokens to another entity",
        description="Transfer tokens to another registered entity.",
    )
    transfer.add_argument("--to", required=True, help="Recipient entity ID (hex)")
    transfer.add_argument("--amount", type=int, required=True, help="Amount to transfer")
    transfer.add_argument("--fee", type=int, default=None, help="Transaction fee (auto-detected if omitted)")
    transfer.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- balance ---
    balance = sub.add_parser(
        "balance",
        help="Check your balance",
        description="Show your account balance, staked amount, and nonce.",
    )
    balance.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- stake ---
    stake = sub.add_parser(
        "stake",
        help="Stake tokens to become a validator",
        description="Lock tokens for validator staking (minimum 100).",
    )
    stake.add_argument("--amount", type=int, required=True, help="Amount to stake")
    stake.add_argument("--fee", type=int, default=None, help="Transaction fee")
    stake.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- unstake ---
    unstake = sub.add_parser(
        "unstake",
        help="Unstake tokens",
        description="Unlock staked tokens (7-day unbonding period).",
    )
    unstake.add_argument("--amount", type=int, required=True, help="Amount to unstake")
    unstake.add_argument("--fee", type=int, default=None, help="Transaction fee")
    unstake.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- delegate ---
    delegate = sub.add_parser(
        "delegate",
        help="Delegate trust to validators",
        description="Delegate voting power to up to 3 validators you trust.",
    )
    delegate.add_argument(
        "--to", action="append", dest="delegates",
        help="Validator entity ID (hex). Can specify up to 3.",
    )
    delegate.add_argument(
        "--pct", action="append", dest="pcts", type=int,
        help="Percentage for each --to (must sum to 100).",
    )
    delegate.add_argument(
        "--revoke", action="store_true",
        help="Revoke all delegations.",
    )
    delegate.add_argument("--fee", type=int, default=None, help="Transaction fee")
    delegate.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- propose ---
    propose = sub.add_parser(
        "propose",
        help="Propose a governance vote",
        description="Create a governance proposal for validators to vote on.",
    )
    propose.add_argument("--title", required=True, help="Short title for the proposal")
    propose.add_argument("--description", required=True, help="Detailed description")
    propose.add_argument("--fee", type=int, default=None, help="Transaction fee (default: 1000)")
    propose.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- vote ---
    vote = sub.add_parser(
        "vote",
        help="Vote on a governance proposal",
        description="Cast a yes/no vote on an active proposal.",
    )
    vote.add_argument("--proposal", required=True, help="Proposal ID (hex)")
    vote_group = vote.add_mutually_exclusive_group(required=True)
    vote_group.add_argument("--yes", action="store_true", help="Vote yes")
    vote_group.add_argument("--no", action="store_true", help="Vote no")
    vote.add_argument("--fee", type=int, default=None, help="Transaction fee (default: 100)")
    vote.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- generate-key ---
    sub.add_parser(
        "generate-key",
        help="Generate a new key pair (offline)",
        description="Generate a key pair offline. Shows private key, public key, and entity ID.",
    )

    # --- verify-key ---
    sub.add_parser(
        "verify-key",
        help="Verify a private key backup (offline)",
        description="Re-derive public key and entity ID from a private key to verify your backup.",
    )

    # --- sign-registration ---
    sub.add_parser(
        "sign-registration",
        help="Sign a registration proof (offline)",
        description="Sign a registration proof offline. Output can be used to register without the private key.",
    )

    # --- read ---
    read = sub.add_parser(
        "read",
        help="Read recent messages",
        description="Read recent messages from the chain.",
    )
    read.add_argument("--last", type=int, default=10, help="Number of messages (default: 10)")
    read.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- demo ---
    sub.add_parser(
        "demo",
        help="Run a local demo",
        description="Run a full local demo of the protocol.",
    )

    # --- info ---
    info = sub.add_parser(
        "info",
        help="Show chain info",
        description="Query a running node for chain info.",
    )
    info.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )

    return parser


def resolve_defaults(args: argparse.Namespace) -> argparse.Namespace:
    """Fill in sensible defaults so users don't have to think about config."""
    cmd = args.command

    # Server address defaults
    if hasattr(args, "server") and args.server is None:
        args.server = "127.0.0.1:9334"

    # Data dir defaults for node
    if cmd == "start" and args.data_dir is None:
        args.data_dir = os.path.join(os.path.expanduser("~"), ".messagechain", "chaindata")

    return args


def _parse_server(server_str: str) -> tuple[str, int]:
    """Parse 'host:port' into (host, port)."""
    if ":" in server_str:
        host, port = server_str.rsplit(":", 1)
        return host, int(port)
    return server_str, 9334


def _collect_private_key():
    """Collect private key from the user."""
    print("Authenticate with your private key.")
    print("Your private key is your identity — guard it carefully.\n")

    private_key = getpass.getpass("Private key (hidden): ").encode("utf-8")

    if not private_key:
        print("Error: Private key is required.")
        sys.exit(1)

    return private_key


def cmd_start(args):
    """Start a MessageChain node."""
    from messagechain.identity.identity import Entity

    # Ensure data directory exists
    os.makedirs(args.data_dir, exist_ok=True)

    seed_nodes = []
    if args.seed:
        for s in args.seed:
            host, port = s.split(":")
            seed_nodes.append((host, int(port)))

    # Import server here to avoid circular imports and keep startup fast
    from server import Server

    server = Server(
        p2p_port=args.port,
        rpc_port=args.rpc_port,
        seed_nodes=seed_nodes,
        data_dir=args.data_dir,
    )

    entity = None
    if args.mine:
        print("=== Start Mining Node ===\n")
        print("To produce blocks and earn rewards, authenticate with your private key.\n")
        private_key = _collect_private_key()
        entity = Entity.create(private_key)

        # Advance keypair past used leaves
        leaves_used = server.blockchain.get_wots_leaves_used(entity.entity_id)
        if leaves_used > 0:
            entity.keypair.advance_to_leaf(leaves_used)

        server.set_wallet_entity(entity)
        print(f"\nMining as: {entity.entity_id_hex[:16]}...")
    else:
        print("=== Start Relay Node ===\n")
        print("Running as relay-only (no block production).")
        print("To earn rewards, restart with: messagechain start --mine\n")

    async def _run():
        await server.start()
        port_info = f"P2P: {args.port} | RPC: {args.rpc_port}"
        print(f"Node running. {port_info}")
        print(f"Data: {args.data_dir}")
        print("Press Ctrl+C to stop.\n")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            await server.stop()

    asyncio.run(_run())


def cmd_account(args):
    """Create a new account.

    Two modes:
    1. Default: enter private key, sign proof, register.
    2. Cold storage: --proof <file> from sign-registration (no private key needed).
    """
    import json
    from messagechain.identity.identity import Entity, derive_entity_id
    from messagechain.crypto.hash_sig import _hash
    from messagechain.crypto.keys import Signature

    print("=== Create Account ===\n")

    if args.proof:
        # Cold storage mode: load registration proof from file
        try:
            with open(args.proof, "r") as f:
                reg_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error reading proof file: {e}")
            sys.exit(1)

        entity_id_hex = reg_data["entity_id"]
        public_key_hex = reg_data["public_key"]
        proof_data = reg_data["registration_proof"]

        # Validate entity_id matches public_key
        public_key = bytes.fromhex(public_key_hex)
        expected_eid = derive_entity_id(public_key)
        if expected_eid.hex() != entity_id_hex:
            print("Error: Entity ID does not match public key. File may be corrupt.")
            sys.exit(1)

        print(f"  Entity ID: {entity_id_hex}")
        print(f"  (from proof file: {args.proof})")

    elif args.public_key:
        print("Error: --public-key requires --proof. Use sign-registration to create a proof file.")
        sys.exit(1)

    else:
        # Standard mode: enter private key, sign proof on the spot
        private_key = _collect_private_key()
        entity = Entity.create(private_key)

        proof_msg = _hash(b"register" + entity.entity_id)
        proof = entity.keypair.sign(proof_msg)

        entity_id_hex = entity.entity_id_hex
        public_key_hex = entity.public_key.hex()
        proof_data = proof.serialize()

    print(f"\nYour entity ID: {entity_id_hex}")

    host, port = _parse_server(args.server)
    print(f"Registering with server at {host}:{port}...")

    from client import rpc_call
    response = rpc_call(host, port, "register_entity", {
        "entity_id": entity_id_hex,
        "public_key": public_key_hex,
        "registration_proof": proof_data,
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nAccount created!")
        print(f"  Entity ID: {result['entity_id']}")
        print(f"  Balance:   {result['initial_balance']} tokens")
        print(f"\nSave your entity ID — this is your wallet address.")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_send(args):
    """Send a message to the chain."""
    from messagechain.identity.identity import Entity

    message = args.message
    char_count = len(message)
    if char_count > 280:
        print(f"Error: Message is {char_count} characters (max 280).")
        sys.exit(1)
    if not message.strip():
        print("Error: Message cannot be empty.")
        sys.exit(1)

    print(f"=== Send Message ({char_count} chars) ===\n")

    # Authenticate
    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nSigning as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)

    from client import rpc_call
    from messagechain.core.transaction import create_transaction

    # Get nonce
    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]

    # Advance keypair past used leaves
    entity.keypair.advance_to_leaf(nonce)

    # Auto-detect fee (or use explicit)
    fee = args.fee
    if fee is None:
        est_resp = rpc_call(host, port, "get_fee_estimate", {})
        fee = est_resp["result"]["fee_estimate"] if est_resp.get("ok") else 5
        print(f"Fee: {fee} tokens (auto)")
    else:
        print(f"Fee: {fee} tokens")

    # Create, sign, submit
    tx = create_transaction(entity, message, fee=fee, nonce=nonce)
    print("Submitting...")

    response = rpc_call(host, port, "submit_transaction", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nMessage sent!")
        print(f"  TX hash: {result['tx_hash']}")
        print(f"  Fee:     {result['fee']} tokens")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_transfer(args):
    """Transfer tokens to another entity."""
    from messagechain.identity.identity import Entity
    from messagechain.core.transfer import create_transfer_transaction

    print("=== Transfer Tokens ===\n")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nSending as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)

    from client import rpc_call

    # Get nonce
    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]

    entity.keypair.advance_to_leaf(nonce)

    # Auto-detect fee
    fee = args.fee
    if fee is None:
        est_resp = rpc_call(host, port, "get_fee_estimate", {})
        fee = est_resp["result"]["fee_estimate"] if est_resp.get("ok") else 1

    from messagechain.validation import parse_hex
    recipient_id = parse_hex(args.to)
    if recipient_id is None:
        print(f"Error: Invalid recipient ID (not valid hex): {args.to}")
        sys.exit(1)
    tx = create_transfer_transaction(entity, recipient_id, args.amount, nonce=nonce, fee=fee)

    print(f"Transferring {args.amount} tokens to {args.to[:16]}... (fee: {fee})")

    response = rpc_call(host, port, "submit_transfer", {
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
    from messagechain.identity.identity import Entity

    print("=== Account Balance ===\n")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)

    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "get_entity", {
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
    from messagechain.identity.identity import Entity
    from messagechain.core.staking import create_stake_transaction

    print("=== Stake Tokens ===\n")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nStaking as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)

    from client import rpc_call

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]

    entity.keypair.advance_to_leaf(nonce)

    fee = args.fee if args.fee is not None else 1
    tx = create_stake_transaction(entity, args.amount, nonce=nonce, fee=fee)

    print(f"Staking {args.amount} tokens (fee: {fee})...")

    response = rpc_call(host, port, "stake", {
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
    from messagechain.identity.identity import Entity
    from messagechain.core.staking import create_unstake_transaction

    print("=== Unstake Tokens ===\n")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nUnstaking as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)

    from client import rpc_call

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]

    entity.keypair.advance_to_leaf(nonce)

    fee = args.fee if args.fee is not None else 1
    tx = create_unstake_transaction(entity, args.amount, nonce=nonce, fee=fee)

    print(f"Unstaking {args.amount} tokens (fee: {fee})...")

    response = rpc_call(host, port, "unstake", {
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


def cmd_delegate(args):
    """Delegate voting power to trusted validators."""
    from messagechain.identity.identity import Entity
    from messagechain.governance.governance import create_delegation
    from messagechain.config import GOVERNANCE_DELEGATE_FEE

    if args.revoke:
        print("=== Revoke Delegation ===\n")
        targets = []
    else:
        print("=== Delegate Trust ===\n")
        if not args.delegates:
            print("Error: Specify at least one --to <validator_id>")
            sys.exit(1)
        if not args.pcts or len(args.pcts) != len(args.delegates):
            print("Error: Each --to must have a matching --pct")
            sys.exit(1)
        if sum(args.pcts) != 100:
            print(f"Error: Percentages must sum to 100 (got {sum(args.pcts)})")
            sys.exit(1)

        from messagechain.validation import parse_hex
        targets = []
        for delegate_hex, pct in zip(args.delegates, args.pcts):
            did = parse_hex(delegate_hex)
            if did is None:
                print(f"Error: Invalid hex: {delegate_hex}")
                sys.exit(1)
            targets.append((did, pct))

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nDelegating as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)
    from client import rpc_call

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    entity.keypair.advance_to_leaf(nonce)

    fee = args.fee if args.fee is not None else GOVERNANCE_DELEGATE_FEE
    tx = create_delegation(entity, targets, fee=fee)

    response = rpc_call(host, port, "submit_delegation", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        if args.revoke:
            print("\nDelegation revoked!")
        else:
            for delegate_hex, pct in zip(args.delegates, args.pcts):
                print(f"  {delegate_hex[:16]}... — {pct}%")
            print("\nDelegation submitted!")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_propose(args):
    """Create a governance proposal."""
    from messagechain.identity.identity import Entity
    from messagechain.governance.governance import create_proposal
    from messagechain.config import GOVERNANCE_PROPOSAL_FEE

    print("=== Create Proposal ===\n")
    print(f"  Title: {args.title}")
    print(f"  Description: {args.description}")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nProposing as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)
    from client import rpc_call

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    entity.keypair.advance_to_leaf(nonce)

    fee = args.fee if args.fee is not None else GOVERNANCE_PROPOSAL_FEE
    tx = create_proposal(entity, args.title, args.description, fee=fee)

    response = rpc_call(host, port, "submit_proposal", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nProposal created!")
        print(f"  Proposal ID: {result['proposal_id']}")
        print(f"  Fee:         {result['fee']} tokens")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_vote(args):
    """Cast a vote on a governance proposal."""
    from messagechain.identity.identity import Entity
    from messagechain.governance.governance import create_vote
    from messagechain.config import GOVERNANCE_VOTE_FEE

    approve = args.yes
    print(f"=== Cast Vote ({'YES' if approve else 'NO'}) ===\n")
    print(f"  Proposal: {args.proposal[:16]}...")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nVoting as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)
    from client import rpc_call

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    entity.keypair.advance_to_leaf(nonce)

    from messagechain.validation import parse_hex
    proposal_id = parse_hex(args.proposal)
    if proposal_id is None:
        print(f"Error: Invalid proposal ID (not valid hex): {args.proposal}")
        sys.exit(1)

    fee = args.fee if args.fee is not None else GOVERNANCE_VOTE_FEE
    tx = create_vote(entity, proposal_id, approve, fee=fee)

    response = rpc_call(host, port, "submit_vote", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print(f"\nVote submitted!")
        print(f"  Vote:    {'YES' if approve else 'NO'}")
        print(f"  TX hash: {result['tx_hash']}")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_generate_key(_args):
    """Generate a full key pair offline (private key, public key, entity ID)."""
    import os
    from messagechain.identity.identity import Entity

    key = os.urandom(32)
    entity = Entity.create(key)

    print("=== Key Pair Generated ===\n")
    print(f"  Private key: {key.hex()}")
    print(f"  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"\n  IMPORTANT: Verify your backup before deleting this key.")
    print("  Run: messagechain verify-key")
    print(f"\n  WARNING: Save your private key securely. It is your sole credential.")
    print("  Anyone with this key controls your account. There is no recovery.")
    print("  This key will NOT be shown again.")


def cmd_verify_key(_args):
    """Re-derive public key and entity ID from a private key (offline)."""
    from messagechain.identity.identity import Entity

    print("=== Verify Key Backup ===\n")
    print("Enter your private key to verify it derives the expected identity.\n")

    private_key_hex = getpass.getpass("Private key (hidden): ")
    try:
        private_key = bytes.fromhex(private_key_hex)
    except ValueError:
        print("Error: Invalid hex. Private key must be a hex string.")
        sys.exit(1)

    try:
        entity = Entity.create(private_key)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"\n  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"\n  Confirm these match your records.")


def cmd_sign_registration(_args):
    """Sign a registration proof offline for later submission."""
    import json
    from messagechain.identity.identity import Entity
    from messagechain.crypto.hash_sig import _hash

    print("=== Sign Registration Proof (Offline) ===\n")
    print("This creates a signed proof that you own the key pair.")
    print("You can use the output file to register without your private key.\n")

    private_key_hex = getpass.getpass("Private key (hidden): ")
    try:
        private_key = bytes.fromhex(private_key_hex)
    except ValueError:
        print("Error: Invalid hex. Private key must be a hex string.")
        sys.exit(1)

    try:
        entity = Entity.create(private_key)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    proof_msg = _hash(b"register" + entity.entity_id)
    proof = entity.keypair.sign(proof_msg)

    registration_data = {
        "entity_id": entity.entity_id_hex,
        "public_key": entity.public_key.hex(),
        "registration_proof": proof.serialize(),
    }

    filename = f"registration_{entity.entity_id_hex[:16]}.json"
    with open(filename, "w") as f:
        json.dump(registration_data, f, indent=2)

    print(f"\n  Entity ID:  {entity.entity_id_hex}")
    print(f"  Public key: {entity.public_key.hex()}")
    print(f"  Proof file: {filename}")
    print(f"\n  Transfer this file to your online machine, then run:")
    print(f"  messagechain account --proof {filename}")


def cmd_read(args):
    """Read recent messages from the chain."""
    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "get_messages", {"count": args.last})

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


def cmd_demo(_args):
    """Run local demo."""
    from run_node import run_demo
    run_demo()


def cmd_info(args):
    """Show chain info from a running node."""
    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "get_chain_info", {})

    if response.get("ok"):
        info = response["result"]
        print("=== Chain Info ===\n")
        for key, value in info.items():
            label = key.replace("_", " ").title()
            print(f"  {label}: {value}")
    else:
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)


def main():
    parser = build_parser()
    args = parser.parse_args()
    args = resolve_defaults(args)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    commands = {
        "start": cmd_start,
        "account": cmd_account,
        "send": cmd_send,
        "transfer": cmd_transfer,
        "balance": cmd_balance,
        "stake": cmd_stake,
        "unstake": cmd_unstake,
        "delegate": cmd_delegate,
        "propose": cmd_propose,
        "vote": cmd_vote,
        "generate-key": cmd_generate_key,
        "verify-key": cmd_verify_key,
        "sign-registration": cmd_sign_registration,
        "read": cmd_read,
        "demo": cmd_demo,
        "info": cmd_info,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
