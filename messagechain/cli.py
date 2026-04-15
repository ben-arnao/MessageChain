"""
Unified CLI for MessageChain.

    messagechain start              # Run a node (relay-only)
    messagechain start --mine       # Run a node and produce blocks
    messagechain account            # Create an account
    messagechain send "Hello!"      # Send a message
    messagechain info               # Show chain info
"""

import argparse
import asyncio
import getpass
import logging
import os
import stat
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
    start.add_argument(
        "--keyfile", type=str, default=None,
        help="Path to file containing the checksummed private key. "
             "Enables unattended restart (e.g. from systemd). "
             "Ensure file permissions are 0600.",
    )
    start.add_argument("--port", type=int, default=9333, help="P2P port (default: 9333)")
    start.add_argument("--rpc-port", type=int, default=9334, help="RPC port (default: 9334)")
    start.add_argument("--seed", nargs="*", help="Seed nodes (host:port)")
    start.add_argument("--data-dir", type=str, default=None, help="Chain data directory")

    # --- account ---
    account = sub.add_parser(
        "account",
        help="Create an account",
        description="Create a new account using your private key.",
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

    # --- bootstrap-seed ---
    bootstrap = sub.add_parser(
        "bootstrap-seed",
        help="One-shot: register + set cold authority + stake a seed validator",
        description=(
            "Perform the full seed-validator bootstrap sequence on a running node:\n"
            "  1. register-entity (hot key proves ownership)\n"
            "  2. set-authority-key (promote the cold wallet pubkey)\n"
            "  3. stake (lock the validator stake)\n"
            "\n"
            "Submits each tx to the local server and prints a summary.  Run this "
            "once per seed during initial network bootstrap.  Confirm with "
            "`messagechain info <entity_id>` after the next block lands."
        ),
    )
    bootstrap.add_argument(
        "--authority-pubkey", required=True,
        help="Cold wallet public key (hex). Generate offline with `generate-key`.",
    )
    bootstrap.add_argument(
        "--stake-amount", type=int, required=True,
        help="Amount to stake (tokens). Your recommended seed stake.",
    )
    bootstrap.add_argument(
        "--fee", type=int, default=None,
        help="Per-tx fee (default: MIN_FEE for each step).",
    )
    bootstrap.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: localhost)",
    )

    # --- set-authority-key ---
    set_auth = sub.add_parser(
        "set-authority-key",
        help="Promote a cold key for withdrawal/revoke operations",
        description=(
            "Designate a separately-generated public key as the cold 'authority' "
            "key for this entity. After this runs, unstake (and emergency revoke) "
            "must be signed by the authority key rather than the hot signing key. "
            "Use this to separate validator block-production keys (hot, on the "
            "server) from withdrawal keys (cold, offline)."
        ),
    )
    set_auth.add_argument(
        "--authority-pubkey", required=True,
        help="New authority public key (hex). Generate offline.",
    )
    set_auth.add_argument("--fee", type=int, default=None, help="Transaction fee")
    set_auth.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- rotate-key ---
    rotate = sub.add_parser(
        "rotate-key",
        help="Rotate to a fresh Merkle tree (leaf exhaustion recovery)",
        description=(
            "Move this entity to a freshly-derived Merkle tree of one-time "
            "keys. Your entity ID (wallet address), balance, stake, delegations, "
            "and authority-key binding all carry over unchanged — only the "
            "underlying signing public key is replaced. Use when your leaf "
            "watermark approaches the tree capacity, typically at ~80% usage."
        ),
    )
    rotate.add_argument("--fee", type=int, default=None, help="Rotation fee")
    rotate.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- key-status ---
    key_status = sub.add_parser(
        "key-status",
        help="Show current key state, leaf usage, and rotation number",
    )
    key_status.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- emergency-revoke ---
    revoke = sub.add_parser(
        "emergency-revoke",
        help="Kill-switch for a compromised validator (cold key required)",
        description=(
            "Immediately disable a validator whose hot signing key is "
            "suspected compromised. Signed by the cold authority key (NOT "
            "the hot signing key). After this runs: the validator can no "
            "longer propose blocks or attest, and all active stake enters "
            "the normal 7-day unbonding queue so the legitimate operator "
            "recovers the funds. Keep a pre-signed revoke tx on paper for "
            "rapid response."
        ),
    )
    revoke.add_argument(
        "--entity-id", required=True,
        help="Hex entity ID of the compromised validator",
    )
    revoke.add_argument("--fee", type=int, default=None, help="Transaction fee")
    revoke.add_argument("--server", type=str, default=None, help="Server address host:port")

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

    # --- read ---
    read = sub.add_parser(
        "read",
        help="Read recent messages",
        description="Read recent messages from the chain.",
    )
    read.add_argument("--last", type=int, default=10, help="Number of messages (default: 10)")
    read.add_argument("--server", type=str, default=None, help="Server address host:port")

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

    # --- proposals ---
    proposals = sub.add_parser(
        "proposals",
        help="List governance proposals",
        description="Show open proposals with current tally and blocks remaining.",
    )
    proposals.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- validators ---
    validators = sub.add_parser(
        "validators",
        help="List the current validator set",
        description="Show staked validators with stake share, blocks produced, and entity ID.",
    )
    validators.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- estimate-fee ---
    estimate_fee = sub.add_parser(
        "estimate-fee",
        help="Estimate the fee for a prospective message or transfer",
        description="Query the node for the recommended fee without submitting.",
    )
    fee_mode = estimate_fee.add_mutually_exclusive_group(required=True)
    fee_mode.add_argument("--message", type=str, help="Message text to price")
    fee_mode.add_argument("--transfer", action="store_true", help="Price a funds transfer")
    estimate_fee.add_argument("--server", type=str, default=None, help="Server address host:port")

    return parser


def resolve_defaults(args: argparse.Namespace) -> argparse.Namespace:
    """Fill in sensible defaults so users don't have to think about config."""
    cmd = args.command

    # Server address: explicit override wins.  Otherwise leave None so
    # _parse_server can run the seed-pick + sqrt(stake) routing.
    # Data dir defaults for node
    if cmd == "start" and args.data_dir is None:
        args.data_dir = os.path.join(os.path.expanduser("~"), ".messagechain", "chaindata")

    return args


def _parse_server(server_str):
    """Resolve a --server value to a (host, port) tuple.

    When the user passes --server host:port, parse and return it.  When
    --server is unset (None), run the auto-discovery path:

    1. Try `CLIENT_SEED_ENDPOINTS` in random order, pick the first that
       accepts a TCP connection.  The seeds are the only hardcoded
       entry points the CLI knows about.
    2. Once connected to a seed, ask for `get_network_validators`.
       If any *non-seed* validator reports a reachable RPC endpoint,
       pick one weighted by sqrt(stake) and route the actual command
       there.  This is the "graceful post-bootstrap switch": while
       the network is just the seeds, clients stick to them; once
       outside validators come online and are reachable, load spreads
       across the network.
    3. If no non-seed validators have endpoints yet, stay on the seed.
    4. Final fallback: localhost:9333 (useful for dev).

    Users always retain manual override via `--server`.
    """
    if server_str is not None and server_str != "":
        if ":" in server_str:
            host, port = server_str.rsplit(":", 1)
            return host, int(port)
        from messagechain.config import DEFAULT_PORT
        return server_str, DEFAULT_PORT

    endpoint = _auto_pick_endpoint()
    if endpoint is not None:
        return endpoint
    # Last-resort dev fallback so a local unconfigured node still works.
    return "127.0.0.1", 9333


def _try_tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Quick liveness probe — returns True if we can open a socket."""
    import socket as _socket
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def _auto_pick_endpoint():
    """Discover a reachable RPC endpoint following the two-stage model.

    Returns (host, port) or None if nothing responds.  Keeps logic here
    (not in every command handler) so all CLI commands share the same
    routing behavior.
    """
    import random
    from messagechain.config import CLIENT_SEED_ENDPOINTS

    # Stage 1: find a reachable seed.
    reachable_seed = None
    candidates = list(CLIENT_SEED_ENDPOINTS)
    random.shuffle(candidates)
    for host, port in candidates:
        if _try_tcp_open(host, port):
            reachable_seed = (host, port)
            break

    if reachable_seed is None:
        return None

    # Stage 2: ask the seed for the wider validator set.  If any
    # non-seed validator has a reachable endpoint, pick one weighted
    # by sqrt(stake) so load spreads without letting mega-validators
    # monopolize client traffic.
    try:
        import json
        import socket as _socket
        import struct as _struct
        seed_hostport = set(CLIENT_SEED_ENDPOINTS)
        req = json.dumps({
            "method": "get_network_validators", "params": {},
        }).encode("utf-8")
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect(reachable_seed)
            s.sendall(_struct.pack(">I", len(req)))
            s.sendall(req)
            length = _struct.unpack(">I", _recv_n(s, 4))[0]
            resp = json.loads(_recv_n(s, length).decode("utf-8"))
        finally:
            s.close()
        if not resp.get("ok"):
            return reachable_seed
        validators = resp["result"].get("validators", []) or []
        non_seed = []
        for v in validators:
            host, port = v.get("rpc_host"), v.get("rpc_port")
            if host is None or port is None:
                continue
            if (host, port) in seed_hostport:
                continue
            stake = v.get("stake", 0)
            if stake <= 0:
                continue
            non_seed.append((host, port, stake))
        if not non_seed:
            return reachable_seed

        import math
        weights = [math.isqrt(max(s, 1)) for _, _, s in non_seed]
        total_w = sum(weights)
        if total_w == 0:
            return reachable_seed
        pick = random.randint(1, total_w)
        cumulative = 0
        for (host, port, _), w in zip(non_seed, weights):
            cumulative += w
            if pick <= cumulative:
                return (host, port)
        return (non_seed[-1][0], non_seed[-1][1])
    except Exception:
        # Any discovery failure -> fall back to the reachable seed.  A
        # broken discovery path must never brick the CLI.
        return reachable_seed


def _recv_n(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def _make_progress_reporter(total_leaves: int, label: str = "Generating key"):
    """Build a progress callback for KeyPair generation.

    At production tree height (20 = 1M leaves), keygen takes a long time.
    Without feedback, users kill the process thinking it hung. This
    callback prints a single-line progress percentage to stderr roughly
    every 5% so the output is readable but not spammy. Returns None if
    the tree is small enough that progress is unnecessary.
    """
    # Skip for small trees (tests, small configs) — the overhead of
    # printing exceeds the wait time.
    if total_leaves < 4096:
        return None

    # Throttle to ~20 updates total
    step = max(1, total_leaves // 20)
    state = {"next": step, "done": 0}

    def report(_leaf_index: int):
        state["done"] += 1
        done = state["done"]
        if done >= state["next"] or done == total_leaves:
            pct = int(100 * done / total_leaves)
            print(
                f"\r{label}: {pct}% ({done:,}/{total_leaves:,} leaves)",
                end="",
                file=sys.stderr,
                flush=True,
            )
            state["next"] += step
            if done == total_leaves:
                print("", file=sys.stderr)  # newline after final update

    return report


class KeyFileError(Exception):
    """Raised when a --keyfile cannot be loaded (missing, empty, bad checksum)."""


def _load_key_from_file(path: str) -> bytes:
    """Load and verify a checksummed private key from a file.

    Returns the raw 32-byte private key. Raises KeyFileError on any
    problem so that validators fail loudly at startup rather than silently
    running as the wrong identity.

    On POSIX systems, warns if the file is group/world-readable. We do
    NOT refuse to load — operators may have valid reasons (e.g. container
    secrets) for wider perms — but we surface the risk.
    """
    from messagechain.identity.key_encoding import (
        decode_private_key,
        InvalidKeyChecksumError,
        InvalidKeyFormatError,
    )

    try:
        with open(path, "r") as f:
            contents = f.read()
    except FileNotFoundError:
        raise KeyFileError(f"Key file not found: {path}")
    except OSError as e:
        raise KeyFileError(f"Cannot read key file {path}: {e}")

    if not contents.strip():
        raise KeyFileError(f"Key file is empty: {path}")

    try:
        key = decode_private_key(contents)
    except InvalidKeyChecksumError:
        raise KeyFileError(
            f"Key file checksum failed: {path}. "
            "The file may be corrupted or truncated."
        )
    except InvalidKeyFormatError as e:
        raise KeyFileError(f"Key file has invalid format: {path}: {e}")

    # Warn about permissive permissions (POSIX only — Windows stat is different).
    if hasattr(os, "getuid"):
        try:
            mode = os.stat(path).st_mode
            if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                print(
                    f"WARNING: key file {path} is readable by group/others. "
                    "Recommended: chmod 0600 to restrict access."
                )
        except OSError:
            pass

    return key


def _collect_private_key():
    """Collect a private key from the user.

    Accepts either a 24-word BIP-39 recovery phrase (preferred) or the
    72-char hex-checksummed form. Both formats carry a checksum, so a
    transcription error from a paper backup is detected immediately
    rather than silently deriving a different identity.

    Returns the raw 32-byte private key.
    """
    from messagechain.identity.key_encoding import (
        decode_private_key,
        InvalidKeyChecksumError,
        InvalidKeyFormatError,
    )

    print("Authenticate with your recovery phrase or private key.")
    print("This is your identity — guard it carefully.\n")

    entered = getpass.getpass("Recovery phrase or private key (hidden): ")

    if not entered:
        print("Error: Recovery phrase or private key is required.")
        sys.exit(1)

    try:
        return decode_private_key(entered)
    except InvalidKeyChecksumError:
        print("\nError: Checksum failed.")
        print("This usually means you mistyped a word or character from your backup.")
        print("Double-check each word/character and try again.")
        sys.exit(1)
    except InvalidKeyFormatError as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except InvalidKeyFormatError as e:
        print(f"\nError: {e}")
        sys.exit(1)


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
    else:
        # Fall back to the shipped default seeds from config, so users
        # don't need to know a peer host:port out of band.
        from messagechain.config import SEED_NODES
        seed_nodes = list(SEED_NODES)
        if seed_nodes:
            seed_str = ", ".join(f"{h}:{p}" for h, p in seed_nodes)
            print(f"Using default seed nodes: {seed_str}")
            print("(override with --seed <host>:<port>)\n")

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
        if args.keyfile:
            print(f"Loading validator key from {args.keyfile}\n")
            try:
                private_key = _load_key_from_file(args.keyfile)
            except KeyFileError as e:
                print(f"Error: {e}")
                sys.exit(1)
        else:
            print("To produce blocks and earn rewards, authenticate with your private key.")
            print("(tip: use --keyfile <path> for unattended restart)\n")
            private_key = _collect_private_key()
        from messagechain.config import MERKLE_TREE_HEIGHT
        progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Loading key tree")
        entity = Entity.create(private_key, progress=progress)

        # Advance keypair past used leaves
        leaves_used = server.blockchain.get_wots_leaves_used(entity.entity_id)
        if leaves_used > 0:
            entity.keypair.advance_to_leaf(leaves_used)

        server.set_wallet_entity(entity)
        print(f"\nMining as: {entity.entity_id_hex[:16]}...")

        # Nudge: if this validator has no separate cold authority key,
        # every destructive path (unstake, emergency revoke) is controlled
        # by the hot signing key loaded on this server. Compromise of this
        # box = total loss. Warn once at startup so operators don't default
        # into the less-safe mode without knowing.
        authority_pk = server.blockchain.get_authority_key(entity.entity_id)
        if authority_pk is None or authority_pk == entity.public_key:
            print()
            print("  ⚠  Single-key model: this server holds the only key that")
            print("     controls your stake. Compromise = drained funds and")
            print("     stolen governance voting power until slow recovery.")
            print("     Harden by promoting an offline-generated cold key:")
            print("       messagechain set-authority-key --authority-pubkey <hex>")
            print("     (from a separately-generated keypair, kept offline).")
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
    """Create a new account. Enter private key, sign proof, register."""
    from messagechain.identity.identity import Entity
    from messagechain.crypto.hash_sig import _hash

    print("=== Create Account ===\n")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)

    # Sign registration proof to demonstrate key ownership.
    proof_msg = _hash(b"register" + entity.entity_id)
    proof = entity.keypair.sign(proof_msg)

    print(f"\nYour entity ID: {entity.entity_id_hex}")

    host, port = _parse_server(args.server)
    print(f"Registering with server at {host}:{port}...")

    from client import rpc_call
    response = rpc_call(host, port, "register_entity", {
        "entity_id": entity.entity_id_hex,
        "public_key": entity.public_key.hex(),
        "registration_proof": proof.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        from messagechain.identity.address import encode_address
        print(f"\nAccount created!")
        print(f"  Entity ID:  {result['entity_id']}")
        print(f"  Address:    {encode_address(entity.entity_id)}")
        print(f"  Balance:    {result['initial_balance']} tokens")
        print(f"\nShare the 'Address' form when receiving funds — it has a")
        print("built-in checksum that catches single-character transcription")
        print("errors. The raw 'Entity ID' is still accepted for compatibility.")
        print("Your private key is your sole credential. Never share it.")
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
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

    # Auto-detect fee (or use explicit). The actual minimum for a message
    # scales non-linearly with size (MIN_FEE + per-byte + quadratic), so
    # always take max(local_min, server_suggestion) to avoid silently
    # submitting a tx the chain will reject.
    from messagechain.core.transaction import calculate_min_fee
    msg_bytes = args.message.encode("ascii")
    local_min = calculate_min_fee(msg_bytes)
    fee = args.fee
    if fee is None:
        est_resp = rpc_call(host, port, "get_fee_estimate", {})
        server_suggested = (
            est_resp["result"]["fee_estimate"] if est_resp.get("ok") else 0
        )
        fee = max(local_min, server_suggested)
        note = " (auto — server floor)" if server_suggested >= local_min else " (auto — size floor)"
        print(f"Fee: {fee} tokens{note}")
    else:
        if fee < local_min:
            print(
                f"Error: fee {fee} is below the minimum {local_min} for "
                f"a {len(msg_bytes)}-byte message. Raise the fee or drop --fee."
            )
            sys.exit(1)
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
    from messagechain.config import MIN_FEE
    from messagechain.validation import parse_hex

    print("=== Transfer Tokens ===\n")

    # Validate recipient BEFORE prompting for the private key — a typo
    # is a permanent loss risk, so we want the user to fix it without
    # having re-entered credentials.
    # Accept either the checksummed "mc1..." display form (preferred,
    # catches single-character typos offline) or the raw 64-char hex
    # form (backward-compatible, no typo protection).
    from messagechain.identity.address import (
        decode_address,
        InvalidAddressChecksumError,
        InvalidAddressError,
    )
    try:
        recipient_id = decode_address(args.to)
    except InvalidAddressChecksumError as e:
        print(f"Error: {e}")
        print(f"  Got: {args.to}")
        print("  Re-check each character with the sender before retrying.")
        sys.exit(1)
    except InvalidAddressError as e:
        print(f"Error: invalid recipient address — {e}")
        print(f"  Got: {args.to}")
        sys.exit(1)

    host, port = _parse_server(args.server)
    from client import rpc_call

    # Check the recipient is actually registered on-chain.  Transferring
    # to an unregistered (or mistyped) address would be rejected by the
    # server, but we want a clean error path without having typed the
    # private key yet.
    recipient_info = rpc_call(host, port, "get_entity", {
        "entity_id": recipient_id.hex(),
    })
    if not recipient_info.get("ok"):
        print(f"Error: recipient not registered on this chain.")
        print(f"  Entity ID: {recipient_id.hex()}")
        print(f"  This is usually a typo. Double-check the address with")
        print(f"  the recipient before continuing.")
        sys.exit(1)

    # Confirmation step — last chance before the key is handled. Shows
    # both ends of the address so a single-character typo is visible, plus
    # the checksummed display form.
    from messagechain.identity.address import encode_address
    head = recipient_id.hex()[:8]
    tail = recipient_id.hex()[-8:]
    print(f"About to transfer:")
    print(f"  Amount:    {args.amount} tokens")
    print(f"  Recipient: {head}...{tail}")
    print(f"             (full:       {recipient_id.hex()})")
    print(f"             (checksummed: {encode_address(recipient_id)})")
    confirm = input("\nConfirm send (type 'yes' to proceed): ").strip().lower()
    if confirm != "yes":
        print("Transfer cancelled.")
        sys.exit(0)

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nSending as: {entity.entity_id_hex[:16]}...")

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

    # Fee: never below MIN_FEE. Use max(local_min, server_suggestion).
    fee = args.fee
    if fee is None:
        est_resp = rpc_call(host, port, "get_fee_estimate", {})
        server_suggested = (
            est_resp["result"]["fee_estimate"] if est_resp.get("ok") else 0
        )
        fee = max(MIN_FEE, server_suggested)
    elif fee < MIN_FEE:
        print(f"Error: fee {fee} is below MIN_FEE {MIN_FEE}.")
        sys.exit(1)

    tx = create_transfer_transaction(entity, recipient_id, args.amount, nonce=nonce, fee=fee)

    print(f"Transferring {args.amount} tokens (fee: {fee})...")

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
        from messagechain.identity.address import encode_address
        print(f"  Entity ID:       {info['entity_id']}")
        print(f"  Address:         {encode_address(bytes.fromhex(info['entity_id']))}")
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

    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

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

    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

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


def cmd_bootstrap_seed(args):
    """One-shot bootstrap for a seed validator: register + set-authority + stake.

    Mirrors the sequence tested in tests/test_bootstrap_rehearsal.py, but
    against a live server via RPC.  Prompts for the hot private key ONCE
    and runs all three operations back-to-back.  Each step fails loudly
    on error rather than silently leaving the validator mis-configured.
    """
    from messagechain.identity.identity import Entity
    from messagechain.crypto.hash_sig import _hash
    from messagechain.core.authority_key import create_set_authority_key_transaction
    from messagechain.core.staking import create_stake_transaction

    print("=== Bootstrap Seed Validator ===\n")
    print("This performs the full seed-validator setup in one pass:")
    print("  1. Register entity (hot key)")
    print("  2. Set cold authority key (so unstake/revoke need the cold key)")
    print("  3. Stake the validator amount\n")

    try:
        authority_pubkey = bytes.fromhex(args.authority_pubkey.strip())
    except ValueError:
        print("Error: --authority-pubkey must be valid hex.")
        sys.exit(1)
    if len(authority_pubkey) != 32:
        print(f"Error: authority public key must be 32 bytes, got {len(authority_pubkey)}.")
        sys.exit(1)

    if args.stake_amount <= 0:
        print("Error: --stake-amount must be positive.")
        sys.exit(1)

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nSeed entity: {entity.entity_id_hex}")
    print(f"Cold authority: {authority_pubkey.hex()}")
    print(f"Stake amount: {args.stake_amount}\n")

    host, port = _parse_server(args.server)
    print(f"Server: {host}:{port}\n")

    from client import rpc_call
    fee_default = args.fee if args.fee is not None else 100  # MIN_FEE equivalent

    def _fatal(step: str, err: str):
        print(f"\n[{step}] FAILED: {err}")
        print("Bootstrap aborted.  Chain state may be partially updated — ")
        print("re-run `messagechain bootstrap-seed ...` to resume from where you stopped.")
        sys.exit(1)

    def _fetch_state():
        resp = rpc_call(host, port, "get_entity", {"entity_id": entity.entity_id_hex})
        return resp.get("result") if resp.get("ok") else None

    def _fetch_authority():
        resp = rpc_call(host, port, "get_authority_key", {"entity_id": entity.entity_id_hex})
        if not resp.get("ok"):
            return None
        ak = resp["result"].get("authority_key")
        return bytes.fromhex(ak) if ak else None

    def _refresh_nonce_and_leaf():
        """Re-fetch nonce + leaf watermark and advance the keypair."""
        resp = rpc_call(host, port, "get_nonce", {"entity_id": entity.entity_id_hex})
        if not resp.get("ok"):
            return None, None
        n = resp["result"]["nonce"]
        w = resp["result"].get("leaf_watermark", n)
        entity.keypair.advance_to_leaf(w)
        return n, w

    # ── Step 1: register ────────────────────────────────────────────
    print("[1/3] Registering entity...")
    existing = _fetch_state()
    if existing is not None:
        print("      already registered; skipping")
    else:
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        resp = rpc_call(host, port, "register_entity", {
            "entity_id": entity.entity_id_hex,
            "public_key": entity.public_key.hex(),
            "registration_proof": proof.serialize(),
        })
        if not resp.get("ok"):
            _fatal("1/3 register", resp.get("error", "unknown"))
        print(f"      OK: {resp['result']}")

    # ── Step 2: set authority key (cold) ────────────────────────────
    print("\n[2/3] Setting cold authority key...")
    current_authority = _fetch_authority()
    if current_authority == authority_pubkey:
        print("      already set to cold key; skipping")
    else:
        nonce, _ = _refresh_nonce_and_leaf()
        if nonce is None:
            _fatal("2/3 set-authority", "could not fetch nonce")
        tx = create_set_authority_key_transaction(
            entity, new_authority_key=authority_pubkey, nonce=nonce, fee=fee_default,
        )
        resp = rpc_call(host, port, "set_authority_key", {"transaction": tx.serialize()})
        if not resp.get("ok"):
            _fatal("2/3 set-authority", resp.get("error", "unknown"))
        print(f"      submitted: {resp['result']}")

    # ── Step 3: stake ───────────────────────────────────────────────
    print(f"\n[3/3] Staking {args.stake_amount} tokens...")
    state = _fetch_state()
    staked = state.get("staked", 0) if state else 0
    if staked >= args.stake_amount:
        print(f"      already staked {staked} (>= target); skipping")
    else:
        needed = args.stake_amount - staked
        nonce, _ = _refresh_nonce_and_leaf()
        if nonce is None:
            _fatal("3/3 stake", "could not fetch nonce")
        stake_tx = create_stake_transaction(entity, amount=needed, nonce=nonce, fee=fee_default)
        resp = rpc_call(host, port, "stake", {"transaction": stake_tx.serialize()})
        if not resp.get("ok"):
            _fatal("3/3 stake", resp.get("error", "unknown"))
        print(f"      submitted: {resp['result']}")

    print("\n=== All three steps submitted ===")
    print("Stake and set-authority-key take effect when the next block is produced.")
    print(f"\nVerify with:")
    print(f"  messagechain info --entity-id {entity.entity_id_hex} --server {host}:{port}")
    print("\nThe verification must show:")
    print(f"  staked         >= {args.stake_amount}")
    print(f"  authority_key  == {authority_pubkey.hex()}")
    print("\nIf either is missing after a block or two, investigate before ")
    print("treating this seed as operational.  A silently-wrong bootstrap is ")
    print("the worst-case security failure.")


def cmd_set_authority_key(args):
    """Promote a cold authority key for this entity."""
    from messagechain.identity.identity import Entity
    from messagechain.core.authority_key import create_set_authority_key_transaction

    print("=== Set Authority Key ===\n")
    print("This designates a cold public key that will gate your unstake and")
    print("emergency-revoke operations. Your hot signing key (the one you're")
    print("about to enter) continues to handle block production and attestations.\n")

    try:
        authority_pubkey = bytes.fromhex(args.authority_pubkey.strip())
    except ValueError:
        print("Error: --authority-pubkey must be valid hex.")
        sys.exit(1)
    if len(authority_pubkey) != 32:
        print(f"Error: authority public key must be 32 bytes, got {len(authority_pubkey)}.")
        sys.exit(1)

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nSigning as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)
    from client import rpc_call

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

    fee = args.fee if args.fee is not None else 500
    tx = create_set_authority_key_transaction(
        entity, new_authority_key=authority_pubkey, nonce=nonce, fee=fee,
    )

    response = rpc_call(host, port, "set_authority_key", {
        "transaction": tx.serialize(),
    })
    if response.get("ok"):
        result = response["result"]
        print(f"\nAuthority key set!")
        print(f"  Entity ID:     {result['entity_id']}")
        print(f"  Authority key: {result['authority_key']}")
        print(f"  TX hash:       {result['tx_hash']}")
        print(f"\nFuture unstake and emergency-revoke operations must be signed")
        print("by the authority (cold) key you just designated.")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_rotate_key(args):
    """Rotate to a fresh Merkle tree, preserving entity_id and state."""
    from messagechain.identity.identity import Entity
    from messagechain.core.key_rotation import (
        create_key_rotation, derive_rotated_keypair,
    )
    from messagechain.config import KEY_ROTATION_FEE, MERKLE_TREE_HEIGHT

    print("=== Rotate Key ===\n")
    print("This moves your entity to a freshly-derived Merkle tree.")
    print("Your entity ID, balance, stake, and delegations are preserved.\n")

    private_key = _collect_private_key()
    entity = Entity.create(private_key)
    print(f"\nSigning as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)
    from client import rpc_call

    # Need current rotation_number from chain
    status = rpc_call(host, port, "get_key_status", {
        "entity_id": entity.entity_id_hex,
    })
    if not status.get("ok"):
        print(f"Error: {status.get('error')}")
        sys.exit(1)
    current_rotation = status["result"]["rotation_number"]
    watermark = status["result"]["leaf_watermark"]
    entity.keypair.advance_to_leaf(watermark)

    print(f"Current rotation number: {current_rotation}")
    print(f"Current leaf watermark:  {watermark} / {1 << MERKLE_TREE_HEIGHT}")
    print(f"\nDeriving fresh Merkle tree (rotation {current_rotation})...")
    progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Building new tree")
    new_kp = derive_rotated_keypair(
        entity, rotation_number=current_rotation, progress=progress,
    )

    fee = args.fee if args.fee is not None else KEY_ROTATION_FEE
    rot_tx = create_key_rotation(
        entity, new_kp, rotation_number=current_rotation, fee=fee,
    )

    response = rpc_call(host, port, "rotate_key", {
        "transaction": rot_tx.serialize(),
    })
    if response.get("ok"):
        result = response["result"]
        print(f"\nKey rotated!")
        print(f"  Entity ID:      {result['entity_id']}")
        print(f"  New public key: {result['new_public_key']}")
        print(f"  Rotation #:     {result['rotation_number']}")
        print(f"\nYour entity ID is unchanged — wallet address, stake, and")
        print("delegations all carry over. You can now continue signing with")
        print("the fresh tree. Back up any new derivation metadata if needed.")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_key_status(args):
    """Show the current key tree's rotation and leaf-consumption status."""
    from messagechain.identity.identity import Entity
    from messagechain.config import MERKLE_TREE_HEIGHT

    private_key = _collect_private_key()
    entity = Entity.create(private_key)

    host, port = _parse_server(args.server)
    from client import rpc_call

    status = rpc_call(host, port, "get_key_status", {
        "entity_id": entity.entity_id_hex,
    })
    if not status.get("ok"):
        print(f"Error: {status.get('error')}")
        sys.exit(1)
    result = status["result"]

    capacity = 1 << MERKLE_TREE_HEIGHT
    used = result["leaf_watermark"]
    remaining = capacity - used
    pct_used = (used * 100) // capacity if capacity else 0

    print("\n=== Key Status ===\n")
    print(f"  Entity ID:       {entity.entity_id_hex}")
    print(f"  Public key:      {result['public_key']}")
    print(f"  Rotation #:      {result['rotation_number']}")
    print(f"  Leaves used:     {used} / {capacity} ({pct_used}%)")
    print(f"  Leaves left:     {remaining}")
    if pct_used >= 80:
        print(f"\n  WARNING: over 80% used — schedule a rotation soon.")
        print("  Run: messagechain rotate-key")


def cmd_emergency_revoke(args):
    """Emergency revoke: disable a compromised validator using the cold key."""
    from messagechain.identity.identity import Entity
    from messagechain.core.emergency_revoke import create_revoke_transaction

    print("=== Emergency Revoke ===\n")
    print("Authenticate with your COLD (authority) key — NOT the hot signing")
    print("key that lives on the validator server. The whole point of revoke")
    print("is that an attacker holding only the hot key cannot do this.\n")

    try:
        target_entity_id = bytes.fromhex(args.entity_id.strip())
    except ValueError:
        print("Error: --entity-id must be valid hex.")
        sys.exit(1)
    if len(target_entity_id) != 32:
        print(f"Error: entity ID must be 32 bytes, got {len(target_entity_id)}.")
        sys.exit(1)

    private_key = _collect_private_key()
    cold = Entity.create(private_key)

    host, port = _parse_server(args.server)
    from client import rpc_call

    # Revoke is nonce-free — no RPC roundtrip required to sign, which is
    # what makes the "keep a pre-signed revoke tx on paper" workflow
    # practical. The cold key's leaf index is local to its own KeyPair.
    fee = args.fee if args.fee is not None else 500
    tx = create_revoke_transaction(
        cold, fee=fee, entity_id=target_entity_id,
    )

    print(f"Broadcasting revoke for {target_entity_id.hex()[:16]}...")
    response = rpc_call(host, port, "emergency_revoke", {
        "transaction": tx.serialize(),
    })
    if response.get("ok"):
        result = response["result"]
        print(f"\nRevoke applied!")
        print(f"  Entity ID: {result['entity_id']}")
        print(f"  TX hash:   {result['tx_hash']}")
        print(f"\nThe validator can no longer propose blocks. Staked funds")
        print("will release to your balance after the 7-day unbonding period.")
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
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

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
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

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
    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(watermark)

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
    from messagechain.identity.key_encoding import encode_private_key
    from messagechain.identity.mnemonic import encode_to_mnemonic
    from messagechain.config import MERKLE_TREE_HEIGHT

    key = os.urandom(32)
    progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Building key tree")
    entity = Entity.create(key, progress=progress)
    mnemonic = encode_to_mnemonic(key)
    encoded_hex = encode_private_key(key)

    # Format the 24 words as a 4x6 grid so it's easy to copy onto paper
    # or stamp into metal without losing place.
    words = mnemonic.split()
    rows = []
    for row_idx in range(4):
        row_words = words[row_idx * 6 : (row_idx + 1) * 6]
        numbered = [f"{row_idx * 6 + i + 1:>2}. {w}" for i, w in enumerate(row_words)]
        rows.append("  " + "   ".join(numbered))

    print("=== Key Pair Generated ===\n")
    print("  Recovery phrase (24 words — write these down IN ORDER):\n")
    for row in rows:
        print(row)
    print(f"\n  Hex form (alternative): {encoded_hex}")
    print(f"\n  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"\n  The recovery phrase follows BIP-39 — every word comes from a")
    print("  known 2048-word list, with a built-in checksum that detects")
    print("  single-word transcription errors when you type it back.")
    print(f"\n  IMPORTANT: Verify your backup before deleting this key.")
    print("  Run: messagechain verify-key")
    print(f"\n  WARNING: Anyone with these words controls your account.")
    print("  There is no recovery. This phrase will NOT be shown again.")


def cmd_verify_key(_args):
    """Re-derive public key and entity ID from a private key (offline)."""
    from messagechain.identity.identity import Entity

    print("=== Verify Key Backup ===\n")
    print("Enter your private key to verify it derives the expected identity.\n")

    from messagechain.config import MERKLE_TREE_HEIGHT
    private_key = _collect_private_key()
    progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Rebuilding key tree")

    try:
        entity = Entity.create(private_key, progress=progress)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"\n  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"\n  Confirm these match your records.")


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


def cmd_proposals(args):
    """List governance proposals with current tally."""
    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "list_proposals", {})

    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    proposals = response["result"]["proposals"]
    if not proposals:
        print("No proposals on chain.")
        return

    print(f"=== Proposals ({len(proposals)}) ===\n")
    for p in proposals:
        print(f"  {p['proposal_id'][:16]}...  [{p['status'].upper()}]  {p['title']}")
        print(f"    proposer: {p['proposer_id'][:16]}...")
        print(f"    votes: {p['vote_count']} cast  |  yes {p['yes_weight']} / total {p['total_weight']}")
        if p["status"] == "open":
            print(f"    {p['blocks_remaining']} blocks remaining")
        print()


def cmd_validators(args):
    """List the current validator set."""
    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "list_validators", {})

    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    validators = response["result"]["validators"]
    if not validators:
        print("No staked validators on chain.")
        return

    print(f"=== Validators ({len(validators)}) ===\n")
    print(f"  {'Entity':<20} {'Stake':>14} {'Share':>8} {'Blocks':>8}")
    for v in validators:
        eid = v["entity_id"][:16] + "..."
        print(f"  {eid:<20} {v['staked']:>14} {v['stake_pct']:>7.2f}% {v['blocks_produced']:>8}")


def cmd_estimate_fee(args):
    """Estimate fee for a message or funds transfer."""
    host, port = _parse_server(args.server)

    if args.transfer:
        params = {"kind": "transfer"}
    else:
        params = {"kind": "message", "message": args.message}

    from client import rpc_call
    response = rpc_call(host, port, "estimate_fee", params)

    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    result = response["result"]
    print("=== Fee Estimate ===\n")
    print(f"  Recommended fee:    {result['recommended_fee']}")
    print(f"  Protocol minimum:   {result['min_fee']}")
    print(f"  Mempool suggestion: {result['mempool_fee']}")


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
        "set-authority-key": cmd_set_authority_key,
        "bootstrap-seed": cmd_bootstrap_seed,
        "emergency-revoke": cmd_emergency_revoke,
        "rotate-key": cmd_rotate_key,
        "key-status": cmd_key_status,
        "delegate": cmd_delegate,
        "propose": cmd_propose,
        "vote": cmd_vote,
        "generate-key": cmd_generate_key,
        "verify-key": cmd_verify_key,
        "read": cmd_read,
        "info": cmd_info,
        "proposals": cmd_proposals,
        "validators": cmd_validators,
        "estimate-fee": cmd_estimate_fee,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
