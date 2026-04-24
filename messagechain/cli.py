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
import re
import stat
import sys

from messagechain import __version__
from messagechain.config import DEFAULT_PORT, MAX_MESSAGE_CHARS


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="messagechain",
        description="MessageChain - decentralized, quantum-resistant messaging",
        usage="messagechain <command> [options]",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Verbose logging"
    )
    # Global --keyfile.  Any subcommand that signs a transaction (send,
    # transfer, stake, unstake, rotate-key, emergency-revoke,
    # set-authority-key, propose, vote, account) can read the private
    # key from this file instead of prompting via getpass.  Enables
    # scripting / unattended usage; previously only `start --keyfile`
    # worked and every other spending command forced interactive input.
    # File should be 0400/0600 and contain the checksummed hex key OR
    # the 24-word mnemonic on a single line.
    parser.add_argument(
        "--keyfile", type=str, default=None,
        help="Path to a file containing the private key (hex or 24-word "
             "mnemonic, one line).  Allows unattended signing.  Ensure "
             "file permissions are 0400 or 0600.",
    )
    # Global --data-dir.  When a signing command runs on the SAME host as
    # the validator daemon (operator convenience case), passing --data-dir
    # lets the CLI (a) reuse the daemon's cached WOTS+ keypair instead of
    # regenerating a multi-minute tree, and (b) coordinate leaf reservation
    # with the running server via the `reserve_leaf` RPC.  Without this
    # flag, cmd_transfer / cmd_stake / etc. work the way they always did
    # (fresh keygen, no daemon coordination) for off-host signers.
    parser.add_argument(
        "--data-dir", type=str, default=None,
        help="Chain data directory (hot-validator co-host optimization).  "
             "When set, signing subcommands load the keypair from the "
             "daemon's on-disk cache and reserve leaves via the server's "
             "reserve_leaf RPC -- eliminating the multi-minute CLI keygen "
             "and preventing WOTS+ leaf collisions with the running daemon.",
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
    # --keyfile is a GLOBAL flag (defined on the top-level parser).
    # Kept callable here as `messagechain start --keyfile ...` for
    # systemd-unit compatibility; redundant but not conflicting.
    start.add_argument("--port", type=int, default=9333, help="P2P port (default: 9333)")
    start.add_argument(
        "--skip-reachability-probe", action="store_true",
        help="Skip the best-effort external-reachability probe on --mine",
    )
    start.add_argument(
        "--yes-nat", action="store_true",
        help="Acknowledge that this validator is behind NAT; continue despite a failed probe",
    )
    start.add_argument("--rpc-port", type=int, default=9334, help="RPC port (default: 9334)")
    start.add_argument(
        "--rpc-bind", type=str, default="127.0.0.1",
        help="RPC bind address.  Default 127.0.0.1 (localhost-only).  "
             "Use 0.0.0.0 for a public validator that accepts remote signed txs.",
    )
    start.add_argument("--seed", nargs="*", help="Seed nodes (host:port)")
    start.add_argument("--data-dir", type=str, default=None, help="Chain data directory")
    start.add_argument(
        "--wallet", type=str, default=None,
        help="Your validator entity_id in hex (the 64-char public one, "
             "NOT the private key).  Pinning this lets the server look "
             "up the chain-stored WOTS+ tree_height for this wallet "
             "instead of regenerating a multi-hour cache if the config "
             "default doesn't match.  Same flag that the systemd unit "
             "example uses (see examples/messagechain-validator.service.example).",
    )

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
    account.add_argument(
        "--sigs-remaining", action="store_true",
        help="Print the number of one-time WOTS+ signatures still "
             "available on your local Merkle key tree.  Useful for "
             "confirming you have room to rotate before the key exhausts.",
    )

    # --- send ---
    send = sub.add_parser(
        "send",
        help="Send a message",
        description="Send a message to the chain (1024 chars max).",
    )
    send.add_argument("message", type=str, help="Message text (1024 chars max)")
    send.add_argument(
        "--fee", type=int, default=None,
        help="Transaction fee (auto-detected if omitted)",
    )
    send.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )

    # --- send-multi ---
    send_multi = sub.add_parser(
        "send-multi",
        help="Send a message via multi-validator HTTPS fan-out",
        description=(
            "Censorship-resistant submission: POST the signed tx in "
            "parallel to N>=3 validator HTTPS endpoints. Receipts are "
            "persisted under --receipts-dir for later evidence use."
        ),
    )
    send_multi.add_argument("message", type=str, help="Message text (1024 chars max)")
    send_multi.add_argument(
        "--fee", type=int, required=True, help="Transaction fee (tokens)",
    )
    send_multi.add_argument(
        "--endpoint", dest="endpoints", action="append", default=[],
        help="Validator endpoint host:port (repeat for each; min 3)",
    )
    send_multi.add_argument(
        "--insecure", action="store_true",
        help="Accept self-signed validator TLS certs (TOFU mode)",
    )
    send_multi.add_argument(
        "--nonce", type=int, default=0,
        help="Tx nonce (default 0; useful for fresh accounts)",
    )
    send_multi.add_argument(
        "--leaf-index", dest="leaf_index", type=int, default=None,
        help=(
            "WOTS+ signing leaf (defaults to nonce). Override when the "
            "chain's leaf-watermark for this entity has drifted past nonce."
        ),
    )
    send_multi.add_argument(
        "--min-successes", dest="min_successes", type=int, default=1,
        help="Minimum endpoints that must accept (default 1)",
    )
    send_multi.add_argument(
        "--per-endpoint-timeout-s", dest="per_endpoint_timeout_s",
        type=float, default=10.0,
        help="Per-endpoint timeout in seconds (default 10)",
    )
    send_multi.add_argument(
        "--receipts-dir", dest="receipts_dir", type=str, default=None,
        help="Where to persist signed receipts (default ~/.messagechain/receipts)",
    )
    send_multi.add_argument(
        "--no-receipts", dest="no_receipts", action="store_true",
        help="Don't request signed receipts (skips X-MC-Request-Receipt)",
    )

    # --- transfer ---
    transfer = sub.add_parser(
        "transfer",
        help="Send tokens to another entity",
        description="Transfer tokens to another registered entity.",
    )
    transfer.add_argument("--to", required=True, help="Recipient address (mc1... checksummed form recommended; raw hex requires --allow-raw-hex-address)")
    transfer.add_argument("--amount", type=int, required=True, help="Amount to transfer")
    transfer.add_argument("--fee", type=int, default=None, help="Transaction fee (auto-detected if omitted)")
    transfer.add_argument("--server", type=str, default=None, help="Server address host:port")
    transfer.add_argument(
        "--allow-raw-hex-address", action="store_true",
        help="Allow raw 64-char hex in --to (bypasses the mc1... "
             "checksum layer).  Required if you are not passing an "
             "mc1... form: raw hex has no typo protection, so a "
             "single mistyped character sends funds to an "
             "unrecoverable address.  Prefer the mc1... form.",
    )

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
        description="Lock tokens for validator staking (minimum graduates 1 -> 10 -> 100 with chain height).",
    )
    stake.add_argument("--amount", type=int, required=True, help="Amount to stake")
    stake.add_argument("--fee", type=int, default=None, help="Transaction fee")
    stake.add_argument("--server", type=str, default=None, help="Server address host:port")
    stake.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )

    # --- unstake ---
    unstake = sub.add_parser(
        "unstake",
        help="Unstake tokens",
        description=(
            "Unlock staked tokens. Unbonding period is ~7 days before "
            "block 50,000 and ~15 days after (UNBONDING_PERIOD_EXTENSION_HEIGHT); "
            "the window covers the evidence slashing lookback."
        ),
    )
    unstake.add_argument("--amount", type=int, required=True, help="Amount to unstake")
    unstake.add_argument("--fee", type=int, default=None, help="Transaction fee")
    unstake.add_argument("--server", type=str, default=None, help="Server address host:port")
    unstake.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )

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
    set_auth.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )

    # --- rotate-key ---
    rotate = sub.add_parser(
        "rotate-key",
        help="Rotate to a fresh Merkle tree (leaf exhaustion recovery)",
        description=(
            "Move this entity to a freshly-derived Merkle tree of one-time "
            "keys. Your entity ID (wallet address), balance, stake, and "
            "authority-key binding all carry over unchanged - only the "
            "underlying signing public key is replaced. Use when your leaf "
            "watermark approaches the tree capacity, typically at ~80% usage."
        ),
    )
    rotate.add_argument("--fee", type=int, default=None, help="Rotation fee")
    rotate.add_argument("--server", type=str, default=None, help="Server address host:port")
    rotate.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )

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
            "the normal unbonding queue so the legitimate operator "
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
    revoke.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )

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

    # --- release-status ---
    # Surface the on-chain release manifest (ReleaseAnnounceTransaction)
    # to the operator - human-readable counterpart to the
    # `get_latest_release` RPC.  Does not download, verify, or apply
    # any binary; notification-only by design.
    release_status = sub.add_parser(
        "release-status",
        help="Show the latest on-chain release manifest",
        description=(
            "Query a running node for the latest on-chain release "
            "manifest (version, severity, signers, binary hashes). "
            "Notification-only - no auto-apply."
        ),
    )
    release_status.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )

    # --- status (operator health-check) ---
    status = sub.add_parser(
        "status",
        help="One-call operator health-check",
        description=(
            "Aggregated validator health + chain state + rotation urgency.\n"
            "Exits 0 when everything is green, 1 if any yellow (warning), "
            "2 if any red (rotation overdue / chain stalled / unreachable).\n"
            "Suitable for cron / monitoring: `messagechain status --server "
            "VAL:9334 && echo ok || echo needs-attention`."
        ),
    )
    status.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )
    status.add_argument(
        "--entity", type=str, default=None,
        help=(
            "Optional entity_id or address to include validator-specific "
            "checks (leaf watermark, rotation urgency).  If omitted, only "
            "chain-level checks run."
        ),
    )
    status.add_argument(
        "--full", action="store_true",
        help="Also print validator-set summary, peer count, and auto-* state",
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

    # --- peers ---
    peers = sub.add_parser(
        "peers",
        help="List P2P peers connected to the target node",
        description=(
            "Show direction (inbound/outbound), connection type, reported "
            "height, duration of the connection, and peer entity_id for "
            "every currently-tracked peer.  Observability only - "
            "routing decisions are not made from CLI output."
        ),
    )
    peers.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- cut-checkpoint ---
    cut_cp = sub.add_parser(
        "cut-checkpoint",
        help="Cut a weak-subjectivity checkpoint from a running node",
        description=(
            "Query a MessageChain node and emit a "
            "WeakSubjectivityCheckpoint JSON object "
            "{block_number, block_hash, state_root}.  Without --out, "
            "prints one JSON object to stdout.  With --out PATH, writes "
            "a JSON array consumable by load_checkpoints_file (single "
            "entry by default, or appended/deduplicated with --append)."
        ),
    )
    cut_cp.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )
    cut_cp.add_argument(
        "--height", type=int, default=None,
        help="Block height to cut at (default: current chain tip)",
    )
    cut_cp.add_argument(
        "--out", type=str, default=None,
        help=(
            "Write output as a JSON array to PATH "
            "(default: print single object to stdout)"
        ),
    )
    cut_cp.add_argument(
        "--append", action="store_true",
        help=(
            "With --out: merge into an existing JSON array, "
            "deduplicating entries by block_number."
        ),
    )

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

    # --- ping ---
    ping = sub.add_parser(
        "ping",
        help="Check connectivity to a MessageChain node (first-run sanity check)",
        description=(
            "Resolve the RPC endpoint (seed auto-discovery or --server "
            "override) and print chain height, validator count, and the "
            "host:port we actually landed on.  No private key required."
        ),
    )
    ping.add_argument("--server", type=str, default=None, help="Server address host:port")

    # --- gen-tor-config ---
    gen_tor = sub.add_parser(
        "gen-tor-config",
        help="Print a torrc snippet fronting this validator's RPC with a hidden service",
        description=(
            "Generate a torrc fragment that exposes the validator's local "
            "RPC endpoint via a Tor hidden service (.onion) address. "
            "Paste the output into /etc/tor/torrc, restart the tor daemon, "
            "and share the hostname from the HiddenServiceDir with clients "
            "in censored networks. MessageChain does not run Tor itself."
        ),
    )
    gen_tor.add_argument(
        "--rpc-bind", type=str, default="127.0.0.1",
        help="RPC bind address on this validator (default: 127.0.0.1). "
             "Must be a loopback address - hidden services forwarding to "
             "a public interface defeat the point.",
    )
    gen_tor.add_argument(
        "--rpc-port", type=int, default=9334,
        help="RPC port on this validator (default: 9334)",
    )
    gen_tor.add_argument(
        "--hidden-service-dir", type=str,
        default="/var/lib/tor/messagechain/",
        help="Filesystem path where tor will store the hidden-service "
             "private key and hostname file (default: /var/lib/tor/messagechain/)",
    )
    gen_tor.add_argument(
        "--external-port", type=int, default=None,
        help="Port advertised on the .onion address (default: same as --rpc-port)",
    )

    # --- migrate-chain-db ---
    migrate_db = sub.add_parser(
        "migrate-chain-db",
        help="Run a one-shot schema migration on an existing chain.db",
        description=(
            "Upgrade an existing chain.db in place to the schema "
            "version this binary expects.  Currently handles the "
            "v1 -> v2 upgrade (populates reputation, key_history, "
            "pending_unstakes, stake_snapshots, and the two new "
            "supply_meta counters from replayed block history).  "
            "Run this BEFORE starting the node on a v1 DB; the node "
            "startup path refuses to open a v1 DB under the v2 "
            "binary and points here for actionable remediation.  "
            "Non-destructive: only writes to the six v2-new tables/"
            "rows and the schema_version meta row.  Idempotent: a "
            "second run on a v2 DB is a no-op.  Can take "
            "minutes-to-hours on a chain with many blocks (replay "
            "is O(chain_length))."
        ),
    )
    migrate_db.add_argument(
        "--data-dir", type=str, required=True,
        help="Chain data directory containing chain.db",
    )

    # --- upgrade ---
    upgrade = sub.add_parser(
        "upgrade",
        help="Upgrade validator binary to a released tag (stop -> backup "
             "-> fetch -> swap -> migrate -> start -> health-check -> rollback)",
        description=(
            "One-shot validator binary upgrade.  Stops the systemd "
            "service, backs up the current install directory, clones "
            "the requested release tag (default: latest GitHub "
            "release), swaps in the new code, runs migrate-chain-db "
            "(idempotent; skip with --skip-migrate for same-schema "
            "hot restarts), starts the service, polls local RPC for "
            "health, and rolls back to the backup on health-check "
            "failure (suppress with --no-rollback).  Requires root "
            "(systemctl) and git.  Pass --tag to pin a specific "
            "release; without it the GitHub Releases API is consulted "
            "and the command hard-fails if the API is unreachable."
        ),
    )
    upgrade.add_argument(
        "--tag", type=str, default=None,
        help="Git tag to install (e.g. v1.2.0-mainnet).  If omitted, "
             "the latest GitHub release tag is used.",
    )
    upgrade.add_argument(
        "--install-dir", type=str, default="/opt/messagechain",
        help="Filesystem path of the validator install directory "
             "(default: /opt/messagechain)",
    )
    upgrade.add_argument(
        "--data-dir", type=str, default="/var/lib/messagechain",
        help="Chain data directory for the migrate-chain-db step "
             "(default: /var/lib/messagechain)",
    )
    upgrade.add_argument(
        "--service", type=str, default="messagechain-validator",
        help="systemd service unit name (default: messagechain-validator)",
    )
    upgrade.add_argument(
        "--repo", type=str,
        default="https://github.com/ben-arnao/MessageChain",
        help="Git repo URL to clone (default: upstream; override for "
             "testing / mirrors)",
    )
    upgrade.add_argument(
        "--service-user", type=str, default="messagechain:messagechain",
        help="user:group to chown the new install dir to "
             "(default: messagechain:messagechain)",
    )
    upgrade.add_argument(
        "--no-rollback", action="store_true",
        help="Do not rollback to the backup on post-start health-check "
             "failure.  New code stays in place; operator must recover "
             "by hand.",
    )
    upgrade.add_argument(
        "--skip-migrate", action="store_true",
        help="Skip the migrate-chain-db step.  Safe for same-schema "
             "upgrades; migration is idempotent so running it on a "
             "target schema DB is a no-op regardless.",
    )
    upgrade.add_argument(
        "--rpc-host", type=str, default="127.0.0.1",
        help="Local RPC host for the post-start health check "
             "(default: 127.0.0.1)",
    )
    upgrade.add_argument(
        "--rpc-port", type=int, default=9334,
        help="Local RPC port for the post-start health check "
             "(default: 9334)",
    )
    upgrade.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip interactive confirmation.",
    )

    # --- init ---
    init_p = sub.add_parser(
        "init",
        help="One-shot operator setup: keyfile, data-dir, systemd units",
        description=(
            "Generate a private key (or adopt an existing one via --keyfile), "
            "lay out the data directory, write /etc/messagechain/onboard.toml, "
            "and emit systemd unit files. Does not enable any services."
        ),
    )
    init_p.add_argument("--init-data-dir", dest="init_data_dir", type=str, default=None,
                        help="Data directory to lay out (default: /var/lib/messagechain as root, ~/.messagechain/chaindata otherwise)")
    init_p.add_argument(
        "--systemd", dest="systemd", action="store_true", default=None,
        help="Emit systemd unit files (default: on when running as root)",
    )
    init_p.add_argument(
        "--no-systemd", dest="systemd", action="store_false",
    )
    init_p.add_argument(
        "--auto-upgrade", dest="auto_upgrade", action="store_true", default=True,
    )
    init_p.add_argument(
        "--no-auto-upgrade", dest="auto_upgrade", action="store_false",
    )
    init_p.add_argument(
        "--auto-rotate", dest="auto_rotate", action="store_true", default=True,
    )
    init_p.add_argument(
        "--no-auto-rotate", dest="auto_rotate", action="store_false",
    )
    init_p.add_argument("--yes", action="store_true",
                        help="Non-interactive; accept all defaults")
    init_p.add_argument("--print-only", action="store_true",
                        help="Dry-run: print what would happen, write nothing")

    # --- doctor ---
    doctor_p = sub.add_parser(
        "doctor",
        help="Local-host preflight checks before starting a validator",
        description=(
            "Run a battery of local checks: Python version, data-dir + "
            "keyfile permissions, disk free, P2P/RPC port bindability, "
            "seed reachability, and (when auto-* is enabled) the "
            "corresponding systemd timers. Exits 0/1/2 for green/yellow/red."
        ),
    )
    doctor_p.add_argument("--doctor-data-dir", dest="doctor_data_dir", type=str, default=None,
                          help="Data directory to inspect (defaults from onboard.toml)")
    doctor_p.add_argument("--check-timers", action="store_true",
                          help="Also probe systemctl is-enabled for auto-* timers")

    # --- rotate-key-if-needed ---
    rotate_if_p = sub.add_parser(
        "rotate-key-if-needed",
        help="Auto-rotate the validator's signing key when >= 95%% consumed",
        description=(
            "Queries the local chain for the current leaf watermark, computes "
            "the consumption percentage, and rotates only when >= 95%%. Exits "
            "0 on any no-op path. Designed to run daily under systemd."
        ),
    )
    rotate_if_p.add_argument("--yes", action="store_true")
    rotate_if_p.add_argument("--server", type=str, default=None)

    # --- config ---
    config_p = sub.add_parser(
        "config",
        help="Read or write onboard.toml flags",
        description=(
            "`messagechain config get <key>` prints the value; "
            "`messagechain config set <key> <value>` writes it. "
            "Supported keys: auto_upgrade, auto_rotate, data_dir, keyfile, entity_id_hex."
        ),
    )
    config_sub = config_p.add_subparsers(dest="config_action", required=True)
    config_get_p = config_sub.add_parser("get")
    config_get_p.add_argument("key")
    config_set_p = config_sub.add_parser("set")
    config_set_p.add_argument("key")
    config_set_p.add_argument("value")


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


def _describe_unbonding_period(tip_height: int | None) -> str:
    """Human-readable unbonding window for the active fork state.

    Callers pass the observed tip height (from an RPC probe) so the
    message matches what the chain will actually enforce when the
    unstake lands.  Tip unknown -> describe both regimes so the user
    isn't misled into planning on the wrong window.
    """
    from messagechain.config import (
        BLOCK_TIME_TARGET,
        UNBONDING_PERIOD_EXTENSION_HEIGHT,
        UNBONDING_PERIOD_LEGACY,
        UNBONDING_PERIOD_POST_EXTENSION,
    )
    legacy_days = round(UNBONDING_PERIOD_LEGACY * BLOCK_TIME_TARGET / 86400)
    post_days = round(UNBONDING_PERIOD_POST_EXTENSION * BLOCK_TIME_TARGET / 86400)
    if tip_height is None:
        return (
            f"~{legacy_days}-day unbonding pre block "
            f"{UNBONDING_PERIOD_EXTENSION_HEIGHT:,}, "
            f"~{post_days}-day after"
        )
    if tip_height >= UNBONDING_PERIOD_EXTENSION_HEIGHT:
        return f"~{post_days}-day unbonding"
    return (
        f"~{legacy_days}-day unbonding (extends to ~{post_days}-day "
        f"at block {UNBONDING_PERIOD_EXTENSION_HEIGHT:,})"
    )


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
    """Quick liveness probe - returns True if we can open a socket."""
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
    import secrets
    from messagechain.config import CLIENT_SEED_ENDPOINTS

    # Stage 1: find a reachable seed.
    # Use crypto randomness instead of stdlib `random`.  Client-side
    # validator selection is not itself a consensus operation, but a
    # predictable RNG lets a surveillance peer correlate CLI traffic
    # back to specific validators for targeted DoS / censorship.
    # secrets.SystemRandom gives us the same shuffle API with kernel
    # randomness underneath.
    _rng = secrets.SystemRandom()
    reachable_seed = None
    candidates = list(CLIENT_SEED_ENDPOINTS)
    _rng.shuffle(candidates)
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
        pick = _rng.randint(1, total_w)
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


def _rpc_call_or_friendly_exit(
    host: str,
    port: int,
    method: str,
    params: dict,
    *,
    server_was_explicit: bool,
):
    """Call `client.rpc_call` and convert connection failures to a clean exit.

    Without this wrapper, a user with an empty / stale CLIENT_SEED_ENDPOINTS
    config (or a typo in --server) sees a raw socket stack trace when they
    run any CLI command.  That is actively misleading: it suggests the
    problem is on their machine when the actual cause is usually "no
    node reachable."

    The recovery advice differs by how we got here:
      - explicit --server: the user picked the address; just tell them it
        is unreachable.  Do not lecture them about CLIENT_SEED_ENDPOINTS
        - they already bypassed it on purpose.
      - auto-discovery: list all three recovery paths so a newcomer with
        a default config can figure out what to do.
    """
    import socket as _socket

    try:
        from client import rpc_call
        return rpc_call(host, port, method, params)
    except (ConnectionRefusedError, ConnectionError, _socket.timeout,
            _socket.gaierror, OSError) as exc:
        target = f"{host}:{port}"
        if server_was_explicit:
            print(
                f"Error: cannot reach the node you specified ({target}).\n"
                f"  Reason: {exc}\n"
                f"  Check the address and that the node's RPC port is open.",
                file=sys.stderr,
            )
        else:
            print(
                f"Error: no MessageChain node reachable "
                f"(tried {target} last).\n"
                f"  Reason: {exc}\n"
                f"\n"
                f"  To fix this, do one of:\n"
                f"    1. Pass --server <host>:<port> to point at a known node.\n"
                f"    2. Configure CLIENT_SEED_ENDPOINTS in messagechain/config.py\n"
                f"       with one or more seed validators.\n"
                f"    3. Run a local validator node: messagechain start --mine",
                file=sys.stderr,
            )
        sys.exit(1)


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
    # Skip for small trees (tests, small configs) - the overhead of
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


def _load_key_from_file(path: str, *, accept_raw_hex: bool = False) -> bytes:
    """Load and verify a checksummed private key from a file.

    Returns the raw 32-byte private key. Raises KeyFileError on any
    problem so that validators fail loudly at startup rather than silently
    running as the wrong identity.

    On POSIX systems, warns if the file is group/world-readable. We do
    NOT refuse to load - operators may have valid reasons (e.g. container
    secrets) for wider perms - but we surface the risk.

    When *accept_raw_hex* is True, also accept the daemon-side 64-char
    raw-hex format (what server.py --keyfile consumes).  Off by default
    so paper-backup users still get the checksum check -- the CLI only
    lowers the bar when it already knows it's running alongside a
    daemon on the same host (operator path, via global --data-dir).
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
        # Daemon-format keyfiles are plain 64-char hex (no 8-char
        # checksum suffix).  When the caller explicitly opts in, fall
        # back to that format so `--data-dir --keyfile /etc/messagechain/
        # mainnet-keyfile` works without hand-reformatting the operator
        # key just to satisfy the CLI's paper-backup checksum path.
        stripped = contents.strip()
        if accept_raw_hex and len(stripped) == 64:
            try:
                key = bytes.fromhex(stripped)
                if len(key) != 32:
                    raise ValueError("expected 32 bytes")
            except ValueError as exc:
                raise KeyFileError(
                    f"Key file has invalid format: {path}: {exc}"
                )
        else:
            raise KeyFileError(f"Key file has invalid format: {path}: {e}")

    # Reject permissive permissions (POSIX only - Windows stat is different).
    if hasattr(os, "getuid"):
        try:
            mode = os.stat(path).st_mode
            if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                raise KeyFileError(
                    f"Key file {path} is readable by group/others (mode {oct(mode)}). "
                    f"Fix with: chmod 600 {path}"
                )
        except OSError:
            pass

    return key


def _load_cached_entity(private_key, data_dir):
    """Load an Entity from the daemon's on-disk keypair cache, or None.

    Used when a signing CLI runs co-resident with a validator daemon on
    the same host: the daemon's cache (~30 min to regenerate from scratch
    for a production tree_height=20 wallet) is reused, so `cli transfer`
    / `cli stake` complete in seconds instead of forcing a fresh keygen.

    Returns None if the cache is absent, stale, or the daemon was never
    started from *data_dir* -- the caller falls back to the slow path.
    Cache authenticity is HMAC-verified by the daemon's loader, so a
    corrupted or tampered cache file can't leak a wrong public key.

    The on-disk tree_height must match the chain's stored height for
    this entity, which for existing wallets is tracked via the
    `--wallet` mechanism on the daemon.  We try 16 (prototype / the
    operator-chosen height on mainnet bootstrap) then the config
    default -- both are cheap misses since _load_or_create_entity falls
    straight through on a bad cache path without touching keygen.
    """
    try:
        import importlib.util
        import os as _os
        spec = importlib.util.spec_from_file_location(
            "_mc_server", _os.path.join(
                _os.path.dirname(_os.path.dirname(__file__)), "server.py",
            ),
        )
        if spec is None or spec.loader is None:
            return None
        srv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(srv)
    except Exception:
        return None

    from messagechain.config import MERKLE_TREE_HEIGHT, LEAF_INDEX_FILENAME
    import os as _os
    # Try the two most plausible heights in priority order: operator
    # override (16) then the compiled-in default.  _load_or_create_entity
    # falls straight through to fresh keygen on cache miss, so speculating
    # costs only a short file-stat / HMAC-verify per attempt.
    candidate_heights = []
    for h in (16, MERKLE_TREE_HEIGHT):
        if h not in candidate_heights:
            candidate_heights.append(h)
    for height in candidate_heights:
        cache_path = srv._keypair_cache_path(private_key, height, data_dir)
        if not _os.path.exists(cache_path):
            continue
        try:
            entity = srv._load_or_create_entity(
                private_key, height, data_dir, no_cache=False,
            )
        except Exception:
            continue
        # Bind leaf-index persistence so sign() durably burns the leaf
        # before the signature can escape the process -- same invariant
        # the daemon relies on.  load_leaf_index silently tolerates a
        # missing file (fresh wallet, never signed).
        leaf_path = _os.path.join(data_dir, LEAF_INDEX_FILENAME)
        try:
            entity.keypair.leaf_index_path = leaf_path
            entity.keypair.load_leaf_index(leaf_path)
        except Exception:
            entity.keypair.leaf_index_path = None
        return entity
    return None


def _reserve_leaf_via_rpc(host, port, entity_id_hex):
    """Ask the server to atomically reserve a leaf for the given entity.

    Returns the reserved leaf index, or None if the server doesn't
    implement the RPC (older daemons) -- in which case the caller should
    fall back to the chain-watermark path.  Reserving bumps the server's
    in-memory _next_leaf so a subsequent block sign by the same wallet
    will skip this leaf, preventing the CLI-vs-daemon collision that
    would otherwise surface as two WOTS+ signatures at the same leaf.
    """
    from client import rpc_call
    r = rpc_call(host, port, "reserve_leaf", {"entity_id": entity_id_hex})
    if not r.get("ok"):
        return None
    result = r.get("result", {})
    leaf = result.get("leaf_index")
    if not isinstance(leaf, int):
        return None
    return leaf


def _resolve_private_key(args=None):
    """Resolve the private key for a signing command.

    If the user passed --keyfile on the command line (global flag),
    read the key from that file.  Otherwise fall back to the
    interactive prompt in `_collect_private_key`.

    This is the single entry point for spending commands - putting the
    branch here means every signing subcommand supports --keyfile for
    free, enabling unattended/scripted operation.
    """
    if args is not None and getattr(args, "keyfile", None):
        # When --data-dir is set, the caller is co-resident with a
        # daemon and the keyfile is almost certainly in daemon raw-hex
        # format.  Opt into the 64-char parser so the CLI can sign
        # with the SAME keyfile the validator unit is using, without
        # needing a parallel checksummed copy of the operator key.
        accept_raw = bool(getattr(args, "data_dir", None))
        try:
            return _load_key_from_file(args.keyfile, accept_raw_hex=accept_raw)
        except KeyFileError as e:
            print(f"Error: {e}")
            sys.exit(1)
    return _collect_private_key()


def _collect_private_key():
    """Collect a private key from the user interactively.

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
    print("This is your identity - guard it carefully.\n")

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
        from messagechain.config import SEED_NODES, DNS_SEED_DOMAINS
        seed_nodes = list(SEED_NODES)
        # Merge DNS-TXT discovered seeds; dedupe, preserve order.
        if DNS_SEED_DOMAINS:
            try:
                from messagechain.network.seed_discovery import discover_dns_seeds
                extra = discover_dns_seeds(DNS_SEED_DOMAINS)
                seen = set(seed_nodes)
                for entry in extra:
                    if entry not in seen:
                        seed_nodes.append(entry)
                        seen.add(entry)
            except Exception:
                pass
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
        rpc_bind=args.rpc_bind,
    )
    if getattr(args, "wallet", None):
        # Let server.py resolve the WOTS+ tree_height from chain state
        # rather than config default.  Avoids multi-hour keygen after a
        # profile flip (matches the --wallet behavior of server.py
        # directly - see examples/messagechain-validator.service.example).
        server.set_wallet(args.wallet)

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
            private_key = _resolve_private_key(args)
        from messagechain.config import MERKLE_TREE_HEIGHT
        progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Loading key tree")
        entity = Entity.create(private_key, progress=progress)

        # Advance keypair past used leaves
        leaves_used = server.blockchain.get_wots_leaves_used(entity.entity_id)
        if leaves_used > 0:
            entity.keypair.advance_to_leaf(leaves_used)

        server.set_wallet_entity(entity)
        print(f"\nMining as: {entity.entity_id_hex[:16]}...")

        # Best-effort external-reachability probe. Runs before the async
        # loop so the operator sees a visible NAT/firewall warning at
        # startup, not buried in mid-flight logs. Skipped under tests
        # via MC_SKIP_REACHABILITY=1.
        if not getattr(args, "skip_reachability_probe", False):
            from messagechain.runtime import onboarding as _ob
            level, detail = _ob.run_reachability_probe(args.port)
            if level == 2 and not getattr(args, "yes_nat", False):
                print()
                print("  [!] External reachability probe FAILED:")
                print(f"      {detail}")
                print("      Inbound P2P from the public internet is likely blocked.")
                print("      Check NAT port-forwarding and host firewall.")
                print("      To continue anyway: --yes-nat")
                print("      To skip the probe entirely: --skip-reachability-probe")
                sys.exit(2)
            elif level == 1:
                print(f"  [warn] reachability probe inconclusive: {detail}")
            elif level == 0 and "skipped" not in detail:
                print(f"  reachability: {detail}")

        # Nudge: if this validator has no separate cold authority key,
        # every destructive path (unstake, emergency revoke) is controlled
        # by the hot signing key loaded on this server. Compromise of this
        # box = total loss. Warn once at startup so operators don't default
        # into the less-safe mode without knowing.
        authority_pk = server.blockchain.get_authority_key(entity.entity_id)
        if authority_pk is None or authority_pk == entity.public_key:
            print()
            print("  [!]  Single-key model: this server holds the only key that")
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
    """Derive a local entity ID from a private key.

    Receive-to-exist model: there is no "register" step.  A new account
    comes into existence as a consequence of RECEIVING a transfer, and
    its signing pubkey is installed on chain by the first outgoing
    transfer (via TransferTransaction.sender_pubkey).  All this command
    does now is derive + display the entity ID and address so you know
    what to tell the sender who will fund you.

    With --sigs-remaining, skip the "create" summary and instead print
    the local WOTS+ signature capacity so a user can see how close they
    are to key exhaustion.  Works entirely off the local key tree - no
    RPC roundtrip - so a user whose node is down can still check.
    """
    from messagechain.identity.identity import Entity
    from messagechain.identity.address import encode_address

    if getattr(args, "sigs_remaining", False):
        _cmd_account_sigs_remaining(args)
        return

    print("=== Create Account ===\n")

    private_key = _resolve_private_key(args)
    entity = Entity.create(private_key)

    print(f"\nAccount derived from your private key.")
    print(f"  Entity ID:  {entity.entity_id_hex}")
    print(f"  Address:    {encode_address(entity.entity_id)}")
    print()
    print("Share the 'Address' form when receiving funds - it has a")
    print("built-in checksum that catches single-character transcription")
    print("errors. The raw 'Entity ID' is still accepted for compatibility.")
    print()
    print("Your account will appear on chain when someone first sends")
    print("you tokens.  Your first outgoing transfer will reveal your")
    print("public key to the chain automatically.")
    print("Your private key is your sole credential. Never share it.")


def _cmd_account_sigs_remaining(args=None):
    """Print WOTS+ one-time-signature capacity for the current wallet.

    Uses ONLY the local keypair - no RPC required.  This is deliberate:
    if the user has run out of leaves, their node may be offline or
    refusing to sign, and they still need a way to see the problem.

    The number shown is a local upper bound on the remaining signatures.
    Actual on-chain usage may be slightly ahead (if the node has advanced
    its leaf_index since the last `load_leaf_index`), but can never be
    behind - so "remaining" is always the safe-to-use floor.
    """
    from messagechain.identity.identity import Entity

    print("=== Signatures Remaining ===\n")

    private_key = _resolve_private_key(args)
    entity = Entity.create(private_key)

    total = entity.keypair.num_leaves
    remaining = entity.keypair.remaining_signatures
    used = total - remaining
    # Exact to 1 decimal place - large trees (2^20 = 1,048,576) need
    # sub-integer precision to distinguish 79.9% from 80.0%, which is
    # where the rotation warning fires.
    pct_used = (used * 1000) // total / 10 if total else 0.0

    print(f"  Signatures remaining: {remaining:,} / {total:,} ({pct_used:.1f}% used)")
    if pct_used >= 95:
        print()
        print("  CRITICAL: over 95% of one-time signatures consumed.")
        print("  Rotate your key NOW with: messagechain rotate-key")
        print("  If the tree exhausts before you rotate, funds lock until")
        print("  a previously-signed KeyRotationTransaction is submitted.")
    elif pct_used >= 80:
        print()
        print("  WARNING: over 80% of one-time signatures consumed.")
        print("  Schedule a rotation soon: messagechain rotate-key")


def _estimate_signature_size(keypair) -> int:
    """Return the exact to_bytes() length of a fresh signature from `keypair`.

    Signature size is a pure function of the WOTS+ parameters and the
    Merkle tree height, so we can compute it without burning a one-time
    leaf to a probe-sign.  Keep in sync with Signature.to_bytes() layout.
    """
    from messagechain.config import WOTS_KEY_CHAINS
    _HASH = 32
    # Layout (see Signature.to_bytes):
    #   u16 wots_count + N*32 wots_sig
    #   u32 leaf_index
    #   u8  auth_len   + M*32 auth_path   (M = keypair.height)
    #   32 wots_pub + 32 wots_seed + u8 sig_version
    return (
        2 + WOTS_KEY_CHAINS * _HASH
        + 4
        + 1 + keypair.height * _HASH
        + _HASH + _HASH
        + 1
    )


def cmd_send(args):
    """Send a message to the chain."""
    from messagechain.identity.identity import Entity

    message = args.message
    char_count = len(message)
    if char_count > MAX_MESSAGE_CHARS:
        print(f"Error: Message is {char_count} characters (max {MAX_MESSAGE_CHARS}).")
        sys.exit(1)
    if not message.strip():
        print("Error: Message cannot be empty.")
        sys.exit(1)

    print(f"=== Send Message ({char_count} chars) ===\n")

    # Authenticate
    private_key = _resolve_private_key(args)
    data_dir = getattr(args, "data_dir", None)
    entity = None
    if data_dir:
        entity = _load_cached_entity(private_key, data_dir)
        if entity is not None:
            print(f"\nUsing cached keypair from {data_dir} (fast path)")
    if entity is None:
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

    # Prefer server-mediated leaf reservation (see cmd_transfer for full
    # rationale) so a co-resident daemon's next block sign skips the
    # leaf this message is signed at.
    leaf = _reserve_leaf_via_rpc(host, port, entity.entity_id_hex)
    if leaf is None:
        leaf = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(leaf)

    # Auto-detect fee (or use explicit). The actual minimum for a message
    # scales non-linearly with size (MIN_FEE + per-byte + quadratic), so
    # always take max(local_min, server_suggestion) to avoid silently
    # submitting a tx the chain will reject.
    from messagechain.core.transaction import calculate_min_fee
    from messagechain.core.compression import encode_payload
    from messagechain.config import FEE_INCLUDES_SIGNATURE_HEIGHT
    # Fee is charged on the canonical stored size - compute locally so
    # we never overpay and never underpay relative to what the chain
    # will enforce.
    msg_bytes = args.message.encode("ascii")
    stored_bytes, _ = encode_payload(msg_bytes)
    # Post-activation the chain prices (message + signature) bytes; ask
    # the server for its tip height to decide which rule to apply.  On
    # RPC failure fall back to legacy pricing -- the node will reject an
    # under-priced tx and the user can retry with an explicit --fee.
    info_resp = rpc_call(host, port, "get_chain_info", {})
    tip_height = 0
    if info_resp.get("ok"):
        count = info_resp["result"].get("height", 0) or 0
        tip_height = max(count - 1, 0)
    if tip_height + 1 >= FEE_INCLUDES_SIGNATURE_HEIGHT:
        # Signature size is deterministic for the scheme parameters baked
        # into the keypair, so compute it without actually signing (a
        # probe-sign would consume a one-time WOTS+ leaf).
        sig_bytes_len = _estimate_signature_size(entity.keypair)
        local_min = calculate_min_fee(
            stored_bytes, signature_bytes=sig_bytes_len,
        )
    else:
        local_min = calculate_min_fee(stored_bytes)
    fee = args.fee
    if fee is None:
        est_resp = rpc_call(host, port, "get_fee_estimate", {})
        server_suggested = (
            est_resp["result"]["fee_estimate"] if est_resp.get("ok") else 0
        )
        fee = max(local_min, server_suggested)
        note = " (auto - server floor)" if server_suggested >= local_min else " (auto - size floor)"
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


def cmd_send_multi_submit(args) -> int:
    """Send a message via multi-validator HTTPS fan-out.

    Censorship-resistant alternative to `send`: instead of trusting one
    RPC node, POST the signed tx in parallel to N>=3 validator HTTPS
    submission endpoints.  Single-validator censorship and single-
    endpoint blocking become useless because the user reaches alternates
    simultaneously.

    Returns 0 on success (>=min_successes endpoints accepted), non-zero
    otherwise.  Receipts collected from accepting validators are
    persisted under args.receipts_dir so the user can later file a
    CensorshipEvidenceTx if any receipted tx fails to land on-chain.
    """
    from messagechain.identity.identity import Entity
    from messagechain.core.transaction import create_transaction
    from messagechain.network.submit_client import (
        SubmitClient, ValidatorEndpoint,
    )

    raw_endpoints = list(getattr(args, "endpoints", None) or [])
    if len(raw_endpoints) < 3:
        print(
            f"Error: --multi-submit requires at least 3 endpoints "
            f"(got {len(raw_endpoints)}). Pass --endpoint host:port "
            f"three or more times, or populate config_local.SUBMIT_ENDPOINTS."
        )
        return 1
    try:
        endpoints = [ValidatorEndpoint.parse(e) for e in raw_endpoints]
    except ValueError as e:
        print(f"Error: invalid endpoint: {e}")
        return 1
    if getattr(args, "insecure", False):
        for ep in endpoints:
            ep.insecure = True

    keyfile = getattr(args, "keyfile", None)
    if not keyfile or not os.path.exists(keyfile):
        print("Error: --keyfile is required and must exist for multi-submit")
        return 1
    with open(keyfile, "r", encoding="ascii") as f:
        hex_key = f.read().strip()
    try:
        private_key = bytes.fromhex(hex_key)
    except ValueError:
        print("Error: keyfile must contain a 64-char hex private key")
        return 1
    entity = Entity.create(private_key)

    nonce = int(getattr(args, "nonce", 0) or 0)
    leaf_index = getattr(args, "leaf_index", None)
    if leaf_index is None:
        leaf_index = nonce
    entity.keypair.advance_to_leaf(int(leaf_index))

    tx = create_transaction(
        entity, args.message, fee=int(args.fee), nonce=nonce,
    )

    client = SubmitClient(
        endpoints=endpoints,
        min_successes=int(getattr(args, "min_successes", 1) or 1),
        per_endpoint_timeout_s=float(
            getattr(args, "per_endpoint_timeout_s", 10.0) or 10.0
        ),
        request_receipts=not bool(getattr(args, "no_receipts", False)),
    )
    result = client.submit(tx)

    print(f"tx_hash:   {result.tx_hash.hex()}")
    print(f"successes: {result.successes}/{len(endpoints)}")
    print(f"receipts:  {len(result.receipts)}")
    print(f"elapsed:   {result.elapsed_ms}ms")
    for ep, reason in result.rejections:
        print(f"  rejected by {ep.host}:{ep.port}: {reason}")

    receipts_dir = getattr(args, "receipts_dir", None) or os.path.join(
        os.path.expanduser("~"), ".messagechain", "receipts",
    )
    if result.receipts:
        os.makedirs(receipts_dir, exist_ok=True)
        # One file per (tx_hash, issuer_id) so multiple validators'
        # receipts for the same tx don't overwrite each other.
        for r in result.receipts:
            fname = f"{r.tx_hash.hex()}_{r.issuer_id.hex()[:16]}.bin"
            path = os.path.join(receipts_dir, fname)
            with open(path, "wb") as f:
                f.write(r.to_bytes())

    if result.successes < client.min_successes:
        return 1
    return 0


def cmd_transfer(args):
    """Transfer tokens to another entity."""
    from messagechain.identity.identity import Entity
    from messagechain.core.transfer import create_transfer_transaction
    from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE
    from messagechain.validation import parse_hex

    print("=== Transfer Tokens ===\n")

    # Validate recipient BEFORE prompting for the private key - a typo
    # is a permanent loss risk, so we want the user to fix it without
    # having re-entered credentials.
    # Accept either the checksummed "mc1..." display form (preferred,
    # catches single-character typos offline) or the raw 64-char hex
    # form (no typo protection; opt-in via --allow-raw-hex-address).
    from messagechain.identity.address import (
        decode_address,
        InvalidAddressChecksumError,
        InvalidAddressError,
    )
    # Gate raw-hex recipients behind an explicit flag.  The raw form
    # has no checksum, so a single-character typo permanently sends
    # funds to an unrecoverable address - a mainnet footgun.  A user
    # who actually wants raw hex (scripting, integration tests) opts
    # in and sees a clear reminder of the risk.
    raw_to = args.to.strip()
    looks_like_raw_hex = (
        not raw_to.lower().startswith("mc1")
        and len(raw_to) == 64
        and all(c in "0123456789abcdefABCDEF" for c in raw_to)
    )
    if looks_like_raw_hex and not getattr(args, "allow_raw_hex_address", False):
        print(
            "Error: --to looks like raw 64-char hex, which has NO "
            "typo protection.  A single mistyped character sends "
            "funds to an unrecoverable address."
        )
        print(
            "  Prefer the checksummed mc1... form - ask the recipient "
            "for it, or run `messagechain account` to see your own."
        )
        print(
            "  If you really want to send to raw hex (scripts, "
            "integration tests), pass --allow-raw-hex-address."
        )
        sys.exit(2)
    try:
        recipient_id = decode_address(raw_to)
    except InvalidAddressChecksumError as e:
        print(f"Error: {e}")
        print(f"  Got: {args.to}")
        print("  Re-check each character with the sender before retrying.")
        sys.exit(1)
    except InvalidAddressError as e:
        print(f"Error: invalid recipient address - {e}")
        print(f"  Got: {args.to}")
        sys.exit(1)
    if looks_like_raw_hex:
        # Explicit opt-in path: remind the operator they're bypassing
        # the checksum layer so it's visible in CI logs / transcripts.
        print(
            "!  Proceeding with raw-hex --to (no checksum protection).  "
            "Verify the address character-by-character before confirming."
        )

    host, port = _parse_server(args.server)
    from client import rpc_call

    # Receive-to-exist: the recipient need NOT be pre-registered - a
    # Transfer to a brand-new entity_id is fine; the chain creates the
    # balance entry on apply.  Call `estimate_fee` with the recipient_id
    # so the server can tell us (a) whether this is a brand-new recipient
    # and (b) what total fee (including any NEW_ACCOUNT_FEE surcharge)
    # will be accepted by the validator.
    fee_resp = rpc_call(host, port, "estimate_fee", {
        "kind": "transfer",
        "recipient_id": recipient_id.hex(),
    })
    recipient_is_new = False
    server_min_fee = MIN_FEE
    if fee_resp.get("ok"):
        r = fee_resp["result"]
        recipient_is_new = bool(r.get("recipient_is_new", False))
        server_min_fee = int(r.get("min_fee", MIN_FEE))

    # Confirmation step - last chance before the key is handled. Shows
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
    if recipient_is_new:
        print(
            f"  Note:      Recipient is brand-new on chain - "
            f"+{NEW_ACCOUNT_FEE} NEW_ACCOUNT_FEE surcharge (burned)."
        )
    confirm = input("\nConfirm send (type 'yes' to proceed): ").strip().lower()
    if confirm != "yes":
        print("Transfer cancelled.")
        sys.exit(0)

    private_key = _resolve_private_key(args)
    data_dir = getattr(args, "data_dir", None)
    entity = None
    if data_dir:
        entity = _load_cached_entity(private_key, data_dir)
        if entity is not None:
            print(f"\nUsing cached keypair from {data_dir} (fast path)")
    if entity is None:
        entity = Entity.create(private_key)
    print(f"\nSending as: {entity.entity_id_hex[:16]}...")

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]
    # Prefer an atomic server-side leaf reservation when the signer
    # shares a wallet with a running daemon: reserve_leaf bumps the
    # daemon's in-memory _next_leaf so its next block sign won't
    # collide with this transfer.  Falls back to the chain-watermark
    # path when the server doesn't implement reserve_leaf (older
    # daemons) or when the signer's entity isn't this daemon's wallet.
    leaf = _reserve_leaf_via_rpc(host, port, entity.entity_id_hex)
    if leaf is None:
        leaf = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(leaf)

    # Receive-to-exist: determine whether this is a first-spend tx
    # (server has no pubkey for this entity yet).  If so we include
    # sender_pubkey so the chain can install it on apply.
    status_resp = rpc_call(host, port, "get_key_status", {
        "entity_id": entity.entity_id_hex,
    })
    is_first_spend = True
    if status_resp.get("ok"):
        pk_hex = status_resp["result"].get("public_key", "") or ""
        is_first_spend = pk_hex == ""

    # Fee policy:
    #   * --fee explicit:  honor it if it clears the estimator floor
    #     (which includes any NEW_ACCOUNT_FEE surcharge); else error.
    #   * --fee omitted:   use the server-suggested minimum (which
    #     already bundles the surcharge when needed).
    fee = args.fee
    required_floor = max(MIN_FEE, server_min_fee)
    if fee is None:
        fee = required_floor
    elif fee < required_floor:
        if recipient_is_new:
            print(
                f"Error: fee {fee} is below required {required_floor} "
                f"(MIN_FEE {MIN_FEE} + NEW_ACCOUNT_FEE {NEW_ACCOUNT_FEE} "
                f"surcharge for brand-new recipient)."
            )
        else:
            print(f"Error: fee {fee} is below MIN_FEE {MIN_FEE}.")
        sys.exit(1)

    tx = create_transfer_transaction(
        entity, recipient_id, args.amount, nonce=nonce, fee=fee,
        include_pubkey=is_first_spend,
    )

    if recipient_is_new:
        print(
            f"Transferring to a brand-new account - "
            f"+{NEW_ACCOUNT_FEE} NEW_ACCOUNT_FEE surcharge (burned)"
        )
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

    private_key = _resolve_private_key(args)
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

    private_key = _resolve_private_key(args)
    data_dir = getattr(args, "data_dir", None)
    entity = None
    if data_dir:
        entity = _load_cached_entity(private_key, data_dir)
        if entity is not None:
            print(f"\nUsing cached keypair from {data_dir} (fast path)")
    if entity is None:
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

    # Prefer server-side atomic leaf reservation (see cmd_transfer).
    leaf = _reserve_leaf_via_rpc(host, port, entity.entity_id_hex)
    if leaf is None:
        leaf = nonce_resp["result"].get("leaf_watermark", nonce)
    entity.keypair.advance_to_leaf(leaf)

    # Default fee: post-flat floor is the safe choice pre- and post-
    # activation (MIN_FEE=100 pre, MIN_FEE_POST_FLAT=1000 post).  The
    # previous default of 1 was below BOTH floors and got on-chain-
    # rejected for underpriced whenever --fee was omitted.
    from messagechain.config import MIN_FEE_POST_FLAT
    fee = args.fee if args.fee is not None else MIN_FEE_POST_FLAT
    tx = create_stake_transaction(entity, args.amount, nonce=nonce, fee=fee)

    print(f"Staking {args.amount} tokens (fee: {fee})...")

    if not getattr(args, "yes", False):
        print(f"\nAbout to stake:")
        print(f"  Amount:  {args.amount} tokens")
        print(f"  Fee:     {fee} tokens")
        print(f"  Entity:  {entity.entity_id_hex[:16]}...{entity.entity_id_hex[-8:]} (self)")
        confirm = input("\nConfirm stake (type 'yes' to proceed): ").strip().lower()
        if confirm != "yes":
            print("Stake cancelled.")
            sys.exit(0)

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

    private_key = _resolve_private_key(args)
    # Mirror cmd_stake / cmd_transfer: when --data-dir points at a
    # running validator's data_dir, reuse the daemon's cached WOTS+
    # keypair instead of regenerating the Merkle tree from scratch
    # (~20-30 min on production tree_height=16/20 wallets; observed to
    # wedge a CLI invocation for 10+ min on an e2-small mainnet node).
    data_dir = getattr(args, "data_dir", None)
    entity = None
    if data_dir:
        entity = _load_cached_entity(private_key, data_dir)
        if entity is not None:
            print(f"\nUsing cached keypair from {data_dir} (fast path)")
    if entity is None:
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

    # Default fee: post-flat floor is safe pre- and post-activation.
    # See cmd_stake for rationale -- 1 was below both MIN_FEE floors.
    from messagechain.config import MIN_FEE_POST_FLAT
    fee = args.fee if args.fee is not None else MIN_FEE_POST_FLAT
    tx = create_unstake_transaction(entity, args.amount, nonce=nonce, fee=fee)

    print(f"Unstaking {args.amount} tokens (fee: {fee})...")

    if not getattr(args, "yes", False):
        # Probe tip height so the warning reflects the CURRENTLY active
        # unbonding fork, not a stale constant baked into the help text.
        tip_resp = rpc_call(host, port, "get_chain_info", {})
        tip_height: int | None = None
        if tip_resp.get("ok"):
            count = tip_resp["result"].get("height", 0) or 0
            tip_height = max(count - 1, 0)
        print(f"\nAbout to unstake:")
        print(f"  Amount:  {args.amount} tokens")
        print(f"  Fee:     {fee} tokens")
        print(f"  Entity:  {entity.entity_id_hex[:16]}...{entity.entity_id_hex[-8:]} (self)")
        print(
            f"  Warning: unstaked funds enter UNBONDING_PERIOD "
            f"({_describe_unbonding_period(tip_height)}) before they "
            f"return to your balance."
        )
        confirm = input("\nConfirm unstake (type 'yes' to proceed): ").strip().lower()
        if confirm != "yes":
            print("Unstake cancelled.")
            sys.exit(0)

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

    private_key = _resolve_private_key(args)
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
        print("Bootstrap aborted.  Chain state may be partially updated - ")
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

    # -- Step 1: verify the seed is already known on chain -----------
    # Receive-to-exist: seeds are installed at genesis (via the
    # allocation table + bootstrap.bootstrap_seed_local on the
    # validator node itself), not via an RPC call.  An unknown seed
    # here means the server was started without this entity in its
    # genesis allocation, which is a misconfiguration that this CLI
    # cannot repair remotely.
    print("[1/3] Verifying seed entity is known on chain...")
    existing = _fetch_state()
    if existing is None:
        _fatal(
            "1/3 verify",
            "Seed entity is not in chain state.  Include it in the "
            "genesis allocation on the validator host before running "
            "bootstrap-seed.",
        )
    print("      OK: entity is in state")

    # -- Step 2: set authority key (cold) ----------------------------
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

    # -- Step 3: stake -----------------------------------------------
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

    private_key = _resolve_private_key(args)
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

    # Default fee: post-flat floor is safe pre- and post-activation.
    from messagechain.config import MIN_FEE_POST_FLAT
    fee = args.fee if args.fee is not None else MIN_FEE_POST_FLAT
    tx = create_set_authority_key_transaction(
        entity, new_authority_key=authority_pubkey, nonce=nonce, fee=fee,
    )

    if not getattr(args, "yes", False):
        ak_hex = authority_pubkey.hex()
        ak_short = f"{ak_hex[:16]}...{ak_hex[-8:]}"
        print(f"\nAbout to set authority key:")
        print(f"  New authority pubkey: {ak_short}")
        print(f"  (full: {ak_hex})")
        print(f"  Fee:                  {fee} tokens")
        print(
            "  This will lock future revoke/unstake authority to the new "
            "key; irreversible."
        )
        confirm = input(
            "\nConfirm set-authority-key (type 'yes' to proceed): "
        ).strip().lower()
        if confirm != "yes":
            print("Set-authority-key cancelled.")
            sys.exit(0)

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
    print("Your entity ID, balance, and stake are preserved.\n")

    private_key = _resolve_private_key(args)
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

    if not getattr(args, "yes", False):
        new_pk_hex = new_kp.public_key.hex()
        new_pk_short = f"{new_pk_hex[:16]}...{new_pk_hex[-8:]}"
        print(f"\nAbout to rotate key:")
        print(f"  New public key: {new_pk_short}")
        print(f"  (full: {new_pk_hex})")
        print(f"  Rotation #:     {current_rotation}")
        print(f"  Fee:            {fee} tokens")
        print(
            "  The OLD Merkle tree is retired after this runs - keep "
            "signing with the fresh tree from now on."
        )
        confirm = input(
            "\nConfirm rotate-key (type 'yes' to proceed): "
        ).strip().lower()
        if confirm != "yes":
            print("Rotate-key cancelled.")
            sys.exit(0)

    response = rpc_call(host, port, "rotate_key", {
        "transaction": rot_tx.serialize(),
    })
    if response.get("ok"):
        result = response["result"]
        print(f"\nKey rotated!")
        print(f"  Entity ID:      {result['entity_id']}")
        print(f"  New public key: {result['new_public_key']}")
        print(f"  Rotation #:     {result['rotation_number']}")
        print(f"\nYour entity ID is unchanged - wallet address and stake all")
        print("carry over. You can now continue signing with the fresh tree.")
        print("Back up any new derivation metadata if needed.")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_key_status(args):
    """Show the current key tree's rotation and leaf-consumption status."""
    from messagechain.identity.identity import Entity
    from messagechain.config import MERKLE_TREE_HEIGHT

    private_key = _resolve_private_key(args)
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
        print(f"\n  WARNING: over 80% used - schedule a rotation soon.")
        print("  Run: messagechain rotate-key")


def cmd_emergency_revoke(args):
    """Emergency revoke: disable a compromised validator using the cold key."""
    from messagechain.identity.identity import Entity
    from messagechain.core.emergency_revoke import create_revoke_transaction

    print("=== Emergency Revoke ===\n")
    print("Authenticate with your COLD (authority) key - NOT the hot signing")
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

    private_key = _resolve_private_key(args)
    cold = Entity.create(private_key)

    host, port = _parse_server(args.server)
    from client import rpc_call

    # Revoke is nonce-free - no RPC roundtrip required to sign, which is
    # what makes the "keep a pre-signed revoke tx on paper" workflow
    # practical. The cold key's leaf index is local to its own KeyPair.
    # Default fee: post-flat floor is safe pre- and post-activation.
    from messagechain.config import MIN_FEE_POST_FLAT
    fee = args.fee if args.fee is not None else MIN_FEE_POST_FLAT
    tx = create_revoke_transaction(
        cold, fee=fee, entity_id=target_entity_id,
    )

    # Probe tip height so the warning reflects the CURRENTLY active
    # unbonding fork.
    tip_resp = rpc_call(host, port, "get_chain_info", {})
    revoke_tip: int | None = None
    if tip_resp.get("ok"):
        count = tip_resp["result"].get("height", 0) or 0
        revoke_tip = max(count - 1, 0)

    if not getattr(args, "yes", False):
        tid_hex = target_entity_id.hex()
        tid_short = f"{tid_hex[:16]}...{tid_hex[-8:]}"
        print(f"\nAbout to emergency-revoke:")
        print(f"  Target entity: {tid_short}")
        print(f"  (full: {tid_hex})")
        print(f"  Fee:           {fee} tokens")
        print(
            f"  This disables the validator PERMANENTLY.  Staked funds "
            f"release to the operator's balance after the unbonding "
            f"period ({_describe_unbonding_period(revoke_tip)}), but "
            f"block production is stopped immediately and cannot be "
            f"undone."
        )
        confirm = input(
            "\nConfirm emergency-revoke (type 'yes' to proceed): "
        ).strip().lower()
        if confirm != "yes":
            print("Emergency-revoke cancelled.")
            sys.exit(0)

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
        print(
            f"will release to your balance after the unbonding period "
            f"({_describe_unbonding_period(revoke_tip)})."
        )
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

    private_key = _resolve_private_key(args)
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

    private_key = _resolve_private_key(args)
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
    proposal_id = parse_hex(args.proposal, expected_len=32)
    if proposal_id is None:
        print(f"Error: Invalid proposal ID (must be 32 bytes hex): {args.proposal}")
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
    print("  Recovery phrase (24 words - write these down IN ORDER):\n")
    for row in rows:
        print(row)
    print(f"\n  Hex form (alternative): {encoded_hex}")
    from messagechain.identity.address import encode_address
    print(f"\n  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"  Address:     {encode_address(entity.entity_id)}")
    print(f"               ^ share this `mc1...` form to receive funds")
    print(f"\n  The recovery phrase follows BIP-39 - every word comes from a")
    print("  known 2048-word list, with a built-in checksum that detects")
    print("  single-word transcription errors when you type it back.")
    print(f"\n  IMPORTANT: Verify your backup before deleting this key.")
    print("  Run: messagechain verify-key")
    print(f"\n  WARNING: Anyone with these words controls your account.")
    print("  There is no recovery. This phrase will NOT be shown again.")


def cmd_verify_key(args):
    """Re-derive public key and entity ID from a private key (offline)."""
    from messagechain.identity.identity import Entity

    print("=== Verify Key Backup ===\n")
    print("Enter your private key to verify it derives the expected identity.\n")

    from messagechain.config import MERKLE_TREE_HEIGHT
    private_key = _resolve_private_key(args)
    progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Rebuilding key tree")

    try:
        entity = Entity.create(private_key, progress=progress)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    from messagechain.identity.address import encode_address
    print(f"\n  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"  Address:     {encode_address(entity.entity_id)}")
    print(f"\n  Confirm all three match your records.")


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


def cmd_release_status(args):
    """Show the latest on-chain release manifest.

    Calls the `get_latest_release` RPC and formats the result for a
    human reader.  If the node has seen no manifest (new chain, or
    the release committee hasn't published yet), prints a one-line
    "No release manifest seen" note with the current node version.

    Notification surface only - no binary download, no signature
    verification against local files.  See
    messagechain/core/release_announce.py for the tx-layer details.
    """
    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "get_latest_release", {})

    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    result = response["result"]
    current = result.get("current_node_version", "?")
    manifest = result.get("latest_manifest")

    if manifest is None:
        print(f"No release manifest seen. Node version: {current}")
        return

    version = manifest.get("version", "?")
    label = manifest.get("severity_label", "?")
    update_available = result.get("update_available", False)

    print("=== Release Status ===\n")
    print(f"  Node version:       {current}")
    print(f"  Latest manifest:    v{version} ({label})")
    print(f"  Update available:   {'YES' if update_available else 'NO'}")

    signer_indices = manifest.get("signer_indices", [])
    num_signers = manifest.get("num_signers", len(signer_indices))
    threshold = manifest.get("threshold", "?")
    idx_str = ", ".join(str(i) for i in signer_indices)
    print(f"  Signers:            {num_signers} of {threshold} "
          f"(indices: {idx_str})")

    # Activation height is optional - manifest may have been issued
    # without one (routine release).  Skip the line entirely in that
    # case, same as the boot-log helper.
    mah = manifest.get("min_activation_height")
    if mah is not None:
        print(f"  Min activation:     height {mah}")

    binary_hashes = manifest.get("binary_hashes", {})
    if binary_hashes:
        print("  Binary hashes:")
        # Align hashes under a fixed-width platform column so the
        # output scans at a glance, even when platform names differ
        # in length.
        max_name = max(len(k) for k in binary_hashes)
        for platform in sorted(binary_hashes):
            h = binary_hashes[platform]
            print(f"    {platform:<{max_name}}  {h}")

    uri = manifest.get("release_notes_uri", "")
    print(f"  Release notes:  {uri}")


def cmd_status(args):
    """One-call operator health-check.

    Exit codes:
      0 - all green
      1 - at least one yellow (warning but functional)
      2 - at least one red (rotation overdue / chain stalled / unreachable)
    """
    host, port = _parse_server(args.server)

    from client import rpc_call
    worst = 0  # 0=green 1=yellow 2=red
    lines: list[str] = []

    def mark(level: int, label: str, status: str, detail: str = ""):
        nonlocal worst
        worst = max(worst, level)
        tag = {0: "OK  ", 1: "WARN", 2: "FAIL"}[level]
        msg = f"  [{tag}] {label}: {status}"
        if detail:
            msg += f" - {detail}"
        lines.append(msg)

    # 1. Chain reachable + basic info
    info_resp = rpc_call(host, port, "get_chain_info", {})
    if not info_resp.get("ok"):
        mark(2, "rpc reachable", "FAIL",
             info_resp.get("error", "could not connect"))
        print(f"=== Status check against {host}:{port} ===\n")
        for line in lines:
            print(line)
        print("\n  Result: RED - chain unreachable")
        sys.exit(2)

    info = info_resp["result"]
    height = info["height"]
    mark(0, "rpc reachable", f"height={height}")

    # 2. Sync state
    sync = info.get("sync_status", {})
    state = sync.get("state", "?")
    if state == "idle":
        mark(0, "sync", "idle (caught up)")
    elif state in ("syncing_headers", "syncing_blocks"):
        progress = sync.get("progress", "?")
        mark(1, "sync", f"{state} {progress}",
             "not yet caught up - catching up to network")
    else:
        mark(1, "sync", str(state))

    # 3. Pinned genesis sanity - present and non-empty
    latest_hash = info.get("latest_block_hash", "")
    if latest_hash and len(latest_hash) == 64:
        mark(0, "chain tip", latest_hash[:16] + "...")
    else:
        mark(2, "chain tip", "missing latest_block_hash", "RPC response malformed")

    # 3b. Liveness - warn if no block in 2x block-time, fail at 6x.
    # Stalls are the single most useful thing a cron check can detect;
    # "height=122" alone doesn't distinguish a healthy idle chain from
    # a halted one.
    try:
        from messagechain.config import BLOCK_TIME_TARGET
    except ImportError:
        BLOCK_TIME_TARGET = 600
    seconds_since = info.get("seconds_since_last_block")
    if seconds_since is None:
        mark(1, "liveness", "no timestamp", "server returned null")
    elif seconds_since < 0:
        mark(1, "liveness", f"future timestamp ({seconds_since}s)",
             "clock skew between client and validator")
    elif seconds_since > 6 * BLOCK_TIME_TARGET:
        mark(2, "liveness", f"STALLED {seconds_since}s",
             f">6x block-time ({6 * BLOCK_TIME_TARGET}s) since last block")
    elif seconds_since > 2 * BLOCK_TIME_TARGET:
        mark(1, "liveness", f"slow {seconds_since}s",
             f">2x block-time since last block")
    else:
        mark(0, "liveness", f"{seconds_since}s since last block")

    # 4. Validator entity-specific checks (optional)
    if args.entity:
        # Accept hex or address format
        entity_hex = args.entity.strip()
        if entity_hex.startswith("mc1") or entity_hex.startswith("Mc1"):
            try:
                from messagechain.identity.address import decode_address
                eid_bytes = decode_address(entity_hex)
                entity_hex = eid_bytes.hex()
            except Exception as e:
                mark(2, "entity", "invalid address", str(e))
                entity_hex = None

        if entity_hex:
            ent_resp = rpc_call(
                host, port, "get_entity",
                {"entity_id": entity_hex},
            )
            if ent_resp.get("ok"):
                e = ent_resp["result"]
                staked = e.get("staked", 0)
                balance = e.get("balance", 0)
                mark(0, "entity state",
                     f"balance={balance} staked={staked}")
            else:
                mark(1, "entity state", "not found",
                     ent_resp.get("error", ""))

            # Leaf watermark - rotation urgency
            wm_resp = rpc_call(
                host, port, "get_leaf_watermark",
                {"entity_id": entity_hex},
            )
            if wm_resp.get("ok"):
                wm = wm_resp["result"].get("leaf_watermark", 0)
                # Assume tree_height=16 (65K leaves) as the default; we
                # don't know the real tree height from an RPC response
                # alone.  This is a heuristic warning, not a hard limit.
                est_total = 1 << 16
                pct = (wm / est_total) * 100
                if pct < 50:
                    mark(0, "leaf usage", f"{wm}/{est_total} ({pct:.1f}%)")
                elif pct < 80:
                    mark(0, "leaf usage",
                         f"{wm}/{est_total} ({pct:.1f}%)",
                         "plenty of signatures remaining")
                elif pct < 95:
                    mark(1, "leaf usage",
                         f"{wm}/{est_total} ({pct:.1f}%)",
                         "plan a key rotation in the next few months")
                else:
                    mark(2, "leaf usage",
                         f"{wm}/{est_total} ({pct:.1f}%)",
                         "ROTATE NOW - signatures nearly exhausted")

    # 5. Liveness - chain height advanced in the last 30s?  Not
    #    reliable from a single probe, but a block-time of 600s means
    #    "height unchanged over 30s" is uninformative.  Skip.

    # Emit report
    print(f"=== Status check against {host}:{port} ===\n")

    # Surface onboard auto-* state at the top so an operator reading a
    # single status pane sees whether their upgrade/rotate timers are
    # armed. Tolerate missing onboard config silently.
    try:
        from messagechain.runtime import onboarding as _ob
        onboard_cfg = _ob.read_onboard_config()
        print(
            f"  Auto-upgrade: {'ON' if onboard_cfg.get('auto_upgrade') else 'OFF'}"
            f"  |  Auto-rotate: {'ON' if onboard_cfg.get('auto_rotate') else 'OFF'}"
        )
        print()
    except Exception:
        pass

    for line in lines:
        print(line)

    if getattr(args, "full", False):
        print()
        print("=== Full view ===")
        vr = rpc_call(host, port, "list_validators", {})
        if vr.get("ok"):
            vlist = vr["result"].get("validators", [])[:10]
            print(f"  Top validators ({len(vlist)}):")
            for v in vlist:
                eid = v.get("entity_id", "")[:16]
                print(
                    f"    {eid}...  stake={v.get('staked', 0)}  "
                    f"share={v.get('stake_pct', 0):.2f}%  "
                    f"blocks={v.get('blocks_produced', 0)}"
                )
        pr = rpc_call(host, port, "get_peers", {})
        if pr.get("ok"):
            count = pr["result"].get("count", len(pr["result"].get("peers", [])))
            print(f"  Peers: {count}")
        if args.entity:
            er = rpc_call(host, port, "get_entity", {"entity_id": args.entity})
            if er.get("ok"):
                e = er["result"]
                print(
                    f"  This node:  balance={e.get('balance', 0)}  "
                    f"staked={e.get('staked', 0)}"
                )
    print()
    verdict = {0: "GREEN (ok)", 1: "YELLOW (needs attention)",
               2: "RED (urgent)"}[worst]
    print(f"  Result: {verdict}")
    sys.exit(worst)


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
        print(f"    votes: {p['vote_count']} cast  |  yes {p['yes_weight']} / eligible {p['total_eligible']}")
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


def cmd_peers(args):
    """List peers connected to the target node, with metadata."""
    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "get_peers", {})

    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    peers = response["result"]["peers"]
    count = response["result"].get("count", len(peers))
    if not peers:
        print(f"=== Peers (0 - this node has no active P2P connections) ===")
        return

    # Compact, grep-friendly table.  No ANSI color - some operators
    # pipe this straight to log aggregators.
    print(f"=== Peers ({count}) ===\n")
    print(
        f"  {'Address':<22} {'Dir':<9} {'Type':<18} {'TLS':<5} {'Height':>8} "
        f"{'Connected':>11} {'Version':<10} {'Entity':<20}"
    )
    def _fmt_elapsed(s: int) -> str:
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s // 60}m{s % 60}s"
        return f"{s // 3600}h{(s % 3600) // 60}m"
    for p in peers:
        eid = (p.get("entity_id") or "")[:16]
        eid_disp = (eid + "...") if eid else "(none)"
        # Older servers without the field return None -> show "?" so the
        # operator sees "I should upgrade" rather than a misleading "no".
        transport = p.get("transport")
        tls_disp = "yes" if transport == "tls" else ("no" if transport == "plain" else "?")
        # Peers running <1.2.0 did not advertise a version in the
        # handshake payload; the server maps "" -> "unknown" on receive,
        # but guard here too so a missing/empty RPC field still renders
        # cleanly instead of as blank whitespace.
        version = p.get("version") or "unknown"
        print(
            f"  {p['address']:<22} {p['direction']:<9} {p['connection_type']:<18} {tls_disp:<5} "
            f"{p['height']:>8} {_fmt_elapsed(p['seconds_connected']):>11} {version:<10} {eid_disp:<20}"
        )


def cmd_cut_checkpoint(args):
    """Cut a weak-subjectivity checkpoint from a running node.

    Queries the target node for (block_number, block_hash, state_root)
    at the requested height (tip by default) and emits the result either
    to stdout (single JSON object) or to a file (JSON array - the shape
    that load_checkpoints_file consumes).

    With --append, an existing file is merged in and entries are
    deduplicated by block_number so an operator can run the cutter on a
    cron without ballooning the file.

    Exits non-zero on any RPC failure or malformed response so a cron
    wrapper can treat stale/missing output as a hard error.
    """
    host, port = _parse_server(args.server)

    from client import rpc_call

    # Pick the RPC: tip -> get_chain_info (already ubiquitous), explicit
    # height -> get_checkpoint_at_height (narrow, returns only the three
    # fields we need).  Doing both saves the --height path from fetching
    # a full block we'd otherwise throw away.
    if args.height is None:
        response = rpc_call(host, port, "get_chain_info", {})
        if not response.get("ok"):
            print(
                f"Error: {response.get('error', 'Could not connect')}",
                file=sys.stderr,
            )
            sys.exit(1)
        info = response["result"]
        height = info.get("height")
        # get_chain_info returns the *count* of blocks as `height` - the
        # tip's block_number is height - 1.  An empty chain has nothing
        # to checkpoint.
        if not height or info.get("latest_block_hash") is None:
            print("Error: chain is empty - nothing to checkpoint", file=sys.stderr)
            sys.exit(1)
        if info.get("state_root") is None:
            print(
                "Error: node did not return state_root "
                "(is it running an older version?)",
                file=sys.stderr,
            )
            sys.exit(1)
        checkpoint = {
            "block_number": height - 1,
            "block_hash": info["latest_block_hash"],
            "state_root": info["state_root"],
        }
    else:
        response = rpc_call(
            host, port, "get_checkpoint_at_height", {"height": args.height},
        )
        if not response.get("ok"):
            print(
                f"Error: {response.get('error', 'Could not connect')}",
                file=sys.stderr,
            )
            sys.exit(1)
        checkpoint = response["result"]
        # Defensive: malformed response should not silently produce a
        # broken checkpoint.  Every field is required.
        for field in ("block_number", "block_hash", "state_root"):
            if field not in checkpoint:
                print(
                    f"Error: RPC response missing '{field}'",
                    file=sys.stderr,
                )
                sys.exit(1)

    import json

    if args.out is None:
        # Stdout: single object (pipe-friendly, matches
        # WeakSubjectivityCheckpoint.serialize()).
        print(json.dumps(checkpoint, indent=2, sort_keys=True))
        return

    # File mode: always write a JSON array (load_checkpoints_file's shape).
    entries: list[dict] = []
    if args.append:
        try:
            with open(args.out, "r") as f:
                existing = json.load(f)
            if isinstance(existing, list):
                entries = [e for e in existing if isinstance(e, dict)]
            else:
                print(
                    f"Error: --append requires {args.out} to contain a "
                    f"JSON array (got {type(existing).__name__})",
                    file=sys.stderr,
                )
                sys.exit(1)
        except FileNotFoundError:
            entries = []
        except (json.JSONDecodeError, OSError) as e:
            print(f"Error: failed to read {args.out}: {e}", file=sys.stderr)
            sys.exit(1)

    # Dedupe by block_number - keep the latest cut for that height so a
    # re-run picks up any hash correction.
    entries = [
        e for e in entries
        if e.get("block_number") != checkpoint["block_number"]
    ]
    entries.append(checkpoint)
    entries.sort(key=lambda e: e.get("block_number", 0))

    with open(args.out, "w") as f:
        json.dump(entries, f, indent=2, sort_keys=True)
        f.write("\n")


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


def cmd_ping(args):
    """Light-client sanity check: resolve endpoint and report chain status.

    Exists specifically for the first-run experience of a non-validator
    user who just wants to confirm their `messagechain` install is wired
    to a live network before they touch any key material.  Cheap, safe,
    and read-only.
    """
    server_was_explicit = args.server is not None and args.server != ""
    host, port = _parse_server(args.server)

    response = _rpc_call_or_friendly_exit(
        host, port, "get_chain_info", {},
        server_was_explicit=server_was_explicit,
    )

    if not response.get("ok"):
        print(f"Error: node at {host}:{port} rejected request: "
              f"{response.get('error', 'unknown error')}", file=sys.stderr)
        sys.exit(1)

    info = response["result"]
    print(f"=== Connected to {host}:{port} ===\n")
    # Surface the fields a first-run user actually cares about.  Keep
    # the key names literal so scripts can grep for them.
    interesting_keys = (
        "height", "best_hash", "validator_count", "total_supply",
        "block_number", "supply", "sync_status",
    )
    for key in interesting_keys:
        if key in info:
            label = key.replace("_", " ").title()
            print(f"  {label}: {info[key]}")


def cmd_gen_tor_config(args):
    """Print a torrc snippet fronting this validator's RPC with a hidden service.

    Censorship-resistance helper: an operator whose users face IP-level
    blocking can expose their RPC over a Tor hidden service.  We don't
    run Tor - we just print the config fragment.  Operator pipes output
    into their torrc, restarts tor, then shares the generated .onion
    hostname with users.

    Refuses to emit a snippet if --rpc-bind is not a loopback address:
    fronting a public-bound RPC with a hidden service exposes the node
    at both addresses and trivially correlates the .onion to the
    operator's real IP.
    """
    from messagechain.network.tor_config import (
        generate_torrc_snippet,
        InvalidTorBindError,
    )

    try:
        snippet = generate_torrc_snippet(
            rpc_bind_addr=args.rpc_bind,
            rpc_port=args.rpc_port,
            hidden_service_dir=args.hidden_service_dir,
            external_port=args.external_port,
        )
    except InvalidTorBindError as e:
        print(f"Refusing to generate torrc: {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"Invalid argument: {e}", file=sys.stderr)
        sys.exit(2)

    print(snippet)
    print("# Next steps:", file=sys.stderr)
    print("#   1. Append the above to /etc/tor/torrc", file=sys.stderr)
    print("#   2. sudo systemctl restart tor", file=sys.stderr)
    print(f"#   3. Read the .onion hostname from {args.hidden_service_dir.rstrip('/')}/hostname",
          file=sys.stderr)
    print("#   4. Share the hostname with clients in censored networks", file=sys.stderr)


def cmd_migrate_chain_db(args):
    """Run a one-shot schema migration on an existing chain.db.

    Operator-invoked after a binary upgrade whose new schema
    requires rebuilding consensus-visible state surfaces that were
    not persisted under the old binary.  Opens the DB with the
    schema-check bypassed (the only caller allowed to), dispatches
    to the appropriate version-pair migration, prints a summary.

    Refuses to do anything if the DB is already at the target
    schema version -- so accidental double-invocation is a no-op
    rather than a replay-over-replay.
    """
    import os as _os
    from messagechain.storage.chaindb import ChainDB, _SCHEMA_VERSION

    db_path = _os.path.join(args.data_dir, "chain.db")
    if not _os.path.isfile(db_path):
        print(
            f"Error: no chain.db found at {db_path}",
            file=sys.stderr,
        )
        sys.exit(2)

    # Bypass the schema-version tripwire so we can inspect a v1 DB
    # and dispatch to the right migration path.
    db = ChainDB(db_path, skip_schema_check=True)
    cur = db._conn.execute(
        "SELECT value FROM meta WHERE key = ?", ("schema_version",),
    )
    row = cur.fetchone()
    disk_version = int(row[0]) if row else 1

    if disk_version == _SCHEMA_VERSION:
        print(
            f"chain.db at {db_path} is already at schema version "
            f"{disk_version}; nothing to do.",
        )
        return

    if disk_version == 1 and _SCHEMA_VERSION == 2:
        print(
            f"Migrating chain.db at {db_path} from schema v1 to v2 "
            "(replaying block history to rebuild reputation, "
            "key_history, pending_unstakes, stake_snapshots, and "
            "supply_meta counters)...",
        )
        summary = db.migrate_schema_v1_to_v2()
        print("Migration complete.")
        for k, v in summary.items():
            label = k.replace("_", " ").title()
            print(f"  {label}: {v}")
        return

    print(
        f"No migration path defined for schema {disk_version} -> "
        f"{_SCHEMA_VERSION}.  Stop and contact the release manager.",
        file=sys.stderr,
    )
    sys.exit(2)


# ---------------------------------------------------------------------------
# messagechain upgrade
# ---------------------------------------------------------------------------
#
# One-shot validator binary upgrade.  Codifies the manual sequence
# operators were running out of a shell buffer: stop -> backup -> clone tag
# -> swap -> migrate-chain-db -> start -> health-check -> rollback-on-fail.
# Using only stdlib (urllib, subprocess, shutil) keeps the dep graph empty,
# which is an explicit project principle -- operators running this from a
# fresh pip install should not need any third-party packages.

_MAINNET_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)-mainnet$")


def _upgrade_resolve_latest_tag(repo_url: str) -> str:
    """Return the highest-semver `vX.Y.Z-mainnet` git tag on *repo_url*.

    Uses the GitHub git-tags API (``/repos/{owner}/{repo}/tags``), not
    the Releases API.  Plain `git tag` / `git push --tags` creates tags
    but NOT GitHub Release objects -- so the Releases API would return
    only tags that were manually published via the Releases UI, which
    is typically the first one ever and nothing since.  The tags API
    returns every pushed tag regardless of Release-object status, which
    matches the "just push the tag" publishing model this repo uses.

    Filters to canonical mainnet-release tags (``vX.Y.Z-mainnet``),
    parses the semver triple, and returns the highest by
    (major, minor, patch).  Skips prereleases, testnet tags, and any
    tag that doesn't match the canonical pattern.

    Raises RuntimeError on any failure (network, parse, empty result).
    Caller translates to exit(2).
    """
    import json
    import urllib.error
    import urllib.parse
    import urllib.request

    # Parse owner/repo out of a URL like https://github.com/ben-arnao/MessageChain
    parsed = urllib.parse.urlparse(repo_url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise RuntimeError(
            f"cannot parse owner/repo from --repo {repo_url!r}; "
            "pass --tag explicitly to skip API lookup"
        )
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    # per_page=100 covers the first page; mainnet tags are low-volume so
    # paginating is overkill here. If this repo ever accumulates >100
    # tags we can add ?page= walking, but for now a one-shot is simpler.
    api = f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=100"
    req = urllib.request.Request(
        api,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"messagechain/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(
            f"GitHub tags API unreachable ({e}); "
            "rerun with --tag <vX.Y.Z-mainnet> to pin a specific release"
        )
    try:
        data = json.loads(body)
    except ValueError as e:
        raise RuntimeError(f"GitHub API returned non-JSON: {e}")
    if not isinstance(data, list):
        raise RuntimeError(
            "GitHub tags API returned non-list payload; "
            "rerun with --tag <vX.Y.Z-mainnet> to pin a specific release"
        )

    best: tuple[int, int, int] | None = None
    best_name: str | None = None
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        m = _MAINNET_TAG_RE.match(name)
        if m is None:
            continue
        triple = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if best is None or triple > best:
            best = triple
            best_name = name

    if best_name is None:
        raise RuntimeError(
            "no canonical vX.Y.Z-mainnet tags found on GitHub; "
            "rerun with --tag to pin a specific tag"
        )
    return best_name


def _upgrade_tag_to_version(tag: str) -> str:
    """Strip a leading `v` and trailing `-mainnet`/`-testnet` from *tag*.

    Operators tag releases like `v1.2.0-mainnet`; the runtime
    __version__ is `1.2.0`.  Used only for the already-at-target
    shortcut; never for anything consensus-critical.
    """
    v = tag
    if v.startswith("v") or v.startswith("V"):
        v = v[1:]
    for suffix in ("-mainnet", "-testnet", "-rc1", "-rc2", "-rc3"):
        if v.endswith(suffix):
            v = v[: -len(suffix)]
            break
    return v


def _upgrade_health_check(host: str, port: int, timeout_s: int = 60) -> bool:
    """Poll local RPC for GREEN.  Returns True on first healthy
    response, False after *timeout_s* seconds without one.
    """
    import time as _time_hc
    from client import rpc_call

    deadline = _time_hc.monotonic() + timeout_s
    while _time_hc.monotonic() < deadline:
        try:
            resp = rpc_call(host, port, "get_chain_info", {})
        except Exception:
            resp = {"ok": False}
        if resp.get("ok"):
            info = resp.get("result") or {}
            # GREEN = reachable + not reporting a stalled sync.  We do
            # NOT require "idle" here -- a just-started node may be in
            # syncing_headers legitimately; for upgrade health, the
            # important invariant is "RPC is up and returning real
            # chain-info without error".
            if "height" in info:
                return True
        _time_hc.sleep(10)
    return False


def cmd_upgrade(args):
    """Run the full validator binary-upgrade flow.

    See subparser help for flags.  Exits non-zero on any step failure.
    """
    import datetime as _dt
    import shutil
    import subprocess

    from messagechain import __version__ as _current_version

    def _say(msg: str) -> None:
        print(f"==> {msg}", flush=True)

    def _fail(msg: str, code: int = 2) -> None:
        print(f"ERROR: {msg}", file=sys.stderr, flush=True)
        sys.exit(code)

    # --- Preflight ---
    if shutil.which("git") is None:
        _fail(
            "git not found on PATH. Install with your distro package "
            "manager (e.g. `apt install git` or `dnf install git`)."
        )
    if shutil.which("systemctl") is None:
        _fail(
            "systemctl not found on PATH. This upgrade command only "
            "supports systemd-managed services."
        )
    # Root check (skip on non-POSIX: geteuid doesn't exist on Windows).
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        _fail(
            "this command must run as root (systemctl stop/start + "
            "chown). Re-run with `sudo messagechain upgrade ...`."
        )

    # Resolve target tag.
    target_tag = args.tag
    if target_tag is None:
        _say("Resolving latest release tag from GitHub...")
        try:
            target_tag = _upgrade_resolve_latest_tag(args.repo)
        except RuntimeError as e:
            _fail(str(e))
        _say(f"Latest release: {target_tag}")
    else:
        _say(f"Target tag (pinned): {target_tag}")

    target_version = _upgrade_tag_to_version(target_tag)
    if target_version == _current_version:
        _say(
            f"Already at {_current_version}; nothing to do."
        )
        return

    # Downgrade gate.  Only meaningful if versions parse cleanly; if
    # not, fall through (rare tag format -- let operator see the mismatch
    # in the summary prompt).
    def _parse_ver(v: str):
        try:
            return tuple(int(x) for x in v.split("."))
        except Exception:
            return None
    cur = _parse_ver(_current_version)
    tgt = _parse_ver(target_version)
    is_downgrade = cur is not None and tgt is not None and tgt < cur
    if is_downgrade and not args.yes:
        _fail(
            f"target version {target_version} is older than running "
            f"version {_current_version}. Re-run with --yes to "
            "force a downgrade."
        )

    # Confirmation prompt.
    if not args.yes:
        print()
        print("  Upgrade summary:")
        print(f"    current version : {_current_version}")
        print(f"    target tag      : {target_tag}  ({target_version})")
        print(f"    service         : {args.service}")
        print(f"    install dir     : {args.install_dir}")
        print(f"    data dir        : {args.data_dir}")
        print(f"    repo            : {args.repo}")
        print(f"    rollback on fail: {'no' if args.no_rollback else 'yes'}")
        print(f"    skip migrate    : {'yes' if args.skip_migrate else 'no'}")
        print()
        try:
            reply = input("  Proceed? [y/N] ").strip().lower()
        except EOFError:
            reply = ""
        if reply not in ("y", "yes"):
            _say("Aborted by operator.")
            return

    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = f"{args.install_dir}.bak-{ts}"
    clone_dir = f"/tmp/mc-release-{ts}"

    # --- Stop service ---
    _say(f"Stopping {args.service}...")
    try:
        subprocess.run(
            ["systemctl", "stop", args.service], check=True,
        )
    except subprocess.CalledProcessError as e:
        _fail(f"systemctl stop failed: {e}")
    # reset-failed is best-effort; a clean stop won't need it.
    subprocess.run(
        ["systemctl", "reset-failed", args.service], check=False,
    )

    # --- Backup ---
    _say(f"Backing up {args.install_dir} -> {backup_dir}")
    try:
        shutil.move(args.install_dir, backup_dir)
    except Exception as e:
        # Restart service so we don't leave the node down on a mistake.
        subprocess.run(
            ["systemctl", "start", args.service], check=False,
        )
        _fail(f"backup move failed: {e}")

    def _restore_backup_and_start() -> None:
        """Best-effort rollback: remove any partial install, move the
        backup back, restart service.  Swallows exceptions so the
        outer failure reason is what the operator sees.
        """
        try:
            if os.path.exists(args.install_dir):
                shutil.rmtree(args.install_dir)
        except Exception:
            pass
        try:
            shutil.move(backup_dir, args.install_dir)
        except Exception:
            pass
        subprocess.run(
            ["systemctl", "start", args.service], check=False,
        )

    # --- Fetch tag ---
    _say(f"Cloning {args.repo} @ {target_tag} -> {clone_dir}")
    clone_cmd = [
        "git", "clone", "--depth", "1", "--branch", target_tag,
        args.repo, clone_dir,
    ]
    try:
        subprocess.run(clone_cmd, check=True)
    except subprocess.CalledProcessError as e:
        _restore_backup_and_start()
        _fail(
            f"git clone failed ({e}); backup restored and service "
            "restarted."
        )

    # --- Swap ---
    _say(f"Installing new code -> {args.install_dir}")
    try:
        shutil.copytree(clone_dir, args.install_dir)
    except Exception as e:
        _restore_backup_and_start()
        _fail(f"copytree failed: {e}; backup restored.")
    # chown to service user.
    try:
        subprocess.run(
            ["chown", "-R", args.service_user, args.install_dir],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        _restore_backup_and_start()
        _fail(f"chown failed: {e}; backup restored.")

    # --- Migrate chain.db ---
    if not args.skip_migrate:
        _say(
            f"Running migrate-chain-db (idempotent) on {args.data_dir}"
        )
        try:
            subprocess.run(
                [
                    sys.executable, "-m", "messagechain",
                    "migrate-chain-db", "--data-dir", args.data_dir,
                ],
                cwd=args.install_dir,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            _restore_backup_and_start()
            _fail(
                f"migrate-chain-db failed: {e}; backup restored."
            )
    else:
        _say("Skipping migrate-chain-db (--skip-migrate).")

    # --- Start service ---
    _say(f"Starting {args.service}...")
    try:
        subprocess.run(
            ["systemctl", "start", args.service], check=True,
        )
    except subprocess.CalledProcessError as e:
        _restore_backup_and_start()
        _fail(f"systemctl start failed: {e}; backup restored.")

    # --- Health check ---
    _say(
        f"Polling RPC {args.rpc_host}:{args.rpc_port} for up to 60s..."
    )
    healthy = _upgrade_health_check(
        args.rpc_host, args.rpc_port, timeout_s=60,
    )
    if not healthy:
        if args.no_rollback:
            _fail(
                "health check failed after 60s, but --no-rollback is "
                f"set. New code left in place. To revert by hand: "
                f"systemctl stop {args.service} && rm -rf "
                f"{args.install_dir} && mv {backup_dir} "
                f"{args.install_dir} && systemctl start {args.service}",
            )
        _say("Health check FAILED. Rolling back to backup...")
        subprocess.run(
            ["systemctl", "stop", args.service], check=False,
        )
        try:
            shutil.rmtree(args.install_dir)
        except Exception:
            pass
        try:
            shutil.move(backup_dir, args.install_dir)
        except Exception as e:
            _fail(
                f"rollback move failed: {e}. Install state is "
                f"broken; backup still at {backup_dir}."
            )
        subprocess.run(
            ["systemctl", "start", args.service], check=False,
        )
        # Short confirmation poll after rollback (10s).
        if _upgrade_health_check(
            args.rpc_host, args.rpc_port, timeout_s=10,
        ):
            _say(f"Rolled back to backup at {backup_dir}.")
            _fail("upgrade failed; rollback succeeded.")
        _fail(
            f"rollback may be incomplete; backup at {backup_dir} -- "
            "inspect by hand."
        )

    # --- Success ---
    _say(
        f"Upgrade complete. Version {target_version} active on "
        f"service {args.service}. Backup preserved at {backup_dir}."
    )


def cmd_init(args):
    """Operator setup: keyfile + data-dir + onboard.toml + systemd units."""
    from messagechain.runtime import onboarding as _ob

    plan = _ob.plan_init(
        data_dir=getattr(args, "init_data_dir", None) or getattr(args, "data_dir", None),
        keyfile=getattr(args, "keyfile", None),
        systemd=getattr(args, "systemd", None),
        auto_upgrade=getattr(args, "auto_upgrade", True),
        auto_rotate=getattr(args, "auto_rotate", True),
        print_only=getattr(args, "print_only", False),
    )

    if getattr(args, "print_only", False):
        print("=== init (dry-run) ===\n")
        print(f"  data_dir:       {plan.data_dir}")
        print(f"  keyfile:        {plan.keyfile}")
        print(f"  onboard_config: {plan.onboard_config}")
        print(f"  entity_id_hex:  {plan.entity_id_hex or '(will generate)'}")
        print(f"  auto_upgrade:   {plan.auto_upgrade}")
        print(f"  auto_rotate:    {plan.auto_rotate}")
        print(f"  systemd:        {plan.systemd}")
        if plan.systemd_units:
            print("\n  systemd units to write:")
            for path in plan.systemd_units:
                print(f"    {path}")
        print()
        print(plan.next_steps_text())
        return

    from messagechain.config import MERKLE_TREE_HEIGHT
    print("Generating signing key tree (this can take a while at "
          f"MERKLE_TREE_HEIGHT={MERKLE_TREE_HEIGHT})...")
    progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Building key tree")
    _ob.apply_init(plan, progress=progress)
    print()
    print(plan.next_steps_text())


def cmd_doctor(args):
    """Preflight checks. Exit 0 green / 1 yellow / 2 red."""
    from messagechain.runtime import onboarding as _ob

    cfg = _ob.read_onboard_config()
    ddir = getattr(args, "doctor_data_dir", None) or getattr(args, "data_dir", None)
    worst, checks = _ob.run_doctor(
        cfg,
        data_dir=ddir,
        check_timers=getattr(args, "check_timers", False),
    )
    print("=== doctor ===\n")
    for c in checks:
        tag = {0: "OK  ", 1: "WARN", 2: "FAIL"}[c.level]
        line = f"  [{tag}] {c.label}: {c.status}"
        if c.detail:
            line += f" - {c.detail}"
        print(line)
    print()
    verdict = {0: "GREEN", 1: "YELLOW (warnings)", 2: "RED (blocking)"}[worst]
    print(f"  Result: {verdict}")
    sys.exit(worst)


def cmd_rotate_key_if_needed(args):
    """Daily watchdog: rotate when the leaf watermark is >= 95%."""
    from messagechain.runtime import onboarding as _ob
    from messagechain.config import MERKLE_TREE_HEIGHT

    cfg = _ob.read_onboard_config()
    entity_hex = cfg.get("entity_id_hex", "")
    if not entity_hex:
        print("rotate-key-if-needed: entity_id_hex not in onboard.toml; run `messagechain init` first")
        sys.exit(1)

    host, port = _parse_server(getattr(args, "server", None))
    from client import rpc_call

    def fetcher() -> int:
        r = rpc_call(host, port, "get_leaf_watermark", {"entity_id": entity_hex})
        if not r.get("ok"):
            raise RuntimeError(r.get("error", "rpc error"))
        return int(r["result"].get("leaf_watermark", 0))

    def get_tree_height() -> int:
        # Prefer chain-reported tree height; fall back to config.
        r = rpc_call(host, port, "get_entity", {"entity_id": entity_hex})
        if r.get("ok"):
            h = r["result"].get("tree_height")
            if isinstance(h, int) and h > 0:
                return h
        return MERKLE_TREE_HEIGHT

    def has_cold_key() -> bool:
        r = rpc_call(host, port, "get_authority_key", {"entity_id": entity_hex})
        if not r.get("ok"):
            return False
        auth = r["result"].get("authority_pubkey")
        own = r["result"].get("public_key")
        return bool(auth) and auth != own

    tree_height = get_tree_height()
    cold = has_cold_key()

    def rotate_now():
        # Delegate to the existing rotate-key command. Build a minimal
        # namespace so cmd_rotate_key can reuse the same interactive
        # flags (--yes, --server). Prefer the keyfile listed in
        # onboard.toml so the timer unit can run unattended.
        import argparse as _ap
        kf = getattr(args, "keyfile", None) or cfg.get("keyfile") or None
        ns = _ap.Namespace(
            server=args.server, yes=True, fee=None, keyfile=kf,
        )
        cmd_rotate_key(ns)

    rc = _ob.run_rotate_if_needed(
        watermark_fetcher=fetcher,
        has_cold_authority_key=cold,
        tree_height=tree_height,
        rotate_impl=rotate_now,
    )
    sys.exit(rc)


def cmd_config(args):
    """Read or write onboard.toml flags."""
    from messagechain.runtime import onboarding as _ob

    action = getattr(args, "config_action", None)
    key = args.key
    try:
        if action == "get":
            print(_ob.config_get(key))
        elif action == "set":
            path = _ob.config_set(key, args.value)
            print(f"wrote {key} to {path}")
        else:
            print("unknown action")
            sys.exit(2)
    except KeyError as e:
        print(f"Error: {e}")
        sys.exit(2)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(2)


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
        "send-multi": cmd_send_multi_submit,
        "transfer": cmd_transfer,
        "balance": cmd_balance,
        "stake": cmd_stake,
        "unstake": cmd_unstake,
        "set-authority-key": cmd_set_authority_key,
        "bootstrap-seed": cmd_bootstrap_seed,
        "emergency-revoke": cmd_emergency_revoke,
        "rotate-key": cmd_rotate_key,
        "key-status": cmd_key_status,
        "propose": cmd_propose,
        "vote": cmd_vote,
        "generate-key": cmd_generate_key,
        "verify-key": cmd_verify_key,
        "read": cmd_read,
        "info": cmd_info,
        "release-status": cmd_release_status,
        "status": cmd_status,
        "proposals": cmd_proposals,
        "validators": cmd_validators,
        "peers": cmd_peers,
        "cut-checkpoint": cmd_cut_checkpoint,
        "estimate-fee": cmd_estimate_fee,
        "ping": cmd_ping,
        "gen-tor-config": cmd_gen_tor_config,
        "migrate-chain-db": cmd_migrate_chain_db,
        "upgrade": cmd_upgrade,
        "init": cmd_init,
        "doctor": cmd_doctor,
        "rotate-key-if-needed": cmd_rotate_key_if_needed,
        "config": cmd_config,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
