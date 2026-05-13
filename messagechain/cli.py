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
from messagechain.config import DEFAULT_PORT, MAX_MESSAGE_CHARS, PUBLIC_FEED_URL


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
    start.add_argument(
        "--accept-leaf-reuse-risk", action="store_true",
        help="Bypass the leaf-index gate that catches the keyfile-"
             "without-cursor restore disaster.  Set ONLY after manually "
             "verifying the local cursor matches or exceeds every leaf "
             "the chain has on record for this entity.  Otherwise the "
             "first sign re-uses a burned leaf -> 100% slash for "
             "equivocation evidence.",
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
    start.add_argument(
        "--state-drift-check-interval", type=int, default=100,
        help="Run the in-memory vs on-disk state-drift tripwire every "
             "N successfully-added blocks (default 100, 0 disables).  "
             "Catches the validator-2-style silent divergence that "
             "previously surfaced only as a struct.error overflow in "
             "compute_post_state_root.",
    )
    start.add_argument(
        "--state-drift-on-detect", choices=("log", "crash"), default="log",
        help="Response when the periodic drift tripwire finds divergent "
             "records.  'log' (default) records an ERROR-level entry "
             "with the full record list and bumps a counter; the next "
             "clean restart will repull state from disk and converge.  "
             "'crash' raises so systemd restarts the node immediately "
             "for a clean reload -- faster fix, more disruptive.",
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
    send.add_argument(
        "--prev", type=str, default=None, metavar="TX_HASH",
        help=(
            "Optional 64-hex-char tx_hash this message references as "
            "its predecessor (reply, chained document, citation, etc). "
            "The referenced tx must already be on-chain in a strictly "
            "earlier block. Adds 33 bytes to the fee basis; does not "
            "count against the 1024-char cap. Activates at "
            "PREV_POINTER_HEIGHT."
        ),
    )
    send.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness (target_blocks rung in the "
             "percentile estimator).  high = ~1 block, normal = ~3 "
             "blocks (default), low = ~10 blocks.  Ignored when "
             "--fee is set.",
    )
    send.add_argument(
        "--community-id", dest="community_id", type=str, default=None,
        metavar="NAME",
        help=(
            "Tag the message with a community handle (Reddit-style "
            "topic grouping).  Short ASCII handle: 1-32 chars from "
            "[a-z0-9_-], first/last char in [a-z0-9].  Input is "
            "NFC-normalized and lowercased before submission.  "
            "Activates at COMMUNITY_ID_HEIGHT."
        ),
    )
    send.add_argument(
        "--poll-option", dest="poll_options",
        action="append", default=[],
        metavar="TEXT",
        help=(
            "Make this message a structured poll.  Repeat 1..4 times "
            "with the option label text (e.g. --poll-option Yes "
            "--poll-option No).  Each option is short UTF-8 (<=32 "
            "bytes) and follows the same charset whitelist as message "
            "text.  Options must be pairwise distinct.  Mutually "
            "exclusive with --vote-target.  Activates at POLL_HEIGHT."
        ),
    )
    send.add_argument(
        "--vote-target", dest="vote_target", type=str, default=None,
        metavar="POLL_TXID:INDEX",
        help=(
            "Make this message a structured vote.  Format: "
            "64-hex-char poll tx_hash, colon, decimal option index "
            "(0-based).  The poll must already be on-chain in a "
            "strictly earlier block, and the index must be in range "
            "of that poll's option set.  An entity may cast at most "
            "one vote per poll.  An entity cannot vote on a poll it "
            "created.  Mutually exclusive with --poll-option.  "
            "Activates at POLL_HEIGHT."
        ),
    )

    # --- send-multi ---
    send_multi = sub.add_parser(
        "send-multi",
        help="Send a message via multi-validator HTTPS fan-out",
        description=(
            "Censorship-resistant submission: POST the signed tx in "
            "parallel to N>=3 validator HTTPS endpoints. Receipts are "
            "persisted under --receipts-dir for later evidence use.\n"
            "\n"
            "Requires --keyfile (the GLOBAL flag, defined on the "
            "top-level parser) pointing at your wallet file -- the "
            "same one ``messagechain generate-key`` writes.  Mnemonic, "
            "checksummed hex, and raw hex are all accepted; the CLI "
            "will prompt interactively if --keyfile is omitted and "
            "no auto-pickup is available."
        ),
    )
    send_multi.add_argument("message", type=str, help="Message text (1024 chars max)")
    send_multi.add_argument(
        "--fee", type=int, default=None,
        help="Transaction fee in tokens (auto-priced via --server if omitted)",
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
        "--server", type=str, default=None,
        help=(
            "host:port of a JSON-RPC node for chain-state queries "
            "(nonce, leaf watermark, fee estimate).  Defaults to your "
            "local node.  The fan-out --endpoint set is independent "
            "and unaffected; --server only sources the auto-defaults "
            "below.  For maximum trust-minimisation, point this at "
            "your own node."
        ),
    )
    send_multi.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness (ignored when --fee is set)",
    )
    send_multi.add_argument(
        "--nonce", type=int, default=None,
        help=(
            "Tx nonce.  Auto-resolved via --server's get_nonce RPC "
            "when omitted (the safe default)."
        ),
    )
    send_multi.add_argument(
        "--leaf-index", dest="leaf_index", type=int, default=None,
        help=(
            "WOTS+ signing leaf.  Auto-resolved to the chain's "
            "leaf_watermark via --server when omitted (the safe "
            "default).  The on-disk per-entity cursor independently "
            "floors this so two consecutive runs cannot reuse the "
            "same leaf even on a fresh machine."
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
    transfer.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness.  See `send --urgency`.  Ignored "
             "when --fee is set.",
    )
    transfer.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )

    # --- balance ---
    balance = sub.add_parser(
        "balance",
        help="Check your balance",
        description="Show your account balance, staked amount, and nonce.",
    )
    balance.add_argument("--server", type=str, default=None, help="Server address host:port")
    # Read-only lookup paths so a user can check a balance with no
    # private-key access at all.  Address (mc1...) is the human-paste
    # form; --entity-id keeps the legacy 64-char hex form working for
    # tooling.  When either is set we skip the personal-wallet cache
    # / Entity.create round-trip entirely and just do the RPC.
    balance.add_argument(
        "--address", type=str, default=None,
        help="Look up an address (mc1...) WITHOUT prompting for a "
             "private key. Useful before you have a wallet, or for "
             "checking somebody else's balance.",
    )
    balance.add_argument(
        "--entity-id", type=str, default=None,
        help="Look up by raw entity ID hex (64 chars). Same read-only "
             "behavior as --address, kept for legacy tooling.",
    )

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
    stake.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness.  See `send --urgency`.  Ignored "
             "when --fee is set.",
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
    unstake.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness.  See `send --urgency`.  Ignored "
             "when --fee is set.",
    )
    unstake.add_argument(
        "--cold-keyfile", type=str, default=None,
        help="Path to the cold authority private-key file.  Required "
             "when this entity has promoted a cold authority key via "
             "`set-authority-key` -- the chain rejects unstake "
             "transactions signed by the hot key in that case.  The "
             "file may contain raw bytes or hex-encoded private key "
             "(same format as `set-authority-key --cold-key-path`).",
    )
    unstake.add_argument(
        "--cold-leaf", type=int, default=0,
        help="Cold-key leaf index to sign at.  Cold-key WOTS+ leaf "
             "state is NOT tracked on chain; the operator self-tracks. "
             "Pass --cold-leaf N+1 on each subsequent cold-key signing "
             "(SetAuthorityKey rebind / SetReceiptSubtreeRoot / unstake) "
             "where N is the previously-burned leaf.  Mirrors "
             "`set-receipt-subtree-root --cold-leaf`.",
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
        "--cold-key-path", type=str, default=None,
        help="Path to the EXISTING cold private-key file (required only "
             "when re-binding an already-installed authority key -- Tier 46. "
             "First-time install: omit. The file may contain raw bytes or "
             "a hex-encoded private key.",
    )
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
    rotate.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness.  See `send --urgency`.  Ignored "
             "when --fee is set.",
    )

    # --- key-status ---
    key_status = sub.add_parser(
        "key-status",
        help="Show current key state, leaf usage, and rotation number",
    )
    key_status.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334 -- "
             "queries YOUR local node for YOUR entity's leaf watermark)",
    )
    # Read-only lookup paths -- same shape as balance.  Skips the
    # personal-wallet cache / Entity.create roundtrip entirely.
    key_status.add_argument(
        "--address", type=str, default=None,
        help="Look up an address (mc1...) WITHOUT prompting for a "
             "private key.",
    )
    key_status.add_argument(
        "--entity-id", type=str, default=None,
        help="Look up by raw entity ID hex (64 chars). Same read-only "
             "behavior as --address.",
    )

    # --- set-receipt-subtree-root ---
    set_root = sub.add_parser(
        "set-receipt-subtree-root",
        help="Register this validator's receipt-subtree root on-chain "
             "(cold key required)",
        description=(
            "Publish the WOTS+ root that verifies this validator's "
            "submission receipts. Cold-key signed: a compromised hot "
            "key must not be able to swap the receipting identity. "
            "Run from a host that holds the cold authority key. By "
            "default the local root is fetched from the running "
            "validator at --server (no need to copy roots out of logs); "
            "pass --root <hex> to skip the fetch in a fully air-gapped "
            "flow. Until this tx lands, receipts issued by this "
            "validator fail verification at evidence-admission time, "
            "which collapses the censorship-evidence pipeline for "
            "anyone receipting through this node."
        ),
    )
    set_root.add_argument(
        "--server", type=str, default=None,
        help="Validator host:port to fetch the local root from and "
             "broadcast through (default: 127.0.0.1:9334).",
    )
    set_root.add_argument(
        "--root", type=str, default=None,
        help="Receipt-subtree root public key as hex (32 bytes). "
             "Skips the get_local_receipt_root RPC fetch -- use for "
             "air-gapped signing where the operator copied the root "
             "out of band.",
    )
    set_root.add_argument(
        "--entity-id", type=str, default=None,
        help="Validator entity ID (hex). Defaults to the entity derived "
             "from the cold key in --keyfile.",
    )
    set_root.add_argument(
        "--fee", type=int, default=None, help="Transaction fee",
    )
    set_root.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )
    set_root.add_argument(
        "--print-tx", action="store_true",
        help="Print the signed tx as JSON to stdout instead of "
             "broadcasting. Pair with --root and --entity-id for an "
             "air-gapped sign-on-cold, broadcast-on-hot workflow.",
    )
    set_root.add_argument(
        "--cold-leaf", type=int, default=0, metavar="N",
        help="WOTS+ leaf index to sign with on the cold key. Default 0 "
             "(first ever use). Each cold-key signing burns one leaf, "
             "and signing two different messages with the same leaf is "
             "a WOTS+ key-reuse vulnerability that the chain rejects. "
             "Cold-key leaf state is not tracked on-chain (the chain "
             "only updates hot-key watermarks), so the operator must "
             "advance this manually across multiple uses of the same "
             "cold key. Tree height is 8 (256 leaves total) by default, "
             "which is plenty for a validator's lifetime of authority "
             "operations.",
    )

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
    revoke.add_argument(
        "--print-only", action="store_true",
        help=(
            "Build and sign the revoke locally, print the tx as hex on "
            "stdout, and DO NOT broadcast.  Intended for the offline "
            "pre-sign workflow: run on an air-gapped machine with the "
            "cold key, save the printed hex offline, then broadcast "
            "later with `messagechain broadcast-revoke --hex <bytes>`.  "
            "Skips the RPC tip probe and the confirmation prompt so "
            "this works fully offline."
        ),
    )
    revoke.add_argument(
        "--valid-for-blocks", type=int, default=None,
        help=(
            "Tier 26: width of the chain-height window the signed "
            "revoke is valid in.  Default 13140 blocks (~90 days at "
            "600s/block) -- the recommended quarterly cold-key re-sign "
            "cadence.  A leaked pre-signed hex expires within this "
            "many blocks of its valid_to_height, bounding the bearer-"
            "replay attack surface.  Pre-fork (height < "
            "REVOKE_TX_WINDOW_HEIGHT) the window is still emitted but "
            "not enforced by the chain, so upgrading the CLI ahead of "
            "the fork is safe."
        ),
    )

    # --- broadcast-revoke ---
    bcast = sub.add_parser(
        "broadcast-revoke",
        help="Broadcast a pre-signed revoke tx (companion to --print-only)",
        description=(
            "Submit a revoke tx that was previously built and signed via "
            "`emergency-revoke --print-only`.  Reads the hex blob, parses "
            "it as a RevokeTransaction, and submits it via the standard "
            "emergency_revoke RPC path.  Use this when the pre-signed "
            "kill-switch needs to fire: scan the QR / type the hex, "
            "broadcast, the validator is disabled the next block."
        ),
    )
    bcast_src = bcast.add_mutually_exclusive_group(required=True)
    bcast_src.add_argument(
        "--hex", dest="tx_hex", type=str, default=None,
        help="Hex string of the serialized revoke tx (from --print-only).",
    )
    bcast_src.add_argument(
        "--file", dest="tx_file", type=str, default=None,
        help="Path to a file containing the hex blob (whitespace ignored).",
    )
    bcast.add_argument(
        "--server", type=str, default=None, help="Server address host:port",
    )
    bcast.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt before broadcasting.",
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
    propose.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness.  See `send --urgency`.  Ignored "
             "when --fee is set.",
    )
    # Governance proposals charge the largest single fee in the
    # protocol (GOVERNANCE_PROPOSAL_FEE = 10,000 tokens) and a typo on
    # title/description is an irreversible burn.  --yes / -y is the
    # script-friendly path that skips the interactive confirm; mirrors
    # cmd_transfer's --yes (1.48.0).
    propose.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt (for scripts / CI).",
    )

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
    vote.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness.  See `send --urgency`.  Ignored "
             "when --fee is set.",
    )

    # --- react ---
    react = sub.add_parser(
        "react",
        help="React (up/down/clear) to a message or user",
        description=(
            "Cast a signed reaction vote against a message tx_hash "
            "(default) or another entity_id (--target-type user).  "
            "Each (voter, target) pair has a single latest choice on "
            "chain; submitting again with --choice clear retracts the "
            "prior vote.  Self-trust votes are rejected; reacting to "
            "your own message is allowed."
        ),
    )
    react.add_argument(
        "target", type=str,
        help="64-hex-char target (message tx_hash by default, or "
             "entity_id when --target-type=user)",
    )
    react.add_argument(
        "--choice", choices=("up", "down", "clear"), required=True,
        help="up = +1, down = -1, clear = retract prior vote",
    )
    react.add_argument(
        "--target-type", dest="target_type",
        choices=("message", "user"), default="message",
        help="message = react to a message tx_hash (default); user = "
             "user-trust vote against an entity_id",
    )
    react.add_argument(
        "--fee", type=int, default=None,
        help="Transaction fee (auto-detected if omitted)",
    )
    react.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334)",
    )
    react.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="Auto-fee aggressiveness.  See `send --urgency`.  Ignored "
             "when --fee is set.",
    )

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
    # Client-side filters - applied to the messages returned by the
    # `get_messages` RPC.  Server-side filter would require a new RPC
    # param; at --last counts that fit one RPC response, client-side
    # filtering is a free win.
    read.add_argument(
        "--community-id", dest="community_id", type=str, default=None,
        help="Show only posts in this Tier 25 community handle",
    )
    read.add_argument(
        "--by-address", dest="by_address", type=str, default=None,
        help="Show only posts from this address (hex or mc1... form)",
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
    peers.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334 -- "
             "queries YOUR local node's peer table)",
    )

    # --- receipt ---
    # The receipt command is the user-visible surface that names the
    # protocol's defining property: slashing-backed permanence.  Without
    # it, `messagechain send` returns a tx hash and ten minutes of
    # nothing -- a user has no way to distinguish "block hasn't mined
    # yet" from "validators colluding".  `messagechain receipt <hash>`
    # closes that gap with a plain-language status that names the
    # guarantee in every code path (included / pending / not-found).
    receipt_p = sub.add_parser(
        "receipt",
        help="Show inclusion + permanence receipt for a tx hash",
        description=(
            "Look up a transaction by hash and print a plain-language "
            "receipt naming its inclusion status and the slashing-backed "
            "permanence guarantee.  Three outcomes:\n"
            "  * INCLUDED  - tx is in a block; receipt names the block, "
            "the attester count, and an inclusion proof.\n"
            "  * PENDING   - tx is in mempool; receipt names the wait "
            "estimate and the submit-evidence escalation if a coerced "
            "validator is suspected.\n"
            "  * NOT FOUND - tx is in neither mempool nor chain; "
            "receipt names the three possible causes.\n"
            "Read-only; never mutates chain state."
        ),
    )
    receipt_p.add_argument(
        "tx_hash", type=str,
        help="32-byte transaction hash in hex (64 hex chars).",
    )
    receipt_p.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port",
    )
    # --cross-check-server is the second-source defense against a
    # colluding primary RPC server: by default the CLI will verify
    # the merkle proof returned by --server against that same
    # server's claimed merkle_root, which leaves a residual
    # "fabricated block" trust gap.  Pinning a second validator
    # here closes that gap -- both servers' merkle_root for the
    # same block_hash MUST agree before the permanence text is
    # printed.  Disagreement surfaces a WARNING.
    receipt_p.add_argument(
        "--cross-check-server", dest="cross_check_server",
        type=str, default=None,
        help="Second validator host:port to cross-check the inclusion "
             "merkle_root against.  When set, both servers must agree on "
             "the merkle_root for the receipt to print the permanence "
             "guarantee.  Without it, the receipt prints a softer "
             "caveat naming this flag as the way to confirm independently.",
    )

    # --- submit-evidence ---
    # The natural next step from a `receipt` that turned up NOT FOUND
    # or stale-PENDING.  Constructs, signs, and submits a real
    # CensorshipEvidenceTx for the most-promised path; the
    # bogus-rejection / non-response variants are accepted at the
    # parser level but currently print a "not yet wired" diagnostic
    # so the receipt CLI's escalation hint always resolves to a real
    # command.
    submit_ev = sub.add_parser(
        "submit-evidence",
        help="Submit slashable censorship evidence for a receipted tx",
        description=(
            "Construct and submit a CensorshipEvidenceTx (or related "
            "evidence type) for a tx whose validator-issued submission "
            "receipt was followed by non-inclusion past "
            "EVIDENCE_INCLUSION_WINDOW.  When matured, the issuing "
            "validator is slashed by CENSORSHIP_SLASH_BPS.  See "
            "messagechain.consensus.censorship_evidence for the "
            "consensus-layer pipeline."
        ),
    )
    submit_ev_sub = submit_ev.add_subparsers(
        dest="evidence_kind",
        # Don't `required=True` so older invocations that pass --tx
        # straight to submit-evidence print a helpful diagnostic
        # instead of an argparse "must choose subcommand" error.
        required=False,
    )

    # The censorship subcommand is the real wiring.
    submit_ev_cens = submit_ev_sub.add_parser(
        "censorship",
        help=(
            "Submit a CensorshipEvidenceTx for a receipt-bundle whose "
            "tx never landed within EVIDENCE_INCLUSION_WINDOW."
        ),
        description=(
            "Reads a receipt bundle (the SubmissionReceipt the "
            "validator returned at submit time + the original "
            "MessageTransaction the receipt covers), confirms the tx "
            "is NOT on chain via get_tx_status, then signs and submits "
            "a CensorshipEvidenceTx.  The accused validator's stake is "
            "slashed by CENSORSHIP_SLASH_BPS once the evidence matures, "
            "unless the receipted tx lands first (which voids the "
            "evidence with no slash)."
        ),
    )
    submit_ev_cens.add_argument(
        "--receipt", type=str, required=True,
        help=(
            "Path to the receipt-bundle JSON file (preferred) "
            "containing both the SubmissionReceipt and the receipted "
            "MessageTransaction.  See `messagechain submit-evidence "
            "censorship --help` for the bundle schema."
        ),
    )
    submit_ev_cens.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port",
    )
    submit_ev_cens.add_argument(
        "--urgency", type=str, default="normal",
        choices=("low", "normal", "high"),
        help=(
            "Auto-fee urgency: 'high' bids the 90th percentile of "
            "recent fees, 'normal' the 75th, 'low' the 25th."
        ),
    )

    # Bogus-rejection -- accepted but not yet wired.
    submit_ev_br = submit_ev_sub.add_parser(
        "bogus-rejection",
        help="(NOT YET WIRED) Submit a BogusRejectionEvidenceTx",
        description=(
            "Submit a BogusRejectionEvidenceTx for a SignedRejection "
            "whose claimed reason is provably false (e.g. "
            "REJECT_INVALID_SIG against a tx whose signature actually "
            "verifies).  This subcommand is a stub: only the "
            "censorship-evidence path is wired in this release.  The "
            "consensus-layer pipeline already exists at "
            "messagechain.consensus.bogus_rejection_evidence."
        ),
    )
    submit_ev_br.add_argument(
        "--rejection", type=str, default=None,
        help="(reserved) Path to a SignedRejection bundle.",
    )

    # Non-response -- accepted but not yet wired.
    submit_ev_nr = submit_ev_sub.add_parser(
        "non-response",
        help="(NOT YET WIRED) Submit a NonResponseEvidenceTx",
        description=(
            "Submit a NonResponseEvidenceTx when a witnessed-submission "
            "request was never acked within "
            "WITNESS_RESPONSE_DEADLINE_BLOCKS.  This subcommand is a "
            "stub: only the censorship-evidence path is wired in this "
            "release.  The consensus-layer pipeline already exists at "
            "messagechain.consensus.non_response_evidence."
        ),
    )
    submit_ev_nr.add_argument(
        "--witness-bundle", dest="witness_bundle",
        type=str, default=None,
        help="(reserved) Path to a witness-submission bundle.",
    )

    # Back-compat: legacy callers passed `--tx <hash>` directly to
    # submit-evidence.  Keep the flag at the top level so an old
    # invocation prints a clear migration message instead of an
    # argparse error.
    submit_ev.add_argument(
        "--tx", dest="tx_hash", type=str, default=None,
        help=argparse.SUPPRESS,
    )
    submit_ev.add_argument(
        "--server", type=str, default=None,
        help=argparse.SUPPRESS,
    )

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
        help="Estimate the fee for a prospective tx (any kind)",
        description=(
            "Query the node for the recommended fee without submitting. "
            "Accepts either the legacy --message / --transfer shortcuts or "
            "the unified --tx-type {message,transfer,stake,unstake,react,"
            "propose,vote,rotate-key} surface, with optional --urgency "
            "{low,normal,high}.  Prints a breakdown so the user can see "
            "why the fee is what it is (protocol minimum, mempool "
            "percentile, total recommended, per-byte rate)."
        ),
    )
    # Either the user names the kind explicitly via --tx-type, or uses
    # one of the two legacy shortcuts (--message TEXT, --transfer).
    # Argparse's mutually_exclusive_group can't model "any one of these
    # three is required" cleanly when the legacy shortcuts also carry
    # payload, so we leave them all optional and validate in
    # cmd_estimate_fee.
    estimate_fee.add_argument("--message", type=str, default=None, help="Message text to price (legacy shortcut for --tx-type message)")
    estimate_fee.add_argument("--transfer", action="store_true", help="Price a funds transfer (legacy shortcut for --tx-type transfer)")
    estimate_fee.add_argument(
        "--tx-type", dest="tx_type", default=None,
        choices=("message", "transfer", "stake", "unstake", "react",
                 "propose", "vote", "rotate-key"),
        help="Tx kind to price.  For 'message' optionally supply "
             "--message TEXT to price the exact byte count; for "
             "'propose' supply --title and --description; other "
             "kinds need no extra payload args.",
    )
    estimate_fee.add_argument(
        "--urgency", choices=("low", "normal", "high"), default="normal",
        help="How aggressively to bid above the floor.  high = ~1 block "
             "(90th percentile), normal = ~3 blocks (75th, default), "
             "low = ~10 blocks (25th).",
    )
    # Optional payload args used by certain --tx-type values; harmless
    # when not relevant.
    estimate_fee.add_argument("--title", type=str, default=None, help="Proposal title (for --tx-type propose)")
    estimate_fee.add_argument("--description", type=str, default=None, help="Proposal description (for --tx-type propose)")
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
    upgrade.add_argument(
        "--lock-path", type=str, default="/run/messagechain-upgrade.lock",
        help="Advisory lock file used to prevent the weekly "
             "auto-upgrade timer and a manual invocation from "
             "running concurrently (default: "
             "/run/messagechain-upgrade.lock).  Use a writable path "
             "on non-systemd hosts.",
    )
    upgrade.add_argument(
        "--no-lock", action="store_true",
        help="Skip the upgrade-contention advisory lock check.  Only "
             "use when recovering from a stale lock file or running "
             "in a container where /run/ is not writable.",
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
    init_p.add_argument(
        "--verify-seed", type=str, default=None, metavar="HOST[:PORT]",
        help="Probe this seed's get_chain_info RPC BEFORE starting "
             "WOTS+ keygen and abort if its chain_id or genesis_hash "
             "disagrees with local config -- catches wrong "
             "MESSAGECHAIN_PROFILE / stale config_local.py before you "
             "spend ~90 min on a keyfile the chain will reject.  "
             "PORT defaults to the RPC port (9334).  Without this "
             "flag, init probes the first reachable entry in "
             "SEED_NODES; network errors log a warning but do not "
             "abort (supports air-gapped / first-validator setups).",
    )
    init_p.add_argument(
        "--skip-verify", action="store_true",
        help="Skip the chain-identity pre-flight probe entirely.  "
             "Use for the first validator on a new chain (no peers "
             "to probe) or air-gapped deployments.",
    )

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
    rotate_if_p.add_argument(
        "--server", type=str, default=None,
        help="Server address host:port (default: 127.0.0.1:9334 -- "
             "the daily timer runs on the validator host and asks "
             "the LOCAL node for OUR entity's watermark)",
    )

    # --- config ---
    config_p = sub.add_parser(
        "config",
        help="Read or write onboard.toml flags",
        description=(
            "`messagechain config get <key>` prints the value; "
            "`messagechain config set <key> <value>` writes it. "
            "Supported keys: auto_upgrade, auto_rotate, data_dir, keyfile, "
            "entity_id_hex, notify.email.enabled, notify.email.recipient, "
            "notify.email.smtp_host, notify.email.smtp_port, "
            "notify.email.smtp_username, notify.email.smtp_password, "
            "notify.email.smtp_starttls."
        ),
    )
    config_sub = config_p.add_subparsers(dest="config_action", required=True)
    config_get_p = config_sub.add_parser("get")
    config_get_p.add_argument("key")
    config_set_p = config_sub.add_parser("set")
    config_set_p.add_argument("key")
    config_set_p.add_argument("value")

    # --- notify-test / notify-status ---
    # --- backup-wallet -------------------------------------------------
    backup = sub.add_parser(
        "backup-wallet",
        help="Offline-signers only: tar keyfile + leaf-cursor into one archive.",
        description=(
            "OFFLINE-SIGNING POWER USERS ONLY.  For online wallets, your "
            "24-word recovery phrase is your backup -- the leaf cursor "
            "is rebuilt from chain state on restore and you do not need "
            "this command.  Use this only if you sign on an air-gapped "
            "machine and broadcast later: in that workflow leaves you've "
            "burned offline aren't visible on chain yet, so the local "
            "~/.messagechain/leaves/<entity_id_hex>.idx cursor is "
            "security-critical between signings.  This command bundles "
            "the keyfile + matching cursor into a single .tar.gz.  "
            "Local-only: never touches the chain or the network."
        ),
    )
    backup.add_argument(
        "--keyfile", type=str, default=None,
        help="Path to the keyfile (defaults to global --keyfile).  Required.",
    )
    backup.add_argument(
        "--leaves", type=str, default=None,
        help="Path to the leaf-cursor file (defaults to "
             "~/.messagechain/leaves/<entity_id_hex>.idx, derived from "
             "--keyfile).",
    )
    backup.add_argument(
        "--receipt-leaves", type=str, default=None,
        dest="receipt_leaves",
        help="Path to the receipt-subtree leaf-cursor "
             "(receipt_leaf_index.json) for validators that issue "
             "submission receipts.  Defaults to "
             "<data_dir>/receipt_leaf_index.json.  Restoring a wallet "
             "without it on a receipt-issuing validator re-uses one-"
             "time WOTS+ leaves on the receipt subtree and produces "
             "equivocation evidence on chain (geometric soft-slash "
             "compounds toward total stake loss).  Pass "
             "--no-receipt-leaves to opt out on validators that do "
             "NOT issue receipts.",
    )
    backup.add_argument(
        "--no-receipt-leaves", action="store_true",
        dest="no_receipt_leaves", default=False,
        help="Opt out of receipt-leaf inclusion (validators that do "
             "NOT issue receipts).  Prints a warning so the choice is "
             "visible in the operator's terminal.",
    )
    backup.add_argument(
        "--entity-id", type=str, default=None, dest="entity_id",
        help="Entity ID hex.  When omitted, derived from --keyfile.",
    )
    backup.add_argument(
        "--output", type=str, default=None,
        help="Output path for the tarball.  Defaults to "
             "<entity_id_hex>-wallet-backup-<YYYYMMDD>.tar.gz in CWD.",
    )

    sub.add_parser(
        "notify-test",
        help="Send a one-shot test email using the configured SMTP creds.",
        description=(
            "Send a one-shot test email using the SMTP credentials in "
            "onboard.toml (notify.email.*). Useful at setup time to "
            "verify the email path works before relying on it for real "
            "governance-proposal notifications."
        ),
    )
    sub.add_parser(
        "notify-status",
        help="Print current notify config (password redacted) + last-sent log.",
        description=(
            "Print the current notify.email.* config (with the SMTP "
            "password redacted) and the most-recent notification "
            "timestamps from the local notify_state.json."
        ),
    )

    # --- ui ---
    # Local wallet UI.  Loopback-only HTTP server that serves the same
    # read views as the public messagechain.org feed plus signing
    # routes for messages, transfers, stake, votes, governance, and key
    # rotation.  See messagechain/network/local_wallet_server.py for
    # the threat model and the four foot-gun defenses (loopback bind,
    # Host-header allowlist, per-session bearer token, no CORS).
    ui = sub.add_parser(
        "ui",
        help="Run the local wallet UI (loopback-only HTTP)",
        description=(
            "Run the local wallet UI: a loopback-only HTTP server that "
            "the user opens in their own browser.  The user's private "
            "key (from --keyfile) is loaded into the wallet-server "
            "process and used to sign transactions; it never reaches "
            "the browser.  Bind is hard-pinned to a literal loopback "
            "IP (127.0.0.1 or ::1) and the server refuses to start on "
            "anything else."
        ),
    )
    ui.add_argument(
        "--port", type=int, default=9335,
        help="Wallet UI port (default: 9335)",
    )
    ui.add_argument(
        "--bind", type=str, default="127.0.0.1",
        help=(
            "Loopback bind address.  Only literal 127.0.0.1 or ::1 "
            "are accepted -- any other value causes startup to fail "
            "(the wallet server exposes signing routes; non-loopback "
            "binds would expose your private key to the network)."
        ),
    )
    ui.add_argument(
        "--server", type=str, default=None,
        help=(
            "host:port of the validator JSON-RPC the wallet UI talks "
            "to for chain reads / nonce / submit_tx.  Defaults to "
            "127.0.0.1:9334 (your local node).  Pointing this at a "
            "remote node shifts read-trust to that operator; signing "
            "is still local."
        ),
    )
    ui.add_argument(
        "--read-only", action="store_true",
        help=(
            "Skip wallet-route registration (no key load, no signing "
            "endpoints).  Useful for browse-only operators who want "
            "the same UI as a logged-in user but with no wallet "
            "affordances."
        ),
    )
    ui.add_argument(
        "--no-browser", action="store_true",
        help="Do not auto-open the printed URL in the system browser.",
    )
    ui.add_argument(
        "--auth-token", type=str, default=None,
        help=(
            "Use a pre-supplied session token instead of generating "
            "a fresh random one.  For testing / scripting only -- the "
            "random default is what you want for normal use."
        ),
    )

    return parser


def resolve_defaults(args: argparse.Namespace) -> argparse.Namespace:
    """Fill in sensible defaults so users don't have to think about config."""
    cmd = args.command

    # Server address: explicit override wins.  Otherwise leave None so
    # _parse_server can run the seed-pick + sqrt(stake) routing.

    # Signing-command ``data_dir`` fallback to onboard.toml.  Same
    # WOTS+ leaf-reuse footgun the 1.57.0 rotate-key-if-needed timer
    # fix (commit c724327) closed, but for the manual signing path:
    # ``messagechain stake`` / ``unstake`` / ``rotate-key`` (and the
    # other signing commands listed in
    # ``_bind_persistent_leaf_index``'s docstring) all read
    # ``getattr(args, "data_dir", None)`` and pass it directly to the
    # leaf-cursor binder.  Without an onboard.toml fallback, an
    # operator running the README's exact validator-bootstrap step
    # (`messagechain stake --amount 200` with no ``--data-dir``)
    # routes the leaf cursor to the per-user fallback at
    # ``~/.messagechain/leaves/<entity>.idx`` while the running
    # validator daemon persists to
    # ``<onboard.data_dir>/leaf_index.json``.  Two cursors with no
    # fsync handshake -- cross-process WOTS+ leaf reuse,
    # equivocation evidence on chain, 100% slash on detection (or
    # geometric soft-slash post-Tier-20).
    #
    # Explicit ``--data-dir`` still wins; this only fires when the
    # operator did not pass one and onboard.toml carries a data_dir
    # value (i.e. the operator ran ``messagechain init`` so the host
    # IS a validator host).  Personal-wallet path with no onboard.toml
    # is unchanged (read_onboard_config returns empty dict, the
    # fallback is a no-op).
    #
    # Set explicitly enumerated rather than "any cmd with the attribute"
    # because the leaf-cursor risk is specific to commands that route
    # through ``_bind_persistent_leaf_index``; non-signing commands
    # that happen to expose ``--data-dir`` (e.g. an inspection tool)
    # should not silently inherit the daemon's data_dir.
    _DATA_DIR_FALLBACK_SIGNING_CMDS = {
        "send", "transfer", "react", "stake", "unstake",
        "rotate-key", "propose", "vote", "set-authority-key",
        "emergency-revoke", "set-receipt-subtree-root",
        "bootstrap-seed", "submit-evidence", "send-multi",
    }
    if (
        cmd in _DATA_DIR_FALLBACK_SIGNING_CMDS
        and getattr(args, "data_dir", None) is None
    ):
        try:
            from messagechain.runtime import onboarding as _ob
            _cfg = _ob.read_onboard_config()
            _ddir = _cfg.get("data_dir")
            if _ddir:
                args.data_dir = _ddir
        except Exception:
            # Best-effort: a corrupt or unreadable onboard.toml is the
            # operator's problem to surface elsewhere; resolve_defaults
            # MUST NOT crash a personal-wallet user who happens to have
            # a malformed config in a parent directory.
            pass

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


def _parse_server_local_default(server_str):
    """Resolve a --server value, defaulting to localhost:RPC_DEFAULT_PORT.

    Use this for OPERATOR-INTROSPECTION commands where the question
    is "what's the state of MY node?" and routing to a remote seed
    would silently return someone else's data.  Concretely:
      * ``status``  -- is MY validator healthy
      * ``peers``   -- who is MY node connected to
      * ``key-status`` -- MY entity's leaf watermark from MY node
      * ``rotate-key-if-needed`` (daily timer on a validator host)

    For wallet / chain-state commands (send, balance, info, read,
    propose, ...), the right default is the seed auto-pick in
    ``_parse_server`` -- a wallet user on a laptop with no local
    node should still be able to submit txs and read chain state.

    Real bug this fixes: pre-fix ``messagechain status`` on a
    validator host probed SEED_NODES and routed to the FIRST
    reachable seed, which on a 2-validator mainnet is the OTHER
    validator.  Operator saw "[OK] rpc reachable: height=284"
    referring to the wrong node and had no way to tell.
    """
    from messagechain.config import RPC_DEFAULT_PORT
    if server_str is not None and server_str != "":
        if ":" in server_str:
            host, port = server_str.rsplit(":", 1)
            return host, int(port)
        return server_str, RPC_DEFAULT_PORT
    return "127.0.0.1", RPC_DEFAULT_PORT


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
    4. Final fallback: localhost:RPC_DEFAULT_PORT (useful for dev).

    Users always retain manual override via `--server`.

    For OPERATOR-INTROSPECTION commands (status / peers / key-status
    / rotate-key-if-needed), use ``_parse_server_local_default``
    instead -- those questions are inherently local and the seed
    auto-pick silently returns the wrong answer.

    Port-default discipline: every callsite of this helper feeds the
    result into a JSON-RPC client (send / transfer / balance / read /
    propose / vote / receipt / ...).  Both the bare-host branch and
    the dev-fallback branch must therefore default to ``RPC_DEFAULT_PORT``
    (9334), NOT the P2P port (9333) -- routing an RPC client to the
    P2P listener succeeds at TCP-connect, mismatches at protocol, and
    surfaces to the user as a generic "Could not connect" with no
    hint the port is wrong.
    """
    from messagechain.config import RPC_DEFAULT_PORT
    if server_str is not None and server_str != "":
        if ":" in server_str:
            host, port = server_str.rsplit(":", 1)
            return host, int(port)
        return server_str, RPC_DEFAULT_PORT

    endpoint = _auto_pick_endpoint()
    if endpoint is not None:
        return endpoint
    # Last-resort dev fallback so a local unconfigured node still works.
    return "127.0.0.1", RPC_DEFAULT_PORT


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


def _format_eta_seconds(seconds: float) -> str:
    """Format a duration in seconds as a human-friendly ETA.

    Kept tiny and deterministic so the progress reporter's output is
    easy to eyeball (``1h23m`` / ``15m42s`` / ``8s``) and the
    accompanying unit tests can assert the exact shape.  Negative or
    infinite inputs map to ``"?"`` -- they only show up in the
    first fraction of a second when rate hasn't stabilized yet.
    """
    import math as _math
    # Catches NaN, +/-inf, negatives, and sub-second values that
    # would round to "0s" and look broken next to a multi-hour job.
    if not _math.isfinite(seconds) or seconds < 1:
        return "?"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h{minutes:02d}m"


def _make_progress_reporter(total_leaves: int, label: str = "Generating key"):
    """Build a progress callback for KeyPair generation.

    At production tree height (20 = 1M leaves), keygen takes 90+
    minutes on a typical VM.  Without feedback operators kill the
    process thinking it hung; with coarse 5% ticks they still see
    ~5 min of silence at startup and have no way to estimate total
    runtime on their hardware.

    This reporter prints a single self-overwriting line to stderr
    with percent, leaves done, current rate (leaves/sec), and a
    running ETA.  Cadence:
      * first tick at leaf 1 (confirms keygen kicked off)
      * 1% increments until 5% (dense early feedback when the
        operator is most anxious)
      * 5% increments after (~20 total updates across the run)
      * forced final tick at 100% followed by a newline

    Returns None if the tree is small enough that progress is
    noise (tests, prototype profile) -- the printing overhead
    would dwarf the keygen itself.
    """
    # Skip for small trees (tests, small configs): the overhead of
    # printing exceeds the wait time.
    if total_leaves < 4096:
        return None

    import time as _time
    # 1% and 5% step sizes; each path gates one cadence regime.
    step_early = max(1, total_leaves // 100)   # 1% increments
    step_steady = max(1, total_leaves // 20)   # 5% increments
    # "next" starts at 1 so the operator sees a ping as soon as
    # the first leaf finishes -- this is the biggest anxiety
    # reducer; first tick arrives within seconds even on a weak VM.
    # base_t / base_done are the rate-window baseline: captured at the
    # FIRST reported tick (not at start) so Python startup / module
    # import / first-leaf overhead don't get folded into the rate
    # average.  Without this, the very first ETA prints something like
    # "391h05m" -- a multi-hundred-hour figure for a ~25s job -- because
    # the elapsed includes ~20s of one-time setup against ~1 leaf done.
    state = {
        "next": 1,
        "done": 0,
        "base_t": None,
        "base_done": 0,
    }

    def report(_leaf_index: int):
        state["done"] += 1
        done = state["done"]
        if done < state["next"] and done != total_leaves:
            return

        now = _time.monotonic()
        if state["base_t"] is None:
            # First reported tick: capture the post-startup baseline
            # but don't print an ETA yet -- we have no rate sample.
            state["base_t"] = now
            state["base_done"] = done
            elapsed_window = 0.0
            rate = 0.0
        else:
            elapsed_window = now - state["base_t"]
            window_done = done - state["base_done"]
            rate = window_done / elapsed_window if elapsed_window > 0 else 0.0
        remaining = total_leaves - done
        eta_sec = remaining / rate if rate > 0 else float("inf")
        pct = 100.0 * done / total_leaves

        # Trailing spaces pad over the previous line in case a
        # longer ETA string ("1h02m") was overwritten by a shorter
        # one ("8s"); without this the stale tail lingers on screen.
        # Rate shows '?' rather than '0' until we have a reliable
        # sample -- '0/s' reads as 'stuck' to a first-time user, '?'
        # reads as 'still calibrating'.  The two co-vary: when rate
        # is unknown the ETA is unknown too.
        rate_str = f"{rate:.0f}/s" if rate > 0 else "?/s"
        print(
            f"\r{label}: {pct:5.1f}% "
            f"({done:,}/{total_leaves:,} leaves) "
            f"[{rate_str}, ETA {_format_eta_seconds(eta_sec)}]     ",
            end="",
            file=sys.stderr,
            flush=True,
        )

        # Cadence switch at 5%: dense early, steady after.
        if pct < 5:
            state["next"] = done + step_early
        else:
            state["next"] = done + step_steady

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
    Cache authenticity is HMAC-verified, so a corrupted or tampered
    cache file can't leak a wrong public key.

    Implementation notes -- this loader deliberately does NOT route
    through ``server._load_or_create_entity`` even though that helper
    knows how to read the cache.  Two side effects of the daemon's
    loader are fatal for the CLI:

      1. On any decode failure it ``os.remove``s the cache file.  If
         this CLI invocation tries the wrong height, an
         HMAC-invalidating bit-flip, or a format-version mismatch, the
         daemon's good cache is silently destroyed -- so the next
         daemon restart also has to regenerate from scratch.  The
         CLI MUST be read-only against the daemon's cache.

      2. On cache hit it calls ``_attach_merkle_node_cache``, which on
         a missing merkle-cache file calls
         ``MerkleNodeCache.build_from_seed`` and re-derives every leaf
         at the tree height -- a multi-minute wedge that completely
         defeats the point of having a fast keypair-cache hit in the
         first place.  The merkle node cache is a sign()-throughput
         optimization for the long-running daemon; a one-shot CLI sign
         just pays the slower auth-path computation and is still
         orders of magnitude faster than rebuilding the cache.

    We therefore call ``decode_keypair_cache`` directly and only bind
    the leaf-index path so persist-before-sign keeps working.

    The on-disk tree_height must match the chain's stored height for
    this entity.  We try the two most plausible heights (the prototype
    /operator-chosen 16 and the compiled-in default), then sweep all
    other plausible WOTS+ heights as a fallback so an operator who
    booted at, say, h=18 still gets a cache hit instead of falling
    through to a fresh ``Entity.create``.  Each probe is a stat() +
    HMAC-verify on hit, both microsecond-cheap.
    """
    import os as _os

    from messagechain.config import (
        MERKLE_TREE_HEIGHT,
        WALLET_DEFAULT_TREE_HEIGHT,
        LEAF_INDEX_FILENAME,
    )
    from messagechain.identity.keypair_cache import (
        decode_keypair_cache,
        keypair_cache_path,
    )

    # Probe the most likely heights first (the compiled-in default and
    # the personal-wallet default), then sweep the rest of the
    # plausible WOTS+ range.  Filename digests differ per height, so a
    # wrong-height probe is a cheap stat() miss -- never an HMAC-fail
    # delete.
    candidate_heights: list[int] = []
    for h in (
        MERKLE_TREE_HEIGHT,
        WALLET_DEFAULT_TREE_HEIGHT,
        16,
        20,
        18,
        14,
        12,
        10,
        8,
        4,
    ):
        if h not in candidate_heights:
            candidate_heights.append(h)

    for height in candidate_heights:
        cache_path = keypair_cache_path(private_key, height, data_dir)
        if not _os.path.exists(cache_path):
            continue
        try:
            with open(cache_path, "rb") as f:
                blob = f.read()
        except OSError:
            continue
        # decode_keypair_cache returns None on any failure (bad MAC,
        # bad magic, wrong height, malformed JSON) -- swallow it here
        # so we keep probing OTHER heights instead of giving up.  And
        # critically: do NOT delete the file on a None return.  The
        # daemon owns this cache; the CLI is a read-only consumer.
        entity = decode_keypair_cache(blob, private_key, height)
        if entity is None:
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


def _read_only_entity_id_hex(args):
    """Return a 64-char entity_id hex when the caller provided one of
    the read-only lookup flags (``--address`` / ``--entity-id``), else
    ``None``.

    Used by RPC-only commands (``balance``, ``key-status``) to skip
    the personal-wallet cache / Entity.create roundtrip entirely when
    the user just wants to look up a published address without
    proving ownership.  No keyfile, no seed phrase, no cache -- just
    "decode the address, send the RPC."

    Validation is strict: an invalid checksum on ``--address`` is a
    fatal error rather than silently falling through to the
    private-key prompt, since the only way that lookup could "work"
    against a typoed address is to query a chain entity that does
    not exist.
    """
    address = getattr(args, "address", None) if args is not None else None
    entity_id = getattr(args, "entity_id", None) if args is not None else None
    if address is None and entity_id is None:
        return None
    if address is not None and entity_id is not None:
        print(
            "Error: pass --address OR --entity-id, not both.",
        )
        sys.exit(1)
    if address is not None:
        from messagechain.identity.address import (
            decode_address,
            InvalidAddressError,
        )
        try:
            entity_id_bytes = decode_address(address)
        except InvalidAddressError as e:
            print(f"Error: invalid --address: {e}")
            sys.exit(1)
        return entity_id_bytes.hex()
    # Raw hex form.
    try:
        entity_id_bytes = bytes.fromhex(entity_id.strip())
    except ValueError as e:
        print(f"Error: invalid --entity-id hex: {e}")
        sys.exit(1)
    if len(entity_id_bytes) != 32:
        print(
            f"Error: --entity-id must decode to 32 bytes, got "
            f"{len(entity_id_bytes)}",
        )
        sys.exit(1)
    return entity_id_bytes.hex()


def _resolve_entity_tree_height(host, port, entity_id_hex):
    """Resolve the per-entity WOTS+ tree_height for display math.

    Mirrors the resolver pattern in ``cmd_rotate_key_if_needed``:
    query ``get_entity`` and read the chain-recorded ``tree_height``;
    fall back to the personal-wallet default when the entity is not
    yet on chain (first-touch state) or the field is absent.

    Personal wallets at h=16 and validators at h=20 coexist on the
    same chain, so a single global constant cannot be correct for
    both.  This helper exists so leaf-usage % displays compute
    against the right denominator instead of hard-coding ``1 << 16``
    or the local ``MERKLE_TREE_HEIGHT`` constant.

    Returns a tuple ``(tree_height, is_fallback)`` where
    ``is_fallback`` is True when the value came from the wallet
    default instead of chain state -- callers can flag the display
    so the operator knows the % is provisional.
    """
    from messagechain.config import WALLET_DEFAULT_TREE_HEIGHT
    from client import rpc_call

    try:
        resp = rpc_call(host, port, "get_entity", {"entity_id": entity_id_hex})
    except Exception:
        return WALLET_DEFAULT_TREE_HEIGHT, True
    if resp.get("ok"):
        h = resp.get("result", {}).get("tree_height")
        if isinstance(h, int) and h > 0:
            return h, False
    return WALLET_DEFAULT_TREE_HEIGHT, True


def _resolve_signing_entity(private_key, args=None, *, tree_height=None):
    """Return an Entity for *private_key*, using whichever cache is available.

    Two paths share the same on-disk cache shape (HMAC-authenticated
    MCKC blob, format from ``messagechain.identity.keypair_cache``):

      * ``--data-dir`` set: the daemon's keypair cache under
        ``<data_dir>/keypair_cache_*.bin`` is reused via
        ``_load_cached_entity``.
      * ``--data-dir`` unset (the README's personal-wallet flow): the
        per-user cache under ``~/.messagechain/wallet_cache/`` is
        reused via ``load_or_create_personal_wallet_entity``.

    Both paths fall through to ``Entity.create`` on cache miss, which
    pays the one-time WOTS+ Merkle keygen cost and writes the cache
    so subsequent invocations are warm.  Without this helper the
    personal-wallet flow regenerates the tree on every command -- a
    ~20-30 minute wedge per signing call at the production tree
    height that makes the README's first-message walkthrough unusable.

    Audit r26 #3: the personal-wallet path also installs a per-leaf
    progress reporter so cold-wallet first signing commands (``send``
    / ``transfer`` / ``stake`` / ``unstake`` / ``react`` / ``propose``
    / ``vote`` / ``submit-evidence`` / ``emergency-revoke`` /
    ``bootstrap-seed``) show the same bar ``generate-key`` shows
    rather than looking frozen for minutes during the one-time
    keygen.  The reporter is forwarded only on the personal-wallet
    branch -- on cache hit it is never invoked, so warm signing
    commands stay silent.  ``_make_progress_reporter`` returns
    ``None`` for small trees (tests, prototype profile) so the test
    suite's reduced ``MERKLE_TREE_HEIGHT`` is unaffected.
    """
    from messagechain.identity.keypair_cache import (
        load_or_create_personal_wallet_entity,
    )
    from messagechain.config import (
        MERKLE_TREE_HEIGHT as _PROD_HEIGHT,
    )
    data_dir = getattr(args, "data_dir", None) if args is not None else None
    if data_dir:
        entity = _load_cached_entity(private_key, data_dir)
        if entity is not None:
            return entity
    # Cap reporter sizing at the height the cache-miss fallback would
    # use.  ``load_or_create_personal_wallet_entity`` probes
    # ``WALLET_DEFAULT_TREE_HEIGHT`` AND ``MERKLE_TREE_HEIGHT`` and
    # falls back to ``MERKLE_TREE_HEIGHT`` on full miss -- sizing the
    # reporter to that upper bound keeps ETA accurate for the worst
    # case.  If a smaller-height cache hits, no keygen runs and the
    # reporter is never invoked.
    effective_height = (
        tree_height if tree_height is not None else _PROD_HEIGHT
    )
    progress = _make_progress_reporter(
        1 << effective_height,
        label="Building wallet keys (one-time)",
    )
    return load_or_create_personal_wallet_entity(
        private_key, tree_height=tree_height, progress=progress,
    )


def _resolve_leaf_index_path(entity_id_hex: str, *, data_dir: str | None = None):
    """Return the on-disk path for this signer's WOTS+ leaf cursor.

    Two paths:
      * ``data_dir`` set (operator/co-resident path): return the
        canonical ``<data_dir>/leaf_index.json`` -- byte-for-byte
        identical to the daemon's leaf-index location.
      * ``data_dir`` unset (end-user CLI): return
        ``~/.messagechain/leaves/<entity_id_hex>.idx``.  Per-entity
        keying lets a single host wallet-juggle without one entity's
        cursor stomping another's.

    Returns a ``pathlib.Path``.  Caller is responsible for ensuring
    the parent directory exists before persistence runs.
    """
    from pathlib import Path
    from messagechain.config import LEAF_INDEX_FILENAME

    if data_dir:
        return Path(data_dir) / LEAF_INDEX_FILENAME
    return Path.home() / ".messagechain" / "leaves" / f"{entity_id_hex}.idx"


def _bind_persistent_leaf_index(
    entity, *, chain_leaf: int, data_dir: str | None,
):
    """Attach a per-wallet leaf-index file and advance to the safe floor.

    The "safe floor" is ``max(on_disk_cursor, chain_leaf)``:

      * If the on-disk cursor is AHEAD of the chain watermark
        (recent same-machine sign that hasn't been gossiped yet), the
        on-disk value wins -- signing at the chain watermark would
        REUSE the leaf we just burned locally.
      * If the chain watermark is AHEAD of the on-disk cursor (this
        machine's file is fresh / lost / new wallet), advance to the
        chain watermark; ``KeyPair.sign``'s persist-before-sign
        ratchet writes the advanced value back to disk before the
        signature escapes the process.

    Once bound, ``entity.keypair.leaf_index_path`` is set so that the
    persist-before-sign hook in ``KeyPair.sign`` writes the post-sign
    cursor back atomically (tmp + rename + parent-dir fsync).

    Returns the resolved path (str-able pathlib.Path) the cursor is
    bound to -- callers don't need it for signing, but tests assert
    on it.

    Note: every CLI signing surface (``cmd_send``, ``cmd_transfer``,
    ``cmd_stake``, ``cmd_unstake``, ``cmd_propose``, ``cmd_vote``,
    ``cmd_rotate_key``, ``cmd_set_authority_key``,
    ``cmd_emergency_revoke``, ``cmd_set_receipt_subtree_root``,
    ``cmd_bootstrap_seed``) MUST route through this helper after
    fetching the chain watermark and BEFORE calling
    ``entity.keypair.sign``.  Skipping it for any of them re-opens
    the cross-process WOTS+ leaf-reuse window the audit closed.
    """
    path = _resolve_leaf_index_path(entity.entity_id_hex, data_dir=data_dir)
    parent = path.parent
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        # Best-effort: if we can't create the parent (read-only fs,
        # permission error), fall back to in-memory-only signing
        # rather than wedging the command.  The daemon's own
        # persistence path remains the safety net for production
        # validators; this guard exists for offline/portable wallet
        # use cases.
        return None

    path_str = str(path)
    try:
        entity.keypair.leaf_index_path = path_str
    except Exception:
        # Non-KeyPair stand-in.  Caller is responsible for re-binding
        # if it cares; tests use a duck-typed shim.
        pass

    # 1. Load the persisted cursor if any.  load_leaf_index never
    #    moves _next_leaf backwards, so this is safe even if the
    #    cursor is already ahead from a previous step.
    try:
        entity.keypair.load_leaf_index(path_str)
    except Exception:
        # A corrupt cursor file is recoverable: the next sign() will
        # rewrite it post-advance.  Don't crash the command.
        pass

    # 2. Advance to the chain watermark.  advance_to_leaf is also
    #    monotonic (max(_next_leaf, leaf_index)) so the higher of the
    #    two floors wins.
    if int(chain_leaf) > 0:
        try:
            entity.keypair.advance_to_leaf(int(chain_leaf))
        except Exception:
            pass

    # 3. First-create hint.  If the cursor file did not exist before
    #    this call, materialize a single stderr line so users know
    #    the file exists -- but DON'T frame it as something they
    #    must back up.  For online wallets the cursor is rebuilt
    #    from chain state on restore (this very helper does that
    #    via chain_leaf above).  The cursor is only security-
    #    critical state for the offline-signing workflow, which the
    #    README's offline-signers section calls out separately.

    return path


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


def _resolve_signing_leaf(
    host, port, entity, *, data_dir, watermark_fallback,
):
    """Atomically reserve a WOTS+ leaf and bind the on-disk cursor.

    Single chokepoint every CLI signing command MUST route through.
    Bypassing this re-opens the cross-process leaf-reuse race window
    that audit r46 #3 closed for ``cmd_send`` / ``cmd_transfer`` /
    ``cmd_stake`` / ``cmd_submit_evidence`` -- a defect-shape audit
    r54 #2 then flagged as still alive on every OTHER signing command
    (cmd_unstake / cmd_rotate_key / cmd_react / cmd_propose /
    cmd_vote / cmd_set_authority_key / cmd_emergency_revoke /
    cmd_set_receipt_subtree_root / cmd_bootstrap_seed /
    cmd_send_multi_submit).

    Strategy:

      1. Try the server-side ``reserve_leaf`` RPC.  This is the
         atomic primitive that prevents the CLI-vs-daemon collision
         where two processes might each pick the same chain watermark
         and each sign a different tx at the same leaf -- publishing
         both signatures discloses the leaf's WOTS+ private chunks
         (100% slash on detection of the disclosure).

      2. If the RPC is unavailable (older daemon, no daemon running,
         standalone-CLI flow), fall back to ``watermark_fallback``
         (typically the ``leaf_watermark`` field the
         ``get_nonce`` / ``get_key_status`` RPC already returned).
         The single-process safety floor is preserved; the cross-
         process race window is the residual hazard the operator
         implicitly accepts by running CLI signing against a daemon
         that doesn't expose the atomic primitive.

      3. Bind the on-disk leaf cursor via
         ``_bind_persistent_leaf_index`` -- closes the same-machine
         residual where two parallel CLI invocations (or one CLI
         plus a daemon without the RPC) might each carry a fresh
         memory view of an earlier sign.

    Returns the resolved leaf index (>= the chain watermark, >= the
    on-disk cursor after bind).

    Note: cold-key signing paths (``cmd_unstake`` /
    ``cmd_set_receipt_subtree_root`` ``--cold-keyfile``) bind a
    cold-key cursor directly without RPC reservation -- the cold key
    is operator-held, not validator-daemon-managed, so the CLI-vs-
    daemon race window doesn't apply.  Those sites continue to call
    ``_bind_persistent_leaf_index`` directly with an operator-
    supplied leaf floor.
    """
    leaf = _reserve_leaf_via_rpc(host, port, entity.entity_id_hex)
    if leaf is None:
        leaf = int(watermark_fallback)
    _bind_persistent_leaf_index(
        entity, chain_leaf=leaf, data_dir=data_dir,
    )
    return leaf


_VALIDATOR_HOT_KEY_DEFAULT_PATH = "/etc/messagechain/keyfile"


def _is_validator_hot_keyfile(path: str) -> bool:
    """Heuristic: does ``path`` name the validator hot-key default?

    The validator daemon writes its hot-signing keyfile to
    ``/etc/messagechain/keyfile`` (root-owned, mode 0600) -- this is
    the path ``default_keyfile()`` returns when running as root, and
    the canonical layout the README's "Run a validator" walkthrough
    bootstraps.  An auto-pick that lands on this path is almost
    certainly about to sign with the validator's identity, which is
    correct for validator-state ops (stake/unstake/rotate-key/etc.)
    but a footgun for personal-wallet ops (send/transfer/react/etc.)
    -- see ``_resolve_private_key`` ``personal_wallet`` rationale.
    """
    try:
        # Use os.path.normpath so a forward-slash literal compares
        # against an OS-normalised auto-pick.  Match exactly (not
        # ``startswith``) -- alternate keyfiles under
        # /etc/messagechain/ MAY be personal (e.g. an operator's
        # personal-wallet keyfile they parked alongside the daemon's).
        return os.path.normpath(path) == os.path.normpath(
            _VALIDATOR_HOT_KEY_DEFAULT_PATH,
        )
    except Exception:
        return False


def _resolve_private_key(args=None, *, personal_wallet=False):
    """Resolve the private key for a signing command.

    Resolution order:
      1. ``args.keyfile`` (operator passed ``--keyfile`` explicitly).
      2. ``onboard.toml.keyfile`` if the file exists.
      3. ``default_keyfile()`` (``/etc/messagechain/keyfile`` for root,
         ``~/.messagechain/keyfile`` for user) if THAT file exists.
      4. Interactive prompt via ``_collect_private_key``.

    This is the single entry point for spending commands - putting the
    branch here means every signing subcommand supports the auto-pickup
    chain for free, enabling unattended/scripted operation without
    requiring the operator to remember ``--keyfile`` on every invocation.

    Anchored in CLAUDE.md "Smart-defaults coverage": when ``init`` has
    written a keyfile and recorded its path in ``onboard.toml``, every
    subsequent signing command should silently use that keyfile rather
    than prompting for the 24-word recovery phrase under sudo (which is
    fragile under piped stdin and routinely captured into shell
    history when typed at a non-TTY-isolated prompt).  Explicit
    ``--keyfile`` always wins; absence-of-onboard-file leaves the
    interactive prompt path unchanged for personal-wallet users who
    haven't opted into a keyfile.

    ``personal_wallet`` (kw-only): when True, the resolver REFUSES to
    auto-pick the validator hot-key default (``/etc/messagechain/
    keyfile``) and falls through to the interactive prompt instead.
    Set by the personal-wallet HARD-GATE command handlers (``send``,
    ``transfer``, ``react``, ``propose``, ``vote``) so that
    ``sudo messagechain transfer ...`` on a validator host does NOT
    silently sign with the validator's identity (which would be a
    fund-loss / identity-attribution footgun).  Validator-state ops
    (``stake``, ``unstake``, ``rotate-key``, ``set-authority-key``,
    etc.) leave the flag at its default of False -- the 1.58.1
    cliff-close (no more 24-word prompt under sudo for the
    validator's own ops) still applies for them, because that's
    exactly the persona it was built for.  Explicit ``--keyfile``
    bypasses the gate (operator's stated intent wins).  Surfaced by
    audit r24 top-3 #2.
    """
    explicit_path = (
        args.keyfile if args is not None and getattr(args, "keyfile", None)
        else None
    )
    keyfile_path = explicit_path
    auto_picked_from = ""

    if keyfile_path is None:
        # Best-effort auto-pickup.  Any failure here (corrupt
        # onboard.toml, IO error, etc.) silently falls through to the
        # interactive prompt - never crash the CLI on a malformed
        # config that's adjacent to a signing command.
        candidate_path = ""
        candidate_source = ""
        try:
            from messagechain.runtime import onboarding as _ob
            try:
                cfg = _ob.read_onboard_config()
            except Exception:
                cfg = {}
            cfg_kf = cfg.get("keyfile") or ""
            if cfg_kf and os.path.exists(cfg_kf):
                candidate_path = cfg_kf
                candidate_source = "onboard.toml"
            else:
                default = _ob.default_keyfile()
                if os.path.exists(default):
                    candidate_path = default
                    candidate_source = "default keyfile"
        except Exception:
            candidate_path = ""

        if candidate_path:
            if personal_wallet and _is_validator_hot_keyfile(candidate_path):
                # Refuse to auto-pick the validator hot-key for a
                # personal-wallet op.  Don't sign with the validator's
                # identity by default; fall through to the interactive
                # prompt instead.  Print one line so the operator sees
                # why -- silent fall-through would re-create the
                # exact "no recovery phrase entered" UX cliff the
                # 1.58.1 fix closed for validator-state ops.
                print(
                    "Refusing to auto-pick validator hot-key "
                    f"({candidate_path}) for a personal-wallet "
                    "command. Pass --keyfile explicitly to use it, "
                    "or supply a personal keyfile / recovery phrase."
                )
            else:
                keyfile_path = candidate_path
                auto_picked_from = candidate_source

    if keyfile_path is None:
        return _collect_private_key()

    # When --data-dir is set, the caller is co-resident with a
    # daemon and the keyfile is almost certainly in daemon raw-hex
    # format.  Opt into the 64-char parser so the CLI can sign
    # with the SAME keyfile the validator unit is using, without
    # needing a parallel checksummed copy of the operator key.
    accept_raw = bool(getattr(args, "data_dir", None) if args is not None else False)
    try:
        key = _load_key_from_file(keyfile_path, accept_raw_hex=accept_raw)
    except KeyFileError as e:
        if explicit_path is not None:
            # Explicit --keyfile that fails to load is a hard error -
            # the operator asked for THIS file, not a fallback.
            print(f"Error: {e}")
            sys.exit(1)
        # Auto-picked path that failed - degrade silently to prompt.
        # The operator may have a stale onboard.toml entry pointing at
        # a moved/deleted keyfile, and the right behavior is to fall
        # through to the interactive prompt rather than refuse to sign.
        return _collect_private_key()
    if auto_picked_from and explicit_path is None:
        print(f"Using keyfile from {auto_picked_from}: {keyfile_path}")
    return key


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


def _print_open_proposals_banner_local(server, entity) -> None:
    """Show a banner if the local node has any open proposals this
    entity hasn't voted on.

    Reads `server.blockchain.governance` directly -- no RPC, no network
    hop. Safe to call from inside `_run` after `server.start()`.

    The function is a no-op for relay-only nodes (entity is None) and
    for any chain where governance state is empty or unloaded.
    """
    if entity is None:
        return
    try:
        from messagechain.runtime import notify as _notify
        proposals = server.blockchain.governance.list_proposals(
            server.blockchain.height, voter_id=entity.entity_id,
        )
    except Exception:
        return
    voted_ids = {
        str(p.get("proposal_id"))
        for p in proposals
        if p.get("voted")
    }
    text = _notify.format_open_proposals_banner(
        proposals=proposals,
        voter_id_hex=entity.entity_id_hex,
        voted_proposal_ids=voted_ids,
    )
    if text:
        print()
        print(text)


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
    # Apply state-drift tripwire flags before the async loop starts so
    # the first periodic fire honours the operator's choice.  The flags
    # default to (100, "log") inside Server.__init__ so an old CLI that
    # doesn't pass them keeps the conservative behaviour.
    if hasattr(args, "state_drift_check_interval"):
        server.state_drift_check_interval = int(
            args.state_drift_check_interval,
        )
    if hasattr(args, "state_drift_on_detect"):
        server.state_drift_on_detect = str(args.state_drift_on_detect)
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
        # Route through the same on-disk keypair cache the daemon uses
        # so a validator restart is a cache HIT (~ms) instead of a
        # full WOTS+ keygen (~20-30 minutes at production tree height).
        # ``server._load_or_create_entity`` writes the cache under
        # ``<data_dir>/keypair_cache_*.bin`` on first run and reads it
        # on every subsequent start; both paths fall through to a
        # fresh ``Entity.create`` on cache miss / corruption so a
        # first-ever start still produces the right entity.
        from server import _load_or_create_entity as _srv_load_entity
        entity = _srv_load_entity(
            private_key, MERKLE_TREE_HEIGHT, args.data_dir,
        )

        # Audit r34 #2: gate the daemon's first signing opportunity on
        # the same leaf-index check `messagechain doctor` runs.  r33 #3
        # surfaced the keyfile-without-cursor restore disaster but
        # only when the operator runs `doctor`.  An operator who
        # restores from paper backup and (a) starts the daemon via
        # `systemctl start messagechain-validator`, (b) skips
        # `doctor` out of habit, or (c) runs `start --mine` straight,
        # bypasses the gate -- on the next sign the keypair re-uses
        # a leaf the chain already has a sig for, equivocation
        # evidence lands, full stake slash.  Lifting the same check
        # here closes that.  Bypass with --accept-leaf-reuse-risk
        # after manual verification of the cursor situation.
        from messagechain.runtime.onboarding import _check_leaf_index
        _li_result = _check_leaf_index(
            args.data_dir, entity.entity_id_hex,
        )
        if _li_result.level == 2:
            print()
            print(f"  [!] leaf-index check FAILED ({_li_result.status})")
            print(f"      {_li_result.detail}")
            if not getattr(args, "accept_leaf_reuse_risk", False):
                print()
                print("      Refusing to start --mine -- the next sign would")
                print("      re-use a leaf the chain has already recorded a")
                print("      signature for, producing equivocation evidence")
                print("      and a 100% stake slash.")
                print()
                print("      Run `messagechain doctor` for the full check-")
                print("      list, restore the leaf-index file from backup,")
                print("      or pass --accept-leaf-reuse-risk if you have")
                print("      manually verified the local cursor exceeds the")
                print("      chain watermark for every prior sign.")
                sys.exit(2)
            print()
            print("      --accept-leaf-reuse-risk set: continuing past the")
            print("      gate.  Operator-acknowledged leaf-reuse risk.")
        elif _li_result.level == 1:
            print(f"  [warn] leaf-index check inconclusive: {_li_result.status}")

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

        # Governance-proposal banner: surface any open proposals the
        # operator hasn't yet voted on.  Cheap, in-process read of the
        # local blockchain state -- no RPC round-trip.  Quiet when there
        # are no open proposals OR the operator has already voted on
        # all of them.  Always runs, regardless of whether email
        # notifications are configured (banner is the always-on
        # fallback; email is the convenience layer on top).
        try:
            _print_open_proposals_banner_local(server, entity)
        except Exception as e:
            # Banner must never abort startup -- log and continue.
            logging.getLogger(__name__).warning(
                "governance proposal banner skipped (%s)", type(e).__name__,
            )

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
    entity = _resolve_signing_entity(private_key, args)

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
    entity = _resolve_signing_entity(private_key, args)

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


def _should_include_pubkey(
    host: str, port: int, entity_id_hex: str, target_height: int,
) -> bool:
    """Decide whether the next signed tx from ``entity_id_hex`` should
    carry ``sender_pubkey`` (Tier 11 first-spend pubkey install).

    Returns True only when:
      (1) target_height is past FIRST_SEND_PUBKEY_HEIGHT (v3 txs are
          rejected pre-fork  --  including the pubkey would only get the
          tx bounced), AND
      (2) the chain reports the entity exists but has not yet had its
          pubkey installed (the freshly-funded-via-receive-to-exist
          case, where the entity has a balance but no on-chain key).

    Single chokepoint for the first-spend decision so every signing
    command (cmd_send, cmd_send_multi_submit, ...) agrees on the
    probe semantics.  Adding a new signing path that bypasses this
    helper reintroduces the audit r46 #3 defect  --  a fresh-key first
    spend through that path gets rejected by every endpoint with
    "Unknown entity  --  must register first", which looks like
    censorship to the user but is actually missing pubkey-install.

    Exception-safe: any RPC failure (unreachable node, malformed
    response) falls back to False so the caller stays on v1/v2.
    The chain returns "Unknown entity" if the entity truly doesn't
    exist, which the caller's own error handler explains.
    """
    from messagechain.config import FIRST_SEND_PUBKEY_HEIGHT
    if target_height < FIRST_SEND_PUBKEY_HEIGHT:
        return False
    try:
        from client import rpc_call
        resp = rpc_call(host, port, "get_entity", {
            "entity_id": entity_id_hex,
        })
    except Exception:
        return False
    if not resp.get("ok"):
        return False
    return not resp["result"].get("pubkey_registered", True)


def _resolve_fee_with_server_floor(
    *,
    kind: str,
    host: str,
    port: int,
    args,
    estimate_extra: dict | None = None,
    auto_fee_extra: dict | None = None,
    local_min_hint: int | None = None,
    target_height: int | None = None,
) -> tuple[int, int]:
    """Resolve a signing command's submission fee with the server's
    live admission floor as the authoritative lower bound.

    Pre-audit-r48 only ``cmd_transfer`` (audit r45 #2) consulted
    ``server_min_fee``.  Every other signing command validated explicit
    ``--fee`` against a stale local constant (``calculate_min_fee``,
    ``KEY_ROTATION_FEE``, ``GOVERNANCE_VOTE_FEE``, ``proposal_fee_floor``)
    or skipped the floor check entirely.  The recurrence-pattern r45 #2
    closed for transfer extends to every signing command via this
    helper, in lockstep with the CLAUDE.md fee-model anchor "when the
    fee model shifts, every auto-fee path shifts with it -- don't
    leave a tx kind defaulting to a stale flat fee while others auto-
    bid by density."

    Returns ``(fee, server_min_fee)``.  Exits on explicit ``--fee``
    below the server's live floor.  Behavior is identical in shape to
    ``cmd_transfer``'s pre-existing pattern; this helper is the single
    chokepoint every other signing command now routes through.

    ``estimate_extra`` and ``auto_fee_extra`` carry kind-specific
    payload (``recipient_id`` for transfer, ``stored_size``/``message``
    for send, etc.).  ``local_min_hint`` is an optional secondary floor
    (e.g. ``calculate_min_fee`` for ``send``) layered on top of the
    server's quote as defense-in-depth -- the server's quote is the
    authoritative gate.
    """
    from client import rpc_call
    from messagechain.config import MIN_FEE
    from messagechain.economics.auto_fee import (
        auto_fee, urgency_to_target_blocks,
    )
    estimate_extra = estimate_extra or {}
    auto_fee_extra = auto_fee_extra or {}
    urgency = getattr(args, "urgency", "normal")

    est_payload = {
        "kind": kind,
        "target_blocks": urgency_to_target_blocks(urgency),
        "urgency": urgency,
        **estimate_extra,
    }
    est_resp = rpc_call(host, port, "estimate_fee", est_payload)
    server_min_fee = MIN_FEE
    mempool_estimate = 0
    if est_resp.get("ok"):
        r = est_resp["result"]
        server_min_fee = int(r.get("min_fee", MIN_FEE))
        mempool_estimate = int(r.get("mempool_fee", 0))

    # Compose the final floor: server's live quote, plus the caller's
    # local hint (e.g. a signature-aware floor that the server's quote
    # may not include).  ``max`` is correct because both represent
    # admission lower bounds.
    floor = server_min_fee
    if local_min_hint is not None:
        floor = max(floor, int(local_min_hint))

    fee = getattr(args, "fee", None)
    if fee is None:
        if target_height is None:
            info_resp = rpc_call(host, port, "get_chain_info", {})
            if info_resp.get("ok"):
                count = info_resp["result"].get("height", 0) or 0
                target_height = max(count - 1, 0) + 1
        fee = auto_fee(
            kind,
            urgency=urgency,
            current_height=target_height,
            mempool_estimate=mempool_estimate,
            **auto_fee_extra,
        )
        # Defense-in-depth: floor at the live server quote so a stale
        # local auto_fee height never underbids the validator's actual
        # admission rule.
        fee = max(fee, floor)
    elif fee < floor:
        print(
            f"Error: --fee {fee} is below the chain's live floor "
            f"{floor} for {kind} tx."
        )
        sys.exit(1)
    return fee, server_min_fee


def cmd_send(args):
    """Send a message to the chain."""
    from messagechain.identity.identity import Entity

    message = args.message
    char_count = len(message)
    if not message.strip():
        print("Error: Message cannot be empty.")
        sys.exit(1)
    # Pre-INTL_MESSAGE_HEIGHT: ASCII only.  Post-INTL_MESSAGE_HEIGHT:
    # NFC UTF-8 in the L/M/N/P/Zs whitelist.  We don't yet know the
    # tip height (it's fetched below), so emit a friendly diagnostic
    # for the most common pre-flight failure (non-UTF-8-encodable input
    # or oversize bytes); the chain validator and create_transaction's
    # height-aware check cover the rest.
    try:
        msg_bytes_preview = message.encode("utf-8")
    except UnicodeEncodeError as e:
        bad = message[e.start:e.start + 1]
        print(
            f"Error: Message contains an unencodable character "
            f"({bad!r}, U+{ord(bad):04X}) at position {e.start}."
        )
        sys.exit(1)
    if len(msg_bytes_preview) > MAX_MESSAGE_CHARS:
        print(
            f"Error: Message is {len(msg_bytes_preview)} bytes UTF-8 "
            f"(max {MAX_MESSAGE_CHARS})."
        )
        sys.exit(1)

    print(f"=== Send Message ({char_count} chars, {len(msg_bytes_preview)} bytes) ===\n")

    # Authenticate
    private_key = _resolve_private_key(args, personal_wallet=True)
    data_dir = getattr(args, "data_dir", None)
    entity = _resolve_signing_entity(private_key, args)
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
    # Bind the persistent on-disk leaf cursor BEFORE advancing.  This
    # is the cross-process WOTS+ leaf-reuse defense: the cursor is
    # keyed per-entity under ~/.messagechain/leaves/<id>.idx (default)
    # or <data_dir>/leaf_index.json (operator path).  The helper
    # max(disk_cursor, chain_leaf)'s the floor; KeyPair.sign's
    # persist-before-sign hook writes the post-sign cursor back.
    _bind_persistent_leaf_index(entity, chain_leaf=leaf, data_dir=data_dir)

    # Parse the optional --prev pointer before we burn a WOTS+ leaf on
    # signing.  Server will re-validate strict-prev against chain state;
    # catching malformed input here avoids a doomed sign + reject round.
    prev_bytes_arg: bytes | None = None
    if getattr(args, "prev", None):
        prev_hex = args.prev.strip()
        if len(prev_hex) != 64:
            print(
                f"Error: --prev must be exactly 64 hex chars "
                f"(got {len(prev_hex)})."
            )
            sys.exit(1)
        try:
            prev_bytes_arg = bytes.fromhex(prev_hex)
        except ValueError:
            print("Error: --prev is not valid hex.")
            sys.exit(1)

    # --community-id: pass the normalized ASCII handle straight to the
    # chain.  Names are NFC-normalized and lowercased so "MyCommunity"
    # / "mycommunity" / "MYCOMMUNITY" all map to the same handle; the
    # chain validator (transaction._validate_community_id) enforces the
    # 1-MAX_COMMUNITY_ID_LEN bytes from [a-z0-9_-] / DNS-label-edge
    # rule -- no client-side hashing is involved.  No registry, no
    # claim; the (handle, display-name) mapping lives in indexers.
    community_id_arg: str | None = None
    if getattr(args, "community_id", None):
        import unicodedata
        normalized = unicodedata.normalize(
            "NFC", args.community_id.strip(),
        ).lower()
        if not normalized:
            print("Error: --community-id must not be empty.")
            sys.exit(1)
        community_id_arg = normalized

    # --poll-option / --vote-target (Tier 72).  Mutually exclusive.
    # Validation here gives a fast pre-flight diagnostic; the chain's
    # _validate_poll_options / _validate_vote_target re-enforces.
    poll_options_arg: tuple[str, ...] | None = None
    vote_target_arg: tuple[bytes, int] | None = None
    raw_poll_opts = getattr(args, "poll_options", None) or []
    raw_vote = getattr(args, "vote_target", None)
    if raw_poll_opts and raw_vote:
        print(
            "Error: --poll-option and --vote-target are mutually "
            "exclusive (a tx is either a poll OR a vote, never both)."
        )
        sys.exit(1)
    if raw_poll_opts:
        import unicodedata
        opts_norm = tuple(
            unicodedata.normalize("NFC", opt) for opt in raw_poll_opts
        )
        if len(opts_norm) < 1 or len(opts_norm) > 4:
            print(
                f"Error: --poll-option must be given 1..4 times "
                f"(got {len(opts_norm)})."
            )
            sys.exit(1)
        poll_options_arg = opts_norm
    if raw_vote:
        if ":" not in raw_vote:
            print(
                "Error: --vote-target must be POLL_TXID:INDEX "
                "(64 hex chars + colon + 0-based int)."
            )
            sys.exit(1)
        poll_hex, _, idx_str = raw_vote.partition(":")
        poll_hex = poll_hex.strip()
        if len(poll_hex) != 64:
            print(
                f"Error: --vote-target poll_txid must be 64 hex chars "
                f"(got {len(poll_hex)})."
            )
            sys.exit(1)
        try:
            poll_txid = bytes.fromhex(poll_hex)
        except ValueError:
            print("Error: --vote-target poll_txid is not valid hex.")
            sys.exit(1)
        try:
            option_index = int(idx_str)
        except ValueError:
            print(
                f"Error: --vote-target option_index must be an integer "
                f"(got {idx_str!r})."
            )
            sys.exit(1)
        vote_target_arg = (poll_txid, option_index)

    # Auto-detect fee (or use explicit). The actual minimum for a message
    # scales non-linearly with size (MIN_FEE + per-byte + quadratic), so
    # always take max(local_min, server_suggestion) to avoid silently
    # submitting a tx the chain will reject.
    from messagechain.core.transaction import (
        calculate_min_fee,
        PREV_POINTER_STORED_BYTES,
    )
    from messagechain.core.compression import encode_payload
    from messagechain.config import FEE_INCLUDES_SIGNATURE_HEIGHT, FIRST_SEND_PUBKEY_HEIGHT
    # Fee is charged on the canonical stored size - compute locally so
    # we never overpay and never underpay relative to what the chain
    # will enforce.
    # UTF-8 is byte-identical to ASCII for printable-ASCII input, so
    # this is safe pre-fork; post-INTL_MESSAGE_HEIGHT it carries the
    # multi-byte sequences the chain validator now accepts.
    msg_bytes = args.message.encode("utf-8")
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
    # Thread the target inclusion height (tip+1) so calculate_min_fee
    # dispatches to the live fee rule (LINEAR at/after LINEAR_FEE_HEIGHT)
    # instead of the stricter legacy quadratic default -- without this,
    # CLI users silently overpay ~5-10x on short messages and low-fee
    # dissident submissions get rejected client-side even though the
    # chain would accept them.
    target_height = tip_height + 1
    prev_overhead = (
        PREV_POINTER_STORED_BYTES if prev_bytes_arg is not None else 0
    )
    if community_id_arg is not None:
        from messagechain.core.transaction import (
            _community_id_stored_bytes, TX_VERSION_COMMUNITY_ID,
        )
        prev_overhead += _community_id_stored_bytes(
            community_id_arg, TX_VERSION_COMMUNITY_ID,
        )
    if poll_options_arg is not None or vote_target_arg is not None:
        # Tier 72: v6 wire layout includes the v4/v5 trailer presence
        # flags + the new poll_options + vote_target blocks.  Mirror
        # create_transaction's accounting so the local fee floor
        # matches what the chain enforces.
        from messagechain.core.transaction import (
            _poll_options_stored_bytes, _vote_target_stored_bytes,
            TX_VERSION_POLL, TX_VERSION_LENGTH_PREFIX,
            TX_VERSION_COMMUNITY_ID,
        )
        # If neither community_id nor prev/sender_pubkey were set, the
        # v4/v5 trailer presence flags still cost 1B each at v6.
        # create_transaction's promote-from-v1/v2 path adds them when
        # bumping up; mirror that here so calculate_min_fee agrees.
        if community_id_arg is None:
            prev_overhead += 1  # community_id presence flag (v5+)
        prev_overhead += _poll_options_stored_bytes(
            poll_options_arg, TX_VERSION_POLL,
        )
        prev_overhead += _vote_target_stored_bytes(
            vote_target_arg, TX_VERSION_POLL,
        )
    if target_height >= FEE_INCLUDES_SIGNATURE_HEIGHT:
        # Signature size is deterministic for the scheme parameters baked
        # into the keypair, so compute it without actually signing (a
        # probe-sign would consume a one-time WOTS+ leaf).
        sig_bytes_len = _estimate_signature_size(entity.keypair)
        local_min = calculate_min_fee(
            stored_bytes,
            signature_bytes=sig_bytes_len,
            current_height=target_height,
            prev_bytes=prev_overhead,
        )
    else:
        local_min = calculate_min_fee(
            stored_bytes,
            current_height=target_height,
            prev_bytes=prev_overhead,
        )
    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper so the message-send
    # path matches every other signing command's fee-resolution
    # semantics (server's live admission floor is authoritative; local
    # signature-aware floor is layered as defense-in-depth).  Pre-fix
    # this path validated explicit ``--fee`` against ``local_min`` only
    # and could silently bounce a sender who priced correctly against
    # the chain's actual height-aware floor.
    from messagechain.economics.auto_fee import urgency_to_target_blocks
    urgency = getattr(args, "urgency", "normal")
    target_blocks = urgency_to_target_blocks(urgency)
    fee_was_explicit = args.fee is not None
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="message",
        host=host,
        port=port,
        args=args,
        estimate_extra={"message": args.message},
        auto_fee_extra={
            "stored_size": len(stored_bytes) + prev_overhead,
        },
        local_min_hint=local_min,
        target_height=target_height,
    )
    if not fee_was_explicit:
        print(
            f"Fee: {fee} tokens (auto, target ~{target_blocks} blocks, "
            f"urgency={urgency})"
        )
    else:
        print(f"Fee: {fee} tokens")

    # Tier 11: auto-include the sender's pubkey on first send.  Routes
    # through the shared ``_should_include_pubkey`` helper so cmd_send
    # and cmd_send_multi_submit agree on the probe semantics  --  a future
    # signing command can adopt the same first-spend behaviour by
    # calling the helper rather than duplicating the inline probe.
    include_pubkey = _should_include_pubkey(
        host, port, entity.entity_id_hex, target_height,
    )
    if include_pubkey:
        print(
            "\nFirst send from this wallet -- attaching pubkey "
            "(Tier 11 receive-to-exist install).  Subsequent "
            "sends will skip this and stay on v1/v2."
        )

    # Create, sign, submit.  Thread the live target_height so the
    # client-side fee floor matches the live (LINEAR-era) rule the
    # chain enforces -- without this, create_transaction defaults to
    # the legacy quadratic floor and rejects auto-fee txs that are
    # correctly priced under LINEAR.  Observed on mainnet 2026-04-25:
    # CLI computed local_min=223 (LINEAR), create_transaction enforced
    # 323 (legacy), every fresh-user submit hit "Fee must be at least
    # 323 ..." and bounced.
    tx = create_transaction(
        entity, message, fee=fee, nonce=nonce,
        current_height=target_height, prev=prev_bytes_arg,
        include_pubkey=include_pubkey,
        community_id=community_id_arg,
        poll_options=poll_options_arg,
        vote_target=vote_target_arg,
    )
    if prev_bytes_arg is not None:
        print(f"Referencing prior tx: {prev_bytes_arg.hex()[:16]}...")
    if community_id_arg is not None:
        print(f"Community: {community_id_arg}")
    if poll_options_arg is not None:
        print(f"Poll options: {list(poll_options_arg)}")
    if vote_target_arg is not None:
        vt_pid, vt_idx = vote_target_arg
        print(f"Voting on poll {vt_pid.hex()[:16]}... option index {vt_idx}")
    print("Submitting...")

    response = rpc_call(host, port, "submit_transaction", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        tx_hash_hex = result["tx_hash"]
        print(f"\nMessage sent!")
        print(f"  TX hash: {tx_hash_hex}")
        print(f"  Fee:     {result['fee']} tokens")
        # Audit-#2 fix (round 7): persist the validator-issued
        # SubmissionReceipt to the canonical default location so the
        # user has the evidence bundle on disk if their tx is later
        # censored.  Pre-fix, cmd_send read tx_hash + fee and silently
        # dropped result["receipt"] -- the slashing-backed permanence
        # promise is the chain's headline guarantee, but the
        # default-send path didn't save the artifact needed to
        # actually escalate.  Bundle shape matches _load_receipt_bundle
        # so `submit-evidence censorship --receipt <path>` consumes
        # the file directly without translation.  Best-effort: a write
        # failure is logged but does NOT fail the send (the tx is
        # already on the wire; surfacing a confusing error after the
        # accept message would erode the headline UX promise).
        receipt_hex = result.get("receipt")
        bundle_path = None
        if receipt_hex:
            try:
                bundle_path = _save_receipt_bundle(
                    tx_hash_hex=tx_hash_hex,
                    receipt_hex=receipt_hex,
                    tx=tx,
                    tx_kind="message",
                )
            except OSError as e:
                print(
                    f"  (warning: could not save receipt bundle to disk: {e})"
                )
                bundle_path = None
        if bundle_path:
            print(f"  Receipt saved: {bundle_path}")
        # Round-6 audit fix: name the headline promise of the project at
        # the exact moment the user just paid for it, and point at the
        # receipt CLI -- the verification surface that grounds the
        # permanence claim in slashable evidence rather than marketing
        # copy.  The `--cross-check-server` pointer is the paranoid-user
        # pivot for the validator-collusion threat model: a single RPC
        # node can't unilaterally forge inclusion if a second is asked
        # to confirm.
        # ``PUBLIC_FEED_URL`` is the configurable base host
        # (default ``https://messagechain.org``); the receipt page
        # at ``/r/<tx_hash>`` reads the hash from its own URL and
        # queries ``/v1/tx_status``, surfacing a polished "permanent
        # -- this message is on-chain and can never be deleted" card
        # any non-technical reader can verify.  Printing the URL
        # here -- alongside the existing ``messagechain receipt``
        # CLI verifier -- makes the chain's headline artifact
        # shareable from the moment the tx is submitted, instead
        # of being discoverable only by hunting through docs.
        from messagechain import cli as _self  # late lookup for test override
        feed_host = getattr(_self, "PUBLIC_FEED_URL", PUBLIC_FEED_URL)
        share_url = f"{feed_host}/r/{tx_hash_hex}"
        print(
            "\n"
            "  Permanence: once this tx is included in a finalized block\n"
            "              (~10 min), the message is permanent and can\n"
            "              never be deleted by any party.  Validators\n"
            "              that drop or suppress it lose stake on chain.\n"
            "\n"
            f"  Share:  {share_url}\n"
            "\n"
            "  Verify inclusion:\n"
            f"    messagechain receipt {tx_hash_hex}\n"
            f"    messagechain receipt {tx_hash_hex} "
            "--cross-check-server <other_validator>"
        )
    else:
        err = response.get("error", "")
        print(f"\nFailed: {err}")
        # Surface actionable next-step text for the most common
        # cold-start failure mode.  receive-to-exist + no faucet means
        # a fresh wallet hits "Unknown entity" with no clue what to do
        # next.  Without this hint the chain looks broken to first-time
        # users (observed during 2026-04-25 submit-UX probe).
        if "Unknown entity" in err or "must register first" in err:
            print(
                "\n"
                "Why this happens: MessageChain uses a 'receive-to-exist'\n"
                "model -- a wallet only becomes an on-chain entity once\n"
                "it has received tokens from another entity.  Your wallet\n"
                f"  {entity.entity_id_hex}\n"
                "has no on-chain balance yet, so it cannot pay the fee\n"
                "for its own first message.\n"
                "\n"
                "Bootstrap path:\n"
                "  1. Get tokens at https://messagechain.org/ (one click\n"
                "     into the 'Get starter tokens' box).\n"
                "  2. Wait ~10 minutes for the next block.\n"
                "  3. Re-run 'messagechain send' -- the CLI auto-includes\n"
                "     your pubkey on first send (Tier 11), so the next\n"
                "     attempt registers your identity in the same tx that\n"
                "     posts your message."
            )
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

    # Route keyfile load through the shared ``_resolve_private_key``
    # helper.  This supports every form ``messagechain generate-key``
    # produces  --  24-word BIP-39 mnemonic, 72-char checksummed hex, and
    # raw 64-char hex (the only form the hand-rolled pre-fix accepted)  -- 
    # plus an interactive prompt fall-through.  ``personal_wallet=True``
    # mirrors ``cmd_send`` so ``sudo messagechain send-multi`` on a
    # validator host does NOT silently sign with the validator's hot
    # key (a fund-loss / identity-attribution footgun).
    private_key = _resolve_private_key(args, personal_wallet=True)
    entity = _resolve_signing_entity(private_key, args)

    # Audit r43 #3 (UX top-1): auto-resolve nonce + leaf-watermark +
    # fee via --server's JSON-RPC, mirroring cmd_send.  send-multi is
    # the censorship-resistance escape hatch -- making it require
    # hand-picked --nonce / --leaf-index / --fee defeated its own
    # purpose, since a dissident reaching for it under pressure is
    # exactly the population that would set --nonce 0 from muscle
    # memory and either bounce off "nonce too low" or burn an
    # already-used WOTS+ leaf.
    #
    # --server is the SOURCE of chain state, independent of the
    # fan-out --endpoint set.  Defaults to localhost; for trust-
    # minimisation users should point it at their own node.  The
    # fan-out continues to use --endpoint exclusively.
    from client import rpc_call as _rpc
    state_host, state_port = _parse_server(getattr(args, "server", None))

    explicit_nonce = getattr(args, "nonce", None)
    explicit_leaf = getattr(args, "leaf_index", None)
    if explicit_nonce is None or explicit_leaf is None:
        nonce_resp = _rpc(state_host, state_port, "get_nonce", {
            "entity_id": entity.entity_id_hex,
        })
        if not nonce_resp.get("ok"):
            print(
                f"Error: could not fetch nonce/leaf from --server "
                f"{state_host}:{state_port}: "
                f"{nonce_resp.get('error', 'rpc failed')}.  Pass --nonce "
                f"and --leaf-index explicitly, or point --server at a "
                f"reachable JSON-RPC node."
            )
            return 1
        chain_nonce = int(nonce_resp["result"].get("nonce", 0))
        chain_leaf = int(
            nonce_resp["result"].get("leaf_watermark", chain_nonce)
        )
    else:
        chain_nonce = int(explicit_nonce)
        chain_leaf = int(explicit_leaf)

    nonce = chain_nonce if explicit_nonce is None else int(explicit_nonce)
    leaf_index = chain_leaf if explicit_leaf is None else int(explicit_leaf)

    # Cross-process WOTS+ leaf-reuse defense.  Multi-submit fans out
    # to N>=3 validators, but the leaf is still ONE WOTS+ leaf -- two
    # consecutive multi-submit runs at the same --leaf-index would
    # double-sign and disclose the leaf private key.
    if explicit_leaf is None:
        # Audit r54 #2: route through the unified
        # ``_resolve_signing_leaf`` chokepoint so the daemon's atomic
        # reservation closes the co-resident same-host race.  This
        # is the common case (operator runs send-multi from the
        # validator host itself).  ``watermark_fallback`` is the
        # leaf_watermark we already fetched above via ``get_nonce``,
        # so older daemons without ``reserve_leaf`` keep working.
        leaf_index = _resolve_signing_leaf(
            state_host, state_port, entity,
            data_dir=getattr(args, "data_dir", None),
            watermark_fallback=leaf_index,
        )
    else:
        # Explicit --leaf-index supersedes the chokepoint -- operator
        # is asserting "sign at exactly this leaf" (typical for
        # offline-signing or air-gapped flows where the daemon's
        # reservation is irrelevant because the daemon is unreachable
        # by design).  Bind the on-disk cursor at the explicit value
        # so a subsequent run still advances past it.
        _bind_persistent_leaf_index(
            entity, chain_leaf=int(leaf_index),
            data_dir=getattr(args, "data_dir", None),
        )

    # Resolve target_height once for the auto-fee and pubkey-install
    # branches below.  Hoisted out of the fee-branch so the pubkey-
    # install probe sees it even when --fee is explicit.
    info_resp = _rpc(state_host, state_port, "get_chain_info", {})
    tip_height = 0
    if info_resp.get("ok"):
        tip_height = max(
            int(info_resp["result"].get("height", 0) or 0) - 1, 0
        )
    target_height = tip_height + 1

    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper so explicit ``--fee``
    # validation uses the server's live floor.  cmd_send-multi shares
    # the helper with cmd_send and every other signing command.
    from messagechain.core.compression import encode_payload
    stored_bytes, _ = encode_payload(args.message.encode("utf-8"))
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="message",
        host=state_host,
        port=state_port,
        args=args,
        estimate_extra={"message": args.message},
        auto_fee_extra={"stored_size": len(stored_bytes)},
        target_height=target_height,
    )

    # Tier 11: auto-include the sender's pubkey on first send.  Routes
    # through the shared ``_should_include_pubkey`` helper -- the same
    # one cmd_send uses -- so a fresh-key dissident's FIRST send-multi
    # post lands as v3 with sender_pubkey set, instead of being silently
    # rejected by every endpoint with "Unknown entity -- must register
    # first" (which would LOOK like validator-collusion censorship but
    # actually be missing pubkey install).  send-multi is exactly the
    # path a fresh-key dissident reaches for first, so closing this gap
    # is what makes the censorship-resistance escape hatch actually
    # usable on first attempt.
    include_pubkey = _should_include_pubkey(
        state_host, state_port, entity.entity_id_hex, target_height,
    )
    if include_pubkey:
        print(
            "First send from this wallet -- attaching pubkey "
            "(Tier 11 receive-to-exist install).",
        )

    # Match cmd_send: do NOT thread current_height when we don't have
    # confidence in target_height (state RPC may have failed).  Pre-fix
    # ``create_transaction`` always ran with current_height=None and
    # produced byte-identical wire form to what the chain's
    # verify_transaction expects at any height (the legacy floor +
    # tx-layout fall through to v1 baseline).  Threading
    # target_height=1 from a failed RPC silently lowers the layout
    # branch a tier-aware chain rejects.  include_pubkey still flows
    # through so first-spend support works once activated.
    tx = create_transaction(
        entity, args.message, fee=int(fee), nonce=nonce,
        include_pubkey=include_pubkey,
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
        # Audit r44 #2: write JSON bundles (the format
        # ``_load_receipt_bundle`` / ``submit-evidence censorship
        # --receipt`` consumes) instead of raw ``.bin`` blobs.
        # Pre-fix the success path wrote ``<tx>_<issuer>.bin`` and
        # the slashable-evidence CLI rejected those with "missing
        # `message_tx` field" -- the censorship-resistance escape
        # hatch produced evidence the same CLI could not consume.
        # One file per (tx_hash, issuer_id) so multiple validators'
        # receipts for the same tx don't overwrite each other.
        bundle_failures: list[tuple[str, OSError]] = []
        for r in result.receipts:
            try:
                _save_receipt_bundle(
                    tx_hash_hex=result.tx_hash.hex(),
                    receipt_hex=r.to_bytes().hex(),
                    tx=tx,
                    tx_kind="message",
                    receipts_dir=receipts_dir,
                    filename_suffix=r.issuer_id.hex()[:16],
                )
            except OSError as e:
                bundle_failures.append((r.issuer_id.hex()[:16], e))
        if bundle_failures:
            # Best-effort: the tx is already on the wire; surfacing
            # write failures lets the user re-fetch from disk later
            # without misleading them about the tx itself.
            for iid_prefix, err in bundle_failures:
                print(
                    f"  (warning: could not save receipt bundle for "
                    f"issuer {iid_prefix}: {err})"
                )

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
    # ``--yes`` / ``-y`` is the script-friendly path: when running over
    # ``gcloud compute ssh`` (or any SSH+sudo wrapper) piped stdin does
    # not always reach ``input()``, so the interactive confirm hangs the
    # session.  Operators driving the CLI from automation pass ``--yes``
    # to acknowledge they have already verified the recipient.
    if not getattr(args, "yes", False):
        confirm = input("\nConfirm send (type 'yes' to proceed): ").strip().lower()
        if confirm != "yes":
            print("Transfer cancelled.")
            sys.exit(0)
    else:
        print("\nSkipping confirmation prompt (--yes).")

    private_key = _resolve_private_key(args, personal_wallet=True)
    data_dir = getattr(args, "data_dir", None)
    entity = _resolve_signing_entity(private_key, args)
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
    # See cmd_send for why this binding runs BEFORE advance: prevents
    # cross-process WOTS+ leaf-reuse by max()ing the disk cursor and
    # the chain watermark.
    _bind_persistent_leaf_index(entity, chain_leaf=leaf, data_dir=data_dir)

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
    #   * --fee explicit:  honor it if it clears the LIVE server floor
    #     (server_min_fee == tx_floor("transfer", current_height, ...),
    #     which already bundles the NEW_ACCOUNT_FEE surcharge when
    #     applicable); else error.
    #   * --fee omitted:   use the unified auto-fee helper so every
    #     tx-submitting command shares one picker (CLAUDE.md anchor).
    #     The helper's tx_floor("transfer", ...) already bundles the
    #     surcharge when recipient_is_new.
    #
    # Audit r45 #2: trust server_min_fee directly.  Previously this
    # code re-clamped the picked fee against the legacy MIN_FEE
    # constant locally -- but MIN_FEE is the legacy pre-FLAT_FEE_HEIGHT
    # value of 100, while Tier 49 (UNIFIED_FEE_FLOOR_HEIGHT=1750)
    # collapsed the unified transfer floor to MARKET_FEE_FLOOR=1 for
    # existing-recipient transfers.
    # The local clamp silently over-charged every wallet user 100x the
    # protocol floor on every transfer since Tier 49 went live.  The
    # server's ``tx_floor`` is the height-aware source of truth; the
    # new-account-surcharge path stays correct via the server returning
    # MIN_FEE + NEW_ACCOUNT_FEE on that branch (validator code path
    # unchanged).
    fee = args.fee
    if fee is None:
        from messagechain.economics.auto_fee import (
            auto_fee, urgency_to_target_blocks,
        )
        urgency = getattr(args, "urgency", "normal")
        # Probe live tip so the helper sees the right height-aware
        # floor.  RPC failure -> fall back to the server's min_fee
        # (which already encodes the surcharge if any).
        info_resp = rpc_call(host, port, "get_chain_info", {})
        target_height = None
        if info_resp.get("ok"):
            count = info_resp["result"].get("height", 0) or 0
            target_height = max(count - 1, 0) + 1
        # Mempool percentile estimate at the urgency-derived rung.
        # Transfers don't compete in the message-byte-budget knapsack,
        # so the percentile estimate is mostly informational here --
        # the type-specific floor binds.
        est_resp = rpc_call(host, port, "estimate_fee", {
            "kind": "transfer",
            "recipient_id": recipient_id.hex(),
            "target_blocks": urgency_to_target_blocks(urgency),
            "urgency": urgency,
        })
        mempool_estimate = (
            est_resp["result"].get("mempool_fee", 0)
            if est_resp.get("ok") else 0
        )
        fee = auto_fee(
            "transfer",
            urgency=urgency,
            current_height=target_height,
            mempool_estimate=mempool_estimate,
            recipient_is_new=recipient_is_new,
        )
        # Defence in depth: floor the picked fee at the server's live
        # quote so a stale local auto_fee height doesn't underbid the
        # validator's actual admission rule.  No legacy MIN_FEE clamp.
        fee = max(fee, server_min_fee)
    elif fee < server_min_fee:
        if recipient_is_new:
            print(
                f"Error: fee {fee} is below the chain's live floor "
                f"{server_min_fee} (includes NEW_ACCOUNT_FEE "
                f"{NEW_ACCOUNT_FEE} surcharge for brand-new recipient)."
            )
        else:
            print(
                f"Error: fee {fee} is below the chain's live floor "
                f"{server_min_fee}."
            )
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
        tx_hash_hex = result["tx_hash"]
        print(f"\nTransfer submitted!")
        print(f"  TX hash: {tx_hash_hex}")
        print(f"  Amount:  {result['amount']} tokens")
        print(f"  Fee:     {result['fee']} tokens")
        # Audit r45 #3: persist the validator-issued SubmissionReceipt
        # to disk so the user holds the on-chain-slashable-evidence
        # artifact if a coerced validator silently drops this transfer.
        # CLAUDE.md collective-censorship anchor: the slashable-
        # evidence path applies to every well-formed tx, not just
        # messages.  Pre-fix cmd_transfer dropped result["receipt"]
        # on the floor while cmd_send saved it, leaving transfers
        # without the bundle ``submit-evidence censorship --receipt``
        # consumes.  Best-effort write -- a disk failure does NOT
        # fail the transfer (the tx is already on the wire).
        receipt_hex = result.get("receipt")
        if receipt_hex:
            try:
                bundle_path = _save_receipt_bundle(
                    tx_hash_hex=tx_hash_hex,
                    receipt_hex=receipt_hex,
                    tx=tx,
                    tx_kind="transfer",
                )
                print(f"  Receipt saved: {bundle_path}")
            except OSError as e:
                print(
                    f"  (warning: could not save receipt bundle to "
                    f"disk: {e})"
                )
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_balance(args):
    """Check account balance."""
    from messagechain.identity.identity import Entity

    print("=== Account Balance ===\n")

    # Read-only lookup branch: --address (mc1...) or --entity-id (hex)
    # shortcuts the keygen/cache roundtrip entirely.  This is the
    # README first-touch path -- the user may not even have a wallet
    # yet, just wants to confirm a published address resolves.  No
    # getpass, no Entity.create, no cache write, no leaf-index
    # binding.
    entity_id_hex = _read_only_entity_id_hex(args)
    if entity_id_hex is None:
        private_key = _resolve_private_key(args)
        entity = _resolve_signing_entity(private_key, args)
        entity_id_hex = entity.entity_id_hex

    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "get_entity", {
        "entity_id": entity_id_hex,
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
    entity = _resolve_signing_entity(private_key, args)
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
    # Cross-process WOTS+ leaf-reuse defense -- see cmd_send.
    _bind_persistent_leaf_index(entity, chain_leaf=leaf, data_dir=data_dir)

    # Default fee: drive through the unified auto-fee helper so the
    # "stake" picker matches every other tx-submitting command
    # (CLAUDE.md anchor: "When the fee model shifts, every auto-fee
    # path shifts with it").  ``auto_fee`` already enforces the live
    # admission floor -- post-Tier-16 that's max(MIN_FEE,
    # MARKET_FEE_FLOOR) = MIN_FEE = 100 -- and never returns 0.  Do
    # NOT re-clamp here against a pre-Tier-16 ``MIN_FEE_POST_FLAT``
    # constant: that 1000-token clamp was a stale artifact that
    # broke the Tier 29 anchored "1 faucet drip funds an end-to-end
    # validator stake" flow (drip=300 = 200 stake + 100 fee).
    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper so explicit ``--fee``
    # validation uses the server's live floor.
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="stake",
        host=host,
        port=port,
        args=args,
    )

    # First-spend pubkey reveal (Tier 11).  The README "Run a validator"
    # flow has the stake step be the operator's FIRST on-chain spend
    # (faucet drip -> stake), so without ``include_pubkey`` the chain
    # has no record of the new validator's signing key and admission
    # rejects with "Unknown entity".  Route through the shared
    # ``_should_include_pubkey`` chokepoint (audit r46 #3) so every
    # signing command agrees on the probe semantics; ``cmd_stake``
    # being the last hold-out is what made the bootstrap path wedge
    # for every fresh validator install (audit r53 #2).
    info_resp = rpc_call(host, port, "get_chain_info", {})
    include_pubkey = False
    if info_resp.get("ok"):
        count = info_resp["result"].get("height", 0) or 0
        target_height = max(count - 1, 0) + 1
        include_pubkey = _should_include_pubkey(
            host, port, entity.entity_id_hex, target_height,
        )
    if include_pubkey:
        print(
            "\nFirst spend from this wallet -- attaching pubkey "
            "(Tier 11 receive-to-exist install).  Subsequent stake "
            "txs will skip this."
        )

    tx = create_stake_transaction(
        entity, args.amount,
        nonce=nonce, fee=fee,
        include_pubkey=include_pubkey,
    )

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
        print(f"  Status:  {result.get('status', 'pending')}")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_unstake(args):
    """Unstake tokens."""
    from messagechain.identity.identity import Entity
    from messagechain.core.staking import create_unstake_transaction

    print("=== Unstake Tokens ===\n")

    private_key = _resolve_private_key(args)
    # WOTS+ Merkle keygen takes ~20-30 min at the production tree
    # height -- both --data-dir (daemon-coresident) and personal-wallet
    # paths route through the shared HMAC-authenticated cache via
    # _resolve_signing_entity so subsequent invocations are warm.
    data_dir = getattr(args, "data_dir", None)
    entity = _resolve_signing_entity(private_key, args)
    print(f"\nUnstaking as: {entity.entity_id_hex[:16]}...")

    host, port = _parse_server(args.server)

    from client import rpc_call

    # Cold-authority gate.  If the on-chain authority key for this
    # entity is NOT the hot signing key, the chain admission rule at
    # _validate_unstake_tx_in_block will reject any unstake signed by
    # the hot key with "Unstake must be signed by the authority (cold)
    # key.  The hot signing key cannot authorize withdrawal."  Detect
    # this pre-broadcast so the operator sees a clear "use --cold-keyfile"
    # message instead of silently broadcasting a tx that round-trips to
    # rejection.
    cold_signing_keypair = None
    auth_resp = rpc_call(host, port, "get_authority_key", {
        "entity_id": entity.entity_id_hex,
    })
    on_chain_authority_pk = None
    if auth_resp.get("ok"):
        ak_hex = auth_resp["result"].get("authority_key")
        if ak_hex:
            on_chain_authority_pk = bytes.fromhex(ak_hex)
    cold_required = (
        on_chain_authority_pk is not None
        and on_chain_authority_pk != entity.public_key
    )
    if cold_required:
        cold_keyfile = getattr(args, "cold_keyfile", None)
        if not cold_keyfile:
            print(
                "\nError: this entity has a cold authority key installed."
            )
            print(
                "Unstake must be signed by the cold key -- the chain "
                "rejects hot-key-signed unstakes (the whole point of "
                "the cold-authority hardening)."
            )
            print(
                "\nRe-run with --cold-keyfile <path> pointing at the "
                "cold private-key file, and --cold-leaf <N> if this is "
                "not your first cold-key signing (cold-key WOTS+ leaf "
                "state is operator-tracked; --cold-leaf 0 on a key that "
                "already signed something is leaf-reuse and will be "
                "rejected)."
            )
            sys.exit(1)
        try:
            with open(cold_keyfile, "rb") as f:
                cold_seed = f.read().strip()
        except OSError as e:
            print(f"Error: could not read cold key file {cold_keyfile!r}: {e}")
            sys.exit(1)
        # Hex-encoded private keys are also accepted (mirrors the
        # personal-wallet keyfile convention used elsewhere).
        try:
            cold_seed = bytes.fromhex(cold_seed.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass  # already raw bytes
        try:
            cold_entity = Entity.create(cold_seed)
        except Exception as e:
            print(f"Error: cold key file did not yield a valid Entity: {e}")
            sys.exit(1)
        if cold_entity.public_key != on_chain_authority_pk:
            print(
                "Error: --cold-keyfile public key does not match the "
                "currently-installed authority key on chain."
            )
            print(f"  installed: {on_chain_authority_pk.hex()}")
            print(f"  provided:  {cold_entity.public_key.hex()}")
            sys.exit(1)
        # Advance past prior cold-key uses.  Mirrors
        # cmd_set_receipt_subtree_root: cold-key leaf state is not on
        # chain.  --cold-leaf N tells the keypair to sign at leaf N
        # rather than 0.  Persistent on-disk cursor closes the
        # "operator forgot --cold-leaf" footgun.
        cold_leaf = max(0, int(getattr(args, "cold_leaf", 0)))
        _bind_persistent_leaf_index(
            cold_entity, chain_leaf=cold_leaf, data_dir=data_dir,
        )
        cold_signing_keypair = cold_entity.keypair
        print(f"Signing with cold authority key: {cold_entity.entity_id_hex[:16]}...")

    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": entity.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    nonce = nonce_resp["result"]["nonce"]

    watermark = nonce_resp["result"].get("leaf_watermark", nonce)
    # Cross-process WOTS+ leaf-reuse defense -- routes through the
    # unified ``_resolve_signing_leaf`` chokepoint (audit r54 #2).
    # Only binds the HOT entity's leaf cursor; cold-key cursor is
    # bound above via --cold-leaf.
    if cold_signing_keypair is None:
        _resolve_signing_leaf(
            host, port, entity,
            data_dir=data_dir, watermark_fallback=watermark,
        )

    # Default fee: route through the unified auto-fee helper.  Mirrors
    # cmd_stake; ``auto_fee`` already enforces the live admission floor
    # (post-Tier-16: MIN_FEE=100), and the urgency-driven percentile
    # estimate sits above it under load.  Do NOT re-clamp against
    # ``MIN_FEE_POST_FLAT`` -- same stale-floor bug as cmd_stake.
    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper.
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="unstake",
        host=host,
        port=port,
        args=args,
    )
    tx = create_unstake_transaction(
        entity, args.amount, nonce=nonce, fee=fee,
        signing_keypair=cold_signing_keypair,
    )

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
        print(f"  Status:  {result.get('status', 'pending')}")
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
    entity = _resolve_signing_entity(private_key, args)
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
        """Re-fetch nonce + leaf watermark and advance the keypair.

        Cross-process WOTS+ leaf-reuse defense -- routes through
        ``_bind_persistent_leaf_index`` so the on-disk cursor is the
        floor (not just the chain watermark).  Without this, two
        consecutive ``bootstrap-seed`` runs (or a partial first run +
        retry) would sign at the same leaf and produce slashable
        equivocation evidence.
        """
        resp = rpc_call(host, port, "get_nonce", {"entity_id": entity.entity_id_hex})
        if not resp.get("ok"):
            return None, None
        n = resp["result"]["nonce"]
        w = resp["result"].get("leaf_watermark", n)
        # Audit r54 #2 -- atomic leaf reservation via the unified
        # chokepoint.  Two consecutive ``bootstrap-seed`` runs (or a
        # partial first run + retry) racing the daemon's own signing
        # at the same chain watermark would otherwise produce
        # slashable equivocation.
        _resolve_signing_leaf(
            host, port, entity,
            data_dir=getattr(args, "data_dir", None),
            watermark_fallback=w,
        )
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
    # ``info`` does NOT take ``--entity-id``; ``balance --address`` is
    # the read-only lookup path that ships with this CLI (and accepts
    # the ``mc1...`` checksummed form so a paste typo is caught).
    from messagechain.identity.address import encode_address as _enc_addr
    print(
        f"  messagechain balance --address "
        f"{_enc_addr(entity.entity_id)} --server {host}:{port}"
    )
    print("\nThe verification must show:")
    print(f"  staked         >= {args.stake_amount}")
    print(f"  authority_key  == {authority_pubkey.hex()}")
    print("\nIf either is missing after a block or two, investigate before ")
    print("treating this seed as operational.  A silently-wrong bootstrap is ")
    print("the worst-case security failure.")


def cmd_set_authority_key(args):
    """Promote a cold authority key for this entity."""
    from messagechain.identity.identity import Entity
    from messagechain.core.authority_key import (
        create_set_authority_key_transaction,
        create_set_authority_key_rebind_transaction,
    )

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
    # WOTS+ Merkle keygen takes ~20-30 min at the production tree
    # height -- both --data-dir (daemon-coresident) and personal-wallet
    # paths route through the shared HMAC-authenticated cache via
    # _resolve_signing_entity so subsequent invocations are warm.
    data_dir = getattr(args, "data_dir", None)
    entity = _resolve_signing_entity(private_key, args)
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
    # Cross-process WOTS+ leaf-reuse defense via unified chokepoint
    # (audit r54 #2).
    _resolve_signing_leaf(
        host, port, entity,
        data_dir=data_dir, watermark_fallback=watermark,
    )

    # Default fee: post-flat floor is safe pre- and post-activation.
    from messagechain.config import MIN_FEE_POST_FLAT
    fee = args.fee if args.fee is not None else MIN_FEE_POST_FLAT

    # Tier 46: post AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT, a SetAuthorityKey
    # that REBINDS an already-installed authority key must carry a second
    # signature from the existing cold key.  Discover whether this entity
    # already has a cold key installed via the get_authority_key RPC.
    auth_resp = rpc_call(host, port, "get_authority_key", {
        "entity_id": entity.entity_id_hex,
    })
    existing_authority_pk = None
    if auth_resp.get("ok"):
        ak_hex = auth_resp["result"].get("authority_key")
        if ak_hex:
            existing_authority_pk = bytes.fromhex(ak_hex)
    # The authority key defaults to the hot signing key for entities
    # that have never run SetAuthorityKey -- get_authority_key returns
    # the hot key in that case, NOT None.  So "rebind" is signaled by
    # the on-chain authority_key differing from the hot signing key.
    is_rebind = (
        existing_authority_pk is not None
        and existing_authority_pk != entity.public_key
    )

    if is_rebind:
        cold_key_path = getattr(args, "cold_key_path", None)
        if not cold_key_path:
            print(
                "\nError: this entity already has a cold authority key installed."
            )
            print(
                "Re-binding it requires a counter-signature from the EXISTING "
                "cold key (Tier 46)."
            )
            print(
                "Re-run with --cold-key-path <path> pointing at the current "
                "cold private-key file."
            )
            sys.exit(1)
        try:
            with open(cold_key_path, "rb") as f:
                cold_seed = f.read().strip()
        except OSError as e:
            print(f"Error: could not read cold key file {cold_key_path!r}: {e}")
            sys.exit(1)
        # Hex-encoded private keys are also accepted (mirrors the
        # personal-wallet keyfile convention used elsewhere).
        try:
            cold_seed = bytes.fromhex(cold_seed.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass  # already raw bytes
        try:
            cold_entity = Entity.create(cold_seed)
        except Exception as e:
            print(f"Error: cold key file did not yield a valid Entity: {e}")
            sys.exit(1)
        if cold_entity.public_key != existing_authority_pk:
            print(
                "Error: --cold-key-path public key does not match the "
                "currently-installed authority key on chain."
            )
            print(f"  installed: {existing_authority_pk.hex()}")
            print(f"  provided:  {cold_entity.public_key.hex()}")
            sys.exit(1)
        tx = create_set_authority_key_rebind_transaction(
            entity, new_authority_key=authority_pubkey,
            nonce=nonce, fee=fee,
            existing_cold_keypair=cold_entity.keypair,
        )
    else:
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
    # WOTS+ Merkle keygen takes ~20-30 min at the production tree
    # height -- both --data-dir (daemon-coresident) and personal-wallet
    # paths route through the shared HMAC-authenticated cache via
    # _resolve_signing_entity so subsequent invocations are warm.  Note:
    # this only saves regen of the CURRENT tree; the new (post-rotation)
    # tree still has to be derived below.
    data_dir = getattr(args, "data_dir", None)
    entity = _resolve_signing_entity(private_key, args)
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
    # Cross-process WOTS+ leaf-reuse defense via unified chokepoint
    # (audit r54 #2).  Critical for rotate-key in particular: the
    # rotation tx itself burns a leaf on the current tree, AND
    # operators typically run this on the validator host where the
    # daemon's block-signing loop is also racing on the same tree.
    _resolve_signing_leaf(
        host, port, entity,
        data_dir=data_dir, watermark_fallback=watermark,
    )

    # Display the watermark against the entity's stored tree_height
    # rather than the global config -- personal wallets at h=16 and
    # validators at h=20 coexist, so a single constant produces a
    # nonsensical denominator for one of them.
    _disp_height, _ = _resolve_entity_tree_height(
        host, port, entity.entity_id_hex,
    )
    print(f"Current rotation number: {current_rotation}")
    print(f"Current leaf watermark:  {watermark} / {1 << _disp_height}")
    print(f"\nDeriving fresh Merkle tree (rotation {current_rotation})...")
    progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Building new tree")
    new_kp = derive_rotated_keypair(
        entity, rotation_number=current_rotation, progress=progress,
    )

    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper.  ``KEY_ROTATION_FEE``
    # remains as a defense-in-depth local hint -- the server's live
    # floor is the authoritative gate.
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="rotate-key",
        host=host,
        port=port,
        args=args,
        local_min_hint=KEY_ROTATION_FEE,
    )
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

    # Read-only lookup branch: same logic as cmd_balance.  Lets an
    # operator inspect another validator's leaf-consumption without
    # holding their private key.
    entity_id_hex = _read_only_entity_id_hex(args)
    if entity_id_hex is None:
        private_key = _resolve_private_key(args)
        entity = _resolve_signing_entity(private_key, args)
        entity_id_hex = entity.entity_id_hex

    # Operator-introspection: query the leaf watermark of THIS
    # entity from the LOCAL node.  Default to localhost so the
    # rotation-urgency answer is not silently sourced from a
    # different validator's chain view.
    host, port = _parse_server_local_default(args.server)
    from client import rpc_call

    status = rpc_call(host, port, "get_key_status", {
        "entity_id": entity_id_hex,
    })
    if not status.get("ok"):
        print(f"Error: {status.get('error')}")
        sys.exit(1)
    result = status["result"]

    # Resolve the per-entity tree_height from chain state -- personal
    # wallets at h=16 and validators at h=20 coexist, so a single
    # global constant gives the wrong denominator for at least one
    # of them.
    tree_height, th_fallback = _resolve_entity_tree_height(
        host, port, entity_id_hex,
    )
    capacity = 1 << tree_height
    used = result["leaf_watermark"]
    remaining = capacity - used
    pct_used = (used * 100) // capacity if capacity else 0

    print("\n=== Key Status ===\n")
    print(f"  Entity ID:       {entity_id_hex}")
    print(f"  Public key:      {result['public_key']}")
    print(f"  Rotation #:      {result['rotation_number']}")
    print(f"  Tree height:     {tree_height}"
          f"{'  (assumed; entity not on chain yet)' if th_fallback else ''}")
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
    cold = _resolve_signing_entity(private_key, args)

    # Cold-key cross-process leaf-reuse defense.  The cold key has no
    # chain-side leaf watermark RPC (revoke is nonce-free), so the
    # on-disk cursor is the ONLY barrier between two consecutive
    # emergency-revoke runs both signing at leaf 0.  Bind the cursor
    # here -- the print-only / air-gapped path also benefits, since
    # the operator may pre-sign multiple staged revokes from one
    # cold-key host.
    _bind_persistent_leaf_index(
        cold, chain_leaf=0, data_dir=getattr(args, "data_dir", None),
    )

    print_only = bool(getattr(args, "print_only", False))

    # Revoke is nonce-free, so signing needs no RPC roundtrip -- that
    # is what makes the "keep a pre-signed revoke tx on paper" workflow
    # practical.  In --print-only mode we DO NOT touch the network at
    # all (this is meant to run on an air-gapped machine), so we
    # don't import rpc_call or compute a `host, port` either.
    #
    # Fee defaults differ by mode:
    #   * Live broadcast: MIN_FEE_POST_FLAT, the current-floor minimum.
    #   * Pre-sign:       10 * MIN_FEE_POST_FLAT, a generous pad against
    #                     a future fee-floor governance bump.  A
    #                     pre-signed revoke that pays today's floor
    #                     becomes invalid the day governance raises
    #                     MIN_FEE_POST_FLAT past that value, which is
    #                     the wrong failure mode for an offline kill-
    #                     switch you only reach for under duress.  The
    #                     extra tokens come out of the cold-key holder's
    #                     balance only when (and if) the revoke fires.
    from messagechain.config import (
        MIN_FEE_POST_FLAT,
        REVOKE_TX_DEFAULT_VALID_FOR_BLOCKS,
    )
    if args.fee is not None:
        fee = args.fee
    elif print_only:
        fee = MIN_FEE_POST_FLAT * 10
    else:
        fee = MIN_FEE_POST_FLAT

    # Tier 26 window: every signed revoke commits to a chain-height
    # range so leaked hexes expire.  In live (broadcast) mode we probe
    # the tip via RPC so the window starts at "now"; in print-only
    # mode we cannot touch the network, so valid_from defaults to 0
    # (the window opens at genesis) and the operator gets the FULL
    # configured width as their re-sign deadline.  Pre-fork the window
    # is harmlessly carried in the wire format but not enforced; post-
    # fork the chain rejects out-of-window blobs.
    # getattr fallback keeps older test fixtures (which build Namespaces
    # by hand and predate this flag) working without code surgery in
    # every test that constructs an argparse.Namespace for cmd_
    # emergency_revoke.
    raw_valid_for = getattr(args, "valid_for_blocks", None)
    valid_for = (
        raw_valid_for
        if raw_valid_for is not None
        else REVOKE_TX_DEFAULT_VALID_FOR_BLOCKS
    )
    if print_only:
        valid_from = 0
    else:
        # Probe tip below; for now hold None and fill it in after the
        # rpc_call (we need `host, port` first, which is computed
        # further down for the live branch).
        valid_from = None
    valid_to = None  # filled in once valid_from is resolved
    if valid_from is not None:
        valid_to = valid_from + valid_for

    tx = None  # built once valid_from / valid_to are settled
    if print_only:
        tx = create_revoke_transaction(
            cold, fee=fee, entity_id=target_entity_id,
            valid_from_height=valid_from,
            valid_to_height=valid_to,
        )

    if print_only:
        # Air-gapped pre-sign path: print the serialized tx as hex on
        # stdout, no tip probe, no confirmation, no broadcast.  The
        # operator is responsible for getting these bytes onto durable
        # offline storage (paper QR + USB recommended) and for running
        # `messagechain broadcast-revoke --hex <bytes>` if/when the
        # kill-switch needs to fire.
        tx_hex = tx.to_bytes().hex()
        print("=== Pre-signed Revoke (DO NOT BROADCAST YET) ===\n")
        print(f"  Target entity: {target_entity_id.hex()}")
        print(f"  Fee paid on broadcast: {fee} tokens")
        print(f"  Tx hash: {tx.tx_hash.hex()}")
        # Tier 26 window: surface BOTH endpoints so the operator
        # records the re-sign deadline alongside the hex.  An expired
        # blob is inert post-fork, so this is the "ladder" the
        # operator climbs every quarter.
        print(f"  Valid from height: {tx.valid_from_height}")
        print(f"  Valid to height:   {tx.valid_to_height}  "
              f"(re-sign before this height -- "
              f"~{(tx.valid_to_height - tx.valid_from_height) * 600 // 86400} "
              "days at 600s blocks)")
        print(f"  Bytes (length {len(tx_hex)//2}):\n")
        print(tx_hex)
        print()
        print("Store the hex above OFFLINE -- paper QR + an encrypted")
        print("USB drive in two physical locations is the recommended")
        print("pattern. Anyone with these bytes can permanently disable")
        print("the target validator (no funds are stolen, but block")
        print("production stops and stake enters the unbonding queue).")
        print()
        print("To fire the kill-switch later:")
        print("  messagechain broadcast-revoke --hex <paste-bytes>")
        return

    host, port = _parse_server(args.server)
    from client import rpc_call

    # Probe tip height so the warning reflects the CURRENTLY active
    # unbonding fork.  The same probe seeds the Tier 26 window so the
    # signed blob's valid_from is "now" and valid_to is "now + N".
    tip_resp = rpc_call(host, port, "get_chain_info", {})
    revoke_tip: int | None = None
    if tip_resp.get("ok"):
        count = tip_resp["result"].get("height", 0) or 0
        revoke_tip = max(count - 1, 0)

    # Now that we have the tip, build the live revoke with a window
    # anchored at the current chain height.  If the probe failed (no
    # tip), default to 0 -- pre-fork the chain accepts un-windowed
    # revokes anyway, and post-fork an unreachable RPC means the
    # operator will see a clear "window not yet active" rejection
    # rather than a silent broadcast.
    valid_from = revoke_tip if revoke_tip is not None else 0
    valid_to = valid_from + valid_for
    tx = create_revoke_transaction(
        cold, fee=fee, entity_id=target_entity_id,
        valid_from_height=valid_from,
        valid_to_height=valid_to,
    )

    if not getattr(args, "yes", False):
        tid_hex = target_entity_id.hex()
        tid_short = f"{tid_hex[:16]}...{tid_hex[-8:]}"
        print(f"\nAbout to emergency-revoke:")
        print(f"  Target entity: {tid_short}")
        print(f"  (full: {tid_hex})")
        print(f"  Fee:           {fee} tokens")
        print(
            f"  Window:        height {tx.valid_from_height}..{tx.valid_to_height} "
            f"(width {valid_for} blocks)"
        )
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


def cmd_broadcast_revoke(args):
    """Broadcast a pre-signed revoke tx (companion to emergency-revoke --print-only).

    Reads the saved hex blob, deserializes it as a RevokeTransaction,
    and submits it via the same RPC path as the build-and-broadcast
    flow.  No cold key required at this point -- the bytes are already
    signed; the host doing the broadcast just needs network access to
    a node.
    """
    from messagechain.core.emergency_revoke import RevokeTransaction
    from client import rpc_call

    if args.tx_file is not None:
        try:
            with open(args.tx_file, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            print(f"Error: could not read --file: {e}")
            sys.exit(1)
        tx_hex = "".join(raw.split())
    else:
        tx_hex = "".join(args.tx_hex.split())

    try:
        tx_bytes = bytes.fromhex(tx_hex)
    except ValueError:
        print("Error: input is not valid hex.")
        sys.exit(1)

    try:
        tx = RevokeTransaction.from_bytes(tx_bytes)
    except (ValueError, IndexError) as e:
        print(f"Error: bytes do not parse as a RevokeTransaction: {e}")
        sys.exit(1)

    if not getattr(args, "yes", False):
        tid_hex = tx.entity_id.hex()
        tid_short = f"{tid_hex[:16]}...{tid_hex[-8:]}"
        print("=== Broadcast Pre-signed Revoke ===\n")
        print(f"  Target entity: {tid_short}")
        print(f"  (full: {tid_hex})")
        print(f"  Fee:           {tx.fee} tokens")
        print(f"  Signed at ts:  {int(tx.timestamp)} (epoch sec)")
        print(f"  Tx hash:       {tx.tx_hash.hex()}")
        print()
        print("This permanently disables the target validator. Block")
        print("production stops immediately; staked funds release to")
        print("the cold-key holder after the standard unbonding period.")
        confirm = input(
            "\nBroadcast this pre-signed revoke (type 'yes' to proceed): "
        ).strip().lower()
        if confirm != "yes":
            print("Broadcast cancelled.")
            sys.exit(0)

    host, port = _parse_server(args.server)
    print(f"Broadcasting pre-signed revoke for {tx.entity_id.hex()[:16]}...")
    response = rpc_call(host, port, "emergency_revoke", {
        "transaction": tx.serialize(),
    })
    if response.get("ok"):
        result = response["result"]
        print("\nRevoke applied!")
        print(f"  Entity ID: {result['entity_id']}")
        print(f"  TX hash:   {result['tx_hash']}")
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_set_receipt_subtree_root(args):
    """Register this validator's receipt-subtree root on-chain (cold key)."""
    from messagechain.identity.identity import Entity
    from messagechain.core.receipt_subtree_root import (
        create_set_receipt_subtree_root_transaction,
    )

    print("=== Set Receipt Subtree Root ===\n")
    print("Authenticate with your COLD (authority) key. Registers the WOTS+")
    print("root that verifies this validator's submission receipts. Without")
    print("this, receipts fail verification at evidence-admission time and")
    print("the censorship-evidence pipeline collapses for this validator.\n")

    private_key = _resolve_private_key(args)
    cold = _resolve_signing_entity(private_key, args)

    # Advance past prior cold-key uses.  Cold-key leaf state is NOT
    # tracked on chain (only the hot-key watermark is updated by
    # SetReceiptSubtreeRoot.apply -- see the comment in
    # apply_set_receipt_subtree_root).  Without --cold-leaf, every
    # invocation signs at leaf 0, so a second invocation with a
    # different timestamp is leaf-reuse and the chain rejects.
    # Operators must self-track; we surface the leaf used after
    # signing so the next invocation is N+1.
    cold_leaf = max(0, int(getattr(args, "cold_leaf", 0)))
    # Cold-key cross-process leaf-reuse defense.  The on-disk cursor
    # closes the "operator forgot --cold-leaf and signs at leaf 0
    # twice" failure mode: even if --cold-leaf is omitted, the
    # persistent cursor advances the floor past the last consumed
    # leaf so a second invocation never reuses one.
    _bind_persistent_leaf_index(
        cold, chain_leaf=cold_leaf,
        data_dir=getattr(args, "data_dir", None),
    )

    host, port = _parse_server(args.server)
    from client import rpc_call

    # Resolve the entity_id we're registering for.  Default: derive
    # from the cold key.  In hot/cold split the cold key's entity_id
    # equals the validator's entity_id (set-authority-key changes
    # which key signs authority txs, not which entity_id is on chain).
    if args.entity_id:
        try:
            target_entity_id = bytes.fromhex(args.entity_id.strip())
        except ValueError:
            print("Error: --entity-id must be valid hex.")
            sys.exit(1)
        if len(target_entity_id) != 32:
            print(
                f"Error: entity ID must be 32 bytes, got "
                f"{len(target_entity_id)}."
            )
            sys.exit(1)
    else:
        target_entity_id = cold.entity_id

    # Resolve the root.  --root wins; otherwise fetch from the running
    # validator at --server.  This avoids forcing operators to scrape
    # the root out of journald / cache files.
    if args.root:
        try:
            root_pk = bytes.fromhex(args.root.strip())
        except ValueError:
            print("Error: --root must be valid hex.")
            sys.exit(1)
        if len(root_pk) != 32:
            print(
                f"Error: root public key must be 32 bytes, got "
                f"{len(root_pk)}."
            )
            sys.exit(1)
        registered_hex = "<not fetched -- pass without --root to compare>"
    else:
        resp = rpc_call(host, port, "get_local_receipt_root", {})
        if not resp.get("ok"):
            print(
                f"Error: could not fetch local receipt root from "
                f"{host}:{port}: {resp.get('error')}"
            )
            sys.exit(1)
        result = resp["result"]
        if not result.get("installed"):
            print(
                f"Error: validator at {host}:{port} reports no receipt "
                f"issuer installed (relay-only node?)."
            )
            sys.exit(1)
        remote_entity = bytes.fromhex(result["entity_id"])
        if remote_entity != target_entity_id:
            print(
                f"Error: validator at {host}:{port} is entity "
                f"{result['entity_id'][:16]}..., but you are registering "
                f"a root for entity {target_entity_id.hex()[:16]}..."
            )
            print(
                "       This usually means you are broadcasting through a "
                "PEER validator (not the one being registered).  That is "
                "fine, but the CLI cannot fetch the local root from a "
                "different entity's server.  Re-run with --root <hex> "
                "to skip the local-root fetch and broadcast through this "
                "peer.  The root value is in the target validator's boot "
                "log: 'Receipt issuer installed: entity=... root=<hex>'."
            )
            sys.exit(1)
        root_pk = bytes.fromhex(result["root_public_key"])
        registered_hex = (
            result["registered_root"][:16] + "..."
            if result.get("registered_root") else "<none>"
        )
        if not result.get("registration_needed"):
            print(
                f"Local root {root_pk.hex()[:16]}... already matches "
                f"on-chain root for this entity. Nothing to do."
            )
            sys.exit(0)

    # SetReceiptSubtreeRoot is nonce-free (idempotent / pre-signable).
    # Default fee mirrors emergency-revoke / set-authority-key.
    from messagechain.config import MIN_FEE_POST_FLAT
    fee = args.fee if args.fee is not None else MIN_FEE_POST_FLAT
    tx = create_set_receipt_subtree_root_transaction(
        entity_id=target_entity_id,
        root_public_key=root_pk,
        authority_signer=cold,
        fee=fee,
    )

    if not getattr(args, "yes", False) and not args.print_tx:
        print(f"\nAbout to register receipt-subtree root:")
        print(f"  Validator entity:   {target_entity_id.hex()[:16]}...")
        print(f"  New root:           {root_pk.hex()[:16]}...")
        print(f"  Currently on-chain: {registered_hex}")
        print(f"  Fee:                {fee} tokens")
        print(
            "  Signed by the cold authority key.  Idempotent -- "
            "submitting the same root again is a no-op."
        )
        confirm = input(
            "\nConfirm set-receipt-subtree-root (type 'yes' to proceed): "
        ).strip().lower()
        if confirm != "yes":
            print("Set-receipt-subtree-root cancelled.")
            sys.exit(0)

    if args.print_tx:
        import json
        print(json.dumps(tx.serialize(), indent=2))
        return

    response = rpc_call(host, port, "set_receipt_subtree_root", {
        "transaction": tx.serialize(),
    })
    if response.get("ok"):
        result = response["result"]
        print(f"\nReceipt-subtree root submitted!")
        print(f"  Entity ID:  {result['entity_id']}")
        print(f"  Root:       {result['root_public_key']}")
        print(f"  TX hash:    {result['tx_hash']}")
        print(f"  Status:     {result['status']}")
        print(f"  Cold leaf:  {tx.signature.leaf_index} (BURNED)")
        print(
            f"\nNEXT TIME you sign anything with this cold key, pass "
            f"--cold-leaf {tx.signature.leaf_index + 1} (or higher) to "
            f"avoid WOTS+ leaf-reuse rejection.  Cold-key leaf state is "
            f"not tracked on-chain; only the operator knows."
        )
        print(
            "\nVerify on-chain with `messagechain info --server "
            f"{host}:{port}` (or check via "
            f"get_local_receipt_root RPC) after the next block lands."
        )
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_propose(args):
    """Create a governance proposal."""
    from messagechain.identity.identity import Entity
    from messagechain.governance.governance import (
        create_proposal,
        proposal_fee_floor,
    )

    print("=== Create Proposal ===\n")
    print(f"  Title: {args.title}")
    print(f"  Description: {args.description}")

    private_key = _resolve_private_key(args, personal_wallet=True)
    entity = _resolve_signing_entity(private_key, args)
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
    # Cross-process WOTS+ leaf-reuse defense via unified chokepoint
    # (audit r54 #2).  cmd_propose has no --data-dir surface today, so
    # this routes to the home-dir default unconditionally.
    _resolve_signing_leaf(
        host, port, entity,
        data_dir=getattr(args, "data_dir", None),
        watermark_fallback=watermark,
    )

    # Query the live chain tip so the auto-fee picks the right floor
    # rule.  Pre-Tier-19: flat GOVERNANCE_PROPOSAL_FEE.  Post-Tier-19:
    # GOVERNANCE_PROPOSAL_FEE_TIER19 + per-byte surcharge * payload.
    # On RPC failure fall back to height=None (legacy floor) -- the
    # node will reject under-priced submissions and the user can retry
    # with explicit --fee.
    info_resp = rpc_call(host, port, "get_chain_info", {})
    target_height = None
    if info_resp.get("ok"):
        count = info_resp["result"].get("height", 0) or 0
        target_height = max(count - 1, 0) + 1
    payload_bytes = (
        len(args.title.encode("utf-8"))
        + len(args.description.encode("utf-8"))
    )
    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper.  ``proposal_fee_floor``
    # is a chain-aware local hint -- defense-in-depth on top of the
    # server's authoritative live quote.
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="propose",
        host=host,
        port=port,
        args=args,
        estimate_extra={"payload_bytes": payload_bytes},
        auto_fee_extra={"payload_bytes": payload_bytes},
        local_min_hint=proposal_fee_floor(payload_bytes, target_height),
        target_height=target_height,
    )

    # Fee preview + confirmation banner.  Governance proposals charge
    # the largest single fee in the protocol (GOVERNANCE_PROPOSAL_FEE
    # baseline = 10,000 tokens) and a typo on title/description is an
    # irreversible burn with no recovery path.  Show the number with
    # thousands separators so the magnitude is unmistakable, then ask
    # for explicit "yes" before signing/submitting.  Mirrors the
    # cmd_transfer pattern shipped in 1.48.0; --yes / -y bypasses the
    # prompt for scripts / CI (gcloud compute ssh + sudo doesn't always
    # deliver piped stdin to input()).
    description_bytes = len(args.description.encode("utf-8"))
    print()
    print("About to propose:")
    print(f"  Title:       {args.title}")
    print(f"  Description: {description_bytes} bytes")
    print(f"  Fee:         {fee:,} tokens  (governance proposal fee)")
    print(f"  Entity:      {entity.entity_id_hex[:16]}...")
    if not getattr(args, "yes", False):
        try:
            confirm = input(
                "\nConfirm propose (type 'yes' to proceed): "
            ).strip().lower()
        except EOFError:
            print("\nProposal cancelled (no stdin).")
            sys.exit(1)
        if confirm != "yes":
            print("Proposal cancelled.")
            sys.exit(0)
    else:
        print("\nSkipping confirmation prompt (--yes).")

    tx = create_proposal(
        entity, args.title, args.description, fee=fee,
        current_height=target_height,
    )

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

    private_key = _resolve_private_key(args, personal_wallet=True)
    entity = _resolve_signing_entity(private_key, args)
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
    # Cross-process WOTS+ leaf-reuse defense via unified chokepoint
    # (audit r54 #2).
    _resolve_signing_leaf(
        host, port, entity,
        data_dir=getattr(args, "data_dir", None),
        watermark_fallback=watermark,
    )

    from messagechain.validation import parse_hex
    proposal_id = parse_hex(args.proposal, expected_len=32)
    if proposal_id is None:
        print(f"Error: Invalid proposal ID (must be 32 bytes hex): {args.proposal}")
        sys.exit(1)

    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper.  ``GOVERNANCE_VOTE_FEE``
    # is a defense-in-depth local hint; server's live floor is the
    # authoritative gate.
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="vote",
        host=host,
        port=port,
        args=args,
        local_min_hint=GOVERNANCE_VOTE_FEE,
    )

    # Fee preview (no confirm prompt -- vote fees are small enough
    # that an extra interactive step is over-friction for the user).
    # Surfacing the cost is still load-bearing: prior to this the user
    # had no signal at all about how much the vote was about to burn.
    print(f"  Fee:     {fee:,} tokens  (governance vote fee)")

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


def cmd_react(args):
    """Cast an up/down/clear reaction against a message tx_hash or entity_id."""
    from messagechain.identity.identity import Entity
    from messagechain.core.reaction import (
        create_react_transaction,
        REACT_CHOICE_CLEAR,
        REACT_CHOICE_UP,
        REACT_CHOICE_DOWN,
    )

    choice_map = {
        "up": REACT_CHOICE_UP,
        "down": REACT_CHOICE_DOWN,
        "clear": REACT_CHOICE_CLEAR,
    }
    choice = choice_map[args.choice]
    target_is_user = (args.target_type == "user")

    target_hex = args.target.strip()
    if len(target_hex) != 64:
        print(
            f"Error: target must be exactly 64 hex chars "
            f"(got {len(target_hex)})."
        )
        sys.exit(1)
    try:
        target_bytes = bytes.fromhex(target_hex)
    except ValueError:
        print("Error: target is not valid hex.")
        sys.exit(1)

    label = "user-trust" if target_is_user else "message-react"
    print(f"=== React ({label}, {args.choice.upper()}) ===\n")
    print(f"  Target: {target_hex[:16]}...")

    private_key = _resolve_private_key(args, personal_wallet=True)
    entity = _resolve_signing_entity(private_key, args)
    print(f"\nReacting as: {entity.entity_id_hex[:16]}...")

    if target_is_user and target_bytes == entity.entity_id:
        print("Error: cannot cast a user-trust vote on yourself.")
        sys.exit(1)

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
    # Cross-process WOTS+ leaf-reuse defense via unified chokepoint
    # (audit r54 #2).
    _resolve_signing_leaf(
        host, port, entity,
        data_dir=getattr(args, "data_dir", None),
        watermark_fallback=watermark,
    )

    # Audit r48 #3: route through the shared
    # ``_resolve_fee_with_server_floor`` helper so explicit ``--fee``
    # validation uses the server's live floor (not silently accepted
    # only to bounce at the RPC).
    fee, _server_min_fee = _resolve_fee_with_server_floor(
        kind="react",
        host=host,
        port=port,
        args=args,
    )

    # Fee preview (no confirm prompt -- reaction fees are small).
    # Without this print the user had zero signal about cost between
    # "Reacting as ..." and the eventual success/failure line.
    print(f"  Fee:     {fee:,} tokens  (reaction fee)")

    tx = create_react_transaction(
        entity,
        target=target_bytes,
        target_is_user=target_is_user,
        choice=choice,
        nonce=nonce,
        fee=fee,
    )

    response = rpc_call(host, port, "submit_react", {
        "transaction": tx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        tx_hash_hex = result["tx_hash"]
        print(f"\nReaction submitted!")
        print(f"  TX hash: {tx_hash_hex}")
        print(f"  Fee:     {result.get('fee', fee)} tokens")
        # Audit r45 #3: persist the validator-issued SubmissionReceipt
        # to disk so the user has a slashable-evidence artifact if a
        # coerced validator silently drops this reaction.  Mirrors the
        # same pattern as cmd_send / cmd_transfer.  Best-effort write.
        receipt_hex = result.get("receipt")
        if receipt_hex:
            try:
                bundle_path = _save_receipt_bundle(
                    tx_hash_hex=tx_hash_hex,
                    receipt_hex=receipt_hex,
                    tx=tx,
                    tx_kind="react",
                )
                print(f"  Receipt saved: {bundle_path}")
            except OSError as e:
                print(
                    f"  (warning: could not save receipt bundle to "
                    f"disk: {e})"
                )
    else:
        print(f"\nFailed: {response.get('error')}")
        sys.exit(1)


def cmd_generate_key(_args):
    """Generate a full key pair offline (private key, public key, entity ID)."""
    import os
    from messagechain.identity.identity import Entity
    from messagechain.identity.key_encoding import encode_private_key
    from messagechain.identity.mnemonic import encode_to_mnemonic
    from messagechain.config import WALLET_DEFAULT_TREE_HEIGHT

    key = os.urandom(32)
    tree_height = WALLET_DEFAULT_TREE_HEIGHT

    # Print the recovery phrase FIRST -- before keygen runs.  At the
    # production wallet height (h=16, ~65k leaves) keygen takes minutes
    # even after parallelization; at any height it dominates the wall
    # clock.  The phrase, the hex form, and the warning are all pure
    # functions of `key` (no Merkle work needed), so we can show them
    # immediately and let the user back up their 24 words DURING the
    # keygen wait instead of staring at a silent progress bar.  The
    # public key / address still require the Merkle root, so they
    # land at the end -- but by then the user is done writing.
    mnemonic = encode_to_mnemonic(key)
    encoded_hex = encode_private_key(key)
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
    print(f"\n  The recovery phrase follows BIP-39 - every word comes from a")
    print("  known 2048-word list, with a built-in checksum that detects")
    print("  single-word transcription errors when you type it back.")
    print(f"\n  WARNING: Anyone with these words controls your account.")
    print("  There is no recovery. This phrase will NOT be shown again.")
    print(f"\n  Back up your phrase NOW -- your wallet address is being")
    print(f"  generated below ({1 << tree_height} one-time signing keys).")
    # Force the phrase to disk before keygen kicks off, so an interrupt
    # (Ctrl-C, SIGTERM, terminal close) during the long wait still leaves
    # the user with the printed phrase.  Without flush() Python's stdout
    # buffer can hold the phrase until process exit, defeating the point
    # of printing it early.
    sys.stdout.flush()

    progress = _make_progress_reporter(1 << tree_height, "Building key tree")
    entity = Entity.create(key, tree_height=tree_height, progress=progress)
    # Warm the personal-wallet cache so the README's next two
    # commands (`verify-key` then `balance`) are cache HITS instead of
    # full re-derivations.  Without this, the user pays the keygen cost
    # multiple times before they've done anything useful.  Best-effort:
    # a permission error / full disk must NOT crash key generation --
    # the key was generated successfully and the cache is purely a UX
    # optimization for the next command on this machine.
    try:
        from messagechain.identity.keypair_cache import (
            personal_wallet_cache_path,
            personal_wallet_cache_dir,
            encode_keypair_cache,
            _atomic_write,
        )
        cache_dir = personal_wallet_cache_dir()
        cache_path = personal_wallet_cache_path(key, tree_height)
        os.makedirs(cache_dir, exist_ok=True)
        blob = encode_keypair_cache(entity, key, tree_height)
        _atomic_write(cache_path, blob)
    except Exception:  # noqa: BLE001 -- cache is best-effort
        pass

    from messagechain.identity.address import encode_address
    print(f"\n  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"  Address:     {encode_address(entity.entity_id)}")
    print(f"               ^ share this `mc1...` form to receive funds")
    print(f"\n  IMPORTANT: Verify your backup before deleting this key.")
    print("  Run: messagechain verify-key")


def cmd_verify_key(args):
    """Re-derive public key and entity ID from a private key (offline)."""
    from messagechain.identity.identity import Entity

    print("=== Verify Key Backup ===\n")
    print("Enter your private key to verify it derives the expected identity.\n")

    private_key = _resolve_private_key(args)
    # Route through the shared cache resolver so a verify-key call
    # immediately after generate-key is a cache HIT rather than a
    # second 20-minute keygen.  The shared helper falls through to
    # ``Entity.create`` on cache miss, so a fresh-machine verify-key
    # of an externally-generated key still produces the right
    # identity -- it just pays the keygen once and warms the cache
    # for the next command.
    try:
        entity = _resolve_signing_entity(private_key, args)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    from messagechain.identity.address import encode_address
    print(f"\n  Public key:  {entity.public_key.hex()}")
    print(f"  Entity ID:   {entity.entity_id_hex}")
    print(f"  Address:     {encode_address(entity.entity_id)}")
    print(f"\n  Confirm all three match your records.")


def cmd_read(args):
    """Read recent messages from the chain.

    The CLI's `read` listing mirrors the public-feed UI surface so
    the same affordances are available to a CLI user - short tx_hash
    (paste-friendly into ``messagechain receipt``), `prev ->` arrow
    when the message has a predecessor, ``[community-id]`` chip
    when the post belongs to a Tier 25 community, and ASCII up/down
    vote totals when at least one vote has been cast.

    Optional client-side filters:
      --community-id <handle>   only show posts in this community
      --by-address <hex|mc1...> only show posts from this entity

    Filters apply on the client; server-side filter would require a
    new RPC param.  At --last counts that fit comfortably in a
    single RPC response (default 10), client-side filtering is a
    free win.
    """
    host, port = _parse_server(args.server)

    from client import rpc_call
    response = rpc_call(host, port, "get_messages", {"count": args.last})

    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    messages = response["result"]["messages"]
    if not messages:
        print("No messages on chain yet.")
        return

    # Resolve --by-address: accept both bare hex and mc1... bech32 form.
    filter_address_hex = None
    raw_addr = getattr(args, "by_address", None)
    if raw_addr:
        s = raw_addr.strip()
        if s.lower().startswith("mc1"):
            try:
                from messagechain.identity.address import decode_address
                filter_address_hex = decode_address(s).hex()
            except Exception as e:
                print(f"Error: invalid address '{raw_addr}': {e}")
                sys.exit(1)
        else:
            filter_address_hex = s.lower()

    filter_community = getattr(args, "community_id", None)

    # Client-side filtering - keep the schema we sent to the server
    # untouched.  Both filters are opt-in; absent flags are no-ops.
    def _keep(msg):
        if filter_community is not None:
            if msg.get("community_id") != filter_community:
                return False
        if filter_address_hex is not None:
            if (msg.get("entity_id") or "").lower() != filter_address_hex:
                return False
        return True

    filtered = [m for m in messages if _keep(m)]
    if not filtered:
        if filter_community or filter_address_hex:
            print("No matching messages on chain.")
            return
        print("No messages on chain yet.")
        return

    import datetime
    print(f"=== Recent Messages ({len(filtered)}) ===\n")
    for msg in filtered:
        ts = datetime.datetime.fromtimestamp(
            msg["timestamp"]
        ).strftime("%Y-%m-%d %H:%M:%S")
        entity = (msg.get("entity_id") or "")[:16]
        # First line: timestamp, sender prefix, optional community chip,
        # short tx hash for `messagechain receipt` round-trip.
        head = f"  [{ts}] {entity}..."
        community_id = msg.get("community_id")
        if community_id:
            head += f"  [{community_id}]"
        tx_hash = msg.get("tx_hash") or ""
        if tx_hash:
            head += f"  tx {tx_hash[:12]}"
        print(head)
        # Full hash on its own indented line so a CLI user can
        # triple-click + paste into `react --target <tx>` /
        # `receipt <tx>` / `submit-evidence censorship --receipt
        # <bundle>` without round-tripping through the web feed.
        # Every command that consumes a tx_hash hard-rejects
        # anything other than the full 64-hex form.
        if tx_hash:
            print(f"  id {tx_hash}")
        # Optional `prev` arrow on its own line so the eye can spot
        # threaded replies / multi-tx continuations.  Render the
        # full 64-hex prev hash (not a truncated prefix) so the
        # user can compose a follow-up react / receipt against the
        # parent without leaving the CLI.  ASCII -> arrow to keep
        # cli.py source ASCII-only (Windows cp1252 console encoding
        # crashes on Unicode in argparse help output).
        prev = msg.get("prev")
        if prev:
            print(f"  prev -> {prev}")
        print(f"  {msg.get('message', '')}")
        # Vote totals only when at least one vote has been cast.
        # ASCII "up"/"down" labels (the web feed uses real triangle
        # glyphs; the CLI source must stay in cp1252).
        ups = int(msg.get("ups") or 0)
        downs = int(msg.get("downs") or 0)
        if ups + downs > 0:
            up_pct = msg.get("up_pct")
            pct_str = (
                f"{up_pct:.0f}% up" if isinstance(up_pct, (int, float))
                else "-% up"
            )
            print(f"  up {ups}  down {downs}  {pct_str}")
        print()


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
    # Default to LOCAL node (operator-introspection): "is MY node
    # healthy" can't be answered by routing to a remote seed -- the
    # pre-fix behavior silently returned the OTHER validator's
    # state on a 2-node mainnet.  --server pins a remote target.
    host, port = _parse_server_local_default(args.server)

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
                # Compute leaf-usage % against the per-entity
                # tree_height from chain state.  Personal wallets at
                # h=16 and validators at h=20 coexist; a single
                # global constant gives the wrong denominator for one
                # of them and produces nonsensical >100% displays.
                tree_height, _th_fallback = _resolve_entity_tree_height(
                    host, port, entity_hex,
                )
                est_total = 1 << tree_height
                pct = (wm / est_total) * 100
                detail_suffix = ""
                if _th_fallback:
                    detail_suffix = (
                        " (entity not on chain yet; "
                        f"assuming tree_height={tree_height})"
                    )
                if pct < 50:
                    mark(0, "leaf usage",
                         f"{wm}/{est_total} ({pct:.1f}%)",
                         detail_suffix.strip(" -()") or "")
                elif pct < 80:
                    mark(0, "leaf usage",
                         f"{wm}/{est_total} ({pct:.1f}%)",
                         "plenty of signatures remaining" + detail_suffix)
                elif pct < 95:
                    mark(1, "leaf usage",
                         f"{wm}/{est_total} ({pct:.1f}%)",
                         "plan a key rotation in the next few months"
                         + detail_suffix)
                else:
                    mark(2, "leaf usage",
                         f"{wm}/{est_total} ({pct:.1f}%)",
                         "ROTATE NOW - signatures nearly exhausted"
                         + detail_suffix)

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
        # Full proposal_id on its own indented line so a CLI user
        # can copy it into `messagechain vote --proposal <id>` --
        # the vote command rejects anything other than the full
        # 64-hex form.
        print(f"    id {p['proposal_id']}")
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
    # Default to LOCAL node: "who is MY node connected to" is a
    # different question for every node, so the seed-pick default
    # would route to a remote validator and show its peer table
    # instead of yours.  --server pins a remote target.
    host, port = _parse_server_local_default(args.server)

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


def _validate_tx_hash_arg(tx_hash_arg: str) -> str | None:
    """Validate a CLI tx_hash argument.

    Returns the lowercased hex string on success, or None on failure
    (caller should print a friendly diagnostic and exit 1).  Centralised
    so `receipt` and `submit-evidence` validate identically.
    """
    if not isinstance(tx_hash_arg, str):
        return None
    s = tx_hash_arg.strip().lower()
    # Accept an optional "0x" prefix.
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64:
        return None
    try:
        bytes.fromhex(s)
    except ValueError:
        return None
    return s


def _fmt_duration(seconds: int | None) -> str:
    """Render an integer second count as a readable duration.

    Examples: 9 -> "9s", 600 -> "10m", 9012 -> "2h 30m".  Used by the
    receipt CLI for both included-tx waits and pending-tx ETAs.
    """
    if seconds is None or seconds < 0:
        return "?"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s" if seconds % 60 else f"{seconds // 60}m"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}m" if m else f"{h}h"


def cmd_receipt(args) -> int:
    """Show inclusion + permanence receipt for a transaction hash.

    The receipt CLI is the user-visible surface that names the
    protocol's defining property: slashing-backed permanence.  Every
    code path here explicitly mentions "permanent" / "can never be
    deleted" / "slashable evidence" in plain language -- this is a
    value-prop fix, not a generic explorer command.

    Three outcomes (driven by the get_tx_status RPC):
      * INCLUDED  - tx is on-chain; receipt names block, attesters,
                    and inclusion proof.
      * PENDING   - tx is in mempool; receipt names wait + escalation.
      * NOT FOUND - receipt names three possible causes + escalation.

    Read-only.  Never mutates chain state.  Returns 0 on a clean
    response (regardless of inclusion outcome); non-zero on protocol
    error / bad input.
    """
    # Input validation up front -- bad hex shouldn't even hit the RPC.
    tx_hash_hex = _validate_tx_hash_arg(args.tx_hash)
    if tx_hash_hex is None:
        print(
            f"Error: invalid tx hash '{args.tx_hash}'.\n"
            f"  Expected: 64 hex characters (32 bytes), optionally with a 0x prefix."
        )
        sys.exit(1)

    host, port = _parse_server(args.server)
    from client import rpc_call

    response = rpc_call(host, port, "get_tx_status", {"tx_hash": tx_hash_hex})
    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    result = response["result"]
    status = result.get("status", "?")

    print(f"=== MessageChain receipt for {tx_hash_hex[:16]}... ===\n")

    if status == "included":
        return _print_included_receipt(
            result, tx_hash_hex,
            primary_server=args.server,
            cross_check_server=getattr(args, "cross_check_server", None),
        )
    if status == "pending":
        return _print_pending_receipt(result, tx_hash_hex, host, port)
    if status == "not_found":
        return _print_not_found_receipt(tx_hash_hex)

    # Unknown status -- surface what we got but don't crash.
    print(f"Unknown status from node: {status}")
    print(f"Raw result: {result}")
    return 1


def _verify_included_proof(result: dict, tx_hash_hex: str) -> tuple[bool, str | None]:
    """Verify the merkle proof carried in a get_tx_status result.

    Returns ``(ok, error_message)``: ``ok=True`` means the proof
    deserializes cleanly AND verifies against the result's
    ``merkle_root``.  ``ok=False`` returns a human-readable
    error_message naming WHY -- missing proof, tampered sibling,
    root mismatch, malformed structure -- so the caller surfaces a
    specific WARNING instead of a generic "not verified".

    No I/O, no RPC -- this is pure structural / cryptographic
    verification of bytes the caller has already received.  Routes
    through the existing ``messagechain.core.spv.verify_merkle_proof``
    so the receipt CLI cannot drift away from the SPV verification
    every other light client uses.
    """
    proof_dict = result.get("merkle_proof")
    if not proof_dict:
        return False, "server returned no merkle_proof"
    merkle_root_hex = result.get("merkle_root", "")
    if not merkle_root_hex:
        return False, "server returned no merkle_root"
    try:
        merkle_root = bytes.fromhex(merkle_root_hex)
    except ValueError:
        return False, f"server's merkle_root is not valid hex: {merkle_root_hex!r}"
    try:
        tx_hash = bytes.fromhex(tx_hash_hex)
    except ValueError:
        return False, f"tx_hash_hex is not valid hex: {tx_hash_hex!r}"

    from messagechain.core.spv import MerkleProof, verify_merkle_proof
    try:
        proof = MerkleProof.deserialize(proof_dict)
    except (ValueError, KeyError, TypeError) as e:
        return False, f"merkle_proof is malformed: {e}"

    if not verify_merkle_proof(tx_hash, proof, merkle_root):
        return False, (
            "merkle_proof does NOT verify against the server's claimed "
            "merkle_root -- the server is either misconfigured or lying"
        )
    return True, None


def _cross_check_merkle_root(
    tx_hash_hex: str, primary_root_hex: str,
    cross_check_server: str,
) -> tuple[bool, str | None, str | None]:
    """Cross-check the inclusion merkle_root via a second RPC server.

    Calls ``get_tx_status`` on the cross-check server for the same
    tx_hash and compares its ``merkle_root`` to ``primary_root_hex``.
    Returns ``(agree, error, peer_root_hex)``:

      * agree=True  when the second server's root matches the primary's.
      * agree=False when they diverge OR when the cross-check call
        fails for any reason -- a non-responsive cross-check is NOT a
        permission slip to print the permanence guarantee.

    The ``error`` string names what went wrong so the caller can
    surface a specific WARNING; ``peer_root_hex`` is the cross-
    check server's reported root (or "" if unavailable) so the
    confidence/warning lines can name it.
    """
    try:
        peer_host, peer_port = _parse_server(cross_check_server)
    except Exception as e:
        return False, f"cross-check server address invalid: {e}", None
    from client import rpc_call
    try:
        resp = rpc_call(peer_host, peer_port, "get_tx_status", {
            "tx_hash": tx_hash_hex,
        })
    except Exception as e:
        return False, f"cross-check server unreachable: {e}", None
    if not resp.get("ok"):
        return False, (
            f"cross-check server returned error: {resp.get('error', '?')}"
        ), None
    peer_result = resp.get("result", {}) or {}
    peer_status = peer_result.get("status", "?")
    if peer_status != "included":
        return False, (
            f"cross-check server reports status={peer_status!r}, NOT 'included' "
            "-- the two servers disagree on whether the tx is on chain"
        ), None
    peer_root = peer_result.get("merkle_root", "") or ""
    if peer_root != primary_root_hex:
        return False, (
            "cross-check server's merkle_root differs from the primary's"
        ), peer_root
    return True, None, peer_root


def _print_included_receipt(
    result: dict, tx_hash_hex: str, *,
    primary_server: str | None = None,
    cross_check_server: str | None = None,
) -> int:
    """Format the INCLUDED-status receipt.

    The permanence guarantee ("This message is permanent.  It can
    never be deleted.") is the protocol's defining property and the
    receipt CLI is the user-visible surface that names it.  Before
    this fix the line was printed unconditionally on a
    ``status:"included"`` response, which let a colluding RPC
    server return a forged proof against a fabricated merkle_root
    and watch the CLI print full conviction.

    Verification gates (all must pass for the permanence text):
      1. The merkle_proof returned by the primary server MUST
         verify against the merkle_root the same response carries
         (closes "fabricated proof" attack).
      2. If --cross-check-server is set, both servers' merkle_root
         for this tx MUST agree (closes "fabricated block" attack).
      3. If --cross-check-server is unset, the receipt prints a
         softer caveat that names the flag the user could pass to
         confirm independently.

    On any verification failure the WARNING line is the dominant
    output and the permanence text is suppressed.
    """
    block_height = result.get("block_height", "?")
    block_hash = result.get("block_hash", "")
    tx_index = result.get("tx_index", "?")
    merkle_root = result.get("merkle_root", "")
    attesters = result.get("attesters", 0)
    total_validators = result.get("total_validators", 0)
    attesting_stake = result.get("attesting_stake", 0)
    total_stake = result.get("total_stake", 0)
    threshold_met = result.get("finality_threshold_met", False)
    num = result.get("finality_numerator", 2)
    den = result.get("finality_denominator", 3)

    print(f"  Status:        INCLUDED")
    print(f"  Block height:  {block_height}")
    if block_hash:
        print(f"  Block hash:    {block_hash[:32]}...")
    print(f"  Tx index:      {tx_index}")

    pct_str = ""
    if total_stake:
        pct = 100.0 * attesting_stake / total_stake
        pct_str = f" ({pct:.1f}% of stake)"
    pct_threshold = (100.0 * num / den) if den else 66.7
    print(
        f"  Attested by:   {attesters}/{total_validators} validators{pct_str}  "
        f"(threshold {pct_threshold:.1f}%)"
    )

    if threshold_met:
        print(f"  Finality:      JUSTIFIED -- {num}/{den} threshold met")
    else:
        print(f"  Finality:      pending -- {num}/{den} threshold not yet met")

    # -- Verification gate 1: proof verifies against primary's root --
    proof_ok, proof_err = _verify_included_proof(result, tx_hash_hex)

    # -- Verification gate 2: cross-check (when supplied) --
    cross_check_agree = None
    cross_check_err = None
    cross_check_peer_root = None
    if proof_ok and cross_check_server:
        cross_check_agree, cross_check_err, cross_check_peer_root = (
            _cross_check_merkle_root(
                tx_hash_hex, merkle_root, cross_check_server,
            )
        )

    # -- Headline output: permanence text ONLY if verified --
    print()
    if not proof_ok:
        # Gate 1 failed.  Permanence text is suppressed; surface a
        # specific WARNING so the user knows what to do next.
        print(
            f"  WARNING: server returned an inclusion claim with a missing "
            f"or invalid merkle proof -- cannot verify permanence.\n"
            f"           Reason: {proof_err}.\n"
            f"           Try a different --server or run a local node "
            f"to verify."
        )
    elif cross_check_agree is False:
        # Gate 2 failed.  Permanence text is suppressed; the two
        # servers disagree on chain state for this tx.
        peer_str = (
            f" (peer reported merkle_root: {cross_check_peer_root})"
            if cross_check_peer_root else ""
        )
        print(
            f"  WARNING: cross-check server {cross_check_server!r} disagrees "
            f"with the primary on this tx's merkle_root{peer_str}.\n"
            f"           Reason: {cross_check_err}.\n"
            f"           Cannot verify permanence -- one of the two servers "
            f"is lying or stale."
        )
    else:
        # Both gates passed (or only gate 1 + no cross-check).  The
        # mission of this command: name the guarantee.
        if threshold_met:
            print(
                "  This message is permanent.  It can never be deleted."
            )
        else:
            print(
                "  This message is on-chain.  Once the 2/3 attestation\n"
                "  threshold is met, it is permanent and can never be deleted."
            )
        print(
            "  Any validator that suppresses or rejects a future copy of\n"
            "  this transaction produces slashable evidence on chain (see\n"
            "  messagechain submit-evidence)."
        )
        # Confidence / caveat trailer naming the verification source.
        if cross_check_agree is True:
            print()
            print(
                f"  Independently verified against {cross_check_server} -- "
                f"merkle roots agree."
            )
        else:
            # cross_check_agree is None (no --cross-check-server passed).
            # Print the softer caveat naming the flag.
            print()
            srv_name = primary_server or "the server above"
            print(
                f"  Inclusion proof verified against the merkle_root "
                f"reported by {srv_name}.\n"
                f"  To independently confirm, pass "
                f"--cross-check-server <other_validator>."
            )

    # -- Inclusion proof: always print (it's data the user might want
    # to save).  Suppression only applies to the permanence headline.
    print()
    if merkle_root:
        print(f"  Inclusion proof:")
        print(f"    block merkle_root: {merkle_root}")
    proof = result.get("merkle_proof")
    if proof:
        siblings = proof.get("siblings", [])
        directions = proof.get("directions", [])
        print(f"    tx_index:          {proof.get('tx_index', tx_index)}")
        print(f"    path depth:        {len(siblings)}")
        for i, (s, d) in enumerate(zip(siblings, directions)):
            side = "L" if d else "R"
            print(f"      [{i:>2}] {side}  {s}")
    else:
        print("    (no proof emitted -- tx is recorded but outside the "
              "merkle inputs)")

    return 0


def _print_pending_receipt(
    result: dict, tx_hash_hex: str, host: str, port: int,
) -> int:
    """Format the PENDING-status receipt.

    Names the wait estimate and the submit-evidence escalation.  The
    pending path is exactly when censorship anxiety is highest -- a tx
    sat in mempool too long, the user wants to know if their validators
    are colluding.  The escalation hint is the actionable next step.
    """
    print(f"  Status:        PENDING -- in mempool, not yet in a block")
    current_height = result.get("current_height", "?")
    if current_height != "?":
        print(f"  Chain tip:     block {current_height}")

    # Try to fetch the block-time hint so the wait estimate is concrete.
    # Best-effort -- if the call fails (offline node, etc.) we still
    # name the escalation path.
    from client import rpc_call as _rpc
    try:
        from messagechain.config import BLOCK_TIME_TARGET as _BTT
    except ImportError:
        _BTT = 600
    info = _rpc(host, port, "get_chain_info", {})
    next_eta = None
    if info.get("ok"):
        ssl = info["result"].get("seconds_since_last_block")
        if isinstance(ssl, int) and ssl >= 0:
            next_eta = max(0, _BTT - ssl)
    if next_eta is not None:
        print(f"  Next block in: ~{_fmt_duration(next_eta)} (target block "
              f"interval {_fmt_duration(_BTT)})")
    else:
        print(f"  Block interval: ~{_fmt_duration(_BTT)} target")

    # Reaffirm the guarantee -- the user shouldn't lose context just
    # because the tx is still queueing.
    print()
    print(
        "  Once your transaction lands in a block, it is permanent\n"
        "  and can never be deleted.  Validators who admit a tx and\n"
        "  then drop it produce slashable evidence on chain."
    )

    # Escalation: name the submit-evidence path.  Mirror the r7
    # NOT_FOUND fix (cli.py:5996-6008) -- point at the LIVE
    # submit-evidence form (``censorship --receipt <bundle.json>``),
    # not the deprecated ``--tx <hash>`` stub which prints a
    # migration diagnostic and files nothing on chain.  The bundle
    # path is the canonical location ``cmd_send`` writes to on
    # submit, so the user can copy-paste verbatim.  Surfaced by
    # audit r24 top-3 #3.
    bundle_path = os.path.join(
        _default_receipts_dir(), f"{tx_hash_hex}.json",
    )
    print()
    print(
        "  If your message is not included in the next 2 blocks, run:\n"
        f"    messagechain submit-evidence censorship --receipt {bundle_path}\n"
        "  to put validator collusion evidence on chain.  Validators\n"
        "  found to have receipted-then-censored the tx are slashed.\n"
        "  (`messagechain send` saves the receipt bundle there\n"
        "  automatically on submit; pass --receipt to point at a\n"
        "  different path if you saved it elsewhere.)"
    )
    return 0


def _print_not_found_receipt(tx_hash_hex: str) -> int:
    """Format the NOT_FOUND-status receipt.

    Three possible causes are explicit so the user can self-diagnose
    without bouncing back to the docs.  Names the submit-evidence
    escalation as the actionable response to the collusion case.
    """
    print(f"  Status:        NOT FOUND in mempool or chain")
    print()
    print("  This may mean:")
    print("    (a) the tx was never submitted (typo, network drop, or")
    print("        the local node hasn't seen it yet);")
    print("    (b) every validator you queried dropped the tx silently")
    print("        -- possible coordinated collusion (see")
    print("        messagechain submit-evidence below);")
    print("    (c) the tx was malformed and rejected at submission")
    print("        time (bad signature, exhausted leaf, fee below floor).")
    print()
    # Audit-#2 fix (round 7): point at the LIVE submit-evidence form,
    # not the deprecated `--tx <hash>` stub.  The legacy form is now a
    # migration prompt that refuses to submit anything, so a user who
    # ran the printed command pre-fix bounced off a wall at the exact
    # moment they needed the slashing pipeline most.  The new form
    # names the canonical bundle path that cmd_send writes on success
    # (~/.messagechain/receipts/<tx_hash>.json) so the user can
    # copy-paste the path verbatim.
    bundle_path = os.path.join(
        _default_receipts_dir(), f"{tx_hash_hex}.json",
    )
    print(
        "  MessageChain's headline guarantee: a well-formed message\n"
        "  paying the fee floor is permanent and can never be deleted\n"
        "  once on chain.  If a validator coalition is suppressing\n"
        "  this tx, the slashing-backed evidence path is your remedy:\n"
        f"    messagechain submit-evidence censorship --receipt {bundle_path}\n"
        "  (`messagechain send` saves the receipt bundle there\n"
        "  automatically on submit; pass --receipt to point at a\n"
        "  different path if you saved it elsewhere.)"
    )
    return 0


def _default_receipts_dir() -> str:
    """The canonical on-disk location for SubmissionReceipt bundles.

    This is the SAME path `submit-evidence censorship --receipt
    <bundle.json>` reads from when the user pastes
    `~/.messagechain/receipts/<tx_hash>.json` -- so a user who hits
    the receipt-CLI's NOT_FOUND escalation hint and copies the
    suggested path can submit the evidence without any further
    translation.
    """
    return os.path.join(
        os.path.expanduser("~"), ".messagechain", "receipts",
    )


def _save_receipt_bundle(
    *,
    tx_hash_hex: str,
    receipt_hex: str,
    tx,
    tx_kind: str = "message",
    receipts_dir: str | None = None,
    filename_suffix: str | None = None,
) -> str:
    """Write a SubmissionReceipt + receipted-tx pair to the user's
    receipts directory and return the file path.

    Bundle shape matches what `_load_receipt_bundle` accepts, so
    `submit-evidence censorship --receipt <path>` can consume the
    file directly with no translation step.

    The write is idempotent: an existing file at the same path is
    overwritten (a re-send of the same tx_hash should not crash).
    The directory is created with mkdir -p semantics so the user
    doesn't have to seed it first.

    `filename_suffix` is appended to the tx_hash in the on-disk name
    so multi-validator paths (``send-multi``) can write N receipts
    for the same tx_hash without overwriting each other.  Callers
    should pass e.g. the first 16 hex chars of the issuer_id.  When
    None, the filename is just ``<tx_hash_hex>.json`` (single-receipt
    case from ``cmd_send`` -- byte-identical to pre-multi behaviour).

    Returns the absolute path of the written file.  Raises OSError
    on unrecoverable write failure -- callers should treat this as
    best-effort and continue (the tx is already on the wire).
    """
    import json

    target_dir = receipts_dir or _default_receipts_dir()
    os.makedirs(target_dir, exist_ok=True)
    fname = (
        f"{tx_hash_hex}_{filename_suffix}.json"
        if filename_suffix else f"{tx_hash_hex}.json"
    )
    bundle_path = os.path.join(target_dir, fname)
    bundle = {
        # The validator returns the receipt as hex of to_bytes() in
        # the submit_transaction RPC response; _load_receipt_bundle
        # accepts both the hex form and the dict form, so passing
        # the hex through unchanged is the minimum-translation
        # option and survives a future schema bump on the dict form.
        "receipt": receipt_hex,
        "message_tx": tx.serialize(),
        "tx_kind": tx_kind,
    }
    # Atomic-ish write: write to a tempfile in the same dir, then
    # rename.  Avoids leaving a half-written bundle if the process
    # is killed mid-write -- the rename is atomic on every OS we
    # support, and if the rename itself fails the original file
    # (or absence thereof) is preserved.
    tmp_path = bundle_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f)
    os.replace(tmp_path, bundle_path)
    return bundle_path


def _load_receipt_bundle(path: str) -> tuple[object, object]:
    """Read a receipt-bundle JSON file from disk.

    The bundle pairs a SubmissionReceipt (the validator's commitment
    that it accepted a tx at a given height) with the original
    receipted tx the receipt covers.  Both fields are needed:
    the receipt alone proves admission, the receipted tx is what
    every node compares against the next block's tx_hashes to decide
    whether to void the evidence (i.e. the tx finally landed) or
    apply the slash on maturity.

    Bundle schema (JSON):

        {
          "receipt":    <SubmissionReceipt.serialize() dict>
                        OR <hex of receipt.to_bytes()>,
          "message_tx": <Transaction.serialize() dict>
                        OR <hex of tx.to_bytes()>,
          "tx_kind":    "message" | "transfer" | "react"   (optional;
                        defaults to "message" for legacy bundles)
        }

    Both `dict` and `hex-string` forms are accepted so an operator
    can either save the JSON the RPC returned (which serializes to
    dict) or the hex blob (which is what the validator returns in
    `result.receipt_hex` from submit_transaction).

    `tx_kind` defaults to "message" so pre-Tier-44 bundles round-trip
    without any change.  Post-fork bundles for transfer/react carry
    the explicit kind so the loader dispatches to the correct decoder.

    Returns ``(SubmissionReceipt, receipted_tx)`` where the second
    element is one of MessageTransaction / TransferTransaction /
    ReactTransaction depending on `tx_kind`.
    Raises ``ValueError`` on malformed input.
    """
    import json
    from messagechain.core.transaction import MessageTransaction
    from messagechain.core.transfer import TransferTransaction
    from messagechain.core.reaction import ReactTransaction
    from messagechain.network.submission_receipt import SubmissionReceipt

    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    if not isinstance(bundle, dict):
        raise ValueError(
            "receipt bundle must be a JSON object with `receipt` and "
            "`message_tx` keys"
        )
    if "receipt" not in bundle:
        raise ValueError("receipt bundle missing `receipt` field")
    if "message_tx" not in bundle:
        raise ValueError("receipt bundle missing `message_tx` field")

    r_field = bundle["receipt"]
    if isinstance(r_field, dict):
        receipt = SubmissionReceipt.deserialize(r_field)
    elif isinstance(r_field, str):
        try:
            receipt = SubmissionReceipt.from_bytes(bytes.fromhex(r_field))
        except ValueError as e:
            raise ValueError(f"`receipt` hex string is not parseable: {e}")
    else:
        raise ValueError(
            "`receipt` field must be a dict (serialize form) or a "
            "hex string (to_bytes form)"
        )

    tx_kind = bundle.get("tx_kind", "message")
    kind_to_class = {
        "message": MessageTransaction,
        "transfer": TransferTransaction,
        "react": ReactTransaction,
    }
    if tx_kind not in kind_to_class:
        raise ValueError(
            f"`tx_kind` must be one of {sorted(kind_to_class)}; "
            f"got {tx_kind!r}"
        )
    rtx_class = kind_to_class[tx_kind]

    mtx_field = bundle["message_tx"]
    if isinstance(mtx_field, dict):
        message_tx = rtx_class.deserialize(mtx_field)
    elif isinstance(mtx_field, str):
        try:
            message_tx = rtx_class.from_bytes(bytes.fromhex(mtx_field))
        except ValueError as e:
            raise ValueError(
                f"`message_tx` hex string is not parseable: {e}"
            )
    else:
        raise ValueError(
            "`message_tx` field must be a dict (serialize form) or a "
            "hex string (to_bytes form)"
        )

    if receipt.tx_hash != message_tx.tx_hash:
        raise ValueError(
            "receipt.tx_hash does NOT match message_tx.tx_hash -- the "
            "bundle pairs a receipt with the wrong transaction"
        )

    return receipt, message_tx


def _cmd_submit_censorship_evidence(args) -> int:
    """Wire the censorship-evidence subcommand: load bundle, sign, submit.

    The user side of the slashing pipeline.  The flow:

      1. Load and parse the receipt-bundle JSON (receipt + message_tx).
      2. Cross-check via get_tx_status that the message_tx is NOT on
         chain (the entire premise of evidence is "validator promised
         inclusion, never delivered" -- if it IS on chain we refuse
         to submit a no-op evidence that the validator can no longer
         be slashed for).
      3. Resolve the user's signing entity through the personal-wallet
         keypair cache so this command doesn't pay the multi-minute
         keygen cliff a fresh Entity.create would.
      4. Auto-fetch nonce + leaf-watermark, auto-pick fee.
      5. Build, sign, submit the CensorshipEvidenceTx via the new
         `submit_censorship_evidence` RPC.
    """
    import time

    from client import rpc_call
    from messagechain.consensus.censorship_evidence import (
        CensorshipEvidenceTx,
    )
    from messagechain.crypto.hashing import default_hash
    from messagechain.crypto.keys import Signature
    from messagechain.economics.auto_fee import (
        auto_fee, urgency_to_target_blocks,
    )

    # -- Load + validate the bundle --
    try:
        receipt, message_tx = _load_receipt_bundle(args.receipt)
    except FileNotFoundError:
        print(f"Error: receipt bundle file not found: {args.receipt!r}")
        sys.exit(1)
    except (ValueError, OSError) as e:
        print(f"Error: could not load receipt bundle: {e}")
        sys.exit(1)

    tx_hash_hex = receipt.tx_hash.hex()
    print(
        f"=== MessageChain submit-evidence (censorship) for "
        f"{tx_hash_hex[:16]}... ==="
    )
    print(f"  Receipt issuer:    {receipt.issuer_id.hex()[:16]}...")
    print(f"  Commit height:     {receipt.commit_height}")
    print()

    host, port = _parse_server(args.server)

    # -- Refuse if the receipted tx is already on chain --
    status_resp = rpc_call(host, port, "get_tx_status", {
        "tx_hash": tx_hash_hex,
    })
    if not status_resp.get("ok"):
        print(
            f"Error: could not query tx status: "
            f"{status_resp.get('error', 'unknown')}"
        )
        sys.exit(1)
    status = status_resp["result"].get("status", "?")
    if status == "included":
        block_height = status_resp["result"].get("block_height", "?")
        print(
            f"Refusing to submit evidence: tx {tx_hash_hex[:16]}... is "
            f"already on chain at block {block_height}.\n"
            f"  CensorshipEvidenceTx is the remedy ONLY when a validator "
            f"issued a receipt and then never included the tx.  Since "
            f"the tx is on chain, no censorship occurred.\n"
            f"  If you suspect inclusion happened only after a long "
            f"delay (past EVIDENCE_INCLUSION_WINDOW), the slash window "
            f"already closed -- nothing to escalate."
        )
        sys.exit(1)

    # -- Resolve signing wallet (cache-warm path) --
    private_key = _resolve_private_key(args)
    data_dir = getattr(args, "data_dir", None)
    submitter = _resolve_signing_entity(private_key, args)
    print(f"Signing as: {submitter.entity_id_hex[:16]}...")

    # -- Auto-fetch nonce + advance leaf watermark --
    nonce_resp = rpc_call(host, port, "get_nonce", {
        "entity_id": submitter.entity_id_hex,
    })
    if not nonce_resp.get("ok"):
        print(f"Error: {nonce_resp.get('error', 'Could not fetch nonce')}")
        sys.exit(1)
    leaf = _reserve_leaf_via_rpc(host, port, submitter.entity_id_hex)
    if leaf is None:
        leaf = nonce_resp["result"].get(
            "leaf_watermark", nonce_resp["result"]["nonce"],
        )
    _bind_persistent_leaf_index(submitter, chain_leaf=leaf, data_dir=data_dir)

    # -- Auto-fee --
    info_resp = rpc_call(host, port, "get_chain_info", {})
    tip_height = 0
    if info_resp.get("ok"):
        count = info_resp["result"].get("height", 0) or 0
        tip_height = max(count - 1, 0)
    target_height = tip_height + 1

    # CensorshipEvidenceTx envelope is small (no message payload), so
    # it's floor-dominated.  Use the unified auto-fee helper with a
    # representative stored size and let the floor bind.
    urgency = getattr(args, "urgency", "normal")
    target_blocks = urgency_to_target_blocks(urgency)
    # The evidence tx uses MIN_FEE (the per-tx flat floor) by default;
    # auto_fee never returns 0 and clamps to the floor.  We pick the
    # `stake` rep size as a reasonable proxy for an envelope-only tx.
    fee = auto_fee(
        "stake",
        stored_size=64,
        urgency=urgency,
        current_height=target_height,
        mempool_estimate=0,
    )
    print(
        f"Fee: {fee} tokens (auto, target ~{target_blocks} blocks, "
        f"urgency={urgency})"
    )

    # -- Construct + sign --
    placeholder = Signature([], 0, [], b"", b"")
    etx = CensorshipEvidenceTx(
        receipt=receipt,
        message_tx=message_tx,
        submitter_id=submitter.entity_id,
        timestamp=int(time.time()),
        fee=int(fee),
        signature=placeholder,
    )
    msg_hash = default_hash(etx._signable_data())
    etx.signature = submitter.keypair.sign(msg_hash)
    etx.tx_hash = etx._compute_hash()

    print("Submitting evidence...")
    response = rpc_call(host, port, "submit_censorship_evidence", {
        "transaction": etx.serialize(),
    })

    if response.get("ok"):
        result = response["result"]
        print()
        print(f"Evidence submitted!")
        print(f"  Evidence tx hash: {result['tx_hash']}")
        print(f"  Evidence hash:    {result['evidence_hash']}")
        print(f"  Accused:          {result['offender_id'][:16]}...")
        print(f"  Fee paid:         {result['fee']} tokens")
        print()
        print(
            "  When this evidence lands in a block and matures past\n"
            "  EVIDENCE_MATURITY_BLOCKS without the receipted tx being\n"
            "  included on chain, the accused validator's stake is\n"
            "  slashed by CENSORSHIP_SLASH_BPS and burned.  If the tx\n"
            "  is included before maturity (by anyone -- not just the\n"
            "  accused), the evidence voids with no slash."
        )
        return 0

    err = response.get("error", "")
    print(f"\nFailed to submit evidence: {err}")
    sys.exit(1)


def cmd_submit_evidence(args) -> int:
    """Dispatch the submit-evidence subcommand.

    Three evidence kinds exist on the consensus layer:

      * censorship       -- CensorshipEvidenceTx (validator issued
                            receipt, then never included the tx).
                            REAL wiring (signs + submits).
      * bogus-rejection  -- BogusRejectionEvidenceTx (validator
                            forged a REJECT_INVALID_SIG).  Stub:
                            consensus pipeline exists; CLI wiring
                            lands in a follow-up branch.
      * non-response     -- NonResponseEvidenceTx (validator
                            silently dropped a witnessed submission).
                            Stub: same status as bogus-rejection.

    The censorship path is the most-promised on the public surface
    (README + COMPARISON.md), so it's the one wired first.  The
    other two print clear "not yet wired" messages so the receipt
    CLI's escalation hint always resolves to a real command.

    Back-compat: a legacy `--tx <hash>` invocation (no subcommand)
    prints a migration diagnostic naming the new flag.
    """
    kind = getattr(args, "evidence_kind", None)

    if kind == "censorship":
        return _cmd_submit_censorship_evidence(args)

    if kind == "bogus-rejection":
        print("=== MessageChain submit-evidence (bogus-rejection) ===\n")
        print(
            "  This subcommand is NOT YET WIRED.  Only the\n"
            "  censorship-evidence path is signed-and-submittable in\n"
            "  this release; the consensus-layer pipeline at\n"
            "  messagechain.consensus.bogus_rejection_evidence is\n"
            "  ready and the CLI wiring will land in a follow-up.\n"
            "\n"
            "  In the meantime: keep your SignedRejection bundle and\n"
            "  hand it to a node operator who can construct and submit\n"
            "  the BogusRejectionEvidenceTx directly."
        )
        return 0

    if kind == "non-response":
        print("=== MessageChain submit-evidence (non-response) ===\n")
        print(
            "  This subcommand is NOT YET WIRED.  Only the\n"
            "  censorship-evidence path is signed-and-submittable in\n"
            "  this release; the consensus-layer pipeline at\n"
            "  messagechain.consensus.non_response_evidence is ready\n"
            "  and the CLI wiring will land in a follow-up.\n"
            "\n"
            "  In the meantime: keep your witnessed-submission bundle\n"
            "  and hand it to a node operator who can construct and\n"
            "  submit the NonResponseEvidenceTx directly."
        )
        return 0

    # Legacy / no-subcommand path.  Existing receipts in the wild
    # name `messagechain submit-evidence --tx <hash>` -- print a
    # clear migration message rather than an argparse error.
    legacy_tx = getattr(args, "tx_hash", None)
    if legacy_tx is not None:
        print("=== MessageChain submit-evidence ===\n")
        print(
            "  The submit-evidence command now takes a subcommand:\n"
            "    messagechain submit-evidence censorship --receipt <bundle.json>\n"
            "    messagechain submit-evidence bogus-rejection ...\n"
            "    messagechain submit-evidence non-response ...\n"
            "\n"
            "  The legacy `--tx <hash>` form was a stub that did not\n"
            "  actually submit anything.  Use the censorship\n"
            "  subcommand with a receipt bundle instead -- save the\n"
            "  validator's SubmissionReceipt at send-time (returned\n"
            "  in the `receipt` field of submit_transaction) along\n"
            "  with the original MessageTransaction, and pass the\n"
            "  bundle path via --receipt."
        )
        return 0

    print(
        "Error: submit-evidence requires a subcommand.\n"
        "  messagechain submit-evidence censorship --receipt <bundle.json>\n"
        "  messagechain submit-evidence bogus-rejection ...\n"
        "  messagechain submit-evidence non-response ..."
    )
    sys.exit(1)


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
    """Estimate fee for any tx kind, with urgency-driven percentile pick.

    Resolves --message / --transfer / --tx-type into a single tx-type
    label, dispatches the unified `estimate_fee` RPC with target_blocks
    derived from --urgency, and prints a breakdown the user can read:

        Tx type:            <kind>
        Urgency:            <urgency>  (target ~N blocks)
        Stored bytes:       <bytes>
        Per-byte rate:      <density>
        Mempool percentile: <fee>
        Protocol minimum:   <fee>
        Recommended fee:    <fee>

    Replaces the prior message/transfer-only path, in line with the
    CLAUDE.md anchor "Auto-fee adjusts to fit this model. ... When the
    fee model shifts, every auto-fee path shifts with it."
    """
    from messagechain.economics.auto_fee import (
        TX_TYPES, urgency_to_target_blocks,
    )

    host, port = _parse_server(args.server)

    # Resolve tx_type from the three input shapes.  --tx-type wins; the
    # --message / --transfer shortcuts set it implicitly.
    tx_type = getattr(args, "tx_type", None)
    if tx_type is None:
        if args.message is not None:
            tx_type = "message"
        elif args.transfer:
            tx_type = "transfer"
        else:
            print(
                "Error: estimate-fee requires --tx-type, --message, or "
                "--transfer.  Run `messagechain estimate-fee --help` for "
                "the full list of tx kinds."
            )
            sys.exit(2)
    if tx_type not in TX_TYPES:
        print(f"Error: unknown tx_type {tx_type!r}")
        sys.exit(2)

    urgency = getattr(args, "urgency", "normal")
    target_blocks = urgency_to_target_blocks(urgency)

    params: dict = {
        "kind": tx_type,
        "target_blocks": target_blocks,
        "urgency": urgency,
    }
    # Tx-type-specific payload args that affect size or floor.
    if tx_type == "message" and args.message is not None:
        params["message"] = args.message
    if tx_type == "propose":
        title = getattr(args, "title", None) or ""
        description = getattr(args, "description", None) or ""
        params["payload_bytes"] = (
            len(title.encode("utf-8")) + len(description.encode("utf-8"))
        )

    from client import rpc_call
    response = rpc_call(host, port, "estimate_fee", params)

    if not response.get("ok"):
        print(f"Error: {response.get('error', 'Could not connect')}")
        sys.exit(1)

    result = response["result"]
    print("=== Fee Estimate ===\n")
    print(f"  Tx type:            {result.get('tx_type', tx_type)}")
    print(
        f"  Urgency:            {result.get('urgency', urgency)} "
        f"(target ~{result.get('target_blocks', target_blocks)} blocks)"
    )
    stored = result.get("stored_bytes", 0)
    if stored:
        per_byte = result.get("fee_per_byte", 0)
        print(f"  Stored bytes:       {stored}")
        print(f"  Mempool per byte:   {per_byte}")
    print(f"  Protocol minimum:   {result['min_fee']}")
    print(f"  Mempool suggestion: {result['mempool_fee']}")
    print(f"  Recommended fee:    {result['recommended_fee']}")


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

    if disk_version == 1 and _SCHEMA_VERSION >= 2:
        print(
            f"Migrating chain.db at {db_path} from schema v1 to v2 "
            "(replaying block history to rebuild reputation, "
            "key_history, pending_unstakes, stake_snapshots, and "
            "supply_meta counters)...",
        )
        summary = db.migrate_schema_v1_to_v2()
        print("v1 -> v2 migration complete.")
        for k, v in summary.items():
            label = k.replace("_", " ").title()
            print(f"  {label}: {v}")
        # Fall through to v2 -> v3 if the binary is even newer.
        disk_version = 2

    if disk_version == 2 and _SCHEMA_VERSION == 3:
        print(
            f"Migrating chain.db at {db_path} from schema v2 to v3 "
            "(backfilling the tx_locations index used by strict-prev "
            "pointer resolution)...",
        )
        summary = db.migrate_schema_v2_to_v3()
        print("v2 -> v3 migration complete.")
        for k, v in summary.items():
            label = k.replace("_", " ").title()
            print(f"  {label}: {v}")
        return

    if disk_version == _SCHEMA_VERSION:
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


def _upgrade_verify_tag_signature(clone_dir: str, tag: str) -> None:
    """Verify *tag* in *clone_dir* is signed by a pinned release signer.

    MessageChain release tags are SSH-signed (``git tag -s``) by a
    maintainer whose pubkey is pinned in
    ``messagechain/release_signers.py``.  Without this check, the
    upgrade path would ``git clone --branch <tag>`` and swap ANY tag
    pushed to the repo into /opt/messagechain as root -- an attacker
    who compromised a maintainer's GitHub credentials, a GitHub
    incident, or a branch-protection bypass could push a malicious
    tag and every validator running ``messagechain upgrade`` would
    execute it as root on next run.  This function closes that
    supply-chain path by refusing to proceed past tag resolution
    unless ``git tag -v`` succeeds against our pinned allowed-signers
    set.

    Raises RuntimeError on any verification failure; caller translates
    to a fatal restore-and-exit.
    """
    import subprocess
    import tempfile
    from messagechain.release_signers import ALLOWED_SIGNERS

    # Write the pinned allowed-signers file to a tempfile for the
    # duration of this verify.  Using tempfile (not a fixed path)
    # means parallel upgrades don't collide and we don't pollute
    # the host filesystem with a persistent signers file.
    with tempfile.NamedTemporaryFile(
        prefix="mc-allowed-signers-",
        suffix=".txt",
        delete=False,
    ) as tf:
        tf.write(ALLOWED_SIGNERS)
        signers_path = tf.name
    try:
        # ``git tag -v`` exits non-zero if the tag is unsigned, signed
        # by an unknown key, or the signature is invalid.  We override
        # the local git config with -c so the operator's personal
        # allowedSignersFile (or lack thereof) doesn't affect the
        # outcome -- only the pinned set matters.
        proc = subprocess.run(
            [
                "git",
                "-C", clone_dir,
                "-c", f"gpg.ssh.allowedSignersFile={signers_path}",
                "-c", "gpg.format=ssh",
                "tag", "-v", tag,
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(
                f"tag {tag!r} failed signature verification against "
                f"pinned release signers: {stderr[:400]}"
            )
        # Belt-and-braces: the output must reference a "Good" signature.
        # git tag -v sends the signature report to stderr; accept either.
        combined = (proc.stderr or "") + (proc.stdout or "")
        if "Good" not in combined and "good" not in combined:
            raise RuntimeError(
                f"tag {tag!r} verified with unexpected output (no "
                f"'Good signature' marker): {combined[:400]}"
            )
    finally:
        try:
            os.unlink(signers_path)
        except OSError:
            pass


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


def _upgrade_acquire_lock(lock_path: str):
    """Acquire an exclusive non-blocking advisory lock on ``lock_path``.

    Purpose: the weekly auto-upgrade systemd timer and an operator
    running ``messagechain upgrade --yes`` manually can fire in the
    same window.  Two concurrent upgrades on the same install
    directory would race on systemctl stop/start, the backup move,
    and the install swap -- corrupting the install or losing the
    backup the manual-rollback path depends on.

    Returns an opaque handle (open file object) the caller MUST keep
    alive for the duration of the upgrade.  The advisory lock is
    bound to the fd's lifetime; letting the fd be garbage-collected
    releases the lock, so callers must hold a reference through all
    of cmd_upgrade.  Raises ``RuntimeError`` if the lock is already
    held by another process.

    Returns ``None`` on platforms without ``fcntl`` (Windows dev env,
    non-POSIX) -- callers treat that as "lock disabled, cannot check
    contention".  Validators run on Linux so the lock is active where
    it matters; the no-op path keeps the test suite portable.
    """
    try:
        import fcntl as _fcntl
    except ImportError:
        return None

    try:
        handle = open(lock_path, "a+")
    except OSError as e:
        raise RuntimeError(
            f"cannot open upgrade lock file {lock_path}: {e}. "
            "Pass --lock-path to point at a writable location, or "
            "--no-lock to skip the contention check."
        ) from e

    try:
        _fcntl.flock(
            handle.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB,
        )
    except OSError as e:
        handle.close()
        raise RuntimeError(
            f"upgrade already in progress (advisory lock held on "
            f"{lock_path}). Wait for the other upgrade to complete, "
            "or -- if you are certain the lock is stale -- remove "
            "the file and retry, or pass --no-lock."
        ) from e

    return handle


def _upgrade_gc_old_backups(install_dir: str, keep: int) -> list:
    """Prune old ``{install_dir}.bak-*`` directories, keeping the
    ``keep`` most recent by mtime.  Returns the list of paths removed.

    Runs on the upgrade success path only -- the upgrade is already
    done, so a GC failure must never fail the whole flow.  Any
    ``OSError`` on rmtree is swallowed; the caller logs what was
    actually removed.

    Why keep >= 1: the most recent backup is the manual-rollback
    parachute referenced in the failure message on `--no-rollback`
    and in the skill's manual-revert section.  Pruning it would
    strand an operator who skipped the auto-rollback.
    """
    import glob as _glob

    if keep < 1:
        keep = 1
    siblings = _glob.glob(f"{install_dir}.bak-*")
    # Newest first.  Same-second mtimes tie-break on path, which
    # embeds the YYYYMMDD-HHMMSS timestamp -- so ordering is stable
    # and deterministic even at sub-second collision.
    siblings.sort(
        key=lambda p: (os.path.getmtime(p), p), reverse=True,
    )
    removed = []
    import shutil as _shutil
    for old in siblings[keep:]:
        try:
            _shutil.rmtree(old)
            removed.append(old)
        except OSError:
            pass
    return removed


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

    # --- Upgrade-contention lock ---
    # Keeps the handle alive for the whole function -- advisory
    # flock is bound to the fd lifetime.  See docstring on
    # _upgrade_acquire_lock for why this matters (weekly auto-
    # upgrade timer vs. manual invocation can otherwise race on
    # systemctl stop/start + backup move + install swap).
    _lock_handle = None  # noqa: F841 -- referenced to keep fd open
    if not args.no_lock:
        try:
            _lock_handle = _upgrade_acquire_lock(args.lock_path)
        except RuntimeError as e:
            _fail(str(e), code=3)

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

    # --- Fetch tag (service still running) ---
    # Ordering: clone + verify BEFORE stopping the service or moving
    # the live install.  Two reasons:
    #   1. Supply-chain gate (signature verify) imports
    #      ``messagechain.release_signers`` -- a LAZY import inside
    #      ``_upgrade_verify_tag_signature``.  At verify time the
    #      interpreter resolves that module against sys.path, which
    #      points into the running install.  If we had already moved
    #      /opt/messagechain to the backup dir, that import would
    #      fail and the operator would be left with a stopped service
    #      AND no live install at all (the 1.5.x bug that left
    #      validator-1 needing manual restore during the 1.5.2 -> 1.6.0
    #      rollout).  Running verify while the install is still in
    #      place keeps the pinned signer list reachable.
    #   2. If clone or verify fails, the service never needed to stop
    #      -- the old binary keeps validating.  Zero downtime on a
    #      rejected upgrade.
    # NOTE: ``--depth 1 --branch <tag>`` creates a shallow clone that
    # still includes the tag object and the commit it points at, which
    # is all ``git tag -v`` needs.  If the remote is configured to
    # refuse shallow tag fetches for signed-tag verification, fall
    # back to a full clone by removing --depth 1.
    _say(f"Cloning {args.repo} @ {target_tag} -> {clone_dir}")
    clone_cmd = [
        "git", "clone", "--depth", "1", "--branch", target_tag,
        args.repo, clone_dir,
    ]
    try:
        subprocess.run(clone_cmd, check=True)
    except subprocess.CalledProcessError as e:
        _fail(
            f"git clone failed ({e}); service untouched and still "
            "running on prior binary."
        )

    # --- Verify tag signature against pinned release signers ---
    # This is the supply-chain gate: no unsigned / unknown-signer tag
    # is ever allowed to swap into the install directory.  Verified
    # here, BEFORE any mutation of the live install, so a bad signature
    # cannot leave the node in a half-upgraded state.
    _say(f"Verifying {target_tag} signature against pinned signers...")
    try:
        _upgrade_verify_tag_signature(clone_dir, target_tag)
    except RuntimeError as e:
        try:
            shutil.rmtree(clone_dir)
        except OSError:
            pass
        _fail(
            f"release tag verification failed: {e}; service untouched "
            "and still running on prior binary."
        )
    _say("Signature OK.")

    # --- Pre-stop cold-load smoke test ---
    # Spawn a short-lived subprocess that imports the NEW code from the
    # clone directory and tries to cold-load chain.db.  Catches the
    # failure mode where the new binary's block decoder can't read
    # blocks the running binary wrote (e.g. a wire-format slot whose
    # activation height was crossed under an older binary that lacked
    # the slot, then encountered by a newer decoder that expects it).
    # That class of bug is invisible to the warm running service --
    # only manifests on cold-load -- so we MUST verify the new code
    # can cold-load BEFORE we stop the service that's keeping the
    # warm in-memory state alive.
    _say("Pre-stop cold-load smoke test against existing chain.db...")
    smoke_code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from messagechain.storage.chaindb import ChainDB; "
        "from messagechain.core.blockchain import Blockchain; "
        "db = ChainDB(sys.argv[2] + '/chain.db'); "
        "bc = Blockchain(db=db); "
        "n = len(bc.chain) if hasattr(bc, 'chain') else 0; "
        "print('cold-load OK: blocks=' + str(n))"
    )
    # `--service-user` carries a user:group spec for chown, but `sudo -u`
    # only accepts a user.  Strip the group portion before invoking sudo.
    smoke_user = args.service_user.split(":", 1)[0]
    try:
        smoke = subprocess.run(
            [
                "sudo", "-n", "-u", smoke_user,
                "python3", "-c", smoke_code,
                clone_dir, args.data_dir,
            ],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        try:
            shutil.rmtree(clone_dir)
        except OSError:
            pass
        _fail(
            "cold-load smoke test timed out (>120s); service untouched "
            "and still running on prior binary.  The new binary may "
            "hang during chain replay -- investigate before retrying."
        )
    if smoke.returncode != 0:
        try:
            shutil.rmtree(clone_dir)
        except OSError:
            pass
        _fail(
            "cold-load smoke test FAILED -- service untouched and still "
            "running on prior binary.  The new binary cannot decode "
            "the existing chain.db.  Likely cause: a wire-format "
            "activation height was crossed under an older binary that "
            "lacked the corresponding code, and the new binary's "
            "decoder expects the post-fork format.  Inspect the "
            "stderr below, then either (a) cut a hotfix that pushes "
            "activation heights past the current tip, or (b) restore "
            "chain.db from a known-good checkpoint.\n"
            f"--- smoke test stdout ---\n{smoke.stdout}\n"
            f"--- smoke test stderr ---\n{smoke.stderr}"
        )
    _say(f"Cold-load smoke test passed: {smoke.stdout.strip()}")

    # --- Stop service ---
    # Only reached after clone + verify + smoke-test succeed.  From here
    # on we own the downtime window and any failure triggers backup
    # restore.
    _say(f"Stopping {args.service}...")
    try:
        subprocess.run(
            ["systemctl", "stop", args.service], check=True,
        )
    except subprocess.CalledProcessError as e:
        try:
            shutil.rmtree(clone_dir)
        except OSError:
            pass
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
        try:
            shutil.rmtree(clone_dir)
        except OSError:
            pass
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

    # --- GC old backups ---
    # Keep the two most recent: the one we just created, and the one
    # before it as an operator parachute.  On a busy release day
    # (multiple upgrades, e.g. a patch hot on a minor) the bak dirs
    # accumulate fast -- seen 13 on validator-1 across a single day --
    # and each is a full install-tree copy.  Fills disk eventually.
    _gc_removed = _upgrade_gc_old_backups(args.install_dir, keep=2)
    if _gc_removed:
        _say(
            f"Pruned {len(_gc_removed)} old backup dir(s): "
            + ", ".join(os.path.basename(p) for p in _gc_removed)
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

    # --- Chain-identity pre-flight ---
    # Before committing to a ~90-min WOTS+ keygen, verify that at
    # least one reachable seed is running the same chain (chain_id +
    # genesis_hash).  Default: probe the first reachable entry in
    # SEED_NODES, warn-and-continue on network errors, ABORT on a
    # real mismatch.  --verify-seed overrides the seed list;
    # --skip-verify bypasses the whole step (first validator /
    # air-gapped deploys).
    if not getattr(args, "skip_verify", False):
        _cmd_init_run_seed_verification(
            getattr(args, "verify_seed", None),
        )

    from messagechain.config import MERKLE_TREE_HEIGHT
    print("Generating signing key tree (this can take a while at "
          f"MERKLE_TREE_HEIGHT={MERKLE_TREE_HEIGHT})...")
    progress = _make_progress_reporter(1 << MERKLE_TREE_HEIGHT, "Building key tree")
    _ob.apply_init(plan, progress=progress)
    print()
    print(plan.next_steps_text())


def _cmd_init_run_seed_verification(explicit_seed: str | None) -> None:
    """Probe seeds and abort on a chain-identity mismatch.

    If ``explicit_seed`` is given, probe only that one (HOST or
    HOST:PORT; PORT defaults to the RPC port) and abort on any
    problem -- the operator asked for a specific check.

    Otherwise, iterate SEED_NODES and abort on the FIRST reachable
    seed that reports a mismatch.  Unreachable seeds are logged as
    warnings and skipped; if every seed is unreachable we warn-and-
    continue (first-validator / air-gapped scenarios shouldn't be
    blocked by a cosmetic feature).
    """
    from messagechain.runtime import onboarding as _ob
    from messagechain.config import (
        CHAIN_ID as _CHAIN_ID,
        RPC_DEFAULT_PORT,
        SEED_NODES,
    )

    our_chain_id = _CHAIN_ID.decode("ascii")
    # Local genesis hash is unavailable pre-init (no chain_db); the
    # verify step only compares chain_id in that case.  If a
    # chain_db already exists (re-running init), the genesis hash
    # is derivable from it -- but skipping that is fine since the
    # chain_id check alone catches profile mismatches.
    our_genesis_hex = None

    def _parse(s: str) -> tuple[str, int]:
        if ":" in s:
            h, p = s.rsplit(":", 1)
            return h, int(p)
        return s, RPC_DEFAULT_PORT

    def _fail(msg: str) -> None:
        print(f"ERROR: {msg}", file=sys.stderr, flush=True)
        print(
            "  (override with --skip-verify if you know what you're "
            "doing, e.g. first validator on a new chain)",
            file=sys.stderr, flush=True,
        )
        sys.exit(2)

    if explicit_seed:
        host, port = _parse(explicit_seed)
        print(f"==> Probing seed {host}:{port} for chain identity...")
        probe = _ob.probe_seed_chain_identity(host, port)
        if not probe.ok:
            _fail(
                f"seed {host}:{port} unreachable: {probe.error}. "
                "Either the seed is down or you have the wrong "
                "host/port."
            )
        ok, msg = _ob.verify_seed_compatible(
            probe, our_chain_id, our_genesis_hex,
        )
        if not ok:
            _fail(msg)
        print(f"    OK: {msg}")
        return

    # Default path: walk SEED_NODES, first reachable wins.
    if not SEED_NODES:
        print(
            "==> SEED_NODES is empty; skipping chain-identity probe. "
            "If this is the first validator on a new chain, "
            "continuing is correct.  Otherwise set SEED_NODES in "
            "config_local.py or pass --verify-seed HOST."
        )
        return

    print("==> Probing bootstrap seeds for chain identity...")
    unreachable = []
    for host, _p2p_port in SEED_NODES:
        port = RPC_DEFAULT_PORT
        probe = _ob.probe_seed_chain_identity(host, port)
        if not probe.ok:
            unreachable.append((host, port, probe.error))
            print(f"    skip {host}:{port}: {probe.error}")
            continue
        ok, msg = _ob.verify_seed_compatible(
            probe, our_chain_id, our_genesis_hex,
        )
        if not ok:
            _fail(msg)
        print(f"    OK: {msg}")
        return

    # All seeds unreachable.  Warn, don't block -- this is the
    # normal case on an air-gapped box or a box without outbound
    # internet to the GCP IPs.  Operator can re-check with
    # `messagechain doctor` once the node is up.
    print(
        f"==> WARNING: none of the {len(SEED_NODES)} configured "
        "seeds were reachable; skipping chain-identity verification.",
        file=sys.stderr,
    )
    for host, port, err in unreachable[:3]:
        print(f"    {host}:{port}: {err}", file=sys.stderr)


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

    # Governance-proposal banner: best-effort RPC probe of the local
    # node.  Silent if the node is not reachable / no entity_id_hex
    # configured / no open proposals -- never alters doctor's exit code.
    try:
        _doctor_proposal_banner(cfg, getattr(args, "server", None))
    except Exception:
        pass

    sys.exit(worst)


def _doctor_proposal_banner(cfg: dict, server_arg: str | None) -> None:
    """Best-effort RPC probe for open proposals + banner emission.

    Used by `cmd_doctor` so that an operator running `messagechain
    doctor` notices an open proposal even if they're not actively
    watching the validator log.  Silent on any failure (no node yet,
    no entity_id, RPC error) -- doctor's job is preflight, not
    chain-state introspection.
    """
    from messagechain.runtime import notify as _notify

    entity_hex = cfg.get("entity_id_hex") or ""
    if not entity_hex:
        return
    try:
        from client import rpc_call
    except Exception:
        return
    host, port = _parse_server_local_default(server_arg)
    try:
        resp = rpc_call(host, port, "list_proposals", {"voter_id": entity_hex})
    except Exception:
        return
    if not isinstance(resp, dict) or not resp.get("ok"):
        return
    proposals = (resp.get("result") or {}).get("proposals") or []
    voted_ids = {
        str(p.get("proposal_id"))
        for p in proposals
        if p.get("voted")
    }
    text = _notify.format_open_proposals_banner(
        proposals=proposals,
        voter_id_hex=entity_hex,
        voted_proposal_ids=voted_ids,
    )
    if text:
        print()
        print(text)


def cmd_rotate_key_if_needed(args):
    """Daily watchdog: rotate when the leaf watermark is >= 95%."""
    from messagechain.runtime import onboarding as _ob
    from messagechain.config import MERKLE_TREE_HEIGHT

    cfg = _ob.read_onboard_config()
    entity_hex = cfg.get("entity_id_hex", "")
    if not entity_hex:
        print("rotate-key-if-needed: entity_id_hex not in onboard.toml; run `messagechain init` first")
        sys.exit(1)

    # Daily systemd timer fires this on the validator host; query
    # OUR node for OUR entity's leaf watermark.  Seed-pick default
    # would route to a remote validator's view, which on a 2-node
    # mainnet is the OTHER validator -- making the rotation-urgency
    # decision off the wrong watermark.
    host, port = _parse_server_local_default(getattr(args, "server", None))
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
        #
        # data_dir MUST be carried through from onboard.toml.  Without
        # it, cmd_rotate_key reads getattr(args, "data_dir", None) ->
        # None and the leaf-cursor resolver routes this signing
        # invocation to the per-user fallback at
        # ~/.messagechain/leaves/<entity>.idx, while the validator
        # daemon is persisting its cursor to <data_dir>/leaf_index.json.
        # Two cursors with no fsync handshake re-opens the cross-process
        # WOTS+ leaf-reuse window -- equivocation evidence on chain and
        # 100% slash on detection.  _reserve_leaf_via_rpc is a
        # best-effort fallback only and silently returns None on
        # transient RPC errors and on older daemons.
        import argparse as _ap
        kf = getattr(args, "keyfile", None) or cfg.get("keyfile") or None
        ddir = getattr(args, "data_dir", None) or cfg.get("data_dir") or None
        ns = _ap.Namespace(
            server=args.server,
            yes=True,
            fee=None,
            keyfile=kf,
            data_dir=ddir,
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


def cmd_backup_wallet(args):
    """Tar up the keyfile + ALL leaf-cursors into one archive.

    Local-only: never touches the chain, never opens a socket, never
    requires a running daemon.  The command exists because the files
    that together constitute a complete wallet backup live in
    different places by default (the keyfile wherever the user put
    it; the block-signing leaf cursor under
    ``~/.messagechain/leaves/<entity>.idx``; the receipt-signing
    leaf cursor under ``<data_dir>/receipt_leaf_index.json`` for
    validators that issue receipts).  A paper-only backup of the
    keyfile alone is a self-slash trap -- restoring without ANY of
    the leaf cursors re-uses one-time WOTS+ leaves and produces
    equivocation evidence on chain (geometric soft-slash compounds
    ``(1 - 0.05)^N`` toward total stake loss as each re-used leaf
    surfaces a distinct equivocation event).

    Inputs:
      ``--keyfile``         path to the keyfile (or global --keyfile)
      ``--leaves``          path to the block-signing leaf cursor
                            (default: ~/.messagechain/leaves/<entity>.idx)
      ``--receipt-leaves``  path to the receipt-subtree leaf cursor
                            (default: <data_dir>/receipt_leaf_index.json
                            when ``data_dir`` is set; absent on
                            non-receipt-issuing validators)
      ``--no-receipt-leaves`` opt out of receipt-leaf inclusion
                            (validators that do NOT issue receipts);
                            prints a visible warning so the choice
                            is not silent
      ``--entity-id``       entity_id hex (default: derived from keyfile)
      ``--output``          tarball path (default:
                            <entity_id_hex>-wallet-backup-<YYYYMMDD>.tar.gz
                            in CWD)

    Failure modes are clean: if a required input file is missing,
    print a message naming the missing path and exit non-zero.
    Never produces a partial archive.

    Receipt-leaf inclusion (audit r39 #2): a receipt-issuing
    validator that backs up only the keyfile + block-signing leaves
    will, on disk-loss restore, re-sign already-burned WOTS+ leaves
    on the receipt subtree.  Pre-fix this command silently dropped
    ``receipt_leaf_index.json`` even though the README explicitly
    names it as one of three security-critical files; this is now
    fixed.  Default-resolution mirrors the existing block-signing
    leaf path: ``<data_dir>/receipt_leaf_index.json``.  Non-receipt-
    issuing validators don't have the file on disk and the command
    proceeds cleanly without it.
    """
    import datetime as _dt
    import tarfile as _tar

    keyfile = getattr(args, "keyfile", None)
    if not keyfile:
        print(
            "Error: --keyfile is required (path to the file containing "
            "your hex private key)."
        )
        return 2

    entity_hex = getattr(args, "entity_id", None)
    leaves_path = getattr(args, "leaves", None)

    # Derive entity_id from keyfile when not explicitly provided.  Need
    # the keyfile to actually exist for that derivation to work, so the
    # missing-keyfile branch must come first.
    if not os.path.exists(keyfile):
        print(f"Error: keyfile not found: {keyfile}")
        return 2

    if entity_hex is None:
        try:
            from messagechain.identity.identity import Entity
            private_key = _load_key_from_file(
                keyfile,
                accept_raw_hex=bool(getattr(args, "data_dir", None)),
            )
            entity = _resolve_signing_entity(private_key, args)
            entity_hex = entity.entity_id_hex
        except KeyFileError as e:
            print(f"Error: {e}")
            return 2
        except Exception as e:
            print(
                f"Error: cannot derive entity_id from {keyfile}: "
                f"{type(e).__name__}: {e}"
            )
            return 2

    # Resolve the leaves path either from --leaves or via the same
    # default-resolution every signing command uses.
    if leaves_path is None:
        leaves_path = str(_resolve_leaf_index_path(
            entity_hex, data_dir=getattr(args, "data_dir", None),
        ))

    if not os.path.exists(leaves_path):
        print(
            f"Error: leaf cursor not found: {leaves_path}\n"
            "If you have signed any tx with this wallet, the leaf "
            "cursor MUST exist on this host -- restoring the keyfile "
            "without it re-uses one-time WOTS+ leaves and produces "
            "equivocation evidence on chain (slashable).  Find the "
            "real cursor file and pass it via --leaves before "
            "re-running."
        )
        return 2

    # Receipt-subtree leaf cursor resolution (audit r39 #2).  Same
    # default-resolution pattern the block-signing leaf cursor above
    # uses: explicit flag wins; else derive from data_dir; else absent
    # (non-receipt-issuing validators don't have the file).  The
    # silent-omission pre-fix bug turned every disk-loss restore into
    # a guaranteed receipt-subtree equivocation slash; default-
    # inclusion closes that trap.
    _RECEIPT_LEAF_INDEX_FILENAME = "receipt_leaf_index.json"
    no_receipt_leaves = bool(
        getattr(args, "no_receipt_leaves", False),
    )
    receipt_leaves_path = getattr(args, "receipt_leaves", None)
    data_dir = getattr(args, "data_dir", None)
    if no_receipt_leaves:
        if receipt_leaves_path is not None:
            print(
                "Error: --no-receipt-leaves is mutually exclusive with "
                "--receipt-leaves.  Pick one."
            )
            return 2
        # Surface the opt-out: warn naming the file we're skipping so
        # the operator can't silently omit it on a receipt-issuing
        # validator and discover the gap only on restore.
        candidate = (
            os.path.join(data_dir, _RECEIPT_LEAF_INDEX_FILENAME)
            if data_dir else None
        )
        if candidate and os.path.exists(candidate):
            print(
                f"WARNING: --no-receipt-leaves opt-out: skipping "
                f"receipt-subtree leaf cursor at {candidate}.  Only "
                "safe on validators that do NOT issue submission "
                "receipts.  A receipt-issuing validator that omits "
                "this file will produce equivocation evidence on "
                "disk-loss restore (geometric soft-slash compounding)."
            )
        receipt_leaves_path = None
    elif receipt_leaves_path is None and data_dir is not None:
        candidate = os.path.join(data_dir, _RECEIPT_LEAF_INDEX_FILENAME)
        if os.path.exists(candidate):
            receipt_leaves_path = candidate
        # else: leave None -- non-receipt-issuing validator, file
        # legitimately absent, do not synthesize.
    elif receipt_leaves_path is not None:
        # Explicit --receipt-leaves: must exist or this is an error
        # (the operator named a file they expect to be in the backup).
        if not os.path.exists(receipt_leaves_path):
            print(
                f"Error: receipt-subtree leaf cursor not found: "
                f"{receipt_leaves_path}\n"
                "If this validator issues submission receipts, the "
                "receipt cursor MUST exist on this host -- restoring "
                "without it re-uses one-time WOTS+ leaves on the "
                "receipt subtree and produces equivocation evidence "
                "on chain (slashable).  Pass --no-receipt-leaves if "
                "this validator does NOT issue receipts."
            )
            return 2

    output = getattr(args, "output", None)
    if not output:
        today = _dt.date.today().strftime("%Y%m%d")
        output = f"{entity_hex}-wallet-backup-{today}.tar.gz"

    # All inputs are present.  Build into a tmp file and rename, so a
    # crash mid-write never leaves a half-archive at the requested
    # path -- callers should be able to retry without a stale file
    # tripping their next attempt.
    output_abs = os.path.abspath(output)
    tmp_path = output_abs + ".part"
    try:
        with _tar.open(tmp_path, "w:gz") as tf:
            tf.add(keyfile, arcname=os.path.basename(keyfile))
            tf.add(leaves_path, arcname=os.path.basename(leaves_path))
            if receipt_leaves_path is not None:
                tf.add(
                    receipt_leaves_path,
                    arcname=os.path.basename(receipt_leaves_path),
                )
        os.replace(tmp_path, output_abs)
    except Exception as e:
        # Best-effort cleanup of the partial.
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        print(
            f"Error: failed to write backup archive {output_abs}: "
            f"{type(e).__name__}: {e}"
        )
        return 2

    print(f"Wrote wallet backup: {output_abs}")
    print(f"  entity_id: {entity_hex}")
    if receipt_leaves_path is not None:
        print(f"  includes receipt-subtree leaf cursor: {receipt_leaves_path}")
    print(
        "Store this archive somewhere offline (paper-equivalent: "
        "encrypted USB in a safe, NOT cloud sync). The keyfile and "
        "ALL leaf cursors are security-critical -- never restore one "
        "without the others."
    )
    return 0


def cmd_notify_test(args):
    """Send a one-shot test email using the configured SMTP creds."""
    from messagechain.runtime import notify as _notify
    from messagechain.runtime import onboarding as _ob

    cfg = _ob.read_onboard_config()
    try:
        _notify.notify_test(cfg)
    except _notify.NotifyConfigError as e:
        print(f"Error: {e}")
        sys.exit(2)
    except Exception as e:
        # SMTP / network error -- show the operator the failure mode
        # without leaking the password (the exception class + recipient
        # are enough to diagnose; never str(cfg)).
        print(
            f"Error: SMTP send failed ({type(e).__name__}): {e}"
        )
        sys.exit(2)
    print("Test email sent. Check the configured recipient inbox.")


def cmd_notify_status(args):
    """Print current notify config (password redacted) + last-sent log."""
    from messagechain.runtime import notify as _notify
    from messagechain.runtime import onboarding as _ob

    cfg = _ob.read_onboard_config()
    # Pull last_sent from the persisted state file (default location);
    # not reading any chain state here.
    data_dir = cfg.get("data_dir") or None
    state_path = _notify.default_state_path(data_dir)
    try:
        state = _notify.NotifyState.load(state_path)
        last_sent = dict(state.last_sent)
    except Exception:
        last_sent = {}
    print(_notify.format_status(cfg, last_sent=last_sent))


def cmd_ui(args):
    """Run the local wallet UI server.

    Loads the user's private key into process memory (unless
    ``--read-only``), then starts the loopback HTTP wallet server.
    See messagechain/network/local_wallet_server.py for the threat
    model and the four foot-gun defenses (loopback bind, Host-header
    allowlist, per-session bearer token, no CORS).
    """
    from messagechain.network.local_wallet_server import (
        LocalWalletServer,
        LoopbackBindError,
    )

    print("=== MessageChain Local Wallet UI ===\n")

    entity = None
    if args.read_only:
        print("Mode: read-only (no key loaded; no signing routes)\n")
    else:
        # Resolve and load the wallet key.  First-ever load on a host
        # without the keypair_cache pays the WOTS+ keygen cost up
        # front (~minutes); subsequent starts are cache HITs in ms.
        # Doing this BEFORE the server starts means the operator
        # never sees a wallet route hang on a slow first sign.
        try:
            private_key = _resolve_private_key(args, personal_wallet=True)
        except KeyFileError as e:
            print(f"Error: {e}")
            sys.exit(1)
        print("Loading wallet keys (this may take minutes the first time)...")
        entity = _resolve_signing_entity(private_key, args)
        print(f"Loaded entity: {entity.entity_id_hex[:16]}...\n")

    # Resolve the local validator's RPC endpoint for chain reads
    # (/v1/*) and tx submission (/wallet/* writes, in follow-ups).
    rpc_host, rpc_port = _parse_server(args.server)

    try:
        server = LocalWalletServer(
            blockchain=None,
            port=args.port,
            bind=args.bind,
            token=args.auth_token,
            entity=entity,
            rpc_endpoint=(rpc_host, rpc_port),
        )
    except LoopbackBindError as e:
        print(f"Error: {e}")
        sys.exit(1)

    server.start()
    print(f"Wallet UI listening on {server.url}")
    print()
    print("This URL contains a per-session token.  Treat it like a password:")
    print("anyone who can read it can drive the wallet routes.  The token")
    print("rotates on every restart; sharing the URL across machines is unsafe.")
    print()

    if not args.no_browser:
        try:
            import webbrowser
            webbrowser.open(server.url)
        except Exception:
            # Headless environment / no browser available --
            # operator can paste the URL themselves.
            pass

    print("Press Ctrl+C to stop.\n")
    try:
        import time as _time
        while True:
            _time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down wallet UI...")
        server.stop()


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
        "set-receipt-subtree-root": cmd_set_receipt_subtree_root,
        "bootstrap-seed": cmd_bootstrap_seed,
        "emergency-revoke": cmd_emergency_revoke,
        "broadcast-revoke": cmd_broadcast_revoke,
        "rotate-key": cmd_rotate_key,
        "key-status": cmd_key_status,
        "propose": cmd_propose,
        "vote": cmd_vote,
        "react": cmd_react,
        "generate-key": cmd_generate_key,
        "verify-key": cmd_verify_key,
        "read": cmd_read,
        "info": cmd_info,
        "release-status": cmd_release_status,
        "status": cmd_status,
        "proposals": cmd_proposals,
        "validators": cmd_validators,
        "peers": cmd_peers,
        "receipt": cmd_receipt,
        "submit-evidence": cmd_submit_evidence,
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
        "notify-test": cmd_notify_test,
        "notify-status": cmd_notify_status,
        "backup-wallet": cmd_backup_wallet,
        "ui": cmd_ui,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
