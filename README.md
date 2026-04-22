# MessageChain

A blockchain for sending messages. Quantum-resistant, proof-of-stake,
built to last centuries.

**Status:** mainnet live since 2026-04-20. Chain ID `messagechain-v1`,
genesis block 0
`4eeb9edaadb42f1a460e95919bc667a3173c4a84aa9b5488da040ac7a1c054f6`.

## Why

- **Censorship-resistant communication.** No platform, government, or
  ISP can hide, filter, or silently remove your messages. If it's
  on-chain, it's there forever.
- **Costly to spam.** Every message costs real tokens. Bots can
  participate, but they pay the same price as everyone else —
  AI-generated noise has a floor.
- **Simple and durable.** Designed to run for centuries with minimal
  moving parts. Slow blocks and expensive fees are features, not bugs.
  Zero runtime dependencies outside the Python stdlib.
- **Democratic by default.** On-chain governance, distributed
  validation, no privileged operators. L2s can layer reputation,
  identity, and moderation on top.

## Install

Python 3.10+, no third-party deps.

```bash
git clone https://github.com/ben-arnao/MessageChain.git
cd MessageChain
pip install .
```

This puts a `messagechain` command on your PATH. You can run it the
same way via `python -m messagechain <cmd>` if you prefer.

## Getting started — your first message

### 1. Generate a private key (offline)

```bash
messagechain generate-key    # write the printed hex on paper, 2–3 copies
messagechain verify-key      # re-type to confirm the backup
```

Paper beats files — files get swept by cloud sync, backups, and
malware. Don't copy-paste (clipboard managers log history). Close
the terminal when done.

Your entity_id and `mc1…` address are derived deterministically from
the key.

### 2. Get tokens

MessageChain uses a **receive-to-exist** model: you do not need to
register anything on-chain to receive tokens. Your account appears in
chain state the moment someone sends you a transfer.

### 3. Send a message

```bash
messagechain send "hello world"                 # auto-priced (default)
messagechain send "hello world" --fee 500       # pay a specific amount
messagechain estimate-fee --message "hello world"   # preview cost
```

Default: `send` picks `max(protocol-floor, network-suggested)` so your
tx is never rejected for underpayment. The protocol floor is a flat
per-tx minimum — a one-character message and a full 280-character
message cost the same. Multi-part messages pay the floor per tx, so
a 10-tx thread costs exactly twice a 5-tx thread. Above the floor,
the market sets the price: base fee is burned; any tip above base
fee goes to the proposer.

Your first outgoing transaction reveals your public key on-chain
(the "first-spend pubkey install" path). After that, every
subsequent transaction is verified against the installed key.

### 4. Read messages back

Wait one block (~10 minutes) for your message to be included, then:

```bash
messagechain read --last 20
```

## CLI reference

### Personal wallet

```bash
messagechain generate-key                       # new private key (offline)
messagechain verify-key                         # confirm backup
messagechain account                            # print your address + entity_id
messagechain balance                            # liquid + staked tokens
messagechain send "hello"                       # post a message
messagechain transfer --to mc1… --amount 100    # send tokens
messagechain read --last 50                     # recent messages
messagechain estimate-fee --message "hi"        # fee preview
```

### Chain & validator info

```bash
messagechain info                               # chain height, supply, sync
messagechain validators                         # validator set, stakes, shares
messagechain peers                              # P2P peers of the target node
messagechain status --server HOST:9334          # one-call health check
messagechain status --server HOST:9334 --entity YOUR_ID
                                                # validator-specific leaf usage
messagechain ping                               # first-run sanity check
```

### Governance

```bash
messagechain propose --title "…" --description "…"
messagechain vote --proposal <id> --yes
messagechain proposals                          # open proposals + tallies
```

### Validator operations

Quick start: stake tokens, then run `start --mine` on a host with
TCP 9333/9334 open. `key-status` warns you when to rotate your
WOTS+ signing key before it exhausts.

```bash
messagechain start --mine                       # run a validator
messagechain stake --amount 10000               # lock as validator stake
messagechain unstake --amount 5000              # 7-day unbonding
messagechain key-status                         # WOTS+ leaf usage; when to rotate
messagechain rotate-key                         # fresh keypair, old key retired
messagechain set-authority-key --authority-pubkey <cold_hex>
messagechain emergency-revoke --entity-id <hex> # cold-signed kill switch
```

