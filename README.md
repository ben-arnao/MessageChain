# MessageChain

[![release](https://img.shields.io/github/v/release/ben-arnao/MessageChain)](https://github.com/ben-arnao/MessageChain/releases)
[![license](https://img.shields.io/github/license/ben-arnao/MessageChain)](./LICENSE)

A blockchain for sending messages. Quantum-resistant, proof-of-stake,
built to last centuries.

**Status:** mainnet live. Chain ID `messagechain-v1`, genesis block 0
`4eeb9edaadb42f1a460e95919bc667a3173c4a84aa9b5488da040ac7a1c054f6`.

**Live feed:** [messagechain.org](https://messagechain.org)

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
- **Cheap to validate.** Runs on commodity hardware — no GPUs, no
  specialized rigs.

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
messagechain send "reply" --prev <tx_hash_hex>  # reference a prior message
messagechain estimate-fee --message "hello world"   # preview cost
```

Your first outgoing transaction reveals your public key on-chain
(the "first-spend pubkey install" path). After that, every
subsequent transaction is verified against the installed key.

The optional `--prev` flag attaches a 32-byte pointer to a prior
on-chain message (by its `tx_hash`), forming a single-linked list —
protocol-agnostic: apps can render this as a reply thread, a chained
long-form document, a citation, etc. The referenced tx must already
be on-chain in a strictly earlier block. The pointer adds 33 bytes
to the fee basis but does NOT count against the 1024-char message
cap, so you keep the full text budget. (Activates at
`PREV_POINTER_HEIGHT`.)

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
messagechain send "reply" --prev <tx_hash>      # reply/chain to a prior message
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

```bash
messagechain stake --amount 10000               # lock as validator stake
messagechain unstake --amount 5000              # ~15-day unbonding
messagechain start --mine                       # run a validator
messagechain key-status                         # WOTS+ leaf usage
messagechain rotate-key                         # fresh keypair, old key retired
messagechain upgrade                            # install the latest mainnet tag
```

## Run a validator

You need 10,000 tokens to stake and an always-on Linux host (Python
3.10+, ~2 GB RAM) with inbound TCP **9333 + 9334** open in your
cloud firewall.

```bash
# 1. install on the host (as root) — generates the validator's keyfile
curl -L https://raw.githubusercontent.com/ben-arnao/MessageChain/main/scripts/install-validator.sh | sudo bash

# 2. print the validator's address (its keyfile signs blocks AND owns the stake)
sudo -u messagechain messagechain account --keyfile /etc/messagechain/keyfile

# 3. from a wallet that has tokens, send 10,000 to that address:
#    messagechain transfer --to mc1... --amount 10000
#    then back on the host:
sudo -u messagechain messagechain stake --amount 10000

# 4. start
systemctl enable --now messagechain-validator messagechain-upgrade.timer messagechain-rotate-key.timer

# 5. verify
messagechain status
journalctl -u messagechain-validator -f   # follow the log if status looks off
```

The installer's keyfile **is** the validator's identity — the same
key signs blocks and owns the stake, so tokens have to flow to the
address it prints, not your wallet's address. Back the keyfile up.

Rewards = block reward + tx fees + attester pool share, pro-rata by
stake. Unbonding takes ~15 days (2176 blocks) — slashing windows
extend past departure.

<details>
<summary>Manual install &amp; advanced operations</summary>

**Manual run.** `messagechain generate-key`, store the hex on paper,
then:

```bash
messagechain start --mine --rpc-bind 0.0.0.0 \
  --data-dir /var/lib/messagechain --keyfile /etc/messagechain/keyfile
```

A systemd unit example ships at
[`examples/messagechain-validator.service.example`](./examples/messagechain-validator.service.example).

**Preflight.** `messagechain doctor` checks perms, ports, seeds, and
disk. `messagechain status --full` confirms chain reachability.

**Toggle automation.** `messagechain config set auto_upgrade false` /
`auto_rotate false` disables the timers.

**Cold authority.** `messagechain set-authority-key --authority-pubkey
<cold_hex>` requires a cold-signed key for future rotations.
`messagechain emergency-revoke --entity-id <hex>` is the cold-signed
kill switch.

**Bare init.** The installer wraps `messagechain init`; you can run
that directly on hosts where you don't want the curl-pipe.

</details>

## Security & changelog

- Vulnerabilities: see [SECURITY.md](./SECURITY.md) — private email
  disclosure, 72h ack, 7d triage. Do not open a public issue.
- Release notes: see [CHANGELOG.md](./CHANGELOG.md).
