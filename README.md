# MessageChain

A blockchain for sending messages. Quantum-resistant, proof-of-stake,
built to last centuries.

**Status:** mainnet live at `35.237.211.12:9334` since 2026-04-18.
See [`docs/launch-readiness.md`](docs/launch-readiness.md) for current state.

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

Ask the operator of a node you trust (or a faucet, if the chain has
one) to send you tokens:

```
Hi, can you send 10,000 tokens to mc1<your address>?
```

A few minutes later (one block, 600 s block time), you have a balance.

### 3. Send a message

```bash
messagechain send "hello world"
```

Your first outgoing transaction reveals your public key on-chain (the
"first-spend pubkey install" path). After that, every subsequent
transaction is verified against the installed key.

### 4. Read messages back

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

See [`docs/second-validator-onboarding.md`](docs/second-validator-onboarding.md)
for the full multi-validator flow.

```bash
messagechain start --mine                       # run a validator
messagechain stake --amount 10000               # lock as validator stake
messagechain unstake --amount 5000              # 7-day unbonding
messagechain key-status                         # WOTS+ leaf usage; when to rotate
messagechain rotate-key                         # fresh keypair, old key retired
messagechain set-authority-key --authority-pubkey <cold_hex>
messagechain emergency-revoke --entity-id <hex> # cold-signed kill switch
```

## Launching a new chain (founder runbook)

If you are minting a fresh MessageChain (not joining mainnet), see
[`docs/operator-action-items.md`](docs/operator-action-items.md) for the
full checklist.  The one-shot is:

```bash
# Offline, on an air-gapped machine:
python -c "import secrets; print(secrets.token_hex(32))" > /etc/messagechain/keyfile
chmod 400 /etc/messagechain/keyfile

python deploy/launch_single_validator.py \
    --data-dir /var/lib/messagechain \
    --keyfile /etc/messagechain/keyfile \
    --liquid 5000000 --stake 95000000 --tree-height 20
# → prints your block-0 hash and validator address

# Commit the block-0 hash into messagechain/config.py _MAINNET_GENESIS_HASH
# (or _TESTNET_GENESIS_HASH for a testnet), then deploy your validator.
```

## Deployment profiles

`MESSAGECHAIN_PROFILE` flips a coherent bundle of defaults:

- `production` (default) — 600s blocks, MERKLE_TREE_HEIGHT=20,
  checkpoints required, RPC auth enabled.
- `prototype` — bootstrap-phase bundle: 30s blocks,
  MERKLE_TREE_HEIGHT=16, checkpoints waived, RPC auth disabled.

Individual env vars
(`MESSAGECHAIN_BLOCK_TIME_TARGET`, `MESSAGECHAIN_MERKLE_TREE_HEIGHT`,
`MESSAGECHAIN_REQUIRE_CHECKPOINTS`, `MESSAGECHAIN_RPC_AUTH_ENABLED`)
override individual profile entries.

## Documentation

- [`docs/launch-readiness.md`](docs/launch-readiness.md) — current launch state, dashboard
- [`docs/security-model.md`](docs/security-model.md) — threat model + external-audit scope
- [`docs/known-issues.md`](docs/known-issues.md) — triaged deferrals + post-launch roadmap
- [`docs/operator-action-items.md`](docs/operator-action-items.md) — pre-mainnet checklist
- [`docs/mainnet-params.md`](docs/mainnet-params.md) — block-0-immutable parameters
- [`docs/going-live.md`](docs/going-live.md) — operator deployment runbook
- [`docs/backup-restore-runbook.md`](docs/backup-restore-runbook.md) — disaster recovery
- [`docs/key-rotation-runbook.md`](docs/key-rotation-runbook.md) — WOTS+ key rotation
- [`docs/second-validator-onboarding.md`](docs/second-validator-onboarding.md) — bringing N>1
- [`docs/tor-setup.md`](docs/tor-setup.md) — hidden-service setup for adversarial environments
- [`docs/system-audit.md`](docs/system-audit.md) — running audit log

## Tests

```bash
python -m unittest discover tests/
# 2,065 tests, 3 skipped
```

## License

MIT.  See `LICENSE`.
