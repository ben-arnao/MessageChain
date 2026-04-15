# MessageChain

A blockchain for sending messages. Quantum-resistant, proof-of-stake, built to last centuries.

## Install

Python 3.10+, no third-party deps.

```bash
git clone https://github.com/ben-arnao/MessageChain.git
cd MessageChain
```

All signing commands prompt for your private key. Override the target node with `--server host:port`; otherwise the CLI auto-picks a seed from [`CLIENT_SEED_ENDPOINTS`](messagechain/config.py) and routes by `sqrt(stake)`.

## CLI

### Create a wallet (to receive funds)

**🔌 Go offline first.**

```bash
python -m messagechain generate-key    # write the private key on paper, 2–3 copies
python -m messagechain verify-key      # re-type to confirm the backup
```

Paper beats files: files get swept by cloud-sync, backups, and malware. Don't copy-paste (clipboard managers log history). Close the terminal when done.

**🔌 Back online.** Register the wallet on-chain (one signature):

```bash
python -m messagechain account
```

Share the `mc1…` address printed by `balance` to receive funds.

### Post a message

```bash
python -m messagechain send "hello"
```

### Send / receive tokens

```bash
python -m messagechain transfer --to <mc1…> --amount 100
python -m messagechain balance
```

### Read the last N messages

```bash
python -m messagechain read --last 50    # entity_id, timestamp, message
```

### Estimate the fee

```bash
python -m messagechain estimate-fee --message "hi"    # or --transfer
```

### Validator set & stake shares

```bash
python -m messagechain validators    # entity, stake, share %, blocks produced
```

### Governance

```bash
# Propose — link a PR by pasting its URL into the description
python -m messagechain propose --title "Adopt EIP-X" \
    --description "See https://github.com/ben-arnao/MessageChain/pull/42"

python -m messagechain vote --proposal <id> --yes        # or --no
python -m messagechain proposals                         # status, tally, blocks remaining
```

### Run a validator (stake + mine)

Validator must keep `start --mine` running continuously. Use a dedicated machine.

```bash
python -m messagechain start --mine                  # foreground; also syncs the chain
python -m messagechain stake --amount 100            # min stake graduates 1→10→100 with chain height; 7-day unbonding
python -m messagechain unstake --amount 100
```

Chain data: `~/.messagechain/chaindata/` (override with `--data-dir`).

**Unattended** (systemd, Docker): put the key in a 0600 file and pass `--keyfile`.

**Bootstrap seed** — one command registers, sets a cold authority key, and stakes:

```bash
python -m messagechain bootstrap-seed \
    --authority-pubkey <cold_pubkey_hex> --stake-amount 250000
```

**Cold-key separation** — after set-up, `unstake` and `emergency-revoke` require the cold key:

```bash
python -m messagechain set-authority-key --authority-pubkey <hex>
python -m messagechain emergency-revoke --entity-id <hex>   # kill-switch, cold-signed
```

**Rotate WOTS+ signing key** before leaves exhaust (~80%):

```bash
python -m messagechain key-status
python -m messagechain rotate-key
```

### Sync the chain (independent audit, no mining)

```bash
python -m messagechain start    # relay-only: downloads and verifies the full chain
```

## Tests

```bash
python -m unittest discover tests/
```
