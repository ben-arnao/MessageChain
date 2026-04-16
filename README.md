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

## Founder runbook (launching a new chain)

If you are the first operator of a fresh MessageChain, the repo ships a
single-command bootstrap script.  Everyone else — including any later
validators — joins via the normal `start --mine` flow and syncs from
your node.

```bash
# 1. Generate a 32-byte key offline, save hex to a 0600 file
python -c "import os; print(os.urandom(32).hex())" > /etc/messagechain/keyfile
chmod 600 /etc/messagechain/keyfile

# 2. Mint genesis + stake in one shot
python deploy/launch_single_validator.py \
    --data-dir /var/lib/messagechain \
    --keyfile /etc/messagechain/keyfile
# → prints your address, block-0 hash, balance, stake

# 3. Paste the block-0 hash into messagechain/config.py PINNED_GENESIS_HASH
#    and commit.  This stops any future cloner from minting a competing
#    genesis on their own machine.

# 4. Start the server (systemd unit provided at deploy/systemd/)
sudo cp deploy/systemd/messagechain-validator.service /etc/systemd/system/
sudo systemctl enable --now messagechain-validator
```

## Tests

```bash
python -m unittest discover tests/
```
