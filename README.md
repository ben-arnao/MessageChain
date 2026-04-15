# MessageChain

A blockchain for sending messages. Quantum-resistant, proof-of-stake, built to last centuries.

## Install

Requires **Python 3.10+** (uses `X | Y` union syntax). No third-party dependencies.

```bash
git clone https://github.com/ben-arnao/MessageChain.git
cd MessageChain
```

## Quickstart

**🔌 Disconnect from the internet before running the next two commands.**

```bash
python -m messagechain generate-key      # prints private key — write it on paper, 2–3 copies
python -m messagechain verify-key        # re-enter by hand; confirms the backup is correct
```

Close the terminal window when done — that discards the scrollback showing your key. Don't copy-paste; clipboard managers log history.

**🔌 Reconnect to the internet.** In a new terminal:

```bash
python -m messagechain account           # register your wallet on-chain (signs once, online)
python -m messagechain start             # sync the full chain — leave running in this terminal
```

`start` is a foreground process; open a second terminal for the commands below. `account` briefly loads your key in memory to sign — unavoidable, so only run it on a trusted machine.

> **Before it'll work:** the shipped seed list is a `127.0.0.1` placeholder. Until a public seed is announced, pass `--seed <host>:<port>` from someone on the network, or `start` will idle with zero peers. New wallets also start at **0 balance** — there is no faucet, so `send` / `transfer` / `stake` need someone to fund you first.

## Everyday commands

```bash
# Messaging & funds
python -m messagechain send "hello"                          # post a message
python -m messagechain transfer --to <id> --amount 100       # send funds
python -m messagechain balance                               # check your balance
python -m messagechain read --last 50                        # last 50 messages
python -m messagechain estimate-fee --message "hi"           # fee preview (or --transfer)

# Governance
python -m messagechain propose --title "..." --description "..."
python -m messagechain vote --proposal <id> --yes            # or --no
python -m messagechain proposals                             # status + tally
python -m messagechain delegate --to <validator_id> --pct 100

# Info
python -m messagechain info                                  # chain info
```

To **receive funds**, share the `mc1…` address printed by `account` / `balance` — the checksummed form catches transcription typos. Raw 64-hex entity IDs still work.

Signing commands prompt for your private key interactively. Override the target node with `--server host:port`.

## Running a validator

Earn block rewards by staking. Validator must keep `start --mine` running continuously.

```bash
python -m messagechain start --mine                          # run as validator (foreground)
python -m messagechain stake --amount 100                    # min stake: 100 tokens
python -m messagechain unstake --amount 100                  # 7-day unbonding before withdrawable
python -m messagechain validators                            # stake %, blocks mined per validator
```

Use a dedicated, patched machine you physically control — not a daily-driver laptop.

## Advanced / validator ops

**Unattended start** (systemd, Docker — no interactive key prompt):

Linux / macOS:

```bash
echo "<checksummed_private_key>" > /etc/messagechain/validator.key
chmod 0600 /etc/messagechain/validator.key
python -m messagechain start --mine --keyfile /etc/messagechain/validator.key
```

Windows (PowerShell, admin):

```powershell
Set-Content -Path "$env:ProgramData\MessageChain\validator.key" -Value "<checksummed_private_key>" -NoNewline
icacls "$env:ProgramData\MessageChain\validator.key" /inheritance:r /grant:r "$env:USERNAME:(R)"
python -m messagechain start --mine --keyfile "$env:ProgramData\MessageChain\validator.key"
```

**Key rotation** — WOTS+ signatures burn leaves. Rotate before the tree fills (typically ~80%):

```bash
python -m messagechain key-status                            # leaf usage
python -m messagechain rotate-key                            # roll signing key (entity ID unchanged)
```

**Cold-key separation** — bind a second, offline-generated key as the withdrawal authority. After this, `unstake` and `emergency-revoke` require the cold key, so a compromised hot key can't drain your stake.

```bash
python -m messagechain set-authority-key --authority-pubkey <hex>
python -m messagechain emergency-revoke --entity-id <hex>    # kill-switch for a compromised validator
```

Keep a pre-signed `emergency-revoke` on paper for rapid response.

## Tests

```bash
python -m unittest discover tests/
```
