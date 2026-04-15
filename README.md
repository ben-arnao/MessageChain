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

**Why paper, not a file?** Any file gets swept up by cloud-sync (iCloud/OneDrive/Dropbox), system backups, disk forensics, or a single malware hit that greps for key-shaped blobs. Paper can only be stolen by physical access or a camera in the room. The `--keyfile` flow further down is a controlled exception for unattended validators on dedicated, locked-down machines.

Close the terminal window when done — that discards the scrollback showing your key. Don't copy-paste; clipboard managers log history.

**🔌 Reconnect to the internet.** In a new terminal:

```bash
python -m messagechain account           # register your wallet on-chain (signs once, online)
python -m messagechain start             # sync the full chain — leave running in this terminal
```

`start` is a foreground process; open a second terminal for the commands below. `account` briefly loads your key in memory to sign — unavoidable, so only run it on a trusted machine.

Chain data lives at `~/.messagechain/chaindata/` by default (override with `--data-dir <path>`). Delete it to wipe local state and re-sync from peers.

> **Before it'll work:** the shipped seed list is empty pending public launch. Pass `--seed <host>:<port>` with an announced seed, or `start` will idle with zero peers. New wallets also start at **0 balance** — there is no faucet, so `send` / `transfer` / `stake` need someone to fund you first.

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
sudo mkdir -p /etc/messagechain
echo "<checksummed_private_key>" | sudo tee /etc/messagechain/validator.key > /dev/null
sudo chmod 0600 /etc/messagechain/validator.key
python -m messagechain start --mine --keyfile /etc/messagechain/validator.key
```

Windows (PowerShell, admin):

```powershell
New-Item -ItemType Directory -Force -Path "$env:ProgramData\MessageChain" | Out-Null
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

## Operator runbook: genesis launch with 3 seeds

Before touching real hardware, rehearse locally:
```bash
python -m unittest tests.test_bootstrap_rehearsal
```

This exercises the exact sequence three seed validators perform on
first launch — register, set-authority-key, stake — plus the post-
conditions a production setup must verify.

**Entity layout per seed:** one hot signing key (lives on the validator
server) + one *separate* cold authority key (offline, stored in a safe).
Reusing the same cold key across seeds is rejected by the chain — it
would collapse all three seeds' trust into a single secret, so use
three distinct cold keys (three separate mnemonics).

**Genesis allocation must cover stake PLUS fee padding.** Each seed
consumes `MIN_FEE` (~100 tokens) during bootstrap to pay for the
`set-authority-key` transaction, and subsequent ops will consume more.
Budget `stake + ~10 × MIN_FEE` of liquid balance per seed at genesis so
an under-estimate doesn't silently leave you unstaked. Example for a
250,000-token target stake:
```
seed_genesis = 250_000 + 1_000  # = 251,000 liquid
```

**Reward sweeps require a separate payout entity.** The chain enforces
that cold authority keys cannot match any registered entity's signing
key.  That means you cannot send rewards from a seed "back to the cold
wallet" if the cold wallet is registered — and you cannot receive
transfers at an unregistered entity.  Two workable patterns:

1. **Three entities per seed: hot + cold + payout.**  Hot signs blocks,
   cold gates unstake/revoke, payout is a separately registered
   on-chain entity that receives swept rewards.  Keep the payout
   private key cold (airgap) and register it on chain once, pre-launch.
2. **Accept that the cold authority key is also the payout key.**  To
   receive rewards you must register it — which forbids using it as
   anyone's authority key.  Simplest option but slightly less isolated.

Most operators want pattern (1).  If you don't need cold authority
coverage, pattern (2) is fine.

**Seed endpoint configuration.**  Before deploy, edit
[`messagechain/config.py`](messagechain/config.py) `CLIENT_SEED_ENDPOINTS`
to list your three seed IPs.  These are the hardcoded entry points
CLI clients use until the network has enough non-seed validators to
route via sqrt(stake)-weighted selection.  Clients fall through to
the dev-only `127.0.0.1:9333` if all seeds are unreachable — that's
a bootstrap convenience, not a production fallback.

**Post-launch routing** — once external validators come online AND a
seed's `peers` map knows their advertised entity IDs, CLI clients
automatically switch from "always use a seed" to a sqrt(stake)-weighted
random pick across all reachable validators.  The seeds stay available
as entry points but stop monopolizing client load.  Users can manually
override per-command with `--server host:port`.

## Tests

```bash
python -m unittest discover tests/
```
