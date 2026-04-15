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

### Rehearse locally first

```bash
python -m unittest tests.test_genesis_launch_plan tests.test_bootstrap_rehearsal
```

These drive the recommended 3-seed + shared-payout layout end-to-end
(genesis allocation, each seed registering + setting authority + staking,
payout entity registering via the block pipeline, a reward sweep).
If they pass on your build, production wiring is sound; what's left is
pure operator ops.

### Keys to generate (offline, airgap)

Seven keypairs total.  Generate each with `messagechain generate-key`
and write the 24-word mnemonic down:

| Keypair | Where the private key lives | On-chain? |
|---|---|---|
| `seed1_hot` | on validator server #1 | yes, registered |
| `seed2_hot` | on validator server #2 | yes, registered |
| `seed3_hot` | on validator server #3 | yes, registered |
| `cold1` | in the safe | no — authority-key binding only |
| `cold2` | in the safe | no — authority-key binding only |
| `cold3` | in the safe | no — authority-key binding only |
| `payout` | in the safe | yes, registered post-genesis |

The three cold keys must be distinct — the chain rejects two entities
sharing the same authority public key (that would collapse three
seeds' trust into one secret).  The payout is a single shared entity
that all three seeds sweep rewards to.

### Genesis allocation

Use the helper rather than computing by hand; it encodes the
recommended numbers and rejects obvious mis-configurations (wrong
seed count, non-distinct seed IDs):

```python
from messagechain.core.bootstrap import build_launch_allocation
from messagechain.core.blockchain import Blockchain

allocation = build_launch_allocation([
    seed1.entity_id, seed2.entity_id, seed3.entity_id,
])
# => {TREASURY_ENTITY_ID: 40_000_000,
#     seed1.entity_id:    251_000,   # 250K stake + 1K fee buffer
#     seed2.entity_id:    251_000,
#     seed3.entity_id:    251_000}

chain = Blockchain()
chain.initialize_genesis(seed1, allocation_table=allocation)
```

Founder-visible supply = 753,000 tokens = **0.0753 %** of the 1 B
genesis cap.  Small enough that nobody can credibly claim "founder
concentration."  The 40 M treasury is governance-controlled, not the
founder's.

The payout entity is NOT in the genesis allocation — it registers
post-genesis by submitting a `RegistrationTransaction` through the
normal block pipeline.

### Seed endpoint config

Before deploying, edit
[`messagechain/config.py`](messagechain/config.py)
`CLIENT_SEED_ENDPOINTS` to your three seed IPs:

```python
CLIENT_SEED_ENDPOINTS: list[tuple[str, int]] = [
    ("seed1.example.com", 9333),
    ("seed2.example.com", 9333),
    ("seed3.example.com", 9333),
]
```

CLI clients contact one of these seeds at random for their first
RPC.  Once non-seed validators come online and are reachable, clients
automatically switch to `sqrt(stake)`-weighted random routing across
the full validator set.  Seeds stay available as entry points but
stop monopolizing client load.  Users can override per-command with
`--server host:port`.

### Per-seed launch commands

On each VPS (after `messagechain start --mine` is running):

```bash
messagechain bootstrap-seed \
    --authority-pubkey <cold_N_public_key_hex> \
    --stake-amount 250000 \
    --server localhost:9333
```

This submits three transactions in sequence — `register_entity`,
`set-authority-key`, `stake` — and reports status.  Verify afterwards:

```bash
messagechain info --entity-id <seed_N_entity_id>
# Must show: staked >= 250000 AND authority_key == <cold_N_public_key>
```

### Register the shared payout

Once any seed is running, from the box that holds the payout
mnemonic (airgap until this moment, then network-connected for a
single RPC):

```bash
messagechain account    # prompts for the payout mnemonic, builds and
                        # submits RegistrationTransaction
```

The registration lands in the next block and propagates to every
peer.  The payout private key can return to the safe immediately
afterwards — receiving transfers does not require its signature.

### Periodic reward sweep

From each seed server, after block rewards have matured
(`COINBASE_MATURITY` = 10 blocks ≈ 100 minutes):

```bash
messagechain transfer \
    --to <payout_entity_id> \
    --amount <matured_rewards>
```

The transfer is signed by the **seed's hot key** — the key that's
already online.  Rewards consolidate on the payout address.  The
payout private key stays cold; you only bring it online if and when
you eventually want to move funds out of the payout wallet.

## Tests

```bash
python -m unittest discover tests/
```
