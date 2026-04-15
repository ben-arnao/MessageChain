# MessageChain

A blockchain for sending messages. Quantum-resistant, proof-of-stake, built to last centuries.

## Install

```bash
git clone https://github.com/ben-arnao/MessageChain.git
cd MessageChain
pip install -r requirements.txt
```

## Quickstart

**🔌 Disconnect from the internet before running the next two commands.**

```bash
python -m messagechain generate-key      # prints private key — write it on paper, 2–3 copies
python -m messagechain verify-key        # re-enter by hand; confirms the backup is correct
```

Clear your terminal history.

**🔌 Reconnect to the internet.**

```bash
python -m messagechain account           # register your wallet on-chain
python -m messagechain start             # sync the full chain (leave running)
```

You're done. Commands below operate against your running node.

## Cheat sheet

```bash
# Messaging & funds
python -m messagechain send "hello"                          # post a message
python -m messagechain transfer --to <id> --amount 100       # send funds
python -m messagechain balance                               # check your balance
python -m messagechain read --last 50                        # last 50 messages
python -m messagechain estimate-fee --message "hi"           # fee preview (or --transfer)

# Validating (stake + mine)
python -m messagechain start --mine                          # run as validator
python -m messagechain stake --amount 100                    # min stake: 100, 7-day unbond
python -m messagechain validators                            # stake %, blocks mined
python -m messagechain key-status                            # leaf usage — rotate before full
python -m messagechain rotate-key                            # roll signing key (ID unchanged)
python -m messagechain set-authority-key --authority-pubkey <hex>   # cold key for unstake/revoke
python -m messagechain emergency-revoke --entity-id <hex>    # disable a compromised validator

# Governance
python -m messagechain propose --title "..." --description "..."
python -m messagechain vote --proposal <id> --yes            # or --no
python -m messagechain proposals                             # status + tally
python -m messagechain delegate --to <validator_id> --pct 100

# Info
python -m messagechain info                                  # chain info
```

To **receive funds**, share your entity ID.

Signing commands prompt for your private key; it stays in memory only long enough to sign. Override the target node with `--server host:port`.

**Cold key (validators):** generate a second key offline (same `generate-key` drill), then run `set-authority-key` with its pubkey. After that, `unstake` and `emergency-revoke` must be signed by the cold key — so a compromised hot key can't drain your stake. Keep a pre-signed `emergency-revoke` on paper for rapid response.

## Tests

```bash
python -m unittest discover tests/
```
