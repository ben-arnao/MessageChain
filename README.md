# MessageChain

A blockchain for sending messages. Quantum-resistant signatures, proof-of-stake consensus, fee-based spam prevention. Designed to last centuries.

## Install

```bash
git clone https://github.com/YourUser/MessageChain.git
cd MessageChain
pip install -r requirements.txt
```

## Commands

All commands target a local node at `127.0.0.1:9334`; override with `--server host:port`. Signing commands prompt for your private key interactively; it lives in memory only long enough to sign.

| You want to... | Command |
|---|---|
| Generate a private key (offline) | `python -m messagechain generate-key` |
| Verify a written-down key (offline) | `python -m messagechain verify-key` |
| Register your wallet on-chain | `python -m messagechain account` |
| Connect to the network and sync the full chain | `python -m messagechain start` |
| Run a validator (sync + mine blocks) | `python -m messagechain start --mine` |
| Stake funds to earn block rewards | `python -m messagechain stake --amount 100` |
| Post a message | `python -m messagechain send "hello"` |
| Send funds | `python -m messagechain transfer --to <entity_id> --amount 100` |
| Receive funds | Share your entity ID — no action on your end. |
| Check your balance | `python -m messagechain balance` |
| Read the last N messages | `python -m messagechain read --last 50` |
| List validators (stake, share %, blocks mined) | `python -m messagechain validators` |
| Estimate a fee before sending | `python -m messagechain estimate-fee --message "hi"` or `--transfer` |
| Propose a governance vote | `python -m messagechain propose --title "..." --description "..."` |
| Vote on a proposal | `python -m messagechain vote --proposal <id> --yes` (or `--no`) |
| Check proposal status + tally | `python -m messagechain proposals` |
| Delegate voting power (up to 3 validators) | `python -m messagechain delegate --to <validator_id> --pct 100` |
| Show chain info | `python -m messagechain info` |

## Key handling

Your private key is generated **offline** and stored on paper. It only enters a networked machine briefly, in memory, when you sign.

1. Disconnect from the internet. `generate-key` → write the key on paper, 2–3 copies in separate secure locations. Do not save it digitally.
2. `verify-key` → re-enter by hand; confirm the derived public key and entity ID match.
3. Clear terminal history, reconnect, `account`.

Validators need the signing key loaded in a running process — use a dedicated, patched machine. For unattended starts:

```bash
echo "<checksummed_private_key>" > /etc/messagechain/validator.key
chmod 0600 /etc/messagechain/validator.key
python -m messagechain start --mine --keyfile /etc/messagechain/validator.key
```

Rotate before your WOTS+ leaf watermark nears tree capacity:

```bash
python -m messagechain key-status     # check leaf usage
python -m messagechain rotate-key     # roll signing key (entity ID unchanged)
```

For hot/cold separation, bind a cold key as your withdrawal authority — unstake and emergency-revoke then require the cold key:

```bash
python -m messagechain set-authority-key --authority-pubkey <hex>
```

## Staking & governance

Minimum stake is 100 tokens; unstaking has a 7-day unbonding period.

Voting power: `staked + sqrt(unstaked_balance)`. Approval requires a 2/3 supermajority; stake and balance snapshot at proposal creation. Proposals cost 1000 tokens. If you don't delegate, your passive voting power auto-distributes across validators who vote, weighted by `sqrt(validator_stake)`.

## Fees

Fees auto-detect inside `send` and `transfer`; override with `--fee <amount>`. Messages pay a size-based curve, transfers pay a flat minimum. Use `estimate-fee` to preview.

## Testing

```bash
python -m unittest discover tests/
```
