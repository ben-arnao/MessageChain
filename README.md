# MessageChain

A blockchain for sending messages. Quantum-resistant signatures, proof-of-stake consensus, fee-based spam prevention. Designed to last centuries.

## Install

```bash
git clone https://github.com/YourUser/MessageChain.git
cd MessageChain
pip install -r requirements.txt
```

## Commands

Every command below talks to a local node at `127.0.0.1:9334` unless you pass `--server host:port`.

| You want to... | Command |
|---|---|
| Create a key + wallet | `python -m messagechain generate-key` then `python -m messagechain account` |
| Run a validator (stake + mine) | `python -m messagechain start --mine` then `python -m messagechain stake --amount 100` |
| Post a message | `python -m messagechain send "hello"` |
| Send funds | `python -m messagechain transfer --to <entity_id> --amount 100` |
| Receive funds | Share your entity ID. No action needed on your end. |
| Read the last N messages | `python -m messagechain read --last 50` |
| List validators (stake %, blocks mined) | `python -m messagechain validators` |
| Estimate a fee before sending | `python -m messagechain estimate-fee --message "hi"` or `--transfer` |
| Propose a vote | `python -m messagechain propose --title "..." --description "..."` |
| Vote on a proposal | `python -m messagechain vote --proposal <id> --yes` (or `--no`) |
| Check proposal status + tally | `python -m messagechain proposals` |
| Delegate voting power | `python -m messagechain delegate --to <validator_id> --pct 100` |
| Connect to the network and sync | `python -m messagechain start` (relay-only, no `--mine`) |
| Show chain info | `python -m messagechain info` |
| Check your balance | `python -m messagechain balance` |

All commands that sign prompt for your private key interactively; it lives in memory only for the few seconds needed to sign.

## First-time setup: key generation

Your private key is generated **offline** and stored on paper. It only enters a networked machine briefly, in memory, when you sign.

1. Disconnect from the internet.
2. `python -m messagechain generate-key` — prints private key, public key, entity ID.
3. Write the private key on paper. Make 2–3 copies in separate secure locations. Do not save it to a file, photograph it, or paste it anywhere.
4. `python -m messagechain verify-key` — re-enter the handwritten key; confirm the derived public key and entity ID match.
5. Clear terminal history, reconnect to the internet.
6. `python -m messagechain account` — registers your entity on-chain.

## Validator operation

A validator must keep its signing key loaded in a running process. Use a dedicated, patched machine you physically control — not a daily-driver laptop.

```bash
# Interactive start (prompts for key once)
python -m messagechain start --mine

# Unattended start (systemd, Docker)
echo "<checksummed_private_key>" > /etc/messagechain/validator.key
chmod 0600 /etc/messagechain/validator.key
python -m messagechain start --mine --keyfile /etc/messagechain/validator.key
```

Minimum stake is 100 tokens. Unstaking has a 7-day unbonding period.

Rotate to a fresh key tree before your WOTS+ leaf watermark nears tree capacity:

```bash
python -m messagechain key-status     # check leaf usage
python -m messagechain rotate-key     # roll to a new signing key (entity ID unchanged)
```

For hot/cold key separation, bind a separately-generated cold key as your withdrawal authority:

```bash
python -m messagechain set-authority-key --authority-pubkey <hex>
# Then unstake and emergency-revoke must be signed by the cold key.
```

## Governance

Every token holder has voting power: `staked + sqrt(unstaked_balance)`. Staked tokens count at full weight; liquid tokens count with sqrt-dampening. Approval requires a 2/3 supermajority, and both stake and balance snapshot at proposal creation — late movement cannot swing the result. Proposals cost 1000 tokens.

If you do not delegate, your passive voting power auto-distributes across validators who actually vote, weighted by `sqrt(validator_stake)`.

## Fees

Fees auto-detect inside `send` and `transfer`. Override with `--fee <amount>`. Messages pay a size-based curve; transfers pay a flat minimum. Use `estimate-fee` to preview.

## Testing

```bash
python -m unittest discover tests/
```

## Architecture

- **Consensus:** Proof-of-stake, stake-weighted proposer selection, auto-fallback on missed slots
- **Cryptography:** WOTS+ (quantum-resistant), SHA3-256, BIP-39 mnemonic backup
- **Governance:** On-chain proposals, snapshot tally, optional delegation
- **Fees:** `base + per-byte + quadratic` curve incentivizes concise messages
- **Supply:** 1 billion genesis; block rewards halve every ~4 years, floor 4 tokens/block
