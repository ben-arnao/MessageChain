# MessageChain

A blockchain for sending messages. Quantum-resistant signatures, proof-of-stake consensus, and fee-based spam prevention. Designed to last centuries.

## Getting Started: From Scratch to Sending a Message

Your private key is generated offline and stored on paper. It only enters a networked machine briefly, in memory, when you sign a transaction.

### 1. Install

```bash
git clone https://github.com/YourUser/MessageChain.git
cd MessageChain
pip install -r requirements.txt
```

### 2. Disconnect from the internet

Disable Wi-Fi, unplug Ethernet. Your private key should never be generated on a networked machine.

### 3. Generate your key pair (offline)

```bash
python -m messagechain generate-key
```

Output:

```
=== Key Pair Generated ===

  Private key: 9a3f...c7d1
  Public key:  b82e...4f90
  Entity ID:   d41a...8e23
```

You now have three values:

| Value | What it is | Who sees it |
|---|---|---|
| **Private key** | Your sole credential. Controls your account. | Only you. Never share. |
| **Public key** | Your cryptographic identity (Merkle tree root). | Public — goes on-chain. |
| **Entity ID** | Your wallet address. | Public — share freely. |

### 4. Write down your private key

Write it on paper (or stamp it into metal). Make 2-3 copies, store them in separate secure locations. Do **not** save it to a file, photograph it, or paste it into a notes app.

### 5. Verify your backup (still offline)

Before you close the terminal, verify that your handwritten copy reproduces the same identity:

```bash
python -m messagechain verify-key
```

```
Private key (hidden): ****
  Public key:  b82e...4f90
  Entity ID:   d41a...8e23
```

Confirm both values match what you just generated. If they don't, you copied the private key wrong — try again before losing the original.

### 6. Clear your traces and reconnect

```bash
history -c    # clear terminal history
```

Close the terminal. Reconnect to the internet.

### 7. Register your account

```bash
python -m messagechain account
```

You'll be prompted for your private key. Type it from your paper backup. It stays in memory only for the few seconds it takes to sign the registration, then the process exits.

Your account is now on-chain. You can receive funds at your entity ID.

### 8. Receive funds

Share your entity ID with the sender. They transfer tokens to you — no action needed on your end.

### 9. Send a message

```bash
python -m messagechain send "Hello, MessageChain!"
```

You'll be prompted for your private key again. Same as registration: briefly in memory, then gone.

```
Private key (hidden): ****
Signing as: d41a...8e23...
Message sent!
  TX hash: 7f2c...
  Fee:     5 tokens
```

### Summary

| Step | Where | Private key |
|---|---|---|
| Generate key pair | Offline | Produced here |
| Verify backup | Offline | Entered briefly |
| Register account | Online | Entered briefly |
| Receive funds | Online | Not needed |
| Send message/funds | Online | Entered briefly |
| Recovery | Offline | Paper backup |

## Quick Reference

### Check Your Balance

```bash
python -m messagechain balance
```

### Receive Funds

Share your entity ID with the sender. They transfer tokens to you — no action needed on your end.

### Send Funds

```bash
python -m messagechain transfer --to <recipient_entity_id> --amount 100
```

Fee is auto-detected. Override with `--fee <amount>`.

### Send a Message

```bash
python -m messagechain send "Hello, MessageChain!"
```

Messages are 280 characters max. Fee scales with message size.

### Read Messages

```bash
python -m messagechain read              # last 10 messages
python -m messagechain read --last 50    # last 50 messages
```

Output shows entity ID, timestamp, and message text.

### Delegate Your Voting Power

Non-validators can signal which validators they trust. This influences governance votes and network security. Funds are not locked.

```bash
# Delegate to a single validator
python -m messagechain delegate --to <validator_id> --pct 100

# Split across multiple validators
python -m messagechain delegate --to <id1> --pct 50 --to <id2> --pct 30 --to <id3> --pct 20

# Revoke delegation (revert to automatic distribution)
python -m messagechain delegate --revoke
```

### Propose a Governance Vote

Staked validators can propose protocol changes. Proposals cost 1000 tokens to prevent spam.

```bash
python -m messagechain propose --title "Increase block size" --description "Raise MAX_TXS_PER_BLOCK to 50"
```

### Vote on a Proposal

```bash
python -m messagechain vote --proposal <proposal_id> --yes
python -m messagechain vote --proposal <proposal_id> --no
```

Voting power is proportional to staked amount. Direct votes override delegation.

### Run a Validator

Start a node that produces blocks and earns rewards.

```bash
python -m messagechain start --mine
```

You'll be prompted for your private key. To stake tokens (required for block production weight):

```bash
python -m messagechain stake --amount 100
```

Minimum stake: 100 tokens. Staking gives you block production weight and governance voting power.

#### Connect to the Network

```bash
python -m messagechain start --mine --seed <host>:<port>
```

#### Custom Ports

```bash
python -m messagechain start --mine --port 9335 --rpc-port 9336
```

#### Validator Fallback

If a validator misses their block slot, the next proposer is selected automatically via stake-weighted randomness. No manual configuration needed — the protocol handles liveness.

### Show Chain Info

```bash
python -m messagechain info
```

## Running Tests

```bash
python -m unittest discover tests/ -v
```

## Architecture

- **Consensus:** Proof-of-stake with stake-weighted proposer selection
- **Cryptography:** Quantum-resistant WOTS+ signatures, SHA3-256 hashing
- **Governance:** On-chain proposals and voting with delegated trust
- **Fees:** Non-linear fee curve (base + per-byte + quadratic) to incentivize concise messages
- **Token supply:** 1 billion genesis, block rewards halve every ~4 years with a floor of 4 tokens/block
