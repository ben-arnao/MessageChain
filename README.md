# MessageChain

A message-based blockchain where your biometrics are your private key.

## Quick Start

Three commands. That's it.

```bash
# 1. Start a node
python -m messagechain start

# 2. Create your account
python -m messagechain account

# 3. Send a message
python -m messagechain send "Hello, MessageChain!"
```

## Commands

### Start a node

```bash
# Relay-only (no biometrics needed)
python -m messagechain start

# Mine blocks and earn rewards
python -m messagechain start --mine
```

That's all you need. The node auto-creates its data directory, picks default ports (P2P: 9333, RPC: 9334), and starts running.

**For power users:**

```bash
python -m messagechain start --port 9333 --rpc-port 9334 --seed 192.168.1.10:9333 --data-dir ./mydata
```

### Create an account

```bash
python -m messagechain account
```

Prompts for your biometrics (DNA, fingerprint, iris) and a private key. Returns your entity ID — that's your wallet address. Done.

### Send a message

```bash
python -m messagechain send "Your message here"
```

Prompts for biometric auth, auto-detects the optimal fee, signs, and submits. One command.

**For power users:**

```bash
python -m messagechain send "Hello" --fee 50 --server 10.0.0.1:9334
```

### Other commands

```bash
python -m messagechain demo     # Run a local demo of the protocol
python -m messagechain info     # Show chain info from a running node
```

## Core Design

| Principle | How |
|---|---|
| **Your body is your key** | Biometrics (DNA + fingerprint + iris) ARE the private key. No passwords, no seed phrases. |
| **One person, one wallet** | Same biometrics = same entity ID. Duplicate registrations are rejected. |
| **Quantum resistant** | WOTS+ hash-based signatures over SHA3-256. Immune to quantum attacks. |
| **Inflationary supply** | Block rewards with halving schedule. Offsets tokens lost to death/abandonment. |
| **Fee bidding** | You set your fee. Higher fee = faster block inclusion. Like Bitcoin. |
| **280 characters per message** | Base layer limit. L2 protocols split long content across multiple transactions. |
| **Timestamped** | Every transaction is timestamped. |

## Architecture

```
Base Layer (this protocol)
├── Biometric identity
├── Quantum-resistant signatures
├── Inflationary token economics
├── Fee-based transaction priority
├── Timestamped messages (280 characters)
└── One entity = one wallet

L2 / Third-Party (built on top)
├── Link entity IDs to real people
├── Trust scores / reputation
├── Message schemas and structure
├── Threading / chaining messages
├── Long message splitting
└── Profile systems, social graphs
```

## Advanced Usage

The original entry points are still available for fine-grained control:

```bash
python server.py [options]       # Full node server
python client.py <command>       # Client commands
python run_node.py --demo        # Demo mode
```

## Running Tests

```bash
python -m unittest discover tests/ -v
```
