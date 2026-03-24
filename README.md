# MessageChain

A message-based blockchain where your biometrics are your private key.

## Quick Start

**Terminal 1 — Start the server:**

```bash
python server.py
# Enter your wallet ID when prompted (or press Enter to skip)
```

**Terminal 2 — Create an account:**

```bash
python client.py create-account
# Enter your DNA, fingerprint, and iris data when prompted
# Save the entity ID it gives you — that's your wallet
```

**Terminal 2 — Send a message:**

```bash
python client.py send-message
# Enter your message, authenticate with biometrics, set a fee
```

## How It Works

### Two commands, that's it

```bash
# 1. Create your one and only account
python client.py create-account

# 2. Send messages
python client.py send-message -m "Hello, MessageChain" -f 10
```

### Server

```bash
# Basic
python server.py

# With options
python server.py --port 9333 --rpc-port 9334 --wallet <your-entity-id>

# Connect to an existing network
python server.py --seed 192.168.1.10:9333
```

The server processes transactions, produces blocks, and deposits fees + block rewards into your wallet.

### Client

```bash
# Create account — provide biometrics, get your wallet ID
python client.py create-account

# Send message — provide biometrics to sign, set your fee
python client.py send-message -m "your message here" -f 10

# Options
python client.py send-message --bio-type iris --fee 25 --message "signed with iris"
python client.py --host 192.168.1.10 --rpc-port 9334 send-message
```

## Core Design

| Principle | How |
|---|---|
| **Your body is your key** | Biometrics (DNA + fingerprint + iris) ARE the private key. No passwords, no seed phrases. |
| **One person, one wallet** | Same biometrics = same entity ID. Duplicate registrations are rejected. |
| **Quantum resistant** | WOTS+ hash-based signatures over SHA3-256. Immune to quantum attacks. |
| **Inflationary supply** | Block rewards with halving schedule. Offsets tokens lost to death/abandonment. |
| **Fee bidding** | You set your fee. Higher fee = faster block inclusion. Like Bitcoin. |
| **100 words per message** | Base layer limit. L2 protocols split long content across multiple transactions. |
| **Timestamped** | Every transaction is timestamped. |

## Architecture

```
Base Layer (this protocol)
├── Biometric identity
├── Quantum-resistant signatures
├── Inflationary token economics
├── Fee-based transaction priority
├── Timestamped messages (100 words)
└── One entity = one wallet

L2 / Third-Party (built on top)
├── Link entity IDs to real people
├── Trust scores / reputation
├── Message schemas and structure
├── Threading / chaining messages
├── Long message splitting
└── Profile systems, social graphs
```

## Running Tests

```bash
python -m unittest discover tests/ -v
```
