# MessageChain

A blockchain for sending messages. Quantum-resistant signatures, proof-of-stake consensus, and fee-based spam prevention. Designed to last centuries.

## Send a Message

```bash
python -m messagechain generate-key
python -m messagechain account
python -m messagechain send "Hello, MessageChain!"
```

## Run a Validator

```bash
python -m messagechain generate-key
python -m messagechain start --mine
```

Anyone can start mining. Early on, staking requires just 1 token. As the network matures, the minimum increases (10 at block 50k, 100 at block 200k). Stake gives you voting power in governance and weight in block production:

```bash
python -m messagechain account
python -m messagechain stake --amount 1
```

## Server Configuration

```bash
# Custom ports
python -m messagechain start --mine --port 9335 --rpc-port 9336

# Connect to an existing network
python -m messagechain start --mine --seed 192.168.1.10:9333

# Custom data directory
python -m messagechain start --data-dir ./mydata
```

## Other Commands

```bash
python -m messagechain read          # Read recent messages
python -m messagechain balance       # Check your balance
python -m messagechain info          # Chain status from a running node
python -m messagechain demo          # Try it locally, no network needed
```

## Running Tests

```bash
python -m unittest discover tests/ -v
```
