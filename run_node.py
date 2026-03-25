#!/usr/bin/env python3
"""
MessageChain Node CLI

Start a node, create entities, post messages, and inspect chain state.

Usage:
    python run_node.py --demo                    # Run a full local demo
    python run_node.py --port 9334 --seed 127.0.0.1:9333  # Start P2P node
"""

import argparse
import asyncio
import logging
import sys

from messagechain.identity.biometrics import Entity, BiometricType
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.mempool import Mempool
from messagechain.network.node import Node


def create_demo_entity(name: str = "demo") -> Entity:
    """Create an entity with simulated biometric data."""
    return Entity.create(
        dna_data=f"{name}-dna-sample".encode(),
        fingerprint_data=f"{name}-fingerprint-scan".encode(),
        iris_data=f"{name}-iris-scan".encode(),
    )


def run_demo():
    """Run a full local demo of the MessageChain protocol."""
    print("=" * 60)
    print("  MessageChain Protocol Demo")
    print("=" * 60)

    # Create entities (simulating biometric enrollment)
    print("\n--- Entity Registration (biometric = private key) ---")
    alice = create_demo_entity("alice")
    bob = create_demo_entity("bob")
    print(f"Alice: {alice.entity_id_hex[:32]}...")
    print(f"Bob:   {bob.entity_id_hex[:32]}...")
    print(f"Alice PQ public key: {alice.public_key.hex()[:32]}...")

    # Initialize blockchain
    print("\n--- Initializing Blockchain ---")
    chain = Blockchain()
    genesis = chain.initialize_genesis(alice)
    success, msg = chain.register_entity(bob.entity_id, bob.public_key)
    print(f"Bob registration: {msg}")
    info = chain.get_chain_info()
    print(f"Genesis block: {genesis.block_hash.hex()[:32]}...")
    print(f"Total supply: {info['total_supply']:,}")

    # Demonstrate duplicate biometric rejection
    print("\n--- One Entity Per Person (duplicate rejection) ---")
    alice_duplicate = create_demo_entity("alice")  # same biometrics!
    success, msg = chain.register_entity(alice_duplicate.entity_id, alice_duplicate.public_key)
    print(f"Alice duplicate registration: {msg}")
    print(f"  (entity_id matches: {alice_duplicate.entity_id == alice.entity_id})")

    # Post messages with fee bidding
    print("\n--- Posting Messages (BTC-style fee bidding) ---")
    messages = [
        (alice, "Hello this is the first message on MessageChain!", BiometricType.FINGERPRINT, 10),
        (bob, "Bob here verified via iris scan", BiometricType.IRIS, 5),
        (alice, "Higher fee means my message gets priority in the next block", BiometricType.DNA, 25),
        (bob, "Decentralized messaging with built in economics", BiometricType.FINGERPRINT, 3),
        (alice, "Each message is quantum resistant and timestamped", BiometricType.IRIS, 15),
    ]

    consensus = ProofOfStake()
    for entity, msg_text, bio_type, fee in messages:
        nonce = chain.nonces.get(entity.entity_id, 0)
        tx = create_transaction(entity, msg_text, bio_type, fee=fee, nonce=nonce)

        # Each message in its own block for demo clarity
        prev = chain.get_latest_block()
        block = consensus.create_block(entity, [tx], prev)
        success, reason = chain.add_block(block)

        bio_label = bio_type.value.upper()
        ts = f"{tx.timestamp:.0f}"
        print(f"  [{bio_label}] fee={fee:>3} | {entity.entity_id_hex[:8]}...: \"{msg_text}\"")
        print(f"    Block #{block.header.block_number} | Timestamp: {ts} | {reason}")

    # Show fee bidding behavior
    print("\n--- Fee Bidding (mempool ordering) ---")
    mempool = Mempool()
    nonce_a = chain.nonces.get(alice.entity_id, 0)
    nonce_b = chain.nonces.get(bob.entity_id, 0)

    low_fee_tx = create_transaction(alice, "Low fee message", BiometricType.DNA, fee=2, nonce=nonce_a)
    high_fee_tx = create_transaction(bob, "High fee message", BiometricType.FINGERPRINT, fee=50, nonce=nonce_b)
    mid_fee_tx = create_transaction(alice, "Mid fee message", BiometricType.IRIS, fee=10, nonce=nonce_a + 1)

    mempool.add_transaction(low_fee_tx)
    mempool.add_transaction(high_fee_tx)
    mempool.add_transaction(mid_fee_tx)

    print(f"  Mempool has {mempool.size} pending transactions")
    print(f"  Fee estimate for next block: {mempool.get_fee_estimate()}")
    ordered = mempool.get_transactions(10)
    for i, tx in enumerate(ordered):
        print(f"    Priority {i+1}: fee={tx.fee} from {tx.entity_id.hex()[:8]}...")

    # Show inflation stats
    print("\n--- Inflation Stats (combats natural deflation) ---")
    info = chain.get_chain_info()
    print(f"Genesis supply:     {info['genesis_supply']:,}")
    print(f"Current supply:     {info['total_supply']:,}")
    print(f"Total minted:       {info['total_minted']:,} (block rewards)")
    print(f"Total fees:         {info['total_fees_collected']:,} (redistributed)")
    print(f"Inflation:          {info['inflation_pct']:.4f}%")
    print(f"Block reward:       {info['current_block_reward']} tokens")
    print(f"Next halving block: {info['next_halving_block']:,}")

    # Entity stats
    print("\n--- Entity Stats ---")
    for name, entity in [("Alice", alice), ("Bob", bob)]:
        stats = chain.get_entity_stats(entity.entity_id)
        print(f"  {name}: balance={stats['balance']}, messages={stats['messages_posted']}, "
              f"remaining_sigs={entity.keypair.remaining_signatures}")

    # Chain integrity
    print("\n--- Chain Integrity ---")
    print(f"Chain height: {chain.height}")
    for i, block in enumerate(chain.chain):
        tx_count = len(block.transactions)
        print(f"  Block #{i}: {block.block_hash.hex()[:16]}... "
              f"({tx_count} txs, proposer: {block.header.proposer_id.hex()[:8]}...)")

    # Architecture info
    print("\n--- Protocol Architecture ---")
    print("BASE LAYER (this protocol):")
    print("  - Biometric identity (your body = your private key)")
    print("  - Quantum-resistant signatures (WOTS+ / SHA3-256)")
    print("  - Inflationary supply (block rewards, halving schedule)")
    print("  - Fee bidding (BTC-style priority)")
    print("  - Timestamped messages (100 word max)")
    print("  - One entity = one wallet (enforced by biometrics)")
    print()
    print("L2 / THIRD-PARTY PROTOCOLS (built on top):")
    print("  - Link entity IDs to real people (verification messages)")
    print("  - Trust scores / reputation (like credit scores)")
    print("  - Message content structure and schemas")
    print("  - Threading / chaining messages together")
    print("  - Splitting long messages across multiple txs")
    print("  - Profile systems, social graphs, etc.")

    print("\n" + "=" * 60)
    print("  Demo complete.")
    print("=" * 60)


async def run_node(args):
    """Run a full P2P node."""
    entity = create_demo_entity(args.entity_name or "node")

    seed_nodes = []
    if args.seed:
        for s in args.seed:
            host, port = s.split(":")
            seed_nodes.append((host, int(port)))

    node = Node(entity=entity, port=args.port, seed_nodes=seed_nodes or None)
    await node.start()

    if args.stake:
        node.consensus.register_validator(entity.entity_id, args.stake)
        node.blockchain.supply.stake(entity.entity_id, args.stake)
        print(f"Staked {args.stake} tokens as validator")

    if args.post:
        nonce = node.blockchain.nonces.get(entity.entity_id, 0)
        tx = create_transaction(
            entity, args.post, BiometricType.FINGERPRINT,
            fee=args.fee or 10, nonce=nonce
        )
        success, reason = node.submit_transaction(tx)
        print(f"Transaction: {reason}")
        await node.broadcast_transaction(tx)

    if args.info:
        print(node.blockchain.get_chain_info())
        return

    # Keep running
    print(f"Node running on port {args.port}. Press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await node.stop()


def main():
    parser = argparse.ArgumentParser(description="MessageChain Node")
    parser.add_argument("--demo", action="store_true", help="Run local demo")
    parser.add_argument("--port", type=int, default=9333, help="TCP port")
    parser.add_argument("--seed", nargs="*", help="Seed nodes (host:port)")
    parser.add_argument("--entity-name", type=str, help="Name for demo entity")
    parser.add_argument("--post", type=str, help="Post a message")
    parser.add_argument("--fee", type=int, help="Transaction fee")
    parser.add_argument("--stake", type=int, help="Stake tokens as validator")
    parser.add_argument("--info", action="store_true", help="Show chain info")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.demo:
        run_demo()
    else:
        asyncio.run(run_node(args))


if __name__ == "__main__":
    main()
