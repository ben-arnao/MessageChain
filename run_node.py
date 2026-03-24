#!/usr/bin/env python3
"""
MessageChain Node CLI

Start a node, create entities, post messages, and inspect chain state.

Usage:
    python run_node.py --create-entity --post "Hello, MessageChain!"
    python run_node.py --port 9334 --seed 127.0.0.1:9333
    python run_node.py --demo  # Run a full local demo
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
    print("\n--- Creating Entities ---")
    alice = create_demo_entity("alice")
    bob = create_demo_entity("bob")
    print(f"Alice: {alice.entity_id_hex[:32]}...")
    print(f"Bob:   {bob.entity_id_hex[:32]}...")
    print(f"Alice PQ public key: {alice.public_key.hex()[:32]}...")

    # Initialize blockchain
    print("\n--- Initializing Blockchain ---")
    chain = Blockchain()
    genesis = chain.initialize_genesis(alice)
    chain.register_entity(bob)
    print(f"Genesis block: {genesis.block_hash.hex()[:32]}...")
    print(f"Chain height: {chain.height}")
    info = chain.get_chain_info()
    print(f"Total supply: {info['total_supply']:,}")
    print(f"Burn cost per message: {info['current_burn_cost']}")

    # Post messages
    print("\n--- Posting Messages ---")
    messages = [
        (alice, "Hello, this is the first message on MessageChain!", BiometricType.FINGERPRINT),
        (alice, "Messages are quantum-resistant and deflationary.", BiometricType.DNA),
        (bob, "Bob here. Verified via iris scan.", BiometricType.IRIS),
        (alice, "Each message burns tokens. Supply only goes down.", BiometricType.FINGERPRINT),
        (bob, "Decentralized messaging with built-in economics.", BiometricType.DNA),
    ]

    consensus = ProofOfStake()
    txs = []
    for entity, msg, bio_type in messages:
        nonce = chain.nonces.get(entity.entity_id, 0)
        tx = create_transaction(entity, msg, bio_type, chain.supply, nonce)

        # Simulate block: each message gets its own block for demo clarity
        prev = chain.get_latest_block()
        block = consensus.create_block(entity, [tx], prev)
        success, reason = chain.add_block(block)

        bio_label = bio_type.value.upper()
        print(f"  [{bio_label}] {entity.entity_id_hex[:8]}...: \"{msg}\"")
        print(f"    Block #{block.header.block_number} | Burned: {tx.burn_amount} tokens | Status: {reason}")
        txs.append(tx)

    # Show deflation
    print("\n--- Deflation Stats ---")
    info = chain.get_chain_info()
    print(f"Total supply: {info['total_supply']:,} (started at 1,000,000)")
    print(f"Total burned: {info['total_burned']:,}")
    print(f"Deflation: {info['deflation_pct']:.4f}%")
    print(f"Current burn cost: {info['current_burn_cost']}")
    print(f"Projected supply after 1000 more msgs: {info['projected_supply_after_1000_msgs']:,}")

    # Entity stats
    print("\n--- Entity Stats ---")
    for name, entity in [("Alice", alice), ("Bob", bob)]:
        stats = chain.get_entity_stats(entity.entity_id)
        print(f"  {name}: balance={stats['balance']}, messages={stats['messages_posted']}, "
              f"remaining_sigs={entity.keypair.remaining_signatures}")

    # Verify chain integrity
    print("\n--- Chain Integrity ---")
    print(f"Chain height: {chain.height}")
    for i, block in enumerate(chain.chain):
        tx_count = len(block.transactions)
        print(f"  Block #{i}: {block.block_hash.hex()[:16]}... "
              f"({tx_count} txs, proposer: {block.header.proposer_id.hex()[:8]}...)")

    # Show quantum resistance info
    print("\n--- Quantum Resistance ---")
    print(f"Signature scheme: WOTS+ (Winternitz One-Time Signature) with Merkle tree")
    print(f"Hash function: SHA3-256")
    print(f"Signatures per entity: {alice.keypair.num_leaves}")
    print(f"Security: Hash-based - resistant to Shor's algorithm")

    # Show L2 extension points
    print("\n--- L2 Extension Points ---")
    print("The base layer stores raw messages. Third-party protocols can:")
    print("  - Link entity IDs to real people (verification messages)")
    print("  - Define message content structure/schemas")
    print("  - Compute trust scores per entity (like credit scores)")
    print("  - Build application-specific logic on top")

    print("\n" + "=" * 60)
    print("  Demo complete. All messages cryptographically signed")
    print("  with quantum-resistant hash-based signatures.")
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
            node.blockchain.supply, nonce
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
