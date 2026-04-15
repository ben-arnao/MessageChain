#!/usr/bin/env python3
"""
MessageChain Node CLI

Start a node, create entities, post messages, and inspect chain state.

Usage:
    python run_node.py --port 9334 --seed 127.0.0.1:9333  # Start P2P node
"""

import argparse
import asyncio
import logging
import sys

from messagechain.identity.identity import Entity
from messagechain.core.transaction import create_transaction
from messagechain.network.node import Node


def create_demo_entity(name: str = "demo") -> Entity:
    """Create an entity with a deterministic private key for demos."""
    return Entity.create(f"{name}-private-key".encode())


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
            entity, args.post,
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

    asyncio.run(run_node(args))


if __name__ == "__main__":
    main()
