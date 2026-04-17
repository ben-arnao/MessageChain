"""Start a local test server for E2E testing."""
import sys
import os
import asyncio
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import messagechain.config
messagechain.config.PINNED_GENESIS_HASH = None
messagechain.config.DEVNET = True
messagechain.config.MERKLE_TREE_HEIGHT = 8  # 256 leaves — plenty for E2E test
messagechain.config.ENFORCE_SLOT_TIMING = False
messagechain.config.REQUIRE_CHECKPOINTS = False
messagechain.config.BLOCK_TIME_TARGET = 10  # fast blocks for testing
messagechain.config.P2P_TLS_ENABLED = False
messagechain.config.RPC_AUTH_ENABLED = False
messagechain.config.SEED_NODES = []

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

from server import Server
from messagechain.identity.identity import Entity


async def main():
    server = Server(p2p_port=49333, rpc_port=49334, seed_nodes=[], rpc_bind="127.0.0.1")
    key = bytes.fromhex("a896648aa959c0065402f313765628dc2d4136f38b6ce6050c4cd39bfe8174be")
    entity = Entity.create(key, tree_height=8)
    server.set_wallet_entity(entity)
    await server.start()
    print("SERVER_READY", flush=True)
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
