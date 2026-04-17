"""One-shot script to mint genesis and stake for a single-founder launch.

Run ONCE by the project founder on the machine that will become the
genesis validator.  Produces a fully-initialized SQLite chain:
  * block 0 signed by the founder, genesis tokens allocated
  * founder registered, hot key set as its own authority
  * founder's validator stake locked

Prints the block-0 hash.  After the script succeeds, paste that hash
into messagechain.config.PINNED_GENESIS_HASH and commit — this is what
stops future cloners from minting a competing genesis locally.

Then start the server:
    python server.py --data-dir <same dir> --rpc-bind 0.0.0.0

Newcomers who clone the repo after PINNED_GENESIS_HASH is set will
sync block 0 from peers instead of attempting to mint their own.

Cold-key upgrade (recommended follow-up): the script wires the hot
key as its own authority so this single command is enough to run.
Move to a cold authority key with:
    python -m messagechain set-authority-key --authority-pubkey <cold_hex>
"""

from __future__ import annotations

import argparse
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Bootstrap-only override: the founder-launch script is the one legitimate
# place where PINNED_GENESIS_HASH is unknown (we're about to mint the first
# block), so flip DEVNET on for this process only.  The long-running server
# that starts afterward will use the committed config with DEVNET=False and
# a pinned genesis hash.
import messagechain.config as _mc_config
_mc_config.DEVNET = True

from messagechain.config import (
    LEAF_INDEX_FILENAME, TREASURY_ENTITY_ID, TREASURY_ALLOCATION,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.address import encode_address
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mint genesis and stake for a single-founder MessageChain launch",
    )
    parser.add_argument(
        "--data-dir", required=True,
        help="Target directory for the SQLite chain data.  Must not already contain a chain.",
    )
    parser.add_argument(
        "--keyfile", required=True,
        help="Path to a file containing the founder's 32-byte private key as hex on one line.",
    )
    parser.add_argument(
        "--liquid", type=int, default=50_000,
        help="Liquid tokens allocated to founder at genesis (default: 50,000).",
    )
    parser.add_argument(
        "--stake", type=int, default=50_000,
        help="Tokens to lock as validator stake (default: 50,000).",
    )
    parser.add_argument(
        "--tree-height", type=int, default=16,
        help="WOTS+ Merkle tree height (default: 16 = 65K signing keys, "
             "~450 days before rotation needed). Higher = more keys but "
             "exponentially slower keygen. Use 20 for production longevity.",
    )
    args = parser.parse_args()

    with open(args.keyfile) as f:
        hex_key = f.read().strip()
    private_key = bytes.fromhex(hex_key)

    leaves = 1 << args.tree_height
    print(f"Generating WOTS+ tree: height={args.tree_height} ({leaves:,} signing keys)...")
    sys.stdout.flush()
    entity = Entity.create(private_key, tree_height=args.tree_height)
    print(f"Entity ID: {entity.entity_id.hex()}")
    print(f"Address:   {encode_address(entity.entity_id)}")

    os.makedirs(args.data_dir, exist_ok=True)

    # Wire WOTS+ leaf-index persistence to the data dir so the genesis
    # signature (and any subsequent signs before the long-running server
    # takes over) advance the on-disk counter.  Without this, a crash
    # between minting genesis and the first server start-up could let the
    # founder re-use leaf 0 against a different block.
    leaf_index_path = os.path.join(args.data_dir, LEAF_INDEX_FILENAME)
    entity.keypair.leaf_index_path = leaf_index_path
    entity.keypair.load_leaf_index(leaf_index_path)
    db_path = os.path.join(args.data_dir, "chain.db")
    if os.path.exists(db_path):
        print(f"ERROR: {db_path} already exists. Refusing to overwrite.", file=sys.stderr)
        print("Move or delete the existing directory to re-initialize.", file=sys.stderr)
        return 1

    db = ChainDB(db_path)
    blockchain = Blockchain(db=db)

    total_alloc = args.liquid + args.stake
    allocation = {
        entity.entity_id: total_alloc,
        TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
    }
    print(f"Allocating {total_alloc} to founder, {TREASURY_ALLOCATION} to treasury...")

    genesis_block = blockchain.initialize_genesis(entity, allocation)
    print(f"Genesis minted, block-0 hash: {genesis_block.block_hash.hex()}")

    print(f"Registering + setting authority + staking {args.stake}...")
    ok, log = bootstrap_seed_local(
        blockchain,
        entity,
        cold_authority_pubkey=entity.public_key,
        stake_amount=args.stake,
    )
    for line in log:
        print(f"  {line}")

    if not ok:
        print("ERROR: bootstrap_seed_local reported failure.", file=sys.stderr)
        return 1

    blockchain._persist_state()
    db.close()

    liquid = blockchain.supply.get_balance(entity.entity_id)
    staked = blockchain.supply.get_staked(entity.entity_id)

    print()
    print("=" * 70)
    print("SUCCESS")
    print("=" * 70)
    print(f"Address (public):    {encode_address(entity.entity_id)}")
    print(f"Entity ID hex:       {entity.entity_id.hex()}")
    print(f"Liquid balance:      {liquid}")
    print(f"Staked:              {staked}")
    print(f"Block-0 hash:        {genesis_block.block_hash.hex()}")
    print()
    print("Next steps:")
    print(f"  1. Paste this into messagechain/config.py:")
    print(f'     PINNED_GENESIS_HASH = bytes.fromhex("{genesis_block.block_hash.hex()}")')
    print(f"  2. Commit + push.")
    print(f"  3. Start the server:")
    print(f"     python server.py --data-dir {args.data_dir} --rpc-bind 0.0.0.0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
