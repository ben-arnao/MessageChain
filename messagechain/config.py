"""Global configuration constants for the MessageChain protocol."""

# Message constraints
MAX_MESSAGE_LENGTH = 256  # max characters per message

# Token economics
GENESIS_SUPPLY = 1_000_000
BURN_RATE = 0.0001  # fraction of supply burned per message
MIN_BURN = 1  # minimum tokens burned per message
GENESIS_ALLOCATION = 1000  # tokens granted to genesis entity

# Block parameters
BLOCK_TIME_TARGET = 10  # seconds between blocks
MAX_TXS_PER_BLOCK = 50

# Cryptography
HASH_ALGO = "sha3_256"
WOTS_W = 16  # Winternitz parameter (base-16)
WOTS_KEY_CHAINS = 64  # number of hash chains per WOTS keypair
WOTS_CHAIN_LENGTH = 15  # max chain depth (W-1)
MERKLE_TREE_HEIGHT = 10  # 2^10 = 1024 one-time keypairs per entity

# Consensus
VALIDATOR_MIN_STAKE = 100
CONSENSUS_THRESHOLD = 0.67  # 2/3 of stake must sign off

# Network
DEFAULT_PORT = 9333
SEED_NODES = [("127.0.0.1", 9333)]
MAX_PEERS = 50
HANDSHAKE_TIMEOUT = 5  # seconds
