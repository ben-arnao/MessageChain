"""Global configuration constants for the MessageChain protocol."""

# Message constraints
MAX_MESSAGE_WORDS = 100  # max words per message (L2 splits long messages across txs)
MAX_MESSAGE_BYTES = 10_000  # max message size in bytes (prevents single-word megabyte abuse)

# Token economics — inflationary to offset natural loss (deaths, lost keys)
# Target: ~2% annual inflation that diminishes over time via halvings.
# At BLOCK_TIME_TARGET=10s, ~3,153,600 blocks/year.
# Year 1: 10 tokens/block * 3,153,600 = 31,536,000 minted against 1B supply = ~3.15%
# Year 2+: halving every 6,307,200 blocks (~2 years) gradually reduces rate.
GENESIS_SUPPLY = 1_000_000_000  # 1 billion initial supply
BLOCK_REWARD = 10  # new tokens minted per block (paid to proposer)
HALVING_INTERVAL = 6_307_200  # blocks between reward halvings (~2 years at 10s blocks)
MIN_FEE = 1  # minimum transaction fee

# Timestamp tolerance
MAX_TIMESTAMP_DRIFT = 300  # max seconds a tx timestamp can be ahead of current time

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

# Peer banning
BAN_THRESHOLD = 100       # misbehavior score that triggers a ban
BAN_DURATION = 86400      # ban length in seconds (24 hours)

# Mempool
MEMPOOL_MAX_SIZE = 5000       # max transactions in mempool
MEMPOOL_TX_TTL = 1_209_600    # tx expiry in seconds (14 days)
MEMPOOL_PER_SENDER_LIMIT = 25 # max pending txs per entity in mempool

# inv/getdata relay
INV_BATCH_SIZE = 500      # max tx hashes per INV message
SEEN_TX_CACHE_SIZE = 10000  # max recently-seen tx hashes to remember

# Key rotation
KEY_ROTATION_FEE = 10     # fee required for key rotation transaction
