"""Global configuration constants for the MessageChain protocol."""

# Message constraints
MAX_MESSAGE_WORDS = 100  # max words per message (L2 splits long messages across txs)

# Token economics — inflationary to offset natural loss (deaths, lost keys)
GENESIS_SUPPLY = 1_000_000
INITIAL_ENTITY_GRANT = 1000  # tokens granted when entity registers
BLOCK_REWARD = 50  # new tokens minted per block (paid to proposer)
ANNUAL_INFLATION_RATE = 0.02  # 2% target annual inflation
HALVING_INTERVAL = 210_000  # blocks between reward halvings (like BTC)
MIN_FEE = 1  # minimum transaction fee

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

# inv/getdata relay
INV_BATCH_SIZE = 500      # max tx hashes per INV message
SEEN_TX_CACHE_SIZE = 10000  # max recently-seen tx hashes to remember
