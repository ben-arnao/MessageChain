"""Global configuration constants for the MessageChain protocol."""

# Message constraints
MAX_MESSAGE_CHARS = 280  # max characters per message (Twitter-length short messages)
MAX_MESSAGE_BYTES = 1_120  # max message size in bytes (~280 chars with Unicode room)

# Token economics — inflationary to offset natural loss (deaths, lost keys)
# Target: ~1% annual inflation that diminishes over time via halvings.
# At BLOCK_TIME_TARGET=10s, ~3,153,600 blocks/year.
# Year 1: 3 tokens/block * 3,153,600 = 9,460,800 minted against 1B supply = ~0.95%
# Halving every ~4 years gradually reduces rate while keeping inflation meaningful.
GENESIS_SUPPLY = 1_000_000_000  # 1 billion initial supply
GENESIS_ALLOCATION = 10_000     # tokens allocated to genesis entity for bootstrapping
BLOCK_REWARD = 3  # new tokens minted per block (paid to proposer)
HALVING_INTERVAL = 12_614_400  # blocks between reward halvings (~4 years at 10s blocks)
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
MERKLE_TREE_HEIGHT = 20  # 2^20 = 1,048,576 one-time keypairs per entity (production)
# Tests override this to 4 (16 leaves) via tests/__init__.py for fast execution.

# Consensus
VALIDATOR_MIN_STAKE = 100
CONSENSUS_THRESHOLD = 0.67  # 2/3 of stake must sign off
MIN_TOTAL_STAKE = 1000  # minimum total stake to prevent bootstrap re-entry

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

# Staking
UNBONDING_PERIOD = 60_480     # blocks before unstaked tokens become spendable (~7 days at 10s)

# Slashing
SLASH_PENALTY_PCT = 100       # % of stake slashed on double-sign (100% = full slash)
SLASH_FINDER_REWARD_PCT = 10  # % of slashed amount paid to evidence submitter

# Finality
FINALITY_THRESHOLD = 0.67     # 2/3 of stake must attest for justification

# Governance — on-chain voting for protocol/codebase changes
GOVERNANCE_VOTING_WINDOW = 60_480     # blocks (~7 days at 10s/block)
GOVERNANCE_APPROVAL_THRESHOLD = 0.50  # >50% of participating balance must approve
GOVERNANCE_PROPOSAL_FEE = 10          # fee to create a proposal (spam deterrent)
GOVERNANCE_VOTE_FEE = 1               # fee to cast a vote
GOVERNANCE_DELEGATE_FEE = 1           # fee to delegate/revoke voting power
