"""Global configuration constants for the MessageChain protocol."""

# Cryptography (defined early — needed by Treasury ID derivation below)
HASH_ALGO = "sha3_256"

# Message constraints — ASCII-only (printable bytes 32-126), so 1 char = 1 byte.
MAX_MESSAGE_CHARS = 280  # max characters per message
MAX_MESSAGE_BYTES = 280  # 1:1 with chars (ASCII only, no multi-byte encoding)

# Token economics — inflationary to offset natural loss (deaths, lost keys)
# BLOCK_REWARD must be a power of 2 so halvings divide cleanly.
# At BLOCK_TIME_TARGET=600s, ~52,600 blocks/year.
# Year 1: 16 tokens/block * 52,600 ≈ 841K minted against 1B supply ≈ 0.084%/year
# 2 meaningful halvings over ~8 years (16→8→4), then floor of 4 forever.
GENESIS_SUPPLY = 1_000_000_000  # 1 billion initial supply
GENESIS_ALLOCATION = 10_000     # tokens allocated to genesis entity for bootstrapping

# Canonical genesis block hash.  When set (bytes, length 32), nodes MUST NOT
# mint their own genesis — they sync block 0 from peers and reject any block
# whose hash doesn't match this pin.  Only the single bootstrap node that
# produced the pinned block may call initialize_genesis and have it succeed.
#
# Left as None in this prototype/devnet build so a first-time operator can
# still create a genesis and then record its hash here.  Production networks
# MUST pin this — otherwise two nodes on empty data dirs each mint their own
# incompatible block 0, creating permanently bifurcated chains.
PINNED_GENESIS_HASH: bytes | None = None

# Treasury — a governance-controlled fund for community spending.
# The treasury entity has a well-known deterministic ID (no private key exists).
# Funds can only leave the treasury via approved governance proposals.
import hashlib as _hashlib
TREASURY_ENTITY_ID = _hashlib.new(HASH_ALGO, b"messagechain-treasury-v1").digest()
TREASURY_ALLOCATION = 40_000_000  # 4% of genesis supply

# Default genesis allocation table: genesis validator + treasury.
# The genesis_entity's ID is filled in at chain init time.
# Allocations are absolute token amounts. Sum must not exceed GENESIS_SUPPLY.
DEFAULT_GENESIS_ALLOCATIONS = {
    TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
    # Genesis validator allocation is added dynamically in Blockchain.initialize_genesis
}

BLOCK_REWARD = 16  # new tokens minted per block (split between proposer + attestors)
if (BLOCK_REWARD & (BLOCK_REWARD - 1)) != 0:
    raise ValueError("BLOCK_REWARD must be a power of 2 for clean halvings")
HALVING_INTERVAL = 210_240  # blocks between reward halvings (~4 years at 600s blocks)
BLOCK_REWARD_FLOOR = 4  # minimum reward per block — never drops below this
# At 600s blocks (~52.6K blocks/year), floor of 4 = ~210K tokens/year ≈ 0.021% of genesis.
# High enough to keep validation lucrative; low enough to limit long-term inflation.

# Attestation reward split — incentivizes attestors who do essential security work.
# Proposer gets 1/4, attestors share 3/4 pro-rata by stake weight.
# If no attestors in a block, proposer gets the full reward (bootstrap/genesis).
PROPOSER_REWARD_NUMERATOR = 1
PROPOSER_REWARD_DENOMINATOR = 4

# Per-block reward cap for any single validator (proposer share + attestor share combined).
# Breaks the compounding loop: large stakers can't earn disproportionately more per block.
# Excess is redirected to the treasury. Set to proposer's normal 1/4 share.
PROPOSER_REWARD_CAP = BLOCK_REWARD * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR  # 4 tokens

# Fee economics — EIP-1559-style base fee + tip
# Non-linear size pricing: fee = MIN_FEE + (bytes * FEE_PER_BYTE) + (bytes^2 * FEE_QUADRATIC_COEFF) // 1000
# This makes larger messages disproportionately expensive, incentivizing conciseness.
MIN_FEE = 100  # absolute floor for base fee (spam deterrent)
FEE_PER_BYTE = 3  # per-byte fee component (3x higher than original — storage is expensive)
FEE_QUADRATIC_COEFF = 2  # quadratic surcharge coefficient: (bytes^2 * 2) // 1000
BASE_FEE_INITIAL = 100               # starting base fee (= MIN_FEE)
BASE_FEE_MAX_CHANGE_DENOMINATOR = 8  # max 12.5% change per block
TARGET_BLOCK_SIZE = 10                # target txs per block (50% of MAX_TXS_PER_BLOCK)
MIN_TIP = 1                          # minimum priority tip to proposer

# Timestamp tolerance
MAX_TIMESTAMP_DRIFT = 60  # max seconds a tx timestamp can be ahead of current time

# Block parameters
BLOCK_TIME_TARGET = 600  # seconds between blocks (10 min, same as BTC — speed is not a priority)
MAX_TXS_PER_BLOCK = 20  # max transactions per block (tx count cap)
MAX_BLOCK_MESSAGE_BYTES = 10_000  # max total message payload bytes per block (byte budget cap)
MAX_BLOCK_SIG_COST = 100  # max signature verification cost per block (1 per tx + 1 proposer + attestations)
COINBASE_MATURITY = 10    # blocks before block rewards become spendable (BTC uses 100)
MTP_BLOCK_COUNT = 11      # number of blocks to compute Median Time Past (same as BTC)

# Message TTL — messages expire after a protocol-defined retention period.
# Expired message data can be pruned; hash commitments remain in headers for auditability.
MESSAGE_DEFAULT_TTL = 4_320   # default message retention in blocks (~30 days at 600s)
MESSAGE_MIN_TTL = 144         # minimum TTL (~1 day at 600s) — prevents gaming fees via short TTL
MESSAGE_MAX_TTL = 52_560      # maximum TTL (~1 year at 600s) — bounds long-term storage commitment

# Cryptography (HASH_ALGO defined at top of file)
WOTS_W = 16  # Winternitz parameter (base-16)
WOTS_KEY_CHAINS = 64  # number of hash chains per WOTS keypair
WOTS_CHAIN_LENGTH = 15  # max chain depth (W-1)
MERKLE_TREE_HEIGHT = 20  # 2^20 = 1,048,576 one-time keypairs per entity (production)
# Tests override this to 4 (16 leaves) via tests/__init__.py for fast execution.

# Consensus — graduated minimum stake
# Early network is accessible (1 token), matures into higher barrier.
# These thresholds are checked via graduated_min_stake() in pos.py.
VALIDATOR_MIN_STAKE = 100            # legacy flat minimum (used as final tier)
GRADUATED_STAKE_TIERS = [
    (50_000, 1),      # blocks 0–49,999: 1 token
    (200_000, 10),    # blocks 50,000–199,999: 10 tokens
    (None, 100),      # blocks 200,000+: 100 tokens
]
CONSENSUS_THRESHOLD_NUMERATOR = 2    # 2/3 of stake must sign off (integer fraction)
CONSENSUS_THRESHOLD_DENOMINATOR = 3  # Use integer arithmetic: stake * 3 >= total * 2
MIN_TOTAL_STAKE = 1000  # minimum total stake to prevent bootstrap re-entry

# Minimum number of distinct validators needed to exit bootstrap mode.
# Bootstrap mode is permissive (allows any node to propose, skips
# attestation thresholds). The chain stays in bootstrap until at least
# this many validators have registered, so we never end up with a
# 1-validator post-bootstrap chain that has a single point of failure.
# Set to 1 in tests via tests/__init__.py for backward compatibility.
# Production: 3 matches the planned 3-seed launch.  A thinner set than
# this risks a single-point-of-failure post-bootstrap chain; a larger
# set means bootstrap doesn't end until more external validators join.
MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 3

# Slot-timing enforcement — if True, validate_block rejects blocks whose
# timestamp is less than BLOCK_TIME_TARGET seconds after the parent's.
# This prevents a malicious proposer from racing ahead of their slot to
# claim round 0 with a near-zero timestamp gap. Disabled in tests
# (tests/__init__.py) because existing fixtures produce blocks rapidly
# with real wall-clock timestamps.
ENFORCE_SLOT_TIMING = True

# Network
DEFAULT_PORT = 9333
SEED_NODES: list[tuple[str, int]] = []
MAX_PEERS = 50
HANDSHAKE_TIMEOUT = 5  # seconds

# Peer banning
BAN_THRESHOLD = 100       # misbehavior score that triggers a ban
BAN_DURATION = 86400      # ban length in seconds (24 hours)

# Mempool
MEMPOOL_MAX_SIZE = 5000       # max transactions in mempool
MEMPOOL_TX_TTL = 1_209_600    # tx expiry in seconds (14 days)
MEMPOOL_PER_SENDER_LIMIT = 5  # max pending txs per entity (tight to throttle burst spam)
MEMPOOL_MAX_ANCESTORS = 5     # max unconfirmed tx chain depth per entity

# Address manager (Sybil/eclipse resistance)
ADDRMAN_NEW_BUCKET_COUNT = 256      # buckets in the "new" table
ADDRMAN_TRIED_BUCKET_COUNT = 64     # buckets in the "tried" table
ADDRMAN_BUCKET_SIZE = 64            # entries per bucket
ADDRMAN_MAX_PER_SOURCE = 32        # max addresses accepted from a single source
ADDRMAN_HORIZON_DAYS = 30           # max age before address is considered stale

# inv/getdata relay
INV_BATCH_SIZE = 500      # max tx hashes per INV message
SEEN_TX_CACHE_SIZE = 10000  # max recently-seen tx hashes to remember

# Key rotation
KEY_ROTATION_FEE = 1000   # fee required for key rotation transaction

# Dust limit — minimum transfer amount to prevent state bloat from tiny accounts
DUST_LIMIT = 10           # transfers below this amount are rejected

# Orphan block pool
MAX_ORPHAN_BLOCKS = 100   # max orphan blocks stored (bounded to prevent memory exhaustion)

# Header spam protection — bound pending headers during IBD to prevent OOM
MAX_PENDING_HEADERS = 50_000  # max headers held in memory during sync

# Transaction relay privacy — Poisson-distributed random delay before INV relay
TX_RELAY_DELAY_MEAN = 2.0  # average seconds of delay before relaying tx to peers

# Orphan transaction pool — hold out-of-order nonce txs temporarily
MEMPOOL_MAX_ORPHAN_TXS = 100       # max orphan txs total
MEMPOOL_MAX_ORPHAN_PER_SENDER = 3  # max orphan txs per entity
MEMPOOL_MAX_ORPHAN_NONCE_GAP = 3   # max nonce gap allowed for orphan txs

# Minimum cumulative stake weight — reject peers on chains below this during IBD
# Prevents fake-chain attacks where an attacker tricks a new node into syncing garbage
MIN_CUMULATIVE_STAKE_WEIGHT = 100

# AssumeValid — skip signature verification for blocks below this known-good hash
# Set to None to verify all blocks (default for new chains)
ASSUME_VALID_BLOCK_HASH = None  # bytes or None

# Weak-subjectivity checkpoints — the PoS long-range-attack defense.
# A list of (block_number, block_hash, state_root) snapshots that new nodes
# treat as ground truth during IBD. Any peer that serves a header at one of
# these heights with a non-matching hash is rejected and penalized.
#
# Populate by embedding `WeakSubjectivityCheckpoint` instances at release
# time. Empty by default — an unprotected fresh chain is intentional so that
# local/test networks don't require bootstrap ceremonies.
TRUSTED_CHECKPOINTS: tuple = ()

# Outbound connection slot allocation — mix full-relay (tx + block) peers
# with block-relay-only peers to defeat topology inference via tx-relay
# timing and preserve block flow under partial eclipse. Matches Bitcoin
# Core's default mix (8 full-relay + 2 block-relay-only).
OUTBOUND_FULL_RELAY_SLOTS = 8
OUTBOUND_BLOCK_RELAY_ONLY_SLOTS = 2

# Staking
UNBONDING_PERIOD = 1_008      # blocks before unstaked tokens become spendable (~7 days at 600s)

# Slashing
SLASH_PENALTY_PCT = 100       # % of stake slashed on double-sign (100% = full slash)
SLASH_FINDER_REWARD_PCT = 10  # % of slashed amount paid to evidence submitter

# Chain identity — included in all transaction signatures to prevent cross-fork replay.
# If MessageChain forks, each fork MUST change this value.
CHAIN_ID = b"messagechain-v1"

# Finality
FINALITY_THRESHOLD_NUMERATOR = 2     # 2/3 of stake must attest for justification
FINALITY_THRESHOLD_DENOMINATOR = 3   # Use integer arithmetic: stake * 3 >= total * 2

# Governance — on-chain voting for protocol/codebase changes
GOVERNANCE_VOTING_WINDOW = 1_008      # blocks (~7 days at 600s/block)
# Supermajority (2/3) required to approve any proposal.  Reasoning:
# passive balance+stake auto-delegates to the validator set, which gives
# validators disproportionate default voting power.  Requiring a 2/3
# supermajority prevents validators from ramming through self-serving
# proposals (rewards, minimum-stake changes, treasury drains) on passive
# power alone.
GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR = 2    # >=2/3 of participating weight must approve
GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR = 3  # Use integer arithmetic: yes * 3 >= total * 2
GOVERNANCE_PROPOSAL_FEE = 1000        # fee to create a proposal (spam deterrent)
GOVERNANCE_VOTE_FEE = 100             # fee to cast a vote
GOVERNANCE_DELEGATE_FEE = 100         # fee to delegate/revoke voting power
MAX_DELEGATION_TARGETS = 3            # max validators a user can delegate to
# Balances below this threshold are ignored when snapshotting balances at
# proposal-creation time.  Dust amounts contribute negligible voting power
# after sqrt-squashing and would balloon snapshot size.
GOVERNANCE_BALANCE_SNAPSHOT_DUST = 1

# RPC authentication — prevents local privilege escalation where an
# unprivileged process calls submit_transaction / stake / ban_peer.
# The token is compared via constant-time HMAC to prevent timing attacks.
# Set to None to auto-generate a random token at startup.
RPC_AUTH_ENABLED = True
RPC_AUTH_TOKEN: str | None = None  # auto-generated if None

# TLS encryption for P2P connections — prevents passive eavesdropping
# and MITM attacks on transaction relay and validator identity.
# Nodes generate a self-signed certificate on first run; peers verify
# only that TLS is in use (no CA chain — blockchain identity is separate).
P2P_TLS_ENABLED = True
TLS_CERT_PATH: str | None = None  # auto-generated if None
TLS_KEY_PATH: str | None = None   # auto-generated if None
