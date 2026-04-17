"""Global configuration constants for the MessageChain protocol."""

# Cryptography (defined early — needed by Treasury ID derivation below)
HASH_ALGO = "sha3_256"

# Crypto agility — version bytes allow future algorithm upgrades via governance
# without a chain reset. Validators MUST reject unknown versions.
#
# These are carry-only registers today (no dispatch table). When a future hash
# or signature scheme ships, it is activated by a governance proposal that
# bumps HASH_VERSION_CURRENT / SIG_VERSION_CURRENT — the existing gate simply
# starts accepting the new value in addition to the old one for a migration
# window. That's the upgrade path this field saves us from ever having to
# hard-fork-and-reset over. SHA-256 will break someday (50 years? 200?); the
# 1-byte-per-block + 1-byte-per-signature cost of carrying these now is a
# trivial price for a chain designed to last 100-1000+ years.
#
# Reserved: 0 is invalid (traps uninitialized). Concrete current values pin
# the scheme-in-use:
#   HASH_VERSION_SHA256   = 1 (actually sha3_256 — HASH_ALGO above; the name
#                             matches the conventional "SHA-256 family" label
#                             the task spec uses). Future: 2 = a successor,
#                             3 = another, etc.
#   SIG_VERSION_WOTS_W16_K64 = 1 (WOTS+ with W=16, chains=64, Merkle h=20).
#                                Future: 2 = XMSS, 3 = SPHINCS+, etc.
HASH_VERSION_SHA256 = 1
HASH_VERSION_CURRENT = HASH_VERSION_SHA256

SIG_VERSION_WOTS_W16_K64 = 1  # current: WOTS W=16 chains=64 merkle h=20
SIG_VERSION_CURRENT = SIG_VERSION_WOTS_W16_K64


def validate_hash_version(hash_version: int) -> tuple[bool, str]:
    """Reject any unknown hash_version at the consensus boundary.

    Forward-compatibility gate: a future governance proposal can add a new
    accepted version by editing HASH_VERSION_CURRENT and widening this
    check. Until then, anything not equal to the current version is treated
    as a byzantine byte flip or a too-new peer and rejected.
    """
    if hash_version != HASH_VERSION_CURRENT:
        return False, (
            f"Unknown hash version {hash_version} "
            f"(current = {HASH_VERSION_CURRENT})"
        )
    return True, "OK"


def validate_sig_version(sig_version: int) -> tuple[bool, str]:
    """Reject any unknown sig_version at the consensus boundary.

    Same forward-compatibility shape as validate_hash_version. A future
    signature scheme (XMSS, SPHINCS+, a larger WOTS profile) is activated
    by governance; until then, only SIG_VERSION_CURRENT is accepted.
    """
    if sig_version != SIG_VERSION_CURRENT:
        return False, (
            f"Unknown sig version {sig_version} "
            f"(current = {SIG_VERSION_CURRENT})"
        )
    return True, "OK"

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
# Network mode — when True, PINNED_GENESIS_HASH may be None (local testing).
# Production nodes MUST leave this False; initialize_genesis will refuse to
# create a genesis block without a pinned hash in non-devnet mode, preventing
# misconfigured nodes from silently forking the network.
DEVNET = False

PINNED_GENESIS_HASH: bytes | None = bytes.fromhex(
    "abe88b0f3af89ae9e99d1c3c8e009e07aca3e35a5826740cc0f67688cdaf1e9c"
)

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
#
# BLOCK_TIME_TARGET: seconds between blocks (10 min, same as BTC — speed is
# not a priority).  Override via MESSAGECHAIN_BLOCK_TIME_TARGET env var for
# testing deployments that need faster block production.  Production nodes
# leave this at 600s.
import os as _os_bt  # noqa: E402
_bt_env = _os_bt.environ.get("MESSAGECHAIN_BLOCK_TIME_TARGET")
BLOCK_TIME_TARGET = int(_bt_env) if _bt_env is not None else 600
MAX_TXS_PER_BLOCK = 20  # max transactions per block (tx count cap)
MAX_TXS_PER_ENTITY_PER_BLOCK = 3  # anti-flooding: max message txs from one sender per block
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
# MERKLE_TREE_HEIGHT: WOTS+ Merkle tree height.  2^height = number of one-
# time signing keys per entity.  Default is 20 (1,048,576 keys ≈ 2 years of
# runtime per hot key at production block cadence).  Keygen is O(2^height)
# and expensive — height=20 takes ~90 min on a weak VM, height=16 takes ~5 min.
# Override via env var for bootstrap-phase deployments on low-CPU hardware.
import os as _os_mt  # noqa: E402
_merkle_env = _os_mt.environ.get("MESSAGECHAIN_MERKLE_TREE_HEIGHT")
MERKLE_TREE_HEIGHT = int(_merkle_env) if _merkle_env is not None else 20
# Tests override this to 4 (16 leaves) via tests/__init__.py for fast execution.
#
# Leaf exhaustion cadence — an active validator consumes one leaf per
# block proposed AND one leaf per attestation issued.  At BLOCK_TIME=600s
# (~525,600 blocks/year), the math works out to roughly:
#
#       leaves/year ≈ 525,600 / N  (proposals)  +  525,600  (attestations)
#
# where N is the validator count.  For any N in the tens-to-hundreds
# range, attestations dominate and per-validator leaf use converges to
# ~530,000/yr — so 1M leaves gives ~2 years of runtime per hot key.
#
# Implication: KeyRotation is a MANDATORY operational task, not a
# "rotate if you feel like it" feature.  Validators must rotate every
# ~1.5 years (safety margin) or risk hitting the "Key exhausted" error
# mid-slot, missing proposals, and bleeding stake to slashing /
# inactivity penalties.  Operators should schedule rotations well
# ahead of exhaustion — ideally at the halfway mark.

# Filename (inside the validator's data_dir) for WOTS+ leaf-index persistence.
# Guards against leaf reuse after a restart: sign() write-aheads the next-leaf
# counter here before returning the signature, so a crash between signing and
# gossip cannot let the restarted validator pick a leaf_index <= one it has
# already used.  See KeyPair.persist_leaf_index / load_leaf_index.
LEAF_INDEX_FILENAME = "leaf_index.json"

# Consensus — flat minimum stake from block 0.
# 100 tokens required to register as a validator at any block height.
VALIDATOR_MIN_STAKE = 100
CONSENSUS_THRESHOLD_NUMERATOR = 2    # 2/3 of stake must sign off (integer fraction)
CONSENSUS_THRESHOLD_DENOMINATOR = 3  # Use integer arithmetic: stake * 3 >= total * 2
MIN_TOTAL_STAKE = 1000  # minimum total stake to prevent bootstrap re-entry

# Attester-reward escrow window (stage 3).  Rewards earned while
# bootstrap_progress < 1.0 sit in escrow for this many blocks before
# unlocking to spendable balance.  During the window they are
# slashable — any stage-4 slashing event burns accumulated escrow.
# 12,960 blocks at BLOCK_TIME_TARGET=600s ≈ 90 days, which is the
# "sliding slashing window" from the design math: long enough to deter
# coordinated attacks, short enough not to punish honest newcomers
# with excessive wait before their first liquid tokens.  Actual escrow
# length at any moment is computed from bootstrap_progress via
# escrow_blocks_for_progress() — this is the max value at progress=0.
ATTESTER_ESCROW_BLOCKS = 12_960

# Reputation-weighted bootstrap lottery.
#
# During bootstrap, a periodic lottery pays a meaningful bounty to one
# non-seed validator, weighted by reputation.  Solves two problems:
#   (a) Uniform attester-committee selection at progress=0 means good
#       behavior doesn't compound into influence — a validator that
#       has correctly attested for months has the same per-block
#       selection odds as one that joined yesterday.  The lottery
#       rewards sustained honest participation in real time.
#   (b) A Sybil operator with N keys splits the committee pool N ways
#       individually, but the lottery is winner-take-all per interval
#       and weighted by reputation, so Sybil keys with similar
#       reputation compete with each other AND with honest single-
#       identity validators.  The Sybil-operator extraction rate
#       is closer to a single honest actor's, not Nx.
#
# Reputation counter: +1 per attestation accepted in a block, zeroed
# when the validator is slashed.  Capped at REPUTATION_CAP so a
# 6-month-old validator can't become a deterministic winner.
#
# Lottery fires every LOTTERY_INTERVAL blocks (144 × 600s ≈ 1 day).
# Bounty is deposited into the winner's escrow so it's slashable
# through the standard escrow window — a winner who misbehaves
# before the window closes loses it.
#
# Lottery stops firing once bootstrap_progress reaches 1.0.  Total
# lottery mint across the bootstrap window is bounded:
#   BOOTSTRAP_END_HEIGHT / LOTTERY_INTERVAL × LOTTERY_BOUNTY
#   ≈ 105,192 / 144 × 100 ≈ 73K tokens (~0.007% of supply).
REPUTATION_CAP = 10_000
LOTTERY_INTERVAL = 144       # blocks (~1 day at 600s)
LOTTERY_BOUNTY = 100         # tokens paid to lottery winner

# Minimum number of distinct validators required for finality.
#
# Historical name "MIN_VALIDATORS_TO_EXIT_BOOTSTRAP" reflects the old
# binary bootstrap flag; the canonical bootstrap signal is now the
# `bootstrap_progress` gradient (see
# messagechain/consensus/bootstrap_gradient.py), and this constant
# survives only as the finality floor — 2/3 of stake is not meaningful
# finality if only one or two validators exist.  Set to 1 because the
# chain launches with a single seed validator.  Tests also override
# this dynamically; keeping the old name avoids breaking that pattern.
# Reader should treat this name as "min validators for finality."
MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 1

# Slot-timing enforcement — if True, validate_block rejects blocks whose
# timestamp is less than BLOCK_TIME_TARGET seconds after the parent's.
# This prevents a malicious proposer from racing ahead of their slot to
# claim round 0 with a near-zero timestamp gap. Disabled in tests
# (tests/__init__.py) because existing fixtures produce blocks rapidly
# with real wall-clock timestamps.
ENFORCE_SLOT_TIMING = True

# Network
DEFAULT_PORT = 9333      # P2P listen port
RPC_DEFAULT_PORT = 9334  # RPC listen port (clients speak JSON-RPC here)
# The genesis validator IS the seed — it doesn't peer with itself.
# Other nodes either use CLIENT_SEED_ENDPOINTS (for CLI RPC discovery),
# pass --seed on startup (for P2P peering), or populate this via
# config_local.py.
SEED_NODES: list[tuple[str, int]] = []

# Hardcoded entry-point endpoints for CLI clients.  The CLI uses them
# to make its initial RPC connection.  Once connected, the CLI calls
# get_network_validators to discover the rest of the network and — if
# non-seed validators with known endpoints exist — routes subsequent
# calls via a sqrt(stake)-weighted random pick so load doesn't
# perpetually concentrate on the seeds.  Users can override per-command
# with `--server host:port`.
#
# These must point at RPC ports (RPC_DEFAULT_PORT), not P2P ports.
CLIENT_SEED_ENDPOINTS: list[tuple[str, int]] = [
    ("35.237.211.12", RPC_DEFAULT_PORT),
]
MAX_PEERS = 50
HANDSHAKE_TIMEOUT = 5  # seconds

# Peer banning
BAN_THRESHOLD = 100       # misbehavior score that triggers a ban
BAN_DURATION = 86400      # ban length in seconds (24 hours)

# Censorship resistance — forced inclusion list (attester-enforced)
#
# An attester tracks every tx it has held in its local mempool for at
# least FORCED_INCLUSION_WAIT_BLOCKS blocks.  From that set, it ranks
# by fee (descending, tiebreak by arrival height then hash) and takes
# the top FORCED_INCLUSION_SET_SIZE.  A proposer that omits any of
# these forced txs without a valid structural excuse (byte budget
# exhausted, tx count cap reached, tx no longer includable) is being
# censored — the attester votes NO on the block.
#
# 2/3 stake must attest for finality, so any 1/3 honest stake that
# sees the censored tx is enough to veto the block without needing
# global mempool consensus.  This is deliberately soft enforcement:
# block validity itself is unchanged (avoiding the impossible
# requirement of global-mempool agreement), but finality is gated.
#
# Parameters tuned for BLOCK_TIME_TARGET=600s and MAX_TXS_PER_BLOCK=20:
#   K=3 → ~30 min wait before a tx becomes "forced" (enough to propagate
#         through honest relay paths, short enough to punish censors)
#   N=5 → 25% of a full block, substantial but not the whole block so
#         proposers retain room to order other txs by fee
FORCED_INCLUSION_WAIT_BLOCKS = 3
FORCED_INCLUSION_SET_SIZE = 5

# Inclusion attestation — proposer mempool-snapshot accountability
#
# When enabled, each proposer embeds a Merkle root of their mempool's
# tx hashes in the block header.  This creates on-chain evidence of
# which txs the proposer saw at proposal time.  The proposer's block
# signature covers it transitively (via signable_data).  Evidence is
# for governance review, NOT automatic slashing.
INCLUSION_ATTESTATION_ENABLED = True

# VRF-based proposer selection — RANDAO lookahead.
#
# Proposer selection for block N uses the RANDAO mix from block
# N - VRF_LOOKAHEAD instead of the immediate parent. This makes the
# proposer for block N unknowable until block N - VRF_LOOKAHEAD is
# finalized, giving ~VRF_LOOKAHEAD * BLOCK_TIME_TARGET seconds of
# unpredictability (32 * 600s = ~5.3 hours).
#
# VRF_ENABLED gates the feature: when False, proposer selection falls
# back to the pre-VRF deterministic path (immediate parent mix).
# For early chain / bootstrap, blocks before VRF_LOOKAHEAD use the
# genesis mix (index 0), so the feature degrades gracefully.
VRF_LOOKAHEAD = 32              # blocks of proposer unpredictability
VRF_ENABLED = True              # feature gate

# Mempool
MEMPOOL_MAX_SIZE = 5000       # max transactions in mempool
MEMPOOL_TX_TTL = 1_209_600    # tx expiry in seconds (14 days)
MEMPOOL_PER_SENDER_LIMIT = 5  # max pending txs per entity (tight to throttle burst spam)
MEMPOOL_MAX_ANCESTORS = 5     # max unconfirmed tx chain depth per entity

# Active mempool replication — censorship-resistance layer on top of
# passive ANNOUNCE_TX gossip.  Every node periodically advertises a
# compact digest of its current mempool (hashes only) to a random subset
# of peers; each recipient pulls any hashes it's missing via
# REQUEST_MEMPOOL_TX.  The responder replies with the existing
# ANNOUNCE_TX — one tx-broadcast path, no duplicate logic.
#
# Why this matters: the per-node mempool means a captured first-hop
# node that silently drops a tx censors it from everyone — including
# attesters who would otherwise trigger the forced-inclusion veto.
# Active replication closes the hole: a tx that reaches ANY honest
# node propagates to every honest node within one sync interval.
#
# Rate limits are mandatory — a fanout of 3 digests every 30s is cheap,
# but a peer sending a digest claiming millions of hashes is DoS.  Hard-
# cap digest size, rate-limit REQUEST_MEMPOOL_TX per-peer, and throttle
# repeated digests from the same peer.
MEMPOOL_SYNC_INTERVAL_SEC = 30        # how often each node fires one sync cycle
MEMPOOL_SYNC_FANOUT = 3               # random peers contacted per cycle
MEMPOOL_DIGEST_MAX_HASHES = 10_000    # digest size cap (10K × 32B = 320KB worst case)
MEMPOOL_REQUEST_RATE_PER_SEC = 10     # steady-state REQUEST_MEMPOOL_TX rate per peer
MEMPOOL_REQUEST_BURST = 50            # burst allowance per peer
MEMPOOL_DIGEST_MIN_INTERVAL_SEC = 10  # reject digests faster than this per peer

# Per-pool cap on non-message-tx pending pools maintained by Server
# (_pending_stake_txs, _pending_unstake_txs, _pending_authority_txs,
# _pending_governance_txs).  Without a cap, a funded attacker could fill
# memory with validly-signed junk.  At 1024 entries per pool, all four
# top out at a few MB — the right trade-off for a chain that targets
# low-throughput, high-durability operation.  When a pool is full, a
# new tx only lands if its fee beats the lowest-fee pending tx, which
# is then evicted (same shape as Mempool's fee-based eviction).
PENDING_POOL_MAX_SIZE = 1024
# Pending-tx TTL: pool entries older than this are swept as stale.  Long
# enough to survive genuine network lag but short enough that a junk tx
# can't clog a pool for long.  1 hour is plenty — on a ~10-min block
# cadence that's 6 chances to land.
PENDING_TX_TTL = 3600

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

# (The explicit RegistrationTransaction was removed in the
# receive-to-exist refactor.  New entities enter chain state only
# when they first receive a transfer — there is no free self-
# registration pipeline to rate-limit or fee-gate any more, so
# REGISTRATION_FEE / MAX_REGISTRATIONS_PER_BLOCK have been deleted.
# Anti-bloat pressure on the receive-to-exist path is the DUST_LIMIT
# plus MIN_FEE on every transfer that creates a new account.)

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

# Signed state-snapshot checkpoints — bootstrap-speed sync for new nodes.
#
# Replaying the chain from genesis in year 100 means replaying 100 years of
# history. To let a new full-node / validator come up quickly, the network
# publishes a signed state snapshot every STATE_CHECKPOINT_INTERVAL blocks.
# A new node downloads the most recent such snapshot (with >= 2/3-stake
# signatures at that height) plus the ~last N blocks since the snapshot and
# starts participating without replaying ancient history. The chain itself
# is permanent — archive nodes keep everything — this is ONLY about new-
# node bootstrap time.
#
# Security model: identical to the finality-vote / weak-subjectivity story.
# A new node MUST treat the signed checkpoint as ground truth (it has no
# other basis on which to validate ancient history). In exchange, any
# validator that double-signs a checkpoint (two different state_roots for
# the same block_number) is slashed 100% stake + full escrow burn — same
# penalty as double-proposal and double-attestation.
#
# STATE_CHECKPOINT_INTERVAL: how often a checkpoint is emitted.  1000 blocks
# at 600s = ~7 days.  A node that wants to bootstrap waits at most one
# interval for a fresh checkpoint.
#
# STATE_CHECKPOINT_THRESHOLD_{NUMERATOR,DENOMINATOR}: 2/3 of stake-at-X must
# have signed the checkpoint for it to be "verified".  Mirrors the finality
# fraction (FINALITY_THRESHOLD_*) so operators see one threshold number for
# "the honest majority commits to this".
#
# MAX_STATE_SNAPSHOT_BYTES: 500MB upper bound on a single snapshot blob.
# Prevents a malicious peer from DoSing a bootstrapping node with a
# multi-GB snapshot.  The real snapshot size scales linearly with the
# active account count — at ~100 B per account, 500MB comfortably
# accommodates >1M accounts, well past any realistic per-person identity
# count the chain targets.
#
# STATE_ROOT_VERSION: format version of the state-snapshot root commitment.
# Bump-then-accept-both pattern lets a future governance proposal upgrade
# the Merkle scheme without a chain reset, same shape as HASH_VERSION_CURRENT.
STATE_CHECKPOINT_INTERVAL = 1000
STATE_CHECKPOINT_THRESHOLD_NUMERATOR = 2
STATE_CHECKPOINT_THRESHOLD_DENOMINATOR = 3
MAX_STATE_SNAPSHOT_BYTES = 500_000_000
STATE_ROOT_VERSION = 1

# Weak-subjectivity checkpoints — the PoS long-range-attack defense.
# A list of (block_number, block_hash, state_root) snapshots that new nodes
# treat as ground truth during IBD. Any peer that serves a header at one of
# these heights with a non-matching hash is rejected and penalized.
#
# Populate by embedding `WeakSubjectivityCheckpoint` instances at release
# time. Empty by default — an unprotected fresh chain is intentional so that
# local/test networks don't require bootstrap ceremonies.
TRUSTED_CHECKPOINTS: tuple = ()

# Strict checkpoint requirement — security default for production.
#
# When True, a node that ends up with zero checkpoints (neither from
# TRUSTED_CHECKPOINTS nor from checkpoints.json) refuses to start.
# This prevents a new node from silently running without long-range-
# attack protection.  Devnet/testnet deployments can set this to False.
#
# Override via env var MESSAGECHAIN_REQUIRE_CHECKPOINTS=false for
# bootstrap-phase deployments that haven't shipped checkpoints yet.
import os as _os_cp  # noqa: E402
_require_cp_env = _os_cp.environ.get("MESSAGECHAIN_REQUIRE_CHECKPOINTS")
REQUIRE_CHECKPOINTS = (
    False if (_require_cp_env is not None and _require_cp_env.lower() == "false")
    else True
)

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

# Finality signing — explicit 2/3-stake commitment to block hashes every
# FINALITY_INTERVAL blocks.  Finalized blocks cannot be reorganized by any
# later fork regardless of stake weight.  This is the long-range-attack
# defense: in year 500, an attacker who has acquired early validator keys
# (leak, coercion, purchase) cannot rewrite history past a finalized
# checkpoint because the finalized-block hashes are persisted on every
# honest node as a cryptographic commitment that is never retroactively
# revisable by any later fork.
#
# Distinct from the attestation layer: attestations live in memory and
# vote for the immediate parent block every slot.  FinalityVotes are
# persistent checkpoints that gossip separately, live in a dedicated
# mempool pool, and are included in later blocks where the proposer
# earns a small bounty per vote included (from treasury).  A validator
# signing two conflicting FinalityVotes for the same height is slashed
# 100% of stake plus full escrow burn, the same penalty as double-sign
# or double-attestation.
FINALITY_INTERVAL = 100               # blocks between finality checkpoints (~16h at 600s)
FINALITY_VOTE_INCLUSION_REWARD = 1    # tokens paid to proposer per vote included (from treasury)
FINALITY_INACTIVITY_PENALTY = 0       # placeholder — reward-loss, not slashing; tune later

# Inactivity leak — Casper-style defense against liveness attacks.
# If finalization stalls, non-participating validators' stakes are slowly
# drained (quadratically) until honest participants hold 2/3 supermajority.
# This is the ONLY known defense against a minority cartel that halts the
# chain by refusing to attest: without it, 40% silent stake permanently
# prevents finalization and no slashing triggers because slashing requires
# finalization.
#
# Quadratic scaling is intentional: early blocks of a stall are nearly free
# (brief outages, node restarts shouldn't catastrophically slash), but
# sustained non-participation bleeds stake rapidly.
#
# INACTIVITY_LEAK_ACTIVATION_THRESHOLD: blocks without finalization before
#   leak mode activates.  4 blocks = ~40 minutes at 600s — short enough
#   to respond to genuine attacks, long enough to ride out transient hiccups.
#
# INACTIVITY_PENALTY_QUOTIENT: ~2^24; controls leak speed.  Higher = slower.
#   After ~4000 blocks (~28 days) a 40% cartel has lost enough stake that
#   honest 60% becomes the new 2/3.
#
# INACTIVITY_BASE_PENALTY: base penalty per missed attestation per block
#   (in tokens).  Multiplied by (blocks_since_finality^2 / quotient).
INACTIVITY_LEAK_ACTIVATION_THRESHOLD = 4
INACTIVITY_PENALTY_QUOTIENT = 16_777_216  # ~2^24
INACTIVITY_BASE_PENALTY = 1
MAX_FINALITY_VOTES_PER_BLOCK = 200    # DoS guard on block-size expansion via finality votes
# A finality vote for a block older than FINALITY_VOTE_MAX_AGE blocks is
# rejected — prevents spam gossip of votes targeting ancient blocks that
# are already beyond the rewrite horizon anyway.  10 × FINALITY_INTERVAL
# = 1000 blocks (~7 days at 600s) is comfortably larger than any
# realistic gossip-lag window and still bounds the lookback.
FINALITY_VOTE_MAX_AGE_BLOCKS = 10 * FINALITY_INTERVAL

# Bitcoin anchoring — external immutability proof via OP_RETURN.
#
# Periodically commit MessageChain block hashes into Bitcoin, creating an
# independent proof that survives even total MessageChain validator collusion.
# No single chain's validator set can be trusted for 1000 years — Bitcoin
# anchors let anyone verify the chain was NOT rewritten by checking the
# OP_RETURN records on the most durable PoW chain in existence.
#
# ANCHOR_INTERVAL: blocks between anchors.  100 blocks at 600s = ~16h.
# Cost: ~$1/anchor at current Bitcoin fee rates.  Cheap insurance.
#
# ANCHOR_DOMAIN_TAG: mixed into the anchor hash to prevent collision with
# other OP_RETURN data on Bitcoin.  Version-tagged (V1) for crypto agility.
#
# ANCHOR_OP_RETURN_PREFIX: 2-byte prefix in the OP_RETURN output for
# identification when scanning Bitcoin blocks for MC anchors.
ANCHOR_INTERVAL = 100                    # blocks between anchors (~16h)
ANCHOR_DOMAIN_TAG = b"MCANCHOR_V1"       # domain separation
ANCHOR_OP_RETURN_PREFIX = b"MC"          # 2-byte prefix in OP_RETURN for identification

# Witness separation — split block storage into state-transition data
# and witness data (WOTS signatures + Merkle auth paths).  After
# finalization, ~97% of a block's bytes are witness data that serves
# only auditability, not consensus safety.  Nothing is ever deleted —
# witness data moves to a separate storage tier.
WITNESS_SEPARATION_ENABLED = True       # feature gate
WITNESS_RETENTION_BLOCKS = 200          # keep witnesses in main storage for this many blocks beyond finality

# Governance — on-chain voting for protocol/codebase changes
GOVERNANCE_VOTING_WINDOW = 1_008      # blocks (~7 days at 600s/block)
# Supermajority (2/3) required to approve a BINDING proposal (treasury
# spend).  Denominator is TOTAL ELIGIBLE voting weight (sum of every
# snapshotted validator's own stake), not just participants — silence
# counts as "no".  This gives an implicit 2/3 turnout floor for binding
# outcomes and keeps self-serving proposals from sliding through on a
# quiet week.
GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR = 2    # >2/3 (strict) of total eligible weight must approve
GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR = 3  # Use integer arithmetic: yes * 3 > total * 2
GOVERNANCE_PROPOSAL_FEE = 10_000      # fee to create a proposal (spam deterrent)
GOVERNANCE_VOTE_FEE = 100             # fee to cast a vote

# RPC authentication — prevents local privilege escalation where an
# unprivileged process calls submit_transaction / stake / ban_peer.
# The token is compared via constant-time HMAC to prevent timing attacks.
# Set to None to auto-generate a random token at startup.
#
# Default is True (secure by default).  A public-facing validator whose
# RPC is bound to 0.0.0.0 and whose operator wants to accept
# unauthenticated signed transactions can opt-in to disabling the token
# check by setting the MESSAGECHAIN_RPC_AUTH_ENABLED=false environment
# variable at process start.  Tx signature auth (WOTS+) still gates
# state changes; RPC auth was an anti-local-privilege-escalation layer,
# not the primary security boundary.
import os as _os
_rpc_auth_env = _os.environ.get("MESSAGECHAIN_RPC_AUTH_ENABLED")
RPC_AUTH_ENABLED = (
    False if (_rpc_auth_env is not None and _rpc_auth_env.lower() == "false")
    else True
)
RPC_AUTH_TOKEN: str | None = None  # auto-generated if None

# TLS encryption for P2P connections — prevents passive eavesdropping
# and MITM attacks on transaction relay and validator identity.
# Nodes generate a self-signed certificate on first run; peers verify
# only that TLS is in use (no CA chain — blockchain identity is separate).
P2P_TLS_ENABLED = True
TLS_CERT_PATH: str | None = None  # auto-generated if None
TLS_KEY_PATH: str | None = None   # auto-generated if None

# Public HTTPS submission endpoint — censorship resistance ingress.
#
# When enabled (CLI --submission-port), the validator exposes a single
# POST endpoint: `POST /v1/submit` with a binary-serialized
# MessageTransaction body.  TLS is mandatory (plaintext HTTP not
# supported); operator provides cert/key via --submission-cert /
# --submission-key.  Clients reach the chain directly over the public
# internet even if their local peers drop their txs.
#
# The endpoint is public by design — anyone on the internet can POST.
# Rate limiting and a hard body-size cap are the two layers keeping
# this from being a DoS cannon:
#   * Per-source-IP token bucket: at 2 tx/sec steady and a 10-tx burst,
#     a single attacker fills a block every ~10s but pays base fees for
#     every accepted tx (fee economics turn sustained spam into
#     validator revenue).
#   * Body cap at 16KB: safely larger than any real tx (a WOTS+
#     signature at MERKLE_TREE_HEIGHT=20 plus a 280-byte message fits
#     under 8KB) yet small enough to prevent memory-exhaustion via
#     chunked giant posts.
SUBMISSION_RATE_LIMIT_PER_SEC = 2
SUBMISSION_BURST = 10
MAX_SUBMISSION_BODY_BYTES = 16384

# Block deserialization size limit — maximum hex-encoded block size
# accepted from peers over the network.  A block with MAX_TXS_PER_BLOCK=20
# transactions each carrying MAX_BLOCK_MESSAGE_BYTES of payload plus WOTS+
# signatures is well under 1MB binary.  We allow 2MB hex (= 1MB binary) as
# a conservative ceiling.  Anything larger is either malicious or a bug on
# the sender side.
MAX_BLOCK_HEX_SIZE = 2_000_000  # 2M hex chars = 1MB binary


def validate_block_hex_size(block_data) -> bool:
    """Return True if block_data is a string within the size limit.

    Used as a guard before Block.from_bytes(bytes.fromhex(block_data))
    to reject oversized payloads from untrusted peers.
    """
    if not isinstance(block_data, str):
        return False
    return len(block_data) <= MAX_BLOCK_HEX_SIZE


# ─────────────────────────────────────────────────────────────────────
# Local overrides
# ─────────────────────────────────────────────────────────────────────
# If messagechain/config_local.py exists next to this file, any names
# defined there replace the values defined above.  config_local.py is
# gitignored so operator-specific settings survive `git pull` without
# risking accidental commits.
#
# Typical contents of config_local.py for a validator VM:
#     SEED_NODES = []
#     REQUIRE_CHECKPOINTS = False
#     MERKLE_TREE_HEIGHT = 16
#
# See config_local.py.example for a template.
import importlib.util as _ilu  # noqa: E402
import os as _os_local  # noqa: E402
_local_path = _os_local.path.join(_os_local.path.dirname(__file__), "config_local.py")
if _os_local.path.isfile(_local_path):
    _spec = _ilu.spec_from_file_location("messagechain._config_local", _local_path)
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _name in dir(_mod):
        if not _name.startswith("_"):
            globals()[_name] = getattr(_mod, _name)
