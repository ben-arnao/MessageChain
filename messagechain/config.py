"""Global configuration constants for the MessageChain protocol."""

# ─────────────────────────────────────────────────────────────────────
# Deployment profile — MESSAGECHAIN_PROFILE env var
# ─────────────────────────────────────────────────────────────────────
# A single switch that flips a coherent bundle of bootstrap-phase
# defaults.  Prior to this, a validator VM needed four separate env vars
# (RPC_AUTH_ENABLED, REQUIRE_CHECKPOINTS, BLOCK_TIME_TARGET,
# MERKLE_TREE_HEIGHT) to bootstrap — forgetting any one caused silent
# wrong behavior (slow keygen, refused start on missing checkpoints).
#
# Profiles:
#   production (or unset) — strict defaults, full security posture.
#   prototype             — coarse bootstrap bundle for early-phase
#                           deployments: fast blocks (30s), small Merkle
#                           trees (h=16, ~5 min keygen), checkpoints
#                           waived, RPC auth disabled.
#
# Precedence (most specific wins):
#   individual env var  >  profile  >  hardcoded default
#
# Unknown values raise a clear error at import — silent fallback would
# defeat the whole purpose (a typo becomes a production default, the
# opposite of what the operator intended).
import os as _os_profile

_PROFILE_RAW = _os_profile.environ.get("MESSAGECHAIN_PROFILE", "").strip().lower()
# Empty string == unset (a bare `Environment=MESSAGECHAIN_PROFILE=` in a
# systemd unit produces "" rather than removing the variable; treat both
# identically so a blank line doesn't crash the node).
if _PROFILE_RAW == "":
    _PROFILE = "production"
elif _PROFILE_RAW in ("production", "prototype"):
    _PROFILE = _PROFILE_RAW
else:
    raise ValueError(
        f"Unknown MESSAGECHAIN_PROFILE={_PROFILE_RAW!r}. "
        f"Valid values: 'production' (or unset) | 'prototype'. "
        f"Refusing to silently fall back to a default — a typo here "
        f"would inherit the opposite of the operator's intent."
    )

# Prototype bundle — the coherent set of bootstrap-phase defaults.
# Individual env vars override these (see _profile_bool / _profile_int
# helpers below).  Keep this dict as the one source of truth for what
# "prototype mode" means.
_PROTOTYPE_OVERRIDES: dict = {
    "REQUIRE_CHECKPOINTS": False,
    "BLOCK_TIME_TARGET": 30,
    "MERKLE_TREE_HEIGHT": 16,
    "RPC_AUTH_ENABLED": False,
}


def _profile_bool(env_name: str, key: str, default: bool) -> bool:
    """Resolve a bool config with precedence: env var > profile > default.

    Bool env-var convention: any value other than the case-insensitive
    string "false" counts as True (matches the pre-profile behavior of
    RPC_AUTH_ENABLED / REQUIRE_CHECKPOINTS).
    """
    raw = _os_profile.environ.get(env_name)
    if raw is not None:
        return raw.strip().lower() != "false"
    if _PROFILE == "prototype" and key in _PROTOTYPE_OVERRIDES:
        return bool(_PROTOTYPE_OVERRIDES[key])
    return default


def _profile_int(env_name: str, key: str, default: int) -> int:
    """Resolve an int config with precedence: env var > profile > default."""
    raw = _os_profile.environ.get(env_name)
    if raw is not None:
        return int(raw)
    if _PROFILE == "prototype" and key in _PROTOTYPE_OVERRIDES:
        return int(_PROTOTYPE_OVERRIDES[key])
    return default


def active_profile() -> str:
    """Return the active profile name ('production' or 'prototype')."""
    return _PROFILE


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


# Wire-format (binary serialization) versions — carry-only registers that
# gate the on-disk / on-wire layout of blocks and transactions, independent
# of the crypto-agility HASH/SIG versions above.
#
# Rationale: a silent breaking change to Block.to_bytes / MessageTransaction.
# to_bytes produces only a cryptic "hash mismatch" when old data is loaded
# by new code — an operator cannot tell whether the chain is corrupted, the
# signature is wrong, or the wire format changed under their feet.  On a
# 100-1000 year chain this class of failure is catastrophic: multiple format
# changes will accumulate over centuries, and any future reader must be
# able to diagnose "this blob predates my version of the decoder" in one
# hop rather than chasing down what the old layout used to look like.
#
# Embedding a leading version byte in every block / tx binary blob costs
# one byte per object and gives the decoder a decisive reject at the
# parse boundary: "unknown serialization version X (current = Y)".
#
# Future upgrade path mirrors HASH_VERSION_CURRENT exactly: a governance
# proposal bumps BLOCK_SERIALIZATION_VERSION / TX_SERIALIZATION_VERSION,
# the validate_*_serialization_version gate widens to accept the new
# value alongside the old during a migration window, and nodes that have
# not upgraded produce a clear error rather than silent corruption.
#
# Reserved: 0 is invalid (traps uninitialized / truncated input).
BLOCK_SERIALIZATION_VERSION = 1
TX_SERIALIZATION_VERSION = 1


def validate_block_serialization_version(version: int) -> tuple[bool, str]:
    """Reject unknown block wire-format versions at the parse boundary.

    Called from Block.from_bytes after reading the leading version byte.
    A future format-bump governance proposal widens this check to accept
    both the old and new values during a migration window.
    """
    if version != BLOCK_SERIALIZATION_VERSION:
        return False, (
            f"Unknown block serialization version {version} "
            f"(current = {BLOCK_SERIALIZATION_VERSION})"
        )
    return True, "OK"


def validate_tx_serialization_version(version: int) -> tuple[bool, str]:
    """Reject unknown transaction wire-format versions at the parse boundary.

    Called from every tx type's from_bytes after reading the leading
    version byte.  Same bump-and-widen upgrade shape as
    validate_block_serialization_version.
    """
    if version != TX_SERIALIZATION_VERSION:
        return False, (
            f"Unknown transaction serialization version {version} "
            f"(current = {TX_SERIALIZATION_VERSION})"
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
# Two nodes on empty data dirs with no pin each mint their own incompatible
# block 0, creating permanently bifurcated chains — which is why the pin
# exists.
#
# Network identity is selected by NETWORK_NAME below rather than by editing a
# raw hex literal.  To cut mainnet:
#   1. Mint mainnet genesis and set _MAINNET_GENESIS_HASH to its hash.
#   2. Flip NETWORK_NAME to "mainnet".
# Doing (2) without (1) raises at config load — a mainnet build cannot
# silently fall back to the testnet hash.
NETWORK_NAME = "testnet"  # "mainnet" | "testnet" | "devnet"

# Per-network canonical block-0 hashes.  Read these via PINNED_GENESIS_HASH
# below; do not reference them directly from other modules.
_TESTNET_GENESIS_HASH: bytes | None = bytes.fromhex(
    "7dfbd378a4bf34c8ac33df3ddc4340efa9d0218d8341dba2c8cdf2438b8f07ae"
)
_MAINNET_GENESIS_HASH: bytes | None = None  # set before mainnet cut


def _resolve_pinned_genesis_hash(network: str) -> bytes | None:
    """Map NETWORK_NAME → the pinned block-0 hash for that network.

    - mainnet: returns _MAINNET_GENESIS_HASH, or raises if it is None.
      A None pin on mainnet is a configuration bug, not a graceful
      fallback — the whole point of this selector is that "ship
      mainnet without filling in the hash" fails loudly rather than
      trusting the testnet hash by accident.
    - testnet: returns _TESTNET_GENESIS_HASH (may be None for a fresh
      testnet that hasn't minted genesis yet; initialize_genesis will
      refuse to start in that case unless network == "devnet").
    - devnet: returns None unconditionally — local testing lets any
      node mint its own genesis.
    - anything else: raises, so typos ("mainet", "staging") don't
      silently degrade to a disabled pin.
    """
    if network == "mainnet":
        if _MAINNET_GENESIS_HASH is None:
            raise RuntimeError(
                "NETWORK_NAME='mainnet' but _MAINNET_GENESIS_HASH is None. "
                "Refusing to load config: a mainnet build must pin the real "
                "mainnet block-0 hash before it can run. Edit "
                "messagechain/config.py and set _MAINNET_GENESIS_HASH to the "
                "mainnet genesis hash, or flip NETWORK_NAME back to "
                "'testnet'/'devnet' for non-production use."
            )
        return _MAINNET_GENESIS_HASH
    if network == "testnet":
        return _TESTNET_GENESIS_HASH
    if network == "devnet":
        return None
    raise RuntimeError(
        f"Unknown NETWORK_NAME {network!r}: must be one of "
        f"'mainnet', 'testnet', 'devnet'."
    )


PINNED_GENESIS_HASH: bytes | None = _resolve_pinned_genesis_hash(NETWORK_NAME)

# Legacy alias — existing call sites (blockchain.py, initialize_genesis) read
# DEVNET directly.  Kept as a derived flag rather than a parallel source of
# truth so the two can never disagree.
DEVNET = NETWORK_NAME == "devnet"

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
# not a priority).  Production default is 600s.  Bootstrap-phase deployments
# can opt in via MESSAGECHAIN_PROFILE=prototype (30s) or override
# individually via MESSAGECHAIN_BLOCK_TIME_TARGET.
BLOCK_TIME_TARGET = _profile_int("MESSAGECHAIN_BLOCK_TIME_TARGET", "BLOCK_TIME_TARGET", 600)
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
# Bootstrap-phase deployments can opt in via MESSAGECHAIN_PROFILE=prototype
# (h=16) or override individually via MESSAGECHAIN_MERKLE_TREE_HEIGHT.
MERKLE_TREE_HEIGHT = _profile_int("MESSAGECHAIN_MERKLE_TREE_HEIGHT", "MERKLE_TREE_HEIGHT", 20)
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

# New-account surcharge — an extra fee, BURNED (not paid to the proposer),
# on any Transfer whose recipient does not yet exist in on-chain state.
# The surcharge is bundled into the tx's single `fee` field — callers
# creating a transfer to a brand-new recipient must set
#     fee >= MIN_FEE + NEW_ACCOUNT_FEE
# or validation rejects it with a clear "new-account surcharge" error.
#
# Rationale: permanent state entry is expensive (storage, proofs,
# proof-serving for the lifetime of the chain).  Pricing it at MIN_FEE
# alone made full account creation cost ~110 tokens, far below the old
# REGISTRATION_FEE=1000 baseline the chain used before receive-to-exist.
# Burning (rather than paying to the proposer) aligns incentives:
# permanent state entry → permanent supply reduction.
#
# Exemptions:
#   * Genesis allocation_table entries (initial state, not user creation)
#   * Intra-block pipelining: only the FIRST tx funding a given
#     brand-new recipient in a single block pays the surcharge; a
#     second tx to the same recipient in the same block does not.
#   * Stake first-spend from an already-credited entity (no new state
#     entry is created — balance entry already exists from the prior
#     Transfer that funded them and paid the surcharge then).
#
# Treasury spends that credit a brand-new recipient burn NEW_ACCOUNT_FEE
# from the treasury balance on execute, failing the spend if treasury
# can't cover amount + NEW_ACCOUNT_FEE.
NEW_ACCOUNT_FEE = 1000

# Per-block cap on NEW permanent state entries (brand-new recipients).
# Second line of defense beyond the NEW_ACCOUNT_FEE surcharge — bounds
# state growth at a predictable rate regardless of how much an attacker
# is willing to burn.
#
# Ceiling math (144 blocks/day at BLOCK_TIME_TARGET=600s):
#   144 blocks/day * 10 accounts/block = 1,440 new accounts/day
#   at ~100 bytes of permanent state per account:
#     1,440 * 100 B = ~140 KB/day = ~50 MB/year worst case
#
# Permissive enough that legitimate onboarding isn't bottlenecked
# (under normal load actual creation is tiny; the cap only bites under
# sustained burn-attack traffic), while keeping permanent-storage
# growth on a schedule operators can plan around for 100+ years.
#
# Counting rules (same as NEW_ACCOUNT_FEE surcharge — uses
# `_recipient_is_new(..., pending_new_account_created=...)`):
#   * TransferTransactions whose recipient has no on-chain state count.
#   * Intra-block pipelining: multiple txs funding the SAME brand-new
#     recipient in one block count as ONE new-account creation.
#   * Genesis allocation_table entries do NOT count (they create state
#     at block 0 before any normal-path validation runs).
#
# Treasury spends that credit a brand-new account are NOT in this
# counter.  Rationale: treasury spends are governance-gated (weeks of
# 2/3-supermajority voting per spend), so a burst of new-account
# creations via that path is rate-limited by governance itself and
# doesn't add burst-attack surface.  They still individually pay
# NEW_ACCOUNT_FEE (burned from treasury on execute) — see
# execute_treasury_spend.
MAX_NEW_ACCOUNTS_PER_BLOCK = 10

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
# Bootstrap-phase deployments can opt in via MESSAGECHAIN_PROFILE=prototype
# (False) or override individually via MESSAGECHAIN_REQUIRE_CHECKPOINTS=false.
REQUIRE_CHECKPOINTS = _profile_bool(
    "MESSAGECHAIN_REQUIRE_CHECKPOINTS", "REQUIRE_CHECKPOINTS", True,
)

# Outbound connection slot allocation — mix full-relay (tx + block) peers
# with block-relay-only peers to defeat topology inference via tx-relay
# timing and preserve block flow under partial eclipse. Matches Bitcoin
# Core's default mix (8 full-relay + 2 block-relay-only).
OUTBOUND_FULL_RELAY_SLOTS = 8
OUTBOUND_BLOCK_RELAY_ONLY_SLOTS = 2

# Seed-validator divestment — non-discretionary unwind of founder stake.
#
# The founder bootstraps the chain with ~99M tokens staked (~9.9% of supply).
# Without an enforced unwind, at H=BOOTSTRAP_END_HEIGHT the founder would
# still dominate consensus with ~98% of stake as every bootstrap guardrail
# drops simultaneously.  The divestment schedule forces a linear unwind of
# each seed's initial stake over SEED_DIVESTMENT_END - SEED_DIVESTMENT_START
# blocks (~4 years at 600s), routing 75% to burn and 25% to the treasury.
#
# This is non-discretionary, always-on, and has no kill-switch.  Seeds can
# still re-stake post-divestment via a normal StakeTransaction using tokens
# earned through fees, rewards, or purchases — they simply lose their
# special genesis-stake status.
#
# Imported from bootstrap_gradient at module load to keep the one source
# of truth for BOOTSTRAP_END_HEIGHT.  Window length is fixed at 210,384
# blocks (~4 years) to match the existing halving cadence.
from messagechain.consensus.bootstrap_gradient import BOOTSTRAP_END_HEIGHT as _BEH  # noqa: E402
SEED_DIVESTMENT_START_HEIGHT = _BEH                                    # 105_192
SEED_DIVESTMENT_END_HEIGHT = SEED_DIVESTMENT_START_HEIGHT + 210_384    # 315_576
SEED_DIVESTMENT_BURN_BPS = 7500       # 75% of each block's divested amount is burned
SEED_DIVESTMENT_TREASURY_BPS = 2500   # 25% routed to treasury
assert SEED_DIVESTMENT_BURN_BPS + SEED_DIVESTMENT_TREASURY_BPS == 10_000

# Staking
UNBONDING_PERIOD = 1_008      # blocks before unstaked tokens become spendable (~7 days at 600s)

# Auto-restake — opt-in, node-local policy.  When AUTO_RESTAKE is True,
# after a node produces a block it sweeps its own liquid balance above
# AUTO_RESTAKE_LIQUID_BUFFER into a new StakeTransaction (provided the
# stakeable amount is at least AUTO_RESTAKE_MIN_AMOUNT).  The stake tx
# goes through the same admission path a real client uses, so every
# mempool invariant (nonce ordering, leaf dedupe, rate limit, pool cap)
# applies.
#
# Why a client-side flag instead of consensus-level auto-compounding:
#   * No consensus rule change — a node with AUTO_RESTAKE=False behaves
#     identically to today.  Individual operators pick their own policy
#     without forcing every validator to inherit our guess of "what
#     fraction is worth restaking."
#   * The optimal dust threshold depends on fee economics at the time.
#     Baking a particular rule into state-transition code would force
#     every operator in 2080 to live with a 2026 parameter.  A config
#     flag is easy to tune per-deployment.
#   * Block rewards already land in supply.balances[proposer] as liquid;
#     the existing StakeTransaction path is exactly the right tool to
#     convert them back into stake.  This is just a loop tied to a
#     local config flag.
#
# Safety:
#   * AUTO_RESTAKE_LIQUID_BUFFER keeps a reserve of liquid tokens so the
#     validator always has fees for future stake/unstake/authority txs.
#   * AUTO_RESTAKE_MIN_AMOUNT avoids spamming stake txs that are small
#     compared to the fee cost.
#   * The node skips if a pending stake tx from it is already queued,
#     so two auto-restake attempts in quick succession don't produce
#     two competing stake txs.
#   * Any failure in stake-tx construction is swallowed with a warning
#     log — block production is never aborted by an auto-restake error.
AUTO_RESTAKE = False                  # opt-in; set True in config_local.py
AUTO_RESTAKE_MIN_AMOUNT = 1_000       # don't sweep dust (avoid fee waste)
AUTO_RESTAKE_LIQUID_BUFFER = 1_000    # always keep at least this much liquid for fees

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
RPC_AUTH_ENABLED = _profile_bool(
    "MESSAGECHAIN_RPC_AUTH_ENABLED", "RPC_AUTH_ENABLED", True,
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
