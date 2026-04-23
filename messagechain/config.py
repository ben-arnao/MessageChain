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


def _profile_str(
    env_var: str,
    profile_var: str | None = None,
    default: str | None = None,
) -> str | None:
    """Return env_var if set and non-empty, else profile-specific fallback, else default.

    Mirrors _profile_bool / _profile_int but for string-typed config.
    Empty string in the env is treated as unset (falls through to
    profile/default) — this avoids surprising operators who might
    ``export MESSAGECHAIN_FOO=`` expecting the default.
    """
    raw = _os_profile.environ.get(env_var)
    if raw is not None and raw != "":
        return raw
    if (
        _PROFILE == "prototype"
        and profile_var is not None
        and profile_var in _PROTOTYPE_OVERRIDES
    ):
        override = _PROTOTYPE_OVERRIDES[profile_var]
        return None if override is None else str(override)
    return default


def active_profile() -> str:
    """Return the active profile name ('production' or 'prototype')."""
    return _PROFILE


# Cryptography (defined early — needed by Treasury ID derivation below)
HASH_ALGO = "sha3_256"

# Crypto agility — version bytes allow future algorithm upgrades via governance
# without a chain reset. Validators MUST reject unknown versions.
#
# HASH_VERSION_CURRENT / SIG_VERSION_CURRENT are active dispatch keys:
# every hash in the codebase flows through
# messagechain.crypto.hashing.default_hash (which consults
# HASH_VERSION_CURRENT) and every signature verify dispatches on the
# signature's own sig_version.  A future governance proposal activates
# a new scheme by adding a row to hashing._ALGO_BY_VERSION (for hashes)
# or widening _ACCEPTED_SIG_VERSIONS (for signatures), then bumping the
# _CURRENT constant.  No logic edits are required at call sites — the
# dispatcher is the single point of change.  SHA-256 will break someday
# (50 years? 200?); the 1-byte-per-block + 1-byte-per-signature cost
# of carrying these now is a trivial price for a chain designed to last
# 100-1000+ years.
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

# Identity-derivation hash version — frozen at genesis and NEVER rotated.
#
# `derive_entity_id(pubkey)` and `_derive_signing_seed(privkey)` in
# messagechain.identity.identity both need to return the exact same
# bytes every time they are called over the ENTIRE lifetime of the
# chain, because:
#
#   * A user's on-chain balance is keyed by the entity_id that
#     `derive_entity_id` produced the first time they transferred.  If
#     the function ever returns a different hash for the same public
#     key, the user's wallet address silently changes and their funds
#     are orphaned at an unreproducible address.
#   * A user's keypair is re-derived from their private key every time
#     they sign.  If `_derive_signing_seed` ever returns a different
#     seed for the same private key, the recomputed WOTS+ keypair has
#     a different public key than the one recorded on chain, so the
#     user can no longer sign for their own account.
#
# Binding those derivations to `HASH_VERSION_CURRENT` (the ACTIVE hash
# version, which governance is designed to rotate over the 100–1000
# year horizon) would guarantee a full account wipe on the first
# rotation — the exact failure mode the crypto-agility story exists to
# prevent.  Pin a SEPARATE "identity hash version" register here that
# NEVER rotates, so the on-chain identity namespace is immortal.
#
# If SHA3-256 is ever broken, we do NOT change this constant.  We ship
# a migration tx type that lets a user SIGN (under the still-valid
# signing primitive of the day) a "rebind from old_entity_id to
# new_entity_id" instruction, moving their balance to the new
# identity namespace under the new hash.  That keeps the namespace
# change user-consented, not silent.
IDENTITY_HASH_VERSION = HASH_VERSION_SHA256

SIG_VERSION_WOTS_W16_K64 = 1      # WOTS W=16 chains=64 merkle h=20.
                                  # NOTE: checksum encoding in this version
                                  # truncates to always-zero — see V2 below.
SIG_VERSION_WOTS_W16_K64_V2 = 2   # Same parameters, but with the fixed
                                  # base-w checksum encoding (2-byte big-
                                  # endian packed as exactly 4 nibbles,
                                  # no truncation).  V1 checksum chains
                                  # always fired at digit 0 regardless of
                                  # message content, reducing the WOTS+
                                  # security from 128-bit to ~2^56
                                  # grinding.  V2 closes this gap.
SIG_VERSION_CURRENT = SIG_VERSION_WOTS_W16_K64_V2
# Accepted sig versions.  V1 was retired at the 2026-04-21 mainnet
# re-mint (genesis bb010943...): the re-minted chain was produced
# entirely by current code (SIG_VERSION_CURRENT = V2), so no V1
# signature exists in the live chain's history, and nothing
# legitimate would ever produce one.  V1's checksum effectively
# collapses to zero (see SIG_VERSION_WOTS_W16_K64 comment above —
# ~2^56 grinding forgery).  Leaving V1 in the accept set after the
# re-mint is a pure forgery gate with no offsetting benefit, so V1
# is rejected at the consensus boundary.  The constant itself stays
# defined for historical reference + a clear rejection error.
#
# To re-accept V1 for some future migration, re-add
# SIG_VERSION_WOTS_W16_K64 here — but only if you genuinely need to
# validate pre-2026-04-21 sigs (e.g., an archival tool, NOT the
# live consensus path).
_ACCEPTED_SIG_VERSIONS: frozenset[int] = frozenset({
    SIG_VERSION_WOTS_W16_K64_V2,
})


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

    Accepts any version in `_ACCEPTED_SIG_VERSIONS`.  V1 signatures
    remain valid because the live mainnet chain committed blocks under
    V1 before the V2 checksum fix shipped; V2 is used for all new
    signatures.  Future schemes (XMSS, SPHINCS+, larger WOTS profiles)
    add themselves to the accepted set via governance.
    """
    if sig_version not in _ACCEPTED_SIG_VERSIONS:
        return False, (
            f"Unknown sig version {sig_version} "
            f"(accepted = {sorted(_ACCEPTED_SIG_VERSIONS)}, "
            f"current = {SIG_VERSION_CURRENT})"
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

# Acceptance sets, mirroring _ACCEPTED_SIG_VERSIONS above.  CLAUDE.md
# principle #3 (crypto agility) says every versioned object must be
# migratable by hard fork; a single-value equality check forces every
# widen-and-accept migration to edit validator logic, whereas a
# frozenset lets the migration be a one-line data edit.  During a
# version-bump window, the set contains BOTH the old and the new
# values; after the migration cutover, the old value can be removed.
# Both validators below read these sets lazily via globals() so test
# monkeypatching sees the mutation and import-order is flexible.
_ACCEPTED_BLOCK_SERIALIZATION_VERSIONS: frozenset[int] = frozenset({
    BLOCK_SERIALIZATION_VERSION,
})
_ACCEPTED_TX_SERIALIZATION_VERSIONS: frozenset[int] = frozenset({
    TX_SERIALIZATION_VERSION,
})


def validate_block_serialization_version(version: int) -> tuple[bool, str]:
    """Reject unknown block wire-format versions at the parse boundary.

    Called from Block.from_bytes after reading the leading version byte.
    A future format-bump governance proposal widens this check by
    adding the new value to _ACCEPTED_BLOCK_SERIALIZATION_VERSIONS — no
    logic edit required.
    """
    accepted = globals().get(
        "_ACCEPTED_BLOCK_SERIALIZATION_VERSIONS",
        frozenset({BLOCK_SERIALIZATION_VERSION}),
    )
    if version not in accepted:
        return False, (
            f"Unknown block serialization version {version} "
            f"(accepted = {sorted(accepted)}, "
            f"current = {BLOCK_SERIALIZATION_VERSION})"
        )
    return True, "OK"


def validate_tx_serialization_version(version: int) -> tuple[bool, str]:
    """Reject unknown transaction wire-format versions at the parse boundary.

    Called from every tx type's from_bytes after reading the leading
    version byte.  Same bump-and-widen upgrade shape as
    validate_block_serialization_version.
    """
    accepted = globals().get(
        "_ACCEPTED_TX_SERIALIZATION_VERSIONS",
        frozenset({TX_SERIALIZATION_VERSION}),
    )
    if version not in accepted:
        return False, (
            f"Unknown transaction serialization version {version} "
            f"(accepted = {sorted(accepted)}, "
            f"current = {TX_SERIALIZATION_VERSION})"
        )
    return True, "OK"


# Submission-receipt wire-format version.  Carried on every
# SubmissionReceipt so a future format bump (new fields, different
# domain tag) can be negotiated via the same governance-widen-accept
# pattern as BLOCK_SERIALIZATION_VERSION.  Defined up here (before
# the submission-receipt constants further down the file) so the
# module is import-order-agnostic — code that imports only
# RECEIPT_VERSION doesn't pay the whole-file cost.
def validate_receipt_version(version: int) -> tuple[bool, str]:
    """Reject unknown receipt versions at the parse boundary.

    Separated from sig_version because receipts are a separate wire
    object: bumping RECEIPT_VERSION doesn't require a sig-scheme change
    and vice versa.  Reserved: 0 is invalid (traps truncated input that
    decodes as all-zero bytes).  Widens by adding to
    _ACCEPTED_RECEIPT_VERSIONS (defined later in this module — read
    lazily via globals() so test monkeypatching works and import
    order is flexible).
    """
    current = globals().get("RECEIPT_VERSION", 1)
    accepted = globals().get("_ACCEPTED_RECEIPT_VERSIONS", frozenset({current}))
    if version not in accepted:
        return False, (
            f"Unknown receipt version {version} "
            f"(accepted = {sorted(accepted)}, current = {current})"
        )
    return True, "OK"


# Message constraints — ASCII-only (printable bytes 32-126), so 1 char = 1 byte.
MAX_MESSAGE_CHARS = 280  # max characters per message
MAX_MESSAGE_BYTES = 280  # 1:1 with chars (ASCII only, no multi-byte encoding)

# Token economics — inflationary to offset natural loss (deaths, lost keys)
# BLOCK_REWARD must be a power of 2 so halvings divide cleanly.
# At BLOCK_TIME_TARGET=600s, ~52,600 blocks/year.
# GENESIS_SUPPLY is set to the sum of the canonical mainnet allocations
# (founder 100M + treasury 40M = 140M) so that
#     total_supply == sum(balances) + sum(staked)
# holds at genesis by construction.  An earlier value of 1_000_000_000
# left 860M phantom tokens (counted in total_supply but owned by nobody),
# which inflated every "% of supply" denominator in the fee model,
# governance thresholds, and analytics.  This is a correctness repair,
# not a rule change — see test_genesis_supply_invariant.py.
#
# Year 1: 16 tokens/block * 52,600 ≈ 841.6K minted against 140M supply ≈ 0.60%/year
# 2 meaningful halvings over ~8 years (16→8→4), then floor of 4 forever.
# Perpetual floor: 4 tokens/block * 52,600 ≈ 210.4K/year against 140M ≈ 0.15%/year
GENESIS_SUPPLY = 140_000_000  # 140 million — matches founder (100M) + treasury (40M)
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
NETWORK_NAME = "mainnet"  # "mainnet" | "testnet" | "devnet"

# Per-network canonical block-0 hashes.  Read these via PINNED_GENESIS_HASH
# below; do not reference them directly from other modules.
#
# Mainnet re-minted 2026-04-22 after the safety-gaps + sybil-bind +
# state_snapshot v12->v14 merge train invalidated the 9458c6db pin
# (state-snapshot version bump alone changes block-0 state root).
# Same founder key, same 5M+95M allocation, new hash.  Previous
# hashes (all abandoned):
#   5e8bc19ccd4449... (2026-04-18 original launch)
#   53a1ce6217436b... (2026-04-20 post state-root-checkpoint)
#   5d37dd1c4b2603... (2026-04-20 post archive rewards + censorship)
#   bb0109432744d1... (2026-04-21 post bogus_rejection_evidence_txs)
#   5c31a3460698c4... (2026-04-22 stale: minted on ec6ce67, pinned in
#                      a deploy that never started — code moved past it)
#   5019f38d570cfe... (2026-04-22 stale: minted on e3431b3, never
#                      pinned because state_snapshot v11->v12 / new
#                      witnessed-submission landed before pin commit)
#   9458c6dbcbc185... (2026-04-22 stale: minted on 93c11e3, pinned but
#                      state_snapshot v12->v14 landed during test cycle)
_TESTNET_GENESIS_HASH: bytes | None = None
_MAINNET_GENESIS_HASH: bytes | None = bytes.fromhex(
    "4eeb9edaadb42f1a460e95919bc667a3173c4a84aa9b5488da040ac7a1c054f6"
)


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
# Carve-out: this is the ONE place config.py hashes at import time.
# Routing it through messagechain.crypto.hashing.default_hash would
# require importing the dispatcher before config.HASH_VERSION_CURRENT
# is bound, which is a circular-import hazard.  The value is a frozen
# genesis ID the live chain has already committed to; a future hash
# migration cannot change it even in principle.  See
# tests/test_hash_dispatch.py ALLOWED_DIRECT_USES.
#
# HASH LITERAL pinning: the hash family is spelled out as a bare
# string ("sha3_256"), NOT the ``HASH_ALGO`` constant, so a future PR
# that updates ``HASH_ALGO`` to track a rotated hash family cannot
# silently move TREASURY_ENTITY_ID to a different 32-byte address.
# Any relocation of the treasury address MUST be an explicit edit to
# this line accompanied by an explicit governance migration — the
# treasury holds 40M tokens and a silent address change orphans all
# of them.
TREASURY_ENTITY_ID = _hashlib.new("sha3_256", b"messagechain-treasury-v1").digest()
TREASURY_ALLOCATION = 40_000_000  # ~28.6% of genesis supply (40M / 140M)

# Default genesis allocation table: genesis validator + treasury.
# The genesis_entity's ID is filled in at chain init time.
# Allocations are absolute token amounts. Sum must not exceed GENESIS_SUPPLY.
DEFAULT_GENESIS_ALLOCATIONS = {
    TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
    # Genesis validator allocation is added dynamically in Blockchain.initialize_genesis
}

# Mainnet genesis allocation — the canonical founder split baked into the
# protocol so a joining validator can reconstruct post-genesis state from
# block 0 + these constants alone (no out-of-band snapshot required).
# These come from the `launch_single_validator.py --liquid 5000000 --stake
# 95000000` invocation the founder ran at mainnet launch.  The founder's
# pubkey is extractable from block 0's proposer_signature via
# compute_root_from_signature — so a joining node can pin block 0 by hash,
# extract the pubkey, and apply liquid + stake + treasury per these
# constants.  Block 1's state_root verification self-checks the values:
# any mismatch with the founder's original setup is immediate rejection.
_MAINNET_FOUNDER_LIQUID = 5_000_000
_MAINNET_FOUNDER_STAKE = 95_000_000
_MAINNET_FOUNDER_TOTAL = _MAINNET_FOUNDER_LIQUID + _MAINNET_FOUNDER_STAKE

# Pinned founder entity_id (= derive_entity_id(founder_pubkey)).  Cross-
# checked against block 0's proposer_id in _apply_mainnet_genesis_state
# as defense-in-depth: the PINNED_GENESIS_HASH already authenticates the
# chain via collision resistance, but pinning the identity separately
# traps any future edit to _MAINNET_GENESIS_HASH that forgets to update
# the allocation constants (which are identity-dependent via block-1
# state_root).  If this is None, the cross-check is skipped (testnet).
_MAINNET_FOUNDER_ENTITY_ID: bytes | None = bytes.fromhex(
    "7a72f1ec1ff9df12318043c91a444daecf7b82731c072371479fba371d6b930e"
)

# Load-time sanity check: the canonical mainnet allocation must fit
# inside GENESIS_SUPPLY alongside the treasury.  Catches a typo at
# import, not at first IBD attempt.  _MAINNET_FOUNDER_STAKE must also
# meet VALIDATOR_MIN_STAKE (checked below once that constant is defined).
assert _MAINNET_FOUNDER_LIQUID > 0, "mainnet founder liquid must be positive"
assert _MAINNET_FOUNDER_STAKE > 0, "mainnet founder stake must be positive"
assert _MAINNET_FOUNDER_TOTAL + TREASURY_ALLOCATION <= GENESIS_SUPPLY, (
    "mainnet founder + treasury allocation exceeds GENESIS_SUPPLY"
)
if _MAINNET_FOUNDER_ENTITY_ID is not None:
    assert len(_MAINNET_FOUNDER_ENTITY_ID) == 32, (
        "_MAINNET_FOUNDER_ENTITY_ID must be a 32-byte SHA3-256 digest"
    )

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

# Fee economics — EIP-1559-style base fee + tip.
#
# LEGACY (pre-FLAT_FEE_HEIGHT) non-linear size pricing — retained so
# historical blocks before the flat-fee fork replay deterministically:
#     fee = MIN_FEE + (bytes * FEE_PER_BYTE) + (bytes^2 * FEE_QUADRATIC_COEFF) // 1000
#
# POST-FLAT_FEE_HEIGHT the formula collapses to a flat per-tx floor
# (``MIN_FEE_POST_FLAT``).  Messages are already hard-capped at tweet
# scale, users are expected to fill that capacity, and multi-part
# messages are a first-class pattern — so charging per byte on top of
# per-tx is redundant.  Bloat defense becomes: (a) the hard size cap
# and (b) a flat fee set high enough that bulk spam is uneconomical.
# Above the floor, the market (EIP-1559 base fee + tip) does the rest.
MIN_FEE = 100  # legacy floor (pre-FLAT_FEE_HEIGHT)
MIN_FEE_POST_FLAT = 1000  # flat per-tx floor post-FLAT_FEE_HEIGHT
FEE_PER_BYTE = 3  # legacy per-byte component (pre-FLAT_FEE_HEIGHT only)
FEE_QUADRATIC_COEFF = 2  # legacy quadratic coeff (pre-FLAT_FEE_HEIGHT only)
BASE_FEE_INITIAL = 100               # starting base fee (= MIN_FEE)
BASE_FEE_MAX_CHANGE_DENOMINATOR = 8  # max 12.5% change per block
TARGET_BLOCK_SIZE = 10                # target txs per block (50% of MAX_TXS_PER_BLOCK)
MIN_TIP = 1                          # minimum priority tip to proposer

# Timestamp tolerance
MAX_TIMESTAMP_DRIFT = 60  # max seconds a tx timestamp can be ahead of current time

# Max seconds a BLOCK header's timestamp may be ahead of wall clock.
# Bitcoin's 7200 s (2 hours) is calibrated for PoW's bursty inter-block
# gaps; MessageChain is deterministic PoS with ~10-minute slots, so the
# window can be much tighter.  At a 2-hour bound a colluding proposer
# can stamp `time.time() + 7200` and — because every subsequent block
# must have `timestamp > parent.timestamp` (see validate_block /
# validate_block_standalone) — lock every honest proposer out of their
# slot until wall clock catches up, systematically denying honest blocks
# to propagate.  120 s is twice the tx drift bound and a small multiple
# of a reasonable NTP error; anything beyond is either a broken clock
# or an adversary abusing the window.
MAX_BLOCK_FUTURE_DRIFT = 120

# Block parameters
#
# BLOCK_TIME_TARGET: seconds between blocks (10 min, same as BTC — speed is
# not a priority).  Production default is 600s.  Bootstrap-phase deployments
# can opt in via MESSAGECHAIN_PROFILE=prototype (30s) or override
# individually via MESSAGECHAIN_BLOCK_TIME_TARGET.
BLOCK_TIME_TARGET = _profile_int("MESSAGECHAIN_BLOCK_TIME_TARGET", "BLOCK_TIME_TARGET", 600)
# Cap on how many fallback rounds a block's claimed timestamp can imply
# past the parent.  Block round is computed as
# int((block.ts - parent.ts - BLOCK_TIME_TARGET) // BLOCK_TIME_TARGET).
# Even after tightening MAX_BLOCK_FUTURE_DRIFT to 120 s, a malicious
# proposer can still inflate the implied round count by picking a
# parent.ts well below current wall clock; the explicit round cap keeps
# slot-rotation grinding bounded regardless of future-drift tolerance.
# Five fallback rounds covers legitimate missed-slot scenarios with
# margin; anything beyond is network pathology or abuse.
MAX_PROPOSER_FALLBACK_ROUNDS = 5
# Cap on concurrently-active governance proposals.  Without this, an
# attacker willing to pay PROPOSAL_FEE per proposal can spin up enough
# proposals to balloon governance state (each snapshot copies the
# staking electorate) — bounded only by the ~7-day voting window.
# 500 proposals is already more than a healthy governance cadence;
# add_proposal returns False past this bound, and the attached
# ProposalTransaction is effectively no-op (fee still paid, proposal
# not tracked) — the cost falls on the spammer.
MAX_ACTIVE_PROPOSALS = 500
# Upper bound on base_fee growth.  Without this, spam-fill attacks can
# compound +12.5% per block indefinitely (EIP-1559 style adjustments are
# unbounded above).  10000x MIN_FEE gives ~1M tokens-per-tx at MIN_FEE=100
# which is clearly pathological — honest org fees sit orders of magnitude
# below.  Recovery on the way down is symmetric, so the cap also bounds
# the post-attack recovery tail.
MAX_BASE_FEE_MULTIPLIER = 10_000
MAX_TXS_PER_BLOCK = 20  # max transactions per block (tx count cap)
MAX_TXS_PER_ENTITY_PER_BLOCK = 3  # anti-flooding: max message txs from one sender per block
MAX_BLOCK_MESSAGE_BYTES = 10_000  # max total message payload bytes per block (byte budget cap)
MAX_BLOCK_SIG_COST = 100  # max signature verification cost per block (1 per tx + 1 proposer + attestations)
# COINBASE_MATURITY must cover the worst-case un-finalized window or a
# reorg can double-spend a coinbase that the honest chain never minted.
# Math: MAX_REORG_DEPTH = 100 caps explicit reorg, but finality lands
# every FINALITY_INTERVAL = 100 blocks and vote inclusion adds 1-2
# more blocks - so a coinbase minted just after a checkpoint can sit
# un-finalized for up to ~100 + 2 blocks.  Mature-at-10 left an 8-90
# block window where a reorg could vanish the coinbase after Alice
# already accepted payment from it.  Matching BTC's canonical 100 is
# necessary but not sufficient here because our reorg cap IS 100;
# 200 covers reorg_depth + finality_interval with margin.  Raised
# from 10 (iter 6 of hardening pass).  The chain was young (h<100,
# no coinbase spends yet) when this changed, so no historical block
# is retroactively affected.
COINBASE_MATURITY = 200
MTP_BLOCK_COUNT = 11      # number of blocks to compute Median Time Past (same as BTC)

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

# Consensus — minimum stake to register as a validator.
#
# Pre-raise (LEGACY): 100 tokens.  Calibrated against the old 1B
# GENESIS_SUPPLY — 0.00001% of supply, permissionless but trivially
# sybil-affordable.  When GENESIS_SUPPLY was rebased from 1B to 140M
# the legacy floor shrank to 0.00007% of supply: still sybil-trivial,
# plus the per-validator capital commitment became negligible
# (~$0.01 under any realistic token price).
#
# Post-raise: 10_000 tokens.  At 140M supply that's 0.007% of supply —
# still permissionless (no whitelist, no gatekeeper) but imposes a
# meaningful per-validator capital cost that raises the floor on
# sybil operations.  The `*_POST_RAISE` suffix mirrors the convention
# used by the prior forks (TREASURY_REBASE_HEIGHT,
# SEED_DIVESTMENT_RETUNE_HEIGHT, etc).
#
# Grandfathering (critical): validators registered pre-fork with
# stake below the new floor KEEP their stake unchanged — we do not
# retroactively eject them.  Post-fork new-stake and partial-unstake
# operations enforce the new floor; full exit (remaining == 0) is
# always permitted so legacy sub-floor validators can walk away
# cleanly.  See `get_validator_min_stake` below and the enforcement
# sites in core/staking.py, core/blockchain.py, economics/inflation.py.
#
# Operators MUST replace the MIN_STAKE_RAISE_HEIGHT placeholder
# (50_000) with a concrete coordinated-fork height before deploying
# to mainnet; the placeholder follows the "current_height + 50_000"
# convention shared with the other pending forks.
VALIDATOR_MIN_STAKE = 100                # LEGACY — see get_validator_min_stake
VALIDATOR_MIN_STAKE_POST_RAISE = 10_000  # 0.007% of 140M supply
MIN_STAKE_RAISE_HEIGHT = 60_000  # Tier 2


def get_validator_min_stake(block_height: int) -> int:
    """Return the validator minimum stake in effect at ``block_height``.

    Hard-fork-gated: pre-activation returns the legacy 100-token value
    so pre-fork chain state is reproducible; at/after activation
    returns the post-raise 10_000-token floor.

    Used by every fresh-stake / partial-unstake enforcement site.
    The apply-time active-set filter (proposer-selection, validator-
    set membership for finality/attestation) continues to honor the
    LEGACY floor: grandfathered sub-floor validators retain their
    participation rights indefinitely; only NEW stake ops see the
    raised bar.
    """
    if block_height >= MIN_STAKE_RAISE_HEIGHT:
        return VALIDATOR_MIN_STAKE_POST_RAISE
    return VALIDATOR_MIN_STAKE


assert _MAINNET_FOUNDER_STAKE >= VALIDATOR_MIN_STAKE_POST_RAISE, (
    "mainnet founder stake must meet VALIDATOR_MIN_STAKE_POST_RAISE"
)
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
# Bootstrap-lottery bounty, hard-fork-gated.
#
# Pre-raise (LEGACY): 100 tokens.  Integrated over the 2-year
# bootstrap window with the (1 - progress) fade this mints
# ~73K tokens (~0.05% of 140M supply) across all winners — too small
# to materially diversify non-founder holdings.
#
# Post-raise: 5_000 tokens.  Integrated envelope rises to ~1.83M
# (~1.3% of supply), feeding meaningful liquidity into non-founder
# wallets during the bootstrap window while still sized well under
# every other bootstrap-era mint mechanic.  The `(1 - progress)` fade
# is preserved — the raise simply scales the base value; collapse-
# to-0 at progress=1.0 is unchanged.
#
# Operators MUST replace the LOTTERY_BOUNTY_RAISE_HEIGHT placeholder
# (50_000) with a concrete coordinated-fork height before deploying
# to mainnet.
LOTTERY_BOUNTY = 100                 # LEGACY — see get_lottery_bounty
LOTTERY_BOUNTY_POST_RAISE = 5_000
LOTTERY_BOUNTY_RAISE_HEIGHT = 62_000  # Tier 2


def get_lottery_bounty(block_height: int) -> int:
    """Return the lottery base bounty in effect at ``block_height``.

    Hard-fork-gated: pre-activation returns the legacy 100-token value
    so pre-fork lottery firings replay byte-for-byte; at/after
    activation returns the post-raise 5_000-token base.  The
    `(1 - bootstrap_progress)` fade is applied to the returned base
    by `lottery_bounty_for_progress` at the firing site — semantics
    preserved across the activation boundary.
    """
    if block_height >= LOTTERY_BOUNTY_RAISE_HEIGHT:
        return LOTTERY_BOUNTY_POST_RAISE
    return LOTTERY_BOUNTY

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
# Default P2P seed list shipped with the release.  A fresh node with no
# --seed flag connects to these to join the network.  Operators override
# via --seed on startup or by setting SEED_NODES in config_local.py.
# The genesis validator does not peer with itself; it reads this list
# only on non-genesis nodes.  As the validator set grows, shipped
# defaults should expand and eventually give way to proper peer-exchange.
SEED_NODES: list[tuple[str, int]] = [
    ("35.237.211.12", DEFAULT_PORT),  # validator-1 (founder / genesis) — us-east1-b
    ("35.231.82.12", DEFAULT_PORT),   # validator-2 — us-east1-c (added v1.0.1)
]

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
    ("35.237.211.12", RPC_DEFAULT_PORT),  # validator-1 — us-east1-b
    ("35.231.82.12", RPC_DEFAULT_PORT),   # validator-2 — us-east1-c (added v1.0.1)
]
MAX_PEERS = 50
HANDSHAKE_TIMEOUT = 10  # seconds - raised from 5 to accommodate TLS
                        # over high-latency links (sat, constrained mobile).
                        # A TLS + MC handshake can take 4+ round-trips; at
                        # 300ms RTT that consumes ~1.2s before any margin.
                        # Honest peers on slow connections should not fail
                        # first-contact for want of a few extra seconds.
# Key-rotation cooldown: minimum blocks between successive rotations
# by the same entity.  Without it a funded attacker could rotate every
# block (cost = KEY_ROTATION_FEE), churning state + erasing forensic
# traceability of recently-slashable behavior.  At 600s/block, 144
# blocks ~ 1 day gives legitimate emergency rotations unimpeded and
# caps spam to 365 rotations/yr/entity — economically irrational at
# 1000 tokens each.  Consensus constant; changing is a hard fork.
KEY_ROTATION_COOLDOWN_BLOCKS = 144

PEER_READ_TIMEOUT = 300  # seconds - idle timeout for post-handshake peer
                         # reads.  Previously a magic 300 literal scattered
                         # across server.py + network/node.py (4 sites);
                         # centralized so ops changes touch one knob.

# Peer banning
BAN_THRESHOLD = 100       # misbehavior score that triggers a ban
BAN_DURATION = 86400      # ban length in seconds (24 hours)
DECAY_INTERVAL = 3600     # score decays by 1 every hour of good behavior
MAX_TRACKED_PEERS = 5000  # memory cap for peer score tracking
# The four ban-accounting knobs above are the authoritative values.
# messagechain/network/ban.py imports from here — do NOT redefine them
# in ban.py (iter 5 found a dead-code duplication that silently made
# config_local.py overrides no-ops for operators trying to tighten
# peer policing).

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

# ─────────────────────────────────────────────────────────────────────
# Quorum-signed inclusion lists — slashing-bearing forced inclusion
# ─────────────────────────────────────────────────────────────────────
#
# Forced inclusion (FORCED_INCLUSION_*) is attester-subjective and
# slashing-free: each attester votes against blocks that omit txs from
# its own mempool view.  A coordinated minority of validators that
# refuses to attest against a censoring proposer can defeat that defense
# while staying under the 1/3 attestation-blocking threshold.
#
# Quorum-signed inclusion lists close the gap.  An InclusionList is a
# CONSENSUS-OBJECTIVE commitment to a set of tx_hashes that >= 2/3 of
# attester stake has independently seen for at least
# INCLUSION_LIST_WAIT_BLOCKS blocks.  The list published in block N
# applies forward to blocks N+1..N+INCLUSION_LIST_WINDOW; any
# proposer in that window MUST include each list-mandated tx (or attach
# a valid structural excuse).  After expiry, anyone can submit an
# InclusionListViolationEvidenceTx slashing the negligent proposer
# INCLUSION_VIOLATION_SLASH_BPS of stake (burned, no finder reward —
# matches censorship-evidence and bogus-rejection-evidence posture).
#
# Parameters tuned for BLOCK_TIME_TARGET=600s:
#   WAIT=4    → ~40 min before a tx becomes list-eligible.  Long enough
#               that gossip lag does not falsely include a tx that
#               hasn't propagated to most attesters; short enough to
#               keep censorship punitive.
#   WINDOW=4  → ~40 min in which proposers must include a listed tx.
#               Multiple proposers cycle through the window so a single
#               coerced proposer cannot single-handedly censor.
#   QUORUM=6667 bps → 2/3 of stake, matches the finality threshold so
#               an inclusion list cannot be assembled by a smaller
#               coalition than would already be needed to finalize.
#   MAX_ENTRIES=64 → bounds the per-block size growth induced by lists
#               (sig-bearing reports dominate; 64 entries × ~4 KB ≈
#               256 KB worst case before fee-market gating).
INCLUSION_LIST_WAIT_BLOCKS = 4
INCLUSION_LIST_WINDOW = 4
INCLUSION_LIST_QUORUM_BPS = 6667  # 2/3 of stake; mirrors finality threshold
MAX_INCLUSION_LIST_ENTRIES = 64
# Stake fraction burned per inclusion-violation evidence.  Hard-coded to
# the same value as CENSORSHIP_SLASH_BPS (= 1000 bps = 10%) — both are
# "soft censorship" offenses, not consensus-corruption equivocation.
# An assertion at the bottom of this file (after CENSORSHIP_SLASH_BPS is
# defined) cross-checks the two and raises on drift.
INCLUSION_VIOLATION_SLASH_BPS = 1000

# Crypto-agility version register for InclusionList wire format.  Bump
# this and widen _ACCEPTED_INCLUSION_LIST_VERSIONS when the on-disk /
# on-wire layout changes.  Reserved: 0 is invalid (traps zero-init blobs).
INCLUSION_LIST_VERSION = 1
_ACCEPTED_INCLUSION_LIST_VERSIONS: frozenset[int] = frozenset({
    INCLUSION_LIST_VERSION,
})


def validate_inclusion_list_version(version: int) -> tuple[bool, str]:
    """Reject unknown InclusionList wire-format versions.

    Read lazily via globals() so test monkeypatching sees mutations and
    import-order is flexible — same shape as
    validate_block_serialization_version.
    """
    current = globals().get(
        "INCLUSION_LIST_VERSION", INCLUSION_LIST_VERSION,
    )
    accepted = globals().get(
        "_ACCEPTED_INCLUSION_LIST_VERSIONS",
        frozenset({current}),
    )
    if version not in accepted:
        return False, (
            f"Unknown inclusion-list version {version} "
            f"(accepted = {sorted(accepted)}, current = {current})"
        )
    return True, "OK"

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
# Per-peer orphan quota: one sybil can no longer fill all MAX_ORPHAN_BLOCKS slots.
# A single honest peer filling its cap during an IBD gap still fits comfortably
# below MAX_ORPHAN_BLOCKS; 10 peers filling it simultaneously fills the pool.
MAX_ORPHAN_BLOCKS_PER_PEER = 10
# Age-based TTL for orphan blocks (in number of block-heights since arrival).
# 100 blocks at a 6-second target ~= 10 minutes — long enough for any honest
# parent to arrive via normal gossip / IBD, short enough that a peer feeding us
# unreachable orphans cannot pin them in memory indefinitely.
ORPHAN_MAX_AGE_BLOCKS = 100

# Header spam protection — bound pending headers during IBD to prevent OOM
MAX_PENDING_HEADERS = 50_000  # max headers held in memory during sync

# Transaction relay privacy — Poisson-distributed random delay before INV relay
TX_RELAY_DELAY_MEAN = 2.0  # average seconds of delay before relaying tx to peers

# Orphan transaction pool — hold out-of-order nonce txs temporarily
MEMPOOL_MAX_ORPHAN_TXS = 100       # max orphan txs total
# 3 was too tight for honest users: a legitimate
# stake -> unstake -> stake pipeline plus a concurrent message or two
# exhausts the quota and legitimate orphans start being rejected.  10
# still caps attacker amplification (at most 10 * MEMPOOL_MAX_ORPHAN_NONCE_GAP
# pending orphans per sender) while giving honest bursts headroom.
MEMPOOL_MAX_ORPHAN_PER_SENDER = 10 # max orphan txs per entity
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
# v2: added seed_divestment_debt section to the snapshot Merkle tree
# (partial-divestment-to-floor schedule).
# v3: added archive_reward_pool (proof-of-custody archive rewards —
# the pool balance scalar must participate in the root so bootstrapping
# nodes see the same value as replaying nodes).
# v4: added attester_coverage_misses section (per-attester
# consecutive-miss counter for the coverage-divergence inactivity
# leak — defense against 1/3 AttesterMempoolReport withholding
# cartels).  Two state-synced nodes that disagreed on the counter
# would burn different amounts at the next non-empty inclusion list
# and silently fork.
# v5: added two new sections — non_response_processed (set of
# evidence_hashes that have been admitted by NonResponseEvidence-
# Processor; double-slash defense) and witness_ack_registry
# (request_hash → observed_height; consulted by
# `validate_non_response_evidence_tx` so an evidence whose
# request_hash is already ack'd in chain state is rejected).  Both
# MUST participate in the state root: a state-synced node that
# inherited empty processed/registry would re-apply already-
# processed evidence (double-slash) or admit evidence the chain
# considers met.  See storage.state_snapshot for the section tags.
STATE_ROOT_VERSION = 5

# ── On-chain state-root checkpoints ──────────────────────────────────
# Periodic commitments of the full snapshot root into the block header
# itself, one every CHECKPOINT_INTERVAL blocks.  Distinct from the
# off-chain-signed StateCheckpoint in consensus/state_checkpoint.py (a
# multi-sig ceremony over a pre-existing block) and from the per-entity
# BlockHeader.state_root (which covers only account dicts, not treasury
# / supply / finalized_checkpoints / seed state).
#
# Purpose: a new node joining in year N can pick any finalized block at
# a checkpoint height, read the committed snapshot root out of that
# block's header, download a matching snapshot from any archive peer,
# verify the root matches, and start participating — without either
# replaying centuries of history or trusting an out-of-band signing
# ceremony.  The commitment is consensus-bound: every validator that
# accepted the checkpoint block agreed on the snapshot root it carries.
#
# CHECKPOINT_INTERVAL: 10,000 blocks at 600s = ~70 days.  Sparse enough
# that the ~32-bytes-per-interval chain-state overhead is negligible;
# dense enough that a first-time joiner in any calendar quarter has a
# recent finalized checkpoint to anchor on.  Non-multiples of the
# interval MUST carry a zero state_root_checkpoint — any other value is
# rejected at validation so a proposer cannot silently corrupt the
# commitment stream.  Block 0 (genesis) is also excluded: the zero
# field there keeps the commitment stream clean and the genesis block
# self-contained rather than carrying a snapshot root of an "empty"
# chain.
#
# CHECKPOINT_VERSION: carry-only register matching HASH_VERSION_CURRENT
# / BLOCK_SERIALIZATION_VERSION.  A future governance proposal can bump
# this to widen the accepted set (e.g., shift from snapshot-root-v2 to
# a future SMT-based commitment) without a chain reset.  Reserved: 0
# traps uninitialized.
#
# Scope discipline — this is a SYNC UX affordance, NOT a pruning
# mechanism.  Archive nodes still retain every block; the checkpoint
# just saves a joiner from downloading all of that history.
CHECKPOINT_INTERVAL = 10_000
CHECKPOINT_VERSION = 1


def is_state_root_checkpoint_block(block_number: int) -> bool:
    """True iff this block height must commit to a state-root checkpoint.

    Rule: positive multiples of CHECKPOINT_INTERVAL.  Genesis (height 0)
    is excluded so the commitment stream starts cleanly at the first
    real checkpoint, not at a snapshot of the pre-application state.
    """
    if block_number <= 0:
        return False
    return (block_number % CHECKPOINT_INTERVAL) == 0

# ── Proof-of-custody archive rewards ─────────────────────────────────
#
# Consensus-enforced reward stream that pays nodes for provably holding
# historical block data, defending the 1000-year permanence principle
# against archive-operator attrition.  See
# `messagechain/consensus/archive_challenge.py` (module docstring +
# `CustodyProof`, `ArchiveProofBundle`) and
# `messagechain/consensus/archive_duty.py` for the full design.
#
# Each challenge block, the chain selects a random past height via
# VRF-over-block-hash.  Any operator holding that block may submit a
# custody proof (header + sampled tx + Merkle inclusion) within
# ARCHIVE_SUBMISSION_WINDOW blocks.  The first
# ARCHIVE_PROOFS_PER_CHALLENGE valid proofs get paid ARCHIVE_REWARD
# tokens each from the ArchiveRewardPool.
#
# Funding: ARCHIVE_BURN_REDIRECT_PCT of what would otherwise burn from
# the EIP-1559 base-fee stream is redirected into the pool.  The rest
# still burns.  Pool persists in the snapshot root (bootstrapping nodes
# see the same value as replaying nodes).  When empty, no rewards pay
# out that block — graceful degradation, no minting.
#
# Cadence sizing (100 blocks / ~1 day at 600s): low enough to detect
# archive dropouts quickly, high enough to bound reward pressure.
# Redirect PCT (25) caps the ongoing archive-reward cost at one-quarter
# of the fee-burn stream — preserves most of the deflationary pressure
# while giving archives a meaningful paycheck.
ARCHIVE_CHALLENGE_INTERVAL = 100
# Iteration 3e (recommendation 1 from the post-3d audit): widen the
# paid-archivist surface from ~10 industrial operators per epoch to
# ~100 distributed ones.  Per-payout reward simultaneously dropped
# so total per-epoch pool drain (cap × reward = 10,000 tokens) is
# unchanged — 10× more winners each earning 1/10 as much.
# Economic-model margins remain wide (~500× storage cost at year
# 100 for a 1-slot-per-epoch winner).  Pairs with the selection
# change in apply_archive_rewards: deterministic uniform shuffle
# replaces strict FCFS, so fast-connection advantage is neutralized
# among valid submitters.
ARCHIVE_PROOFS_PER_CHALLENGE = 100
ARCHIVE_REWARD = 100
ARCHIVE_SUBMISSION_WINDOW = 100
ARCHIVE_BURN_REDIRECT_PCT = 25
# Multi-height sampling: K distinct historical heights challenged per
# epoch, so a validator keeping only a small slice of history cannot
# reliably pass the custody check.  Each validator submits K proofs
# per epoch; all K must land for the validator to be credited (the
# duty-enforcement layer applies the all-or-nothing rule — sampling
# layer just produces K challenges and K leaves per submitter).
#
# Bumped from 3 to 5 in iteration 3c.  Evasion probability at p=0.5
# (keep half the history) drops from ~12% to ~3%; at p=0.7 from 34%
# to 17%.  First K//2 challenges sample uniformly across all history;
# the remaining K - K//2 are age-skewed (see ARCHIVE_AGE_SKEW_FRACTION)
# so a pruner keeping only recent blocks fails deterministically.
#
# At ~100 validators this is ~500 bundle leaves per epoch (~35 KB
# canonical bytes), still well inside the bloat budget.  Tunable via
# future governance proposal.
ARCHIVE_CHALLENGE_K = 5
# Age-skewed sampling: the second half of each epoch's challenges
# targets the oldest AGE_SKEW_FRACTION of history.  Prevents a
# validator from passing by retaining only recent blocks — the
# weakest-incentivized data (ancient blocks with no recent access)
# gets sampled disproportionately.
#
# 0.1 = oldest 10%.  A validator keeping only the newest 90% fails
# every age-skewed challenge deterministically; keeping only the
# newest 99% fails ~90% of them.  At very small B (bootstrap era)
# the age-skewed bucket collapses to full-range sampling — see
# compute_challenges for the degradation path.
ARCHIVE_AGE_SKEW_FRACTION = 0.1
# Graduated reward-withhold tiers applied to a validator who misses
# successive archive-custody epochs.  Index i = withhold% at miss
# count i; any miss count >= len(tiers)-1 uses the final tier
# (saturates at 100%).  Three-strike ramp gives operators room to
# recover from honest disk failure before hitting full withhold.
#
# Miss decay: see ARCHIVE_MISS_DECAY_STREAK — iteration 3c replaced
# the old per-epoch-decrement rule (attackers could cycle prune/serve
# with amortized ~50% withhold) with a consecutive-successes rule.
ARCHIVE_WITHHOLD_TIERS = (0, 25, 50, 100)
# Miss-counter decay: number of CONSECUTIVE successful epochs
# required before the miss counter decrements by 1.  Streak is per-
# validator, persisted in state, and resets on any miss.  3 epochs
# ≈ 3 days at default cadence — short enough for honest operators
# recovering from disk failure, long enough that a cycling pruner
# cannot cheaply wash out reputation.
ARCHIVE_MISS_DECAY_STREAK = 3
# Highest miss count the tier table indexes directly.  Counter may
# exceed this but the tier saturates at 100%.  Kept in sync with the
# last index of ARCHIVE_WITHHOLD_TIERS.
ARCHIVE_MAX_MISS_COUNT = len(ARCHIVE_WITHHOLD_TIERS) - 1
# Bootstrap grace: a newly-joined validator has this many blocks to
# sync full history before the archive duty applies.  Chosen as
# 10 challenge epochs so a new operator has ~10 days at current
# cadence to download history before being scored.  Tradeoff: a
# malicious joiner can dodge duty for this window, but they've also
# earned no reputation/rewards yet to exploit.
ARCHIVE_BOOTSTRAP_GRACE_BLOCKS = 10 * ARCHIVE_CHALLENGE_INTERVAL
# Carry-only crypto-agility register.  A future governance proposal can
# widen the accepted proof format (e.g., switch to witness-archive
# rewards) without a chain reset.  Reserved: 0 traps uninitialized.
ARCHIVE_CHALLENGE_VERSION = 1

assert 0 <= ARCHIVE_BURN_REDIRECT_PCT <= 100, (
    "ARCHIVE_BURN_REDIRECT_PCT must be in [0, 100]"
)
assert ARCHIVE_CHALLENGE_INTERVAL > 0
assert ARCHIVE_PROOFS_PER_CHALLENGE > 0
assert ARCHIVE_REWARD > 0
assert ARCHIVE_SUBMISSION_WINDOW > 0
assert ARCHIVE_CHALLENGE_K > 0, "ARCHIVE_CHALLENGE_K must be positive"
assert ARCHIVE_WITHHOLD_TIERS[0] == 0, (
    "first withhold tier must be 0% (clean validator pays nothing)"
)
assert ARCHIVE_WITHHOLD_TIERS[-1] == 100, (
    "last withhold tier must be 100% (full withhold at max strikes)"
)
assert all(0 <= t <= 100 for t in ARCHIVE_WITHHOLD_TIERS), (
    "every withhold tier must be in [0, 100]"
)
assert all(
    ARCHIVE_WITHHOLD_TIERS[i] <= ARCHIVE_WITHHOLD_TIERS[i + 1]
    for i in range(len(ARCHIVE_WITHHOLD_TIERS) - 1)
), "withhold tiers must be monotonically non-decreasing"
assert ARCHIVE_BOOTSTRAP_GRACE_BLOCKS > 0, (
    "bootstrap grace must be positive"
)
assert 0 < ARCHIVE_AGE_SKEW_FRACTION < 1, (
    "ARCHIVE_AGE_SKEW_FRACTION must be in (0, 1)"
)
assert ARCHIVE_MISS_DECAY_STREAK > 0, (
    "ARCHIVE_MISS_DECAY_STREAK must be positive — "
    "1 would make decay equivalent to the old per-epoch rule"
)


def is_archive_challenge_block(block_number: int) -> bool:
    """True iff this block height fires an archive-custody challenge.

    Same shape as is_state_root_checkpoint_block: positive multiples of
    ARCHIVE_CHALLENGE_INTERVAL, with genesis (0) excluded — there is
    no historical block to challenge over at height 0.
    """
    if block_number <= 0:
        return False
    return (block_number % ARCHIVE_CHALLENGE_INTERVAL) == 0


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

# Partial divestment: the founder's initial stake is drained DOWN TO
# this floor, not to zero.  Sized to be "one of the bigger players but
# not dominant" post-bootstrap.  The founder can still voluntarily
# unstake this floor later via an UnstakeTransaction; no protocol
# mechanism drains below it.
#
# Rationale:
#   * Preserves a meaningful founder stake commensurate with the
#     effort of bootstrapping the chain.
#   * Keeps the floor well below any individual quorum threshold so
#     the founder can never single-handedly block consensus.
#   * Floor is a CONSENSUS CONSTANT — changing it is a hard fork.
#
# The legacy value (1M) was sized against a 1B GENESIS_SUPPLY; after
# the 1B→140M supply rebase the relative weight of the routed-to-
# treasury 25% share climbed and the 94M-burn schedule became
# co-complicit in a governance-captured-treasury outcome.  The
# post-retune values (floor=20M, burn=95%, treasury=5%) are the
# correct sizing for 140M supply — founder ends with 5M liquid + 20M
# stake = 25M (~14% of supply), dominant-but-not-decisive.  Activation
# gated by SEED_DIVESTMENT_RETUNE_HEIGHT below.  Pre-activation the
# legacy values apply byte-for-byte.
SEED_DIVESTMENT_RETAIN_FLOOR = 1_000_000  # LEGACY — see get_seed_divestment_params
# The founder's initial stake is divested DOWN TO this floor, not to zero.
SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE = 20_000_000
SEED_DIVESTMENT_BURN_BPS_POST_RETUNE = 9500       # 95% burn after retune
SEED_DIVESTMENT_TREASURY_BPS_POST_RETUNE = 500    # 5% treasury after retune
assert (
    SEED_DIVESTMENT_BURN_BPS_POST_RETUNE
    + SEED_DIVESTMENT_TREASURY_BPS_POST_RETUNE
    == 10_000
)

# Activation height for the seed-divestment retune hard fork.
# Operators MUST replace this placeholder with a concrete coordinated-
# fork height BEFORE BOOTSTRAP_END_HEIGHT = 105_192; otherwise the
# first divestment block fires under old-schedule terms and the
# network cannot uniformly transition.  Placeholder matches the
# convention used by the three prior forks (50_000).
SEED_DIVESTMENT_RETUNE_HEIGHT = 72_000  # Tier 3

# Seed-divestment lottery-redistribution hard fork.
#
# The retune (above) fixed the TREASURY concentration problem but
# still routed 95% of divested founder stake to BURN — i.e. out of
# circulation.  Even with deeper burn the founder ends at ~93%
# consensus weight because non-founder wallets don't grow.
#
# The redistribution fork redirects the 95% "burn" share to:
#   50% burn
#   5% treasury (unchanged)
#   45% lottery redistribution — accumulates in SupplyTracker.lottery_prize_pool
#                                and is paid out to non-founder wallets via
#                                the existing reputation-weighted lottery.
#
# Expected end state (moderate sybil resistance): founder consensus
# weight drops from ~93% to ~60-75% as real tokens flow into
# non-founder wallets.
#
# Activation-gated at SEED_DIVESTMENT_REDIST_HEIGHT.  Must activate
# BEFORE BOOTSTRAP_END_HEIGHT = 105_192 or the first divestment block
# fires under RETUNE-era terms with no lottery share.  Placeholder
# matches the convention used by prior forks (50_000); operators
# coordinate REDIST >= RETUNE so the fork schedule is monotonic.
SEED_DIVESTMENT_BURN_BPS_POST_REDIST = 5000       # 50% burn
SEED_DIVESTMENT_TREASURY_BPS_POST_REDIST = 500    # 5% treasury (unchanged vs retune)
SEED_DIVESTMENT_LOTTERY_BPS_POST_REDIST = 4500    # 45% lottery — NEW mechanism
assert (
    SEED_DIVESTMENT_BURN_BPS_POST_REDIST
    + SEED_DIVESTMENT_TREASURY_BPS_POST_REDIST
    + SEED_DIVESTMENT_LOTTERY_BPS_POST_REDIST
    == 10_000
)

SEED_DIVESTMENT_REDIST_HEIGHT = 74_000            # Tier 3

# Operators MUST coordinate REDIST at or after RETUNE — REDIST is a
# LATER fork that extends the retune policy.  Activating REDIST before
# RETUNE would leave the divestment mechanism in an undefined
# intermediate state (post-redist bps against pre-retune floor).  Load-
# time assertion guards against operator mis-setting.
assert SEED_DIVESTMENT_REDIST_HEIGHT >= SEED_DIVESTMENT_RETUNE_HEIGHT, (
    "REDIST fork must land at or after RETUNE fork"
)


def get_seed_divestment_params(
    block_height: int,
) -> tuple[int, int, int, int]:
    """Return (retain_floor, burn_bps, treasury_bps, lottery_bps).

    Hard-fork-gated three-era schedule:
      * pre-RETUNE: legacy 1M floor, 75% burn, 25% treasury, 0% lottery.
      * RETUNE-era (RETUNE <= h < REDIST): 20M floor, 95% burn,
        5% treasury, 0% lottery.
      * REDIST-era (h >= REDIST): 20M floor, 50% burn, 5% treasury,
        45% lottery.

    The fourth element (lottery_bps) is the share of each divestment
    step's divest_amount that accumulates in
    ``SupplyTracker.lottery_prize_pool`` for later distribution via
    the reputation-weighted lottery.  Zero in both legacy schedules
    so byte-for-byte preservation is trivial.

    Used by both the apply path (_apply_seed_divestment) and the sim
    path (compute_post_state_root) so the two remain in lockstep
    across the activation boundaries.
    """
    if block_height >= SEED_DIVESTMENT_REDIST_HEIGHT:
        return (
            SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE,
            SEED_DIVESTMENT_BURN_BPS_POST_REDIST,
            SEED_DIVESTMENT_TREASURY_BPS_POST_REDIST,
            SEED_DIVESTMENT_LOTTERY_BPS_POST_REDIST,
        )
    if block_height >= SEED_DIVESTMENT_RETUNE_HEIGHT:
        return (
            SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE,
            SEED_DIVESTMENT_BURN_BPS_POST_RETUNE,
            SEED_DIVESTMENT_TREASURY_BPS_POST_RETUNE,
            0,
        )
    return (
        SEED_DIVESTMENT_RETAIN_FLOOR,
        SEED_DIVESTMENT_BURN_BPS,
        SEED_DIVESTMENT_TREASURY_BPS,
        0,
    )

# Staking
#
# Unbonding period — how many blocks a validator's queued unstake
# sits in the pending queue before the tokens become spendable.  The
# pending balance is slashable; the spendable balance is not.  Thus
# the unbonding period MUST be at least as long as the window during
# which slashing evidence for a past offense is still actionable,
# otherwise a malicious validator can equivocate, immediately queue
# an unstake, wait for the unbond to mature, withdraw, and be
# judgment-proof when slow evidence (finality double-votes,
# censorship-receipt evidence) finally lands on chain.
#
# The original ``UNBONDING_PERIOD = 1_008`` (~7 days at 600 s/block)
# was SHORTER than ``EVIDENCE_EXPIRY_BLOCKS = 2_016`` (~14 days),
# opening a ~7-day slash-evasion window.  The post-extension value
# is derived from the evidence-window constants (see the
# ``UNBONDING_PERIOD_POST_EXTENSION`` block lower in this file,
# defined AFTER ``EVIDENCE_EXPIRY_BLOCKS`` and
# ``EVIDENCE_MATURITY_BLOCKS``) and activated at
# ``UNBONDING_PERIOD_EXTENSION_HEIGHT``.
#
# The module-level name ``UNBONDING_PERIOD`` binds to the
# post-extension value so callers that read the bare constant
# without threading block height see the SAFE (longer) window.
# Consensus-critical call sites thread block height and call
# ``get_unbonding_period(block_height)`` which returns the legacy
# value pre-activation so in-flight unstakes and historical replay
# produce identical release_block arithmetic.
UNBONDING_PERIOD_LEGACY = 1_008      # pre-fork value; kept for activation gate

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

# Attestable submission receipts — gossip-layer censorship defense.
#
# Consensus-layer forced-inclusion (see FORCED_INCLUSION_*) punishes a
# proposer that drops a tx from its own block, BUT only if the tx is
# already in the proposer's mempool.  A captured gossip neighborhood
# that silently refuses to relay a user's tx bypasses the whole
# mechanism — no proposer ever sees the tx, so no consensus rule is
# broken.
#
# Attestable submission receipts close the gap: when a user submits a
# tx via a validator's public /submit endpoint, the validator signs a
# receipt attesting "I received this tx_hash at height H."  If the
# validator subsequently fails to include the tx (and doesn't relay
# it so someone else does) within the grace window, the user can
# publish the receipt as slashable evidence on-chain.
#
# Two-phase slashing (critical — see
# `messagechain/network/submission_receipt.py` +
# `messagechain/consensus/censorship_evidence.py` for the authoritative
# design + security analysis):
#   1. Accuser posts CensorshipEvidenceTx (pays MIN_FEE).
#   2. Evidence is recorded in pending state, NOT yet applied.
#   3. Accused validator has EVIDENCE_MATURITY_BLOCKS (defined below) to
#      void the evidence by producing any block that includes the
#      receipted tx.
#   4. If the window elapses with no inclusion, slash fires:
#      CENSORSHIP_SLASH_BPS of stake is BURNED (not paid to accuser,
#      to prevent forge-for-profit).
#
# Why burn rather than pay the accuser: a payer-funded attack could
# forge receipts (if WOTS+ was ever broken) and profit from the
# slash.  Burning means the accuser's only reward is "this validator
# no longer censors me" — a public good, not a private profit.
#
# Timing constants (EVIDENCE_INCLUSION_WINDOW, EVIDENCE_MATURITY_BLOCKS,
# EVIDENCE_EXPIRY_BLOCKS, CENSORSHIP_SLASH_BPS) are defined together in
# the "Attestable submission receipts" block farther down, calibrated
# for BLOCK_TIME_TARGET=600s.  Don't duplicate them here.
SUBMISSION_FEE = MIN_FEE              # anti-spam; paid to validator regardless of inclusion
RECEIPT_VERSION = 1                   # on-wire version of SubmissionReceipt
# Acceptance set for validate_receipt_version above — same
# widen-by-data-edit shape as _ACCEPTED_SIG_VERSIONS.  During a
# RECEIPT_VERSION=2 rollout this becomes frozenset({1, 2}); after the
# migration window the old value is removed.
_ACCEPTED_RECEIPT_VERSIONS: frozenset[int] = frozenset({RECEIPT_VERSION})
# NOTE: the actual per-validator receipt-signing tree is
# RECEIPT_SUBTREE_HEIGHT (defined further down, currently 16).  An
# earlier RECEIPT_MERKLE_TREE_HEIGHT=24 constant lived here but was
# never referenced — auditors kept asking "why two receipt-tree
# heights?" so it was removed in the iter-1 hardening audit.  Don't
# reintroduce it; configure receipt tree sizing via RECEIPT_SUBTREE_HEIGHT.

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

# ─────────────────────────────────────────────────────────────────────
# Coverage-divergence inactivity leak — defense against 1/3-cartel
# selective withholding of AttesterMempoolReports for inclusion lists.
#
# Threat: a coordinated minority of validators can defeat the
# inclusion-list censorship-resistance lever by silently NOT reporting
# specific tx_hashes from their gossiped AttesterMempoolReports.
# Because the chain still finalizes (the cartel attests to BLOCKS
# normally), the existing finalization-based inactivity leak doesn't
# trigger.  No inclusion list ever forms for the censored txs; the
# proposer-side slashing-bearing path never engages.
#
# Defense: when an inclusion list DOES form (proving 2/3+ of stake saw
# the listed txs), every active-set attester whose mempool reports
# lacked any listed tx has their per-attester "coverage_misses"
# counter incremented.  An attester whose reports covered all listed
# txs resets to zero.  Penalties are quadratic-in-misses, mirroring
# the existing finalization-based inactivity leak's shape.
#
# Calibration (against a default validator stake of 10**12 tokens —
# the test-suite default; production stake distributions are
# heterogeneous, so these are policy values not invariants):
#
#   * COVERAGE_LEAK_BASE_PENALTY = 4 + COVERAGE_LEAK_QUOTIENT = 2*10**6
#     produce per-cycle penalty = stake * 4 * misses^2 / 2_000_000
#     once misses > COVERAGE_LEAK_ACTIVATION_MISSES.
#   * Activation = 4 → at most 4 consecutive honest mempool divergences
#     are free.  False-positive defense rests primarily on the 2/3-
#     quorum threshold (the inclusion-list mechanism itself), but the
#     buffer guards against transient gossip disruption.
#   * 32-cycle persistent withholding drains roughly 2.3% of stake
#     (target: "~5%"; the calibration favours the 128-cycle target
#     because the 32- and 128-cycle "ideal" rates conflict for any
#     pure quadratic — see [tests/test_coverage_leak.py] for the
#     loose-bound assertions).
#   * 128-cycle persistent withholding drains roughly 76% of stake.
#     The cartel falls below the 1/3 threshold needed to make their
#     withholding matter long before the stake hits zero.
#
# COVERAGE_LEAK_WINDOW_BLOCKS is a defensive observation cap rather
# than a hard cycle bound — counter values larger than this would
# imply a withholder with stake far above the calibration target,
# which is fine; the cap exists to keep the per-attester counter from
# growing unboundedly across pathological forks.
COVERAGE_LEAK_BASE_PENALTY = 4
COVERAGE_LEAK_QUOTIENT = 2_000_000
COVERAGE_LEAK_ACTIVATION_MISSES = 4
COVERAGE_LEAK_WINDOW_BLOCKS = 32

MAX_FINALITY_VOTES_PER_BLOCK = 200    # DoS guard on block-size expansion via finality votes
# Per-block count caps on the remaining consensus-path lists.  The fee
# market only prices mempool-submitted user txs; attestations,
# validator_signatures, governance_txs, authority_txs, and censorship-
# evidence txs are inserted by the block proposer directly and have no
# fee counterparty (the proposer would be paying fees to itself).  Hard
# count caps are therefore the structural ceiling — permanence-scope
# data cannot be allowed to grow without bound.
#
# Sizing rationale:
#   * Attestations and validator_signatures scale with the validator
#     set — mirror MAX_FINALITY_VOTES_PER_BLOCK = 200 as the cap.
#   * Governance and authority txs are rare administrative events; a
#     tight cap bounds worst-case block bloat without constraining
#     normal usage.
#   * Censorship-evidence txs should not dominate a block — 16 per
#     block is ample for legitimate evidence traffic given the
#     submission-receipt maturity window.
MAX_ATTESTATIONS_PER_BLOCK = 200
MAX_VALIDATOR_SIGNATURES_PER_BLOCK = 200
MAX_GOVERNANCE_TXS_PER_BLOCK = 16
MAX_AUTHORITY_TXS_PER_BLOCK = 16
MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK = 16
# Per-tx byte ceiling for authority txs (SetAuthorityKey / Revoke /
# KeyRotation).  Each authority tx is structurally bounded by its
# ~2.8 KB WOTS+ signature; this cap is a safety rail that catches
# malformed or future-incompatible variants before they land as
# unpriced permanent data.  Headroom above the real ~2.8 KB size
# keeps legitimate txs safe while closing the oversize escape hatch.
MAX_AUTHORITY_TX_BYTES = 3_200

# ─────────────────────────────────────────────────────────────────────
# Release-announce transaction (ReleaseAnnounceTransaction)
# ─────────────────────────────────────────────────────────────────────
# Threshold multi-sig'd "new release available" manifest committed on-
# chain so operators learn about upgrades through the same gossip path
# as blocks themselves, rather than via a centralized update server
# that a state actor could compel, block, or poison.  The tx records a
# version tag, per-platform binary hashes, and an optional release
# notes URI — nodes surface it to operators but NEVER auto-download or
# auto-apply.  Rotation of the signing set is a hard fork (consistent
# with "no permissioned validators" plus "crypto agility" — signers
# are protocol-defined, not governance-elected).
#
# RELEASE_KEY_ROOTS: Tuple of 32-byte WOTS+ Merkle-tree public keys
# for the authorized release signers.  Default is an empty tuple —
# the real keys are seeded via a hard fork once the multi-party key
# ceremony completes.  Until then, `verify()` on any ReleaseAnnounce
# tx returns False (no signer index is in range of an empty tuple),
# so the tx type is inert on mainnet without coordination.
#
# RELEASE_THRESHOLD: M-of-N unique signers required.  Default 3-of-5
# when seeded.  Picked so a single compromised or lost key cannot
# issue a release (threshold > 1) and the ceremony survives two
# offline signers (threshold <= N - 2).
RELEASE_KEY_ROOTS: tuple[bytes, ...] = ()
RELEASE_THRESHOLD: int = 3

# Per-field DoS bounds.  A release tx is broadcast through the same
# authority-tx slot as SetAuthorityKey/Revoke/KeyRotation, so loose
# string/map lengths would translate directly into unpriced permanent
# storage growth.  Caps are generous for real content but cheap to
# enforce at deserialize time.
RELEASE_ANNOUNCE_MAX_URI_LEN = 256
RELEASE_ANNOUNCE_MAX_PLATFORMS = 16
RELEASE_ANNOUNCE_VERSION_MAX_LEN = 32

# Per-tx byte ceiling specifically for ReleaseAnnounceTransaction.
# A valid tx carries up to RELEASE_THRESHOLD..N signatures (each
# ~2.8 KB WOTS+), plus the manifest body.  5 signatures * ~3 KB +
# headroom = 20 KB.  This is larger than MAX_AUTHORITY_TX_BYTES
# (3.2 KB) because release txs carry multi-sig, not single-sig.
MAX_RELEASE_ANNOUNCE_TX_BYTES = 20_480
# A finality vote for a block older than FINALITY_VOTE_MAX_AGE blocks is
# rejected — prevents spam gossip of votes targeting ancient blocks that
# are already beyond the rewrite horizon anyway.  10 × FINALITY_INTERVAL
# = 1000 blocks (~7 days at 600s) is comfortably larger than any
# realistic gossip-lag window and still bounds the lookback.
FINALITY_VOTE_MAX_AGE_BLOCKS = 10 * FINALITY_INTERVAL

# Witness separation — split block storage into state-transition data
# and witness data (WOTS signatures + Merkle auth paths).  After
# finalization, ~97% of a block's bytes are witness data that serves
# only auditability, not consensus safety.  Nothing is ever deleted —
# witness data moves to a separate storage tier.
WITNESS_SEPARATION_ENABLED = True       # feature gate
WITNESS_RETENTION_BLOCKS = 200          # keep witnesses in main storage for this many blocks beyond finality
# Opt-in auto-separation: when True, ChainDB.auto_separate_finalized_
# witnesses moves signatures of old finalized blocks from inline
# storage to the side-table on every call.  Default False so the
# existing block-read surface (callers that don't pass
# include_witnesses=True) is unchanged on upgrade.  Operators enable
# this once they've verified their block-consumer paths either
# tolerate stripped blocks or opt into witnesses explicitly.
# Nothing is deleted in either mode — separation only moves bytes.
WITNESS_AUTO_SEPARATION_ENABLED = False


# Governance — on-chain voting for protocol/codebase changes
GOVERNANCE_VOTING_WINDOW = 1_008      # blocks (~7 days at 600s/block)
# Sanity floor: at 600s/block, 144 blocks is ~1 day.  A misconfigured 0
# or 1 would close proposals before honest validators could even see
# them — reject such configurations at import time rather than failing
# silently at governance time.
assert GOVERNANCE_VOTING_WINDOW >= 144, (
    "GOVERNANCE_VOTING_WINDOW must be >= 144 blocks (~1 day at 600s/block)"
)
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
# RPC_AUTH_TOKEN: operator-pinned token, or None to auto-generate.
# Without this env-var the server auto-generates a fresh random token on
# every startup — which rotates the admin token and invalidates all
# external client / deployment tooling.  Setting
# MESSAGECHAIN_RPC_AUTH_TOKEN pins the token across restarts so
# operator tooling keeps working.  The value is treated as a secret and
# is never logged.
RPC_AUTH_TOKEN: str | None = _profile_str(
    "MESSAGECHAIN_RPC_AUTH_TOKEN", default=None,
)  # auto-generated if None

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

# Dedicated per-IP budget for submissions that opt into a
# SignedRejection response (X-MC-Request-Receipt: 1).  A signed
# rejection consumes one WOTS+ leaf from the validator's receipt
# subtree.  At RECEIPT_SUBTREE_HEIGHT=16 (65k leaves) the plain
# SUBMISSION_RATE_LIMIT cap of 2/sec would let one attacker drain
# the whole subtree in ~9 hours from a single IPv4, or minutes with
# cheap IPv6 /64 rotation.  After exhaustion the censorship-
# evidence framework disables itself until an on-chain subtree
# rotation lands (+ ~9min keygen on an e2-small).
#
# This dedicated budget caps rejection issuance FAR below the base
# submission rate — honest clients who genuinely need a rejection
# for slash evidence get one; attackers get a plain 400 and zero
# leaves burned.  Chosen so that a single /64 can provoke at most
# SUBMISSION_REJECTION_BURST + sustained_rate * time leaves; burst
# tokens replenish slowly.  When the budget is exhausted the HTTP
# handler silently drops the header rather than 429'ing the whole
# request — the submission still processes.
SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC = 0.05  # 1 per 20 seconds steady
SUBMISSION_REJECTION_BURST = 3                   # up to 3 rejection proofs immediately

# ─────────────────────────────────────────────────────────────────────
# Attestable submission receipts + censorship-evidence slashing
# ─────────────────────────────────────────────────────────────────────
# Validators issue signed "submission receipts" committing to having
# accepted a tx for inclusion. If the receipted tx is NOT included in
# any block within EVIDENCE_INCLUSION_WINDOW blocks, anyone can submit
# a CensorshipEvidenceTx binding (receipt, window) as proof of
# censorship.  Evidence enters a pending-matrix for a challenge window
# during which the accused proposer can include the tx on-chain and
# void the evidence; if the window closes with the tx still missing,
# the validator is slashed CENSORSHIP_SLASH_BPS of their stake.
#
# This is deliberately LESS SEVERE than the 100%-burn slashes for
# equivocation / double-attestation, because censorship is a weaker
# offense than corrupting consensus state itself — see the design
# discussion in consensus/slashing.py.  A partial slash gives honest
# validators an economic nudge to include what they receipt without
# pushing a temporary mistake to existential penalty.
CENSORSHIP_SLASH_BPS = 1000  # 10% of stake, in basis points (10_000 = 100%)

# Cross-check: inclusion-list violations and submission-receipt
# censorship are both "soft censorship" offenses and intentionally
# carry the same slash percentage.  Catching drift here at import time
# prevents a future tweak from accidentally desyncing the two paths.
assert INCLUSION_VIOLATION_SLASH_BPS == CENSORSHIP_SLASH_BPS, (
    "INCLUSION_VIOLATION_SLASH_BPS must equal CENSORSHIP_SLASH_BPS — "
    "both are soft-censorship slashes and should move together"
)

# Blocks after a receipt's commit_height by which the receipted tx
# must appear on-chain.  If the tx is not included within this window,
# the receipt becomes evidence-eligible.  Generous enough to absorb
# fork-choice churn yet short enough that a censor cannot stall
# indefinitely.
EVIDENCE_INCLUSION_WINDOW = 32

# Maximum age (blocks) of a receipt at evidence-submission time.
# Beyond this, evidence is stale and rejected at mempool admission.
#
# Value must dominate MEMPOOL_TX_TTL so a censoring validator can't
# simply stall a tx past the evidence window while the user still
# sees "pending" in their UX for the full mempool TTL.  Previous 512
# blocks (~3.5d at 600s) was less than MEMPOOL_TX_TTL of 14d: a
# validator issued a receipt, dropped the tx, waited 4d past the
# evidence window, and voided all accountability while the user still
# sat on a "pending" UI for another 10 days (iter 6 M3 finding).
#
# 2016 blocks = 14 days at BLOCK_TIME_TARGET=600s - matches the
# MEMPOOL_TX_TTL window 1:1 so there is no gap where receipts are
# enforceable but dropped txs aren't.  Raised from 512 (iter 7).
EVIDENCE_EXPIRY_BLOCKS = 2016

# Maturity delay (blocks) between evidence admission and actual slash
# application.  During this window, the accused proposer (or any other
# party) can include the receipted tx in a block, which voids the
# pending evidence.  Prevents griefing: an attacker who files evidence
# against a proposer who was about-to-include a tx does not land the
# slash, because the proposer's good-faith inclusion cancels the
# pending evidence before maturity.
EVIDENCE_MATURITY_BLOCKS = 16

# ─────────────────────────────────────────────────────────────────────
# Witnessed submission — closes the silent-TCP-drop censorship gap.
# ─────────────────────────────────────────────────────────────────────
# Today's signed-rejection slashing catches validators who answer an
# HTTPS submission with a bogus rejection reason.  It does NOT catch
# validators who simply hang up the TCP connection silently — the
# client has no proof the validator received the submission, so no
# on-chain evidence can be filed.
#
# Witnessed submission closes this: the client opts in (paying a small
# fee surcharge), signs a SubmissionRequest blob and sends it to the
# target validator AND gossips the digest to a witness topic.  The
# target validator MUST publish a signed SubmissionAck within
# WITNESS_RESPONSE_DEADLINE_BLOCKS.  If they don't, peers who saw the
# witness gossip submit a NonResponseEvidenceTx and the validator gets
# slashed WITNESS_NON_RESPONSE_SLASH_BPS of stake.

# Surcharge above MIN_FEE that an opt-in client pays to use the
# witnessed-submission path.  Small enough that legitimate users in
# coercion contexts can afford it; large enough that the witness
# topic's bandwidth is paid for and not griefable.
WITNESS_SURCHARGE = MIN_FEE * 2

# Number of blocks after a witness gossip's observed_height by which
# the target validator MUST publish a SubmissionAck.  Beyond this,
# peers can file NonResponseEvidenceTx.  Generous enough to absorb
# block-time jitter, short enough that silent censorship is not
# economic.
WITNESS_RESPONSE_DEADLINE_BLOCKS = 8

# Minimum number of distinct witness signatures required to admit a
# NonResponseEvidenceTx.  Q-of-N witness model — a few honest peers
# seeing the gossip is enough to slash, no consensus-grade BFT
# reliability required from the witness path.
WITNESS_QUORUM = 3

# Per-validator slash percentage applied when a NonResponseEvidenceTx
# is admitted.  Set smaller than CENSORSHIP_SLASH_BPS (10%) because a
# silent drop is less aggressive censorship than admit-then-drop —
# 5% still hurts but leaves room to escalate via repeated evidence.
WITNESS_NON_RESPONSE_SLASH_BPS = 500  # 5% of stake

# Maximum number of (request_hash) entries a proposer may embed in
# their block as the "acks_observed_this_block" list.  Caps block
# size so the witness ack registry cannot bloat block bandwidth.
MAX_ACKS_PER_BLOCK = 256

# How long the in-memory WitnessObservationStore keeps observations
# before pruning.  Bound on memory at the cost of forgetting older
# obligations — anything older than this is past the
# WITNESS_RESPONSE_DEADLINE_BLOCKS window anyway, so evidence cannot
# be assembled from it.
WITNESS_OBSERVATION_RETENTION_BLOCKS = 64

# ─────────────────────────────────────────────────────────────────────
# Unbonding period — derived from the evidence-window invariant.
# ─────────────────────────────────────────────────────────────────────
# The pending-unstake queue holds tokens in a slashable-but-locked
# state.  To close the slash-evasion window (equivocate → unstake →
# wait-out-unbond → withdraw → evidence arrives too late), the
# unbonding period must cover the longest window during which slash
# evidence is still actionable, plus the maturity delay between
# evidence admission and slash application, plus a small clock-skew
# margin.
#
# Invariant (enforced in tests/test_unbonding_evidence_invariant.py):
#     UNBONDING_PERIOD_POST_EXTENSION
#         >= EVIDENCE_EXPIRY_BLOCKS + EVIDENCE_MATURITY_BLOCKS
#
# Derivation (defined AFTER EVIDENCE_* so future tweaks stay coherent —
# bump EVIDENCE_EXPIRY_BLOCKS and the unbonding period follows):
#     2016 + 16 + 144 = 2176 blocks  (~15.1 days at 600 s/block)
#
# The +144 (1 day) margin absorbs block-time jitter and any future
# slash-evidence window that gets added without remembering to touch
# this file.  NOTE: ``ATTESTER_ESCROW_BLOCKS = 12_960`` (~90 days) is
# a SEPARATE bootstrap-era escrow-slash window — the escrow itself
# burns on slash via ``_escrow.slash_all()`` and does NOT require
# active stake in the pending queue, so it doesn't raise the
# unbonding-period floor.
UNBONDING_PERIOD_POST_EXTENSION = (
    EVIDENCE_EXPIRY_BLOCKS + EVIDENCE_MATURITY_BLOCKS + 144
)

# ═════════════════════════════════════════════════════════════════════
# FORK SCHEDULE — operator deployment reference
# ═════════════════════════════════════════════════════════════════════
#
# All shipped hard forks and their canonical activation ordering.
# Every ``*_HEIGHT`` constant below is a placeholder; OPERATORS MUST
# rewrite these to concrete coordinated values before deploy.  The
# published schedule preserves all inter-fork dependencies and spaces
# forks ≥1,000 blocks apart so each is observable and debuggable in
# isolation.  All heights land before ``BOOTSTRAP_END_HEIGHT = 105,192``
# so fork activity stays inside the bootstrap window.
#
#   Tier 1 — Safety defenses (no dependencies):
#     50,000  UNBONDING_PERIOD_EXTENSION_HEIGHT
#     52,000  TREASURY_CAP_TIGHTEN_HEIGHT
#     54,000  FINALITY_VOTE_CAP_HEIGHT
#     56,000  SEED_STAKE_CEILING_HEIGHT
#
#   Tier 2 — Economic re-sizing:
#     60,000  MIN_STAKE_RAISE_HEIGHT
#     62,000  LOTTERY_BOUNTY_RAISE_HEIGHT
#     64,000  FEE_INCLUDES_SIGNATURE_HEIGHT
#
#   Tier 3 — Treasury + divestment (REDIST depends on RETUNE):
#     68,000  TREASURY_REBASE_HEIGHT
#     72,000  SEED_DIVESTMENT_RETUNE_HEIGHT
#     74,000  SEED_DIVESTMENT_REDIST_HEIGHT
#
#   Tier 4 — Reward mechanics (depend on MIN_STAKE raise):
#     78,000  ATTESTER_REWARD_SPLIT_HEIGHT
#     80,000  ATTESTER_FEE_FUNDING_HEIGHT
#     82,000  FINALITY_REWARD_FROM_ISSUANCE_HEIGHT
#     84,000  ATTESTER_REWARD_CAP_HEIGHT
#     86,000  ATTESTER_CAP_FIX_HEIGHT
#
#   Tier 5 — Deflation defense:
#     90,000  DEFLATION_FLOOR_HEIGHT      (v1: 2× reward, legacy)
#     92,000  DEFLATION_FLOOR_V2_HEIGHT   (v2: fee-responsive rebate)
#
#   Tier 6 — Sybil defense (depends on MIN_STAKE raise):
#     96,000  VALIDATOR_REGISTRATION_BURN_HEIGHT
#
#   Tier 7 — Fee-model simplification:
#     98,000  FLAT_FEE_HEIGHT  (flat per-tx floor; retires quadratic)
#
# Dependency invariants (enforced via load-time asserts where
# declared):
#   * SEED_DIVESTMENT_REDIST_HEIGHT  >= SEED_DIVESTMENT_RETUNE_HEIGHT
#   * VALIDATOR_REGISTRATION_BURN_HEIGHT > MIN_STAKE_RAISE_HEIGHT
#   * All heights < BOOTSTRAP_END_HEIGHT (105,192)
#   * All heights > current_tip_height + 50,000 at deploy time
#     (honest-node upgrade runway)
#
# DEPLOY CHECKLIST
#   1. Confirm current tip leaves ≥50,000 blocks of runway before Tier 1.
#   2. If runway is short, shift the whole schedule upward by a constant
#      — preserve ordering and spacing.
#   3. Edit every ``*_HEIGHT`` constant below to match the schedule.
#   4. Run ``python -m unittest discover tests/`` — must stay fully green.
#   5. Coordinate binary rollout: all honest validators on the fork-aware
#      build before the earliest activation height.
# ═════════════════════════════════════════════════════════════════════

# Activation height for the unbonding-period extension (hard fork).
# Pre-activation, ``get_unbonding_period(h)`` returns the legacy
# 1008-block value so historical replay is deterministic.  At/after
# activation, newly initiated unstakes use the post-extension value.
# In-flight unstakes queued before activation keep their originally
# scheduled ``release_block`` — we never rewrite pending entries.
#
# Per the FORK SCHEDULE above: Tier 1, target 50,000.  Current
# value is a placeholder — operators MUST replace with a concrete
# coordinated-fork height before deploying to mainnet.
UNBONDING_PERIOD_EXTENSION_HEIGHT = 50_000  # Tier 1

# Module-level alias: the SAFE value.  Callers that read
# ``UNBONDING_PERIOD`` without threading block height get the
# post-extension period — this is the right default for anti-bloat
# and config-inspection tooling.  Consensus-critical code paths that
# must match historical chain state at a specific block height MUST
# call ``get_unbonding_period(block_height)`` instead of this bare
# constant.
UNBONDING_PERIOD = UNBONDING_PERIOD_POST_EXTENSION


def get_unbonding_period(block_height: int) -> int:
    """Return the unbonding period in effect at ``block_height``.

    Hard-fork-gated: pre-activation returns the legacy 1008-block
    value so pre-fork chain state is reproducible; at/after
    activation returns the post-extension value derived from the
    evidence-window constants.

    Callers that queue a new unstake MUST pass the CURRENT block
    height (the height of the block that applies the unstake tx) so
    the release_block arithmetic uses the period that was in effect
    at unstake time.  Re-computing with ``self.height`` at a later
    moment would retroactively extend in-flight unstakes, which is
    explicitly not what we want.
    """
    if block_height >= UNBONDING_PERIOD_EXTENSION_HEIGHT:
        return UNBONDING_PERIOD_POST_EXTENSION
    return UNBONDING_PERIOD_LEGACY


# Dedicated WOTS+ subtree height for receipt-signing.  Separate from
# the block-signing tree (MERKLE_TREE_HEIGHT) so receipt traffic cannot
# burn leaves that the proposer needs for block production.
#
# Height 16 (65K leaves) matches the block-signing tree.  Receipt-
# throughput budget: at MAX_TXS_PER_BLOCK=20 and BLOCK_TIME_TARGET=600s,
# full-capacity throughput is ~2880 admitted txs/day network-wide.
# A validator issuing one receipt per admitted tx exhausts 65K leaves
# in ~22 days (65536 / 2880).  At early-phase volume (dozens of txs
# per day), the same tree lasts years.  Operators MUST plan to rotate
# the receipt subtree via SetReceiptSubtreeRootTransaction before leaf
# exhaustion at sustained high throughput; exhaustion-warning logs
# fire at 80% and 95% usage (see _maybe_warn_exhaustion).  An earlier
# h=24 setting was measured to take ~36 hours of blocking startup
# keygen on a 2-vCPU VM, which is unacceptable as a boot-time op.
# If 65K leaves becomes limiting in steady state, bump this height
# with async keygen machinery added.  Generated lazily on first
# startup and cached to disk.
RECEIPT_SUBTREE_HEIGHT = 16

# Block deserialization size limit — maximum hex-encoded block size
# accepted from peers over the network.  A block with MAX_TXS_PER_BLOCK=20
# transactions each carrying MAX_BLOCK_MESSAGE_BYTES of payload plus WOTS+
# signatures is well under 1MB binary.  We allow 2MB hex (= 1MB binary) as
# a conservative ceiling.  Anything larger is either malicious or a bug on
# the sender side.
MAX_BLOCK_HEX_SIZE = 2_000_000  # 2M hex chars = 1MB binary

# Activation height for charging fee on (message + signature/witness) bytes.
# Before this height, fee covers only the canonical message payload — the
# legacy rule that shipped on mainnet.  At/after this height consensus
# charges the linear + quadratic formula on (message_bytes + signature_bytes),
# so an attacker cannot bulk-flood WOTS+ signatures (~2.7 KB each including
# Merkle auth path) while paying only the payload fee.  Operators MUST
# replace this placeholder with a concrete coordinated-fork height before
# deploying to mainnet; the current value is chosen as "current_height +
# 50_000" headroom so honest nodes have time to upgrade.  Set
# ``MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT`` in systemd/k8s env to pin
# the coordinated-fork height without editing this file — avoids the
# edit-and-redeploy slip that otherwise risks validators diverging on
# consensus at activation.
FEE_INCLUDES_SIGNATURE_HEIGHT = _profile_int(
    "MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT",
    "FEE_INCLUDES_SIGNATURE_HEIGHT",
    64_000,  # Tier 2 of canonical fork schedule (see CLAUDE.md)
)

# Activation height for decoupling attester committee size from the
# reward-pool token budget.  Pre-activation the committee was implicitly
# capped at `attester_pool // ATTESTER_REWARD_PER_SLOT` (== 1 token/slot,
# so committee <= 12 tokens at BLOCK_REWARD=16 and only 3 at the
# BLOCK_REWARD_FLOOR=4 floor — a permanent 3-attester decentralization
# failure once halvings drive reward to the floor).  At/after this
# height the committee is sized by consensus policy
# (`ATTESTER_COMMITTEE_TARGET_SIZE`) and the `attester_pool` is divided
# pro-rata across the full committee; integer-division remainder BURNS.
# If the pool is smaller than the committee, per-slot reward rounds to
# zero and the whole pool burns — the committee still attests for
# finality-weight credit, the reward is a bonus not a gate on
# participation.  Operators MUST replace this placeholder with a
# concrete coordinated-fork height before deploying to mainnet.
ATTESTER_REWARD_SPLIT_HEIGHT = 78_000  # Tier 4

# Target attester committee size post-activation.  Decoupled from the
# per-block reward pool so a floor-era reward budget (3 tokens/block
# under PROPOSER_REWARD_NUMERATOR=1/DENOMINATOR=4 at BLOCK_REWARD_FLOOR=4)
# does not permanently cap the committee at 3 validators.  128 is
# generous enough to accommodate a large active validator set while
# keeping per-slot reward non-trivial in the early issuance regime
# (BLOCK_REWARD=16 → attester_pool=12 → under-pool for the first few
# halvings; see corner-case handling in mint_block_reward).  Not yet
# used pre-activation; the old committee_size derivation continues to
# drive selection until ATTESTER_REWARD_SPLIT_HEIGHT fires.
ATTESTER_COMMITTEE_TARGET_SIZE = 128

# ─────────────────────────────────────────────────────────────────────
# Treasury rebase — one-shot burn + per-epoch spend-rate cap
# ─────────────────────────────────────────────────────────────────────
# When GENESIS_SUPPLY was rebased from 1_000_000_000 to 140_000_000,
# TREASURY_ALLOCATION (40M) went from ~4% to ~28.6% of supply.  Once
# the seed-divestment schedule routes another ~23.5M to the treasury,
# ~91% of post-bootstrap circulating supply sits in a single
# governance-captured pool — an existential censorship-resistance
# failure.  TREASURY_ALLOCATION cannot be changed (it lives in
# genesis state); the fix is a hard-fork burn-down at activation
# height plus a per-epoch spend-rate cap that even a supermajority
# cannot bypass.
#
# At block_height == TREASURY_REBASE_HEIGHT:
#   * TREASURY_REBASE_BURN_AMOUNT (33M) is deducted from the treasury
#     balance and burned (total_supply and total_burned update).
#     Post-burn treasury = 40M - 33M = 7M = 5% of 140M supply.
#   * Fires exactly once per canonical chain history.  The step is
#     idempotent: an adjacent re-apply at the same height is a no-op.
#
# At block_height >= TREASURY_REBASE_HEIGHT:
#   * treasury_spend enforces a cap of TREASURY_MAX_SPEND_BPS_PER_EPOCH
#     (100 bps = 1%) of treasury balance per epoch, measured in
#     TREASURY_SPEND_CAP_EPOCH_BLOCKS (= FINALITY_INTERVAL = 100)
#     block windows.  A second spend in the same epoch that exceeds
#     the remaining budget reverts regardless of governance approval.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.
TREASURY_REBASE_HEIGHT = 68_000  # Tier 3
TREASURY_REBASE_BURN_AMOUNT = 33_000_000  # 40M - 33M = 7M ≈ 5% of 140M
TREASURY_MAX_SPEND_BPS_PER_EPOCH = 100    # LEGACY — see get_treasury_max_spend_bps_per_epoch
TREASURY_SPEND_CAP_EPOCH_BLOCKS = FINALITY_INTERVAL  # 100-block cadence

# Treasury spend-rate cap tightening (hard fork).
#
# The original per-epoch cap of 100 bps (1%) was introduced in the
# treasury-rebase fork as a supermajority-proof ceiling on governance
# spends.  With 525.6 epochs/year (52,560 blocks / 100 blocks per
# epoch) compounding a max-rate spend drains the treasury to
# (1 - 0.01)^526 ≈ 0.5% of starting balance in ~1 year — i.e. the cap
# as written permits a near-total drain inside a year, defeating its
# purpose as a safeguard against a governance-captured treasury.
#
# Post-seed-divestment founder stake is ~14% of supply liquid + ~60%
# pre-retune stake → founder individually approaches the 2/3
# supermajority threshold and IS governance.  The spend-rate cap is
# the last line of defense between founder and treasury, so it must
# survive a year of uninterrupted max-vote governance.
#
# Two-layer cap (both must pass; either binding rejects the spend):
#   1. Per-epoch cap tightens 100 bps -> 10 bps (0.1%).  Annual
#      compounded worst case: (1 - 0.001)^526 ≈ 0.59 → 41% drainable
#      per year on its own.  Still not great; gated by layer 2.
#   2. Absolute annual ceiling TREASURY_MAX_SPEND_BPS_PER_YEAR = 500
#      (5% of the current treasury balance) measured over a rolling
#      52,560-block window (365.25 days at BLOCK_TIME_TARGET=600s).
#      Max drain: 5%/year compounded → treasury halves in ~14 years
#      under continuous max-vote governance, not 1 year.
#
# At block_height >= TREASURY_CAP_TIGHTEN_HEIGHT:
#   * Per-epoch cap reads via get_treasury_max_spend_bps_per_epoch
#     and returns 10 bps instead of 100.
#   * Annual cap is enforced at every treasury_spend.  Pre-activation
#     the annual cap is effectively infinity (disabled); post-
#     activation a spend whose addition to the rolling-window total
#     would exceed 5% of the current treasury balance is rejected.
#
# Operators MUST replace the TREASURY_CAP_TIGHTEN_HEIGHT placeholder
# (50_000) with a concrete coordinated-fork height before deploying
# to mainnet; the placeholder follows the "current_height + 50_000"
# convention shared with the other pending forks.
TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN = 10    # 0.1% per 100-block epoch
TREASURY_MAX_SPEND_BPS_PER_YEAR = 500                 # 5% per rolling-year window
TREASURY_SPEND_CAP_YEAR_BLOCKS = 52_560               # 365 days at 600s (≈1yr)
TREASURY_CAP_TIGHTEN_HEIGHT = 52_000                  # Tier 1


def get_treasury_max_spend_bps_per_epoch(block_height: int) -> int:
    """Return the per-epoch treasury spend cap in effect at ``block_height``.

    Hard-fork-gated: pre-activation returns the legacy 100 bps (1%)
    value so pre-fork chain state is reproducible; at/after activation
    returns the tightened 10 bps (0.1%) value.

    Used by SupplyTracker.treasury_spend at spend time.  Pre-activation
    callers (or callers that pass current_block < activation) get byte-
    identical behavior to the pre-fork cap.
    """
    if block_height >= TREASURY_CAP_TIGHTEN_HEIGHT:
        return TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN
    return TREASURY_MAX_SPEND_BPS_PER_EPOCH


assert TREASURY_REBASE_BURN_AMOUNT < TREASURY_ALLOCATION, (
    "TREASURY_REBASE_BURN_AMOUNT cannot exceed TREASURY_ALLOCATION — "
    "rebase would underflow the genesis treasury."
)
assert TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN < TREASURY_MAX_SPEND_BPS_PER_EPOCH, (
    "post-tighten per-epoch cap must be STRICTLY tighter than legacy"
)
assert TREASURY_MAX_SPEND_BPS_PER_YEAR > 0 and TREASURY_MAX_SPEND_BPS_PER_YEAR <= 10_000, (
    "annual cap must be a positive basis-point value <= 100%"
)
assert TREASURY_SPEND_CAP_YEAR_BLOCKS > TREASURY_SPEND_CAP_EPOCH_BLOCKS, (
    "annual rolling window must cover multiple epochs"
)

# ─────────────────────────────────────────────────────────────────────
# Attester pool fee-funding (hard fork)
# ─────────────────────────────────────────────────────────────────────
# Latent economic failure in the shipped code: at BLOCK_REWARD=16 the
# attester pool is 12 tokens; divided across the 128-member committee
# post-ATTESTER_REWARD_SPLIT_HEIGHT fork, per-slot reward is 12 // 128
# == 0.  Every committee member gets exactly zero per block.  At the
# floor (BLOCK_REWARD=4, pool=3, committee=128) it's still 0.  The
# consensus-critical attestation work is uncompensated.
#
# Fix: redirect half of the base-fee BURN into the attester pool.  At
# MIN_FEE=100 and TARGET_BLOCK_SIZE=10 txs/block, that's ~500 tokens
# flowing to the 128-member committee per block = ~4 tokens/slot.
# Real reward, scales with traffic.
#
# At/after block_height == ATTESTER_FEE_FUNDING_HEIGHT:
#   * Every pay_fee_with_burn call splits base_fee into
#     attester_share = base_fee * ATTESTER_FEE_SHARE_BPS // 10_000
#     and actual_burn = base_fee - attester_share.  Only
#     actual_burn increments total_burned and decrements total_supply;
#     attester_share accrues into a per-block accumulator
#     (SupplyTracker.attester_fee_pool_this_block).
#   * In mint_block_reward the accumulator is added to the existing
#     attester_pool (= reward - proposer_share) before pro-rata
#     division across the committee.  Integer-division remainder
#     still burns — no change to the rounding policy.
#   * The accumulator is reset at the start of every block apply so
#     it never leaks between blocks.
#
# Pre-activation: accumulator always 0; attester pool comes solely
# from issuance as before.  Byte-for-byte identical to current
# behavior.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.  The height
# is independent of other *_HEIGHT forks even though it shares the
# same placeholder value.
ATTESTER_FEE_SHARE_BPS = 5000           # 50% of base-fee burn → attester pool
ATTESTER_FEE_FUNDING_HEIGHT = 80_000  # Tier 4

# ─────────────────────────────────────────────────────────────────────
# Per-entity attester-reward cap per epoch (hard fork)
# ─────────────────────────────────────────────────────────────────────
# Belt-and-suspenders defense limiting any single entity's capture of
# the attester fee+issuance pool.  Attester-fee-funding redirects 50%
# of base-fee burn to the 128-member committee, distributed pro-rata
# across committee seats.  Committee selection is stake-weighted, so
# the largest staker naturally earns a share of the pool proportional
# to their stake; a 42%-stake founder captures ~42% of per-block
# attester revenue.  Concentration drift is slow (rewards flow in
# proportion to existing stake) but external fee-payer outflow still
# favors large stakers, and a raw cap limits naive large-staker
# advantage.
#
# At block_height >= ATTESTER_REWARD_CAP_HEIGHT:
#   * Each FINALITY_INTERVAL-block window is a rolling "epoch" for the
#     purposes of this cap.  SupplyTracker tracks per-entity earnings
#     from the attester pool in a dict reset at every epoch boundary.
#   * A per-entity cap of (attester_pool_this_block *
#     PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH / 10_000 *
#     FINALITY_INTERVAL) tokens/epoch is enforced at credit time.
#     (At attester_pool=500, cap ≈ 500 tokens/entity/epoch.  At pool=50
#     it's ~50; the cap scales with pool volume, not fixed.)
#   * Rewards beyond the cap BURN — no treasury credit, no carryover.
#
# Sybil evasion: to beat the cap a mega-staker must split their stake
# into sybils, each individually stake-gated by VALIDATOR_MIN_STAKE
# (10_000 tokens).  A founder with 25M stake can operationally run
# up to ~100-500 sybils; beyond that, collective capture saturates
# the pool regardless (25M / 10K = 2500 sybils → cap * 2500 = 25x
# pool size → pool fully drained via burn).  So the cap either limits
# direct capture (few sybils) or forces large-staker burn (many
# sybils) — either way defends decentralization.
#
# Pre-activation: cap_active=False; legacy mint path byte-for-byte.
# Operators MUST replace the placeholder with a coordinated-fork height.
# Height chosen independently of ATTESTER_FEE_FUNDING_HEIGHT even
# though they share the placeholder value.
PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH = 100  # 1% of epoch pool
# Tier 4.  Activates after ATTESTER_REWARD_SPLIT_HEIGHT (78,000) and
# ATTESTER_FEE_FUNDING_HEIGHT (80,000) so the cap operates on the
# post-split, fee-funded pool.
ATTESTER_REWARD_CAP_HEIGHT = 84_000

assert 0 < PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH <= 10_000, (
    "cap must be a positive basis-point fraction <= 100%"
)

# ─────────────────────────────────────────────────────────────────────
# Finality-vote reward from issuance (hard fork)
# ─────────────────────────────────────────────────────────────────────
# Latent economic failure in the shipped code: the
# FINALITY_VOTE_INCLUSION_REWARD (1 token per included vote, paid to
# the block proposer) is debited from the treasury via
# treasury_spend.  Three failure modes stack:
#   1. Treasury eventually empties → finality becomes silently
#      uneconomic (the legacy code falls back to paying what the
#      treasury has, all the way down to 0).
#   2. TREASURY_MAX_SPEND_BPS_PER_EPOCH is saturable by combined
#      governance-spend + finality-reward draws → finality starves.
#   3. The same cap is being tightened (separately) from 1%/epoch to
#      0.1%/epoch, making failure mode #2 worse.
#
# Fix: at/after ``FINALITY_REWARD_FROM_ISSUANCE_HEIGHT`` the
# ``FINALITY_VOTE_INCLUSION_REWARD`` is MINTED directly (bumps
# total_supply and total_minted) and credited to the proposer.  No
# treasury interaction.  The numeric reward value is unchanged.
#
# Annual cost sanity-check: ~100 validators voting every 100 blocks
# → 1 token/block → 52,600 tokens/year.  At 140M supply that's
# 0.038%/year additional inflation.  Acceptable.
#
# Pre-activation: treasury-spend path preserved byte-for-byte,
# including the silent zero-fallback when the treasury is short.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.  The height
# is independent of ATTESTER_FEE_FUNDING_HEIGHT even though it
# shares the same placeholder value.
FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = 82_000  # Tier 4 (must follow FINALITY_VOTE_CAP_HEIGHT)

# ─────────────────────────────────────────────────────────────────────
# Finality-vote apply-path clamp (defense-in-depth, hard fork)
# ─────────────────────────────────────────────────────────────────────
# `_validate_finality_votes` already rejects blocks whose
# finality_votes list exceeds MAX_FINALITY_VOTES_PER_BLOCK, and rejects
# duplicates on (signer_entity_id, target_block_number) within a single
# block.  Under the post-FINALITY_REWARD_FROM_ISSUANCE_HEIGHT direct-
# mint path, however, any validation drift that let an oversize block
# through would mint one token per vote with NO treasury check — an
# unbacked-supply failure.
#
# This fork adds a SECOND-LAYER hard cap inside `_apply_finality_votes`
# itself so the mint loop stops at MAX_FINALITY_VOTES_PER_BLOCK even
# if validation was bypassed or drifted.  Belt-and-suspenders against
# a single bug class.  At/after FINALITY_VOTE_CAP_HEIGHT the apply-
# path clamp is authoritative.  Pre-activation the legacy (validation-
# only) path applies byte-for-byte.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.
FINALITY_VOTE_CAP_HEIGHT = 54_000  # Tier 1 (defensive cap — MUST activate before direct-mint)

# ─────────────────────────────────────────────────────────────────────
# Seed-validator stake ceiling (founder re-stake defense, hard fork)
# ─────────────────────────────────────────────────────────────────────
# SEED_DIVESTMENT_END_HEIGHT (block 315,576) terminates the forced
# divestment schedule with the founder's seed entity_id locked at
# SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE (= 20M) staked tokens.
# Nothing in the legacy StakeTransaction validation prevents the
# founder from ACCUMULATING tokens externally (purchases, unstake-
# then-transfer, OTC) and re-staking them — i.e. the entire dilution
# the divestment schedule produced can be silently undone by a normal
# stake tx that pushes the seed back above 20M.
#
# Fix: at/after SEED_STAKE_CEILING_HEIGHT, any StakeTransaction whose
# entity_id is in `seed_entity_ids` is rejected when
# `current_stake + stake_amount > SEED_MAX_STAKE_CEILING`.  Seeds may
# still stake UP TO the ceiling (top-up after unstake, re-enter after
# full exit) and may freely unstake any amount — they simply cannot
# exceed the post-divestment retention floor.
#
# Non-seed validators are unaffected by this gate.  The ceiling is
# PERMANENT: it does not lift after END — that's the point.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.
SEED_MAX_STAKE_CEILING = SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE   # 20_000_000
SEED_STAKE_CEILING_HEIGHT = 56_000  # Tier 1

# ─────────────────────────────────────────────────────────────────────
# Supply-responsive issuance floor (deflation anchor, hard fork)
# ─────────────────────────────────────────────────────────────────────
# Steady-state burn math under the shipped fixes is net-deflationary:
# issuance at the BLOCK_REWARD_FLOOR era (~210K/yr) plus the finality
# mint (~52K/yr) totals ~262K tokens/yr, while base-fee burn at
# moderate traffic (~5 tx/block after the ATTESTER_FEE_FUNDING_HEIGHT
# redirect) burns an order of magnitude more.  Net of other minor
# burns (new-account, slashing, seed divestment residuals) the chain
# loses roughly 10–15M tokens/year.  Over decades this drives
# circulating supply toward dangerously thin totals — at <~50M the
# per-token impact of every economic event becomes unwieldy and the
# security-incentive surface thins out.
#
# Fix (anchor, not cure): when `total_supply` drops below
# TARGET_CIRCULATING_SUPPLY_FLOOR, double the issuance-side block
# reward until supply recovers.  Self-correcting — above the floor
# the multiplier snaps back to 1x.  Bounded — capped at 2x even if
# burn pathology continues, so an implementation bug cannot produce
# runaway inflation.  This does NOT prevent deflation (burn can
# still exceed boosted issuance), but meaningfully slows it at low
# supply.  A full deflation fix would require fee-responsive
# issuance, which is deliberately deferred — the anchor is the
# simple, auditable long-term guard.
#
# At/after block_height == DEFLATION_FLOOR_HEIGHT:
#   * If supply < TARGET_CIRCULATING_SUPPLY_FLOOR at reward-compute
#     time, the halvings-adjusted reward is multiplied by
#     DEFLATION_ISSUANCE_MULTIPLIER (2x) AFTER the BLOCK_REWARD_FLOOR
#     clamp.  Post-floor era that's 4 × 2 = 8 tokens/block.
#   * If supply >= floor, no boost.  Strictly-less-than: the boundary
#     value (supply == floor exactly) is "recovered, don't boost".
#
# Pre-activation: boost never applies regardless of supply.
# Byte-for-byte legacy reward behavior preserved.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.  The height
# is independent of other *_HEIGHT forks even though it shares the
# same placeholder value.

# Deflation floor: when circulating supply drops below this, issuance
# doubles until supply recovers.  Conservative target (71% of genesis)
# preserves deflationary dynamics while capping the worst-case
# extinction trajectory.  Not a full deflation fix — that would
# require fee-responsive issuance — but a meaningful long-term anchor.
TARGET_CIRCULATING_SUPPLY_FLOOR = 100_000_000

# When supply is below the floor, multiply BLOCK_REWARD by this.
# Capped at 2x to prevent runaway inflation if burn pathology bugs
# out.  Chosen as a round, conservative number — a 4x boost might
# fix deflation faster but risks overcorrection during data-anomaly
# scenarios.
#
# DEPRECATED at DEFLATION_FLOOR_V2_HEIGHT: the 2× multiplier at floor
# era produces only ~420K/yr of extra issuance while steady-state burn
# at moderate traffic is ~13M/yr (31× the boost) — doesn't arrest
# deflation, barely slows it.  Replaced by a fee-responsive rebate at
# DEFLATION_FLOOR_V2_HEIGHT; constant is retained as a stub so
# already-shipped tests that import it don't fail — not referenced by
# active post-v2 code paths.
DEFLATION_ISSUANCE_MULTIPLIER = 2

# Activation — operators must replace with a concrete coordinated
# height before deploy.
DEFLATION_FLOOR_HEIGHT = 90_000  # Tier 5 (legacy v1; superseded by v2)

# ─────────────────────────────────────────────────────────────────────
# Fee-responsive deflation floor (v2 hard fork)
# ─────────────────────────────────────────────────────────────────────
# The v1 anchor (DEFLATION_FLOOR_HEIGHT) doubles BLOCK_REWARD when
# supply < TARGET.  At BLOCK_REWARD_FLOOR era that produces 4 × 2 = 8
# tokens/block, ~420K/yr.  Steady-state burn at moderate traffic
# (~5 tx/block × MIN_FEE=100 × 50% redirected) is ~13M/yr — the 2×
# boost is ~31× too small to arrest deflation.
#
# Fix: replace the fixed multiplier with a fee-responsive rebate.  At/
# after DEFLATION_FLOOR_V2_HEIGHT, when total_supply < TARGET, issuance
# becomes
#     max(base_reward, rolling_burn_rate × DEFLATION_REBATE_BPS // 10_000)
# where rolling_burn_rate is the trailing window's total burn divided by
# DEFLATION_REBATE_WINDOW_BLOCKS.  rebate_bps = 7000 (70%) offsets most
# of the burn without eliminating the deflationary incentive entirely.
#
# Pre-activation (block_height < DEFLATION_FLOOR_V2_HEIGHT): v1 2×
# behavior preserved byte-for-byte.  Between DEFLATION_FLOOR_HEIGHT
# (90_000) and DEFLATION_FLOOR_V2_HEIGHT (92_000) the legacy 2×
# multiplier continues to fire so v1-era blocks remain re-validatable.
#
# Rolling-window mechanics:
#   * Every post-activation fee-burn appends (block_height, actual_burn)
#     to SupplyTracker.rolling_fee_burn.
#   * Before computing boosted issuance, entries older than the
#     trailing window are pruned.
#   * Sum remaining amounts; divide by DEFLATION_REBATE_WINDOW_BLOCKS to
#     get per-block burn rate.
#
# Reorg safety: the rolling list is consensus state.  Snapshotted
# alongside treasury_spend_rolling_debits; committed to the
# state-snapshot root (see _TAG_FEE_BURN_ROLLING in state_snapshot.py)
# so state-synced nodes inherit the same window as replaying nodes.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploy.
DEFLATION_REBATE_BPS = 7000                 # 70% rebate share
DEFLATION_REBATE_WINDOW_BLOCKS = 1000       # ~1 week at 600s/block
DEFLATION_FLOOR_V2_HEIGHT = 92_000          # Tier 5 (must follow DEFLATION_FLOOR_HEIGHT)

assert 0 < DEFLATION_REBATE_BPS <= 10_000, (
    "DEFLATION_REBATE_BPS must be a non-empty fraction <= 100%"
)
assert DEFLATION_REBATE_WINDOW_BLOCKS > 0, (
    "DEFLATION_REBATE_WINDOW_BLOCKS must be positive"
)

# ─────────────────────────────────────────────────────────────────────
# Attester-reward cap formula fix (hard fork)
# ─────────────────────────────────────────────────────────────────────
# The original cap (ATTESTER_REWARD_CAP_HEIGHT = 60_000) was
#   cap = attester_pool_this_block × PER_VALIDATOR_ATTESTER_REWARD_
#         CAP_BPS_PER_EPOCH × FINALITY_INTERVAL // 10_000
# But `attester_pool_this_block` includes the fee-funded portion,
# which varies per block.  A high-fee block at the first slot of an
# epoch banks huge rewards under a temporarily-large cap; a low-fee
# block lowers the cap later in the same epoch — path-dependent.
#
# Fix: at/after ATTESTER_CAP_FIX_HEIGHT, the cap uses the issuance-only
# component:
#   cap = (reward - proposer_share) × PER_VALIDATOR...
#         × FINALITY_INTERVAL // 10_000
# At BLOCK_REWARD=16, proposer_share=4, issuance_pool=12 →
# cap = 12 × 100 × 100 / 10_000 = 12 tokens/entity/epoch.  Floor era
# (reward=4): cap = 3 × 100 × 100 / 10_000 = 3.  Stable across fee
# variation, predictable, path-independent.
#
# Dilution impact: naive founder at 42% stake earns ~5 tokens/epoch
# before cap — cap at 12 barely binds.  Against founder sybils each
# hitting the cap, the per-validator ceiling bounds aggregate capture.
# Cap is belt-and-suspenders, not a dominant dilution mechanism;
# predictability matters more than dilution strength.
#
# Pre-activation: cap retains the old (broken) fee-dependent formula
# byte-for-byte so v1-era mint blocks remain re-validatable.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploy.
ATTESTER_CAP_FIX_HEIGHT = 86_000            # Tier 4 (must follow ATTESTER_REWARD_CAP_HEIGHT)

# ─────────────────────────────────────────────────────────────────────
# Validator registration burn (hard fork)
# ─────────────────────────────────────────────────────────────────────
# The per-entity attester-reward cap (ATTESTER_REWARD_CAP_HEIGHT) is
# sybil-negative for a large staker: at VALIDATOR_MIN_STAKE = 10_000,
# a 25M-stake founder can split into ~2,500 sybils, each with its own
# per-epoch cap allowance — aggregate capture exceeds what the founder's
# main entity would earn uncapped.  Splitting increases revenue.
#
# Fix: raise the real cost of spawning a validator.  Burn
# VALIDATOR_REGISTRATION_BURN tokens when an entity FIRST registers as
# a validator (first-ever StakeTransaction).  Sybil cost rises from
# 10K (recoverable on unstake) to 20K (10K stake + 10K permanently
# burned).  Infrastructure cost remains the ultimate bound, but the
# protocol now charges a meaningful entry fee against pure-capital
# splitting strategies.
#
# Policy (Option A from the design doc):
#   * One-time per entity.  Once registered, always registered.  An
#     entity that fully unstakes and later re-stakes does NOT pay a
#     second burn — punishing legitimate operators who cycle stake is
#     a false-positive we deliberately avoid.
#   * Grandfathering: entities already staked at activation height
#     are added to the registered set by a one-shot migration at
#     VALIDATOR_REGISTRATION_BURN_HEIGHT, without paying.  Guarded
#     by ``SupplyTracker.grandfather_applied`` for reorg safety
#     (same pattern as ``treasury_rebase_applied``).
#   * Pre-activation: the set never populates and no burn fires.
#     Byte-for-byte legacy behavior preserved.
#
# Sized at VALIDATOR_MIN_STAKE_POST_RAISE so first-time registration
# cost exactly doubles (stake + burn).
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.  The height is
# independent of other *_HEIGHT forks even though it shares the
# placeholder spacing convention (current_height + 50_000).
VALIDATOR_REGISTRATION_BURN = 10_000
VALIDATOR_REGISTRATION_BURN_HEIGHT = 96_000  # Tier 6 (must follow MIN_STAKE_RAISE_HEIGHT)

assert VALIDATOR_REGISTRATION_BURN > 0, (
    "registration burn must be positive — zero disables sybil defense"
)


# ─────────────────────────────────────────────────────────────────────
# Flat per-tx fee floor — retires the legacy quadratic formula
# ─────────────────────────────────────────────────────────────────────
# At/after FLAT_FEE_HEIGHT the fee floor collapses to ``MIN_FEE_POST_FLAT``
# regardless of message or signature size.  Rationale:
#
#   * Messages are hard-capped at tweet scale (MAX_MESSAGE_CHARS /
#     MAX_MESSAGE_BYTES), so size-indexed pricing inside a single tx
#     buys little real protection — rational users fill the cap.
#   * Multi-part messages are a first-class pattern; charging per-byte
#     on top of per-tx double-counts the cost a user already pays by
#     splitting.  Flat per-tx → N-part message pays exactly N × floor.
#   * Bloat defense stays intact: (1) the hard size cap, (2) a floor
#     high enough that bulk spam is uneconomical, (3) market-driven
#     fees above the floor during congestion.
#
# Legacy constants (MIN_FEE, FEE_PER_BYTE, FEE_QUADRATIC_COEFF) are
# retained so pre-fork blocks replay deterministically.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.  Per the FORK
# SCHEDULE: Tier 7, target 98,000 — after the last Tier 6 fork
# (VALIDATOR_REGISTRATION_BURN_HEIGHT) and before BOOTSTRAP_END_HEIGHT.
FLAT_FEE_HEIGHT = 98_000

assert MIN_FEE_POST_FLAT > MIN_FEE, (
    "MIN_FEE_POST_FLAT must exceed the legacy floor — otherwise the fork "
    "silently lowers fees and weakens anti-spam pressure"
)
assert FLAT_FEE_HEIGHT > FEE_INCLUDES_SIGNATURE_HEIGHT, (
    "FLAT_FEE_HEIGHT must follow FEE_INCLUDES_SIGNATURE_HEIGHT — the flat "
    "fee supersedes the sig-aware quadratic rule, so blocks in the "
    "[FEE_INCLUDES_SIGNATURE_HEIGHT, FLAT_FEE_HEIGHT) window still apply "
    "the witness-aware formula during replay"
)

# ─────────────────────────────────────────────────────────────────────
# Fork-schedule ordering invariants (load-time asserts)
# ─────────────────────────────────────────────────────────────────────
# The defensive per-block finality-vote mint cap MUST activate before
# the direct-mint path goes live.  Otherwise any _validate_finality_
# votes drift in [FINALITY_VOTE_CAP_HEIGHT, FINALITY_REWARD_FROM_
# ISSUANCE_HEIGHT) mints unbacked tokens with no clamp — the exact
# failure mode the cap was designed to prevent.
assert FINALITY_VOTE_CAP_HEIGHT < FINALITY_REWARD_FROM_ISSUANCE_HEIGHT, (
    "FINALITY_VOTE_CAP_HEIGHT must activate BEFORE "
    "FINALITY_REWARD_FROM_ISSUANCE_HEIGHT — the cap is the defensive "
    "clamp on the direct-mint path; activating mint first leaves a "
    "window of uncapped issuance under validation drift"
)
# The attester-cap basis-fix fork is a pure correction to the cap
# formula introduced by ATTESTER_REWARD_CAP_HEIGHT.  Activating the
# fix before the cap is nonsensical — pre-cap blocks have no cap to
# fix — and creates a window where the "fixed" formula operates
# without the bookkeeping initialization the cap path establishes.
assert ATTESTER_CAP_FIX_HEIGHT > ATTESTER_REWARD_CAP_HEIGHT, (
    "ATTESTER_CAP_FIX_HEIGHT must follow ATTESTER_REWARD_CAP_HEIGHT"
)
# The registration-burn grandfather reads the already-raised validator
# min stake floor.  Activating the burn before the min-stake raise
# means the grandfather's floor check runs against the legacy 100
# threshold, letting legacy sub-10_000 validators register for free
# even though they'd be below floor post-fork.
assert VALIDATOR_REGISTRATION_BURN_HEIGHT > MIN_STAKE_RAISE_HEIGHT, (
    "VALIDATOR_REGISTRATION_BURN_HEIGHT must follow MIN_STAKE_RAISE_HEIGHT"
)
# The v2 rebate-style deflation floor supersedes the v1 2× multiplier.
# v1 must activate first so the [v1, v2) window still applies the
# legacy multiplier during replay of pre-v2 blocks.
assert DEFLATION_FLOOR_V2_HEIGHT > DEFLATION_FLOOR_HEIGHT, (
    "DEFLATION_FLOOR_V2_HEIGHT must follow DEFLATION_FLOOR_HEIGHT — v2 "
    "replaces v1's 2× multiplier with a fee-responsive rebate"
)
# All shipped forks must land inside the bootstrap window so activation
# happens while the founder-led governance regime is still in effect
# and a coordinated rollback is still feasible.
for _fork_name, _fork_height in (
    ("UNBONDING_PERIOD_EXTENSION_HEIGHT", UNBONDING_PERIOD_EXTENSION_HEIGHT),
    ("TREASURY_CAP_TIGHTEN_HEIGHT", TREASURY_CAP_TIGHTEN_HEIGHT),
    ("FINALITY_VOTE_CAP_HEIGHT", FINALITY_VOTE_CAP_HEIGHT),
    ("SEED_STAKE_CEILING_HEIGHT", SEED_STAKE_CEILING_HEIGHT),
    ("MIN_STAKE_RAISE_HEIGHT", MIN_STAKE_RAISE_HEIGHT),
    ("LOTTERY_BOUNTY_RAISE_HEIGHT", LOTTERY_BOUNTY_RAISE_HEIGHT),
    ("FEE_INCLUDES_SIGNATURE_HEIGHT", FEE_INCLUDES_SIGNATURE_HEIGHT),
    ("TREASURY_REBASE_HEIGHT", TREASURY_REBASE_HEIGHT),
    ("SEED_DIVESTMENT_RETUNE_HEIGHT", SEED_DIVESTMENT_RETUNE_HEIGHT),
    ("SEED_DIVESTMENT_REDIST_HEIGHT", SEED_DIVESTMENT_REDIST_HEIGHT),
    ("ATTESTER_REWARD_SPLIT_HEIGHT", ATTESTER_REWARD_SPLIT_HEIGHT),
    ("ATTESTER_FEE_FUNDING_HEIGHT", ATTESTER_FEE_FUNDING_HEIGHT),
    ("FINALITY_REWARD_FROM_ISSUANCE_HEIGHT", FINALITY_REWARD_FROM_ISSUANCE_HEIGHT),
    ("ATTESTER_REWARD_CAP_HEIGHT", ATTESTER_REWARD_CAP_HEIGHT),
    ("ATTESTER_CAP_FIX_HEIGHT", ATTESTER_CAP_FIX_HEIGHT),
    ("DEFLATION_FLOOR_HEIGHT", DEFLATION_FLOOR_HEIGHT),
    ("DEFLATION_FLOOR_V2_HEIGHT", DEFLATION_FLOOR_V2_HEIGHT),
    ("VALIDATOR_REGISTRATION_BURN_HEIGHT", VALIDATOR_REGISTRATION_BURN_HEIGHT),
    ("FLAT_FEE_HEIGHT", FLAT_FEE_HEIGHT),
):
    assert _fork_height < _BEH, (
        f"{_fork_name} ({_fork_height}) must activate before "
        f"BOOTSTRAP_END_HEIGHT ({_BEH})"
    )
del _fork_name, _fork_height


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

# If the local override flipped NETWORK_NAME (e.g. the default "testnet"
# baked in above was replaced with "mainnet" by an operator's
# config_local.py), re-resolve PINNED_GENESIS_HASH so it tracks the
# current network rather than the default.  Without this, flipping
# NETWORK_NAME alone leaves PINNED_GENESIS_HASH stuck at the original
# network's pin, and the validator silently rejects its own chain.
if "PINNED_GENESIS_HASH" not in (dir(_mod) if _os_local.path.isfile(_local_path) else []):
    PINNED_GENESIS_HASH = _resolve_pinned_genesis_hash(NETWORK_NAME)

# Re-derive DEVNET if NETWORK_NAME was overridden by config_local.py.
# DEVNET is defined above as a one-shot `NETWORK_NAME == "devnet"`
# derivation — but if config_local.py flipped NETWORK_NAME after that
# line ran, the two end up disagreeing.  The original comment at
# line 282 explicitly says "kept as a derived flag rather than a
# parallel source of truth so the two can never disagree" — enforcing
# that invariant requires a second derivation after local overrides.
if "DEVNET" not in (dir(_mod) if _os_local.path.isfile(_local_path) else []):
    DEVNET = NETWORK_NAME == "devnet"
