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
#
# Block serialization version 2 introduces the validator_version field
# (Fork 1, audit finding #2): a uint16 carried in every V2 block header
# stamping the proposer's running release.  V1 (legacy) blocks have no
# such field and decode with validator_version=UNSIGNALLED.  Both V1 and
# V2 are accepted during the migration window so a node running new
# code can ingest the entire pre-fork chain history.  After the network
# has fully migrated to V2, V1 can be dropped from the accept set in a
# follow-up fork.
BLOCK_SERIALIZATION_VERSION_V1 = 1
BLOCK_SERIALIZATION_VERSION_V2 = 2
BLOCK_SERIALIZATION_VERSION = BLOCK_SERIALIZATION_VERSION_V2
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
    BLOCK_SERIALIZATION_VERSION_V1,
    BLOCK_SERIALIZATION_VERSION_V2,
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


# Maximum block-header `version` this binary understands at the
# consensus layer.  Distinct from BLOCK_SERIALIZATION_VERSION (wire
# format): this is the CONSENSUS ruleset version carried inside the
# header, and it exists specifically so an out-of-date binary can
# HALT cleanly when the network activates newer rules rather than
# rejecting post-fork blocks as "invalid" and spamming peer-ban
# machinery.
#
# Current value is 1 (the only version ever shipped).  A future hard
# fork that changes consensus semantics bumps this to 2 (or higher),
# and ``messagechain upgrade`` installs the binary that understands
# it.  Old binaries that see ``block.header.version = 2`` raise
# ``BinaryOutOfDateError`` from ``validate_block`` with an operator-
# facing message pointing at the upgrade command.
#
# See ``BinaryOutOfDateError`` in ``messagechain/core/blockchain.py``
# for the halt semantics and the block-version gate that reads this.
MAX_SUPPORTED_BLOCK_VERSION = 1


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
# Cap raised from 280 → 1024 at LINEAR_FEE_HEIGHT (Tier 8 fork). The constant
# itself is monotone-safe to bump: every historical (pre-fork) tx satisfied
# len ≤ 280, which trivially still satisfies len ≤ 1024 — no replay risk.
# Long-form posts pay the linear-in-bytes fee floor introduced by the same
# fork; storage discipline lives in the fee, not in the cap.
MAX_MESSAGE_CHARS = 1024  # max characters per message
MAX_MESSAGE_BYTES = 1024  # 1:1 with chars (ASCII only, no multi-byte encoding)

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
TARGET_BLOCK_SIZE = 10                # target txs per block (pre-Tier-9: 50% of legacy MAX_TXS_PER_BLOCK=20)
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
# Historical: a per-block ``MAX_PROPOSER_FALLBACK_ROUNDS`` cap once
# bounded how many fallback rounds a block's claimed timestamp could
# imply past the parent.  It existed to defend against timestamp-skew
# slot-hijacking grinding — a proposer pushing ``block.timestamp``
# forward to claim a round where THEY are selected, skipping the honest
# round-0 proposer.
#
# Removed in the round-cap-decoupling change after we recognized the
# defense is fully redundant with ``MAX_BLOCK_FUTURE_DRIFT``: a
# malicious proposer cannot fabricate ``parent.timestamp`` (it's
# already committed to the chain), and ``block.timestamp`` is bounded
# by ``now + MAX_BLOCK_FUTURE_DRIFT``.  The maximum extra round an
# attacker can claim above what an honest proposer would claim is
# ``MAX_BLOCK_FUTURE_DRIFT / BLOCK_TIME_TARGET = 120 / 600 = 0`` —
# i.e. the round-cap added zero defense beyond future-drift.
#
# Meanwhile the cap was load-bearing for the recovery path: every chain
# stall longer than ``cap × BLOCK_TIME_TARGET`` became self-perpetuating,
# because the producer's natural recovery block computed a
# ``round_number`` proportional to the wall-clock gap from the stale
# parent and got rejected as "timestamp-skew slot hijacking" before any
# fix could be exercised.  The cap drifted reactively three times
# (5 → 100 → 10_000) chasing this ratchet.  Removing it decouples
# grinding-resistance (still enforced by ``MAX_BLOCK_FUTURE_DRIFT`` and
# the ``ts_gap >= BLOCK_TIME_TARGET`` rule) from recovery-time
# (now unbounded — a chain can self-heal from any stall length).
#
# See tests/test_round_cap_recovery.py for the recovery property pin.
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
MAX_TXS_PER_BLOCK = 45  # max transactions per block (tx count cap)
# Raised from 20 → 45 at BLOCK_BYTES_RAISE_HEIGHT (Tier 9).  Targets
# ~24 GB/yr on-disk chain growth at 100-validator saturation.  Per-
# message cap stays at MAX_MESSAGE_CHARS=1024 — this is a throughput
# raise, not a message-size raise.  Monotone-safe to bump: pre-fork
# blocks satisfied total ≤ 20, which trivially still satisfies ≤ 45.
MAX_TXS_PER_ENTITY_PER_BLOCK = 3  # anti-flooding: max message txs from one sender per block
MAX_BLOCK_MESSAGE_BYTES = 45_000  # max total message payload bytes per block (byte budget cap)
# Raised 10_000 → 15_000 at LINEAR_FEE_HEIGHT (Tier 8) alongside the
# per-message cap raise, then 15_000 → 45_000 at BLOCK_BYTES_RAISE_HEIGHT
# (Tier 9) to widen the per-block byte budget in step with the tx-count
# raise.  Bloat discipline is preserved via the simultaneously-raised
# FEE_PER_STORED_BYTE_POST_RAISE (1 → 3).  Monotone-safe to bump:
# pre-fork blocks satisfied total ≤ 15_000, which trivially still
# satisfies ≤ 45_000.
MAX_BLOCK_SIG_COST = 250  # max signature verification cost per block (1 per tx + 1 proposer + attestations)
# Raised 100 → 250 at BLOCK_BYTES_RAISE_HEIGHT (Tier 9) to match the
# MAX_TXS_PER_BLOCK raise — each tx carries a signature verification
# cost, so the sig-cost ceiling has to widen in proportion.
# Monotone-safe to bump: pre-fork blocks satisfied cost ≤ 100, which
# trivially still satisfies ≤ 250.
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

# Personal-wallet default tree height — strictly lower than MERKLE_TREE_HEIGHT
# because the cost/benefit ratio differs from validators.  A validator
# proposes / attests once per slot and burns ~530k leaves/year, so the
# 90-minute keygen at h=20 amortizes across ~2 years of runtime.  A
# personal wallet sends a few messages a day and will never approach 65k
# signatures, so charging it the same upfront wait has no security benefit
# and turns the README's first-message walkthrough into a 90-minute wedge.
# h=16 (~65k leaves) gives an active personal user multiple lifetimes of
# capacity at a fraction of the keygen cost.  Per-entity tree heights are
# stored on chain (see Blockchain.set_wots_tree_height), so different
# entities at different heights coexist on the same chain.
WALLET_DEFAULT_TREE_HEIGHT = _profile_int(
    "MESSAGECHAIN_WALLET_DEFAULT_TREE_HEIGHT", "WALLET_DEFAULT_TREE_HEIGHT", 16,
)

# Worker-process count for parallel WOTS+ leaf derivation during keygen.
# Each leaf is independent so the work parallelizes across cores cleanly.
# 0 = auto (os.cpu_count()).  1 = serial (the historical path).
# Tests pin this to 1 in tests/__init__.py to avoid multiprocessing
# overhead and to keep deterministic execution under pytest-xdist.
KEYGEN_WORKERS = _profile_int(
    "MESSAGECHAIN_KEYGEN_WORKERS", "KEYGEN_WORKERS", 0,
)
# Below this count, parallel keygen is slower than serial because of
# subprocess spawn overhead (Windows uses 'spawn', not 'fork').  At
# h=14 (16384 leaves) the per-worker payload is large enough that
# the spawn cost amortizes; smaller trees stay serial regardless of
# KEYGEN_WORKERS.
KEYGEN_PARALLEL_MIN_LEAVES = 16384
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
MIN_STAKE_RAISE_HEIGHT = 701  # Tier 2 — fast-forwarded for 1.26.0 hard fork sweep

# Tier 28: validator minimum stake collapses to one faucet drip.
# Tier 2 raised the floor to 10_000 to give validator entry a meaningful
# capital cost; in practice that capital wall ($X-equivalent at any real
# token price) made permissionless entry "permissionless on paper."
# Tier 28 drops the floor to exactly one faucet grab so any user who can
# solve the faucet PoW can spin up a validator from a single drip.
# Sybil cost collapses to ~one faucet drip + the per-/24 + PoW limits the
# faucet enforces; slashing still bites but the absolute burn shrinks
# proportionally.  Pinned to FAUCET_DRIP by an assert below so the two
# constants cannot drift.
VALIDATOR_MIN_STAKE_FAUCET_DRIP = 300
MIN_STAKE_FAUCET_DRIP_HEIGHT = 754  # Tier 28 — fast-forwarded for 1.32.0 hard fork sweep

# Tier 29: a single faucet drip funds a full validator end-to-end.
# Tier 28 set the stake floor to FAUCET_DRIP, but a wallet holding
# exactly one drip still cannot pay the stake-tx fee floor
# (``MIN_FEE`` = 100; the Tier-16 protocol floor is 1, but stake-tx
# admission carries its own type-specific 100-token floor) without
# dipping below the stake floor — and Tier 6's
# VALIDATOR_REGISTRATION_BURN=10_000 dominates first-time registration
# regardless.  Tier 29 closes both gaps: the stake floor drops by one
# MIN_FEE (so 300 drip = 100 fee + 200 stake works) and first-time
# registration carries no burn at/post activation.  Sybil floor stays
# at one drip per validator + the faucet's per-/24 + PoW limits — same
# posture as Tier 28, just actually achievable from a single drip.
# VALIDATOR_MIN_STAKE_TIER29 is pinned to FAUCET_DRIP - MIN_FEE by an
# assert further down (after MIN_FEE is defined above us, FAUCET_DRIP
# is imported lazily by the assert helper).
VALIDATOR_MIN_STAKE_TIER29 = 200  # = FAUCET_DRIP (300) - MIN_FEE (100)
VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT = 755  # Tier 29 — fast-forwarded for 1.32.0 hard fork sweep


def get_validator_min_stake(block_height: int) -> int:
    """Return the validator minimum stake in effect at ``block_height``.

    Hard-fork-gated:
      * pre-Tier-2: legacy 100-token floor.
      * Tier 2 .. Tier 28: 10_000-token post-raise floor.
      * Tier 28 .. Tier 29: one-faucet-drip floor (300).
      * Tier 29+: drip-minus-fee-floor (299), so a single drip funds
        stake + fee end to end.

    Used by every fresh-stake / partial-unstake enforcement site.
    The apply-time active-set filter (proposer-selection, validator-
    set membership for finality/attestation) continues to honor the
    LEGACY floor: grandfathered sub-floor validators retain their
    participation rights indefinitely; only NEW stake ops see the
    raised bar.
    """
    if block_height >= VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT:
        return VALIDATOR_MIN_STAKE_TIER29
    if block_height >= MIN_STAKE_FAUCET_DRIP_HEIGHT:
        return VALIDATOR_MIN_STAKE_FAUCET_DRIP
    if block_height >= MIN_STAKE_RAISE_HEIGHT:
        return VALIDATOR_MIN_STAKE_POST_RAISE
    return VALIDATOR_MIN_STAKE


def get_validator_registration_burn(block_height: int) -> int:
    """Return the first-time validator-registration burn at ``block_height``.

    Hard-fork-gated:
      * pre-Tier-6: 0 (the burn fork hasn't activated).
      * Tier 6 .. Tier 29: ``VALIDATOR_REGISTRATION_BURN`` (10_000).
      * Tier 29+: 0 — Tier 28 collapsed sybil-defense to the stake
        floor itself; the additional burn no longer pulls its weight
        once one drip is supposed to fund a fresh validator.

    Already-registered entities pay nothing regardless; this helper
    only governs the FIRST-time registration cost.
    """
    if block_height >= VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT:
        return 0
    if block_height >= VALIDATOR_REGISTRATION_BURN_HEIGHT:
        return VALIDATOR_REGISTRATION_BURN
    return 0


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
LOTTERY_BOUNTY_RAISE_HEIGHT = 702  # Tier 2 — fast-forwarded for 1.26.0 hard fork sweep


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

# Optional DNS seed domains. When set, nodes query TXT records on each
# domain at startup for additional peer endpoints ("host=1.2.3.4 port=9333").
# Empty by default — no public seed domain is live yet. Merged into the
# hardcoded SEED_NODES list; operators can override via --seed.
DNS_SEED_DOMAINS: list[str] = []

# Auto-upgrade + auto-rotate defaults. Operators flip these in onboard.toml;
# config-level constants exist so unit tests and scripts can read the
# shipped default without parsing the TOML file.
AUTO_UPGRADE_ENABLED = True
AUTO_ROTATE_ENABLED = True

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

PEER_READ_TIMEOUT = 1800  # seconds (30 min) — idle timeout for
                          # post-handshake peer reads.  Previously 300s,
                          # but on a small network where block cadence
                          # is ~10 min and the counter-party rarely
                          # produces (low stake), the inbound read loop
                          # timed out every ~block interval of silence
                          # and killed live connections; the counter-
                          # party's maintenance loop redialed 30s later,
                          # accumulating ghost Peer entries.  Dead-
                          # socket detection is now handled by TCP
                          # keepalive (~2 min); the remaining job of
                          # this timeout is slow-loris defense, where
                          # 30 min + MAX_PEERS + ban_manager is fine.

# Seed connections are established once at startup.  Without a
# maintenance loop, a dropped connection (silent NAT timeout, peer
# restart, transient network blip) is never retried — on a small
# network this degrades to two solo-producing chains.  The maintenance
# loop walks self.seed_nodes every PEER_MAINTENANCE_INTERVAL seconds
# and kicks off a fresh _connect_to_peer for any seed whose Peer entry
# is missing or has is_connected=False.  30s balances responsiveness
# with log noise on a disconnected seed.
PEER_MAINTENANCE_INTERVAL = 30  # seconds

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
# Compressed from 50_000 to 7_500 — ~50 days of runway at 600s blocks.
# Earlier compressions (_BEH 105_192 → 50_000) still buy nothing while
# the operator runs both validators with effectively zero external
# stake; pulling start in further tightens the credibility story for
# external observers without sacrificing security (the 4-year bleed
# itself is unchanged).  The bleed window duration (END - START =
# 210_384 blocks ≈ 4 years) is preserved so the per-block divestment
# rate stays sane; only the start is pulled forward.  See CHANGELOG
# 1.21.0 rationale.
SEED_DIVESTMENT_START_HEIGHT = 1711  # Compressed 2026-05-05 — was 7_500; collapsed to mainnet-tip+runway under the 1.55.1 sweep (only 2 validators on chain, both ours)
SEED_DIVESTMENT_END_HEIGHT = SEED_DIVESTMENT_START_HEIGHT + 210_384    # 217_884
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
# co-complicit in a governance-captured-treasury outcome.
#
# Floor history on the 140M supply:
#   * 20M (~14.3% of supply)  — the original retune target, "dominant
#     but not decisive".  Read in retrospect as still founder-heavy
#     given the thin starting validator set.
#   * 10M (~7.1% of supply)   — current target.  "Top holder, not
#     controlling holder."  Leaves the founder a meaningful position
#     commensurate with bootstrap effort while the lottery share grows
#     non-founder wallets to a clearly democratized end-state.
#
# Floor is a CONSENSUS CONSTANT — changing it is a hard fork.  The
# RETUNE/REDIST forks gate activation; pre-activation the legacy 1M
# floor applies byte-for-byte.
SEED_DIVESTMENT_RETAIN_FLOOR = 1_000_000  # LEGACY — see get_seed_divestment_params
# The founder's initial stake is divested DOWN TO this floor, not to zero.
SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE = 10_000_000
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
SEED_DIVESTMENT_RETUNE_HEIGHT = 1400  # Tier 3 (compressed: was 72_000)

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

SEED_DIVESTMENT_REDIST_HEIGHT = 1700              # Tier 3 (compressed 2026-05-05 in 1.55.1 sweep — was 1600; collapsed to mainnet-tip+runway since both validators are ours)

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
      * RETUNE-era (RETUNE <= h < REDIST): 10M floor, 95% burn,
        5% treasury, 0% lottery.
      * REDIST-era (h >= REDIST): 10M floor, 50% burn, 5% treasury,
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

# Fork-emergency auto-recovery — full-node-only, opt-in, default False.
#
# CLAUDE.md anchor: "a node that ends up on a minority/unintentional
# fork must auto-resync to the canonical chain with no manual state
# surgery on the operator side, and must not accumulate slashable
# evidence solely from being briefly on the wrong tip."
#
# When True AND the node is NOT a registered validator (no slashable
# role), Blockchain.attempt_fork_emergency_recovery() will rewind the
# local chain to the height before the lowest active emergency and
# clear the detector flags so the syncer re-fetches the canonical
# chain forward via normal peer sync.
#
# Default is False because validators MUST stay halted on a fork
# emergency rather than auto-flip — autoflipping on a quorum-signal
# bug would weaponize the bug into network-wide chain abandonment
# (the supermajority signal is what consensus already trusts to
# finalize, so a bug in it is a bug consensus already can't catch).
# Full nodes have no slashable role, so an incorrect rewind costs
# only resync time; that's why opt-in is safe for them. Operators
# running a non-validating node can flip this on via env override
# or a future CLI flag once they understand the trade-off.
FORK_EMERGENCY_AUTO_RECOVERY = False

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
INACTIVITY_PENALTY_QUOTIENT = 16_777_216  # ~2^24 (legacy flat formula)
INACTIVITY_BASE_PENALTY = 1
# Tier 59 -- post-fork stake-scaled formula uses a separate
# quotient.  At ``stake * BASE * blocks² / Q`` with the values below,
# the cumulative drain over a 10000-block-stall window yields ~2% of
# stake regardless of stake size -- matching the cumulative drain
# the legacy formula imposed on a 1M-stake validator.  The shape
# preserves cartel-defense (quadratic in blocks, fast-acceleration
# under sustained stalls) while delivering the "fractional of
# stake" property the CLAUDE.md honest-operator-insurance anchor
# calls for.  Pre-fork blocks use ``INACTIVITY_PENALTY_QUOTIENT``
# unchanged so historical replay is byte-identical.
#
# Calibration note: 16_777_216_000_000 = 2^24 * 1_000_000.  The
# 1M factor reflects "the legacy formula was effectively calibrated
# for 1M-stake validators -- whales -- whose 2% cumulative drain
# survived as a fractional bound; we now apply that same fractional
# bound to every validator size."
INACTIVITY_PENALTY_STAKE_SCALED_QUOTIENT = 16_777_216_000_000

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
# Auto-separation: when True (and tip >= WITNESS_AUTO_SEPARATION_HEIGHT),
# ChainDB.auto_separate_finalized_witnesses moves signatures of old
# finalized blocks from inline storage to the side-table on every
# call.  The default flipped from False -> True at the
# WITNESS_AUTO_SEPARATION_HEIGHT hard fork (see below) — at saturation
# WOTS+ signatures are ~73% of full-node block storage and serve only
# auditability after finalization, so leaving them inline forever
# would push commodity full-node storage off-target on the centuries
# horizon CLAUDE.md anchors to ("ordinary user — not just a datacenter
# — can sync and store the full history of the chain decades or
# centuries from now").  Nothing is ever deleted — separation only
# moves bytes from blocks.data into block_witnesses.witness_data on
# the same node, and reassembly via
# get_block_by_hash(..., include_witnesses=True) stays available.
# This flag remains an operator-facing kill switch: setting it to
# False at runtime suspends new separation work without touching
# already-separated blocks.
WITNESS_AUTO_SEPARATION_ENABLED = True

# Hard fork activation height.  Pre-fork blocks (block_number <
# WITNESS_AUTO_SEPARATION_HEIGHT) are NEVER stripped — the chain
# committed to their inline encoding before the fork activated, and
# replay determinism for historical blocks requires those bytes to
# stay where they are.  At and above this height the sweep starts
# processing newly-finalized blocks past the retention window.
#
# Activation: WITNESS_AUTO_SEPARATION_HEIGHT = 3000, riding above the
# Tier 23 cluster (currently topping out at HONESTY_CURVE_HEIGHT = 720
# after the 1.26.0 fast-forward sweep) with a comfortable runway from
# the live mainnet tip (~670 at the time of this writing) — ~2330
# blocks of advance notice (~16 days at 600s/block) for operators to
# upgrade.  The fork is one-way: once activated, pre-fork blocks
# remain un-stripped forever; only blocks at or above this height are
# eligible for separation.
WITNESS_AUTO_SEPARATION_HEIGHT = 1704  # Compressed 2026-05-05 in 1.55.1 sweep — was 3000


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

# Dedicated per-IP budget for SubmissionAck issuance on the
# `X-MC-Witnessed-Submission` opt-in path.  Each ack consumes one
# WOTS+ leaf from the receipt subtree (same finite 2^RECEIPT_SUBTREE_HEIGHT
# pool as receipts and rejections).  Without a dedicated budget, an
# attacker spamming the witnessed-submission header with random
# 32-byte values from a /24 drains all 65k leaves in minutes -- and
# once drained, the entire censorship-evidence pipeline (receipts,
# rejections, acks) collapses silently because every issuance path
# shares the same subtree.
#
# Witnessed-submission is the OPT-IN slow path (client paid
# WITNESS_SURCHARGE on top of the normal fee at the gossip layer);
# legitimate volume is bounded by that surcharge cost, not by HTTP
# request rate.  The budget is sized so honest opt-in flows always
# get an ack while any IP-flood attacker hits the ceiling within a
# few seconds.
SUBMISSION_ACK_RATE_LIMIT_PER_SEC = 0.1   # 1 per 10 seconds steady
SUBMISSION_ACK_BURST = 5                   # up to 5 acks immediately

# Dedicated per-IP budget for SUCCESS-PATH receipt issuance.  Audit
# (2026-04-28): pre-fix the message-path success branch in
# `submit_transaction_to_mempool` always called `receipt_issuer.issue`
# whenever an issuer was wired -- with NO budget gate.  An attacker
# paying floor-fee txs at the standard SUBMISSION_RATE_LIMIT cap
# (2/sec, 10-burst) drains the validator's receipt subtree in minutes
# from a single /24, silently bricking the censorship-evidence
# pipeline (the chain's primary defense against the PRIMARY anchored
# adversary -- validator collusion).
#
# A dedicated bucket -- separate from rejection/ack -- means the
# success-path leaf budget isn't competing with opt-in slash-evidence
# issuance.  All three families share the SAME global cap (see
# RECEIPT_GLOBAL_BURST) because all three burn from the same
# RECEIPT_SUBTREE pool.
#
# Sized intentionally tighter than SUBMISSION_BURST=10: an honest
# client typically submits one or two receipts per session (one per
# message they want slash-evidence for); a 5-burst with 0.1/sec
# refill (1 every 10s) covers honest workload generously while
# capping single-IP drain to single digits per minute.  Exhaustion
# falls open: the tx is still admitted, the response just doesn't
# include a receipt_hex (same shape as the broken-issuer fail-open
# path that already existed pre-fix).
SUBMISSION_RECEIPT_RATE_LIMIT_PER_SEC = 0.1   # 1 per 10 seconds steady
SUBMISSION_RECEIPT_BURST = 5                   # up to 5 receipts immediately

# ─────────────────────────────────────────────────────────────────────
# Public read-only feed (messagechain.network.public_feed_server)
# ─────────────────────────────────────────────────────────────────────
# Operator-facing endpoint that lets non-technical visitors browse
# recent on-chain messages over plain HTTP.  Read-only; no state
# mutations possible.  Message payloads are public by design (see
# CLAUDE.md "Payloads are fully public"), so nothing sensitive is
# exposed that the chain hasn't already committed.
#
# Steady 4/sec with a 30-request burst per source IP: enough for a
# browser polling /v1/latest every 10s with a handful of concurrent
# visitors, tight enough that an unbounded scraper can't walk the
# whole chain in a loop.  PUBLIC_FEED_MAX_LIMIT caps how far back a
# single request can reach — a client asking for more just gets the
# cap, same as `messagechain read --last N` clamps today.
PUBLIC_FEED_RATE_LIMIT_PER_SEC = 4
PUBLIC_FEED_BURST = 30
PUBLIC_FEED_MAX_LIMIT = 50

# Canonical public-feed base URL used by client-side helpers (the
# CLI's send-success path emits ``<PUBLIC_FEED_URL>/r/<tx_hash>`` so
# the user gets a shareable link to the receipt page the moment
# their tx is submitted).  Operator/testnet/alternative-feed
# deployments override via ``config_local.py`` or env without
# forking the CLI.  No trailing slash — the consumer appends one.
PUBLIC_FEED_URL = "https://messagechain.org"

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
#   Tier 7 — Fee-model simplification (RETIRED — superseded by Tier 8
#            in the bootstrap-compressed schedule.  FLAT_FEE_HEIGHT is
#            kept at 98,000 for code-path audit clarity but never
#            activates, because Tier 8 (below) is now scheduled earlier
#            and takes precedence in ``calculate_min_fee``):
#     98,000  FLAT_FEE_HEIGHT  (flat per-tx floor; never live in prod)
#
#   Tier 8 — Linear-in-stored-bytes fees + per-message cap raise:
#      4,300  LINEAR_FEE_HEIGHT  (pulled forward from 100,000 so the
#             1024-char cap is testable inside the bootstrap window)
#
#   Tier 9 — Throughput raise (depends on LINEAR_FEE_HEIGHT active):
#      4,500  BLOCK_BYTES_RAISE_HEIGHT
#
# Dependency invariants (enforced via load-time asserts where
# declared):
#   * SEED_DIVESTMENT_REDIST_HEIGHT  >= SEED_DIVESTMENT_RETUNE_HEIGHT
#   * VALIDATOR_REGISTRATION_BURN_HEIGHT > MIN_STAKE_RAISE_HEIGHT
#   * BLOCK_BYTES_RAISE_HEIGHT > LINEAR_FEE_HEIGHT
#   * All heights < BOOTSTRAP_END_HEIGHT (105,192)
#   * Honest-node upgrade runway: the 50,000-block rule from the
#     original schedule is relaxed during bootstrap.  With only two
#     operator-controlled validators, a sub-5k-block runway is
#     acceptable — the rule scales with validator-set size and
#     coordination cost, both minimal here.
#   * LINEAR_FEE_HEIGHT > FLAT_FEE_HEIGHT is NO LONGER required.  In
#     compressed schedules Tier 7 is intentionally unreachable; the
#     fee-routing code already prefers LINEAR first.
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
UNBONDING_PERIOD_EXTENSION_HEIGHT = 600  # Tier 1 (compressed: was 50_000)

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
    615,  # Tier 2 — fast-forwarded for live ReactTx test
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
ATTESTER_REWARD_SPLIT_HEIGHT = 706  # Tier 4 — fast-forwarded for 1.26.0 hard fork sweep

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
TREASURY_REBASE_HEIGHT = 704  # Tier 3 — fast-forwarded for 1.26.0 hard fork sweep
TREASURY_REBASE_BURN_AMOUNT = 33_000_000  # 40M - 33M = 7M ≈ 5% of 140M
TREASURY_MAX_SPEND_BPS_PER_EPOCH = 100    # LEGACY — see get_treasury_max_spend_bps_per_epoch
TREASURY_SPEND_CAP_EPOCH_BLOCKS = FINALITY_INTERVAL  # 100-block cadence

# ── Supply Reconciliation Hard Fork (1.50.0) ────────────────────────────
#
# Mainnet was launched with the original GENESIS_SUPPLY = 1_000_000_000
# and an allocation table that distributed only ~88.5M tokens (founder
# 47.5M staked + treasury 40M + scattered ~1M).  When the 1.26.0 fork
# rebased GENESIS_SUPPLY from 1B to 140M (chaindb.migrate_phantom_supply_
# if_needed), the migration assumed the 140M figure was correct because
# that's what the canonical mainnet config said -- but the ACTUAL
# allocation only ever summed to ~88.5M.  After the 33M treasury rebase
# burn, total_supply = 107M while actual buckets only ever held ~55.5M:
# a permanent ~47.5M phantom that the 1.49.0 supply-conservation
# invariant correctly began flagging.  See ROOT-CAUSE in CHANGELOG 1.50.0.
#
# The phantom does not affect any user balance (it is purely a counter
# bug in total_supply), but it inflates every "% of supply" denominator
# in the fee model, governance thresholds, and analytics -- the exact
# class of distortion the 1.26.0 phantom-migration was trying to fix.
#
# At block_height == SUPPLY_RECONCILIATION_HEIGHT, every node:
#   * computes actual via the SAME sum that
#     ``Blockchain.check_supply_conservation()`` uses
#     (non_treasury_balances + treasury + staked + pending_unstakes
#     + archive_reward_pool + lottery_prize_pool).
#   * sets self.supply.total_supply = actual.
#   * persists the new total_supply via supply_meta.set_supply_meta
#     so a subsequent restart rehydrates the corrected value.
#   * logs delta = post - pre at WARNING with the breakdown.
#
# Sum-equals-conservation-sum is intentional: post-reconciliation the
# conservation invariant passes by construction, and the cross-reference
# test (test_supply_conservation_pool_coverage) guarantees every
# total_supply mutation site has a corresponding bucket counted in the
# conservation sum.  The two together give a closed system.
#
# Idempotent: guarded by SupplyTracker.supply_reconciliation_applied,
# which is reorg-safe (snapshotted with the supply state).  An adjacent
# re-apply at the same height is a no-op.
#
# Operators MUST set this above the current chain tip with enough
# runway for both validators to upgrade (per CLAUDE.md release
# procedure) before activation.  Current mainnet tip ~1351 (2026-05-03);
# 5000 gives ~25 days of runway at 600s/block.
SUPPLY_RECONCILIATION_HEIGHT = 1708  # Compressed 2026-05-05 in 1.55.1 sweep — was 5000

# Supply-reconciliation FIX (1.58.4 hard fork).
#
# The 1.50.0 SUPPLY_RECONCILIATION_HEIGHT rebase set ``total_supply``
# to match the bucket-sum invariant (``check_supply_conservation``)
# but did NOT bump ``total_burned`` by the same delta — so the
# SCALAR invariant ``total_supply == GENESIS_SUPPLY + total_minted -
# total_burned`` was left broken by exactly the rebase delta.  The
# scalar invariant fires at the END of every ``_apply_block_state``;
# at the activation block itself (``SUPPLY_RECONCILIATION_HEIGHT``)
# the check runs BEFORE the reconciliation (the rebase is called from
# ``_append_block`` after ``_apply_block_state`` returns) so it
# passes.  The very NEXT block trips the check with a
# ``ChainIntegrityError`` and the chain wedges.
#
# Mainnet realized this incident on 2026-05-06: the rebase at block
# 1708 set ``total_supply`` from ~107M to ~59.5M (delta -47,494,983)
# without bumping ``total_burned``; block 1709's apply tripped the
# scalar check and both validators wedged at height 1709 indefinitely.
#
# This fix: at ``SUPPLY_RECONCILIATION_FIX_HEIGHT`` a one-shot bumps
# ``total_burned`` by the gap (or ``total_minted`` if the gap is
# negative — defensive, not expected on the realized mainnet
# trajectory) to restore the scalar invariant.  Runs at the START
# of ``_apply_block_state`` (alongside other one-shot activation
# hooks) so the rest of the apply path — including the end-of-apply
# scalar check — sees the corrected state.
#
# Activation = 1709: the next block to be applied on mainnet (block
# 1708 is the wedged-on tip; block 1709 is what validators are
# repeatedly failing to apply).  Mainnet recovery: validators
# upgrade to the fix release, the same-height-sign-guard at 1709 is
# manually reset operator-side, and the next slot timer fires a
# fresh proposal at height 1709 whose apply succeeds because the
# fix establishes the scalar invariant before the per-block
# mutations run.
#
# Idempotent via ``self.supply.supply_reconciliation_fix_applied``;
# snapshotted for reorg safety alongside ``treasury_rebase_applied``
# and ``supply_reconciliation_applied`` so a rolled-back fix block
# correctly un-flips the flag for the canonical replay.
SUPPLY_RECONCILIATION_FIX_HEIGHT = 1709  # Tier 52 — 1.58.4 hotfix.

assert SUPPLY_RECONCILIATION_FIX_HEIGHT >= SUPPLY_RECONCILIATION_HEIGHT, (
    f"SUPPLY_RECONCILIATION_FIX_HEIGHT "
    f"({SUPPLY_RECONCILIATION_FIX_HEIGHT}) must be >= "
    f"SUPPLY_RECONCILIATION_HEIGHT ({SUPPLY_RECONCILIATION_HEIGHT}) — "
    f"the fix only makes sense at or after the original reconciliation "
    f"has fired (the broken scalar state IS a consequence of the "
    f"original reconciliation)"
)

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
# Post-seed-divestment founder stake is ~7% of supply staked (10M of
# ~95M post-burn supply) + ~60% pre-retune stake → founder individually
# approaches the 2/3 supermajority threshold during the bleed and IS
# governance until divestment completes.  The spend-rate cap is
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
TREASURY_CAP_TIGHTEN_HEIGHT = 703                     # Tier 1 — fast-forwarded for 1.26.0 hard fork sweep.  Constraints:
                                                      # (1) > GOVERNANCE_VOTING_WINDOW (1008) so
                                                      # existing treasury-spend tests with ~1014
                                                      # close-blocks don't trip the new 5%-annual
                                                      # cap on small test treasuries; (2) <=
                                                      # TREASURY_REBASE_HEIGHT (1300) so the per-
                                                      # epoch cap is already tightened to 0.1% by
                                                      # the time the rebase fork's per-epoch logic
                                                      # activates -- treasury-cap-tightening tests
                                                      # rely on this ordering.  (compressed: was 52_000)


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
ATTESTER_FEE_FUNDING_HEIGHT = 707  # Tier 4 — fast-forwarded for 1.26.0 hard fork sweep

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
ATTESTER_REWARD_CAP_HEIGHT = 709  # Tier 4 — fast-forwarded for 1.26.0 hard fork sweep

assert 0 < PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH <= 10_000, (
    "cap must be a positive basis-point fraction <= 100%"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 45 — per-validator attester cap retune (5000 bps post-activation)
# ─────────────────────────────────────────────────────────────────────
# Defect the Tier 4 cap was sized for committees of ~128 members, where
# each validator's per-slot reward is small and 100 bps (1%) of the
# epoch pool is plenty of headroom for an honest, broadly-distributed
# attester to earn its full pro-rata share across a 100-block epoch.
# At today's mainnet committee size of 2 (`min(eligible_validators,
# 128)` resolves to 2 with two staked validators), per-slot reward is
# roughly half the attester pool.  That hits the 100 bps cap by block
# ~3 of every 100-block epoch and burns the rest of the validator's
# legitimate rewards for the next 97 blocks.  ~79% of attester issuance
# evaporates per epoch under the legacy constant.
#
# Fix raise the cap to 5000 bps (50% of the epoch pool per entity) at
# a coordinated fork height.  At committee=2, that gives each honest
# validator headroom to earn its pro-rata ~50% share across the full
# epoch without burning.  At committee=128, the cap is still well below
# any individual entity's reachable share (each member earns ~1/128 of
# the pool = ~0.78%, far under 50%) so the sybil/concentration defense
# the Tier 4 cap was designed for is preserved at its target committee
# size — the cap remains a strict upper bound, just one that doesn't
# trip during legitimate bootstrap operation.
#
# Reward-curve SHAPE is unchanged this is a single-knob retune of the
# per-entity cap, not a touch on smooth-V2 / floor / halving / any
# anchored economics constant.
#
# Pre-activation byte-identical to the legacy 100 bps path.
PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45 = 5000  # 50% of epoch pool
PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT = 1707  # Tier 45 — compressed 2026-05-05 in 1.55.1 sweep (was 4534)

assert 0 < PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45 <= 10_000, (
    "Tier 45 cap must be a positive basis-point fraction <= 100%"
)
assert (
    PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45
    > PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH
), (
    "Tier 45 retune must RAISE (not lower) the per-validator cap — the "
    "legacy 100 bps was sized for committees of 128 and starves "
    "validators at today's committee size of 2; lowering it under the "
    "fork would deepen the bug the tier is designed to fix"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 46: SetAuthorityKey rebind requires cold-key counter-signature
# ─────────────────────────────────────────────────────────────────────
# Defends against the validator-collusion / coerced-operator threat
# (PRIMARY adversary in CLAUDE.md) when the lever is the validator's
# own hot key.
#
# The shipped code path makes SetAuthorityKey signed by the entity's
# HOT signing key only, with no requirement that the EXISTING cold
# authority key counter-sign a re-binding to a new cold key. Result:
# a hot-key compromise is operationally equivalent to a cold-key
# compromise. An attacker who steals the hot key (which lives on the
# 24/7 online validator) can broadcast SetAuthorityKey with
# new_authority_key=ATTACKER_COLD and inherit all cold-key powers
# (Unstake, Revoke). The legitimate operator can no longer revoke
# (Revoke is signed by the now-attacker cold key) or unstake. The
# defense-in-depth that the hot/cold split is supposed to provide
# does not actually exist.
#
# Fix: at/above AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT, a
# SetAuthorityKey that *re-binds* an entity's already-installed
# authority key MUST carry a second signature, verified under the
# CURRENTLY-installed cold key. The first-time install path
# (authority_keys[entity_id] not yet set) is unchanged — that path is
# the bootstrap, the user is authenticating "as themselves" with the
# only key they have.
#
# Wire format (post-activation): the existing primary signature field
# is byte-identical; the new cold counter-signature appends as an
# optional trailer disambiguated by a 0x01 marker (mirrors the
# Tier 26 RevokeTransaction window-marker pattern). Pre-activation
# blobs (no trailer) round-trip byte-identically to the pre-fork
# encoding; replay determinism on historical blocks is preserved.
#
# Activation: AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT = 5234 — +700
# spacing above Tier 45 (4534), matching the cohort spacing used
# throughout the recent fork ladder. Current mainnet tip is ~860, so
# every live operator has multiple weeks of runway to upgrade their
# cmd_set_authority_key invocation to attach a cold-key counter-sig
# before the gate binds.
AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT = 1709  # Tier 46 — compressed 2026-05-05 in 1.55.1 sweep (was 5234)

# ─────────────────────────────────────────────────────────────────────
# Dormancy-filtered active-supply controller (hard fork — Tier 47)
# ─────────────────────────────────────────────────────────────────────
# Rationale: see CLAUDE.md anchor "Issuance targets a stable active
# supply, not a fixed schedule."  Pre-fork issuance is a fixed schedule
# (BLOCK_REWARD with halving + a one-sided deflation-floor lever); both
# were partial mechanisms aimed at the supply-stability problem.  Post-
# fork the chain replaces them with a single controller that targets a
# fixed nominal point for `active_supply` (= sum of balances filtered by
# how recently their owner was active).  Burns and lost-key dormancy
# pull active supply down; the controller mints to refill toward the
# target.  The user-visible promise is "X tokens always means roughly X
# tokens" — fixed-token fees, stake thresholds, and proposal costs keep
# their economic weight forever because the denominator is held
# constant.
#
# Activity definition (signed action by the entity required — receiving
# tokens does NOT count, since that would let an attacker keep dormant
# wallets "active" by sending dust):
#   * outgoing tx signed by the entity (transfer, message, react,
#     stake, unstake, key-rotation, set-authority, revoke,
#     governance proposal/vote)
#   * attestation by the entity (validators)
#   * block proposal by the entity (validators)
#
# Smooth taper, integer-deterministic:
#   age = current_height - last_active_height
#   if age <  WINDOW - TAPER:        weight_bps = 10_000  (full active)
#   if WINDOW - TAPER <= age < WINDOW: weight_bps = 10_000 * (WINDOW - age) // TAPER
#   if age >= WINDOW:                weight_bps = 0       (fully dormant)
#   active_supply = Σ balance × weight_bps // 10_000
#
# Dormancy is observability of the supply metric only — dormant
# balances are NEVER confiscated.  They continue to exist with their
# full balance and rejoin active_supply the moment the owner transacts.
# Bitcoin's "lost coins" treatment, made explicit at the protocol
# level.
#
# Controller (proportional, integer-deterministic):
#   gap = max(0, TARGET_ACTIVE_SUPPLY - active_supply)
#   issuance = min(MAX_ISSUANCE_PER_BLOCK, gap * K_NUM // K_DEN)
# At target, gap=0, issuance=0 — validators run on fees alone (the
# fee market is the long-term security budget; issuance's purpose is
# supply integrity, not validator pay).  No floor — issuance is
# allowed to drop to zero indefinitely if active_supply is at target.
#
# Activation backfill: at block_height == DORMANCY_CONTROLLER_HEIGHT,
# every entity with a balance > 0 has its last_active_height stamped to
# the activation height (one-shot, idempotent flag).  Active_supply at
# activation therefore equals the sum of post-fork balances; the
# controller starts from gap≈0 and refills only as burns / dormancy
# accumulate over time.  Same pattern as treasury_rebase / registration-
# burn grandfather hard forks — flag snapshotted with the supply state
# for reorg safety.
#
# State-tree fold: post-activation, _leaf_value() folds
# last_active_height into the per-entity leaf hash so state-synced
# nodes inherit the same dormancy state as replaying nodes.  Pre-
# activation the leaf format is byte-identical to the legacy hash
# (the new field is defaulted to 0 and excluded from the hash by a
# height gate inside _leaf_value).
#
# Halving + deflation-floor retirement: post-activation, both legacy
# levers are bypassed.  calculate_block_reward() routes through the
# controller and returns its output directly; the BLOCK_REWARD /
# HALVING_INTERVAL / BLOCK_REWARD_FLOOR / DEFLATION_FLOOR_V2 paths are
# never read post-fork.  Constants retained as imports because the
# legacy code path remains live for replay of pre-fork heights.
#
# Activation: DORMANCY_CONTROLLER_HEIGHT = 5934 — +700 spacing above
# Tier 46 (5234), matching the cohort spacing used throughout the
# recent fork ladder.  Current mainnet tip is ~860, so live operators
# have many weeks of runway to upgrade.

# Activation height for the controller and all dormancy bookkeeping.
DORMANCY_CONTROLLER_HEIGHT = 1710  # Tier 47 — compressed 2026-05-05 in 1.55.1 sweep (was 5934)

# Dormancy window: how long a balance can sit idle before its weight
# tapers out of active_supply.  Set on the centuries horizon per
# CLAUDE.md anchor — decades, not years.  At 600s/block this is
# 1_314_000 blocks ≈ 25 years.  Loosening later (raising the window)
# only un-reclassifies dormant balances; tightening it reclassifies
# live holders, which is the operationally harder direction — so
# pick conservatively at fork time.
DORMANCY_WINDOW_BLOCKS = 1_314_000

# Smooth taper width.  A balance whose age is within the last
# TAPER_BLOCKS of the WINDOW gets a linearly-decreasing weight from
# 10_000 bps down to 0 bps.  Avoids a cliff at exactly WINDOW where a
# balance flips from 100% active to 0% active in one block, which
# would create a controller jitter and a perverse incentive to time
# transactions exactly at the boundary.  10% of the window
# (~2.5 years at 600s blocks) is generous.
DORMANCY_TAPER_BLOCKS = 131_400

# Target nominal active supply — the value the controller targets
# forever.  Set to ``GENESIS_SUPPLY - TREASURY_ALLOCATION = 100M`` so
# the TARGET aligns with ``compute_active_supply``'s definition: the
# active-supply measure skips ``TREASURY_ENTITY_ID`` (treasury is
# governance state, not a live economic user — see the rationale in
# ``inflation.compute_active_supply``), so the controller's TARGET
# must use the same definition or the gap perma-binds at one of the
# extremes.  At mainnet activation (founder=100M + treasury=40M, both
# stamped active by the one-shot backfill), active=100M=TARGET, gap=0,
# controller mints zero — and only mints as real dormancy or burns
# open the gap, exactly as the "stable active supply" anchor intends.
#
# Pre-retune (1.58.1) value was 140M = GENESIS_SUPPLY: at activation
# active=100M (treasury excluded), gap=40M, raw_issuance=2000/block,
# clamped to MAX=500/block — the controller pegged at MAX for ~60K
# blocks (~1.14 yr) until the founder's balance grew to ~130M, at
# which point convergence began.  ~30M new tokens were minted over
# the bind window, ~99.99% of which would have accrued to the founder
# via the sole-proposer share + stake-pro-rata attester pool, ratchet-
# ing founder concentration 71.4% → 79.2% — the *opposite* direction
# the stake-concentration soft-cap and founder-handoff anchors want.
# Surfaced by audit r24 top-3 #1.
#
# Pure constant retune; no consensus-shape change.  Rides under the
# existing Tier 47 height — pre-fork heights replay byte-identically
# because ``compute_dormancy_issuance`` is height-gated and Tier 47
# has not yet activated on mainnet at edit time, so no historical
# block-replay output changes.  Governance may retune via a future
# fork; the fixed-target shape is anchored.
DORMANCY_TARGET_ACTIVE_SUPPLY = 100_000_000

# Controller gain.  Per-block issuance = gap * K_NUM // K_DEN, where
# gap = TARGET - active_supply.  K = 1/20_000 chosen so the controller
# halves the gap roughly quarterly at 600s/block.  Tuning retune
# (not a shape change — proportional refill is anchored): the prior
# 1/100_000 gain combined with the 64-token ceiling left the
# controller saturated for years under the documented 10–15M
# tokens/yr burn estimate (see TARGET_CIRCULATING_SUPPLY_FLOOR
# commentary below), so the gap-tracking property the controller
# was sized for never bound.  Tightening the gain restores
# responsive tracking under realistic founder-dormancy and long-
# burn scenarios.  Governance can retune again via a future fork.
DORMANCY_CONTROLLER_K_NUM = 1
DORMANCY_CONTROLLER_K_DEN = 20_000

# Per-block issuance ceiling.  Hard cap so a pathological state
# (active_supply briefly far below target due to a bug or large slash)
# can't trigger a runaway mint.  500 tokens/block ≈ 26.3M tokens/yr
# at 52,560 blocks/yr — roughly 2× the documented 10–15M tokens/yr
# burn estimate, so the controller can actually close the gap rather
# than peg at MAX while supply continues falling.  Prior value (64
# tokens/block ≈ 3.37M/yr) was 3–5× too low: the controller
# saturated whenever gap ≥ 6.4M (~4.6% of target), which under
# realistic burn meant net active supply continued dropping ~7–12M/yr
# indefinitely, breaking the anchored "stable active supply" promise
# within a decade post-activation.  Tuning retune (not a shape
# change) per the CLAUDE.md anchor that controller curve, ceiling,
# and window are tuning knobs in code.  Safe to change in place —
# Tier 47 has not yet activated on mainnet at edit time, so no
# historical block-replay output changes.
DORMANCY_MAX_ISSUANCE_PER_BLOCK = 500

assert DORMANCY_CONTROLLER_HEIGHT > AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT, (
    "DORMANCY_CONTROLLER_HEIGHT must follow Tier 46 — operators upgrade "
    "through prior forks before the controller binds, and the +700 "
    "cohort spacing is preserved"
)
assert 0 < DORMANCY_TAPER_BLOCKS < DORMANCY_WINDOW_BLOCKS, (
    "DORMANCY_TAPER_BLOCKS must be a non-empty proper subset of the "
    "window — taper width must leave a non-empty 'fully active' interval"
)
assert DORMANCY_CONTROLLER_K_NUM > 0 and DORMANCY_CONTROLLER_K_DEN > 0, (
    "controller gain must be positive — a zero or negative gain breaks "
    "the supply-replenishment invariant"
)
assert DORMANCY_TARGET_ACTIVE_SUPPLY > 0, (
    "DORMANCY_TARGET_ACTIVE_SUPPLY must be positive — a zero or "
    "negative target makes 'gap' negative for any positive supply, "
    "and the controller would never mint"
)
assert DORMANCY_MAX_ISSUANCE_PER_BLOCK > 0, (
    "DORMANCY_MAX_ISSUANCE_PER_BLOCK must be positive — a zero ceiling "
    "would prevent the controller from ever minting, defeating the "
    "purpose of the entire fork"
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
FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = 708  # Tier 4 — fast-forwarded for 1.26.0 hard fork sweep (must follow FINALITY_VOTE_CAP_HEIGHT)

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
FINALITY_VOTE_CAP_HEIGHT = 700  # Tier 1 — fast-forwarded for 1.26.0 hard fork sweep

# ─────────────────────────────────────────────────────────────────────
# Seed-validator stake ceiling (founder re-stake defense, hard fork)
# ─────────────────────────────────────────────────────────────────────
# SEED_DIVESTMENT_END_HEIGHT terminates the forced divestment schedule
# with the founder's seed entity_id locked at
# SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE (= 10M) staked tokens.
# Nothing in the legacy StakeTransaction validation prevents the
# founder from ACCUMULATING tokens externally (purchases, unstake-
# then-transfer, OTC) and re-staking them — i.e. the entire dilution
# the divestment schedule produced can be silently undone by a normal
# stake tx that pushes the seed back above the floor.
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
SEED_MAX_STAKE_CEILING = SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE   # 10_000_000
SEED_STAKE_CEILING_HEIGHT = 900  # Tier 1 (compressed: was 56_000)

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
DEFLATION_FLOOR_HEIGHT = 711  # Tier 5 — fast-forwarded for 1.26.0 hard fork sweep (legacy v1; superseded by v2)

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
DEFLATION_FLOOR_V2_HEIGHT = 712             # Tier 5 — fast-forwarded for 1.26.0 hard fork sweep (must follow DEFLATION_FLOOR_HEIGHT)

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
ATTESTER_CAP_FIX_HEIGHT = 710               # Tier 4 — fast-forwarded for 1.26.0 hard fork sweep (must follow ATTESTER_REWARD_CAP_HEIGHT)

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
VALIDATOR_REGISTRATION_BURN_HEIGHT = 713  # Tier 6 — fast-forwarded for 1.26.0 hard fork sweep (must follow MIN_STAKE_RAISE_HEIGHT)

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
FLAT_FEE_HEIGHT = 616   # Tier 7 — fast-forwarded for live ReactTx test (must follow FEE_INCLUDES_SIGNATURE_HEIGHT=615)

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
# Linear-in-stored-bytes fee floor — supersedes the flat per-tx floor
# ─────────────────────────────────────────────────────────────────────
# At/after LINEAR_FEE_HEIGHT the fee floor becomes:
#
#     fee_floor = BASE_TX_FEE + FEE_PER_STORED_BYTE * len(stored_message)
#
# Paired with the cap raise (MAX_MESSAGE_CHARS 280 → 1024) and the
# byte-budget raise (MAX_BLOCK_MESSAGE_BYTES 10_000 → 15_000), this
# unlocks short-post-scale messages without giving away storage:
# longer messages pay proportionally more for the bytes they pin to
# permanent state.
#
# Why linear and not flat:
#   * Under the raised cap, a flat per-tx floor under-prices long
#     messages — a 1024-byte tx and a 10-byte tx pay the same minimum,
#     and rational users fill the cap, donating bloat.
#   * Linear is the simplest formula that prices stored bytes honestly.
#     Quadratic distorts the market without adding bloat discipline
#     (we already have a hard per-message cap).
#   * The base term amortizes the per-tx WOTS+ signature overhead
#     (~1.1 KB regardless of message size); without it, tiny messages
#     would pay near-zero for the sig bloat they still impose.
#
# Calibration philosophy: keep the floor "very low" — symbolic, not a
# spam deterrent on its own. The market (EIP-1559 base-fee + tip)
# prices above the floor whenever there's competition. The floor only
# guarantees no-free-txs; it doesn't try to set the equilibrium price.
#
# Legacy constants (MIN_FEE, MIN_FEE_POST_FLAT, FEE_PER_BYTE,
# FEE_QUADRATIC_COEFF) are retained so pre-fork blocks replay
# deterministically under the rule current at their height.
#
# Operators MUST replace the placeholder height with a concrete
# coordinated-fork height before deploying to mainnet.  Per the FORK
# SCHEDULE: Tier 8, target 100_000 — after the last Tier 7 fork
# (FLAT_FEE_HEIGHT) and before BOOTSTRAP_END_HEIGHT.
BASE_TX_FEE = 10                 # per-tx base — sig-overhead amortization
FEE_PER_STORED_BYTE = 1          # per-byte component (charged on STORED, not plaintext)
# Pulled forward from 100_000 so the 1024-char cap becomes testable inside
# the bootstrap window.  LINEAR_FEE_HEIGHT now PRECEDES FLAT_FEE_HEIGHT; the
# Tier 7 flat-fee intermediate is effectively retired — at its activation
# height (98_000) the linear rule is already in force, so the flat floor
# never applies in production.  Pre-linear heights still replay under
# their original legacy-quadratic rules unchanged.
LINEAR_FEE_HEIGHT = 300  # Tier 8 (bootstrap-compressed: pulled forward from 4_300 so a live operator test of the Tier 10 prev-pointer feature is viable within bootstrap — see CLAUDE.md fork schedule for runway notes)

assert BASE_TX_FEE >= 0, "BASE_TX_FEE cannot be negative"
assert FEE_PER_STORED_BYTE >= 1, (
    "FEE_PER_STORED_BYTE must be at least 1 — a zero per-byte rate "
    "lets long messages share the same floor as short ones, which is "
    "the under-pricing failure mode the linear rule is designed to fix"
)
# NOTE: Prior schedules required LINEAR_FEE_HEIGHT > FLAT_FEE_HEIGHT so the
# flat-fee intermediate had a live window.  In bootstrap-compressed
# schedules this invariant is deliberately inverted — the flat-fee
# intermediate is retired before it ever activates.  The fee-routing code
# in ``calculate_min_fee`` already checks LINEAR first, so LINEAR ≤ FLAT
# is safe: linear takes precedence at every height ≥ LINEAR_FEE_HEIGHT.


# ─────────────────────────────────────────────────────────────────────
# Tier 9 — throughput raise (wider per-block budgets)
# ─────────────────────────────────────────────────────────────────────
# At/after BLOCK_BYTES_RAISE_HEIGHT the per-block throughput budgets
# widen: MAX_TXS_PER_BLOCK 20 → 45, MAX_BLOCK_MESSAGE_BYTES 15k → 45k,
# MAX_BLOCK_SIG_COST 100 → 250.  The constants above already carry the
# post-fork values (they are monotone-safe bumps — pre-fork blocks
# satisfied stricter bounds that trivially still satisfy the looser
# ones).  This section carries the height-gated knobs that DO change
# consensus-visible behavior with the fork:
#
#   * FEE_PER_STORED_BYTE_POST_RAISE — per-byte fee floor rises 1 → 3,
#     preserving bloat discipline under the wider cap.  Without this,
#     a 3× per-block byte budget at a flat 1/byte floor would let a
#     block carry ~3× more permanent-state bytes at the same floor
#     price.
#   * TARGET_BLOCK_SIZE_POST_RAISE — EIP-1559 target climbs 10 → 22,
#     tracking ~50% of the new MAX_TXS_PER_BLOCK=45.  Without this the
#     base fee would saturate upward permanently at the old 10-tx
#     target once the network fills beyond 10 txs/block.
#
# Per-message cap stays at MAX_MESSAGE_CHARS=1024 — this is a
# THROUGHPUT raise, not a message-size raise.
#
# Ordering:
#   * BLOCK_BYTES_RAISE_HEIGHT > LINEAR_FEE_HEIGHT — the linear fee
#     formula must be active when the per-byte rate multiplies, since
#     the post-raise branch reads BASE_TX_FEE and the post-raise
#     per-byte rate.
BLOCK_BYTES_RAISE_HEIGHT = 350           # Tier 9 (bootstrap-compressed: pulled forward from 4_500; rides on top of LINEAR_FEE_HEIGHT)
FEE_PER_STORED_BYTE_POST_RAISE = 3       # 3× Tier 8 floor — preserves bloat discipline under wider cap
TARGET_BLOCK_SIZE_POST_RAISE = 22        # ~50% of new MAX_TXS_PER_BLOCK = 45 (was 10, 50% of 20)

# Tier 10 — `prev` pointer activation.
# Enables a single 32-byte `prev` pointer on message transactions (tx
# version=2), forming a single-linked list of prior messages.  Strict:
# `prev` must resolve to a tx that already appears on-chain in a
# strictly earlier block (or same block at an earlier tx index).
# Bytes are charged at the per-stored-byte rate (33B: 1B presence flag +
# 32B tx_hash) but do NOT count against MAX_MESSAGE_CHARS — the cap is
# a human-content constraint, the pointer is structural metadata.
# Pre-activation: tx version must be 1 (no prev field).  Post-activation:
# version=2 is accepted; version=1 remains valid for prev-less txs.
PREV_POINTER_HEIGHT = 400                # Tier 10 (bootstrap-compressed: pulled forward from 6_000 for live operator testing)

# Tier 11: MessageTransaction first-send pubkey reveal.  Closes the
# receive-to-exist asymmetry that made TransferTransaction install the
# sender's pubkey on first outgoing tx but rejected MessageTransaction
# from any unknown entity.  At/after FIRST_SEND_PUBKEY_HEIGHT, a v3
# MessageTransaction may carry an optional sender_pubkey field; when
# the sender's entity_id is not yet on chain, the field is required and
# is installed on apply.  Mirrors TransferTransaction.sender_pubkey so
# the cold-start path "get tokens via faucet -> send first message"
# works in one round-trip instead of needing an explicit register-via-
# transfer hop first.
#
# Pre-activation: v3 txs are rejected.  Post-activation: v3 accepted;
# v1/v2 remain valid for senders already on chain.
FIRST_SEND_PUBKEY_HEIGHT = 500           # Tier 11 (bootstrap-compressed)

# Tier 12: international (UTF-8) message bodies.  Pre-activation:
# message plaintexts MUST be printable ASCII (codepoints 32-126) — the
# legacy rule, kept so historical blocks replay deterministically.
# Post-activation: plaintexts MUST be NFC-normalized UTF-8 whose
# codepoints fall under General_Category L*/M*/N*/P*/Zs (letters,
# marks, numbers, punctuation, space), plus a narrow allowlist of
# format characters required for script shaping (U+200C ZWNJ,
# U+200D ZWJ).  Bidi override / isolate characters
# (U+202A-U+202E, U+2066-U+2069) are explicitly rejected as spoofing
# vectors.  All `S*` (symbols, including emoji and currency), `C*`
# (controls, surrogates, private-use, unassigned) outside the ZWJ/ZWNJ
# allowlist, and Zl/Zp (line/paragraph separators) are rejected.
#
# Why structural categories rather than a script allowlist:
# "Allow Latin/Cyrillic/Arabic/CJK..." is a discretionary admission
# rule — moving the cutoff line is a political knob, and the project's
# audience (dissidents, coerced-speech contexts) is disproportionately
# small-population languages that a "popular scripts" cutoff would
# strand.  The L/M/N/P/Zs whitelist has no knob: every modern living
# language is structurally letters + marks + numbers + punctuation,
# and any future Unicode script automatically becomes valid without
# a config change.
#
# Storage: post-activation, the byte cap MAX_MESSAGE_CHARS still binds,
# but it now caps UTF-8-encoded plaintext bytes rather than ASCII
# characters.  The fee market already prices stored bytes via
# FEE_PER_STORED_BYTE_POST_RAISE, so the bloat-discipline math stays
# clean — a CJK user gets ~341 chars for the same byte budget an
# English user gets 1024 chars; each pays per byte for the storage
# they actually pin to permanent state.
INTL_MESSAGE_HEIGHT = 705               # Tier 12 — fast-forwarded for 1.26.0 hard fork sweep

# Tier 13 (Fork 1, audit finding #2): validator version signaling.
# At/after VERSION_SIGNALING_HEIGHT, blocks serialize under V2 wire
# format (BLOCK_SERIALIZATION_VERSION_V2) which carries a uint16
# validator_version field in the block header stamping the proposer's
# running release.  Pre-activation blocks remain V1 (no field).
#
# This fork itself does NOT consume the field for any consensus rule
# yet -- it only lays the wire-format groundwork.  The field exists so
# Fork 2 (the active-set liveness fallback, audit finding #1) can
# refuse to cross its own activation height until enough validators
# have signaled support, breaking the chicken-and-egg gap where every
# fork-coordination mechanism would itself need to be deployed via the
# unprotected mechanism it replaces.
#
# Runway: ~3000 blocks above the live tip (~451 at the time this
# constant was added).  20+ days at 10-minute blocks gives both
# operators comfortable time to upgrade without the protection of
# this very gate (which doesn't exist yet) -- manual coordination is
# the mitigation for fork-1 itself; subsequent forks use the gate.
VERSION_SIGNALING_HEIGHT = 620           # Tier 13 (Fork 1) — fast-forwarded for live ReactTx test

# Tier 14 — MessageTransaction signable-data length-prefix fix.
# Closes a tx_hash-collision hole in the legacy v1/v2/v3 _signable_data:
# `self.message` was concatenated raw with no length prefix, and the
# optional prev/sender_pubkey trailers have multiple legal byte
# lengths.  An attacker who induces a victim to sign carefully-
# structured bytes (or who controls part of the message content) can
# re-encode the same SIGNED bytes into a *different* parsed
# MessageTransaction (alt message length, alt ts/nonce/fee/prev,
# alt sender_pubkey).  Both wire forms hash to the same tx_hash;
# the WOTS+ signature verifies under both parses.  Mempool dedup
# then displaces the victim's intended tx with the attacker's
# alternate content.  Defect class: same length-prefix omission
# already fixed in M23 for Signature.canonical_bytes and the
# binary-hashes blob -- MessageTransaction was missed.
#
# Fix: TX_VERSION_LENGTH_PREFIX (v=4).  v4 _signable_data prepends
# `struct.pack(">H", len(self.message))` immediately before the
# message bytes, binding the length into the signed commitment so
# any alt parse necessarily produces a different signable-data byte
# string and a different tx_hash.
#
# Pre-activation: v4 admission is rejected (only v1/v2/v3 accepted
# under their own activation gates).  Historical replay of pre-v4
# blocks runs the legacy _signable_data path byte-for-byte
# unchanged.  At/after activation: v4 is the canonical version for
# new MessageTransactions; v1/v2/v3 remain ADMISSIBLE for backward
# compatibility (the chain has never gated v3 outbound to honest
# senders, and an attacker who can collide a v3 tx_hash with another
# v3 tx_hash gains nothing more than they could already), but the
# RECOMMENDED creation path emits v4.  A future tier can tighten
# this by REJECTING v3 admission; that's a separate consensus
# change.
MESSAGE_TX_LENGTH_PREFIX_HEIGHT = 621    # Tier 14 — fast-forwarded for live ReactTx test

assert MESSAGE_TX_LENGTH_PREFIX_HEIGHT > FIRST_SEND_PUBKEY_HEIGHT, (
    "MESSAGE_TX_LENGTH_PREFIX_HEIGHT must follow FIRST_SEND_PUBKEY_HEIGHT "
    "— v4 supersedes v3 as the canonical message tx version, but the "
    "v3 dispatch must already be live so honest senders can keep "
    "using v3 during the runway and historical v3 replay continues "
    "to work after the fork lands"
)
assert MESSAGE_TX_LENGTH_PREFIX_HEIGHT > VERSION_SIGNALING_HEIGHT, (
    "MESSAGE_TX_LENGTH_PREFIX_HEIGHT must follow VERSION_SIGNALING_HEIGHT "
    "— the wire-format gate is the foundation any future fork should "
    "ride on top of for coordinated upgrade signaling"
)

# Tier 15 — governance signable-data length-prefix fix.
# ProposalTransaction and TreasurySpendTransaction `_signable_data`
# concatenated variable-length `title` / `description` /
# `reference_hash` raw, with no length prefixes.  Two parses of the
# same signed bytes can therefore yield different (title, description,
# reference_hash) tuples while sharing the same tx_hash and signature.
# A relay that controls a propagation path can rewrite the on-chain
# text of any approved governance proposal -- voters approve one set
# of words, the chain stores another.  For binding TreasurySpend
# proposals (which auto-execute fund movement), a victim can be
# tricked into voting yes on a proposal whose displayed justification
# differs from any other validator's view of the same proposal_id,
# while the binding recipient_id and amount fields (fixed-width) stay
# the same.
#
# Same defect class as the v4 message-tx fix
# (MESSAGE_TX_LENGTH_PREFIX_HEIGHT).
#
# Fix: GOVERNANCE_TX_VERSION_LENGTH_PREFIX (v=2) hard fork.  v2
# `_signable_data` length-prefixes title (>H), description (>I), and
# reference_hash (>B) so the parsed tuple is uniquely committed.
# Pre-activation: v2 admission is rejected; only v=1 governance txs
# are accepted under their existing rules.  At/after activation: v2
# is the canonical version for new proposals; v1 remains admissible
# for backward compatibility but the recommended creation path emits
# v2 (and the founder-led governance regime should use only v2 for
# any treasury spend during the bootstrap window).
GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT = 622    # Tier 15 — fast-forwarded for live ReactTx test

assert GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT > MESSAGE_TX_LENGTH_PREFIX_HEIGHT, (
    "GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT must follow "
    "MESSAGE_TX_LENGTH_PREFIX_HEIGHT — same defect class as v4 message "
    "tx, gated behind it so the runway windows don't overlap"
)

# ─── Tier 16 — Market-driven fee floor ────────────────────────────────
# At/after MARKET_FEE_FLOOR_HEIGHT the protocol-level fee floor for
# MessageTransactions collapses to a flat MARKET_FEE_FLOOR=1 token,
# regardless of message size.  The linear-in-stored-bytes formula
# (BASE_TX_FEE + FEE_PER_STORED_BYTE × len) is retired as the *floor* —
# it remains only for replay of pre-fork blocks under the height-gated
# rule current at their height.
#
# Rationale: the linear floor was trying to do two jobs at once —
# keep zero-fee txs out of the mempool, and discipline long-message
# bloat by per-byte pricing.  The first is the only job a floor needs
# to do; the second is already done by:
#
#   * MAX_BLOCK_MESSAGE_BYTES per block — a hard ceiling on bytes
#     pinned per ~10-min window, regardless of fee paid.  This is the
#     real spam ceiling: an attacker willing to pay any price still
#     cannot pin more than 45_000 bytes/block × 144 blocks/day ≈
#     6.5 MB/day, ≈ 2.4 GB/year.  That number is set by block timing,
#     not by the fee floor.
#   * EIP-1559 base fee — automatically rises 12.5% per over-target
#     block under congestion and decays 12.5% per under-target block,
#     pricing the marginal byte at whatever clears the queue.  The
#     market sets the actual cost-per-byte during the only times that
#     matter (when blocks are full); the protocol floor only sets
#     behavior during the times that don't matter (when blocks are
#     empty and bloat-discipline is moot).
#
# Setting the floor to 1 (rather than 0) preserves the no-free-tx
# invariant — every tx still pays at least 1 token of fee, so the
# zero-fee mempool-DoS path stays closed — without the protocol
# trying to set the equilibrium price.
#
# Type-specific surcharges (NEW_ACCOUNT_FEE, GOVERNANCE_PROPOSAL_FEE,
# KEY_ROTATION_FEE, etc.) are unaffected: they price externalities
# specific to those tx types (permanent state entry, binding governance
# vote, key rotation) and live above the protocol floor.
#
# Legacy constants (BASE_TX_FEE, FEE_PER_STORED_BYTE,
# FEE_PER_STORED_BYTE_POST_RAISE, MIN_FEE_POST_FLAT, MIN_FEE,
# FEE_PER_BYTE, FEE_QUADRATIC_COEFF) are retained so pre-fork blocks
# replay deterministically under the rule current at their height.
#
# Activation: ride above Tier 15 (GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT
# = 5000).  Runway window 5000→7000 = ~2000 blocks (~14 days at
# 600s/block) — operators upgrade in that window.
MARKET_FEE_FLOOR = 1            # post-Tier-16 protocol fee floor (flat, all sizes)
MARKET_FEE_FLOOR_HEIGHT = 623   # Tier 16 — fast-forwarded for live ReactTx test

assert MARKET_FEE_FLOOR >= 1, (
    "MARKET_FEE_FLOOR must be at least 1 — a zero floor reopens the "
    "zero-fee-mempool-DoS path the floor exists to close"
)
assert MARKET_FEE_FLOOR_HEIGHT > GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT, (
    "MARKET_FEE_FLOOR_HEIGHT must follow GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT "
    "— Tier 16 retires the linear fee floor and rides on top of the "
    "established fork schedule"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 17: ReactTransaction (user-trust + message-react votes)
# ─────────────────────────────────────────────────────────────────────
# Activation gate for the ReactTransaction tx kind.  A ReactTx
# represents a single voter casting a {clear, up, down} signal against
# either another entity (user-trust vote) or a message tx_hash
# (message-react vote).  See messagechain/core/reaction.py for the full
# field layout, signing rules, and validation.
#
# Aggregation semantics: each (voter, target) pair has a single latest
# choice in consensus state; superseding votes mutate the entry rather
# than appending to a tally.  Per-target sums (user_trust_score,
# message_score) are denormalised inside the same state map and
# committed into the chain's state root, so light clients can verify a
# score with a Merkle proof rooted in any block header at or after the
# activation height.
#
# Spam discipline: ReactTx pays the same MARKET_FEE_FLOOR-driven fee
# as every other tx kind; the byte cost is permanent (every vote and
# every supersede is stored forever) so flipping a vote pays full
# freight, which is the whole anti-bulk-vote lever (per the settled
# fee-only anti-spam rule).
#
# Activation: rides above Tier 16 (MARKET_FEE_FLOOR_HEIGHT = 7000).
# Runway 7000 → 9000 = ~2000 blocks (~14 days at 600 s/block) to give
# operators time to upgrade past the prior fork before the new tx kind
# starts admitting.
REACT_TX_HEIGHT = 624   # Tier 17 — fast-forwarded for live ReactTx test

# ReactTransaction choice byte values (packed into the flags field —
# see reaction.py).  CLEAR retracts a prior vote; UP and DOWN are the
# two signed positions.  Numeric values are fixed at the protocol
# boundary so the linear score formula
#     +1 for UP, -1 for DOWN, 0 for CLEAR
# is unambiguous across implementations.
REACT_CHOICE_CLEAR = 0
REACT_CHOICE_UP = 1
REACT_CHOICE_DOWN = 2

# ReactTransaction target-type bit (packed into the flags field).
# 0 = the 32-byte target is a message tx_hash (message-react vote);
# 1 = the 32-byte target is an entity_id (user-trust vote).  The bit
# is committed into the tx hash so swapping target_type after signing
# is tamper-evident.
REACT_TARGET_MESSAGE = 0
REACT_TARGET_USER = 1

assert REACT_TX_HEIGHT > MARKET_FEE_FLOOR_HEIGHT, (
    "REACT_TX_HEIGHT must follow MARKET_FEE_FLOOR_HEIGHT — Tier 17 rides "
    "on the post-Tier-16 protocol fee floor; activating before the floor "
    "is in effect would let ReactTx admit under the legacy linear-fee "
    "rule, diverging from the floor the rest of the chain has settled on"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 18: unified fee market across Message + Transfer + React
# ─────────────────────────────────────────────────────────────────────
# Three coordinated changes that close the cross-kind market gap left
# by Tier 17.  Goal: every fee-bearing tx kind competes in ONE market,
# under ONE per-block scarcity, with ONE shared EIP-1559 signal —
# wallets bid honestly against each other regardless of tx kind, and
# the fee market is the only inclusion-priority signal.
#
# (1) Unified per-block byte budget
#     `MAX_BLOCK_TOTAL_BYTES` caps the SUM of serialized bytes across
#     every Message, Transfer, and React tx in a block.  Pre-Tier-18
#     blocks keep the per-kind caps (`MAX_BLOCK_MESSAGE_BYTES` for
#     messages, `MAX_TXS_PER_BLOCK` count for transfers/react).
#     Post-Tier-18 the per-kind rules still apply structurally, but
#     the binding scarcity is the unified byte ceiling — a hot lane
#     squeezes the others, forcing fungible auction behaviour.
#
# (2) EIP-1559 controller measures all three kinds
#     The base-fee controller's "block fullness" signal at and after
#     TIER_18_HEIGHT counts Message + Transfer + React tx counts
#     against `TARGET_BLOCK_SIZE_POST_RAISE`.  Pre-fork it stays
#     Message + Transfer (replay determinism on historical blocks).
#
# (3) REACT_FEE_FLOOR retires
#     At and after TIER_18_HEIGHT, ReactTx admission is gated by
#     `MARKET_FEE_FLOOR=1` (the same floor every other kind sees).
#     The legacy `REACT_FEE_FLOOR=10` constant is preserved for
#     pre-fork replay determinism only.  Type-specific surcharges
#     with real externalities (`NEW_ACCOUNT_FEE`, `KEY_ROTATION_FEE`,
#     `GOVERNANCE_PROPOSAL_FEE`) remain — those price actual costs
#     the market doesn't see.
#
# Activation: rides above Tier 17 (REACT_TX_HEIGHT = 9000) with a
# ~2000-block runway (~14 days at 600 s/block).
TIER_18_HEIGHT = 714  # Tier 18 — fast-forwarded for 1.26.0 hard fork sweep

# Unified per-block byte ceiling for the fee-bearing tx kinds.
#
# Sizing target: must bind under TWO-lane congestion (the typical
# organic high-load shape — e.g. messages + react both heated up by
# a viral thread).  Three-lane-only binding is too loose because in
# practice transfers, messages, and reacts rarely all spike together,
# so a 3-lane-only cap leaves each lane with its own siloed market
# under any realistic congestion pattern.
#
# Production tx sizes (measured at MERKLE_TREE_HEIGHT=20):
#   message  ~2.9 KB  (witness dominates; 1 KB max payload adds ~1 KB)
#   transfer ~2.9 KB
#   react    ~2.9 KB
# Per-kind structural cap (MAX_TXS_PER_BLOCK = 45):
#   1-lane max:  ~150 KB    (45 messages-with-1KB-payload)
#   2-lane max:  ~280 KB
#   3-lane max:  ~390 KB
#
# Setting the cap at 200 KB:
#   * fits 1-lane-full of any kind (no honest-block rejection)
#   * BINDS under 2-lane congestion (forces cross-kind auction)
#   * binds harder under 3-lane (the natural extreme)
# This is the smallest value that delivers the user-stated goal of
# "any tx kind competes for any byte under congestion" without
# rejecting any otherwise-valid 1-lane block.
MAX_BLOCK_TOTAL_BYTES = 200_000

assert TIER_18_HEIGHT > REACT_TX_HEIGHT, (
    "TIER_18_HEIGHT must follow REACT_TX_HEIGHT — Tier 18 unifies the "
    "fee market across Message + Transfer + React, so React must be a "
    "first-class tx kind on chain before the unified budget bites"
)

# ----------------------------------------------------------------------
# Tier 20: soft equivocation slash (operator-mistake survivability)
# ----------------------------------------------------------------------
#
# Pre-fork policy: any double-proposal / double-attestation / finality-
# double-vote evidence resulted in 100% stake burn + full bootstrap-
# escrow burn + permanent removal from the validator set
# (`slashed_validators`).  That penalty matched a deliberate Byzantine
# attack but was catastrophic for the most common honest-operator
# failure mode: running two nodes under the same key (failover
# misconfig, restored backup with the old node still running, restart
# race).  One accidental dual-sign wiped the operator's full bond.
#
# Post-fork policy: equivocation slashes SOFT_SLASH_PCT of stake +
# the same fraction of bootstrap escrow + the same fraction of any
# pending unstakes (kept in the slash basis so an attacker cannot
# escape by unstaking faster than evidence can be submitted, but at
# the partial percent).  The validator stays in the set with reduced
# stake — no permanent ban from a single offense; only the SAME piece
# of evidence is dedupe'd via `_processed_evidence`.
#
# Repeat-offender economics fall out without escalation logic: each
# new piece of evidence slashes 5% of what remains, so a stuck dual-
# node operator with N accidental dual-signs decays geometrically as
# (1-0.05)^N — 10 mistakes ≈ 40% loss, 50 mistakes ≈ 92% loss.
# Sustained misbehavior still approaches total stake loss; a single
# accident does not.
#
# Activation: rides above Tier 19 (PROPOSAL_FEE_TIER19_HEIGHT = 13000)
# with a ~2000-block runway (~14 days at 600 s/block), giving
# operators time to acknowledge the new slashing semantics.
SOFT_SLASH_HEIGHT = 716  # Tier 20 — fast-forwarded for 1.26.0 hard fork sweep
SOFT_SLASH_PCT = 5  # % of stake/escrow/pending burned per equivocation post-fork


def get_slash_pct(current_block: int) -> int:
    """Return the % of stake/escrow burned for one equivocation offense
    at this height.  Pre-fork: SLASH_PENALTY_PCT (100, full burn).
    Post-fork: SOFT_SLASH_PCT (5, partial).

    The dynamic config lookup (re-read each call) is what lets test
    suites monkey-patch SOFT_SLASH_HEIGHT to exercise both regimes
    without spinning the chain forward 15k blocks.
    """
    from messagechain import config as _cfg
    if current_block >= _cfg.SOFT_SLASH_HEIGHT:
        return _cfg.SOFT_SLASH_PCT
    return _cfg.SLASH_PENALTY_PCT


assert 0 < SOFT_SLASH_PCT < SLASH_PENALTY_PCT, (
    "SOFT_SLASH_PCT must be a partial slash (0 < pct < 100). The whole "
    "point of Tier 20 is to soften the catastrophic full-burn penalty "
    "for honest dual-node operator mistakes; equality with "
    "SLASH_PENALTY_PCT would make the fork a no-op"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 21: halvings-aware proposer reward cap
# ─────────────────────────────────────────────────────────────────────
# `PROPOSER_REWARD_CAP` is computed once at module load as
#     BLOCK_REWARD * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
# i.e. 16 * 1 / 4 = 4 tokens.  This frozen value silently turns the
# anti-mega-staker cap OFF once the halving schedule drives the actual
# block reward down to BLOCK_REWARD_FLOOR=4: at floor era a single
# validator who proposes AND attests can earn proposer_share(1) +
# attester_pool(3) = 4 tokens, which equals the cap exactly — no
# clawback, no burn.  The mechanism is permanently non-binding.
#
# Post-activation: the per-block cap is recomputed every block from
# the actual `reward` returned by `calculate_block_reward(height)`,
# which already accounts for halvings AND the v1/v2 deflation-floor
# boosts.  The cap stays at exactly 1/4 of the issued reward
# regardless of era — at BLOCK_REWARD=16 the cap is 4 (unchanged from
# today), at the first halving (8) it's 2, at floor (4) it's 1.
#
# Pre-activation: continues to read the import-time
# `PROPOSER_REWARD_CAP` constant byte-for-byte so historical blocks
# replay identically.
#
# Activation height: well before the first halving
# (HALVING_INTERVAL=210_240) so the new logic is in place long before
# the failure mode could manifest.  Sits above Tier 20 with the same
# ~2000-block runway pattern.
PROPOSER_CAP_HALVING_HEIGHT = 718  # Tier 21 — fast-forwarded for 1.26.0 hard fork sweep

# ─────────────────────────────────────────────────────────────────────
# Tier 22 — Voter rewards on passed proposals
# ─────────────────────────────────────────────────────────────────────
# Governance suffers from a quiet-electorate problem: the binding
# supermajority test (yes_weight × 3 > total_eligible × 2) means an
# unread proposal lapses by inertia even when no one objects.  Validators
# already pay for the *processing* of a vote (the VoteTransaction's
# normal tx fee is paid to the block proposer), but the *staker* casting
# the vote gets nothing for the attention cost of reading and judging
# the proposal.  Pure pay-for-participation is rejected (rubber-stamp
# incentive — vote on everything without reading), so this fork adopts
# a retrospective design:
#
#   1. At proposal-apply time, the proposer pays VOTER_REWARD_SURCHARGE
#      ON TOP OF the regular tx fee.  The surcharge is held in a per-
#      proposal escrow on ProposalState.voter_reward_pool — debited
#      from the proposer's balance, NOT minted, NOT burned.  The
#      net-inflation invariant is unchanged because the tokens still
#      exist; they're just not in any individual balance.
#
#   2. At proposal close (the same block where prune_closed_proposals
#      runs):
#        - If yes_weight * 3 > total_eligible * 2 (the existing binding
#          supermajority rule, evaluated in live-weight mode like the
#          H6 treasury-spend tally) — distribute the pool pro-rata by
#          live stake to YES voters whose stake_at_close > 0.
#        - Otherwise (proposal failed or had insufficient yes-weight) —
#          burn the entire pool (decrement total_supply, increment
#          total_burned).
#
#   3. Whale cap: a single yes-voter cannot collect more than
#      VOTER_REWARD_MAX_SHARE_BPS / 10_000 of the pool, even if they
#      hold all the yes-side stake.  Excess from the cap burns.  The
#      cap exists because without it a 70%-stake validator captures
#      ~70% of every reward and the system reduces to "validators tax
#      proposers via a 2/3 rubber stamp on their own proposals."
#
#   4. Integer-division dust burns deterministically (so every node
#      agrees byte-for-byte on the post-distribution state).
#
# Pay-on-pass intentionally has a small yes-bias for marginal voters.
# Acceptable because passing requires affirmative 2/3 supermajority —
# nudging the truly-undecided from "abstain" to "yes" cannot drag a bad
# proposal across that bar, but it can save a good one from a sleepy
# electorate.  The alternative (pay both sides of every vote) just
# degenerates back into pay-for-participation.
#
# Activation: VOTER_REWARD_HEIGHT = 19000, riding above
# PROPOSER_CAP_HALVING_HEIGHT (17000) with the established ~2000-block
# runway pattern.  Pre-fork proposals close with no payout; their
# voter_reward_pool stays 0 by construction (the surcharge debit is
# height-gated).
VOTER_REWARD_HEIGHT = 719  # Tier 22 — fast-forwarded for 1.26.0 hard fork sweep
VOTER_REWARD_SURCHARGE = 50_000        # tokens escrowed per post-fork proposal
VOTER_REWARD_MAX_SHARE_BPS = 2_500     # cap on single-voter share (25%)

assert VOTER_REWARD_HEIGHT > PROPOSER_CAP_HALVING_HEIGHT, (
    "VOTER_REWARD_HEIGHT must follow PROPOSER_CAP_HALVING_HEIGHT — Tier 22 "
    "rides above Tier 21 in the fork schedule"
)
assert VOTER_REWARD_SURCHARGE > 0, (
    "VOTER_REWARD_SURCHARGE must be positive — a zero surcharge makes the "
    "fork a no-op (nothing to escrow, nothing to distribute)"
)
assert 0 < VOTER_REWARD_MAX_SHARE_BPS <= 10_000, (
    "VOTER_REWARD_MAX_SHARE_BPS must be in (0, 10_000] bps — 10_000 = "
    "no cap, 0 would mean every voter gets nothing and the entire pool "
    "burns regardless of outcome"
)

assert MAX_BLOCK_TOTAL_BYTES >= MAX_BLOCK_MESSAGE_BYTES, (
    "MAX_BLOCK_TOTAL_BYTES must accommodate at least the legacy "
    "message-byte budget — otherwise a block of pure messages valid "
    "under the per-kind cap would be invalid under the unified one, "
    "creating a backward-incompatible activation surprise"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 19 — Proposal fee tightening + per-byte surcharge
# ─────────────────────────────────────────────────────────────────────
# Governance proposals (advisory + treasury-spend) carry permanent on-
# chain weight far heavier than a normal message: each one allocates a
# stake_snapshot of the entire validator electorate (held for the full
# GOVERNANCE_VOTING_WINDOW = 1008 blocks ≈ 7 days), counts toward the
# MAX_ACTIVE_PROPOSALS = 500 cap, and lives forever in the chain
# whether it passes, fails, or attracts zero votes.
#
# Pre-fork the floor was a flat GOVERNANCE_PROPOSAL_FEE = 10_000
# regardless of payload size, with a 20 KB description ceiling.  At
# max size that's ≈0.49 fee/byte — under any congestion the typical
# message's EIP-1559 base fee × bytes wins (and after Tier 18 the
# unified market makes those bytes auctioned against everything else),
# so a max-sized proposal pays LESS per stored byte than a typical
# message.  That inverts the per-byte cost ordering: the heavier tx
# kind (proposal) is cheaper per byte than the lighter one (message),
# and the size-amortization escape hatch lets a spammer stuff ~half
# a block's MAX_BLOCK_MESSAGE_BYTES into a single proposal at sub-
# message rates.  Tier 18 unified the market for the kinds it covers
# but ProposalTransaction was not in that scope -- this fork closes
# the residual gap.
#
# Tier 19 closes the inversion with three coordinated levers:
#
#   1. Tighter byte caps — description 20_000 → 2_000, title 400 →
#      200.  Long-form rationale must live off-chain behind
#      ``reference_hash`` (already a field on ProposalTransaction).
#      Cuts the worst-case payload from ≈20.4 KB to ≈2.2 KB.
#
#   2. Higher flat floor — GOVERNANCE_PROPOSAL_FEE 10_000 → 100_000.
#      At the new ≈2.2 KB max payload that's ≈45 fee/byte minimum —
#      well above any plausible message fee/byte under congestion.
#
#   3. Per-byte surcharge —
#      GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 = 50.  Locks the
#      fee/byte invariant intrinsically: it cannot be re-amortized
#      away by raising the byte cap in a future fork.  The total
#      post-Tier-19 floor for a proposal whose payload (title +
#      description + reference_hash) is ``p`` bytes is
#          GOVERNANCE_PROPOSAL_FEE_TIER19
#          + GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 * p
#      i.e. ≥ 100_000 + 50·p tokens.  At any p this exceeds the
#      typical message floor (MARKET_FEE_FLOOR=1 + EIP-1559 base ×
#      message bytes) by orders of magnitude.
#
# Activation rides above Tier 18 (TIER_18_HEIGHT = 11_000).  Runway
# 11_000 → 13_000 = ~2000 blocks (~14 days at 600 s/block) gives
# operators time to upgrade past the prior fork before the new
# proposal admission rule starts biting.
#
# Legacy constants (GOVERNANCE_PROPOSAL_FEE,
# MAX_PROPOSAL_TITLE_BYTES, MAX_PROPOSAL_DESCRIPTION_BYTES — the
# latter two live in messagechain.governance.governance) remain the
# active rule pre-fork so historical blocks replay byte-for-byte
# under the rule current at their height.
PROPOSAL_FEE_TIER19_HEIGHT = 715  # Tier 19 — fast-forwarded for 1.26.0 hard fork sweep
GOVERNANCE_PROPOSAL_FEE_TIER19 = 100_000
GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 = 50
MAX_PROPOSAL_TITLE_BYTES_TIER19 = 200
MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19 = 2_000


# ─────────────────────────────────────────────────────────────────────
# Tier 23 — Honesty curve slashing
# ─────────────────────────────────────────────────────────────────────
#
# Tier 20 (SOFT_SLASH) flattened the catastrophic 100% burn down to a
# fixed 5% per offense and let geometric decay handle repeat offenders.
# That softened the headline accident — operator dual-node misconfig —
# but left two design gaps that the audit on this branch surfaced:
#
#   1. Severity is INDIFFERENT to evidence quality.  A genuine
#      double-sign attack (two headers with distinct ``state_root`` —
#      the proposer chose two parallel post-states for the same height,
#      a clear deliberate violation) is slashed at the same 5% as a
#      crash-restart artifact (two headers that differ only in
#      ``merkle_root`` because the rebuilt mempool snapshot moved
#      between the partial-propagation and the restart-resign).  Tier 20
#      treats accident and attack identically.
#
#   2. Severity is INDIFFERENT to the offender's track record.  A
#      validator who has correctly proposed 100,000 blocks and attested
#      to 1,000,000 over years pays the same 5% on a single accident as
#      a validator who staked yesterday and started misbehaving
#      immediately.  The CLAUDE.md anchor ("honest operators are
#      insured against accidents… severity should be informed by track
#      record, not just the single offense") is not realized.
#
# Tier 23 closes both gaps with an honesty curve.  ``slashing_severity``
# (in ``messagechain.consensus.honesty_curve``) computes a per-offense
# slash percentage from:
#
#   * ``proposer_sig_counts[validator_id]`` — accepted block proposals.
#     A proxy for "this operator has been doing block production
#     correctly for a long time."  Already maintained on chain by
#     ``Blockchain._apply_block_state``.
#   * ``reputation[validator_id]`` — accepted attestations.  Same
#     intuition, finer-grained (validators attest more than they
#     propose).  Already maintained on chain by
#     ``_process_attestations``.
#   * ``slash_offense_counts[validator_id]`` — count of slashes
#     successfully applied to this offender across chain history.  New
#     in this fork; rebuildable from the slash-tx stream so it is not
#     opaque persisted state.
#   * Evidence unambiguity — block double-proposal where the only diff
#     is ``merkle_root`` + a small ``timestamp`` drift is classified
#     AMBIGUOUS (single-restart artifact).  Anything else (different
#     ``state_root`` / different ``prev_hash`` / large timestamp gap /
#     attestation double-vote / finality double-vote) is UNAMBIGUOUS
#     and slashes hard regardless of history.
#
# The severity function is BACKWARD-COMPAT-ABLE behind this fork
# height: below ``HONESTY_CURVE_HEIGHT`` the slash policy is the
# byte-identical Tier 20 (or pre-Tier 20) path.  Above, the curve
# computes the slash percent and ``slash_validator`` applies it.
#
# Persistent same-height sign guard.  In the same release, the
# proposer / attester / finality-voter persist their last-signed height
# to disk before the signature leaves the process — same persist-
# before-sign ratchet pattern that ``messagechain.crypto.keys`` uses
# for WOTS+ leaf indexes.  An honest crash-restart that would have
# produced byte-different conflicting headers (because timestamp ticks
# and the rebuilt mempool snapshot has shifted) is now refused at the
# guard layer instead of producing slashable evidence.
#
# Activation: HONESTY_CURVE_HEIGHT = 21000, riding above Tier 22
# (VOTER_REWARD_HEIGHT = 19000) with the standard ~2000-block runway.
HONESTY_CURVE_HEIGHT = 720  # Tier 23 — fast-forwarded for 1.26.0 hard fork sweep

# Severity-curve tuning knobs.  Anchored *shape* is "small AMBIGUOUS
# baseline + escalation per repeat + relief from honest history",
# numbers are tunable via fork.

# Floor — no slash that lands ever rounds below this percent.  Paired
# with the universal slash_pct > 0 invariant in slash_validator().
HONESTY_CURVE_MIN_PCT = 1

# Baseline percent for an AMBIGUOUS first offense from a fresh
# validator (no track record).  Intentionally matches SOFT_SLASH_PCT
# so the curve degrades gracefully toward Tier 20 semantics in the
# absence of any tilting input.
HONESTY_CURVE_AMBIGUOUS_BASE_PCT = 5

# Each prior recorded offense scales the AMBIGUOUS base by
# (1 + AMBIGUOUS_REPEAT_MULTIPLIER * prior_offenses).  At
# multiplier=2.0, prior=5 → base × 11; rapid escalation but the floor
# at 1% and ceiling at 100% bound it.
HONESTY_CURVE_AMBIGUOUS_REPEAT_MULTIPLIER = 2

# Honest-history relief: at HONEST_TRACK_THRESHOLD signs (good_blocks
# weighted × 4 + good_attestations) and above, the AMBIGUOUS slash is
# scaled by max(HONEST_TRACK_FLOOR, threshold / track_record).  Below
# the threshold, full base percent applies (no relief — fresh
# validator is already at the soft-slash baseline).
HONESTY_CURVE_HONEST_TRACK_THRESHOLD = 100
# Floor expressed as an exact rational (NUM/DEN) so the curve can do
# integer-only severity arithmetic.  A pure-float floor would push
# `slashing_severity` through `int(base * escalation * float_relief)`,
# whose output is IEEE-754-dependent at the boundaries — adequate in
# practice but a latent consensus-determinism trap on a permanent
# ledger.  Keeping the float form for any external caller that reads
# the human-readable ratio.
HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM = 1
HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN = 5
HONESTY_CURVE_HONEST_TRACK_FLOOR = (
    HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM
    / HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN
)  # 0.2 — never relieve below 1/5 of base

# Weight on accepted block proposals when computing track_record.
# A successful block proposal is a stronger signal of operator quality
# than a successful attestation (proposer chose every byte; attester
# only voted on someone else's bytes), so we weight it heavier.
HONESTY_CURVE_BLOCK_WEIGHT = 4
HONESTY_CURVE_ATTEST_WEIGHT = 1

# UNAMBIGUOUS first offense for a long-history validator: cannot drop
# below HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT.  This is the deliberate-
# Byzantine band; even a perfect track record cannot soften it below
# half-stake.
HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT = 50

# Tier 51 — AMBIGUOUS slash severity ceiling.
#
# The CLAUDE.md "Honest operators are insured against accidents" anchor
# requires that "when an honest node IS slashed (transient evidence
# collision, recoverable misconfig), the burn is a small fraction of
# stake, not a wipe."  Pre-Tier-51 the AMBIGUOUS path produces
# escalation-driven severity:
#
#   sev = base × (1 + REPEAT_MULTIPLIER × prior) × relief
#
# At ``BASE=5``, ``REPEAT_MULTIPLIER=2``, ``HONEST_TRACK_FLOOR=1/5``,
# a long-tenured operator at ``track=200`` and ``prior=5`` lands at
# ``5 × 11 × 0.5 = 27%``; at ``prior=10`` -> ``52%``; at very high
# tenure the relief floor pins at 0.2 so a ``prior=20`` veteran still
# gets ``5 × 41 × 0.2 = 41%``.  21--52% on AMBIGUOUS (restart-shape)
# evidence does NOT pass the "small fractional" bar, exactly inverting
# the anchor for the long-tenured / high-volume class it names.
#
# Tier 51 bounds the AMBIGUOUS-path output at
# ``HONESTY_CURVE_AMBIGUOUS_MAX_PCT`` (= 10, 2× SOFT_SLASH_PCT) at and
# above ``HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT``.  10% is firmly in
# "small fraction" territory while still producing a real deterrent
# against repeat hiccups (5 events compound to ~40% lost over time).
# Pre-fork heights replay byte-identically.  UNAMBIGUOUS path is
# unchanged -- the deliberate-Byzantine bar (UNAMBIGUOUS_FIRST_PCT on
# first offense, 100% on any repeat) still applies, because the anchor
# explicitly carves out "Catastrophic slashes are reserved for
# unambiguous, intentional protocol violations."
HONESTY_CURVE_AMBIGUOUS_MAX_PCT = 10

assert HONESTY_CURVE_AMBIGUOUS_MAX_PCT >= HONESTY_CURVE_AMBIGUOUS_BASE_PCT, (
    "HONESTY_CURVE_AMBIGUOUS_MAX_PCT must be at least BASE_PCT — a cap "
    "below the baseline would force first-offense AMBIGUOUS slashes "
    "BELOW the soft-slash floor, breaking the ratchet from the legacy "
    "Tier 20 semantics"
)
assert HONESTY_CURVE_AMBIGUOUS_MAX_PCT <= HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT, (
    "HONESTY_CURVE_AMBIGUOUS_MAX_PCT must be at most UNAMBIGUOUS_FIRST_PCT "
    "— deliberate Byzantine evidence cannot be slashed less than an "
    "accidental one for the same offender"
)

# Restart-drift tolerance: two block headers whose timestamps differ
# by ≤ this many seconds and whose only signable_data difference is
# merkle_root (and timestamp) are classified AMBIGUOUS.  Beyond this,
# the gap is too large for a single crash-restart cycle on commodity
# hardware and the headers are treated as a deliberate double-sign.
HONESTY_CURVE_RESTART_DRIFT_SECS = 120

assert HONESTY_CURVE_MIN_PCT >= 1, (
    "HONESTY_CURVE_MIN_PCT must be ≥ 1 — slash_validator's universal "
    "slash_pct > 0 invariant means a 0% slash silently no-ops"
)
assert HONESTY_CURVE_AMBIGUOUS_BASE_PCT > 0, (
    "Ambiguous base must be positive — a 0% baseline turns the curve "
    "into a no-op for the most common (honest accident) path"
)
assert 0 < HONESTY_CURVE_HONEST_TRACK_FLOOR <= 1.0, (
    "HONEST_TRACK_FLOOR must be in (0, 1.0] — at 0 the relief is "
    "unbounded (a long-history validator could escape any slash); at "
    "1.0 there is no relief at all and the fork is pointless"
)
assert (
    HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM > 0
    and HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN > 0
    and HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM
    <= HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN
), (
    "HONEST_TRACK_FLOOR_NUM/DEN must form a positive ratio in (0, 1] — "
    "the integer-rational form must agree with the float form's bound"
)
assert HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT >= HONESTY_CURVE_AMBIGUOUS_BASE_PCT, (
    "UNAMBIGUOUS_FIRST_PCT must be ≥ AMBIGUOUS_BASE_PCT — deliberate "
    "Byzantine evidence cannot be slashed *less* than an accidental "
    "one for the same offender"
)
assert HONESTY_CURVE_RESTART_DRIFT_SECS > 0, (
    "Restart-drift tolerance must be positive — at 0 every byte-"
    "different header pair is treated as deliberate, defeating the "
    "anchored honest-restart insurance"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 24 — Honesty-curve rate factor
# ─────────────────────────────────────────────────────────────────────
# Tier 23 introduced honest-history relief based on track_record, but
# track_record is a pure VOLUME measure: a validator with 1000 good
# blocks and 5 priors gets the same relief as one with 1000 good
# blocks and 0 priors.  The CLAUDE.md anchor ("a node that has
# behaved correctly for a long run and trips on one block should not
# be punished the same as a node that misbehaves repeatedly") implies
# the curve should account for the *rate* of good-vs-bad behavior,
# not just the absolute count of good actions.
#
# Tier 24 closes that gap with a single composition: post-activation,
# track_record is rate-adjusted by subtracting
# `BAD_PENALTY_WEIGHT × prior_offenses` from the raw weighted sum,
# clamped to ≥ 0.  Effect:
#
#   * Long-tenured validator with 0 priors: relief unchanged (high
#     track_record → small severity).
#   * Long-tenured validator with many priors: track_record erodes
#     fast → relief shrinks → severity climbs back toward base.
#   * Mixed pattern (good run, then a streak of slashes): the relief
#     decays in proportion to bad volume.  Combined with Tier 23's
#     escalation multiplier (1 + REPEAT_MULTIPLIER × prior), the net
#     effect is a smooth penalty ramp that respects the good:bad
#     ratio rather than just the counts.
#
# BAD_PENALTY_WEIGHT defaults to HONEST_TRACK_THRESHOLD (=100): each
# prior offense erases roughly one threshold's worth of good
# standing.  At default weights (block=4, attest=1) and threshold=100,
# that's ≈ 25 good blocks OR ≈ 100 good attestations to "earn back"
# from one slash.  The shape is anchored; the exact weight is a
# tuning knob.
#
# Activation rides above HONESTY_CURVE_HEIGHT (Tier 23) with normal
# fork runway.  Below activation: track_record is computed exactly
# as Tier 23 left it — byte-for-byte preservation across the fork
# boundary so historical slashes replay under the rule current at
# their height.
HONESTY_CURVE_RATE_HEIGHT = 750  # Tier 24 — fast-forwarded for 1.32.0 hard fork sweep

# Each prior recorded offense subtracts this much from the raw
# track_record before the relief multiplier is computed.  Default
# equals HONEST_TRACK_THRESHOLD so one slash erodes one threshold's
# worth of accumulated good standing.
HONESTY_CURVE_BAD_PENALTY_WEIGHT = 100

# Perfect-record amnesty threshold (Tier 24).  A validator whose
# track_record clears this bar AND has zero priors gets full pass
# (severity = 0) on AMBIGUOUS evidence — the "low CHANCE of getting
# penalized" half of the CLAUDE.md anchored property.  Default 10×
# HONEST_TRACK_THRESHOLD: a validator must accumulate ten thresholds
# of good behavior before earning the amnesty.  Single-shot: the
# amnesty bumps slash_offense_counts so the next AMBIGUOUS incident
# sees priors=1 and no longer qualifies (the validator must rebuild
# the perfect-record cushion).  Only AMBIGUOUS evidence can be
# amnestied — UNAMBIGUOUS double-sign / state-root divergence is
# always slashable regardless of tenure (deliberate-Byzantine bar).
HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD = 1_000

assert HONESTY_CURVE_RATE_HEIGHT > HONESTY_CURVE_HEIGHT, (
    "HONESTY_CURVE_RATE_HEIGHT must follow HONESTY_CURVE_HEIGHT — Tier "
    "24 rides on top of the Tier 23 honesty-curve baseline; activating "
    "the rate factor before the underlying curve exists is nonsensical"
)
assert HONESTY_CURVE_BAD_PENALTY_WEIGHT > 0, (
    "HONESTY_CURVE_BAD_PENALTY_WEIGHT must be positive — at 0 the rate "
    "factor is a no-op and Tier 24 reduces to Tier 23 behavior"
)
assert (
    HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD > HONESTY_CURVE_HONEST_TRACK_THRESHOLD
), (
    "HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD must exceed HONEST_TRACK_"
    "THRESHOLD — the amnesty band is a STRICTER condition (full pass) "
    "than the relief band (small severity), so the threshold must be "
    "higher; otherwise relief and amnesty collapse into one rule"
)


def get_honesty_curve_active(current_block: int) -> bool:
    """Return True if the honesty curve has activated at this height.

    Dynamic config lookup (re-read each call) lets the test suite
    monkey-patch ``HONESTY_CURVE_HEIGHT`` to exercise both regimes
    without spinning the chain forward 21k blocks.
    """
    from messagechain import config as _cfg
    return current_block >= _cfg.HONESTY_CURVE_HEIGHT


# ─── Tier 25: per-message community_id ─────────────────────────────────
#
# An optional short ASCII-handle field on MessageTransaction lets
# senders attach a Reddit-style community/topic grouping to a post.
# Pure first-poster-creates semantics — there is NO on-chain registry,
# NO creation tx, NO claim mechanism, and NO entity owns a community.
# The community_id is purely a CATEGORY TAG; the (handle → display
# name / description / icon) mapping is L2/app-layer concern.
#
# Wire format / charset (v5 MessageTransaction):
#   * Presence flag (1B): 0x00 = absent, 0x01 = present.
#   * Length byte (1B): valid range [1, MAX_COMMUNITY_ID_LEN].
#   * N bytes of ASCII handle text in [a-z0-9_-].
#   * First and last byte MUST NOT be '-' or '_' (DNS-label style).
#
# Why a stricter rule than message text:
#   * Identifiers must be UNAMBIGUOUS.  Allowing the full Tier 12
#     UTF-8 whitelist (L*/M*/N*/P*/Zs) opens the homoglyph attack
#     vector — `art` (Latin) vs `аrt` (Cyrillic а) render identically
#     but are distinct strings, so a hostile actor can squat a
#     visually-identical community handle.  Permanence makes this
#     worse, not better: an impersonation handle is on chain forever.
#     Restricting to [a-z0-9_-] makes the namespace zero-ambiguity.
#   * Case-insensitivity by construction (lowercase only) avoids
#     "Art" / "art" / "ART" fragmentation by typo.
#   * No whitespace eliminates "art" vs "art " vs " art" fragments.
#   * Leading/trailing punctuation rule (`[a-z0-9]` at edges) avoids
#     "art" vs "-art" vs "art_" edge cases.
#   * Length cap of 32 is enough for organic-growth handles
#     (Reddit caps at 21, GitHub at 39) and small enough that wire
#     overhead is bounded at 1+1+32 = 34 bytes worst case (vs 17B
#     for the original opaque-hash design but typically 5-15 bytes).
#
# Internationalization tradeoff: native-script community NAMES live
# at app/L2 layer (display name, icon, description), exactly like
# GitHub `torvalds` (ASCII) → display name in any script.  Message
# CONTENT keeps the full Tier 12 UTF-8 whitelist — only the grouping
# handle is restricted, in line with every successful identifier
# system (DNS, GitHub, package names, Reddit, Twitter handles).
#
# Asymmetric reversibility: starting strict and loosening later is
# additive (a future tier can allow more codepoints behind a new
# version flag without invalidating any existing community_id).
# Starting permissive and tightening later requires breaking the
# wire format.  Strict-first is the correct default.
#
# Fee treatment: counted toward stored bytes for the per-stored-byte
# fee floor and the proposer's fee-per-byte ranking.  Excluded from
# MAX_MESSAGE_CHARS — community_id is structural metadata, not the
# user's speech.
#
# Activation rides above Tier 24 (HONESTY_CURVE_RATE_HEIGHT = 5_000).
# Originally cut at 6_000 in 1.28.0; bumped to 8_000 in 1.28.1 alongside
# the wire-format revision (16-byte opaque -> ASCII handle), widening
# the operator upgrade window so the in-flight 1.28.0 nodes are not
# left parsing the new v5 layout against stale rules.  Pre-activation
# at the time of the bump (mainnet tip well below 5_000), so the
# height change is operationally costless.
COMMUNITY_ID_HEIGHT = 751  # Tier 25 — fast-forwarded for 1.32.0 hard fork sweep
# Maximum length in ASCII bytes (= chars, since charset is ASCII).
# Anchored as part of the wire format — see _validate_community_id
# in messagechain.core.transaction for the structural rules.
MAX_COMMUNITY_ID_LEN = 32


# ─── Tier 26: chain-height window on RevokeTransaction ─────────────────
#
# RevokeTransaction is intentionally nonce-free so an operator can
# pre-sign it on paper / air-gapped media and broadcast later under
# duress (the cold key never has to come back online during an
# active incident).  The original design bounded only the FUTURE
# timestamp drift -- past timestamps were unbounded.  Combined with
# nonce-free idempotency, that made any captured signed-revoke hex a
# permanent bearer broadcast token: anyone who later recovered a
# leaked backup, photo, or USB stick (insider, coerced operator,
# thief) could broadcast the un-aged revoke and force the target
# validator into the 7-day unbonding queue.  With two operator
# validators on mainnet, simultaneously firing both leaked revokes
# halts consensus.
#
# Tier 26 closes the bearer-replay window without giving up the
# pre-sign / offline workflow.  At/above this height, every revoke
# commits to a chain-height window [valid_from_height, valid_to_height]
# in the signable bytes.  Validation rejects the tx if current_height
# is outside that window.  The operator re-signs every quarter
# (~13140 blocks ≈ 90 days at 600 s/block); a hex leaked today
# expires within 90 days of its valid_to_height, bounding the
# bearer-replay surface.  The window IS the signed payload, so an
# attacker holding a leaked hex cannot extend it without the cold
# key -- the signature commits to the original window.
#
# Pre-fork (height < REVOKE_TX_WINDOW_HEIGHT) the legacy un-windowed
# encoding is still accepted, so historical replay is preserved.  The
# CLI layer always emits the windowed encoding once tooling is
# upgraded -- the pre-fork branch is purely a replay-determinism
# concession for blocks already on chain.
#
# Activation rides above Tier 25 (COMMUNITY_ID_HEIGHT = 8_000) with
# ample runway above current mainnet tip (~670 at fork-design time),
# so no in-flight pre-signed revoke is invalidated by the fork itself
# -- operators have the full pre-activation window to refresh their
# stored hexes to the post-fork format.
REVOKE_TX_WINDOW_HEIGHT = 752  # Tier 26 — fast-forwarded for 1.32.0 hard fork sweep

# Default re-sign cadence for the CLI's --print-only path: ~90 days
# at 600 s/block.  90 days matches a reasonable quarterly cold-key
# ritual: the operator dusts off the cold key, signs a fresh revoke,
# replaces the offline copy, and is good for another quarter.  Short
# enough that a leaked hex expires within a quarter; long enough that
# an operator who travels for two months still has unexpired
# kill-switch coverage when they get home.
REVOKE_TX_DEFAULT_VALID_FOR_BLOCKS = 13_140

# ─────────────────────────────────────────────────────────────────────
# Tier 27 — Symmetric no-self-react rule
# ─────────────────────────────────────────────────────────────────────
# Tier 17 (REACT_TX_HEIGHT) shipped ReactTransaction with an asymmetry:
# self-trust votes (target_is_user=True with target == voter_id) were
# rejected (a free unbounded reputation pump otherwise), but message-
# react votes (target_is_user=False with the message-author == voter)
# were ALLOWED on the rationale that the per-tx fee was the spam tax.
#
# That rationale undersells the score's purpose: a vote signals
# external reception, not author preference.  Allowing self-votes on
# one's own message lets an author cheaply pump their own visibility
# whenever message_score is consulted (sort order, "popular" feeds,
# any future reputation derivative), with the only cost being a fee
# the author would pay to anyone else's vote at the same price.  The
# fee gates spam volume, not motivated self-promotion.
#
# Tier 27 closes the asymmetry: at/after activation, a ReactTx with
# target_is_user=False is rejected if its `target` (a message tx_hash)
# resolves to a MessageTransaction whose sender_id equals the voter_id.
# Pre-activation blocks keep admitting self-message-reacts unchanged
# for replay determinism — historical state must continue to apply
# under the rules in force when each block was produced.
#
# The author-of-target lookup uses the existing tx_locations index
# (Tier 10) plus a block load via get_block_by_number.  Both are
# already on the message-react admission path (the existence check
# at blockchain.py:7938-7948 calls get_tx_location), so post-Tier-27
# admission adds a single get_block_by_number per message-react tx.
# Cost is bounded by the per-block byte budget * react fee floor; the
# index lookup is O(1) and the block load is amortized via SQLite's
# row cache.  No new persisted state is added — the chain's message
# txs already carry sender_id, so resolving authorship is read-only.
#
# Activation height rides above Tier 26 (REVOKE_TX_WINDOW_HEIGHT =
# 10_000) with ample runway over current mainnet tip, so no in-flight
# pre-signed message-react is invalidated by the fork itself —
# operators upgrade through the prior fork before the new admission
# rule starts.
REACT_NO_SELF_MESSAGE_HEIGHT = 753  # Tier 27 — fast-forwarded for 1.32.0 hard fork sweep

assert PROPOSAL_FEE_TIER19_HEIGHT > TIER_18_HEIGHT, (
    "PROPOSAL_FEE_TIER19_HEIGHT must follow TIER_18_HEIGHT — Tier 19 "
    "rides on top of the established post-Tier-18 schedule; activating "
    "the proposal-fee tightening before Tier 18 settles would interleave "
    "two unrelated forks in the same upgrade window"
)
assert GOVERNANCE_PROPOSAL_FEE_TIER19 > GOVERNANCE_PROPOSAL_FEE, (
    "GOVERNANCE_PROPOSAL_FEE_TIER19 must raise (not lower) the legacy "
    "flat floor — Tier 19's whole point is to push proposal fee/byte "
    "above typical message fee/byte"
)
assert GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 > 0, (
    "GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 must be positive — a zero "
    "rate reopens the size-amortization escape hatch the surcharge "
    "exists to close"
)
assert COMMUNITY_ID_HEIGHT > HONESTY_CURVE_RATE_HEIGHT, (
    "COMMUNITY_ID_HEIGHT must follow HONESTY_CURVE_RATE_HEIGHT — "
    "Tier 25 rides on top of the highest established fork (Tier 24, "
    "honesty-curve rate factor); spacing only needs to satisfy the "
    "operator upgrade cutover window since the wire-format and "
    "slashing-curve subsystems are disjoint"
)
assert REVOKE_TX_WINDOW_HEIGHT > COMMUNITY_ID_HEIGHT, (
    "REVOKE_TX_WINDOW_HEIGHT must follow COMMUNITY_ID_HEIGHT — Tier 26 "
    "rides above the highest established fork (Tier 25 community-id) "
    "with the standard runway buffer.  Pre-activation, legacy "
    "un-windowed revoke txs are accepted as before; at/above, the "
    "wire format requires the [valid_from, valid_to] window."
)
assert REACT_NO_SELF_MESSAGE_HEIGHT > REVOKE_TX_WINDOW_HEIGHT, (
    "REACT_NO_SELF_MESSAGE_HEIGHT must follow REVOKE_TX_WINDOW_HEIGHT — "
    "Tier 27 rides above the highest established fork (Tier 26 revoke-"
    "window) with the standard runway buffer.  Pre-activation, self-"
    "reacts on one's own messages are admitted as before (Tier 17 "
    "rules); at/above, message-react admission rejects when the "
    "target's authoring sender_id equals the voter_id."
)
assert MIN_STAKE_FAUCET_DRIP_HEIGHT > REACT_NO_SELF_MESSAGE_HEIGHT, (
    "MIN_STAKE_FAUCET_DRIP_HEIGHT must follow REACT_NO_SELF_MESSAGE_HEIGHT — "
    "Tier 28 rides above the highest established fork (Tier 27 react-self-"
    "rule) with the standard runway buffer."
)
assert VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT > MIN_STAKE_FAUCET_DRIP_HEIGHT, (
    "VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT must follow "
    "MIN_STAKE_FAUCET_DRIP_HEIGHT — Tier 29 lowers the floor below Tier 28's "
    "and zeroes the Tier 6 registration burn, so the order matters: callers "
    "between the two heights still see the Tier 28 floor + Tier 6 burn."
)
# ─── Tier 30: honest-operator insurance for soft slashes ──────────────
# CLAUDE.md anchors "honest operators are insured against accidents" —
# slashing must reserve catastrophic burn for provable malicious intent
# and ramp severity by track record (length of service + volume + good-
# vs-bad rate).  Two soft-slash paths violate this anchor pre-Tier-30:
#
#   * `_apply_censorship_slash` burns flat CENSORSHIP_SLASH_BPS (10%)
#     and never consults the honesty curve — a long-tenured validator
#     who happened to omit one tx during honest mempool churn pays the
#     same as a deliberate censoring proposer.
#   * `process_inclusion_list_violation` classifies first offenses as
#     UNAMBIGUOUS, producing a 50%/100% slash on a single missed
#     include.  An IL violation CAN be honest mempool divergence — only
#     a repeat pattern, or evidence of distinct mempool views proving
#     the proposer saw the tx, justifies UNAMBIGUOUS classification.
#
# Tier 30 routes both paths through `slashing_severity` with
# `Unambiguity.AMBIGUOUS` on first offense; subsequent offenses (read
# off slash_offense_counts, persisted from Tier 24) escalate.
# A new `OffenseKind.CENSORSHIP` entry slots into the existing curve.
# Pre-activation: byte-identical to legacy behavior (flat 10% +
# UNAMBIGUOUS first-offense for IL violations).
HONESTY_CURVE_INSURANCE_HEIGHT = 756  # Tier 30 — fast-forwarded for 1.33.0 hard fork sweep
assert HONESTY_CURVE_INSURANCE_HEIGHT > VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT, (
    "HONESTY_CURVE_INSURANCE_HEIGHT must follow "
    "VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT — Tier 30 rides on top of the "
    "highest established fork (Tier 29) with the standard runway "
    "buffer so callers between the two heights see the legacy flat-BPS "
    "censorship slash and UNAMBIGUOUS-first IL violation classification."
)
# ─── Tier 31: censorship/IL slash basis includes pending_unstakes ─────
# CLAUDE.md "validator collusion" anchor: a coerced/colluding validator
# who censors a tx must not escape the slash by immediately unstaking.
# EVIDENCE_MATURITY_BLOCKS (~16 blocks ~2.7h) is far shorter than
# UNBONDING_PERIOD (>14 days), so pre-Tier-31 a censoring validator
# could move ≥90% of stake from `staked` to `pending_unstakes` before
# evidence matured, gutting the slash.  Both apply paths
# (`_apply_censorship_slash` and `process_inclusion_list_violation`)
# computed the slash on `staked` only and capped it at the post-unstake
# remainder, leaving the pending bucket intact.
#
# Tier 31 changes the BASIS to (staked + pending_unstakes) — matching
# the canonical pattern at `validate_slash_transaction` and the
# equivocation-slash path in `slash_validator()` — and drains
# proportionally from BOTH buckets.  The percentage is unchanged
# (Tier 30's curve still grades severity).  Pre-activation: legacy
# staked-only basis preserved byte-for-byte for replay determinism.
CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT = 760
assert CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT > HONESTY_CURVE_INSURANCE_HEIGHT, (
    "CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT must follow "
    "HONESTY_CURVE_INSURANCE_HEIGHT — Tier 31 extends the curve-graded "
    "severity introduced in Tier 30 by widening the slash basis to "
    "(staked + pending_unstakes); callers between the two heights see "
    "the curve-graded percentage applied to staked only."
)
# ─── Tier 32: honesty curve for non-response + bogus-rejection ────────
# Tier 30 routed _apply_censorship_slash and process_inclusion_list_
# violation through the honesty curve, but two more soft-slash paths
# kept burning flat BPS on first offense:
#
#   * `compute_non_response_slash_amount` → flat
#     WITNESS_NON_RESPONSE_SLASH_BPS (5%) on every silent-drop
#     evidence acceptance.  A long-tenured validator who missed one
#     witnessed submission under transient packet loss paid the same
#     as a deliberate silent-drop censoring node.
#   * `BogusRejectionProcessor.process` → flat CENSORSHIP_SLASH_BPS
#     (10%) on every bogus REJECT_INVALID_SIG.  A borderline rejection
#     racing a fee-rule fork edge cost the issuer the same as
#     deliberate forged-rejection censorship.
#
# This fork closes both, mirroring Tier 30's pattern: route through
# `slashing_severity` with new `OffenseKind.WITNESS_NON_RESPONSE` /
# `OffenseKind.BOGUS_REJECTION` entries + `Unambiguity.AMBIGUOUS` on
# first offense; subsequent offenses escalate via the curve's
# repeat-offense ramp.  Pre-activation: byte-identical to legacy.
HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT = 761  # Tier 32
assert HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT > CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT, (
    "HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT must follow "
    "CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT — Tier 32 rides on top of "
    "the Tier 30/31 cluster, closing the two remaining flat-BPS "
    "soft-slash paths Tier 30 missed (witness-non-response and "
    "bogus-rejection)."
)
# ─── Tier 33: pending-unstake drain for non-response + bogus-rejection ──
# Tier 31 widened the slash basis from `staked` to `(staked +
# pending_unstakes)` for `_apply_censorship_slash` and
# `process_inclusion_list_violation`, closing the censor-then-unstake
# evasion: a coerced/colluding validator could censor a high-fee-per-byte
# tx, immediately submit an unstake, and ride out the unbonding queue
# with ≥90% of the would-be slashed stake intact (EVIDENCE_MATURITY_BLOCKS
# is ~16 blocks ≈ 2.7h vs UNBONDING_PERIOD >14 days).
#
# Tier 32 routed the witness-non-response and bogus-rejection paths
# through the honesty curve — but those two paths still drained `staked`
# only.  Same evasion still works against silent-drop censorship and
# bogus-REJECT_INVALID_SIG censorship: drop the witnessed submission (or
# sign the bogus rejection), unstake, and the slash hits a tiny
# remainder while the rest releases at unbond maturity.  Tier 33 closes
# both, mirroring Tier 31 exactly: route the apply through
# `burn_slash_proportional` so the slash bites both buckets
# proportionally.  Pre-activation: legacy staked-only basis preserved
# byte-for-byte for replay determinism.
NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT = 1496  # Tier 33 — re-runwayed in 1.38.1 (was 762; chain advanced past original height under 1.34.0 which lacked this code; +734 preserves relative spacing)
assert (
    NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT
    > HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT
), (
    "NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT must follow "
    "HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT — Tier 33 widens the slash "
    "basis to (staked + pending_unstakes) for the same two paths Tier "
    "32 routed through the curve; the curve must already be live so "
    "`sev_pct` is well-defined when Tier 33 dispatches."
)
assert (
    NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT
    > CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT
), (
    "NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT must follow "
    "CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT — Tier 33 is the sibling "
    "of Tier 31 for the two slash paths Tier 31 missed; the operator "
    "upgrade window for the pending-drain shape opens at Tier 31 and "
    "this fork closes it for the remaining offense classes."
)
# ─── Tier 34: forced-inclusion check covers all block tx-list fields ──
# `check_forced_inclusion` (the attester-enforced soft censorship-
# resistance gate) was scoped to message-only txs from day one: it
# built `included_hashes` from `block.transactions` (the message-tx
# list) only, and it accounted for byte budget via `len(tx.message)`
# (payload bytes, not stored bytes).  Two correctness gaps fall out:
#
#   * **False positive on honest blocks carrying transfers.** Transfers
#     share `mempool.pending` with messages — `get_forced_inclusion_set`
#     returns them — but a proposer who correctly placed a forced
#     transfer in `block.transfer_transactions` had its tx_hash absent
#     from `included_hashes`, so attesters voted NO on an honest block.
#     In production the gate has not bitten because mainnet traffic
#     rarely keeps a transfer pending for FORCED_INCLUSION_WAIT_BLOCKS,
#     but the trap is armed and would fire as transfer volume grows.
#   * **False negative on the audit's anchored concern.** The CLAUDE.md
#     anchor "a tx that is well-formed, pays at least the per-byte
#     floor, and fits the byte budget cannot be suppressed by anything
#     weaker than a full validator-set majority actively colluding AND
#     willing to absorb slashing risk" silently exempted every non-
#     message tx kind because the gate didn't enforce against them.
#     A colluding proposer dropping high-fee transfers walked free.
#
# Tier 34 closes both: post-fork `included_hashes` walks every known
# block tx-list field, and the byte budget uses stored bytes
# (`len(tx.to_bytes())`) — the same axis the mempool already ranks
# fee-per-byte by.  Pre-fork: byte-identical to legacy attester
# behavior so any block accepted under the old rule still attests.
#
# Scope: this fork extends the gate to the tx kinds that the consensus
# mempool already tracks (Message + Transfer).  Stake / Unstake /
# Governance / Authority / React live in server-local pools or
# separate sub-pools today and require a follow-up architectural lift
# to bring them into the attester-shared mempool before the gate can
# enforce against them.  That work is tracked separately; Tier 34 is
# the prerequisite that makes the broader expansion mechanical.
FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT = 1498  # Tier 34 — re-runwayed in 1.38.1 (was 764)
assert (
    FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT
    > NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT
), (
    "FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT must follow Tier 33 — the "
    "attester-side rule change rides on top of the most recent slashing "
    "cluster so a single coordinated upgrade window covers both the "
    "slashing-basis (Tier 31/33) and attester-gate (Tier 34) changes."
)
# ─── Tier 35: NonResponseEvidenceTx block slot wired in ─────────────────
# Audit finding #1 (2026-04-28).  Every prior NonResponseEvidenceTx
# admission/processor change shipped dead code: ``Block`` had no
# ``non_response_evidence_txs`` field, the canonical
# ``_BLOCK_TX_LIST_ATTRS`` registries didn't list it, and
# ``_apply_block_state`` never invoked ``NonResponseEvidenceProcessor``.
# A coerced validator who silently dropped a witnessed POST could lose
# nothing — categorical bypass of the validator-collusion anchor in
# CLAUDE.md ("a tx that is well-formed, pays at least the per-byte
# floor, and fits the byte budget cannot be suppressed by anything
# weaker than a full validator-set majority actively colluding...").
#
# Tier 35 wires the slot end-to-end: dataclass field on ``Block``,
# slot in both ``to_bytes`` / ``from_bytes`` (gated on this height),
# entry in both forced-inclusion and Blockchain ``_BLOCK_TX_LIST_ATTRS``
# registries, and an apply loop in ``_apply_block_state`` that mirrors
# the bogus-rejection apply path exactly (Tier 32 curve + Tier 33
# pending-unstake drain via ``burn_slash_proportional``).  Pre-fork:
# the slot is not emitted on the wire (byte-identical to the historical
# encoding) and the apply loop is skipped (replay determinism).
NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT = 1500  # Tier 35 — re-runwayed in 1.38.1 (was 766; this is the wire-format slot whose missed activation crashed validator-1 cold-load on the 1.38.0 upgrade attempt)
assert (
    NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT
    > NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT
), (
    "NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT must follow Tier 33 — the "
    "apply path consumes Tier 33's curve + pending-unstake drain shape, "
    "so the prerequisite slashing-basis change must already be live "
    "when the block slot first carries traffic."
)
assert (
    NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT
    > FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT
), (
    "NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT must follow Tier 34 — the "
    "forced-inclusion gate's multi-list path is what makes the new slot "
    "visible to the censorship-resistance attester check; the gate must "
    "already be in multi-list mode by the time the slot starts carrying "
    "traffic so a forced NRE in its correct slot is not flagged as "
    "censored."
)
# ─── Tier 36: dynamic attester committee shrinks below pool size ──────
# Audit finding #3 (2026-04-28).  Tier 4 (`ATTESTER_REWARD_SPLIT_HEIGHT`)
# decoupled committee size from reward budget — fixed-target 128-slot
# committee, pool divided pro-rata, integer remainder burns.  That
# solved the legacy "only 3 paid forever at floor" failure but
# introduced a worse one: when `attester_pool <
# ATTESTER_COMMITTEE_TARGET_SIZE`, integer division rounds to 0 and
# EVERY attester earns 0 from issuance.
#
# Concretely, once halvings drive `BLOCK_REWARD` to `BLOCK_REWARD_FLOOR
# = 4`, `proposer_share = 1`, `attester_pool = 3`, and
# `3 // 128 == 0` — every attester's issuance income is permanently 0
# from year ~8 onward.  Even at genesis (`pool = 12`) only the first 12
# committee slots get 1 token; the remaining 116 burn (~90% leak of
# the pool's intended budget across the entire pre-floor regime).
#
# Two CLAUDE.md anchors are violated at once:
#   * "Validator profitability over decades" — issuance income drops to
#     0 forever once the floor binds.
#   * "Stake concentration is capped — sigmoid mid-tier compression
#     band closes the gap fastest" (Settled Design Decisions, reward
#     curve) — the Tier 20 multiplier (1.25× mid) on a base of 0 is
#     still 0; the entire compression mechanism is inert at floor era.
#
# Tier 36 fixes both with a dynamic committee: when `attester_pool <
# ATTESTER_COMMITTEE_TARGET_SIZE`, the caller shrinks committee_size
# to `min(target, attester_pool)` BEFORE invoking
# `select_attester_committee`.  Selection rule, randomness, and
# stake-weighted blending are unchanged — only the paid prefix length
# shrinks so every paid slot receives >= 1 token.  The remaining
# stake-set still attests for finality liveness; they just don't draw
# issuance for THIS block.  Stake-weighted committee selection rotates
# them through paid blocks at their stake-weighted frequency.
#
# Why this preserves anchors:
#   * Reward-curve multiplier reactivates because `per_slot_reward` is
#     now non-zero; mid-tier compression band actually applies.
#   * No change to proposer reward, base inflation curve, fee
#     distribution, or selection rule — pure attester-side parameter.
#   * Liveness unchanged: every committee member still attests for
#     finality; only payout eligibility changes.
#
# Pre-activation: `committee_size = ATTESTER_COMMITTEE_TARGET_SIZE`
# (Tier 4 behavior) so any block accepted under the old rule still
# replays byte-identically.  Post-activation: dynamic shrink active.
ATTESTER_DYNAMIC_COMMITTEE_HEIGHT = 1502  # Tier 36 — re-runwayed in 1.38.1 (was 768)
assert (
    ATTESTER_DYNAMIC_COMMITTEE_HEIGHT
    > NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT
), (
    "ATTESTER_DYNAMIC_COMMITTEE_HEIGHT must follow Tier 35 — Tier 36 "
    "rides on top of the most recent established fork with the standard "
    "runway buffer so callers between the two heights see the legacy "
    "fixed-target committee path."
)
# ─── Tier 37: forced-inclusion entity-cap excuse no longer accepts a
# same-entity lower-fpb fill ──────────────────────────────────────────
# Tier 34 wired the forced-inclusion gate into multi-list mode and
# anchored excuse #3 ("entity already at MAX_TXS_PER_ENTITY_PER_BLOCK")
# against `entity_counts` built from every block tx-list field.  That
# count, however, included every same-entity tx the proposer chose to
# include — even at LOWER fee-per-byte than the forced tx itself.  A
# colluding proposer with multiple pending lower-fpb txs from a single
# victim entity at sequential nonces could then:
#
#   1. Include the lower-fpb txs (filling MAX_TXS_PER_ENTITY_PER_BLOCK).
#   2. Omit the higher-fpb forced tx of the same entity.
#   3. Have the gate (correctly per the Tier 34 rule, incorrectly per
#      the broader anchor) accept the block under excuse #3.
#
# Because nonces must be sequential the forced tx IS the next nonce
# after the fill — it always fits structurally.  The cap was therefore
# an artifact of the proposer's own selection, not a real reason to
# skip.  The slashing risk on the inclusion-list-abuse surface
# collapsed to zero, breaking the CLAUDE.md anchor: "a tx that is well-
# formed, pays at least the per-byte floor, and fits the byte budget
# cannot be suppressed by anything weaker than a full validator-set
# majority actively colluding AND willing to absorb the slashing risk
# that exposed collusion produces."
#
# Tier 37 tightens excuse #3: when computing the cap for a forced tx,
# same-entity block txs whose fee-per-byte is STRICTLY LOWER than the
# forced tx's fee-per-byte do NOT count toward the cap.  Equivalent
# phrasing: the cap binds only on same-entity block txs the proposer
# could not have replaced with the forced tx without lowering revenue
# density — anything LESS-dense than the forced tx is the proposer's
# own selection artifact.  Honest full-quota cases (where same-entity
# block txs are at >= the forced tx's fpb) still excuse correctly:
# in that case the proposer maximized density honestly and the forced
# tx is the one that legitimately gets bumped.
#
# Pre-activation: legacy excuse #3 preserved byte-for-byte for replay
# determinism.  Post-activation: same-entity lower-fpb fill is no
# longer a valid excuse; the gate flags the omission as censorship.
FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT = 1534  # Tier 37 — re-runwayed in 1.38.1 (was 800)
assert (
    FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT
    > ATTESTER_DYNAMIC_COMMITTEE_HEIGHT
), (
    "FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT must follow Tier 36 — Tier "
    "37 rides on top of the most recent established fork with the "
    "standard runway buffer so callers between the two heights see "
    "the legacy excuse-#3 path."
)
assert (
    FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT
    > FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT
), (
    "FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT must follow Tier 34 — the "
    "cap-fix tightens the excuse on the multi-list gate; that gate "
    "must already be live by the time the new rule activates so the "
    "entity-count tally Tier 37 reads is the multi-list shape."
)
assert VALIDATOR_MIN_STAKE_TIER29 == VALIDATOR_MIN_STAKE_FAUCET_DRIP - MIN_FEE, (
    "VALIDATOR_MIN_STAKE_TIER29 must equal FAUCET_DRIP - MIN_FEE — "
    "Tier 29's whole intent is 'one drip = stake + fee + burn' end-to-end "
    "where MIN_FEE is the stake-tx fee floor; if either FAUCET_DRIP or "
    "MIN_FEE moves, this constant moves with them"
)
# Pin VALIDATOR_MIN_STAKE_FAUCET_DRIP to FAUCET_DRIP so the two cannot drift.
# Imported lazily below to avoid a top-of-module import cycle if any future
# faucet code grows a back-reference to config.
def _assert_faucet_drip_equality() -> None:
    from messagechain.network.faucet import FAUCET_DRIP as _FAUCET_DRIP
    assert VALIDATOR_MIN_STAKE_FAUCET_DRIP == _FAUCET_DRIP, (
        "VALIDATOR_MIN_STAKE_FAUCET_DRIP must equal FAUCET_DRIP byte-for-byte "
        "— Tier 28's whole intent is 'minimum stake = one faucet grab'; if "
        "FAUCET_DRIP moves, this constant moves with it"
    )

_assert_faucet_drip_equality()
assert REVOKE_TX_DEFAULT_VALID_FOR_BLOCKS > 0, (
    "REVOKE_TX_DEFAULT_VALID_FOR_BLOCKS must be positive — a zero "
    "default makes valid_from_height == valid_to_height, which is a "
    "single-block window that almost certainly does not include the "
    "broadcast height; a defaulted revoke would then never validate"
)
assert MAX_COMMUNITY_ID_LEN >= 1 and MAX_COMMUNITY_ID_LEN <= 255, (
    "MAX_COMMUNITY_ID_LEN must fit in a u8 length byte and allow at "
    "least one character — wire format reserves a single byte for "
    "the length prefix"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 20 — Sigmoid validator-reward curve (small/mid/large bands)
# ─────────────────────────────────────────────────────────────────────
# CLAUDE.md anchors a three-band shape for per-stake-unit earnings:
# small validators earn LESS per unit stake (slight suppression to
# discourage dust validators that add overhead without meaningful
# security), mid-tier validators earn MORE per unit stake (the catch-
# up band that compresses the distribution upward over time), and
# large validators saturate to a linear baseline (capped on the upper
# end by SEED_STAKE_CEILING_HEIGHT for seed entities).
#
# Pre-Tier-20 the only piece in code is the upper cap; the small and
# mid bands do not exist — every staker below the ceiling earns at the
# same flat per-stake rate.  Tier 20 introduces the missing two bands
# as a piecewise-constant multiplier applied to per-attester rewards
# in mint_block_reward.  Multiplier > 1 mints the delta on top of the
# halvings-adjusted reward; multiplier < 1 burns the shortfall.  Net
# issuance fluctuates slightly with the live stake distribution and
# averages near 1.0 once stakes settle into the curve's design region.
#
# Curve shape (basis points; 1 bp = 0.01%):
#   share <  50 bp  (<0.5%)        → multiplier 80/100  = 0.80
#   50 bp ≤ share < 500 bp (0.5–5%) → multiplier 125/100 = 1.25
#   share ≥ 500 bp (≥5%)            → multiplier 1/1     = 1.00 (baseline)
#
# Thresholds are expressed as fractions of total active stake (not
# absolute token amounts) so the curve auto-tracks network growth and
# does not require re-tuning via hard fork.  Exact numbers are tuning
# knobs; the SHAPE (small < mid > large, large = baseline) is what's
# anchored.
#
# Activation rides above Tier 19 (PROPOSAL_FEE_TIER19_HEIGHT = 13_000)
# with a ~2000-block runway (~14 days at 600 s/block) so operators
# upgrade through the prior fork before the new reward distribution
# starts.
REWARD_CURVE_HEIGHT = 717  # Tier 20 (reward curve) — fast-forwarded for 1.26.0 hard fork sweep

# Stake-share thresholds in basis points (1 bp = 0.01%, so 50 bp = 0.5%
# and 500 bp = 5%).  Defined as bp ints to keep the curve evaluable in
# pure integer arithmetic — no floats anywhere on the consensus path.
REWARD_CURVE_SMALL_THRESHOLD_BPS = 50    # 0.5% of total active stake
REWARD_CURVE_MID_THRESHOLD_BPS = 500     # 5%   of total active stake

# Multiplier numerator / denominator per band.  Applied as
# `reward * num // den` so the result stays integer.  Large band is
# implicit 1/1 (no scaling) — pre- and post-fork large-validator
# rewards are byte-identical, which keeps the upper-cap interaction
# with SEED_STAKE_CEILING simple.
REWARD_CURVE_SMALL_NUMERATOR = 80
REWARD_CURVE_SMALL_DENOMINATOR = 100
REWARD_CURVE_MID_NUMERATOR = 125
REWARD_CURVE_MID_DENOMINATOR = 100

assert REWARD_CURVE_HEIGHT > PROPOSAL_FEE_TIER19_HEIGHT, (
    "REWARD_CURVE_HEIGHT must follow PROPOSAL_FEE_TIER19_HEIGHT — Tier "
    "20 rides on top of the post-Tier-19 schedule; activating the new "
    "reward curve before Tier 19 settles would interleave two "
    "unrelated forks in the same upgrade window"
)
assert (
    0 < REWARD_CURVE_SMALL_THRESHOLD_BPS < REWARD_CURVE_MID_THRESHOLD_BPS
    < 10_000
), (
    "Reward-curve thresholds must satisfy "
    "0 < small < mid < 10_000 (=100%) — anything else collapses or "
    "inverts the band ordering and makes the piecewise function "
    "ill-defined"
)
assert (
    REWARD_CURVE_SMALL_NUMERATOR < REWARD_CURVE_SMALL_DENOMINATOR
), (
    "REWARD_CURVE_SMALL_NUMERATOR/DENOMINATOR must encode a multiplier "
    "< 1.0 — the small band is the suppression region; a ≥1 multiplier "
    "removes the dust-validator disincentive the band exists for"
)
assert (
    REWARD_CURVE_MID_NUMERATOR > REWARD_CURVE_MID_DENOMINATOR
), (
    "REWARD_CURVE_MID_NUMERATOR/DENOMINATOR must encode a multiplier "
    "> 1.0 — the mid band is the catch-up region; a ≤1 multiplier "
    "removes the boost that closes the gap between mid-tier validators "
    "and whales"
)
assert (
    REWARD_CURVE_SMALL_DENOMINATOR > 0
    and REWARD_CURVE_MID_DENOMINATOR > 0
), (
    "Reward-curve denominators must be positive — a zero denominator "
    "is an unevaluable multiplier and would crash the consensus path"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 37 — Reward-curve large band saturates downward
# ─────────────────────────────────────────────────────────────────────
# The Tier-20 curve was piecewise-constant 0.80 / 1.25 / 1.00 — a 5%-
# stake mid-tier validator and a 40%-stake whale earned at the SAME per-
# token rate.  CLAUDE.md's anchored shape is "small < middle > large,
# large saturating to flat/linear past a cap point" — large should earn
# at a LOWER per-unit-stake rate than middle-tier, never at parity.  At
# parity, a whale's reward share grows linearly with stake forever and
# concentration ossifies past 5%.
#
# Tier 38 adds a fourth band on top of the existing three:
#   share <  SMALL_THRESHOLD                           → 0.80   (unchanged)
#   SMALL_THRESHOLD ≤ share < MID_THRESHOLD            → 1.25   (unchanged)
#   MID_THRESHOLD   ≤ share < LARGE_THRESHOLD          → 1.00   (unchanged)
#   LARGE_THRESHOLD ≤ share < LARGE_FLOOR_THRESHOLD    → linear interp
#                                                        from 1.00 down
#                                                        to LARGE_FLOOR
#   share ≥ LARGE_FLOOR_THRESHOLD                      → LARGE_FLOOR
#
# The 5%→15% range is preserved at 1.0 so real-network behavior in the
# active stake range is unchanged; only the upper tail (15%+) compresses.
#
# Conservative tuning: LARGE_THRESHOLD = 1500 bp (15%), LARGE_FLOOR_
# THRESHOLD = 3000 bp (30%), floor = 50/100 (0.5).  Past 30% stake the
# multiplier sits at 0.5 — large stakers still earn (incentive to keep
# 24/7 uptime), still earn proportionally more in absolute tokens than
# anyone smaller, but no longer at the same per-stake-unit rate as a
# 5%-stake mid-tier validator.  Distribution compresses upward over time.
#
# All arithmetic is exact-rational integer; mirror the 1.35.0 honesty-
# curve treatment.  The new helper `reward_curve_multiplier_v2` in
# inflation.py interpolates with `(1 - t) * DEN + t * NUM` over an
# integer span and returns a (num, den) tuple — no float anywhere.
#
# Activation rides above Tier 36 with a runway buffer well clear of the
# current ~1300 mainnet tip so operators upgrade through prior forks
# before the new curve bites.
REWARD_CURVE_LARGE_BAND_HEIGHT = 1535  # Tier 38 — re-runwayed in 1.38.1 (was 801)

# Stake-share thresholds in basis points for the new saturating tail.
# 1500 bp = 15% (slope start), 3000 bp = 30% (slope end / floor).
REWARD_CURVE_LARGE_THRESHOLD_BPS = 1_500
REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS = 3_000

# Multiplier at and past LARGE_FLOOR_THRESHOLD_BPS.  50/100 = 0.5 — a
# 30%-stake validator earns at half the per-token rate of a 5%-stake
# mid-tier validator (1.25 × 2 = 2.5× compression ratio mid-vs-floor).
REWARD_CURVE_LARGE_FLOOR_NUM = 50
REWARD_CURVE_LARGE_FLOOR_DEN = 100

assert REWARD_CURVE_LARGE_BAND_HEIGHT > ATTESTER_DYNAMIC_COMMITTEE_HEIGHT, (
    "REWARD_CURVE_LARGE_BAND_HEIGHT must follow Tier 36 — Tier 38 "
    "rides on top of the most recent established fork with the "
    "standard runway buffer; pre-activation callers see the legacy "
    "Tier-20 piecewise-constant curve byte-for-byte"
)
assert REWARD_CURVE_LARGE_BAND_HEIGHT > FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT, (
    "REWARD_CURVE_LARGE_BAND_HEIGHT must follow Tier 37 — Tier 38 "
    "rides above the forced-inclusion entity-cap fix to preserve "
    "monotone tier ordering; the two are independent forks but the "
    "ladder is one-block-per-tier by convention"
)
assert REWARD_CURVE_LARGE_BAND_HEIGHT > REWARD_CURVE_HEIGHT, (
    "REWARD_CURVE_LARGE_BAND_HEIGHT must follow REWARD_CURVE_HEIGHT — "
    "the new saturating-large band is an extension of the Tier-20 "
    "small/mid/large curve; activating it before Tier 20 would make "
    "the slope path apply to history that never had even the legacy "
    "multiplier"
)
assert (
    REWARD_CURVE_MID_THRESHOLD_BPS
    < REWARD_CURVE_LARGE_THRESHOLD_BPS
    < REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS
    < 10_000
), (
    "Reward-curve large-band thresholds must satisfy "
    "MID < LARGE < LARGE_FLOOR < 10_000 (=100%) — anything else "
    "collapses or inverts the slope and makes the piecewise-linear "
    "function ill-defined"
)
assert (
    0 < REWARD_CURVE_LARGE_FLOOR_NUM < REWARD_CURVE_LARGE_FLOOR_DEN
), (
    "REWARD_CURVE_LARGE_FLOOR_NUM/DEN must encode a multiplier "
    "strictly between 0 and 1 — a floor at or above 1 leaves the "
    "large band at parity with mid (the bug), a floor at 0 nukes "
    "large stakers entirely (eliminating the uptime incentive)"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 39 — Submission-ack backdating defense
# ─────────────────────────────────────────────────────────────────────
# Pre-Tier-39 the validator-collusion threat surface had a two-validator
# escape hatch on the witness-non-response slashing arm: a coerced target
# validator could sign a SubmissionAck whose ``commit_height`` was set
# to any past height (e.g. ``earliest_observation_height - 1``), and a
# colluding proposer could embed that ack in
# ``block.acks_observed_this_block``.  The chain recorded
# ``ack.commit_height`` verbatim into ``witness_ack_registry``, the
# non-response apply gate then saw
# ``ack_h <= earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS`` →
# "obligation met" → no slash.  Two validators (target + proposer) was
# enough to neutralise the silent-drop arm of the validator-collusion
# defense entirely.
#
# Tier 39 lands two complementary defenses on the same activation
# height:
#
#   (a) ``_validate_acks_observed_this_block`` rejects an ack whose
#       ``commit_height`` is in the future
#       (``> block.header.block_number``) or too far in the past
#       (``block.header.block_number - commit_height >
#       WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE``).
#   (b) ``apply_block`` records ``block.header.block_number`` (the
#       inclusion height the chain first observed the ack at) in
#       ``witness_ack_registry``, NOT ``ack.commit_height``.
#
# (a) is defense-in-depth — it bounds the issuer's claim window to a
# small range around the inclusion height.  (b) is the real teeth: the
# stored discharge height is no longer issuer-controlled at all, so
# even if a future bug widens (a), the registry-source change still
# binds the discharge to actual on-chain observation.
#
# Pre-activation: legacy behavior preserved byte-for-byte for replay
# determinism — the registry continues to store
# ``ack.commit_height`` and the inclusion-window bound is skipped.
#
# Activation rides above Tier 38 with the standard runway buffer well
# clear of the current ~1300 mainnet tip.
ACK_BACKDATING_DEFENSE_HEIGHT = 1536  # Tier 39 — re-runwayed in 1.38.1 (was 802)

# Slack between an ack's signed ``commit_height`` and the height the
# proposer first lands the ack on chain.  An ack legitimately created
# at the moment a witness gossip arrives may take a few blocks to
# reach the next proposer's mempool and land in a block; the grace
# absorbs that propagation delay so honest acks are not rejected at
# the bound.  Small enough that it cannot itself be used to backdate
# meaningfully (DEADLINE = 8 + GRACE = 4 = 12 blocks ≈ 2 hours, vs.
# the censorship deadline the obligation is anchored to anyway).
ACK_INCLUSION_GRACE = 4

assert ACK_BACKDATING_DEFENSE_HEIGHT > REWARD_CURVE_LARGE_BAND_HEIGHT, (
    "ACK_BACKDATING_DEFENSE_HEIGHT must follow Tier 38 — Tier 39 rides "
    "on top of the most recent established fork with the standard "
    "runway buffer; pre-activation callers see the legacy "
    "registry-stores-commit_height path byte-for-byte"
)
assert ACK_INCLUSION_GRACE >= 0, (
    "ACK_INCLUSION_GRACE must be non-negative — a negative grace would "
    "reject acks whose commit_height landed at the same block they "
    "were signed at, which is the legitimate fast-path"
)
assert ACK_INCLUSION_GRACE < WITNESS_RESPONSE_DEADLINE_BLOCKS, (
    "ACK_INCLUSION_GRACE must be smaller than "
    "WITNESS_RESPONSE_DEADLINE_BLOCKS — a grace at or above the "
    "deadline would let an issuer backdate an ack to before the "
    "earliest legitimate observation height, defeating the whole "
    "point of the bound"
)

# Tier 40 — smooth concave reward curve.  Replaces the piecewise
# small/mid/baseline/saturating-tail shape of Tiers 20+38 with a single
# monotonically-diminishing function whose per-unit-stake yield decays
# smoothly from PEAK at near-zero stake toward FLOOR as stake grows
# without bound, but never reaches FLOOR — the asymptotic "soft cap"
# that CLAUDE.md anchors as the new reward-curve shape.
#
# The function is rational and pure-int (no float on consensus path):
#
#     multiplier(stake_bps) =
#       (FLOOR_NUM * stake_bps + PEAK_NUM * SCALE_BPS)
#       /
#       (MULT_DEN  * (SCALE_BPS + stake_bps))
#
# Properties (all derivable from the formula; documented here so a future
# reader doesn't have to re-derive them when touching parameters):
#   - At stake_bps=0:        multiplier = PEAK_NUM/MULT_DEN     (peak)
#   - As stake_bps→∞:        multiplier → FLOOR_NUM/MULT_DEN    (asymptote)
#   - Strictly decreasing in stake_bps (per-unit yield diminishes).
#   - Absolute reward (= stake_bps * multiplier) is strictly increasing
#     and concave in stake_bps — adding stake always pays more in
#     absolute terms, but each additional unit pays less than the last
#     (the "diminishing returns" the user wanted, and the "always earn
#     more" property that keeps the uptime incentive intact).
#   - Smooth: no kinks, no boundary-gaming incentives at piecewise
#     transitions (the Tier 20/38 curves had four).
#
# The single tuning knob with the most leverage on shape is SCALE_BPS:
# at stake_bps = SCALE_BPS the multiplier is exactly the midpoint of
# PEAK and FLOOR — i.e., (PEAK+FLOOR)/(2*MULT_DEN).  Smaller SCALE_BPS
# bends the curve harder in the small-stake region; larger SCALE_BPS
# pushes the bend out toward the whale region.  Current 300 puts the
# midpoint at 3% stake and yields a 0.5x multiplier exactly at 30%
# stake (algebraically equal to the old Tier 38 hard floor — chosen so
# the smoothed curve roughly preserves whale-tier compression at the
# height of activation, then continues to compress past it instead of
# flat-lining).
#
# Activation height comfortably above Tier 39 (height 802) and current
# tip (~835 at 1.37.0) with several hours of runway for operator
# rollout before the new shape bites.
REWARD_CURVE_SMOOTH_HEIGHT = 1701  # Tier 40 — compressed 2026-05-05 in 1.55.1 sweep (was 1634)

# Multiplier shape parameters.  All in the same MULT_DEN basis so the
# helper composes them with a single common denominator.
REWARD_CURVE_SMOOTH_PEAK_NUM = 150    # 1.50x at stake_bps=0 (tiny-validator yield)
REWARD_CURVE_SMOOTH_FLOOR_NUM = 40    # 0.40x asymptote as stake_bps→∞
REWARD_CURVE_SMOOTH_MULT_DEN = 100    # common denominator for PEAK/FLOOR
REWARD_CURVE_SMOOTH_SCALE_BPS = 300   # midpoint-multiplier point: at 3% stake the multiplier is (PEAK+FLOOR)/(2*MULT_DEN) = 0.95

assert REWARD_CURVE_SMOOTH_HEIGHT > ACK_BACKDATING_DEFENSE_HEIGHT, (
    "REWARD_CURVE_SMOOTH_HEIGHT must follow Tier 39 — Tier 40 rides "
    "on top of the most recent established fork; pre-activation "
    "callers continue to see the v2 saturating-tail curve byte-for-byte"
)
assert REWARD_CURVE_SMOOTH_HEIGHT > REWARD_CURVE_LARGE_BAND_HEIGHT, (
    "REWARD_CURVE_SMOOTH_HEIGHT must follow Tier 38 — Tier 40 replaces "
    "the piecewise-tail v2 helper with a smooth concave function and "
    "must not activate before the v2 shape it supersedes"
)
assert (
    0 < REWARD_CURVE_SMOOTH_FLOOR_NUM
    < REWARD_CURVE_SMOOTH_PEAK_NUM
), (
    "REWARD_CURVE_SMOOTH_FLOOR_NUM must be strictly between 0 and PEAK — "
    "FLOOR>=PEAK inverts or flattens the curve (no diminishing returns), "
    "FLOOR<=0 lets the asymptote nuke whale yield entirely, breaking the "
    "anchored 'always earn more for more stake' property"
)
assert REWARD_CURVE_SMOOTH_MULT_DEN > 0, (
    "REWARD_CURVE_SMOOTH_MULT_DEN must be positive — it is the common "
    "denominator for PEAK and FLOOR; zero is undefined"
)
assert REWARD_CURVE_SMOOTH_SCALE_BPS > 0, (
    "REWARD_CURVE_SMOOTH_SCALE_BPS must be positive — it sets where the "
    "curve bends and is the divisor in the rational form; zero would "
    "collapse the formula at stake_bps=0"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 41 — Ack-deadline grace defense on the slash-decision comparator
# ─────────────────────────────────────────────────────────────────────
# Tier 39 (ACK_BACKDATING_DEFENSE_HEIGHT) re-pinned the registry's
# recorded ack discharge height to ``block.header.block_number`` (the
# chain-observed inclusion height), closing the issuer-side backdating
# attack on witness-non-response slashing.  That fix introduced an
# asymmetry on the OTHER side of the same gate: an honest acker who
# publishes a valid SubmissionAck just before the deadline can be
# slashed if the next-proposer (colluding) declines to include it and
# the next honest proposer includes it at
# ``block_number = observed + DEADLINE + 1`` (one block past the
# deadline).  The slash-decision comparator
# ``ack_h <= earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS``
# returns False → "obligation not met" → curve-graded slash against
# the honest validator.  A two-validator collusion (Q witnesses +
# 1 deadline-tip proposer that drops the honest ack for one block)
# fabricates a non-response slash against an honest target.
#
# The validate-side path (``_validate_acks_observed_this_block``)
# already tolerates ``ACK_INCLUSION_GRACE`` of slack on the inclusion
# height; the slash-decision path must do the same so propose-side and
# apply-side stay in sync about what counts as "in window".
#
# Tier 41 widens the slash-decision comparator to:
#   ``ack_h <= earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS +
#              ACK_INCLUSION_GRACE``
# AND the same change is mirrored in ``compute_post_state_root`` so the
# propose-time sim and the apply-time non-response processor reach the
# same byte-identical decision on every block.
#
# Pre-activation: legacy comparator preserved byte-for-byte for replay
# determinism — historical mainnet blocks reapply unchanged.
#
# Activation rides above Tier 40 with a comfortable runway buffer
# above the current ~840 mainnet tip so operators upgrade through
# prior forks before the new comparator bites.
ACK_DEADLINE_GRACE_DEFENSE_HEIGHT = 1702  # Tier 41 — compressed 2026-05-05 in 1.55.1 sweep (was 1640)

assert ACK_DEADLINE_GRACE_DEFENSE_HEIGHT > REWARD_CURVE_SMOOTH_HEIGHT, (
    "ACK_DEADLINE_GRACE_DEFENSE_HEIGHT must follow Tier 40 — Tier 41 "
    "rides on top of the most recent established fork; pre-activation "
    "callers continue to see the legacy slash-decision comparator "
    "(no GRACE) byte-for-byte"
)
assert ACK_DEADLINE_GRACE_DEFENSE_HEIGHT > ACK_BACKDATING_DEFENSE_HEIGHT, (
    "ACK_DEADLINE_GRACE_DEFENSE_HEIGHT must follow Tier 39 — Tier 41 "
    "is the symmetric counterpart to the Tier-39 backdating defense "
    "on the slash-decision side; the registry-source change Tier 39 "
    "lands must already be live before the wider comparator activates "
    "or the comparator widens against issuer-controlled discharge "
    "heights instead of inclusion-controlled ones"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 42 — Smooth-curve V2 retune (tuning-knob change, anchored shape
# preserved)
# ─────────────────────────────────────────────────────────────────────
# Tier 40 (REWARD_CURVE_SMOOTH_HEIGHT) introduced the smooth concave
# multiplier helper with constants PEAK=150 / FLOOR=40 / SCALE_BPS=300.
# At today's mainnet bootstrap concentrations (2 validators ≈ 50% each,
# stake_bps≈5000) those constants put the multiplier at ~0.46×, which
# means ~50–67% of the attester pool burns every block (integer-rounding
# short of the pool at the attester_tokens_paid<attester_pool branch in
# inflation.mint_block_reward).  That violates two CLAUDE.md anchors at
# once: the bootstrap-arc anchor (issuance must be calibrated so the
# founder can credibly secure the network solo while it has only a
# handful of nodes) AND the "low steady perpetual inflation funds the
# security budget forever" anchor.  The Tier-40 curve-bend point (3%
# stake) sits below every realistic bootstrap concentration, so a
# bootstrap-era validator effectively earns at the asymptote.
#
# Tier 42 retunes the V1 constants to a wider curve-bend point and a
# higher floor:
#   PEAK_V2  = 130  (1.30× near-zero peak; was 1.50× under V1)
#   FLOOR_V2 =  80  (0.80× asymptote;   was 0.40× under V1)
#   SCALE_V2 = 1000 (curve-bend point at 10% stake; was 3% under V1)
# Resulting target shape (multiplier at given stake share):
#   50% (5000 bps): ~0.88×  (was ~0.46× under V1)
#   25% (2500 bps): ~0.94×
#   10% (1000 bps): ~1.05×
#    5% ( 500 bps): ~1.13×
#   near-zero peak: 1.30×
#
# CLAUDE.md anchors the SHAPE of this curve (concave, monotonically
# diminishing per-unit yield, asymptotic soft cap, no hard cap, no per-
# validator anti-sybil gate, strictly-increasing absolute reward,
# concave absolute reward, pure-int) but explicitly leaves the
# parameters as tuning knobs: "exact constants ... are tuning knobs."
# All shape invariants asserted by the V1 (Tier 40) test file continue
# to hold under V2 — see tests/test_reward_curve_smooth_tier_v2.py.
#
# Activation height comfortably above Tier 41 (1640) with multi-day
# runway above the current ~840 mainnet tip so operators upgrade
# through the prior fork ladder before the new shape bites.
REWARD_CURVE_SMOOTH_V2_HEIGHT = 1703  # Tier 42 — compressed 2026-05-05 in 1.55.1 sweep (was 2400)

# Multiplier shape parameters for the V2 retune.  Same MULT_DEN basis
# (REWARD_CURVE_SMOOTH_MULT_DEN, shared with V1) so the v4 helper
# composes them with a single common denominator, matching v3.
REWARD_CURVE_SMOOTH_V2_PEAK_NUM = 130    # 1.30x at stake_bps=0 (was 1.50x under V1)
REWARD_CURVE_SMOOTH_V2_FLOOR_NUM = 80    # 0.80x asymptote as stake_bps→∞ (was 0.40x under V1)
REWARD_CURVE_SMOOTH_V2_SCALE_BPS = 1000  # midpoint at 10% stake: (130+80)/(2*100) = 1.05 (was 3% under V1)

assert REWARD_CURVE_SMOOTH_V2_HEIGHT > REWARD_CURVE_SMOOTH_HEIGHT, (
    "REWARD_CURVE_SMOOTH_V2_HEIGHT must follow Tier 40 — Tier 42 retunes "
    "the V1 helper's tuning knobs (peak / floor / curve-bend point) "
    "while preserving the anchored CLAUDE.md shape; pre-activation "
    "callers continue to see the V1 helper byte-for-byte for replay "
    "determinism"
)
assert REWARD_CURVE_SMOOTH_V2_HEIGHT > ACK_DEADLINE_GRACE_DEFENSE_HEIGHT, (
    "REWARD_CURVE_SMOOTH_V2_HEIGHT must follow Tier 41 — Tier 42 rides "
    "on top of the most recent established fork; rolling the retune "
    "before the most recent comparator widening lands risks a "
    "mid-fork-ladder restart leaving the chain in an inconsistent "
    "comparator state across the curve change"
)
assert (
    0 < REWARD_CURVE_SMOOTH_V2_FLOOR_NUM
    < REWARD_CURVE_SMOOTH_V2_PEAK_NUM
), (
    "REWARD_CURVE_SMOOTH_V2_FLOOR_NUM must be strictly between 0 and "
    "PEAK — FLOOR>=PEAK inverts or flattens the V2 curve (no diminishing "
    "returns); FLOOR<=0 lets the asymptote nuke whale yield entirely, "
    "breaking the anchored 'always earn more for more stake' property"
)
assert REWARD_CURVE_SMOOTH_V2_SCALE_BPS > 0, (
    "REWARD_CURVE_SMOOTH_V2_SCALE_BPS must be positive — it sets where "
    "the V2 curve bends and is the divisor in the rational form; zero "
    "would collapse the formula at stake_bps=0"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 43 — Forced-inclusion source-side covers ALL tx pools.
# ─────────────────────────────────────────────────────────────────────
# Tier 34 closed the BLOCK-side gap of the forced-inclusion attester
# duty: post-Tier-34 the gate walks every block tx-list field via
# `_BLOCK_TX_LIST_ATTRS` so a forced TransferTransaction placed in
# `block.transfer_transactions` is recognized as included rather than
# flagged as omitted.  The corresponding SOURCE-side gap was left as a
# follow-up: `Mempool.get_forced_inclusion_set` walked only
# `self.pending` (Message + Transfer), so every other tx kind —
# server-local stake / unstake / authority / governance pools, AND
# the on-mempool censorship-evidence pool — was silently exempt from
# the rule.  A colluding proposer could drop the very
# CensorshipEvidenceTx filed against itself, an honest stake-rebalance
# or unstake-exit, or a governance vote that threatened its position,
# all with zero slashable evidence.  That violates the CLAUDE.md
# anchor "a tx that is well-formed, pays at least the per-byte floor,
# and fits the byte budget cannot be suppressed by anything weaker
# than a full validator-set majority actively colluding."
#
# Tier 43 closes the source-side symmetrically:
#   * Mempool gains a `register_forced_inclusion_source(callable)` API
#     so server-local pools can plug in without circular imports.
#     Pre-fork the registered sources are silently ignored to keep
#     historical attester behavior byte-identical.
#   * Mempool registers its on-board censorship_evidence_pool
#     internally — that pool already lives here so no plumbing across
#     module boundaries is needed.
#   * Server registers each of its four pending-tx pools (stake /
#     unstake / authority / governance) with arrival-height
#     bookkeeping so the wait-gate works the same way it does for
#     messages.
#   * Block-side: `censorship_evidence_txs` is added to
#     `_BLOCK_TX_LIST_ATTRS` so a forced evidence tx placed in its
#     correct slot is recognized as included.
#
# Pre-fork: byte-identical to legacy attester behavior — extra
# sources are NOT consulted, so any block accepted under the old
# rule still attests.  Post-fork: a forced governance / stake /
# unstake / authority / censorship-evidence tx left out of an
# otherwise-empty block fails the gate.
#
# Activation height comfortably above Tier 42 (REWARD_CURVE_SMOOTH_V2
# = 2400) with multi-day runway so operators upgrade through the
# prior fork ladder before the new source-side rule bites.  +734
# spacing matches the cohort the 1.38.1 re-runway used.
FORCED_INCLUSION_ALL_POOLS_HEIGHT = 1705  # Tier 43 — compressed 2026-05-05 in 1.55.1 sweep (was 3134)

assert FORCED_INCLUSION_ALL_POOLS_HEIGHT > REWARD_CURVE_SMOOTH_V2_HEIGHT, (
    "FORCED_INCLUSION_ALL_POOLS_HEIGHT must follow Tier 42 — the "
    "source-side rule rides on top of the most recent established "
    "fork ladder; rolling Tier 43 before Tier 42 risks a "
    "mid-fork-ladder restart leaving the chain on the extended "
    "source set without the curve-tuning fork active"
)
assert FORCED_INCLUSION_ALL_POOLS_HEIGHT > FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT, (
    "FORCED_INCLUSION_ALL_POOLS_HEIGHT must follow Tier 34 — the "
    "block-side multi-list walk is the prerequisite for the source-"
    "side extension; the gate cannot enforce against a tx kind whose "
    "block slot is not yet recognized"
)
assert FORCED_INCLUSION_ALL_POOLS_HEIGHT > FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT, (
    "FORCED_INCLUSION_ALL_POOLS_HEIGHT must follow Tier 37 — the "
    "entity-cap excuse fix is part of the same fee-per-byte ranking "
    "machinery the extended source set feeds into; activating the "
    "extended source before the cap-fix would re-open a same-entity "
    "lower-fpb fill loophole on the new tx kinds"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 44 — Polymorphic receipted-tx in CensorshipEvidenceTx.
# ─────────────────────────────────────────────────────────────────────
# CensorshipEvidenceTx hard-coded `MessageTransaction` for the receipted
# tx field, but `submit_transaction_to_mempool` issues
# `SubmissionReceipt`s for MessageTransaction AND TransferTransaction
# AND ReactTransaction.  A user holding a receipt for a Transfer or
# React that was silently dropped could NOT package it as evidence —
# `CensorshipEvidenceTx.from_bytes` / `.deserialize` called
# `MessageTransaction.from_bytes(...)` which fails on transfer / react
# payloads.  Net: receipts on transfer/react were slash-theatre — a
# coerced validator could issue them (looks fully accountable on the
# wire) and silently drop, with NO slashing path.
#
# Tier 44 closes this by extending the CensorshipEvidenceTx wire
# format to carry a single-byte kind-tag (0=Message, 1=Transfer,
# 2=React) immediately before the receipted-tx blob.  Decoder
# dispatches on the tag to the appropriate `*Transaction.from_bytes` /
# `.deserialize`.
#
# Pre-fork: byte-identical to legacy MessageTransaction-only format
# (no leading discriminator byte; receipts always lead with 4-byte
# u32 receipt-len whose high byte is 0x00).  Post-fork: a leading
# byte of 0x01 marks the new layout; the next byte is the kind tag.
# This is a wire-format change for blocks at/after the activation
# height; pre-fork blobs replay byte-identically.
#
# Also extends `CensorshipEvidenceProcessor.observe_block` to walk
# Message + Transfer + React tx lists when voiding pending evidence
# whose receipted tx lands on-chain.  Pre-fork observe_block only
# walked `block.transactions` — a transfer or react that WAS included
# would not void a (legacy) evidence, but legacy evidence couldn't
# target transfer/react in the first place, so the pre-fork
# observation is consistent with the pre-fork wire format.
#
# Activation height comfortably above Tier 43 (FORCED_INCLUSION_ALL_
# POOLS = 3134) with the standard +700-block runway so operators
# upgrade through the prior fork before the new wire format binds.
CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT = 1706  # Tier 44 — compressed 2026-05-05 in 1.55.1 sweep (was 3834)

assert CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT > FORCED_INCLUSION_ALL_POOLS_HEIGHT, (
    "CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT must follow Tier 43 — "
    "polymorphic receipted-tx rides on top of the source-side gate "
    "covering the censorship-evidence pool; rolling Tier 44 before "
    "Tier 43 leaves the new transfer/react-receipt evidences "
    "vulnerable to the same source-side drop the prior tier closed"
)

assert (
    PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT
    > CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT
), (
    "PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT must follow Tier 44 — "
    "the cap retune is an economics-only knob change that has nothing "
    "to do with the Tier 44 evidence wire format, but height ordering "
    "is enforced in tier order so operators upgrade through prior "
    "forks before the new cap binds"
)

assert BLOCK_BYTES_RAISE_HEIGHT > LINEAR_FEE_HEIGHT, (
    "BLOCK_BYTES_RAISE_HEIGHT must follow LINEAR_FEE_HEIGHT — the "
    "throughput raise rides on top of the linear fee formula; pre-"
    "linear heights still replay under the legacy flat / quadratic "
    "rules and do not see the post-raise per-byte rate"
)
assert FEE_PER_STORED_BYTE_POST_RAISE > FEE_PER_STORED_BYTE, (
    "FEE_PER_STORED_BYTE_POST_RAISE must raise (not lower) the per-byte "
    "floor — lowering it under a wider cap is the bloat-discipline "
    "failure mode the Tier 9 fork is designed to prevent"
)
assert TARGET_BLOCK_SIZE_POST_RAISE < MAX_TXS_PER_BLOCK, (
    "TARGET_BLOCK_SIZE_POST_RAISE must fit under the new MAX_TXS_PER_BLOCK "
    "cap — a target at or above the cap means the EIP-1559 controller "
    "can never see 'above-target' blocks and base fee only ever drops"
)
assert PREV_POINTER_HEIGHT > BLOCK_BYTES_RAISE_HEIGHT, (
    "PREV_POINTER_HEIGHT must follow BLOCK_BYTES_RAISE_HEIGHT — the "
    "prev-pointer feature prices the 33 extra bytes at the per-stored-"
    "byte rate, so the linear fee formula and its post-raise per-byte "
    "multiplier must already be active"
)
assert FIRST_SEND_PUBKEY_HEIGHT > PREV_POINTER_HEIGHT, (
    "FIRST_SEND_PUBKEY_HEIGHT must follow PREV_POINTER_HEIGHT — the "
    "first-send pubkey field is encoded in v3 txs that ALSO carry the "
    "prev-pointer presence-flag (in the same wire layout), so the "
    "prev-pointer dispatch must already be live before v3 is admitted"
)
assert INTL_MESSAGE_HEIGHT > FIRST_SEND_PUBKEY_HEIGHT, (
    "INTL_MESSAGE_HEIGHT must follow FIRST_SEND_PUBKEY_HEIGHT — the "
    "Tier 12 UTF-8 plaintext rule rides on top of the established "
    "v3 message-tx layout; activating it before v3 would mean the "
    "post-fork validator dispatches on a height range where the "
    "wire format the chain expects is still v1/v2-only"
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
# Halvings-aware proposer cap rides on top of Tier 18.  No structural
# dependency on TIER_18_HEIGHT itself, but ordering keeps the fork
# numbering monotone and gives operators a single readable timeline.
assert PROPOSER_CAP_HALVING_HEIGHT > SOFT_SLASH_HEIGHT, (
    "PROPOSER_CAP_HALVING_HEIGHT must follow SOFT_SLASH_HEIGHT — Tier 21 "
    "rides above Tier 20 in the fork schedule"
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
    ("LINEAR_FEE_HEIGHT", LINEAR_FEE_HEIGHT),
    ("BLOCK_BYTES_RAISE_HEIGHT", BLOCK_BYTES_RAISE_HEIGHT),
    ("PREV_POINTER_HEIGHT", PREV_POINTER_HEIGHT),
    ("FIRST_SEND_PUBKEY_HEIGHT", FIRST_SEND_PUBKEY_HEIGHT),
    ("INTL_MESSAGE_HEIGHT", INTL_MESSAGE_HEIGHT),
    ("VERSION_SIGNALING_HEIGHT", VERSION_SIGNALING_HEIGHT),
    ("MESSAGE_TX_LENGTH_PREFIX_HEIGHT", MESSAGE_TX_LENGTH_PREFIX_HEIGHT),
    ("GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT", GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT),
    ("MARKET_FEE_FLOOR_HEIGHT", MARKET_FEE_FLOOR_HEIGHT),
    ("REACT_TX_HEIGHT", REACT_TX_HEIGHT),
    ("TIER_18_HEIGHT", TIER_18_HEIGHT),
    ("PROPOSAL_FEE_TIER19_HEIGHT", PROPOSAL_FEE_TIER19_HEIGHT),
    ("SOFT_SLASH_HEIGHT", SOFT_SLASH_HEIGHT),
    ("PROPOSER_CAP_HALVING_HEIGHT", PROPOSER_CAP_HALVING_HEIGHT),
    ("VOTER_REWARD_HEIGHT", VOTER_REWARD_HEIGHT),
    ("HONESTY_CURVE_HEIGHT", HONESTY_CURVE_HEIGHT),
    ("COMMUNITY_ID_HEIGHT", COMMUNITY_ID_HEIGHT),
    ("REVOKE_TX_WINDOW_HEIGHT", REVOKE_TX_WINDOW_HEIGHT),
):
    assert _fork_height < _BEH, (
        f"{_fork_name} ({_fork_height}) must activate before "
        f"BOOTSTRAP_END_HEIGHT ({_BEH})"
    )
del _fork_name, _fork_height

# Tier 20 (soft equivocation slash) rides above Tier 19 (proposal fee
# tightening).  The two forks touch disjoint subsystems (slashing vs
# governance fees) so the order is operational, not semantic — but
# spacing them by ~2000 blocks (~14 days at 600 s/block) gives
# operators a clean cutover window per fork rather than collapsing
# both rule changes into a single activation block.
assert SOFT_SLASH_HEIGHT > PROPOSAL_FEE_TIER19_HEIGHT, (
    "SOFT_SLASH_HEIGHT must follow PROPOSAL_FEE_TIER19_HEIGHT — Tier 20 "
    "soft slashing rides above the latest established fork (Tier 19 "
    "proposal fee tightening)"
)
# Tier 23 (honesty curve) supersedes Tier 20's flat soft-slash with a
# per-offender curve.  Curve must activate AFTER soft-slash so the
# graceful-degrade case (no track record, ambiguous evidence) lands
# at the same 5% baseline Tier 20 already established.
assert HONESTY_CURVE_HEIGHT > SOFT_SLASH_HEIGHT, (
    "HONESTY_CURVE_HEIGHT must follow SOFT_SLASH_HEIGHT — Tier 23 "
    "supersedes Tier 20's flat 5% with a track-record-aware curve; "
    "the curve's AMBIGUOUS first-offense baseline equals Tier 20's "
    "SOFT_SLASH_PCT, so the soft-slash regime must already be the "
    "active default at curve activation"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 48 — witness-root activation (B-2 of the witness-tier fork)
# ─────────────────────────────────────────────────────────────────────
# At and after WITNESS_ROOT_ACTIVATION_HEIGHT, every block header MUST
# carry header.witness_root == compute_block_witness_root(block) — a
# Merkle commitment to every signature byte across all signed body
# slots (see messagechain.core.witness.SLOT_*).  Pre-activation blocks
# pass the field through unchecked (legacy default b"\x00" * 32).
#
# Why this matters: witness separation already runs in production
# (strip_block_witnesses + attach_block_witnesses in chaindb.py) but
# the existing single-slot compute_witness_root is never called from
# production code, so today's separated witnesses have no header
# commitment to verify against.  Tier 48 closes that gap by binding
# every signed body slot's signatures into a single Merkle root that
# the proposer signs and validators check on receipt.  Pre-activation
# behavior is unchanged; activation makes the existing strip/attach
# flow cryptographically safe.
#
# Activation height: 15_000.  Mainnet tip is ~1_500 (live since
# 2026-04-20); 15_000 leaves ~95 days of runway at 600s blocks for
# operators to upgrade past Tier 47 (dormancy controller, height
# 5_934) before the new check engages.  Don't compress this — the
# only way to test the activation gate without a network split is to
# have every operator on a binary that knows about the new rule
# before the cutover.
WITNESS_ROOT_ACTIVATION_HEIGHT = 1712  # Tier 48 — compressed 2026-05-05 in 1.55.1 sweep (was 15_000)

# Witness-root must activate after the most recent body-slot addition
# (Tier 35 added non_response_evidence_txs).  Activating before that
# slot exists would commit witness_root to a body shape the chain
# hasn't reached, making historical re-validation impossible.
assert WITNESS_ROOT_ACTIVATION_HEIGHT > NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT, (
    "WITNESS_ROOT_ACTIVATION_HEIGHT must follow "
    "NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT — Tier 48 commits to every "
    "signed body slot, so the latest body-slot addition (Tier 35 NRE) "
    "must already be active before the commitment locks in"
)

# Witness-root activation also rides above the dormancy controller
# (Tier 47), since both touch consensus-binding header fields and
# operators benefit from a clean cutover window between them.
assert WITNESS_ROOT_ACTIVATION_HEIGHT > DORMANCY_CONTROLLER_HEIGHT, (
    "WITNESS_ROOT_ACTIVATION_HEIGHT must follow DORMANCY_CONTROLLER_HEIGHT "
    "— Tier 48 rides above Tier 47 (dormancy controller); spacing keeps "
    "the consensus-header-field changes from collapsing into a single "
    "activation window"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 49: unified fee floor across non-message tx types (hard fork)
# ─────────────────────────────────────────────────────────────────────
# Pre-Tier-49 admission for TransferTransaction / StakeTransaction /
# UnstakeTransaction enforced ``tx.fee >= max(MIN_FEE, MARKET_FEE_FLOOR)``
# = ``max(100, 1)`` = 100, while MessageTransaction admission used the
# Tier-16 ``MARKET_FEE_FLOOR=1`` directly.  Same fee model, 100×
# different floors — a transfer at 96 stored bytes paying 100 tokens
# is fee-per-byte 1.04, while a message at ~280 stored bytes paying 1
# token is fee-per-byte 0.0036, so transfers structurally crowd
# messages out of the mempool at the floor.  Violates the fee-model
# anchor "Every tx type the chain accepts ... follows this same fee
# model.  Don't carve out per-type fee logic" and the auto-fee
# anchor "any wallet/CLI helper ... computes a target fee-per-byte
# from current mempool conditions and multiplies by the tx's stored
# byte count".
#
# At and after this height, transfer / stake / unstake admission uses
# ``flat_floor = MARKET_FEE_FLOOR`` instead of ``MIN_FEE``, restoring
# the unified fee model: every tx type binds at the same protocol
# baseline, with selection-by-fee-per-byte and the EIP-1559 base fee
# above the floor doing the market work.  Reaction txs already moved
# to MARKET_FEE_FLOOR at Tier 18 (TIER_18_HEIGHT); this fork brings
# transfer / stake / unstake into the same regime.
#
# Type-specific surcharges that legitimately bind above
# MARKET_FEE_FLOOR (NEW_ACCOUNT_FEE on transfer, GOVERNANCE_PROPOSAL_FEE
# on propose, KEY_ROTATION_FEE, AUTHORITY_KEY_FEE, REVOKE_TX_FEE,
# RECEIPT_SUBTREE_ROOT_FEE) are unaffected — they are layered on top
# of the protocol floor at their respective callsites.
#
# Activation: above the existing 1700–1712 fork band with ~38 blocks
# (~6.3h at 600s) of additional spacing.  Two-validator network, both
# operator-controlled, so the cutover is coordinated and the runway
# bound is operational (binary deploy + restart) rather than the
# multi-week external-validator notice the band was originally sized
# for.  Pre-fork blocks replay byte-identically because every
# historical transfer / stake / unstake on chain paid >= MIN_FEE=100
# anyway — the verifier admits everything it admitted before; only
# new low-fee txs become acceptable post-fork.
UNIFIED_FEE_FLOOR_HEIGHT = 1750  # Tier 49

assert UNIFIED_FEE_FLOOR_HEIGHT > WITNESS_ROOT_ACTIVATION_HEIGHT, (
    "UNIFIED_FEE_FLOOR_HEIGHT must follow Tier 48 — operators upgrade "
    "through prior forks before this admission-rule change binds, and "
    "the cohort spacing keeps consensus-rule changes from collapsing "
    "into a single activation window"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 50 — Inclusive voter rewards (hard fork)
# ─────────────────────────────────────────────────────────────────────
# Pre-Tier-50 (i.e. Tier 22, VOTER_REWARD_HEIGHT) violated the
# governance anchor in CLAUDE.md:
#
#     "voters who cast a vote during the window receive a reward
#      funded out of the proposal fee."
#
# in two compounding ways:
#
#   1. NO-voters never earned anything, even on a passing proposal —
#      the winners filter excluded `if not approve: continue`.
#   2. Rejected proposals burned the entire pool, so every voter's
#      deliberation was unrewarded.
#
# Net: a stake-weighted voter has a measurable pay incentive to vote
# YES regardless of merit (50_000-token surcharge × yes-only payouts ×
# full-burn-on-reject), corrupting the very signal governance is
# supposed to produce — and biasing the founder→community handoff in
# the wrong direction during the bootstrap window where this hurts
# most.
#
# Tier 50 closes both gaps: at and above VOTER_REWARD_INCLUSIVE_HEIGHT,
# the per-proposal voter-reward escrow distributes pro-rata across
# ALL voters (yes OR no) by live stake at close, regardless of
# pass/fail.  Pre-fork proposals (closed at current_block <
# VOTER_REWARD_INCLUSIVE_HEIGHT) preserve the byte-identical legacy
# Tier-22 behavior so historical replay is unchanged.
#
# Activation height 1800 sits above Tier 49 (UNIFIED_FEE_FLOOR_HEIGHT
# = 1750) with ~50 blocks ≈ 8.3h cohort spacing at 600s blocks; current
# tip ~1593 gives ~207 blocks ≈ 35 hours of runway for the binary
# rollout.  Two-validator network, both operator-controlled, so the
# cutover is coordinated and the runway bound is operational rather
# than the multi-week external-validator notice the band was
# originally sized for.
VOTER_REWARD_INCLUSIVE_HEIGHT = 1800  # Tier 50

assert VOTER_REWARD_INCLUSIVE_HEIGHT > UNIFIED_FEE_FLOOR_HEIGHT, (
    "VOTER_REWARD_INCLUSIVE_HEIGHT must follow Tier 49 — operators "
    "upgrade through Tier 49 before this consensus-rule change binds, "
    "and the cohort spacing keeps two consecutive consensus-rule "
    "changes from collapsing into a single activation window"
)
assert VOTER_REWARD_INCLUSIVE_HEIGHT > VOTER_REWARD_HEIGHT, (
    "VOTER_REWARD_INCLUSIVE_HEIGHT must follow Tier 22 — the legacy "
    "yes-only path must remain reachable for historical proposals "
    "closing pre-Tier-50"
)

# Tier 51 — AMBIGUOUS slash severity cap (hard fork)
#
# Bounds AMBIGUOUS-path output at HONESTY_CURVE_AMBIGUOUS_MAX_PCT.
# See the constants block above for the math, motivation, and
# CLAUDE.md anchor (honest-operator insurance).  UNAMBIGUOUS path is
# unchanged.
#
# Activation height 1850 sits above Tier 50 (VOTER_REWARD_INCLUSIVE_
# HEIGHT = 1800) with ~50 blocks ≈ 8.3h cohort spacing at 600s blocks.
# Two-validator network, both operator-controlled, so the cutover is
# coordinated and the runway bound is operational rather than the
# multi-week external-validator notice the band was originally sized
# for.  Pre-fork blocks replay byte-identically because the cap only
# REDUCES severity, and every historical AMBIGUOUS slash on chain was
# applied uncapped — the verifier admits the same slash_pct it
# admitted before.  Only post-fork high-prior + relief-erosion cases
# see the cap bind.
HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT = 1850  # Tier 51

assert HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT > VOTER_REWARD_INCLUSIVE_HEIGHT, (
    "HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT must follow Tier 50 — operators "
    "upgrade through Tier 50 before this consensus-rule change binds, "
    "and the cohort spacing keeps two consecutive consensus-rule "
    "changes from collapsing into a single activation window"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 53 — proposer-cap clawback redistributes (no longer burns)
# ─────────────────────────────────────────────────────────────────────
# `SupplyTracker.mint_block_reward` enforces a per-block cap on the
# proposer's combined earnings (proposer share + their attester slot
# if they're on the committee).  Pre-fork the cap-overage was BURNED
# from supply.  CLAUDE.md anchor: stake-concentration soft cap is
# anchored as compression of *share* via diminishing returns, NOT
# punitive burn of validator earnings.  The legacy burn defeats the
# anchor and -- post-Tier-47 dormancy controller (height 1710) -- is
# now incinerating ~50% of every issuance refill on today's
# 2-validator mainnet (each validator both proposes and attests on
# the other's blocks; cap binds every block; per-slot ≈ 187 tokens
# burns).  Net effect: the controller's "close the gap to
# DORMANCY_TARGET_ACTIVE_SUPPLY" function lands at 50% efficiency,
# slowing the bootstrap-arc dilution toward broad democratization.
#
# Post-fork: the trim is REDISTRIBUTED pro-rata among non-proposer
# attesters (those with positive attestor_rewards credit) instead of
# burned.  The cap's anti-disproportionate-capture intent is
# preserved (proposer's net retention still tops out at
# effective_cap), but total issuance still accrues to validators.
# When no non-proposer attester has positive credit (sole-proposer-
# attester committee, all others zeroed by per-validator cap, etc.)
# the trim falls back to BURN -- preserving the cap's intent without
# inventing a tie-breaker.  Rounding remainder from pro-rata
# distribution (< len(other_attesters) tokens per block) burns to
# keep the net-inflation invariant tight.
#
# Pre-fork blocks replay byte-identically: when the cap binds and
# `proposer_share == effective_cap` (the post-Tier-21 typical case)
# the legacy "burn full proposer_att_reward" matches the new "trim
# full proposer_att_reward and fall through to burn when no other
# credited attester" path.  The behavioral split kicks in only on
# multi-attester committees with at least one non-proposer holding
# positive credit -- exactly the case the fix targets.
#
# Activation height 1900 sits above Tier 51
# (HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT = 1850) with ~50 blocks ≈ 8.3h
# cohort spacing at 600s blocks, matching the spacing pattern Tiers
# 49-51 used (1750/1800/1850).  Two-validator network, both
# operator-controlled, so the cutover is coordinated and the runway
# bound is operational.
PROPOSER_CAP_REDISTRIBUTE_HEIGHT = 1900  # Tier 53


# ─────────────────────────────────────────────────────────────────────
# Tier 54 — dormancy controller K_DEN retune (linear band → 100M gap)
# ─────────────────────────────────────────────────────────────────────
# Pre-Tier-54 the controller's gain is K = 1 / 20_000.  Combined with
# DORMANCY_MAX_ISSUANCE_PER_BLOCK = 500, the proportional term saturates
# the ceiling at gap = 10M tokens (10M × 1 / 20_000 = 500 = MAX).  Any
# gap beyond 10M produces the same per-block mint as a 10M gap — the
# controller's "respond proportionally to the gap" property collapses
# to "constant at MAX once the gap exceeds 10M."
#
# That tuning is wrong for the realized mainnet trajectory.  Seed-
# divestment is scheduled to burn ~85M of founder stake over its
# 4-year window; mid-divestment plausible active supply ≈ 55M, gap ≈
# 45M, controller pegs at MAX = 500/block = ~26.3M tokens/yr ≈ 26%/yr
# of TARGET sustained for years until active recovers above 90M.
# That regime breaks two anchors at once: "the chain's nominal token
# unit must hold its real economic weight across centuries" (a 26%/yr
# regime for years inverts the promise) and "issuance's purpose is
# supply replenishment, not security-funding" (at MAX the controller
# dwarfs every other economic lever).
#
# Tier 54 retunes K_DEN from 20_000 → 200_000 so the linear band
# reaches MAX only at gap = 100M (the real catastrophic-event scale,
# not a routine mid-divestment gap).  Post-retune at gap = 10M, raw =
# 50/block ≈ 2.6M tokens/yr — order of the documented burn rate, no
# saturation, controller actually closes the gap proportionally as
# CLAUDE.md anchors.  At gap = 100M (founder fully dormant scenario),
# raw = 500/block = MAX, ceiling still binds for a real worst case.
#
# Pure constant retune; no consensus-shape change.  Pre-fork blocks
# replay byte-identically via the height gate inside
# ``compute_dormancy_issuance``.  Activation height 1950 sits above
# Tier 53 (PROPOSER_CAP_REDISTRIBUTE_HEIGHT = 1900) with ~50 blocks ≈
# 8.3h cohort spacing at 600s blocks, matching the spacing pattern
# Tiers 49-53 used.  Surfaced by audit r29 top-3 #2.
DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT = 1950  # Tier 54
DORMANCY_CONTROLLER_K_DEN_POST_RETUNE = 200_000

assert DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT > PROPOSER_CAP_REDISTRIBUTE_HEIGHT, (
    "DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT must follow Tier 53 — "
    "operators upgrade through Tier 53 before this consensus-rule "
    "change binds, and the cohort spacing keeps two consecutive "
    "consensus-rule changes from collapsing into a single activation "
    "window"
)
assert DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT > DORMANCY_CONTROLLER_HEIGHT, (
    "DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT must follow Tier 47 — "
    "the controller itself activates at Tier 47; retuning its gain "
    "before activation is a contradiction"
)
assert DORMANCY_CONTROLLER_K_DEN_POST_RETUNE > 0, (
    "DORMANCY_CONTROLLER_K_DEN_POST_RETUNE must be positive — same "
    "invariant as the legacy K_DEN"
)
assert DORMANCY_CONTROLLER_K_DEN_POST_RETUNE > DORMANCY_CONTROLLER_K_DEN, (
    "DORMANCY_CONTROLLER_K_DEN_POST_RETUNE must be strictly greater "
    "than the legacy K_DEN — Tier 54's intent is to tighten the gain "
    "(larger denominator), not loosen it"
)


assert PROPOSER_CAP_REDISTRIBUTE_HEIGHT > HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT, (
    "PROPOSER_CAP_REDISTRIBUTE_HEIGHT must follow Tier 51 — operators "
    "upgrade through Tier 51 before this consensus-rule change binds, "
    "and the cohort spacing keeps two consecutive consensus-rule "
    "changes from collapsing into a single activation window"
)
assert PROPOSER_CAP_REDISTRIBUTE_HEIGHT > PROPOSER_CAP_HALVING_HEIGHT, (
    "PROPOSER_CAP_REDISTRIBUTE_HEIGHT must follow Tier 21 — Tier 21 "
    "established the halving-aware cap; the redistribute fork only "
    "changes what happens to the cap-overage (burn -> redistribute) "
    "and assumes the cap itself is already binding via Tier 21's "
    "post-halving formula"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 55 — inactivity & coverage leaks consult the honesty curve.
# ─────────────────────────────────────────────────────────────────────
# Pre-Tier-55: ``compute_inactivity_penalty`` and
# ``compute_coverage_penalty`` were pure functions of
# ``(blocks_since_finality, validator_stake)`` /
# ``(consecutive_misses, attester_stake)``.  Neither consulted
# ``slashing_severity``, ``_track_record``, or ``_prior_offenses`` --
# the entire Tier-23/24/51 honesty-curve machinery every other
# slashing path uses.
#
# Worst case: a fork-emergency auto-halt (network/node.py correctly
# halts attestation/finality voting on the minority side -- the right
# thing) puts honest, long-tenured validators into the leak-eligible
# set the moment finality stalls past
# INACTIVITY_LEAK_ACTIVATION_THRESHOLD.  The validator is doing
# exactly what the protocol asks; the chain bleeds their stake
# quadratically as punishment, identical to a withholding cartel's
# bleed.  CLAUDE.md anchor at risk: "long-tenured, high-volume,
# high-honesty operators get fractional penalties at worst" -- the
# inactivity leak silently exempted itself.
#
# Tier 55 routes both penalty paths through a relief multiplier
# (``honest_history_relief_multiplier_bps``) that mirrors the
# AMBIGUOUS-path relief in ``slashing_severity``:
#
#   * Validator with prior offenses: NO relief (10000 bps = full
#     nominal penalty).  Repeat offenders pay full price.
#   * Validator with track_record < HONEST_TRACK_THRESHOLD:
#     NO relief.  Fresh validators carry less benefit-of-the-doubt.
#   * Long-tenured high-honesty validator with no priors: relief
#     multiplier capped at FLOOR_NUM/FLOOR_DEN = 1/5 = 2000 bps =
#     20% of nominal penalty.
#
# Cartel-defense behavior is preserved: cartel members are by
# definition NOT long-tenured-high-honesty (the curve reads
# proposer_sig_counts + reputation, both of which a cartel can't
# forge without doing tons of honest work first), so a 40% withholding
# cartel still gets the full quadratic bleed.  The relief targets
# the honest minority that ends up on the wrong side of a partition
# or fork-emergency halt -- exactly the operators the
# honest-operator-insurance anchor is for.
#
# Pure relief-multiplier post-pass; pre-fork blocks replay byte-
# identically because the legacy 4-arg call shape stays the default
# (``current_height=None, blockchain=None`` ⇒ no relief, byte-for-
# byte legacy bleed).  Activation height 2000 sits above Tier 54
# (DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT = 1950) with ~50 blocks ≈
# 8.3h cohort spacing at 600s blocks, matching the spacing pattern
# Tiers 49-54 used.  Surfaced by audit r30 top-3 #2.
INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT = 2000  # Tier 55

assert INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT > DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT, (
    "INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT must follow Tier 54 -- "
    "operators upgrade through Tier 54 before this consensus-rule "
    "change binds, and the cohort spacing keeps two consecutive "
    "consensus-rule changes from collapsing into a single activation "
    "window"
)
assert INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT > HONESTY_CURVE_HEIGHT, (
    "INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT must follow Tier 23 -- the "
    "honesty-curve infrastructure activates at Tier 23; the "
    "inactivity-leak path can only consult it after that activates"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 56 — TreasurySpendTransaction proposers pay VOTER_REWARD_SURCHARGE.
# ─────────────────────────────────────────────────────────────────────
# Pre-fix bug: ``Blockchain._validate_governance_tx`` required ``fee +
# VOTER_REWARD_SURCHARGE`` for ``ProposalTransaction`` only; the
# ``TreasurySpendTransaction`` branch fell through with
# ``required = fee``.  The apply path tried to debit the surcharge
# for both classes, but without a corresponding validation gate a
# treasury-spend proposer with exactly ``fee`` balance silently
# escrowed ``voter_reward_pool=0`` -- voters did the work of
# evaluating the proposal and got paid nothing.
#
# Treasury spends are arguably the *most* economically consequential
# governance class (they actually move treasury funds, vs. advisory
# proposals that don't move money).  CLAUDE.md anchor: "voters who
# cast a vote during the window receive a reward funded out of the
# proposal fee -- the proposer pays the voters they're asking to
# evaluate the proposal."  Pre-fix the most-money-moving proposal
# class was exempt from the rule.
#
# Tier 56 makes the surcharge mandatory for both
# ``ProposalTransaction`` and ``TreasurySpendTransaction`` post-
# activation: validation rejects a treasury-spend whose proposer
# cannot afford ``fee + SURCHARGE``; apply debits the surcharge into
# ``voter_reward_pool`` symmetrically with the existing proposal
# path.
#
# Pure admission-rule tightening + apply-path symmetrization; pre-
# fork blocks replay byte-identically because the validation gate
# stays loose below the activation height (the looser pre-fork rule
# is the ground truth for any pre-fork block).  Activation height
# 2050 sits 50 blocks above Tier 55 (INACTIVITY_LEAK_HONESTY_CURVE_
# HEIGHT = 2000) -- ~8.3h cohort spacing at 600s blocks, matching
# the Tier 49-55 spacing pattern.  Surfaced by audit r30 top-3 #3.
TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT = 2050  # Tier 56

assert TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT > INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT, (
    "TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT must follow Tier 55 -- "
    "operators upgrade through Tier 55 before this consensus-rule "
    "change binds, and the cohort spacing keeps two consecutive "
    "consensus-rule changes from collapsing into a single activation "
    "window"
)
assert TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT > VOTER_REWARD_HEIGHT, (
    "TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT must follow Tier 22 -- "
    "the voter-reward-surcharge mechanism activates at Tier 22; the "
    "Tier 56 fork only EXTENDS that mechanism to TreasurySpend, so "
    "Tier 22 must already be active"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 57 — transfer apply path routes through ``pay_fee_with_burn``
# so the attester-fee-funding split, the DEFLATION_FLOOR_V2 rolling-
# fee-burn accumulator, and the ``fee_burn_this_block`` ticker accrue
# on transfer txs.
# ─────────────────────────────────────────────────────────────────────
# Pre-fix bug: ``Blockchain._apply_transfer_with_burn`` hand-rolled
# fee accounting (``balances[from] -= fee; balances[proposer] += tip;
# total_supply -= burned``) instead of routing through
# ``SupplyTracker.pay_fee_with_burn``.  Every other tx kind (message,
# stake, governance, react, authority) routes through the helper.
# Transfers alone bypassed it.
#
# Three CLAUDE.md anchors break silently as soon as transfer volume
# matters:
#   (a) ATTESTER_FEE_FUNDING split (Tier 4) -- attester pool silently
#       missed the transfer-share of base-fee burn.
#   (b) DEFLATION_FLOOR_V2 rolling-fee-burn accumulator -- fee-
#       responsive issuance rebate undercounts transfer-share burns.
#   (c) ``fee_burn_this_block`` ticker -- archive-reward redirect
#       missed transfer-share burns.
#
# Today's mainnet has near-zero transfer volume so the leak is
# invisible -- that is the worst possible time to catch it.  The
# moment the dual-purpose-token anchor pays off and transfers become
# a real share of fee burn, the under-accrual bites.
#
# Tier 57 splits the apply path on a height gate.  Pre-fork (height <
# TRANSFER_FEE_UNIFIED_HEIGHT) the legacy hand-rolled accounting runs
# unchanged -- byte-identical to pre-Tier-57 code, so every historical
# transfer block replays identically post-upgrade.  Post-fork the
# (tx.fee - surcharge) base-fee+tip portion routes through
# pay_fee_with_burn; the NEW_ACCOUNT_FEE surcharge burns separately
# (matching legacy "burned was the full base_fee + surcharge"
# semantics for total-supply/total-burned, plus crediting fee_burn_
# this_block so archive-reward redirect sees the full burn).
#
# Activation height 2100 sits 50 blocks above Tier 56 (TREASURY_SPEND_
# VOTER_SURCHARGE_HEIGHT = 2050) -- ~8.3h cohort spacing at 600s
# blocks, matching the Tier 49-56 spacing pattern.  Surfaced by audit
# r31 top-3 #2.
TRANSFER_FEE_UNIFIED_HEIGHT = 2100  # Tier 57

assert TRANSFER_FEE_UNIFIED_HEIGHT > TREASURY_SPEND_VOTER_SURCHARGE_HEIGHT, (
    "TRANSFER_FEE_UNIFIED_HEIGHT must follow Tier 56 -- operators "
    "upgrade through Tier 56 before this consensus-rule change binds, "
    "and the cohort spacing keeps two consecutive consensus-rule "
    "changes from collapsing into a single activation window"
)
assert TRANSFER_FEE_UNIFIED_HEIGHT > ATTESTER_FEE_FUNDING_HEIGHT, (
    "TRANSFER_FEE_UNIFIED_HEIGHT must follow Tier 4 (ATTESTER_FEE_"
    "FUNDING_HEIGHT) -- the helper Tier 57 starts routing through "
    "(pay_fee_with_burn) only internally activates the attester-"
    "share split at Tier 4, so Tier 4 must already be live"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 58 — Cold authority key chain-state WOTS+ leaf watermark
# ─────────────────────────────────────────────────────────────────────
# Pre-fix: ``Blockchain._validate_unstake_tx_in_block`` /
# ``validate_revoke`` / ``validate_set_authority_key`` verified
# signatures, nonces, balances -- but never tracked any chain-state
# watermark for cold-key-signed leaves.  ``apply_revoke`` / unstake
# apply / set-authority-key apply only bumped the HOT-key watermark
# (and only when ``authority_pk == signing_pk`` for unstake).  No
# ``cold_leaf_watermarks`` dict existed anywhere.
#
# Sibling of audit r31 #1 (cross-pool WOTS+ leaf-reuse on
# mempool.pending) on the COLD-KEY side: r31 closed the hot-key
# cross-pool admission gap; Tier 58 closes the same defect class
# for cold-key-signed txs across BLOCKS.
#
# Concrete bite: an operator pre-signs an offline emergency revoke
# at cold-key leaf=N (the documented hardening pattern in
# emergency_revoke.py:21-30), then later signs an unstake / fresh
# revoke / set-authority-key cold-counter-sig at the SAME cold-key
# leaf=N from the same cold key.  Both txs admit and apply.  Anyone
# observing both signatures recovers the WOTS+ one-time secret for
# that leaf and forges arbitrary cold-key signatures -- including a
# fresh RevokeTransaction, an Unstake of full balance, or a
# SetAuthorityKey rebind.  Worst case for any operator who followed
# the recommended hardening recipe: total stake loss + identity
# hijack with no cold-key recovery path.
#
# Fix: a new ``Blockchain.cold_leaf_watermarks`` dict keyed by COLD
# PUBKEY BYTES (NOT entity_id, since one cold key may sign for
# multiple entities -- the documented cluster pattern at
# blockchain.py:3046-3050).  At and above
# ``COLD_LEAF_WATERMARK_HEIGHT``:
#   * ``validate_revoke`` rejects when the cold sig's leaf_index is
#     below ``cold_leaf_watermarks[authority_pk]``.
#   * ``_validate_unstake_tx_in_block`` rejects ditto when the
#     unstake was signed by a separate cold key (authority_pk !=
#     signing_pk).
#   * ``validate_set_authority_key`` rejects when the cold counter-
#     signature's leaf_index is below
#     ``cold_leaf_watermarks[existing_cold_pk]``.
#   * Apply paths bump the watermark identically to the hot-key
#     pattern at ``_bump_watermark``.
#
# Pre-fork (height < COLD_LEAF_WATERMARK_HEIGHT) the new check is
# skipped entirely so historical blocks replay byte-identically --
# every Revoke / Unstake / SetAuthorityKey accepted by the legacy
# rules continues to be accepted.
#
# Activation height 2150 sits 50 blocks above Tier 57 (TRANSFER_FEE_
# UNIFIED_HEIGHT = 2100) -- ~8.3h cohort spacing at 600s blocks,
# matching the Tier 49-57 spacing pattern.  Two-validator network,
# both operator-controlled, so the cutover is coordinated.
COLD_LEAF_WATERMARK_HEIGHT = 2150  # Tier 58

assert COLD_LEAF_WATERMARK_HEIGHT > TRANSFER_FEE_UNIFIED_HEIGHT, (
    "COLD_LEAF_WATERMARK_HEIGHT must follow Tier 57 -- operators "
    "upgrade through Tier 57 before this admission-rule change binds, "
    "and the cohort spacing keeps two consecutive consensus-rule "
    "changes from collapsing into a single activation window"
)
assert COLD_LEAF_WATERMARK_HEIGHT > AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT, (
    "COLD_LEAF_WATERMARK_HEIGHT must follow Tier 46 (AUTHORITY_REBIND_"
    "REQUIRES_COLD_HEIGHT) -- the cold counter-signature wire format "
    "Tier 58 starts watermarking only exists at and above Tier 46"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 59 — Inactivity-leak penalty stake-scaling
# ─────────────────────────────────────────────────────────────────────
# Pre-fix: ``compute_inactivity_penalty`` is FLAT in tokens
# (``BASE * blocks² / quotient``); ``validator_stake`` is used only
# as a CAP, not as a scale factor.  ``compute_coverage_penalty`` IS
# stake-scaled (``stake * BASE * misses² / QUOTIENT``).  The two
# leak paths diverge sharply at low- and high-stake extremes: a
# 10k-stake honest-but-isolated validator hits zero stake at
# ``blocks_since_finality≈12700`` (~88 days) while a 1M-stake whale
# at the same blocks_since absorbs <0.06% of stake.  Tier 55
# honesty-curve relief floors at 20% of nominal -- still a wipe for
# the small validator on a long partition.
#
# CLAUDE.md anchor: "honest operators are insured against accidents
# ... when an honest node IS slashed (transient evidence collision,
# recoverable misconfig), the burn is a small *fraction* of stake,
# not a wipe."  A flat-token penalty fundamentally breaks this for
# the smallest validators on extended partitions or fork-emergency
# halts -- exactly the operators the chain wants to recruit.
#
# Fix: at and above ``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT`` the
# nominal penalty becomes ``stake * BASE * blocks² / QUOTIENT``,
# mirroring ``compute_coverage_penalty`` exactly.  The Tier-55
# honesty-curve relief layer wraps the new shape unchanged -- it
# multiplies the nominal whatever shape the nominal takes.  Pre-
# fork blocks replay byte-identically via a height gate; the
# legacy flat formula is preserved on the pre-fork branch.
#
# Cartel-defense intent preserved: a 1/3-stake withholding cartel
# under the new shape pays the SAME FRACTION of stake per block as
# a small honest validator -- in absolute tokens the cartel's drain
# is much larger because their stake is much larger.  Tier 55
# honesty-curve relief still grades the cartel separately (cartels
# don't accumulate the long honest-history a curve-relieved operator
# does).
#
# Activation height 2200 sits 50 blocks above Tier 58 (COLD_LEAF_
# WATERMARK_HEIGHT = 2150) -- ~8.3h cohort spacing at 600s blocks,
# matching the Tier 49-58 pattern.
INACTIVITY_LEAK_STAKE_SCALED_HEIGHT = 2200  # Tier 59

assert INACTIVITY_LEAK_STAKE_SCALED_HEIGHT > COLD_LEAF_WATERMARK_HEIGHT, (
    "INACTIVITY_LEAK_STAKE_SCALED_HEIGHT must follow Tier 58 -- "
    "operators upgrade through Tier 58 before this consensus-rule "
    "change binds, and the cohort spacing keeps consecutive consensus-"
    "rule changes from collapsing into a single activation window"
)
assert INACTIVITY_LEAK_STAKE_SCALED_HEIGHT > INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT, (
    "INACTIVITY_LEAK_STAKE_SCALED_HEIGHT must follow Tier 55 "
    "(INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT) -- Tier 55's relief "
    "multiplier wraps the nominal Tier 59 produces, so Tier 55 must "
    "already be live before Tier 59's nominal-shape change kicks in"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 60 — Dormancy controller TARGET retune (bootstrap-arc anchor)
# ─────────────────────────────────────────────────────────────────────
# Pre-fix: ``DORMANCY_TARGET_ACTIVE_SUPPLY = 100_000_000`` exactly
# matches the founder's genesis balance (100M; treasury 40M is
# excluded from active-supply per ``compute_active_supply`` lines
# 779-780).  While the founder signs blocks (validator-1's hot key
# signs every block), ``last_active`` bumps each block, weight =
# 10000 bps, contribution = 100M.  ``gap = 100M - 100M = 0`` →
# ``compute_dormancy_issuance`` returns 0/block, indefinitely.  The
# legacy halving-floor (BLOCK_REWARD_FLOOR=4) was short-circuited at
# ``DORMANCY_CONTROLLER_HEIGHT`` (Tier 47).  Validators currently
# earn ~0/block of issuance during the entire 25-year DORMANCY_
# WINDOW (or until the founder transfers tokens to other signing
# holders, which keeps gap≈0 because receivers also become active).
#
# CLAUDE.md anchor: founder-bootstrap arc -- "early-phase issuance
# is calibrated so the founder can credibly secure the network solo
# while it has only a handful of nodes, and progressively dilutes
# toward broad democratization as more validators stake in".  The
# 0/block delivery contradicts the front-loaded shape the anchor
# calls for.  CLAUDE.md also anchors fee-market as the long-term
# security funder, but the chain is in bootstrap and fees are
# dormant by design -- 0 fees + 0 issuance = 0 validator pay.
#
# Fix: at and above ``DORMANCY_TARGET_RETUNE_HEIGHT`` the controller
# uses ``DORMANCY_TARGET_ACTIVE_SUPPLY_V2 = 110_000_000`` instead of
# the legacy 100M.  At founder=100M-active, gap = 110M - 100M = 10M;
# raw_issuance = (10M * 1) // 200_000 = 50/block; ~2.6M tokens/yr
# split across validators -- comparable to the legacy halving floor
# era (4/block = ~210k/yr), generously front-loaded to satisfy the
# bootstrap-arc anchor without overshooting.  As the founder
# divests toward target, gap rises proportionally and the controller
# scales up smoothly.
#
# Shape-preserving: still gap-driven, still dormancy-filtered, still
# capped at MAX_ISSUANCE_PER_BLOCK, still zero at active >= target.
# Only the equilibrium point moves from 100M -> 110M.
#
# Pre-fork blocks (height < DORMANCY_TARGET_RETUNE_HEIGHT) replay
# byte-identically via the height gate; the legacy 100M target is
# preserved on the pre-fork branch so every historical block under
# the controller (heights 1710..2249) replays exactly.
#
# Activation height 2250 sits 50 blocks above Tier 59 (INACTIVITY_
# LEAK_STAKE_SCALED_HEIGHT = 2200) -- ~8.3h cohort spacing matching
# the Tier 49-59 pattern.
DORMANCY_TARGET_ACTIVE_SUPPLY_V2 = 110_000_000
DORMANCY_TARGET_RETUNE_HEIGHT = 2250  # Tier 60

assert DORMANCY_TARGET_RETUNE_HEIGHT > INACTIVITY_LEAK_STAKE_SCALED_HEIGHT, (
    "DORMANCY_TARGET_RETUNE_HEIGHT must follow Tier 59 -- operators "
    "upgrade through Tier 59 before this controller-parameter change "
    "binds, and the cohort spacing keeps consecutive consensus-rule "
    "changes from collapsing into a single activation window"
)
assert DORMANCY_TARGET_RETUNE_HEIGHT > DORMANCY_CONTROLLER_HEIGHT, (
    "DORMANCY_TARGET_RETUNE_HEIGHT must follow Tier 47 "
    "(DORMANCY_CONTROLLER_HEIGHT) -- Tier 60 retunes the controller "
    "Tier 47 introduced, so Tier 47 must already be live"
)
assert DORMANCY_TARGET_ACTIVE_SUPPLY_V2 > DORMANCY_TARGET_ACTIVE_SUPPLY, (
    "DORMANCY_TARGET_ACTIVE_SUPPLY_V2 must be strictly greater than "
    "the legacy target -- the bootstrap-arc anchor calls for non-zero "
    "front-loaded issuance, achieved by raising the target so gap > 0 "
    "even when the founder is fully active"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 61 -- inactivity-leak penalty cumulative-floor formula.
# Audit r33 top-3 #2.  Pre-fix the Tier 59 stake-scaled per-block
# formula `stake * BASE * blocks² // Q` integer-truncated to zero for
# any validator with stake < ~1M tokens at the calibrated quotient
# (Q = 16_777_216_000_000).  Cumulative drain over a 10000-block stall
# was the SUM of per-block penalties; if every per-block term floored
# to 0, the SUM was also 0.  Net effect: the leak fired correctly for
# whales, but the rank-and-file validator set (stake = 10K..100K)
# experienced zero drain on arbitrarily long partitions -- breaking
# cartel defense for any colluding subset of small-stake validators.
#
# Tier 61 fix is stateless and preserves the calibration constants:
# compute the per-block penalty as the integer DIFFERENCE of
# cumulative-floor values rather than the FLOOR of per-block-real::
#
#     cum(k) = stake * BASE * sum_{j=1..k} j² // Q
#            = stake * BASE * (k * (k+1) * (2k+1) / 6) // Q
#     penalty_at_block_k = cum(k) - cum(k-1)
#
# The cumulative-floor trick integer-truncates at the *cumulative*
# level (well above 1 token for any realistic stake over a realistic
# partition) instead of at the per-block level.  Over a 10000-block
# stall:
#
#   * stake=10K:   cum(10000) ≈ 198 tokens (~2% drain) -- works.
#   * stake=1M:    cum(10000) ≈ 19_842 tokens (~2%)    -- works.
#   * stake=100M:  cum(10000) ≈ 1_984_226 tokens (~2%) -- works.
#
# Activation height 2300 sits 50 blocks above Tier 60 (DORMANCY_
# TARGET_RETUNE_HEIGHT = 2250) -- ~8.3h cohort spacing matching the
# Tier 49-60 pattern.  Pre-fork (height < 2300) the legacy Tier 59
# formula runs unchanged so historical blocks replay byte-identically.
# No new wire format, no state-tree changes -- pure function-shape
# change inside compute_inactivity_penalty.
INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT = 2300  # Tier 61

assert INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT > DORMANCY_TARGET_RETUNE_HEIGHT, (
    "INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT must follow Tier 60 -- "
    "the cohort spacing keeps consecutive consensus-rule changes "
    "from collapsing into a single activation window"
)
assert INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT > INACTIVITY_LEAK_STAKE_SCALED_HEIGHT, (
    "INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT must follow Tier 59 -- "
    "Tier 61 fixes the integer-truncation bug Tier 59 introduced, "
    "so Tier 59 must already be live before the fix activates"
)


# ``LOTTERY_DETERMINISTIC_HEIGHT``: Tier 62 -- post-activation
# ``select_lottery_winner`` uses ``decimal.Decimal.ln()`` at fixed
# precision instead of ``math.log`` (a libm call whose ULP-level
# rounding is not portable across glibc / musl / MSVC libm / macOS
# libm).  Pre-fix, two heterogeneous-libc validators on the same
# chain could disagree on the lottery winner for a given (randao,
# candidates) input, producing divergent ``balances`` mutations and
# a silent state-root split on every lottery firing.  The fix
# mirrors the pattern ``attester_committee.py`` already adopted at
# pre-mainnet for the same reason.
#
# Pre-fork (height < ``LOTTERY_DETERMINISTIC_HEIGHT``) the legacy
# float-math branch runs unchanged -- byte-for-byte identical to
# pre-fix code so every historical lottery-firing block replays
# byte-identically post-upgrade.  Post-fork the deterministic
# Decimal branch is the rule.
#
# Activation height 2350 sits 50 blocks above Tier 61 (height 2300)
# -- ~8.3h cohort spacing matching the Tier 49-61 pattern.  Two-
# validator coordinated upgrade.  No new wire format, no new tx
# kinds, no state-tree changes -- pure consensus-rule swap inside
# ``select_lottery_winner``.
LOTTERY_DETERMINISTIC_HEIGHT = 2350  # Tier 62

assert LOTTERY_DETERMINISTIC_HEIGHT > INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT, (
    "LOTTERY_DETERMINISTIC_HEIGHT must follow Tier 61 -- consecutive "
    "consensus-rule activations need cohort spacing to keep the "
    "validator-upgrade window from collapsing"
)


# ``STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT``: Tier 63 -- post-
# activation a SlashTransaction carrying StateCheckpointDoubleSignEvidence
# (a validator who signed two distinct ``state_root`` values for the
# same checkpoint ``block_number``) is admitted and applies at the
# UNAMBIGUOUS-evidence severity (100% on first-and-fresh-tenure / on
# any repeat).  Pre-fix the evidence type and verifier existed in
# ``messagechain.consensus.state_checkpoint`` and the docstring claimed
# "Penalty: 100% stake + full escrow burn", but the slashing pipeline
# only dispatched kinds 0/1/2 (block / attestation / finality-vote);
# OffenseKind had no entry; SlashTransaction.{to,from}_bytes raised
# 'Unknown slash evidence kind' on kind=3.  The slashable offense was
# therefore unenforceable, leaving validator-collusion bootstrap-fork
# attacks (different new nodes adopt different post-states from a
# weak-subjectivity snapshot) without an on-chain penalty.
#
# Pre-fork (height < ``STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT``)
# ``validate_slash_transaction`` rejects kind=3 with an explicit "Tier
# 63" gate message so the admission rule is binary and historical
# blocks (which never carried a kind=3 slash tx -- the encoder rejected
# it pre-fix) replay byte-identically.  Post-fork the gate opens and
# admission proceeds through the standard verify -> slashing-severity
# -> apply path.  Severity classification: state-checkpoint double-
# sign is UNAMBIGUOUS by construction -- the snapshot ``state_root`` is
# a function of deterministically-replayed chain state, so two distinct
# values for the same height cannot be a benign restart artifact.  The
# offender deliberately chose two parallel post-states.
#
# Activation height 2400 sits 50 blocks above Tier 62 (height 2350) --
# ~8.3h cohort spacing matching the Tier 49-62 pattern.  Two-validator
# coordinated upgrade.  No new wire format on the unsigned-block path,
# no new tx kinds beyond the kind=3 SlashTransaction discriminator, no
# state-tree changes.
STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT = 2400  # Tier 63

assert STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT > LOTTERY_DETERMINISTIC_HEIGHT, (
    "STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT must follow Tier 62 -- "
    "consecutive consensus-rule activations need cohort spacing to "
    "keep the validator-upgrade window from collapsing"
)


# ``FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT``: Tier 64 -- post-
# activation ``Mempool.get_forced_inclusion_set`` walks the sorted
# qualifying list and applies a per-entity cap of
# ``MAX_TXS_PER_ENTITY_PER_BLOCK`` to the FORCED SOURCE SET.
# Pre-fix the source set was sorted by (-fpb, arrival, tx_hash) and
# sliced to ``FORCED_INCLUSION_SET_SIZE`` with NO per-entity cap.  A
# colluding cartel could pay a high-stake entity to flood the mempool
# with N high-fpb txs from a single entity_id; after the wait window
# those N txs occupied all FORCED_INCLUSION_SET_SIZE slots, evicting a
# censored victim's lower-fpb tx from the forced set entirely.  The
# cartel proposer could then exclude the victim without triggering
# excuse #1 (the victim wasn't in the forced set anymore) or excuse
# #3 (Tier 37's cap-fix tightens excuse #3 on the proposer-validator
# axis but not on the attester-side forced source set).  CLAUDE.md
# anchor at risk: "a tx that is well-formed, pays at least the per-
# byte floor, and fits the byte budget cannot be suppressed by
# anything weaker than a full validator-set majority actively colluding
# AND willing to absorb the slashing risk that exposed collusion
# produces."
#
# Tier 64 closes the gap: forcing more than
# ``MAX_TXS_PER_ENTITY_PER_BLOCK`` from one entity is meaningless
# anyway -- the proposer literally cannot fit them in a single block
# under the existing block-validator cap.  Capping the forced source
# set at the same constant therefore preserves every honest forced-
# inclusion outcome while denying the flooder the eviction primitive.
# The freed slots fill with the next-ranked txs from OTHER entities,
# which is exactly the censored-victim path the anchor protects.
#
# Soft-fork: the forced source set is per-attester local state, not
# consensus-relevant block content.  Different attesters may see
# different mempool views and the soft-vote aggregation handles
# divergence.  Pre-fork (height < FORCED_INCLUSION_PER_ENTITY_CAP_
# HEIGHT) the legacy uncapped path runs byte-identically so historical
# attester votes replay byte-identically.  Activation height 2450
# sits 50 blocks above Tier 63 (2400) -- ~8.3h cohort spacing
# matching the Tier 49-63 pattern.
FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT = 2450  # Tier 64

assert (
    FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
    > STATE_CHECKPOINT_DOUBLE_SIGN_SLASH_HEIGHT
), (
    "FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT must follow Tier 63 -- "
    "consecutive consensus-rule activations need cohort spacing to "
    "keep the validator-upgrade window from collapsing"
)
assert (
    FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
    > FORCED_INCLUSION_ALL_POOLS_HEIGHT
), (
    "FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT must follow Tier 43 -- "
    "the cap binds against the multi-pool source set Tier 43 wires "
    "in, so that gate must already be live"
)


# ``VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT``: Tier 65 -- post-
# activation ``Governance.finalize_voter_rewards`` REDISTRIBUTES
# cap-overflow to non-cap voters before the burn fallback.
#
# Pre-fix (Tier 22 -> Tier 50 -> Tier 56 sequence) the distribution
# was a single pass: pro-rata-by-stake share, capped at
# ``VOTER_REWARD_MAX_SHARE_BPS / 10_000`` per voter, and BOTH
# cap_excess and integer-division dust burned.  At today's bootstrap
# (founder ≈ near-100% of active stake) the founder hits the 25% cap
# on every proposal and the other 75% of the per-proposal pool burns.
# After seed-divestment to the 10M founder + 90M elsewhere
# distribution, a small voter with 10K stake on a 100M-staked network
# would earn 50000 × 10K / 100M = 5 tokens -- below the vote-tx fee
# floor of 100.  The mechanism currently *demotivates* voting at the
# small end while burning the surcharge that was supposed to motivate
# it.  CLAUDE.md anchor at risk: "voters who cast a vote during the
# window receive a reward funded *out of the proposal fee* -- the
# proposer pays the voters they're asking to evaluate the proposal."
# When ≥75% of every proposal's voter pool incinerates instead of
# paying voters, the anchor is materially inverted.
#
# Tier 65 fix: post-activation, cap_excess is REDISTRIBUTED to the
# non-cap voters before the burn fallback.  The redistribution
# iterates: each round, fill non-cap voters pro-rata-by-stake from
# the remaining excess; voters that hit the cap during a round drop
# out for the next round.  Convergence in O(N_voters) rounds because
# every round either fills another voter to cap or distributes
# everything to uncapped voters.  When no progress can be made (all
# voters at cap, OR only one voter exists), the residual burns --
# the same defensive invariant the legacy path enforces.  Integer-
# division dust still burns (unavoidable at the per-token level).
#
# Hard fork: balance writes shift between the legacy single-pass-
# and-burn path and the iterative redistribute path, which is
# consensus-visible.  Pre-fork (close-block height < activation)
# the legacy code runs byte-for-byte so historical proposals replay
# identically.  Activation height 2500 sits 50 blocks above Tier 64
# (2450) -- ~8.3h cohort spacing matching the Tier 49-64 pattern.
VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT = 2500  # Tier 65

assert (
    VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT
    > FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
), (
    "VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT must follow Tier "
    "64 -- consecutive consensus-rule activations need cohort "
    "spacing to keep the validator-upgrade window from collapsing"
)


# ``VOTER_REWARD_ADAPTIVE_CAP_HEIGHT``: Tier 66 -- post-activation the
# per-voter share cap becomes adaptive in the number of voters.
#
# Pre-fix: Tier 65 made cap-overflow REDISTRIBUTE to non-cap voters
# before the burn fallback -- correct for skewed-stake distributions.
# But the redistribute loop can only redistribute *within voters
# present*; it cannot break the per-voter
# ``VOTER_REWARD_MAX_SHARE_BPS`` cap.  When every voter is already
# at the cap, the residual still burns.  At N=1 voter the lone voter
# caps at 25% and 75% burns; at N=2 voters with equal stake each
# caps at 25% and 50% burns.  On today's two-validator bootstrap
# mainnet (founder ≈ 100% of stake; typical participating-voter
# count is N=1 or N=2) every governance proposal STILL burns 50-75%
# of the voter surcharge after Tier 65.
#
# CLAUDE.md anchor at risk: governance economics anchor -- "voters
# who cast a vote during the window receive a reward funded *out of
# the proposal fee* -- the proposer pays the voters they're asking
# to evaluate the proposal."  When the cap binds for every voter,
# the surcharge isn't going to voters at all -- it's just supply
# deflation.  Tier 65 closed the skewed-stake leak; Tier 66 closes
# the small-N leak.
#
# Tier 66 fix: ``effective_cap_bps = max(VOTER_REWARD_MAX_SHARE_BPS,
# 10_000 // num_voters)``.  N=1 → 10_000 bps (100%, lone voter gets
# the pool).  N=2 → 5_000 bps (50% each, two voters split equally
# absent stake skew).  N=3 → 3_333 bps.  N >= 4 → 2_500 bps (the
# legacy 25% floor binds, so the anchored "large-N anti-whale"
# shape is preserved unchanged).  The Tier 65 redistribute loop runs
# unchanged on top of the new cap value -- a skewed N=2 distribution
# (whale=99 small=1 pool=100) goes whale capped at 50 + small lifted
# to 50 by redistribute → 100 distributed, 0 burned.
#
# Hard fork: balance writes shift between the legacy cap and the
# adaptive cap, which is consensus-visible.  Pre-fork (close-block
# height < activation) the legacy code runs byte-for-byte so
# historical proposals replay identically.  Activation height 2550
# sits 50 blocks above Tier 65 (2500) -- ~8.3h cohort spacing
# matching the Tier 49-65 pattern.  No new wire format, no new tx
# kinds, no state-tree changes.
VOTER_REWARD_ADAPTIVE_CAP_HEIGHT = 2550  # Tier 66

assert (
    VOTER_REWARD_ADAPTIVE_CAP_HEIGHT
    > VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT
), (
    "VOTER_REWARD_ADAPTIVE_CAP_HEIGHT must follow Tier 65 -- the "
    "adaptive cap is layered on top of Tier 65's redistribute loop, "
    "so the redistribute path must already be the active default "
    "at adaptive-cap activation"
)


# ``ATTESTER_COMMITTEE_DECIMAL_HEIGHT``: Tier 67 -- post-activation
# the attester-committee weighted-reservoir sampler keeps the per-
# candidate priority as ``decimal.Decimal`` end-to-end and sorts on
# Decimal directly, eliminating the cross-platform IEEE-754 rank-
# flip risk introduced by the legacy ``float(u.ln() / Decimal(w))``
# cast at the sort key.  Decimal.ln IS deterministic (Tier 62
# established this for ``select_lottery_winner``), but the cast back
# to float at the sort key reintroduces an IEEE-754 ULP-level
# rounding hazard -- two near-equal log-keys can rank-flip on
# different libc / different CPython builds, producing different
# attester sets on different platforms.  Committee selection is
# consensus-critical (rewards land in ``mint_block_reward`` and are
# committed in ``state_root``), so divergent committees mean
# divergent state-roots -- a chain-wide partition class.
#
# Today's homogeneous-Linux-glibc mainnet hides the bug; the moment
# a third validator joins on different libc / arch / CPython build,
# partition risk goes live.  Same bug class, same fix shape as Tier
# 62 (``LOTTERY_DETERMINISTIC_HEIGHT``) -- pure consensus-rule swap
# inside the sampler, no new wire format, no new tx kinds, no
# state-tree changes.
#
# Pre-fork (height < ``ATTESTER_COMMITTEE_DECIMAL_HEIGHT``) the
# legacy float-cast branch runs unchanged so historical blocks
# replay byte-identically.  Post-fork the deterministic Decimal
# branch is the consensus rule.
#
# Activation height 2600 sits 50 blocks above Tier 66 (height 2550)
# -- ~8.3h cohort spacing matching the Tier 49-66 pattern.  Two-
# validator coordinated upgrade.
ATTESTER_COMMITTEE_DECIMAL_HEIGHT = 2600  # Tier 67

assert (
    ATTESTER_COMMITTEE_DECIMAL_HEIGHT
    > VOTER_REWARD_ADAPTIVE_CAP_HEIGHT
), (
    "ATTESTER_COMMITTEE_DECIMAL_HEIGHT must follow Tier 66 -- "
    "consecutive consensus-rule activations need cohort spacing to "
    "keep the validator-upgrade window from collapsing"
)


# ``WITNESS_ACK_ISSUER_BINDING_HEIGHT``: Tier 68 -- post-activation
# the witnessed-submission discharge readers (admission gate, sim
# path, ``NonResponseEvidenceProcessor.process``) consult a parallel
# per-issuer registry ``witness_ack_by_issuer: dict[request_hash,
# dict[issuer_id, ack_height]]`` instead of the legacy single-key
# ``witness_ack_registry: dict[request_hash, ack_height]``.  Only the
# request's TARGET validator's own ack discharges the silent-drop
# obligation; an attacker validator's ack for the same request_hash
# does NOT discharge the target's obligation.
#
# Pre-fix the legacy registry was keyed only on ``request_hash``, so
# any registered validator's ack discharged the target's obligation.
# Concrete attack: the target validator silently drops a witnessed
# SubmissionRequest; an attacker validator (any registered validator
# -- a sybil under the registration burn is fine) signs an ack for
# the same request_hash and a colluding proposer embeds it in
# ``acks_observed_this_block``.  The chain's apply path writes the
# legacy registry keyed on ``rh``.  ``validate_non_response_evidence
# _tx`` then rejects honest evidence with "ack present in chain
# state: obligation was met" -- discharging the target's silent-drop
# obligation by the attacker's ack.
#
# Net pre-fix: the entire silent-drop censorship arm of the
# witnessed-submission slashing pipeline collapses to a 2-validator
# collusion threshold (target + 1 ack-signer + a friendly proposer).
# CLAUDE.md anchor at risk: "censorship resistance is a *collective
# decision* … any new inclusion / mempool / proposer rule must raise
# the evidentiary cost of suppression."  The witnessed-submission
# pipeline IS that slashable-evidence layer for silent-drop censorship;
# pre-fix it could be defeated by 2 validators.
#
# Tier 68 fix: maintain a parallel per-issuer registry, populated at
# apply time alongside the legacy registry.  Discharge readers
# post-activation consult ``witness_ack_by_issuer[rh].get(target_id)``
# so only the target's own ack discharges.  Pre-fork the legacy
# reader runs unchanged so historical blocks replay byte-identically.
#
# State-sync caveat: the per-issuer registry is in-memory only (not
# serialized into the v23 snapshot envelope; the next snapshot
# version bump will add it).  A node that bootstraps from a v23
# snapshot at/after the activation height has an empty per-issuer
# registry until the registry's prune window passes
# (``WITNESS_OBSERVATION_RETENTION_BLOCKS +
# WITNESS_RESPONSE_DEADLINE_BLOCKS``); during that window
# discharge-by-target-ack does not short-circuit.  The worst-case
# outcome is the slash check proceeds to the deadline + active-set +
# quorum gates -- no incorrect slash, just no early discharge.
#
# Activation height 2650 sits 50 blocks above Tier 67 (height 2600)
# -- ~8.3h cohort spacing matching the Tier 49-67 pattern.  Two-
# validator coordinated upgrade.  No new wire format, no new tx
# kinds, no state-tree changes -- pure consensus-rule swap inside
# the discharge-reader path.
WITNESS_ACK_ISSUER_BINDING_HEIGHT = 2650  # Tier 68

assert (
    WITNESS_ACK_ISSUER_BINDING_HEIGHT
    > ATTESTER_COMMITTEE_DECIMAL_HEIGHT
), (
    "WITNESS_ACK_ISSUER_BINDING_HEIGHT must follow Tier 67 -- "
    "consecutive consensus-rule activations need cohort spacing to "
    "keep the validator-upgrade window from collapsing"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 69 — Honesty-curve leniency refinement
# ─────────────────────────────────────────────────────────────────────
# Three coupled tweaks that push the honesty curve further toward the
# CLAUDE.md "honest operators are insured against accidents" anchor,
# without weakening the deliberate-Byzantine bar:
#
#   1. ``slash_offense_counts`` decay.  Pre-Tier-69 the per-offender
#      slash counter was monotonic — one transient slash in year 1
#      permanently disqualified a validator from Tier 24 amnesty AND
#      from full honest-history relief for the rest of their tenure.
#      That mismatches the third anchor factor ("good-vs-bad RATE"):
#      a long-tenured operator with one ancient slip and a million
#      good blocks has a near-zero bad rate, but the curve was treating
#      them as if the slip just happened.  Post-Tier-69 every
#      ``HONESTY_CURVE_DECAY_PERIOD_BLOCKS`` of wall-clock progress
#      decays every positive prior by 1, so a single offense recovers
#      to amnesty-eligible after one period of clean operation.
#      Sustained bad actors still accumulate priors faster than they
#      decay — the deliberate-bad-actor curve is unchanged.
#
#   2. Restart drift window extension.  Pre-Tier-69 the AMBIGUOUS-vs-
#      UNAMBIGUOUS classifier admitted block-header restart-shape
#      evidence only if the two timestamps differed by ≤120s.  Honest
#      restart cycles on heavy load (mempool rebuild + disk fsync +
#      WOTS+ leaf seek) routinely take longer than that; the tight
#      window was forcing legitimately-honest restart artifacts onto
#      the UNAMBIGUOUS path (50% floor on first offense, 100% on
#      repeat).  Post-Tier-69 the window widens to 600s.  Pure
#      classification change — no attacker gains anything from a wider
#      restart-shape window because the shape itself (same parent,
#      same state_root, same checkpoint, only merkle_root + timestamp
#      differ) has no fork-grinding economic value.
#
#   3. AMBIGUOUS-path cap tightening.  Pre-Tier-69 the Tier-51 cap
#      bounded AMBIGUOUS-path output at 10%.  10% is "small fractional"
#      against a wipe, but for a restart-shape repeat-offense pattern
#      it is still operationally painful (5 events compound to ~40%
#      of stake lost over time).  Post-Tier-69 the cap tightens to 3%,
#      firmly in "operational nuisance, recoverable" territory.
#      UNAMBIGUOUS path is untouched — deliberate Byzantine evidence
#      still carries the 50%+ first-offense floor and 100% repeat.
#
# Activation height 2700 sits 50 blocks above Tier 68 (2650) -- ~8.3h
# cohort spacing matching the Tier 49-68 pattern.  Two-validator
# coordinated upgrade.  No new wire format, no new tx kinds, no
# state-tree changes -- pure consensus-rule swap inside the slashing
# severity / classifier paths.  ``slash_offense_counts`` storage shape
# unchanged (still ``dict[bytes, int]``); the decay is a deterministic
# sweep over existing entries at fixed-cadence heights.
HONESTY_CURVE_TIER69_HEIGHT = 2700  # Tier 69

# Decay cadence.  Every DECAY_PERIOD_BLOCKS of progress past activation,
# every positive entry in ``slash_offense_counts`` decrements by 1
# (clamped at 0).  4_320 ≈ 30 days at the 600s block target — short
# enough that a honest operator's once-a-year slip-and-recover loop
# completes well within a season, long enough that an attacker cannot
# trivially clean their slate between repeat offenses (they'd need to
# wait 30 days of clean operation per prior of decay).
HONESTY_CURVE_DECAY_PERIOD_BLOCKS = 4_320

# Widened restart-drift window.  600s (10 min) is the empirical p99
# of restart-cycle wall-clock for a node under heavy mempool churn
# plus on-disk WOTS+ leaf-index re-fsync, observed on the existing
# mainnet validators 2026-04 to 2026-05.  120s caught only the
# happy-path restart; 600s catches the heavy-load case too.  Beyond
# 600s a single restart cycle is implausible — no realistic crash-
# recovery sequence keeps a process alive that long between sign
# attempts at the same height.
HONESTY_CURVE_RESTART_DRIFT_SECS_TIER69 = 600

# Tightened AMBIGUOUS-path cap.  3% is below the Tier-20 SOFT_SLASH_PCT
# floor (5%) and well below the prior Tier-51 cap (10%).  A 3%
# restart-shape burn is an operational signal ("your node had an
# evidence-producing restart, fix it") without being economically
# catastrophic.  UNAMBIGUOUS path is unaffected — deliberate evidence
# still carries the 50%+ first-offense floor.
HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69 = 3

assert HONESTY_CURVE_TIER69_HEIGHT > WITNESS_ACK_ISSUER_BINDING_HEIGHT, (
    "HONESTY_CURVE_TIER69_HEIGHT must follow Tier 68 -- consecutive "
    "consensus-rule activations need cohort spacing"
)
assert HONESTY_CURVE_DECAY_PERIOD_BLOCKS > 0, (
    "HONESTY_CURVE_DECAY_PERIOD_BLOCKS must be positive -- a 0 period "
    "would decay every block, immediately erasing every prior and "
    "neutering the repeat-offense curve"
)
assert HONESTY_CURVE_RESTART_DRIFT_SECS_TIER69 > HONESTY_CURVE_RESTART_DRIFT_SECS, (
    "Tier 69 restart-drift window must widen, not narrow, the AMBIGUOUS "
    "classifier -- the fork is a one-way leniency move"
)
assert HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69 < HONESTY_CURVE_AMBIGUOUS_MAX_PCT, (
    "Tier 69 AMBIGUOUS cap must tighten, not loosen, the previous cap "
    "-- the fork is a one-way leniency move"
)
assert HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69 >= HONESTY_CURVE_MIN_PCT, (
    "Tier 69 AMBIGUOUS cap must be at least MIN_PCT -- a cap below "
    "the universal slash floor would be unreachable (the clamp would "
    "round up to MIN_PCT and the cap would be dead code)"
)

# ─────────────────────────────────────────────────────────────────────
# Tier 70 — Stake-concentration soft cap (sublinear concave reward curve)
# ─────────────────────────────────────────────────────────────────────
# CLAUDE.md anchor: "rich nodes do not just keep getting richer -- small
# nodes actually earn more than large nodes per unit staked."  Pre-Tier-70
# proposer selection (``select_proposer_vrf``, ``_selected_proposer_for_
# slot`` fallback) and attester-committee weighting (``weights_for_
# progress``) all used raw stake as the selection weight -- strictly
# linear stake-proportional.  Founder-scale stake captured proposer slots
# and attester picks in proportion to raw stake, indefinitely.  That is
# the "permanent rent-extracting majority" CLAUDE.md explicitly forbids.
#
# Tier 70 introduces the rational soft-cap form:
#     effective_weight(s) = s * C / (s + C)
#
# Properties (matching the CLAUDE.md anchor exactly):
#   * monotonically increasing in s  -- whale's absolute reward still
#     rises when adding stake; 24/7 honest operation always preferred
#     over withdrawal
#   * per-unit yield w(s)/s = C/(s+C) is monotonically DECREASING in s
#     -- smaller validators earn at a strictly higher per-unit rate
#   * asymptote: w(s) -> C as s -> infinity  -- this is the "asymptotic
#     soft cap" wording from the anchor
#   * no hard cap: w(s) < C for all finite s, but approaches it
#   * concave: second derivative is everywhere negative
#   * at s << C: w(s) ~= s  -- small stakers see linear behavior, no
#     artificial punishment of min-stake validators by the curve
#   * at s >> C: w(s) ~= C - C^2/s  -- whales see strongly diminishing
#     returns
#
# C = 1_000_000 tokens.  Tuning rationale:
#   * a min-stake (200-token) validator sees w(200) ~= 199.96 -- the
#     curve is essentially invisible at the floor
#   * a founder-scale (50M-token) validator sees w(50M) ~= 980_000 --
#     the founder's selection probability is bounded to ~1M units of
#     weight regardless of stake size, so per-unit yield collapses to
#     C/(50M+C) ~= 2% of the linear baseline
#   * per-unit-yield ratio (small/founder) at progress=1 is ~51x -- a
#     min-stake validator earns ~51 tokens for every 1 token the
#     founder earns per unit staked
#   * the parameter is tunable; a future Tier may re-tune.  The
#     ASYMPTOTIC-SOFT-CAP SHAPE is the anchored choice; the value
#     of C is not.
#
# Activation height 4500 sits 1800 blocks above Tier 69 (2700) -- ~12.5d
# cohort spacing well above the Tier 49-69 tight-cohort pattern.  An
# economic-distribution change is qualitatively different from honesty-
# curve tightening, so the runway is longer for validator coordination.
#
# No new wire format, no new tx kinds, no state-tree changes.  Pure
# consensus-rule swap inside the proposer-selection / attester-committee-
# weighting paths.
STAKE_CONCENTRATION_SOFT_CAP_HEIGHT = 4500  # Tier 70
STAKE_CONCENTRATION_SOFT_CAP = 1_000_000  # tokens; ``C`` in the rational form

assert STAKE_CONCENTRATION_SOFT_CAP_HEIGHT > HONESTY_CURVE_TIER69_HEIGHT, (
    "STAKE_CONCENTRATION_SOFT_CAP_HEIGHT must follow Tier 69 -- "
    "consecutive consensus-rule activations need cohort spacing"
)
assert STAKE_CONCENTRATION_SOFT_CAP > 0, (
    "STAKE_CONCENTRATION_SOFT_CAP=0 would divide by zero in the "
    "rational form AND collapse every weight to 0"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 71 -- effective_weight flows to per-slot attester reward sizing
# ─────────────────────────────────────────────────────────────────────
# Tier 70 (above) routed three call sites through ``effective_weight``:
# ``weights_for_progress`` (attester-committee SELECTION),
# ``select_proposer_vrf`` (active proposer-selection), and
# ``Blockchain._selected_proposer_for_slot`` fallback.  But the per-
# slot attester reward SIZING path in ``SupplyTracker.mint_block_reward``
# (and its sim mirror in ``Blockchain._apply_block_state``) was still
# reading RAW stake for the bps numerator and the total-active-stake
# denominator:
#
#     total_active_stake = sum(self.staked.values())            # raw
#     stake_bps = self.staked.get(eid, 0) * 10_000 // total     # raw
#
# Both halves linear in whale stake -- so the v4 reward-curve multiplier
# was sizing per-slot reward off a raw bps distribution even when Tier
# 70 had compressed the selection-weight distribution.  Tier 70's anchor
# ("rich-get-richer in absolute terms but share of issuance compresses
# over time") therefore landed at the SELECTION layer but stretched
# back at the reward-sizing layer.
#
# Tier 71 closes the leak: both the numerator and denominator route
# through ``effective_weight(stake, block_height)`` so per-slot reward
# sizing inherits the same concave compression as selection.  Pre-fork
# behavior is byte-identical (``effective_weight`` is the identity
# below Tier 70, and Tier 71 is strictly above Tier 70 by construction
# of the height ordering below).
#
# Activation height 6500 sits 2000 blocks above Tier 70 (4500) -- ~13.9d
# cohort spacing matching the Tier 69→70 runway pattern.  Two
# consecutive reward-distribution changes need their own cohorts; piling
# both into the same window forces operators to absorb the combined
# change in one upgrade cycle.
#
# No new wire format, no new tx kinds, no state-tree changes.  Pure
# consensus-rule swap inside the per-slot reward-sizing path.  Both
# the apply path (SupplyTracker.mint_block_reward) AND the sim mirror
# (Blockchain._apply_block_state) flip in lockstep at the activation
# block -- sim drives state_root, so any drift between sim and apply
# at the activation block would fork the chain.
EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT = 6500  # Tier 71

assert (
    EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT
    > STAKE_CONCENTRATION_SOFT_CAP_HEIGHT
), (
    "EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT (Tier 71) must strictly "
    "follow STAKE_CONCENTRATION_SOFT_CAP_HEIGHT (Tier 70) -- "
    "effective_weight is the identity below Tier 70, so gating Tier 71 "
    "below Tier 70 would be a no-op for live nodes and risk a sim-vs-"
    "apply drift at the Tier-70 activation block."
)


# ─────────────────────────────────────────────────────────────────────
# Tier 72 — Structured polls + structured votes
# ─────────────────────────────────────────────────────────────────────
# MessageChain's anti-spam-via-fees lever is enough to filter raw bulk
# text, but threaded sentiment ("which of these options do you prefer")
# has only had the free-text-reply escape hatch so far -- and free-text
# replies are ambiguous (typo / synonym / sarcasm / language drift) and
# uncountable without app-layer NLP that every indexer has to ship
# separately.  Tier 72 promotes polls from an indexer convention to a
# protocol primitive so the tally is unambiguous, computable from the
# chain alone, and resistant to "we changed what the options meant
# later" front-end revisionism.
#
# Wire shape (anchored, post-activation):
#   * A poll-creating message tx carries an optional ``poll_options``
#     field: 1..MAX_POLL_OPTIONS short UTF-8 strings.  The message body
#     is the question; the options are the structured answers.  Options
#     follow the same NFC + L/M/N/P/Zs whitelist that Tier 12 enforces
#     on message text (homoglyph discipline) and each option is
#     constrained to MAX_POLL_OPTION_BYTES UTF-8 bytes.  Options must
#     be pairwise distinct within a single poll -- "Yes / No / Yes" is
#     a structural error, not a vote-distribution accident.
#   * A vote-casting message tx carries an optional ``vote_target``
#     field: (poll_txid, option_index).  Only the index (0-based) is
#     stored -- the option text is recovered by mapping the index back
#     to the referenced poll, exactly like Reddit / Twitter / Strawpoll.
#     This is what makes votes "minimal payload": no per-vote text bytes,
#     no per-vote homoglyph surface, just a 33-byte reference.
#   * A single tx is EITHER a poll OR a vote, never both.  Mutual
#     exclusivity at the wire level keeps the validation rules sharp
#     and the indexer aggregation trivial.
#
# Protocol-level enforcement (this is what makes votes structured and
# not just free text):
#   * The vote's ``poll_txid`` must resolve to a tx in a strictly
#     earlier block whose ``poll_options`` is set.  A vote that points
#     at a non-poll message, a poll in the future, or nothing at all
#     is rejected at admission.
#   * The vote's ``option_index`` must be in ``[0, len(options))`` of
#     the resolved poll.  An index out of range is rejected.
#   * Free-text vote labels are NOT admissible -- the structure IS the
#     vote.  Indexers compute "votes per option" by scanning vote txs
#     pointing at a poll and reading the index field.
#
# Dedup model (one-vote-per-entity): NOT enforced on chain.  Every vote
# tx that satisfies the above is admissible, and the permanence anchor
# forbids deleting a prior vote.  Indexers resolve "current effective
# vote" per (voter, poll) as last-vote-wins -- the older votes stay on
# chain forever (which is desirable: an entity changing their mind is
# itself signal).  This keeps consensus stateless w.r.t. who has voted
# on what; the only state the protocol cares about is the poll's option
# set, which is immutable in the originating tx.
#
# No close condition: polls are open forever.  An optional close-height
# was considered and rejected -- it adds wire-format surface for a
# property the indexer can already express ("ignore votes after height
# X") without baking it into consensus.  If a later proposal wants
# enforced close, it can ride a future tier.
#
# Storage / fee: option bytes and the vote_target block are counted
# toward stored bytes for the per-stored-byte fee floor and the
# proposer's fee-per-byte ranking.  Excluded from MAX_MESSAGE_CHARS --
# poll options are structural metadata, not the user's speech (same
# treatment as community_id).
#
# Activation height 2400 sits 11 blocks above the mainnet tip at
# fork-cut time (tip 2389, ~110 minutes of upgrade runway at 600s/
# block).  The two-validator upgrade cycle (cut release, ssh-upgrade
# each node) takes ~20-30 minutes; ~110 minutes of runway gives
# comfortable margin without delaying activation.
#
# Tier 72's wire format is disjoint from Tier 71's reward-sizing
# math, so the two tiers can activate in either order without
# operator coordination -- a v6 tx admitted before Tier 71 activates
# pays the same reward-sizing rules as any other tx in that window,
# and Tier 72's protocol-level checks are self-contained in the
# message-tx admission path.  Both tiers ship in the same binary
# (1.78.0), so cold-start operators on this release support both
# regardless of activation order.
POLL_HEIGHT = 2400  # Tier 72
MAX_POLL_OPTIONS = 4
MAX_POLL_OPTION_BYTES = 32

assert MAX_POLL_OPTIONS >= 2, (
    "MAX_POLL_OPTIONS must be at least 2 -- a single-option poll has "
    "no choice to make and reduces to a regular message"
)
assert MAX_POLL_OPTIONS <= 4, (
    "MAX_POLL_OPTIONS must stay at 4 -- the design anchor caps options "
    "at four to keep the choice set legible (single-screen-readable on "
    "any client) and the wire footprint tight"
)
assert 1 <= MAX_POLL_OPTION_BYTES <= 64, (
    "MAX_POLL_OPTION_BYTES must be in [1, 64] -- short labels keep "
    "the choice set legible and the per-tx stored-byte cost bounded "
    "(4 options * 64B = 256B worst case plus 4 length bytes)"
)


# ─────────────────────────────────────────────────────────────────────
# Tier 73 — Attester fee-share minimum unit (audit r51 #3)
# ─────────────────────────────────────────────────────────────────────
# Tier 4 redirected ``ATTESTER_FEE_SHARE_BPS / 10_000`` of every fee
# burn into the per-block attester pool to fund long-horizon
# validator security from fees rather than issuance (CLAUDE.md
# pillar: "Perpetual security via fees, not issuance").  Integer
# arithmetic silently breaks the redirect at the floor-binding regime
# the chain spends most of its life in:
#
#     base_fee = 1                  # MARKET_FEE_FLOOR=1 binds
#     ATTESTER_FEE_SHARE_BPS = 5000 # 50%
#     attester_share = 1 * 5000 // 10_000 = 0
#
# At ``base_fee=1`` (the dominant regime on a low-utilization chain),
# all 100% of the fee burns and attesters receive nothing from the
# fee channel.  Same flooring at ``base_fee`` in {2, 3} (still rounds
# to 1) -- but {2, 3} is at least non-zero; the {1} case is the live
# defect because it's the literal steady-state value of base_fee
# whenever no spam wave has lifted it.
#
# Tier 73 introduces a ``max(1, ...)`` clamp on the fee-share
# integer-divide so the redirect channel is guaranteed non-zero
# whenever a fee actually burns.  The clamp is gated on
# ``base_fee > 0`` so an off-chain audit / test path with
# ``base_fee = 0`` doesn't manufacture pool credit from thin air.
#
# Consensus-visible math change (every fee redirect that pre-fork
# rounded to 0 now redirects 1 token) -- gated by activation height.
# Pre-fork is byte-identical to legacy at every (base_fee, fee)
# combination so historical-block replay matches.
#
# Activation height 8500 sits 2000 blocks above Tier 71 (6500,
# EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT) -- ~13.9 days cohort
# spacing matching the Tier 70→71 runway.  Tier 73 is the
# next-scheduled fee/economics retune; consecutive economics
# changes deserve their own cohort so operators can absorb each
# in its own upgrade cycle.  Tier 72 (POLL_HEIGHT=2400) is below
# this and disjoint -- a wire-format-only tier on the message-tx
# admission path; the two tiers' apply paths do not interact.
#
# No new wire format, no new tx kinds, no state-tree changes.  Pure
# consensus-rule swap inside ``SupplyTracker.pay_fee_with_burn``;
# the sim-vs-apply parity falls out trivially because
# ``pay_fee_with_burn`` is the single chokepoint both paths route
# fee payments through.
ATTESTER_FEE_MIN_UNIT_HEIGHT = 8500  # Tier 73

assert (
    ATTESTER_FEE_MIN_UNIT_HEIGHT > EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT
), (
    "ATTESTER_FEE_MIN_UNIT_HEIGHT (Tier 73) must strictly follow "
    "EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT (Tier 71) -- both are "
    "validator-economics retunes; consecutive reward-distribution "
    "changes deserve their own cohort so operators can absorb each "
    "in its own upgrade cycle."
)
assert ATTESTER_FEE_MIN_UNIT_HEIGHT > POLL_HEIGHT, (
    "ATTESTER_FEE_MIN_UNIT_HEIGHT (Tier 73) must strictly follow "
    "POLL_HEIGHT (Tier 72) to keep activation ordering monotone."
)


# ─── Tier 74 (audit r52 #3) — proposer-share / per-block-cap min-unit
# clamp ────────────────────────────────────────────────────────────────
#
# Tier 73 (r51 #3) clamped the attester-share integer-divide to a
# minimum of 1 token whenever ``base_fee * 5000 // 10_000`` rounded to
# zero.  The Tier 73 CHANGELOG explicitly deferred the wider abstraction:
#
#     "Sibling defect-shape DEFERRED (scope-bounded for this round): the
#      wider abstraction calls for a shared ``_split_bps(amount, bps,
#      denom=10_000, min_unit=1)`` helper to catch every future
#      ``bps // 10_000`` site that could round to zero under a realistic
#      minimum."
#
# The next site that bites the same shape is ``proposer_share`` in
# ``SupplyTracker.mint_block_reward``:
#
#     proposer_share = reward * PROPOSER_REWARD_NUMERATOR
#                    // PROPOSER_REWARD_DENOMINATOR    # = reward * 1 // 4
#
# At ``reward in {1, 2, 3}`` the proposer share silently rounds to zero
# and the entire reward routes to the attester pool / per-block burn.
# The dormancy-controller (Tier 47+) is *designed* to emit small per-
# block issuance when ``active_supply`` is close to ``TARGET``, so the
# small-reward regime is the steady state, not a corner case.  Same
# shape on ``effective_cap`` (post-PROPOSER_CAP_HALVING_HEIGHT) -- the
# per-block cap on combined proposer earnings also rounds to zero at
# small ``reward``, silently turning OFF the clawback in the regime
# it's anchored to bound.
#
# Pillar at risk: "Perpetual security via fees, not issuance" + "Stable
# active supply" + "Mathematical decentralization over time" -- if the
# small-issuance regime never actually pays the proposer their anchored
# 25% share, the role economics invert in steady state.
#
# Tier 74 lands two changes:
#   1. ``_split_bps(amount, num, den, *, min_unit=1, gate=False)`` --
#      the deferred shared helper, exposed at module scope on
#      ``messagechain.economics.inflation``.  Pre-fork callers
#      (``gate=False``) get byte-identical floor-divide behavior; the
#      gated path clamps to ``min_unit`` only when a positive
#      ``amount`` would otherwise round to zero, and never exceeds
#      the input ``amount`` so supply conservation cannot be silently
#      manufactured into existence.
#   2. ``PROPOSER_SHARE_MIN_UNIT_HEIGHT`` -- new activation height
#      gating two consensus-visible sites in ``mint_block_reward``:
#      ``proposer_share`` and ``effective_cap``.  Both refactored to
#      call ``_split_bps`` with ``gate=(block_height >= ...)``.
#      Pre-fork is byte-identical to legacy at every (reward, ...)
#      combination so historical-block replay matches.
#
# Tier 73's attester-fee clamp is refactored to call ``_split_bps``
# too -- byte-identical behavior on both sides of every fork so the
# refactor doesn't tamper with the consensus-visible result.
#
# Activation height ``10500`` sits 2000 blocks above Tier 73 (8500)
# -- the same ~13.9-day cohort spacing the Tier 70 → 71 → 73 runway
# used.  Consecutive validator-economics retunes get their own cohort
# so operators absorb each in its own upgrade cycle.
PROPOSER_SHARE_MIN_UNIT_HEIGHT = 10500  # Tier 74

assert PROPOSER_SHARE_MIN_UNIT_HEIGHT > ATTESTER_FEE_MIN_UNIT_HEIGHT, (
    "PROPOSER_SHARE_MIN_UNIT_HEIGHT (Tier 74) must strictly follow "
    "ATTESTER_FEE_MIN_UNIT_HEIGHT (Tier 73) -- both are validator-"
    "economics retunes; consecutive reward-distribution changes "
    "deserve their own cohort so operators absorb each in its own "
    "upgrade cycle."
)


# ─────────────────────────────────────────────────────────────────────
# Tier 75 - Punishment-side ``_split_bps`` min-unit clamp (audit r53 #3)
# ─────────────────────────────────────────────────────────────────────
#
# Tier 73 / Tier 74 closed the silent-round-to-zero defect class on
# the REWARD side: every ``bps // den`` shape site that could underflow
# to zero at the dormancy controller's steady-state low-issuance regime
# now routes through ``_split_bps`` with a ``min_unit=1`` clamp.
#
# The PUNISHMENT side has the same defect on a different denominator:
# ``slash_validator`` / ``burn_slash_proportional`` / ``EscrowLedger
# .slash_all`` all compute the slash as ``basis * slash_pct // 100``.
# At the Tier 20 anchored ``SOFT_SLASH_PCT = 5`` (honest-operator
# insurance), any basis under 20 tokens rounds to zero and the
# offender silently keeps their full stake / pending / escrow entry.
# That inverts the CLAUDE.md anchor "Honest operators are insured ...
# a pattern of bad behavior from a thin-history node is not laundered
# by the same leniency" -- thin-history offenders are exactly where
# the basis is small, and the integer-floor was silently laundering
# every soft slash against them.
#
# Tier 75 routes the three slash sites through ``_split_bps`` with
# ``min_unit=1, gate=block_height >= SLASH_MIN_UNIT_HEIGHT``.  Pre-fork
# the gate evaluates False at every height and the floor-divide
# matches legacy byte-for-byte -- historical-block replay preserved.
# Post-fork the slash is clamped to at least 1 token whenever a
# positive basis would otherwise round to zero, and never exceeds the
# bucket's actual size so supply conservation is preserved.
#
# Activation height ``12500`` sits 2000 blocks above Tier 74 (10500),
# matching the Tier 70 → 71 → 73 → 74 ~13.9-day cohort spacing.  A
# punishment-shape change deserves its own operator runway -- piling
# it into Tier 74's cohort would force operators to absorb a reward-
# side AND a punishment-side retune in the same upgrade cycle.
SLASH_MIN_UNIT_HEIGHT = 12500  # Tier 75

assert SLASH_MIN_UNIT_HEIGHT > PROPOSER_SHARE_MIN_UNIT_HEIGHT, (
    "SLASH_MIN_UNIT_HEIGHT (Tier 75) must strictly follow "
    "PROPOSER_SHARE_MIN_UNIT_HEIGHT (Tier 74) -- both are validator-"
    "economics retunes; consecutive reward/punishment-distribution "
    "changes deserve their own cohort so operators absorb each in "
    "its own upgrade cycle."
)


# ─────────────────────────────────────────────────────────────────────
# Tier 76 - Finality-vote inclusion-reward per-block cap (audit r54 #1)
# ─────────────────────────────────────────────────────────────────────
#
# Pre-Tier-76, ``_apply_finality_votes`` mints
# ``FINALITY_VOTE_INCLUSION_REWARD = 1`` tokens of direct mint to the
# proposer for EVERY survivor of the pre-filter, up to
# ``MAX_FINALITY_VOTES_PER_BLOCK = 200``.  The mint never routes
# through any of the issuance-discipline plumbing every other reward
# path now goes through:
#   * ``_split_bps`` (Tier 73/74/75 round-to-zero clamp + supply-
#     conservation invariant)
#   * ``effective_weight`` (Tier 70/71 stake-concentration soft cap)
#   * the ``mint_block_reward`` per-block-cap / redistribute logic
#   * the ``DORMANCY_MAX_ISSUANCE_PER_BLOCK = 500`` dormancy controller
#     clamp
#
# Pillars at risk:
#   * "Mathematical decentralization over time" -- whale proposers
#     receive a per-vote inclusion bonus that scales linearly with
#     their proposer-slot share (which itself is sublinear via Tier
#     70/71 effective_weight, so the linear-on-top compounds back
#     toward the plutocracy regime Tier 70 anchored against).
#   * "Stable active supply" -- 200 tokens/block of mint outside the
#     dormancy controller's regulated band leaks the anchored
#     issuance envelope.  At the controller's small-issuance steady
#     state (~50 tokens/block) the finality-mint actually dominates
#     the bounded path 4:1.
#
# Tier 76 caps the per-block finality-mint TOTAL at
# ``FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS =
# MAX_FINALITY_VOTES_PER_BLOCK // 8`` = 25.  Cap is grounded in the
# DoS-guard cap (``MAX_FINALITY_VOTES_PER_BLOCK``), not a magic
# number.  Real chains sit ~1 vote/block on average
# (FINALITY_INTERVAL=100), so the cap leaves 25x headroom for
# finality-vote backlogs without exposing the controller envelope to
# saturation.
#
# Pre-fork: byte-identical to legacy at every (n_votes, ...)
# combination so historical-block replay matches.
# Post-fork: the first ``cap`` survivors mint
# ``FINALITY_VOTE_INCLUSION_REWARD`` each; further survivors still
# contribute to the 2/3 finality tally (checkpoint safety/liveness
# is uncapped on purpose -- finalization must still cross 2/3 at
# high vote count) but produce no mint -- the inclusion service is
# unpaid past the budget.  Honest proposers including <= 25 votes/
# block see zero change.  Whales packing 200 votes/block see their
# bonus capped at 25 -- bound to the dormancy-controller envelope.
#
# Activation height ``14500`` sits 2000 blocks above Tier 75 (12500),
# matching the Tier 70 -> 71 -> 73 -> 74 -> 75 ~13.9-day cohort
# spacing.  A reward-distribution retune deserves its own operator
# runway -- piling it into Tier 75's cohort would force operators to
# absorb a punishment-side AND an issuance-discipline retune in the
# same upgrade cycle.
FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT = 14500  # Tier 76
FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS = (
    MAX_FINALITY_VOTES_PER_BLOCK // 8
)

assert FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT > SLASH_MIN_UNIT_HEIGHT, (
    "FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT (Tier 76) must strictly "
    "follow SLASH_MIN_UNIT_HEIGHT (Tier 75) -- consecutive issuance-"
    "discipline retunes deserve their own cohort so operators absorb "
    "each in its own upgrade cycle."
)
assert FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS > 0, (
    "FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS must be positive -- "
    "a cap of zero would silently disable the inclusion bonus, "
    "breaking the proposer-incentive anchor entirely."
)
assert FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS < MAX_FINALITY_VOTES_PER_BLOCK, (
    "FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS must be strictly below "
    "MAX_FINALITY_VOTES_PER_BLOCK or the fork is a no-op."
)


# ─────────────────────────────────────────────────────────────────────
# Tier 77 -- PROPOSER_CAP_REDISTRIBUTE pro-rata min-unit clamp.
# ─────────────────────────────────────────────────────────────────────
# Audit r55 #2 closer.  The Tier 53 redistribute path (which made the
# proposer-cap clawback redistribute trim pro-rata instead of burning
# it) computes each non-proposer attester's share as:
#
#     bonus = trim_from_att * existing // other_total
#
# The same integer-floor-divide shape Tier 73 (audit r51 #3), Tier 74
# (r52 #3), and Tier 75 (r53 #3) introduced ``_split_bps`` to clamp on
# the reward / per-block-cap / attester-fee / slash sides.  The audit
# r52 #3 CHANGELOG named the wider abstraction explicitly:
#
#     "the wider abstraction calls for a shared ``_split_bps`` helper
#      to catch every future ``bps // den`` site that could round to
#      zero under a realistic minimum."
#
# The bite: with N >= 2 non-proposer attesters and a small
# ``trim_from_att``, every per-attester ``bonus`` rounds to 0 and the
# entire trim flows to ``burned`` instead of redistributing -- silently
# inverting Tier 53's "issuance accrues to validators" intent back to
# the pre-Tier-53 burn-everything regime in the dormancy-controller's
# anchored steady state.
#
# Tier 77 routes the redistribute loop's per-attester ``bonus`` through
# ``_split_bps(trim_from_att, existing, other_total, min_unit=1,
# gate=cap_min_unit_active)`` with a per-iteration ``remaining`` clamp
# that prevents two consecutive min-unit clamps from over-distributing
# past ``trim_from_att`` (supply conservation).
#
# Pre-fork (``gate=False``) the helper returns the byte-identical
# floor-divide; historical-block replay across the activation gate is
# preserved.  Post-fork small-trim redistributions land at least 1
# token on the first eligible attester instead of silently burning.
#
# Activation height ``16500`` sits 2000 blocks above Tier 76 (14500),
# matching the Tier 70 -> 71 -> 73 -> 74 -> 75 -> 76 ~13.9-day cohort
# spacing.  Each issuance-discipline retune deserves its own operator
# upgrade cycle.
PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT = 16500  # Tier 77

assert PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT > (
    FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT
), (
    "PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT (Tier 77) must strictly "
    "follow FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT (Tier 76) -- "
    "consecutive issuance-discipline retunes deserve their own cohort "
    "so operators absorb each in its own upgrade cycle."
)


# ─────────────────────────────────────────────────────────────────────
# Tier 78 — Retroactive-evidence stake-pin defense (audit r56 #1).
# ─────────────────────────────────────────────────────────────────────
#
# CLAUDE.md anchors defended:
#   * Collective censorship-resistance: a colluding subset must not be
#     able to fabricate slashable evidence against honest validators.
#   * Honest-operator insurance: long-tenured operators must not be
#     slashed by attackers who freshly stake sock-puppets in the
#     immediate past.
#
# The vector closed: retroactive consensus-quorum active-set checks
# (NonResponseEvidence witness filter, InclusionList quorum verifier)
# previously read `blockchain.supply.staked` -- the LIVE map -- when
# deciding whether a witness/reporter was in the active set AT the
# past `observed_height` / `report_height` they claim to be reporting
# about.  An attacker who stakes up `WITNESS_QUORUM` sock-puppet
# validators today can therefore sign retroactive `WitnessObservation`
# messages for an observed_height in the past where they were NOT
# validators, and the admission gate happily counts their CURRENT
# stake to satisfy the active-set check.  Same shape on the
# InclusionList side: a recent-stake attacker could inflate per-entry
# stake support by counting stake that wasn't present at report time.
#
# Tier 78 routes both retroactive checks through the pinned stake
# snapshot at the relevant PAST height instead of the live map, via
# a new `_stake_at_height` chokepoint on `Blockchain` that consults
# `self._stake_snapshots`.  The helper is strict on miss (returns 0
# -- "not staked") rather than falling back to live state: a missing
# pin must NEVER cause a retroactive check to read fresh-stake.
#
# Activation `18500` sits 2000 blocks above Tier 77 (16500), matching
# the Tier 70 -> 71 -> 73 -> 74 -> 75 -> 76 -> 77 ~13.9-day cohort
# spacing.  A defense-rule change deserves its own operator runway.
#
# Pre-fork the legacy `supply.staked` read runs unchanged for replay
# determinism.  Post-fork:
#   * `non_response_evidence.NonResponseEvidenceProcessor.process`
#     filters witnesses by stake at `o.observed_height`.
#   * `Blockchain._validate_inclusion_list_quorum` sources `stakes`
#     from `_stake_snapshots[lst.publish_height - 1]` (the latest
#     legal report_height -- since reports are in the
#     `[publish_height - INCLUSION_LIST_WAIT_BLOCKS, publish_height - 1]`
#     window and the IL is committed at `publish_height`).
#
# Pinned-snapshot retention window is `FINALITY_VOTE_MAX_AGE_BLOCKS`
# (== 10 * FINALITY_INTERVAL == 1000 blocks).  Maximum lookback for
# retroactive evidence is `WITNESS_OBSERVATION_RETENTION_BLOCKS` (64)
# on the NonResponse side and `INCLUSION_LIST_WAIT_BLOCKS` (4) on the
# IL side -- both comfortably inside the retention window.
RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT = 18500  # Tier 78

assert RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT > (
    PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT
), (
    "RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT (Tier 78) must strictly "
    "follow PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT (Tier 77) -- "
    "consecutive consensus-rule retunes deserve their own cohort so "
    "operators absorb each in its own upgrade cycle."
)


# ─────────────────────────────────────────────────────────────────────
# Tier 79 — censorship-evidence admission basis widening
# ─────────────────────────────────────────────────────────────────────
# Audit r57 #2 closure.  Pre-r57 the censorship-evidence admission path
# captured ``staked_at_admission = supply.staked.get(offender)`` --
# ``pending_unstakes`` excluded.  ``burn_slash_proportional`` then
# capped the matured slash at that staked-only snapshot, even though
# the helper is willing to drain ``pending_unstakes`` too.  An accused
# validator who saw the CensorshipEvidenceTx land in the mempool could
# pre-emptively unstake (move balance from staked -> pending_unstakes)
# before admission and shrink the slash cap by the pending portion --
# defeating Tier 31's "censor-then-unstake evasion closure" anchor on
# the basis-CAPTURE side.  (Tier 31 closed it on the apply side; the
# admission-side snapshot was still too narrow.)
#
# Tier 79 routes the admission-basis snapshot through one chokepoint
# (``Blockchain._capture_slashable_basis(offender_id, *, height)``):
#   * pre-fork: returns ``supply.staked.get(offender_id, 0)``       (legacy,
#     byte-identical to historical replay)
#   * post-fork: returns ``staked + pending_unstakes``              (Tier 79)
#
# The chokepoint is the abstraction-over-symptom fix the audit called
# out: every evidence-admission site routes through one helper, so a
# future 2-phase evidence kind cannot silently re-acquire the same
# narrow-basis bug.
#
# Pre-fork the legacy bare ``.staked.get`` capture is preserved so
# replay of historical blocks across the activation gate is byte-
# identical to legacy behavior.  Pure consensus-rule swap; no new
# wire format, no new tx kinds, no state-tree changes.  Activation
# height 20500 sits 2000 blocks above Tier 78 (18500), matching the
# Tier 70 -> 71 -> 73 -> 74 -> 75 -> 76 -> 77 -> 78 ~13.9-day cohort
# spacing -- one operator upgrade cycle per consensus-rule retune.
SLASHABLE_BASIS_AT_ADMISSION_HEIGHT = 20500  # Tier 79

assert SLASHABLE_BASIS_AT_ADMISSION_HEIGHT > (
    RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT
), (
    "SLASHABLE_BASIS_AT_ADMISSION_HEIGHT (Tier 79) must strictly "
    "follow RETROACTIVE_EVIDENCE_STAKE_PIN_HEIGHT (Tier 78) -- "
    "consecutive consensus-rule retunes deserve their own cohort so "
    "operators absorb each in its own upgrade cycle."
)


# ─── Tier 80 — multi-key re-verify on slashing & inclusion paths ────
#
# Audit r58 #1 (security top-1).  Three slashing / inclusion re-verify
# paths still read ``public_keys.get(entity_id)`` (single CURRENT key)
# while the existing ``_verify_signer_at_height`` multi-key chokepoint
# covers only Attestation + FinalityVote validation/gossip (audit r50
# #2):
#
#   * ``inclusion_list.verify_inclusion_list_quorum`` -- reporter sig
#     recheck on AttesterMempoolReports (rejects the WHOLE list on a
#     single bad sig, defeating the forced-inclusion-list arm).
#   * ``NonResponseEvidenceProcessor.process`` (and the proposer-sim
#     mirror in ``Blockchain._sim_apply_block`` non-response branch) --
#     witness observation sig recheck (drops below WITNESS_QUORUM and
#     dismisses the slash).
#   * ``BogusRejectionProcessor.process`` -- embedded ``message_tx``
#     sig recheck (treats a rotation-affected tx as "honest rejection"
#     and lets the lying validator escape slashing).
#
# In every case a colluding entity that rotates between the relevant
# observation-time and apply-time silently invalidates the verify --
# directly threatening the CLAUDE.md "collective censorship-resistance"
# and "honest-operator insurance" anchors that the slashable-evidence
# arm is built on.  ``KEY_ROTATION_COOLDOWN_BLOCKS = 144`` is short
# enough to make the timing trivial: 4 blocks for InclusionList, 64
# blocks for NRE, full evidence-TTL for BogusRejection.
#
# Tier 80 routes all three sites through the existing multi-key
# candidate set:
#
#   * pre-fork: legacy single-current-key behaviour                   (legacy,
#     byte-identical to historical replay)
#   * post-fork: try every key the offender ever held + the current
#     key, accept if ANY matches; on InclusionList, a report whose sig
#     fails ALL candidates is DROPPED (fail-soft, same shape as the
#     existing unknown-reporter / stale-window skips) rather than
#     failing the whole list.
#
# Abstraction-over-symptom fix.  Adding a new signed-aggregation
# re-verify site that goes around the multi-key chokepoint reintroduces
# the same defect class by definition.  Activation height 22500 sits
# 2000 blocks above Tier 79 (20500), matching the Tier 70 -> 71 -> 73
# -> 74 -> 75 -> 76 -> 77 -> 78 -> 79 ~13.9-day cohort spacing -- one
# operator upgrade cycle per consensus-rule retune.
MULTI_KEY_RE_VERIFY_HEIGHT = 22500  # Tier 80

assert MULTI_KEY_RE_VERIFY_HEIGHT > SLASHABLE_BASIS_AT_ADMISSION_HEIGHT, (
    "MULTI_KEY_RE_VERIFY_HEIGHT (Tier 80) must strictly follow "
    "SLASHABLE_BASIS_AT_ADMISSION_HEIGHT (Tier 79) -- consecutive "
    "consensus-rule retunes deserve their own cohort."
)


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
