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
# Cap on how many fallback rounds a block's claimed timestamp can imply
# past the parent.  Block round is computed as
# int((block.ts - parent.ts - BLOCK_TIME_TARGET) // BLOCK_TIME_TARGET).
# Even after tightening MAX_BLOCK_FUTURE_DRIFT to 120 s, a malicious
# proposer can still inflate the implied round count by picking a
# parent.ts well below current wall clock; the explicit round cap keeps
# slot-rotation grinding bounded regardless of future-drift tolerance.
# Original cap of 5 covered legitimate missed-slot scenarios.  In
# 1.26.2 the cap was raised to 100 after an operational chain-stall
# during the 1.25.x → 1.26.x rollout sequence (the chain went ~2h
# without a block while a series of regressions in mempool sort key
# and a corrupted height-guard ratchet were being patched).  Round
# count (= ts_gap / BLOCK_TIME_TARGET ≈ 1 per 10 min) had run up to
# ~12, so every recovery proposal was rejected by the round cap and
# the chain couldn't self-heal until the cap was lifted.  100 covers
# ~16 h of stall and still bounds slot-rotation grinding to a small
# constant — well below the future-drift window's worst-case abuse.
MAX_PROPOSER_FALLBACK_ROUNDS = 100
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
MIN_STAKE_FAUCET_DRIP_HEIGHT = 14_000  # Tier 28

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
VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT = 16_000  # Tier 29


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
SEED_DIVESTMENT_START_HEIGHT = 7_500                                   # was 50_000
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

SEED_DIVESTMENT_REDIST_HEIGHT = 1600              # Tier 3 (compressed: was 74_000)

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
WITNESS_AUTO_SEPARATION_HEIGHT = 3000


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
HONESTY_CURVE_HONEST_TRACK_FLOOR = 0.2  # never relieve below 1/5 of base

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
HONESTY_CURVE_RATE_HEIGHT = 5000  # Tier 24

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
COMMUNITY_ID_HEIGHT = 8_000  # Tier 25
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
REVOKE_TX_WINDOW_HEIGHT = 10_000  # Tier 26

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
REACT_NO_SELF_MESSAGE_HEIGHT = 12_000  # Tier 27

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
