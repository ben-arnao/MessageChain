"""
Inflationary token economics for MessageChain.

Why inflation? People die, lose access, or abandon wallets. Without new token
issuance the effective circulating supply would shrink to zero over time.
Controlled inflation ensures the network remains usable indefinitely.

Model:
- Fixed block reward (power of 2), halving periodically (like BTC's issuance)
- Block reward = BLOCK_REWARD / (2 ^ (block_height // HALVING_INTERVAL))
- BLOCK_REWARD=16 gives meaningful halvings (16->8->4) then hits floor of 4
- Floor of BLOCK_REWARD_FLOOR tokens/block ensures validation stays lucrative
- Block reward is split: 1/4 to proposer, 3/4 to attestors (pro-rata by stake)
- Transaction fees use EIP-1559-style base fee + tip:
  - Base fee adjusts dynamically based on block fullness (burned — removed from supply)
  - Tip (fee minus base fee) goes to the block proposer
- Fee burning creates deflationary pressure to support long-term token value

The inflation rate decreases over time due to halvings, but never fully stops,
ensuring permanent (diminishing) issuance to replace lost tokens. Fee burning
partially offsets inflation, creating a balanced tokenomic model.
"""

import math
from messagechain.config import (
    GENESIS_SUPPLY, BLOCK_REWARD, HALVING_INTERVAL, MIN_FEE,
    SLASH_FINDER_REWARD_PCT, UNBONDING_PERIOD, MIN_TOTAL_STAKE,
    TREASURY_ENTITY_ID, VALIDATOR_MIN_STAKE, BLOCK_REWARD_FLOOR,
    PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR,
    PROPOSER_REWARD_CAP,
    PROPOSER_CAP_HALVING_HEIGHT,
    BASE_FEE_INITIAL, BASE_FEE_MAX_CHANGE_DENOMINATOR,
    TARGET_BLOCK_SIZE, MIN_TIP,
    BLOCK_BYTES_RAISE_HEIGHT, TARGET_BLOCK_SIZE_POST_RAISE,
    get_unbonding_period,
    ATTESTER_REWARD_SPLIT_HEIGHT,
    ATTESTER_FEE_FUNDING_HEIGHT,
    ATTESTER_FEE_SHARE_BPS,
    TARGET_CIRCULATING_SUPPLY_FLOOR,
    DEFLATION_ISSUANCE_MULTIPLIER,
    DEFLATION_FLOOR_HEIGHT,
    DEFLATION_FLOOR_V2_HEIGHT,
    DEFLATION_REBATE_BPS,
    DEFLATION_REBATE_WINDOW_BLOCKS,
    REWARD_CURVE_HEIGHT,
    REWARD_CURVE_SMALL_THRESHOLD_BPS,
    REWARD_CURVE_MID_THRESHOLD_BPS,
    REWARD_CURVE_SMALL_NUMERATOR,
    REWARD_CURVE_SMALL_DENOMINATOR,
    REWARD_CURVE_MID_NUMERATOR,
    REWARD_CURVE_MID_DENOMINATOR,
    REWARD_CURVE_LARGE_BAND_HEIGHT,
    REWARD_CURVE_LARGE_THRESHOLD_BPS,
    REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS,
    REWARD_CURVE_LARGE_FLOOR_NUM,
    REWARD_CURVE_LARGE_FLOOR_DEN,
    REWARD_CURVE_SMOOTH_HEIGHT,
    REWARD_CURVE_SMOOTH_PEAK_NUM,
    REWARD_CURVE_SMOOTH_FLOOR_NUM,
    REWARD_CURVE_SMOOTH_MULT_DEN,
    REWARD_CURVE_SMOOTH_SCALE_BPS,
    REWARD_CURVE_SMOOTH_V2_HEIGHT,
    REWARD_CURVE_SMOOTH_V2_PEAK_NUM,
    REWARD_CURVE_SMOOTH_V2_FLOOR_NUM,
    REWARD_CURVE_SMOOTH_V2_SCALE_BPS,
    DORMANCY_CONTROLLER_HEIGHT,
    DORMANCY_WINDOW_BLOCKS,
    DORMANCY_TAPER_BLOCKS,
    DORMANCY_TARGET_ACTIVE_SUPPLY,
    DORMANCY_CONTROLLER_K_NUM,
    DORMANCY_CONTROLLER_K_DEN,
    DORMANCY_MAX_ISSUANCE_PER_BLOCK,
)


def reward_curve_multiplier(stake_bps: int) -> tuple[int, int]:
    """Return (numerator, denominator) for a validator's Tier 20 reward
    multiplier given their stake share of total active stake.

    Implements the three-band piecewise-constant curve anchored in
    CLAUDE.md (small < mid > large, large = baseline):
        bps <  SMALL_THRESHOLD                → SMALL_NUM/SMALL_DEN  (<1.0)
        SMALL_THRESHOLD ≤ bps < MID_THRESHOLD → MID_NUM/MID_DEN      (>1.0)
        bps ≥ MID_THRESHOLD                   → 1/1                  (baseline)

    Caller is responsible for height-gating: this helper is pure and
    has no notion of activation height.  Pre-Tier-20 callers must NOT
    invoke it; the legacy reward distribution is byte-for-byte
    preserved by skipping the multiplier entirely below
    REWARD_CURVE_HEIGHT.

    `stake_bps` is in basis points (1 bp = 0.01%) of total active
    stake.  Caller computes it as
        stake_bps = validator_stake * 10_000 // total_active_stake
    Defensive note: if total_active_stake is 0 (early bootstrap, all-
    unstaked edge cases), the caller MUST short-circuit to the baseline
    multiplier (1/1) BEFORE invoking this helper — division-by-zero
    avoidance is a caller responsibility, kept here so the helper stays
    pure-int and has a single behavior contract.

    Returns integer (num, den) so the consensus path stays float-free:
    the eventual reward computation is `reward * num // den`.
    """
    if stake_bps < REWARD_CURVE_SMALL_THRESHOLD_BPS:
        return (
            REWARD_CURVE_SMALL_NUMERATOR,
            REWARD_CURVE_SMALL_DENOMINATOR,
        )
    if stake_bps < REWARD_CURVE_MID_THRESHOLD_BPS:
        return (
            REWARD_CURVE_MID_NUMERATOR,
            REWARD_CURVE_MID_DENOMINATOR,
        )
    return (1, 1)


def reward_curve_multiplier_v2(stake_bps: int) -> tuple[int, int]:
    """Tier 37 — saturating-large reward curve.

    Adds a fourth band on top of the Tier 20 piecewise-constant curve:

        bps <  SMALL_THRESHOLD                            → SMALL  (<1.0)
        SMALL ≤ bps <  MID_THRESHOLD                       → MID    (>1.0)
        MID   ≤ bps <  LARGE_THRESHOLD                     → 1/1    (baseline)
        LARGE ≤ bps <  LARGE_FLOOR_THRESHOLD               → linear-interp
                                                             from 1.0 down
                                                             to FLOOR
        bps ≥ LARGE_FLOOR_THRESHOLD                        → FLOOR  (<1.0)

    The 5%–15% range stays at 1.0 so real-network behavior in the
    active stake range is unchanged; only the upper tail (>=15%)
    compresses downward, restoring CLAUDE.md's anchored "large
    saturating to less than middle" property.

    Linear interpolation in pure-integer arithmetic.  We compute the
    slope at fixed precision = LARGE_FLOOR_DEN * (LARGE_FLOOR_THRESHOLD
    - LARGE_THRESHOLD) so every multiplication and floor-division stays
    int-only.  Result is a (num, den) pair sharing a common denominator
    big enough to preserve every distinct slope point.

    Caller (mint_block_reward + sim mirror) gates this helper on
    block_height >= REWARD_CURVE_LARGE_BAND_HEIGHT.  Pre-fork callers
    invoke `reward_curve_multiplier` (the legacy helper) byte-for-byte.

    Mirrors the integer-rational pattern from the 1.35.0 honesty-curve
    rewrite (`slashing_severity` AMBIGUOUS branch) — no `float()` on the
    consensus hot path.
    """
    if stake_bps < REWARD_CURVE_SMALL_THRESHOLD_BPS:
        return (
            REWARD_CURVE_SMALL_NUMERATOR,
            REWARD_CURVE_SMALL_DENOMINATOR,
        )
    if stake_bps < REWARD_CURVE_MID_THRESHOLD_BPS:
        return (
            REWARD_CURVE_MID_NUMERATOR,
            REWARD_CURVE_MID_DENOMINATOR,
        )
    if stake_bps < REWARD_CURVE_LARGE_THRESHOLD_BPS:
        return (1, 1)
    if stake_bps >= REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS:
        return (
            REWARD_CURVE_LARGE_FLOOR_NUM,
            REWARD_CURVE_LARGE_FLOOR_DEN,
        )
    # Linear-interp band: at LARGE_THRESHOLD multiplier = 1.0, at
    # LARGE_FLOOR_THRESHOLD multiplier = FLOOR_NUM/FLOOR_DEN.  Express
    # both endpoints over a common denominator FLOOR_DEN:
    #   start = FLOOR_DEN     / FLOOR_DEN  (= 1.0)
    #   end   = FLOOR_NUM     / FLOOR_DEN
    # Linearly interpolate:
    #   span_bps = LARGE_FLOOR_THRESHOLD - LARGE_THRESHOLD
    #   t_bps    = stake_bps               - LARGE_THRESHOLD
    #   raw_num  = (FLOOR_DEN * (span_bps - t_bps) + FLOOR_NUM * t_bps)
    #   raw_den  =  FLOOR_DEN * span_bps
    # Both raw_num and raw_den are positive ints; result is the rational
    # multiplier exactly (no rounding) — caller applies as
    # `reward * raw_num // raw_den`.
    span_bps = (
        REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS
        - REWARD_CURVE_LARGE_THRESHOLD_BPS
    )
    t_bps = stake_bps - REWARD_CURVE_LARGE_THRESHOLD_BPS
    raw_num = (
        REWARD_CURVE_LARGE_FLOOR_DEN * (span_bps - t_bps)
        + REWARD_CURVE_LARGE_FLOOR_NUM * t_bps
    )
    raw_den = REWARD_CURVE_LARGE_FLOOR_DEN * span_bps
    return (raw_num, raw_den)


def reward_curve_multiplier_v3(stake_bps: int) -> tuple[int, int]:
    """Tier 40 — smooth concave reward curve.

    Replaces the piecewise small/mid/baseline/saturating-tail shape of
    Tiers 20+38 with a single monotonically-diminishing rational
    function whose per-unit-stake yield decays smoothly from
    PEAK at near-zero stake toward FLOOR as stake grows large, but
    never reaches FLOOR.  This is the asymptotic "soft cap" CLAUDE.md
    anchors as the new reward-curve shape: rich-get-richer in absolute
    terms (adding stake always pays more), but the *share* of issuance
    compresses over time because each additional unit of stake earns
    less than the last.

    Formula (rational, pure-int):

        multiplier(stake_bps) =
          (FLOOR_NUM * stake_bps + PEAK_NUM * SCALE_BPS)
          /
          (MULT_DEN  * (SCALE_BPS + stake_bps))

    Both numerator and denominator are positive ints for any
    stake_bps >= 0; the result is the rational multiplier exactly with
    no rounding.  Caller applies as `reward * num // den`.

    Properties (all derivable from the formula):
      - At stake_bps=0:        multiplier = PEAK_NUM/MULT_DEN
      - As stake_bps→∞:        multiplier → FLOOR_NUM/MULT_DEN
      - Strictly decreasing in stake_bps (per-unit yield diminishes).
      - Absolute reward (= stake * multiplier) is strictly increasing
        and concave in stake — adds always pay something, but the
        delta shrinks.

    Caller (mint_block_reward + sim mirror) gates this helper on
    block_height >= REWARD_CURVE_SMOOTH_HEIGHT.  Pre-Tier-40 callers
    invoke `reward_curve_multiplier_v2` (Tier 38) byte-for-byte for
    pre-fork blocks, preserving consensus determinism on replay.

    Mirrors the integer-rational pattern from Tier 38's
    linear-interpolation band — no `float()` on the consensus hot path.
    """
    raw_num = (
        REWARD_CURVE_SMOOTH_FLOOR_NUM * stake_bps
        + REWARD_CURVE_SMOOTH_PEAK_NUM * REWARD_CURVE_SMOOTH_SCALE_BPS
    )
    raw_den = (
        REWARD_CURVE_SMOOTH_MULT_DEN
        * (REWARD_CURVE_SMOOTH_SCALE_BPS + stake_bps)
    )
    return (raw_num, raw_den)


def reward_curve_multiplier_v4(stake_bps: int) -> tuple[int, int]:
    """Tier 42 — smooth concave reward curve V2 retune.

    Same rational form as v3 (Tier 40); only the tuning knobs change:

        multiplier(stake_bps) =
          (FLOOR_V2_NUM * stake_bps + PEAK_V2_NUM * SCALE_V2_BPS)
          /
          (MULT_DEN     * (SCALE_V2_BPS + stake_bps))

    The CLAUDE.md-anchored shape (concave / monotonically diminishing
    per-unit yield / asymptotic soft cap / no hard cap / strictly-
    increasing absolute reward / concave absolute reward / pure-int) is
    preserved bit-for-bit because the formula shape is identical to v3
    — only the constants differ.  CLAUDE.md explicitly leaves the
    parameters as tuning knobs ("exact constants ... are tuning knobs").

    Why retune: at today's mainnet bootstrap concentrations (2
    validators ≈ 50% each, stake_bps≈5000), v3's PEAK=150/FLOOR=40/
    SCALE=300 puts the multiplier at ~0.46×, burning ~50–67% of the
    attester pool every block (integer-rounding short of the pool at
    mint_block_reward's `attester_tokens_paid<attester_pool` branch).
    That violates two CLAUDE.md anchors at once: the bootstrap-arc
    anchor (issuance must be calibrated so the founder can credibly
    secure the network solo while it has only a handful of nodes) AND
    the "low steady perpetual inflation funds the security budget
    forever" anchor.  The v3 curve-bend point (3% stake) sits below
    every realistic bootstrap concentration, so a bootstrap-era
    validator effectively earns at the asymptote.

    Tier 42 lifts the bootstrap-era multiplier to ~0.88× (50% stake)
    by widening the curve-bend point to 10% stake and raising both peak
    and floor; whales still hit diminishing returns, but the floor is
    high enough to keep block-by-block burn from gating away the bulk
    of issuance during bootstrap.

    Caller (mint_block_reward + sim mirror) gates this helper on
    block_height >= REWARD_CURVE_SMOOTH_V2_HEIGHT.  Pre-Tier-42 callers
    invoke `reward_curve_multiplier_v3` (Tier 40) byte-for-byte for
    pre-fork blocks, preserving consensus determinism on replay.

    Mirrors the integer-rational pattern from v3 — no `float()` on the
    consensus hot path.
    """
    raw_num = (
        REWARD_CURVE_SMOOTH_V2_FLOOR_NUM * stake_bps
        + REWARD_CURVE_SMOOTH_V2_PEAK_NUM * REWARD_CURVE_SMOOTH_V2_SCALE_BPS
    )
    raw_den = (
        REWARD_CURVE_SMOOTH_MULT_DEN
        * (REWARD_CURVE_SMOOTH_V2_SCALE_BPS + stake_bps)
    )
    return (raw_num, raw_den)


def _attester_cap_bps_per_epoch(current_block_height: int) -> int:
    """Return the active per-validator attester-reward cap (bps of pool)
    at the given block height.

    Tier 4 set the cap at 100 bps (1%) of the per-block attester-pool
    basis, scaled across FINALITY_INTERVAL.  That value was sized for
    committees of ~128 members where each validator's per-slot reward
    is small.  At today's mainnet committee size of 2, per-slot reward
    is ~half the attester pool — the 100 bps cap is hit by block 3 of
    every 100-block epoch and ~79% of attester issuance evaporates per
    epoch.

    Tier 45 raises the cap to 5000 bps (50%) at and above
    PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT.  At committee=2 each
    honest validator can earn its pro-rata ~50% share without burning;
    at committee=128 each member's reachable share is ~0.78%, far below
    the cap so the sybil/concentration defense is preserved.

    Helper exists so the dispatch logic is in one place and unit-
    testable directly without crafting a full mint_block_reward call.
    Pre-fork path returns the legacy constant byte-for-byte.
    """
    from messagechain.config import (
        PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT,
        PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH,
        PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45,
    )
    if current_block_height >= PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT:
        return PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45
    return PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH


class SupplyTracker:
    """Tracks total supply, minting, and per-entity balances."""

    def __init__(self):
        self.total_supply: int = GENESIS_SUPPLY
        self.total_minted: int = 0  # tokens created via block rewards
        self.total_fees_collected: int = 0
        self.total_burned: int = 0  # tokens destroyed via base fee burns
        self.balances: dict[bytes, int] = {}
        self.staked: dict[bytes, int] = {}
        # Pending unstakes: entity_id -> list of (amount, release_block)
        self.pending_unstakes: dict[bytes, list[tuple[int, int]]] = {}
        # Optional ChainDB handle.  When set by Blockchain.__init__ the
        # pending_unstakes mutation paths (unstake / process / slash)
        # mirror each change into the `pending_unstakes` SQL table so a
        # cold process restart rehydrates the identical queue — without
        # this mirror the in-memory queue is lost on restart and the
        # next process_pending_unstakes call releases different tokens
        # on restarted vs. un-restarted nodes, forking consensus at the
        # next state_root check.  None-safe: tests and non-persisted
        # contexts don't set it and the mirror calls are skipped.
        self.db = None
        # EIP-1559 dynamic base fee
        self.base_fee: int = BASE_FEE_INITIAL
        # Per-block fee-burn ticker.  Incremented by every
        # pay_fee_with_burn call that actually burns a base_fee; read
        # and reset by Blockchain._apply_block_state after all txs have
        # been applied, to compute how much of this block's burn should
        # be redirected into the ArchiveRewardPool.  See
        # ARCHIVE_BURN_REDIRECT_PCT in config.py / the
        # proof-of-custody-archive-rewards design doc.  Kept separate
        # from total_burned so other burn sources (slashing, inactivity
        # leak, new-account surcharge) are not mistakenly redirected.
        self.fee_burn_this_block: int = 0

        # Treasury rebase (hard fork): once-per-chain flag that the
        # one-shot burn at TREASURY_REBASE_HEIGHT has fired.  Guards
        # against double-burn from an adjacent re-apply of the same
        # block height.  Snapshotted alongside balances/total_supply
        # for reorg safety; a reorg that undoes the rebase block rolls
        # this back to False so the replay re-fires cleanly.
        self.treasury_rebase_applied: bool = False

        # Idempotency flag for the SUPPLY_RECONCILIATION_HEIGHT hard
        # fork (1.50.0).  Snapshotted with the supply state for reorg
        # safety -- a reorg that undoes the reconciliation block also
        # un-flips this flag so the canonical replay re-fires cleanly.
        # See ``Blockchain._apply_supply_reconciliation`` for the
        # mechanism and CHANGELOG 1.50.0 for the root-cause history.
        self.supply_reconciliation_applied: bool = False

        # Treasury spend-rate cap bookkeeping (hard fork): per-epoch
        # rolling window of debited amounts.  A spend at current_block
        # is charged against the epoch whose start is
        # (current_block // TREASURY_SPEND_CAP_EPOCH_BLOCKS) * epoch.
        # The cap is recomputed against the treasury balance at spend
        # time (1% of current, not frozen at epoch start) so the cap
        # naturally shrinks alongside the treasury.  Using -1 as a
        # sentinel for "no epoch recorded yet" sidesteps a real epoch
        # 0 collision.
        self._treasury_spend_epoch_start: int = -1
        self._treasury_spend_debited_this_epoch: int = 0

        # Treasury cap-tightening hard fork
        # (TREASURY_CAP_TIGHTEN_HEIGHT): rolling list of
        # (block_height, debit_amount) tuples recording every
        # treasury_spend debit observed at/after activation.  At each
        # post-activation spend the list is pruned to entries whose
        # block_height is within the trailing
        # TREASURY_SPEND_CAP_YEAR_BLOCKS window, summed, and checked
        # against TREASURY_MAX_SPEND_BPS_PER_YEAR of the current
        # treasury balance.  Bounded size: pre-tighten the per-epoch
        # cap produces at most ~525 entries/year (one spend per
        # 100-block epoch × 526 epochs/year window).
        #
        # Consensus-visible state: snapshotted alongside the other
        # treasury-cap bookkeeping and committed to the state root
        # so state-synced nodes inherit the identical rolling total
        # — otherwise a cold-booted node would accept a post-sync
        # spend that a replaying node rejects.
        self._treasury_spend_rolling_debits: list[tuple[int, int]] = []

        # Seed-divestment lottery-redistribution hard fork
        # (SEED_DIVESTMENT_REDIST_HEIGHT): consensus-visible scalar
        # pool that accumulates the 45% "lottery" share of each
        # REDIST-era divestment block's divested amount.  Drained
        # evenly across remaining lottery firings in the divestment
        # window via Blockchain._apply_block_state's lottery step, so
        # the pool ends at exactly 0 at the last firing before
        # SEED_DIVESTMENT_END_HEIGHT.
        #
        # Pre-REDIST-activation this scalar remains 0 at all times
        # — the divestment step's lottery share is zero — so byte-
        # for-byte preservation of legacy / RETUNE-era behavior is
        # trivial.
        #
        # Lifecycle:
        #   - accumulated by _apply_seed_divestment (REDIST-era only)
        #   - drained by _apply_block_state's lottery step
        #   - snapshotted by _snapshot_memory_state for reorg
        #     rollback safety
        #   - committed to the state-snapshot root (state_snapshot.py
        #     _GLOBAL_LOTTERY_PRIZE_POOL under _TAG_GLOBAL) so state-
        #     synced nodes inherit the same pool as replaying nodes
        self.lottery_prize_pool: int = 0

        # Attester-pool fee-funding hard fork
        # (ATTESTER_FEE_FUNDING_HEIGHT): per-block accumulator of the
        # base-fee share that redirects into the attester committee
        # reward pool instead of burning.  Every pay_fee_with_burn
        # call post-activation splits base_fee into
        #   attester_share = base_fee * ATTESTER_FEE_SHARE_BPS // 10_000
        #   actual_burn    = base_fee - attester_share
        # and accrues attester_share here.  mint_block_reward adds
        # this accumulator to the issuance-side attester_pool before
        # dividing pro-rata across the committee, then zeroes it so
        # the next block starts clean.
        #
        # EPHEMERAL: reset at the start of every _apply_block_state
        # (mirrors fee_burn_this_block) and consumed at mint-time
        # within the same block.  Not snapshotted — a reorg replay
        # produces the same value deterministically because the fees
        # that fed it are themselves in the block.  Re-apply of the
        # same block sees the same fee set, accrues the same amount,
        # and mints the same per-slot reward.
        #
        # Pre-activation: never accrues (the gate lives in
        # pay_fee_with_burn) and never consumed (the gate lives in
        # mint_block_reward).  Byte-for-byte legacy behavior.
        self.attester_fee_pool_this_block: int = 0

        # Per-entity attester-reward cap per epoch hard fork
        # (ATTESTER_REWARD_CAP_HEIGHT): rolling-epoch bookkeeping for
        # the PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH limit.
        # ``attester_epoch_earnings`` tracks per-entity earnings
        # (bytes→int) inside the current FINALITY_INTERVAL window; it
        # resets to empty when ``attester_epoch_earnings_start`` no
        # longer matches the current block's epoch-start.  Rewards
        # exceeding the per-entity cap BURN rather than crediting
        # the entity.
        #
        # Consensus-visible state: snapshotted alongside the treasury
        # cap bookkeeping and committed to the state root (see
        # _TAG_ATTESTER_EPOCH under messagechain/storage/state_snapshot.py)
        # so a state-synced node computes the identical cap-overflow
        # burn at the next reward block — otherwise a cold-booted
        # node that disagreed on per-entity earnings would silently
        # fork the next mint.
        #
        # Sentinel -1 for the start marker sidesteps a real epoch-0
        # collision; pre-activation the dict stays empty and the
        # sentinel never changes, giving byte-for-byte legacy
        # behavior.
        self.attester_epoch_earnings: dict[bytes, int] = {}
        self.attester_epoch_earnings_start: int = -1

        # Fee-responsive deflation floor hard fork
        # (DEFLATION_FLOOR_V2_HEIGHT): rolling window of
        # (block_height, fee_burn_amount) entries used to compute the
        # trailing burn rate that drives the new rebate-style boosted
        # issuance.  At/after DEFLATION_FLOOR_V2_HEIGHT, every fee-burn
        # appends an entry here; calculate_block_reward prunes entries
        # older than DEFLATION_REBATE_WINDOW_BLOCKS, sums the rest, and
        # uses (sum / window) × DEFLATION_REBATE_BPS / 10_000 as a
        # rebate floor on issuance when supply < TARGET.
        #
        # Consensus-visible state: snapshotted alongside
        # _treasury_spend_rolling_debits (same pattern) and committed
        # to the state-snapshot root (_TAG_FEE_BURN_ROLLING) so
        # state-synced nodes inherit the identical rolling total —
        # otherwise a cold-booted node would compute a different
        # boosted reward at the next block under the floor regime
        # and silently fork.
        #
        # Bounded size: at most DEFLATION_REBATE_WINDOW_BLOCKS entries
        # survive the prune per block (the prune runs before each
        # reward computation).  Intra-block we can transiently hold
        # more if multiple fees burn in the same block, but the next
        # calculate_block_reward call prunes back down.
        #
        # Pre-activation: never appended and never read; byte-for-byte
        # legacy behavior preserved.
        self.rolling_fee_burn: list[tuple[int, int]] = []

        # Deflation-floor-v2 activation-seed flag: one-shot guard that
        # the synthetic seed entry has been installed at
        # DEFLATION_FLOOR_V2_HEIGHT.  Without this seed the rolling
        # window is empty at activation, so the first ~1,000 blocks
        # post-activation compute rolling_rate=0 and fall back to
        # base_reward — defeating the fee-responsive rebate at exactly
        # the moment it is needed (the fork fires when supply < TARGET,
        # i.e. when deflation is already hurting the chain).
        #
        # The seed itself is installed by
        # ``Blockchain._apply_deflation_floor_v2_seed`` at the start of
        # _apply_block_state, using the lifetime burn-per-block average
        # (total_burned / block_height) scaled over
        # DEFLATION_REBATE_WINDOW_BLOCKS to approximate a full window
        # of real burns.  The synthetic entry is placed at the oldest
        # edge of the window (seed_height = block_height
        # - DEFLATION_REBATE_WINDOW_BLOCKS + 1) so it rotates out over
        # DEFLATION_REBATE_WINDOW_BLOCKS of real accumulation post-
        # activation — the rebate ramps UP from the bootstrap estimate
        # rather than up from zero.
        #
        # Consensus-visible state.  Snapshotted alongside
        # rolling_fee_burn for reorg safety (a reorg past the
        # activation block MUST un-flip this flag and remove the
        # synthetic entry, or the canonical replay would skip the
        # seed).  Committed to the state-snapshot root (_TAG_GLOBAL /
        # _GLOBAL_ROLLING_FEE_BURN_SEEDED) so state-synced nodes
        # inherit the same flag — otherwise a cold-booted node that
        # disagreed on whether the seed had fired would compute a
        # different boosted reward at the next low-supply block and
        # silently fork.  Same pattern as ``treasury_rebase_applied``.
        self.rolling_fee_burn_seeded: bool = False

        # Validator-registration-burn hard fork
        # (VALIDATOR_REGISTRATION_BURN_HEIGHT): set of entity_ids that
        # have paid the one-time registration burn OR were grandfathered
        # in at activation.  Consult this on every stake-tx apply path:
        #   * post-activation, if stx.entity_id not in this set, charge
        #     VALIDATOR_REGISTRATION_BURN against the entity's balance
        #     (reducing total_supply + incrementing total_burned) and
        #     add the entity to this set.
        #   * if the entity IS in the set, no burn — Option A: once
        #     registered, always registered.  A full-unstake / re-stake
        #     cycle does NOT re-burn.
        #
        # Consensus-visible state.  Snapshotted alongside balances /
        # staked for reorg safety and committed to the state root (see
        # state_snapshot.py _TAG_REGISTERED_VALIDATORS).  Pre-activation
        # the set stays empty and the apply-path gate is a no-op, so
        # legacy chain state is reproducible byte-for-byte.
        self.registered_validators: set[bytes] = set()

        # One-shot grandfather flag for the registration-burn fork:
        # flipped True the first time _apply_registration_grandfather
        # runs at VALIDATOR_REGISTRATION_BURN_HEIGHT.  Same reorg-safety
        # pattern as ``treasury_rebase_applied`` — snapshotted with the
        # set so a failed reorg that un-applies the grandfather block
        # also un-flips the flag, letting the canonical replay re-run
        # the migration cleanly.
        self.grandfather_applied: bool = False

        # Current-block-height tunnel: set by _apply_block_state at
        # block start so pay_fee_with_burn can gate its split without
        # every call site threading an explicit block_height parameter.
        # Reset to None after the block applies — any stray call
        # outside a block-apply window (off-chain audit, legacy test)
        # sees None and takes the pre-fork full-burn path.
        #
        # Consensus-visibility: this field is NEVER the authoritative
        # source of a block's height — compute_post_state_root and
        # _apply_block_state read the block header directly when they
        # need the height.  The tunnel is only a convenience channel
        # for the many pay_fee_with_burn call sites so we don't have
        # to plumb block_height through every validation helper.
        # Explicit block_height= kwargs on pay_fee_with_burn still
        # win; the tunnel is a fallback only.
        self._current_block_height: int | None = None

        # Dormancy-controller hard fork (DORMANCY_CONTROLLER_HEIGHT,
        # Tier 47): per-entity last-activity height for the dormancy
        # filter that drives compute_active_supply().  Bumped by
        # bump_active() on every signed action by the entity (outgoing
        # tx, attestation, block proposal — incoming transfers do NOT
        # count, by design, so an attacker can't keep dormant wallets
        # "active" by sending dust).
        #
        # Consensus-visible state: folded into _leaf_value() at and
        # above DORMANCY_CONTROLLER_HEIGHT (height-gated so pre-fork
        # leaf hashes are byte-identical to the legacy format), and
        # snapshotted alongside balances for reorg safety.  Persisted
        # to chaindb so cold restart rehydrates the same dormancy
        # state — without persistence a restart would zero every
        # entry and active_supply would silently collapse to 0 on
        # the restarted node, forking consensus at the next mint.
        #
        # Lifecycle: empty pre-activation.  At
        # DORMANCY_CONTROLLER_HEIGHT, ``_apply_dormancy_backfill``
        # stamps every existing balance-holder with the activation
        # height in one shot (idempotent flag below).  From then on,
        # bump_active() updates entries in lockstep with apply-path
        # activity; entries are never deleted (dormant balances stay
        # in the dict at their last-active-height value forever, so
        # the dormancy filter can recompute their weight on demand).
        self.last_active_heights: dict[bytes, int] = {}

        # One-shot guard for the activation backfill at
        # DORMANCY_CONTROLLER_HEIGHT.  Same pattern as
        # ``treasury_rebase_applied`` and ``grandfather_applied``:
        # snapshotted with the supply state for reorg safety so a
        # reorg past the activation block un-flips this flag and
        # the canonical replay re-fires the backfill cleanly.
        self.dormancy_backfill_applied: bool = False

    def get_balance(self, entity_id: bytes) -> int:
        """Get spendable (non-staked) balance."""
        return self.balances.get(entity_id, 0)

    def get_staked(self, entity_id: bytes) -> int:
        return self.staked.get(entity_id, 0)

    # ─── Dormancy controller (Tier 47, DORMANCY_CONTROLLER_HEIGHT) ──
    #
    # Three primitives drive the post-fork supply-replenishing
    # controller:
    #
    #   1. bump_active(eid, height) — record an entity's signed action
    #   2. compute_active_supply(current_height) — dormancy-filtered Σ
    #   3. compute_dormancy_issuance(current_height) — controller mint
    #
    # All three are pure functions of (in-memory state, current_height)
    # and contain no I/O, so they are safe to call from both the sim
    # path (compute_post_state_root) and the apply path
    # (_apply_block_state) — sim/apply stay in lockstep automatically,
    # mirroring the calculate_block_reward pattern above.

    def bump_active(self, entity_id: bytes, height: int) -> None:
        """Record that ``entity_id`` was active at ``height``.

        Monotonic: a later height always wins.  An equal-height bump
        is a no-op (an entity active at h is still active at h, no
        meaningful state change).  An earlier-height bump is silently
        ignored — this guards against an out-of-order reorg replay
        accidentally rolling activity backwards; the canonical replay
        always sees the highest height for any given (entity, action)
        pair last.

        Pre-activation callers can invoke this freely — the dict
        accumulates state, but nothing reads it until
        compute_active_supply() is called from a post-activation gate
        in calculate_block_reward().  Cheap to call unconditionally.

        Mirrors the bump into the chaindb ``entity_last_active`` table
        when ``self.db`` is set (production path).  Without persistence
        a cold restart would zero every entry and active_supply would
        silently collapse on the restarted node, forking consensus at
        the next mint.  Test contexts that don't set ``self.db``
        skip the mirror — the in-memory dict is sufficient there.
        """
        prev = self.last_active_heights.get(entity_id, 0)
        if height > prev:
            self.last_active_heights[entity_id] = height
            if self.db is not None:
                self.db.set_last_active_height(entity_id, height)

    def _dormancy_weight_bps(self, age: int) -> int:
        """Integer-deterministic dormancy weight in basis points.

        Helper for compute_active_supply().  Pulled out so the taper
        math is independently unit-testable without constructing a
        full balance state.  See CLAUDE.md anchor for the smooth-
        taper rationale (avoid a cliff at exactly WINDOW that would
        flip a balance from 100% active to 0% in one block).

            age <  WINDOW - TAPER     → 10_000 (full active)
            WINDOW - TAPER ≤ age < WINDOW → linear interp 10_000 → 0
            age ≥ WINDOW              → 0 (fully dormant)

        Negative ``age`` (last_active is in the future, normally
        impossible) clamps to 0 — defensive only, the apply path
        never produces this state because bump_active is monotonic
        and is called BEFORE the height advances.
        """
        if age < 0:
            return 10_000
        cliff = DORMANCY_WINDOW_BLOCKS - DORMANCY_TAPER_BLOCKS
        if age < cliff:
            return 10_000
        if age >= DORMANCY_WINDOW_BLOCKS:
            return 0
        # Linear taper: at age == cliff weight is 10_000, at age ==
        # WINDOW weight is 0.  Integer math is exact at endpoints
        # because (WINDOW - age) at age==cliff is TAPER, and
        # 10_000 * TAPER // TAPER == 10_000.
        return (10_000 * (DORMANCY_WINDOW_BLOCKS - age)) // DORMANCY_TAPER_BLOCKS

    def compute_active_supply(self, current_height: int) -> int:
        """Sum of balances weighted by recency-of-activity.

        Iterates ``self.balances`` once.  An entity's contribution to
        active_supply is ``balance * weight_bps // 10_000`` where the
        weight is computed from ``current_height - last_active``.  An
        entity whose ``last_active_heights`` entry is missing
        (genesis-era balance never bumped, or the missing default
        case) is treated as last-active=0, i.e. potentially fully
        dormant — but the activation backfill at
        DORMANCY_CONTROLLER_HEIGHT seeds every existing balance-
        holder so this default only affects pre-activation callers
        and post-activation entities that received tokens but never
        signed an outgoing action (which is exactly the lost-keys
        case the dormancy filter is meant to detect).

        Staked balances are also weighted: staking IS activity at the
        time it happens (the entity signed a stake tx, bumping
        last_active), but a staker who hasn't signed anything since
        — no attestations, no proposals, no rotations — eventually
        falls out of active_supply just like a regular hodler.  In
        practice no live validator goes that long without attesting.

        Pre-activation callers (block_height < DORMANCY_CONTROLLER_HEIGHT)
        can still call this — it returns a meaningful value based on
        whatever bump_active calls have happened — but the returned
        value is NOT consensus-critical pre-fork because
        calculate_block_reward gates the controller on the activation
        height.
        """
        total: int = 0
        # Sum spendable + staked: staked balances are real tokens
        # that should count toward active_supply when their owner is
        # active.  See _treat_stake_as_active rationale in CLAUDE.md.
        #
        # TREASURY_ENTITY_ID is excluded: the treasury is governance
        # state, not a live economic user.  CLAUDE.md anchors active
        # supply on holders whose "stake/attestation/proposal activity
        # counts as active without a transfer" — the treasury produces
        # none of those signals, so absent this skip its 40M balance
        # would forever be max-weighted (the activation backfill stamps
        # it active at fork height, and the only thing that demotes a
        # stamped entity is going DORMANCY_WINDOW_BLOCKS without any
        # activity, which the treasury's perpetual existence guarantees
        # never happens).  At mainnet's exact founder=100M + treasury=40M
        # = GENESIS_SUPPLY = DORMANCY_TARGET_ACTIVE_SUPPLY shape, that
        # would peg gap=0 and force the controller to mint 0/block for
        # ~25 years post-Tier-47 activation, breaking the validator-
        # profitability and stable-active-supply anchors simultaneously.
        for eid, balance in self.balances.items():
            if balance <= 0:
                continue
            if eid == TREASURY_ENTITY_ID:
                continue
            last_active = self.last_active_heights.get(eid, 0)
            age = current_height - last_active
            weight_bps = self._dormancy_weight_bps(age)
            if weight_bps == 0:
                continue
            if weight_bps == 10_000:
                total += balance
            else:
                total += (balance * weight_bps) // 10_000
        for eid, staked in self.staked.items():
            if staked <= 0:
                continue
            if eid == TREASURY_ENTITY_ID:
                continue
            last_active = self.last_active_heights.get(eid, 0)
            age = current_height - last_active
            weight_bps = self._dormancy_weight_bps(age)
            if weight_bps == 0:
                continue
            if weight_bps == 10_000:
                total += staked
            else:
                total += (staked * weight_bps) // 10_000
        return total

    def compute_dormancy_issuance(self, current_height: int) -> int:
        """Per-block issuance under the Tier 47 controller.

        Replaces calculate_block_reward at and above
        DORMANCY_CONTROLLER_HEIGHT.  Computed as

            gap = max(0, TARGET - active_supply(current_height))
            issuance = min(MAX_ISSUANCE_PER_BLOCK,
                           gap * K_NUM // K_DEN)

        At target (active_supply ≥ TARGET) the gap is zero and the
        controller mints zero — validators run on fees alone, which is
        the long-term design intent (the fee market is the security
        budget; issuance's purpose is supply integrity, not pay).

        Caller (calculate_block_reward) is responsible for the
        height-gate: pre-DORMANCY_CONTROLLER_HEIGHT this function is
        not invoked, so legacy halving + deflation-floor behavior is
        preserved byte-for-byte for re-validation of historical
        blocks.
        """
        active = self.compute_active_supply(current_height)
        gap = DORMANCY_TARGET_ACTIVE_SUPPLY - active
        if gap <= 0:
            return 0
        raw_issuance = (gap * DORMANCY_CONTROLLER_K_NUM) // DORMANCY_CONTROLLER_K_DEN
        return min(DORMANCY_MAX_ISSUANCE_PER_BLOCK, raw_issuance)

    def calculate_block_reward(self, block_height: int) -> int:
        """
        Calculate block reward with halving schedule.

        Reward halves every HALVING_INTERVAL blocks. The floor is
        BLOCK_REWARD_FLOOR (not 1), keeping validation lucrative
        even after all halvings complete.

        Supply-responsive issuance floor evolution — two hard forks:

        v1 (DEFLATION_FLOOR_HEIGHT): when total_supply < TARGET, reward
        doubles.  Retained byte-for-byte below DEFLATION_FLOOR_V2_HEIGHT
        so v1-era blocks remain re-validatable.

        v2 (DEFLATION_FLOOR_V2_HEIGHT, fee-responsive rebate): the
        fixed 2× multiplier was ~31× too small to arrest real burn
        rates.  Replaced with
            reward = max(base_reward,
                         rolling_burn_rate
                         * DEFLATION_REBATE_BPS // 10_000)
        where rolling_burn_rate = (sum of fee burns in the trailing
        DEFLATION_REBATE_WINDOW_BLOCKS window) / window.  At 70% rebate
        the new issuance offsets most of the burn without eliminating
        the deflationary incentive entirely.  Prune of expired entries
        is inline so the rolling list stays bounded.

        Strictly-less-than on the floor: supply == floor exactly means
        "recovered, no boost".  Self-correcting — once supply recovers
        above the floor the next block returns to the unboosted
        schedule.

        Pre-activation: boost never applies; byte-for-byte identical
        to the legacy reward curve.

        Consensus-critical: this helper is the single source of
        truth called by both the sim path (compute_post_state_root)
        and the apply path (_apply_block_state / mint_block_reward),
        so sim/apply stay in lockstep automatically.

        Tier 47 (DORMANCY_CONTROLLER_HEIGHT): at and above the
        activation height the controller short-circuits halving +
        deflation-floor entirely.  Issuance is governed solely by
        the gap between TARGET_ACTIVE_SUPPLY and the dormancy-
        filtered active_supply.  Pre-activation behavior is
        unchanged byte-for-byte (the legacy schedule below is the
        sole code path).
        """
        if block_height >= DORMANCY_CONTROLLER_HEIGHT:
            return self.compute_dormancy_issuance(block_height)
        return self._calculate_legacy_block_reward(block_height)

    def _calculate_legacy_block_reward(self, block_height: int) -> int:
        """Pre-Tier-47 halving + deflation-floor schedule.

        Extracted from calculate_block_reward so re-validation paths
        for pre-fork blocks (and legacy regression tests) can invoke
        the legacy formula directly without depending on the post-
        fork dispatch gate.  Behavior is byte-for-byte identical to
        the original calculate_block_reward body — the function name
        was renamed to make the legacy/post-fork split explicit.
        """
        halvings = block_height // HALVING_INTERVAL
        reward = BLOCK_REWARD >> halvings  # integer division by 2^halvings
        reward = max(BLOCK_REWARD_FLOOR, reward)
        supply_below_floor = (
            self.total_supply < TARGET_CIRCULATING_SUPPLY_FLOOR
        )
        if (
            block_height >= DEFLATION_FLOOR_V2_HEIGHT
            and supply_below_floor
        ):
            # v2 fee-responsive rebate.  Prune rolling window in-place,
            # then compute burn_rate = sum / window.  The prune is
            # defensive; pay_fee_with_burn already keeps the list
            # bounded, but a cold-booted node whose snapshot carried a
            # not-yet-pruned window should still converge to the same
            # burn rate.
            window_start = block_height - DEFLATION_REBATE_WINDOW_BLOCKS
            self.rolling_fee_burn = [
                (h, a) for (h, a) in self.rolling_fee_burn
                if h >= window_start
            ]
            rolling_sum = sum(a for (_, a) in self.rolling_fee_burn)
            rolling_rate = rolling_sum // DEFLATION_REBATE_WINDOW_BLOCKS
            rebate_floor = (
                rolling_rate * DEFLATION_REBATE_BPS // 10_000
            )
            reward = max(reward, rebate_floor)
        elif (
            block_height >= DEFLATION_FLOOR_HEIGHT
            and supply_below_floor
        ):
            # v1 legacy 2× multiplier — applies only at heights in
            # [DEFLATION_FLOOR_HEIGHT, DEFLATION_FLOOR_V2_HEIGHT).
            reward *= DEFLATION_ISSUANCE_MULTIPLIER
        return reward

    def mint_block_reward(
        self,
        proposer_id: bytes,
        block_height: int,
        attester_committee: list[bytes] | None = None,
        bootstrap: bool = False,
    ) -> dict:
        """Mint the block reward: proposer share + committee slots.

        Design (see messagechain.consensus.attester_committee):
          * Proposer gets PROPOSER_REWARD_NUMERATOR/DENOMINATOR of the
            halvings-adjusted reward (subject to PROPOSER_REWARD_CAP).
          * Each entity in `attester_committee` gets
            ATTESTER_REWARD_PER_SLOT tokens.  Committee is pre-selected
            by the caller (Blockchain._apply_block_state) using
            select_attester_committee() — this method does not know
            about seed identity or bootstrap_progress; it only credits.
          * Unfilled committee slots (attester_pool_tokens > len(committee))
            send the excess to the treasury, same pattern as
            PROPOSER_REWARD_CAP overflow.
          * If proposer is also in the committee, their combined
            earnings are subject to the cap; overage is clawed back
            from the attester credit and redirected to the treasury.

        `attester_committee=None` or empty → proposer gets the full
        reward (minus cap overflow); used for genesis / bootstrap
        blocks where no attestations exist yet.
        """
        from messagechain.consensus.attester_committee import (
            ATTESTER_REWARD_PER_SLOT,
        )

        reward = self.calculate_block_reward(block_height)
        self.total_supply += reward
        self.total_minted += reward

        # Per-block cap on combined proposer earnings.
        #
        # Pre-PROPOSER_CAP_HALVING_HEIGHT (Tier 19): the cap is the
        # import-time constant `PROPOSER_REWARD_CAP` (=4 with the
        # default constants).  This silently turns OFF once the
        # halving schedule drives reward down to BLOCK_REWARD_FLOOR=4
        # — at floor era a mega-staker can earn proposer_share(1) +
        # attester_pool(3) = 4 = cap, no clawback ever fires.
        #
        # Post-activation: recompute the cap from the actual reward
        # at this height so it stays at exactly
        # `PROPOSER_REWARD_NUMERATOR / DENOMINATOR` of issuance across
        # all halving eras.  At BLOCK_REWARD=16 this is unchanged
        # (cap=4); after the first halving it tightens to 2; at floor
        # it tightens to 1 — the mega-staker capture is properly
        # bounded forever.
        #
        # Bootstrap path is orthogonal: when no validator has staked
        # yet, the whole reward goes to the proposer regardless of
        # cap (genesis incentive).
        if bootstrap:
            effective_cap = reward
        elif block_height >= PROPOSER_CAP_HALVING_HEIGHT:
            effective_cap = (
                reward * PROPOSER_REWARD_NUMERATOR
                // PROPOSER_REWARD_DENOMINATOR
            )
        else:
            effective_cap = PROPOSER_REWARD_CAP

        # Proposer + attester pool split.
        proposer_share = reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
        attester_pool = reward - proposer_share

        # ATTESTER_FEE_FUNDING_HEIGHT hard fork: merge the per-block
        # fee-funded accumulator into the attester_pool BEFORE pro-rata
        # division.  The accumulated share is neither minted here nor
        # in pay_fee_with_burn — it's a redirect (tokens that would
        # have burned, now accrue to the committee).  Supply totals
        # are therefore NOT adjusted at this step; consumption simply
        # drains the accumulator into the committee's balances via
        # the pro-rata loop below.  The accumulator is zeroed AFTER
        # consumption so a re-apply of the same block (reorg replay)
        # sees the same freshly-computed value.
        #
        # Gate is strictly on block_height — pre-activation the
        # accumulator is always 0 (guarded in pay_fee_with_burn) but
        # we defend-in-depth by skipping the merge too, so a
        # hypothetical nonzero accumulator at a pre-fork height can't
        # leak into legacy-mode mint results.
        fee_funded_attester_bonus = 0
        if block_height >= ATTESTER_FEE_FUNDING_HEIGHT:
            fee_funded_attester_bonus = self.attester_fee_pool_this_block
            attester_pool += fee_funded_attester_bonus

        # No committee: proposer absorbs the whole reward.  Previously
        # the cap fired here and siphoned the difference into the
        # treasury, which was surprising (treasury accumulated purely
        # because no attesters existed yet — not because governance
        # directed funds there).  The cap protects against a mega-
        # staker capturing disproportionate reward in a MULTI-validator
        # committee; with no committee the proposer IS all the work,
        # so no cap applies.
        #
        # Post-ATTESTER_FEE_FUNDING_HEIGHT note: the fee-funded
        # accumulator (if any) has been merged into attester_pool
        # above but there is no committee to pay.  The accumulator
        # tokens are in total_supply (pay_fee_with_burn redirected
        # them away from burn) but unassigned.  Burn them here to
        # match the no-committee case's "no attester tokens accrue"
        # semantics and to avoid unassigned inflation.  In practice
        # this path is genesis / bootstrap-only and fees at those
        # heights are effectively zero, so the burn is a defensive
        # no-op in all realistic deployments.
        if not attester_committee:
            proposer_reward = reward
            self.balances[proposer_id] = (
                self.balances.get(proposer_id, 0) + proposer_reward
            )
            leaked_burn = 0
            if fee_funded_attester_bonus > 0:
                self.total_supply -= fee_funded_attester_bonus
                self.total_burned += fee_funded_attester_bonus
                leaked_burn = fee_funded_attester_bonus
                self.attester_fee_pool_this_block = 0
            return {
                "total_reward": reward,
                "proposer_reward": proposer_reward,
                "total_attestor_reward": 0,
                "attestor_rewards": {},
                "treasury_excess": 0,
                "burned": leaked_burn,
            }

        # Reward-distribution policy gate.  Pre-activation (legacy):
        # cap the PAID committee at what the pool can afford at 1 token
        # per slot — remaining committee members truncate to 0.  This
        # permanently caps paid slots at BLOCK_REWARD_FLOOR // 4 == 3
        # once halvings drive reward to the floor, which is a
        # structural decentralization failure.  Post-activation: divide
        # the full attester_pool pro-rata across the full committee,
        # integer-division remainder burns.  If the committee is larger
        # than the pool, per-slot rounds to zero and the whole pool
        # burns — the committee still attests for finality-weight
        # credit, reward is a bonus not a gate on participation.
        attestor_rewards: dict[bytes, int] = {}
        attester_tokens_paid = 0
        if block_height >= ATTESTER_REWARD_SPLIT_HEIGHT:
            paid_committee = list(attester_committee)
            n = len(paid_committee)
            # n == 0 is unreachable here because the early `if not
            # attester_committee` branch above already returns, but be
            # defensive so a future refactor can't silently divide by
            # zero.
            per_slot_reward = (attester_pool // n) if n > 0 else 0

            # ATTESTER_REWARD_CAP_HEIGHT hard fork: enforce a per-
            # entity cap on epoch-cumulative attester earnings.  Reset
            # the rolling tracker if the block's epoch boundary differs
            # from what's recorded.  Cap is computed from THIS block's
            # attester_pool (a conservative per-block upper bound on
            # the epoch pool) — at attester_pool=512 and bps=100,
            # epoch=100, the cap is 512 tokens/entity/epoch.  Overflow
            # burns.
            from messagechain.config import (
                ATTESTER_REWARD_CAP_HEIGHT,
                ATTESTER_CAP_FIX_HEIGHT,
                PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH,
                FINALITY_INTERVAL,
            )
            cap_active = block_height >= ATTESTER_REWARD_CAP_HEIGHT
            cap_fix_active = block_height >= ATTESTER_CAP_FIX_HEIGHT
            # REWARD_CURVE_HEIGHT (Tier 20): apply per-attester
            # multiplier based on stake share before the per-entity
            # cap.  Curve runs first so the cap remains a strict
            # upper bound — mid-tier validators (multiplier > 1) hit
            # the cap faster, small validators (multiplier < 1) reach
            # it slower; neither can exceed cap_per_entity.  Pre-
            # activation: byte-for-byte identical to legacy (no
            # multiplier path executes).  Total active stake is read
            # from self.staked at mint time, which reflects the
            # post-block staking state — same value the sim mirror
            # in blockchain.py reads from sim_staked.
            curve_active = block_height >= REWARD_CURVE_HEIGHT
            # Tier 37 — saturating-large band: at heights >=
            # REWARD_CURVE_LARGE_BAND_HEIGHT, swap in
            # `reward_curve_multiplier_v2` which interpolates the
            # multiplier linearly from 1.0 down to LARGE_FLOOR between
            # LARGE_THRESHOLD and LARGE_FLOOR_THRESHOLD.  Pre-Tier-37
            # callers continue to invoke the legacy helper byte-for-
            # byte; replay determinism preserved.
            curve_v2_active = block_height >= REWARD_CURVE_LARGE_BAND_HEIGHT
            # Tier 40 — smooth concave curve: at heights >=
            # REWARD_CURVE_SMOOTH_HEIGHT, swap in
            # `reward_curve_multiplier_v3` which replaces the entire
            # piecewise shape with a single rational function.  Per-unit
            # yield diminishes monotonically from PEAK at near-zero
            # stake toward FLOOR as stake grows large; absolute reward
            # remains strictly increasing in stake (so adding stake
            # always pays more).  Pre-Tier-40 callers continue to
            # invoke v2 (or v1 below v2's height) byte-for-byte; replay
            # determinism preserved across the entire fork ladder.
            curve_v3_active = block_height >= REWARD_CURVE_SMOOTH_HEIGHT
            # Tier 42 — smooth-curve V2 retune: at heights >=
            # REWARD_CURVE_SMOOTH_V2_HEIGHT, swap in
            # `reward_curve_multiplier_v4` which uses the same rational
            # form as v3 with retuned constants (PEAK=130, FLOOR=80,
            # SCALE_BPS=1000) — anchored shape preserved, only the
            # tuning knobs change.  Lifts the bootstrap-era multiplier
            # at 50% stake from ~0.46× (v3) to ~0.88× so the attester
            # pool isn't ~half-burned every block during bootstrap.
            # Pre-Tier-42 callers continue to invoke v3 byte-for-byte;
            # replay determinism preserved across the fork ladder.
            curve_v4_active = block_height >= REWARD_CURVE_SMOOTH_V2_HEIGHT
            total_active_stake = (
                sum(self.staked.values()) if curve_active else 0
            )
            cap_per_entity = 0
            if cap_active:
                epoch_start = (
                    (block_height // FINALITY_INTERVAL) * FINALITY_INTERVAL
                )
                if self.attester_epoch_earnings_start != epoch_start:
                    self.attester_epoch_earnings_start = epoch_start
                    self.attester_epoch_earnings = {}
                # Per-entity cap, in TOKENS, for the full epoch.
                #
                # Pre-ATTESTER_CAP_FIX_HEIGHT (broken): uses
                # attester_pool post-fee-merge, which includes the
                # fee-funded component and flips 500× between high-
                # fee and low-fee blocks in the same epoch.  Path-
                # dependent.  Preserved byte-for-byte for heights
                # strictly below the fix activation.
                #
                # Post-ATTESTER_CAP_FIX_HEIGHT (fix): uses the
                # issuance-only component (reward - proposer_share),
                # which is a deterministic function of block_height
                # via calculate_block_reward.  Stable across fee
                # variation, predictable, path-independent.  At
                # BLOCK_REWARD=16 the cap is 12 tokens/entity/epoch;
                # at floor era (reward=4) it's 3 — both small but
                # predictable.
                cap_pool_basis = (
                    (reward - proposer_share)
                    if cap_fix_active
                    else attester_pool
                )
                # Tier 45 — per-validator attester cap retune.  At and
                # above PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT the bps
                # constant lifts from 100 (1%) to 5000 (50%) so today's
                # 2-validator committee doesn't cap-and-burn at block 3
                # of every 100-block epoch.  Pre-fork path is byte-
                # identical to the legacy 100 bps read.
                cap_bps = _attester_cap_bps_per_epoch(block_height)
                cap_per_entity = (
                    cap_pool_basis
                    * cap_bps
                    * FINALITY_INTERVAL
                    // 10_000
                )

            for eid in paid_committee:
                reward_amount = per_slot_reward
                # REWARD_CURVE_HEIGHT (Tier 20): apply piecewise-
                # constant multiplier based on this attester's stake
                # share of total active stake.  Defensive zero-stake
                # short-circuit: if the network has no stake at all,
                # bps is undefined and we fall back to baseline (1/1)
                # — same effect as legacy.  per_slot_reward == 0 is
                # also a no-op (multiplier on 0 is 0).
                if curve_active and per_slot_reward > 0 and total_active_stake > 0:
                    stake_bps = (
                        self.staked.get(eid, 0) * 10_000
                        // total_active_stake
                    )
                    if curve_v4_active:
                        num, den = reward_curve_multiplier_v4(stake_bps)
                    elif curve_v3_active:
                        num, den = reward_curve_multiplier_v3(stake_bps)
                    elif curve_v2_active:
                        num, den = reward_curve_multiplier_v2(stake_bps)
                    else:
                        num, den = reward_curve_multiplier(stake_bps)
                    reward_amount = reward_amount * num // den
                if cap_active and per_slot_reward > 0:
                    earned = self.attester_epoch_earnings.get(eid, 0)
                    available = cap_per_entity - earned
                    if available < 0:
                        available = 0
                    reward_amount = min(reward_amount, available)
                    # Bookkeeping: track credited amount (pre-cap
                    # overflow) so the tracker reflects ACTUAL
                    # earnings, not paid-intent.
                    self.attester_epoch_earnings[eid] = earned + reward_amount
                attestor_rewards[eid] = (
                    attestor_rewards.get(eid, 0) + reward_amount
                )
                if reward_amount > 0:
                    self.balances[eid] = (
                        self.balances.get(eid, 0) + reward_amount
                    )
                attester_tokens_paid += reward_amount
        else:
            # Legacy path: first `max_slots` committee members paid 1
            # token each, rest truncated.  Preserved byte-for-byte for
            # any height strictly below ATTESTER_REWARD_SPLIT_HEIGHT so
            # the fork is cleanly reversible and pre-fork blocks remain
            # re-validatable.
            max_slots = attester_pool // ATTESTER_REWARD_PER_SLOT
            paid_committee = list(attester_committee)[:max_slots]
            for eid in paid_committee:
                attestor_rewards[eid] = (
                    attestor_rewards.get(eid, 0) + ATTESTER_REWARD_PER_SLOT
                )
                self.balances[eid] = (
                    self.balances.get(eid, 0) + ATTESTER_REWARD_PER_SLOT
                )
                attester_tokens_paid += ATTESTER_REWARD_PER_SLOT

        # Unfilled slots + any cap overflow BURN — reduce total_supply
        # rather than credit the treasury.  Rationale: the treasury is
        # a governance-controlled pool; auto-crediting it without a
        # vote is not how governance-spent funds should accumulate.
        # Burning any "earmarked but unpaid" reward keeps the active-
        # participation invariant intact: tokens in circulation were
        # earned by a validator who did real work, the rest is
        # deflationary.
        #
        # REWARD_CURVE_HEIGHT (Tier 20): the per-attester multiplier
        # can push `attester_tokens_paid` either side of `attester_
        # pool`.  Under-allocation (small-band-heavy committee) keeps
        # the legacy semantic: pool minus actual = burned.  Over-
        # allocation (mid-band-heavy committee) is curve-driven mint:
        # the excess is added to total_supply / total_minted as a
        # net new issuance.  Pre-Tier-20 the over-allocation case is
        # unreachable because `attester_tokens_paid ≤ attester_pool`
        # always held, so this branch is byte-for-byte identical to
        # legacy at heights below activation.
        if attester_tokens_paid > attester_pool:
            curve_mint_extra = attester_tokens_paid - attester_pool
            self.total_supply += curve_mint_extra
            self.total_minted += curve_mint_extra
            burned = 0
        else:
            burned = attester_pool - attester_tokens_paid

        # Proposer-cap check: in a multi-validator committee, the
        # proposer's combined earnings (proposer share + committee
        # slot if they're on it) must not exceed effective_cap.  This
        # prevents a mega-staker from capturing disproportionate
        # reward when they both propose AND sit on the committee.
        # Trim attester credit first (smaller), then proposer share.
        # Trimmed tokens BURN (previously flowed to treasury).
        proposer_att_reward = attestor_rewards.get(proposer_id, 0)
        proposer_total = proposer_share + proposer_att_reward
        if proposer_total > effective_cap:
            self.balances[proposer_id] = (
                self.balances.get(proposer_id, 0) - proposer_att_reward
            )
            attestor_rewards[proposer_id] = 0
            burned += proposer_att_reward
            # ATTESTER_REWARD_CAP_HEIGHT: a PROPOSER_REWARD_CAP
            # clawback of the proposer's committee slot must ALSO
            # reverse the epoch-earnings tracker entry — the
            # proposer never actually retained those tokens, so
            # they should not count against the per-entity cap in
            # subsequent blocks.  Pre-cap-activation the tracker is
            # empty so this is a no-op.
            if proposer_att_reward > 0 and (
                self.attester_epoch_earnings.get(proposer_id, 0) > 0
            ):
                self.attester_epoch_earnings[proposer_id] = max(
                    0,
                    self.attester_epoch_earnings[proposer_id]
                    - proposer_att_reward,
                )
            proposer_att_reward = 0
            if proposer_share > effective_cap:
                burned += proposer_share - effective_cap
                proposer_share = effective_cap

        self.balances[proposer_id] = (
            self.balances.get(proposer_id, 0) + proposer_share
        )
        if burned > 0:
            # Supply-reduction: undo the mint for the unpaid portion.
            # Both totals must move to keep the net-inflation invariant
            # (total_supply == GENESIS_SUPPLY + total_minted - total_burned).
            self.total_supply -= burned
            self.total_burned += burned

        # ATTESTER_FEE_FUNDING_HEIGHT: drain the accumulator now that
        # its contents have been credited (pro-rata) or burned
        # (remainder / cap-overflow).  Zeroing here — not at block
        # start — means the mint step is idempotent within a single
        # block apply: consuming the accumulator leaves nothing for
        # a following code path to double-spend.  _apply_block_state
        # also resets fee_burn_this_block and attester_fee_pool_this_
        # block to 0 at block-start so a re-apply of the same block
        # produces the same consumption amount deterministically.
        if fee_funded_attester_bonus > 0:
            self.attester_fee_pool_this_block = 0

        return {
            "total_reward": reward,
            "proposer_reward": proposer_share,
            "total_attestor_reward": attester_tokens_paid,
            "attestor_rewards": attestor_rewards,
            "treasury_excess": 0,
            "burned": burned,
        }

    def pay_fee(self, from_id: bytes, to_proposer_id: bytes, fee: int) -> bool:
        """Transfer fee from sender to block proposer."""
        if fee < MIN_FEE:
            return False
        if self.get_balance(from_id) < fee:
            return False
        self.balances[from_id] -= fee
        self.balances[to_proposer_id] = self.balances.get(to_proposer_id, 0) + fee
        self.total_fees_collected += fee
        return True

    def pay_fee_with_burn(
        self,
        from_id: bytes,
        to_proposer_id: bytes,
        fee: int,
        base_fee: int,
        block_height: int | None = None,
    ) -> bool:
        """Pay a transaction fee with EIP-1559-style base fee burning.

        The base_fee portion is burned (permanently removed from supply).
        The remainder (tip = fee - base_fee) goes to the block proposer.
        Returns False if fee < base_fee or sender can't afford it.

        ``block_height`` activates the ATTESTER_FEE_FUNDING_HEIGHT hard
        fork: post-activation, `ATTESTER_FEE_SHARE_BPS / 10_000` of the
        base_fee is diverted into `attester_fee_pool_this_block` (a
        per-block accumulator consumed by `mint_block_reward`) instead
        of being burned.  The remainder still burns.  Pre-activation,
        or when ``block_height is None`` (off-chain audit / legacy test
        paths that pre-date the fork), 100% of base_fee burns as
        before — byte-for-byte-identical to the pre-fork code path.
        """
        if fee < base_fee:
            return False
        if self.get_balance(from_id) < fee:
            return False

        # Hard-fork split: post-ATTESTER_FEE_FUNDING_HEIGHT the base_fee
        # is split into an attester-pool share (accrued into the per-
        # block accumulator, consumed by mint_block_reward below) and
        # a burn share (destroyed as before).  block_height=None falls
        # back to the self._current_block_height tunnel that
        # Blockchain._apply_block_state sets at block start; when that
        # too is None the full-burn legacy path is used (mirror of
        # verify_transaction(current_height=None)).
        effective_height = (
            block_height
            if block_height is not None
            else self._current_block_height
        )
        attester_share = 0
        if (
            effective_height is not None
            and effective_height >= ATTESTER_FEE_FUNDING_HEIGHT
        ):
            attester_share = base_fee * ATTESTER_FEE_SHARE_BPS // 10_000
        actual_burn = base_fee - attester_share

        tip = fee - base_fee
        self.balances[from_id] -= fee
        self.balances[to_proposer_id] = self.balances.get(to_proposer_id, 0) + tip
        # Only the non-diverted portion reduces total_supply / bumps
        # total_burned.  The attester share stays in circulation (it
        # will be credited to committee members when mint_block_reward
        # runs).
        if actual_burn > 0:
            self.total_supply -= actual_burn
            self.total_burned += actual_burn
            # DEFLATION_FLOOR_V2_HEIGHT hard fork: accrue every
            # post-activation fee-burn into the rolling window that
            # drives the fee-responsive issuance rebate.  Pre-activation
            # the list stays empty (byte-for-byte legacy behavior).
            # Effective height for the gate mirrors the attester-fee
            # split above so an explicit block_height= kwarg still
            # wins over the tunnel.
            if (
                effective_height is not None
                and effective_height >= DEFLATION_FLOOR_V2_HEIGHT
            ):
                self.rolling_fee_burn.append(
                    (int(effective_height), int(actual_burn)),
                )
        if attester_share > 0:
            self.attester_fee_pool_this_block += attester_share
        # Fee-burn-only ticker: tracks the CURRENT block's fee-burn so
        # Blockchain._apply_block_state can redirect the configured
        # fraction into the archive-reward pool.  Post-fork this
        # reflects the POST-SPLIT burn amount (attester_share is not
        # burned and so is not a redirect candidate).  Not double-
        # counted — the redirect step subtracts from total_burned to
        # compensate.
        self.fee_burn_this_block += actual_burn
        self.total_fees_collected += fee
        return True

    def update_base_fee(
        self,
        parent_tx_count: int,
        current_height: int | None = None,
    ) -> int:
        """Adjust base fee based on parent block fullness (EIP-1559).

        If the parent block had more txs than the target block size, base
        fee increases. If fewer, it decreases. Max change per block is
        1/BASE_FEE_MAX_CHANGE_DENOMINATOR of the current base fee.

        ``current_height`` selects the post-fork target: at/after
        BLOCK_BYTES_RAISE_HEIGHT (Tier 9) the target is
        TARGET_BLOCK_SIZE_POST_RAISE (22, tracking the raised
        MAX_TXS_PER_BLOCK=45).  Default ``None`` preserves the legacy
        TARGET_BLOCK_SIZE=10 so pre-fork blocks and non-consensus call
        sites (e.g. isolated tests) retain their prior behavior.

        At/after MARKET_FEE_FLOOR_HEIGHT (Tier 16) the lower bound on
        base_fee drops to MARKET_FEE_FLOOR (=1) — the protocol fee
        floor collapses to a flat 1 token, so base_fee can decay to 1
        during quiet periods.  Pre-fork the lower bound stays at
        MIN_FEE (=100) for replay determinism.  The upper cap stays
        absolute (MIN_FEE × MAX_BASE_FEE_MULTIPLIER = 1_000_000) — it
        bounds pathological pricing in absolute tokens, not as a
        multiple of the floor.

        Returns the new base fee.
        """
        if current_height is not None and current_height >= BLOCK_BYTES_RAISE_HEIGHT:
            target = TARGET_BLOCK_SIZE_POST_RAISE
        else:
            target = TARGET_BLOCK_SIZE

        if parent_tx_count == target:
            return self.base_fee

        from messagechain.config import (
            MIN_FEE,
            MAX_BASE_FEE_MULTIPLIER,
            MARKET_FEE_FLOOR,
            MARKET_FEE_FLOOR_HEIGHT,
        )
        max_base_fee = MIN_FEE * MAX_BASE_FEE_MULTIPLIER
        if (
            current_height is not None
            and current_height >= MARKET_FEE_FLOOR_HEIGHT
        ):
            base_floor = MARKET_FEE_FLOOR
        else:
            base_floor = MIN_FEE
        if parent_tx_count > target:
            # Block was over target — increase base fee
            excess = parent_tx_count - target
            delta = self.base_fee * excess // (target * BASE_FEE_MAX_CHANGE_DENOMINATOR)
            # Upper bound on base_fee: without a cap, a determined attacker
            # willing to burn tokens on full blocks can compound +12.5% per
            # block indefinitely, permanently pricing out honest users even
            # after the attack stops (base_fee only drops 12.5% per
            # empty-target block on the way down, so recovery is symmetric
            # but a month-long attack leaves a month-long recovery tail).
            # Cap at MAX_BASE_FEE_MULTIPLIER × MIN_FEE — well above any
            # realistic organic fee but finite.
            self.base_fee = min(self.base_fee + max(1, delta), max_base_fee)
        else:
            # Block was under target — decrease base fee.  Mirror the
            # increase branch's max(1, delta): integer truncation of
            # (base_fee * deficit) // (target * denom) floors to 0
            # once base_fee gets small enough (e.g. base_fee=7,
            # target=22, denom=8 → 154 // 176 = 0), pinning base_fee
            # above the intended MARKET_FEE_FLOOR=1.  Force a minimum
            # 1-token step whenever the parent block was under target,
            # so quiet periods can decay base_fee all the way down to
            # the floor.
            deficit = target - parent_tx_count
            delta = max(1, self.base_fee * deficit // (target * BASE_FEE_MAX_CHANGE_DENOMINATOR))
            self.base_fee = max(base_floor, self.base_fee - delta)

        return self.base_fee

    def can_afford_fee(self, entity_id: bytes, fee: int) -> bool:
        return self.get_balance(entity_id) >= fee

    def stake(self, entity_id: bytes, amount: int) -> bool:
        """Lock tokens for validator staking."""
        if amount <= 0:
            return False
        if self.get_balance(entity_id) < amount:
            return False
        self.balances[entity_id] -= amount
        self.staked[entity_id] = self.staked.get(entity_id, 0) + amount
        return True

    def get_pending_unstake(self, entity_id: bytes) -> int:
        """Total tokens pending release for this entity."""
        return sum(amt for amt, _ in self.pending_unstakes.get(entity_id, []))

    def unstake(
        self,
        entity_id: bytes,
        amount: int,
        current_block: int = 0,
        total_staked_after_check: int | None = None,
        min_total_stake: int = MIN_TOTAL_STAKE,
        bootstrap_ended: bool = False,
    ) -> bool:
        """Queue staked tokens for unbonding.

        Tokens are removed from stake immediately but held in a pending
        state for UNBONDING_PERIOD blocks. During this time they can
        still be slashed but cannot be spent or re-staked.

        If bootstrap_ended is True, rejects unstakes that would drop
        total network stake below MIN_TOTAL_STAKE.
        """
        if amount <= 0:
            return False
        current_stake = self.get_staked(entity_id)
        if current_stake < amount:
            return False

        # M7: Per-validator minimum stake enforcement.
        # After unstaking, remaining stake must be either 0 (full exit)
        # or >= the current VALIDATOR_MIN_STAKE floor (still a valid
        # validator).  Hard-fork-gated via `get_validator_min_stake`:
        # pre-fork the legacy 100-token floor applies, post-fork the
        # raised 10_000-token floor.  Full exit (remaining == 0) is
        # ALWAYS permitted — legacy sub-floor validators retain the
        # escape hatch to unwind their grandfathered stake cleanly.
        from messagechain.config import get_validator_min_stake
        min_stake_floor = get_validator_min_stake(current_block)
        remaining = current_stake - amount
        if remaining > 0 and remaining < min_stake_floor:
            return False

        # Prevent total stake from dropping below safety floor
        if bootstrap_ended and total_staked_after_check is not None:
            if total_staked_after_check < min_total_stake:
                return False

        self.staked[entity_id] -= amount
        # Hard-fork-gated unbonding period: pre-activation uses the legacy
        # 1008-block window so historical chain state is reproducible;
        # at/after ``UNBONDING_PERIOD_EXTENSION_HEIGHT`` the longer
        # evidence-covering window applies so a validator cannot
        # equivocate, unstake, and outrun slow slashing evidence.
        # The per-entry release_block is baked in here and never mutated
        # later — in-flight unstakes queued pre-activation keep their
        # original (legacy) maturity even after the chain crosses the
        # activation height.  See messagechain/config.py.
        release_block = current_block + get_unbonding_period(current_block)
        if entity_id not in self.pending_unstakes:
            self.pending_unstakes[entity_id] = []
        self.pending_unstakes[entity_id].append((amount, release_block))
        if self.db is not None and hasattr(self.db, "add_pending_unstake"):
            self.db.add_pending_unstake(entity_id, amount, release_block)
        return True

    def process_pending_unstakes(self, current_block: int) -> int:
        """Release matured unstakes. Returns total tokens released."""
        total_released = 0
        db = self.db if hasattr(self, "db") else None
        for entity_id in list(self.pending_unstakes.keys()):
            pending = self.pending_unstakes[entity_id]
            still_pending = []
            for amount, release_block in pending:
                if current_block >= release_block:
                    self.balances[entity_id] = self.balances.get(entity_id, 0) + amount
                    total_released += amount
                    # Mirror the matured ticket's removal into the DB
                    # so a cold-booted node rehydrates a queue that
                    # matches what the running node just released.
                    if db is not None and hasattr(db, "clear_pending_unstake"):
                        db.clear_pending_unstake(entity_id, release_block)
                else:
                    still_pending.append((amount, release_block))
            if still_pending:
                self.pending_unstakes[entity_id] = still_pending
            else:
                del self.pending_unstakes[entity_id]
        return total_released

    def transfer(self, from_id: bytes, to_id: bytes, amount: int) -> bool:
        """Transfer tokens between entities.

        Treasury funds cannot be moved via normal transfers — only
        governance-approved treasury spends can debit the treasury.
        """
        if amount <= 0:
            return False
        if from_id == TREASURY_ENTITY_ID:
            return False
        if self.get_balance(from_id) < amount:
            return False
        self.balances[from_id] -= amount
        self.balances[to_id] = self.balances.get(to_id, 0) + amount
        return True

    def treasury_spend(
        self,
        recipient_id: bytes,
        amount: int,
        *,
        new_account_surcharge: int = 0,
        current_block: int | None = None,
    ) -> bool:
        """Move funds from treasury to recipient (governance-authorized only).

        This is the ONLY way to debit the treasury. Callers must ensure
        governance approval before invoking this method.

        If `new_account_surcharge > 0`, the recipient is brand-new (no
        on-chain state) and the treasury must additionally cover the
        surcharge, which is BURNED (not credited to the recipient).
        The recipient receives exactly `amount`; the treasury is debited
        by `amount + new_account_surcharge`, and the surcharge is added
        to total_burned.  If the treasury cannot cover
        `amount + new_account_surcharge`, the spend is rejected.

        **Spend-rate cap (hard fork, active at
        block_height >= TREASURY_REBASE_HEIGHT)**: a single epoch of
        TREASURY_SPEND_CAP_EPOCH_BLOCKS blocks may debit at most
        get_treasury_max_spend_bps_per_epoch(block_height) / 10_000 of
        the treasury balance (measured at spend time).  The cap is a
        hard gate — even a supermajority-approved governance proposal
        that would exceed it is rejected.  Callers that pass
        `current_block=None` (legacy tests, off-chain introspection)
        bypass the cap for back-compat, matching the legacy-rule
        pattern used by `verify_transaction(current_height=None)`.

        **Cap-tightening hard fork (block_height >=
        TREASURY_CAP_TIGHTEN_HEIGHT)**: in addition to the tightened
        per-epoch cap (100 bps -> 10 bps), an absolute annual ceiling
        of TREASURY_MAX_SPEND_BPS_PER_YEAR / 10_000 (5%) of the
        current treasury balance is enforced over a rolling
        TREASURY_SPEND_CAP_YEAR_BLOCKS (52,560 blocks ≈ 365.25 days)
        window.  BOTH caps must pass; either binding rejects the
        spend.  Pre-tightening the annual cap is effectively infinity.
        """
        if amount <= 0:
            return False
        if new_account_surcharge < 0:
            return False
        debit_total = amount + new_account_surcharge
        if self.get_balance(TREASURY_ENTITY_ID) < debit_total:
            return False

        # Per-epoch spend-rate cap (post-activation only).  Runs BEFORE
        # any balance mutation so a cap-rejected spend is a clean
        # no-op.  Imports deferred to avoid a config import cycle on
        # module load.
        cap_active = False
        annual_cap_active = False
        if current_block is not None:
            from messagechain.config import (
                TREASURY_REBASE_HEIGHT,
                TREASURY_SPEND_CAP_EPOCH_BLOCKS,
                TREASURY_CAP_TIGHTEN_HEIGHT,
                TREASURY_MAX_SPEND_BPS_PER_YEAR,
                TREASURY_SPEND_CAP_YEAR_BLOCKS,
                get_treasury_max_spend_bps_per_epoch,
            )
            if current_block >= TREASURY_REBASE_HEIGHT:
                cap_active = True
                epoch_start = (
                    current_block
                    // TREASURY_SPEND_CAP_EPOCH_BLOCKS
                    * TREASURY_SPEND_CAP_EPOCH_BLOCKS
                )
                if self._treasury_spend_epoch_start != epoch_start:
                    # New epoch — roll the rolling window forward.
                    self._treasury_spend_epoch_start = epoch_start
                    self._treasury_spend_debited_this_epoch = 0
                # Cap is a bps fraction of CURRENT treasury balance,
                # so as the treasury shrinks over time the cap shrinks
                # with it — no permanent "spend budget" frozen at fork
                # time.  Post-tighten the bps is 10 (0.1%); pre-tighten
                # it is the legacy 100 (1%).
                epoch_bps = get_treasury_max_spend_bps_per_epoch(
                    current_block,
                )
                treasury_balance = self.get_balance(TREASURY_ENTITY_ID)
                epoch_cap = (
                    treasury_balance
                    * epoch_bps
                    // 10_000
                )
                already = self._treasury_spend_debited_this_epoch
                if already + debit_total > epoch_cap:
                    return False

            # Annual rolling-window cap (cap-tightening hard fork).
            # Only enforced at/after TREASURY_CAP_TIGHTEN_HEIGHT; pre-
            # activation the annual ceiling is infinity so legacy
            # behavior is byte-preserved.  Checked AFTER the per-epoch
            # cap so the error mode is deterministic — per-epoch
            # violations fail first.  Prune happens unconditionally
            # once activated so operator-driven long pauses between
            # spends don't let an outdated stale entry re-enter the
            # window.
            if current_block >= TREASURY_CAP_TIGHTEN_HEIGHT:
                annual_cap_active = True
                window_start = current_block - TREASURY_SPEND_CAP_YEAR_BLOCKS
                self._treasury_spend_rolling_debits = [
                    (h, a) for (h, a) in self._treasury_spend_rolling_debits
                    if h >= window_start
                ]
                annual_debited = sum(
                    a for (_, a) in self._treasury_spend_rolling_debits
                )
                treasury_balance = self.get_balance(TREASURY_ENTITY_ID)
                annual_cap = (
                    treasury_balance
                    * TREASURY_MAX_SPEND_BPS_PER_YEAR
                    // 10_000
                )
                if annual_debited + debit_total > annual_cap:
                    return False

        self.balances[TREASURY_ENTITY_ID] -= debit_total
        self.balances[recipient_id] = self.balances.get(recipient_id, 0) + amount
        if new_account_surcharge > 0:
            self.total_supply -= new_account_surcharge
            self.total_burned += new_account_surcharge
        if cap_active:
            self._treasury_spend_debited_this_epoch += debit_total
        if annual_cap_active:
            self._treasury_spend_rolling_debits.append(
                (current_block, debit_total),
            )
        return True

    def burn_from_treasury(self, amount: int) -> bool:
        """Burn `amount` tokens out of the treasury balance.

        Used exclusively by the treasury-rebase hard fork
        (Blockchain._apply_treasury_rebase) to apply the one-shot
        33M burn at activation height.  Updates total_supply and
        total_burned to preserve the net-inflation invariant.

        Returns False if `amount` is non-positive or the treasury
        balance would underflow; neither failure mode should happen
        in normal operation because the fork constants are
        import-time-asserted to fit, but the guard is defense-in-depth
        against operator-replaced placeholder heights that happen to
        line up with a drained treasury.
        """
        if amount <= 0:
            return False
        if self.get_balance(TREASURY_ENTITY_ID) < amount:
            return False
        self.balances[TREASURY_ENTITY_ID] -= amount
        self.total_supply -= amount
        self.total_burned += amount
        return True

    def slash_validator(
        self,
        offender_id: bytes,
        finder_id: bytes,
        slash_pct: int = 100,
    ) -> tuple[int, int]:
        """
        Slash a validator: burn `slash_pct` of stake + pending unstakes,
        pay finder a reward proportional to what was burned.

        Pre-Tier 20 (default slash_pct=100): the full-burn path — every
        token in `staked` and every pending-unstake entry is wiped, and
        the offender is dropped from the validator set by the caller.

        Tier 20+ (slash_pct=SOFT_SLASH_PCT, typically 5): partial burn.
        Stake is reduced proportionally; each pending entry's amount is
        scaled by (1 - slash_pct/100) and rewritten in place; the
        offender retains the remaining stake and stays in the set
        (caller decides whether to mutate `slashed_validators`).  Pending
        unstakes stay in the slash basis on purpose — otherwise an
        equivocator could outrun evidence by unstaking immediately.

        Returns (total_slashed, finder_reward).
        """
        if not 0 < slash_pct <= 100:
            raise ValueError(
                f"slash_pct must be in (0, 100], got {slash_pct}"
            )

        staked_amount = self.staked.get(offender_id, 0)
        pending_amount = self.get_pending_unstake(offender_id)
        basis = staked_amount + pending_amount

        if basis == 0:
            return 0, 0

        # Compute per-bucket slash so rounding lands once per bucket
        # rather than redistributing a single combined slash —
        # otherwise a partial slash with stake=0 + pending=N would
        # have to drain pending, but a combined-then-apportioned path
        # would round it to staked=0 and lose the pending burn entirely.
        stake_burn = staked_amount * slash_pct // 100
        pending_burn = pending_amount * slash_pct // 100
        slashed_amount = stake_burn + pending_burn

        if slashed_amount == 0:
            return 0, 0

        finder_reward = slashed_amount * SLASH_FINDER_REWARD_PCT // 100
        burned = slashed_amount - finder_reward

        db = self.db if hasattr(self, "db") else None
        if slash_pct == 100:
            # Full burn — preserve the exact pre-Tier 20 byte-level
            # state transition so historical chain replay reaches the
            # same `staked`/`pending_unstakes` shape it always did.
            self.staked[offender_id] = 0
            if offender_id in self.pending_unstakes:
                del self.pending_unstakes[offender_id]
            # Mirror the slash into the DB so restarted peers see the
            # same empty queue — without this, a cold-booted node would
            # rehydrate a ghost queue for a slashed offender and release
            # tokens that the canonical chain burned.
            if db is not None and hasattr(db, "clear_all_pending_unstakes"):
                db.clear_all_pending_unstakes(offender_id)
        else:
            # Partial burn — scale stake and each pending entry in
            # place.  Each entry's release_block is preserved so the
            # unbonding schedule the offender originally chose is not
            # extended by the slash (extending it would be a hidden
            # second penalty on top of the proportional burn).
            self.staked[offender_id] = staked_amount - stake_burn
            if offender_id in self.pending_unstakes:
                rebuilt = []
                for amount, release_block in self.pending_unstakes[offender_id]:
                    new_amount = amount - (amount * slash_pct // 100)
                    if new_amount > 0:
                        rebuilt.append((new_amount, release_block))
                if rebuilt:
                    self.pending_unstakes[offender_id] = rebuilt
                else:
                    del self.pending_unstakes[offender_id]
                # Mirror the rewritten queue into the DB.  No
                # per-entry "scale" primitive exists, so we clear and
                # re-add — atomic replace, same shape on every replayer.
                if db is not None and hasattr(db, "clear_all_pending_unstakes"):
                    db.clear_all_pending_unstakes(offender_id)
                if db is not None and hasattr(db, "add_pending_unstake"):
                    for new_amount, release_block in rebuilt:
                        db.add_pending_unstake(
                            offender_id, new_amount, release_block,
                        )

        # Pay finder
        self.balances[finder_id] = self.balances.get(finder_id, 0) + finder_reward

        # Burn the rest — permanently removed from supply.  Both totals
        # must be updated so `get_supply_stats["net_inflation"]` stays
        # consistent with the invariant `total_supply == GENESIS_SUPPLY
        # + total_minted - total_burned`.  Previously only total_supply
        # moved, silently breaking the invariant and inflating every
        # "net inflation" auditor calculation on the chain.
        self.total_supply -= burned
        self.total_burned += burned

        return slashed_amount, finder_reward

    def burn_slash_proportional(
        self,
        offender_id: bytes,
        slash_pct: int,
        admission_basis: int | None = None,
        blockchain=None,
    ) -> int:
        """Pure-burn slash drawing from `staked` AND `pending_unstakes`.

        Tier 31: censorship and inclusion-list-violation apply paths
        share this shape — the slash basis is (staked + pending) and
        the burn is proportional across both buckets.  Mirrors the
        partial-burn loop in ``slash_validator`` but with no finder
        reward (those paths burn the full slashed amount).

        ``admission_basis`` (optional) caps the slash at the basis
        snapshotted when the evidence was admitted — protects against
        an offender topping up post-evidence to inflate the slash, and
        matches the censorship-evidence "snapshot at admission"
        anchor.  Pass ``None`` to skip the cap (IL violation path,
        which has no admission snapshot).

        ``blockchain`` (optional) is the structural guard for the
        ``_touch_state`` contract.  When passed, the helper itself
        calls ``blockchain._touch_state({offender_id})`` after the
        burn lands so the offender's state_tree leaf reflects the new
        ``staked`` value — even if the caller's ``affected_entities()``
        registration omits the offender.  Existing call sites whose
        block-level sweep already covers the offender (IL violation,
        bogus rejection, non-response) are no-op double-refreshes;
        the censorship-evidence call site relies on this in-band
        refresh because evidence matures several blocks after the
        admission tx and the per-tx sweep cannot reach the offender.
        Future call sites that forget to refresh the offender are
        protected by this guard rather than silently regressing into
        the same defect-class bug.

        Returns the total amount burned (sum of stake_burn +
        pending_burn).
        """
        if not 0 < slash_pct <= 100:
            raise ValueError(
                f"slash_pct must be in (0, 100], got {slash_pct}"
            )

        staked_amount = self.staked.get(offender_id, 0)
        pending_amount = self.get_pending_unstake(offender_id)
        basis = staked_amount + pending_amount
        if admission_basis is not None and admission_basis < basis:
            # Slash basis cannot exceed the admission snapshot — an
            # offender who restakes after evidence admission must not
            # see a larger slash than the censorship rule originally
            # claimed against them.
            basis = admission_basis
        if basis == 0:
            return 0

        # Compute the requested total slash on the (capped) basis,
        # then apportion proportionally to current staked vs pending.
        # Apportioning AFTER capping ensures the cap binds the total
        # burn, not the pre-cap fractions.
        target_total = basis * slash_pct // 100
        if target_total <= 0:
            return 0

        bucket_total = staked_amount + pending_amount
        if bucket_total <= 0:
            return 0
        # Stake burn = floor(target_total × staked_amount / bucket_total).
        # Pending burn picks up the remainder so the total burn equals
        # target_total exactly (no rounding loss).
        stake_burn = (target_total * staked_amount) // bucket_total
        pending_burn = target_total - stake_burn
        # Defensive clamps — never debit more than the bucket holds.
        if stake_burn > staked_amount:
            stake_burn = staked_amount
        if pending_burn > pending_amount:
            pending_burn = pending_amount
        slashed_amount = stake_burn + pending_burn
        if slashed_amount == 0:
            return 0

        db = self.db if hasattr(self, "db") else None
        # Drain stake.
        self.staked[offender_id] = staked_amount - stake_burn

        # Drain pending — proportional rewrite of every entry, same
        # shape as `slash_validator`'s partial-burn branch so the DB
        # mirror logic is identical.
        if pending_burn > 0 and offender_id in self.pending_unstakes:
            # Apportion pending_burn across the offender's pending
            # entries proportional to each entry's amount.  Last entry
            # picks up the rounding remainder so the total drained
            # equals pending_burn exactly.
            entries = self.pending_unstakes[offender_id]
            total_pending = sum(amt for amt, _ in entries)
            rebuilt = []
            running = 0
            for idx, (amount, release_block) in enumerate(entries):
                if idx == len(entries) - 1:
                    drain = pending_burn - running
                else:
                    drain = (pending_burn * amount) // total_pending
                    running += drain
                # Defensive clamp.
                if drain > amount:
                    drain = amount
                new_amount = amount - drain
                if new_amount > 0:
                    rebuilt.append((new_amount, release_block))
            if rebuilt:
                self.pending_unstakes[offender_id] = rebuilt
            else:
                del self.pending_unstakes[offender_id]
            if db is not None and hasattr(db, "clear_all_pending_unstakes"):
                db.clear_all_pending_unstakes(offender_id)
            if db is not None and hasattr(db, "add_pending_unstake"):
                for new_amount, release_block in rebuilt:
                    db.add_pending_unstake(
                        offender_id, new_amount, release_block,
                    )

        # Pure burn: no finder reward, no recipient — total burn
        # leaves total_supply by the slashed amount.
        self.total_supply -= slashed_amount
        self.total_burned += slashed_amount

        # Structural guard for the ``_touch_state`` contract.  When the
        # caller threads the blockchain through, the helper refreshes
        # the offender's state_tree leaf in-band so a forgotten per-
        # call-site refresh cannot leave the leaf stale.  The check
        # is defensive (``hasattr`` rather than a hard import) so test
        # stubs that pass a stripped-down blockchain still work.
        if blockchain is not None and hasattr(blockchain, "_touch_state"):
            blockchain._touch_state({offender_id})
        return slashed_amount

    def get_supply_stats(self, current_block_height: int = 0) -> dict:
        active_supply = self.compute_active_supply(current_block_height)
        dormancy_gap = max(0, DORMANCY_TARGET_ACTIVE_SUPPLY - active_supply)
        return {
            "total_supply": self.total_supply,
            "genesis_supply": GENESIS_SUPPLY,
            "total_minted": self.total_minted,
            "total_fees_collected": self.total_fees_collected,
            "total_burned": self.total_burned,
            "net_inflation": self.total_minted - self.total_burned,
            "inflation_pct": (self.total_minted / self.total_supply) * 100 if self.total_supply > 0 else 0,
            "current_block_reward": self.calculate_block_reward(current_block_height),
            "current_base_fee": self.base_fee,
            "next_halving_block": ((current_block_height // HALVING_INTERVAL) + 1) * HALVING_INTERVAL,
            # Tier 47 dormancy controller observability.  Pre-activation
            # `active_supply` is computed against whatever bump_active
            # calls have happened (typically near-zero since the
            # backfill hasn't fired); not consensus-critical pre-fork
            # because calculate_block_reward gates the controller on
            # the activation height.
            "active_supply": active_supply,
            "dormancy_target_active_supply": DORMANCY_TARGET_ACTIVE_SUPPLY,
            "dormancy_gap": dormancy_gap,
            "dormancy_window_blocks": DORMANCY_WINDOW_BLOCKS,
            "dormancy_taper_blocks": DORMANCY_TAPER_BLOCKS,
            "dormancy_controller_height": DORMANCY_CONTROLLER_HEIGHT,
            "dormancy_backfill_applied": self.dormancy_backfill_applied,
        }
