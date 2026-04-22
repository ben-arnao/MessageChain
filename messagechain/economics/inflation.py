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
    BASE_FEE_INITIAL, BASE_FEE_MAX_CHANGE_DENOMINATOR,
    TARGET_BLOCK_SIZE, MIN_TIP,
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
)


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

    def get_balance(self, entity_id: bytes) -> int:
        """Get spendable (non-staked) balance."""
        return self.balances.get(entity_id, 0)

    def get_staked(self, entity_id: bytes) -> int:
        return self.staked.get(entity_id, 0)

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

        effective_cap = reward if bootstrap else PROPOSER_REWARD_CAP

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
                cap_per_entity = (
                    cap_pool_basis
                    * PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH
                    * FINALITY_INTERVAL
                    // 10_000
                )

            for eid in paid_committee:
                reward_amount = per_slot_reward
                if cap_active and per_slot_reward > 0:
                    earned = self.attester_epoch_earnings.get(eid, 0)
                    available = cap_per_entity - earned
                    if available < 0:
                        available = 0
                    reward_amount = min(per_slot_reward, available)
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

    def update_base_fee(self, parent_tx_count: int) -> int:
        """Adjust base fee based on parent block fullness (EIP-1559).

        If the parent block had more txs than TARGET_BLOCK_SIZE, base fee
        increases. If fewer, it decreases. Max change per block is
        1/BASE_FEE_MAX_CHANGE_DENOMINATOR of the current base fee.

        Returns the new base fee.
        """
        if parent_tx_count == TARGET_BLOCK_SIZE:
            return self.base_fee

        from messagechain.config import MIN_FEE, MAX_BASE_FEE_MULTIPLIER
        max_base_fee = MIN_FEE * MAX_BASE_FEE_MULTIPLIER
        if parent_tx_count > TARGET_BLOCK_SIZE:
            # Block was over target — increase base fee
            excess = parent_tx_count - TARGET_BLOCK_SIZE
            delta = self.base_fee * excess // (TARGET_BLOCK_SIZE * BASE_FEE_MAX_CHANGE_DENOMINATOR)
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
            # Block was under target — decrease base fee
            deficit = TARGET_BLOCK_SIZE - parent_tx_count
            delta = self.base_fee * deficit // (TARGET_BLOCK_SIZE * BASE_FEE_MAX_CHANGE_DENOMINATOR)
            self.base_fee = max(MIN_FEE, self.base_fee - delta)

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
        return True

    def process_pending_unstakes(self, current_block: int) -> int:
        """Release matured unstakes. Returns total tokens released."""
        total_released = 0
        for entity_id in list(self.pending_unstakes.keys()):
            pending = self.pending_unstakes[entity_id]
            still_pending = []
            for amount, release_block in pending:
                if current_block >= release_block:
                    self.balances[entity_id] = self.balances.get(entity_id, 0) + amount
                    total_released += amount
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

    def slash_validator(self, offender_id: bytes, finder_id: bytes) -> tuple[int, int]:
        """
        Slash a validator: burn their entire stake + pending unstakes, pay finder a reward.

        Returns (total_slashed, finder_reward).
        """
        staked_amount = self.staked.get(offender_id, 0)
        pending_amount = self.get_pending_unstake(offender_id)
        slashed_amount = staked_amount + pending_amount

        if slashed_amount == 0:
            return 0, 0

        finder_reward = slashed_amount * SLASH_FINDER_REWARD_PCT // 100
        burned = slashed_amount - finder_reward

        # Remove all stake and pending unstakes
        self.staked[offender_id] = 0
        if offender_id in self.pending_unstakes:
            del self.pending_unstakes[offender_id]

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

    def get_supply_stats(self, current_block_height: int = 0) -> dict:
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
        }
