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
    ATTESTER_REWARD_SPLIT_HEIGHT,
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
        """
        halvings = block_height // HALVING_INTERVAL
        reward = BLOCK_REWARD >> halvings  # integer division by 2^halvings
        return max(BLOCK_REWARD_FLOOR, reward)

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

        # No committee: proposer absorbs the whole reward.  Previously
        # the cap fired here and siphoned the difference into the
        # treasury, which was surprising (treasury accumulated purely
        # because no attesters existed yet — not because governance
        # directed funds there).  The cap protects against a mega-
        # staker capturing disproportionate reward in a MULTI-validator
        # committee; with no committee the proposer IS all the work,
        # so no cap applies.
        if not attester_committee:
            proposer_reward = reward
            self.balances[proposer_id] = (
                self.balances.get(proposer_id, 0) + proposer_reward
            )
            return {
                "total_reward": reward,
                "proposer_reward": proposer_reward,
                "total_attestor_reward": 0,
                "attestor_rewards": {},
                "treasury_excess": 0,
                "burned": 0,
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
            for eid in paid_committee:
                attestor_rewards[eid] = (
                    attestor_rewards.get(eid, 0) + per_slot_reward
                )
                if per_slot_reward > 0:
                    self.balances[eid] = (
                        self.balances.get(eid, 0) + per_slot_reward
                    )
                attester_tokens_paid += per_slot_reward
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
        self, from_id: bytes, to_proposer_id: bytes, fee: int, base_fee: int,
    ) -> bool:
        """Pay a transaction fee with EIP-1559-style base fee burning.

        The base_fee portion is burned (permanently removed from supply).
        The remainder (tip = fee - base_fee) goes to the block proposer.
        Returns False if fee < base_fee or sender can't afford it.
        """
        if fee < base_fee:
            return False
        if self.get_balance(from_id) < fee:
            return False

        tip = fee - base_fee
        self.balances[from_id] -= fee
        self.balances[to_proposer_id] = self.balances.get(to_proposer_id, 0) + tip
        self.total_supply -= base_fee  # burn
        self.total_burned += base_fee
        # Fee-burn-only ticker: tracks the CURRENT block's fee-burn so
        # Blockchain._apply_block_state can redirect the configured
        # fraction into the archive-reward pool.  Not double-counted —
        # the redirect step subtracts from total_burned to compensate.
        self.fee_burn_this_block += base_fee
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
        # or >= VALIDATOR_MIN_STAKE (still a valid validator).
        remaining = current_stake - amount
        if remaining > 0 and remaining < VALIDATOR_MIN_STAKE:
            return False

        # Prevent total stake from dropping below safety floor
        if bootstrap_ended and total_staked_after_check is not None:
            if total_staked_after_check < min_total_stake:
                return False

        self.staked[entity_id] -= amount
        release_block = current_block + UNBONDING_PERIOD
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
        """
        if amount <= 0:
            return False
        if new_account_surcharge < 0:
            return False
        debit_total = amount + new_account_surcharge
        if self.get_balance(TREASURY_ENTITY_ID) < debit_total:
            return False
        self.balances[TREASURY_ENTITY_ID] -= debit_total
        self.balances[recipient_id] = self.balances.get(recipient_id, 0) + amount
        if new_account_surcharge > 0:
            self.total_supply -= new_account_surcharge
            self.total_burned += new_account_surcharge
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
