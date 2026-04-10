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
        attestor_stakes: dict[bytes, int] | None = None,
        bootstrap: bool = False,
    ) -> dict:
        """Mint new tokens and split between proposer and attestors.

        The block reward is split:
        - PROPOSER_REWARD_NUMERATOR/PROPOSER_REWARD_DENOMINATOR to the proposer
        - The remainder distributed pro-rata among attestors by stake weight

        If no attestors are present (genesis, bootstrap, empty attestations),
        the proposer receives the entire reward.

        Returns a dict with distribution details for logging/verification.
        """
        reward = self.calculate_block_reward(block_height)
        self.total_supply += reward
        self.total_minted += reward

        # Determine effective cap (no cap during bootstrap)
        effective_cap = reward if bootstrap else PROPOSER_REWARD_CAP

        if not attestor_stakes:
            # No attestors — proposer gets everything (bootstrap/genesis)
            # Apply reward cap: excess goes to treasury
            proposer_reward = min(reward, effective_cap)
            treasury_excess = reward - proposer_reward
            self.balances[proposer_id] = self.balances.get(proposer_id, 0) + proposer_reward
            if treasury_excess > 0:
                self.balances[TREASURY_ENTITY_ID] = (
                    self.balances.get(TREASURY_ENTITY_ID, 0) + treasury_excess
                )
            return {
                "total_reward": reward,
                "proposer_reward": proposer_reward,
                "total_attestor_reward": 0,
                "attestor_rewards": {},
                "treasury_excess": treasury_excess,
            }

        # Split: proposer share + attestor pool
        proposer_share = reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
        attestor_pool = reward - proposer_share

        # Distribute attestor pool pro-rata by stake weight
        total_attestor_stake = sum(attestor_stakes.values())
        attestor_rewards: dict[bytes, int] = {}
        distributed = 0

        if total_attestor_stake > 0:
            sorted_attestors = sorted(attestor_stakes.items(), key=lambda x: x[0])
            for i, (att_id, stake) in enumerate(sorted_attestors):
                if i == len(sorted_attestors) - 1:
                    # Last attestor gets remainder to avoid rounding dust
                    att_reward = attestor_pool - distributed
                else:
                    att_reward = attestor_pool * stake // total_attestor_stake
                attestor_rewards[att_id] = att_reward
                self.balances[att_id] = self.balances.get(att_id, 0) + att_reward
                distributed += att_reward
        else:
            # Zero total stake — give attestor pool to proposer
            proposer_share += attestor_pool
            attestor_pool = 0

        # If proposer is also an attestor, their total earnings may exceed cap
        proposer_att_reward = attestor_rewards.get(proposer_id, 0)
        proposer_total = proposer_share + proposer_att_reward

        treasury_excess = 0
        if proposer_total > effective_cap:
            treasury_excess = proposer_total - effective_cap
            # Claw back attestor overage already credited + reduce proposer share
            self.balances[proposer_id] = self.balances.get(proposer_id, 0) - proposer_att_reward
            proposer_share = effective_cap
            proposer_att_reward = 0
            attestor_rewards[proposer_id] = 0
            self.balances[TREASURY_ENTITY_ID] = (
                self.balances.get(TREASURY_ENTITY_ID, 0) + treasury_excess
            )

        self.balances[proposer_id] = self.balances.get(proposer_id, 0) + proposer_share

        return {
            "total_reward": reward,
            "proposer_reward": proposer_share,
            "total_attestor_reward": attestor_pool,
            "attestor_rewards": attestor_rewards,
            "treasury_excess": treasury_excess,
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

        if parent_tx_count > TARGET_BLOCK_SIZE:
            # Block was over target — increase base fee
            excess = parent_tx_count - TARGET_BLOCK_SIZE
            delta = self.base_fee * excess // (TARGET_BLOCK_SIZE * BASE_FEE_MAX_CHANGE_DENOMINATOR)
            self.base_fee += max(1, delta)  # always increase by at least 1
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
        if from_id == TREASURY_ENTITY_ID:
            return False
        if self.get_balance(from_id) < amount:
            return False
        self.balances[from_id] -= amount
        self.balances[to_id] = self.balances.get(to_id, 0) + amount
        return True

    def treasury_spend(self, recipient_id: bytes, amount: int) -> bool:
        """Move funds from treasury to recipient (governance-authorized only).

        This is the ONLY way to debit the treasury. Callers must ensure
        governance approval before invoking this method.
        """
        if self.get_balance(TREASURY_ENTITY_ID) < amount:
            return False
        if amount <= 0:
            return False
        self.balances[TREASURY_ENTITY_ID] -= amount
        self.balances[recipient_id] = self.balances.get(recipient_id, 0) + amount
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

        # Burn the rest — permanently removed from supply
        self.total_supply -= burned

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
