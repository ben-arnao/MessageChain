"""
Inflationary token economics for MessageChain.

Why inflation? People die, lose access, or abandon wallets. Without new token
issuance the effective circulating supply would shrink to zero over time.
Controlled inflation ensures the network remains usable indefinitely.

Model:
- Fixed block reward, halving periodically (like BTC's issuance schedule)
- Block reward = BLOCK_REWARD / (2 ^ (block_height // HALVING_INTERVAL))
- Transaction fees use a BTC-style bidding system: users set their own fee,
  higher fee = higher priority for block inclusion
- Fees are paid to the block proposer (incentivizes validators)
- New tokens are minted each block (block reward), paid to proposer

The inflation rate decreases over time due to halvings, but never fully stops,
ensuring permanent (diminishing) issuance to replace lost tokens.
"""

import math
from messagechain.config import (
    GENESIS_SUPPLY, BLOCK_REWARD, HALVING_INTERVAL, MIN_FEE,
    SLASH_FINDER_REWARD_PCT,
)


class SupplyTracker:
    """Tracks total supply, minting, and per-entity balances."""

    def __init__(self):
        self.total_supply: int = GENESIS_SUPPLY
        self.total_minted: int = 0  # tokens created via block rewards
        self.total_fees_collected: int = 0
        self.balances: dict[bytes, int] = {}
        self.staked: dict[bytes, int] = {}

    def get_balance(self, entity_id: bytes) -> int:
        """Get spendable (non-staked) balance."""
        return self.balances.get(entity_id, 0)

    def get_staked(self, entity_id: bytes) -> int:
        return self.staked.get(entity_id, 0)

    def calculate_block_reward(self, block_height: int) -> int:
        """
        Calculate block reward with halving schedule.

        Reward halves every HALVING_INTERVAL blocks, asymptotically approaching
        but never reaching zero. This provides permanent diminishing inflation.
        """
        halvings = block_height // HALVING_INTERVAL
        reward = BLOCK_REWARD >> halvings  # integer division by 2^halvings
        return max(1, reward)  # minimum 1 token per block, always

    def mint_block_reward(self, proposer_id: bytes, block_height: int) -> int:
        """Mint new tokens as block reward to the proposer."""
        reward = self.calculate_block_reward(block_height)
        self.balances[proposer_id] = self.balances.get(proposer_id, 0) + reward
        self.total_supply += reward
        self.total_minted += reward
        return reward

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

    def can_afford_fee(self, entity_id: bytes, fee: int) -> bool:
        return self.get_balance(entity_id) >= fee

    def stake(self, entity_id: bytes, amount: int) -> bool:
        """Lock tokens for validator staking."""
        if self.get_balance(entity_id) < amount:
            return False
        self.balances[entity_id] -= amount
        self.staked[entity_id] = self.staked.get(entity_id, 0) + amount
        return True

    def unstake(self, entity_id: bytes, amount: int) -> bool:
        """Unlock staked tokens."""
        if self.get_staked(entity_id) < amount:
            return False
        self.staked[entity_id] -= amount
        self.balances[entity_id] = self.balances.get(entity_id, 0) + amount
        return True

    def transfer(self, from_id: bytes, to_id: bytes, amount: int) -> bool:
        """Transfer tokens between entities."""
        if self.get_balance(from_id) < amount:
            return False
        self.balances[from_id] -= amount
        self.balances[to_id] = self.balances.get(to_id, 0) + amount
        return True

    def slash_validator(self, offender_id: bytes, finder_id: bytes) -> tuple[int, int]:
        """
        Slash a validator: burn their entire stake, pay finder a reward.

        Returns (total_slashed, finder_reward).
        """
        slashed_amount = self.staked.get(offender_id, 0)
        if slashed_amount == 0:
            return 0, 0

        finder_reward = slashed_amount * SLASH_FINDER_REWARD_PCT // 100
        burned = slashed_amount - finder_reward

        # Remove all stake
        self.staked[offender_id] = 0

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
            "inflation_pct": (self.total_minted / self.total_supply) * 100 if self.total_supply > 0 else 0,
            "current_block_reward": self.calculate_block_reward(current_block_height),
            "next_halving_block": ((current_block_height // HALVING_INTERVAL) + 1) * HALVING_INTERVAL,
        }
