"""
Deflationary token economics for MessageChain.

The supply is mathematically guaranteed to decrease over time:
- Fixed genesis supply, no minting ever
- Each message burns tokens proportional to current supply
- Burn cost: max(MIN_BURN, floor(current_supply * BURN_RATE))
- Supply after n messages: S_n ≈ S_0 * (1 - BURN_RATE)^n (exponential decay)
- Supply asymptotically approaches zero but never reaches it

This creates natural scarcity: as supply decreases, each remaining token
becomes more valuable, and posting becomes cheaper in absolute terms but
the relative cost stays constant.
"""

import math
from messagechain.config import GENESIS_SUPPLY, BURN_RATE, MIN_BURN


class SupplyTracker:
    """Tracks total supply, burns, and per-entity balances."""

    def __init__(self):
        self.total_supply: int = GENESIS_SUPPLY
        self.total_burned: int = 0
        self.balances: dict[bytes, int] = {}
        self.staked: dict[bytes, int] = {}  # staked amounts (locked)

    def initialize_balance(self, entity_id: bytes, amount: int):
        """Set initial balance for an entity (used at genesis)."""
        self.balances[entity_id] = amount

    def get_balance(self, entity_id: bytes) -> int:
        """Get spendable (non-staked) balance."""
        return self.balances.get(entity_id, 0)

    def get_staked(self, entity_id: bytes) -> int:
        return self.staked.get(entity_id, 0)

    def calculate_burn_cost(self) -> int:
        """
        Calculate the current cost to post a message.

        Cost = max(MIN_BURN, floor(current_supply * BURN_RATE))

        As supply decreases, absolute cost decreases, but relative cost
        (as fraction of supply) stays constant at BURN_RATE.
        """
        return max(MIN_BURN, math.floor(self.total_supply * BURN_RATE))

    def can_afford(self, entity_id: bytes) -> bool:
        return self.get_balance(entity_id) >= self.calculate_burn_cost()

    def execute_burn(self, entity_id: bytes, amount: int) -> bool:
        """Burn tokens from an entity's balance. Returns False if insufficient."""
        balance = self.get_balance(entity_id)
        if balance < amount:
            return False
        self.balances[entity_id] = balance - amount
        self.total_supply -= amount
        self.total_burned += amount
        return True

    def stake(self, entity_id: bytes, amount: int) -> bool:
        """Lock tokens for validator staking."""
        balance = self.get_balance(entity_id)
        if balance < amount:
            return False
        self.balances[entity_id] = balance - amount
        self.staked[entity_id] = self.staked.get(entity_id, 0) + amount
        return True

    def unstake(self, entity_id: bytes, amount: int) -> bool:
        """Unlock staked tokens."""
        staked = self.get_staked(entity_id)
        if staked < amount:
            return False
        self.staked[entity_id] = staked - amount
        self.balances[entity_id] = self.balances.get(entity_id, 0) + amount
        return True

    def transfer(self, from_id: bytes, to_id: bytes, amount: int) -> bool:
        """Transfer tokens between entities."""
        if self.get_balance(from_id) < amount:
            return False
        self.balances[from_id] -= amount
        self.balances[to_id] = self.balances.get(to_id, 0) + amount
        return True

    def get_supply_stats(self) -> dict:
        """Return current economic state."""
        return {
            "total_supply": self.total_supply,
            "total_burned": self.total_burned,
            "burn_rate": BURN_RATE,
            "current_burn_cost": self.calculate_burn_cost(),
            "deflation_pct": (self.total_burned / GENESIS_SUPPLY) * 100 if GENESIS_SUPPLY > 0 else 0,
            "projected_supply_after_1000_msgs": math.floor(
                self.total_supply * ((1 - BURN_RATE) ** 1000)
            ),
        }
