"""
Soft fork activation signaling for MessageChain.

Problem: After a governance vote passes, there's no mechanism to
coordinate when nodes should start enforcing new rules.

Solution: Validators signal readiness in their blocks. Once a
threshold of recent blocks signal support, the feature "locks in"
and activates after a grace period, giving all nodes time to upgrade.

This mirrors Bitcoin's BIP 9 version-bits signaling, adapted for PoS.
"""

from dataclasses import dataclass, field


@dataclass
class SignalTracker:
    """Tracks validator signaling for a proposed soft fork.

    Args:
        feature_name: Human-readable name of the feature.
        start_height: Block height at which signaling begins.
        timeout_height: Block height at which signaling expires if not locked in.
        threshold: Fraction of blocks that must signal (0.0–1.0).
        bit: Which bit in the block version signals this feature.
        activation_delay: Blocks after lock-in before the feature activates.
    """
    feature_name: str
    start_height: int
    timeout_height: int
    threshold: float
    bit: int
    activation_delay: int = 10
    min_window: int = 10  # minimum blocks before evaluating threshold

    # Internal state
    _signals: int = 0
    _total_blocks: int = 0
    _locked_in: bool = False
    _lock_in_height: int = -1

    def record_block(self, block_height: int, signals: bool):
        """Record whether a block signals support for this feature.

        Args:
            block_height: The height of the block being recorded.
            signals: True if the block's version bits include this feature's bit.
        """
        if self._locked_in:
            return  # already locked in, no need to track

        if block_height < self.start_height or block_height >= self.timeout_height:
            return  # outside signaling window

        self._total_blocks += 1
        if signals:
            self._signals += 1

        # Check if we've reached threshold (require minimum window)
        if self._total_blocks >= self.min_window:
            ratio = self._signals / self._total_blocks
            if ratio >= self.threshold:
                self._locked_in = True
                self._lock_in_height = block_height

    @property
    def is_locked_in(self) -> bool:
        return self._locked_in

    @property
    def lock_in_height(self) -> int:
        return self._lock_in_height

    @property
    def is_active(self) -> bool:
        """Whether the feature is currently active (past lock-in + delay)."""
        if not self._locked_in:
            return False
        return True  # simplified — use is_active_at for height-specific checks

    def is_active_at(self, block_height: int) -> bool:
        """Check if the feature is active at a specific block height."""
        if not self._locked_in:
            return False
        return block_height >= self._lock_in_height + self.activation_delay

    @property
    def signal_progress(self) -> float:
        """Current signaling ratio (0.0–1.0)."""
        if self._total_blocks == 0:
            return 0.0
        return self._signals / self._total_blocks

    def serialize(self) -> dict:
        return {
            "feature_name": self.feature_name,
            "start_height": self.start_height,
            "timeout_height": self.timeout_height,
            "threshold": self.threshold,
            "bit": self.bit,
            "activation_delay": self.activation_delay,
            "locked_in": self._locked_in,
            "lock_in_height": self._lock_in_height,
            "signals": self._signals,
            "total_blocks": self._total_blocks,
        }
