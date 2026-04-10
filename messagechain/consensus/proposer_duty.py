"""
Proposer duty tracking and censorship detection.

Monitors whether block proposers are fulfilling their duty to include
transactions when the mempool has pending work. Proposers who consistently
produce empty blocks while transactions are waiting are flagged with a
censorship score.

This is a detection mechanism, not an enforcement one — the censorship
score can be used by governance proposals or future slashing conditions.
"""

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class ProposerStats:
    """Cumulative statistics for a single proposer."""
    blocks_proposed: int = 0
    total_txs_included: int = 0
    empty_blocks_with_pending: int = 0
    empty_blocks_no_pending: int = 0

    @property
    def censorship_score(self) -> float:
        """Score representing likelihood of censorship behavior.

        Ratio of empty-when-pending blocks to total blocks proposed.
        0.0 = no censorship signal, 1.0 = always censoring.
        """
        if self.blocks_proposed == 0:
            return 0.0
        return self.empty_blocks_with_pending / self.blocks_proposed


class ProposerDutyTracker:
    """Track proposer behavior for censorship detection.

    Records each block production event along with the mempool state
    at the time of proposal. Proposers who repeatedly produce empty
    blocks while transactions are pending accumulate censorship score.
    """

    def __init__(self):
        self._stats: dict[bytes, ProposerStats] = defaultdict(ProposerStats)

    def record_block(self, proposer_id: bytes, tx_count: int, mempool_size: int):
        """Record a block production event.

        Args:
            proposer_id: The entity ID of the block proposer
            tx_count: Number of transactions included in the block
            mempool_size: Number of transactions in the mempool at proposal time
        """
        stats = self._stats[proposer_id]
        stats.blocks_proposed += 1
        stats.total_txs_included += tx_count

        if tx_count == 0:
            if mempool_size > 0:
                stats.empty_blocks_with_pending += 1
            else:
                stats.empty_blocks_no_pending += 1

    def get_proposer_stats(self, proposer_id: bytes) -> dict:
        """Get stats for a proposer as a dict."""
        stats = self._stats[proposer_id]
        return {
            "blocks_proposed": stats.blocks_proposed,
            "total_txs_included": stats.total_txs_included,
            "empty_blocks_with_pending": stats.empty_blocks_with_pending,
            "empty_blocks_no_pending": stats.empty_blocks_no_pending,
            "censorship_score": stats.censorship_score,
        }

    def get_suspected_censors(self, min_blocks: int = 10, threshold: float = 0.5) -> list[bytes]:
        """Get proposers with censorship score above threshold.

        Only considers proposers with at least min_blocks to avoid
        flagging new validators who happened to propose during low traffic.
        """
        suspects = []
        for proposer_id, stats in self._stats.items():
            if stats.blocks_proposed >= min_blocks and stats.censorship_score >= threshold:
                suspects.append(proposer_id)
        return suspects
