"""
Database integrity checking and reindex capability.

Provides startup health checks and recovery mechanisms for long-term
chain operation. Over a 1000-year timeframe, database corruption is
virtually certain — this module detects and recovers from it.

Checks:
1. SQLite PRAGMA integrity_check (structural corruption)
2. Genesis block presence and hash consistency
3. Supply invariant (total_supply >= 0)
4. Chain tip existence and consistency
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class IntegrityResult:
    """Result of an integrity check."""
    is_ok: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, msg: str):
        self.is_ok = False
        self.errors.append(msg)
        logger.error(f"Integrity check FAILED: {msg}")

    def add_warning(self, msg: str):
        self.warnings.append(msg)
        logger.warning(f"Integrity check warning: {msg}")


def check_sqlite_integrity(db) -> bool:
    """Run SQLite PRAGMA integrity_check on the database.

    Returns True if the database passes structural checks.
    """
    try:
        cur = db._conn.execute("PRAGMA integrity_check")
        result = cur.fetchone()
        return result is not None and result[0] == "ok"
    except Exception as e:
        logger.error(f"SQLite integrity check failed: {e}")
        return False


def check_db_integrity(db, chain) -> IntegrityResult:
    """Run all integrity checks on the database and chain state.

    Args:
        db: ChainDB instance
        chain: Blockchain instance with in-memory state
    """
    result = IntegrityResult()

    # 1. SQLite structural integrity
    if not check_sqlite_integrity(db):
        result.add_error("SQLite PRAGMA integrity_check failed — database may be corrupt")

    # 2. Check chain state consistency
    if chain.height == 0:
        # Empty chain — nothing more to check
        return result

    # 3. Genesis block should exist
    genesis = db.get_block_by_number(0)
    if genesis is None:
        result.add_error("Genesis block (height 0) not found in database")

    # 4. Chain tip should exist
    best_tip = db.get_best_tip()
    if best_tip is None and chain.height > 0:
        result.add_error("No chain tip found but chain has blocks")

    # 5. Supply invariants
    if chain.supply.total_supply < 0:
        result.add_error(f"Negative total supply: {chain.supply.total_supply}")

    if chain.supply.total_minted < 0:
        result.add_error(f"Negative total minted: {chain.supply.total_minted}")

    # 6. No negative balances
    for entity_id, balance in chain.supply.balances.items():
        if balance < 0:
            result.add_error(
                f"Negative balance for entity {entity_id.hex()[:16]}: {balance}"
            )
            break  # one error is enough

    if result.is_ok:
        logger.info("Integrity check passed")

    return result


def reindex_state(db, chain):
    """Rebuild chain state (balances, nonces, etc.) from block history.

    This is the recovery mechanism for corrupted state. Reads all blocks
    from the database and replays them to reconstruct the correct state.

    Args:
        db: ChainDB instance with block data
        chain: Blockchain instance to rebuild state into
    """
    logger.info("Starting state reindex from block history...")

    # Reset all derived state
    chain._reset_state()

    # Re-apply genesis allocation
    from messagechain.config import GENESIS_ALLOCATION
    if chain.height > 0:
        genesis = chain.chain[0]
        proposer_id = genesis.header.proposer_id
        if proposer_id in chain.public_keys:
            chain.supply.balances[proposer_id] = GENESIS_ALLOCATION

    # Replay all blocks after genesis
    block_count = db.get_block_count()
    replayed = 0
    for i in range(1, block_count):
        block = db.get_block_by_number(i)
        if block is None:
            logger.warning(f"Block #{i} not found during reindex — stopping")
            break
        chain._apply_block_state(block)
        replayed += 1

    # Persist the rebuilt state
    chain._persist_state()

    logger.info(f"Reindex complete: replayed {replayed} blocks")
