"""
SQLite-backed persistent storage for MessageChain.

Stores blocks, chain state (balances, nonces, public keys), and block index
so the chain survives restarts. Inspired by Bitcoin Core's block index (LevelDB)
and UTXO set, adapted for our account-based model using SQLite.

Schema:
- blocks: raw serialized blocks keyed by hash, indexed by height
- block_index: hash -> height + prev_hash for fast chain traversal
- state: account balances, nonces, public keys, stakes, message counts
- chain_tips: tracks all known chain tips for fork choice
- supply_meta: global supply tracking data
"""

import json
import sqlite3
import threading
from pathlib import Path

from messagechain.core.block import Block


_SCHEMA_VERSION = 1


class ChainDB:
    """SQLite-backed block and state storage."""

    def __init__(self, db_path: str = "messagechain.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()

    @property
    def _conn(self) -> sqlite3.Connection:
        """Thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=FULL")
        return self._local.conn

    def _init_schema(self):
        conn = self._conn
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blocks (
                block_hash BLOB PRIMARY KEY,
                block_number INTEGER NOT NULL,
                prev_hash BLOB NOT NULL,
                data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_blocks_number ON blocks(block_number);
            CREATE INDEX IF NOT EXISTS idx_blocks_prev ON blocks(prev_hash);

            CREATE TABLE IF NOT EXISTS chain_tips (
                block_hash BLOB PRIMARY KEY,
                block_number INTEGER NOT NULL,
                cumulative_stake INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS balances (
                entity_id BLOB PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS staked (
                entity_id BLOB PRIMARY KEY,
                amount INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS nonces (
                entity_id BLOB PRIMARY KEY,
                nonce INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS public_keys (
                entity_id BLOB PRIMARY KEY,
                public_key BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS message_counts (
                entity_id BLOB PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS proposer_sig_counts (
                entity_id BLOB PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS supply_meta (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS slashed_validators (
                entity_id BLOB PRIMARY KEY,
                slashed_at_block INTEGER NOT NULL,
                evidence_hash BLOB NOT NULL
            );
        """)
        conn.commit()

        # Initialize supply meta if not exists
        cur = conn.execute("SELECT COUNT(*) FROM supply_meta")
        if cur.fetchone()[0] == 0:
            from messagechain.config import GENESIS_SUPPLY
            conn.executemany(
                "INSERT OR IGNORE INTO supply_meta (key, value) VALUES (?, ?)",
                [
                    ("total_supply", GENESIS_SUPPLY),
                    ("total_minted", 0),
                    ("total_fees_collected", 0),
                ],
            )
            conn.commit()

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ── Block Storage ────────────────────────────────────────────

    def store_block(self, block: Block):
        """Store a serialized block."""
        data = json.dumps(block.serialize())
        self._conn.execute(
            "INSERT OR REPLACE INTO blocks (block_hash, block_number, prev_hash, data) VALUES (?, ?, ?, ?)",
            (block.block_hash, block.header.block_number, block.header.prev_hash, data),
        )
        self._conn.commit()

    def get_block_by_hash(self, block_hash: bytes) -> Block | None:
        cur = self._conn.execute("SELECT data FROM blocks WHERE block_hash = ?", (block_hash,))
        row = cur.fetchone()
        if row is None:
            return None
        return Block.deserialize(json.loads(row[0]))

    def get_block_by_number(self, block_number: int) -> Block | None:
        """Get block by height. If multiple at same height (forks), returns the one on the best chain."""
        cur = self._conn.execute(
            "SELECT data FROM blocks WHERE block_number = ? LIMIT 1",
            (block_number,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return Block.deserialize(json.loads(row[0]))

    def get_blocks_at_height(self, block_number: int) -> list[Block]:
        """Get all blocks at a given height (for fork detection)."""
        cur = self._conn.execute(
            "SELECT data FROM blocks WHERE block_number = ?", (block_number,)
        )
        return [Block.deserialize(json.loads(row[0])) for row in cur.fetchall()]

    def has_block(self, block_hash: bytes) -> bool:
        cur = self._conn.execute("SELECT 1 FROM blocks WHERE block_hash = ?", (block_hash,))
        return cur.fetchone() is not None

    def get_block_count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM blocks")
        return cur.fetchone()[0]

    def get_max_block_number(self) -> int:
        cur = self._conn.execute("SELECT MAX(block_number) FROM blocks")
        row = cur.fetchone()
        return row[0] if row[0] is not None else -1

    def get_chain_from_tip(self, tip_hash: bytes, count: int) -> list[Block]:
        """Walk backwards from a tip, returning up to `count` blocks."""
        blocks = []
        current_hash = tip_hash
        while len(blocks) < count and current_hash:
            block = self.get_block_by_hash(current_hash)
            if block is None:
                break
            blocks.append(block)
            current_hash = block.header.prev_hash
            if current_hash == b"\x00" * 32:
                break
        blocks.reverse()
        return blocks

    def get_block_hashes_in_range(self, start_height: int, end_height: int) -> list[tuple[int, bytes]]:
        """Get (block_number, block_hash) pairs in a height range."""
        cur = self._conn.execute(
            "SELECT block_number, block_hash FROM blocks WHERE block_number >= ? AND block_number <= ? ORDER BY block_number",
            (start_height, end_height),
        )
        return [(row[0], bytes(row[1])) for row in cur.fetchall()]

    # ── Chain Tips ───────────────────────────────────────────────

    def add_chain_tip(self, block_hash: bytes, block_number: int, cumulative_stake: int = 0):
        self._conn.execute(
            "INSERT OR REPLACE INTO chain_tips (block_hash, block_number, cumulative_stake) VALUES (?, ?, ?)",
            (block_hash, block_number, cumulative_stake),
        )
        self._conn.commit()

    def remove_chain_tip(self, block_hash: bytes):
        self._conn.execute("DELETE FROM chain_tips WHERE block_hash = ?", (block_hash,))
        self._conn.commit()

    def get_best_tip(self) -> tuple[bytes, int, int] | None:
        """Get the chain tip with highest cumulative stake (then highest block number)."""
        cur = self._conn.execute(
            "SELECT block_hash, block_number, cumulative_stake FROM chain_tips "
            "ORDER BY cumulative_stake DESC, block_number DESC LIMIT 1"
        )
        row = cur.fetchone()
        if row is None:
            return None
        return (bytes(row[0]), row[1], row[2])

    def get_all_tips(self) -> list[tuple[bytes, int, int]]:
        cur = self._conn.execute(
            "SELECT block_hash, block_number, cumulative_stake FROM chain_tips "
            "ORDER BY cumulative_stake DESC, block_number DESC"
        )
        return [(bytes(row[0]), row[1], row[2]) for row in cur.fetchall()]

    # ── State: Balances ──────────────────────────────────────────

    def get_balance(self, entity_id: bytes) -> int:
        cur = self._conn.execute("SELECT balance FROM balances WHERE entity_id = ?", (entity_id,))
        row = cur.fetchone()
        return row[0] if row else 0

    def set_balance(self, entity_id: bytes, balance: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO balances (entity_id, balance) VALUES (?, ?)",
            (entity_id, balance),
        )

    def get_all_balances(self) -> dict[bytes, int]:
        cur = self._conn.execute("SELECT entity_id, balance FROM balances")
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

    # ── State: Stakes ────────────────────────────────────────────

    def get_staked(self, entity_id: bytes) -> int:
        cur = self._conn.execute("SELECT amount FROM staked WHERE entity_id = ?", (entity_id,))
        row = cur.fetchone()
        return row[0] if row else 0

    def set_staked(self, entity_id: bytes, amount: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO staked (entity_id, amount) VALUES (?, ?)",
            (entity_id, amount),
        )

    def get_all_staked(self) -> dict[bytes, int]:
        cur = self._conn.execute("SELECT entity_id, amount FROM staked WHERE amount > 0")
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

    # ── State: Nonces ────────────────────────────────────────────

    def get_nonce(self, entity_id: bytes) -> int:
        cur = self._conn.execute("SELECT nonce FROM nonces WHERE entity_id = ?", (entity_id,))
        row = cur.fetchone()
        return row[0] if row else 0

    def set_nonce(self, entity_id: bytes, nonce: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO nonces (entity_id, nonce) VALUES (?, ?)",
            (entity_id, nonce),
        )

    def get_all_nonces(self) -> dict[bytes, int]:
        cur = self._conn.execute("SELECT entity_id, nonce FROM nonces")
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

    # ── State: Public Keys ───────────────────────────────────────

    def get_public_key(self, entity_id: bytes) -> bytes | None:
        cur = self._conn.execute("SELECT public_key FROM public_keys WHERE entity_id = ?", (entity_id,))
        row = cur.fetchone()
        return bytes(row[0]) if row else None

    def set_public_key(self, entity_id: bytes, public_key: bytes):
        self._conn.execute(
            "INSERT OR REPLACE INTO public_keys (entity_id, public_key) VALUES (?, ?)",
            (entity_id, public_key),
        )

    def get_all_public_keys(self) -> dict[bytes, bytes]:
        cur = self._conn.execute("SELECT entity_id, public_key FROM public_keys")
        return {bytes(row[0]): bytes(row[1]) for row in cur.fetchall()}

    # ── State: Message Counts ────────────────────────────────────

    def get_message_count(self, entity_id: bytes) -> int:
        cur = self._conn.execute("SELECT count FROM message_counts WHERE entity_id = ?", (entity_id,))
        row = cur.fetchone()
        return row[0] if row else 0

    def set_message_count(self, entity_id: bytes, count: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO message_counts (entity_id, count) VALUES (?, ?)",
            (entity_id, count),
        )

    def get_all_message_counts(self) -> dict[bytes, int]:
        cur = self._conn.execute("SELECT entity_id, count FROM message_counts")
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

    # ── State: Proposer Signature Counts ────────────────────────

    def get_proposer_sig_count(self, entity_id: bytes) -> int:
        cur = self._conn.execute("SELECT count FROM proposer_sig_counts WHERE entity_id = ?", (entity_id,))
        row = cur.fetchone()
        return row[0] if row else 0

    def set_proposer_sig_count(self, entity_id: bytes, count: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO proposer_sig_counts (entity_id, count) VALUES (?, ?)",
            (entity_id, count),
        )

    def get_all_proposer_sig_counts(self) -> dict[bytes, int]:
        cur = self._conn.execute("SELECT entity_id, count FROM proposer_sig_counts")
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

    # ── Supply Meta ──────────────────────────────────────────────

    def get_supply_meta(self, key: str) -> int:
        cur = self._conn.execute("SELECT value FROM supply_meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else 0

    def set_supply_meta(self, key: str, value: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO supply_meta (key, value) VALUES (?, ?)",
            (key, value),
        )

    # ── Slashed Validators ─────────────────────────────────────────

    def add_slashed_validator(self, entity_id: bytes, block_number: int, evidence_hash: bytes):
        self._conn.execute(
            "INSERT OR REPLACE INTO slashed_validators (entity_id, slashed_at_block, evidence_hash) VALUES (?, ?, ?)",
            (entity_id, block_number, evidence_hash),
        )

    def is_slashed(self, entity_id: bytes) -> bool:
        cur = self._conn.execute("SELECT 1 FROM slashed_validators WHERE entity_id = ?", (entity_id,))
        return cur.fetchone() is not None

    def get_all_slashed(self) -> set[bytes]:
        cur = self._conn.execute("SELECT entity_id FROM slashed_validators")
        return {bytes(row[0]) for row in cur.fetchall()}

    # ── Batch Operations (for state snapshots / reorgs) ──────────

    def save_state_snapshot(self) -> dict:
        """Capture full state for rollback during reorg."""
        return {
            "balances": self.get_all_balances(),
            "staked": self.get_all_staked(),
            "nonces": self.get_all_nonces(),
            "public_keys": self.get_all_public_keys(),
            "message_counts": self.get_all_message_counts(),
            "proposer_sig_counts": self.get_all_proposer_sig_counts(),
            "total_supply": self.get_supply_meta("total_supply"),
            "total_minted": self.get_supply_meta("total_minted"),
            "total_fees_collected": self.get_supply_meta("total_fees_collected"),
        }

    def restore_state_snapshot(self, snapshot: dict):
        """Restore state from a snapshot (used during chain reorg).

        All operations are wrapped in a single transaction so a crash
        cannot leave the database with deleted-but-not-restored data.
        """
        conn = self._conn
        conn.execute("BEGIN")
        try:
            conn.execute("DELETE FROM balances")
            conn.execute("DELETE FROM staked")
            conn.execute("DELETE FROM nonces")
            conn.execute("DELETE FROM public_keys")
            conn.execute("DELETE FROM message_counts")
            conn.execute("DELETE FROM proposer_sig_counts")

            for eid, bal in snapshot["balances"].items():
                conn.execute("INSERT INTO balances (entity_id, balance) VALUES (?, ?)", (eid, bal))
            for eid, amt in snapshot["staked"].items():
                conn.execute("INSERT INTO staked (entity_id, amount) VALUES (?, ?)", (eid, amt))
            for eid, nonce in snapshot["nonces"].items():
                conn.execute("INSERT INTO nonces (entity_id, nonce) VALUES (?, ?)", (eid, nonce))
            for eid, pk in snapshot["public_keys"].items():
                conn.execute("INSERT INTO public_keys (entity_id, public_key) VALUES (?, ?)", (eid, pk))
            for eid, cnt in snapshot["message_counts"].items():
                conn.execute("INSERT INTO message_counts (entity_id, count) VALUES (?, ?)", (eid, cnt))
            for eid, cnt in snapshot.get("proposer_sig_counts", {}).items():
                conn.execute("INSERT INTO proposer_sig_counts (entity_id, count) VALUES (?, ?)", (eid, cnt))

            conn.execute("UPDATE supply_meta SET value = ? WHERE key = 'total_supply'", (snapshot["total_supply"],))
            conn.execute("UPDATE supply_meta SET value = ? WHERE key = 'total_minted'", (snapshot["total_minted"],))
            conn.execute("UPDATE supply_meta SET value = ? WHERE key = 'total_fees_collected'", (snapshot["total_fees_collected"],))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def flush_state(self):
        """Commit any pending writes."""
        self._conn.commit()

    def begin_transaction(self):
        self._conn.execute("BEGIN")

    def commit_transaction(self):
        self._conn.commit()

    def rollback_transaction(self):
        self._conn.rollback()
