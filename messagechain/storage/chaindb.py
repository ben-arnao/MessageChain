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
        self._check_db_permissions()
        self._check_and_write_schema_version()

    def _check_and_write_schema_version(self):
        """Enforce a schema-version pin in the meta table.

        _SCHEMA_VERSION is the binary compatibility token.  On first
        init we write it; on every subsequent open we refuse to start
        if the token on disk disagrees with the code's version.  Without
        this, a newer validator binary silently opens an older schema
        and CREATE TABLE IF NOT EXISTS papers over missing columns —
        nodes with the old schema silently return NULL for new fields
        while peers with the new schema produce real values, which can
        diverge consensus.

        Migration path: each version bump ships with an explicit
        ALTER-driven migration function.  This check is the tripwire
        that forces us to write one rather than ride the silent-
        default train.
        """
        conn = self._conn
        cur = conn.execute(
            "SELECT value FROM meta WHERE key = ?", ("schema_version",),
        )
        row = cur.fetchone()
        if row is None:
            # Fresh DB (or one created before this check landed); stamp it.
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", str(_SCHEMA_VERSION)),
            )
            conn.commit()
            return
        try:
            on_disk = int(row[0])
        except (TypeError, ValueError):
            raise RuntimeError(
                f"chain.db meta.schema_version is not an integer: {row[0]!r}"
            )
        if on_disk != _SCHEMA_VERSION:
            raise RuntimeError(
                f"chain.db schema version mismatch: disk={on_disk}, "
                f"code={_SCHEMA_VERSION}.  A migration is required before "
                f"this binary can open this database — do NOT downgrade "
                f"or upgrade across versions without running the migration."
            )

    def _check_db_permissions(self):
        """Warn if chain.db is world-writable.

        A world-writable DB lets any UID on the host mutate validator state
        — an attacker on the box could edit balances in place, silently
        forking consensus without tripping our HMAC/integrity checks
        (which only protect the keypair & Merkle caches, not chain.db
        itself).  The production unit's systemd hardening drops privileges
        and the installer should `chmod 0640 chain.db`; this check catches
        a botched deploy that missed that step.
        """
        import os
        import stat as _stat
        try:
            st = os.stat(self.db_path)
        except OSError:
            return  # fresh db, no file yet — fine
        mode = st.st_mode
        if mode & _stat.S_IWOTH:
            import logging
            logging.getLogger(__name__).error(
                "chain.db at %s is world-writable (mode=%o) — any local "
                "process can tamper with chain state.  Run `chmod 0640 "
                "%s` and verify service user ownership.",
                self.db_path, mode & 0o777, self.db_path,
            )

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
                data BLOB NOT NULL
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

            CREATE TABLE IF NOT EXISTS leaf_watermarks (
                entity_id BLOB PRIMARY KEY,
                next_leaf INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS authority_keys (
                entity_id BLOB PRIMARY KEY,
                authority_public_key BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revoked_entities (
                entity_id BLOB PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS key_rotation_counts (
                entity_id BLOB PRIMARY KEY,
                rotation_number INTEGER NOT NULL DEFAULT 0
            );

            -- WOTS+ Merkle tree height per entity.  Recorded the moment
            -- the entity's pubkey is installed on chain (genesis,
            -- first-spend reveal, or direct install).  The server looks
            -- this up at startup to reconstruct the SAME keypair from a
            -- private key — without it, a config default that drifted
            -- from the value used at creation would silently derive a
            -- different entity_id and make the node unable to sign for
            -- its own wallet.  Set-once per entity; key rotation
            -- preserves the height by construction.
            CREATE TABLE IF NOT EXISTS wots_tree_heights (
                entity_id BLOB PRIMARY KEY,
                tree_height INTEGER NOT NULL
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

            CREATE TABLE IF NOT EXISTS processed_evidence (
                evidence_hash BLOB PRIMARY KEY,
                processed_at_block INTEGER NOT NULL DEFAULT 0
            );

            -- Pending censorship-evidence.  Mirrors
            -- CensorshipEvidenceProcessor.pending so a cold-booted node
            -- resumes the maturity pipeline.  Rows are removed at void
            -- time (observe_block) or mature time (mature()), matching
            -- the in-memory transition.  See
            -- messagechain.consensus.censorship_evidence.
            CREATE TABLE IF NOT EXISTS pending_censorship_evidence (
                evidence_hash BLOB PRIMARY KEY,
                offender_id BLOB NOT NULL,
                tx_hash BLOB NOT NULL,
                admitted_height INTEGER NOT NULL,
                evidence_tx_hash BLOB NOT NULL
            );

            -- Per-validator receipt-subtree root public keys.  A
            -- 32-byte pubkey per registered entity identifies the WOTS+
            -- subtree the validator uses to sign submission receipts.
            -- Separate from public_keys (block-signing root).
            CREATE TABLE IF NOT EXISTS receipt_subtree_roots (
                entity_id BLOB PRIMARY KEY,
                root_public_key BLOB NOT NULL
            );

            -- Entity-index registry (bloat reduction).  Bidirectional
            -- map entity_id <-> entity_index, assigned monotonically on
            -- registration.  Persistence lets a restart rehydrate the
            -- map without replaying every RegistrationTransaction from
            -- genesis.  entity_index is UNIQUE so duplicate assignment
            -- is impossible at the storage layer.
            CREATE TABLE IF NOT EXISTS entity_indices (
                entity_id BLOB PRIMARY KEY,
                entity_index INTEGER NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS idx_entity_indices_index
                ON entity_indices(entity_index);

            -- Finalized block checkpoints (long-range-attack defense).
            -- A (block_number, block_hash) pair persisted the moment a
            -- block accumulates 2/3-stake in FinalityVotes.  These are
            -- permanent, append-only: no reorg ever removes a row here.
            -- On cold restart, the blockchain rehydrates
            -- FinalityCheckpoints.finalized_hashes/by_height from this
            -- table, so the reorg-rejection rule (no chain may
            -- contradict a finalized block) survives the full process
            -- lifecycle.  Rows are small (32 B hash + 8 B height ≈ 40 B
            -- per entry, one every FINALITY_INTERVAL blocks) — at 100
            -- blocks/checkpoint and 600 s blocks that's ~525 rows/year.
            CREATE TABLE IF NOT EXISTS finalized_blocks (
                block_number INTEGER PRIMARY KEY,
                block_hash BLOB NOT NULL UNIQUE
            );

            -- Verified state checkpoints (bootstrap-speed sync).
            -- Every STATE_CHECKPOINT_INTERVAL blocks, validators sign
            -- StateCheckpoint(block_number, block_hash, state_root)
            -- and when >=2/3 of stake has signed, the result is stored
            -- here.  An archive node can serve these via the
            -- REQUEST_STATE_CHECKPOINT p2p message so a new full node
            -- can bootstrap without replaying ancient history.  The
            -- chain itself is permanent — this table is a cache of
            -- compact, signed snapshot commitments that new nodes
            -- trust as ground-truth for state at block N.
            --
            -- `checkpoint_blob` is StateCheckpoint.to_bytes() (fixed
            -- 72 bytes).  `signatures_blob` is a length-prefixed
            -- concatenation of StateCheckpointSignature.to_bytes()
            -- entries.  Kept as opaque BLOBs so the storage layer
            -- does not depend on the exact object shape — future
            -- scheme upgrades bump STATE_ROOT_VERSION without
            -- migrating the table.
            CREATE TABLE IF NOT EXISTS verified_state_checkpoints (
                block_number INTEGER PRIMARY KEY,
                checkpoint_blob BLOB NOT NULL,
                signatures_blob BLOB NOT NULL
            );

            -- Witness separation — stores witness data (WOTS signatures +
            -- Merkle auth paths) separately from block bodies for finalized
            -- blocks.  Full nodes strip witnesses from finalized blocks to
            -- save ~97% of block storage; witness-archive nodes keep this
            -- table populated.  Nothing is ever deleted — the data just
            -- moves to a separate tier.
            CREATE TABLE IF NOT EXISTS block_witnesses (
                block_hash BLOB PRIMARY KEY,
                witness_data BLOB NOT NULL
            );

            -- Equivocation-watcher observation store.  Records every
            -- signed block header and attestation that passed signature
            -- verification on arrival, keyed by
            -- (validator_id, block_height, round, message_type).  When a
            -- second distinct payload arrives for a key already present,
            -- the watcher constructs slashing evidence from the two
            -- stored payloads and broadcasts a SlashTransaction.
            --
            -- Why persistent (not in-memory): a node restart must not
            -- give an equivocator a free pass.  Otherwise a malicious
            -- validator could time double-signs around their target's
            -- node restarts.
            --
            -- Rolling 7-day window (UNBONDING_PERIOD = 1008 blocks at
            -- 600s).  Entries are pruned when
            --     first_seen_block_height < current_height - UNBONDING_PERIOD
            -- because any older observation is useless — the chain
            -- rejects evidence older than UNBONDING_PERIOD in
            -- Blockchain.validate_slash_transaction.  At ~144 validators
            -- × 1008 blocks × ~100 B/row the disk ceiling is ~15 MB.
            --
            -- `signed_payload` stores the fully-signed wire form
            -- (BlockHeader.to_bytes() or Attestation.to_bytes()) so the
            -- watcher can reconstruct evidence after a restart.
            CREATE TABLE IF NOT EXISTS seen_signatures (
                validator_id BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                round_number INTEGER NOT NULL DEFAULT 0,
                message_type TEXT NOT NULL,
                signed_payload BLOB NOT NULL,
                signature_bytes BLOB NOT NULL,
                first_seen_block_height INTEGER NOT NULL,
                PRIMARY KEY (validator_id, block_height, round_number, message_type)
            );
            CREATE INDEX IF NOT EXISTS idx_seen_sigs_first_seen
                ON seen_signatures(first_seen_block_height);
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

    def store_block(self, block: Block, state=None):
        """Store a block in its compact binary form.

        The `data` column is BLOB — the raw output of Block.to_bytes().
        This is ~2x smaller than the old JSON-with-hex-fields format
        (a WOTS signature drops from ~5.5 KB JSON to ~2 KB binary) and
        compounds forever in the permanent-history model.

        When `state` is provided, entity references in each embedded
        tx are serialized in their compact varint-index form instead
        of the legacy 32-byte id.  This is the bloat-reduction wire
        form actually hitting disk — without threading state through,
        the varint encoder silently falls back to full-id mode and
        saves nothing on the BLOB column.  `state` here is a duck-
        typed object exposing `entity_id_to_index` (typically the
        Blockchain instance owning the db).
        """
        data = block.to_bytes(state=state)
        self._conn.execute(
            "INSERT OR REPLACE INTO blocks (block_hash, block_number, prev_hash, data) VALUES (?, ?, ?, ?)",
            (block.block_hash, block.header.block_number, block.header.prev_hash, data),
        )
        self._maybe_commit()

    def get_block_by_hash(self, block_hash: bytes, state=None, include_witnesses=False) -> Block | None:
        """Get a block by hash.

        When `include_witnesses=True` and the block has been witness-
        stripped (witness data stored separately in block_witnesses),
        the witness data is reattached before returning.  Default is
        False — callers that need witness data must opt in.
        """
        cur = self._conn.execute("SELECT data FROM blocks WHERE block_hash = ?", (block_hash,))
        row = cur.fetchone()
        if row is None:
            return None
        block = Block.from_bytes(bytes(row[0]), state=state)
        if include_witnesses and self.has_witness_data(block_hash):
            from messagechain.core.witness import attach_block_witnesses
            witness_data = self.get_witness_data(block_hash)
            if witness_data is not None:
                block = attach_block_witnesses(block, witness_data)
        return block

    def get_block_by_number(self, block_number: int, state=None) -> Block | None:
        """Get block by height. If multiple at same height (forks), returns the one on the best chain.

        `state` (if provided) is threaded to `Block.from_bytes` so
        any compact-form entity refs can be resolved to their full
        32-byte ids.  Callers without a live state pass None and
        will fail loudly on any compact-form blob — which is the
        correct behavior for a standalone inspector.
        """
        cur = self._conn.execute(
            "SELECT data FROM blocks WHERE block_number = ? LIMIT 1",
            (block_number,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return Block.from_bytes(bytes(row[0]), state=state)

    def get_blocks_at_height(self, block_number: int, state=None) -> list[Block]:
        """Get all blocks at a given height (for fork detection)."""
        cur = self._conn.execute(
            "SELECT data FROM blocks WHERE block_number = ?", (block_number,)
        )
        return [Block.from_bytes(bytes(row[0]), state=state) for row in cur.fetchall()]

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

    def get_chain_from_tip(self, tip_hash: bytes, count: int, state=None) -> list[Block]:
        """Walk backwards from a tip, returning up to `count` blocks."""
        blocks = []
        current_hash = tip_hash
        while len(blocks) < count and current_hash:
            block = self.get_block_by_hash(current_hash, state=state)
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
        self._maybe_commit()

    def remove_chain_tip(self, block_hash: bytes):
        self._conn.execute("DELETE FROM chain_tips WHERE block_hash = ?", (block_hash,))
        self._maybe_commit()

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

    # ── State: Entity Index Registry (bloat reduction) ──────────

    def set_entity_index(self, entity_id: bytes, entity_index: int):
        """Persist a (entity_id, entity_index) pair.

        Idempotent: INSERT OR IGNORE preserves the first assignment.
        Indices are immutable once assigned — a second call with the
        same entity_id must not rewrite the stored index.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO entity_indices (entity_id, entity_index) "
            "VALUES (?, ?)",
            (entity_id, entity_index),
        )

    def get_entity_index(self, entity_id: bytes) -> int | None:
        cur = self._conn.execute(
            "SELECT entity_index FROM entity_indices WHERE entity_id = ?",
            (entity_id,),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def get_entity_id_by_index(self, entity_index: int) -> bytes | None:
        cur = self._conn.execute(
            "SELECT entity_id FROM entity_indices WHERE entity_index = ?",
            (entity_index,),
        )
        row = cur.fetchone()
        return bytes(row[0]) if row else None

    def get_all_entity_indices(self) -> dict[bytes, int]:
        cur = self._conn.execute(
            "SELECT entity_id, entity_index FROM entity_indices"
        )
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

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

    # ── State: Leaf Watermarks (WOTS+ reuse prevention) ─────────

    def get_leaf_watermark(self, entity_id: bytes) -> int:
        cur = self._conn.execute(
            "SELECT next_leaf FROM leaf_watermarks WHERE entity_id = ?",
            (entity_id,),
        )
        row = cur.fetchone()
        return row[0] if row else 0

    def set_leaf_watermark(self, entity_id: bytes, next_leaf: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO leaf_watermarks (entity_id, next_leaf) VALUES (?, ?)",
            (entity_id, next_leaf),
        )

    def get_all_leaf_watermarks(self) -> dict[bytes, int]:
        cur = self._conn.execute("SELECT entity_id, next_leaf FROM leaf_watermarks")
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

    # ── State: Authority Keys (cold-key withdrawal gating) ──────

    def get_authority_key(self, entity_id: bytes) -> bytes | None:
        cur = self._conn.execute(
            "SELECT authority_public_key FROM authority_keys WHERE entity_id = ?",
            (entity_id,),
        )
        row = cur.fetchone()
        return bytes(row[0]) if row else None

    def set_authority_key(self, entity_id: bytes, authority_public_key: bytes):
        self._conn.execute(
            "INSERT OR REPLACE INTO authority_keys (entity_id, authority_public_key) VALUES (?, ?)",
            (entity_id, authority_public_key),
        )

    def get_all_authority_keys(self) -> dict[bytes, bytes]:
        cur = self._conn.execute("SELECT entity_id, authority_public_key FROM authority_keys")
        return {bytes(row[0]): bytes(row[1]) for row in cur.fetchall()}

    # ── State: Revoked Entities (emergency kill-switch) ─────────

    def set_revoked(self, entity_id: bytes):
        self._conn.execute(
            "INSERT OR IGNORE INTO revoked_entities (entity_id) VALUES (?)",
            (entity_id,),
        )

    def is_revoked(self, entity_id: bytes) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM revoked_entities WHERE entity_id = ?", (entity_id,),
        )
        return cur.fetchone() is not None

    def get_all_revoked(self) -> set[bytes]:
        cur = self._conn.execute("SELECT entity_id FROM revoked_entities")
        return {bytes(row[0]) for row in cur.fetchall()}

    # ── State: Key Rotation Counts ──────────────────────────────

    def get_key_rotation_count(self, entity_id: bytes) -> int:
        cur = self._conn.execute(
            "SELECT rotation_number FROM key_rotation_counts WHERE entity_id = ?",
            (entity_id,),
        )
        row = cur.fetchone()
        return row[0] if row else 0

    def set_key_rotation_count(self, entity_id: bytes, rotation_number: int):
        self._conn.execute(
            "INSERT OR REPLACE INTO key_rotation_counts (entity_id, rotation_number) VALUES (?, ?)",
            (entity_id, rotation_number),
        )

    def get_all_key_rotation_counts(self) -> dict[bytes, int]:
        cur = self._conn.execute(
            "SELECT entity_id, rotation_number FROM key_rotation_counts"
        )
        return {bytes(row[0]): row[1] for row in cur.fetchall()}

    # ── State: WOTS+ Tree Heights per Entity ────────────────────

    def get_wots_tree_height(self, entity_id: bytes) -> int | None:
        cur = self._conn.execute(
            "SELECT tree_height FROM wots_tree_heights WHERE entity_id = ?",
            (entity_id,),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def set_wots_tree_height(self, entity_id: bytes, tree_height: int):
        # INSERT OR IGNORE preserves the set-once invariant at the
        # storage layer: even if a caller passes a different height
        # later, the first value wins and the entity's binding is as
        # immutable as its entity_id.
        self._conn.execute(
            "INSERT OR IGNORE INTO wots_tree_heights (entity_id, tree_height) "
            "VALUES (?, ?)",
            (entity_id, int(tree_height)),
        )

    def get_all_wots_tree_heights(self) -> dict[bytes, int]:
        cur = self._conn.execute(
            "SELECT entity_id, tree_height FROM wots_tree_heights"
        )
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

    # ── Phantom-Supply Migration (one-shot correctness repair) ──────────
    #
    # Earlier mainnet builds set GENESIS_SUPPLY = 1_000_000_000 while the
    # canonical allocation table only distributed 140_000_000 tokens
    # (founder 100M + treasury 40M).  The 860M gap was phantom — counted
    # in total_supply but owned by no entity — which broke the invariant
    #     total_supply == sum(balances) + sum(staked) + (minted - burned)
    # and inflated every "% of supply" denominator (fee model, governance
    # thresholds, analytics).
    #
    # The fix rebases GENESIS_SUPPLY to 140_000_000 in config.py.  But
    # existing mainnet state files have total_supply=1B persisted here
    # via _create_tables' initial INSERT (see _create_tables above).  A
    # joining validator or a restarting mainnet node needs a one-shot
    # migration that detects the anomaly and rebases on load.
    #
    # Detection: any stored total_supply that exceeds the correct
    # GENESIS_SUPPLY by EXACTLY 860_000_000 is the phantom-supply
    # signature — rebase by subtracting 860M.  Idempotent: after the
    # first run, stored == GENESIS_SUPPLY and the check is false.
    _PHANTOM_SUPPLY_GAP: int = 860_000_000

    def migrate_phantom_supply_if_needed(self) -> bool:
        """One-shot migration: detect legacy total_supply=1B and rebase
        to the corrected 140M value.

        Returns True iff a rebase actually occurred (phantom gap was
        detected).  Idempotent — subsequent calls after a successful
        rebase see the corrected value and return False.

        Called automatically from Blockchain._load_from_db on startup,
        so existing mainnet state gets repaired in place.  No-op on a
        fresh chain (total_supply already matches GENESIS_SUPPLY).
        """
        from messagechain.config import GENESIS_SUPPLY
        stored = self.get_supply_meta("total_supply")
        expected_gap = stored - GENESIS_SUPPLY
        # Also repair total_minted/total_burned nets: net_inflation
        # equals total_minted - total_burned, independent of the
        # constant rebase.  Only total_supply itself was inflated.
        if expected_gap == self._PHANTOM_SUPPLY_GAP:
            self.set_supply_meta("total_supply", stored - self._PHANTOM_SUPPLY_GAP)
            self._maybe_commit()
            return True
        return False

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

    def get_slashed_validators(self) -> set[bytes]:
        """Alias for get_all_slashed — used by restart-recovery paths."""
        return self.get_all_slashed()

    def set_slashed(self, entity_id: bytes, block_number: int = 0, evidence_hash: bytes = b"") -> None:
        """Persist a slashed-validator record. Convenience wrapper around
        add_slashed_validator that auto-commits for callers that don't batch.
        """
        self.add_slashed_validator(entity_id, block_number, evidence_hash or b"\x00" * 32)
        self._conn.commit()

    # ── Processed Slashing Evidence ─────────────────────────────────

    def mark_evidence_processed(self, evidence_hash: bytes, block_number: int = 0) -> None:
        """Record that a slashing-evidence tx has been processed, so the same
        evidence cannot be re-submitted to double-slash a validator.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO processed_evidence (evidence_hash, processed_at_block) VALUES (?, ?)",
            (evidence_hash, block_number),
        )
        self._conn.commit()

    def is_evidence_processed(self, evidence_hash: bytes) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM processed_evidence WHERE evidence_hash = ?",
            (evidence_hash,),
        )
        return cur.fetchone() is not None

    def get_all_processed_evidence(self) -> set[bytes]:
        cur = self._conn.execute("SELECT evidence_hash FROM processed_evidence")
        return {bytes(row[0]) for row in cur.fetchall()}

    # ── Pending Censorship Evidence ─────────────────────────────────

    def set_pending_censorship_evidence(
        self,
        evidence_hash: bytes,
        offender_id: bytes,
        tx_hash: bytes,
        admitted_height: int,
        evidence_tx_hash: bytes,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO pending_censorship_evidence "
            "(evidence_hash, offender_id, tx_hash, admitted_height, "
            "evidence_tx_hash) VALUES (?, ?, ?, ?, ?)",
            (evidence_hash, offender_id, tx_hash, admitted_height, evidence_tx_hash),
        )

    def remove_pending_censorship_evidence(self, evidence_hash: bytes) -> None:
        self._conn.execute(
            "DELETE FROM pending_censorship_evidence WHERE evidence_hash = ?",
            (evidence_hash,),
        )

    def get_all_pending_censorship_evidence(self) -> dict:
        """Return {evidence_hash -> (offender_id, tx_hash, admitted_height,
        evidence_tx_hash)}."""
        cur = self._conn.execute(
            "SELECT evidence_hash, offender_id, tx_hash, admitted_height, "
            "evidence_tx_hash FROM pending_censorship_evidence"
        )
        out: dict[bytes, tuple] = {}
        for row in cur.fetchall():
            out[bytes(row[0])] = (
                bytes(row[1]),
                bytes(row[2]),
                int(row[3]),
                bytes(row[4]),
            )
        return out

    # ── Receipt-subtree Roots ───────────────────────────────────────

    def set_receipt_subtree_root(
        self, entity_id: bytes, root_public_key: bytes,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO receipt_subtree_roots "
            "(entity_id, root_public_key) VALUES (?, ?)",
            (entity_id, root_public_key),
        )

    def get_all_receipt_subtree_roots(self) -> dict:
        cur = self._conn.execute(
            "SELECT entity_id, root_public_key FROM receipt_subtree_roots"
        )
        return {bytes(row[0]): bytes(row[1]) for row in cur.fetchall()}

    # ── Equivocation Watcher: Seen Signatures ───────────────────────

    def get_seen_signature(
        self,
        validator_id: bytes,
        block_height: int,
        round_number: int,
        message_type: str,
    ) -> tuple[bytes, bytes, int] | None:
        """Return (signed_payload, signature_bytes, first_seen_block_height)
        or None if no observation exists for the given key.
        """
        cur = self._conn.execute(
            "SELECT signed_payload, signature_bytes, first_seen_block_height "
            "FROM seen_signatures "
            "WHERE validator_id = ? AND block_height = ? "
            "  AND round_number = ? AND message_type = ?",
            (validator_id, block_height, round_number, message_type),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return (bytes(row[0]), bytes(row[1]), row[2])

    def add_seen_signature(
        self,
        validator_id: bytes,
        block_height: int,
        round_number: int,
        message_type: str,
        signed_payload: bytes,
        signature_bytes: bytes,
        first_seen_block_height: int,
    ) -> bool:
        """Record an observation.  Idempotent via INSERT OR IGNORE — the
        first payload seen for a given key is pinned; subsequent distinct
        payloads are NOT silently overwritten, because the equivocation
        detector needs to compare against the ORIGINAL observation to
        build evidence.
        """
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO seen_signatures "
            "(validator_id, block_height, round_number, message_type, "
            " signed_payload, signature_bytes, first_seen_block_height) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                validator_id, block_height, round_number, message_type,
                signed_payload, signature_bytes, first_seen_block_height,
            ),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def prune_seen_signatures_before(self, cutoff_block_height: int) -> int:
        """Delete seen_signatures rows with first_seen_block_height < cutoff.

        Returns the number of rows deleted.  Safe to call on every block:
        SQLite + the first_seen index makes this a cheap range DELETE,
        bounded by the ~1008-block rolling window.
        """
        cur = self._conn.execute(
            "DELETE FROM seen_signatures WHERE first_seen_block_height < ?",
            (cutoff_block_height,),
        )
        self._conn.commit()
        return cur.rowcount

    def count_seen_signatures(self) -> int:
        """Total rows in seen_signatures.  Used by tests + ops metrics."""
        cur = self._conn.execute("SELECT COUNT(*) FROM seen_signatures")
        return cur.fetchone()[0]

    # ── Finalized Block Checkpoints ─────────────────────────────

    def add_finalized_block(self, block_number: int, block_hash: bytes):
        """Persist a (block_number, block_hash) finality checkpoint.

        Idempotent via INSERT OR IGNORE — once a height is finalized,
        its hash is fixed for eternity; a second call with a different
        hash is ignored (the pre-existing row wins, which is the
        correct long-range-attack-defense semantic).
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO finalized_blocks "
            "(block_number, block_hash) VALUES (?, ?)",
            (block_number, block_hash),
        )
        self._conn.commit()

    def is_block_finalized(self, block_hash: bytes) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM finalized_blocks WHERE block_hash = ?",
            (block_hash,),
        )
        return cur.fetchone() is not None

    def get_finalized_block_at_height(self, block_number: int) -> bytes | None:
        cur = self._conn.execute(
            "SELECT block_hash FROM finalized_blocks WHERE block_number = ?",
            (block_number,),
        )
        row = cur.fetchone()
        return bytes(row[0]) if row else None

    def get_all_finalized_blocks(self) -> dict[int, bytes]:
        """Return {block_number: block_hash} for every finalized checkpoint."""
        cur = self._conn.execute(
            "SELECT block_number, block_hash FROM finalized_blocks"
        )
        return {row[0]: bytes(row[1]) for row in cur.fetchall()}

    # ── Verified State Checkpoints (bootstrap-speed sync) ───────────

    def add_verified_state_checkpoint(self, checkpoint, signatures) -> None:
        """Persist a verified (>=2/3 stake-signed) state checkpoint.

        `checkpoint` is a messagechain.consensus.state_checkpoint.StateCheckpoint.
        `signatures` is a list of StateCheckpointSignature.

        Idempotent per block_number: the first-stored checkpoint for a
        height wins (INSERT OR IGNORE).  A second call at the same
        height with different contents would mean the network has seen
        two verified checkpoints for one block, which is only possible
        if 2/3 of stake double-signed — a scenario that manifests as
        state_ckpt_double_sign slashing evidence, not as a silent
        database row replacement.
        """
        import struct as _s
        cp_blob = checkpoint.to_bytes()
        parts = [_s.pack(">I", len(signatures))]
        for sig in signatures:
            sb = sig.to_bytes()
            parts.append(_s.pack(">I", len(sb)))
            parts.append(sb)
        sigs_blob = b"".join(parts)
        self._conn.execute(
            "INSERT OR IGNORE INTO verified_state_checkpoints "
            "(block_number, checkpoint_blob, signatures_blob) VALUES (?, ?, ?)",
            (checkpoint.block_number, cp_blob, sigs_blob),
        )
        self._conn.commit()

    def get_verified_state_checkpoint(self, block_number: int):
        """Return (StateCheckpoint, [StateCheckpointSignature, ...]) or None."""
        import struct as _s
        from messagechain.consensus.state_checkpoint import (
            StateCheckpoint, StateCheckpointSignature,
        )
        cur = self._conn.execute(
            "SELECT checkpoint_blob, signatures_blob "
            "FROM verified_state_checkpoints WHERE block_number = ?",
            (block_number,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        cp = StateCheckpoint.from_bytes(bytes(row[0]))
        sigs_blob = bytes(row[1])
        off = 0
        (n,) = _s.unpack_from(">I", sigs_blob, off); off += 4
        signatures = []
        for _ in range(n):
            (ln,) = _s.unpack_from(">I", sigs_blob, off); off += 4
            signatures.append(
                StateCheckpointSignature.from_bytes(sigs_blob[off:off + ln])
            )
            off += ln
        return cp, signatures

    def get_latest_verified_state_checkpoint_height(self) -> int | None:
        cur = self._conn.execute(
            "SELECT MAX(block_number) FROM verified_state_checkpoints"
        )
        row = cur.fetchone()
        return row[0] if row and row[0] is not None else None

    def get_all_verified_state_checkpoint_heights(self) -> list[int]:
        cur = self._conn.execute(
            "SELECT block_number FROM verified_state_checkpoints "
            "ORDER BY block_number"
        )
        return [row[0] for row in cur.fetchall()]

    # ── Batch Operations (for state snapshots / reorgs) ──────────

    def save_state_snapshot(self) -> dict:
        """Capture full state for rollback during reorg.

        leaf_watermarks is captured for the record but must not be
        reduced on restore — WOTS+ leaves, once published, are burned
        permanently regardless of whether the containing block survives.
        authority_keys IS rolled back: a SetAuthorityKey tx that ends up
        on a discarded fork must have its effect reverted.
        """
        return {
            "balances": self.get_all_balances(),
            "staked": self.get_all_staked(),
            "nonces": self.get_all_nonces(),
            "public_keys": self.get_all_public_keys(),
            "message_counts": self.get_all_message_counts(),
            "proposer_sig_counts": self.get_all_proposer_sig_counts(),
            "leaf_watermarks": self.get_all_leaf_watermarks(),
            "authority_keys": self.get_all_authority_keys(),
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
            # Authority keys revert with the block that set them. Keys set
            # on a fork that lost the reorg must not persist silently.
            conn.execute("DELETE FROM authority_keys")
            # NOTE: leaf_watermarks and revoked_entities are intentionally
            # NOT wiped — they are security ratchets that never decrease.

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
            for eid, ak in snapshot.get("authority_keys", {}).items():
                conn.execute(
                    "INSERT INTO authority_keys (entity_id, authority_public_key) VALUES (?, ?)",
                    (eid, ak),
                )

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

    def _txn_depth(self) -> int:
        """Thread-local counter: how many begin_transaction scopes are
        currently nested.  Enables atomic composition of higher-level
        chain-write sequences (see _apply_mainnet_genesis_state and
        initialize_genesis) without rewriting the dozens of mutator
        methods that currently call _conn.commit() directly — only the
        OUTER begin commits; inner begin_transaction calls by
        _persist_state become no-ops at depth > 0.
        """
        return int(getattr(self._local, "txn_depth", 0))

    def _in_txn(self) -> bool:
        return self._txn_depth() > 0

    def _maybe_commit(self):
        """Commit iff no wrapping begin_transaction is active."""
        if not self._in_txn():
            self._conn.commit()

    def begin_transaction(self):
        if self._txn_depth() == 0:
            # Flush any implicit autocommit txn the sqlite3 module may
            # have auto-opened on a prior INSERT (default
            # isolation_level="" autostarts on DML).  Without this,
            # `BEGIN` raises "cannot start a transaction within a
            # transaction" when the outer scope runs right after
            # _init_schema's INSERTs or similar setup writes.
            if self._conn.in_transaction:
                self._conn.commit()
            self._conn.execute("BEGIN")
        self._local.txn_depth = self._txn_depth() + 1

    def commit_transaction(self):
        d = self._txn_depth()
        if d <= 0:
            # Tolerate spurious commit — historically some paths called
            # commit_transaction without a matching BEGIN.
            self._conn.commit()
            return
        self._local.txn_depth = d - 1
        if self._local.txn_depth == 0:
            self._conn.commit()

    def rollback_transaction(self):
        # Rollback always unwinds the entire transaction stack — SQLite
        # doesn't support nested rollbacks without SAVEPOINTs, and the
        # callers here (genesis / IBD) treat any failure as fatal.
        self._local.txn_depth = 0
        self._conn.rollback()

    # ── Witness Separation (block witness data) ─────────────────────

    def store_witness_data(self, block_hash: bytes, witness_data: bytes):
        """Store witness data (signatures + auth paths) for a block.

        Idempotent: INSERT OR REPLACE so re-storing is safe.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO block_witnesses "
            "(block_hash, witness_data) VALUES (?, ?)",
            (block_hash, witness_data),
        )
        self._conn.commit()

    def get_witness_data(self, block_hash: bytes) -> bytes | None:
        """Get stored witness data for a block, or None."""
        cur = self._conn.execute(
            "SELECT witness_data FROM block_witnesses WHERE block_hash = ?",
            (block_hash,),
        )
        row = cur.fetchone()
        return bytes(row[0]) if row else None

    def has_witness_data(self, block_hash: bytes) -> bool:
        """Check if separate witness data exists for a block."""
        cur = self._conn.execute(
            "SELECT 1 FROM block_witnesses WHERE block_hash = ?",
            (block_hash,),
        )
        return cur.fetchone() is not None

    def strip_finalized_witnesses(self, block_hash: bytes, state=None):
        """Retroactively strip witnesses from a stored finalized block.

        Reads the full block, extracts witness data into block_witnesses,
        then overwrites the blocks row with the stripped form.  The
        original block data is NOT deleted — it is replaced in-place
        with the smaller stripped form.  Witness data moves to the
        block_witnesses table so it can be served to auditors on demand.
        """
        from messagechain.core.witness import (
            get_block_witness_data, strip_block_witnesses,
        )
        cur = self._conn.execute(
            "SELECT data FROM blocks WHERE block_hash = ?",
            (block_hash,),
        )
        row = cur.fetchone()
        if row is None:
            return  # block not found or already pruned

        block = Block.from_bytes(bytes(row[0]), state=state)

        # Extract witness data
        witness_data = get_block_witness_data(block)

        # Strip witnesses from block
        stripped = strip_block_witnesses(block)
        stripped_bytes = stripped.to_bytes(state=state)

        # Store witness data separately
        self._conn.execute(
            "INSERT OR REPLACE INTO block_witnesses "
            "(block_hash, witness_data) VALUES (?, ?)",
            (block_hash, witness_data),
        )

        # Replace full block with stripped block
        self._conn.execute(
            "UPDATE blocks SET data = ? WHERE block_hash = ?",
            (stripped_bytes, block_hash),
        )
        self._conn.commit()

    def auto_separate_finalized_witnesses(
        self, finalized_height: int, state=None,
    ) -> int:
        """Move witnesses of old finalized blocks to the side table.

        Opt-in via WITNESS_AUTO_SEPARATION_ENABLED.  When disabled
        (the default) this is a no-op — the current storage shape
        is preserved byte-for-byte and no existing block-read caller
        silently loses access to inline signatures.

        When enabled, every block at height <=
        (finalized_height - WITNESS_RETENTION_BLOCKS) whose witness
        data is still inline gets re-organized: signatures move from
        the `blocks.data` BLOB to the `block_witnesses` side table.
        Nothing is deleted — the message payload, timestamp, and
        entity_id stay in place forever; only the WOTS sig bytes
        move.  A caller that needs the full block still passes
        `include_witnesses=True` to get_block_by_hash.

        Idempotent: skips blocks already separated (identified by a
        row in block_witnesses).  Safe to call on every finality
        advance.

        Returns the number of blocks separated in this call.
        """
        import messagechain.config as _cfg
        if not getattr(_cfg, "WITNESS_AUTO_SEPARATION_ENABLED", False):
            return 0

        retention = _cfg.WITNESS_RETENTION_BLOCKS
        horizon = finalized_height - retention
        if horizon < 0:
            return 0

        # Candidate blocks: finalized depth past the retention window
        # AND not yet separated.  LEFT JOIN is cheap — the blocks
        # table is indexed on block_hash and block_witnesses is
        # keyed on the same hash.
        cur = self._conn.execute(
            "SELECT b.block_hash FROM blocks b "
            "LEFT JOIN block_witnesses w ON b.block_hash = w.block_hash "
            "WHERE b.block_number <= ? AND w.block_hash IS NULL",
            (horizon,),
        )
        candidates = [bytes(row[0]) for row in cur.fetchall()]

        count = 0
        for block_hash in candidates:
            self.strip_finalized_witnesses(block_hash, state=state)
            count += 1
        return count
