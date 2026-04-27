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


_SCHEMA_VERSION = 3
# v1 -> v2 changelog (cold-restart-persistence class, rounds 7/13/14/
# 15/17/18 of the pre-launch audit):
#   * Added tables: pending_unstakes, key_history, reputation,
#     stake_snapshots.
#   * Added supply_meta keys: blocks_since_last_finalization,
#     lottery_prize_pool.
# All of these were consensus-visible in-memory state in v1 that
# `_load_from_db` did not rebuild, which on a cold restart produced
# a different state than uprestarted peers and forked the restarted
# node off the honest chain at the next lottery / finality / slash
# block.  v2 persists them explicitly.
#
# Migration shape: a v1 DB opened under a v2 binary has all the
# balance/staked/nonce/supply_meta invariants already correct
# (those were always persisted) but the six new state surfaces
# are empty.  `migrate_schema_v1_to_v2` replays the persisted
# blocks through an in-memory Blockchain to repopulate them from
# history, then bumps the `schema_version` meta row.  Operators on
# v1 DBs are pointed at `messagechain migrate-chain-db` in the
# startup error rather than silently getting an incomplete state.
#
# v2 -> v3 changelog (Tier 10 prev-pointer feature):
#   * Added table: tx_locations — indexes every MessageTransaction
#     tx_hash to the (block_height, tx_index) where it landed.  The
#     strict-prev validator needs an O(1) lookup to answer "does this
#     tx_hash resolve to a prior on-chain tx?" — O(chain_length) walks
#     would make the feature untenable once the chain grows.
# Migration shape: index is backfilled by replaying persisted blocks
# and recording each message tx's position.  Non-destructive; idempotent
# (re-running on v3 is a no-op because the schema_version tripwire
# rejects the v3->v3 open before migration is reachable).


class ChainDB:
    """SQLite-backed block and state storage."""

    def __init__(
        self,
        db_path: str = "messagechain.db",
        *,
        skip_schema_check: bool = False,
    ):
        """Open a chain.db.

        ``skip_schema_check=True`` bypasses the schema-version
        tripwire — used ONLY by the `migrate-chain-db` CLI path so
        it can open a v1 DB to run `migrate_schema_v1_to_v2`.  Every
        other caller (Blockchain __init__, tests, the server
        startup path) leaves this at the default and takes the
        actionable error if the DB isn't at the binary's expected
        version.
        """
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()
        self._check_db_permissions()
        if not skip_schema_check:
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
            # Actionable startup error: point the operator at the CLI
            # migration rather than printing a cryptic mismatch.  The
            # specific v1 -> v2 path is safe, non-destructive, and
            # covered by `migrate_schema_v1_to_v2` below; anything
            # further out should halt here and require an explicit
            # ops-authored migration function before it's allowed to
            # open.
            if on_disk == 1 and _SCHEMA_VERSION == 2:
                raise RuntimeError(
                    f"chain.db schema version mismatch: disk=1, "
                    f"code=2.  This binary adds six consensus-visible "
                    f"cold-restart persistence surfaces (reputation, "
                    f"key_history, pending_unstakes, stake_snapshots, "
                    f"blocks_since_last_finalization, "
                    f"lottery_prize_pool).  Run the one-shot migration "
                    f"before starting the node:\n\n"
                    f"    messagechain migrate-chain-db "
                    f"--data-dir <path-containing-chain.db>\n\n"
                    f"The migration replays block history through an "
                    f"in-memory Blockchain to repopulate the six new "
                    f"state surfaces from persisted blocks -- it is "
                    f"non-destructive and idempotent."
                )
            if on_disk == 2 and _SCHEMA_VERSION == 3:
                raise RuntimeError(
                    f"chain.db schema version mismatch: disk=2, "
                    f"code=3.  This binary adds the `tx_locations` "
                    f"index (Tier 10 prev-pointer feature) — maps every "
                    f"MessageTransaction tx_hash to the "
                    f"(block_height, tx_index) where it was included, "
                    f"enabling O(1) strict-prev resolution.  Run the "
                    f"one-shot migration before starting the node:\n\n"
                    f"    messagechain migrate-chain-db "
                    f"--data-dir <path-containing-chain.db>\n\n"
                    f"The migration walks persisted blocks and records "
                    f"each message tx's location -- non-destructive "
                    f"and idempotent."
                )
            raise RuntimeError(
                f"chain.db schema version mismatch: disk={on_disk}, "
                f"code={_SCHEMA_VERSION}.  A migration is required before "
                f"this binary can open this database — do NOT downgrade "
                f"or upgrade across versions without running the migration."
            )

    def migrate_schema_v1_to_v2(self) -> dict:
        """Replay chain history to populate v2-new state surfaces.

        v1 -> v2 added six consensus-visible state surfaces that
        `_load_from_db` cannot reconstruct without replaying blocks:
        `reputation`, `key_history`, `pending_unstakes`,
        `stake_snapshots`, `blocks_since_last_finalization`,
        `lottery_prize_pool`.  An operator upgrading the binary
        without this migration gets empty versions of each and
        diverges consensus at the first lottery / finality / slash
        block after restart.

        Strategy: build an in-memory Blockchain pointed at a
        temporary *detached* ChainDB (to avoid double-writes back
        to the file we're migrating), replay every persisted block
        in order so the in-memory state accumulates the six
        surfaces, then copy the accumulated state into the on-disk
        DB and bump the schema_version row.

        Non-destructive: the only table we rewrite is
        `meta.schema_version`; the six target tables / supply_meta
        rows are cleared first (in case a partial prior migration
        left stale rows) and then repopulated.  Every other v1
        table is untouched.

        Idempotent: running twice on a v2 DB is a no-op because
        `_check_and_write_schema_version` rejects the v2->v2 open
        at the standard "no mismatch" path before we ever reach
        here (the migration is only callable via the CLI).

        Returns a summary dict for the CLI to print.
        """
        from messagechain.core.blockchain import Blockchain

        # Force the current schema_version back to 1 in memory so
        # the migration can actually examine a v1 DB -- the
        # __init__ tripwire would otherwise have blocked us.
        # (The CLI opens us with an explicit "migration" flag that
        # bypasses the tripwire.)

        # Step 1: Rebuild an in-memory Blockchain from the
        # persisted blocks.  We route it at a scratch db so its
        # own writes don't double-commit into the live file.
        import tempfile
        import os as _os
        scratch_dir = tempfile.mkdtemp(prefix="mc_migrate_")
        scratch_path = _os.path.join(scratch_dir, "scratch.db")
        # Stamp the scratch DB to v2 so it doesn't itself trigger
        # the tripwire.  The scratch file is discarded at the end.
        scratch_db = ChainDB(scratch_path)

        rebuilt = Blockchain(db=scratch_db)

        # Pre-seed entity-index mappings from the v1 DB so compact
        # entity-refs in post-genesis blocks can be decoded before
        # the replay loop walks the registrations.  Without this,
        # `get_block_by_number` at the first height that references
        # a non-genesis entity by index raises
        # `entity ref uses unknown index N (state lacks mapping)`
        # and the whole migration aborts — because `rebuilt` is a
        # fresh Blockchain pointed at a scratch DB, so its maps
        # start empty while the on-disk `entity_indices` table is
        # fully populated.
        persisted_indices = self.get_all_entity_indices()
        if persisted_indices:
            rebuilt.entity_id_to_index = dict(persisted_indices)
            rebuilt.entity_index_to_id = {
                idx: eid for eid, idx in persisted_indices.items()
            }
            rebuilt._next_entity_index = max(persisted_indices.values()) + 1

        # Copy v1 state (balances, staked, etc.) into `rebuilt` so
        # block replay starts from the live state.  Simpler: just
        # replay every block from 0.
        block_count = self.get_block_count()
        for height in range(block_count):
            block = self.get_block_by_number(height, state=rebuilt)
            if block is None:
                continue
            if height == 0:
                # Genesis is initialized fresh by the Blockchain
                # constructor's pipeline; skip re-applying block 0
                # to avoid the "genesis already applied" guard.
                continue
            rebuilt._apply_block_state(block)
            rebuilt.chain.append(block)

        # Step 2: Copy the six new state surfaces from the rebuilt
        # in-memory Blockchain into this (v1-on-disk) ChainDB.
        conn = self._conn
        conn.execute("BEGIN")
        try:
            # Clear then repopulate the six surfaces.
            conn.execute("DELETE FROM reputation")
            for eid, count in rebuilt.reputation.items():
                conn.execute(
                    "INSERT INTO reputation (entity_id, count) "
                    "VALUES (?, ?)",
                    (eid, int(count)),
                )
            conn.execute("DELETE FROM key_history")
            for eid, entries in rebuilt.key_history.items():
                for installed_at, public_key in entries:
                    conn.execute(
                        "INSERT INTO key_history "
                        "(entity_id, installed_at, public_key) "
                        "VALUES (?, ?, ?)",
                        (eid, int(installed_at), public_key),
                    )
            conn.execute("DELETE FROM pending_unstakes")
            for eid, tickets in rebuilt.supply.pending_unstakes.items():
                for amount, release_block in tickets:
                    conn.execute(
                        "INSERT INTO pending_unstakes "
                        "(entity_id, release_block, amount) "
                        "VALUES (?, ?, ?)",
                        (eid, int(release_block), int(amount)),
                    )
            conn.execute("DELETE FROM stake_snapshots")
            for block_number, stake_map in rebuilt._stake_snapshots.items():
                for entity_id, amount in stake_map.items():
                    conn.execute(
                        "INSERT INTO stake_snapshots "
                        "(block_number, entity_id, amount) "
                        "VALUES (?, ?, ?)",
                        (int(block_number), entity_id, int(amount)),
                    )
            # Two scalar supply_meta keys.
            conn.execute(
                "INSERT OR REPLACE INTO supply_meta (key, value) "
                "VALUES (?, ?)",
                (
                    "blocks_since_last_finalization",
                    int(rebuilt.blocks_since_last_finalization),
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO supply_meta (key, value) "
                "VALUES (?, ?)",
                (
                    "lottery_prize_pool",
                    int(rebuilt.supply.lottery_prize_pool),
                ),
            )
            # Step 3: stamp the new schema version LAST so a crash
            # mid-migration leaves the DB at v1 and the operator's
            # next start re-runs the migration (idempotent).
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", str(2)),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            # Scratch DB cleanup.
            try:
                sc = getattr(scratch_db._local, "conn", None)
                if sc is not None:
                    sc.close()
            except Exception:
                pass
            try:
                import shutil as _shutil
                _shutil.rmtree(scratch_dir, ignore_errors=True)
            except Exception:
                pass

        return {
            "schema_from": 1,
            "schema_to": 2,
            "blocks_replayed": max(0, block_count - 1),
            "reputation_entries": len(rebuilt.reputation),
            "key_history_entities": len(rebuilt.key_history),
            "pending_unstake_entities": len(
                rebuilt.supply.pending_unstakes,
            ),
            "stake_snapshots_heights": len(rebuilt._stake_snapshots),
            "blocks_since_last_finalization": (
                rebuilt.blocks_since_last_finalization
            ),
            "lottery_prize_pool": rebuilt.supply.lottery_prize_pool,
        }

    def migrate_schema_v2_to_v3(self) -> dict:
        """Backfill the tx_locations index from persisted blocks.

        v2 -> v3 adds the Tier 10 prev-pointer feature's per-tx index
        (tx_hash -> (block_height, tx_index)) so strict-prev validation
        resolves in O(1).  The table is append-only and derived entirely
        from existing block storage, so the migration just walks every
        persisted block and records each MessageTransaction's position.

        Non-destructive: only writes to `tx_locations` (created fresh by
        `_init_schema` on the v3 binary) and bumps the `meta.schema_version`
        row.  Every other table is untouched.

        Idempotent: running on a v3 DB is blocked by the schema_version
        tripwire before this function is reachable.  Within the migration
        we use INSERT OR REPLACE so a partial-prior migration's rows are
        overwritten cleanly on re-run from the CLI.
        """
        conn = self._conn
        block_count = self.get_block_count()
        total_tx_indexed = 0
        conn.execute("BEGIN")
        try:
            conn.execute("DELETE FROM tx_locations")
            for height in range(block_count):
                # Pass state=None — at migration time we don't have a
                # live Blockchain to resolve compact entity refs.  If a
                # block uses the compact form, it'll raise; the v1->v2
                # path handles that case by threading a rebuilt state,
                # but for v2->v3 the tx_locations population only needs
                # tx_hash + block_hash + height + index, none of which
                # depend on entity-id resolution.  If decode fails for
                # that reason, fall back to a state-threaded path.
                try:
                    block = self.get_block_by_number(height, state=None)
                except Exception:
                    # Rebuild state for compact-ref resolution.  Lazy
                    # import to avoid the circular dep at module load.
                    from messagechain.core.blockchain import Blockchain
                    import tempfile as _tempfile
                    import os as _os
                    scratch_dir = _tempfile.mkdtemp(prefix="mc_v3_migrate_")
                    scratch_path = _os.path.join(scratch_dir, "scratch.db")
                    scratch_db = ChainDB(scratch_path)
                    rebuilt = Blockchain(db=scratch_db)
                    persisted_indices = self.get_all_entity_indices()
                    if persisted_indices:
                        rebuilt.entity_id_to_index = dict(persisted_indices)
                        rebuilt.entity_index_to_id = {
                            idx: eid for eid, idx in persisted_indices.items()
                        }
                        rebuilt._next_entity_index = (
                            max(persisted_indices.values()) + 1
                        )
                    block = self.get_block_by_number(height, state=rebuilt)
                if block is None:
                    continue
                for tx_index, tx in enumerate(block.transactions):
                    conn.execute(
                        "INSERT OR REPLACE INTO tx_locations "
                        "(tx_hash, block_hash, block_height, tx_index) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            tx.tx_hash,
                            block.block_hash,
                            height,
                            tx_index,
                        ),
                    )
                    total_tx_indexed += 1
            # Stamp the schema version LAST so a crash mid-migration
            # leaves the DB at v2 and the operator's next start re-runs
            # the migration cleanly.
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", str(3)),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return {
            "schema_from": 2,
            "schema_to": 3,
            "blocks_walked": block_count,
            "tx_locations_indexed": total_tx_indexed,
        }

    # ── tx_locations helpers (Tier 10 prev-pointer) ──────────────────

    def record_tx_location(
        self,
        tx_hash: bytes,
        block_hash: bytes,
        block_height: int,
        tx_index: int,
    ) -> None:
        """Record where a message tx landed.  Idempotent under fork replay."""
        self._conn.execute(
            "INSERT OR REPLACE INTO tx_locations "
            "(tx_hash, block_hash, block_height, tx_index) "
            "VALUES (?, ?, ?, ?)",
            (tx_hash, block_hash, block_height, tx_index),
        )
        self._maybe_commit()

    def get_tx_location(self, tx_hash: bytes) -> tuple[int, int] | None:
        """Return (block_height, tx_index) for the earliest block this
        tx_hash appears in, or None if it's not in the index.

        "Earliest" = lowest block_height, breaking ties by block_hash
        (deterministic).  Callers that need the full (block_hash, height,
        index) tuple can use the raw table; strict-prev only needs
        existence + height for the "strictly earlier block" check.
        """
        cur = self._conn.execute(
            "SELECT block_height, tx_index FROM tx_locations "
            "WHERE tx_hash = ? ORDER BY block_height ASC, block_hash ASC "
            "LIMIT 1",
            (tx_hash,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return (int(row[0]), int(row[1]))

    def get_message_author(self, tx_hash: bytes, state=None) -> bytes | None:
        """Return the authoring entity_id of the MessageTransaction at
        `tx_hash`, or None if `tx_hash` is not a MessageTransaction in
        canonical chain history.

        Used by the Tier 27 message-react admission rule to reject a
        ReactTx whose voter is also the target message's author.  The
        lookup chains tx_locations (O(1)) → get_block_by_number (one
        block load) → block.transactions[tx_index] → entity_id; cost is
        amortized by SQLite's row cache for hot-tip blocks.  Returns
        None if the location is missing, the block load fails, the
        in-block tx is not a MessageTransaction (e.g. a confused caller
        passes a transfer/stake tx_hash), or its `entity_id` is unset.

        `state` MUST be the live Blockchain when blocks were stored in
        compact entity-ref form (the standard production path) — without
        it, the block decoder cannot resolve the varint indices back to
        full 32-byte entity_ids and Block.from_bytes raises.  Callers
        on the consensus path pass `state=self` (the Blockchain).
        """
        loc = self.get_tx_location(tx_hash)
        if loc is None:
            return None
        block_height, tx_index = loc
        try:
            blk = self.get_block_by_number(block_height, state=state)
        except Exception:
            # Compact-form decode without a state map raises ValueError.
            # Treat any decode failure as "author unknown" rather than
            # propagating — admission paths fall back to admitting
            # under the conservative "author cannot be confirmed equal
            # to voter" interpretation, which keeps the gate from
            # blocking legitimate non-self reacts when state is missing.
            return None
        if blk is None:
            return None
        if tx_index < 0 or tx_index >= len(blk.transactions):
            return None
        tx = blk.transactions[tx_index]
        if tx.tx_hash != tx_hash:
            return None
        # MessageTransaction stores its author under `entity_id` (the
        # signer/sender of the message).  Non-message txs landing at
        # this tx_index would not match the tx_hash check above; this
        # getattr is defence-in-depth.
        author = getattr(tx, "entity_id", None)
        if author is None or len(author) != 32:
            return None
        return bytes(author)

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

            -- Pending unbonding tickets for every validator that has
            -- called unstake() but whose UNBONDING_PERIOD hasn't elapsed.
            -- Tokens have been debited from `staked` but not yet
            -- credited back to `balances` — they live here in the
            -- meantime.  Consensus-critical: without persistence,
            -- process_pending_unstakes(block_height) runs on a cold-
            -- booted node with an empty queue while uprestarted peers
            -- release the real tokens, producing a state_root mismatch
            -- and forking the restarted node off the honest chain.
            -- Composite key (entity_id, release_block) lets a single
            -- entity stack multiple concurrent unstakes.
            CREATE TABLE IF NOT EXISTS pending_unstakes (
                entity_id BLOB NOT NULL,
                release_block INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                PRIMARY KEY (entity_id, release_block)
            );

            CREATE TABLE IF NOT EXISTS nonces (
                entity_id BLOB PRIMARY KEY,
                nonce INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS public_keys (
                entity_id BLOB PRIMARY KEY,
                public_key BLOB NOT NULL
            );

            -- Per-entity public-key rotation history.  Append-only log
            -- of (installed_at, public_key) tuples: one entry per
            -- first-spend install + one per key rotation.  Used by
            -- `validate_slash_transaction` to look up the
            -- PRE-rotation pubkey an equivocation was signed under, so
            -- a validator that equivocates at height M and then
            -- rotates at height N > M can still be slashed with
            -- evidence signed by the old key.  Consensus-critical:
            -- without persistence, cold-restart empties the history,
            -- `_public_key_at_height` falls back to the CURRENT
            -- (post-rotation) pubkey, WOTS+ verify against old-key-
            -- signed evidence fails, and the restarted node rejects
            -- a slash block uprestarted peers accept — state_root
            -- divergence + silent slash evasion.  Composite PK allows
            -- multiple rotations for the same entity at distinct
            -- heights; repeated installs at the exact same height are
            -- a no-op under INSERT OR REPLACE (replay fidelity with
            -- the in-memory list, where duplicates at the same height
            -- are tolerated but not deduped).
            CREATE TABLE IF NOT EXISTS key_history (
                entity_id BLOB NOT NULL,
                installed_at INTEGER NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (entity_id, installed_at)
            );

            -- Per-entity accepted-attestation counter that drives the
            -- bootstrap-era reputation-weighted lottery.  Every
            -- LOTTERY_INTERVAL block, `select_lottery_winner` reads
            -- the current reputation map and picks a winner who
            -- receives a `bounty + pool_payout` mint/redirect -- the
            -- winner's balance changes, total_supply / total_minted
            -- bump, so the reputation input is fully consensus-
            -- visible.  Consensus-critical: without persistence, a
            -- cold-booted peer starts with an empty map,
            -- `select_lottery_winner(candidates=[], ...)` returns
            -- None, no bounty is paid, balances diverge from
            -- uprestarted peers, and the restarted peer forks off at
            -- the next lottery firing.  Same structural shape as the
            -- `pending_unstakes` / `key_history` cold-restart fixes.
            CREATE TABLE IF NOT EXISTS reputation (
                entity_id BLOB PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );

            -- Tier 23 / Tier 24 honesty-curve repeat-offense counter.
            -- Per-validator count of successfully-applied slashes.  Read
            -- by `slashing_severity` to grade severity for the next
            -- offense — a repeat offender is slashed harder than a
            -- first-timer (UNAMBIGUOUS repeat ⇒ 100%; AMBIGUOUS repeat
            -- escalates linearly).  The Tier 24 perfect-record amnesty
            -- ALSO bumps the counter (single-shot: the next AMBIGUOUS
            -- incident sees prior=1 and falls back to standard
            -- severity).  Consensus-critical post-HONESTY_CURVE_RATE_HEIGHT:
            -- without persistence, a cold-booted node starts with an
            -- empty map, `slashing_severity` returns different
            -- `slash_pct` than uprestarted peers on the next slash tx,
            -- and `supply.staked[offender]` diverges → state_root
            -- diverges → chain split.  `CREATE TABLE IF NOT EXISTS` is
            -- the migration path: a v3 chain.db opened under a
            -- newer binary auto-creates the empty table and starts
            -- accumulating counts going forward.  Pre-existing chains
            -- that have already applied slashes will rebuild the
            -- counter on first replay (counter is derived state — every
            -- successful `apply_slash_transaction` increments it).
            CREATE TABLE IF NOT EXISTS slash_offense_counts (
                entity_id BLOB PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS message_counts (
                entity_id BLOB PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );

            -- Per-block pinned stake distributions used as the 2/3
            -- finality denominator in `_process_attestations` and
            -- `_process_finality_votes`.  Consensus-critical: the
            -- finality-vote path can target a block up to
            -- FINALITY_VOTE_MAX_AGE_BLOCKS (=1000) slots back, and
            -- the threshold-crossing predicate must use the stake
            -- distribution AS-OF the target block (not post-churn
            -- live state) or validators who unstaked after casting
            -- are silently dropped from the denominator and the
            -- `crossed` decision diverges.  Without persistence, a
            -- cold-booted peer loses every historical snapshot and
            -- falls back to live stakes -- uprestarted peers reach
            -- finality on blocks restarted peers don't, and
            -- `finalized_checkpoints` (the long-range-attack
            -- ratchet) diverges irreversibly.  Bounded: pruned to
            -- the trailing FINALITY_VOTE_MAX_AGE_BLOCKS window on
            -- every insert, so table size is O(1000 * |validators|)
            -- regardless of chain length.
            CREATE TABLE IF NOT EXISTS stake_snapshots (
                block_number INTEGER NOT NULL,
                entity_id BLOB NOT NULL,
                amount INTEGER NOT NULL,
                PRIMARY KEY (block_number, entity_id)
            );
            CREATE INDEX IF NOT EXISTS idx_stake_snapshots_block
                ON stake_snapshots(block_number);

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

            -- Per-entity height of the most-recent applied KeyRotation,
            -- driving the KEY_ROTATION_COOLDOWN_BLOCKS gate in
            -- validate_key_rotation.  Prior to this table the map was
            -- in-memory-only -- a cold-booted node rehydrated empty
            -- and would accept a rotation the warm cluster rejected,
            -- silently forking.  Included in the state-root commitment
            -- (v18) and mirrored here for cold-boot rehydration.
            CREATE TABLE IF NOT EXISTS key_rotation_last_height (
                entity_id BLOB PRIMARY KEY,
                block_height INTEGER NOT NULL
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
                evidence_tx_hash BLOB NOT NULL,
                -- Offender's staked balance at admission time.  The
                -- slash amount at maturity is computed from THIS
                -- value, not current stake, so an unstake during the
                -- EVIDENCE_MATURITY_BLOCKS window can't shrink the
                -- realized penalty.  Added 2026-04-21; legacy rows
                -- migrated via ALTER TABLE below.
                staked_at_admission INTEGER NOT NULL DEFAULT 0
            );

            -- Per-validator receipt-subtree root public keys.  A
            -- 32-byte pubkey per registered entity identifies the WOTS+
            -- subtree the validator uses to sign submission receipts.
            -- Separate from public_keys (block-signing root).
            CREATE TABLE IF NOT EXISTS receipt_subtree_roots (
                entity_id BLOB PRIMARY KEY,
                root_public_key BLOB NOT NULL
            );

            -- Per-validator HISTORICAL receipt-subtree roots.  When an
            -- entity rotates their receipt subtree via
            -- SetReceiptSubtreeRoot, the OLD root is appended here so
            -- evidence validation (CensorshipEvidence, BogusRejection,
            -- ack registry) can still admit receipts issued under it.
            -- Without this history, a coerced validator who has issued
            -- many receipts under R1 could wipe ALL outstanding
            -- evidence by publishing a single rotation tx to R2.
            -- Composite primary key so multiple historical roots per
            -- entity are stored side-by-side; the rolling-history set
            -- is rebuilt by SELECTing all rows for a given entity.
            CREATE TABLE IF NOT EXISTS past_receipt_subtree_roots (
                entity_id BLOB NOT NULL,
                root_public_key BLOB NOT NULL,
                PRIMARY KEY (entity_id, root_public_key)
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
            -- Rolling window tied to UNBONDING_PERIOD (~15 days at
            -- 600s post-slash-evasion-fix; ~7 days pre-fix).  Entries
            -- are pruned when
            --     first_seen_block_height < current_height - UNBONDING_PERIOD
            -- because any older observation is useless — the chain
            -- rejects evidence older than UNBONDING_PERIOD in
            -- Blockchain.validate_slash_transaction.  At ~144 validators
            -- × 2176 blocks × ~100 B/row the disk ceiling is ~31 MB.
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

            -- Tier 10 prev-pointer feature: per-tx index mapping every
            -- MessageTransaction tx_hash to the block_height and
            -- in-block tx_index where it was included.  Strict-prev
            -- validation resolves a tx's `prev` pointer via this index
            -- in O(1) rather than walking block history on every check.
            -- Populated on store_block; entries are append-only under
            -- normal operation.  Permanent history means no pruning.
            --
            -- block_hash is stored alongside so fork-aware lookups can
            -- distinguish multiple inclusions of the same tx across
            -- competing blocks at the same height (rare; strict-prev
            -- only requires existence in some persisted block).
            CREATE TABLE IF NOT EXISTS tx_locations (
                tx_hash BLOB NOT NULL,
                block_hash BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                PRIMARY KEY (tx_hash, block_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_tx_locations_hash
                ON tx_locations(tx_hash);

            -- Tier 17 ReactTransaction state: ground-truth per-pair
            -- (voter, target, target_is_user) -> latest_choice map.
            -- Per-target aggregates (user_trust_score, message_score)
            -- are NOT persisted; they're rebuilt from this map at
            -- restore time so the invariant
            --   aggregate == sum_of_pairs(choices)
            -- is enforced at load and cannot drift through hand-edits
            -- to one half of the pair.  Composite PK keeps user-trust
            -- and message-react votes in distinct rows even when the
            -- 32-byte target value coincides between an entity_id and
            -- a tx_hash.  CLEAR entries (choice == 0) are never stored
            -- — absent ≡ CLEAR — so the table only carries non-zero
            -- contributions.
            CREATE TABLE IF NOT EXISTS reaction_choices (
                voter_id BLOB NOT NULL,
                target BLOB NOT NULL,
                target_is_user INTEGER NOT NULL,
                choice INTEGER NOT NULL,
                PRIMARY KEY (voter_id, target, target_is_user)
            );
        """)
        conn.commit()

        # ── Schema migrations ─────────────────────────────────────
        # Additive column migrations for running chain.db files that
        # were created before today's hardening landed.  SQLite has
        # no IF NOT EXISTS on ALTER TABLE, so we introspect first.
        # Each migration is idempotent: running on a fresh db (where
        # CREATE TABLE already included the column) is a no-op.
        def _has_column(table: str, col: str) -> bool:
            cur = conn.execute(f"PRAGMA table_info({table})")
            return any(row[1] == col for row in cur.fetchall())

        if not _has_column("pending_censorship_evidence", "staked_at_admission"):
            # 2026-04-21 hardening: slash-at-admission fix requires
            # a per-row snapshot of the offender's `staked` balance
            # at admission time.  Default 0 for legacy rows (the
            # pre-fix chain.db may contain them); on the post-reset
            # mainnet there are no rows to migrate.
            conn.execute(
                "ALTER TABLE pending_censorship_evidence "
                "ADD COLUMN staked_at_admission INTEGER NOT NULL DEFAULT 0"
            )
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
        # Tier 10 prev-pointer: populate tx_locations index for every
        # message tx in this block.  Idempotent via INSERT OR REPLACE —
        # re-storing a block under fork replay cleanly refreshes its
        # rows.  Non-message txs (governance, transfer, etc.) are
        # currently not indexed; the prev-pointer feature only
        # references MessageTransaction tx_hashes.
        from messagechain.core.transaction import MessageTransaction
        for tx_index, tx in enumerate(block.transactions):
            if isinstance(tx, MessageTransaction):
                self._conn.execute(
                    "INSERT OR REPLACE INTO tx_locations "
                    "(tx_hash, block_hash, block_height, tx_index) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        tx.tx_hash,
                        block.block_hash,
                        block.header.block_number,
                        tx_index,
                    ),
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

    # ── State: Pending Unstakes ──────────────────────────────────
    # Unbonding queue per validator.  Tokens here have been debited
    # from `staked` but are not yet in `balances`; they sit for
    # UNBONDING_PERIOD blocks before process_pending_unstakes releases
    # them.  The table must be kept in lockstep with
    # SupplyTracker.pending_unstakes — every queue insert in
    # SupplyTracker.unstake() must mirror into add_pending_unstake(),
    # and every matured release in process_pending_unstakes() must
    # call clear_pending_unstake() for the (entity_id, release_block)
    # composite key.

    def add_pending_unstake(
        self, entity_id: bytes, amount: int, release_block: int,
    ) -> None:
        """Persist one pending unstake ticket.

        Uses INSERT OR REPLACE so a re-apply of the same (entity,
        release_block) pair overwrites rather than duplicating —
        matches the in-memory list semantics where a second append at
        the exact same release_block is unreachable in normal flow but
        deterministic under reorg replay.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO pending_unstakes "
            "(entity_id, release_block, amount) VALUES (?, ?, ?)",
            (entity_id, int(release_block), int(amount)),
        )
        self._maybe_commit()

    def clear_pending_unstake(
        self, entity_id: bytes, release_block: int,
    ) -> None:
        """Delete one matured or slashed pending-unstake ticket."""
        self._conn.execute(
            "DELETE FROM pending_unstakes "
            "WHERE entity_id = ? AND release_block = ?",
            (entity_id, int(release_block)),
        )
        self._maybe_commit()

    def clear_all_pending_unstakes(self, entity_id: bytes) -> None:
        """Delete every pending-unstake ticket for an entity (slash path)."""
        self._conn.execute(
            "DELETE FROM pending_unstakes WHERE entity_id = ?",
            (entity_id,),
        )
        self._maybe_commit()

    def get_all_pending_unstakes(
        self,
    ) -> dict[bytes, list[tuple[int, int]]]:
        """Rehydrate the full pending-unstakes map on cold start.

        Returns `{entity_id: [(amount, release_block), ...]}` with
        release_block ordering preserved (ascending), matching the
        in-memory list shape SupplyTracker expects.
        """
        cur = self._conn.execute(
            "SELECT entity_id, amount, release_block "
            "FROM pending_unstakes "
            "ORDER BY entity_id, release_block",
        )
        out: dict[bytes, list[tuple[int, int]]] = {}
        for eid, amount, release_block in cur.fetchall():
            out.setdefault(bytes(eid), []).append(
                (int(amount), int(release_block)),
            )
        return out

    # ── State: Stake Snapshots (per-block finality denominator) ──
    # Must mirror `Blockchain._stake_snapshots`.  Every
    # `_record_stake_snapshot(block_number)` call on the Blockchain
    # side routes through `add_stake_snapshot` here when a db
    # handle is attached.  Pruning keeps the persisted tail bounded
    # to FINALITY_VOTE_MAX_AGE_BLOCKS so a decades-old chain
    # doesn't carry a stake-snapshot row for every entity at every
    # historical height -- anything older than that window cannot
    # be a valid finality-vote target anyway.

    def add_stake_snapshot(
        self, block_number: int, stakes: dict[bytes, int],
    ) -> None:
        """Persist one (block_number, entity_id, amount) row per
        entity in the supplied stake map.

        INSERT OR REPLACE so a re-apply of the same block overwrites
        cleanly (matches the in-memory `self._stake_snapshots
        [block_number] = dict(self.supply.staked)` replace-on-write
        semantics).
        """
        for entity_id, amount in stakes.items():
            self._conn.execute(
                "INSERT OR REPLACE INTO stake_snapshots "
                "(block_number, entity_id, amount) VALUES (?, ?, ?)",
                (int(block_number), entity_id, int(amount)),
            )
        self._maybe_commit()

    def prune_stake_snapshots_before(self, height_cutoff: int) -> None:
        """Delete every stake_snapshots row with block_number <
        height_cutoff.  Bounds the table to a trailing window so a
        long-running chain doesn't accumulate snapshots forever.
        """
        self._conn.execute(
            "DELETE FROM stake_snapshots WHERE block_number < ?",
            (int(height_cutoff),),
        )
        self._maybe_commit()

    def get_all_stake_snapshots(
        self,
    ) -> dict[int, dict[bytes, int]]:
        """Rehydrate the full stake-snapshots map on cold start.

        Returns ``{block_number: {entity_id: amount, ...}, ...}`` --
        the same shape `Blockchain._stake_snapshots` holds in memory.
        Bounded by whatever the most recent `prune_stake_snapshots_
        before` left behind (≤ FINALITY_VOTE_MAX_AGE_BLOCKS entries
        under normal operation).
        """
        cur = self._conn.execute(
            "SELECT block_number, entity_id, amount "
            "FROM stake_snapshots "
            "ORDER BY block_number, entity_id",
        )
        out: dict[int, dict[bytes, int]] = {}
        for block_number, entity_id, amount in cur.fetchall():
            out.setdefault(int(block_number), {})[
                bytes(entity_id)
            ] = int(amount)
        return out

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

    # ── State: Reaction Choices (Tier 17) ────────────────────────
    # The (voter, target, target_is_user) -> choice ground truth.
    # Aggregates are derived at restore time, not persisted.

    def set_reaction_choice(
        self,
        voter_id: bytes,
        target: bytes,
        target_is_user: bool,
        choice: int,
    ) -> None:
        """Upsert one (voter, target, target_is_user) -> choice row.

        ``choice`` must be one of REACT_CHOICE_UP / REACT_CHOICE_DOWN.
        CLEAR entries are NEVER persisted — call ``clear_reaction_choice``
        to remove a row instead.  Mirrors the in-memory rule
        ``absent ≡ CLEAR``.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO reaction_choices "
            "(voter_id, target, target_is_user, choice) "
            "VALUES (?, ?, ?, ?)",
            (voter_id, target, 1 if target_is_user else 0, int(choice)),
        )

    def clear_reaction_choice(
        self,
        voter_id: bytes,
        target: bytes,
        target_is_user: bool,
    ) -> None:
        """Delete one row — used when a CLEAR vote retracts a prior UP/DOWN."""
        self._conn.execute(
            "DELETE FROM reaction_choices "
            "WHERE voter_id = ? AND target = ? AND target_is_user = ?",
            (voter_id, target, 1 if target_is_user else 0),
        )

    def clear_all_reaction_choices(self) -> None:
        """Wipe the entire reaction_choices table.

        Round-13 fix: used by `Blockchain._persist_state`'s full-flush
        path (post `_reset_state`, post-reorg replay) to drop every
        row before re-INSERTing the canonical-replay choices.  The
        round-12 dirty-key flush leaves rows that existed only on a
        rolled-back fork on disk -- after the next cold restart
        `_load_from_db` rehydrates the orphan vote, mixes it into
        `state_root_contribution()`, and the restarted node silently
        forks off peers that didn't restart.  Wiping here closes the
        successful-reorg twin of the round-12 failed-reorg fix in
        `restore_state_snapshot`.

        Caller is expected to be inside an outer
        `begin_transaction` scope (the one `_persist_state` opens),
        so the DELETE rides the same SQL transaction as the
        subsequent re-INSERTs and is atomic with them.  No
        `_maybe_commit` here.
        """
        self._conn.execute("DELETE FROM reaction_choices")

    def get_all_reaction_choices(
        self,
    ) -> dict[tuple[bytes, bytes, bool], int]:
        """Rehydrate the full reaction-choices map on cold start.

        Returns ``{(voter_id, target, target_is_user): choice, ...}`` —
        the exact shape `ReactionState.choices` holds in memory.  The
        aggregates (`user_trust_score`, `message_score`) are rebuilt
        from this map at load time via
        `ReactionState.deserialize`-style replay, so the on-disk
        representation cannot drift from the in-memory derived state.
        """
        cur = self._conn.execute(
            "SELECT voter_id, target, target_is_user, choice "
            "FROM reaction_choices"
        )
        out: dict[tuple[bytes, bytes, bool], int] = {}
        for voter_id, target, target_is_user, choice in cur.fetchall():
            out[(bytes(voter_id), bytes(target), bool(target_is_user))] = int(choice)
        return out

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

    # ── State: Key Rotation History ──────────────────────────────
    # Append-only audit log of every public-key install for every
    # entity.  Must stay in lockstep with
    # `Blockchain.key_history` — every `_record_key_history` call on
    # the Blockchain side must mirror into `add_key_history_entry`
    # here, and the full dict is rehydrated on cold start via
    # `get_all_key_history()`.  See the `key_history` table comment
    # in the schema block for the slash-evasion / consensus-divergence
    # rationale.

    def add_key_history_entry(
        self, entity_id: bytes, installed_at: int, public_key: bytes,
    ) -> None:
        """Persist one (entity_id, installed_at) → public_key entry.

        INSERT OR REPLACE mirrors the in-memory list's behaviour:
        the Blockchain side deliberately does not guard against
        duplicate inserts at the same height (replay fidelity is
        more important than deduplication), so repeated calls at the
        same height overwrite rather than error.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO key_history "
            "(entity_id, installed_at, public_key) VALUES (?, ?, ?)",
            (entity_id, int(installed_at), public_key),
        )
        self._maybe_commit()

    def clear_key_history(self, entity_id: bytes) -> None:
        """Delete every key_history row for an entity.

        Used by the reorg-rollback path: when a replay re-applies
        installs from genesis forward, the DB rows from the old
        history must be cleared first so the replay doesn't leave
        stale (height, pubkey) pairs that a later
        `_public_key_at_height` lookup could incorrectly resolve to.
        """
        self._conn.execute(
            "DELETE FROM key_history WHERE entity_id = ?",
            (entity_id,),
        )
        self._maybe_commit()

    def get_all_key_history(
        self,
    ) -> dict[bytes, list[tuple[int, bytes]]]:
        """Rehydrate the full key_history map on cold start.

        Returns ``{entity_id: [(installed_at, public_key), ...]}``
        with entries ordered ascending by ``installed_at`` so
        `_public_key_at_height` can walk them in forward-order (the
        same shape the in-memory list holds after a linear replay).
        """
        cur = self._conn.execute(
            "SELECT entity_id, installed_at, public_key "
            "FROM key_history "
            "ORDER BY entity_id, installed_at",
        )
        out: dict[bytes, list[tuple[int, bytes]]] = {}
        for eid, installed_at, public_key in cur.fetchall():
            out.setdefault(bytes(eid), []).append(
                (int(installed_at), bytes(public_key)),
            )
        return out

    # ── State: Reputation ────────────────────────────────────────
    # Per-entity accepted-attestation count driving the bootstrap
    # reputation-weighted lottery.  Must mirror
    # `Blockchain.reputation` in lockstep: every increment in
    # `_process_attestations` and every reset in
    # `apply_slash_transaction` routes through here when a db handle
    # is attached.  On cold start `_load_from_db` rehydrates the full
    # dict via `get_all_reputation()` — without this the restarted
    # peer starts empty, `select_lottery_winner` returns None, no
    # bounty is paid, and the balance diverges from uprestarted peers
    # at the next lottery firing.

    def set_reputation(self, entity_id: bytes, count: int) -> None:
        """Upsert the reputation counter for an entity."""
        self._conn.execute(
            "INSERT OR REPLACE INTO reputation (entity_id, count) "
            "VALUES (?, ?)",
            (entity_id, int(count)),
        )
        self._maybe_commit()

    def clear_reputation(self, entity_id: bytes) -> None:
        """Delete the reputation row for an entity (slash path)."""
        self._conn.execute(
            "DELETE FROM reputation WHERE entity_id = ?",
            (entity_id,),
        )
        self._maybe_commit()

    def get_all_reputation(self) -> dict[bytes, int]:
        """Rehydrate the full reputation map on cold start."""
        cur = self._conn.execute(
            "SELECT entity_id, count FROM reputation",
        )
        return {bytes(row[0]): int(row[1]) for row in cur.fetchall()}

    # ── State: Slash Offense Counts (Tier 23/24 honesty curve) ───
    # Per-validator slash-applied counter driving the
    # `slashing_severity` repeat-offense escalation + Tier 24 rate
    # erosion.  Must mirror `Blockchain.slash_offense_counts` in
    # lockstep: every increment in `apply_slash_transaction` (and
    # the inclusion-list-violation slash path) routes through here
    # via `_bump_slash_offense_count` when a db handle is attached.
    # On cold start `_load_from_db` rehydrates the full dict via
    # `get_all_slash_offense_counts()` -- without this, the
    # restarted peer starts empty, `slashing_severity` returns a
    # different slash_pct on the next slash tx vs. uprestarted
    # peers, and `supply.staked[offender]` diverges → state_root
    # diverges → chain split.  Mirror of the reputation pattern
    # immediately above.

    def set_slash_offense_count(
        self, entity_id: bytes, count: int,
    ) -> None:
        """Upsert the slash-offense counter for an entity."""
        self._conn.execute(
            "INSERT OR REPLACE INTO slash_offense_counts "
            "(entity_id, count) VALUES (?, ?)",
            (entity_id, int(count)),
        )
        self._maybe_commit()

    def clear_slash_offense_count(self, entity_id: bytes) -> None:
        """Delete the slash-offense row for an entity.

        Used by the reorg-rollback path when a slash tx that bumped
        the counter ends up on a discarded fork.
        """
        self._conn.execute(
            "DELETE FROM slash_offense_counts WHERE entity_id = ?",
            (entity_id,),
        )
        self._maybe_commit()

    def get_all_slash_offense_counts(self) -> dict[bytes, int]:
        """Rehydrate the full slash-offense map on cold start."""
        cur = self._conn.execute(
            "SELECT entity_id, count FROM slash_offense_counts",
        )
        return {bytes(row[0]): int(row[1]) for row in cur.fetchall()}

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

    # -- State: Key-rotation last heights (cooldown gate) -----------

    def set_key_rotation_last_height(
        self, entity_id: bytes, block_height: int,
    ):
        self._conn.execute(
            "INSERT OR REPLACE INTO key_rotation_last_height "
            "(entity_id, block_height) VALUES (?, ?)",
            (entity_id, int(block_height)),
        )

    def get_all_key_rotation_last_height(self) -> dict[bytes, int]:
        cur = self._conn.execute(
            "SELECT entity_id, block_height FROM key_rotation_last_height",
        )
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

    # ── Finalization-stall counter ───────────────────────────────
    # The number of blocks since the most recent finalization.
    # Consensus-critical because `_apply_block_state` reads this
    # counter to decide whether the inactivity leak activates, and
    # (if active) scales the per-validator burn QUADRATICALLY with
    # the counter — so a cold-restart that resets the counter to 0
    # silently stops the burn on the restarted peer while uprestarted
    # peers continue burning, diverging `supply.staked` +
    # `supply.total_supply` + state_root.  Rides the existing
    # `supply_meta` key/value table (no new schema), with the key
    # "blocks_since_last_finalization".  Dedicated wrapper pair
    # below so the mutation site in Blockchain stays single-line
    # and includes the `_maybe_commit` that `set_supply_meta` on
    # its own omits.

    def get_finalization_stall_counter(self) -> int:
        """Return the persisted finalization-stall counter (0 if unset)."""
        return int(self.get_supply_meta("blocks_since_last_finalization"))

    def set_finalization_stall_counter(self, value: int) -> None:
        """Persist the finalization-stall counter.  Idempotent upsert."""
        self.set_supply_meta("blocks_since_last_finalization", int(value))
        self._maybe_commit()

    # ── Lottery Prize Pool ───────────────────────────────────────
    # Consensus-visible scalar accumulator for the seed-divestment
    # redistribution lottery (post-SEED_DIVESTMENT_REDIST_HEIGHT).
    # Accumulated at REDIST-era divestment blocks, drained into the
    # lottery winner's balance at every LOTTERY_INTERVAL firing.
    # Rides the existing `supply_meta` key/value table under the key
    # "lottery_prize_pool" (no new schema needed for a single
    # scalar).  Without persistence, cold-restart zeros the pool on
    # the restarted peer while uprestarted peers carry the
    # accumulated value -- next lottery firing pays different
    # amounts to the winner, `supply.balances` diverges, state_root
    # mismatches.  Sixth in the cold-restart-persistence class after
    # pending_unstakes / key_history / reputation /
    # blocks_since_last_finalization / stake_snapshots.

    def get_lottery_prize_pool(self) -> int:
        """Return the persisted lottery prize pool (0 if unset)."""
        return int(self.get_supply_meta("lottery_prize_pool"))

    def set_lottery_prize_pool(self, value: int) -> None:
        """Persist the lottery prize pool.  Idempotent upsert."""
        self.set_supply_meta("lottery_prize_pool", int(value))
        self._maybe_commit()

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
        self._maybe_commit()

    # ── Processed Slashing Evidence ─────────────────────────────────

    def mark_evidence_processed(self, evidence_hash: bytes, block_number: int = 0) -> None:
        """Record that a slashing-evidence tx has been processed, so the same
        evidence cannot be re-submitted to double-slash a validator.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO processed_evidence (evidence_hash, processed_at_block) VALUES (?, ?)",
            (evidence_hash, block_number),
        )
        self._maybe_commit()

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
        staked_at_admission: int = 0,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO pending_censorship_evidence "
            "(evidence_hash, offender_id, tx_hash, admitted_height, "
            "evidence_tx_hash, staked_at_admission) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                evidence_hash, offender_id, tx_hash, admitted_height,
                evidence_tx_hash, int(staked_at_admission),
            ),
        )

    def remove_pending_censorship_evidence(self, evidence_hash: bytes) -> None:
        self._conn.execute(
            "DELETE FROM pending_censorship_evidence WHERE evidence_hash = ?",
            (evidence_hash,),
        )

    def get_all_pending_censorship_evidence(self) -> dict:
        """Return {evidence_hash -> (offender_id, tx_hash, admitted_height,
        evidence_tx_hash, staked_at_admission)}."""
        cur = self._conn.execute(
            "SELECT evidence_hash, offender_id, tx_hash, admitted_height, "
            "evidence_tx_hash, staked_at_admission "
            "FROM pending_censorship_evidence"
        )
        out: dict[bytes, tuple] = {}
        for row in cur.fetchall():
            out[bytes(row[0])] = (
                bytes(row[1]),
                bytes(row[2]),
                int(row[3]),
                bytes(row[4]),
                int(row[5]) if row[5] is not None else 0,
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

    def add_past_receipt_subtree_root(
        self, entity_id: bytes, root_public_key: bytes,
    ) -> None:
        """Append a historical receipt-subtree root for an entity.

        Idempotent (composite PK + INSERT OR IGNORE): re-rotating
        through the same prior root is a no-op at the storage layer.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO past_receipt_subtree_roots "
            "(entity_id, root_public_key) VALUES (?, ?)",
            (entity_id, root_public_key),
        )

    def get_all_past_receipt_subtree_roots(self) -> dict:
        """Return {entity_id -> set[root_public_key]} of all historical
        roots ever installed for each entity.  Used at cold-restart
        rehydration so receipt-validation can still admit receipts
        under any past root."""
        cur = self._conn.execute(
            "SELECT entity_id, root_public_key "
            "FROM past_receipt_subtree_roots"
        )
        out: dict[bytes, set[bytes]] = {}
        for row in cur.fetchall():
            out.setdefault(bytes(row[0]), set()).add(bytes(row[1]))
        return out

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
        self._maybe_commit()
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
        self._maybe_commit()
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
        self._maybe_commit()

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
        self._maybe_commit()

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
            # pending_unstakes must round-trip with the other supply
            # state: a reorg that rolls past an unstake tx (but not past
            # its maturity block) has to restore the ticket so the
            # re-applied chain releases the same tokens at the same
            # height a peer who never forked would.  Without this, a
            # reorg-and-restore silently clears the queue and diverges
            # consensus at the next `process_pending_unstakes`.
            "pending_unstakes": self.get_all_pending_unstakes(),
            # key_history must round-trip with public_keys: a reorg
            # that rolls past a key-rotation block has to restore
            # the pre-rotation entry so post-reorg slash-evidence
            # lookups at pre-rotation heights still resolve to the
            # correct pubkey.  See the `key_history` table comment
            # in the schema block for the full consensus rationale.
            "key_history": self.get_all_key_history(),
            # reputation must round-trip with supply state because
            # lottery payouts debit/credit supply.balances and the
            # winner is a function of this map; a reorg that rolls
            # past attestations must restore the pre-reorg counts
            # so the post-reorg replay converges on the same winner.
            "reputation": self.get_all_reputation(),
            # slash_offense_counts mirror table (Tier 23/24 honesty
            # curve).  Must round-trip with supply state because the
            # severity grading at slash-apply time reads this map; a
            # reorg that rolls past a slash-tx block must restore the
            # pre-reorg counts so post-reorg replay computes the
            # identical slash_pct on the canonical chain.  Same defect
            # class as the reputation mirror above.
            "slash_offense_counts": self.get_all_slash_offense_counts(),
            # Per-block pinned stake snapshots used as the 2/3
            # finality denominator.  Must round-trip with supply
            # state: a reorg that rolls past any block whose stake
            # pin we've already consumed (or will consume for a
            # finality vote targeting that height) has to restore
            # the ancestor's snapshot so post-reorg replay converges
            # on the same crossing decision.
            "stake_snapshots": self.get_all_stake_snapshots(),
            # Finalization-stall counter — scalar input to the
            # quadratic inactivity leak.  Must round-trip with supply
            # state because a reorg that rolls past the finalization-
            # reset block has to restore the pre-reorg counter, or
            # the post-reorg replay computes a different burn than
            # peers that never forked.
            "blocks_since_last_finalization": (
                self.get_finalization_stall_counter()
            ),
            # Lottery prize pool -- scalar input to
            # `select_lottery_winner` + pool_payout math at every
            # LOTTERY_INTERVAL firing.  Must round-trip with supply
            # state because payouts mutate supply.balances, so the
            # pool's value at the fork point must be restored on
            # reorg rollback.
            "lottery_prize_pool": self.get_lottery_prize_pool(),
            # Receipt-subtree mirror tables: round-8 fix.  Pre-fix
            # `restore_state_snapshot` DELETEd these tables (correctly,
            # to flush losing-fork rotations) but the snapshot dict
            # didn't carry them, so the post-restore DB had empty
            # mirrors.  In-memory state was correct, but a process
            # exit before the next `_persist_state` flushed left a
            # cold-restart node rehydrating from empty maps -> silent
            # fork on the next contested CensorshipEvidence /
            # BogusRejection (cold-restart node rejected evidence the
            # warm cluster admitted under the issuer's registered
            # root).  Same defect class as the round-2
            # entity_id_to_index and round-4 key_rotation_last_height
            # leaks; the round-7 fix moved the WRITE path inside
            # `_persist_state` but did not close the save/restore
            # asymmetry.
            "receipt_subtree_roots": self.get_all_receipt_subtree_roots(),
            "past_receipt_subtree_roots": (
                self.get_all_past_receipt_subtree_roots()
            ),
            # key_rotation_last_height mirror table: same round-8 fix.
            # `restore_state_snapshot` DELETEs the table (to roll back
            # losing-fork rotations) but the snapshot dict didn't
            # carry it.  Cold restart in the post-restore window
            # rehydrated an empty map -> rotation-cooldown gate
            # (KEY_ROTATION_COOLDOWN_BLOCKS) silently bypassed on the
            # restarted node, while warm nodes still enforce.  The
            # round-4 fix added the chaindb mirror to defeat the
            # cold-boot inheritance gap; this round-8 fix closes the
            # remaining save/restore asymmetry.
            "key_rotation_last_height": (
                self.get_all_key_rotation_last_height()
            ),
            # Round-12 fix: reaction_choices mirror table (Tier 17).
            # Pre-fix `restore_state_snapshot` did NOT wipe this table
            # at all -- a successful reorg across a block carrying
            # a ReactTransaction left the losing-fork vote permanently
            # on disk.  Cold restart of any node that processed the
            # losing fork rehydrates the orphan choice, which mixes
            # into `state_root_contribution()` and produces a
            # divergent state root vs. the warm cluster -> silent
            # consensus fork on the next block.  Same defect class as
            # the round-2 entity_id_to_index, round-4
            # key_rotation_last_height, and round-7
            # receipt_subtree_roots leaks.  Snapshot now carries the
            # full reaction_choices map AND restore wipes+re-inserts
            # the table inside the same SQL transaction.
            "reaction_choices": self.get_all_reaction_choices(),
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
            # Pending-unstakes mirror the supply-state balances/staked
            # that we just wiped — restore them alongside so the
            # validator unbonding queue reflects the ancestor state.
            conn.execute("DELETE FROM pending_unstakes")
            # key_history must roll back with public_keys: a
            # SetAuthorityKey / KeyRotation / first-spend install
            # on the losing fork must have its history entry
            # reverted, or post-reorg `_public_key_at_height`
            # lookups would resolve to a key the canonical chain
            # never installed.
            conn.execute("DELETE FROM key_history")
            # reputation mirrors attestation counts -- must roll
            # back with them so the post-reorg replay rebuilds from
            # the ancestor's state, not the losing fork's.
            conn.execute("DELETE FROM reputation")
            # slash_offense_counts mirrors slash-tx applications.
            # Same reorg-safety reasoning as reputation: a slash-tx
            # block on the losing fork must NOT leave a stale +1
            # row on disk, or post-reorg `slashing_severity` calls
            # would grade the next offense against a phantom prior
            # the canonical chain never observed.  Same defect class
            # as the reputation / receipt-subtree-roots mirror leaks.
            conn.execute("DELETE FROM slash_offense_counts")
            # stake_snapshots pin the 2/3 finality denominator at
            # each block's apply -- must roll back with the blocks
            # themselves so post-reorg replay repopulates pins
            # consistent with the canonical chain.
            conn.execute("DELETE FROM stake_snapshots")
            # key_rotation_last_height mirrors the in-memory cooldown
            # gate.  v18 added the on-disk mirror so a cold-booted
            # node inherits the cooldown state it would otherwise
            # lose (the `_reset_state` comment notes restart timing
            # is not attacker-controllable, but a stale mirror IS).
            # Must wipe alongside the rest of the canonical-chain
            # rebuildable state -- if a rotation that landed only on
            # the losing fork keeps its (higher) row on disk, a cold
            # restart of any reorg-survivor node would re-hydrate the
            # stale row and enforce a different cooldown than the
            # warm cluster.  The snapshot root commits to
            # `_TAG_KEY_ROTATION_LAST_HEIGHT`, so the divergence
            # surfaces as an immediate consensus split at the next
            # checkpoint block.  Same defect class as the
            # entity_id_to_index reorg leak; this is the second
            # mirror table that needed to join the wipe list after
            # being added.
            conn.execute("DELETE FROM key_rotation_last_height")
            # receipt_subtree_roots mirrors the in-memory map of each
            # validator's published receipt-issuance subtree root.
            # CensorshipEvidenceTx + BogusRejectionEvidenceTx
            # validation gate on `receipt_subtree_roots[offender]`,
            # so a stale row from a losing fork (e.g. a
            # SetReceiptSubtreeRoot that landed only on the fork
            # we're reorging out of) leaves the cold-restarted node
            # rejecting evidence the warm cluster accepts (or vice
            # versa) -- silent consensus split on every evidence
            # decision involving that entity.  Same defect class as
            # the round-2 entity_id_to_index leak and round-4
            # key_rotation_last_height leak; this is the third such
            # mirror table that needed to join the wipe list.
            # past_receipt_subtree_roots (added for the rotation-
            # invalidates-evidence fix) is wiped alongside since it's
            # derived from the same canonical-chain replay -- old-
            # fork rotation history must not survive.
            conn.execute("DELETE FROM receipt_subtree_roots")
            conn.execute("DELETE FROM past_receipt_subtree_roots")
            # Round-12 fix: reaction_choices mirror table (Tier 17)
            # joins the wipe list.  Each ReactTransaction landed on
            # the losing fork mutates `reaction_choices` rows; on
            # successful reorg the in-memory `reaction_state` is
            # rebuilt from canonical replay but the disk rows for the
            # losing-fork votes survive without this DELETE.  The
            # next cold restart rehydrates the orphan choices
            # (`_load_from_db` calls `get_all_reaction_choices`),
            # `state_root_contribution()` then mixes them, and the
            # restarted node silently forks at the next block whose
            # state root the warm cluster computes WITHOUT those
            # entries.  Same defect class as the four mirror tables
            # already wiped above.  Re-inserts happen after the
            # canonical replays restore the supply state below.
            conn.execute("DELETE FROM reaction_choices")
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
            for eid, tickets in snapshot.get("pending_unstakes", {}).items():
                for amount, release_block in tickets:
                    conn.execute(
                        "INSERT INTO pending_unstakes "
                        "(entity_id, release_block, amount) "
                        "VALUES (?, ?, ?)",
                        (eid, int(release_block), int(amount)),
                    )
            for eid, entries in snapshot.get("key_history", {}).items():
                for installed_at, public_key in entries:
                    conn.execute(
                        "INSERT INTO key_history "
                        "(entity_id, installed_at, public_key) "
                        "VALUES (?, ?, ?)",
                        (eid, int(installed_at), public_key),
                    )
            for eid, count in snapshot.get("reputation", {}).items():
                conn.execute(
                    "INSERT INTO reputation (entity_id, count) "
                    "VALUES (?, ?)",
                    (eid, int(count)),
                )
            # slash_offense_counts re-insert -- mirrors the reputation
            # block immediately above.  See save_state_snapshot for the
            # round-trip rationale.
            for eid, count in snapshot.get(
                "slash_offense_counts", {},
            ).items():
                conn.execute(
                    "INSERT INTO slash_offense_counts "
                    "(entity_id, count) VALUES (?, ?)",
                    (eid, int(count)),
                )
            for block_number, stake_map in snapshot.get(
                "stake_snapshots", {},
            ).items():
                for entity_id, amount in stake_map.items():
                    conn.execute(
                        "INSERT INTO stake_snapshots "
                        "(block_number, entity_id, amount) "
                        "VALUES (?, ?, ?)",
                        (int(block_number), entity_id, int(amount)),
                    )
            # Round-8 fix: re-insert the receipt-subtree mirror tables
            # the DELETE above just wiped.  Without this restore, the
            # post-restore window between
            # `restore_state_snapshot` and the next `_persist_state`
            # leaves the DB with empty mirrors -- a process exit in
            # that window cold-restarts the node into a state where
            # CensorshipEvidence / BogusRejection are rejected because
            # the issuer's registered root reads back as None.  The
            # snapshot dict NOW carries these maps (see
            # save_state_snapshot above), so the symmetry holds in a
            # single SQL transaction.
            for eid, root in snapshot.get(
                "receipt_subtree_roots", {},
            ).items():
                conn.execute(
                    "INSERT OR REPLACE INTO receipt_subtree_roots "
                    "(entity_id, root_public_key) VALUES (?, ?)",
                    (eid, root),
                )
            for eid, roots in snapshot.get(
                "past_receipt_subtree_roots", {},
            ).items():
                for root in roots:
                    conn.execute(
                        "INSERT OR IGNORE INTO past_receipt_subtree_roots "
                        "(entity_id, root_public_key) VALUES (?, ?)",
                        (eid, root),
                    )
            # Round-12: re-insert reaction_choices that the DELETE
            # above just wiped.  Snapshot key is
            # `(voter_id, target, target_is_user)` -> choice; the
            # ReactionState round-trip rebuild reads back via
            # `get_all_reaction_choices` so the on-disk shape and
            # the in-memory dict stay in lockstep.  CLEAR entries
            # are never persisted (in-memory absent ≡ CLEAR), so any
            # snapshot dict carrying CLEAR is treated as a no-op
            # (the upstream `apply` path won't have stored them).
            for (voter, target, tu), choice in snapshot.get(
                "reaction_choices", {},
            ).items():
                conn.execute(
                    "INSERT OR REPLACE INTO reaction_choices "
                    "(voter_id, target, target_is_user, choice) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        voter,
                        target,
                        1 if tu else 0,
                        int(choice),
                    ),
                )
            # Round-8 fix: re-insert key_rotation_last_height the
            # DELETE above just wiped.  Same defect class as the
            # receipt-subtree mirror leak above; matches the round-4
            # in-memory cooldown gate semantics.
            for eid, h in snapshot.get(
                "key_rotation_last_height", {},
            ).items():
                conn.execute(
                    "INSERT OR REPLACE INTO key_rotation_last_height "
                    "(entity_id, block_height) VALUES (?, ?)",
                    (eid, int(h)),
                )

            conn.execute("UPDATE supply_meta SET value = ? WHERE key = 'total_supply'", (snapshot["total_supply"],))
            conn.execute("UPDATE supply_meta SET value = ? WHERE key = 'total_minted'", (snapshot["total_minted"],))
            conn.execute("UPDATE supply_meta SET value = ? WHERE key = 'total_fees_collected'", (snapshot["total_fees_collected"],))
            # Finalization-stall counter round-trip -- INSERT OR
            # REPLACE because older snapshots predate this field and
            # the supply_meta row may not exist yet on the disk.
            conn.execute(
                "INSERT OR REPLACE INTO supply_meta (key, value) "
                "VALUES (?, ?)",
                (
                    "blocks_since_last_finalization",
                    int(snapshot.get("blocks_since_last_finalization", 0)),
                ),
            )
            # Lottery prize pool -- same INSERT OR REPLACE shape so
            # pre-field snapshots still round-trip cleanly (default
            # 0 on older snapshots predating this field).
            conn.execute(
                "INSERT OR REPLACE INTO supply_meta (key, value) "
                "VALUES (?, ?)",
                (
                    "lottery_prize_pool",
                    int(snapshot.get("lottery_prize_pool", 0)),
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def flush_state(self):
        """Commit any pending writes -- depth-aware.

        Routes through `_maybe_commit` so a caller invoked inside an
        outer `begin_transaction` scope (e.g. `Blockchain.add_block`'s
        round-9 apply+verify+persist wrap) does NOT prematurely
        commit the outer transaction mid-flight, breaking the
        atomicity guarantee the wrap exists to provide.  Direct
        `self._conn.commit()` was the prior implementation and would
        flush the outer wrap on the first apply-time helper that
        called flush_state (apply_revoke_transaction,
        apply_key_rotation, _install_pubkey_direct, etc.), partially
        defeating the round-9 fix.  Outside any wrap (cold-start
        bootstrap, standalone tests) this still commits immediately.
        """
        self._maybe_commit()

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
        """Commit iff no wrapping begin_transaction is active.

        Every state-mutating helper in this class must route its commit
        through here rather than calling self._conn.commit() directly —
        otherwise a helper invoked inside an outer begin_transaction
        scope (e.g. Blockchain._persist_state) prematurely commits the
        outer transaction mid-flight, silently breaking the atomicity
        guarantee the scope exists to provide.
        """
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
        self._maybe_commit()

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
        self._maybe_commit()

    def auto_separate_finalized_witnesses(
        self, finalized_height: int, state=None,
    ) -> int:
        """Move witnesses of old finalized blocks to the side table.

        Two-part gate:
          1. WITNESS_AUTO_SEPARATION_ENABLED (operator kill switch).
          2. WITNESS_AUTO_SEPARATION_HEIGHT (hard-fork activation).
             Pre-fork blocks (block_number < fork_height) are NEVER
             stripped — replay determinism for blocks the chain
             committed to inline forever.

        When both gates pass, every block at
            block_number >= WITNESS_AUTO_SEPARATION_HEIGHT
        AND
            block_number <= (finalized_height - WITNESS_RETENTION_BLOCKS)
        whose witness data is still inline gets re-organized:
        signatures move from the `blocks.data` BLOB to the
        `block_witnesses` side table.  Nothing is deleted — the
        message payload, timestamp, and entity_id stay in place
        forever; only the WOTS sig bytes move.  A caller that needs
        the full block still passes `include_witnesses=True` to
        get_block_by_hash.

        Idempotent: skips blocks already separated (identified by a
        row in block_witnesses).  Safe to call on every finality
        advance.

        Returns the number of blocks separated in this call.
        """
        import messagechain.config as _cfg
        if not getattr(_cfg, "WITNESS_AUTO_SEPARATION_ENABLED", False):
            return 0

        # Hard-fork gate — the sweep itself is inert until the
        # finality horizon crosses the activation height.  Pre-fork
        # blocks remain inline forever (filtered again in the SQL
        # WHERE clause as a defense in depth).
        fork_height = getattr(_cfg, "WITNESS_AUTO_SEPARATION_HEIGHT", 0)
        if finalized_height < fork_height:
            return 0

        retention = _cfg.WITNESS_RETENTION_BLOCKS
        horizon = finalized_height - retention
        if horizon < 0:
            return 0

        # Candidate blocks: at-or-above the fork height (pre-fork
        # blocks are never eligible, full stop), past the retention
        # window of the finality horizon, and not yet separated.
        # LEFT JOIN is cheap — both tables are keyed on block_hash.
        cur = self._conn.execute(
            "SELECT b.block_hash FROM blocks b "
            "LEFT JOIN block_witnesses w ON b.block_hash = w.block_hash "
            "WHERE b.block_number >= ? "
            "AND b.block_number <= ? "
            "AND w.block_hash IS NULL",
            (fork_height, horizon),
        )
        candidates = [bytes(row[0]) for row in cur.fetchall()]

        count = 0
        for block_hash in candidates:
            self.strip_finalized_witnesses(block_hash, state=state)
            count += 1
        return count
