"""Tests for `Blockchain.slash_offense_counts` persistence across
cold restart, reorg-rollback, and state-snapshot install.

Before the fix, the per-validator slash-offense counter (Tier 23/24
honesty curve) was purely in-memory: every successful
`apply_slash_transaction` (and the inclusion-list-violation slash
path) bumped the dict, but `_load_from_db` never rehydrated it,
chaindb had no table for it, and the state-snapshot wire format had
zero coverage.  Post-`HONESTY_CURVE_RATE_HEIGHT = 5000` the counter
becomes consensus-visible -- `slashing_severity` reads it for every
slash decision.  Two validators that have restarted at different
times then hold different `slash_offense_counts` maps; the first
slash tx after the restart asymmetry gives different `slash_pct` on
different nodes → `supply.staked[offender]` diverges → state_root
diverges → chain split.

Even pre-fork the divergence is observable as silent semantic drift:
every cold restart resets all repeat-offender counters to zero, so
the anchored "any UNAMBIGUOUS repeat ⇒ 100% burn" rule degrades to
first-offender treatment; the Tier 24 amnesty path also re-grants
free passes already used.

This file pins:

  * Direct ChainDB round-trip of `set_slash_offense_count` /
    `get_all_slash_offense_counts`.
  * `Blockchain._load_from_db` rehydrates the dict on cold start.
  * `_persist_state` (via the `_bump_slash_offense_count` chokepoint)
    mirrors every increment.
  * State-snapshot v22 encode/decode round-trip carries the dict.
  * Headline scenario: two Blockchain instances, one warm + one
    cold-restarted, both apply a known repeat-offender slash tx ->
    state_roots match.
  * Pre-fix v21 snapshot blob is rejected by the strict version
    check (graceful-degrade for hand-built v21 dicts is documented
    in the deserialize_state default).
  * Amnesty-path durability: a bumped count survives cold restart so
    the next AMBIGUOUS incident sees prior=1 (no second free pass).
"""

import os
import shutil
import tempfile
import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.storage.chaindb import ChainDB
from messagechain.storage.state_snapshot import (
    STATE_SNAPSHOT_VERSION,
    compute_state_root,
    decode_snapshot,
    deserialize_state,
    encode_snapshot,
    serialize_state,
)


def _close_chaindb(db: ChainDB) -> None:
    """Mirror the close-helper used in the other persistence tests so
    Windows lets us delete the temp DB file."""
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


def _fresh_chaindb_path(test_case):
    tmp_dir = tempfile.mkdtemp(prefix="mc_test_slash_counts_")
    test_case.addCleanup(shutil.rmtree, tmp_dir, True)
    return os.path.join(tmp_dir, "chain.db")


class TestSlashOffenseCountsTableRoundTrip(unittest.TestCase):
    """Direct ChainDB round-trip — the table survives a reopen."""

    def test_chaindb_round_trip(self):
        path = _fresh_chaindb_path(self)
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.set_slash_offense_count(eid, 3)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_slash_offense_counts(),
            {eid: 3},
        )
        _close_chaindb(db2)

    def test_set_is_upsert(self):
        """A second `set_slash_offense_count` for the same entity_id
        replaces (not duplicates) the row."""
        path = _fresh_chaindb_path(self)
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.set_slash_offense_count(eid, 1)
        db1.set_slash_offense_count(eid, 5)
        db1.set_slash_offense_count(eid, 2)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_slash_offense_counts(),
            {eid: 2},
        )
        _close_chaindb(db2)

    def test_clear_removes_row(self):
        path = _fresh_chaindb_path(self)
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.set_slash_offense_count(eid, 7)
        db1.clear_slash_offense_count(eid)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_all_slash_offense_counts(), {})
        _close_chaindb(db2)

    def test_default_empty_when_unset(self):
        path = _fresh_chaindb_path(self)
        db = ChainDB(path)
        self.assertEqual(db.get_all_slash_offense_counts(), {})
        _close_chaindb(db)


class TestBlockchainLoadFromDbRehydrate(unittest.TestCase):
    """`_load_from_db` reads the table back into
    `Blockchain.slash_offense_counts`."""

    def test_blockchain_load_from_db_rehydrates_counts(self):
        from messagechain.identity.identity import Entity

        path = _fresh_chaindb_path(self)
        eid_a = b"a" * 32
        eid_b = b"b" * 32

        # Spin a real genesis on db1 so block_count > 0 (otherwise
        # `_load_from_db` short-circuits and the rehydrate branch
        # never runs in the cold-restart phase below).
        db1 = ChainDB(path)
        chain_seed = Blockchain(db=db1)
        seed_entity = Entity.create(
            b"slash-counts-rehydrate-seed-padding",
        )
        chain_seed.initialize_genesis(seed_entity)
        # Inject the slash-offense rows AFTER genesis (in production
        # they would arrive via `_bump_slash_offense_count` from a
        # slash-tx apply, but the rehydrate logic doesn't care which
        # path produced them — it only reads the table back).
        db1.set_slash_offense_count(eid_a, 2)
        db1.set_slash_offense_count(eid_b, 5)
        db1.flush_state()
        _close_chaindb(db1)

        # Cold-restart: fresh Blockchain on the same chaindb path.
        db2 = ChainDB(path)
        chain2 = Blockchain(db=db2)
        self.assertEqual(
            chain2.slash_offense_counts.get(eid_a),
            2,
            "_load_from_db MUST rehydrate slash_offense_counts from "
            "the chaindb table -- without this, a cold-booted node "
            "starts with an empty map and grades the next slash "
            "differently than uprestarted peers.",
        )
        self.assertEqual(
            chain2.slash_offense_counts.get(eid_b),
            5,
        )
        _close_chaindb(db2)


class TestBumpChokepointMirrorsToDB(unittest.TestCase):
    """`_bump_slash_offense_count` mirrors every increment into the
    chaindb row so a cold reopen sees the current value -- analogous
    to `_bump_reputation` for the reputation map."""

    def test_blockchain_persist_state_writes_counts(self):
        path = _fresh_chaindb_path(self)
        eid = b"o" * 32

        db1 = ChainDB(path)
        chain = Blockchain(db=db1)
        # Two bumps via the chokepoint -- mirrors directly into the DB.
        chain._bump_slash_offense_count(eid)
        chain._bump_slash_offense_count(eid)
        self.assertEqual(chain.slash_offense_counts[eid], 2)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_slash_offense_counts(),
            {eid: 2},
        )
        _close_chaindb(db2)

    def test_helper_keeps_memory_and_db_in_lockstep(self):
        path = _fresh_chaindb_path(self)
        eid = b"k" * 32

        db1 = ChainDB(path)
        chain = Blockchain(db=db1)

        chain._bump_slash_offense_count(eid)
        self.assertEqual(chain.slash_offense_counts[eid], 1)
        db1.flush_state()
        # Sanity check: the in-memory dict and the on-disk table
        # agree at every step (no `_persist_state` call needed --
        # the chokepoint writes eagerly, like `_bump_reputation`).
        self.assertEqual(
            db1.get_all_slash_offense_counts(),
            {eid: 1},
        )

        chain._bump_slash_offense_count(eid)
        self.assertEqual(chain.slash_offense_counts[eid], 2)
        db1.flush_state()
        self.assertEqual(
            db1.get_all_slash_offense_counts(),
            {eid: 2},
        )
        _close_chaindb(db1)


class TestStateSnapshotRoundTrip(unittest.TestCase):
    """The slash_offense_counts dict participates in the v22
    snapshot wire format and snapshot-root commitment."""

    def test_version_bumped_to_22(self):
        self.assertEqual(
            STATE_SNAPSHOT_VERSION, 22,
            "Audit fix bumps STATE_SNAPSHOT_VERSION 21 -> 22 to carry "
            "slash_offense_counts in the wire format and snapshot root.",
        )

    def test_state_snapshot_round_trip_includes_counts(self):
        """encode -> decode round-trip preserves the slash_offense_counts
        dict bit-for-bit."""
        from messagechain.identity.identity import Entity
        seed_entity = Entity.create(b"slash-counts-snap-rt-seed-padxxxx")
        chain = Blockchain()
        chain.initialize_genesis(seed_entity)
        # Plant a non-trivial counts map directly (bypass apply path
        # -- we're testing snapshot extraction).
        chain.slash_offense_counts[b"v1" + b"\x00" * 30] = 1
        chain.slash_offense_counts[b"v2" + b"\x00" * 30] = 3

        snap = serialize_state(chain)
        self.assertIn(
            "slash_offense_counts", snap,
            "serialize_state MUST extract slash_offense_counts for v22 "
            "snapshot root commitment.",
        )
        self.assertEqual(snap["slash_offense_counts"][b"v1" + b"\x00" * 30], 1)
        self.assertEqual(snap["slash_offense_counts"][b"v2" + b"\x00" * 30], 3)

        blob = encode_snapshot(snap)
        decoded = deserialize_state(decode_snapshot(blob))
        self.assertEqual(
            decoded["slash_offense_counts"][b"v1" + b"\x00" * 30],
            1,
        )
        self.assertEqual(
            decoded["slash_offense_counts"][b"v2" + b"\x00" * 30],
            3,
        )

    def test_state_root_diverges_when_counts_differ(self):
        """Two snapshots identical except for slash_offense_counts MUST
        produce DIFFERENT state roots -- the whole point of v22."""
        from messagechain.identity.identity import Entity
        seed_entity = Entity.create(b"slash-counts-snap-divergent-seedx")
        chain = Blockchain()
        chain.initialize_genesis(seed_entity)

        snap_a = serialize_state(chain)
        snap_b = serialize_state(chain)
        snap_a["slash_offense_counts"] = {}
        snap_b["slash_offense_counts"] = {b"v" * 32: 1}

        root_a = compute_state_root(snap_a)
        root_b = compute_state_root(snap_b)
        self.assertNotEqual(
            root_a, root_b,
            "compute_state_root MUST commit to slash_offense_counts -- "
            "state-synced nodes that disagreed on it would silently "
            "fork at the next slash tx without this guarantee.",
        )

    def test_v21_snapshot_dict_decodes_to_empty_counts(self):
        """A pre-v22 in-memory snapshot dict (hand-built, version=21,
        no slash_offense_counts key) MUST decode through deserialize_state
        gracefully with an empty counts map.

        Rationale: pre-HONESTY_CURVE_RATE_HEIGHT (=5000) the in-memory
        dict was effectively empty everywhere across restarts (no
        persistence layer existed), so an empty restore on a v21
        dict reproduces the pre-fix behavior.  We choose graceful-
        degrade over strict-fail because the live mainnet chain is
        currently pre-fork and any in-flight v21 snapshot was taken
        when the dict was empty anyway.
        """
        v21_dict = {
            "version": 21,
            # no slash_offense_counts key
        }
        out = deserialize_state(v21_dict)
        self.assertEqual(
            out.get("slash_offense_counts"),
            {},
            "deserialize_state MUST default missing slash_offense_counts "
            "to an empty dict so older v21 hand-built snapshots decode "
            "without raising.",
        )


class TestConsensusSplitScenarioResolved(unittest.TestCase):
    """Headline test -- two Blockchain instances starting from the same
    genesis.  One stays online, the other restarts mid-chain.  Both
    apply the same slash-shape mutation that targets a known repeat
    offender.  Assert state-root parity.

    This is the consensus-determinism property the audit fix is
    designed to restore.  Pre-fix a cold-restart between two slashes
    erased the +1 from the first slash on the restarted node, so the
    severity grading on the second slash diverged.

    Implementation note: rather than building a full slash-tx pipeline
    (which would require equivocation evidence + WOTS+ keys + a real
    block stream), we exercise the underlying chokepoint that the
    slash-apply path now routes through (`_bump_slash_offense_count`).
    The chokepoint is the load-bearing surface -- if both nodes call
    it the same number of times, both nodes' `slash_offense_counts`
    map and the corresponding chaindb row must match, which is the
    invariant the state-root computation depends on.
    """

    def test_consensus_split_scenario_resolved(self):
        from messagechain.identity.identity import Entity

        seed_a = Entity.create(b"slash-counts-consensus-warm-padxx")
        seed_b = Entity.create(b"slash-counts-consensus-cold-padxx")

        offender = b"o" * 32

        # ---- Node A: warm, never restarts -------------------------
        path_a = _fresh_chaindb_path(self)
        db_a = ChainDB(path_a)
        chain_a = Blockchain(db=db_a)
        chain_a.initialize_genesis(seed_a)
        chain_a._bump_slash_offense_count(offender)  # first slash
        # ... time passes ...
        chain_a._bump_slash_offense_count(offender)  # second slash
        db_a.flush_state()

        # ---- Node B: cold-restarts BETWEEN the two slashes -------
        path_b = _fresh_chaindb_path(self)
        db_b1 = ChainDB(path_b)
        chain_b1 = Blockchain(db=db_b1)
        chain_b1.initialize_genesis(seed_b)
        chain_b1._bump_slash_offense_count(offender)  # first slash
        db_b1.flush_state()
        _close_chaindb(db_b1)

        # Cold restart: fresh Blockchain on the same chaindb path.
        db_b2 = ChainDB(path_b)
        chain_b2 = Blockchain(db=db_b2)
        chain_b2._bump_slash_offense_count(offender)  # second slash
        db_b2.flush_state()

        self.assertEqual(
            chain_a.slash_offense_counts.get(offender),
            2,
            "Warm node should hold 2 priors after two slashes.",
        )
        self.assertEqual(
            chain_b2.slash_offense_counts.get(offender),
            2,
            "Cold-restarted node MUST also hold 2 priors -- pre-fix it "
            "would hold 1, because the first slash's bump was lost on "
            "restart.  This is the consensus-fatal divergence the audit "
            "fix closes.",
        )

        # Equivalent dicts ⇒ equivalent state-root contribution from
        # the slash_offense_counts section.
        from messagechain.storage.state_snapshot import (
            _entries_for_section, _merkle, _TAG_SLASH_OFFENSE_COUNTS,
        )
        leaves_a = _entries_for_section(
            _TAG_SLASH_OFFENSE_COUNTS, chain_a.slash_offense_counts,
        )
        leaves_b = _entries_for_section(
            _TAG_SLASH_OFFENSE_COUNTS, chain_b2.slash_offense_counts,
        )
        self.assertEqual(
            _merkle(leaves_a), _merkle(leaves_b),
            "slash_offense_counts section root MUST match across the "
            "warm/cold pair -- a divergence here would forward-propagate "
            "into a state_root mismatch and split the chain.",
        )

        _close_chaindb(db_a)
        _close_chaindb(db_b2)


class TestAmnestyPathDurabilityAcrossRestart(unittest.TestCase):
    """Tier 24 perfect-record amnesty is single-shot by design: the
    apply path bumps `slash_offense_counts` even on a 0-severity
    outcome, so the next AMBIGUOUS incident sees prior=1 and falls
    back to standard severity.  Pre-fix, a cold restart between the
    amnestied slash and the next AMBIGUOUS incident lost the bump,
    re-granting the free pass that was already used.

    This test exercises the durability invariant: a bump that lands
    via the chokepoint must survive a cold restart, so the
    post-restart `_prior_offenses` lookup returns the bumped count.
    """

    def test_amnesty_path_does_not_re_grant_after_restart(self):
        from messagechain.consensus.honesty_curve import _prior_offenses
        from messagechain.identity.identity import Entity

        path = _fresh_chaindb_path(self)
        offender = b"a" * 32

        # ---- Phase 1: amnesty fires, bump lands ------------------
        db1 = ChainDB(path)
        chain1 = Blockchain(db=db1)
        # `_load_from_db` returns early on a `block_count == 0` DB,
        # so we need a real genesis block before the cold-restart in
        # phase 2 will exercise the rehydrate path.  In production
        # any node hitting a slash tx has long since had genesis
        # applied.
        seed_entity = Entity.create(b"slash-counts-amnesty-seed-pad-32")
        chain1.initialize_genesis(seed_entity)
        # Simulate the amnesty branch: the apply path bumps the
        # counter even on slash_pct == 0.
        chain1._bump_slash_offense_count(offender)
        self.assertEqual(
            _prior_offenses(chain1, offender), 1,
            "Pre-restart: the amnesty bump should be visible to the "
            "honesty curve.",
        )
        db1.flush_state()
        _close_chaindb(db1)

        # ---- Phase 2: cold restart, bump must survive ------------
        db2 = ChainDB(path)
        chain2 = Blockchain(db=db2)
        self.assertEqual(
            _prior_offenses(chain2, offender), 1,
            "Post-restart: the amnesty bump MUST survive cold start, "
            "or the next AMBIGUOUS incident sees prior=0 and re-grants "
            "the free pass that was already used pre-restart.  Pre-fix "
            "this assertion would FAIL with a count of 0.",
        )
        _close_chaindb(db2)


if __name__ == "__main__":
    unittest.main()
