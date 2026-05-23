"""Tests for 1.91.0 cold-load self-heal of snapshot drift.

Background: the 2026-05-22 v1 incident left validator-1's chain.db
with state_snapshots / chaindb tables that carried fork-state from a
prior fork excursion, while the canonical blocks were unchanged.  The
1.89.0 ``ChainIntegrityError`` correctly detected the divergence at
cold-load and refused to start; operator recovery was either splicing
a healthy chain.db from a peer or hand-crafting DELETEs (the latter
later operationalised as the 1.90.0 ``prune-fork-branches`` CLI).

The 1.91.0 self-heal preserves the same detection (same invariant)
but adds an automatic recovery path: when the state_root mismatch is
detected, replay every canonical block from genesis (the canonical
block chain is the inviolate source of truth, ``block_hash`` is
hash-of-contents), then overwrite the poisoned chaindb tables and the
bad state_snapshots row with the rebuilt state.

These tests pin the contract:
  * Happy path: a chain.db poisoned to look like a fork-state-stored
    scenario self-heals on cold-load with no operator intervention,
    and the next cold-load doesn't re-trigger self-heal (the bad
    snapshot was overwritten in step 1).
  * Truly-broken path: if the chain.db's canonical blocks plus the
    genesis-allocation restoration path cannot reproduce the claimed
    header state_root, self-heal completes the replay but
    re-verification fails and ``ChainIntegrityError`` is raised --
    same fail-loud behaviour as 1.89.0 in the unrecoverable case.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

import messagechain.config as _cfg
from messagechain.config import (
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ALLOCATION,
    TREASURY_ENTITY_ID,
)
from messagechain.core.blockchain import Blockchain, ChainIntegrityError
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _close(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class _MainnetPinOverride:
    """Pin the test entity as the mainnet founder AND pin the
    test's genesis block hash as the canonical mainnet genesis hash.
    Both pins are needed for the self-heal path's
    ``is_mainnet_genesis`` check to fire, which in turn lets
    ``_apply_mainnet_genesis_supply_state`` restore the founder /
    treasury allocations on a from-genesis replay."""

    def _install_founder(self, eid: bytes):
        self._saved_founder = _cfg._MAINNET_FOUNDER_ENTITY_ID
        _cfg._MAINNET_FOUNDER_ENTITY_ID = eid

    def _install_genesis_pins(self, genesis_hash: bytes):
        self._saved_pinned = getattr(_cfg, "PINNED_GENESIS_HASH", None)
        self._saved_mainnet_hash = getattr(
            _cfg, "_MAINNET_GENESIS_HASH", None,
        )
        _cfg.PINNED_GENESIS_HASH = genesis_hash
        _cfg._MAINNET_GENESIS_HASH = genesis_hash

    def _restore_all(self):
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self._saved_founder
        if getattr(self, "_saved_pinned", None) is not None or hasattr(
            self, "_saved_pinned",
        ):
            _cfg.PINNED_GENESIS_HASH = self._saved_pinned
        if hasattr(self, "_saved_mainnet_hash"):
            _cfg._MAINNET_GENESIS_HASH = self._saved_mainnet_hash


class TestColdLoadSelfHealsSnapshotDrift(
    _MainnetPinOverride, unittest.TestCase,
):
    """The 1.91.0 cold-load self-heal contract on mainnet-pinned
    chains (where ``_apply_mainnet_genesis_supply_state`` can restore
    founder + treasury allocations during a from-genesis replay)."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"cold-load-self-heal-test-founder",
            tree_height=4,
        )

    def _build_chain_with_blocks(self, db_path: str, n_blocks: int):
        """Build a chain at ``db_path`` with N post-genesis blocks
        AND install the genesis hash pins so the cold-load self-heal
        path treats it as mainnet.  Returns
        (chain, db, tip_state_root_clean)."""
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        self._install_founder(self.founder.entity_id)
        db = ChainDB(db_path)
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        # Now that the genesis block exists with its real hash, pin
        # it as the canonical mainnet genesis so the self-heal path
        # can route through ``_apply_mainnet_genesis_supply_state``.
        self._install_genesis_pins(chain.chain[0].block_hash)
        bootstrap_seed_local(
            chain, self.founder,
            cold_authority_pubkey=self.founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        consensus = ProofOfStake()
        consensus.register_validator(
            self.founder.entity_id,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        for _ in range(n_blocks):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, reason)
        return chain, db, chain.compute_current_state_root()

    def test_cold_load_self_heals_fork_state_pollution(self):
        """Reproduce the v1 scenario: chaindb tables + state_snapshots
        carry state that no longer matches the canonical tip's stored
        header.state_root.  Cold-load must detect the drift and
        self-heal via replay-from-genesis without raising, AND a
        second cold-load must NOT re-trigger self-heal (the first
        run overwrote the poisoned tables + snapshot)."""
        try:
            tmp = tempfile.mkdtemp(prefix="mc_test_")
            self.addCleanup(shutil.rmtree, tmp, True)
            db_path = os.path.join(tmp, "chain.db")

            # Phase 1: build a clean chain.
            chain1, db1, tip_state_root_clean = self._build_chain_with_blocks(
                db_path, n_blocks=3,
            )
            tip_height = chain1.chain[-1].header.block_number
            self.assertEqual(
                chain1.chain[-1].header.state_root,
                tip_state_root_clean,
                "chain1 tip header should match compute_current_state_root",
            )

            # Phase 2: poison chaindb tables + state_snapshots WITHOUT
            # changing block bodies.  Mutate a balance in-memory (this
            # is what a fork-state apply would have produced), then
            # force a full flush + re-snapshot at tip_height.  The
            # canonical blocks in chain.db are unchanged -- their
            # header.state_root still reflects the clean state.
            poison_eid = self.founder.entity_id
            clean_founder_balance = chain1.supply.balances.get(
                poison_eid, 0,
            )
            chain1.supply.balances[poison_eid] = (
                clean_founder_balance + 12345
            )
            chain1._rebuild_state_tree()
            chain1._dirty_entities = None
            chain1._persist_state()
            chain1._persist_state_snapshot(tip_height)
            db1.flush_state()
            _close(db1)

            # Sanity-check the poison: a fresh ChainDB read should
            # return the poisoned balance.
            db_check = ChainDB(db_path)
            self.assertEqual(
                db_check.get_balance(poison_eid),
                clean_founder_balance + 12345,
                "poison must reach chaindb table",
            )
            _close(db_check)

            # Phase 3: cold-load.  Without self-heal this would raise
            # ChainIntegrityError; with self-heal it must succeed and
            # the loaded state must match the canonical tip header.
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            self.assertEqual(
                chain2.compute_current_state_root(),
                tip_state_root_clean,
                "cold-load self-heal must rebuild state to the "
                "canonical tip's claimed state_root",
            )
            self.assertEqual(
                chain2.supply.balances[poison_eid],
                clean_founder_balance,
                "self-heal must overwrite the poisoned balance with "
                "the canonical-replay value",
            )
            db2.flush_state()
            _close(db2)

            # Phase 4: a second cold-load must NOT re-trigger
            # self-heal.  The first self-heal overwrote both the
            # chaindb tables (via _persist_state) and the bad
            # state_snapshots row at tip_height (via
            # _persist_state_snapshot), so the next load passes the
            # invariant directly.
            db3 = ChainDB(db_path)
            chain3 = Blockchain(db=db3)
            self.assertEqual(
                chain3.compute_current_state_root(),
                tip_state_root_clean,
            )
            _close(db3)
        finally:
            self._restore_all()


class TestColdLoadRaisesWhenUnrecoverable(
    _MainnetPinOverride, unittest.TestCase,
):
    """If the chain.db is in a state where neither the loaded
    state_root nor the post-replay state_root matches the canonical
    tip header.state_root, ``ChainIntegrityError`` MUST still be
    raised -- same fail-loud behaviour as 1.89.0 in the truly-broken
    case.  Operator recovery: splice a healthy chain.db from a peer."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"cold-load-unrecoverable-founder1",
            tree_height=4,
        )
        cls.imposter = Entity.create(
            private_key=b"cold-load-unrecoverable-imposter1",
            tree_height=4,
        )

    def test_genesis_pin_mismatch_makes_replay_unrecoverable(self):
        """If between writing the chain.db and cold-load, the pinned
        ``_MAINNET_FOUNDER_ENTITY_ID`` no longer matches the chain's
        actual genesis proposer, ``_apply_mainnet_genesis_supply_state``
        refuses to restore founder allocations.  Self-heal returns
        failure, and the caller raises ``ChainIntegrityError`` with a
        message identifying it as a self-heal failure (operator
        recovery hint: splice a healthy chain.db from a peer).

        Realistic shape this models: a chain.db produced under one
        binary's pinned identity opened under a different binary's
        pin (config drift, wrong network, post-fork mismatch).  The
        pre-1.91.0 behaviour was a bare ``ChainIntegrityError`` from
        phase 3; the 1.91.0 behaviour distinguishes the unrecoverable
        case with a specific self-heal-failed message.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        try:
            tmp = tempfile.mkdtemp(prefix="mc_test_")
            self.addCleanup(shutil.rmtree, tmp, True)
            db_path = os.path.join(tmp, "chain.db")

            # Build chain pinned to the real founder.
            self._install_founder(self.founder.entity_id)
            db1 = ChainDB(db_path)
            chain1 = Blockchain(db=db1)
            chain1.initialize_genesis(
                self.founder,
                {
                    self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                    TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
                },
            )
            self._install_genesis_pins(chain1.chain[0].block_hash)
            bootstrap_seed_local(
                chain1, self.founder,
                cold_authority_pubkey=self.founder.public_key,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            consensus = ProofOfStake()
            consensus.register_validator(
                self.founder.entity_id,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            proposer = pick_selected_proposer(chain1, [self.founder])
            blk = chain1.propose_block(consensus, proposer, [])
            self.assertTrue(chain1.add_block(blk)[0])
            tip_height = chain1.chain[-1].header.block_number

            # Poison the chaindb to force a state_root mismatch on
            # cold-load.
            poison_eid = self.founder.entity_id
            chain1.supply.balances[poison_eid] = (
                chain1.supply.balances.get(poison_eid, 0) + 12345
            )
            chain1._rebuild_state_tree()
            chain1._dirty_entities = None
            chain1._persist_state()
            chain1._persist_state_snapshot(tip_height)
            db1.flush_state()
            _close(db1)

            # Switch the pin to a different entity BEFORE cold-load.
            # Genesis-allocation restoration will refuse because the
            # genesis block's proposer_id no longer matches the
            # pinned ``_MAINNET_FOUNDER_ENTITY_ID``.
            _cfg._MAINNET_FOUNDER_ENTITY_ID = self.imposter.entity_id

            db2 = ChainDB(db_path)
            with self.assertRaises(ChainIntegrityError) as ctx:
                Blockchain(db=db2)
            msg = str(ctx.exception)
            self.assertIn("self-heal", msg)
            _close(db2)
        finally:
            self._restore_all()


if __name__ == "__main__":
    unittest.main()
