"""Scoped ``_persist_state`` writes only dirty entities after the first flush.

The previous implementation re-UPSERTed every entity_id in every per-entity
table on every block, producing O(N_accounts) SQLite writes per block
independent of how many accounts the block actually touched.  For a chain
with 100k+ accounts that becomes a steady-state bottleneck and bloats
the WAL with duplicate rows.

The dirty-set tracker works at the ``_touch_state`` choke point:

* ``Blockchain._dirty_entities`` is ``None`` after a fresh ``__init__`` /
  ``_reset_state`` → the next ``_persist_state`` does a full flush.
* After that first flush, ``_dirty_entities`` holds the set of entity_ids
  touched since the last flush; ``_persist_state`` iterates only those.
* A successful ``_persist_state`` resets the dirty set to ``set()`` so the
  next block starts clean.

These tests pin the contract end-to-end: the first persist writes
everything, subsequent persists write only dirty rows, and reload-from-db
produces identical in-memory state regardless of which code path
persisted it.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.config import VALIDATOR_MIN_STAKE
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test, pick_selected_proposer


class _CountingChainDB(ChainDB):
    """ChainDB subclass that counts per-entity write calls.

    Every ``set_<field>(entity_id, ...)`` bumps the counter for that
    field.  The counter is NOT reset by internal ChainDB operations —
    only by tests that explicitly call ``reset_counts``.  Counts let
    us pin the scaling property ("only dirty rows") without depending
    on the exact names of dirty entities.
    """

    def __init__(self, db_path: str):
        super().__init__(db_path)
        self.write_counts: dict[str, int] = {}

    def reset_counts(self) -> None:
        self.write_counts = {}

    def _bump(self, name: str) -> None:
        self.write_counts[name] = self.write_counts.get(name, 0) + 1

    def set_balance(self, entity_id, balance):
        self._bump("balance")
        return super().set_balance(entity_id, balance)

    def set_staked(self, entity_id, amount):
        self._bump("staked")
        return super().set_staked(entity_id, amount)

    def set_nonce(self, entity_id, nonce):
        self._bump("nonce")
        return super().set_nonce(entity_id, nonce)

    def set_public_key(self, entity_id, public_key):
        self._bump("public_key")
        return super().set_public_key(entity_id, public_key)

    def set_message_count(self, entity_id, count):
        self._bump("message_count")
        return super().set_message_count(entity_id, count)

    def set_proposer_sig_count(self, entity_id, count):
        self._bump("proposer_sig")
        return super().set_proposer_sig_count(entity_id, count)

    def set_leaf_watermark(self, entity_id, next_leaf):
        self._bump("leaf_watermark")
        return super().set_leaf_watermark(entity_id, next_leaf)

    def set_authority_key(self, entity_id, authority_public_key):
        self._bump("authority_key")
        return super().set_authority_key(entity_id, authority_public_key)

    def set_key_rotation_count(self, entity_id, rotation_number):
        self._bump("key_rotation")
        return super().set_key_rotation_count(entity_id, rotation_number)


def _make_chain(db_path: str, num_validators: int = 3):
    """Build a staked, persistent chain with `num_validators` validators."""
    db = _CountingChainDB(db_path)
    entities = [
        Entity.create(f"validator_{i}_key".encode().ljust(32, b"\x00"))
        for i in range(num_validators)
    ]
    chain = Blockchain(db=db)
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)
    consensus = ProofOfStake()
    for e in entities:
        chain.supply.balances[e.entity_id] = (
            chain.supply.balances.get(e.entity_id, 0) + 50_000
        )
        chain.supply.stake(e.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[e.entity_id] = VALIDATOR_MIN_STAKE
    # Test harness back-door: mutating ``chain.supply.balances`` /
    # ``chain.supply.stake`` directly bypasses ``_touch_state``, so the
    # dirty-set tracker wouldn't otherwise pick these up.  Sync the
    # tracker and the state tree now so the test's priming persist
    # behaves like a real post-setup flush.
    chain._touch_state({e.entity_id for e in entities})
    return chain, consensus, entities


class TestDirtySetTrackerContract(unittest.TestCase):
    """Shape of the dirty-entity tracker itself."""

    def test_fresh_chain_has_no_dirty_set(self):
        chain = Blockchain()
        # Sentinel None = "full flush on next _persist_state".
        self.assertIsNone(chain._dirty_entities)

    def test_touch_state_populates_dirty_set_once_initialised(self):
        chain = Blockchain()
        chain._dirty_entities = set()
        entity_id = b"\x01" * 32
        chain._touch_state({entity_id})
        self.assertIn(entity_id, chain._dirty_entities)

    def test_touch_state_is_noop_when_dirty_set_is_none(self):
        """While in "full-flush" mode (None sentinel) we do not waste
        memory accumulating dirty entries — the next persist writes
        everything anyway."""
        chain = Blockchain()
        self.assertIsNone(chain._dirty_entities)
        chain._touch_state({b"\x02" * 32})
        self.assertIsNone(chain._dirty_entities)

    def test_reset_state_clears_to_none_sentinel(self):
        chain = Blockchain()
        chain._dirty_entities = {b"\x03" * 32}
        chain._reset_state()
        self.assertIsNone(chain._dirty_entities)


class TestScopedPersistBehavior(unittest.TestCase):
    """End-to-end scoping against a real ChainDB."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "chain.db")
        self._chains: list = []

    def tearDown(self):
        # SQLite on Windows holds the file lock until every connection
        # on every thread is closed — tempfile cleanup fails noisily
        # otherwise.  Close each chain's ChainDB before the tempdir
        # teardown.
        for c in self._chains:
            if getattr(c, "db", None) is not None:
                try:
                    c.db.close()
                except Exception:
                    pass
        self.tmp.cleanup()

    def _make(self, **kwargs):
        chain, consensus, entities = _make_chain(self.db_path, **kwargs)
        self._chains.append(chain)
        return chain, consensus, entities

    def test_first_persist_writes_all_entities(self):
        """The first _persist_state after genesis / load must cover
        every live entity — _dirty_entities is None, full flush."""
        chain, _, entities = self._make(num_validators=3)
        chain.db.reset_counts()
        chain._dirty_entities = None  # force the full-flush path
        chain._persist_state()
        # Each of the 3 validators owns a balance row; the treasury
        # owns one too — so >= 3 balance writes.  Exact count depends
        # on how many "entity-owning" rows genesis produced; the
        # guarantee is "≥ num_validators" to prove it's not scoped.
        self.assertGreaterEqual(
            chain.db.write_counts.get("balance", 0), len(entities),
        )

    def test_second_persist_after_no_op_writes_nothing(self):
        """After a full flush, an immediate repeat _persist_state
        with no intervening state changes must NOT re-write every
        per-entity row — dirty set is empty."""
        chain, _, _ = self._make(num_validators=3)
        chain._persist_state()                # prime (full flush)
        chain.db.reset_counts()
        chain._persist_state()                # repeat, no changes
        # Zero per-entity writes — that's the whole point of the
        # dirty tracker.
        self.assertEqual(chain.db.write_counts.get("balance", 0), 0)
        self.assertEqual(chain.db.write_counts.get("nonce", 0), 0)
        self.assertEqual(chain.db.write_counts.get("staked", 0), 0)
        self.assertEqual(chain.db.write_counts.get("public_key", 0), 0)

    def test_block_persist_scoped_to_affected_entities(self):
        """A block that touches a small set of entities must not
        persist rows for unrelated accounts."""
        from messagechain.core.transaction import create_transaction
        chain, consensus, entities = self._make(num_validators=4)

        # Prime with a full flush.
        chain._persist_state()
        chain.db.reset_counts()

        # Produce one block: a single message transaction from entities[1]
        # to install a payload.  _block_affected_entities covers
        # (proposer, treasury, sender).
        proposer = pick_selected_proposer(chain, entities)
        sender = entities[1] if entities[1] is not proposer else entities[2]

        tx = create_transaction(
            sender,
            "hello",
            fee=5000,
            nonce=chain.nonces.get(sender.entity_id, 0),
        )

        block = chain.propose_block(consensus, proposer, [tx])
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)

        # The dirty set should have been flushed AND reset during
        # add_block -> _persist_state.  The write counters captured
        # ONLY that flush.
        n_entities = len(chain.supply.balances)
        balance_writes = chain.db.write_counts.get("balance", 0)
        # Strictly fewer writes than total accounts — proves scoping.
        self.assertLess(
            balance_writes, n_entities,
            f"Scoped persist must write fewer than the total account "
            f"count ({n_entities}); got {balance_writes}."
        )
        # AND at most a handful — proposer, sender, treasury, any
        # attester-reward pool recipient.  Generous upper bound.
        self.assertLessEqual(
            balance_writes, 8,
            f"Scoped persist wrote {balance_writes} balance rows for a "
            f"block that touched ~3 entities."
        )

    def test_scoped_persist_matches_full_persist_on_disk(self):
        """Correctness: a scoped persist and a full persist leave the
        SAME rows in the DB.  Reload and compare in-memory state."""
        from messagechain.core.transaction import create_transaction

        chain, consensus, entities = self._make(num_validators=3)
        chain._persist_state()                  # prime

        proposer = pick_selected_proposer(chain, entities)
        sender = entities[1] if entities[1] is not proposer else entities[2]
        tx = create_transaction(
            sender,
            "round-trip",
            fee=5000,
            nonce=chain.nonces.get(sender.entity_id, 0),
        )
        block = chain.propose_block(consensus, proposer, [tx])
        ok, _ = chain.add_block(block)
        self.assertTrue(ok)

        # Snapshot in-memory state on the live chain.
        live_balances = dict(chain.supply.balances)
        live_nonces = dict(chain.nonces)
        live_staked = dict(chain.supply.staked)
        live_watermarks = dict(chain.leaf_watermarks)

        chain.db.close()

        # Reopen from scratch; reload path rebuilds state strictly
        # from the persisted rows.  Any scoped-persist bug would
        # surface as a missing or stale row here.
        reloaded_db = ChainDB(self.db_path)
        self.assertEqual(reloaded_db.get_all_balances(), live_balances)
        self.assertEqual(reloaded_db.get_all_nonces(), live_nonces)
        self.assertEqual(reloaded_db.get_all_staked(), live_staked)
        self.assertEqual(
            reloaded_db.get_all_leaf_watermarks(), live_watermarks,
        )
        reloaded_db.close()

    def test_reset_state_forces_next_persist_to_full_flush(self):
        """After ``_reset_state`` (reorg path), the next persist
        must cover every entity — dirty tracking is invalidated."""
        chain, _, entities = self._make(num_validators=3)
        chain._persist_state()                  # prime

        chain._reset_state()
        # The reorg path replays blocks before persisting; simulate
        # that replay with a direct _touch_state for each entity
        # that _apply_block_state would touch.
        chain._touch_state(set(chain.supply.balances.keys()))

        chain.db.reset_counts()
        chain._persist_state()
        # Full flush happened — at least one balance row per live
        # entity.  The sentinel None at persist start forces the
        # "iterate every dict" path.
        self.assertGreaterEqual(
            chain.db.write_counts.get("balance", 0),
            len(chain.supply.balances),
        )


if __name__ == "__main__":
    unittest.main()
