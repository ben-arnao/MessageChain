"""Tier 17 finish: chaindb persistence, mempool admission, RPC endpoints.

Covers the wiring that builds on top of the block-pipeline integration:

* chaindb — `reaction_choices` table round-trips through
  set/clear/get_all; `_persist_state` flushes only dirty keys via
  `ReactionState._dirty_keys`; `_load_from_db` rebuilds aggregates
  from the on-disk choices.
* Mempool — `add_react_transaction` / `get_react_transactions` /
  `remove_react_transactions` honour dedup, fee floor, and the pool
  cap.
* RPC — `submit_react` validates and routes to the mempool;
  `get_user_trust` and `get_message_score` return the canonical
  on-chain aggregates.
"""

import os
import tempfile
import unittest

import messagechain.config as _config
from messagechain.config import (
    GENESIS_ALLOCATION,
    REACT_CHOICE_UP,
    REACT_CHOICE_DOWN,
    REACT_CHOICE_CLEAR,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.reaction import (
    create_react_transaction,
    ReactionState,
)
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _msg_target() -> bytes:
    return b"\xab" * 32


# ── chaindb persistence ─────────────────────────────────────────────


class TestChainDBReactionChoices(unittest.TestCase):
    """`reaction_choices` table round-trips through set/clear/get_all."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_set_and_get_all(self):
        v = b"\x01" * 32
        t1 = b"\x02" * 32
        t2 = b"\x03" * 32
        self.db.set_reaction_choice(v, t1, True, REACT_CHOICE_UP)
        self.db.set_reaction_choice(v, t2, False, REACT_CHOICE_DOWN)
        out = self.db.get_all_reaction_choices()
        self.assertEqual(out[(v, t1, True)], REACT_CHOICE_UP)
        self.assertEqual(out[(v, t2, False)], REACT_CHOICE_DOWN)

    def test_replace_overwrites(self):
        v = b"\x01" * 32
        t = b"\x02" * 32
        self.db.set_reaction_choice(v, t, True, REACT_CHOICE_UP)
        self.db.set_reaction_choice(v, t, True, REACT_CHOICE_DOWN)
        self.assertEqual(
            self.db.get_all_reaction_choices()[(v, t, True)],
            REACT_CHOICE_DOWN,
        )

    def test_clear_deletes_row(self):
        v = b"\x01" * 32
        t = b"\x02" * 32
        self.db.set_reaction_choice(v, t, True, REACT_CHOICE_UP)
        self.db.clear_reaction_choice(v, t, True)
        self.assertEqual(self.db.get_all_reaction_choices(), {})

    def test_target_type_isolation(self):
        """Same 32-byte value indexed under both target_is_user values keeps two rows."""
        v = b"\x01" * 32
        t = b"\x02" * 32
        self.db.set_reaction_choice(v, t, True, REACT_CHOICE_UP)
        self.db.set_reaction_choice(v, t, False, REACT_CHOICE_DOWN)
        out = self.db.get_all_reaction_choices()
        self.assertEqual(len(out), 2)
        self.assertEqual(out[(v, t, True)], REACT_CHOICE_UP)
        self.assertEqual(out[(v, t, False)], REACT_CHOICE_DOWN)


class TestPersistStateAndLoad(unittest.TestCase):
    """Blockchain._persist_state flushes ReactionState; _load_from_db rebuilds aggregates."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_react_height = _config.REACT_TX_HEIGHT
        _config.REACT_TX_HEIGHT = 0
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        self._orig_bc_h = _bc.REACT_TX_HEIGHT
        self._orig_rxn_h = _rxn.REACT_TX_HEIGHT
        _bc.REACT_TX_HEIGHT = 0
        _rxn.REACT_TX_HEIGHT = 0

        self.proposer = Entity.create(b"persist_prop".ljust(32, b"\x00"))
        self.voter = Entity.create(b"persist_voter".ljust(32, b"\x00"))
        self.target = Entity.create(b"persist_target".ljust(32, b"\x00"))

    def tearDown(self):
        _config.REACT_TX_HEIGHT = self._orig_react_height
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        _bc.REACT_TX_HEIGHT = self._orig_bc_h
        _rxn.REACT_TX_HEIGHT = self._orig_rxn_h
        if hasattr(self, "_chain") and self._chain.db is not None:
            self._chain.db.close()
        try:
            self.tmp.cleanup()
        except (OSError, PermissionError):
            # Windows holds onto sqlite files briefly after close;
            # ignore the cleanup race — the temp dir gets reaped by
            # the OS eventually.
            pass

    def _build_chain(self) -> Blockchain:
        db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))
        chain = Blockchain(db=db)
        chain.initialize_genesis(self.proposer)
        register_entity_for_test(chain, self.proposer)
        register_entity_for_test(chain, self.voter)
        register_entity_for_test(chain, self.target)
        chain.supply.balances[self.voter.entity_id] = 1_000_000_000
        self._chain = chain  # so tearDown can close the db handle
        return chain

    def test_persist_then_load_rebuilds_aggregates(self):
        chain = self._build_chain()
        rtx = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        chain.reaction_state.apply(rtx)
        chain._persist_state()
        # Dirty set is cleared after a successful flush so a follow-up
        # persist with no new mutations writes nothing.
        self.assertEqual(chain.reaction_state._dirty_keys, set())

        # Cold-start a fresh Blockchain from the same db.
        db2 = chain.db
        # Don't close — reuse the same handle so the memory and disk
        # views are independent (a real cold-start would open a new
        # ChainDB; for this test in-process is sufficient).
        chain2 = Blockchain(db=db2)
        chain2._load_from_db()
        self.assertEqual(
            chain2.reaction_state.user_trust_score(self.target.entity_id),
            1,
        )
        self.assertIn(
            (self.voter.entity_id, self.target.entity_id, True),
            chain2.reaction_state.choices,
        )

    def test_clear_vote_removes_persisted_row(self):
        chain = self._build_chain()
        up = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        clear = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_CLEAR, nonce=1, fee=10_000,
        )
        chain.reaction_state.apply(up)
        chain._persist_state()
        chain.reaction_state.apply(clear)
        chain._persist_state()
        self.assertEqual(chain.db.get_all_reaction_choices(), {})


# ── Mempool admission ───────────────────────────────────────────────


class TestMempoolReactPool(unittest.TestCase):
    """`add_react_transaction` enforces dedup, fee floor, cap; pull/remove work."""

    def setUp(self):
        self.voter = Entity.create(b"mp_voter".ljust(32, b"\x00"))
        self.target = Entity.create(b"mp_target".ljust(32, b"\x00"))
        self.mp = Mempool()

    def _rtx(self, nonce=0, fee=10_000, choice=REACT_CHOICE_UP):
        return create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=choice, nonce=nonce, fee=fee,
        )

    def test_add_get_remove(self):
        tx = self._rtx()
        self.assertTrue(self.mp.add_react_transaction(tx))
        self.assertEqual(self.mp.get_react_transactions(), [tx])
        self.mp.remove_react_transactions([tx.tx_hash])
        self.assertEqual(self.mp.get_react_transactions(), [])

    def test_dedup_rejects_second_insert(self):
        tx = self._rtx()
        self.assertTrue(self.mp.add_react_transaction(tx))
        self.assertFalse(self.mp.add_react_transaction(tx))

    def test_low_fee_rejected(self):
        tx = self._rtx(fee=0)
        self.assertFalse(self.mp.add_react_transaction(tx))

    def test_pool_cap(self):
        self.mp.react_pool_max_size = 2
        a = self._rtx(nonce=0)
        b = self._rtx(nonce=1)
        c = self._rtx(nonce=2)
        self.assertTrue(self.mp.add_react_transaction(a))
        self.assertTrue(self.mp.add_react_transaction(b))
        self.assertFalse(self.mp.add_react_transaction(c))


# ── RPC endpoints ───────────────────────────────────────────────────


class TestRPCReactEndpoints(unittest.TestCase):
    """`submit_react`, `get_user_trust`, `get_message_score` end-to-end via the dispatcher.

    Constructs a minimal server-like fixture rather than spinning up
    the full asyncio Server — same approach as test_rpc_attack_surface
    style fixtures.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_react_height = _config.REACT_TX_HEIGHT
        _config.REACT_TX_HEIGHT = 0
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        self._orig_bc_h = _bc.REACT_TX_HEIGHT
        self._orig_rxn_h = _rxn.REACT_TX_HEIGHT
        _bc.REACT_TX_HEIGHT = 0
        _rxn.REACT_TX_HEIGHT = 0

        self.proposer = Entity.create(b"rpc_prop".ljust(32, b"\x00"))
        self.voter = Entity.create(b"rpc_voter".ljust(32, b"\x00"))
        self.target = Entity.create(b"rpc_target".ljust(32, b"\x00"))

        db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))
        self.chain = Blockchain(db=db)
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        register_entity_for_test(self.chain, self.voter)
        register_entity_for_test(self.chain, self.target)
        self.chain.supply.balances[self.voter.entity_id] = 1_000_000_000
        self.mempool = Mempool()

        # Minimal stub that exposes the methods the RPC handlers reach into.
        from server import Server
        self.server = Server.__new__(Server)
        self.server.blockchain = self.chain
        self.server.mempool = self.mempool

    def tearDown(self):
        _config.REACT_TX_HEIGHT = self._orig_react_height
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        _bc.REACT_TX_HEIGHT = self._orig_bc_h
        _rxn.REACT_TX_HEIGHT = self._orig_rxn_h
        if self.chain.db is not None:
            self.chain.db.close()
        try:
            self.tmp.cleanup()
        except (OSError, PermissionError):
            pass

    def _submit(self, rtx):
        return self.server._rpc_submit_react({"transaction": rtx.serialize()})

    def test_submit_react_admits_to_mempool(self):
        rtx = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        resp = self._submit(rtx)
        self.assertTrue(resp["ok"], resp.get("error"))
        self.assertEqual(resp["result"]["tx_hash"], rtx.tx_hash.hex())
        self.assertEqual(self.mempool.get_react_transactions(), [rtx])

    def test_submit_react_rejects_unregistered_voter(self):
        stranger = Entity.create(b"rpc_stranger".ljust(32, b"\x00"))
        rtx = create_react_transaction(
            stranger, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        resp = self._submit(rtx)
        self.assertFalse(resp["ok"])
        self.assertIn("voter", resp["error"])

    def test_submit_react_rejects_unknown_user_target(self):
        unknown = b"\xee" * 32
        # Bypass create-time guard since unknown isn't the voter id.
        rtx = create_react_transaction(
            self.voter, target=unknown, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        resp = self._submit(rtx)
        self.assertFalse(resp["ok"])
        self.assertIn("target", resp["error"])

    def test_submit_react_rejects_unknown_message_target(self):
        rtx = create_react_transaction(
            self.voter, target=_msg_target(), target_is_user=False,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        resp = self._submit(rtx)
        self.assertFalse(resp["ok"])
        self.assertIn("target", resp["error"])

    def test_submit_react_rejects_nonce_mismatch(self):
        rtx = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=42, fee=10_000,
        )
        resp = self._submit(rtx)
        self.assertFalse(resp["ok"])
        self.assertIn("nonce", resp["error"].lower())

    def test_get_user_trust_reads_state(self):
        rtx = create_react_transaction(
            self.voter, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        self.chain.reaction_state.apply(rtx)
        resp = self.server._rpc_get_user_trust({
            "entity_id": self.target.entity_id.hex(),
        })
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["result"]["trust_score"], 1)

    def test_get_user_trust_invalid_entity(self):
        resp = self.server._rpc_get_user_trust({"entity_id": "not-hex"})
        self.assertFalse(resp["ok"])

    def test_get_message_score_reads_state(self):
        rtx = create_react_transaction(
            self.voter, target=_msg_target(), target_is_user=False,
            choice=REACT_CHOICE_DOWN, nonce=0, fee=10_000,
        )
        self.chain.reaction_state.apply(rtx)
        resp = self.server._rpc_get_message_score({
            "tx_hash": _msg_target().hex(),
        })
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["result"]["score"], -1)


if __name__ == "__main__":
    unittest.main()
