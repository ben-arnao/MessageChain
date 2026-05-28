"""Phase 3 hard fork: accumulator commitment in state_root.

Pins the canonical-encoder determinism contract and the
state_root behavior on either side of
``ACCUMULATOR_COMMITMENT_HEIGHT``.

At and after the activation height, any drift in any committed
accumulator field changes the canonical state_root -- which is the
property that finally makes drift consensus-rejected at the source
instead of cascading silently.

These tests don't activate the fork on mainnet (that's the
operator-coordinated step at deploy time).  They verify the
mechanism is correct.
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import unittest

import messagechain.config as _cfg
from messagechain.config import (
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ALLOCATION,
    TREASURY_ENTITY_ID,
)
from messagechain.consensus.accumulator_commitment import (
    canon_encode,
    compute_accumulator_root,
)
from messagechain.core.blockchain import Blockchain
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


class TestCanonEncoderDeterminism(unittest.TestCase):
    """Same input → same output.  Cross-Python-run, cross-process,
    cross-PYTHONHASHSEED stability is the whole point."""

    def test_primitives(self):
        self.assertEqual(canon_encode(None), b"\x00")
        self.assertEqual(canon_encode(False), b"\x01")
        self.assertEqual(canon_encode(True), b"\x02")
        self.assertEqual(
            canon_encode(0), b"\x03" + struct.pack(">q", 0),
        )
        self.assertEqual(
            canon_encode(-1), b"\x03" + struct.pack(">q", -1),
        )
        self.assertEqual(
            canon_encode(b"abc"),
            b"\x05" + struct.pack(">I", 3) + b"abc",
        )
        self.assertEqual(
            canon_encode("abc"),
            b"\x06" + struct.pack(">I", 3) + b"abc",
        )

    def test_float_unsupported(self):
        with self.assertRaises(TypeError):
            canon_encode(1.5)

    def test_dict_order_independent(self):
        """Two dicts with same items but different insertion order
        MUST produce the same canonical encoding -- otherwise nodes
        whose mutations happened in different orders would commit
        different state_roots even though the visible state is
        identical."""
        d1 = {}
        d1[b"\x01"] = 1
        d1[b"\x02"] = 2
        d2 = {}
        d2[b"\x02"] = 2
        d2[b"\x01"] = 1
        self.assertEqual(canon_encode(d1), canon_encode(d2))

    def test_set_order_independent(self):
        """Sets MUST canonical-encode the same regardless of
        iteration order (which is PYTHONHASHSEED-dependent and
        therefore non-deterministic across nodes)."""
        s1 = {b"\x03", b"\x01", b"\x02"}
        s2 = {b"\x01", b"\x02", b"\x03"}
        self.assertEqual(canon_encode(s1), canon_encode(s2))

    def test_list_order_preserved(self):
        """Lists are ordered collections -- a different list-order
        IS a different value."""
        self.assertNotEqual(
            canon_encode([1, 2, 3]),
            canon_encode([3, 2, 1]),
        )

    def test_nested_dict_with_bytes_keys(self):
        """Real consensus state uses dict[bytes, int] (entity_id ->
        counter) heavily.  Make sure nested encoding works."""
        d = {b"alice": 10, b"bob": 20, b"\xff" * 32: 30}
        b1 = canon_encode(d)
        # Reverse insertion order
        d2 = {b"\xff" * 32: 30, b"bob": 20, b"alice": 10}
        b2 = canon_encode(d2)
        self.assertEqual(b1, b2)

    def test_unsupported_type_raises(self):
        class Custom:
            pass

        with self.assertRaises(TypeError):
            canon_encode(Custom())


class _MainnetPinOverride:
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
        if hasattr(self, "_saved_pinned"):
            _cfg.PINNED_GENESIS_HASH = self._saved_pinned
        if hasattr(self, "_saved_mainnet_hash"):
            _cfg._MAINNET_GENESIS_HASH = self._saved_mainnet_hash


class TestAccumulatorRootSensitivity(_MainnetPinOverride, unittest.TestCase):
    """``compute_accumulator_root`` must change when any committed
    field changes.  Otherwise drift would still slip through
    consensus post-activation."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"accumulator-commitment-test-fndr",
            tree_height=4,
        )

    def _build_chain(self):
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        self._install_founder(self.founder.entity_id)
        tmp = tempfile.mkdtemp(prefix="mc_accum_commit_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db = ChainDB(os.path.join(tmp, "chain.db"))
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
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
        for _ in range(2):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            ok, _ = chain.add_block(blk)
            self.assertTrue(ok)
        return chain

    def test_same_state_same_root(self):
        try:
            chain = self._build_chain()
            r1 = compute_accumulator_root(chain)
            r2 = compute_accumulator_root(chain)
            self.assertEqual(r1, r2)
            self.assertEqual(len(r1), 32)
            _close(chain.db)
        finally:
            self._restore_all()

    def test_mutating_a_counter_changes_root(self):
        """Any change to a per-validator counter MUST change the
        accumulator root -- consensus rejects drift at source."""
        try:
            chain = self._build_chain()
            r_before = compute_accumulator_root(chain)
            # Poison a non-state_root counter (this is the field
            # class that drove the 2026-05-27 drift hunt).
            chain.validator_archive_misses[self.founder.entity_id] = (
                chain.validator_archive_misses.get(
                    self.founder.entity_id, 0,
                ) + 1
            )
            r_after = compute_accumulator_root(chain)
            self.assertNotEqual(r_before, r_after)
            _close(chain.db)
        finally:
            self._restore_all()

    def test_mutating_supply_scalar_changes_root(self):
        try:
            chain = self._build_chain()
            r_before = compute_accumulator_root(chain)
            chain.supply.total_burned += 1
            r_after = compute_accumulator_root(chain)
            self.assertNotEqual(r_before, r_after)
            _close(chain.db)
        finally:
            self._restore_all()

    def test_flipping_activation_flag_changes_root(self):
        try:
            chain = self._build_chain()
            r_before = compute_accumulator_root(chain)
            chain.supply.treasury_rebase_applied = (
                not chain.supply.treasury_rebase_applied
            )
            r_after = compute_accumulator_root(chain)
            self.assertNotEqual(r_before, r_after)
            _close(chain.db)
        finally:
            self._restore_all()


class TestStateRootGate(_MainnetPinOverride, unittest.TestCase):
    """Pre-activation state_root is unchanged from 1.95.x behavior.
    Post-activation state_root mixes in the accumulator commitment."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"accum-state-root-gate-test-fndr1",
            tree_height=4,
        )

    def _build_chain(self):
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        self._install_founder(self.founder.entity_id)
        tmp = tempfile.mkdtemp(prefix="mc_accum_gate_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db = ChainDB(os.path.join(tmp, "chain.db"))
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
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
        for _ in range(2):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            self.assertTrue(chain.add_block(blk)[0])
        return chain

    def test_pre_activation_state_root_unchanged_by_accumulator(self):
        """With ACCUMULATOR_COMMITMENT_HEIGHT in the far future
        (default 10**9), poisoning an accumulator must NOT change
        state_root -- this confirms the gate works and existing
        chains are unaffected by 1.96.0 until activation."""
        try:
            chain = self._build_chain()
            r_before = chain.compute_current_state_root()
            chain.validator_archive_misses[self.founder.entity_id] = (
                chain.validator_archive_misses.get(
                    self.founder.entity_id, 0,
                ) + 1
            )
            r_after = chain.compute_current_state_root()
            self.assertEqual(
                r_before, r_after,
                "Pre-activation: accumulator changes must not "
                "affect state_root.  If this fails, the activation "
                "gate is firing prematurely.",
            )
            _close(chain.db)
        finally:
            self._restore_all()

    def test_end_to_end_activation_chain_advances(self):
        """The hard fork's real consensus contract: propose-side
        state_root must EQUAL validator-side state_root after the
        block applies, both before AND after activation height.

        Build a 3-block chain all post-activation (height set to
        1 so block 1+ is past activation).  If propose and apply
        disagree, ``chain.add_block`` rejects with 'Invalid
        state_root' and the test fails -- which would mean
        ``_compute_post_state_root_via_real_apply`` isn't producing
        the same state_root as the validator's post-apply
        ``compute_current_state_root``.

        Passing test = activation-day consensus contract works.
        Operator can then coordinate setting
        ``ACCUMULATOR_COMMITMENT_HEIGHT`` to a real value on
        mainnet without wedging the chain.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        saved_activation = _cfg.ACCUMULATOR_COMMITMENT_HEIGHT
        try:
            _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = 1
            self._install_founder(self.founder.entity_id)
            tmp = tempfile.mkdtemp(prefix="mc_accum_e2e_")
            self.addCleanup(shutil.rmtree, tmp, True)
            db = ChainDB(os.path.join(tmp, "chain.db"))
            chain = Blockchain(db=db)
            chain.initialize_genesis(
                self.founder,
                {
                    self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                    TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
                },
            )
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
            for n in range(3):
                proposer = pick_selected_proposer(
                    chain, [self.founder],
                )
                blk = chain.propose_block(consensus, proposer, [])
                ok, reason = chain.add_block(blk)
                self.assertTrue(
                    ok,
                    f"Block #{n + 1} (post-activation) failed to "
                    f"add: {reason}.  Propose-side state_root != "
                    f"apply-side state_root -- the hard-fork "
                    f"consensus contract is broken.  "
                    f"_compute_post_state_root_via_real_apply must "
                    f"produce the same root as the validator's "
                    f"post-apply compute_current_state_root.",
                )
            _close(db)
        finally:
            _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = saved_activation
            self._restore_all()

    def test_post_activation_accumulator_change_changes_state_root(self):
        """With ACCUMULATOR_COMMITMENT_HEIGHT lowered so
        ``compute_current_state_root`` is post-activation, the same
        poisoning MUST change state_root -- consensus catches the
        drift at source.

        NOTE on scope: this test exercises ONLY the
        ``compute_current_state_root`` gate.  Cross-validation
        between propose-side ``compute_post_state_root`` (a
        block-sim function that doesn't currently include the
        commitment) and apply-side ``compute_current_state_root``
        requires sim-side accumulator simulation, which is a
        follow-up before the hard fork can ACTIVATE on a live chain.
        The 1.96.0 ship lays the apply-side groundwork; the
        propose-side sim is the next layer.  Until both layers
        agree, ``ACCUMULATOR_COMMITMENT_HEIGHT`` must stay at the
        ``10**9`` placeholder on mainnet.
        """
        # Build the chain BEFORE flipping the activation height so
        # the propose/apply path uses pre-activation rules and
        # doesn't trip on the sim/apply mismatch noted above.
        try:
            chain = self._build_chain()
        finally:
            self._restore_all()

        saved_activation = _cfg.ACCUMULATOR_COMMITMENT_HEIGHT
        try:
            _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = 1  # post-activation
            r_before = chain.compute_current_state_root()
            chain.validator_archive_misses[self.founder.entity_id] = (
                chain.validator_archive_misses.get(
                    self.founder.entity_id, 0,
                ) + 1
            )
            r_after = chain.compute_current_state_root()
            self.assertNotEqual(
                r_before, r_after,
                "Post-activation: accumulator changes MUST flip "
                "state_root.  If this fails, the accumulator "
                "commitment isn't actually being mixed in -- the "
                "whole point of the hard fork is broken.",
            )
            _close(chain.db)
        finally:
            _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = saved_activation


if __name__ == "__main__":
    unittest.main()
