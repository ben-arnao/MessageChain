"""IBD-from-genesis reconstruction tests.

Validator #2 onboarding onto a running mainnet must work via plain P2P
sync — no out-of-band state snapshot required.  The founder's launch
flow minted block 0 and then applied off-block direct-state mutations
(register founder pubkey, self-authority-key, stake 95M).  Those
mutations aren't serialised in the block; a joining node can only
reconstruct them from:

  1. Block 0 itself (pinned by hash in config).
  2. Canonical allocation constants in config (_MAINNET_FOUNDER_LIQUID
     / _MAINNET_FOUNDER_STAKE).

This test asserts that Blockchain._apply_mainnet_genesis_state produces
the same state a founder's initialize_genesis + bootstrap_seed_local
flow produces — i.e., two independently-built Blockchains land at an
identical state_root, balances, nonces, authority_keys, watermarks,
and seed set.  If the constants drift from the founder's actual
parameters, this test fails loudly.
"""

from __future__ import annotations

import unittest

import messagechain.config as _cfg
from messagechain.config import (
    _MAINNET_FOUNDER_LIQUID,
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ENTITY_ID,
    TREASURY_ALLOCATION,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.crypto.keys import compute_root_from_signature
from messagechain.identity.identity import Entity, derive_entity_id


class _PinOverrideMixin:
    """Redirects `_MAINNET_FOUNDER_ENTITY_ID` to the test founder's
    entity_id so the defense-in-depth pin check passes for test
    fixtures that use ephemeral keys (we don't have the real mainnet
    founder's private key at test time)."""
    _saved_pin: object = object()

    @classmethod
    def _install_pin(cls, eid: bytes):
        cls._saved_pin = _cfg._MAINNET_FOUNDER_ENTITY_ID
        _cfg._MAINNET_FOUNDER_ENTITY_ID = eid

    @classmethod
    def _restore_pin(cls):
        _cfg._MAINNET_FOUNDER_ENTITY_ID = cls._saved_pin


class TestIBDFromGenesisReconstruction(_PinOverrideMixin, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Small tree_height so the keygen cost is trivial for tests.
        cls.tree_height = 4
        cls.founder = Entity.create(
            private_key=b"ibd-reconstruction-test-founder!" * 1,
            tree_height=cls.tree_height,
        )
        cls.founder_eid = cls.founder.entity_id
        cls._install_pin(cls.founder_eid)

    @classmethod
    def tearDownClass(cls):
        cls._restore_pin()

    def _build_founder_chain(self):
        """Replicate launch_single_validator.py exactly, in-memory."""
        chain = Blockchain(db=None)
        allocation = {
            self.founder_eid: _MAINNET_FOUNDER_TOTAL,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        block0 = chain.initialize_genesis(self.founder, allocation)
        ok, log = bootstrap_seed_local(
            chain, self.founder,
            cold_authority_pubkey=self.founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        self.assertTrue(ok, f"bootstrap_seed_local failed: {log}")
        return chain, block0

    def _build_joiner_chain(self, block0):
        """Simulate val-2 receiving block 0 and reconstructing state."""
        chain = Blockchain(db=None)
        ok, reason = chain._apply_mainnet_genesis_state(block0)
        self.assertTrue(ok, f"_apply_mainnet_genesis_state failed: {reason}")
        return chain

    def test_founder_pubkey_recoverable_from_block0(self):
        founder_chain, block0 = self._build_founder_chain()
        recovered = compute_root_from_signature(
            block0.header.proposer_signature,
        )
        self.assertEqual(recovered, self.founder.public_key,
                         "block 0 signature's Merkle root should equal "
                         "founder's long-term public key")
        self.assertEqual(derive_entity_id(recovered), self.founder_eid,
                         "derived entity_id should match founder's")

    def test_joiner_state_matches_founder(self):
        founder_chain, block0 = self._build_founder_chain()
        joiner_chain = self._build_joiner_chain(block0)

        eid = self.founder_eid
        # Balances
        self.assertEqual(
            joiner_chain.supply.get_balance(eid),
            founder_chain.supply.get_balance(eid),
            "founder liquid balance must match",
        )
        self.assertEqual(
            joiner_chain.supply.get_balance(TREASURY_ENTITY_ID),
            founder_chain.supply.get_balance(TREASURY_ENTITY_ID),
            "treasury balance must match",
        )
        # Stake
        self.assertEqual(
            joiner_chain.supply.get_staked(eid),
            founder_chain.supply.get_staked(eid),
            "founder stake must match",
        )
        self.assertEqual(
            joiner_chain.supply.get_staked(eid),
            _MAINNET_FOUNDER_STAKE,
            "joiner's founder stake must equal canonical constant",
        )
        # Nonce
        self.assertEqual(
            joiner_chain.nonces[eid], founder_chain.nonces[eid],
            "founder nonce must match",
        )
        # Authority — mainnet founder's authority falls through to the
        # hot pubkey (launch script passed hot=hot, so set-auth skipped).
        # Both sides should return the same effective key via the
        # get_authority_key fallback.
        self.assertEqual(
            joiner_chain.get_authority_key(eid),
            founder_chain.get_authority_key(eid),
            "founder effective authority_key must match",
        )
        # Public keys
        self.assertEqual(
            joiner_chain.public_keys[eid],
            founder_chain.public_keys[eid],
            "founder public_key must match",
        )
        # Watermarks
        self.assertEqual(
            joiner_chain.leaf_watermarks[eid],
            founder_chain.leaf_watermarks[eid],
            "founder leaf_watermark must match — state_tree "
            "commits to this, so divergence would reject block 1",
        )
        # Proposer sig counts
        self.assertEqual(
            joiner_chain.proposer_sig_counts[eid],
            founder_chain.proposer_sig_counts[eid],
        )
        # Seed set
        self.assertEqual(
            joiner_chain.seed_entity_ids,
            founder_chain.seed_entity_ids,
        )
        # Tree height
        self.assertEqual(
            joiner_chain.wots_tree_heights[eid],
            founder_chain.wots_tree_heights[eid],
        )
        # Supply-level totals
        self.assertEqual(
            joiner_chain.supply.total_supply,
            founder_chain.supply.total_supply,
            "total_supply must match (both should reflect the burn of "
            "MIN_FEE from the set-authority-key tx)",
        )
        self.assertEqual(
            joiner_chain.supply.total_burned,
            founder_chain.supply.total_burned,
        )

    def test_joiner_state_root_matches_founder(self):
        """The canonical cryptographic equivalence check: if the state
        trees compute to the same root, block 1's state_root commitment
        will be identical whether computed by founder or joiner — which
        is precisely what P2P consensus requires."""
        founder_chain, block0 = self._build_founder_chain()
        joiner_chain = self._build_joiner_chain(block0)
        self.assertEqual(
            joiner_chain.compute_current_state_root(),
            founder_chain.compute_current_state_root(),
            "state_root must match between founder and joiner — "
            "mismatch would reject block 1 during IBD",
        )

    def test_joiner_rejects_malformed_block0_signature(self):
        founder_chain, block0 = self._build_founder_chain()
        # Corrupt the signature's wots_public_key
        import copy
        bad_block = copy.deepcopy(block0)
        bad_block.header.proposer_signature.wots_public_key = b"\x00" * 32
        chain = Blockchain(db=None)
        ok, reason = chain._apply_mainnet_genesis_state(bad_block)
        self.assertFalse(ok)

    def test_joiner_rejects_proposer_id_mismatch(self):
        founder_chain, block0 = self._build_founder_chain()
        import copy
        bad_block = copy.deepcopy(block0)
        # Rewrite proposer_id to something that doesn't match the
        # pubkey the signature would recover to.
        bad_block.header.proposer_id = b"\xff" * 32
        chain = Blockchain(db=None)
        ok, reason = chain._apply_mainnet_genesis_state(bad_block)
        self.assertFalse(ok)
        self.assertIn("proposer_id", reason)


class TestIBDOrphanDrain(_PinOverrideMixin, unittest.TestCase):
    """Val-2 during IBD often receives block 1+ before block 0.  Those
    land in the orphan pool; after block 0 arrives the orphans must be
    re-examined automatically, not left stranded until a peer happens
    to resend them.
    """

    def test_orphan_drained_after_synced_genesis(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity

        founder = Entity.create(
            private_key=b"orphan-drain-test-founder-key!!!" * 1,
            tree_height=4,
        )
        self._install_pin(founder.entity_id)
        self.addCleanup(self._restore_pin)
        founder_chain = Blockchain(db=None)
        allocation = {
            founder.entity_id: _MAINNET_FOUNDER_TOTAL,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        block0 = founder_chain.initialize_genesis(founder, allocation)
        ok, _ = bootstrap_seed_local(
            founder_chain, founder,
            cold_authority_pubkey=founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        self.assertTrue(ok)

        # Val-2 joiner: receives a NON-zero block first (land as orphan),
        # then receives block 0 and should drain the orphan.
        joiner = Blockchain(db=None)
        # Give joiner a fake "future" block with prev_hash=block0.hash.
        # add_block's empty-chain guard stores it in the orphan pool.
        # We don't need it to be *valid* block 1 — the orphan pool is a
        # structure-only cache, and _process_orphans will attempt to
        # apply it but benignly fail (not panic) when the block doesn't
        # validate.  What we verify is the DRAIN ATTEMPT happened.
        import copy
        fake_block1 = copy.deepcopy(block0)
        fake_block1.header.block_number = 1
        fake_block1.header.prev_hash = block0.block_hash
        fake_block1.block_hash = fake_block1._compute_hash()
        # Step 1: submit "block 1" first — chain is empty, stored as orphan.
        joiner.add_block(fake_block1)
        self.assertIn(fake_block1.block_hash, joiner.orphan_pool,
                      "fake block-1 should be orphaned on empty chain")
        # Step 2: submit block 0 via synced-reconstruction path.
        ok, _ = joiner._apply_mainnet_genesis_state(block0)
        self.assertTrue(ok)
        # The orphan should have been examined (drained out of the pool).
        # The fake block is malformed so it won't actually be appended,
        # but _process_orphans should have removed it.  Structure-valid
        # orphans would be applied in the same pass.
        self.assertNotIn(fake_block1.block_hash, joiner.orphan_pool,
                         "orphan pool should be drained after block 0 "
                         "applied — _process_orphans must run")


class TestSeedEntityIdsRehydration(unittest.TestCase):
    """seed_entity_ids is consensus-visible (attester committee tilt,
    reputation-lottery exclusion) but was never persisted.  _load_from_db
    now re-derives it from block 0's proposer_id."""

    def test_load_from_db_restores_seed_entity_ids(self):
        import tempfile, os
        from messagechain.core.blockchain import Blockchain
        from messagechain.storage.chaindb import ChainDB
        from messagechain.identity.identity import Entity

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "chain.db")
            founder = Entity.create(
                private_key=b"seed-rehydration-test-founder-ky" * 1,
                tree_height=4,
            )
            db1 = ChainDB(db_path)
            chain1 = Blockchain(db=db1)
            allocation = {
                founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            }
            chain1.initialize_genesis(founder, allocation)
            bootstrap_seed_local(
                chain1, founder,
                cold_authority_pubkey=founder.public_key,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            chain1._persist_state()
            self.assertEqual(chain1.seed_entity_ids,
                             frozenset({founder.entity_id}))
            db1.close()

            # Reload from disk — seed_entity_ids must survive.
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            self.assertEqual(chain2.seed_entity_ids,
                             frozenset({founder.entity_id}),
                             "seed_entity_ids must be re-derived from "
                             "block 0 on restart — empty set changes "
                             "committee weights and breaks consensus")
            db2.close()


class TestMainnetFounderConstants(unittest.TestCase):
    """Config-load sanity checks: the canonical mainnet allocation must
    be internally consistent.  If these raise at import time, a joining
    node crashes loudly at config load instead of silently IBD'ing into
    a bad state."""

    def test_constants_fit_in_supply(self):
        from messagechain.config import (
            _MAINNET_FOUNDER_TOTAL, TREASURY_ALLOCATION, GENESIS_SUPPLY,
        )
        self.assertLessEqual(
            _MAINNET_FOUNDER_TOTAL + TREASURY_ALLOCATION, GENESIS_SUPPLY,
        )

    def test_founder_entity_id_pin_length(self):
        from messagechain.config import _MAINNET_FOUNDER_ENTITY_ID
        self.assertIsNotNone(_MAINNET_FOUNDER_ENTITY_ID)
        self.assertEqual(len(_MAINNET_FOUNDER_ENTITY_ID), 32)


if __name__ == "__main__":
    unittest.main()
