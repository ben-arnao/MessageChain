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


class TestIBDFromGenesisReconstruction(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Small tree_height so the keygen cost is trivial for tests.
        cls.tree_height = 4
        cls.founder = Entity.create(
            private_key=b"ibd-reconstruction-test-founder!" * 1,
            tree_height=cls.tree_height,
        )
        cls.founder_eid = cls.founder.entity_id

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


if __name__ == "__main__":
    unittest.main()
