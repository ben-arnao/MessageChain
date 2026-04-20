"""Tests for stake-as-first-spend support.

StakeTransaction now mirrors TransferTransaction's receive-to-exist
first-spend reveal pattern: a new entity's FIRST on-chain action can be
either a Transfer OR a Stake.  In either case the tx carries
`sender_pubkey` so the chain can verify the signature and install the
pubkey into state.

Invariants mirrored from Transfer (see test_receive_to_exist.py):
  * On first-spend: sender_pubkey required, derive_entity_id check,
    signature verified against it, pubkey installed on apply.
  * On subsequent spends: sender_pubkey MUST be empty; non-empty is
    malleability and rejected.
  * The field is committed to tx_hash via a length-prefixed slot in
    `_signable_data` (same pattern as Transfer), so tampering is
    tamper-evident.
  * Leaf-reuse guard still applies.
  * Within a single block: a Transfer that funds X followed by a Stake
    from X (first-spend) validates & applies correctly; the simulated
    state root matches the applied one.
"""

import unittest

from messagechain import config
from messagechain.config import GENESIS_ALLOCATION, MIN_FEE, NEW_ACCOUNT_FEE
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block
from messagechain.core.staking import (
    StakeTransaction,
    create_stake_transaction,
    verify_stake_transaction,
)
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity, derive_entity_id


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestStakeSenderPubkeyField(unittest.TestCase):
    """StakeTransaction gains an optional sender_pubkey field."""

    def setUp(self):
        self.sender = _entity(b"stake-pk-sender")

    def test_sender_pubkey_field_default_empty(self):
        """By default a StakeTransaction's sender_pubkey is empty."""
        stx = create_stake_transaction(self.sender, amount=1000, nonce=0)
        self.assertEqual(stx.sender_pubkey, b"")

    def test_sender_pubkey_included_when_requested(self):
        """create_stake_transaction(include_pubkey=True) populates sender_pubkey."""
        stx = create_stake_transaction(
            self.sender, amount=1000, nonce=0, include_pubkey=True,
        )
        self.assertEqual(stx.sender_pubkey, self.sender.public_key)

    def test_sender_pubkey_committed_to_tx_hash(self):
        """Flipping sender_pubkey from empty to non-empty changes tx_hash."""
        stx_without = create_stake_transaction(self.sender, amount=1000, nonce=0)
        stx_with = create_stake_transaction(
            self.sender, amount=1000, nonce=0, include_pubkey=True,
        )
        self.assertNotEqual(stx_without.tx_hash, stx_with.tx_hash)

    def test_stake_roundtrip_binary_with_pubkey(self):
        """Binary round-trip preserves sender_pubkey."""
        stx = create_stake_transaction(
            self.sender, amount=1000, nonce=0, include_pubkey=True,
        )
        blob = stx.to_bytes()
        decoded = StakeTransaction.from_bytes(blob)
        self.assertEqual(decoded.sender_pubkey, self.sender.public_key)
        self.assertEqual(decoded.tx_hash, stx.tx_hash)

    def test_stake_roundtrip_json_with_pubkey(self):
        """JSON round-trip preserves sender_pubkey."""
        stx = create_stake_transaction(
            self.sender, amount=1000, nonce=0, include_pubkey=True,
        )
        decoded = StakeTransaction.deserialize(stx.serialize())
        self.assertEqual(decoded.sender_pubkey, self.sender.public_key)
        self.assertEqual(decoded.tx_hash, stx.tx_hash)

    def test_verify_stake_signature_with_explicit_pubkey(self):
        """verify_stake_transaction works when handed the sender's own pubkey."""
        stx = create_stake_transaction(
            self.sender, amount=1000, nonce=0, include_pubkey=True,
        )
        self.assertTrue(verify_stake_transaction(stx, self.sender.public_key))

    def test_stake_roundtrip_binary_without_pubkey(self):
        """Binary round-trip without sender_pubkey still works (legacy path)."""
        stx = create_stake_transaction(self.sender, amount=1000, nonce=0)
        blob = stx.to_bytes()
        decoded = StakeTransaction.from_bytes(blob)
        self.assertEqual(decoded.sender_pubkey, b"")
        self.assertEqual(decoded.tx_hash, stx.tx_hash)


class TestStakeFirstSpendValidation(unittest.TestCase):
    """Funded-but-unregistered entity's first stake with include_pubkey must pass."""

    def _prep_chain_with_funded_new_entity(self):
        funder = _entity(b"funder_stake_fs")
        new_entity = _entity(b"new_stake_fs")
        chain = Blockchain()
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000
        # Fund the new entity but don't install its pubkey.  Brand-new
        # recipient → MIN_FEE + NEW_ACCOUNT_FEE.
        tx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        ok, reason = chain.validate_transfer_transaction(tx)
        self.assertTrue(ok, reason)
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)
        self.assertGreater(chain.supply.get_balance(new_entity.entity_id), 0)
        self.assertNotIn(new_entity.entity_id, chain.public_keys)
        return chain, funder, new_entity

    def test_first_stake_with_pubkey_validates(self):
        chain, _, new_entity = self._prep_chain_with_funded_new_entity()
        stx = create_stake_transaction(
            new_entity, amount=1000, nonce=0, include_pubkey=True,
        )
        ok, reason = chain._validate_stake_tx(stx)
        self.assertTrue(ok, f"First-spend stake with pubkey must validate: {reason}")

    def test_first_stake_without_pubkey_is_rejected(self):
        chain, _, new_entity = self._prep_chain_with_funded_new_entity()
        stx = create_stake_transaction(new_entity, amount=1000, nonce=0)
        ok, reason = chain._validate_stake_tx(stx)
        self.assertFalse(ok, "Stake from unregistered entity without pubkey must fail")
        # Must be rejected for a missing-pubkey reason, not some other structural issue.
        self.assertTrue(
            "pubkey" in reason.lower() or "unknown" in reason.lower()
            or "register" in reason.lower() or "first" in reason.lower(),
            f"Expected a missing-pubkey error, got: {reason}",
        )

    def test_first_stake_with_mismatched_pubkey_rejected(self):
        chain, _, new_entity = self._prep_chain_with_funded_new_entity()
        impostor = _entity(b"impostor_stake_fs")

        stx = create_stake_transaction(
            new_entity, amount=1000, nonce=0, include_pubkey=True,
        )
        # A relayer swaps the pubkey for one whose hash doesn't match entity_id.
        stx.sender_pubkey = impostor.public_key
        stx.tx_hash = stx._compute_hash()

        ok, reason = chain._validate_stake_tx(stx)
        self.assertFalse(ok)
        self.assertTrue(
            "derive" in reason.lower() or "mismatch" in reason.lower()
            or "does not" in reason.lower(),
            f"Expected a pubkey-hash-mismatch error, got: {reason}",
        )


class TestKnownEntityMalleability(unittest.TestCase):
    """Known entities staking must leave sender_pubkey empty."""

    def test_known_entity_stake_with_nonempty_pubkey_rejected(self):
        funder = _entity(b"km_funder")
        new_entity = _entity(b"km_new")
        chain = Blockchain()
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000
        tx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        self.assertTrue(chain.validate_transfer_transaction(tx)[0])
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)

        # First stake with pubkey — installs the pubkey.
        stx1 = create_stake_transaction(
            new_entity, amount=1000, nonce=0, include_pubkey=True,
        )
        ok, reason = chain._validate_stake_tx(stx1)
        self.assertTrue(ok, reason)
        # Apply via the block pipeline would be heavier; here we just call
        # the public_keys install path via the stake-apply routine so the
        # entity is "known" in the same way propose_block would make it.
        chain.apply_stake_transaction(stx1, proposer_id=funder.entity_id)
        self.assertIn(new_entity.entity_id, chain.public_keys)

        # Second stake: sender_pubkey must now be empty.
        stx2 = create_stake_transaction(
            new_entity, amount=500, nonce=1, include_pubkey=True,
        )
        ok, reason = chain._validate_stake_tx(stx2)
        self.assertFalse(ok, "Second stake with pubkey must be rejected")
        self.assertIn("empty", reason.lower())

    def test_known_entity_stake_with_empty_pubkey_validates(self):
        from tests import register_entity_for_test
        funder = _entity(b"ke_funder")
        user = _entity(b"ke_user")
        chain = Blockchain()
        chain.initialize_genesis(funder)
        # Register via the legacy test helper so the entity is "known".
        ok, _ = register_entity_for_test(chain, user)
        self.assertTrue(ok)
        chain.supply.balances[user.entity_id] = 100_000

        stx = create_stake_transaction(user, amount=1000, nonce=0)
        ok, reason = chain._validate_stake_tx(stx)
        self.assertTrue(ok, f"Known entity stake with empty pubkey must pass: {reason}")


class TestStakeFirstSpendApply(unittest.TestCase):
    """apply_stake_transaction on first-spend installs pubkey + assigns index."""

    def test_apply_stake_installs_pubkey_assigns_index_bumps_watermark(self):
        funder = _entity(b"apply_funder")
        new_entity = _entity(b"apply_new")
        chain = Blockchain()
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000
        tx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        self.assertTrue(chain.validate_transfer_transaction(tx)[0])
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)

        self.assertNotIn(new_entity.entity_id, chain.public_keys)
        self.assertNotIn(new_entity.entity_id, chain.entity_id_to_index)

        stx = create_stake_transaction(
            new_entity, amount=1000, nonce=0, include_pubkey=True,
        )
        ok, reason = chain._validate_stake_tx(stx)
        self.assertTrue(ok, reason)
        chain.apply_stake_transaction(stx, proposer_id=funder.entity_id)

        # Pubkey installed.
        self.assertIn(new_entity.entity_id, chain.public_keys)
        self.assertEqual(chain.public_keys[new_entity.entity_id], new_entity.public_key)
        # Nonce bumped.
        self.assertEqual(chain.nonces[new_entity.entity_id], 1)
        # Leaf watermark moved past the consumed leaf.
        self.assertGreater(chain.leaf_watermarks[new_entity.entity_id], 0)
        # Stake reflected.
        self.assertEqual(chain.supply.get_staked(new_entity.entity_id), 1000)
        # Entity index assigned.
        self.assertIn(new_entity.entity_id, chain.entity_id_to_index)

    def test_leaf_reuse_after_first_spend_stake_rejected(self):
        """After a first-spend stake consumes a leaf, re-using it is rejected."""
        funder = _entity(b"reuse_funder")
        new_entity = _entity(b"reuse_new")
        chain = Blockchain()
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000
        tx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)

        stx = create_stake_transaction(
            new_entity, amount=1000, nonce=0, include_pubkey=True,
        )
        chain.apply_stake_transaction(stx, proposer_id=funder.entity_id)
        consumed_leaf = stx.signature.leaf_index

        # Craft a second stake signed with a leaf at or below the watermark.
        # Easiest way: mutate the signature.leaf_index on a fresh tx to the
        # already-consumed value and recompute the tx_hash — it'll pass
        # deserialization but fail the watermark check at validate.
        stx2 = create_stake_transaction(new_entity, amount=500, nonce=1)
        if stx2.signature.leaf_index > consumed_leaf:
            stx2.signature.leaf_index = consumed_leaf
            # Re-sign would be wrong; we just want the pre-sig watermark
            # check to fire.  We manipulate leaf_index directly.
        ok, reason = chain._validate_stake_tx(stx2)
        self.assertFalse(ok, "Reusing a consumed leaf must be rejected")
        self.assertIn("leaf", reason.lower())


class TestStakeFirstSpendSingleBlock(unittest.TestCase):
    """A single block containing "fund X via Transfer + X stakes as first-spend"
    validates and applies correctly."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_single_block_fund_then_stake_first_spend(self):
        funder = _entity(b"sb_funder")
        new_entity = _entity(b"sb_new")
        chain = Blockchain()
        chain.initialize_genesis(funder)
        # Give funder a big liquid balance.
        chain.supply.balances[funder.entity_id] = 1_000_000

        # Transfer that funds new_entity.  Brand-new recipient → surcharge.
        ttx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        # Stake from new_entity using first-spend pubkey reveal.
        stx = create_stake_transaction(
            new_entity, amount=100_000, nonce=0, fee=MIN_FEE,
            include_pubkey=True,
        )

        consensus = ProofOfStake()
        block = chain.propose_block(
            consensus, funder, [],
            transfer_transactions=[ttx],
            stake_transactions=[stx],
        )

        # Round-trip through serialize/deserialize to prove sender_pubkey
        # survives the block envelope (sanity check).
        rehydrated = Block.deserialize(block.serialize())
        self.assertEqual(len(rehydrated.stake_transactions), 1)
        self.assertEqual(
            rehydrated.stake_transactions[0].sender_pubkey,
            new_entity.public_key,
        )

        # Add via the main pipeline — which uses validate_block's
        # cumulative pending-state tracking (transfers credit recipients
        # visible to later-in-block stake txs) and the apply path's
        # first-spend install.
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, f"Block must apply: {reason}")
        self.assertIn(new_entity.entity_id, chain.public_keys)
        self.assertEqual(chain.supply.get_staked(new_entity.entity_id), 100_000)

    def test_state_root_simulation_matches_apply(self):
        """propose_block's state_root prediction must match post-apply reality
        when the block contains a first-spend stake."""
        funder = _entity(b"sr_funder")
        new_entity = _entity(b"sr_new")
        chain = Blockchain()
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000

        ttx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        stx = create_stake_transaction(
            new_entity, amount=100_000, nonce=0, fee=MIN_FEE,
            include_pubkey=True,
        )

        consensus = ProofOfStake()
        # propose_block internally computes expected state_root via the
        # simulated path; if that prediction diverges from the actual apply
        # path, add_block would reject the block with a state-root
        # mismatch.  Running end-to-end covers this.
        block = chain.propose_block(
            consensus, funder, [],
            transfer_transactions=[ttx],
            stake_transactions=[stx],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(
            ok,
            f"State root must match between simulation and apply "
            f"(first-spend stake in same block as funding transfer): {reason}",
        )


class TestStakeFirstSpendStandaloneEntity(unittest.TestCase):
    """New validator bootstraps via receive+stake only (no prior Transfer)."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_new_validator_can_stake_as_first_action(self):
        """A validator who received funds but never Transferred can still stake
        directly, and is recognized on-chain afterwards."""
        genesis = _entity(b"gen_solo")
        newcomer = _entity(b"newcomer_solo")
        chain = Blockchain()
        chain.initialize_genesis(genesis)
        chain.supply.balances[genesis.entity_id] = 1_000_000

        # Block 1: genesis transfers funds to newcomer.  Brand-new
        # recipient → MIN_FEE + NEW_ACCOUNT_FEE.
        consensus = ProofOfStake()
        ttx = create_transfer_transaction(
            genesis, newcomer.entity_id, 300_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        blk1 = chain.propose_block(
            consensus, genesis, [],
            transfer_transactions=[ttx],
        )
        ok, reason = chain.add_block(blk1)
        self.assertTrue(ok, reason)

        # Post-block 1: newcomer is funded, no pubkey yet.
        self.assertGreater(chain.supply.get_balance(newcomer.entity_id), 0)
        self.assertNotIn(newcomer.entity_id, chain.public_keys)

        # Block 2: newcomer stakes for the first time — this is the natural
        # first-action flow the feature enables.  Stake carries pubkey.
        stx = create_stake_transaction(
            newcomer, amount=100_000, nonce=0, fee=MIN_FEE,
            include_pubkey=True,
        )
        blk2 = chain.propose_block(
            consensus, genesis, [],
            stake_transactions=[stx],
        )
        ok, reason = chain.add_block(blk2)
        self.assertTrue(ok, f"First-action stake must apply: {reason}")

        # Post-block 2: newcomer is fully registered and staked.
        self.assertIn(newcomer.entity_id, chain.public_keys)
        self.assertEqual(chain.public_keys[newcomer.entity_id], newcomer.public_key)
        self.assertEqual(chain.supply.get_staked(newcomer.entity_id), 100_000)


if __name__ == "__main__":
    unittest.main()
