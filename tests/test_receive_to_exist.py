"""Tests for the receive-to-exist account model.

This model replaces the explicit RegistrationTransaction with an implicit
Bitcoin P2PKH-style flow:

  * Entities enter on-chain state ONLY as a consequence of receiving a
    transfer (or a validator reward).  No self-registration tx.
  * On their FIRST outgoing Transfer, a brand-new entity must include
    `sender_pubkey` so the chain can verify the signature and install
    the pubkey into state.
  * Subsequent outgoing txs from the same entity must leave
    `sender_pubkey` empty (defense against malleability).

Other tx types (Stake, Message, Authority, KeyRotation) do NOT carry a
self-reveal field; they look up the pubkey from chain state.  If the
entity hasn't established its pubkey via a first Transfer yet, these
operations fail with a clear error.
"""

import time
import unittest

from messagechain.config import GENESIS_ALLOCATION, MIN_FEE, NEW_ACCOUNT_FEE
from messagechain.identity.identity import Entity, derive_entity_id
from messagechain.core.blockchain import Blockchain
from messagechain.core.transfer import (
    TransferTransaction,
    create_transfer_transaction,
    verify_transfer_transaction,
)
from tests import register_entity_for_test, pick_selected_proposer


class TestTransferSenderPubkeyField(unittest.TestCase):
    """TransferTransaction gains an optional sender_pubkey field."""

    def setUp(self):
        self.sender = Entity.create(b"sender_exist_key".ljust(32, b"\x00"))
        self.recipient = Entity.create(b"recipient_exist_key".ljust(32, b"\x00"))

    def test_sender_pubkey_field_default_empty(self):
        """By default a TransferTransaction's sender_pubkey is empty."""
        tx = create_transfer_transaction(
            self.sender, self.recipient.entity_id, 50, nonce=0,
        )
        self.assertEqual(tx.sender_pubkey, b"")

    def test_sender_pubkey_included_when_requested(self):
        """create_transfer_transaction(include_pubkey=True) populates sender_pubkey."""
        tx = create_transfer_transaction(
            self.sender, self.recipient.entity_id, 50, nonce=0,
            include_pubkey=True,
        )
        self.assertEqual(tx.sender_pubkey, self.sender.public_key)

    def test_sender_pubkey_committed_to_tx_hash(self):
        """Flipping sender_pubkey from empty to non-empty changes tx_hash
        (prevents a relayer from stripping the pubkey after signing)."""
        tx_without = create_transfer_transaction(
            self.sender, self.recipient.entity_id, 50, nonce=0,
        )
        tx_with = create_transfer_transaction(
            self.sender, self.recipient.entity_id, 50, nonce=0,
            include_pubkey=True,
        )
        self.assertNotEqual(tx_without.tx_hash, tx_with.tx_hash)

    def test_transfer_roundtrip_binary_with_pubkey(self):
        """Binary round-trip preserves sender_pubkey."""
        tx = create_transfer_transaction(
            self.sender, self.recipient.entity_id, 50, nonce=0,
            include_pubkey=True,
        )
        blob = tx.to_bytes()
        decoded = TransferTransaction.from_bytes(blob)
        self.assertEqual(decoded.sender_pubkey, self.sender.public_key)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)

    def test_transfer_roundtrip_json_with_pubkey(self):
        """JSON round-trip preserves sender_pubkey."""
        tx = create_transfer_transaction(
            self.sender, self.recipient.entity_id, 50, nonce=0,
            include_pubkey=True,
        )
        decoded = TransferTransaction.deserialize(tx.serialize())
        self.assertEqual(decoded.sender_pubkey, self.sender.public_key)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)

    def test_verify_transfer_signature_with_explicit_pubkey(self):
        """The verify helper works when handed the sender's own pubkey."""
        tx = create_transfer_transaction(
            self.sender, self.recipient.entity_id, 50, nonce=0,
            include_pubkey=True,
        )
        self.assertTrue(verify_transfer_transaction(tx, self.sender.public_key))


class TestImplicitRecipientCreation(unittest.TestCase):
    """Transferring to an unknown recipient creates a balance entry."""

    def _make_chain(self, sender, recipient_eid):
        chain = Blockchain()
        # Only the sender exists at genesis (is allocated liquid balance).
        chain.initialize_genesis(sender, allocation_table={sender.entity_id: GENESIS_ALLOCATION})
        return chain

    def test_transfer_to_unknown_recipient_is_accepted(self):
        """Validation passes even when the recipient has never been seen."""
        sender = Entity.create(b"tx_sender_key".ljust(32, b"\x00"))
        # Unknown recipient — we only know an entity_id derived from a pubkey
        # but that pubkey is NOT in chain state.
        recipient = Entity.create(b"unknown_recipient".ljust(32, b"\x00"))
        chain = self._make_chain(sender, recipient.entity_id)

        # Brand-new recipient → must pay MIN_FEE + NEW_ACCOUNT_FEE.
        tx = create_transfer_transaction(
            sender, recipient.entity_id, 100, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        ok, reason = chain.validate_transfer_transaction(tx)
        self.assertTrue(ok, f"Unknown recipient should be accepted now: {reason}")

    def test_apply_transfer_creates_recipient_balance(self):
        """Applying a transfer credits the unknown recipient's balance."""
        sender = Entity.create(b"tx_sender_key2".ljust(32, b"\x00"))
        recipient = Entity.create(b"unknown_recipient2".ljust(32, b"\x00"))
        chain = self._make_chain(sender, recipient.entity_id)

        self.assertNotIn(recipient.entity_id, chain.supply.balances)
        self.assertNotIn(recipient.entity_id, chain.public_keys)

        tx = create_transfer_transaction(
            sender, recipient.entity_id, 100, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        ok, _ = chain.validate_transfer_transaction(tx)
        self.assertTrue(ok)
        chain.apply_transfer_transaction(tx, proposer_id=sender.entity_id)

        self.assertEqual(chain.supply.get_balance(recipient.entity_id), 100)
        # Receiving alone does NOT install a pubkey.
        self.assertNotIn(recipient.entity_id, chain.public_keys)


class TestFirstSpendPubkeyReveal(unittest.TestCase):
    """First outgoing Transfer must include sender_pubkey; installs it."""

    def _prep_chain_with_funded_new_entity(self):
        """Build a chain where `new_entity` has a balance but no pubkey."""
        funder = Entity.create(b"funder_key".ljust(32, b"\x00"))
        new_entity = Entity.create(b"brand_new_key".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(
            funder, allocation_table={funder.entity_id: GENESIS_ALLOCATION},
        )
        # Fund new_entity via a direct transfer application — no block
        # machinery, we just want state that looks like "received funds
        # but never spent."  New account → MIN_FEE + NEW_ACCOUNT_FEE.
        tx = create_transfer_transaction(
            funder, new_entity.entity_id, 5_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        ok, reason = chain.validate_transfer_transaction(tx)
        self.assertTrue(ok, reason)
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)
        # Post-condition: funded but unknown pubkey.
        self.assertGreater(chain.supply.get_balance(new_entity.entity_id), 0)
        self.assertNotIn(new_entity.entity_id, chain.public_keys)
        return chain, funder, new_entity

    def test_first_outgoing_transfer_with_pubkey_succeeds_and_installs(self):
        """First outgoing Transfer reveals the pubkey and installs it."""
        chain, funder, new_entity = self._prep_chain_with_funded_new_entity()
        destination = Entity.create(b"destination_key".ljust(32, b"\x00"))

        # Brand-new destination → MIN_FEE + NEW_ACCOUNT_FEE.
        tx = create_transfer_transaction(
            new_entity, destination.entity_id, 100, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
            include_pubkey=True,
        )
        ok, reason = chain.validate_transfer_transaction(tx)
        self.assertTrue(ok, f"First outgoing transfer with pubkey must validate: {reason}")
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)

        # Pubkey now installed.
        self.assertIn(new_entity.entity_id, chain.public_keys)
        self.assertEqual(chain.public_keys[new_entity.entity_id], new_entity.public_key)
        # Nonce initialized + bumped.
        self.assertEqual(chain.nonces[new_entity.entity_id], 1)
        # Watermark bumped past the signature's leaf.
        self.assertGreater(chain.leaf_watermarks[new_entity.entity_id], 0)

    def test_first_outgoing_transfer_without_pubkey_is_rejected(self):
        """Missing sender_pubkey on a first outgoing transfer is rejected.

        Use an EXISTING destination so the surcharge check doesn't fire
        first — we want to exercise the "must include sender_pubkey"
        error specifically.
        """
        chain, funder, new_entity = self._prep_chain_with_funded_new_entity()
        # Use funder (an existing entity) as destination so that the
        # brand-new-recipient surcharge rule isn't the reason for failure.
        # include_pubkey defaults to False — this is exactly the error case.
        tx = create_transfer_transaction(
            new_entity, funder.entity_id, 100, nonce=0,
        )
        ok, reason = chain.validate_transfer_transaction(tx)
        self.assertFalse(ok, "Transfer from unregistered entity without pubkey must fail")
        self.assertIn("sender_pubkey", reason.lower())

    def test_first_outgoing_transfer_with_mismatched_pubkey_rejected(self):
        """sender_pubkey whose hash != entity_id must be rejected.

        Use an existing destination so the surcharge check is not the
        reason for failure.
        """
        chain, funder, new_entity = self._prep_chain_with_funded_new_entity()
        impostor = Entity.create(b"impostor_key".ljust(32, b"\x00"))

        # Build a transfer signed by new_entity but carrying impostor's pubkey.
        tx = create_transfer_transaction(
            new_entity, funder.entity_id, 100, nonce=0,
            include_pubkey=True,
        )
        # Swap the pubkey in and recompute tx_hash as a malicious relayer would.
        tx.sender_pubkey = impostor.public_key
        tx.tx_hash = tx._compute_hash()

        ok, reason = chain.validate_transfer_transaction(tx)
        self.assertFalse(ok)
        # Should fail because derive_entity_id(impostor.public_key) != new_entity.entity_id.
        self.assertTrue(
            "derive" in reason.lower() or "mismatch" in reason.lower()
            or "does not" in reason.lower(),
            f"Expected a pubkey-hash-mismatch error, got: {reason}",
        )

    def test_second_outgoing_transfer_with_nonempty_pubkey_rejected(self):
        """After install, subsequent Transfers must carry empty sender_pubkey."""
        chain, funder, new_entity = self._prep_chain_with_funded_new_entity()
        destination = Entity.create(b"destination4".ljust(32, b"\x00"))

        # First transfer: reveal pubkey.  Brand-new destination → surcharge.
        tx1 = create_transfer_transaction(
            new_entity, destination.entity_id, 100, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
            include_pubkey=True,
        )
        ok, reason = chain.validate_transfer_transaction(tx1)
        self.assertTrue(ok, reason)
        chain.apply_transfer_transaction(tx1, proposer_id=funder.entity_id)

        # Second transfer: must NOT populate sender_pubkey again.
        # destination now exists — no surcharge required.
        tx2 = create_transfer_transaction(
            new_entity, destination.entity_id, 50, nonce=1,
            include_pubkey=True,
        )
        ok, reason = chain.validate_transfer_transaction(tx2)
        self.assertFalse(ok, "Second transfer with pubkey must be rejected")
        self.assertIn("empty", reason.lower())


class TestStakeFromUnregisteredEntity(unittest.TestCase):
    """Other tx types (Stake) fail for entities with no chain pubkey."""

    def test_stake_from_funded_but_unregistered_entity_fails(self):
        """A received-only entity cannot stake before sending a Transfer."""
        from messagechain.core.staking import create_stake_transaction
        funder = Entity.create(b"funder_stk".ljust(32, b"\x00"))
        receiver = Entity.create(b"receiver_stk".ljust(32, b"\x00"))

        chain = Blockchain()
        chain.initialize_genesis(
            funder, allocation_table={funder.entity_id: GENESIS_ALLOCATION},
        )

        # Fund receiver to put them "in state" by balance.  Brand-new
        # recipient → MIN_FEE + NEW_ACCOUNT_FEE.
        tx = create_transfer_transaction(
            funder, receiver.entity_id, 5_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        self.assertTrue(chain.validate_transfer_transaction(tx)[0])
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)

        # Try to stake without having sent any outgoing Transfer — no pubkey installed yet.
        stx = create_stake_transaction(receiver, amount=1000, nonce=0)
        ok, reason = chain._validate_stake_tx(stx)
        self.assertFalse(ok, "Stake from entity with no registered pubkey must fail")
        # Accept either "unknown" or "pubkey" wording — the important thing
        # is that the error is about the missing pubkey.
        self.assertTrue(
            "pubkey" in reason.lower() or "unknown" in reason.lower()
            or "register" in reason.lower() or "first" in reason.lower(),
            f"Expected a missing-pubkey error, got: {reason}",
        )


class TestReceiveOnlyEntityInStateTree(unittest.TestCase):
    """Receive-only entities contribute to state root via balance, no pubkey."""

    def test_receive_only_entity_state_tree_leaf(self):
        """A funded-only entity has a state_tree leaf with balance set
        and public_key empty.  The consensus state root commits to this
        so every replaying node ends up at the same root."""
        funder = Entity.create(b"funder_leaf".ljust(32, b"\x00"))
        receiver = Entity.create(b"receiver_leaf".ljust(32, b"\x00"))

        chain = Blockchain()
        chain.initialize_genesis(
            funder, allocation_table={funder.entity_id: GENESIS_ALLOCATION},
        )
        tx = create_transfer_transaction(
            funder, receiver.entity_id, 777, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        self.assertTrue(chain.validate_transfer_transaction(tx)[0])
        chain.apply_transfer_transaction(tx, proposer_id=funder.entity_id)

        # Force an SMT sync so the leaf reflects the receive-only entity.
        chain._touch_state({receiver.entity_id, funder.entity_id})
        leaf = chain.state_tree.get(receiver.entity_id)
        self.assertIsNotNone(leaf, "receive-only entity should exist in state tree")
        # Tuple layout: (balance, nonce, stake, authority_key, public_key,
        #                leaf_watermark, rotation_count, is_revoked, is_slashed)
        self.assertEqual(leaf[0], 777)          # balance
        self.assertEqual(leaf[1], 0)            # nonce unset
        self.assertEqual(leaf[2], 0)            # stake
        self.assertEqual(leaf[4], b"")          # public_key empty
        self.assertEqual(leaf[5], 0)            # leaf_watermark


class TestInstallPubkeyDirectIsInternal(unittest.TestCase):
    """Genesis/bootstrap path uses `_install_pubkey_direct`."""

    def test_install_pubkey_direct_method_exists(self):
        """The internal install helper must be exposed for bootstrap + tests."""
        chain = Blockchain()
        self.assertTrue(
            hasattr(chain, "_install_pubkey_direct"),
            "Blockchain must expose _install_pubkey_direct for genesis/bootstrap",
        )

    def test_register_entity_for_test_helper_still_works(self):
        """tests.register_entity_for_test keeps working via the direct helper."""
        chain = Blockchain()
        seed = Entity.create(b"seed_direct".ljust(32, b"\x00"))
        chain.initialize_genesis(
            seed, allocation_table={seed.entity_id: GENESIS_ALLOCATION},
        )
        other = Entity.create(b"other_direct".ljust(32, b"\x00"))
        ok, _ = register_entity_for_test(chain, other)
        self.assertTrue(ok)
        self.assertIn(other.entity_id, chain.public_keys)


if __name__ == "__main__":
    unittest.main()
