"""Regression: fresh-wallet first-sign admission must not fail-closed.

Bug: ``Server._tx_signer_pubkey`` resolved the signer pubkey by
looking up ``Blockchain.public_keys[tx.entity_id]``.  For a brand-new
entity submitting its very first signed tx (e.g. a v3+ message with
``sender_pubkey`` reveal), the entity has not yet been installed in
``public_keys`` — the install happens on apply, not on admission.
``public_keys.get(entity_id)`` returned None, so
``_check_leaf_across_all_pools`` hit its "incoming_signer is None"
branch and rejected with "WOTS+ leaf already used by another pending
tx" — even though no tx with that signer exists in any pool.

This wedged every fresh-wallet-first-message flow on mainnet:
``/faucet`` happily funded a new wallet, but the wallet could not
post its first message because the very first ``submit_transaction``
RPC fail-closed.

Fix: when ``public_keys`` does not have the entity, fall back to
``tx.sender_pubkey`` IFF it derives back to the claimed ``entity_id``
— matching the admission-validation path's first-spend reveal rule.

Property tested: a fresh-wallet ``MessageTransaction`` with
``include_pubkey=True`` reaches the mempool admission boundary; the
leaf-reuse check does NOT short-circuit it on the "signer unknown"
fail-closed branch.
"""

from __future__ import annotations

import unittest

from messagechain.core.transaction import (
    create_transaction,
    TX_VERSION_FIRST_SEND_PUBKEY,
)
from messagechain.identity.identity import Entity


class TestFreshWalletSignerResolution(unittest.TestCase):
    """The unit under test is ``Server._tx_signer_pubkey``: it must
    return the entity's pubkey for a fresh-wallet first-message tx,
    NOT None.  Without that, ``_check_leaf_across_all_pools`` rejects
    every fresh-wallet first sign.
    """

    def _make_fresh_first_message(self):
        """Build a v3+ MessageTransaction with sender_pubkey reveal,
        signed by an entity that is NOT (yet) on the test chain."""
        entity = Entity.create(b"fresh-first-sign-seed-padded-32by!1")
        tx = create_transaction(
            entity, "hello from fresh wallet",
            fee=1_000, nonce=0,
            include_pubkey=True,
        )
        self.assertGreaterEqual(tx.version, TX_VERSION_FIRST_SEND_PUBKEY)
        self.assertEqual(tx.sender_pubkey, entity.public_key)
        return entity, tx

    def test_signer_resolves_from_sender_pubkey_when_unregistered(self):
        from server import Server

        class _StubBlockchain:
            def __init__(self):
                self.public_keys = {}  # entity is NOT registered
                self.height = 0

            def get_authority_key(self, eid):
                return None

        srv = Server.__new__(Server)
        srv.blockchain = _StubBlockchain()
        entity, tx = self._make_fresh_first_message()
        # entity NOT in public_keys, but tx.sender_pubkey is set and
        # derives back to entity_id — _tx_signer_pubkey MUST return
        # the pubkey, not None.
        signer = srv._tx_signer_pubkey(tx)
        self.assertEqual(
            signer, entity.public_key,
            "fresh-wallet first-message signer must resolve from "
            "tx.sender_pubkey when public_keys lacks the entity",
        )

    def test_signer_resolves_from_chain_when_registered(self):
        # Pre-existing behavior must be preserved: when the entity IS
        # in public_keys, return the chain-stored pubkey (which is the
        # only authoritative key once the entity is registered).
        from server import Server

        class _StubBlockchain:
            def __init__(self, eid, pk):
                self.public_keys = {eid: pk}
                self.height = 0

            def get_authority_key(self, eid):
                return None

        entity, tx = self._make_fresh_first_message()
        srv = Server.__new__(Server)
        srv.blockchain = _StubBlockchain(entity.entity_id, entity.public_key)
        # Even though tx carries sender_pubkey, registered key wins.
        signer = srv._tx_signer_pubkey(tx)
        self.assertEqual(signer, entity.public_key)

    def test_signer_returns_none_when_neither_source_resolves(self):
        # Defensive: no chain registration AND no sender_pubkey on the
        # tx → still None (no key to dedupe against; caller fails closed).
        from server import Server

        class _StubBlockchain:
            def __init__(self):
                self.public_keys = {}
                self.height = 0

            def get_authority_key(self, eid):
                return None

        srv = Server.__new__(Server)
        srv.blockchain = _StubBlockchain()
        # Build a v1 tx (no sender_pubkey field permitted).
        entity = Entity.create(b"no-pubkey-reveal-seed-padded-32by!1")
        tx = create_transaction(entity, "v1 message", fee=1_000, nonce=0)
        self.assertEqual(tx.version, 1)
        self.assertEqual(tx.sender_pubkey, b"")
        signer = srv._tx_signer_pubkey(tx)
        self.assertIsNone(signer)

    def test_signer_rejects_mismatched_sender_pubkey(self):
        # Security: a tx carrying a sender_pubkey that does NOT derive
        # back to the claimed entity_id must NOT be trusted — that's a
        # spoofing attempt, and admission validation will reject it.
        # _tx_signer_pubkey must mirror that judgment and return None
        # rather than the mismatched pubkey.
        from server import Server

        class _StubBlockchain:
            def __init__(self):
                self.public_keys = {}
                self.height = 0

            def get_authority_key(self, eid):
                return None

        srv = Server.__new__(Server)
        srv.blockchain = _StubBlockchain()
        entity, tx = self._make_fresh_first_message()
        # Tamper: replace sender_pubkey with someone else's pubkey.
        impostor = Entity.create(b"impostor-pubkey-seed-padded-32by!12")
        tx.sender_pubkey = impostor.public_key
        signer = srv._tx_signer_pubkey(tx)
        self.assertIsNone(
            signer,
            "mismatched sender_pubkey must NOT resolve as the signer",
        )


if __name__ == "__main__":
    unittest.main()
