"""_sweep_stale_pending_txs must treat SetReceiptSubtreeRoot as cold-signed.

Observed on mainnet 2026-04-25 when registering validator-2's
receipt-subtree root post cold-key promotion: every submission was
admitted to `_pending_authority_txs` (RPC returned a tx_hash), then
silently dropped on every block proposal so it never landed.

Root cause: the sweep's "leaf below watermark" check carved out
RevokeTransaction and (cold-key-promoted) UnstakeTransaction as
cold-signed, but treated everything else as hot-signed. The check
then compared the cold key's leaf_index (typically single digits
for a freshly-promoted cold key) against the VALIDATOR ENTITY's
hot-key leaf_watermark (which after a few hundred blocks of
sustained production is in the hundreds). Cold leaf << hot
watermark, so the tx was flagged stale and evicted before
propose_block could pull it.

The fix adds SetReceiptSubtreeRootTransaction to the cold-signed
set. This regression test guards against future cold-signed tx
types regressing the same way: any new tx whose signature lives in
a separate (cold) leaf namespace must be added to the carve-out
explicitly, with a unit test pinning that the sweep doesn't evict
it under a hot-watermark > 0 condition.
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock

from messagechain import config as _mcfg
from messagechain.core.blockchain import Blockchain
from messagechain.core.receipt_subtree_root import (
    create_set_receipt_subtree_root_transaction,
)
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity

from tests import register_entity_for_test


def _entity(seed: bytes, height: int = 4) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestSweepRespectsColdSignedSetReceiptRoot(unittest.TestCase):

    def setUp(self):
        self._orig_h = _mcfg.MERKLE_TREE_HEIGHT
        _mcfg.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        _mcfg.MERKLE_TREE_HEIGHT = self._orig_h

    def test_set_receipt_subtree_root_not_swept_when_cold_leaf_below_hot_watermark(self):
        """Reproduces the mainnet 2026-04-25 wedge.

        Validator entity has a HIGH hot-key leaf watermark (it's been
        signing blocks). Cold key signs a SetReceiptSubtreeRoot tx
        using cold leaf 0. The sweep MUST NOT drop the tx — the cold
        leaf is in a different namespace from the hot watermark.
        """
        # Lazy-import server module to avoid a heavy top-level import
        # in test collection.
        import server as server_mod

        chain = Blockchain()

        # Validator entity (the one whose receipt root is being set).
        validator = _entity(b"validator")
        register_entity_for_test(chain, validator)
        chain.supply.balances[validator.entity_id] = 100_000

        # Promote a separate cold key as the authority for this
        # validator — exactly the mainnet shape.
        cold = _entity(b"cold-authority")
        chain.authority_keys[validator.entity_id] = cold.public_key

        # Pretend the validator has been signing blocks and burned
        # 250 hot-key leaves. This is the value the sweep would
        # compare against.
        chain.leaf_watermarks[validator.entity_id] = 250

        # Generate a receipt-subtree root, cold-sign the tx with
        # leaf 0 (the failure case from mainnet).
        receipt_kp = KeyPair.generate(b"receipt-" + b"x".ljust(28, b"\x00"), height=4)
        tx = create_set_receipt_subtree_root_transaction(
            entity_id=validator.entity_id,
            root_public_key=receipt_kp.public_key,
            authority_signer=cold,
        )
        # Sanity: cold tx really is at leaf 0 (well below hot wm=250).
        self.assertLess(tx.signature.leaf_index, 250)

        # Build a stub server with the pool populated.
        stub = MagicMock(spec=server_mod.Server)
        stub.blockchain = chain
        stub._pending_authority_txs = {tx.tx_hash: tx}
        stub._pending_stake_txs = {}
        stub._pending_unstake_txs = {}
        stub._pending_governance_txs = {}

        dropped = server_mod.Server._sweep_stale_pending_txs(stub)

        self.assertEqual(dropped, 0,
            "SetReceiptSubtreeRoot must not be evicted by the hot-key "
            "watermark check — it's cold-signed, so its leaf_index lives "
            "in the cold key's namespace, not the validator entity's.")
        self.assertIn(tx.tx_hash, stub._pending_authority_txs,
            "tx must remain in the authority pool for block proposal.")

    def test_revoke_still_carved_out(self):
        """Sanity: the existing RevokeTransaction carve-out still works
        — fixing one cold-signed tx type must not regress the others.
        """
        import server as server_mod
        from messagechain.core.emergency_revoke import create_revoke_transaction

        chain = Blockchain()
        validator = _entity(b"validator-r")
        register_entity_for_test(chain, validator)
        chain.supply.balances[validator.entity_id] = 100_000
        cold = _entity(b"cold-r")
        chain.authority_keys[validator.entity_id] = cold.public_key
        chain.leaf_watermarks[validator.entity_id] = 250

        revoke = create_revoke_transaction(
            cold, fee=1000, entity_id=validator.entity_id,
        )
        self.assertLess(revoke.signature.leaf_index, 250)

        stub = MagicMock(spec=server_mod.Server)
        stub.blockchain = chain
        stub._pending_authority_txs = {revoke.tx_hash: revoke}
        stub._pending_stake_txs = {}
        stub._pending_unstake_txs = {}
        stub._pending_governance_txs = {}

        dropped = server_mod.Server._sweep_stale_pending_txs(stub)
        self.assertEqual(dropped, 0)
        self.assertIn(revoke.tx_hash, stub._pending_authority_txs)


if __name__ == "__main__":
    unittest.main()
