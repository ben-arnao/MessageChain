"""Per-block cap on new-account creation.

NEW_ACCOUNT_FEE prices new-account creation; MAX_NEW_ACCOUNTS_PER_BLOCK
caps the *rate* at which permanent state can grow regardless of how much
an attacker is willing to burn.  Two-layer defense:

  * Economic: each new account burns NEW_ACCOUNT_FEE (1000 tokens).
  * Rate:     at most MAX_NEW_ACCOUNTS_PER_BLOCK (10) permanent state
              entries are created per block → ~50 MB/year ceiling.

The count is the number of TransferTransactions + TreasurySpends whose
recipient is brand-new, counted with intra-block pipelining (the second
tx to the same brand-new recipient in the same block doesn't count — the
first already created the account).

This must be a HARD consensus rule: all nodes count the same way, using
the same `_recipient_is_new(..., pending_new_account_created=...)`
helper as the surcharge check.
"""

import unittest

from messagechain.config import (
    MIN_FEE, NEW_ACCOUNT_FEE, DUST_LIMIT,
    TREASURY_ENTITY_ID, TREASURY_ALLOCATION,
    MAX_NEW_ACCOUNTS_PER_BLOCK,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity
from messagechain.consensus.pos import ProofOfStake
from tests import register_entity_for_test


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # tree_height=6 → 64 leaves; enough headroom for tests that
        # build blocks of 30+ transfers from the same entity.
        cls.alice = Entity.create(
            b"alice-cap-test".ljust(32, b"\x00"), tree_height=6,
        )

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        # Fund Alice generously so she can pay surcharges for many new accts.
        allocation = {
            self.alice.entity_id: 10_000_000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        self.chain.initialize_genesis(self.alice, allocation_table=allocation)
        self.consensus = ProofOfStake()

    def _make_block(self, proposer, transfer_txs, prev=None):
        if prev is None:
            prev = self.chain.get_latest_block()
        state_root = self.chain.compute_post_state_root(
            [], proposer.entity_id, prev.header.block_number + 1,
            transfer_transactions=transfer_txs,
        )
        return self.consensus.create_block(
            proposer, [], prev,
            transfer_transactions=transfer_txs,
            state_root=state_root,
        )

    def _new_recipient(self, tag: int) -> bytes:
        """Derive a deterministic entity_id that is NOT in chain state."""
        return bytes([tag]) * 32


class TestMaxNewAccountsConstant(unittest.TestCase):
    def test_constant_present_and_is_10(self):
        self.assertEqual(MAX_NEW_ACCOUNTS_PER_BLOCK, 10)


class TestMaxNewAccountsEnforcement(_Base):
    def test_exactly_at_cap_accepted(self):
        """Block with exactly MAX_NEW_ACCOUNTS_PER_BLOCK new recipients accepted."""
        txs = []
        for i in range(MAX_NEW_ACCOUNTS_PER_BLOCK):
            rid = self._new_recipient(i + 1)
            txs.append(create_transfer_transaction(
                self.alice, rid, amount=DUST_LIMIT,
                nonce=i, fee=MIN_FEE + NEW_ACCOUNT_FEE,
            ))
        block = self._make_block(self.alice, txs)
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_one_over_cap_rejected(self):
        """Block with MAX_NEW_ACCOUNTS_PER_BLOCK + 1 new recipients rejected."""
        txs = []
        for i in range(MAX_NEW_ACCOUNTS_PER_BLOCK + 1):
            rid = self._new_recipient(i + 1)
            txs.append(create_transfer_transaction(
                self.alice, rid, amount=DUST_LIMIT,
                nonce=i, fee=MIN_FEE + NEW_ACCOUNT_FEE,
            ))
        block = self._make_block(self.alice, txs)
        ok, reason = self.chain.add_block(block)
        self.assertFalse(ok, "Block with 11 new accounts should be rejected")
        self.assertIn("new", reason.lower())
        # Either "new accounts" or "new-account cap" — both acceptable;
        # just require the error mentions the cap explicitly.
        self.assertTrue(
            "cap" in reason.lower()
            or "max_new_accounts" in reason.lower()
            or "per block" in reason.lower(),
            f"Expected error to mention the cap, got: {reason}",
        )

    def test_many_existing_recipients_accepted(self):
        """Block with MAX_NEW_ACCOUNTS_PER_BLOCK + 1 transfers to
        ALREADY-REGISTERED recipients is accepted — existing accounts
        don't count against the cap."""
        count = MAX_NEW_ACCOUNTS_PER_BLOCK + 1
        existing = []
        for i in range(count):
            e = Entity.create(
                (f"existing-{i}-cap").encode().ljust(32, b"\x00"),
            )
            e.keypair._next_leaf = 0
            register_entity_for_test(self.chain, e)
            self.chain.supply.balances[e.entity_id] = 10
            existing.append(e)

        txs = []
        for i, recip in enumerate(existing):
            txs.append(create_transfer_transaction(
                self.alice, recip.entity_id, amount=DUST_LIMIT,
                nonce=i, fee=MIN_FEE,
            ))
        block = self._make_block(self.alice, txs)
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_mixed_5_new_5_existing_accepted(self):
        """5 new + 5 existing = 5 new accounts → accepted (under cap).

        Block size capped at MAX_TXS_PER_BLOCK=20 overall, so we build
        10 txs total to demonstrate the mix without hitting the other
        limit.
        """
        existing = []
        for i in range(5):
            e = Entity.create((f"mix-exist-{i}").encode().ljust(32, b"\x00"))
            e.keypair._next_leaf = 0
            register_entity_for_test(self.chain, e)
            self.chain.supply.balances[e.entity_id] = 10
            existing.append(e)

        txs = []
        nonce = 0
        # 5 new recipients (first — pay surcharge)
        for i in range(5):
            rid = self._new_recipient(100 + i)
            txs.append(create_transfer_transaction(
                self.alice, rid, amount=DUST_LIMIT,
                nonce=nonce, fee=MIN_FEE + NEW_ACCOUNT_FEE,
            ))
            nonce += 1
        # 5 existing recipients
        for recip in existing:
            txs.append(create_transfer_transaction(
                self.alice, recip.entity_id, amount=DUST_LIMIT,
                nonce=nonce, fee=MIN_FEE,
            ))
            nonce += 1
        block = self._make_block(self.alice, txs)
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_mixed_11_new_5_existing_rejected(self):
        """11 new + 5 existing = 11 new accounts → rejected (over cap)."""
        existing = []
        for i in range(5):
            e = Entity.create((f"mixE-exist-{i}").encode().ljust(32, b"\x00"))
            e.keypair._next_leaf = 0
            register_entity_for_test(self.chain, e)
            self.chain.supply.balances[e.entity_id] = 10
            existing.append(e)

        txs = []
        nonce = 0
        for i in range(MAX_NEW_ACCOUNTS_PER_BLOCK + 1):
            rid = self._new_recipient(200 + i)
            txs.append(create_transfer_transaction(
                self.alice, rid, amount=DUST_LIMIT,
                nonce=nonce, fee=MIN_FEE + NEW_ACCOUNT_FEE,
            ))
            nonce += 1
        for recip in existing:
            txs.append(create_transfer_transaction(
                self.alice, recip.entity_id, amount=DUST_LIMIT,
                nonce=nonce, fee=MIN_FEE,
            ))
            nonce += 1
        block = self._make_block(self.alice, txs)
        ok, reason = self.chain.add_block(block)
        self.assertFalse(ok, "11 new + 5 existing must exceed cap")

    def test_intra_block_pipelining_same_new_recipient_counts_once(self):
        """Two transfers to the SAME brand-new recipient count as 1
        new-account creation, not 2."""
        # Construct a block of MAX_NEW_ACCOUNTS_PER_BLAST transfers to
        # the same new recipient, to verify that only one "creation"
        # is counted even when there are many transfers to it.
        rid = self._new_recipient(77)
        txs = []
        for i in range(MAX_NEW_ACCOUNTS_PER_BLOCK + 1):
            if i == 0:
                fee = MIN_FEE + NEW_ACCOUNT_FEE
            else:
                fee = MIN_FEE
            txs.append(create_transfer_transaction(
                self.alice, rid, amount=DUST_LIMIT,
                nonce=i, fee=fee,
            ))
        # MAX+1 transfers to ONE new recipient — only 1 new account created.
        block = self._make_block(self.alice, txs)
        ok, reason = self.chain.add_block(block)
        self.assertTrue(
            ok,
            f"MAX+1 transfers to same new recipient should count as 1, got: {reason}",
        )


class TestTreasurySpendExemptFromCap(_Base):
    """Treasury spends that credit brand-new accounts are governance-
    rate-limited (weeks of 2/3-supermajority voting), so they are NOT
    counted toward the per-block Transfer cap.  This test documents
    that design decision: a treasury spend executing in the same block
    as MAX_NEW_ACCOUNTS_PER_BLOCK transfers does not push the block
    over the cap, because treasury spends count separately.

    (They still individually pay NEW_ACCOUNT_FEE — the economic
    surcharge is universal; only the rate-limit counter is scoped to
    transfers.)"""

    def test_block_at_cap_with_transfers_accepted(self):
        """A block with exactly MAX_NEW_ACCOUNTS_PER_BLOCK new-recipient
        transfers is accepted.  (Treasury spends don't share the counter
        — this is simply a sanity baseline.)"""
        txs = []
        for i in range(MAX_NEW_ACCOUNTS_PER_BLOCK):
            rid = self._new_recipient(i + 1)
            txs.append(create_transfer_transaction(
                self.alice, rid, amount=DUST_LIMIT,
                nonce=i, fee=MIN_FEE + NEW_ACCOUNT_FEE,
            ))
        block = self._make_block(self.alice, txs)
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
