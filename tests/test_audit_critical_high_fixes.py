"""
Regression tests for the 2026-04-14 critical/high audit findings.

Covers:
  C1 — governance txs (Proposal/Vote/TreasurySpend) must include
       CHAIN_ID in their signable data to prevent cross-fork signature
       replay.
  H1 — RPC auth token bytes must not be logged, not even a prefix.
  H2 — reorg snapshot/restore must cover authority_keys so that rolling back
       a block containing a SetAuthorityKey tx reverts the authority key.
       leaf_watermarks and revoked_entities are deliberately monotonic
       (security-ratchet) and must NOT be rolled back.
"""

import unittest
from unittest import mock

from messagechain import config
from messagechain.core.blockchain import Blockchain
from messagechain.governance.governance import (
    ProposalTransaction,
    VoteTransaction,
    TreasurySpendTransaction,
    create_proposal,
    create_vote,
    create_treasury_spend_proposal,
    verify_proposal,
    verify_vote,
    verify_treasury_spend,
)
from messagechain.identity.identity import Entity


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


class TestGovernanceTxsBindChainId(unittest.TestCase):
    """C1: every governance tx type must prepend CHAIN_ID to its signable
    data. Otherwise a signed vote/proposal from one fork can be byte-for-
    byte replayed on a sibling fork that shares the proposer key.
    """

    @classmethod
    def setUpClass(cls):
        cls.alice = _entity(b"alice-audit-fixes")
        cls.bob = _entity(b"bob-audit-fixes")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_proposal_signable_data_includes_chain_id(self):
        tx = create_proposal(self.alice, "t", "d")
        self.assertIn(config.CHAIN_ID, tx._signable_data())
        self.assertTrue(tx._signable_data().startswith(config.CHAIN_ID))

    def test_vote_signable_data_includes_chain_id(self):
        tx = create_vote(self.alice, b"\x11" * 32, approve=True)
        self.assertTrue(tx._signable_data().startswith(config.CHAIN_ID))

    def test_treasury_spend_signable_data_includes_chain_id(self):
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 1000, "t", "d",
        )
        self.assertTrue(tx._signable_data().startswith(config.CHAIN_ID))

    def _verify_rejects_foreign_chain_sig(self, tx, verify_fn, pubkey):
        """A signature produced under a different CHAIN_ID must fail
        verification on this chain."""
        real_chain_id = config.CHAIN_ID
        try:
            config.CHAIN_ID = b"messagechain-FORK-B"
            self.assertFalse(verify_fn(tx, pubkey))
        finally:
            config.CHAIN_ID = real_chain_id

    def test_proposal_cross_fork_replay_rejected(self):
        tx = create_proposal(self.alice, "t", "d")
        self._verify_rejects_foreign_chain_sig(
            tx, verify_proposal, self.alice.public_key,
        )

    def test_vote_cross_fork_replay_rejected(self):
        tx = create_vote(self.alice, b"\x22" * 32, approve=False)
        self._verify_rejects_foreign_chain_sig(
            tx, verify_vote, self.alice.public_key,
        )

    def test_treasury_spend_cross_fork_replay_rejected(self):
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 500, "t", "d",
        )
        self._verify_rejects_foreign_chain_sig(
            tx, verify_treasury_spend, self.alice.public_key,
        )


class TestRpcAuthTokenNotLogged(unittest.TestCase):
    """H1: the RPC auth token must never be logged, not even a prefix.
    Leaking 8 of 64 hex chars is 32 bits off the brute-force margin and
    persists in log files the operator likely does not treat as secret."""

    def test_server_source_does_not_slice_token_into_log(self):
        import inspect
        import server as server_mod

        src = inspect.getsource(server_mod)
        self.assertNotIn(
            "rpc_auth_token[:", src,
            "RPC auth token must not be sliced into any log/format string",
        )

    def test_auth_enabled_log_line_has_no_token_hex(self):
        """Whatever message the auth-enabled branch logs must not contain
        any portion of the generated token."""
        import server as server_mod

        # Build a throwaway object that looks like the relevant slice of
        # MessageChainNode so we can exercise the logging helper.
        marker_token = "deadbeefcafef00d" * 4  # 64 hex chars, distinctive
        dummy = type("N", (), {})()
        dummy.rpc_auth_enabled = True
        dummy.rpc_auth_token = marker_token

        logged = []
        with mock.patch.object(server_mod.logger, "info",
                               side_effect=lambda m: logged.append(m)):
            server_mod.Server._log_rpc_auth_status(dummy)

        self.assertTrue(logged, "expected an auth-enabled log line")
        for msg in logged:
            self.assertNotIn("deadbeef", msg)
            self.assertNotIn("cafef00d", msg)


class TestReorgStatePreservation(unittest.TestCase):
    """H2: reorg memory-snapshot path must restore authority_keys so a
    reverted SetAuthorityKey block does not leave a stale cold key in
    place. leaf_watermarks and revoked_entities are intentionally
    monotonic across reorgs — they must NOT be rolled back."""

    def test_authority_keys_are_snapshotted_and_restored(self):
        chain = Blockchain()
        chain.authority_keys[b"alice-id"] = b"cold-key-v1"

        snap = chain._snapshot_memory_state()
        self.assertIn("authority_keys", snap)
        self.assertEqual(snap["authority_keys"][b"alice-id"], b"cold-key-v1")

        # Simulate a reorged-out SetAuthorityKey block that mutated state
        chain.authority_keys[b"alice-id"] = b"attacker-key"
        chain.authority_keys[b"bob-id"] = b"attacker-key"

        chain._restore_memory_snapshot(snap)
        self.assertEqual(chain.authority_keys[b"alice-id"], b"cold-key-v1")
        self.assertNotIn(b"bob-id", chain.authority_keys)

    def test_leaf_watermarks_are_ratchet_only_across_reorg(self):
        """A leaf that was ever published on any fork is permanently burned
        because the WOTS+ private material is now public. Watermarks must
        not rewind even if the containing block is rolled back."""
        chain = Blockchain()
        chain.leaf_watermarks[b"alice-id"] = 5

        snap = chain._snapshot_memory_state()
        # Forward progress during the attempted reorg
        chain.leaf_watermarks[b"alice-id"] = 10
        chain._restore_memory_snapshot(snap)

        self.assertGreaterEqual(
            chain.leaf_watermarks[b"alice-id"], 10,
            "leaf_watermarks must never decrease, even on reorg",
        )

    def test_revoked_entities_are_ratchet_only_across_reorg(self):
        """Emergency revocation is an authority-key-signed kill-switch. Once
        broadcast it represents a clear authorized intent to disable the
        entity, so we preserve it across reorgs as a safety ratchet."""
        chain = Blockchain()
        snap = chain._snapshot_memory_state()

        chain.revoked_entities.add(b"compromised")
        chain._restore_memory_snapshot(snap)

        self.assertIn(
            b"compromised", chain.revoked_entities,
            "revoked_entities must not be cleared by a reorg",
        )


if __name__ == "__main__":
    unittest.main()
