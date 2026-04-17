"""Equivocation watcher — auto-generate slash evidence from p2p gossip.

The chain already slashes double-signers if someone submits
SlashTransaction with the conflicting signatures.  Without an on-node
watcher, though, nobody is actually looking for equivocation on the
wire — so during the single-seed bootstrap window the founder could
double-sign with zero economic penalty because no other honest party
witnesses + files evidence.

These tests pin the behaviour of an EquivocationWatcher component that:

  1. Indexes every inbound signed block header / attestation by
     (validator_id, height, round, message_type).
  2. On receiving a conflicting signature, constructs the right
     SlashingEvidence / AttestationSlashingEvidence and emits a
     SlashTransaction into the mempool slash pool.
  3. Persists its observations to chaindb, so a node restart cannot be
     used to evade detection.
  4. Prunes observations older than UNBONDING_PERIOD — matching the
     evidence-validity window in Blockchain.validate_slash_transaction
     (blockchain.py:1642).  Observations older than that are useless
     because the chain will reject slash txs built from them.
"""

import os
import tempfile
import time
import unittest

from messagechain.config import (
    TREASURY_ENTITY_ID,
    UNBONDING_PERIOD,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.attestation import Attestation, create_attestation
from messagechain.consensus.equivocation_watcher import EquivocationWatcher
from messagechain.consensus.slashing import (
    AttestationSlashingEvidence,
    SlashTransaction,
    SlashingEvidence,
)
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


# ── helpers ──────────────────────────────────────────────────────────

def _make_signed_header(
    proposer_entity, prev_block, merkle_seed: bytes, t_offset: float = 0.0,
):
    """Build a signed BlockHeader over prev_block at height+1."""
    block_num = prev_block.header.block_number + 1
    header = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(merkle_seed),
        timestamp=time.time() + t_offset,
        proposer_id=proposer_entity.entity_id,
    )
    header.proposer_signature = proposer_entity.keypair.sign(
        _hash(header.signable_data())
    )
    return header


def _make_signed_attestation(
    validator_entity, block_hash: bytes, block_number: int,
):
    """Build a signed Attestation for the given block."""
    return create_attestation(validator_entity, block_hash, block_number)


# ── fixture ──────────────────────────────────────────────────────────

class _WatcherFixture(unittest.TestCase):
    """Shared setup: a seeded chain + a funded offender + a funded finder."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-watch-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)

        self.alice = Entity.create(b"alice-watch".ljust(32, b"\x00"))
        self.offender = Entity.create(b"offender-watch".ljust(32, b"\x00"))
        self.finder = Entity.create(b"finder-watch".ljust(32, b"\x00"))

        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.alice,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.alice.entity_id: 1_000_000,
            },
        )
        register_entity_for_test(self.chain, self.offender)
        register_entity_for_test(self.chain, self.finder)
        self.chain.supply.balances[self.offender.entity_id] = 10_000
        self.chain.supply.balances[self.finder.entity_id] = 10_000
        # Offender needs a positive stake for a slash tx to be acceptable
        # (validate_slash_transaction rejects "offender has no stake").
        self.chain.supply.stake(
            self.offender.entity_id, VALIDATOR_MIN_STAKE,
        )

        self.mempool = Mempool()
        self.watcher = EquivocationWatcher(
            chaindb=self.db,
            blockchain=self.chain,
            mempool=self.mempool,
            submitter_entity=self.finder,
        )

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


# ── tests ────────────────────────────────────────────────────────────

class TestDoubleProposal(_WatcherFixture):
    """Watcher emits a SlashTransaction when a proposer equivocates."""

    def test_baseline_double_proposal_slash(self):
        """Two conflicting signed headers at H=N by the same proposer
        cause the watcher to emit a SlashTransaction into the mempool.
        """
        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.offender, prev, b"A")
        header_b = _make_signed_header(self.offender, prev, b"B", t_offset=1.0)
        self.assertEqual(header_a.block_number, header_b.block_number)

        # First sighting: just record, no slash.
        self.watcher.observe_block_header(header_a)
        self.assertEqual(len(self.mempool.slash_pool), 0)

        # Second sighting with a DIFFERENT payload at the same height:
        # this is equivocation, watcher must emit evidence.
        self.watcher.observe_block_header(header_b)
        self.assertEqual(
            len(self.mempool.slash_pool), 1,
            "Watcher must emit a SlashTransaction on double-proposal",
        )

        stx = next(iter(self.mempool.slash_pool.values()))
        self.assertIsInstance(stx, SlashTransaction)
        self.assertIsInstance(stx.evidence, SlashingEvidence)
        self.assertEqual(stx.evidence.offender_id, self.offender.entity_id)
        # Both signatures are carried on the evidence so a verifier can
        # check them without any additional chain lookup.
        self.assertIsNotNone(stx.evidence.header_a.proposer_signature)
        self.assertIsNotNone(stx.evidence.header_b.proposer_signature)

    def test_gossip_echo_is_ignored(self):
        """Same payload received twice (gossip echo) MUST NOT emit a slash."""
        prev = self.chain.get_latest_block()
        header = _make_signed_header(self.offender, prev, b"same")

        self.watcher.observe_block_header(header)
        # Re-deliver the IDENTICAL header — simulate gossip fan-in from
        # a second peer.  This is not equivocation.
        self.watcher.observe_block_header(header)
        self.assertEqual(
            len(self.mempool.slash_pool), 0,
            "Watcher must NOT emit on gossip echo of identical payload",
        )


class TestRestartPersistence(_WatcherFixture):
    """Crucial test: a node restart doesn't let an equivocator skate."""

    def test_restart_then_conflicting_proposal_still_slashes(self):
        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.offender, prev, b"A")

        # First sighting recorded on the "pre-restart" watcher.
        self.watcher.observe_block_header(header_a)
        self.assertEqual(len(self.mempool.slash_pool), 0)

        # Simulate a node restart: drop the old watcher + blockchain +
        # mempool, rebuild them from the SAME chaindb file on disk.
        self.db.close()
        self.db = ChainDB(self.db_path)
        self.chain = Blockchain(db=self.db)
        self.mempool = Mempool()
        self.watcher = EquivocationWatcher(
            chaindb=self.db,
            blockchain=self.chain,
            mempool=self.mempool,
            submitter_entity=self.finder,
        )

        # Now the conflicting header arrives after "restart".  The
        # watcher must still catch the equivocation.
        header_b = _make_signed_header(
            self.offender, prev, b"B", t_offset=1.0,
        )
        self.watcher.observe_block_header(header_b)
        self.assertEqual(
            len(self.mempool.slash_pool), 1,
            "Watcher MUST catch equivocation that straddles a restart",
        )
        stx = next(iter(self.mempool.slash_pool.values()))
        self.assertEqual(stx.evidence.offender_id, self.offender.entity_id)


class TestConcurrentObservers(_WatcherFixture):
    """Two watcher instances see the same equivocation; blockchain dedupes."""

    def test_two_watchers_produce_identical_evidence_hash(self):
        """Two independent watcher instances that witness the same
        double-signing must both produce a SlashTransaction with the
        SAME evidence_hash, so the blockchain's processed_evidence
        dedup kicks in (only one slash-tx ever lands on chain).
        """
        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.offender, prev, b"A")
        header_b = _make_signed_header(self.offender, prev, b"B", t_offset=1.0)

        # Second watcher on an independent chaindb + mempool, but with
        # its own submitter (a different finder identity).
        alt_tmp = tempfile.mkdtemp(prefix="mc-watch2-")
        try:
            alt_db = ChainDB(os.path.join(alt_tmp, "chain.db"))
            alt_chain = Blockchain(db=alt_db)
            alt_chain.initialize_genesis(
                self.alice,
                allocation_table={
                    TREASURY_ENTITY_ID: 1_000_000,
                    self.alice.entity_id: 1_000_000,
                },
            )
            register_entity_for_test(alt_chain, self.offender)
            alt_finder = Entity.create(b"finder-alt".ljust(32, b"\x00"))
            register_entity_for_test(alt_chain, alt_finder)
            alt_chain.supply.balances[alt_finder.entity_id] = 10_000
            alt_chain.supply.stake(
                self.offender.entity_id, VALIDATOR_MIN_STAKE,
            )
            alt_mempool = Mempool()
            alt_watcher = EquivocationWatcher(
                chaindb=alt_db,
                blockchain=alt_chain,
                mempool=alt_mempool,
                submitter_entity=alt_finder,
            )

            # Both watchers see both headers.
            self.watcher.observe_block_header(header_a)
            self.watcher.observe_block_header(header_b)
            alt_watcher.observe_block_header(header_a)
            alt_watcher.observe_block_header(header_b)

            stx1 = next(iter(self.mempool.slash_pool.values()))
            stx2 = next(iter(alt_mempool.slash_pool.values()))

            # Identical evidence hash — the chain will accept one and
            # reject the other as _processed_evidence.
            self.assertEqual(
                stx1.evidence.evidence_hash, stx2.evidence.evidence_hash,
                "Independent observers MUST produce identical evidence hashes",
            )
        finally:
            alt_db.close()
            import shutil
            shutil.rmtree(alt_tmp, ignore_errors=True)


class TestRollingPrune(_WatcherFixture):
    """Observations older than UNBONDING_PERIOD must be pruned."""

    def test_old_observations_are_pruned(self):
        """Record an observation at block height X.  After the chain
        advances to X + UNBONDING_PERIOD + 1 (with prune hooks firing),
        the stored observation must be gone.

        We don't need to build 1008 blocks — prune() takes the current
        chain height as an argument.  We record at a synthetic height
        and then call the prune hook with a later height.
        """
        prev = self.chain.get_latest_block()
        header = _make_signed_header(self.offender, prev, b"A")

        recorded_at = 5  # pretend we saw this header when chain was at H=5
        self.watcher.observe_block_header(header, current_height=recorded_at)
        self.assertTrue(
            self.watcher.has_observation_for(
                self.offender.entity_id,
                header.block_number,
                message_type="block",
            ),
            "Observation must be present immediately after observe()",
        )

        # Now simulate the chain advancing well past the window.
        self.watcher.prune(current_height=recorded_at + UNBONDING_PERIOD + 1)

        self.assertFalse(
            self.watcher.has_observation_for(
                self.offender.entity_id,
                header.block_number,
                message_type="block",
            ),
            "Observation must be pruned once it is older than "
            "UNBONDING_PERIOD — it is worthless for slashing anyway.",
        )


class TestDoubleAttestation(_WatcherFixture):
    """Double-attestation path: same shape as double-proposal but for votes."""

    def test_double_attestation_slash(self):
        # Two block hashes the validator could vote for at H=7.
        bh_a = _hash(b"fake-block-a")
        bh_b = _hash(b"fake-block-b")
        att_a = _make_signed_attestation(self.offender, bh_a, 7)
        att_b = _make_signed_attestation(self.offender, bh_b, 7)

        self.watcher.observe_attestation(att_a)
        self.assertEqual(len(self.mempool.slash_pool), 0)

        self.watcher.observe_attestation(att_b)
        self.assertEqual(
            len(self.mempool.slash_pool), 1,
            "Watcher must emit a SlashTransaction on double-attestation",
        )
        stx = next(iter(self.mempool.slash_pool.values()))
        self.assertIsInstance(stx.evidence, AttestationSlashingEvidence)
        self.assertEqual(stx.evidence.offender_id, self.offender.entity_id)


class TestSlashViaWatcherAtBootstrap(_WatcherFixture):
    """Sanity check: at progress ~= 0, a watcher-emitted slash tx is
    still accepted by the blockchain.  Duplicates part of
    test_slashing_bootstrap but exercises the end-to-end path from
    watcher -> mempool -> apply_slash_transaction.
    """

    def test_pre_bootstrap_slash_via_watcher(self):
        self.assertLess(
            self.chain.bootstrap_progress, 1e-3,
            "Precondition: progress must be ~0 for this test to be meaningful",
        )

        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.offender, prev, b"A")
        header_b = _make_signed_header(self.offender, prev, b"B", t_offset=1.0)
        self.watcher.observe_block_header(header_a)
        self.watcher.observe_block_header(header_b)
        self.assertEqual(len(self.mempool.slash_pool), 1)

        stx = next(iter(self.mempool.slash_pool.values()))
        success, msg = self.chain.apply_slash_transaction(
            stx, self.alice.entity_id,
        )
        self.assertTrue(
            success,
            f"Watcher-produced slash tx MUST be accepted at bootstrap: {msg}",
        )
        self.assertEqual(
            self.chain.supply.get_staked(self.offender.entity_id), 0,
        )
        self.assertIn(
            self.offender.entity_id, self.chain.slashed_validators,
        )


if __name__ == "__main__":
    unittest.main()
