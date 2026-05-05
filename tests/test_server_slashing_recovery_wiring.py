"""Server-side wiring of the slashing & fork-emergency enforcement layer.

Pre-fix (audit r19 #1): the EquivocationWatcher, the FinalityVote-layer
slasher emission, and the fork-emergency auto-recovery were all wired
exclusively in ``messagechain/network/node.py:Node`` -- but the production
mainnet validator runs ``server.py:Server`` (instantiated by
``messagechain.cli`` via ``from server import Server``).  Node is never
instantiated by any production code path.  The auto-slash backbone for
the chain's primary anchored adversary (validator collusion) was therefore
running in dead code.  Multiple recently-shipped audit fixes (1.55.0
EquivocationWatcher, 1.57.0 FinalityVote slash drain, 1.57.0
fork-emergency auto-recovery) landed in the same dead module.

This file pins the wiring on the ``Server`` class itself so the
production runtime gets the slashing-evidence trail CLAUDE.md anchors as
the deterrent for validator collusion ("collective censorship resistance
via slashable-evidence trail").
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from messagechain import config
from messagechain.consensus.equivocation_watcher import EquivocationWatcher
from messagechain.consensus.pos import ProofOfStake
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _entity(seed: bytes, height: int = 4) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_server(data_dir):
    """In-memory Server with a real chaindb (so EquivocationWatcher wires)."""
    from server import Server
    return Server(
        p2p_port=0, rpc_port=0, seed_nodes=[],
        data_dir=data_dir,
    )


def _teardown_server(srv):
    """Release the chaindb file handle and the data_dir lock so the
    Windows tempdir can be removed without a PermissionError on the
    open SQLite db.  Mirrors what server.stop() does on a clean exit
    but skipping the network-shutdown machinery the tests never start.
    """
    db = getattr(srv, "db", None)
    if db is not None and hasattr(db, "close"):
        try:
            db.close()
        except Exception:
            pass
    if srv._data_dir_lock is not None:
        try:
            srv._data_dir_lock.__exit__(None, None, None)
        except Exception:
            pass


class ServerEquivocationWatcherWiringTest(unittest.TestCase):
    """Pre-fix Server() never constructed an EquivocationWatcher; post-fix
    it does, gated on the same db-presence rule Node uses.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_server_constructs_equivocation_watcher_when_chaindb_present(self):
        srv = _build_server(self.data_dir)
        try:
            self.assertIsNotNone(
                getattr(srv, "equivocation_watcher", None),
                "Server with a chaindb must wire EquivocationWatcher "
                "(production validators run Server, not Node).",
            )
            self.assertIsInstance(srv.equivocation_watcher, EquivocationWatcher)
            # Same db as the chain — this is what makes restart
            # survivability work.
            self.assertIs(
                srv.equivocation_watcher.chaindb,
                srv.blockchain.db,
            )
            # Same mempool — emitted slash txs land where the proposer
            # picks them up.
            self.assertIs(srv.equivocation_watcher.mempool, srv.mempool)
        finally:
            _teardown_server(srv)

    def test_server_without_chaindb_leaves_watcher_disabled(self):
        # Mirrors Node's "no db -> detect-only mode would not survive a
        # restart, so don't bother".  Server with data_dir=None has no
        # chaindb, so equivocation_watcher must be None (not a crash).
        from server import Server
        srv = Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)
        self.assertIsNone(getattr(srv, "equivocation_watcher", None))


class ServerAfterBlockAddedHookTest(unittest.TestCase):
    """The post-add_block hook is the single point where the wiring
    fires:

      * equivocation_watcher.observe_block_header + prune
      * _emit_pending_finality_slashes (drain the FinalityVote-layer
        equivocation accumulator into mempool slash txs)
      * _maybe_auto_recover_from_fork_emergency (full nodes only)

    Pre-fix Server had _maybe_auto_restake + _maybe_notify_governance_
    proposals on its add_block-success paths but no equivalent of Node's
    _after_block_added.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = self._tmp.name
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4
        self.srv = _build_server(self.data_dir)
        self.entity = _entity(b"after-block")
        self.srv.blockchain.initialize_genesis(self.entity)
        register_entity_for_test(self.srv.blockchain, self.entity)
        self.srv.set_wallet_entity(self.entity)

    def tearDown(self):
        _teardown_server(self.srv)
        self._tmp.cleanup()
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_after_block_added_method_exists(self):
        self.assertTrue(
            hasattr(self.srv, "_after_block_added"),
            "Server must expose _after_block_added (mirrors Node so the "
            "auto-slash + finality-slash drain + auto-recover hooks fire "
            "on the production path).",
        )
        self.assertTrue(callable(self.srv._after_block_added))

    def test_after_block_added_drains_pending_finality_slashes(self):
        """Pre-injected FinalityDoubleVoteEvidence on
        ``blockchain._pending_finality_slashes`` must be drained into
        mempool slash txs when ``_after_block_added`` fires.  This is
        the 1.57.0 'FinalityVote-layer slasher emission edge' fix --
        which lived only in node.py until this audit.
        """
        # Reuse the canonical test helper so this stays in lockstep
        # with the node-side drain test (tests/test_pending_finality_
        # slashes_drain.py:_make_double_vote_evidence).
        from messagechain.consensus.finality import FinalityCheckpoints
        from tests.test_pending_finality_slashes_drain import (
            _make_double_vote_evidence,
        )
        ev = _make_double_vote_evidence()
        # Pre-fix this list had a writer (FinalityCheckpoints.add_vote
        # via _apply_block_state) but no reader on the production
        # Server path.  Post-fix _after_block_added drains it.
        self.srv.blockchain._pending_finality_slashes = [ev]

        # _after_block_added doesn't actually need a real block --
        # the drain step doesn't read fields off `block`.  Use the
        # genesis block as a stand-in.
        self.srv._after_block_added(self.srv.blockchain.get_latest_block())

        # The accumulator should be empty (drained).
        self.assertEqual(
            self.srv.blockchain._pending_finality_slashes, [],
            "post-fix Server._after_block_added must drain "
            "_pending_finality_slashes (FinalityVote-layer equivocation "
            "auto-slash emission)",
        )
        # And the slash tx should be in the mempool slash pool.
        slash_txs = self.srv.mempool.get_slash_transactions()
        self.assertEqual(
            len(slash_txs), 1,
            "drained finality-slash evidence must land in mempool "
            "as a SlashTransaction",
        )
        self.assertEqual(
            slash_txs[0].evidence.offender_id, ev.offender_id,
        )

    def test_after_block_added_invokes_observe_block_header_and_prune(self):
        """The watcher's seen_signatures table is populated after the
        post-add hook fires for an accepted block.  This is what makes
        block-header equivocation slashing actually run on mainnet.
        """
        latest = self.srv.blockchain.get_latest_block()
        self.assertIsNotNone(latest, "genesis must exist for this test")
        # genesis has a proposer signature (bootstrap entity).
        self.srv._after_block_added(latest)
        # Watcher should have observed the genesis header.
        observed = self.srv.equivocation_watcher.has_observation_for(
            validator_id=latest.header.proposer_id,
            block_height=latest.header.block_number,
            message_type="block",
        )
        self.assertTrue(
            observed,
            "post-fix _after_block_added must call "
            "equivocation_watcher.observe_block_header so block-header "
            "equivocation auto-slashing actually runs",
        )


class ServerForkEmergencyAutoRecoveryTest(unittest.TestCase):
    """The 1.57.0 auto-recovery method must exist on Server and respect
    the validator-stake gate (registered validators MUST stay halted
    instead of auto-flipping; only zero-stake full nodes auto-recover).
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = self._tmp.name
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4
        self.srv = _build_server(self.data_dir)
        self.entity = _entity(b"recovery-srv")
        self.srv.blockchain.initialize_genesis(self.entity)
        register_entity_for_test(self.srv.blockchain, self.entity)
        self.srv.set_wallet_entity(self.entity)

    def tearDown(self):
        _teardown_server(self.srv)
        self._tmp.cleanup()
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_method_exists(self):
        self.assertTrue(
            hasattr(self.srv, "_maybe_auto_recover_from_fork_emergency"),
            "Server must expose _maybe_auto_recover_from_fork_emergency "
            "(mirrors Node so 1.57.0 standing-focus item "
            "'accidental-fork auto-recovery for full nodes' is actually "
            "wired on the production path).",
        )

    def test_validator_stake_gate_blocks_auto_recovery(self):
        """A staked validator MUST stay halted instead of auto-flipping;
        only zero-stake full nodes are safe to auto-recover.
        """
        # Stake the wallet entity into the active set.
        self.srv.consensus.stakes[self.entity.entity_id] = 100_000
        # Force the config flag on so the gate is the only thing
        # blocking recovery.
        with patch.object(config, "FORK_EMERGENCY_AUTO_RECOVERY", True):
            recover_calls = []
            orig = self.srv.blockchain.attempt_fork_emergency_recovery

            def _spy():
                recover_calls.append(True)
                return orig()
            self.srv.blockchain.attempt_fork_emergency_recovery = _spy
            self.srv._maybe_auto_recover_from_fork_emergency()
        self.assertEqual(
            recover_calls, [],
            "validator with stake must NOT auto-recover; halt is the "
            "anchored behaviour (avoids weaponizing a quorum-signal bug "
            "into network-wide chain abandonment)",
        )

    def test_zero_stake_full_node_with_no_emergency_is_noop(self):
        """No emergency present + zero stake + flag on => no recovery
        attempted (cheap fast-path; no spurious rewinds).
        """
        # Wallet is NOT in consensus.stakes -> zero-stake full node.
        with patch.object(config, "FORK_EMERGENCY_AUTO_RECOVERY", True):
            recover_calls = []
            orig = self.srv.blockchain.attempt_fork_emergency_recovery

            def _spy():
                recover_calls.append(True)
                return orig()
            self.srv.blockchain.attempt_fork_emergency_recovery = _spy
            # No emergency injected -> is_in_emergency() is False
            self.srv._maybe_auto_recover_from_fork_emergency()
        self.assertEqual(
            recover_calls, [],
            "no emergency -> recovery attempt must short-circuit "
            "without calling attempt_fork_emergency_recovery",
        )


class ServerForkEmergencyHaltGateTest(unittest.TestCase):
    """When ``fork_emergency_detector.is_in_emergency()`` is True, the
    Server's block-production path must halt (no propose, no attest)
    so the validator does not accumulate slashable evidence on a
    minority/wrong tip.  Mirrors the Node halt gates at
    network/node.py:1613 (attest) and :2315 (propose).
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = self._tmp.name
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4
        self.srv = _build_server(self.data_dir)
        self.entity = _entity(b"halt-gate")
        self.srv.blockchain.initialize_genesis(self.entity)
        register_entity_for_test(self.srv.blockchain, self.entity)
        self.srv.set_wallet_entity(self.entity)
        # Make ourselves the proposer.
        from messagechain.config import VALIDATOR_MIN_STAKE
        self.srv.blockchain.supply.balances[self.entity.entity_id] = (
            VALIDATOR_MIN_STAKE * 2
        )
        self.srv.blockchain.supply.stake(
            self.entity.entity_id, VALIDATOR_MIN_STAKE,
        )
        self.srv.consensus.stakes[self.entity.entity_id] = VALIDATOR_MIN_STAKE
        self.srv._running = True

    def tearDown(self):
        _teardown_server(self.srv)
        self._tmp.cleanup()
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_propose_halts_during_fork_emergency(self):
        """A staked validator must NOT propose while an emergency is
        live -- producing a block on the wrong tip burns WOTS+ leaves
        on a chain we'll need to abandon, and accumulates slashable
        evidence.
        """
        # Inject a synthetic emergency.  The detector's `_emergencies`
        # dict is the source of truth for is_in_emergency().
        from messagechain.consensus.fork_emergency import ForkEmergency
        det = self.srv.blockchain.fork_emergency_detector
        det._emergencies[1] = ForkEmergency(
            height=1,
            supermajority_hash=b"\xff" * 32,
            local_hash=b"\x00" * 32,
            attested_stake=100,
            total_stake=100,
        )
        self.assertTrue(det.is_in_emergency())

        result = self.srv._try_produce_block_sync()
        self.assertIsNone(
            result,
            "Server must halt block production while fork-emergency "
            "is active; pre-fix it produced a block on the wrong tip",
        )


class ServerAttestationEquivocationObserveTest(unittest.TestCase):
    """``_handle_announce_attestation`` must feed verified attestations
    into ``equivocation_watcher.observe_attestation`` so a peer
    double-attesting at the same (validator, height) auto-emits a
    SlashTransaction.  Pre-fix the production validator path didn't
    invoke the watcher at all.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = self._tmp.name
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4
        self.srv = _build_server(self.data_dir)
        self.entity = _entity(b"observer")
        self.srv.blockchain.initialize_genesis(self.entity)
        register_entity_for_test(self.srv.blockchain, self.entity)

    def tearDown(self):
        _teardown_server(self.srv)
        self._tmp.cleanup()
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_handle_announce_attestation_feeds_watcher(self):
        # Build a real attestation from a separate entity.
        attester = _entity(b"attester")
        register_entity_for_test(self.srv.blockchain, attester)
        latest = self.srv.blockchain.get_latest_block()
        from messagechain.consensus.attestation import (
            create_attestation,
        )
        att = create_attestation(
            attester,
            block_hash=latest.block_hash,
            block_number=latest.header.block_number,
        )

        observe_calls = []
        orig = self.srv.equivocation_watcher.observe_attestation

        def _spy(att_arg, **kwargs):
            observe_calls.append(att_arg)
            return orig(att_arg, **kwargs)
        self.srv.equivocation_watcher.observe_attestation = _spy

        # Build a fake peer; the handler only reads peer.address.
        class _FakePeer:
            address = "1.2.3.4:1234"

        import asyncio
        asyncio.run(
            self.srv._handle_announce_attestation(att.serialize(), _FakePeer())
        )
        self.assertEqual(
            len(observe_calls), 1,
            "post-fix _handle_announce_attestation must call "
            "equivocation_watcher.observe_attestation so peer "
            "double-attestation auto-emits a slash tx",
        )
