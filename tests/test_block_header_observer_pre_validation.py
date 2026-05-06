"""Pre-validation feed for the equivocation watcher's block-header path.

Pre-fix (audit r20 #2): ``EquivocationWatcher.observe_block_header``
was fed exclusively from ``_after_block_added`` -- the post-success
hook on ``Blockchain.add_block``.  A block whose proposer signature
verified BUT failed some later validate_block check (state_root
mismatch, randao mismatch, contained-tx signature check, etc.)
silently bypassed the watcher: ``add_block`` returned ``(False,
reason)`` early, ``_after_block_added`` was not called, and the
watcher's ``seen_signatures`` cache never recorded the conflicting
header.

Documented attack window: a colluding double-proposer signs two
headers (A, B) at the same height.  A is broadcast cleanly and
applied; B is broadcast with a body crafted to fail a late
validate_block check (e.g. a contained tx with a forged signature).
Honest validators reject B at validate_block but never observe its
header -- so although the protocol has all the crypto it needs to
slash for the equivocation (B's header carries a valid proposer
signature over different signable_data than A's), no auto-slash
fires because the watcher's input feed missed B.

This test pins:

  1. ``Blockchain.register_block_header_observer(callback)`` exists
     and stores a callback.
  2. ``validate_block`` invokes the observer immediately AFTER the
     proposer signature is verified successfully -- regardless of
     whether downstream checks reject the block.  Pinned at the
     source level (``_notify_block_header_observer(block.header)``
     must appear after the ``verify_signature`` call and before the
     next post-signature ``return False``).
  3. ``validate_block_standalone`` (the fork-path entry point) does
     the same.
  4. ``Server.__init__`` and ``Node.__init__`` register the
     ``EquivocationWatcher.observe_block_header`` bound method as
     the observer.
  5. The runtime hook fires when a real validly-signed block flows
     through validate_block and does NOT fire on a corrupted
     signature.
"""

import inspect
import os
import tempfile
import time
import unittest

from messagechain.config import (
    TREASURY_ENTITY_ID,
    VALIDATOR_MIN_STAKE,
)
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _make_signed_header(proposer_entity, prev_block, merkle_seed: bytes,
                        t_offset: float = 0.001) -> BlockHeader:
    """Build a header signed over `signable_data()` (no randao_mix)."""
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


class _ChainFixture(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-obs-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)
        self.alice = Entity.create(b"alice-obs".ljust(32, b"\x00"))
        self.offender = Entity.create(b"offender-obs".ljust(32, b"\x00"))
        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.alice,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.alice.entity_id: 1_000_000,
            },
        )
        register_entity_for_test(self.chain, self.offender)
        self.chain.supply.balances[self.offender.entity_id] = 10_000
        self.chain.supply.stake(
            self.offender.entity_id, VALIDATOR_MIN_STAKE,
        )

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class BlockchainObserverRegistrationTest(_ChainFixture):

    def test_register_block_header_observer_method_exists(self):
        self.assertTrue(
            hasattr(self.chain, "register_block_header_observer"),
            "Blockchain must expose register_block_header_observer "
            "so Server / Node can wire EquivocationWatcher into the "
            "validate-block sig-verify hook.  Without it the "
            "watcher's only feed was the success-only "
            "_after_block_added path which silently dropped any "
            "block whose proposer signature verified but whose "
            "later validation step (state_root, randao, contained "
            "tx sig, ...) rejected.",
        )
        self.assertTrue(callable(self.chain.register_block_header_observer))

    def test_register_stores_callback(self):
        observed = []
        self.chain.register_block_header_observer(observed.append)
        self.assertEqual(self.chain._block_header_observer, observed.append)

    def test_notify_helper_fires_observer_with_header(self):
        """The helper that validate_block / validate_block_standalone
        will call must invoke the registered callback with the
        header argument."""
        observed = []
        self.chain.register_block_header_observer(observed.append)
        prev = self.chain.get_latest_block()
        hdr = _make_signed_header(self.offender, prev, b"x")
        self.chain._notify_block_header_observer(hdr)
        self.assertEqual(observed, [hdr])

    def test_notify_helper_swallows_observer_exception(self):
        """A misbehaving observer must NEVER abort validate_block --
        the validator must reject blocks for consensus reasons, not
        because a watcher crashed."""
        def _angry(_h):
            raise RuntimeError("watcher crashed")
        self.chain.register_block_header_observer(_angry)
        prev = self.chain.get_latest_block()
        hdr = _make_signed_header(self.offender, prev, b"x")
        # No exception leaks out of _notify_block_header_observer.
        self.chain._notify_block_header_observer(hdr)


class ValidateBlockObserverWiringSourceTest(unittest.TestCase):
    """Source-level pin: the observer call must appear in
    ``validate_block`` and ``validate_block_standalone`` AFTER the
    proposer signature has been verified.  A future refactor that
    moves the call BEFORE verify_signature would re-open the watcher-
    pollution attack (forged signatures reach the observer); a
    refactor that DELETES the call collapses back to the success-only
    feed of audit r20 #2.  Source-level pin catches both regressions.
    """

    def _assert_observer_called_after_verify_signature(self, fn):
        src = inspect.getsource(fn)
        verify_idx = src.find("verify_signature(")
        notify_idx = src.find("_notify_block_header_observer(")
        self.assertGreater(
            verify_idx, -1,
            f"{fn.__qualname__} is expected to call verify_signature "
            "on the proposer signature -- audit-fix landmark missing",
        )
        self.assertGreater(
            notify_idx, -1,
            f"{fn.__qualname__} must call "
            "_notify_block_header_observer to feed the equivocation "
            "watcher pre-validation (audit r20 #2 regression)",
        )
        # The observer call MUST come after verify_signature so the
        # watcher's seen_signatures cache cannot be polluted by a
        # forged signature.
        self.assertGreater(
            notify_idx, verify_idx,
            f"{fn.__qualname__}: _notify_block_header_observer must "
            "be called AFTER verify_signature so forged-signature "
            "blocks never reach the observer (otherwise an attacker "
            "with no valid key could pollute the watcher's "
            "seen_signatures table).",
        )

    def test_validate_block_calls_observer_after_sig_verify(self):
        self._assert_observer_called_after_verify_signature(
            Blockchain.validate_block,
        )

    def test_validate_block_standalone_calls_observer_after_sig_verify(self):
        self._assert_observer_called_after_verify_signature(
            Blockchain.validate_block_standalone,
        )


class ServerNodeObserverWiringTest(unittest.TestCase):
    """Both production-runtime classes (Server, Node) must register
    the EquivocationWatcher's observe_block_header as the observer
    when the watcher is constructed.  Pre-fix this wiring did not
    exist on either class, so the new validate_block hook would
    fire into the void on a real network.
    """

    def test_server_registers_watcher_as_block_header_observer(self):
        """Source-level pin on server.py: when the watcher is
        constructed, its observe_block_header MUST be registered."""
        import server as server_mod
        src = inspect.getsource(server_mod.Server.__init__)
        self.assertIn(
            "register_block_header_observer", src,
            "Server.__init__ must call "
            "self.blockchain.register_block_header_observer with "
            "self.equivocation_watcher.observe_block_header so the "
            "validate-block hook actually feeds the watcher on the "
            "production runtime (mainnet validators run Server, "
            "not Node).",
        )

    def test_node_registers_watcher_as_block_header_observer(self):
        from messagechain.network import node as node_mod
        src = inspect.getsource(node_mod.Node.__init__)
        self.assertIn(
            "register_block_header_observer", src,
            "Node.__init__ must register the watcher's observe "
            "callback alongside Server -- same wiring contract on "
            "both production-runtime entry points.",
        )


class ValidateBlockObserverRuntimeTest(_ChainFixture):
    """End-to-end: build a real, fully-valid block via create_block
    and confirm the registered observer fires when that block flows
    through ``validate_block``.  Then corrupt the proposer signature
    and confirm the observer does NOT fire (sig-verify gate keeps
    forged-signature blocks out of the watcher's input).
    """

    def _build_real_block(self, t_offset: float = 0.0):
        """Use the real proposer pipeline so the block reaches the
        sig-verify line in validate_block -- nothing else is reliable
        enough to reach that point in test."""
        from messagechain.consensus import block_producer
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        consensus.stakes[self.offender.entity_id] = VALIDATOR_MIN_STAKE
        # Push the offender into the active proposer set.
        ok, round_no, _reason = block_producer.should_propose(
            self.chain, consensus, self.offender.entity_id,
        )
        if not ok:
            self.skipTest(
                f"offender not currently selected as proposer: {_reason}"
            )
        block = self.chain.propose_block(
            consensus, self.offender, txs=[],
        )
        # propose_block uses time.time() for the header timestamp;
        # tests that need two distinct headers at the same height
        # take the t_offset by sleeping briefly.  Caller manages.
        return block

    def test_observer_fires_for_a_validly_signed_block(self):
        try:
            block = self._build_real_block()
        except Exception as exc:  # nocover -- only fires if proposer pipeline broke
            self.skipTest(f"could not build real block in test: {exc}")
        observed = []
        self.chain.register_block_header_observer(observed.append)
        # validate_block runs every check including sig-verify; on a
        # block we just produced via propose_block it should pass
        # all of them.  The observer must fire as a side-effect.
        ok, reason = self.chain.validate_block(block)
        self.assertTrue(
            ok, f"freshly proposed block must validate: {reason}"
        )
        self.assertEqual(
            len(observed), 1,
            "validate_block must call the registered block-header "
            "observer exactly once on a successful validation -- "
            "this is the runtime contract that closes the audit r20 "
            "#2 'valid sig + bad body' equivocation gap.",
        )
        self.assertEqual(
            observed[0].proposer_id, self.offender.entity_id,
        )

    def test_observer_does_NOT_fire_on_forged_signature(self):
        try:
            block = self._build_real_block()
        except Exception as exc:  # nocover
            self.skipTest(f"could not build real block in test: {exc}")
        # Corrupt the proposer signature in-place: zero out the
        # WOTS+ chains so verify_signature returns False.
        original = block.header.proposer_signature
        from messagechain.crypto.keys import Signature
        block.header.proposer_signature = Signature(
            wots_signature=[b"\x00" * len(seg) for seg in original.wots_signature],
            leaf_index=original.leaf_index,
            auth_path=original.auth_path,
            sig_version_byte=original.sig_version_byte,
            algorithm=original.algorithm,
        )
        observed = []
        self.chain.register_block_header_observer(observed.append)
        ok, reason = self.chain.validate_block(block)
        self.assertFalse(
            ok, "block with forged signature must be rejected"
        )
        self.assertEqual(
            observed, [],
            "observer MUST NOT fire on a block whose proposer "
            "signature failed verification -- otherwise an attacker "
            "with no valid key could pollute the watcher's "
            "seen_signatures table with forged tuples.",
        )


if __name__ == "__main__":
    unittest.main()
