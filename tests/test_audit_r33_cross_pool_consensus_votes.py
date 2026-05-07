"""Audit r33 #1 -- cross-pool WOTS+ leaf check missing on consensus-vote
pools and gossip-admit handlers.

Pre-fix `Server._check_leaf_across_all_pools` scanned every server-side
pool (`_pending_{stake,unstake,authority,governance}_txs`),
`mempool.react_pool`, and `mempool.pending` -- but NOT the
consensus-vote pools `mempool.finality_pool`, `mempool.slash_pool`, or
`mempool.censorship_evidence_pool`.  Plus the three gossip handlers
that admit signed objects from peers --
`_handle_announce_finality_vote`, `_handle_announce_slash`,
`_handle_announce_attestation` -- never called the cross-pool sweep
themselves before pooling.

Concrete bite: validator V signs a finality vote at leaf=N every
FINALITY_INTERVAL blocks.  V's local mempool also holds a pending
message tx at leaf=N (stale watermark, wallet bug, race during a
restart).  `mempool.add_finality_vote` admits the vote because the
finality_pool is keyed by consensus_hash, not by (signer, leaf).
Both signed objects now carry the same WOTS+ leaf; the two
publications leak enough one-time-key preimages for any observer to
forge an arbitrary signature at that leaf -- including a fresh
revoke, full-balance unstake, or set-authority rebind transferring
authority to the attacker.

Same defect class as audit r31 #1 (which closed the gap on
mempool.pending) and r12 (react_pool), but on the consensus-vote
side validators trip every cycle rather than only on user action.

The fix has three pieces:

1. `_tx_signer_pubkey` resolves `validator_id` (Attestation) and
   `signer_entity_id` (FinalityVote) in addition to the existing
   `entity_id / proposer_id / voter_id / submitter_id` fields, so
   the signer-keyed dedupe path can identify the signing pubkey for
   every pooled object kind.

2. `_check_leaf_across_all_pools` extended to scan
   `mempool.finality_pool`, `mempool.slash_pool`, and
   `mempool.censorship_evidence_pool` in BOTH the signer-keyed
   (default) and entity-id-keyed (legacy call shape) branches.

3. The three gossip handlers
   (`_handle_announce_finality_vote`, `_handle_announce_slash`,
   `_handle_announce_attestation`) call
   `_check_leaf_across_all_pools(...)` BEFORE the
   `mempool.add_*` / `blockchain.finality.add_attestation` step,
   so an incoming gossiped object at a leaf already used by a
   pending tx in any pool is dropped (and the source ban-scored)
   rather than amplified onto the wire.

Soft-fix: admission-side only, no consensus rule change.  Block-
level dedupe still catches anything that slips through admission;
this purely tightens admission so the gossip-broadcast amplification
never fires.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain import config
from messagechain.core.staking import create_stake_transaction
from messagechain.core.transaction import create_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_server():
    from server import Server
    return Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


# ---------------------------------------------------------------------------
# Source pins
# ---------------------------------------------------------------------------


class TestCheckLeafSourceScansConsensusVotePools(_Base):
    """Source pin: `_check_leaf_across_all_pools` MUST scan
    `mempool.finality_pool`, `mempool.slash_pool`, and
    `mempool.censorship_evidence_pool` so a cross-pool collision
    between a consensus-vote object and any other pending tx from
    the same signer is rejected at admission."""

    def test_source_includes_finality_pool(self):
        from server import Server
        src = inspect.getsource(Server._check_leaf_across_all_pools)
        self.assertIn(
            "finality_pool", src,
            "_check_leaf_across_all_pools MUST scan "
            "mempool.finality_pool -- a pending FinalityVote at "
            "leaf=N collides with any other pending tx at leaf=N "
            "from the same signer (WOTS+ leak).",
        )

    def test_source_includes_slash_pool(self):
        from server import Server
        src = inspect.getsource(Server._check_leaf_across_all_pools)
        self.assertIn(
            "slash_pool", src,
            "_check_leaf_across_all_pools MUST scan "
            "mempool.slash_pool -- a pending SlashTransaction at "
            "leaf=N collides with any other pending tx at leaf=N "
            "from the same submitter (WOTS+ leak).",
        )

    def test_source_includes_censorship_evidence_pool(self):
        from server import Server
        src = inspect.getsource(Server._check_leaf_across_all_pools)
        self.assertIn(
            "censorship_evidence_pool", src,
            "_check_leaf_across_all_pools MUST scan "
            "mempool.censorship_evidence_pool -- a pending CE tx "
            "at leaf=N collides with any other pending tx at "
            "leaf=N from the same submitter (WOTS+ leak).",
        )


class TestTxSignerPubkeyResolvesConsensusVoteFields(_Base):
    """Source pin: `_tx_signer_pubkey` MUST resolve `validator_id`
    (Attestation) and `signer_entity_id` (FinalityVote) in addition
    to the existing fields so the signer-keyed dedupe identifies
    every pooled object kind correctly."""

    def test_source_includes_validator_id(self):
        from server import Server
        src = inspect.getsource(Server._tx_signer_pubkey)
        self.assertIn(
            "validator_id", src,
            "_tx_signer_pubkey MUST recognize Attestation's "
            "validator_id field so cross-pool dedupe can resolve "
            "the signing pubkey for attestation objects.",
        )

    def test_source_includes_signer_entity_id(self):
        from server import Server
        src = inspect.getsource(Server._tx_signer_pubkey)
        self.assertIn(
            "signer_entity_id", src,
            "_tx_signer_pubkey MUST recognize FinalityVote's "
            "signer_entity_id field so cross-pool dedupe can "
            "resolve the signing pubkey for finality-vote objects.",
        )


class TestGossipHandlersCallCrossPoolCheck(_Base):
    """Source pin: the three consensus-vote gossip handlers MUST
    call `_check_leaf_across_all_pools` before pooling so an
    incoming gossiped object at a leaf already used by a pending
    tx in any pool is dropped rather than amplified onto the wire."""

    def test_finality_vote_handler_calls_cross_pool(self):
        from server import Server
        src = inspect.getsource(Server._handle_announce_finality_vote)
        self.assertIn(
            "_check_leaf_across_all_pools", src,
            "_handle_announce_finality_vote MUST call "
            "_check_leaf_across_all_pools before mempool.add_"
            "finality_vote.  A finality vote arriving at the same "
            "leaf as any pending tx from the same signer is the "
            "WOTS+ collision precondition; admission must refuse.",
        )

    def test_slash_handler_calls_cross_pool(self):
        from server import Server
        src = inspect.getsource(Server._handle_announce_slash)
        self.assertIn(
            "_check_leaf_across_all_pools", src,
            "_handle_announce_slash MUST call "
            "_check_leaf_across_all_pools before "
            "mempool.add_slash_transaction.",
        )

    def test_attestation_handler_calls_cross_pool(self):
        from server import Server
        src = inspect.getsource(Server._handle_announce_attestation)
        self.assertIn(
            "_check_leaf_across_all_pools", src,
            "_handle_announce_attestation MUST call "
            "_check_leaf_across_all_pools before "
            "blockchain.finality.add_attestation.  Attestations "
            "use the validator's hot key; a same-leaf collision "
            "with any pending tx from that validator is a WOTS+ "
            "leak primitive.",
        )


# ---------------------------------------------------------------------------
# Behavioral pin
# ---------------------------------------------------------------------------


class TestPendingFinalityVoteBlocksSameLeafTx(_Base):
    """Behavioral pin: a FinalityVote already in
    `mempool.finality_pool` at leaf=N MUST cause
    `_check_leaf_across_all_pools(stake_tx)` for a stake tx at the
    same leaf from the same signer to return False -- the second
    object is the one that would leak WOTS+ secret material on
    publication, so admission must refuse it."""

    def test_pending_finality_vote_blocks_stake_at_same_leaf(self):
        from messagechain.consensus.finality import create_finality_vote

        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 100_000

        # Build a real signed finality vote (uses leaf 0 by default).
        vote = create_finality_vote(
            signer_entity=alice,
            target_block_hash=b"\x00" * 32,
            target_block_number=1,
            signed_at_height=1,
        )
        vote_leaf = vote.signature.leaf_index

        # Park the vote in mempool.finality_pool exactly as a
        # successful admission would.  Skips ban-score / verify --
        # we are exercising the cross-pool dedupe in isolation.
        srv.mempool.finality_pool[vote.consensus_hash()] = vote

        # Now build a stake tx at the SAME leaf from the SAME signer.
        alice.keypair._next_leaf = vote_leaf
        stake = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        self.assertEqual(
            stake.signature.leaf_index, vote_leaf,
            "Test setup error: stake tx should be at the same leaf "
            "as the parked finality vote.",
        )

        self.assertFalse(
            srv._check_leaf_across_all_pools(stake),
            "Cross-pool dedupe MUST reject a stake tx at the same "
            "leaf as a pending finality vote in "
            "mempool.finality_pool -- two distinct signed payloads "
            "at the same WOTS+ leaf leak one-time-key secret "
            "material.",
        )


class TestPendingMessageBlocksSameLeafFinalityVote(_Base):
    """Behavioral pin: the symmetric direction -- a pending message
    tx at leaf=N must cause `_check_leaf_across_all_pools(vote)` for
    a finality vote at the same leaf from the same signer to return
    False.  Validates the signer-keyed branch correctly resolves a
    FinalityVote's signer_entity_id field."""

    def test_pending_message_blocks_finality_vote_at_same_leaf(self):
        from messagechain.consensus.finality import create_finality_vote

        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 100_000

        # Park a message tx in mempool.pending at leaf 0.
        msg_tx = create_transaction(
            entity=alice, message="hello", nonce=0, fee=500,
        )
        msg_leaf = msg_tx.signature.leaf_index
        srv.mempool.pending[msg_tx.tx_hash] = msg_tx

        # Now sign a finality vote at the same leaf.
        alice.keypair._next_leaf = msg_leaf
        vote = create_finality_vote(
            signer_entity=alice,
            target_block_hash=b"\x00" * 32,
            target_block_number=1,
            signed_at_height=1,
        )
        self.assertEqual(
            vote.signature.leaf_index, msg_leaf,
            "Test setup error: vote should be at the same leaf "
            "as the parked message tx.",
        )

        self.assertFalse(
            srv._check_leaf_across_all_pools(vote),
            "Cross-pool dedupe MUST reject a finality vote at the "
            "same leaf as a pending message tx -- the signer-"
            "keyed path must resolve FinalityVote.signer_entity_id "
            "as the signer.",
        )


if __name__ == "__main__":
    unittest.main()
