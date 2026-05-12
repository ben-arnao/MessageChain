"""Audit r50 #3 -- one bad-sig entry in a proposer's attestation or
finality-vote bundle fails the entire block; cheap proposer-grief
primitive.

``_validate_attestations`` and ``_validate_finality_votes`` (the
block-validation path) return False on the first invalid signature,
rejecting the whole block.  Mirroring the survivor-filter behaviour
at validation time would change the block-acceptance criterion and
require a hard fork (CLAUDE.md anchor: "minimize hard forks; only
break compatibility when there's no compatible path").

Soft-fix shape -- ensure an honest proposer NEVER constructs a block
with a bad signature in the first place.  ``Blockchain.propose_block``
pre-filters attestations and finality_votes through a shared
``_partition_verified_aggregation`` helper that drops any entry the
historical-key candidate set (audit r50 #2's ``_verify_signer_at_
height``) cannot verify.  Bad-sig entries planted in the proposer's
mempool or finality-tracker by a malicious peer are silently
discarded before block assembly, so:

  * the proposer's block-validate path can't fail on signatures the
    proposer themselves had access to verify;
  * the proposer's WOTS+ leaf isn't burnt on a block that's destined
    to be rejected by peers;
  * future signed-aggregation kinds added to ``propose_block`` pick
    up the same discipline by routing through the helper.

CLAUDE.md anchors at risk: honest-operator insurance (a proposer
griefed off a block via a planted bad sig is being slashed-adjacent
on cost: wasted leaf, no fee revenue), and validator-collusion
defense (the surface this round's signature-aggregation lens
flagged).

This is a non-consensus, non-fork, defense-in-depth change.  Old
clients still propose with no pre-filter and still reject bad-sig
blocks; the chain stays in sync.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain.consensus.attestation import (
    Attestation, create_attestation, verify_attestation,
)
from messagechain.consensus.finality import (
    FinalityVote, create_finality_vote, verify_finality_vote,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.block import _hash
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


def _entity(seed: bytes, tree_height: int = 6) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"), tree_height=tree_height)


def _forge_bad_signature(good_sig: Signature) -> Signature:
    """Flip every WOTS+ chain byte; signature stays well-formed but
    won't verify."""
    return Signature(
        wots_signature=[bytes(b ^ 0xFF for b in s) for s in good_sig.wots_signature],
        leaf_index=good_sig.leaf_index,
        auth_path=list(good_sig.auth_path),
        wots_public_key=good_sig.wots_public_key,
        wots_public_seed=good_sig.wots_public_seed,
        sig_version=good_sig.sig_version,
    )


class TestPartitionHelperExists(unittest.TestCase):
    """Single chokepoint every proposer-side signed-aggregation pre-
    filter MUST route through.  Adding a new signed-aggregation kind
    in propose_block can't reintroduce the all-or-nothing-rejection
    grief surface so long as it routes through this helper."""

    def test_blockchain_exposes_partition_verified_aggregation(self):
        self.assertTrue(
            hasattr(Blockchain, "_partition_verified_aggregation"),
            "Blockchain must expose _partition_verified_aggregation as "
            "the single chokepoint for proposer-side pre-filtering of "
            "signed aggregation lists (audit r50 #3).",
        )


class TestProposerDropsBadSigsBeforePacking(unittest.TestCase):
    """Behavioural: an honest proposer who pulls signed aggregations
    from gossip-poisoned sources MUST drop the bad-sig entries before
    packing them into the block -- otherwise a single planted bad
    sig kills the entire block and burns the proposer's WOTS+ leaf."""

    def _build_chain(self):
        alice = _entity(b"r50_pf_alice")
        bob = _entity(b"r50_pf_bob")
        carol = _entity(b"r50_pf_carol")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, bob)
        register_entity_for_test(chain, carol)
        chain.supply.balances[alice.entity_id] = 10_000
        chain.supply.balances[bob.entity_id] = 10_000
        chain.supply.balances[carol.entity_id] = 10_000
        chain.supply.stake(alice.entity_id, 2_000)
        chain.supply.stake(bob.entity_id, 500)
        chain.supply.stake(carol.entity_id, 500)
        return chain, alice, bob, carol

    def test_propose_block_drops_bad_attestation(self):
        chain, alice, bob, carol = self._build_chain()
        pos = ProofOfStake()
        # Build block 1 with no attestations (no parent to attest to).
        proposer = pick_selected_proposer(chain, [alice, bob, carol])
        block1 = chain.propose_block(pos, proposer, [])
        ok, reason = chain.add_block(block1)
        self.assertTrue(ok, reason)

        # Now build attestations for block1 from bob and carol.
        att_bob = create_attestation(bob, block1.block_hash, block1.header.block_number)
        att_carol = create_attestation(carol, block1.block_hash, block1.header.block_number)
        # Plant a bad sig: bob's attestation with a corrupted signature.
        att_bad = Attestation(
            validator_id=bob.entity_id,
            block_hash=block1.block_hash,
            block_number=block1.header.block_number,
            signature=_forge_bad_signature(att_bob.signature),
        )

        # Proposer for block 2 packs both bad and good.  The pre-filter
        # must drop the bad one and keep the good ones.
        proposer2 = pick_selected_proposer(chain, [alice, bob, carol])
        block2 = chain.propose_block(
            pos, proposer2, [],
            attestations=[att_bad, att_bob, att_carol],
        )

        # block.attestations may not contain the bad entry.
        sigs = [a.signature.wots_signature for a in block2.attestations]
        self.assertNotIn(
            att_bad.signature.wots_signature, sigs,
            "propose_block must drop the bad-sig attestation before "
            "packing (audit r50 #3).",
        )
        # The good ones should still be present.
        validator_ids = {a.validator_id for a in block2.attestations}
        self.assertIn(bob.entity_id, validator_ids,
                      "bob's legitimate attestation must remain.")
        self.assertIn(carol.entity_id, validator_ids,
                      "carol's legitimate attestation must remain.")

    def test_propose_block_drops_bad_finality_vote(self):
        chain, alice, bob, carol = self._build_chain()
        pos = ProofOfStake()
        proposer = pick_selected_proposer(chain, [alice, bob, carol])
        block1 = chain.propose_block(pos, proposer, [])
        ok, reason = chain.add_block(block1)
        self.assertTrue(ok, reason)

        signed_at = block1.header.block_number
        vote_bob = create_finality_vote(
            signer_entity=bob,
            target_block_hash=block1.block_hash,
            target_block_number=block1.header.block_number,
            signed_at_height=signed_at,
        )
        vote_carol = create_finality_vote(
            signer_entity=carol,
            target_block_hash=block1.block_hash,
            target_block_number=block1.header.block_number,
            signed_at_height=signed_at,
        )
        vote_bad = FinalityVote(
            signer_entity_id=bob.entity_id,
            target_block_hash=block1.block_hash,
            target_block_number=block1.header.block_number,
            signed_at_height=signed_at,
            signature=_forge_bad_signature(vote_bob.signature),
        )

        proposer2 = pick_selected_proposer(chain, [alice, bob, carol])
        block2 = chain.propose_block(
            pos, proposer2, [],
            finality_votes=[vote_bad, vote_bob, vote_carol],
        )

        votes_in_block = getattr(block2, "finality_votes", [])
        sigs = [v.signature.wots_signature for v in votes_in_block]
        self.assertNotIn(
            vote_bad.signature.wots_signature, sigs,
            "propose_block must drop the bad-sig finality vote before "
            "packing (audit r50 #3).",
        )
        signer_ids = {v.signer_entity_id for v in votes_in_block}
        self.assertIn(bob.entity_id, signer_ids,
                      "bob's legitimate vote must remain.")
        self.assertIn(carol.entity_id, signer_ids,
                      "carol's legitimate vote must remain.")


class TestProposeBlockRoutesThroughPartitionHelper(unittest.TestCase):
    """Structural: propose_block must call the partition helper for
    both attestations and finality_votes -- so a future signed-
    aggregation type added to propose_block can't bypass the filter
    just by being a new tx kind."""

    def test_propose_block_source_uses_partition(self):
        src = inspect.getsource(Blockchain.propose_block)
        self.assertIn(
            "_partition_verified_aggregation", src,
            "propose_block must route attestation and finality_vote "
            "pre-filtering through "
            "Blockchain._partition_verified_aggregation (audit r50 #3).",
        )


class TestPartitionDropsOnHistoricalMismatch(unittest.TestCase):
    """The partition helper must use the historical-key candidate set
    (audit r50 #2's ``_verify_signer_at_height``).  A signature from
    a never-registered entity is dropped; a signature from a known
    entity with the candidate-set verifying it is kept."""

    def test_unknown_entity_signature_dropped(self):
        chain = Blockchain()
        stranger = _entity(b"r50_pf_stranger")
        att = create_attestation(stranger, _hash(b"r50_pf_blk"), 1)
        verified, dropped = chain._partition_verified_aggregation(
            [att],
            get_entity_id=lambda a: a.validator_id,
            get_signed_at_height=lambda a: a.block_number,
            verifier=verify_attestation,
        )
        self.assertEqual(verified, [])
        self.assertEqual(len(dropped), 1)

    def test_registered_entity_passes(self):
        chain = Blockchain()
        signer = _entity(b"r50_pf_known")
        chain.initialize_genesis(signer)
        att = create_attestation(signer, _hash(b"r50_pf_known_blk"), 1)
        verified, dropped = chain._partition_verified_aggregation(
            [att],
            get_entity_id=lambda a: a.validator_id,
            get_signed_at_height=lambda a: a.block_number,
            verifier=verify_attestation,
        )
        self.assertEqual(len(verified), 1)
        self.assertEqual(dropped, [])


if __name__ == "__main__":
    unittest.main()
