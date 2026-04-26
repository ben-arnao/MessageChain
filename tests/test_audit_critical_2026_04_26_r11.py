"""Critical-severity audit fix -- round 11 (2026-04-26).

ONE CRITICAL: FinalityDoubleVote slash-evasion via key rotation
between conflicting votes.  The prior single-key path in
`Blockchain.validate_slash_transaction` resolved ONE pubkey at
`vote_a.signed_at_height` and called
`verify_finality_double_vote_evidence(ev, K_old)`.  An equivocator
who rotated keys between vote_a and vote_b had vote_b signed under
K_new -- verification under K_old failed and the slash was
dismissed.  Cooldown (KEY_ROTATION_COOLDOWN_BLOCKS=144) <<
vote-age window (FINALITY_VOTE_MAX_AGE_BLOCKS=1000), so the rotation
window comfortably fits inside the same target's vote window.

Round 6 introduced a multi-key candidate enumeration (full
key_history + current pubkey) for AttestationSlashing and
double-proposal SlashingEvidence -- the parallel
FinalityDoubleVoteEvidence path was overlooked.

Fix: extend the multi-key shape to FinalityDoubleVote.  Update
`verify_finality_double_vote_evidence` to accept an iterable of
candidate pubkeys; verify each vote independently against ANY
candidate.  Update `validate_slash_transaction` to enumerate the
same key_history + current candidate set for FinalityDoubleVote
that AttestationSlashing already uses.

Tests:
1. Forward-compat: legacy single-pubkey caller still works.
2. Multi-key candidate iterable verifies vote_a under K_old AND
   vote_b under K_new (the previously-bypassable case).
3. End-to-end via `validate_slash_transaction`: a rotate-then-
   equivocate FinalityDoubleVote slash is now ADMITTED, where
   pre-fix it was dismissed as "Invalid evidence: vote_b signature
   is invalid".
"""

from __future__ import annotations

import unittest

from messagechain.identity.identity import Entity
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.consensus.finality import (
    FinalityVote, FinalityDoubleVoteEvidence,
    create_finality_vote, verify_finality_double_vote_evidence,
)
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.slashing import SlashTransaction


def _entity(seed: bytes, height: int = 4) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestVerifyFinalityDoubleVoteEvidenceAcceptsCandidates(unittest.TestCase):
    """`verify_finality_double_vote_evidence` MUST accept an iterable
    of candidate pubkeys and verify each vote against ANY candidate."""

    def test_legacy_single_pubkey_still_works(self):
        """Forward-compat: callers passing a single 32-byte pubkey
        should keep working without migration."""
        signer = _entity(b"r11-legacy")
        vote_a = create_finality_vote(
            signer_entity=signer,
            target_block_hash=b"\xaa" * 32,
            target_block_number=10,
            signed_at_height=10,
        )
        vote_b = create_finality_vote(
            signer_entity=signer,
            target_block_hash=b"\xbb" * 32,
            target_block_number=10,
            signed_at_height=10,
        )
        ev = FinalityDoubleVoteEvidence(
            offender_id=signer.entity_id, vote_a=vote_a, vote_b=vote_b,
        )
        ok, reason = verify_finality_double_vote_evidence(
            ev, signer.public_key,
        )
        self.assertTrue(ok, f"Single-pubkey legacy path broken: {reason}")

    def test_multi_key_verifies_each_vote_independently(self):
        """The round-11 multi-key shape: vote_a signed with K_old,
        vote_b signed with K_new (post-rotation).  Each vote MUST
        verify against SOME candidate in the iterable.  Pre-fix the
        function only checked both against ONE pubkey, so this case
        returned 'vote_b signature is invalid'."""
        signer_old = _entity(b"r11-mk-old")
        signer_new = _entity(b"r11-mk-new")
        eid = signer_old.entity_id  # both votes claim the same offender
        # vote_a signed by K_old at height N
        vote_a = create_finality_vote(
            signer_entity=signer_old,
            target_block_hash=b"\xaa" * 32,
            target_block_number=10,
            signed_at_height=10,
        )
        # vote_b signed by K_new at height N+200 (post-rotation, same target)
        vote_b_unsigned = FinalityVote(
            signer_entity_id=eid,
            target_block_hash=b"\xbb" * 32,
            target_block_number=10,
            signed_at_height=210,
            signature=Signature([], 0, [], b"", b""),
        )
        msg_hash = _hash(vote_b_unsigned._signable_data())
        vote_b_unsigned.signature = signer_new.keypair.sign(msg_hash)
        vote_b = vote_b_unsigned
        ev = FinalityDoubleVoteEvidence(
            offender_id=eid, vote_a=vote_a, vote_b=vote_b,
        )
        # Multi-key candidates: K_old + K_new (matches what the
        # validate_slash_transaction enumeration produces from
        # key_history).
        candidates = [signer_old.public_key, signer_new.public_key]
        ok, reason = verify_finality_double_vote_evidence(
            ev, candidates,
        )
        self.assertTrue(
            ok,
            f"Multi-key candidate set MUST admit a rotate-then-"
            f"equivocate FinalityDoubleVote slash. Got: {reason}",
        )

    def test_single_pubkey_pre_fix_path_rejects_rotated_vote(self):
        """Regression guard: confirm the pre-fix shape (single
        pubkey resolved at vote_a.signed_at_height) WOULD reject the
        rotate-then-equivocate evidence.  This documents the exploit
        the round-11 fix closes."""
        signer_old = _entity(b"r11-pre-old")
        signer_new = _entity(b"r11-pre-new")
        eid = signer_old.entity_id
        vote_a = create_finality_vote(
            signer_entity=signer_old,
            target_block_hash=b"\xaa" * 32,
            target_block_number=10,
            signed_at_height=10,
        )
        vote_b_unsigned = FinalityVote(
            signer_entity_id=eid,
            target_block_hash=b"\xbb" * 32,
            target_block_number=10,
            signed_at_height=210,
            signature=Signature([], 0, [], b"", b""),
        )
        vote_b_unsigned.signature = signer_new.keypair.sign(
            _hash(vote_b_unsigned._signable_data())
        )
        vote_b = vote_b_unsigned
        ev = FinalityDoubleVoteEvidence(
            offender_id=eid, vote_a=vote_a, vote_b=vote_b,
        )
        # Pre-fix: pass ONLY K_old (the single resolved key).  vote_b
        # was signed with K_new, so verification must fail.
        ok, reason = verify_finality_double_vote_evidence(
            ev, signer_old.public_key,
        )
        self.assertFalse(
            ok,
            "Sanity: legacy single-pubkey path with K_old MUST still "
            "reject vote_b signed with K_new -- this is the exact "
            "bypass round-11's multi-key path closes.",
        )
        self.assertIn("vote_b", reason)


class TestValidateSlashTransactionRotatorIsSlashable(unittest.TestCase):
    """End-to-end via `Blockchain.validate_slash_transaction`: an
    equivocator who rotated keys between conflicting votes MUST be
    slashable.  Pre-fix this path was dismissed as
    'Invalid evidence: vote_b signature is invalid'."""

    def test_rotate_then_equivocate_finality_slash_admitted(self):
        chain = Blockchain()
        # Submitter (any registered entity will do).
        submitter = _entity(b"r11-e2e-submitter")
        chain._install_pubkey_direct(
            submitter.entity_id, submitter.public_key,
            registration_proof=submitter.keypair.sign(
                _hash(b"register" + submitter.entity_id),
            ),
        )
        chain.supply.balances[submitter.entity_id] = 1_000_000

        # Offender with TWO keys (K_old, K_new) -- mirrors what the
        # chain sees after the offender's KeyRotation has been
        # applied.  We register K_new as the current pubkey and
        # populate `key_history` with both heights.
        old_kp = _entity(b"r11-e2e-old")
        new_kp = _entity(b"r11-e2e-new")
        eid = old_kp.entity_id
        chain._install_pubkey_direct(
            eid, old_kp.public_key,
            registration_proof=old_kp.keypair.sign(
                _hash(b"register" + eid),
            ),
        )
        # Simulate a rotation: history holds K_old at height 0,
        # K_new at height 150 (>= cooldown 144); current pubkey is
        # K_new.
        chain.public_keys[eid] = new_kp.public_key
        chain.key_history[eid] = [
            (0, old_kp.public_key),
            (150, new_kp.public_key),
        ]
        # Stake the offender so the slash bookkeeping has something
        # to seize (irrelevant to admission, but realistic).
        chain.supply.balances[eid] = 100_000
        chain.supply.staked[eid] = 50_000

        # vote_a signed by K_old at height 10
        vote_a = create_finality_vote(
            signer_entity=old_kp,
            target_block_hash=b"\xaa" * 32,
            target_block_number=10,
            signed_at_height=10,
        )
        # vote_b signed by K_new at height 200 -- same target,
        # different hash.
        vote_b = FinalityVote(
            signer_entity_id=eid,
            target_block_hash=b"\xbb" * 32,
            target_block_number=10,
            signed_at_height=200,
            signature=Signature([], 0, [], b"", b""),
        )
        vote_b.signature = new_kp.keypair.sign(_hash(vote_b._signable_data()))

        ev = FinalityDoubleVoteEvidence(
            offender_id=eid, vote_a=vote_a, vote_b=vote_b,
        )

        # Build the SlashTransaction wrapping the evidence.
        import time
        slash_tx = SlashTransaction(
            evidence=ev,
            submitter_id=submitter.entity_id,
            timestamp=int(time.time()),
            fee=200,
            signature=Signature([], 0, [], b"", b""),
        )
        slash_tx.signature = submitter.keypair.sign(
            _hash(slash_tx._signable_data())
        )
        slash_tx.tx_hash = slash_tx._compute_hash()

        ok, reason = chain.validate_slash_transaction(slash_tx)
        self.assertTrue(
            ok,
            f"Rotate-then-equivocate FinalityDoubleVote slash MUST "
            f"now be admitted.  Pre-fix this path was dismissed as "
            f"'Invalid evidence: vote_b signature is invalid' -- "
            f"the validator could equivocate, rotate, and keep "
            f"stake.  Got: {reason}",
        )


if __name__ == "__main__":
    unittest.main()
