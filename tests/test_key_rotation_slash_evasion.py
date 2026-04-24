"""R6-A: validate_slash_transaction must verify evidence with the key
that was active at evidence_height, not the offender's current public
key. Without this, a validator can equivocate at block H, rotate keys
at H+1, and defeat any slash submitted after the rotation because the
old signature doesn't verify under the new key.

These tests cover the key_history structure and historical-key lookup
directly, plus snapshot/restore round-trip. The end-to-end
equivocate-then-rotate path is exercised via the lookup primitive that
validate_slash_transaction now calls — building real double-sign
evidence duplicates other test_slashing_evidence fixtures.
"""

import unittest
from unittest.mock import MagicMock

from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _at_height(chain: Blockchain, height: int) -> None:
    """Force chain.height to a target value by stubbing the `chain` list.

    Blockchain.height is `len(self.chain)` so replace the list with a
    MagicMock whose __len__ returns the target height.
    """
    stub = MagicMock()
    stub.__len__ = lambda _self: height
    chain.chain = stub


class TestKeyHistoryRecording(unittest.TestCase):
    def test_genesis_install_recorded(self):
        chain = Blockchain()
        genesis_entity = Entity.create(b"genesis-seed" + b"\x00" * 20, tree_height=6)
        chain.initialize_genesis(genesis_entity)
        hist = chain.key_history.get(genesis_entity.entity_id)
        self.assertIsNotNone(hist, "genesis entity must be in key_history")
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0][1], genesis_entity.public_key)

    def test_lookup_at_height_returns_active_key(self):
        chain = Blockchain()
        eid = b"e" * 32
        # Simulate install at height 5 then rotation at height 10.
        _at_height(chain, 5)
        chain._record_key_history(eid, b"\x11" * 32)
        _at_height(chain, 10)
        chain._record_key_history(eid, b"\x22" * 32)

        self.assertEqual(chain._public_key_at_height(eid, 5), b"\x11" * 32)
        self.assertEqual(chain._public_key_at_height(eid, 9), b"\x11" * 32)
        self.assertEqual(chain._public_key_at_height(eid, 10), b"\x22" * 32)
        self.assertEqual(chain._public_key_at_height(eid, 99), b"\x22" * 32)

    def test_lookup_before_install_returns_none(self):
        chain = Blockchain()
        eid = b"e" * 32
        _at_height(chain, 5)
        chain._record_key_history(eid, b"\x11" * 32)
        # Evidence from height 3, before install — nothing to verify.
        self.assertIsNone(chain._public_key_at_height(eid, 3))

    def test_lookup_without_history_falls_back_to_current(self):
        chain = Blockchain()
        eid = b"e" * 32
        chain.public_keys[eid] = b"\x33" * 32
        self.assertEqual(chain._public_key_at_height(eid, 100), b"\x33" * 32)


class TestKeyHistorySnapshotRestore(unittest.TestCase):
    def test_snapshot_captures_history_deepcopy(self):
        chain = Blockchain()
        eid = b"e" * 32
        _at_height(chain, 5)
        chain._record_key_history(eid, b"\x11" * 32)
        _at_height(chain, 10)
        chain._record_key_history(eid, b"\x22" * 32)

        snap = chain._snapshot_memory_state()
        # Mutate post-snapshot — must not leak into the snapshot.
        chain.key_history[eid].append((20, b"\x33" * 32))
        self.assertEqual(len(snap["key_history"][eid]), 2)

        chain._restore_memory_snapshot(snap)
        self.assertEqual(len(chain.key_history[eid]), 2)
        self.assertEqual(chain._public_key_at_height(eid, 10), b"\x22" * 32)

    def test_legacy_snapshot_restores_empty(self):
        chain = Blockchain()
        eid = b"e" * 32
        _at_height(chain, 5)
        chain._record_key_history(eid, b"\x11" * 32)
        snap = chain._snapshot_memory_state()
        snap.pop("key_history", None)
        chain._restore_memory_snapshot(snap)
        self.assertEqual(chain.key_history, {})

    def test_reset_state_clears_history(self):
        chain = Blockchain()
        eid = b"e" * 32
        _at_height(chain, 5)
        chain._record_key_history(eid, b"\x11" * 32)
        self.assertNotEqual(chain.key_history, {})
        chain._reset_state()
        self.assertEqual(chain.key_history, {})


class TestFinalityDoubleVoteSigningHeightLookup(unittest.TestCase):
    """C3 (round 2): FinalityDoubleVoteEvidence slashing MUST use the
    vote's SIGNING height for the offender-pubkey lookup, not the
    target height.  Finality votes may be signed up to
    FINALITY_VOTE_MAX_AGE_BLOCKS after the target they commit to, so
    if target_block_number is used for the key-at-height lookup, an
    equivocator who rotates between target and signing escapes the
    100%-slash -- the lookup returns the pre-rotation key, but the
    vote was signed with the post-rotation key, so signature
    verification fails and the evidence is dismissed.
    """

    def test_evidence_block_number_for_finality_uses_signing_height(self):
        """_evidence_block_number MUST return the vote's signed_at_height
        for FinalityDoubleVoteEvidence -- not target_block_number.
        """
        from messagechain.consensus.finality import (
            FinalityVote, FinalityDoubleVoteEvidence,
        )
        from messagechain.crypto.keys import Signature
        # Construct two conflicting votes targeting block 10 but signed
        # at block 100 -- the exact gap the rotation-race attack exploits.
        vote_a = FinalityVote(
            signer_entity_id=b"v" * 32,
            target_block_hash=b"\x11" * 32,
            target_block_number=10,
            signed_at_height=100,
            signature=Signature([], 0, [], b"", b""),
        )
        vote_b = FinalityVote(
            signer_entity_id=b"v" * 32,
            target_block_hash=b"\x22" * 32,
            target_block_number=10,
            signed_at_height=100,
            signature=Signature([], 0, [], b"", b""),
        )
        ev = FinalityDoubleVoteEvidence(
            offender_id=b"v" * 32, vote_a=vote_a, vote_b=vote_b,
        )
        chain = Blockchain()
        result = chain._evidence_block_number(ev)
        self.assertEqual(
            result, 100,
            "Finality double-vote evidence block number must be the "
            "signing height (100), not the target height (10) -- "
            "using target height lets a rotator defeat the slash.",
        )
        self.assertNotEqual(
            result, 10,
            "Regression guard: the previous buggy implementation "
            "returned target_block_number (10). That path allows "
            "rotation-race slash evasion.",
        )

    def test_finality_vote_signing_height_is_in_signable_data(self):
        """signed_at_height MUST be covered by the signature so an
        equivocator cannot spoof it to dodge the key-at-height lookup.
        Changing signed_at_height must change the signable bytes --
        otherwise signature replay with a forged height succeeds.
        """
        from messagechain.consensus.finality import FinalityVote
        from messagechain.crypto.keys import Signature
        base = FinalityVote(
            signer_entity_id=b"v" * 32,
            target_block_hash=b"\x11" * 32,
            target_block_number=10,
            signed_at_height=100,
            signature=Signature([], 0, [], b"", b""),
        )
        spoofed = FinalityVote(
            signer_entity_id=b"v" * 32,
            target_block_hash=b"\x11" * 32,
            target_block_number=10,
            signed_at_height=999,  # attacker claims a different signing height
            signature=Signature([], 0, [], b"", b""),
        )
        self.assertNotEqual(
            base._signable_data(), spoofed._signable_data(),
            "signed_at_height must be committed in the signable bytes "
            "so the offender cannot spoof it post-hoc.",
        )


if __name__ == "__main__":
    unittest.main()
