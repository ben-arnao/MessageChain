"""Audit r50 #2 -- attestation and FinalityVote validation/gossip
verify under the CURRENT key, not the key active at signed-at-height.

CLAUDE.md anchors at risk:
  * honest-operator insurance ("honest, well-configured nodes should
    rarely if ever be slashed under normal operation"),
  * crypto-agility (rotation is the mechanism via which signature
    schemes migrate; "future identity-adjacent features must preserve
    the 'one live key at a time' invariant" -- preserving identity
    means in-flight votes from prior keys must remain verifiable),
  * collective-decision censorship resistance (silent gossip-layer
    suppression of valid signed messages sidesteps the slashable
    evidence surface).

``KEY_ROTATION_COOLDOWN_BLOCKS = 144`` is << ``FINALITY_VOTE_MAX_AGE_
BLOCKS = 10 * FINALITY_INTERVAL = 1000``.  An honest validator who
rotates while their previously-signed votes are still in flight: those
votes verify-fail under the new key, get dropped from gossip, fail
``_validate_finality_votes`` when an honest proposer includes them,
and the relaying peer is hit with ``OFFENSE_INVALID_TX`` and banned
by peers.  Inversely, an attacker can replay a rotator's pre-rotation
gossip votes to make honest peers ban each other.

The slashing-evidence path already resolves the offender's key via
``_evidence_block_number`` -> ``vote_a.signed_at_height`` ->
``_public_key_at_height`` (see ``test_audit_r38_non_response_multi
_key.py`` for the same pattern on the non-response axis, and
``_compute_slash_pct`` / ``_evidence_block_number`` in
``blockchain.py``).  Attestation and FinalityVote validation +
gossip handlers do NOT, even though ``_validate_finality_votes``
already carries an explicit comment block at the verification site
calling out ``_public_key_at_height``.

Abstraction fix: a single ``Blockchain._verify_signer_at_height``
chokepoint routes both signed-message verifiers (and any future
signed-aggregation type that accumulates votes from rotating-key
entities) through ``_public_key_at_height(entity_id, signed_at_
height)``.  The four call sites:
  * ``_validate_attestations``         -> uses att.block_number
  * ``_validate_finality_votes``       -> uses v.signed_at_height
  * ``_handle_announce_attestation``   -> uses att.block_number
  * ``_handle_announce_finality_vote`` -> uses v.signed_at_height
"""

from __future__ import annotations

import asyncio
import inspect
import unittest

from messagechain.consensus.attestation import (
    Attestation, create_attestation, verify_attestation,
)
from messagechain.consensus.finality import (
    FinalityVote, create_finality_vote, verify_finality_vote,
)
from messagechain.core.block import _hash
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


def _make_node(port: int, seed: bytes):
    from messagechain.network.node import Node
    entity = _entity(seed)
    return Node(entity, port=port, seed_nodes=[])


def _peer(addr: str = "10.50.3.1:9333"):
    from messagechain.network.peer import Peer
    host, _, port_s = addr.partition(":")
    return Peer(host=host, port=int(port_s), is_connected=True)


def _run(coro):
    return asyncio.run(coro)


def _install_rotated_state(chain: Blockchain, eid: bytes,
                           old_pk: bytes, new_pk: bytes,
                           old_installed_at: int,
                           new_installed_at: int) -> None:
    """Simulate that ``eid`` had ``old_pk`` from ``old_installed_at``
    through ``new_installed_at-1``, then rotated to ``new_pk`` at
    ``new_installed_at``.  Mutates chain state directly so the test
    does not have to drive a full key-rotation tx (the rotation
    apply path is well-covered by other tests; this test exercises
    SIG VERIFICATION discipline after a rotation has landed).
    """
    chain.public_keys[eid] = new_pk
    chain.key_history.setdefault(eid, [])
    chain.key_history[eid] = [
        (old_installed_at, old_pk),
        (new_installed_at, new_pk),
    ]


class TestVerifySignerAtHeightHelperExists(unittest.TestCase):
    """The fix is a single chokepoint helper on Blockchain.  Adding a
    new signed-aggregation verify call site that goes around the
    helper reintroduces the audit r50 #2 defect by definition."""

    def test_blockchain_exposes_verify_signer_at_height(self):
        self.assertTrue(
            hasattr(Blockchain, "_verify_signer_at_height"),
            "Blockchain must expose _verify_signer_at_height as the "
            "single chokepoint for signed-message verification on "
            "rotating-key entities (audit r50 #2).",
        )


class TestSignedMessageVerifiesAfterRotation(unittest.TestCase):
    """Behavioural: an attestation signed with K_old before a rotation
    must STILL verify on a chain that has rotated the signer to K_new,
    because the helper resolves the key by signed-at-height."""

    def test_attestation_signed_with_old_key_verifies_after_rotation(self):
        chain = Blockchain()
        # Two entities with distinct keypairs.  We'll keep entity_id
        # bound to old_signer.entity_id and "rotate" its key on chain
        # to new_signer.public_key.
        old_signer = _entity(b"r50_att_old")
        new_signer = _entity(b"r50_att_new")
        eid = old_signer.entity_id

        block_number = 5
        att = create_attestation(old_signer, _hash(b"r50_att_block"), block_number)

        _install_rotated_state(
            chain, eid,
            old_pk=old_signer.public_key,
            new_pk=new_signer.public_key,
            old_installed_at=0,
            new_installed_at=block_number + 1,
        )

        self.assertTrue(
            verify_attestation(att, old_signer.public_key),
            "Sanity: attestation must verify under the K_old it was signed with.",
        )
        self.assertFalse(
            verify_attestation(att, new_signer.public_key),
            "Sanity: attestation must NOT verify under K_new (the new key).",
        )
        self.assertTrue(
            chain._verify_signer_at_height(
                att, eid, block_number, verify_attestation,
            ),
            "_verify_signer_at_height MUST resolve K_old from signed-at "
            "height and accept the attestation -- this is the audit "
            "r50 #2 fix.",
        )

    def test_finality_vote_signed_with_old_key_verifies_after_rotation(self):
        chain = Blockchain()
        old_signer = _entity(b"r50_fv_old")
        new_signer = _entity(b"r50_fv_new")
        eid = old_signer.entity_id

        target_block_number = 4
        signed_at_height = 5
        vote = create_finality_vote(
            signer_entity=old_signer,
            target_block_hash=_hash(b"r50_fv_block"),
            target_block_number=target_block_number,
            signed_at_height=signed_at_height,
        )

        _install_rotated_state(
            chain, eid,
            old_pk=old_signer.public_key,
            new_pk=new_signer.public_key,
            old_installed_at=0,
            new_installed_at=signed_at_height + 1,
        )

        self.assertTrue(
            verify_finality_vote(vote, old_signer.public_key),
            "Sanity: vote must verify under the K_old it was signed with.",
        )
        self.assertFalse(
            verify_finality_vote(vote, new_signer.public_key),
            "Sanity: vote must NOT verify under K_new.",
        )
        self.assertTrue(
            chain._verify_signer_at_height(
                vote, eid, signed_at_height, verify_finality_vote,
            ),
            "_verify_signer_at_height MUST resolve K_old from signed-at "
            "height and accept the vote -- this is the audit r50 #2 fix.",
        )

    def test_helper_rejects_when_no_key_at_height(self):
        """Defensive: if no key was installed at signed-at-height
        (e.g., the entity had not yet registered), the helper must
        return False rather than raise -- callers must treat
        "missing key" as "invalid signature."""
        chain = Blockchain()
        signer = _entity(b"r50_no_key")
        att = create_attestation(signer, _hash(b"r50_no_key_block"), 5)
        # Note: chain has NEVER registered signer; no public_keys
        # entry, no key_history.
        self.assertFalse(
            chain._verify_signer_at_height(
                att, signer.entity_id, 5, verify_attestation,
            ),
            "Helper MUST return False when the entity had no key at "
            "the queried height.",
        )


class TestValidateAttestationsRoutesThroughHelper(unittest.TestCase):
    """Structural: the in-block attestation validator must route
    signature verification through the historical-key helper.  Adding
    a new validation site that reads ``self.public_keys[...]``
    directly reintroduces the defect."""

    def test_validate_attestations_source_resolves_signed_at_height(self):
        src = inspect.getsource(Blockchain._validate_attestations)
        self.assertNotIn(
            "verify_attestation(att, pk)",
            src.replace("_verify_signer_at_height", ""),
            "_validate_attestations must NOT call verify_attestation "
            "with self.public_keys[...] -- a rotated validator's "
            "in-flight attestation would silently fail validation "
            "under the new key.  Route through "
            "_verify_signer_at_height instead (audit r50 #2).",
        )
        self.assertIn(
            "_verify_signer_at_height", src,
            "_validate_attestations must route signature verification "
            "through Blockchain._verify_signer_at_height.",
        )


class TestValidateFinalityVotesRoutesThroughHelper(unittest.TestCase):
    """Structural: the in-block finality-vote validator must route
    signature verification through the historical-key helper."""

    def test_validate_finality_votes_source_resolves_signed_at_height(self):
        src = inspect.getsource(Blockchain._validate_finality_votes)
        self.assertNotIn(
            "verify_finality_vote(v, pk)",
            src.replace("_verify_signer_at_height", ""),
            "_validate_finality_votes must NOT call verify_finality_vote "
            "with self.public_keys[...] -- a rotated validator's "
            "in-flight vote silently fails validation under the new "
            "key, breaking the 1000-block FINALITY_VOTE_MAX_AGE_BLOCKS "
            "admission window (audit r50 #2).",
        )
        self.assertIn(
            "_verify_signer_at_height", src,
            "_validate_finality_votes must route signature verification "
            "through Blockchain._verify_signer_at_height with "
            "v.signed_at_height.",
        )


class TestGossipHandlersRouteThroughHelper(unittest.TestCase):
    """Structural: the two gossip-ingress handlers must also route
    through the helper.  Otherwise an honest validator's pre-rotation
    gossip votes silently fail under the new key, the relayer takes
    OFFENSE_INVALID_TX, and ban-cascades fragment the gossip mesh."""

    def _source(self, fn_name: str) -> str:
        from messagechain.network.node import Node
        return inspect.getsource(getattr(Node, fn_name))

    def test_handle_announce_attestation_routes_through_helper(self):
        src = self._source("_handle_announce_attestation")
        self.assertNotIn(
            "verify_attestation(att, pk)", src,
            "_handle_announce_attestation must not verify with the "
            "current key (pk = self.blockchain.public_keys[...]).  "
            "Route through Blockchain._verify_signer_at_height with "
            "att.block_number (audit r50 #2).",
        )
        self.assertIn(
            "_verify_signer_at_height", src,
            "_handle_announce_attestation must route through "
            "Blockchain._verify_signer_at_height.",
        )

    def test_handle_announce_finality_vote_routes_through_helper(self):
        src = self._source("_handle_announce_finality_vote")
        self.assertNotIn(
            "verify_finality_vote(vote, pk)", src,
            "_handle_announce_finality_vote must not verify with the "
            "current key.  Route through Blockchain._verify_signer_at_"
            "height with vote.signed_at_height (audit r50 #2).",
        )
        self.assertIn(
            "_verify_signer_at_height", src,
            "_handle_announce_finality_vote must route through "
            "Blockchain._verify_signer_at_height.",
        )


if __name__ == "__main__":
    unittest.main()
