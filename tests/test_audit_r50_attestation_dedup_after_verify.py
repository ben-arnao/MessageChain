"""Audit r50 #1 -- attestation gossip dedup is poisoned BEFORE signature
verification, silently suppressing honest finality.

``_handle_announce_attestation`` inserted the dedup key into
``_seen_attestations`` BEFORE running ``verify_attestation``.  A peer
that pre-relays a forged-signature attestation with the right
``(validator_id, block_number, block_hash)`` triple -- all three
components are publicly predictable from chain state -- poisons the
LRU; the genuine, correctly-signed attestation arriving later
short-circuits at dedup and never reaches the FinalityTracker or the
relay broadcast.

CLAUDE.md adversary anchor: validator collusion (primary).  A peer
can deterministically suppress any honest validator's attestations
from the local finality view AND from onward gossip, stalling
finality without producing any slashable evidence.  The collective-
decision-censorship anchor calls out exactly this -- "any deviation
from pure inclusion requires a coordinated majority *and* willing to
absorb slashable risk."  A gossip-layer dedup poison sidesteps the
slashable surface entirely.

Abstraction-over-symptom: ``_seen`` must mean "seen-AFTER-verify".
The insert must come below the ``verify_attestation`` call so a
failed verify never marks the key.  The same rule applies to every
present and future signed-gossip handler that uses an explicit
dedup cache; the attestation handler is the only one today, but the
discipline must be load-bearing for new handlers.
"""

from __future__ import annotations

import asyncio
import unittest

from messagechain.consensus.attestation import (
    Attestation,
    create_attestation,
)
from messagechain.core.block import _hash
from messagechain.crypto.keys import Signature


def _make_node(port: int, seed: bytes):
    from messagechain.identity.identity import Entity
    from messagechain.network.node import Node
    entity = Entity.create(seed.ljust(32, b"\x00"))
    return Node(entity, port=port, seed_nodes=[])


def _peer(addr: str = "10.50.1.1:9333"):
    from messagechain.network.peer import Peer
    host, _, port_s = addr.partition(":")
    return Peer(host=host, port=int(port_s), is_connected=True)


def _run(coro):
    return asyncio.run(coro)


def _forge_bad_signature(good_sig: Signature) -> Signature:
    """Return a Signature object with the same metadata but a body
    that won't verify -- flip every byte of every WOTS+ chain so the
    derived public key doesn't match."""
    bad_chains = [bytes(b ^ 0xFF for b in s) for s in good_sig.wots_signature]
    return Signature(
        wots_signature=bad_chains,
        leaf_index=good_sig.leaf_index,
        auth_path=list(good_sig.auth_path),
        wots_public_key=good_sig.wots_public_key,
        wots_public_seed=good_sig.wots_public_seed,
        sig_version=good_sig.sig_version,
    )


class TestForgedAttestationDoesNotPoisonDedup(unittest.TestCase):
    """Behavioural: a forged-sig attestation that fails verification
    must NOT populate the ``_seen_attestations`` LRU.  Otherwise the
    genuine attestation arriving later short-circuits at dedup and
    silently disappears from this node's finality view and onward
    gossip.
    """

    def test_forged_sig_attestation_leaves_dedup_empty(self):
        from tests import register_entity_for_test
        from messagechain.identity.identity import Entity

        node = _make_node(port=19850, seed=b"r50_dedup_a")
        relayer = _peer("10.50.2.1:9333")

        validator = Entity.create(b"r50_attester_a".ljust(32, b"\x00"))
        register_entity_for_test(node.blockchain, validator)

        block_hash = _hash(b"r50_block_a")
        good_att = create_attestation(validator, block_hash, block_number=1)
        bad_att = Attestation(
            validator_id=good_att.validator_id,
            block_hash=good_att.block_hash,
            block_number=good_att.block_number,
            signature=_forge_bad_signature(good_att.signature),
        )

        _run(node._handle_announce_attestation(bad_att.serialize(), relayer))

        att_key = (bad_att.validator_id, bad_att.block_number, bad_att.block_hash)
        seen = getattr(node, "_seen_attestations", {})
        self.assertNotIn(
            att_key, seen,
            "Forged-sig attestation must NOT populate _seen_attestations -- "
            "doing so silently short-circuits the genuine attestation that "
            "arrives later (audit r50 #1).",
        )

    def test_genuine_attestation_reaches_relay_after_forged_attempt(self):
        """End-to-end: poison with a forged attestation first, then the
        genuine one with the same triple must still process and be
        relayed (not short-circuit at dedup)."""
        from tests import register_entity_for_test
        from messagechain.identity.identity import Entity

        node = _make_node(port=19851, seed=b"r50_dedup_b")
        relayer = _peer("10.50.2.2:9333")
        relayer2 = _peer("10.50.2.3:9333")

        validator = Entity.create(b"r50_attester_b".ljust(32, b"\x00"))
        register_entity_for_test(node.blockchain, validator)

        block_hash = _hash(b"r50_block_b")
        good_att = create_attestation(validator, block_hash, block_number=1)
        bad_att = Attestation(
            validator_id=good_att.validator_id,
            block_hash=good_att.block_hash,
            block_number=good_att.block_number,
            signature=_forge_bad_signature(good_att.signature),
        )

        broadcasts: list = []

        async def _record_broadcast(msg, exclude=None):
            broadcasts.append((msg.msg_type, exclude))

        node._broadcast = _record_broadcast  # type: ignore[assignment]

        _run(node._handle_announce_attestation(bad_att.serialize(), relayer))
        self.assertEqual(
            len(broadcasts), 0,
            "Forged attestation must not be relayed.",
        )

        _run(node._handle_announce_attestation(good_att.serialize(), relayer2))
        self.assertEqual(
            len(broadcasts), 1,
            "Genuine attestation arriving after a forged-sig poisoning "
            "attempt MUST still be relayed -- the dedup cache was "
            "poisoned by audit r50 #1.",
        )


class TestDedupInsertHappensAfterVerify(unittest.TestCase):
    """Structural guard: the source of ``_handle_announce_attestation``
    must place the ``_seen_attestations`` insert AFTER the
    ``verify_attestation`` call.  This locks the abstraction in place
    so a future refactor can't silently re-introduce the defect, and
    documents the discipline ("seen = seen-after-verify") for new
    signed-gossip handlers.
    """

    def _source(self) -> str:
        import inspect
        from messagechain.network.node import Node
        return inspect.getsource(Node._handle_announce_attestation)

    def _verify_call_idx(self, src: str) -> int:
        """Return the index of the signature-verify call in the handler
        source.  Accepts either the direct ``verify_attestation(`` call
        OR the audit r50 #2 historical-key chokepoint
        ``_verify_signer_at_height(`` -- both are valid verify sites
        and either may live in the handler at any given commit."""
        candidates = [
            src.find("_verify_signer_at_height("),
            src.find("verify_attestation("),
        ]
        present = [i for i in candidates if i >= 0]
        return min(present) if present else -1

    def test_verify_appears_before_dedup_insert(self):
        src = self._source()
        verify_idx = self._verify_call_idx(src)
        insert_idx = src.find("_seen_attestations[att_key]")
        self.assertGreater(
            verify_idx, 0,
            "_handle_announce_attestation must call a signature-verify "
            "primitive (verify_attestation or _verify_signer_at_height).",
        )
        self.assertGreater(
            insert_idx, 0,
            "_handle_announce_attestation must populate _seen_attestations "
            "via an assignment to _seen_attestations[att_key].",
        )
        self.assertLess(
            verify_idx, insert_idx,
            "Signature verification must execute BEFORE the "
            "_seen_attestations[att_key] insert -- otherwise a forged-sig "
            "attestation poisons the dedup cache and silently suppresses "
            "honest finality (audit r50 #1).  'Seen' must mean "
            "'seen-after-verify'; the same discipline applies to every "
            "future signed-gossip handler that maintains an explicit "
            "dedup cache.",
        )

    def test_dedup_membership_check_precedes_verify(self):
        """The dedup membership check (the early-return short-circuit)
        is allowed to run BEFORE verify -- that's the whole point of
        having a cache (skip expensive verify on already-seen entries).
        What's not allowed is to INSERT into the cache before verify.

        This test pins the ordering: ``att_key in self._seen_attestations``
        check appears before the verify call (cheap dedup gate runs
        first), AND the INSERT appears after verify.
        """
        src = self._source()
        membership_idx = src.find("att_key in self._seen_attestations")
        verify_idx = self._verify_call_idx(src)
        insert_idx = src.find("_seen_attestations[att_key]")
        self.assertLess(
            membership_idx, verify_idx,
            "dedup membership check should run BEFORE verify (cheap gate "
            "skips expensive verification of already-seen entries).",
        )
        self.assertLess(
            verify_idx, insert_idx,
            "but the dedup INSERT must run AFTER verify.",
        )


if __name__ == "__main__":
    unittest.main()
