"""Two Round-11 follow-up fixes, one file:

Test A: InclusionListProcessor dedup key must include `list_hash`.
  A proposer who omits the same tx from two overlapping inclusion
  lists must be slashable TWICE — once per list.  Under the old
  (tx, proposer) key, the second evidence was silently rejected
  as a duplicate and the proposer escaped the second slash.

Test B: Regression — same-list same-tx same-proposer submitted
  twice is still a duplicate (no double-slash via resubmission).

Test C: _handle_announce_slash must record an OFFENSE_PROTOCOL_VIOLATION
  when validate_slash_transaction rejects the tx semantically (e.g.,
  offender has no stake).  Previously only deserialize-failure scored
  an offense; a peer could flood syntactically-valid but semantically-
  invalid slashes indefinitely without ban-score accrual.

Test D: Regression — a well-formed valid slash does NOT score the
  relayer (offense-on-error refactors must not catch honest gossip).
"""

import asyncio
import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO, MIN_FEE,
    INCLUSION_LIST_WAIT_BLOCKS, INCLUSION_LIST_WINDOW,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    InclusionListProcessor,
    InclusionListViolationEvidenceTx,
    build_attester_mempool_report,
    aggregate_inclusion_list,
    process_inclusion_list_violation,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_validators(n: int, tag: bytes = b"iv") -> list[Entity]:
    return [
        Entity.create((tag + b"-v" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _stakes(validators: list[Entity], per: int = 1_000_000) -> dict[bytes, int]:
    return {v.entity_id: per for v in validators}


def _sign_violation_evidence(
    submitter: Entity,
    inclusion_list: InclusionList,
    omitted_tx_hash: bytes,
    accused_proposer_id: bytes,
    accused_height: int,
    fee: int = MIN_FEE,
    timestamp: int | None = None,
) -> InclusionListViolationEvidenceTx:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    placeholder = Signature([], 0, [], b"", b"")
    tx = InclusionListViolationEvidenceTx(
        inclusion_list=inclusion_list,
        omitted_tx_hash=omitted_tx_hash,
        accused_proposer_id=accused_proposer_id,
        accused_height=accused_height,
        submitter_id=submitter.entity_id,
        timestamp=ts,
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


# ─────────────────────────────────────────────────────────────────────
# Tests A + B — inclusion-list dedup key includes list_hash
# ─────────────────────────────────────────────────────────────────────


class TestInclusionListViolationDedupKeyIncludesListHash(unittest.TestCase):
    """Dedup key is (list_hash, tx, proposer), NOT (tx, proposer).

    Two overlapping inclusion lists can both mandate the same tx; a
    proposer who omits that tx while BOTH are active has committed
    two violations, not one.  Each list gets its own slash.
    """

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.submitter = Entity.create(b"iv-dd-sub".ljust(32, b"\x00"))
        self.accused = Entity.create(b"iv-dd-acc".ljust(32, b"\x00"))
        self.submitter.keypair._next_leaf = 0
        self.accused.keypair._next_leaf = 0

        self.chain = Blockchain()
        self.chain.initialize_genesis(self.submitter)
        register_entity_for_test(self.chain, self.accused)
        self.chain.supply.balances[self.submitter.entity_id] = 1_000_000
        self.chain.supply.balances[self.accused.entity_id] = 1_000_000
        # Give the accused enough stake to survive two slashes.
        self.chain.supply.staked[self.accused.entity_id] = 10_000_000

    def _build_list(self, target_txs, publish_height, tag: bytes):
        """Two different tags → two inclusion lists with different
        list_hash (which includes publish_height + entries, but we
        also vary publish_height to guarantee distinctness)."""
        validators = _make_validators(3, b"iv-dd-" + tag)
        stakes = _stakes(validators)
        reports = [
            build_attester_mempool_report(
                v, report_height=publish_height - 1,
                tx_hashes=list(target_txs),
            )
            for v in validators
        ]
        return aggregate_inclusion_list(
            reports=reports, stakes=stakes,
            publish_height=publish_height,
        )

    def test_two_overlapping_lists_both_slash(self):
        """Test A: Two distinct lists, same tx, same proposer → both
        evidences admitted and both slashes applied."""
        tx_h = _h(b"dedup-hot-tx")
        lst_1 = self._build_list([tx_h], publish_height=11, tag=b"L1")
        lst_2 = self._build_list([tx_h], publish_height=12, tag=b"L2")
        self.assertNotEqual(
            lst_1.list_hash, lst_2.list_hash,
            "Two lists must have distinct list_hashes for this test.",
        )

        etx_1 = _sign_violation_evidence(
            self.submitter, lst_1, tx_h,
            self.accused.entity_id, accused_height=12,
        )
        etx_2 = _sign_violation_evidence(
            self.submitter, lst_2, tx_h,
            self.accused.entity_id, accused_height=13,
        )

        stake_before = self.chain.supply.staked[self.accused.entity_id]

        r1 = process_inclusion_list_violation(etx_1, self.chain)
        self.assertTrue(r1.accepted and r1.slashed, r1.reason)
        stake_mid = self.chain.supply.staked[self.accused.entity_id]
        self.assertLess(stake_mid, stake_before)

        # Under the buggy 2-tuple key this returns accepted=False;
        # with the correct 3-tuple key it slashes again.
        r2 = process_inclusion_list_violation(etx_2, self.chain)
        self.assertTrue(r2.accepted, r2.reason)
        self.assertTrue(r2.slashed, r2.reason)
        stake_after = self.chain.supply.staked[self.accused.entity_id]
        self.assertLess(
            stake_after, stake_mid,
            "Second evidence (different list) must slash again.",
        )

    def test_same_list_same_tx_same_proposer_dedups(self):
        """Test B (regression): resubmission of the same (list, tx,
        proposer) evidence is still a duplicate."""
        tx_h = _h(b"regression-tx")
        lst = self._build_list([tx_h], publish_height=11, tag=b"R")

        etx = _sign_violation_evidence(
            self.submitter, lst, tx_h,
            self.accused.entity_id, accused_height=12,
        )

        r1 = process_inclusion_list_violation(etx, self.chain)
        self.assertTrue(r1.accepted and r1.slashed)
        stake_mid = self.chain.supply.staked[self.accused.entity_id]

        r2 = process_inclusion_list_violation(etx, self.chain)
        self.assertFalse(r2.accepted, "Second identical evidence must dedupe.")
        self.assertFalse(r2.slashed)
        self.assertEqual(
            self.chain.supply.staked[self.accused.entity_id], stake_mid,
            "Dedup must prevent a second slash on the same (list, tx, proposer).",
        )


# ─────────────────────────────────────────────────────────────────────
# Tests C + D — _handle_announce_slash offense on validation failure
# ─────────────────────────────────────────────────────────────────────


def _make_node(port: int, seed: bytes):
    # Lazy import — node.py binds REQUIRE_CHECKPOINTS at import time.
    from messagechain.network.node import Node
    entity = Entity.create(seed.ljust(32, b"\x00"))
    return Node(entity, port=port, seed_nodes=[])


def _peer(addr: str):
    from messagechain.network.peer import Peer
    host, _, port_s = addr.partition(":")
    return Peer(host=host, port=int(port_s), is_connected=True)


def _run(coro):
    return asyncio.run(coro)


class TestAnnounceSlashOffenseOnValidationFailure(unittest.TestCase):
    """_handle_announce_slash must score OFFENSE_PROTOCOL_VIOLATION when
    validate_slash_transaction rejects the tx semantically.  Previously
    only deserialize-failure scored — a flooding peer sending well-
    formed but semantically-invalid slashes paid zero ban score."""

    def _make_valid_slash_tx_against_unstaked_offender(self, node):
        """Build a syntactically-valid SlashTransaction whose offender
        has zero stake → validate_slash_transaction returns
        (False, 'Offender has no stake to slash').  The tx itself is
        well-formed: real submitter signature, real evidence signatures.

        Uses AttestationSlashingEvidence (double-attestation) because
        it's the simplest "two conflicting signed objects from the same
        validator at the same height" shape to construct.
        """
        from messagechain.consensus.slashing import (
            AttestationSlashingEvidence, create_slash_transaction,
        )
        from messagechain.consensus.attestation import create_attestation

        # Submitter must be a registered entity with a balance so the
        # validation path gets past the "Unknown submitter" + fee checks.
        submitter = Entity.create(b"sl-sub".ljust(32, b"\x00"))
        submitter.keypair._next_leaf = 0
        register_entity_for_test(node.blockchain, submitter)
        node.blockchain.supply.balances[submitter.entity_id] = 10_000_000

        # Offender must be a registered entity too (otherwise validation
        # bails on "Unknown offender" which is a different code path —
        # still semantically invalid but we want to hit the
        # "no stake to slash" branch on the common path).
        offender = Entity.create(b"sl-off".ljust(32, b"\x00"))
        offender.keypair._next_leaf = 0
        register_entity_for_test(node.blockchain, offender)
        # Deliberately: do NOT stake the offender.

        # Two attestations for DIFFERENT blocks at the SAME height =
        # valid double-attestation evidence.  Current chain height is
        # 0 post-genesis; use height 5 which is future but the
        # "no stake" gate triggers before the evidence-height gate.
        att_a = create_attestation(offender, _h(b"sl-blk-a"), block_number=5)
        att_b = create_attestation(offender, _h(b"sl-blk-b"), block_number=5)
        evidence = AttestationSlashingEvidence(
            offender_id=offender.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )
        slash_tx = create_slash_transaction(
            submitter_entity=submitter, evidence=evidence, fee=MIN_FEE,
        )
        return slash_tx

    def test_semantically_invalid_slash_scores_peer(self):
        """Test C: well-formed slash tx that fails semantic validation
        must score the relayer OFFENSE_PROTOCOL_VIOLATION."""
        node = _make_node(port=19801, seed=b"sl_invalid")
        peer = _peer("10.9.5.1:9333")

        slash_tx = self._make_valid_slash_tx_against_unstaked_offender(node)

        # Sanity: validation really does reject this tx.
        ok, reason = node.blockchain.validate_slash_transaction(slash_tx)
        self.assertFalse(
            ok,
            "Test setup: slash against unstaked offender must "
            "fail validation",
        )

        score_before = node.ban_manager.get_score(peer.address)
        _run(node._handle_announce_slash(slash_tx.serialize(), peer))
        score_after = node.ban_manager.get_score(peer.address)

        self.assertGreater(
            score_after, score_before,
            "Semantic validation failure must score the peer — otherwise "
            "flooding valid-but-invalid slashes pays zero ban score.",
        )

    def test_valid_slash_does_not_score_relayer(self):
        """Test D: regression — a well-formed, semantically-valid slash
        must NOT score the relayer."""
        from messagechain.consensus.slashing import (
            AttestationSlashingEvidence, create_slash_transaction,
        )
        from messagechain.consensus.attestation import create_attestation

        node = _make_node(port=19802, seed=b"sl_valid")
        peer = _peer("10.9.5.2:9333")

        submitter = Entity.create(b"sl-sub-good".ljust(32, b"\x00"))
        submitter.keypair._next_leaf = 0
        register_entity_for_test(node.blockchain, submitter)
        node.blockchain.supply.balances[submitter.entity_id] = 10_000_000

        offender = Entity.create(b"sl-off-good".ljust(32, b"\x00"))
        offender.keypair._next_leaf = 0
        register_entity_for_test(node.blockchain, offender)
        node.blockchain.supply.staked[offender.entity_id] = 1_000_000

        # Use block_number near current chain height to survive the
        # evidence-age gate.
        blk_num = max(1, node.blockchain.height)
        att_a = create_attestation(offender, _h(b"sl-good-a"), block_number=blk_num)
        att_b = create_attestation(offender, _h(b"sl-good-b"), block_number=blk_num)
        evidence = AttestationSlashingEvidence(
            offender_id=offender.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )
        slash_tx = create_slash_transaction(
            submitter_entity=submitter, evidence=evidence, fee=MIN_FEE,
        )

        ok, reason = node.blockchain.validate_slash_transaction(slash_tx)
        # If validation fails for an unrelated reason, this test is
        # degenerate — skip rather than falsely pass.
        if not ok:
            self.skipTest(
                f"Test setup couldn't produce a valid slash "
                f"(validation said: {reason})"
            )

        score_before = node.ban_manager.get_score(peer.address)
        _run(node._handle_announce_slash(slash_tx.serialize(), peer))
        score_after = node.ban_manager.get_score(peer.address)

        self.assertEqual(
            score_after, score_before,
            "Valid slash must NOT score the relayer.",
        )


if __name__ == "__main__":
    unittest.main()
