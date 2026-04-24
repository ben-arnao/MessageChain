"""R5-A: Signature-byte fee parity across every tx type post-activation.

Pre-fix, only MessageTransaction enforced the
``FEE_INCLUDES_SIGNATURE_HEIGHT`` rule (fee must cover message +
signature bytes).  Every other tx type (transfer, stake, unstake,
governance, authority, revoke, key-rotation, receipt-subtree-root,
slash) charged a flat minimum regardless of witness size, letting an
attacker flood permanent chain state with ~2.7 KB WOTS+ signatures
at MIN_FEE per tx.

Post-fix, every verifier that applies a flat fee floor ALSO applies
``calculate_min_fee(b"", signature_bytes=sig_len)`` at/after the
activation height — so fee must cover ``max(existing_flat_floor,
signature-aware min)``.  Below the activation height the legacy flat
floor alone still applies (preserves historical-block validity).
"""

import unittest

from messagechain.config import (
    FEE_INCLUDES_SIGNATURE_HEIGHT,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    KEY_ROTATION_FEE,
    MIN_FEE,
)
from messagechain.consensus.slashing import (
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
    verify_set_authority_key_transaction,
)
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.emergency_revoke import (
    create_revoke_transaction,
    verify_revoke_transaction,
)
from messagechain.core.key_rotation import (
    create_key_rotation,
    derive_rotated_keypair,
    verify_key_rotation,
)
from messagechain.core.receipt_subtree_root import (
    create_set_receipt_subtree_root_transaction,
    verify_set_receipt_subtree_root_transaction,
)
from messagechain.core.staking import (
    create_stake_transaction,
    create_unstake_transaction,
    verify_stake_transaction,
    verify_unstake_transaction,
)
from messagechain.core.transaction import (
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.core.transfer import (
    create_transfer_transaction,
    verify_transfer_transaction,
)
from messagechain.crypto.keys import verify_signature
from messagechain.governance.governance import (
    create_proposal,
    create_treasury_spend_proposal,
    create_vote,
    verify_proposal,
    verify_treasury_spend,
    verify_vote,
)
from messagechain.identity.identity import Entity


POST = FEE_INCLUDES_SIGNATURE_HEIGHT
PRE = FEE_INCLUDES_SIGNATURE_HEIGHT - 1


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _required_post_activation(flat_floor: int, sig_len: int) -> int:
    """Post-activation floor = max(existing flat floor, sig-aware min)."""
    return max(flat_floor, calculate_min_fee(b"", signature_bytes=sig_len))


class TestMessageTxRegression(unittest.TestCase):
    """MessageTransaction must continue to behave per the existing rule."""

    def setUp(self):
        self.alice = _entity(b"msg-regress")
        self.pk = self.alice.public_key

    def test_pre_activation_message_only_fee_passes(self):
        tx = create_transaction(self.alice, "hi", fee=calculate_min_fee(b"hi"), nonce=0)
        self.assertTrue(verify_transaction(tx, self.pk, current_height=PRE))

    # test_post_activation_sig_aware_fee_passes retired: previously
    # asserted that MessageTx at POST=FEE_INCLUDES_SIGNATURE_HEIGHT
    # rejects a message-only fee under sig-aware-quadratic.  In the
    # bootstrap-compressed schedule, LINEAR_FEE_HEIGHT (4,300) precedes
    # FEE_INCLUDES_SIGNATURE_HEIGHT (64,000), so linear pricing is
    # already active at POST and ignores signature bytes.  The
    # sig-aware-quadratic window is unreachable in the production
    # schedule for MessageTx.  Non-MessageTx tx types (transfer, stake,
    # etc.) still exercise the sig-aware path via
    # ``enforce_signature_aware_min_fee`` — those regressions live in
    # the classes below this one.


class TestTransferFeeParity(unittest.TestCase):
    def setUp(self):
        self.alice = _entity(b"xfer-parity-a")
        self.bob = _entity(b"xfer-parity-b")
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_transfer_transaction(
            self.alice, self.bob.entity_id, amount=1000, nonce=0, fee=fee,
        )

    def test_pre_activation_flat_minfee_passes(self):
        tx = self._mk(MIN_FEE)
        self.assertTrue(verify_transfer_transaction(tx, self.pk, current_height=PRE))

    def test_post_activation_flat_minfee_fails(self):
        tx = self._mk(MIN_FEE)
        self.assertFalse(verify_transfer_transaction(tx, self.pk, current_height=POST))

    def test_post_activation_sig_aware_fee_passes(self):
        # Fund the fee at the new required level.
        probe = self._mk(MIN_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(MIN_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(verify_transfer_transaction(tx, self.pk, current_height=POST))

    def test_no_height_falls_back_to_legacy(self):
        tx = self._mk(MIN_FEE)
        self.assertTrue(verify_transfer_transaction(tx, self.pk))


class TestStakeFeeParity(unittest.TestCase):
    def setUp(self):
        self.alice = _entity(b"stake-parity")
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_stake_transaction(
            self.alice, amount=10_000_000, nonce=0, fee=fee,
        )

    def test_pre_activation_flat_minfee_passes(self):
        tx = self._mk(MIN_FEE)
        self.assertTrue(
            verify_stake_transaction(
                tx, self.pk, min_stake_override=1, current_height=PRE,
            )
        )

    def test_post_activation_flat_minfee_fails(self):
        tx = self._mk(MIN_FEE)
        self.assertFalse(
            verify_stake_transaction(
                tx, self.pk, min_stake_override=1, current_height=POST,
            )
        )

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(MIN_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(MIN_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(
            verify_stake_transaction(
                tx, self.pk, min_stake_override=1, current_height=POST,
            )
        )


class TestUnstakeFeeParity(unittest.TestCase):
    def setUp(self):
        self.alice = _entity(b"unstake-parity")
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_unstake_transaction(
            self.alice, amount=1000, nonce=0, fee=fee,
        )

    def test_pre_activation_flat_minfee_passes(self):
        tx = self._mk(MIN_FEE)
        self.assertTrue(
            verify_unstake_transaction(tx, self.pk, current_height=PRE)
        )

    def test_post_activation_flat_minfee_fails(self):
        tx = self._mk(MIN_FEE)
        self.assertFalse(
            verify_unstake_transaction(tx, self.pk, current_height=POST)
        )

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(MIN_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(MIN_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(
            verify_unstake_transaction(tx, self.pk, current_height=POST)
        )


class TestSetAuthorityKeyFeeParity(unittest.TestCase):
    def setUp(self):
        self.alice = _entity(b"auth-parity")
        self.new_auth = b"\xAB" * 32
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_set_authority_key_transaction(
            self.alice, self.new_auth, nonce=0, fee=fee,
        )

    def test_pre_activation_flat_minfee_passes(self):
        tx = self._mk(MIN_FEE)
        self.assertTrue(
            verify_set_authority_key_transaction(tx, self.pk, current_height=PRE)
        )

    def test_post_activation_flat_minfee_fails(self):
        tx = self._mk(MIN_FEE)
        self.assertFalse(
            verify_set_authority_key_transaction(tx, self.pk, current_height=POST)
        )

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(MIN_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(MIN_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(
            verify_set_authority_key_transaction(tx, self.pk, current_height=POST)
        )


class TestRevokeFeeParity(unittest.TestCase):
    def setUp(self):
        self.alice = _entity(b"revoke-parity")
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_revoke_transaction(self.alice, fee=fee)

    def test_pre_activation_flat_minfee_passes(self):
        tx = self._mk(MIN_FEE)
        self.assertTrue(verify_revoke_transaction(tx, self.pk, current_height=PRE))

    def test_post_activation_flat_minfee_fails(self):
        tx = self._mk(MIN_FEE)
        self.assertFalse(verify_revoke_transaction(tx, self.pk, current_height=POST))

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(MIN_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(MIN_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(verify_revoke_transaction(tx, self.pk, current_height=POST))


class TestKeyRotationFeeParity(unittest.TestCase):
    """Key rotation keeps KEY_ROTATION_FEE as an absolute floor."""

    def setUp(self):
        self.alice = _entity(b"rot-parity")
        self.new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_key_rotation(self.alice, self.new_kp, rotation_number=0, fee=fee)

    def test_pre_activation_flat_fee_passes(self):
        tx = self._mk(KEY_ROTATION_FEE)
        self.assertTrue(verify_key_rotation(tx, self.pk, current_height=PRE))

    def test_post_activation_flat_fee_may_be_insufficient(self):
        """KEY_ROTATION_FEE < sig-aware min, so flat floor alone must fail."""
        tx = self._mk(KEY_ROTATION_FEE)
        sig_len = len(tx.signature.to_bytes())
        sig_min = calculate_min_fee(b"", signature_bytes=sig_len)
        # Only assert failure if the sig-aware min actually exceeds the flat floor;
        # on very small WOTS+ trees it might not. In practice with default tree
        # height sig bytes >> KEY_ROTATION_FEE bump, so this branch is the real case.
        if sig_min > KEY_ROTATION_FEE:
            self.assertFalse(verify_key_rotation(tx, self.pk, current_height=POST))
        else:
            self.assertTrue(verify_key_rotation(tx, self.pk, current_height=POST))

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(KEY_ROTATION_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(KEY_ROTATION_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(verify_key_rotation(tx, self.pk, current_height=POST))

    def test_post_activation_preserves_key_rotation_floor(self):
        """fee below KEY_ROTATION_FEE must fail pre- AND post-activation."""
        tx = self._mk(KEY_ROTATION_FEE - 1)
        self.assertFalse(verify_key_rotation(tx, self.pk, current_height=PRE))
        self.assertFalse(verify_key_rotation(tx, self.pk, current_height=POST))


class TestSetReceiptSubtreeRootFeeParity(unittest.TestCase):
    def setUp(self):
        self.authority = _entity(b"receipt-auth")
        self.entity_id = b"\xC1" * 32
        self.root_pk = b"\xD2" * 32
        self.pk = self.authority.public_key

    def _mk(self, fee: int):
        self.authority.keypair._next_leaf = 0
        return create_set_receipt_subtree_root_transaction(
            entity_id=self.entity_id,
            root_public_key=self.root_pk,
            authority_signer=self.authority,
            fee=fee,
        )

    def test_pre_activation_flat_minfee_passes(self):
        tx = self._mk(MIN_FEE)
        self.assertTrue(
            verify_set_receipt_subtree_root_transaction(tx, self.pk, current_height=PRE)
        )

    def test_post_activation_flat_minfee_fails(self):
        tx = self._mk(MIN_FEE)
        self.assertFalse(
            verify_set_receipt_subtree_root_transaction(tx, self.pk, current_height=POST)
        )

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(MIN_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(MIN_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(
            verify_set_receipt_subtree_root_transaction(tx, self.pk, current_height=POST)
        )


class TestProposalFeeParity(unittest.TestCase):
    """Governance proposal preserves GOVERNANCE_PROPOSAL_FEE floor."""

    def setUp(self):
        self.alice = _entity(b"prop-parity")
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_proposal(
            self.alice, title="t", description="d", fee=fee,
        )

    def test_pre_activation_flat_fee_passes(self):
        tx = self._mk(GOVERNANCE_PROPOSAL_FEE)
        self.assertTrue(verify_proposal(tx, self.pk, current_height=PRE))

    def test_post_activation_flat_fee_may_be_insufficient(self):
        tx = self._mk(GOVERNANCE_PROPOSAL_FEE)
        sig_len = len(tx.signature.to_bytes())
        sig_min = calculate_min_fee(b"", signature_bytes=sig_len)
        if sig_min > GOVERNANCE_PROPOSAL_FEE:
            self.assertFalse(verify_proposal(tx, self.pk, current_height=POST))
        else:
            self.assertTrue(verify_proposal(tx, self.pk, current_height=POST))

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(GOVERNANCE_PROPOSAL_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(GOVERNANCE_PROPOSAL_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(verify_proposal(tx, self.pk, current_height=POST))

    def test_governance_floor_preserved(self):
        tx = self._mk(GOVERNANCE_PROPOSAL_FEE - 1)
        self.assertFalse(verify_proposal(tx, self.pk, current_height=PRE))
        self.assertFalse(verify_proposal(tx, self.pk, current_height=POST))


class TestVoteFeeParity(unittest.TestCase):
    """Governance vote preserves GOVERNANCE_VOTE_FEE floor."""

    def setUp(self):
        self.alice = _entity(b"vote-parity")
        self.pk = self.alice.public_key
        self.proposal_id = b"\x7A" * 32

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_vote(
            self.alice, proposal_id=self.proposal_id, approve=True, fee=fee,
        )

    def test_pre_activation_flat_fee_passes(self):
        tx = self._mk(GOVERNANCE_VOTE_FEE)
        self.assertTrue(verify_vote(tx, self.pk, current_height=PRE))

    def test_post_activation_flat_fee_fails(self):
        tx = self._mk(GOVERNANCE_VOTE_FEE)
        # GOVERNANCE_VOTE_FEE is only 100 so sig-aware min should clearly exceed it.
        self.assertFalse(verify_vote(tx, self.pk, current_height=POST))

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(GOVERNANCE_VOTE_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(GOVERNANCE_VOTE_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(verify_vote(tx, self.pk, current_height=POST))

    def test_vote_floor_preserved(self):
        tx = self._mk(GOVERNANCE_VOTE_FEE - 1)
        self.assertFalse(verify_vote(tx, self.pk, current_height=PRE))
        self.assertFalse(verify_vote(tx, self.pk, current_height=POST))


class TestTreasurySpendFeeParity(unittest.TestCase):
    """Treasury spend preserves GOVERNANCE_PROPOSAL_FEE floor."""

    def setUp(self):
        self.alice = _entity(b"tsp-parity")
        self.pk = self.alice.public_key

    def _mk(self, fee: int):
        self.alice.keypair._next_leaf = 0
        return create_treasury_spend_proposal(
            self.alice,
            recipient_id=b"\x42" * 32,
            amount=1000,
            title="t",
            description="d",
            fee=fee,
        )

    def test_pre_activation_flat_fee_passes(self):
        tx = self._mk(GOVERNANCE_PROPOSAL_FEE)
        self.assertTrue(verify_treasury_spend(tx, self.pk, current_height=PRE))

    def test_post_activation_sig_aware_fee_passes(self):
        probe = self._mk(GOVERNANCE_PROPOSAL_FEE)
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(GOVERNANCE_PROPOSAL_FEE, sig_len)
        tx = self._mk(required)
        self.assertTrue(verify_treasury_spend(tx, self.pk, current_height=POST))

    def test_treasury_floor_preserved(self):
        tx = self._mk(GOVERNANCE_PROPOSAL_FEE - 1)
        self.assertFalse(verify_treasury_spend(tx, self.pk, current_height=PRE))
        self.assertFalse(verify_treasury_spend(tx, self.pk, current_height=POST))


class TestSlashFeeParity(unittest.TestCase):
    """Slash tx fee-gated via validate_slash_transaction on blockchain."""

    def _conflicting_headers(self, entity, block_number: int = 1):
        import time as _time
        header_a = BlockHeader(
            version=1,
            block_number=block_number,
            prev_hash=b"\x00" * 32,
            merkle_root=_hash(b"a"),
            timestamp=_time.time(),
            proposer_id=entity.entity_id,
        )
        header_a.proposer_signature = entity.keypair.sign(_hash(header_a.signable_data()))
        header_b = BlockHeader(
            version=1,
            block_number=block_number,
            prev_hash=b"\x00" * 32,
            merkle_root=_hash(b"b"),
            timestamp=_time.time() + 1,
            proposer_id=entity.entity_id,
        )
        header_b.proposer_signature = entity.keypair.sign(_hash(header_b.signable_data()))
        return header_a, header_b

    def _setup_chain(self):
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        offender = _entity(b"slash-offender")
        submitter = _entity(b"slash-submitter")
        bc.public_keys[offender.entity_id] = offender.public_key
        bc.public_keys[submitter.entity_id] = submitter.public_key
        bc.supply.balances[submitter.entity_id] = 10_000_000
        bc.supply.staked[offender.entity_id] = 10_000_000
        return bc, offender, submitter

    def _make_slash(self, submitter, offender, fee, evidence_block_number: int = 1):
        submitter.keypair._next_leaf = 0
        header_a, header_b = self._conflicting_headers(
            offender, block_number=evidence_block_number,
        )
        evidence = SlashingEvidence(
            offender_id=offender.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        return create_slash_transaction(submitter, evidence, fee=fee)

    def test_post_activation_flat_minfee_fails(self):
        bc, offender, submitter = self._setup_chain()
        slash_tx = self._make_slash(
            submitter, offender, fee=MIN_FEE, evidence_block_number=POST,
        )
        ok, _ = bc.validate_slash_transaction(slash_tx, chain_height=POST)
        self.assertFalse(ok)

    def test_post_activation_sig_aware_fee_passes(self):
        bc, offender, submitter = self._setup_chain()
        probe = self._make_slash(
            submitter, offender, fee=MIN_FEE, evidence_block_number=POST,
        )
        sig_len = len(probe.signature.to_bytes())
        required = _required_post_activation(MIN_FEE, sig_len)
        # Rebuild with the funded fee (fresh leaf index).
        slash_tx = self._make_slash(
            submitter, offender, fee=required, evidence_block_number=POST,
        )
        ok, reason = bc.validate_slash_transaction(slash_tx, chain_height=POST)
        self.assertTrue(ok, reason)

    def test_pre_activation_flat_minfee_passes(self):
        bc, offender, submitter = self._setup_chain()
        slash_tx = self._make_slash(
            submitter, offender, fee=MIN_FEE, evidence_block_number=PRE,
        )
        ok, reason = bc.validate_slash_transaction(slash_tx, chain_height=PRE)
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
