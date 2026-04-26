"""Critical-severity audit fix -- round 10 (2026-04-26).

ONE CRITICAL: the governance branch of the
ANNOUNCE_PENDING_TX gossip handler in server.py admitted forged
ProposalTransaction / VoteTransaction / TreasurySpendTransaction
without verifying the signature.  An unauthenticated peer could
craft a tx with any registered entity's id as `proposer_id` /
`voter_id` and the validator would admit it to
`_pending_governance_txs` and rebroadcast.  When the validator
became proposer it packed the forged tx into its block;
`validate_block` then rejected the block at
`_validate_governance_tx_in_block` because the signature failed --
the proposer wasted its slot.  Sustained flood across rotated peers
prevents block production indefinitely on a 2-validator chain.

Compare with the sibling branches that all DO verify before
admitting:
  * stake -> verify_stake_transaction
  * unstake -> verify_unstake_transaction
  * authority -> validate_set_authority_key / validate_revoke /
    validate_key_rotation (each verifies internally)

Fix: in the governance branch, call the existing in-tree helper
`Blockchain._validate_governance_tx(tx)` (the same verifier
`_validate_governance_tx_in_block` already trusts) before
`_admit_to_pool`.  Mirrors the verify-before-admit pattern of the
sibling branches.
"""

from __future__ import annotations

import time
import unittest

from messagechain import config
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from messagechain.governance.governance import (
    ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
    create_proposal, create_vote,
)


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _FakePeer:
    host = "127.0.0.1"
    port = 9333
    address = "127.0.0.1:9333"
    is_connected = True
    writer = None


def _build_server():
    from server import Server
    return Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)


class TestGovernanceGossipVerifiesSignature(unittest.TestCase):
    """Regression: forged governance tx via ANNOUNCE_PENDING_TX MUST
    NOT be admitted to `_pending_governance_txs`."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(
            entity.entity_id, entity.public_key, proof,
        )

    def test_genuine_proposal_lands_in_pool(self):
        """Sanity: a properly-signed ProposalTransaction from the
        author still admits.  Guards against the new gate being too
        tight."""
        srv = _build_server()
        alice = _entity(b"r10-alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 1_000_000
        tx = create_proposal(
            alice,
            title="genuine",
            description="real proposal",
        )
        srv._handle_announce_pending_tx(
            {"kind": "governance", "tx": tx.serialize()},
            _FakePeer(),
        )
        self.assertIn(
            tx.tx_hash,
            getattr(srv, "_pending_governance_txs", {}),
            "Genuine proposal MUST land in the gov pool",
        )

    def test_forged_proposal_rejected(self):
        """Attacker crafts a ProposalTransaction with `proposer_id`
        pointing at a registered victim but signed with an attacker
        key -- the gossip handler MUST reject before admit.  Pre-fix
        this proposal landed in `_pending_governance_txs` and
        eventually wasted the victim's proposer slot when the block
        carrying it failed validation."""
        srv = _build_server()
        victim = _entity(b"r10-victim")
        attacker = _entity(b"r10-attacker")
        self._register(srv.blockchain, victim)
        srv.blockchain.supply.balances[victim.entity_id] = 1_000_000
        # Build a Proposal that CLAIMS to be from victim but is signed
        # by attacker.
        tx = ProposalTransaction(
            proposer_id=victim.entity_id,
            title="forged",
            description="attacker forged this",
            timestamp=int(time.time()),
            fee=1_000,
            signature=Signature([], 0, [], b"", b""),
            reference_hash=b"",
        )
        tx.signature = attacker.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        srv._handle_announce_pending_tx(
            {"kind": "governance", "tx": tx.serialize()},
            _FakePeer(),
        )
        self.assertNotIn(
            tx.tx_hash,
            getattr(srv, "_pending_governance_txs", {}),
            "Forged-signature ProposalTransaction MUST be rejected. "
            "Pre-fix it would land in the pool, the validator would "
            "later pack it into a block, and validate_block would "
            "reject the entire block -- silently wasting the "
            "proposer's slot.  Sustained attacker flood halts block "
            "production on a 2-validator chain.",
        )

    def test_forged_vote_rejected(self):
        """Same shape as the proposal test but on the VoteTransaction
        path.  Attacker forges a vote claiming to be from a victim
        staker."""
        srv = _build_server()
        victim = _entity(b"r10-vvictim")
        attacker = _entity(b"r10-vattacker")
        self._register(srv.blockchain, victim)
        srv.blockchain.supply.balances[victim.entity_id] = 1_000_000
        # Build a Vote forged with attacker's key but voter_id=victim.
        tx = VoteTransaction(
            voter_id=victim.entity_id,
            proposal_id=b"\x99" * 32,
            approve=True,
            timestamp=int(time.time()),
            fee=1_000,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = attacker.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        srv._handle_announce_pending_tx(
            {"kind": "governance", "tx": tx.serialize()},
            _FakePeer(),
        )
        self.assertNotIn(
            tx.tx_hash,
            getattr(srv, "_pending_governance_txs", {}),
            "Forged-signature VoteTransaction MUST be rejected.",
        )

    def test_forged_treasury_spend_rejected(self):
        """Same shape on the TreasurySpendTransaction path -- the
        most consequential of the three because a treasury-spend tx
        landing in a real block disburses funds."""
        srv = _build_server()
        victim = _entity(b"r10-tvictim")
        attacker = _entity(b"r10-tattacker")
        recipient = _entity(b"r10-trecipient")
        self._register(srv.blockchain, victim)
        srv.blockchain.supply.balances[victim.entity_id] = 1_000_000
        tx = TreasurySpendTransaction(
            proposer_id=victim.entity_id,
            recipient_id=recipient.entity_id,
            amount=1_000_000,
            title="forged-spend",
            description="attacker forged",
            timestamp=int(time.time()),
            fee=1_000,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = attacker.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        srv._handle_announce_pending_tx(
            {"kind": "governance", "tx": tx.serialize()},
            _FakePeer(),
        )
        self.assertNotIn(
            tx.tx_hash,
            getattr(srv, "_pending_governance_txs", {}),
            "Forged-signature TreasurySpendTransaction MUST be "
            "rejected.  Pre-fix this admit-then-reject-at-block path "
            "let an attacker waste proposer slots indefinitely.",
        )


if __name__ == "__main__":
    unittest.main()
