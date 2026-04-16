"""
Tests for entity-index bloat reduction.

Every transaction carries a 32-byte entity_id. Once registered, an
entity can be referenced by a monotonic index (varint, 1-5 bytes).
This saves ~29 bytes per tx forever on a permanent-history chain.

Covers:
    * LEB128 varint encode/decode edge cases (1, 127, 128, 16383,
      16384, 2097151, 2097152, u32 max) with byte-count assertions.
    * Registration assigns monotonic indices starting at 1;
      duplicate registration is rejected (already enforced).
    * Bidirectional entity_id ↔ entity_index maps survive a chain
      restart (persist through ChainDB).
    * MessageTransaction, TransferTransaction, StakeTransaction,
      and friends: to_bytes(state) uses the varint index, from_bytes
      (with state) resolves back to the full entity_id.
    * Critical consensus invariant: _signable_data() still commits
      to the full 32-byte entity_id, so tx_hash is stable regardless
      of the wire encoding.
    * Unknown entity_index at validate time is rejected.
    * Typical MessageTransaction shrinks by ~29 bytes when encoded
      with the varint form vs the legacy 32-byte form.
"""

import os
import tempfile
import unittest

from messagechain.core.varint import (
    decode_varint, encode_varint, varint_size,
)


class TestVarint(unittest.TestCase):
    def test_roundtrip_edge_values(self):
        """Round-trip every size class (boundary values for 1..5 bytes)."""
        for value in (0, 1, 127, 128, 16383, 16384, 2097151, 2097152,
                      268435455, 268435456, 2**32 - 1, 2**32, 2**63 - 1):
            blob = encode_varint(value)
            decoded, n = decode_varint(blob)
            self.assertEqual(decoded, value, f"roundtrip failed for {value}")
            self.assertEqual(n, len(blob))

    def test_byte_counts(self):
        """Each 7-bit boundary crosses into a longer encoding."""
        self.assertEqual(len(encode_varint(0)), 1)
        self.assertEqual(len(encode_varint(127)), 1)   # 2^7 - 1
        self.assertEqual(len(encode_varint(128)), 2)
        self.assertEqual(len(encode_varint(16383)), 2)   # 2^14 - 1
        self.assertEqual(len(encode_varint(16384)), 3)
        self.assertEqual(len(encode_varint(2097151)), 3)   # 2^21 - 1
        self.assertEqual(len(encode_varint(2097152)), 4)
        self.assertEqual(len(encode_varint(268435455)), 4)  # 2^28 - 1
        self.assertEqual(len(encode_varint(268435456)), 5)
        # 32-bit max fits in 5 bytes
        self.assertEqual(len(encode_varint(2**32 - 1)), 5)

    def test_varint_size_matches_encode(self):
        """varint_size(v) == len(encode_varint(v)) — used on hot paths."""
        for value in (0, 1, 127, 128, 16383, 16384, 2**32 - 1):
            self.assertEqual(varint_size(value), len(encode_varint(value)))

    def test_negative_rejected(self):
        """Negative values are always bugs at this layer."""
        with self.assertRaises(ValueError):
            encode_varint(-1)
        with self.assertRaises(ValueError):
            varint_size(-1)

    def test_decode_rejects_truncated(self):
        """A continuation byte without a terminator must raise."""
        with self.assertRaises(ValueError):
            decode_varint(b"\x80")
        with self.assertRaises(ValueError):
            decode_varint(b"\x80\x80\x80")

    def test_decode_rejects_non_canonical(self):
        """`0x80 0x00` encodes the same value as `0x00` — reject it."""
        with self.assertRaises(ValueError):
            decode_varint(b"\x80\x00")
        with self.assertRaises(ValueError):
            decode_varint(b"\x81\x80\x00")

    def test_decode_rejects_oversized(self):
        """10-byte cap — an attacker cannot stall the parser."""
        # 11 continuation bytes: always too long
        blob = b"\x80" * 11
        with self.assertRaises(ValueError):
            decode_varint(blob)

    def test_decode_offset(self):
        """Partial decode: (value, bytes_consumed) reports where to resume."""
        blob = encode_varint(42) + encode_varint(1_000_000)
        v1, n1 = decode_varint(blob, 0)
        self.assertEqual(v1, 42)
        v2, n2 = decode_varint(blob, n1)
        self.assertEqual(v2, 1_000_000)
        self.assertEqual(n1 + n2, len(blob))


class TestEntityIndexRegistry(unittest.TestCase):
    """Registration assigns monotonic indices starting at 1."""

    def test_fresh_state_starts_at_1(self):
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        self.assertEqual(bc._next_entity_index, 1)
        self.assertEqual(bc.entity_id_to_index, {})
        self.assertEqual(bc.entity_index_to_id, {})

    def test_registration_assigns_monotonic_index(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity

        bc = Blockchain()
        alices = [
            Entity.create(f"alice-idx-{i}".encode().ljust(32, b"\x00"))
            for i in range(5)
        ]
        # Genesis sets up seed entity (optional — test here registers
        # fresh entities directly via register_entity).
        assigned = []
        for e in alices:
            reg_proof = e.keypair.sign(
                __import__("hashlib").new(
                    "sha3_256", b"register" + e.entity_id,
                ).digest()
            )
            ok, _ = bc.register_entity(
                e.entity_id, e.public_key, reg_proof,
            )
            self.assertTrue(ok)
            assigned.append(bc.entity_id_to_index[e.entity_id])
        # Monotonic starting at 1, no gaps
        self.assertEqual(assigned, [1, 2, 3, 4, 5])
        # Bidirectional
        for eid, idx in bc.entity_id_to_index.items():
            self.assertEqual(bc.entity_index_to_id[idx], eid)

    def test_duplicate_registration_does_not_reassign_index(self):
        """An already-registered entity's index is immutable."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity
        import hashlib

        bc = Blockchain()
        e = Entity.create(b"alice-dup".ljust(32, b"\x00"))
        proof = e.keypair.sign(
            hashlib.new("sha3_256", b"register" + e.entity_id).digest()
        )
        ok, _ = bc.register_entity(e.entity_id, e.public_key, proof)
        self.assertTrue(ok)
        first_idx = bc.entity_id_to_index[e.entity_id]

        # Duplicate registration is rejected (existing behavior)
        ok2, _ = bc.register_entity(e.entity_id, e.public_key, proof)
        self.assertFalse(ok2)
        # Index unchanged
        self.assertEqual(bc.entity_id_to_index[e.entity_id], first_idx)

    def test_index_survives_chaindb_restart(self):
        """Restart a node: entity_index_to_id rebuilds from persisted state."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity
        from messagechain.storage.chaindb import ChainDB
        import hashlib

        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "chain.db")
        try:
            db = ChainDB(db_path)
            bc = Blockchain(db=db)
            bc.initialize_genesis(
                Entity.create(b"genesis-persist".ljust(32, b"\x00")),
            )

            entities = [
                Entity.create(f"persist-{i}".encode().ljust(32, b"\x00"))
                for i in range(3)
            ]
            for e in entities:
                proof = e.keypair.sign(
                    hashlib.new(
                        "sha3_256", b"register" + e.entity_id,
                    ).digest()
                )
                ok, _ = bc.register_entity(e.entity_id, e.public_key, proof)
                self.assertTrue(ok)

            pre_restart_map = dict(bc.entity_id_to_index)
            pre_restart_next = bc._next_entity_index
            db.close()

            # Simulate restart
            db2 = ChainDB(db_path)
            bc2 = Blockchain(db=db2)
            self.assertEqual(bc2.entity_id_to_index, pre_restart_map)
            self.assertEqual(bc2._next_entity_index, pre_restart_next)
            # Bidirectional consistency
            for eid, idx in bc2.entity_id_to_index.items():
                self.assertEqual(bc2.entity_index_to_id[idx], eid)
            db2.close()
        finally:
            for fn in os.listdir(tmpdir):
                try:
                    os.remove(os.path.join(tmpdir, fn))
                except OSError:
                    pass
            os.rmdir(tmpdir)


class TestTxIndexedEncoding(unittest.TestCase):
    """Transaction to_bytes(state) uses the varint index form;
    from_bytes(data, state) resolves the index back to the entity_id.
    """

    def _setup(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity
        bc = Blockchain()
        alice = Entity.create(b"alice-ti".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-ti".ljust(32, b"\x00"))
        import hashlib

        for e in (alice, bob):
            proof = e.keypair.sign(
                hashlib.new("sha3_256", b"register" + e.entity_id).digest()
            )
            bc.register_entity(e.entity_id, e.public_key, proof)
        return bc, alice, bob

    def test_message_tx_roundtrip_with_state(self):
        from messagechain.core.transaction import (
            MessageTransaction, create_transaction,
        )
        bc, alice, _ = self._setup()
        tx = create_transaction(alice, "hello indexed", fee=2000, nonce=0)

        # With state, to_bytes emits the varint index form
        blob = tx.to_bytes(state=bc)
        decoded = MessageTransaction.from_bytes(blob, state=bc)
        self.assertEqual(decoded.entity_id, tx.entity_id)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.message, tx.message)

    def test_message_tx_signable_data_uses_entity_id_not_index(self):
        """Consensus invariant: tx_hash commits to the 32-byte entity_id.

        The wire form can change (index vs full id) but _signable_data
        must not. Future-proof: if someone ever reassigned an index,
        tx_hash still verifies against the signed-over entity_id.
        """
        from messagechain.core.transaction import create_transaction
        bc, alice, _ = self._setup()
        tx = create_transaction(alice, "sig test", fee=2000, nonce=0)
        signable = tx._signable_data()
        # The full 32-byte entity_id must appear in signable_data
        self.assertIn(tx.entity_id, signable)
        # The varint index (1 byte for idx=1) must NOT be what's signed
        # (can't really "not contain" a single byte, so just verify
        # tx_hash is independent of state encoding).
        legacy_blob = tx.to_bytes()
        state_blob = tx.to_bytes(state=bc)
        # Decode both and confirm tx_hash + entity_id are identical
        from messagechain.core.transaction import MessageTransaction
        legacy_decoded = MessageTransaction.from_bytes(legacy_blob)
        state_decoded = MessageTransaction.from_bytes(state_blob, state=bc)
        self.assertEqual(legacy_decoded.tx_hash, state_decoded.tx_hash)
        self.assertEqual(legacy_decoded.entity_id, state_decoded.entity_id)

    def test_indexed_form_is_smaller(self):
        """A 50-byte MessageTransaction with index is >= 29 B smaller
        than the legacy 32-byte entity_id form.
        """
        from messagechain.core.transaction import create_transaction
        bc, alice, _ = self._setup()
        tx = create_transaction(alice, "X" * 50, fee=5000, nonce=0)
        legacy = tx.to_bytes()
        indexed = tx.to_bytes(state=bc)
        self.assertGreaterEqual(len(legacy) - len(indexed), 29,
            f"legacy={len(legacy)} indexed={len(indexed)} "
            f"saved={len(legacy) - len(indexed)}")

    def test_unknown_index_rejected(self):
        """from_bytes(blob, state) with an index unknown to state raises."""
        from messagechain.core.transaction import (
            MessageTransaction, create_transaction,
        )
        from messagechain.core.blockchain import Blockchain
        bc, alice, _ = self._setup()
        tx = create_transaction(alice, "ghost", fee=2000, nonce=0)
        blob = tx.to_bytes(state=bc)
        # Empty-state decoder has no such index
        bare = Blockchain()
        with self.assertRaises(Exception):
            MessageTransaction.from_bytes(blob, state=bare)

    def test_transfer_tx_indexed_roundtrip(self):
        from messagechain.core.transfer import (
            TransferTransaction, create_transfer_transaction,
        )
        bc, alice, bob = self._setup()
        tx = create_transfer_transaction(
            alice, bob.entity_id, amount=100, nonce=0, fee=100,
        )
        blob = tx.to_bytes(state=bc)
        decoded = TransferTransaction.from_bytes(blob, state=bc)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.entity_id, tx.entity_id)
        self.assertEqual(decoded.recipient_id, tx.recipient_id)
        # Savings: 29 bytes from sender + 29 from recipient = ~58 B
        legacy = tx.to_bytes()
        self.assertGreaterEqual(len(legacy) - len(blob), 58,
            f"legacy={len(legacy)} indexed={len(blob)}")

    def test_stake_unstake_indexed_roundtrip(self):
        from messagechain.core.staking import (
            StakeTransaction, UnstakeTransaction,
            create_stake_transaction, create_unstake_transaction,
        )
        bc, alice, _ = self._setup()
        s = create_stake_transaction(alice, amount=1_000_000, nonce=0)
        u = create_unstake_transaction(alice, amount=500_000, nonce=1)

        s_blob = s.to_bytes(state=bc)
        u_blob = u.to_bytes(state=bc)
        s_dec = StakeTransaction.from_bytes(s_blob, state=bc)
        u_dec = UnstakeTransaction.from_bytes(u_blob, state=bc)
        self.assertEqual(s_dec.tx_hash, s.tx_hash)
        self.assertEqual(u_dec.tx_hash, u.tx_hash)
        self.assertEqual(s_dec.entity_id, s.entity_id)
        self.assertEqual(u_dec.entity_id, u.entity_id)

    def test_authority_txs_indexed_roundtrip(self):
        from messagechain.core.authority_key import (
            SetAuthorityKeyTransaction,
            create_set_authority_key_transaction,
        )
        from messagechain.core.emergency_revoke import (
            RevokeTransaction, create_revoke_transaction,
        )
        from messagechain.core.key_rotation import (
            KeyRotationTransaction, create_key_rotation,
            derive_rotated_keypair,
        )
        bc, alice, bob = self._setup()

        auth = create_set_authority_key_transaction(
            alice, new_authority_key=bob.public_key, nonce=0,
        )
        revoke = create_revoke_transaction(alice)
        new_kp = derive_rotated_keypair(alice, rotation_number=1)
        rot = create_key_rotation(alice, new_kp, rotation_number=1)

        for tx, klass in (
            (auth, SetAuthorityKeyTransaction),
            (revoke, RevokeTransaction),
            (rot, KeyRotationTransaction),
        ):
            blob = tx.to_bytes(state=bc)
            dec = klass.from_bytes(blob, state=bc)
            self.assertEqual(dec.tx_hash, tx.tx_hash)
            self.assertEqual(dec.entity_id, tx.entity_id)

    def test_governance_txs_indexed_roundtrip(self):
        from messagechain.governance.governance import (
            ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
            create_proposal, create_vote, create_treasury_spend_proposal,
        )
        bc, alice, bob = self._setup()

        prop = create_proposal(alice, "title", "description")
        vote = create_vote(alice, prop.tx_hash, approve=True)
        treas = create_treasury_spend_proposal(
            alice, bob.entity_id, amount=500, title="T", description="D",
        )

        p_blob = prop.to_bytes(state=bc)
        p_dec = ProposalTransaction.from_bytes(p_blob, state=bc)
        self.assertEqual(p_dec.tx_hash, prop.tx_hash)
        self.assertEqual(p_dec.proposer_id, prop.proposer_id)

        v_blob = vote.to_bytes(state=bc)
        v_dec = VoteTransaction.from_bytes(v_blob, state=bc)
        self.assertEqual(v_dec.tx_hash, vote.tx_hash)
        self.assertEqual(v_dec.voter_id, vote.voter_id)

        t_blob = treas.to_bytes(state=bc)
        t_dec = TreasurySpendTransaction.from_bytes(t_blob, state=bc)
        self.assertEqual(t_dec.tx_hash, treas.tx_hash)
        self.assertEqual(t_dec.proposer_id, treas.proposer_id)
        self.assertEqual(t_dec.recipient_id, treas.recipient_id)

    def test_attestation_indexed_roundtrip(self):
        from messagechain.consensus.attestation import (
            Attestation, create_attestation,
        )
        bc, alice, _ = self._setup()
        att = create_attestation(alice, b"\xff" * 32, block_number=42)
        blob = att.to_bytes(state=bc)
        dec = Attestation.from_bytes(blob, state=bc)
        self.assertEqual(dec.validator_id, att.validator_id)
        self.assertEqual(dec.block_hash, att.block_hash)

    def test_registration_tx_keeps_full_entity_id(self):
        """Registration CREATES the entity — cannot reference its own index."""
        from messagechain.core.registration import (
            RegistrationTransaction, create_registration_transaction,
        )
        from messagechain.identity.identity import Entity

        e = Entity.create(b"new-reg".ljust(32, b"\x00"))
        tx = create_registration_transaction(e)
        # Registration ALWAYS uses the full entity_id form — the state
        # doesn't know about this entity yet.
        blob = tx.to_bytes()
        dec = RegistrationTransaction.from_bytes(blob)
        self.assertEqual(dec.entity_id, e.entity_id)
        self.assertEqual(dec.tx_hash, tx.tx_hash)


class TestBlockRoundtripWithState(unittest.TestCase):
    def test_block_with_state_roundtrip(self):
        """End-to-end: block.to_bytes(state) → from_bytes(..., state)."""
        from messagechain.core.block import (
            Block, BlockHeader, compute_merkle_root, _hash,
        )
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.transaction import create_transaction
        from messagechain.identity.identity import Entity
        import time as _time
        import hashlib

        bc = Blockchain()
        alice = Entity.create(b"block-state".ljust(32, b"\x00"))
        proof = alice.keypair.sign(
            hashlib.new("sha3_256", b"register" + alice.entity_id).digest()
        )
        bc.register_entity(alice.entity_id, alice.public_key, proof)

        txs = [create_transaction(alice, f"m{i}", fee=2000, nonce=i)
               for i in range(3)]
        merkle = compute_merkle_root([t.tx_hash for t in txs])
        header = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=merkle, timestamp=_time.time(),
            proposer_id=alice.entity_id,
        )
        header.proposer_signature = alice.keypair.sign(
            _hash(header.signable_data())
        )
        block = Block(header=header, transactions=txs)

        blob = block.to_bytes(state=bc)
        decoded = Block.from_bytes(blob, state=bc)
        self.assertEqual(decoded.block_hash, block.block_hash)
        self.assertEqual(len(decoded.transactions), 3)
        for o, d in zip(txs, decoded.transactions):
            self.assertEqual(d.tx_hash, o.tx_hash)
            self.assertEqual(d.entity_id, o.entity_id)


if __name__ == "__main__":
    unittest.main()
