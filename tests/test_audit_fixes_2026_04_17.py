"""
Audit fixes batch 2026-04-17: M1, M4, M7.

M1: TOFU pin must bind to entity_id. First-contact pin stores
    (entity_id, fingerprint); on reconnect, the peer's declared entity
    must match the one pinned against the cert.

M4: When a block contains both Revoke and SetAuthorityKey for the same
    entity, Revoke must precede SetAuthorityKey. A revoke only gets
    issued by the cold key when the hot key is suspected compromised,
    so it must override any hot-key-signed auth swap in the same block.

M7: A corrupted anchors.json must not silently return an empty list.
    The node must log a warning, attempt recovery from an .bak sidecar,
    and use tmp-file-then-rename on save so a partial write cannot
    corrupt the active file.
"""

import hashlib
import json
import os
import ssl
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from messagechain import config
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.authority_key import (
    SetAuthorityKeyTransaction, create_set_authority_key_transaction,
)
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.core.emergency_revoke import RevokeTransaction
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from messagechain.network.anchor import AnchorStore
from messagechain.network.tls import (
    CertificatePinStore,
    verify_peer_certificate,
)


# ─── M1: TOFU pin binds to entity_id ──────────────────────────────────

def _fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


class TestM1TofuBindsToEntity(unittest.TestCase):
    """Cert pin must bind to a specific entity_id; entity swap = reject."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.pin_path = os.path.join(self.tmpdir, "pins.json")
        self.store = CertificatePinStore(self.pin_path)

    def tearDown(self):
        if os.path.exists(self.pin_path):
            os.remove(self.pin_path)
        if os.path.exists(self.pin_path + ".bak"):
            os.remove(self.pin_path + ".bak")
        os.rmdir(self.tmpdir)

    def test_first_connection_pins_cert_with_entity(self):
        """First connection records (entity_id, fingerprint) as a pair."""
        fp = "a" * 64
        eid = b"alice-entity-id-32bytes!!!!!!!!!"
        result = self.store.check_or_pin("10.0.0.1", 9333, fp, entity_id=eid)
        self.assertTrue(result)
        self.assertEqual(self.store.get("10.0.0.1", 9333), fp)
        self.assertEqual(self.store.get_entity("10.0.0.1", 9333), eid)

    def test_same_cert_same_entity_accepted(self):
        """Reconnect with same cert and same entity_id is accepted."""
        fp = "a" * 64
        eid = b"alice-entity-id-32bytes!!!!!!!!!"
        self.store.check_or_pin("10.0.0.1", 9333, fp, entity_id=eid)
        result = self.store.check_or_pin("10.0.0.1", 9333, fp, entity_id=eid)
        self.assertTrue(result)

    def test_same_cert_different_entity_rejected(self):
        """Pinned cert + different entity_id must be rejected (impersonation)."""
        fp = "a" * 64
        eid1 = b"alice-entity-id-32bytes!!!!!!!!!"
        eid2 = b"mallory-entity-id-32bytes!!!!!!!"
        self.store.check_or_pin("10.0.0.1", 9333, fp, entity_id=eid1)
        result = self.store.check_or_pin("10.0.0.1", 9333, fp, entity_id=eid2)
        self.assertFalse(result)

    def test_different_cert_same_entity_rejected(self):
        """Pinned entity + different cert must still fail (MITM)."""
        fp1 = "a" * 64
        fp2 = "b" * 64
        eid = b"alice-entity-id-32bytes!!!!!!!!!"
        self.store.check_or_pin("10.0.0.1", 9333, fp1, entity_id=eid)
        result = self.store.check_or_pin("10.0.0.1", 9333, fp2, entity_id=eid)
        self.assertFalse(result)

    def test_legacy_call_without_entity_still_works(self):
        """Existing callers that don't yet pass entity_id still work."""
        fp = "a" * 64
        self.assertTrue(self.store.check_or_pin("10.0.0.1", 9333, fp))
        self.assertTrue(self.store.check_or_pin("10.0.0.1", 9333, fp))

    def test_entity_binding_persists_across_reload(self):
        """(entity_id, fingerprint) survives a save/load round trip."""
        fp = "a" * 64
        eid = b"alice-entity-id-32bytes!!!!!!!!!"
        self.store.check_or_pin("10.0.0.1", 9333, fp, entity_id=eid)
        self.store.save()

        store2 = CertificatePinStore(self.pin_path)
        self.assertEqual(store2.get("10.0.0.1", 9333), fp)
        self.assertEqual(store2.get_entity("10.0.0.1", 9333), eid)

        # Impersonation attempt after reload must still fail
        eid2 = b"mallory-entity-id-32bytes!!!!!!!"
        self.assertFalse(
            store2.check_or_pin("10.0.0.1", 9333, fp, entity_id=eid2)
        )


class TestM1VerifyPeerCertificateWithEntity(unittest.TestCase):
    """verify_peer_certificate accepts an entity_id and enforces binding."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.pin_path = os.path.join(self.tmpdir, "pins.json")
        self.store = CertificatePinStore(self.pin_path)

    def tearDown(self):
        if os.path.exists(self.pin_path):
            os.remove(self.pin_path)
        if os.path.exists(self.pin_path + ".bak"):
            os.remove(self.pin_path + ".bak")
        os.rmdir(self.tmpdir)

    def test_entity_mismatch_rejected(self):
        der = b"\x30\x82" + b"\x00" * 100
        sock = MagicMock(spec=ssl.SSLSocket)
        sock.getpeercert.return_value = der

        eid1 = b"alice!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        eid2 = b"mallory!!!!!!!!!!!!!!!!!!!!!!!!!"

        self.assertTrue(
            verify_peer_certificate(sock, "10.0.0.1", 9333, self.store, entity_id=eid1)
        )
        self.assertFalse(
            verify_peer_certificate(sock, "10.0.0.1", 9333, self.store, entity_id=eid2)
        )


# ─── M4: Revoke precedes SetAuthorityKey in same block ────────────────


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestM4RevokeBeforeSetAuthorityOrdering(unittest.TestCase):
    """If a block contains both Revoke and SetAuthorityKey for the same
    entity, the Revoke must win. A hot-key-signed SetAuthorityKey in the
    same block as a cold-key-signed Revoke is the exact attack the cold
    key is supposed to defeat."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def _bootstrap(self, include=()):
        chain = Blockchain()
        proposer = _entity(b"proposer")
        self._register(chain, proposer)
        # Heavy proposer stake swamps stake-weighted RNG in proposer
        # selection — genesis timestamps are non-deterministic across
        # runs (see test_authority_tx_block_pipeline.py's long-form
        # note), so we lean hard on the stake weight to avoid flakes.
        chain.supply.balances[proposer.entity_id] = 2_000_000_000_000
        chain.supply.staked[proposer.entity_id] = 1_000_000_000_000
        extras = {}
        for seed, balance, stake in include:
            e = _entity(seed)
            self._register(chain, e)
            chain.supply.balances[e.entity_id] = balance
            if stake:
                chain.supply.staked[e.entity_id] = stake
            extras[seed] = e
        chain.initialize_genesis(proposer)
        consensus = ProofOfStake()
        consensus.register_validator(
            proposer.entity_id, stake_amount=1_000_000_000_000,
        )
        return chain, proposer, consensus, extras

    def _make_revoke(self, target_eid: bytes, cold) -> RevokeTransaction:
        tx = RevokeTransaction(
            entity_id=target_eid, timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = cold.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        return tx

    def test_revoke_wins_even_when_set_listed_first(self):
        """Order authority_txs as [Set, Revoke] — outcome must still be revoked,
        and the Set's new_authority_key must NOT become the live authority."""
        chain, proposer, consensus, extras = self._bootstrap(
            include=[(b"hot", 100_000, 50_000)],
        )
        hot = extras[b"hot"]
        cold = _entity(b"cold")
        attacker_pk = _entity(b"attacker").public_key

        # Step 1: legitimate cold-key promotion via block 1
        set_initial = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        blk1 = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[set_initial],
        )
        ok, reason = chain.add_block(blk1)
        self.assertTrue(ok, reason)
        self.assertEqual(chain.get_authority_key(hot.entity_id), cold.public_key)

        # Step 2: attacker (with stolen hot key) tries to swap authority to
        # their own key; legitimate owner simultaneously submits a Revoke
        # signed by cold. A malicious proposer orders Set first.
        set_attack = create_set_authority_key_transaction(
            hot, new_authority_key=attacker_pk, nonce=1, fee=500,
        )
        revoke = self._make_revoke(hot.entity_id, cold)

        blk2 = chain.propose_block(
            consensus, proposer, transactions=[],
            authority_txs=[set_attack, revoke],  # Set listed FIRST
        )
        ok, reason = chain.add_block(blk2)
        self.assertTrue(ok, reason)

        # Revoke must win: entity is revoked, stake drained, authority NOT
        # replaced by the attacker's key.
        self.assertTrue(chain.is_revoked(hot.entity_id))
        self.assertEqual(chain.supply.get_staked(hot.entity_id), 0)
        self.assertNotEqual(
            chain.get_authority_key(hot.entity_id), attacker_pk,
            "Revoke must override SetAuthorityKey regardless of listed order",
        )

    def test_revoke_wins_when_revoke_listed_first(self):
        """Order authority_txs as [Revoke, Set] — same revoked outcome."""
        chain, proposer, consensus, extras = self._bootstrap(
            include=[(b"hot2", 100_000, 50_000)],
        )
        hot = extras[b"hot2"]
        cold = _entity(b"cold2")
        attacker_pk = _entity(b"attacker2").public_key

        set_initial = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        blk1 = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[set_initial],
        )
        ok, reason = chain.add_block(blk1)
        self.assertTrue(ok, reason)

        set_attack = create_set_authority_key_transaction(
            hot, new_authority_key=attacker_pk, nonce=1, fee=500,
        )
        revoke = self._make_revoke(hot.entity_id, cold)

        blk2 = chain.propose_block(
            consensus, proposer, transactions=[],
            authority_txs=[revoke, set_attack],  # Revoke listed FIRST
        )
        ok, reason = chain.add_block(blk2)
        self.assertTrue(ok, reason)

        self.assertTrue(chain.is_revoked(hot.entity_id))
        self.assertNotEqual(chain.get_authority_key(hot.entity_id), attacker_pk)


# ─── M7: Anchor file corruption recovery ──────────────────────────────


class TestM7AnchorCorruptionRecovery(unittest.TestCase):
    """Corrupt anchors.json must log + try .bak; saves use tmp+rename."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = os.path.join(self.tmpdir, "anchors.json")

    def tearDown(self):
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def test_corrupt_file_logs_warning(self):
        """A malformed anchors file emits a WARNING mentioning the path."""
        with open(self.path, "w") as f:
            f.write("{ not valid json !!!")
        store = AnchorStore(self.path)

        import logging as _logging
        with self.assertLogs("messagechain.network.anchor", level="WARNING") as cm:
            anchors = store.load_anchors()
        self.assertEqual(anchors, [])
        # Warning mentions the path so operators can find the bad file.
        joined = "\n".join(cm.output)
        self.assertIn(self.path, joined)

    def test_corrupt_file_recovers_from_bak(self):
        """If anchors.json is corrupt but anchors.json.bak is good, use the bak."""
        # Good data lives in the .bak sidecar
        good = [{"host": "8.8.8.8", "port": 9333}]
        with open(self.path + ".bak", "w") as f:
            json.dump(good, f)
        # Primary file is corrupted
        with open(self.path, "w") as f:
            f.write("\x00\x01garbage")

        store = AnchorStore(self.path)
        anchors = store.load_anchors()
        self.assertEqual(anchors, [("8.8.8.8", 9333)])

    def test_save_uses_tmp_then_rename(self):
        """save_anchors must write to a tmp sibling then rename atomically.

        Verified by making os.rename raise: the destination file must not
        be created/touched, i.e. the partial write does NOT corrupt the
        live file.
        """
        # Prime the file with valid content
        existing = [{"host": "1.1.1.1", "port": 9333}]
        with open(self.path, "w") as f:
            json.dump(existing, f)

        store = AnchorStore(self.path)

        import unittest.mock as _mock
        original_replace = os.replace
        original_rename = os.rename

        def boom(*a, **kw):
            raise OSError("simulated rename failure")

        with _mock.patch("os.replace", boom), _mock.patch("os.rename", boom):
            store.save_anchors([("9.9.9.9", 9333)])

        # Live file must still contain the ORIGINAL anchors — no partial write.
        with open(self.path, "r") as f:
            data = json.load(f)
        self.assertEqual(data, existing)

    def test_save_writes_bak_sidecar(self):
        """Successful save leaves a .bak with the PREVIOUS contents.

        This is what makes the corruption-recovery path meaningful: the
        .bak is a last-known-good snapshot of what was on disk BEFORE the
        latest save.
        """
        store = AnchorStore(self.path)
        # First save: no prior state, bak optional
        store.save_anchors([("1.1.1.1", 9333)])
        # Second save: previous should be moved into .bak
        store.save_anchors([("2.2.2.2", 9333)])
        self.assertTrue(os.path.exists(self.path + ".bak"))
        with open(self.path + ".bak", "r") as f:
            bak_data = json.load(f)
        self.assertEqual(bak_data, [{"host": "1.1.1.1", "port": 9333}])


if __name__ == "__main__":
    unittest.main()
