"""
Entity registration as a consensus-visible transaction.

Every other persistent state change on MessageChain flows through a
block-committed transaction so every peer reaches the same state.  The
sole outlier used to be `register_entity`: the RPC handler mutated
local state directly, the registration never rode a block, and peer
nodes never learned about the new entity.  A first-time user who
registered via seed A could not then have their transactions accepted
by seeds B and C — those peers saw the signed tx but had no public_key
to verify against, so they rejected the block containing it.

RegistrationTransaction closes that gap.  It is:

  * Fee-free.  A brand-new entity has no balance; charging a fee would
    require a bootstrap faucet or proposer subsidy (both worse than
    just accepting that cheap new identities are fine — the anti-sybil
    defense is stake, not registration cost).
  * Nonce-free.  Registration is the FIRST tx for an entity; there is
    nothing to replay-protect against beyond "duplicate registration
    rejected," which the tx hash + on-chain public_keys dedupe already
    enforces.
  * Self-authenticating.  The tx bundles the entity's public_key so
    the signature can be verified without consulting chain state;
    that's the whole point — the chain doesn't know about the entity
    yet when it receives the tx.
"""

import hashlib
import struct
import time
from dataclasses import dataclass

from messagechain.config import CHAIN_ID, HASH_ALGO, SIG_VERSION_CURRENT, REGISTRATION_FEE
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class RegistrationTransaction:
    """Register a new entity on the chain.

    Fields:
        entity_id: SHA3-256 hash of public_key (derived client-side).
        public_key: the registrant's public key.  Bundled because the
            chain has no way to look it up before registration.
        registration_proof: signature over SHA3-256("register" || entity_id)
            using the keypair matching `public_key`.  Proves the registrant
            controls the keypair.
        timestamp: wall-clock at tx creation.
    """
    entity_id: bytes
    public_key: bytes
    registration_proof: Signature
    timestamp: float
    randao_commitment: bytes = b"\x00" * 32  # SHA3(randao_seed); published at registration
    sponsor_id: bytes = b""  # existing entity who pays the registration fee
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        """Canonical bytes for hashing.  The registration_proof signs a
        separate message (`SHA3("register" || entity_id)`) so its
        domain-separation is independent of this tx hash.

        Crypto-agility: the registration_proof's sig_version is committed
        into tx_hash so an attacker can't rewrite the registrant's chosen
        scheme without invalidating the whole tx hash.  getattr fallback
        keeps None-proof test fixtures working.
        """
        sig_version = getattr(
            self.registration_proof, "sig_version", SIG_VERSION_CURRENT,
        )
        return (
            CHAIN_ID
            + b"register_entity"
            + struct.pack(">B", sig_version)
            + self.entity_id
            + self.public_key
            + struct.pack(">Q", int(self.timestamp))
            + self.randao_commitment
            + self.sponsor_id
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        d = {
            "type": "register_entity",
            "entity_id": self.entity_id.hex(),
            "public_key": self.public_key.hex(),
            "registration_proof": self.registration_proof.serialize(),
            "timestamp": self.timestamp,
            "randao_commitment": self.randao_commitment.hex(),
            "tx_hash": self.tx_hash.hex(),
        }
        if self.sponsor_id:
            d["sponsor_id"] = self.sponsor_id.hex()
        return d

    def to_bytes(self) -> bytes:
        """Binary: 32 entity_id | 32 public_key | u32 proof_len | proof |
        f64 timestamp | 32 randao_commitment | u8 has_sponsor | [32 sponsor_id] |
        32 tx_hash.
        """
        proof_blob = self.registration_proof.to_bytes()
        parts = [
            self.entity_id,
            self.public_key,
            struct.pack(">I", len(proof_blob)),
            proof_blob,
            struct.pack(">d", float(self.timestamp)),
            self.randao_commitment,
        ]
        if self.sponsor_id:
            parts.append(b"\x01")
            parts.append(self.sponsor_id)
        else:
            parts.append(b"\x00")
        parts.append(self.tx_hash)
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "RegistrationTransaction":
        off = 0
        # 32 entity_id + 32 public_key + 4 proof_len + 8 timestamp + 32 randao_commitment + 1 has_sponsor + 32 tx_hash
        if len(data) < 32 + 32 + 4 + 8 + 32 + 1 + 32:
            raise ValueError("Registration blob too short")
        entity_id = bytes(data[off:off + 32]); off += 32
        public_key = bytes(data[off:off + 32]); off += 32
        proof_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + proof_len + 8 + 32 + 1 + 32 > len(data):
            raise ValueError("Registration truncated at proof/timestamp/commitment/hash")
        proof = Signature.from_bytes(bytes(data[off:off + proof_len])); off += proof_len
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        randao_commitment = bytes(data[off:off + 32]); off += 32
        has_sponsor = data[off]; off += 1
        sponsor_id = b""
        if has_sponsor:
            if off + 32 + 32 > len(data):
                raise ValueError("Registration truncated at sponsor_id")
            sponsor_id = bytes(data[off:off + 32]); off += 32
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("Registration has trailing bytes")
        tx = cls(
            entity_id=entity_id, public_key=public_key,
            registration_proof=proof, timestamp=timestamp,
            randao_commitment=randao_commitment,
            sponsor_id=sponsor_id,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"Registration hash mismatch: declared {declared.hex()[:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "RegistrationTransaction":
        proof = Signature.deserialize(data["registration_proof"])
        randao_commitment = (
            bytes.fromhex(data["randao_commitment"])
            if data.get("randao_commitment")
            else b"\x00" * 32
        )
        sponsor_id = (
            bytes.fromhex(data["sponsor_id"])
            if data.get("sponsor_id")
            else b""
        )
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            public_key=bytes.fromhex(data["public_key"]),
            registration_proof=proof,
            timestamp=data["timestamp"],
            randao_commitment=randao_commitment,
            sponsor_id=sponsor_id,
        )
        expected = tx._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"Registration hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx


def create_registration_transaction(
    entity, sponsor_id: bytes = b"",
) -> RegistrationTransaction:
    """Build and sign a registration tx for `entity`.

    Entity is the client-side object holding keypair, entity_id, public_key.

    When REGISTRATION_FEE > 0, `sponsor_id` must be the entity_id of an
    existing registered entity who will pay the fee.  When REGISTRATION_FEE
    is 0, sponsor_id may be omitted.
    """
    proof_msg = _hash(b"register" + entity.entity_id)
    proof = entity.keypair.sign(proof_msg)
    tx = RegistrationTransaction(
        entity_id=entity.entity_id,
        public_key=entity.public_key,
        registration_proof=proof,
        timestamp=time.time(),
        sponsor_id=sponsor_id,
    )
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_registration_transaction(tx: RegistrationTransaction) -> tuple[bool, str]:
    """Verify structural fields and the self-contained proof.

    Does NOT check for duplicate registration — that's application-
    layer (`entity_id not in blockchain.public_keys`) and is enforced
    separately at apply time.
    """
    if len(tx.entity_id) != 32:
        return False, "entity_id must be 32 bytes"
    if len(tx.public_key) != 32:
        return False, "public_key must be 32 bytes"
    # Derived entity_id must match the embedded public_key using the
    # domain-separated derivation (see identity.derive_entity_id).
    from messagechain.identity.identity import derive_entity_id
    if derive_entity_id(tx.public_key) != tx.entity_id:
        return False, "entity_id does not derive from public_key"
    if tx.timestamp <= 0:
        return False, "timestamp must be positive"
    # Proof message + signature must verify against the embedded public_key.
    proof_msg = _hash(b"register" + tx.entity_id)
    if not verify_signature(proof_msg, tx.registration_proof, tx.public_key):
        return False, "registration_proof does not verify against public_key"
    return True, "Valid"
