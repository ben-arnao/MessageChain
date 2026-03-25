"""
Biometric identity system for MessageChain.

Core principle: your biometric data IS your private key.

Each entity is uniquely identified by a combination of three biometric factors:
DNA, fingerprint, and iris scan. The combined biometric hashes serve as the
cryptographic private key — there is no separate secret. Your body is your key.

Security model:
- The ENTITY ID is PUBLIC. It is visible on-chain in every transaction.
  It is derived via: SHA3-256("entity_id" || dna_hash || fingerprint_hash || iris_hash)
- The BIOMETRIC SEED is PRIVATE. It never leaves the local device.
  It is derived via: SHA3-256("private_key" || dna_hash || fingerprint_hash || iris_hash)
- Domain separation ensures that knowing the entity ID reveals nothing about
  the private key seed, and vice versa. Both are deterministic from the same
  biometric inputs, but are cryptographically independent.

One person = one entity = one wallet. Duplicate registrations are rejected.
Entity ID == wallet ID. There is no separate wallet concept.

In production, biometric data never leaves the local device. Hashes are computed
locally, the keypair derived locally, and only the public key goes on-chain.
The biometric type used for a given message is metadata indicating which factor
authenticated the user locally to unlock signing.
"""

import hashlib
from enum import Enum
from dataclasses import dataclass
from messagechain.config import HASH_ALGO
from messagechain.crypto.keys import KeyPair

# Domain separation tags — ensure entity_id and private seed are
# cryptographically independent even though they derive from the same inputs.
_DOMAIN_ENTITY_ID = b"entity_id"
_DOMAIN_PRIVATE_KEY = b"private_key"


class BiometricType(Enum):
    DNA = "dna"
    FINGERPRINT = "fingerprint"
    IRIS = "iris"


def derive_entity_id(dna_hash: bytes, fingerprint_hash: bytes, iris_hash: bytes) -> bytes:
    """
    Derive a unique entity ID from three biometric hashes.

    The entity ID is PUBLIC — it appears on-chain in every transaction and
    block. It is the wallet address. Same biometrics always produce the same
    entity ID, enforcing one-wallet-per-person.

    Domain-separated from the private key seed so that knowing the entity ID
    reveals nothing about the signing key.
    """
    combined = _DOMAIN_ENTITY_ID + dna_hash + fingerprint_hash + iris_hash
    return hashlib.new(HASH_ALGO, combined).digest()


def _derive_biometric_seed(dna_hash: bytes, fingerprint_hash: bytes, iris_hash: bytes) -> bytes:
    """
    Derive the private key seed from three biometric hashes.

    This seed is SECRET — it never leaves the local device. It is the sole
    input to keypair generation. Same biometrics always produce the same seed,
    so the entity can always re-derive their keys from their body.

    Domain-separated from the entity ID so that knowing the public entity ID
    reveals nothing about this seed.
    """
    combined = _DOMAIN_PRIVATE_KEY + dna_hash + fingerprint_hash + iris_hash
    return hashlib.new(HASH_ALGO, combined).digest()


@dataclass
class Entity:
    """
    A unique participant in the MessageChain network.

    Identity model:
    - entity_id == wallet ID (public, visible on-chain)
    - biometric_seed == private key (secret, never transmitted)
    - One person = one entity = one wallet (enforced by biometric uniqueness)

    The biometric hashes ARE the private key material. The keypair is derived
    from them via a domain-separated seed. Same biometrics = same entity ID =
    same wallet = same keys. There is no separate key management — your body
    is your credential.
    """
    entity_id: bytes               # PUBLIC — the wallet/entity address on-chain
    keypair: KeyPair
    _biometric_seed: bytes         # PRIVATE — the cryptographic seed (never transmitted)
    _dna_hash: bytes               # PRIVATE — individual biometric hash
    _fingerprint_hash: bytes       # PRIVATE — individual biometric hash
    _iris_hash: bytes              # PRIVATE — individual biometric hash

    @classmethod
    def create(cls, dna_data: bytes, fingerprint_data: bytes, iris_data: bytes) -> "Entity":
        """
        Create an entity from raw biometric data.

        In production, raw data comes from biometric sensors on the local device.
        All hashing and key derivation happens locally — nothing secret is transmitted.
        """
        h = hashlib.new
        dna_hash = h(HASH_ALGO, dna_data).digest()
        fingerprint_hash = h(HASH_ALGO, fingerprint_data).digest()
        iris_hash = h(HASH_ALGO, iris_data).digest()

        return cls.from_hashes(dna_hash, fingerprint_hash, iris_hash)

    @classmethod
    def from_hashes(cls, dna_hash: bytes, fingerprint_hash: bytes, iris_hash: bytes) -> "Entity":
        """
        Create an entity from pre-hashed biometric data.

        Used on the server side — the client hashes biometrics locally and
        sends only hashes. Raw biometric data never leaves the client device.
        """
        entity_id = derive_entity_id(dna_hash, fingerprint_hash, iris_hash)

        # Biometric seed is the PRIVATE KEY — domain-separated from entity_id.
        # entity_id is public (on-chain), biometric_seed is secret (local only).
        # Knowing entity_id cannot reveal biometric_seed, and vice versa.
        biometric_seed = _derive_biometric_seed(dna_hash, fingerprint_hash, iris_hash)
        keypair = KeyPair.generate(biometric_seed)

        return cls(
            entity_id=entity_id,
            keypair=keypair,
            _biometric_seed=biometric_seed,
            _dna_hash=dna_hash,
            _fingerprint_hash=fingerprint_hash,
            _iris_hash=iris_hash,
        )

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key

    @property
    def entity_id_hex(self) -> str:
        """The public entity/wallet ID as a hex string."""
        return self.entity_id.hex()

    def verify_biometric(self, bio_type: BiometricType, bio_data: bytes) -> bool:
        """
        Verify that the provided biometric matches this entity.

        This simulates local biometric authentication before allowing a signature.
        In production, this happens on the local device — the chain never sees raw biometrics.
        """
        bio_hash = hashlib.new(HASH_ALGO, bio_data).digest()
        if bio_type == BiometricType.DNA:
            return bio_hash == self._dna_hash
        elif bio_type == BiometricType.FINGERPRINT:
            return bio_hash == self._fingerprint_hash
        elif bio_type == BiometricType.IRIS:
            return bio_hash == self._iris_hash
        return False
