"""
Biometric identity system for MessageChain.

Each entity is uniquely identified by a combination of three biometric factors:
DNA, fingerprint, and iris scan. The entity ID is derived from all three,
ensuring one-person-one-identity on the chain.

In production, biometric data never leaves the local device. The hash is computed
locally, and only the derived entity ID and quantum-resistant public key go on-chain.
The biometric type used for a given message is metadata indicating which factor
authenticated the user locally.
"""

import hashlib
from enum import Enum
from dataclasses import dataclass
from messagechain.config import HASH_ALGO
from messagechain.crypto.keys import KeyPair


class BiometricType(Enum):
    DNA = "dna"
    FINGERPRINT = "fingerprint"
    IRIS = "iris"


def derive_entity_id(dna_hash: bytes, fingerprint_hash: bytes, iris_hash: bytes) -> bytes:
    """
    Derive a unique entity ID from three biometric hashes.

    The entity ID is the fundamental identity on-chain. It is deterministic:
    the same biometrics always produce the same ID. This enforces one-wallet-per-person.
    """
    combined = dna_hash + fingerprint_hash + iris_hash
    return hashlib.new(HASH_ALGO, combined).digest()


@dataclass
class Entity:
    """
    A unique participant in the MessageChain network.

    Each entity has:
    - A unique ID derived from their biometric combination
    - A quantum-resistant keypair derived from their identity
    - The ability to sign messages using any of their three biometric types
    """
    entity_id: bytes
    keypair: KeyPair
    _dna_hash: bytes
    _fingerprint_hash: bytes
    _iris_hash: bytes

    @classmethod
    def create(cls, dna_data: bytes, fingerprint_data: bytes, iris_data: bytes) -> "Entity":
        """
        Create an entity from raw biometric data.

        In production, raw data would come from biometric sensors.
        For the prototype, any bytes work (simulating sensor output).
        """
        h = hashlib.new
        dna_hash = h(HASH_ALGO, dna_data).digest()
        fingerprint_hash = h(HASH_ALGO, fingerprint_data).digest()
        iris_hash = h(HASH_ALGO, iris_data).digest()

        entity_id = derive_entity_id(dna_hash, fingerprint_hash, iris_hash)

        # Keypair is deterministically derived from entity_id
        # This means the same person always gets the same keys
        keypair = KeyPair.generate(entity_id)

        return cls(
            entity_id=entity_id,
            keypair=keypair,
            _dna_hash=dna_hash,
            _fingerprint_hash=fingerprint_hash,
            _iris_hash=iris_hash,
        )

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key

    @property
    def entity_id_hex(self) -> str:
        return self.entity_id.hex()

    def verify_biometric(self, bio_type: BiometricType, bio_data: bytes) -> bool:
        """
        Verify that the provided biometric matches this entity.

        This simulates local biometric authentication before allowing a signature.
        """
        bio_hash = hashlib.new(HASH_ALGO, bio_data).digest()
        if bio_type == BiometricType.DNA:
            return bio_hash == self._dna_hash
        elif bio_type == BiometricType.FINGERPRINT:
            return bio_hash == self._fingerprint_hash
        elif bio_type == BiometricType.IRIS:
            return bio_hash == self._iris_hash
        return False
