"""
Biometric identity system for MessageChain.

Core principle: two-factor authentication — biometrics + private key.

Each entity is uniquely identified by a combination of three biometric factors:
DNA, fingerprint, and iris scan. The entity ID (wallet address) is derived
from biometrics alone, enforcing one-person-one-wallet.

To SIGN transactions, both factors are required:
1. Biometric data (something you are) — determines your wallet address
2. A private key (something you know) — combined with biometrics to derive
   the signing key seed

Security model:
- The ENTITY ID is PUBLIC. It is visible on-chain in every transaction.
  It is derived via: SHA3-256("entity_id" || dna_hash || fingerprint_hash || iris_hash)
  Entity ID depends ONLY on biometrics (one person = one wallet).
- The SIGNING KEY SEED is PRIVATE. It never leaves the local device.
  It is derived via: SHA3-256("private_key" || dna_hash || fingerprint_hash || iris_hash || private_key)
  The seed requires BOTH biometrics and the private key — stolen biometrics
  alone cannot produce a valid signature.
- Domain separation ensures that knowing the entity ID reveals nothing about
  the signing key seed, and vice versa.

One person = one entity = one wallet. Duplicate registrations are rejected.
Entity ID == wallet ID. There is no separate wallet concept.

In production, biometric data and the private key never leave the local device.
Hashes are computed locally, the keypair derived locally, and only the public
key goes on-chain.
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


def _derive_signing_seed(
    dna_hash: bytes, fingerprint_hash: bytes, iris_hash: bytes, private_key: bytes
) -> bytes:
    """
    Derive the signing key seed from biometric hashes + private key.

    This seed is SECRET — it never leaves the local device. It is the sole
    input to keypair generation. Requires BOTH biometrics and the private key,
    so stolen biometrics alone cannot produce a valid signing key.

    Domain-separated from the entity ID so that knowing the public entity ID
    reveals nothing about this seed.
    """
    combined = _DOMAIN_PRIVATE_KEY + dna_hash + fingerprint_hash + iris_hash + private_key
    return hashlib.new(HASH_ALGO, combined).digest()


@dataclass
class Entity:
    """
    A unique participant in the MessageChain network.

    Two-factor identity model:
    - entity_id == wallet ID (public, derived from biometrics only)
    - signing seed == derived from biometrics + private key (secret, never transmitted)
    - One person = one entity = one wallet (enforced by biometric uniqueness)

    To sign transactions, BOTH factors are required:
    1. Biometric data (something you are) — determines wallet address
    2. Private key (something you know) — combined with biometrics for signing key
    """
    entity_id: bytes               # PUBLIC — the wallet/entity address on-chain
    keypair: KeyPair
    _biometric_seed: bytes         # PRIVATE — the cryptographic seed (never transmitted)
    _dna_hash: bytes               # PRIVATE — individual biometric hash
    _fingerprint_hash: bytes       # PRIVATE — individual biometric hash
    _iris_hash: bytes              # PRIVATE — individual biometric hash

    @classmethod
    def create(
        cls,
        dna_data: bytes,
        fingerprint_data: bytes,
        iris_data: bytes,
        *,
        private_key: bytes,
    ) -> "Entity":
        """
        Create an entity from raw biometric data and a private key.

        Both factors are required:
        - Biometric data: from hardware sensors on the local device
        - Private key: a secret known only to the user

        All hashing and key derivation happens locally — nothing secret is transmitted.
        """
        if not private_key:
            raise ValueError("Private key is required — both biometrics and a private key are needed to sign")

        h = hashlib.new
        dna_hash = h(HASH_ALGO, dna_data).digest()
        fingerprint_hash = h(HASH_ALGO, fingerprint_data).digest()
        iris_hash = h(HASH_ALGO, iris_data).digest()

        return cls.from_hashes(dna_hash, fingerprint_hash, iris_hash, private_key=private_key)

    @classmethod
    def from_hashes(
        cls,
        dna_hash: bytes,
        fingerprint_hash: bytes,
        iris_hash: bytes,
        *,
        private_key: bytes,
    ) -> "Entity":
        """
        Create an entity from pre-hashed biometric data and a private key.

        Entity ID is derived from biometrics only (one person = one wallet).
        Signing key seed is derived from biometrics + private key (2FA).
        """
        if not private_key:
            raise ValueError("Private key is required — both biometrics and a private key are needed to sign")

        entity_id = derive_entity_id(dna_hash, fingerprint_hash, iris_hash)

        # Signing seed requires BOTH biometrics and private key.
        # entity_id is public (on-chain), signing seed is secret (local only).
        # Stolen biometrics alone cannot produce a valid signing key.
        biometric_seed = _derive_signing_seed(dna_hash, fingerprint_hash, iris_hash, private_key)
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
