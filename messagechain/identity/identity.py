"""
Identity system for MessageChain.

Core principle: private key = identity.

Each entity is uniquely identified by its public key. The entity ID (wallet
address) is derived from the public key. The private key is a secret seed
that deterministically generates the signing keypair.

Security model:
- The ENTITY ID is PUBLIC. It is visible on-chain in every transaction.
  It is derived via: SHA3-256("entity_id" || public_key)
  Entity ID depends ONLY on the public key.
- The SIGNING KEY SEED is PRIVATE. It never leaves the local device.
  It is derived via: SHA3-256("signing_seed" || private_key)
  The seed is used to generate the quantum-resistant keypair.
- Domain separation ensures that knowing the entity ID reveals nothing about
  the signing key seed, and vice versa.

Entity ID == wallet ID. There is no separate wallet concept.

In production, the private key never leaves the local device.
The keypair is derived locally, and only the public key goes on-chain.

Anti-bot/anti-AI incentives come from the fee system, not from identity.
L2 protocols can layer identity verification, reputation, and trust on top.
"""

import hashlib
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, MERKLE_TREE_HEIGHT
from messagechain.crypto.keys import KeyPair

# Domain separation tags — ensure entity_id and signing seed are
# cryptographically independent even though they derive from related inputs.
_DOMAIN_ENTITY_ID = b"entity_id"
_DOMAIN_SIGNING_SEED = b"signing_seed"


def derive_entity_id(public_key: bytes) -> bytes:
    """
    Derive a unique entity ID from a public key.

    The entity ID is PUBLIC — it appears on-chain in every transaction and
    block. It is the wallet address. Same public key always produces the same
    entity ID.

    Domain-separated from the signing seed so that knowing the entity ID
    reveals nothing about the signing key.
    """
    combined = _DOMAIN_ENTITY_ID + public_key
    return hashlib.new(HASH_ALGO, combined).digest()


def _derive_signing_seed(private_key: bytes) -> bytes:
    """
    Derive the signing key seed from a private key.

    This seed is SECRET — it never leaves the local device. It is the sole
    input to keypair generation.

    Domain-separated from the entity ID so that knowing the public entity ID
    reveals nothing about this seed.
    """
    combined = _DOMAIN_SIGNING_SEED + private_key
    return hashlib.new(HASH_ALGO, combined).digest()


@dataclass
class Entity:
    """
    A unique participant in the MessageChain network.

    Private-key identity model:
    - entity_id == wallet ID (public, derived from public key)
    - signing seed == derived from private key (secret, never transmitted)
    - Private key is the sole credential. Guard it carefully.
    """
    entity_id: bytes               # PUBLIC — the wallet/entity address on-chain
    keypair: KeyPair
    _seed: bytes                   # PRIVATE — the cryptographic seed (never transmitted)

    @classmethod
    def create(
        cls,
        private_key: bytes,
        *,
        tree_height: int | None = None,
    ) -> "Entity":
        """
        Create an entity from a private key.

        The private key is the sole credential:
        - It deterministically derives the signing keypair
        - The entity ID is derived from the resulting public key

        All key derivation happens locally — nothing secret is transmitted.
        """
        if not private_key:
            raise ValueError("Private key is required")

        seed = _derive_signing_seed(private_key)

        if tree_height is None:
            # Import at call time so tests can patch config.MERKLE_TREE_HEIGHT
            from messagechain.config import MERKLE_TREE_HEIGHT as _h
            tree_height = _h

        keypair = KeyPair.generate(seed, height=tree_height)
        entity_id = derive_entity_id(keypair.public_key)

        return cls(
            entity_id=entity_id,
            keypair=keypair,
            _seed=seed,
        )

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_key

    @property
    def entity_id_hex(self) -> str:
        """The public entity/wallet ID as a hex string."""
        return self.entity_id.hex()