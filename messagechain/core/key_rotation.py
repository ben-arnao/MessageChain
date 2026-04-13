"""
Key rotation transaction for MessageChain.

WOTS+ keys exhaust after 2^MERKLE_TREE_HEIGHT signatures (default: 2^20 =
1,048,576). Without key rotation, an entity's funds and identity are
permanently locked once all one-time keys are used. This module provides
an on-chain mechanism to rotate to a fresh Merkle tree before exhaustion.

The rotation is authorized by the entity's CURRENT key — they sign the
new public key with their old key, proving ownership. The chain then
updates the entity's public key to the new one.

Entities should rotate well before exhaustion (e.g., at 80% usage).
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, KEY_ROTATION_FEE, CHAIN_ID, MAX_TIMESTAMP_DRIFT
from messagechain.crypto.keys import Signature, verify_signature, KeyPair
from messagechain.identity.identity import Entity


@dataclass
class KeyRotationTransaction:
    """A transaction that rotates an entity's public key to a new Merkle tree."""
    entity_id: bytes
    old_public_key: bytes
    new_public_key: bytes
    rotation_number: int  # monotonic counter to prevent replay
    timestamp: float
    fee: int
    signature: Signature  # signed by the OLD key (proves current ownership)
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        """Canonical byte representation for signing."""
        return (
            CHAIN_ID
            + self.entity_id
            + self.old_public_key
            + self.new_public_key
            + struct.pack(">Q", self.rotation_number)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return hashlib.new(HASH_ALGO, self._signable_data()).digest()

    def serialize(self) -> dict:
        return {
            "type": "key_rotation",
            "entity_id": self.entity_id.hex(),
            "old_public_key": self.old_public_key.hex(),
            "new_public_key": self.new_public_key.hex(),
            "rotation_number": self.rotation_number,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "KeyRotationTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            old_public_key=bytes.fromhex(data["old_public_key"]),
            new_public_key=bytes.fromhex(data["new_public_key"]),
            rotation_number=data["rotation_number"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"KeyRotation tx hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return tx


def create_key_rotation(
    entity: Entity,
    new_keypair: KeyPair,
    rotation_number: int,
    fee: int | None = None,
) -> KeyRotationTransaction:
    """
    Create a key rotation transaction.

    The entity signs the new public key with their current (old) key,
    authorizing the chain to update their public key.

    Args:
        entity: The entity rotating their key (signs with current keypair)
        new_keypair: The fresh KeyPair to rotate to
        rotation_number: Monotonic counter (must match chain state)
        fee: Transaction fee (defaults to KEY_ROTATION_FEE)
    """
    if fee is None:
        fee = KEY_ROTATION_FEE

    tx = KeyRotationTransaction(
        entity_id=entity.entity_id,
        old_public_key=entity.public_key,
        new_public_key=new_keypair.public_key,
        rotation_number=rotation_number,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )

    # Sign with the OLD key to prove current ownership
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()

    return tx


def verify_key_rotation(tx: KeyRotationTransaction, current_public_key: bytes) -> bool:
    """
    Verify a key rotation transaction.

    Checks that:
    1. Timestamp is sane (positive and within drift window)
    2. The old_public_key matches the entity's current key on chain
    3. The signature is valid under the old key
    4. The new key is different from the old key
    """
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    if tx.old_public_key != current_public_key:
        return False
    if tx.new_public_key == tx.old_public_key:
        return False
    if tx.fee < KEY_ROTATION_FEE:
        return False

    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    return verify_signature(msg_hash, tx.signature, current_public_key)


def derive_rotated_keypair(entity: Entity, rotation_number: int) -> KeyPair:
    """
    Derive a new KeyPair for key rotation.

    Uses the entity's seed + rotation number to deterministically generate
    a fresh Merkle tree. Same private key + same rotation number = same new keys.
    This means the entity can always re-derive their rotated keys from their key.
    """
    rotation_seed = hashlib.new(
        HASH_ALGO,
        entity._seed + struct.pack(">Q", rotation_number),
    ).digest()
    return KeyPair.generate(rotation_seed)
