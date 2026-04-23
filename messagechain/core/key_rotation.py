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
from messagechain.config import (
    HASH_ALGO, KEY_ROTATION_FEE, CHAIN_ID, MAX_TIMESTAMP_DRIFT,
    SIG_VERSION_CURRENT,
)
from messagechain.crypto.hashing import default_hash
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
        """Canonical byte representation for signing.

        Includes sig_version from the attached signature so the tx_hash
        commits to the signer's crypto scheme (crypto-agility register).
        getattr fallback keeps None-signature test fixtures working.
        """
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"key_rotation"  # domain-separation tag: prevents cross-type sig replay
            + struct.pack(">B", sig_version)
            + self.entity_id
            + self.old_public_key
            + self.new_public_key
            + struct.pack(">Q", self.rotation_number)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return default_hash(self._signable_data())

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

    def to_bytes(self, state=None) -> bytes:
        """Binary: ENT entity_ref | 32 old_pk | 32 new_pk | u64 rotation_number |
        f64 timestamp | u64 fee | u32 sig_len | sig | 32 tx_hash.

        old_public_key and new_public_key are raw pubkeys, not entity
        references — they do not resolve through the state's
        entity_id↔entity_index registry.  The rotation tx carries both
        keys directly so a verifier can confirm the signature without
        any additional state lookup.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        return b"".join([
            encode_entity_ref(self.entity_id, state=state),
            self.old_public_key,
            self.new_public_key,
            struct.pack(">Q", self.rotation_number),
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "KeyRotationTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 32 + 32 + 8 + 8 + 8 + 4 + 32:
            raise ValueError("KeyRotation blob too short")
        entity_id, n = decode_entity_ref(data, off, state=state); off += n
        old_pk = bytes(data[off:off + 32]); off += 32
        new_pk = bytes(data[off:off + 32]); off += 32
        rotation_number = struct.unpack_from(">Q", data, off)[0]; off += 8
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("KeyRotation truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("KeyRotation has trailing bytes")
        tx = cls(
            entity_id=entity_id, old_public_key=old_pk,
            new_public_key=new_pk, rotation_number=rotation_number,
            timestamp=timestamp, fee=fee, signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"KeyRotation tx hash mismatch: declared {declared.hex()[:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx

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
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )

    # Sign with the OLD key to prove current ownership
    msg_hash = default_hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()

    return tx


def verify_key_rotation(
    tx: KeyRotationTransaction,
    current_public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """
    Verify a key rotation transaction.

    Checks that:
    1. Timestamp is sane (positive and within drift window)
    2. The old_public_key matches the entity's current key on chain
    3. The signature is valid under the old key
    4. The new key is different from the old key
    5. Fee covers KEY_ROTATION_FEE AND (post FEE_INCLUDES_SIGNATURE_HEIGHT)
       the signature-aware minimum, so an attacker can't churn rotations
       with large WOTS+ witnesses at the KEY_ROTATION_FEE floor (R5-A).
       KEY_ROTATION_FEE remains an absolute floor pre- and post-activation.
    """
    from messagechain.core.transaction import enforce_signature_aware_min_fee
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    if tx.old_public_key != current_public_key:
        return False
    if tx.new_public_key == tx.old_public_key:
        return False
    if not enforce_signature_aware_min_fee(
        tx.fee,
        signature_bytes=len(tx.signature.to_bytes()),
        current_height=current_height,
        flat_floor=KEY_ROTATION_FEE,
    ):
        return False

    msg_hash = default_hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, current_public_key)


def derive_rotated_keypair(
    entity: Entity,
    rotation_number: int,
    progress=None,
) -> KeyPair:
    """
    Derive a new KeyPair for key rotation.

    Uses the entity's seed + rotation number to deterministically generate
    a fresh Merkle tree. Same private key + same rotation number = same new keys.
    This means the entity can always re-derive their rotated keys from their key.

    `progress`, if provided, is called with each leaf index as it is derived —
    the same callback shape KeyPair.generate accepts. Use this to drive a
    status indicator during rotations on full-height trees (MERKLE_TREE_HEIGHT
    = 20 means ~1M derivations, minutes of work with no visible output).
    """
    rotation_seed = hashlib.new(
        HASH_ALGO,
        entity._seed + struct.pack(">Q", rotation_number),
    ).digest()
    return KeyPair.generate(rotation_seed, progress=progress)
