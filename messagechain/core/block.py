"""
Block structure for MessageChain.

Each block contains a set of message transactions, linked to the previous
block via hash chaining. The Merkle root of all transaction hashes enables
efficient verification of transaction inclusion.
"""

import hashlib
import struct
import time
import json
from dataclasses import dataclass, field
from messagechain.config import HASH_ALGO
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import Signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def compute_merkle_root(tx_hashes: list[bytes]) -> bytes:
    """Compute Merkle root from a list of transaction hashes."""
    if not tx_hashes:
        return _hash(b"empty")

    # Pad to even number
    layer = list(tx_hashes)
    if len(layer) % 2 == 1:
        layer.append(layer[-1])

    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = _hash(layer[i] + layer[i + 1])
            next_layer.append(combined)
        layer = next_layer
        if len(layer) > 1 and len(layer) % 2 == 1:
            layer.append(layer[-1])

    return layer[0]


@dataclass
class BlockHeader:
    version: int
    block_number: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: float
    proposer_id: bytes
    proposer_signature: Signature | None = None

    def signable_data(self) -> bytes:
        return (
            struct.pack(">I", self.version)
            + struct.pack(">Q", self.block_number)
            + self.prev_hash
            + self.merkle_root
            + struct.pack(">d", self.timestamp)
            + self.proposer_id
        )

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "block_number": self.block_number,
            "prev_hash": self.prev_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "timestamp": self.timestamp,
            "proposer_id": self.proposer_id.hex(),
            "proposer_signature": self.proposer_signature.serialize() if self.proposer_signature else None,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "BlockHeader":
        return cls(
            version=data["version"],
            block_number=data["block_number"],
            prev_hash=bytes.fromhex(data["prev_hash"]),
            merkle_root=bytes.fromhex(data["merkle_root"]),
            timestamp=data["timestamp"],
            proposer_id=bytes.fromhex(data["proposer_id"]),
            proposer_signature=Signature.deserialize(data["proposer_signature"]) if data.get("proposer_signature") else None,
        )


@dataclass
class Block:
    header: BlockHeader
    transactions: list[MessageTransaction]
    validator_signatures: list[tuple[bytes, Signature]] = field(default_factory=list)
    block_hash: bytes = b""

    def __post_init__(self):
        if not self.block_hash:
            self.block_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        return _hash(self.header.signable_data())

    def serialize(self) -> dict:
        return {
            "header": self.header.serialize(),
            "transactions": [tx.serialize() for tx in self.transactions],
            "validator_signatures": [
                {"entity_id": eid.hex(), "signature": sig.serialize()}
                for eid, sig in self.validator_signatures
            ],
            "block_hash": self.block_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "Block":
        header = BlockHeader.deserialize(data["header"])
        txs = [MessageTransaction.deserialize(t) for t in data["transactions"]]
        val_sigs = [
            (bytes.fromhex(vs["entity_id"]), Signature.deserialize(vs["signature"]))
            for vs in data.get("validator_signatures", [])
        ]
        block = cls(header=header, transactions=txs, validator_signatures=val_sigs)
        block.block_hash = bytes.fromhex(data["block_hash"])
        return block


def create_genesis_block(proposer_entity) -> Block:
    """Create the genesis block (block 0) with no transactions."""
    header = BlockHeader(
        version=1,
        block_number=0,
        prev_hash=b"\x00" * 32,
        merkle_root=_hash(b"genesis"),
        timestamp=time.time(),
        proposer_id=proposer_entity.entity_id,
    )

    # Sign the genesis block
    header_hash = _hash(header.signable_data())
    header.proposer_signature = proposer_entity.keypair.sign(header_hash)

    block = Block(header=header, transactions=[])
    block.block_hash = block._compute_hash()
    return block
