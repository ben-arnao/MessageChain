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

# Account count at which compute_state_root starts logging a scaling
# warning. See compute_state_root's docstring for context.
STATE_ROOT_WARN_THRESHOLD = 100_000


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


def compute_state_root(
    balances: dict[bytes, int],
    nonces: dict[bytes, int],
    staked: dict[bytes, int],
) -> bytes:
    """
    Compute a Merkle commitment to the full account state.

    This enables light clients to verify account state without replaying
    the entire chain. Each leaf is hash(entity_id || balance || nonce || stake).
    The leaves are sorted by entity_id for determinism.

    Scaling note: this is O(N log N) in the total account count because
    every block recomputes the root from scratch. Each block creation and
    each block validation pay this cost in full. At ~1M accounts the
    recomputation dominates block processing; at ~10M it makes IBD
    impractical. The correct long-term fix is an incremental Merkle
    Patricia Trie that only touches modified leaves per block, matching
    Ethereum's state trie. That is a structural change tracked as a
    follow-up. Until it lands, operators should watch
    `len(balances)` — if it approaches STATE_ROOT_WARN_THRESHOLD the
    function emits a log warning so the scaling limit is not a surprise.
    """
    if not balances:
        return _hash(b"empty_state")

    # Soft warning at ~100K accounts. Chosen because on commodity hardware
    # the full recomputation starts to noticeably eat into a target
    # block-production budget around there (a few hundred milliseconds).
    # Not a hard error — just a loud hint to operators that the current
    # state-commitment implementation is approaching its ceiling.
    if len(balances) > STATE_ROOT_WARN_THRESHOLD:
        import logging
        logging.getLogger(__name__).warning(
            "compute_state_root: %d accounts is near the scaling limit "
            "of the full-rebuild Merkle commitment. Migration to an "
            "incremental Merkle Patricia Trie is required before N grows "
            "much larger — every block pays O(N log N) in full.",
            len(balances),
        )

    leaves = []
    for entity_id in sorted(balances.keys()):
        balance = balances.get(entity_id, 0)
        nonce = nonces.get(entity_id, 0)
        stake = staked.get(entity_id, 0)
        leaf = _hash(
            entity_id
            + struct.pack(">Q", balance)
            + struct.pack(">Q", nonce)
            + struct.pack(">Q", stake)
        )
        leaves.append(leaf)

    # Build Merkle tree over sorted leaves
    layer = list(leaves)
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
    state_root: bytes = b"\x00" * 32  # Merkle root of account state
    randao_mix: bytes = b"\x00" * 32  # accumulated RANDAO entropy (post-sign derived)
    proposer_signature: Signature | None = None

    def signable_data(self) -> bytes:
        # NOTE: randao_mix is intentionally NOT included here. It is derived
        # from the proposer signature (which is itself over signable_data),
        # so including it would create a circular dependency. The randao_mix
        # is bound to the block via _compute_hash() instead.
        return (
            struct.pack(">I", self.version)
            + struct.pack(">Q", self.block_number)
            + self.prev_hash
            + self.merkle_root
            + self.state_root
            + struct.pack(">Q", int(self.timestamp))
            + self.proposer_id
        )

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "block_number": self.block_number,
            "prev_hash": self.prev_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "state_root": self.state_root.hex(),
            "timestamp": self.timestamp,
            "proposer_id": self.proposer_id.hex(),
            "randao_mix": self.randao_mix.hex(),
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
            state_root=bytes.fromhex(data["state_root"]) if data.get("state_root") else b"\x00" * 32,
            randao_mix=bytes.fromhex(data["randao_mix"]) if data.get("randao_mix") else b"\x00" * 32,
            proposer_signature=Signature.deserialize(data["proposer_signature"]) if data.get("proposer_signature") else None,
        )


@dataclass
class Block:
    header: BlockHeader
    transactions: list[MessageTransaction]
    validator_signatures: list[tuple[bytes, Signature]] = field(default_factory=list)
    slash_transactions: list = field(default_factory=list)  # list[SlashTransaction]
    attestations: list = field(default_factory=list)  # list[Attestation] for parent block
    transfer_transactions: list = field(default_factory=list)  # list[TransferTransaction]
    block_hash: bytes = b""

    def __post_init__(self):
        if not self.block_hash:
            self.block_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        # Bind both signable_data and randao_mix into block_hash. randao_mix
        # is derived from the proposer signature post-signing, so it cannot
        # live in signable_data, but it must still be tamper-evident.
        return _hash(self.header.signable_data() + self.header.randao_mix)

    def serialize(self) -> dict:
        result = {
            "header": self.header.serialize(),
            "transactions": [tx.serialize() for tx in self.transactions],
            "validator_signatures": [
                {"entity_id": eid.hex(), "signature": sig.serialize()}
                for eid, sig in self.validator_signatures
            ],
            "block_hash": self.block_hash.hex(),
        }
        if self.slash_transactions:
            result["slash_transactions"] = [tx.serialize() for tx in self.slash_transactions]
        if self.attestations:
            result["attestations"] = [att.serialize() for att in self.attestations]
        if self.transfer_transactions:
            result["transfer_transactions"] = [tx.serialize() for tx in self.transfer_transactions]
        return result

    @classmethod
    def deserialize(cls, data: dict) -> "Block":
        header = BlockHeader.deserialize(data["header"])
        txs = [MessageTransaction.deserialize(t) for t in data["transactions"]]
        val_sigs = [
            (bytes.fromhex(vs["entity_id"]), Signature.deserialize(vs["signature"]))
            for vs in data.get("validator_signatures", [])
        ]
        # Lazy import to avoid circular dependency
        slash_txs = []
        if data.get("slash_transactions"):
            from messagechain.consensus.slashing import SlashTransaction
            slash_txs = [SlashTransaction.deserialize(s) for s in data["slash_transactions"]]
        attestations = []
        if data.get("attestations"):
            from messagechain.consensus.attestation import Attestation
            attestations = [Attestation.deserialize(a) for a in data["attestations"]]
        transfer_txs = []
        if data.get("transfer_transactions"):
            from messagechain.core.transfer import TransferTransaction
            transfer_txs = [TransferTransaction.deserialize(t) for t in data["transfer_transactions"]]
        block = cls(header=header, transactions=txs, validator_signatures=val_sigs,
                    slash_transactions=slash_txs, attestations=attestations,
                    transfer_transactions=transfer_txs)
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = block._compute_hash()
        declared_hash = bytes.fromhex(data["block_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"Block hash mismatch: declared {data['block_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
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
