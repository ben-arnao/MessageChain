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
    """Compute Merkle root from a list of transaction hashes.

    Uses tagged internal nodes (prefixed with 0x01) and tagged leaf nodes
    (prefixed with 0x00) to prevent second-preimage attacks via
    duplicate-last-element padding (CVE-2012-2459). Odd-length layers
    are padded with a sentinel value rather than duplicating the last
    element, so [A, B, C] and [A, B, C, C] produce different roots.
    """
    if not tx_hashes:
        return _hash(b"empty")

    # Tag leaves with 0x00 prefix for domain separation
    layer = [_hash(b"\x00" + h) for h in tx_hashes]

    while len(layer) > 1:
        # Pad odd layers with a sentinel (not a duplicate)
        if len(layer) % 2 == 1:
            layer.append(_hash(b"\x02sentinel"))
        next_layer = []
        for i in range(0, len(layer), 2):
            # Tag internal nodes with 0x01 prefix
            combined = _hash(b"\x01" + layer[i] + layer[i + 1])
            next_layer.append(combined)
        layer = next_layer

    return layer[0]


def _deserialize_authority_tx(data: dict):
    """Rehydrate an authority-related transaction by its "type" tag.

    Authority txs are consensus-visible operations on an entity's key
    material: set-authority-key (promote cold key), revoke (emergency
    kill-switch), and key-rotation (leaf-exhaustion recovery). They
    share a block slot so peers learn about key-state changes through
    the same gossip path as message and transfer txs.
    """
    from messagechain.core.authority_key import SetAuthorityKeyTransaction
    from messagechain.core.emergency_revoke import RevokeTransaction
    from messagechain.core.key_rotation import KeyRotationTransaction
    tag = data.get("type")
    if tag == "set_authority_key":
        return SetAuthorityKeyTransaction.deserialize(data)
    if tag == "revoke":
        return RevokeTransaction.deserialize(data)
    if tag == "key_rotation":
        return KeyRotationTransaction.deserialize(data)
    raise ValueError(f"Unknown authority tx type: {tag!r}")


def _deserialize_governance_tx(data: dict):
    """Rehydrate a governance transaction based on its "type" tag.

    Delegates to the concrete class's deserialize method so hash/signature
    integrity checks run the same way they would for a standalone tx.
    """
    from messagechain.governance.governance import (
        ProposalTransaction, VoteTransaction, DelegateTransaction,
        TreasurySpendTransaction, ValidatorEjectionProposal,
    )
    tag = data.get("type")
    if tag == "governance_proposal":
        return ProposalTransaction.deserialize(data)
    if tag == "governance_vote":
        return VoteTransaction.deserialize(data)
    if tag == "governance_delegate":
        return DelegateTransaction.deserialize(data)
    if tag == "treasury_spend":
        return TreasurySpendTransaction.deserialize(data)
    if tag == "validator_ejection":
        return ValidatorEjectionProposal.deserialize(data)
    raise ValueError(f"Unknown governance tx type: {tag!r}")


def compute_state_root(
    balances: dict[bytes, int],
    nonces: dict[bytes, int],
    staked: dict[bytes, int],
) -> bytes:
    """Compute a Merkle commitment to the full account state.

    Thin wrapper over messagechain.core.state_tree.compute_state_root.
    The real implementation is a Sparse Merkle Tree (O(TREE_DEPTH)
    per update, replacing the earlier O(N log N) full rebuild).

    Prefer `Blockchain.state_tree.root()` in hot paths — this function
    builds a fresh tree from scratch every call. It exists for callers
    that only have dicts in hand (tests, one-shot light-client
    commitments) and for backward compatibility with import sites that
    already reference `block.compute_state_root`.
    """
    # Lazy import to avoid a circular dependency with state_tree which
    # needs nothing from block.py — keeps the module graph acyclic.
    from messagechain.core.state_tree import compute_state_root as _impl
    return _impl(balances, nonces, staked)


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
    # On-chain governance traffic: proposals, votes, delegations, treasury
    # spend proposals, and validator-ejection proposals.  Each carries a
    # "type" tag in its serialized form that the block pipeline dispatches on.
    governance_txs: list = field(default_factory=list)
    # Authority-key traffic: SetAuthorityKey (hot -> cold promotion), Revoke
    # (emergency kill-switch, signed by cold), KeyRotation (leaf-exhaustion
    # migration). Block-included so every peer applies the same state
    # transitions — without this, a SetAuthorityKey or Revoke on one node
    # would never propagate to the rest of the network, defeating the
    # security model entirely.
    authority_txs: list = field(default_factory=list)
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
        if self.governance_txs:
            result["governance_txs"] = [tx.serialize() for tx in self.governance_txs]
        if self.authority_txs:
            result["authority_txs"] = [tx.serialize() for tx in self.authority_txs]
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
        governance_txs = []
        if data.get("governance_txs"):
            governance_txs = [_deserialize_governance_tx(g) for g in data["governance_txs"]]
        authority_txs = []
        if data.get("authority_txs"):
            authority_txs = [_deserialize_authority_tx(a) for a in data["authority_txs"]]
        block = cls(header=header, transactions=txs, validator_signatures=val_sigs,
                    slash_transactions=slash_txs, attestations=attestations,
                    transfer_transactions=transfer_txs, governance_txs=governance_txs,
                    authority_txs=authority_txs)
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
