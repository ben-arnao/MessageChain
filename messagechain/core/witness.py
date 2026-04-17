"""
Witness separation — split block storage into state-transition data and
witness data (WOTS signatures + Merkle auth paths).

After a block is FINALIZED (2/3 stake signed), signatures serve only
auditability, not consensus safety.  Separating them lets full nodes
carry witness data only for recent/unfinalized blocks, while witness-
archive nodes carry everything.  Nothing is ever deleted — every byte
persists somewhere forever.

Key design property: tx_hash is computed from _signable_data() which
EXCLUDES the signature, so stripping witnesses preserves tx_hash exactly.
No SegWit-style txid/wtxid split is needed.
"""

import hashlib
import struct
from messagechain.config import HASH_ALGO
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import Signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# Sentinel signature for witness-stripped transactions.  Empty lists +
# empty bytes so the Signature dataclass is structurally valid but
# trivially distinguishable from a real WOTS+ signature.
WITNESS_STRIPPED_SENTINEL = Signature(
    wots_signature=[],
    leaf_index=0,
    auth_path=[],
    wots_public_key=b"",
    wots_public_seed=b"",
)


def compute_witness_root(transactions: list) -> bytes:
    """Compute Merkle root over all transaction witness data.

    Each transaction contributes one leaf: the hash of its signature's
    canonical bytes.  For blocks with no transactions, returns SHA256(b"").

    The witness_root is included in BlockHeader.signable_data() so the
    block_hash commits to witnesses even when they are stored separately.
    """
    if not transactions:
        return hashlib.new(HASH_ALGO, b"").digest()

    leaves = []
    for tx in transactions:
        sig_bytes = tx.signature.canonical_bytes() if tx.signature else b""
        leaves.append(_hash(sig_bytes))

    # Build Merkle tree over leaves (same structure as tx Merkle root)
    layer = list(leaves)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(_hash(b"\x02witness_sentinel"))
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = _hash(layer[i] + layer[i + 1])
            next_layer.append(combined)
        layer = next_layer

    return layer[0]


def tx_has_witness(tx: MessageTransaction) -> bool:
    """Check if a transaction has witness data (non-sentinel signature)."""
    if tx.signature is None:
        return False
    if not tx.signature.wots_signature and not tx.signature.wots_public_key:
        return False
    return True


def strip_tx_witness(tx: MessageTransaction) -> MessageTransaction:
    """Return a copy of the transaction with its signature stripped.

    Preserves tx_hash (which excludes the signature by design) and all
    other fields.  The stripped tx carries the sentinel signature.
    """
    return MessageTransaction(
        entity_id=tx.entity_id,
        message=tx.message,
        timestamp=tx.timestamp,
        nonce=tx.nonce,
        fee=tx.fee,
        signature=Signature([], 0, [], b"", b""),
        version=tx.version,
        ttl=tx.ttl,
        compression_flag=tx.compression_flag,
        tx_hash=tx.tx_hash,
        witness_hash=tx.witness_hash,
    )


def get_tx_witness_data(tx: MessageTransaction) -> bytes:
    """Serialize a transaction's witness data (signature) for separate storage."""
    return tx.signature.to_bytes()


def attach_tx_witness(stripped_tx: MessageTransaction, witness_data: bytes) -> MessageTransaction:
    """Reattach witness data to a stripped transaction."""
    sig = Signature.from_bytes(witness_data)
    return MessageTransaction(
        entity_id=stripped_tx.entity_id,
        message=stripped_tx.message,
        timestamp=stripped_tx.timestamp,
        nonce=stripped_tx.nonce,
        fee=stripped_tx.fee,
        signature=sig,
        version=stripped_tx.version,
        ttl=stripped_tx.ttl,
        compression_flag=stripped_tx.compression_flag,
        tx_hash=stripped_tx.tx_hash,
        witness_hash=stripped_tx.witness_hash,
    )


def strip_block_witnesses(block) -> "Block":
    """Return a new Block with all tx signatures stripped.

    The witness_root in the header is preserved — it was computed from
    the original witnesses before stripping.  The block_hash changes
    because the block is reconstructed, but the header data (including
    witness_root) remains identical, so the block_hash still matches.
    """
    from messagechain.core.block import Block, BlockHeader
    import copy

    stripped_txs = [strip_tx_witness(tx) for tx in block.transactions]

    # Deep copy header to avoid mutating original
    header = copy.deepcopy(block.header)

    stripped_block = Block(
        header=header,
        transactions=stripped_txs,
        validator_signatures=block.validator_signatures,
        slash_transactions=block.slash_transactions,
        attestations=block.attestations,
        transfer_transactions=block.transfer_transactions,
        governance_txs=block.governance_txs,
        authority_txs=block.authority_txs,
        stake_transactions=block.stake_transactions,
        unstake_transactions=block.unstake_transactions,
        finality_votes=block.finality_votes,
    )
    # block_hash is header-derived, so it should match the original
    stripped_block.block_hash = stripped_block._compute_hash()
    return stripped_block


def get_block_witness_data(block) -> bytes:
    """Serialize all witness data from a block for separate storage.

    Format: u32 tx_count | for each tx: u32 witness_len | witness_bytes
    """
    parts = [struct.pack(">I", len(block.transactions))]
    for tx in block.transactions:
        w = get_tx_witness_data(tx)
        parts.append(struct.pack(">I", len(w)))
        parts.append(w)
    return b"".join(parts)


def attach_block_witnesses(stripped_block, witness_data: bytes):
    """Reattach witness data to a stripped block."""
    from messagechain.core.block import Block
    import copy

    offset = 0
    tx_count = struct.unpack_from(">I", witness_data, offset)[0]
    offset += 4

    if tx_count != len(stripped_block.transactions):
        raise ValueError(
            f"Witness data tx count {tx_count} != block tx count "
            f"{len(stripped_block.transactions)}"
        )

    restored_txs = []
    for tx in stripped_block.transactions:
        w_len = struct.unpack_from(">I", witness_data, offset)[0]
        offset += 4
        w_bytes = witness_data[offset:offset + w_len]
        offset += w_len
        restored_txs.append(attach_tx_witness(tx, w_bytes))

    header = copy.deepcopy(stripped_block.header)

    restored = Block(
        header=header,
        transactions=restored_txs,
        validator_signatures=stripped_block.validator_signatures,
        slash_transactions=stripped_block.slash_transactions,
        attestations=stripped_block.attestations,
        transfer_transactions=stripped_block.transfer_transactions,
        governance_txs=stripped_block.governance_txs,
        authority_txs=stripped_block.authority_txs,
        stake_transactions=stripped_block.stake_transactions,
        unstake_transactions=stripped_block.unstake_transactions,
        finality_votes=stripped_block.finality_votes,
    )
    restored.block_hash = restored._compute_hash()
    return restored
