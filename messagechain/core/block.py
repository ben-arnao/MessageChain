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
from messagechain.config import (
    HASH_ALGO, HASH_VERSION_CURRENT,
    BLOCK_SERIALIZATION_VERSION, validate_block_serialization_version,
)
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
        ProposalTransaction, VoteTransaction,
        TreasurySpendTransaction,
    )
    tag = data.get("type")
    if tag == "governance_proposal":
        return ProposalTransaction.deserialize(data)
    if tag == "governance_vote":
        return VoteTransaction.deserialize(data)
    if tag == "treasury_spend":
        return TreasurySpendTransaction.deserialize(data)
    raise ValueError(f"Unknown governance tx type: {tag!r}")


def compute_state_root(
    balances: dict[bytes, int],
    nonces: dict[bytes, int],
    staked: dict[bytes, int],
    *,
    authority_keys: dict[bytes, bytes] | None = None,
    public_keys: dict[bytes, bytes] | None = None,
    leaf_watermarks: dict[bytes, int] | None = None,
    key_rotation_counts: dict[bytes, int] | None = None,
    revoked_entities: "set[bytes] | frozenset[bytes] | None" = None,
    slashed_validators: "set[bytes] | frozenset[bytes] | None" = None,
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
    return _impl(
        balances, nonces, staked,
        authority_keys=authority_keys,
        public_keys=public_keys,
        leaf_watermarks=leaf_watermarks,
        key_rotation_counts=key_rotation_counts,
        revoked_entities=revoked_entities,
        slashed_validators=slashed_validators,
    )


@dataclass
class BlockHeader:
    version: int
    block_number: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: float
    proposer_id: bytes
    state_root: bytes = b"\x00" * 32  # Merkle root of account state
    witness_root: bytes = b"\x00" * 32  # Merkle root over tx witness data (sigs + auth paths)
    randao_mix: bytes = b"\x00" * 32  # accumulated RANDAO entropy (post-sign derived)
    proposer_signature: Signature | None = None
    # Crypto-agility: identifies the hash algorithm used for this block's
    # block_hash (over the header) and tx_root. Carried on every header so a
    # governance proposal can widen the accepted set for a future scheme
    # without a chain reset.  See config.HASH_VERSION_* and
    # validate_hash_version.
    hash_version: int = HASH_VERSION_CURRENT
    # Inclusion attestation: Merkle root of proposer's mempool tx hashes
    # at proposal time.  Committed via signable_data so the proposer's
    # block signature covers it transitively — no separate snapshot sig.
    mempool_snapshot_root: bytes = b"\x00" * 32

    def signable_data(self) -> bytes:
        # NOTE: randao_mix is intentionally NOT included here. It is derived
        # from the proposer signature (which is itself over signable_data),
        # so including it would create a circular dependency. The randao_mix
        # is bound to the block via _compute_hash() instead.
        #
        # hash_version is committed here so the header hash itself is
        # tamper-evident against a version swap: flipping the byte changes
        # the hash, breaking the prev_hash chain and the proposer signature.
        return (
            struct.pack(">I", self.version)
            + struct.pack(">B", self.hash_version)
            + struct.pack(">Q", self.block_number)
            + self.prev_hash
            + self.merkle_root
            + self.state_root
            + self.witness_root
            + struct.pack(">Q", int(self.timestamp))
            + self.proposer_id
            + self.mempool_snapshot_root
        )

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "hash_version": self.hash_version,
            "block_number": self.block_number,
            "prev_hash": self.prev_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "state_root": self.state_root.hex(),
            "witness_root": self.witness_root.hex(),
            "timestamp": self.timestamp,
            "proposer_id": self.proposer_id.hex(),
            "randao_mix": self.randao_mix.hex(),
            "mempool_snapshot_root": self.mempool_snapshot_root.hex(),
            "proposer_signature": self.proposer_signature.serialize() if self.proposer_signature else None,
        }

    def to_bytes(self) -> bytes:
        """Compact binary encoding for storage/wire.

        Layout:
            u32  version
            u8   hash_version        <- crypto-agility register
            u64  block_number
            32   prev_hash
            32   merkle_root
            32   state_root
            32   witness_root        <- Merkle root over tx witness data
            f64  timestamp
            32   proposer_id
            32   randao_mix
            32   mempool_snapshot_root  <- inclusion attestation
            u32  sig_blob_len  (0 = no proposer signature)
            N    sig_blob

        hash_version sits right after `version` so a header blob is
        unambiguously one flavor of hash commitment end-to-end — a
        validator's decoder reads the version before any 32-byte hash
        field and can dispatch when multiple schemes are active.
        """
        if self.proposer_signature is None:
            sig_blob = b""
        else:
            sig_blob = self.proposer_signature.to_bytes()
        return b"".join([
            struct.pack(">I", self.version),
            struct.pack(">B", self.hash_version),
            struct.pack(">Q", self.block_number),
            self.prev_hash,
            self.merkle_root,
            self.state_root,
            self.witness_root,
            struct.pack(">d", float(self.timestamp)),
            self.proposer_id,
            self.randao_mix,
            self.mempool_snapshot_root,
            struct.pack(">I", len(sig_blob)),
            sig_blob,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "BlockHeader":
        off = 0
        # +1 byte for the u8 hash_version field (crypto agility).
        # +32 bytes for the witness_root field.
        # +32 bytes for the mempool_snapshot_root field.
        expected_min = 4 + 1 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 32 + 32 + 4
        if len(data) < expected_min:
            raise ValueError("BlockHeader blob too short")
        version = struct.unpack_from(">I", data, off)[0]; off += 4
        hash_version = struct.unpack_from(">B", data, off)[0]; off += 1
        # Reject unknown hash versions at decode time so a malformed blob
        # never reaches validate_block.  The consensus-layer check is still
        # the primary gate; this one cuts off DoS via spray-and-pray blobs.
        from messagechain.config import validate_hash_version
        ok, reason = validate_hash_version(hash_version)
        if not ok:
            raise ValueError(f"Invalid block header: {reason}")
        block_number = struct.unpack_from(">Q", data, off)[0]; off += 8
        prev_hash = bytes(data[off:off + 32]); off += 32
        merkle_root = bytes(data[off:off + 32]); off += 32
        state_root = bytes(data[off:off + 32]); off += 32
        witness_root = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        proposer_id = bytes(data[off:off + 32]); off += 32
        randao_mix = bytes(data[off:off + 32]); off += 32
        mempool_snapshot_root = bytes(data[off:off + 32]); off += 32
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len > len(data):
            raise ValueError("BlockHeader truncated at signature")
        if sig_len == 0:
            proposer_signature = None
        else:
            proposer_signature = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        if off != len(data):
            raise ValueError("BlockHeader has trailing bytes")
        return cls(
            version=version, block_number=block_number,
            prev_hash=prev_hash, merkle_root=merkle_root,
            state_root=state_root, witness_root=witness_root,
            timestamp=timestamp,
            proposer_id=proposer_id, randao_mix=randao_mix,
            proposer_signature=proposer_signature,
            hash_version=hash_version,
            mempool_snapshot_root=mempool_snapshot_root,
        )

    @classmethod
    def deserialize(cls, data: dict) -> "BlockHeader":
        # Default missing hash_version to HASH_VERSION_CURRENT so pre-
        # migration dicts round-trip cleanly; a present-but-unknown value
        # falls through to validate_block's consensus check and is rejected
        # there with a human-readable reason.
        return cls(
            version=data["version"],
            block_number=data["block_number"],
            prev_hash=bytes.fromhex(data["prev_hash"]),
            merkle_root=bytes.fromhex(data["merkle_root"]),
            timestamp=data["timestamp"],
            proposer_id=bytes.fromhex(data["proposer_id"]),
            state_root=bytes.fromhex(data["state_root"]) if data.get("state_root") else b"\x00" * 32,
            witness_root=bytes.fromhex(data["witness_root"]) if data.get("witness_root") else b"\x00" * 32,
            randao_mix=bytes.fromhex(data["randao_mix"]) if data.get("randao_mix") else b"\x00" * 32,
            proposer_signature=Signature.deserialize(data["proposer_signature"]) if data.get("proposer_signature") else None,
            hash_version=data.get("hash_version", HASH_VERSION_CURRENT),
            mempool_snapshot_root=bytes.fromhex(data["mempool_snapshot_root"]) if data.get("mempool_snapshot_root") else b"\x00" * 32,
        )


@dataclass
class Block:
    header: BlockHeader
    transactions: list[MessageTransaction]
    validator_signatures: list[tuple[bytes, Signature]] = field(default_factory=list)
    slash_transactions: list = field(default_factory=list)  # list[SlashTransaction]
    attestations: list = field(default_factory=list)  # list[Attestation] for parent block
    transfer_transactions: list = field(default_factory=list)  # list[TransferTransaction]
    # On-chain governance traffic: proposals, votes, and treasury-spend
    # proposals.  Each carries a "type" tag in its serialized form that
    # the block pipeline dispatches on.
    governance_txs: list = field(default_factory=list)
    # Authority-key traffic: SetAuthorityKey (hot -> cold promotion), Revoke
    # (emergency kill-switch, signed by cold), KeyRotation (leaf-exhaustion
    # migration). Block-included so every peer applies the same state
    # transitions — without this, a SetAuthorityKey or Revoke on one node
    # would never propagate to the rest of the network, defeating the
    # security model entirely.
    authority_txs: list = field(default_factory=list)
    # On-chain staking traffic: StakeTransaction locks a validator's liquid
    # tokens as stake.  Block-included so every peer agrees on the validator
    # set — previously the RPC path queued these in server-local state and
    # they never propagated, breaking consensus on who can propose/attest.
    stake_transactions: list = field(default_factory=list)
    # Unstake txs are on-chain because unbonding releases stake weight
    # deterministically across all peers — the validator set must agree
    # on who is unbonding and when.  Same block-pipeline shape as
    # stake_transactions but dispatched to supply.unstake on apply.
    unstake_transactions: list = field(default_factory=list)
    # (The explicit RegistrationTransaction field was removed in the
    # receive-to-exist refactor.  An entity now enters chain state
    # implicitly when it first RECEIVES a transfer, and its pubkey is
    # installed during its FIRST outgoing transfer via the
    # `TransferTransaction.sender_pubkey` reveal.  Removing the field
    # is a consensus-format change — blocks produced by pre-refactor
    # nodes cannot round-trip through the new decoder.)
    # Long-range-attack defense: FinalityVotes signed by validators
    # that commit to a specific block hash at a specific height.  When
    # >= 2/3 of stake has signed votes for a block and those votes
    # have been included in any later block, the target block becomes
    # FINALIZED — no subsequent reorg may revert it regardless of
    # stake weight.  Proposers that include votes earn a small bounty
    # from treasury (FINALITY_VOTE_INCLUSION_REWARD).  Defense is
    # additive to the existing attestation-layer finality and
    # persists across restart, so a cold-booted node inherits the
    # chain's irreversibility commitments.
    finality_votes: list = field(default_factory=list)  # list[FinalityVote]
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
        if self.stake_transactions:
            result["stake_transactions"] = [tx.serialize() for tx in self.stake_transactions]
        if self.unstake_transactions:
            result["unstake_transactions"] = [tx.serialize() for tx in self.unstake_transactions]
        if self.finality_votes:
            result["finality_votes"] = [v.serialize() for v in self.finality_votes]
        return result

    def to_bytes(self, state=None) -> bytes:
        """Compact binary encoding for storage/wire.

        Every tx-list field is length-prefixed — empty lists contribute
        exactly 4 bytes (a zero count) regardless of whether the
        corresponding dict-format serialize() would have omitted them.
        This keeps the decoder straight-line and avoids an optional-field
        bitmap.

        Authority and governance tx lists carry polymorphic tx types,
        so each element in those lists is prefixed with a 1-byte
        discriminator (see _encode_authority_tx / _encode_governance_tx).

        Layout:
            header_blob_len  (u32)  + header_blob
            tx_count         (u32)  + N x (tx_len u32 + tx_blob)
            vsig_count       (u32)  + N x (32 entity_id + sig_len u32 + sig_blob)
            slash_count      (u32)  + N x (slash_len u32 + slash_blob)
            att_count        (u32)  + N x (att_len u32 + att_blob)
            xfer_count       (u32)  + N x (xfer_len u32 + xfer_blob)
            gov_count        (u32)  + N x (u8 kind + gov_len u32 + gov_blob)
            auth_count       (u32)  + N x (u8 kind + auth_len u32 + auth_blob)
            stake_count      (u32)  + N x (stake_len u32 + stake_blob)
            unstake_count    (u32)  + N x (unstake_len u32 + unstake_blob)
            fvote_count      (u32)  + N x (fvote_len u32 + fvote_blob)
            32               block_hash

        (The `reg_count`/registration-tx block slot was removed with
        the receive-to-exist refactor — new entities enter state
        implicitly via Transfer txs, so there is no RegistrationTransaction
        type on the wire anymore.  This is a consensus-format change.)

        `state` is threaded down to each child tx's `to_bytes(state)`
        so the varint-index compact form is emitted when an entity
        registry is available.  Without state, child txs emit the
        legacy 32-byte-id form.
        """
        from messagechain.consensus.slashing import SlashTransaction
        from messagechain.consensus.attestation import Attestation
        from messagechain.core.transfer import TransferTransaction
        from messagechain.core.staking import (
            StakeTransaction, UnstakeTransaction,
        )
        from messagechain.core.authority_key import SetAuthorityKeyTransaction
        from messagechain.core.emergency_revoke import RevokeTransaction
        from messagechain.core.key_rotation import KeyRotationTransaction
        from messagechain.governance.governance import (
            ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
        )

        def _tx_bytes(item):
            # Every participating tx type now accepts an optional state
            # arg; fall back to the no-arg form for any legacy types
            # that don't yet take one (slash txs carry no entity_id at
            # top level — they nest evidence that is block-internal).
            try:
                return item.to_bytes(state=state)
            except TypeError:
                return item.to_bytes()

        def enc_list(items):
            parts = [struct.pack(">I", len(items))]
            for item in items:
                b = _tx_bytes(item)
                parts.append(struct.pack(">I", len(b)))
                parts.append(b)
            return b"".join(parts)

        def enc_vsigs():
            parts = [struct.pack(">I", len(self.validator_signatures))]
            for eid, sig in self.validator_signatures:
                sb = sig.to_bytes()
                parts.append(eid)
                parts.append(struct.pack(">I", len(sb)))
                parts.append(sb)
            return b"".join(parts)

        def enc_authority():
            parts = [struct.pack(">I", len(self.authority_txs))]
            for t in self.authority_txs:
                if isinstance(t, SetAuthorityKeyTransaction):
                    kind = 0
                elif isinstance(t, RevokeTransaction):
                    kind = 1
                elif isinstance(t, KeyRotationTransaction):
                    kind = 2
                else:
                    raise ValueError(f"Unknown authority tx: {type(t).__name__}")
                b = _tx_bytes(t)
                parts.append(struct.pack(">B", kind))
                parts.append(struct.pack(">I", len(b)))
                parts.append(b)
            return b"".join(parts)

        def enc_governance():
            parts = [struct.pack(">I", len(self.governance_txs))]
            for t in self.governance_txs:
                if isinstance(t, ProposalTransaction):
                    kind = 0
                elif isinstance(t, VoteTransaction):
                    kind = 1
                elif isinstance(t, TreasurySpendTransaction):
                    kind = 2
                else:
                    raise ValueError(f"Unknown governance tx: {type(t).__name__}")
                b = _tx_bytes(t)
                parts.append(struct.pack(">B", kind))
                parts.append(struct.pack(">I", len(b)))
                parts.append(b)
            return b"".join(parts)

        header_blob = self.header.to_bytes()
        return b"".join([
            # Leading u8 wire-format version — see
            # config.BLOCK_SERIALIZATION_VERSION.  Lets a future
            # governance proposal bump the binary layout without
            # silently invalidating existing chain data.  Decoder
            # rejects unknown values at parse time with a clear
            # error rather than letting a layout change surface as
            # a cryptic hash mismatch further down the pipeline.
            struct.pack(">B", BLOCK_SERIALIZATION_VERSION),
            struct.pack(">I", len(header_blob)),
            header_blob,
            enc_list(self.transactions),
            enc_vsigs(),
            enc_list(self.slash_transactions),
            enc_list(self.attestations),
            enc_list(self.transfer_transactions),
            enc_governance(),
            enc_authority(),
            enc_list(self.stake_transactions),
            enc_list(self.unstake_transactions),
            enc_list(self.finality_votes),
            self.block_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "Block":
        from messagechain.consensus.slashing import SlashTransaction
        from messagechain.consensus.attestation import Attestation
        from messagechain.core.transfer import TransferTransaction
        from messagechain.core.staking import (
            StakeTransaction, UnstakeTransaction,
        )
        from messagechain.core.authority_key import SetAuthorityKeyTransaction
        from messagechain.core.emergency_revoke import RevokeTransaction
        from messagechain.core.key_rotation import KeyRotationTransaction
        from messagechain.governance.governance import (
            ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
        )

        off = 0

        def take(n):
            nonlocal off
            if off + n > len(data):
                raise ValueError("Block blob truncated")
            b = bytes(data[off:off + n])
            off += n
            return b

        def take_u32():
            nonlocal off
            if off + 4 > len(data):
                raise ValueError("Block blob truncated at u32")
            v = struct.unpack_from(">I", data, off)[0]
            off += 4
            return v

        def take_u8():
            nonlocal off
            if off + 1 > len(data):
                raise ValueError("Block blob truncated at u8")
            v = struct.unpack_from(">B", data, off)[0]
            off += 1
            return v

        def dec_list(klass):
            n = take_u32()
            out = []
            for _ in range(n):
                ln = take_u32()
                blob = take(ln)
                # Every participating tx type now accepts an optional
                # state kw; legacy types (e.g., SlashTransaction) don't
                # need it and fall through to the no-kw path.
                try:
                    out.append(klass.from_bytes(blob, state=state))
                except TypeError:
                    out.append(klass.from_bytes(blob))
            return out

        # Wire-format gate: a leading u8 marks the binary layout version.
        # Unknown values are rejected at the parse boundary with a clear
        # error so a future layout change doesn't surface as a cryptic
        # hash mismatch further down.  See config.BLOCK_SERIALIZATION_VERSION.
        ser_version = take_u8()
        ok, reason = validate_block_serialization_version(ser_version)
        if not ok:
            raise ValueError(f"Block: {reason}")

        header_len = take_u32()
        header = BlockHeader.from_bytes(take(header_len))

        txs = dec_list(MessageTransaction)

        # validator_signatures: count | [32 eid + u32 sig_len + sig]
        vsig_count = take_u32()
        val_sigs = []
        for _ in range(vsig_count):
            eid = take(32)
            sig_len = take_u32()
            sig = Signature.from_bytes(take(sig_len))
            val_sigs.append((eid, sig))

        slash_txs = dec_list(SlashTransaction)
        attestations = dec_list(Attestation)
        transfer_txs = dec_list(TransferTransaction)

        def _call_from_bytes(klass, blob):
            try:
                return klass.from_bytes(blob, state=state)
            except TypeError:
                return klass.from_bytes(blob)

        # Governance txs with 1-byte kind discriminator
        gov_count = take_u32()
        gov_classes = (
            ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
        )
        governance_txs = []
        for _ in range(gov_count):
            kind = take_u8()
            if kind >= len(gov_classes):
                raise ValueError(f"Unknown governance tx kind: {kind}")
            ln = take_u32()
            governance_txs.append(
                _call_from_bytes(gov_classes[kind], take(ln))
            )

        # Authority txs with 1-byte kind discriminator
        auth_count = take_u32()
        auth_classes = (
            SetAuthorityKeyTransaction, RevokeTransaction, KeyRotationTransaction,
        )
        authority_txs = []
        for _ in range(auth_count):
            kind = take_u8()
            if kind >= len(auth_classes):
                raise ValueError(f"Unknown authority tx kind: {kind}")
            ln = take_u32()
            authority_txs.append(
                _call_from_bytes(auth_classes[kind], take(ln))
            )

        stake_txs = dec_list(StakeTransaction)
        unstake_txs = dec_list(UnstakeTransaction)

        # Finality votes.  The receive-to-exist refactor removed the
        # registration_transactions list from the binary block layout,
        # so finality_votes now sits directly after unstake_transactions.
        # Pre-refactor blobs cannot round-trip through this decoder (the
        # first u32 here reads what used to be the registration count)
        # — that's a deliberate consensus-format hard break: a node
        # carrying pre-refactor blocks must resync from a peer running
        # the new code.
        from messagechain.consensus.finality import FinalityVote
        finality_votes = dec_list(FinalityVote)

        declared_hash = take(32)
        if off != len(data):
            raise ValueError("Block blob has trailing bytes")

        block = cls(
            header=header, transactions=txs,
            validator_signatures=val_sigs,
            slash_transactions=slash_txs,
            attestations=attestations,
            transfer_transactions=transfer_txs,
            governance_txs=governance_txs,
            authority_txs=authority_txs,
            stake_transactions=stake_txs,
            unstake_transactions=unstake_txs,
            finality_votes=finality_votes,
        )
        expected_hash = block._compute_hash()
        if expected_hash != declared_hash:
            raise ValueError(
                f"Block hash mismatch: declared {declared_hash.hex()[:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return block

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
        stake_txs = []
        if data.get("stake_transactions"):
            from messagechain.core.staking import StakeTransaction
            stake_txs = [StakeTransaction.deserialize(s) for s in data["stake_transactions"]]
        unstake_txs = []
        if data.get("unstake_transactions"):
            from messagechain.core.staking import UnstakeTransaction
            unstake_txs = [UnstakeTransaction.deserialize(s) for s in data["unstake_transactions"]]
        finality_votes = []
        if data.get("finality_votes"):
            from messagechain.consensus.finality import FinalityVote
            finality_votes = [
                FinalityVote.deserialize(v) for v in data["finality_votes"]
            ]
        block = cls(header=header, transactions=txs, validator_signatures=val_sigs,
                    slash_transactions=slash_txs, attestations=attestations,
                    transfer_transactions=transfer_txs, governance_txs=governance_txs,
                    authority_txs=authority_txs, stake_transactions=stake_txs,
                    unstake_transactions=unstake_txs,
                    finality_votes=finality_votes)
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
    # Genesis pins hash_version explicitly even though it's the dataclass
    # default — the intent is that future readers of this function see that
    # genesis is crypto-versioned, not that we accidentally got the current
    # scheme by omitting the field.
    header = BlockHeader(
        version=1,
        hash_version=HASH_VERSION_CURRENT,
        block_number=0,
        prev_hash=b"\x00" * 32,
        merkle_root=_hash(b"genesis"),
        timestamp=int(time.time()),
        proposer_id=proposer_entity.entity_id,
    )

    # Sign the genesis block
    header_hash = _hash(header.signable_data())
    header.proposer_signature = proposer_entity.keypair.sign(header_hash)

    block = Block(header=header, transactions=[])
    block.block_hash = block._compute_hash()
    return block
