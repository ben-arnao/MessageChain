"""
ReactTransaction (Tier 17) — user-trust + message-react votes.

A ReactTx is a single voter's signed claim against either another
entity (user-trust vote) or a message tx_hash (message-react vote).
The choice is one of {CLEAR, UP, DOWN}; CLEAR retracts a prior vote
from the same (voter, target) pair, UP and DOWN are the two signed
positions.

Aggregation semantics
---------------------

Each (voter, target) pair has a single latest choice in consensus
state.  A new ReactTx for the same pair supersedes the previous one;
both txs remain on chain forever (every byte is permanent), but only
the latest counts toward the per-target sum.

The per-target sums (`user_trust_score[target]`,
`message_score[target]`) are denormalised into ReactionState alongside
the (voter, target) → choice map.  Apply mutates them by the delta
between the prior and new choice — no re-scan of history is required.

Wire layout (binary)
--------------------

The signed payload is intentionally minimal so the linear-fee floor
keeps the per-tx cost close to BASE_TX_FEE.  WOTS+ signature dominates
total size (~2.7 KB) — payload-level micro-optimisation is in the
noise relative to the witness.

    u8   serialization_version    (wire-format gate)
    ENT  voter entity reference   (varint after registration; 32 B otherwise)
    32   target                   (entity_id OR message tx_hash, see flags)
    u8   flags                    (bit0: target_is_user;
                                   bit1-2: choice [00=CLEAR, 01=UP, 10=DOWN, 11=reserved];
                                   bit3-7: must be 0)
    u64  nonce                    (per-voter monotonic, reuses entity nonce space)
    f64  timestamp
    u64  fee
    u32  signature_blob_len
    M    signature_blob           (WOTS+ + auth path + sig_version)
    32   tx_hash                  (declared; verified on decode)

`_signable_data` covers every field above except the signature blob
itself; sig_version is committed via the explicit byte so swapping
crypto schemes after signing is tamper-evident.

Validation rules (verify_react_transaction)
-------------------------------------------

1. current_height >= REACT_TX_HEIGHT (activation gate).
2. Fee >= max(REACT_FEE_FLOOR, market floor) — gates spam at the byte level.
3. timestamp not too far in the future (MAX_TIMESTAMP_DRIFT).
4. flags byte is canonical (reserved bits = 0, choice in {0,1,2}).
5. If target_is_user: target ≠ voter_id (no self-trust).
6. Signature verifies under the supplied public_key.

Self-trust note: a user can react UP/DOWN/CLEAR on their OWN message
tx_hashes — the no-self-vote rule applies only to user-trust votes,
because a user up-voting their own user-trust score would be a free
unbounded reputation pump.  Reacting to your own message is fine; if
you want to inflate your message-score that way, every self-react
still costs full fee (which is the spam discipline).
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from messagechain.config import (
    HASH_ALGO,
    MAX_TIMESTAMP_DRIFT,
    CHAIN_ID,
    SIG_VERSION_CURRENT,
    TX_SERIALIZATION_VERSION,
    validate_tx_serialization_version,
    REACT_TX_HEIGHT,
    REACT_CHOICE_CLEAR,
    REACT_CHOICE_UP,
    REACT_CHOICE_DOWN,
    REACT_TARGET_MESSAGE,
    REACT_TARGET_USER,
)
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.crypto.hashing import default_hash


# Type-specific flat floor.  Sits at the same conservative baseline as
# MIN_FEE; the post-Tier-16 market-floor + EIP-1559 base fee do the
# real spam-pricing work.  Type-specific surcharges live above this if
# we ever want to make votes pricier than baseline (none today).
REACT_FEE_FLOOR = 10


def _hash(data: bytes) -> bytes:
    return default_hash(data)


# ── flags byte: target_type + choice ────────────────────────────────
#
# bit0      target_is_user (0 = message tx_hash, 1 = entity_id)
# bit1-2    choice (00 = CLEAR, 01 = UP, 10 = DOWN, 11 = reserved)
# bit3-7    reserved, must be zero (canonical-form rule — non-zero
#           rejected by the verifier so two encodings can't collide
#           on the same signed semantics)


_VALID_CHOICES = {
    REACT_CHOICE_CLEAR,
    REACT_CHOICE_UP,
    REACT_CHOICE_DOWN,
}


def _pack_flags(*, target_is_user: bool, choice: int) -> int:
    if choice not in _VALID_CHOICES:
        raise ValueError(f"invalid react choice: {choice!r}")
    flags = 0
    if target_is_user:
        flags |= 0x01
    flags |= (choice & 0x03) << 1
    return flags


def _unpack_flags(flags: int) -> tuple[bool, int]:
    """Return (target_is_user, choice) from a flags byte, raising on non-canonical input."""
    if flags & 0xF8:
        # bit3-7 set — non-canonical encoding, reject so the byte
        # uniquely commits to the (target_type, choice) pair.
        raise ValueError(f"invalid react flags byte (reserved bits set): {flags:#04x}")
    target_is_user = bool(flags & 0x01)
    choice = (flags >> 1) & 0x03
    if choice not in _VALID_CHOICES:
        raise ValueError(f"invalid react choice in flags byte: {choice}")
    return target_is_user, choice


def _score_value(choice: int) -> int:
    """Per-vote score contribution: UP=+1, DOWN=-1, CLEAR=0."""
    if choice == REACT_CHOICE_UP:
        return 1
    if choice == REACT_CHOICE_DOWN:
        return -1
    return 0


# ── Transaction class ───────────────────────────────────────────────


@dataclass
class ReactTransaction:
    """A single signed reaction vote (user-trust or message-react)."""

    voter_id: bytes        # 32B entity_id of the signer
    target: bytes          # 32B — entity_id (user-trust) OR tx_hash (message-react)
    target_is_user: bool   # selects the meaning of `target`
    choice: int            # REACT_CHOICE_{CLEAR, UP, DOWN}
    nonce: int             # per-voter monotonic (shared with other tx kinds)
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if len(self.voter_id) != 32:
            raise ValueError("voter_id must be 32 bytes")
        if len(self.target) != 32:
            raise ValueError("target must be 32 bytes")
        if self.choice not in _VALID_CHOICES:
            raise ValueError(f"invalid react choice: {self.choice!r}")
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    # ── Hashing / signable form ─────────────────────────────────────

    def _signable_data(self) -> bytes:
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        flags = _pack_flags(
            target_is_user=self.target_is_user,
            choice=self.choice,
        )
        return (
            CHAIN_ID
            + b"react"
            + struct.pack(">B", sig_version)
            + self.voter_id
            + self.target
            + struct.pack(">B", flags)
            + struct.pack(">Q", self.nonce)
            + struct.pack(">d", float(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    # ── Dict serialisation (JSON / RPC) ─────────────────────────────

    def serialize(self) -> dict:
        return {
            "type": "react",
            "voter_id": self.voter_id.hex(),
            "target": self.target.hex(),
            "target_is_user": self.target_is_user,
            "choice": self.choice,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ReactTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            voter_id=bytes.fromhex(data["voter_id"]),
            target=bytes.fromhex(data["target"]),
            target_is_user=bool(data["target_is_user"]),
            choice=int(data["choice"]),
            nonce=int(data["nonce"]),
            timestamp=float(data["timestamp"]),
            fee=int(data["fee"]),
            signature=sig,
        )
        declared = bytes.fromhex(data["tx_hash"])
        if tx._compute_hash() != declared:
            raise ValueError(
                f"ReactTransaction hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {tx.tx_hash.hex()[:16]}"
            )
        return tx

    # ── Compact binary encoding ─────────────────────────────────────

    def to_bytes(self, state=None) -> bytes:
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        flags = _pack_flags(
            target_is_user=self.target_is_user,
            choice=self.choice,
        )
        return b"".join([
            struct.pack(">B", TX_SERIALIZATION_VERSION),
            encode_entity_ref(self.voter_id, state=state),
            self.target,
            struct.pack(">B", flags),
            struct.pack(">Q", self.nonce),
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "ReactTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        # Minimum: ser_ver(1) + ENT(>=1) + target(32) + flags(1)
        # + nonce(8) + timestamp(8) + fee(8) + sig_len(4) + tx_hash(32) = 95
        if len(data) < 95:
            raise ValueError("ReactTransaction blob too short")
        off = 0
        ser_version = struct.unpack_from(">B", data, off)[0]; off += 1
        ok, reason = validate_tx_serialization_version(ser_version)
        if not ok:
            raise ValueError(f"ReactTransaction: {reason}")
        voter_id, n = decode_entity_ref(data, off, state=state); off += n
        if off + 32 + 1 + 8 + 8 + 8 + 4 + 32 > len(data):
            raise ValueError("ReactTransaction truncated after voter_ref")
        target = bytes(data[off:off + 32]); off += 32
        flags = struct.unpack_from(">B", data, off)[0]; off += 1
        target_is_user, choice = _unpack_flags(flags)
        nonce = struct.unpack_from(">Q", data, off)[0]; off += 8
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("ReactTransaction truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared_hash = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("ReactTransaction has trailing bytes")
        tx = cls(
            voter_id=voter_id,
            target=target,
            target_is_user=target_is_user,
            choice=choice,
            nonce=nonce,
            timestamp=timestamp,
            fee=fee,
            signature=sig,
        )
        if tx._compute_hash() != declared_hash:
            raise ValueError(
                f"ReactTransaction hash mismatch: declared "
                f"{declared_hash.hex()[:16]}, computed {tx.tx_hash.hex()[:16]}"
            )
        return tx


# ── Constructor + verifier ──────────────────────────────────────────


def create_react_transaction(
    entity,
    *,
    target: bytes,
    target_is_user: bool,
    choice: int,
    nonce: int,
    fee: int = REACT_FEE_FLOOR,
    timestamp: float | None = None,
) -> ReactTransaction:
    """Create and sign a ReactTransaction.

    Performs the user-side guards that don't depend on chain state:
        * choice is in {CLEAR, UP, DOWN}
        * target is 32 bytes
        * if target_is_user, target ≠ voter (no self-trust)

    The chain-side guards (entity registered, target exists, signature
    verifies, fee covers floor at current_height) live in
    `verify_react_transaction` and the apply path.
    """
    if choice not in _VALID_CHOICES:
        raise ValueError(f"invalid react choice: {choice!r}")
    if len(target) != 32:
        raise ValueError("react target must be 32 bytes")
    if target_is_user and target == entity.entity_id:
        raise ValueError("cannot react-trust yourself (target == voter)")

    tx = ReactTransaction(
        voter_id=entity.entity_id,
        target=target,
        target_is_user=target_is_user,
        choice=choice,
        nonce=nonce,
        timestamp=time.time() if timestamp is None else timestamp,
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_react_transaction(
    tx: ReactTransaction,
    public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify a ReactTransaction's signature, structural fields, and admission rules.

    `current_height` is required to evaluate the activation-height gate
    (REACT_TX_HEIGHT) and the height-aware fee floor.  Callers that
    pass None are running outside an admission context — the activation
    gate is skipped (so unit tests can exercise verify with a
    None-history fixture) but the structural, fee-floor, and signature
    checks still run.
    """
    from messagechain.core.transaction import enforce_signature_aware_min_fee

    # Activation gate — strict-future heights at REACT_TX_HEIGHT.
    if current_height is not None and current_height < REACT_TX_HEIGHT:
        return False

    # Structural canon-form check on choice/flags + target_type.
    if tx.choice not in _VALID_CHOICES:
        return False
    if len(tx.target) != 32 or len(tx.voter_id) != 32:
        return False

    # No self-trust on user-trust votes.  (Self-react on a message
    # tx_hash is allowed; the spam tax is the per-tx fee.)
    if tx.target_is_user and tx.target == tx.voter_id:
        return False

    # Fee floor — uses the same per-height ladder as every other tx kind.
    if not enforce_signature_aware_min_fee(
        tx.fee,
        signature_bytes=len(tx.signature.to_bytes()),
        current_height=current_height,
        flat_floor=REACT_FEE_FLOOR,
    ):
        return False

    # Timestamp drift
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False

    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


# ── ReactionState — consensus-state aggregator ──────────────────────


@dataclass
class ReactionState:
    """In-memory consensus state for ReactTransactions.

    Owns three dicts:

        choices            : (voter_id, target, target_is_user) → choice
                             — the ground-truth latest vote per pair.
        _user_trust_score  : entity_id → int   (sum of UP/DOWN votes)
        _message_score     : tx_hash → int     (sum of UP/DOWN votes)

    The aggregates are denormalised projections of `choices`; both are
    committed into the chain state root so light clients can verify a
    score with a Merkle proof.  ``apply`` mutates all three together
    by the delta between the prior and new choice — no rescan of
    history is required, so per-block cost is O(num_react_tx).

    ``serialize`` / ``deserialize`` round-trip through the chaindb
    save/restore path; like every other state dict, these must be
    written and read in a single chaindb txn alongside balances /
    nonces / staked (the round-8/round-9 save-restore-symmetry rule).
    The aggregates are rebuilt from `choices` on deserialize so the
    invariant `aggregate == sum_of_pairs(choices)` is enforced at load
    time, not just at apply.
    """

    # Stored ground truth — maps (voter_id, target, target_is_user) to choice.
    # CLEAR entries are removed (absent ≡ CLEAR), so the dict only
    # carries non-zero contributions.  target_is_user is included in
    # the key to keep user-trust votes separate from message-react
    # votes when the 32-byte target value happens to coincide.
    choices: dict[tuple[bytes, bytes, bool], int] = field(default_factory=dict)
    _user_trust_score: dict[bytes, int] = field(default_factory=dict)
    _message_score: dict[bytes, int] = field(default_factory=dict)

    # ── Read API ────────────────────────────────────────────────────

    def user_trust_score(self, entity_id: bytes) -> int:
        return self._user_trust_score.get(entity_id, 0)

    def message_score(self, tx_hash: bytes) -> int:
        return self._message_score.get(tx_hash, 0)

    def get_choice(
        self,
        voter_id: bytes,
        target: bytes,
        target_is_user: bool,
    ) -> int:
        """Return the latest choice for (voter, target) pair, or CLEAR if none."""
        return self.choices.get(
            (voter_id, target, target_is_user),
            REACT_CHOICE_CLEAR,
        )

    # ── Apply ───────────────────────────────────────────────────────

    def apply(self, tx: ReactTransaction) -> None:
        """Apply one ReactTransaction to state, updating both the per-pair
        choice and the per-target aggregate.

        Idempotent: applying the same (voter, target, target_type, choice)
        twice is a no-op (delta = 0).  In the live chain this never
        happens because tx_hash dedup rejects the second copy at mempool;
        the idempotence here is a defence-in-depth invariant.
        """
        key = (tx.voter_id, tx.target, tx.target_is_user)
        prev_choice = self.choices.get(key, REACT_CHOICE_CLEAR)
        delta = _score_value(tx.choice) - _score_value(prev_choice)

        if tx.target_is_user:
            new_score = self._user_trust_score.get(tx.target, 0) + delta
            if new_score == 0:
                self._user_trust_score.pop(tx.target, None)
            else:
                self._user_trust_score[tx.target] = new_score
        else:
            new_score = self._message_score.get(tx.target, 0) + delta
            if new_score == 0:
                self._message_score.pop(tx.target, None)
            else:
                self._message_score[tx.target] = new_score

        if tx.choice == REACT_CHOICE_CLEAR:
            self.choices.pop(key, None)
        else:
            self.choices[key] = tx.choice

    # ── Serialise / deserialise (chaindb save/restore) ──────────────

    def serialize(self) -> dict:
        """Dump the ground-truth choices map; aggregates are rebuilt on load.

        Storing ONLY the (voter, target, target_type) → choice ground
        truth keeps the on-disk state minimal AND enforces the invariant
        ``aggregate == sum_of_pairs(choices)`` at restore time — a
        validator that hand-edits the persisted aggregates and not the
        underlying votes will see the discrepancy on the next reload.
        """
        entries = []
        for (voter, target, tu), choice in self.choices.items():
            entries.append({
                "voter": voter.hex(),
                "target": target.hex(),
                "target_is_user": tu,
                "choice": int(choice),
            })
        return {
            "version": 1,
            "choices": entries,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ReactionState":
        s = cls()
        for entry in data.get("choices", []):
            voter = bytes.fromhex(entry["voter"])
            target = bytes.fromhex(entry["target"])
            tu = bool(entry["target_is_user"])
            choice = int(entry["choice"])
            if choice not in _VALID_CHOICES or choice == REACT_CHOICE_CLEAR:
                # CLEAR entries should never have been persisted; skip
                # them rather than letting them corrupt the rebuild.
                continue
            s.choices[(voter, target, tu)] = choice
            score_delta = _score_value(choice)
            if tu:
                s._user_trust_score[target] = (
                    s._user_trust_score.get(target, 0) + score_delta
                )
                if s._user_trust_score[target] == 0:
                    s._user_trust_score.pop(target, None)
            else:
                s._message_score[target] = (
                    s._message_score.get(target, 0) + score_delta
                )
                if s._message_score[target] == 0:
                    s._message_score.pop(target, None)
        return s

    # ── State-root contribution ─────────────────────────────────────

    def state_root_contribution(self) -> bytes:
        """Return a 32-byte commitment to the entire reaction state.

        Hashes the canonically-sorted (voter, target, target_is_user, choice)
        tuples so two validators agree on the digest regardless of dict
        iteration order.  Mixed into the chain state root via the same
        hashing discipline as the SparseMerkleTree's account leaves.

        NOTE: this is the simple-and-correct linear hash, not an
        incremental Merkle subtree.  Per-block cost scales with total
        non-CLEAR entries.  If reaction volume becomes large enough
        that this dominates state-root computation, swap in a
        SparseMerkleTree keyed by H("react_key" || voter || target ||
        target_is_user).  The choice of scheme does not affect any
        consensus rule above — only the size of this commitment's
        rebuild work.
        """
        sorted_entries = sorted(self.choices.items(), key=lambda kv: kv[0])
        h_input = b"react_state_v1"
        for (voter, target, tu), choice in sorted_entries:
            h_input += (
                voter
                + target
                + (b"\x01" if tu else b"\x00")
                + struct.pack(">B", choice)
            )
        return _hash(h_input)
