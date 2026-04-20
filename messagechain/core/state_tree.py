"""
Sparse Merkle Tree state commitment for MessageChain.

This is the incremental replacement for the flat-binary-Merkle state
commitment that was previously computed from scratch on every block
(see compute_state_root's earlier implementation). The flat rebuild
was O(N log N) in the total account count — at ~1M accounts a full
IBD became impractical because every block paid the full cost.

Design:

* Each account is addressed by `key = hash(entity_id)`, a 256-bit value.
  The key's bit string (MSB-first) is the path from root to leaf in a
  fixed-depth binary tree (TREE_DEPTH = 256). Fixed-depth addressing
  keeps insertions and deletions O(TREE_DEPTH) — the node positions
  of existing accounts never shift.

* Unused subtrees have well-known "empty" hashes precomputed once
  for every level. A subtree whose hash equals the empty hash is
  *not* materialized in storage, so memory stays O(non-empty leaves).

* Leaf value is `hash(entity_id || balance || nonce || stake)` — the
  same triple the flat implementation committed to, so SMT semantics
  for "what is committed" match the old commitment's intent.

* `set(entity_id, balance, nonce, stake)` updates the single leaf
  and rehashes the O(TREE_DEPTH) path from that leaf to the root.
  Per-update cost is O(256) hash operations regardless of N.

* `begin()` / `commit()` / `rollback()` expose a journal so block
  proposers can apply a tentative set of transactions, compute the
  resulting root for commitment in the block header, and roll back
  if the block is rejected. Rollback is O(changes) — no O(N) copies.

* `compute_state_root(balances, nonces, staked)` is a pure function
  that builds a fresh tree and returns its root. Used by validator
  fallback paths and tests that have dicts in hand. Kept separate
  so the test surface that exercised the old `block.compute_state_root`
  still works bit-for-bit after the migration.

Scaling characteristics at N accounts, K modifications per block:

    operation          old impl        this impl
    ---------          --------        ---------
    per-block update   O(N log N)      O(K * TREE_DEPTH)   ~256x better at N=1M
    full rebuild       O(N log N)      O(N * TREE_DEPTH)   slower, used only for
                                                            test fallback paths
    snapshot/restore   O(N) copy       O(K) journal        no big-O bound on
                                                            base state

Consensus note: this replacement changes the cryptographic commitment
for a given state. A chain whose blocks committed to state_roots under
the old flat-Merkle algorithm cannot be loaded with this code and have
those roots re-verified. Treat the upgrade as a hard consensus change.
"""

import hashlib
import struct
from messagechain.config import HASH_ALGO

# Every account's leaf address is hash-of-entity-id, so the tree depth
# matches the hash output in bits. 256 bits → 256 levels.
TREE_DEPTH = 256


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# Precomputed empty-subtree hashes. _EMPTY[level] is the hash of a
# fully empty subtree at `level`, where level=0 means "an empty leaf"
# and level=TREE_DEPTH means "an entirely empty tree" (the default root).
# Subtrees whose computed hash equals _EMPTY[level] are never materialized
# in _nodes — they're implied by absence.
_EMPTY: list[bytes] = [b"\x00" * 32]
for _level in range(TREE_DEPTH):
    _EMPTY.append(_h(_EMPTY[-1] + _EMPTY[-1]))

EMPTY_ROOT = _EMPTY[TREE_DEPTH]


def _leaf_value(
    entity_id: bytes,
    balance: int,
    nonce: int,
    stake: int,
    *,
    authority_key: bytes = b"",
    public_key: bytes = b"",
    leaf_watermark: int = 0,
    rotation_count: int = 0,
    is_revoked: bool = False,
    is_slashed: bool = False,
) -> bytes:
    """Commitment hash for a single account's full state.

    Covers every per-entity field consensus cares about: liquid balance,
    tx nonce, active stake, the hot signing key (public_key — changed by
    KeyRotation), the cold authority key (authority_key — changed by
    SetAuthorityKey), the WOTS+ leaf watermark (bumped on every
    signature), the rotation counter (bumped on every KeyRotation), the
    revoked flag, and the slashed flag.

    Without all of these inside the leaf, two honest nodes could disagree
    on who is revoked / slashed / whose cold key is what / whose rotation
    happened, yet still compute matching state roots — defeating the
    whole point of the commitment.  is_slashed in particular gates the
    "already slashed" check in apply_slash_transaction, so divergence
    could let two nodes accept/reject the same double-slash tx
    differently.

    All variable-length byte fields (authority_key, public_key) are
    prefixed with a 2-byte length so b"" vs b"\\x00\\x00" cannot collide.
    """
    ak = authority_key or b""
    pk = public_key or b""
    return _h(
        entity_id
        + struct.pack(">Q", balance)
        + struct.pack(">Q", nonce)
        + struct.pack(">Q", stake)
        + struct.pack(">H", len(ak)) + ak
        + struct.pack(">H", len(pk)) + pk
        + struct.pack(">Q", leaf_watermark)
        + struct.pack(">Q", rotation_count)
        + (b"\x01" if is_revoked else b"\x00")
        + (b"\x01" if is_slashed else b"\x00")
    )


def _key_for(entity_id: bytes) -> bytes:
    """Derive the tree address of an account."""
    return _h(b"state_key" + entity_id)


class SparseMerkleTree:
    """Fixed-depth binary Merkle tree indexed by hash(entity_id).

    Provides amortized O(TREE_DEPTH) update, O(1) root read after
    updates, and journal-based rollback for tentative mutations.
    """

    DEPTH = TREE_DEPTH

    # Canonical "no extra authority state" record — used when a caller
    # only has (balance, nonce, stake) in hand (tests, old persistence).
    # Matches the defaults of _leaf_value so leaves stay identical to
    # the pre-authority-coverage layout for accounts that never set a
    # cold key, rotated, or got revoked.  Fields:
    #   (authority_key, public_key, leaf_watermark, rotation_count,
    #    revoked, slashed)
    _DEFAULT_AUTH = (b"", b"", 0, 0, False, False)

    def __init__(self):
        # (level, path_int) -> non-default node hash at that position.
        # level=0 holds leaves, level=TREE_DEPTH holds the root (position 0).
        self._nodes: dict[tuple[int, int], bytes] = {}
        # entity_id -> full committed tuple:
        #   (balance, nonce, stake, authority_key, public_key,
        #    leaf_watermark, rotation_count, is_revoked, is_slashed)
        # The tree itself doesn't store accounts, only their committed
        # hashes, so we keep this side-index for reads and for rebuild
        # from persistence.
        self._accounts: dict[
            bytes, tuple[int, int, int, bytes, bytes, int, int, bool, bool]
        ] = {}
        # Cached current root — invalidated on any write.
        self._root_cache: bytes | None = EMPTY_ROOT
        # Active transaction journal, or None outside a transaction.
        # Each entry is enough information to reverse one _set call.
        self._journal: list | None = None

    # ── Transaction / journal API ────────────────────────────────────

    def begin(self):
        """Begin a tentative mutation sequence.

        Any set()/remove() calls between begin() and commit()/rollback()
        are journaled so they can be undone. Used by
        `compute_post_state_root` to compute the resulting root of a
        proposed block without permanently mutating state.
        """
        if self._journal is not None:
            raise RuntimeError("SparseMerkleTree: nested transactions not supported")
        self._journal = []

    def commit(self):
        """Accept all pending mutations — discard the journal."""
        self._journal = None

    def rollback(self):
        """Undo every mutation performed since begin().

        Rollback cost is O(number of set()/remove() calls during the
        transaction), not O(N). No state copy is made.
        """
        if self._journal is None:
            return
        # Undo in reverse order so overlapping writes unwind correctly.
        for entry in reversed(self._journal):
            # Entry form: ("account", entity_id, old_tuple_or_None,
            #              list[(level, path, old_node_or_None)])
            _tag, entity_id, old_account, old_nodes = entry
            if old_account is None:
                self._accounts.pop(entity_id, None)
            else:
                self._accounts[entity_id] = old_account
            for level, path, old_node in old_nodes:
                if old_node is None:
                    self._nodes.pop((level, path), None)
                else:
                    self._nodes[(level, path)] = old_node
        self._journal = None
        self._root_cache = None

    # ── Read API ─────────────────────────────────────────────────────

    def get(self, entity_id: bytes):
        """Return the full committed tuple for an account, or None.

        Tuple layout:
            (balance, nonce, stake, authority_key, public_key,
             leaf_watermark, rotation_count, is_revoked, is_slashed)
        """
        return self._accounts.get(entity_id)

    def root(self) -> bytes:
        """Return the current Merkle root of the committed state."""
        if self._root_cache is None:
            self._root_cache = self._nodes.get(
                (TREE_DEPTH, 0), _EMPTY[TREE_DEPTH]
            )
        return self._root_cache

    def __len__(self) -> int:
        return len(self._accounts)

    # ── Write API ────────────────────────────────────────────────────

    def set(
        self,
        entity_id: bytes,
        balance: int,
        nonce: int,
        stake: int,
        *,
        authority_key: bytes = b"",
        public_key: bytes = b"",
        leaf_watermark: int = 0,
        rotation_count: int = 0,
        is_revoked: bool = False,
        is_slashed: bool = False,
    ):
        """Upsert an account's committed state.

        Idempotent: setting the same record twice is a no-op after the
        first call.  An account whose entire record matches the default
        (all zero / empty / not-revoked / not-slashed) is treated as
        absent so genuine empty accounts don't contribute to the
        commitment.

        The authority fields are keyword-only so existing call sites that
        pass only (balance, nonce, stake) continue to mean "empty
        authority record" — i.e., no cold key, default public key, no
        revoke, no slash, no rotations.  Blockchain._touch_state is the
        canonical caller and passes every field explicitly.
        """
        ak = authority_key or b""
        pk = public_key or b""
        new_tuple = (
            balance, nonce, stake, ak, pk,
            leaf_watermark, rotation_count, is_revoked, is_slashed,
        )
        old_tuple = self._accounts.get(entity_id)
        if new_tuple == old_tuple:
            return
        is_default = (
            balance == 0 and nonce == 0 and stake == 0
            and ak == b"" and pk == b""
            and leaf_watermark == 0 and rotation_count == 0
            and not is_revoked and not is_slashed
        )
        if is_default:
            self.remove(entity_id)
            return

        key = _key_for(entity_id)
        leaf = _leaf_value(
            entity_id, balance, nonce, stake,
            authority_key=ak,
            public_key=pk,
            leaf_watermark=leaf_watermark,
            rotation_count=rotation_count,
            is_revoked=is_revoked,
            is_slashed=is_slashed,
        )
        changes = self._set_leaf(key, leaf)

        if self._journal is not None:
            self._journal.append(("account", entity_id, old_tuple, changes))
        self._accounts[entity_id] = new_tuple
        self._root_cache = None

    def remove(self, entity_id: bytes):
        """Remove an account from the commitment entirely."""
        old_tuple = self._accounts.get(entity_id)
        if old_tuple is None:
            return
        key = _key_for(entity_id)
        changes = self._set_leaf(key, _EMPTY[0])

        if self._journal is not None:
            self._journal.append(("account", entity_id, old_tuple, changes))
        del self._accounts[entity_id]
        self._root_cache = None

    # ── Internal path recomputation ──────────────────────────────────

    def _set_leaf(self, key: bytes, leaf_hash: bytes) -> list:
        """Rehash the O(TREE_DEPTH) path from a leaf to the root.

        Returns a list of (level, path, old_node_or_None) entries in
        the order they were written, for journal rollback. The caller
        is responsible for journaling if they're in a transaction.
        """
        path = int.from_bytes(key, "big")
        changes: list = []

        # Level 0: the leaf itself.
        self._journal_change(changes, 0, path)
        if leaf_hash == _EMPTY[0]:
            self._nodes.pop((0, path), None)
        else:
            self._nodes[(0, path)] = leaf_hash
        current = leaf_hash

        # Walk up one level at a time, hashing with the sibling.
        for level in range(TREE_DEPTH):
            is_right = path & 1
            sibling_path = path ^ 1
            sibling_hash = self._nodes.get(
                (level, sibling_path), _EMPTY[level]
            )
            if is_right:
                parent_hash = _h(sibling_hash + current)
            else:
                parent_hash = _h(current + sibling_hash)

            parent_path = path >> 1
            parent_level = level + 1

            self._journal_change(changes, parent_level, parent_path)
            if parent_hash == _EMPTY[parent_level]:
                self._nodes.pop((parent_level, parent_path), None)
            else:
                self._nodes[(parent_level, parent_path)] = parent_hash

            current = parent_hash
            path = parent_path

        return changes

    def _journal_change(self, changes: list, level: int, path: int):
        """Record the old node hash at (level, path) if we're journaling."""
        if self._journal is None:
            return
        changes.append((level, path, self._nodes.get((level, path))))

    # ── Serialization for persistence ────────────────────────────────

    def serialize(self) -> dict:
        """Dump just the account table — the tree can be rebuilt from it.

        Storing only accounts (and not the full _nodes map) keeps
        persistence small and makes loading trivially reconstructable:
        replay the accounts into a fresh tree and the root will match.
        """
        return {
            "version": 3,
            "accounts": [
                {
                    "entity_id": eid.hex(),
                    "balance": bal,
                    "nonce": nonce,
                    "stake": stake,
                    "authority_key": ak.hex(),
                    "public_key": pk.hex(),
                    "leaf_watermark": wm,
                    "rotation_count": rc,
                    "is_revoked": rev,
                    "is_slashed": sl,
                }
                for eid, (bal, nonce, stake, ak, pk, wm, rc, rev, sl)
                in self._accounts.items()
            ],
        }

    @classmethod
    def deserialize(cls, data: dict) -> "SparseMerkleTree":
        tree = cls()
        for entry in data.get("accounts", []):
            tree.set(
                bytes.fromhex(entry["entity_id"]),
                entry["balance"],
                entry["nonce"],
                entry["stake"],
                authority_key=bytes.fromhex(entry.get("authority_key", "")),
                public_key=bytes.fromhex(entry.get("public_key", "")),
                leaf_watermark=entry.get("leaf_watermark", 0),
                rotation_count=entry.get("rotation_count", 0),
                is_revoked=entry.get("is_revoked", False),
                is_slashed=entry.get("is_slashed", False),
            )
        return tree


def compute_state_root(
    balances: dict[bytes, int],
    nonces: dict[bytes, int],
    staked: dict[bytes, int],
    *,
    authority_keys: dict[bytes, bytes] | None = None,
    public_keys: dict[bytes, bytes] | None = None,
    leaf_watermarks: dict[bytes, int] | None = None,
    key_rotation_counts: dict[bytes, int] | None = None,
    revoked_entities: set[bytes] | frozenset[bytes] | None = None,
    slashed_validators: set[bytes] | frozenset[bytes] | None = None,
) -> bytes:
    """Pure-function Merkle commitment over all per-entity state.

    Builds a fresh SparseMerkleTree from the dicts and returns its
    root.  The authority-field arguments are keyword-only with empty
    defaults so legacy call sites that only have (balances, nonces,
    staked) still work — but any chain whose state_root should cover
    authority state must pass the full set.

    For the on-chain incremental case, use `Blockchain.state_tree`
    directly — it avoids the O(N * DEPTH) rebuild cost this function
    pays every call.
    """
    authority_keys = authority_keys or {}
    public_keys = public_keys or {}
    leaf_watermarks = leaf_watermarks or {}
    key_rotation_counts = key_rotation_counts or {}
    revoked_entities = revoked_entities or set()
    slashed_validators = slashed_validators or set()

    tree = SparseMerkleTree()
    # Union every per-entity key set so an entity that shows up only in,
    # say, authority_keys still gets a leaf.  Without the union an entity
    # with zero balance but a bound cold key would be invisible to the
    # commitment.
    all_keys = (
        set(balances) | set(nonces) | set(staked)
        | set(authority_keys) | set(public_keys)
        | set(leaf_watermarks) | set(key_rotation_counts)
        | set(revoked_entities) | set(slashed_validators)
    )
    for eid in all_keys:
        tree.set(
            eid,
            balances.get(eid, 0),
            nonces.get(eid, 0),
            staked.get(eid, 0),
            authority_key=authority_keys.get(eid, b""),
            public_key=public_keys.get(eid, b""),
            leaf_watermark=leaf_watermarks.get(eid, 0),
            rotation_count=key_rotation_counts.get(eid, 0),
            is_revoked=eid in revoked_entities,
            is_slashed=eid in slashed_validators,
        )
    return tree.root()
