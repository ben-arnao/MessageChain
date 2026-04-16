"""
On-wire encoding for entity references (32-byte id vs varint index).

Every transaction carries at least one entity_id (sender, sometimes a
recipient/validator/offender as well). Each entity_id is 32 bytes; for
a permanent-history chain that compounds fast. Once an entity has
been registered, the state assigns it a monotonic `entity_index`
(1, 2, 3, ...) that fits in 1-5 LEB128 bytes — saving up to 31 B per
reference.

Encoding:
    * u8 tag: 0x00 = legacy, full 32-byte entity_id follows.
              0x01 = compact, varint entity_index follows.
    * For tag=0x00: the 32-byte entity_id.
    * For tag=0x01: a LEB128 varint (1-5 bytes) giving the index.

When `state` is None (backward-compat callers that don't thread a
blockchain instance through), we always emit tag=0x00.  When `state`
is provided and has an index for the entity_id, we emit tag=0x01 +
the varint.  `_signable_data()` across every tx type continues to
use the full 32-byte entity_id — the wire form is a pure storage
optimization and does not touch consensus hashing.

Decode mirror: `from_bytes(..., state=None)` reads either tag. A
varint-form blob without a state to resolve it rejects with a clear
error — that represents a real bug (a peer sent you a compact blob
but you haven't synced the entity table yet). Legacy-form blobs
decode without state.

The helpers return `(entity_id_bytes, bytes_consumed)` so callers
can be layout-agnostic and just keep advancing their offset.
"""

from messagechain.core.varint import (
    decode_varint, encode_varint, varint_size,
)

# Tag values. A new tag value would be a breaking wire change —
# reserve the rest of the byte for forward-compat schemes (e.g., a
# short-hash form) without collision.
TAG_FULL_ID = 0x00   # 32-byte entity_id follows
TAG_INDEX = 0x01     # varint entity_index follows


def encode_entity_ref(entity_id: bytes, state=None) -> bytes:
    """Emit an on-wire entity reference for `entity_id`.

    When `state` is None OR `state` has no index for this entity_id
    yet, we fall back to the legacy 32-byte form (tag 0x00).  This
    keeps RegistrationTransaction and any pre-state caller working
    without special-casing them.

    When `state.entity_id_to_index[entity_id]` exists, emit the
    compact varint form (tag 0x01 + LEB128 index).
    """
    if len(entity_id) != 32:
        raise ValueError(
            f"entity_id must be 32 bytes, got {len(entity_id)}"
        )
    if state is not None:
        idx = _lookup_index(state, entity_id)
        if idx is not None:
            return bytes([TAG_INDEX]) + encode_varint(idx)
    return bytes([TAG_FULL_ID]) + entity_id


def decode_entity_ref(
    data: bytes, offset: int = 0, state=None,
) -> tuple[bytes, int]:
    """Read one entity reference from `data` starting at `offset`.

    Returns `(entity_id, bytes_consumed)`.  Raises on:
        * truncated input,
        * unknown tag byte,
        * tag=0x01 (index) with no state available to resolve, or
          an index not present in state's index→id map.
    """
    if offset >= len(data):
        raise ValueError("entity ref truncated at tag")
    tag = data[offset]
    if tag == TAG_FULL_ID:
        if offset + 1 + 32 > len(data):
            raise ValueError("entity ref truncated at full id")
        entity_id = bytes(data[offset + 1:offset + 1 + 32])
        return entity_id, 1 + 32
    if tag == TAG_INDEX:
        index, n = decode_varint(data, offset + 1)
        entity_id = _lookup_entity_id(state, index)
        if entity_id is None:
            raise ValueError(
                f"entity ref uses unknown index {index} (state lacks mapping)"
            )
        return entity_id, 1 + n
    raise ValueError(f"unknown entity-ref tag 0x{tag:02x}")


def encoded_entity_ref_size(entity_id: bytes, state=None) -> int:
    """Return the byte length that `encode_entity_ref` would produce.

    Avoids allocating the blob on hot paths (e.g., fee estimation,
    layout math).
    """
    if state is not None:
        idx = _lookup_index(state, entity_id)
        if idx is not None:
            return 1 + varint_size(idx)
    return 1 + 32


def _lookup_index(state, entity_id: bytes) -> int | None:
    """Pluck `entity_id_to_index[entity_id]` off the state safely.

    `state` is typed as Blockchain at call sites, but we use duck typing
    here so test fixtures with lightweight state stubs also work.
    Returns None if state doesn't carry the registry or the entity
    isn't present — the caller then falls back to the full-id form.
    """
    if state is None:
        return None
    mapping = getattr(state, "entity_id_to_index", None)
    if mapping is None:
        return None
    return mapping.get(entity_id)


def _lookup_entity_id(state, index: int) -> bytes | None:
    if state is None:
        return None
    mapping = getattr(state, "entity_index_to_id", None)
    if mapping is None:
        return None
    return mapping.get(index)
