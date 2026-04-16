"""
LEB128 unsigned-varint encoding for entity indices.

LEB128 is the simplest self-delimiting variable-length integer encoding
in common use: each byte carries 7 bits of payload plus a "more follows"
continuation bit in the MSB. Set the continuation bit on every byte except
the last one; the decoder walks bytes until it sees a clear MSB.

Why here, why now:
    * Every on-chain transaction references its sender by `entity_id`
      (32 bytes, derived from pubkey hash). Once an entity has been
      registered, the state can assign it a monotonic `entity_index`
      (1, 2, 3, ...). An index fits in 1-5 bytes vs 32.
    * For the first ~16M entities the index fits in 3 bytes; 16B fits
      in 5 bytes. A varint lets tiny chains pay 1 byte and huge chains
      pay 5 bytes — no wasted bits for typical indices.
    * Saving ~29 bytes per transaction compounds forever in a
      permanent-history chain. At a 15% further reduction on top of
      binary serialization + compression, this is the single largest
      low-risk bloat cut available.

Determinism notes:
    * Unsigned only. A negative index is a programming bug, not a
      wire-level value — encode rejects it.
    * Canonical: encode produces the shortest possible byte sequence
      for each value. A peer that sends a non-canonical encoding
      (e.g., `0x80 0x00` for the value 0) is rejected by decode —
      keeps the on-wire representation a bijection so tx_hash
      integrity checks bite any re-encoding.
    * Bounded: decode enforces a 10-byte cap (enough for any 64-bit
      value; for our 32-bit index range, 5 bytes suffice but we allow
      a little headroom for forward-compat without making the cap
      unbounded — an attacker cannot stall the parser with an
      arbitrarily long "continuation" sequence).
"""

MAX_VARINT_BYTES = 10  # cap: more than enough for a 64-bit payload


def encode_varint(value: int) -> bytes:
    """Encode a non-negative int as canonical LEB128.

    Raises ValueError for negative values — those are always bugs at
    this layer (entity indices are monotonic from 1; 0 is the reserved
    "invalid/unassigned" sentinel, encoded as a single 0x00 byte).
    """
    if value < 0:
        raise ValueError(f"varint requires non-negative, got {value}")
    if value == 0:
        return b"\x00"
    out = bytearray()
    while value > 0:
        byte = value & 0x7F
        value >>= 7
        if value > 0:
            byte |= 0x80  # continuation bit
        out.append(byte)
    return bytes(out)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode one LEB128 varint from `data` starting at `offset`.

    Returns (value, bytes_consumed). Raises ValueError on:
        * truncated input (ran off the end before the terminator byte),
        * non-canonical encoding (a trailing 0x80 byte encodes the
          same value as a single 0x00 — we reject that to keep the
          representation canonical),
        * an encoding longer than MAX_VARINT_BYTES.
    """
    value = 0
    shift = 0
    i = 0
    while True:
        if offset + i >= len(data):
            raise ValueError("varint truncated")
        if i >= MAX_VARINT_BYTES:
            raise ValueError(
                f"varint too long (exceeds {MAX_VARINT_BYTES} bytes)"
            )
        byte = data[offset + i]
        value |= (byte & 0x7F) << shift
        i += 1
        if (byte & 0x80) == 0:
            # Canonical check: a multi-byte encoding whose final byte
            # is 0 means the high 7 bits contributed nothing — that
            # encoding is not minimal, reject it. Exception: a single
            # 0x00 byte is the canonical encoding of 0.
            if i > 1 and byte == 0:
                raise ValueError("non-canonical varint: trailing zero byte")
            return value, i
        shift += 7


def varint_size(value: int) -> int:
    """Return the byte length that `encode_varint(value)` would produce.

    Cheaper than `len(encode_varint(value))` when you only need the
    size (no allocation). Useful for fee calculations and layout math
    that happens on hot paths.
    """
    if value < 0:
        raise ValueError(f"varint requires non-negative, got {value}")
    if value == 0:
        return 1
    n = 0
    while value > 0:
        value >>= 7
        n += 1
    return n
