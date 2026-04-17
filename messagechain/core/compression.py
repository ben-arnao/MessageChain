"""Canonical-form payload compression for MessageTransaction.

Rationale: every byte written to the chain is paid for forever by every
future node that syncs or archives history. Short messages compressed
with raw-deflate shrink roughly 30-50% on typical English text and
>95% on pathological repeating content, which is pure storage win for
the full-history durability model.

Why stdlib zlib (not zstd):
- zlib ships with Python since 1995, guaranteed on every platform.
- Dropping a pip dependency into a permanent-ledger project introduces
  long-term supply-chain risk — if pyzstd/zstandard ever stops
  maintaining wheels for a future Python, old nodes can't sync old
  blocks. stdlib only.
- zlib level 9 output is deterministic across Python versions
  (regression-tested in tests/test_payload_compression.py).

Canonical form:
- Strip the 2-byte zlib header and 4-byte adler32 trailer — they're
  redundant with the surrounding tx_hash integrity check and cost 6
  bytes per transaction forever.
- Decompression uses raw-deflate (negative MAX_WBITS).
- Always compute both raw and compressed forms; keep whichever is
  smaller. On a tie, prefer raw (no decode step, simpler). This rule
  makes the stored form a deterministic function of the plaintext —
  two honest encoders produce identical bytes, so tx_hash matches.
"""

import zlib


RAW_FLAG = 0
COMPRESSED_FLAG = 1

# Hard cap on decompressed payload size.  4x MAX_MESSAGE_CHARS (280)
# gives generous margin for any valid message while stopping
# decompression bombs cold.  A malicious tx with small compressed
# bytes that decompress to megabytes/gigabytes is rejected here.
MAX_DECOMPRESSED_MESSAGE_SIZE = 1120


def encode_payload(plaintext: bytes) -> tuple[bytes, int]:
    """Return (stored_bytes, compression_flag) in canonical form.

    Canonical rule: store whichever is smaller of raw or compressed. On
    a size tie, prefer raw. Deterministic — same plaintext always
    yields the same (stored, flag) pair.
    """
    if not plaintext:
        return b"", RAW_FLAG
    compressed = zlib.compress(plaintext, 9)[2:-4]
    if len(compressed) < len(plaintext):
        return compressed, COMPRESSED_FLAG
    return plaintext, RAW_FLAG


def decode_payload(stored: bytes, flag: int) -> bytes:
    """Reverse encode_payload — return the original plaintext bytes.

    Raises ValueError on unknown flags to make malformed inputs
    explicit rather than silently re-interpreting bytes.
    """
    if flag == RAW_FLAG:
        return stored
    if flag == COMPRESSED_FLAG:
        dobj = zlib.decompressobj(-zlib.MAX_WBITS)
        result = dobj.decompress(stored, MAX_DECOMPRESSED_MESSAGE_SIZE)
        if dobj.unconsumed_tail:
            raise ValueError(
                f"Decompressed payload exceeds {MAX_DECOMPRESSED_MESSAGE_SIZE} bytes"
            )
        return result
    raise ValueError(f"Unknown compression flag: {flag}")
