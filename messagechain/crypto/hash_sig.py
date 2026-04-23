"""
WOTS+ (Winternitz One-Time Signature) implementation.

A quantum-resistant hash-based signature scheme using only SHA3-256.
SPHINCS+ and XMSS are built on this primitive. This is the real cryptographic
foundation - hash-based signatures are provably secure against quantum computers
because their security reduces to the preimage/collision resistance of the hash function.
"""

import hashlib
import hmac
import struct
from messagechain.config import (
    HASH_ALGO, WOTS_W, WOTS_KEY_CHAINS, WOTS_CHAIN_LENGTH,
    SIG_VERSION_WOTS_W16_K64, SIG_VERSION_WOTS_W16_K64_V2,
    SIG_VERSION_CURRENT,
)
from messagechain.crypto.hashing import default_hash


def _hash(data: bytes) -> bytes:
    return default_hash(data)


def _prf(seed: bytes, index: int) -> bytes:
    """Pseudorandom function: deterministic key derivation."""
    return _hash(seed + struct.pack(">Q", index))


def _chain(value: bytes, start: int, steps: int, public_seed: bytes, address: int) -> bytes:
    """Iterate the hash chain `steps` times starting at position `start`."""
    if start < 0:
        raise ValueError(f"chain start must be non-negative, got {start}")
    if steps < 0:
        raise ValueError(f"chain steps must be non-negative, got {steps}")
    if start + steps > WOTS_CHAIN_LENGTH:
        raise ValueError(
            f"chain overflow: start({start}) + steps({steps}) > CHAIN_LENGTH({WOTS_CHAIN_LENGTH})"
        )
    result = value
    for i in range(start, start + steps):
        # Domain separation prevents multi-target attacks
        domain = struct.pack(">QQ", address, i)
        result = _hash(public_seed + domain + result)
    return result


def wots_keygen(seed: bytes) -> tuple[list[bytes], bytes, bytes]:
    """
    Generate a WOTS+ keypair.

    Returns:
        (private_keys, public_key, public_seed)
        - private_keys: list of secret chain starting values
        - public_key: hash of all chain endpoints (the verifiable identity)
        - public_seed: randomization value for chaining
    """
    public_seed = _hash(seed + b"public_seed")

    # Generate private key chains (as mutable bytearrays for safe zeroing)
    private_keys = []
    for i in range(WOTS_KEY_CHAINS):
        sk_i = bytearray(_prf(seed, i))
        private_keys.append(sk_i)

    # Compute public key: hash chain each private key to the end, then hash all together
    pk_parts = []
    for i, sk in enumerate(private_keys):
        pk_i = _chain(sk, 0, WOTS_CHAIN_LENGTH, public_seed, i)
        pk_parts.append(pk_i)

    public_key = _hash(b"".join(pk_parts))
    return private_keys, public_key, public_seed


def _message_to_base_w(
    msg_hash: bytes, sig_version: int = SIG_VERSION_CURRENT,
) -> list[int]:
    """Convert message hash to base-W digits for signing.

    WOTS+ security rests on the checksum: it ensures that any attempt
    to advance a message chain forward (forging a higher digit) must
    be balanced by a DECREASE in some checksum chain — which is
    preimage-hard.  That guarantee requires the checksum value to
    actually land in the retained chain positions.

    Two encodings are supported for crypto-agility:

    V1 (SIG_VERSION_WOTS_W16_K64): `struct.pack(">I", checksum)` (4
    bytes = 8 nibbles) truncated to `[:WOTS_KEY_CHAINS]` which kept
    only the FIRST 4 of those 8 nibbles — the high nibbles of the top
    16 bits.  Max checksum is 60*15 = 900 = 0x384, so the top 16 bits
    were always zero, meaning every checksum chain always fired at
    digit 0.  The checksum was effectively constant, collapsing WOTS+
    security from the intended 128-bit margin to ~2^56 grinding
    (60 monotonic-digit constraints each at ≈0.53 probability).
    Retained only so the live mainnet chain (committed under V1) still
    validates; all new signatures use V2.

    V2 (SIG_VERSION_WOTS_W16_K64_V2): `struct.pack(">H", checksum)`
    gives exactly 4 nibbles — enough to represent 900 (fits in 10
    bits) and no truncation is needed.  All 4 checksum chains carry
    the real checksum value; WOTS+ security is at its intended level.
    """
    digits = []
    for byte in msg_hash:
        digits.append(byte >> 4)   # high nibble (0-15)
        digits.append(byte & 0x0F)  # low nibble (0-15)
    msg_digits = digits[:WOTS_KEY_CHAINS - 4]

    checksum = sum(WOTS_CHAIN_LENGTH - d for d in msg_digits)

    if sig_version == SIG_VERSION_WOTS_W16_K64_V2:
        # 2 bytes = 4 nibbles exactly, matching the 4 retained checksum
        # chain positions.  Max encoded value 65535 ≫ max checksum 900.
        checksum_bytes = struct.pack(">H", checksum)
    else:
        # Legacy V1 encoding.  Preserved byte-for-byte for backward
        # compatibility with pre-V2 signatures on the committed chain.
        checksum_bytes = struct.pack(">I", checksum)

    for byte in checksum_bytes:
        msg_digits.append(byte >> 4)
        msg_digits.append(byte & 0x0F)

    return msg_digits[:WOTS_KEY_CHAINS]


def wots_sign(
    msg_hash: bytes, private_keys: list[bytes], public_seed: bytes,
    sig_version: int = SIG_VERSION_CURRENT,
) -> list[bytes]:
    """
    Sign a message hash with WOTS+.

    Each digit d of the base-W message determines how many times we hash
    the corresponding private key chain. The verifier can hash the remaining
    (W-1-d) times to reach the public chain endpoint.

    `sig_version` selects the base-w encoding — see `_message_to_base_w`.
    """
    digits = _message_to_base_w(msg_hash, sig_version=sig_version)
    signature = []
    for i, d in enumerate(digits):
        sig_i = _chain(private_keys[i], 0, d, public_seed, i)
        # When d=0, _chain returns the input object unchanged. Convert
        # to immutable bytes so the signature is independent of any
        # later zeroing of the private key material.
        signature.append(bytes(sig_i))
    return signature


def wots_verify(
    msg_hash: bytes, signature: list[bytes], public_key: bytes,
    public_seed: bytes, sig_version: int = SIG_VERSION_CURRENT,
) -> bool:
    """
    Verify a WOTS+ signature.

    For each signature element, hash it (W-1-d) more times to reach the
    public chain endpoint. If all endpoints match the public key, it's valid.

    Returns False on malformed input rather than raising — callers rely on
    this being total over all inputs to avoid DoS via uncaught exceptions.

    `sig_version` selects the base-w encoding used at sign time.  Legacy
    V1 sigs use the old checksum-truncation encoding; V2+ uses the fix.
    """
    # Strict structural validation. A WOTS+ verification must be total
    # (never raise) so that adversarial peers cannot crash validation
    # by sending malformed signatures.
    if not isinstance(msg_hash, (bytes, bytearray)) or len(msg_hash) != 32:
        return False
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    if not isinstance(public_seed, (bytes, bytearray)) or len(public_seed) != 32:
        return False
    if not isinstance(signature, list) or len(signature) != WOTS_KEY_CHAINS:
        return False
    for part in signature:
        if not isinstance(part, (bytes, bytearray)) or len(part) != 32:
            return False

    digits = _message_to_base_w(msg_hash, sig_version=sig_version)
    pk_parts = []
    dummy = b'\x00' * 32
    for i, d in enumerate(digits):
        remaining = WOTS_CHAIN_LENGTH - d
        pk_i = _chain(signature[i], d, remaining, public_seed, i)
        pk_parts.append(pk_i)
        # Constant-time normalization: always perform WOTS_CHAIN_LENGTH total
        # hash iterations per chain element regardless of digit value d.
        # The real computation does `remaining` steps; the dummy does `d` steps.
        # Total = remaining + d = WOTS_CHAIN_LENGTH for every chain element.
        if d > 0:
            _chain(dummy, 0, d, public_seed, i)

    computed_pk = _hash(b"".join(pk_parts))
    return hmac.compare_digest(computed_pk, public_key)
