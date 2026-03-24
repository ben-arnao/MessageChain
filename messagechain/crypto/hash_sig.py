"""
WOTS+ (Winternitz One-Time Signature) implementation.

A quantum-resistant hash-based signature scheme using only SHA3-256.
SPHINCS+ and XMSS are built on this primitive. This is the real cryptographic
foundation - hash-based signatures are provably secure against quantum computers
because their security reduces to the preimage/collision resistance of the hash function.
"""

import hashlib
import struct
from messagechain.config import HASH_ALGO, WOTS_W, WOTS_KEY_CHAINS, WOTS_CHAIN_LENGTH


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _prf(seed: bytes, index: int) -> bytes:
    """Pseudorandom function: deterministic key derivation."""
    return _hash(seed + struct.pack(">Q", index))


def _chain(value: bytes, start: int, steps: int, public_seed: bytes, address: int) -> bytes:
    """Iterate the hash chain `steps` times starting at position `start`."""
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

    # Generate private key chains
    private_keys = []
    for i in range(WOTS_KEY_CHAINS):
        sk_i = _prf(seed, i)
        private_keys.append(sk_i)

    # Compute public key: hash chain each private key to the end, then hash all together
    pk_parts = []
    for i, sk in enumerate(private_keys):
        pk_i = _chain(sk, 0, WOTS_CHAIN_LENGTH, public_seed, i)
        pk_parts.append(pk_i)

    public_key = _hash(b"".join(pk_parts))
    return private_keys, public_key, public_seed


def _message_to_base_w(msg_hash: bytes) -> list[int]:
    """Convert message hash to base-W digits for signing."""
    digits = []
    for byte in msg_hash:
        digits.append(byte >> 4)   # high nibble (0-15)
        digits.append(byte & 0x0F)  # low nibble (0-15)
    # Pad or truncate to WOTS_KEY_CHAINS
    # First part: message digits. Remainder: checksum digits.
    msg_digits = digits[:WOTS_KEY_CHAINS - 4]

    # Checksum: prevents attacker from advancing chains further
    checksum = sum(WOTS_CHAIN_LENGTH - d for d in msg_digits)
    checksum_bytes = struct.pack(">I", checksum)
    for byte in checksum_bytes:
        msg_digits.append(byte >> 4)
        msg_digits.append(byte & 0x0F)

    return msg_digits[:WOTS_KEY_CHAINS]


def wots_sign(msg_hash: bytes, private_keys: list[bytes], public_seed: bytes) -> list[bytes]:
    """
    Sign a message hash with WOTS+.

    Each digit d of the base-W message determines how many times we hash
    the corresponding private key chain. The verifier can hash the remaining
    (W-1-d) times to reach the public chain endpoint.
    """
    digits = _message_to_base_w(msg_hash)
    signature = []
    for i, d in enumerate(digits):
        sig_i = _chain(private_keys[i], 0, d, public_seed, i)
        signature.append(sig_i)
    return signature


def wots_verify(msg_hash: bytes, signature: list[bytes], public_key: bytes, public_seed: bytes) -> bool:
    """
    Verify a WOTS+ signature.

    For each signature element, hash it (W-1-d) more times to reach the
    public chain endpoint. If all endpoints match the public key, it's valid.
    """
    digits = _message_to_base_w(msg_hash)
    pk_parts = []
    for i, d in enumerate(digits):
        remaining = WOTS_CHAIN_LENGTH - d
        pk_i = _chain(signature[i], d, remaining, public_seed, i)
        pk_parts.append(pk_i)

    computed_pk = _hash(b"".join(pk_parts))
    return computed_pk == public_key
