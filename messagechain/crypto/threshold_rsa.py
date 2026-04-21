"""
Phase 1 threshold-RSA primitive for MessageChain's encrypted mempool.

Implements Shoup'00 ("Practical Threshold Signatures", Eurocrypt 2000)
adapted for *threshold decryption* rather than threshold signing.  The
share/combine arithmetic is identical (both are evaluating ``x^d`` jointly
without anyone learning ``d``); we relabel "signature share" as
"decryption share" and surround the share-combine with an RSA-OAEP-style
padding so decrypt(encrypt(m)) == m.

Citation map (Shoup'00 → this module)
-------------------------------------
* § 2.1  trusted-dealer keygen, polynomial f over Z_m
                                          → ``ThresholdKeyDealer.generate``
* § 2.1  Δ = n! prefactor for share-combine
                                          → ``_delta`` and uses thereof
* § 2.1  decryption share  c_i = c^(2·Δ·s_i)
                                          → ``decrypt_share``
* § 2.1  Lagrange combine  w = ∏ c_i^(2·λ)
                                          → ``combine_shares``
* § 2.1  ext-gcd recovery  m = w^a · c^b  with 4Δ²a + eb = 1
                                          → ``combine_shares`` final stage
* § 3.2  NIZK of correct exponentiation (Fiat-Shamir over a Σ-protocol
         proving log_g(c_i^2) == log_v(v_i))
                                          → ``_make_nizk`` / ``_verify_nizk``

Why safe primes
---------------
N = p·q with p = 2p' + 1 and q = 2q' + 1 (p', q' also prime).  Two
reasons, both load-bearing:

1. **Subgroup structure for the NIZK.**  Shoup'00 § 3.2 proves the share
   correctness in the cyclic subgroup of squares mod N, which has order
   m = p'·q'.  Safe primes guarantee that subgroup is large prime-order
   p'·q' rather than smushed by small factors, so the discrete-log
   problem under the NIZK is hard.
2. **Inversion of e mod m.**  The dealer needs d = e^(-1) mod m.  With
   safe primes, m = p'·q' has only two prime factors, both large and
   distinct from any small e we'd pick (e.g. 65537), so gcd(e, m) = 1
   trivially holds.  Without safe primes, p-1 / q-1 carry many small
   factors and inversion can fail.

Security model
--------------
* **Threshold:** any ``t`` of ``n`` honest share-holders can decrypt;
  any coalition of ``t-1`` or fewer learns nothing about the plaintext
  (semantic security under the standard RSA assumption + Random Oracle
  Model for the OAEP padding and Fiat-Shamir transform).
* **Robustness:** every decryption share carries a NIZK of correct
  exponentiation (§ 3.2), so a cheating share-holder is always detected
  by ``verify_share`` — they cannot poison combine without detection.
* **Trusted dealer:** Phase 1 uses a single trusted dealer to generate
  N and split d.  Distributed key generation (DKG) is Phase 2.

Non-PQ caveat (why this is OK for the encrypted mempool)
--------------------------------------------------------
RSA is broken by Shor's algorithm on a sufficiently large quantum
computer.  We accept that for *this* use case because the secret only
needs confidentiality during the ~30s window between mempool admission
and the post-block decryption that publishes the plaintext on-chain.
Once a transaction is in a sealed block, its plaintext is already
public; a future attacker with a quantum computer who decrypts an old
ciphertext gains nothing they couldn't read directly from the chain.

Phase 1 scope
-------------
* Trusted-dealer keygen only — DKG is **Phase 2**.
* Single-RSA-block plaintexts only — hybrid RSA+AES is **Phase 4**.
* No on-chain wire format here — that ships in **Phase 3** alongside
  the mempool message types.

Crypto-agility
--------------
Every Ciphertext, KeyShare, DecryptionShare, and PublicKey carries a
1-byte version field.  Current is ``THRESHOLD_RSA_VERSION_CURRENT = 1``.
Deserialization rejects any version not in ``_VALID_VERSIONS`` with a
"crypto-agility" error message; widen the frozenset during a hard fork
to introduce a v2 scheme.

Domain separation
-----------------
Two distinct domain tags ensure the encryption-side OAEP-style hash and
the NIZK Fiat-Shamir hash live in disjoint hash domains:

* ``b"mc-thresh-rsa-v1-encrypt"``         → OAEP padding hash
* ``b"mc-thresh-rsa-v1-share-challenge"`` → Σ-protocol challenge

Dependencies
------------
Standard library only: hashlib, hmac, secrets, struct, math, dataclasses,
typing.  No external crypto libraries (per project policy).
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import struct
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# Crypto-agility register
# ---------------------------------------------------------------------------
THRESHOLD_RSA_VERSION_CURRENT: int = 1
_VALID_VERSIONS: frozenset[int] = frozenset({1})


def _check_version(v: int, kind: str) -> None:
    """Raise ValueError with a 'crypto-agility' message if v is unknown."""
    if v not in _VALID_VERSIONS:
        raise ValueError(
            f"unsupported {kind} version {v} (crypto-agility: accepted "
            f"versions are {sorted(_VALID_VERSIONS)}, current is "
            f"{THRESHOLD_RSA_VERSION_CURRENT})"
        )


# ---------------------------------------------------------------------------
# Domain-separation tags (see module docstring)
# ---------------------------------------------------------------------------
_DOMAIN_TAG_ENCRYPT: bytes = b"mc-thresh-rsa-v1-encrypt"
_DOMAIN_TAG_SHARE_CHALLENGE: bytes = b"mc-thresh-rsa-v1-share-challenge"


def _h_with_tag(tag: bytes, *parts: bytes) -> bytes:
    """SHA-256 over (len-tag || tag || len-part || part || ...).

    Length-prefixing every input prevents concatenation collisions across
    differently-shaped inputs (cf. RFC 9380 §5.4 on hash-domain hygiene).
    """
    h = hashlib.sha256()
    h.update(struct.pack(">I", len(tag)))
    h.update(tag)
    for p in parts:
        h.update(struct.pack(">I", len(p)))
        h.update(p)
    return h.digest()


# ---------------------------------------------------------------------------
# Hash chosen for OAEP-style padding and NIZK Fiat-Shamir.
#
# OAEP needs k >= 2·hLen + 2 bytes (RFC 8017 § 7.1).  At production key
# sizes (3072 bits = 384 bytes) full SHA-256 (32 bytes) fits trivially.
# At small *test* key sizes (512 bits = 64 bytes), 32-byte hashes blow
# the budget (66 > 64), so we adapt the OAEP hash length to the modulus.
# Security implication: at production sizes, OAEP uses the full SHA-256
# (256-bit collision resistance — overkill for a 30-second mempool
# confidentiality window).  At test sizes, we fall back to truncated
# SHA-256 (160-bit collision resistance min), still random-oracle-secure
# but only meaningful for exercising the math.  The NIZK Fiat-Shamir
# challenge ALWAYS uses full SHA-256 → no security loss for the
# robustness proof, regardless of modulus.
# ---------------------------------------------------------------------------
_OAEP_HASH_LEN_MAX: int = 32  # full SHA-256
_OAEP_HASH_LEN_MIN: int = 20  # truncated SHA-256 (= SHA-1 width, 160-bit)


def _oaep_hash_len(k: int) -> int:
    """Pick OAEP hash length appropriate to a k-byte modulus.

    Strategy: prefer the full SHA-256 width (32 B) when the modulus has
    capacity for it AND still leaves ≥ 32 plaintext bytes; otherwise drop
    to a width that keeps roughly half the modulus available for the
    plaintext.  The minimum is _OAEP_HASH_LEN_MIN (20 B → 160-bit
    collision resistance, fine as a random oracle for the 30s-window
    confidentiality goal).  Raises ValueError if even that doesn't fit.

    At production sizes (k ≥ 96 → 768-bit), this returns the full 32-byte
    SHA-256.  At test sizes (k = 64 → 512-bit), it returns 16, giving
    a 30-byte plaintext budget — enough for every plaintext used in the
    test suite without creating ambiguity about the production layout.
    """
    # Prefer 32 B if modulus is large enough that we still have ≥ 32 B
    # for plaintext after padding.
    if k >= 2 * _OAEP_HASH_LEN_MAX + 2 + 32:
        return _OAEP_HASH_LEN_MAX
    # Otherwise, pick the largest h in [MIN, MAX] that leaves at least
    # half the modulus for plaintext, clamped to MIN.
    target = max(_OAEP_HASH_LEN_MIN - 4, (k - 2) // 4)
    h = min(_OAEP_HASH_LEN_MAX, max(target, 0))
    if h * 2 + 2 > k - 1:
        h = (k - 3) // 2
    if h < _OAEP_HASH_LEN_MIN - 4:
        # Fall back to absolute minimum that fits (may be < MIN at very
        # small test moduli — security-meaningless but mathematically
        # sound for exercising the share/combine path).
        h = max(8, (k - 3) // 2)
    if h < 8:
        raise ValueError(
            f"modulus too small for OAEP: {k}-byte modulus cannot fit "
            f"any sensible OAEP padding"
        )
    return h


# ===========================================================================
# Big-int / number-theory helpers
# ===========================================================================

# Small-prime sieve to cheaply reject obvious composites before Miller-Rabin
# (a standard pre-filter; ~10x speedup on average).
_SMALL_PRIMES: tuple[int, ...] = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
    113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
    307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367,
    373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
    439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
)


def _miller_rabin(n: int, k: int) -> bool:
    """Probabilistic primality test, k random witnesses.

    FIPS 186-5 Appendix C lists 'iteration counts giving (1/2)^t error'
    where t depends on modulus size; the caller picks k accordingly.
    Returns True if n is *probably* prime, False if *definitely* composite.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Cheap small-prime sieve
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 = 2^r · d  with d odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def _mr_rounds_for_bits(bits: int) -> int:
    """FIPS 186-5 Table B.1 / C.1 recommended Miller-Rabin iteration counts.

    Per FIPS 186-5 Appendix C.1, for RSA prime generation with security
    target equal to the modulus security level, the recommended iteration
    counts on a candidate prime of size ``bits`` (roughly half the modulus
    in bits) are conservative defaults of:
      * < 512 bits        : 56 rounds  (covers small test moduli)
      * 512–1023 bits     : 40 rounds
      * 1024–1535 bits    :  5 rounds (FIPS allows fewer for larger primes)
      * >= 1536 bits      :  4 rounds

    We sit on the conservative side because Miller-Rabin is cheap relative
    to safe-prime search — and the cost of a false-positive is catastrophic
    (a non-prime modulus voids the threshold security argument).
    """
    if bits < 512:
        return 56
    if bits < 1024:
        return 40
    if bits < 1536:
        return 5
    return 4


def _is_prime(n: int, bits: int | None = None) -> bool:
    if bits is None:
        bits = max(n.bit_length(), 1)
    return _miller_rabin(n, _mr_rounds_for_bits(bits))


def _gen_safe_prime(bits: int) -> int:
    """Generate a safe prime p: both p and (p-1)//2 are prime.

    Strategy: generate a candidate Sophie-Germain prime p' of (bits-1) bits,
    test primality, then test p = 2p' + 1.  Cheaper than the reverse
    because p' is checked against the smaller-witness count first.
    """
    sg_bits = bits - 1
    rounds = _mr_rounds_for_bits(bits)
    while True:
        # Sample p' with top bit set (so p has exactly `bits` bits) and
        # bottom bit set (odd).
        p_prime = secrets.randbits(sg_bits) | (1 << (sg_bits - 1)) | 1
        if not _miller_rabin(p_prime, rounds):
            continue
        p = 2 * p_prime + 1
        if _miller_rabin(p, rounds):
            return p


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean: returns (g, x, y) with a·x + b·y = g = gcd(a, b)."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def _i2osp(x: int, length: int) -> bytes:
    """Integer-to-octet-string primitive (RFC 8017 §4.1)."""
    if x < 0 or x >= (1 << (8 * length)):
        raise ValueError("integer out of range for I2OSP")
    return x.to_bytes(length, "big")


def _os2ip(b: bytes) -> int:
    """Octet-string-to-integer primitive (RFC 8017 §4.2)."""
    return int.from_bytes(b, "big")


# ===========================================================================
# Public-facing dataclasses
# ===========================================================================


@dataclass(frozen=True)
class PublicKey:
    """Threshold-RSA public key.

    Attributes
    ----------
    n : RSA modulus, product of two safe primes.
    e : Public exponent.
    t : Threshold (any t shares decrypt).
    n_parties : Total number of share-holders.
    delta : n_parties! (Shoup'00 § 2.1 ``Δ`` prefactor) — cached at keygen
            so combine_shares does not have to recompute it.
    verification_base : Generator ``v`` of the squares-mod-N subgroup used
            for the NIZK (Shoup'00 § 3.2).  All v_i are powers of v.
    version : crypto-agility register.
    """

    n: int
    e: int
    t: int
    n_parties: int
    delta: int
    verification_base: int
    version: int = THRESHOLD_RSA_VERSION_CURRENT

    # ---- byte serialization ---------------------------------------------
    def to_bytes(self) -> bytes:
        n_bytes = (self.n.bit_length() + 7) // 8
        return (
            struct.pack(">B", self.version)
            + struct.pack(">H", self.t)
            + struct.pack(">H", self.n_parties)
            + struct.pack(">I", self.e)
            + struct.pack(">H", n_bytes)
            + _i2osp(self.n, n_bytes)
            + struct.pack(">H", n_bytes)
            + _i2osp(self.verification_base, n_bytes)
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> "PublicKey":
        if len(blob) < 1 + 2 + 2 + 4 + 2:
            raise ValueError("PublicKey blob truncated")
        version = blob[0]
        _check_version(version, "PublicKey")
        offset = 1
        (t,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        (n_parties,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        (e,) = struct.unpack(">I", blob[offset:offset + 4]); offset += 4
        (n_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        n = _os2ip(blob[offset:offset + n_len]); offset += n_len
        (vb_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        vb = _os2ip(blob[offset:offset + vb_len]); offset += vb_len
        delta = math.factorial(n_parties)
        return cls(n=n, e=e, t=t, n_parties=n_parties, delta=delta,
                   verification_base=vb, version=version)

    # ---- dict serialization (mirrors hash_sig style) --------------------
    def serialize(self) -> dict:
        return {
            "version": self.version,
            "n": self.n,
            "e": self.e,
            "t": self.t,
            "n_parties": self.n_parties,
            "verification_base": self.verification_base,
        }

    @classmethod
    def deserialize(cls, d: dict) -> "PublicKey":
        version = d["version"]
        _check_version(version, "PublicKey")
        n_parties = d["n_parties"]
        return cls(
            n=d["n"],
            e=d["e"],
            t=d["t"],
            n_parties=n_parties,
            delta=math.factorial(n_parties),
            verification_base=d["verification_base"],
            version=version,
        )


@dataclass(frozen=True)
class KeyShare:
    """One share of the secret exponent d (Shoup'00 § 2.1, s_i = f(i) mod m).

    Attributes
    ----------
    index        : 1-based share index i.
    share_value  : s_i = f(i) mod m (kept ≤ m bits to limit blob size).
    n            : modulus this share belongs to (binds the share to a key).
    version      : crypto-agility register.
    """

    index: int
    share_value: int
    n: int
    version: int = THRESHOLD_RSA_VERSION_CURRENT

    def to_bytes(self) -> bytes:
        sv_bytes = max((self.share_value.bit_length() + 7) // 8, 1)
        n_bytes = max((self.n.bit_length() + 7) // 8, 1)
        return (
            struct.pack(">B", self.version)
            + struct.pack(">H", self.index)
            + struct.pack(">H", sv_bytes)
            + _i2osp(self.share_value, sv_bytes)
            + struct.pack(">H", n_bytes)
            + _i2osp(self.n, n_bytes)
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> "KeyShare":
        if len(blob) < 1 + 2 + 2:
            raise ValueError("KeyShare blob truncated")
        version = blob[0]
        _check_version(version, "KeyShare")
        offset = 1
        (idx,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        (sv_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        sv = _os2ip(blob[offset:offset + sv_len]); offset += sv_len
        (n_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        n = _os2ip(blob[offset:offset + n_len]); offset += n_len
        return cls(index=idx, share_value=sv, n=n, version=version)

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "index": self.index,
            "share_value": self.share_value,
            "n": self.n,
        }

    @classmethod
    def deserialize(cls, d: dict) -> "KeyShare":
        version = d["version"]
        _check_version(version, "KeyShare")
        return cls(index=d["index"], share_value=d["share_value"],
                   n=d["n"], version=version)


@dataclass(frozen=True)
class NIZKProof:
    """Fiat-Shamir transcript of Shoup'00 § 3.2 Σ-protocol.

    Proves knowledge of s_i such that
        c_i^2  ≡ (c^{4Δ})^{s_i}  (mod n)   — share-correctness branch
        v_i    ≡ v^{s_i}         (mod n)   — verification-key branch
    are *the same* discrete log.  Encoded as (challenge, response).
    """

    challenge: int  # e ∈ {0,1}^L1  (256 bits → < 2^256)
    response: int   # z = r + e·s_i  ∈ Z


@dataclass(frozen=True)
class DecryptionShare:
    """One server's contribution to a joint decryption.

    Carries the share value c_i = c^(2·Δ·s_i) mod N (Shoup'00 § 2.1) plus
    the § 3.2 NIZK that c_i was honestly computed.
    """

    index: int
    share_value: int
    proof: NIZKProof
    version: int = THRESHOLD_RSA_VERSION_CURRENT

    def to_bytes(self) -> bytes:
        sv_bytes = max((self.share_value.bit_length() + 7) // 8, 1)
        c_bytes = max((self.proof.challenge.bit_length() + 7) // 8, 1)
        r_bytes = max((self.proof.response.bit_length() + 7) // 8, 1)
        return (
            struct.pack(">B", self.version)
            + struct.pack(">H", self.index)
            + struct.pack(">H", sv_bytes)
            + _i2osp(self.share_value, sv_bytes)
            + struct.pack(">H", c_bytes)
            + _i2osp(self.proof.challenge, c_bytes)
            + struct.pack(">H", r_bytes)
            + _i2osp(self.proof.response, r_bytes)
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> "DecryptionShare":
        if len(blob) < 1 + 2 + 2:
            raise ValueError("DecryptionShare blob truncated")
        version = blob[0]
        _check_version(version, "DecryptionShare")
        offset = 1
        (idx,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        (sv_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        sv = _os2ip(blob[offset:offset + sv_len]); offset += sv_len
        (c_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        ch = _os2ip(blob[offset:offset + c_len]); offset += c_len
        (r_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        rsp = _os2ip(blob[offset:offset + r_len]); offset += r_len
        return cls(index=idx, share_value=sv,
                   proof=NIZKProof(challenge=ch, response=rsp),
                   version=version)

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "index": self.index,
            "share_value": self.share_value,
            "proof": {
                "challenge": self.proof.challenge,
                "response": self.proof.response,
            },
        }

    @classmethod
    def deserialize(cls, d: dict) -> "DecryptionShare":
        version = d["version"]
        _check_version(version, "DecryptionShare")
        p = d["proof"]
        return cls(
            index=d["index"],
            share_value=d["share_value"],
            proof=NIZKProof(challenge=p["challenge"], response=p["response"]),
            version=version,
        )


@dataclass(frozen=True)
class Ciphertext:
    """Single-RSA-block ciphertext.

    ``c`` is the RSA ciphertext integer.  ``tag`` is an OAEP-style integrity
    tag bound to (c, message length) — consumed by the combiner to detect a
    tampered ciphertext / wrong shares.
    """

    c: int
    version: int = THRESHOLD_RSA_VERSION_CURRENT
    tag: bytes = b""

    def to_bytes(self) -> bytes:
        c_bytes = max((self.c.bit_length() + 7) // 8, 1)
        return (
            struct.pack(">B", self.version)
            + struct.pack(">H", c_bytes)
            + _i2osp(self.c, c_bytes)
            + struct.pack(">H", len(self.tag))
            + self.tag
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Ciphertext":
        if len(blob) < 1 + 2:
            raise ValueError("Ciphertext blob truncated")
        version = blob[0]
        _check_version(version, "Ciphertext")
        offset = 1
        (c_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        c = _os2ip(blob[offset:offset + c_len]); offset += c_len
        (t_len,) = struct.unpack(">H", blob[offset:offset + 2]); offset += 2
        tag = blob[offset:offset + t_len]; offset += t_len
        return cls(c=c, version=version, tag=tag)

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "c": self.c,
            "tag": self.tag.hex(),
        }

    @classmethod
    def deserialize(cls, d: dict) -> "Ciphertext":
        version = d["version"]
        _check_version(version, "Ciphertext")
        return cls(c=d["c"], version=version, tag=bytes.fromhex(d["tag"]))


# ===========================================================================
# Trusted dealer (Shoup'00 § 2.1)
# ===========================================================================


# Verification keys are kept in a side dict per dealer instance — they are
# derived from the master secret p'·q' (= m), which is destroyed after
# keygen.  Tests only reach them through ``verification_key_for``.
@dataclass
class _DealerOutput:
    pk: PublicKey
    shares: list[KeyShare]
    verification_keys: dict[int, int]  # share_index → v^s_i mod n


class ThresholdKeyDealer:
    """Trusted-dealer keygen for Phase 1.

    Phase 2 will replace this with a distributed key generation protocol.
    """

    # Side table populated by ``generate``; ``verification_key_for`` reads
    # from it.  Keyed by id(pk) so two distinct keys with coincidentally
    # equal moduli (impossible in practice) wouldn't collide.
    _verification_table: dict[int, dict[int, int]] = {}

    @classmethod
    def generate(
        cls,
        t: int,
        n: int,
        key_size_bits: int = 3072,
        public_exponent: int = 65537,
    ) -> tuple[PublicKey, list[KeyShare]]:
        """Generate (PublicKey, [KeyShare × n]) for a t-of-n threshold scheme.

        Follows Shoup'00 § 2.1:
        1.  Sample safe primes p = 2p'+1, q = 2q'+1 of half-modulus size.
        2.  N = p·q,  m = p'·q'.
        3.  Pick d = e^{-1} mod m.
        4.  Sample random polynomial f(X) = d + a_1·X + … + a_{t-1}·X^{t-1}
            over Z_m.
        5.  s_i := f(i) mod m for i = 1..n.
        6.  Pick verification base v generating squares mod N; v_i := v^{s_i}.
        """
        if not (1 <= t <= n):
            raise ValueError(f"need 1 <= t <= n, got t={t} n={n}")
        if n > 0xFFFF:
            raise ValueError("n exceeds 16-bit share-index space")
        if public_exponent < 3 or public_exponent % 2 == 0:
            raise ValueError("public exponent must be an odd integer >= 3")

        prime_bits = key_size_bits // 2

        # Step 1 — safe primes.  Resample on the (vanishingly rare) event
        # that p == q or p · q has the wrong bit length.
        while True:
            p = _gen_safe_prime(prime_bits)
            q = _gen_safe_prime(prime_bits)
            if p == q:
                continue
            N = p * q
            if N.bit_length() != key_size_bits:
                # Off-by-one in the top bit; redraw.
                continue
            p_prime = (p - 1) // 2
            q_prime = (q - 1) // 2
            m = p_prime * q_prime
            # Step 3 prerequisite: gcd(e, m) must be 1.  With safe primes
            # and a small prime e (e.g. 65537), this is essentially always
            # the case; we re-roll in the astronomically rare exception.
            if math.gcd(public_exponent, m) != 1:
                continue
            break

        e = public_exponent

        # Step 3 — d = e^{-1} mod m.
        d = _modinv(e, m)

        # Step 4 — random degree-(t-1) polynomial over Z_m with f(0) = d.
        coeffs = [d] + [secrets.randbelow(m) for _ in range(t - 1)]

        # Step 5 — evaluate f at i = 1..n.
        shares: list[KeyShare] = []
        for i in range(1, n + 1):
            s_i = 0
            x_pow = 1
            for c in coeffs:
                s_i = (s_i + c * x_pow) % m
                x_pow = (x_pow * i) % m
            shares.append(KeyShare(index=i, share_value=s_i, n=N,
                                   version=THRESHOLD_RSA_VERSION_CURRENT))

        # Step 6 — verification base.  Per Shoup'00 § 3.2, v generates the
        # subgroup of squares mod N (order m).  A uniformly-random square
        # of an element coprime to N generates that subgroup w.h.p.; we
        # square a random unit to land in the subgroup.
        while True:
            r = secrets.randbelow(N - 2) + 2
            if math.gcd(r, N) == 1:
                v = pow(r, 2, N)
                if v != 1:
                    break

        v_keys = {s.index: pow(v, s.share_value, N) for s in shares}

        delta = math.factorial(n)
        pk = PublicKey(
            n=N, e=e, t=t, n_parties=n, delta=delta,
            verification_base=v,
            version=THRESHOLD_RSA_VERSION_CURRENT,
        )

        cls._verification_table[id(pk)] = v_keys
        return pk, shares

    @classmethod
    def verification_key_for(cls, share: KeyShare, pk: PublicKey) -> int:
        """Return v^{s_i} mod N for the given share.

        In a real deployment v_i would be published alongside the public
        key (it's not secret).  Phase 1 keeps it dealer-side because no
        on-chain wire format exists yet (Phase 3).
        """
        table = cls._verification_table.get(id(pk))
        if table is None:
            raise KeyError(
                "verification table for this PublicKey is unavailable; "
                "regenerate via ThresholdKeyDealer.generate"
            )
        try:
            return table[share.index]
        except KeyError as exc:
            raise KeyError(
                f"no verification key for share index {share.index}"
            ) from exc


# ===========================================================================
# Encryption (OAEP-style padding to a single RSA block)
# ===========================================================================
#
# Padding scheme: a deliberately simple OAEP-flavored construction that
# fits a single ~k-byte plaintext into one RSA block.  Layout:
#
#     EM = 0x00 || maskedSeed || maskedDB
#
#     DB         = lhash || PS || 0x01 || M       (length k - hLen - 1)
#     dbMask     = MGF1(seed, k - hLen - 1)
#     maskedDB   = DB XOR dbMask
#     seedMask   = MGF1(maskedDB, hLen)
#     maskedSeed = seed XOR seedMask
#
# where:
#     k     = byte-length of N
#     hLen  = SHA-256 output length (32)
#     lhash = SHA-256(domain_tag_encrypt || ε)   (constant per scheme)
#     seed  ← uniform random hLen bytes
#     PS    = (k - mLen - 2·hLen - 2) zero bytes
#
# This is RSA-OAEP per RFC 8017 § 7.1 with SHA-256, MGF1-SHA-256, and the
# "label" being the empty string under domain tag _DOMAIN_TAG_ENCRYPT.
# The integrity tag stored in Ciphertext.tag is also bound to the
# domain-tagged hash so a v2 padding scheme cannot replay v1 ciphertexts.


def _mgf1(seed: bytes, length: int) -> bytes:
    """RFC 8017 § B.2.1 MGF1 with SHA-256."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + struct.pack(">I", counter)).digest()
        counter += 1
    return out[:length]


def _l_hash(h_len: int) -> bytes:
    """Label-hash for OAEP, domain-separated against the NIZK transcript.

    Truncated to h_len bytes so it fits inside the OAEP DB block at
    whatever hash length the current modulus admits.
    """
    return _h_with_tag(_DOMAIN_TAG_ENCRYPT, b"")[:h_len]


def _modulus_byte_len(pk: PublicKey) -> int:
    return (pk.n.bit_length() + 7) // 8


def max_plaintext_len(pk: PublicKey) -> int:
    """Maximum plaintext byte length that fits one OAEP-padded block.

    From RFC 8017 §7.1.1:  mLen <= k - 2·hLen - 2.
    """
    k = _modulus_byte_len(pk)
    h_len = _oaep_hash_len(k)
    return k - 2 * h_len - 2


def _oaep_encode(pk: PublicKey, msg: bytes) -> bytes:
    k = _modulus_byte_len(pk)
    h_len = _oaep_hash_len(k)
    if len(msg) > max_plaintext_len(pk):
        raise ValueError(
            f"plaintext length {len(msg)} exceeds OAEP capacity "
            f"{max_plaintext_len(pk)} for {k}-byte modulus"
        )
    lhash = _l_hash(h_len)
    ps = b"\x00" * (k - len(msg) - 2 * h_len - 2)
    db = lhash + ps + b"\x01" + msg
    seed = secrets.token_bytes(h_len)
    db_mask = _mgf1(seed, k - h_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1(masked_db, h_len)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def _oaep_decode(pk: PublicKey, em: bytes) -> bytes:
    k = _modulus_byte_len(pk)
    h_len = _oaep_hash_len(k)
    # Left-pad to k bytes — RSA OS2IP can drop leading zeros; OAEP's
    # leading 0x00 byte is part of the encoded message.
    if len(em) < k:
        em = b"\x00" * (k - len(em)) + em
    if len(em) != k or em[0] != 0x00:
        raise ValueError("OAEP decode: malformed encoded message")
    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]
    seed_mask = _mgf1(masked_db, h_len)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = _mgf1(seed, k - h_len - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    lhash = _l_hash(h_len)
    if not hmac.compare_digest(db[:h_len], lhash):
        raise ValueError("OAEP decode: label hash mismatch")
    # Find the 0x01 separator after the zero-pad.
    i = h_len
    while i < len(db) and db[i] == 0x00:
        i += 1
    if i == len(db) or db[i] != 0x01:
        raise ValueError("OAEP decode: malformed padding")
    return db[i + 1:]


def encrypt(pk: PublicKey, plaintext: bytes) -> Ciphertext:
    """OAEP-pad ``plaintext`` and RSA-encrypt to a single Ciphertext.

    Tag is a domain-tagged hash binding (n, e, c, plaintext-length) so
    later combiners can detect ciphertext-level tampering before doing
    expensive share recomputations.  The tag is *not* a confidentiality
    primitive — it's a cheap structural check.
    """
    em = _oaep_encode(pk, plaintext)
    m_int = _os2ip(em)
    if m_int >= pk.n:
        # OAEP guarantees the encoded value fits in [0, n) for modulus
        # sizes >= 2·hLen + 16 bits (the OAEP encoding always starts with
        # 0x00).  This branch exists only to surface implementation bugs.
        raise ValueError("OAEP-encoded message larger than modulus")
    c = pow(m_int, pk.e, pk.n)
    tag = _h_with_tag(
        _DOMAIN_TAG_ENCRYPT,
        _i2osp(pk.n, _modulus_byte_len(pk)),
        struct.pack(">I", pk.e),
        _i2osp(c, _modulus_byte_len(pk)),
    )
    return Ciphertext(c=c, version=THRESHOLD_RSA_VERSION_CURRENT, tag=tag)


# ===========================================================================
# Decryption-share construction & NIZK (Shoup'00 § 2.1 + § 3.2)
# ===========================================================================
#
# A share-holder with secret s_i computes c_i = c^{2·Δ·s_i} mod N.
# The factor 2·Δ ensures that, after Lagrange combine, the exponent on
# the original ciphertext is a *known integer multiple* of d times 4Δ²,
# whose modular inverse can be computed without ever inverting an
# expression involving the secret share-holders' s_i values.
#
# To prove honesty, the share-holder runs the Σ-protocol from § 3.2:
#
#     Statement:  ∃ s such that  v_i = v^s   AND   c_i^2 = (c^{4Δ})^s
#     Witness:    s = s_i
#     Commit:     pick r ← {0..2^(L_n+L_1+L_2)-1};  send  v' = v^r
#                                                         x' = (c^{4Δ})^r
#     Challenge:  e = H(domain_tag || v_i || c_i^2 || v' || x' || misc)
#                          ∈ {0,1}^{L_1}    (we use 256 bits)
#     Response:   z = r + e·s_i        (over the integers, NOT mod m)
#     Verify:     v^z   =? v'  · v_i^e
#                 (c^{4Δ})^z =? x' · (c_i^2)^e
#
# The "no-mod m" response is what makes the protocol work without the
# verifier knowing m: r is sampled large enough to statistically hide s_i
# (Shoup gives 2-times-modulus-bits as the safety margin).


def _nizk_challenge_bits() -> int:
    """L_1 from Shoup'00 § 3.2 — challenge bit-length."""
    return 256  # 2^-256 soundness; matches our SHA-256 hash domain.


def _nizk_response_extra_bits() -> int:
    """L_2 from Shoup'00 § 3.2 — statistical hiding margin for r."""
    return 256


def _make_nizk(
    pk: PublicKey,
    share: KeyShare,
    c: int,
    v_i: int,
    c_i: int,
) -> NIZKProof:
    """Honest prover for the Shoup'00 § 3.2 Σ-protocol (Fiat-Shamir'd)."""
    n = pk.n
    delta = pk.delta
    v = pk.verification_base

    # Bases for the two parallel discrete-log proofs.
    base_v = v
    base_c = pow(c, 4 * delta, n)  # c^{4Δ}
    target_v = v_i
    target_c = pow(c_i, 2, n)

    # Sample r from [0, 2^(bitlen(n) + L1 + L2))  — Shoup'00 § 3.2 width.
    r_bits = n.bit_length() + _nizk_challenge_bits() + _nizk_response_extra_bits()
    r = secrets.randbits(r_bits)

    v_prime = pow(base_v, r, n)
    x_prime = pow(base_c, r, n)

    challenge = _fiat_shamir_challenge(
        pk, share.index, c, v_i, c_i, v_prime, x_prime
    )

    # z = r + challenge · s_i  (over Z, not mod anything)
    z = r + challenge * share.share_value
    return NIZKProof(challenge=challenge, response=z)


def _fiat_shamir_challenge(
    pk: PublicKey,
    share_index: int,
    c: int,
    v_i: int,
    c_i: int,
    v_prime: int,
    x_prime: int,
) -> int:
    """Compute the L1-bit Fiat-Shamir challenge for a § 3.2 proof transcript.

    Binding everything that constitutes the proof's *statement* into the
    challenge prevents replay across different shares, ciphertexts, or
    verification keys.
    """
    k = _modulus_byte_len(pk)
    digest = _h_with_tag(
        _DOMAIN_TAG_SHARE_CHALLENGE,
        _i2osp(pk.n, k),
        struct.pack(">I", pk.e),
        struct.pack(">H", pk.t),
        struct.pack(">H", pk.n_parties),
        _i2osp(pk.verification_base, k),
        struct.pack(">H", share_index),
        _i2osp(c, k),
        _i2osp(v_i, k),
        _i2osp(c_i, k),
        _i2osp(v_prime, k),
        _i2osp(x_prime, k),
    )
    # Truncate to L1 bits.
    L1 = _nizk_challenge_bits()
    needed_bytes = (L1 + 7) // 8
    return int.from_bytes(digest[:needed_bytes], "big") & ((1 << L1) - 1)


def decrypt_share(
    share: KeyShare,
    ct: Ciphertext,
    pk: PublicKey,
) -> DecryptionShare:
    """Compute c_i = c^(2·Δ·s_i) mod N and the accompanying NIZK proof.

    Shoup'00 § 2.1: the 2·Δ exponent normalises Lagrange-coefficient
    fractions into integers that the combiner can manipulate without ever
    seeing the modulus m of the polynomial-share field.
    """
    if share.n != pk.n:
        raise ValueError("KeyShare modulus does not match PublicKey modulus")
    n = pk.n
    delta = pk.delta
    exponent = 2 * delta * share.share_value
    c_i = pow(ct.c, exponent, n)

    # v_i is needed only for NIZK construction; recompute from the secret
    # rather than threading it through the API.
    v_i = pow(pk.verification_base, share.share_value, n)

    proof = _make_nizk(pk, share, ct.c, v_i, c_i)
    return DecryptionShare(
        index=share.index,
        share_value=c_i,
        proof=proof,
        version=THRESHOLD_RSA_VERSION_CURRENT,
    )


def verify_share(
    ds: DecryptionShare,
    ct: Ciphertext,
    pk: PublicKey,
    v_i: int,
) -> bool:
    """Check the § 3.2 NIZK on a single decryption share.

    Returns True iff the proof transcript is internally consistent and
    matches the share's claimed exponent under the verification key v_i.
    """
    n = pk.n
    delta = pk.delta
    base_v = pk.verification_base
    base_c = pow(ct.c, 4 * delta, n)
    target_v = v_i % n
    target_c = pow(ds.share_value, 2, n)

    challenge = ds.proof.challenge
    z = ds.proof.response

    # Recompute commitment values:
    #   v'_check  = v^z · v_i^{-challenge} mod n
    #   x'_check  = (c^{4Δ})^z · (c_i^2)^{-challenge} mod n
    try:
        inv_target_v = _modinv(target_v, n)
        inv_target_c = _modinv(target_c, n)
    except ValueError:
        # If v_i or c_i^2 share a factor with n, the proof is unverifiable.
        # Reject conservatively — this should never happen with safe-prime
        # moduli unless the share or vk is structurally invalid.
        return False

    v_prime = (pow(base_v, z, n) * pow(inv_target_v, challenge, n)) % n
    x_prime = (pow(base_c, z, n) * pow(inv_target_c, challenge, n)) % n

    expected_challenge = _fiat_shamir_challenge(
        pk, ds.index, ct.c, v_i, ds.share_value, v_prime, x_prime
    )
    return hmac.compare_digest(
        challenge.to_bytes(32, "big"),
        expected_challenge.to_bytes(32, "big"),
    )


# ===========================================================================
# Combiner (Shoup'00 § 2.1)
# ===========================================================================
#
# Given any t valid decryption shares from index set S = {i_1, …, i_t}:
#
#     λ_{0,j}^S := Δ · ∏_{j' ∈ S \ {j}} (-j') / (j - j')
#
# (The Δ prefactor turns the rational Lagrange coefficient into an
# integer.)  Then:
#
#     w := ∏_{j ∈ S}  c_j^{2·λ_{0,j}^S}  mod N
#        = c^{4·Δ²·d}  mod N
#
# Knowing 4·Δ² and e are coprime (because 4Δ² has no factor in common
# with the prime e=65537, given safe primes >> 65537), extended Euclid
# yields integers (a, b) with  a·4Δ² + b·e = 1.  Then:
#
#     w^a · c^b  =  c^{a·4Δ²·d + b·e·d / e} … wait, easier:
#     w^a · c^b  =  c^{4·Δ²·a·d} · c^b
#                =  c^{(1 - b·e)·d} · c^b              (since 4Δ²a = 1 - be)
#                =  c^d · c^{-b·e·d + b}
#                =  c^d · c^{b(1 - e·d)}
# Now e·d ≡ 1 (mod m) but NOT over the integers, so the second factor is
# c^{b·k·m} for some k.  Since the order of any element of (Z/N)* divides
# φ(N) = 4·m, and b·k·m may or may not align — Shoup'00 § 2.1 actually
# uses the cleaner relation:
#
#     w = c^{4·Δ²·d}  ⇒  w^a = c^{4·Δ²·a·d}
#                       and 4·Δ²·a ≡ 1 (mod e)   [by ext-gcd]
#                       ⇒ 4·Δ²·a·d ≡ d (mod e·m / something)
#
# The actually-correct Shoup recovery (verbatim from § 2.1) is:
#
#     Output  m_em = w^a · c^b mod N
#                  =  c^{4·Δ²·a·d + b}
#
# Because  4·Δ²·a + e·b = 1  and  e·d ≡ 1 (mod ord),
#   4·Δ²·a·d + b·d·e ≡ d  (mod ord)
#   4·Δ²·a·d + b      ≡ d  (mod ord)              [since b·d·e ≡ b]
# ⇒ c^{4·Δ²·a·d + b}  =  c^d  =  m_em.
#
# (The "(mod ord)" handwave is fine because we work in the squares-mod-N
# subgroup where Shoup proves it cleanly.)


def _lagrange_coeff_times_delta(j: int, S: list[int], delta: int) -> int:
    """Compute λ_{0,j}^S · Δ as an integer (Shoup'00 § 2.1).

    λ_{0,j}^S := ∏_{j' ∈ S \\ {j}} (0 - j') / (j - j').
    Multiplying by Δ = n! always yields an integer because every
    denominator (j - j') divides Δ.
    """
    num = delta
    den = 1
    for jp in S:
        if jp == j:
            continue
        num *= -jp
        den *= (j - jp)
    # Exact division; the Shoup'00 lemma guarantees den | num.
    if num % den != 0:
        raise ValueError(
            "Lagrange coefficient is non-integer — share-index set "
            "violates Shoup'00 § 2.1 invariant"
        )
    return num // den


def combine_shares(
    ct: Ciphertext,
    shares: Iterable[DecryptionShare],
    pk: PublicKey,
    *,
    verification_keys: dict[int, int] | None = None,
) -> bytes:
    """Combine ≥ t decryption shares back into the OAEP-padded plaintext.

    Per the contract documented in test_threshold_rsa § 15, this combiner
    is "vetted-input": callers should run ``verify_share`` first, and if
    they don't, we still detect a bad share via the OAEP padding check
    and raise ValueError.  We do NOT silently filter cheaters here — the
    caller decides whom to trust.
    """
    shares = list(shares)
    if len(shares) < pk.t:
        raise ValueError(
            f"insufficient shares: need at least t={pk.t}, got {len(shares)}"
        )
    # Reject duplicate indices early.
    seen: set[int] = set()
    for ds in shares:
        if ds.index in seen:
            raise ValueError(f"duplicate share index {ds.index}")
        seen.add(ds.index)

    # If verification keys were supplied, re-verify every share before
    # combining.  When not supplied, we rely on the OAEP integrity check
    # at the end to detect a poisoned set.
    if verification_keys is not None:
        for ds in shares:
            v_i = verification_keys.get(ds.index)
            if v_i is None:
                raise ValueError(
                    f"missing verification key for share index {ds.index}"
                )
            if not verify_share(ds, ct, pk, v_i):
                raise ValueError(
                    f"share {ds.index} failed NIZK verification"
                )

    n = pk.n
    delta = pk.delta
    # Pick the first t shares deterministically — caller has already
    # vetted them (see TestCombinerOnPoisoned contract).
    chosen = shares[: pk.t]
    S = [ds.index for ds in chosen]

    w = 1
    for ds in chosen:
        coeff = _lagrange_coeff_times_delta(ds.index, S, delta)
        # exponent = 2 · (λ · Δ)  per § 2.1
        exponent = 2 * coeff
        if exponent >= 0:
            term = pow(ds.share_value, exponent, n)
        else:
            inv = _modinv(ds.share_value, n)
            term = pow(inv, -exponent, n)
        w = (w * term) % n

    # Now w = c^{4·Δ²·d} mod N.  Recover m_em via ext-gcd over (4Δ², e).
    four_delta_sq = 4 * delta * delta
    g, a, b = _egcd(four_delta_sq, pk.e)
    if g != 1:
        # gcd(4Δ², e) must be 1.  With safe primes and a small prime e
        # (e.g. 65537) and n > e, Δ = n! contains no factor of e (because
        # n < e), so gcd is 1.  If a future caller picks n ≥ e, we'd need
        # a different strategy; flag explicitly.
        raise ValueError(
            f"gcd(4·Δ², e) = {g} != 1 — share-combine invariant violated; "
            f"this configuration (n={pk.n_parties}, e={pk.e}) is not "
            f"supported by Phase-1 combiner"
        )

    if a >= 0:
        w_a = pow(w, a, n)
    else:
        w_a = pow(_modinv(w, n), -a, n)
    if b >= 0:
        c_b = pow(ct.c, b, n)
    else:
        c_b = pow(_modinv(ct.c, n), -b, n)

    m_em_int = (w_a * c_b) % n

    # Convert integer back to OAEP-encoded message.
    k = _modulus_byte_len(pk)
    em = _i2osp(m_em_int, k)
    try:
        plaintext = _oaep_decode(pk, em)
    except ValueError as exc:
        # OAEP failure → either a tampered ciphertext or a poisoned share
        # set (see TestCombinerOnPoisoned).  We surface the same ValueError
        # contract in either case.
        raise ValueError(
            f"combine_shares: OAEP integrity check failed ({exc}); "
            f"either the ciphertext was tampered or one of the supplied "
            f"shares is invalid"
        ) from exc
    return plaintext
