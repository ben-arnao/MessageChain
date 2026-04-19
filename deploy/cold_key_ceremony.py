"""Air-gapped cold authority key generation + 2-of-3 Shamir split.

Run this ONCE, on an **air-gapped machine**, as part of the founder
cold-key ceremony.  Produces:

  * `cold-key-public.txt`   - the public key (commit this to chain via
                              `python -m messagechain set-authority-key`)
  * `cold-share-1.txt`      - Shamir share #1 (keep with founder)
  * `cold-share-2.txt`      - Shamir share #2 (hand to trusted party A)
  * `cold-share-3.txt`      - Shamir share #3 (hand to trusted party B)

Any TWO of the three shares can reconstruct the private key.
The shares and the private key **never touch the network**.

**Post-ceremony**:
  1. Move each share to its designated holder via physical transfer
     (USB + safe-deposit box, paper wallet in a safe, etc.).
  2. Verify recovery once: bring two shares together on a fresh
     air-gapped machine, run `cold_key_ceremony.py --recover`, confirm
     the reconstructed public key matches `cold-key-public.txt`.
  3. Shred `cold-share-*.txt` on the generation machine.
  4. Wipe the generation machine.

The chain only ever sees the PUBLIC key, installed via
`SetAuthorityKeyTransaction`.  The cold private key is used only to
sign `emergency-revoke` / authority-gated `unstake` in the rare case
the hot key is compromised.  In routine operation the cold key is
never online.

**This script uses only Python stdlib** - no pip deps - so it runs
on any clean Python 3.10+ environment without needing to install
anything on the air-gapped machine.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys

# 257-bit prime (Mersenne): p = 2^521 - 1.  Accepts any 32-byte secret
# as an integer < p, with 489 bits of headroom for polynomial coeffs.
# Shamir security is information-theoretic in the prime field - any
# t-1 shares leak zero information about the secret.
_P = 2**521 - 1

_SHARE_PREFIX = "MC-SHAMIR-v1"


def _split_secret(secret_int: int, threshold: int, num_shares: int) -> list[tuple[int, int]]:
    """Return [(x, f(x)), ...] with f(0) = secret_int.  x values are 1..num_shares."""
    if not (2 <= threshold <= num_shares <= 255):
        raise ValueError("require 2 <= threshold <= num_shares <= 255")
    if secret_int >= _P or secret_int < 0:
        raise ValueError("secret must be non-negative and < prime")
    # Random polynomial coefficients a_1 .. a_(t-1); a_0 = secret_int.
    coeffs = [secret_int] + [secrets.randbelow(_P) for _ in range(threshold - 1)]
    shares: list[tuple[int, int]] = []
    for x in range(1, num_shares + 1):
        y = 0
        x_pow = 1
        for c in coeffs:
            y = (y + c * x_pow) % _P
            x_pow = (x_pow * x) % _P
        shares.append((x, y))
    return shares


def _combine_shares(shares: list[tuple[int, int]]) -> int:
    """Lagrange interpolation at x=0 over GF(_P)."""
    if len({x for x, _ in shares}) != len(shares):
        raise ValueError("duplicate x values in shares")
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % _P
            den = (den * (xi - xj)) % _P
        lagrange = (num * pow(den, -1, _P)) % _P
        secret = (secret + yi * lagrange) % _P
    return secret


def _encode_share(x: int, y: int, threshold: int, num_shares: int) -> str:
    """Human-readable share with checksum."""
    body = f"{_SHARE_PREFIX}:{threshold}/{num_shares}:{x}:{y:0132x}"
    digest = hashlib.sha3_256(body.encode()).hexdigest()[:16]
    return f"{body}:{digest}"


def _decode_share(text: str) -> tuple[int, int, int, int]:
    """Return (x, y, threshold, num_shares) after checksum verify."""
    parts = text.strip().split(":")
    if len(parts) != 5 or parts[0] != _SHARE_PREFIX:
        raise ValueError("malformed share: bad prefix or field count")
    body = ":".join(parts[:-1])
    expect = hashlib.sha3_256(body.encode()).hexdigest()[:16]
    if expect != parts[-1]:
        raise ValueError("share checksum mismatch - share is corrupted or tampered")
    tn = parts[1].split("/")
    if len(tn) != 2:
        raise ValueError("malformed share: threshold/total field")
    threshold, num_shares = int(tn[0]), int(tn[1])
    x = int(parts[2])
    y = int(parts[3], 16)
    return x, y, threshold, num_shares


def generate(threshold: int, num_shares: int, out_dir: str) -> None:
    """Generate a 32-byte cold key and split into `num_shares` Shamir shares."""
    os.makedirs(out_dir, exist_ok=True)
    key_bytes = secrets.token_bytes(32)
    key_int = int.from_bytes(key_bytes, "big")

    # Derive the public key the chain will store.  Import from messagechain
    # locally - never touches the network since Entity.create is pure crypto.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    # Use a small tree for the cold key - it signs rarely (emergency only).
    from messagechain.identity.identity import Entity
    from messagechain.identity.address import encode_address
    ce = Entity.create(key_bytes, tree_height=10)  # 1024 signing keys
    print(f"  Cold key public:  {ce.public_key.hex()}")
    print(f"  Cold entity_id:   {ce.entity_id.hex()}")
    print(f"  Cold address:     {encode_address(ce.entity_id)}")
    pub_path = os.path.join(out_dir, "cold-key-public.txt")
    with open(pub_path, "w") as f:
        f.write(f"Cold key public:  {ce.public_key.hex()}\n")
        f.write(f"Cold entity_id:   {ce.entity_id.hex()}\n")
        f.write(f"Cold address:     {encode_address(ce.entity_id)}\n")
    print(f"  Wrote {pub_path}")

    shares = _split_secret(key_int, threshold, num_shares)
    for i, (x, y) in enumerate(shares, 1):
        encoded = _encode_share(x, y, threshold, num_shares)
        path = os.path.join(out_dir, f"cold-share-{i}.txt")
        with open(path, "w") as f:
            f.write(encoded + "\n")
        try:
            os.chmod(path, 0o400)
        except Exception:
            pass  # Windows or non-POSIX - best-effort
        print(f"  Wrote {path}  (keep this SECRET; any 2 of {num_shares} shares reconstruct the key)")

    # Zero the in-memory key
    key_bytes = b"\x00" * 32
    del key_int


def recover(share_files: list[str]) -> None:
    """Reconstruct the cold key from `threshold` share files; print public key."""
    shares: list[tuple[int, int]] = []
    declared_t: int | None = None
    declared_n: int | None = None
    for path in share_files:
        with open(path) as f:
            x, y, t, n = _decode_share(f.read())
        if declared_t is None:
            declared_t, declared_n = t, n
        elif (t, n) != (declared_t, declared_n):
            raise ValueError(
                f"share {path} has threshold/total {t}/{n}, expected {declared_t}/{declared_n}"
            )
        shares.append((x, y))
    assert declared_t is not None
    if len(shares) < declared_t:
        raise ValueError(
            f"need at least {declared_t} shares to recover, got {len(shares)}"
        )

    secret_int = _combine_shares(shares[:declared_t])
    key_bytes = secret_int.to_bytes(32, "big")

    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from messagechain.identity.identity import Entity
    from messagechain.identity.address import encode_address
    ce = Entity.create(key_bytes, tree_height=10)
    print(f"  Recovered public:  {ce.public_key.hex()}")
    print(f"  Recovered address: {encode_address(ce.entity_id)}")
    print()
    print("  Verify this matches your cold-key-public.txt.  If it does NOT,")
    print("  one or more shares are wrong - STOP and investigate.")

    # Zero the memory
    key_bytes = b"\x00" * 32
    del secret_int


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cold authority key generation + 2-of-3 Shamir split.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="Generate key + split into shares")
    gen.add_argument("--threshold", type=int, default=2)
    gen.add_argument("--total", type=int, default=3)
    gen.add_argument(
        "--out-dir", default="cold-key-output",
        help="Directory to write shares to (created if missing)",
    )

    rec = sub.add_parser("recover", help="Reconstruct key from shares + verify")
    rec.add_argument(
        "shares", nargs="+",
        help="Paths to share files (need >= threshold)",
    )

    args = parser.parse_args()

    # ASCII-only output so the script runs on Windows air-gapped
    # machines (cp1252 default encoding can't print Unicode box
    # characters and the whole ceremony aborts mid-generation).
    print()
    print("  ============================================================")
    print("  Cold-Key Ceremony - air-gapped, quorum-custody shares")
    print("  ============================================================")
    print()

    if args.cmd == "generate":
        generate(args.threshold, args.total, args.out_dir)
        print()
        print("  [OK] Cold key generated + split into Shamir shares.")
        print()
        print("  Next steps (do these in order, THEN wipe this machine):")
        print("  1. Copy each cold-share-N.txt to its designated holder's")
        print("     physical storage.  No digital copies on networked hosts.")
        print("  2. Run `python deploy/cold_key_ceremony.py recover ...`")
        print("     with 2 shares on a separate air-gapped machine to verify")
        print("     the reconstruction works BEFORE you destroy the originals.")
        print("  3. Commit the public key on-chain:")
        print("       python -m messagechain set-authority-key \\")
        print("           --authority-pubkey <cold_public_hex> --server ...")
        print("  4. Shred cold-share-*.txt on this machine.")
        print("  5. Wipe this machine.  It must not retain the key material.")
        return 0

    if args.cmd == "recover":
        recover(args.shares)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
