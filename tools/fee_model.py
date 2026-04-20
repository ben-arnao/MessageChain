"""Economic analysis of MessageChain fee parameters under sustained spam.

This script reads the real protocol parameters from messagechain.config and
messagechain.core.transaction.calculate_min_fee, then projects four
adversarial / high-traffic scenarios over 1 / 10 / 100 / 1000 year horizons
and reports:

  * raw ledger bloat (GB) added
  * compressed bloat (GB) added, using zlib on the exact worst-case payload
    the attacker would send
  * total fees paid by the attacker (tokens)
  * those fees as a percentage of genesis supply

All numbers come from live constants — nothing is hard-coded. When the
protocol tightens (or loosens) a fee parameter, re-running this script
immediately re-scores the attack surface.

Run:
    python tools/fee_model.py
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# Make the repo root importable regardless of where we're launched from.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from messagechain import config  # noqa: E402
from messagechain.core.compression import encode_payload  # noqa: E402
from messagechain.core.transaction import calculate_min_fee  # noqa: E402


# --- Derived constants ----------------------------------------------------

SECONDS_PER_YEAR = 365 * 24 * 3600
BLOCKS_PER_YEAR = SECONDS_PER_YEAR // config.BLOCK_TIME_TARGET  # integer

HORIZONS_YEARS = (1, 10, 100, 1000)


# --- Helpers --------------------------------------------------------------


def _high_entropy_payload(n_bytes: int) -> bytes:
    """Return a worst-case-compressibility ASCII payload of length n_bytes.

    An attacker optimizing for maximum bloat per fee unit will not send
    'aaaa...' — that compresses to ~1% and they'd pay the quadratic fee on
    a tiny stored size. Instead they send content that is near-random
    within the printable-ASCII range (32..126, width 95), which zlib at
    level 9 barely shrinks. We synthesize that deterministically.
    """
    # Lagged Fibonacci over the 95-char printable-ASCII alphabet; the
    # sequence has no short-period structure that zlib can exploit.
    alphabet_lo, alphabet_hi = 32, 126
    width = alphabet_hi - alphabet_lo + 1
    buf = bytearray(n_bytes)
    a, b = 1103515245, 12345  # classic LCG constants as seed state
    for i in range(n_bytes):
        a = (a * 1103515245 + 12345) & 0xFFFFFFFF
        b = (b * 22695477 + 1) & 0xFFFFFFFF
        buf[i] = alphabet_lo + ((a ^ b) % width)
    return bytes(buf)


def stored_size_after_compression(plaintext: bytes) -> int:
    """Return len(encoded_payload) — i.e. the *stored* byte count, which is
    what the fee formula is charged on."""
    stored, _flag = encode_payload(plaintext)
    return len(stored)


@dataclass
class Scenario:
    name: str
    msg_plaintext_bytes: int     # attacker-chosen plaintext size (before compression)
    txs_per_block: int           # txs the attacker fits per block
    effective_base_fee: int      # base_fee the attacker is paying at (MIN_FEE or saturated)


def bytes_per_block(s: Scenario) -> tuple[int, int]:
    """Return (raw_bytes_per_block, stored_bytes_per_block) for the scenario."""
    payload = _high_entropy_payload(s.msg_plaintext_bytes)
    stored = stored_size_after_compression(payload)
    return s.txs_per_block * s.msg_plaintext_bytes, s.txs_per_block * stored


def fee_per_tx(s: Scenario) -> int:
    """Protocol-enforced minimum fee an attacker must actually pay per tx."""
    payload = _high_entropy_payload(s.msg_plaintext_bytes)
    stored, _ = encode_payload(payload)
    size_floor = calculate_min_fee(stored)
    # Effective floor is max(size-based min fee, current base_fee). Under
    # attack, base_fee climbs; in the non-adversarial baseline it sits at
    # MIN_FEE. We let the caller decide which regime via effective_base_fee.
    return max(size_floor, s.effective_base_fee)


# --- Scenario definitions -------------------------------------------------

# For scenarios that hit MAX_BLOCK_MESSAGE_BYTES, each tx is the largest
# stored-bytes message the attacker can fit. Since plaintext 280 bytes of
# high-entropy content barely compresses, stored ≈ 280.
# MAX_BLOCK_MESSAGE_BYTES / MAX_MESSAGE_BYTES = 10_000 / 280 ≈ 35 txs by
# byte budget, but MAX_TXS_PER_BLOCK=20 is tighter, and
# MAX_TXS_PER_ENTITY_PER_BLOCK=3 would require ceil(20/3)=7 colluding
# entities. We assume the attacker controls ≥7 entities (cheap — identity
# creation is one-time).

def build_scenarios() -> list[Scenario]:
    max_msg = config.MAX_MESSAGE_BYTES
    # At MAX_TXS_PER_BLOCK=20 with MAX_MESSAGE_BYTES=280, per-block byte
    # budget is 20*280 = 5600 < MAX_BLOCK_MESSAGE_BYTES=10_000, so the
    # tx-count cap binds before the byte-budget cap under current params.
    effective_txs = min(
        config.MAX_TXS_PER_BLOCK,
        config.MAX_BLOCK_MESSAGE_BYTES // max_msg,
    )

    # Max base fee under sustained attack — base_fee saturates at
    # MIN_FEE * MAX_BASE_FEE_MULTIPLIER per the EIP-1559 adjustment.
    saturated_base_fee = config.MIN_FEE * config.MAX_BASE_FEE_MULTIPLIER

    return [
        Scenario(
            name="1) Full-size spam at base fee (MIN_FEE)",
            msg_plaintext_bytes=max_msg,
            txs_per_block=effective_txs,
            effective_base_fee=config.MIN_FEE,
        ),
        Scenario(
            name="2) Small-tx spam, MIN_FEE, hit MAX_TXS_PER_BLOCK",
            msg_plaintext_bytes=1,  # 1 byte plaintext — minimum payload
            txs_per_block=config.MAX_TXS_PER_BLOCK,
            effective_base_fee=config.MIN_FEE,
        ),
        Scenario(
            name="3) Sustained TARGET_BLOCK_SIZE (normal heavy state)",
            msg_plaintext_bytes=max_msg,
            txs_per_block=config.TARGET_BLOCK_SIZE,
            effective_base_fee=config.MIN_FEE,
        ),
        Scenario(
            name="4) Worst case: base_fee saturated at MAX_BASE_FEE_MULTIPLIER",
            msg_plaintext_bytes=max_msg,
            txs_per_block=effective_txs,
            effective_base_fee=saturated_base_fee,
        ),
    ]


# --- Report ---------------------------------------------------------------


def format_bytes(n: float) -> str:
    if n >= 1e12:
        return f"{n / 1e12:.2f} TB"
    if n >= 1e9:
        return f"{n / 1e9:.2f} GB"
    if n >= 1e6:
        return f"{n / 1e6:.2f} MB"
    if n >= 1e3:
        return f"{n / 1e3:.2f} KB"
    return f"{n:.0f} B"


def format_tokens(n: float) -> str:
    if n >= 1e12:
        return f"{n / 1e12:.2f}T"
    if n >= 1e9:
        return f"{n / 1e9:.2f}B"
    if n >= 1e6:
        return f"{n / 1e6:.2f}M"
    if n >= 1e3:
        return f"{n / 1e3:.2f}K"
    return f"{n:.0f}"


def print_header_block() -> None:
    print("=" * 96)
    print("MessageChain fee-model — adversarial spam projection")
    print("=" * 96)
    print("Protocol parameters in use:")
    print(f"  MIN_FEE                      = {config.MIN_FEE}")
    print(f"  FEE_PER_BYTE                 = {config.FEE_PER_BYTE}")
    print(f"  FEE_QUADRATIC_COEFF          = {config.FEE_QUADRATIC_COEFF}  "
          f"(applied as bytes^2 * coeff / 1000)")
    print(f"  MAX_MESSAGE_BYTES            = {config.MAX_MESSAGE_BYTES}")
    print(f"  MAX_BLOCK_MESSAGE_BYTES      = {config.MAX_BLOCK_MESSAGE_BYTES}")
    print(f"  MAX_TXS_PER_BLOCK            = {config.MAX_TXS_PER_BLOCK}")
    print(f"  MAX_TXS_PER_ENTITY_PER_BLOCK = {config.MAX_TXS_PER_ENTITY_PER_BLOCK}")
    print(f"  TARGET_BLOCK_SIZE            = {config.TARGET_BLOCK_SIZE}")
    print(f"  BLOCK_TIME_TARGET            = {config.BLOCK_TIME_TARGET} s "
          f"({BLOCKS_PER_YEAR:,} blocks/year)")
    print(f"  BASE_FEE_MAX_CHANGE_DENOM    = {config.BASE_FEE_MAX_CHANGE_DENOMINATOR} "
          f"(max {100 / config.BASE_FEE_MAX_CHANGE_DENOMINATOR:.1f}% change/block)")
    print(f"  MAX_BASE_FEE_MULTIPLIER      = {config.MAX_BASE_FEE_MULTIPLIER:,}  "
          f"(saturates at base_fee={config.MIN_FEE * config.MAX_BASE_FEE_MULTIPLIER:,})")
    print(f"  GENESIS_SUPPLY               = {config.GENESIS_SUPPLY:,} tokens")
    print()

    # Quick sanity check: show per-tx fee at a few sizes.
    print("Per-tx min-fee ladder (size -> calculate_min_fee, tokens):")
    for size in (1, 32, 128, 280):
        payload = _high_entropy_payload(size)
        stored = stored_size_after_compression(payload)
        fee = calculate_min_fee(encode_payload(payload)[0])
        print(f"  plaintext={size:>4}B  stored={stored:>4}B  "
              f"min_fee={fee:>8,} tokens  "
              f"(= {config.MIN_FEE} + {stored}*{config.FEE_PER_BYTE} + "
              f"{stored}^2*{config.FEE_QUADRATIC_COEFF}//1000)")
    print()


def run_scenario(s: Scenario) -> None:
    print("-" * 96)
    print(s.name)
    print(f"  per-tx plaintext:       {s.msg_plaintext_bytes} B")
    payload = _high_entropy_payload(s.msg_plaintext_bytes)
    stored = stored_size_after_compression(payload)
    compression_ratio = (s.msg_plaintext_bytes / stored) if stored else 1.0
    print(f"  per-tx stored (zlib):   {stored} B  (compression x{compression_ratio:.2f})")
    print(f"  txs/block:              {s.txs_per_block}")
    print(f"  effective base_fee:     {s.effective_base_fee:,}")
    per_tx_fee = fee_per_tx(s)
    print(f"  per-tx fee paid:        {per_tx_fee:,} tokens "
          f"(= max(calculate_min_fee, base_fee))")

    raw_per_block, stored_per_block = bytes_per_block(s)
    fee_per_block = per_tx_fee * s.txs_per_block
    print(f"  raw bytes/block:        {raw_per_block:,}")
    print(f"  stored bytes/block:     {stored_per_block:,}")
    print(f"  fee/block (attacker):   {fee_per_block:,} tokens")
    print()

    # Horizon table
    hdr = (f"    {'horizon':<10} | {'raw bloat':>12} | {'stored bloat':>12} | "
           f"{'total fee':>14} | {'% of supply':>12}")
    print(hdr)
    print(f"    {'-' * 10}-+-{'-' * 12}-+-{'-' * 12}-+-{'-' * 14}-+-{'-' * 12}")
    for years in HORIZONS_YEARS:
        blocks = BLOCKS_PER_YEAR * years
        raw_total = raw_per_block * blocks
        stored_total = stored_per_block * blocks
        fee_total = fee_per_block * blocks
        pct_supply = 100.0 * fee_total / config.GENESIS_SUPPLY
        print(f"    {years:>4}y      | {format_bytes(raw_total):>12} | "
              f"{format_bytes(stored_total):>12} | "
              f"{format_tokens(fee_total):>14} | {pct_supply:>10.2f}%")
    print()


def main() -> None:
    print_header_block()
    for s in build_scenarios():
        run_scenario(s)

    print("=" * 96)
    print("Interpretation notes:")
    print("  * Fees are burned (base_fee portion) and paid to proposer (tip). Either way")
    print("    the attacker must *have* the tokens. Compare 'total fee' to GENESIS_SUPPLY")
    print("    for a coarse 'can any realistic actor afford this' sanity check.")
    print("  * 'stored bloat' is the figure that actually lands on every archive node's")
    print("    disk forever. 'raw bloat' is what the attacker had to type.")
    print("  * Scenario 4 shows the ceiling: even if base_fee rides its cap forever, the")
    print("    attacker still has to pay MAX_BASE_FEE_MULTIPLIER * MIN_FEE per tx.")
    print("=" * 96)


if __name__ == "__main__":
    main()
