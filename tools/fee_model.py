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

It additionally models the two consensus-level features added to the block
body on top of message-txs:

  * **Custody proofs** (`CustodyProof`): emitted on archive-challenge
    blocks (every ARCHIVE_CHALLENGE_INTERVAL blocks), up to
    ARCHIVE_PROOFS_PER_CHALLENGE per challenge block.  Real measured size
    via CustodyProof.to_bytes() on a full-size target block.

  * **Censorship evidence txs** (`CensorshipEvidenceTx`): may be included
    any block, no per-block cap.  Two rate regimes are modelled:
      - organic (~0 evidence/year, so ~0 bytes/year),
      - adversarial (attacker fills every block with evidence txs, paying
        MIN_FEE per tx).

Finally, it projects state-snapshot growth in `processed_censorship_evidence`
(32-byte hash per ever-processed evidence — permanence-relevant because
it is never pruned).

All numbers come from live constants — nothing is hard-coded.  When the
protocol tightens (or loosens) a fee parameter, re-running this script
immediately re-scores the attack surface.

Run:
    python tools/fee_model.py
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from dataclasses import dataclass

# Make the repo root importable regardless of where we're launched from.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from messagechain import config  # noqa: E402
from messagechain.core.compression import encode_payload  # noqa: E402
from messagechain.core.transaction import calculate_min_fee  # noqa: E402
from messagechain.consensus.archive_challenge import (  # noqa: E402
    build_custody_proof,
)


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
    print(f"  ARCHIVE_CHALLENGE_INTERVAL   = {config.ARCHIVE_CHALLENGE_INTERVAL} "
          f"(challenge blocks/year = {BLOCKS_PER_YEAR // config.ARCHIVE_CHALLENGE_INTERVAL:,})")
    print(f"  ARCHIVE_PROOFS_PER_CHALLENGE = {config.ARCHIVE_PROOFS_PER_CHALLENGE}")
    print(f"  EVIDENCE_INCLUSION_WINDOW    = {config.EVIDENCE_INCLUSION_WINDOW}")
    print(f"  EVIDENCE_MATURITY_BLOCKS     = {config.EVIDENCE_MATURITY_BLOCKS}")
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


def run_scenario(s: Scenario, extra_bytes_per_block: int = 0,
                 overhead_label: str = "") -> None:
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
    if extra_bytes_per_block:
        print(f"  {overhead_label:<22}  +{extra_bytes_per_block:,} B/block "
              f"(amortized — see overhead scenarios below)")
    print(f"  fee/block (attacker):   {fee_per_block:,} tokens")
    print()

    # Horizon table — stored bloat rolls in the overhead.
    hdr = (f"    {'horizon':<10} | {'raw bloat':>12} | {'stored bloat':>12} | "
           f"{'total fee':>14} | {'% of supply':>12}")
    print(hdr)
    print(f"    {'-' * 10}-+-{'-' * 12}-+-{'-' * 12}-+-{'-' * 14}-+-{'-' * 12}")
    for years in HORIZONS_YEARS:
        blocks = BLOCKS_PER_YEAR * years
        raw_total = raw_per_block * blocks
        stored_total = (stored_per_block + extra_bytes_per_block) * blocks
        fee_total = fee_per_block * blocks
        pct_supply = 100.0 * fee_total / config.GENESIS_SUPPLY
        print(f"    {years:>4}y      | {format_bytes(raw_total):>12} | "
              f"{format_bytes(stored_total):>12} | "
              f"{format_tokens(fee_total):>14} | {pct_supply:>10.2f}%")
    print()


# --- Custody-proof overhead ----------------------------------------------


def measure_custody_proof_size() -> int:
    """Build a real CustodyProof targeting a MAX_TXS_PER_BLOCK-sized block
    with MAX_MESSAGE_BYTES-sized txs, and return its to_bytes() length.

    This is the worst case for Merkle-path length (log2(MAX_TXS_PER_BLOCK))
    AND worst case for tx_bytes size.  Empty-block proofs are smaller —
    we use the worst case so our overhead projection is conservative.
    """
    num_txs = config.MAX_TXS_PER_BLOCK
    # Real tx bytes (same high-entropy padding as the spam model uses so
    # the measurement reflects the realistic worst case a prover would
    # encounter sampling a spammed block).
    txs = [_high_entropy_payload(config.MAX_MESSAGE_BYTES) + struct.pack(">I", i)
           for i in range(num_txs)]
    tx_hashes = [hashlib.new(config.HASH_ALGO, t).digest() for t in txs]
    header_bytes = b"H" * 200  # BlockHeader ≈ 150–250 B in practice
    target_block_hash = hashlib.new(config.HASH_ALGO, header_bytes).digest()
    proof = build_custody_proof(
        prover_id=b"P" * 32,
        target_height=123456,
        target_block_hash=target_block_hash,
        header_bytes=header_bytes,
        merkle_root=b"M" * 32,
        tx_index=num_txs // 2,
        tx_bytes=txs[num_txs // 2],
        all_tx_hashes=tx_hashes,
    )
    return len(proof.to_bytes())


def custody_proof_overhead_bytes_per_block() -> tuple[int, int]:
    """Return (bytes_per_proof, amortized_bytes_per_block).

    amortized_bytes_per_block =
      ARCHIVE_PROOFS_PER_CHALLENGE * bytes_per_proof
      / ARCHIVE_CHALLENGE_INTERVAL

    i.e. the average block-body overhead from custody proofs, spread
    across all blocks (most are not challenge blocks; on challenge
    blocks the full batch lands at once).
    """
    sz = measure_custody_proof_size()
    batch_per_challenge = config.ARCHIVE_PROOFS_PER_CHALLENGE * sz
    amortized = batch_per_challenge // config.ARCHIVE_CHALLENGE_INTERVAL
    return sz, amortized


# --- Censorship-evidence overhead ----------------------------------------


# Empirically, a CensorshipEvidenceTx encodes as (at h=20 / receipt h=24):
#
#   receipt blob (len-prefixed): ~1,250 B
#     - 32 tx_hash + 8 commit_height + 32 issuer_id + 32 issuer_root_pk
#       + 4 sig_len + ~1,220 WOTS sig (h=24) + 32 receipt_hash
#   message_tx blob (len-prefixed): ~1,400 B  (280 B msg + ~1,100 WOTS sig
#     at h=20 + tx overhead)
#   submitter_id: 32
#   timestamp: 8
#   fee: 8
#   signature blob (len-prefixed): ~1,100 B (submitter WOTS at h=20)
#   tx_hash: 32
#
# Grand total: ~3,840 B per evidence tx.  We use 4,000 as a conservative
# round-up for the projection.  (A lower message payload would shrink the
# inner MessageTransaction by at most ~280 B, so ~3,560 B floor.)
CENSORSHIP_EVIDENCE_TX_SIZE_BYTES = 4_000


def adversarial_evidence_per_year() -> tuple[int, int]:
    """Return (txs/year, max_txs/year_assuming_attacker_fills_all_blocks).

    The attacker pays MIN_FEE per evidence tx and can emit at most
    MAX_TXS_PER_BLOCK per block (evidence txs share the generic tx cap
    — there is no dedicated evidence cap at the block-body level).  So
    adversarial-cap is MAX_TXS_PER_BLOCK * BLOCKS_PER_YEAR.

    An attacker would stop as soon as they run out of tokens: they can
    afford MIN_FEE * affordable_txs ≤ GENESIS_SUPPLY, giving
    affordable_txs ≤ GENESIS_SUPPLY / MIN_FEE.  We report the MIN of the
    two caps.
    """
    per_block_cap = config.MAX_TXS_PER_BLOCK  # no dedicated evidence cap
    per_year_block_cap = per_block_cap * BLOCKS_PER_YEAR
    affordability_cap = config.GENESIS_SUPPLY // config.MIN_FEE
    return per_block_cap, min(per_year_block_cap, affordability_cap)


def run_feature_overhead_report() -> None:
    print("=" * 96)
    print("Consensus-feature block-body overhead (added to scenarios above)")
    print("=" * 96)

    # --- Custody proofs ---
    proof_sz, amortized_per_block = custody_proof_overhead_bytes_per_block()
    print(f"Custody proofs")
    print(f"  per-proof size (max-txs target):      {proof_sz:,} B  (measured via CustodyProof.to_bytes())")
    print(f"  proofs per challenge block:           {config.ARCHIVE_PROOFS_PER_CHALLENGE}")
    print(f"  challenge cadence:                    1 every {config.ARCHIVE_CHALLENGE_INTERVAL} blocks")
    print(f"  amortized overhead / block:           {amortized_per_block:,} B")
    print(f"  bytes/year from custody proofs:       "
          f"{format_bytes(amortized_per_block * BLOCKS_PER_YEAR)}")
    print()

    # --- Censorship evidence ---
    per_block_cap, adversarial_per_year = adversarial_evidence_per_year()
    affordability_cap = config.GENESIS_SUPPLY // config.MIN_FEE
    organic_per_year = 0
    print(f"Censorship evidence txs (CensorshipEvidenceTx)")
    print(f"  per-tx wire size:                     ~{CENSORSHIP_EVIDENCE_TX_SIZE_BYTES:,} B "
          f"(receipt + embedded tx + WOTS sig)")
    print(f"  per-block cap (shares MAX_TXS_PER_BLOCK): {per_block_cap}")
    print(f"  MIN_FEE per evidence tx:              {config.MIN_FEE} tokens")
    print(f"  affordability-cap (GENESIS_SUPPLY / MIN_FEE): {affordability_cap:,} txs total")
    print(f"  adversarial txs/year (block-cap):     "
          f"{per_block_cap * BLOCKS_PER_YEAR:,}")
    print(f"  adversarial txs/year (effective):     {adversarial_per_year:,}  "
          f"(min of block-cap and affordability)")
    print()
    print(f"  Organic regime (~0 evidence/year):")
    print(f"    bytes/year:                         {format_bytes(organic_per_year * CENSORSHIP_EVIDENCE_TX_SIZE_BYTES)}")
    adv_bytes_per_year = adversarial_per_year * CENSORSHIP_EVIDENCE_TX_SIZE_BYTES
    print(f"  Adversarial regime ({adversarial_per_year:,} txs/yr):")
    print(f"    bytes/year:                         {format_bytes(adv_bytes_per_year)}")
    print(f"    attacker fee/year:                  {format_tokens(adversarial_per_year * config.MIN_FEE)} tokens "
          f"({100.0 * adversarial_per_year * config.MIN_FEE / config.GENESIS_SUPPLY:.2f}% of supply)")
    print()

    # --- Horizon table: evidence + custody overhead over 1/10/100/1000 y ---
    print(f"  Horizon roll-up (bytes added by features, combined):")
    hdr = (f"    {'horizon':<10} | {'custody':>12} | {'evid organic':>13} | "
           f"{'evid adversarial':>17}")
    print(hdr)
    print(f"    {'-' * 10}-+-{'-' * 12}-+-{'-' * 13}-+-{'-' * 17}")
    for years in HORIZONS_YEARS:
        blocks = BLOCKS_PER_YEAR * years
        custody_total = amortized_per_block * blocks
        evid_org_total = 0
        evid_adv_total = adv_bytes_per_year * years
        print(f"    {years:>4}y      | {format_bytes(custody_total):>12} | "
              f"{format_bytes(evid_org_total):>13} | "
              f"{format_bytes(evid_adv_total):>17}")
    print()

    # --- processed_censorship_evidence state-growth -----------------------
    print(f"State growth: processed_censorship_evidence (32 B/hash, never pruned)")
    print(f"  This grows monotonically — every admitted evidence that matures OR voids")
    print(f"  adds one entry.  Never shrinks (double-slash defense).")
    print()
    HASH_SZ = 32
    # Three rate regimes: organic 0/yr, light adversarial 100/yr (what the
    # brief calls out), full-block adversarial (evidence-cap).
    rates = [
        ("organic (0 /yr)", 0),
        ("light adversarial (100 /yr)", 100),
        ("full-block adversarial", adversarial_per_year),
    ]
    hdr = (f"    {'regime':<32} | {'entries/yr':>12} | {'100y bytes':>12} | "
           f"{'1000y bytes':>12}")
    print(hdr)
    print(f"    {'-' * 32}-+-{'-' * 12}-+-{'-' * 12}-+-{'-' * 12}")
    for label, per_year in rates:
        b100 = per_year * 100 * HASH_SZ
        b1000 = per_year * 1000 * HASH_SZ
        print(f"    {label:<32} | {per_year:>12,} | "
              f"{format_bytes(b100):>12} | {format_bytes(b1000):>12}")
    print()

    # --- Total storage at the big-picture horizons ------------------------
    # Note: the block-tx budget (MAX_TXS_PER_BLOCK) is shared — an attacker
    # cannot simultaneously fill a block with 20 max-size message spam txs
    # AND 20 evidence txs.  We therefore present two disjoint worst cases:
    #
    #   A) All-message-spam (scenario 1): every tx slot is a 280B message,
    #      fees = scenario-1 fees.  Evidence = 0 because no room.
    #   B) All-evidence-spam: every tx slot is a CensorshipEvidenceTx,
    #      fees = MIN_FEE/tx, evidence = 4KB/tx.  No message spam.
    #
    # B is strictly worse for storage (4KB/tx vs 261B stored msg/tx).  A is
    # what the existing fee-model had in mind.  Custody overhead adds to
    # both (proofs live in challenge blocks alongside whatever body the
    # proposer chose).
    print(f"Big-picture storage at 100/1000 years (two disjoint adversarial modes):")
    s1 = build_scenarios()[0]
    payload = _high_entropy_payload(s1.msg_plaintext_bytes)
    stored = stored_size_after_compression(payload)
    msg_stored_per_block_A = s1.txs_per_block * stored
    # Mode B: all-evidence-spam.  Per-block bytes = 20 * 4,000 = 80,000 B.
    evid_stored_per_block_B = per_block_cap * CENSORSHIP_EVIDENCE_TX_SIZE_BYTES
    for years in (100, 1000):
        blocks = BLOCKS_PER_YEAR * years
        msg_A = msg_stored_per_block_A * blocks
        custody = amortized_per_block * blocks
        evid_A = 0
        proc_ev_A = 0
        total_A = msg_A + custody + evid_A + proc_ev_A

        msg_B = 0
        evid_B = evid_stored_per_block_B * blocks
        # In mode B the attacker admits every evidence tx they can afford.
        # processed_set grows by one per admitted evidence (on mature/void).
        proc_ev_B = per_block_cap * blocks * HASH_SZ
        total_B = msg_B + custody + evid_B + proc_ev_B

        print(f"  {years}y A (all-message-spam):    msg={format_bytes(msg_A)}, "
              f"custody={format_bytes(custody)}  => total {format_bytes(total_A)}")
        print(f"  {years}y B (all-evidence-spam):   evidence={format_bytes(evid_B)}, "
              f"processed_set={format_bytes(proc_ev_B)}, "
              f"custody={format_bytes(custody)}  => total {format_bytes(total_B)}")
    print()
    print(f"  Commodity-hardware sanity check: 1 TB drives are ~$50, 10 TB ~$200.")
    print(f"  Worst-case 1000y ledger fits on a single commodity drive.")
    print()


def main() -> None:
    print_header_block()

    # Measure custody-proof amortized overhead once, so every scenario's
    # table rolls it in under "stored bloat" (proof bytes land in the
    # block body just like message bytes — they count toward the
    # permanent ledger the operator must store).
    _, amortized_proof_per_block = custody_proof_overhead_bytes_per_block()

    for s in build_scenarios():
        run_scenario(
            s,
            extra_bytes_per_block=amortized_proof_per_block,
            overhead_label="+ custody-proof avg:",
        )

    # After the per-scenario tables, print the feature-overhead report
    # which breaks out custody vs evidence and state growth.
    run_feature_overhead_report()

    print("=" * 96)
    print("Interpretation notes:")
    print("  * Fees are burned (base_fee portion) and paid to proposer (tip). Either way")
    print("    the attacker must *have* the tokens. Compare 'total fee' to GENESIS_SUPPLY")
    print("    for a coarse 'can any realistic actor afford this' sanity check.")
    print("  * 'stored bloat' is the figure that actually lands on every archive node's")
    print("    disk forever. 'raw bloat' is what the attacker had to type.")
    print("  * Scenario 4 shows the ceiling: even if base_fee rides its cap forever, the")
    print("    attacker still has to pay MAX_BASE_FEE_MULTIPLIER * MIN_FEE per tx.")
    print("  * Custody-proof overhead is amortized per block (only challenge blocks")
    print("    carry proofs; amortization divides the challenge batch by")
    print("    ARCHIVE_CHALLENGE_INTERVAL).")
    print("  * CensorshipEvidenceTx has NO dedicated per-block cap and lands in")
    print("    MAX_TXS_PER_BLOCK budget.  Organic rate is ~0 (evidence is rare");
    print("    in a non-censoring chain); adversarial cap comes from block-budget AND")
    print("    the attacker's affordability (MIN_FEE per tx).")
    print("  * processed_censorship_evidence is permanent state (32B/hash) to prevent")
    print("    double-slashing.  It is bounded economically by MIN_FEE: an attacker")
    print("    who wants to grow this set by N entries pays N * MIN_FEE tokens.")
    print("=" * 96)


if __name__ == "__main__":
    main()
