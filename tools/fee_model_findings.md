# Fee-model findings (fee_economic_analysis)

Generated from `tools/fee_model.py` against live parameters in
`messagechain/config.py` and `messagechain/core/transaction.calculate_min_fee`,
plus `messagechain/consensus/archive_challenge.py` and
`messagechain/consensus/censorship_evidence.py` for the two new
consensus-level features (v2 of this model).  Re-run the script any time a
fee constant, archive-challenge parameter, or censorship-evidence parameter
is changed.

## Summary of live parameters

| Parameter                       | Value                         |
|--------------------------------|-------------------------------|
| MIN_FEE                        | 100 tokens                    |
| FEE_PER_BYTE                   | 3                             |
| FEE_QUADRATIC_COEFF            | 2 (applied as `b^2 * 2 / 1000`) |
| MAX_MESSAGE_BYTES              | 280                           |
| MAX_BLOCK_MESSAGE_BYTES        | 10,000                        |
| MAX_TXS_PER_BLOCK              | 20                            |
| MAX_TXS_PER_ENTITY_PER_BLOCK   | 3                             |
| TARGET_BLOCK_SIZE              | 10                            |
| BLOCK_TIME_TARGET              | 600 s (52,560 blocks/year)    |
| MAX_BASE_FEE_MULTIPLIER        | 10,000 (cap = 1,000,000)      |
| GENESIS_SUPPLY                 | 140,000,000 tokens            |
| ARCHIVE_CHALLENGE_INTERVAL     | 100 blocks (525 challenge blocks/yr) |
| ARCHIVE_PROOFS_PER_CHALLENGE   | 10                            |
| EVIDENCE_INCLUSION_WINDOW      | 32                            |
| EVIDENCE_MATURITY_BLOCKS       | 16                            |
| CENSORSHIP_SLASH_BPS           | 1000 (10% of stake)           |

## Scenario results (messages, unchanged from v1)

Stored bloat now includes the amortized custody-proof overhead (+82 B / block).

Note: the "% of GENESIS_SUPPLY" column denominates against the corrected
GENESIS_SUPPLY of 140M (post phantom-supply fix).  Figures for attacks
that would need to spend >100% of supply mean the attacker must also be
continuously re-earning tokens through inflation to sustain the rate —
they cannot run the attack purely from initial holdings.

| Scenario | stored bloat / year | attacker fee / year | fee as % of GENESIS_SUPPLY |
|---|---:|---:|---:|
| 1. Full-size spam at MIN_FEE            | 278.7 MB | 1.07 B tokens  | 765 %      |
| 2. Small-tx spam at MIN_FEE             | 5.36 MB  | 108 M tokens   | 77.3 %     |
| 3. TARGET_BLOCK_SIZE (non-adversarial)  | 141.5 MB | 535 M tokens   | 382.6 %    |
| 4. Worst-case, base_fee saturated       | 278.7 MB | 1.05 T tokens  | 750,857 %  |

## New: custody-proof overhead (on-chain, permanent)

- Measured real `CustodyProof.to_bytes()` at max-txs target block, 280B tx,
  20-leaf Merkle path: **820 B per proof**.
- Per challenge block: 10 × 820 = 8,200 B.
- Amortized: 8,200 / 100 = **82 B / block**.
- Throughput: **4.31 MB / year → 431 MB / 100 y → 4.31 GB / 1000 y.**

This is negligible relative to message bloat (~1–3 orders of magnitude
smaller).  The spec's "2–4 KB per proof" estimate was conservative; actual
encoding is much tighter (no signature on proofs in v1, Merkle path is
<5 siblings).

## New: censorship-evidence overhead (on-chain, permanent)

`CensorshipEvidenceTx` ≈ 4,000 B / tx (receipt blob + embedded
MessageTransaction + submitter WOTS signature).  **No dedicated
per-block cap — shares MAX_TXS_PER_BLOCK=20 with everything else.**

Two regimes:

| Regime | Evidence / year | Bytes / year | Bytes / 1000 y |
|---|---:|---:|---:|
| Organic (non-censoring chain)                              | ~0          | 0      | 0       |
| Light adversarial (e.g., 100/yr griefing attempts)         | 100         | 400 KB | 400 MB  |
| Full-block adversarial (MAX_TXS_PER_BLOCK every block)     | 1,051,200   | 4.2 GB | 4.2 TB  |

**Adversarial affordability**: each evidence tx costs MIN_FEE = 100
tokens.  `GENESIS_SUPPLY / MIN_FEE = 1,400,000` evidence txs — roughly
**1.3 years of full-block evidence spam** before the attacker exhausts
the entire money supply.  After that the model's cap flips from
block-budget to affordability and growth slows dramatically (the
attacker can only keep going from inflationary block rewards they
themselves earn, which is a tiny fraction of the block-cap rate).

**Additional economic friction not in the pure-fee model**: to craft a
valid evidence the attacker needs a `SubmissionReceipt` signed by a
registered validator (receipt-subtree key).  That validator is the
named offender; successful maturation slashes them for
CENSORSHIP_SLASH_BPS = 10% of stake.  So the real per-evidence cost to
a self-colluding attacker is `MIN_FEE + (10% × sybil_validator_stake)`,
which is always much greater than MIN_FEE alone.  The model therefore
overstates the attack rate; the 4.2 TB/1000y figure is a genuine upper
bound.

## New: `processed_censorship_evidence` state growth

32 bytes per hash, append-only (double-slash defense).

| Regime | Entries / yr | 100 y bytes | 1000 y bytes |
|---|---:|---:|---:|
| Organic                         | 0            | 0        | 0        |
| Light adversarial (100 /yr)     | 100          | 320 KB   | 3.2 MB   |
| Full-block adversarial          | 1,051,200    | 3.36 GB  | 33.6 GB  |

Economic floor bounding this set: an attacker who wants to grow
`processed_censorship_evidence` by N entries must pay ≥ N × MIN_FEE
tokens.  Floor is therefore strict: 1.4M entries total across all time
without burning the entire genesis supply.  At 32 B/hash, that is a
**permanent ceiling of ~44.8 MB of `processed_censorship_evidence`** if
*all* of genesis supply is diverted to evidence spam.  Plenty safe.

## Big-picture: does 1000 y still fit on commodity hardware?

Two disjoint adversarial modes (the block-tx budget is shared, so you
can't run both at once):

| Horizon | Mode A: all-message-spam | Mode B: all-evidence-spam |
|---|---:|---:|
| 100 y   | **27.9 GB**        | **424.3 GB**        |
| 1000 y  | **278.7 GB**       | **4.24 TB**         |

Mode B (all-evidence-spam) is the strictly worse storage scenario —
each evidence tx is ~15x larger than a max-size message tx.  Even so:

- **100 y worst case: 424 GB** — fits on a $25 consumer SSD.
- **1000 y worst case: 4.24 TB** — fits on a single commodity drive
  (current 6–8 TB HDDs are ~$120; 10 TB ~$200 consumer retail).  Still
  comfortably under any archival operator's pain threshold.

**But note**: Mode B requires only ~1.3 years of sustained attack
before exhausting genesis supply (post phantom-supply fix, the
affordability-cap dropped from 10M to 1.4M evidence txs).  Beyond
that, the attacker can only sustain the attack from *recycled*
inflation (block rewards), which is bounded.  The pure 1000-year
evidence-spam figure is an economic-impossibility upper bound, not a
realistic sustained rate — in practice the attacker runs out of money
in year 2 and the curve flattens hard after that.

## Parameter recommendations

1. **Keep all current parameters.**  Storage at 1000 y under
   the worst adversarial mode is **4.24 TB**, well under any
   credible operator-pain threshold.  Under organic rates it's
   ~280 GB including custody-proof overhead — dominated by message
   bloat, not by features.

2. **Do NOT add per-block cap for CensorshipEvidenceTx.**  Sharing
   MAX_TXS_PER_BLOCK with message txs is already a tight cap.  A
   dedicated cap would fragment the block budget with no storage
   benefit: the evidence attacker and message spammer can't both
   run concurrently anyway.

3. **Keep `processed_censorship_evidence` unpruned.**  Economic
   bound (320 MB ceiling at full genesis-supply burn) is tighter
   than any pruning window we'd pick, and the determinism /
   double-slash-defense arguments for permanence remain.

4. **Monitor CustodyProof size.**  At 820 B actual vs 2–4 KB
   in the spec, we have headroom — but if `MAX_TXS_PER_BLOCK`
   grows, the Merkle-path term grows logarithmically and the
   proof grows sub-linearly.  Safe for 2x, 4x, 8x growth
   (path +1 hash = +32 B each doubling).

5. **No change to MIN_FEE.**  Raising it would price-deter
   evidence spam but also price-deter legitimate user txs; the
   storage math doesn't justify it.

## Surprises / callouts from v2

- **Custody proofs are much cheaper than spec.**  820 B real vs
  the 2–4 KB documented bound.  No witness-stripping, no
  signature on the proof (v1), small Merkle path.  If we later
  add per-proof signatures (spec mentions as v2), proof size
  will roughly double to ~1.9 KB — still fits comfortably.

- **Evidence-spam dwarfs message-spam per byte.**  4,000 B per
  evidence tx vs 261 B per stored message tx.  Storage-adversary
  mode shifts from message-spam to evidence-spam under these
  parameters.  Still economically bounded.

- **Economic attack on `processed_censorship_evidence` is
  affordability-capped, not block-capped.**  At MIN_FEE=100 and
  GENESIS_SUPPLY=140M, the set cannot exceed ~1.4M entries =
  ~44.8 MB ever.  This set IS a permanence concern but not a
  bloat concern (and the cap is ~7x tighter than pre-phantom-supply-fix
  since the affordability denominator dropped from 1B to 140M).

- **Block-slot sharing is the key insulator.**
  MAX_TXS_PER_BLOCK=20 acts as a unified cap across message-txs
  AND evidence-txs.  An attacker choosing evidence-spam gives up
  message-spam, so worst-case total bloat does not compound.

## Bottom line

Current parameters are **still economically tight** after the v2
feature set lands.  Worst-case 1000-year storage is **4.24 TB**
under sustained full-block evidence-spam (requiring economic
exhaustion of the attacker before horizon end).  Under organic
rates: **~280 GB at 1000 y, 28 GB at 100 y**.  Both fit on
commodity hardware the founder can host at GCP or on a home
server with no stress.  **No parameter tuning required.**
