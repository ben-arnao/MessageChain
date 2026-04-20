# Fee-model findings (fee_economic_analysis)

Generated from `tools/fee_model.py` against live parameters in
`messagechain/config.py` and `messagechain/core/transaction.calculate_min_fee`.
Re-run the script any time a fee constant is changed to re-score.

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
| GENESIS_SUPPLY                 | 1,000,000,000 tokens          |

Under the current values, the byte-budget cap `MAX_BLOCK_MESSAGE_BYTES=10,000`
is slack: the tx-count cap `MAX_TXS_PER_BLOCK=20` binds first
(20 * 280 = 5,600 < 10,000). The MESSAGE_BYTES budget is therefore unreachable
via message-txs and is effectively reserved headroom for other tx types.

## Scenario results

| Scenario | stored bloat / year | attacker fee / year | fee as % of GENESIS_SUPPLY |
|---|---:|---:|---:|
| 1. Full-size spam at MIN_FEE            | 274 MB | 1.07 B tokens  | 107 %      |
| 2. Small-tx spam at MIN_FEE             | 1.05 MB | 108 M tokens  | 10.8 %     |
| 3. TARGET_BLOCK_SIZE (non-adversarial)  | 137 MB | 535 M tokens  | 53.6 %     |
| 4. Worst-case, base_fee saturated       | 274 MB | 1.05 T tokens | 105,120 %  |

Century scale (x100): scenario 1 produces ~27 GB of stored bloat. Millennium
scale (x1000): ~274 GB. These are modest compared to modern disk and are
small enough to not push away archival nodes over the 100-1000 year horizon.

## Is MIN_FEE / quadratic coefficient tight enough?

**Short answer: yes, raise nothing.** The quadratic term plus the 280-byte
message cap already makes a full-size message cost 1,019 tokens (10.2x
MIN_FEE). At that rate, a 24/7 attacker filling every block with max-size
messages spends **107 % of the entire genesis supply in one year** just to
add 274 MB of bloat. No realistic adversary sustains that.

The weaker spot is scenario 2 (small-tx spam): it costs only 10.8 %/yr of
supply but produces only ~1 MB/yr, so the storage externality is trivially
small. Even at the 1000-year horizon it's ~1 GB, less than one modern ISO.

### Specific recommendations

1. **Keep MIN_FEE at 100 and FEE_QUADRATIC_COEFF at 2.** The compound cost
   of 1,019 tokens per max-size tx already exceeds 1000x the small-tx fee
   (103 tokens), meaning the quadratic term is doing its job of pricing
   bloat-heavy messages much higher than conciseness-rewarded ones.

2. **Consider lowering MAX_BLOCK_MESSAGE_BYTES from 10,000 to 5,600**
   (= `MAX_TXS_PER_BLOCK * MAX_MESSAGE_BYTES`), or deleting the constant
   entirely. As shipped, it is unreachable for message-txs (the tx-count
   cap binds first), so it provides no real protection and is dead code
   from the attacker's perspective. Tightening it aligns code with
   reality; deleting it if no other tx type uses it reduces surprise.
   This is a hygiene fix, not a security fix.

3. **No raise to MIN_FEE.** Raising MIN_FEE would make small txs more
   expensive without meaningfully improving the bloat ceiling — the
   bloat ceiling is already set by the quadratic, not by MIN_FEE.
   Doubling MIN_FEE to 200 only lifts scenario 1 from 107 % to ~117 %
   of supply per year (fee_per_tx = 1,119). Marginal benefit, real UX cost.

4. **No raise to FEE_QUADRATIC_COEFF.** Going from 2 to 4 roughly doubles
   the cost of max-size messages to ~2,000 tokens but leaves small-tx
   fees essentially unchanged. Since scenario 1 already prices out a
   well-funded nation-state, there's no realistic attacker this would
   defend against that isn't already priced out.

5. **Base-fee dynamics are healthy.** Under saturated attack (scenario 4),
   the base_fee cap (1,000,000 tokens/tx) would consume 1.05T tokens per
   year — a 1000x multiple of genesis supply. The 10,000x multiplier cap
   is correctly placed: high enough to deter, finite so the chain recovers.

### Minor surprise / callout

- The **byte-budget cap is slack under current params** (MAX_TXS_PER_BLOCK
  binds first). If MAX_MESSAGE_BYTES is ever raised above 500 or
  MAX_TXS_PER_BLOCK is raised, re-run this model before shipping the
  change — the analysis assumes the current binding constraint.
- Compression on 280 bytes of high-entropy ASCII yields only ~1.07x
  (261/280 stored bytes). zlib adds zero meaningful bloat reduction on
  worst-case spam payloads. This is expected and doesn't weaken the
  model — attackers already maximize raw bytes.

## Bottom line

Current fee parameters are **economically tight** against sustained spam
over 100-1000 year horizons. The quadratic coefficient plus the 280-byte
message cap produce a pricing curve where any attacker willing to fill
the chain pays more than the entire token supply within the first year.
No parameter change is needed for security; the only recommended change
is hygiene (tighten or remove the currently-unreachable
`MAX_BLOCK_MESSAGE_BYTES=10,000`).
