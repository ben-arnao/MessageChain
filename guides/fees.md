# Fees: how pricing actually works

> **The shape:** a flat per-tx admission floor as a spam gate, a
> per-byte component above it driven by the market, and an
> EIP-1559-style base fee that adjusts with congestion. The CLI
> auto-prices for you by default — you almost never have to think
> about this — but it helps to know what's happening under the
> hood.

Fees are the only anti-spam mechanism MessageChain has. There's no
captcha, no proof-of-human, no allowlist, no content-based
filtering. The chain trusts that *every* message is worth
permanent storage if and only if someone was willing to pay for
that permanence in real tokens. Everything in the fee model rolls
out from that single principle.

## The four moving parts

A fee bid you submit is evaluated against four things:

1. **A flat per-tx floor** — the spam gate. Pay less than this and
   your tx is rejected at admission, full stop.
2. **A per-stored-byte component** — short messages cost less than
   long ones. Storage discipline, market-driven.
3. **An EIP-1559-style base fee** — adjusts block-by-block to
   match congestion. The portion of your fee that meets the base
   fee is **burned**; the rest goes to the proposer as a tip.
4. **Per-tx-type surcharges** — a few high-stakes operations
   (governance proposals, transfers to brand-new accounts) carry
   extra fixed fees. These layer on top of the floor.

You don't have to compute any of this manually. The default CLI
flow auto-prices.

## What the floor is (and isn't)

The flat per-tx floor is **1,000 tokens** today (Tier-16 protocol
floor; the relay floor at the network edge is lower at 1 token,
but the in-block floor is what actually matters for inclusion).

A few things to keep straight:

- The floor is a **spam gate**, not the market price. It exists to
  separate "real user-submitted tx" from "free-rider tx that costs
  the network permanent storage." Pricing *above* the floor is
  market-driven, not floor-driven.
- The floor is **flat by design**, not linear-in-bytes. Storage
  pricing for long messages is delivered by fee-per-byte ranking
  in the mempool, not by the floor. (See [anti-bloat
  guide](./anti-bloat.md) for why this composition is sufficient.)
- The floor is a **hard fork knob**, not a market parameter. It
  changes only via a coordinated upgrade. Day-to-day fee dynamics
  happen entirely above it.

## The base fee — burn vs tip

Above the floor, fees split into two parts:

- **Base fee:** burned. Removed from supply forever.
- **Tip** (the rest): goes to the block proposer as a validator
  reward.

The base fee adjusts every block based on whether the previous
block was full or slack:

- **Block ran hot** (lots of contention) → base fee *rises* next
  block → larger fraction of your fee burns → smaller tip.
- **Block ran slack** (plenty of empty space) → base fee *falls* →
  smaller fraction burns → larger tip.

Net effect: under congestion, posting becomes more expensive
overall (you bid higher to win inclusion) *and* a larger share of
that bid is destroyed rather than paid out — the chain itself is
the counterparty to congestion, not the validators. Validators
still earn the marginal tip, but they can't extract congestion rent
the way they would under a pure auction model.

## Fee-per-byte ranking

When the byte budget binds (i.e., not every pending tx fits), the
proposer ranks pending txs by **fee-per-stored-byte**, highest
first, and packs the block accordingly.

A short, high-fee tx beats a long, low-fee tx — even when the long
tx paid more in absolute terms. A 50-byte one-liner paying 500
tokens (10 tokens/byte) outranks a 1000-byte essay paying 5000
tokens (5 tokens/byte). This is the lever that keeps long messages
from edging out short ones just by carrying a bigger sticker fee.

The same ranking governs **eviction**. When the mempool fills up,
the lowest-density txs are dropped first.

## The auto-fee picker

The CLI's auto-fee mode looks at the *last 50 blocks* of fee
density, picks a percentile based on your urgency, and bids the
percentile rate × your tx's stored byte count.

| Urgency | Percentile | Target inclusion |
|---------|-----------|------------------|
| `high`  | 90th      | ~1 block (~10 min) |
| `normal` (default) | 75th | ~3 blocks (~30 min) |
| `low`   | 25th      | ~10 blocks (~100 min) |

The picker clamps to the protocol floor — if the percentile rate
times your size comes in below the floor, you pay the floor.

In practice, on a quiet chain like MessageChain in its bootstrap
phase, your auto-fee almost always **clamps to the floor** —
nothing's competing for your slot, the percentile rate is
irrelevant, and you pay the minimum. The auto-fee picker becomes
load-bearing later, as the network heats up.

## Estimating before you send

`estimate-fee` previews any tx without sending it:

```bash
messagechain estimate-fee --tx-type message --message "hello"
messagechain estimate-fee --tx-type transfer --amount 100 --to mc1...
messagechain estimate-fee --tx-type proposal \
    --title "..." --description "..."
```

The output breaks down:

- **`stored_bytes`** — the serialized size you're being charged on.
- **`fee_per_byte`** — the percentile rate from recent blocks.
- **`min_fee`** — the protocol floor for this tx kind.
- **`mempool_fee`** — what the percentile estimate alone suggests.
- **`recommended_fee`** — `max(min_fee, mempool_fee)` — the bid
  the CLI will use if you let it auto-price.

Useful for governance proposals especially, since their fees can
be substantial — better to know in advance.

## Manual override

```bash
messagechain send "hello" --fee 5000
```

Any explicit `--fee N` skips the picker. Admission rule: **N must
be at least the floor.** No upper bound. Pay whatever you want
above that.

If you under-bid (pay floor, but mempool density is way above
floor under congestion), your tx will sit in the mempool, ranking
near the bottom. Most likely outcomes:

- **The pressure subsides** before your tx is evicted, and it gets
  included a few blocks later than you wanted.
- **Pressure persists**, your tx is evicted, and you have to
  resubmit at a higher price.

There's **no on-chain fee bumping** (no replace-by-fee semantics
between mempool entries). If you need to escalate, you submit a
new tx with a higher fee. Old mempool entries expire after ~24h
TTL, so they don't accumulate forever.

## Per-tx-type surcharges

A few transaction types carry fixed fees beyond the standard
floor:

| Tx kind | Fee | Notes |
|---------|-----|-------|
| Message | floor + per-byte | The default. Auto-priced. |
| Transfer | floor + per-byte | Same as message. |
| Transfer to brand-new account | floor + per-byte + **1,000 burn surcharge** | One-time cost to create chain state for a new entity. Sender pays. |
| Stake / unstake | floor + per-byte | Same as message. |
| React (vote/trust/flag) | floor + per-byte | Same fee model — no free votes, no free flags. |
| Key rotation | **1,000** flat | Fixed, not per-byte. |
| Governance proposal | **100,000 + 50/byte** | Deliberately expensive. See [governance guide](./governance.md). |
| Governance vote | **100** flat | Cheap on purpose; vote rewards come from the proposal fee. |

The per-tx-type surcharges layer **on top of** the standard floor;
they don't replace it.

## What the fee actually pays for

When you submit a tx, the fee goes:

1. **Sender's balance** is debited the full `amount + fee`.
2. **Recipient's balance** is credited `amount` (zero fee on
   their side — see "receive-to-exist" below).
3. **Base-fee component** is burned (irreversibly removed from
   supply).
4. **Tip component** is credited to the block proposer.
5. **Special-purpose surcharges** (e.g., NEW_ACCOUNT_FEE,
   governance proposer fee) are routed per their rules — most are
   burned; the governance voter pool is escrowed for distribution
   to YES voters at proposal close.

A separate funding stream that *isn't* in the per-tx fee:
**archive challenge bounties** are funded by a 25% redirect of
the base-fee burn into a dedicated pool. So a small slice of every
fee you pay is, indirectly, paying for proof-of-storage rewards.

## Receive-to-exist: zero cost on the recipient side

You do **not** need to pay anything to *receive* tokens or
messages. There's no "create account" fee on the recipient. There's
no "register your pubkey" fee. Your account appears in chain state
the moment someone sends you a transfer.

If the sender is sending to a brand-new entity (you), the **sender**
pays the 1,000-token NEW_ACCOUNT_FEE surcharge as part of their
transfer fee. You receive the full amount.

This matters for adoption: a new user can be onboarded by anyone
sending them a small amount, and they don't need to come to the
chain with tokens already in hand. The faucet on
[messagechain.org](https://messagechain.org) does exactly this —
sends a 300-token drip to any address that asks (rate-limited per
network).

## Practical rules of thumb

- **For everyday messages, use the default `normal` urgency.**
  Auto-fee will clamp to the floor on a quiet chain; it'll bid
  appropriately as the chain heats up. You don't have to think
  about it.
- **Use `--urgency high` for time-sensitive ops** (publishing
  evidence, announcing something where a 30-minute lag matters).
- **Use `--urgency low` for batch posts** that you don't mind
  waiting an hour or two for.
- **Run `estimate-fee` before any expensive op** (governance
  proposal in particular — the per-byte component on a long
  description can surprise you).
- **Never pay below the floor.** The CLI won't let you, but if
  you're constructing txs by hand, double-check.

## Summary

| Component | Current value | Knob type |
|-----------|--------------|-----------|
| Per-tx flat floor | 1,000 tokens | Hard-fork |
| Per-stored-byte component (above floor) | 3 tokens/byte (Tier-9) | Hard-fork |
| Base fee | Adjusts per block | Market |
| Auto-fee lookback | Last 50 blocks | CLI |
| Urgency rungs | 25 / 75 / 90 percentile | CLI |
| New-account surcharge | 1,000 tokens (burned) | Hard-fork |
| Governance proposal fee | 100,000 + 50/byte | Hard-fork |
| Governance vote fee | 100 tokens | Hard-fork |
| Mempool TTL | ~24 hours | Soft (relay) |

The whole model exists to do one thing: make permanent storage
**genuinely costly enough that bulk machine-generated content
isn't economical**, while keeping individual human messages
affordable. Fees are the lever; everything else flows from there.

## Further reading

- [Anti-bloat: keeping the chain small enough to run forever](./anti-bloat.md)
  — the protocol-side counterpart to user-side fees.
- [Validator economics](./validator-economics.md) — the other
  side of the fee market: where the tips and burn redirects end
  up.
- [Governance: expensive proposals, permanent record](./governance.md)
  — the most expensive tx type, and why.
