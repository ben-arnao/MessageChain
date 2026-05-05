# Keeping rewards fair

> **The shape:** larger stakers always earn *more* tokens in absolute
> terms — running honest infrastructure 24/7 with more skin in the
> game is strictly preferable to walking away. But the *yield per
> token* gets worse the larger you are, so the distribution
> compresses upward over time rather than ossifying around whoever
> showed up first.

A fixed-rate proof-of-stake reward curve has a known endgame: rich
gets richer, share of the validator set drifts toward whoever started
biggest, and a decade later one operator effectively owns the
network. MessageChain explicitly designs against that endgame, while
keeping the *positive* incentive of stake (run more infra, secure
more of the chain, earn more in absolute terms) intact.

There are two cooperating mechanisms:

1. A **diminishing-returns reward curve** that pays a higher
   per-token yield to small validators and a lower per-token yield
   to whales.
2. A **founder/seed divestment schedule** that gradually retires the
   genesis stake and redirects the freed weight to the broader
   validator set via a reputation-weighted lottery.

## 1. The reward curve

MessageChain's per-block validator rewards are scaled by a
multiplier that depends on the validator's share of total active
stake. The current curve (Tier 42, "Smooth V2") looks like this:

```
multiplier(stake_share) = (FLOOR·share + PEAK·SCALE) / (DEN·(SCALE + share))
```

In plain English:

- A **tiny validator** (≈ 0% stake share) earns at a multiplier of
  **1.30×** the base reward — the highest yield on the curve.
- A **whale** (stake share → ∞) approaches an asymptotic floor of
  **0.80×** the base reward — yield never goes to zero, never goes
  negative.
- The midpoint sits at **10% stake share**, where the multiplier is
  about **1.05×**.

The curve is **concave and monotonically decreasing in per-unit
yield** — every extra token of stake earns slightly less than the
last one. There's no hard cap and no "you stop earning here" cliff.

### Why it doesn't punish honest whales

Two important properties:

- **Absolute reward keeps growing.** A 50%-stake validator still
  earns more total tokens per block than a 10%-stake validator —
  just at a lower rate per token. Walking away from honest infra is
  always strictly worse than running it.
- **Sybil-splitting a whale is fine.** If a whale fragments one
  large identity into many smaller honest validators, each running
  real infra, the chain *welcomes that* — more validators, broader
  operational footprint. The cost of running real infra under each
  identity is the natural sybil tax. The curve isn't trying to
  detect this; it's trying to make raw concentration unprofitable
  on a per-token basis.

The compression effect is gradual. A 10× imbalance in stake doesn't
become a 10× imbalance in earned yield — it becomes more like a 4–5×
imbalance, and that gap shrinks over time as smaller validators
compound at a higher rate.

## 2. The founder divestment schedule

MessageChain launched with a single founder validator carrying the
overwhelming majority of stake — that's how a permissionless chain
gets bootstrapped at all without a token sale. Genesis allocation:

- **Liquid (founder):** 5,000,000 tokens
- **Staked (founder):** 95,000,000 tokens
- **Total founder allocation:** 100,000,000 tokens

The "founder runs the network" phase is **not a permanent gate** —
it's just what naturally emerges from the founder holding the bulk
of genesis stake. As validators stake in and the founder's share
dilutes, founder influence smoothly decays to "any other validator."
There is no flag-flip handover, no migration tx, no protocol-level
cutoff event.

To accelerate that natural dilution, the founder's stake is
**actively divested** by the protocol on a fixed schedule:

- **Start:** block 7,500
- **End:** block 217,884 (block 7,500 + 210,384)
- **Window:** ~210,000 blocks ≈ **4 years** at 600 s/block
- **Retain floor:** 10,000,000 tokens — divestment never takes the
  founder below this amount, so a residual reward for bootstrap work
  remains.

Each block in that window, a small slice of the founder's stake is
peeled off. Where does it go? After the redistribution upgrade
(activates at block 1,600):

- **50%** is **burned** (permanently removed from supply).
- **5%** routed to **treasury** (governed by treasury-spend
  proposals).
- **45%** routed to a **validator lottery**.

## 3. The lottery: where the 45% lands

The 45% slice doesn't go to the next-largest validator (that would
just shift concentration around, not break it up). It goes into a
reputation-weighted lottery that pays out to non-seed validators
proportional to their **on-chain reputation** — accepted attestation
counts, with a cap.

A few important properties:

- **Excludes the seed/founder.** Lottery winners are drawn from the
  non-seed set, so divested stake genuinely flows *out* of the
  founder's neighborhood and into the broader validator population.
- **Reputation-weighted, not stake-weighted.** This rewards
  operators who actually do honest work (attesting correctly, being
  online), not just operators who happen to hold lots of stake.
- **Bounty fades over the bootstrap arc.** The full bounty is
  active early in the divestment window, then linearly fades toward
  zero as the founder approaches their retain floor. The lottery is
  there to *kickstart* a competitive validator set, not to be a
  permanent rent.

Combined with the diminishing-returns curve, the founder divestment
schedule converts the bootstrap configuration into a broadly
distributed validator set over a few years, without ever forcing
anyone out and without ever confiscating anyone's tokens.

## 4. Slashing leniency for honest operators

Fair rewards aren't enough on their own — fair *penalties* matter
too. Validator slashing in MessageChain is graded by track record,
not by raw severity:

- **Catastrophic, unambiguous offenses** (like deliberate
  double-signing with overlapping evidence windows): full or
  near-full slash, especially for validators with thin history.
- **Ambiguous evidence** (timestamp drift, restart-shape evidence
  that could be a transient fault): a small base penalty, scaled by
  history relief — long-tenured validators with clean records get
  a much smaller hit, and may receive **first-incident amnesty** if
  their record is perfect.
- **Soft-slash regime** (active on mainnet today): equivocation
  penalty drops to **5% per offense**, and the validator stays in
  the set with reduced stake. Pre-soft-slash, the same offense was
  100% of stake.

The intent: one bad block doesn't nuke a long-honest operator, but
a pattern of bad behavior from a thin-history node doesn't get
laundered by the same leniency.

## 5. Activation status (as of mid-2026)

Some of these features are activated; some are scheduled for future
blocks and will activate as the chain reaches them:

- **Soft-slash regime:** active.
- **Reward curve V2 (Smooth):** activates at block 2,400.
- **Seed divestment redistribution (with 45% lottery routing):**
  activates at block 1,600.
- **Seed divestment window (start → end):** runs blocks 7,500 →
  217,884.

Pre-activation, the chain runs the prior versions of each curve
byte-for-byte. Operators don't need to do anything — the activations
fire automatically at the scheduled heights.

## Summary

The system isn't trying to flatten outcomes — it's trying to keep
the *rate of concentration* below the rate at which new participants
can join and grow. A whale in MessageChain still earns the largest
absolute reward and still has the largest voice in governance.
What's been engineered out is the runaway dynamic where their
*share* compounds faster than anyone else can catch up.

Over decades, the design target is a validator set that looks more
like a community than a court — many participants, a flat-ish
middle, no permanent incumbent.

## Further reading

- [Stable money over centuries](./stable-money.md) — what the
  active-supply controller does for the unit of account, and why
  rewards are paid out of dormancy-replenishment issuance.
- [Governance: expensive proposals, permanent record](./governance.md)
  — how voting power is allocated. Stake-weighted, with the same
  "per-unit voice diminishes" instinct expressed via the threshold
  rather than the curve.
