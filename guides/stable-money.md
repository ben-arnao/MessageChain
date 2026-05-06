# Stable money over centuries

> **The goal:** when you read "10 tokens" in MessageChain in the year
> 2125, it means roughly the same fraction of the live economy as
> "10 tokens" does today.

A messaging chain that's supposed to last for centuries has a money
problem most blockchains never have to solve. Bitcoin's 21-million-coin
cap looks tidy, but a fixed cap interacts badly with two centuries of
key loss: every wallet that gets dropped into the ocean shrinks the
*usable* supply, and the surviving holders silently inherit the
difference. A fee that costs "1 BTC" today and "1 BTC" in 200 years
would not mean the same thing — the unit drifts under your feet.

MessageChain's headline promise is permanence. That promise extends
to the unit of account itself: the protocol holds the *active* supply
constant, so fixed-token fees, stake thresholds, and proposal costs
keep their economic meaning forever.

## The mechanism in one paragraph

Every balance on chain has a "last active" height — the most recent
block in which that key signed something. Balances that have signed
recently count toward `active_supply`. Balances that have been silent
for a very long time slowly fade out of `active_supply` (without ever
being deleted from the chain). A simple proportional controller mints
new tokens each block in just the amount needed to keep `active_supply`
near a fixed target. Lost keys quietly drop out; new issuance refills.
The total supply drifts upward over centuries, but the *live* supply
holds steady.

If a long-dormant key wakes up and signs a transaction, its balance
re-enters `active_supply` immediately — nothing is confiscated, nothing
is lost. The chain just stops counting it as live until it proves
liveness again.

## What counts as "active"

Receiving tokens is not enough. If incoming transfers counted, a
spammer could keep dormant wallets "active" by sending dust. Activity
requires the key to actually *sign* something:

- Outgoing transfers
- Posting a message
- Stake / unstake
- Validator attestations
- Block proposals
- Governance proposals and votes
- Reactions (votes on messages, trust/flag on users)
- Authority changes, key rotations, evidence submissions

In short: anything that proves the key holder is alive and in
possession of the seed.

This matters for validators in particular — a long-tenured operator
might never move stake for years. Their attestations and proposals
keep them counted as active without forcing a transfer they didn't
need to make.

## The numbers

The values below are what's anchored in the protocol today. They're
tuning knobs, not laws of physics — a future fork can adjust them.
The *shape* (dormancy filter + supply-replenishing controller) is
what's permanent.

- **Dormancy window:** 1,314,000 blocks. At 600 seconds/block, that's
  about **25 years** of total inactivity before a balance is fully
  dormant.
- **Taper:** 131,400 blocks (the last ~2.5 years of the window). A
  balance crossing the threshold doesn't snap from "100% active" to
  "0% active" in a single block — it linearly fades over the taper.
  This avoids cliff effects where one quiet block reclassifies a
  large holder.
- **Target active supply:** 140,000,000 tokens. The controller steers
  toward this number forever.
- **Issuance ceiling:** 64 tokens per block, no matter how big the
  gap is. This bounds pathological states (e.g., a sudden mass
  dormancy event) so issuance can't spike.
- **Controller curve:** the gap between target and current active
  supply is closed proportionally — roughly halved every 16 months
  at current block timing. Slow and stable, not a step function.

## Why a window measured in decades

Setting the window short would punish ordinary "I forgot about that
wallet for a while" behavior. Setting it longer than human lifetimes
would mean lost-key dilution piles up uncorrected for generations.
~25 years is the sweet spot: it lets a key sit untouched through a
single human life-event (career change, illness, generational
handoff) without being treated as lost, while still applying the
filter aggressively enough to keep the live supply meaningful across
centuries.

The taper is what keeps the threshold from being a sharp edge. As a
balance ages from year 22.5 to year 25 of inactivity, its weight in
`active_supply` linearly slides from full to zero. A balance that
becomes active again at any point in that window is restored to full
weight on the next block.

## What this is NOT

- **Not confiscation.** A dormant balance is *never* deleted. Its
  full token amount sits in chain state, signed-for by its key,
  forever. It just doesn't count toward `active_supply` for the
  controller's purposes. The moment the key wakes up, the balance is
  fully usable and fully active again.
- **Not "demurrage" or wealth tax.** Active holders don't lose tokens
  because other people's tokens are dormant. The dormancy filter
  changes the *denominator* the controller targets, not anyone's
  actual balance.
- **Not a security funding mechanism.** Validator security is funded
  by the fee market and the existing reward curve. Issuance under
  this controller exists to replenish supply lost to dormancy — not
  to underwrite consensus.

## What this protects

- **Fixed-token costs keep their meaning.** A 1-token minimum fee,
  a 200-token validator stake floor, a 100,000-token proposal fee,
  a 1,000-token new-account surcharge — none of these need to be
  retuned every few years to track changes in supply. The chain
  holds the denominator constant and the constants stay constant.
- **Lost-key drift is silent and self-correcting.** If half the
  genesis distribution disappears into lost laptops over the next
  two centuries, the controller refills it from issuance over time
  — and the moment any of those keys ever resurface, their tokens
  are still right there.
- **No cliff for legitimate long-term holders.** A cold-storage
  saver who comes back after 20 years is welcomed back with their
  full balance and their full active-supply weight, with the next
  block they sign.

## When does this activate?

The dormancy controller activates at a future block height (Tier 47
in the upgrade schedule). Until activation, the chain runs the
legacy halving-based issuance schedule. Both behaviors are
byte-for-byte identical pre-activation, and the controller takes
over cleanly at the activation block — no migration tx required.

## Further reading

- [Anti-bloat: keeping the chain small enough to run forever](./anti-bloat.md)
  — the storage side of the same long-horizon problem.
- [Keeping rewards fair](./fair-rewards.md) — how PoS issuance is
  shared across validators of different sizes, including the
  diminishing-returns curve.
