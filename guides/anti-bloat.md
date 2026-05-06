# Anti-bloat: keeping the chain small enough to run forever

> **The promise:** an ordinary user — not just a datacenter — should
> be able to sync and store the *full* history of MessageChain on
> commodity hardware, decades or centuries from now. Bloat reduction
> isn't an end in itself. It's the lever that keeps "run a full node
> from your laptop" realistic at scale.

There's a quiet failure mode in any "permanent ledger" pitch:
permanence implies storage cost, storage cost grows linearly with
volume, and an unbounded ingress rate eventually puts full-node
operation out of reach for anyone but cloud operators. At that
point the chain is technically uncensorable but practically
centralized — a handful of well-funded archives become the only
sources of truth, and the ground-up promise of "anyone can verify
the whole thing" quietly dies.

MessageChain attacks this head-on with five protocol-level levers,
all of which are intentional and all of which are tuned for the
*long game*, not next month's UX.

## 1. Slow blocks

**One block every 10 minutes.** (`BLOCK_TIME_TARGET = 600 seconds`,
144 blocks per day.)

This is the same cadence Bitcoin chose, for the same reason: it
caps the worst-case ingress rate. No matter how heated network
demand gets, no matter how many people pile on, only one block's
worth of transactions can land per 10 minutes. That single decision
puts a hard ceiling on how fast the chain can grow.

A messaging chain that fired off blocks every 2 seconds would have
to fight bloat with much harsher per-message limits or aggressive
storage tricks. Slow blocks let MessageChain keep per-message limits
generous (a full 1024-byte body — tweet-scale text in any modern
script) while keeping daily growth modest.

## 2. The 1024-byte message cap

**Every message body is capped at 1024 UTF-8 bytes.** Period. No
long-form posts, no embedded images, no inline attachments.

Plaintext is NFC-normalized UTF-8 in the Unicode Letter / Mark /
Number / Punctuation / Space-separator categories — every modern
written language is admissible. ASCII English fits 1024 characters
in 1024 bytes; scripts like CJK or Devanagari fit fewer characters
for the same byte budget, because each codepoint encodes to more
bytes. Per-byte storage pricing means every user pays for the
permanence they actually pin, regardless of script.

This isn't a UX bug, it's a feature: it forces "tweet-scale" speech
to live on chain and pushes everything longer to either be chained
together (one message per block, see below) or to live on L2.
Ledger-level permanence for short-form public speech is what
MessageChain promises; document hosting is somebody else's problem.

For longer content, the protocol supports **chained messages**:
each message can carry a `prev` pointer (32-byte tx hash) referencing
an earlier on-chain message. A 5,000-character essay becomes five
1,024-character messages, each pointing at the previous one. The
referenced tx must be in a strictly earlier block, so chained
posts pay the block cadence — about 10 minutes between pieces.

## 3. Per-block byte budget

Even with 1024-byte messages, an unbounded number of messages per
block would defeat the cap. Each block has hard byte budgets:

- **Per-block message-payload budget:** 45,000 bytes. The proposer
  can include any combination of message txs that fits under this.
- **Per-block total tx envelope:** 200,000 bytes. Includes
  transfers, stake txs, attestations, governance, witnesses inline,
  everything. Wider than the message budget because non-message txs
  carry overhead the message budget shouldn't have to compete with.

When a block is full, the budget *binds* — not every pending tx
gets in. This is where the fee market kicks in.

## 4. Fee-per-byte ranking

When the byte budget binds, validators rank pending txs by
**fee-per-stored-byte** (`fee / stored_bytes`), not by absolute
fee. The highest-density txs land first; lower-density txs wait or
get evicted.

This is what stops large messages from outbidding small ones just
by carrying a bigger sticker fee. A 1,024-byte essay paying 1,000
tokens (≈ 1 token/byte) ranks *worse* than a 50-byte one-liner
paying 200 tokens (≈ 4 tokens/byte) — even though the essay paid
five times more in absolute terms.

The result: when the network is busy, long messages have to bid
proportionally harder than short ones. Storage discipline is
delivered by the *market*, not by an artificial schedule.

The floor underneath the market is intentionally simple:

- **Flat per-tx admission floor (`MARKET_FEE_FLOOR`):** 1 token
  minimum, no matter the size — this is the spam gate, keeping
  zero-fee txs out and separating "user-submitted tx" from
  "free-rider that costs the network permanent storage." The floor
  is *not* the market price; it's the lower bound the EIP-1559
  base fee sits above.
- **Per-stored-byte cost above the floor:** market-driven, not a
  fixed schedule. When blocks fill, the EIP-1559 base fee rises
  and longer txs lose inclusion races at the floor — they have to
  bid proportionally higher to win the same priority. The
  fee-per-byte ranking in the mempool is what makes long messages
  compete with short ones at equal stake.

## 5. Witness separation and compression

Two more storage tricks worth naming:

- **WOTS+ witnesses are heavy** (a single signature is roughly 2.7
  KB — most of a tx's bytes). A signature is needed to *verify*
  the tx, but once the tx is finalized and far enough buried, the
  witness can be split into a separate archive layer. Full nodes
  can keep just the witness Merkle root in the main chain and let
  witness-archive nodes carry the heavy bytes. Activates at block
  3,000; witnesses are retained in main storage for 200 blocks
  past finality, then split.
- **Canonical compression.** Message payloads are compressed with
  zlib level 9 (raw deflate), and the chain stores whichever is
  smaller of raw or compressed (preferring raw on ties to skip a
  decompress step). Typical English text shrinks 30–50%.

Nothing is ever *deleted*. Witness separation moves bytes from one
storage tier to another; compression encodes them more efficiently.
The full chain is still recoverable by anyone willing to keep the
archive layer too.

## What this actually adds up to: storage trajectory

Let's do the math on the worst case — *every block always full,
zero compression help*:

```
worst-case bytes/year =
    MAX_BLOCK_MESSAGE_BYTES × blocks/day × 365
  = 45,000 × 144 × 365
  = 2,367,600,000 bytes
  ≈ 2.37 GB / year
```

Projecting forward — message-payload bytes only, worst case:

| Years | Worst-case GB | Notes |
|-------|---------------|-------|
| 1     | ~2.4 GB       | Modern phones have more storage than this. |
| 5     | ~12 GB        | Comfortably below a typical laptop SSD. |
| 10    | ~24 GB        | Still tiny relative to commodity storage. |
| 25    | ~59 GB        | Small fraction of a 1 TB drive. |
| 50    | ~118 GB       | Storage cost will fall by orders of magnitude over this horizon. |
| 100   | ~237 GB       | Comparable to a single 4K movie's archival copy *today*; trivial then. |

A rough text trajectory plot of the same numbers (every `█` ≈ 12 GB):

```
year  1 │ ▏                                          (2.4 GB)
year  5 │ █                                          (12 GB)
year 10 │ ██                                         (24 GB)
year 25 │ █████                                      (59 GB)
year 50 │ ██████████                                 (118 GB)
year100 │ ████████████████████                       (237 GB)
```

A few things this hides:

- **This is the absolute worst case.** It assumes every block is
  packed to the byte budget, every byte of every block is a maximum
  message payload, and zlib gives zero help. None of those will
  hold in practice — typical message volume is a small fraction of
  the budget today, and compression typically halves payloads.
  Realistic trajectories are an order of magnitude or more below
  these numbers.
- **It's only message-payload bytes.** Adding the full tx envelope
  (transfers, stake operations, governance, witnesses) under the
  same worst-case assumption pushes the number up by ~4×. Full-tx
  worst-case is closer to **~10 GB/year** at the current 200 KB
  total budget — still tractable.
- **Witness separation** moves a large fraction of those bytes out
  of mainline storage for nodes that opt out of carrying the
  archive layer.
- **Storage cost is falling.** Every $/GB datapoint over the last
  30 years has trended down. By 2126, today's worst case is rounding
  error.

The point isn't that storage is free — it's that the storage growth
curve fits comfortably under the *hardware curve* even on
unfavorable assumptions. A hobbyist a century from now, on whatever
commodity storage looks like then, can still run a full archival
node.

## What this is NOT

- **Not pruning.** No protocol path deletes message content. A
  message included in block 1 is still in the chain at block
  10,000,000. Witness separation moves bytes between storage tiers;
  it doesn't remove them.
- **Not a TTL.** Messages don't expire. There's no "rent." There's
  no "garbage collection."
- **Not a per-tx fee inflation cycle.** Fees rise and fall with
  market demand for inclusion. The protocol does *not* defend
  against spam by ratcheting up the floor over time. The lever
  against runaway demand is shorter blocks or a tighter byte
  budget — not a fatter fee schedule.

## Summary

| Lever | What it does | Why it matters |
|-------|--------------|----------------|
| 600s blocks | Caps ingress rate | Hard ceiling on growth; no amount of demand can speed it up |
| 1024-byte messages | Forces short-post scale | Long-form goes to L2 or chained messages; ledger stays focused |
| 45 KB block message budget | Caps per-block volume | Even at full load, per-day growth is bounded |
| Fee-per-byte ranking | Storage discipline via market | Long messages bid harder; small messages don't get edged out |
| Witness separation + compression | Storage encoding | Roughly 30–50% smaller chain at no security cost |

Together, these turn a "messages are forever" promise into something
a hobbyist can actually carry — for the next decade, the next
century, and beyond.

## Further reading

- [Stable money over centuries](./stable-money.md) — the dual
  long-horizon problem on the *unit of account* side.
- [Permanence guarantees: archive duty and censorship resistance](./permanence.md)
  — the protocol-level mechanics that ensure full nodes actually
  store the full history they claim to, and that included messages
  can't quietly disappear.
