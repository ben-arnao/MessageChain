# Guides

Short, focused write-ups on how MessageChain works and why it's
designed the way it is. Linked from the project [README](../README.md).

## Identity & keys

- [Identity, keys, and rotation](./identity.md) — one live key per
  entity, but rotation preserves identity, history, and
  reputation. Plus the cold authority key and emergency revoke.
- [Quantum resistance and WOTS+](./quantum-resistance.md) — why
  MessageChain signs with hash-based signatures from day one, and
  how versioned schemes make a future migration a rotation rather
  than a forklift upgrade.

## Economics & supply

- [Stable money over centuries](./stable-money.md) — how the
  active-supply controller and dormancy filter make `X tokens`
  mean `X tokens` 100+ years from now.
- [Fees: how pricing actually works](./fees.md) — flat floor,
  per-byte component, EIP-1559-style burn, auto-fee picker, and
  what every fee actually pays for.
- [Keeping rewards fair](./fair-rewards.md) — the
  diminishing-returns reward curve, the founder divestment
  schedule, and the lottery that redistributes seed stake to the
  broader validator set.
- [Validator economics](./validator-economics.md) — what running
  a validator costs, what you earn, what's at risk, and rough
  break-even math.

## Governance

- [Governance: expensive proposals, permanent record](./governance.md)
  — how proposals work, who gets paid for voting, why results are
  advisory but recorded forever.

## Storage & permanence

- [Anti-bloat: how the chain stays small enough to run forever](./anti-bloat.md)
  — slow blocks, the 1024-byte message cap, the per-block byte
  budget, and worst-case storage projections out to 50+ years.
- [Permanence guarantees: archive duty and censorship resistance](./permanence.md)
  — the protocol-level mechanics that make "your message can
  never be deleted" enforceable rather than aspirational.

## Social primitives

- [Forum primitives](./forum-primitives.md) — replies, up/down
  votes, communities, long-form threading. The on-chain building
  blocks any app or front-end can render.
- [Reputation primitive](./reputation.md) — trust and flag votes
  between users, what the protocol stores, and where richer
  reputation systems can be built on top.
- [Combating AI spam and generated content](./ai-spam.md) — the
  thesis: real fee floor + permanent reputation graph =
  bulk-machine-spam economics that don't pencil out. No
  detection, no blocklists, no proof-of-human.
