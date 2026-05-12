# How MessageChain compares to nearby projects

Five projects share enough of MessageChain's design space — by mission,
functionality, or both — to be worth contrasting against. The matrix
shows how each delivers on MC's core promises.

| Feature | MC | Hive | DeSo | Nostr | Bastyon | Arweave |
|---------|:--:|:----:|:----:|:-----:|:-------:|:-------:|
| Censorship resistance via slashable evidence | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Text-only, slow blocks, anti-bloat — runnable on commodity hardware indefinitely | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Consensus-driven permanence | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| Full-history retention incentivized; pruning disincentivized | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Disciplined scope — basic primitives, no higher-level programmability | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ |
| Quantum resistant + crypto agility | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Identity continuity across key rotations | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Proof-of-Stake — no energy waste | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |
| No special nodes | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ |
| Built-in on-chain governance | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Structured polls + on-chain votes with consensus-enforced tally | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Self-funding in perpetuity — no reliance on good faith | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |

Tallies: **MC 11 · Hive 5 · DeSo 4 · Bastyon 3 · Nostr 2 · Arweave 2**.

## Why the gaps

**Slashable censorship evidence.** No other listed project has
cryptographic slashing for "validator silently dropped my tx" or
"validator forged an invalid-signature rejection." Inclusion rests on
majority honesty alone, with no recourse if a minority colludes. MC has
three explicit evidence types plus a forced-inclusion list.

**Text-only, anti-bloat, hobbyist archive forever.** MC caps payloads
at 1024 UTF-8 bytes and blocks at 600s — worst-case ~2.4 GB/year. Hive
runs 3s blocks; DeSo includes NFTs and rich media; Bastyon ships video
on chain; Arweave stores arbitrary data with no per-payload cap. None
preserve the property MC engineers for: an ordinary user can run a full
archive on commodity hardware indefinitely.

**Consensus-driven permanence.** A Nostr post exists only as long as
at least one relay still hosts it — no consensus layer to fall back on.

**Full-history retention.** MC challenges validators every 100 blocks
to prove they still hold random ancient blocks; missed proofs withhold
rewards. Other chains technically retain history but have no protocol-
level mechanism that *pays* nodes to retain it. Arweave's mining
incentivizes replication but no individual node holds everything.

**Disciplined scope.** DeSo bolted on creator coins, social tokens,
NFTs, on-chain marketplaces, and games. Hive ships HBD (a stablecoin)
and on-chain markets. Arweave runs full programmability via AO. Bastyon
extends past basic primitives with on-chain video and a built-in DEX.
Each addition is regulatory exposure and attack surface that
"messages-only" avoids.

**Quantum resistance + crypto agility.** All other listed projects use
elliptic-curve or RSA signatures with no version tag — a future quantum
break (or any cryptographic compromise) requires a coordinated migration
with no native primitive. MC uses hash-based WOTS+ from day one, with
algorithm tags so retired schemes can be swapped via hard fork while old
signatures remain verifiable.

**Identity continuity.** Nostr's identity *is* the `nsec` key — lose it
and the entity restarts from zero. Arweave has no rotation primitive.
DeSo and Bastyon lack first-class rotation that preserves history. MC's
key-rotation tx preserves posts, threads, balances, and reputation
across rotations and across cryptographic-algorithm migrations.

**Proof-of-Stake.** Arweave is PoW-based (SPoRA); Nostr has no
consensus to evaluate.

**No special nodes.** Hive's active block-producing set is the top ~20
elected witnesses — a small permissioned-by-vote slate. Same structural
vulnerability that forced the 2020 Steem→Hive emergency fork.

**Built-in governance.** DeSo, Nostr, Bastyon, and Arweave have no
native on-chain proposal system. MC's governance is deliberately
expensive (proposal fee), pays voters out of that fee, and records
every vote permanently on chain. Hive has a comparable system (HPS).

**Self-funding in perpetuity.** Arweave's endowment bets on storage
costs continuing to decline; if the trend stalls the fund runs dry.
Bastyon caps PKOIN issuance, narrowing the security budget toward
fees-only. Nostr has no native economy at all. MC's perpetual-issuance
+ fees model is unconditional.

---

MessageChain is what falls out of taking every promise seriously
simultaneously and refusing to trade any of them for short-term feature
velocity.
