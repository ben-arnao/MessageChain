# How MessageChain compares to nearby projects

Five projects share enough of MessageChain's design space — by mission,
functionality, or both — to be worth contrasting against. The matrix
below shows how each delivers on MC's core promises.

| Promise | MC | Hive | DeSo | Nostr | Bastyon | Arweave |
|---------|:--:|:----:|:----:|:-----:|:-------:|:-------:|
| Permanent on-chain payloads | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| Permissionless validator entry — no elected slate | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ |
| Slashable evidence for validator-collusion censorship | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Self-funding security in perpetuity | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| Disciplined scope — messages-only, no DeFi or programmability | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ |
| Crypto agility + identity continuity across key rotations | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |

## Why the gaps

**Permanent on-chain payloads.** A Nostr post exists only as long as at
least one relay still hosts it — relays delete, go offline, or get
coerced, and the protocol has no consensus layer to fall back on.

**Permissionless validator entry.** Hive's active block-producing set
is the top ~20 witnesses by stake-weighted vote. Becoming a block
producer means winning a popularity contest — exactly the failure mode
Justin Sun exploited in 2020 by buying Steemit's treasury and voting
his own slate into all 20 slots, forcing the Steem→Hive emergency fork.

**Slashable evidence for validator-collusion censorship.** No other
listed project has cryptographic slashing for "validator silently
dropped my tx" or "validator forged an invalid-signature rejection."
Their inclusion guarantees rest on majority honesty alone, with no
recourse if a minority colludes to suppress specific posts. MC has
three explicit evidence types plus a forced-inclusion list — collusion
produces provable misbehavior on chain.

**Self-funding security in perpetuity.** Arweave's endowment bets the
entire security budget on storage costs continuing to decline; if the
trend stalls, the fund runs dry. Bastyon caps PKOIN issuance, narrowing
the security budget toward fees-only on the long horizon. MC's
perpetual-issuance + fees model is unconditional.

**Disciplined scope.** DeSo bolted on creator coins, social tokens,
NFT minting, on-chain marketplaces, and on-chain games — drifting from
"decentralized social" toward "everything-app on a social graph." Hive
ships HBD (a stablecoin) and on-chain markets. Bastyon includes video
and richer media types. Each addition is regulatory exposure and attack
surface that messages-only avoids.

**Crypto agility + identity continuity.** Arweave's signing scheme is
fixed at the protocol level (RSA, set in 2018) — when the scheme
eventually breaks, identity migration has no native primitive. Nostr's
identity *is* the `nsec` key; lose it and the entity restarts from
zero. MC's signatures carry version/algorithm tags and key rotation is
a first-class transaction type, so an entity survives multiple
generations of cryptographic migration with full history intact.

---

MessageChain is what falls out of taking every promise seriously
simultaneously and refusing to trade any of them for short-term feature
velocity.
