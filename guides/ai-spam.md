# Combating AI spam and generated content

> **The thesis:** there is no way to keep machine-generated text
> *off* a permissionless public ledger, and any project that
> claims otherwise is selling something. What you *can* do is make
> bulk machine-generated content uneconomical at the protocol
> layer, and give applications enough on-chain primitives to
> filter out what slips through. MessageChain attacks the problem
> from both ends: a real fee floor that bots have to pay like
> everyone else, plus a permanent reputation graph that lets
> humans amplify humans.

A short pre-emptive disclaimer, because this is the area people
have the strongest priors on:

- **The chain does not try to detect "AI vs. human" content.** It
  can't. No one can. Any classifier you build today is wrong
  tomorrow, any classifier in protocol consensus locks in one
  era's idea of "real writing" forever, and any heuristic that
  works *now* is just a moat for whichever model can next bypass
  it.
- **The chain does not have a content blocklist.** Permanence is
  the headline promise; selective admission would defeat it.
- **The chain does not have proof-of-human, captchas, or KYC.**
  Identity gates create either a trusted gatekeeper (defeats
  permissionlessness) or a botnet's favorite attack surface
  (defeats the goal).

What the chain *does* have is two compounding mechanisms — one
economic, one social — that together change the *economics* of
machine-generated speech, without ever asking "is this human?"

## The two levers

### 1. The cost floor: machines pay too

Every message on chain costs **real tokens**. The fee scales
linearly with stored bytes (see [Fees: how pricing actually
works](./fees.md)). There's a flat per-tx admission floor of
1,000 tokens — explicitly designed as a spam gate, not a market
price — and a per-byte component above it.

This is the same fee everyone pays. A human posting "happy
birthday" pays it. A bot posting "happy birthday" pays it. There
is no human discount and no machine surcharge. **Equality of cost
is the point.**

The lever is: at *some* per-message price, bulk machine-generated
posting stops being economically attractive relative to whatever
the bot was hoping to extract from the message (engagement
farming, propaganda, link-laundering, scam recruitment). The
chain doesn't have to set that price by guessing — the fee
*floor* keeps zero-cost spam impossible, and the **fee market
above the floor** sets the rest.

A few properties that follow:

- **The floor is denominated in tokens, but its real meaning is
  set by the token's market price.** If MessageChain's token
  trades at $0.10, posting a message costs ~$100 at floor —
  brutal for short messages, *aggressively* anti-spam. If the
  token trades at $0.0001, posting a message costs ~$0.10 —
  spammable. The chain doesn't optimize the floor for any
  particular price level; it relies on the token having *some*
  real market value, which is what the
  ["dual-purpose token" anchor](../CLAUDE.md) commits to. The
  token has to be *tradable* for the fee to *mean* anything.
- **The fee is not refunded.** Burned bytes are burned. A bot
  flooding the chain with low-quality content is destroying
  its own treasury into the base-fee burn — the chain literally
  consumes the economic resource being used to attack it.
- **The fee scales with congestion.** When blocks fill, the
  EIP-1559 base fee rises, the burn portion grows, and every
  message becomes more expensive. A bot escalating volume *makes
  the cost of escalating volume go up*. There is no "spray cheap
  during peak hours" attack; peak hours are when spraying is
  most expensive.

The cost floor doesn't stop a determined, well-funded actor from
posting AI-generated content one message at a time — and it
shouldn't have to. What it does stop is **the bulk economics**:
the "spin up 10,000 bots and flood the public square" attack
that's killing every mainstream platform. At the protocol-level
fee schedule, that attack costs orders of magnitude more on
MessageChain than on any free-to-post platform.

The mainstream platforms made a different bet: free posting +
content moderation. The bet failed because moderation doesn't
scale against generative AI, and free posting subsidizes the
attacker. MessageChain's bet is the inverse: **paid posting + no
moderation**. If the cost is real, the volume is bounded by the
attacker's willingness to spend.

### 2. The reputation primitive: humans amplify humans

The cost floor changes the *economics* of bulk spam. The
[reputation primitive](./reputation.md) changes the *visibility*
of whatever slips through.

The protocol stores a permanent, on-chain graph of trust and flag
votes between entities. Anyone can `react --target-type user
--choice up` (vouch for a user) or `--choice down` (flag them),
both as fee-paid transactions. The chain stores the raw graph;
apps and L2s build the weighting on top.

What this enables:

- **Trust-amplified feeds.** A reading app shows you, by default,
  messages from entities trusted (transitively or directly) by
  people *you* trust. A bot has to either earn legitimate trust
  signals from humans (very expensive, since each signal is a
  paid tx from a real entity) or be invisible in trust-weighted
  views.
- **Flag-deprioritized feeds.** Entities flagged by enough trusted
  humans drop down or out of trust-weighted feeds. The chain
  doesn't *delete* them — the message is permanent — but it
  doesn't *promote* them either, and apps that read the graph
  can render them however they want.
- **No global authority over either.** The chain doesn't ship a
  blessed reputation algorithm, doesn't bless a particular
  community's mod team, doesn't endorse any specific filter. Each
  application picks its own weighting and its own seed set of
  trusted users. Different communities can disagree about who's
  legitimate, and that disagreement lives in app space, not in
  consensus.

This matters specifically against AI spam because:

- **Sybil attacks against the reputation graph cost real tokens.**
  Spinning up 10,000 fake-trust entities, paying the per-tx fee
  for each, and then having them vouch for each other is a
  detectable pattern — they form an isolated subgraph with no
  edges *into* it from real long-tenured users. Trust algorithms
  on top of the graph are free to weight transitive trust by
  graph distance to a seed of known-real users.
- **The cost compounds.** A bot has to (a) pay the fee floor for
  every message it posts, and (b) earn legitimate trust edges
  to be visible at all in trust-weighted feeds. Those are
  *multiplicative* costs, not additive — and the second one is
  the harder problem, because trust comes from real humans
  vouching, not from money.

## What this is NOT

- **Not detection.** The chain has no opinion on whether a given
  message is AI-generated. It doesn't try; it *can't*; it
  shouldn't.
- **Not deletion.** A spammy or AI-generated message that lands
  on chain is on chain forever. Apps can hide it; the chain
  can't.
- **Not a perfect filter.** A motivated, well-funded attacker can
  buy tokens, post genuine-looking content one message at a time,
  cultivate trust connections over years, and infiltrate
  trust-weighted feeds. This is true of any system. The goal isn't
  "zero AI spam ever" — it's "make bulk spam economically
  unattractive, and give humans the on-chain primitives to
  amplify each other above the noise."
- **Not a moderation layer.** The chain itself doesn't moderate.
  Moderation is an app/L2 concern, the same way moderation on top
  of email is the inbox provider's job, not SMTP's.

## The compounding picture

The two mechanisms compound in interesting ways:

- **The cost floor sets a permanent attack tax.** Every spam
  message is a small token donation to the burn pool. The
  attacker is, mechanically, paying the network for the privilege
  of being on it.
- **The reputation graph sets a visibility tax.** Even if an
  attacker pays the cost floor at scale, their messages don't
  *reach* trust-weighted feeds without earning trust edges first.
  The cost of being *seen* compounds on top of the cost of being
  *included*.
- **Both costs are denominated in real economic value.** Token
  fees are a real cost. Trust edges from real humans are a real
  cost (real humans don't vouch for bots in volume; if they do,
  they get flagged themselves and lose their own trust weight).
  There is no botnet-cheap way around either.

Compare to the failure modes on free public platforms:

| Lever | Free platforms | MessageChain |
|-------|---------------|--------------|
| Cost to post | Zero | Real, denominated in tradable tokens |
| Cost to scale spam volume | Linear-ish in CPU/bandwidth (cheap) | Linear in token spend (expensive at any token price) |
| Cost to be visible | Zero (recommendation algorithm picks up engagement) | Trust edges from real humans (slow to acquire, slashable to fake) |
| Moderation | Centralized, unscalable, politically captured | Decentralized, app-layer, no global gate |
| Spam tax | Paid by the platform's users in attention | Paid by the spammer in burned tokens |

The bet is that **the second column scales worse than the first
column under generative AI pressure**. Mainstream platforms are
already losing this fight. MessageChain's structure — paid posts,
permanent record, on-chain reputation primitives, app-layer
filtering — is designed to *not* lose it.

## What about the determined attacker?

Every honest design discussion has to address this. There's no
mechanism that defeats a state-funded adversary willing to spend
millions of dollars per month posting genuine-looking AI content
through real-looking entities. MessageChain doesn't claim to.

What MessageChain *does* claim:

- **The floor takes the casual attacker out.** A college kid with
  an OpenAI key and 3 hours of time can ruin a free public
  platform. They cannot meaningfully attack MessageChain at
  scale, because they can't afford the fee tab.
- **The floor scales the cost of bulk attacks.** The
  organization-level attack stops being "post millions of
  messages" and starts being "post a few hundred high-quality
  messages." The attack surface narrows from "drown the network"
  to "compete on quality with humans," which is the same playing
  field humans are already on.
- **Reputation drains attacker value over time.** Even if the
  attacker breaks through with 100 high-quality posts, the
  permanent record means a month later — when the
  account-cluster's pattern becomes obvious — humans can flag,
  apps can deweight, and the attacker's invested cost is sunk
  with no ongoing yield.

The protocol is the *floor*, not the *ceiling*, of anti-spam
defense. Apps and L2s build on top. But every layer above
inherits the protocol's economic and social discipline, and that
discipline is what makes the rest work.

## The single-sentence summary

MessageChain doesn't try to keep AI off the chain. It tries to
make AI spam *cost more than it earns*, and it tries to give
humans *durable on-chain primitives* to find each other above the
noise. The first job is done by the fee floor and the
EIP-1559-style burn; the second job is done by the reputation
graph and the apps that read it.

If the token has real economic value, the floor bites. If humans
keep showing up and vouching for each other, the reputation
graph bites. Both are necessary. Neither is sufficient alone.

## Further reading

- [Fees: how pricing actually works](./fees.md) — the economic
  half of the anti-spam thesis, in detail.
- [Reputation primitive](./reputation.md) — the social half. What
  the protocol stores, what L2 can build on top.
- [Forum primitives](./forum-primitives.md) — up/down voting on
  individual messages, the second-by-second tool for surfacing
  good content above the noise.
- [Anti-bloat: keeping the chain small enough to run forever](./anti-bloat.md)
  — the related but distinct concern of keeping AI-generated
  *volume* from blowing up storage. Same fee model, slightly
  different lens.
