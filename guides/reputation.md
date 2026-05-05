# Reputation primitive

> **The shape:** the protocol stores a **flat, raw graph of trust and
> flag votes** between users. It does not compute a "weighted
> reputation score." That weighting — whose endorsements count for
> more, whose flags should be ignored, what the threshold for "good
> standing" is — is left to apps, indexers, and L2 layers building on
> top.

A reputation system that tries to do everything at the protocol
layer always ends up baking one project's idea of "good user" into
consensus forever. MessageChain takes the opposite approach: keep
the *primitive* simple and on chain, leave the *interpretation* to
whoever wants to ship a UI on top. Different communities can ship
different reputation models against the same on-chain graph,
without having to fight each other for a single canonical score.

## The on-chain primitive

There is one transaction type that drives the reputation system:
the **React** transaction. It comes in two flavors:

- **`react <message_tx_hash> --choice up | down | clear`** — votes
  on a message.
- **`react <entity_id> --target-type user --choice up | down | clear`**
  — votes on a *user* (an entity).

For user-targeted reactions:

- `--choice up` = **trust / vouch.** "I think this user is
  legitimate."
- `--choice down` = **flag.** "I think this user is bad faith."
- `--choice clear` = **retract.** Wipe my prior trust or flag.

Each `(voter, target)` pair has exactly one **latest** choice in
consensus state. Re-voting supersedes the prior choice. The earlier
votes are still in the chain history (everything is permanent), but
only the latest counts toward the live aggregate.

**Self-trust is rejected.** You cannot vouch for yourself. The
chain validates this both at tx creation and at apply time.

## Skin in the game: trust and flags cost

A trust or flag vote is **a real transaction with a real fee**. Same
fee model as a message. There are no free votes and no free flags —
the cost-of-spam logic that protects the message layer protects the
reputation layer too.

This matters more than it sounds:

- A botnet trying to brigade an account's score has to pay for every
  vote.
- A user issuing a trust signal is putting a (small but non-zero)
  amount of token weight behind their claim. Trust isn't infinite
  and free — it's earned by the recipient and *spent* by the
  voucher.
- A vendetta flagger who flags 10,000 strangers has to pay 10,000
  fees. The economic cost of bulk action is the natural rate-limit.

The fee floor is the same `MARKET_FEE_FLOOR` (1 token) post-Tier-18
that applies to any tx — modest enough that legitimate users can
participate freely, painful enough that adversarial scale loses to
the math.

## What's stored on chain

The chain records:

- `(voter_id, target_id, choice)` triples — the raw graph.
- A denormalized **count** per target — `_user_trust_score` is a
  running sum of (UP votes) − (DOWN votes) from distinct voters,
  capped at `REPUTATION_CAP = 10,000`.

That's it. The chain stores **flat, equally-weighted votes**. There
is no per-voter weighting at the protocol level — a vote from a
brand-new wallet and a vote from a 5-year-old high-stake validator
are *both* counted as +1 in the on-chain tally.

That sounds unsophisticated, and intentionally so. The richer
reputation logic — "trust from already-trusted users matters more,"
"stake-weighted endorsements," "transitive trust to N hops," "decay
trust signals over time" — is **not** in the protocol. The protocol
just records the underlying votes; everything else is L2.

## Why protocol stays minimal

Three reasons:

1. **Reputation models are political.** Whose endorsement should
   count more? A high-stake validator's? A long-tenured user's? An
   L2 sub-community's appointed moderators'? Different apps will
   answer this differently, and the protocol shouldn't pick the
   winner.
2. **Reputation models evolve.** The right answer in 2026 is not
   the right answer in 2046. Bolting a specific weighting scheme
   into consensus would require a hard fork every time anyone
   wanted to iterate on it.
3. **Reputation models break.** Sybil attacks, coordinated
   downvotes, vote-trading rings — every weighting scheme has
   adversaries. Keeping the weighting at the app layer means
   attacks are *contained* at the app layer; they don't leak into
   consensus.

The flat graph in consensus is the **public ground truth** that all
apps build on. They can disagree about who matters; they can't
disagree about who voted for whom.

## What apps can build on top

A few examples of richer reputation systems that fit cleanly on top
of the primitive:

- **Web-of-trust.** Pull the raw vote graph, compute transitive
  trust from a set of seed accounts you personally trust, weight
  endorsements by graph distance.
- **Stake-weighted reputation.** Weigh each endorsement by the
  voter's stake at the moment of the vote — useful for validator
  reputation in particular.
- **Time-decayed reputation.** Old endorsements count less; recent
  ones count more.
- **Per-community reputation.** Combine the trust graph with the
  community-id field on messages — "users trusted by this
  community's regulars" is a valid scoping.
- **Mod-team reputation.** A community designates a small mod team;
  flags from mods carry more weight inside that community than
  flags from random accounts.
- **Skin-in-the-game amplification.** Endorsements from accounts
  that have themselves received many endorsements count more — the
  "trust from trusted users matters more" pattern, computed off
  chain.

All of these are pure functions of `(raw vote graph, optional stake
data, optional community membership)`. The chain hands you the
inputs; the app picks the function.

## Operator honesty (separate concept)

Don't confuse the user-trust primitive with **operator honesty** —
they're different systems:

- **User trust** (this guide): per-pair UP / DOWN / CLEAR votes
  between entities, fee-paid, raw-counted.
- **Operator honesty:** an internal-to-consensus track record of
  validator behavior — block proposals signed correctly,
  attestations accepted on chain, etc. Used by the **slashing**
  system to decide leniency on ambiguous evidence (a long-tenured
  honest validator gets a smaller penalty for borderline incidents
  than a brand-new validator).

Operator honesty is invisible to social UX; it just shapes how the
protocol treats validators when something goes wrong. User trust is
the social layer.

## Summary

The MessageChain reputation primitive is:

- **Two-target React tx** (message or user) with three choices (up,
  down, clear).
- **Latest-vote-wins** in consensus state, with the full history
  recorded permanently.
- **Fee-paid** — skin in the game, no free trust, no free flags.
- **Self-trust rejected.**
- **Flat, equal-weight** at the protocol layer; no built-in
  weighting by stake, age, or transitivity.

That intentional minimalism is the point. The protocol's job is to
record who said what about whom; the interpretation belongs to
whatever app or community is reading the graph. Build the
reputation system you want, on top of a permanent, tamper-proof,
spam-resistant set of underlying votes that nobody — not even the
project — gets to delete or rewrite.

## Further reading

- [Forum primitives](./forum-primitives.md) — the same React tx
  also drives up/down voting on individual messages, replies via
  `prev` pointers, and the `community-id` tagging primitive.
- [Governance: expensive proposals, permanent record](./governance.md)
  — the protocol-level voting system, distinct from the social
  reputation layer described here. Different mechanism, different
  purpose, but the same "permanent record + paid participation"
  shape.
