# Forum primitives

> **The shape:** a small, tightly-scoped set of on-chain primitives
> that any app, indexer, or front-end can reassemble into a public
> forum. Replies, votes, communities, long-form threads — all
> recorded once, permanently, on the base chain. Render them
> however you want.

Most "decentralized social" projects make a tradeoff: either the
underlying primitives are so generic that you have to build the
whole forum yourself, or they're so opinionated that you're locked
into one project's idea of what a "post" looks like. MessageChain
aims for the middle: enough structure on chain that a basic public
forum is implementable straightforwardly, no more.

The primitives — all of them — fit on one page.

## 1. The message

The base unit. Up to **1024 UTF-8 bytes** of human-readable text,
signed by the sender's key, included in a block by validators,
permanent forever.

```bash
messagechain send "hello world"
messagechain send "привет, мир"
messagechain send "你好，世界"
```

Plaintext is NFC-normalized UTF-8 in the Unicode Letter / Mark /
Number / Punctuation / Space-separator categories — every modern
written language is a first-class citizen. ASCII English fits 1024
characters; CJK or Devanagari content fits about a third of that
character count for the same byte budget. The chain prices stored
bytes uniformly, so each user pays per byte for the permanence they
actually pin.

Anything longer than the byte cap has to be split into multiple
messages and chained (see *long-form threads* below).

That's it. There's no separate "post" type, "comment" type, or
"thread" type. Everything in MessageChain is a message; structure
is built from optional pointer fields described below.

## 2. The `prev` pointer — replies and threads

Every message tx carries an optional `prev` field: a 32-byte
reference to the `tx_hash` of an earlier message. Apps render this
as a **reply**.

```bash
messagechain send "good point" --prev <tx_hash>
```

Rules the protocol enforces:

- A `prev` value must reference an actual on-chain message.
- The referenced message must be in a **strictly earlier block**
  than the reply — same-block self-replies aren't allowed.
- A message cannot reference itself.

Beyond those rules, `prev` is just a pointer. Apps decide what to do
with it:

- **Threading view.** Render replies as a tree under the message
  they reference.
- **Citation.** A "according to <prev>, …" UX, like a quote-tweet.
- **Long-form threads** (see next section).

`prev` bytes do count against the per-stored-byte fee — you pay for
the pointer like you pay for any other byte. But they do **not**
count against the 1024-byte message-content cap. Pointer is
structural metadata; message text is content.

## 3. Long-form threads

Since each message tops out at 1024 bytes of body text, "write a
5,000-word essay" is implemented by splitting the essay into chunks
that fit the cap and chaining them with `prev`:

```
[essay part 1]                      ←  block N
[essay part 2, prev=part1]          ←  block N+1
[essay part 3, prev=part2]          ←  block N+2
…
```

The chain enforces "prev target must be in a strictly earlier
block," so each piece pays the block cadence — about 10 minutes
between pieces. That's intentional: long-form posting is a
different workflow than short-form posting, and the chain doesn't
pretend otherwise.

For most cases, a multi-block thread is overkill — a single 1024-
byte message says plenty. Long-form is there when it's needed.

## 4. Up/down votes on messages

The same React tx that drives the user-trust primitive (see
[reputation guide](./reputation.md)) also drives message-level
voting:

```bash
messagechain react <tx_hash> --choice up
messagechain react <tx_hash> --choice down
messagechain react <tx_hash> --choice clear   # retract
```

Properties:

- Each `(voter, message)` pair has exactly **one latest choice** in
  consensus state. Re-voting supersedes; `clear` retracts.
- Both prior and current votes are permanently recorded in chain
  history; only the latest counts toward the live aggregate.
- The chain stores a `_message_score` — a running sum where each
  UP vote contributes +1 and each DOWN vote contributes −1.
- Each vote is a fee-paid tx. Same anti-spam logic as messages.

What you build on top is up to you: pure score sort, "controversial"
sort (high engagement, mixed sign), threshold-collapse for
flagged-down content, etc. The chain hands you raw vote events; the
app turns them into a UI.

## 5. Communities — the `community_id` field

A message can optionally carry a `community_id`: a short, plain-text
handle that groups it with other messages under the same handle.

```bash
messagechain send "build report" --community-id mc-dev
messagechain send "rules question" --community-id offtopic
```

Constraints:

- **Charset:** lowercase ASCII letters, digits, `_` and `-`. First
  and last byte must be a letter or digit. Length 1–32.
- **No registry.** There is no on-chain "create community" tx. No
  one *owns* a community. Any valid handle is admissible from any
  sender, and the first user to post under a handle is just the
  first user — no claim semantics, no founder rights.
- **No protocol-level moderation.** Membership, kicks, bans,
  pinned posts, mod teams — all of that is app/indexer layer. The
  chain stores raw `(message, community_id)` associations and
  nothing else.

This deliberately mirrors the message-permanence model: anyone can
post anywhere, the chain doesn't filter. Apps that want curated
communities with moderation build that on top — same way Reddit
runs above DNS, not inside it.

The handle is part of the **signed payload**, so loosening the
admissible character set requires a new tx version. Strict-first
wins: it's easier to allow more characters in the future than to
take them back.

### What about non-ASCII community names?

Native-script community *names* (Chinese, Cyrillic, emoji) live at
the **app/L2 display layer** — exactly like a flat ASCII handle on
a mainstream platform mapping to a display name in any script. The
protocol-level handle is restricted to make homoglyph attacks
impossible at the consensus layer (no two visually-confusable
handles can exist simultaneously). Display names that map onto a
canonical ASCII handle are an app concern.

## 6. Tags — same field

There's no separate "tag" or "topic" field beyond `community_id`.
That's the entire categorical-tagging primitive. If you want
multiple categories on a single message, the chain's answer is:
post the message, send a follow-up under the second community,
link them with `prev`. That's by design — adding more index fields
is more bytes per message, more attack surface, and more complexity
that L2 can deliver instead.

## 7. Putting it together: what a forum gets, for free

| Forum feature | MessageChain primitive |
|---------------|------------------------|
| Post a message | A message tx |
| Reply to a post | `prev` pointer |
| Long-form post | Chained messages via `prev` (one per block) |
| Upvote / downvote | React tx, `target_type=message`, choice up/down |
| Retract a vote | React tx, choice clear |
| Subreddit-style topic | `community-id` handle |
| Vouch for a user | React tx, `target_type=user`, choice up |
| Flag a user | React tx, `target_type=user`, choice down |
| Permanent archive | The chain itself — every tx forever |

What a forum has to build itself, on top of these primitives:

- **Display.** How do you render a thread? A community page? Sort
  order on votes? That's UI.
- **Moderation.** Who can hide or de-rank a message in a given
  app's view? Front-ends are free to filter — the chain just won't
  *delete*.
- **Reputation weighting.** Whose votes count more? See the
  [reputation guide](./reputation.md) for the protocol-level
  primitive and what L2 can build with it.
- **Search and indexing.** Apps maintain their own full-text
  indexes off chain. The chain is a verification layer, not a
  search engine.

## 8. What's intentionally missing

- **No DMs.** Encryption is a strict no at the protocol level —
  every payload is fully public. (See CLAUDE.md.) Private messaging
  belongs at the app layer, on top of any encrypted transport you
  like. The chain is for *public* speech.
- **No edits.** A message included in a block is final. If you want
  to "edit" a post, you publish a new message and link it with
  `prev`; apps can render the latest revision. The original stays
  on chain forever.
- **No deletes.** This is the headline promise of the chain. Once
  in, always in.
- **No reposts.** A "repost" is a new message that references the
  original via `prev`. Apps can render those as boosts/RTs/quotes —
  there's no separate primitive.
- **No follows.** Following is a 100% client-side concept. Build a
  list of `entity_id`s you care about and filter the public
  message stream against it. The chain doesn't need to know who
  you read.
- **No images, no attachments.** Plain text only, capped at 1024
  UTF-8 bytes. Anything richer goes to L2 / off-chain hosting,
  referenced by URL inside the message body if you want it
  alongside.

## Summary

The full set of forum primitives:

- **One tx type for content** (message), with a 1024-byte UTF-8
  body, an optional `prev` pointer, and an optional `community-id`.
- **One tx type for reactions** (React), with two target flavors
  (message, user) and three choices (up, down, clear).
- **Permanent, on-chain, fee-paid, signed** — every one of them.

Out of those two transaction types, you can build replies,
threads, long-form essays, communities, voting, vouching, flagging,
reposts, quote-replies, and most of what people actually do on
public social platforms. The *protocol* is small; the *space of
applications* it makes possible is large.

## Further reading

- [Reputation primitive](./reputation.md) — the user-trust side of
  the React tx, and how richer reputation systems plug in on top.
- [Anti-bloat: keeping the chain small enough to run forever](./anti-bloat.md)
  — why messages are short and blocks are slow.
- [Permanence guarantees: archive duty and censorship resistance](./permanence.md)
  — the protocol-level mechanics that make "your message can never
  be deleted" actually enforceable.
