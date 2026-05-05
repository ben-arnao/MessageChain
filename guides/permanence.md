# Permanence guarantees: archive duty and censorship resistance

> **The headline promise:** every message included on chain is
> stored, by every full node, forever — and validators that try to
> quietly drop or refuse a well-formed message can be slashed for
> doing it. "Permanent and uncensorable" is enforced at the
> protocol layer, not requested at the social layer.

There are two failure modes a permanent ledger can have, and most
projects only defend against one of them:

1. **Storage failure.** Nodes drop old data because keeping it is
   expensive or boring. The chain becomes a chain of *recent*
   history; ancient blocks rot away.
2. **Inclusion failure.** Validators collude to refuse to include
   specific messages in new blocks. The chain still has a perfect
   archive of *what they let in*, but disfavored content never gets
   recorded in the first place.

MessageChain treats both as protocol problems. Storage is enforced
by **archive duty**; inclusion is enforced by a stack of three
**evidence types** plus a **forced-inclusion mechanism** that lets
the validator set's honest minority overrule a colluding majority.

## Part 1: Archive duty — every full node carries the full history

A "full node" only means something if it actually stores the full
history. Nothing in classical consensus actually verifies that. A
validator can claim to be full-archival, accept the rewards for it,
and quietly retain only the last 10,000 blocks. By the time anyone
notices, the deleted history is gone from the network.

MessageChain's answer is to **regularly challenge validators to
prove they still have old data, and pay them when they do.**

### Archive challenge in one sentence

Every 100 blocks, the chain randomly picks 5 historical heights
from the entire chain history (with a strong bias toward old
blocks), and any validator that can produce a Merkle proof of a
specific transaction in each of those blocks gets paid.

### The mechanics

- **Challenge cadence:** every 100 blocks (`ARCHIVE_CHALLENGE_INTERVAL`).
  At each challenge, 5 distinct historical heights are derived from
  the issuing block's hash via VRF — unforgeable, identical for all
  validators.
- **Age-skew:** about half the heights are sampled uniformly across
  all of history; the other half are sampled from the **oldest 25%
  of blocks**. This is what forces validators to actually retain
  ancient data, not just last week's blocks.
- **Custody proof shape:** the validator submits the block header
  (hash + Merkle root), a randomly-selected transaction from that
  block, the Merkle inclusion path from the tx leaf to the root,
  and a WOTS+ signature binding the proof to the prover's identity
  (so a validator can't free-ride on a peer's proof).
- **Reward:** the first N valid proofs per challenge get paid out
  of an `ArchiveRewardPool` — a fund seeded by redirecting **25%
  of EIP-1559-style base-fee burn** into the archive pool instead
  of burning it. Storage is funded by the same fee market that
  pays for inclusion.
- **Miss handling:** if a validator misses an archive challenge,
  their next block reward is proportionally withheld. Persistent
  missers see an escalating withhold percentage. Streaks of
  consecutive successful epochs slowly decay the miss count back
  down — recovering from a brief outage is straightforward.
- **Bootstrap grace:** brand-new validators are exempt from archive
  duty for their first 1,000 blocks of life, since they need time
  to backfill historical state.

### Why first-come-first-served, not all-or-nothing

The archive reward pool is a fixed-size budget per challenge. If
every validator could claim the full reward, paying out would scale
linearly with set size and exhaust the pool. The first-come-first-
served structure caps total payout per challenge while still giving
every honest archival node a real chance of winning the race over
time. The biased sampling toward ancient blocks ensures the only
way to consistently win that race is to actually carry the full
archive.

## Part 2: Forced inclusion — a colluding proposer can't censor

The censorship threat in MessageChain is **validator collusion**: a
subset of validators conspiring (or being coerced) to refuse to
include or attest to specific messages. Defenses scale up
accordingly: the protocol shouldn't just rely on the proposer's
goodwill, and shouldn't even rely on a single honest proposer
showing up next block.

### Layer 1: the inclusion list (consensus-objective)

When ≥ 2/3 of active validators independently report holding a
particular pending tx for several blocks running, the next block
proposer is **required** to include that tx (or one of a small
sorted list of such txs).

In practice:

- Each attester gossips its own mempool snapshot.
- The block proposer aggregates ≥ 2/3 stake-weighted reports into
  a published `InclusionList` of up to 64 txs, applied to the
  next ~4 blocks.
- If a subsequent proposer omits a mandated tx without a structural
  excuse (block byte budget exhausted, tx-count cap reached, tx
  no longer valid under current state), other nodes submit an
  `InclusionListViolationEvidence` tx and the offending proposer
  is slashed.

This is the heaviest mechanism: it requires supermajority
coordination, which makes it slower, but the resulting mandate is
unforgeable. A colluding minority cannot block a 2/3-supported tx
from inclusion.

### Layer 2: forced-inclusion (attester-subjective)

Below the 2/3 threshold, individual attesters still have leverage.
Each attester maintains their own forced-inclusion set — the top 5
txs by fee-per-byte that they've held in their mempool for at least
3 blocks. If a block omits any of those without a structural
excuse, the attester votes **no** on that block.

This means a single honest validator's mempool view is enough to
force a no-vote on a block that ignores high-fee txs sitting in the
network. Combined with attestation thresholds for finality, this
is the "one honest validator is enough" lower bound for censorship
resistance.

### Layer 3: evidence types — proving a silent drop

There are three transactions a node can submit to prove a
validator misbehaved on inclusion:

#### Censorship evidence (proven silent drop after a receipt)

If a sender obtained a `SubmissionReceipt` from a validator
(promising to include the tx), and the tx never lands on chain
within a window of blocks, anyone can submit a
`CensorshipEvidenceTx`. The validator that issued the receipt is
slashed **10% of stake at receipt time** (snapshotting prevents
unstake-and-evade). The slashed amount is **burned** to prevent
the evidence-submission market from becoming a griefing vector.

#### Non-response evidence (proven silent TCP drop)

For an extra fee, a sender can opt into a witnessed submission
flow where the request is gossiped to a witness topic. Peers sign
attestations that the gossip happened. If the validator never
responds (with either an ack or a rejection) by a deadline, three
or more witness attestations bundled into a `NonResponseEvidenceTx`
slash the validator **5% of stake**, also burned.

This catches the "I'll just close the TCP connection without
acknowledging the request" attack — the validator never even
*claims* to have seen the tx, but witnesses can prove they did.

#### Bogus rejection evidence (proven false "invalid sig")

If a validator returns a `SignedRejection` claiming a tx had an
invalid signature, but the signature actually verifies under the
sender's on-chain public key, anyone can submit a
`BogusRejectionEvidenceTx`. The chain re-verifies the signature; if
it passes, the rejection was forged → validator is slashed **10%
of stake** immediately. If it fails, the rejection was honest and
no slash applies.

This closes the "we're not censoring you, your signature is just
bad" exit route. The chain has the public key and can check.

### The combined picture

A validator that wants to censor a message has to choose between:

- **Including it** (defeats the censorship goal).
- **Silently dropping it** → exposed by witness observations →
  slashed.
- **Issuing a receipt and dropping it** → exposed by the absence of
  the tx on chain → slashed.
- **Forging an "invalid sig" rejection** → exposed by re-verifying
  on chain → slashed.
- **Refusing to attest a block that included it** → moves the
  problem to the next block; if 2/3 reports it, an inclusion list
  forces it; if even one honest validator holds it, attestation
  pressure forces a no-vote.

There is no clean censorship path that doesn't either (a) fail
because the message got included anyway, or (b) generate
slashable evidence. The only remaining attack is **a colluding
≥ 2/3 of validators willing to absorb the slashing risk**, which
is — by design — the heaviest possible threshold.

## Part 3: Why this matters together

Storage permanence and inclusion permanence are two sides of the
same promise. A chain with perfect inclusion but rotting storage
becomes a chain of rumors. A chain with perfect storage but
trivial censorship becomes a chain of curated propaganda.

MessageChain's design tries to make both *expensive to attack*:

| Attack vector | Defense |
|---------------|---------|
| Validator drops old blocks | Archive challenges + reward |
| Validator silently drops a new tx | Witness evidence → slash |
| Validator pretends a tx is invalid | Signature re-check → slash |
| Validator omits a tx after issuing a receipt | Censorship evidence → slash |
| Validator omits a high-fee tx | Attester-subjective forced inclusion → no-vote on the block |
| Coordinated validator suppression | Quorum-signed inclusion list (≥ 2/3) overrules proposer |

Each mechanism is independent. Each one has its own slashing
trigger. None requires the user being censored to even know they're
being censored — the network's other validators carry the
detection and the evidence.

## Activation status

- **Witness separation** (a related storage feature, separate from
  archive duty itself) activates at block 3,000 and lets full nodes
  delegate signature bytes to witness-archive nodes after finality
  + 200 blocks.
- **Archive challenges** are active on mainnet today.
- **Forced-inclusion lists, censorship evidence, non-response
  evidence, bogus-rejection evidence** are all active on mainnet
  today.

## Summary

The "your message can never be deleted" promise has two halves, and
MessageChain enforces both:

- **The chain that has your message will keep your message** —
  enforced by archive challenges that pay validators to retain
  ancient data and slash them (via reward withholding) when they
  don't.
- **The chain will accept your message in the first place** —
  enforced by forced-inclusion lists, attester-subjective
  inclusion duties, and three flavors of slashable evidence for
  validators caught silently dropping or falsely rejecting txs.

Together, these turn permanence and censorship-resistance from
slogans into protocol invariants — properties that hold by
construction, not by goodwill.

## Further reading

- [Anti-bloat: keeping the chain small enough to run forever](./anti-bloat.md)
  — the *cost* side of the permanence promise: how the chain stays
  small enough that "every node carries the full history" stays
  realistic.
- [Forum primitives](./forum-primitives.md) — what's actually being
  made permanent (messages, replies, votes, communities).
