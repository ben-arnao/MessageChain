# Quantum resistance and WOTS+

> **The bet:** today's elliptic-curve signatures will eventually
> fall to a sufficiently large quantum computer, possibly within
> the lifetime of this chain. Hash-based signatures (the family
> WOTS+ belongs to) rely only on the difficulty of inverting hash
> functions, which is not meaningfully threatened by quantum
> attacks. MessageChain signs with WOTS+ from day one — and pairs
> it with a versioned signature scheme so a future migration is a
> rotation tx, not a fork-and-abandon.

A blockchain that's supposed to last centuries can't punt on the
quantum question. ECDSA, EdDSA, and Schnorr — the signature
families most chains use today — all rely on the discrete-
logarithm or factoring assumption, both of which Shor's algorithm
breaks polynomially. Estimates of when a cryptographically-
relevant quantum computer arrives range from "soon" to "never,"
but a permanent ledger doesn't get to bet on "never."

MessageChain's design takes the conservative path: hash-based
signatures, version-tagged, with rotation as the migration
mechanism.

## Why hash-based signatures

Hash-based signatures (Lamport, Winternitz, WOTS+, XMSS, SPHINCS+,
etc.) build their security entirely on the **one-way property of
cryptographic hash functions**:

- An attacker with the public key can't derive the private key
  unless they can invert the hash.
- Quantum computers don't break hash inversion polynomially.
  Grover's algorithm gives a square-root speedup at best —
  256-bit hashes lose ~128 bits of preimage resistance, which is
  still well above any practical attack threshold.

Compare to elliptic-curve signatures: a sufficiently large quantum
computer running Shor's algorithm derives the private key from the
public key in polynomial time. A chain whose entire history is
verified by ECDSA signatures becomes retroactively forgeable on
that day.

The cost of choosing hash-based: signatures are bigger (kilobytes
instead of tens of bytes), and each signing key has a finite
budget of signatures. MessageChain's storage and rotation design
absorb that cost (see below).

## What WOTS+ actually is

WOTS+ ("Winternitz One-Time Signature, plus") is a one-time-use
signature: each public/private key pair can sign **exactly one
message** before the security degrades. To sign more than one
message, you build a **Merkle tree** of WOTS+ public keys (one per
leaf), publish the root as your effective public key, and use a
fresh leaf for each signature.

The relevant numbers in MessageChain:

- **Tree height:** 20 by default (`MERKLE_TREE_HEIGHT = 20`).
- **Signatures per keypair:** 2²⁰ = **1,048,576** signatures.
- **One signature consumes one leaf**, permanently. Reusing a leaf
  reveals the underlying WOTS+ private key and is detected by the
  chain as **equivocation**.

A million signatures sounds like a lot, but a busy validator
proposing and attesting on every block burns through them faster
than you'd expect. A casual user posting messages will essentially
never run out.

## The leaf consumption problem

Every signature you sign — every message you post, every transfer
you send, every attestation a validator submits — uses up exactly
one leaf. Once a leaf is used, it can never be used again, and
the chain enforces this:

- The CLI tracks the next-safe leaf in a small **cursor file**
  (`leaf_index.json`), advanced atomically before each signature.
- The chain records a per-entity high-water-mark in consensus
  state.
- A signature at any leaf at-or-below the high-water-mark is
  rejected as a re-use attempt — and worse, generates **slashable
  equivocation evidence**, since re-signing at the same leaf
  mathematically discloses the WOTS+ private key for that leaf.

This is why the leaf cursor is **load-bearing for validators**.
Restoring a keyfile from backup *without* the matching cursor
state causes the validator to start signing at leaves it already
burned, producing many equivocation events. Under the soft-slash
regime each offense is 5% of stake; bulk reuse compounds toward
total loss.

For everyday users using the CLI online, the cursor is rebuilt
from chain state on restore. Online wallets just need the seed
phrase. Offline-signing power users (air-gapped signers) need to
move the cursor with their keyfile — the CLI's `backup-wallet`
command bundles them together.

## Auto-rotation: refilling the well

When a keypair runs low on leaves, you rotate to a fresh keypair
— same identity, new signing key, fresh tree of 2²⁰ leaves.

The default validator setup auto-rotates at **≥95% leaf
consumption**:

- The daily watchdog reads `messagechain key-status` to compute
  consumption.
- At 80% it logs a warning.
- At 95% it triggers a `key-rotation` tx automatically, signed by
  the soon-to-retire key.
- The chain accepts the rotation, records it in `key_history`,
  resets the leaf cursor for the new key, and the validator
  resumes signing under the new key on the next block.

You don't have to babysit this. The defaults are sensible. But
it's worth understanding what's happening — it explains why
`key-status` exists, why backup procedures emphasize the cursor,
and why there's a fixed `KEY_ROTATION_FEE = 1000` in the fee
schedule (rotations are routine, not exceptional).

## Versioned signature schemes

MessageChain signs every transaction with a 1-byte **signature
version tag** (`sig_version`), committed into the transaction's
signed data. Today's tag is `SIG_VERSION_WOTS_W16_K64_V2 = 2`,
encoding the specific WOTS+ parameters in use:

- `W16`: Winternitz parameter 16
- `K64`: 64 hash chains
- `V2`: the second iteration of the encoding (V1 was retired
  during the bootstrap phase)

The protocol's **acceptance set** is the set of valid sig versions
at a given height. Today: `{V2}`. Anything else is rejected.

When a successor scheme is needed — because the current one
weakens, because a stronger scheme is invented, or because
post-quantum standards evolve — the migration path is clean:

1. **Governance proposes** introducing a new scheme — call it `V3`
   (could be a tightened WOTS+, or a stateless hash-based scheme
   like SPHINCS+, or whatever the post-quantum standardization
   process settles on).
2. **A hard fork widens the acceptance set** to `{V2, V3}` for a
   transition window.
3. **Existing entities rotate** to V3 keys via the normal
   `key-rotation` tx — the rotation says "old key was V2, new key
   is V3." Same entity_id, same balances, same history.
4. **Eventually the acceptance set narrows** to `{V3}`, and V2
   signatures stop being valid for new txs (existing V2 signatures
   on past txs remain valid for verification of historical state).

The transition is entity-by-entity, gated by individual rotation
choices. Nobody's stuck. Nobody loses their identity. And the
chain doesn't have to do a forklift upgrade — it just adds a new
acceptable version, and the natural flow of rotations migrates the
network over a transition window.

## Why this matters in practice

Three things shake out from this design:

### 1. Today's signatures will still be verifiable in 2126

Even when WOTS+ V2 is retired from the acceptance set for *new*
txs, the historical signatures on past blocks remain
mathematically valid. A node syncing the chain in 2126 will still
verify a 2026 signature using whatever scheme it was signed under,
because the signature carries its version tag and the verifier
knows how to interpret each version.

This is what makes the permanence guarantee actually durable.
"Your message can never be deleted" only means something if the
signature on that message can still be verified a century later
— even after the underlying signature scheme has been retired
for new use.

### 2. The migration is a rotation, not a re-creation

Crypto migrations on chains without versioned signatures are
brutal: announce a deadline, force every user to move balances to
a new account on the new chain, leave behind whatever doesn't
migrate. Reputation, message history, threading, all of it gets
abandoned at the cutover.

MessageChain's rotation-as-migration design avoids this. You stay
the same entity through the transition. Your messages from before
the migration are still your messages. Your trust votes are still
your trust votes. Your validator stake is still your stake. The
key changed; you didn't.

### 3. There's no "quantum break" timeline pressure

Some PoS chains plan to migrate to post-quantum schemes if and
when a threat materializes — but until then, they're
single-scheme. If the threat materializes faster than the
migration, history that was already signed under the old scheme
is retroactively forgeable.

MessageChain signs with hash-based signatures from day one. There
is no "before quantum" and "after quantum" segment of the chain.
History as far back as genesis is signed with a scheme that
survives the threat. The version tag exists to handle *future*
weakenings (a new attack on WOTS+ specifically, a stronger scheme
that's just better, etc.) — not to bridge a known transition.

## Caveats and honest limits

A few things this design does *not* claim:

- **WOTS+ is not a panacea.** Hash-based signatures are
  conservative, not bulletproof. If a fundamental break in
  cryptographic hash functions arrives, MessageChain (and
  essentially every other chain) is in trouble. Hash inversion is
  a much weaker target for quantum attacks than discrete log, but
  "much weaker" isn't "zero."
- **Post-quantum standardization is ongoing.** NIST's post-quantum
  process has moved hash-based signatures (SPHINCS+) into its
  standards portfolio, but the field is still evolving. The
  versioned-scheme design exists precisely so we can adopt
  standards as they mature, rather than locking in today's choice
  forever.
- **Signatures are bigger.** A WOTS+ signature is roughly 2.7 KB
  — much larger than ECDSA's 64 bytes. This is the storage cost of
  quantum resistance, and MessageChain manages it with witness
  separation (see [anti-bloat guide](./anti-bloat.md)) — moving
  signature bytes out of the main chain after finality so the
  bytes everyone has to keep forever stay manageable.
- **Leaf budgets are finite.** A million-leaf tree is plenty for a
  user, generous for a validator, and not infinite. Auto-rotation
  is essential, not optional.

## Summary

| Property | What MessageChain does |
|----------|-----------------------|
| Signature family | Hash-based (WOTS+) — quantum-resistant |
| Signatures per keypair | ~1 million (Merkle tree of height 20) |
| Leaf reuse | Detected on chain, slashable as equivocation |
| Auto-rotation trigger | ≥95% leaf consumption (validator default) |
| Sig version tag | 1 byte, committed into every signed tx |
| Migration to a future scheme | Hard-fork widens acceptance set; entities rotate via the existing key-rotation tx |
| Historical signatures | Remain verifiable forever, under their original scheme |

The whole point: when (not if) the cryptographic ground shifts
underneath us, MessageChain doesn't need a forklift upgrade or a
"v2 chain" — it just rotates, and history is preserved.

## Further reading

- [Identity, keys, and rotation](./identity.md) — the operational
  side of all of this. How rotation works as a tx, what the cold
  authority key adds, what happens when keys are lost.
- [Anti-bloat: keeping the chain small enough to run forever](./anti-bloat.md)
  — including witness separation, which is what keeps multi-KB
  WOTS+ signatures from blowing up storage.
- [Validator economics](./validator-economics.md) — leaf
  consumption is one of the operational chores; auto-rotation is
  why most operators don't have to think about it.
