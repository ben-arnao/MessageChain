# How MessageChain compares to nearby projects

Five projects share enough of MessageChain's design space — by mission,
functionality, or both — to be worth contrasting against. For each, the
single biggest advantage MC has, chosen to highlight the deepest design
difference rather than the most superficial one.

---

## vs Hive

A community-driven hard fork of Steem (March 2020): on-chain content,
native HIVE token, block production by ~20 stake-elected witnesses.

**MC's advantage: pure stake-threshold permissionless validator entry.**
Hive's elected-witness slate is captureable by anyone with enough stake
to swing the vote — exactly the failure mode that forced the 2020
Steem→Hive fork when Justin Sun bought Steemit's treasury and voted in
his own slate. MC has no slots and no elections; meet the stake floor,
run a node, you validate. The Sun-style takeover is structurally
impossible on MC because there is no seat to take over.

---

## vs DeSo

Closest structural twin: purpose-built blockchain for social with
on-chain content, permissionless validators, native token.

**MC's advantage: anchored "messages-only, no DeFi ever" scope
discipline.** DeSo's product surface drifted into creator coins, social
tokens, NFTs, on-chain games, and marketplaces — each addition adding
regulatory exposure, attack surface, and token-concentration risk. MC's
no-programmability rule is a foundational design anchor that routine
governance cannot overturn — token holders cannot *want* this hard
enough to make it happen by accident.

---

## vs Nostr

Closest project in spirit: censorship-resistant public speech,
public-only payloads, no identity gates.

**MC's advantage: consensus-layer permanence backed by a native economic
incentive.** A Nostr post exists if and only if at least one relay still
has it — relays delete content, go offline, get coerced, and the
protocol has no economic backbone for relay operation. MC's permanence
is structural: once finalized, the message is in the chain forever, and
validators are paid out of a portion of the base-fee burn to prove they
still hold ancient blocks. A post that disappears when the last willing
relay drops it has been censored just as effectively as one that was
never accepted.

---

## vs Bastyon (Pocketnet)

Closest in literal headline promise: *"all operations stored on the
blockchain and cannot be deleted by anyone."* Permissionless nodes,
native PKOIN token.

**MC's advantage: slashable evidence for validator-collusion
censorship.** Bastyon's "cannot be deleted" promise assumes the chain
itself is honest — its published design has no comparably layered
defense for the case where validators coordinate to refuse inclusion of
specific posts. MC has three explicit evidence types
(`CensorshipEvidenceTx`, `NonResponseEvidenceTx`,
`BogusRejectionEvidenceTx`) plus a forced-inclusion list that turn
validator collusion into cryptographic evidence the moment it is
attempted.

---

## vs Arweave

Closest on the delivered permanence property: consensus-layer storage at
petabyte scale.

**MC's advantage: crypto agility and identity continuity across key
rotations.** Arweave's signing scheme is fixed at the protocol level
(RSA, set in 2018) — no version tag, no rotation primitive. When the
scheme breaks (and on a 100+ year horizon every signature scheme
eventually does), Arweave faces a coordinated migration with no native
primitive for moving identities to the new scheme. MC's signatures carry
version/algorithm tags and key rotation is a first-class transaction
type — entities survive multiple generations of cryptographic migration
with their full history intact.

---

## Synthesis

| Project | Where MC differs deepest |
|---------|--------------------------|
| Hive    | Validator entry — pure stake-threshold, no elected slots |
| DeSo    | Scope — anchored no-DeFi, ever |
| Nostr   | Storage — consensus-stored, paid by base-fee burn |
| Bastyon | Anti-collusion slashing primitives |
| Arweave | Crypto agility + identity continuity across rotations |

MessageChain is what falls out of taking every axis seriously
simultaneously and refusing to trade any of them for short-term feature
velocity.
