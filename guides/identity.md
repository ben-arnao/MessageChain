# Identity, keys, and rotation

> **The shape:** one live key per entity, but key rotation is a
> first-class operation that preserves your identity, your history,
> your balances, and your reputation. A signature scheme that
> breaks in 2080 doesn't force you to abandon the account you've
> built — you rotate to a new scheme via the same mechanism, and
> you're still you.

Most blockchains treat identity as one-shot pseudonymous: lose your
key and you lose the account. MessageChain takes a different stance.
Pseudonymity is preserved (the chain never asks who you are in real
life), but **continuity of voice** is a first-class goal. A
dissident or long-running author who has been signing under one
identity for ten years should not have to abandon that identity
every time a key is compromised, lost, or migrated to a stronger
algorithm.

## The model in one paragraph

An *entity* is whatever account is reading and writing on the chain
— a person, a bot, a validator, a multi-key team's shared identity.
At any moment an entity has exactly one **active signing key**.
Rotating from the current key to a successor key is a normal
transaction type, signed by the current key, and the result is
"same entity, new active key." Balances, message history, replies,
trust votes, validator stake — all of it carries forward
unchanged. The chain stores the rotation history so anyone can
audit the chain-of-custody from your original key to the current
one.

## Where identity comes from

Your identity is derived deterministically from a 24-word seed
phrase:

- **Seed phrase:** 24 words from the BIP-39 English wordlist.
  256 bits of entropy plus an 8-bit checksum encoded as 11 bits per
  word. Standard format, transcription errors are caught at decode
  time.
- **Private key:** the 32-byte entropy is used directly. (Note:
  unlike some BIP-39 wallets, MessageChain does *not* run PBKDF2
  over the phrase — the words are the entropy.)
- **Public key:** derived from the private key.
- **Entity ID:** `SHA3-256("entity_id" || public_key)` — a 32-byte
  identifier that uniquely names you on chain.
- **Address:** displayed as `mc1<64 hex entity_id><8 hex checksum>`
  — 75 characters total, with a built-in checksum that catches
  typos before you send anything anywhere.

Backup is just the 24 words. Anyone with the words controls the
account. Anyone who receives only the address can send you tokens
but can't act on your behalf.

## "One live key at a time"

There are no multi-sig accounts in MessageChain. There are no
hierarchical sub-keys. There is no social recovery. At any single
block, exactly one public key is the authoritative signer for an
entity, and any tx signed by anything else is rejected.

That's a deliberately strict invariant. Every weakening of it
("just let two keys sign, just let a friend co-sign in
emergencies") opens new attack surfaces — a stolen "recovery key"
racing a stolen current key, abuse vectors where the recovery
mechanism becomes the soft target. MessageChain's stance:
**rotation is cheap and reliable when you have your current key;
backup discipline is your responsibility when you don't.**

## How the chain learns your key

The chain doesn't know your public key until you announce it. The
first time you sign and broadcast a transaction, the validator
that includes it learns your pubkey from the signature itself and
records it on-chain — this is the **first-spend pubkey install**.
From that block forward, all subsequent transactions for that
entity are verified against the installed key.

You don't have to do anything special for this — the CLI handles
it. It just means your *first* outgoing tx is the one that
publishes your pubkey to the world. A pure receive-only wallet has
no on-chain pubkey at all.

## Key rotation: the mechanism

Rotation is a tx type. Concretely:

- **Type:** `key_rotation`
- **Carries:** entity_id, old public key, new public key, a
  monotonic rotation counter, fee, signature.
- **Signed by:** the **old** key, proving current ownership.
- **Effect on inclusion:**
  - The new public key replaces the old one as the entity's active
    signer.
  - The entity_id, balances, stake, key history, and on-chain
    history all carry forward unchanged.
  - The old public key is recorded in `key_history` — the
    chain-of-custody is auditable forever.
  - The leaf cursor is reset for the new keypair (a fresh tree of
    1M+ signing leaves).

The fee is `KEY_ROTATION_FEE = 1000` tokens — a real cost, but not
prohibitive. You can rotate as often as you want.

### Why rotation matters

There are several reasons you might rotate:

- **WOTS+ leaf exhaustion.** Each signature consumes one leaf in
  your Merkle tree. The default tree has about 1 million leaves —
  plenty for a casual user, but a busy validator might burn through
  them in a year or two. Auto-rotation kicks in at **≥95% leaf
  consumption** by default to head this off.
- **Suspected key compromise.** If you fear your seed has been
  copied or your machine compromised, you rotate to a new key
  generated on a clean machine. The chain forgets the old key as a
  signer.
- **Crypto-agility migration.** When the protocol introduces a
  successor signature scheme via a hard fork (see below), rotation
  is how you migrate.

Crucially: **you remain the same entity** through all of this. Your
trust votes are still your trust votes. Your message threads are
still your threads. People who replied to you years ago are still
replying to *you*.

## Crypto agility — the long view

MessageChain assumes any signature scheme in use today will
eventually fail. WOTS+ in particular is hash-based and quantum-
resistant *as far as anyone currently knows*, but "currently knows"
is a poor bet on a 100-year horizon.

Every signature on chain carries a 1-byte **version tag**
(`sig_version`), committed into the transaction's signed data.
Today's value is `SIG_VERSION_WOTS_W16_K64_V2 = 2`. The protocol's
acceptance set is currently `{V2}` — anything else is rejected.

When a successor scheme is needed (because the current scheme
weakens, or a stronger scheme is invented):

1. A governance proposal introduces a new scheme — call it `V3`.
2. The acceptance set widens to `{V2, V3}` for a transition window.
3. Existing entities **rotate** to `V3` keys via the normal
   `key_rotation` tx — same mechanism, new scheme on the other side.
4. Eventually the acceptance set narrows to `{V3}` and `V2`
   signatures stop being valid.

Identity persists across the migration. You rotated; you didn't
abandon and re-create.

## Cold authority key — the second layer

For higher-stakes operations (validator unstaking, emergency
revoke), MessageChain supports a separate **cold authority key**
that you keep offline. The hot signing key handles day-to-day
activity (block signing, attestations, messages); the cold key
authorizes the destructive operations.

How it works:

- **Initial install:** call `set-authority-key --authority-pubkey
  <cold_hex>`, signed by the hot key. From that block, the cold
  key is required for unstaking and emergency revoke.
- **Pre-install:** the authority key implicitly equals the signing
  key (single-key model, backward compatible).
- **Cold key is off-chain.** It doesn't have to belong to any
  registered entity — it's just a public key the chain remembers.
  Keeping it off-chain prevents leaf-reveal attacks against it.
- **Re-binding requires the existing cold key.** Once a cold key
  is set, *changing* it requires a counter-signature from the
  existing cold key. This blocks the attack where a compromised hot
  key escalates by quietly re-pointing the cold key at an attacker-
  controlled key.

The right mental model: **hot key is for activity, cold key is for
big decisions.** A validator running 24/7 with the hot key on the
host can still keep the cold key on a piece of paper in a safe.

## Emergency revoke — the kill switch

If your hot key is compromised and you can't trust it to rotate
honestly, you sign a `revoke` transaction with your cold key. On
inclusion:

- The entity is flagged as revoked. Subsequent blocks,
  attestations, and txs signed by the entity are rejected.
- All active stake enters the normal ~15-day unbonding queue.
- Slashing windows remain open during unbonding — the cold-key
  holder cannot escape punishment for misbehavior committed before
  the revoke.

The revoke is **bearer-replay-resistant**: it commits to a chain
height window, so a leaked revoke tx expires within ~90 days of
its `valid_to` height. You can pre-sign a revoke and store it on
paper as a "break glass" measure without worrying that a stray
copy will haunt you a decade later.

## What if you lose everything?

You don't get the account back.

This is a hard line in MessageChain. There is **no protocol-level
recovery for the lost-everything case** — no pre-committed recovery
keys, no time-locked rotation-from-nothing, no social-recovery
quora. Every such mechanism smuggles in extra surface area
(recovery-key custody, abuse vectors, third-party trust anchors)
to address a problem that's already solvable with multi-location
backup discipline.

The protocol's job is to make rotation *cheap and reliable when
you have your current key*. Backup is yours.

Practical implications:

- **Back up the 24 words on paper, in multiple physical
  locations.** Don't rely on cloud sync, photos, or files —
  malware sweeps those.
- **Verify your backup before you fund the account.** The CLI's
  `verify-key` flow exists for this — re-type the phrase, confirm
  it derives the same entity_id.
- **For validators, also back up the leaf cursor.** The keyfile
  alone isn't enough on a validator host — restoring without the
  leaf cursor will reuse signing leaves and produce equivocation
  evidence on chain.

## Validator-specific: the leaf cursor

Each WOTS+ signature is one-time-use. The chain detects re-use as
equivocation and slashes for it. So a validator running 24/7 has
to track which leaves it has already burned. That state lives in
`leaf_index.json` (and `receipt_leaf_index.json` if the validator
issues submission receipts):

- **What it is:** a small JSON file recording the next safe leaf
  index for the keypair.
- **Where it lives:** `/var/lib/messagechain/leaf_index.json` on a
  Linux validator install.
- **Why it's load-bearing:** restoring a keyfile from backup
  without the matching leaf cursor causes the validator to re-sign
  at leaves it already burned — and the soft-slash regime
  compounds geometrically across many such offenses, draining the
  stake quickly.
- **Online wallets don't need to worry about this.** The CLI
  reconstructs the cursor from chain state on restore. The cursor
  is only security-critical when you're signing offline (or
  validating, where signing happens between every chain-state
  read).

The shorter version: validators back up *both* the keyfile *and*
the leaf cursor; everyday users back up the seed phrase and that's
enough.

## Summary

| What | How |
|------|-----|
| Identity | Derived from a 24-word BIP-39 seed phrase |
| Address | `mc1` + 64-hex entity_id + 8-hex checksum |
| Live signers | Exactly one at a time |
| Rotation | A tx signed by your current key; preserves entity_id, balances, history |
| Auto-rotation trigger | ≥95% of WOTS+ leaves consumed |
| Crypto agility | 1-byte sig version + governance-driven acceptance set + rotation-as-migration |
| Cold key | Off-chain authority key for unstake + emergency revoke |
| Emergency revoke | Cold-signed kill switch; expires by height |
| Lost seed | Account is gone. No protocol recovery. Back up your seed. |

The summary in one sentence: **your identity is durable across a
century of crypto migrations, but only as durable as your seed
backup.**

## Further reading

- [Forum primitives](./forum-primitives.md) — what's keyed by your
  entity_id (messages, replies, votes, communities).
- [Validator economics](./validator-economics.md) — the
  obligations and risks of running an entity that signs every block.
- [Permanence guarantees](./permanence.md) — how your messages
  outlive your current key, and the next key, and the one after
  that.
