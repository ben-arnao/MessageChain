# MessageChain

[![release](https://img.shields.io/github/v/release/ben-arnao/MessageChain)](https://github.com/ben-arnao/MessageChain/releases)
[![license](https://img.shields.io/github/license/ben-arnao/MessageChain)](./LICENSE)

A permanent, censorship-resistant ledger for human speech.
**Your message can never be deleted.** A well-formed message that
pays the fee floor is guaranteed inclusion — validators that drop or
suppress it lose stake on chain.

**Status:** mainnet live. Chain ID `messagechain-v1`, genesis block 0
`4eeb9edaadb42f1a460e95919bc667a3173c4a84aa9b5488da040ac7a1c054f6`.

**Live feed:** [messagechain.org](https://messagechain.org)

## Why

- **Your message can never be deleted.** Once a message is on-chain,
  no platform, government, ISP, or validator can hide, filter, or
  remove it. The ledger is the source of truth and there is no
  takedown path.
- **Suppression is slashable.** A well-formed message that pays the
  per-byte floor and fits the block budget cannot be quietly dropped.
  Refusing to include or attest to such a message produces evidence
  that any node can submit, and the offending validators lose stake.
- **Permanence is funded forever.** Storage is paid for by perpetual
  validator rewards, not a one-shot endowment. The security budget
  never runs out, so the promise of permanence does not have an
  expiry date.
- **Costly to spam.** Every message costs real tokens, with the fee
  scaling linearly in stored bytes. Bots can participate, but they
  pay the same price as everyone else — AI-generated noise has a
  floor.
- **Simple and durable.** Designed to run for centuries with minimal
  moving parts. Slow blocks and expensive fees are features, not bugs.
  Zero runtime dependencies outside the Python stdlib.
- **Democratic by default.** On-chain governance, distributed
  validation, no privileged operators, no permissioned validator set.
  L2s can layer reputation, identity, and moderation on top.
- **Cheap to validate.** Runs on commodity hardware — no GPUs, no
  specialized rigs. Quantum-resistant signatures throughout.

## Install

Python 3.10+, no third-party deps.

```bash
git clone https://github.com/ben-arnao/MessageChain.git
cd MessageChain
pip install .
```

This puts a `messagechain` command on your PATH. You can run it the
same way via `python -m messagechain <cmd>` if you prefer.

## Getting started — your first message

### 1. Generate a private key (offline)

```bash
messagechain generate-key    # write the printed hex on paper, 2–3 copies
messagechain verify-key      # re-type to confirm the backup
```

Paper beats files — files get swept by cloud sync, backups, and
malware. Don't copy-paste (clipboard managers log history). Close
the terminal when done.

Your entity_id and `mc1…` address are derived deterministically from
the key.

### 2. Get tokens

MessageChain uses a **receive-to-exist** model: you do not need to
register anything on-chain to receive tokens. Your account appears in
chain state the moment someone sends you a transfer.

### 3. Post

**Fees.** Every CLI submission auto-prices by default. The picker
samples fee-per-byte across the last 50 blocks and bids the
percentile that matches your urgency rung — `high` (~1 block, 90th
pct), `normal` (~3 blocks, 75th pct, default), `low` (~10 blocks,
25th pct) — then multiplies by the tx's stored byte count, never
dropping below the protocol floor. Override with `--fee N` for a
specific bid. `messagechain estimate-fee --tx-type <kind> ...`
previews the cost of any tx without submitting.

**Post a message.**

```bash
messagechain send "hello world"
messagechain send "hello world" --fee 500          # manual fee
messagechain send "hi" --urgency high              # ~1-block target
```

**Tag a community.** `--community-id NAME` groups the message under
a Reddit-style topic. The on-chain id is `sha256(name)[:16]`; any
human-readable name maps deterministically. No registry, no claim —
first-poster semantics; moderation is an app/indexer concern.

```bash
messagechain send "build report" --community-id mc-dev
```

**Reply to a message.** `--prev <tx_hash>` attaches a 32-byte
pointer to a prior on-chain message — apps render this as a reply,
chained long-form, citation, etc. The referenced tx must already
be in a strictly earlier block.

```bash
messagechain send "good point" --prev <tx_hash>
```

**Long-form posts (>1024 chars).** A single message is capped at
1024 chars. For longer content, send a sequence and chain each
piece with `--prev` pointing at the previous tx_hash. The chain
requires each `--prev` target to be in a strictly earlier block,
so you'll wait one block (~10 min) between pieces.

**Up/down-vote a message.** `react <tx_hash> --choice up|down|clear`
votes on a message. Re-voting supersedes; `--choice clear` retracts.
Each (voter, target) pair has a single latest choice in consensus
state.

```bash
messagechain react <tx_hash> --choice up
messagechain react <tx_hash> --choice clear
```

**Trust/flag a user.** Same `react` command with
`--target-type user`, passing the target's entity_id (raw hex).
`--choice up` = trust, `--choice down` = flag, `--choice clear` =
retract. Self-trust is rejected by the protocol.

```bash
messagechain react <entity_id> --target-type user --choice up    # vouch
messagechain react <entity_id> --target-type user --choice down  # flag
```

**First send.** Your first outgoing transaction reveals your
public key on-chain (the "first-spend pubkey install" path).
Subsequent transactions verify against the installed key — the CLI
handles this automatically.

### 4. Read messages back

Wait one block (~10 minutes) for your message to be included, then:

```bash
messagechain read --last 20
```

### 5. Back up your wallet

**Your 24-word recovery phrase is your backup.** Write it down on
paper (or stamp it into metal) and store it offline. Anyone with
those words controls the account; lose them and the funds are gone
with no recovery. Don't put it in cloud sync, don't email it to
yourself, don't photograph it.

That's it. Restoring on a new machine just means feeding the phrase
back to any signing command (`--keyfile <path>` to a file containing
the phrase, or paste it at the prompt) — the wallet re-derives the
keypair and queries the network for your highest-used leaf so it can
resume signing safely.

#### Offline-signing power users only

If you sign on an air-gapped machine and broadcast later, the
network can't see leaves you've used until you broadcast them. In
that workflow the local leaf cursor at
`~/.messagechain/leaves/<entity_id_hex>.idx` IS security-critical
between signings: re-signing at a leaf you've already burned offline
discloses that leaf's WOTS+ private key and produces equivocation
evidence on chain (100% slash on detection). Bundle the cursor with
your keyfile when moving the offline signer to new hardware:

```bash
messagechain backup-wallet --keyfile /path/to/keyfile
# writes <entity_id_hex>-wallet-backup-<YYYYMMDD>.tar.gz in CWD
```

For online wallets — the default path — ignore this section. The
cursor is rebuilt from chain state on restore.

## CLI reference

### Personal wallet

```bash
messagechain generate-key                       # new private key (offline)
messagechain verify-key                         # confirm backup
messagechain account                            # print your address + entity_id
messagechain balance                            # liquid + staked tokens
messagechain send "hello"                       # post a message
messagechain send "hi" --community-id mc-dev    # tag with a community
messagechain send "reply" --prev <tx_hash>      # reply/chain to a prior message
messagechain react <tx_hash> --choice up        # up/down/clear-vote a message
messagechain react <entity_id> --target-type user --choice up   # trust/flag a user
messagechain transfer --to mc1… --amount 100    # send tokens
messagechain read --last 50                     # recent messages
messagechain estimate-fee --tx-type message --message "hi"  # fee preview
messagechain backup-wallet --keyfile <path>     # offline-signers only:
                                                # bundle keyfile + leaf cursor
```

### Chain & validator info

```bash
messagechain info                               # chain height, supply, sync
messagechain validators                         # validator set, stakes, shares
messagechain peers                              # P2P peers of the target node
messagechain status --server HOST:9334          # one-call health check
messagechain status --server HOST:9334 --entity YOUR_ID
                                                # validator-specific leaf usage
messagechain ping                               # first-run sanity check
```

### Governance

```bash
messagechain propose --title "…" --description "…"
messagechain vote --proposal <id> --yes
messagechain proposals                          # open proposals + tallies
```

### Validator operations

```bash
messagechain stake --amount 10000               # lock as validator stake
messagechain unstake --amount 5000              # ~15-day unbonding
messagechain start --mine                       # run a validator
messagechain key-status                         # WOTS+ leaf usage
messagechain rotate-key                         # fresh keypair, old key retired
messagechain upgrade                            # install the latest mainnet tag
```

## Run a validator

You need 10,000 tokens to stake and an always-on Linux host (Python
3.10+, ~2 GB RAM) with inbound TCP **9333 + 9334** open in your
cloud firewall.

```bash
# 1. on the host (as root) — installs MessageChain, generates the validator's
#    keyfile, and prints its mc1... address.  Save that address.
#
# Pull the script down and read it before running.  The installer pins
# the install to the latest signed `vX.Y.Z-mainnet` tag and refuses to
# proceed if the tag isn't signed by a release signer baked into the
# script — but the script itself is the trust root, so eyeball it.
curl -fsSL -o install-validator.sh \
    https://raw.githubusercontent.com/ben-arnao/MessageChain/main/scripts/install-validator.sh
less install-validator.sh                  # review before running as root
sudo bash install-validator.sh

# 2. from a wallet with tokens, fund the address printed above:
messagechain transfer --to mc1... --amount 10000

# 3. back on the host, lock the funds as stake:
sudo -u messagechain messagechain stake --amount 10000

# 4. start
systemctl enable --now messagechain-validator messagechain-upgrade.timer messagechain-rotate-key.timer

# 5. verify
messagechain status
```

The installer's keyfile **is** the validator's identity — the same
key signs blocks and owns the stake. Back it up:
`sudo cat /etc/messagechain/keyfile` and store the hex offline.
**Important:** the keyfile alone is not a complete backup. See
*Operating a live validator → Back up the keyfile* below for the
WOTS+ leaf-state files that must be preserved alongside it; restoring
a keyfile without the matching leaf state will cause one-time WOTS+
leaves to be re-used and the chain will slash 100% of your stake on
detection.

Rewards = block reward + tx fees + attester pool share, pro-rata by
stake. Unbonding takes ~15 days (2176 blocks) — slashing windows
extend past departure, so don't shut a validator down inside the
unbonding window.

<details>
<summary>Operating a live validator (backups, migration, retirement, monitoring)</summary>

**Back up the keyfile AND the leaf-index files.** Three files together
make up a complete validator backup:

1. `/etc/messagechain/keyfile` — the hex secret. `sudo cat` it and
   store offline (paper, hardware token, encrypted USB). Lose this
   and the staked funds are gone with no recovery.
2. `/var/lib/messagechain/leaf_index.json` — the WOTS+ next-leaf
   counter for block signing.
3. `/var/lib/messagechain/receipt_leaf_index.json` — the WOTS+
   next-leaf counter for the submission-receipt key (only present on
   validators that issue receipts).

The leaf-index files record which one-time WOTS+ leaves the keyfile
has already burned. **Restoring the keyfile without the matching
leaf-index files re-signs already-used leaves**, which mathematically
discloses the WOTS+ private key for those leaves and produces
equivocation evidence on chain. Pre-Tier 20 the protocol slashed
100% of stake on detection (`SLASH_PENALTY_PCT = 100`) with no
recovery path. At/after `SOFT_SLASH_HEIGHT = 15000` the per-offense
penalty drops to `SOFT_SLASH_PCT = 5` and the validator stays in
the set with reduced stake — but a leaf-index restore burns leaves
in BULK, producing many distinct equivocation events that compound
geometrically `(1 - 0.05)^N` toward total stake loss. Treat the
leaf-index files as security-critical state, not as a regenerable
cache. Snapshot them whenever you snapshot the keyfile, and never
restore one without the other.

**Migrate to a new host.** Stop the validator on the old host
(`systemctl stop messagechain-validator`), then copy **both** the
keyfile and the leaf-index files to the new host:

```bash
# on the OLD host — capture keyfile + leaf state atomically
# (after systemctl stop, so leaf_index.json is no longer being written).
sudo tar czf /tmp/mc-validator-backup.tgz \
    -C / etc/messagechain/keyfile \
    var/lib/messagechain/leaf_index.json \
    var/lib/messagechain/receipt_leaf_index.json
# transfer /tmp/mc-validator-backup.tgz to the new host (scp, etc.)

# on the NEW host — extract, fix ownership, then run the installer
sudo tar xzf /tmp/mc-validator-backup.tgz -C /
sudo chown messagechain:messagechain /etc/messagechain/keyfile \
    /var/lib/messagechain/leaf_index.json \
    /var/lib/messagechain/receipt_leaf_index.json
sudo chmod 0600 /etc/messagechain/keyfile
```

Then run the installer on the new host. Init reuses the existing
keyfile rather than regenerating — no multi-hour keygen, and no
double-sign risk because only one host runs at a time. Skipping the
leaf-index files (e.g. copying just the keyfile, or restoring from a
keyfile-only paper backup after a disk-loss event) **will cause leaf
reuse and a 100% slash** the first time the new validator signs.
If you ever find yourself with a keyfile but no leaf-index, do NOT
start the validator — instead, reach out to a peer for a chain-state
inspection of your entity's existing on-chain signatures so you can
recover the high-water-mark leaf index before signing again.

**Drain & retire.** `messagechain unstake --amount 10000`, wait the
full ~15-day unbonding window so the slashing window closes, *then*
shut the host down. Bringing a validator down with stake still bonded
risks downtime slashing.

**What gets you slashed.** Double-signing or equivocating — signing
two competing blocks at the same height — or WOTS+ leaf reuse, which
is detected as equivocation under the same rule. Leaf reuse is most
commonly caused by restoring a keyfile from backup without the
matching `leaf_index.json` (see *Back up the keyfile AND the
leaf-index files* above). The unbonding window exists so peers can
prove misbehavior committed before you left.

**Health monitoring.** `messagechain validators` (your stake share +
whether you're in the active set). `messagechain key-status` (WOTS+
leaf consumption — auto-rotation handles this at ≥95% but check by
hand if curious). `journalctl -u messagechain-validator -f` to follow
the log live.

**Manual upgrade.** `messagechain upgrade` installs the latest mainnet
tag. The weekly timer does this automatically; run it by hand if you
disabled the timer.

**Toggle automation.** `messagechain config set auto_upgrade false` /
`auto_rotate false` disables the timers.

**Cold authority.** `messagechain set-authority-key --authority-pubkey
<cold_hex>` requires a cold-signed key for future rotations.
`messagechain emergency-revoke --entity-id <hex>` is the cold-signed
kill switch.

**Manual run (no installer).** `messagechain generate-key`, store the
hex on paper, then `messagechain start --mine --rpc-bind 0.0.0.0
--data-dir /var/lib/messagechain --keyfile /etc/messagechain/keyfile`.
A systemd unit example ships at
[`examples/messagechain-validator.service.example`](./examples/messagechain-validator.service.example).
`messagechain doctor` runs preflight checks. `messagechain init` is
what the installer wraps — run it directly if you don't want the
curl-pipe.

</details>

## Security & changelog

- Vulnerabilities: see [SECURITY.md](./SECURITY.md) — private email
  disclosure, 72h ack, 7d triage. Do not open a public issue.
- Release notes: see [CHANGELOG.md](./CHANGELOG.md).
