# Validator economics

> **The pitch:** running a MessageChain validator is intentionally
> accessible — one faucet drip and a Linux box are enough to
> participate. The tradeoff is that you have real obligations, real
> rewards, and real slashing risk if you misbehave or go down. This
> guide is the honest "should I do this?" rundown.

MessageChain validators have three jobs: propose blocks when it's
their turn, attest to the validity of others' blocks, and keep a
copy of the full history. In exchange for doing those jobs
honestly and continuously, they earn a share of newly-issued tokens
and tx fees. If they misbehave or go offline, they lose stake.

This guide covers what comes in, what goes out, what's at risk,
and roughly what the math looks like at the current stage of the
network.

## What it costs to start

- **300 tokens** total (one [faucet drip](https://messagechain.org)).
  - 200 tokens get **staked** as your validator deposit.
  - 100 tokens cover the stake-tx fee.
- **Hardware:** any always-on Linux host with Python 3.10+,
  ~2 GB RAM, and inbound TCP ports 9333 + 9334 open. No GPU, no
  specialized rigs, no SSD floor enforced by the protocol.
- **Time:** the install script runs in a few minutes; key
  generation takes a few minutes more (one-time keygen of a WOTS+
  Merkle tree of ~1M leaves).

The 300-token entry stake is *very low* by PoS standards on
purpose. There is no capital wall on validator entry — the
protocol isn't trying to keep small operators out. A smaller stake
means smaller rewards in absolute terms, but the per-token yield
is **higher** at the small end of the curve (see [Keeping rewards
fair](./fair-rewards.md)).

## What you earn

Reward sources, in roughly decreasing order of typical contribution:

### 1. Block reward + attester pool

Every block, the chain mints a fixed reward and splits it:

- **Proposer share:** 1/4 of the block reward goes to whoever
  proposed the block, capped at 4 tokens.
- **Attester pool:** 3/4 goes into a pool that's distributed
  pro-rata by stake to that block's attester committee.

The base block reward is currently **16 tokens** per block, with a
halving every 210,240 blocks (~4 years) and a permanent floor of
**4 tokens** per block. Once the active-supply controller activates
(see [Stable money over centuries](./stable-money.md)), issuance
becomes governed by the controller instead of the halving
schedule, but the *flow* (proposer share + attester pool) stays
the same.

The amount you actually earn from this is roughly:

```
your_share_of_attester_pool ≈ (your_stake / total_active_stake) × (3/4 × block_reward)
                              × diminishing_returns_multiplier
```

Plus an occasional proposer share when it's your turn to propose
the block.

### 2. Tx fee tips

Every transaction's fee splits into a **base-fee burn** and a
**tip**. The tip flows to the block proposer. On a quiet chain in
the bootstrap phase, tx fees are modest; on a busy chain, they
can dominate the per-block reward over time. Validator security
in the long run is funded by the fee market, not by issuance.

### 3. Archive challenge bounties

Every 100 blocks, the chain runs an archive challenge — picks 5
random historical heights, asks validators to prove they still
have those blocks, and pays the first valid proofs out of the
**ArchiveRewardPool**. The pool is funded by redirecting **25%**
of the base-fee burn into archive rewards.

If you maintain the full archive (which you should — that's the
deal), and your node responds to challenges promptly, this is a
steady supplemental income stream. If you let your archive rot,
you miss challenges and your reward share starts being **withheld**
proportionally — recoverable, but expensive while it lasts.

### 4. Lottery payouts

A reputation-weighted lottery fires every ~144 blocks (about once
a day) during the bootstrap arc, paying a bounty to a non-seed
validator selected proportional to on-chain reputation (accepted
attestation count). The bounty fades to zero as the founder
divestment schedule approaches its end, which is intentional —
this lottery exists to *bootstrap* a competitive validator set,
not to provide permanent rent.

Wins are infrequent per-validator but meaningful when they hit
(currently ~5,000 tokens per win, post-Tier 2).

## Realistic napkin math

These numbers are rough orders of magnitude, not promises. Your
mileage depends on total active stake (which grows as more
validators join), congestion, your honest-operation track record,
and where the network is in its activation schedule.

Assuming:

- 600 s/block → ~52,600 blocks/year
- 16 tokens/block base reward → **~841,600 tokens issued
  per year** to the validator set as a whole (pre-halving)
- Your stake: 200 tokens
- Plus diminishing-returns curve multiplier (favorable at small
  stake): ~1.3× early, ~1.05× at 10% network share

| Total active stake | Your annual block-reward share | APY (rough) |
|--------------------|-------------------------------|-------------|
| 5,000,000 tokens   | ~33–45 tokens/year            | ~16–22%     |
| 10,000,000 tokens  | ~17–22 tokens/year            | ~8–11%      |
| 50,000,000 tokens  | ~3–5 tokens/year              | ~1.5–2.5%   |
| 100,000,000 tokens | ~1.5–2.5 tokens/year          | ~0.7–1.2%   |

Plus archive challenge bounties (steady), tx fee tips (variable),
lottery wins (rare). On the small end of network growth, you might
clear 15–25% APY. On a fully-grown network with 100M+ active
stake, expect closer to 1–3% APY from issuance, with fees making
up the rest.

The numbers shift downward as the network grows, but **absolute
reward grows with stake** at every point on the curve — adding
more stake never reduces what you earn, just the marginal rate per
extra token.

## What you risk

### Slashing

Slashing in MessageChain is graded by track record (see [Keeping
rewards fair § Slashing leniency](./fair-rewards.md)). The current
schedule (post-Tier 20 soft-slash regime, active on mainnet
today):

| Offense | Penalty | Notes |
|---------|---------|-------|
| Equivocation / double-sign (single offense) | 5% of stake | Soft-slash; validator stays in set |
| WOTS+ leaf reuse (single offense) | 5% of stake | Same mechanism as equivocation |
| Bulk leaf reuse (e.g. restored bad backup) | Compounds geometrically: `(1 − 0.05)^N` | Many offenses → near-total loss |
| Censorship (after issuing receipt) | 10% of stake | Burned, not paid to evidence submitter |
| Non-response (silent TCP drop) | 5% of stake | Burned |
| Bogus rejection (forged "invalid sig") | 10% of stake | Re-verified on chain |
| Repeat unambiguous double-sign | Up to 100% | Reserved for clear repeat misbehavior |

A long-tenured validator with a clean record gets **first-incident
amnesty** on ambiguous evidence (single restart-shape incident,
borderline timestamp drift) — the first such offense after a
significant track record can be slash-zero. After that, ambiguous
offenses escalate normally.

The pre-soft-slash regime (100% slash on any equivocation) is
retired. One bad block does not nuke a long-honest validator.

### Inactivity

If a large fraction of the network goes silent for an extended
window, an **inactivity leak** activates: balances bleed at a
quadratic rate against the gap. This forces a stalled cartel
(e.g. 1/3+ of stake offline blocking finality) to either come back
online or lose enough stake that 2/3 finality is achievable
without them.

For a normal validator running 24/7, the inactivity leak doesn't
apply — it triggers only when finality has been missed across many
consecutive blocks.

### Operational mistakes

The biggest real-world risk to a validator isn't malice — it's
restoring a backup wrong. **Restoring the keyfile without the
matching `leaf_index.json`** causes the validator to re-sign at
leaves it already burned, producing equivocation evidence on
chain. Under the soft-slash regime, that's 5% per offense, and
bulk leaf reuse compounds quickly toward total loss.

The defensive posture: back up *both* the keyfile *and* the leaf
cursor file together, atomically, and restore them together. The
README's "Operating a live validator" section spells out the exact
backup procedure.

### Unbonding

If you decide to retire your validator, you call
`messagechain unstake --amount N`, then wait the **unbonding
window** (currently ~2,176 blocks ≈ **15 days**) before the stake
returns to your liquid balance. Slashing windows extend across
the unbonding window — peers can prove misbehavior committed
*before* you left and you'll still be slashed for it.

**Don't shut a validator host down inside the unbonding window.**
Going offline before the window closes can trigger downtime
penalties; wait it out. The 15-day buffer exists precisely so
peers have time to surface evidence of any pre-departure
misbehavior.

## Operator obligations

To stay in good standing and keep earning:

1. **Keep the validator running.** Inactivity slashing only kicks
   in for prolonged outages, but missing attestations costs you
   per-block share immediately.
2. **Auto-rotate keys.** The default at 95% leaf consumption is
   sensible for most operators; you can lower the threshold via
   `messagechain config set` if you want more headroom.
3. **Submit archive proofs.** They're handled automatically by the
   running validator; just don't let your data dir corrupt or
   shrink.
4. **Attest correctly.** Same — automatic when running honestly.
5. **Back up the keyfile + leaf cursor + receipt cursor together.**
   This is the one truly load-bearing manual chore. Snapshot when
   you snapshot the keyfile.
6. **Set up a cold authority key.** For destructive ops
   (unstaking, emergency revoke), keeping the cold key off the
   validator host means a hot-key compromise can't drain your
   stake. See the [identity guide](./identity.md).

## Day-in-the-life: what running a node feels like

If you're running honestly and the chain isn't stressed:

- The systemd unit just runs. It proposes blocks when it's your
  turn, attests when it's not, replies to archive challenges
  in the background.
- `messagechain status` shows your stake share, recent rewards,
  and leaf-consumption percentage.
- `messagechain validators` shows the active set ordered by stake.
- `journalctl -u messagechain-validator -f` follows the log.
- A weekly auto-upgrade timer pulls the latest signed mainnet
  release and restarts the service.
- A daily auto-rotate timer rotates your key when leaves
  approach 95%.

It's deliberately undemanding. The point is "this should run on a
$5/month VPS without you noticing it most of the time."

## Should you run one?

A few honest considerations:

- **Yes, if** you want to participate in the network meaningfully,
  understand the slashing risks, and have an always-on host you
  trust.
- **Maybe not, if** you're hoping for high passive yield with no
  operational discipline. The slashing schedule is real; an
  operator who treats backup as optional will eventually
  experience why it isn't.
- **No, if** you can't keep the host online reliably. Spotty
  uptime won't cost you 100% of your stake under the soft-slash
  regime, but it'll cost you reward share and possibly inactivity
  penalties under network-wide stress.

The spirit of the design: anyone with modest hardware and basic
operational hygiene should be able to run a validator and earn a
fair share of the network's issuance. The chain isn't optimizing
for "make small operators uneconomic" — it's optimizing for "many
honest validators, broadly distributed, none with a permanent
incumbency advantage."

## Further reading

- [Keeping rewards fair](./fair-rewards.md) — the diminishing-
  returns curve, founder divestment, slashing leniency in detail.
- [Identity, keys, and rotation](./identity.md) — keyfile, leaf
  cursor, cold authority key, the operations that gate
  destructive actions.
- [Quantum resistance and WOTS+](./quantum-resistance.md) — what
  the leaf consumption is actually about, and why running out
  matters.
- [Permanence guarantees](./permanence.md) — what archive duty
  actually involves.
- The README's [`Run a validator`](../README.md#run-a-validator)
  section is the step-by-step install reference; this guide is
  the *why*.
