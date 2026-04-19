# Mainnet Parameters (Proposed)

Concrete values for every block-0 immutable parameter.  Once baked
into genesis they **cannot be changed without a hard fork / chain
reset**.  Anything not listed here is governance-mutable post-launch
(voting window, fee schedule, block time, unbonding period, slash %,
min validator stake, etc.).

**Status**: proposed, not yet committed.  Approve each line before
the mainnet mint.

---

## Hard-frozen at block 0

| Parameter | Proposed value | Notes |
|---|---|---|
| `GENESIS_SUPPLY` | `1_000_000_000` (1B) | Status quo.  No reason to change; round number fits everywhere. |
| `CHAIN_ID` | `b"messagechain-v1"` | Becomes the fork identifier forever.  If we ever hard-fork, bump to `v2`. |
| `TREASURY_ENTITY_ID` | deterministic from `b"messagechain-treasury-v1"` | No private key, governance-controlled only. |
| `TREASURY_ALLOCATION` | `40_000_000` (4%) | Funds the treasury for first-year ops.  Sized so governance can move meaningful amounts without immediate starvation. |
| **Founder allocation** | `100_000_000` (10%) | **RECOMMENDED: 50M–100M.**  Less → founder runs out of stake-security before external validators arrive.  More → founder dominance visible for too long even with divestment. 100M is "enough to solo-secure during 2-year bootstrap" with room for modest spending + future re-stake. |
| **Founder stake (at genesis)** | `95_000_000` of the 100M | 5M liquid for ops/fees; 95M staked immediately.  Post-bootstrap divestment drains to `SEED_DIVESTMENT_RETAIN_FLOOR = 1M` via 4-year linear unwind. |
| **Founder tree height** | `20` | 2^20 = 1,048,576 signing keys.  At production block time (600s) + active attesting, ~530K leaves/year consumed.  ~18 months before first rotation.  Key-rotation runbook at `docs/key-rotation-runbook.md`. |
| `HASH_VERSION_CURRENT` | `1` (SHA3-256) | Same as today.  Upgrade path via governance version bump (messagechain/config.py:115). |
| `SIG_VERSION_CURRENT` | `1` (WOTS+ W=16 chains=64) | Same as today. |
| `PROPOSER_REWARD_NUMERATOR` / `DENOMINATOR` | `1 / 4` | Proposer gets 1/4, attestors share 3/4.  Incentivizes the attestation work that actually secures the chain. |
| `BLOCK_REWARD` (initial) | `16` | Power of 2 for clean halvings. |
| `HALVING_INTERVAL` | `210_240` blocks (~4 yr at 600s) | Matches Bitcoin's halving cadence. |
| `BLOCK_REWARD_FLOOR` | `4` | Halving stops at 4 tokens/block.  Long-run inflation: ~0.02%/yr of genesis. |

## Divestment schedule (already fixed in config.py, re-confirm for mainnet)

| Parameter | Value | Notes |
|---|---|---|
| `SEED_DIVESTMENT_START_HEIGHT` | `BOOTSTRAP_END_HEIGHT` (105,192) | Starts exactly when bootstrap ends, ~2 years in. |
| `SEED_DIVESTMENT_END_HEIGHT` | start + 210,384 | Linear unwind over ~4 years. |
| `SEED_DIVESTMENT_BURN_BPS` | `7500` (75%) | Majority of unwound stake is burned (deflationary). |
| `SEED_DIVESTMENT_TREASURY_BPS` | `2500` (25%) | Rest tops up the treasury. |
| `SEED_DIVESTMENT_RETAIN_FLOOR` | `1_000_000` (0.1% of supply) | Founder always keeps at least this much.  "One of the bigger players, not dominant." |

## Bootstrap parameters (configurable via governance but should be nailed at launch)

| Parameter | Proposed value | Notes |
|---|---|---|
| `BOOTSTRAP_END_HEIGHT` | `105_192` (~2 yr) | Hardcoded constant in bootstrap_gradient.py.  Long enough for real validator set to form; short enough that lock-in isn't permanent. |
| `MIN_VALIDATORS_TO_EXIT_BOOTSTRAP` | `1` at genesis | **Operator decision: single-validator launch.**  Raise to 3 via governance once 2+ more validators join. |
| `LOTTERY_INTERVAL` | `144` blocks (~1/day) | Zero-stake early-validator bounty opportunity. |
| `LOTTERY_BOUNTY` | `100` tokens (fades to 0 at bootstrap end) | Total bootstrap-era lottery mint: 73K tokens (~0.007% of supply). |
| `REPUTATION_CAP` | `10_000` | Reputation saturates; no infinite compounding. |
| `ATTESTER_ESCROW_BLOCKS` | `12_960` (~90 days) | Attester-reward escrow during bootstrap, deters grief-then-exit. |

## Economic parameters (governance-mutable post-launch, but pick launch defaults)

| Parameter | Proposed value | Rationale |
|---|---|---|
| `BLOCK_TIME_TARGET` | `600` (10 min) | Same as Bitcoin.  Chain is intentionally slow. |
| `MAX_TXS_PER_BLOCK` | `20` | Tx count cap. |
| `MAX_BLOCK_MESSAGE_BYTES` | `10_000` | Byte budget cap — tighter bound than tx count alone. |
| `MIN_FEE` | `100` | High floor: 1-char message = 103 tokens.  Chain is for durable messages, not spam. |
| `FEE_PER_BYTE` | `3` | Linear size fee. |
| `FEE_QUADRATIC_COEFF` | `2` (per 1000) | Quadratic surcharge — 280-char max-size message = 1,096 tokens. |
| `DUST_LIMIT` | `10` | Below this, transfers rejected. |
| `NEW_ACCOUNT_FEE` | `1_000` (burned) | Per-new-account surcharge, deters free account creation under receive-to-exist model. |
| `MAX_NEW_ACCOUNTS_PER_BLOCK` | `10` | Hard cap on bloat-via-new-accounts. |
| `UNBONDING_PERIOD` | `1_008` blocks (~7 days) | Industry standard minimum. |
| `SLASH_PENALTY_PCT` | `100` | Full stake slash on confirmed double-sign. |
| `SLASH_FINDER_REWARD_PCT` | `10` | 10% to the evidence submitter. |
| `KEY_ROTATION_FEE` | `1_000` | Fee to rotate WOTS+ keypair.  Deters frivolous rotation. |
| `VALIDATOR_MIN_STAKE` | `100` (flat from block 0) | Low-barrier entry; reputation + escrow carry the weight against sybil. |

## Governance parameters

| Parameter | Proposed value | Notes |
|---|---|---|
| `GOVERNANCE_VOTING_WINDOW` | `1_008` blocks (~7 days) | Long enough for real people to participate across time zones. |
| `GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR / DENOMINATOR` | `2 / 3` | Strict supermajority of **total eligible stake** (silence = NO). |
| `GOVERNANCE_PROPOSAL_FEE` | `10_000` | Spam deterrent.  A legit proposer can afford it. |
| `GOVERNANCE_VOTE_FEE` | `100` | Same as MIN_FEE.  Sybil-vote spam is expensive. |

---

## Napkin math (for reference)

**Inflation**

```
Era 1 (blocks 0–210,239 ≈ yr 0–4):  reward=16  →  0.084%/yr of GENESIS
Era 2 (blocks 210,240–420,479):     reward=8   →  0.042%/yr of GENESIS
Era 3+ (blocks 420,480+, floor):    reward=4   →  0.021%/yr of GENESIS forever

20-year cumulative mint: 7.57M = 0.76% of GENESIS
```

**Founder share over time**

```
At genesis:          95M staked of 100M wallet of 1B supply  =  9.5% share
At bootstrap end:    95M staked (divestment not yet started) =  9.5% share
Mid-divestment (yr 4): ~48M staked                          =  ~4.8% share
End of divestment (yr 6): 1M staked (floor)                 =  ~0.1% share
```

**Divestment burn impact**

```
Total founder stake divested over 4 yr: 100M − 1M = 99M tokens
75% burned:   74.25M burned  (reduces total_supply)
25% treasury: 24.75M to treasury balance
```

Post-divestment, `total_supply` is ~1B − 74M minted − 74M burned ≈ `~930M`
tokens (still a round-looking number that reflects the "the founder paid
for their bootstrap privilege" principle).

---

## Open decisions

All block-0-immutable decisions below were signed off 2026-04-18 and
minted into the live mainnet at block 0 hash
`5e8bc19ccd4449730684744951f1cca1eabb7d7c008623ea2257fd837fb63d18`.

- [x] Founder allocation: **100M** (95M staked, 5M liquid)
- [x] Founder stake at genesis: **95M of 100M**
- [x] Founder tree height: **16** (temporary — see note below)
- [x] Treasury allocation: **40M (4%)** — TREASURY_ENTITY_ID derived from `b"messagechain-treasury-v1"`
- [x] Genesis parameters doc signed off
- [ ] Code freeze — **debatable**: mainnet already live. See `docs/launch-readiness.md` for the "freeze debate."
- [ ] External audit — **pending**.  Not a block-0 decision; can be scheduled post-launch.  Shortlist: Trail of Bits / Least Authority / NCC.

**Tree height note:** launched at h=16 (not the spec's h=20) because at
mainnet mint time the pure-Python signer required ~80 minutes per block
signature at h=20, exceeding the 600s block time.  The MerkleNodeCache
(iter 10 fix) gives a 13,714× speedup, which makes h=20 feasible on
current hardware.  A deliberate key rotation to h=20 via
`messagechain rotate-key` is part of the post-launch roadmap.

## Post-launch parameter decisions (governance-mutable)

None are blocking.  Logged here so operators know they're adjustable:

- Raise `MIN_VALIDATORS_TO_EXIT_BOOTSTRAP` from 1 → 3 once ≥3 honest
  validators are active on the chain
- Bump sig_version / hash_version when a cryptographic migration is
  needed
- Publish the first signed weak-subjectivity checkpoint around block 1000
