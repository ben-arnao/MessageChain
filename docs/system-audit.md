# MessageChain System Audit

Comprehensive pre-launch audit covering correctness, security, and
economic-design goals. Running doc — check items off as they're
verified, append concerns to the relevant section.

**Status legend**: `[ ]` pending · `[x]` verified OK · `[!]` concern raised · `[-]` n/a

**First pass completed 2026-04-18.** Findings below are from code
review + napkin math + partial live testing. Items marked `[x]` have
been traced end-to-end. Items marked `[!]` have open concerns. Items
still `[ ]` need deeper review before mainnet.

---

## 1. Bootstrap phase (ramp to decentralization)

**Goal**: founder secures the chain early; other validators can join
and accumulate stake/reputation; chain gradually decentralizes.

- [x] **`bootstrap_progress` formula** — `height / BOOTSTRAP_END_HEIGHT`, clamped to [0,1]. `BOOTSTRAP_END_HEIGHT = 105_192` (~2 years at 600s/block). Code at `messagechain/consensus/bootstrap_gradient.py:88`.
- [!] **`MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 1`** (config.py:452). Per comment in config.py: "this constant survives only as the finality floor — 2/3 of stake is not meaningful finality if only one or two validators exist. Tests override this dynamically to 1 for single-validator chains." **For mainnet, must be raised back to 3 — a lone founder-validator is not a chain.** Value in repo was recently lowered, presumably for prototype.
- [x] **Bootstrap window length (~2 years)** — reasonable. Long enough for a real validator set to form; short enough that lock-in from the founder isn't permanent.
- [x] **Post-bootstrap behavior diverges from pre-bootstrap** — several gates drop at progress=1.0: `PROPOSER_REWARD_CAP` kicks in, lottery bounty fades to 0, attester-committee seed-exclusion disappears, escrow window for attestor rewards hits 0. See grep for `bootstrap_progress` in blockchain.py.
- [x] **Divestment starts at bootstrap end** — `SEED_DIVESTMENT_START_HEIGHT = BOOTSTRAP_END_HEIGHT` (105_192). Keeps the transition tied to a single knob.

**Concerns**:
- `MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 1` in the repo is a prototype setting; must be 3 before mainnet. Ship a test that asserts this at config-load in mainnet mode.
- There's no hard gate preventing the founder from running a second validator key that's "pseudo-independent" and pretending to satisfy the N≥3 finality floor. The deployment guide needs to address validator identity distinctness, not just count.

## 2. Register-on-receive / receive-to-exist

**Goal**: new entity materializes on its first received transfer; first
outgoing transfer carries the pubkey to install on-chain.

- [x] **Transfer to unknown recipient creates state entry** — confirmed via live test 2026-04-17: transfer 5000 to brand-new address `mc1c158a...` accepted with recipient balance initialized.
- [x] **First-spend with `include_pubkey=True` installs pubkey** — `messagechain/core/transfer.py:228` sets `sender_pubkey` on tx; blockchain applies it on first-spend.
- [x] **Subsequent spends with `include_pubkey=True` are rejected** — verified via transfer.py: "non-empty on a subsequent transfer is rejected" (comment + code path).
- [x] **`NEW_ACCOUNT_FEE = 1000` (burned) surcharge active** — confirmed via live test: transfer at fee=100 to new recipient was correctly rejected with `"Transfer to brand-new recipient requires fee >= 1100 (MIN_FEE 100 + new-account surcharge 1000); got 100"`.
- [x] **Per-block cap: `MAX_NEW_ACCOUNTS_PER_BLOCK = 10`** — caps mass-creation bloat. At 10 new accounts/block × 52,596 blocks/year = ~526K new accounts/year max, or ~1.4K/day.
- [ ] **Stress test: receive → spend without first-spend-pubkey** — not yet tested. Should reject because no pubkey is on-chain to verify the signature.
- [ ] **Stress test: forged first-spend pubkey** — attempt to include a pubkey that doesn't correspond to the signing key. Signature verification should catch it, but worth direct test.

## 3. Natural inflation + supply curve

**Goal**: modest inflation offsets natural loss; not an attack on
holders; not so low the chain dies from insufficient validator
incentive.

- [x] **Constants sane**: GENESIS=1B, BLOCK_REWARD=16, HALVING=210,240 blocks (~4yr), FLOOR=4. Halving interval ≈ 4 years exactly at 600s blocks.
- [x] **Year-1 inflation: 0.084% of genesis**. Era 2 (yr 4–8): 0.042%. Era 3+ (yr 8+): 0.021% forever at floor.
- [x] **20-year cumulative mint: 7.57M tokens = 0.76% of genesis**. Long-run: supply grows ~0.02%/yr forever at floor.
- [x] **Proposer/attestor split: 1/4 proposer, 3/4 attestors** (PROPOSER_REWARD_NUMERATOR=1, DENOMINATOR=4). Sensible — rewards the attestation work that actually secures the chain.
- [x] **Halving math clean** — BLOCK_REWARD=16 is power of 2 (asserted at config.py:300); halvings: 16→8→4, then floor.
- [x] **Floor behavior**: halving stops at 4 forever (BLOCK_REWARD_FLOOR=4). Guarantees validators always have SOMETHING to earn.

**Napkin math (done)**:
```
Blocks/year: 52,596 (at 600s)
Era 1 (yr 0-4):  0.084%/yr mint
Era 2 (yr 4-8):  0.042%/yr mint
Era 3+ (yr 8+):  0.021%/yr mint (floor forever)
20-year total:   0.76% mint
```

**Fee math**:
```
1-byte msg:   103 tokens
32-byte msg:  198 tokens
280-byte msg: 1,096 tokens
Max block:    ~21,920 tokens (20 × full 280-byte messages)
```

**Verdict**: inflation is deliberately low — nearly deflationary after
year 8 relative to a growing-activity chain. Fees carry most of the
validator income long-term. The BLOCK_REWARD_FLOOR=4 ensures the
chain never rug-pulls validators to zero-block-reward.

## 4. Reward caps (anti-compound)

**Goal**: rich validators don't compound disproportionately.

- [x] **`PROPOSER_REWARD_CAP = 4` tokens per block** (BLOCK_REWARD × 1/4). During bootstrap it's bypassed (`effective_cap = reward if is_bootstrap`); post-bootstrap the cap is enforced in state sim (`blockchain.py:2202`) and at apply (`blockchain.py:4297`).
- [x] **Excess routing**: proposer-as-attestor excess is clawed back into the proposer share and treasury-diverted if it exceeds the cap (see comment at blockchain.py:4381-4384).
- [x] **Attester pool sized by remaining reward**: `attester_pool = reward - proposer_share`. With BLOCK_REWARD=4, that's 3 tokens across the committee, 1 token/slot (`ATTESTER_REWARD_PER_SLOT`).
- [x] **No obvious un-capped reward path**: lottery is capped at `LOTTERY_BOUNTY = 100` tokens, fades to 0 post-bootstrap. Governance treasury spends are gated on supermajority.

**Verdict**: the cap is real and enforced on the hot path. Excess
goes to treasury rather than to the largest staker, which is the
correct direction.

## 5. Quantum resistance

**Goal**: signing + hashing primitives remain secure under a
quantum adversary.

- [x] **Hash: SHA3-256** — `HASH_ALGO = "sha3_256"` (config.py:86). SHA3 (Keccak) has no known quantum attack beyond Grover's √N speedup. Post-Grover security: 128 bits, which is still strong.
- [x] **Signatures: WOTS+ hash-based** — W=16, chains=64, variable Merkle tree height (MERKLE_TREE_HEIGHT configurable per entity, default=20 for mainnet). Quantum-safe by construction (relies only on one-way hash, not on integer factorization or discrete log).
- [x] **No classical crypto in signing path** — grep confirmed no ECDSA/RSA/Ed25519/secp256k1 in signature code.
- [x] **WOTS+ leaf reuse strictly rejected** — `leaf_watermark` tracked on-chain; re-use errors out both at sign time and at server acceptance. See `messagechain/crypto/keys.py` + `_bump_watermark` in blockchain.
- [x] **Per-entity tree height** (recent: `45f0f66 Carry WOTS+ tree_height in chain state per entity`). Heterogeneous validators (prototype h=16, production h=20) coexist.
- [x] **Hash/sig version bytes embedded** — `HASH_VERSION_CURRENT` and `SIG_VERSION_CURRENT` at config.py:108-111. Upgrade path exists: governance proposal bumps version, accept old during migration window.

**Verdict**: quantum resistance is a first-class design goal, enforced
throughout. The hash-and-sig-version registers mean the chain can
absorb a future Q-safe algorithm swap without a hard reset.

## 6. Slow blocks + high fees (by design)

**Goal**: consensus prioritizes durability over throughput.

- [x] **`BLOCK_TIME_TARGET = 600s` (10 min)** on production (same as Bitcoin). Prototype env can override via `MESSAGECHAIN_BLOCK_TIME_TARGET`.
- [x] **`MIN_FEE = 100` + `FEE_PER_BYTE = 3` + quadratic coefficient** make even tiny messages expensive: 103 tokens for a 1-byte message. 280-byte max-size message: 1,096 tokens.
- [x] **`MAX_TXS_PER_BLOCK = 20` + `MAX_BLOCK_MESSAGE_BYTES = 10,000`** — byte budget bounds block size firmly, not just tx count.
- [x] **EIP-1559 base-fee adjustment** — `BASE_FEE_MAX_CHANGE_DENOMINATOR = 8` (12.5%/block), target 10 txs/block. Standard, well-understood behavior.
- [x] **Comparative**: a 280-byte message on MessageChain costs ~1,096 tokens of fee; at max block saturation for a year, fee income could exceed the entire genesis supply.

**Verdict**: the fee structure is designed to make MessageChain
unsuitable for high-frequency spam and well-suited for low-volume,
durable messages. Aligns with the project's stated "100 to 1000+
year" goal.

## 7. Divestment schedule (founder)

**Goal**: founder stake decays to a floor post-bootstrap.

- [x] **Start: `BOOTSTRAP_END_HEIGHT` (105,192 = ~2 years)**. End: +210,384 blocks later (~4 more years). Total 6-year founder presence.
- [x] **Rate: linear over 210,384 blocks**. Predictable, non-discretionary — no kill-switch, no founder override.
- [x] **Drain target: 75% burn + 25% treasury** (`SEED_DIVESTMENT_BURN_BPS=7500` / `SEED_DIVESTMENT_TREASURY_BPS=2500`). Majority of divested stake is burned, which is deflationary and aligns with "long-term durability" over "treasury enrichment."
- [x] **Retained floor: `SEED_DIVESTMENT_RETAIN_FLOOR = 1,000,000` tokens (0.1% of genesis)**. Per comment: "roughly 10x the expected average non-seed validator stake after bootstrap." Founder ends up a big-but-not-dominant stakeholder.
- [x] **Non-discretionary**: enforced in the block apply path. Changing the floor is a hard fork (consensus constant).

**Verdict**: divestment is well-designed. Founder keeps meaningful
stake to stay engaged (~1M tokens = 0.1% of supply). Rest mechanically
unwinds. 75% burn means the chain becomes strictly more scarce over
the 4-year window.

## 8. Genesis stake sizing (founder dominance window)

**Goal**: founder enough to solo-secure during bootstrap, not
enough to permanently veto post-bootstrap.

- [x] **Recommended founder stake**: `RECOMMENDED_STAKE_PER_SEED = 33_000_000` × 3 seeds = 99M (9.9% of supply) if using `build_launch_allocation`. Testnet today uses 50K+50K for a single validator; this is NOT production-sized.
- [!] **Mainnet stake NOT yet decided** — going-live.md still has "Final genesis parameters agreed" unchecked. Current prototype uses 50K/50K split which is test-scale.
- [x] **Path for external validators to reach meaningful stake**: bootstrap lottery mints ~73K tokens over bootstrap (LOTTERY_BOUNTY=100 × 105,192 blocks / LOTTERY_INTERVAL=144 = 73,050). Plus attester rewards. External validators can accumulate ~1-10K stake in a bootstrap window, which is enough to participate but not dominate.
- [x] **Post-bootstrap founder floor (1M) < governance veto threshold (2/3 of total stake)**: 1M on a ~1B chain = 0.1%, nowhere near 66.7% veto. Can't block proposals alone.

**Concerns**:
- The allocation table for mainnet is still the operator's choice. The `build_launch_allocation` default (99M across 3 seeds) is a strong recommendation, but there's no hard-coded enforcement. A misconfigured mainnet launch could allocate way too much to the founder.

## 9. Early-validator rewards + reputation growth

**Goal**: new validators earn something from day one; reputation
grows with honest behavior.

- [x] **Bootstrap lottery**: `LOTTERY_INTERVAL = 144` (~daily at 600s/block), `LOTTERY_BOUNTY = 100` tokens. Zero-stake validators can win. Fades linearly to 0 at bootstrap end.
- [x] **`REPUTATION_CAP = 10,000`** — reputation saturates; not infinite compounding. Sensible.
- [x] **Reputation updates on attestation + proposal** (see `messagechain/consensus/reputation_lottery.py`).
- [x] **Seed exclusion from attester committee during first half of bootstrap** — non-seed validators get elevated attester selection chance early when they need rewards most.
- [x] **Attester-reward escrow**: `ATTESTER_ESCROW_BLOCKS = 12,960` (~90 days at 600s). Rewards locked for 90 days during bootstrap so grief-then-quit doesn't pay. Escrow window shrinks to 0 as bootstrap_progress → 1.

**Verdict**: the "early validator earns while building trust" loop
is well-engineered. Zero-stake joiners are viable from day one via
lottery; they accumulate reputation + tokens over bootstrap and can
self-stake. The 90-day escrow discourages churn.

## 10. Slashing

**Goal**: double-sign and similar byzantine behaviors cost the
offender. Evidence submission is open and incentivized.

- [x] **Evidence types**: double-proposal (same slot, different blocks) + double-attestation (same slot, different targets). See `messagechain/consensus/slashing.py`.
- [x] **`SLASH_PENALTY_PCT = 100`** — full stake slash on confirmed evidence.
- [x] **`SLASH_FINDER_REWARD_PCT = 10`** — 10% of slashed amount goes to the evidence submitter. Skin in the game for watchers.
- [x] **Evidence submittable by any node**: the equivocation watcher (commit `f04e89e`) auto-files evidence from gossip observations. Not gated to the victim.
- [x] **Replay protection**: processed evidence hashes are persisted (`processed_evidence` column in chaindb). Same evidence can't pay the finder twice.
- [x] **Inactivity leak (`messagechain/consensus/inactivity_leak.py`)** — quadratic drain on inactive validators.
- [!] **Bootstrap-window slashing pinned** — commit `19ffa01`: "verify double-sign at progress ~= 0 is slashed." So bootstrap does not disable slashing. Good.
- [ ] **Honest-near-miss test**: timestamp skew + late block arrival shouldn't trigger slashing. Needs direct test.

## 11. Governance

**Goal**: on-chain proposals + stake-weighted voting.

- [x] **Proposal fee: `GOVERNANCE_PROPOSAL_FEE = 10,000`** — 10x key rotation fee. High enough to deter spam, low enough that a legitimate proposer can afford it.
- [x] **Voting window: `GOVERNANCE_VOTING_WINDOW = 1,008` blocks (~7 days)**. Real people can participate across time zones.
- [x] **Supermajority: strict >2/3 of total eligible weight** (numerator=2, denominator=3). Silence counts as NO.
- [x] **Denominator is total eligible, not participants**: implicit turnout floor. A quiet week means self-serving proposals fail.
- [x] **Vote fee: `GOVERNANCE_VOTE_FEE = 100`** — same as MIN_FEE. Token sybil vote spam is expensive.
- [x] **Treasury spend semantics**: `TreasurySpendTransaction` class exists, auto-executes post-quorum via block pipeline. Tested in `test_governance_tx_block_pipeline`.

**Verdict**: governance is well-structured for a slow, deliberate
chain. The strict supermajority + denominator-is-total-eligible
prevents low-turnout capture. Fee schedule discourages spam without
gatekeeping legitimate users.

## 12. Network stress (break-the-thing testing)

From live tests today (2026-04-17 / 2026-04-18):

- [x] **Replay** — same tx twice: 2nd rejected with "Invalid nonce" or "duplicate"
- [x] **Tampered tx** — message mutated after signing: rejected with "Internal error" (raw cause logged now)
- [x] **Non-ASCII message** — `create_transaction` raises "Non-printable-ASCII character..."
- [x] **Fee=1** — `create_transaction` raises "Fee must be at least N..."
- [x] **Transfer to self** — `create_transfer_transaction` raises "Cannot transfer to yourself"
- [x] **Overdraft transfer** — server rejects "Insufficient spendable balance..."
- [x] **Negative / zero amount** — `create_transfer_transaction` raises "Transfer amount must be positive"
- [x] **Dust transfer (5 < DUST_LIMIT=10)** — rejected (needs re-verification against receive-to-exist model)
- [x] **Nonce gap** — "Invalid nonce: expected N, got N+K"
- [x] **Sequential nonces via mempool** — accepted consecutively for message + transfer + stake
- [x] **Oversized message (281 chars)** — "Message exceeds 280 characters"
- [x] **RPC rate limit 300/min** enforced per-IP
- [x] **Admin vs public RPC split** enforced (admin methods require auth when RPC_AUTH_ENABLED=True)
- [ ] **Forged WOTS+ signature** — not directly tested
- [ ] **WOTS+ leaf reuse at submission time** — server has a check; not stress-tested
- [ ] **Expired tx (timestamp too old)** — not directly tested
- [ ] **Future tx (timestamp > MAX_TIMESTAMP_DRIFT=60)** — not directly tested
- [ ] **Oversized RPC payload (>1MB)** — not directly tested
- [ ] **Malformed JSON-RPC request** — not directly tested

## 13. CLI commands sweep

Tested against VM 35.237.211.12:9334 today (2026-04-18 post-key-rotation):

- [x] `get_chain_info` (via RPC)
- [x] `get_entity` (via RPC)
- [x] `get_nonce` (via RPC)
- [x] `get_messages` (via RPC)
- [x] `list_validators` (via RPC) — stake=0 display bug noted
- [x] `get_fee_estimate` (via RPC)
- [x] `submit_transaction` (via RPC)
- [x] `submit_transfer` (via RPC)
- [x] `stake` (via RPC)
- [x] `unstake` (via RPC)
- [ ] End-user CLI (`python -m messagechain send/balance/transfer/...`) — `getpass`-blocked in this shell, need separate verification
- [ ] `rotate-key`, `set-authority-key`, `emergency-revoke`, `propose`, `vote` — unverified

## 14. Concerns raised

Ordered by severity.

### Must fix before mainnet

1. **`MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 1`** currently in config.py:452. This is a prototype/test setting. Mainnet MUST be 3 to prevent a single-validator chain from crossing into post-bootstrap state where finality "completes" without actual consensus. **Action**: add an assert that raises if `NETWORK_NAME == "mainnet"` and value < 3.

2. **Mainnet genesis parameters undecided**: founder stake, tree height, treasury allocation, fee schedule — none frozen. Must be committed + tagged before mainnet cut. See going-live.md.

3. **Founder key is a single hot file on one VM**. Post-rotation (today), the new key `2195a4be…` is safer than the compromised one, but still lacks HSM/KMS backing and 2-of-3 Shamir split per the Key Custody section of going-live.md.

4. **Chain re-minted 4× today due to parallel consensus-breaking merges**. Domain-separation tags, receive-to-exist, wire-format v1, key rotation. Production needs a **code freeze window** (no consensus-breaking merges) before mainnet genesis is pinned.

### Should fix soon

5. **`list_validators` shows stake=0 for a validator with real staked balance** (verified today). `get_entity` shows the correct staked amount. Two data paths; one is stale. Cosmetic but misleading.

6. **Round-number anomaly on block production** — blocks regularly propose at round 15+ rather than round 0. Wastes CPU + delays consensus. Not a correctness bug but an efficiency bug. See today's investigation.

7. **4 flaky tests in the full suite** (pre-existing, not caused by today's work). Pass individually, fail together. Indicates test-state leakage — real risk that a real bug gets masked.

8. **`register_entity_for_test` backdoor** (`tests/__init__.py:32-42`) installs a pubkey directly, bypassing the receive-to-exist flow. ~65 tests use it. They're not testing the live pubkey-install path. Long-term: migrate tests to actually fund + spend to install the key.

### Minor

9. No fork-detection / disk-usage / leaf-exhaustion alerting yet (liveness is done). See going-live.md Operations section.

10. Backup+restore runbook not yet written (daily snapshots are running but restore procedure is undocumented).

11. VM's `config_local.py` is not under version control (intentional) but the deployment flow should guarantee it's in place. A fresh VM re-clone without config_local.py reverts to production posture which may crash if checkpoints aren't shipped.

12. `NEW_ACCOUNT_FEE = 1000` is burned, not routed to treasury. If the design intent shifts toward treasury, it's a one-line flip. Document the choice.

### Live test items not yet run

13. Forged WOTS+ signature direct test
14. WOTS+ leaf-reuse attack direct test
15. Expired / future timestamp direct tests
16. Oversized RPC payload (>1MB) direct test
17. Honest-near-miss slashing test (clock skew, late block)
18. Receive → spend without first-spend-pubkey reveal (does it correctly reject?)
19. End-user CLI sweep (`python -m messagechain ...`) with real key prompt

---

## Next steps

Before pronouncing "production ready," at minimum:

1. **Gate `MIN_VALIDATORS_TO_EXIT_BOOTSTRAP`** — assert ≥3 in mainnet mode
2. **Decide mainnet genesis parameters** and freeze them in config
3. **Set up HSM/KMS for founder hot key + 2-of-3 Shamir split for cold key** (Key Custody section of going-live.md)
4. **Recruit ≥2 independent validators** (network needs it for real finality)
5. **External security audit** — Trail of Bits, Least Authority, NCC Group, etc.
6. **Run the remaining stress tests in section 12** — forged sig, leaf reuse, timestamp bounds, oversized payloads
7. **Run end-user CLI sweep** — all README-listed commands end-to-end with real key prompt flow
8. **Write and drill backup/restore procedure**
9. **Code freeze window** — no consensus-breaking merges for at least one month before mainnet genesis mint

The **economic design is sound** — inflation, fees, caps, divestment,
reputation, and slashing are all well-reasoned and implemented. The
**operational posture is improving but not mainnet-ready** — single
key, single VM, unverified end-to-end CLI, pending audit.
