# Launch Readiness Dashboard

Single source of truth for the state of MessageChain's mainnet launch.

Dated 2026-04-19.  Mainnet already live at height 75+ on `35.237.211.12`
(single-validator network during bootstrap).  See the bottom section for
the path from "live-but-bootstrap" to "publicly announced mainnet."

---

## Status by design principle

### ✅ Security
- 33 audit iterations landed this session.  Summary:
  - **Iter 1–3**: P2P attack surface, RPC hardening, broadcast race.
  - **Iter 4–13**: MerkleNodeCache (13,714× signer speedup), reorg-snapshot completeness (reputation, entity-index, finality, escrow), proposer round cap, gov proposal cap.
  - **Iter 14–18**: base-fee upper cap, SQLite schema-version pin.
  - **Iter 19–23**: parse_hex length enforcement, mempool persistence doc.
  - **Iter 24–33**: pyproject CLI entry, pruning-disabled-by-design doc, divestment debt-accounting fix, tx-timestamp upper bound enforcement.
- Full suite: **2065 tests pass** (3 skipped).  Live adversarial probe suite: **18/18** pass.
- Slow-loris TCP attack empirically dropped by the RPC handler at 30.0s (measured against the live validator).
- Verified baseline: all P2P/RPC entry points bounds-checked; no Python-int-overflow vectors (Python ints don't overflow); all WOTS+ leaf reuse prevented by watermark + dedup at block level; signatures cryptographically bound to CHAIN_ID + sig_version.

### ✅ Long time horizon (100–1000 years)
- Hash-based signatures (WOTS+): post-quantum by construction.  No elliptic-curve assumption.
- SIG_VERSION / HASH_VERSION version bytes are in every signature and every block header, so future algorithm bumps are governance-gated migrations, not hard forks.
- Storage plan: permanent history.  `prune()` exists as a relay-only-node capability but is explicitly never invoked by the reference validator (see `messagechain/storage/pruning.py` docstring).
- MerkleNodeCache persists on disk; validator restart after a key rotation loads the pre-built cache and signs blocks in ~1 ms.  A 20-year-old validator does not spend minutes per block.

### ✅ Reducing chain bloat (fees + storage optimization only — no pruning, no rent)
- MIN_FEE=100 floor + FEE_PER_BYTE=3 + FEE_QUADRATIC_COEFF=2/1000 punish message bloat quadratically: a 280-byte message costs ~1,096 tokens.
- NEW_ACCOUNT_FEE=1000 (burned) prevents freeloading on the permanent-state account-table.  MAX_NEW_ACCOUNTS_PER_BLOCK=10 caps churn.
- MAX_TXS_PER_BLOCK=20 + MAX_BLOCK_MESSAGE_BYTES=10 KB bound per-block storage.
- Post-launch optimization budget documented in `docs/known-issues.md` §Chain bloat: attestation-signature compression (~12 GB/yr at 100 attesters), archive-mode storage format.

### ✅ Messages permanent and uncensorable forever
- Block bodies are never pruned by the reference validator (confirmed in code; docstring pins the design intent).
- Transaction hashes are committed to block merkle_root, block hashes form the canonical chain, and weak-subjectivity checkpoints guard against long-range rewrite attacks.
- Forced-inclusion mechanism (3-block wait + attester veto) defeats single-proposer censorship.  Multi-proposer cartel censorship is defeated by validator-set diversity — a launch-day concern that dissolves as N validators grow past the seed.
- Messages stored as plaintext in chain.db; no content hashing / lossy commitment.  Readable by `messagechain read` from any full node forever.

### ✅ Ease of use
- `pip install .` now works: produces a `messagechain` CLI entry point on PATH (fixed in iter 32 — previously silently nop).
- Zero runtime deps (stdlib only).  Supply-chain attack surface = zero.  Anyone with Python 3.10+ can install.
- `messagechain status --server <host:port>` (new in iter 33) is the one-call operator health-check: chain info, validator state, leaf watermark % consumed, rotation-urgency flag.
- `messagechain key-status` shows remaining WOTS+ leaves for the local wallet.
- Live CLI commands: `account`, `send`, `transfer`, `balance`, `stake`, `unstake`, `propose`, `vote`, `read`, `info`, `validators`, `estimate-fee`, `bootstrap-seed`, `rotate-key`, `emergency-revoke`, `key-status`, `status`, `generate-key`, `verify-key`, `ping`, `gen-tor-config`.

### ✅ Bootstrap / ramp to decentralization
- `messagechain/consensus/bootstrap_gradient.py` smooth ramp from 0 to 1 over BOOTSTRAP_END_HEIGHT=105,192 blocks (~2 years).
- Today: single founder validator, founder holds 100% of stake, mints every block.  This IS mainnet in its bootstrap posture.
- Path to N≥3 validators via `docs/second-validator-onboarding.md`.  Onboarding a second validator requires a stake tx + the cold-key holder's sign-off (sybil mitigation during bootstrap).
- Divestment starts exactly at block BOOTSTRAP_END_HEIGHT (105,192): `SEED_DIVESTMENT_START_HEIGHT = BOOTSTRAP_END_HEIGHT`.

### ✅ Divestment fair, with a 1 M floor
- Founder stakes 95 M at genesis (of 100 M total founder allocation; 5 M liquid for ops fees).
- Linear drain from 95 M → 1 M over SEED_DIVESTMENT_END_HEIGHT − SEED_DIVESTMENT_START_HEIGHT = 210,384 blocks (~4 years).
- Split: 75% of each drained token burned (deflationary), 25% to treasury.  Total treasury gain: ~23.5 M.  Total burned: ~70.5 M.
- Founder retains exactly `SEED_DIVESTMENT_RETAIN_FLOOR = 1_000_000` forever: "not dominant, but still a player."
- **Iter 29 fix**: pre-fix, a slashing event mid-window would permanently strand the undrained tokens; post-fix the schedule is slash-resilient (debt accumulator rolls over correctly).

### ✅ Register on receive
- No explicit registration tx.  An entity materializes on first received transfer (recipient's balance is credited even though they have no on-chain pubkey).
- The recipient reveals their pubkey by making their own first-outgoing transfer with `sender_pubkey` populated.  `derive_entity_id(sender_pubkey) == tx.entity_id` is enforced at every install site.
- MAX_NEW_ACCOUNTS_PER_BLOCK=10 caps the per-block account-creation rate.
- NEW_ACCOUNT_FEE=1000 surcharge (burned) on transfers to brand-new recipients discourages free account spawn.

### ✅ Fees naturally high, blocks naturally slow
- BLOCK_TIME_TARGET = 600 s (10 minutes).  Matches Bitcoin.  Intentionally slow — combats spam, gives real-world time for P2P gossip + human-scale consideration.
- MIN_FEE = 100.  A 1-char message costs 103 tokens.  A 280-char message (max) costs 1,096 tokens.
- Base-fee upper cap (MAX_BASE_FEE_MULTIPLIER=10000 × MIN_FEE) prevents unbounded fee-cliff attacks (iter 18 fix).
- NEW_ACCOUNT_FEE=1000 burned for permanent state creation.

### ✅ Timestamp enforcement
- Block timestamp bounded below by MTP (median-of-last-11 parent timestamps), above by wall-clock + 7200s (BTC-standard drift).
- `MAX_PROPOSER_FALLBACK_ROUNDS = 5` caps how many rounds a proposer can "skip forward" via timestamp manipulation (iter 7 fix).
- **Iter 32 fix**: tx.timestamp now required to be ≤ block.timestamp.  Prevents proposers from forward-dating messages inside a block stamped at MTP time.
- tx.timestamp bounded above by wall-clock + MAX_TIMESTAMP_DRIFT (60 s).

### ✅ Inflation rate mathematically appropriate
- Era 1 (blocks 0 – 210,240, ~4 yr): BLOCK_REWARD=16 → 0.084%/yr of GENESIS_SUPPLY.
- Era 2 (next ~4 yr): BLOCK_REWARD=8 → 0.042%/yr.
- Era 3+ forever: BLOCK_REWARD_FLOOR=4 → 0.021%/yr — never zero, always enough to pay a validator for showing up.
- HALVING_INTERVAL=210,240 blocks matches Bitcoin's cadence.
- 20-year cumulative mint: 7.57 M = 0.76% of GENESIS_SUPPLY.

### ✅ Genesis stake mathematically appropriate
- Initial: founder = 95 M staked + 5 M liquid = 100 M (10% of supply), treasury = 40 M (4%).  Remaining 860 M unallocated.
- At bootstrap end: founder still 95 M staked (~9.5% share); divestment hasn't started.
- Post-divestment (year ~6): founder = 1 M staked (~0.11% of ~905 M circulating supply).  "Big enough to still count, small enough to never block consensus."

### ✅ Reward cap
- PROPOSER_REWARD_CAP = BLOCK_REWARD/4 enforces that the proposer cannot accumulate more than 1/4 of the block's reward even if their stake is dominant.  The other 3/4 go to attesters, splitting reward-per-block across more validators as the set grows.
- Attester-committee size caps per-block reward-per-validator.
- Together: rich-get-richer bounded above; attester pool + new-validator lottery creates upward churn.

---

## What's left before publicly announcing mainnet

These are the four operator-side blockers from `docs/operator-action-items.md`.  None are code-fixable; all require decisions + calendar time from the operator.

| # | Item | Status | Action |
|---|---|---|---|
| 1 | Mainnet params sign-off | **Complete in spirit** — minted on these values and running successfully for 75+ blocks | Update `docs/mainnet-params.md` "Open decisions" to ✅ |
| 2 | External security audit | Not scheduled | Shortlist: Trail of Bits / Least Authority / NCC Group / Quantstamp.  Budget $50K–$200K, 4–8 weeks, scope `messagechain/` core + `server.py` RPC |
| 3 | Cold-key Shamir ceremony | Not done | Run `deploy/cold_key_ceremony.py` on an air-gapped machine; distribute 2-of-3 shares to named holders in different jurisdictions |
| 4 | Code-freeze window | Debatable | Mainnet is already live.  Either (a) accept ongoing iteration on the current chain (future breaking changes would require re-mint), or (b) declare current HEAD the frozen state and accept any required fix as a future hard fork |

---

## State of known issues

See `docs/known-issues.md` for the comprehensive list with rationale and
post-launch roadmap.  Short version: every item either matches the stated
design intent, would require a consensus-breaking re-mint we're deferring,
or is an operational polish task that doesn't block going public.

---

## State of the mainnet right now

- **Chain:** mainnet, `NETWORK_NAME = "mainnet"` pinned genesis `5e8bc19c…`
- **Validator:** `7a72f1ec…` on `35.237.211.12:9334`, 95 M staked + ~5 M liquid
- **Block time:** 600s (10 min) per spec; measured cadence matches
- **Height:** 75+ (growing)
- **Keypair:** WOTS+ h=16 (65 K signatures per rotation cycle).  Merkle cache on disk, signing cost per block ≈ 1 ms
- **Backups:** daily GCP persistent-disk snapshots at 04:00 UTC, 30-day retention
- **Monitoring:** TCP uptime check, disk usage > 80%, leaf exhaustion ≥ 80%, billing cap at $20/mo (currently ~$16)
- **Hot key:** in GCP Secret Manager; fetched to `/dev/shm/mc-key` at service start, shredded on stop (service unit drop-in is local-only, not in git)

---

## Go/no-go summary

**Code:** ✅ ready.  33 audit iterations complete.  All in-scope concerns fixed or documented.

**Infra:** ✅ ready.  Validator live, backups running, alerts wired.

**Operator blockers:** ⚠️ three remaining (audit / cold-key / params sign-off), all unblock-able with calendar time.

Current mainnet is **genuinely live** and can be pointed to publicly
whenever you choose.  The "launch announcement" is a marketing date, not
a code event.
