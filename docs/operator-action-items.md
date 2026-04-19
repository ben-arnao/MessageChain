# Operator Action Items (Post-Launch Tracker)

Status: **mainnet is live** at `35.237.211.12:9334` as of 2026-04-18.
What remains is operator work that Claude can't do — ordered by urgency.

For the current overall state, see
[`docs/launch-readiness.md`](launch-readiness.md).

---

## ✅ Completed

### Mainnet parameters signed off (2026-04-18)
- Founder allocation: 100M (95M staked, 5M liquid)
- Treasury allocation: 40M (4% of genesis supply)
- CHAIN_ID: `messagechain-v1`
- Block-0 hash: `5e8bc19c…` pinned in `messagechain/config.py`
- All "Open decisions" in `docs/mainnet-params.md` resolved
  except the still-debatable code-freeze window (see below).

### Governance H6 policy
- Chose (b): tally against current stake.  Slashed-to-zero voters
  contribute nothing.  Landed in commit 6d02797 / merged 7388054.

### Hot-key custody
- Migrated to GCP Secret Manager (operator-specific; not in git).
- Plaintext keyfile destroyed.
- Service drop-in fetches at ExecStartPre, shreds at ExecStopPost.

### Operational hardening
- Daily GCP disk snapshots at 04:00 UTC, 30-day retention
- TCP uptime + email-alert monitoring
- Disk > 80% and WOTS+ leaf > 80% log-based alerts
- systemd unit hardened (ProtectKernel*, SystemCallFilter, MemoryMax)
- `chain.db` at 0640 (group `adm` read-only), LLMNR disabled, static IP
- Billing kill-switch at $20/mo (current spend ~$16/mo)
- journald capped 500M / 1 month

### Runbooks written
- `docs/key-rotation-runbook.md` — WOTS+ rotation workflow
- `docs/backup-restore-runbook.md` — 3 disaster-recovery scenarios

---

## ⏳ Remaining before a public announcement

### 1. External security audit — **pending, NOT blocking mainnet operation**

Mainnet is running without external audit.  That's a risk an operator
accepts for going live early.  A post-launch audit has these benefits:
- Catches class-of-bug the 33 internal audit iterations couldn't see
- Reputational signal to new validators / users
- De-risks the eventual N≥3 validator state

Shortlist:
- **Trail of Bits** — blockchain + cryptography specialists, ~$100–200K, 4–8 weeks
- **Least Authority** — decentralized systems + privacy focus, similar range
- **NCC Group** — large general-purpose, broader but less crypto-specific
- **Quantstamp** — cheaper option, ~$25–50K, lighter touch

Scope to propose: `messagechain/` core (signatures, consensus, governance,
stake accounting) + `server.py` RPC + `deploy/cold_key_ceremony.py`.
See `docs/security-model.md` for the full in-/out-of-scope breakdown.

Budget: dollars + 4–8 weeks calendar time.

### 2. Cold-key Shamir ceremony — **pending**

Today's validator uses hot-key-only authority (no cold-key separation).
This means an attacker who compromises the GCP Secret Manager entry
can drain the founder's stake.  The mitigation is a cold-key
2-of-3 Shamir ceremony that lets us `set-authority-key` to a key whose
private material is only reconstructable from 2 of 3 shares stored
offline by named holders in different jurisdictions.

Steps (see `deploy/cold_key_ceremony.py`):

- [ ] Pick 2 trusted parties as share holders (founder + 2 = 3 total).
      Different jurisdictions preferred.  Named individuals, not roles.
- [ ] Acquire an air-gapped machine (old laptop / never-networked SD-booted
      Raspberry Pi).  Fresh install of any Linux with Python 3.10+.
- [ ] Copy `deploy/cold_key_ceremony.py` to the air-gapped machine
      via USB.  Do not network.
- [ ] Run: `python deploy/cold_key_ceremony.py generate --out-dir out/`
- [ ] Verify reconstruction BEFORE destroying originals:
      `python deploy/cold_key_ceremony.py recover out/cold-share-1.txt out/cold-share-2.txt`
      — confirm the recovered public key matches `out/cold-key-public.txt`.
- [ ] Copy each `cold-share-N.txt` to the designated holder's physical
      storage (paper + safe-deposit box ideal).  No digital copies on
      networked devices.
- [ ] Promote the cold public key on-chain:
      `messagechain set-authority-key --authority-pubkey <hex>`
- [ ] Shred all share files on the generation machine.
- [ ] Wipe the generation machine.
- [ ] Document shareholder identities + physical share locations in a
      PRIVATE ops memo (not on-chain, not in this repo).

### 3. Drill key rotation — **pending**

- [ ] Generate a throwaway testnet key offline.
- [ ] Follow `docs/key-rotation-runbook.md` end-to-end against the live
      testnet validator.  DON'T use the production founder key.
- [ ] Time the exercise.  Fix any ambiguity in the runbook.

### 4. Drill backup/restore — **pending**

- [ ] Pick a snapshot from 2 days ago.
- [ ] Follow `docs/backup-restore-runbook.md` Scenario A against a
      throwaway disk.  Confirm chain returns to expected height.
- [ ] Measure time-to-recover (expect 30–60 min).
- [ ] If any step is ambiguous, fix the runbook.

---

## 🔄 Nice to have, not blocking

### Tor / onion endpoint (optional)

- [ ] Install `tor` on the validator VM
- [ ] Configure a hidden service pointing at `127.0.0.1:9334`
- [ ] Document the `.onion` address alongside the IPv4
- [ ] Test CLI client over Tor

Useful for users in adversarial jurisdictions.  Out-of-scope for MVP
mainnet; keep on the list.

### Re-drill with multiple validators

Once you onboard validator #2 (see
`docs/second-validator-onboarding.md`):

- [ ] Both validators do an independent key rotation drill on their own
      keys
- [ ] Both validators do a backup/restore drill
- [ ] Confirm attestation flow works end-to-end with 2 live validators
- [ ] After 3+ validators: propose raising
      `MIN_VALIDATORS_TO_EXIT_BOOTSTRAP` from 1 to 3 via governance

### Post-launch code migrations (tracked in known-issues.md)

- Rotate founder key from h=16 → h=20 now that MerkleNodeCache makes
  it feasible
- Generate + publish first signed weak-subjectivity checkpoint around
  block 1000
- Decide on attestation-signature archival format (post-launch
  storage optimization)

---

## The "code freeze" question

The original mainnet-launch doctrine said "4 weeks of no
consensus-breaking merges before cutting mainnet genesis."  You didn't
do that — mainnet was cut with breaking changes still landing.

Paths forward:

- **(A) Accept the cut.**  Current mainnet is the canonical chain.
  Any future consensus-breaking fix requires either a hard-fork
  coordinated upgrade or a full re-mint (wipes history).
- **(B) Pre-announcement re-mint.**  Declare the current mainnet
  "pre-production," run a 4-week freeze, then re-mint and re-announce.
  Loses 75+ blocks of real history but aligns with the original
  doctrine.

Either path is defensible.  Most chains launch with (A).  Recommended:
(A) + make the external audit a blocker on the public announcement,
not on the chain's existence.
