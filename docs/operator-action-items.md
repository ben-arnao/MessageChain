# Operator Action Items Before Mainnet

Everything Claude can't do for you.  Ordered by when you should start.

## This week

### 1. Sign off on mainnet parameters

- [ ] Review [`docs/mainnet-params.md`](mainnet-params.md) line-by-line.
- [ ] Confirm or adjust founder allocation (proposed 100M of 1B = 10%).
- [ ] Confirm founder tree height (proposed 20, ~18 months per key).
- [ ] Confirm treasury allocation (40M = 4%).
- [ ] Confirm CHAIN_ID (`messagechain-v1`).
- [ ] Move the doc's "Open decisions" checkboxes to done.

Once signed, these become block-0 immutable.  No changes post-mint
without a hard fork.

### 2. Decide the H6 governance policy

Audit item H6: a slashed validator's pre-slash vote currently still
counts at full weight (stake is snapshotted at proposal creation).
Two options:

- **(a) Current behavior** — votes count at snapshot weight regardless
  of subsequent slashes/revokes.  Simpler, deterministic, predictable.
- **(b) Tally against current stake** — re-evaluate each voter's
  weight at window close.  Slashed-to-zero voters contribute nothing.

Agent 2 is implementing option (b) as the safer default.  If you
prefer (a), flag it and I'll revert that agent's change.

### 3. Engage a security audit firm

This is weeks of calendar time, start now.  Shortlist:

- **Trail of Bits** — blockchain + cryptography specialists, ~$100–200K, 4–8 weeks
- **Least Authority** — focus on decentralized systems + privacy, similar range
- **NCC Group** — large general-purpose firm, broader but less crypto-specific
- **Consensys Diligence** — Ethereum-heavy, might not fit hash-signature design as well
- **Quantstamp** — cheaper option, ~$25–50K, lighter touch

Scope to propose: `messagechain/` core (signatures, consensus, governance,
stake accounting) + `server.py` RPC surface.  Estimated 6–8 weeks
including remediation.

Budget the money and the calendar time.  Do NOT cut mainnet genesis
before the audit completes.

## Over the next few weeks

### 4. Run the cold-key Shamir ceremony

- [ ] Pick 2 trusted parties to hold cold-key shares (founder + 2 = 3 total).
      Different jurisdictions preferred.  Named individuals, not roles.
- [ ] Acquire an air-gapped machine (old laptop, never-networked SD-booted
      Raspberry Pi, etc.).  Fresh install of any Linux with Python 3.10+.
- [ ] Copy `deploy/cold_key_ceremony.py` to the air-gapped machine via
      USB.  Do not network the machine.
- [ ] Run: `python deploy/cold_key_ceremony.py generate --out-dir out/`
- [ ] Verify reconstruction works BEFORE destroying originals:
      `python deploy/cold_key_ceremony.py recover out/cold-share-1.txt out/cold-share-2.txt`
      — confirm the recovered public key matches `out/cold-key-public.txt`.
- [ ] Copy each `cold-share-N.txt` to the designated holder's physical
      storage (paper + safe-deposit box is ideal).  No digital copies
      on networked devices.
- [ ] Commit the public key on-chain:
      `python -m messagechain set-authority-key --authority-pubkey <hex>`
- [ ] Shred all share files on the generation machine.
- [ ] Wipe the generation machine.
- [ ] Document shareholder identities + physical share locations in a
      PRIVATE ops memo (not on-chain, not in this repo).

### 5. Drill key rotation

- [ ] Generate a throwaway testnet key offline.
- [ ] Follow `docs/key-rotation-runbook.md` end-to-end against the live
      testnet validator.  DON'T use the production founder key for the
      drill.
- [ ] Time the exercise.  Fix any ambiguity in the runbook.

### 6. Drill backup/restore

- [ ] Pick a snapshot from 2 days ago.
- [ ] Follow `docs/backup-restore-runbook.md` Scenario A against a
      throwaway disk.  Confirm the chain comes back at the expected
      height.
- [ ] Measure time-to-recover.  Should be 30–60 min.
- [ ] If any step is ambiguous, fix the runbook.

### 7. Tor / onion endpoint (optional but recommended)

- [ ] Install `tor` on the VM.
- [ ] Configure a hidden service pointing at `127.0.0.1:9334`.
- [ ] Document the `.onion` address in `CLIENT_SEED_ENDPOINTS`
      alongside the IPv4.
- [ ] Test that a CLI client with Tor installed can reach the node
      via `.onion`.

Useful for users in adversarial jurisdictions or operating behind
national firewalls.  Out-of-scope for MVP mainnet; keep on the list.

## Before mainnet cut

### 8. Code freeze window

After the last consensus-breaking merge lands (and its deploy is
verified stable on testnet), **freeze the main branch** for at least
4 weeks before minting mainnet genesis.  Any new commits during
freeze:

- Documentation only, OR
- Bug fixes that don't change block/tx serialization, OR
- Tests

**No** schema changes, no new tx types, no new state fields,
no protocol bumps.  Breaks during this window reset the 4-week
clock.  This is what prevents another "4 re-mints in one day"
scenario at the worst possible time.

### 9. Mainnet mint

Once 1–8 are complete:

- [ ] Re-derive the founder key on an air-gapped machine from the
      paper backup.  Verify derived entity_id matches production.
- [ ] On the air-gapped machine, run `deploy/launch_single_validator.py`
      with the sanctioned mainnet parameters from `docs/mainnet-params.md`.
- [ ] Capture the resulting block-0 hash.  Paste into
      `_MAINNET_GENESIS_HASH` in `messagechain/config.py`.
- [ ] Flip `NETWORK_NAME = "mainnet"`, commit, tag release.
- [ ] scp the mainnet `chain.db` to the production VM (destroying the
      testnet chain).
- [ ] Restart the validator.  Verify block-0 hash matches the pin.
- [ ] Announce the mainnet genesis hash publicly so anyone who clones
      the repo and starts a validator gets a pin-verifiable chain.

## Already done (for reference)

- Hot-key custody: migrated to operator's secrets backend (GCP
  Secret Manager on this VM); plaintext keyfile destroyed.
- Daily disk snapshots: 04:00 UTC, 30-day retention.
- Liveness monitoring: TCP uptime check + email alert on downtime.
- Disk usage alert: > 80% triggers email.
- Leaf-exhaustion log alert: WOTS+ `>80%` usage triggers email.
- systemd unit hardened: `ProtectKernel*`, `SystemCallFilter`,
  `MemoryMax`, etc.
- Journald capped at 500M / 1 month.
- `chain.db` 0640 (group `adm` read-only), LLMNR disabled.
- Static IP `mc-seed` (35.237.211.12) reserved.
- Cold-key Shamir ceremony script ready.
- Mainnet params proposed.
- Key rotation + backup/restore runbooks written (both need drills).
