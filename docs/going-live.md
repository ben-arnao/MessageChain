# Going Live — Pre-Launch Checklist

Running doc of everything that needs to happen before MessageChain mainnet launch.
Append freely. Check items off as they land. Move resolved items to the **Done** section
at the bottom so the top of the file is always "what's left."

## Current state (as of 2026-04-17)

- **Testnet:** single validator running remotely on a GCP VM.
- **Mode:** pre-mainnet. `NETWORK_NAME = "testnet"` selects `_TESTNET_GENESIS_HASH`. `_MAINNET_GENESIS_HASH` is still `None` — flipping `NETWORK_NAME` to `"mainnet"` without setting it raises at config load.
- **Profile:** `MESSAGECHAIN_PROFILE=prototype` on the VM (dev-scale bundle: 30s blocks, tree height 16, checkpoints waived, RPC auth off). The shipped systemd unit no longer bakes this in — operators install `messagechain-validator-prototype.conf.example` as a drop-in to opt into prototype mode.
- **Clients:** seed endpoint list in `CLIENT_SEED_ENDPOINTS` points only at the test VM.

---

## Key Custody (Mainnet Gating)

**This section is a hard blocker for cutting mainnet.** Every checkbox below
must be ticked before genesis is pinned.

### Rationale

The seed validator controls roughly 98% of validator stake throughout the
bootstrap window (~2 years minimum, see the bootstrap-gradient schedule). In
that window a single custody failure — lost key, coerced founder, compromised
host, founder death — is a chain-death event, not a recoverable incident. The
custody model therefore has to survive **one lost share AND one coerced
party** before the chain has enough external stake to heal itself.

The prescription is **Tier B: 2-of-3 authority-key split, HSM/KMS-backed hot
key.**

### Authority (cold) key

The on-chain authority key (see `messagechain/core/authority_key.py`) is a
single 32-byte public key. Native m-of-n multi-sig is **not** implemented —
`SetAuthorityKeyTransaction` rotates to exactly one new public key. The
split is therefore handled **off-chain via Shamir Secret Sharing** over the
authority key's private key material. The chain continues to see a single
authority key; the quorum requirement lives entirely in the custody process.

Requirements:

- **2-of-3 Shamir split** of the authority private key, generated air-gapped
  during the founder cold-key ceremony.
- **Shareholders:** founder + 2 trusted parties, each in a **separate legal
  jurisdiction**. Shareholders are named individuals, not roles.
- **At least one share** stored in a tamper-evident physical medium
  (safe-deposit box or equivalent) in a **jurisdiction different from the
  founder's primary residence**.
- **Annual recovery drill:** the quorum reconstructs the key air-gapped,
  signs a test message, wipes the reconstructed material, and records the
  result in the private ops memo. A failed or skipped drill is itself an
  incident.

### Hot (validator signing) key

- Stored in an **HSM, cloud KMS (GCP Cloud KMS preferred — the testnet
  already runs on GCP), or equivalent hardware-backed key store**. Never
  on plain disk on the validator host.
- All key-access events logged to an **immutable / append-only audit sink**
  (e.g. Cloud Logging with a locked retention bucket).
- Validator host hardened: SSH key-only, firewall default-deny, no
  interactive root, `fail2ban` or equivalent on the SSH surface.
- Validator host is **physically and administratively separate** from any
  shareholder of the authority key — no shareholder has login on the
  validator, and the validator operator is not a shareholder.

### Compromise response runbook

- **Detect:** anomalous signing activity, suspicious login on the validator
  host, shareholder reports coercion or duress, or an HSM/KMS alarm.
- **Immediate:** halt the validator process (stop signing blocks). **Do not
  attempt a key rotation under duress** — a coerced rotation is worse than
  a halted validator.
- **Within 24h:** convene the 2-of-3 quorum, sign and broadcast a
  `SetAuthorityKeyTransaction` rotating to a freshly generated authority
  key, and announce publicly on the project's public channel (mailing list
  / forum / whatever lands as the official channel).
- **Within 1 week:** publish a post-mortem.

### Pre-mainnet checklist

- [ ] Authority key 2-of-3 Shamir split generated air-gapped; shares distributed to founder + 2 other named shareholders. *(Ceremony script ready: `deploy/cold_key_ceremony.py`.)*
- [ ] Shareholder identities and jurisdictions documented in a private ops memo (not on-chain, not in this repo).
- [ ] Recovery drill completed at least once end-to-end; result documented. *(Supported by `cold_key_ceremony.py recover`.)*
- [x] **Hot signing key migrated to GCP Secret Manager (KMS-backed).** As of 2026-04-18, the testnet validator loads the hex key at startup via the VM's metadata-server auth token + Secret Manager REST API. The key is Google-symmetric-encrypted at rest via KMS keyring `mc-validator-keyring/mc-hot-key-encryption`, never touches disk on the VM, and every access is logged to Cloud Audit Logs. Server code uses stdlib-only (no pip deps). Disk keyfile `/etc/messagechain/keyfile` destroyed post-migration.
- [x] **Hot key access logged to an immutable audit sink.** Cloud Audit Logs capture every `secretmanager.v1.SecretManagerService.AccessSecretVersion` call on `mc-validator-hotkey`. Retention per GCP default (400 days for admin activity logs, longer for data access if enabled).
- [ ] Compromise response runbook finalized and shared in writing with all three shareholders.
- [ ] Physical location of each authority key share confirmed in writing by the holder.

---

## Open items

### Consensus & validator set

- [ ] Recruit and onboard at least N additional independent validators (decide N).
- [ ] Geographic + jurisdictional diversity for the initial validator set.
- [ ] Decide final minimum stake schedule for mainnet.
- [ ] Finalize unbonding period (currently 7 days) — confirm this is what we want for mainnet.

### Cryptography & keys

- [ ] Decide final WOTS+ / Merkle tree height for mainnet (production-scale, not 16).
- [ ] Document founder cold-key ceremony (air-gapped generation, paper backup, witnesses). Custody split is covered by **Key Custody (Mainnet Gating)** above.
- [x] **Key-rotation runbook written** — [docs/key-rotation-runbook.md](key-rotation-runbook.md). End-to-end procedure for founder hot-key rotation with failure modes documented. Drill on testnet still pending.
- [ ] Key-rotation **drill**: run `rotate-key` end-to-end against the live testnet before leaves exhaust in prod.
- [ ] Review choice of hash function(s) and signature scheme against the current quantum-resistance literature.

### Genesis & chain config

- [~] **Proposed genesis parameters written.** [docs/mainnet-params.md](mainnet-params.md) has the concrete values for every block-0 immutable parameter (founder allocation 100M, treasury 40M, tree height 20, CHAIN_ID, hash/sig versions) and governance-mutable launch defaults. Each line still needs operator sign-off.
- [ ] Sign off on every line of `docs/mainnet-params.md`.
- [ ] Mint mainnet genesis, set `_MAINNET_GENESIS_HASH` in `messagechain/config.py` to the resulting block-0 hash, commit, tag release. (Do not flip `NETWORK_NAME` to `"mainnet"` until this is done — config will refuse to load.)
- [ ] Flip `NETWORK_NAME` from `"testnet"` to `"mainnet"`, commit, tag release.
- [ ] Freeze `CLIENT_SEED_ENDPOINTS` to the initial mainnet seed set.

### Security review

- [ ] Internal security review of all consensus + signature code paths.
- [ ] External security audit (pick firm, scope, timeline, budget).
- [ ] Address all audit findings; re-audit fixes if material.
- [ ] Threat model document: adversary classes, assumptions, known limitations.
- [ ] Fuzz testing: network layer, block validation, transaction decoder.

### Network & infra

- [ ] DDoS posture for seed nodes.
- [ ] TOFU pin store behavior reviewed under validator churn + key rotation.
- [ ] Peer-discovery / gossip behavior tested with ≥10 nodes, including adversarial peers.
- [ ] Tor / onion endpoint support documented and tested ([tor-setup.md](tor-setup.md)).

### Operations

- [x] **Systemd unit hardening** — `ProtectKernel*`, `PrivateDevices`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service ~@privileged @resources`, `LockPersonality`, `MemoryMax=1500M`, `LimitNOFILE=65536`, crash-loop guard (`StartLimitBurst=5/hour`). See [deploy/systemd/messagechain-validator.service](../deploy/systemd/messagechain-validator.service).
- [x] **Log rotation** — journald drop-in at [deploy/systemd/journald-messagechain.conf](../deploy/systemd/journald-messagechain.conf) caps at 500M / 1 month retention. Prevents runaway logs from filling the root partition.
- [ ] Monitoring + alerting (partial: liveness done, fork detection / disk / signature-leaf exhaustion pending).
    - [x] **Liveness:** GCP Uptime Check on TCP `35.237.211.12:9334` every 5 min; alert policy `validator-rpc-down` emails `arnaoben@gmail.com` after 60s downtime. Check ID `validator-rpc-check-S5wGEEcMtmI`, alert policy `210243887955051052`.
    - [ ] Fork detection (two conflicting tips at same height).
    - [ ] Disk usage alert (predicts when snapshots or chaindata will fill the boot disk).
    - [ ] Signature-leaf exhaustion alert — the server logs WARN at 80/95%; pipe to PagerDuty or similar.
- [ ] Backup + restore runbook (partial: daily snapshots done, restore procedure not yet written).
    - [x] **Daily GCP persistent-disk snapshots** at 04:00 UTC, 30-day retention, attached to `validator-1` boot disk. Resource policy: `validator-daily-snap` in `us-east1`.
    - [ ] Restore procedure documented + dry-run tested.
- [ ] Incident response plan (including `emergency-revoke` drill).

### Governance

- [ ] On-chain governance parameters finalized (voting period, quorum, threshold).
- [ ] Process for publishing + linking proposals (GitHub PR convention) documented for end users.

### Testing

- [ ] Full `python -m unittest discover tests/` passing on mainnet config (prod tree height).
- [ ] Long-running stability test on testnet: N days with no operator intervention.
- [ ] Chain re-sync from scratch on a fresh machine, verified against pinned genesis.
- [ ] Upgrade / migration path tested (shut down, upgrade binary, restart, no fork).

### Docs & user-facing

- [ ] README reflects mainnet reality (not testnet).
- [ ] Wallet-generation guide reviewed for non-technical users.
- [ ] Validator operator guide: hardware, network, OS, key custody.
- [ ] Reproducible-build instructions so users can verify the binary they're running.

### Launch

- [ ] Launch-day runbook (who does what, in what order, rollback plan).
- [ ] Communication plan (announcement channels, where users report issues).
- [ ] Post-launch monitoring rota for first N days.

---

## Done

- **2026-04-18 — Testnet founder key rotated.** The previous genesis private key had leaked into chat scrollback during the dev session that bootstrapped the prototype. Rotated to a fresh `os.urandom(32)` key, re-minted testnet genesis, updated `_TESTNET_GENESIS_HASH`. Old entity `ad66c101...` is burnt; new entity is `2195a4be011608dffed899613393f52de6ef51f8d822d26c0d3d6cca6acd3576` / `mc12195a4be011608dffed899613393f52de6ef51f8d822d26c0d3d6cca6acd35769cf6094e`. Private key lives only in `/etc/messagechain/keyfile` on the validator VM (mode 0400, owner `messagechain`). **Still a single-file, single-host hot key** — replacing it with an HSM/KMS is the next step in the Key Custody section.
- **2026-04-18 — Key-rotation runbook written.** [docs/key-rotation-runbook.md](key-rotation-runbook.md) — procedure and failure modes for rotating the founder hot key while the validator is live. Drill on testnet still pending.
- **2026-04-18 — Systemd unit hardened.** Added `ProtectKernel*`, `PrivateDevices`, `SystemCallFilter=@system-service ~@privileged @resources`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `LockPersonality`, `MemoryMax=1500M`, `LimitNOFILE=65536`. A code-execution bug in the validator is now box-local; no kernel tunable access, no new namespaces, no realtime scheduling, no raw sockets.
- **2026-04-18 — Log rotation configured.** journald drop-in caps system logs at 500M with 1-month max retention, 50M per file. A runaway log spew can no longer fill the boot disk.
- **2026-04-18 — Liveness monitoring live.** GCP Uptime Check on TCP `35.237.211.12:9334` + email alert to `arnaoben@gmail.com` on 60s downtime. Operator learns about a dead validator in minutes instead of "when someone complains."
- **2026-04-18 — Daily disk backups live.** GCP persistent-disk snapshot schedule at 04:00 UTC with 30-day retention. VM loss is no longer a chain-loss event (restore procedure still needs to be written + drilled).
- **2026-04-18 — Hot signing key migrated to GCP Secret Manager (KMS-backed).** Disk-file keyfile replaced by metadata-server-authed Secret Manager fetch at server startup. Stdlib-only (no pip deps) — keeps the "no third-party deps" promise. At-rest encryption via KMS keyring `mc-validator-keyring/mc-hot-key-encryption`, access audit-logged. On-disk keyfile `/etc/messagechain/keyfile` shredded post-migration.
- **2026-04-18 — Cold-key Shamir ceremony script shipped.** [deploy/cold_key_ceremony.py](../deploy/cold_key_ceremony.py) — air-gapped 2-of-3 Shamir split for founder cold authority key, stdlib-only, SHA3-checksummed shares, supports recover subcommand for pre-destruction verification.
- **2026-04-18 — Proposed mainnet parameters documented.** [docs/mainnet-params.md](mainnet-params.md) — every block-0 immutable parameter (founder allocation, treasury, tree height, CHAIN_ID, hash/sig versions) with proposed value and rationale. Operator must sign off line-by-line before mainnet mint.
- **2026-04-17 — Keypair cache no longer pickle-based.** Replaced `pickle.load`/`pickle.dump` in `server.py` with HMAC-SHA3-256-authenticated JSON keyed on the validator's private key. A planted file (malware, restored backup, stray `cp`) can no longer execute arbitrary code as the validator user. Regression tests in [tests/test_keypair_cache_versioning.py](../tests/test_keypair_cache_versioning.py) pin the format and prove a planted pickle does not deserialize.
- **2026-04-17 — `PINNED_GENESIS_HASH` gated on `NETWORK_NAME` selector.** Cutting mainnet now requires two explicit edits (set `_MAINNET_GENESIS_HASH`, flip `NETWORK_NAME`); doing the second without the first raises at config load. A clone of the repo can no longer accidentally trust a testnet hash on mainnet.
- **2026-04-17 — Production systemd unit purged of dev-time overrides.** Default unit ships with no `MESSAGECHAIN_PROFILE=prototype` (=production posture) and adds `StartLimitBurst` for crash-loop protection. Prototype-phase deployments install the new `messagechain-validator-prototype.conf.example` drop-in. A copy-paste install no longer silently runs in degraded mode.
