# Going Live — Pre-Launch Checklist

Running doc of everything that needs to happen before MessageChain mainnet launch.
Append freely. Check items off as they land. Move resolved items to the **Done** section
at the bottom so the top of the file is always "what's left."

## Current state (as of 2026-04-17)

- **Testnet:** single validator running remotely on a GCP VM.
- **Mode:** pre-mainnet. Genesis hash is not yet pinned in `messagechain/config.py`.
- **Tree height:** `MESSAGECHAIN_MERKLE_TREE_HEIGHT=16` on the VM (dev-scale).
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

- [ ] Authority key 2-of-3 Shamir split generated air-gapped; shares distributed to founder + 2 other named shareholders.
- [ ] Shareholder identities and jurisdictions documented in a private ops memo (not on-chain, not in this repo).
- [ ] Recovery drill completed at least once end-to-end; result documented.
- [ ] Hot signing key migrated to HSM or GCP Cloud KMS.
- [ ] Hot key access logged to an immutable / append-only audit sink.
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
- [ ] Key-rotation runbook: drill `rotate-key` on testnet before leaves exhaust in prod.
- [ ] Review choice of hash function(s) and signature scheme against the current quantum-resistance literature.

### Genesis & chain config

- [ ] Final genesis parameters agreed (supply, initial allocations, fee schedule).
- [ ] Mint mainnet genesis, pin its hash in `messagechain/config.py::PINNED_GENESIS_HASH`, commit, tag release.
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

- [ ] Systemd unit hardening reviewed (user, capabilities, restart policy).
- [ ] Log rotation + retention policy.
- [ ] Monitoring + alerting: liveness, fork detection, disk, signature-leaf exhaustion.
- [ ] Backup + restore runbook for chaindata and keys.
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

_(move completed items here with the date they landed)_
