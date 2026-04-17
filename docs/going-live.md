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

## Open items

### Consensus & validator set

- [ ] Recruit and onboard at least N additional independent validators (decide N).
- [ ] Geographic + jurisdictional diversity for the initial validator set.
- [ ] Decide final minimum stake schedule for mainnet.
- [ ] Finalize unbonding period (currently 7 days) — confirm this is what we want for mainnet.

### Cryptography & keys

- [ ] Decide final WOTS+ / Merkle tree height for mainnet (production-scale, not 16).
- [ ] Document founder cold-key ceremony (air-gapped generation, paper backup, witnesses).
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
