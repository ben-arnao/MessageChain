# Backup + Restore Runbook

Written procedure for restoring a MessageChain validator from disk
snapshot after a catastrophic VM loss (disk failure, accidental wipe,
instance deleted, zone outage).

**Read end-to-end before disaster strikes.**  When you actually need
it, you'll have hours not days to recover cleanly.

## Preconditions

- Daily persistent-disk snapshots are enabled (resource policy
  `validator-daily-snap` on the VM's boot disk, 04:00 UTC, 30-day
  retention). Verify with:
  ```
  gcloud compute resource-policies describe validator-daily-snap \
      --region=us-east1 --project=messagechain-validator
  gcloud compute disks describe validator-1 \
      --zone=us-east1-b --project=messagechain-validator \
      --format="value(resourcePolicies)"
  ```
- Hot key is stored in the operator's secrets backend (not just on
  the disk).  The snapshot does NOT contain the hot key — it lives
  independently.
- Static external IP `mc-seed` (35.237.211.12) is reserved at the
  project level — survives VM deletion.

## What's in a snapshot

The daily snapshot is a block-level image of the boot disk.  It
contains:
- `/opt/messagechain` — the server code (recoverable from git anyway)
- `/var/lib/messagechain` — **the chain data** (critical)
  - `chain.db` — blocks + state
  - `keypair_cache_*.bin` — WOTS+ keypair cache (regenerable from the
    hot key, so not strictly needed)
  - `leaf_index.json` — next-leaf watermark (regenerable from chain
    state)
- `/etc/systemd/system/messagechain-validator.service` + drop-in
- `/etc/systemd/journald.conf.d/journald-messagechain.conf`
- `/etc/systemd/resolved.conf.d/disable-llmnr.conf`
- The `messagechain` service user + group

What's NOT in a snapshot:
- Hot key (lives in the secrets backend)
- config_local.py (has been on disk but you should verify per VM)
- anchors.json (regenerable from P2P reconnect, but useful to carry)

## Restore procedures

### Scenario A: boot disk lost, VM still exists

Fastest path.  Reattach a restored disk.

1. **Pick the most recent healthy snapshot**:
   ```
   gcloud compute snapshots list --project=messagechain-validator \
       --filter="sourceDisk:validator-1" --sort-by=~creationTimestamp \
       --limit=5
   ```
2. **Stop the VM** (just in case it's thrashing):
   ```
   gcloud compute instances stop validator-1 \
       --zone=us-east1-b --project=messagechain-validator
   ```
3. **Detach the current boot disk**:
   ```
   gcloud compute instances detach-disk validator-1 \
       --disk=validator-1 --zone=us-east1-b \
       --project=messagechain-validator
   ```
4. **Create a new disk from snapshot**:
   ```
   gcloud compute disks create validator-1-restored \
       --source-snapshot=<SNAPSHOT_NAME> \
       --zone=us-east1-b --project=messagechain-validator
   ```
5. **Attach + boot**:
   ```
   gcloud compute instances attach-disk validator-1 \
       --disk=validator-1-restored --boot \
       --zone=us-east1-b --project=messagechain-validator
   gcloud compute instances start validator-1 \
       --zone=us-east1-b --project=messagechain-validator
   ```
6. **Verify**: SSH in, check `systemctl status messagechain-validator`.
   Expect `active (running)` after the hot-key fetch + leaf watermark
   advance.
7. **Delete the old disk** after a day of stability:
   ```
   gcloud compute disks delete validator-1 --zone=us-east1-b --project=messagechain-validator
   ```

### Scenario B: entire VM lost (instance deleted, zone outage, etc.)

Recreate from scratch.

1. **Pick snapshot** (same as A.1).
2. **Create new disk from snapshot**:
   ```
   gcloud compute disks create validator-1 \
       --source-snapshot=<SNAPSHOT_NAME> \
       --zone=us-east1-b --project=messagechain-validator
   ```
3. **Recreate instance** with same config:
   ```
   gcloud compute instances create validator-1 \
       --zone=us-east1-b --project=messagechain-validator \
       --machine-type=e2-small \
       --disk=name=validator-1,boot=yes \
       --address=35.237.211.12 \
       --tags=mc-validator \
       --scopes=cloud-platform
   ```
4. **Re-attach the static IP** (should auto-attach via `--address`):
   ```
   gcloud compute addresses describe mc-seed --region=us-east1 \
       --project=messagechain-validator
   # Confirm "status: IN_USE" and "users: .../instances/validator-1"
   ```
5. **Re-attach the snapshot policy**:
   ```
   gcloud compute disks add-resource-policies validator-1 \
       --zone=us-east1-b --resource-policies=validator-daily-snap \
       --project=messagechain-validator
   ```
6. **Verify**: SSH in, `systemctl status messagechain-validator`.
7. **Reconfigure OpenSSH client**: `gcloud compute config-ssh` — the
   host key will be different.

### Scenario C: chain.db corrupted but VM otherwise fine

Fastest path — restore only the data dir, not the boot disk.

1. **Copy chain.db from a recent snapshot to a fresh disk**, attach
   as secondary.
2. **Stop the service**: `sudo systemctl stop messagechain-validator`
3. **Replace `/var/lib/messagechain/chain.db*` from the restore source**
4. **Start the service**: `sudo systemctl start messagechain-validator`
5. **Verify**: `sudo journalctl -u messagechain-validator | grep 'Loaded chain'`

## Post-restore verification

Regardless of scenario, after restore:

- [ ] `systemctl status messagechain-validator` → `active (running)`
- [ ] `ss -tlnp | grep -E '9333|9334'` → both ports listening
- [ ] `python -m messagechain info --server 35.237.211.12:9334` → chain
      height matches the snapshot's expected height (within a few blocks
      of the snapshot time — any new blocks produced since the snapshot
      are LOST)
- [ ] `sudo journalctl -u messagechain-validator --since '5 minutes ago' | grep -i error`
      → no recurring errors
- [ ] Liveness uptime check reports healthy (check Cloud Monitoring
      console)

## Chain rollback caveat

A snapshot is a point-in-time image. If the chain had height N at
snapshot time, restoring loses ALL blocks between N and the moment of
disaster. On a 10-min-block chain with 24-hour snapshot cadence, that
means **up to 24 hours of history vanish** on worst-case recovery.
Accepted trade-off for a single-validator chain: there's no other
validator to re-sync from.  **Once there are ≥3 validators**, a
restored node should instead re-sync from peers via the normal IBD
path and discard the snapshotted chain.db.

## Key custody during restore

The hot key is NOT in the snapshot — it's fetched from the secrets
backend at service start.  After restore:

- The restored VM must have the same service account attached (or a
  new one with `roles/secretmanager.secretAccessor` on the hot-key
  secret) for Secret Manager fetch to succeed.
- If you can't restore service-account access promptly, the validator
  will fail to start with a "Failed to fetch secret" error.
- In the worst case (service account lost, Secret Manager access
  broken, etc.), fall back to a cold-authority-key-signed emergency
  revoke + fresh mint on a new entity.  This is chain-death for the
  current entity.

## Drill schedule

**This runbook is untested.**  Before relying on it:

- [ ] Run Scenario A end-to-end against a throwaway disk.  Expect to
      take 30–60 minutes.  Document any steps that were ambiguous or
      wrong, fix this doc.
- [ ] Re-drill annually, or after any significant infrastructure change.

## See also

- `docs/going-live.md` § Operations
- `docs/key-rotation-runbook.md`
- `docs/system-audit.md` § 15 (open findings)
