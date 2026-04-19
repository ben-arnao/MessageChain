# Onboarding Validator #2 (and beyond)

How to invite a second validator onto mainnet — the path from
"single-founder bootstrap" to "N-validator decentralized network."

This is the operational follow-up to launch.  Today the founder runs
the sole validator; every additional validator incrementally dilutes
founder influence and increases censorship resistance.

---

## When to onboard

The founder chooses.  Reasonable triggers:

- After 1–3 months of stable mainnet (confirms code + infra).
- When you've identified a trusted operator willing to run a validator
  and stake real tokens.
- When founder wants to stress-test consensus under N≥2 validators
  BEFORE bootstrap_progress=1.0 forces it.

You do NOT need to onboard immediately.  Bootstrap is a 2-year window;
the chain is designed to run with N=1 throughout.

---

## The candidate's prerequisites

The new validator operator needs:

1. A host that can run a validator 24/7 — minimum: 2 vCPU, 2 GB RAM,
   30 GB disk, stable public IP, Python 3.10+.  The reference deployment
   uses a GCP `e2-small` running at ~$16/mo.  Any equivalent VM works.
2. Network reachability: inbound TCP on ports 9333 (P2P) and 9334 (RPC).
   Operators behind NAT can serve RPC locally-only and just need
   outbound P2P.
3. Enough tokens to stake `VALIDATOR_MIN_STAKE = 100` (flat from block
   0).  In practice, early validators should stake significantly more
   to matter in the weight-selection — 10K+ is reasonable.
4. A distinct entity identity.  Their key should be freshly generated,
   not derived from the founder's.
5. Ability to run the cold-key-holder ceremony for their own cold key
   if they want emergency-revoke capability.  Recommended but not
   required at launch — they can set authority key = hot key
   initially and promote a cold key later.

---

## Plain P2P sync works — no state snapshot required

Val-2 joins via normal initial-block-download (IBD) from val-1.  No
out-of-band state transfer, no signed checkpoint, no tarball — just
start the candidate's node and point it at val-1 as a bootstrap peer.

How it works: block 0's proposer signature carries a Merkle auth path
from the signed leaf up to the founder's long-term public key.  When
val-2 receives block 0 over gossip, it:

1. Verifies the block hash matches `PINNED_GENESIS_HASH` in config
   (rejects any forked-genesis peer).
2. Reconstructs the founder's public key from the block-0 signature's
   auth path (the Merkle root IS the public key).
3. Verifies `derive_entity_id(pubkey) == block.header.proposer_id` and
   that the block-0 signature actually validates under that pubkey.
4. Applies the canonical mainnet genesis allocation from
   `_MAINNET_FOUNDER_LIQUID` / `_MAINNET_FOUNDER_STAKE` constants in
   `messagechain/config.py` — pinned at the release the candidate
   installed, so a malicious peer can't feed different numbers.
5. Stakes 95M to the founder and pins the seed set.

If any constant drifted from val-1's actual setup, block 1's
`state_root` check rejects immediately — the constants are
self-verifying against the first real state commitment.  So the
reconstruction is safe even under a fully-untrusted P2P path.

Implementation: `Blockchain._apply_mainnet_genesis_state` in
`messagechain/core/blockchain.py`; regression coverage in
`tests/test_ibd_from_genesis.py`.

## The onboarding flow

### Step 1 — Candidate generates their key offline

On an air-gapped laptop or fresh VM:

```bash
pip install .  # from the MessageChain repo
messagechain generate-key > candidate-private.hex
messagechain verify-key --keyfile candidate-private.hex
```

The `verify-key` output prints their entity_id and address.  Record both.

### Step 2 — Candidate spins up their node

On their validator host:

```bash
# Copy in the private key; chmod 0400 it; path it into systemd env
cp candidate-private.hex /etc/messagechain/keyfile
chmod 0400 /etc/messagechain/keyfile

# Clone the repo; `pip install -e .` or install the tarball at v1.0.0-mainnet
git clone https://github.com/ben-arnao/MessageChain
cd MessageChain
git checkout v1.0.0-mainnet

# Install systemd unit (sample in deploy/systemd/), point at
# /etc/messagechain/keyfile and `--data-dir /var/lib/messagechain`

# Start the service; it will IBD from the founder's validator
sudo systemctl start messagechain-validator
```

On first start, the candidate's node does initial-block-download from
the founder's node.  At height 75+ this is <1 MB of block data, fast.

The candidate's node will produce a keypair cache + Merkle cache during
startup (1–10 minutes at `MERKLE_TREE_HEIGHT=16`, depending on hardware).

### Step 3 — Candidate receives tokens

The candidate runs:

```bash
messagechain account --keyfile /etc/messagechain/keyfile
# prints their address (mc1…)
```

They give the founder their address.  The founder runs:

```bash
messagechain transfer --to <candidate-address> --amount 100000 \
    --server localhost:9334
```

This uses the receive-to-exist path: the candidate gets an on-chain state
entry on the first transfer.  Transfer surcharge is `NEW_ACCOUNT_FEE = 1000`
(burned).  A few minutes (one block time) later the candidate's balance
is credited.

### Step 4 — Candidate stakes

```bash
messagechain stake --amount 10000 --server localhost:9334 \
    --keyfile /etc/messagechain/keyfile
```

First-outgoing transaction — their `sender_pubkey` is installed on-chain
via the first-spend reveal path.  After this commits, they are a
registered staker.

The `get_stake_tx` flow checks `min_stake_for_progress(bootstrap_progress)`,
which is lenient during early bootstrap.  The candidate's 10K stake is
accepted.

### Step 5 — Verify they are in the validator set

After one block:

```bash
messagechain validators --server <founder-ip>:9334
# should list both founder and candidate
```

Both nodes will see both validators in the set.  From this point:
- The candidate can propose blocks when they win their slot via
  `_selected_proposer_for_slot` (weighted by stake).
- Attestation selection includes both validators.
- Finality votes start to accumulate meaningful weight.

### Step 6 — (optional, recommended) Candidate promotes a cold key

For emergency-revoke capability, the candidate runs the cold-key
ceremony separately:

```bash
# On an air-gapped machine:
python deploy/cold_key_ceremony.py generate --out-dir ~/cold-shares/
# (distribute 2-of-3 shares to named holders)

# Derive the cold public key from the generated key
messagechain verify-key --keyfile ~/cold-shares/cold-key-private.hex

# Back on their validator host, promote that cold pubkey as their authority
messagechain set-authority-key \
    --authority-pubkey <cold_hex> \
    --server localhost:9334 \
    --keyfile /etc/messagechain/keyfile
```

Now only the cold key can revoke the candidate's validator — even if
their hot-key server is fully compromised, the attacker can't drain
or un-register the validator.

---

## Founder's role during onboarding

Beyond just sending the tokens, the founder should:

1. **Confirm IP reachability** from the founder's validator to the
   candidate's `9333` port.  `messagechain ping --server CANDIDATE:9334`
   should succeed.
2. **Watch for equivocation** in the first days.  A misbehaving new
   validator produces slashing evidence automatically; the founder
   should confirm their `equivocation_watcher` is active.
3. **Monitor the validator set**: `messagechain validators` after
   each new validator joins.
4. **Do NOT immediately raise `MIN_VALIDATORS_TO_EXIT_BOOTSTRAP`**.
   Keep at 1 until you have ≥3 validators you trust.  Then propose a
   governance change raising it to 3.

---

## When you have 3 validators

### Raise the finality floor via governance

```bash
messagechain propose \
    --title "Raise MIN_VALIDATORS_TO_EXIT_BOOTSTRAP to 3" \
    --summary "Three-validator finality floor post-bootstrap" \
    --server localhost:9334 \
    --keyfile /etc/messagechain/keyfile
```

Vote passes at 2/3+ of total eligible stake (founder has 95% so
effectively a founder decision at this stage, but requires the explicit
governance motion).

### Re-drill key rotation

Each validator should do a dry-run key rotation on a testnet or
throwaway key to confirm their runbook is accurate.  See
`docs/key-rotation-runbook.md`.

### Re-drill backup/restore

Each validator runs the Scenario A recovery exercise from
`docs/backup-restore-runbook.md` against a throwaway disk.

---

## When you have 10+ validators

- Raise `MIN_VALIDATORS_TO_EXIT_BOOTSTRAP` higher (e.g., 5 or 7) via
  governance.  At that point the founder's ≥2/3 threshold is no longer
  unilateral.
- Publish the canonical signed checkpoint at height 1000+ via
  `create_state_checkpoint_signature()` + collect signatures from
  ≥2/3 of stake.  Bake the signed checkpoint into
  `TRUSTED_CHECKPOINTS` in config.py.  New clients bootstrapping past
  block 1000 will require this.

---

## Failure modes

### Candidate's node misbehaves

- Equivocation → auto-slashing evidence → 100% of their stake burned +
  10% finder reward.  Operator loses their stake; chain is unaffected.
- Unresponsive → stake drains to the censorship/inactivity leak (see
  `messagechain/consensus/inactivity.py`, quadratic-drain mechanism).

### Candidate's key is compromised

- Their cold-key holder signs an emergency-revoke transaction;
  attacker cannot produce further signed blocks.
- If cold key is unavailable and the hot-key compromise is active, the
  slashing mechanism eventually catches any equivocation.

### Onboarding fails partway

- Candidate never received tokens: no on-chain state, no risk.
- Candidate received tokens but never staked: they have a balance they
  can use or return.
- Candidate staked but never produced blocks: stake drains via
  inactivity leak over ~quarter.
