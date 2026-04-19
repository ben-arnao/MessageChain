# Key Rotation Runbook

Written procedure for rotating the genesis / founder signing key on a
running MessageChain validator.  **Read this end-to-end before starting.**
Do not skip steps.  If a step fails, STOP and ask for help — don't
improvise.

## When to rotate

- **Leaf watermark ≥ 80% of tree capacity** (`messagechain key-status`
  will warn you; the server also logs WARN at 80% and 95%).  Rotation before
  exhaustion is mandatory — a validator that exhausts its WOTS+ leaves mid-slot
  will miss blocks and bleed stake to inactivity penalties.
- **Suspected key compromise** (keyfile was read by an unauthorized party,
  hosting environment may have leaked it, etc.).  Rotate *immediately* and
  treat the old key as burnt.
- **Routine hygiene** — at least every ~1 year, regardless of watermark.

## What rotation does

`messagechain rotate-key` submits a `RotateKeyTransaction` signed
by the **current** hot key.  It swaps in a new public key on-chain.  After
the next block confirms, the OLD key can no longer sign for this entity —
the chain refuses any signature whose Merkle root doesn't match the new
public key.

The entity_id and address do NOT change.  Only the underlying keypair
(and its Merkle root = public key) changes.  Callers do not need to update
the recipient address to keep sending you funds.

## Preconditions

- [ ] VM is up and producing blocks.  `systemctl status
      messagechain-validator` shows `active (running)`.
- [ ] You have 2 clean terminals open — one on your local workstation
      (for generating the new key) and one SSH'd to the VM (for
      installing it).
- [ ] You have enough balance to pay `KEY_ROTATION_FEE` (1000 tokens by
      default — see `messagechain/config.py`).  Check with
      `messagechain balance`.
- [ ] The current hot key still has at least 1 unused WOTS+ leaf.  The
      rotate-key tx itself consumes one leaf.  Verify with
      `messagechain key-status`.

## Procedure

### 1. Generate new private key offline

On a machine **that is not connected to the internet**:

```bash
python -c "import os; print(os.urandom(32).hex())"
```

Write the hex string on paper.  Two copies minimum.  Store each copy in
a different physical location.  Do not photograph, screenshot, or
copy-paste into a cloud document.

### 2. Derive the new entity's public key + confirm

Still offline, verify you can re-derive the same public key from the
paper backup:

```bash
python -c "
import sys
sys.path.insert(0, '/path/to/MessageChain')
from messagechain.identity.identity import Entity
key = bytes.fromhex(input('paste key: ').strip())
e = Entity.create(key, tree_height=16)
print('Public key:', e.public_key.hex())
"
```

Write down the public key.  This is what goes on-chain.

### 3. Submit the rotate-key transaction

From the machine that currently has the **old** key (the validator VM
or wherever the CLI is authorized):

```bash
messagechain rotate-key --new-pubkey <new_public_key_hex>
```

The CLI will:
- Prompt for the OLD private key
- Sign the rotation tx with a still-unused OLD WOTS+ leaf
- Submit to the network

### 4. Wait for confirmation

Wait for the tx to be included in a block (~10 min on production):

```bash
messagechain key-status
# Public key should show the NEW value after confirmation.
```

DO NOT SHUT DOWN the server between submission and confirmation — the
block producer still needs the OLD key to propose during this window.

### 5. Install the new keyfile on the VM

Once confirmed on-chain, replace the keyfile:

```bash
# On your local workstation, write the NEW key to a temp file:
echo "<new_hex_key>" > /tmp/new-keyfile

# Copy to the VM:
scp /tmp/new-keyfile validator-1.us-east1-b.messagechain-validator:/tmp/

# On the VM:
ssh validator-1.us-east1-b.messagechain-validator
sudo systemctl stop messagechain-validator
sudo cp /tmp/new-keyfile /etc/messagechain/keyfile
sudo chown messagechain:messagechain /etc/messagechain/keyfile
sudo chmod 0400 /etc/messagechain/keyfile
# Wipe the stale keypair cache — new key derives a different keypair:
sudo rm -f /var/lib/messagechain/keypair_cache_*.bin
sudo systemctl start messagechain-validator

# Purge the temp file securely:
shred -u /tmp/new-keyfile
```

Back on your workstation:
```bash
shred -u /tmp/new-keyfile
```

### 6. Verify the new key is active

```bash
# From anywhere:
messagechain key-status
# public_key should match what you derived in step 2.

# On the VM:
sudo journalctl -u messagechain-validator --since '2 minutes ago' | grep Authenticated
# Should show "Authenticated as: ..." matching your entity_id.
```

### 7. Destroy the OLD key

The OLD private key is no longer authoritative on-chain, but anyone with
it could still try to sign things (they'll be rejected, but the signature
attempt leaks metadata).  Destroy all copies:

- Shred paper backups (cross-cut shredder, or burn)
- Delete any digital copies and empty your terminal scrollback
- If the old key ever touched a cloud-synced folder, assume it's
  permanently leaked — treat it as burnt.  (This is why we generate
  offline in step 1.)

## After rotation

- [ ] `messagechain key-status` shows the new public key
- [ ] The server on the VM is producing blocks (`journalctl | grep "Block #"`)
- [ ] All paper backups of the NEW key are stored securely in ≥2 locations
- [ ] All copies of the OLD key are destroyed
- [ ] This runbook is updated if any step was ambiguous or wrong

## Failure modes

**"Key exhausted" during rotate-key submission:**
The OLD key has no leaves left.  You cannot self-rotate.  You must
recover via the cold authority key (if set) using
`set-authority-key --authority-pubkey <new>` signed by the cold key.
If no cold authority was ever set, the entity is stuck at its current
public key forever.  This is why cold-key setup is mandatory for any
validator intended to run longer than half a tree's worth of leaves.

**Tx confirms but new key doesn't activate:**
Check that the tx's `new_public_key` field matches what you intended.
A typo in the hex will submit a valid tx that swaps to a key you don't
control.  If the server rejects your NEW keyfile as "unknown wallet",
you've rotated to the wrong key.  You must recover via the cold key.

**Server won't start after installing new keyfile:**
Most likely: keypair cache wasn't wiped, and the cache is for the OLD
key.  Remove all `keypair_cache_*.bin` files in `/var/lib/messagechain`
and restart.  Fresh keygen takes ~5 min on e2-small, ~2 min on e2-medium.

## See also

- `messagechain/crypto/keys.py` — WOTS+ implementation, leaf tracking
- `messagechain/core/authority_key.py` — cold authority key semantics
- `docs/going-live.md` — broader pre-launch checklist
