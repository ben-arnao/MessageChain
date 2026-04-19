# Simple Cold-Key Ceremony (founder, 1-of-1)

The minimum viable version of the cold-key setup: 15 minutes,
single-holder, no Shamir quorum.  Run this before announcing mainnet
publicly.

## Why not defer this?

The cold key is a single-purpose kill switch: if the hot validator key
is ever compromised (host breach, malware, stolen laptop), the attacker
can produce signed blocks and burn reputation, but the cold key can
sign an `emergency-revoke` transaction that permanently disables the
compromised entity on-chain.

Without a cold key, the founder has no emergency brake.  Transferring
funds to a "more secure entity" later does not fix this:

- Stake is subject to a 7-day unbonding queue.  An attacker with the hot
  key can keep equivocating and getting slashed for a week before the
  funds are available to move.
- The seed identity is pinned in block 0.  Moving funds transfers
  tokens but does not transfer the seed role.  Divestment economics,
  bootstrap-era seed exclusion, and governance weights stay attached to
  the original entity.
- Moving 95M staked tokens is a large, on-chain observable transaction.
  The optics of "founder moves all funds to new address" without
  context are bad.

So do the 1-of-1 ceremony now.  You can upgrade to a 2-of-3 Shamir
quorum later by running `deploy/cold_key_ceremony.py generate
--threshold 2 --total 3` and rotating the authority key.

## Prerequisites

- An air-gapped laptop.  Ideal: a spare machine, wifi + bluetooth off,
  fresh OS install.  Acceptable: your normal laptop, offline for the
  duration of the ceremony (airplane mode + ethernet unplugged).
- Python 3.10+ on that laptop.
- The MessageChain repo cloned onto it (via USB stick, not download).
- A physical storage plan for the key material:
  - 1 printed copy in a fireproof safe (or steel-etched for fire/flood
    resilience)
  - 1 USB stick in a safe-deposit box

Single-holder means single point of failure.  Two independent physical
copies give you redundancy against a house fire or a lost safe.

## The ceremony (15 min)

```bash
# 1. Air-gapped laptop.  Disconnect network.  Boot.
# 2. Clone / unzip the repo onto the laptop via USB.
cd MessageChain
pip install .

# 3. Generate the cold key pair.  Records the 32-byte private key as
#    hex plus a 24-word mnemonic for hand-copying onto paper.
messagechain generate-key > cold-key-private.hex

# 4. Derive the cold public key + address from the private key.  Only
#    the public key needs to touch the network.
messagechain verify-key --keyfile cold-key-private.hex > cold-key-public.txt
cat cold-key-public.txt
# Note the "Public key:" and "Address:" lines — these are safe to share.

# 5. Write the 24-word mnemonic from step 3's stdout onto paper, IN
#    ORDER.  File it in the safe.
#
# 6. Copy cold-key-private.hex to a clean USB stick.  File that stick
#    in the safe-deposit box.
#
# 7. Shred the on-disk key material:
shred -u cold-key-private.hex
# macOS:   rm -P cold-key-private.hex
# Windows: sdelete -p 3 cold-key-private.hex  (or just wipe the laptop
#          if it was a spare)
```

## Verify recovery BEFORE going online

Before trusting the backup, confirm the paper mnemonic can reproduce
the same public key.  Still on the air-gapped laptop:

```bash
# Type the 24 words back from the paper into a file (the mnemonic's
# built-in checksum catches typos).
vim cold-mnemonic.txt
# (paste all 24 words on a single line, then save + quit)

messagechain verify-key --keyfile cold-mnemonic.txt
# verify-key auto-detects mnemonic vs. hex.  The "Public key:" line
# should EXACTLY match cold-key-public.txt.  If it doesn't, the paper
# copy was miscopied — re-do step 5.

# Then wipe the recovered file:
shred -u cold-mnemonic.txt
```

## Promote the cold key on-chain

Bring `cold-key-public.txt` to your online validator host:

```bash
# On the validator, read the public-key hex out of cold-key-public.txt
# (the line starting "Public key:"), then:
messagechain set-authority-key \
    --authority-pubkey <cold_public_hex> \
    --server localhost:9334 \
    --keyfile /etc/messagechain/keyfile

# One block time later, confirm:
messagechain account --server localhost:9334 \
    --keyfile /etc/messagechain/keyfile
# authority_key should now equal <cold_public_hex>.
```

From this point on, any `emergency-revoke` or authority-gated
`unstake` must be signed by the cold key.  The hot key can still
produce blocks and do routine transfers — it is just no longer able
to self-revoke.

## If the hot key is compromised (emergency drill)

```bash
# On a clean, offline machine — NOT the compromised validator.
# 1. Retrieve cold-key-private.hex from the safe-deposit box USB, OR
#    re-type the 24-word mnemonic from the safe-stored paper into a
#    file (messagechain commands that read --keyfile auto-detect
#    mnemonic vs. hex).
# 2. Use the cold key to sign and submit emergency-revoke against your
#    own entity_id.  See docs/key-rotation-runbook.md for the full
#    procedure.
```

After emergency-revoke commits, your validator is permanently disabled
on-chain.  Stake is pushed into the 7-day unbonding queue; after the
queue drains, the tokens return to the hot key's liquid balance (which
you still control — the hot key was compromised for SIGNING new
blocks, not for RECEIVING funds).

## Upgrade to 2-of-3 later

When you want multi-party custody (or before a public mainnet
announcement if you want quorum from day 1), run the full ceremony
and rotate the authority key:

```bash
# Air-gapped laptop:
python deploy/cold_key_ceremony.py generate \
    --threshold 2 --total 3 \
    --out-dir ./new-cold-key-output

# Distribute cold-share-{1,2,3}.txt to three separate holders.  Verify
# recovery with 2 shares (see deploy/cold_key_ceremony.py recover).

# Online validator:
messagechain set-authority-key \
    --authority-pubkey <new_cold_pubkey_hex> \
    --server localhost:9334 \
    --keyfile /etc/messagechain/keyfile
```

On-chain authority transfers atomically — there is never a window
during which both keys are active.  Retire the old 1-of-1 material:
shred the USB stick and burn the paper after the rotation is
confirmed on-chain.
