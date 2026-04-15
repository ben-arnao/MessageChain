"""Seed-validator bootstrap orchestration.

Running three validators with proper security posture requires three
distinct on-chain operations on each server, in the right order, with
the right keys:

  1. Register the hot (signing) entity.
  2. Set its authority key to the operator's cold wallet public key
     — so hot-key compromise cannot unstake, revoke, or drain.
  3. Lock the seed stake via the supply tracker.

Doing this by hand across three VPS is how footguns happen.  One step
silently fails, the node still runs, and you have a "staked validator"
whose hot key is its own authority — a rug-waiting-to-happen.

`bootstrap_seed_local` performs the full sequence against a Blockchain
instance and verifies every post-condition on chain state.  It is
idempotent: re-running after partial success picks up where it stopped.
Returns (ok, log).  The log is plain text so a runbook can print it
verbatim.
"""

from __future__ import annotations

import hashlib
from messagechain.config import HASH_ALGO, MIN_FEE
from messagechain.core.authority_key import create_set_authority_key_transaction


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def bootstrap_seed_local(
    blockchain,
    seed_entity,
    cold_authority_pubkey: bytes,
    stake_amount: int,
    proposer_id: bytes | None = None,
    fee: int = MIN_FEE,
) -> tuple[bool, list[str]]:
    """Register, authority-key, and stake a seed validator on `blockchain`.

    Direct-chain orchestration — bypasses the block pipeline because this
    is the *initial* bootstrap and there are no validators yet to produce
    blocks.  After this completes for all seeds, normal block production
    can start.

    Arguments:
        blockchain: a Blockchain instance (post-genesis) with the seed's
            liquid balance already allocated.
        seed_entity: an Entity whose keypair is the hot signing key.
        cold_authority_pubkey: the operator's cold wallet public key.
            Destructive ops (unstake, revoke) will be gated on this key.
        stake_amount: how many tokens to lock as validator stake.
        proposer_id: fee recipient for the set-authority-key tx.  Defaults
            to the seed's own entity_id (fee burns back to the same account
            minus base_fee).
        fee: governance tx fee for the authority-key tx.  Defaults to MIN_FEE.

    Returns:
        (ok, log) — ok is True iff every step AND every post-condition
        check passed.  log is a list of human-readable step descriptions.
    """
    log: list[str] = []
    eid = seed_entity.entity_id
    eid_short = eid.hex()[:16]
    pid = proposer_id if proposer_id is not None else eid

    # ── Step 1: Register entity ────────────────────────────────────
    if eid in blockchain.public_keys:
        log.append(f"[1/3] registration: already present for {eid_short}, skipping")
    else:
        msg = _hash(b"register" + eid)
        proof = seed_entity.keypair.sign(msg)
        ok, reason = blockchain.register_entity(eid, seed_entity.public_key, proof)
        if not ok:
            log.append(f"[1/3] registration FAILED: {reason}")
            return False, log
        log.append(f"[1/3] registration submitted for {eid_short}")

    # Post-condition: entity must be in public_keys
    if eid not in blockchain.public_keys:
        log.append("[1/3] POST-CHECK FAILED: entity_id not in public_keys after register")
        return False, log
    if blockchain.public_keys[eid] != seed_entity.public_key:
        log.append("[1/3] POST-CHECK FAILED: public_key mismatch for entity_id")
        return False, log
    log.append(f"[1/3] OK verified: entity registered")

    # ── Step 2: Set authority (cold) key ───────────────────────────
    current_authority = blockchain.get_authority_key(eid)
    if current_authority == cold_authority_pubkey:
        log.append("[2/3] authority key already set to cold key, skipping")
    else:
        nonce = blockchain.nonces.get(eid, 0)
        tx = create_set_authority_key_transaction(
            seed_entity, cold_authority_pubkey, nonce=nonce, fee=fee,
        )
        ok, reason = blockchain.apply_set_authority_key(tx, proposer_id=pid)
        if not ok:
            log.append(f"[2/3] set-authority-key FAILED: {reason}")
            return False, log
        log.append("[2/3] set-authority-key submitted")

    # Post-condition: authority_key must equal cold_authority_pubkey
    if blockchain.get_authority_key(eid) != cold_authority_pubkey:
        log.append(
            "[2/3] POST-CHECK FAILED: authority key is not the cold key — "
            "unstake / revoke would still be gated on the hot key!"
        )
        return False, log
    log.append(f"[2/3] OK verified: authority key == cold key")

    # ── Step 3: Stake ──────────────────────────────────────────────
    current_stake = blockchain.supply.get_staked(eid)
    if current_stake >= stake_amount:
        log.append(f"[3/3] already staked {current_stake} (>= {stake_amount}), skipping")
    else:
        needed = stake_amount - current_stake
        liquid = blockchain.supply.get_balance(eid)
        if liquid < needed:
            log.append(
                f"[3/3] stake FAILED: liquid balance {liquid} < needed {needed}. "
                f"Fund this entity at genesis or via a transfer first."
            )
            return False, log
        ok = blockchain.supply.stake(eid, needed)
        if not ok:
            log.append(f"[3/3] stake FAILED: supply.stake returned False (likely amount<=0 or insufficient balance)")
            return False, log
        log.append(f"[3/3] staked {needed} tokens")

    # Post-condition: stake must meet target
    final_stake = blockchain.supply.get_staked(eid)
    if final_stake < stake_amount:
        log.append(
            f"[3/3] POST-CHECK FAILED: staked={final_stake}, expected>={stake_amount}"
        )
        return False, log
    log.append(f"[3/3] OK verified: staked={final_stake}")

    log.append(
        f"BOOTSTRAP COMPLETE: entity={eid_short}, stake={final_stake}, "
        f"authority={cold_authority_pubkey.hex()[:16]}"
    )
    return True, log
