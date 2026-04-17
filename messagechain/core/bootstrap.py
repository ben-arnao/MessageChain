"""Seed-validator bootstrap orchestration.

Running a validator with proper security posture requires three
distinct on-chain operations, in the right order, with the right keys:

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
from messagechain.config import HASH_ALGO, MIN_FEE, NEW_ACCOUNT_FEE
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

    # ── Step 1: Install the seed's pubkey directly ────────────────
    # This is a pre-consensus bootstrap op — no block pipeline yet.
    # _install_pubkey_direct is the same in-memory shortcut that
    # `register_entity_for_test` uses; it bypasses the receive-to-exist
    # Transfer flow because the seed has nothing from which to receive
    # funds yet (it IS the origin of the validator set).
    if eid in blockchain.public_keys:
        log.append(f"[1/3] registration: already present for {eid_short}, skipping")
    else:
        msg = _hash(b"register" + eid)
        proof = seed_entity.keypair.sign(msg)
        ok, reason = blockchain._install_pubkey_direct(
            eid, seed_entity.public_key, proof,
        )
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


# ───────────────────────────────────────────────────────────────────────
# Recommended launch plan for the single-seed layout.
#
# Encodes the decisions documented in the operator runbook so operators
# don't have to re-derive them (and can't silently under-budget fees or
# mis-size stake):
#   * The seed stakes 99,000,000 tokens (~9.9% of supply).
#   * The seed is allocated 99,001,000 liquid at genesis (stake + fee
#     buffer for set-authority-key + bootstrap retries + initial ops).
#   * Treasury allocation is 4% of supply per the existing default.
#   * Payout entity is registered post-genesis via the block pipeline.
#
# Tweak the constants below if you have a different scale in mind, but
# check the README operator runbook first — the numbers are there for
# reasons (security + optics + bootstrap runway).
# ───────────────────────────────────────────────────────────────────────

# The seed stakes ~1/10 of total supply — 99M tokens — chosen so the
# founder holds a durable 2/3+ supermajority of stake throughout the
# bootstrap window even after thousands of zero-funds validators
# accumulate escrow-era rewards.
#
# Napkin math for the security floor:
#   * BOOTSTRAP_END_HEIGHT ≈ 105K blocks → ≈ 1.68M tokens total minted
#     during bootstrap (16 tokens/block × 105K).
#   * Even if 100% of minted tokens are captured by non-seed validators
#     and immediately staked, that's ≤ 2M of non-seed stake.
#   * With 1 seed × 99M = 99M seed stake, seed share stays above
#     99M / (99M + 2M) = 98%.  Comfortable headroom against Sybil
#     stake accumulation AND against the founder wanting to move
#     some allocation (e.g. treasury grants, early backers) without
#     losing >2/3 control.
#
# This is the "founder secures the chain during bootstrap" constant.
# Smaller values weaken Sybil resistance; larger values over-concentrate
# supply.  99M (~9.9%) is the pragmatic sweet spot.
RECOMMENDED_STAKE_PER_SEED: int = 99_000_000

# Fee buffer sized to cover the seed's initial surcharge-bearing ops.
#
# Since NEW_ACCOUNT_FEE = 1000 burns on any Transfer whose recipient
# does not yet exist on chain, a single sweep from the seed to a brand-
# new payout address now costs MIN_FEE + NEW_ACCOUNT_FEE = 1100 tokens.
# The previous 1000-token buffer was insufficient — it would not cover
# even one such sweep.
#
# We budget for ~5 surcharge-bearing ops: set-authority-key (no
# surcharge, but still fee), a first payout-address funding (surcharge),
# and a few retries / emergency sweeps to fresh addresses.  The math:
#   (MIN_FEE + NEW_ACCOUNT_FEE) * 5 = 1100 * 5 = 5500
# rounds to a clean 5500 which is still dwarfed by stake + treasury,
# so the fee buffer has no meaningful impact on genesis allocation math.
RECOMMENDED_FEE_BUFFER: int = (MIN_FEE + NEW_ACCOUNT_FEE) * 5  # 5_500
RECOMMENDED_GENESIS_PER_SEED: int = (
    RECOMMENDED_STAKE_PER_SEED + RECOMMENDED_FEE_BUFFER
)


def build_launch_allocation(
    seed_entity_ids: list[bytes],
    stake_per_seed: int = RECOMMENDED_STAKE_PER_SEED,
    fee_buffer: int = RECOMMENDED_FEE_BUFFER,
) -> dict[bytes, int]:
    """Build the genesis allocation table for a seed-validator launch.

    Credits the seed with `stake_per_seed + fee_buffer` liquid at
    genesis, plus the standard treasury allocation.  Payout entities
    are NOT pre-allocated — they are created implicitly when they first
    receive a transfer from the seed (receive-to-exist model), and
    their pubkey is installed on their first outgoing transfer.

    Requires exactly 1 seed entity_id — the founder's single validator.
    If you want a different shape, build the dict yourself.
    """
    from messagechain.config import TREASURY_ENTITY_ID, TREASURY_ALLOCATION
    if len(seed_entity_ids) != 1:
        raise ValueError(
            f"Recommended launch plan requires exactly 1 seed entity_id, "
            f"got {len(seed_entity_ids)}.  Build the allocation table "
            f"manually if you need a different shape."
        )
    if len(set(seed_entity_ids)) != 1:
        raise ValueError("seed entity_ids must be distinct")
    if stake_per_seed <= 0 or fee_buffer < 0:
        raise ValueError("stake_per_seed must be positive, fee_buffer non-negative")

    per_seed = stake_per_seed + fee_buffer
    allocation = {TREASURY_ENTITY_ID: TREASURY_ALLOCATION}
    for eid in seed_entity_ids:
        allocation[eid] = per_seed
    return allocation
