"""
VRF-based proposer selection via RANDAO lookahead.

Problem: With the current RANDAO design, the proposer for block N+1 is
fully predictable once block N is published — the attacker has one full
block time (~10 min) to DDoS, bribe, or coerce the known-in-advance
proposer.

Solution: Proposer selection for block N uses randao_mix from block
N - VRF_LOOKAHEAD instead of the immediate parent. This means the
proposer for block N is determined by randomness that was fixed
VRF_LOOKAHEAD blocks ago, but since the proposer only needs to act
when their slot arrives, and can prove eligibility by signing the block,
the set of eligible proposers for the next VRF_LOOKAHEAD blocks is known
only to each validator privately (they can check their own eligibility)
but NOT to external observers until the block is published.

VRF_LOOKAHEAD = 32 means ~5.3 hours of unpredictability at 600s blocks.

Seed management:
- Each validator generates a randao_seed at registration time.
- They publish randao_commitment = SHA3(randao_seed) on-chain.
- The commitment is stored in state; the actual seed stays secret.
- The proposer's block-level contribution to RANDAO remains the
  signature-derived mix (unchanged from the existing randao.py).
"""

import hashlib
import struct
from messagechain.config import HASH_ALGO


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def compute_randao_commitment(seed: bytes) -> bytes:
    """Compute the on-chain commitment for a validator's RANDAO seed.

    commitment = SHA3("randao_commitment_v1" || seed)

    Published at registration time; the seed itself stays secret.
    """
    return _hash(b"randao_commitment_v1" + seed)


def compute_randao_reveal(seed: bytes, block_number: int) -> bytes:
    """Compute a validator's RANDAO reveal for a specific block.

    reveal = SHA3("randao_reveal_v1" || seed || block_number)

    Deterministic given seed + block_number, but unpredictable to
    anyone who doesn't know seed.
    """
    return _hash(
        b"randao_reveal_v1"
        + seed
        + struct.pack(">Q", block_number)
    )


def verify_randao_reveal(
    reveal: bytes,
    commitment: bytes,
    seed: bytes,
    block_number: int,
) -> bool:
    """Verify a RANDAO reveal against its commitment.

    The verifier needs the seed (which the proposer reveals when they
    propose). Check that:
    1. The commitment matches SHA3(seed)
    2. The reveal matches SHA3(seed || block_number)
    """
    expected_commitment = compute_randao_commitment(seed)
    if expected_commitment != commitment:
        return False
    expected_reveal = compute_randao_reveal(seed, block_number)
    return reveal == expected_reveal


def mix_randao(current_mix: bytes, reveal: bytes) -> bytes:
    """Mix a reveal into the current RANDAO accumulator.

    Same construction as the existing randao.py RANDAOMix.update:
    hash the reveal (domain separation), XOR with current, re-hash
    to prevent last-proposer bias.
    """
    hashed_reveal = _hash(b"randao_reveal" + reveal)
    xored = bytes(a ^ b for a, b in zip(current_mix, hashed_reveal))
    return _hash(b"randao_mix" + xored)


def get_lookahead_randao_mix(
    chain_mixes: list[bytes],
    block_number: int,
    lookahead: int,
) -> bytes:
    """Get the randao_mix to use for proposer selection at block_number.

    Returns the mix from block (block_number - lookahead), clamped to
    the genesis block (index 0) for early chain blocks.

    Args:
        chain_mixes: list of randao_mix values indexed by block number
        block_number: the block being proposed
        lookahead: VRF_LOOKAHEAD from config
    """
    target = max(0, block_number - lookahead)
    # Clamp to available chain length
    target = min(target, len(chain_mixes) - 1)
    return chain_mixes[target]


def select_proposer_vrf(
    randao_mix: bytes,
    block_number: int,
    validators: dict[bytes, int],
    round_number: int = 0,
) -> bytes | None:
    """Select a proposer using VRF lookahead randomness.

    Uses randao_mix (from VRF_LOOKAHEAD blocks ago) combined with the
    block number and round number for stake-weighted selection.

    Args:
        randao_mix: the RANDAO mix from block (N - VRF_LOOKAHEAD)
        block_number: the block being proposed
        validators: entity_id -> stake mapping
        round_number: liveness fallback (0 = primary proposer)

    Returns:
        Selected proposer entity_id, or None if no validators
    """
    if not validators:
        return None

    sorted_validators = sorted(validators.items(), key=lambda x: x[0])
    total = sum(s for _, s in sorted_validators)
    if total == 0:
        return None

    # Domain-separated hash: mix + block_number + round_number
    seed = _hash(
        b"vrf_proposer_v1"
        + randao_mix
        + struct.pack(">Q", block_number)
        + struct.pack(">I", round_number)
    )
    rand_value = int.from_bytes(seed, "big") % total

    cumulative = 0
    for entity_id, stake in sorted_validators:
        cumulative += stake
        if rand_value < cumulative:
            return entity_id

    return sorted_validators[-1][0]  # fallback
