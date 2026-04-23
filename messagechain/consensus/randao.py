"""
RANDAO commit-reveal randomness for proposer selection.

Problem: Using prev_block_hash alone as the randomness seed lets the
current proposer grind block contents (include/exclude transactions)
to influence who proposes the next block.

Solution: Each proposer contributes a "reveal" value that is mixed into
a cumulative RANDAO accumulator. The reveal is the hash of a secret
pre-committed in a previous block. Since the reveal can't be predicted
by other validators, and can't be withheld without forfeiting the block
reward, this produces unbiasable randomness.

This is the same approach used by Ethereum's Beacon Chain.
"""

import hashlib
from messagechain.config import HASH_ALGO
from messagechain.crypto.hashing import default_hash


def _hash(data: bytes) -> bytes:
    return default_hash(data)


class RANDAOMix:
    """Accumulates randomness from proposer reveals.

    Each block, the proposer's reveal is XORed into the current mix.
    The mix is used alongside prev_block_hash for proposer selection.
    """

    def __init__(self, initial_mix: bytes | None = None):
        self.current_mix: bytes = initial_mix or b"\x00" * 32

    def update(self, reveal: bytes) -> bytes:
        """Mix in a new proposer reveal.

        The reveal is hashed first (domain separation), then XORed
        with the current mix to produce the new mix.
        """
        hashed_reveal = _hash(b"randao_reveal" + reveal)
        # XOR then re-hash to prevent last-proposer bias.
        # Without re-hash, the last proposer can compute desired output
        # by choosing reveal = current_mix XOR desired_output.
        xored = bytes(
            a ^ b for a, b in zip(self.current_mix, hashed_reveal)
        )
        self.current_mix = _hash(b"randao_mix" + xored)
        return self.current_mix

    def serialize(self) -> dict:
        return {"current_mix": self.current_mix.hex()}

    @classmethod
    def deserialize(cls, data: dict) -> "RANDAOMix":
        return cls(initial_mix=bytes.fromhex(data["current_mix"]))


def derive_randao_mix(parent_mix: bytes, proposer_signature) -> bytes:
    """Derive a block's randao_mix from its parent's mix and the proposer signature.

    The proposer signature is over the block header, so each distinct block
    candidate produces a distinct signature, which produces a distinct mix.
    Grinding the mix therefore requires consuming a fresh WOTS+ leaf for
    every attempt — visible on chain via proposer_sig_counts.

    The signature's canonical_bytes() representation is hashed first
    (domain separation against accidental collisions with bare bytes).
    """
    sig_bytes = proposer_signature.canonical_bytes()
    reveal = _hash(b"randao_reveal" + sig_bytes)
    # XOR + re-hash to prevent last-proposer bias (same construction as
    # RANDAOMix.update — kept consistent for the existing test suite).
    xored = bytes(a ^ b for a, b in zip(parent_mix, reveal))
    return _hash(b"randao_mix" + xored)


def randao_select_proposer(
    stakes: dict[bytes, int],
    prev_block_hash: bytes,
    randao_mix: bytes,
) -> bytes | None:
    """Select a proposer using RANDAO mix + prev_block_hash.

    Combines both entropy sources for stake-weighted selection.
    This prevents grinding attacks since the RANDAO mix depends on
    all previous proposers' reveals, not just the block contents.
    """
    if not stakes:
        return None

    validators = sorted(stakes.items(), key=lambda x: x[0])
    total = sum(s for _, s in validators)

    # Combine prev_block_hash and RANDAO mix for seed
    seed = _hash(prev_block_hash + randao_mix + b"proposer_selection")
    rand_value = int.from_bytes(seed, "big") % total

    cumulative = 0
    for entity_id, stake in validators:
        cumulative += stake
        if rand_value < cumulative:
            return entity_id

    return validators[-1][0]
