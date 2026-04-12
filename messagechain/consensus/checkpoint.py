"""
Weak subjectivity checkpoints for MessageChain.

PoS chains are vulnerable to long-range attacks: an attacker with old validator
keys can create a fake chain from far in the past. Weak subjectivity checkpoints
solve this by providing a trusted recent state that new nodes verify against
during initial sync.

Nodes MUST obtain a recent checkpoint from a trusted source (e.g., embedded
in the node software, or downloaded from a known operator) before syncing.
Any chain that doesn't match the checkpoint at the specified height is rejected.

This is the same approach used by Ethereum's Beacon Chain.
"""

import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class WeakSubjectivityCheckpoint:
    """A trusted snapshot of chain state at a specific height.

    Fields:
        block_number: The height at which this checkpoint applies.
        block_hash: The expected block hash at that height.
        state_root: The expected state root at that height.
    """
    block_number: int
    block_hash: bytes
    state_root: bytes

    def serialize(self) -> dict:
        return {
            "block_number": self.block_number,
            "block_hash": self.block_hash.hex(),
            "state_root": self.state_root.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "WeakSubjectivityCheckpoint":
        return cls(
            block_number=data["block_number"],
            block_hash=bytes.fromhex(data["block_hash"]),
            state_root=bytes.fromhex(data["state_root"]),
        )


def create_checkpoint(chain, block_number: int) -> WeakSubjectivityCheckpoint:
    """Create a checkpoint from an existing block in the chain.

    Args:
        chain: The Blockchain instance.
        block_number: The block height to checkpoint.

    Returns:
        A WeakSubjectivityCheckpoint for the specified block.

    Raises:
        ValueError: If the block doesn't exist.
    """
    block = chain.get_block(block_number)
    if block is None:
        raise ValueError(f"Block {block_number} not found in chain")

    return WeakSubjectivityCheckpoint(
        block_number=block_number,
        block_hash=block.block_hash,
        state_root=block.header.state_root,
    )


def load_checkpoints_file(path: str) -> list[WeakSubjectivityCheckpoint]:
    """Load trusted weak-subjectivity checkpoints from a JSON file.

    Operators ship this file out-of-band (e.g., alongside release binaries,
    fetched from a trusted source, or distributed via signed update).
    Trust anchors in "operator placed this file here" — the loader does
    not verify signatures on the file itself; that's a deployment concern.

    File format: a JSON array of objects, each with fields
        {"block_number": int, "block_hash": hex, "state_root": hex}

    Returns an empty list on missing/malformed files so a first-run node
    still starts successfully — the operator is responsible for noticing
    that checkpoints are absent and populating them.
    """
    try:
        with open(path, "r") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read checkpoints file {path}: {e}")
        return []

    if not isinstance(raw, list):
        logger.warning(f"Checkpoints file {path}: expected a JSON array")
        return []

    result: list[WeakSubjectivityCheckpoint] = []
    for entry in raw:
        try:
            result.append(WeakSubjectivityCheckpoint.deserialize(entry))
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(f"Skipping malformed checkpoint entry: {e}")
            continue
    logger.info(f"Loaded {len(result)} trusted checkpoint(s) from {path}")
    return result


def validate_checkpoint(chain, checkpoint: WeakSubjectivityCheckpoint) -> bool:
    """Validate that the chain matches a checkpoint.

    Returns True if the chain has the specified block and its hash
    and state root match the checkpoint. Returns False otherwise.
    """
    block = chain.get_block(checkpoint.block_number)
    if block is None:
        return False

    if block.block_hash != checkpoint.block_hash:
        return False

    if block.header.state_root != checkpoint.state_root:
        return False

    return True
