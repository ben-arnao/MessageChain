"""
Protocol version activation framework for MessageChain.

Each ProtocolVersion defines a set of consensus rules that activate at a
specific block height. This allows coordinated protocol upgrades:

- Old blocks validated under old rules remain valid forever.
- New rules take effect deterministically at the activation height.
- Nodes that haven't upgraded will reject blocks after an activation
  height they don't understand, prompting operators to upgrade.

To add a new protocol version:
1. Define the new ProtocolVersion with its activation height and features.
2. Append it to PROTOCOL_VERSIONS (must stay sorted by activation_height).
3. In block validation, check is_feature_active() to gate new behavior.
"""

from dataclasses import dataclass, field


@dataclass
class ProtocolVersion:
    """A protocol version with activation rules."""
    version: int
    activation_height: int  # block number where this version takes effect
    features: list[str] = field(default_factory=list)
    description: str = ""


# ── Protocol version history ──────────────────────────────────────────
# Append-only. Never remove or reorder entries.
PROTOCOL_VERSIONS: list[ProtocolVersion] = [
    ProtocolVersion(
        version=1,
        activation_height=0,
        features=[
            "base_protocol",
            "biometric_identity",
            "wots_signatures",
            "pos_consensus",
            "fee_market",
            "state_root",
            "slashing",
            "attestation_finality",
            "key_rotation",
            "governance",
            "unbonding_period",
            "authenticated_registration",
        ],
        description="Genesis protocol — all initial features",
    ),
]


def get_active_version(block_height: int) -> ProtocolVersion:
    """Return the protocol version active at the given block height.

    Returns the version with the highest activation_height that is
    <= block_height.
    """
    active = PROTOCOL_VERSIONS[0]
    for pv in PROTOCOL_VERSIONS:
        if pv.activation_height <= block_height:
            active = pv
        else:
            break
    return active


def is_feature_active(feature: str, block_height: int) -> bool:
    """Check if a specific feature is active at the given block height."""
    version = get_active_version(block_height)
    return feature in version.features


def get_max_known_version() -> int:
    """Return the highest protocol version this node understands."""
    return PROTOCOL_VERSIONS[-1].version
