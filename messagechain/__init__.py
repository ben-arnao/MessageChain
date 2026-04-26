"""MessageChain - A message-based blockchain protocol."""

# Runtime version string. Advertised to peers in the P2P handshake payload
# (see messagechain/network/node.py and server.py) and surfaced in the
# `messagechain status` / `messagechain peers` CLI output. Keep this in
# sync with pyproject.toml's `version` field.
__version__ = "1.16.0"
