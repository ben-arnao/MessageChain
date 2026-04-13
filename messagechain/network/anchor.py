"""
Anchor connection persistence for MessageChain.

Anchor connections are saved to disk on shutdown and reconnected first on
startup. This prevents eclipse attacks across node restarts — an attacker
cannot isolate a node by waiting for it to restart and then filling all
its connection slots.

Inspired by Bitcoin Core's anchors.dat (PR #17428).
"""

import json
import logging

logger = logging.getLogger(__name__)


class AnchorStore:
    """Persists anchor peer addresses to survive node restarts."""

    def __init__(self, path: str):
        self.path = path

    def save_anchors(self, anchors: list[tuple[str, int]]):
        """Save anchor addresses to disk.

        Args:
            anchors: List of (host, port) tuples.
        """
        try:
            data = [{"host": h, "port": p} for h, p in anchors]
            with open(self.path, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning(f"Failed to save anchors: {e}")

    def load_anchors(self) -> list[tuple[str, int]]:
        """Load anchor addresses from disk.

        Returns empty list if file doesn't exist or is corrupt.
        Validates host and port to prevent anchor file poisoning.
        """
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            result = []
            for entry in data:
                host = entry.get("host", "")
                port = entry.get("port", 0)
                # H7: Validate port range
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    logger.warning(f"Skipping anchor with invalid port: {host}:{port}")
                    continue
                if not isinstance(host, str) or not host:
                    logger.warning(f"Skipping anchor with invalid host")
                    continue
                result.append((host, port))
            return result
        except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError):
            return []
