"""Shared pytest configuration and fixtures for MessageChain tests."""

import os

import pytest

# Guard the CLI `start --mine` reachability probe so unit tests never hit
# the network. Tests that specifically exercise the probe clear this.
os.environ.setdefault("MC_SKIP_REACHABILITY", "1")

# ---------------------------------------------------------------------------
# Reduce MERKLE_TREE_HEIGHT for tests (height=4 -> 16 leaves instead of 1M).
# This cuts entity creation time by ~64k× vs the production default of 20,
# while still exercising the full WOTS+ / Merkle-tree code path.
# ---------------------------------------------------------------------------
import messagechain.config

_PROD_MERKLE_TREE_HEIGHT = messagechain.config.MERKLE_TREE_HEIGHT
messagechain.config.MERKLE_TREE_HEIGHT = 4


@pytest.fixture(autouse=True)
def _reset_merkle_height_after_slow(request):
    """Tests marked @pytest.mark.slow run with the production tree height."""
    marker = request.node.get_closest_marker("slow")
    if marker:
        messagechain.config.MERKLE_TREE_HEIGHT = _PROD_MERKLE_TREE_HEIGHT
        yield
        messagechain.config.MERKLE_TREE_HEIGHT = 4
    else:
        yield


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: run with production MERKLE_TREE_HEIGHT=20")
