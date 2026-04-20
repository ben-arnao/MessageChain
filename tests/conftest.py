"""Shared pytest configuration and fixtures for MessageChain tests."""

import pytest

# ---------------------------------------------------------------------------
# Reduce MERKLE_TREE_HEIGHT for tests (height=4 -> 16 leaves instead of 1024).
# This cuts entity creation time by ~64x while still exercising the full
# WOTS+ / Merkle-tree code path.
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
