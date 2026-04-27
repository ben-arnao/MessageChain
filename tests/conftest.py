"""Shared pytest configuration and fixtures for MessageChain tests."""

import os
import tempfile

import pytest

# Guard the CLI `start --mine` reachability probe so unit tests never hit
# the network. Tests that specifically exercise the probe clear this.
os.environ.setdefault("MC_SKIP_REACHABILITY", "1")

# ---------------------------------------------------------------------------
# Sandbox HOME so CLI tests don't share leaf-index state with the
# operator's real ~/.messagechain/leaves/ directory.  Every test that
# exercises the CLI signing path (cmd_send / cmd_transfer / cmd_stake /
# cmd_unstake / cmd_set_authority_key / cmd_emergency_revoke / ...) goes
# through ``_resolve_leaf_index_path`` which reads ``Path.home()``.  With
# the cross-process advisory lock in place ``KeyPair.sign`` re-loads the
# cursor from disk on every sign, so accumulating state across tests on
# the same hardcoded private-key fixture causes
# ``Corrupted leaf index file: next_leaf=N >= num_leaves=N`` once N hits
# 2^MERKLE_TREE_HEIGHT.  Sandboxing HOME per session-and-worker keeps the
# test suite hermetic AND keeps the operator's real home untouched.
_TEST_HOME_DIR = tempfile.mkdtemp(prefix="mc-test-home-")
os.environ["HOME"] = _TEST_HOME_DIR
# Windows: Path.home() reads USERPROFILE (or HOMEDRIVE+HOMEPATH).
os.environ["USERPROFILE"] = _TEST_HOME_DIR

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
