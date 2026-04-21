"""Shared-runtime mixin regression guard.

Iter B-small (post-iter-5 hardening): `server.Server` and
`messagechain.network.node.Node` were two parallel validator
runtimes with 20 methods duplicated by name.  Fifteen of those
duplications were byte-identical modulo docstring text — a maintenance
hazard because every hardening fix had to be applied to both copies.

This test suite pins the non-drifted methods into a single mixin
(`messagechain.runtime.shared.SharedRuntimeMixin`) and asserts both
runtime classes inherit from it.  If a future contributor
re-duplicates a method on one class that already lives on the mixin,
these tests fail early instead of silently drifting.
"""

from __future__ import annotations

import unittest

from messagechain.runtime.shared import SharedRuntimeMixin


# The canonical list of methods the mixin owns.  Grows as more
# behavioral-drift pairs are reconciled in future iters.  Each name
# must:
#   1. Be defined on SharedRuntimeMixin.
#   2. Be REACHABLE from both Server and Node via MRO.
#   3. NOT be shadowed by a re-definition on Server or Node.
_MIXIN_OWNED_METHODS = frozenset({
    "_block_production_loop",
    "_current_cumulative_weight",
    "_get_peer_writer",
    "_handle_task_exception",
    "_msg_category",
    "_next_connection_type",
    "_on_sync_offense",
    "_track_seen_tx",
})


class TestMixinOwnership(unittest.TestCase):

    def test_mixin_defines_each_owned_method(self):
        for name in _MIXIN_OWNED_METHODS:
            self.assertTrue(
                name in vars(SharedRuntimeMixin),
                f"{name} must be defined on SharedRuntimeMixin",
            )

    def test_server_inherits_mixin_owned_methods(self):
        from server import Server
        self.assertTrue(
            issubclass(Server, SharedRuntimeMixin),
            "Server must inherit SharedRuntimeMixin",
        )
        for name in _MIXIN_OWNED_METHODS:
            # The method on Server must resolve via MRO to the mixin's
            # definition — NOT be re-defined on Server itself.
            owner = _defining_class(Server, name)
            self.assertIs(
                owner, SharedRuntimeMixin,
                f"Server.{name} was re-defined on Server (should come "
                f"from SharedRuntimeMixin) — did a contributor silently "
                f"re-duplicate a unified method?",
            )

    def test_node_inherits_mixin_owned_methods(self):
        from messagechain.network.node import Node
        self.assertTrue(
            issubclass(Node, SharedRuntimeMixin),
            "Node must inherit SharedRuntimeMixin",
        )
        for name in _MIXIN_OWNED_METHODS:
            owner = _defining_class(Node, name)
            self.assertIs(
                owner, SharedRuntimeMixin,
                f"Node.{name} was re-defined on Node (should come "
                f"from SharedRuntimeMixin) — did a contributor silently "
                f"re-duplicate a unified method?",
            )


def _defining_class(cls: type, name: str) -> type | None:
    """Walk cls.__mro__ and return the first class that owns `name` in
    its own __dict__ (i.e., defines it rather than inheriting it).
    Returns None if no class in the MRO defines it.
    """
    for c in cls.__mro__:
        if name in vars(c):
            return c
    return None


if __name__ == "__main__":
    unittest.main()
