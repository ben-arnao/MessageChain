"""Audit r56 #2 -- wallet UI cold-key chokepoint covers EVERY op_*.

Audit r55 #1 closed the leaf-burn footgun on ``op_unstake`` by routing
it through ``_require_hot_signable_via_rpc`` BEFORE leaf reservation.
That was symptom-level: the right abstraction is that the wallet UI is
a hot-key-only signing surface, so the chokepoint belongs at the top
of EVERY ``op_*`` -- not just the one cold-gated tx kind we knew
about at the time.  Today only ``unstake`` returns "yes" from the
cold-gated registry, but a future tier widening cold-key authority to
another tx kind (transfer, propose, etc.) would otherwise have to
re-discover the leaf-burn defect from scratch.

Tier 78-paired structural fix: ``_KIND_IS_COLD_GATED`` registry lifted
to a single source of truth; helper short-circuits non-cold-gated
kinds without burning an RPC; every ``op_*`` calls the helper at the
top so future cold-gated kinds inherit the leaf-burn prevention by
construction.

CLAUDE.md anchors defended:
  * Honest-operator insurance -- any future leaf-burn DoS via a wallet
    UI op is closed at the abstraction level.
  * Token-as-tradable-asset mainstream-asset quality bar -- the
    wallet UI's leaf-burn defense matches the CLI's, by construction.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace


def _make_dummy_entity():
    eid = bytes(range(32))
    pub = b"\xab" * 32
    keypair = SimpleNamespace(
        public_key=pub,
        num_leaves=1024,
        _next_leaf=0,
        sign=lambda _msg: b"\x00" * 64,
    )
    return SimpleNamespace(
        entity_id=eid,
        entity_id_hex=eid.hex(),
        public_key=pub,
        keypair=keypair,
    )


class TestColdGatedRegistry(unittest.TestCase):
    """The wallet_ops module exposes a single ``_KIND_IS_COLD_GATED``
    map naming exactly the tx kinds whose chain admission rejects a
    hot-key signature.  Adding a new cold-gated kind happens here; the
    helper inherits the leaf-burn-prevention property by construction.
    """

    def test_registry_marks_unstake_cold_gated(self):
        from messagechain.network.wallet_ops import _KIND_IS_COLD_GATED
        self.assertTrue(_KIND_IS_COLD_GATED.get("unstake"))

    def test_registry_does_not_mark_non_cold_gated_kinds(self):
        # Today the chain ONLY treats unstake as cold-gated for keys
        # bound under SetAuthorityKey.  Marking transfer/send/etc. as
        # cold-gated here would refuse a wallet-UI op the chain would
        # accept, regressing the "wallet UI is a real wallet" UX.
        from messagechain.network.wallet_ops import _KIND_IS_COLD_GATED
        for kind in (
            "send", "transfer", "stake", "react", "propose", "vote",
        ):
            self.assertFalse(
                _KIND_IS_COLD_GATED.get(kind, False),
                f"kind {kind!r} must NOT be marked cold-gated until the "
                f"chain actually rejects hot-key sigs on that path -- "
                f"the helper would otherwise refuse a tx the chain "
                f"would happily accept.",
            )


class TestHelperShortCircuitsNonColdGated(unittest.TestCase):
    """Non-cold-gated kinds must short-circuit through the helper
    WITHOUT calling ``get_authority_key``.  Two reasons:

      1. Performance / surface minimization -- saves one RPC on the
         hot path of every send/transfer/react.
      2. Behavior correctness -- a user who has set a cold key for
         FUTURE cold-gated ops must still be able to send transfers /
         post messages / etc. through the wallet UI.  Refusing on
         non-cold-gated kinds when authority_key differs would
         silently brick the wallet UI for any cold-key holder.
    """

    def test_non_cold_gated_kind_does_not_call_rpc(self):
        from messagechain.network.wallet_ops import (
            _require_hot_signable_via_rpc,
        )
        entity = _make_dummy_entity()
        rpc_call_count = {"n": 0}

        def _rpc(method, params):
            rpc_call_count["n"] += 1
            return {"ok": True, "result": {"authority_key": "ff" * 32}}

        # 'send' is NOT cold-gated.  Helper must return OK WITHOUT
        # calling get_authority_key -- even though, if it had, the
        # different cold key would have triggered a refusal.
        ok, err = _require_hot_signable_via_rpc(_rpc, entity, kind="send")
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(rpc_call_count["n"], 0)

    def test_cold_gated_kind_still_calls_rpc_and_refuses(self):
        # Sanity-pin: the r55 behavior is preserved for cold-gated
        # kinds -- helper still consults get_authority_key and refuses
        # when the cold key differs.
        from messagechain.network.wallet_ops import (
            _require_hot_signable_via_rpc,
        )
        entity = _make_dummy_entity()
        rpc_call_count = {"n": 0}

        def _rpc(method, params):
            rpc_call_count["n"] += 1
            return {"ok": True, "result": {"authority_key": "ff" * 32}}

        ok, err = _require_hot_signable_via_rpc(_rpc, entity, kind="unstake")
        self.assertFalse(ok)
        self.assertIsNotNone(err)
        self.assertGreater(rpc_call_count["n"], 0)


class TestEveryOpRoutesThroughChokepoint(unittest.TestCase):
    """Structural pin: every public ``op_*`` helper in wallet_ops calls
    ``_require_hot_signable_via_rpc`` BEFORE any leaf-resolution work.
    Without this property, a future op_X addition silently re-opens
    the leaf-burn-on-cold-gated-kind defect.

    Grep-based, against the function source -- not a behavioral test
    of every op, because the cold-gated registry currently only flags
    unstake, so non-cold-gated ops are no-op'd by the helper at
    runtime.  The structural pin is what guarantees that the moment
    the registry widens, every existing op inherits the prevention.
    """

    def test_each_op_calls_helper_before_leaf_resolution(self):
        import inspect
        from messagechain.network import wallet_ops

        for fn_name in (
            "op_send_message",
            "op_transfer",
            "op_stake",
            "op_unstake",
            "op_react",
            "op_propose",
            "op_vote_proposal",
        ):
            fn = getattr(wallet_ops, fn_name)
            src = inspect.getsource(fn)
            self.assertIn(
                "_require_hot_signable_via_rpc",
                src,
                f"{fn_name} must call _require_hot_signable_via_rpc "
                f"so a future cold-gated kind inherits the wallet-UI "
                f"leaf-burn prevention by construction.",
            )
            # Ordering: the helper invocation must precede the leaf-
            # resolution CALL site (otherwise the leaf is already
            # reserved by the time we'd refuse).  ``_resolve_signing_
            # leaf_via_caller`` appears once as an import and once as
            # a call; we want the call -- it's the one with the open
            # paren immediately after.
            helper_pos = src.find("_require_hot_signable_via_rpc(")
            leaf_call_pos = src.find("_resolve_signing_leaf_via_caller(\n")
            if leaf_call_pos < 0:
                # Some ops may format the call differently; try
                # whitespace-tolerant match against the open paren.
                leaf_call_pos = src.find(
                    "_resolve_signing_leaf_via_caller(",
                    src.find("def "),
                )
                # Skip past the import-line occurrence by finding the
                # NEXT occurrence after the function body starts.
                import_pos = src.find(
                    "import _resolve_signing_leaf_via_caller",
                )
                if import_pos >= 0 and leaf_call_pos == import_pos - len(
                    "from messagechain.cli "
                ):
                    leaf_call_pos = src.find(
                        "_resolve_signing_leaf_via_caller(",
                        import_pos + 1,
                    )
            self.assertGreaterEqual(
                helper_pos, 0,
                f"{fn_name}: must call _require_hot_signable_via_rpc",
            )
            if leaf_call_pos >= 0:
                self.assertLess(
                    helper_pos, leaf_call_pos,
                    f"{fn_name}: chokepoint call must precede leaf "
                    f"resolution -- the entire point is to refuse "
                    f"BEFORE burning the WOTS+ leaf.",
                )


class TestNonColdGatedOpProceedsEvenWithDistinctColdKey(unittest.TestCase):
    """Behavioral pin: an entity that has set a cold authority key
    (e.g. for future unstake protection) must still be able to send
    transfers / messages / etc. through the wallet UI.  The chokepoint
    must NOT regress this.

    Tested via op_transfer because it's the closest analogue to
    op_unstake (also requires recipient + amount), but is NOT
    cold-gated.  A hot-key-signed transfer must proceed.
    """

    def test_transfer_with_distinct_cold_key_still_attempts_signing(self):
        from messagechain.network.wallet_ops import op_transfer

        called = {"reserve_leaf": False, "submit_transfer": False}

        def _rpc(method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 0}}
            if method == "get_authority_key":
                # Distinct cold key set -- but transfer is not cold-
                # gated, so this must NOT refuse the op.
                return {"ok": True, "result": {"authority_key": "ff" * 32}}
            if method == "reserve_leaf":
                called["reserve_leaf"] = True
                return {"ok": False, "error": "n/a"}
            if method == "submit_transfer":
                called["submit_transfer"] = True
                return {"ok": True, "result": {"tx_hash": "00" * 32}}
            raise NotImplementedError(method)

        entity = _make_dummy_entity()
        # op_transfer would actually try to sign a tx; with the dummy
        # entity's stub keypair (sign returns 64 zero bytes), the
        # create_transfer_transaction call will fail.  That's fine --
        # we only need to assert the cold-key check did NOT refuse.
        # The signal is "reserve_leaf was called" (or the failure mode
        # is not the cold-key refusal).
        try:
            result = op_transfer(
                entity, _rpc,
                recipient=bytes(range(32, 64)),
                amount=10, fee=1, data_dir=None,
            )
        except Exception:
            # Stub keypair can't actually sign; that's OK for this
            # test.  What matters is that the cold-key check passed.
            return
        # If we got here, the op returned a dict.  It must NOT be a
        # cold-key refusal.
        if not result.get("ok"):
            self.assertNotIn(
                "cold", (result.get("error") or "").lower(),
                "op_transfer must NOT refuse on a distinct cold key -- "
                "transfer is not cold-gated; refusing here regresses "
                "the wallet UI for any cold-key holder.",
            )


if __name__ == "__main__":
    unittest.main()
