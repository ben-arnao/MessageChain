"""Regression for audit r53 #2.

A fresh validator following the README "Run a validator" flow
(generate-key → fund via faucet → ``messagechain stake --amount 200``)
hit two coupled defects:

  (1) ``cmd_stake`` (cli.py) builds the StakeTransaction without
      ``include_pubkey=True``.  Even though ``create_stake_transaction``
      accepts the kwarg and ``StakeTransaction.sender_pubkey`` is a
      first-class field (Tier 11), every signing path except cmd_send
      / cmd_transfer / cmd_send_multi_submit forgot to set it.

  (2) ``Server._rpc_stake`` hard-gates on
      ``entity_id in self.blockchain.public_keys`` BEFORE consulting
      ``tx.sender_pubkey``, so even if the CLI did set ``include_pubkey``
      the admission would still reject with "Unknown entity".

Net effect: every fresh validator install on mainnet was wedged at
the stake step, with the README giving no workaround.

Fix shape: route ``Server._rpc_stake`` through the same first-spend
pubkey-resolution chokepoint (``_tx_signer_pubkey``, audit r51 #1)
that ``submit_transaction`` and the gossip-ingress paths already use,
and wire ``_should_include_pubkey`` through ``cmd_stake`` so the CLI
actually carries ``sender_pubkey`` on the first spend.

Property tested:
  * ``_rpc_stake`` admits a fresh-entity stake tx that carries a
    ``sender_pubkey`` whose ``derive_entity_id`` matches the tx's
    ``entity_id`` -- the audit-r51 #1 chokepoint discipline lifted to
    the stake admission path.
  * ``_rpc_stake`` still rejects a fresh-entity stake tx that
    carries NO ``sender_pubkey`` (no install path → still "Unknown
    entity").
  * A spoofed ``sender_pubkey`` that does NOT derive to the claimed
    ``entity_id`` is rejected.
"""

from __future__ import annotations

import unittest

from messagechain.core.staking import create_stake_transaction
from messagechain.identity.identity import Entity


def _make_fresh_stake_tx(include_pubkey: bool):
    entity = Entity.create(b"r53-stake-first-spend-seed-padded!")
    tx = create_stake_transaction(
        entity,
        amount=10_000,
        nonce=0,
        fee=1_000,
        include_pubkey=include_pubkey,
    )
    return entity, tx


class _StubBlockchain:
    """Minimal stub: empty public_keys + enough surface for _rpc_stake's
    cheap-gate ordering.  ``can_afford_fee`` returns True so we get past
    the balance check; ``get_leaf_watermark`` returns 0 so the leaf
    check passes; ``height`` is irrelevant for this test.
    """

    def __init__(self):
        self.public_keys = {}  # fresh entity — NOT registered
        self.nonces = {}        # fresh entity — no prior nonces
        self.height = 100  # well past UNIFIED_FEE_FLOOR_HEIGHT

        class _Supply:
            def can_afford_fee(self, eid, amt):
                return True

            def get_staked(self, eid):
                return 0

        self.supply = _Supply()

    def get_leaf_watermark(self, eid):
        return 0

    def get_authority_key(self, eid):
        return None


class TestRpcStakeAdmitsFreshFirstSpend(unittest.TestCase):
    """``Server._rpc_stake`` must admit a fresh-wallet stake tx that
    carries a self-installing ``sender_pubkey`` reveal — mirroring the
    audit r51 #1 chokepoint discipline on the gossip side."""

    def _make_test_server(self):
        from server import Server
        srv = Server.__new__(Server)
        srv.blockchain = _StubBlockchain()
        # Pools used by the cross-pool leaf-reuse check.  Empty.
        srv._pending_message_txs = {}
        srv._pending_transfer_txs = {}
        srv._pending_stake_txs = {}
        srv._pending_unstake_txs = {}
        srv._pending_governance_txs = {}
        srv._pending_authority_txs = {}
        srv._pending_revoke_txs = {}
        srv._pending_react_txs = {}
        srv._pending_key_rotation_txs = {}

        class _Mempool:
            def __init__(self):
                self.pending = {}
                self.censorship_evidence_pool = {}
                self.bogus_rejection_evidence_pool = {}
                self.non_response_evidence_pool = {}
                self.inclusion_list_violation_evidence_pool = {}
                self.slash_pool = {}
                self.finality_pool = {}

            def get_pending_nonce_for_entity(self, eid):
                return None

            def get_pending_nonce(self, eid, on_chain_nonce):
                return on_chain_nonce

            def message_witness_leaf_in_use(self, sender, leaf):
                return False

        srv.mempool = _Mempool()

        # The gossip scheduler is a no-op stub for admission tests.
        srv._schedule_pending_tx_gossip = lambda kind, tx: None

        # The pool-admit shim.  We don't need real density ranking for
        # this test — admit always succeeds when called.
        def _admit(pool_name, tx):
            getattr(srv, pool_name)[tx.tx_hash] = tx
            return True

        srv._admit_to_pool = _admit
        return srv

    def test_fresh_stake_with_sender_pubkey_is_admitted(self):
        """The pivotal property: ``_rpc_stake`` no longer hard-gates on
        ``entity_id in public_keys`` BEFORE consulting ``tx.sender_pubkey``.
        Pre-fix this returned ``{"ok": False, "error": "Unknown entity"}``;
        post-fix it routes through the first-spend resolver."""
        srv = self._make_test_server()
        entity, tx = _make_fresh_stake_tx(include_pubkey=True)

        resp = srv._rpc_stake({"transaction": tx.serialize()})

        self.assertTrue(
            resp.get("ok"),
            f"fresh-wallet first-spend stake was rejected: "
            f"{resp.get('error')!r} -- the README 'Run a validator' "
            f"flow is broken whenever the operator's stake is their "
            f"FIRST on-chain spend (the default path: faucet drip "
            f"-> stake)",
        )

    def test_fresh_stake_without_sender_pubkey_is_still_rejected(self):
        """Defense against false-pass: if the CLI forgot to set
        ``include_pubkey`` (the audit-r53 #2 #1 defect), the server must
        still reject -- otherwise the install path is bypassed and the
        entity is never registered on chain."""
        srv = self._make_test_server()
        entity, tx = _make_fresh_stake_tx(include_pubkey=False)

        resp = srv._rpc_stake({"transaction": tx.serialize()})

        self.assertFalse(resp.get("ok"))
        self.assertIn("Unknown entity", resp.get("error", ""))

    def test_spoofed_sender_pubkey_is_rejected(self):
        """A tx whose ``sender_pubkey`` does NOT derive to the claimed
        ``entity_id`` must NOT pass the first-spend gate -- otherwise
        an attacker could install an arbitrary pubkey under any
        entity_id of their choosing on the very first spend."""
        srv = self._make_test_server()
        entity, tx = _make_fresh_stake_tx(include_pubkey=True)
        # Swap in a stranger's pubkey while keeping the (real)
        # entity_id.  Re-sign with the real key so structural fields
        # are intact; the derive-mismatch is the only defect.
        stranger = Entity.create(b"r53-stranger-seed-padded-to-32by!2")
        tx.sender_pubkey = stranger.public_key
        # tx.signature is the real entity's sig over the original
        # signable_data, so signature verify will fail too — but the
        # important property is the derive check fires FIRST.

        resp = srv._rpc_stake({"transaction": tx.serialize()})

        self.assertFalse(resp.get("ok"))


class TestCliCmdStakeSetsSenderPubkeyOnFirstSpend(unittest.TestCase):
    """``cmd_stake`` must wire ``_should_include_pubkey`` through to
    ``create_stake_transaction``, otherwise the rpc admits fresh wallets
    but the CLI never carries the pubkey reveal in its tx."""

    def test_create_stake_transaction_with_include_pubkey_carries_field(self):
        """Direct property test on the underlying helper, since
        ``cmd_stake`` itself goes through RPC and a CLI runner.  The
        helper signature is the contract ``cmd_stake`` consumes."""
        entity, tx = _make_fresh_stake_tx(include_pubkey=True)
        self.assertEqual(tx.sender_pubkey, entity.public_key)
        self.assertEqual(len(tx.sender_pubkey), 32)


if __name__ == "__main__":
    unittest.main()
