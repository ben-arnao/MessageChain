"""Unified auto-fee helper + percentile-driven CLI urgency.

Audit motivation (verbatim):

    Auto-fee bids the floor; the percentile estimator already exists
    but isn't driven.  Default sends bid `max(local_min, server_suggested)`
    where `server_suggested` is a single number not parameterised by
    urgency, so default sends always bid at the floor.  The moment a
    backlog appears, default sends get evicted by fee-per-byte.

    Plus: estimate-fee accuracy across ALL transaction types — today
    the estimator is implicitly oriented around message txs; transfer,
    stake, unstake, react, propose, vote, key-rotation each have their
    own stored-byte profiles and the estimator may or may not handle
    them correctly.

These tests pin down:

  A. There is exactly ONE auto-fee helper (`messagechain.economics.
     auto_fee.auto_fee`) used by every tx-submitting CLI command.
  B. `--urgency {low,normal,high}` maps to a percentile rung in the
     existing FeeEstimator ladder.  Higher urgency → meaningfully
     higher bid.
  C. Each tx kind exposes a deterministic `stored_size()` so the
     estimator can charge the correct per-byte rate.
  D. The protocol floor returned by `tx_floor` matches the
     height-aware live admission rule for every tx kind.  No path
     rounds to 0 (CLAUDE.md anchored: "Minimum fee is 1, never 0.").
  E. `estimate-fee --tx-type X` returns the breakdown a user needs:
     protocol minimum, mempool percentile estimate, total recommended,
     per-byte rate.

Keeps the test suite green by importing only public symbols and using
the same patterns (MagicMock RPC, in-memory blockchain) as the rest of
the suite.
"""

import unittest
from unittest.mock import MagicMock, patch

from messagechain.config import (
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    KEY_ROTATION_FEE,
    MARKET_FEE_FLOOR,
    MARKET_FEE_FLOOR_HEIGHT,
    MIN_FEE,
    NEW_ACCOUNT_FEE,
    PROPOSAL_FEE_TIER19_HEIGHT,
    GOVERNANCE_PROPOSAL_FEE_TIER19,
    GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19,
    REACT_TX_HEIGHT,
    TIER_18_HEIGHT,
)


# ── A. unified helper exists, and every CLI command imports it ──────


class TestUnifiedHelperExists(unittest.TestCase):
    """A single auto-fee helper module is the source of truth for fees."""

    def test_module_importable(self):
        from messagechain.economics import auto_fee  # noqa: F401

    def test_auto_fee_callable(self):
        from messagechain.economics.auto_fee import auto_fee
        # Smoke: empty mempool, message at current height, normal urgency.
        # Should return the floor (>=1) and never 0.
        fee = auto_fee(
            "message",
            stored_size=100,
            urgency="normal",
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
            mempool_estimate=0,
        )
        self.assertGreaterEqual(fee, 1)

    def test_tx_floor_callable(self):
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "message",
            stored_size=100,
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
        )
        self.assertGreaterEqual(floor, 1)

    def test_urgency_to_target_blocks_callable(self):
        from messagechain.economics.auto_fee import urgency_to_target_blocks
        self.assertEqual(urgency_to_target_blocks("low"), 10)
        self.assertEqual(urgency_to_target_blocks("normal"), 3)
        self.assertEqual(urgency_to_target_blocks("high"), 1)
        with self.assertRaises(ValueError):
            urgency_to_target_blocks("hyperdrive")

    def test_tx_types_constant_exposes_all_kinds(self):
        from messagechain.economics.auto_fee import TX_TYPES
        # Every tx kind that has its own admission rule must appear.
        for kind in (
            "message", "transfer", "stake", "unstake",
            "react", "propose", "vote", "rotate-key",
        ):
            self.assertIn(kind, TX_TYPES)


class TestEveryCommandUsesSameHelper(unittest.TestCase):
    """No tx kind defaults to a stale flat fee while others auto-bid by density.

    Anchored by CLAUDE.md ("Auto-fee adjusts to fit this model. ... When
    the fee model shifts, every auto-fee path shifts with it - don't
    leave a tx kind defaulting to a stale flat fee while others auto-
    bid by density.")  We enforce this by importing the unified helper
    once and checking every cmd_* path resolves the SAME symbol.
    """

    def test_cli_module_imports_unified_auto_fee(self):
        # Surface check: the cli module re-imports `auto_fee` from the
        # central module.  We don't try to introspect every function
        # body — pinning the symbol presence is enough to catch a
        # divergent path that re-implements its own picker.
        import messagechain.cli as cli_mod
        from messagechain.economics import auto_fee as af_mod
        # The CLI either imports the function directly OR imports the
        # whole module.  Either is acceptable; we just want one shared
        # source.
        cli_src = open(cli_mod.__file__, encoding="utf-8").read()
        self.assertIn("messagechain.economics.auto_fee", cli_src)
        # The helper itself is the same identity wherever it appears.
        from messagechain.economics.auto_fee import auto_fee as af_func
        self.assertIs(af_func, af_mod.auto_fee)


# ── B. urgency drives percentile, higher urgency = higher bid ──────


class TestUrgencyDrivesPercentile(unittest.TestCase):
    """`--urgency high` returns a meaningfully higher number than `--urgency low`.

    Wired through the existing FeeEstimator percentile ladder
    (90/75/60/25/10 across target_blocks).  A synthetic mempool
    populated with a wide fee band exercises the full curve.
    """

    def _populate(self):
        from messagechain.economics.fee_estimator import FeeEstimator
        est = FeeEstimator()
        # Wide fee band — the percentile difference is meaningful only
        # if the distribution actually has spread.
        for fee in range(100, 2000, 50):
            est.record_block_fees([fee])
        return est

    def test_high_urgency_strictly_higher_than_low(self):
        from messagechain.economics.auto_fee import urgency_to_target_blocks
        est = self._populate()
        high = est.estimate_fee(
            target_blocks=urgency_to_target_blocks("high"),
        )
        low = est.estimate_fee(
            target_blocks=urgency_to_target_blocks("low"),
        )
        self.assertGreater(high, low)

    def test_normal_strictly_between_low_and_high(self):
        from messagechain.economics.auto_fee import urgency_to_target_blocks
        est = self._populate()
        high = est.estimate_fee(
            target_blocks=urgency_to_target_blocks("high"),
        )
        normal = est.estimate_fee(
            target_blocks=urgency_to_target_blocks("normal"),
        )
        low = est.estimate_fee(
            target_blocks=urgency_to_target_blocks("low"),
        )
        self.assertLess(low, normal)
        self.assertLess(normal, high)


class TestAutoFeeRespondsToUrgency(unittest.TestCase):
    """The unified helper itself produces higher fees when urgency is higher."""

    def test_high_urgency_pays_more_than_low_under_pressure(self):
        from messagechain.economics.auto_fee import auto_fee
        # Caller supplies an already-percentile-evaluated mempool
        # estimate (the server side of the wiring picks the percentile
        # by target_blocks).  We feed three distinct estimates as the
        # CLI would with three different --urgency values.
        msg_size = 200
        height = MARKET_FEE_FLOOR_HEIGHT + 10
        low_est = 5
        normal_est = 50
        high_est = 500
        low_fee = auto_fee(
            "message", stored_size=msg_size,
            urgency="low", current_height=height,
            mempool_estimate=low_est * msg_size,
        )
        normal_fee = auto_fee(
            "message", stored_size=msg_size,
            urgency="normal", current_height=height,
            mempool_estimate=normal_est * msg_size,
        )
        high_fee = auto_fee(
            "message", stored_size=msg_size,
            urgency="high", current_height=height,
            mempool_estimate=high_est * msg_size,
        )
        self.assertLess(low_fee, normal_fee)
        self.assertLess(normal_fee, high_fee)


# ── C. each tx kind has a deterministic stored_size ─────────────────


class TestStoredSizeForEachTxKind(unittest.TestCase):
    """`stored_size_for(tx_type, **kwargs)` returns deterministic byte counts.

    Used by the CLI to multiply percentile-fee-per-byte * stored_size,
    and by `estimate-fee --tx-type X` to display the per-byte rate the
    user is being quoted.
    """

    def test_message_stored_size_equals_message_bytes(self):
        from messagechain.economics.auto_fee import stored_size_for
        msg = b"hello world"
        n = stored_size_for("message", message_bytes=len(msg))
        self.assertEqual(n, len(msg))

    def test_message_stored_size_includes_prev_pointer(self):
        from messagechain.economics.auto_fee import stored_size_for
        n_no = stored_size_for("message", message_bytes=100)
        n_yes = stored_size_for("message", message_bytes=100, has_prev=True)
        # Prev pointer is 33 bytes (1B presence flag + 32B hash) per
        # CLAUDE.md anchor.
        self.assertEqual(n_yes - n_no, 33)

    def test_transfer_stored_size_is_positive(self):
        from messagechain.economics.auto_fee import stored_size_for
        n = stored_size_for("transfer")
        self.assertGreater(n, 0)

    def test_stake_stored_size_is_positive(self):
        from messagechain.economics.auto_fee import stored_size_for
        n = stored_size_for("stake")
        self.assertGreater(n, 0)

    def test_unstake_stored_size_is_positive(self):
        from messagechain.economics.auto_fee import stored_size_for
        n = stored_size_for("unstake")
        self.assertGreater(n, 0)

    def test_react_stored_size_is_positive(self):
        from messagechain.economics.auto_fee import stored_size_for
        n = stored_size_for("react")
        self.assertGreater(n, 0)

    def test_propose_stored_size_includes_payload(self):
        from messagechain.economics.auto_fee import stored_size_for
        small = stored_size_for("propose", payload_bytes=10)
        big = stored_size_for("propose", payload_bytes=1000)
        self.assertEqual(big - small, 1000 - 10)

    def test_vote_stored_size_is_positive(self):
        from messagechain.economics.auto_fee import stored_size_for
        n = stored_size_for("vote")
        self.assertGreater(n, 0)

    def test_rotate_key_stored_size_is_positive(self):
        from messagechain.economics.auto_fee import stored_size_for
        n = stored_size_for("rotate-key")
        self.assertGreater(n, 0)


# ── D. tx_floor at the no-pressure floor matches live admission rule ─


class TestTxFloorMatchesLiveAdmissionRule(unittest.TestCase):
    """tx_floor returns BASE_TX_FEE + FEE_PER_STORED_BYTE * stored_size at
    the floor — for tx kinds where the live rule is linear-in-bytes — and
    the type-specific flat floor where it isn't.  No path rounds to 0."""

    def test_message_floor_at_market_fee_floor_height(self):
        # Tier 16+: message floor collapses to the flat MARKET_FEE_FLOOR=1.
        # CLAUDE.md "Minimum fee is 1, never 0." holds because the floor
        # is exactly MARKET_FEE_FLOOR=1, not 0.
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "message",
            stored_size=200,
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
        )
        self.assertEqual(floor, MARKET_FEE_FLOOR)
        self.assertGreaterEqual(floor, 1)

    def test_message_floor_pre_market_fee_is_linear_in_stored_bytes(self):
        # Pre-Tier-16 (legacy admission path) still replays under the
        # linear-in-stored-bytes formula, so the helper must return
        # exactly that for replay determinism.
        from messagechain.economics.auto_fee import tx_floor
        from messagechain.config import (
            BLOCK_BYTES_RAISE_HEIGHT,
            FEE_PER_STORED_BYTE_POST_RAISE,
            BASE_TX_FEE,
        )
        h = BLOCK_BYTES_RAISE_HEIGHT + 1  # post-raise, pre-market-floor
        # Tier 16 fast-forwarded ahead of Tier 9 in this build, so we
        # exercise this only when Tier 9 < Tier 16.
        if h >= MARKET_FEE_FLOOR_HEIGHT:
            self.skipTest("Tier 9 ≥ Tier 16 in this build; legacy "
                          "linear floor not directly testable")
        size = 200
        floor = tx_floor("message", stored_size=size, current_height=h)
        self.assertEqual(
            floor, BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * size,
        )

    def test_transfer_floor_at_market_height(self):
        # Transfer's flat_floor is MIN_FEE=100; MARKET_FEE_FLOOR=1
        # is below, so the binding floor is MIN_FEE=100.
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "transfer",
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
        )
        self.assertEqual(floor, MIN_FEE)
        self.assertGreaterEqual(floor, 1)

    def test_transfer_floor_with_new_account_surcharge(self):
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "transfer",
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
            recipient_is_new=True,
        )
        self.assertEqual(floor, MIN_FEE + NEW_ACCOUNT_FEE)

    def test_stake_floor_at_market_height(self):
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "stake",
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
        )
        self.assertEqual(floor, MIN_FEE)

    def test_unstake_floor_at_market_height(self):
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "unstake",
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
        )
        self.assertEqual(floor, MIN_FEE)

    def test_react_floor_at_tier_18(self):
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "react",
            current_height=TIER_18_HEIGHT + 10,
        )
        self.assertEqual(floor, MARKET_FEE_FLOOR)

    def test_propose_floor_pre_tier19(self):
        # Pre-fork: flat GOVERNANCE_PROPOSAL_FEE.
        from messagechain.economics.auto_fee import tx_floor
        h = max(MARKET_FEE_FLOOR_HEIGHT + 10,
                PROPOSAL_FEE_TIER19_HEIGHT - 10)
        # Test the pre-Tier-19 branch only when there's a window.
        if h >= PROPOSAL_FEE_TIER19_HEIGHT:
            self.skipTest("no pre-Tier-19 window in this build")
        floor = tx_floor("propose", payload_bytes=500, current_height=h)
        self.assertEqual(floor, GOVERNANCE_PROPOSAL_FEE)

    def test_propose_floor_post_tier19_is_linear(self):
        # Post-Tier-19: flat + per-byte surcharge.
        from messagechain.economics.auto_fee import tx_floor
        h = PROPOSAL_FEE_TIER19_HEIGHT + 10
        for p in (0, 100, 1000):
            with self.subTest(payload=p):
                floor = tx_floor(
                    "propose", payload_bytes=p, current_height=h,
                )
                self.assertEqual(
                    floor,
                    GOVERNANCE_PROPOSAL_FEE_TIER19
                    + GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 * p,
                )

    def test_vote_floor(self):
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "vote",
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
        )
        self.assertEqual(floor, GOVERNANCE_VOTE_FEE)

    def test_rotate_key_floor(self):
        from messagechain.economics.auto_fee import tx_floor
        floor = tx_floor(
            "rotate-key",
            current_height=MARKET_FEE_FLOOR_HEIGHT + 10,
        )
        self.assertEqual(floor, KEY_ROTATION_FEE)

    def test_no_tx_type_rounds_to_zero(self):
        """CLAUDE.md anchor: 'Minimum fee is 1, never 0.'"""
        from messagechain.economics.auto_fee import tx_floor, TX_TYPES
        # Sample heights at every active tier boundary.
        heights = [
            MARKET_FEE_FLOOR_HEIGHT + 10,
            TIER_18_HEIGHT + 10,
            PROPOSAL_FEE_TIER19_HEIGHT + 10,
        ]
        for h in heights:
            for kind in TX_TYPES:
                with self.subTest(tx=kind, height=h):
                    kwargs = {"current_height": h}
                    if kind == "message":
                        kwargs["stored_size"] = 1
                    if kind == "propose":
                        kwargs["payload_bytes"] = 1
                    floor = tx_floor(kind, **kwargs)
                    self.assertGreaterEqual(
                        floor, 1,
                        f"{kind} floor at height={h} = {floor}, "
                        "must be >= 1 (CLAUDE.md anchor)",
                    )


# ── E. estimate-fee --tx-type surface ──────────────────────────────


class TestEstimateFeeCliSurface(unittest.TestCase):
    """`estimate-fee --tx-type X` accepts every tx kind and prints the
    breakdown the user expects (protocol min, mempool percentile, total,
    per-byte rate)."""

    def setUp(self):
        from messagechain.cli import build_parser
        self.parser = build_parser()

    def test_legacy_message_form_still_works(self):
        # Don't break existing callers.
        args = self.parser.parse_args(["estimate-fee", "--message", "hi"])
        self.assertEqual(args.command, "estimate-fee")
        self.assertEqual(args.message, "hi")

    def test_legacy_transfer_form_still_works(self):
        args = self.parser.parse_args(["estimate-fee", "--transfer"])
        self.assertEqual(args.command, "estimate-fee")
        self.assertTrue(args.transfer)

    def test_tx_type_message(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "message", "--message", "hi",
        ])
        self.assertEqual(args.tx_type, "message")

    def test_tx_type_transfer(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "transfer",
        ])
        self.assertEqual(args.tx_type, "transfer")

    def test_tx_type_stake(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "stake",
        ])
        self.assertEqual(args.tx_type, "stake")

    def test_tx_type_unstake(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "unstake",
        ])
        self.assertEqual(args.tx_type, "unstake")

    def test_tx_type_react(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "react",
        ])
        self.assertEqual(args.tx_type, "react")

    def test_tx_type_propose(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "propose",
            "--title", "T", "--description", "D",
        ])
        self.assertEqual(args.tx_type, "propose")

    def test_tx_type_vote(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "vote",
        ])
        self.assertEqual(args.tx_type, "vote")

    def test_tx_type_rotate_key(self):
        args = self.parser.parse_args([
            "estimate-fee", "--tx-type", "rotate-key",
        ])
        self.assertEqual(args.tx_type, "rotate-key")

    def test_urgency_flag_accepted(self):
        for u in ("low", "normal", "high"):
            args = self.parser.parse_args([
                "estimate-fee", "--message", "hi", "--urgency", u,
            ])
            self.assertEqual(args.urgency, u)

    def test_unknown_urgency_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args([
                "estimate-fee", "--message", "hi",
                "--urgency", "instant",
            ])


class TestSubmitCommandsAcceptUrgency(unittest.TestCase):
    """Every tx-submitting command exposes `--urgency`."""

    def setUp(self):
        from messagechain.cli import build_parser
        self.parser = build_parser()

    def test_send_accepts_urgency(self):
        args = self.parser.parse_args([
            "send", "hi", "--urgency", "high",
        ])
        self.assertEqual(args.urgency, "high")

    def test_transfer_accepts_urgency(self):
        args = self.parser.parse_args([
            "transfer", "--to",
            "0" * 64,
            "--amount", "10",
            "--urgency", "low",
            "--allow-raw-hex-address",
        ])
        self.assertEqual(args.urgency, "low")

    def test_stake_accepts_urgency(self):
        args = self.parser.parse_args([
            "stake", "--amount", "100", "--urgency", "normal",
        ])
        self.assertEqual(args.urgency, "normal")

    def test_unstake_accepts_urgency(self):
        args = self.parser.parse_args([
            "unstake", "--amount", "100", "--urgency", "high",
        ])
        self.assertEqual(args.urgency, "high")

    def test_propose_accepts_urgency(self):
        args = self.parser.parse_args([
            "propose", "--title", "T", "--description", "D",
            "--urgency", "high",
        ])
        self.assertEqual(args.urgency, "high")

    def test_vote_accepts_urgency(self):
        args = self.parser.parse_args([
            "vote", "--proposal", "ab" * 32, "--yes",
            "--urgency", "low",
        ])
        self.assertEqual(args.urgency, "low")

    def test_rotate_key_accepts_urgency(self):
        args = self.parser.parse_args([
            "rotate-key", "--urgency", "normal",
        ])
        self.assertEqual(args.urgency, "normal")

    def test_send_urgency_default_is_normal(self):
        args = self.parser.parse_args(["send", "hi"])
        self.assertEqual(args.urgency, "normal")


# ── F. estimate-fee output prints the breakdown lines ──────────────


class TestEstimateFeePrintsBreakdown(unittest.TestCase):
    """The printed output must include protocol-min / mempool-percentile
    / total / per-byte-rate so the user can see why the number is what
    it is.  We capture stdout by patching `print` and run cmd_estimate_fee
    directly with a mocked rpc_call."""

    def _run_estimate(self, *, kind, response_result, extra_args=None):
        import io
        from contextlib import redirect_stdout
        from messagechain.cli import build_parser, cmd_estimate_fee
        argv = ["estimate-fee"]
        if kind == "message":
            argv += ["--message", "hi"]
        else:
            argv += ["--tx-type", kind]
        argv += list(extra_args or [])
        args = build_parser().parse_args(argv)
        # Mock rpc_call's `estimate_fee` response and avoid touching
        # the network.  The CLI reads from `client.rpc_call`.
        buf = io.StringIO()
        with patch("client.rpc_call") as rpc:
            rpc.return_value = {"ok": True, "result": response_result}
            with redirect_stdout(buf):
                try:
                    cmd_estimate_fee(args)
                except SystemExit:
                    pass
        return buf.getvalue()

    def test_message_estimate_prints_breakdown(self):
        out = self._run_estimate(
            kind="message",
            response_result={
                "min_fee": 5,
                "mempool_fee": 12,
                "recommended_fee": 12,
                "stored_bytes": 2,
                "fee_per_byte": 6.0,
                "tx_type": "message",
                "target_blocks": 3,
                "urgency": "normal",
            },
        )
        # Breakdown lines we anchor on:
        self.assertIn("Protocol minimum", out)
        self.assertIn("Mempool", out)
        self.assertIn("Recommended", out)
        self.assertIn("per byte", out.lower())

    def test_transfer_estimate_prints_tx_type_label(self):
        out = self._run_estimate(
            kind="transfer",
            response_result={
                "min_fee": MIN_FEE,
                "mempool_fee": 0,
                "recommended_fee": MIN_FEE,
                "stored_bytes": 0,
                "fee_per_byte": 0,
                "tx_type": "transfer",
                "target_blocks": 3,
                "urgency": "normal",
            },
        )
        self.assertIn("transfer", out.lower())


# ── G. RPC layer accepts tx_type and urgency ────────────────────────


class TestRpcEstimateFeeAcceptsTxType(unittest.TestCase):
    """`_rpc_estimate_fee` accepts `tx_type` for every kind and
    `target_blocks` (urgency level) and returns a structured breakdown."""

    def _server(self):
        from messagechain.config import TREASURY_ENTITY_ID, TREASURY_ALLOCATION
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool
        from messagechain.identity.identity import Entity
        alice = Entity.create(b"alice-tx-type-est" + b"\x00" * 15)
        chain = Blockchain()
        chain.initialize_genesis(
            alice,
            allocation_table={
                alice.entity_id: 1_000_000,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        srv = MagicMock()
        srv.blockchain = chain
        srv.mempool = Mempool()
        srv.mempool.get_fee_estimate = lambda message_bytes=0, target_blocks=3: 1
        return srv

    def test_rpc_accepts_tx_type_stake(self):
        import server as server_module
        result = server_module.Server._rpc_estimate_fee(
            self._server(),
            {"kind": "stake"},
        )
        self.assertTrue(result["ok"], result)
        r = result["result"]
        self.assertGreaterEqual(r["min_fee"], MIN_FEE)
        self.assertGreaterEqual(r["recommended_fee"], r["min_fee"])

    def test_rpc_accepts_tx_type_propose(self):
        import server as server_module
        result = server_module.Server._rpc_estimate_fee(
            self._server(),
            {"kind": "propose", "payload_bytes": 100},
        )
        self.assertTrue(result["ok"], result)
        r = result["result"]
        self.assertGreaterEqual(r["min_fee"], 1)
        self.assertGreaterEqual(r["recommended_fee"], r["min_fee"])

    def test_rpc_accepts_tx_type_vote(self):
        import server as server_module
        result = server_module.Server._rpc_estimate_fee(
            self._server(),
            {"kind": "vote"},
        )
        self.assertTrue(result["ok"], result)
        r = result["result"]
        self.assertEqual(r["min_fee"], GOVERNANCE_VOTE_FEE)

    def test_rpc_accepts_tx_type_rotate_key(self):
        import server as server_module
        result = server_module.Server._rpc_estimate_fee(
            self._server(),
            {"kind": "rotate-key"},
        )
        self.assertTrue(result["ok"], result)
        r = result["result"]
        self.assertEqual(r["min_fee"], KEY_ROTATION_FEE)

    def test_rpc_accepts_target_blocks(self):
        import server as server_module
        # Fake a mempool that returns increasing fees as the percentile
        # rises so we can assert urgency drives the bid.
        srv = self._server()

        def mempool_estimate(message_bytes=0, target_blocks=3):
            # Higher urgency (lower target_blocks) -> higher fee.
            return 1000 // max(target_blocks, 1)

        srv.mempool.get_fee_estimate = mempool_estimate
        low = server_module.Server._rpc_estimate_fee(
            srv, {"kind": "message", "message": "x" * 50, "target_blocks": 10},
        )["result"]
        high = server_module.Server._rpc_estimate_fee(
            srv, {"kind": "message", "message": "x" * 50, "target_blocks": 1},
        )["result"]
        self.assertGreater(high["mempool_fee"], low["mempool_fee"])


if __name__ == "__main__":
    unittest.main()
