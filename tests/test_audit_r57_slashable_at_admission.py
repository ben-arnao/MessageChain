"""Audit r57 #2: censorship-evidence admission basis widens to
``staked + pending_unstakes`` (Tier 79 / `SLASHABLE_BASIS_AT_ADMISSION_HEIGHT`).

CLAUDE.md anchors defended: "Collective censorship-resistance" and
"Honest operators are insured" -- the slash must bind the offender's
full slashable wealth at admission, not just the `staked` bucket.

Pre-r57 ``_apply_censorship_evidence_txs`` captured
``staked_at_admission = supply.staked.get(offender_id, 0)`` --
``pending_unstakes`` excluded.  ``burn_slash_proportional(
admission_basis=staked_at_admission)`` then capped the matured slash
at that frozen staked-only number, even though the helper is willing
to drain ``pending_unstakes`` too.  An accused validator who watched
the CensorshipEvidenceTx land in the mempool could pre-emptively
unstake (shifting balance from ``staked`` -> ``pending_unstakes``)
before the evidence cleared admission and shrink the slash cap by the
pending portion -- defeating Tier 31's "censor-then-unstake evasion"
anchor on the basis-capture side.

Tier 79 routes admission-basis capture through one chokepoint
(``Blockchain._capture_slashable_basis``) that returns:
  * pre-fork: ``supply.staked.get(offender)``                    (legacy,
    byte-identical to historical replay)
  * post-fork: ``supply.staked.get(offender) + supply.get_pending_unstake(offender)``
    -- the offender's full slashable wealth at admission time.

These tests pin:

  1. The chokepoint helper exists on Blockchain.
  2. Pre-fork the helper returns staked-only (legacy replay safety).
  3. Post-fork the helper widens to staked + pending.
  4. ``_PendingEvidence.staked_at_admission`` field name + serialization
     contract is preserved (no rename needed -- semantics widen behind
     the helper, the field is the *captured-at-admission* slashable
     basis regardless of legacy name).
  5. Structural pin: every censorship-evidence admission call site
     routes through the helper, not a bare ``supply.staked.get(...)``.
"""

import inspect
import unittest

from messagechain.config import SLASHABLE_BASIS_AT_ADMISSION_HEIGHT
from messagechain.consensus.censorship_evidence import _PendingEvidence


class TestCaptureSlashableBasisExists(unittest.TestCase):
    """The chokepoint helper must exist on Blockchain."""

    def test_chokepoint_method_exists(self):
        from messagechain.core.blockchain import Blockchain
        self.assertTrue(
            hasattr(Blockchain, "_capture_slashable_basis"),
            "Tier 79 chokepoint Blockchain._capture_slashable_basis "
            "must exist -- it's the single source of truth for "
            "admission-basis snapshots and the abstraction-over-symptom "
            "fix for audit r57 #2.",
        )

    def test_chokepoint_signature(self):
        from messagechain.core.blockchain import Blockchain
        sig = inspect.signature(Blockchain._capture_slashable_basis)
        # offender_id positional + height kw-only (the Tier 79 height
        # gate read).
        self.assertIn("offender_id", sig.parameters)
        self.assertIn("height", sig.parameters)


class TestCaptureSlashableBasisPrefork(unittest.TestCase):
    """Pre-fork heights MUST return staked-only.

    Replay determinism: every block admitted before Tier 79 activates
    must produce the legacy ``staked_at_admission`` value or historical
    replay diverges.
    """

    def _make_supply_like(self, staked=1000, pending=400):
        from unittest.mock import MagicMock
        supply = MagicMock()
        supply.staked = {b"\xaa" * 32: staked}
        supply.get_pending_unstake = MagicMock(return_value=pending)
        return supply

    def test_prefork_returns_staked_only(self):
        from messagechain.core.blockchain import Blockchain
        bc = object.__new__(Blockchain)
        bc.supply = self._make_supply_like(staked=1000, pending=400)
        # height STRICTLY below activation -> legacy staked-only.
        basis = bc._capture_slashable_basis(
            b"\xaa" * 32,
            height=SLASHABLE_BASIS_AT_ADMISSION_HEIGHT - 1,
        )
        self.assertEqual(basis, 1000)

    def test_prefork_unknown_offender_returns_zero(self):
        from messagechain.core.blockchain import Blockchain
        bc = object.__new__(Blockchain)
        bc.supply = self._make_supply_like(staked=1000, pending=400)
        basis = bc._capture_slashable_basis(
            b"\xbb" * 32,  # not in staked map
            height=SLASHABLE_BASIS_AT_ADMISSION_HEIGHT - 1,
        )
        self.assertEqual(basis, 0)


class TestCaptureSlashableBasisPostfork(unittest.TestCase):
    """Post-fork heights MUST return staked + pending_unstakes."""

    def _make_supply_like(self, staked=1000, pending=400):
        from unittest.mock import MagicMock
        supply = MagicMock()
        supply.staked = {b"\xaa" * 32: staked}
        supply.get_pending_unstake = MagicMock(return_value=pending)
        return supply

    def test_postfork_widens_basis(self):
        from messagechain.core.blockchain import Blockchain
        bc = object.__new__(Blockchain)
        bc.supply = self._make_supply_like(staked=1000, pending=400)
        basis = bc._capture_slashable_basis(
            b"\xaa" * 32,
            height=SLASHABLE_BASIS_AT_ADMISSION_HEIGHT,
        )
        # staked + pending = 1400 (vs legacy 1000).  The 400-token
        # pending portion is the censor-then-unstake evasion that
        # Tier 79 closes.
        self.assertEqual(basis, 1400)

    def test_postfork_no_pending_matches_legacy(self):
        from messagechain.core.blockchain import Blockchain
        bc = object.__new__(Blockchain)
        bc.supply = self._make_supply_like(staked=1000, pending=0)
        basis = bc._capture_slashable_basis(
            b"\xaa" * 32,
            height=SLASHABLE_BASIS_AT_ADMISSION_HEIGHT + 100,
        )
        # When the offender has nothing in pending, the wider basis
        # collapses to the legacy value -- no behavioural drift on the
        # common case.
        self.assertEqual(basis, 1000)

    def test_postfork_unknown_offender_returns_zero(self):
        from messagechain.core.blockchain import Blockchain
        bc = object.__new__(Blockchain)
        bc.supply = self._make_supply_like(staked=1000, pending=400)
        # Unknown offender: staked=0, but ``get_pending_unstake`` could
        # still return 400 on the mock.  The helper must short-circuit
        # to 0 when the offender has no staked balance (mirroring
        # ``burn_slash_proportional``'s ``basis == 0`` short-circuit
        # at inflation.py:2253) so an entirely-unstaked offender's
        # admission basis is 0, not just-the-pending.  Actually --
        # the helper is the *snapshot*; the apply-side path already
        # short-circuits at basis=0.  We just need basis = staked +
        # pending here.  ``staked`` for an unknown id is 0; the mock
        # returns 400 for ``get_pending_unstake`` regardless of id.
        # So basis = 0 + 400 = 400.  This is the expected shape:
        # an offender who has fully unstaked but whose tokens are
        # still in pending should be slashable for the pending
        # portion -- exactly the case Tier 79 widens to cover.
        basis = bc._capture_slashable_basis(
            b"\xbb" * 32,
            height=SLASHABLE_BASIS_AT_ADMISSION_HEIGHT,
        )
        self.assertEqual(basis, 400)


class TestPendingEvidenceSerializationStable(unittest.TestCase):
    """Tier 79 must NOT rename the persisted field -- the snapshot key
    ``staked_at_admission`` is contracted with state-snapshot V*. The
    *semantics* widen behind the helper; the field name and serialize/
    deserialize shape stay byte-identical.
    """

    def test_serialize_round_trip(self):
        pe = _PendingEvidence(
            evidence_hash=b"\x11" * 32,
            offender_id=b"\x22" * 32,
            tx_hash=b"\x33" * 32,
            admitted_height=1234,
            evidence_tx_hash=b"\x44" * 32,
            staked_at_admission=5500,  # post-Tier-79 this would be staked+pending
        )
        data = pe.serialize()
        round = _PendingEvidence.deserialize(data)
        self.assertEqual(round.staked_at_admission, 5500)
        self.assertEqual(round.offender_id, b"\x22" * 32)

    def test_forward_compat_missing_field(self):
        # Snapshot written by very-old code (pre-staked_at_admission
        # field) must round-trip with default 0 -- no crash on cold
        # load.  Unchanged from pre-r57; pinned here to prevent a
        # future schema-rename from accidentally breaking it.
        data = {
            "evidence_hash": ("\x11" * 32).encode().hex(),
            "offender_id": ("\x22" * 32).encode().hex(),
            "tx_hash": ("\x33" * 32).encode().hex(),
            "admitted_height": 100,
            "evidence_tx_hash": ("\x44" * 32).encode().hex(),
            # staked_at_admission MISSING
        }
        # Hex-encoding mismatch -- use proper hex.
        data = {
            "evidence_hash": (b"\x11" * 32).hex(),
            "offender_id": (b"\x22" * 32).hex(),
            "tx_hash": (b"\x33" * 32).hex(),
            "admitted_height": 100,
            "evidence_tx_hash": (b"\x44" * 32).hex(),
        }
        pe = _PendingEvidence.deserialize(data)
        self.assertEqual(pe.staked_at_admission, 0)


class TestApplyPathRoutesThroughHelper(unittest.TestCase):
    """Structural pin: ``_apply_censorship_evidence_txs`` must call the
    chokepoint, not ``self.supply.staked.get(offender)`` bare.

    If a future refactor accidentally reverts to a bare ``.staked.get``
    read at the admission site, the helper's height gate is bypassed
    and pre-emptive-unstake evasion silently returns.
    """

    def test_admission_site_uses_chokepoint(self):
        # Read the source of the apply path; the only acceptable shape
        # post-r57 is ``self._capture_slashable_basis(...)``.  A bare
        # ``self.supply.staked.get(etx.offender_id, 0)`` for the
        # admission-basis capture is the regression we're pinning
        # against.
        import inspect

        from messagechain.core import blockchain as bc_module

        src = inspect.getsource(bc_module)
        # The chokepoint must appear (positive pin).
        self.assertIn(
            "_capture_slashable_basis",
            src,
            "_apply_censorship_evidence_txs must route through the "
            "Tier 79 chokepoint.",
        )
        # The exact pre-r57 bare read used for admission-basis capture
        # must NOT appear in the censorship-evidence admission site.
        # (Other call sites of ``self.supply.staked.get`` -- e.g. fee
        # apportionment, IL slashing -- are unrelated and may persist.)
        # Pin the specific construct:
        #     staked_now = self.supply.staked.get(etx.offender_id, 0)
        bare = "staked_now = self.supply.staked.get(etx.offender_id"
        self.assertNotIn(
            bare,
            src,
            "Censorship-evidence admission must not bare-read "
            "supply.staked at the basis-capture site -- route through "
            "_capture_slashable_basis instead.",
        )


if __name__ == "__main__":
    unittest.main()
