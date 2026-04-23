"""Tests for the systemd unit file shape.

The unit is a config artifact, not Python — but the failure mode it
guards against is real and dangerous: if a mainnet operator copies the
unit file thinking it's production-safe and it actually ships prototype
defaults (RPC auth off, fast blocks, small Merkle tree, checkpoints
waived), the validator runs in a security-degraded mode without anyone
noticing. So we pin the contract here.
"""

import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
# PROD_UNIT points at the PUBLIC shipped template, not the operator-
# local `deploy/systemd/...` copy.  The public template is the one a
# new operator will copy into their own /etc/systemd/system/ path;
# any regression that weakens its hardening contract (strips
# MemoryDenyWriteExecute, bakes in MESSAGECHAIN_PROFILE=prototype,
# etc.) must fail CI on every PR, not only on the operator's local
# machine where `deploy/` happens to exist.  Gating this contract
# behind _DEPLOY_PRESENT previously skipped the regression gate on
# every public CI run — exactly the silent drift the tests were
# written to catch.
PROD_UNIT = REPO_ROOT / "examples" / "messagechain-validator.service.example"
PROTOTYPE_DROPIN = (
    REPO_ROOT / "deploy" / "systemd" / "messagechain-validator-prototype.conf.example"
)

# deploy/ is gitignored per CLAUDE.md (operator/founder-local content).
# Only the prototype drop-in test uses this skip — the prototype
# drop-in is operator-specific config that doesn't belong in the
# public examples/ tree.  The prod-unit hardening contract ran above
# is always active on CI.
_DEPLOY_PRESENT = (REPO_ROOT / "deploy").is_dir()


class TestProductionUnitIsSafe(unittest.TestCase):
    """The default unit file must be production-safe out of the box."""

    @classmethod
    def setUpClass(cls):
        cls.text = PROD_UNIT.read_text(encoding="utf-8")

    def test_unit_file_exists(self):
        self.assertTrue(PROD_UNIT.is_file(), f"missing: {PROD_UNIT}")

    def test_no_prototype_profile_in_prod_unit(self):
        """Prod unit must not bake in MESSAGECHAIN_PROFILE=prototype.

        Prototype profile flips RPC_AUTH_ENABLED=false, BLOCK_TIME_TARGET=30,
        MERKLE_TREE_HEIGHT=16, REQUIRE_CHECKPOINTS=false — the full
        bootstrap-phase posture. Shipping this in the prod-default unit
        means a copy-paste install runs in a degraded security mode and
        burns through WOTS+ leaves ~4× faster than intended.
        """
        for line in self.text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            self.assertNotIn(
                "MESSAGECHAIN_PROFILE=prototype",
                stripped,
                "prod unit must not set MESSAGECHAIN_PROFILE=prototype "
                "in an active line; move that to a drop-in override",
            )

    def test_no_individual_dev_overrides(self):
        """Prod unit must not bake in individual dev/testnet env overrides.

        These are exactly the values that the prototype profile bundles —
        any active line setting them in the prod unit reproduces the same
        footgun the profile mechanism was supposed to fix.
        """
        forbidden = (
            "MESSAGECHAIN_RPC_AUTH_ENABLED=false",
            "MESSAGECHAIN_REQUIRE_CHECKPOINTS=false",
            "MESSAGECHAIN_BLOCK_TIME_TARGET=30",
            "MESSAGECHAIN_MERKLE_TREE_HEIGHT=16",
        )
        for line in self.text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for needle in forbidden:
                self.assertNotIn(
                    needle,
                    stripped,
                    f"prod unit must not contain dev override {needle!r}",
                )

    def test_has_crash_loop_guard(self):
        """Prod unit must rate-limit restarts so a block-level DoS bug
        cannot loop the validator forever, burning CPU and log volume."""
        self.assertIn(
            "StartLimitBurst",
            self.text,
            "prod unit needs StartLimitBurst (and StartLimitIntervalSec) "
            "so on-failure restarts cap out and the operator gets paged",
        )
        self.assertIn("StartLimitIntervalSec", self.text)


@unittest.skipUnless(_DEPLOY_PRESENT, "deploy/ gitignored; operator-only test")
class TestPrototypeDropinExists(unittest.TestCase):
    """The prototype-phase drop-in is shipped as a separate, opt-in file."""

    def test_dropin_file_exists(self):
        self.assertTrue(
            PROTOTYPE_DROPIN.is_file(),
            f"missing prototype drop-in: {PROTOTYPE_DROPIN} — operators on "
            "prototype-phase chains need a one-line copy-paste to flip the "
            "profile, not a doc-walked sequence of env vars",
        )

    def test_dropin_sets_prototype_profile(self):
        text = PROTOTYPE_DROPIN.read_text(encoding="utf-8")
        self.assertIn("MESSAGECHAIN_PROFILE=prototype", text)
        # And under a [Service] section so systemd's drop-in mechanism
        # actually applies it.
        self.assertIn("[Service]", text)


if __name__ == "__main__":
    unittest.main()
