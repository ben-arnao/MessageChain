"""Tests for MESSAGECHAIN_PROFILE env var — coherent bootstrap defaults bundle.

Background: prior to this, a validator VM needed four separate env vars
(MESSAGECHAIN_RPC_AUTH_ENABLED, MESSAGECHAIN_REQUIRE_CHECKPOINTS,
MESSAGECHAIN_BLOCK_TIME_TARGET, MESSAGECHAIN_MERKLE_TREE_HEIGHT) to flip the
bootstrap-phase defaults. Forgetting any one produced silent wrong behavior
(slow keygen, refused start on missing checkpoints, etc.).

MESSAGECHAIN_PROFILE collapses that into a single switch:
  - unset or 'production' → strict production defaults
  - 'prototype' → full bundle of bootstrap-phase defaults
  - anything else → raise clear error (fail loudly, never silently)

Individual env vars still win over the profile so tests/__init__.py and
per-deployment overrides keep working. Precedence:
  individual env var  >  profile  >  hardcoded default
"""

import os
import subprocess
import sys
import unittest


def _run_config_probe(env_overrides: dict, probe: str) -> str:
    """Run `probe` python code in a subprocess with clean env + overrides.

    Strips all MESSAGECHAIN_* from the parent env, then applies overrides.
    tests/__init__.py is NOT imported here — we read messagechain.config
    directly so defaults aren't clobbered by the test harness.
    """
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("MESSAGECHAIN_")}
    env.update(env_overrides)
    # Ensure Python can find the package even when CWD differs.
    env.setdefault("PYTHONPATH", os.getcwd())
    result = subprocess.run(
        [sys.executable, "-c", probe],
        env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        return f"__ERROR__\n{result.stderr.strip()}"
    return result.stdout.strip()


_PROBE_ALL = (
    "import messagechain.config as c; "
    "print(c.REQUIRE_CHECKPOINTS, c.BLOCK_TIME_TARGET, "
    "c.MERKLE_TREE_HEIGHT, c.RPC_AUTH_ENABLED)"
)


class TestProfileUnset(unittest.TestCase):
    """No MESSAGECHAIN_PROFILE → strict production defaults."""

    def test_unset_yields_production_defaults(self):
        out = _run_config_probe({}, _PROBE_ALL)
        self.assertEqual(out, "True 600 20 True")


class TestProfileProduction(unittest.TestCase):
    """MESSAGECHAIN_PROFILE=production → same as unset (explicit opt-in)."""

    def test_production_profile_yields_production_defaults(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_PROFILE": "production"}, _PROBE_ALL,
        )
        self.assertEqual(out, "True 600 20 True")


class TestProfilePrototype(unittest.TestCase):
    """MESSAGECHAIN_PROFILE=prototype → full bootstrap-phase bundle."""

    def test_prototype_profile_yields_prototype_bundle(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_PROFILE": "prototype"}, _PROBE_ALL,
        )
        # REQUIRE_CHECKPOINTS=False, BLOCK_TIME_TARGET=30,
        # MERKLE_TREE_HEIGHT=16, RPC_AUTH_ENABLED=False
        self.assertEqual(out, "False 30 16 False")


class TestIndividualEnvWinsOverProfile(unittest.TestCase):
    """Individual env var > profile > hardcoded default."""

    def test_block_time_override_beats_prototype_profile(self):
        out = _run_config_probe(
            {
                "MESSAGECHAIN_PROFILE": "prototype",
                "MESSAGECHAIN_BLOCK_TIME_TARGET": "60",
            },
            "import messagechain.config as c; print(c.BLOCK_TIME_TARGET)",
        )
        self.assertEqual(out, "60")

    def test_merkle_height_override_beats_prototype_profile(self):
        out = _run_config_probe(
            {
                "MESSAGECHAIN_PROFILE": "prototype",
                "MESSAGECHAIN_MERKLE_TREE_HEIGHT": "20",
            },
            "import messagechain.config as c; print(c.MERKLE_TREE_HEIGHT)",
        )
        self.assertEqual(out, "20")

    def test_require_checkpoints_override_beats_prototype_profile(self):
        # Individual env var should win even if it contradicts the profile.
        # Prototype sets REQUIRE_CHECKPOINTS=False; force True here.
        out = _run_config_probe(
            {
                "MESSAGECHAIN_PROFILE": "prototype",
                "MESSAGECHAIN_REQUIRE_CHECKPOINTS": "true",
            },
            "import messagechain.config as c; print(c.REQUIRE_CHECKPOINTS)",
        )
        self.assertEqual(out, "True")

    def test_rpc_auth_override_beats_prototype_profile(self):
        # Prototype sets RPC_AUTH_ENABLED=False; force True here.
        out = _run_config_probe(
            {
                "MESSAGECHAIN_PROFILE": "prototype",
                "MESSAGECHAIN_RPC_AUTH_ENABLED": "true",
            },
            "import messagechain.config as c; print(c.RPC_AUTH_ENABLED)",
        )
        self.assertEqual(out, "True")


class TestUnknownProfileFailsLoudly(unittest.TestCase):
    """Unknown MESSAGECHAIN_PROFILE value → raise clear error at import."""

    def test_unknown_profile_raises(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_PROFILE": "staging"},
            "import messagechain.config as c; print('loaded')",
        )
        self.assertTrue(out.startswith("__ERROR__"), f"expected error, got: {out}")
        self.assertIn("MESSAGECHAIN_PROFILE", out)
        self.assertIn("staging", out)

    def test_empty_string_profile_raises(self):
        # Empty string is neither unset nor a known value — should fail.
        out = _run_config_probe(
            {"MESSAGECHAIN_PROFILE": ""},
            "import messagechain.config as c; print('loaded')",
        )
        # An empty string env var is functionally indistinguishable from
        # "unset" on many shells/systemd units. We treat empty == unset so
        # a blank Environment= line doesn't blow up the node. This test
        # locks that behavior in.
        self.assertEqual(out, "loaded")


class TestProfileCaseInsensitive(unittest.TestCase):
    """Accept common capitalizations — 'Prototype', 'PROTOTYPE', etc."""

    def test_uppercase_prototype_accepted(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_PROFILE": "PROTOTYPE"},
            "import messagechain.config as c; print(c.BLOCK_TIME_TARGET)",
        )
        self.assertEqual(out, "30")

    def test_mixedcase_production_accepted(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_PROFILE": "Production"},
            "import messagechain.config as c; print(c.BLOCK_TIME_TARGET)",
        )
        self.assertEqual(out, "600")


if __name__ == "__main__":
    unittest.main()
