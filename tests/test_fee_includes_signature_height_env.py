"""Tests for MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT env-var override.

FEE_INCLUDES_SIGNATURE_HEIGHT is the coordinated-fork activation height
for charging fees on (message + signature) bytes. Before this fix it was
a hardcoded placeholder (``50_000``) in config.py with an explicit
"operators MUST replace before mainnet" docstring and no env-var path —
every operator had to edit config.py to pin the real fork height,
risking silent consensus divergence at activation if one operator's edit
was skipped or stale.

Now operators can set ``MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT`` in
systemd / k8s without a source edit. Same pattern as
``MESSAGECHAIN_BLOCK_TIME_TARGET`` / ``MESSAGECHAIN_MERKLE_TREE_HEIGHT``
(via the shared ``_profile_int`` helper).

Precedence: env var > profile (N/A for this key) > hardcoded default.
"""

import os
import subprocess
import sys
import unittest


def _run_config_probe(env_overrides: dict, probe: str) -> str:
    """Run ``probe`` in a clean subprocess with MESSAGECHAIN_* overrides.

    Strips all MESSAGECHAIN_* from the parent env before applying the
    overrides so ``tests/__init__.py`` doesn't clobber the default path
    for Test B.
    """
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("MESSAGECHAIN_")}
    env.update(env_overrides)
    env.setdefault("PYTHONPATH", os.getcwd())
    result = subprocess.run(
        [sys.executable, "-c", probe],
        env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        return f"__ERROR__\n{result.stderr.strip()}"
    return result.stdout.strip()


_PROBE = (
    "import messagechain.config as c; "
    "print(c.FEE_INCLUDES_SIGNATURE_HEIGHT)"
)


class TestFeeIncludesSigHeightEnvSet(unittest.TestCase):
    """Test A: env-var set to an int → config picks it up."""

    def test_env_var_override_applied(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT": "75000"},
            _PROBE,
        )
        # Must be < FLAT_FEE_HEIGHT (98000) per config.py's invariant
        # assertion that the signature-gate precedes the flat-fee fork.
        self.assertEqual(out, "75000")


class TestFeeIncludesSigHeightDefault(unittest.TestCase):
    """Test B: env-var unset → hardcoded canonical default (64_000, Tier 2)."""

    def test_default_when_unset(self):
        out = _run_config_probe({}, _PROBE)
        self.assertEqual(out, "64000")


class TestFeeIncludesSigHeightInvalidInt(unittest.TestCase):
    """Test C: env-var set to a non-int → fails loudly at import.

    ``_profile_int`` calls ``int(raw)`` directly on the env-var value
    with no fallback, so a non-int value raises ``ValueError`` at
    module import time. That's the right behavior — silent fallback to
    a placeholder default on a malformed coordinated-fork height would
    be a silent-divergence footgun. This test locks that in.
    """

    def test_non_int_env_var_raises_at_import(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_FEE_INCLUDES_SIGNATURE_HEIGHT": "abc"},
            _PROBE,
        )
        self.assertTrue(
            out.startswith("__ERROR__"),
            f"expected import-time error, got: {out}",
        )
        # Surface the concrete failure so operators can debug quickly.
        self.assertIn("ValueError", out)
        self.assertIn("abc", out)


if __name__ == "__main__":
    unittest.main()
