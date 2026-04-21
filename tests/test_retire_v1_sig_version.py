"""V1 signature acceptance is retired on the post-reset mainnet.

The re-mint at 2026-04-21 (block-0 hash bb010943...) produced a
fresh chain with SIG_VERSION_CURRENT = V2 on every block.  No V1
signatures exist in the chain's history.

V1's WOTS+ checksum was shown to effectively collapse to zero
(iter-51 finding, commit cd4263a): a forgery under the founder's
tree root takes ~2^56 grinding (~8 days on a 100-GPU farm), well
below the nominal 2^128 security.  Leaving V1 in
`_ACCEPTED_SIG_VERSIONS` on the re-minted chain is a pure forgery
gate with no offsetting benefit (nothing legitimate would ever
produce a V1 signature).

This test pins V1 out of the accept set so a future careless
widening doesn't silently re-open the gate.
"""

import unittest

import messagechain.config as cfg


class TestV1SigRetired(unittest.TestCase):

    def test_accepted_set_does_not_include_v1(self):
        self.assertNotIn(
            cfg.SIG_VERSION_WOTS_W16_K64,
            cfg._ACCEPTED_SIG_VERSIONS,
            "V1 must NOT be in _ACCEPTED_SIG_VERSIONS on the post-reset "
            "mainnet — V1's checksum is ~2^56-forgeable and no legitimate "
            "V1 signatures exist in the new chain's history.",
        )

    def test_accepted_set_still_contains_current(self):
        # Sanity: the current sig version still validates.
        self.assertIn(
            cfg.SIG_VERSION_CURRENT,
            cfg._ACCEPTED_SIG_VERSIONS,
        )

    def test_v1_constant_is_still_defined(self):
        # The constant is kept (for historical reference + the ability to
        # reject V1 messages with a clear "known-retired version" error
        # rather than an opaque "unknown version" one).  Just its
        # membership in the ACCEPT set is revoked.
        self.assertTrue(hasattr(cfg, "SIG_VERSION_WOTS_W16_K64"))
        self.assertEqual(cfg.SIG_VERSION_WOTS_W16_K64, 1)

    def test_validate_sig_version_rejects_v1(self):
        ok, reason = cfg.validate_sig_version(cfg.SIG_VERSION_WOTS_W16_K64)
        self.assertFalse(
            ok, "validate_sig_version must reject V1 after the retire",
        )
        self.assertIn("1", reason)  # mentions the rejected version

    def test_validate_sig_version_accepts_v2(self):
        ok, _ = cfg.validate_sig_version(cfg.SIG_VERSION_WOTS_W16_K64_V2)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
