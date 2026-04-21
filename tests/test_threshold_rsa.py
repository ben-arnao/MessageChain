"""
Tests for Phase 1 threshold-RSA primitive (Shoup'00 adapted for encryption).

KEY-SIZE NOTE: These tests use a 512-bit modulus FOR SPEED ONLY. Production
deployment uses ``key_size_bits=3072`` (the default in ``ThresholdKeyDealer.
generate``). 512-bit RSA is meaningfully weak for confidentiality but the
threshold/Lagrange/NIZK math is identical at any modulus size — these tests
exercise the math, not real-world security margins. Do NOT lift this size
into any production code path.

If safe-prime keygen at 512 bits proves too slow on CI, drop the SHARED_KEY
fixture to 256 bits — meaninglessly weak even for tests but mathematically
sufficient to exercise share/combine/verify.

Cached module-level fixtures avoid paying the safe-prime keygen cost more
than once per (t, n) pair the suite touches.
"""

import unittest

from messagechain.crypto import threshold_rsa as tr
from messagechain.crypto.threshold_rsa import (
    Ciphertext,
    DecryptionShare,
    KeyShare,
    NIZKProof,
    PublicKey,
    THRESHOLD_RSA_VERSION_CURRENT,
    ThresholdKeyDealer,
    combine_shares,
    decrypt_share,
    encrypt,
    verify_share,
)


# ---------------------------------------------------------------------------
# Module-level cached fixtures — keygen with safe primes is the expensive
# part of these tests, so we cache one keypair per (t, n) configuration.
# ---------------------------------------------------------------------------

_TEST_KEY_BITS = 512  # see module docstring re: speed-vs-security trade-off

_CACHE: dict[tuple[int, int], tuple[PublicKey, list[KeyShare]]] = {}


def _key(t: int, n: int) -> tuple[PublicKey, list[KeyShare]]:
    if (t, n) not in _CACHE:
        _CACHE[(t, n)] = ThresholdKeyDealer.generate(
            t=t, n=n, key_size_bits=_TEST_KEY_BITS
        )
    return _CACHE[(t, n)]


# ---------------------------------------------------------------------------
# 1. Round-trip happy path  (t, n) = (3, 5)
# ---------------------------------------------------------------------------
class TestRoundTrip(unittest.TestCase):
    def test_happy_path_3_of_5(self):
        pk, shares = _key(3, 5)
        msg = b"hello threshold mempool"
        ct = encrypt(pk, msg)
        decryption_shares = [
            decrypt_share(shares[i], ct, pk) for i in range(3)
        ]
        recovered = combine_shares(ct, decryption_shares, pk)
        self.assertEqual(recovered, msg)


# ---------------------------------------------------------------------------
# 2. Threshold = exactly t works
# ---------------------------------------------------------------------------
class TestExactThreshold(unittest.TestCase):
    def test_exactly_t_shares_succeeds(self):
        pk, shares = _key(3, 5)
        msg = b"exactly t shares"
        ct = encrypt(pk, msg)
        # pick a contiguous set of t=3
        ds = [decrypt_share(shares[i], ct, pk) for i in range(3)]
        self.assertEqual(combine_shares(ct, ds, pk), msg)


# ---------------------------------------------------------------------------
# 3. Threshold security — t-1 shares CANNOT recover plaintext
# ---------------------------------------------------------------------------
class TestThresholdSecurity(unittest.TestCase):
    def test_t_minus_one_shares_fails(self):
        pk, shares = _key(3, 5)
        msg = b"insufficient shares"
        ct = encrypt(pk, msg)
        ds = [decrypt_share(shares[i], ct, pk) for i in range(2)]  # t-1
        with self.assertRaises(ValueError):
            combine_shares(ct, ds, pk)


# ---------------------------------------------------------------------------
# 4. More than t shares — any t-subset works
# ---------------------------------------------------------------------------
class TestExtraShares(unittest.TestCase):
    def test_all_n_shares_combine(self):
        pk, shares = _key(3, 5)
        msg = b"all n shares present"
        ct = encrypt(pk, msg)
        ds_all = [decrypt_share(s, ct, pk) for s in shares]
        recovered = combine_shares(ct, ds_all, pk)
        self.assertEqual(recovered, msg)

    def test_different_t_subsets_agree(self):
        pk, shares = _key(3, 5)
        msg = b"subset agreement"
        ct = encrypt(pk, msg)
        ds_all = [decrypt_share(s, ct, pk) for s in shares]
        a = combine_shares(ct, ds_all[0:3], pk)
        b = combine_shares(ct, ds_all[2:5], pk)
        c = combine_shares(ct, [ds_all[0], ds_all[2], ds_all[4]], pk)
        self.assertEqual(a, msg)
        self.assertEqual(b, msg)
        self.assertEqual(c, msg)


# ---------------------------------------------------------------------------
# 5. NIZK soundness — honest share verifies
# ---------------------------------------------------------------------------
class TestNIZKHonest(unittest.TestCase):
    def test_every_honest_share_verifies(self):
        pk, shares = _key(3, 5)
        ct = encrypt(pk, b"honest share")
        for s in shares:
            ds = decrypt_share(s, ct, pk)
            vk = ThresholdKeyDealer.verification_key_for(s, pk)
            self.assertTrue(verify_share(ds, ct, pk, vk))


# ---------------------------------------------------------------------------
# 6. NIZK soundness — tampered share fails
# ---------------------------------------------------------------------------
class TestNIZKTampered(unittest.TestCase):
    def setUp(self):
        self.pk, self.shares = _key(3, 5)
        self.ct = encrypt(self.pk, b"tamper me")
        self.ds = decrypt_share(self.shares[0], self.ct, self.pk)
        self.vk = ThresholdKeyDealer.verification_key_for(self.shares[0], self.pk)

    def test_baseline_passes(self):
        self.assertTrue(verify_share(self.ds, self.ct, self.pk, self.vk))

    def test_flipped_share_value_fails(self):
        bad = DecryptionShare(
            index=self.ds.index,
            share_value=(self.ds.share_value + 1) % self.pk.n,
            proof=self.ds.proof,
            version=self.ds.version,
        )
        self.assertFalse(verify_share(bad, self.ct, self.pk, self.vk))

    def test_flipped_challenge_fails(self):
        bad_proof = NIZKProof(
            challenge=self.ds.proof.challenge ^ 1,
            response=self.ds.proof.response,
        )
        bad = DecryptionShare(
            index=self.ds.index,
            share_value=self.ds.share_value,
            proof=bad_proof,
            version=self.ds.version,
        )
        self.assertFalse(verify_share(bad, self.ct, self.pk, self.vk))

    def test_flipped_response_fails(self):
        bad_proof = NIZKProof(
            challenge=self.ds.proof.challenge,
            response=self.ds.proof.response ^ 1,
        )
        bad = DecryptionShare(
            index=self.ds.index,
            share_value=self.ds.share_value,
            proof=bad_proof,
            version=self.ds.version,
        )
        self.assertFalse(verify_share(bad, self.ct, self.pk, self.vk))


# ---------------------------------------------------------------------------
# 7. NIZK soundness — wrong ciphertext
# ---------------------------------------------------------------------------
class TestNIZKWrongCiphertext(unittest.TestCase):
    def test_share_for_a_does_not_verify_for_b(self):
        pk, shares = _key(3, 5)
        ct_a = encrypt(pk, b"AAAA")
        ct_b = encrypt(pk, b"BBBB")
        ds_for_a = decrypt_share(shares[0], ct_a, pk)
        vk = ThresholdKeyDealer.verification_key_for(shares[0], pk)
        self.assertTrue(verify_share(ds_for_a, ct_a, pk, vk))
        self.assertFalse(verify_share(ds_for_a, ct_b, pk, vk))


# ---------------------------------------------------------------------------
# 8. Domain-tag separation — proves the encryption-side hash and the NIZK
#    Fiat-Shamir hash use different domain tags, so an encryption-side hash
#    output cannot be substituted into a NIZK challenge.
# ---------------------------------------------------------------------------
class TestDomainTagSeparation(unittest.TestCase):
    def test_encryption_hash_is_not_nizk_challenge(self):
        # Compute the encryption-side OAEP-style hash and a NIZK challenge
        # over THE SAME inputs.  If domain tags weren't separating them,
        # the two values would (often) coincide.
        seed = b"fixed input seed"
        encrypt_tag = tr._DOMAIN_TAG_ENCRYPT
        nizk_tag = tr._DOMAIN_TAG_SHARE_CHALLENGE
        self.assertNotEqual(encrypt_tag, nizk_tag)
        h_encrypt = tr._h_with_tag(encrypt_tag, seed)
        h_nizk = tr._h_with_tag(nizk_tag, seed)
        self.assertNotEqual(h_encrypt, h_nizk)


# ---------------------------------------------------------------------------
# 9. Configuration matrix — multiple (t, n)
# ---------------------------------------------------------------------------
class TestConfigMatrix(unittest.TestCase):
    def test_matrix(self):
        for (t, n) in [(1, 1), (1, 3), (2, 3), (3, 5), (5, 7)]:
            with self.subTest(t=t, n=n):
                pk, shares = _key(t, n)
                msg = f"matrix t={t} n={n}".encode()
                ct = encrypt(pk, msg)
                ds = [decrypt_share(shares[i], ct, pk) for i in range(t)]
                recovered = combine_shares(ct, ds, pk)
                self.assertEqual(recovered, msg)


# ---------------------------------------------------------------------------
# 10. Version tag enforcement
# ---------------------------------------------------------------------------
class TestVersionEnforcement(unittest.TestCase):
    def test_unknown_ciphertext_version_rejected(self):
        pk, shares = _key(2, 3)
        ct = encrypt(pk, b"versioned")
        # construct a future-version blob
        bad = Ciphertext(c=ct.c, version=2, tag=ct.tag)
        with self.assertRaises(ValueError) as cm:
            Ciphertext.from_bytes(bad.to_bytes())
        self.assertIn("crypto-agility", str(cm.exception).lower())

    def test_unknown_keyshare_version_rejected(self):
        pk, shares = _key(2, 3)
        bad = KeyShare(
            index=shares[0].index,
            share_value=shares[0].share_value,
            n=shares[0].n,
            version=2,
        )
        with self.assertRaises(ValueError) as cm:
            KeyShare.from_bytes(bad.to_bytes())
        self.assertIn("crypto-agility", str(cm.exception).lower())

    def test_unknown_decryptionshare_version_rejected(self):
        pk, shares = _key(2, 3)
        ct = encrypt(pk, b"version d-share")
        ds = decrypt_share(shares[0], ct, pk)
        bad = DecryptionShare(
            index=ds.index,
            share_value=ds.share_value,
            proof=ds.proof,
            version=2,
        )
        with self.assertRaises(ValueError) as cm:
            DecryptionShare.from_bytes(bad.to_bytes())
        self.assertIn("crypto-agility", str(cm.exception).lower())


# ---------------------------------------------------------------------------
# 11. Plaintext size limits
# ---------------------------------------------------------------------------
class TestSizeLimits(unittest.TestCase):
    def test_max_size_succeeds(self):
        pk, shares = _key(2, 3)
        max_len = tr.max_plaintext_len(pk)
        msg = b"M" * max_len
        ct = encrypt(pk, msg)
        ds = [decrypt_share(shares[i], ct, pk) for i in range(2)]
        self.assertEqual(combine_shares(ct, ds, pk), msg)

    def test_too_big_rejected(self):
        pk, _ = _key(2, 3)
        too_big = b"M" * (tr.max_plaintext_len(pk) + 1)
        with self.assertRaises(ValueError) as cm:
            encrypt(pk, too_big)
        self.assertIn("plaintext", str(cm.exception).lower())


# ---------------------------------------------------------------------------
# 12. Empty plaintext
# ---------------------------------------------------------------------------
class TestEmptyPlaintext(unittest.TestCase):
    def test_empty_round_trips(self):
        pk, shares = _key(2, 3)
        ct = encrypt(pk, b"")
        ds = [decrypt_share(shares[i], ct, pk) for i in range(2)]
        self.assertEqual(combine_shares(ct, ds, pk), b"")


# ---------------------------------------------------------------------------
# 13. Deterministic share verification
# ---------------------------------------------------------------------------
class TestDeterministicVerify(unittest.TestCase):
    def test_verify_is_deterministic(self):
        pk, shares = _key(2, 3)
        ct = encrypt(pk, b"deterministic")
        ds = decrypt_share(shares[0], ct, pk)
        vk = ThresholdKeyDealer.verification_key_for(shares[0], pk)
        results = [verify_share(ds, ct, pk, vk) for _ in range(20)]
        self.assertTrue(all(results))


# ---------------------------------------------------------------------------
# 14. Combiner rejects fewer than t shares
# ---------------------------------------------------------------------------
class TestCombinerInsufficient(unittest.TestCase):
    def test_insufficient_raises(self):
        pk, shares = _key(3, 5)
        ct = encrypt(pk, b"not enough")
        ds = [decrypt_share(shares[i], ct, pk) for i in range(2)]
        with self.assertRaises(ValueError):
            combine_shares(ct, ds, pk)


# ---------------------------------------------------------------------------
# 15. Combiner behavior on a poisoned share.  Documented behavior:
#     combine_shares does NOT silently filter — it raises if any supplied
#     share fails verification.  The combiner treats the share list as
#     "vetted by the caller"; the caller is expected to use verify_share
#     to filter cheaters before invoking combine_shares.  This is the
#     simpler, audit-friendly contract.
# ---------------------------------------------------------------------------
class TestCombinerOnPoisoned(unittest.TestCase):
    def test_poisoned_share_raises(self):
        pk, shares = _key(3, 5)
        ct = encrypt(pk, b"poisoned set")
        ds = [decrypt_share(shares[i], ct, pk) for i in range(4)]
        # Flip a bit in ds[0].share_value
        ds[0] = DecryptionShare(
            index=ds[0].index,
            share_value=(ds[0].share_value + 1) % pk.n,
            proof=ds[0].proof,
            version=ds[0].version,
        )
        with self.assertRaises(ValueError):
            combine_shares(ct, ds, pk)


# ---------------------------------------------------------------------------
# 16. Round-trip preserves bytes exactly through serialization
# ---------------------------------------------------------------------------
class TestSerializationRoundTrip(unittest.TestCase):
    def test_ciphertext_bytes_round_trip(self):
        pk, shares = _key(2, 3)
        msg = b"serialize me please"
        ct = encrypt(pk, msg)
        ct_blob = ct.to_bytes()
        ct2 = Ciphertext.from_bytes(ct_blob)
        ds = [decrypt_share(shares[i], ct2, pk) for i in range(2)]
        self.assertEqual(combine_shares(ct2, ds, pk), msg)

    def test_pubkey_bytes_round_trip(self):
        pk, _ = _key(2, 3)
        pk2 = PublicKey.from_bytes(pk.to_bytes())
        self.assertEqual(pk.n, pk2.n)
        self.assertEqual(pk.e, pk2.e)
        self.assertEqual(pk.version, pk2.version)

    def test_keyshare_bytes_round_trip(self):
        _, shares = _key(2, 3)
        s = shares[0]
        s2 = KeyShare.from_bytes(s.to_bytes())
        self.assertEqual(s.index, s2.index)
        self.assertEqual(s.share_value, s2.share_value)
        self.assertEqual(s.n, s2.n)
        self.assertEqual(s.version, s2.version)

    def test_decryption_share_bytes_round_trip(self):
        pk, shares = _key(2, 3)
        ct = encrypt(pk, b"d-share serialize")
        ds = decrypt_share(shares[0], ct, pk)
        ds2 = DecryptionShare.from_bytes(ds.to_bytes())
        self.assertEqual(ds.index, ds2.index)
        self.assertEqual(ds.share_value, ds2.share_value)
        self.assertEqual(ds.proof.challenge, ds2.proof.challenge)
        self.assertEqual(ds.proof.response, ds2.proof.response)
        self.assertEqual(ds.version, ds2.version)
        # And the deserialized share verifies
        vk = ThresholdKeyDealer.verification_key_for(shares[0], pk)
        self.assertTrue(verify_share(ds2, ct, pk, vk))

    def test_dict_round_trip(self):
        pk, shares = _key(2, 3)
        ct = encrypt(pk, b"dict")
        ds = decrypt_share(shares[0], ct, pk)
        # All four types support serialize/deserialize symmetrically
        self.assertEqual(
            PublicKey.deserialize(pk.serialize()).to_bytes(), pk.to_bytes()
        )
        self.assertEqual(
            KeyShare.deserialize(shares[0].serialize()).to_bytes(),
            shares[0].to_bytes(),
        )
        self.assertEqual(
            Ciphertext.deserialize(ct.serialize()).to_bytes(), ct.to_bytes()
        )
        self.assertEqual(
            DecryptionShare.deserialize(ds.serialize()).to_bytes(), ds.to_bytes()
        )


# ---------------------------------------------------------------------------
# 17. Different ciphertexts decrypt independently
# ---------------------------------------------------------------------------
class TestMultipleCiphertexts(unittest.TestCase):
    def test_three_ciphertexts(self):
        pk, shares = _key(3, 5)
        msgs = [b"first", b"second message", b"third"]
        cts = [encrypt(pk, m) for m in msgs]
        for m, ct in zip(msgs, cts):
            ds = [decrypt_share(shares[i], ct, pk) for i in range(3)]
            self.assertEqual(combine_shares(ct, ds, pk), m)


# ---------------------------------------------------------------------------
# Sanity: module-level constants
# ---------------------------------------------------------------------------
class TestConstants(unittest.TestCase):
    def test_version_constant_exposed(self):
        self.assertEqual(THRESHOLD_RSA_VERSION_CURRENT, 1)
        self.assertIn(1, tr._VALID_VERSIONS)


if __name__ == "__main__":
    unittest.main()
