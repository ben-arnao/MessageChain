"""Faucet public entry points must accept BOTH `mc1...` bech32 addresses
AND the raw 64-char hex form.

Motivation: the CLI (`messagechain account`, `messagechain generate-key`)
prints `Address: mc1...` and tells users *"Share the 'Address' form when
receiving funds — it has a built-in checksum."* The public faucet at
messagechain.org used to reject anything other than 64-char hex, so every
newcomer who pasted the `mc1...` form they were just told to share got
hard-bounced at step 1 of the headline funnel ("post your first message").

These tests pin:
  1. issue_challenge accepts `mc1...` addresses.
  2. issue_challenge accepts hex (regression — must not break the old path).
  3. issue_challenge rejects a tampered `mc1...` (bad checksum) with a
     clear error mentioning the checksum.
  4. try_drip accepts `mc1...` and successfully drips.
  5. try_drip on a tampered `mc1...` returns a clear bad-checksum error.
  6. End-to-end: a challenge issued in `mc1...` form can be solved and
     redeemed in `mc1...` form (the address is the same entity_id either
     way, so the bound-to-address check passes regardless of the form
     each request used).
"""
from __future__ import annotations

import hashlib
import unittest

from messagechain.identity.address import encode_address
from messagechain.network.faucet import FAUCET_DRIP, FaucetState


def _mk_state(window_cap: int = 5, pow_difficulty: int = 1):
    submits: list[dict] = []

    def submit_cb(tx_dict):
        submits.append(tx_dict)
        return True, ""

    def build_cb(recipient_bytes):
        return {
            "tx_hash": ("a" * 60) + recipient_bytes[:2].hex(),
            "amount": FAUCET_DRIP,
        }

    return FaucetState(
        submit_callback=submit_cb,
        build_tx_callback=build_cb,
        window_cap=window_cap,
        pow_difficulty=pow_difficulty,
    ), submits


def _solve_pow_for_payload(payload: dict) -> int:
    seed = bytes.fromhex(payload["seed"])
    address = bytes.fromhex(payload["address"])
    diff = payload["difficulty"]
    for nonce in range(0, 1 << 32):
        digest = hashlib.sha256(
            seed + nonce.to_bytes(8, "big") + address,
        ).digest()
        bits = 0
        for byte in digest:
            if byte == 0:
                bits += 8
                continue
            for shift in range(7, -1, -1):
                if byte & (1 << shift):
                    break
                bits += 1
            break
        if bits >= diff:
            return nonce
    raise RuntimeError("PoW solver exhausted")


# A canonical entity_id we'll use across tests. 32 bytes.
_ENTITY_ID = bytes.fromhex("ab" * 32)
_HEX_FORM = _ENTITY_ID.hex()
_MC1_FORM = encode_address(_ENTITY_ID)


class TestFaucetAcceptsMc1OnIssueChallenge(unittest.TestCase):

    def test_issue_challenge_accepts_mc1_address(self):
        st, _ = _mk_state()
        ok, err, payload = st.issue_challenge(_MC1_FORM)
        self.assertTrue(ok, err)
        # Internally the address is normalized to the 32-byte entity_id;
        # the payload echoes the hex form so the JS PoW worker can hash
        # over the same canonical bytes the verifier uses.
        self.assertEqual(payload["address"], _HEX_FORM)

    def test_issue_challenge_still_accepts_hex(self):
        """Regression: don't break the existing hex path."""
        st, _ = _mk_state()
        ok, err, payload = st.issue_challenge(_HEX_FORM)
        self.assertTrue(ok, err)
        self.assertEqual(payload["address"], _HEX_FORM)

    def test_issue_challenge_rejects_tampered_mc1_with_checksum_error(self):
        """A typo'd `mc1...` (last char flipped) must NOT be silently
        accepted as if it were a different valid address — the whole
        point of bech32 was to catch transcription errors, and the
        public faucet is the exact place users will paste a typo.
        """
        st, _ = _mk_state()
        # Flip the last hex char of the checksum to break it.
        last = _MC1_FORM[-1]
        bad_last = "0" if last != "0" else "1"
        tampered = _MC1_FORM[:-1] + bad_last
        ok, err, _payload = st.issue_challenge(tampered)
        self.assertFalse(ok)
        self.assertIn("checksum", err.lower())

    def test_issue_challenge_rejects_uppercase_garbage(self):
        """Anything that isn't either form should fail with a useful
        message — not crash, not wrongly succeed."""
        st, _ = _mk_state()
        ok, err, _payload = st.issue_challenge("not a real address")
        self.assertFalse(ok)
        self.assertTrue(err)


class TestFaucetAcceptsMc1OnTryDrip(unittest.TestCase):

    def test_try_drip_accepts_mc1_address(self):
        st, submits = _mk_state(window_cap=10)
        ok, err, payload = st.issue_challenge(_MC1_FORM)
        self.assertTrue(ok, err)
        nonce = _solve_pow_for_payload(payload)
        r = st.try_drip(
            "1.2.3.4",
            _MC1_FORM,
            challenge_seed_hex=payload["seed"],
            nonce=nonce,
        )
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.amount, FAUCET_DRIP)
        self.assertEqual(len(submits), 1)

    def test_try_drip_still_accepts_hex(self):
        """Regression: the existing hex path still works end-to-end."""
        st, submits = _mk_state(window_cap=10)
        ok, err, payload = st.issue_challenge(_HEX_FORM)
        self.assertTrue(ok, err)
        nonce = _solve_pow_for_payload(payload)
        r = st.try_drip(
            "1.2.3.4",
            _HEX_FORM,
            challenge_seed_hex=payload["seed"],
            nonce=nonce,
        )
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(submits), 1)

    def test_try_drip_rejects_tampered_mc1_with_checksum_error(self):
        st, submits = _mk_state(window_cap=10)
        last = _MC1_FORM[-1]
        bad_last = "0" if last != "0" else "1"
        tampered = _MC1_FORM[:-1] + bad_last
        # Even before any PoW: address sanity rejects up front.
        r = st.try_drip(
            "1.2.3.4",
            tampered,
            challenge_seed_hex="00" * 16,
            nonce=0,
        )
        self.assertFalse(r.ok)
        self.assertIn("checksum", r.error.lower())
        self.assertEqual(submits, [],
            "tampered address must not reach submit")

    def test_mc1_challenge_redeemable_via_hex_and_vice_versa(self):
        """The two forms describe the same entity_id, so a challenge
        issued in `mc1...` form must be redeemable when the drip
        request quotes the hex form (and vice versa).  This keeps the
        client/server contract simple: the wire form is interchangeable
        because the canonical key is the 32-byte entity_id."""
        st, submits = _mk_state(window_cap=10)
        ok, err, payload = st.issue_challenge(_MC1_FORM)
        self.assertTrue(ok, err)
        nonce = _solve_pow_for_payload(payload)
        # Quote the hex form on POST /faucet even though the challenge
        # was issued for `mc1...`.
        r = st.try_drip(
            "1.2.3.4",
            _HEX_FORM,
            challenge_seed_hex=payload["seed"],
            nonce=nonce,
        )
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(submits), 1)


if __name__ == "__main__":
    unittest.main()
