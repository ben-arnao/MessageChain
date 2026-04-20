"""
Structural bounds on Signature.deserialize.

Element-size checks already exist.  What was missing:

1. WOTS+ signature must carry exactly WOTS_KEY_CHAINS elements.  A
   signature with fewer (or extra) chains is malformed — accepting it
   lets a hostile peer spend CPU on a doomed verify() call.

2. auth_path length has an upper bound.  An absurdly deep path costs
   O(len) hash operations in verify; the rehash-per-level loop is a
   cheap DoS if unbounded.  Cap at a conservative MAX_AUTH_PATH_LEN
   (64 levels → 2^64 leaves, well past any sane MERKLE_TREE_HEIGHT).

3. leaf_index must fit inside the auth_path's coverage: a path of
   length N addresses at most 2^N leaves, so leaf_index < 2^N.  A
   larger index is structurally nonsense.

All three rejections happen at deserialize time so the bad input
never reaches verify_signature's hot path.
"""

import unittest

from messagechain.config import WOTS_KEY_CHAINS
from messagechain.crypto.keys import MAX_AUTH_PATH_LEN, Signature


_HASH_SIZE = 32


def _good_chains(n: int = WOTS_KEY_CHAINS):
    return ["aa" * _HASH_SIZE for _ in range(n)]


def _good_path(n: int):
    return ["bb" * _HASH_SIZE for _ in range(n)]


def _good_pk():
    return "cc" * _HASH_SIZE


def _good_seed():
    return "dd" * _HASH_SIZE


def _base_payload(**overrides) -> dict:
    payload = {
        "wots_signature": _good_chains(),
        "leaf_index": 0,
        "auth_path": _good_path(4),
        "wots_public_key": _good_pk(),
        "wots_public_seed": _good_seed(),
    }
    payload.update(overrides)
    return payload


class TestSignatureDeserializeBounds(unittest.TestCase):
    def test_accepts_canonical_signature(self):
        """Baseline: a well-formed payload deserializes cleanly."""
        sig = Signature.deserialize(_base_payload())
        self.assertEqual(len(sig.wots_signature), WOTS_KEY_CHAINS)
        self.assertEqual(sig.leaf_index, 0)

    def test_rejects_wrong_wots_chain_count(self):
        """WOTS+ signature with != WOTS_KEY_CHAINS elements is malformed."""
        too_few = _base_payload(wots_signature=_good_chains(WOTS_KEY_CHAINS - 1))
        with self.assertRaises(ValueError):
            Signature.deserialize(too_few)

        too_many = _base_payload(wots_signature=_good_chains(WOTS_KEY_CHAINS + 1))
        with self.assertRaises(ValueError):
            Signature.deserialize(too_many)

    def test_rejects_oversized_auth_path(self):
        """auth_path longer than MAX_AUTH_PATH_LEN is a DoS vector —
        every extra element costs a hash op in verify."""
        huge = _base_payload(auth_path=_good_path(MAX_AUTH_PATH_LEN + 1))
        with self.assertRaises(ValueError):
            Signature.deserialize(huge)

    def test_rejects_leaf_index_outside_path_coverage(self):
        """A path of length N addresses exactly 2^N leaves; any
        leaf_index >= 2^N cannot be a valid position in the tree."""
        # Path length 4 → max leaf_index = 15
        payload = _base_payload(auth_path=_good_path(4), leaf_index=16)
        with self.assertRaises(ValueError):
            Signature.deserialize(payload)

    def test_leaf_index_at_boundary_accepted(self):
        """Path length 4, leaf_index 15 is the max valid — must pass."""
        payload = _base_payload(auth_path=_good_path(4), leaf_index=15)
        sig = Signature.deserialize(payload)
        self.assertEqual(sig.leaf_index, 15)

    def test_empty_auth_path_still_validates_leaf_index(self):
        """Edge case: auth_path=[] means a single-leaf tree, so the only
        valid leaf_index is 0."""
        payload = _base_payload(auth_path=[], leaf_index=0)
        Signature.deserialize(payload)  # ok

        bad = _base_payload(auth_path=[], leaf_index=1)
        with self.assertRaises(ValueError):
            Signature.deserialize(bad)


if __name__ == "__main__":
    unittest.main()
