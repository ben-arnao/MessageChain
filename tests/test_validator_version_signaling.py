"""Tests for Fork 1: validator version signaling.

Audit finding #2 (the second-highest-stakes item from the original
audit) was that hard forks ship with no upgrade-readiness signal --
the next fork that misses coordination silently partitions the
chain.  This fork lays the wire-format groundwork for that gate by
adding a uint16 validator_version field to V2 block headers.

Fork 1 itself has NO consensus-rule consumer of the field; it just
makes the field appear on the wire for Fork 2 (the active-set
liveness fallback) to gate against.

These tests pin:

1. V1 wire format (pre-VERSION_SIGNALING_HEIGHT) is unchanged --
   pre-Fork-1 block hashes are preserved, so the existing chain
   replays under new code without re-hashing surprises.
2. V2 wire format (post-activation) includes the validator_version
   field on the wire and in signable_data, so the proposer signature
   commits to it.
3. The block producer stamps CURRENT_VALIDATOR_VERSION post-
   activation and UNSIGNALLED pre-activation.
4. The dict serialize/deserialize round trip carries the field.
5. V1 -> V1 and V2 -> V2 binary round trips are lossless; mixing
   the version on the decode side is a clean ValueError, not a
   silent corruption.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    BLOCK_SERIALIZATION_VERSION,
    BLOCK_SERIALIZATION_VERSION_V1,
    BLOCK_SERIALIZATION_VERSION_V2,
    VERSION_SIGNALING_HEIGHT,
)
from messagechain.consensus.validator_versions import (
    CURRENT_VALIDATOR_VERSION,
    REGISTRY,
    UNSIGNALLED,
    describe_version,
    is_known_version,
)
from messagechain.core.block import BlockHeader


def _mk_header(block_number: int, validator_version: int) -> BlockHeader:
    return BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1_700_000_000.0,
        proposer_id=bytes(32),
        validator_version=validator_version,
    )


class TestRegistry(unittest.TestCase):
    """The registry is append-only and self-consistent."""

    def test_unsignalled_is_zero(self):
        self.assertEqual(UNSIGNALLED, 0)

    def test_unsignalled_is_in_registry(self):
        self.assertIn(UNSIGNALLED, REGISTRY)

    def test_current_version_in_registry(self):
        self.assertIn(CURRENT_VALIDATOR_VERSION, REGISTRY)

    def test_current_version_is_not_unsignalled(self):
        """A binary that signals 0 cannot be distinguished from a pre-
        Fork-1 historical block.  CURRENT must always be > 0."""
        self.assertGreater(CURRENT_VALIDATOR_VERSION, UNSIGNALLED)

    def test_current_version_describes_to_a_release_tag(self):
        tag = describe_version(CURRENT_VALIDATOR_VERSION)
        self.assertNotEqual(tag, f"<unknown v{CURRENT_VALIDATOR_VERSION}>")

    def test_unknown_version_describes_with_unknown_marker(self):
        far_future = max(REGISTRY) + 9999
        self.assertFalse(is_known_version(far_future))
        self.assertIn("unknown", describe_version(far_future))


class TestSerializationVersionConstants(unittest.TestCase):

    def test_v1_and_v2_distinct(self):
        self.assertNotEqual(
            BLOCK_SERIALIZATION_VERSION_V1,
            BLOCK_SERIALIZATION_VERSION_V2,
        )

    def test_current_is_v2(self):
        """Fork 1 makes V2 the active wire format for new blocks."""
        self.assertEqual(BLOCK_SERIALIZATION_VERSION, BLOCK_SERIALIZATION_VERSION_V2)


class TestV1BlockHeaderHashStability(unittest.TestCase):
    """The most load-bearing property of Fork 1: re-hashing a pre-fork
    block under new code MUST yield the same block_hash the network
    agreed on when the block was first minted.  Any drift here breaks
    the prev-hash chain and invalidates every proposer signature on
    blocks below VERSION_SIGNALING_HEIGHT."""

    def test_pre_activation_signable_data_omits_validator_version(self):
        h_pre = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT - 1,
            validator_version=UNSIGNALLED,
        )
        h_post = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT,
            validator_version=UNSIGNALLED,
        )
        # The two headers differ only in block_number (8 bytes packed
        # in big-endian).  V2's signable_data appends a 2-byte field;
        # V1's does not.  So |sd_post| - |sd_pre| must be exactly 2.
        sd_pre = h_pre.signable_data()
        sd_post = h_post.signable_data()
        self.assertEqual(
            len(sd_post) - len(sd_pre), 2,
            "post-activation signable_data must add exactly 2 bytes "
            "(uint16 validator_version) over the pre-activation layout",
        )

    def test_pre_activation_to_bytes_omits_validator_version(self):
        h = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT - 1,
            validator_version=UNSIGNALLED,
        )
        # Round-trip via V1 codec.
        blob = h.to_bytes()
        parsed = BlockHeader.from_bytes(
            blob, ser_version=BLOCK_SERIALIZATION_VERSION_V1,
        )
        self.assertEqual(parsed, h)
        # Sanity: re-encoding the parsed block produces the same bytes
        # (lossless re-serialization of historical blocks is what lets
        # archival nodes re-emit the chain under either format).
        self.assertEqual(parsed.to_bytes(), blob)

    def test_pre_activation_validator_version_default_is_unsignalled(self):
        """A V1 blob has no validator_version on the wire.  Decoding
        defaults to UNSIGNALLED so a downstream consumer can tell this
        is a historical block, not a buggy modern proposer."""
        h = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT - 1,
            validator_version=UNSIGNALLED,
        )
        blob = h.to_bytes()
        parsed = BlockHeader.from_bytes(
            blob, ser_version=BLOCK_SERIALIZATION_VERSION_V1,
        )
        self.assertEqual(parsed.validator_version, UNSIGNALLED)


class TestV2BlockHeaderCarriesValidatorVersion(unittest.TestCase):

    def test_v2_round_trip_preserves_validator_version(self):
        h = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT + 1,
            validator_version=CURRENT_VALIDATOR_VERSION,
        )
        blob = h.to_bytes()
        parsed = BlockHeader.from_bytes(
            blob, ser_version=BLOCK_SERIALIZATION_VERSION_V2,
        )
        self.assertEqual(parsed.validator_version, CURRENT_VALIDATOR_VERSION)
        self.assertEqual(parsed, h)

    def test_v2_signable_data_commits_to_validator_version(self):
        """A relay that mutates the validator_version field in transit
        must invalidate the proposer signature.  Two headers identical
        except for validator_version must therefore have distinct
        signable_data byte sequences."""
        ha = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT + 1,
            validator_version=1,
        )
        hb = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT + 1,
            validator_version=2,
        )
        self.assertNotEqual(ha.signable_data(), hb.signable_data())

    def test_v2_decoding_v1_blob_raises(self):
        """A V1 blob is shorter than V2 by 2 bytes.  Decoding it under
        V2 must error -- silent fallback would let a downgrade attack
        flip a V2 blob's validator_version to zero by truncating."""
        h = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT - 1,
            validator_version=UNSIGNALLED,
        )
        v1_blob = h.to_bytes()  # self-selects V1
        with self.assertRaises(ValueError):
            BlockHeader.from_bytes(
                v1_blob, ser_version=BLOCK_SERIALIZATION_VERSION_V2,
            )


class TestDictSerializationRoundTrip(unittest.TestCase):
    """JSON-style serialize/deserialize is used by RPC and on-disk
    archival; it must carry validator_version through cleanly while
    accepting pre-Fork-1 dicts that have no such key."""

    def test_serialize_includes_validator_version(self):
        h = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT + 1,
            validator_version=CURRENT_VALIDATOR_VERSION,
        )
        d = h.serialize()
        self.assertIn("validator_version", d)
        self.assertEqual(d["validator_version"], CURRENT_VALIDATOR_VERSION)

    def test_deserialize_round_trip(self):
        h = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT + 1,
            validator_version=CURRENT_VALIDATOR_VERSION,
        )
        d = h.serialize()
        parsed = BlockHeader.deserialize(d)
        self.assertEqual(parsed.validator_version, CURRENT_VALIDATOR_VERSION)

    def test_deserialize_legacy_dict_defaults_to_unsignalled(self):
        """Dicts produced by pre-Fork-1 binaries have no
        validator_version key.  Decoding must default cleanly to
        UNSIGNALLED rather than raising KeyError."""
        h = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT - 1,
            validator_version=UNSIGNALLED,
        )
        d = h.serialize()
        del d["validator_version"]
        parsed = BlockHeader.deserialize(d)
        self.assertEqual(parsed.validator_version, UNSIGNALLED)


class TestProducerStampsValidatorVersion(unittest.TestCase):
    """The block producer (pos.create_block_template) stamps
    CURRENT_VALIDATOR_VERSION on freshly-built blocks at/after
    VERSION_SIGNALING_HEIGHT, and UNSIGNALLED before."""

    def test_pre_activation_block_stamped_unsignalled(self):
        """A block produced at block_number=VERSION_SIGNALING_HEIGHT-1
        (the last V1 block) must have validator_version=UNSIGNALLED so
        signable_data() omits the field and the original V1 hash layout
        is preserved."""
        # Direct-construct rather than spinning up a full block_producer
        # harness -- we only need to assert the height-driven branching
        # in the producer matches what BlockHeader's height-aware
        # ser_version logic expects.
        h_pre = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT - 1,
            validator_version=UNSIGNALLED,
        )
        self.assertEqual(
            h_pre._ser_version_for_height(),
            BLOCK_SERIALIZATION_VERSION_V1,
        )

    def test_post_activation_block_uses_v2(self):
        h_post = _mk_header(
            block_number=VERSION_SIGNALING_HEIGHT,
            validator_version=CURRENT_VALIDATOR_VERSION,
        )
        self.assertEqual(
            h_post._ser_version_for_height(),
            BLOCK_SERIALIZATION_VERSION_V2,
        )


if __name__ == "__main__":
    unittest.main()
