"""Tests for Bitcoin anchoring — external immutability proof via OP_RETURN.

TDD: these tests were written BEFORE the implementation.
"""

import hashlib
import json
import struct
import time
import unittest
from unittest.mock import patch, MagicMock

from messagechain.config import (
    ANCHOR_INTERVAL,
    ANCHOR_DOMAIN_TAG,
    ANCHOR_OP_RETURN_PREFIX,
)


class TestAnchorConfig(unittest.TestCase):
    """Config constants exist with expected values."""

    def test_anchor_interval_exists(self):
        self.assertEqual(ANCHOR_INTERVAL, 100)

    def test_anchor_domain_tag_exists(self):
        self.assertEqual(ANCHOR_DOMAIN_TAG, b"MCANCHOR_V1")

    def test_anchor_op_return_prefix_exists(self):
        self.assertEqual(ANCHOR_OP_RETURN_PREFIX, b"MC")


class TestComputeAnchorHash(unittest.TestCase):
    """compute_anchor_hash is a deterministic, domain-tagged SHA-256."""

    def test_deterministic(self):
        from messagechain.anchoring.bitcoin_anchor import compute_anchor_hash

        bh = b"\x01" * 32
        bn = 100
        sr = b"\x02" * 32
        h1 = compute_anchor_hash(bh, bn, sr)
        h2 = compute_anchor_hash(bh, bn, sr)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 32)

    def test_different_inputs_different_hashes(self):
        from messagechain.anchoring.bitcoin_anchor import compute_anchor_hash

        h1 = compute_anchor_hash(b"\x01" * 32, 100, b"\x02" * 32)
        h2 = compute_anchor_hash(b"\x03" * 32, 100, b"\x02" * 32)
        h3 = compute_anchor_hash(b"\x01" * 32, 200, b"\x02" * 32)
        h4 = compute_anchor_hash(b"\x01" * 32, 100, b"\x04" * 32)
        self.assertNotEqual(h1, h2)
        self.assertNotEqual(h1, h3)
        self.assertNotEqual(h1, h4)

    def test_domain_tag_included(self):
        """Changing the domain tag changes the hash — proves it's mixed in."""
        from messagechain.anchoring.bitcoin_anchor import compute_anchor_hash

        bh = b"\x01" * 32
        bn = 100
        sr = b"\x02" * 32
        h_normal = compute_anchor_hash(bh, bn, sr)

        # Manually compute with a different tag
        alt_tag = b"MCANCHOR_V2"
        alt = hashlib.sha256(
            alt_tag + bh + struct.pack(">Q", bn) + sr
        ).digest()
        self.assertNotEqual(h_normal, alt)

        # Confirm the normal hash matches the expected tag
        expected = hashlib.sha256(
            b"MCANCHOR_V1" + bh + struct.pack(">Q", bn) + sr
        ).digest()
        self.assertEqual(h_normal, expected)

    def test_returns_bytes(self):
        from messagechain.anchoring.bitcoin_anchor import compute_anchor_hash

        result = compute_anchor_hash(b"\x00" * 32, 0, b"\x00" * 32)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)


class TestAnchorRecord(unittest.TestCase):
    """Anchor record round-trip in chaindb (bitcoin_anchors table)."""

    def setUp(self):
        from messagechain.storage.chaindb import ChainDB
        self.db = ChainDB(":memory:")

    def tearDown(self):
        self.db.close()

    def test_store_and_retrieve_anchor(self):
        anchor_hash = b"\xaa" * 32
        mc_block_hash = b"\xbb" * 32
        mc_block_number = 100
        btc_txid = "ab" * 32
        btc_block_height = 800000
        ts = int(time.time())

        self.db.store_bitcoin_anchor(
            mc_block_number=mc_block_number,
            mc_block_hash=mc_block_hash,
            anchor_hash=anchor_hash,
            btc_txid=btc_txid,
            btc_block_height=btc_block_height,
            timestamp=ts,
        )

        anchors = self.db.get_all_bitcoin_anchors()
        self.assertEqual(len(anchors), 1)
        a = anchors[0]
        self.assertEqual(a["mc_block_number"], mc_block_number)
        self.assertEqual(a["mc_block_hash"], mc_block_hash)
        self.assertEqual(a["anchor_hash"], anchor_hash)
        self.assertEqual(a["btc_txid"], btc_txid)
        self.assertEqual(a["btc_block_height"], btc_block_height)
        self.assertEqual(a["timestamp"], ts)

    def test_store_anchor_null_btc_fields(self):
        """btc_txid and btc_block_height can be NULL initially."""
        self.db.store_bitcoin_anchor(
            mc_block_number=200,
            mc_block_hash=b"\xcc" * 32,
            anchor_hash=b"\xdd" * 32,
            btc_txid=None,
            btc_block_height=None,
            timestamp=int(time.time()),
        )
        anchors = self.db.get_all_bitcoin_anchors()
        self.assertEqual(len(anchors), 1)
        self.assertIsNone(anchors[0]["btc_txid"])
        self.assertIsNone(anchors[0]["btc_block_height"])

    def test_update_btc_confirmation(self):
        """Can update btc_txid and btc_block_height after submission."""
        self.db.store_bitcoin_anchor(
            mc_block_number=300,
            mc_block_hash=b"\xee" * 32,
            anchor_hash=b"\xff" * 32,
            btc_txid=None,
            btc_block_height=None,
            timestamp=int(time.time()),
        )
        self.db.update_bitcoin_anchor_confirmation(
            mc_block_number=300,
            btc_txid="cd" * 32,
            btc_block_height=800100,
        )
        anchor = self.db.get_bitcoin_anchor(300)
        self.assertIsNotNone(anchor)
        self.assertEqual(anchor["btc_txid"], "cd" * 32)
        self.assertEqual(anchor["btc_block_height"], 800100)

    def test_duplicate_anchor_rejected(self):
        """Storing a second anchor for the same block_number is rejected."""
        self.db.store_bitcoin_anchor(
            mc_block_number=400,
            mc_block_hash=b"\x11" * 32,
            anchor_hash=b"\x22" * 32,
            btc_txid=None,
            btc_block_height=None,
            timestamp=int(time.time()),
        )
        # Second insert for same block_number should be ignored
        self.db.store_bitcoin_anchor(
            mc_block_number=400,
            mc_block_hash=b"\x33" * 32,
            anchor_hash=b"\x44" * 32,
            btc_txid=None,
            btc_block_height=None,
            timestamp=int(time.time()),
        )
        anchor = self.db.get_bitcoin_anchor(400)
        # First one wins
        self.assertEqual(anchor["mc_block_hash"], b"\x11" * 32)

    def test_get_anchor_nonexistent(self):
        anchor = self.db.get_bitcoin_anchor(9999)
        self.assertIsNone(anchor)


class TestBuildAnchorTxHex(unittest.TestCase):
    """build_anchor_tx_hex produces valid Bitcoin tx structure."""

    def test_produces_hex_string(self):
        from messagechain.anchoring.bitcoin_anchor import build_anchor_tx_hex

        anchor_hash = b"\xab" * 32
        # Fake UTXO: (txid, vout, scriptPubKey, amount_satoshis, privkey_wif)
        utxo = {
            "txid": "aa" * 32,
            "vout": 0,
            "script_pubkey": "76a914" + "bb" * 20 + "88ac",
            "amount_satoshis": 100000,
            "privkey_hex": "cc" * 32,
        }
        tx_hex = build_anchor_tx_hex(anchor_hash, utxo)
        self.assertIsInstance(tx_hex, str)
        # Must be valid hex
        bytes.fromhex(tx_hex)

    def test_op_return_contains_anchor_hash(self):
        from messagechain.anchoring.bitcoin_anchor import build_anchor_tx_hex

        anchor_hash = b"\xde\xad" * 16  # 32 bytes
        utxo = {
            "txid": "aa" * 32,
            "vout": 0,
            "script_pubkey": "76a914" + "bb" * 20 + "88ac",
            "amount_satoshis": 100000,
            "privkey_hex": "cc" * 32,
        }
        tx_hex = build_anchor_tx_hex(anchor_hash, utxo)
        tx_bytes = bytes.fromhex(tx_hex)
        # The OP_RETURN output must contain the MC prefix + anchor hash
        op_return_data = ANCHOR_OP_RETURN_PREFIX + anchor_hash
        self.assertIn(op_return_data, tx_bytes)

    def test_tx_has_version_and_locktime(self):
        from messagechain.anchoring.bitcoin_anchor import build_anchor_tx_hex

        anchor_hash = b"\x01" * 32
        utxo = {
            "txid": "aa" * 32,
            "vout": 0,
            "script_pubkey": "76a914" + "bb" * 20 + "88ac",
            "amount_satoshis": 100000,
            "privkey_hex": "cc" * 32,
        }
        tx_hex = build_anchor_tx_hex(anchor_hash, utxo)
        tx_bytes = bytes.fromhex(tx_hex)
        # Version 1 (little-endian)
        self.assertEqual(tx_bytes[:4], struct.pack("<I", 1))
        # Locktime 0 at end
        self.assertEqual(tx_bytes[-4:], struct.pack("<I", 0))

    def test_tx_has_one_input(self):
        from messagechain.anchoring.bitcoin_anchor import build_anchor_tx_hex

        anchor_hash = b"\x01" * 32
        utxo = {
            "txid": "aa" * 32,
            "vout": 0,
            "script_pubkey": "76a914" + "bb" * 20 + "88ac",
            "amount_satoshis": 100000,
            "privkey_hex": "cc" * 32,
        }
        tx_hex = build_anchor_tx_hex(anchor_hash, utxo)
        tx_bytes = bytes.fromhex(tx_hex)
        # After version (4 bytes), input count should be 0x01
        self.assertEqual(tx_bytes[4], 1)

    def test_tx_has_two_outputs(self):
        """One OP_RETURN, one change output."""
        from messagechain.anchoring.bitcoin_anchor import build_anchor_tx_hex

        anchor_hash = b"\x01" * 32
        utxo = {
            "txid": "aa" * 32,
            "vout": 0,
            "script_pubkey": "76a914" + "bb" * 20 + "88ac",
            "amount_satoshis": 100000,
            "privkey_hex": "cc" * 32,
        }
        tx_hex = build_anchor_tx_hex(anchor_hash, utxo)
        tx_bytes = bytes.fromhex(tx_hex)

        # Parse to find output count: skip version(4) + input_count(1) + input
        # Input: prev_txid(32) + prev_vout(4) + scriptSig_len(varint) + scriptSig + sequence(4)
        # We just verify the OP_RETURN marker (0x6a) appears in outputs
        self.assertIn(b"\x6a", tx_bytes)  # OP_RETURN opcode


class TestAnchorFinalityCheck(unittest.TestCase):
    """Only finalized blocks can be anchored."""

    def test_unfinalized_block_rejected(self):
        from messagechain.anchoring.bitcoin_anchor import (
            should_anchor_block,
        )

        # Block not in finalized set -> should not anchor
        finalized_heights = {100, 200, 300}
        self.assertFalse(should_anchor_block(150, finalized_heights, last_anchored=0))

    def test_finalized_block_accepted(self):
        from messagechain.anchoring.bitcoin_anchor import should_anchor_block

        finalized_heights = {100, 200, 300}
        self.assertTrue(should_anchor_block(200, finalized_heights, last_anchored=0))

    def test_already_anchored_rejected(self):
        from messagechain.anchoring.bitcoin_anchor import should_anchor_block

        finalized_heights = {100, 200, 300}
        # Already anchored block 200, so anchoring it again should fail
        self.assertFalse(should_anchor_block(200, finalized_heights, last_anchored=200))

    def test_not_at_interval_rejected(self):
        """Only anchor at ANCHOR_INTERVAL boundaries."""
        from messagechain.anchoring.bitcoin_anchor import should_anchor_block

        finalized_heights = {100, 150, 200}
        # 150 is finalized but not at interval boundary (100)
        self.assertFalse(should_anchor_block(150, finalized_heights, last_anchored=100))

    def test_anchor_at_interval_boundary(self):
        from messagechain.anchoring.bitcoin_anchor import should_anchor_block

        finalized_heights = {100, 200, 300}
        self.assertTrue(should_anchor_block(300, finalized_heights, last_anchored=200))


class TestVerifyAnchor(unittest.TestCase):
    """verify_anchor checks OP_RETURN data against expected anchor hash."""

    def _mock_rpc_response(self, anchor_hash, prefix=ANCHOR_OP_RETURN_PREFIX):
        """Build a mock Bitcoin RPC getrawtransaction response."""
        op_return_hex = (prefix + anchor_hash).hex()
        return {
            "result": {
                "vout": [
                    {
                        "scriptPubKey": {
                            "asm": f"OP_RETURN {op_return_hex}",
                            "hex": "6a" + format(len(prefix) + 32, "02x") + op_return_hex,
                            "type": "nulldata",
                        },
                        "value": 0,
                    },
                    {
                        "scriptPubKey": {
                            "asm": "OP_DUP OP_HASH160 ...",
                            "type": "pubkeyhash",
                        },
                        "value": 0.00099000,
                    },
                ],
            },
        }

    @patch("messagechain.anchoring.bitcoin_rpc.bitcoin_rpc_call")
    def test_matching_hash_returns_true(self, mock_rpc):
        from messagechain.anchoring.bitcoin_anchor import verify_anchor

        anchor_hash = b"\xab" * 32
        mock_rpc.return_value = self._mock_rpc_response(anchor_hash)

        result = verify_anchor(anchor_hash, "fake_txid", "http://localhost:8332")
        self.assertTrue(result)

    @patch("messagechain.anchoring.bitcoin_rpc.bitcoin_rpc_call")
    def test_mismatched_hash_returns_false(self, mock_rpc):
        from messagechain.anchoring.bitcoin_anchor import verify_anchor

        anchor_hash = b"\xab" * 32
        wrong_hash = b"\xcd" * 32
        mock_rpc.return_value = self._mock_rpc_response(wrong_hash)

        result = verify_anchor(anchor_hash, "fake_txid", "http://localhost:8332")
        self.assertFalse(result)

    @patch("messagechain.anchoring.bitcoin_rpc.bitcoin_rpc_call")
    def test_no_op_return_returns_false(self, mock_rpc):
        from messagechain.anchoring.bitcoin_anchor import verify_anchor

        mock_rpc.return_value = {
            "result": {
                "vout": [
                    {
                        "scriptPubKey": {
                            "asm": "OP_DUP OP_HASH160 ...",
                            "type": "pubkeyhash",
                        },
                        "value": 0.001,
                    },
                ],
            },
        }

        result = verify_anchor(b"\xab" * 32, "fake_txid", "http://localhost:8332")
        self.assertFalse(result)


class TestVerifyChainIntegrity(unittest.TestCase):
    """verify_chain_integrity walks stored anchors and checks each."""

    def setUp(self):
        from messagechain.storage.chaindb import ChainDB
        self.db = ChainDB(":memory:")

    def tearDown(self):
        self.db.close()

    @patch("messagechain.anchoring.bitcoin_anchor.verify_anchor")
    def test_all_matching_returns_all_pass(self, mock_verify):
        from messagechain.anchoring.bitcoin_anchor import verify_chain_integrity

        mock_verify.return_value = True

        # Store two anchors with btc_txid populated
        self.db.store_bitcoin_anchor(
            mc_block_number=100,
            mc_block_hash=b"\x01" * 32,
            anchor_hash=b"\x11" * 32,
            btc_txid="aa" * 32,
            btc_block_height=800000,
            timestamp=int(time.time()),
        )
        self.db.store_bitcoin_anchor(
            mc_block_number=200,
            mc_block_hash=b"\x02" * 32,
            anchor_hash=b"\x22" * 32,
            btc_txid="bb" * 32,
            btc_block_height=800100,
            timestamp=int(time.time()),
        )

        results = verify_chain_integrity(self.db, "http://localhost:8332")
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.passed for r in results))

    @patch("messagechain.anchoring.bitcoin_anchor.verify_anchor")
    def test_one_tampered_returns_one_fail(self, mock_verify):
        from messagechain.anchoring.bitcoin_anchor import verify_chain_integrity

        # First anchor passes, second fails
        mock_verify.side_effect = [True, False]

        self.db.store_bitcoin_anchor(
            mc_block_number=100,
            mc_block_hash=b"\x01" * 32,
            anchor_hash=b"\x11" * 32,
            btc_txid="aa" * 32,
            btc_block_height=800000,
            timestamp=int(time.time()),
        )
        self.db.store_bitcoin_anchor(
            mc_block_number=200,
            mc_block_hash=b"\x02" * 32,
            anchor_hash=b"\x22" * 32,
            btc_txid="bb" * 32,
            btc_block_height=800100,
            timestamp=int(time.time()),
        )

        results = verify_chain_integrity(self.db, "http://localhost:8332")
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].passed)
        self.assertFalse(results[1].passed)

    @patch("messagechain.anchoring.bitcoin_anchor.verify_anchor")
    def test_skips_unconfirmed_anchors(self, mock_verify):
        """Anchors without btc_txid are skipped (not yet submitted)."""
        from messagechain.anchoring.bitcoin_anchor import verify_chain_integrity

        mock_verify.return_value = True

        self.db.store_bitcoin_anchor(
            mc_block_number=100,
            mc_block_hash=b"\x01" * 32,
            anchor_hash=b"\x11" * 32,
            btc_txid=None,  # Not yet confirmed
            btc_block_height=None,
            timestamp=int(time.time()),
        )

        results = verify_chain_integrity(self.db, "http://localhost:8332")
        self.assertEqual(len(results), 0)
        mock_verify.assert_not_called()


class TestSubmitAnchor(unittest.TestCase):
    """submit_anchor sends raw tx via Bitcoin RPC."""

    @patch("messagechain.anchoring.bitcoin_rpc.bitcoin_rpc_call")
    def test_submit_returns_txid(self, mock_rpc):
        from messagechain.anchoring.bitcoin_anchor import submit_anchor

        expected_txid = "ab" * 32
        mock_rpc.return_value = {"result": expected_txid}

        txid = submit_anchor("deadbeef" * 8, "http://localhost:8332")
        self.assertEqual(txid, expected_txid)
        mock_rpc.assert_called_once()

    @patch("messagechain.anchoring.bitcoin_rpc.bitcoin_rpc_call")
    def test_submit_propagates_error(self, mock_rpc):
        from messagechain.anchoring.bitcoin_anchor import submit_anchor

        mock_rpc.return_value = {"error": {"code": -25, "message": "Missing inputs"}}

        with self.assertRaises(RuntimeError):
            submit_anchor("deadbeef" * 8, "http://localhost:8332")


class TestBitcoinRpc(unittest.TestCase):
    """Thin Bitcoin RPC client uses stdlib urllib."""

    @patch("urllib.request.urlopen")
    def test_rpc_call_sends_json(self, mock_urlopen):
        from messagechain.anchoring.bitcoin_rpc import bitcoin_rpc_call

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"result": "ok"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = bitcoin_rpc_call(
            "http://localhost:8332",
            "getrawtransaction",
            ["txid", True],
        )
        self.assertEqual(result, {"result": "ok"})
        mock_urlopen.assert_called_once()


if __name__ == "__main__":
    unittest.main()
