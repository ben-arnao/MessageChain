"""`messagechain receipt` MUST verify the merkle proof before
printing the permanence guarantee.

Audit finding: ``cmd_receipt`` rendered the
"This message is permanent.  It can never be deleted." line
based purely on the RPC server's ``status: included`` response,
including a ``merkle_proof`` blob it never verified.  A colluding
RPC server could return ``{status:"included", merkle_root: H',
merkle_proof:<forged>, finality_threshold_met: True}`` and the
CLI printed the headline guarantee with full conviction.

This file pins the post-fix behavior:

  * Valid proof + matching merkle_root => permanence text printed.
  * Invalid proof (tampered sibling) => permanence text NOT
    printed; WARNING surfaced.
  * Missing proof => permanence text NOT printed; WARNING.
  * --cross-check-server agreement => permanence text + a
    "Independently verified" confidence line.
  * --cross-check-server disagreement => permanence text NOT
    printed; WARNING.
  * Default (no --cross-check-server) => permanence text + a
    softer "to independently confirm" caveat naming the flag.
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from messagechain.crypto.hashing import default_hash


def _build_real_proof_against_root():
    """Construct a (tx_hash_hex, merkle_root_hex, proof_dict) tuple
    where the proof actually verifies against the root.

    Mirrors the construction in ``core/spv.generate_merkle_proof``
    and ``core/block.compute_merkle_root`` -- 0x00 prefix on
    leaves, 0x01 prefix on internal nodes, sentinel for odd-layer
    padding.  We avoid building a real Block to keep the test
    fast (no entity, no consensus, no signatures).
    """
    def h(b):
        return default_hash(b)

    tx_hashes = [
        b"\x10" * 32, b"\x11" * 32, b"\x12" * 32, b"\x13" * 32,
    ]
    target_index = 1
    target_hash = tx_hashes[target_index]

    # Build the tree, recording siblings/directions for target_index.
    siblings = []
    directions = []
    layer = [h(b"\x00" + t) for t in tx_hashes]
    idx = target_index
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(h(b"\x02sentinel"))
        if idx % 2 == 0:
            sibling_idx = idx + 1
            directions.append(False)
        else:
            sibling_idx = idx - 1
            directions.append(True)
        siblings.append(layer[sibling_idx])
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(h(b"\x01" + layer[i] + layer[i + 1]))
        layer = next_layer
        idx //= 2
    root = layer[0]

    proof_dict = {
        "tx_hash": target_hash.hex(),
        "tx_index": target_index,
        "siblings": [s.hex() for s in siblings],
        "directions": directions,
    }
    return target_hash.hex(), root.hex(), proof_dict


def _receipt_args(tx_hash: str, **overrides) -> argparse.Namespace:
    base = dict(
        tx_hash=tx_hash,
        server="127.0.0.1:9334",
        cross_check_server=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _included_response(tx_hash_hex, merkle_root_hex, proof_dict, **overrides):
    base = {
        "status": "included",
        "block_height": 14523,
        "block_hash": "cd" * 32,
        "tx_index": proof_dict["tx_index"],
        "merkle_root": merkle_root_hex,
        "attesters": 12,
        "total_validators": 14,
        "attesting_stake": 800_000,
        "total_stake": 1_000_000,
        "finality_threshold_met": True,
        "finality_numerator": 2,
        "finality_denominator": 3,
        "merkle_proof": proof_dict,
    }
    base.update(overrides)
    return base


_PERMANENCE_PHRASE = "this message is permanent"


# ── valid proof => permanence printed --------------------------------------

class TestValidProofPrintsPermanence(unittest.TestCase):

    def test_valid_proof_prints_permanence(self):
        from messagechain import cli as cli_mod

        tx_hash_hex, merkle_root_hex, proof_dict = _build_real_proof_against_root()

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 14600}}
            if method == "get_tx_status":
                return {"ok": True, "result": _included_response(
                    tx_hash_hex, merkle_root_hex, proof_dict,
                )}
            return {"ok": False, "error": f"unexpected method {method}"}

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(tx_hash_hex))

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(
            _PERMANENCE_PHRASE, out.lower(),
            f"valid proof must surface permanence text; got:\n{out}",
        )
        # No WARNING about an invalid / missing proof.
        self.assertNotIn(
            "warning", out.lower(),
            f"valid proof must NOT trigger a WARNING; got:\n{out}",
        )


# ── invalid proof => warning, no permanence --------------------------------

class TestInvalidProofDoesNotPrintPermanence(unittest.TestCase):

    def test_invalid_proof_does_not_print_permanence(self):
        from messagechain import cli as cli_mod

        tx_hash_hex, merkle_root_hex, proof_dict = _build_real_proof_against_root()
        # Tamper with a sibling -- the proof no longer verifies.
        proof_dict = dict(proof_dict)
        proof_dict["siblings"] = list(proof_dict["siblings"])
        proof_dict["siblings"][0] = "ff" * 32

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 14600}}
            if method == "get_tx_status":
                return {"ok": True, "result": _included_response(
                    tx_hash_hex, merkle_root_hex, proof_dict,
                )}
            return {"ok": False, "error": f"unexpected method {method}"}

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(tx_hash_hex))

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(
            "warning", out.lower(),
            f"invalid proof must surface WARNING; got:\n{out}",
        )
        self.assertNotIn(
            _PERMANENCE_PHRASE, out.lower(),
            f"invalid proof must NOT print permanence text; got:\n{out}",
        )


# ── missing proof => warning, no permanence --------------------------------

class TestMissingProofDoesNotPrintPermanence(unittest.TestCase):

    def test_missing_proof_does_not_print_permanence(self):
        from messagechain import cli as cli_mod

        tx_hash_hex, merkle_root_hex, proof_dict = _build_real_proof_against_root()
        # Strip the proof entirely.
        included = _included_response(tx_hash_hex, merkle_root_hex, proof_dict)
        included.pop("merkle_proof")

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 14600}}
            if method == "get_tx_status":
                return {"ok": True, "result": included}
            return {"ok": False, "error": f"unexpected method {method}"}

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(tx_hash_hex))

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(
            "warning", out.lower(),
            f"missing proof must surface WARNING; got:\n{out}",
        )
        self.assertNotIn(
            _PERMANENCE_PHRASE, out.lower(),
            f"missing proof must NOT print permanence text; got:\n{out}",
        )


# ── cross-check disagreement => warning, no permanence --------------------

class TestCrossCheckServerDisagreement(unittest.TestCase):

    def test_cross_check_server_disagreement_does_not_print_permanence(self):
        from messagechain import cli as cli_mod

        tx_hash_hex, merkle_root_hex, proof_dict = _build_real_proof_against_root()
        # Cross-check returns a DIFFERENT root for the same tx.  This
        # is the colluding-primary attack.
        forged_root_hex = "ee" * 32

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 14600}}
            if method == "get_tx_status":
                if host == "10.1.1.1":
                    # Cross-check server -- returns a divergent root.
                    return {"ok": True, "result": _included_response(
                        tx_hash_hex, forged_root_hex, proof_dict,
                    )}
                # Primary server.
                return {"ok": True, "result": _included_response(
                    tx_hash_hex, merkle_root_hex, proof_dict,
                )}
            return {"ok": False, "error": f"unexpected method {method}"}

        # Two different parse_server calls -- primary + cross-check.
        def parse_side(s):
            if s == "10.1.1.1:9334":
                return ("10.1.1.1", 9334)
            return ("127.0.0.1", 9334)

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server", side_effect=parse_side):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(
                    tx_hash_hex, cross_check_server="10.1.1.1:9334",
                ))

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(
            "warning", out.lower(),
            f"cross-check disagreement must surface WARNING; got:\n{out}",
        )
        self.assertNotIn(
            _PERMANENCE_PHRASE, out.lower(),
            f"cross-check disagreement must NOT print permanence; got:\n{out}",
        )


# ── cross-check agreement => permanence + confidence line -----------------

class TestCrossCheckServerAgreement(unittest.TestCase):

    def test_cross_check_server_agreement_prints_confidence_line(self):
        from messagechain import cli as cli_mod

        tx_hash_hex, merkle_root_hex, proof_dict = _build_real_proof_against_root()

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 14600}}
            if method == "get_tx_status":
                # Both primary AND cross-check return the same root.
                return {"ok": True, "result": _included_response(
                    tx_hash_hex, merkle_root_hex, proof_dict,
                )}
            return {"ok": False, "error": f"unexpected method {method}"}

        def parse_side(s):
            if s == "10.1.1.1:9334":
                return ("10.1.1.1", 9334)
            return ("127.0.0.1", 9334)

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server", side_effect=parse_side):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(
                    tx_hash_hex, cross_check_server="10.1.1.1:9334",
                ))

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(
            _PERMANENCE_PHRASE, out.lower(),
            f"cross-check agreement must print permanence; got:\n{out}",
        )
        # The confidence line names the cross-check server.
        self.assertIn(
            "independently verified", out.lower(),
            f"cross-check agreement must surface 'Independently verified' "
            f"confidence line; got:\n{out}",
        )
        self.assertIn(
            "10.1.1.1", out,
            f"confidence line must name the cross-check server; got:\n{out}",
        )


# ── default (no cross-check) => softer caveat -----------------------------

class TestDefaultNoCrossCheck(unittest.TestCase):

    def test_default_no_cross_check_prints_softer_caveat(self):
        from messagechain import cli as cli_mod

        tx_hash_hex, merkle_root_hex, proof_dict = _build_real_proof_against_root()

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 14600}}
            if method == "get_tx_status":
                return {"ok": True, "result": _included_response(
                    tx_hash_hex, merkle_root_hex, proof_dict,
                )}
            return {"ok": False, "error": f"unexpected method {method}"}

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                # cross_check_server=None (the default)
                rc = cli_mod.cmd_receipt(_receipt_args(tx_hash_hex))

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(
            _PERMANENCE_PHRASE, out.lower(),
            "default no-cross-check path must still print permanence on a "
            "valid proof",
        )
        # The softer caveat names the flag the user could pass to
        # confirm independently.
        self.assertIn(
            "--cross-check-server", out,
            "default path must surface the --cross-check-server flag as "
            "an actionable next step",
        )


# ── parser registration --------------------------------------------------

class TestReceiptParserAcceptsCrossCheckServer(unittest.TestCase):

    def test_receipt_accepts_cross_check_server(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        ns = parser.parse_args([
            "receipt", "ab" * 32,
            "--cross-check-server", "10.1.1.1:9334",
        ])
        self.assertEqual(ns.cross_check_server, "10.1.1.1:9334")


if __name__ == "__main__":
    unittest.main()
