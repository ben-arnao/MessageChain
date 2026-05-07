"""
Regression pin for the CLAUDE.md "no protocol-level encrypted message
types" anchor.

Settled Design Decisions: "Payloads are fully public.  Hard no, ever
on protocol-level encrypted message types.  Encryption is strictly
a user/app-layer concern."

A "Phase 1 threshold-RSA primitive for MessageChain's encrypted
mempool" module previously sat under ``messagechain/crypto/`` with
no production callers but with phased-deployment language inviting
a future contributor to wire Phase 2/3/4 (DKG, on-chain wire
format, hybrid RSA+AES).  Audit r35 #1 deleted it because half-
paved-road code in ``crypto/`` undermines the anchor at the code
level: someone reading the tree sees the module and treats the
anchor as soft.

These tests pin the deletion: re-adding any protocol-level
decryption primitive into the tree should trip them immediately.
"""

import importlib
import pathlib

import pytest


_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_threshold_rsa_module_file_absent():
    """The threshold-RSA file must not return to the tree."""
    candidate = _REPO_ROOT / "messagechain" / "crypto" / "threshold_rsa.py"
    assert not candidate.exists(), (
        f"{candidate} re-introduced.  CLAUDE.md anchors a 'Hard no, "
        "ever' on protocol-level encrypted message types; a Phase-1 "
        "decryption primitive in the crypto/ namespace contradicts "
        "the anchor even when no production code imports it.  Delete "
        "the file or revisit the anchor explicitly in CLAUDE.md."
    )


def test_threshold_rsa_module_not_importable():
    """``import messagechain.crypto.threshold_rsa`` must fail."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("messagechain.crypto.threshold_rsa")


def test_no_protocol_decryption_module_in_crypto_namespace():
    """No file under ``messagechain/crypto/`` may carry the encrypted-
    mempool / threshold-decryption shape.

    We grep for the load-bearing phrase the deleted module used in
    its docstring rather than a generic 'encrypt' substring (the
    project legitimately uses encryption at the user/app layer for
    keystore at-rest protection, etc.).
    """
    crypto_dir = _REPO_ROOT / "messagechain" / "crypto"
    forbidden_phrases = (
        "encrypted mempool",
        "threshold decryption",
        "threshold-rsa primitive",
    )
    offenders = []
    for path in crypto_dir.rglob("*.py"):
        body = path.read_text(encoding="utf-8", errors="replace").lower()
        for phrase in forbidden_phrases:
            if phrase in body:
                offenders.append((str(path), phrase))
                break
    assert not offenders, (
        "Files under messagechain/crypto/ describe protocol-level "
        f"decryption primitives: {offenders}.  CLAUDE.md anchors a "
        "'Hard no, ever' on protocol-level encrypted message types; "
        "encryption is strictly a user/app-layer concern."
    )
