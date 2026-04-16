"""Core Bitcoin anchoring logic — compute, build, submit, and verify anchors.

Anchoring is an OPERATIONAL task performed by willing validators, not a
consensus rule. Any validator can submit an anchor; the protocol does not
require it. MessageChain must never halt if Bitcoin is unavailable.

The raw Bitcoin tx builder here is NOT security-critical for MessageChain.
It IS security-critical for the Bitcoin UTXO being spent, which is the
operator's responsibility. The builder constructs the simplest possible
Bitcoin transaction: 1 input (UTXO), 1 OP_RETURN output (anchor data),
1 change output. No full wallet logic.
"""

import hashlib
import struct
from dataclasses import dataclass

from messagechain.config import (
    ANCHOR_DOMAIN_TAG,
    ANCHOR_INTERVAL,
    ANCHOR_OP_RETURN_PREFIX,
)


# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------

def compute_anchor_hash(
    block_hash: bytes,
    block_number: int,
    state_root: bytes,
) -> bytes:
    """Compute the 32-byte anchor hash committed to Bitcoin via OP_RETURN.

    anchor_hash = SHA-256(ANCHOR_DOMAIN_TAG + block_hash + block_number_be64 + state_root)

    Domain-tagged to prevent collision with other OP_RETURN data.
    Version-tagged (V1 in the domain tag) for crypto agility.
    Uses SHA-256 (not SHA3) because the anchor lives on Bitcoin and
    SHA-256 is Bitcoin's native hash — keeping one hash family simplifies
    cross-chain verification tooling.
    """
    return hashlib.sha256(
        ANCHOR_DOMAIN_TAG
        + block_hash
        + struct.pack(">Q", block_number)
        + state_root
    ).digest()


def should_anchor_block(
    block_number: int,
    finalized_heights: set[int],
    last_anchored: int,
) -> bool:
    """Decide whether a block should be anchored.

    Rules:
    1. Block must be at an ANCHOR_INTERVAL boundary (block_number % ANCHOR_INTERVAL == 0)
    2. Block must be finalized (present in finalized_heights)
    3. Block must not have been anchored already (block_number > last_anchored)
    """
    if block_number % ANCHOR_INTERVAL != 0:
        return False
    if block_number not in finalized_heights:
        return False
    if block_number <= last_anchored:
        return False
    return True


# ---------------------------------------------------------------------------
# Bitcoin transaction builder (minimal OP_RETURN tx)
# ---------------------------------------------------------------------------

def build_anchor_tx_hex(anchor_hash: bytes, utxo: dict) -> str:
    """Build a raw Bitcoin transaction hex with an OP_RETURN output.

    This constructs the simplest possible Bitcoin tx:
    - 1 input: the provided UTXO
    - Output 0: OP_RETURN with MC prefix + anchor_hash (0 satoshis)
    - Output 1: change back to the same scriptPubKey (minus fee)

    The transaction is UNSIGNED — the scriptSig is left empty. The
    operator must sign it externally (e.g. via bitcoin-cli signrawtransactionwithkey)
    or use a pre-signed UTXO workflow. This keeps us out of the business
    of implementing Bitcoin signature logic (ECDSA/secp256k1).

    WARNING: This builder is NOT security-critical for MessageChain.
    It IS security-critical for the Bitcoin UTXO. The operator is
    responsible for verifying the constructed tx before broadcasting.

    Args:
        anchor_hash: 32-byte hash to commit
        utxo: dict with keys:
            txid: hex string (64 chars) of the input txid
            vout: int output index
            script_pubkey: hex string of the scriptPubKey to pay change to
            amount_satoshis: int total value of the UTXO
            privkey_hex: NOT USED for signing (signing is external).
                         Kept in the interface for forward compatibility.

    Returns:
        Hex-encoded raw Bitcoin transaction (unsigned).
    """
    ESTIMATED_TX_SIZE = 250  # bytes, conservative
    FEE_RATE_SAT_PER_BYTE = 5  # ~5 sat/byte, moderate fee
    estimated_fee = ESTIMATED_TX_SIZE * FEE_RATE_SAT_PER_BYTE

    change_amount = utxo["amount_satoshis"] - estimated_fee
    if change_amount < 0:
        raise ValueError(
            f"UTXO value {utxo['amount_satoshis']} sats is insufficient "
            f"for estimated fee {estimated_fee} sats"
        )

    parts = []

    # Version (4 bytes, little-endian)
    parts.append(struct.pack("<I", 1))

    # Input count (varint)
    parts.append(b"\x01")

    # Input: prev txid (32 bytes, reversed for Bitcoin's internal byte order)
    prev_txid = bytes.fromhex(utxo["txid"])
    parts.append(prev_txid[::-1])

    # Input: prev vout (4 bytes, little-endian)
    parts.append(struct.pack("<I", utxo["vout"]))

    # Input: scriptSig (empty — unsigned tx)
    parts.append(b"\x00")  # scriptSig length = 0

    # Input: sequence (4 bytes)
    parts.append(b"\xff\xff\xff\xff")

    # Output count: 2 (OP_RETURN + change)
    parts.append(b"\x02")

    # Output 0: OP_RETURN (value = 0)
    parts.append(struct.pack("<Q", 0))  # 0 satoshis
    op_return_data = ANCHOR_OP_RETURN_PREFIX + anchor_hash
    # scriptPubKey: OP_RETURN <push data>
    # OP_RETURN = 0x6a, then OP_PUSHDATA with length prefix
    op_return_script = b"\x6a" + bytes([len(op_return_data)]) + op_return_data
    parts.append(bytes([len(op_return_script)]))  # script length
    parts.append(op_return_script)

    # Output 1: change
    parts.append(struct.pack("<Q", change_amount))
    change_script = bytes.fromhex(utxo["script_pubkey"])
    parts.append(bytes([len(change_script)]))
    parts.append(change_script)

    # Locktime (4 bytes)
    parts.append(struct.pack("<I", 0))

    return b"".join(parts).hex()


# ---------------------------------------------------------------------------
# Submission and verification (operational, uses Bitcoin RPC)
# ---------------------------------------------------------------------------

def submit_anchor(raw_tx_hex: str, bitcoin_rpc_url: str) -> str:
    """Submit a raw Bitcoin transaction via sendrawtransaction RPC.

    Returns the Bitcoin txid on success.
    Raises RuntimeError if Bitcoin Core rejects the transaction.
    """
    from messagechain.anchoring.bitcoin_rpc import bitcoin_rpc_call

    response = bitcoin_rpc_call(
        bitcoin_rpc_url,
        "sendrawtransaction",
        [raw_tx_hex],
    )

    if "error" in response and response["error"] is not None:
        err = response["error"]
        raise RuntimeError(
            f"Bitcoin RPC rejected transaction: "
            f"code={err.get('code')}, message={err.get('message')}"
        )

    return response["result"]


def verify_anchor(
    expected_anchor_hash: bytes,
    btc_txid: str,
    bitcoin_rpc_url: str,
) -> bool:
    """Verify that a Bitcoin transaction contains the expected anchor hash.

    Fetches the decoded tx via getrawtransaction (verbose=true) and
    checks every output for an OP_RETURN containing MC_PREFIX + anchor_hash.

    Returns True if a matching OP_RETURN output is found, False otherwise.
    """
    from messagechain.anchoring.bitcoin_rpc import bitcoin_rpc_call

    response = bitcoin_rpc_call(
        bitcoin_rpc_url,
        "getrawtransaction",
        [btc_txid, True],
    )

    tx_data = response.get("result", {})
    expected_data = (ANCHOR_OP_RETURN_PREFIX + expected_anchor_hash).hex()

    for vout in tx_data.get("vout", []):
        script_pub_key = vout.get("scriptPubKey", {})
        if script_pub_key.get("type") != "nulldata":
            continue
        # The asm field looks like: "OP_RETURN <hex_data>"
        asm = script_pub_key.get("asm", "")
        parts = asm.split()
        if len(parts) >= 2 and parts[0] == "OP_RETURN":
            if parts[1] == expected_data:
                return True

    return False


# ---------------------------------------------------------------------------
# Chain integrity audit
# ---------------------------------------------------------------------------

@dataclass
class AnchorVerification:
    """Result of verifying a single anchor against Bitcoin."""
    mc_block_number: int
    anchor_hash: bytes
    btc_txid: str
    passed: bool
    error: str = ""


def verify_chain_integrity(
    chaindb,
    bitcoin_rpc_url: str,
) -> list[AnchorVerification]:
    """Walk all stored anchors with btc_txid and verify each against Bitcoin.

    This is an AUDIT function, not a consensus rule. A failed verification
    is a governance alarm, not an automatic chain halt.

    Anchors without btc_txid (not yet submitted to Bitcoin) are skipped.

    Returns a list of AnchorVerification results, one per verified anchor.
    """
    anchors = chaindb.get_all_bitcoin_anchors()
    results = []

    for anchor in anchors:
        btc_txid = anchor["btc_txid"]
        if btc_txid is None:
            continue  # Not yet submitted

        anchor_hash = anchor["anchor_hash"]
        try:
            passed = verify_anchor(anchor_hash, btc_txid, bitcoin_rpc_url)
            results.append(AnchorVerification(
                mc_block_number=anchor["mc_block_number"],
                anchor_hash=anchor_hash,
                btc_txid=btc_txid,
                passed=passed,
            ))
        except Exception as e:
            results.append(AnchorVerification(
                mc_block_number=anchor["mc_block_number"],
                anchor_hash=anchor_hash,
                btc_txid=btc_txid,
                passed=False,
                error=str(e),
            ))

    return results
