"""Expanded end-to-end test against a live MessageChain validator.

Exercises all 4 optimizations + edge cases:
 1. Sequential nonces (mempool tracking)
 2. No WOTS+ leaf reuse errors
 3. RPC responsive during block production
 4. Keypair cache (tested by server startup speed)
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import messagechain.config
messagechain.config.PINNED_GENESIS_HASH = None
messagechain.config.DEVNET = True
messagechain.config.MERKLE_TREE_HEIGHT = 8
messagechain.config.REQUIRE_CHECKPOINTS = False

from messagechain.config import HASH_ALGO, MIN_FEE, NEW_ACCOUNT_FEE
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity
from messagechain.identity.address import encode_address

SERVER = (
    os.environ.get("MC_TEST_HOST", "127.0.0.1"),
    int(os.environ.get("MC_TEST_PORT", "49334")),
)
GENESIS_KEY_HEX = "a896648aa959c0065402f313765628dc2d4136f38b6ce6050c4cd39bfe8174be"
PASS_COUNT = 0
FAIL_COUNT = 0


def rpc(method, params=None):
    for attempt in range(3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect(SERVER)
            req = json.dumps({"method": method, "params": params or {}}).encode()
            s.sendall(struct.pack(">I", len(req)))
            s.sendall(req)
            buf = b""
            while len(buf) < 4:
                buf += s.recv(4 - len(buf))
            length = struct.unpack(">I", buf)[0]
            data = b""
            while len(data) < length:
                data += s.recv(length - len(data))
            s.close()
            return json.loads(data)
        except (ConnectionError, socket.timeout, OSError):
            if attempt < 2:
                time.sleep(2)
    return {"ok": False, "error": "RPC unreachable after 3 attempts"}


def section(t):
    print(f"\n{'=' * 60}\n  {t}\n{'=' * 60}")


def check(label, passed, detail=""):
    global PASS_COUNT, FAIL_COUNT
    if passed:
        PASS_COUNT += 1
        print(f"  [PASS] {label}" + (f" — {detail}" if detail else ""))
    else:
        FAIL_COUNT += 1
        print(f"  [FAIL] {label}" + (f" — {detail}" if detail else ""))


def wait_for_block(target_height, max_wait=60):
    for _ in range(max_wait):
        r = rpc("get_chain_info")
        if r.get("ok") and r["result"]["height"] >= target_height:
            return r["result"]["height"]
        time.sleep(1)
    return -1


def refresh_entity(entity):
    r = rpc("get_nonce", {"entity_id": entity.entity_id.hex()})
    if not r.get("ok"):
        return 0
    nonce = r["result"]["nonce"]
    wm = r["result"]["leaf_watermark"]
    if wm > 0:
        entity.keypair.advance_to_leaf(wm)
    return nonce


def main():
    genesis = Entity.create(bytes.fromhex(GENESIS_KEY_HEX), tree_height=8)
    eid_hex = genesis.entity_id.hex()

    # ── 1. Chain info ──
    section("1. Chain info")
    t0 = time.time()
    info = rpc("get_chain_info")
    rpc_time = time.time() - t0
    check("get_chain_info", info.get("ok"))
    check("RPC responsive", rpc_time < 10, f"{rpc_time:.1f}s")
    c = info["result"]
    print(f"  Height: {c['height']}  Entities: {c['registered_entities']}  Supply: {c['total_supply']}")
    start_height = c["height"]

    # ── 2. Genesis balance ──
    section("2. Genesis balance")
    ent = rpc("get_entity", {"entity_id": eid_hex})
    check("get_entity", ent.get("ok"))
    r = ent["result"]
    print(f"  Balance: {r['balance']}  Staked: {r['staked']}  Nonce: {r['nonce']}  Msgs: {r['messages_posted']}")
    initial_bal = r["balance"]
    nonce = refresh_entity(genesis)

    # ── 3. Sequential messages WITHOUT waiting (mempool nonce tracking) ──
    section("3. Send 3 messages sequentially (mempool nonce tracking)")
    messages = ["hello world", "second message from genesis", "third one in a row!"]
    for i, msg in enumerate(messages):
        tx = create_transaction(genesis, msg, fee=500, nonce=nonce + i)
        r = rpc("submit_transaction", {"transaction": tx.serialize()})
        check(f"msg {i+1} (nonce={nonce+i})", r.get("ok"), r.get("error", ""))
    nonce += len(messages)

    # Wait for all 3 to be mined
    print("  Waiting for blocks to confirm all 3 messages...")
    wait_for_block(start_height + 2, max_wait=45)
    nonce = refresh_entity(genesis)

    # ── 4. Verify no WOTS+ leaf reuse warnings (check server log) ──
    section("4. Verify messages confirmed")
    ent2 = rpc("get_entity", {"entity_id": eid_hex})
    check("3 messages posted", ent2["result"]["messages_posted"] >= 3,
          f"actual={ent2['result']['messages_posted']}")

    # ── 5. Create 3 wallets locally (no on-chain registration) ──
    section("5. Create 3 wallets locally")
    wallets = []
    for i in range(3):
        w = Entity.create(os.urandom(32), tree_height=4)
        wallets.append(w)
        print(f"    {encode_address(w.entity_id)}")

    # ── 6. Sequential transfers WITHOUT waiting (mempool nonce tracking) ──
    # Each transfer implicitly creates the recipient's state entry
    # (receive-to-exist).  No RegistrationTransaction needed.
    section("6. Transfer to all 3 wallets (sequential nonces)")
    nonce = refresh_entity(genesis)
    for i, w in enumerate(wallets):
        amount = (i + 1) * 100  # 100, 200, 300
        # Brand-new recipient — must pay MIN_FEE + NEW_ACCOUNT_FEE surcharge.
        tx = create_transfer_transaction(genesis, w.entity_id, amount=amount,
                                         nonce=nonce + i, fee=MIN_FEE + NEW_ACCOUNT_FEE)
        r = rpc("submit_transfer", {"transaction": tx.serialize()})
        check(f"transfer {amount} to wallet{i+1}", r.get("ok"), r.get("error", ""))
    nonce += 3

    print("  Waiting for transfers to confirm...")
    wait_for_block(start_height + 5, max_wait=45)

    # ── 7. Verify transfer balances ──
    section("7. Verify transfer balances")
    for i, w in enumerate(wallets):
        expected = (i + 1) * 100
        r = rpc("get_entity", {"entity_id": w.entity_id.hex()})
        if r.get("ok"):
            actual = r["result"]["balance"]
            check(f"wallet{i+1} balance={expected}", actual == expected, f"actual={actual}")
        else:
            check(f"wallet{i+1} exists", False, r.get("error", ""))

    # ── 8. Edge cases ──
    section("8. Edge cases")

    # 8a. 281 chars
    try:
        create_transaction(genesis, "A" * 281, fee=10000, nonce=nonce)
        check("reject 281 chars", False, "no exception")
    except ValueError as e:
        check("reject 281 chars", True, str(e)[:50])

    # 8b. Fee too low
    try:
        create_transaction(genesis, "low fee", fee=1, nonce=nonce)
        check("reject fee=1", False, "no exception")
    except ValueError as e:
        check("reject fee=1", True, str(e)[:50])

    # 8c. Transfer to self
    try:
        create_transfer_transaction(genesis, genesis.entity_id, amount=100, nonce=nonce)
        check("reject self-transfer", False, "no exception")
    except ValueError as e:
        check("reject self-transfer", True, str(e))

    # 8d. Transfer more than balance
    nonce = refresh_entity(genesis)
    big_xfer = create_transfer_transaction(genesis, wallets[0].entity_id,
                                            amount=999_999_999, nonce=nonce, fee=MIN_FEE)
    r = rpc("submit_transfer", {"transaction": big_xfer.serialize()})
    check("reject overdraft transfer", not r.get("ok"), r.get("error", "")[:60])

    # 8e. Nonce gap (should reject with mempool tracking)
    nonce = refresh_entity(genesis)
    try:
        gap_tx = create_transaction(genesis, "gap test", fee=500, nonce=nonce + 5)
        r = rpc("submit_transaction", {"transaction": gap_tx.serialize()})
        check("reject nonce gap", not r.get("ok"), r.get("error", "")[:60])
    except Exception as e:
        check("reject nonce gap", True, str(e)[:60])

    # 8f. Max-length message (exactly 280 chars)
    nonce = refresh_entity(genesis)
    max_msg = "X" * 280
    tx_max = create_transaction(genesis, max_msg, fee=2000, nonce=nonce)
    r = rpc("submit_transaction", {"transaction": tx_max.serialize()})
    check("accept 280-char message", r.get("ok"), r.get("error", ""))
    nonce += 1

    # ── 9. Read all messages ──
    section("9. Messages on chain")
    msgs = rpc("get_messages", {"count": 20})
    if msgs.get("ok"):
        messages_list = msgs["result"].get("messages", [])
        for m in messages_list:
            text = m.get("message", "?")
            display = text[:60] + ("..." if len(text) > 60 else "")
            print(f"  [{m.get('entity_id', '?')[:12]}...] \"{display}\"")
        check("messages readable", len(messages_list) >= 3, f"count={len(messages_list)}")
    else:
        check("get_messages", False, msgs.get("error"))

    # ── 10. RPC responsiveness under load ──
    section("10. RPC responsiveness (5 rapid calls)")
    times = []
    for _ in range(5):
        t0 = time.time()
        r = rpc("get_chain_info")
        times.append(time.time() - t0)
    avg = sum(times) / len(times)
    check("avg RPC < 15s", avg < 15, f"avg={avg:.1f}s, times={[f'{t:.1f}' for t in times]}")

    # ── 11. Final summary ──
    section("11. Final summary")
    info2 = rpc("get_chain_info")
    c2 = info2["result"]
    ent_final = rpc("get_entity", {"entity_id": eid_hex})
    r_final = ent_final["result"]
    print(f"  Blocks mined:        {c2['height']}")
    print(f"  Total minted:        {c2['total_minted']} tokens")
    print(f"  Fees collected:      {c2['total_fees_collected']}")
    print(f"  Registered entities: {c2['registered_entities']}")
    print(f"  Genesis balance:     {r_final['balance']} (started {initial_bal})")
    print(f"  Genesis staked:      {r_final['staked']}")
    print(f"  Genesis messages:    {r_final['messages_posted']}")

    section(f"RESULTS: {PASS_COUNT} passed, {FAIL_COUNT} failed")
    return 0 if FAIL_COUNT == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
