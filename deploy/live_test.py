"""Comprehensive live validator test — exercises all user flows + edge cases."""

from __future__ import annotations
import hashlib, json, os, socket, struct, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import messagechain.config
messagechain.config.PINNED_GENESIS_HASH = None
messagechain.config.DEVNET = True
messagechain.config.MERKLE_TREE_HEIGHT = 16
messagechain.config.REQUIRE_CHECKPOINTS = False

from messagechain.config import HASH_ALGO, MIN_FEE
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.core.staking import create_stake_transaction, create_unstake_transaction
from messagechain.identity.identity import Entity
from messagechain.identity.address import encode_address

SERVER = (os.environ.get("MC_HOST", "35.237.211.12"), int(os.environ.get("MC_PORT", "9334")))
GEN_KEY = "a896648aa959c0065402f313765628dc2d4136f38b6ce6050c4cd39bfe8174be"
P, F = 0, 0


def rpc(method, params=None):
    for _ in range(3):
        try:
            s = socket.socket(); s.settimeout(30); s.connect(SERVER)
            req = json.dumps({"method": method, "params": params or {}}).encode()
            s.sendall(struct.pack(">I", len(req))); s.sendall(req)
            b = b""
            while len(b) < 4: b += s.recv(4 - len(b))
            ln = struct.unpack(">I", b)[0]; d = b""
            while len(d) < ln: d += s.recv(ln - len(d))
            s.close(); return json.loads(d)
        except Exception:
            time.sleep(1)
    return {"ok": False, "error": "unreachable"}


def ok(label, r):
    global P, F
    if r.get("ok"): P += 1; print(f"  [PASS] {label}")
    else: F += 1; print(f"  [FAIL] {label} -- {r.get('error', '?')}")
    return r.get("ok")


def chk(label, cond, detail=""):
    global P, F
    if cond: P += 1; print(f"  [PASS] {label}" + (f" -- {detail}" if detail else ""))
    else: F += 1; print(f"  [FAIL] {label}" + (f" -- {detail}" if detail else ""))


def wait_block(h, mx=120):
    for _ in range(mx):
        r = rpc("get_chain_info")
        if r.get("ok") and r["result"]["height"] >= h: return r["result"]["height"]
        time.sleep(1)
    return -1


def refresh(e):
    r = rpc("get_nonce", {"entity_id": e.entity_id.hex()})
    if not r.get("ok"): return 0
    wm = r["result"]["leaf_watermark"]
    if wm > 0: e.keypair.advance_to_leaf(wm)
    return r["result"]["nonce"]


def sec(t):
    print(f"\n{'=' * 60}\n  {t}\n{'=' * 60}")


def main():
    print("Generating genesis entity (tree_height=16, ~105s)...")
    t0 = time.time()
    gen = Entity.create(bytes.fromhex(GEN_KEY), tree_height=16)
    print(f"Done in {time.time() - t0:.0f}s")

    # ── 1. Chain info + genesis status ──
    sec("1. Chain info + genesis wallet")
    info = rpc("get_chain_info"); ok("get_chain_info", info)
    c = info["result"]
    print(f"  Height: {c['height']}  Minted: {c['total_minted']}  Fees: {c['total_fees_collected']}  Entities: {c['registered_entities']}")
    start_h = c["height"]

    ent = rpc("get_entity", {"entity_id": gen.entity_id.hex()})
    ok("genesis entity", ent)
    g = ent["result"]
    print(f"  Public address:   {encode_address(gen.entity_id)}")
    print(f"  Entity ID:        {gen.entity_id.hex()}")
    print(f"  Balance (liquid): {g['balance']}")
    print(f"  Staked:           {g['staked']}")
    print(f"  Nonce:            {g['nonce']}")
    print(f"  Messages posted:  {g['messages_posted']}")
    nonce = refresh(gen)

    # ── 2. New user creates wallet from scratch ──
    # Receive-to-exist: no on-chain registration step.  The user's
    # entity materializes when genesis funds them; the user's first
    # outgoing transfer reveals their pubkey to the chain.
    sec("2. New user: create wallet from scratch")
    user_key = os.urandom(32)
    user = Entity.create(user_key, tree_height=4)
    print(f"  Generated key: {user_key.hex()[:16]}... (tree_height=4, instant)")
    print(f"  Address: {encode_address(user.entity_id)}")

    tx = create_transfer_transaction(gen, user.entity_id, amount=5000, nonce=nonce, fee=MIN_FEE)
    r = rpc("submit_transfer", {"transaction": tx.serialize()})
    ok("fund user with 5000 tokens (implicit account creation)", r)
    nonce += 1
    print("  Waiting for transfer to confirm...")
    wait_block(start_h + 1)

    # ── 3. User does a first outgoing transfer (reveals pubkey) ──
    # Other tx types (message, stake) require pubkey to be on chain
    # already, so the user must spend via Transfer first.
    sec("3. First outgoing transfer from user (installs pubkey on chain)")
    un = refresh(user)
    tx = create_transfer_transaction(
        user, gen.entity_id, amount=10, nonce=un, fee=MIN_FEE,
        include_pubkey=True,
    )
    r = rpc("submit_transfer", {"transaction": tx.serialize()})
    ok("user -> genesis (10, first-spend pubkey reveal)", r)
    un += 1
    print("  Waiting for pubkey install...")
    wait_block(start_h + 2)

    # ── 4. New user sends messages ──
    sec("4. New user sends messages")
    user_msgs = ["gm everyone!", "just joined MessageChain", "testing 1 2 3"]
    for i, m in enumerate(user_msgs):
        tx = create_transaction(user, m, fee=500, nonce=un + i)
        r = rpc("submit_transaction", {"transaction": tx.serialize()})
        ok(f'user msg {i+1}: "{m}"', r)
    un += len(user_msgs)
    print("  Waiting for block...")
    wait_block(start_h + 3)

    # ── 4. Bad actor scenarios ──
    sec("4. Bad actor scenarios")
    nonce = refresh(gen)

    # 4a. Replay attack
    tx_replay = create_transaction(gen, "replay test", fee=500, nonce=nonce)
    r1 = rpc("submit_transaction", {"transaction": tx_replay.serialize()})
    ok("first submit (legit)", r1)
    r2 = rpc("submit_transaction", {"transaction": tx_replay.serialize()})
    chk("reject replay (same tx)", not r2.get("ok"), r2.get("error", "")[:60])
    nonce += 1

    # 4b. Tampered message (forged signature)
    nonce = refresh(gen)
    tx_forged = create_transaction(gen, "forged sig", fee=500, nonce=nonce)
    ser = tx_forged.serialize()
    ser["message"] = "TAMPERED MESSAGE"
    r = rpc("submit_transaction", {"transaction": ser})
    chk("reject tampered message", not r.get("ok"), r.get("error", "")[:60])

    # 4c. Transfer more than balance
    tx_over = create_transfer_transaction(gen, user.entity_id, amount=999_999_999, nonce=nonce, fee=MIN_FEE)
    r = rpc("submit_transfer", {"transaction": tx_over.serialize()})
    chk("reject overdraft", not r.get("ok"), r.get("error", "")[:60])

    # 4d. Non-ASCII
    try:
        create_transaction(gen, "hello \u00e9\u00e8", fee=500, nonce=nonce)
        chk("reject non-ASCII", False, "no exception")
    except (ValueError, UnicodeEncodeError) as e:
        chk("reject non-ASCII", True, str(e)[:50])

    # 4e. Negative transfer
    try:
        create_transfer_transaction(gen, user.entity_id, amount=-100, nonce=nonce)
        chk("reject negative transfer", False)
    except ValueError as e:
        chk("reject negative transfer", True, str(e))

    # 4f. Zero transfer
    try:
        create_transfer_transaction(gen, user.entity_id, amount=0, nonce=nonce)
        chk("reject zero transfer", False)
    except ValueError as e:
        chk("reject zero transfer", True, str(e))

    # 4g. Dust transfer (below DUST_LIMIT=10)
    tx_dust = create_transfer_transaction(gen, user.entity_id, amount=5, nonce=nonce, fee=MIN_FEE)
    r = rpc("submit_transfer", {"transaction": tx_dust.serialize()})
    chk("reject dust transfer (5 < 10)", not r.get("ok"), r.get("error", "")[:60])

    print("  Waiting for block...")
    wait_block(start_h + 4)

    # ── 5. Transfer funds around ──
    # Receive-to-exist: wallet3 materializes implicitly when funded.
    sec("5. Transfer funds around")
    nonce = refresh(gen)
    w3 = Entity.create(os.urandom(32), tree_height=4)
    print(f"  Wallet3: {encode_address(w3.entity_id)}")

    tx = create_transfer_transaction(gen, w3.entity_id, amount=1000, nonce=nonce, fee=MIN_FEE)
    r = rpc("submit_transfer", {"transaction": tx.serialize()})
    ok("genesis -> wallet3 (1000, implicit account creation)", r)
    nonce += 1
    wait_block(start_h + 5)

    un = refresh(user)
    tx = create_transfer_transaction(user, w3.entity_id, amount=200, nonce=un, fee=MIN_FEE)
    r = rpc("submit_transfer", {"transaction": tx.serialize()})
    ok("user -> wallet3 (200)", r)
    wait_block(start_h + 6)

    for label, eid in [("Genesis", gen.entity_id), ("User", user.entity_id), ("Wallet3", w3.entity_id)]:
        r = rpc("get_entity", {"entity_id": eid.hex()})
        if r.get("ok"):
            d = r["result"]
            print(f"  {label}: bal={d['balance']} stake={d['staked']} nonce={d['nonce']} msgs={d['messages_posted']}")

    # ── 6. Stake + unstake ──
    sec("6. Stake + unstake")
    nonce = refresh(gen)
    tx = create_stake_transaction(gen, amount=10000, nonce=nonce, fee=MIN_FEE)
    r = rpc("stake", {"transaction": tx.serialize()})
    ok("stake 10000", r)
    nonce += 1
    wait_block(start_h + 8)

    r = rpc("get_entity", {"entity_id": gen.entity_id.hex()})
    if r.get("ok"):
        g2 = r["result"]
        chk("stake reflected", g2["staked"] >= 60000, f"staked={g2['staked']}")
        print(f"  After stake: bal={g2['balance']} staked={g2['staked']}")
    else:
        chk("stake reflected", False, f"get_entity failed: {r.get('error', '?')}")
        g2 = {"staked": 0, "balance": 0}

    nonce = refresh(gen)
    tx = create_unstake_transaction(gen, amount=5000, nonce=nonce, fee=MIN_FEE)
    r = rpc("unstake", {"transaction": tx.serialize()})
    ok("unstake 5000", r)
    nonce += 1
    wait_block(start_h + 9)

    r = rpc("get_entity", {"entity_id": gen.entity_id.hex()})
    if r.get("ok"):
        g3 = r["result"]
        print(f"  After unstake: bal={g3['balance']} staked={g3['staked']}")
        chk("staked decreased", g3["staked"] < g2["staked"], f"was {g2['staked']}, now {g3['staked']}")
    else:
        chk("staked decreased", False, f"get_entity failed: {r.get('error', '?')}")

    # ── 7. CLI-style queries ──
    sec("7. CLI-style queries")
    vals = rpc("list_validators")
    ok("list_validators", vals)
    if vals.get("ok"):
        for v in vals["result"].get("validators", [])[:5]:
            eid = v.get("entity_id", "?")[:16]
            print(f"  Validator: {eid}... stake={v.get('stake', 0)}")

    msgs = rpc("get_messages", {"count": 20})
    ok("get_messages", msgs)
    if msgs.get("ok"):
        for m in msgs["result"].get("messages", []):
            print(f'  [{m.get("entity_id", "?")[:12]}...] "{m.get("message", "?")[:50]}"')

    fee_est = rpc("get_fee_estimate")
    ok("get_fee_estimate", fee_est)
    if fee_est.get("ok"):
        print(f"  Current fee estimate: {fee_est['result']['fee_estimate']}")

    props = rpc("list_proposals")
    ok("list_proposals", props)
    print(f"  Active proposals: {len(props.get('result', {}).get('proposals', []))}")

    # ── 8. Confirm mining rewards/fees ──
    sec("8. Confirm mining rewards + fees")
    info2 = rpc("get_chain_info")
    c2 = info2.get("result", {"total_minted": 0, "total_fees_collected": 0, "height": 0,
                               "registered_entities": 0, "current_block_reward": 0,
                               "current_base_fee": 0, "next_halving_block": 0})
    chk("total_minted > 0", c2["total_minted"] > 0, f"minted={c2['total_minted']}")
    chk("fees collected > 0", c2["total_fees_collected"] > 0, f"fees={c2['total_fees_collected']}")
    blocks_during_test = c2["height"] - start_h
    print(f"  Blocks during test: {blocks_during_test}")
    print(f"  Rewards minted this session: {blocks_during_test * 16} expected, {c2['total_minted']} total")

    # ── 9. Final report ──
    sec("9. FINAL REPORT")
    r = rpc("get_entity", {"entity_id": gen.entity_id.hex()})
    gf = r.get("result", {"balance": 0, "staked": 0, "messages_posted": 0, "nonce": 0})

    print("  === YOUR GENESIS VALIDATOR ===")
    print(f"  Public address:     {encode_address(gen.entity_id)}")
    print(f"  Entity ID:          {gen.entity_id.hex()}")
    print(f"  Liquid balance:     {gf['balance']}")
    print(f"  Staked:             {gf['staked']}")
    print(f"  Messages posted:    {gf['messages_posted']}")
    print(f"  Nonce:              {gf['nonce']}")
    print()
    print("  === CHAIN STATE ===")
    print(f"  Blocks mined:       {c2['height']}")
    print(f"  Total minted:       {c2['total_minted']} tokens")
    print(f"  Fees collected:     {c2['total_fees_collected']}")
    print(f"  Registered entities: {c2['registered_entities']}")
    print(f"  Block reward:       {c2['current_block_reward']} tokens/block")
    print(f"  Base fee:           {c2['current_base_fee']}")
    print(f"  Next halving:       block {c2['next_halving_block']}")
    print()
    print("  === NETWORK ===")
    print("  P2P: 35.237.211.12:9333")
    print("  RPC: 35.237.211.12:9334")

    sec(f"RESULTS: {P} passed, {F} failed")
    return 0 if F == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
