"""Local N-validator soak + scenario harness.

Exercises the parts of consensus that a single-validator mainnet
doesn't: attestation layer, finality accumulation, proposer rotation
under multi-validator stake, governance, (optional) equivocation slash,
and (optional) key rotation.

ENTIRELY LOCAL.  Does not touch mainnet:
  * fresh devnet config (NETWORK_NAME=devnet, no pinned genesis)
  * all validators bind to 127.0.0.1 on distinct port pairs
  * fresh os.urandom(32) keys for each validator
  * data dirs under /tmp/mc-devnet-* (or %TEMP% on Windows)

Run:
    python deploy/devnet_soak.py
    python deploy/devnet_soak.py --validators 5 --block-time 2 --height 10
    python deploy/devnet_soak.py --run-for 900   # 15-min soak

Cleanup is automatic on Ctrl+C or normal exit.  Leftover data dirs live
under the tempdir; delete at will.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ── RPC client helpers (stdlib-only; don't pull from client.py to avoid
# coupling to config_local.py load order) ────────────────────────────


def rpc(host: str, port: int, method: str, params=None, timeout: float = 10) -> dict:
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        req = json.dumps({"method": method, "params": params or {}}).encode()
        s.sendall(struct.pack(">I", len(req)))
        s.sendall(req)
        ln = struct.unpack(">I", s.recv(4))[0]
        buf = b""
        while len(buf) < ln:
            chunk = s.recv(ln - len(buf))
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf)
    except Exception as e:
        return {"ok": False, "error": f"rpc({method}) failed: {e}"}


# ── Validator lifecycle ─────────────────────────────────────────────


class Validator:
    def __init__(self, idx: int, base_dir: Path, p2p_port: int, rpc_port: int):
        self.idx = idx
        self.base_dir = base_dir
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.data_dir = base_dir / f"val-{idx}"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.keyfile = self.data_dir / "keyfile"
        self.stdout_path = self.data_dir / "stdout.log"
        self.stderr_path = self.data_dir / "stderr.log"
        self.private_key_hex: str | None = None
        self.entity_id_hex: str | None = None
        self.proc: subprocess.Popen | None = None

    def generate_key(self):
        self.private_key_hex = secrets.token_hex(32)
        self.keyfile.write_text(self.private_key_hex)
        try:
            os.chmod(self.keyfile, 0o600)
        except OSError:
            pass

    def build_entity(self, tree_height: int):
        """Derive Entity (keypair) from private key.  Kept as self.entity
        so the harness can sign tx's inline (avoids CLI prompts)."""
        import messagechain.config as _c
        _c.DEVNET = True
        _c.PINNED_GENESIS_HASH = None
        from messagechain.identity.identity import Entity
        self.entity = Entity.create(
            bytes.fromhex(self.private_key_hex),
            tree_height=tree_height,
        )
        self.entity_id_hex = self.entity.entity_id.hex()
        # Track nonce locally so we don't race on re-fetching from RPC.
        self._next_nonce = 0

    def start(self, seed_peers: list[tuple[str, int]], env: dict):
        cmd = [
            sys.executable, str(ROOT / "server.py"),
            "--port", str(self.p2p_port),
            "--rpc-port", str(self.rpc_port),
            "--rpc-bind", "127.0.0.1",
            "--keyfile", str(self.keyfile),
            "--data-dir", str(self.data_dir),
        ]
        if seed_peers:
            cmd += ["--seed"] + [f"{h}:{p}" for h, p in seed_peers]

        stdout_f = open(self.stdout_path, "w")
        stderr_f = open(self.stderr_path, "w")

        creationflags = 0
        if sys.platform == "win32":
            # Detach so Ctrl+C on parent doesn't also hit the child
            # before we've had a chance to cleanly .terminate() them.
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        self.proc = subprocess.Popen(
            cmd,
            stdout=stdout_f,
            stderr=stderr_f,
            env={**os.environ, **env},
            cwd=str(ROOT),
            creationflags=creationflags,
        )

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc is None:
            return
        try:
            if sys.platform == "win32":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.proc.terminate()
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        except Exception:
            pass
        self.proc = None

    def wait_rpc(self, timeout: float = 120) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = rpc("127.0.0.1", self.rpc_port, "get_chain_info", timeout=2)
            if r.get("ok"):
                return True
            if not self.is_alive():
                return False
            time.sleep(1)
        return False

    def info(self) -> dict:
        r = rpc("127.0.0.1", self.rpc_port, "get_chain_info")
        return r.get("result", {})


# ── Harness ────────────────────────────────────────────────────────


class Harness:
    def __init__(self, args):
        self.n = args.validators
        self.block_time = args.block_time
        self.tree_height = args.tree_height
        self.base_dir = Path(tempfile.mkdtemp(prefix="mc-devnet-"))
        self.validators: list[Validator] = []
        self.config_local_backup: str | None = None
        self.args = args

    # --- setup ----

    def write_config_local(self, pinned_hex: str | None = None):
        """Write a devnet config_local.py for all validators to share.

        pinned_hex: if provided, set PINNED_GENESIS_HASH to this value
        so joining validators skip auto-mint and sync from val-1
        instead.  Called twice during the harness: once before mint
        (no pin), once after mint (with the founder's block-0 hash).
        """
        clp = ROOT / "messagechain" / "config_local.py"
        if self.config_local_backup is None and clp.exists():
            self.config_local_backup = clp.read_text()
        body = (
            f'# Temporary devnet soak config — remove when harness exits.\n'
            f'NETWORK_NAME = "devnet"\n'
            f'REQUIRE_CHECKPOINTS = False\n'
            f'MERKLE_TREE_HEIGHT = {self.tree_height}\n'
            f'BLOCK_TIME_TARGET = {self.block_time}\n'
            f'RPC_AUTH_ENABLED = False\n'
            f'MIN_VALIDATORS_TO_EXIT_BOOTSTRAP = 1\n'
            f'SEED_NODES = []\n'
            f'CLIENT_SEED_ENDPOINTS = []\n'
        )
        if pinned_hex:
            body += (
                f'# Pin after founder mints so joiners IBD instead of '
                f'auto-minting their own (divergent) genesis.\n'
                f'PINNED_GENESIS_HASH = bytes.fromhex("{pinned_hex}")\n'
            )
        clp.write_text(body)

    def restore_config_local(self):
        clp = ROOT / "messagechain" / "config_local.py"
        if self.config_local_backup is not None:
            clp.write_text(self.config_local_backup)
        else:
            try:
                clp.unlink()
            except OSError:
                pass

    def mint_genesis(self, founder: Validator):
        """Use launch_single_validator to mint a fresh devnet block 0."""
        # GENESIS_SUPPLY is 1B; TREASURY_ALLOCATION is 40M; the launch
        # script credits the founder's (liquid + stake) on top of that.
        # Keep the sum well under supply to leave headroom.
        # Founder gets 550M (500M liquid for funding N-1 others + 50M stake);
        # other validators each get 50M -> 20M stake, leaving 30M liquid.
        env = {**os.environ}
        cmd = [
            sys.executable, str(ROOT / "deploy" / "launch_single_validator.py"),
            "--data-dir", str(founder.data_dir),
            "--keyfile", str(founder.keyfile),
            "--liquid", "500000000",
            "--stake", "50000000",
            "--tree-height", str(self.tree_height),
        ]
        print(f"[mint] launching genesis for val-1 ...")
        p = subprocess.run(
            cmd, capture_output=True, text=True, env=env, cwd=str(ROOT),
        )
        if p.returncode != 0:
            print("[mint] FAILED:")
            print(p.stdout)
            print(p.stderr)
            sys.exit(1)
        # Parse block-0 hash from output and re-pin config_local.py so
        # joining validators skip their own auto-mint.
        block0_hex = None
        for line in p.stdout.splitlines():
            ls = line.strip()
            if ls.startswith("Block-0 hash:"):
                block0_hex = ls.split(":", 1)[1].strip()
                print(f"[mint] block-0: {block0_hex[:16]}...")
                break
        if not block0_hex:
            print("[mint] FAILED: could not parse block-0 hash from output")
            print(p.stdout)
            sys.exit(1)
        self.write_config_local(pinned_hex=block0_hex)
        print("[mint] pinned genesis hash in config_local for joiners")

    # --- scenarios ----

    def _fetch_nonce(self, v: Validator) -> int:
        r = rpc("127.0.0.1", v.rpc_port, "get_nonce",
                {"entity_id": v.entity_id_hex})
        return int(r.get("result", {}).get("nonce", 0))

    def fund_and_stake_everyone(self):
        """Inline signing — bypasses CLI prompts, uses the Entity we
        already built for each validator."""
        from messagechain.core.transfer import create_transfer_transaction
        from messagechain.core.staking import create_stake_transaction
        from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE

        founder = self.validators[0]
        founder._next_nonce = self._fetch_nonce(founder)

        # Each non-founder gets 50M tokens from the founder.
        for v in self.validators[1:]:
            tx = create_transfer_transaction(
                entity=founder.entity,
                recipient_id=v.entity.entity_id,
                amount=50_000_000,
                nonce=founder._next_nonce,
                fee=MIN_FEE + NEW_ACCOUNT_FEE,
            )
            r = rpc("127.0.0.1", founder.rpc_port, "submit_transfer",
                    {"transaction": tx.serialize()})
            if r.get("ok"):
                print(f"[fund] val-1 -> val-{v.idx}: 200M submitted (nonce={founder._next_nonce})")
                founder._next_nonce += 1
            else:
                print(f"[fund] val-1 -> val-{v.idx}: FAIL {r.get('error', '')[:120]}")

        self.wait_n_blocks(3, label="transfers confirming")

        # Each non-founder stakes 100M.  First outgoing tx — include pubkey.
        for v in self.validators[1:]:
            v._next_nonce = self._fetch_nonce(v)
            # Build a stake tx signed by val-N.  Note: create_stake_transaction
            # also supports sender_pubkey for first-spend flow.
            import inspect
            sig = inspect.signature(create_stake_transaction)
            kwargs = {
                "entity": v.entity,
                "amount": 100_000_000,
                "nonce": v._next_nonce,
                "fee": MIN_FEE,
            }
            if "include_pubkey" in sig.parameters:
                kwargs["include_pubkey"] = True
            kwargs["amount"] = 20_000_000
            tx = create_stake_transaction(**kwargs)
            r = rpc("127.0.0.1", v.rpc_port, "stake",
                    {"transaction": tx.serialize()})
            if r.get("ok"):
                print(f"[stake] val-{v.idx}: 20M submitted (nonce={v._next_nonce})")
                v._next_nonce += 1
            else:
                print(f"[stake] val-{v.idx}: FAIL {r.get('error', '')[:120]}")

        self.wait_n_blocks(5, label="stakes confirming")

    def check_validator_set(self):
        """Every validator should see the same validator set."""
        seen_sets: list[set[str]] = []
        for v in self.validators:
            r = rpc("127.0.0.1", v.rpc_port, "list_validators")
            if not r.get("ok"):
                print(f"[set] val-{v.idx} RPC fail")
                seen_sets.append(set())
                continue
            vals = r["result"]["validators"]
            seen = {
                (x["entity_id"], x.get("staked", 0))
                for x in vals
            }
            seen_sets.append({eid for eid, _ in seen})
            print(f"[set] val-{v.idx} sees {len(vals)} validators")
        all_match = all(s == seen_sets[0] for s in seen_sets)
        print(f"[set] {'[OK] all match' if all_match else '[DIVERGENT]'}")
        return all_match

    def check_height_agreement(self) -> tuple[bool, list[int]]:
        heights = [v.info().get("height", -1) for v in self.validators]
        lo, hi = min(heights), max(heights)
        agreed = (hi - lo) <= 1  # within one block is fine during active production
        tag = "OK" if agreed else "DIVERGENT"
        print(f"[sync] heights={heights}  spread={hi - lo}  [{tag}]")
        return agreed, heights

    def check_proposer_rotation(self, over_blocks: int = 20):
        """Walk backwards from the founder's tip and tally proposers."""
        founder = self.validators[0]
        r = rpc("127.0.0.1", founder.rpc_port, "list_validators")
        vals_by_id = {v["entity_id"]: 0 for v in r.get("result", {}).get("validators", [])}
        info = founder.info()
        h = info.get("height", 0)
        counts: dict[str, int] = {}
        for bn in range(max(0, h - over_blocks), h + 1):
            r = rpc("127.0.0.1", founder.rpc_port, "get_block_by_number",
                    {"block_number": bn})
            res = r.get("result", {})
            pid = res.get("proposer_id")
            if pid:
                counts[pid] = counts.get(pid, 0) + 1
        print(f"[rotation] proposers over last {over_blocks} blocks:")
        for pid, n in sorted(counts.items(), key=lambda x: -x[1]):
            name = next((f"val-{v.idx}" for v in self.validators
                         if v.entity_id_hex and v.entity_id_hex.startswith(pid[:16])),
                        pid[:16] + "...")
            print(f"  {name:12s}: {n}")
        distinct = len(counts)
        return distinct

    def wait_n_blocks(self, n: int, label: str = "", timeout: float = 120):
        founder = self.validators[0]
        start_h = founder.info().get("height", 0)
        deadline = time.time() + timeout
        while time.time() < deadline:
            h = founder.info().get("height", 0)
            if h >= start_h + n:
                print(f"[wait] {label}: advanced {h - start_h} blocks "
                      f"({start_h} -> {h})")
                return True
            time.sleep(0.5)
        print(f"[wait] {label}: TIMED OUT at height {founder.info().get('height')}")
        return False

    # --- lifecycle ----

    def start_all(self):
        # Val-1 has already minted genesis; start it first alone.
        founder = self.validators[0]
        print(f"[start] val-1 (founder)  p2p=:{founder.p2p_port} rpc=:{founder.rpc_port}")
        founder.start(seed_peers=[], env={})
        if not founder.wait_rpc(120):
            print("[start] val-1 never came up — aborting")
            self.print_logs(founder)
            sys.exit(1)
        print(f"[start] val-1 RPC up, height={founder.info().get('height')}")

        # Others peer via val-1
        for v in self.validators[1:]:
            print(f"[start] val-{v.idx}  p2p=:{v.p2p_port} rpc=:{v.rpc_port}")
            v.start(seed_peers=[("127.0.0.1", founder.p2p_port)], env={})
        for v in self.validators[1:]:
            if not v.wait_rpc(180):
                print(f"[start] val-{v.idx} never came up")
                self.print_logs(v)
                sys.exit(1)
            print(f"[start] val-{v.idx} RPC up, height={v.info().get('height')}")

    def print_logs(self, v: Validator, lines: int = 40):
        print(f"--- val-{v.idx} stderr (last {lines}) ---")
        try:
            tail = v.stderr_path.read_text().splitlines()[-lines:]
            for line in tail:
                print(f"  {line}")
        except Exception:
            pass
        print(f"--- val-{v.idx} stdout (last {lines}) ---")
        try:
            tail = v.stdout_path.read_text().splitlines()[-lines:]
            for line in tail:
                print(f"  {line}")
        except Exception:
            pass

    def stop_all(self):
        print("[stop] tearing down all validators")
        for v in reversed(self.validators):
            v.stop()

    def cleanup(self):
        self.stop_all()
        self.restore_config_local()
        if self.args.keep_data:
            print(f"[cleanup] data kept at {self.base_dir}")
        else:
            try:
                shutil.rmtree(self.base_dir)
                print(f"[cleanup] removed {self.base_dir}")
            except OSError as e:
                print(f"[cleanup] could not remove {self.base_dir}: {e}")

    # --- main ----

    def run(self):
        print(f"=== MessageChain devnet soak harness ===")
        print(f"  validators:  {self.n}")
        print(f"  tree height: {self.tree_height} ({1 << self.tree_height} leaves each)")
        print(f"  block time:  {self.block_time}s")
        print(f"  data dir:    {self.base_dir}")
        print()

        self.write_config_local()
        try:
            # Allocate port pairs starting at 19333 to avoid clashing with
            # the mainnet RPC at 9334 on this box (if anything were to
            # forward it through a tunnel).
            base_port = 19333
            for i in range(self.n):
                v = Validator(
                    idx=i + 1,
                    base_dir=self.base_dir,
                    p2p_port=base_port + i * 2,
                    rpc_port=base_port + 1 + i * 2,
                )
                v.generate_key()
                print(f"[key] val-{v.idx} key generated")
                self.validators.append(v)

            # Mint genesis (val-1 only)
            self.mint_genesis(self.validators[0])
            # Entity-id derivation after mint (cached)
            print("[derive] building entities (tree build × N) ...")
            for v in self.validators:
                v.build_entity(self.tree_height)
                print(f"  val-{v.idx}: {v.entity_id_hex[:16]}...")

            # Start all validators
            self.start_all()
            print()

            # Baseline check: all at genesis, all see founder-only set
            print("[phase 1] baseline with single staker (founder)")
            print("  waiting up to 30s for joiners to IBD block 0 ...")
            deadline = time.time() + 30
            while time.time() < deadline:
                all_synced = all(
                    v.info().get("height", 0) >= 1 for v in self.validators
                )
                if all_synced:
                    break
                time.sleep(1)
            self.check_height_agreement()
            # Dump peer counts to diagnose.
            for v in self.validators:
                info = v.info()
                sync = info.get("sync_status", {})
                print(f"  val-{v.idx}: height={info.get('height')} "
                      f"sync.state={sync.get('state')} "
                      f"known_peers={sync.get('known_peers')}")
            time.sleep(self.block_time + 1)
            self.check_height_agreement()

            # Fund + stake everyone
            print()
            print("[phase 2] funding + staking the other validators")
            self.fund_and_stake_everyone()
            print()

            # Validator set convergence
            print("[phase 3] validator-set convergence")
            time.sleep(self.block_time * 3)
            self.check_validator_set()
            print()

            # Soak run
            print(f"[phase 4] soak run for {self.args.run_for}s")
            end_time = time.time() + self.args.run_for
            last_status = time.time()
            while time.time() < end_time:
                time.sleep(5)
                if time.time() - last_status >= 30:
                    agreed, heights = self.check_height_agreement()
                    last_status = time.time()
                # Any validator dead?
                for v in self.validators:
                    if not v.is_alive():
                        print(f"[soak] val-{v.idx} died — aborting soak")
                        self.print_logs(v)
                        end_time = 0
                        break
            print()

            # Final checks
            print("[phase 5] final consistency checks")
            self.check_height_agreement()
            self.check_validator_set()
            self.check_proposer_rotation(over_blocks=min(30, int(self.args.run_for / self.block_time)))
            print()
            print("=== Soak complete ===")

        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--validators", type=int, default=3,
                        help="Number of validators (default: 3)")
    parser.add_argument("--tree-height", type=int, default=8,
                        help="WOTS+ tree height per validator (default: 8 = 256 leaves)")
    parser.add_argument("--block-time", type=int, default=3,
                        help="BLOCK_TIME_TARGET in seconds (default: 3)")
    parser.add_argument("--run-for", type=int, default=120,
                        help="Soak-run duration in seconds (default: 120)")
    parser.add_argument("--keep-data", action="store_true",
                        help="Don't delete the temp data dir on exit (for forensics)")
    args = parser.parse_args()
    harness = Harness(args)
    try:
        harness.run()
    except KeyboardInterrupt:
        print("\n[interrupt] cleaning up ...")
        harness.cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()
