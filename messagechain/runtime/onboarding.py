"""Validator onboarding helpers: init, doctor, upgrade, auto-rotate, config.

These are local-host / operator-facing helpers that live outside the
consensus hot path. Keeping them in one module lets cli.py stay a thin
parser+dispatch layer.
"""

from __future__ import annotations

import os
import secrets
import socket
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11 fallback; project requires 3.10+
    tomllib = None


ONBOARD_CONFIG_BASENAME = "onboard.toml"
ENV_ONBOARD_CONFIG = "MESSAGECHAIN_ONBOARD_CONFIG"
ENV_UPGRADE_DRY_RUN = "MESSAGECHAIN_UPGRADE_DRY_RUN"
ENV_SKIP_REACHABILITY = "MC_SKIP_REACHABILITY"


DEFAULT_ONBOARD = {
    "auto_upgrade": True,
    "auto_rotate": True,
    "data_dir": "",
    "keyfile": "",
    "entity_id_hex": "",
}

_ALLOWED_CONFIG_KEYS = frozenset(DEFAULT_ONBOARD)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _is_root() -> bool:
    # Windows has no real euid; treat non-POSIX as non-root for path defaults.
    return hasattr(os, "geteuid") and os.geteuid() == 0


def default_data_dir() -> str:
    if _is_root():
        return "/var/lib/messagechain"
    return os.path.join(os.path.expanduser("~"), ".messagechain", "chaindata")


def default_keyfile() -> str:
    if _is_root():
        return "/etc/messagechain/keyfile"
    return os.path.join(os.path.expanduser("~"), ".messagechain", "keyfile")


def default_onboard_config_path(prefer_root: bool | None = None) -> str:
    if prefer_root is None:
        prefer_root = _is_root()
    if prefer_root:
        return "/etc/messagechain/" + ONBOARD_CONFIG_BASENAME
    return os.path.join(
        os.path.expanduser("~"), ".messagechain", ONBOARD_CONFIG_BASENAME,
    )


def onboard_config_search_paths() -> list[str]:
    env = os.environ.get(ENV_ONBOARD_CONFIG)
    paths: list[str] = []
    if env:
        paths.append(env)
    paths.append("/etc/messagechain/" + ONBOARD_CONFIG_BASENAME)
    paths.append(
        os.path.join(
            os.path.expanduser("~"), ".messagechain", ONBOARD_CONFIG_BASENAME,
        )
    )
    return paths


def resolve_onboard_config_path() -> str | None:
    for p in onboard_config_search_paths():
        if os.path.exists(p):
            return p
    return None


# ---------------------------------------------------------------------------
# Read / write onboard.toml
# ---------------------------------------------------------------------------

def read_onboard_config(path: str | None = None) -> dict:
    """Return a dict with DEFAULT_ONBOARD merged with any on-disk overrides.

    Missing file is tolerated; returns the defaults unchanged so callers
    can always ask for e.g. `cfg["auto_upgrade"]` without a KeyError.
    """
    resolved = path or resolve_onboard_config_path()
    cfg = dict(DEFAULT_ONBOARD)
    if not resolved or not os.path.exists(resolved):
        return cfg
    if tomllib is None:
        return cfg
    try:
        with open(resolved, "rb") as f:
            data = tomllib.load(f)
    except OSError:
        return cfg
    for key in _ALLOWED_CONFIG_KEYS:
        if key in data:
            cfg[key] = data[key]
    return cfg


def _format_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    s = str(value).replace("\\", "\\\\").replace("\"", "\\\"")
    return f"\"{s}\""


def write_onboard_config(path: str, cfg: dict) -> None:
    """Write the onboard config with a stable key order + comment header."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    merged = dict(DEFAULT_ONBOARD)
    for key, val in cfg.items():
        if key in _ALLOWED_CONFIG_KEYS:
            merged[key] = val
    lines = ["# MessageChain onboarding config", ""]
    # Stable ordering so diffs are readable.
    order = ["auto_upgrade", "auto_rotate", "data_dir", "keyfile", "entity_id_hex"]
    for key in order:
        lines.append(f"{key} = {_format_value(merged.get(key, DEFAULT_ONBOARD[key]))}")
    data = "\n".join(lines) + "\n"
    # Writing keyfile paths is harmless; the sensitive thing is the keyfile itself.
    with open(path, "w") as f:
        f.write(data)


def config_get(key: str, path: str | None = None) -> object:
    if key not in _ALLOWED_CONFIG_KEYS:
        raise KeyError(f"Unknown onboard config key: {key}")
    cfg = read_onboard_config(path)
    return cfg.get(key, DEFAULT_ONBOARD[key])


def config_set(key: str, value, path: str | None = None) -> str:
    """Persist a single key. Returns the file path written to.

    Path resolution for first-write cases: explicit path > env var >
    already-existing config file > role-based default.
    """
    if key not in _ALLOWED_CONFIG_KEYS:
        raise KeyError(f"Unknown onboard config key: {key}")
    env_path = os.environ.get(ENV_ONBOARD_CONFIG)
    resolved = (
        path
        or env_path
        or resolve_onboard_config_path()
        or default_onboard_config_path()
    )
    cfg = read_onboard_config(resolved)
    # Normalize booleans from CLI-supplied strings.
    if key in ("auto_upgrade", "auto_rotate"):
        value = _coerce_bool(value)
    cfg[key] = value
    write_onboard_config(resolved, cfg)
    return resolved


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    raise ValueError(f"Not a boolean: {value!r}")


# ---------------------------------------------------------------------------
# Keyfile helpers
# ---------------------------------------------------------------------------

def generate_new_private_key() -> bytes:
    return secrets.token_bytes(32)


def write_keyfile(path: str, private_key: bytes) -> None:
    """Atomically write a hex-encoded checksummed private key at mode 0600."""
    from messagechain.identity.key_encoding import encode_private_key

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    encoded = encode_private_key(private_key)
    # Write then chmod; on POSIX, use O_CREAT|O_EXCL-less open since the
    # init command explicitly overwrites-when-permitted.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(encoded + "\n")
    finally:
        pass
    if hasattr(os, "chmod"):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# systemd unit bodies
# ---------------------------------------------------------------------------

VALIDATOR_UNIT_PATH = "/etc/systemd/system/messagechain-validator.service"
UPGRADE_UNIT_PATH = "/etc/systemd/system/messagechain-upgrade.service"
UPGRADE_TIMER_PATH = "/etc/systemd/system/messagechain-upgrade.timer"
ROTATE_UNIT_PATH = "/etc/systemd/system/messagechain-rotate-key.service"
ROTATE_TIMER_PATH = "/etc/systemd/system/messagechain-rotate-key.timer"


_HARDENING = """\
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
PrivateIPC=true
RemoveIPC=true
ProcSubset=pid
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
ReadWritePaths=/var/lib/messagechain
ReadOnlyPaths=/etc/messagechain /opt/messagechain
"""


def render_validator_unit(entity_id_hex: str, keyfile: str, data_dir: str) -> str:
    return (
        "[Unit]\n"
        "Description=MessageChain validator node\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=3600\n"
        "StartLimitBurst=5\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=messagechain\n"
        "Group=messagechain\n"
        "WorkingDirectory=/opt/messagechain\n"
        f"ExecStart=/usr/bin/env python3 -m messagechain start --mine \\\n"
        f"    --data-dir {data_dir} \\\n"
        "    --rpc-bind 0.0.0.0 \\\n"
        f"    --keyfile {keyfile} \\\n"
        f"    --wallet {entity_id_hex}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "TimeoutStopSec=30\n"
        "KillSignal=SIGTERM\n"
        "\n"
        + _HARDENING +
        "LimitNOFILE=65536\n"
        "MemoryMax=1500M\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


_UPGRADE_HARDENING = """\
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=false
LockPersonality=true
ReadWritePaths=/opt /var/lib/messagechain /etc/systemd
ReadOnlyPaths=/etc/messagechain
"""


def render_upgrade_service() -> str:
    # Runs as root because `messagechain upgrade` invokes systemctl stop/
    # start, writes /opt/messagechain, and chowns the new install. An
    # unprivileged user cannot do any of that.
    #
    # ExecStart is wrapped in ``flock -n`` on the same advisory lock
    # path the Python-level check uses.  Two defenses for the
    # timer-vs-manual race:
    #   * systemd-level: ``flock -n`` makes the timer's ExecStart bail
    #     at the shell (exit 1) without even launching Python if an
    #     operator is currently running ``messagechain upgrade --yes``
    #     by hand.  Silent no-op from the timer's perspective.
    #   * Python-level: ``_upgrade_acquire_lock`` in cmd_upgrade
    #     re-acquires the same flock, so two manual invocations (or
    #     two timer hosts pointed at a shared NFS) also bail cleanly.
    # ``-n`` is non-blocking (no waiting); ``-E 0`` makes flock exit 0
    # when the lock can't be acquired so the timer unit doesn't go
    # red on a normal contention event.
    return (
        "[Unit]\n"
        "Description=MessageChain auto-upgrade runner\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "Requires=messagechain-validator.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "User=root\n"
        "Group=root\n"
        "WorkingDirectory=/opt/messagechain\n"
        "ExecStart=/usr/bin/flock -n -E 0 /run/messagechain-upgrade.lock "
        "/usr/bin/env python3 -m messagechain upgrade --yes\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "\n"
        + _UPGRADE_HARDENING
    )


def render_upgrade_timer() -> str:
    return (
        "[Unit]\n"
        "Description=MessageChain weekly auto-upgrade timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=Sun 03:17\n"
        "RandomizedDelaySec=30min\n"
        "Persistent=true\n"
        "Unit=messagechain-upgrade.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def render_rotate_service() -> str:
    return (
        "[Unit]\n"
        "Description=MessageChain auto key-rotation runner\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "User=messagechain\n"
        "Group=messagechain\n"
        "WorkingDirectory=/opt/messagechain\n"
        "ExecStart=/usr/bin/env python3 -m messagechain rotate-key-if-needed --yes\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "\n"
        + _HARDENING
    )


def render_rotate_timer() -> str:
    return (
        "[Unit]\n"
        "Description=MessageChain daily key-rotation watchdog timer\n"
        "\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "RandomizedDelaySec=1h\n"
        "Persistent=true\n"
        "Unit=messagechain-rotate-key.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


# ---------------------------------------------------------------------------
# Chain-identity probe — init pre-flight
# ---------------------------------------------------------------------------


@dataclass
class SeedProbeResult:
    """Outcome of a single seed's get_chain_info RPC probe.

    ``ok=True, mismatch=False`` -> seed is compatible with our local
    config; safe to proceed with keygen.  ``ok=True, mismatch=True``
    -> seed is reachable but its chain_id or genesis_hash disagree
    with ours; abort before wasting a keygen on a chain the operator
    will be rejected from.  ``ok=False`` -> seed unreachable /
    malformed response; caller decides whether to try the next seed
    or warn-and-continue (first validator / air-gapped deploys).
    """
    ok: bool
    host: str
    port: int
    chain_id: str = ""
    genesis_hash: str = ""
    height: int = 0
    version: str = ""
    mismatch: bool = False
    error: str = ""


def probe_seed_chain_identity(
    host: str, port: int, timeout: float = 5.0,
) -> SeedProbeResult:
    """Call ``get_chain_info`` on a seed and return the identity
    fields.  Never raises; failures are returned as ``ok=False`` so
    the caller can distinguish "skip this seed" from "abort the
    init".  Chain-identity mismatch detection is the caller's job
    (see ``verify_seed_compatible``); this function is pure
    transport.
    """
    try:
        from client import rpc_call
    except Exception as e:
        return SeedProbeResult(
            ok=False, host=host, port=port,
            error=f"rpc_call import failed: {e}",
        )

    try:
        resp = rpc_call(host, port, "get_chain_info", {})
    except Exception as e:
        return SeedProbeResult(
            ok=False, host=host, port=port,
            error=f"rpc error: {e}",
        )

    if not isinstance(resp, dict) or not resp.get("ok"):
        return SeedProbeResult(
            ok=False, host=host, port=port,
            error=f"rpc error: {resp.get('error', 'bad response') if isinstance(resp, dict) else 'non-dict response'}",
        )

    info = resp.get("result") or {}
    return SeedProbeResult(
        ok=True,
        host=host,
        port=port,
        chain_id=str(info.get("chain_id", "")),
        genesis_hash=str(info.get("genesis_hash") or ""),
        height=int(info.get("height") or 0),
        version=str(info.get("version", "")),
    )


def verify_seed_compatible(
    probe: SeedProbeResult,
    our_chain_id: str,
    our_genesis_hex: str | None,
) -> tuple[bool, str]:
    """Check a successful probe against local config.

    Returns (compatible, operator_message).  ``compatible=False``
    means the operator's local config disagrees with the seed on
    either chain_id or (if our side has any chain state) genesis
    hash.  Message text is written for direct display and includes
    concrete recovery guidance so a fresh operator can fix the
    config without reading source.

    If the local node has no chain_db yet (common for a fresh
    validator mid-init), genesis_hash comparison is skipped and
    only chain_id is used.  A mismatch on chain_id alone is enough
    to abort: it's a profile-config error (mainnet vs testnet vs
    prototype) and cannot be resolved by "just syncing".
    """
    if not probe.ok:
        # Caller should treat probe failure as "skip this seed",
        # not "incompatible".  Return True with a diagnostic so
        # compose_verify_report can log the skip reason.
        return True, f"probe skipped: {probe.error}"

    if probe.chain_id and probe.chain_id != our_chain_id:
        return False, (
            f"chain_id mismatch with seed {probe.host}:{probe.port}: "
            f"seed reports {probe.chain_id!r}, local config is "
            f"{our_chain_id!r}. Your MESSAGECHAIN_PROFILE env var or "
            "config_local.py likely targets the wrong network. "
            "Fix the config BEFORE running init -- a keyfile "
            "generated for a different chain_id will be rejected by "
            "every tx on this chain."
        )

    if (
        our_genesis_hex
        and probe.genesis_hash
        and probe.genesis_hash != our_genesis_hex
    ):
        return False, (
            f"genesis_hash mismatch with seed {probe.host}:{probe.port}: "
            f"seed={probe.genesis_hash[:16]}..., ours={our_genesis_hex[:16]}... "
            "This usually means a stale local chain_db from a "
            "previous testnet / fork.  Wipe the data dir or point "
            "init at a fresh one, then retry."
        )

    return True, (
        f"seed {probe.host}:{probe.port} compatible "
        f"(chain_id={probe.chain_id}, height={probe.height})"
    )


# ---------------------------------------------------------------------------
# init command
# ---------------------------------------------------------------------------

@dataclass
class InitPlan:
    data_dir: str
    keyfile: str
    onboard_config: str
    entity_id_hex: str
    auto_upgrade: bool
    auto_rotate: bool
    systemd: bool
    keyfile_exists: bool
    systemd_units: dict = field(default_factory=dict)

    def next_steps_text(self) -> str:
        au = "ON " if self.auto_upgrade else "OFF"
        ar = "ON " if self.auto_rotate else "OFF"
        address = ""
        if self.entity_id_hex:
            try:
                from messagechain.identity.address import encode_address
                address = encode_address(bytes.fromhex(self.entity_id_hex))
            except Exception:
                address = ""
        lines = [
            "Done. Your validator is configured.",
            f"  Data dir:  {self.data_dir}",
            f"  Keyfile:   {self.keyfile}  (0600)",
        ]
        if address:
            lines.append(f"  Address:   {address}")
        lines += [
            f"  Entity:    {self.entity_id_hex[:16]}...",
            f"  Auto-upgrade:     {au}  (disable: messagechain config set auto_upgrade false)",
            f"  Auto key-rotate:  {ar}  (disable: messagechain config set auto_rotate false)",
            "",
            "Fund this validator (the keyfile above is its identity — back it up):",
            "  1. From a wallet with tokens:",
            f"       messagechain transfer --to {address or 'mc1...'} --amount 10000",
            "  2. Back on this host, lock the funds as stake:",
            "       sudo -u messagechain messagechain stake --amount 10000",
            "",
            "Then start the validator:",
            "  sudo systemctl daemon-reload",
            "  sudo systemctl enable --now messagechain-validator",
        ]
        if self.systemd and self.auto_upgrade:
            lines.append("  sudo systemctl enable --now messagechain-upgrade.timer")
        if self.systemd and self.auto_rotate:
            lines.append("  sudo systemctl enable --now messagechain-rotate-key.timer")
        return "\n".join(lines)


def plan_init(
    data_dir: str | None = None,
    keyfile: str | None = None,
    systemd: bool | None = None,
    auto_upgrade: bool = True,
    auto_rotate: bool = True,
    print_only: bool = False,
    onboard_config_path: str | None = None,
    key_override: bytes | None = None,
) -> InitPlan:
    """Compute the init plan. Pure function — does not touch disk."""
    ddir = data_dir or default_data_dir()
    kf = keyfile or default_keyfile()
    ocfg = onboard_config_path or default_onboard_config_path()
    sm = systemd if systemd is not None else _is_root()

    # Resolve the private-key source but DO NOT build the WOTS+ tree here.
    # Entity.create at production MERKLE_TREE_HEIGHT=20 is a multi-hour
    # keygen; plan_init must stay cheap so --print-only and unit tests
    # run in milliseconds. The tree is built once in apply_init with a
    # progress reporter.
    entity_hex = ""
    keyfile_exists = os.path.exists(kf)
    pk_bytes: bytes | None = None
    if keyfile_exists:
        try:
            from messagechain.identity.key_encoding import decode_private_key
            with open(kf, "r") as f:
                pk_bytes = decode_private_key(f.read())
        except Exception:
            pk_bytes = None
    elif key_override is not None:
        pk_bytes = key_override

    # Only derive entity_id here when a caller passed key_override
    # (unit tests, which pin MERKLE_TREE_HEIGHT=4 via conftest).
    if pk_bytes is not None and key_override is not None:
        try:
            from messagechain.identity.identity import Entity
            entity = Entity.create(pk_bytes)
            entity_hex = entity.entity_id_hex
        except Exception:
            entity_hex = ""

    units: dict = {}
    if sm:
        units[VALIDATOR_UNIT_PATH] = render_validator_unit(
            entity_hex or "ENTITY_ID_HEX", kf, ddir,
        )
        units[UPGRADE_UNIT_PATH] = render_upgrade_service()
        units[UPGRADE_TIMER_PATH] = render_upgrade_timer()
        units[ROTATE_UNIT_PATH] = render_rotate_service()
        units[ROTATE_TIMER_PATH] = render_rotate_timer()

    return InitPlan(
        data_dir=ddir,
        keyfile=kf,
        onboard_config=ocfg,
        entity_id_hex=entity_hex,
        auto_upgrade=auto_upgrade,
        auto_rotate=auto_rotate,
        systemd=sm,
        keyfile_exists=keyfile_exists,
        systemd_units=units,
    )


def apply_init(
    plan: InitPlan,
    *,
    key_override: bytes | None = None,
    build_tree: bool = True,
    progress=None,
) -> None:
    """Perform disk writes for a plan. Idempotent where safe.

    With build_tree=True (default), the WOTS+ Merkle tree is built so
    entity_id_hex can be derived and baked into the systemd unit's
    --wallet flag. At production MERKLE_TREE_HEIGHT=20 this is a
    multi-hour operation — pass a progress reporter from the CLI so
    operators see motion. Callers that only need the scaffolding (tests,
    --print-only via a different code path) pass build_tree=False.
    """
    os.makedirs(plan.data_dir, exist_ok=True)

    if not plan.keyfile_exists:
        pk = key_override if key_override is not None else generate_new_private_key()
        write_keyfile(plan.keyfile, pk)
    else:
        try:
            from messagechain.identity.key_encoding import decode_private_key
            with open(plan.keyfile, "r") as f:
                pk = decode_private_key(f.read())
        except Exception as e:
            raise RuntimeError(
                f"Existing keyfile at {plan.keyfile} cannot be decoded: {e}"
            )

    if build_tree and not plan.entity_id_hex:
        try:
            from messagechain.identity.identity import Entity
            entity = Entity.create(pk, progress=progress) if progress else Entity.create(pk)
            plan.entity_id_hex = entity.entity_id_hex
            if plan.systemd and plan.systemd_units:
                plan.systemd_units[VALIDATOR_UNIT_PATH] = render_validator_unit(
                    plan.entity_id_hex, plan.keyfile, plan.data_dir,
                )
        except Exception:
            pass

    write_onboard_config(plan.onboard_config, {
        "auto_upgrade": plan.auto_upgrade,
        "auto_rotate": plan.auto_rotate,
        "data_dir": plan.data_dir,
        "keyfile": plan.keyfile,
        "entity_id_hex": plan.entity_id_hex,
    })

    if plan.systemd:
        for path, body in plan.systemd_units.items():
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w") as f:
                f.write(body)


# ---------------------------------------------------------------------------
# doctor command
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    level: int  # 0 ok, 1 warn, 2 fail
    label: str
    status: str
    detail: str = ""


def _fmt(res: CheckResult) -> str:
    tag = {0: "OK  ", 1: "WARN", 2: "FAIL"}[res.level]
    line = f"  [{tag}] {res.label}: {res.status}"
    if res.detail:
        line += f" - {res.detail}"
    return line


def _check_python() -> CheckResult:
    if sys.version_info >= (3, 10):
        return CheckResult(0, "python version",
                           f"{sys.version_info.major}.{sys.version_info.minor}")
    return CheckResult(2, "python version",
                       f"{sys.version_info.major}.{sys.version_info.minor}",
                       "need >= 3.10")


def _check_data_dir(data_dir: str) -> CheckResult:
    if not data_dir:
        return CheckResult(1, "data-dir", "unset")
    if not os.path.exists(data_dir):
        return CheckResult(2, "data-dir", "missing",
                           f"{data_dir} -- run `messagechain init` first")
    if not os.access(data_dir, os.W_OK):
        return CheckResult(2, "data-dir", "not writable", data_dir)
    return CheckResult(0, "data-dir", data_dir)


def _check_keyfile(keyfile: str) -> CheckResult:
    if not keyfile:
        return CheckResult(1, "keyfile", "unset")
    if not os.path.exists(keyfile):
        return CheckResult(2, "keyfile", "missing",
                           f"{keyfile} -- run `messagechain init` or `generate-key`")
    try:
        st = os.stat(keyfile)
    except OSError as e:
        return CheckResult(2, "keyfile", "stat failed", str(e))
    mode = stat.S_IMODE(st.st_mode)
    if hasattr(os, "geteuid"):
        if mode not in (0o400, 0o600):
            return CheckResult(
                2, "keyfile", "bad permissions",
                f"mode {oct(mode)}, want 0400 or 0600",
            )
        if st.st_uid != os.geteuid():
            return CheckResult(
                1, "keyfile", "not owned by current user",
                f"uid {st.st_uid}",
            )
    return CheckResult(0, "keyfile", f"mode {oct(mode)}")


def _check_disk(data_dir: str, disk_usage_fn=None) -> CheckResult:
    import shutil as _shutil
    if not data_dir or not os.path.exists(data_dir):
        return CheckResult(1, "disk free", "data-dir missing", "skipping")
    fn = disk_usage_fn or _shutil.disk_usage
    try:
        usage = fn(data_dir)
    except OSError as e:
        return CheckResult(1, "disk free", "stat failed", str(e))
    gb = usage.free / (1024 ** 3)
    if gb < 2.0:
        return CheckResult(2, "disk free", f"{gb:.1f} GB", "< 2 GB free")
    if gb < 5.0:
        return CheckResult(1, "disk free", f"{gb:.1f} GB", "< 5 GB free")
    return CheckResult(0, "disk free", f"{gb:.1f} GB")


def _check_port_bindable(port: int, bind_fn=None) -> CheckResult:
    """Return FAIL if unbindable and nothing identifies as messagechain."""
    fn = bind_fn or _try_bind
    ok, err = fn(port)
    if ok:
        return CheckResult(0, f"port {port}", "bindable")
    # Port busy — check if it's our own validator.
    if _looks_like_messagechain_on_port(port):
        return CheckResult(
            1, f"port {port}", "in use by messagechain", "node already running",
        )
    return CheckResult(2, f"port {port}", "in use", err or "bind failed")


def _try_bind(port: int) -> tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        return True, ""
    except OSError as e:
        return False, str(e)
    finally:
        s.close()


def _looks_like_messagechain_on_port(port: int) -> bool:
    """Best-effort: ask lsof or ss what's listening. Return True on match."""
    import shutil as _shutil
    import subprocess
    for cmd in (
        ["lsof", "-iTCP", f":{port}", "-sTCP:LISTEN", "-n", "-P"],
        ["ss", "-ltnp", f"sport = :{port}"],
    ):
        if not _shutil.which(cmd[0]):
            continue
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=2,
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        if "messagechain" in out.lower() or "python" in out.lower():
            return True
    return False


def _check_seeds(seeds: list[tuple[str, int]], connect_fn=None) -> CheckResult:
    if not seeds:
        return CheckResult(2, "seeds", "none configured")
    reached = 0
    for host, port in seeds:
        if _probe_tcp(host, port, connect_fn):
            reached += 1
    if reached == 0:
        return CheckResult(2, "seeds", f"0/{len(seeds)} reachable")
    if reached < len(seeds):
        return CheckResult(
            1, "seeds", f"{reached}/{len(seeds)} reachable",
            "partial reachability",
        )
    return CheckResult(0, "seeds", f"{reached}/{len(seeds)} reachable")


def _probe_tcp(host: str, port: int, connect_fn=None) -> bool:
    fn = connect_fn or _tcp_connect
    return fn(host, port)


def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _check_systemd_timer(unit: str) -> CheckResult:
    import shutil as _shutil
    import subprocess
    if not _shutil.which("systemctl"):
        return CheckResult(1, unit, "systemctl not found", "skipping")
    try:
        r = subprocess.run(
            ["systemctl", "is-enabled", unit],
            capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return CheckResult(1, unit, "probe failed", str(e))
    status = r.stdout.strip()
    if status == "enabled":
        return CheckResult(0, unit, "enabled")
    return CheckResult(1, unit, status or "disabled", "enable with systemctl")


def run_doctor(
    onboard_cfg: dict | None = None,
    data_dir: str | None = None,
    *,
    seeds: list[tuple[str, int]] | None = None,
    bind_fn=None,
    connect_fn=None,
    disk_usage_fn=None,
    check_timers: bool = False,
) -> tuple[int, list[CheckResult]]:
    """Return (worst_level, checks).

    Injection points keep this unit-testable without sockets, filesystem
    race conditions, or real systemctl calls.
    """
    cfg = onboard_cfg if onboard_cfg is not None else read_onboard_config()
    ddir = data_dir or cfg.get("data_dir") or default_data_dir()
    kf = cfg.get("keyfile") or default_keyfile()

    results: list[CheckResult] = [
        _check_python(),
        _check_data_dir(ddir),
        _check_keyfile(kf),
        _check_disk(ddir, disk_usage_fn=disk_usage_fn),
        _check_port_bindable(9333, bind_fn=bind_fn),
        _check_port_bindable(9334, bind_fn=bind_fn),
    ]

    if seeds is None:
        try:
            from messagechain.config import SEED_NODES as _SN
            seeds = list(_SN)
        except Exception:
            seeds = []
    results.append(_check_seeds(seeds, connect_fn=connect_fn))

    if check_timers:
        if cfg.get("auto_upgrade"):
            results.append(_check_systemd_timer("messagechain-upgrade.timer"))
        if cfg.get("auto_rotate"):
            results.append(_check_systemd_timer("messagechain-rotate-key.timer"))

    worst = max((r.level for r in results), default=0)
    return worst, results


# ---------------------------------------------------------------------------
# Upgrade command helpers
# ---------------------------------------------------------------------------

def _is_dry_run() -> bool:
    return os.environ.get(ENV_UPGRADE_DRY_RUN, "").strip() == "1"


def _parse_version_tag(tag: str) -> tuple[int, int, int] | None:
    """Parse `vX.Y.Z-mainnet` into a tuple, else None."""
    if not tag:
        return None
    t = tag.strip()
    if not t.startswith("v"):
        return None
    t = t[1:]
    if t.endswith("-mainnet"):
        t = t[:-len("-mainnet")]
    parts = t.split(".")
    if len(parts) != 3:
        return None
    try:
        return tuple(int(p) for p in parts)  # type: ignore[return-value]
    except ValueError:
        return None


def resolve_latest_tag_from_api(api_response: dict) -> str | None:
    """Extract the highest vX.Y.Z-mainnet tag from a GitHub releases payload.

    Accepts either a single-release dict or a list of releases. Ignores
    non-mainnet tags, pre-releases, and draft releases.
    """
    items: list[dict]
    if isinstance(api_response, dict):
        items = [api_response]
    elif isinstance(api_response, list):
        items = list(api_response)
    else:
        return None
    best: tuple[tuple[int, int, int], str] | None = None
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("draft") or item.get("prerelease"):
            continue
        tag = item.get("tag_name") or ""
        parsed = _parse_version_tag(tag)
        if parsed is None:
            continue
        if best is None or parsed > best[0]:
            best = (parsed, tag)
    return best[1] if best else None


def run_upgrade(
    *,
    installed_version: str,
    latest_tag_fetcher=None,
    shell_runner=None,
    health_check=None,
    tag_override: str | None = None,
    printer=print,
) -> int:
    """Run the upgrade flow. Returns exit code.

    Injection points:
      * latest_tag_fetcher() -> str (the tag to install). Default hits the web.
      * shell_runner(cmd: list[str]) -> int. Default runs subprocess.
      * health_check() -> bool. Default polls local RPC.
    """
    if tag_override:
        target_tag = tag_override
    else:
        if latest_tag_fetcher is None:
            latest_tag_fetcher = _default_latest_tag_fetcher
        try:
            target_tag = latest_tag_fetcher()
        except Exception as e:
            printer(f"Error: cannot resolve latest tag: {e}")
            return 1

    if not target_tag:
        printer("Error: no latest tag resolved")
        return 1

    installed_triple = _parse_version_tag("v" + installed_version + "-mainnet")
    target_triple = _parse_version_tag(target_tag)
    if installed_triple and target_triple and installed_triple >= target_triple:
        printer(f"already up to date (installed={installed_version}, latest={target_tag})")
        return 0

    previous_tag = f"v{installed_version}-mainnet"

    if shell_runner is None:
        shell_runner = _default_shell_runner
    if health_check is None:
        health_check = _default_health_check

    printer(f"Upgrading {installed_version} -> {target_tag}")
    steps = [
        ["git", "fetch", "--tags", "origin"],
        ["git", "stash", "push", "--include-untracked", "-m", "mc-upgrade"],
        ["git", "checkout", target_tag],
        ["pip", "install", "-e", "."],
    ]
    for cmd in steps:
        rc = shell_runner(cmd)
        if rc != 0:
            printer(f"step failed (exit {rc}): {' '.join(cmd)}")
            return rc

    # Optional smoke tests.
    if os.path.isdir("tests/smoke"):
        rc = shell_runner(["python", "-m", "pytest", "tests/smoke/"])
        if rc != 0:
            printer("smoke tests failed; rolling back")
            _rollback(shell_runner, previous_tag, printer)
            return rc

    # Restart under systemd if available.
    import shutil as _shutil
    if _shutil.which("systemctl"):
        shell_runner(["systemctl", "restart", "messagechain-validator"])

    # Post-restart health check.
    if not health_check():
        printer("post-restart health check failed; rolling back")
        _rollback(shell_runner, previous_tag, printer)
        return 2

    printer(f"upgrade to {target_tag} complete")
    return 0


def _rollback(shell_runner, previous_tag: str, printer) -> None:
    shell_runner(["git", "checkout", previous_tag])
    shell_runner(["pip", "install", "-e", "."])
    import shutil as _shutil
    if _shutil.which("systemctl"):
        shell_runner(["systemctl", "restart", "messagechain-validator"])


def _default_latest_tag_fetcher() -> str:
    """Prefer git if .git exists, else hit GitHub API."""
    import subprocess
    if os.path.isdir(".git"):
        try:
            out = subprocess.run(
                ["git", "ls-remote", "--tags", "origin"],
                capture_output=True, text=True, timeout=15,
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        best: tuple[tuple[int, int, int], str] | None = None
        for line in out.splitlines():
            if "refs/tags/" not in line:
                continue
            tag = line.rsplit("refs/tags/", 1)[1].strip()
            if tag.endswith("^{}"):
                tag = tag[:-3]
            parsed = _parse_version_tag(tag)
            if parsed is None:
                continue
            if best is None or parsed > best[0]:
                best = (parsed, tag)
        if best is not None:
            return best[1]

    import json
    import urllib.request
    url = "https://api.github.com/repos/ben-arnao/MessageChain/releases"
    req = urllib.request.Request(url, headers={"User-Agent": "messagechain-upgrade"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    tag = resolve_latest_tag_from_api(data)
    if not tag:
        raise RuntimeError("no mainnet tag found")
    return tag


def _default_shell_runner(cmd: list[str]) -> int:
    import subprocess
    if _is_dry_run():
        print(f"[dry-run] {' '.join(cmd)}")
        return 0
    try:
        return subprocess.call(cmd)
    except OSError as e:
        print(f"shell error: {e}")
        return 127


def _default_health_check() -> bool:
    """Poll localhost RPC for up to 60s."""
    import time
    if _is_dry_run():
        return True
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            from client import rpc_call
            r = rpc_call("127.0.0.1", 9334, "get_chain_info", {})
            if r.get("ok"):
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


# ---------------------------------------------------------------------------
# rotate-key-if-needed
# ---------------------------------------------------------------------------

def compute_watermark_pct(leaf_watermark: int, tree_height: int) -> float:
    cap = 1 << tree_height
    if cap <= 0:
        return 0.0
    return leaf_watermark / cap


def run_rotate_if_needed(
    *,
    watermark_fetcher,
    has_cold_authority_key: bool,
    tree_height: int,
    rotate_impl=None,
    printer=print,
) -> int:
    """Invoke rotate if pct >= 0.95, else print status + exit 0.

    `watermark_fetcher()` returns the leaf_watermark int.
    `rotate_impl()` is called at >=95% when no cold key is set.
    """
    try:
        wm = int(watermark_fetcher())
    except Exception as e:
        printer(f"Error fetching leaf watermark: {e}")
        return 1

    pct = compute_watermark_pct(wm, tree_height)
    pct_int = int(pct * 100)

    if pct < 0.80:
        printer(f"no-op, watermark {pct_int}%")
        return 0
    if pct < 0.95:
        printer(f"approaching threshold, watermark {pct_int}%")
        return 0
    if has_cold_authority_key:
        printer(
            "Cold authority key policy active — auto-rotation disabled. "
            "Rotate manually."
        )
        return 0
    if rotate_impl is None:
        printer(
            f"watermark {pct_int}% — would rotate but no rotate_impl wired"
        )
        return 0
    try:
        rotate_impl()
    except SystemExit as e:
        return int(e.code or 0)
    except Exception as e:
        printer(f"rotate failed: {e}")
        return 1
    return 0


# ---------------------------------------------------------------------------
# Reachability probe
# ---------------------------------------------------------------------------

def should_skip_reachability() -> bool:
    return os.environ.get(ENV_SKIP_REACHABILITY, "").strip() == "1"


def run_reachability_probe(
    port: int,
    *,
    external_ip_fetcher=None,
    tcp_connector=None,
    printer=print,
) -> tuple[int, str]:
    """Best-effort probe. Return (level, detail).

    level: 0 ok, 1 warn (skipped or inconclusive), 2 fail (bad NAT/firewall).
    """
    if should_skip_reachability():
        return 0, "skipped via MC_SKIP_REACHABILITY"
    fetch = external_ip_fetcher or _default_external_ip
    connect = tcp_connector or _tcp_connect
    try:
        ip = fetch()
    except Exception as e:
        printer(f"reachability probe: external IP lookup failed ({e}); skipping")
        return 1, "external ip lookup failed"
    if not ip:
        printer("reachability probe: external IP unknown; skipping")
        return 1, "external ip empty"
    if connect(ip, port):
        return 0, f"{ip}:{port} reachable from outside"
    return 2, f"{ip}:{port} unreachable — likely NAT/firewall"


def _default_external_ip() -> str:
    import urllib.request
    req = urllib.request.Request(
        "https://api.ipify.org", headers={"User-Agent": "messagechain"},
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.read().decode("utf-8").strip()
