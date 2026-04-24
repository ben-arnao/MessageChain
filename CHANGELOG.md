# Changelog

All notable changes to MessageChain are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] — 2026-04-24

Patch release — fixes `messagechain upgrade` default tag resolution so
it actually finds the latest release with zero flags.

### Fixed

- `messagechain upgrade` (no `--tag`) previously queried the GitHub
  *Releases* API, which only returns tags that were explicitly
  published as GitHub Release objects via the Releases UI. This
  repo publishes by pushing git tags directly, so the Releases API
  returned the one-and-only pre-existing Release (v1.0.0-mainnet)
  and the command would attempt a downgrade. Now the resolver hits
  the git-tags API (`/repos/{owner}/{repo}/tags`), filters to
  canonical `vX.Y.Z-mainnet` tags, and picks the highest by semver
  triple — not lexicographic order, so `v1.10.0-mainnet` correctly
  ranks above `v1.9.0-mainnet`.

## [1.2.1] — 2026-04-24

Version-bump-only release. No behavior changes; cut to exercise the
`messagechain upgrade` command end-to-end on live mainnet validators.
Safe no-op rollout.

## [1.2.0] — 2026-04-24

Minor release — operator ergonomics. Adds a one-shot `messagechain upgrade`
command and surfaces peer binary versions in the `peers` table.

### Added

- `messagechain upgrade [--tag vX.Y.Z-mainnet]` — stops the validator
  service, backs up the install dir, fetches the release tag, swaps in
  the new code, runs `migrate-chain-db` (idempotent), restarts the
  service, polls local RPC status, and rolls back to the backup on
  health-check failure. Replaces the 20-line bash procedure we were
  running by hand. `--no-rollback` keeps the new code even on health
  failure. Defaults: install-dir `/opt/messagechain`, data-dir
  `/var/lib/messagechain`, service `messagechain-validator`.
- Peer binary versions now flow through the P2P handshake. `peers`
  output gains a **Version** column; peers running ≤1.1.1 show as
  `unknown` (they didn't advertise a version before this release).

### Changed

- Runtime `__version__` bumped 1.0.0 → 1.2.0. The 1.0.0 constant had
  drifted stale across 1.0.1, 1.0.2, 1.1.0, and 1.1.1 releases;
  1.2.0 resumes correct versioning and is advertised in handshakes
  from now on.

## [1.1.1] — 2026-04-24

Patch release — fixes a regression in the schema v1→v2 migration
introduced alongside the six cold-restart persistence surfaces. Any
operator running 1.1.0 and attempting `migrate-chain-db` on a chain.db
that contains blocks referencing non-genesis entities (i.e. any live
chain past block 0) would hit:

    ValueError: entity ref uses unknown index N (state lacks mapping)

and abort before stamping schema_version to 2.

### Fixed

- `migrate_schema_v1_to_v2` now pre-seeds the rebuilt Blockchain's
  `entity_id_to_index` / `entity_index_to_id` maps from the v1 DB's
  `entity_indices` table before the replay loop. Compact entity-refs
  in persisted blocks now decode correctly through
  `get_block_by_number`. Verified end-to-end against a live mainnet
  v1 chain.db (183 blocks replayed cleanly).

## [1.1.0] — 2026-04-24

Minor release — two sequential hard forks activate inside the bootstrap
window. Coordinated validator-binary upgrade required before the first
activation height (100,000). Current tip is well below the activation
window; operators have ample runway to roll the upgrade.

### Added

- **Tier 8 (`LINEAR_FEE_HEIGHT = 100_000`)** — retires the flat per-tx
  floor in favor of a linear-in-stored-bytes formula
  `fee_floor = BASE_TX_FEE + FEE_PER_STORED_BYTE * len(stored)`.
  Longer messages pay proportionally for the bytes they pin to
  permanent state. Pre-fork replay paths (flat floor, legacy
  quadratic) keep their semantics so historical blocks validate
  unchanged.
- **Tier 8 cap raises** — `MAX_MESSAGE_CHARS` 280 → 1024 (short-post
  scale, not document scale) and `MAX_BLOCK_MESSAGE_BYTES`
  10,000 → 15,000.
- **Tier 9 (`BLOCK_BYTES_RAISE_HEIGHT = 102_000`)** — per-block
  throughput raise: `MAX_BLOCK_MESSAGE_BYTES` 15,000 → 45,000,
  `MAX_TXS_PER_BLOCK` 20 → 45, `MAX_BLOCK_SIG_COST` 100 → 250.
  Per-message cap unchanged. Targets ~24 GB/yr on-disk chain growth
  at 100-validator saturation. Attestation overhead dominates total
  size at that scale; future ceiling raises live in a sig-aggregation
  fork, not in byte caps.
- **Tier 9 economic retune** — `FEE_PER_STORED_BYTE` 1 → 3 at fork
  height (preserves bloat discipline under the wider byte budget);
  `TARGET_BLOCK_SIZE` 10 → 22 at fork height (~50% of the new
  `MAX_TXS_PER_BLOCK` for EIP-1559 base-fee targeting).

### Operator action required

- All honest validators must run 1.1.0 (or later) before block
  height 100,000. An older binary past that height will reject
  valid post-fork blocks and halt — losing its slot and bleeding
  stake to inactivity penalties until upgraded.

## [1.0.2] — 2026-04-23

Patch release — ship validator-2 in the default seed list so fresh
clients bootstrap against both validators instead of one.

### Changed

- `SEED_NODES` and `CLIENT_SEED_ENDPOINTS` in `messagechain/config.py`
  now include both validator-1 (35.237.211.12) and validator-2
  (35.231.82.12). A fresh install — `messagechain send "hi"` or
  `python server.py --mine` with no flags — connects to either
  validator automatically. Users keep full `--seed` / `--server`
  override.

## [1.0.1] — 2026-04-23

Patch release — operator ergonomics + gossip correctness. No consensus
or chain-state changes; no hard fork needed. Safe to roll in-place on
a running validator via a systemd restart.

### Added

- `reserve_leaf` RPC on `server.py`. Atomic WOTS+ leaf reservation for
  CLI signers co-resident with the validator daemon: eliminates the
  window in which an operator `messagechain transfer` and a
  block-producer `sign()` pick the same leaf and leak the private key.
- Global `--data-dir` flag on the CLI. When set, `transfer`, `stake`,
  and `send` load the daemon's on-disk keypair cache (skipping the
  multi-minute WOTS+ keygen) and call `reserve_leaf` for the signing
  leaf (collision-free with block production).
- `_load_key_from_file(..., accept_raw_hex=True)` opt-in parser. The
  CLI now accepts the daemon-side 64-char raw-hex keyfile when
  `--data-dir` is present, so the operator keyfile the validator unit
  consumes is directly usable for CLI signing.

### Fixed

- ANNOUNCE_TX gossip for `TransferTransaction` payloads. The handler
  previously only deserialized `MessageTransaction`, so a transfer
  gossiped from a peer was rejected as `invalid_tx_data` and never
  reached the block producer. Dispatch now reads the `type`
  discriminator in the serialized dict and routes to the matching
  validator.

## [1.0.0] — 2026-04-22

Initial mainnet release. Current chain minted 2026-04-22 after several
bootstrap-window re-mints; see the `_MAINNET_GENESIS_HASH` history
block in `messagechain/config.py` for the full list of abandoned
genesis hashes that preceded the current pin.

### Chain facts

- Network: `mainnet`, chain ID `messagechain-v1`
- Genesis block-0 hash: `4eeb9edaadb42f1a460e95919bc667a3173c4a84aa9b5488da040ac7a1c054f6`
- Block cadence: 10 minutes
- Genesis supply: 140M, fully allocated at block 0 (founder 100M +
  treasury 40M). Additional tokens enter circulation via block
  rewards (inflationary, perpetual low-rate issuance) — they are NOT
  pre-minted into genesis. See `GENESIS_SUPPLY` in
  `messagechain/config.py` for the pinned value and rationale.

### Added

- PoS consensus with attestation-based finality, slashing, and unbonding.
- WOTS+ quantum-resistant signatures with version-tagged crypto agility.
- Key rotation, governance, authenticated registration.
- Flat per-tx fee market (activates at height 98,000).
- Twelve scheduled hard forks through the bootstrap window (see
  `CLAUDE.md` for the canonical activation heights).
- CLI: `generate-key`, `verify-key`, `send`, `read`, `estimate-fee`,
  `stake`, `unstake`, `rotate`, `set-authority-key`.
- Zero runtime dependencies outside the Python stdlib.
