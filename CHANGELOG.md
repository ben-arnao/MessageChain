# Changelog

All notable changes to MessageChain are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
