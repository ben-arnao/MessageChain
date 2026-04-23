# Changelog

All notable changes to MessageChain are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
