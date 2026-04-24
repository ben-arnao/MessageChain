# Changelog

All notable changes to MessageChain are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] — 2026-04-24

Minor release. Ships the **Tier 10 `prev` pointer** feature and pulls
the remaining bootstrap-era fork schedule forward so the feature can
be exercised end-to-end on the live chain within hours rather than
months. Consensus-breaking: requires all validators to upgrade before
the earliest activation height.

### Added

- **`prev` pointer on message transactions.** Optional single 32-byte
  `tx_hash` reference to a prior on-chain message, forming a
  protocol-agnostic single-linked list — apps can render the
  relationship as a reply, a chained long-form document, a citation,
  etc. The field is opt-in via tx `version=2`; `version=1` remains
  valid for prev-less messages.
- **Strict-prev validation.** When set, `prev` must resolve to a
  `MessageTransaction` already included in a strictly earlier
  persisted block. Self-reference, forward reference, and dangling
  reference are all rejected at the validation boundary.
- **ChainDB `tx_locations` index (schema v3).** Maps every message
  `tx_hash` to its `(block_height, tx_index)` for O(1) strict-prev
  resolution. One-shot migration `migrate_schema_v2_to_v3` walks
  persisted blocks to backfill; non-destructive, idempotent. The
  `messagechain migrate-chain-db` CLI now cascades v1 → v2 → v3 in a
  single invocation. `messagechain upgrade` runs migrations
  automatically.
- **`messagechain send --prev <tx_hash>`** CLI flag. Adds 33 stored
  bytes (1B presence flag + 32B hash) to the fee basis, priced at
  the live per-stored-byte rate. Pointer bytes do NOT count against
  `MAX_MESSAGE_CHARS` — the full 1024-char text budget stays intact.
- **Public feed (messagechain.org) surfaces `prev`.** `/v1/latest`
  JSON includes a `prev` hex field when a message carries a pointer;
  `feed.html` renders a `↳ refs <tx_hash_short>` row above the
  message text. Absent pre-fork and for prev-less post-fork messages.

### Changed (consensus)

- **Fork schedule pulled forward** so live operator testing is
  viable within the current bootstrap-era chain height:
  `LINEAR_FEE_HEIGHT` 4_300 → 300, `BLOCK_BYTES_RAISE_HEIGHT`
  4_500 → 350, `PREV_POINTER_HEIGHT` 6_000 → 400. All three forks
  activate in sequence within ~24 hours at the current block cadence.
  Validators MUST run 1.6.0 before the earliest activation height
  (300); an older binary at height ≥ 300 diverges consensus.

### Security

- No new security findings. Field-level tamper resistance on `prev`
  is covered by the standard signature commitment: the field is
  part of `_signable_data` at `version >= 2`, so flipping "no prev
  ↔ prev set" or swapping a `prev` value after signing invalidates
  the signature.

## [1.5.2] — 2026-04-24

Patch release. Bundles a security audit rollup with a P2P
maintenance-loop fix. No consensus changes.

### Security

- **C1 — validator-collusion censorship escape.**
  `BogusRejectionProcessor.process()` and its state-root simulator
  re-verified the embedded message tx without threading
  `current_height`, so at LINEAR-era heights `verify_transaction`
  fell back to the legacy quadratic fee rule. Low-fee txs that
  were valid under consensus but below the legacy floor were
  dismissed as "honest rejection," letting a lying validator
  escape slashing and successfully censor the message — directly
  defeating the stated primary-threat defense. Thread
  `block_height` through both paths and through mempool RBF.
  Regression test exercises the LINEAR-era gap window end to end.
  (ebde4d1)
- **C2 — supply-chain RCE in `messagechain upgrade`.** The
  upgrade CLI cloned and installed any `vX.Y.Z-mainnet` tag as
  root without verifying the tag's signature against an
  authoritative key. Now pins the release signer's SSH pubkey in
  `messagechain/release_signers.py` and runs `git tag -v` with
  `gpg.ssh.allowedSignersFile` pointed at that pinned list after
  clone, before the copytree swap. On verification failure:
  discard the clone, restore the backup, exit non-zero. The
  allowed-signers file is binary-local so a repo-level compromise
  cannot rotate the trust anchor. (ebde4d1)
- **C3 — fee-rule height threading in CLI send.**
  `calculate_min_fee` was called without `current_height`, so CLI
  users overpaid ~5–10× on short messages under the live LINEAR
  rule and low-fee dissident submissions were silently rejected
  client-side even though the chain would have accepted them.
  Thread tip+1 through the fee estimator; add an optional
  `current_height` arg to mempool RBF for consistent dispatch.
  (ebde4d1)

### Fixed

- **Maintenance loop now entity-aware.** After the 1.5.1
  entity-dedup rollout, the lower-entity side of each pair kept
  logging `p2p dedup: closing duplicate inbound session` every 30
  seconds. Root cause: the maintenance tick was keyed on
  `(host, listen_port)` and didn't recognize an inbound session
  from the same remote (keyed by the peer's ephemeral source
  port) as "already peered," so it re-dialed the seed every
  interval and each redial completed TLS+handshake just to be
  closed by the dedup. Now stores the remote's advertised listen
  port from the HANDSHAKE payload on `Peer.advertised_port`; the
  maintenance tick skips a seed `(host, port)` when any live,
  handshook peer already advertises that exact endpoint.
  Cosmetic at n=2, but the churn went quadratic as the validator
  set grew. (81298fb, a16a347)

## [1.5.1] — 2026-04-24

Patch release — P2P session dedup. No consensus changes.

### Fixed

- **Entity-level peer session dedup.** When two validators dialed
  each other simultaneously, each ended up with two live sockets to
  the same remote entity (one inbound on an ephemeral source port
  plus one outbound to the remote's listen port). The existing
  address-level dial dedup (keyed on `host:port`) couldn't catch
  this because the two sockets had genuinely different `host:port`
  tuples. Add a symmetric post-handshake tiebreaker — keep the
  session where the LOWER entity_id is the outbound dialer. Both
  ends apply the same rule against the same id pair, so both ends
  close the same TCP connection and the network converges to one
  session per peer pair. Observed on live mainnet after 1.5.0
  rollout; does not affect consensus or message delivery, only peer
  bookkeeping and metric honesty. (62eeabd, 18083cb)

## [1.5.0] — 2026-04-24

Minor release — validator operator onboarding automation plus a P2P
security hardening. No consensus changes.

### Added

- **Validator onboarding pack**: `messagechain init` / `doctor` /
  `config` / `rotate-if-needed` CLI surface, plus
  `scripts/install-validator.sh` for a one-command fresh-host install.
  Covers keyfile + hot-key generation, systemd unit install, seed
  configuration, reachability checks, and routine key rotation.
  (32ddfa7, bb1a91d, adc80b7, 7ee590e)
- **CLI reference** documents the full onboarding surface
  (`init`, `doctor`, `config`, `upgrade`, `rotate-if-needed`). (7ee590e)

### Security

- P2P handshake now gates on `CHAIN_ID` in addition to `genesis_hash`
  (defense-in-depth — an attacker flipping either field is rejected
  before the handshake completes). (35c7f7f)

### Fixed

- `install-validator.sh` clones the repo as root then chowns to the
  `messagechain` user, instead of attempting the clone as the
  unprivileged user against a root-owned target. (51ddf29)
- `init` now chowns `/etc/messagechain/*` to the `messagechain` user
  after writing, so the service user can read its own config. (6bd1445)
- Escape backticks in `install-validator.sh` progress echo so shell
  expansion doesn't garble output on some terminals. (1da5c30)
- `upgrade` runs as root end-to-end (fixes file-permission failures on
  validator hosts); `rotate` accepts `--yes` to skip the interactive
  prompt for automation; defer WOTS+ Merkle tree build during `init`
  so onboarding doesn't block on key derivation; env-scoped config
  lookup in `doctor` with actionable hint text. (91fbc0a, e3e9fcd)
- Drop duplicate `test_upgrade_command.py` left over after rebase. (8ce0ad7)

### Tests

- Cover `init`, `doctor`, `upgrade`, `rotate`, seeds, reachability,
  and config commands end-to-end. (bb1a91d)

## [1.4.0] — 2026-04-24

Minor release — **consensus-breaking hard fork**. Pulls the Tier 8
(linear-in-stored-bytes fees + 1024-char cap raise) and Tier 9
(throughput raise) activation heights forward into the bootstrap
window so the cap raise is testable on a realistic timeline with
the current two-validator network.

### Changed (consensus)

- `LINEAR_FEE_HEIGHT`: **100,000 → 4,300**. The linear formula
  (`BASE_TX_FEE + FEE_PER_STORED_BYTE × stored_bytes`) and the
  `MAX_MESSAGE_CHARS` raise to 1024 now activate ~28 days (nominal
  10-min blocks) after release instead of ~2 years.
- `BLOCK_BYTES_RAISE_HEIGHT`: **102,000 → 4,500**. Follows Tier 8
  immediately, same per-byte floor and tx-per-block bumps as before.
- **Tier 7 (`FLAT_FEE_HEIGHT = 98,000`) retired.** The flat-fee
  intermediate is superseded by Tier 8 at a lower height — in
  `calculate_min_fee` the LINEAR branch is checked first, so at height
  98,000 the linear rule is already in force and the flat floor
  never activates. The constant is kept for code-path audit clarity.
- The Tier-2 `FEE_INCLUDES_SIGNATURE_HEIGHT = 64,000` sig-aware
  quadratic rule is similarly unreachable for `MessageTransaction`
  (Tier 8 precedes it). Non-MessageTx tx types (transfer / stake /
  governance / etc.) still traverse the sig-aware branch via
  `enforce_signature_aware_min_fee`.

### Fixed

- `verify_transaction` now delegates fee-floor selection to
  `calculate_min_fee` (single source of truth) instead of branching
  on each gate locally. Previously, at heights in
  `[LINEAR_FEE_HEIGHT, FEE_INCLUDES_SIGNATURE_HEIGHT)` the verifier
  fell through to the legacy quadratic rule while `calculate_min_fee`
  had already routed to linear — the two disagreed. Unified. Only
  surfaces under compressed schedules where LINEAR precedes FLAT.

### Upgrade notes

Consensus-breaking. Both validators MUST upgrade before height
4,300 (~28 days from release at nominal pace). The two-validator
bootstrap set makes coordination trivial; re-tighten the
50,000-block runway rule in CLAUDE.md once the validator set grows.

## [1.3.1] — 2026-04-24

Patch release — P2P handshake symmetry for peer observability.

### Fixed

- The inbound side of the P2P handshake now echoes its own `HANDSHAKE`
  back to the dialer, so the dialer's `Peer` record populates with the
  peer's `entity_id`, `chain_height`, and `version`. Before this,
  outbound peers on `messagechain peers` output showed `Entity: (none)`,
  `Height: 0`, and `Version: unknown` indefinitely. Chain sync was
  unaffected (it runs off the inbound path) — this was an observability
  fix, not a liveness fix. Applied to both the `Server` runtime
  (`server.py`) and the `Node` class (`messagechain/network/node.py`).

### Added

- `Peer.handshake_sent` flag (`messagechain/network/peer.py`) — guards
  the new echo against re-firing on a reconnecting peer and is set on
  outbound at dial time for symmetry.

## [1.3.0] — 2026-04-24

Minor release — fork-skew halt semantics. An out-of-date binary now
halts cleanly with an actionable operator message instead of rejecting
post-fork blocks as "invalid" and spamming peer-ban state.

### Added

- `MAX_SUPPORTED_BLOCK_VERSION` config constant (currently 1). A
  future hard fork that changes consensus semantics bumps this to 2+;
  `messagechain upgrade` installs the binary that understands it.
- `BinaryOutOfDateError` (`messagechain/core/blockchain.py`) — a
  distinct exception class (sibling to `ChainIntegrityError`) raised
  by `validate_block` when a block carries a version newer than this
  binary understands. Semantically: "the network has moved past my
  binary" — NOT "the chain is broken" and NOT "the block is malicious".
- `server.py` installs an asyncio loop-level exception handler that
  converts `BinaryOutOfDateError` from any task into a clean
  `os._exit(42)` with a single clear journald entry:
  `BINARY OUT OF DATE -- HALTING: Block at height N has version V,
  but this binary supports up to W. Run \`messagechain upgrade\``.
  Systemd's `StartLimitBurst=5` turns the repeated exit into a
  failed-unit state, which is exactly the operator signal we want.

### Changed

- `Blockchain.validate_block` no longer treats unknown-version blocks
  as soft rejections. A `version > MAX_SUPPORTED_BLOCK_VERSION` now
  raises `BinaryOutOfDateError` (halt). A `version < 1` (malformed
  input, not fork-skew) remains a regular `(False, reason)` rejection
  so peer-ban machinery fires normally.

### Operator UX

No action needed to adopt 1.3.0 — the halt path only fires when a
future fork activates. When that happens on an old binary:

1. The unit exits with code 42 and journald records
   `BINARY OUT OF DATE -- HALTING`.
2. Systemd tries 5 restarts, hits `StartLimitBurst`, marks the unit
   failed.
3. Operator sees the failed unit, runs `messagechain upgrade --yes`.
4. New binary boots, accepts the blocks that the old one couldn't,
   catches up via normal P2P sync.

Previously, the old binary would spin instead of halting — rejecting
every post-fork block as "invalid block", ban-scoring every peer that
relayed one, and silently losing proposal slots to inactivity
slashing. 1.3.0 turns that failure mode into a fast, loud, actionable
halt.

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
