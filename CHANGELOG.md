# Changelog

All notable changes to MessageChain are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.10.0] — 2026-04-26

Minor release.  Hard fork (Tier 12) opens the chain to non-English
speech.  Closes the largest mission/mechanism mismatch in the project:
the public framing pitches MessageChain as a censorship-resistant
ledger for dissidents and coerced-speech contexts, but the protocol
rejected every codepoint outside printable ASCII (32-126), shutting
out the bulk of the world's writing systems.

### Added -- Tier 12 hard fork

- **`MessageTransaction` plaintext rule, post-INTL_MESSAGE_HEIGHT.**
  At/after `INTL_MESSAGE_HEIGHT = 1500`, message plaintexts are NFC-
  normalized UTF-8 whose codepoints fall under Unicode General_Category
  L*/M*/N*/P*/Zs (letters, marks, numbers, punctuation, space), plus a
  narrow allowlist of two format characters required for script
  shaping: U+200C ZWNJ and U+200D ZWJ.  Bidi override / isolate
  characters (U+202A-U+202E, U+2066-U+2069) are explicitly rejected
  as spoofing vectors.  All `S*` (symbols including emoji, math glyphs,
  currency), `C*` outside the ZWJ/ZWNJ allowlist (controls,
  surrogates, private-use, unassigned, other format chars), and Zl/Zp
  separators are rejected.  Pre-activation: legacy printable-ASCII rule
  (32-126) unchanged so historical blocks replay deterministically.
  (`messagechain/core/transaction.py`, `messagechain/config.py`)
- **Why categories, not a script allowlist.**  The L/M/N/P/Zs
  whitelist is structural -- "characters that are letters, marks,
  numbers, punctuation, or space" -- and has no political knob.  A
  "popular scripts" allowlist would force a discretionary admission
  rule (which scripts count?  who decides when Tibetan or Burmese
  qualifies?), and the project's audience is disproportionately
  small-population languages in coerced-speech contexts that any such
  cutoff would strand.  Future Unicode scripts land in L/M/N
  automatically and become valid without a config change.
- **Coverage, by speaker count.**  Every modern living language with
  >=10M speakers is covered: Latin (English, Spanish, French, German,
  Vietnamese, Polish, Turkish, Indonesian, Swahili, Filipino, ...),
  Cyrillic (Russian, Ukrainian, Bulgarian, Serbian, Kazakh, ...),
  Arabic (Arabic, Persian, Urdu, Pashto, Uyghur, ...), CJK (Mandarin,
  Cantonese, Japanese, Korean), Indic (Hindi, Bengali, Tamil, Telugu,
  Marathi, Gujarati, Kannada, Malayalam, Sinhala, Punjabi, Nepali),
  Southeast Asian (Thai, Lao, Khmer, Burmese), plus Greek, Hebrew,
  Armenian, Georgian, Amharic, Tigrinya, Tibetan.
- **Storage cap unchanged in numerator, semantically shifted in
  denominator.**  `MAX_MESSAGE_CHARS = 1024` still binds, but post-fork
  it caps UTF-8-encoded plaintext bytes (1024 bytes) rather than ASCII
  characters.  English users still get ~1024 chars; Cyrillic / Greek /
  Hebrew users get ~512; CJK users get ~341.  Each pays
  `BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * len(stored)` -- the
  fee market already prices stored bytes, so bloat discipline is
  unchanged across regimes.
- **NFC normalization required (not auto-applied).**  Without this
  rule "café" encoded as U+00E9 vs U+0065+U+0301 would yield two
  distinct tx_hashes for the same visible message, breaking dedup,
  prev-pointer references, and feed-equality checks.  The chain
  rejects non-NFC input rather than silently normalizing -- determinism
  + replay sanity outweigh client-side convenience.

### Changed

- **`messagechain send` pre-flight check is now UTF-8-aware.**
  Replaces the pre-1.10.0 ASCII-only diagnostic that named em-dash /
  smart-quotes / ellipsis as "common culprits."  Post-fork those are
  legitimate punctuation (P* category) and the friendly diagnostic
  shifts to byte-cap overruns -- the only failure mode the CLI can
  pre-empt locally without a chain round-trip.
- **`MessageTransaction.deserialize` and `to_dict` now use UTF-8.**
  Byte-identical to the legacy ascii-encode path for ASCII-only
  plaintexts; correctly carries multi-byte sequences for post-fork
  messages.

### Deployment

- `INTL_MESSAGE_HEIGHT = 1500` is well above the live tip (~451 at
  release time), giving operators ~7 days of upgrade runway before
  the fork point -- substantially longer than the ~100-minute runways
  used for Tier 8-11.  This is a UX-visible change for every wallet
  and reader client, not just operators, so the wider window lets
  third-party tooling catch up.
- No operator action beyond the standard `messagechain upgrade`.  The
  validator binary picks up the new validation function on restart;
  pre-fork blocks continue to validate under the legacy ASCII rule
  through height 1499 and v1/v2 message wire formats keep working
  unchanged at all heights.

## [1.9.0] — 2026-04-26

Minor release. Hard fork (Tier 11) plus an opt-in operator feature.
Two structurally-correct fixes for the cold-start gap that the 1.8.x
faucet exposed: the chain itself now lets fresh wallets post their
first message in one tx, and the faucet now uses client-side
proof-of-work instead of pure rate-limiting so Tor / privacy users
stay first-class.

### Added — Tier 11 hard fork

- **`MessageTransaction.sender_pubkey` (v3 txs).**
  At/after `FIRST_SEND_PUBKEY_HEIGHT = 500`, message txs may carry
  an optional 32-byte `sender_pubkey` field.  When the sender's
  entity_id is not yet on chain, the field is required and is
  installed in `chain.public_keys` on apply.  Mirrors
  `TransferTransaction.sender_pubkey` exactly so messaging works
  for receive-to-exist wallets in one round-trip instead of
  needing a transfer-first dance to install the pubkey.  Closes
  the asymmetry where the faucet could fund a wallet but the
  recipient still couldn't post a first message until they did
  some other on-chain action.  Backwards-compatible: v1 / v2 txs
  remain valid; v3 is rejected pre-activation; activation gate is
  enforced at every validation entry point (mempool admit,
  validate_block, validate_block_signatures).
  (`messagechain/core/transaction.py`,
  `messagechain/core/blockchain.py`, `messagechain/config.py`)
- **`messagechain send` auto-attaches `sender_pubkey` on first send.**
  Probes the chain for the sender's pubkey via `get_entity`; when
  not registered AND past `FIRST_SEND_PUBKEY_HEIGHT`, sets
  `include_pubkey=True` so the chain installs on apply.  User
  experiences "get tokens, then send" as two CLI invocations
  instead of three.

### Added — Faucet PoW gate

- **`GET /faucet/challenge?address=<hex>`** mints a per-address
  challenge: 16 random seed bytes + difficulty + 10-min TTL.
- **`POST /faucet`** now requires `{address, challenge_seed, nonce}`.
  Server verifies that `sha256(seed || nonce_be_8 || address)` has
  at least `FAUCET_POW_BITS = 22` leading zero bits.  Average ~5s
  on desktop, ~15s on mobile in pure-JS sha256.  Per-/24 IP cooldown
  and daily aggregate cap remain as defense-in-depth.  Replay-
  protected: each challenge consumed atomically on use.  Address-
  bound: a nonce solving the challenge for address A cannot be used
  for address B.
- **No CAPTCHA dependency.**  Pure-JS sha256 in a WebWorker.  Tor
  and privacy users pay CPU, not credentials.  No third-party
  scripts on the public feed page.
- **Why PoW vs CAPTCHA**: the project's no-external-deps memory
  rules out Google/hCaptcha, and CAPTCHAs are actively hostile to
  Tor users (the censorship-resistance audience).  Per-address
  PoW makes bulk Sybil farming uneconomical (each new address
  costs the attacker the same CPU time as an honest user); the
  daily cap caps the operator's worst-case daily exposure.
  (`messagechain/network/faucet.py`,
  `messagechain/network/public_feed_server.py`,
  `messagechain/static/feed.html`)

### Changed

- **`messagechain send` "Unknown entity" hint** now points users at
  the public faucet URL and explains the Tier 11 auto-include flow:
  "get tokens at messagechain.org, wait one block, retry."  The
  bootstrap step list is now 3 items, not the awkward 4-step
  "transfer-first then message" workaround that 1.8.x described.
- **Per-address one-shot rate limit** is unchanged but the failure
  path is no longer reachable via cheap address-spam: the PoW
  consumes ~5s of attacker CPU per probe.

### Deployment

- Activation height `FIRST_SEND_PUBKEY_HEIGHT = 500` is well above
  the live tip (~451 at release time), giving operators ~10
  blocks (~100 minutes) of runway to upgrade before the fork
  point.  Validators on 1.8.x keep producing pre-Tier-11 blocks
  through height 500; v3 txs land starting at 501.
- The faucet PoW change is operator-side and takes effect
  immediately on validator restart -- no fork dependency.

## [1.8.2] — 2026-04-26

Patch release. Fixes the threadsafe-relay gap exposed by the 1.8.1
faucet drip path. No consensus changes.

### Fixed

- **`_rpc_submit_transfer` and `_rpc_submit_transaction` now schedule
  their gossip-relay task safely from any thread.** The two handlers
  previously called `asyncio.create_task(self._relay_tx_inv(...))`
  directly, which only works inside the main event loop's thread.
  When invoked from the public-feed faucet's worker pool (a thread
  outside asyncio), the call raised `RuntimeError: no running event
  loop` AFTER the mempool had already accepted the tx. The handler
  caught the exception and returned `{"ok": false, "error": "Internal
  error"}` -- so the faucet UI looked broken even though the drip
  tx was sitting in mempool waiting for the next block. Worse, on
  retry the cold-key would advance to the next leaf and a SECOND
  conflicting tx would land in mempool. The new
  `Server._schedule_coro_threadsafe` helper detects whether it's
  inside the main loop and dispatches via `create_task` or
  `run_coroutine_threadsafe` accordingly. (server.py)
- **`Server._main_loop`** captured at `start()` so cross-thread
  callers have a stable reference to the asyncio loop without
  having to chase `get_event_loop()` (which is deprecated and
  thread-local in 3.12+).

## [1.8.1] — 2026-04-25

Patch release. Fixes the faucet drip fee so transfers to brand-new
recipients (which is every recipient, by design) actually land. No
consensus changes.

### Fixed

- **Faucet now pays `MIN_FEE_POST_FLAT + NEW_ACCOUNT_FEE` per drip.**
  The 1.8.0 wiring hardcoded `fee=MIN_FEE_POST_FLAT=1000`, but the
  chain charges a `NEW_ACCOUNT_FEE=1000` surcharge on top of the
  base floor when the recipient has no on-chain history yet.  Faucet
  recipients are by definition brand-new wallets (a fresh user's
  first contact with the chain), so every drip hit
  `Transfer to brand-new recipient requires fee >= 1100; got 1000`
  and bounced.  The chain rejection was clean (no funds moved, no
  rate-limit slot consumed -- per the
  test_submit_failure_does_not_consume_quota guard) but the user-
  facing behavior was still "faucet returns an error every time."
  Now: fee = 1000 + 1000 = 2100 per drip.  At
  FAUCET_DRIP=1000, each drip costs the faucet 3100 tokens
  (1000 sent + 2100 fee), so a 200,000-token reserve covers ~64
  drips before refill -- just over a day at the daily cap.

## [1.8.0] — 2026-04-25

Minor release. Closes the receive-to-exist cold-start gap with an
opt-in operator-funded faucet on the public feed server. Pure
addition: no consensus changes; default-off so existing operators
get identical behavior.

### Added

- **Cold-start funding faucet (`POST /faucet`).**
  When the validator is launched with `--faucet-keyfile <path>` and
  `--public-feed-port` is set, the public feed exposes a JSON POST
  endpoint at `/faucet` that drips a fixed `FAUCET_DRIP=1000` tokens
  to the requested address. Three rate-limit layers stack: per-/24
  IP cooldown (24h), per-address one-shot (in-memory for the process
  lifetime), and a global daily cap (`FAUCET_DAILY_CAP=50`). Closes
  the receive-to-exist gap that made fresh wallets unable to send
  their first message without an out-of-band token transfer -- the
  dominant cold-start failure documented during the 2026-04-25
  submit-UX probe. (`messagechain/network/faucet.py`,
  `messagechain/network/public_feed_server.py`,
  `server.py:_build_faucet`)
- **"Get starter tokens" UI on `messagechain.org`.**
  Collapsible section above the live feed with an address input,
  one-line bootstrap explanation, and a "Get tokens" button that
  POSTs `/faucet`. Hidden when the validator does not advertise
  `faucet_enabled=true` on `/v1/info`. Counter shows remaining
  drips today so a visitor sees the daily cap state at a glance.
  (`messagechain/static/feed.html`)
- **`/v1/info.faucet`** block: when the faucet is enabled the info
  endpoint reports `{drip_amount, daily_cap, remaining_today}` so
  the UI does not need a separate roundtrip and operator dashboards
  can poll the cap counter.
- **`scripts/generate_faucet_key.py`** mirrors the cold-authority
  generator: produces a tree_height=16 wallet key, prints the public
  key on stdout, pushes private material straight to GCP Secret
  Manager via stdin (no filesystem touch).

### Operator workflow

1. `python scripts/generate_faucet_key.py <project> mc-faucet-key`
   -> records the printed pubkey.
2. Update the validator deploy script to fetch the secret to
   `/dev/shm/mc-faucet-key` (raw 64-char hex, mode 0400) at boot
   and pass `--faucet-keyfile /dev/shm/mc-faucet-key` to `server.py`.
3. Restart the validator (cold keygen ~10-20 min the first time;
   warm restarts hit the keypair cache).
4. From any wallet with sufficient balance, transfer the desired
   runway: `messagechain transfer --to <faucet-pubkey>
   --amount <N>`. A common starting allocation is
   `FAUCET_DRIP * 200 = 200,000` tokens (~4 days at peak cap).
5. Verify: `curl -X POST -H 'Content-Type: application/json'
   -d '{"address":"<test-entity-id>"}' https://messagechain.org/faucet`.

## [1.7.7] — 2026-04-25

Patch release. Closes the five submit-side UX gaps surfaced during
the 2026-04-25 first-ever-user-message probe and the v2 receipt-
subtree-root registration debug. No consensus changes; CLI-only.

### Fixed

- **`messagechain send` auto-fee was rejected by the chain.** The
  CLI computed `local_min` under the live LINEAR rule and passed it
  to `create_transaction`, but did not thread `current_height`, so
  `create_transaction` fell back to the legacy quadratic floor and
  rejected fees that the chain would have accepted at LINEAR. Net
  effect on mainnet (LINEAR_FEE_HEIGHT=300, tip~432): every fresh
  user with auto-fee hit `Fee must be at least 323 ...` and bounced.
  Pass `target_height` through; client-side floor now matches the
  on-chain rule.
- **`messagechain send` non-ASCII messages now produce a friendly
  diagnostic, not a Python traceback.** Pasting from a word
  processor (smart-quotes, em-dash, ellipsis) used to surface
  `UnicodeEncodeError: 'ascii' codec can't encode character ...`
  with the call stack. Now: clean error naming the offending
  character + codepoint + position, with a list of common culprits.
- **`Unknown entity -- must register first` now explains the
  receive-to-exist model.** A fresh wallet trying to send its first
  message gets rejected because it has no on-chain history to fund
  the fee. Pre-1.7.7 the CLI surfaced a bare `Failed: ...` with no
  next step, so users assumed the chain was broken. The CLI now
  detects this specific error and prints the bootstrap path: ask an
  existing token holder to send a small transfer to the user's
  address, then retry.
- **`messagechain set-receipt-subtree-root` now exposes a
  `--cold-leaf N` flag and surfaces the leaf used after signing.**
  Cold-key leaf state is not tracked on chain (see
  `apply_set_receipt_subtree_root`), so successive invocations with
  the default leaf 0 produce different messages signed at the same
  WOTS+ leaf -- a leaf-reuse violation the chain rejects. Operators
  must self-track; the post-signing output now says "Cold leaf: N
  (BURNED)" + "NEXT TIME pass --cold-leaf N+1". Discovered while
  registering validator-2's receipt root on 2026-04-25 -- worked
  around manually; now first-class.
- **`messagechain set-receipt-subtree-root` `--server` mismatch
  error now points at the workaround.** When the operator targets
  a peer validator (broadcasting through a node other than the one
  being registered), the local-root fetch returns the peer's own
  entity_id and the safety check fired with no actionable next
  step. Now: explains the cross-validator submission case and tells
  the operator to pass `--root <hex>` (with a pointer to the boot-
  log line where the root is printed).

## [1.7.6] — 2026-04-25

Patch release. Adds an outbound-click redirect on the public feed
viewer so operators can count how many people click through to the
GitHub repo from `https://messagechain.org`. Cosmetic; no protocol
or consensus impact.

### Added

- **`GET /gh` on `PublicFeedServer`** — 302 redirect to
  `https://github.com/ben-arnao/MessageChain`. The homepage's
  `<a>github</a>` link now points here instead of straight at
  GitHub, so each click lands in the Caddy access log under a path
  the `mc-feed-stats` script can grep for and report alongside the
  feed-viewer headcount.

## [1.7.5] — 2026-04-25

Patch release. Closes the mempool-sweep gap that prevented
SetReceiptSubtreeRoot transactions from ever landing on chain
when the validator entity had a non-zero hot-key leaf watermark.
No consensus changes.

### Fixed

- **`_sweep_stale_pending_txs` now treats SetReceiptSubtreeRoot
  as cold-signed.** Observed on mainnet 2026-04-25 when registering
  validator-2's receipt-subtree root post cold-key promotion: the
  RPC accepted the tx into `_pending_authority_txs` (returning a
  tx_hash), but the sweep run immediately before each block
  proposal compared the cold key's leaf_index (single digits) against
  the validator entity's hot-key leaf_watermark (high triple digits
  after sustained block production), declared it "stale leaf reuse,"
  and dropped it before `propose_block` could pull it. The carve-out
  for cold-signed txs only listed `RevokeTransaction` and
  cold-promoted `UnstakeTransaction`; `SetReceiptSubtreeRootTransaction`
  fell through. Net effect: a hot/cold validator could never register
  its receipt-subtree root on-chain, which broke every receipt that
  validator would issue at evidence-admission time. Carve-out now
  covers `SetReceiptSubtreeRootTransaction` explicitly.

## [1.7.4] — 2026-04-25

Patch release. Adds the missing operator CLI for registering a
validator's receipt-subtree root from a cold key, plus the RPC the
CLI relies on. No consensus changes.

### Fixed

- **`messagechain set-receipt-subtree-root` exists.** After the cold-
  authority-key promotion landed on validator-2 on 2026-04-25, the
  boot-time receipt-subtree auto-submit detected the cold-key gap
  and printed an actionable warning telling the operator to run
  `client.py set-receipt-subtree-root`. That command did not exist
  in either `client.py` or the `messagechain` CLI. Net effect: v2's
  receipt-subtree root has sat unregistered since the promotion,
  which would have made every receipt issued by v2 fail at evidence-
  admission time and collapsed the censorship-evidence pipeline for
  any submitter routed through that node. The new CLI fetches the
  validator's local root via the new `get_local_receipt_root` RPC
  (no scraping it out of journald or cache files), signs the
  `SetReceiptSubtreeRoot` tx with the cold key, and broadcasts via
  `set_receipt_subtree_root`. Refuses to broadcast when the remote
  validator's entity_id does not match the cold key's, exits zero
  when the on-chain root already matches (idempotent re-runs), and
  supports `--root` + `--print-tx` for fully air-gapped sign-on-cold,
  broadcast-on-hot workflows.
- **Boot-time warning text now references the real command.** The
  warning in `_bootstrap_receipt_subtree` previously pointed at
  `client.py set-receipt-subtree-root`; updated to the correct
  `messagechain set-receipt-subtree-root` invocation with concrete
  arguments.

### Changed

- **Public feed header**: replaced the tagline with a bare GitHub
  link, dropping one line of chrome above the message stream.
  (e711d28, b9c09dd)

## [1.7.3] — 2026-04-25

Patch release. The `get_nonce` RPC now returns the mempool-aware
next nonce, matching what the submit-side validators
(`_rpc_submit_transaction`, `_rpc_stake`, `_rpc_unstake`,
`_rpc_set_authority_key`, etc.) gate on. Previously the read
path returned the chain-state nonce only while the write path
gated on `_get_pending_nonce_all_pools`, so a client that
fetched the nonce while a prior tx was still in mempool would
sign with a stale value and get rejected with `Invalid nonce:
expected N+1, got N` until the prior tx landed in a block
(~10 min per wedge). Observed on mainnet 2026-04-25 when
chaining a transfer immediately after a set-authority-key
submission. Read and write paths now share the same helper, so
the contract holds for any pool combination. Empty-mempool
behavior is unchanged. No consensus change.

## [1.7.2] — 2026-04-24

Patch release. `messagechain set-authority-key` and `messagechain
rotate-key` now use the daemon's cached WOTS+ keypair when invoked
with `--data-dir`, mirroring the existing fast-path in `cmd_stake`,
`cmd_unstake`, and `cmd_transfer`. Previously both commands called
`Entity.create(private_key)` unconditionally on every invocation,
regenerating the full Merkle tree from scratch — a 20-30 minute
operation at production `tree_height=20` (1M leaves) that wedged
the CLI on a live validator host. Observed on mainnet 2026-04-24
when promoting a cold authority key to separate withdrawal
authority from block-signing authority. New regression tests bind
all four authority-gated CLI flows (stake / unstake /
set-authority-key / rotate-key) to the same cached-entity contract
so the next addition can't silently regress. Also adds
`scripts/generate_cold_authority_key.py`, an operator utility that
generates a cold authority key and pipes the secret material
directly to GCP Secret Manager via stdin (private material never
touches disk). No consensus change.

## [1.7.1] — 2026-04-24

Patch release. Display-only bugfix in `messagechain stake` and
`messagechain unstake`: the CLI attempted to print
`result['staked']` and `result['balance']` on successful
submission, but the RPC handlers return `{entity_id, tx_hash,
status}` — raising `KeyError` and exiting 1 even though the tx
had already been queued for inclusion. Operators saw the
exception and reasonably assumed the submission failed. The fix
prints `tx_hash` and `status` from the real response and adds a
regression test that exercises both commands against the actual
server contract so the next contract shift fails at test time
rather than silently on mainnet. No consensus change; operators
can upgrade at their convenience, but should upgrade before
driving the next stake/unstake so the CLI exits cleanly.

## [1.7.0] — 2026-04-24

Minor release. Extends the WOTS+ leaf-reuse gate to evidence txs
and custody proofs so every hot-key-signed tx type enforces the
same single-use-leaf invariant. Consensus-affecting: block-
validity rules are stricter and the state-root simulator gains a
new watermark bump for admitted custody proofs — requires all
validators to upgrade before producing blocks with the new
transaction flavors.

### Security

- **Round-4 defense-in-depth: evidence-tx + custody-proof WOTS+
  leaf-reuse gate.** Previously, every other hot-key-signed tx
  type (message, transfer, stake, governance, attestation,
  finality vote, authority) enforced the `leaf_index >=
  leaf_watermarks[submitter_id]` gate at both per-tx validation
  and the block-level `_check_leaf` dedupe. Evidence txs
  (censorship, bogus-rejection, inclusion-list violation,
  non-response) and custody proofs skipped both gates. A
  malicious submitter could sign a MessageTx +
  CensorshipEvidenceTx at the same `leaf_index` in one block (or
  across blocks) and leak the one-time WOTS+ secret by publishing
  two signatures under the same private material. Damage stopped
  at submitter self-compromise — the ratcheted watermark elsewhere
  keeps the leaked leaf unusable for any future tx — so this was
  not critical, but closing it here keeps the invariant uniform
  across tx types and insures against future refactors that could
  make leaf-leak actually exploitable. The block-level
  `_check_leaf` loop now iterates evidence txs and custody proofs
  (hot-key leaf namespace keyed by `submitter_id` / `prover_id`);
  each evidence validator gains the watermark check;
  `_apply_archive_rewards` bumps the watermark for every admitted
  custody-proof prover with an on-chain pubkey; the state-root
  simulator mirrors the bump so sim and apply stay in lockstep.
  Custody proofs from hobbyist-archivist provers without on-chain
  pubkeys are exempt (no prior leaf to collide with). (15d5539)

### Changed

- **Public feed: `refs` spans are now clickable anchors.** Each
  message card on https://messagechain.org now carries
  `id="tx-<full_hash>"` so a prev-pointer row can link to its
  target via URL fragment. When the referenced tx is in the
  current feed window, the ref span is an `<a href="#tx-<hash>">`
  that scrolls to and highlights the target card (CSS `:target` +
  keyframe flash). When the reference points at a tx older than
  the last LIMIT messages, the link is marked `.missing` (muted
  color, `pointer-events: none`) so users can see the reference
  exists but know it's out of view rather than clicking a dead
  link. README also surfaces `messagechain send --prev <tx_hash>`
  in the wallet CLI-reference block. (276e294)

### Fixed

- **Test hygiene: deterministic slot-0 proposer in
  `TestAckForgeryRejected`.** The ack-forgery regression suite
  added in 1.6.0 gave `self.proposer` and `self.target` equal
  stake, so the PoS slot-0 election was a coin flip against
  genesis-timestamp entropy — `test_legitimate_ack_accepted_and_
  commit_height_honored` flaked ~50% of the time. Proposer stake
  is now `VALIDATOR_MIN_STAKE * 1000` (vs. target's ×10) so the
  election is reliably deterministic. No production code change.

## [1.6.1] — 2026-04-24

Patch release. Fixes the `messagechain upgrade` CLI ordering bug
that bricked validator-1 during the 1.5.2 -> 1.6.0 rollout and
required a manual backup-directory restore before the service could
come back up. No consensus changes.

### Fixed

- **`messagechain upgrade` ordering: clone + verify now run BEFORE
  the live install is moved to backup.** The 1.5.x CLI moved
  `/opt/messagechain` to a `.bak-*` directory and THEN invoked
  `_upgrade_verify_tag_signature`, which lazily imports
  `messagechain.release_signers` from sys.path. With the install
  directory already gone, the import raised `ModuleNotFoundError`
  and the upgrade aborted with the service stopped and no live
  install — leaving the operator to `mv .bak-* /opt/messagechain`
  by hand. Fixed by reordering: clone to `/tmp`, verify against the
  still-in-place install's pinned signer list, stop the service,
  move the install to backup, copy the verified clone into place.
  Failure in clone or verify now leaves the prior binary running
  and untouched (zero downtime on rejected upgrades). Regression
  test asserts the ordering invariant.

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
