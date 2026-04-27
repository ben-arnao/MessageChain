# Changelog

All notable changes to MessageChain are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.24.0] — 2026-04-26

Minor release. **Hard fork: Tier 22 — voter rewards on passed
proposals** (activates at `VOTER_REWARD_HEIGHT = 19000`). Plus a
faucet rate-limit retune and a web-UI prose trim — both
non-consensus, active immediately.

### Governance — Tier 22: voter rewards on passed proposals (activates block 19000)

Hard fork at `VOTER_REWARD_HEIGHT = 19000` (rides above Tier 21's 17000
with the established ~2000-block runway). Reward-aligned governance
participation without a rubber-stamp incentive.

- **Per-proposal escrow funded by a proposer surcharge.** Post-fork,
  every `ProposalTransaction` debits an additional
  `VOTER_REWARD_SURCHARGE = 50_000` from the proposer's balance on
  top of the regular tx fee. The surcharge is held in
  `ProposalState.voter_reward_pool` — debited from the proposer, not
  minted, not burned. Net inflation invariant is preserved because
  the tokens stay in circulation, just sequestered until close.
- **Pay-on-pass, retrospective only.** At proposal close, if
  `yes_weight × 3 > total_eligible × 2` (the existing supermajority
  rule, evaluated in live-weight mode like the H6 binding tally),
  the pool is distributed pro-rata-by-live-stake to YES voters whose
  `get_staked > 0` at close. Proposals that fail the threshold burn
  the entire pool. No-voters and slashed-out yes-voters get nothing.
  The asymmetry is intentional: rewarding both sides degenerates back
  into pay-for-participation, which incentivizes uninformed voting.
- **Whale cap.** A single yes-voter cannot collect more than
  `VOTER_REWARD_MAX_SHARE_BPS / 10_000 = 25%` of the pool, even if
  they hold all the yes-side stake. Excess from the cap burns
  deterministically. Without this cap, a 70%-stake validator captures
  ~70% of every reward and the system reduces to "validators tax
  proposers via a 2/3 rubber stamp on their own proposals."
- **Dust burns deterministically.** Integer-division remainder from
  pro-rata distribution burns rather than going to a "lucky voter" —
  every node agrees on the post-distribution state byte-for-byte.
- **Validation enforces fee + surcharge affordability.** Post-fork
  proposal admission requires the proposer's balance to cover both
  the tx fee and the surcharge; pre-fork validation is unchanged so
  historical replay is byte-identical.
- **Pre-fork proposals are no-ops.** Pre-fork-height proposals carry
  `voter_reward_pool = 0` and `finalize_voter_rewards` is a no-op for
  zero-pool proposals — replay through Tier 22 height does not
  perturb their state.

### Changed (off-chain, active immediately)

- **Faucet: 15-min rolling window cap replaces daily cap** (401d940).
  The public-feed faucet now meters per-IP requests over a 15-min
  rolling window instead of a calendar-day cap, smoothing out the
  abuse vector where one IP could exhaust the daily budget in
  seconds at midnight UTC.
- **Web UI: trim hero/faucet/footer prose; consolidate entity
  profile sections** (3e49408). Tightens the public-facing copy on
  https://messagechain.org and folds duplicated entity-profile
  sub-sections together. Cosmetic only — no API changes.

## [1.23.0] — 2026-04-26

Combined release rolling up everything since the 1.21.0 tag — the
1.22.0 metadata bump and Tier 21 reward-cap rework were prepared on
`origin/main` but never tagged, so this version folds Tier 20 (soft
equivocation slash), the fork-emergency detector, Tier 21
(halvings-aware proposer reward cap), and the seed-divestment
retune-v2 into a single coordinated release. Validators upgrading
from 1.21.0 land on 1.23.0 directly.

This is the first release covering Tier 20, Tier 21, and the
divestment retune; pre-fork chain history replays byte-identically
under all three forks.

### Consensus — Tier 20: soft equivocation slash (activates block 15000)

Hard fork at `SOFT_SLASH_HEIGHT = 15000` (rides above Tier 19's 13000
with a ~2000-block runway, ~14 days at 600 s/block). Honest-operator
survivability under accidental dual-sign.

- **Equivocation penalty drops from 100% to 5% per offense.** Any
  double-proposal / double-attestation / finality-double-vote
  evidence used to wipe 100% of the offender's stake + full
  bootstrap escrow + permanently ban via `slashed_validators`. That
  penalty matched a deliberate Byzantine attack but was catastrophic
  for the most common honest-operator failure mode (failover
  misconfig, restored backup with the old node still running,
  restart race). Post-fork the slash is partial —
  `SOFT_SLASH_PCT = 5` of stake + the same fraction of bootstrap
  escrow + the same fraction of any pending unstakes. The validator
  stays in the set with reduced stake; only `_processed_evidence`
  dedupes so the SAME piece of evidence cannot be applied twice.
- **Repeat-offender economics fall out without escalation logic.**
  Each new piece of evidence slashes 5% of what remains:
  `(1 - 0.05)^N` — 10 mistakes ≈ 40% loss, 50 ≈ 92%. Sustained
  misbehavior still approaches total loss; a single accident does
  not.
- **Pending unstakes scaled in place.** Each pending entry's amount
  is multiplied by `(1 - SOFT_SLASH_PCT/100)`; `release_block` is
  preserved so the unbonding schedule the offender originally chose
  is not extended by the slash. DB mirroring uses atomic
  clear-and-re-add so cold-booted nodes rehydrate the same shape.
- **Pre-fork path byte-identical.** `slash_validator(slash_pct=100)`
  takes the legacy full-wipe code path verbatim; `slash_all` with
  the same default does the same for escrow.

### Operations — fork-emergency detector + validator auto-halt

- Detector watches for unintentional fork conditions; validator
  auto-halts rather than continuing to mint on a divergent fork.
  Reduces operator damage when consensus splits unexpectedly.

### Consensus — Tier 21: halvings-aware proposer reward cap (activates block 17000)

Hard fork at `PROPOSER_CAP_HALVING_HEIGHT = 17000`.

- **Per-block proposer reward cap is now recomputed every block.**
  Previously computed once at module load as `BLOCK_REWARD * 1/4 = 4`
  tokens. Once halvings drove the actual issued reward down to
  `BLOCK_REWARD_FLOOR = 4`, the cap (still 4) equaled the entire
  block reward — so a single validator who proposes AND attests
  could sweep everything with no clawback. The anti-mega-staker
  mechanism silently turned off forever at floor era.
- Post-fork the cap is recomputed every block from the live
  `reward` returned by the issuance schedule, so the clawback ratio
  is preserved across halvings. Pre-fork blocks still apply the
  cached cap byte-for-byte for replay parity.

### Consensus — seed-divestment retune-v2 (parameter-only)

Tightens the non-discretionary founder-stake unwind so it starts
sooner and ends at a smaller floor — cleaner end-state for "secure
early on, democratize later on, leave the founder a meaningful but
non-controlling stake." Parameter-only (no schema bumps, no new
state, no apply-path or sim-path code edits). Both validators must
upgrade before `SEED_DIVESTMENT_RETUNE_HEIGHT = 1400`; current head
is well below that, so plenty of runway.

- `SEED_DIVESTMENT_START_HEIGHT`: 50_000 → **7_500** (~50 days at
  600s/block, down from ~10 months). The 4-year bleed window length
  (`END - START = 210_384` blocks) is preserved so the per-block
  divestment rate stays sane; only the start moves.
- `SEED_DIVESTMENT_END_HEIGHT` (derived): 260_384 → **217_884**.
- `SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE`: 20_000_000 →
  **10_000_000** (~14.3% of supply → ~7.1% of supply). End-state
  reads as "top holder, not controlling holder." Legacy 1M
  pre-RETUNE floor is unchanged byte-for-byte.
- `SEED_MAX_STAKE_CEILING` (derived from floor): 20M → **10M**.
  Existing seed stake above 10M (currently ~22.5M on v1) is
  grandfathered — the ceiling is enforced on `StakeTransaction`
  validation only, not on existing stake; divestment will drain v1
  to the new floor naturally over the bleed window.

End-state for the ~95M founder bootstrap shifts:

|                    | pre-retune    | post-retune     |
|--------------------|---------------:|---------------:|
| Founder retained   | 20M (~14.3%) | **10M (~7.1%)** |
| Burned             | 37.5M (~26.8%) | **42.5M (~30.4%)** |
| Lottery payouts    | 33.75M (~24.1%) | **38.25M (~27.3%)** |
| Treasury           | 3.75M (~2.7%) | **4.25M (~3.0%)** |

### Files (this release)

- `messagechain/config.py` — `SOFT_SLASH_HEIGHT`, `SOFT_SLASH_PCT`,
  `get_slash_pct`, `PROPOSER_CAP_HALVING_HEIGHT`, divestment
  parameter retune, ordering invariants.
- `messagechain/economics/inflation.py` — `slash_validator()` +
  proposer-cap recomputation gating.
- `messagechain/economics/escrow.py` — `slash_all()` partial-burn
  branch.
- `messagechain/core/blockchain.py` — slash apply paths gate on
  `get_slash_pct(height)`; comment updates for new divestment floor.
- `tests/test_soft_slash_fork.py`, `tests/test_seed_divestment*.py`,
  `tests/test_seed_stake_ceiling.py`, fork-emergency tests, Tier 21
  reward-cap tests.

## [1.21.0] — 2026-04-27

Minor release. **Hard fork: Tier 18 — unified fee market** (activates
at `TIER_18_HEIGHT = 11000`) and **Tier 19 — proposal fee tightening
+ per-byte surcharge** (activates at `PROPOSAL_FEE_TIER19_HEIGHT =
13000`). Plus one CRITICAL security fix from the round-13 audit
(active immediately, pre-Tier-17). Plus front-end features: entity
profile page (`/e/<id>`) + per-post vote indicator.

### Added (consensus, gated by activation height)

- **Tier 18 — unified fee market across Message + Transfer + React**
  (b3202e2). At `TIER_18_HEIGHT=11000` the per-block tx-count cap
  (`MAX_TXS_PER_BLOCK=45`) and total-bytes ceiling
  (`MAX_BLOCK_TOTAL_BYTES=300_000`) cover Message + Transfer +
  React jointly, and the EIP-1559 base-fee controller auctions all
  three kinds against each other. Closes the per-kind silos that
  let one tx type underprice the others under congestion.
- **Tier 19 — proposal fee tightening + per-byte surcharge**
  (cdf89d7). At `PROPOSAL_FEE_TIER19_HEIGHT=13000`:
  - title cap 400 → 200 bytes; description cap 20_000 → 2_000
    bytes (long-form rationale moves off-chain behind
    `reference_hash`).
  - flat fee 10_000 → 100_000.
  - new per-byte surcharge: 50 tokens/byte over title +
    description + reference_hash.
  - Total post-fork floor for a proposal of payload `p` bytes:
    `100_000 + 50·p`. At any p this exceeds the typical
    message floor by orders of magnitude — closes the inversion
    where a max-size proposal paid LESS per stored byte than a
    typical message.

### Security (round-13 audit)

- **`_persist_state` now full-flushes `reaction_choices` on
  post-reorg replay** (bf7f6aa). Pre-fix the per-block reaction
  flush only iterated `self.reaction_state._dirty_keys`, which
  contains ONLY the keys touched during the new fork's replay.
  Old-fork-only rows in chaindb's `reaction_choices` table were
  never DELETEd. After the next cold restart `_load_from_db`
  rehydrated the orphan vote, mixed it into
  `state_root_contribution()`, and the restarted node silently
  forked off peers that didn't restart on the next state-root
  computation. Round-12 fixed the FAILED-reorg path via
  `restore_state_snapshot`; this fix closes the SUCCESSFUL-reorg
  twin via a `full_flush` sentinel in `_persist_state`. New
  `ChainDB.clear_all_reaction_choices()` helper wipes the table
  inside the same SQL transaction as the subsequent re-INSERTs,
  atomic with the wipe. Steady-state per-block flush still uses
  the dirty-key optimization (O(K_touched), not O(N_total)).

### Added (frontend / RPC)

- **Entity profile page + RPC** (b2c3384). New `/v1/entity` JSON
  endpoint and `/e/<entity_id>` static page surface per-entity
  state.
- **Per-post vote indicator** (6b5155e). Public feed UI now shows
  per-post vote counts and renders `entity_id` as a clickable
  link to the new profile page.

### Operational

- Validators must upgrade to 1.21.0 within the runway window
  (current tip → 11_000 → 13_000) to follow the Tier 18 / Tier 19
  forks. Pre-1.21.0 nodes will reject blocks at/after activation
  height that violate the new fee-market or proposal-fee rules.
- The round-13 fix is active immediately — closes a state-root
  fork vector that activates the moment Tier 17
  (`REACT_TX_HEIGHT=9000`) is crossed plus any subsequent reorg.

## [1.20.0] — 2026-04-26

Minor release. **Two CRITICAL Tier 17 wiring fixes from the round-12
audit.** Hard fork: `STATE_SNAPSHOT_VERSION 20 → 21` (additive
section for `reaction_choices`; pre-v21 snapshot blobs are rejected
by the strict version check). Plus a fee-coherence improvement.

Neither round-12 critical is exploitable today (Tier 17 activates at
`REACT_TX_HEIGHT = 9000`, current tip ~590), but both MUST land
before activation block 9000 or first-touch turns into key
compromise / state-sync hard break. **All mainnet operators should
upgrade ASAP.**

### Security (round-12 audit)

- **`ReactTransaction` now enforces WOTS+ leaf-watermark + in-block
  leaf-collision sweep + cross-pool dedupe** (3dd5ff0). Three layers
  of leaf-reuse defense were missing on the new react path:
  - `_validate_react_tx_in_block` admitted any `leaf_index`,
    including one already past the voter's `leaf_watermarks[]`.
    Mirror the message / transfer / stake / governance gate.
  - The block-level `_check_leaf` sweep iterated every other tx
    kind but NOT `block.react_transactions` — two same-leaf signed
    payloads in the same block (e.g. Transfer at leaf N + React at
    leaf N from the same voter) bypassed dedup, both applied, the
    WOTS+ leaf secret was publicly leaked from the two signatures.
  - `Server._check_leaf_across_all_pools` didn't scan
    `mempool.react_pool`; `_rpc_submit_react` skipped both the
    cross-pool check and the per-entity watermark gate at admission.
  - Two distinct signed payloads under the same WOTS+ leaf trivially
    leak enough one-time-key material for any observer to forge
    arbitrary signatures under that leaf — including a
    `TransferTransaction` draining the voter's full balance and
    stake. Once `REACT_TX_HEIGHT` activates, any wallet bug or
    backup-restore that regresses `_next_leaf` (per
    `reference_test_wallets.md` workflow) and submits
    `transfer-then-react` hands the network a leaf-reuse pair.
- **`ReactionState` ground-truth `choices` map now in snapshot +
  chaindb save/restore symmetry** (3dd5ff0). Pre-fix:
  - `state_snapshot.serialize_state` didn't extract
    `reaction_choices`; `_TAG_REACTION_CHOICES` didn't exist;
    `encode_snapshot` / `decode_snapshot` didn't write/read it;
    `compute_state_root` committed zero reaction data.
  - `_install_state_snapshot` left `self.reaction_state` as the
    default empty `ReactionState()` after install.
  - `chaindb.save_state_snapshot` didn't capture
    `reaction_choices`; `restore_state_snapshot` didn't wipe /
    re-insert.
  - Once `REACT_TX_HEIGHT` activates and the first vote lands, every
    checkpoint-bootstrapped node would FAIL the install-time
    root-equality check (synced node computes
    `state_root_contribution()` over empty reactions; canonical
    header committed root over real reactions) — **state-sync
    becomes IMPOSSIBLE** post-activation. Reorg across a
    React-bearing block leaves orphan-fork rows on disk → cold
    restart silently forks. Same defect class as the round-2
    `entity_id_to_index`, round-4 `key_rotation_last_height`, and
    round-7 `receipt_subtree_roots` mirror leaks.
  - **Fix.** Bump `STATE_SNAPSHOT_VERSION 20 → 21`. Add
    `_TAG_REACTION_CHOICES` Merkle section + leaf builder.
    `serialize_state` extracts `blockchain.reaction_state.choices`.
    `_install_state_snapshot` rebuilds `ReactionState` from the
    snapshot map AND mirrors entries to chaindb.
    `chaindb.save_state_snapshot` captures `reaction_choices`;
    `restore_state_snapshot` wipes the table and re-INSERTs inside
    the same SQL transaction (mirrors round-8 pattern).

### Changed

- **Mempool fee-coherence: size-aware estimator, best-fit fill,
  flat `MARKET_FEE_FLOOR`** (9ce9cdb). Mempool block-fill selection
  now uses a size-aware fee-per-byte estimator and best-fit
  packing; protocol-level `MARKET_FEE_FLOOR` enforced flatly across
  all tx kinds at admission.

### Notes

- The `STATE_SNAPSHOT_VERSION` bump is a wire-format break: a
  v1.20+ node cannot decode a v20 snapshot blob (and vice versa).
  Live operators do not currently bootstrap via checkpoint, so this
  is forward-only — re-bake any archived snapshots on the upgraded
  code.
- No CLI / RPC behavior change for honest operators on the
  steady-state path (Tier 17 still activates at height 9000;
  honest validators don't trigger the leaf-reuse class).

## [1.19.1] — 2026-04-26

Patch release. **CRITICAL upgrade-blocking fix.** 1.19.0 shipped
with a wire-format regression that crashed any node attempting to
load existing on-disk blocks: Tier 17 added `react_transactions` to
`Block.from_bytes` UNCONDITIONALLY, but every block already on disk
pre-1.19.0 was serialized without that field. The decoder ran off
the end of the blob inside `_load_from_db` on first startup,
systemd entered a crash-loop, and the upgrade CLI's auto-rollback
could not recover (the stale-import path predates the deeper
crash, so the verifier never noticed). validator-1 was taken down
mid-roll on 2026-04-26 and required manual rollback to the
pre-1.19.0 backup; validator-2 was untouched per the runbook
"never both at once" rule. **No node should run 1.19.0.**

### Fixed

- **`Block.from_bytes` end-of-blob shim for pre-Tier-17 blobs**
  (2864118). Detect `len(data) - off == 32` (only the trailing
  `declared_hash` remaining) and treat `react_transactions` as
  `[]` without consuming bytes. Pre-Tier-17 blobs are a strict
  prefix of post-Tier-17 blobs up to the new field, so the shim
  cleanly distinguishes the two cases. Post-Tier-17 blobs (which
  carry at least 4 bytes for the u32 count + 32 bytes for the
  hash) decode normally.
- Includes regression test
  (`tests/test_react_tx_block_backward_compat.py`) that builds a
  real Block, strips the empty-react u32 to simulate a pre-Tier-17
  on-disk blob, and asserts decode succeeds.

### Upgrade path

- Validators that already hit the 1.19.0 crash and rolled back to
  1.18.0 (or earlier) should upgrade directly to 1.19.1 — the
  pre-Tier-17 blob shim makes the upgrade safe regardless of
  starting version.
- The 1.19.0 tag remains in git history (signed and immutable, per
  release policy) but should NOT be installed by anyone.

## [1.19.0] — 2026-04-26

Minor release. **Hard fork: Tier 17 — `ReactTransaction` (user-trust
+ message-react votes).** Activates at `REACT_TX_HEIGHT = 9000`
(~14 days runway above Tier 16 at height 7000). Plus one CRITICAL
security fix from the round-11 audit.

### Added (consensus, gated by activation height)

- **`ReactTransaction` — first-class on-chain reaction tx type**
  (2fb5e86, aa6899b). Activates at `REACT_TX_HEIGHT = 9000`. Lets
  any registered entity cast (a) a `react` vote on a specific
  `MessageTransaction.tx_hash` (e.g. like / dislike / report) or
  (b) a `trust` vote on another entity's `entity_id` (e.g.
  trust / distrust / mute). Both vote types share the same
  WOTS+-signed wire format and pay the standard signature-aware
  fee floor; reactions ride the message-tx storage budget the
  same way every other signed payload does (no special
  per-reaction subsidy or surcharge). Pre-activation a v1
  ReactTransaction is rejected at admission; post-activation it's
  the canonical user-trust + message-react primitive.
  - **State commitment.** A new `ReactionState` aggregator tracks
    per-target reaction counts (per `tx_hash` for message reacts;
    per `entity_id` for trust votes); apply-time mutations are
    committed to the snapshot root via the same per-block flush
    discipline as every other consensus-visible field.
  - **Block-pipeline integration.** `Block.react_transactions`
    rides alongside the existing per-type tx lists; admission gates
    + apply ordering mirror `MessageTransaction` (fee burn + leaf
    watermark + nonce ratchet, all routed through the round-9
    add_block transaction wrap so apply-time mutations roll back
    cleanly on a state-root mismatch).

### Security (round-11 audit)

- **`FinalityDoubleVoteEvidence` slash now uses multi-key candidate
  verification** (cf4340c). Pre-fix the FinalityDoubleVote branch
  of `Blockchain.validate_slash_transaction` resolved ONE pubkey at
  `vote_a.signed_at_height` and called
  `verify_finality_double_vote_evidence(ev, K_old)` — checking
  BOTH votes against ONE pubkey. An equivocator who signed vote_a
  with K_old at height N, submitted a `KeyRotationTransaction` at
  N + `KEY_ROTATION_COOLDOWN_BLOCKS=144`, then signed vote_b with
  K_new at N+200 (within the
  `FINALITY_VOTE_MAX_AGE_BLOCKS=1000` window targeting the same
  checkpoint) bypassed the slash: K_old verified vote_a but
  vote_b's K_new signature failed → "Invalid evidence: vote_b
  signature is invalid", slash dismissed, **equivocator keeps
  stake**. Cooldown (144) << vote-age window (1000), so the
  rotation comfortably fits inside the same target's vote window
  and the bypass is trivial for any rotating validator.
  - **Fix.** Mirror the multi-key shape of
    `verify_attestation_slashing_evidence` (Round 6): drop the
    single-key shortcut and enumerate the offender's full
    `key_history` (+ current pubkey) as candidates. Verify each
    vote independently against ANY candidate. Every candidate is
    one the offender legitimately published on-chain (each
    rotation step is signed by the prior key), so matching ANY
    candidate is proof the offender produced the signature —
    attacker cannot exploit the candidate set to forge evidence.
  - This is **distinct** from the carried-over "multi-key resolver
    doesn't bind to evidence_height" item — that concerns
    *over-acceptance* in the multi-key path; this is the
    symmetric *under-acceptance* hole in the still-single-key
    FinalityDoubleVote branch.

### Operational

- Validators must upgrade to 1.19.0 within the runway window
  (7000 → 9000) to follow the Tier 17 fork. Pre-1.19.0 nodes will
  reject blocks at/after height 9000 that carry
  `ReactTransaction`s.
- The round-11 security fix is active immediately (pre-Tier-17),
  so all mainnet operators should upgrade promptly to close the
  finality-vote slash-evasion window.

## [1.18.0] — 2026-04-26

Minor release. **Hard fork: Tier 16 — market-driven fee floor.**
Activates at `MARKET_FEE_FLOOR_HEIGHT = 7000` (~14 days runway above
Tier 15 at height 5000).

### Changed (consensus, gated by activation height)

- **`MARKET_FEE_FLOOR = 1` retires the linear-in-stored-bytes fee
  floor.** At/after `MARKET_FEE_FLOOR_HEIGHT`, the protocol-level fee
  floor for `MessageTransaction`s collapses to a flat 1 token,
  regardless of message size, prev-pointer presence, or witness size.
  The linear formula
  (`BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE × len`) is retained
  only as a replay rule for blocks in `[BLOCK_BYTES_RAISE_HEIGHT,
  MARKET_FEE_FLOOR_HEIGHT)`. Pre-fork heights replay under the rule
  current at their height (legacy quadratic, flat
  `MIN_FEE_POST_FLAT`, or one of the two linear variants) — historical
  blocks validate unchanged.

  Rationale: the linear floor was doing two jobs — keep zero-fee txs
  out of the mempool, and discipline long-message bloat by per-byte
  pricing. Only the first is the floor's job. Bloat discipline is
  already delivered by `MAX_BLOCK_MESSAGE_BYTES` (a hard byte ceiling
  per block, ~6.5 MB/day at full utilization regardless of fee paid)
  and EIP-1559 base fee dynamics (which automatically price the
  marginal byte under congestion). Setting the floor to 1 — not 0 —
  preserves the no-free-tx invariant without the protocol trying to
  set the equilibrium price.
- **EIP-1559 base-fee lower bound drops from `MIN_FEE` (=100) to
  `MARKET_FEE_FLOOR` (=1) at/after `MARKET_FEE_FLOOR_HEIGHT`.** Base
  fee can now decay to 1 token during quiet periods, then ratchet up
  via the existing 12.5%-per-over-target-block dynamics under
  congestion. Upper cap stays absolute (`MIN_FEE × MAX_BASE_FEE_MULTIPLIER`
  = 1_000_000) — it bounds pathological pricing in absolute tokens,
  not as a multiple of the floor.
- **`enforce_signature_aware_min_fee` protocol baseline drops to
  `MARKET_FEE_FLOOR` for all non-message tx types at/after
  activation.** Type-specific surcharges (`NEW_ACCOUNT_FEE`,
  `GOVERNANCE_PROPOSAL_FEE`, `KEY_ROTATION_FEE`, etc.) are
  unaffected — they price externalities specific to those tx types
  (permanent state entry, binding governance vote, key rotation) and
  remain the binding floor for those tx types in practice.

### Operational

- Validators must upgrade to 1.18.0 within the runway window
  (5000 → 7000) to follow the fork. Pre-1.18.0 nodes will reject
  blocks at/after height 7000 that carry messages priced below the
  pre-Tier-16 linear floor.

### Security (round-10 audit)

- **Governance-tx gossip handler now verifies signatures before
  admitting** (b991720). Pre-fix the `kind=="governance"` branch of
  `Server._handle_announce_pending_tx` admitted forged
  `ProposalTransaction` / `VoteTransaction` /
  `TreasurySpendTransaction` after checking only that
  `signer_id in public_keys`. An unauthenticated peer could craft a
  tx with any registered entity's id as `proposer_id` / `voter_id`
  and the validator would admit it to `_pending_governance_txs` and
  rebroadcast. When the validator next became proposer it packed
  the forged tx into its block; `validate_block` then rejected the
  entire block at `_validate_governance_tx_in_block` (sig fails) —
  the proposer wasted its slot, produced no block, and accrued
  inactivity-leak / archive-miss penalties. Sustained flood across
  rotated peers prevents block production indefinitely on a
  2-validator chain. The fix routes admission through the existing
  in-tree `Blockchain._validate_governance_tx` helper — the same
  verifier `_validate_governance_tx_in_block` already trusts at
  consensus-time validation. Mirrors the verify-before-admit pattern
  of the sibling `stake` / `unstake` / `authority` branches; this
  was the lone gap.

## [1.17.1] — 2026-04-26

Patch release. ONE CRITICAL silent-fork fix from the round-9 audit
pass against the post-v1.17.0 chain state. **All mainnet operators
should upgrade ASAP** — every node that processed a state-root-
rejected block since the chain went live is exposed on its next cold
restart.

### Security

- **`add_block` now wraps apply + state-root verify + persist in a
  single chaindb transaction** (f28c872). Pre-fix multiple apply-time
  helpers eagerly committed to chaindb BEFORE the per-block
  transaction opened — `_record_key_history` /
  `apply_key_rotation` (set_public_key, set_leaf_watermark,
  set_key_rotation_count, set_key_rotation_last_height, plus an
  explicit `db.flush_state()`), `apply_revoke_transaction`
  (set_revoked + flush_state), and the first-spend pubkey installs
  in transfer-with-burn / message-tx apply paths (set_public_key).
  A block whose `state_root` mismatched got rolled back in-memory by
  `_restore_memory_snapshot`, but the disk mirror kept the
  rejected-block writes. A subsequent cold restart rehydrated the
  phantom rows and silently forked off the canonical chain.
  - **Concrete exploit**: a staked proposer crafts a block carrying
    a self-targeted `KeyRotationTransaction(new_public_key=
    PK_attacker)` plus a deliberately wrong `state_root`. The
    simulated-root pre-check skips slash-bearing blocks, so any
    block including a slash tx reaches apply unconditionally. Apply
    eagerly writes `(height, PK_attacker)` to `key_history` and
    `PK_attacker` to `public_keys`; state-root verify fails;
    in-memory rolls back; disk keeps the writes. Cold restart
    on any node that processed the block then resolves PK_attacker
    via `_public_key_at_height` for any block the entity signs and
    rejects pre-rotation slash evidence as having an invalid
    signature → silent fork at the slash block, plus a slashing
    escape for any equivocator who can land such a block.
  - **Fix shape**: in `add_block`, every chaindb write inside
    `_apply_block_state` now rides the outer txn via the chaindb's
    `_txn_depth` nesting (inner `begin_transaction` at depth>0 is a
    no-op; inner `_maybe_commit` at depth>0 is a no-op; only the
    outer commits or rolls back). On state-root mismatch we
    `rollback_transaction` to undo all eager DB writes alongside
    the existing `_restore_memory_snapshot`. Same defect-class fix
    as round-7's `_record_receipt_subtree_root` deferral, but
    applied at the apply-loop boundary so it covers ALL current
    AND future eager writers without per-helper plumbing changes.
- **Belt-and-suspenders cleanup** (f28c872):
  - `_record_key_history` no longer eager-writes; `_persist_state`
    gains a key_history flush loop after the existing past-roots
    loop.
  - `apply_key_rotation` no longer eager-writes; relies on
    `_persist_state`'s pre-existing `public_keys` /
    `leaf_watermarks` / `key_rotation_counts` /
    `key_rotation_last_height` flush loops.
  - `db.flush_state()` is now depth-aware (routes through
    `_maybe_commit`) so any helper invoked inside the outer wrap
    cannot prematurely commit the outer txn and partially defeat
    the fix. Outside any wrap (cold-start bootstrap, standalone
    tests) it still commits immediately.

### Notes

- No on-chain schema bump (no `STATE_SNAPSHOT_VERSION` change).
- No CLI / RPC behavior change for honest operators on the
  steady-state path.
- Mainnet validators have restarted multiple times during the
  recent 1.14→1.17 release sequence, so the exposure was real:
  the next restart on a node that had ever processed a bad-state-
  root block could have triggered the fork. Roll both validators
  promptly.

## [1.17.0] — 2026-04-26

Minor release. Two CRITICAL silent-fork fixes from the round-8 audit
pass against the post-v1.16.0 chain state. Both are state-sync /
cold-restart hazards: a node bootstrapped from a checkpoint snapshot
or restarted after a failed reorg ended up with empty maps that the
warm cluster relied on for evidence verification. **All mainnet
operators should upgrade ASAP** — once Fix #1 is in place, freshly
bootstrapped validators will correctly verify slash evidence at
pre-rotation heights.

Hard fork: `STATE_SNAPSHOT_VERSION 19 → 20`. Adds the new
`key_history` section (per-entity rotation history) to the
state-snapshot wire format and snapshot-root commitment. Pre-v20
snapshots can no longer be decoded; the in-memory `setdefault` to an
empty `key_history` is preserved for hand-built snapshot dicts in
tests, but the binary decoder is strict.

### Security

- **`key_history` now lives in the state snapshot** (04d2548). Pre-fix
  the snapshot did not encode `key_history` at all. State-synced nodes
  bootstrapping from a checkpoint started with `self.key_history = {}`
  for every entity, so `_public_key_at_height` fell back to the
  CURRENT pubkey for any rotated entity. Slash evidence whose signing
  height predated the rotation verified against the wrong key on the
  synced node — slash rejected, while warm nodes admitted — silent
  fork at the slash block. Adds:
  - `_TAG_KEY_HISTORY` (`khist`) section with a custom
    `(eid, height, pk)` leaf builder so the snapshot root commits to
    every rotation tuple
  - `_encode_key_history` / `_decode_key_history` with deterministic
    outer-by-eid + inner-by-(height, pk) sort order
  - `serialize_state` extracts `blockchain.key_history`
  - `_install_state_snapshot` installs the dict AND mirrors entries
    into chaindb's `key_history` table so cold restart on the synced
    node rehydrates from disk
- **chaindb save/restore symmetry on receipt-subtree + key-rotation-
  cooldown mirror tables** (04d2548). Pre-fix `save_state_snapshot`
  did NOT capture `receipt_subtree_roots`,
  `past_receipt_subtree_roots`, or `key_rotation_last_height`, but
  `restore_state_snapshot` DELETEd all three. The reorg-failure path
  in blockchain.py called `restore_state_snapshot` then returned
  without `_persist_state` — in the post-restore window a process
  exit (operator restart, OOM, SIGKILL) cold-restarted the node into
  empty mirrors. After the round-7 forged-receipt fix an empty
  `receipt_subtree_roots` makes LEGITIMATE `CensorshipEvidence`
  rejected on the cold-restarted node while warm nodes admit —
  silent fork. The fix:
  - `save_state_snapshot` includes the three missing keys
  - `restore_state_snapshot` adds three INSERT loops that re-populate
    from the snapshot dict atomically inside the same transaction
    that ran the DELETEs
  - belt-and-suspenders: the reorg-failure path now calls
    `_persist_state` after `_reset_state` + replay so future fields
    added to one side without the other still resync before the next
    block.

### Notes

- `STATE_SNAPSHOT_VERSION` bump is a wire-format break: a v1.17+ node
  cannot decode a v19 snapshot blob. Live operators do not currently
  bootstrap via checkpoint, so this is forward-only — re-bake any
  archived snapshots on the upgraded code.
- No new CLI commands, no new RPC methods, no behavior change for
  honest operators on the steady-state path. The fixes are purely
  "make state-sync and post-reorg-crash recovery actually work."

## [1.16.0] — 2026-04-26

Minor release. Four CRITICAL security fixes from the round-7 audit
pass against the post-v1.15.0 chain state. **All mainnet operators
should upgrade ASAP** — Fix #1 below directly exposes live validators
to a one-tx slash for the price of `MIN_FEE` until they upgrade.

### Security

- **Forged-receipt slashing of unonboarded validators closed**
  (135de3c). `validate_censorship_evidence_tx` and
  `validate_bogus_rejection_evidence_tx` no longer short-circuit the
  receipt-root admissibility gate when the offender has never
  installed a `SetReceiptSubtreeRoot`. Pre-fix the gate
  `if tx.offender_id in self.receipt_subtree_roots and not
  receipt_root_admissible(...)` skipped entirely for unonboarded
  victims, letting an attacker generate their own receipt subtree,
  sign a `SubmissionReceipt` purporting to be from the victim under
  an attacker-controlled root, wrap it in a `CensorshipEvidenceTx`,
  and slash the victim for `CENSORSHIP_SLASH_BPS` of stake at the
  price of `MIN_FEE`. Both live mainnet validators were exposed
  (neither has run their initial `SetReceiptSubtreeRoot` onboarding).
  The gate now defers to `receipt_root_admissible` unconditionally;
  that helper already returns `False` for offenders with no anchor
  of trust.
- **`_record_receipt_subtree_root` chaindb-write rollback safety**
  (135de3c). Pre-fix the helper called `db.set_receipt_subtree_root`
  and `db.add_past_receipt_subtree_root` synchronously at apply time,
  BEFORE the per-block SQL transaction opened in
  `_apply_block_state`. A bad-state-root block whose apply mutated
  the maps got rolled back in-memory by `_restore_memory_snapshot`,
  but the chaindb mirror kept the rejected-block writes — a cold
  restart then rehydrated the corrupted mirror and silently forked
  off the canonical chain. Writes are now deferred to
  `_persist_state`, which runs inside the per-block transaction
  wrapper for crash atomicity.
- **`_install_state_snapshot` installs `past_receipt_subtree_roots`**
  (135de3c). v19 made the historical-roots dict load-bearing for
  evidence admission AND committed it to the snapshot root, but the
  install path was never updated. State-synced (checkpoint-
  bootstrapped) nodes started with the dict empty and silently
  forked off the warm cluster on the first contested
  `CensorshipEvidence` under a rotated-away root. Install now
  mirrors the same shape as the live-roots assignment.
- **`FinalityVote.signed_at_height` bounded by
  `[target_block_number, current_height]`** (135de3c).
  `_validate_finality_votes` now rejects any vote whose
  `signed_at_height` exceeds the block being assembled (signer
  claims a tip they hadn't seen) or precedes the vote's target
  (signer predates the block they commit to). Pre-fix the field
  was unconstrained: the slash-evidence pipeline keys the TTL gate
  on `signed_at_height`, so an equivocator who picked a far-past
  value drove the TTL check past expiry the moment the votes landed
   — their double-vote was no longer slashable.

### Notes

- Pure security release. No new CLI commands, no new RPC methods,
  no `STATE_SNAPSHOT_VERSION` bump (no on-chain schema change), no
  behavior change for honest operators.
- The `FinalityVote.signed_at_height` bound is technically a
  consensus-rule tightening (a previously-valid block carrying an
  out-of-bounds vote would now be rejected). Honest validators
  produce votes with `signed_at_height` equal to the chain tip at
  signing time, so historical replay is unaffected. Roll both
  validators promptly to keep the rule uniformly enforced.

## [1.15.0] — 2026-04-26

Minor release. Three CRITICAL security fixes — all the same root
cause: the v1.14.0 `past_receipt_subtree_roots` defense (rotation
no longer wipes outstanding evidence) had three integration gaps
that effectively disabled the fix in production. **All mainnet
operators should upgrade ASAP** — the v1.14.0 release notes told
operators that rotation no longer wipes evidence; this release is
what actually makes that true.

Hard fork: `STATE_SNAPSHOT_VERSION 18 → 19`. Adds the new
`past_receipt_subtree_roots` section to the state-snapshot root
commitment. Pre-v19 snapshots are upgraded via a `setdefault` to an
empty history (no prior rotations to preserve), so a v18→v19
upgrade is seamless. Two state-synced nodes that observed different
rotation histories now correctly produce different state roots
instead of agreeing on root but disagreeing on which receipts are
admissible.

### Security

- **Block-apply path now routes through `_record_receipt_subtree_root`**
  (cd80604). Pre-fix `_apply_authority_tx` inlined the live-root
  overwrite and bypassed the helper that appends the OLD root to
  `past_receipt_subtree_roots`. The standalone
  `apply_set_receipt_subtree_root` method (which DOES use the
  helper) was dead production code — only tests called it. Net
  result: the v1.14.0 rotation-evidence-wipe defense was a no-op
  on mainnet. A coerced validator who issued thousands of receipts
  under R1 could publish ONE cold-key `SetReceiptSubtreeRoot(R2)`
  in a block; on every honest peer replaying that block, R1
  receipts became permanently inadmissible.
- **`_snapshot_memory_state` / `_restore_memory_snapshot` now
  capture `receipt_subtree_roots` + `past_receipt_subtree_roots`**
  (cd80604). Pre-fix a bad-state-root block whose apply path
  mutated the live map got caught by the post-apply state_root
  check and rolled back, but the snapshot didn't include these
  fields → in-memory map kept the rejected-block mutations.
  Combined with the chaindb mirror write that already landed
  during apply, the corruption persisted across restart.
- **`past_receipt_subtree_roots` now committed to the state-
  snapshot root** (cd80604). New `_TAG_PAST_RECEIPT_ROOT` section
  with deterministic `(eid, root)` leaf builder, encoder/decoder
  pair, and `serialize_state` extraction. Two state-synced nodes
  that observed different rotation histories now produce different
  state roots — closes the silent-fork window where they agreed on
  root but disagreed on `receipt_root_admissible`.

### Notes

- The `STATE_SNAPSHOT_VERSION` bump means a v1.15+ node MUST be
  used to validate v19 snapshots. v18 snapshots remain readable
  on v1.15+ via the upgrade-path `setdefault` to an empty
  `past_receipt_subtree_roots` map.
- No new CLI commands, no new RPC methods, no behavior change for
  honest operators. The fix is purely "make the v1.14.0 defense
  actually run."

## [1.14.0] — 2026-04-26

Minor release. Eleven critical security audit fixes across rounds 4
and 5. Closes the censorship-evidence pipeline end-to-end on both
HTTPS and RPC ingress, defeats a coerced-validator evidence-wipe via
`SetReceiptSubtreeRoot` rotation, plus several consensus-safety + DoS
holes. **All mainnet operators should upgrade ASAP** — five of these
issues directly target the headline structural defense against
validator collusion.

### Security

- **Wire `receipt_issuer` into `SubmissionServer`** (a6fd35e, fdcf83e).
  Pre-fix the public HTTPS submission endpoint never issued
  SubmissionReceipts / Acks / Rejections — the entire censorship-
  evidence pipeline was silently dead since the endpoint shipped. A
  coerced validator could admit-and-drop honest user submissions
  with zero on-chain accountability.
- **Wire `WitnessObservationStore` into `SubmissionServer`** (a6fd35e).
  Without it, the `obs_ok` ack-issuance gate short-circuits to True
  for any 32-byte `X-MC-Witnessed-Submission` header, letting a
  botnet drain the 65k-leaf receipt subtree in hours via the per-IP
  ack budget alone.
- **Route `_rpc_submit_transaction` through the receipt-issuer
  helper** (a6fd35e). Pre-fix the RPC submission path bypassed
  receipt issuance entirely. RPC submissions now return a `receipt`
  field clients can weaponize as `CensorshipEvidenceTx`.
- **`receipt_subtree_roots` reorg leak** (a6fd35e). Same defect class
  as the round-2 `entity_id_to_index` and round-4
  `key_rotation_last_height` leaks. `_reset_state` now clears the
  in-memory map; `restore_state_snapshot` `DELETE`s the chaindb
  mirror.
- **Receipt-subtree-root rotation no longer wipes outstanding
  evidence** (a6fd35e). New `past_receipt_subtree_roots` history per
  entity — receipt validation accepts the current root OR any
  historical root the entity ever installed. Pre-fix a coerced
  validator could pre-emptively erase every in-flight evidence
  receipt with one cold-key `SetReceiptSubtreeRoot` tx. New
  `past_receipt_subtree_roots` chaindb table mirrors the history.
- **Slashed-this-block validators excluded from finality**
  (a6fd35e). Pre-fix a coordinated proposer could push a target
  block over 2/3 finalization using stake that consensus had already
  declared malicious in the same block. `_apply_finality_votes` and
  the matching `compute_post_state_root` sim path now pre-filter
  survivors against `slashed_validators`.
- **Empty-entries inclusion list rejects non-empty
  `quorum_attestation`** (a6fd35e). Pre-fix the empty-entries
  shortcut returned OK before signature-verifying any quorum-
  attestation report — a proposer could attach arbitrarily large
  unverified garbage at zero fee.
- **Governance v1 admission rejected post-Tier-15 activation**
  (a6fd35e). Pre-fix both v1 and v2 of the SAME logical proposal
  text could exist concurrently (different tx_hashes → different
  proposal_ids), splitting honest votes; for `TreasurySpend`, both
  could clear 2/3 and double-debit the treasury. Post-fork
  (height ≥ `GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT=5000`), v1 admission
  is rejected. Historical v1 blocks still replay.
- **`KeyPair.sign` thread-safety** (fdcf83e). Concurrent calls
  could both observe the same `_next_leaf` before either advanced
  it, producing two WOTS+ signatures over different message hashes
  under the same one-time leaf — mathematically reveals the leaf's
  WOTS+ private key. New `_sign_lock` (threading.Lock) wraps the
  read-modify-write of `_next_leaf` (including persist-before-sign
  disk write).
- **`key_rotation_last_height` reorg leak** (fdcf83e).
  `restore_state_snapshot` now `DELETE FROM key_rotation_last_height`.
- **30-second socket read timeout on `_SubmissionHandler` and
  `_FeedHandler`** (a6fd35e). Closes a slow-loris vector — pre-fix
  a single attacker could pin thousands of validator threads.

### Notes

- The `past_receipt_subtree_roots` table is added by
  `CREATE TABLE IF NOT EXISTS` so a downgrade-then-upgrade cycle is
  safe.
- Validators on this version expose a new `receipt` field in the
  `submit_transaction` RPC response; older clients ignore unknown
  JSON keys, so this is a forward-compatible additive change.

## [1.13.0] — 2026-04-26

Minor release. Adds an engagement-signal beacon to the public feed
viewer: a one-shot `GET /beacon/scroll` the homepage's JS fires the
first time a visitor scrolls past the initial fold. Pairs visitor
IPs with reader-depth in the access log so operators can tell who
actually read past the first screen of messages. Cosmetic; no
protocol or consensus impact.

### Added

- **`GET /beacon/scroll` on `PublicFeedServer`** — 204 response, no
  body, `Cache-Control: no-store`. The homepage now ships a small
  scroll listener that fires this exactly once per page load when
  `window.scrollY` exceeds one viewport. The listener detaches
  itself after firing.

## [1.12.0] — 2026-04-25

Minor release.  Hard fork: compress the bootstrap-window fork
schedule (Tier 1-7) from the original 50_000-98_000 height range
into 600-2800.  Pulls SEED_DIVESTMENT_START_HEIGHT forward from
105_192 (~2 years) to 50_000 (~1 year).  No new consensus
mechanisms; every fork in this release is a parameter change the
schedule had already committed to.

### Why compress

The original schedule's wide spacing existed to give independent
operators 1-2 years of upgrade runway between forks.  With the
network in its bootstrap phase (one operator running both validators,
no external validators), that runway is artificial -- you're
upgrade-coordinating with yourself, and every additional block of
"future fork waiting to land" is unfinished business carried across
releases.  Pulling Tier 1-7 to the 600-2800 window gets the chain
into its steady-state parameters now, so future audits and validator
onboarding land against the final rule set instead of a partially-
activated transitional one.

### Compressed heights

Tier 1 (UNBONDING extension, FINALITY_VOTE cap, SEED_STAKE ceiling,
TREASURY_CAP tightening): 50_000-56_000 -> 600-1200.

Tier 2 (MIN_STAKE raise, LOTTERY_BOUNTY raise, FEE_INCLUDES_SIGNATURE):
60_000-64_000 -> 1000-1200.

Tier 3 (TREASURY_REBASE -33M burn, SEED_DIVESTMENT retune+redist):
68_000-74_000 -> 1300, 1400, 1600.

Tier 4 (ATTESTER reward split, fee funding, finality reward, cap, fix):
78_000-86_000 -> 1700-2300.

Tier 5 (DEFLATION_FLOOR v1+v2): 90_000-92_000 -> 2500-2600.

Tier 6 (VALIDATOR_REGISTRATION burn): 96_000 -> 2700.

Tier 7 (FLAT_FEE): 98_000 -> 2800.

All existing ordering asserts in `messagechain/config.py` are
preserved.  TREASURY_CAP_TIGHTEN_HEIGHT (1200) is placed after the
typical GOVERNANCE_VOTING_WINDOW close (~1014) so existing
treasury-spend tests with small treasuries don't trip the new
0.1%-per-epoch + 5%-annual caps; ATTESTER_REWARD_CAP_HEIGHT (2000)
and ATTESTER_CAP_FIX_HEIGHT (2300) are spaced 300 blocks apart
(vs. the original 2000) to preserve the [CAP, FIX) test window.

### Seed divestment pull-forward

`SEED_DIVESTMENT_START_HEIGHT`: was 105_192 (= BOOTSTRAP_END_HEIGHT,
~2 years from launch).  Now 50_000 (~1 year).  The 4-year bleed-
window duration (END - START = 210_384 blocks) is preserved, so the
per-block divestment rate is unchanged; only the start is pulled
forward.

`SEED_DIVESTMENT_END_HEIGHT`: 315_576 -> 260_384 (= 50_000 + 210_384).

This is the largest economically-significant change in the release.
By the end of the bleed (height ~260_384, ~5 years from launch), the
founder bond drops from the genesis 95M to a 20M floor, with the
delta burned 95% / treasury 5% / lottery (after redist fork) 45%/5%/50%
per the existing post-redist params.  Pulling the start forward by
one year compresses the runway to credible decentralization without
touching the bleed mechanics.  Why one year and not less: the audit
credibility win comes when the founder stake is no longer the
supermajority of stake, which requires external validators to exist;
starting the bleed before plausibly any external validator can exist
just burns tokens into a one-operator network.

### Activation runway

Lowest new fork height is 600.  Current tip ~451 at release time, so
~150 blocks (~25 hours at 600s/block) of upgrade runway.  Standard
`messagechain upgrade` on both validators picks up the new constants
on restart; pre-fork blocks continue to validate under the legacy
parameters at every height below the new activation, so historical
replay is byte-preserved.

## [1.11.0] — 2026-04-25

Minor release.  Hard fork (Tier 13, audit finding #2) plus an
operator feature.  Lays the wire-format groundwork for upgrade
signaling so future forks can refuse to cross their activation
height until enough validators have upgraded -- without that, a
single missed upgrade silently partitions the chain.  Also adds an
offline pre-sign workflow for the existing emergency-revoke
kill-switch.

### Added — Tier 13 hard fork (validator version signaling)

- **`BlockHeader.validator_version` (V2 wire format).**
  At/after `VERSION_SIGNALING_HEIGHT = 3500`, blocks serialize
  under `BLOCK_SERIALIZATION_VERSION_V2` carrying a uint16
  `validator_version` field stamping the proposer's running
  release.  Pre-activation blocks remain V1 (no field), and the
  V1 codec is preserved end-to-end so the entire pre-fork chain
  history hashes byte-for-byte identically under new code -- no
  migration step, no re-hashing, no surprise prev-hash drift.
  V1 and V2 are both accepted indefinitely so historical blocks
  always replay cleanly.  (`messagechain/core/block.py`,
  `messagechain/config.py`)
- **`messagechain/consensus/validator_versions.py` registry.**
  Append-only mapping from uint16 -> (release_tag, notes).
  `CURRENT_VALIDATOR_VERSION = 1` for this release; future
  releases bump and append.  Reserved value 0 = UNSIGNALLED, used
  for pre-Fork-1 historical blocks; consumers MUST treat it as
  "no signal" and never as "matches any version" so a downgrade
  attack can't bypass future activation gates by zeroing the
  field.
- **Block producer stamps `CURRENT_VALIDATOR_VERSION` post-
  activation.**  Pre-activation blocks default to UNSIGNALLED so
  the V1 layout is preserved.  `BlockHeader._ser_version_for_height`
  is the single point of truth: every codec path
  (signable_data, to_bytes, from_bytes, the Block envelope's
  leading-byte stamp) reads from it, so the in-memory
  representation can serialize cleanly under either format.
  (`messagechain/consensus/pos.py`)

This fork ITSELF has no consensus-rule consumer of the new field
-- it only makes the field appear on the wire.  Fork 2 (the
active-set liveness fallback, audit finding #1) will land in a
follow-up release and consume it as its activation gate.  Two
separate forks is the deliberate sequencing: activating a
liveness-recovery fork using the same heights-only deployment
mechanism that put liveness at risk would be reckless; fork-1
ships first, fork-2 ships behind the gate.

### Added — Offline emergency-revoke pre-sign workflow

- **`messagechain emergency-revoke --print-only`.** Builds and
  signs a revoke locally with the cold key, prints serialized
  hex on stdout, makes ZERO RPC calls.  Intended for an
  air-gapped machine: pre-sign once while the cold key is
  available, store the bytes offline (paper QR + encrypted USB
  in two physical locations), broadcast later under duress.
  Default fee in this mode is 10x `MIN_FEE_POST_FLAT` so a
  single fork worth of governance fee inflation does not strand
  the saved bytes.  `--fee` overrides.
- **`messagechain broadcast-revoke --hex <bytes> | --file <path>`.**
  Companion on the network-attached side.  Parses the saved
  hex (whitespace-tolerant, so a printed page with newlines
  works), confirms target entity + fee + tx hash, then submits
  via the existing `emergency_revoke` RPC.  No cold key
  required at broadcast time -- the bytes are already signed.

The protocol's `RevokeTransaction` was designed for this
workflow from day one (nonce-free, no expiration; see the
module docstring) -- only the CLI was missing.  Now closed.

### Deployment

Activation height `VERSION_SIGNALING_HEIGHT = 3500` sits well
above the live tip (~451 at release time), giving operators
~20 days of runway to upgrade without protection from this very
gate (which doesn't exist yet).  Manual coordination is the
mitigation for fork-1 itself; future forks use the gate.

Both validators MUST be on 1.11.0 before block 3500 or they
will silently diverge there: blocks produced post-activation
under V2 wire format are rejected by older code as "trailing
bytes," which presents as a fork.  See the design doc in the
operator runbook for the full rollout sequence.

### Changed

- `BLOCK_SERIALIZATION_VERSION` is now `2` (was `1`); both V1
  and V2 are in `_ACCEPTED_BLOCK_SERIALIZATION_VERSIONS` so
  old-format blocks still decode cleanly.

## [1.10.0] — 2026-04-25

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
