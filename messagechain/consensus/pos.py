"""
Proof-of-Stake consensus for MessageChain.

Validators stake tokens to participate in block production.
The proposer for each block is selected deterministically based on
the previous block hash and stake-weighted randomness.

Validators also attest (vote) for blocks they consider valid. A block
needs 2/3+ of total stake attesting to become finalized. Finalized
blocks can never be reverted.
"""

import hashlib
import struct
import time
from messagechain.config import (
    HASH_ALGO, VALIDATOR_MIN_STAKE,
    CONSENSUS_THRESHOLD_NUMERATOR,
    CONSENSUS_THRESHOLD_DENOMINATOR, MAX_TXS_PER_BLOCK, MAX_BLOCK_MESSAGE_BYTES,
)
from messagechain.core.block import Block, BlockHeader, compute_merkle_root
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import verify_signature
from messagechain.consensus.attestation import Attestation, create_attestation, verify_attestation
from messagechain.crypto.hashing import default_hash


def _hash(data: bytes) -> bytes:
    return default_hash(data)


class ProposerSkipSlotError(RuntimeError):
    """Raised by ``create_block`` when the candidate block would fail
    the validator-side rejection rules that depend solely on
    (header, prev_block, wall-clock now).

    Distinct from ``HeightAlreadySignedError``: this is raised BEFORE
    the height-guard floor is reserved, so the floor is unaffected and
    the proposer may legitimately retry at the same height in a future
    slot.  Catching this in the block-production loop and skipping the
    slot is the correct response.

    The bug this prevents: pre-fix, ``record_block_sign`` ran before
    these checks, so a candidate that would be rejected downstream
    (e.g. round_number > MAX_PROPOSER_FALLBACK_ROUNDS on a long-stalled
    chain) still permanently advanced the height-guard floor.  After
    that, every legitimate retry at the same height was refused as
    "already signed at height N" — the chain wedged with no recovery
    path short of manual floor surgery.

    See ``_local_pre_sign_validation`` for the rule list, and
    ``tests/test_proposer_floor_not_poisoned_on_local_rejection.py``
    for the regression coverage.
    """


def _local_pre_sign_validation(
    header,
    prev_block,
    *,
    now: float | None = None,
    median_time_past: float | None = None,
) -> str | None:
    """Mirror the (header, prev_block, wall-clock)-only rejection rules
    from ``Blockchain.validate_block``.

    Returns ``None`` if the candidate block would NOT be rejected by
    any of these rules; returns a short error string explaining the
    rejection otherwise.

    The rules covered are exactly those that depend solely on the
    candidate header, the parent block, and the proposer's wall-clock
    time — not on full state-machine application, signature
    verification, mempool content, or anything else heavy.  They are
    the only rules that can fire AFTER the proposer has built the
    block but BEFORE any validator-side state work is done, which makes
    them the rules that risk poisoning the height-guard floor on
    rejection (the floor is reserved inside ``create_block`` itself).

    Mirroring authoritative checks like this is a deliberate
    duplication.  The contract is: the validator-side check is the
    one consensus runs against; the pre-sign check is a defensive
    pre-flight that prevents floor poisoning on our own rejected
    blocks.  If the two ever drift, the worst case is a block we
    pre-accepted gets rejected by the network (small liveness loss,
    no equivocation, no floor poisoning — because the floor is now
    only reserved if BOTH the pre-sign check AND the eventual
    validator-side check accept the timestamp; see ``create_block``).
    Drift in the other direction (pre-sign accepts what the network
    would reject) is the historical bug we're fixing.

    Coverage as of this fix:
      * timestamp-too-early (``ts_gap < BLOCK_TIME_TARGET``)
      * round-cap (``round_number > MAX_PROPOSER_FALLBACK_ROUNDS``)
      * future-drift (``timestamp > now + MAX_BLOCK_FUTURE_DRIFT``)
      * MTP, when ``median_time_past`` is supplied by the caller

    Other validate_block rules — state-root match, signature
    verification, fee/byte-budget, etc. — are NOT mirrored here
    because they don't fire on (header, prev, now) alone.  If a
    future rule does, add it here too.
    """
    # The whole pre-sign check is gated on ``ENFORCE_SLOT_TIMING``.
    # The test conftest pins this to False to let unit tests assemble
    # synthetic block sequences (back-to-back same-second blocks for
    # MTP coverage, far-future timestamps for VRF lookahead coverage,
    # etc.) without slot-timing constraints.  Production keeps it
    # True so all four rules fire and the height-guard floor is
    # never advanced for a block the validator-side would reject.
    #
    # Pre-sign being slightly weaker than validator-side in test mode
    # is safe by design: the floor-poisoning concern only matters
    # when a height-guard is attached and a real signature is
    # produced, which is the production wiring path.  Tests that
    # exercise the floor-poisoning property explicitly toggle
    # ENFORCE_SLOT_TIMING=True in their setUp/tearDown — see
    # tests/test_proposer_floor_not_poisoned_on_local_rejection.py.
    import messagechain.config as _cfg
    if not getattr(_cfg, "ENFORCE_SLOT_TIMING", True):
        return None

    from messagechain.config import (
        BLOCK_TIME_TARGET,
        MAX_PROPOSER_FALLBACK_ROUNDS,
        MAX_BLOCK_FUTURE_DRIFT,
    )

    if now is None:
        now = time.time()

    ts_gap = header.timestamp - prev_block.header.timestamp
    if ts_gap < BLOCK_TIME_TARGET:
        return (
            f"timestamp too early: gap {ts_gap:.0f}s < "
            f"BLOCK_TIME_TARGET {BLOCK_TIME_TARGET}s"
        )
    round_number = int((ts_gap - BLOCK_TIME_TARGET) // BLOCK_TIME_TARGET)
    if round_number > MAX_PROPOSER_FALLBACK_ROUNDS:
        return (
            f"proposer round {round_number} exceeds cap "
            f"{MAX_PROPOSER_FALLBACK_ROUNDS} — would be rejected by "
            f"validate_block as timestamp-skew slot hijacking"
        )
    if header.timestamp > now + MAX_BLOCK_FUTURE_DRIFT:
        return (
            f"timestamp {header.timestamp} > now + "
            f"MAX_BLOCK_FUTURE_DRIFT ({MAX_BLOCK_FUTURE_DRIFT}s)"
        )
    if median_time_past is not None and header.timestamp <= median_time_past:
        return (
            f"timestamp {header.timestamp} <= median_time_past "
            f"{median_time_past}"
        )
    return None


class ProofOfStake:
    """Stake-weighted block proposer selection and validation."""

    def __init__(self):
        self.stakes: dict[bytes, int] = {}  # entity_id -> staked amount
        self._bootstrap_ended: bool = False  # one-way flag

    @property
    def is_bootstrap_mode(self) -> bool:
        """PoS-local "not enough validators yet" heuristic.

        Stays active until at least MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        distinct validators are registered — once exited, the flag is
        one-way.

        This is NOT the canonical bootstrap state.  The canonical signal
        is `Blockchain.bootstrap_progress` (a monotonic [0, 1] gradient
        that drives min-stake, attester-committee weighting, escrow
        window, and seed-exclusion rules — see
        messagechain/consensus/bootstrap_gradient.py).  This property
        survives as a local PoS-layer signal used by
        `validate_block_attestations`, which does not have a Blockchain
        reference and needs a local answer to "is the validator set
        large enough for a 2/3-of-stake threshold to count as finality?"
        The historical name is kept so dynamic test overrides continue
        to work without churn (see tests/__init__.py).
        """
        if self._bootstrap_ended:
            return False
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        return len(self.stakes) < MIN_VALIDATORS_TO_EXIT_BOOTSTRAP

    def register_validator(self, entity_id: bytes, stake_amount: int, block_height: int = 0) -> bool:
        """Register a validator with their stake."""
        if stake_amount < VALIDATOR_MIN_STAKE:
            return False
        self.stakes[entity_id] = self.stakes.get(entity_id, 0) + stake_amount
        # Local bootstrap-heuristic ends once we have enough distinct
        # validators for the finality floor.  This only flips a PoS-
        # internal flag; the canonical bootstrap signal
        # (Blockchain.bootstrap_progress) is independent.
        from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        if len(self.stakes) >= MIN_VALIDATORS_TO_EXIT_BOOTSTRAP:
            self._bootstrap_ended = True
        return True

    def remove_validator(self, entity_id: bytes):
        self.stakes.pop(entity_id, None)

    @property
    def total_stake(self) -> int:
        return sum(self.stakes.values())

    @property
    def validator_count(self) -> int:
        return len(self.stakes)

    def select_proposer(
        self,
        prev_block_hash: bytes,
        randao_mix: bytes | None = None,
        round_number: int = 0,
    ) -> bytes | None:
        """
        Deterministically select the block proposer for a given round.

        Uses the previous block hash, optional RANDAO mix, and the round
        number as the seed. Every node computes the same result for the
        same chain state and round.

        round_number rotates the proposer when an earlier round timed out
        without producing a block. Round 0 is the primary proposer; round
        N is the fallback after the previous N proposers failed to produce
        within their slot window. This is the network's liveness escape
        hatch — without it, a single offline validator stalls the chain
        forever.
        """
        if not self.stakes:
            return None

        # Sort validators for deterministic ordering
        validators = sorted(self.stakes.items(), key=lambda x: x[0])
        total = self.total_stake
        if total == 0:
            return None  # all stakes are zero — no valid proposer

        # Build seed from prev_block_hash, optional RANDAO mix, and round number
        seed_input = prev_block_hash
        if randao_mix is not None:
            seed_input = seed_input + randao_mix
        seed_input = seed_input + struct.pack(">I", round_number)
        seed = _hash(seed_input + b"proposer_selection")
        rand_value = int.from_bytes(seed, "big") % total

        # Stake-weighted selection
        cumulative = 0
        for entity_id, stake in validators:
            cumulative += stake
            if rand_value < cumulative:
                return entity_id

        return validators[-1][0]  # fallback

    def validate_proposer(
        self,
        entity_id: bytes,
        prev_block_hash: bytes,
        randao_mix: bytes | None = None,
        round_number: int = 0,
    ) -> bool:
        """Check if entity_id is the legitimate proposer for the given round."""
        expected = self.select_proposer(prev_block_hash, randao_mix=randao_mix, round_number=round_number)
        return expected == entity_id

    def validate_block_attestations(
        self,
        block: Block,
        public_keys: dict[bytes, bytes] | None = None,
    ) -> bool:
        """
        Check that enough validators have attested to the block's parent.

        Requires >= CONSENSUS_THRESHOLD of total stake to have attested.
        Attestations are carried in the block and vote for the parent block.

        During bootstrap (no validators staked), this is permissive.
        """
        bootstrap = self.is_bootstrap_mode

        total = self.total_stake
        if total == 0 and not bootstrap:
            return False  # post-bootstrap with zero stake — cannot meet threshold

        # SECURITY: during bootstrap we relax the THRESHOLD requirement
        # (accepting blocks with fewer attestations) but we still VERIFY
        # SIGNATURES on any attestations that are present, when public keys
        # are available.  Earlier revisions returned True immediately in
        # bootstrap, which let forged attestations become "finalized" before
        # the network hardened.
        if public_keys is not None and block.attestations:
            for att in block.attestations:
                pub = public_keys.get(att.validator_id)
                if pub is not None and not verify_attestation(att, pub):
                    return False  # bad sig — reject even in bootstrap

        if bootstrap:
            return True  # threshold is relaxed, but sigs were checked above

        # Post-bootstrap: require public keys for attestation counting.
        if public_keys is None:
            return False

        attested_stake = 0
        seen = set()
        for att in block.attestations:
            if att.validator_id in seen:
                continue  # skip duplicates
            seen.add(att.validator_id)

            # H1: Attestations must vote for the parent block. Reject
            # attestations for a different block hash or block number —
            # prevents replaying valid attestations from other blocks.
            if att.block_hash != block.header.prev_hash:
                continue
            if att.block_number != block.header.block_number - 1:
                continue

            # A validator's public key must be known AND the attestation
            # signature must verify. Anything else is rejected.
            pub = public_keys.get(att.validator_id)
            if pub is None:
                continue
            if not verify_attestation(att, pub):
                continue

            if att.validator_id in self.stakes:
                attested_stake += self.stakes[att.validator_id]

        # Integer arithmetic to avoid floating-point rounding errors in consensus.
        # attested/total >= NUM/DEN  ↔  attested * DEN >= total * NUM
        return (attested_stake * CONSENSUS_THRESHOLD_DENOMINATOR
                >= total * CONSENSUS_THRESHOLD_NUMERATOR)

    def create_block(
        self,
        proposer_entity,
        transactions: list[MessageTransaction],
        prev_block: Block,
        state_root: bytes = b"\x00" * 32,
        attestations: list[Attestation] | None = None,
        transfer_transactions: list | None = None,
        slash_transactions: list | None = None,
        governance_txs: list | None = None,
        authority_txs: list | None = None,
        stake_transactions: list | None = None,
        unstake_transactions: list | None = None,
        finality_votes: list | None = None,
        custody_proofs: list | None = None,
        censorship_evidence_txs: list | None = None,
        bogus_rejection_evidence_txs: list | None = None,
        timestamp: float | None = None,
        state_root_checkpoint: bytes = b"\x00" * 32,
        acks_observed_this_block: list[bytes] | None = None,
        react_transactions: list | None = None,
        inclusion_list_violation_evidence_txs: list | None = None,
        inclusion_list=None,
    ) -> Block:
        """Create a new block as the selected proposer.

        Attestations are votes for the parent block (prev_block), collected
        from validators after the parent was proposed.

        slash_transactions (if any) are committed into the merkle_root so
        that a byzantine relayer cannot strip them from the block without
        invalidating the proposer's signature. Previously, slash_transactions
        were attached post-signing and not cryptographically bound — any
        relay node could drop them in transit.
        """
        # Best-fit knapsack fill: walk the density-sorted candidate list
        # and skip txs that don't fit in the remaining byte budget,
        # rather than stopping at the first oversize tx.  When a 1024B
        # tx can't fit but a 200B tx further down the list can, we
        # still pack it — keeps the byte budget tight under the
        # fee-per-byte selection priority.  Stop only when the count
        # cap is hit or the candidate list is exhausted.
        txs = []
        msg_bytes_used = 0
        for tx in transactions:
            if len(txs) >= MAX_TXS_PER_BLOCK:
                break
            tx_msg_size = len(tx.message)
            if msg_bytes_used + tx_msg_size > MAX_BLOCK_MESSAGE_BYTES:
                continue  # too big to fit here; try smaller txs next
            txs.append(tx)
            msg_bytes_used += tx_msg_size
        transfer_txs = (transfer_transactions or [])[:MAX_TXS_PER_BLOCK]
        slash_txs = list(slash_transactions or [])
        gov_txs = list(governance_txs or [])
        auth_txs = list(authority_txs or [])
        stake_txs = list(stake_transactions or [])
        unstake_txs = list(unstake_transactions or [])
        fin_votes = list(finality_votes or [])
        cust_proofs = list(custody_proofs or [])
        censorship_txs = list(censorship_evidence_txs or [])
        bogus_rej_txs = list(bogus_rejection_evidence_txs or [])
        acks_observed = list(acks_observed_this_block or [])
        react_txs = list(react_transactions or [])
        il_violation_txs = list(inclusion_list_violation_evidence_txs or [])
        # Optional scalar — None means "no list this block".
        included_inclusion_list = inclusion_list

        # Tier 18: enforce the unified per-block byte budget across
        # Message + Transfer + React.  Without this trim, an honest
        # proposer pulling near MAX_TXS_PER_BLOCK from each lane would
        # exceed MAX_BLOCK_TOTAL_BYTES and validators would reject the
        # block — wasting the proposer's slot.  Trim policy: while over
        # budget, evict the lowest-fee-per-byte entry across the three
        # lanes.  This mirrors the validate_block budget check
        # symmetrically (same byte accounting, same set of kinds) and
        # matches the chain-wide fee-density selection priority — the
        # txs the proposer would have lost the most revenue keeping
        # are the ones to drop first.
        from messagechain.config import (
            TIER_18_HEIGHT as _TIER_18_H,
            MAX_BLOCK_TOTAL_BYTES as _MAX_TOTAL_B,
        )
        new_block_number_preview = prev_block.header.block_number + 1
        if new_block_number_preview >= _TIER_18_H:
            def _density(t) -> float:
                try:
                    return t.fee / max(1, len(t.to_bytes()))
                except Exception:
                    return float(t.fee)
            def _size(t) -> int:
                try:
                    return len(t.to_bytes())
                except Exception:
                    return 0
            # Build a unified candidate list with lane tags so we can
            # evict from the right list.
            unified = (
                [("msg", t) for t in txs]
                + [("xfer", t) for t in transfer_txs]
                + [("react", t) for t in react_txs]
            )
            total_bytes = sum(_size(t) for _lane, t in unified)
            if total_bytes > _MAX_TOTAL_B:
                # Sort ascending by density so the lowest is at index 0.
                unified.sort(key=lambda lt: _density(lt[1]))
                while unified and total_bytes > _MAX_TOTAL_B:
                    lane, victim = unified.pop(0)
                    total_bytes -= _size(victim)
                    if lane == "msg":
                        txs = [t for t in txs if t.tx_hash != victim.tx_hash]
                    elif lane == "xfer":
                        transfer_txs = [
                            t for t in transfer_txs if t.tx_hash != victim.tx_hash
                        ]
                    elif lane == "react":
                        react_txs = [
                            t for t in react_txs if t.tx_hash != victim.tx_hash
                        ]

        # Route through the canonical tx-hash builder so proposer and
        # validator cannot drift on what's in the merkle tree.  We
        # assemble a minimal namespace-like object that exposes the
        # attributes `canonical_block_tx_hashes` reads from a Block —
        # we don't have a Block yet at this point (we're building it).
        from types import SimpleNamespace
        _block_like = SimpleNamespace(
            transactions=txs,
            transfer_transactions=transfer_txs,
            slash_transactions=slash_txs,
            governance_txs=gov_txs,
            authority_txs=auth_txs,
            stake_transactions=stake_txs,
            unstake_transactions=unstake_txs,
            finality_votes=fin_votes,
            custody_proofs=cust_proofs,
            censorship_evidence_txs=censorship_txs,
            bogus_rejection_evidence_txs=bogus_rej_txs,
            acks_observed_this_block=acks_observed,
            react_transactions=react_txs,
            inclusion_list_violation_evidence_txs=il_violation_txs,
            inclusion_list=included_inclusion_list,
        )
        from messagechain.core.block import canonical_block_tx_hashes
        tx_hashes = canonical_block_tx_hashes(_block_like)
        merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")

        # mempool_snapshot_root is retired (was the inclusion-attestation
        # audit layer, superseded by inclusion_list's consensus-objective
        # slashing).  Field retained in the header for historical block
        # compat; new blocks always set zeros.
        snapshot_root = b"\x00" * 32

        # Clamp against parent.timestamp so an honest proposer with a
        # wall clock that trails the parent's header (e.g., the previous
        # proposer's clock ran ahead, or the NTP sync on this host is
        # late) still emits a block that passes
        # `block.header.timestamp > parent.header.timestamp`.  Without
        # this floor, a single future-dated parent can deny every
        # subsequent honest slot until wall clock catches up.  Callers
        # passing an explicit timestamp (tests / special harnesses) keep
        # their exact value so negative-path tests can still construct
        # invalid blocks on purpose.
        if timestamp is None:
            chosen_ts = max(time.time(), prev_block.header.timestamp + 1)
        else:
            chosen_ts = timestamp
        # Validator version signaling (Fork 1): blocks produced at/after
        # VERSION_SIGNALING_HEIGHT carry CURRENT_VALIDATOR_VERSION in
        # the header so peers (and future activation gates) can tell
        # which release minted them.  Pre-activation blocks default the
        # field to UNSIGNALLED so signable_data() omits it under V1
        # wire format and the original block hash is preserved.
        from messagechain.config import VERSION_SIGNALING_HEIGHT
        from messagechain.consensus.validator_versions import (
            CURRENT_VALIDATOR_VERSION,
            UNSIGNALLED as _VV_UNSIGNALLED,
        )
        new_block_number = prev_block.header.block_number + 1
        if new_block_number >= VERSION_SIGNALING_HEIGHT:
            stamped_version = CURRENT_VALIDATOR_VERSION
        else:
            stamped_version = _VV_UNSIGNALLED
        header = BlockHeader(
            version=1,
            block_number=new_block_number,
            prev_hash=prev_block.block_hash,
            merkle_root=merkle_root,
            timestamp=chosen_ts,
            proposer_id=proposer_entity.entity_id,
            state_root=state_root,
            mempool_snapshot_root=snapshot_root,
            state_root_checkpoint=state_root_checkpoint,
            validator_version=stamped_version,
        )

        # Guard against WOTS+ leaf reuse: if the proposer also has
        # transactions in this block (signed earlier, possibly before a
        # keypair restart), the keypair's _next_leaf may not have been
        # advanced past those txs' leaves.  Scan all tx lists for the
        # proposer's entity_id and advance past the highest used leaf to
        # guarantee the header signature gets a fresh leaf.
        proposer_id = proposer_entity.entity_id
        for tx_list in (txs, transfer_txs, slash_txs, gov_txs,
                        auth_txs, stake_txs, unstake_txs):
            for tx in tx_list:
                tx_entity = getattr(tx, "entity_id", None)
                if tx_entity == proposer_id:
                    sig = getattr(tx, "signature", None)
                    if sig is not None and hasattr(sig, "leaf_index"):
                        proposer_entity.keypair.advance_to_leaf(sig.leaf_index + 1)

        # Pre-sign local validation.  Mirror the validator-side
        # rejection rules that depend solely on (header, prev_block,
        # wall-clock now), so a candidate that the network would
        # reject is caught HERE — before the height-guard reservation
        # below — and never poisons the floor.
        #
        # Why this is load-bearing: the height-guard floor is durable
        # by design (a crash-restart must refuse to re-sign at any
        # height where a prior signature could have escaped the
        # process).  Pre-fix, ``record_block_sign`` ran before
        # ``add_block``'s validation, so a candidate rejected
        # downstream (round-cap, future-drift, etc.) advanced the
        # floor anyway — every legitimate retry at the same height
        # was then refused as "already signed", with no recovery short
        # of manual floor surgery.  Running these checks pre-sign
        # closes that path: the floor only ratchets when the block
        # would actually pass network validation, while the
        # crash-restart equivocation guarantee is preserved (the
        # floor still ratchets BEFORE the signing call below).
        # MTP is handled by the outer ``Blockchain.propose_block`` (it
        # computes the timestamp as ``max(now, mtp + epsilon)``) so by
        # the time we land here the MTP rule is already satisfied for
        # the production path.  Tests that invoke ``create_block``
        # directly with an explicit ``timestamp`` are expected to know
        # what they're doing; we don't have chain access here to
        # second-guess them.
        local_err = _local_pre_sign_validation(header, prev_block)
        if local_err is not None:
            raise ProposerSkipSlotError(
                f"create_block at height {new_block_number} rejected "
                f"pre-sign: {local_err}; skipping slot without advancing "
                f"the height-guard floor"
            )

        # Tier 23 same-height sign guard.  If the proposer entity has a
        # ``height_sign_guard`` attached (production validators wire one
        # in at startup; tests omit it), reserve the proposer-signing
        # slot at this height BEFORE signing.  If the guard refuses
        # (HeightAlreadySignedError) we propagate the exception — the
        # caller's "we already produced a block at this height" recovery
        # is the right response (skip this slot, log loudly), which is
        # exactly what the audit anchor demands: an honest crash-restart
        # must NOT produce two byte-different headers at the same
        # height.  See messagechain.consensus.height_guard for the
        # persist-before-sign ratchet rationale.
        guard = getattr(proposer_entity, "height_sign_guard", None)
        if guard is not None:
            guard.record_block_sign(new_block_number)

        # If anything between the reserve above and the ``return block``
        # below raises, the floor stays advanced with no signature
        # reaching the caller — exactly the floor-poisoning shape that
        # wedged the chain at heights 671/672 in the 2026-04-27
        # incident.  Wrap the post-reserve work so any failure path
        # rolls the floor back durably.  Successful return commits the
        # reservation as before.
        #
        # The caller (``server.py``'s ``_try_produce_block_sync``) is
        # ALSO responsible for calling ``guard.rollback_block_sign``
        # when ``add_block`` rejects a block this method returned —
        # state-root mismatches and other state-machine-level
        # rejections fire AFTER ``create_block`` has returned and
        # cannot be detected here.  The two rollback paths together
        # close the entire window between reserve-and-broadcast.
        try:
            # Proposer signs the block header. randao_mix is excluded from
            # signable_data to break a circular dependency (the mix is derived
            # from this very signature) but is bound to the block via _compute_hash.
            header_hash = _hash(header.signable_data())
            header.proposer_signature = proposer_entity.keypair.sign(header_hash)

            # Derive RANDAO mix from parent.randao_mix + proposer signature.
            # Each grinding attempt requires a new signature → consumes a fresh
            # WOTS+ leaf, observable on chain via proposer_sig_counts.
            from messagechain.consensus.randao import derive_randao_mix
            header.randao_mix = derive_randao_mix(
                prev_block.header.randao_mix, header.proposer_signature
            )

            block = Block(
                header=header,
                transactions=txs,
                attestations=attestations or [],
                transfer_transactions=transfer_txs,
                slash_transactions=slash_txs,
                governance_txs=gov_txs,
                authority_txs=auth_txs,
                stake_transactions=stake_txs,
                unstake_transactions=unstake_txs,
                finality_votes=fin_votes,
                custody_proofs=cust_proofs,
                censorship_evidence_txs=censorship_txs,
                bogus_rejection_evidence_txs=bogus_rej_txs,
                acks_observed_this_block=acks_observed,
                react_transactions=react_txs,
                inclusion_list_violation_evidence_txs=il_violation_txs,
                inclusion_list=included_inclusion_list,
            )
            block.block_hash = block._compute_hash()
            return block
        except BaseException:
            if guard is not None:
                try:
                    guard.rollback_block_sign(new_block_number)
                except Exception:
                    # Rollback durability failure during exception
                    # handling — log and proceed.  The original
                    # exception is the user-visible one; the floor
                    # may be left poisoned, in which case the operator
                    # sees a HeightAlreadySignedError on the next
                    # propose attempt and can investigate.  Don't
                    # mask the original failure.
                    import logging as _logging
                    _logging.getLogger(__name__).exception(
                        "rollback_block_sign(%d) raised during "
                        "create_block exception handling — floor may "
                        "remain poisoned",
                        new_block_number,
                    )
            raise
