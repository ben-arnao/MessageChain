"""
Equivocation watcher — auto-generate slashing evidence from p2p gossip.

The blockchain already slashes double-signers when someone submits a
SlashTransaction containing the two conflicting signatures (see
:mod:`messagechain.consensus.slashing`).  What was missing before this
module: nothing on a running node was *watching the wire* for
equivocation and auto-submitting that evidence.  During the single-
seed bootstrap window (>=2 years) the founder could double-sign
blocks or attestations with zero economic penalty because no honest
party was looking.

The watcher fixes that.  It is a small, in-process component attached
to the Node (see :mod:`messagechain.network.node`).  Every inbound
signed block header and attestation that has already passed signature
verification is fed to ``observe_block_header`` / ``observe_attestation``.
The watcher:

  * Indexes observations by
    ``(validator_id, block_height, round, message_type)``.
  * On a repeat observation with a byte-identical payload — no-op
    (ordinary gossip echo from multiple peers is completely normal).
  * On a repeat observation with a DIFFERENT payload — constructs the
    appropriate evidence object and wraps it in a ``SlashTransaction``
    signed by the local submitter entity, then places it in the node's
    mempool slash pool for inclusion in the next block.

Storage is persistent via ``chaindb.seen_signatures``: a node restart
must not give an equivocator a free pass by restart-timing the
double-sign.  Rows are pruned when older than ``UNBONDING_PERIOD``
because the chain refuses to slash on evidence from before that
window anyway (``Blockchain.validate_slash_transaction``), so keeping
older observations would only waste disk.

Design notes:

  * Size ceiling — the rolling window at ~144 validators × ~1008 blocks
    × ~100 B/row comes to ~15 MB on disk.  Negligible.

  * Mempool dedup — multiple honest watchers will emit identical
    ``evidence_hash`` values (the hash is a pure function of the two
    signed payloads).  The chain's ``_processed_evidence`` dedup
    (``blockchain.py:1627``) accepts the first one and rejects the
    rest, so no special coordination between watchers is needed.

  * Out of scope — surround-vote ("Casper double-vote") detection.
    Attestations in this chain are plain votes with no source/target
    epoch pair, so the attack doesn't apply.  Only double-proposal and
    double-attestation are detected here because those are the only
    two offenses the chain is set up to slash on.

  * Not a daemon — the watcher is synchronous method calls, not a
    background thread.  It runs inline on the same dispatch path as
    block/attestation validation.  Keeping the surface narrow matches
    the "simplicity > cleverness" principle in ``CLAUDE.md``.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from messagechain.config import (
    CHAIN_ID,
    SIG_VERSION_CURRENT,
    UNBONDING_PERIOD,
)
from messagechain.consensus.attestation import Attestation
from messagechain.consensus.slashing import (
    AttestationSlashingEvidence,
    SlashTransaction,
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.core.block import BlockHeader

if TYPE_CHECKING:
    from messagechain.core.blockchain import Blockchain
    from messagechain.core.mempool import Mempool
    from messagechain.identity.identity import Entity
    from messagechain.storage.chaindb import ChainDB


logger = logging.getLogger(__name__)


# Message-type tags stored in chaindb.seen_signatures.message_type.
# Short so the TEXT column stays tiny.
_MSG_BLOCK = "block"
_MSG_ATTEST = "attest"

# Round is not part of BlockHeader or Attestation in the current protocol —
# both message types are produced once per slot.  The schema carries a
# round_number column anyway so a future upgrade that introduces rounds
# (e.g. view-change protocols) does not need a table migration.
_DEFAULT_ROUND = 0


class EquivocationWatcher:
    """Observes signed consensus messages and files slash evidence.

    Parameters
    ----------
    chaindb:
        Persistent store (``seen_signatures`` table).  MUST be the same
        db used by the blockchain — otherwise restart survivability is
        silently broken.
    blockchain:
        Used for current-height queries (pruning cutoff) and for the
        ``_processed_evidence`` / ``slashed_validators`` skip lists so
        we don't produce evidence for a validator that's already been
        slashed.
    mempool:
        Destination for the emitted ``SlashTransaction``.
    submitter_entity:
        Local entity that signs the slash transaction as the submitter
        (the finder of the evidence).  Passing ``None`` degrades the
        watcher to detect-only mode — it still records observations
        and logs equivocations, but doesn't broadcast a slash tx.  A
        non-staking/non-validator node may choose this mode.
    """

    def __init__(
        self,
        chaindb: "ChainDB",
        blockchain: "Blockchain",
        mempool: "Mempool",
        submitter_entity: "Entity | None" = None,
    ):
        self.chaindb = chaindb
        self.blockchain = blockchain
        self.mempool = mempool
        self.submitter_entity = submitter_entity

    # ── observation entry points ─────────────────────────────────

    def observe_block_header(
        self,
        header: BlockHeader,
        current_height: int | None = None,
    ) -> SlashTransaction | None:
        """Record a signed block header; slash if it contradicts an earlier one.

        Returns the ``SlashTransaction`` if equivocation was detected
        and emitted, else ``None``.  The slash tx is also added to the
        mempool slash pool — callers don't have to handle the return
        value for the evidence to propagate.

        ``current_height`` defaults to ``blockchain.height``; tests
        override it to exercise the prune window without building a
        thousand real blocks.
        """
        if header.proposer_signature is None:
            # Unsigned header — can't build evidence anyway.  Silently
            # ignore; this is the caller's job to filter, but belt-and-
            # braces prevents a crash.
            return None

        validator_id = header.proposer_id
        height = header.block_number
        payload = header.to_bytes()
        sig_bytes = header.proposer_signature.to_bytes()

        return self._observe(
            validator_id=validator_id,
            height=height,
            round_number=_DEFAULT_ROUND,
            message_type=_MSG_BLOCK,
            signed_payload=payload,
            signature_bytes=sig_bytes,
            current_height=current_height,
            incoming_object=header,
        )

    def observe_attestation(
        self,
        attestation: Attestation,
        current_height: int | None = None,
    ) -> SlashTransaction | None:
        """Record a signed attestation; slash if it contradicts an earlier one."""
        if attestation.signature is None:
            return None

        validator_id = attestation.validator_id
        height = attestation.block_number
        payload = attestation.to_bytes()
        sig_bytes = attestation.signature.to_bytes()

        return self._observe(
            validator_id=validator_id,
            height=height,
            round_number=_DEFAULT_ROUND,
            message_type=_MSG_ATTEST,
            signed_payload=payload,
            signature_bytes=sig_bytes,
            current_height=current_height,
            incoming_object=attestation,
        )

    # ── maintenance ──────────────────────────────────────────────

    def prune(self, current_height: int | None = None) -> int:
        """Delete observations older than UNBONDING_PERIOD blocks.

        Should be called once per applied block — a single bounded
        DELETE is cheaper than a periodic scan.  Safe to no-op early
        in chain life (current_height < UNBONDING_PERIOD).
        """
        h = self._current_height(current_height)
        cutoff = h - UNBONDING_PERIOD
        if cutoff <= 0:
            return 0
        return self.chaindb.prune_seen_signatures_before(cutoff)

    def has_observation_for(
        self,
        validator_id: bytes,
        block_height: int,
        message_type: str,
        round_number: int = _DEFAULT_ROUND,
    ) -> bool:
        """Introspection helper — used by tests."""
        return (
            self.chaindb.get_seen_signature(
                validator_id, block_height, round_number, message_type,
            )
            is not None
        )

    # ── internal ─────────────────────────────────────────────────

    def _current_height(self, override: int | None) -> int:
        if override is not None:
            return override
        return getattr(self.blockchain, "height", 0)

    def _observe(
        self,
        *,
        validator_id: bytes,
        height: int,
        round_number: int,
        message_type: str,
        signed_payload: bytes,
        signature_bytes: bytes,
        current_height: int | None,
        incoming_object,
    ) -> SlashTransaction | None:
        # Skip already-slashed validators — no point producing more
        # evidence for a validator the chain has already zero'd out.
        if validator_id in getattr(
            self.blockchain, "slashed_validators", set(),
        ):
            return None

        seen_at = self._current_height(current_height)
        existing = self.chaindb.get_seen_signature(
            validator_id, height, round_number, message_type,
        )

        if existing is None:
            # First time we've seen a signed message for this slot —
            # record and exit.
            self.chaindb.add_seen_signature(
                validator_id=validator_id,
                block_height=height,
                round_number=round_number,
                message_type=message_type,
                signed_payload=signed_payload,
                signature_bytes=signature_bytes,
                first_seen_block_height=seen_at,
            )
            return None

        stored_payload, stored_sig, _first_seen = existing
        if stored_payload == signed_payload:
            # Gossip echo — a totally normal byte-identical retransmit.
            return None

        # Equivocation — two distinct signed payloads from the same
        # validator at the same (height, round).  Build evidence.
        logger.warning(
            "Equivocation detected: validator=%s height=%d type=%s — "
            "filing slash evidence",
            validator_id.hex()[:16], height, message_type,
        )
        return self._emit_slash(
            message_type=message_type,
            stored_payload=stored_payload,
            incoming_object=incoming_object,
            validator_id=validator_id,
        )

    def _emit_slash(
        self,
        *,
        message_type: str,
        stored_payload: bytes,
        incoming_object,
        validator_id: bytes,
    ) -> SlashTransaction | None:
        """Reconstruct the stored payload, build evidence, sign and pool."""
        try:
            if message_type == _MSG_BLOCK:
                stored = BlockHeader.from_bytes(stored_payload)
                evidence = SlashingEvidence(
                    offender_id=validator_id,
                    header_a=stored,
                    header_b=incoming_object,
                )
            elif message_type == _MSG_ATTEST:
                stored = Attestation.from_bytes(stored_payload)
                evidence = AttestationSlashingEvidence(
                    offender_id=validator_id,
                    attestation_a=stored,
                    attestation_b=incoming_object,
                )
            else:
                logger.error(
                    "Unknown message_type %r in watcher; skipping",
                    message_type,
                )
                return None
        except Exception as exc:
            # If the stored payload fails to decode we can't build
            # evidence — log loudly but don't crash the node.  This
            # should be unreachable on well-formed data, but a storage-
            # level corruption must not take the whole node down.
            logger.error(
                "Watcher failed to decode stored payload for %s at "
                "validator=%s: %r",
                message_type, validator_id.hex()[:16], exc,
            )
            return None

        # Already-processed evidence: the chain has seen this exact
        # equivocation before — another honest watcher got there first.
        # Swallow silently.
        if evidence.evidence_hash in getattr(
            self.blockchain, "_processed_evidence", set(),
        ):
            return None

        if self.submitter_entity is None:
            # Detect-only mode — no submitter identity, so we can't
            # sign a slash tx.  The observation is still recorded; a
            # future call with a valid submitter will re-emit.  Return
            # None so callers know nothing hit the mempool.
            return None

        # Fee must clear the current base_fee; pay_fee_with_burn rejects
        # any slash tx whose fee is below base_fee.  Reading base_fee
        # live from SupplyTracker keeps the watcher in step with fee
        # market moves instead of hard-coding a number that eventually
        # goes stale.
        base_fee = getattr(
            getattr(self.blockchain, "supply", None), "base_fee", 100,
        )
        try:
            slash_tx = create_slash_transaction(
                self.submitter_entity, evidence, fee=base_fee,
            )
        except Exception as exc:
            logger.error(
                "Failed to build SlashTransaction: %r", exc,
            )
            return None

        self.mempool.add_slash_transaction(slash_tx)
        return slash_tx
