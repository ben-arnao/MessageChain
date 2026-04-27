"""Shared validator-runtime methods.

The project has two validator runtimes — `server.Server` (what the
VM runs) and `messagechain.network.node.Node` (better-architected,
but not wired to systemd).  An audit of the two classes found 20
methods duplicated by name; 8 of those were byte-identical modulo
docstring prose, leaving every hardening fix with a "did you edit
both copies?" review cost.  This mixin owns the 8 identical-code
methods so a future fix lands in exactly one place.

Method membership is pinned by `tests/test_shared_runtime_mixin.py`
via an MRO walk — if a contributor re-defines one of these on
either Server or Node, the test fails.

Behavioral-drift methods (_connect_to_peer, _try_produce_block,
_handle_announce_attestation, etc.) are NOT in the mixin — they
need a case-by-case reconciliation pass first, logged in the
hardening-findings doc.

Attributes the mixin reads from `self` (documented here so future
contributors know what the host class owes the mixin):
  * self.blockchain           — Blockchain instance
  * self.peers                — dict[str, Peer]
  * self.ban_manager          — PeerBanManager
  * self._running             — bool, block-production loop gate
  * self._seen_txs            — OrderedDict LRU for tx-hash dedup
  * self._try_produce_block   — coroutine owned by the host class
"""

from __future__ import annotations

import asyncio
import logging

from messagechain.config import (
    OUTBOUND_FULL_RELAY_SLOTS,
    OUTBOUND_BLOCK_RELAY_ONLY_SLOTS,
    SEEN_TX_CACHE_SIZE,
)
from messagechain.network.peer import ConnectionType
from messagechain.network.protocol import MessageType


logger = logging.getLogger(__name__)


class SharedRuntimeMixin:
    """Methods shared verbatim between `Server` and `Node`.

    Both classes inherit from this mixin.  The concrete class
    supplies the attributes listed in the module docstring.
    """

    # ── Observability ──────────────────────────────────────────────

    def _handle_task_exception(self, task_name: str, task: asyncio.Task) -> None:
        """Log uncaught exceptions from background tasks so they don't die silently.

        Without this callback, an exception escaping a ``create_task``-launched
        coroutine is swallowed by asyncio's default handler at garbage-collection
        time. The task dies, the node keeps running as a zombie (listening but
        not producing blocks or syncing), and in a PoS system with an inactivity
        leak, the operator's stake gets slowly drained to zero before anyone
        notices. Loud CRITICAL logging is the minimum viable alarm.
        """
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        logger.critical(
            f"Background task {task_name} crashed: {exc!r}",
            exc_info=(type(exc), exc, exc.__traceback__),
        )

    # ── Chain-state introspection ──────────────────────────────────

    def _current_cumulative_weight(self) -> int:
        """Our node's best-tip cumulative stake weight, for handshakes."""
        best = self.blockchain.fork_choice.get_best_tip()
        return best[2] if best else 0

    # ── Peer bookkeeping ───────────────────────────────────────────

    def _get_peer_writer(self, address: str):
        """Get writer for a peer by address. Used by ChainSyncer."""
        peer = self.peers.get(address)
        if peer and peer.is_connected and peer.writer:
            return (peer.writer, peer)
        return None

    def _on_sync_offense(self, peer_address: str, points: int, reason: str):
        """Callback invoked by ChainSyncer for sync-time misbehavior."""
        self.ban_manager.record_offense(peer_address, points, reason)

    def _next_connection_type(self) -> ConnectionType:
        """Decide the ConnectionType for the next outbound slot.

        Mixes block-relay-only slots with full-relay slots so that a partial
        eclipse can't block our view of blocks. Block-relay-only peers do
        not relay transactions, which also defeats topology inference via
        tx-relay timing analysis (BTC PR #15759).
        """
        full_relay_count = sum(
            1 for p in self.peers.values()
            if p.is_connected and p.connection_type == ConnectionType.FULL_RELAY
        )
        block_only_count = sum(
            1 for p in self.peers.values()
            if p.is_connected and p.connection_type == ConnectionType.BLOCK_RELAY_ONLY
        )
        if full_relay_count < OUTBOUND_FULL_RELAY_SLOTS:
            return ConnectionType.FULL_RELAY
        if block_only_count < OUTBOUND_BLOCK_RELAY_ONLY_SLOTS:
            return ConnectionType.BLOCK_RELAY_ONLY
        return ConnectionType.FULL_RELAY

    # ── Rate-limit policy ──────────────────────────────────────────

    def _msg_category(self, msg_type: MessageType) -> str:
        """Map message type to rate limit category.

        Delegates to the shared dispatch module so Node and Server can
        never drift on rate-limit policy (they did in the past).
        """
        from messagechain.network.dispatch import message_category
        return message_category(msg_type)

    # ── Tx-hash LRU for gossip de-dup ──────────────────────────────

    def _track_seen_tx(self, tx_hash_hex: str):
        """Mark a tx hash as seen (LRU bounded)."""
        if tx_hash_hex in self._seen_txs:
            self._seen_txs.move_to_end(tx_hash_hex)
            return
        if len(self._seen_txs) >= SEEN_TX_CACHE_SIZE:
            self._seen_txs.popitem(last=False)
        self._seen_txs[tx_hash_hex] = True

    # ── Block-production driver ────────────────────────────────────

    async def _block_production_loop(self):
        """Slot-aligned block production with round-based proposer rotation.

        Uses the shared block_producer helper so timing/rotation/RANDAO
        logic stays in lockstep across Server and Node.  See
        messagechain/consensus/block_producer.py for the timing model.
        The host class supplies `_try_produce_block` (the concrete
        producer) and `_running` (the loop gate).
        """
        from messagechain.consensus import block_producer

        # Small startup delay so the host finishes init before first attempt
        await asyncio.sleep(1)

        # Imported lazily so this mixin stays a pure runtime helper
        # without a hard dependency on the consensus package's import
        # order at module-load time.
        from messagechain.consensus.pos import ProposerSkipSlotError
        from messagechain.consensus.height_guard import (
            HeightAlreadySignedError,
        )

        while self._running:
            try:
                await self._try_produce_block()
            except ProposerSkipSlotError as e:
                # Pre-sign local validation rejected this slot's
                # candidate (e.g. round_number > cap on a long-stalled
                # chain).  No floor was advanced; we'll retry at the
                # next slot.  This is the working-as-designed defense
                # against floor poisoning — log at INFO so operators
                # can see slot skips without it looking like an error.
                logger.info("Skipping block production slot: %s", e)
            except HeightAlreadySignedError as e:
                # The persistent same-height guard refused a re-sign.
                # If this fires it's the guard working as designed
                # (crash-restart at the same height) — log at WARNING,
                # not ERROR.  An ERROR-level log here historically
                # produced misleading "block production failed"
                # alarms for what is in fact the correct behavior.
                logger.warning("Same-height sign guard refused: %s", e)
            except Exception:
                logger.exception("Block production iteration failed")

            sleep_seconds = block_producer.next_wake_seconds(self.blockchain)
            await asyncio.sleep(sleep_seconds)
