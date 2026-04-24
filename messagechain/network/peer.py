"""
Peer connection management for MessageChain P2P network.

Connection types (Bitcoin Core-inspired):
- FULL_RELAY: Standard connection that relays blocks, transactions, and addresses.
- BLOCK_RELAY_ONLY: Only relays blocks. Prevents network topology mapping via
  transaction relay timing analysis.
- ANCHOR: Persisted across restarts to prevent eclipse attacks on reboot.
  Functionally identical to BLOCK_RELAY_ONLY during operation.
- FEELER: Short-lived probe to verify address reachability. No relay at all.
"""

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from messagechain.config import SEEN_TX_CACHE_SIZE


class ConnectionType(Enum):
    """Type of peer connection, following Bitcoin Core's connection model."""
    FULL_RELAY = "full_relay"
    BLOCK_RELAY_ONLY = "block_relay_only"
    ANCHOR = "anchor"
    FEELER = "feeler"


@dataclass
class Peer:
    host: str
    port: int
    entity_id: str = ""  # hex
    last_seen: float = 0.0
    reader: object = None
    writer: object = None
    is_connected: bool = False
    connection_type: ConnectionType = ConnectionType.FULL_RELAY
    # Observability metadata — surfaced via the get_peers RPC.  None of
    # these participate in consensus; they exist so operators can see
    # the network shape from the CLI without scraping journald.
    direction: str = "inbound"       # "inbound" | "outbound"
    connected_at: float = 0.0        # unix seconds; 0 until socket opens
    peer_height: int = 0             # peer's last-reported chain height
    peer_version: str = ""           # peer's self-reported version string
    # The listen port the remote advertised in its HANDSHAKE payload.
    # For outbound peers this equals self.port (we dialed the listen
    # port). For inbound peers self.port is the remote's ephemeral
    # source port — advertised_port is how the maintenance loop
    # recognizes "I already have a session with the validator at
    # (host, listen_port)" and skips a redundant re-dial that would
    # just race into the entity-level dedup and churn.
    advertised_port: int = 0
    # Transport security: "plain" | "tls".  Set by the connection-
    # establishment path when it knows whether the socket was wrapped
    # in an SSLContext.  Default is "plain" — an honest default lets
    # an operator trust the CLI output when auditing whether
    # P2P_TLS_ENABLED is actually taking effect across the fleet.
    transport: str = "plain"
    # True once this side has written its HANDSHAKE to the peer. Outbound
    # sets it when dialing; inbound sets it after echoing the peer's
    # HANDSHAKE back. Prevents the observability-only echo from re-firing
    # on every inbound HANDSHAKE a reconnecting peer might send.
    handshake_sent: bool = False
    # inv/getdata: track which tx hashes this peer already knows about
    known_txs: object = field(default_factory=lambda: _LRUSet(SEEN_TX_CACHE_SIZE))

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def touch(self):
        self.last_seen = time.time()

    def is_stale(self, timeout: float = 300) -> bool:
        return (time.time() - self.last_seen) > timeout if self.last_seen > 0 else False

    def should_relay_tx(self) -> bool:
        """Only FULL_RELAY connections relay transactions."""
        return self.connection_type == ConnectionType.FULL_RELAY

    def is_feeler(self) -> bool:
        """Feeler connections are transient probes."""
        return self.connection_type == ConnectionType.FEELER


class _LRUSet:
    """Bounded set that evicts oldest entries when full. Used to track seen tx hashes."""

    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self._data: OrderedDict = OrderedDict()

    def add(self, item):
        if item in self._data:
            self._data.move_to_end(item)
            return
        if len(self._data) >= self.maxsize:
            self._data.popitem(last=False)
        self._data[item] = True

    def __contains__(self, item):
        return item in self._data

    def __len__(self):
        return len(self._data)
