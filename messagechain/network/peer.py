"""
Peer connection management for MessageChain P2P network.
"""

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from messagechain.config import SEEN_TX_CACHE_SIZE


@dataclass
class Peer:
    host: str
    port: int
    entity_id: str = ""  # hex
    last_seen: float = 0.0
    reader: object = None
    writer: object = None
    is_connected: bool = False
    # inv/getdata: track which tx hashes this peer already knows about
    known_txs: object = field(default_factory=lambda: _LRUSet(SEEN_TX_CACHE_SIZE))

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def touch(self):
        self.last_seen = time.time()

    def is_stale(self, timeout: float = 300) -> bool:
        return (time.time() - self.last_seen) > timeout if self.last_seen > 0 else False


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
