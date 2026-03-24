"""
Peer connection management for MessageChain P2P network.
"""

import time
from dataclasses import dataclass, field


@dataclass
class Peer:
    host: str
    port: int
    entity_id: str = ""  # hex
    last_seen: float = 0.0
    reader: object = None
    writer: object = None
    is_connected: bool = False

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def touch(self):
        self.last_seen = time.time()

    def is_stale(self, timeout: float = 300) -> bool:
        return (time.time() - self.last_seen) > timeout if self.last_seen > 0 else False
