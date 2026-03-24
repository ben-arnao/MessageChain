"""
P2P network protocol for MessageChain.

Defines message types and serialization for node-to-node communication.
Uses JSON over TCP with length-prefixed framing.

New in v2: header sync and batch block download messages for IBD.
"""

import json
import struct
from enum import Enum
from dataclasses import dataclass


class MessageType(Enum):
    HANDSHAKE = "handshake"
    PEER_LIST = "peer_list"
    ANNOUNCE_TX = "announce_tx"
    ANNOUNCE_BLOCK = "announce_block"
    REQUEST_BLOCK = "request_block"
    RESPONSE_BLOCK = "response_block"
    REQUEST_CHAIN_HEIGHT = "request_chain_height"
    RESPONSE_CHAIN_HEIGHT = "response_chain_height"

    # IBD / Sync messages (headers-first)
    REQUEST_HEADERS = "request_headers"
    RESPONSE_HEADERS = "response_headers"
    REQUEST_BLOCKS_BATCH = "request_blocks_batch"
    RESPONSE_BLOCKS_BATCH = "response_blocks_batch"


@dataclass
class NetworkMessage:
    msg_type: MessageType
    payload: dict
    sender_id: str = ""  # entity_id hex

    def serialize(self) -> dict:
        return {
            "type": self.msg_type.value,
            "payload": self.payload,
            "sender_id": self.sender_id,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "NetworkMessage":
        return cls(
            msg_type=MessageType(data["type"]),
            payload=data["payload"],
            sender_id=data.get("sender_id", ""),
        )


def encode_message(msg: NetworkMessage) -> bytes:
    """Encode a network message with length prefix for TCP framing."""
    json_bytes = json.dumps(msg.serialize()).encode("utf-8")
    length = struct.pack(">I", len(json_bytes))
    return length + json_bytes


def decode_message(data: bytes) -> NetworkMessage:
    """Decode a length-prefixed network message."""
    parsed = json.loads(data.decode("utf-8"))
    return NetworkMessage.deserialize(parsed)


async def read_message(reader) -> NetworkMessage | None:
    """Read a single length-prefixed message from an asyncio StreamReader."""
    try:
        length_bytes = await reader.readexactly(4)
        length = struct.unpack(">I", length_bytes)[0]
        if length > 10_000_000:  # 10MB sanity limit
            return None
        data = await reader.readexactly(length)
        return decode_message(data)
    except Exception:
        return None


async def write_message(writer, msg: NetworkMessage):
    """Write a single length-prefixed message to an asyncio StreamWriter."""
    encoded = encode_message(msg)
    writer.write(encoded)
    await writer.drain()
