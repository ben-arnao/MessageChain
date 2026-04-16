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
from messagechain.validation import safe_json_loads


class MessageType(Enum):
    HANDSHAKE = "handshake"
    PEER_LIST = "peer_list"
    ANNOUNCE_TX = "announce_tx"
    ANNOUNCE_BLOCK = "announce_block"
    REQUEST_BLOCK = "request_block"
    RESPONSE_BLOCK = "response_block"
    REQUEST_CHAIN_HEIGHT = "request_chain_height"
    RESPONSE_CHAIN_HEIGHT = "response_chain_height"

    # inv/getdata transaction relay (BTC-style)
    INV = "inv"              # announce tx/block hashes we have
    GETDATA = "getdata"      # request full tx/block by hash

    # Attestation relay
    ANNOUNCE_ATTESTATION = "announce_attestation"

    # Slashing evidence relay
    ANNOUNCE_SLASH = "announce_slash"

    # FinalityVote gossip — long-range-attack defense.  Separate
    # from ANNOUNCE_ATTESTATION because finality votes are persistent
    # checkpoints that live in a dedicated mempool pool, not the
    # ephemeral per-slot attestation tracker.
    ANNOUNCE_FINALITY_VOTE = "announce_finality_vote"

    # Non-message-tx gossip: stake / unstake / authority-tx (SetAuthorityKey,
    # Revoke, KeyRotation) / governance txs. Without this, a pending tx
    # submitted to one node would only land in a block if that specific
    # node became proposer — other nodes couldn't see it.  Payload shape:
    #     {"kind": "stake" | "unstake" | "authority" | "governance", "tx": <serialized>}
    # The "kind" tag tells the peer which class to deserialize and which
    # pending pool to enqueue into.
    ANNOUNCE_PENDING_TX = "announce_pending_tx"

    # IBD / Sync messages (headers-first)
    REQUEST_HEADERS = "request_headers"
    RESPONSE_HEADERS = "response_headers"
    REQUEST_BLOCKS_BATCH = "request_blocks_batch"
    RESPONSE_BLOCKS_BATCH = "response_blocks_batch"

    # State-checkpoint bootstrap: let a new full-node / validator skip
    # the replay cost of ancient history by downloading a signed
    # state snapshot from an archive node.  See
    # messagechain/storage/state_snapshot.py and
    # messagechain/consensus/state_checkpoint.py for the object model.
    # Payload shapes:
    #   REQUEST_STATE_CHECKPOINT:  {"block_number": int}
    #   RESPONSE_STATE_CHECKPOINT: {
    #       "checkpoint": <serialized StateCheckpoint>,
    #       "signatures": [<serialized StateCheckpointSignature>, ...],
    #       "snapshot_hex": str,                 # encode_snapshot(...) hex
    #       "checkpoint_block_hex": str,         # Block.to_bytes() hex
    #       "recent_blocks_hex": [str, ...],     # Block.to_bytes() hex each
    #   }
    REQUEST_STATE_CHECKPOINT = "request_state_checkpoint"
    RESPONSE_STATE_CHECKPOINT = "response_state_checkpoint"

    # Active mempool replication — anti-censorship layer on top of
    # passive ANNOUNCE_TX gossip.  A node periodically advertises a
    # compact digest (sorted list of tx_hashes) of its current mempool
    # to a random subset of peers; each recipient pulls any hashes it
    # is missing via REQUEST_MEMPOOL_TX.  The responder replies with
    # the existing ANNOUNCE_TX — one tx-broadcast code path, no
    # duplication.  This defeats the single-captured-node censorship
    # attack: a tx that reaches ANY honest node propagates to every
    # honest node within one sync interval.  Payload shapes:
    #   MEMPOOL_DIGEST:     {"hashes": [<hex>, ...]}
    #   REQUEST_MEMPOOL_TX: {"hashes": [<hex>, ...]}
    MEMPOOL_DIGEST = "mempool_digest"
    REQUEST_MEMPOOL_TX = "request_mempool_tx"


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
        # Strict validation. A peer MUST NOT be able to crash the deserializer
        # with a malformed payload — any defect raises a ValueError which the
        # caller can handle (ban the peer, log, etc.) rather than an
        # uncaught KeyError/TypeError bubbling up through async handlers.
        if not isinstance(data, dict):
            raise ValueError("NetworkMessage data must be a dict")
        if "type" not in data:
            raise ValueError("NetworkMessage missing 'type' field")
        if "payload" not in data:
            raise ValueError("NetworkMessage missing 'payload' field")
        raw_type = data["type"]
        if not isinstance(raw_type, str):
            raise ValueError("NetworkMessage 'type' must be a string")
        try:
            msg_type = MessageType(raw_type)
        except ValueError:
            raise ValueError(f"Unknown NetworkMessage type: {raw_type!r}")
        payload = data["payload"]
        if not isinstance(payload, dict):
            raise ValueError("NetworkMessage 'payload' must be a dict")
        sender_id = data.get("sender_id", "")
        if not isinstance(sender_id, str):
            raise ValueError("NetworkMessage 'sender_id' must be a string")
        return cls(
            msg_type=msg_type,
            payload=payload,
            sender_id=sender_id,
        )


def encode_message(msg: NetworkMessage) -> bytes:
    """Encode a network message with length prefix for TCP framing."""
    json_bytes = json.dumps(msg.serialize()).encode("utf-8")
    length = struct.pack(">I", len(json_bytes))
    return length + json_bytes


def decode_message(data: bytes) -> NetworkMessage:
    """Decode a length-prefixed network message."""
    parsed = safe_json_loads(data.decode("utf-8"), max_depth=32)
    return NetworkMessage.deserialize(parsed)


async def read_message(reader) -> NetworkMessage | None:
    """Read a single length-prefixed message from an asyncio StreamReader."""
    try:
        length_bytes = await reader.readexactly(4)
        length = struct.unpack(">I", length_bytes)[0]
        if length > 1_000_000:  # 1MB sanity limit (reduced from 10MB)
            return None
        data = await reader.readexactly(length)
        return decode_message(data)
    except Exception:
        return None


# Timeout for P2P write operations — a stalled peer must not block the
# async loop indefinitely.  Matches the read timeout (5s handshake +
# 300s idle) but is tighter because a healthy peer should accept data
# within seconds.
P2P_WRITE_TIMEOUT = 10  # seconds


async def write_message(writer, msg: NetworkMessage):
    """Write a single length-prefixed message to an asyncio StreamWriter.

    Enforces P2P_WRITE_TIMEOUT to prevent slow-loris DoS where a peer
    accepts the TCP connection but never reads data, causing the write
    buffer to fill and drain() to block forever.
    """
    import asyncio
    encoded = encode_message(msg)
    writer.write(encoded)
    await asyncio.wait_for(writer.drain(), timeout=P2P_WRITE_TIMEOUT)
