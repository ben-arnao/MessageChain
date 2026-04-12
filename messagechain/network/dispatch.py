"""
Shared P2P dispatch helpers used by both the Node and Server entry points.

Node and Server historically duplicated message-category mapping and
message-handler dispatch, which led to silent drift (e.g., Server using
`general` for PEER_LIST while Node used `addr`). Centralizing the pieces
that don't depend on class state — currently just `message_category` —
is the minimum change that removes the demonstrated drift and gives us
one place to update when new message types are added.

Full consolidation of the dispatch tree is a bigger structural change
tracked as a follow-up.
"""

from messagechain.network.protocol import MessageType


def message_category(msg_type: MessageType) -> str:
    """Map a network message type to its rate-limit bucket category.

    Buckets (see messagechain.network.ratelimit):
        tx          — transaction gossip, block announce-by-inv
        block_req   — explicit block/block-batch requests
        headers_req — header download requests
        addr        — ADDR-equivalent peer-list gossip (strictly throttled)
        general     — handshakes, chain-height probes, everything else

    Any message type that isn't explicitly mapped falls into `general`.
    """
    if msg_type in (MessageType.ANNOUNCE_TX, MessageType.INV, MessageType.GETDATA):
        return "tx"
    if msg_type in (MessageType.REQUEST_BLOCK, MessageType.REQUEST_BLOCKS_BATCH):
        return "block_req"
    if msg_type == MessageType.REQUEST_HEADERS:
        return "headers_req"
    if msg_type == MessageType.PEER_LIST:
        # ADDR-equivalent — strictly throttled to prevent eclipse-prep
        # flooding (BTC PR #22387).
        return "addr"
    return "general"
