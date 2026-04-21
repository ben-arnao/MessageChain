"""RPC parse-error handling: malformed JSON should get a structured
error response, not a silent socket close.

Iter-3 live-mainnet adversarial probe finding: sending invalid JSON
as the RPC body resulted in EOF with no response body.  An honest
client with a bug sees a cryptic ConnectionError; an attacker
learns nothing either way.  Returning
    {"ok": False, "error": "Invalid JSON: ..."}
improves observability for honest clients and does not leak anything
that wasn't already leaked by the "Unknown method" error path.
"""

from __future__ import annotations

import asyncio
import json
import struct
import unittest
from unittest.mock import MagicMock


class TestRpcInvalidJsonResponse(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        # Build a Server instance without touching disk.  We only need
        # the _handle_rpc_connection coroutine and the rate-limiter /
        # auth knobs it touches before the parse step.
        from server import Server
        self.server = Server.__new__(Server)

        class _AllowAll:
            def check(self, *a, **k):
                return True

        self.server.rpc_rate_limiter = _AllowAll()
        self.server.rpc_auth_enabled = False
        self.server.rpc_auth_token = ""

    async def _drive_handler(self, body: bytes) -> dict | None:
        """Feed `body` through _handle_rpc_connection and capture
        what the handler wrote back (length-prefixed framing).

        Returns the decoded response dict, or None if the handler
        wrote nothing (silent close).
        """
        # Compose the framed request: length prefix + body.
        framed = struct.pack(">I", len(body)) + body

        class _FakeReader:
            def __init__(self, data):
                self._buf = data

            async def readexactly(self, n):
                out, self._buf = self._buf[:n], self._buf[n:]
                return out

        reader = _FakeReader(framed)
        writer_writes: list[bytes] = []

        class _FakeWriter:
            def __init__(self):
                self.closed = False

            def get_extra_info(self, key):
                if key == "peername":
                    return ("127.0.0.1", 12345)
                return None

            def write(self, data):
                writer_writes.append(data)

            async def drain(self):
                pass

            def close(self):
                self.closed = True

        writer = _FakeWriter()
        await self.server._handle_rpc_connection(reader, writer)

        if not writer_writes:
            return None

        combined = b"".join(writer_writes)
        length = struct.unpack(">I", combined[:4])[0]
        body_bytes = combined[4:4 + length]
        return json.loads(body_bytes)

    async def test_invalid_json_returns_structured_error(self):
        resp = await self._drive_handler(b"{not valid json at all")
        self.assertIsNotNone(resp, "Handler silently closed; expected structured error response")
        self.assertIs(resp.get("ok"), False)
        err = resp.get("error", "").lower()
        self.assertIn("json", err, f"Expected 'json' in error, got {resp['error']!r}")

    async def test_overly_deep_json_returns_structured_error(self):
        # safe_json_loads caps depth at 16; 20 levels should be rejected.
        obj = {}
        cur = obj
        for _ in range(20):
            cur["n"] = {}
            cur = cur["n"]
        body = json.dumps({"method": "get_chain_info", "params": {"deep": obj}}).encode()
        resp = await self._drive_handler(body)
        self.assertIsNotNone(resp, "Handler silently closed on deeply nested JSON")
        self.assertIs(resp.get("ok"), False)


if __name__ == "__main__":
    unittest.main()
