"""Input validation utilities for MessageChain.

Centralizes security-critical input validation: hex parsing, JSON depth
limiting, and error sanitization. All trust-boundary code should use
these instead of raw bytes.fromhex() or json.loads().
"""

import json
import re


def parse_hex(hex_string: str, expected_len: int | None = None) -> bytes | None:
    """Safely parse a hex string into bytes.

    Returns None on invalid input instead of raising an exception.
    Optionally validates the decoded byte length.
    """
    if not hex_string or not isinstance(hex_string, str):
        return None
    if len(hex_string) % 2 != 0:
        return None
    try:
        result = bytes.fromhex(hex_string)
    except ValueError:
        return None
    if expected_len is not None and len(result) != expected_len:
        return None
    return result


# Known business-logic error messages that are safe to return to clients.
_SAFE_ERROR_PATTERNS = [
    "Unknown entity",
    "Entity not found",
    "Entity already registered",
    "Insufficient balance",
    "Invalid nonce",
    "Invalid signature",
    "Invalid transaction",
    "Invalid stake",
    "Invalid unstake",
    "Invalid transfer",
    "Unknown method",
    "Transaction rejected",
    "already registered",
    "not registered",
]


def sanitize_error(error_msg: str) -> str:
    """Sanitize an error message for external RPC responses.

    Passes through known business-logic errors verbatim.
    Replaces unknown errors with a generic message to prevent
    leaking file paths, line numbers, or internal state.
    """
    for pattern in _SAFE_ERROR_PATTERNS:
        if pattern.lower() in error_msg.lower():
            return error_msg
    return "Internal error"


class JSONDepthError(Exception):
    """Raised when JSON exceeds the allowed nesting depth."""
    pass


def _check_depth(obj, max_depth: int, current: int = 0):
    """Recursively check JSON nesting depth."""
    if current > max_depth:
        raise JSONDepthError(f"JSON nesting exceeds max depth of {max_depth}")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, max_depth, current + 1)
    elif isinstance(obj, list):
        for v in obj:
            _check_depth(v, max_depth, current + 1)


def _prescan_depth(text: str, max_depth: int) -> None:
    """Streaming-style depth check on raw JSON text.

    Counts '{'/'['/']'/'}' nesting while respecting string literals and
    escape sequences. This runs BEFORE json.loads(), so a pathological
    input like '{{{...}}}' with millions of levels is rejected without
    ever materialising the nested Python object.

    We still run the post-parse `_check_depth` for belt-and-braces, but
    the prescan is what makes the function safe against JSON-bomb DoS.
    """
    if isinstance(text, (bytes, bytearray)):
        # json.loads accepts bytes; we need str for our scanner.
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("safe_json_loads: invalid UTF-8")
    depth = 0
    in_string = False
    escape = False
    limit = max_depth
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{" or ch == "[":
            depth += 1
            if depth > limit:
                raise ValueError(
                    f"JSON nesting exceeds max depth of {max_depth}"
                )
        elif ch == "}" or ch == "]":
            if depth > 0:
                depth -= 1


def safe_json_loads(data: str | bytes, max_depth: int = 32) -> dict:
    """Parse JSON with a nesting depth limit.

    Prevents JSON bomb attacks where deeply nested structures
    consume excessive memory or CPU during parsing. The depth check is
    performed on the raw text BEFORE json.loads() so that a pathological
    input is rejected without building the full Python object tree.
    """
    if isinstance(data, (bytes, bytearray)):
        text = data.decode("utf-8", errors="strict")
    else:
        text = data
    _prescan_depth(text, max_depth)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e.msg}") from None
    # Defence-in-depth: also run the object-walking check. A corrupted
    # json module could theoretically produce deeper structures than the
    # text implied, so we keep this belt-and-braces pass.
    try:
        _check_depth(parsed, max_depth)
    except JSONDepthError as e:
        raise ValueError(str(e)) from None
    return parsed


# Maximum sane block height (~31,000 years at 10s blocks)
MAX_SANE_BLOCK_HEIGHT = 100_000_000  # ~31 years at 10s blocks, generous upper bound
