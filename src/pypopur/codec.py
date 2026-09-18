"""Shared raw-value helpers used by the firmware-4 DP codecs."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from .exceptions import ProtocolError


def decode_raw_bytes(value: Any, *, allow_base64: bool = False) -> bytes | None:
    """Decode the raw encodings accepted by the Popur app into bytes.

    Delegates to ``Dp102SystemSettings.decodeToBytes`` semantics
    (``app.dp101.decode_to_bytes``): byte arrays, ``[int, int, ...]`` strings
    (comma-split, non-integer tokens skipped), hex strings, and Collections
    of Numbers via ``intValue()``.  ``allow_base64`` is a pypopur extension:
    the app does base64→hex at the transport boundary (``DevUtil.decodeRaw``),
    never inside the DP codec; keep it for mobile records.
    """

    from .app.dp101 import decode_to_bytes

    decoded = decode_to_bytes(value)
    if decoded is not None or not (allow_base64 and isinstance(value, str)):
        return decoded
    compact = "".join(value.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None


def require_raw_bytes(value: Any, *, dp: int | None = None) -> bytes:
    """Decode *value* or raise a useful protocol exception."""

    decoded = decode_raw_bytes(value)
    if decoded is None:
        suffix = f" for DP{dp}" if dp is not None else ""
        raise ProtocolError(f"Invalid raw byte payload{suffix}")
    return decoded


def normalize_bytes(value: Any, length: int, default: bytes | None = None) -> bytes:
    """Pad/truncate an app-compatible raw payload to a fixed wire length."""

    decoded = decode_raw_bytes(value)
    if decoded is None or not decoded:
        base = default or bytes(length)
        return bytes(base[:length]).ljust(length, b"\x00")
    return decoded[:length].ljust(length, b"\x00")


def encode_hex(value: bytes) -> str:
    """Return the lowercase compact hexadecimal representation used by the app."""

    return value.hex()


def clamp(value: int, minimum: int, maximum: int) -> int:
    """Clamp an integer to an inclusive range."""

    return max(minimum, min(maximum, value))


def parse_bool(value: Any) -> bool:
    """Mirror the app's permissive scalar boolean parser."""

    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
        try:
            return int(text) != 0
        except ValueError:
            return False
    return False
