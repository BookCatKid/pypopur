"""Shared raw-value helpers used by the firmware-4 DP codecs."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Collection
from typing import Any

from .exceptions import ProtocolError


def decode_raw_bytes(value: Any, *, allow_base64: bool = False) -> bytes | None:
    """Decode the raw encodings accepted by the Popur app into bytes.

    The Android app accepts byte arrays, numeric collections, hexadecimal strings,
    and strings containing a JSON-style integer array. Thing mobile device records
    additionally return RAW datapoints as padded Base64 strings.
    """

    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list) and all(
                isinstance(item, int) and not isinstance(item, bool) for item in parsed
            ):
                return bytes(item & 0xFF for item in parsed)
        compact = "".join(text.split())
        if len(compact) % 2:
            return None
        try:
            return bytes.fromhex(compact)
        except ValueError:
            if not allow_base64:
                return None
            try:
                return base64.b64decode(compact, validate=True)
            except (binascii.Error, ValueError):
                return None
    if isinstance(value, Collection) and not isinstance(value, (str, bytes, bytearray)):
        numeric: list[int] = []
        for item in value:
            if isinstance(item, bool) or not isinstance(item, int):
                continue
            numeric.append(item)
        if numeric:
            return bytes(item & 0xFF for item in numeric)
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
