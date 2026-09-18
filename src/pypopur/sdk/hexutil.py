"""Port of ``com.thingclips.smart.android.common.utils.HexUtil`` and the
``ByteUtils`` helpers used by the SDK framing code.

smali: smali_classes3/com/thingclips/smart/android/common/utils/HexUtil.smali
       smali_classes3/com/thingclips/smart/android/common/utils/ByteUtils.smali

Two different hex encoders exist in the app and the distinction matters:
``HexUtil.bytesToHexString`` produces lowercase hex, while
``AESUtil.byte2hex`` produces uppercase.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

_HEX_CHARS = "0123456789ABCDEF"


def bytes_to_hex_string(data: bytes | None) -> str | None:
    """``HexUtil.bytesToHexString``: lowercase, zero-padded; null/empty → None."""

    if data is None or len(data) == 0:
        return None
    return data.hex()


def check_hex_char(char: str) -> bool:
    """``HexUtil.checkHexChar``: 0-9, A-F, a-f."""

    return char in _HEX_CHARS or char in "abcdef"


def check_hex_string(value: str | None) -> bool:
    """``HexUtil.checkHexString``: non-empty and all-hex (either case)."""

    if value is None or len(value) == 0:
        return False
    return all(check_hex_char(char) for char in value)


def _char_to_byte(char: str) -> int:
    """``HexUtil.charToByte``: uppercase-only ``indexOf``, -1 on miss."""

    return _HEX_CHARS.find(char)


def hex_string_to_bytes(value: str | None) -> bytes | None:
    """``HexUtil.hexStringToBytes``.

    Uppercases the input, emits ``len//2`` bytes (odd trailing char dropped),
    and — critically — does NOT validate: characters outside ``0-9A-F`` map
    through ``indexOf == -1`` into garbage nibbles (``0xFF``) rather than
    raising. Callers validate separately via :func:`check_hex_string`.
    """

    if value is None or value == "":
        return None
    upper = value.upper()
    out = bytearray(len(upper) // 2)
    for index in range(len(out)):
        hi = _char_to_byte(upper[index * 2])
        lo = _char_to_byte(upper[index * 2 + 1])
        out[index] = ((hi << 4) | lo) & 0xFF
    return bytes(out)


def encode(value: str) -> str:
    """``HexUtil.encode``: uppercase hex of the platform-default-charset bytes."""

    return value.encode().hex().upper()


def decode(value: str) -> str:
    """``HexUtil.decode``: hex pairs → string via UPPERCASE-only lookup.

    The input is not uppercased — lowercase hex chars indexOf to -1 and
    produce garbage, and an odd-length input reads past the end (Java
    StringIndexOutOfBoundsException → Python IndexError).
    """

    out = bytearray()
    for index in range(0, len(value), 2):
        hi = _HEX_CHARS.find(value[index])
        lo = _HEX_CHARS.find(value[index + 1])
        out.append(((hi << 4) | lo) & 0xFF)
    return out.decode()


def string_to_hex_string(value: str) -> str:
    """``HexUtil.stringToHexString``: per-char ``Integer.toHexString`` — NOT
    zero-padded, so the output can be odd-length."""

    return "".join(format(ord(char), "x") for char in value)


def hex_string2_bytes(value: str) -> bytes:
    """``HexUtil.HexString2Bytes``: fixed 6 bytes via Byte.decode nibble pairs."""

    raw = value.encode()
    return bytes(_unite_bytes(raw[index * 2], raw[index * 2 + 1]) for index in range(6))


def _unite_bytes(hi_ascii: int, lo_ascii: int) -> int:
    """``HexUtil.uniteBytes``: each byte is an ASCII nibble decoded via
    ``Byte.decode("0x" + chr)`` — ValueError propagates on non-hex input."""

    hi = int("0x" + chr(hi_ascii), 16) & 0xFF
    lo = int("0x" + chr(lo_ascii), 16) & 0xFF
    return ((hi << 4) | lo) & 0xFF


# --- ByteUtils (smali_classes3/.../common/utils/ByteUtils.smali) ---


def int_to_bytes2(value: int) -> bytes:
    """``ByteUtils.intToBytes2``: 4-byte BIG-endian despite the name."""

    return struct.pack(">I", value & 0xFFFFFFFF)


def bytes_to_int2(data: bytes, offset: int = 0) -> int:
    """``ByteUtils.bytesToInt2(byte[], int)``: 4-byte big-endian read at
    ``offset``; the Java result is a signed ``int``."""

    return int.from_bytes(data[offset : offset + 4], "big", signed=True)


def contact(*parts: bytes) -> bytes:
    """``ByteUtils.contact``: byte-array concatenation."""

    return b"".join(parts)


def byte_list_to_bytes(values: Iterable[int]) -> bytes:
    """Java ``byte[]`` from an int collection — each value truncated to a byte."""

    return bytes(value & 0xFF for value in values)
