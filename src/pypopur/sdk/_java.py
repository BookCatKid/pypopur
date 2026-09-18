"""Java semantics helpers used by the ThingClips SDK port.

These helpers reproduce the JVM behaviors the smali relies on: 32-bit int
arithmetic, ``Number.intValue()`` narrowing, UTF-16 string length, and the
checked-cast failure mode (ClassCastException) that callers in the SDK catch
as a generic validation failure.
"""

from __future__ import annotations

import math
from typing import Any

INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
LONG_MAX = (1 << 63) - 1


class JavaCastError(TypeError):
    """Raised where smali ``check-cast`` would throw ClassCastException."""


def to_int32(value: int) -> int:
    """Wrap an int to Java ``int`` range (two's complement, 32-bit)."""

    value &= 0xFFFFFFFF
    return value - (1 << 32) if value > INT32_MAX else value


def java_shl_int(value: int, shift: int) -> int:
    """Java ``shl-int``: shift count masked to 5 bits, result truncated to int."""

    return to_int32(value << (shift & 0x1F))


def java_number_int_value(value: Any) -> int:
    """Reproduce ``Number.intValue()`` for a boxed value.

    - bool is not a Java ``Number`` → :class:`JavaCastError`.
    - int is narrowed to int32 (Java int→byte/int casts truncate).
    - float follows Java ``(int) double`` semantics: NaN → 0, values beyond
      int32 saturate, otherwise truncate toward zero.
    - anything else → :class:`JavaCastError`.
    """

    if isinstance(value, bool):
        raise JavaCastError("Boolean is not a Number")
    if isinstance(value, int):
        return to_int32(value)
    if isinstance(value, float):
        if math.isnan(value):
            return 0
        if value >= INT32_MAX:
            return INT32_MAX
        if value <= INT32_MIN:
            return INT32_MIN
        return int(value)
    raise JavaCastError(f"{type(value).__name__} is not a Number")


def is_java_integer(value: Any) -> bool:
    """True when fastjson/boxing would have produced a Java ``Integer``.

    JSON numbers inside int32 become ``Integer``; larger integral values
    become ``Long``. Python ``bool`` maps to Java ``Boolean`` (not Integer).
    """

    return (
        isinstance(value, int) and not isinstance(value, bool) and INT32_MIN <= value <= INT32_MAX
    )


def is_java_long(value: Any) -> bool:
    """True when a JSON/boxed integral value would be a Java ``Long``."""

    return isinstance(value, int) and not isinstance(value, bool) and not is_java_integer(value)


def java_string_length(value: str) -> int:
    """``String.length()`` — UTF-16 code units, not code points."""

    return len(value.encode("utf-16-be")) // 2


def text_is_empty(value: Any) -> bool:
    """``TextUtils.isEmpty``: null or zero length."""

    return value is None or len(value) == 0


def to_java_byte(value: int) -> int:
    """Java ``(byte) int`` cast — low 8 bits, sign-extended to Python int."""

    value &= 0xFF
    return value - 0x100 if value > 0x7F else value


def java_substring(value: str, begin: int, end: int) -> str:
    """``String.substring(begin, end)`` — throws
    ``StringIndexOutOfBoundsException`` when begin < 0, end > len, or
    begin > end. Python slices silently clamp; this raises ``IndexError``."""

    if begin < 0 or end > len(value) or begin > end:
        raise IndexError(
            f"String index out of range: begin {begin}, end {end}, length {len(value)}"
        )
    return value[begin:end]
