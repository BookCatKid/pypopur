"""Port of ``DeviceDpStringParser`` and ``UnifiedDeviceControlManager.d``.

``parse_dp_string`` accepts a lenient org.json object first, then a legacy
comma-separated ``key:value`` form.  ``serialize_dps`` is the app's hand-rolled
JSON writer — note it does not escape embedded quotes.
"""

from __future__ import annotations

import base64
from numbers import Number
from typing import Any


class JsonNull:
    """``org.json.JSONObject.NULL`` — a JSON null is this sentinel, not ``None``."""

    _instance: JsonNull | None = None

    def __new__(cls) -> JsonNull:  # noqa: PYI034 - singleton mirrors JSONObject.NULL
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "null"

    def __eq__(self, other: object) -> bool:
        return other is None or isinstance(other, JsonNull)

    def __hash__(self) -> int:
        return hash(None)


JSON_NULL = JsonNull()

_LITERAL_EXCLUDED = set("{}[]/\\:,=;# \t\f")


def _next_clean(text: str, pos: int) -> tuple[str, int]:
    """``JSONTokener.nextCleanInternal`` — returns ``(char, pos-at-char)``."""

    n = len(text)
    while pos < n:
        c = text[pos]
        pos += 1
        if c in "\t \n\r":
            continue
        if c == "/":
            if pos == n:
                return c, pos - 1
            peek = text[pos]
            if peek == "*":
                pos += 1
                end = text.find("*/", pos)
                if end == -1:
                    raise ValueError("Unterminated comment")
                pos = end + 2
                continue
            if peek == "/":
                pos += 1
                pos = _skip_to_end_of_line(text, pos)
                continue
            return c, pos - 1
        if c == "#":
            pos = _skip_to_end_of_line(text, pos)
            continue
        return c, pos - 1
    return "", pos


def _skip_to_end_of_line(text: str, pos: int) -> int:
    while pos < len(text):
        c = text[pos]
        pos += 1
        if c in "\r\n":
            break
    return pos


def _read_escape(text: str, pos: int) -> tuple[str, int]:
    """``JSONTokener.readEscapeCharacter`` — the backslash was already read."""

    if pos >= len(text):
        raise ValueError("Unterminated escape sequence")
    e = text[pos]
    pos += 1
    if e == "u":
        if pos + 4 > len(text):
            raise ValueError("Unterminated escape sequence")
        hex4 = text[pos : pos + 4]
        pos += 4
        try:
            return chr(int(hex4, 16)), pos
        except ValueError:
            raise ValueError("Invalid escape sequence: " + hex4) from None
    if e == "t":
        return "\t", pos
    if e == "b":
        return "\b", pos
    if e == "n":
        return "\n", pos
    if e == "r":
        return "\r", pos
    if e == "f":
        return "\f", pos
    return e, pos


def _next_string(text: str, pos: int, quote: str) -> tuple[str, int]:
    """``JSONTokener.nextString`` — ``pos`` sits on the opening quote."""

    out: list[str] = []
    pos += 1
    while pos < len(text):
        c = text[pos]
        pos += 1
        if c == quote:
            return "".join(out), pos
        if c == "\\":
            e, pos = _read_escape(text, pos)
            out.append(e)
        else:
            out.append(c)
    raise ValueError("Unterminated string")


def _java_parse_long(number: str, base: int) -> int | None:
    """``Long.parseLong(number, base)`` — ``None`` on NumberFormatException."""

    body = number
    neg = False
    if body.startswith(("+", "-")):
        neg = body[0] == "-"
        body = body[1:]
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"[:base]
    if not body or any(ch.lower() not in digits for ch in body):
        return None
    value = int(body, base)
    if neg:
        value = -value
    if value < -(2**63) or value > 2**63 - 1:
        return None
    return value


def _java_double(token: str) -> float | None:
    """``Double.valueOf`` — decimal, d/f suffixes, hex floats, NaN/Infinity."""

    candidate = token
    if len(candidate) > 1 and candidate[-1] in "dDfF":
        candidate = candidate[:-1]
    try:
        return float(candidate)
    except ValueError:
        pass
    if "x" in candidate.lower() and "p" in candidate.lower():
        try:
            return float.fromhex(candidate)
        except ValueError:
            pass
    return None


def _read_literal(text: str, pos: int) -> tuple[Any, int]:
    """``JSONTokener.readLiteral`` — null/boolean/number or unquoted string."""

    start = pos
    n = len(text)
    while pos < n and text[pos] not in _LITERAL_EXCLUDED and text[pos] not in "\r\n":
        pos += 1
    literal = text[start:pos]
    if not literal:
        raise ValueError("Expected literal value")
    lowered = literal.lower()
    if lowered == "null":
        return JSON_NULL, pos
    if lowered == "true":
        return True, pos
    if lowered == "false":
        return False, pos
    if "." not in literal:
        base = 10
        number = literal
        if number.startswith(("0x", "0X")):
            number = number[2:]
            base = 16
        elif len(number) > 1 and number.startswith("0"):
            number = number[1:]
            base = 8
        long_value = _java_parse_long(number, base)
        if long_value is not None:
            return long_value, pos
    double_value = _java_double(literal)
    if double_value is not None:
        return double_value, pos
    return literal, pos


def _next_value(text: str, pos: int) -> tuple[Any, int]:
    """``JSONTokener.nextValue``."""

    c, pos = _next_clean(text, pos)
    if c == "":
        raise ValueError("End of input")
    if c == "{":
        return _read_object(text, pos + 1)
    if c == "[":
        return _read_array(text, pos + 1)
    if c in "\"'":
        return _next_string(text, pos, c)
    return _read_literal(text, pos)


def _read_object(text: str, pos: int) -> tuple[dict[str, Any], int]:
    """``JSONTokener.readObject`` — ``pos`` is just past the '{'"."""

    out: dict[str, Any] = {}
    c, pos = _next_clean(text, pos)
    if c == "}":
        return out, pos + 1
    while True:
        name, pos = _next_value(text, pos)
        if not isinstance(name, str):
            raise ValueError("Names must be strings")  # noqa: TRY004 - fastjson JSONException maps to ValueError
        sep, pos = _next_clean(text, pos)
        if sep not in ":=":
            raise ValueError("Expected ':' after " + str(name))
        pos += 1
        if pos < len(text) and text[pos] == ">":
            pos += 1
        value, pos = _next_value(text, pos)
        out[name] = value
        c, pos = _next_clean(text, pos)
        if c == "}":
            return out, pos + 1
        if c in ";,":
            pos += 1
            continue
        raise ValueError("Unterminated object")


def _read_array(text: str, pos: int) -> tuple[list[Any], int]:
    """``JSONTokener.readArray`` — ``pos`` is just past the '['".

    ``[,]`` yields ``[null, null]``; separators without values are null.
    """

    out: list[Any] = []
    has_trailing_separator = False
    while True:
        c, pos = _next_clean(text, pos)
        if c == "":
            raise ValueError("Unterminated array")
        if c == "]":
            if has_trailing_separator:
                out.append(JSON_NULL)
            return out, pos + 1
        if c in ",;":
            out.append(JSON_NULL)
            has_trailing_separator = True
            pos += 1
            continue
        value, pos = _next_value(text, pos)
        out.append(value)
        c, pos = _next_clean(text, pos)
        if c == "]":
            return out, pos + 1
        if c in ",;":
            has_trailing_separator = True
            pos += 1
            continue
        raise ValueError("Unterminated array")


def parse_org_json_object(dp_str: str) -> dict[str, Any]:
    """``new JSONObject(String)`` — raises on malformed or non-object input."""

    dp_str = dp_str.removeprefix("\ufeff")
    value, _ = _next_value(dp_str, 0)
    if not isinstance(value, dict):
        raise ValueError("JSONObject expected")  # noqa: TRY004 - fastjson JSONException maps to ValueError
    return value


def _unquote(text: str) -> str:
    """Kotlin ``removeSurrounding("\"")`` — strips one pair of outer quotes."""

    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


def parse_dp_string(dp_str: str) -> dict[str, Any]:
    """``DeviceDpStringParser.a`` — malformed input returns an empty map."""

    if not dp_str or not dp_str.strip():
        return {}
    try:
        result: dict[str, Any] = parse_org_json_object(dp_str)
    except Exception:
        result = {}
    if result:
        return result
    try:
        out: dict[str, Any] = {}
        body = dp_str.strip()
        body = body.removeprefix("{")
        body = body.removesuffix("}")
        if not body:
            return {}
        for part in body.split(","):
            components = part.split(":")
            if len(components) != 2:
                continue
            key = _unquote(components[0].strip())
            raw = components[1].strip()
            if raw == "true":
                value: Any = True
            elif raw == "false":
                value = False
            elif raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
                value = _unquote(raw)
            else:
                try:
                    value = int(raw)
                except ValueError:
                    try:
                        value = float(raw)
                    except ValueError:
                        value = raw
            out[key] = value
        return out
    except Exception:
        return {}


def serialize_dps(dps: dict[str, Any]) -> str:
    """``UnifiedDeviceControlManager.d`` — insertion-ordered manual serializer.

    Strings and unknown objects are quoted verbatim (no escaping); ``bytes`` are
    emitted as no-wrap base64.  Any failure yields ``"{}"``.
    """

    try:
        out = ["{"]
        first = True
        for key, value in dps.items():
            if not first:
                out.append(",")
            first = False
            out.append('"')
            out.append(str(key))
            out.append('":')
            if isinstance(value, str):
                out.append('"')
                out.append(value)
                out.append('"')
            elif isinstance(value, bool):
                out.append("true" if value else "false")
            elif isinstance(value, Number):
                out.append(str(value))
            elif isinstance(value, (bytes, bytearray, memoryview)):
                out.append('"')
                out.append(base64.b64encode(bytes(value)).decode())
                out.append('"')
            else:
                out.append('"')
                out.append(str(value))
                out.append('"')
        out.append("}")
        return "".join(out)
    except Exception:
        return "{}"


def dp_string_arg(args: list[Any] | tuple[Any, ...] | None) -> str | None:
    """``UnifiedDeviceControlManager.c`` — args[0] as a non-blank string."""

    if not args:
        return None
    first = args[0] if len(args) > 0 else None
    if first is None:
        return None
    text = str(first)
    return text if text.strip() else None


def dp_flag_arg(args: list[Any] | tuple[Any, ...] | None) -> bool:
    """``UnifiedDeviceControlManager.b`` — args[1] truthiness, app-style."""

    if not args or len(args) < 2:
        return False
    value = args[1]
    if isinstance(value, bool):
        return value
    if isinstance(value, Number):
        return int(value) != 0
    if isinstance(value, str):
        return value.lower() == "true" or value == "1"
    return False
