"""Port of ``com.thingclips.sdk.device.utils.DevUtil`` DP validation and RAW
conversion — opcode-faithful to DevUtil.smali lines 27-1744.

Java semantics reproduced:

- Public ``checkSendCommond``/``checkReceiveCommond`` wrap the whole loop in
  ``catch (Exception) → printStackTrace → return false`` — a ClassCastException
  or NPE anywhere fails the whole command, not just that DP.
- ``check-cast`` to ``String`` accepts null (Java null casts fine) and rejects
  any non-String; ``check-cast Integer`` rejects Java ``Long`` — values
  outside int32 box as ``Long`` — as well as ``Boolean``/``String``/null.
- A schema with ``type == null`` NPEs on ``getType().equals(...)`` → false.
- bool's ``"toggle"`` string short-circuits ``return true`` for the WHOLE map,
  skipping validation of the remaining entries.
- Send-side bitmap has a compiler quirk: ``if-gez`` jumps to acceptance, so
  any non-negative Integer passes and negatives pass whenever
  ``v < (1 << (maxlen & 31))`` — effectively every Integer is accepted for
  sane maxlen; receive-side is strict ``0 <= v < 1 << maxlen``.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, MutableMapping
from typing import Any

from ._fastjson import to_json_string
from ._java import (
    INT32_MIN,
    LONG_MAX,
    JavaCastError,
    is_java_integer,
    is_java_long,
    java_shl_int,
    java_string_length,
    text_is_empty,
)
from .crypto import base64_decode
from .hexutil import bytes_to_hex_string, check_hex_string, hex_string_to_bytes
from .schema import (
    DATA_TYPE_OBJ,
    DATA_TYPE_RAW,
    MODE_RO,
    SchemaBean,
    to_bitmap_schema,
    to_enum_schema,
    to_string_schema,
    to_value_schema,
)


def _cast_string(value: Any) -> str | None:
    """``check-cast Ljava/lang/String;`` — null casts fine, non-String throws."""

    if value is None or isinstance(value, str):
        return value
    raise JavaCastError(f"{type(value).__name__} cannot be cast to String")


def _cast_integer(value: Any) -> int:
    """``check-cast Ljava/lang/Integer;`` + ``intValue()``.

    Only int32-range Python ints model boxed ``Integer``; wider ints model
    ``Long`` and fail the cast, as do bool (``Boolean``), str, float, and null
    (``null.intValue()`` NPEs — same failure result).
    """

    if not is_java_integer(value):
        raise JavaCastError(f"{type(value).__name__} cannot be cast to Integer")
    return value


def _type_equals(schema: SchemaBean, expected: str) -> bool:
    """``schema.getType().equals(expected)`` — NPE on null type."""

    if schema.type is None:
        raise JavaCastError("SchemaBean.getType() is null")
    return schema.type == expected


def _check_send(schema_map: Mapping[str, SchemaBean] | None, dps: Mapping[str, Any]) -> bool:
    if schema_map is None:
        return False
    for key, value in dps.items():
        if value is None:
            continue
        schema = schema_map.get(key)
        if schema is None:
            continue
        if schema.mode == MODE_RO:
            return False
        if _type_equals(schema, DATA_TYPE_OBJ):
            schema_type = schema.schema_type
            if schema_type == "bool":
                if isinstance(value, str) and value == "toggle":
                    return True  # Java: unconditional return true, mid-loop
                if not isinstance(value, bool):
                    return False
            elif schema_type == "enum":
                value = _cast_string(value)
                bean = to_enum_schema(schema.property)
                if bean is None or bean.range is None or value not in bean.range:
                    return False
            elif schema_type == "string":
                value = _cast_string(value)
                bean = to_string_schema(schema.property)
                if java_string_length(value) > bean.maxlen:  # noqa: E1101 — null bean NPEs like Java
                    return False
            elif schema_type == "value":
                ivalue = _cast_integer(value)
                bean = to_value_schema(schema.property)
                if ivalue < bean.min or ivalue > bean.max:  # noqa: E1101
                    return False
            elif schema_type == "bitmap":
                ivalue = _cast_integer(value)
                bean = to_bitmap_schema(schema.property)
                if ivalue < 0 and ivalue >= java_shl_int(1, bean.maxlen):  # noqa: E1101
                    return False
            # unknown schemaType under "obj" is accepted (falls out of the branch)
        elif _type_equals(schema, DATA_TYPE_RAW):
            svalue = _cast_string(value)
            if not check_hex_string(svalue) or len(svalue) % 2 == 1:
                return False
        else:
            svalue = _cast_string(value)
            if text_is_empty(svalue):
                return False
    return True


def check_send_command(schema_map: Mapping[str, SchemaBean] | None, dps: Mapping[str, Any]) -> bool:
    """``DevUtil.checkSendCommond`` — null schemaMap → false; exceptions →
    false (the public wrapper's catch-all)."""

    try:
        return _check_send(schema_map, dps)
    except Exception:
        return False


def _check_receive(schema_map: Mapping[str, SchemaBean] | None, dps: Mapping[str, Any]) -> bool:
    for key, value in dps.items():
        schema = schema_map.get(key)
        if schema is None:
            continue
        if _type_equals(schema, DATA_TYPE_OBJ):
            schema_type = schema.schema_type
            if schema_type == "bool":
                if isinstance(value, str) and value == "toggle":
                    return True
                if not isinstance(value, bool):
                    return False
            elif schema_type == "enum":
                value = _cast_string(value)
                bean = to_enum_schema(schema.property)
                if bean is None or bean.range is None or value not in bean.range:
                    return False
            elif schema_type == "string":
                value = _cast_string(value)
                bean = to_string_schema(schema.property)
                if java_string_length(value) > bean.maxlen:  # noqa: E1101
                    return False
            elif schema_type == "value":
                if is_java_integer(value) or is_java_long(value):
                    lvalue = value
                else:
                    lvalue = LONG_MAX
                bean = to_value_schema(schema.property)
                if lvalue < bean.min or lvalue > bean.max:  # noqa: E1101
                    return False
            elif schema_type == "bitmap":
                ivalue = _cast_integer(value)
                bean = to_bitmap_schema(schema.property)
                if ivalue < 0 or ivalue >= java_shl_int(1, bean.maxlen):  # noqa: E1101
                    return False
        elif _type_equals(schema, DATA_TYPE_RAW):
            svalue = _cast_string(value)
            if not check_hex_string(svalue) or len(svalue) % 2 == 1:
                return False
        else:
            svalue = _cast_string(value)
            if text_is_empty(svalue):
                return False
    return True


def check_receive_command(
    schema_map: Mapping[str, SchemaBean] | None, dps: Mapping[str, Any]
) -> bool:
    """``DevUtil.checkReceiveCommond`` — null schemaMap → **true**; exceptions
    → false."""

    if schema_map is None:
        return True
    try:
        return _check_receive(schema_map, dps)
    except Exception:
        return False


def decode_raw(
    dps: MutableMapping[str, Any] | None,
    schema_map: Mapping[str, SchemaBean] | None,
) -> bool:
    """``DevUtil.decodeRaw(Map, Map)``: base64→lowercase-hex for every DP whose
    schema ``type == "raw"``, mutating the map in place.

    Returns true if at least one raw DP was *encountered* (set even when the
    conversion throws). A decode that yields empty hex from a non-empty source
    keeps the original value.
    """

    if dps is None or schema_map is None:
        return False
    converted = False
    for key, value in dps.items():
        schema = schema_map.get(key)
        if schema is None:
            continue
        if not _type_equals(schema, DATA_TYPE_RAW):
            continue
        try:
            svalue = _cast_string(value)
            decoded = base64_decode(svalue.encode())
            hex_value = bytes_to_hex_string(decoded)
            if not text_is_empty(svalue) and text_is_empty(hex_value):
                pass  # keep original — "decodeRaw dpValue is empty."
            else:
                dps[key] = hex_value
        except Exception:
            pass
        converted = True
    return converted


def encode_raw(
    schema_map: Mapping[str, SchemaBean] | None,
    dps: MutableMapping[str, Any] | None,
) -> str:
    """``DevUtil.encodeRaw(Map, Map)``: hex→bytes→base64 in place for raw DPs,
    then fastjson-serializes the map."""

    if schema_map is not None and dps is not None:
        for key, value in dps.items():
            schema = schema_map.get(key)
            if schema is None or not _type_equals(schema, DATA_TYPE_RAW):
                continue
            try:
                svalue = _cast_string(value)
                # hexStringToBytes(None/"") → None → encodeBase64 NPE in Java;
                # b64encode(None) raises TypeError here — same catch path.
                dps[key] = base64.b64encode(hex_string_to_bytes(svalue)).decode()
            except Exception:
                pass
    return to_json_string(dps)


def encode_raw_with_fallback(
    schema_map: Mapping[str, SchemaBean] | None,
    original: str,
    dps: MutableMapping[str, Any] | None,
) -> str:
    """``DevUtil.encodeRaw(Map, String, Map)``: same in-place conversion, but
    returns ``original`` unchanged when no raw DP was encountered. Null
    schema_map → ``original``."""

    if schema_map is None:
        return original
    converted = False
    if dps is not None:
        for key, value in dps.items():
            schema = schema_map.get(key)
            if schema is None or not _type_equals(schema, DATA_TYPE_RAW):
                continue
            try:
                svalue = _cast_string(value)
                dps[key] = base64.b64encode(hex_string_to_bytes(svalue)).decode()
            except Exception:
                pass
            converted = True
    if converted:
        return to_json_string(dps)
    return original


__all__ = [
    "INT32_MIN",
    "check_receive_command",
    "check_send_command",
    "decode_raw",
    "encode_raw",
    "encode_raw_with_fallback",
]
