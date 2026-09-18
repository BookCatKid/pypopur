"""fastjson ``JSON.toJSONString`` compatibility serializer.

The SDK serializes DP maps and publish beans with
``com.alibaba.fastjson.JSON`` — often with ``SerializerFeature.WriteMapNullValue``.
Relevant default behavior reproduced here:

- insertion-ordered object keys (``LinkedHashMap``/bean field order)
- compact separators ``{"k":v}`` with no whitespace
- null map values are emitted as ``"k":null`` even without
  ``WriteMapNullValue`` (the feature matters for bean *fields*; maps always
  include nulls)
- ``byte[]`` values serialize as base64 strings
- non-ASCII characters are written raw (``BrowserCompatible`` is off)
- control characters use fastjson's uppercase ``\\uXXXX`` escapes
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

_U_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        # fastjson writes byte[] as a base64 JSON string.
        return base64.b64encode(bytes(value)).decode("ascii")
    if hasattr(value, "to_fastjson"):
        return value.to_fastjson()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def to_json_string(value: Any, write_nulls: bool = False) -> str:
    """``JSON.toJSONString(Object[, WriteMapNullValue])``.

    ``write_nulls`` mirrors ``SerializerFeature.WriteMapNullValue`` —
    it only affects *bean field* serialization (``to_fastjson``
    implementations consult it); map values are always emitted."""

    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=_default)
    # Python emits lowercase hex in \uXXXX; fastjson uses uppercase.
    return _U_ESCAPE.sub(lambda m: "\\u" + m.group(1).upper(), text)


def to_json_bytes(value: Any) -> bytes:
    """``JSON.toJSONBytes(Object)`` — UTF-8 of :func:`to_json_string`."""

    return to_json_string(value).encode("utf-8")


def parse_object(text: str | bytes) -> Any:
    """``JSON.parseObject`` — dict/list/scalar tree. Python dict preserves
    fastjson's insertion order."""

    return json.loads(text)
