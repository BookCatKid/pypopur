"""Port of ``com.thingclips.sdk.mqtt.pbbppqb`` — the MQTT/LAN sign and CRC
helpers.

smali: smali_classes3/com/thingclips/sdk/mqtt/pbbppqb.smali

Five distinct functions share the obfuscated name ``bdpdqbp``:

1. ``bdpdqbp(JSONObject, key)`` → :func:`sign_json` — TreeMap-sorted
   ``k=v||`` over every non-null, non-"sign", non-empty entry, then the key
   appended directly. MD5, UPPERCASE.
2. ``bdpdqbp(Map, key)`` → :func:`sign_map` — same canonical shape but only
   whitelisted keys ``{pv, t, data, gwId, protocol}``; MD5 UPPERCASE.
3. ``bdpdqbp(PublishBean, key)`` → :func:`sign_publish_bean` — bean→map then
   :func:`sign_map`, lowercased.
4. ``bdpdqbp(String pv, String data, String key)`` → :func:`sign_data_pv` —
   ``md5("data="+data+"||pv="+pv+"||"+key).lower()[8:24]``.
5. ``bdpdqbp(II[B)`` → :func:`crc_s_o_data` and
   ``bdpdqbp(II[B,String)`` → :func:`crc_s_o_data_key` — big-endian CRC32
   frames.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from typing import Any

from ._fastjson import to_json_string
from .crypto import crc32, md5_upper
from .hexutil import int_to_bytes2

# pbbppqb.<clinit> — the sign whitelist (order in the list is irrelevant).
SIGN_KEYS = ("pv", "t", "data", "gwId", "protocol")


def _java_str(value: Any) -> str:
    """``Object.toString()`` for the boxed values found in these maps."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return to_json_string(value)
    if value is None:
        return "null"
    return str(value)


def sign_json(obj: Mapping[str, Any], key: str) -> str:
    """``bdpdqbp(JSONObject, String)`` — canonical ``k=v||`` over sorted
    non-null non-"sign" non-empty entries + key; MD5 uppercase."""

    pairs = sorted((k, _java_str(v)) for k, v in obj.items() if v is not None and k != "sign")
    canonical = "".join(f"{k}={v}||" for k, v in pairs if v != "") + key
    return md5_upper(canonical)


def sign_map(values: Mapping[str, str], key: str) -> str:
    """``bdpdqbp(Map, String)`` — whitelist-filtered canonical + ``||`` + key;
    MD5 uppercase."""

    canonical = "||".join(
        f"{k}={values[k]}"
        for k in sorted(values.keys())
        if k in SIGN_KEYS and values[k] is not None and values[k] != ""
    )
    return md5_upper(canonical + "||" + key)


def sign_publish_bean(
    data: str | None,
    gw_id: str | None,
    protocol: int,
    pv: str | None,
    t: int,
    key: str,
) -> str:
    """``bdpdqbp(PublishBean, String)`` — bean→map via ``String.valueOf`` then
    :func:`sign_map`, lowercased."""

    bean_map = {
        "data": data,
        "gwId": gw_id,
        "protocol": str(protocol),
        "pv": pv,
        "t": str(t),
    }
    return sign_map(bean_map, key).lower()


def sign_data_pv(pv: str, data: str, key: str) -> str | None:
    """``bdpdqbp(String, String, String)`` —
    ``md5("data="+data+"||pv="+pv+"||"+key).lower()[8:24]``; null MD5 → null."""

    digest = md5_upper(f"data={data}||pv={pv}||{key}")
    return digest.lower()[8:24]


def crc_s_o_data(s: int, o: int, data: bytes) -> bytes:
    """``bdpdqbp(II[B)`` — ``be32(crc32(be32(s) || be32(o) || data))``."""

    return int_to_bytes2(crc32(int_to_bytes2(s) + int_to_bytes2(o) + data))


def crc_s_o_data_key(s: int, o: int, data: bytes, key: str) -> bytes:
    """``bdpdqbp(II[B,String)`` —
    ``be32(crc32(be32(s) || be32(o) || be32(crc32(data)) || key.bytes))``."""

    inner = int_to_bytes2(crc32(data))
    return int_to_bytes2(crc32(int_to_bytes2(s) + int_to_bytes2(o) + inner + key.encode()))


def parse_frame_u32(payload: bytes, offset: int) -> int:
    """Big-endian u32 read used by the inbound frame parsers."""

    return struct.unpack(">I", payload[offset : offset + 4])[0]
