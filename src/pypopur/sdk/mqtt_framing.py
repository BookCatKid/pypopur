"""MQTT message framing — outbound publish payloads and inbound decoders.

smali:
- outbound: ``qpqddqd`` (bean builders/encryptors) + per-pv handlers
  ``dqdpbbd`` (1.1), ``qqdbbpp`` (2.0), ``bpqqdpq`` (2.1), ``qpbpqpq`` (2.2),
  ``dbbpbbb`` (2.3), dispatched by pv in ``ppdpppq``
- inbound: ``qqqpdpb`` (1.1), ``pdbbqdp`` (2.1), ``qbpppdb`` (2.2),
  ``dbpdpbp`` (2.3)

Bean field order is fastjson declaration order:
- ``PublishBean``   → ``{data, gwId, protocol, pv, sign, t}``
- ``PublishBean2_1`` → ``{data, protocol, s, t}``
- ``PublishBean2_2`` / ``2_3`` → ``{data, protocol, t}``
"""

from __future__ import annotations

from typing import Any

from ._fastjson import parse_object, to_json_bytes, to_json_string
from ._java import text_is_empty
from .crypto import AESUtil, crc32, gcm_decrypt_appended_nonce, gcm_encrypt_appended_nonce
from .hexutil import int_to_bytes2
from .mqtt_sign import (
    crc_s_o_data,
    crc_s_o_data_key,
    sign_data_pv,
    sign_json,
    sign_publish_bean,
)

PROTOCOL_DP_COMMAND = 5
SMART_MB_IN_PREFIX = "smart/mb/in/"


class MqttFrameError(Exception):
    """The inbound decoders' ``onError(code, msg)`` and the outbound builders'
    error callbacks, as an exception. ``code``/``message`` match the smali
    strings exactly."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# Outbound payloads (published to "smart/mb/out/<devId>")
# --------------------------------------------------------------------------


def build_payload_1_1(local_key: str, data: Any, protocol: int, t: int, s: int, o: int) -> bytes:
    """``dqdpbbd`` — ``PublishBean2_2`` JSON plaintext + keyed CRC:

    ``pv || be32(crc32(be32(s)||be32(o)||be32(crc32(data))||key)) || be32(s)
    || be32(o) || data``
    """

    # JSON.toJSONBytes without WriteMapNullValue — null bean fields omitted.
    bean = {k: v for k, v in {"data": data, "protocol": protocol, "t": t}.items() if v is not None}
    data_bytes = to_json_bytes(bean)
    crc = crc_s_o_data_key(s, o, data_bytes, local_key)
    return b"1.1" + crc + int_to_bytes2(s) + int_to_bytes2(o) + data_bytes


def build_payload_2_0(
    local_key: str, pv: str, data: Any, gw_id: str, protocol: int, t: int
) -> bytes:
    """``qqdbbpp`` (mqtt) — ``PublishBean`` JSON envelope: ``data`` hex-AES
    encrypted in place, ``sign`` over the encrypted bean, serialized in
    declaration order."""

    data_text = to_json_string(data)
    enc_hex = AESUtil(local_key.encode()).encrypt(data_text)
    bean = {
        "data": enc_hex,
        "gwId": gw_id,
        "protocol": protocol,
        "pv": pv,
        "sign": None,
        "t": t,
    }
    bean["sign"] = sign_publish_bean(enc_hex, gw_id, protocol, pv, t, local_key).lower()
    return to_json_bytes(bean)


def build_payload_2_1(local_key: str, pv: str, data: Any, protocol: int, t: int, sn: int) -> bytes:
    """``bpqqdpq`` — ``PublishBean2_1`` JSON → AES base64; sign over
    ``data=..||pv=..||key`` → ``(pv + sign + enc).bytes``."""

    enc = AESUtil(local_key.encode()).encrypt_with_base64(
        to_json_string({"data": data, "protocol": protocol, "s": sn, "t": t})
    )
    if text_is_empty(enc):
        raise MqttFrameError("11003", "aesBytes==null")
    sign = sign_data_pv(pv, enc, local_key)
    if text_is_empty(sign):
        raise MqttFrameError("11004", "sign==null")
    return (pv + sign + enc).encode()


def build_payload_2_2(
    local_key: str, pv: str, data: Any, protocol: int, t: int, s: int, o: int
) -> bytes:
    """``qpbpqpq`` — ``PublishBean2_2`` JSON → AES raw bytes; CRC32 over
    ``be32(s)||be32(o)||ct``; ``pv || crc || be32(s) || be32(o) || ct``."""

    aes_bytes = AESUtil(local_key.encode()).encrypt_with_bytes(
        to_json_string({"data": data, "protocol": protocol, "t": t})
    )
    if aes_bytes is None:
        raise MqttFrameError("11003", "aesBytes==null")
    return (
        pv.encode()
        + crc_s_o_data(s, o, aes_bytes)
        + int_to_bytes2(s)
        + int_to_bytes2(o)
        + aes_bytes
    )


def build_payload_2_3(
    local_key: str, pv: str, data: Any, protocol: int, t: int, s: int, o: int
) -> bytes:
    """``dbbpbbb`` — GCM with the 12-byte head as AAD:

    ``head = pv || be32(s) || be32(o) || 0x00``;
    ``payload = head || nonce(12) || AES/GCM ct+tag``."""

    head = pv.encode() + int_to_bytes2(s) + int_to_bytes2(o) + bytes(1)
    enc = gcm_encrypt_appended_nonce(
        local_key.encode(),
        to_json_bytes({"data": data, "protocol": protocol, "t": t}),
        head,
    )
    if enc is None:
        raise MqttFrameError("11003", "aesBytes==null")
    return head + enc


def build_mqtt_publish(
    pv: str,
    local_key: str,
    data: Any,
    gw_id: str,
    protocol: int,
    t: int,
    s: int,
    o: int,
) -> bytes:
    """pv dispatch from ``ppdpppq``: ≥2.3 → 2.3, ≥2.2 → 2.2, ≥2.1 → 2.1,
    ≥2.0 → 2.0, ≥1.1 → 1.1. ``pv`` here is the device's protocol version
    string (e.g. ``"2.2"``)."""

    def _at_least(minimum: float) -> bool:
        try:
            return float(pv) >= minimum
        except (TypeError, ValueError):
            return False

    if _at_least(2.3):
        return build_payload_2_3(local_key, pv, data, protocol, t, s, o)
    if _at_least(2.2):
        return build_payload_2_2(local_key, pv, data, protocol, t, s, o)
    if _at_least(2.1):
        return build_payload_2_1(local_key, pv, data, protocol, t, s)
    if _at_least(2.0):
        return build_payload_2_0(local_key, pv, data, gw_id, protocol, t)
    return build_payload_1_1(local_key, data, protocol, t, s, o)


# --------------------------------------------------------------------------
# Inbound payload decoders (from "smart/mb/in/<devId>")
#
# Each returns (protocol:int, json:dict). Failures raise MqttFrameError with
# the smali's exact code/message. ``dedup`` is a callable
# ``(topic_id, s, o) -> bool`` standing in for the listener's
# ``isDataUpdated``; a true result is the Java "drop" branch (error 12003).
# --------------------------------------------------------------------------


def _be32(payload: bytes, offset: int) -> int:
    """``ByteUtils.bytesToInt2`` — big-endian, Java-signed int."""

    return int.from_bytes(payload[offset : offset + 4], "big", signed=True)


def _protocol_or_raise(obj: dict, missing_msg: str) -> int:
    protocol = obj.get("protocol")
    if protocol is None:
        raise MqttFrameError("12004", missing_msg)
    return int(protocol)


def parse_inbound_2_3(
    local_key: str, payload: bytes, topic_id: str, dedup=None
) -> tuple[int, dict]:
    """``dbpdpbp`` — ``pv(3) || s(4) || o(4) || b(1) || gcm(nonce||ct+tag)``;
    head [0:12] is the GCM AAD."""

    s, o = _be32(payload, 3), _be32(payload, 7)
    if dedup is not None and dedup(topic_id, s, o):
        raise MqttFrameError("12003", f"cloud command repeat with s:{s} o:{o}")
    try:
        plain = gcm_decrypt_appended_nonce(local_key.encode(), payload[12:], payload[:12])
        text = plain.decode("utf-8", errors="replace")
    except Exception:
        text = None
    if text_is_empty(text):
        raise MqttFrameError("12001", "mqtt2_3: data parsing failure")
    obj = parse_object(text)
    return _protocol_or_raise(obj, "protocol is not exist"), obj


def parse_inbound_2_2(
    local_key: str, payload: bytes, topic_id: str, dedup=None
) -> tuple[int, dict]:
    """``qbpppdb`` — ``pv(3) || crc(4) || s(4) || o(4) || ct`` where
    ``crc == crc32(payload[7:])``."""

    s, o = _be32(payload, 7), _be32(payload, 11)
    if dedup is not None and dedup(topic_id, s, o):
        raise MqttFrameError("12003", f"cloud command repeat with s:{s} o:{o}")
    body = payload[7:]
    if crc32(body) != _be32(payload, 3):
        raise MqttFrameError(
            "12002",
            f"mqtt2_2: signature is not match signStrBt{crc32(body)}signBt:{_be32(payload, 3)}",
        )
    try:
        text = AESUtil(local_key.encode()).decrypt_bytes(payload[15:])
    except Exception:
        text = None
    if text_is_empty(text):
        raise MqttFrameError("12001", "mqtt2_2: data parsing failure")
    obj = parse_object(text)
    return _protocol_or_raise(obj, "protocol is not exist"), obj


def parse_inbound_2_1(local_key: str, payload: bytes, topic_id: str) -> tuple[int, dict]:
    """``pdbbqdp`` — payload text ``pv(3) || sign(16) || b64``; sign verified
    before decrypt. No dedup in this variant."""

    text = payload.decode()
    pv, rest = text[:3], text[3:]
    sign, enc = rest[:16], rest[16:]
    if sign_data_pv(pv, enc, local_key) != sign:
        raise MqttFrameError("12002", "signature is not match 2_1")
    try:
        plain = AESUtil(local_key.encode()).decrypt_with_base64(enc)
    except Exception:
        plain = None
    if text_is_empty(plain):
        raise MqttFrameError("12001", "dealWithDeviceTopic2_1 data parsing failure")
    obj = parse_object(plain)
    return _protocol_or_raise(obj, "protocol is not exist"), obj


def parse_inbound_1_1(
    local_key: str, payload: bytes, topic_id: str, dedup=None
) -> tuple[int, dict]:
    """``qqqpdpb`` — ``pv(3) || crc(4) || s(4) || o(4) || data`` where
    ``crc == crc32(be32(s)||be32(o)||be32(crc32(data))||key)``."""

    s, o = _be32(payload, 7), _be32(payload, 11)
    if dedup is not None and dedup(topic_id, s, o):
        raise MqttFrameError("12003", f"cloud command repeat with s:{s} o:{o}")
    data = payload[15:]
    expected = crc_s_o_data_key(s, o, data, local_key)
    actual = _be32(payload, 3)
    if int.from_bytes(expected, "big", signed=True) != actual:
        computed = int.from_bytes(expected, "big", signed=True)
        raise MqttFrameError(
            "12002", f"mqtt1_1: signature is not match signStrBt{computed}signBt:{actual}"
        )
    text = data.decode("utf-8", errors="replace")
    if text_is_empty(text):
        raise MqttFrameError("12001", "dealWithDeviceTopic1_1 data parsing failure")
    obj = parse_object(text)
    return _protocol_or_raise(obj, "protocol is not exist null"), obj


# --------------------------------------------------------------------------
# Inbound dispatcher — ``qbqddpp`` (thing_mqtt-ThingMessageManager)
# --------------------------------------------------------------------------


def _check_pv_version(pv, threshold: float) -> bool:
    """``ThingUtil.checkPvVersion`` — ``!isEmpty && Float.valueOf(pv) >= f``.
    No 'v' stripping; ``Float.valueOf`` raises on malformed input."""

    if pv is None or pv == "":
        return False
    return float(pv) >= threshold


def _get_string(obj: dict, key: str):
    """fastjson ``getString`` — returns the string value, ``str(v)`` for
    primitives, JSON for objects/arrays, or None."""

    v = obj.get(key)
    if v is None or isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return to_json_string(v)
    return str(v)


def _get_int_value(obj: dict, key: str) -> int:
    """fastjson ``getIntValue`` — missing/unparseable → 0."""

    v = obj.get(key)
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v.strip())
        except ValueError:
            return 0
    return 0


def _deal_with_device_topic_signed(
    protocol: int, topic: str, obj: dict, get_local_key
) -> tuple[int, dict]:
    """``qbqddpp.bdpdqbp(I, String, JSONObject, cb)`` — the pv 2.0 signed
    path: verify ``sign``, AES-hex-decrypt ``data`` in place."""

    sign = _get_string(obj, "sign")
    local_key = get_local_key(topic)
    if text_is_empty(local_key):
        raise MqttFrameError("F101", "localKey == null")
    if sign_json(obj, local_key).lower() != (sign or "").lower():
        raise MqttFrameError("11004", "sign is not equals")
    enc_data = _get_string(obj, "data")
    plain = AESUtil(local_key.encode()).decrypt(enc_data)
    obj["data"] = parse_object(plain)
    return protocol, obj


def _deal_with_device_topic(topic: str, obj: dict, get_local_key) -> tuple[int, dict]:
    """``qbqddpp.bdpdqbp(String, JSONObject, cb)`` — JSON device-topic
    messages: pv 2.0 takes the signed path; everything else passes through."""

    protocol = _get_int_value(obj, "protocol")
    if protocol != 16 and _get_string(obj, "pv") == "2.0":
        return _deal_with_device_topic_signed(protocol, topic, obj, get_local_key)
    return protocol, obj


def dispatch_inbound_message(
    topic: str,
    payload: bytes | None,
    get_local_key,
    dedup=None,
    prefixes=(),
) -> list[tuple[int, dict]]:
    """``qbqddpp.bdpdqbp(cb)`` — full inbound dispatch.

    ``payload`` None → silent drop (returns ``[]``). A ``"{"`` prefix parses
    the payload as a JSON envelope (the signed 2.0 path lives here).
    Otherwise the first 3 bytes are the pv prefix; for every subscribed
    ``prefix`` the topic starts with, the matching decoder runs once and its
    ``(protocol, obj)`` result is appended — Java invokes the callback once
    per match, so callers with multiple matching prefixes get one element
    each. Errors raise :class:`MqttFrameError` carrying the Java
    ``onError(code, msg)`` pair.
    """

    if payload is None:
        return []
    prefix = payload[:3].decode(errors="replace")
    if prefix.startswith("{"):
        obj = parse_object(payload.decode())
        if topic.startswith(SMART_MB_IN_PREFIX):
            return [_deal_with_device_topic(topic, obj, get_local_key)]
        return [(_get_int_value(obj, "protocol"), obj)]
    local_key = get_local_key(topic)
    if text_is_empty(local_key):
        return []  # silent drop — no error callback in the binary branch
    results = []
    for p in prefixes:
        if not topic.startswith(p):
            continue
        # Java: topic.replace(prefix, "") result is discarded; the decoders
        # still see the FULL topic as "topicId".
        if _check_pv_version(prefix, 2.3):
            results.append(parse_inbound_2_3(local_key, payload, topic, dedup))
        elif _check_pv_version(prefix, 2.2):
            results.append(parse_inbound_2_2(local_key, payload, topic, dedup))
        elif _check_pv_version(prefix, 2.1):
            results.append(parse_inbound_2_1(local_key, payload, topic))
        elif _check_pv_version(prefix, 1.1):
            results.append(parse_inbound_1_1(local_key, payload, topic, dedup))
        # else: log "pv：.. support min：1.1" — no callback
    return results
