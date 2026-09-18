"""LAN request assembly — port of the ``ddbdpqb`` ("LocalControl") family.

smali:
- smali_classes3/com/thingclips/sdk/hardware/ddqpdpp.smali  (request spec bean)
- .../hardware/ddbdpqb.smali      (LocalControl base — shared fields + build)
- .../hardware/bbbdppp.smali      ("LocalControlManager" — lpv dispatcher)
- .../hardware/qbqppdb.smali      (lpv ≥ 3.4 — plaintext inner JSON)
- .../hardware/bdqbdpp.smali      (lpv ≥ 3.2 — AES-ECB raw bytes)
- .../hardware/bpbqpqd.smali      (lpv ≥ 3.1 — AES-ECB base64 + sign)
- .../hardware/qdbpqqq.smali      (lpv == "1.1" — AES-ECB hex)
- .../hardware/bbppbbd.smali      (default — AES-ECB hex)
- .../hardware/pbbqpqd.smali      (shared encrypt/sign helpers)

Version dispatch uses ``ThingUtil.checkHgwVersion`` — the lpv string with
every ``v`` stripped, parsed as a float — and ``isHgwVersionEquals``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._fastjson import to_json_bytes, to_json_string
from ._java import text_is_empty
from .crypto import AESUtil, md5_upper
from .hexutil import contact, int_to_bytes2


@dataclass
class HRequest:
    """``com.thingclips.sdk.hardwareprotocol.bean.HRequest``."""

    dev_id: str | None = None
    type: int = 0
    data: bytes = b""
    t: int = 0


@dataclass
class LocalControlSpec:
    """``ddqpdpp`` — the input to request assembly (``ThingLocalControlBean``
    contents: devId, lpv, s, o, t, protocol, frameType, localKey, data)."""

    dev_id: str
    frame_type: int
    data: Any  # the payload object — fastjson-serialized (dict/bean)
    lpv: str = ""
    local_key: str | None = None
    s: int = 0
    o: int = 0
    t: int = 0
    protocol: int = 0


def check_hgw_version(version: str | None, minimum: float) -> bool:
    """``ThingUtil.checkHgwVersion`` — strip every ``"v"``, parse float,
    ``>=`` compare; empty/unparseable → false."""

    if version is None or version == "":
        return False
    try:
        return float(version.replace("v", "")) >= minimum
    except (ValueError, TypeError):
        return False


def is_hgw_version_equals(version: str | None, expected: str) -> bool:
    """``ThingUtil.isHgwVersionEquals`` — strip every ``"v"`` then equals."""

    if version is None or version == "":
        return False
    return version.replace("v", "") == expected


def _base_request(spec: LocalControlSpec) -> HRequest:
    """``ddbdpqb.bdpdqbp()`` — HRequest{devId, frameType,
    data = fastjson(dataObject, WriteMapNullValue)}."""

    return HRequest(
        dev_id=spec.dev_id,
        type=spec.frame_type,
        data=to_json_bytes(spec.data),
    )


def _encrypt_hex(request: HRequest, local_key: str | None) -> HRequest:
    """``pbbqpqd.bdpdqbp(HRequest, String)`` — AES/ECB encrypt → UPPERCASE hex
    string bytes. Empty key → data untouched."""

    if not text_is_empty(local_key):
        try:
            request.data = AESUtil(local_key.encode()).encrypt(request.data.decode()).encode()
        except Exception:
            pass
    return request


def _encrypt_base64(request: HRequest, local_key: str | None) -> HRequest:
    """``pbbqpqd.pdqppqb(HRequest, String)`` — AES/ECB encrypt → base64 string
    bytes. Empty key → data untouched."""

    if not text_is_empty(local_key):
        try:
            request.data = (
                AESUtil(local_key.encode()).encrypt_with_base64(request.data.decode()).encode()
            )
        except Exception:
            pass
    return request


def sign_lpv(lpv: str, data: str, local_key: str) -> str | None:
    """``pbbqpqd.bdpdqbp(String lpv, String data, String key)`` —
    ``md5("data="+data+"||lpv="+lpv+"||"+key).lower()[8:24]``."""

    digest = md5_upper(f"data={data}||lpv={lpv}||{local_key}")
    return digest.lower()[8:24]


def assemble_3_4(spec: LocalControlSpec) -> HRequest:
    """``qbqppdb`` — lpv ≥ 3.4.

    Inner JSON ``{"protocol":p, "data":<obj>, "t":t}`` (insertion order,
    WriteMapNullValue) carried plaintext — session-layer GCM encryption
    happens below this. ``data = lpv || 0x00000000 || be32(s) || be32(o) ||
    jsonBytes``.
    """

    request = HRequest(dev_id=spec.dev_id, type=spec.frame_type)
    inner = {"protocol": spec.protocol, "data": spec.data, "t": spec.t}
    request.data = contact(
        spec.lpv.encode(),
        bytes(4),
        int_to_bytes2(spec.s),
        int_to_bytes2(spec.o),
        to_json_bytes(inner),
    )
    return request


def assemble_3_2(spec: LocalControlSpec) -> HRequest:
    """``bdqbdpp`` — lpv ≥ 3.2. ``data = lpv || 0x00000000 || be32(s) ||
    be32(o) || aes_ecb_bytes(fastjson(dataObject))``; empty key leaves the
    plaintext JSON."""

    request = HRequest(dev_id=spec.dev_id, type=spec.frame_type)
    json_text = to_json_string(spec.data)
    # Java leaves HRequest.data unset on encrypt failure and NPEs in
    # ByteUtils.contact — propagate rather than silently sending plaintext.
    if not text_is_empty(spec.local_key):
        payload = AESUtil(spec.local_key.encode()).encrypt_with_bytes(json_text)
    else:
        payload = json_text.encode()
    request.data = contact(
        spec.lpv.encode(),
        bytes(4),
        int_to_bytes2(spec.s),
        int_to_bytes2(spec.o),
        payload,
    )
    return request


def assemble_3_1(spec: LocalControlSpec) -> HRequest:
    """``bpbqpqd`` — lpv ≥ 3.1. ``data = lpv || sign || base64Enc`` where
    ``sign = sign_lpv(lpv, base64Enc, localKey)``.

    Raises :class:`SignatureError` (``11005``/"SIGNTURE NOT EQUALS") when the
    sign comes back empty — the Java path fires ``onError`` instead of
    producing a request.
    """

    request = _base_request(spec)
    request = _encrypt_base64(request, spec.local_key)
    sign = sign_lpv(spec.lpv, request.data.decode(), spec.local_key or "")
    if text_is_empty(sign):
        raise SignatureError("11005", "SIGNTURE NOT EQUALS")
    request.data = contact(spec.lpv.encode(), sign.encode(), request.data)
    return request


def assemble_1_1(spec: LocalControlSpec) -> HRequest:
    """``qdbpqqq`` — lpv == "1.1": plain JSON → AES hex string, no prefix."""

    return _encrypt_hex(_base_request(spec), spec.local_key)


def assemble_default(spec: LocalControlSpec) -> HRequest:
    """``bbppbbd`` — fallback: identical to 1.1 (AES hex, no prefix)."""

    return _encrypt_hex(_base_request(spec), spec.local_key)


class SignatureError(Exception):
    """The 3.1 assembler's ``onError("11005", "SIGNTURE NOT EQUALS")``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def assemble_request(spec: LocalControlSpec) -> HRequest:
    """``bbbdppp`` — lpv-version dispatcher:

    lpv ≥ 3.4 → 3.4 plaintext; ≥ 3.2 → AES bytes; ≥ 3.1 → AES base64 + sign;
    lpv == "1.1" → AES hex; else → AES hex (default).
    """

    if check_hgw_version(spec.lpv, 3.4):
        return assemble_3_4(spec)
    if check_hgw_version(spec.lpv, 3.2):
        return assemble_3_2(spec)
    if check_hgw_version(spec.lpv, 3.1):
        return assemble_3_1(spec)
    if is_hgw_version_equals(spec.lpv, "1.1"):
        return assemble_1_1(spec)
    return assemble_default(spec)
