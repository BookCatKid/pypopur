"""Deterministic crypto vectors verified against ``libthing_security.so``.

Every expected value below was produced by emulating the real JNI function
in ``popur-research/emu_jni.py`` with ``GLOBAL_S`` (and the ``getChKey``
globals) injected as ndk strings at their BSS addresses:

- ``GLOBAL_S`` @0x384f0 = ``APP2_NATIVE_MASTER_HEX`` decoded
- ``GLOBAL_D`` @0x38520 = ``com.smartapp.popur.app``
- ``GLOBAL_C`` @0x384d8 = APK signing-cert SHA-256 (colon hex)
"""

from __future__ import annotations

import pytest

from pypopur.mobile import (
    canonical_sign_input,
    derive_ch_key,
    mobile_response_signature,
    sign_mobile_params,
)
from pypopur.popur_app2_material import APP2_CH_KEY, APP2_NATIVE_MASTER_HEX
from pypopur.sdk.security import ThingNetworkSecurity, default_cmd2, default_signer

GLOBAL_S = bytes.fromhex(APP2_NATIVE_MASTER_HEX)

_sec = ThingNetworkSecurity(GLOBAL_S)


@pytest.mark.parametrize(
    ("arg0", "arg1", "expected"),
    [
        ("abc123456789", "secretkey", "eadf385f1314b646b620d76e606473bb"),
        ("req-42", "ec00", "f39c4f2fe79e0e4e6c3240aed2c36952"),
        ("", "", "3b5c21c3908b5aa8149049b5db5d034a"),
        ("unicode-key-é", "data-漢字", "a51f463e04d428352d2af221abdf6feb"),
    ],
)
def test_compute_digest(arg0: str, arg1: str, expected: str) -> None:
    assert _sec.compute_digest(arg0, arg1) == expected


@pytest.mark.parametrize(
    ("request_id", "ecode", "expected"),
    [
        ("req123", "ec00", b"093f95f4c7e352cb"),
        ("R1", "", b"7ab76d47736bd2ca"),
        ("long-request-id-0123456789", "ec", b"ca80bc5a48f0c057"),
    ],
)
def test_get_encrypto_key(request_id: str, ecode: str, expected: bytes) -> None:
    assert _sec.get_encrypto_key(request_id, ecode) == expected


@pytest.mark.parametrize(
    ("a", "b", "c", "expected"),
    [
        ("a1", "0123456789abcdef", "c1", "d064eecc21cebdb6"),
        ("key!@#", "zyxwvutsrqponmlk", "session42", "6cdd5d081a2b0e43"),
        ("", "0123456789abcdef", "", "3c85a6193e707e68"),
        # b shorter than 16: native loops min(strlen,16) times reading
        # b[b[i]&0xF] — indexes past len hit the NUL-padded tail of the
        # UTF buffer, mirrored by ljust(16, "\0").
        ("a", "short", "c", "7e0f4f507dd6006a"),
    ],
)
def test_gen_key(a: str, b: str, c: str, expected: str) -> None:
    assert _sec.gen_key(a, b, c) == expected


def test_encrypt_post_data() -> None:
    assert _sec.encrypt_post_data("somekey", b"payload") == b"667f83ac5d2f381f"


def test_do_command_native_sign_is_hmac_sha256() -> None:
    # doCommandNative cmd 1 = hmac_sha256(GLOBAL_S, canonical) — verified by
    # running cmd 1 natively after a real cmd-0 global derivation.
    assert (
        default_signer("a=1||b=2||postData=abc", GLOBAL_S)
        == "5b6be30e5e83ec020442648589b3a077f3416d1be896a86e96f23b0ba2b784ef"
    )


def test_sign_mobile_params_uses_hmac_sha256() -> None:
    params = {"a": "1", "b": "2", "postData": "abc"}
    assert sign_mobile_params(params, GLOBAL_S) == default_signer(
        canonical_sign_input(params), GLOBAL_S
    )


@pytest.mark.parametrize(
    ("ecode", "expected"),
    [
        (b"ec00", "deff3b899b64e7e66f33150964d16c5e"),
        (b"ec01", "e47c139e123a7bc8d84b7339c3fa170f"),
        (b"", "32730dedaad3c47af867f664cd6534bf"),
    ],
)
def test_do_command_native_cmd2_is_nested_md5(ecode: bytes, expected: str) -> None:
    # cmd 2 = md5hex(md5hex(GLOBAL_S) + arg) — MQTT password seed,
    # verified by running cmd 2 natively after a real cmd-0 derivation.
    assert default_cmd2(ecode, GLOBAL_S) == expected


def test_mobile_response_signature_vector() -> None:
    # Business.verifyResponseResult — md5Hex("result="+result+"||t="+t+"||"+keyStr)
    assert (
        mobile_response_signature("abc123", 7, b"093f95f4c7e352cb")
        == "844a4a544782a4f634febb5a8cdf53dc"
    )
    assert mobile_response_signature("", 0, b"k") == "92b1a0342c373c9890970b9d30615b72"


def test_get_ch_key_vector() -> None:
    # hmac-sha256(key=app_id, msg=package + "_" + cert_sha256)[8:16] —
    # emulated getChKey output equals the shipped APP2_CH_KEY constant.
    assert APP2_CH_KEY == "fa44caaa"
    assert (
        derive_ch_key(
            "aup8mma84uvgeeeayman",
            "com.smartapp.popur.app",
            "F9:6D:61:DA:09:C6:8F:FA:AE:6E:D6:FA:D6:ED:BF:22:38:CF:3E"
            ":5D:44:50:59:4D:0B:1E:31:50:83:20:A1:DB",
        )
        == APP2_CH_KEY
    )
