from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import struct
import tempfile
import unittest
import urllib.error
import uuid
import zipfile
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pypopur import (
    S7_PRODUCT_IDS,
    AccountDeviceNotFound,
    DiscoveredS7,
    MobileApiError,
    MobileAppProfile,
    MobileAuthenticationError,
    MobileSession,
    PopurAccount,
    ProtocolError,
    ThingMobileApi,
    TransportError,
    bootstrap_discovered_s7,
    bootstrap_discovered_s7_popur_app2,
    canonical_sign_input,
    decrypt_mobile_payload,
    derive_android_device_id,
    derive_ch_key,
    derive_request_key,
    encrypt_mobile_payload,
    extract_apk_signing_certificate_sha256,
    extract_popur_app2_build_config,
    extract_thing_security_components,
    mobile_response_signature,
    normalize_certificate_sha256,
    sign_mobile_params,
)
from pypopur.mobile import (
    _extract_build_config_from_dex,
    _header_value,
    _require_mapping,
    _require_text,
    _rsa_encrypt_password,
    _stdlib_post_form,
    _stdlib_post_form_sync,
    _swap_md5_blocks,
    _transform_thing_security_component,
)


def _uleb(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def _synthetic_build_config_dex(values: Mapping[str, str]) -> bytes:
    descriptor = "Lcom/smartapp/popur/app/BuildConfig;"
    names = list(values)
    strings = [descriptor, *names, *(values[name] for name in names)]
    header_size = 0x70
    string_ids_offset = header_size
    type_ids_offset = string_ids_offset + len(strings) * 4
    field_ids_offset = type_ids_offset + 4
    class_defs_offset = field_ids_offset + len(names) * 8
    data_offset = class_defs_offset + 32

    string_blobs = []
    string_offsets = []
    cursor = data_offset
    for value in strings:
        encoded = value.encode()
        blob = _uleb(len(value)) + encoded + b"\0"
        string_offsets.append(cursor)
        string_blobs.append(blob)
        cursor += len(blob)

    class_data_offset = cursor
    class_data = bytearray(_uleb(len(names)) + _uleb(0) + _uleb(0) + _uleb(0))
    for index in range(len(names)):
        class_data.extend(_uleb(0 if index == 0 else 1))
        class_data.extend(_uleb(0x19))
    cursor += len(class_data)
    static_values_offset = cursor
    static_values = bytearray(_uleb(len(names)))
    for index in range(len(names)):
        string_index = 1 + len(names) + index
        width = max(1, (string_index.bit_length() + 7) // 8)
        static_values.append(0x17 | ((width - 1) << 5))
        static_values.extend(string_index.to_bytes(width, "little"))

    data = bytearray(static_values_offset + len(static_values))
    data[:8] = b"dex\n035\0"
    struct.pack_into("<II", data, 0x38, len(strings), string_ids_offset)
    struct.pack_into("<II", data, 0x40, 1, type_ids_offset)
    struct.pack_into("<II", data, 0x50, len(names), field_ids_offset)
    struct.pack_into("<II", data, 0x60, 1, class_defs_offset)
    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", data, string_ids_offset + index * 4, offset)
    struct.pack_into("<I", data, type_ids_offset, 0)
    for index, name in enumerate(names):
        struct.pack_into("<HHI", data, field_ids_offset + index * 8, 0, 0, 1 + index)
    struct.pack_into(
        "<IIIIIIII",
        data,
        class_defs_offset,
        0,
        1,
        0,
        0,
        0xFFFFFFFF,
        0,
        class_data_offset,
        static_values_offset,
    )
    cursor = data_offset
    for blob in string_blobs:
        data[cursor : cursor + len(blob)] = blob
        cursor += len(blob)
    data[class_data_offset : class_data_offset + len(class_data)] = class_data
    data[static_values_offset : static_values_offset + len(static_values)] = static_values
    return bytes(data)


def _synthetic_security_bitmap(client_id: str, component: bytes) -> bytes:
    payload = bytearray(4096)
    length = len(payload)
    java_hash = 0
    for byte in client_id.encode():
        java_hash = ((java_hash * 31) + byte) & 0xFFFFFFFF
    if java_hash & 0x80000000:
        java_hash -= 1 << 32
    cursor = ((abs(java_hash) % length) // 2) % length + 1

    def write_byte(value: int) -> None:
        nonlocal cursor
        for bit in range(8):
            index = cursor % length
            payload[index] = (payload[index] & 0xFE) | ((value >> bit) & 1)
            cursor += 1

    write_byte(1)
    write_byte(2)
    cursor += 32
    constant = int.from_bytes(component, "big")
    for x_value in (1, 2):
        y_value = constant + 3 * x_value
        for value in (x_value, y_value):
            raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
            write_byte(len(raw))
            for byte in raw:
                write_byte(byte)

    size = 54 + len(payload)
    header = bytearray(54)
    header[:2] = b"BM"
    header[2:6] = size.to_bytes(4, "little")
    header[10:14] = (54).to_bytes(4, "little")
    return bytes(header + payload)


def _synthetic_v2_signed_apk(certificate: bytes) -> bytes:
    def lp(value: bytes, width: int = 4) -> bytes:
        return len(value).to_bytes(width, "little") + value

    certificates = lp(certificate)
    signed_data = lp(b"") + lp(certificates)
    signer = lp(signed_data)
    signers = lp(signer)
    pair = (0x7109871A).to_bytes(4, "little") + lp(signers)
    pair_record = lp(pair, 8)
    block_size = len(pair_record) + 24
    block = block_size.to_bytes(8, "little") + pair_record
    block += block_size.to_bytes(8, "little") + b"APK Sig Block 42"
    central_directory_offset = len(block)
    eocd = bytearray(22)
    eocd[:4] = b"PK\x05\x06"
    struct.pack_into("<I", eocd, 16, central_directory_offset)
    return block + eocd


def make_profile() -> MobileAppProfile:
    return MobileAppProfile(
        api_host="https://example.invalid",
        client_id="dummy-client",
        app_version="2.0.0",
        sdk_version="6.7.3",
        device_core_version="9.9",
        ttid="dummy-ttid",
        ch_key="dummy-channel",
        signing_key=b"s" * 32,
        encryption_secret=b"synthetic-master-secret",
        package_name="com.example.popur-test",
        region_hosts={"us": "https://example.invalid", "eu": "https://a1.tuyaeu.com"},
    )


class SyntheticThingServer:
    """In-memory ATOP server that validates the requests pypopur emits."""

    def __init__(self, profile: MobileAppProfile) -> None:
        self.profile = profile
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.calls: list[dict[str, str]] = []
        self.plain_post_data: list[dict[str, Any]] = []
        self.local_key_in_detail = False
        self.local_key = "synthetic-local-key"
        self.product_id = min(S7_PRODUCT_IDS)
        self.domain_host = "example.invalid"
        self.expected_url = "https://example.invalid/api.json"
        self.home_list_result: Any = [{"homeId": 7, "name": "Home"}]
        self.key_result: Any | None = None
        self.error_by_action: dict[str, tuple[str, str]] = {}
        self.error_once_by_action: dict[str, tuple[str, str]] = {}
        self.http_status_by_action: dict[str, int] = {}
        self.invalid_json_action: str | None = None
        self.compress_action: str | None = None

    def _token(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "publicKey": str(numbers.n),
            "exponent": str(numbers.e),
            "token": "synthetic-rsa-token",
        }

    def _decode_request(self, data: Mapping[str, str]) -> dict[str, Any]:
        expected_sign = sign_mobile_params(data, self.profile.signing_key)
        if data["sign"] != expected_sign:
            raise AssertionError("request signature mismatch")
        if "postData" not in data:
            return {}
        if data["et"] == "3":
            key = derive_request_key(
                data["requestId"],
                self.profile.encryption_secret,
                "synthetic-ecode" if data.get("sid") else None,
            )
            raw = decrypt_mobile_payload(data["postData"], key)
            return json.loads(raw)
        return json.loads(data["postData"])

    def _encode_result(
        self, action: str, data: Mapping[str, str], result: Any
    ) -> tuple[dict[str, str], Any]:
        if data["et"] != "3":
            return {}, result
        key = derive_request_key(
            data["requestId"],
            self.profile.encryption_secret,
            "synthetic-ecode" if data.get("sid") else None,
        )
        inner_envelope = {"success": True, "status": "ok", "result": result}
        raw = json.dumps(inner_envelope, separators=(",", ":")).encode()
        headers: dict[str, str] = {}
        if action == self.compress_action:
            raw = gzip.compress(raw)
            headers["x-content-compress"] = "gzip"
        encoded = encrypt_mobile_payload(
            raw.decode("latin1") if action == self.compress_action else raw.decode(),
            key,
            nonce=b"\x02" * 12,
        )
        if action == self.compress_action:
            # ``encrypt_mobile_payload`` accepts text. Rebuild the equivalent envelope for raw
            # gzip bytes so response decompression gets exercised without altering production API.
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            encrypted = AESGCM(key).encrypt(b"\x02" * 12, raw, None)
            encoded = base64.b64encode(b"\x02" * 12 + encrypted).decode()
        return headers, encoded

    async def __call__(
        self,
        url: str,
        data: Mapping[str, str],
        request_headers: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, Mapping[str, str], bytes]:
        self.assert_request_url(url, request_headers, timeout)
        if request_headers["x-client-trace-id"] != data["requestId"]:
            raise AssertionError(request_headers)
        call = dict(data)
        self.calls.append(call)
        action = data["a"]
        if action == self.invalid_json_action:
            return 200, {}, b"not-json"
        status = self.http_status_by_action.get(action, 200)
        if status != 200:
            return status, {}, b"{}"
        if action in self.error_once_by_action:
            code, message = self.error_once_by_action.pop(action)
            return (
                200,
                {},
                json.dumps(
                    {
                        "success": False,
                        "errorCode": code,
                        "errorMsg": message,
                        "t": 1_700_000_500,
                    }
                ).encode(),
            )
        if action in self.error_by_action:
            code, message = self.error_by_action[action]
            return (
                200,
                {},
                json.dumps(
                    {
                        "success": False,
                        "errorCode": code,
                        "errorMsg": message,
                        "t": 1_700_000_500,
                    }
                ).encode(),
            )

        post_data = self._decode_request(data)
        self.plain_post_data.append(post_data)
        if action == "smartlife.m.user.username.token.get":
            result: Any = self._token()
        elif action == "smartlife.m.user.email.password.login":
            cipher = bytes.fromhex(post_data["passwd"])
            plain = self.private_key.decrypt(cipher, padding.PKCS1v15()).decode()
            if plain != hashlib.md5(b"correct horse", usedforsecurity=False).hexdigest():
                raise AssertionError("password was not MD5 + RSA wrapped")
            result = {
                "sid": "synthetic-sid",
                "ecode": "synthetic-ecode",
                "uid": "synthetic-uid",
                "partnerIdentity": "synthetic-partner",
                "domain": {"mobileApiUrl": self.domain_host} if self.domain_host else {},
            }
        elif action == "m.life.home.space.list":
            result = self.home_list_result
        elif action == "m.life.location.get":
            result = {"homeId": post_data["gid"], "name": "Home"}
        elif action == "m.life.my.group.device.list":
            result = [self._device_record()]
        elif action == "smartlife.m.device.get":
            result = self._device_record()
        elif action == "smartlife.m.device.key.get":
            result = self.key_result
            if result is None:
                result = (
                    [{"devId": post_data["gwId"], "localKey": self.local_key}]
                    if self.local_key
                    else []
                )
        elif action == "smartlife.m.api.batch.invoke":
            beans = post_data["apis"]
            assert isinstance(beans, list) and beans
            responses = []
            for bean in beans:
                assert bean["et"] == "3" and bean["requestId"] and bean["sign"]
                bean_key = derive_request_key(
                    bean["requestId"],
                    self.profile.encryption_secret,
                    "synthetic-ecode",
                )
                bean_post = json.loads(decrypt_mobile_payload(bean["params"], bean_key))
                responses.append(
                    {
                        "a": bean["a"],
                        "success": True,
                        "result": {"api": bean["a"], "postData": bean_post},
                    }
                )
            result = responses
        elif action == "m.life.app.smart.local.device.list":
            result = [{"devId": "local-dev", "homeId": post_data["homeId"]}]
        else:
            raise AssertionError(f"unexpected API action {action}")

        headers, encoded_result = self._encode_result(action, data, result)
        envelope: dict[str, Any] = {"success": True, "result": encoded_result}
        if data["et"] == "3":
            key = derive_request_key(
                data["requestId"],
                self.profile.encryption_secret,
                "synthetic-ecode" if data.get("sid") else None,
            )
            response_time = 1_700_000_000
            envelope["t"] = response_time
            envelope["sign"] = mobile_response_signature(encoded_result, response_time, key)
        return 200, headers, json.dumps(envelope).encode()

    def assert_request_url(
        self, url: str, request_headers: Mapping[str, str], timeout: float
    ) -> None:
        if url != self.expected_url:
            raise AssertionError(url)
        if timeout != 4:
            raise AssertionError(timeout)
        if request_headers["Connection"] != "keep-alive":
            raise AssertionError(request_headers)
        if request_headers["x-client-trace-id"] == "":
            raise AssertionError(request_headers)
        expected_user_agent = (
            f"Thing-UA=APP/Android/{self.profile.app_version}/SDK/{self.profile.sdk_version}"
        )
        if request_headers["User-Agent"] != expected_user_agent:
            raise AssertionError(request_headers)

    def _device_record(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "devId": "s7-device",
            "productId": self.product_id,
            "name": "Popur S7",
            "ip": "192.0.2.50",
            "dataPointInfo": {
                "dps": {
                    "1": True,
                    "12": 4,
                    "101": "AQUAAAA=",
                    "102": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "109": "power_on",
                    "146": 2,
                    "150": 7,
                }
            },
        }
        if self.local_key_in_detail:
            value["localKey"] = self.local_key
        return value


class CryptoTests(unittest.TestCase):
    def test_apk_material_extractors_and_complete_profile(self) -> None:
        client_id = "synthetic-client-id"
        app_secret = "synthetic-app-secret"
        component = b"\x12\x34\x56\x78"
        build_config = {
            "APPLICATION_ID": "com.smartapp.popur.app",
            "THING_SMART_APPKEY": client_id,
            "THING_SMART_SECRET": app_secret,
            "VERSION_NAME": "2.0.0",
        }
        dex = _synthetic_build_config_dex(build_config)
        self.assertEqual(_extract_build_config_from_dex(dex), build_config)
        bitmap = _synthetic_security_bitmap(client_id, component)
        transformed_component = _transform_thing_security_component(component)
        self.assertEqual(transformed_component.hex(), "defc3873")
        self.assertEqual(
            _transform_thing_security_component(bytes(range(32))).hex(),
            "ccc96c08f327f839b1a1908bf3f2f1f08c8bd0d2be79010feec8cb85cebc2ab5",
        )
        self.assertEqual(
            extract_thing_security_components(client_id, bitmap), (transformed_component,)
        )

        with tempfile.TemporaryDirectory() as directory:
            apk_path = f"{directory}/popur.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("classes.dex", dex)
                archive.writestr("assets/t_s.bmp", bitmap)
            extracted_config = extract_popur_app2_build_config(apk_path)
            self.assertEqual(extracted_config, build_config)
            with patch(
                "pypopur.mobile.extract_apk_signing_certificate_sha256", return_value="11" * 32
            ):
                profile = MobileAppProfile.from_popur_app2_apk(apk_path)
            normalized_certificate = normalize_certificate_sha256("11" * 32)
            self.assertEqual(profile.client_id, client_id)
            self.assertEqual(
                profile.signing_key,
                b"com.smartapp.popur.app_"
                + normalized_certificate.encode()
                + b"_"
                + transformed_component
                + b"_"
                + app_secret.encode(),
            )
            self.assertNotIn(client_id, repr(profile))
            self.assertNotIn(app_secret, repr(profile))

            wrong_values = dict(build_config, VERSION_NAME="9.9.9")
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("classes.dex", _synthetic_build_config_dex(wrong_values))
                archive.writestr("assets/t_s.bmp", bitmap)
            with self.assertRaisesRegex(ValueError, "verified Popur App-2 version"):
                MobileAppProfile.from_popur_app2_apk(apk_path)

        certificate = b"synthetic DER certificate bytes"
        with tempfile.NamedTemporaryFile() as apk_file:
            apk_file.write(_synthetic_v2_signed_apk(certificate))
            apk_file.flush()
            self.assertEqual(
                extract_apk_signing_certificate_sha256(apk_file.name),
                hashlib.sha256(certificate).hexdigest(),
            )

    def test_apk_material_extractor_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "BMP"):
            extract_thing_security_components("client", b"not-a-bitmap")
        with self.assertRaisesRegex(ValueError, "client_id"):
            extract_thing_security_components("", _synthetic_security_bitmap("client", b"x"))
        with tempfile.NamedTemporaryFile() as file:
            file.write(b"not-an-apk")
            file.flush()
            with self.assertRaisesRegex(ValueError, "signing block|ZIP end"):
                extract_apk_signing_certificate_sha256(file.name)

    def test_profile_derivation_and_secret_redaction(self) -> None:
        certificate = "11" * 32
        profile = MobileAppProfile.from_native_components(
            api_host="example.invalid",
            client_id="sensitive-app-id",
            app_version="2",
            sdk_version="6",
            ttid="ttid",
            package_name="com.example.app",
            certificate_sha256=certificate,
            transformed_security_component="component",
            app_secret="never-print-this",
        )
        normalized_certificate = normalize_certificate_sha256(certificate)
        master = f"com.example.app_{normalized_certificate}_component_never-print-this".encode()
        self.assertEqual(profile.encryption_secret, master)
        self.assertEqual(profile.signing_key, master)
        self.assertEqual(
            profile.ch_key,
            derive_ch_key("sensitive-app-id", "com.example.app", normalized_certificate),
        )
        expected_ch_key = hmac.new(
            b"sensitive-app-id",
            b"com.example.app_" + normalized_certificate.encode(),
            hashlib.sha256,
        ).hexdigest()[8:16]
        self.assertEqual(profile.ch_key, expected_ch_key)
        self.assertNotIn("never-print-this", repr(profile))
        self.assertNotIn("sensitive-app-id", repr(profile))
        self.assertNotIn(profile.ch_key, repr(profile))
        self.assertIn("<redacted>", repr(profile))

        binary_component = b"\x00\xff\x10binary"
        binary_profile = MobileAppProfile.from_native_components(
            api_host="example.invalid",
            client_id="sensitive-app-id",
            app_version="2",
            sdk_version="6",
            ttid="ttid",
            package_name="com.example.app",
            certificate_sha256=certificate,
            transformed_security_component=binary_component,
            app_secret="never-print-this",
        )
        self.assertEqual(
            binary_profile.signing_key,
            b"com.example.app_"
            + normalized_certificate.encode()
            + b"_"
            + binary_component
            + b"_never-print-this",
        )

        for kwargs, message in (
            ({"api_host": ""}, "api_host"),
            ({"client_id": ""}, "client_id"),
            ({"app_version": ""}, "app_version"),
            ({"sdk_version": ""}, "sdk_version"),
            ({"ttid": ""}, "ttid"),
            ({"ch_key": ""}, "ch_key"),
            ({"signing_key": b""}, "signing_key"),
            ({"encryption_secret": b""}, "encryption_secret"),
            ({"channel": ""}, "channel"),
        ):
            values = {
                "api_host": "host",
                "client_id": "client",
                "app_version": "2",
                "sdk_version": "6",
                "ttid": "ttid",
                "ch_key": "ch",
                "signing_key": b"sign",
                "encryption_secret": b"encrypt",
            }
            values.update(kwargs)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                MobileAppProfile(**values)

        native_values = {
            "api_host": "host",
            "client_id": "client",
            "app_version": "2",
            "sdk_version": "6",
            "ttid": "ttid",
            "package_name": "package",
            "certificate_sha256": certificate,
            "transformed_security_component": "component",
            "app_secret": "secret",
        }
        for field_name in (
            "package_name",
            "certificate_sha256",
            "transformed_security_component",
            "app_secret",
        ):
            values = dict(native_values)
            values[field_name] = ""
            with (
                self.subTest(field_name=field_name),
                self.assertRaisesRegex(ValueError, field_name),
            ):
                MobileAppProfile.from_native_components(**values)

        values = dict(native_values)
        values["transformed_security_component"] = b""
        with self.assertRaisesRegex(ValueError, "transformed_security_component"):
            MobileAppProfile.from_native_components(**values)

        with self.assertRaisesRegex(ValueError, "certificate_sha256"):
            normalize_certificate_sha256("not-a-sha256")
        with self.assertRaisesRegex(ValueError, "certificate_sha256"):
            normalize_certificate_sha256("Z" * 64)
        with self.assertRaisesRegex(ValueError, "app_id"):
            derive_ch_key("", "com.example.app", certificate)
        with self.assertRaisesRegex(ValueError, "package_name"):
            derive_ch_key("app-id", "", certificate)

    def test_popur_app2_profile_metadata_and_ch_key_helpers(self) -> None:
        certificate = "ab" * 32
        profile = MobileAppProfile.for_popur_app2(
            client_id="synthetic-app-id",
            certificate_sha256=certificate,
            transformed_security_component="synthetic-component",
            app_secret="synthetic-secret",
        )
        self.assertEqual(profile.api_host, "https://a1-us.iotbing.com")
        self.assertEqual(profile.package_name, "com.smartapp.popur.app")
        self.assertEqual(profile.app_version, "2.0.0")
        self.assertEqual(profile.sdk_version, "6.7.0")
        self.assertEqual(profile.device_core_version, "6.7.0")
        self.assertEqual(profile.ttid, "android")
        self.assertTrue(profile.neutral_domain)
        self.assertEqual(
            profile.ch_key,
            derive_ch_key(
                "synthetic-app-id",
                "com.smartapp.popur.app",
                normalize_certificate_sha256(certificate),
            ),
        )
        with self.assertRaisesRegex(ValueError, "unsupported App-2 region"):
            MobileAppProfile.for_popur_app2(
                client_id="synthetic-app-id",
                certificate_sha256=certificate,
                transformed_security_component="synthetic-component",
                app_secret="synthetic-secret",
                region="moon",
            )

    def test_android_device_id_derivation(self) -> None:
        expected = (
            hashlib.md5(b"BrandModel", usedforsecurity=False).hexdigest()[4:16]
            + hashlib.md5(b"r3r4", usedforsecurity=False).hexdigest()[8:24]
            + hashlib.md5(b"r1r2", usedforsecurity=False).hexdigest()[16:]
        )
        self.assertEqual(
            derive_android_device_id(
                brand="Brand",
                model="Model",
                random_id1="r1",
                random_id2="r2",
                random_id3="r3",
                random_id4="r4",
            ),
            expected,
        )
        with self.assertRaisesRegex(ValueError, "brand"):
            derive_android_device_id(
                brand="",
                model="Model",
                random_id1="r1",
                random_id2="r2",
                random_id3="r3",
                random_id4="r4",
            )

    def test_canonical_signing_matches_sdk_shape(self) -> None:
        params = {
            "v": "3.0",
            "a": "thing.m.test",
            "postData": '{"hello":"world"}',
            "time": "123",
            "ignored": "not-signed",
            "sid": "",
        }
        post_md5 = hashlib.md5(params["postData"].encode(), usedforsecurity=False).hexdigest()
        swapped = post_md5[8:16] + post_md5[:8] + post_md5[24:] + post_md5[16:24]
        canonical = canonical_sign_input(params)
        self.assertEqual(
            canonical,
            f"a=thing.m.test||postData={swapped}||time=123||v=3.0",
        )
        expected = hmac.new(
            b"key", canonical.encode(), hashlib.sha256
        ).hexdigest()
        self.assertEqual(sign_mobile_params(params, b"key"), expected)
        with self.assertRaisesRegex(ValueError, "32-character"):
            _swap_md5_blocks("short")

    def test_request_key_and_aes_gcm_roundtrip_and_errors(self) -> None:
        key = derive_request_key("request", b"master", "ecode")
        expected_key = (
            __import__("hmac")
            .new(b"request", b"master_ecode", hashlib.sha256)
            .hexdigest()[:16]
            .encode()
        )
        self.assertEqual(key, expected_key)
        self.assertEqual(
            derive_request_key("request", b"master", None),
            __import__("hmac").new(b"request", b"master", hashlib.sha256).hexdigest()[:16].encode(),
        )
        self.assertEqual(
            derive_request_key("request", b"master", ""),
            hmac.new(b"request", b"master_", hashlib.sha256).hexdigest()[:16].encode(),
        )
        self.assertEqual(len(key), 16)
        encoded = encrypt_mobile_payload("hello", key, nonce=b"\x01" * 12)
        self.assertEqual(decrypt_mobile_payload(encoded, key), b"hello")
        gz = gzip.compress(b'{"ok":true}')
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        raw = b"\x03" * 12 + AESGCM(key).encrypt(b"\x03" * 12, gz, None)
        self.assertEqual(
            decrypt_mobile_payload(base64.b64encode(raw).decode(), key, compressed=True),
            b'{"ok":true}',
        )
        with self.assertRaisesRegex(ValueError, "nonce"):
            encrypt_mobile_payload("x", key, nonce=b"short")
        with self.assertRaisesRegex(ProtocolError, "base64"):
            decrypt_mobile_payload("***", key)
        with self.assertRaisesRegex(ProtocolError, "too short"):
            decrypt_mobile_payload(base64.b64encode(b"tiny").decode(), key)
        bad = bytearray(base64.b64decode(encoded))
        bad[-1] ^= 1
        with self.assertRaisesRegex(ProtocolError, "decryption"):
            decrypt_mobile_payload(base64.b64encode(bad).decode(), key)

        broken_gzip = b"\x1f\x8bnot-a-valid-gzip-stream"
        nonce = b"\x04" * 12
        broken_blob = nonce + AESGCM(key).encrypt(nonce, broken_gzip, None)
        with self.assertRaisesRegex(ProtocolError, "gzip"):
            decrypt_mobile_payload(base64.b64encode(broken_blob).decode(), key)

        response_sign = mobile_response_signature("ciphertext", 1234, key)
        expected = hashlib.md5(
            f"result=ciphertext||t=1234||{key.decode()}".encode(), usedforsecurity=False
        ).hexdigest()
        self.assertEqual(response_sign, expected)
        with self.assertRaisesRegex(ValueError, "ASCII"):
            mobile_response_signature("ciphertext", 1234, b"\xff")

    def test_helper_validation_and_header_lookup(self) -> None:
        self.assertEqual(
            _header_value({"X-Content-Compress": "gzip"}, "x-content-compress"), "gzip"
        )
        self.assertIsNone(_header_value({"Other": "value"}, "x-content-compress"))
        with self.assertRaisesRegex(ProtocolError, "not an object"):
            _require_mapping([], "test")
        with self.assertRaisesRegex(ProtocolError, "did not contain value"):
            _require_text({}, "value", "test")
        with self.assertRaisesRegex(ProtocolError, "invalid RSA public key"):
            _rsa_encrypt_password("password", {"publicKey": "bad", "exponent": "also-bad"})


class MobileFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.profile = make_profile()
        self.server = SyntheticThingServer(self.profile)
        self.api = ThingMobileApi(
            self.profile,
            install_id="install-id",
            timeout=4,
            _post_form=self.server,
            _clock=lambda: 1234.9,
            _uuid_factory=lambda: uuid.UUID("00000000-0000-0000-0000-000000000001"),
        )
        self.account = PopurAccount(self.api)

    async def login(self) -> MobileSession:
        return await self.account.login(
            "person@example.invalid",
            "correct horse",
            country_code="1",
        )

    async def test_session_storage_round_trip_and_restore(self) -> None:
        session = MobileSession(
            sid="stored-sid",
            ecode="",
            uid="stored-uid",
            partner_identity="partner",
            domain={"mobileApiUrl": "https://api.example.test"},
            raw_user={"sid": "stored-sid"},
        )
        blob = json.loads(json.dumps(session.to_storage()))
        self.assertEqual(MobileSession.from_storage(blob), session)
        adopted = self.account.restore_session(blob)
        self.assertEqual(adopted, session)
        self.assertEqual(self.account.session, session)
        self.assertEqual(self.api.api_host, "https://api.example.test")
        self.assertEqual(self.api.install_id, "install-id")
        self.assertEqual(self.server.calls, [])
        self.assertNotIn("stored-sid", repr(adopted))

    def test_session_storage_rejects_missing_sid(self) -> None:
        with self.assertRaisesRegex(ValueError, "session id"):
            MobileSession.from_storage({"domain": {}})
        self.assertIsNone(self.account.session)

    async def test_login_exact_two_stage_flow_and_session_redaction(self) -> None:
        session = await self.login()
        self.assertEqual(
            [call["a"] for call in self.server.calls],
            [
                "smartlife.m.user.username.token.get",
                "smartlife.m.user.email.password.login",
            ],
        )
        token_post, login_post = self.server.plain_post_data
        self.assertEqual(
            token_post,
            {"countryCode": "1", "username": "person@example.invalid", "isUid": False},
        )
        self.assertEqual(login_post["countryCode"], "1")
        self.assertEqual(login_post["email"], "person@example.invalid")
        self.assertEqual(login_post["token"], "synthetic-rsa-token")
        self.assertEqual(login_post["ifencrypt"], 1)
        self.assertEqual(login_post["options"], '{"group": 1}')
        self.assertEqual(json.loads(login_post["options"]), {"group": 1})
        self.assertEqual(session.sid, "synthetic-sid")
        self.assertEqual(session.ecode, "synthetic-ecode")
        self.assertNotIn("synthetic-sid", repr(session))
        self.assertNotIn("synthetic-ecode", repr(session))
        self.assertIs(self.account.session, session)
        self.assertEqual(self.api.api_host, "example.invalid")
        self.assertEqual(self.server.calls[0]["channel"], "sdk")
        self.assertEqual(json.loads(self.server.calls[0]["bizData"]), {"customDomainSupport": "1"})

    async def test_login_adopts_regional_domain_and_can_leave_host_unchanged(self) -> None:
        self.server.domain_host = "regional.example.invalid"
        await self.login()
        self.assertEqual(self.api.api_host, "regional.example.invalid")
        self.assertEqual(self.api.endpoint, "https://regional.example.invalid/api.json")
        self.server.expected_url = "https://regional.example.invalid/api.json"
        self.assertEqual(await self.account.homes(), ({"homeId": 7, "name": "Home"},))

        api = ThingMobileApi(self.profile, install_id="i", timeout=4, _post_form=self.server)
        account = PopurAccount(api)
        self.server.calls.clear()
        self.server.plain_post_data.clear()
        self.server.domain_host = ""
        self.server.expected_url = "https://example.invalid/api.json"
        await account.login("person@example.invalid", "correct horse")
        self.assertEqual(api.api_host, "https://example.invalid")

    async def test_api_metadata_endpoint_and_unencrypted_response_guards(self) -> None:
        profile = MobileAppProfile(
            api_host="https://example.invalid/api.json/",
            client_id="client",
            app_version="2",
            sdk_version="6",
            ttid="ttid",
            ch_key="ch",
            signing_key=b"sign",
            encryption_secret=b"encrypt",
            os_system="15",
            platform="Phone",
            time_zone_id="America/Los_Angeles",
            biz_data={},
        )

        seen_requests: list[dict[str, str]] = []

        async def poster(
            url: str,
            data: Mapping[str, str],
            _headers: Mapping[str, str],
            timeout: float,
        ):
            seen_requests.append(dict(data))
            self.assertEqual(url, "https://example.invalid/api.json")
            self.assertNotIn("bizData", data)
            self.assertNotIn("cp", data)
            self.assertEqual(data["osSystem"], "15")
            self.assertEqual(data["platform"], "Phone")
            self.assertEqual(data["timeZoneId"], "America/Los_Angeles")
            return 200, {}, json.dumps({"success": True, "result": {"ok": True}}).encode()

        api = ThingMobileApi(profile, install_id="i", _post_form=poster)
        self.assertEqual(api.endpoint, "https://example.invalid/api.json")
        self.assertEqual(
            await api.request("test", "1", session_required=False, encrypted=False),
            {"ok": True},
        )
        self.assertNotIn("postData", seen_requests[-1])
        self.assertEqual(
            await api.request(
                "test",
                "1",
                {"value": 1},
                session_required=False,
                encrypted=False,
            ),
            {"ok": True},
        )
        self.assertEqual(seen_requests[-1]["postData"], '{"value":1}')
        self.assertEqual(
            await api.request("test", "1", {}, session_required=False, encrypted=False),
            {"ok": True},
        )
        self.assertEqual(seen_requests[-1]["postData"], "{}")
        with self.assertRaisesRegex(ValueError, "api_host"):
            api.set_api_host("  ")

        async def non_mapping(*_args: Any):
            return 200, {}, b"[]"

        api = ThingMobileApi(self.profile, install_id="i", _post_form=non_mapping)
        with self.assertRaisesRegex(ProtocolError, "envelope was not an object"):
            await api.request("test", "1", session_required=False, encrypted=False)

    async def test_app2_neutral_domain_and_biz_metadata(self) -> None:
        profile = MobileAppProfile(
            api_host="https://example.invalid",
            client_id="client",
            app_version="2",
            sdk_version="6",
            device_core_version="6",
            ttid="android",
            ch_key="ch",
            signing_key=b"sign",
            encryption_secret=b"encrypt",
            neutral_domain=True,
            sdk_int=36,
            brand="ExampleBrand",
        )

        async def poster(
            _url: str,
            data: Mapping[str, str],
            _headers: Mapping[str, str],
            _timeout: float,
        ):
            self.assertEqual(data["deviceCoreVersion"], "6")
            self.assertEqual(data["nd"], "1")
            self.assertEqual(
                json.loads(data["bizData"]),
                {
                    "customDomainSupport": "1",
                    "nd": "1",
                    "sdkInt": "36",
                    "brand": "ExampleBrand",
                },
            )
            return 200, {}, json.dumps({"success": True, "result": {"ok": True}}).encode()

        api = ThingMobileApi(profile, install_id="i", timeout=4, _post_form=poster)
        self.assertEqual(
            await api.request("test", "1", session_required=False, encrypted=False),
            {"ok": True},
        )

    async def test_decrypted_invalid_json_and_case_insensitive_compression_header(self) -> None:
        await self.login()
        request_id = "00000000-0000-0000-0000-000000000001"
        key = derive_request_key(request_id, self.profile.encryption_secret, "synthetic-ecode")

        async def bad_json(*_args: Any):
            encrypted = encrypt_mobile_payload("not-json", key, nonce=b"5" * 12)
            response_time = 1_700_000_001
            return (
                200,
                {},
                json.dumps(
                    {
                        "success": True,
                        "result": encrypted,
                        "t": response_time,
                        "sign": mobile_response_signature(encrypted, response_time, key),
                    }
                ).encode(),
            )

        self.api._post_form = bad_json
        with self.assertRaisesRegex(ProtocolError, "decrypted result was invalid JSON"):
            await self.account.homes()

        raw = gzip.compress(b"[]")
        nonce = b"6" * 12
        encrypted = base64.b64encode(nonce + AESGCM(key).encrypt(nonce, raw, None)).decode()

        async def compressed(*_args: Any):
            response_time = 1_700_000_002
            return (
                200,
                {"X-Content-Compress": "GZIP"},
                json.dumps(
                    {
                        "success": True,
                        "result": encrypted,
                        "t": response_time,
                        "sign": mobile_response_signature(encrypted, response_time, key),
                    }
                ).encode(),
            )

        self.api._post_form = compressed
        self.assertEqual(await self.account.homes(), ())

    async def test_encrypted_response_signature_and_shape_are_required(self) -> None:
        await self.login()
        request_id = "00000000-0000-0000-0000-000000000001"
        key = derive_request_key(request_id, self.profile.encryption_secret, "synthetic-ecode")
        encrypted = encrypt_mobile_payload("[]", key, nonce=b"7" * 12)

        async def missing_signature(*_args: Any):
            return 200, {}, json.dumps({"success": True, "result": encrypted}).encode()

        self.api._post_form = missing_signature
        with self.assertRaisesRegex(ProtocolError, "was not signed"):
            await self.account.homes()

        async def bad_signature(*_args: Any):
            return (
                200,
                {},
                json.dumps(
                    {"success": True, "result": encrypted, "t": 1_700_000_003, "sign": "00" * 16}
                ).encode(),
            )

        self.api._post_form = bad_signature
        with self.assertRaisesRegex(ProtocolError, "signature was invalid"):
            await self.account.homes()

        async def non_string_result(*_args: Any):
            return 200, {}, json.dumps({"success": True, "result": []}).encode()

        self.api._post_form = non_string_result
        with self.assertRaisesRegex(ProtocolError, "result was not a string"):
            await self.account.homes()

    async def test_authenticated_home_device_and_key_calls_use_encrypted_transport(self) -> None:
        await self.login()
        self.assertEqual(await self.account.homes(), ({"homeId": 7, "name": "Home"},))
        self.assertNotIn("postData", self.server.calls[-1])
        self.assertEqual((await self.account.home_detail(7))["homeId"], 7)
        self.assertNotIn("gid", self.server.calls[-1])
        self.assertEqual(self.server.plain_post_data[-1]["gid"], 7)
        devices = await self.account.home_devices(7)
        self.assertNotIn("gid", self.server.calls[-1])
        self.assertEqual(self.server.plain_post_data[-1]["gid"], 7)
        self.assertEqual(devices[0].device_id, "s7-device")
        self.assertNotIn(self.server.local_key, repr(devices[0]))
        detail = await self.account.device_detail("s7-device", home_id=7)
        self.assertEqual(self.server.calls[-1]["gid"], "7")
        self.assertEqual(detail.product_id, self.server.product_id)
        dps = await self.account.device_dps("s7-device", home_id=7)
        self.assertEqual(set(dps), {1, 12, 101, 102, 109, 146, 150})
        snapshot = await self.account.device_snapshot("s7-device", home_id=7)
        self.assertEqual(snapshot.automatic_clean_count, 4)
        self.assertEqual(snapshot.clean_count_after_full, 2)
        self.assertEqual(snapshot.fault_free_time, 7)
        self.assertIsNotNone(snapshot.run_mode)
        self.assertIsNotNone(snapshot.system_settings)
        self.assertEqual(
            await self.account.local_keys("s7-device"),
            (("s7-device", self.server.local_key),),
        )
        authenticated = self.server.calls[2:]
        self.assertTrue(authenticated)
        self.assertTrue(all(call["et"] == "3" for call in authenticated))
        self.assertTrue(all(call["sid"] == "synthetic-sid" for call in authenticated))

    async def test_bootstrap_prefers_detail_key_and_falls_back_to_key_api(self) -> None:
        await self.login()
        discovered = DiscoveredS7("192.0.2.50", "s7-device", self.server.product_id, "3.5")
        fallback = await self.account.bootstrap_local_config(discovered)
        self.assertEqual(fallback.local_key, self.server.local_key)
        self.assertEqual(fallback.host, "192.0.2.50")
        self.assertEqual(fallback.protocol_version, "3.5")
        self.assertEqual(self.server.calls[-1]["a"], "smartlife.m.device.key.get")

        self.server.local_key_in_detail = True
        before = len(self.server.calls)
        direct = await self.account.bootstrap_local_config(discovered)
        self.assertEqual(direct.local_key, self.server.local_key)
        self.assertEqual(len(self.server.calls), before + 1)
        self.assertEqual(self.server.calls[-1]["a"], "smartlife.m.device.get")

    async def test_bootstrap_rejects_wrong_product_and_missing_key(self) -> None:
        await self.login()
        discovered = DiscoveredS7("192.0.2.50", "s7-device", min(S7_PRODUCT_IDS), "3.5")
        self.server.product_id = "other-product"
        with self.assertRaisesRegex(AccountDeviceNotFound, "product family"):
            await self.account.bootstrap_local_config(discovered)

        self.server.product_id = min(S7_PRODUCT_IDS)
        self.server.local_key = ""
        with self.assertRaisesRegex(AccountDeviceNotFound, "local key"):
            await self.account.bootstrap_local_config(discovered)

    async def test_error_classification_and_malformed_responses(self) -> None:
        self.server.error_by_action["smartlife.m.user.email.password.login"] = (
            "USER_PASSWD_WRONG",
            "wrong password",
        )
        with self.assertRaises(MobileAuthenticationError):
            await self.login()

        self.server.error_by_action["smartlife.m.user.email.password.login"] = (
            "SOME_OTHER_ERROR",
            "other",
        )
        with self.assertRaises(MobileApiError):
            await self.login()

        self.server.error_by_action.clear()
        self.server.http_status_by_action["smartlife.m.user.username.token.get"] = 503
        with self.assertRaisesRegex(TransportError, "HTTP 503"):
            await self.login()
        self.server.http_status_by_action.clear()
        self.server.invalid_json_action = "smartlife.m.user.username.token.get"
        with self.assertRaisesRegex(ProtocolError, "invalid JSON"):
            await self.login()

    async def test_validation_no_session_and_response_compression(self) -> None:
        # checkApiParams: a session-required request with no session fails
        # locally as USER_SESSION_LOSS — no HTTP call leaves the client.
        with self.assertRaisesRegex(MobileApiError, "USER_SESSION_LOSS"):
            await self.api.request("m.life.home.space.list", "1.0", {})
        for email, password, message in (("", "x", "email"), ("x", "", "password")):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                await self.account.login(email, password)
        with self.assertRaisesRegex(ValueError, "timeout"):
            ThingMobileApi(self.profile, timeout=0)

        await self.login()
        self.server.compress_action = "m.life.home.space.list"
        self.assertEqual(await self.account.homes(), ({"homeId": 7, "name": "Home"},))

    async def test_home_and_local_key_response_validation_edges(self) -> None:
        await self.login()
        self.server.home_list_result = None
        self.assertEqual(await self.account.homes(), ())
        self.server.home_list_result = {"bad": "shape"}
        with self.assertRaisesRegex(ProtocolError, "home list"):
            await self.account.homes()

        self.server.key_result = None
        self.server.local_key = ""
        with patch.object(self.api, "request", AsyncMock(return_value=None)):
            self.assertEqual(await self.account.local_keys("s7-device"), ())
        self.server.key_result = {"bad": "shape"}
        with self.assertRaisesRegex(ProtocolError, "local-key response"):
            await self.account.local_keys("s7-device")
        self.server.key_result = [{"devId": "node", "localKey": "key"}]
        self.assertEqual(
            await self.account.local_keys("s7-device", node_ids=["node"]),
            (("node", "key"),),
        )
        self.assertEqual(json.loads(self.server.plain_post_data[-1]["nodeIds"]), ["node"])

    async def test_device_list_validation_and_bootstrap_skips_nonmatching_key_records(self) -> None:
        await self.login()
        with patch.object(self.api, "request", AsyncMock(return_value=None)):
            self.assertEqual(await self.account.home_devices(7), ())
        with (
            patch.object(self.api, "request", AsyncMock(return_value={"bad": "shape"})),
            self.assertRaisesRegex(ProtocolError, "home device list"),
        ):
            await self.account.home_devices(7)

        self.server.local_key = ""
        self.server.key_result = [
            {"devId": "some-other-device", "localKey": "wrong-key"},
            {"devId": "s7-device", "localKey": "right-key"},
        ]
        discovered = DiscoveredS7("192.0.2.50", "s7-device", self.server.product_id, "3.5")
        config = await self.account.bootstrap_local_config(discovered)
        self.assertEqual(config.local_key, "right-key")

    async def test_one_shot_bootstrap_convenience(self) -> None:
        discovered = DiscoveredS7("192.0.2.50", "s7-device", min(S7_PRODUCT_IDS), "3.5")
        config = await bootstrap_discovered_s7(
            discovered,
            email="person@example.invalid",
            password="correct horse",
            profile=self.profile,
            install_id="install-id",
            timeout=4,
            _post_form=self.server,
        )
        self.assertEqual(config.device_id, "s7-device")
        self.assertEqual(config.local_key, self.server.local_key)

    async def test_popur_app2_one_shot_bootstrap_uses_bundled_profile(self) -> None:
        discovered = DiscoveredS7("192.0.2.50", "s7-device", min(S7_PRODUCT_IDS), "3.5")
        bundled = MobileAppProfile.bundled_popur_app2()
        server = SyntheticThingServer(bundled)
        server.product_id = discovered.product_id
        server.domain_host = ""
        server.expected_url = "https://a1-us.iotbing.com/api.json"
        config = await bootstrap_discovered_s7_popur_app2(
            discovered,
            email="person@example.invalid",
            password="correct horse",
            install_id="install-id",
            timeout=4,
            _post_form=server,
        )
        self.assertEqual(config.device_id, discovered.device_id)
        self.assertEqual(config.local_key, server.local_key)

    async def test_time_validate_failed_retries_once_with_new_request_id(self) -> None:
        await self.login()
        action = "m.life.home.space.list"
        self.server.error_once_by_action[action] = ("TIME_VALIDATE_FAILED", "clock skew")
        counter = iter(range(1_000))
        self.api._uuid_factory = lambda: uuid.UUID(int=next(counter))

        result = await self.api.request(action, "1.0")
        self.assertEqual(result, self.server.home_list_result)
        calls = [c for c in self.server.calls if c["a"] == action]
        self.assertEqual(len(calls), 2)
        # retryTime 1→0: exactly one re-request, fresh requestId.
        self.assertNotEqual(calls[0]["requestId"], calls[1]["requestId"])
        # TimeStampManager.updateTimeStamp(t) — the offset is applied to `time`.
        self.assertEqual(
            int(calls[1]["time"]),
            int(1234.9 + (1_700_000_500 - 1234.9)),
        )

    async def test_time_validate_failed_second_failure_fails(self) -> None:
        await self.login()

        async def always_fails(url, data, headers, timeout):
            return (
                200,
                {},
                json.dumps(
                    {
                        "success": False,
                        "errorCode": "TIME_VALIDATE_FAILED",
                        "errorMsg": "skew",
                        "t": 1_700_000_500,
                    }
                ).encode(),
            )

        api = ThingMobileApi(
            self.profile,
            install_id="install-id",
            timeout=4,
            _post_form=always_fails,
            _clock=lambda: 1234.9,
            _uuid_factory=lambda: uuid.UUID("00000000-0000-0000-0000-000000000001"),
        )
        api.session = self.api.session
        with self.assertRaisesRegex(MobileApiError, "TIME_VALIDATE_FAILED"):
            await api.request("m.life.home.space.list", "1.0")

    async def test_session_invalid_broadcast_and_105_rewrite(self) -> None:
        await self.login()
        seen: list[MobileApiError] = []
        self.api.on_session_invalid = seen.append
        action = "m.life.home.space.list"
        self.server.error_by_action[action] = ("USER_SESSION_INVALID", "gone")

        with self.assertRaises(MobileApiError) as ctx:
            await self.api.request(action, "1.0")
        self.assertEqual(ctx.exception.code, "105")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].code, "USER_SESSION_INVALID")

    async def test_region_scoped_request_uses_region_host(self) -> None:
        await self.login()
        urls: list[str] = []

        async def recording_post(url, data, headers, timeout):
            urls.append(url)
            return await self.server(url, data, headers, timeout)

        api = ThingMobileApi(
            self.profile,
            install_id="install-id",
            timeout=4,
            _post_form=recording_post,
            _clock=lambda: 1234.9,
            _uuid_factory=lambda: uuid.UUID("00000000-0000-0000-0000-000000000001"),
        )
        api.session = self.api.session
        self.server.expected_url = "https://a1.tuyaeu.com/api.json"
        await api.request("m.life.home.space.list", "1.0", region="eu")
        self.assertEqual(urls[-1], "https://a1.tuyaeu.com/api.json")

    async def test_batch_invoke_signs_sub_requests(self) -> None:
        await self.login()
        beans_out = await self.account.batch_invoke(
            (
                ("m.life.my.group.device.list", "2.2", {"gid": 7}),
                ("thing.m.my.shared.device.list", "3.2", {}),
            ),
            gid=7,
        )
        call = next(c for c in self.server.calls if c["a"] == "smartlife.m.api.batch.invoke")
        self.assertEqual(call["gid"], "7")
        post = self.server.plain_post_data[-1]
        self.assertEqual(post["gid"], 7)
        apis = post["apis"]
        self.assertEqual(
            [b["a"] for b in apis],
            ["m.life.my.group.device.list", "smartlife.m.my.shared.device.list"],
        )
        for bean in apis:
            self.assertEqual(bean["et"], "3")
            self.assertEqual(bean["v"], apis[0]["v"] if bean is apis[0] else "3.2")
            self.assertTrue(bean["requestId"] and bean["sign"] and bean["params"])
        self.assertEqual(len(beans_out), 2)
        self.assertEqual(beans_out[0]["a"], "m.life.my.group.device.list")

    async def test_fetch_home_batch_order_and_local_list(self) -> None:
        await self.login()
        subscribed: list[str] = []
        merged = await self.account.fetch_home(
            7, mqtt_subscribe=lambda topic: subscribed.append(topic)
        )
        self.assertEqual(subscribed, ["m/ug/7"])
        actions = [c["a"] for c in self.server.calls]
        self.assertIn("smartlife.m.api.batch.invoke", actions)
        self.assertIn("m.life.app.smart.local.device.list", actions)
        post = next(p for p in self.server.plain_post_data if "apis" in p)
        apis = [b["a"] for b in post["apis"]]
        self.assertEqual(
            apis,
            [
                "m.life.my.group.device.sort.list",
                "m.life.my.group.device.list",
                "m.life.my.group.mesh.list",
                "m.life.my.group.device.group.list",
                "m.life.location.get",
                "m.life.device.ref.info.my.list",
                "smartlife.m.my.shared.device.list",
                "smartlife.m.my.shared.device.group.list",
            ],
        )
        # ApiResponeBean.getApi un-rewrites smartlife→thing for the merged keys.
        self.assertIn("thing.m.my.shared.device.list", merged)
        self.assertIn("m.life.my.group.device.list", merged)
        self.assertIn("m.life.app.smart.local.device.list", merged)


class StdlibPosterTests(unittest.TestCase):
    def test_http_error_is_returned_and_transport_error_is_normalized(self) -> None:
        error = urllib.error.HTTPError(
            "https://example.invalid", 403, "no", {"X-Test": "yes"}, None
        )
        error.read = lambda: b"denied"  # type: ignore[method-assign]
        with patch("pypopur.mobile.urllib.request.urlopen", side_effect=error):
            status, headers, body = _stdlib_post_form_sync(
                "https://example.invalid", {"a": "b"}, {}, 1
            )
        self.assertEqual(status, 403)
        self.assertEqual(headers["X-Test"], "yes")
        self.assertEqual(body, b"denied")

        with (
            patch("pypopur.mobile.urllib.request.urlopen", side_effect=OSError("offline")),
            self.assertRaisesRegex(TransportError, "offline"),
        ):
            _stdlib_post_form_sync("https://example.invalid", {"a": "b"}, {}, 1)

    def test_success_path(self) -> None:
        response = MagicMock()
        response.status = 200
        response.headers.items.return_value = [("X-Test", "yes")]
        response.read.return_value = b"ok"
        response.__enter__.return_value = response
        with patch("pypopur.mobile.urllib.request.urlopen", return_value=response):
            status, headers, body = _stdlib_post_form_sync(
                "https://example.invalid", {"a": "b"}, {}, 1
            )
        self.assertEqual((status, headers["X-Test"], body), (200, "yes", b"ok"))


class AsyncStdlibPosterTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_wrapper(self) -> None:
        with patch(
            "pypopur.mobile._stdlib_post_form_sync", return_value=(200, {"X": "y"}, b"ok")
        ) as sync:
            result = await _stdlib_post_form("https://example.invalid", {"a": "b"}, {}, 2)
        self.assertEqual(result, (200, {"X": "y"}, b"ok"))
        sync.assert_called_once_with("https://example.invalid", {"a": "b"}, {}, 2)


if __name__ == "__main__":
    unittest.main()
