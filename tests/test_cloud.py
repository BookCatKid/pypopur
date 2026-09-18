"""Tests for pypopur.cloud — Business/DeviceApi wiring over a profile."""

import asyncio
import unittest
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pypopur.cloud import (
    AtopCloudBackend,
    CloudTransport,
    build_device_api,
)
from pypopur.exceptions import ProtocolError


@dataclass
class _Profile:
    api_host: str = "https://a1.api.example.com"
    client_id: str = "clientid0123456789ab"
    app_version: str = "2.0.0"
    sdk_version: str = "6.7.0"
    ttid: str = "android"
    ch_key: str = "fa44caaa"
    signing_key: bytes = b"pkg_cert_blob_secret"
    encryption_secret: bytes = b"pkg_cert_blob_secret"
    package_name: str = "com.example"
    device_core_version: str | None = "6.7.0"
    lang: str = "en_US"
    os_name: str = "Android"
    channel: str = "sdk"
    os_system: str | None = "14"
    platform: str | None = "Pixel"
    time_zone_id: str | None = "America/Los_Angeles"
    neutral_domain: bool = False
    sdk_int: int | str | None = 34
    brand: str | None = "Pixel"
    biz_data: Mapping[str, Any] = field(default_factory=lambda: {"customDomainSupport": "1"})
    extra_params: Mapping[str, str] = field(default_factory=dict)


@dataclass
class _Session:
    sid: str = "sid123"
    ecode: str | None = "ec"
    uid: str | None = "u1"


def _api(calls: list, response: Mapping[str, Any]):
    def http_post(url, headers, body):
        calls.append((url, dict(headers), dict(body)))
        return 200, __import__("json").dumps(dict(response)), []

    return build_device_api(_Profile(), _Session(), device_id="inst0", http_post=http_post)


def _decrypt_post_data(body: Mapping[str, str]) -> dict:
    """Reverse the et=3 postData envelope: b64(GCM(key, json)) where
    key = getEncryptoKey(requestId, ecode)."""

    import base64
    import hashlib
    import hmac
    import json

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    request_id = body["requestId"]
    key = (
        hmac.new(
            request_id.encode(),
            b"pkg_cert_blob_secret_ec",
            hashlib.sha256,
        )
        .hexdigest()[:16]
        .encode("ascii")
    )
    blob = base64.b64decode(body["postData"])
    return json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], None))


class TestBuildBusiness(unittest.TestCase):
    def test_publish_dps_wire(self):
        calls: list = []
        api = _api(calls, {"success": True, "result": {}})
        res = api.publish_dps("dev1", "gw1", '{"1":true}')
        self.assertTrue(res.succeeded)
        url, _headers, body = calls[0]
        self.assertTrue(url.startswith("https://a1.api.example.com"))
        # thing.* → smartlife.* rewrite on the wire
        self.assertEqual(body["a"], "smartlife.m.device.dp.publish")
        self.assertEqual(body["sid"], "sid123")
        post = _decrypt_post_data(body)
        self.assertEqual(list(post.keys()), ["devId", "gwId", "dps"])
        self.assertEqual(post["dps"], '{"1":true}')

    def test_get_dps_v1_arg_order(self):
        calls: list = []
        api = _api(calls, {"success": True, "result": {"dps": '{"1":true}'}})
        res = api.get_dps_v1("gw1", "dev1")
        self.assertTrue(res.succeeded)
        post = _decrypt_post_data(calls[0][2])
        self.assertEqual(list(post.keys()), ["gwId", "devId"])
        self.assertEqual((post["gwId"], post["devId"]), ("gw1", "dev1"))


class TestAtopCloudBackend(unittest.TestCase):
    def test_read_dps_v1_string_payload(self):
        calls: list = []
        api = _api(calls, {"success": True, "result": {"dps": '{"101":5,"1":true}'}})
        backend = AtopCloudBackend(api, dev_id="dev1", gw_id="gw1")
        out = asyncio.run(backend.read_dps())
        self.assertEqual(out, {101: 5, 1: True})

    def test_read_dps_filter(self):
        calls: list = []
        api = _api(calls, {"success": True, "result": {"dps": '{"101":5,"1":true}'}})
        backend = AtopCloudBackend(api, dev_id="dev1")
        out = asyncio.run(backend.read_dps({101}))
        self.assertEqual(out, {101: 5})

    def test_read_dps_failure_raises(self):
        calls: list = []
        api = _api(calls, {"success": False, "errorCode": "X", "errorMsg": "bad"})
        backend = AtopCloudBackend(api, dev_id="dev1")
        with self.assertRaises(ProtocolError):
            asyncio.run(backend.read_dps())

    def test_write_dps_publishes(self):
        calls: list = []
        api = _api(calls, {"success": True, "result": {}})
        backend = AtopCloudBackend(api, dev_id="dev1", gw_id="gw1")
        asyncio.run(backend.write_dps({1: True}))
        post = _decrypt_post_data(calls[0][2])
        self.assertEqual(post["dps"], '{"1":true}')

    def test_write_dps_failure_raises(self):
        calls: list = []
        api = _api(calls, {"success": False, "errorCode": "X", "errorMsg": "bad"})
        backend = AtopCloudBackend(api, dev_id="dev1")
        with self.assertRaises(ProtocolError):
            asyncio.run(backend.write_dps({1: True}))

    def test_cloud_transport_delegates(self):
        calls: list = []
        api = _api(calls, {"success": True, "result": {"dps": '{"1":true}'}})
        transport = CloudTransport(AtopCloudBackend(api, dev_id="dev1"))
        out = asyncio.run(transport.read_dps())
        self.assertEqual(out, {1: True})


if __name__ == "__main__":
    unittest.main()
