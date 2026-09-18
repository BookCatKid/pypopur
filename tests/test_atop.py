"""Parity tests for ``pypopur.sdk.security`` + ``pypopur.sdk.atop``."""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json

from pypopur.sdk.atop import (
    Business,
    DeviceApi,
    NetworkStatics,
    ThingApiParams,
)
from pypopur.sdk.crypto import gcm_decrypt_appended_nonce, gcm_encrypt_appended_nonce
from pypopur.sdk.security import (
    ThingApiSignManager,
    ThingNetworkSecurity,
    default_signer,
    post_data_md5_hex,
    swap_sign_string,
)
from pypopur.sdk.timestamp import TimeStampManager

GLOBAL_S = "pkg_cert_blob_secret"  # stands in for APP2_NATIVE_MASTER contents
APP_SECRET = "appsecret0123456789"


def _net(**kw) -> NetworkStatics:
    args = {
        "app_id": "clientid0123456789ab",
        "app_secret": APP_SECRET,
        "app_version": "2.0.0",
        "sdk_version": "6.7.0",
        "device_core_version": "6.7.0",
        "ttid": "android",
        "lang": "en",
        "os_system": "14",
        "platform": "Pixel",
        "time_zone_id": "America/Los_Angeles",
        "ch_key": "fa44caaa",
        "device_id": "devphone0123456789",
    }
    args.update(kw)
    return NetworkStatics(**args)


def _sec() -> ThingNetworkSecurity:
    return ThingNetworkSecurity(GLOBAL_S)


class TestSecurity:
    def test_swap_sign_string(self):
        h = "0123456789abcdef0123456789abcdef"
        # h[8:16] + h[0:8] + h[24:32] + h[16:24]
        assert swap_sign_string(h) == "89abcdef" + "01234567" + "89abcdef" + "01234567"

    def test_post_data_md5_hex(self):
        raw = '{"devId":"x"}'
        h = hashlib.md5(raw.encode()).hexdigest()
        assert post_data_md5_hex(raw) == h[8:16] + h[0:8] + h[24:32] + h[16:24]

    def test_generate_signature_filters_and_swaps(self):
        signed: list[str] = []
        mgr = ThingApiSignManager(
            APP_SECRET, signer=lambda canon, secret: signed.append(canon) or "SIGN"
        )
        params = {"a": "x", "notAllowed": "1", "postData": "P", "empty": "", "v": "1.0"}
        assert mgr.generate_signature_sdk(params) == "SIGN"
        # sorted whitelist order: a, postData(swapped), v — empty dropped,
        # notAllowed dropped
        canon = signed[0]
        assert canon.startswith("a=x||postData=")
        assert canon.endswith("||v=1.0")
        # postData swapped in place in the caller's map
        assert params["postData"] == post_data_md5_hex("P")

    def test_default_signer_is_hmac_sha256(self):
        # doCommandNative cmd 1 = hmac_sha256(key, canonical) — verified by
        # native emulation after a real cmd-0 global derivation.
        canon = "a=x||v=1.0"
        assert (
            default_signer(canon, APP_SECRET)
            == hmac.new(APP_SECRET.encode(), canon.encode(), hashlib.sha256).hexdigest()
        )

    def test_request_key_no_whitelist(self):
        params = {"b": "2", "a": "1"}
        assert (
            ThingApiSignManager.get_request_key_by_sorted(params)
            == hashlib.md5(b"a=1||b=2").hexdigest()
        )

    def test_native_primitives(self):
        sec = _sec()
        key = sec.get_encrypto_key("rid", "ec")
        assert (
            key
            == hmac.new(b"rid", f"{GLOBAL_S}_ec".encode(), hashlib.sha256).hexdigest()[:16].encode()
        )
        assert len(key) == 16
        # ecode=None (Java null) → data is GLOBAL_S alone, no underscore
        # (cbz x21 @0x14d18 → empty tmp → GLOBAL_S fallback); a non-null
        # empty ecode → GLOBAL_S + "_"
        key2 = sec.get_encrypto_key("rid", None)
        assert key2 == hmac.new(b"rid", GLOBAL_S.encode(), hashlib.sha256).hexdigest()[:16].encode()
        key3 = sec.get_encrypto_key("rid", "")
        assert (
            key3
            == hmac.new(b"rid", f"{GLOBAL_S}_".encode(), hashlib.sha256).hexdigest()[:16].encode()
        )
        assert (
            sec.compute_digest("a0", "a1") == hashlib.md5(f"a1||a0_{GLOBAL_S}".encode()).hexdigest()
        )
        # gen_key nibble-permutes b through itself
        assert (
            sec.gen_key("k", "0123456789abcdef", "p")
            == hmac.new(
                b"k", f"p_{GLOBAL_S}_0123456789123456".encode(), hashlib.sha256
            ).hexdigest()[:16]
        )


class TestApiParams:
    def test_thing_api_rewritten_to_smartlife(self):
        p = ThingApiParams("thing.m.device.dp.publish", "1.0", _net())
        assert p.api_name == "smartlife.m.device.dp.publish"
        assert p.get_url_params()["a"] == "smartlife.m.device.dp.publish"

    def test_non_thing_name_unchanged(self):
        p = ThingApiParams("s.m.dev.dp.get", "2.0", _net())
        assert p.api_name == "s.m.dev.dp.get"

    def test_init_url_params(self):
        p = ThingApiParams("a.b.c", "1.0", _net())
        up = p.url_get_params
        assert up["clientId"] == "clientid0123456789ab"
        assert up["os"] == "Android"
        assert up["appVersion"] == "2.0.0"
        assert up["sdkVersion"] == "6.7.0"
        assert up["deviceCoreVersion"] == "6.7.0"
        assert up["ttid"] == "android"
        assert up["chKey"] == "fa44caaa"
        assert up["et"] == "3"
        assert up["cp"] == "gzip"
        assert up["deviceId"] == "devphone0123456789"
        biz = json.loads(up["bizData"])
        assert biz["customDomainSupport"] == "1"
        assert "sdkInt" in biz

    def test_request_body_merges_and_signs(self):
        signers: list[dict] = []

        class Rec:
            def generate_signature_sdk(self, m):
                signers.append(dict(m))
                return "SIGNVAL"

        p = ThingApiParams("a.b", "1.0", _net(), signer=Rec())
        p.put_post_data("devId", "d1")
        p.sign_with_encrypted_body = False
        p.session = "sid123"
        body = p.get_request_body()
        assert body["sign"] == "SIGNVAL"
        assert body["sid"] == "sid123"
        assert body["postData"] == '{"devId":"d1"}'
        assert body["a"] == "a.b"
        assert body["deviceId"] == "devphone0123456789"
        # the signer receives the raw serialized postData (the real signer
        # swaps it to the MD5 reorder internally)
        signed_map = signers[0]
        assert signed_map["postData"] == '{"devId":"d1"}'
        assert signed_map["sid"] == "sid123"

    def test_encrypted_post_data_et3(self):
        p = ThingApiParams("a.b", "1.0", _net(), security=_sec())
        p.url_get_params["requestId"] = "rid-fixed"
        p.put_post_data("devId", "d1")
        p.session_require = False
        enc = p.get_encrypt_post_data_string()
        key = _sec().get_encrypto_key("rid-fixed", None)
        blob = base64.b64decode(enc)
        plain = gcm_decrypt_appended_nonce(key, blob, None).decode()
        assert json.loads(plain) == {"devId": "d1"}

    def test_encrypted_post_data_ecb(self):
        from pypopur.sdk.crypto import AESUtil

        p = ThingApiParams("a.b", "1.0", _net(), security=_sec())
        p.url_get_params["requestId"] = "rid-fixed"
        p.et_version = "0.0.2"
        p.put_post_data("x", 1)
        p.session_require = False
        enc = p.get_encrypt_post_data_string()
        key = _sec().get_encrypto_key("rid-fixed", None)
        assert AESUtil(key).decrypt_with_base64(enc) == '{"x":1}'

    def test_request_url_trailing_slash(self):
        p = ThingApiParams("a.b", "1.0", _net())
        assert p.get_request_url() == "https://a1-us.iotbing.com/"

    def test_region_host(self):
        p = ThingApiParams("a.b", "1.0", _net(), region="eu")
        assert p.server_host_url == "https://a1.tuyaeu.com"


class _User:
    def __init__(self, sid=None, ecode=None):
        self._sid, self._ecode = sid, ecode

    def get_sid(self):
        return self._sid

    def get_ecode(self):
        return self._ecode


def _business(http_post=None, **kw):
    net = _net(user=_User(sid="sid-1", ecode="ec-1"), **kw)
    ts = TimeStampManager()
    return Business(
        net,
        security=_sec(),
        http_post=http_post,
        timestamp=ts,
        signer=ThingApiSignManager(net.app_secret, signer=lambda c, s: "S"),
    ), ts


def _ok(body, headers=None):
    return lambda url, h, form: (200, body, headers or [])


class TestBusiness:
    def test_plain_success(self):
        biz, _ = _business(_ok('{"success":true,"result":{"a":1},"t":1}'))
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.succeeded and res.data == {"a": 1}

    def test_api_failure(self):
        biz, _ = _business(_ok('{"success":false,"errorCode":"X","errorMsg":"m"}'))
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert not res.succeeded and res.response.error_code == "X"

    def test_http_error_101(self):
        biz, _ = _business(lambda u, h, f: (500, "err", []))
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.response.error_code == "101"

    def test_timeout_108(self):
        def boom(u, h, f):
            raise TimeoutError()

        biz, _ = _business(boom)
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.response.error_code == "108"

    def test_json_error_102(self):
        biz, _ = _business(_ok("not-json"))
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.response.error_code == "102"

    def test_missing_session(self):
        biz, _ = _business(
            _ok("{}"),
        )
        biz.net.user = _User(sid=None)
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.response.error_code == "USER_SESSION_LOSS"

    def test_time_validate_retries_once(self):
        calls = []

        def post(u, h, f):
            calls.append(f)
            if len(calls) == 1:
                return 200, '{"success":false,"errorCode":"TIME_VALIDATE_FAILED","t":999}', []
            return 200, '{"success":true,"result":1,"t":2}', []

        biz, ts = _business(post)
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.succeeded and len(calls) == 2
        # server timestamp adopted: t=999
        assert ts.get_current_timestamp() >= 999

    def test_time_validate_second_still_fails(self):
        def post(u, h, f):
            return 200, '{"success":false,"errorCode":"TIME_VALIDATE_FAILED","t":9}', []

        biz, _ = _business(post)
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        # retry-mode failure → onFailure with the raw code (no third attempt)
        assert not res.succeeded
        assert res.response.error_code == "TIME_VALIDATE_FAILED"

    def test_session_invalid_remapped_105(self):
        seen = []
        biz, _ = _business(_ok('{"success":false,"errorCode":"USER_SESSION_INVALID"}'))
        biz.on_session_invalid = seen.append
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.response.error_code == "105"
        assert len(seen) == 1

    def test_encrypted_response_roundtrip(self):
        net = _net(user=_User(sid="sid-1", ecode="ec-1"))
        sec = _sec()
        biz = Business(
            net,
            security=sec,
            timestamp=TimeStampManager(),
            signer=ThingApiSignManager(net.app_secret, signer=lambda c, s: "S"),
        )
        params = biz.new_api_params("a.b", "1.0")
        params.url_get_params["requestId"] = "rid-1"
        key = sec.get_encrypto_key("rid-1", "ec-1")
        inner = '{"success":true,"result":{"ok":1},"t":5}'
        blob = gcm_encrypt_appended_nonce(key, inner.encode(), None, nonce=b"N" * 12)
        result_b64 = base64.b64encode(blob).decode()
        sign = hashlib.md5(f"result={result_b64}||t=7||{key.decode()}".encode()).hexdigest()
        outer = json.dumps({"result": result_b64, "sign": sign.upper(), "t": 7})
        biz.http_post = _ok(outer)
        res = biz.request(params)
        assert res.succeeded and res.data == {"ok": 1}

    def test_encrypted_response_gzip(self):
        net = _net(user=_User(sid="sid-1", ecode="ec-1"))
        sec = _sec()
        biz = Business(
            net,
            security=sec,
            timestamp=TimeStampManager(),
            signer=ThingApiSignManager(net.app_secret, signer=lambda c, s: "S"),
        )
        params = biz.new_api_params("a.b", "1.0")
        params.url_get_params["requestId"] = "rid-1"
        key = sec.get_encrypto_key("rid-1", "ec-1")
        inner = gzip.compress(b'{"success":true,"result":42,"t":5}')
        blob = gcm_encrypt_appended_nonce(key, inner, None, nonce=b"N" * 12)
        result_b64 = base64.b64encode(blob).decode()
        sign = hashlib.md5(f"result={result_b64}||t=7||{key.decode()}".encode()).hexdigest()
        outer = json.dumps({"result": result_b64, "sign": sign, "t": 7})
        biz.http_post = _ok(outer, [("x-content-compress", "gzip")])
        res = biz.request(params)
        assert res.succeeded and res.data == 42

    def test_bad_response_sign_fails_102(self):
        biz, _ = _business(_ok('{"result":"x","sign":"bad","t":1}'))
        res = biz.request(biz.new_api_params("a.b", "1.0"))
        assert res.response.error_code == "102"


class TestDeviceApi:
    def test_publish_dps_post_data(self):
        captured = []
        biz, _ = _business(_ok('{"success":true,"result":true,"t":1}'))
        api = DeviceApi(biz)

        orig = biz.request

        def spy(params):
            captured.append(params)
            return orig(params)

        biz.request = spy
        api.publish_dps("dev1", "gw1", '{"1":true}')
        post = captured[0].post_data
        assert list(post) == ["devId", "gwId", "dps"]
        assert post == {"devId": "dev1", "gwId": "gw1", "dps": '{"1":true}'}
        assert captured[0].api_name == "smartlife.m.device.dp.publish"
        assert captured[0].api_version == "1.0"

    def test_nb_publish(self):
        captured = []
        biz, _ = _business(_ok('{"success":true,"result":true,"t":1}'))
        api = DeviceApi(biz)
        orig = biz.request
        biz.request = lambda p: (captured.append(p), orig(p))[1]
        api.publish_dps_nb("dev1", '{"1":0}')
        assert captured[0].post_data == {"devId": "dev1", "dps": '{"1":0}'}
        assert captured[0].api_name == "smartlife.m.nb.device.dp.publish"

    def test_dp_bean_order_and_callback(self):
        from pypopur.sdk.lan_control import DpPublish, ResultCallback

        captured = []
        biz, _ = _business(_ok('{"success":true,"result":true,"t":1}'))
        api = DeviceApi(biz)
        orig = biz.request
        biz.request = lambda p: (captured.append(p), orig(p))[1]

        events = []

        class CB(ResultCallback):
            def on_success(self):
                events.append("ok")

            def on_error(self, code, msg):
                events.append(("err", code, msg))

        api.atop_publish(DpPublish(gw_id="g", dev_id="d", dps='{"1":1}', pcc="x"), CB())
        assert list(captured[0].post_data) == ["gwId", "devId", "dps", "pcc"]
        assert events == ["ok"]

    def test_atop_publish_failure_callback(self):
        from pypopur.sdk.lan_control import DpPublish, ResultCallback

        biz, _ = _business(_ok('{"success":false,"errorCode":"E1","errorMsg":"m"}'))
        api = DeviceApi(biz)
        events = []

        class CB(ResultCallback):
            def on_error(self, code, msg):
                events.append((code, msg))

        api.atop_publish(DpPublish(gw_id="g", dev_id="d", dps="{}"), CB())
        assert events == [("E1", "m")]
