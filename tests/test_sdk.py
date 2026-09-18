"""Parity tests for pypopur.sdk — each assertion encodes behavior verified
against the Popur S7 2.0.0 smali (see docs/parity/)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import unittest
import zlib

from pypopur.sdk.crypto import AESUtil, crc32, md5_upper
from pypopur.sdk.dedup import ThingMessageCache
from pypopur.sdk.hexutil import (
    bytes_to_hex_string,
    check_hex_string,
    hex_string_to_bytes,
    int_to_bytes2,
)
from pypopur.sdk.mqtt_framing import (
    MqttFrameError,
    build_mqtt_publish,
    build_payload_1_1,
    build_payload_2_0,
    build_payload_2_1,
    build_payload_2_2,
    build_payload_2_3,
    dispatch_inbound_message,
    parse_inbound_1_1,
    parse_inbound_2_1,
    parse_inbound_2_2,
    parse_inbound_2_3,
)
from pypopur.sdk.mqtt_sign import (
    crc_s_o_data,
    crc_s_o_data_key,
    sign_data_pv,
    sign_json,
    sign_publish_bean,
)
from pypopur.sdk.sando import SandO, SandRMap
from pypopur.sdk.schema import (
    DATA_TYPE_OBJ,
    DATA_TYPE_RAW,
    MODE_RO,
    MODE_RW,
    SchemaBean,
)
from pypopur.sdk.timestamp import TimeStampManager
from pypopur.sdk.validation import (
    check_receive_command,
    check_send_command,
    decode_raw,
    encode_raw,
)

KEY = "0123456789abcdef"
DUMMY = {"dps": {"1": True}}


def _obj_schema(schema_type: str, prop: str, mode: str = MODE_RW) -> SchemaBean:
    return SchemaBean(id="1", type=DATA_TYPE_OBJ, mode=mode, schema_type=schema_type, property=prop)


class TestHexutil(unittest.TestCase):
    def test_bytes_to_hex_lowercase(self):
        # ByteUtils.bytesToHexString → Integer.toHexString → lowercase
        self.assertEqual(bytes_to_hex_string(b"\xaa\x4b\x00"), "aa4b00")

    def test_hex_roundtrip(self):
        self.assertEqual(hex_string_to_bytes("aa4b"), b"\xaa\x4b")

    def test_check_hex_string(self):
        self.assertTrue(check_hex_string("aa4B"))
        self.assertFalse(check_hex_string("zz"))
        self.assertFalse(check_hex_string(None))

    def test_int_to_bytes2_is_be32(self):
        self.assertEqual(int_to_bytes2(3), b"\x00\x00\x00\x03")
        self.assertEqual(int_to_bytes2(-1), b"\xff\xff\xff\xff")


class TestCrypto(unittest.TestCase):
    def test_aes_encrypt_is_uppercase_hex(self):
        aes = AESUtil(KEY.encode())
        enc = aes.encrypt("hello")
        self.assertEqual(enc, enc.upper())
        self.assertEqual(aes.decrypt(enc), "hello")

    def test_aes_base64_roundtrip(self):
        aes = AESUtil(KEY.encode())
        enc = aes.encrypt_with_base64("hello")
        base64.b64decode(enc)  # valid base64
        self.assertEqual(aes.decrypt_with_base64(enc), "hello")

    def test_md5_upper(self):
        self.assertEqual(md5_upper("abc"), hashlib.md5(b"abc").hexdigest().upper())

    def test_crc32_signed_int(self):
        # Java CRC32 → int (signed); zlib.crc32 is unsigned — equality modulo sign
        v = crc32(b"abc")
        self.assertEqual(v & 0xFFFFFFFF, zlib.crc32(b"abc"))


class TestValidation(unittest.TestCase):
    def test_send_null_schema_map_false(self):
        self.assertFalse(check_send_command(None, {"1": True}))

    def test_recv_null_schema_map_true(self):
        self.assertTrue(check_receive_command(None, {"1": True}))

    def test_send_ro_rejected(self):
        sm = {"1": _obj_schema("bool", "{}", mode=MODE_RO)}
        self.assertFalse(check_send_command(sm, {"1": True}))
        # receive has no ro check
        self.assertTrue(check_receive_command(sm, {"1": True}))

    def test_toggle_short_circuits_whole_map(self):
        sm = {
            "1": _obj_schema("bool", "{}"),
            "2": _obj_schema("value", '{"min":0,"max":10,"scale":0,"step":1}'),
        }
        # "2" is invalid but "toggle" on "1" returns true immediately
        self.assertTrue(check_send_command(sm, {"1": "toggle", "2": 999}))
        self.assertTrue(check_receive_command(sm, {"1": "toggle", "2": 999}))

    def test_send_bitmap_nonnegative_skips_bound(self):
        sm = {"1": _obj_schema("bitmap", '{"maxlen": 5}')}
        self.assertTrue(check_send_command(sm, {"1": 1 << 30}))  # if-gez quirk
        self.assertTrue(check_send_command(sm, {"1": -1}))  # -1 < 1<<31 → accept
        self.assertFalse(check_send_command(sm, {"1": 1 << 40}))  # Long → cast fails

    def test_recv_bitmap_strict(self):
        sm = {"1": _obj_schema("bitmap", '{"maxlen": 5}')}
        self.assertTrue(check_receive_command(sm, {"1": 31}))
        self.assertFalse(check_receive_command(sm, {"1": 32}))
        self.assertFalse(check_receive_command(sm, {"1": -1}))

    def test_value_int32_only_on_send(self):
        sm = {"1": _obj_schema("value", '{"min":0,"max":300,"scale":0,"step":1}')}
        self.assertTrue(check_send_command(sm, {"1": 100}))
        self.assertFalse(check_send_command(sm, {"1": 1 << 40}))  # Long not Integer
        self.assertFalse(check_receive_command(sm, {"1": 1 << 40}))  # out of range

    def test_send_null_value_skipped(self):
        sm = {"1": _obj_schema("bool", "{}")}
        self.assertTrue(check_send_command(sm, {"1": None}))
        self.assertFalse(check_receive_command(sm, {"1": None}))

    def test_missing_schema_entries_skipped(self):
        sm = {"1": _obj_schema("bool", "{}")}
        self.assertTrue(check_send_command(sm, {"9": True}))
        self.assertTrue(check_receive_command(sm, {"9": True}))

    def test_enum_membership(self):
        sm = {"1": _obj_schema("enum", '{"range": ["a","b"]}')}
        self.assertTrue(check_send_command(sm, {"1": "a"}))
        self.assertFalse(check_send_command(sm, {"1": "c"}))

    def test_raw_hex_even(self):
        sm = {"1": SchemaBean(id="1", type=DATA_TYPE_RAW, mode=MODE_RW)}
        self.assertTrue(check_send_command(sm, {"1": "aa4b"}))
        self.assertFalse(check_send_command(sm, {"1": "abc"}))
        self.assertFalse(check_send_command(sm, {"1": "zz"}))

    def test_decode_raw_mutates_in_place(self):
        sm = {"1": SchemaBean(id="1", type=DATA_TYPE_RAW, mode=MODE_RW)}
        dps = {"1": "qks=", "9": "x"}
        self.assertTrue(decode_raw(dps, sm))
        self.assertEqual(dps, {"1": "aa4b", "9": "x"})

    def test_encode_raw_hex_to_base64(self):
        sm = {"1": SchemaBean(id="1", type=DATA_TYPE_RAW, mode=MODE_RW)}
        dps = {"1": "aa4b", "9": "x"}
        out = encode_raw(sm, dps)
        self.assertEqual(dps["1"], "qks=")
        self.assertEqual(json.loads(out), {"1": "qks=", "9": "x"})


class TestSandO(unittest.TestCase):
    def test_defaults(self):
        s = SandO()
        self.assertEqual(s.get_s(), 2)
        self.assertTrue(1000 <= s.get_o() <= 1000999)

    def test_sadd(self):
        s = SandO()
        s.s_add()
        self.assertEqual(s.get_s(), 3)

    def test_map_put_get(self):
        m = SandRMap()
        a = SandO()
        m.put("dev1", a)
        self.assertIs(m.get("dev1"), a)
        self.assertIsNone(m.get("dev2"))


class TestDedup(unittest.TestCase):
    def test_first_seen_not_dup_second_is(self):
        c = ThingMessageCache()
        self.assertFalse(c.is_data_updated("dev", 5))
        self.assertTrue(c.is_data_updated("dev", 5))

    def test_s_minus1_always_dup(self):
        c = ThingMessageCache()
        self.assertTrue(c.is_data_updated("dev", -1))

    def test_o_zero_never_dup(self):
        c = ThingMessageCache()
        self.assertFalse(c.is_data_updated_so("dev", 5, 0))
        self.assertFalse(c.is_data_updated_so("dev", 5, 0))

    def test_so_dedup(self):
        c = ThingMessageCache()
        self.assertFalse(c.is_data_updated_so("dev", 5, 42))
        self.assertTrue(c.is_data_updated_so("dev", 5, 42))

    def test_hit_removes_entry(self):
        # a hit removes the key — a third check within the window is NOT a dup
        c = ThingMessageCache()
        self.assertFalse(c.is_data_updated("dev", 5))
        self.assertTrue(c.is_data_updated("dev", 5))
        self.assertFalse(c.is_data_updated("dev", 5))

    def test_low_power_repeats_pass(self):
        # attribute & 0x1000 → isDataUpdated ANDs !lowPower → repeats are
        # never reported as updated for low-power devices
        c = ThingMessageCache(attribute_provider=lambda dev: 0x1000)
        self.assertFalse(c.is_data_updated("dev", 5))
        self.assertFalse(c.is_data_updated("dev", 5))  # hit, but low-power

    def test_unknown_device_dedups_normally(self):
        c = ThingMessageCache(attribute_provider=lambda dev: None)
        self.assertFalse(c.is_data_updated("dev", 5))
        self.assertTrue(c.is_data_updated("dev", 5))


class TestTimestamp(unittest.TestCase):
    def test_seconds(self):
        mgr = TimeStampManager()
        ts = mgr.get_current_timestamp()
        self.assertAlmostEqual(ts, time.time(), delta=5)
        self.assertLess(ts, 10**11)  # seconds, not millis


class TestMqttSign(unittest.TestCase):
    def test_sign_data_pv(self):
        self.assertEqual(
            sign_data_pv("2.1", "abc", "key"),
            hashlib.md5(b"data=abc||pv=2.1||key").hexdigest()[8:24],
        )

    def test_sign_publish_bean_whitelist(self):
        # whitelist {pv,t,data,gwId,protocol}, sorted, k=v||, +key, lowercase
        sign = sign_publish_bean("enc", "gw", 5, "2.0", 123, "key")
        expected = hashlib.md5(b"data=enc||gwId=gw||protocol=5||pv=2.0||t=123||key").hexdigest()
        self.assertEqual(sign, expected)

    def test_sign_json_all_keys_except_sign(self):
        sign = sign_json({"b": "2", "a": "1", "sign": "x", "z": None}, "key")
        expected = hashlib.md5(b"a=1||b=2||key").hexdigest().upper()
        self.assertEqual(sign, expected)

    def test_crc_s_o_data(self):
        # be32(crc32(be32(3) || be32(42) || data))
        inner = zlib.crc32(b"\x00\x00\x00\x03\x00\x00\x00\x2axyz")
        self.assertEqual(crc_s_o_data(3, 42, b"xyz"), inner.to_bytes(4, "big"))

    def test_crc_s_o_data_key(self):
        # be32(crc32(be32(s)||be32(o)||be32(crc32(data))||key.bytes))
        data_crc = zlib.crc32(b"data")
        inner = zlib.crc32(
            b"\x00\x00\x00\x03\x00\x00\x00\x2a" + data_crc.to_bytes(4, "big") + b"key"
        )
        self.assertEqual(crc_s_o_data_key(3, 42, b"data", "key"), inner.to_bytes(4, "big"))


class TestMqttFraming(unittest.TestCase):
    GK = staticmethod(lambda topic: KEY)

    def test_2_3_roundtrip(self):
        p = build_payload_2_3(KEY, "2.3", DUMMY, 5, 1700000000, 7, 42)
        self.assertEqual(p[:3], b"2.3")
        proto, obj = parse_inbound_2_3(KEY, p, "dev")
        self.assertEqual(proto, 5)
        self.assertEqual(obj["data"], DUMMY)

    def test_2_3_bad_decrypt_12001(self):
        p = bytearray(build_payload_2_3(KEY, "2.3", DUMMY, 5, 1, 7, 42))
        p[-1] ^= 0xFF
        with self.assertRaises(MqttFrameError) as ctx:
            parse_inbound_2_3(KEY, bytes(p), "dev")
        self.assertEqual(ctx.exception.code, "12001")

    def test_2_2_roundtrip(self):
        p = build_payload_2_2(KEY, "2.2", DUMMY, 5, 1700000000, 7, 42)
        proto, obj = parse_inbound_2_2(KEY, p, "dev")
        self.assertEqual(proto, 5)
        self.assertEqual(obj["data"], DUMMY)

    def test_2_2_bad_crc_12002(self):
        p = bytearray(build_payload_2_2(KEY, "2.2", DUMMY, 5, 1, 7, 42))
        p[-1] ^= 0xFF
        with self.assertRaises(MqttFrameError) as ctx:
            parse_inbound_2_2(KEY, bytes(p), "dev")
        self.assertEqual(ctx.exception.code, "12002")

    def test_2_1_roundtrip(self):
        p = build_payload_2_1(KEY, "2.1", DUMMY, 5, 1700000000, 7)
        self.assertEqual(p[:3], b"2.1")
        proto, obj = parse_inbound_2_1(KEY, p, "dev")
        self.assertEqual(proto, 5)
        self.assertEqual(obj["s"], 7)

    def test_2_1_bad_sign_12002(self):
        p = build_payload_2_1(KEY, "2.1", DUMMY, 5, 1, 7)
        bad = p[:3] + b"0" * 16 + p[19:]
        with self.assertRaises(MqttFrameError) as ctx:
            parse_inbound_2_1(KEY, bad, "dev")
        self.assertEqual(ctx.exception.code, "12002")
        self.assertEqual(ctx.exception.message, "signature is not match 2_1")

    def test_1_1_roundtrip(self):
        p = build_payload_1_1(KEY, DUMMY, 5, 1700000000, 7, 42)
        self.assertEqual(p[:3], b"1.1")
        proto, _obj = parse_inbound_1_1(KEY, p, "dev")
        self.assertEqual(proto, 5)

    def test_1_1_bad_crc_12002(self):
        p = bytearray(build_payload_1_1(KEY, DUMMY, 5, 1, 7, 42))
        p[-1] ^= 0xFF
        with self.assertRaises(MqttFrameError) as ctx:
            parse_inbound_1_1(KEY, bytes(p), "dev")
        self.assertEqual(ctx.exception.code, "12002")

    def test_dedup_12003(self):
        p = build_payload_2_2(KEY, "2.2", DUMMY, 5, 1, 7, 42)
        cache = ThingMessageCache()
        parse_inbound_2_2(KEY, p, "dev", dedup=cache.is_data_updated_so)
        with self.assertRaises(MqttFrameError) as ctx:
            parse_inbound_2_2(KEY, p, "dev", dedup=cache.is_data_updated_so)
        self.assertEqual(ctx.exception.code, "12003")

    def test_missing_protocol_12004(self):
        # 2.2 frame whose decrypted JSON lacks "protocol"
        # protocol is inside the encrypted bean — build a bean without it
        from pypopur.sdk._fastjson import to_json_string
        from pypopur.sdk.crypto import AESUtil as _A

        ct = _A(KEY.encode()).encrypt_with_bytes(to_json_string({"data": {}, "t": 1}))
        from pypopur.sdk.hexutil import int_to_bytes2 as i2b

        frame = b"2.2" + crc_s_o_data(7, 42, ct) + i2b(7) + i2b(42) + ct
        with self.assertRaises(MqttFrameError) as ctx:
            parse_inbound_2_2(KEY, frame, "dev")
        self.assertEqual(ctx.exception.code, "12004")

    def test_2_0_envelope(self):
        p = build_payload_2_0(KEY, "2.0", DUMMY, "gw", 5, 1700000000)
        obj = json.loads(p)
        self.assertEqual(list(obj), ["data", "gwId", "protocol", "pv", "sign", "t"])
        self.assertEqual(obj["pv"], "2.0")
        self.assertEqual(obj["data"], obj["data"].upper())  # uppercase hex

    def test_2_0_signed_inbound(self):
        p = build_payload_2_0(KEY, "2.0", DUMMY, "dev1", 5, 1700000000)
        results = dispatch_inbound_message("smart/mb/in/dev1", p, self.GK)
        proto, obj = results[0]
        self.assertEqual(proto, 5)
        self.assertEqual(obj["data"], DUMMY)  # decrypted in place

    def test_2_0_tampered_sign_11004(self):
        obj = json.loads(build_payload_2_0(KEY, "2.0", DUMMY, "dev1", 5, 1700000000))
        obj["sign"] = "0" * 32
        with self.assertRaises(MqttFrameError) as ctx:
            dispatch_inbound_message("smart/mb/in/dev1", json.dumps(obj).encode(), self.GK)
        self.assertEqual(ctx.exception.code, "11004")

    def test_dispatch_binary_by_prefix(self):
        for pv, builder in (
            ("2.3", lambda: build_payload_2_3(KEY, "2.3", DUMMY, 5, 1, 7, 42)),
            ("2.2", lambda: build_payload_2_2(KEY, "2.2", DUMMY, 5, 1, 7, 42)),
            ("2.1", lambda: build_payload_2_1(KEY, "2.1", DUMMY, 5, 1, 7)),
            ("1.1", lambda: build_payload_1_1(KEY, DUMMY, 5, 1, 7, 42)),
        ):
            results = dispatch_inbound_message(
                "smart/mb/in/dev1", builder(), self.GK, prefixes=("smart/mb/in/",)
            )
            self.assertEqual(results[0][0], 5)

    def test_dispatch_silent_drops(self):
        self.assertEqual(dispatch_inbound_message("t", None, self.GK), [])
        p = build_payload_2_3(KEY, "2.3", DUMMY, 5, 1, 7, 42)
        self.assertEqual(dispatch_inbound_message("smart/mb/in/d", p, lambda t: ""), [])

    def test_dispatch_non_mb_topic_passthrough(self):
        j = json.dumps({"protocol": 8, "bizData": {}}).encode()
        results = dispatch_inbound_message("m/ug/123", j, self.GK)
        self.assertEqual(results[0][0], 8)

    def test_build_mqtt_publish_dispatch(self):
        p = build_mqtt_publish("2.3", KEY, DUMMY, "gw", 5, 1, 7, 42)
        self.assertEqual(p[:3], b"2.3")
        p = build_mqtt_publish("1.1", KEY, DUMMY, "gw", 5, 1, 7, 42)
        self.assertEqual(p[:3], b"1.1")


if __name__ == "__main__":
    unittest.main()


class TestMqttSession(unittest.TestCase):
    def test_oem_username_formula(self):
        # pid_v1_<appid>_<chkey>_mb_<token><md5(md5(appid)+ecode)[-16:]>
        import hashlib

        from pypopur.sdk.mqtt_session import MqttConnectConfig, SdkMqttCredentials

        cfg = MqttConnectConfig(partner_identity="pid", uid="u1", token="tok", ecode="ec1")
        cred = SdkMqttCredentials(
            cfg, "appid", get_ch_key=lambda b: "k", do_command_native_2=lambda b: "x" * 40
        )
        last16 = hashlib.md5(hashlib.md5(b"appid").hexdigest().encode() + b"ec1").hexdigest()[-16:]
        self.assertEqual(cred.username(), f"pid_v1_appid_k_mb_tok{last16}")
        self.assertEqual(cred.user_topic(), "pid/mb/u1")

    def test_oem_password_centered_slice(self):
        from pypopur.sdk.mqtt_session import MqttConnectConfig, SdkMqttCredentials

        cfg = MqttConnectConfig(partner_identity="p", uid="u", token="t", ecode="e")
        cred = SdkMqttCredentials(cfg, "a", lambda b: "k", lambda b: "0123456789abcdef" * 4)
        # 64-char v → v[len/2-8 : len/2+8] = [24:40]
        self.assertEqual(cred.password(), ("0123456789abcdef" * 4)[24:40])

    def test_oem_password_null_native_throws(self):
        from pypopur.sdk.mqtt_session import MqttConnectConfig, SdkMqttCredentials

        cfg = MqttConnectConfig(partner_identity="p", uid="u", token="t", ecode="e")
        cred = SdkMqttCredentials(cfg, "a", lambda b: "k", lambda b: None)
        # "value ==null" (12 chars) → substring(-2, 14) → Java throws
        with self.assertRaises(IndexError):
            cred.password()

    def test_init_mqtt_config(self):
        import hashlib

        from pypopur.sdk.mqtt_session import MQTT_SSL_PORT, init_mqtt_config

        bean = init_mqtt_config("mqtt.example", "com.x", "tag", "devid", "uid")
        uname = "devid_" + hashlib.md5(b"uidsdkfasodifca").hexdigest()
        self.assertEqual(bean.username, uname)
        self.assertEqual(bean.client_id, f"com.x_mb_{uname}_tag")
        self.assertEqual(bean.server_url, f"ssl://mqtt.example:{MQTT_SSL_PORT}")
        self.assertTrue(bean.clean_session)
        self.assertEqual(bean.qos, 1)
        self.assertEqual(bean.will_topic, "tuya/smart/will")

    def test_is_subscribe_semantics(self):
        from pypopur.sdk.mqtt_session import MqttServerManager

        m = MqttServerManager("t")
        self.assertTrue(m.is_subscribe(""))
        self.assertTrue(m.is_subscribe("any/other"))
        self.assertFalse(m.is_subscribe("smart/mb/in/x"))  # miss → False
        m.subscribe_state["smart/mb/in/x"] = True
        self.assertTrue(m.is_subscribe("smart/mb/in/x"))

    def test_subscribe_bookkeeping(self):
        from pypopur.sdk.mqtt_session import MqttServerManager

        m = MqttServerManager("t")
        pending = m.subscribe(["smart/mb/in/a", "", "smart/mb/in/b"], [1, 1, 1])
        self.assertEqual(pending, ["smart/mb/in/a", "smart/mb/in/b"])
        self.assertFalse(m.is_subscribe("smart/mb/in/a"))  # pending → False
        for t in pending:
            m.mark_subscribe(t)
        self.assertTrue(m.is_subscribe("smart/mb/in/a"))
        # already-TRUE topics are skipped
        self.assertEqual(m.subscribe(["smart/mb/in/a"], [1]), [])
        m.mark_unsubscribe("smart/mb/in/a")
        self.assertNotIn("smart/mb/in/a", m.subscribe_state)

    def test_parse_message_routes(self):
        from pypopur.sdk.mqtt_framing import build_payload_2_3
        from pypopur.sdk.mqtt_session import MqttServerManager

        class L:
            def __init__(self):
                self.events = []

            def on_mqtt_dp_received_success(self, t, p, o):
                self.events.append(("ok", t, p, o))

            def on_mqtt_dp_received_error(self, t, c, m):
                self.events.append(("err", t, c, m))

            def get_topic_suffix(self):
                return ["smart/mb/in/"]

            def get_local_key(self, d):
                return KEY

            def is_data_updated(self, t, s, o):
                return False

        mgr = MqttServerManager("t")
        listener = L()
        mgr.message_listeners.append(listener)

        p23 = build_payload_2_3(KEY, "2.3", DUMMY, 5, 1, 7, 42)
        mgr.parse_message("smart/mb/in/dev1", p23)
        self.assertEqual(listener.events[0][:3], ("ok", "smart/mb/in/dev1", 5))

        listener.events.clear()
        mgr.parse_message("tylink/x", b'{"a":1}')
        self.assertEqual(listener.events[0][2], -1)

        listener.events.clear()
        mgr.parse_message("yu/mb/in/x", b"\x01\x02")
        self.assertEqual(listener.events[0][3], {"data": b"\x01\x02"})

    def test_mmi_flow_frame(self):
        from pypopur.sdk.crypto import crc32
        from pypopur.sdk.mqtt_session import mmi_flow_crc_ok, mmi_flow_decrypt

        data = AESUtil(KEY.encode()).encrypt_with_bytes(b"hello")
        frame = b"\x55\xaa\x00\x00\x00\x00" + len(data).to_bytes(2, "big") + data
        frame += (crc32(frame) & 0xFFFFFFFF).to_bytes(4, "big")
        self.assertTrue(mmi_flow_crc_ok(frame))
        self.assertEqual(mmi_flow_decrypt(KEY, frame), b"hello")

        # encFlag=1 → raw slice
        raw = b"plain!"
        frame = b"\x55\xaa\x00\x00\x00\x01" + len(raw).to_bytes(2, "big") + raw
        frame += (crc32(frame) & 0xFFFFFFFF).to_bytes(4, "big")
        self.assertEqual(mmi_flow_decrypt(KEY, frame), raw)

        # bad magic / bad crc → None
        bad = b"\x00\x00" + frame[2:]
        self.assertIsNone(mmi_flow_decrypt(KEY, bad))
        self.assertIsNone(mmi_flow_decrypt(KEY, frame[:-4] + b"\x00" * 4))


class TestDeviceId(unittest.TestCase):
    def test_remote_device_id(self):
        import hashlib

        from pypopur.sdk.device_id import remote_device_id

        rids = ("r1", "r2", "r3", "r4")
        expected = (
            hashlib.md5(b"brandmodel").hexdigest()[4:16]
            + hashlib.md5(b"r3r4").hexdigest()[8:24]
            + hashlib.md5(b"r1r2").hexdigest()[16:]
        )
        self.assertEqual(remote_device_id("brand", "model", rids), expected)

    def test_get_device_id_persists(self):
        from pypopur.sdk.device_id import PhoneUtil

        store = {}
        p = PhoneUtil(store, brand="b", model="m", rng=lambda: 0x0123456789ABCDEF)
        first = p.get_device_id()
        self.assertEqual(len(first), 44)
        self.assertEqual(store["deviceId"], first)
        # second instance reuses the persisted id
        self.assertEqual(PhoneUtil(store, brand="b", model="m").get_device_id(), first)

    def test_generate_random_id_format(self):
        from pypopur.sdk.device_id import generate_random_id

        v = generate_random_id("Pixel 6", clock=lambda: 1700000012345, rng=lambda: 0xDEADBEEF)
        # last5(millis) + first6(model-no-space '0'-pad) + first4(hex(long))
        self.assertEqual(v, "12345" + "Pixel6" + "dead")


class TestDeviceCache(unittest.TestCase):
    def _cache(self):
        from pypopur.sdk.device_cache import (
            CommunicationEnum,
            CommunicationModule,
            CommunicationModuleT,
            DataPointModule,
            DeviceDataManager,
            DeviceRespBean,
            DevListCacheManager,
            ProductBean,
            SchemaInfo,
        )

        cache = DevListCacheManager()
        product = ProductBean("pid1")
        product.is_standard = True
        product.schema_info = SchemaInfo(
            schema_map={"1": object()}, dp_code_schema_map={"switch": object()}
        )
        cache.add_product_versioned(product, "1.0")
        bean = DeviceRespBean()
        bean.dev_id = "dev1"
        bean.uuid = "uuid1"
        bean.product_id = "pid1"
        bean.product_ver = "1.0"
        bean.local_key = "localkey"
        bean.cloud_online = True
        bean.data_point_info = DataPointModule(dps={"1": True}, dps_time={"1": 1000})
        bean.communication = CommunicationModule(
            communication_modes=[
                CommunicationModuleT(type=CommunicationEnum.MQTT, pv="2.2"),
                CommunicationModuleT(type=CommunicationEnum.LAN, pv="3.4"),
            ]
        )
        cache.add_dev(bean)
        return cache, DeviceDataManager(cache), bean, product

    def test_product_key(self):
        from pypopur.sdk.device_cache import product_key

        self.assertEqual(product_key("pid", "2.0"), "pid_2.0")
        self.assertEqual(product_key("pid", ""), "pid_1.0.0")
        self.assertEqual(product_key("", "2.0"), "")

    def test_get_dev_wraps(self):
        cache, _, _, _ = self._cache()
        dev = cache.get_dev("dev1")
        self.assertIsNotNone(dev)
        self.assertEqual(dev.pv, "2.2")
        self.assertTrue(dev.has_mqtt_communication)
        self.assertTrue(dev.has_lan_communication)
        self.assertFalse(dev.has_ble_communication)
        self.assertEqual(dev.dps, {"1": True})
        self.assertTrue(dev.is_online)
        # product missing → None
        from pypopur.sdk.device_cache import (
            DeviceRespBean,
            DevListCacheManager,
        )

        cache2 = DevListCacheManager()

        b = DeviceRespBean()
        b.dev_id = "x"
        cache2.add_dev(b)
        self.assertIsNone(cache2.get_dev("x"))

    def test_get_dev_empty_and_missing(self):
        cache, _, _, _ = self._cache()
        self.assertIsNone(cache.get_dev(""))
        self.assertIsNone(cache.get_dev("nope"))
        self.assertIsNone(cache.get_dev_resp_bean(""))

    def test_uuid_index(self):
        cache, _, _, _ = self._cache()
        self.assertIs(cache.get_dev_by_uuid("uuid1").dev_id, "dev1")

    def test_sub_dev_index(self):
        from pypopur.sdk.device_cache import (
            DeviceRespBean,
            DeviceTopoMoudle,
            DevListCacheManager,
        )

        cache = DevListCacheManager()
        sub = DeviceRespBean()
        sub.dev_id = "subdev"
        sub.device_topo = DeviceTopoMoudle(mesh_id="mesh1", node_id="ab", parent_dev_id="gw1")
        cache.add_dev(sub)
        # nodeId len 2 → "00" pad
        self.assertIs(cache.get_sub_dev("gw1", "ab"), sub)
        self.assertIs(cache.get_sub_dev("mesh1", "ab"), sub)
        self.assertIsNone(cache.get_sub_dev("gw1", ""))
        self.assertIsNone(cache.get_sub_dev("", "ab"))

    def test_get_dps_lazy_raw_decode(self):
        from pypopur.sdk import device_cache

        calls = []
        device_cache.set_lite_presenter(lambda dev_id, dps: calls.append((dev_id, dps)) or True)
        try:
            _cache, _, bean, _ = self._cache()
            self.assertEqual(bean.get_dps(), {"1": True})
            bean.get_dps()
            # decode runs once
            self.assertEqual(len(calls), 1)
            self.assertTrue(bean.is_raw_decoded)
        finally:
            device_cache.set_lite_presenter(None)

    def test_get_dps_time_npe_when_no_module(self):
        from pypopur.sdk.device_cache import DeviceRespBean

        bean = DeviceRespBean()
        with self.assertRaises(AttributeError):
            bean.get_dps_time()

    def test_update_sub_dev_dps_creates_map(self):
        from pypopur.sdk.device_cache import DeviceRespBean, DevListCacheManager

        cache = DevListCacheManager()
        bean = DeviceRespBean()
        bean.dev_id = "s"
        cache.update_sub_dev_dps(bean, {"2": 5})
        self.assertEqual(bean.get_dps(), {"2": 5})
        cache.update_sub_dev_dps(None, {"2": 9})  # no-op, no raise

    def test_zigbee_inherit(self):
        import time

        from pypopur.sdk.device_cache import (
            CommunicationModule,
            DataPointModule,
            DeviceRespBean,
            DevListCacheManager,
            ProductBean,
        )

        cache = DevListCacheManager()
        product = ProductBean("zp")
        product.capability = ProductBean.CAP_ZIGBEE
        cache.add_product_versioned(product, None)
        old = DeviceRespBean()
        old.dev_id = "sub1"
        old.product_id = "zp"
        old.data_point_info = DataPointModule(dps={"1": "old"})
        old.cloud_online = True
        cache.add_dev(old)
        cache.set_zigbee_sub_dev_timestamp("gw", int(time.time() * 1000))
        # re-add within 60 s window via communicationNode edge
        new = DeviceRespBean()
        new.dev_id = "sub1"
        new.product_id = "zp"
        new.communication = CommunicationModule(communication_node="gw")
        cache.add_dev(new)
        self.assertEqual(new.get_dps(), {"1": "old"})
        self.assertTrue(new.cloud_online)
        # outside window → no inherit
        new2 = DeviceRespBean()
        new2.dev_id = "sub2"
        new2.product_id = "zp"
        new2.communication = CommunicationModule(communication_node="gw")
        cache.set_zigbee_sub_dev_timestamp("gw", int(time.time() * 1000) - 0xEA60)
        cache.add_dev(new2)
        self.assertIsNone(new2.get_dps_may_raw_un_decoded())

    def test_device_bean_attribute_from_product(self):
        cache, _, _, product = self._cache()
        dev = cache.get_dev("dev1")
        self.assertEqual(dev.get_attribute(), 0)
        product.attribute = 0x1000
        self.assertEqual(dev.get_attribute(), 0x1000)

    def test_data_manager(self):

        _cache, data, _, _ = self._cache()
        self.assertEqual(data.get_dp("dev1", "1"), True)
        self.assertIsNone(data.get_dp("dev1", "9"))
        self.assertIsNone(data.get_dps("nope"))
        self.assertIn("1", data.get_schema_bean("dev1"))
        self.assertIn("switch", data.get_dp_code_schema_map("dev1"))


class TestCentralDpIngest(unittest.TestCase):
    def _world(self, **kw):
        from pypopur.sdk.device_cache import (
            CentralDpIngest,
            DataPointModule,
            DeviceDataManager,
            DeviceRespBean,
            DevListCacheManager,
            ProductBean,
        )

        cache = DevListCacheManager()
        product = ProductBean("p")
        cache.add_product_versioned(product, None)
        bean = DeviceRespBean()
        bean.dev_id = "d1"
        bean.product_id = "p"
        bean.data_point_info = DataPointModule(dps={}, dps_time={})
        cache.add_dev(bean)
        events = []
        ingest = CentralDpIngest(
            cache,
            DeviceDataManager(cache),
            on_dp_update=events.append,
            **kw,
        )
        return ingest, bean, events

    def test_happy_path_merges_and_emits(self):
        ingest, bean, events = self._world()
        ingest.ingest(
            "d1",
            "d1",
            {"1": 5000},
            '{"1": true}',
            True,
            decode_raw=lambda d, m: False,
            check_receive=lambda d, m: True,
        )
        self.assertEqual(bean.get_dps(), {"1": True})
        self.assertEqual(bean.get_dps_time(), {"1": 5000})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].dps_json, '{"1": true}')
        self.assertTrue(events[0].is_cloud)

    def test_devid_empty_falls_back_to_subdev(self):
        ingest, _bean, events = self._world()
        ingest.ingest(
            "",
            "d1",
            None,
            '{"1": 1}',
            False,
            decode_raw=lambda d, m: False,
            check_receive=lambda d, m: True,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].dev_id, "d1")

    def test_unknown_device_dropped(self):
        ingest, _, events = self._world()
        ingest.ingest(
            "ghost",
            "ghost",
            None,
            '{"1": 1}',
            True,
            decode_raw=lambda d, m: False,
            check_receive=lambda d, m: True,
        )
        self.assertEqual(events, [])

    def test_check_receive_false_drops(self):
        ingest, bean, events = self._world()
        ingest.ingest(
            "d1",
            "d1",
            None,
            '{"1": 1}',
            True,
            decode_raw=lambda d, m: False,
            check_receive=lambda d, m: False,
        )
        self.assertEqual(events, [])
        self.assertEqual(bean.get_dps(), {})

    def test_stale_dps_time_filters_equal_values(self):
        ingest, bean, events = self._world(is_yu_online=lambda d: True)
        bean.set_dps({"1": True})
        bean.set_dps_time({"1": 9000})
        # incoming t=5000 older than cached 9000 and value equal → dropped
        ingest.ingest(
            "d1",
            "d1",
            {"1": 5000, "2": 6000},
            '{"1": true, "2": 7}',
            True,
            decode_raw=lambda d, m: False,
            check_receive=lambda d, m: True,
        )
        self.assertEqual(events[0].dps_json, '{"1": true, "2": 7}')
        # dp1 removed from map; dp2 kept (no cached value)
        self.assertEqual(bean.get_dps()["2"], 7)

    def test_stale_all_dropped_no_event(self):
        ingest, bean, events = self._world(is_yu_online=lambda d: True)
        bean.set_dps({"1": True})
        bean.set_dps_time({"1": 9000})
        ingest.ingest(
            "d1",
            "d1",
            {"1": 5000},
            '{"1": true}',
            True,
            decode_raw=lambda d, m: False,
            check_receive=lambda d, m: True,
        )
        self.assertEqual(events, [])

    def test_raw_mutation_reserializes(self):
        ingest, _bean, events = self._world()

        def decode(d, m):
            m["2"] = "abcd"
            m.pop("raw", None)
            return True

        ingest.ingest(
            "d1",
            "d1",
            None,
            '{"raw": "aGk="}',
            True,
            decode_raw=decode,
            check_receive=lambda d, m: True,
        )
        self.assertEqual(events[0].dps_json, '{"2": "abcd"}')

    def test_merge_dps_null_cache_throwaway(self):
        # cached dps None → merge goes to throwaway map, bean keeps None
        from pypopur.sdk.device_cache import (
            CentralDpIngest,
            DeviceDataManager,
            DeviceRespBean,
            DevListCacheManager,
            ProductBean,
        )

        cache = DevListCacheManager()
        cache.add_product_versioned(ProductBean("p"), None)
        bean = DeviceRespBean()
        bean.dev_id = "d"
        bean.product_id = "p"
        bean.data_point_info = None
        cache.add_dev(bean)
        ingest = CentralDpIngest(cache, DeviceDataManager(cache))
        out = ingest.merge_dps("d", {"1": 1})
        self.assertEqual(out, {"1": 1})
        self.assertIsNone(bean.get_dps_may_raw_un_decoded())


class TestLanControl(unittest.TestCase):
    """``qqdbbpp``/``bpqqdpq``/``dqdpbbd``/``dddpppb``/``bddqdbd`` —
    the LAN send chain above lan_framing."""

    def _world(self, *, hgw_version="3.4", encrypt=True, active=2, cadv="1.0.1", capability=0x1):
        from pypopur.sdk.device_cache import (
            CommunicationModule,
            DataPointModule,
            DeviceRespBean,
            DeviceTopoMoudle,
            DevListCacheManager,
            ProductBean,
        )
        from pypopur.sdk.lan_control import (
            DeviceCommController,
            DevLocalControl,
            HgwBean,
            LocalControlModel,
            ResultCallback,
        )
        from pypopur.sdk.sando import SandRMap

        cache = DevListCacheManager()
        cache.add_product(ProductBean("p"))
        cache.products["p_1.0.0"].capability = capability

        resp = DeviceRespBean()
        resp.dev_id = "d"
        resp.product_id = "p"
        resp.local_key = "lk"
        resp.is_raw_decoded = True
        resp.data_point_info = DataPointModule()
        resp.data_point_info.dps = {}
        resp.communication = CommunicationModule()
        resp.communication.communication_node = "d"
        resp.device_topo = DeviceTopoMoudle()
        resp.gateway_ver_cad = cadv
        cache.dev_map["d"] = resp

        hgw = HgwBean(gw_id="d", ip="10.0.0.2", version=hgw_version, active=active, encrypt=encrypt)
        hgws = {"d": hgw}

        captured = {}

        def hw(bean, cb):
            captured["bean"] = bean
            cb.on_success()

        class CB(ResultCallback):
            def __init__(s):
                s.ok = False
                s.err = None

            def on_success(s):
                s.ok = True

            def on_error(s, code, msg):
                s.err = (code, msg)

        model = LocalControlModel(
            cache, hardware_control=hw, timestamp_fn=lambda: 7, hgw_provider=hgws.get
        )
        local = DevLocalControl(cache, model, uid="u1")
        ctl = DeviceCommController("d", cache, local, sand_r_map=SandRMap())
        return cache, resp, hgw, hgws, captured, ctl, CB, model, local

    def test_version_compare(self):
        from pypopur.sdk.lan_control import compare_version

        self.assertEqual(compare_version("3.3.0", "1.1"), 1)
        self.assertEqual(compare_version("1.0", "1.0.1"), -1)
        self.assertEqual(compare_version("1.0.1", "1.0.1"), 0)
        self.assertEqual(compare_version(None, "1.1"), -1)
        self.assertEqual(compare_version("1.1", None), -1)
        self.assertEqual(compare_version("1.0.x", "1.0.1"), -1)

    def test_control_bean_fields(self):
        from pypopur.sdk.lan_control import FrameTypeEnum
        from pypopur.sdk.sando import SandO

        _cache, _resp, _hgw, _hgws, captured, _ctl, CB, model, _ = self._world()
        so = SandO()
        so.s, so.o = 3, 9
        cb = CB()
        model.control("d", {"dps": {"1": True}}, so, FrameTypeEnum.CONTROL, cb)
        b = captured["bean"]
        self.assertEqual(
            (b.dev_id, b.lpv, b.s, b.o, b.t, b.protocol, b.frame_type, b.local_key),
            ("d", "3.4", 3, 9, 7, 5, 0x7, "lk"),
        )
        self.assertTrue(cb.ok)

    def test_encrypt_gate_drops_local_key(self):
        from pypopur.sdk.lan_control import FrameTypeEnum
        from pypopur.sdk.sando import SandO

        _, _, _hgw, _, captured, _, _CB, model, _ = self._world(encrypt=False)
        model.control("d", {}, SandO(), FrameTypeEnum.CONTROL)
        self.assertIsNone(captured["bean"].local_key)

    def test_missing_dev_and_offline_errors(self):
        from pypopur.sdk.lan_control import FrameTypeEnum
        from pypopur.sdk.sando import SandO

        _, _, _, hgws, _, _, CB, model, _ = self._world()
        cb = CB()
        model.control("nope", {}, SandO(), FrameTypeEnum.CONTROL, cb)
        self.assertEqual(cb.err, ("11005", "device is not exist"))
        del hgws["d"]
        cb = CB()
        model.control("d", {}, SandO(), FrameTypeEnum.CONTROL, cb)
        self.assertEqual(cb.err, ("11005", "device is not local online"))

    def test_error_message_hash_suffix(self):
        from pypopur.sdk.lan_control import FrameTypeEnum
        from pypopur.sdk.sando import SandO

        _, _, _, _, _, _, CB, model, _ = self._world()

        def hw_fail(bean, cb):
            cb.on_error("x", "y")

        model.hardware_control = hw_fail
        cb = CB()
        model.control("d", {}, SandO(), FrameTypeEnum.CONTROL, cb)
        self.assertEqual(cb.err, ("x", "y#"))

    def test_cadv_gate_frame_types(self):
        import json

        _, resp, _, _, captured, ctl, CB, _, _ = self._world()
        ctl.publish_dps_lan(json.dumps({"1": True}), CB())
        self.assertEqual(captured["bean"].frame_type, 0xD)  # CONTROL_NEW
        self.assertEqual(captured["bean"].data, {"dps": {"1": True}})

        resp.gateway_ver_cad = "1.0.0"
        ctl.publish_dps_lan(json.dumps({"1": True}), CB())
        b = captured["bean"]
        self.assertEqual(b.frame_type, 0x7)  # CONTROL
        self.assertEqual(b.data, {"dps": {"1": True}, "devId": "d", "t": 7, "uid": "u1"})

    def test_cadv_gate_zigbee_overrides_old(self):
        import json

        _, _resp, _, _, captured, ctl, CB, _, _ = self._world(
            cadv="1.0.0", capability=0x1000
        )  # zigbee
        ctl.publish_dps_lan(json.dumps({"1": True}), CB())
        self.assertEqual(captured["bean"].frame_type, 0xD)

    def test_old_path_lpv_1_1_t_quirk(self):
        """checkHgwVersion parses lpv as float — '3.3.0' throws → no t."""
        import json

        _, _resp, hgw, _, captured, ctl, CB, _, _ = self._world(cadv="1.0.0", hgw_version="3.3.0")
        ctl.publish_dps_lan(json.dumps({"1": True}), CB())
        self.assertNotIn("t", captured["bean"].data)

        hgw.version = "1.2"
        ctl.publish_dps_lan(json.dumps({"1": True}), CB())
        self.assertEqual(captured["bean"].data["t"], 7)

    def test_sando_sequence_per_dev(self):
        import json

        _, _, _, _, captured, ctl, CB, _, _ = self._world()
        ctl.publish_dps_lan(json.dumps({"1": True}), CB())
        s1 = captured["bean"].s
        ctl.publish_dps_lan(json.dumps({"1": True}), CB())
        self.assertEqual(captured["bean"].s, s1 + 1)

    def test_sub_device_cid_ctype(self):
        import json

        from pypopur.sdk.device_cache import (
            CommunicationModule,
            DeviceRespBean,
            DeviceTopoMoudle,
            DevListCacheManager,
        )
        from pypopur.sdk.lan_control import DeviceCommController
        from pypopur.sdk.sando import SandRMap

        cache, _resp, _, _, captured, _ctl, CB, _, local = self._world()
        sub = DeviceRespBean()
        sub.dev_id = "s1"
        sub.product_id = "p"
        sub.is_raw_decoded = True
        sub.communication = CommunicationModule()
        sub.communication.communication_node = "d"
        sub.device_topo = DeviceTopoMoudle()
        sub.device_topo.node_id = "aabb"
        sub.device_topo.parent_dev_id = "d"
        cache.dev_map["s1"] = sub
        cache.sub_dev_map["d" + DevListCacheManager._SUB_SEP + "aabb"] = "s1"

        ctl2 = DeviceCommController("s1", cache, local, sand_r_map=SandRMap())
        ctl2.publish_dps_lan(json.dumps({"2": 5}), CB())
        b = captured["bean"]
        self.assertEqual(b.dev_id, "d")
        self.assertEqual(b.frame_type, 0xD)
        self.assertEqual(b.data, {"cid": "aabb", "ctype": 0, "dps": {"2": 5}})

    def test_add_cid_ctype_rules(self):
        from pypopur.sdk.device_cache import (
            CommunicationModule,
            DeviceRespBean,
            DeviceTopoMoudle,
            DevListCacheManager,
            ProductBean,
        )
        from pypopur.sdk.lan_control import add_cid_ctype

        cache, _, _, _, _, _, _, _, _ = self._world()
        prod_ir = ProductBean("irp")
        prod_ir.capability = 0x2000
        cache.add_product(prod_ir)

        for dev_id, node, prod in (
            ("s1", "aabb", "p"),
            ("s2", "ccdd-v-e", "irp"),
        ):
            sub = DeviceRespBean()
            sub.dev_id = dev_id
            sub.product_id = prod
            sub.is_raw_decoded = True
            sub.communication = CommunicationModule()
            sub.device_topo = DeviceTopoMoudle()
            sub.device_topo.node_id = node
            sub.device_topo.parent_dev_id = "d"
            cache.dev_map[dev_id] = sub
            cache.sub_dev_map["d" + DevListCacheManager._SUB_SEP + node] = dev_id

        o = {}
        add_cid_ctype(cache, "d", "aabb", 0, o)
        self.assertEqual(o, {"cid": "aabb", "ctype": 0})

        # infrared product + plain nodeId → nothing added
        cache.dev_map["s1"].product_id = "irp"
        o = {}
        add_cid_ctype(cache, "d", "aabb", 0, o)
        self.assertEqual(o, {})
        cache.dev_map["s1"].product_id = "p"

        # infrared + "-v-" → trimmed cid
        o = {}
        add_cid_ctype(cache, "d", "ccdd-v-e", 0, o)
        self.assertEqual(o, {"cid": "ccdd", "ctype": 0})

        # unknown node → untrimmed cid
        o = {}
        add_cid_ctype(cache, "d", "zz-v-q", 0, o)
        self.assertEqual(o, {"cid": "zz-v-q", "ctype": 0})

        # gw-id / empty / None → nothing
        for node in ("d", "", None):
            o = {}
            add_cid_ctype(cache, "d", node, 0, o)
            self.assertEqual(o, {})

    def test_gate_active_states(self):
        """isIntranetControl resolves hgw by dev.communicationId."""
        from pypopur.sdk.lan_control import ActiveEnum, LanGate

        cache, _, hgw, hgws, _, _, _, _, _ = self._world()
        gate = LanGate(cache, hgws.get)
        hgw.active = ActiveEnum.ACTIVED
        self.assertTrue(gate.is_intranet_control("d"))
        hgw.active = ActiveEnum.LOCAL_ACTIVED
        self.assertTrue(gate.is_intranet_control("d"))
        for st in (ActiveEnum.UNACTIVE, ActiveEnum.ACTIVING, ActiveEnum.LOCAL_UNACTIVE):
            hgw.active = st
            self.assertFalse(gate.is_intranet_control("d"))
        del hgws["d"]
        self.assertFalse(gate.is_intranet_control("d"))
        # missing device bean → False
        self.assertFalse(gate.is_intranet_control("ghost"))

    def test_pipeline_error_fallback(self):
        from pypopur.sdk.lan_control import LanCommPipeline, ResultCallback

        events = []

        def lan_send(cmd, cb):
            cb.on_error("E1", "oops")

        def cloud_send(cmd, cb):
            events.append(("cloud", cmd))
            cb.on_success()

        def sched(d, f):
            return type("T", (), {"cancel": lambda s: None})()

        pipe = LanCommPipeline(lan_send, cloud_send, scheduler=sched)
        cb = ResultCallback()
        pipe.send("cmd1", cb)
        self.assertEqual(events, [("cloud", "cmd1")])

    def test_pipeline_watchdog_fallback(self):
        from pypopur.sdk.lan_control import LanCommPipeline, ResultCallback

        events, pending = [], {}

        def lan_send(cmd, cb):
            pending["cb"] = cb

        def cloud_send(cmd, cb):
            events.append(("cloud", cmd))

        def sched(d, f):
            pending["wd"] = f
            return type("T", (), {"cancel": lambda s: None})()

        pipe = LanCommPipeline(lan_send, cloud_send, scheduler=sched)
        pipe.send("cmd2", ResultCallback())
        pending["wd"]()
        self.assertEqual(events, [("cloud", "cmd2")])

    def test_pipeline_hash_suppresses_stat(self):
        from pypopur.sdk.lan_control import LanCommPipeline, ResultCallback

        stats, events = [], []

        def lan_send(cmd, cb):
            cb.on_error("E2", "dup#")

        def cloud_send(cmd, cb):
            events.append(cmd)

        def sched(d, f):
            return type("T", (), {"cancel": lambda s: None})()

        pipe = LanCommPipeline(lan_send, cloud_send, scheduler=sched)
        pipe.on_stat = lambda *a: stats.append(a)
        pipe.send("cmd3", ResultCallback())
        self.assertEqual(events, ["cmd3"])
        self.assertEqual(stats, [])


class TestDevSendChain(unittest.TestCase):
    """``qqdbbpp`` internet half + ``dqdpbbd`` cloud leaf +
    ``bqbppdq.publishDevice`` — the whole publishDps graph."""

    LK = "0123456789abcdef"

    def _world(self, *, pv="2.3", cadv="1.0.2", online=True):
        import json as _json  # noqa

        from pypopur.sdk.device_cache import (
            CommunicationEnum,
            CommunicationModule,
            CommunicationModuleT,
            DataPointModule,
            DeviceRespBean,
            DeviceTopoMoudle,
            DevListCacheManager,
            ProductBean,
        )
        from pypopur.sdk.lan_control import (
            DevCloudControl,
            DevLocalControl,
            DeviceCommController,
            LocalControlModel,
            ResultCallback,
        )
        from pypopur.sdk.mqtt_session import MqttServerManager
        from pypopur.sdk.sando import SandRMap

        cache = DevListCacheManager()
        prod = ProductBean("p")
        prod.capability = 0x1
        cache.add_product(prod)
        resp = DeviceRespBean()
        resp.dev_id = "d"
        resp.product_id = "p"
        resp.local_key = self.LK
        resp.cloud_online = online
        resp.is_raw_decoded = True
        resp.data_point_info = DataPointModule()
        resp.data_point_info.dps = {}
        resp.communication = CommunicationModule()
        resp.communication.communication_node = "d"
        resp.communication.communication_modes = [
            CommunicationModuleT(type=CommunicationEnum.MQTT, pv=pv)
        ]
        resp.device_topo = DeviceTopoMoudle()
        resp.gateway_ver_cad = cadv
        cache.dev_map["d"] = resp

        published, atop = [], []

        def pub(topic, payload, cb):
            published.append((topic, payload))
            cb.on_success()

        def atop_pub(dp, cb):
            atop.append(dp)
            cb.on_success()

        class CB(ResultCallback):
            def __init__(s):
                s.ok = False
                s.err = None

            def on_success(s):
                s.ok = True

            def on_error(s, code, msg):
                s.err = (code, msg)

        mgr = MqttServerManager("T" + str(id(cache)))
        mgr.is_real_connect = lambda: True
        mgr.publish_fn = pub
        mgr.subscribe_state["smart/mb/in/d"] = True

        model = LocalControlModel(cache, timestamp_fn=lambda: 7, hgw_provider=lambda d: None)
        local = DevLocalControl(cache, model, uid="u1")
        cloud = DevCloudControl(
            cache, publish_device=mgr.publish_device, atop_publish=atop_pub, timestamp_fn=lambda: 7
        )
        ctl = DeviceCommController("d", cache, local, sand_r_map=SandRMap())
        return (cache, resp, published, atop, mgr, model, cloud, ctl, CB)

    def test_mqtt_path(self):
        import json

        _, _, published, _, _, _, cloud, ctl, CB = self._world()
        cb = CB()
        ctl.publish_dps(
            "d",
            "",
            json.dumps({"1": True}),
            0,
            "",
            cb,
            is_online=lambda d, e: False,
            server_available=lambda: True,
            is_mqtt_subscribed=lambda d: True,
            mqtt_send=cloud.send_command,
        )
        self.assertTrue(cb.ok)
        topic, payload = published[-1]
        self.assertEqual(topic, "smart/mb/out/d")
        self.assertEqual(payload[:3], b"2.3")

    def test_pv_below_1_1_goes_http(self):
        import json

        _, _, _, atop, _, _, cloud, ctl, CB = self._world(pv="1.0")
        cb = CB()
        ctl.publish_dps(
            "d",
            "",
            json.dumps({"1": True}),
            0,
            "",
            cb,
            is_online=lambda d, e: False,
            server_available=lambda: True,
            is_mqtt_subscribed=lambda d: True,
            mqtt_send=cloud.send_command,
            http_publish=cloud._http_send,
        )
        self.assertTrue(cb.ok)
        self.assertEqual(atop[-1].dps, '{"1":true}')
        self.assertEqual((atop[-1].gw_id, atop[-1].dev_id), ("d", "d"))

    def test_lan_error_falls_back_to_server(self):
        import json

        _, _, published, _, _, model, cloud, ctl, CB = self._world()
        model.hardware_control = lambda b, c: c.on_error("E", "boom")
        cb = CB()
        ctl.publish_dps(
            "d",
            "",
            json.dumps({"1": True}),
            0,
            "",
            cb,
            is_online=lambda d, e: True,
            server_available=lambda: True,
            is_mqtt_subscribed=lambda d: True,
            mqtt_send=cloud.send_command,
            http_publish=cloud._http_send,
        )
        self.assertTrue(cb.ok)
        self.assertEqual(published[-1][0], "smart/mb/out/d")

    def test_server_down_network_up_goes_http(self):
        import json

        _, _, _, atop, _, _, cloud, ctl, CB = self._world()
        cb = CB()
        ctl.publish_dps(
            "d",
            "",
            json.dumps({"1": True}),
            0,
            "",
            cb,
            is_online=lambda d, e: False,
            server_available=lambda: False,
            is_network_available=lambda: True,
            mqtt_send=cloud.send_command,
            http_publish=cloud._http_send,
        )
        self.assertTrue(cb.ok)
        self.assertEqual(atop[-1].dev_id, "d")

    def test_offline_device_10203(self):
        import json

        _, _resp, _, _, _, _, cloud, ctl, CB = self._world(online=False)
        cb = CB()
        ctl.publish_dps(
            "d",
            "",
            json.dumps({"1": True}),
            0,
            "",
            cb,
            is_online=lambda d, e: False,
            server_available=lambda: True,
            mqtt_send=cloud.send_command,
        )
        self.assertEqual(cb.err, ("10203", None))

    def test_missing_dev_11002(self):
        from pypopur.sdk.lan_control import DeviceCommController
        from pypopur.sdk.sando import SandRMap

        cache, _, _, _, _, _, _, _, CB = self._world()
        cb = CB()
        DeviceCommController("ghost", cache, None, sand_r_map=SandRMap()).publish_dps(
            "ghost", "", "{}", cb=cb, is_online=lambda d, e: False
        )
        self.assertEqual(cb.err, ("11002", None))

    def test_invalid_dp_11001(self):
        import json

        from pypopur.sdk.lan_control import DeviceCommController
        from pypopur.sdk.sando import SandRMap

        cache, _, _, _, _, _, _, _, CB = self._world()
        ctl = DeviceCommController(
            "d", cache, None, sand_r_map=SandRMap(), check_send=lambda d, m: False
        )
        cb = CB()
        ctl.publish_dps("d", "", json.dumps({"1": True}), 0, "", cb, is_online=lambda d, e: False)
        self.assertEqual(cb.err, ("11001", None))

    def test_send_command_dev_null_11002(self):
        from pypopur.sdk.sando import SandO

        _, _, _, _, _, _, cloud, _, CB = self._world()
        cb = CB()
        cloud.send_command("ghost", {}, "", 0, "", SandO(), cb)
        self.assertEqual(cb.err, ("11002", "dev==null"))

    def test_publish_device_errors_and_subscribe(self):
        from pypopur.sdk.mqtt_session import MqttControlBuilder

        _, _, published, _, mgr, _, _, _, CB = self._world()
        mgr.is_real_connect = lambda: False
        cb = CB()
        mgr.publish_device(MqttControlBuilder(topic_id="d"), cb)
        self.assertEqual(cb.err, ("6000", "mqtt is not connect"))
        cb = CB()
        mgr.publish_device(None, cb)
        self.assertEqual(cb.err, ("100001", "MqttControlBuilder is empty"))

        # not subscribed → subscribe bookkeeping marks pending (False)
        mgr.is_real_connect = lambda: True
        mgr.subscribe_state.clear()
        cb = CB()
        mgr.publish_device(
            MqttControlBuilder(
                topic_id="d",
                pv="2.3",
                local_key=self.LK,
                data={"dps": {}},
                protocol=5,
                s=3,
                sn=3,
                o=9,
                t=7,
            ),
            cb,
        )
        self.assertIs(mgr.subscribe_state["smart/mb/in/d"], False)
        self.assertEqual(published[-1][0], "smart/mb/out/d")

    def test_mqtt_payload_shapes(self):
        """cadv≥1.0.2 → {cid?,ctype?,mbid?,dps}; old cadv non-mesh →
        {devId,dps[,gwId]} for pv 2.0."""
        from pypopur.sdk.lan_control import DevCloudControl
        from pypopur.sdk.sando import SandO

        cache, resp, _, _, _, _, _, _, CB = self._world()
        sent = []
        cloud = DevCloudControl(cache, publish_device=lambda b, c: sent.append(b))
        so = SandO()

        # cadv 1.0.2 → new shape
        cloud.send_command("d", {"1": True}, "", 0, "L1", so, CB())
        self.assertEqual(sent[-1].data, {"mbid": "L1", "dps": {"1": True}})

        # cadv 1.0.0, wifi-only, non-virtual → {devId, dps}
        resp.gateway_ver_cad = "1.0.0"
        cloud.send_command("d", {"1": True}, "", 0, "", so, CB())
        self.assertEqual(sent[-1].data, {"devId": "d", "dps": {"1": True}})

        # + pv 2.0 → gwId
        resp.communication.communication_modes[0].pv = "2.0"
        cloud.send_command("d", {"1": True}, "", 0, "", so, CB())
        self.assertEqual(sent[-1].data["gwId"], "d")


class TestCommPipeline(unittest.TestCase):
    """``AbsThingDevice`` + ``qqqbbbd`` handler chain +
    ``qpbpqpq`` DevModel — the communicationModes dispatcher."""

    LK = "0123456789abcdef"

    def _world(self, modes, pv="2.3", cadv="1.0.2", online=True, hgw_active=4):
        from pypopur.sdk.comm_pipeline import (
            DevModel,
            ThingDevicePresenter,
        )
        from pypopur.sdk.device_cache import (
            CommunicationModule,
            CommunicationModuleT,
            DeviceRespBean,
            DeviceTopoMoudle,
            DevListCacheManager,
            ProductBean,
            SchemaInfo,
        )
        from pypopur.sdk.lan_control import (
            DevCloudControl,
            DeviceCommController,
            DevLocalControl,
            HgwBean,
            LanGate,
            LocalControlModel,
            ResultCallback,
        )
        from pypopur.sdk.schema import SchemaBean

        cache = DevListCacheManager()
        prod = ProductBean("p")
        prod.capability = 0x1
        si = SchemaInfo()
        si.schema_map = {"1": SchemaBean(id="1", mode="rw", type="obj", property='{"type":"bool"}')}
        prod.schema_info = si
        cache.add_product(prod)
        resp = DeviceRespBean()
        resp.dev_id = "d"
        resp.product_id = "p"
        resp.uuid = "u1"
        resp.is_raw_decoded = True
        resp.local_key = self.LK
        resp.cloud_online = online
        resp.communication = CommunicationModule()
        resp.communication.communication_node = "d"
        resp.communication.communication_modes = [
            CommunicationModuleT(type=t, pv=pv if t == 1 else None) for t in modes
        ]
        resp.device_topo = DeviceTopoMoudle()
        resp.gateway_ver_cad = cadv
        cache.add_dev(resp)
        hgw = HgwBean("d")
        hgw.active = hgw_active
        hgw.encrypt = True
        hgw.version = "3.4"
        hgws = {"d": hgw}

        lan_beans, published, atop = [], [], []

        def hw(bean, cb):
            lan_beans.append(bean)
            cb.on_success()

        class CB(ResultCallback):
            def __init__(s):
                s.events = []

            def on_error(s, code, msg):
                s.events.append(("err", code, msg))

            def on_success(s):
                s.events.append(("ok",))

        model = LocalControlModel(cache, hardware_control=hw, hgw_provider=hgws.get)
        local = DevLocalControl(cache, model)
        cloud = DevCloudControl(
            cache,
            publish_device=lambda b, c: (published.append(b), c.on_success()),
            atop_publish=lambda dp, c: (atop.append(dp), c.on_success()),
        )
        ctl = DeviceCommController("d", cache, local, cloud=cloud)
        gate = LanGate(cache, hgws.get)
        dm = DevModel("d", ctl, cache, gate, mqtt_up=lambda: True)
        dm.send_seams["mqtt_send"] = cloud.send_command
        pres = ThingDevicePresenter("d", dm, cache)
        pres._scheduler = staticmethod(lambda d, f: None)  # never fire
        return (cache, resp, hgw, hgws, lan_beans, published, atop, cloud, ctl, dm, pres, CB)

    def test_lan_first_then_success(self):
        import json

        *_, lan_beans, published, _atop, _cloud, _ctl, _dm, pres, CB = self._world([0, 1, 2])
        cb = CB()
        pres.publish_dps(json.dumps({"1": True}), cb)
        self.assertEqual(lan_beans[0].frame_type, 0xD)
        self.assertEqual(lan_beans[0].data, {"dps": {"1": True}})
        self.assertEqual(cb.events, [("ok",)])
        self.assertEqual(published, [])

    def test_lan_down_mqtt_handler_sends_internet(self):
        """LAN unavailable → MQTT handler's awake → internet send."""
        import json

        *_, lan_beans, published, _atop, _cloud, _ctl, _dm, pres, CB = self._world(
            [0, 1, 2], hgw_active=0
        )
        cb = CB()
        pres.publish_dps(json.dumps({"1": True}), cb)
        self.assertEqual(lan_beans, [])
        self.assertEqual(cb.events, [("ok",)])
        self.assertEqual(published[-1].topic_id, "d")
        self.assertEqual(published[-1].data, {"dps": {"1": True}})

    def test_http_handler_send_dps_by_api(self):
        import json

        w = self._world([2])
        _cache, _resp, _hgw, _hgws, _lan_beans, _published = w[:6]
        atop = []
        dm = w[9]
        dm.atop_send = lambda a, v, d, c: atop.append((a, v, d))
        cb = w[11]()
        w[10].publish_dps(json.dumps({"1": True}), cb)
        self.assertEqual(
            atop[-1], ("thing.m.nb.device.dp.publish", "1.0", {"devId": "d", "dps": '{"1":true}'})
        )

    def test_cloud_mode_handler(self):
        import json

        w = self._world([100])
        atop = []
        w[9].atop_send = lambda a, v, d, c: atop.append((a, v, d))
        cb = w[11]()
        w[10].publish_dps(json.dumps({"1": True}), cb)
        self.assertEqual(
            atop[-1], ("thing.m.device.dp.publish", "1.0", {"devId": "d", "dps": '{"1":true}'})
        )

    def test_empty_modes_11001(self):
        import json

        w = self._world([])
        cb = w[11]()
        w[10].publish_dps(json.dumps({"1": True}), cb)
        self.assertEqual(cb.events, [("err", "11001", "communication types illegal")])

    def test_check_send_fail_11001(self):
        w = self._world([2])
        w[9].schema_fn = lambda d: None  # null schema → false
        cb = w[11]()
        import json

        w[10].publish_dps(json.dumps({"1": True}), cb)
        self.assertEqual(cb.events, [("err", "11001", None)])

    def test_channels_requested_order(self):
        """Requested [MQTT,LAN] chains in REQUESTED order; MQTT handler
        wins (LAN never reached)."""
        import json

        w = self._world([0, 1, 2])
        cb = w[11]()
        w[10].publish_dps_channels(json.dumps({"1": True}), "[1,0]", cb)
        self.assertEqual(w[4], [])  # lan_beans empty
        self.assertEqual(cb.events, [("ok",)])
        self.assertEqual(w[5][-1].topic_id, "d")

    def test_channels_unknown_and_missing(self):
        import json

        w = self._world([2])
        cb = w[11]()
        w[10].publish_dps_channels(json.dumps({"1": True}), "[99]", cb)
        self.assertEqual(cb.events, [("err", "301001", "communication_types_illegal")])
        cb = w[11]()
        w[10].publish_dps_channels(json.dumps({"1": True}), "[0]", cb)
        self.assertEqual(cb.events, [("err", "301001", "communication_types_illegal")])

    def test_channels_yu_mqtt_synthesized(self):
        """Requesting YU_MQTT synthesizes a module even when the device
        doesn't declare it → handler exists but is unavailable → falls
        to nothing → 11005 'no channel available'."""
        import json

        w = self._world([2])
        cb = w[11]()
        w[10].publish_dps_channels(json.dumps({"1": True}), "[12]", cb)
        # YU_MQTT module synthesized → BleCommHandler+dqqbppb chain,
        # both unavailable → 11005 "send error,no channel available."
        self.assertEqual(cb.events, [("err", "11005", "send error,no channel available.")])

    def test_mode_local_and_inactive(self):
        import json

        from pypopur.sdk.comm_pipeline import ThingDevicePublishModeEnum

        w = self._world([0, 1])
        cb = w[11]()
        w[10].publish_dps_mode(json.dumps({"1": True}), ThingDevicePublishModeEnum.Local, cb)
        self.assertEqual(w[4][0].frame_type, 0xD)
        self.assertEqual(cb.events, [("ok",)])
        w[2].active = 0
        cb = w[11]()
        w[10].publish_dps_mode(json.dumps({"1": True}), ThingDevicePublishModeEnum.Local, cb)
        self.assertEqual(cb.events, [("err", "10201", "device is not in intranet online")])

    def test_mode_internet_mqtt_down(self):
        import json

        from pypopur.sdk.comm_pipeline import ThingDevicePublishModeEnum

        w = self._world([0, 1])
        w[9].mqtt_up = lambda: False
        cb = w[11]()
        w[10].publish_dps_mode(json.dumps({"1": True}), ThingDevicePublishModeEnum.Internet, cb)
        self.assertEqual(cb.events, [("err", "10202", "device is not in cloud online")])

    def test_mode_mqtt_send_with_node(self):
        import json

        from pypopur.sdk.comm_pipeline import ThingDevicePublishModeEnum

        w = self._world([1])
        cb = w[11]()
        w[10].publish_dps_mode(json.dumps({"1": True}), ThingDevicePublishModeEnum.Mqtt, cb)
        self.assertEqual(cb.events, [("ok",)])
        self.assertEqual(w[5][-1].topic_id, "d")

    def test_mode_http_send_with_node(self):
        import json

        from pypopur.sdk.comm_pipeline import ThingDevicePublishModeEnum

        w = self._world([1])
        cb = w[11]()
        w[10].publish_dps_mode(json.dumps({"1": True}), ThingDevicePublishModeEnum.Http, cb)
        self.assertEqual(cb.events, [("ok",)])
        self.assertEqual(w[6][-1].dev_id, "d")
        self.assertEqual(w[6][-1].dps, '{"1":true}')

    def test_stat_strip_hash(self):
        """``#``-marked errors strip the marker and skip the stat."""
        from pypopur.sdk.comm_pipeline import PipelineAnalytics, StatStripCallback

        class A(PipelineAnalytics):
            def __init__(s):
                s.stats = []

            def stat_error(s, code, msg):
                s.stats.append((code, msg))

        class C:
            def __init__(s):
                s.events = []

            def on_error(s, c, m):
                s.events.append((c, m))

            def on_success(s):
                s.events.append(("ok",))

        a, inner = A(), C()
        w = StatStripCallback(inner, a)
        w.on_error("X", "oops#")
        self.assertEqual(inner.events, [("X", "oops")])
        self.assertEqual(a.stats, [])
        w.on_error("Y", "plain")
        self.assertEqual(inner.events[-1], ("Y", "plain"))
        self.assertEqual(a.stats, [("Y", "plain")])

    def test_check_direct_gateway_ble_promotion(self):
        """Sub-device + bleOnline parent with bit-19 cap and BLE-first
        parent modes → BLE module inserted at index 0."""

        from pypopur.sdk.device_cache import (
            CommunicationModule,
            CommunicationModuleT,
            DeviceRespBean,
            DeviceTopoMoudle,
        )

        w = self._world([1, 2])
        cache, resp, _hgw, _hgws = w[:4]
        # make 'd' a sub-device of 'gw'
        resp.device_topo.parent_dev_id = "gw"
        gw = DeviceRespBean()
        gw.dev_id = "gw"
        gw.product_id = "p"
        gw.is_raw_decoded = True
        gw.communication = CommunicationModule()
        gw.communication.communication_node = "gw"
        gw.communication.communication_modes = [
            CommunicationModuleT(type=3),
            CommunicationModuleT(type=1),
        ]
        gw.device_topo = DeviceTopoMoudle()
        cache.dev_map["gw"] = gw
        cache.use_new_cache = True
        gw_bean = cache.get_dev("gw")  # fresh wrap
        gw_bean.bluetooth_capability = "ffff"
        cache.dev_bean_map["gw"] = gw_bean  # pinned for get_dev
        pres = w[10]
        pres.is_single_ble_local_online = lambda d: d == "gw"
        pres.ble_capability_bit19 = lambda c: True

        modes = list(resp.communication.communication_modes)
        pres._check_direct_gateway(modes)
        self.assertEqual(modes[0].type, 3)  # BLE promoted to front
