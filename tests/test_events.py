"""Tests for events.py — the app's real-time MQTT channel."""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import threading
import time
import unittest
from typing import ClassVar

from pypopur.events import (
    DeviceEvent,
    DeviceEventListener,
    PopurMqttEvents,
    build_mqtt_credentials,
    make_central_ingest_sink,
)
from pypopur.sdk.dedup import ThingMessageCache
from pypopur.sdk.mqtt_framing import build_payload_2_0, build_payload_2_2

KEY = "0123456789abcdef"
MASTER = b"master-material-for-tests"


class _Profile:
    api_host = "https://a1-us.iotbing.com"
    client_id = "testappid"
    ch_key = "chkey123"
    signing_key = MASTER
    package_name = "com.test.app"


class _Session:
    uid = "u123"
    ecode = "ec00"
    sid = "s1d-t0k3n"
    partner_identity = "p2603060"
    domain: ClassVar[dict] = {"mobileMqttsUrl": "m1-us.iotbing.com", "mqttsPort": "8883"}
    raw_user: ClassVar[dict] = {}


def _events(sock_factory=None, **kwargs) -> PopurMqttEvents:
    kwargs.setdefault("devices", {"dev1": KEY})
    return PopurMqttEvents(
        _Profile(), _Session(), "installid" * 3, sock_factory=sock_factory, **kwargs
    )


class CredentialsTests(unittest.TestCase):
    def test_connect_config_from_session(self) -> None:
        config, _ = build_mqtt_credentials(_Profile(), _Session())
        # getMqttConfigInfo — token = sid, appTag = "os".
        self.assertEqual(config.token, "s1d-t0k3n")
        self.assertEqual(config.app_tag, "os")
        self.assertEqual(config.uid, "u123")
        self.assertEqual(config.ecode, "ec00")
        self.assertEqual(config.partner_identity, "p2603060")

    def test_user_topic(self) -> None:
        _, creds = build_mqtt_credentials(_Profile(), _Session())
        self.assertEqual(creds.user_topic(), "p2603060/mb/u123")

    def test_username_formula(self) -> None:
        _, creds = build_mqtt_credentials(_Profile(), _Session())
        inner = hashlib.md5(
            hashlib.md5(b"testappid").hexdigest().encode() + b"ec00"
        ).hexdigest()[-16:]
        self.assertEqual(
            creds.username(),
            f"p2603060_v1_testappid_chkey123_mb_s1d-t0k3n{inner}",
        )

    def test_password_uses_cmd2_centered16(self) -> None:
        _, creds = build_mqtt_credentials(_Profile(), _Session())
        seed = hashlib.md5(
            hashlib.md5(MASTER).hexdigest().encode() + b"ec00"
        ).hexdigest()
        self.assertEqual(len(seed), 32)
        self.assertEqual(creds.password(), seed[8:24])


class ConnectEventsTests(unittest.TestCase):
    class _Api:
        def __init__(self, session) -> None:
            self.session = session
            self.profile = _Profile()
            self.install_id = "iid"

    def test_requires_session(self) -> None:
        from pypopur.mobile import MobileApiError, PopurAccount

        account = PopurAccount(self._Api(None))
        with self.assertRaises(MobileApiError):
            account.connect_events()

    def test_builds_from_session(self) -> None:
        from pypopur.mobile import PopurAccount

        account = PopurAccount(self._Api(_Session()))
        ev = account.connect_events(devices={"dev1": KEY})
        self.assertIsInstance(ev, PopurMqttEvents)
        self.assertEqual(ev.config.host, "m1-us.iotbing.com")
        self.assertEqual(ev.listener.get_local_key("smart/mb/in/dev1"), KEY)


class ConstructionTests(unittest.TestCase):
    def test_host_port_client_id_from_session(self) -> None:
        ev = _events()
        self.assertEqual(ev.config.host, "m1-us.iotbing.com")
        self.assertEqual(ev.config.port, 8883)
        self.assertEqual(ev.config.server_url, "ssl://m1-us.iotbing.com:8883")
        self.assertIn("_mb_", ev.config.client_id)
        self.assertTrue(ev.config.client_id.startswith("com.test.app_mb_"))
        self.assertTrue(ev.config.client_id.endswith("_os"))

    def test_port_override_updates_urls(self) -> None:
        class S(_Session):
            domain: ClassVar[dict] = {"mobileMqttsUrl": "h.example.com", "mqttsPort": "9883"}

        ev = PopurMqttEvents(_Profile(), S(), "iid")
        self.assertEqual(ev.config.port, 9883)
        self.assertEqual(ev.config.server_url, "ssl://h.example.com:9883")
        self.assertEqual(ev.config.mqtt_urls, ["ssl://h.example.com:9883"])

    def test_listener_registered_once(self) -> None:
        ev = _events()
        self.assertEqual(ev.manager.message_listeners.count(ev.listener), 1)


class ListenerTests(unittest.TestCase):
    def _listener(self) -> DeviceEventListener:
        return DeviceEventListener(
            {"dev1": KEY}, ThingMessageCache(), lambda e: None, user_topic="pid/mb/uid"
        )

    def test_topic_suffix_matches_smali(self) -> None:
        # qqpqqpq.getTopicSuffix() = {"smart/mb/in/", "m/dg/", userTopic}
        self.assertEqual(
            self._listener().get_topic_suffix(),
            ["smart/mb/in/", "m/dg/", "pid/mb/uid"],
        )

    def test_get_local_key_strips_prefixes(self) -> None:
        listener = self._listener()
        self.assertEqual(listener.get_local_key("smart/mb/in/dev1"), KEY)
        self.assertEqual(listener.get_local_key("smart/mb/out/dev1"), KEY)
        self.assertIsNone(listener.get_local_key("smart/mb/in/unknown"))

    def test_is_data_updated_strips_prefix_and_dedups(self) -> None:
        # First sight → False (accepted); repeat in-window → True (swallowed).
        dedup = ThingMessageCache()
        listener = DeviceEventListener(
            {"dev1": KEY}, dedup, lambda e: None, user_topic="pid/mb/uid"
        )
        self.assertFalse(listener.is_data_updated("smart/mb/in/dev1", 10, 5))
        self.assertTrue(listener.is_data_updated("smart/mb/in/dev1", 10, 5))
        self.assertFalse(listener.is_data_updated("m/dg/dev1", 10, 6))

    def test_event_callback_lifts_dps(self) -> None:
        events: list[DeviceEvent] = []
        listener = DeviceEventListener(
            {"dev1": KEY}, ThingMessageCache(), events.append, user_topic="pid/mb/uid"
        )
        listener.on_mqtt_dp_received_success(
            "smart/mb/in/dev1",
            5,
            {"data": {"devId": "dev1", "dps": {"1": True, "4": 42}, "dpsTime": {"1": 9}}},
        )
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.dev_id, "dev1")
        self.assertEqual(ev.protocol, 5)
        self.assertEqual(ev.dps, {1: True, 4: 42})
        self.assertEqual(ev.dps_time, {1: 9})
        self.assertEqual(ev.topic, "smart/mb/in/dev1")

    def test_event_dev_id_falls_back_to_topic(self) -> None:
        events: list[DeviceEvent] = []
        listener = DeviceEventListener(
            {"dev1": KEY}, ThingMessageCache(), events.append, user_topic="pid/mb/uid"
        )
        listener.on_mqtt_dp_received_success("smart/mb/in/dev1", 5, {"dps": {"1": False}})
        self.assertEqual(events[0].dev_id, "dev1")

    def test_dp_sink_runs_before_on_event(self) -> None:
        order: list[str] = []
        listener = DeviceEventListener(
            {"dev1": KEY},
            ThingMessageCache(),
            lambda e: order.append("event"),
            user_topic="pid/mb/uid",
            dp_sink=lambda e: order.append("sink"),
        )
        listener.on_mqtt_dp_received_success("smart/mb/in/dev1", 5, {"dps": {"1": True}})
        self.assertEqual(order, ["sink", "event"])


class IngestSinkTests(unittest.TestCase):
    """make_central_ingest_sink → CentralDpIngest.ingest merge path."""

    def _ingest(self):
        from pypopur.sdk.device_cache import (
            CentralDpIngest,
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
        product.schema_info = SchemaInfo(schema_map={"1": object()})
        cache.add_product_versioned(product, "1.0")
        bean = DeviceRespBean()
        bean.dev_id = "dev1"
        bean.product_id = "pid1"
        bean.product_ver = "1.0"
        bean.local_key = KEY
        bean.cloud_online = True
        bean.data_point_info = DataPointModule(dps={"1": False}, dps_time={"1": 1})
        cache.add_dev(bean)
        return CentralDpIngest(cache, DeviceDataManager(cache)), cache

    def test_mqtt_push_merges_into_cache(self) -> None:
        ingest, cache = self._ingest()
        sink = make_central_ingest_sink(ingest)
        listener = DeviceEventListener(
            {"dev1": KEY}, ThingMessageCache(), lambda e: None,
            user_topic="pid/mb/uid", dp_sink=sink,
        )
        listener.on_mqtt_dp_received_success(
            "smart/mb/in/dev1", 5,
            {"data": {"devId": "dev1", "dps": {"1": True}, "dpsTime": {"1": 2000}}},
        )
        bean = cache.get_dev_resp_bean("dev1")
        self.assertEqual(bean.get_dps()["1"], True)

    def test_sink_skips_events_without_dps(self) -> None:
        ingest, _ = self._ingest()
        calls = []
        sink = make_central_ingest_sink(ingest)
        original = ingest.ingest
        ingest.ingest = lambda *a, **k: calls.append(1) or original(*a, **k)
        sink(DeviceEvent(dev_id="dev1", protocol=5, data={}, topic="t"))
        self.assertEqual(calls, [])


# -- fake broker end-to-end -------------------------------------------------


def _enc_str(s: str) -> bytes:
    d = s.encode()
    return struct.pack(">H", len(d)) + d


def _packet(header: int, body: bytes = b"") -> bytes:
    out = bytes([header])
    n = len(body)
    while True:
        b = n % 128
        n //= 128
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out + body


class FakeBroker:
    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.port = self.listener.getsockname()[1]
        self.conn: socket.socket | None = None
        self.connect_packet: dict = {}
        self.subscribed: list[str] = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    @staticmethod
    def _read_exact(conn: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            part = conn.recv(n - len(buf))
            if not part:
                raise ConnectionError
            buf.extend(part)
        return bytes(buf)

    @classmethod
    def _read_remaining(cls, conn: socket.socket) -> int:
        value, mult = 0, 1
        while True:
            b = cls._read_exact(conn, 1)[0]
            value += (b & 0x7F) * mult
            if not (b & 0x80):
                return value
            mult *= 128

    def _run(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.conn = conn
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            header = self._read_exact(conn, 1)[0]
            assert header >> 4 == 1
            body = self._read_exact(conn, self._read_remaining(conn))
            self.connect_packet = self._parse_connect(body)
            conn.sendall(_packet(0x20, b"\x00\x00"))
            while True:
                header = self._read_exact(conn, 1)[0]
                body = self._read_exact(conn, self._read_remaining(conn))
                ptype = header >> 4
                if ptype == 8:  # SUBSCRIBE
                    pid = struct.unpack(">H", body[:2])[0]
                    pos = 2
                    while pos < len(body):
                        tl = struct.unpack(">H", body[pos : pos + 2])[0]
                        self.subscribed.append(body[pos + 2 : pos + 2 + tl].decode())
                        pos += 2 + tl + 1
                    conn.sendall(_packet(0x90, struct.pack(">H", pid) + b"\x01"))
                elif ptype == 3 and (header >> 1) & 3:  # PUBLISH qos>0
                    tl = struct.unpack(">H", body[:2])[0]
                    rest = body[2 + tl :]
                    pid = struct.unpack(">H", rest[:2])[0]
                    conn.sendall(_packet(0x40, struct.pack(">H", pid)))
                elif ptype == 12:  # PINGREQ
                    conn.sendall(_packet(0xD0))
                elif ptype == 14:  # DISCONNECT
                    return
        except (ConnectionError, OSError, AssertionError):
            return

    @staticmethod
    def _parse_connect(body: bytes) -> dict:
        pos = 0
        proto_len = struct.unpack(">H", body[:2])[0]
        pos += 2 + proto_len
        level, flags = body[pos], body[pos + 1]
        keepalive = struct.unpack(">H", body[pos + 2 : pos + 4])[0]
        pos += 4

        def rd_str(p: int) -> tuple[str, int]:
            tl = struct.unpack(">H", body[p : p + 2])[0]
            return body[p + 2 : p + 2 + tl].decode(), p + 2 + tl

        client_id, pos = rd_str(pos)
        out = {
            "level": level,
            "flags": flags,
            "keepalive": keepalive,
            "client_id": client_id,
        }
        if flags & 0x04:
            out["will_topic"], pos = rd_str(pos)
            wl = struct.unpack(">H", body[pos : pos + 2])[0]
            out["will_payload"] = body[pos + 2 : pos + 2 + wl]
            pos += 2 + wl
        if flags & 0x80:
            out["username"], pos = rd_str(pos)
        if flags & 0x40:
            wl = struct.unpack(">H", body[pos : pos + 2])[0]
            out["password"] = body[pos + 2 : pos + 2 + wl]
        return out

    def push(self, topic: str, payload: bytes) -> None:
        self.conn.sendall(_packet(0x30, _enc_str(topic) + payload))

    def stop(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        finally:
            self.listener.close()


def _wait_for(pred, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met")


class WireTests(unittest.TestCase):
    _tag_counter = 0

    def _events_on_broker(
        self, broker: FakeBroker, events: list[DeviceEvent]
    ) -> PopurMqttEvents:
        class S(_Session):
            domain: ClassVar[dict] = {"mobileMqttsUrl": "127.0.0.1", "mqttsPort": str(broker.port)}

        # MqttServerManager is a per-tag singleton — give each test its own
        # tag so subscribe_state doesn't leak between tests.
        type(self)._tag_counter += 1
        return PopurMqttEvents(
            _Profile(),
            S(),
            "installid" * 3,
            devices={"dev1": KEY},
            on_event=events.append,
            sock_factory=lambda h, p, t: socket.create_connection((h, p), timeout=t),
            tag=f"t{self._tag_counter}",
        )

    def test_connect_sends_derived_credentials(self) -> None:
        broker = FakeBroker()
        events: list[DeviceEvent] = []
        ev = self._events_on_broker(broker, events)
        try:
            import asyncio

            asyncio.run(ev.connect())
            pkt = broker.connect_packet
            self.assertEqual(pkt["level"], 4)
            self.assertTrue(pkt["username"].startswith("p2603060_v1_testappid_chkey123_mb_"))
            self.assertEqual(len(pkt["password"]), 16)
            _wait_for(lambda: "smart/mb/in/dev1" in broker.subscribed)
            self.assertIn("p2603060/mb/u123", broker.subscribed)
        finally:
            asyncio.run(ev.close())
            broker.stop()

    def test_signed_json_push_decodes_to_event(self) -> None:
        broker = FakeBroker()
        events: list[DeviceEvent] = []
        ev = self._events_on_broker(broker, events)
        try:
            import asyncio

            asyncio.run(ev.connect())
            _wait_for(lambda: "smart/mb/in/dev1" in broker.subscribed)
            payload = build_payload_2_0(
                KEY, "2.0", {"dps": {"1": True}}, "dev1", 5, 1700000000
            )
            broker.push("smart/mb/in/dev1", payload)
            _wait_for(lambda: len(events) == 1)
            self.assertEqual(events[0].dev_id, "dev1")
            self.assertEqual(events[0].dps, {1: True})
            self.assertEqual(events[0].protocol, 5)
        finally:
            asyncio.run(ev.close())
            broker.stop()

    def test_bad_sign_reports_error_not_event(self) -> None:
        broker = FakeBroker()
        events: list[DeviceEvent] = []
        errors: list[tuple] = []
        ev = self._events_on_broker(broker, events)
        ev.listener._on_error = lambda t, c, m: errors.append((t, c, m))
        try:
            import asyncio

            asyncio.run(ev.connect())
            _wait_for(lambda: "smart/mb/in/dev1" in broker.subscribed)
            payload = build_payload_2_0(
                KEY, "2.0", {"dps": {"1": True}}, "dev1", 5, 1
            )
            obj = json.loads(payload)
            obj["sign"] = "0" * 32
            broker.push("smart/mb/in/dev1", json.dumps(obj).encode())
            _wait_for(lambda: len(errors) == 1)
            self.assertEqual(errors[0][1], "11004")
            self.assertEqual(events, [])
        finally:
            asyncio.run(ev.close())
            broker.stop()

    def test_duplicate_s_o_reports_repeat_error(self) -> None:
        # pv 2.2 binary frames carry s/o; a repeat hits the
        # isDataUpdated dedup → onError("12003", "cloud command repeat").
        broker = FakeBroker()
        events: list[DeviceEvent] = []
        errors: list[tuple] = []
        ev = self._events_on_broker(broker, events)
        ev.listener._on_error = lambda t, c, m: errors.append((t, c, m))
        try:
            import asyncio

            asyncio.run(ev.connect())
            _wait_for(lambda: "smart/mb/in/dev1" in broker.subscribed)
            payload = build_payload_2_2(
                KEY, "2.2", {"dps": {"1": True}, "devId": "dev1"}, 5, 1, 7, 42
            )
            broker.push("smart/mb/in/dev1", payload)
            broker.push("smart/mb/in/dev1", payload)
            _wait_for(lambda: len(events) == 1 and len(errors) == 1)
            self.assertEqual(errors[0][1], "12003")
            self.assertEqual(events[0].dps, {1: True})
        finally:
            asyncio.run(ev.close())
            broker.stop()


if __name__ == "__main__":
    unittest.main()
