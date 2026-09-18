"""End-to-end tests for sdk/mqtt_client.py over a fake broker socket."""

from __future__ import annotations

import json
import socket
import struct
import threading
import time

from pypopur.sdk.mqtt_client import MqttWireClient
from pypopur.sdk.mqtt_session import MqttConfigBean, MqttServerManager


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
    """Minimal MQTT 3.1.1 broker: CONNACK/SUBACK/PUBACK + inbound push."""

    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.port = self.listener.getsockname()[1]
        self.conn: socket.socket | None = None
        self.connect_packet: dict = {}
        self.published: list[tuple[str, bytes]] = []
        self.subscribed: list[str] = []
        self.connect_count = 0
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
            self.connect_count += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            # CONNECT
            header = self._read_exact(conn, 1)[0]
            assert header >> 4 == 1
            body = self._read_exact(conn, self._read_remaining(conn))
            self.connect_packet = self._parse_connect(body)
            conn.sendall(_packet(0x20, b"\x00\x00"))
            while True:
                header = self._read_exact(conn, 1)[0]
                body = self._read_exact(conn, self._read_remaining(conn))
                ptype, flags = header >> 4, header & 0x0F
                if ptype == 8:  # SUBSCRIBE
                    pid = struct.unpack(">H", body[:2])[0]
                    pos = 2
                    while pos < len(body):
                        tl = struct.unpack(">H", body[pos : pos + 2])[0]
                        self.subscribed.append(body[pos + 2 : pos + 2 + tl].decode())
                        pos += 2 + tl + 1
                    conn.sendall(_packet(0x90, struct.pack(">H", pid) + b"\x01"))
                elif ptype == 3:  # PUBLISH
                    tl = struct.unpack(">H", body[:2])[0]
                    topic = body[2 : 2 + tl].decode()
                    rest = body[2 + tl :]
                    if (flags >> 1) & 3:
                        pid = struct.unpack(">H", rest[:2])[0]
                        rest = rest[2:]
                        conn.sendall(_packet(0x40, struct.pack(">H", pid)))
                    self.published.append((topic, rest))
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
        proto = body[2 : 2 + proto_len].decode()
        pos = 2 + proto_len
        level, flags = body[pos], body[pos + 1]
        keepalive = struct.unpack(">H", body[pos + 2 : pos + 4])[0]
        pos += 4

        def rd_str(p: int) -> tuple[str, int]:
            tl = struct.unpack(">H", body[p : p + 2])[0]
            return body[p + 2 : p + 2 + tl].decode(), p + 2 + tl

        client_id, pos = rd_str(pos)
        out = {
            "proto": proto,
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

    def push(self, topic: str, payload: bytes, qos: int = 0) -> None:
        body = _enc_str(topic) + payload
        self.conn.sendall(_packet(0x30 | (qos << 1), body))

    def stop(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        finally:
            self.listener.close()


def _client(broker: FakeBroker, tag: str = "t1") -> tuple[MqttServerManager, MqttWireClient]:
    manager = MqttServerManager(tag)
    config = MqttConfigBean(
        client_id="pkg_mb_dev-tag_tag",
        host="127.0.0.1",
        port=broker.port,
        keep_alive=60,
    )

    class Creds:
        def username(self) -> str:
            return "pid_v1_appid_chkey_mb_tokAAAA"

        def password(self) -> str:
            return "pass16charsXXXXX"

        def user_topic(self) -> str:
            return "pid/mb/uid"

    client = MqttWireClient(
        manager,
        config,
        Creds(),
        sock_factory=lambda h, p, t: socket.create_connection((h, p), timeout=t),
    )
    return manager, client


def _wait_for(pred, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met")


class Cb:
    def __init__(self) -> None:
        self.ok = False
        self.error: tuple | None = None
        self.event = threading.Event()

    def on_success(self) -> None:
        self.ok = True
        self.event.set()

    def on_error(self, code: str, msg) -> None:
        self.error = (code, msg)
        self.event.set()


def test_connect_packet_shape() -> None:
    broker = FakeBroker()
    _manager, client = _client(broker)
    try:
        client.connect()
        assert client.connected
        pkt = broker.connect_packet
        assert pkt["proto"] == "MQTT" and pkt["level"] == 4
        assert pkt["flags"] & 0x02  # cleanSession
        assert pkt["flags"] & 0x04  # will flag
        assert pkt["will_topic"] == "tuya/smart/will"
        assert pkt["keepalive"] == 60
        assert pkt["client_id"] == "pkg_mb_dev-tag_tag"
        assert pkt["username"] == "pid_v1_appid_chkey_mb_tokAAAA"
        assert pkt["password"] == b"pass16charsXXXXX"
    finally:
        client.close()
        broker.stop()


def test_subscribe_marks_and_publish_qos1() -> None:
    broker = FakeBroker()
    manager, client = _client(broker)
    try:
        client.connect()
        cb = Cb()
        client.subscribe(["smart/mb/in/dev1"], [1], cb)
        assert cb.event.wait(3) and cb.ok
        assert manager.is_subscribe("smart/mb/in/dev1") is True
        assert broker.subscribed == ["smart/mb/in/dev1"]

        # publish_device → smart/mb/out/<topicId> QoS1
        from pypopur.sdk.mqtt_session import MqttControlBuilder

        manager.is_real_connect = client.is_real_connect
        pcb = Cb()
        manager.publish_device(
            MqttControlBuilder(
                data={"dps": {"1": True}},
                local_key="0123456789abcdef",
                pv="2.2",
                protocol=4,
                topic_id="dev1",
                t=1700000000,
                s=1,
                o=0,
            ),
            pcb,
        )
        assert pcb.event.wait(3), "publish cb never fired"
        _wait_for(lambda: len(broker.published) == 1)
        topic, payload = broker.published[0]
        assert topic == "smart/mb/out/dev1"
        assert payload  # framed by mqtt_framing.build_mqtt_publish
    finally:
        client.close()
        broker.stop()


def test_inbound_publish_routed_to_parse_message() -> None:
    broker = FakeBroker()
    manager, client = _client(broker)
    got: list[tuple[str, int, dict]] = []

    class Listener:
        def on_mqtt_dp_received_success(self, topic, protocol, obj):
            got.append((topic, protocol, obj))

        def on_mqtt_dp_received_error(self, topic, code, msg):
            raise AssertionError(f"{code}: {msg}")

        def get_topic_suffix(self):
            return ["smart/mb/in/"]

        def get_local_key(self, dev):
            return "0123456789abcdef"

        def is_data_updated(self, topic_id, s, o):
            return False

    manager.message_listeners.append(Listener())
    try:
        client.connect()
        # tylink/ messages are JSON-parsed directly
        broker.push("tylink/dev1/thing/event", json.dumps({"x": 1}).encode())
        _wait_for(lambda: len(got) == 1)
        assert got[0][0] == "tylink/dev1/thing/event"
        assert got[0][2] == {"x": 1}
    finally:
        client.close()
        broker.stop()


def test_is_real_connect_reconnect_side_effect() -> None:
    broker = FakeBroker()
    _manager, client = _client(broker)
    attempts: list[int] = []
    orig = client.connect

    def counted():
        attempts.append(1)
        return orig()

    client.connect = counted  # type: ignore[assignment]
    try:
        client.connect()
        # connected → no reconnect attempt
        assert client.is_real_connect() is True
        assert len(attempts) == 1
        # drop the link
        client._connected = False
        client._last_connect_attempt = 0  # force > 120 s ago
        client.is_real_connect()
        _wait_for(lambda: client.connected)
        assert len(attempts) == 2
    finally:
        client.close()
        broker.stop()


def test_publish_device_offline_error() -> None:
    manager = MqttServerManager("t9")
    manager.is_real_connect = lambda: False
    cb = Cb()
    manager.publish_device(object(), cb)  # non-null builder
    assert cb.error == ("6000", "mqtt is not connect")
