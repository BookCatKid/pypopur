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
    orig = client._do_connect

    def counted():
        attempts.append(1)
        return orig()

    client._do_connect = counted  # type: ignore[method-assign]
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


def _flaky_client(broker: FakeBroker, failures: int) -> tuple[MqttWireClient, list[int]]:
    """A client whose socket factory refuses ``failures`` connects after
    the first one, like a network that is away for a while."""

    manager = MqttServerManager("t-flaky")
    config = MqttConfigBean(
        client_id="pkg_mb_dev-tag_tag",
        host="127.0.0.1",
        port=broker.port,
        keep_alive=60,
    )

    class Creds:
        def username(self) -> str:
            return "u"

        def password(self) -> str:
            return "p"

        def user_topic(self) -> str:
            return "pid/mb/uid"

    calls: list[int] = []

    def factory(h, p, t):
        calls.append(1)
        if 1 < len(calls) <= 1 + failures:
            raise OSError("network unreachable")
        return socket.create_connection((h, p), timeout=t)

    client = MqttWireClient(
        manager,
        config,
        Creds(),
        sock_factory=factory,
        reconnect_backoff=(0.05, 0.2),
    )
    return client, calls


def _drop_link(broker: FakeBroker) -> None:
    # shutdown() sends the FIN; a bare close() under a blocked recv() does not.
    broker.conn.shutdown(socket.SHUT_RDWR)
    broker.conn.close()


def test_link_loss_keeps_retrying_until_reconnected() -> None:
    """Regression: a link loss used to try one reconnect only; when that
    failed (network still down) the session stayed dead for good."""

    broker = FakeBroker()
    client, calls = _flaky_client(broker, failures=3)
    try:
        client.connect()
        _wait_for(lambda: broker.connect_count == 1)
        _drop_link(broker)
        # _connected flips before the new reader starts: wait for both.
        _wait_for(
            lambda: (
                client.connected
                and broker.connect_count == 2
                and client._reader is not None
                and client._reader.is_alive()
            )
        )
        assert len(calls) == 5  # first connect, 3 refused, then back
    finally:
        client.close()
        broker.stop()


def test_close_stops_reconnect_loop() -> None:
    broker = FakeBroker()
    client, calls = _flaky_client(broker, failures=10_000)
    try:
        client.connect()
        _wait_for(lambda: broker.connect_count == 1)
        _drop_link(broker)
        _wait_for(lambda: len(calls) >= 3)
        client.close()
        time.sleep(0.3)
        settled = len(calls)
        time.sleep(0.5)
        assert len(calls) == settled
        assert not client.connected
    finally:
        broker.stop()


def test_close_during_connect_drops_the_new_session() -> None:
    """close() while a (re)connect is in its handshake must not leave a
    session behind: no connect callback, socket closed, not connected."""

    broker = FakeBroker()
    manager = MqttServerManager("t-close-race")
    config = MqttConfigBean(
        client_id="pkg_mb_dev-tag_tag",
        host="127.0.0.1",
        port=broker.port,
        keep_alive=60,
    )

    class Creds:
        def username(self) -> str:
            return "u"

        def password(self) -> str:
            return "p"

        def user_topic(self) -> str:
            return "pid/mb/uid"

    entered = threading.Event()
    release = threading.Event()
    socks: list[socket.socket] = []

    def factory(h, p, t):
        entered.set()
        release.wait(5)
        sock = socket.create_connection((h, p), timeout=t)
        socks.append(sock)
        return sock

    client = MqttWireClient(manager, config, Creds(), sock_factory=factory)
    connects: list[int] = []

    class Status:
        def on_connect_success(self) -> None:
            connects.append(1)

        def on_connect_error(self, code: str, error: str) -> None:
            pass

    client.register_mqtt_callback(Status())
    worker = threading.Thread(target=client.connect, daemon=True)
    try:
        worker.start()
        assert entered.wait(5)
        client.close()  # lands during the handshake
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert not client.connected
        assert connects == []
        assert client._sock is None
        assert socks and socks[0].fileno() == -1  # closed
    finally:
        release.set()
        client.close()
        broker.stop()


def test_close_wakes_the_reader() -> None:
    broker = FakeBroker()
    _manager, client = _client(broker, tag="t-close-wake")
    try:
        client.connect()
        reader = client._reader
        assert reader is not None and reader.is_alive()
        client.close()
        reader.join(2)
        assert not reader.is_alive()
    finally:
        broker.stop()


def test_flapping_session_waits_before_reconnecting() -> None:
    """A session the broker drops right after CONNACK is retried after
    one backoff step, not at once."""

    broker = FakeBroker()
    client, _calls = _flaky_client(broker, failures=0)
    client._reconnect_backoff = (0.5, 1.0)
    try:
        client.connect()
        _wait_for(lambda: broker.connect_count == 1)
        dropped = time.monotonic()
        _drop_link(broker)
        _wait_for(lambda: broker.connect_count == 2)
        assert time.monotonic() - dropped >= 0.45
    finally:
        client.close()
        broker.stop()


def test_connect_error_callback_may_connect_again() -> None:
    """The error callback runs outside the connect lock: retrying from it
    must not deadlock."""

    broker = FakeBroker()
    client, calls = _flaky_client(broker, failures=0)
    # Refuse the very first connect only.
    factory = client._sock_factory

    def refuse_first(h, p, t):
        if not calls:
            calls.append(0)
            raise OSError("network unreachable")
        return factory(h, p, t)

    client._sock_factory = refuse_first
    retried: list[int] = []

    class Status:
        def on_connect_success(self) -> None:
            pass

        def on_connect_error(self, code: str, error: str) -> None:
            if not retried:
                retried.append(1)
                client.connect()

    client.register_mqtt_callback(Status())
    errors: list[BaseException] = []

    def run() -> None:
        try:
            client.connect()
        except OSError as err:
            errors.append(err)

    worker = threading.Thread(target=run, daemon=True)
    try:
        worker.start()
        worker.join(5)
        assert not worker.is_alive()
        assert retried == [1]
        assert len(errors) == 1  # the outer attempt still reports its error
        assert client.connected
    finally:
        client.close()
        broker.stop()


def test_close_does_not_wait_for_a_stuck_send() -> None:
    broker = FakeBroker()
    _manager, client = _client(broker, tag="t-close-stuck")
    try:
        client.connect()
        reader = client._reader
        client._send_lock.acquire()  # a send blocked on a stalled peer
        try:
            started = time.monotonic()
            client.close()
            assert time.monotonic() - started < 3
        finally:
            client._send_lock.release()
        assert reader is not None
        reader.join(2)
        assert not reader.is_alive()
    finally:
        broker.stop()


def test_link_loss_keeps_requests_of_a_newer_session(monkeypatch) -> None:
    """A session that comes up while the old reader is still cleaning up
    keeps its in-flight requests."""

    from pypopur.sdk import mqtt_client

    broker = FakeBroker()
    client, _calls = _flaky_client(broker, failures=0)
    results: list[bool] = []
    real_close = mqtt_client._close_socket
    old_sock: list[object] = []

    def close_and_race(sock, disconnect=None):
        real_close(sock, disconnect)
        if old_sock and sock is old_sock[0]:
            old_sock.clear()
            # A connect() from another caller wins the race here.
            client._do_connect()
            client._pending[999] = (0x90, lambda ok, _d: results.append(ok))

    monkeypatch.setattr(mqtt_client, "_close_socket", close_and_race)
    try:
        client.connect()
        _wait_for(lambda: broker.connect_count == 1)
        old_sock.append(client._sock)
        _drop_link(broker)
        _wait_for(lambda: broker.connect_count == 2 and not old_sock)
        time.sleep(0.2)
        assert results == []
        assert 999 in client._pending
    finally:
        client.close()
        broker.stop()


def test_publish_device_offline_error() -> None:
    manager = MqttServerManager("t9")
    manager.is_real_connect = lambda: False
    cb = Cb()
    manager.publish_device(object(), cb)  # non-null builder
    assert cb.error == ("6000", "mqtt is not connect")


def test_idle_session_outlives_handshake_timeout() -> None:
    """Regression: the handshake ``time_out`` used to stay on the socket,
    so the reader timed out after every quiet window and reconnected
    (~every 16 s live), dropping pushes in the gap."""

    broker = FakeBroker()
    manager = MqttServerManager("t-idle")
    config = MqttConfigBean(
        client_id="pkg_mb_dev-tag_tag",
        host="127.0.0.1",
        port=broker.port,
        keep_alive=60,
        time_out=0.2,  # handshake timeout far below the idle window
    )

    class Creds:
        def username(self) -> str:
            return "u"

        def password(self) -> str:
            return "p"

        def user_topic(self) -> str:
            return "pid/mb/uid"

    client = MqttWireClient(
        manager,
        config,
        Creds(),
        sock_factory=lambda h, p, t: socket.create_connection((h, p), timeout=t),
    )
    try:
        client.connect()
        time.sleep(1.0)  # 5× the handshake timeout with no traffic
        assert client.connected
        assert broker.connect_count == 1
        assert client.read_timeout == 90.0
    finally:
        client.close()
        broker.stop()
