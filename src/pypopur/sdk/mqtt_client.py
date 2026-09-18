"""Concrete MQTT 3.1.1 wire client — the ``pqpbdqq``/vendored-Paho layer.

``MqttServerManager`` (``bqbppdq``) models the session bookkeeping; this
module is the transport underneath it: TLS socket, CONNECT/CONNACK,
SUBSCRIBE/SUBACK, QoS-0/1 PUBLISH/PUBACK, PINGREQ keepalive, and the
``isRealConnect``/reconnect policy.

Wire-parity notes taken from smali:

- Server URL ``ssl://host:8883`` (``MqttConfigBean``).
- CONNECT: cleanSession, keepAlive=60 s, clientId/username/password from
  the beans/``SdkMqttCredentials``, will = ``tuya/smart/will`` (empty
  payload).
- ``isRealConnect()`` is not just a flag — when the link is down and the
  last connect attempt is older than 120 s it *triggers* ``tryToConnect``
  as a side effect (pqpbdqq 3109-3149).
- ``publishDevice`` frames are QoS-1 PUBLISH to ``smart/mb/out/{id}``;
  the IResultCallback resolves on PUBACK.
- ``subscribe`` marks each requested topic ``TRUE`` on SUBACK
  (``$pbpdpdp.onSuccess``); the pending-FALSE bookkeeping lives in
  ``MqttServerManager.subscribe``.
- Inbound PUBLISH → ``manager.parse_message(topic, payload)``; QoS-1
  inbound is PUBACK'd.
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable
from typing import Any

from .mqtt_session import MqttConfigBean, MqttServerManager

log = logging.getLogger(__name__)

# MQTT 3.1.1 packet types
_CONNECT = 0x10
_CONNACK = 0x20
_PUBLISH = 0x30
_PUBACK = 0x40
_PUBREC = 0x50
_PUBREL = 0x60
_PUBCOMP = 0x70
_SUBSCRIBE = 0x82
_SUBACK = 0x90
_UNSUBSCRIBE = 0xA2
_UNSUBACK = 0xB0
_PINGREQ = 0xC0
_PINGRESP = 0xD0
_DISCONNECT = 0xE0

# pqpbdqq.isRealConnect — reconnect only when the last attempt is older.
RECONNECT_MIN_INTERVAL_MS = 0x1D4C0  # 120_000


def _encode_remaining(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _decode_remaining(read: Callable[[int], bytes]) -> int:
    multiplier, value = 1, 0
    while True:
        b = read(1)[0]
        value += (b & 0x7F) * multiplier
        if not (b & 0x80):
            return value
        multiplier *= 128
        if multiplier > 128 * 128 * 128 * 128:
            raise ValueError("malformed remaining length")


def _encode_string(s: str) -> bytes:
    data = s.encode()
    return struct.pack(">H", len(data)) + data


def _encode_binary(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


class MqttConnectError(Exception):
    """CONNACK failure — carries the broker return code."""

    def __init__(self, code: int) -> None:
        super().__init__(f"MQTT connect refused (rc={code})")
        self.code = code


class MqttWireClient:
    """``pqdbppq`` + ``pqpbdqq`` — the wire half of ``MqttServerManager``.

    ``manager`` receives inbound messages and subscription bookkeeping;
    ``credentials`` supplies username()/password()/user_topic();
    ``config`` supplies clientId/host/port/keepAlive/will.

    ``sock_factory`` (``(host, port, timeout) -> socket-like``) is the
    injectable transport seam — tests pass a fake broker without TLS.
    """

    def __init__(
        self,
        manager: MqttServerManager,
        config: MqttConfigBean,
        credentials: Any,
        *,
        sock_factory: Callable | None = None,
        tls_context: ssl.SSLContext | None = None,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
        reconnect_interval_ms: int = RECONNECT_MIN_INTERVAL_MS,
    ) -> None:
        self.manager = manager
        self.config = config
        self.credentials = credentials
        self._clock_ms = clock_ms
        self._reconnect_interval = reconnect_interval_ms
        self._sock_factory = sock_factory or self._default_sock_factory
        self._tls_context = tls_context

        self._sock: socket.socket | None = None
        self._connected = False
        self._closing = False
        self._last_connect_attempt = 0
        self._packet_id = 0
        self._send_lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._pinger: threading.Thread | None = None
        # packetId -> (expected_type, resolve) for in-flight requests
        self._pending: dict[int, tuple[int, Callable]] = {}
        self._last_rx = 0.0
        self._last_tx = 0.0
        self._status_callbacks: list[Any] = []

        # Wire the session seams.
        self.manager.publish_fn = self.publish
        self.manager.is_real_connect = self.is_real_connect

    # -- transport -----------------------------------------------------

    def _default_sock_factory(self, host: str, port: int, timeout: float):
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = self._tls_context
        if ctx is None:
            ctx = ssl.create_default_context()
        return ctx.wrap_socket(raw, server_hostname=host)

    def _next_packet_id(self) -> int:
        self._packet_id = (self._packet_id + 1) & 0xFFFF
        if self._packet_id == 0:
            self._packet_id = 1
        return self._packet_id

    def _read_exact(self, n: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < n:
            part = self._sock.recv(n - len(chunks))  # type: ignore[union-attr]
            if not part:
                raise ConnectionError("socket closed")
            chunks.extend(part)
        return bytes(chunks)

    def _send(self, packet: bytes) -> None:
        with self._send_lock:
            self._sock.sendall(packet)  # type: ignore[union-attr]
            self._last_tx = time.monotonic()

    def _packet(self, header: int, body: bytes = b"") -> bytes:
        return bytes([header]) + _encode_remaining(len(body)) + body

    # -- lifecycle ------------------------------------------------------

    def connect(self) -> None:
        """``realConnect`` — CONNECT → CONNACK; raises MqttConnectError on
        a refusal return code. Idempotent when already connected."""
        if self._connected:
            return
        self._last_connect_attempt = self._clock_ms()
        self._closing = False
        try:
            host = self.config.host or ""
            port = self.config.port
            sock = self._sock_factory(host, port, float(self.config.time_out))
            self._sock = sock

            flags = 0x02  # cleanSession
            will_payload = b""
            will_topic = self.config.will_topic or ""
            payload = _encode_string(self.config.client_id or "")
            if will_topic:
                flags |= 0x04
                payload += _encode_string(will_topic) + _encode_binary(will_payload)
            username = self.credentials.username() if self.credentials else ""
            password = self.credentials.password() if self.credentials else ""
            flags |= 0x80  # username
            payload += _encode_string(username)
            flags |= 0x40  # password
            payload += _encode_binary(password.encode())
            vh = (
                _encode_string("MQTT")
                + bytes([0x04, flags])
                + struct.pack(">H", int(self.config.keep_alive))
            )
            self._send(self._packet(_CONNECT, vh + payload))
            header = self._read_exact(1)[0]
            if header >> 4 != _CONNACK >> 4:
                raise MqttConnectError(-1)
            body = self._read_exact(_decode_remaining(self._read_exact))
            rc = body[1]
            if rc != 0:
                raise MqttConnectError(rc)
        except Exception as e:
            self._notify_connect_error(
                str(e.code if isinstance(e, MqttConnectError) else -1), str(e)
            )
            raise
        self._connected = True
        self._notify_connect_success()
        self._last_rx = time.monotonic()
        self._reader = threading.Thread(
            target=self._reader_loop, name="pypopur-mqtt-rx", daemon=True
        )
        self._reader.start()
        self._pinger = threading.Thread(
            target=self._ping_loop, name="pypopur-mqtt-ping", daemon=True
        )
        self._pinger.start()

    def is_real_connect(self) -> bool:
        """``isRealConnect`` — flag plus the 120 s reconnect side effect."""
        ok = self._connected
        if not ok and (self._clock_ms() - self._last_connect_attempt > self._reconnect_interval):
            self._last_connect_attempt = self._clock_ms()
            self._try_reconnect()
        return ok

    def _try_reconnect(self) -> None:
        """``tryToConnect`` — best-effort reconnect; failures are logged,
        not raised (Java swallows into the connect-lost log)."""
        try:
            self.connect()
        except Exception:
            log.exception("mqtt reconnect failed")

    def close(self) -> None:
        """``justClose``/``close`` — DISCONNECT then socket close."""
        self._closing = True
        self._connected = False
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                with self._send_lock:
                    sock.sendall(self._packet(_DISCONNECT))
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        # Fail everything in flight.
        pending, self._pending = self._pending, {}
        for _, resolve in pending.values():
            try:
                resolve(False, None)
            except Exception:
                pass

    @property
    def connected(self) -> bool:
        return self._connected

    # -- IMqttServerStatusCallback seam -----------------------------------

    def register_mqtt_callback(self, cb: Any) -> None:
        """``IMqttServer.registerMqttCallback`` — ``on_connect_success()``/
        ``on_connect_error(code, error)`` fired from ``connect()``."""
        if cb not in self._status_callbacks:
            self._status_callbacks.append(cb)

    def _notify_connect_success(self) -> None:
        for cb in list(self._status_callbacks):
            try:
                cb.on_connect_success()
            except Exception:
                pass

    def _notify_connect_error(self, code: str, error: str) -> None:
        for cb in list(self._status_callbacks):
            try:
                cb.on_connect_error(code, error)
            except Exception:
                pass

    # -- subscribe / publish -------------------------------------------

    def subscribe(
        self,
        topics: list[str],
        qoses: list[int] | None = None,
        cb: Any = None,
    ) -> None:
        """``mqtt.subscribe`` — pending bookkeeping via
        ``manager.subscribe`` then SUBSCRIBE for the remainder; SUBACK
        marks each topic ``TRUE`` and resolves ``cb``."""
        pending = self.manager.subscribe(topics, qoses or [0] * len(topics))
        if not pending:
            if cb is not None:
                cb.on_success()
            return
        if not self._connected:
            if cb is not None:
                cb.on_error("6000", "mqtt is not connect")
            return
        qos_map = dict(zip(topics, qoses or [0] * len(topics)))
        body = struct.pack(">H", (pid := self._next_packet_id()))
        for t in pending:
            body += _encode_string(t) + bytes([qos_map.get(t, 0) & 0x3])

        def resolve(ok: bool, data: bytes | None) -> None:
            if ok:
                for t in pending:
                    self.manager.mark_subscribe(t, True)
                if cb is not None:
                    cb.on_success()
            elif cb is not None:
                cb.on_error("6000", "subscribe failed")

        self._pending[pid] = (_SUBACK, resolve)
        self._send(self._packet(_SUBSCRIBE, body))

    def unsubscribe(self, topics: list[str], cb: Any = None) -> None:
        if not self._connected:
            if cb is not None:
                cb.on_error("6000", "mqtt is not connect")
            return
        body = struct.pack(">H", (pid := self._next_packet_id()))
        for t in topics:
            body += _encode_string(t)

        def resolve(ok: bool, data: bytes | None) -> None:
            if ok:
                for t in topics:
                    self.manager.mark_unsubscribe(t)
                if cb is not None:
                    cb.on_success()
            elif cb is not None:
                cb.on_error("6000", "unsubscribe failed")

        self._pending[pid] = (_UNSUBACK, resolve)
        self._send(self._packet(_UNSUBSCRIBE, body))

    def publish(
        self,
        topic: str,
        payload: bytes,
        cb: Any = None,
        qos: int = 1,
        retain: bool = False,
    ) -> None:
        """``mqtt.publish`` — QoS-1 default; ``cb`` resolves on PUBACK."""
        if not self._connected:
            if cb is not None:
                cb.on_error("6000", "mqtt is not connect")
            return
        header = _PUBLISH | (qos << 1) | (0x01 if retain else 0)
        body = _encode_string(topic)
        pid = 0
        if qos:
            pid = self._next_packet_id()
            body += struct.pack(">H", pid)
        body += payload
        if qos == 1:

            def resolve(ok: bool, data: bytes | None) -> None:
                if cb is not None:
                    cb.on_success() if ok else cb.on_error("6000", "publish failed")

            self._pending[pid] = (_PUBACK, resolve)
        elif qos == 2:

            def resolve(ok: bool, data: bytes | None) -> None:
                if cb is not None:
                    cb.on_success() if ok else cb.on_error("6000", "publish failed")

            self._pending[pid] = (_PUBREC, resolve)
        try:
            self._send(self._packet(header, body))
        except OSError:
            self._pending.pop(pid, None)
            if cb is not None:
                cb.on_error("6000", "publish failed")

    # -- reader / keepalive ---------------------------------------------

    def _reader_loop(self) -> None:
        try:
            while self._connected and not self._closing:
                header = self._read_exact(1)[0]
                remaining = _decode_remaining(self._read_exact)
                body = self._read_exact(remaining)
                self._last_rx = time.monotonic()
                self._dispatch_packet(header, body)
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            self._link_lost()

    def _dispatch_packet(self, header: int, body: bytes) -> None:
        ptype = header >> 4
        flags = header & 0x0F
        if ptype == _PUBLISH >> 4:
            topic_len = struct.unpack(">H", body[:2])[0]
            topic = body[2 : 2 + topic_len].decode()
            rest = body[2 + topic_len :]
            qos = (flags >> 1) & 0x3
            if qos == 1:
                pid = struct.unpack(">H", rest[:2])[0]
                rest = rest[2:]
                self._send(self._packet(_PUBACK, struct.pack(">H", pid)))
            elif qos == 2:
                pid = struct.unpack(">H", rest[:2])[0]
                rest = rest[2:]
                self._send(self._packet(_PUBREC, struct.pack(">H", pid)))
            try:
                self.manager.parse_message(topic, rest)
            except Exception:
                log.exception("parseMessage")
            return
        if ptype == _PUBREC >> 4:
            pid = struct.unpack(">H", body[:2])[0]
            self._send(self._packet(_PUBREL | 0x02, struct.pack(">H", pid)))
            self._pending[pid] = (_PUBCOMP, self._pending.pop(pid, (0, lambda *_: None))[1])
            return
        if ptype == _PINGRESP >> 4:
            return
        # Ack types: CONNACK, PUBACK, PUBCOMP, SUBACK, UNSUBACK
        pid = struct.unpack(">H", body[:2])[0] if len(body) >= 2 else -1
        pending = self._pending.pop(pid, None)
        if pending is None:
            return
        expected, resolve = pending
        ok = ptype == expected >> 4
        try:
            resolve(ok, body)
        except Exception:
            log.exception("mqtt resolve")

    def _ping_loop(self) -> None:
        interval = max(1.0, float(self.config.keep_alive) * 0.9)
        while self._connected and not self._closing:
            time.sleep(interval)
            if not self._connected or self._closing:
                return
            try:
                self._send(self._packet(_PINGREQ))
            except OSError:
                return

    def _link_lost(self) -> None:
        was = self._connected
        self._connected = False
        if not was or self._closing:
            return
        pending, self._pending = self._pending, {}
        for _, resolve in pending.values():
            try:
                resolve(False, None)
            except Exception:
                pass
        try:
            self._sock.close()  # type: ignore[union-attr]
        except Exception:
            pass
        self._try_reconnect()
