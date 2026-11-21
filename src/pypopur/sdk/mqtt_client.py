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

# Retry delay after a link loss: first and maximum delay, in seconds,
# doubling between attempts until the session is back.
RECONNECT_BACKOFF_S = (5.0, 300.0)


# A session that drops sooner than this after CONNACK is a flap: wait
# before reconnecting instead of reconnecting at once.
FLAP_WINDOW_S = 10.0


# How long close() waits for a send in progress before it skips the
# DISCONNECT packet and shuts the socket down anyway.
CLOSE_SEND_WAIT_S = 1.0


def _close_socket(sock: Any, disconnect: bytes | None = None) -> None:
    """Best-effort DISCONNECT, shutdown (wakes a reader blocked in
    ``recv``) and close."""
    if sock is None:
        return
    if disconnect is not None:
        try:
            sock.sendall(disconnect)
        except OSError:
            pass
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, AttributeError):
        pass
    try:
        sock.close()
    except OSError:
        pass


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
        reconnect_backoff: tuple[float, float] = RECONNECT_BACKOFF_S,
    ) -> None:
        self.manager = manager
        self.config = config
        self.credentials = credentials
        self._clock_ms = clock_ms
        self._reconnect_interval = reconnect_interval_ms
        self._reconnect_backoff = reconnect_backoff
        self._connect_lock = threading.Lock()
        # Guards _closing/_connected/_sock between close() and a connect
        # that finishes its handshake; never held across network I/O.
        self._state_lock = threading.Lock()
        self._connected_at = 0.0
        # Set by close(): stops the reconnect loop and the pinger's wait.
        self._stop = threading.Event()
        self._generation = 0
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

    @property
    def read_timeout(self) -> float:
        """Post-CONNACK socket read timeout — 1.5×keepAlive, so a regular
        PINGREQ/PINGRESP exchange always lands inside it."""

        return max(float(self.config.time_out), float(self.config.keep_alive) * 1.5)

    def _next_packet_id(self) -> int:
        self._packet_id = (self._packet_id + 1) & 0xFFFF
        if self._packet_id == 0:
            self._packet_id = 1
        return self._packet_id

    def _read_exact(self, n: int, sock: Any = None) -> bytes:
        sock = sock if sock is not None else self._sock
        chunks = bytearray()
        while len(chunks) < n:
            part = sock.recv(n - len(chunks))  # type: ignore[union-attr]
            if not part:
                raise ConnectionError("socket closed")
            chunks.extend(part)
        return bytes(chunks)

    def _send(self, packet: bytes) -> None:
        with self._send_lock:
            sock = self._sock
            if sock is None:
                raise ConnectionError("mqtt is not connected")
            sock.sendall(packet)
            self._last_tx = time.monotonic()

    def _packet(self, header: int, body: bytes = b"") -> bytes:
        return bytes([header]) + _encode_remaining(len(body)) + body

    # -- lifecycle ------------------------------------------------------

    def connect(self) -> None:
        """``realConnect`` — CONNECT → CONNACK; raises MqttConnectError on
        a refusal return code. Idempotent when already connected.

        Re-arms a client that was closed: after a link loss the client
        keeps reconnecting on its own until :meth:`close`."""
        with self._state_lock:
            self._closing = False
            self._stop.clear()
        self._do_connect()

    def _do_connect(self) -> None:
        """One connect attempt, serialized with every other one (the
        reconnect loop, ``is_real_connect`` and callers may race). Never
        reopens a client that was closed.

        The status callbacks run once the connect lock is released (and,
        on success, once the reader is up): a callback may then wait for
        an ack or start another connect without deadlocking."""
        with self._connect_lock:
            if self._connected or self._closing:
                return
            try:
                connected = self._connect_once()
            except Exception as e:
                error = e
            else:
                error = None
        if error is not None:
            self._notify_connect_error(
                str(error.code if isinstance(error, MqttConnectError) else -1),
                str(error),
            )
            raise error
        # close() may have run since the session went up: a closed client
        # does not report a connection.
        if connected and self._connected and not self._closing:
            self._notify_connect_success()

    def _connect_once(self) -> bool:
        """CONNECT → CONNACK on a fresh socket, then start the reader and
        pinger. Returns False when :meth:`close` ran during the handshake:
        the new socket is closed instead of becoming a session nobody
        owns."""
        self._last_connect_attempt = self._clock_ms()
        sock = None
        try:
            host = self.config.host or ""
            port = self.config.port
            sock = self._sock_factory(host, port, float(self.config.time_out))

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

            def read(n: int) -> bytes:
                return self._read_exact(n, sock)

            sock.sendall(self._packet(_CONNECT, vh + payload))
            header = read(1)[0]
            if header >> 4 != _CONNACK >> 4:
                raise MqttConnectError(-1)
            body = read(_decode_remaining(read))
            rc = body[1]
            if rc != 0:
                raise MqttConnectError(rc)
            # ``time_out`` bounds the TCP/TLS handshake + CONNACK only. Once
            # the session is up the reader blocks between pushes; keeping
            # the handshake timeout there drops the link after every quiet
            # ``time_out`` window (pings only go out at 0.9×keepAlive).
            # Allow one missed PINGRESP before declaring the link dead.
            settimeout = getattr(sock, "settimeout", None)
            if settimeout is not None:
                settimeout(self.read_timeout)
        except Exception:
            _close_socket(sock)
            raise
        with self._state_lock:
            if self._closing:
                # close() ran during the handshake: drop this session.
                _close_socket(sock, disconnect=self._packet(_DISCONNECT))
                return False
            # The reader and pinger of an earlier session exit when they
            # see the generation move on, so a reconnect never runs two of
            # each.
            self._generation += 1
            generation = self._generation
            self._sock = sock
            self._last_tx = time.monotonic()
            self._connected_at = time.monotonic()
            self._connected = True
        self._last_rx = time.monotonic()
        self._reader = threading.Thread(
            target=self._reader_loop,
            args=(generation, sock),
            name="pypopur-mqtt-rx",
            daemon=True,
        )
        self._reader.start()
        self._pinger = threading.Thread(
            target=self._ping_loop,
            args=(generation,),
            name="pypopur-mqtt-ping",
            daemon=True,
        )
        self._pinger.start()
        return True

    def is_real_connect(self) -> bool:
        """``isRealConnect`` — flag plus the 120 s reconnect side effect."""
        ok = self._connected
        if not ok and (self._clock_ms() - self._last_connect_attempt > self._reconnect_interval):
            self._last_connect_attempt = self._clock_ms()
            self._try_reconnect()
        return ok

    def _try_reconnect(self) -> None:
        """``tryToConnect`` — best-effort reconnect; failures are logged,
        not raised (Java swallows into the connect-lost log). Never
        reopens a client that was closed."""
        try:
            self._do_connect()
        except Exception as err:
            log.warning("mqtt reconnect failed: %s", err)

    def _reconnect_loop(self, wait_first: bool = False) -> None:
        """Reconnect after a link loss until connected or closed.

        A single attempt is not enough: the link usually drops because the
        network or the broker is away, and the next attempt fails too.
        Nothing else retries (``is_real_connect`` only runs on a publish),
        so the session would stay down for good. Retries back off from
        ``reconnect_backoff[0]`` to ``reconnect_backoff[1]`` seconds.
        ``wait_first`` waits the first delay before trying: a session the
        broker drops right after accepting it is not hammered."""
        delay, max_delay = self._reconnect_backoff
        if wait_first and self._stop.wait(delay):
            return
        while not self._closing and not self._connected:
            try:
                self._do_connect()
            except Exception as err:
                log.warning("mqtt reconnect failed, retrying in %.1f s: %s", delay, err)
            else:
                if self._connected:
                    log.info("mqtt reconnected")
                return
            if self._stop.wait(delay):
                return
            delay = min(delay * 2, max_delay)

    def close(self) -> None:
        """``justClose``/``close`` — DISCONNECT then socket close; also
        stops a running reconnect loop and a connect in flight."""
        with self._state_lock:
            self._closing = True
            self._stop.set()
            self._connected = False
            sock = self._sock
            self._sock = None
        if sock is not None:
            # shutdown() wakes the reader blocked in recv(); a bare close()
            # leaves it there until the read timeout. DISCONNECT needs the
            # send lock so it does not interleave with another packet, but
            # a send stuck on a stalled peer must not hold close() up:
            # then skip DISCONNECT, and the shutdown also unblocks it.
            if self._send_lock.acquire(timeout=CLOSE_SEND_WAIT_S):
                try:
                    _close_socket(sock, disconnect=self._packet(_DISCONNECT))
                finally:
                    self._send_lock.release()
            else:
                _close_socket(sock)
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

    def _current(self, generation: int) -> bool:
        return self._generation == generation and self._connected and not self._closing

    def _reader_loop(self, generation: int, sock: Any) -> None:
        def read(n: int) -> bytes:
            return self._read_exact(n, sock)

        try:
            while self._current(generation):
                header = read(1)[0]
                remaining = _decode_remaining(read)
                body = read(remaining)
                self._last_rx = time.monotonic()
                self._dispatch_packet(header, body)
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            self._link_lost(generation, sock)

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

    def _ping_loop(self, generation: int) -> None:
        interval = max(1.0, float(self.config.keep_alive) * 0.9)
        while self._current(generation):
            if self._stop.wait(interval) or not self._current(generation):
                return
            try:
                self._send(self._packet(_PINGREQ))
            except OSError:
                return

    def _link_lost(self, generation: int, sock: Any) -> None:
        """The reader of session ``generation`` stopped reading ``sock``.

        Only that session's own socket is closed: a newer session may
        already own ``self._sock``."""
        with self._state_lock:
            current = generation == self._generation
            was = current and self._connected
            if current:
                self._connected = False
            closing = self._closing
            # Take this session's in-flight requests while still holding
            # the state lock: a newer session can only go up after this,
            # so its requests land in the fresh map and are not failed.
            pending: dict[int, tuple[int, Callable]] = {}
            if was and not closing:
                pending, self._pending = self._pending, {}
        _close_socket(sock)
        if not was or closing:
            return
        for _, resolve in pending.values():
            try:
                resolve(False, None)
            except Exception:
                pass
        flapped = time.monotonic() - self._connected_at < FLAP_WINDOW_S
        log.info("mqtt link lost, reconnecting")
        self._reconnect_loop(wait_first=flapped)
