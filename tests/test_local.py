from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import threading
import time
import unittest
from typing import Any

from pypopur.exceptions import (
    HandshakeError,
    MissingLocalKey,
    ProtocolError,
    TransportError,
)
from pypopur.local import LocalDeviceConfig, LocalTuyaTransport
from pypopur.sdk.crypto import aes_ecb_decrypt, aes_ecb_encrypt
from pypopur.sdk.lan_socket import (
    SESS_KEY_NEG_FINISH,
    SESS_KEY_NEG_RESP,
    SESS_KEY_NEG_START,
    SocketThingNetworkApi,
    _ecb_nopad_encrypt,
    pack_55aa,
    read_frame,
)

REAL_KEY = "0123456789abcdef"

DP_QUERY = 0x0A
CONTROL = 0x07
STATUS = 0x08
HEART_BEAT = 0x09


def _wait_for(pred, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met within timeout")


class FakeDevice34:
    """Simulated lpv=3.4 device: session-key exchange, then answers
    DP_QUERY with a scripted ``{dps:...}`` body and records CONTROL
    payload inners (post session-ECB decrypt)."""

    def __init__(self, key: bytes, status_dps: dict | None = None) -> None:
        self.key = key
        self.session_key: bytes | None = None
        self.remote_nonce = bytes(range(0xA0, 0xB0))
        self.status_dps = status_dps if status_dps is not None else {"1": True}
        self.received: list[tuple[int, bytes]] = []
        self.control_inners: list[dict] = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.conn: socket.socket | None = None
        self.buf = bytearray()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _read(self, key: bytes):
        seq, cmd, _retcode, payload, ok = read_frame(self.conn, self.buf, key, no_retcode=True)
        if not ok:
            raise AssertionError("bad frame")
        return seq, cmd, payload

    def _run(self) -> None:
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return  # listener closed before any connection
        self.conn = conn
        _, cmd, payload = self._read(self.key)
        assert cmd == SESS_KEY_NEG_START
        local = aes_ecb_decrypt(self.key, payload)
        resp = self.remote_nonce + hmac.new(self.key, local, hashlib.sha256).digest()
        conn.sendall(
            pack_55aa(1, SESS_KEY_NEG_RESP, aes_ecb_encrypt(self.key, resp), self.key, retcode=0)
        )
        _, cmd, payload = self._read(self.key)
        assert cmd == SESS_KEY_NEG_FINISH
        finish = aes_ecb_decrypt(self.key, payload)
        assert finish == hmac.new(self.key, self.remote_nonce, hashlib.sha256).digest()
        xored = bytes(a ^ b for a, b in zip(local, self.remote_nonce))
        self.session_key = _ecb_nopad_encrypt(self.key, xored)[:16]
        while True:
            try:
                _, cmd, payload = self._read(self.session_key)
            except Exception:  # noqa: BLE001
                return
            inner = aes_ecb_decrypt(self.session_key, payload)
            self.received.append((cmd, inner))
            if cmd == DP_QUERY:
                # The app's queryDps sends {"gwId":..,"devId":..} raw JSON;
                # the device answers with a raw {"dps":{...}} body.
                body = json.dumps({"dps": self.status_dps}).encode()
                conn.sendall(
                    pack_55aa(
                        2,
                        DP_QUERY,
                        aes_ecb_encrypt(self.session_key, body),
                        self.session_key,
                        retcode=0,
                    )
                )
            elif cmd == CONTROL:
                obj = json.loads(inner[15:].decode())
                self.control_inners.append(obj)

    def push_status(self, dps: dict) -> None:
        """Send a spontaneous STATUS push (3.4 wrapped inner)."""
        inner = (
            b"3.4"
            + b"\x00" * 4
            + (1).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + json.dumps({"protocol": 5, "data": {"dps": dps}, "t": int(time.time())}).encode()
        )
        self.conn.sendall(
            pack_55aa(
                3,
                STATUS,
                aes_ecb_encrypt(self.session_key, inner),
                self.session_key,
                retcode=0,
            )
        )

    def stop(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        finally:
            self.listener.close()


def _transport(dev: FakeDevice34, **kw: Any) -> LocalTuyaTransport:
    api = SocketThingNetworkApi(port=dev.port)
    return LocalTuyaTransport(
        "127.0.0.1",
        "dev",
        REAL_KEY,
        api=api,
        protocol_version="3.4",
        timeout=3.0,
        **kw,
    )


class LocalTransportTests(unittest.IsolatedAsyncioTestCase):
    def test_local_key_never_appears_in_config_repr(self) -> None:
        config = LocalDeviceConfig("192.0.2.1", "dev", "top-secret-local-key")
        self.assertNotIn("top-secret-local-key", repr(config))
        self.assertIn("<redacted>", repr(config))

    def test_missing_key_rejected_before_transport_creation(self) -> None:
        with self.assertRaises(MissingLocalKey):
            LocalTuyaTransport("192.0.2.1", "dev", "")

    def test_constructor_validates_local_connection_parameters(self) -> None:
        with self.assertRaisesRegex(ValueError, "host"):
            LocalTuyaTransport(" ", "dev", "key")
        with self.assertRaisesRegex(ValueError, "device_id"):
            LocalTuyaTransport("192.0.2.1", " ", "key")
        with self.assertRaisesRegex(ValueError, "timeout"):
            LocalTuyaTransport("192.0.2.1", "dev", "key", timeout=0)

    async def test_connect_read_write_close_end_to_end(self) -> None:
        dev = FakeDevice34(REAL_KEY.encode(), {"1": True, "101": "0100000000"})
        transport = _transport(dev)
        try:
            await transport.connect()
            await transport.connect()
            self.assertTrue(transport.connected)
            self.assertEqual(transport.protocol_version, "3.4")
            self.assertEqual(transport.config.device_id, "dev")

            self.assertEqual(await transport.read_dps(), {1: True, 101: "0100000000"})
            # The DP_QUERY request the app sends is {"gwId":..,"devId":..}.
            queries = [i for c, i in dev.received if c == DP_QUERY]
            self.assertEqual(json.loads(queries[-1]), {"gwId": "dev", "devId": "dev"})

            await transport.write_dps({102: "00" * 29, 1: True})
            _wait_for(lambda: len(dev.control_inners) >= 1)
            inner = dev.control_inners[-1]
            self.assertEqual(inner["protocol"], 5)
            self.assertIn("t", inner)
            self.assertEqual(inner["data"]["devId"], "dev")
            self.assertEqual(
                inner["data"]["dps"],
                {"102": base64.b64encode(b"\x00" * 29).decode(), "1": True},
            )

            # A STATUS push lands via the 3.4 parse chain and merges.
            dev.push_status({"1": False})
            _wait_for(lambda: transport._last_dps.get(1) is False)
            # read_dps issues a live query — the next answer overwrites
            # the pushed value, so update the script accordingly.
            dev.status_dps = {"1": False}
            self.assertEqual(await transport.read_dps({1}), {1: False})
        finally:
            await transport.close()
            dev.stop()
        self.assertFalse(transport.connected)
        self.assertIsNone(transport.protocol_version)
        await transport.close()

    async def test_connection_refused_is_handshake_error(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()  # closed port → connect fails
        api = SocketThingNetworkApi(port=port)
        transport = LocalTuyaTransport(
            "127.0.0.1",
            "dev",
            REAL_KEY,
            api=api,
            protocol_version="3.4",
            timeout=1.0,
        )
        with self.assertRaises(HandshakeError):
            await transport.connect()

    async def test_handshake_timeout_is_transport_error(self) -> None:
        # Device accepts the TCP link but never answers the negotiation.
        dev = socket.socket()
        dev.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        dev.bind(("127.0.0.1", 0))
        dev.listen(1)
        port = dev.getsockname()[1]
        holder: list[socket.socket] = []

        def accept() -> None:
            conn, _ = dev.accept()
            holder.append(conn)

        threading.Thread(target=accept, daemon=True).start()
        api = SocketThingNetworkApi(port=port)
        transport = LocalTuyaTransport(
            "127.0.0.1",
            "dev",
            REAL_KEY,
            api=api,
            protocol_version="3.4",
            timeout=1.0,
        )
        try:
            with self.assertRaisesRegex(TransportError, "timed out"):
                await transport.connect()
        finally:
            dev.close()
            for c in holder:
                c.close()

    async def test_raw_dp_hex_rejected_before_io(self) -> None:
        dev = FakeDevice34(REAL_KEY.encode())
        transport = _transport(dev)
        try:
            with self.assertRaisesRegex(ProtocolError, "DP105"):
                await transport.write_dps({105: "not-hex-or-b64!!"})
            self.assertFalse(dev.control_inners)
        finally:
            await transport.close()
            dev.stop()


if __name__ == "__main__":
    unittest.main()
