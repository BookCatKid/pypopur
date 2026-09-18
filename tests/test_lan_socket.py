"""Tests for the concrete socket transport (lan_socket.py)."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import struct
import threading
import time

import pytest

from pypopur.sdk.crypto import aes_ecb_decrypt, aes_ecb_encrypt
from pypopur.sdk.lan_session import ThingNetworkInterface
from pypopur.sdk.lan_socket import (
    BOARDCAST_LPV34,
    SESS_KEY_NEG_FINISH,
    SESS_KEY_NEG_RESP,
    SESS_KEY_NEG_START,
    STATUS,
    SocketThingNetworkApi,
    pack_55aa,
    pack_6699,
    read_frame,
    read_keys_from_content,
)

REAL_KEY = b"0123456789abcdef"


@pytest.fixture
def socket_pair() -> tuple[socket.socket, socket.socket]:
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_pack_55aa_crc_roundtrip(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    a, b = socket_pair
    a.sendall(pack_55aa(3, STATUS, b"payload", None))
    buf = bytearray()
    seq, cmd, retcode, payload, ok = read_frame(b, buf, None, no_retcode=True)
    assert (seq, cmd, retcode, payload, ok) == (3, STATUS, 0, b"payload", True)


def test_pack_55aa_hmac_response(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    a, b = socket_pair
    a.sendall(pack_55aa(7, STATUS, b"secret", REAL_KEY, retcode=0))
    buf = bytearray()
    seq, cmd, retcode, payload, ok = read_frame(b, buf, REAL_KEY)
    assert (seq, cmd, retcode, payload, ok) == (7, STATUS, 0, b"secret", True)


def test_pack_6699_roundtrip(socket_pair: tuple[socket.socket, socket.socket]) -> None:
    a, b = socket_pair
    a.sendall(pack_6699(9, STATUS, b"gcmdata", REAL_KEY, retcode=0))
    buf = bytearray()
    seq, cmd, retcode, payload, ok = read_frame(b, buf, REAL_KEY)
    assert (seq, cmd, retcode, payload, ok) == (9, STATUS, 0, b"gcmdata", True)


def _make_bmp(pixel_byte: int, size: int = 0x5000) -> bytes:
    bmp = bytearray(size)
    bmp[0:2] = b"BM"
    struct.pack_into("<I", bmp, 2, size)
    struct.pack_into("<I", bmp, 0xA, 0x36)
    struct.pack_into("<H", bmp, 0x1C, 24)
    bmp[0x36:] = bytes([pixel_byte]) * (size - 0x36)
    return bytes(bmp)


def test_read_keys_bad_magic() -> None:
    rc, keys = read_keys_from_content(b"k", b"XX" + b"\x00" * 0x5000)
    assert rc == 0x15 and keys == []


def test_read_keys_v1_empty() -> None:
    rc, keys = read_keys_from_content(b"(Rdf+$9)}Y:x:_pJ", _make_bmp(1))
    assert rc == 0x0B and keys == []


def test_read_keys_v_out_of_range() -> None:
    rc, keys = read_keys_from_content(b"(Rdf+$9)}Y:x:_pJ", _make_bmp(3))
    assert rc == 0x15 and keys == []


def test_fixed_key_bmp_yields_empty() -> None:
    """The real APK asset selects v=1 -> empty key vector."""
    import pathlib

    asset = (
        pathlib.Path(__file__).resolve().parents[1]
        / "../popur-research/apktool/assets/fixed_key.bmp"
    )
    if not asset.exists():
        pytest.skip("popur-research checkout not available")
    rc, keys = read_keys_from_content(b"(Rdf+$9)}Y:x:_pJ", asset.read_bytes())
    assert rc == 0x0B and keys == []


def _read_app_frame(sock: socket.socket, buf: bytearray, key: bytes | None):
    """Device-side read of an app->device frame (no retcode)."""
    seq, cmd, _retcode, payload, ok = read_frame(sock, buf, key, no_retcode=True)
    assert ok
    return seq, cmd, payload


class FakeDevice34:
    """Simulated lpv=3.4 device doing the session-key exchange."""

    def __init__(self, key: bytes = REAL_KEY) -> None:
        self.key = key
        self.session_key: bytes | None = None
        self.remote_nonce = bytes(range(0xA0, 0xB0))
        self.received: list[tuple[int, bytes]] = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.conn: socket.socket | None = None
        self.buf = bytearray()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        conn, _ = self.listener.accept()
        self.conn = conn
        _, cmd, payload = _read_app_frame(conn, self.buf, self.key)
        assert cmd == SESS_KEY_NEG_START
        local = aes_ecb_decrypt(self.key, payload)
        resp = self.remote_nonce + hmac.new(self.key, local, hashlib.sha256).digest()
        conn.sendall(
            pack_55aa(1, SESS_KEY_NEG_RESP, aes_ecb_encrypt(self.key, resp), self.key, retcode=0)
        )
        _, cmd, payload = _read_app_frame(conn, self.buf, self.key)
        assert cmd == SESS_KEY_NEG_FINISH
        finish = aes_ecb_decrypt(self.key, payload)
        assert finish == hmac.new(self.key, self.remote_nonce, hashlib.sha256).digest()
        xored = bytes(a ^ b for a, b in zip(local, self.remote_nonce))
        from pypopur.sdk.lan_socket import _ecb_nopad_encrypt

        self.session_key = _ecb_nopad_encrypt(self.key, xored)[:16]
        while True:
            try:
                _, cmd, payload = _read_app_frame(conn, self.buf, self.session_key)
            except Exception:  # noqa: BLE001
                return
            self.received.append((cmd, aes_ecb_decrypt(self.session_key, payload)))

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
    raise AssertionError("condition not met within timeout")


def test_34_session_negotiation_and_dispatch() -> None:
    dev = FakeDevice34()
    api = SocketThingNetworkApi(port=dev.port)
    iface = ThingNetworkInterface(api)
    handshake: list[str] = []
    frames: list[object] = []

    class CB:
        def on_success(self, dev_id: str) -> None:
            handshake.append(dev_id)

        def on_error(self, dev_id: str, code: int, msg: str) -> None:
            raise AssertionError(f"handshake error {code}: {msg}")

    class RCB:
        def on_response_data(self, dev_id: str, frame) -> None:
            frames.append(frame)

        def on_response_exception(self, dev_id: str, code: int, msg: str) -> None:
            pass

    iface.add_lan_handshake_callback("gw1", CB())
    iface.add_read_res_data_callback("gw1", RCB())
    api.set_device_address("gw1", "127.0.0.1")
    try:
        assert api.connect_device_with_key("gw1", REAL_KEY.decode(), 4, 0) == 1
        api.start_swap_key("gw1", REAL_KEY.decode())
        _wait_for(lambda: handshake == ["gw1"])
        _wait_for(lambda: dev.session_key is not None)

        inner = b"3.4" + b"\x00" * 12 + b'{"dps":{"1":true}}'
        dev.conn.sendall(
            pack_55aa(
                2, STATUS, aes_ecb_encrypt(dev.session_key, inner), dev.session_key, retcode=0
            )
        )
        _wait_for(lambda: len(frames) == 1)
        frame = frames[0]
        assert frame.type == STATUS and frame.data == inner

        assert api.send_bytes2(b"3.4" + b"\x00" * 12 + b"{}", 0, 7, "gw1") == 0
        _wait_for(lambda: any(cmd == 7 for cmd, _ in dev.received))
        _cmd, pt = next(r for r in dev.received if r[0] == 7)
        assert pt == b"3.4" + b"\x00" * 12 + b"{}"
    finally:
        api.shutdown()
        dev.stop()


class FakeDevice35:
    """Simulated lpv=3.5 device (6699/GCM session-key exchange)."""

    def __init__(self, key: bytes = REAL_KEY) -> None:
        self.key = key
        self.session_key: bytes | None = None
        self.remote_nonce = bytes(range(0xB0, 0xC0))
        self.received: list[tuple[int, bytes]] = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.conn: socket.socket | None = None
        self.buf = bytearray()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        conn, _ = self.listener.accept()
        self.conn = conn
        _, cmd, payload = _read_app_frame(conn, self.buf, self.key)
        assert cmd == SESS_KEY_NEG_START
        local = payload  # 3.5 sends the nonce as GCM plaintext
        resp = self.remote_nonce + hmac.new(self.key, local, hashlib.sha256).digest()
        conn.sendall(pack_6699(1, SESS_KEY_NEG_RESP, resp, self.key, retcode=0))
        _, cmd, payload = _read_app_frame(conn, self.buf, self.key)
        assert cmd == SESS_KEY_NEG_FINISH
        assert payload == hmac.new(self.key, self.remote_nonce, hashlib.sha256).digest()
        xored = bytes(a ^ b for a, b in zip(local, self.remote_nonce))
        self.session_key = AESGCM(self.key).encrypt(local[:12], xored, None)[:16]
        while True:
            try:
                _, cmd, payload = _read_app_frame(conn, self.buf, self.session_key)
            except Exception:  # noqa: BLE001
                return
            self.received.append((cmd, payload))

    def stop(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        finally:
            self.listener.close()


def test_35_session_negotiation() -> None:
    dev = FakeDevice35()
    api = SocketThingNetworkApi(port=dev.port)
    iface = ThingNetworkInterface(api)
    handshake: list[str] = []

    class CB:
        def on_success(self, dev_id: str) -> None:
            handshake.append(dev_id)

        def on_error(self, dev_id: str, code: int, msg: str) -> None:
            raise AssertionError(f"handshake error {code}: {msg}")

    iface.add_lan_handshake_callback("gw2", CB())
    api.set_device_address("gw2", "127.0.0.1")
    try:
        assert api.connect_device_with_key("gw2", REAL_KEY.decode(), 5, 0) == 1
        api.start_swap_key("gw2", REAL_KEY.decode())
        _wait_for(lambda: handshake == ["gw2"])
        _wait_for(lambda: dev.session_key is not None)

        inner = b"3.5" + b"\x00" * 12 + b'{"dps":{"1":true}}'
        frames: list[object] = []

        class RCB:
            def on_response_data(self, dev_id: str, frame) -> None:
                frames.append(frame)

            def on_response_exception(self, dev_id: str, code: int, msg: str) -> None:
                pass

        iface.add_read_res_data_callback("gw2", RCB())
        dev.conn.sendall(pack_6699(6, STATUS, inner, dev.session_key, retcode=0))
        _wait_for(lambda: len(frames) == 1)
        assert frames[0].data == inner

        assert api.send_bytes2(inner, 0, 7, "gw2") == 0
        _wait_for(lambda: any(cmd == 7 for cmd, _ in dev.received))
        _cmd, pt = next(r for r in dev.received if r[0] == 7)
        assert pt == inner
    finally:
        api.shutdown()
        dev.stop()


def test_udp_announcement_dispatch() -> None:
    api = SocketThingNetworkApi()
    iface = ThingNetworkInterface(api)
    beans: list[object] = []

    class PCB:
        def get_gw_bean(self, hgw) -> None:
            beans.append(hgw)

        def on_smart_config_result(self, version, result, data) -> None:
            pass

    iface.add_package_callback(PCB())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    api._udp_socks[port] = sock
    threading.Thread(target=api._udp_loop, args=(port, sock), daemon=True).start()

    announce = json.dumps(
        {
            "gwId": "gw-udp-1",
            "ip": "192.168.1.50",
            "version": "3.4",
            "active": 2,
            "ability": 1,
            "mode": 0,
            "encrypt": True,
            "productKey": "pk",
            "token": True,
        }
    ).encode()
    frame = pack_55aa(0, BOARDCAST_LPV34, announce, None, retcode=0)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(frame, ("127.0.0.1", port))
    _wait_for(lambda: len(beans) == 1)
    hgw = beans[0]
    assert hgw.gw_id == "gw-udp-1" and hgw.ip == "192.168.1.50"
    assert hgw.version == "3.4" and hgw.encrypt is True
    assert api.device_address("gw-udp-1") == "192.168.1.50"
    api.shutdown()
    sock.close()
    sender.close()


def test_discover_s7_end_to_end() -> None:
    """discover_s7 drives the real UDP monitor stack and filters to S7."""
    import asyncio

    from pypopur.discovery import discover_s7
    from pypopur.reference import S7_PRODUCT_IDS

    api = SocketThingNetworkApi()
    pk = min(S7_PRODUCT_IDS)

    async def run() -> tuple:
        async def feed() -> None:
            await asyncio.sleep(0.3)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for i, prod in enumerate((pk, pk, "notanS7")):
                ann = json.dumps(
                    {
                        "gwId": f"gw-e2e-{i}",
                        "ip": f"192.168.9.{10 + i}",
                        "version": "3.4",
                        "active": 2,
                        "productKey": prod,
                        "encrypt": True,
                    }
                ).encode()
                sender.sendto(
                    pack_55aa(0, BOARDCAST_LPV34, ann, None, retcode=0),
                    ("127.0.0.1", 6667),
                )
            sender.close()

        asyncio.create_task(feed())
        return await discover_s7(1.2, api=api)

    try:
        found = asyncio.run(run())
    finally:
        api.shutdown()
    assert sorted(d.device_id for d in found) == ["gw-e2e-0", "gw-e2e-1"]
    assert all(d.product_id == pk for d in found)
    assert {d.host for d in found} == {"192.168.9.10", "192.168.9.11"}


def test_send_broadcast_token() -> None:
    api = SocketThingNetworkApi()
    iface = ThingNetworkInterface(api)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.settimeout(5)
    try:
        # ThingNetworkInterface.sendBroadcast(ip, port, period, data, type, version, token)
        token = iface.send_broadcast(
            "127.0.0.1", port, 60000, b'{"from":"app"}', BOARDCAST_LPV34, 5, 0
        )
        assert token > 0
        data, _ = listener.recvfrom(65536)
        assert b'{"from":"app"}' in data
        assert iface.stop_broadcast(token) is True
        assert api.stop_broadcast(token) is False
        assert iface.send_broadcast("", port, 60000, b"x", 0x25, 5, 0) == -1
        assert iface.send_broadcast("127.0.0.1", 0, 60000, b"x", 0x25, 5, 0) == -1
    finally:
        api.shutdown()
        listener.close()
