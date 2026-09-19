"""Concrete socket implementation of ``libnetwork-android.so``.

Real TCP/UDP transport bound to the :class:`ThingNetworkApi` JNI seam:

- TCP links on port 6668 with ``0x55aa`` framing (CRC32 trailer for ≤3.3 /
  HMAC-SHA256 trailer for 3.4+) and ``0x6699`` AES-GCM framing for lpv ≥ 3.5.
- Session-key negotiation (``SESS_KEY_NEG`` cmds 3/4/5): 3.4 uses
  AES-ECB payloads inside HMAC'd 0x55aa frames and derives the session key as
  ``ECB_nopad(realKey, localNonce XOR remoteNonce)``; 3.5 uses AES-GCM
  throughout and derives the key as ``GCM(realKey, iv=localNonce[:12],
  pt=localNonce XOR remoteNonce)[0:16]``.
- Heartbeats + response timeout -> link-close upcalls.
- UDP listeners (``listenUDP``) that parse announcement frames into
  ``HgwBean`` and raise the ``getGWBean`` upcall; periodic
  ``sendBroadcast``/``stopBroadcast`` discovery tokens.
- Crypto helpers: ``encryptAesData``/``parseAesData`` (AES-ECB),
  ``encryptAesDataForUDP``/``gcmDecryptData`` (security-content keys),
  ``encryptGcmData``.
- ``setSecurityContent`` -> ``read_keys_from_content``: BMP header checks,
  java-style key hash -> pixel byte dispatch, LSB-steganography extraction.

Wire formats verified against the tinytuya 1.20 reference implementation
(``core/message_helper.py``, ``core/XenonDevice.py``).

Security-content notes (emulated from ``libnetwork-android.so``
``read_keys_from_content``): this APK's ``fixed_key.bmp`` selects pixel byte
``1`` under the ``"(Rdf+$9)}Y:x:_pJ"`` hash, which the native code rejects
with rc=0x0b — the key vector stays empty and ``get_key(i)`` falls back to a
zero-initialized std::string. Consequently the app's UDP AES/GCM helpers have
no usable key; S7 announcements are plaintext JSON. The v∈{0,2}
share-reconstruction branch (a Shamir-style combiner over BMP-embedded
string pairs) is unreachable with the shipped asset and is not ported — the
extraction up to that point is.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import socket
import struct
import threading
import time
import zlib
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import aes_ecb_decrypt, aes_ecb_encrypt
from .lan_session import (
    ProtocolVersion,
    ThingFrame,
    ThingNetworkApi,
)

log = logging.getLogger(__name__)

LAN_TCP_PORT = 6668

PREFIX_55AA = 0x000055AA
PREFIX_6699 = 0x00006699
SUFFIX_55AA = 0x0000AA55
SUFFIX_6699 = 0x00009966

HEADER_FMT_55AA = ">4I"
HEADER_FMT_6699 = ">IHIII"  # prefix(4) unk(2) seq(4) cmd(4) len(4) = 18 bytes
HEADER_LEN_55AA = 16
HEADER_LEN_6699 = 18
MAX_PAYLOAD_LENGTH = 4096 * 2

# Frame command types (native FRM_ constants)
AP_CONFIG = 1
SESS_KEY_NEG_START = 3
SESS_KEY_NEG_RESP = 4
SESS_KEY_NEG_FINISH = 5
CONTROL = 7
STATUS = 8
HEART_BEAT = 9
DP_QUERY = 10
CONTROL_NEW = 13
DP_QUERY_NEW = 16
UPDATEDPS = 18
UDP_NEW = 0x13
AP_CONFIG_NEW = 0x14
BOARDCAST_LPV34 = 0x23
REQ_DEVINFO = 0x25
LAN_EXT_STREAM = 0x40

ANNOUNCEMENT_CMDS = (UDP_NEW, BOARDCAST_LPV34, 0, REQ_DEVINFO)

# Key string libnetwork passes to read_keys_from_content for the UDP
# security blob (embedded in the setSecurityContent JNI body).
SECURITY_CONTENT_KEY = b"(Rdf+$9)}Y:x:_pJ"

_HANDSHAKE_TIMEOUT = 5.0
_DEFAULT_HB_INTERVAL = 9
_DEFAULT_HB_TIMEOUT_MS = 3000


# ---------------------------------------------------------------------------
# frame codec
# ---------------------------------------------------------------------------


def _ecb_nopad_encrypt(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def _ecb_nopad_decrypt(key: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def pack_55aa(
    seq: int, cmd: int, payload: bytes, hmac_key: bytes | None, retcode: int | None = None
) -> bytes:
    """Pack a 0x55aa frame; ``retcode`` is set only on device->app responses."""
    body = (struct.pack(">I", retcode) if retcode is not None else b"") + payload
    trailer_len = 36 if hmac_key else 8
    data = struct.pack(HEADER_FMT_55AA, PREFIX_55AA, seq, cmd, len(body) + trailer_len)
    data += body
    if hmac_key:
        trailer = hmac.new(hmac_key, data, hashlib.sha256).digest()
    else:
        trailer = struct.pack(">I", zlib.crc32(data) & 0xFFFFFFFF)
    return data + trailer + struct.pack(">I", SUFFIX_55AA)


def pack_6699(
    seq: int, cmd: int, plaintext: bytes, key: bytes, retcode: int | None = None
) -> bytes:
    """Pack a 0x6699 AES-GCM frame; ``retcode`` lives inside the GCM payload."""
    iv = os.urandom(12)
    inner = (struct.pack(">I", retcode) if retcode is not None else b"") + plaintext
    length = 12 + len(inner) + 16
    header = struct.pack(HEADER_FMT_6699, PREFIX_6699, 0, seq, cmd, length)
    ct = AESGCM(key).encrypt(iv, inner, header[4:])
    return header + iv + ct + struct.pack(">I", SUFFIX_6699)


class FrameError(Exception):
    pass


def _read_exact(sock: socket.socket, n: int, buf: bytearray) -> bytes:
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise EOFError
        buf += chunk
    out = bytes(buf[:n])
    del buf[:n]
    return out


def read_frame(
    sock: socket.socket,
    buf: bytearray,
    key: bytes | None | Callable[[], bytes | None],
    no_retcode: bool = False,
) -> tuple[int, int, int, bytes, bool]:
    """Read one frame from ``sock``.

    Returns ``(seq, cmd, retcode, plaintext_payload, auth_ok)``. For 0x6699
    frames the payload is GCM-decrypted (retcode stripped from the plaintext);
    for 0x55aa frames the raw (still inner-encrypted) payload is returned and
    ``auth_ok`` reports CRC32/HMAC validity. Device->app frames always carry a
    4-byte retcode; ``no_retcode`` reads app->device frames which do not.

    ``key`` may be a zero-arg callable, resolved only once the frame has been
    fully read — a reader blocking on the socket must pick up a session key
    negotiated while it was waiting.
    """
    key_fn: Callable[[], bytes | None] = key if callable(key) else lambda: key
    # resync to a known prefix
    p55, p66 = struct.pack(">I", PREFIX_55AA), struct.pack(">I", PREFIX_6699)
    while True:
        while len(buf) < 8:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError
            buf += chunk
        i55, i66 = bytes(buf[:8]).find(p55), bytes(buf[:8]).find(p66)
        if i55 == 0 or i66 == 0:
            break
        if i55 > 0 and (i66 < 0 or i55 <= i66):
            del buf[:i55]
            break
        if i66 > 0:
            del buf[:i66]
            break
        del buf[0]  # no prefix in the window — drop a byte and rescan

    prefix = struct.unpack(">I", buf[:4])[0]
    if prefix == PREFIX_55AA:
        hdr = _read_exact(sock, HEADER_LEN_55AA, buf)
        _, seq, cmd, length = struct.unpack(HEADER_FMT_55AA, hdr)
        if length > MAX_PAYLOAD_LENGTH:
            raise FrameError(f"payload length {length} over cap")
        body = _read_exact(sock, length, buf)
        trailer_len = 36 if key_fn() is not None else 8
        retcode_len = 0 if no_retcode else 4
        if len(body) < trailer_len + retcode_len:
            raise FrameError("short frame body")
        retcode = 0 if no_retcode else struct.unpack(">I", body[:4])[0]
        payload = body[retcode_len : len(body) - trailer_len]
        trailer = body[len(body) - trailer_len :]
        k = key_fn()
        if k is not None:
            ok = hmac.compare_digest(
                hmac.new(k, hdr + body[: len(body) - trailer_len], hashlib.sha256).digest(),
                trailer[:32],
            )
        else:
            ok = (zlib.crc32(hdr + body[: len(body) - trailer_len]) & 0xFFFFFFFF) == struct.unpack(
                ">I", trailer[:4]
            )[0]
        return seq, cmd, retcode, payload, ok

    if prefix == PREFIX_6699:
        hdr = _read_exact(sock, HEADER_LEN_6699, buf)
        _, _, seq, cmd, length = struct.unpack(HEADER_FMT_6699, hdr)
        if length > MAX_PAYLOAD_LENGTH:
            raise FrameError(f"payload length {length} over cap")
        body = _read_exact(sock, length, buf)
        _read_exact(sock, 4, buf)
        k = key_fn()
        if k is None or len(body) < 28:
            return seq, cmd, 0, body, False
        iv, ctt = body[:12], body[12:]
        try:
            raw = AESGCM(k).decrypt(iv, ctt, hdr[4:])
        except Exception:
            return seq, cmd, 0, b"", False
        if no_retcode or len(raw) < 4:
            return seq, cmd, 0, raw, True
        retcode = struct.unpack(">I", raw[:4])[0]
        return seq, cmd, retcode, raw[4:], True

    raise FrameError(f"bad prefix {prefix:#x}")


# ---------------------------------------------------------------------------
# security content (read_keys_from_content)
# ---------------------------------------------------------------------------


def _java_hash(s: bytes) -> int:
    """``abs(31*h+c)`` string hash used to pick the stego pixel offset."""
    h = 0
    for b in s:
        h = (31 * h + b) & 0xFFFFFFFF
    if h & 0x80000000:
        h -= 0x100000000
    return abs(h)


def _stego_read_byte(pixels: bytes, plen: int, cursor: list[int]) -> int:
    """One byte from 8 pixel LSBs, LSB-first; cursor wraps mod plen."""
    if cursor[0] >= plen:
        cursor[0] %= plen
    acc = 0
    for j in range(8):
        acc |= (pixels[cursor[0]] & 1) << j
        cursor[0] += 1
    return acc


def _stego_read_string(pixels: bytes, plen: int, cursor: list[int]) -> bytes:
    """Length-prefixed string from the stego stream."""
    n = _stego_read_byte(pixels, plen, cursor)
    return bytes(_stego_read_byte(pixels, plen, cursor) for _ in range(n))


def read_keys_from_content(key: bytes, content: bytes) -> tuple[int, list[bytes]]:
    """Port of ``read_keys_from_content``.

    Returns ``(rc, keys)`` — rc 0x15 = content validation failure,
    rc 0x0b = the pixel byte selected the (empty) v1 layout, rc 0 = keys.
    The v∈{0,2} share-combiner (``0x5ae4`` — Vandermonde/Shamir machinery)
    is not ported; it is unreachable with this APK's shipped asset and
    returns rc 1 here.
    """
    if len(content) < 0x36 or content[:2] != b"BM":
        return 0x15, []
    file_size = struct.unpack("<I", content[2:6])[0]
    data_off = struct.unpack("<I", content[0xA:0xE])[0]
    # file_size - 0x200001 (mod 2^32) must be >= 0xFFE027FF -> 0x4800 <= size < 0x200001
    if not 0x4800 <= file_size < 0x200001:
        return 0x15, []
    if data_off > file_size - 0x36:
        return 0x15, []
    bpp = struct.unpack("<H", content[0x1C:0x1E])[0]
    if bpp not in (24, 32):
        return 0x15, []
    if struct.unpack("<I", content[0x1E:0x22])[0] != 0:
        return 0x15, []
    pixels = content[0x36:]
    plen = file_size - data_off
    if plen <= 0 or len(pixels) < plen:
        return 0x15, []
    off = ((_java_hash(key) % plen) // 2) % plen
    v = pixels[off]
    if v > 2:
        return 0x15, []
    if v == 1:
        return 0x0B, []
    cursor = [off + 1]
    count = _stego_read_byte(pixels, plen, cursor)
    if not 1 <= count <= 5:
        return 0x15, []
    total_pairs = _stego_read_byte(pixels, plen, cursor) * count
    cursor[0] += 0x20  # 32 pixel bytes skipped after the pair-count byte
    pairs = [
        (_stego_read_string(pixels, plen, cursor), _stego_read_string(pixels, plen, cursor))
        for _ in range(total_pairs)
    ]
    del pairs  # extracted; the per-key share combiner is not ported
    return 1, []


# ---------------------------------------------------------------------------
# SocketThingNetworkApi
# ---------------------------------------------------------------------------


class _Link:
    """One native TCP link (devId -> ip:6668)."""

    def __init__(
        self, dev_id: str, sock: socket.socket, proto: str, real_key: bytes | None
    ) -> None:
        self.dev_id = dev_id
        self.sock = sock
        self.proto = proto  # "3.4" | "3.5" | "3.5.1" | "legacy"
        self.real_key = real_key
        self.session_key: bytes | None = None
        self.online = True
        self.closed = False
        self.seq = 0
        self.send_lock = threading.Lock()
        self.buf = bytearray()
        self.neg_queue: queue.Queue[tuple[int, int, int, bytes, bool]] = queue.Queue()
        self.negotiating = False
        self.last_rx = time.monotonic()
        self.last_hb = time.monotonic()

    @property
    def verify_key(self) -> bytes | None:
        """Trailer/GCM verify key: session key once negotiated, else real key."""
        if self.proto == "legacy":
            return None
        return self.session_key or self.real_key

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq


_PROTO_BY_VERSION = {
    int(ProtocolVersion.LAN_PROTOCOL_VERSION_3_4): "3.4",
    int(ProtocolVersion.LAN_PROTOCOL_VERSION_3_5): "3.5",
    int(ProtocolVersion.LAN_PROTOCOL_VERSION_3_5_1): "3.5.1",
}


class SocketThingNetworkApi(ThingNetworkApi):
    """Concrete ``libnetwork-android.so`` over real sockets."""

    def __init__(self, port: int = LAN_TCP_PORT, connect_timeout: float = 5.0) -> None:
        self.port = port
        self.connect_timeout = connect_timeout
        self._iface: Any = None
        self._links: dict[str, _Link] = {}
        self._links_lock = threading.Lock()
        self._addrs: dict[str, str] = {}  # native devId->ip table (from announcements)
        self._udp_socks: dict[int, socket.socket] = {}
        self._udp_threads: dict[int, threading.Thread] = {}
        self._broadcasts: dict[int, tuple[threading.Event, threading.Thread]] = {}
        self._broadcast_seq = 0
        self._hb_interval = _DEFAULT_HB_INTERVAL
        self._hb_timeout_ms = _DEFAULT_HB_TIMEOUT_MS
        self._hb_stop = threading.Event()
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop, name="pypopur-lan-hb", daemon=True
        )
        self._hb_thread.start()
        self._security_content = b""
        self._udp_keys: list[bytes] = []
        self.debug = False

    # --- wiring ---------------------------------------------------------

    def attach(self, iface: Any) -> None:
        """Bind the owning ``ThingNetworkInterface`` for upcalls."""
        self._iface = iface

    def set_device_address(self, dev_id: str, ip: str) -> None:
        """Seed the native devId->ip table (e.g. from cloud/manual config)."""
        self._addrs[dev_id] = ip

    def device_address(self, dev_id: str) -> str | None:
        return self._addrs.get(dev_id)

    # --- TCP link lifecycle --------------------------------------------

    def _resolve(self, dev_id: str) -> str | None:
        return self._addrs.get(dev_id)

    def _open_link(self, dev_id: str, proto: str, real_key: bytes | None) -> int:
        ip = self._resolve(dev_id)
        if ip is None:
            return -1
        try:
            sock = socket.create_connection((ip, self.port), timeout=self.connect_timeout)
            sock.settimeout(None)
        except OSError:
            return -1
        link = _Link(dev_id, sock, proto, real_key)
        with self._links_lock:
            old = self._links.get(dev_id)
            self._links[dev_id] = link
        if old is not None:
            self._close_link(old, dispatch=False)
        threading.Thread(
            target=self._reader, args=(link,), name=f"pypopur-lan-{dev_id}", daemon=True
        ).start()
        return 1

    def check_online(self, dev_id: str) -> bool:
        link = self._links.get(dev_id)
        return link is not None and link.online and not link.closed

    def connect_device(self, dev_id: str, net_id: int) -> int:
        return self._open_link(dev_id, "legacy", None)

    def connect_device_with_key(
        self, dev_id: str, key: str | None, version: int, net_id: int
    ) -> int:
        proto = _PROTO_BY_VERSION.get(version, "legacy")
        real_key = key.encode() if key else None
        return self._open_link(dev_id, proto, real_key)

    def start_swap_key(self, dev_id: str, key: str) -> None:
        link = self._links.get(dev_id)
        if link is None or not link.online:
            return
        link.negotiating = True
        threading.Thread(target=self._negotiate, args=(link, key.encode()), daemon=True).start()

    def _close_link(self, link: _Link, dispatch: bool, code: int = -1) -> None:
        if link.closed:
            return
        link.closed = True
        link.online = False
        try:
            link.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            link.sock.close()
        except OSError:
            pass
        if dispatch and self._iface is not None:
            self._iface.dispatch_link_close(link.dev_id, code)

    def close_device(self, dev_id: str) -> None:
        link = self._links.pop(dev_id, None)
        if link is not None:
            self._close_link(link, dispatch=False)

    def close_all_connection(self) -> None:
        with self._links_lock:
            links = list(self._links.values())
            self._links.clear()
        for link in links:
            self._close_link(link, dispatch=False)

    # --- sends -----------------------------------------------------------

    def _send_55aa(self, link: _Link, cmd: int, payload: bytes, key: bytes | None) -> int:
        frame = pack_55aa(link.next_seq(), cmd, payload, key)
        try:
            with link.send_lock:
                link.sock.sendall(frame)
        except OSError:
            return -2
        return 0

    def _send_6699(self, link: _Link, cmd: int, plaintext: bytes, key: bytes) -> int:
        frame = pack_6699(link.next_seq(), cmd, plaintext, key)
        try:
            with link.send_lock:
                link.sock.sendall(frame)
        except OSError:
            return -2
        return 0

    def send_bytes(self, data: bytes, length: int, type_: int, dev_id: str) -> int:
        """``sendBytes`` — raw-payload 0x55aa path (≤3.3, pre-actived 3.4)."""
        link = self._links.get(dev_id)
        if link is None or not link.online:
            return -1
        if link.proto == "3.5" or link.proto == "3.5.1":
            key = link.session_key or link.real_key
            if key is None:
                return -1
            return self._send_6699(link, type_, data, key)
        key = link.real_key if link.proto == "3.4" else None
        return self._send_55aa(link, type_, data, key)

    def send_bytes2(self, data: bytes, length: int, type_: int, dev_id: str) -> int:
        """``sendBytes2`` — session-encrypted path."""
        link = self._links.get(dev_id)
        if link is None or not link.online:
            return -1
        if link.proto in ("3.5", "3.5.1"):
            key = link.session_key or link.real_key
            if key is None:
                return -1
            return self._send_6699(link, type_, data, key)
        if link.proto == "3.4":
            if link.session_key is None:
                return -1
            payload = aes_ecb_encrypt(link.session_key, data)
            return self._send_55aa(link, type_, payload, link.session_key)
        return self._send_55aa(link, type_, data, None)

    def send_cmd(self, dev_id: str, a: int, b: int, c: int, d: int) -> int:
        raise NotImplementedError("native sendCMD (AP-config path)")

    # --- session-key negotiation ----------------------------------------

    def _negotiate(self, link: _Link, real_key: bytes) -> None:
        try:
            if link.proto == "3.4":
                self._negotiate_34(link, real_key)
            else:
                self._negotiate_35(link, real_key)
        except Exception as exc:
            link.negotiating = False
            # A stale/replaced link's failure must not fault the session
            # that superseded it (auto-probe races the next link's gw).
            if self._iface is not None and self._links.get(link.dev_id) is link:
                self._iface.dispatch_handshake_error(link.dev_id, -1, str(exc))
            return
        link.negotiating = False

    def _wait_neg_resp(self, link: _Link) -> tuple[int, int, int, bytes, bool]:
        try:
            return link.neg_queue.get(timeout=_HANDSHAKE_TIMEOUT)
        except queue.Empty:
            raise TimeoutError("session-key negotiation timed out")

    def _negotiate_34(self, link: _Link, real_key: bytes) -> None:
        local_nonce = os.urandom(16)
        if (
            self._send_55aa(
                link, SESS_KEY_NEG_START, aes_ecb_encrypt(real_key, local_nonce), real_key
            )
            != 0
        ):
            raise OSError("SESS_KEY_NEG_START send failed")
        _, cmd, _, payload, ok = self._wait_neg_resp(link)
        if cmd != SESS_KEY_NEG_RESP or not ok or len(payload) < 16:
            raise ValueError("bad session-key negotiation response")
        pt = aes_ecb_decrypt(real_key, payload)
        remote_nonce, hmac_check = pt[:16], pt[16:48]
        if not hmac.compare_digest(
            hmac.new(real_key, local_nonce, hashlib.sha256).digest(), hmac_check
        ):
            raise ValueError("session-key negotiation HMAC mismatch")
        finish = hmac.new(real_key, remote_nonce, hashlib.sha256).digest()
        if (
            self._send_55aa(link, SESS_KEY_NEG_FINISH, aes_ecb_encrypt(real_key, finish), real_key)
            != 0
        ):
            raise OSError("SESS_KEY_NEG_FINISH send failed")
        xored = bytes(a ^ b for a, b in zip(local_nonce, remote_nonce))
        link.session_key = _ecb_nopad_encrypt(real_key, xored)[:16]
        if self._iface is not None and self._links.get(link.dev_id) is link:
            self._iface.dispatch_handshake_success(link.dev_id)

    def _negotiate_35(self, link: _Link, real_key: bytes) -> None:
        local_nonce = os.urandom(16)
        if self._send_6699(link, SESS_KEY_NEG_START, local_nonce, real_key) != 0:
            raise OSError("SESS_KEY_NEG_START send failed")
        _, cmd, _, payload, ok = self._wait_neg_resp(link)
        if cmd != SESS_KEY_NEG_RESP or not ok or len(payload) < 48:
            raise ValueError("bad session-key negotiation response")
        remote_nonce, hmac_check = payload[:16], payload[16:48]
        if not hmac.compare_digest(
            hmac.new(real_key, local_nonce, hashlib.sha256).digest(), hmac_check
        ):
            raise ValueError("session-key negotiation HMAC mismatch")
        finish = hmac.new(real_key, remote_nonce, hashlib.sha256).digest()
        if self._send_6699(link, SESS_KEY_NEG_FINISH, finish, real_key) != 0:
            raise OSError("SESS_KEY_NEG_FINISH send failed")
        xored = bytes(a ^ b for a, b in zip(local_nonce, remote_nonce))
        ct = AESGCM(real_key).encrypt(local_nonce[:12], xored, None)
        link.session_key = ct[:16]
        if self._iface is not None and self._links.get(link.dev_id) is link:
            self._iface.dispatch_handshake_success(link.dev_id)

    # --- inbound ---------------------------------------------------------

    def _reader(self, link: _Link) -> None:
        try:
            while link.online:
                seq, cmd, retcode, payload, ok = read_frame(
                    link.sock, link.buf, lambda: link.verify_key
                )
                link.last_rx = time.monotonic()
                if link.negotiating and cmd == SESS_KEY_NEG_RESP:
                    link.neg_queue.put((seq, cmd, retcode, payload, ok))
                    continue
                if cmd == HEART_BEAT:
                    continue
                if not ok and link.proto != "legacy":
                    continue
                data = self._inbound_payload(link, payload)
                if data is None or self._iface is None:
                    continue
                self._iface.dispatch_response_data(
                    link.dev_id,
                    ThingFrame(type=cmd, seq=seq, code=retcode, data=data),
                )
        except (EOFError, OSError, FrameError):
            pass
        finally:
            was_online = link.online
            link.online = False
            if (
                was_online
                and not link.closed
                and self._iface is not None
                and self._links.get(link.dev_id) is link
            ):
                self._iface.dispatch_link_close(link.dev_id, -1)
            self._close_link(link, dispatch=False)

    def _inbound_payload(self, link: _Link, payload: bytes) -> bytes | None:
        """Native-side inbound decrypt: the Java layer receives the inner
        ``ver|0|s|o|json`` block plaintext for 3.4+ session links and the raw
        payload for legacy links (it decrypts the inner body itself)."""
        if link.proto == "3.4":
            if link.session_key is None:
                return payload
            try:
                return aes_ecb_decrypt(link.session_key, payload)
            except Exception:
                return None
        # 3.5+ already GCM-decrypted by read_frame; legacy is raw by design.
        return payload

    # --- heartbeats ------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        while not self._hb_stop.wait(1.0):
            now = time.monotonic()
            with self._links_lock:
                links = list(self._links.values())
            for link in links:
                if not link.online or link.closed:
                    continue
                if (now - link.last_rx) * 1000 > self._hb_timeout_ms + self._hb_interval * 1000:
                    self._close_link(link, dispatch=True, code=-2)
                    continue
                if now - link.last_hb >= self._hb_interval:
                    link.last_hb = now
                    self._send_heartbeat(link)

    def _send_heartbeat(self, link: _Link) -> None:
        if link.proto in ("3.5", "3.5.1"):
            key = link.session_key or link.real_key
            if key is not None:
                self._send_6699(link, HEART_BEAT, b"", key)
        elif link.proto == "3.4":
            key = link.session_key or link.real_key
            if key is None:
                return
            payload = aes_ecb_encrypt(key, b"")
            self._send_55aa(link, HEART_BEAT, payload, key)
        else:
            self._send_55aa(link, HEART_BEAT, b"", None)

    # --- UDP -------------------------------------------------------------

    def listen_udp(self, port: int) -> None:
        if port in self._udp_socks:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        sock.bind(("", port))
        self._udp_socks[port] = sock
        thread = threading.Thread(
            target=self._udp_loop,
            args=(port, sock),
            name=f"pypopur-udp-{port}",
            daemon=True,
        )
        self._udp_threads[port] = thread
        thread.start()

    def shut_down_udp_listen(self, port: int) -> None:
        sock = self._udp_socks.pop(port, None)
        self._udp_threads.pop(port, None)
        if sock is not None:
            sock.close()

    def shut_down_all_udp_listen(self) -> None:
        for port in list(self._udp_socks):
            self.shut_down_udp_listen(port)

    def _udp_loop(self, port: int, sock: socket.socket) -> None:
        while True:
            try:
                data, addr = sock.recvfrom(65536)
            except OSError:
                return
            try:
                self._handle_udp_packet(port, data, addr)
            except Exception:
                log.debug("udp packet handling failed", exc_info=True)

    def _handle_udp_packet(self, port: int, data: bytes, addr: tuple[str, int]) -> None:
        p55 = data.find(struct.pack(">I", PREFIX_55AA))
        p66 = data.find(struct.pack(">I", PREFIX_6699))
        payload: bytes | None = None
        cmd = -1
        retcode = 0
        if p55 >= 0 and (p66 < 0 or p55 <= p66):
            frame = data[p55:]
            if len(frame) < HEADER_LEN_55AA + 8:
                return
            _, _seq, cmd, length = struct.unpack(HEADER_FMT_55AA, frame[:HEADER_LEN_55AA])
            if len(frame) < HEADER_LEN_55AA + length:
                return
            body = frame[HEADER_LEN_55AA : HEADER_LEN_55AA + length]
            if len(body) >= 8:
                retcode = struct.unpack(">I", body[:4])[0]
                payload = body[4:-8]
        elif p66 >= 0:
            frame = data[p66:]
            if len(frame) < HEADER_LEN_6699:
                return
            _, _, _seq, cmd, length = struct.unpack(HEADER_FMT_6699, frame[:HEADER_LEN_6699])
            body = frame[HEADER_LEN_6699 : HEADER_LEN_6699 + length]
            pt = self._udp_gcm_decrypt(body)
            if pt is not None and len(pt) >= 4:
                retcode = struct.unpack(">I", pt[:4])[0]
                payload = pt[4:]
        else:
            # bare datagram (plaintext announcement without a frame wrapper)
            payload = data

        if payload is None:
            return
        obj = self._decode_announcement(payload)
        if obj is not None:
            self._announce(obj, addr)
            return
        if self._iface is not None and cmd >= 0:
            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:
                text = ""
            self._iface.dispatch_smart_udp_data(int(ProtocolVersion.DEFAULT), cmd, retcode, text)

    def _decode_announcement(self, payload: bytes) -> dict[str, Any] | None:
        """Try plaintext JSON, then AES-ECB with each security-content key."""
        for cand in (payload, payload.strip(b"\x00").strip()):
            try:
                obj = json.loads(cand.decode("utf-8", errors="strict"))
            except Exception:
                continue
            if isinstance(obj, dict) and "gwId" in obj:
                return obj
        for key in self._udp_keys:
            try:
                pt = aes_ecb_decrypt(key, payload)
            except Exception:
                continue
            try:
                obj = json.loads(pt.decode("utf-8", errors="strict"))
            except Exception:
                continue
            if isinstance(obj, dict) and "gwId" in obj:
                return obj
        return None

    def _udp_gcm_decrypt(self, data: bytes) -> bytes | None:
        for key in self._udp_keys:
            try:
                return AESGCM(key).decrypt(data[:12], data[12:], None)
            except Exception:
                continue
        return None

    def _announce(self, obj: dict[str, Any], addr: tuple[str, int]) -> None:
        from .discovery import HgwBean  # local import: sdk.discovery imports nothing from here

        gw_id = obj.get("gwId") or obj.get("devId")
        ip = obj.get("ip") or addr[0]
        if gw_id is None:
            return
        self._addrs[gw_id] = ip
        hgw = HgwBean(
            ablilty=int(obj.get("ability") or 0),
            active=int(obj.get("active") or 0),
            ap_config_type=int(obj.get("apConfigType") or 0),
            dev_config_attribute=int(obj.get("devConfigAttribute") or 0),
            encrypt=bool(obj.get("encrypt")),
            extend=obj.get("extend"),
            gw_id=gw_id,
            ip=ip,
            last_seen_time=int(time.time() * 1000),
            mode=int(obj.get("mode") or 0),
            pro_ability=int(obj.get("proAbility") or 0),
            product_key=obj.get("productKey"),
            sl=int(obj.get("sl") or 0),
            ssid=obj.get("ssid"),
            token=bool(obj.get("token")),
            uuid=obj.get("uuid"),
            version=str(obj.get("version")) if obj.get("version") is not None else None,
            wf_cfg=bool(obj.get("wf_cfg") or obj.get("wfCfg")),
        )
        if self._iface is not None:
            self._iface.dispatch_gw_bean(hgw)

    def send_broadcast(
        self,
        ip: str,
        port: int,
        period_ms: int,
        data: bytes,
        data_len: int,
        frame_type: int,
        version: int,
        token: int,
    ) -> int:
        """``sendBroadcast`` — periodic UDP broadcast; returns a stop token."""
        del data_len, token
        if version >= int(ProtocolVersion.LAN_PROTOCOL_VERSION_3_5) and self._udp_keys:
            frame = pack_6699(0, frame_type, data, self._udp_keys[0])
        else:
            frame = pack_55aa(0, frame_type, data, None)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            return -1
        self._broadcast_seq += 1
        token = self._broadcast_seq
        stop = threading.Event()

        def loop() -> None:
            try:
                while not stop.wait(period_ms / 1000.0):
                    try:
                        sock.sendto(frame, (ip, port))
                    except OSError:
                        pass
            finally:
                sock.close()

        # first send is immediate
        try:
            sock.sendto(frame, (ip, port))
        except OSError:
            sock.close()
            return -1
        thread = threading.Thread(target=loop, name=f"pypopur-bcast-{token}", daemon=True)
        self._broadcasts[token] = (stop, thread)
        thread.start()
        return token

    def stop_broadcast(self, token: int) -> bool:
        entry = self._broadcasts.pop(token, None)
        if entry is None:
            return False
        entry[0].set()
        return True

    # --- crypto primitives ------------------------------------------------

    def _udp_key(self, index: int = 0) -> bytes | None:
        return self._udp_keys[index] if index < len(self._udp_keys) else None

    def encrypt_aes_data(self, text: str, key: str) -> bytes:
        return aes_ecb_encrypt(key.encode(), text.encode())

    def parse_aes_data(self, data: bytes, key: str) -> bytes:
        return aes_ecb_decrypt(key.encode(), data)

    def encrypt_aes_data_for_udp(self, data: bytes) -> bytes | None:
        key = self._udp_key(0)
        if key is None:
            return None  # native returns NULL on the empty-key path
        return aes_ecb_encrypt(key, data)

    def encrypt_gcm_data(self, version: int, type_: int, data: bytes, key: str) -> bytes:
        del version, type_
        iv = os.urandom(12)
        return iv + AESGCM(key.encode()).encrypt(iv, data, None)

    def gcm_decrypt_data(self, data: bytes) -> bytes | None:
        key = self._udp_key(0)
        if key is None:
            return None
        try:
            return AESGCM(key).decrypt(data[:12], data[12:], None)
        except Exception:
            return None

    def set_security_content(self, data: bytes) -> None:
        self._security_content = data
        rc, keys = read_keys_from_content(SECURITY_CONTENT_KEY, data)
        self._udp_keys = keys
        if rc != 0:
            log.debug("setSecurityContent: read_keys_from_content rc=%#x", rc)

    # --- housekeeping ------------------------------------------------------

    def enable_debug(self, flag: bool) -> None:
        self.debug = flag

    def set_heart_beat_interval(self, seconds: int) -> None:
        self._hb_interval = seconds

    def set_heart_beat_response_timeout(self, ms: int) -> None:
        self._hb_timeout_ms = ms

    def bind_network_interface(self, ifname: str) -> None:
        log.debug("bindNetworkInterface(%s) — no-op on this platform", ifname)

    def show_connection_history(self) -> None:
        log.debug("links: %s", list(self._links))

    def shutdown(self) -> None:
        """Tear down all threads/links (Python-side lifecycle helper)."""
        self._hb_stop.set()
        self.close_all_connection()
        self.shut_down_all_udp_listen()
        for token in list(self._broadcasts):
            self.stop_broadcast(token)
