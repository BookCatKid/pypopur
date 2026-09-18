"""LAN session/transfer layer — the 0x55aa JNI boundary.

smali:
- smali_classes3/com/thingclips/smart/android/hardware/service/DevTransferService.smali
  (+ $1 binder, $3 link-close cb, $4 handshake cb, $5 read-resp cb, $6 delayed
  connect, $UpdateTimerTask ping watchdog)
- .../sdk/hardware/model/GwTransferModel.smali (+ $2 ITransferAidlInterface
  stub, $pdqppqb send runnable, $pppbppp addDev runnable, $qddqppb connect
  runnable, $bdpdqbp ServiceConnection)
- .../sdk/hardware/bdbbqqd.smali        — ``qpqbbpp`` impl (facade over
  GwTransferModel + GwBroadcastMonitorModel)
- .../sdk/hardware/dpppdpq.smali        — ``ThingHardwareManager``, the
  ``IThingHardware`` impl: ``control(ThingLocalControlBean)`` → ``ddqpdpp``
  → ``bbbdppp`` assemblers → service send; inbound ``onDevResponse`` dispatch.
- .../sdk/hardware/dbpbdpb.smali        — ``ThingHgwBeanCacheManager``
  (devId → HgwBean map behind putHgwBean/getDevId/removeHgwBean).
- .../sdk/hardware/bqpbddq.smali        — ``ThingLocalRespParseBuilder``
- .../sdk/hardware/bqqbpqb.smali        — ``LocalRespManager`` lpv dispatch
- .../sdk/hardware/bdbbqbd.smali        — ``LocalResp`` base + parsers
  ``pqqqddq`` (3.4), ``ppbdppp`` (3.2), ``bdqqqpq`` (3.1/1.1), ``dqbpdbq``.
- .../smart/android/device/ThingNetworkInterface.smali /
  ThingNetworkApi.smali                     — the JNI surface.

The Java stack splits across a bound Android service (``DevTransferService``)
and the SDK-process model (``GwTransferModel``) joined by AIDL. Here the
service and model live in one process; the AIDL round-trips (executor +
handler hops) are preserved as injectable seams because ordering matters.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from ._fastjson import parse_object, to_json_string
from ._java import text_is_empty
from .crypto import AESUtil
from .hexutil import bytes_to_int2, hex_string_to_bytes
from .lan_control import (
    ActiveEnum,
    FrameTypeEnum,
    HgwBean,
    ThingLocalControlBean,
)
from .lan_framing import (
    HRequest,
    LocalControlSpec,
    SignatureError,
    assemble_request,
    check_hgw_version,
    is_hgw_version_equals,
    sign_lpv,
)

log = logging.getLogger(__name__)

# Error strings produced along the chain.
ERR_LOCAL_CONTROL = "11005"
ERR_DEV_NOT_ONLINE = "208001"
ERR_DEV_NOT_FOUND = "208002"
ERR_TRANSFER_CLOSED_MSG = "dev transfer is closed"
ERR_TCP_MSG = "tcp is not exist! detail error code "


# ---------------------------------------------------------------------------
# com.thingclips.smart.android.hardware.bean.ThingFrame / sdk HResponse
# ---------------------------------------------------------------------------


@dataclass
class ThingFrame:
    """``com.thingclips.smart.android.hardware.bean.ThingFrame`` — the
    native-parsed 0x55aa frame handed to ``OnResponseDataCallback``."""

    header: int = 0x55AA
    footer: int = 0xAA55
    code: int = 0
    crc32: int = 0
    data: bytes = b""
    length: int = 0
    seq: int = 0
    type: int = 0


@dataclass
class HResponse:
    """``com.thingclips.sdk.hardware.bean.HResponse`` — the AIDL/parcel
    response. Ctor arg order: ``(devId, type, seq, code, dataBinary, version)``."""

    dev_id: str | None = None
    type: int = 0
    seq: int = 0
    code: int = 0
    data_binary: bytes = b""
    version: str | None = None


@dataclass
class HDpResponse:
    """``com.thingclips.sdk.hardwareprotocol.bean.HDpResponse`` — parsed DP
    payload from a LAN response body."""

    cid: str | None = None
    ctype: int = 0
    dev_id: str | None = None
    dps: str | None = None
    mbid: str | None = None
    s: int = 0
    t: int = 0


def _parse_hdp_response(raw: bytes | str) -> HDpResponse | None:
    """``JSON.parseObject(bytes, HDpResponse.class)`` — ``dps`` is a Java
    ``String`` field, so a JSON-object value is re-serialized to its
    compact JSON form."""
    obj = parse_object(raw)
    if not isinstance(obj, dict):
        return None
    dps = obj.get("dps")
    if dps is not None and not isinstance(dps, str):
        dps = to_json_string(dps)
    return HDpResponse(
        cid=obj.get("cid"),
        ctype=obj.get("ctype") or 0,
        dev_id=obj.get("devId"),
        dps=dps,
        mbid=obj.get("mbid"),
        s=obj.get("s") or 0,
        t=obj.get("t") or 0,
    )


@dataclass
class ResponseSRBean:
    """``ResponseSRBean3_2`` — header of 3.2+/3.4 LAN response payloads:
    ``version`` = UTF-8 bytes[0:3]; ``s`` = be32 at offset 7;
    ``o`` = be32 at offset 11."""

    version: str = ""
    s: int = 0
    o: int = 0


def _parse_sr_header(data: bytes) -> ResponseSRBean:
    """``pqqqddq/ppbdppp.bdpdqbp([B)`` — static header parse."""
    return ResponseSRBean(
        s=bytes_to_int2(data, 7),
        o=bytes_to_int2(data, 11),
        version=data[0:3].decode("utf-8", errors="replace"),
    )


# ---------------------------------------------------------------------------
# ThingNetworkInterface$ProtocolVersion
# ---------------------------------------------------------------------------


class ProtocolVersion(IntEnum):
    """``ThingNetworkInterface$ProtocolVersion`` — ctor arg order is
    ``(name, ordinal, version)``; ``version`` is what JNI receives."""

    LAN_PROTOCOL_VERSION_3_2 = 2
    LAN_PROTOCOL_VERSION_3_3 = 3
    DEFAULT = 4
    LAN_PROTOCOL_VERSION_3_4 = 4
    LAN_PROTOCOL_VERSION_BEFORE_3_5 = 4
    LAN_PROTOCOL_VERSION_3_5 = 5
    LAN_PROTOCOL_VERSION_3_5_1 = 6


def get_protocol_version(value: int) -> ProtocolVersion:
    """``ProtocolVersion.getProtocolVersion(int)``."""
    if value == 3:
        return ProtocolVersion.LAN_PROTOCOL_VERSION_3_4
    if value == 4:
        return ProtocolVersion.LAN_PROTOCOL_VERSION_BEFORE_3_5
    if value == 5:
        return ProtocolVersion.LAN_PROTOCOL_VERSION_3_5
    if value == 6:
        return ProtocolVersion.LAN_PROTOCOL_VERSION_3_5_1
    return ProtocolVersion.DEFAULT


# ---------------------------------------------------------------------------
# ThingNetworkApi — the JNI surface (injectable)
# ---------------------------------------------------------------------------


class ThingNetworkApi:
    """``com.thingclips.smart.android.device.ThingNetworkApi`` — all methods
    are JNI in the APK. Bind an implementation by subclassing or assigning
    attributes; unbound calls raise ``NotImplementedError`` like an unloaded
    native lib (``UnsatisfiedLinkError``)."""

    # TCP link lifecycle
    def check_online(self, dev_id: str) -> bool:
        raise NotImplementedError("native checkOnline")

    def connect_device(self, dev_id: str, net_id: int) -> int:
        raise NotImplementedError("native connectDevice")

    def connect_device_with_key(
        self, dev_id: str, key: str | None, version: int, net_id: int
    ) -> int:
        """``connectDeviceWithKey(String, String, int protocolVersion, long)``."""
        raise NotImplementedError("native connectDeviceWithKey")

    def connect_ap_device(
        self, dev_id: str, type_: int, data: bytes, net_id: int, net_id2: int
    ) -> int:
        raise NotImplementedError("native connectApDevice")

    def start_swap_key(self, dev_id: str, key: str) -> None:
        raise NotImplementedError("native startSwapKey")

    def close_device(self, dev_id: str) -> None:
        raise NotImplementedError("native closeDevice")

    def close_all_connection(self) -> None:
        raise NotImplementedError("native closeAllConnection")

    # sends
    def send_bytes(self, data: bytes, length: int, type_: int, dev_id: str) -> int:
        raise NotImplementedError("native sendBytes")

    def send_bytes2(self, data: bytes, length: int, type_: int, dev_id: str) -> int:
        raise NotImplementedError("native sendBytes2")

    def send_cmd(self, dev_id: str, a: int, b: int, c: int, d: int) -> int:
        raise NotImplementedError("native sendCMD")

    # UDP
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
        """``sendBroadcast(String, int, int, byte[], int len, int type,
        int version, long token)``."""
        raise NotImplementedError("native sendBroadcast")

    def stop_broadcast(self, token: int) -> bool:
        raise NotImplementedError("native stopBroadcast")

    def listen_udp(self, port: int) -> None:
        raise NotImplementedError("native listenUDP")

    def shut_down_udp_listen(self, port: int) -> None:
        raise NotImplementedError("native shutDownUDPListen")

    def shut_down_all_udp_listen(self) -> None:
        raise NotImplementedError("native shutDownAllUDPListen")

    # TLS channel
    def create_tls_channel(self, host: str, port: int, net_id: int) -> int:
        raise NotImplementedError("native createTlsChannel")

    def create_security_tls_channel(
        self, host: str, cert: str, key: str, port: int, net_id: int
    ) -> int:
        raise NotImplementedError("native createSecurityTlsChannel")

    def send_req_over_tls_channel(self, data: bytes, length: int) -> Any:
        raise NotImplementedError("native sendReqOverTlsChannel")

    def async_send_over_tls_channel(self, data: bytes, length: int) -> int:
        raise NotImplementedError("native asyncSendOverTlsChannel")

    def read_over_tls_channel(self) -> Any:
        raise NotImplementedError("native ReadOverTlsChannel")

    def close_tls_channel(self) -> None:
        raise NotImplementedError("native closeTlsChannel")

    # crypto primitives
    def encrypt_aes_data(self, text: str, key: str) -> bytes:
        raise NotImplementedError("native encryptAesData")

    def parse_aes_data(self, data: bytes, key: str) -> bytes:
        raise NotImplementedError("native parseAesData")

    def encrypt_aes_data_for_udp(self, data: bytes) -> bytes:
        raise NotImplementedError("native encryptAesDataForUDP")

    def encrypt_gcm_data(self, version: int, type_: int, data: bytes, key: str) -> bytes:
        raise NotImplementedError("native encryptGcmData")

    def encrypt_gcm_data_for_ap_config(self, version: int, data: bytes) -> bytes:
        raise NotImplementedError("native encryptGcmDataForApConfig")

    def encrypt_gcm_data_for_ap_config_with_type(
        self, version: int, data: bytes, type_: int
    ) -> bytes:
        raise NotImplementedError("native encryptGcmDataForApConfigWithType")

    def gcm_decrypt_data(self, data: bytes) -> bytes:
        raise NotImplementedError("native gcmDecryptData")

    def set_security_content(self, data: bytes) -> None:
        raise NotImplementedError("native setSecurityContent")

    # housekeeping
    def enable_debug(self, flag: bool) -> None:
        raise NotImplementedError("native enableDebug")

    def set_heart_beat_interval(self, seconds: int) -> None:
        raise NotImplementedError("native setHeartBeatInterval")

    def set_heart_beat_response_timeout(self, ms: int) -> None:
        raise NotImplementedError("native setHeartBeatResponseTimeout")

    def bind_network_interface(self, ifname: str) -> None:
        raise NotImplementedError("native bindNetworkInterface")

    def show_connection_history(self) -> None:
        raise NotImplementedError("native showConnectionHistory")


# ---------------------------------------------------------------------------
# ThingNetworkInterface — callback registry + native dispatch
# ---------------------------------------------------------------------------


class ThingNetworkInterface:
    """``ThingNetworkInterface`` — the Java-side singleton wrapping
    ``ThingNetworkApi`` and routing native callbacks to registered listeners.

    The private ``OnXxxCallback`` methods are the JNI upcall entry points;
    they are exposed here as ``dispatch_*`` so a bound native impl can raise
    them.
    """

    BIZ_AP_CONFIG_DEVICE_REPORT_TYPE = 0x11
    BIZ_AP_CONFIG_CLIENT_CONFIG_TYPE = 0x14
    BIZ_AP_CONFIG_DEVICE_RESPONSE_TYPE = 0x15
    BIZ_AP_CONFIG_CLIENT_RESPONSE_TYPE = 0x15

    def __init__(self, api: ThingNetworkApi | None = None) -> None:
        self.api = api if api is not None else ThingNetworkApi()
        self.link_close_cb: dict[str, Any] = {}
        self.lan_handshake_cb: dict[str, Any] = {}
        self.read_res_data_cb: dict[str, Any] = {}
        self.package_callbacks: list[Any] = []
        self.ap_config_callbacks: list[Any] = []
        self.device_conn_callback: Any = None
        self.tcp_ap_config_callback: Any = None
        attach = getattr(self.api, "attach", None)
        if attach is not None:
            attach(self)

    # --- registration --------------------------------------------------

    def add_link_close_callback(self, dev_id: str, cb: Any) -> None:
        self.link_close_cb[dev_id] = cb

    def remove_link_close_callback(self, dev_id: str) -> None:
        self.link_close_cb.pop(dev_id, None)

    def add_lan_handshake_callback(self, dev_id: str, cb: Any) -> None:
        self.lan_handshake_cb[dev_id] = cb

    def add_read_res_data_callback(self, dev_id: str, cb: Any) -> None:
        self.read_res_data_cb[dev_id] = cb

    def remove_read_res_data_callback(self, dev_id: str) -> None:
        """``reomveReadResDataCallback`` (sic)."""
        self.read_res_data_cb.pop(dev_id, None)

    def add_package_callback(self, cb: Any) -> None:
        self.package_callbacks.append(cb)

    def remove_package_callback(self, cb: Any) -> None:
        if cb in self.package_callbacks:
            self.package_callbacks.remove(cb)

    def add_ap_config_result_callback(self, cb: Any) -> None:
        self.ap_config_callbacks.append(cb)

    def remove_ap_config_result_callback(self, cb: Any) -> None:
        if cb in self.ap_config_callbacks:
            self.ap_config_callbacks.remove(cb)

    def set_device_conn_callback(self, cb: Any) -> None:
        self.device_conn_callback = cb

    def set_tcp_ap_config_callback(self, cb: Any) -> None:
        self.tcp_ap_config_callback = cb

    def remove_tcp_ap_config_callback(self) -> None:
        self.tcp_ap_config_callback = None

    # --- native upcalls (private OnXxx/onXxx dispatchers) ---------------

    def dispatch_link_close(self, dev_id: str, error_code: int) -> None:
        cb = self.link_close_cb.get(dev_id)
        if cb is not None:
            cb.on_link_close(dev_id, error_code)

    def dispatch_response_data(self, dev_id: str, frame: ThingFrame) -> None:
        cb = self.read_res_data_cb.get(dev_id)
        if cb is not None:
            cb.on_response_data(dev_id, frame)

    def dispatch_response_exception(self, dev_id: str, error_code: int, msg: str) -> None:
        cb = self.read_res_data_cb.get(dev_id)
        if cb is not None:
            cb.on_response_exception(dev_id, error_code, msg)

    def dispatch_handshake_success(self, dev_id: str) -> None:
        """Private ``onSuccess(String)``."""
        cb = self.lan_handshake_cb.get(dev_id)
        if cb is not None:
            cb.on_success(dev_id)

    def dispatch_handshake_error(self, dev_id: str, error_code: int, msg: str) -> None:
        """Private ``onError(String, int, String)``."""
        cb = self.lan_handshake_cb.get(dev_id)
        if cb is not None:
            cb.on_error(dev_id, error_code, msg)

    def dispatch_smart_udp_data(
        self, version: int, frame_type: int, result: int, data: str
    ) -> None:
        """``OnSmartUDPDataCallback(int, int, int, String)``."""
        if frame_type in (
            self.BIZ_AP_CONFIG_DEVICE_REPORT_TYPE,
            self.BIZ_AP_CONFIG_DEVICE_RESPONSE_TYPE,
        ):
            for cb in self.ap_config_callbacks:
                if frame_type == self.BIZ_AP_CONFIG_DEVICE_REPORT_TYPE:
                    cb.on_ap_config_device_info_report(get_protocol_version(version), data)
                else:
                    cb.on_ap_config_result(get_protocol_version(version), result, data)
        else:
            for cb in self.package_callbacks:
                cb.on_smart_config_result(get_protocol_version(version), result, data)

    def dispatch_gw_bean(self, hgw: Any) -> None:
        """Private ``getGWBean(HgwBean)`` — native UDP announcement upcall."""
        for cb in self.package_callbacks:
            cb.get_gw_bean(hgw)

    def dispatch_connection_success(self, dev_id: str) -> None:
        if self.device_conn_callback is not None:
            self.device_conn_callback.on_connection_success(dev_id)

    def dispatch_connection_fail(self, dev_id: str, error_code: int, msg: str) -> None:
        if self.device_conn_callback is not None:
            self.device_conn_callback.on_connection_fail(dev_id, error_code, msg)

    def dispatch_connection_closed(self, dev_id: str, a: int, b: int, msg: str) -> None:
        if self.device_conn_callback is not None:
            self.device_conn_callback.on_connection_closed(dev_id, a, b, msg)

    def dispatch_tcp_ap_config_result(self, code: int, data: str) -> None:
        if self.tcp_ap_config_callback is not None:
            self.tcp_ap_config_callback.on_tcp_ap_config_result(code, data)

    # --- thin statics over the native api --------------------------------

    def check_online(self, dev_id: str) -> bool:
        return self.api.check_online(dev_id)

    def send_bytes(self, data: bytes, length: int, type_: int, dev_id: str) -> int:
        return self.api.send_bytes(data, length, type_, dev_id)

    def send_bytes2(self, data: bytes, length: int, type_: int, dev_id: str) -> int:
        return self.api.send_bytes2(data, length, type_, dev_id)

    def connect_device(self, dev_id: str, net_id: int) -> int:
        return self.api.connect_device(dev_id, net_id)

    def connect_device_with_key(self, dev_id: str, key: str, net_id: int) -> int:
        """3-arg wrapper — protocol version ``LAN_PROTOCOL_VERSION_3_4``."""
        return self.api.connect_device_with_key(
            dev_id, key, int(ProtocolVersion.LAN_PROTOCOL_VERSION_3_4), net_id
        )

    def connect_device_with_key_ver(
        self, dev_id: str, key: str | None, version: ProtocolVersion, net_id: int
    ) -> int:
        return self.api.connect_device_with_key(dev_id, key, int(version), net_id)

    def start_swap_key(self, dev_id: str, key: str) -> None:
        self.api.start_swap_key(dev_id, key)

    def close_device(self, dev_id: str) -> None:
        self.api.close_device(dev_id)

    def close_all_connection(self) -> None:
        self.api.close_all_connection()

    def parse_aes_data(self, data: bytes, key: str) -> bytes:
        return self.api.parse_aes_data(data, key)

    def encrypt_aes_data(self, text: str, key: str) -> bytes:
        return self.api.encrypt_aes_data(text, key)

    def enable_debug(self, flag: bool) -> None:
        self.api.enable_debug(flag)

    def set_heart_beat_interval(self, seconds: int) -> None:
        self.api.set_heart_beat_interval(seconds)

    def set_heart_beat_response_timeout(self, ms: int) -> None:
        self.api.set_heart_beat_response_timeout(ms)

    # --- UDP statics ------------------------------------------------------

    def send_broadcast(
        self,
        ip: str,
        port: int,
        period_ms: int,
        data: bytes,
        frame_type: int,
        version: int,
        token: int,
    ) -> int:
        """``ThingNetworkInterface.sendBroadcast`` — guards empty ip /
        non-positive port, inserts ``data_len`` for the native call."""
        if text_is_empty(ip) or port <= 0:
            return -1
        return self.api.send_broadcast(
            ip,
            port,
            period_ms,
            data,
            len(data) if data is not None else 0,
            frame_type,
            version,
            token,
        )

    def stop_broadcast(self, token: int) -> bool:
        return self.api.stop_broadcast(token)

    def listen_udp(self, port: int) -> None:
        self.api.listen_udp(port)

    def shut_down_udp_listen(self, port: int) -> None:
        self.api.shut_down_udp_listen(port)

    def shut_down_all_udp_listen(self) -> None:
        self.api.shut_down_all_udp_listen()

    def set_security_content(self, data: bytes) -> None:
        self.api.set_security_content(data)


# ---------------------------------------------------------------------------
# DevTransferService — the bound service keeping live gw links
# ---------------------------------------------------------------------------


class _LinkCloseCallback:
    """``DevTransferService$3``."""

    def __init__(self, service: DevTransfer, gw_id: str, lpv: str) -> None:
        self.service = service
        self.gw_id = gw_id
        self.lpv = lpv

    def on_link_close(self, dev_id: str, error_code: int) -> None:
        self.service._on_gw_online_changed(dev_id, False)
        self.service.hardware_log(6, dev_id, self.lpv, error_code, -1)


class _HandshakeCallback:
    """``DevTransferService$4`` — LanHandShakeCallback."""

    def __init__(self, service: DevTransfer, hgw: HgwBean, lpv: str) -> None:
        self.service = service
        self.hgw = hgw
        self.gw_id = hgw.gw_id
        self.lpv = lpv

    def on_error(self, dev_id: str, error_code: int, msg: str) -> None:
        self.service._on_gw_online_changed(self.gw_id, False)
        self.service.hardware_log(10, self.gw_id, self.lpv, error_code, -1)

    def on_success(self, dev_id: str) -> None:
        self.service._connect_success(self.hgw)
        self.service.hardware_log(
            9,
            self.gw_id,
            self.lpv,
            int(self.service._clock_ms() - self.service.connect_time),
            -1,
        )


class _ReadResponseCallback:
    """``DevTransferService$5`` — ReadResponseDataCallback."""

    def __init__(self, service: DevTransfer, hgw: HgwBean, lpv: str) -> None:
        self.service = service
        self.hgw = hgw
        self.gw_id = hgw.gw_id
        self.lpv = lpv

    def on_response_data(self, dev_id: str, frame: ThingFrame) -> None:
        service = self.service
        service.m_timer_ping[dev_id] = service._clock_ms()
        resp = HResponse(
            code=frame.code,
            data_binary=frame.data,
            dev_id=self.gw_id,
            seq=frame.seq,
            type=frame.type,
            version=self.hgw.version,
        )
        if frame.type == FrameTypeEnum.LAN_REQUEST_GW_LOG:
            data = service._parse_multi_package_frame(frame.data)
            if data is not None:
                try:
                    resp.data_binary = data
                    service._on_result(resp)
                except Exception:
                    log.exception("TCPConnect handler Exception")
            return
        resp.data_binary = frame.data
        service._on_result(resp)

    def on_response_exception(self, dev_id: str, error_code: int, msg: str) -> None:
        self.service.hardware_log(11, dev_id, self.lpv, error_code, -1)


class DevTransfer:
    """``DevTransferService`` — the LAN link keeper.

    Seams:

    - ``native`` — :class:`ThingNetworkInterface` (or duck-type).
    - ``clock_ms()`` — ``System.currentTimeMillis``.
    - ``post_delayed(fn, ms)`` — ``SafeHandler.postDelayed``; default runs
      immediately (Java defers 3 s — inject a scheduler for fidelity).
    - listeners in ``m_transfer`` — ``ITransferAidlInterface`` objects with
      ``gw_on(hgw)`` / ``gw_off(hgw)`` / ``response_by_binary(dev_id, version,
      type, seq, code, data)`` / ``parse_pkg_frame_progress(seq, pack)`` /
      ``hardware_log(level, dev_id, lpv, a, b)``.
    """

    SERVICE_VERSION = "2.5"
    CONNECTING_WINDOW_MS = 10000
    IP_CONFLICT_DELAY_MS = 3000
    PING_STALE_MS = 60000  # UpdateTimerTask threshold
    TIMER_INITIAL_DELAY_MS = 2500  # scheduleWithFixedDelay initial
    TIMER_PERIOD_MS = 60000  # scheduleWithFixedDelay period
    HEARTBEAT_INTERVAL_S = 10
    HEARTBEAT_TIMEOUT_MS = 10000

    def __init__(
        self,
        native: ThingNetworkInterface,
        *,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
        post_delayed: Callable[[Callable[[], None], int], None] | None = None,
    ) -> None:
        self.native = native
        self._clock_ms = clock_ms
        self._post_delayed = post_delayed or (lambda fn, ms: fn())
        self.live_gw: dict[str, HgwBean] = {}
        self.connecting_gw: dict[str, tuple[HgwBean, int] | None] = {}
        self.m_transfer: list[Any] = []
        self.m_timer_ping: dict[str, int] = {}
        self.connect_time = 0
        self._lock = threading.RLock()

    # --- ITransferServiceAidlInterface face -----------------------------

    def register_callback(self, listener: Any) -> None:
        self.m_transfer.append(listener)

    def unregister_callback(self, listener: Any) -> None:
        """``unRegisterCallback`` — Java removes by token; the port removes
        the listener object itself."""
        if listener in self.m_transfer:
            self.m_transfer.remove(listener)

    def get_gw(self, dev_id: str) -> HgwBean | None:
        return self.live_gw.get(dev_id)

    def query_gw(self) -> list[HgwBean]:
        return list(self.live_gw.values())

    def get_service_version(self) -> str:
        return self.SERVICE_VERSION

    def add_gw(self, hgw: HgwBean, local_key: str | None, net_id: int) -> None:
        self.add_dev(hgw, local_key, net_id)

    def delete_gw(self, dev_id: str) -> None:
        self.delete_dev(dev_id)

    def delete_all_gw(self) -> None:
        self.delete_all_dev()

    def close_service(self) -> None:
        self.on_destroy()

    # --- service lifecycle ------------------------------------------------

    def on_create(self) -> None:
        """``onCreate`` — maps cleared + native housekeeping. (The
        ``ThingNetworkBinder`` init is an Android seam, skipped.)"""
        self.live_gw = {}
        self.connecting_gw = {}
        self.m_transfer = []
        self.m_timer_ping = {}
        self.native.enable_debug(log.isEnabledFor(logging.DEBUG))
        self.native.set_heart_beat_interval(self.HEARTBEAT_INTERVAL_S)
        self.native.set_heart_beat_response_timeout(self.HEARTBEAT_TIMEOUT_MS)

    def update_timer_task(self) -> None:
        """``UpdateTimerTask.run`` — entries idle > 60 s get ``deleteDev``
        plus removal from the ping map."""
        for dev_id, ts in list(self.m_timer_ping.items()):
            if self._clock_ms() - ts > self.PING_STALE_MS:
                self.delete_dev(dev_id)
                self.m_timer_ping.pop(dev_id, None)

    def on_destroy(self) -> None:
        """``onDestroy`` — gwOffline each live gw, remove native callbacks,
        clear all maps."""
        for gw_id, hgw in list(self.live_gw.items()):
            self._gw_offline(hgw)
            self.native.remove_link_close_callback(gw_id)
            self.native.remove_read_res_data_callback(gw_id)
        self.live_gw.clear()
        self.connecting_gw.clear()

    # --- device registration ----------------------------------------------

    def add_dev(self, hgw: HgwBean, local_key: str | None, net_id: int) -> None:
        """``addDev`` — synchronized; 10 s connecting-window dedup, IP
        conflict eviction with a 3 s delayed connect."""
        with self._lock:
            gw_id = hgw.gw_id
            if gw_id in self.connecting_gw:
                pair = self.connecting_gw[gw_id]
                if pair is None or self._clock_ms() - pair[1] < self.CONNECTING_WINDOW_MS:
                    log.debug("addDev: %s is connecting", gw_id)
                    return
                del self.connecting_gw[gw_id]
            if not self.native.check_online(gw_id):
                if gw_id in self.live_gw:
                    self._on_gw_online_changed(gw_id, False)
                conflict = False
                for other in list(self.live_gw.values()):
                    if other is not None and hgw.ip == other.ip:
                        log.debug("ip conflict with %s, removed", other.gw_id)
                        self.delete_dev(other.gw_id)
                        conflict = True
                self.connecting_gw[gw_id] = (hgw, self._clock_ms())
                if conflict:
                    self._post_delayed(
                        lambda: self._build_connect(hgw, local_key, net_id),
                        self.IP_CONFLICT_DELAY_MS,
                    )
                else:
                    self._build_connect(hgw, local_key, net_id)

    def _build_connect(self, hgw: HgwBean, local_key: str | None, net_id: int) -> None:
        """``buildConnect`` — link-close callback always; with a localKey:
        handshake callback + ``connectDeviceWithKey`` (3.5 proto enum for
        lpv ≥ 3.5) + ``startSwapKey``; without: plain ``connectDevice`` /
        4-arg ``connectDeviceWithKey(null, 3.5, netId)``."""
        gw_id = hgw.gw_id
        version = hgw.version
        self.hardware_log(1, gw_id, version, 0, -1)
        self.native.add_link_close_callback(gw_id, _LinkCloseCallback(self, gw_id, version))
        if local_key is not None:
            self.native.add_lan_handshake_callback(gw_id, _HandshakeCallback(self, hgw, version))
            if check_hgw_version(version, 3.5):
                ret = self.native.connect_device_with_key_ver(
                    gw_id,
                    local_key,
                    ProtocolVersion.LAN_PROTOCOL_VERSION_3_5,
                    net_id,
                )
            else:
                ret = self.native.connect_device_with_key(gw_id, local_key, net_id)
            self.connect_time = self._clock_ms()
            if not self._check_connect_result(hgw, ret):
                return
            self.native.start_swap_key(gw_id, local_key)
            return
        if check_hgw_version(version, 3.5):
            ret = self.native.connect_device_with_key_ver(
                gw_id, None, ProtocolVersion.LAN_PROTOCOL_VERSION_3_5, net_id
            )
        else:
            ret = self.native.connect_device(gw_id, net_id)
        if self._check_connect_result(hgw, ret):
            self._connect_success(hgw)

    def _check_connect_result(self, hgw: HgwBean, ret: int) -> bool:
        """``checkConnectResult`` — ret ≤ 0: hardwareLog(7) + offline +
        remove from connectingGw → False; else hardwareLog(2) → True."""
        gw_id = hgw.gw_id
        if ret <= 0:
            self.hardware_log(7, gw_id, hgw.version, ret, -1)
            self._on_gw_online_changed(gw_id, False)
            self.connecting_gw.pop(gw_id, None)
            return False
        self.hardware_log(2, gw_id, hgw.version, ret, -1)
        return True

    def _connect_success(self, hgw: HgwBean) -> None:
        self._on_gw_online_changed(hgw.gw_id, True)
        self._add_dev_response(hgw)

    def _add_dev_response(self, hgw: HgwBean) -> None:
        """``addDevResponse`` — registers the per-gw ReadResponseDataCallback."""
        self.native.add_read_res_data_callback(
            hgw.gw_id, _ReadResponseCallback(self, hgw, hgw.version)
        )

    # --- online transitions -------------------------------------------------

    def _on_gw_online_changed(self, dev_id: str, online: bool) -> None:
        """``onGwOnlineChanged``."""
        pair = self.connecting_gw.pop(dev_id, None)
        if online:
            if pair is not None:
                self.live_gw[dev_id] = pair[0]
                self._gw_online(pair[0])
            self.m_timer_ping[dev_id] = self._clock_ms()
        else:
            removed = self.live_gw.pop(dev_id, None)
            if removed is not None:
                self._gw_offline(removed)
            self.m_timer_ping.pop(dev_id, None)

    def _gw_online(self, hgw: HgwBean) -> None:
        for listener in self.m_transfer:
            try:
                listener.gw_on(hgw)
            except Exception:
                log.exception("gwOnline %s", hgw.gw_id)

    def _gw_offline(self, hgw: HgwBean) -> None:
        for listener in self.m_transfer:
            try:
                listener.gw_off(hgw)
            except Exception:
                log.exception("gwOffline %s", hgw.gw_id)

    def _on_result(self, resp: HResponse) -> None:
        """``onResult`` — ``responseByBinary`` fanout."""
        for listener in self.m_transfer:
            try:
                listener.response_by_binary(
                    resp.dev_id,
                    resp.version,
                    resp.type,
                    resp.seq,
                    resp.code,
                    resp.data_binary,
                )
            except Exception:
                log.exception("onResult")

    def _parse_multi_package_frame(self, data: bytes) -> bytes:
        """``parseMultiPackageFrame`` — reads packNum/seqNum headers, fires
        the progress fanout, returns the bytes unchanged."""
        pack_num = bytes_to_int2(data, 0)
        seq_num = bytes_to_int2(data, 4)
        self._parse_pkg_frame_progress(seq_num, pack_num)
        return data

    def _parse_pkg_frame_progress(self, seq_num: int, pack_num: int) -> None:
        for listener in self.m_transfer:
            try:
                listener.parse_pkg_frame_progress(seq_num, pack_num)
            except Exception:
                log.exception("parsePkgFrameProgress")

    def hardware_log(
        self,
        level: int,
        dev_id: str | None,
        lpv: str | None,
        code: int,
        type_: int,
    ) -> None:
        for listener in self.m_transfer:
            try:
                listener.hardware_log(level, dev_id, lpv, code, type_)
            except Exception:
                log.exception("hardwareLog")

    # --- sends --------------------------------------------------------------

    def control_by_binary(self, dev_id: str, type_: int, data: bytes) -> str:
        """``controlByBinary`` → ``sendBytes``. Returns ``str(ret)`` — ``"0"``
        on success; ``"208001"`` when the gw is known but the native link is
        offline; ``"208002"`` when the gw is unknown entirely."""
        if self.native.check_online(dev_id) and dev_id in self.live_gw:
            if type_ == FrameTypeEnum.LAN_GW_UPDATE and bytes(data).startswith(b"file://"):
                try:
                    path = bytes(data).decode(errors="replace")[7:]
                    with open(path, "rb") as fh:
                        data = fh.read()
                    return self._send_bytes(dev_id, type_, data)
                except Exception:
                    log.exception("controlByBinary file read")
            return self._send_bytes(dev_id, type_, data)
        if dev_id in self.live_gw:
            self._on_gw_online_changed(dev_id, False)
            return ERR_DEV_NOT_ONLINE
        self.live_gw.pop(dev_id, None)
        self._gw_offline(HgwBean(gw_id=dev_id))
        self.m_timer_ping.pop(dev_id, None)
        return ERR_DEV_NOT_FOUND

    def _send_bytes(self, dev_id: str, type_: int, data: bytes) -> str:
        """``sendBytes`` — lpv ≥ 3.5, or ≥ 3.4 with ``active == ACTIVED`` →
        ``sendBytes2``; otherwise ``sendBytes``. ret −1/−2 marks the gw
        offline; the stringified ret is returned."""
        hgw = self.live_gw.get(dev_id)
        version = hgw.version if hgw is not None else ""
        ret = 0
        if hgw is not None:
            if check_hgw_version(version, 3.5) or (
                check_hgw_version(version, 3.4) and hgw.active == ActiveEnum.ACTIVED
            ):
                ret = self.native.send_bytes2(data, len(data), type_, dev_id)
            else:
                ret = self.native.send_bytes(data, len(data), type_, dev_id)
        self.hardware_log(8 if ret != 0 else 12, dev_id, version, ret, type_)
        if ret in (-1, -2):
            self._on_gw_online_changed(dev_id, False)
        return str(ret)

    def delete_dev(self, dev_id: str) -> None:
        """``deleteDev`` — only acts when the gw is in ``liveGw``."""
        with self._lock:
            if dev_id not in self.live_gw:
                return
            version = self.live_gw[dev_id].version or ""
            self.native.remove_link_close_callback(dev_id)
            self.connecting_gw.pop(dev_id, None)
            self.native.close_device(dev_id)
            self._on_gw_online_changed(dev_id, False)
            self.hardware_log(5, dev_id, version, 0, -1)

    def delete_all_dev(self) -> None:
        """``deleteAllDev`` — remove callbacks, close all native links,
        gwOffline fanout for each, clear maps."""
        with self._lock:
            for dev_id in list(self.live_gw):
                self.native.remove_link_close_callback(dev_id)
            self.connecting_gw.clear()
            self.native.close_all_connection()
            for hgw in list(self.live_gw.values()):
                self._gw_offline(hgw)
            self.connecting_gw.clear()
            self.m_timer_ping.clear()
            self.live_gw.clear()


# ---------------------------------------------------------------------------
# GwTransferModel — the SDK-side model in front of the service
# ---------------------------------------------------------------------------


class _ControlRunnableResult:
    """``GwTransferModel$pdqppqb$bdpdqbp`` — the handler-posted result."""

    def __init__(self, cb: Any, ret: str) -> None:
        self.cb = cb
        self.ret = ret

    def run(self) -> None:
        if self.ret == "0":
            if self.cb is not None:
                self.cb.on_success()
            return
        if self.cb is not None:
            self.cb.on_error(ERR_LOCAL_CONTROL, ERR_TCP_MSG + self.ret)


class TransferModel:
    """``GwTransferModel`` — binds the service, executes sends on a single
    thread, reassembles multi-package LAN_REQUEST_GW_LOG frames, and fans
    service callbacks out through a main-thread handler.

    Seams:

    - ``service`` — the ``ITransferServiceAidlInterface`` (a
      :class:`DevTransfer` or test double); ``None`` models an unbound
      service (``pbpqqdp`` false).
    - ``execute_single(fn)`` — ``ThingExecutor.executeSingleThread``
      (default: run inline).
    - ``execute_oldest(fn)`` — ``excutorDiscardOldestPolicy`` (default:
      inline).
    - ``post(fn)`` — the main-thread ``Handler.post`` for results
      (default: inline).
    - ``context`` — package-name provider for ``getAppId`` ("" when absent).
    """

    MSG_GW_ON = 1
    MSG_GW_OFF = 2
    MSG_DEV_RESPONSE = 3
    MSG_CLOSE_SERVICE = 4
    MSG_SERVICE_DISCONNECTED = 5
    MSG_SERVICE_CONNECTED = 6

    def __init__(
        self,
        service: Any = None,
        *,
        execute_single: Callable[[Callable[[], None]], None] | None = None,
        execute_oldest: Callable[[Callable[[], None]], None] | None = None,
        post: Callable[[Callable[[], None]], None] | None = None,
        context: Any = None,
    ) -> None:
        self.service = service
        self.connected = service is not None  # pbpqqdp
        self._execute_single = execute_single or (lambda fn: fn())
        self._execute_oldest = execute_oldest or (lambda fn: fn())
        self._post = post or (lambda fn: fn())
        self._context = context
        self._reassembly = b""  # qpbpqpq
        self.dev_response_listeners: list[Any] = []  # pbqpqdq
        self.service_disconnect_listeners: list[Any] = []  # qqpdpbp (dddpppb)
        self.parse_pkg_listeners: list[Any] = []  # IParsePkgFrameListener
        self.hardware_log_delegate: Any = None  # qqbbddb

    # --- listener registration -------------------------------------------

    def add_dev_response_listener(self, listener: Any) -> None:
        """``bdpdqbp(pbqpqdq)`` — no duplicates."""
        if listener is not None and listener not in self.dev_response_listeners:
            self.dev_response_listeners.append(listener)

    def add_service_disconnect_listener(self, listener: Any) -> None:
        """``bdpdqbp(dddpppb)`` — gets ``pdqppqb()`` on connect and
        ``bdpdqbp()`` on disconnect."""
        if listener is not None and listener not in self.service_disconnect_listeners:
            self.service_disconnect_listeners.append(listener)

    def add_parse_pkg_frame_listener(self, listener: Any) -> None:
        if listener is not None and listener not in self.parse_pkg_listeners:
            self.parse_pkg_listeners.append(listener)

    def set_hardware_log_delegate(self, delegate: Any) -> None:
        """``bdpdqbp(qqbbddb)``."""
        self.hardware_log_delegate = delegate

    # --- control path ------------------------------------------------------

    def control(self, dev_id: str, type_: int, data: bytes, cb: Any = None) -> None:
        """``bdpdqbp(String, int, byte[], bddbqbq)`` — executor hop → AIDL
        ``controlByBinary`` → handler-posted result."""
        if not self.connected:
            log.error("dev transfer is closed")
            if cb is not None:
                cb.on_error(ERR_LOCAL_CONTROL, ERR_TRANSFER_CLOSED_MSG)
            return

        def run() -> None:
            try:
                if self.service is not None:
                    ret = self.service.control_by_binary(dev_id, type_, data)
                    if cb is not None:
                        self._post(_ControlRunnableResult(cb, ret).run)
            except Exception:
                log.exception("controlByBinary")

        self._execute_single(run)

    def add_dev(self, hgw: HgwBean, local_key: str | None = None, net_id: int = 0) -> None:
        """``bdpdqbp(HgwBean, String, long)`` — ``addGw`` via the
        discard-oldest executor; silent when the service is closed."""
        if self.service is None:
            log.error("addDev failure with transfer service null")
            return

        def run() -> None:
            self.service.add_gw(hgw, local_key, net_id)

        self._execute_oldest(run)

    def delete_dev(self, dev_id: str) -> None:
        if self.service is not None:
            self.service.delete_gw(dev_id)

    def delete_all_dev(self) -> None:
        if self.service is not None:
            self.service.delete_all_gw()

    def get_dev_id(self, dev_id: str) -> HgwBean | None:
        """``getDevId`` → service ``getGw``; ``None`` when closed."""
        if not self.connected:
            return None
        try:
            if self.service is not None:
                return self.service.get_gw(dev_id)
        except Exception:
            log.exception("getDevId")
        return None

    def query_dev(self) -> list[HgwBean]:
        if self.service is not None:
            return self.service.query_gw()
        return []

    def close_service(self) -> None:
        """``pdqppqb(Context)`` — unbind; models ``connected = False``."""
        self.connected = False
        if self.service is not None:
            self.service.close_service()

    # --- AIDL callback surface (ITransferAidlInterface$Stub = $2) -----------

    def get_app_id(self) -> str:
        ctx = self._context() if callable(self._context) else self._context
        if ctx is None:
            return ""
        return getattr(ctx, "package_name", "") or ""

    def gw_on(self, hgw: HgwBean) -> None:
        self.handle(self.MSG_GW_ON, hgw)

    def gw_off(self, hgw: HgwBean) -> None:
        self.handle(self.MSG_GW_OFF, hgw)

    def hardware_log(self, level: int, dev_id: str, lpv: str, code: int, type_: int) -> None:
        if self.hardware_log_delegate is not None:
            self.hardware_log_delegate.hardware_log(level, dev_id, lpv, code, type_)

    def parse_pkg_frame_progress(self, seq_num: int, pack_num: int) -> None:
        for listener in self.parse_pkg_listeners:
            listener.on_parse_pkg_frame_changed(seq_num, pack_num)

    def response_by_binary(
        self,
        dev_id: str,
        version: str | None,
        type_: int,
        seq: int,
        code: int,
        data: bytes,
    ) -> None:
        """``$2.responseByBinary`` — GW_LOG frames go through multi-package
        reassembly before the HResponse is posted."""
        resp = HResponse(
            dev_id=dev_id,
            type=type_,
            seq=seq,
            code=code,
            data_binary=data,
            version=version,
        )
        if type_ == FrameTypeEnum.LAN_REQUEST_GW_LOG:
            assembled = self._reassemble(data)
            if assembled is not None:
                try:
                    resp.data_binary = bytes(assembled)
                    self._reassembly = b""
                    self.handle(self.MSG_DEV_RESPONSE, resp)
                except Exception:
                    log.exception("TCPConnect handler Exception")
            return
        self.handle(self.MSG_DEV_RESPONSE, resp)

    def _reassemble(self, data: bytes) -> bytes | None:
        """``bdpdqbp([B)`` — appends ``data[8:]`` to the buffer; returns the
        buffer when ``packNum == seqNum`` (last fragment), else ``None``."""
        pack_num = bytes_to_int2(data, 0)
        seq_num = bytes_to_int2(data, 4)
        self._reassembly = self._reassembly + bytes(data[8:])
        if pack_num == seq_num:
            return self._reassembly
        return None

    # --- handler ------------------------------------------------------------

    def handle(self, what: int, obj: Any = None) -> bool:
        """``handleMessage`` — the main-thread dispatch."""
        if what == self.MSG_GW_ON:
            if isinstance(obj, HgwBean):
                self.on_dev_update(obj, True)
        elif what == self.MSG_GW_OFF:
            if isinstance(obj, HgwBean):
                self.on_dev_update(obj, False)
        elif what == self.MSG_DEV_RESPONSE:
            self.on_dev_response(obj)
        elif what == self.MSG_CLOSE_SERVICE:
            ctx = self._context() if callable(self._context) else self._context
            if ctx is not None:
                self.close_service()
        elif what == self.MSG_SERVICE_DISCONNECTED:
            self.connected = False
            for listener in self.service_disconnect_listeners:
                listener.on_service_disconnected()
        elif what == self.MSG_SERVICE_CONNECTED:
            # $qddqppb runnable — runs on the discard-oldest executor:
            # asInterface(binder) → service, registerCallback($2 stub),
            # dddpppb.pdqppqb() fanout, then pbpqqdp = true.
            def connect() -> None:
                self.service = obj
                if self.service is not None:
                    self.service.register_callback(self)
                for listener in self.service_disconnect_listeners:
                    if listener is not None:
                        listener.on_service_connected()
                self.connected = True

            self._execute_oldest(connect)
        return False

    def on_dev_response(self, resp: HResponse) -> None:
        for listener in self.dev_response_listeners:
            if listener is not None:
                listener.on_dev_response(resp)

    def on_dev_update(self, hgw: HgwBean, online: bool) -> None:
        for listener in self.dev_response_listeners:
            if listener is not None:
                listener.on_dev_update(hgw, online)


# ---------------------------------------------------------------------------
# bdbbqqd — qpqbbpp facade (hardware service proxy)
# ---------------------------------------------------------------------------


class HardwareServiceProxy:
    """``bdbbqqd`` — the ``qpqbbpp`` facade over the transfer model and the
    broadcast-monitor model. ``add_hgw`` drops the localKey for lpv < 3.4."""

    def __init__(
        self,
        transfer: TransferModel | None = None,
        monitor: Any = None,
    ) -> None:
        self.transfer = transfer
        self.monitor = monitor

    def add_hgw(self, hgw: HgwBean, local_key: str | None = None, net_id: int = 0) -> None:
        """``addHgw`` — 3-arg: lpv ≥ 3.4 keeps the key, else dropped."""
        if check_hgw_version(hgw.version, 3.4):
            self.transfer.add_dev(hgw, local_key, net_id)
            return
        self.transfer.add_dev(hgw, None, net_id)

    def control(self, dev_id: str, type_: int, data: bytes, cb: Any = None) -> None:
        if self.transfer is not None:
            self.transfer.control(dev_id, type_, data, cb)

    def delete_dev(self, dev_id: str) -> None:
        self.transfer.delete_dev(dev_id)

    def delete_all_dev(self) -> None:
        self.transfer.delete_all_dev()

    def get_dev_id(self, dev_id: str) -> HgwBean | None:
        return self.transfer.get_dev_id(dev_id)

    def query_dev(self) -> list[HgwBean]:
        return self.transfer.query_dev()

    def remove_hgw_from_monitor_service(self, dev_id: str) -> None:
        self.monitor.remove_dev(dev_id)

    def add_dev_response_listener(self, listener: Any) -> None:
        """``bdpdqbp(pbqpqdq)`` → ``GwTransferModel``."""
        self.transfer.add_dev_response_listener(listener)

    def remove_dev_response_listener(self, listener: Any) -> None:
        """``pdqppqb(pbqpqdq)`` → ``GwTransferModel``."""
        if listener in self.transfer.dev_response_listeners:
            self.transfer.dev_response_listeners.remove(listener)

    def add_monitor_listener(self, listener: Any) -> None:
        """``bdpdqbp(qbdqpqq)`` → ``GwBroadcastMonitorModel``."""
        self.monitor.add_monitor_listener(listener)

    def remove_monitor_listener(self, listener: Any) -> None:
        """``pdqppqb(qbdqpqq)`` → ``GwBroadcastMonitorModel``."""
        self.monitor.remove_monitor_listener(listener)

    def add_monitor_config_listener(self, listener: Any) -> None:
        """``pdqppqb(qpbdppq)`` → ``GwBroadcastMonitorModel.bdpdqbp``."""
        self.monitor.add_config_listener(listener)

    def remove_service_disconnect_listener(self, listener: Any) -> None:
        """``pdqppqb(dddpppb)`` → ``GwTransferModel``."""
        if listener in self.transfer.service_disconnect_listeners:
            self.transfer.service_disconnect_listeners.remove(listener)

    def add_service_disconnect_listener(self, listener: Any) -> None:
        self.transfer.add_service_disconnect_listener(listener)

    def add_parse_pkg_frame_listener(self, listener: Any) -> None:
        self.transfer.add_parse_pkg_frame_listener(listener)

    def set_hardware_log_delegate(self, delegate: Any) -> None:
        self.transfer.set_hardware_log_delegate(delegate)

    def stop_service(self, context: Any = None) -> None:
        """``stopService(Context)`` — unbind/stop the transfer service."""
        self.transfer.close_service()

    def just_stop_service(self, context: Any = None) -> None:
        self.transfer.close_service()


# ---------------------------------------------------------------------------
# dbpbdpb — ThingHgwBeanCacheManager
# ---------------------------------------------------------------------------


class HgwBeanCache:
    """``dbpbdpb`` — the devId → HgwBean map behind ``putHgwBean`` /
    ``getDevId`` / ``removeHgwBean``."""

    def __init__(self) -> None:
        self._map: dict[str, HgwBean] = {}

    def get(self, dev_id: str | None) -> HgwBean | None:
        if dev_id is None:
            return None
        return self._map.get(dev_id)

    def put(self, dev_id: str, hgw: HgwBean | None) -> None:
        """``bdpdqbp(String, HgwBean)`` — empty key or null bean ignored."""
        if text_is_empty(dev_id) or hgw is None:
            return
        self._map[dev_id] = hgw

    def remove(self, dev_id: str) -> None:
        self._map.pop(dev_id, None)


# ---------------------------------------------------------------------------
# Inbound LAN response parsers — bdbbqbd family + bqqbpqb dispatch
# ---------------------------------------------------------------------------


class LocalRespParseBuilder:
    """``bqpbddq`` — builder for the STATUS/DP response parse chain."""

    def __init__(self) -> None:
        self.data: bytes = b""
        self.dev_id: str | None = None
        self.lpv: str | None = None
        self.local_key: str | None = None
        self.dedup: Any = None  # bdbdqdp — isDataUpdated(devId, s[, o])

    def build(self) -> LocalRespManager:
        return LocalRespManager(self)


def _dedup_drop(dedup: Any, dev_id: str, s: int, o: int | None = None) -> bool:
    """``bdbdqdp.isDataUpdated`` — true means the frame is a duplicate and
    is dropped."""
    if dedup is None:
        return False
    if o is None:
        return bool(dedup(dev_id, s))
    return bool(dedup(dev_id, s, o))


class _LocalRespParser:
    """``bdbbqbd`` — base: stores the ``dddddqd`` callback and provides the
    ``bdpdqbp(HDpResponse)`` delivery (null resp → ``onError`` twice the
    same message)."""

    def __init__(self, builder: LocalRespParseBuilder) -> None:
        self.spec = builder
        self.cb: Any = None

    def parse(self, cb: Any) -> None:
        self.cb = cb
        self._parse()

    def _deliver(self, resp: HDpResponse | None) -> None:
        if self.cb is None:
            return
        if resp is None:
            self.cb.on_error("result data is null", "result data is null")
            return
        self.cb.on_dp_response(resp)

    def _parse(self) -> None:
        raise NotImplementedError


class _LocalResp34(_LocalRespParser):
    """``pqqqddq`` — lpv ≥ 3.4: ``ver(3B)‖0*4‖s‖o‖json`` plaintext."""

    def _parse(self) -> None:
        header = _parse_sr_header(self.spec.data)
        if _dedup_drop(self.spec.dedup, self.spec.dev_id, header.s, header.o):
            log.debug("Data is Updated")
            return
        payload = self.spec.data[15:]
        obj = parse_object(payload.decode(errors="replace"))
        if self.cb is not None:
            # Java NPEs on a missing "protocol" — caught by bqqbpqb.
            protocol = obj.get("protocol")
            if protocol is None:
                raise TypeError("protocol is null")
            self.cb.on_local_data(self.spec.dev_id, int(protocol), obj)


class _LocalResp32(_LocalRespParser):
    """``ppbdppp`` — lpv ≥ 3.2: same header, AES-ECB payload."""

    def _parse(self) -> None:
        header = _parse_sr_header(self.spec.data)
        if _dedup_drop(self.spec.dedup, self.spec.dev_id, header.s, header.o):
            log.debug("Data is Updated")
            return
        payload = self.spec.data[15:]
        resp = None
        if not text_is_empty(self.spec.local_key):
            try:
                plain = AESUtil(self.spec.local_key.encode()).decrypt_with_bytes(payload)
                resp = _parse_hdp_response(plain)
            except Exception:
                resp = None
        self._deliver(resp)


class _LocalResp31(_LocalRespParser):
    """``bdqqqpq`` — lpv ≥ 3.1 or == 1.1: ``lpv‖sign16‖base64``."""

    def _parse(self) -> None:
        text = self.spec.data.decode(errors="replace")
        body = text[3:]  # substring(3) — strip the lpv chars
        sign = body[0:16]
        enc = body[16:]
        resp = self._decrypt(enc)
        if resp is None:
            log.debug("hdpResponse == null")
            return
        if resp.s != -1 and _dedup_drop(self.spec.dedup, self.spec.dev_id, resp.s):
            log.debug("Data is Updated")
            return
        expected = sign_lpv(self.spec.lpv or "", enc, self.spec.local_key or "")
        if sign == expected:
            self._deliver(resp)
            return
        log.debug("The sign is invaild")

    def _decrypt(self, enc: str) -> HDpResponse | None:
        """``pbbqpqd.bdpdqbp(String, String)`` — AES-ECB ``decryptWithBase64``
        → HDpResponse; empty key or failure → ``None``."""
        if text_is_empty(self.spec.local_key):
            return None
        try:
            plain = AESUtil(self.spec.local_key.encode()).decrypt_with_base64(enc)
            return _parse_hdp_response(plain)
        except Exception:
            return None


class _LocalRespDefault(_LocalRespParser):
    """``dqbpdbq`` — plaintext JSON → HDpResponse."""

    def _parse(self) -> None:
        self._deliver(_parse_hdp_response(self.spec.data))


class LocalRespManager:
    """``bqqbpqb`` — lpv dispatcher; parser exceptions are swallowed into
    the ``LocalRespManager parseResp`` log."""

    def __init__(self, builder: LocalRespParseBuilder) -> None:
        self.spec = builder

    def parse(self, cb: Any) -> None:
        try:
            lpv = self.spec.lpv
            if check_hgw_version(lpv, 3.4):
                parser = _LocalResp34(self.spec)
            elif check_hgw_version(lpv, 3.2):
                parser = _LocalResp32(self.spec)
            elif check_hgw_version(lpv, 3.1) or is_hgw_version_equals(lpv, "1.1"):
                parser = _LocalResp31(self.spec)
            else:
                parser = _LocalRespDefault(self.spec)
            parser.parse(cb)
        except Exception:
            log.exception("parseResp")


# ---------------------------------------------------------------------------
# dpppdpq — ThingHardwareManager (IThingHardware)
# ---------------------------------------------------------------------------


class _HRequestCallback:
    """``dpppdpq$bdpdqbp`` — the ``ddbbppb`` receiving the assembled
    ``HRequest``: sends bytes through the service and fires the
    message-send log."""

    def __init__(
        self,
        manager: ThingHardwareManager,
        cb: Any,
        dev_id: str,
        frame_type: int,
        entry_ms: int,
        bean: ThingLocalControlBean,
    ) -> None:
        self.manager = manager
        self.cb = cb
        self.dev_id = dev_id
        self.frame_type = frame_type
        self.entry_ms = entry_ms
        self.bean = bean

    def on_success(self, request: HRequest) -> None:
        """``$bdpdqbp.bdpdqbp(HRequest)`` — send via the raw control path,
        then ``messageSendLogCallback(devId, frameType, lpv)``."""
        data = bytes(request.data)
        log.debug("%s", data)
        manager = self.manager

        class _Inner:  # dpppdpq$bdpdqbp$bdpdqbp
            def on_error(inner, code: str, msg: str) -> None:
                # Java dereferences the outer callback without a null check.
                self.cb.on_error(code, msg)

            def on_success(inner) -> None:
                listener = manager.log_event_listener
                if listener is not None:
                    listener.record_log_callback(
                        self.dev_id,
                        self.frame_type,
                        len(data),
                        manager._clock_ms() - self.entry_ms,
                    )
                self.cb.on_success()

        manager._control_bytes(self.dev_id, self.frame_type, data, _Inner())
        manager.message_send_log(self.dev_id, self.frame_type, self.bean.lpv)

    def on_error(self, code: str, msg: str) -> None:
        if self.cb is not None:
            self.cb.on_error(code, msg)


class _StatusDelivery:
    """``dpppdpq$pppbppp`` — ``dddddqd`` delivering parsed STATUS bodies to
    ``ILocalDpMessageRespListener``."""

    def __init__(self, listener: Any, resp: HResponse) -> None:
        self.listener = listener
        self.resp = resp

    def on_dp_response(self, dp: HDpResponse) -> None:
        dev_id = self.resp.dev_id
        if dp.ctype == 2:
            if not text_is_empty(dp.mbid):
                self.listener.on_local_dp_zigbee_group_received_success(dev_id, dp.mbid, dp.dps)
            return
        if dp.cid != dev_id and not text_is_empty(dp.cid):
            self.listener.on_local_dp_sub_device_received_success(
                dev_id, dp.cid, dp.ctype, dp.dps, dp.t
            )
            return
        self.listener.on_local_dp_received_success(dev_id, dp.dps, dp.t)

    def on_local_data(self, dev_id: str, protocol: int, obj: dict) -> None:
        self.listener.on_local_data_received(dev_id, protocol, obj)

    def on_error(self, code: str, msg: str) -> None:
        self.listener.on_local_dp_received_error(self.resp.dev_id, code, msg)


class _StatusDedup:
    """``dpppdpq$qddqppb`` — ``bdbdqdp`` delegating to the listener's
    ``isDataUpdated``."""

    def __init__(self, listener: Any) -> None:
        self.listener = listener

    def __call__(self, dev_id: str, s: int, o: int | None = None) -> bool:
        if o is None:
            return bool(self.listener.is_data_updated(dev_id, s))
        log.debug("updateLocalDpData s: %s o: %s", dev_id, o)
        return bool(self.listener.is_data_updated(dev_id, s, o))


class ThingHardwareManager:
    """``dpppdpq`` — ``IThingHardware``.

    Seams:

    - ``service`` — ``qpqbbpp`` (:class:`HardwareServiceProxy` or double).
    - ``hgw_cache`` — :class:`HgwBeanCache` (``dbpbdpb``).
    - listeners: ``local_dp_listener`` (``ILocalDpMessageRespListener`` —
      ``get_lpv``/``get_local_key``/``is_data_updated``/``on_local_dp_*``),
      ``raw_response_listener`` (``IDevResponseWithoutDpDataListener`` —
      ``on_response(devId, type, ok, data)``), ``local_online_listener``
      (``ILocalOnlineStatusListener``), ``ble_connect_listener``
      (``IGwBleConnectStatusListener``), ``log_event_listener``
      (``IHardwareLogEventListener`` — ``message_send_log_callback`` /
      ``message_received_log_callback`` / ``hardware_log``).
    - ``clock_ms`` — ``SystemClock.elapsedRealtime`` for the control span;
      ``wall_ms`` for the log timestamps.
    """

    def __init__(
        self,
        service: HardwareServiceProxy,
        native: ThingNetworkApi | None = None,
        *,
        hgw_cache: HgwBeanCache | None = None,
        clock_ms: Callable[[], int] = lambda: int(time.monotonic() * 1000),
        wall_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ) -> None:
        self.service = service
        self.native = native if native is not None else ThingNetworkApi()
        self.hgw_cache = hgw_cache if hgw_cache is not None else HgwBeanCache()
        self._clock_ms = clock_ms
        self._wall_ms = wall_ms
        self.local_dp_listener: Any = None  # bpbbqdb
        self.raw_response_listener: Any = None  # bqqppqq
        self.local_online_listener: Any = None  # qqpdpbp
        self.ble_connect_listener: Any = None  # pbpqqdp
        self.log_event_listener: Any = None  # dqdpbbd
        self.config_listeners: list[Any] = []  # pqpbpqd
        self.find_listeners: list[Any] = []  # dpdqppp
        self._registered = False  # qqdbbpp

    # --- listener registration (qddqppb) -------------------------------------

    def register(self) -> None:
        """``qddqppb()`` — one-shot registration on the service: dev-response
        → hardware-log → monitor listener (``qbdqpqq``) → disconnect listener
        → monitor config listener (``qpbdppq``), then ``qqdbbpp = true``."""
        if self._registered:
            return
        self.service.add_dev_response_listener(self)
        self.service.set_hardware_log_delegate(self)
        self.service.add_monitor_listener(self)
        self.service.add_service_disconnect_listener(self)
        self.service.add_monitor_config_listener(self)
        self._registered = True

    def unregister(self, context: Any = None) -> None:
        """``pdqppqb(Context)`` — stopService, remove the three listener
        registrations, ``qqdbbpp = false``, clear the find-listener list."""
        self.service.stop_service(context)
        self.service.remove_dev_response_listener(self)
        self.service.remove_monitor_listener(self)
        self.service.remove_service_disconnect_listener(self)
        self._registered = False
        if self.find_listeners:
            self.find_listeners.clear()

    # --- outbound control -----------------------------------------------------

    def control(self, *args: Any) -> None:
        """Overloads:

        - ``control(ThingLocalControlBean, cb)`` — assemble per lpv → send.
        - ``control(dev_id, type, data_bytes, cb)`` — raw send via service.
        """
        if isinstance(args[0], ThingLocalControlBean):
            self._control_bean(args[0], args[1] if len(args) > 1 else None)
        else:
            dev_id, type_, data = args[0], args[1], args[2]
            cb = args[3] if len(args) > 3 else None
            self._control_bytes(dev_id, type_, data, cb)

    def _control_bean(self, bean: ThingLocalControlBean, cb: Any = None) -> None:
        """``control(ThingLocalControlBean, IResultCallback)`` — captures
        ``elapsedRealtime`` at entry (used for ``recordLogCallback``'s span)."""
        entry_ms = self._clock_ms()
        spec = LocalControlSpec(
            dev_id=bean.dev_id,
            frame_type=bean.frame_type,
            data=bean.data,
            lpv=bean.lpv or "",
            local_key=bean.local_key,
            s=bean.s,
            o=bean.o,
            t=bean.t,
            protocol=bean.protocol,
        )
        handler = _HRequestCallback(self, cb, bean.dev_id, bean.frame_type, entry_ms, bean)
        try:
            request = assemble_request(spec)
        except SignatureError as exc:
            handler.on_error(exc.code, exc.message)
            return
        handler.on_success(request)

    def _control_bytes(self, dev_id: str, type_: int, data: bytes, cb: Any = None) -> None:
        """``control(String, int, byte[], IResultCallback)``."""
        self.service.control(dev_id, type_, data, cb)

    def lan_gw_update(self, dev_id: str, path: str, cb: Any = None) -> None:
        """``lanGwUpdate`` — ``LAN_GW_UPDATE`` frame with ``file://`` body."""
        data = ("file://" + path).encode()
        self.control(dev_id, FrameTypeEnum.LAN_GW_UPDATE, data, cb)

    def normal_control(self, bean: Any, cb: Any = None) -> None:
        """``normalControl`` (deprecated, ``ThingLocalNormalControlBean``) —
        ``toJSONString(data)`` → lpv ≥ 3.4 plaintext; ≥ 3.3 →
        ``IPC_LAN_LOCAL_CONFIG`` uses the hex-key AES helper, else
        ``encryptAesData``; < 3.3 plaintext. ``ddbdpdp``→``bqbdpqd`` just
        forwards the bytes, so this calls the raw control path directly and
        then ``messageSendLogCallback``."""
        text = to_json_string(bean.data)
        if check_hgw_version(bean.lpv, 3.4):
            data = text.encode()
        elif check_hgw_version(bean.lpv, 3.3):
            if bean.frame_type == FrameTypeEnum.IPC_LAN_LOCAL_CONFIG:
                data = self._encrypt_hex_key(bean.local_key, text)
            else:
                data = self.native.encrypt_aes_data(text, bean.local_key)
        else:
            data = text.encode()
        # bqbdpqd.bdpdqbp(ddbbppb) → onSuccess(HRequest{devId,type,data})
        self._control_bytes(bean.dev_id, bean.frame_type, data, cb)
        self.message_send_log(bean.dev_id, bean.frame_type, bean.lpv)

    def _encrypt_hex_key(self, local_key: str, text: str) -> bytes | None:
        """``bdpdqbp(String, String)[B`` — AES/ECB with the hex-decoded key;
        failure → ``None``."""
        try:
            return AESUtil(hex_string_to_bytes(local_key)).encrypt_with_bytes(text)
        except Exception:
            return None

    # --- gw bookkeeping --------------------------------------------------------

    def add_hgw(self, hgw: HgwBean, local_key: str | None = None, net_id: int = 0) -> None:
        """``addHgw`` overloads — 1/2-arg (netId only) go straight to the
        service; the keyed variants drop the key for lpv < 3.4 inside the
        proxy."""
        self.service.add_hgw(hgw, local_key, net_id)

    def delete_dev(self, dev_id: str) -> None:
        if text_is_empty(dev_id):
            log.error("devId: ==null")
            return
        self.service.delete_dev(dev_id)

    def delete_all_dev(self) -> None:
        self.service.delete_all_dev()

    def get_dev_id(self, dev_id: str) -> HgwBean | None:
        return self.hgw_cache.get(dev_id)

    def put_hgw_bean(self, dev_id: str, hgw: HgwBean | None) -> None:
        self.hgw_cache.put(dev_id, hgw)

    def remove_hgw_bean(self, dev_id: str) -> None:
        self.hgw_cache.remove(dev_id)

    def query_dev(self) -> list[HgwBean]:
        return self.service.query_dev()

    # --- inbound dispatch (pbqpqdq impl) ---------------------------------------

    def on_dev_update(self, hgw: HgwBean, online: bool) -> None:
        """``onDevUpdate`` — offline updates for unknown gws are dropped."""
        if not online and self.get_dev_id(hgw.gw_id) is None:
            return
        if self.local_online_listener is not None:
            self.local_online_listener.on_dev_update(hgw, online)

    def on_dev_response(self, resp: HResponse) -> None:
        """``onDevResponse`` — ``FrameTypeEnum.to(type)`` then the
        ``$pbbppqb`` switch: STATUS → parse chain; DP_QUERY_NEW/DP_QUERY →
        direct HDpResponse handling; HEART_BEAT → return;
        LAN_REQUEST_GW_LOG → raw listener, no decrypt;
        FRM_LAN_EXT_STREAM → ext-stream parse **then** the default branch;
        everything else → default branch."""
        try:
            if resp.type != FrameTypeEnum.HEART_BEAT:
                self._log_received(resp)
            if resp.type == FrameTypeEnum.STATUS:
                self._on_status(resp)
            elif resp.type in (
                FrameTypeEnum.DP_QUERY_NEW,
                FrameTypeEnum.DP_QUERY,
            ):
                self._on_dp_query(resp)
            elif resp.type == FrameTypeEnum.HEART_BEAT:
                return
            elif resp.type == FrameTypeEnum.LAN_REQUEST_GW_LOG:
                self._on_gw_log(resp)
            elif resp.type == FrameTypeEnum.FRM_LAN_EXT_STREAM:
                self._on_ext_stream(resp)
                self._on_other(resp)
            else:
                self._on_other(resp)
        except Exception:
            log.exception("hardware response error")

    def _log_received(self, resp: HResponse) -> None:
        """``bdpdqbp(HResponse)`` — ``messageReceivedLogCallback``."""
        listener = self.log_event_listener
        if listener is not None:
            model = {
                "type": resp.type,
                "code": resp.code,
                "index": resp.seq,
                "lpv": resp.version,
            }
            listener.message_received_log_callback(
                {
                    "devId": resp.dev_id,
                    "type": 4,
                    "time": self._wall_ms(),
                    "readModels": [model],
                }
            )

    def _on_status(self, resp: HResponse) -> None:
        """``qddqppb(HResponse)`` — STATUS → ``bqpbddq`` parse chain."""
        listener = self.local_dp_listener
        if listener is None:
            return
        if resp.code != 0:
            listener.on_local_dp_received_error(
                resp.dev_id, ERR_LOCAL_CONTROL, "hResponse return code != 0"
            )
            return
        builder = LocalRespParseBuilder()
        builder.data = resp.data_binary
        builder.dev_id = resp.dev_id
        builder.lpv = resp.version
        builder.local_key = listener.get_local_key(resp.dev_id)
        builder.dedup = _StatusDedup(listener)
        builder.build().parse(_StatusDelivery(listener, resp))

    def _on_dp_query(self, resp: HResponse) -> None:
        """``pswitch_2`` — DP_QUERY_NEW/DP_QUERY. Code != 0 →
        ``onLocalDpReceivedError``; else decrypt by lpv (≥3.4 plaintext,
        ≥3.3 ``parseAesData``, else plaintext), parse ``HDpResponse``, and
        route. The ``cid`` sub-device check applies to DP_QUERY_NEW at
        ≥3.3 and to *both* frame types below 3.3."""
        listener = self.local_dp_listener
        if resp.code != 0:
            if listener is not None:
                listener.on_local_dp_received_error(
                    resp.dev_id, ERR_LOCAL_CONTROL, "hResponse return code != 0"
                )
            return
        if listener is None:
            return
        lpv = listener.get_lpv(resp.dev_id)
        if check_hgw_version(lpv, 3.4):
            data = resp.data_binary
        elif check_hgw_version(lpv, 3.3):
            data = self._parse_aes(resp.data_binary, listener.get_local_key(resp.dev_id))
        else:
            data = resp.data_binary
        dp = _parse_hdp_response(data)
        if dp is None:
            return
        check_cid = resp.type == FrameTypeEnum.DP_QUERY_NEW or not (
            check_hgw_version(lpv, 3.4) or check_hgw_version(lpv, 3.3)
        )
        if check_cid and dp.cid != resp.dev_id and not text_is_empty(dp.cid):
            listener.on_local_dp_sub_device_received_success(
                resp.dev_id, dp.cid, dp.ctype, dp.dps, dp.t
            )
            return
        listener.on_local_dp_received_success(resp.dev_id, dp.dps, dp.t)

    def _on_gw_log(self, resp: HResponse) -> None:
        """``pswitch_1`` — LAN_REQUEST_GW_LOG → raw-response listener."""
        listener = self.raw_response_listener
        if listener is not None:
            listener.on_response(resp.dev_id, resp.type, resp.code == 0, resp.data_binary)
        else:
            log.warning("DevResponseWithoutDpDataListener is empty  : %s", resp)

    def _on_ext_stream(self, resp: HResponse) -> None:
        """``bppdpdq(HResponse)`` — FRM_LAN_EXT_STREAM: decrypt per lpv
        (≥3.4 plaintext; ≥3.3 ``parseAesData``, null → ``""``; else
        plaintext), JSON, ``reqType == "subdev_online_stat_report"`` →
        online/offline/nearby lists."""
        listener = self.local_dp_listener
        lpv = listener.get_lpv(resp.dev_id)
        if check_hgw_version(lpv, 3.4):
            text = resp.data_binary.decode(errors="replace")
        elif check_hgw_version(lpv, 3.3):
            plain = self._parse_aes(resp.data_binary, listener.get_local_key(resp.dev_id))
            text = plain.decode(errors="replace") if plain is not None else ""
        else:
            text = resp.data_binary.decode(errors="replace")
        if text_is_empty(text):
            return
        obj = parse_object(text)
        if not isinstance(obj, dict):
            return
        if obj.get("reqType") != "subdev_online_stat_report":
            return
        data = obj.get("data")
        if not isinstance(data, dict):
            return
        online = [str(v) for v in data.get("online") or []]
        offline = [str(v) for v in data.get("offline") or []]
        nearby = [str(v) for v in data.get("nearby") or []]
        if self.local_online_listener is not None:
            self.local_online_listener.on_sub_dev_update(resp.dev_id, online, offline)
        if self.ble_connect_listener is not None:
            self.ble_connect_listener.on_connect_status_changed(
                resp.dev_id, online, offline, nearby
            )

    def _on_other(self, resp: HResponse) -> None:
        """``pdqppqb(HResponse)`` — default branch → ``bqqppqq`` raw
        listener; ≥ 3.3 bodies are AES-decrypted (``IPC_LAN_LOCAL_CONFIG``
        uses the hex-key variant)."""
        listener = self.raw_response_listener
        if listener is None:
            return
        if check_hgw_version(resp.version, 3.4):
            listener.on_response(resp.dev_id, resp.type, resp.code == 0, resp.data_binary)
            return
        if check_hgw_version(resp.version, 3.3):
            key = self.local_dp_listener.get_local_key(resp.dev_id)
            if resp.type == FrameTypeEnum.IPC_LAN_LOCAL_CONFIG:
                data = self._decrypt_hex_key(resp, key)
            else:
                data = self._parse_aes(resp.data_binary, key)
            listener.on_response(resp.dev_id, resp.type, resp.code == 0, data)
            return
        listener.on_response(resp.dev_id, resp.type, resp.code == 0, resp.data_binary)

    def _decrypt_hex_key(self, resp: HResponse, local_key: str) -> bytes | None:
        """``bdpdqbp(HResponse, String)[B`` — AES/ECB decrypt with the
        hex-decoded key; failure → ``None``."""
        try:
            return AESUtil(hex_string_to_bytes(local_key)).decrypt_with_bytes(resp.data_binary)
        except Exception:
            return None

    def _parse_aes(self, data: bytes, key: str) -> bytes | None:
        """``ThingNetworkApi.parseAesData`` seam."""
        try:
            return self.native.parse_aes_data(data, key)
        except Exception:
            return None

    # --- misc listeners -------------------------------------------------------

    def on_dev_config_result(self, dev_id: str) -> None:
        """``bdpdqbp(String)`` — ``IDeviceHardwareConfigListener`` fanout."""
        for listener in self.config_listeners:
            listener.on_dev_config_result(dev_id)

    def on_find(self, hgw_list: list[HgwBean]) -> None:
        """``onFind(List)`` — ``IDeviceHardwareFindListener`` fanout."""
        for listener in self.find_listeners:
            listener.on_find(hgw_list)

    def on_service_disconnected(self) -> None:
        """``dddpppb.bdpdqbp()`` — service-disconnect hook (no-op in base)."""

    def message_send_log(self, dev_id: str, frame_type: int, lpv: str) -> None:
        """``bdpdqbp(String, int, String)`` — ``messageSendLogCallback``."""
        listener = self.log_event_listener
        if listener is not None:
            listener.message_send_log_callback(dev_id, frame_type, lpv)

    def hardware_log(self, level: int, dev_id: str, lpv: str, code: int, type_: int) -> None:
        """``qqbbddb.hardwareLog`` → ``dqdpbbd.hardwareLogCallback``."""
        listener = self.log_event_listener
        if listener is not None:
            listener.hardware_log_callback(level, dev_id, lpv, code, type_)
