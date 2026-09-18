"""UDP gateway discovery and the hardware-manager glue above it.

Layer map (smali canonical):

- ``GwBroadcastMonitorService`` — the UDP broadcast listener/discovery
  sender. Listens on ports ``6650/6667/7000`` through
  ``ThingNetworkInterface`` (native), keeps a dedup'd ``gwMap`` of
  :class:`HgwBean`, drains it to ``IUDPMonitorAidlInterface`` monitors
  every 1000 ms, and repeats an ``APP_SEND_BROADCAST`` (``0x25``)
  discovery frame under ``LAN_PROTOCOL_VERSION_3_5`` (``5``).
- ``GwBroadcastMonitorModel`` — the AIDL→listener dispatcher: monitor
  ``update(list)`` fans out to ``qbdqpqq.onFind``;
  ``onConfigResult(str)`` fans out to ``qpbdppq`` config listeners.
- ``dpppdpq`` — the ``IThingHardware`` impl; its ``onFind`` forwards to
  registered ``IDeviceHardwareFindListener`` listeners (the native layer keeps
  the actual gwId→HgwBean map that ``getDevId`` reads).
- ``qbdpdpp`` — ``ThingSmartHardwareManager``: ``onFind`` decides when a
  discovered gateway is pushed into the hardware layer via ``addHgw``
  (with/without ``localKey``), tracks LAN-connect backoff per devId,
  fans ``onDevUpdate`` out to online-status listeners, and answers
  ``getLocalKey``/``getLpv``.
- ``ppqqqpb.checkGw`` / ``devRespWrap`` — gwId-in-cache check and the
  ``DeviceBean.hgwBean`` attach point (implemented in
  :mod:`pypopur.sdk.device_cache`).

Everything Android-specific (sockets, multicast lock, WiFi IP lookup,
handler/scheduler, asset load) is injectable.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from ._java import text_is_empty
from .device_cache import DeviceRespBean, DevListCacheManager
from .lan_control import FrameTypeEnum

# ---------------------------------------------------------------------------
# enums / beans


class ActiveEnum:
    """``com.thingclips.smart.interior.enums.ActiveEnum`` — ``type`` ints."""

    UNACTIVE = 0
    ACTIVING = 1
    ACTIVED = 2
    LOCAL_UNACTIVE = 3
    LOCAL_ACTIVED = 4


class DeviceActiveEnum:
    """``com.thingclips.smart.sdk.enums.DeviceActiveEnum`` — ``to(int)`` →
    name or ``None``."""

    _MAP: ClassVar[dict[int, str]] = {0: "UNACTIVE", 1: "ACTIVING", 2: "ACTIVED"}

    @staticmethod
    def to(value: int) -> str | None:
        return DeviceActiveEnum._MAP.get(value)


class SaasSdkType:
    """``com.thingclips.smart.sdk.SaasSdkType`` — only the members the
    hardware manager compares against matter."""

    NORMAL = "NORMAL"
    COMMERCIAL_LIGHTING = "COMMERCIAL_LIGHTING"
    CONSTRUCTION = "CONSTRUCTION"


@dataclass
class HgwBean:
    """``com.thingclips.smart.android.hardware.bean.HgwBean``."""

    ablilty: int = 0  # sic — Java field name
    active: int = 0
    ap_config_type: int = 0
    dev_config_attribute: int = 0
    encrypt: bool = False
    extend: str | None = None
    gw_id: str | None = None
    ip: str | None = None
    last_seen_time: int = 0
    mode: int = 0
    pro_ability: int = 0
    product_key: str | None = None
    sl: int = 0
    ssid: str | None = None
    token: bool = False
    uuid: str | None = None
    version: str | None = None
    wf_cfg: bool = False


# ---------------------------------------------------------------------------
# helpers (DevUtil / qpqbbpp)


def is_ap_directly_device_bean(resp: DeviceRespBean | None) -> bool:
    """``DevUtil.isAPDirectlyDevice(DeviceRespBean)`` — true iff ``meta``
    *contains* the key ``isSupportDirectlyDevice`` (presence, not truth)."""
    return resp is not None and resp.meta is not None and ("isSupportDirectlyDevice" in resp.meta)


def is_valid_ip(ip: str | None) -> bool:
    """``qpqbbpp.bppdpdq(String)`` — IPv4 or IPv6 parseable."""
    if text_is_empty(ip):
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# GwBroadcastMonitorService


class GwBroadcastMonitor:
    """``GwBroadcastMonitorService`` — the UDP discovery service.

    Injectable seams (``ThingNetworkInterface`` / WiFi / Android):

    - ``send_broadcast(addr, port, period_ms, data, frame_type, version,
      token) -> int`` — native ``sendBroadcast``; returns a broadcast
      token used by ``stop_broadcast``.
    - ``stop_broadcast(token) -> bool``
    - ``listen_udp(port)`` / ``shutdown_udp()``
    - ``local_ip() -> str`` (``WiFiUtil.getIpAddress``)
    - ``subnet_broadcast() -> Optional[str]`` (``getSubnetBroadcastAddress``;
      may raise — mapped to ``None``)
    - ``schedule(delay_ms, fn)`` — used for the 3000 ms subnet re-send
      and the 1000 ms drain tick.
    - ``acquire_multicast()`` / ``release_multicast()``
    - ``load_security(asset, fallback) -> bytes`` then
      ``set_security_content(bytes)``
    """

    PERIOD_MS = 1000
    SUBNET_BROADCAST_DELAY_MS = 3000
    VERSION = "3.0"
    UDP_PORTS = (6650, 6667, 7000)
    BROADCAST_ADDR = "255.255.255.255"
    BROADCAST_PORT = 7000  # 0x1b58
    BROADCAST_PERIOD_MS = 6000  # 0x1770
    FRAME_TYPE = FrameTypeEnum.APP_SEND_BROADCAST  # 0x25
    PROTOCOL_VERSION = 5  # LAN_PROTOCOL_VERSION_3_5
    SECURITY_ASSET = "fixed_key.bmp"
    SECURITY_FALLBACK = b"soisiwoejre"

    def __init__(
        self,
        *,
        send_broadcast: Callable[..., int] | None = None,
        stop_broadcast: Callable[[int], bool] | None = None,
        listen_udp: Callable[[int], None] | None = None,
        shutdown_udp: Callable[[], None] | None = None,
        local_ip: Callable[[], str | None] | None = None,
        subnet_broadcast: Callable[[], str | None] | None = None,
        schedule: Callable[[int, Callable[[], None]], None] | None = None,
        acquire_multicast: Callable[[], None] | None = None,
        release_multicast: Callable[[], None] | None = None,
        load_security: Callable[[str, bytes], bytes] | None = None,
        set_security_content: Callable[[bytes], None] | None = None,
    ) -> None:
        self._send_broadcast = send_broadcast
        self._stop_broadcast = stop_broadcast
        self._listen_udp = listen_udp
        self._shutdown_udp = shutdown_udp
        self._local_ip = local_ip
        self._subnet_broadcast = subnet_broadcast
        self._schedule = schedule
        self._acquire_multicast = acquire_multicast
        self._release_multicast = release_multicast
        self._load_security = load_security
        self._set_security_content = set_security_content

        self.finished = True  # AtomicBoolean — starts finished
        self.broadcast_token = 0
        self.subnet_broadcast_token = 0
        self.gw_map: dict[str, HgwBean] = {}
        self.monitors: list[Any] = []  # IUDPMonitorAidlInterface

    # --- lifecycle -------------------------------------------------------

    def start(self) -> bool:
        """``buildUDPReceiver`` — ``finished.compareAndSet(true,false)``."""
        if not self.finished:
            return False
        self.finished = False
        if self._acquire_multicast is not None:
            self._acquire_multicast()
        if self._set_security_content is not None:
            loader = self._load_security or (lambda asset, fb: fb)
            self._set_security_content(loader(self.SECURITY_ASSET, self.SECURITY_FALLBACK))
        if self._listen_udp is not None:
            for port in self.UDP_PORTS:
                self._listen_udp(port)
        self.send_discovery()
        if self._schedule is not None:
            self._schedule(self.PERIOD_MS, self._tick_loop)
        return True

    def stop(self) -> None:
        """``onDestroy`` — flag finished, stop broadcast + listeners."""
        self.finished = True
        self.stop_discovery()
        if self._shutdown_udp is not None:
            self._shutdown_udp()
        if self._release_multicast is not None:
            self._release_multicast()

    def _tick_loop(self) -> None:
        self.update_tick()
        if not self.finished and self._schedule is not None:
            self._schedule(self.PERIOD_MS, self._tick_loop)

    # --- PackageCallback -------------------------------------------------

    def get_gw_bean(self, hgw: HgwBean) -> None:
        """``getGWBean`` — same-gwId entries are overwritten by ``put``;
        entries with the *same ip* but a *different* gwId are evicted."""
        if self.gw_map is None:
            return
        for key in list(self.gw_map.keys()):
            entry = self.gw_map[key]
            if key != hgw.gw_id and entry.ip == hgw.ip:
                del self.gw_map[key]
        self.gw_map[hgw.gw_id] = hgw

    def on_smart_config_result(self, protocol_version: Any, code: int, config: str) -> None:
        """``OnSmartConfigResultCallback`` — dropped while finished."""
        if self.finished:
            return
        dead = []
        for monitor in list(self.monitors):
            try:
                monitor.on_config_result(config)
            except Exception:
                dead.append(monitor)
        for monitor in dead:
            self.monitors.remove(monitor)

    def update_tick(self) -> None:
        """``UpdateTimerTask.run`` — drains ``gwMap`` into a snapshot and
        pushes it to monitors; RemoteException-ish failures unregister."""
        if self.finished or self.gw_map is None:
            return
        snapshot: list[HgwBean] = []
        for key in list(self.gw_map.keys()):
            snapshot.append(self.gw_map.pop(key))
        if not snapshot:
            return
        dead = []
        for monitor in list(self.monitors):
            try:
                monitor.update(snapshot)
            except Exception:
                dead.append(monitor)
        for monitor in dead:
            self.monitors.remove(monitor)

    # --- discovery broadcast ---------------------------------------------

    def send_discovery(self) -> None:
        """``sendBroadcastForDiscovery`` — stops any in-flight broadcast,
        sends ``{"ip":…,"from":"app"}`` to ``255.255.255.255:7000`` under
        frame ``0x25``/version ``5``/period 6000 ms, and re-sends to the
        subnet broadcast address after 3000 ms when it differs."""
        self.stop_discovery()
        payload = json.dumps(
            {"ip": self._local_ip() if self._local_ip else None, "from": "app"},
            separators=(",", ":"),
        ).encode("utf-8")
        if self._send_broadcast is not None:
            self.broadcast_token = self._send_broadcast(
                self.BROADCAST_ADDR,
                self.BROADCAST_PORT,
                self.BROADCAST_PERIOD_MS,
                payload,
                self.FRAME_TYPE,
                self.PROTOCOL_VERSION,
                0,
            )
        subnet: str | None = None
        if self._subnet_broadcast is not None:
            try:
                subnet = self._subnet_broadcast()
            except Exception:
                subnet = None
        if (
            subnet is not None
            and subnet != self.BROADCAST_ADDR
            and self._send_broadcast is not None
            and self._schedule is not None
        ):

            def _subnet_send() -> None:
                self.subnet_broadcast_token = self._send_broadcast(
                    subnet,
                    self.BROADCAST_PORT,
                    self.BROADCAST_PERIOD_MS,
                    payload,
                    self.FRAME_TYPE,
                    self.PROTOCOL_VERSION,
                    0,
                )

            self._schedule(self.SUBNET_BROADCAST_DELAY_MS, _subnet_send)

    def stop_discovery(self) -> None:
        """``stopSendBroadcastForDiscovery``."""
        if (
            self.broadcast_token > 0
            and self._stop_broadcast is not None
            and self._stop_broadcast(self.broadcast_token)
        ):
            self.broadcast_token = -1
        if (
            self.subnet_broadcast_token > 0
            and self._stop_broadcast is not None
            and self._stop_broadcast(self.subnet_broadcast_token)
        ):
            self.subnet_broadcast_token = -1

    # --- monitor registry -------------------------------------------------

    def register_monitor(self, monitor: Any) -> None:
        if monitor not in self.monitors:
            self.monitors.append(monitor)

    def unregister_monitor(self, monitor: Any) -> None:
        if monitor in self.monitors:
            self.monitors.remove(monitor)


# ---------------------------------------------------------------------------
# qbdpdpp — ThingSmartHardwareManager


@dataclass
class _LanFailState:
    """``qbdpdpp$qpppdqb`` — per-devId LAN backoff bookkeeping."""

    last_ok_ms: int = 0  # bdpdqbp — last success
    last_fail_ms: int = 0  # pdqppqb — last failure
    illegal_times: int = 0  # qddqppb
    disabled_since_ms: int = 0  # bppdpdq


_LAN_DISABLE_WINDOW_MS = 0x1D4C0  # qpppdqb.pppbppp = 120_000
_LAN_ILLEGAL_BURST_MS = 1000  # fail within 1 s of last success
_LAN_STALE_MS = 60000  # entry dropped when lastFail-lastOk > 60 s
_LAN_ILLEGAL_THRESHOLD = 3


class HardwareManager:
    """``qbdpdpp`` — ``ThingSmartHardwareManager``.

    Seams:

    - ``hardware`` — ``IThingHardware``: ``get_dev_id(dev_id)`` →
      :class:`HgwBean` or ``None``; ``put_hgw_bean(gw_id, hgw)``;
      ``add_hgw(hgw, network_handle, local_key=None)`` (fuses the two
      Java overloads ``addHgw(hgw,long)`` / ``addHgw(hgw,String,long)``).
    - ``dev_cache`` — :class:`DevListCacheManager` (``get_dev_resp_bean``,
      ``check_gw``).
    - ``products`` — ``pbqdddb`` product map (``product_key``-keyed
      ``Dict[str, ProductBean]`` or a callable ``(pid, ver) -> bean``).
    - ``saas_type`` — :class:`SaasSdkType` constant.
    - ``network_handle(ip) -> int`` — ``qpqbbpp.bdpdqbp(ctx, ip)``;
      defaults to ``0``.
    - ``clock_ms()`` — ``SystemClock.elapsedRealtime`` (monotonic ms).
    - ``lan_send(gw_id, obj, frame_type, cb)`` — ``dddpppb.bdpdqbp``.
    - ``unix_ts()`` — ``TimeStampManager.getCurrentTimeStamp`` seconds.
    - ``time_zone()`` — ``ThingCommonUtil.getTimeZoneValue``.
    - ``event_send(event)`` — ``BaseEventSender.send`` seam; receives
      ``("dev_online_status", hgw, online)`` tuples for ``pdqdqbd``.
    """

    def __init__(
        self,
        *,
        hardware: Any = None,
        dev_cache: DevListCacheManager | None = None,
        products: Any = None,
        saas_type: str = SaasSdkType.NORMAL,
        network_handle: Callable[[str], int] | None = None,
        clock_ms: Callable[[], int] = lambda: int(time.monotonic() * 1000),
        lan_send: Callable[..., None] | None = None,
        unix_ts: Callable[[], int] = lambda: int(time.time()),
        time_zone: Callable[[], int] = lambda: 0,
        event_send: Callable[[Any], None] | None = None,
    ) -> None:
        self.hardware = hardware
        self.dev_cache = dev_cache
        self.products = products
        self.saas_type = saas_type
        self._network_handle = network_handle or (lambda ip: 0)
        self._clock_ms = clock_ms
        self._lan_send = lan_send
        self._unix_ts = unix_ts
        self._time_zone = time_zone
        self._event_send = event_send

        self.search_listeners: list[Any] = []  # IThingSearchDeviceListener
        self.online_listeners: list[Any] = []  # IThingHardwareOnlineStatusListener
        self._lan_fail: dict[str, _LanFailState] = {}  # pbpdpdp

    # --- listener registry ------------------------------------------------

    def add_search_listener(self, listener: Any) -> None:
        self.search_listeners.append(listener)

    def add_online_listener(self, listener: Any) -> None:
        self.online_listeners.append(listener)

    # --- LAN backoff (qpppdqb) --------------------------------------------

    def record_lan_result(self, success: bool, dev_id: str) -> None:
        """``bdpdqbp(Z,String)`` — success stamps ``last_ok``; failure
        stamps ``last_fail`` and bumps ``illegal_times`` when it lands
        within 1 s of the previous success. Entries where
        ``lastFail - lastOk > 60 s`` are dropped."""
        state = self._lan_fail.get(dev_id)
        if state is None:
            state = _LanFailState()
            self._lan_fail[dev_id] = state
        now = self._clock_ms()
        if success:
            state.last_ok_ms = now
        else:
            state.last_fail_ms = now
            if now - state.last_ok_ms < _LAN_ILLEGAL_BURST_MS:
                state.illegal_times += 1
        if (
            state.last_fail_ms != 0
            and state.last_ok_ms != 0
            and state.last_fail_ms - state.last_ok_ms > _LAN_STALE_MS
        ):
            del self._lan_fail[dev_id]

    def is_lan_disabled(self, dev_id: str | None) -> bool:
        """``bdpdqbp(String)Z`` — after 3 burst failures the device is
        LAN-disabled for 120 s; the window start is stamped on first
        query, expiry removes the entry."""
        if text_is_empty(dev_id):
            return False
        state = self._lan_fail.get(dev_id)
        if state is None or state.illegal_times < _LAN_ILLEGAL_THRESHOLD:
            return False
        if state.disabled_since_ms != 0:
            if self._clock_ms() - state.disabled_since_ms >= _LAN_DISABLE_WINDOW_MS:
                del self._lan_fail[dev_id]
                return False
            return True
        state.disabled_since_ms = self._clock_ms()
        return True

    # --- discovery ingest (onFind) -----------------------------------------

    def on_find(self, hgw_list: list[HgwBean] | None) -> None:
        """``qbdpdpp.onFind`` — routes discovered gateways into the
        hardware layer, then fans out to search listeners."""
        if self.hardware is None or hgw_list is None:
            return
        if self.saas_type == SaasSdkType.COMMERCIAL_LIGHTING:
            for hgw in hgw_list:
                check = self._check_gw(hgw)
                if hgw is not None and hgw.active == ActiveEnum.ACTIVED and check:
                    self.hardware.put_hgw_bean(hgw.gw_id, hgw)
        else:
            for hgw in hgw_list:
                if hgw is None:
                    continue
                if text_is_empty(hgw.ip) or not is_valid_ip(hgw.ip):
                    continue  # logged as "… is invalid"
                if self.is_lan_disabled(hgw.gw_id):
                    continue
                check = self._check_gw(hgw)
                if self.saas_type == SaasSdkType.CONSTRUCTION:
                    if hgw.active == ActiveEnum.ACTIVED:
                        self.hardware.add_hgw(hgw, self._network_handle(hgw.ip))
                elif check and (
                    hgw.active == ActiveEnum.ACTIVED
                    or (self._is_ap_direct(hgw.gw_id) and hgw.active == ActiveEnum.LOCAL_ACTIVED)
                ):
                    resp = self._get_resp(hgw.gw_id)
                    product = self._get_product(resp)
                    if resp is not None and product is not None:
                        self.hardware.add_hgw(
                            hgw,
                            self._network_handle(hgw.ip),
                            local_key=resp.local_key,
                        )
                if hgw.active == ActiveEnum.LOCAL_UNACTIVE or (
                    not self._is_ap_direct(hgw.gw_id) and hgw.active == ActiveEnum.LOCAL_ACTIVED
                ):
                    self.hardware.add_hgw(hgw, self._network_handle(hgw.ip))
        self._notify_find(hgw_list)

    def _notify_find(self, hgw_list: list[HgwBean]) -> None:
        """``bdpdqbp(List)`` — ``onDeviceFind(gwId, DeviceActiveEnum.to)``."""
        for hgw in hgw_list:
            for listener in self.search_listeners:
                listener.on_device_find(hgw.gw_id, DeviceActiveEnum.to(hgw.active))

    # --- online updates -----------------------------------------------------

    def on_dev_update(self, hgw: HgwBean, online: bool) -> None:
        """``onDevUpdate(hgw, Z)`` — ``bdqqbqd`` event +
        ``IThingHardwareOnlineStatusListener`` fanout."""
        if self._event_send is not None:
            self._event_send(("dev_online_status", hgw, online))
        for listener in self.online_listeners:
            listener.on_device_online_status_update(hgw, online)

    # --- AP-direct school-time sync -----------------------------------------

    def is_local_actived(self, hgw: HgwBean | None) -> bool:
        """``bdpdqbp(HgwBean)Z``."""
        return hgw is not None and hgw.active == ActiveEnum.LOCAL_ACTIVED

    def maybe_sync_school_time(self, hgw: HgwBean) -> None:
        """``bppdpdq(HgwBean)`` — for AP-direct LOCAL_ACTIVED gateways,
        push ``{timeStamp, timeZone}`` under
        ``LAN_REQUEST_SCHOOL_TIME_TYPE`` (0x18)."""
        if not self._is_ap_direct(hgw.gw_id):
            return
        if not self.is_local_actived(hgw):
            return
        if self._lan_send is None:
            return
        payload = {
            "timeStamp": int(self._unix_ts()),
            "timeZone": self._time_zone(),
        }
        self._lan_send(hgw.gw_id, payload, FrameTypeEnum.LAN_REQUEST_SCHOOL_TIME_TYPE, None)

    # --- bean lookups ------------------------------------------------------

    def get_local_key(self, dev_id: str) -> str | None:
        """``getLocalKey`` — resp AND product bean must exist."""
        resp = self._get_resp(dev_id)
        if resp is None:
            return None
        if self._get_product(resp) is None:
            return None
        return resp.local_key

    def get_lpv(self, dev_id: str) -> str | None:
        """``getLpv`` — ``hardware.getDevId(devId).version``."""
        if self.hardware is None:
            return None
        hgw = self.hardware.get_dev_id(dev_id)
        return hgw.version if hgw is not None else None

    def get_hgw(self, dev_id: str) -> HgwBean | None:
        """``IThingHardware.getDevId`` passthrough — also used by
        ``devRespWrap`` to attach ``DeviceBean.hgwBean``."""
        if self.hardware is None:
            return None
        return self.hardware.get_dev_id(dev_id)

    # --- internals -----------------------------------------------------------

    def _check_gw(self, hgw: HgwBean | None) -> bool:
        if self.dev_cache is None:
            return False
        return self.dev_cache.check_gw(hgw)

    def _get_resp(self, dev_id: str | None) -> DeviceRespBean | None:
        if self.dev_cache is None or dev_id is None:
            return None
        return self.dev_cache.get_dev_resp_bean(dev_id)

    def _is_ap_direct(self, dev_id: str | None) -> bool:
        """``DevUtil.isAPDirectlyDevice(String)``."""
        return is_ap_directly_device_bean(self._get_resp(dev_id))

    def _get_product(self, resp: DeviceRespBean | None) -> Any:
        """``pbqdddb`` product lookup by ``productId_productVer``."""
        if resp is None or self.products is None:
            return None
        pid, ver = resp.product_id, resp.product_ver
        if callable(self.products):
            return self.products(pid, ver)
        from .device_cache import product_key

        return self.products.get(product_key(pid, ver))
