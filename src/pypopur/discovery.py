"""Passive LAN discovery for Popur S7 devices.

Drives the real ``GwBroadcastMonitorService`` stack end-to-end:
``SocketThingNetworkApi`` UDP listeners on ports 6650/6667/7000, the
``APP_SEND_BROADCAST`` (0x25) discovery frame at 6000 ms, security-content
loading (``fixed_key.bmp``/``soisiwoejre`` fallback), the dedup'd
``gwMap`` drain at 1000 ms, and ``HgwBean`` fan-out — exactly as the app
does inside ``ThingNetworkInterface``.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib import resources
from typing import Any

from .exceptions import ProtocolError
from .reference import S7_PRODUCT_IDS
from .sdk.discovery import GwBroadcastMonitor, HgwBean
from .sdk.lan_session import ThingNetworkInterface
from .sdk.lan_socket import SocketThingNetworkApi


@dataclass(frozen=True, slots=True)
class DiscoveredS7:
    """One firmware-4 S7 observed through Tuya LAN discovery."""

    host: str
    device_id: str
    product_id: str
    protocol_version: str | None = None


ScanFunction = Callable[[], Mapping[str, Mapping[str, Any]]]


def _first_text(info: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = info.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def parse_scan_results(
    results: Mapping[str, Mapping[str, Any]],
) -> tuple[DiscoveredS7, ...]:
    """Return only Popur S7 devices from a host→announcement map.

    Accepts the announcement field spellings the device's UDP JSON uses
    (``gwId``/``productKey``/``version``) plus the API-shaped aliases seen
    in older captures (``id``/``productId``/``pv``).
    """

    discovered: list[DiscoveredS7] = []
    for host, info in results.items():
        if not isinstance(info, Mapping):
            raise ProtocolError("LAN discovery returned a non-mapping device record")
        product_id = _first_text(info, "product_id", "productId", "product_key", "productKey")
        if product_id not in S7_PRODUCT_IDS:
            continue
        device_id = _first_text(info, "gwId", "id", "device_id", "devId")
        if device_id is None:
            raise ProtocolError("Popur S7 discovery record did not contain a device ID")
        protocol_version = _first_text(info, "version", "pv", "protocol_version")
        discovered.append(
            DiscoveredS7(
                host=str(host),
                device_id=device_id,
                product_id=product_id,
                protocol_version=protocol_version,
            )
        )

    discovered.sort(key=lambda item: (item.device_id, item.host))
    return tuple(discovered)


def hgw_beans_to_discovered(beans: list[HgwBean]) -> tuple[DiscoveredS7, ...]:
    """``HgwBean`` → :class:`DiscoveredS7`, filtered to S7 product keys."""
    results = {
        (b.ip or ""): {
            "gwId": b.gw_id,
            "productKey": b.product_key,
            "version": b.version,
        }
        for b in beans
        if b is not None
    }
    return parse_scan_results(results)


# ---------------------------------------------------------------------------
# platform seams (Android → Python)
# ---------------------------------------------------------------------------


def _local_ip() -> str | None:
    """``WiFiUtil.getIpAddress`` — outbound-interface IPv4."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("255.255.255.255", 7000))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _subnet_broadcast() -> str | None:
    """``getSubnetBroadcastAddress`` — ``ip | ~netmask`` from DHCP info.

    Best-effort: uses ``netifaces`` when installed; otherwise ``None``
    (the app maps lookup failures to "no subnet resend" identically).
    """
    try:
        import netifaces  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ip, mask = addr.get("addr"), addr.get("netmask")
                if not ip or ip.startswith("127.") or not mask:
                    continue
                bcast = (_ipv4_to_int(ip) & _ipv4_to_int(mask)) | (~_ipv4_to_int(mask) & 0xFFFFFFFF)
                return ".".join(str((bcast >> s) & 0xFF) for s in (24, 16, 8, 0))
    except Exception:
        return None
    return None


def _ipv4_to_int(text: str) -> int:
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError(text)
    value = 0
    for part in parts:
        value = (value << 8) | int(part)
    return value


def _timer_schedule(delay_ms: int, fn: Callable[[], None]) -> None:
    """``Handler.postDelayed`` — daemon ``threading.Timer``."""
    timer = threading.Timer(delay_ms / 1000.0, fn)
    timer.daemon = True
    timer.start()


def load_security_asset(asset: str, fallback: bytes) -> bytes:
    """``ThingUtil.getAssetsData`` — raw asset bytes, ``fallback`` on miss.

    Searches ``pypopur/assets/<asset>`` inside the installed package,
    then the caller's working directory; returns ``fallback``
    (``b"soisiwoejre"``) when unreadable, exactly like the Java
    IOException path.
    """
    try:
        ref = resources.files("pypopur").joinpath("assets", asset)
        if ref.is_file():
            return ref.read_bytes()
    except Exception:
        pass
    try:
        import pathlib

        path = pathlib.Path(asset)
        if path.is_file():
            return path.read_bytes()
    except OSError:
        pass
    return fallback


class _BeanCollector:
    """``IUDPMonitorAidlInterface`` — collects ``update(list)`` snapshots."""

    def __init__(self) -> None:
        self.beans: list[HgwBean] = []

    def update(self, items: list[HgwBean]) -> None:
        self.beans.extend(items)

    def on_config_result(self, config: str) -> None:
        pass


def build_gw_monitor(
    iface: ThingNetworkInterface,
) -> GwBroadcastMonitor:
    """Wire ``GwBroadcastMonitor`` to the concrete interface seams."""
    api = iface.api
    return GwBroadcastMonitor(
        send_broadcast=iface.send_broadcast,
        stop_broadcast=iface.stop_broadcast,
        listen_udp=iface.listen_udp,
        shutdown_udp=iface.shut_down_all_udp_listen,
        local_ip=_local_ip,
        subnet_broadcast=_subnet_broadcast,
        schedule=_timer_schedule,
        load_security=load_security_asset,
        set_security_content=api.set_security_content,
    )


async def discover_s7(
    duration: float = 5.0,
    *,
    api: SocketThingNetworkApi | None = None,
    _scan: ScanFunction | None = None,
) -> tuple[DiscoveredS7, ...]:
    """Passively discover S7 devices without authenticating or writing to them.

    Runs the app's real discovery loop — UDP listeners, the 0x25
    discovery broadcast, gw-map dedup, and the 1000 ms monitor drain —
    for ``duration`` seconds, then filters announcements to S7 product
    keys. ``_scan`` is a legacy test seam: when supplied it bypasses the
    socket stack entirely and feeds raw maps to :func:`parse_scan_results`.
    """

    if _scan is not None:
        results = await asyncio.to_thread(_scan)
        return parse_scan_results(results)

    own_api = api is None
    api = api or SocketThingNetworkApi()
    iface = ThingNetworkInterface(api)
    monitor = build_gw_monitor(iface)
    iface.add_package_callback(monitor)
    collector = _BeanCollector()
    monitor.register_monitor(collector)

    monitor.start()
    try:
        await asyncio.sleep(duration)
        monitor.update_tick()  # final drain before teardown
    finally:
        monitor.stop()
        if own_api:
            api.shutdown()
    return hgw_beans_to_discovered(collector.beans)
