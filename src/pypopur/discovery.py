"""Passive LAN discovery for Popur S7 devices."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib import import_module
from typing import Any

from .exceptions import ProtocolError, TransportDependencyMissing
from .reference import S7_PRODUCT_IDS


@dataclass(frozen=True, slots=True)
class DiscoveredS7:
    """One firmware-4 S7 observed through Tuya LAN discovery."""

    host: str
    device_id: str
    product_id: str
    protocol_version: str | None = None


ScanFunction = Callable[[], Mapping[str, Mapping[str, Any]]]


def _default_scan() -> Mapping[str, Mapping[str, Any]]:
    try:
        tinytuya = import_module("tinytuya")
    except ImportError as err:
        raise TransportDependencyMissing(
            "LAN discovery requires the 'tinytuya' dependency"
        ) from err
    return tinytuya.deviceScan(verbose=False, color=False, poll=False)


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
    """Return only Popur S7 devices from TinyTuya scan results."""

    discovered: list[DiscoveredS7] = []
    for host, info in results.items():
        if not isinstance(info, Mapping):
            raise ProtocolError("LAN discovery returned a non-mapping device record")
        # TinyTuya calls this field ``productKey`` in current decrypted UDP
        # broadcasts. Older captures and test fixtures use the API-shaped
        # ``productId`` spelling, so accept both without weakening the S7 filter.
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


async def discover_s7(
    *,
    _scan: ScanFunction | None = None,
) -> tuple[DiscoveredS7, ...]:
    """Passively discover S7 devices without authenticating or writing to them."""

    scan = _scan or _default_scan
    results = await asyncio.to_thread(scan)
    return parse_scan_results(results)
