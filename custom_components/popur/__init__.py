"""The Popur integration."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.typing import ConfigType

from pypopur.client import PopurClient
from pypopur.discovery import find_lan_hosts
from pypopur.events import DeviceEvent
from pypopur.local import LocalTuyaTransport
from pypopur.mobile import (
    AccountDevice,
    MobileAppProfile,
    MobileAuthenticationError,
    PopurAccount,
    ThingMobileApi,
)
from pypopur.transport import FallbackTransport, PopurTransport

from .const import CONF_HOST, CONF_INSTALL_ID, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN
from .coordinator import PopurCoordinator
from .transport import CloudHttpTransport

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.NUMBER,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
]


@dataclass
class PopurEntryData:
    """Runtime state for one config entry."""

    account: PopurAccount
    home_id: int | str
    coordinator: PopurCoordinator
    account_devices: list[Any] = field(default_factory=list)
    clients: dict[str, PopurClient] = field(default_factory=dict)
    events: Any = None


PopurConfigEntry = ConfigEntry[PopurEntryData]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    return True


async def _local_transport(
    device: AccountDevice, host_override: str | None
) -> LocalTuyaTransport | None:
    """Build the LAN transport for one device — explicit host first, then
    ARP/neigh by the cloud-recorded MAC, then a port-6668 subnet probe.

    Candidates are connect-verified (the handshake checks local_key +
    devId), but a transport is returned even when every probe fails: the
    S7 accepts a single LAN session at a time, so a momentarily-busy
    device must stay retryable via FallbackTransport rather than pin the
    entry to the cloud until the next reload."""

    if not device.local_key:
        return None
    candidates: list[str] = []
    if host_override:
        candidates.append(host_override)
    else:
        try:
            candidates = await find_lan_hosts(device.mac)
        except Exception:
            _LOGGER.debug("LAN host scan failed", exc_info=True)
    first: LocalTuyaTransport | None = None
    for host in candidates:
        transport = LocalTuyaTransport(
            host, device.device_id, device.local_key, timeout=5.0
        )
        if first is None:
            first = transport
        try:
            await transport.connect()
        except Exception as err:  # noqa: BLE001 — try the next candidate
            _LOGGER.debug("local connect to %s failed: %s", host, err)
            continue
        _LOGGER.info(
            "Popur %s local channel up at %s (pv %s)",
            device.device_id,
            host,
            transport.protocol_version,
        )
        return transport
    if first is not None:
        _LOGGER.info(
            "Popur %s LAN unreachable at setup — will keep retrying %s",
            device.device_id,
            first.config.host,
        )
    return first


async def async_setup_entry(hass: HomeAssistant, entry: PopurConfigEntry) -> bool:
    """Log in, enumerate devices, and start the coordinator."""
    install_id = entry.data[CONF_INSTALL_ID]
    api = ThingMobileApi(
        MobileAppProfile.bundled_popur_app2(), install_id=install_id
    )
    account = PopurAccount(api)
    try:
        await account.login(entry.data[CONF_EMAIL], entry.data[CONF_PASSWORD])
    except MobileAuthenticationError as err:
        raise ConfigEntryAuthFailed("Popur credentials rejected") from err
    except Exception as err:
        raise ConfigEntryNotReady(f"Popur login failed: {err}") from err

    try:
        homes = await account.homes()
    except Exception as err:
        raise ConfigEntryNotReady(f"could not list homes: {err}") from err
    if not homes:
        raise ConfigEntryNotReady("account has no homes")

    home_id: int | str = homes[0]["gid"]
    try:
        devices = await account.home_devices(home_id)
    except Exception as err:
        raise ConfigEntryNotReady(f"could not list devices: {err}") from err

    # The optional host override only makes sense for a single-device home.
    host_override = entry.data.get(CONF_HOST) or None
    if host_override and len(devices) != 1:
        _LOGGER.warning(
            "ignoring configured host %s with %d devices — use discovery",
            host_override,
            len(devices),
        )
        host_override = None

    clients: dict[str, PopurClient] = {}
    for device in devices:
        cloud: PopurTransport = CloudHttpTransport(account, device.device_id)
        local = await _local_transport(device, host_override)
        transport: PopurTransport = (
            FallbackTransport(local, cloud) if local is not None else cloud
        )
        clients[device.device_id] = PopurClient(transport)

    scan_seconds = entry.data.get(
        CONF_SCAN_INTERVAL, int(DEFAULT_SCAN_INTERVAL.total_seconds())
    )
    coordinator = PopurCoordinator(
        hass,
        account,
        home_id,
        clients,
        timedelta(seconds=scan_seconds),
        devices={d.device_id: d for d in devices},
    )
    await coordinator.async_config_entry_first_refresh()

    entry_data = PopurEntryData(
        account=account,
        home_id=home_id,
        coordinator=coordinator,
        account_devices=list(devices),
        clients=clients,
    )
    entry.runtime_data = entry_data

    # Real-time push: decode MQTT frames into coordinator merges, and
    # resync state on every (re)connect. The wire client is thread-based;
    # hop onto the loop for state updates.
    try:
        local_keys = {
            dev.device_id: dev.local_key
            for dev in devices
            if dev.local_key
        }

        def _on_event(event: DeviceEvent) -> None:
            if event.dps:
                hass.loop.call_soon_threadsafe(
                    coordinator.push_dps, event.dev_id, dict(event.dps)
                )

        entry_data.events = account.connect_events(
            devices=local_keys,
            on_event=_on_event,
            on_connect=coordinator.request_refresh,
        )
        await entry_data.events.connect()
        coordinator.events = entry_data.events
        _LOGGER.debug("Popur MQTT events connected")
    except Exception as err:  # noqa: BLE001 — realtime is best-effort; polling still works
        _LOGGER.warning("Popur realtime events unavailable, polling only: %s", err)
        entry_data.events = None

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: PopurConfigEntry) -> bool:
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = entry.runtime_data
        if data.events is not None:
            try:
                await data.events.close()
            except Exception:
                _LOGGER.debug("Popur MQTT close failed", exc_info=True)
        for client in data.clients.values():
            await client.close()
    return unload_ok
