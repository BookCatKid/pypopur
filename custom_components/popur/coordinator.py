"""DataUpdateCoordinator for Popur devices and pets."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from pypopur import decode_snapshot
from pypopur.discovery import find_lan_hosts
from pypopur.local import LocalTuyaTransport
from pypopur.models import DeviceSnapshot
from pypopur.reads import Pet, PetRecord
from pypopur.transport import FallbackTransport

from .const import CLOUD_REFRESH_INTERVAL, DOMAIN, PET_RECORDS_PAGE_SIZE

if TYPE_CHECKING:
    from pypopur.client import PopurClient
    from pypopur.mobile import PopurAccount

_LOGGER = logging.getLogger(__name__)


@dataclass
class PetVisit:
    """Latest decoded toilet visit for one pet."""

    record: PetRecord
    weight_grams: int | None
    duration_seconds: int | None


@dataclass
class PopurRuntimeData:
    """One coordinator refresh worth of state."""

    snapshots: dict[str, DeviceSnapshot] = field(default_factory=dict)
    pets: dict[int, Pet] = field(default_factory=dict)
    pet_visits: dict[int, PetVisit] = field(default_factory=dict)
    # dev_id → "lan" / "cloud" — which channel served the last refresh.
    transports: dict[str, str] = field(default_factory=dict)
    mqtt_connected: bool = False


class PopurCoordinator(DataUpdateCoordinator[PopurRuntimeData]):
    """Polls device snapshots (LAN-first) + household pet data (cloud).

    Live device state refreshes every ``scan_interval`` over the local
    channel; the cloud is only touched on the slow cadence for the DP
    shadow (settings DPs the LAN omits) and pet/record data, or when the
    local channel is down.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        account: PopurAccount,
        home_id: int | str,
        clients: dict[str, PopurClient],
        scan_interval,
        events: Any = None,
        devices: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=scan_interval,
        )
        self.account = account
        self.home_id = home_id
        self.clients = clients
        self.events = events
        self._devices = devices or {}
        self._shadow_dps: dict[str, dict[int, Any]] = {}
        self._next_cloud_refresh = 0.0

    def transport_state(self, dev_id: str) -> str:
        """Which channel last served this device: ``lan`` or ``cloud``."""

        transport = getattr(self.clients.get(dev_id), "transport", None)
        if isinstance(transport, FallbackTransport):
            return "lan" if transport.active == "primary" else "cloud"
        return "cloud"

    def _apply_shadow(self, dev_id: str, snapshot: DeviceSnapshot) -> DeviceSnapshot:
        """Fill LAN-missing DPs (settings payloads) from the cloud shadow;
        live LAN values always win."""

        shadow = self._shadow_dps.get(dev_id)
        if not shadow:
            return snapshot
        merged = dict(shadow)
        merged.update(snapshot.raw_dps)
        return decode_snapshot(merged)

    async def _async_update_data(self) -> PopurRuntimeData:
        data = PopurRuntimeData()
        for dev_id, client in self.clients.items():
            try:
                snapshot = await client.refresh()
            except Exception as err:
                raise UpdateFailed(f"device {dev_id} refresh failed: {err}") from err
            data.snapshots[dev_id] = self._apply_shadow(dev_id, snapshot)
            data.transports[dev_id] = self.transport_state(dev_id)
        data.mqtt_connected = bool(
            self.events is not None and self.events.connected
        )

        # Cloud tier: carry forward previous cloud-side state, refresh on
        # the slow cadence so routine polling stays off Popur's servers.
        previous = self.data
        if previous is not None:
            data.pets = previous.pets
            data.pet_visits = previous.pet_visits
        if time.monotonic() >= self._next_cloud_refresh:
            self._next_cloud_refresh = (
                time.monotonic() + CLOUD_REFRESH_INTERVAL.total_seconds()
            )
            await self._async_refresh_cloud(data)
        return data

    async def _async_refresh_cloud(self, data: PopurRuntimeData) -> None:
        """Slow tier: device DP shadow + pets + latest usage records."""

        # Re-locate devices whose LAN channel is down — DHCP may have
        # moved them; a fresh candidate swaps into the fallback transport.
        for dev_id, client in self.clients.items():
            transport = getattr(client, "transport", None)
            device = self._devices.get(dev_id)
            if (
                not isinstance(transport, FallbackTransport)
                or transport.active == "primary"
                or device is None
                or not device.local_key
            ):
                continue
            try:
                candidates = await find_lan_hosts(device.mac)
            except Exception:
                _LOGGER.debug("LAN re-scan failed for %s", dev_id, exc_info=True)
                continue
            for host in candidates:
                if host == getattr(
                    getattr(transport.primary, "config", None), "host", None
                ):
                    break  # current host still looks best; keep retrying it
                probe = LocalTuyaTransport(
                    host, dev_id, device.local_key, timeout=4.0
                )
                try:
                    await probe.connect()
                except Exception as err:  # noqa: BLE001 — next candidate
                    _LOGGER.debug("re-scan connect to %s failed: %s", host, err)
                    continue
                _LOGGER.info(
                    "Popur %s rediscovered at %s (pv %s) — switching to LAN",
                    dev_id,
                    host,
                    probe.protocol_version,
                )
                old, transport.primary = transport.primary, probe
                transport.reset_backoff()
                try:
                    await old.close()
                except Exception:
                    _LOGGER.debug("old LAN transport close failed", exc_info=True)
                break

        for dev_id in self.clients:
            try:
                self._shadow_dps[dev_id] = dict(
                    await self.account.device_dps(dev_id)
                )
                snapshot = data.snapshots.get(dev_id)
                if snapshot is not None:
                    data.snapshots[dev_id] = self._apply_shadow(dev_id, snapshot)
            except Exception as err:  # noqa: BLE001 — shadow is best-effort
                _LOGGER.debug("cloud shadow refresh failed for %s: %s", dev_id, err)
        try:
            pets: dict[int, Pet] = {}
            for pet in await self.account.pets(self.home_id):
                pets[pet.pet_id] = pet
            data.pets = pets
            page = await self.account.pet_records(
                self.home_id, page_size=PET_RECORDS_PAGE_SIZE
            )
            visits: dict[int, PetVisit] = {}
            for record in page.records:
                pet_id = record.pet_id
                if pet_id is None or pet_id in visits:
                    continue  # records are newest-first
                usage = record.toilet_usage()
                visits[pet_id] = PetVisit(
                    record=record,
                    weight_grams=usage.weight_grams if usage else None,
                    duration_seconds=usage.duration_seconds if usage else None,
                )
            data.pet_visits = visits
        except Exception as err:  # noqa: BLE001 — pets are auxiliary; never fail the refresh
            _LOGGER.debug("pet data refresh failed: %s", err)

    def request_refresh(self) -> None:
        """Thread-safe refresh trigger (MQTT (re)connect resync)."""

        self.hass.loop.call_soon_threadsafe(
            lambda: self.hass.async_create_task(self.async_request_refresh())
        )

    def push_dps(self, dev_id: str, dps: dict[int, Any]) -> None:
        """Merge a real-time MQTT push into the cached snapshot."""
        if self.data is None or dev_id not in self.clients:
            return
        old = self.data.snapshots.get(dev_id)
        merged = dict(old.raw_dps) if old else {}
        merged.update(dps)
        self.data.snapshots[dev_id] = decode_snapshot(merged)
        self.async_set_updated_data(self.data)
