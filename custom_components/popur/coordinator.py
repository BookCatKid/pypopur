"""DataUpdateCoordinator for Popur devices and pets."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from pypopur import decode_snapshot
from pypopur.activity import ActivityEvent, extract_activity_events
from pypopur.discovery import find_lan_hosts
from pypopur.local import LocalTuyaTransport
from pypopur.models import DeviceSnapshot
from pypopur.reads import Pet, PetRecord
from pypopur.transport import FallbackTransport

from .const import (
    CLOUD_REFRESH_INTERVAL,
    DOMAIN,
    PET_RECORDS_MAX_PAGES,
    PET_RECORDS_PAGE_SIZE,
    signal_device_event,
    signal_pet_visit,
)

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
        self._record_fetch_timer: asyncio.TimerHandle | None = None
        self._record_fetch_task: asyncio.Task[None] | None = None
        self._record_fetch_attempt = 0
        # Pet records are fetched by both the slow tier and the delayed
        # post-``cat_left`` fetch; the lock serializes them so one record
        # is never dispatched twice.
        self._pet_lock = asyncio.Lock()
        # Newest record time already seen, per pet. ``None`` until the
        # first successful fetch: records seen then are history, not events.
        self._seen_record_time: dict[int, int] | None = None
        # Newest record time of that first fetch: pets appearing later only
        # count records newer than it, so they do not replay their history.
        self._records_baseline = 0
        self._latest_visits: dict[int, PetVisit] = {}

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
            await self._refresh_pet_data(data)
        except Exception as err:  # noqa: BLE001 — pets are auxiliary; never fail the refresh
            _LOGGER.debug("pet data refresh failed: %s", err)

    async def _refresh_pet_data(self, data: PopurRuntimeData) -> int:
        """Fetch latest pet profiles + records into ``data``.

        Signals one ``visit_recorded`` per new toilet-usage record and
        returns the number of new records seen (of any kind)."""

        async with self._pet_lock:
            pets: dict[int, Pet] = {}
            for pet in await self.account.pets(self.home_id):
                pets[pet.pet_id] = pet
            data.pets = pets
            records = await self._fetch_unseen_records()

            # Latest record per pet; a pet whose records fell off the fetched
            # pages keeps its previously known visit.
            visits = dict(self._latest_visits)
            latest_on_page: set[int] = set()
            for record in records:  # newest-first
                pet_id = record.pet_id
                if pet_id is None or pet_id in latest_on_page:
                    continue
                latest_on_page.add(pet_id)
                usage = record.toilet_usage()
                visits[pet_id] = PetVisit(
                    record=record,
                    weight_grams=usage.weight_grams if usage else None,
                    duration_seconds=usage.duration_seconds if usage else None,
                )
            self._latest_visits = visits
            data.pet_visits = visits
            return self._dispatch_new_records(records)

    async def _fetch_unseen_records(self) -> list[PetRecord]:
        """Fetch record pages (newest first) until one reaches already-seen
        records, so a burst larger than a page is not skipped. The first
        fetch only sets the baseline and reads a single page."""

        records: list[PetRecord] = []
        seen = self._seen_record_time
        for page_no in range(1, PET_RECORDS_MAX_PAGES + 1):
            page = await self.account.pet_records(
                self.home_id, page_no=page_no, page_size=PET_RECORDS_PAGE_SIZE
            )
            records.extend(page.records)
            if seen is None or not page.has_next or not page.records:
                break
            if any(
                r.record_time is not None
                and r.pet_id is not None
                and r.record_time <= seen.get(r.pet_id, self._records_baseline)
                for r in page.records
            ):
                break  # reached records we already know
        return records

    def _dispatch_new_records(self, records: Sequence[PetRecord]) -> int:
        """Signal every toilet-usage record newer than the last one seen for
        its pet, oldest first; advance the per-pet watermarks."""

        dated = sorted(
            (r for r in records if r.pet_id is not None and r.record_time is not None),
            key=lambda r: r.record_time,
        )
        if self._seen_record_time is None:
            # First successful fetch: history, not events.
            self._seen_record_time = {}
            for record in dated:
                self._seen_record_time[record.pet_id] = record.record_time
            self._records_baseline = dated[-1].record_time if dated else 0
            return 0

        seen = self._seen_record_time
        new = 0
        for record in dated:
            pet_id, record_time = record.pet_id, record.record_time
            if record_time <= seen.get(pet_id, self._records_baseline):
                continue
            seen[pet_id] = record_time
            new += 1
            usage = record.toilet_usage()
            if usage is None:
                continue  # another record kind: not a visit
            attrs: dict[str, Any] = {
                "pet_id": pet_id,
                "weight_g": usage.weight_grams,
                "duration_s": usage.duration_seconds,
                "record_time": dt_util.utc_from_timestamp(
                    record_time / 1000
                ).isoformat(),
            }
            if record.dev_id:
                attrs["device_id"] = record.dev_id
            _LOGGER.debug("New visit recorded for pet %s: %s", pet_id, attrs)
            async_dispatcher_send(self.hass, signal_pet_visit(pet_id), attrs)
        return new

    def cancel_record_fetch(self) -> None:
        """Cancel a pending or running delayed record fetch (entry unload)."""

        if self._record_fetch_timer is not None:
            self._record_fetch_timer.cancel()
            self._record_fetch_timer = None
        if self._record_fetch_task is not None:
            self._record_fetch_task.cancel()
            self._record_fetch_task = None

    def _schedule_record_fetch(self) -> None:
        """Debounce + schedule a delayed record fetch after ``cat_left``."""

        self.cancel_record_fetch()
        self._record_fetch_attempt = 0
        self._arm_record_fetch()

    def _arm_record_fetch(self) -> None:
        self._record_fetch_timer = self.hass.loop.call_later(
            45, self._start_record_fetch
        )

    def _start_record_fetch(self) -> None:
        self._record_fetch_timer = None
        self._record_fetch_task = self.hass.async_create_background_task(
            self._fetch_pet_records(), "popur delayed pet record fetch"
        )

    async def _fetch_pet_records(self) -> None:
        """Fetch records ~45 s after cat_left; retry once if no new record."""

        if self.data is None:
            return
        self._record_fetch_attempt += 1
        try:
            new = await self._refresh_pet_data(self.data)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("delayed pet record fetch failed: %s", err)
            return
        if not new and self._record_fetch_attempt < 2:
            # Record hasn't landed in the cloud yet — retry once.
            self._arm_record_fetch()
            return
        self.async_set_updated_data(self.data)

    def request_refresh(self) -> None:
        """Thread-safe refresh trigger (MQTT (re)connect resync)."""

        self.hass.loop.call_soon_threadsafe(
            lambda: self.hass.async_create_task(self.async_request_refresh())
        )

    def push_dps(self, dev_id: str, dps: dict[int, Any]) -> None:
        """Merge a real-time MQTT push into the cached snapshot.

        Only live pushes reach this method, so this is the single place
        activity/fault events are raised: polling never replays them."""
        if self.data is None or dev_id not in self.clients:
            return
        old = self.data.snapshots.get(dev_id)
        previous_raw = dict(old.raw_dps) if old else {}
        events = extract_activity_events(dps, previous_raw)
        received_at = dt_util.utcnow()

        merged = dict(previous_raw)
        merged.update(dps)
        self.data.snapshots[dev_id] = decode_snapshot(merged)
        self.async_set_updated_data(self.data)

        for event in events:
            self._dispatch_device_event(dev_id, event, received_at)

        # A cat just left — the record lands in the cloud shortly after.
        # Fetch it on a delay rather than waiting for the slow timer.
        if any(event.event_type == "cat_left" for event in events):
            self._schedule_record_fetch()

    def _dispatch_device_event(
        self, dev_id: str, event: ActivityEvent, received_at
    ) -> None:
        attrs: dict[str, Any] = {
            **event.attributes,
            "source": "mqtt",
            "raw_value": event.raw_value,
            "received_at": received_at.isoformat(),
        }
        _LOGGER.debug("Popur %s event %s: %s", dev_id, event.event_type, attrs)
        async_dispatcher_send(self.hass, signal_device_event(dev_id), event, attrs)
