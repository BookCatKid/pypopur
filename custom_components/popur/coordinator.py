"""DataUpdateCoordinator for Popur devices and pets."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from pypopur import decode_snapshot
from pypopur.models import DeviceSnapshot
from pypopur.reads import Pet, PetRecord

from .const import DOMAIN, PET_RECORDS_PAGE_SIZE

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


class PopurCoordinator(DataUpdateCoordinator[PopurRuntimeData]):
    """Polls device snapshots + household pet data."""

    def __init__(
        self,
        hass: HomeAssistant,
        account: PopurAccount,
        home_id: int | str,
        clients: dict[str, PopurClient],
        scan_interval,
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

    async def _async_update_data(self) -> PopurRuntimeData:
        data = PopurRuntimeData()
        for dev_id, client in self.clients.items():
            try:
                data.snapshots[dev_id] = await client.refresh()
            except Exception as err:
                raise UpdateFailed(f"device {dev_id} refresh failed: {err}") from err
        try:
            for pet in await self.account.pets(self.home_id):
                data.pets[pet.pet_id] = pet
            page = await self.account.pet_records(
                self.home_id, page_size=PET_RECORDS_PAGE_SIZE
            )
            for record in page.records:
                pet_id = record.pet_id
                if pet_id is None or pet_id in data.pet_visits:
                    continue  # records are newest-first
                usage = record.toilet_usage()
                data.pet_visits[pet_id] = PetVisit(
                    record=record,
                    weight_grams=usage.weight_grams if usage else None,
                    duration_seconds=usage.duration_seconds if usage else None,
                )
        except Exception as err:  # noqa: BLE001 — pets are auxiliary; never fail the refresh
            _LOGGER.debug("pet data refresh failed: %s", err)
        return data

    def push_dps(self, dev_id: str, dps: dict[int, Any]) -> None:
        """Merge a real-time MQTT push into the cached snapshot."""
        if self.data is None or dev_id not in self.clients:
            return
        old = self.data.snapshots.get(dev_id)
        merged = dict(old.raw_dps) if old else {}
        merged.update(dps)
        self.data.snapshots[dev_id] = decode_snapshot(merged)
        self.async_set_updated_data(self.data)
