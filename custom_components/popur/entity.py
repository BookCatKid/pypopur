"""Base entities for Popur."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import PopurCoordinator

if TYPE_CHECKING:
    from pypopur.client import PopurClient
    from pypopur.mobile import AccountDevice
    from pypopur.models import DeviceSnapshot


class PopurEntity(CoordinatorEntity[PopurCoordinator]):
    """Entity bound to one litter box device."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: PopurCoordinator,
        client: PopurClient,
        device: AccountDevice,
    ) -> None:
        super().__init__(coordinator)
        self.client = client
        self.device = device
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.device_id)},
            name=device.name or "Popur S7",
            manufacturer="Popur",
            model="Popur S7 SLS",
            serial_number=device.device_id,
        )

    @property
    def snapshot(self) -> DeviceSnapshot | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.snapshots.get(self.device.device_id)


class PopurPetEntity(CoordinatorEntity[PopurCoordinator]):
    """Entity bound to one pet, linked to the litter box device."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: PopurCoordinator,
        device: AccountDevice,
        pet_id: int,
    ) -> None:
        super().__init__(coordinator)
        self.device = device
        self.pet_id = pet_id
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"pet_{pet_id}")},
            name="Pet",
            manufacturer="Popur",
            via_device=(DOMAIN, device.device_id),
        )
