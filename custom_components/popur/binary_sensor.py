"""Binary sensors for Popur devices."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from pypopur.models import BinStatus, CatPresence, RunningStatus

from . import PopurConfigEntry
from .entity import PopurEntity


@dataclass(frozen=True, kw_only=True)
class PopurBinarySensorDescription(BinarySensorEntityDescription):
    is_on_fn: Callable[[Any], bool]
    attrs_fn: Callable[[Any], dict[str, Any]] | None = None


BINARY_SENSORS: tuple[PopurBinarySensorDescription, ...] = (
    PopurBinarySensorDescription(
        key="bin_full",
        translation_key="bin_full",
        device_class=BinarySensorDeviceClass.PROBLEM,
        is_on_fn=lambda s: s.run_mode is not None
        and s.run_mode.bin_status == BinStatus.BIN_FULL,
    ),
    PopurBinarySensorDescription(
        key="cat_present",
        translation_key="cat_present",
        is_on_fn=lambda s: s.cat_presence == CatPresence.CAT_EXIST,
    ),
    PopurBinarySensorDescription(
        key="cleaning",
        translation_key="cleaning",
        device_class=BinarySensorDeviceClass.RUNNING,
        is_on_fn=lambda s: s.run_mode is not None
        and s.run_mode.running_status == RunningStatus.CLEAN_START,
    ),
    PopurBinarySensorDescription(
        key="fault",
        translation_key="fault",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_category=EntityCategory.DIAGNOSTIC,
        is_on_fn=lambda s: bool(s.self_check_faults),
        attrs_fn=lambda s: {"faults": [f.label for f in s.self_check_faults]},
    ),
    PopurBinarySensorDescription(
        key="powered",
        translation_key="powered",
        device_class=BinarySensorDeviceClass.POWER,
        entity_category=EntityCategory.DIAGNOSTIC,
        is_on_fn=lambda s: s.machine_status is not None
        and str(s.machine_status) not in ("power_off",),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PopurConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    coordinator = data.coordinator
    entities: list[BinarySensorEntity] = []
    for dev_id, client in data.clients.items():
        device = next(
            d for d in data.account_devices if d.device_id == dev_id
        )
        entities.extend(
            PopurBinarySensor(coordinator, client, device, desc)
            for desc in BINARY_SENSORS
        )
    async_add_entities(entities)


class PopurBinarySensor(PopurEntity, BinarySensorEntity):
    entity_description: PopurBinarySensorDescription

    def __init__(self, coordinator, client, device, description) -> None:
        super().__init__(coordinator, client, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.device_id}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        if self.snapshot is None:
            return None
        return self.entity_description.is_on_fn(self.snapshot)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None or self.snapshot is None:
            return None
        return self.entity_description.attrs_fn(self.snapshot)
