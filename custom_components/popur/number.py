"""Numbers for Popur device settings."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.number import (
    NumberEntity,
    NumberEntityDescription,
    NumberMode,
)
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from pypopur.models import DeviceSnapshot

from . import PopurConfigEntry
from .entity import PopurEntity


@dataclass(frozen=True, kw_only=True)
class PopurNumberDescription(NumberEntityDescription):
    value_fn: Callable[[DeviceSnapshot], float | None]
    set_fn: Callable[[Any, float], Awaitable[Any]]


NUMBERS: tuple[PopurNumberDescription, ...] = (
    PopurNumberDescription(
        key="clean_delay",
        translation_key="clean_delay",
        entity_category=EntityCategory.CONFIG,
        native_min_value=1,
        native_max_value=60,
        native_step=1,
        native_unit_of_measurement=UnitOfTime.MINUTES,
        mode=NumberMode.SLIDER,
        value_fn=lambda s: (
            float(s.system_settings.delay_minutes)
            if s.system_settings
            else None
        ),
        set_fn=lambda c, v: c.set_clean_delay(int(v)),
    ),
    PopurNumberDescription(
        key="radar_sensitivity",
        translation_key="radar_sensitivity",
        entity_category=EntityCategory.CONFIG,
        native_min_value=1,
        native_max_value=10,
        native_step=1,
        mode=NumberMode.SLIDER,
        value_fn=lambda s: (
            float(s.system_settings.active_shield.sensitivity)
            if s.system_settings
            else None
        ),
        set_fn=lambda c, v: c.set_radar_sensitivity(int(v)),
    ),
    PopurNumberDescription(
        key="radar_range",
        translation_key="radar_range",
        entity_category=EntityCategory.CONFIG,
        native_min_value=1,
        native_max_value=5,
        native_step=1,
        mode=NumberMode.SLIDER,
        value_fn=lambda s: (
            float(s.system_settings.active_shield.range)
            if s.system_settings
            else None
        ),
        set_fn=lambda c, v: c.set_radar_range(int(v)),
    ),
    PopurNumberDescription(
        key="smooth_spread_count",
        translation_key="smooth_spread_count",
        entity_category=EntityCategory.CONFIG,
        native_min_value=2,
        native_max_value=7,
        native_step=1,
        mode=NumberMode.SLIDER,
        value_fn=lambda s: (
            float(s.system_settings.smooth_spread_count)
            if s.system_settings
            else None
        ),
        set_fn=lambda c, v: c.update_system_settings(
            smooth_spread_count=int(v)
        ),
    ),
    PopurNumberDescription(
        key="cycle_count",
        translation_key="cycle_count",
        entity_category=EntityCategory.CONFIG,
        native_min_value=1,
        native_max_value=10,
        native_step=1,
        mode=NumberMode.SLIDER,
        value_fn=lambda s: (
            float(s.dustbin.cycle_count) if s.dustbin else None
        ),
        set_fn=lambda c, v: c.update_dustbin_settings(cycle_count=int(v)),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PopurConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    coordinator = data.coordinator
    entities: list[NumberEntity] = []
    for dev_id, client in data.clients.items():
        device = next(
            d for d in data.account_devices if d.device_id == dev_id
        )
        entities.extend(
            PopurNumber(coordinator, client, device, desc) for desc in NUMBERS
        )
    async_add_entities(entities)


class PopurNumber(PopurEntity, NumberEntity):
    entity_description: PopurNumberDescription

    def __init__(self, coordinator, client, device, description) -> None:
        super().__init__(coordinator, client, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.device_id}_{description.key}"

    @property
    def native_value(self) -> float | None:
        if self.snapshot is None:
            return None
        return self.entity_description.value_fn(self.snapshot)

    async def async_set_native_value(self, value: float) -> None:
        await self.entity_description.set_fn(self.client, value)
        await self.coordinator.async_request_refresh()
