"""Selects for Popur device settings."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from pypopur.models import CalibrationLevel, DeviceSnapshot

from . import PopurConfigEntry
from .entity import PopurEntity

RESHUFFLE_OPTIONS = ("2X", "3X", "4X", "5X")
COLOR_OPTIONS = ("white", "black")


@dataclass(frozen=True, kw_only=True)
class PopurSelectDescription(SelectEntityDescription):
    current_fn: Callable[[DeviceSnapshot], str | None]
    select_fn: Callable[[Any, DeviceSnapshot, str], Awaitable[Any]]


SELECTS: tuple[PopurSelectDescription, ...] = (
    PopurSelectDescription(
        key="calibration_level",
        translation_key="calibration_level",
        entity_category=EntityCategory.CONFIG,
        options=[level.label for level in CalibrationLevel],
        current_fn=lambda s: (
            s.dustbin.calibration.label if s.dustbin else None
        ),
        select_fn=lambda c, s, opt: c.update_dustbin_settings(
            calibration=CalibrationLevel(
                [level.label for level in CalibrationLevel].index(opt)
            )
        ),
    ),
    PopurSelectDescription(
        key="device_color",
        translation_key="device_color",
        entity_category=EntityCategory.CONFIG,
        options=list(COLOR_OPTIONS),
        current_fn=lambda s: (
            s.system_settings.device_color if s.system_settings else None
        ),
        select_fn=lambda c, s, opt: c.update_system_settings(device_color=opt),
    ),
    PopurSelectDescription(
        key="reshuffle_oscillation",
        translation_key="reshuffle_oscillation",
        entity_category=EntityCategory.CONFIG,
        options=list(RESHUFFLE_OPTIONS),
        current_fn=lambda s: (
            s.system_settings.spin.reshuffle_oscillation
            if s.system_settings
            else None
        ),
        select_fn=lambda c, s, opt: c.update_system_settings(
            spin=replace(
                s.system_settings.spin, reshuffle_oscillation=opt
            )
        ),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PopurConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    coordinator = data.coordinator
    entities: list[SelectEntity] = []
    for dev_id, client in data.clients.items():
        device = next(
            d for d in data.account_devices if d.device_id == dev_id
        )
        entities.extend(
            PopurSelect(coordinator, client, device, desc) for desc in SELECTS
        )
    async_add_entities(entities)


class PopurSelect(PopurEntity, SelectEntity):
    entity_description: PopurSelectDescription

    def __init__(self, coordinator, client, device, description) -> None:
        super().__init__(coordinator, client, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.device_id}_{description.key}"

    @property
    def current_option(self) -> str | None:
        if self.snapshot is None:
            return None
        return self.entity_description.current_fn(self.snapshot)

    async def async_select_option(self, option: str) -> None:
        if self.snapshot is None:
            return
        await self.entity_description.select_fn(self.client, self.snapshot, option)
        await self.coordinator.async_request_refresh()
