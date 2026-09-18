"""Buttons for Popur device actions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import PopurConfigEntry
from .entity import PopurEntity


@dataclass(frozen=True, kw_only=True)
class PopurButtonDescription(ButtonEntityDescription):
    press_fn: Callable[[Any], Awaitable[Any]]


BUTTONS: tuple[PopurButtonDescription, ...] = (
    PopurButtonDescription(
        key="clean_now",
        translation_key="clean_now",
        press_fn=lambda c: c.start_cleaning(),
    ),
    PopurButtonDescription(
        key="pause_clean",
        translation_key="pause_clean",
        press_fn=lambda c: c.pause_cleaning(),
    ),
    PopurButtonDescription(
        key="resume_clean",
        translation_key="resume_clean",
        press_fn=lambda c: c.continue_cleaning(),
    ),
    PopurButtonDescription(
        key="self_check",
        translation_key="self_check",
        entity_category=EntityCategory.DIAGNOSTIC,
        press_fn=lambda c: c.start_self_check(),
    ),
    PopurButtonDescription(
        key="sifter_open",
        translation_key="sifter_open",
        press_fn=lambda c: c.open_sifter(),
    ),
    PopurButtonDescription(
        key="sifter_close",
        translation_key="sifter_close",
        press_fn=lambda c: c.close_sifter(),
    ),
    PopurButtonDescription(
        key="scoop_start",
        translation_key="scoop_start",
        press_fn=lambda c: c.start_scoop(),
    ),
    PopurButtonDescription(
        key="scoop_pause",
        translation_key="scoop_pause",
        press_fn=lambda c: c.pause_scoop(),
    ),
    PopurButtonDescription(
        key="dustbin_open",
        translation_key="dustbin_open",
        press_fn=lambda c: c.set_dustbin_open(True),
    ),
    PopurButtonDescription(
        key="dustbin_close",
        translation_key="dustbin_close",
        press_fn=lambda c: c.set_dustbin_open(False),
    ),
    PopurButtonDescription(
        key="zero_bin",
        translation_key="zero_bin",
        entity_category=EntityCategory.CONFIG,
        press_fn=lambda c: c.zero_bin(),
    ),
    PopurButtonDescription(
        key="recalibrate_spin",
        translation_key="recalibrate_spin",
        entity_category=EntityCategory.CONFIG,
        press_fn=lambda c: c.recalibrate_spin_sensor(),
    ),
    PopurButtonDescription(
        key="recalibrate_scale",
        translation_key="recalibrate_scale",
        entity_category=EntityCategory.CONFIG,
        press_fn=lambda c: c.recalibrate_scale(),
    ),
    PopurButtonDescription(
        key="reboot",
        translation_key="reboot",
        entity_category=EntityCategory.CONFIG,
        press_fn=lambda c: c.reboot(),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PopurConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    coordinator = data.coordinator
    entities: list[ButtonEntity] = []
    for dev_id, client in data.clients.items():
        device = next(
            d for d in data.account_devices if d.device_id == dev_id
        )
        entities.extend(
            PopurButton(coordinator, client, device, desc) for desc in BUTTONS
        )
    async_add_entities(entities)


class PopurButton(PopurEntity, ButtonEntity):
    entity_description: PopurButtonDescription

    def __init__(self, coordinator, client, device, description) -> None:
        super().__init__(coordinator, client, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.device_id}_{description.key}"

    async def async_press(self) -> None:
        await self.entity_description.press_fn(self.client)
        await self.coordinator.async_request_refresh()
