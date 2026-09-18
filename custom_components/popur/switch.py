"""Switches for Popur device settings."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from pypopur.models import DeviceSnapshot

from . import PopurConfigEntry
from .entity import PopurEntity


@dataclass(frozen=True, kw_only=True)
class PopurSwitchDescription(SwitchEntityDescription):
    """Toggle backed by a snapshot field and a client mutation.

    ``set_fn`` receives the client, the current snapshot (for
    read-modify-write of nested settings) and the desired state.
    """

    is_on_fn: Callable[[DeviceSnapshot], bool | None]
    set_fn: Callable[[Any, DeviceSnapshot, bool], Awaitable[Any]]


def _sys_nested(parent: str, field: str):
    """Setter for ``SystemSettings.<parent>.<field>``."""

    def _set(client, snapshot, on):
        current = snapshot.system_settings
        if current is None:
            raise ValueError("system settings unavailable")
        return client.update_system_settings(
            **{parent: replace(getattr(current, parent), **{field: on})}
        )

    return _set


def _dustbin_toggle(field: str):
    def _set(client, snapshot, on):
        current = snapshot.dustbin
        if current is None:
            raise ValueError("dustbin settings unavailable")
        return client.update_dustbin_settings(
            toggles=replace(current.toggles, **{field: on})
        )

    return _set


SWITCHES: tuple[PopurSwitchDescription, ...] = (
    PopurSwitchDescription(
        key="power",
        translation_key="power",
        is_on_fn=lambda s: (
            None if s.machine_status is None
            else str(s.machine_status) != "power_off"
        ),
        set_fn=lambda c, s, on: c.set_power(on),
    ),
    PopurSwitchDescription(
        key="status_light",
        translation_key="status_light",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.panel.status_light_enabled
            if s.system_settings else None
        ),
        set_fn=lambda c, s, on: c.set_status_light(on),
    ),
    PopurSwitchDescription(
        key="buzzer",
        translation_key="buzzer",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.panel.buzzer_enabled
            if s.system_settings else None
        ),
        set_fn=lambda c, s, on: c.set_buzzer(on),
    ),
    PopurSwitchDescription(
        key="anti_interference",
        translation_key="anti_interference",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.active_shield.anti_interference
            if s.system_settings else None
        ),
        set_fn=lambda c, s, on: c.set_anti_interference(on),
    ),
    PopurSwitchDescription(
        key="auto_clean",
        translation_key="auto_clean",
        is_on_fn=lambda s: (
            s.system_settings.weight_functions.automatic
            if s.system_settings else None
        ),
        set_fn=_sys_nested("weight_functions", "automatic"),
    ),
    PopurSwitchDescription(
        key="sentinel_mode",
        translation_key="sentinel_mode",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.weight_functions.sentinel
            if s.system_settings else None
        ),
        set_fn=_sys_nested("weight_functions", "sentinel"),
    ),
    PopurSwitchDescription(
        key="caring_mode",
        translation_key="caring_mode",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.weight_functions.caring
            if s.system_settings else None
        ),
        set_fn=_sys_nested("weight_functions", "caring"),
    ),
    PopurSwitchDescription(
        key="track_pet_data",
        translation_key="track_pet_data",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.weight_functions.track_pet_data
            if s.system_settings else None
        ),
        set_fn=_sys_nested("weight_functions", "track_pet_data"),
    ),
    PopurSwitchDescription(
        key="auto_power_cycle",
        translation_key="auto_power_cycle",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.spin.auto_power_cycle
            if s.system_settings else None
        ),
        set_fn=_sys_nested("spin", "auto_power_cycle"),
    ),
    PopurSwitchDescription(
        key="lower_speed",
        translation_key="lower_speed",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.spin.lower_speed if s.system_settings else None
        ),
        set_fn=_sys_nested("spin", "lower_speed"),
    ),
    PopurSwitchDescription(
        key="reshuffle",
        translation_key="reshuffle",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.spin.reshuffle_enabled
            if s.system_settings else None
        ),
        set_fn=_sys_nested("spin", "reshuffle_enabled"),
    ),
    PopurSwitchDescription(
        key="auto_self_check",
        translation_key="auto_self_check",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.system_settings.spin.auto_self_check
            if s.system_settings else None
        ),
        set_fn=_sys_nested("spin", "auto_self_check"),
    ),
    PopurSwitchDescription(
        key="notifications_master",
        translation_key="notifications_master",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: s.notifications.master_enabled,
        set_fn=lambda c, s, on: c.set_notifications(
            replace(s.notifications, master_enabled=on)
        ),
    ),
    PopurSwitchDescription(
        key="bin_full_detection",
        translation_key="bin_full_detection",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.dustbin.toggles.bin_full_detection if s.dustbin else None
        ),
        set_fn=_dustbin_toggle("bin_full_detection"),
    ),
    PopurSwitchDescription(
        key="allow_overfill",
        translation_key="allow_overfill",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.dustbin.toggles.allow_overfill if s.dustbin else None
        ),
        set_fn=_dustbin_toggle("allow_overfill"),
    ),
    PopurSwitchDescription(
        key="keep_upright",
        translation_key="keep_upright",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.dustbin.toggles.keep_upright if s.dustbin else None
        ),
        set_fn=_dustbin_toggle("keep_upright"),
    ),
    PopurSwitchDescription(
        key="block_on_full",
        translation_key="block_on_full",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.dustbin.toggles.block_on_full if s.dustbin else None
        ),
        set_fn=_dustbin_toggle("block_on_full"),
    ),
    PopurSwitchDescription(
        key="dump_override",
        translation_key="dump_override",
        entity_category=EntityCategory.CONFIG,
        is_on_fn=lambda s: (
            s.dustbin.toggles.dump_override if s.dustbin else None
        ),
        set_fn=_dustbin_toggle("dump_override"),
    ),
    PopurSwitchDescription(
        key="child_lock",
        translation_key="child_lock",
        is_on_fn=lambda s: (
            s.key_settings.lock_mask == 0xF if s.key_settings else None
        ),
        set_fn=lambda c, s, on: c.set_all_keys_locked(on),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PopurConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    coordinator = data.coordinator
    entities: list[SwitchEntity] = []
    for dev_id, client in data.clients.items():
        device = next(
            d for d in data.account_devices if d.device_id == dev_id
        )
        entities.extend(
            PopurSwitch(coordinator, client, device, desc)
            for desc in SWITCHES
        )
    async_add_entities(entities)


class PopurSwitch(PopurEntity, SwitchEntity):
    entity_description: PopurSwitchDescription

    def __init__(self, coordinator, client, device, description) -> None:
        super().__init__(coordinator, client, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.device_id}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        if self.snapshot is None:
            return None
        return self.entity_description.is_on_fn(self.snapshot)

    async def _async_set(self, on: bool) -> None:
        snapshot = self.snapshot
        if snapshot is None:
            return
        await self.entity_description.set_fn(self.client, snapshot, on)
        await self.coordinator.async_request_refresh()

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_set(False)
