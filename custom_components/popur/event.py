"""Event entities for Popur devices and pets.

Activity (DP22) and fault (DP125) events are raised only from live MQTT
pushes; pet visits from newly fetched cloud records. Polling never
triggers any of them.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from homeassistant.components.event import EventEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from pypopur.activity import ACTIVITY_EVENT_TYPES, FAULT_EVENT_TYPES, ActivityEvent

from . import PopurConfigEntry
from .const import EVENT_TYPE_VISIT_RECORDED, signal_device_event, signal_pet_visit
from .entity import PopurEntity, PopurPetEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PopurConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    coordinator = data.coordinator

    entities: list[EventEntity] = []
    pet_device = None
    for dev_id, client in data.clients.items():
        device = next(
            d for d in data.account_devices if d.device_id == dev_id
        )
        pet_device = pet_device or device
        entities.append(PopurActivityEvent(coordinator, client, device))
        entities.append(PopurFaultEvent(coordinator, client, device))
    async_add_entities(entities)

    if pet_device is None:
        return

    # One visit entity per pet (pets are household-wide, not per device).
    # Pets can show up after setup (added in the app, or pet data
    # unavailable at first refresh): add their entity when they appear.
    known_pets: set[int] = set()

    @callback
    def _add_new_pets() -> None:
        if coordinator.data is None:
            return
        new_pets = [p for p in coordinator.data.pets if p not in known_pets]
        if not new_pets:
            return
        known_pets.update(new_pets)
        async_add_entities(
            PopurPetVisitEvent(coordinator, pet_device, pet_id)
            for pet_id in new_pets
        )

    _add_new_pets()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_pets))


class _PopurDeviceEvent(PopurEntity, EventEntity):
    """Event entity fed by the coordinator's per-device dispatcher signal."""

    _event_types: tuple[str, ...] = ()

    def __init__(self, coordinator, client, device) -> None:
        super().__init__(coordinator, client, device)
        self._attr_unique_id = f"{device.device_id}_{self._attr_translation_key}"
        self._attr_event_types = list(self._event_types)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_device_event(self.device.device_id),
                self._async_handle_event,
            )
        )

    @callback
    def _async_handle_event(
        self, event: ActivityEvent, attrs: Mapping[str, Any]
    ) -> None:
        if event.event_type not in self._event_types:
            return
        self._trigger_event(event.event_type, dict(attrs))
        self.async_write_ha_state()


class PopurActivityEvent(_PopurDeviceEvent):
    """Litter box activity (DP22): pet detected, clean completed, bin full…"""

    _attr_translation_key = "activity"
    _event_types = ACTIVITY_EVENT_TYPES


class PopurFaultEvent(_PopurDeviceEvent):
    """One event per fault bit set or cleared in DP125."""

    _attr_translation_key = "fault_event"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _event_types = FAULT_EVENT_TYPES


class PopurPetVisitEvent(PopurPetEntity, EventEntity):
    """A new toilet visit record for one pet."""

    _attr_translation_key = "pet_visit"

    def __init__(self, coordinator, device, pet_id) -> None:
        super().__init__(coordinator, device, pet_id)
        self._attr_event_types = [EVENT_TYPE_VISIT_RECORDED]
        self._attr_unique_id = f"pet_{pet_id}_visit"
        if coordinator.data is not None:
            pet = coordinator.data.pets.get(pet_id)
            if pet is not None:
                self._attr_device_info["name"] = pet.name

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, signal_pet_visit(self.pet_id), self._async_handle_visit
            )
        )

    @callback
    def _async_handle_visit(self, attrs: Mapping[str, Any]) -> None:
        self._trigger_event(EVENT_TYPE_VISIT_RECORDED, dict(attrs))
        self.async_write_ha_state()
