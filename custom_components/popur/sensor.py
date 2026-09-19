"""Sensors for Popur devices and pets."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfMass, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from pypopur.models import (
    BinStatus,
    CatPresence,
    DeviceSnapshot,
    MachineStatus,
    RunningStatus,
)

from . import PopurConfigEntry
from .entity import PopurEntity, PopurPetEntity


@dataclass(frozen=True, kw_only=True)
class PopurSensorDescription(SensorEntityDescription):
    """Sensor reading a decoded DeviceSnapshot field."""

    value_fn: Callable[[DeviceSnapshot], Any]
    attrs_fn: Callable[[DeviceSnapshot], dict[str, Any]] | None = None


DEVICE_SENSORS: tuple[PopurSensorDescription, ...] = (
    PopurSensorDescription(
        key="machine_status",
        translation_key="machine_status",
        device_class=SensorDeviceClass.ENUM,
        options=[str(s) for s in MachineStatus],
        value_fn=lambda s: str(s.machine_status) if s.machine_status else None,
    ),
    PopurSensorDescription(
        key="running_status",
        translation_key="running_status",
        device_class=SensorDeviceClass.ENUM,
        options=[str(s) for s in RunningStatus],
        value_fn=lambda s: (
            str(s.run_mode.running_status) if s.run_mode else None
        ),
    ),
    PopurSensorDescription(
        key="bin_status",
        translation_key="bin_status",
        device_class=SensorDeviceClass.ENUM,
        options=[str(s) for s in BinStatus],
        value_fn=lambda s: (
            str(s.run_mode.bin_status) if s.run_mode else None
        ),
    ),
    PopurSensorDescription(
        key="cat_presence",
        translation_key="cat_presence",
        device_class=SensorDeviceClass.ENUM,
        options=[str(s) for s in CatPresence],
        value_fn=lambda s: str(s.cat_presence) if s.cat_presence else None,
    ),
    PopurSensorDescription(
        key="recent_activity",
        translation_key="recent_activity",
        value_fn=lambda s: (
            s.recent_activity.display_text
            if s.recent_activity and s.recent_activity.display_text
            else (str(s.recent_activity) if s.recent_activity else None)
        ),
    ),
    PopurSensorDescription(
        key="cat_weight",
        translation_key="cat_weight",
        device_class=SensorDeviceClass.WEIGHT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfMass.GRAMS,
        suggested_unit_of_measurement=UnitOfMass.KILOGRAMS,
        value_fn=lambda s: s.cat_weight,
    ),
    PopurSensorDescription(
        key="countdown",
        translation_key="countdown",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.MINUTES,
        value_fn=lambda s: s.run_mode.countdown_minutes if s.run_mode else None,
    ),
    PopurSensorDescription(
        key="daily_clean_count",
        translation_key="daily_clean_count",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda s: s.daily_clean_count,
    ),
    PopurSensorDescription(
        key="total_clean_count",
        translation_key="total_clean_count",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda s: s.total_clean_count,
    ),
    PopurSensorDescription(
        key="clean_count_after_full",
        translation_key="clean_count_after_full",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda s: s.clean_count_after_full,
    ),
    PopurSensorDescription(
        key="manual_clean_count",
        translation_key="manual_clean_count",
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.manual_clean_count,
    ),
    PopurSensorDescription(
        key="scheduled_clean_count",
        translation_key="scheduled_clean_count",
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.scheduled_clean_count,
    ),
    PopurSensorDescription(
        key="automatic_clean_count",
        translation_key="automatic_clean_count",
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.automatic_clean_count,
    ),
    PopurSensorDescription(
        key="total_use_time",
        translation_key="total_use_time",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        suggested_unit_of_measurement=UnitOfTime.HOURS,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.total_use_time,
    ),
    PopurSensorDescription(
        key="clean_duration",
        translation_key="clean_duration",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.clean_duration,
    ),
    PopurSensorDescription(
        key="cat_toilet_time",
        translation_key="cat_toilet_time",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        value_fn=lambda s: s.cat_toilet_time,
    ),
    PopurSensorDescription(
        key="fault_free_time",
        translation_key="fault_free_time",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        suggested_unit_of_measurement=UnitOfTime.HOURS,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.fault_free_time,
    ),
    PopurSensorDescription(
        key="self_check",
        translation_key="self_check",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.self_check.progress if s.self_check else None,
        attrs_fn=lambda s: {
            "faults": [f.label for f in s.self_check_faults],
            "fault_value": s.self_check_fault_value,
        },
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PopurConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    coordinator = data.coordinator

    entities: list[SensorEntity] = []
    for dev_id, client in data.clients.items():
        device = next(
            d for d in data.account_devices if d.device_id == dev_id
        )
        entities.extend(
            PopurDeviceSensor(coordinator, client, device, desc)
            for desc in DEVICE_SENSORS
        )
        entities.append(PopurConnectionSensor(coordinator, client, device))
        if coordinator.data:
            for pet_id in coordinator.data.pets:
                entities.extend(
                    PopurPetSensor(coordinator, device, pet_id, desc)
                    for desc in PET_SENSORS
                )
    async_add_entities(entities)


class PopurDeviceSensor(PopurEntity, SensorEntity):
    """A sensor reading the device snapshot."""

    entity_description: PopurSensorDescription

    def __init__(self, coordinator, client, device, description) -> None:
        super().__init__(coordinator, client, device)
        self.entity_description = description
        self._attr_unique_id = f"{device.device_id}_{description.key}"

    @property
    def native_value(self) -> Any:
        snapshot = self.snapshot
        if snapshot is None:
            return None
        return self.entity_description.value_fn(snapshot)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None or self.snapshot is None:
            return None
        return self.entity_description.attrs_fn(self.snapshot)


class PopurConnectionSensor(PopurEntity, SensorEntity):
    """Diagnostic sensor: which channel currently serves the device."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "connection"

    def __init__(self, coordinator, client, device) -> None:
        super().__init__(coordinator, client, device)
        self._attr_unique_id = f"{device.device_id}_connection"

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.transports.get(self.device.device_id)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.coordinator.data is None:
            return None
        return {"mqtt_connected": self.coordinator.data.mqtt_connected}


PET_SENSORS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key="last_weight",
        translation_key="pet_last_weight",
        device_class=SensorDeviceClass.WEIGHT,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfMass.GRAMS,
        suggested_unit_of_measurement=UnitOfMass.KILOGRAMS,
    ),
    SensorEntityDescription(
        key="last_visit_duration",
        translation_key="pet_last_visit_duration",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
    ),
    SensorEntityDescription(
        key="last_visit",
        translation_key="pet_last_visit",
        device_class=SensorDeviceClass.TIMESTAMP,
    ),
)


class PopurPetSensor(PopurPetEntity, SensorEntity):
    """A sensor reading the latest decoded visit for one pet."""

    def __init__(self, coordinator, device, pet_id, description) -> None:
        super().__init__(coordinator, device, pet_id)
        self.entity_description = description
        self._attr_unique_id = f"pet_{pet_id}_{description.key}"
        if coordinator.data is not None:
            pet = coordinator.data.pets.get(pet_id)
            if pet is not None:
                self._attr_device_info["name"] = pet.name

    @property
    def _visit(self):
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.pet_visits.get(self.pet_id)

    @property
    def native_value(self) -> Any:
        visit = self._visit
        key = self.entity_description.key
        if key == "last_weight":
            return visit.weight_grams if visit else None
        if key == "last_visit_duration":
            return visit.duration_seconds if visit else None
        if key == "last_visit":
            if visit and visit.record.record_time:
                return datetime.fromtimestamp(visit.record.record_time / 1000).astimezone()
            return None
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        visit = self._visit
        if visit is None:
            return None
        return {"match_reason": visit.record.match_reason}
