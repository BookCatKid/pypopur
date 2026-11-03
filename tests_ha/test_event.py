"""Event entities: live MQTT activity/faults and new pet visit records."""

from __future__ import annotations

from datetime import timedelta

import pytest
from homeassistant.const import EVENT_STATE_CHANGED, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er

from pypopur.activity import ACTIVITY_EVENT_TYPES, FAULT_EVENT_TYPES

from .conftest import BASE_TIME_MS, DEV_ID, PET_ID, FakePopur, make_record

pytestmark = pytest.mark.usefixtures("setup_entry")


def _entity_id(hass: HomeAssistant, unique_id: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id("event", "popur", unique_id)
    assert entity_id is not None, unique_id
    return entity_id


@pytest.fixture
def activity_id(hass: HomeAssistant) -> str:
    return _entity_id(hass, f"{DEV_ID}_activity")


@pytest.fixture
def fault_id(hass: HomeAssistant) -> str:
    return _entity_id(hass, f"{DEV_ID}_fault_event")


@pytest.fixture
def visit_id(hass: HomeAssistant) -> str:
    return _entity_id(hass, f"pet_{PET_ID}_visit")


@pytest.fixture
def fired(hass: HomeAssistant):
    """Record ``(entity_id, event_type, attributes)`` for every event state write."""

    calls: list[tuple[str, str, dict]] = []

    @callback
    def _listener(event) -> None:
        new = event.data["new_state"]
        if new is None or not new.entity_id.startswith("event.") or new.state == STATE_UNKNOWN:
            return
        calls.append((new.entity_id, new.attributes.get("event_type"), dict(new.attributes)))

    hass.bus.async_listen(EVENT_STATE_CHANGED, _listener)
    return calls


def _of(calls, entity_id):
    return [(t, a) for e, t, a in calls if e == entity_id]


async def test_entities_created(hass: HomeAssistant, activity_id, fault_id, visit_id) -> None:
    activity = hass.states.get(activity_id)
    assert activity.state == STATE_UNKNOWN
    assert activity.attributes["event_types"] == list(ACTIVITY_EVENT_TYPES)
    assert hass.states.get(fault_id).attributes["event_types"] == list(FAULT_EVENT_TYPES)
    assert hass.states.get(visit_id).attributes["event_types"] == ["visit_recorded"]
    # First load of pet records is history, not an event.
    assert hass.states.get(visit_id).state == STATE_UNKNOWN
    assert er.async_get(hass).async_get(fault_id).entity_category == "diagnostic"


async def test_mqtt_dp22_triggers_activity(
    hass: HomeAssistant, popur: FakePopur, fired, activity_id
) -> None:
    popur.push({22: "cat_done_business"})
    await hass.async_block_till_done()

    [(event_type, attrs)] = _of(fired, activity_id)
    assert event_type == "cat_done_business"
    assert attrs["source"] == "mqtt"
    assert attrs["raw_value"] == "cat_done_business"
    assert "received_at" in attrs


async def test_repeated_dp22_triggers_twice(
    hass: HomeAssistant, popur: FakePopur, fired, activity_id, freezer
) -> None:
    popur.push({22: "cat_exist"})
    await hass.async_block_till_done()
    freezer.tick(timedelta(seconds=1))
    popur.push({22: "cat_exist"})
    await hass.async_block_till_done()

    assert [t for t, _ in _of(fired, activity_id)] == ["cat_exist", "cat_exist"]


async def test_idle_and_other_dps_do_not_trigger(
    hass: HomeAssistant, popur: FakePopur, fired, activity_id
) -> None:
    popur.push({22: "idle"})
    popur.push({101: "AQUAAwA="})
    await hass.async_block_till_done()
    assert _of(fired, activity_id) == []


async def test_polling_never_triggers(
    hass: HomeAssistant, popur: FakePopur, setup_entry, fired
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.client.raw_dps.update({22: "cat_left", 125: 0x3})
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    assert fired == []
    assert coordinator._record_fetch_task is None


async def test_dp125_fault_appear_and_clear(
    hass: HomeAssistant, popur: FakePopur, fired, fault_id, freezer
) -> None:
    popur.push({125: 0x1})
    await hass.async_block_till_done()
    freezer.tick(timedelta(seconds=1))
    popur.push({125: 0x0})
    await hass.async_block_till_done()

    events = _of(fired, fault_id)
    assert [t for t, _ in events] == ["fault_detected", "fault_cleared"]
    attrs = events[0][1]
    assert attrs["fault"] == "Error code A"
    assert attrs["mask"] == 1
    assert attrs["url"].endswith("error-code-a")
    assert attrs["source"] == "mqtt"
    assert attrs["raw_value"] == 0x1


async def test_dp125_unchanged_does_not_trigger(
    hass: HomeAssistant, popur: FakePopur, fired, fault_id
) -> None:
    popur.push({125: 0})
    await hass.async_block_till_done()
    assert _of(fired, fault_id) == []


async def test_cat_left_schedules_record_fetch_and_fires_visit(
    hass: HomeAssistant, popur: FakePopur, setup_entry, fired, activity_id, visit_id
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.push({22: "cat_left"})
    await hass.async_block_till_done()

    assert [t for t, _ in _of(fired, activity_id)] == ["cat_left"]
    assert coordinator._record_fetch_task is not None

    # The delayed fetch finds a newer record → one visit event.
    coordinator._record_fetch_task.cancel()
    popur.records.append(make_record(BASE_TIME_MS + 60_000, weight=4100, duration=45))
    await coordinator._fetch_pet_records()
    await hass.async_block_till_done()

    [(event_type, attrs)] = _of(fired, visit_id)
    assert event_type == "visit_recorded"
    assert attrs["pet_id"] == PET_ID
    assert attrs["weight_g"] == 4100
    assert attrs["duration_s"] == 45
    assert attrs["device_id"] == DEV_ID
    assert attrs["record_time"].startswith("2026-11-03T")


async def test_slow_tier_fires_visit_only_for_new_records(
    hass: HomeAssistant, popur: FakePopur, setup_entry, fired, visit_id
) -> None:
    coordinator = setup_entry.runtime_data.coordinator

    # Same records again → nothing.
    coordinator._next_cloud_refresh = 0
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert _of(fired, visit_id) == []

    popur.records.append(make_record(BASE_TIME_MS + 120_000))
    coordinator._next_cloud_refresh = 0
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert [t for t, _ in _of(fired, visit_id)] == ["visit_recorded"]
