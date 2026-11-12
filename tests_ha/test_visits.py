"""Pet visit events: every new record, once, for every pet; fetches end on unload."""

from __future__ import annotations

import asyncio

import pytest
from homeassistant.const import EVENT_STATE_CHANGED, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er

from pypopur.reads import Pet

from .conftest import BASE_TIME_MS, PET_ID, FakePopur, make_record

OTHER_PET_ID = 8


def _visit_entity(hass: HomeAssistant, pet_id: int) -> str | None:
    return er.async_get(hass).async_get_entity_id("event", "popur", f"pet_{pet_id}_visit")


@pytest.fixture
def visits(hass: HomeAssistant):
    """Collect ``(entity_id, attributes)`` for every visit event fired."""

    calls: list[tuple[str, dict]] = []

    @callback
    def _listener(event) -> None:
        new = event.data["new_state"]
        if (
            new is None
            or not new.entity_id.startswith("event.")
            or not new.entity_id.endswith("_visit")
            or new.state == STATE_UNKNOWN
        ):
            return
        calls.append((new.entity_id, dict(new.attributes)))

    hass.bus.async_listen(EVENT_STATE_CHANGED, _listener)
    return calls


async def _slow_refresh(hass: HomeAssistant, coordinator) -> None:
    coordinator._next_cloud_refresh = 0
    await coordinator.async_refresh()
    await hass.async_block_till_done()


async def test_every_new_record_fires_oldest_first(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.records += [
        make_record(BASE_TIME_MS + 120_000, weight=4200),
        make_record(BASE_TIME_MS + 60_000, weight=4100),
    ]
    await _slow_refresh(hass, coordinator)

    assert [a["weight_g"] for _, a in visits] == [4100, 4200]


async def test_burst_larger_than_a_page_fires_every_record(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.records += [
        make_record(BASE_TIME_MS + i * 60_000, weight=4000 + i) for i in range(1, 31)
    ]
    await _slow_refresh(hass, coordinator)

    assert [a["weight_g"] for _, a in visits] == [4000 + i for i in range(1, 31)]
    pages = [c.kwargs["page_no"] for c in popur.account.pet_records.await_args_list[-2:]]
    assert pages == [1, 2]


async def test_paging_stops_at_known_records(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    # A long history the integration has already seen, plus one new record.
    popur.records += [make_record(BASE_TIME_MS - i * 60_000) for i in range(1, 60)]
    popur.records.append(make_record(BASE_TIME_MS + 60_000))
    popur.account.pet_records.reset_mock()
    await _slow_refresh(hass, coordinator)

    assert len(visits) == 1
    assert [c.kwargs["page_no"] for c in popur.account.pet_records.await_args_list] == [1]


async def test_non_toilet_usage_record_does_not_fire(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.records.append(make_record(BASE_TIME_MS + 60_000, dp_code="weight_data"))
    await _slow_refresh(hass, coordinator)

    assert visits == []


async def test_non_visit_during_delayed_fetch_still_retries(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    # A different cloud record arrives before the delayed toilet-usage record.
    popur.records.append(make_record(BASE_TIME_MS + 60_000, dp_code="weight_data"))

    await coordinator._fetch_pet_records()
    await hass.async_block_till_done()

    assert visits == []
    assert coordinator._record_fetch_attempt == 1
    assert coordinator._record_fetch_timer is not None


async def test_newer_non_visit_does_not_replace_latest_toilet_visit(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.records.extend(
        [
            make_record(BASE_TIME_MS + 60_000, weight=4200),
            make_record(BASE_TIME_MS + 120_000, dp_code="weight_data"),
        ]
    )

    await _slow_refresh(hass, coordinator)

    latest = coordinator.data.pet_visits[PET_ID]
    assert latest.record.record_time == BASE_TIME_MS + 60_000
    assert latest.weight_grams == 4200
    assert [attrs["weight_g"] for _, attrs in visits] == [4200]


async def test_overlapping_fetches_fire_once(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.records.append(make_record(BASE_TIME_MS + 60_000))
    fetch = popur.account.pet_records.side_effect

    async def _yielding(*args, **kwargs):
        await asyncio.sleep(0)  # a real cloud call yields to the loop
        return await fetch(*args, **kwargs)

    popur.account.pet_records.side_effect = _yielding

    # Delayed post-cat_left fetch and slow-tier refresh race on the same record.
    coordinator._next_cloud_refresh = 0
    await asyncio.gather(coordinator._fetch_pet_records(), coordinator.async_refresh())
    await hass.async_block_till_done()

    assert len(visits) == 1


async def test_pet_missing_from_page_keeps_its_visit(
    hass: HomeAssistant, popur: FakePopur, setup_entry
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.records = [make_record(BASE_TIME_MS + 60_000, pet_id=OTHER_PET_ID)]
    await _slow_refresh(hass, coordinator)

    assert coordinator.data.pet_visits[PET_ID].record.record_time == BASE_TIME_MS
    assert OTHER_PET_ID in coordinator.data.pet_visits


async def test_pet_added_later_gets_a_visit_entity(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    assert _visit_entity(hass, OTHER_PET_ID) is None

    popur.pets.append(Pet.from_json({"id": OTHER_PET_ID, "name": "Felix"}))
    await _slow_refresh(hass, coordinator)
    entity_id = _visit_entity(hass, OTHER_PET_ID)
    assert entity_id is not None

    popur.records.append(make_record(BASE_TIME_MS + 60_000, pet_id=OTHER_PET_ID))
    await _slow_refresh(hass, coordinator)
    assert [e for e, _ in visits] == [entity_id]


async def test_unload_cancels_running_fetch(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    started, release = asyncio.Event(), asyncio.Event()
    fetch = popur.account.pet_records.side_effect

    async def _slow(*args, **kwargs):
        started.set()
        await release.wait()
        return await fetch(*args, **kwargs)

    popur.account.pet_records.side_effect = _slow
    popur.records.append(make_record(BASE_TIME_MS + 60_000))

    coordinator._start_record_fetch()
    await started.wait()
    task = coordinator._record_fetch_task
    coordinator.cancel_record_fetch()
    release.set()
    await hass.async_block_till_done()

    assert task.cancelled()
    assert visits == []


async def test_mqtt_connects_after_event_entities_exist(
    hass: HomeAssistant, popur: FakePopur, setup_entry
) -> None:
    assert popur.event_entities_at_connect, "MQTT connected before event entities"



async def _run_scheduled_record_fetch(hass: HomeAssistant, coordinator) -> None:
    """Fire the actual delayed-fetch callback without waiting 45 real seconds."""
    timer = coordinator._record_fetch_timer
    assert timer is not None and not timer.cancelled()
    timer.cancel()
    coordinator._record_fetch_timer = None
    coordinator._start_record_fetch()
    await hass.async_block_till_done()


async def test_first_delayed_fetch_with_visit_does_not_schedule_retry(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.push({22: "cat_left"})
    await hass.async_block_till_done()
    assert coordinator._record_fetch_timer is not None

    popur.records.append(make_record(BASE_TIME_MS + 60_000, weight=4150, duration=42))
    previous_requests = popur.account.pet_records.await_count
    await _run_scheduled_record_fetch(hass, coordinator)

    assert popur.account.pet_records.await_count == previous_requests + 1
    assert coordinator._record_fetch_attempt == 1
    assert coordinator._record_fetch_timer is None
    assert [(entity, attrs["weight_g"], attrs["duration_s"]) for entity, attrs in visits] == [
        (_visit_entity(hass, PET_ID), 4150, 42)
    ]


async def test_second_delayed_fetch_finds_visit_after_non_visit(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    popur.push({22: "cat_left"})
    await hass.async_block_till_done()

    popur.records.append(make_record(BASE_TIME_MS + 60_000, dp_code="weight_data"))
    previous_requests = popur.account.pet_records.await_count
    await _run_scheduled_record_fetch(hass, coordinator)

    assert popur.account.pet_records.await_count == previous_requests + 1
    assert visits == []
    assert coordinator._record_fetch_attempt == 1
    assert coordinator._record_fetch_timer is not None

    popur.records.append(make_record(BASE_TIME_MS + 120_000, weight=4250, duration=50))
    await _run_scheduled_record_fetch(hass, coordinator)

    assert popur.account.pet_records.await_count == previous_requests + 2
    assert coordinator._record_fetch_attempt == 2
    assert coordinator._record_fetch_timer is None
    assert [(attrs["weight_g"], attrs["duration_s"]) for _, attrs in visits] == [(4250, 50)]
    assert coordinator.data.pet_visits[PET_ID].record.record_time == BASE_TIME_MS + 120_000


async def test_non_visit_refresh_preserves_sensor_values_until_next_visit(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    registry = er.async_get(hass)
    weight_id = registry.async_get_entity_id("sensor", "popur", f"pet_{PET_ID}_last_weight")
    duration_id = registry.async_get_entity_id(
        "sensor", "popur", f"pet_{PET_ID}_last_visit_duration"
    )
    time_id = registry.async_get_entity_id("sensor", "popur", f"pet_{PET_ID}_last_visit")
    assert weight_id is not None and duration_id is not None and time_id is not None

    popur.records.append(make_record(BASE_TIME_MS + 60_000, weight=4300, duration=45))
    await _slow_refresh(hass, coordinator)
    initial_weight = hass.states.get(weight_id)
    initial_duration = hass.states.get(duration_id)
    initial_time = hass.states.get(time_id)
    # HA converts the sensor's native grams to its suggested kilograms.
    assert initial_weight is not None and float(initial_weight.state) == 4.3
    assert initial_weight.attributes["unit_of_measurement"] == "kg"
    assert initial_duration is not None and float(initial_duration.state) == 45
    assert initial_time is not None and initial_time.state != STATE_UNKNOWN

    # A newer weight_data record must not erase the last measured toilet visit.
    popur.records.append(make_record(BASE_TIME_MS + 120_000, dp_code="weight_data"))
    await _slow_refresh(hass, coordinator)
    assert hass.states.get(weight_id).state == initial_weight.state
    assert hass.states.get(duration_id).state == initial_duration.state
    assert hass.states.get(time_id).state == initial_time.state
    assert [attrs["weight_g"] for _, attrs in visits] == [4300]

    # A subsequent actual visit must still update the sensors and emit an event.
    popur.records.append(make_record(BASE_TIME_MS + 180_000, weight=4550, duration=55))
    await _slow_refresh(hass, coordinator)
    assert float(hass.states.get(weight_id).state) == 4.55
    assert float(hass.states.get(duration_id).state) == 55
    assert hass.states.get(time_id).state != initial_time.state
    assert [attrs["weight_g"] for _, attrs in visits] == [4300, 4550]


async def test_repeated_refreshes_do_not_replay_or_modify_visit_event(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    visit_id = _visit_entity(hass, PET_ID)
    assert visit_id is not None
    popur.records.append(make_record(BASE_TIME_MS + 60_000, weight=4400, duration=39))
    await _slow_refresh(hass, coordinator)

    first_state = hass.states.get(visit_id)
    assert first_state is not None and first_state.state != STATE_UNKNOWN
    assert first_state.attributes["event_type"] == "visit_recorded"
    assert first_state.attributes["weight_g"] == 4400
    assert [attrs["weight_g"] for _, attrs in visits] == [4400]

    for _ in range(3):
        await _slow_refresh(hass, coordinator)

    final_state = hass.states.get(visit_id)
    assert final_state is not None
    assert final_state.state == first_state.state
    assert final_state.attributes == first_state.attributes
    assert [attrs["weight_g"] for _, attrs in visits] == [4400]
    assert coordinator._seen_record_time[PET_ID] == BASE_TIME_MS + 60_000
