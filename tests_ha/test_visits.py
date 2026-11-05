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
