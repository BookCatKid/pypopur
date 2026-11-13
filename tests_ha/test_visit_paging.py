"""Record paging reaches back to every household pet's last seen record."""

from __future__ import annotations

import pytest
from homeassistant.const import EVENT_STATE_CHANGED, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er

from pypopur.reads import Pet, PetRecord, PetRecordPage

from .conftest import BASE_TIME_MS, PET_ID, FakePopur, make_record

OTHER_PET_ID = 8
# Pet 8's last record at setup, well before pet 7's.
OTHER_SEEN_MS = BASE_TIME_MS - 600_000


@pytest.fixture
def popur() -> FakePopur:
    fake = FakePopur()
    fake.pets.append(Pet.from_json({"id": OTHER_PET_ID, "name": "Felix"}))
    fake.records.append(make_record(OTHER_SEEN_MS, pet_id=OTHER_PET_ID))
    # Older history: more than a page in total.
    fake.records += [make_record(OTHER_SEEN_MS - i * 60_000) for i in range(1, 31)]
    return fake


@pytest.fixture
def visits(hass: HomeAssistant):
    """Collect ``(pet_id, weight_g)`` for every visit event fired."""

    calls: list[tuple[int, int]] = []

    @callback
    def _listener(event) -> None:
        new = event.data["new_state"]
        if (
            new is None
            or not new.entity_id.startswith("event.")
            or not new.entity_id.endswith("_visit")
            or new.state in (STATE_UNKNOWN, STATE_UNAVAILABLE)
        ):
            return
        calls.append((new.attributes["pet_id"], new.attributes["weight_g"]))

    hass.bus.async_listen(EVENT_STATE_CHANGED, _listener)
    return calls


def _pages_read(popur: FakePopur) -> list[int]:
    return [c.kwargs["page_no"] for c in popur.account.pet_records.await_args_list]


async def _slow_refresh(hass: HomeAssistant, coordinator) -> None:
    coordinator._next_cloud_refresh = 0
    await coordinator.async_refresh()
    await hass.async_block_till_done()


async def test_first_fetch_reads_one_page(
    hass: HomeAssistant, popur: FakePopur, setup_entry
) -> None:
    coordinator = setup_entry.runtime_data.coordinator

    assert _pages_read(popur) == [1]  # although more pages exist
    assert coordinator._seen_record_time == {
        PET_ID: BASE_TIME_MS,
        OTHER_PET_ID: OTHER_SEEN_MS,
    }
    assert er.async_get(hass).async_get_entity_id(
        "event", "popur", f"pet_{OTHER_PET_ID}_visit"
    )


async def test_known_record_of_one_pet_does_not_hide_another_pets_visit(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    # Page 1: 24 new visits of pet 7, then its already seen record.
    popur.records += [
        make_record(BASE_TIME_MS + i * 60_000, weight=4000 + i) for i in range(1, 25)
    ]
    # Page 2: a visit of pet 8, older than pet 7's seen record but newer
    # than pet 8's, then pet 8's seen record.
    popur.records.append(
        make_record(BASE_TIME_MS - 300_000, pet_id=OTHER_PET_ID, weight=3500)
    )
    popur.account.pet_records.reset_mock()
    await _slow_refresh(hass, coordinator)

    assert [v for v in visits if v[0] == OTHER_PET_ID] == [(OTHER_PET_ID, 3500)]
    assert [w for p, w in visits if p == PET_ID] == [4000 + i for i in range(1, 25)]
    assert _pages_read(popur) == [1, 2]
    assert coordinator._seen_record_time[OTHER_PET_ID] == BASE_TIME_MS - 300_000


async def test_paging_stops_below_lowest_watermark(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    """The pages need to reach back past the lowest watermark, not to each
    pet's own record; unmatched and undated records neither crash nor stop
    paging early."""

    coordinator = setup_entry.runtime_data.coordinator
    unmatched = [
        PetRecord.from_json(
            {"dpCode": "toilet_usage_data", "time": BASE_TIME_MS + i * 1_000, "value": "01"}
        )
        for i in range(1, 24)
    ]
    undated = PetRecord.from_json({"dpCode": "toilet_usage_data", "petId": PET_ID})
    pages = {
        # Nothing on page 1 is at or below pet 8's watermark.
        1: [*reversed(unmatched), undated, make_record(BASE_TIME_MS)],
        # Pet 8's new visit, then a pet 7 record below pet 8's watermark;
        # pet 8's own seen record would only come on page 3.
        2: [
            make_record(BASE_TIME_MS - 300_000, pet_id=OTHER_PET_ID, weight=3500),
            make_record(OTHER_SEEN_MS - 60_000),
        ],
    }

    async def _serve(*_args, page_no: int = 1, **_kwargs) -> PetRecordPage:
        return PetRecordPage(records=tuple(pages.get(page_no, ())), total=100, has_next=True)

    popur.account.pet_records.side_effect = _serve
    popur.account.pet_records.reset_mock()
    await _slow_refresh(hass, coordinator)

    assert _pages_read(popur) == [1, 2]
    assert visits == [(OTHER_PET_ID, 3500)]


async def test_pet_left_household_does_not_hold_paging_open(
    hass: HomeAssistant, popur: FakePopur, setup_entry, visits
) -> None:
    coordinator = setup_entry.runtime_data.coordinator
    # History between the two pets' watermarks, landed after setup: already
    # seen for pet 7, but it pushes pet 8's watermark past page 1.
    popur.records += [
        make_record(BASE_TIME_MS - i * 10_000, weight=3000) for i in range(1, 31)
    ]
    popur.records.append(make_record(BASE_TIME_MS + 60_000, weight=4100))
    popur.account.pet_records.reset_mock()
    await _slow_refresh(hass, coordinator)

    assert _pages_read(popur) == [1, 2]  # pet 8 is still in the household
    assert visits == [(PET_ID, 4100)]

    popur.pets = [p for p in popur.pets if p.pet_id != OTHER_PET_ID]
    popur.records.append(make_record(BASE_TIME_MS + 120_000, weight=4200))
    popur.account.pet_records.reset_mock()
    await _slow_refresh(hass, coordinator)

    assert OTHER_PET_ID in coordinator._seen_record_time
    assert _pages_read(popur) == [1]
    assert visits == [(PET_ID, 4100), (PET_ID, 4200)]
