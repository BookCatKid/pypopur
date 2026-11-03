"""The first successful records fetch is history, even after a failed one."""

from __future__ import annotations

import pytest
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .conftest import PET_ID, FakePopur


@pytest.fixture
def popur() -> FakePopur:
    fake = FakePopur()
    ok = fake.account.pet_records.side_effect
    calls = {"n": 0}

    async def _flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("cloud down")
        return await ok(*args, **kwargs)

    fake.account.pet_records.side_effect = _flaky
    return fake


async def test_no_visit_on_first_successful_load(
    hass: HomeAssistant, popur: FakePopur, setup_entry
) -> None:
    visit_id = er.async_get(hass).async_get_entity_id("event", "popur", f"pet_{PET_ID}_visit")
    assert visit_id is not None
    coordinator = setup_entry.runtime_data.coordinator

    coordinator._next_cloud_refresh = 0
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    assert popur.account.pet_records.await_count == 2
    assert coordinator.data.pet_visits  # records are now loaded
    assert hass.states.get(visit_id).state == STATE_UNKNOWN
