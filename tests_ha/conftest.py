"""Fixtures for the Popur Home Assistant integration tests.

Cloud, LAN and MQTT are faked at the integration's import boundary; the
coordinator, platforms and entities run for real.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Make ``custom_components`` importable from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.popur.const import CONF_INSTALL_ID, DOMAIN
from pypopur import decode_snapshot
from pypopur.mobile import AccountDevice
from pypopur.reads import Pet, PetRecord, PetRecordPage

DEV_ID = "dev123"
PET_ID = 7
BASE_TIME_MS = 1_793_742_868_000


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


def make_record(record_time: int, *, weight: int = 4000, duration: int = 60) -> PetRecord:
    value = bytes([1, weight >> 8, weight & 0xFF, duration >> 8, duration & 0xFF]).hex()
    return PetRecord.from_json(
        {
            "id": str(record_time),
            "devId": DEV_ID,
            "dpCode": "toilet_usage_data",
            "petId": PET_ID,
            "time": record_time,
            "value": value,
        }
    )


class FakeClient:
    """Stand-in for ``PopurClient``: ``refresh`` decodes ``raw_dps``."""

    def __init__(self) -> None:
        self.raw_dps: dict[int, Any] = {125: 0}
        self.transport = None

    async def refresh(self):
        return decode_snapshot(dict(self.raw_dps))

    async def close(self) -> None:
        return None


class FakeEvents:
    def __init__(self, on_event: Callable, on_connect: Callable) -> None:
        self.on_event = on_event
        self.on_connect = on_connect
        self.connected = True

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        self.connected = False


class FakePopur:
    """Fake account + device, with hooks the tests drive."""

    def __init__(self) -> None:
        self.client = FakeClient()
        self.records: list[PetRecord] = [make_record(BASE_TIME_MS)]
        self.events: FakeEvents | None = None
        self.account = MagicMock()
        self.account.login = AsyncMock()
        self.account.homes = AsyncMock(return_value=[{"gid": 1}])
        self.account.home_devices = AsyncMock(
            return_value=[
                AccountDevice(
                    device_id=DEV_ID, product_id="p", name="Litter", local_key="k"
                )
            ]
        )
        self.account.device_dps = AsyncMock(return_value={})
        self.account.pets = AsyncMock(
            return_value=[Pet.from_json({"id": PET_ID, "name": "Minou"})]
        )
        self.account.pet_records = AsyncMock(side_effect=self._records)
        self.account.connect_events = MagicMock(side_effect=self._connect_events)

    async def _records(self, *_args: Any, **_kwargs: Any) -> PetRecordPage:
        newest_first = sorted(self.records, key=lambda r: r.record_time or 0, reverse=True)
        return PetRecordPage(records=tuple(newest_first), total=len(newest_first), has_next=False)

    def _connect_events(self, *, devices, on_event, on_connect) -> FakeEvents:
        self.events = FakeEvents(on_event, on_connect)
        return self.events

    def push(self, dps: Mapping[int, Any]) -> None:
        """Deliver an MQTT DP report through the integration's callback."""

        from pypopur.events import DeviceEvent

        assert self.events is not None
        self.events.on_event(
            DeviceEvent(dev_id=DEV_ID, protocol=4, data={"dps": dict(dps)}, topic="t", dps=dict(dps))
        )


@pytest.fixture
def popur() -> FakePopur:
    return FakePopur()


@pytest.fixture
async def setup_entry(hass: HomeAssistant, popur: FakePopur):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_EMAIL: "a@b.c", CONF_PASSWORD: "pw", CONF_INSTALL_ID: "install"},
    )
    entry.add_to_hass(hass)
    with (
        patch("custom_components.popur.ThingMobileApi"),
        patch("custom_components.popur.MobileAppProfile"),
        patch("custom_components.popur.PopurAccount", return_value=popur.account),
        patch("custom_components.popur._local_transport", AsyncMock(return_value=None)),
        patch("custom_components.popur.PopurClient", return_value=popur.client),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    yield entry
    coordinator = entry.runtime_data.coordinator
    coordinator.cancel_record_fetch()
    await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
