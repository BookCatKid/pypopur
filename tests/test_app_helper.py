"""Tests for ``app/helper.py`` — ``UnifiedDeviceControlHelper`` parity.

Each assertion pins the exact DP map, command string, or packed-byte output
the APK's smali produces.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pypopur.app.helper import (
    DeviceCommandError,
    UnifiedDeviceControlHelper,
)
from pypopur.app.manager import UnifiedDeviceControlManager
from pypopur.app.repository import DeviceRepository, RepositoryDevice

DEV_ID = "dev1"

# A DP102 baseline with recognisable bytes at touched indexes.
DP102_BASE = bytes(range(29))


class _FakeDevice:
    """Device instance exposing the SDK ``publishDps``/``getDps`` surface."""

    def __init__(self, dev_id: str = DEV_ID, dps: dict | None = None):
        self._dev_id = dev_id
        self._dps: dict[str, Any] = dict(dps or {})
        self.published: list[dict[str, Any]] = []

    def getDevId(self) -> str:
        return self._dev_id

    def getDps(self) -> dict[str, Any]:
        return dict(self._dps)

    def publishDps(self, dps_json: str, callback: Any) -> None:
        parsed = json.loads(dps_json)
        self.published.append(parsed)
        self._dps.update(parsed)
        callback.onSuccess()


class _FailingDevice(_FakeDevice):
    def publishDps(self, dps_json: str, callback: Any) -> None:
        callback.onError("11001", "bad dps")


@pytest.fixture()
def device() -> _FakeDevice:
    return _FakeDevice()


@pytest.fixture()
def helper(device: _FakeDevice) -> UnifiedDeviceControlHelper:
    manager = UnifiedDeviceControlManager(device_factory=lambda dev_id: _FakeDevice(dev_id))
    manager.device_instances[DEV_ID] = device
    repository = DeviceRepository(device_lookup=lambda dev_id: RepositoryDevice(dev_id))
    return UnifiedDeviceControlHelper(manager, repository)


def _last_dp(helper: UnifiedDeviceControlHelper) -> dict[str, Any]:
    device = helper.manager.device_instances[DEV_ID]
    return device.published[-1]


# -- exact DP maps ---------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("coro", "expected"),
    [
        (lambda h: h.set_clean_control(DEV_ID, True), {"1": True}),
        (lambda h: h.set_clean_control(DEV_ID, False), {"1": False}),
        (lambda h: h.start_cleaning(DEV_ID), {"1": True}),
        (lambda h: h.stop_cleaning(DEV_ID), {"1": False}),
        (lambda h: h.set_machine_control(DEV_ID, "power_on"), {"109": "power_on"}),
        (lambda h: h.set_machine_control(DEV_ID, "reboot"), {"109": "reboot"}),
        (lambda h: h.control_sifter(DEV_ID, "open"), {"108": "open"}),
        (lambda h: h.control_sifter(DEV_ID, "pause_scoop"), {"108": "pause_scoop"}),
        (lambda h: h.control_trash_bin(DEV_ID, True), {"31": True}),
        (lambda h: h.set_operation_mode(DEV_ID, "auto_clean"), {"102": "auto_clean"}),
        # Firmware strings keep the app's literal misspellings.
        (lambda h: h.zero_bin(DEV_ID), {"107": "zeoring"}),
        (lambda h: h.recalibrate_spin_sensor(DEV_ID), {"107": "specail_calibrate"}),
        (lambda h: h.start_self_check(DEV_ID), {"110": True}),
        (lambda h: h.stop_self_check(DEV_ID), {"110": False}),
        (lambda h: h.start_weight_calibration(DEV_ID), {"111": True}),
        (lambda h: h.set_real_led_switch(DEV_ID, True), {"20": True}),
        (lambda h: h.set_work_mode(DEV_ID, "music"), {"21": "music"}),
        (lambda h: h.set_work_mode_white(DEV_ID), {"21": "white"}),
        (lambda h: h.set_real_brightness(DEV_ID, 750), {"22": 750}),
        (lambda h: h.set_notification_switch(DEV_ID, "140", False), {"140": False}),
    ],
)
async def test_write_dp_map(
    helper: UnifiedDeviceControlHelper, coro: Any, expected: dict[str, Any]
) -> None:
    await coro(helper)
    assert _last_dp(helper) == expected


@pytest.mark.asyncio
async def test_raw_schedule_dps(helper: UnifiedDeviceControlHelper) -> None:
    # DND raw → DP10 (the app logs "DP167" — the wire key is 10).
    await helper.set_do_not_disturb_schedules_raw(DEV_ID, b"\x01\x02\x03\x04\x05\x06")
    assert _last_dp(helper) == {"10": "010203040506"}
    await helper.set_scheduled_clean_raw(DEV_ID, b"\xaa\xbb\xcc\xdd")
    assert _last_dp(helper) == {"14": "aabbccdd"}
    await helper.set_key_settings(DEV_ID, bytes([0, 1, 0, 1, 2, 1, 3]))
    assert _last_dp(helper) == {"105": "0001000102010 3".replace(" ", "")}


# -- validation --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_real_work_mode_validation(helper: UnifiedDeviceControlHelper) -> None:
    with pytest.raises(ValueError):
        await helper.set_real_work_mode(DEV_ID, "party")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [b"", b"\x01\x02", b"\x01" * 7, b"\x00" * 301],
    ids=["empty", "not-six-multiple", "seven", "over-300"],
)
async def test_dnd_raw_length_validation(helper: UnifiedDeviceControlHelper, bad: bytes) -> None:
    with pytest.raises(ValueError):
        await helper.set_do_not_disturb_schedules_raw(DEV_ID, bad)


@pytest.mark.asyncio
async def test_dnd_raw_accepts_single_byte(
    helper: UnifiedDeviceControlHelper,
) -> None:
    await helper.set_do_not_disturb_schedules_raw(DEV_ID, b"\x00")
    assert _last_dp(helper) == {"10": "00"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [b"", b"\x01\x02\x03", b"\x01" * 5, b"\x00" * 201],
    ids=["empty", "three", "five", "over-200"],
)
async def test_scheduled_clean_raw_length_validation(
    helper: UnifiedDeviceControlHelper, bad: bytes
) -> None:
    with pytest.raises(ValueError):
        await helper.set_scheduled_clean_raw(DEV_ID, bad)


@pytest.mark.asyncio
async def test_null_dp_values_rejected(helper: UnifiedDeviceControlHelper) -> None:
    with pytest.raises(ValueError):
        await helper.send_device_command(DEV_ID, {"1": None, "2": True})


@pytest.mark.asyncio
async def test_command_failure_raises() -> None:
    manager = UnifiedDeviceControlManager(device_factory=lambda dev_id: _FailingDevice(dev_id))
    manager.device_instances[DEV_ID] = _FailingDevice()
    helper = UnifiedDeviceControlHelper(manager, DeviceRepository())
    with pytest.raises(DeviceCommandError) as exc:
        await helper.set_clean_control(DEV_ID, True)
    assert exc.value.code == "11001"


@pytest.mark.asyncio
async def test_post_command_repo_hook(helper: UnifiedDeviceControlHelper) -> None:
    await helper.set_clean_control(DEV_ID, True)
    assert helper.repository.dp_states[DEV_ID]["1"] is True
    assert helper.local_dps[DEV_ID]["1"] is True


# -- packed-payload mutations --------------------------------------------------------


def _packed(device: _FakeDevice, dp: str) -> bytes:
    raw = device.published[-1][dp]
    return bytes.fromhex(raw)


@pytest.mark.asyncio
async def test_dp102_toggle_writes_byte_index(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice
) -> None:
    device._dps["102"] = DP102_BASE.hex()
    await helper.set_buzzer(DEV_ID, True)
    out = _packed(device, "102")
    assert len(out) == 29
    assert out[21] == 1
    # Untouched bytes preserved.
    assert out[:21] == DP102_BASE[:21] and out[22:] == DP102_BASE[22:]


@pytest.mark.asyncio
async def test_dp102_toggle_clear(helper: UnifiedDeviceControlHelper) -> None:
    device = helper.manager.device_instances[DEV_ID]
    device._dps["102"] = DP102_BASE.hex()
    await helper.set_status_light(DEV_ID, False)
    assert _packed(device, "102")[20] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("coro", "index"),
    [
        (lambda h: h.set_anti_interference(DEV_ID, True), 12),
        (lambda h: h.set_expert_mode(DEV_ID, True), 23),
        (lambda h: h.set_auto_power_cycle(DEV_ID, True), 24),
        (lambda h: h.set_lower_speed(DEV_ID, True), 25),
        (lambda h: h.set_auto_self_check(DEV_ID, True), 28),
    ],
)
async def test_dp102_toggle_indexes(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice, coro: Any, index: int
) -> None:
    device._dps["102"] = bytes(29).hex()
    await coro(helper)
    assert _packed(device, "102")[index] == 1


@pytest.mark.asyncio
async def test_dp102_field_setters(helper: UnifiedDeviceControlHelper, device: _FakeDevice) -> None:
    device._dps["102"] = bytes(29).hex()
    await helper.set_delay_clean_time(DEV_ID, 30)
    assert _packed(device, "102")[13] == 30
    await helper.set_radar_range(DEV_ID, 4)
    assert _packed(device, "102")[11] == 4
    await helper.set_radar_sensitivity(DEV_ID, 9)
    assert _packed(device, "102")[10] == 9
    await helper.set_device_color(DEV_ID, "black")
    assert _packed(device, "102")[17] == 1
    await helper.set_utc_setting(DEV_ID, -5)
    assert _packed(device, "102")[15] == (-5) & 0xFF


@pytest.mark.asyncio
async def test_dp102_reshuffle(helper: UnifiedDeviceControlHelper, device: _FakeDevice) -> None:
    device._dps["102"] = bytes(29).hex()
    await helper.set_reshuffle_clumps_enabled(DEV_ID, True)
    assert _packed(device, "102")[26] == 0x80
    await helper.set_reshuffle_oscillation(DEV_ID, "3X")
    out = _packed(device, "102")[26]
    assert out & 0x7F == 1  # "3X" = index 1


@pytest.mark.asyncio
async def test_dp102_notification_master(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice
) -> None:
    from pypopur.dps import dp102_bytes_with_notification_master

    device._dps["102"] = bytes(29).hex()
    await helper.update_system_settings_payload(
        DEV_ID, lambda b: dp102_bytes_with_notification_master(b, True)
    )
    assert _packed(device, "102")[19] == 1


@pytest.mark.asyncio
async def test_weight_function_bit(helper: UnifiedDeviceControlHelper, device: _FakeDevice) -> None:
    device._dps["102"] = bytes(29).hex()
    await helper.set_weight_function_bit(DEV_ID, 0x02, True)
    assert _packed(device, "102")[22] == 0x02


@pytest.mark.asyncio
async def test_weight_function_bit_preserves_existing(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice
) -> None:
    base = bytearray(29)
    base[22] = 0x05  # automatic + caring already set
    device._dps["102"] = bytes(base).hex()
    await helper.set_weight_function_bit(DEV_ID, 0x02, True)
    assert _packed(device, "102")[22] == 0x07
    # Fresh state for the clear case — the state flow caches prior merges.
    manager = helper.manager
    state = manager.device_state(DEV_ID)
    state.dp_data["102"] = bytes(base).hex()
    await helper.set_weight_function_bit(DEV_ID, 0x01, False)
    assert _packed(device, "102")[22] == 0x04


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("coro", "mask"),
    [
        (lambda h: h.set_bin_full_detection(DEV_ID, True), 0x01),
        (lambda h: h.set_allow_overfill(DEV_ID, True), 0x02),
        (lambda h: h.set_keep_upright(DEV_ID, True), 0x04),
        (lambda h: h.set_dump_override(DEV_ID, True), 0x08),
        (lambda h: h.set_block_on_full(DEV_ID, True), 0x10),
    ],
)
async def test_dp104_toggle_bits(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice, coro: Any, mask: int
) -> None:
    device._dps["104"] = bytes([0x05, 0x01, 0x05]).hex()
    await coro(helper)
    out = _packed(device, "104")
    assert out[0] & mask
    assert out[1:] == bytes([0x01, 0x05])


@pytest.mark.asyncio
async def test_dp104_fields(helper: UnifiedDeviceControlHelper, device: _FakeDevice) -> None:
    device._dps["104"] = bytes([0x05, 0x01, 0x05]).hex()
    await helper.set_cycle_counts(DEV_ID, 8)
    assert _packed(device, "104")[2] == 8
    await helper.set_dustbin_sensor_calibration(DEV_ID, 3)
    assert _packed(device, "104")[1] == 3


@pytest.mark.asyncio
async def test_dp104_clamps(helper: UnifiedDeviceControlHelper, device: _FakeDevice) -> None:
    device._dps["104"] = bytes([0x05, 0x01, 0x05]).hex()
    await helper.set_cycle_counts(DEV_ID, 50)
    assert _packed(device, "104")[2] == 10
    await helper.set_dustbin_sensor_calibration(DEV_ID, 9)
    assert _packed(device, "104")[1] == 3


@pytest.mark.asyncio
async def test_dp103_hibernate(helper: UnifiedDeviceControlHelper, device: _FakeDevice) -> None:
    device._dps["103"] = bytes(10).hex()
    await helper.set_sleep_time(DEV_ID, 120)
    out = _packed(device, "103")
    assert len(out) == 10 and out[9] == 120
    await helper.set_sleep_time(DEV_ID, 999)  # clamped to 200
    assert _packed(device, "103")[9] == 200


@pytest.mark.asyncio
async def test_packed_write_sends_hex_string(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice
) -> None:
    device._dps["102"] = bytes(29).hex()
    await helper.set_buzzer(DEV_ID, True)
    sent = device.published[-1]["102"]
    assert isinstance(sent, str) and len(sent) == 58


# -- queries --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_from_state(helper: UnifiedDeviceControlHelper, device: _FakeDevice) -> None:
    device._dps["101"] = "paws_up"
    assert await helper.query_device_status(DEV_ID) == "paws_up"
    assert await helper.query_battery_level(DEV_ID) == "paws_up"


@pytest.mark.asyncio
async def test_query_missing_device_raises(
    helper: UnifiedDeviceControlHelper,
) -> None:
    with pytest.raises(DeviceCommandError) as exc:
        await helper.query_device_dp("nope", "101")
    assert exc.value.code == "DP_QUERY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_query_packed_decoders(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice
) -> None:
    base = bytearray(29)
    base[13] = 7
    base[14] = 5
    device._dps["102"] = bytes(base).hex()
    assert await helper.query_delay_clean_time(DEV_ID) == 7
    assert await helper.query_litter_spread_count(DEV_ID) == 5


@pytest.mark.asyncio
async def test_real_device_all_status(
    helper: UnifiedDeviceControlHelper, device: _FakeDevice
) -> None:
    device._dps.update({"20": True, "21": "white", "22": 500})
    result = await helper.query_real_device_all_status(DEV_ID)
    assert result == {"led_switch": True, "work_mode": "white", "brightness": 500}
