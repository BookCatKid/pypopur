"""Port of ``UnifiedDeviceControlHelper`` — the app's typed control surface.

Method-for-method port of the APK's ``UnifiedDeviceControlHelper``
(``com.popur.android.feature.device``): every public suspend function maps
to a Python ``async`` method producing the same DP map, validation, and
packed-payload mutation as the smali.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ..codec import decode_raw_bytes
from ..dps import (
    decode_dp102,
    decode_dp104,
    decode_dp105,
    dp102_bytes_with_byte,
    dp102_bytes_with_device_color,
    dp102_bytes_with_notification_bit,
    dp102_bytes_with_reshuffle_enabled,
    dp102_bytes_with_reshuffle_oscillation,
    dp102_bytes_with_smooth_spread,
    dp102_bytes_with_timezone,
    dp102_bytes_with_toggle,
    dp103_with_hibernate_duration,
    dp104_bytes_with_calibration,
    dp104_bytes_with_cycle_count,
    dp104_bytes_with_toggle,
    validate_value_range,
)
from .manager import DeviceControlCallback, UnifiedDeviceControlManager
from .repository import DeviceRepository


class DeviceCommandError(Exception):
    """``Result.failure(Exception(code + ": " + error))`` from the app."""

    def __init__(self, code: str, error: str):
        super().__init__(f"{code}: {error}")
        self.code = code
        self.error = error


class _CommandResult(DeviceControlCallback):
    """``sendDeviceCommand$result$1$1`` — records the first outcome."""

    def __init__(self) -> None:
        self.outcome: tuple[bool, str, str] | None = None

    def on_error(self, code: str, error: str) -> None:
        if self.outcome is None:
            self.outcome = (False, code, error)

    def on_success(self) -> None:
        if self.outcome is None:
            self.outcome = (True, "", "")


# -- DP ids on the wire (verified against smali const-strings) -----------------
_DP_CLEAN_CONTROL = "1"
_DP_DAILY_CLEAN_COUNT = "7"
_DP_DND_SCHEDULES = "10"  # app logs "DP167 Raw" — the wire DP is 10
_DP_SCHEDULED_CLEAN = "14"  # app logs "DP104 Raw" — the wire DP is 14
_DP_LED_SWITCH = "20"
_DP_WORK_MODE = "21"
_DP_BRIGHTNESS = "22"
_DP_TRASH_BIN = "31"
_DP_STATUS = "101"
_DP_SYSTEM_SETTINGS = "102"
_DP_TIME_POWER = "103"
_DP_DUSTBIN_SETTINGS = "104"
_DP_KEY_SETTINGS = "105"
_DP_SPECIAL_OP = "107"
_DP_SIFTER = "108"
_DP_MACHINE = "109"
_DP_SELF_CHECK = "110"
_DP_WEIGHT_CAL = "111"
_DP_TOTAL_USE = "116"
_DP_LITTER_CAPACITY = "121"
_DP_CLEAN_AFTER_FULL = "146"
_DP_TOTAL_CLEAN = "152"

# Firmware command strings — the app's intentional spellings.
_CMD_ZEROING = "zeoring"
_CMD_SPECIAL_CALIBRATE = "specail_calibrate"

_REAL_WORK_MODES = ("music", "white", "colour")
_OPERATION_MODES = ("auto_clean", "forbidden_clean", "manual_clean")

# ``Dp104DustbinSettings`` byte-0 toggle bits.
_D104_BIN_FULL_DETECTION = 0x01
_D104_ALLOW_OVERFILL = 0x02
_D104_KEEP_UPRIGHT = 0x04
_D104_DUMP_OVERRIDE = 0x08
_D104_BLOCK_ON_FULL = 0x10

# ``Dp102SystemSettings`` byte indexes.
_D102_IDX_SENSITIVE = 10
_D102_IDX_RANGE = 11
_D102_IDX_ANTI_INTERFERENCE = 12
_D102_IDX_DELAY = 13
_D102_IDX_SMOOTH = 14
_D102_IDX_TIMEZONE = 15
_D102_IDX_DEVICE_COLOR = 17
_D102_IDX_NOTIFICATION_MASTER = 19
_D102_IDX_STATUS_LIGHT = 20
_D102_IDX_BUZZER = 21
_D102_IDX_WEIGHT_FUNCTION = 22
_D102_IDX_EXPERT_MODE = 23
_D102_IDX_AUTO_POWER_CYCLE = 24
_D102_IDX_LOWER_SPEED = 25
_D102_IDX_RESHUFFLE = 26
_D102_IDX_AUTO_SELF_CHECK = 28


def _hex_encode(data: bytes, spaced: bool = False) -> str:
    """``a([B,Z)`` — lowercase hex, optionally space-separated."""
    if not data:
        return ""
    if spaced:
        return " ".join(f"{b:02x}" for b in data)
    return data.hex()


def _hex_decode(text: str) -> bytes | None:
    """``b(String)`` — whitespace-stripped lowercase hex → bytes."""
    compact = "".join(str(text).lower().split())
    if len(compact) % 2:
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def _payload_to_bytes(value: Any) -> bytes | None:
    """``h(Object)``/``decodeToBytes`` — byte[] | JSON-array str | hex str."""
    return decode_raw_bytes(value)


class UnifiedDeviceControlHelper:
    """``UnifiedDeviceControlHelper`` — couples manager + repository."""

    def __init__(
        self,
        manager: UnifiedDeviceControlManager,
        repository: DeviceRepository,
    ) -> None:
        self.manager = manager
        self.repository = repository
        # ``d`` — the helper's own devId→{dpId→value} write-through cache.
        self.local_dps: dict[str, dict[str, Any]] = {}

    # -- core primitives --------------------------------------------------------

    async def send_device_command(self, dev_id: str, dps: Mapping[str, Any]) -> None:
        """``I`` — reject null values, dispatch, then run the post-write hook."""

        null_keys = [k for k, v in dps.items() if v is None]
        if null_keys:
            # IllegalArgumentException returned via Result.failure
            raise ValueError("DPS 包含 null，拒绝下发: " + ", ".join(null_keys))
        result = _CommandResult()
        self.manager.send_device_command(dev_id, dps, result)
        assert result.outcome is not None
        ok, code, error = result.outcome
        if not ok:
            raise DeviceCommandError(code, error)
        await self.repository.on_command_sent(dev_id, dps)

    def get_device_dp(self, dev_id: str, dp_id: str) -> Any:
        """``c`` — synchronous read of the repository's DP map (``K``)."""
        return (self.repository.dp_states.get(dev_id) or {}).get(dp_id)

    def _update_local_dp(self, dev_id: str, dp_id: str, value: Any) -> None:
        """``z0`` — write-through into the helper's local DP cache."""
        self.local_dps.setdefault(dev_id, {})[dp_id] = value

    async def query_device_dp(self, dev_id: str, dp_id: str) -> Any:
        """``o`` — state-cache hit → device-instance refresh → cache fallback.

        Returns the DP value or raises :class:`DeviceCommandError`
        (``DP_QUERY_UNAVAILABLE``/``DEVICE_NOT_FOUND``/``QUERY_EXCEPTION``).
        """
        state = self.manager.device_state(dev_id)
        if state is not None and dp_id in state.dp_data:
            return state.dp_data[dp_id]

        instance = self.manager.device_instances.get(dev_id)
        if instance is None:
            instance = self.manager.get_or_create_device(dev_id)
            if instance is None:
                raise DeviceCommandError("DEVICE_NOT_FOUND", "设备实例初始化失败")

        result = _CommandResult()
        try:
            self.manager.query_device_dp(instance, result)
        except Exception as exc:  # QUERY_EXCEPTION
            raise DeviceCommandError("QUERY_EXCEPTION", str(exc)) from exc

        state = self.manager.device_state(dev_id)
        if state is not None and dp_id in state.dp_data:
            return state.dp_data[dp_id]

        cached = self.get_device_dp(dev_id, dp_id)
        if cached is not None:
            return cached
        raise DeviceCommandError(
            "DP_QUERY_UNAVAILABLE",
            f"无法从设备实例主动查询 DP，请依赖本地缓存或监听器上报（设备 {dev_id}）",
        )

    async def query_device_dp_value(self, dev_id: str, dp_id: str) -> Any:
        """``p`` — ``o`` followed by the cached-value extraction."""
        value = await self.query_device_dp(dev_id, dp_id)
        if value is not None:
            return value
        return self.get_device_dp(dev_id, dp_id)

    # -- packed-payload updater engine (A0/C0/E0) --------------------------------

    async def _update_packed_payload(
        self, dev_id: str, dp_id: str, fn: Callable[[bytes], bytes]
    ) -> None:
        """Read the raw DP → ``fn(bytes)`` → send ``{dp: hex}`` → repo write."""
        try:
            raw = await self.query_device_dp(dev_id, dp_id)
        except DeviceCommandError:
            raw = self.get_device_dp(dev_id, dp_id)
        payload = _payload_to_bytes(raw)
        new_bytes = fn(payload or b"")
        await self.send_device_command(dev_id, {dp_id: _hex_encode(new_bytes)})

    async def update_dustbin_settings_payload(
        self, dev_id: str, fn: Callable[[bytes], bytes]
    ) -> None:
        """``A0`` — DP104 read-modify-write."""
        await self._update_packed_payload(dev_id, _DP_DUSTBIN_SETTINGS, fn)

    async def update_system_settings_payload(
        self, dev_id: str, fn: Callable[[bytes], bytes]
    ) -> None:
        """``C0`` — DP102 read-modify-write."""
        await self._update_packed_payload(dev_id, _DP_SYSTEM_SETTINGS, fn)

    async def update_time_power_on_off_payload(
        self, dev_id: str, fn: Callable[[bytes], bytes]
    ) -> None:
        """``E0`` — DP103 read-modify-write."""
        await self._update_packed_payload(dev_id, _DP_TIME_POWER, fn)

    async def update_dustbin_settings_toggle(
        self, dev_id: str, bit_mask: int, enabled: bool
    ) -> None:
        """``B0`` — ``Dp104.bytesWithToggle`` on byte 0."""
        await self.update_dustbin_settings_payload(
            dev_id, lambda b: dp104_bytes_with_toggle(b, bit_mask, enabled)
        )

    async def update_system_settings_toggle(self, dev_id: str, index: int, enabled: bool) -> None:
        """``D0`` — ``Dp102.bytesWithToggle`` byte write."""
        await self.update_system_settings_payload(
            dev_id, lambda b: dp102_bytes_with_toggle(b, index, enabled)
        )

    async def set_weight_function_bit(self, dev_id: str, bit_mask: int, enabled: bool) -> None:
        """``q0`` — ``Dp102.bytesWithWeightFunctionBit`` on byte 22."""
        await self.update_system_settings_payload(
            dev_id,
            lambda b: dp102_bytes_with_notification_bit(
                b, _D102_IDX_WEIGHT_FUNCTION, bit_mask, enabled
            ),
        )

    async def mutate_system_settings_payload(
        self, dev_id: str, fn: Callable[[bytes], bytes]
    ) -> None:
        """``g`` — public passthrough to ``update_system_settings_payload``."""
        await self.update_system_settings_payload(dev_id, fn)

    # -- clean control ------------------------------------------------------------

    async def set_clean_control(self, dev_id: str, start: bool) -> None:
        """``Q`` — ``{"1": bool}`` + local-DP write-through on success."""
        await self.send_device_command(dev_id, {_DP_CLEAN_CONTROL: start})
        self._update_local_dp(dev_id, _DP_CLEAN_CONTROL, start)

    async def start_cleaning(self, dev_id: str) -> None:
        """``t0`` — delegates to ``set_clean_control(true)``."""
        await self.set_clean_control(dev_id, True)

    async def stop_cleaning(self, dev_id: str) -> None:
        """``w0`` — delegates to ``set_clean_control(false)``."""
        await self.set_clean_control(dev_id, False)

    # -- machine / sifter / trash-bin ---------------------------------------------

    async def set_machine_control(self, dev_id: str, command: str) -> None:
        """``c0`` — ``{"109": command}`` (power_on/power_off/reboot)."""
        await self.send_device_command(dev_id, {_DP_MACHINE: command})

    async def control_sifter(self, dev_id: str, command: str) -> None:
        """``{"108": command}`` (open/close/start_scoop/pause_scoop)."""
        await self.send_device_command(dev_id, {_DP_SIFTER: command})

    async def control_trash_bin(self, dev_id: str, open_: bool) -> None:
        """``{"31": bool}`` — trash-bin lid."""
        await self.send_device_command(dev_id, {_DP_TRASH_BIN: open_})

    async def set_operation_mode(self, dev_id: str, mode: str) -> None:
        """``e0`` — ``{"102": mode}`` (auto_clean/forbidden_clean/manual_clean)."""
        await self.send_device_command(dev_id, {_DP_SYSTEM_SETTINGS: mode})

    # -- special operations ---------------------------------------------------------

    async def zero_bin(self, dev_id: str) -> None:
        """``F0`` — ``{"107": "zeoring"}`` (the app's literal spelling)."""
        await self.send_device_command(dev_id, {_DP_SPECIAL_OP: _CMD_ZEROING})

    async def recalibrate_spin_sensor(self, dev_id: str) -> None:
        """``G`` — ``{"107": "specail_calibrate"}``."""
        await self.send_device_command(dev_id, {_DP_SPECIAL_OP: _CMD_SPECIAL_CALIBRATE})

    # -- self-check / weight --------------------------------------------------------

    async def start_self_check(self, dev_id: str) -> None:
        """``u0`` — ``{"110": true}``."""
        await self.send_device_command(dev_id, {_DP_SELF_CHECK: True})

    async def stop_self_check(self, dev_id: str) -> None:
        """``x0`` — ``{"110": false}``."""
        await self.send_device_command(dev_id, {_DP_SELF_CHECK: False})

    async def start_weight_calibration(self, dev_id: str) -> None:
        """``v0`` — ``{"111": true}``."""
        await self.send_device_command(dev_id, {_DP_WEIGHT_CAL: True})

    # -- real-device lighting / mode --------------------------------------------------

    async def set_real_led_switch(self, dev_id: str, enabled: bool) -> None:
        """``i0`` — ``{"20": bool}``."""
        await self.send_device_command(dev_id, {_DP_LED_SWITCH: enabled})

    async def set_real_work_mode(self, dev_id: str, mode: str) -> None:
        """``j0`` — ``{"21": mode}``; validates music/white/colour."""
        if mode not in _REAL_WORK_MODES:
            raise ValueError(f"无效的工作模式: {mode}, 有效值: {list(_REAL_WORK_MODES)}")
        await self.send_device_command(dev_id, {_DP_WORK_MODE: mode})

    async def set_work_mode(self, dev_id: str, mode: str) -> None:
        """``r0`` — ``{"21": mode}`` (unvalidated variant)."""
        await self.send_device_command(dev_id, {_DP_WORK_MODE: mode})

    async def set_work_mode_white(self, dev_id: str) -> None:
        """``s0`` — convenience → ``set_work_mode("white")``."""
        await self.set_work_mode(dev_id, "white")

    async def set_real_brightness(self, dev_id: str, brightness: int) -> None:
        """``h0`` — ``{"22": int}``; the app logs a 10-1000 range hint."""
        await self.send_device_command(dev_id, {_DP_BRIGHTNESS: int(brightness)})

    # -- notification switch ------------------------------------------------------------

    async def set_notification_switch(self, dev_id: str, dp_id: str, enabled: bool) -> None:
        """``d0`` — ``{dp: bool}`` for a caller-chosen notification DP."""
        await self.send_device_command(dev_id, {str(dp_id): enabled})

    # -- raw schedule payloads -----------------------------------------------------------

    async def set_do_not_disturb_schedules_raw(self, dev_id: str, data: bytes) -> None:
        """``U`` — ``{"10": hex}``; len must be 1 or a multiple of 6, ≤300."""
        data = bytes(data)
        if len(data) == 0 or (len(data) != 1 and len(data) % 6 != 0):
            raise ValueError("DP167数据长度必须是1字节（空列表）或6的倍数")
        if len(data) > 300:
            raise ValueError("DP167数据长度不能超过300字节")
        await self.send_device_command(dev_id, {_DP_DND_SCHEDULES: _hex_encode(data)})

    async def set_scheduled_clean_raw(self, dev_id: str, data: bytes) -> None:
        """``m0`` — ``{"14": hex}``; len must be 1 or a multiple of 4, ≤200."""
        data = bytes(data)
        if len(data) == 0 or (len(data) != 1 and len(data) % 4 != 0):
            raise ValueError("DP104数据长度必须是1字节（空列表）或4的倍数")
        if len(data) > 200:
            raise ValueError("DP104数据长度不能超过200字节")
        await self.send_device_command(dev_id, {_DP_SCHEDULED_CLEAN: _hex_encode(data)})

    async def set_key_settings(self, dev_id: str, data: bytes) -> None:
        """``Z`` — ``{"105": hex}``."""
        await self.send_device_command(dev_id, {_DP_KEY_SETTINGS: _hex_encode(bytes(data))})

    # -- DP104 toggle wrappers -----------------------------------------------------------

    async def set_bin_full_detection(self, dev_id: str, enabled: bool) -> None:
        """``N`` — dustbin toggle bit 1."""
        await self.update_dustbin_settings_toggle(dev_id, _D104_BIN_FULL_DETECTION, enabled)

    async def set_allow_overfill(self, dev_id: str, enabled: bool) -> None:
        """``J`` — dustbin toggle bit 2."""
        await self.update_dustbin_settings_toggle(dev_id, _D104_ALLOW_OVERFILL, enabled)

    async def set_keep_upright(self, dev_id: str, enabled: bool) -> None:
        """``Y`` — dustbin toggle bit 4."""
        await self.update_dustbin_settings_toggle(dev_id, _D104_KEEP_UPRIGHT, enabled)

    async def set_dump_override(self, dev_id: str, enabled: bool) -> None:
        """``V`` — dustbin toggle bit 8."""
        await self.update_dustbin_settings_toggle(dev_id, _D104_DUMP_OVERRIDE, enabled)

    async def set_block_on_full(self, dev_id: str, enabled: bool) -> None:
        """``O`` — dustbin toggle bit 16."""
        await self.update_dustbin_settings_toggle(dev_id, _D104_BLOCK_ON_FULL, enabled)

    # -- DP102 toggle wrappers -----------------------------------------------------------

    async def set_anti_interference(self, dev_id: str, enabled: bool) -> None:
        """``K`` — system-settings toggle byte 12."""
        await self.update_system_settings_toggle(dev_id, _D102_IDX_ANTI_INTERFERENCE, enabled)

    async def set_status_light(self, dev_id: str, enabled: bool) -> None:
        """``o0`` — byte 20."""
        await self.update_system_settings_toggle(dev_id, _D102_IDX_STATUS_LIGHT, enabled)

    async def set_buzzer(self, dev_id: str, enabled: bool) -> None:
        """``P`` — byte 21."""
        await self.update_system_settings_toggle(dev_id, _D102_IDX_BUZZER, enabled)

    async def set_expert_mode(self, dev_id: str, enabled: bool) -> None:
        """``X`` — byte 23."""
        await self.update_system_settings_toggle(dev_id, _D102_IDX_EXPERT_MODE, enabled)

    async def set_auto_power_cycle(self, dev_id: str, enabled: bool) -> None:
        """``L`` — byte 24."""
        await self.update_system_settings_toggle(dev_id, _D102_IDX_AUTO_POWER_CYCLE, enabled)

    async def set_lower_speed(self, dev_id: str, enabled: bool) -> None:
        """``b0`` — byte 25."""
        await self.update_system_settings_toggle(dev_id, _D102_IDX_LOWER_SPEED, enabled)

    async def set_auto_self_check(self, dev_id: str, enabled: bool) -> None:
        """``M`` — byte 28."""
        await self.update_system_settings_toggle(dev_id, _D102_IDX_AUTO_SELF_CHECK, enabled)

    # -- DP102/DP104/DP103 field setters ---------------------------------------------------

    async def set_cycle_counts(self, dev_id: str, count: int) -> None:
        """``R`` — ``Dp104.bytesWithCycleCount``."""
        await self.update_dustbin_settings_payload(
            dev_id, lambda b: dp104_bytes_with_cycle_count(b, count)
        )

    async def set_dustbin_sensor_calibration(self, dev_id: str, level: int) -> None:
        """``W`` — ``Dp104.bytesWithCalibration``."""
        await self.update_dustbin_settings_payload(
            dev_id, lambda b: dp104_bytes_with_calibration(b, level)
        )

    async def set_delay_clean_time(self, dev_id: str, minutes: int) -> None:
        """``S`` — ``Dp102.bytesWithByte(13, minutes)``."""
        await self.update_system_settings_payload(
            dev_id,
            lambda b: dp102_bytes_with_byte(b, _D102_IDX_DELAY, minutes),
        )

    async def set_device_color(self, dev_id: str, label: str) -> None:
        """``T`` — ``Dp102.bytesWithDeviceColor``."""
        await self.update_system_settings_payload(
            dev_id, lambda b: dp102_bytes_with_device_color(b, label)
        )

    async def set_litter_spread_count(self, dev_id: str, count: int) -> None:
        """``a0`` — ``Dp102.bytesWithSmoothSpread``."""
        await self.update_system_settings_payload(
            dev_id, lambda b: dp102_bytes_with_smooth_spread(b, count)
        )

    async def set_radar_range(self, dev_id: str, range_: int) -> None:
        """``f0`` — ``Dp102.bytesWithByte(11, range)``."""
        await self.update_system_settings_payload(
            dev_id,
            lambda b: dp102_bytes_with_byte(b, _D102_IDX_RANGE, range_),
        )

    async def set_radar_sensitivity(self, dev_id: str, sensitivity: int) -> None:
        """``g0`` — ``Dp102.bytesWithByte(10, sensitivity)``."""
        await self.update_system_settings_payload(
            dev_id,
            lambda b: dp102_bytes_with_byte(b, _D102_IDX_SENSITIVE, sensitivity),
        )

    async def set_reshuffle_clumps_enabled(self, dev_id: str, enabled: bool) -> None:
        """``k0`` — ``Dp102.bytesWithReshuffleEnabled`` (byte 26 bit 7)."""
        await self.update_system_settings_payload(
            dev_id, lambda b: dp102_bytes_with_reshuffle_enabled(b, enabled)
        )

    async def set_reshuffle_oscillation(self, dev_id: str, label: str) -> None:
        """``l0`` — ``Dp102.bytesWithReshuffleOscillation``."""
        await self.update_system_settings_payload(
            dev_id, lambda b: dp102_bytes_with_reshuffle_oscillation(b, label)
        )

    async def set_sleep_time(self, dev_id: str, minutes: int) -> None:
        """``n0`` — ``Dp103.withHibernateDuration``; value clamped 0..200."""
        value = validate_value_range(int(minutes), 0, 200)
        await self.update_time_power_on_off_payload(
            dev_id, lambda b: dp103_with_hibernate_duration(b, value)
        )

    async def set_utc_setting(self, dev_id: str, offset_hours: int) -> None:
        """``p0`` — ``Dp102.bytesWithTimezone``."""
        await self.update_system_settings_payload(
            dev_id, lambda b: dp102_bytes_with_timezone(b, offset_hours)
        )

    # -- queries ---------------------------------------------------------------------------

    async def query_system_settings_raw(self, dev_id: str) -> bytes | None:
        """``A``/``b`` — DP102 raw payload bytes."""
        value = await self.query_device_dp(dev_id, _DP_SYSTEM_SETTINGS)
        return _payload_to_bytes(value)

    async def query_dustbin_settings_raw(self, dev_id: str) -> bytes | None:
        """``t`` — DP104 raw payload bytes."""
        value = await self.query_device_dp(dev_id, _DP_DUSTBIN_SETTINGS)
        return _payload_to_bytes(value)

    async def read_time_power_on_off_payload(self, dev_id: str) -> bytes | None:
        """``F`` — DP103 raw payload bytes."""
        value = await self.query_device_dp(dev_id, _DP_TIME_POWER)
        return _payload_to_bytes(value)

    async def query_key_settings(self, dev_id: str) -> Any:
        """``u`` — DP105 parsed ``KeySettings``."""
        value = await self.query_device_dp(dev_id, _DP_KEY_SETTINGS)
        return decode_dp105(value)

    async def query_do_not_disturb_schedules_raw(self, dev_id: str) -> list[int] | None:
        """``r`` — DP10 raw bytes as an int list."""
        value = await self.query_device_dp(dev_id, _DP_DND_SCHEDULES)
        raw = _payload_to_bytes(value)
        return list(raw) if raw is not None else None

    async def query_scheduled_clean_raw(self, dev_id: str) -> bytes | None:
        """``z``/``y0`` — DP14 raw bytes."""
        value = await self.query_device_dp(dev_id, _DP_SCHEDULED_CLEAN)
        return _payload_to_bytes(value)

    async def query_total_clean_count(self, dev_id: str) -> Any:
        """``B`` — DP152."""
        return await self.query_device_dp_value(dev_id, _DP_TOTAL_CLEAN)

    async def query_total_use_time(self, dev_id: str) -> Any:
        """``C`` — DP116."""
        return await self.query_device_dp_value(dev_id, _DP_TOTAL_USE)

    async def query_clean_count_after_full(self, dev_id: str) -> Any:
        """``l`` — DP146."""
        return await self.query_device_dp_value(dev_id, _DP_CLEAN_AFTER_FULL)

    async def query_daily_clean_count(self, dev_id: str) -> Any:
        """``m`` — DP7."""
        return await self.query_device_dp_value(dev_id, _DP_DAILY_CLEAN_COUNT)

    async def query_litter_capacity(self, dev_id: str) -> Any:
        """``v`` — DP121."""
        return await self.query_device_dp_value(dev_id, _DP_LITTER_CAPACITY)

    async def query_battery_level(self, dev_id: str) -> Any:
        """``i`` — DP101."""
        return await self.query_device_dp(dev_id, _DP_STATUS)

    async def query_bin_status(self, dev_id: str) -> Any:
        """``j`` — DP101."""
        return await self.query_device_dp(dev_id, _DP_STATUS)

    async def query_bin_status_report(self, dev_id: str) -> Any:
        """``k`` — DP101."""
        return await self.query_device_dp_value(dev_id, _DP_STATUS)

    async def query_device_status(self, dev_id: str) -> Any:
        """``q`` — DP101."""
        return await self.query_device_dp(dev_id, _DP_STATUS)

    async def query_machine_status(self, dev_id: str) -> Any:
        """``x`` — DP101."""
        return await self.query_device_dp_value(dev_id, _DP_STATUS)

    async def query_real_device_all_status(self, dev_id: str) -> dict[str, Any]:
        """``y`` — DP20 + DP21 + DP22."""
        return {
            "led_switch": await self.query_device_dp(dev_id, _DP_LED_SWITCH),
            "work_mode": await self.query_device_dp(dev_id, _DP_WORK_MODE),
            "brightness": await self.query_device_dp(dev_id, _DP_BRIGHTNESS),
        }

    async def query_weight_function_settings(self, dev_id: str) -> Any:
        """``D`` — DP102 → ``WeightFunctionSettings``."""
        settings = decode_dp102(await self.query_system_settings_raw(dev_id))
        return settings.weight_functions if settings is not None else None

    async def query_delay_clean_time(self, dev_id: str) -> int | None:
        """``n`` — DP102 → ``delay_minutes``."""
        settings = decode_dp102(await self.query_system_settings_raw(dev_id))
        return settings.delay_minutes if settings is not None else None

    async def query_litter_spread_count(self, dev_id: str) -> int | None:
        """``w`` — DP102 → ``smooth_spread_count``."""
        settings = decode_dp102(await self.query_system_settings_raw(dev_id))
        return settings.smooth_spread_count if settings is not None else None

    async def query_dustbin_sensor_calibration(self, dev_id: str) -> Any:
        """``s`` — DP104 → ``calibration``."""
        settings = decode_dp104(await self.query_dustbin_settings_raw(dev_id))
        return settings.calibration if settings is not None else None

    async def get_device_support_summary(self, dev_id: str) -> Any:
        """``d`` — the device support summary."""
        return self.manager.device_state(dev_id)

    def register_device_listener(self, dev_id: str, listener: Any) -> bool:
        """``H`` — register a ``DeviceListener`` on the manager."""
        return self.manager.register_listener(dev_id, listener)
