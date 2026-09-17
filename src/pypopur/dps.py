"""Firmware-4 Popur S7 datapoint codecs recovered from the official app-v2 APK."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from enum import IntEnum
from typing import Any

from .codec import clamp, decode_raw_bytes, encode_hex, normalize_bytes, parse_bool
from .models import (
    ActiveShieldSettings,
    BinStatus,
    CalibrationLevel,
    CatPresence,
    DetailedNotificationExtSettings,
    DetailedNotificationSettings,
    DeviceSnapshot,
    DustbinSettings,
    DustbinSwitch,
    DustbinToggles,
    FaultItem,
    KeyGesture,
    KeySettings,
    MachineStatus,
    NotificationSettings,
    PanelToggles,
    RecentActivity,
    RunModeReport,
    RunningStatus,
    SelfCheckStatus,
    SpinSettings,
    SystemSettings,
    TimePowerSettings,
    TimerSlice,
    WeightFunctionSettings,
)


class DpId(IntEnum):
    """Current IDs used by the firmware-4/app-v2 control path.

    The APK also contains many legacy symbolic names that collide on the same
    numeric IDs.  Those aliases are intentionally not represented as separate
    wire datapoints here.
    """

    CLEAN_CONTROL = 1
    LEGACY_START_SELF_CHECK = 3
    CAT_WEIGHT = 6
    DAILY_CLEAN_COUNT = 7
    CLEAN_DURATION = 8
    DO_NOT_DISTURB = 10
    AUTOMATIC_CLEAN_COUNT = 12
    SCHEDULED_CLEAN = 14
    SCHEDULED_CLEAN_COUNT = 15
    MANUAL_CLEAN_COUNT = 19
    SCHEDULE_OR_LIGHT_SETTINGS = 20
    RECENT_ACTIVITY = 22
    FACTORY_RESET = 23
    TRASH_BIN_CONTROL = 31
    RUN_MODE_REPORT = 101
    SYSTEM_SETTINGS = 102
    TIME_POWER_ON_OFF = 103
    DUSTBIN_SETTINGS = 104
    KEY_SETTINGS = 105
    SELF_CHECK_STATUS = 106
    SPECIAL_OPERATE = 107
    SIFTER_CONTROL = 108
    MACHINE_CONTROL = 109
    SELF_CHECK_CONTROL = 110
    SCALE_RECALIBRATE = 111
    NOTIFY_ALL = 112
    NOTIFY_PET_DETECTED = 113
    NOTIFY_PET_DONE_BUSINESS = 114
    NOTIFY_PET_LEFT = 115
    TOTAL_USE_TIME = 116
    NOTIFY_CLEAN_STARTED = 117
    NOTIFY_CLEAN_PAUSED = 118
    NOTIFY_CLEAN_RESUMED = 119
    NOTIFY_AUTOMATIC_CLEAN = 120
    NOTIFY_SCHEDULE_CLEAN = 121
    NOTIFY_MANUAL_CLEAN = 122
    NOTIFY_BIN_FULL = 123
    NOTIFY_SELF_CHECK_DONE = 124
    SELF_CHECK_FAULT = 125
    CAT_PRESENCE = 126
    CLEAN_COUNT_AFTER_FULL = 146
    FAULT_FREE_TIME = 150
    UTC_SETTING = 133
    DEVICE_RENAME = 134
    TOTAL_CLEAN_COUNT = 152
    CAT_TOILET_TIME = 154


PACKED_DP_IDS = frozenset(
    {
        DpId.RUN_MODE_REPORT,
        DpId.SYSTEM_SETTINGS,
        DpId.TIME_POWER_ON_OFF,
        DpId.DUSTBIN_SETTINGS,
        DpId.KEY_SETTINGS,
        DpId.SELF_CHECK_STATUS,
        DpId.SELF_CHECK_FAULT,
    }
)

NOTIFICATION_DP_IDS = (112, 113, 114, 115, 117, 118, 119, 120, 121, 122, 123, 124)


_BIN_VALUES = tuple(BinStatus)
_RUNNING_VALUES = tuple(RunningStatus)
_MACHINE_VALUES = tuple(MachineStatus)
_CAT_VALUES = tuple(CatPresence)


def _enum_at(values: tuple[Any, ...], index: int, default: Any) -> Any:
    return values[index] if 0 <= index < len(values) else default


def _index_or(values: tuple[Any, ...], value: Any, default: int) -> int:
    try:
        return values.index(value)
    except ValueError:
        return default


def decode_dp101(value: Any) -> RunModeReport | None:
    """Decode the five-byte run-mode/status report (DP101)."""

    # The app tolerates one legacy representation where DP101 itself contains a
    # machine-status string.  Keep that read compatibility without treating it
    # as a current wire shape.
    if isinstance(value, str):
        try:
            status = MachineStatus(value)
        except ValueError:
            pass
        else:
            return RunModeReport(machine_status=status)

    raw = decode_raw_bytes(value, allow_base64=True)
    if raw is None or len(raw) < 5:
        return None
    return RunModeReport(
        bin_status=_enum_at(_BIN_VALUES, raw[0], BinStatus.NEAR_EMPTY),
        running_status=_enum_at(_RUNNING_VALUES, raw[1], RunningStatus.IDLE),
        machine_status=_enum_at(_MACHINE_VALUES, raw[2], MachineStatus.POWER_ON),
        cat_presence=_enum_at(_CAT_VALUES, raw[3], CatPresence.NO_CAT),
        countdown_minutes=raw[4],
    )


def decode_dp109_machine_status(value: Any) -> MachineStatus | None:
    """Decode the scalar machine-work-mode fallback reported by live S7 firmware."""

    if isinstance(value, MachineStatus):
        return value
    if not isinstance(value, str):
        return None
    try:
        return MachineStatus(value.strip().lower())
    except ValueError:
        return None


def decode_dp126_cat_presence(value: Any) -> CatPresence | None:
    """Decode the scalar cat-presence fallback used by the current app cache."""

    if isinstance(value, CatPresence):
        return value
    if isinstance(value, str):
        try:
            return CatPresence(value.strip().lower())
        except ValueError:
            pass
    index = _decode_int_scalar(value)
    if index is None or not 0 <= index < len(_CAT_VALUES):
        return None
    return _CAT_VALUES[index]


def encode_dp101(report: RunModeReport) -> str:
    """Encode DP101 to the hexadecimal RAW-DP value used by app-v2 writes."""

    raw = bytes(
        (
            _index_or(_BIN_VALUES, report.bin_status, 1),
            _index_or(_RUNNING_VALUES, report.running_status, 0),
            _index_or(_MACHINE_VALUES, report.machine_status, 0),
            _index_or(_CAT_VALUES, report.cat_presence, 0),
            clamp(report.countdown_minutes, 0, 255),
        )
    )
    return encode_hex(raw)


DP102_LENGTH = 29
DP102_RESHUFFLE_LABELS = ("2X", "3X", "4X", "5X")


def _valid_or(value: int, minimum: int, maximum: int, default: int) -> int:
    return value if minimum <= value <= maximum else default


def decode_dp102(value: Any) -> SystemSettings | None:
    """Decode all statically recoverable fields in the 29-byte DP102 payload."""

    decoded = decode_raw_bytes(value, allow_base64=True)
    if decoded is None:
        return None
    raw = normalize_bytes(decoded, DP102_LENGTH)

    sensitivity = _valid_or(raw[10], 1, 10, 5)
    radar_range = _valid_or(raw[11], 1, 5, 3)
    delay = _valid_or(raw[13], 1, 60, 5)
    smooth = clamp(raw[14], 2, 7)
    signed_timezone = raw[15] - 256 if raw[15] > 127 else raw[15]
    timezone = clamp(signed_timezone, -12, 12)
    color = "black" if raw[17] == 1 else "white"

    notify = raw[18]
    notify_ext = raw[27]
    weight = raw[22]
    reshuffle = raw[26]
    reshuffle_index = reshuffle & 0x7F
    reshuffle_label = (
        DP102_RESHUFFLE_LABELS[reshuffle_index]
        if reshuffle_index < len(DP102_RESHUFFLE_LABELS)
        else "2X"
    )

    return SystemSettings(
        active_shield=ActiveShieldSettings(bool(raw[12]), sensitivity, radar_range),
        delay_minutes=delay,
        smooth_spread_count=smooth,
        timezone_offset_hours=timezone,
        device_color=color,
        detailed_notifications=DetailedNotificationSettings(
            self_check_enabled=bool(notify & 0x01),
            bin_full_enabled=bool(notify & 0x02),
            manual_cleaning_enabled=bool(notify & 0x04),
            scheduled_cleaning_enabled=bool(notify & 0x08),
            automatic_cleaning_enabled=bool(notify & 0x10),
            cleaning_started_enabled=bool(notify & 0x20),
            pet_finished_enabled=bool(notify & 0x40),
            pet_detected_enabled=bool(notify & 0x80),
        ),
        notification_master_enabled=bool(raw[19]),
        panel=PanelToggles(bool(raw[20]), bool(raw[21]), bool(raw[23])),
        weight_functions=WeightFunctionSettings(
            automatic=bool(weight & 0x01),
            sentinel=bool(weight & 0x02),
            caring=bool(weight & 0x04),
            track_pet_data=bool(weight & 0x40),
        ),
        spin=SpinSettings(
            auto_power_cycle=bool(raw[24]),
            lower_speed=bool(raw[25]),
            reshuffle_enabled=bool(reshuffle & 0x80),
            reshuffle_oscillation=reshuffle_label,
            auto_self_check=bool(raw[28]),
        ),
        detailed_notifications_ext=DetailedNotificationExtSettings(
            new_firmware_enabled=bool(notify_ext & 0x01),
            pet_left_without_business_enabled=bool(notify_ext & 0x02),
            cleaning_paused_enabled=bool(notify_ext & 0x04),
            cleaning_resumed_enabled=bool(notify_ext & 0x08),
        ),
        raw=raw,
    )


def _notification_byte(settings: DetailedNotificationSettings) -> int:
    flags = (
        (0x01, settings.self_check_enabled),
        (0x02, settings.bin_full_enabled),
        (0x04, settings.manual_cleaning_enabled),
        (0x08, settings.scheduled_cleaning_enabled),
        (0x10, settings.automatic_cleaning_enabled),
        (0x20, settings.cleaning_started_enabled),
        (0x40, settings.pet_finished_enabled),
        (0x80, settings.pet_detected_enabled),
    )
    return sum(bit for bit, enabled in flags if enabled)


def _notification_ext_byte(settings: DetailedNotificationExtSettings) -> int:
    flags = (
        (0x01, settings.new_firmware_enabled),
        (0x02, settings.pet_left_without_business_enabled),
        (0x04, settings.cleaning_paused_enabled),
        (0x08, settings.cleaning_resumed_enabled),
    )
    return sum(bit for bit, enabled in flags if enabled)


def encode_dp102(settings: SystemSettings) -> str:
    """Encode DP102 using the app's read-modify-write behavior.

    A decoded model can contain fallback semantics for an unusual raw firmware byte. Fields
    unchanged from that decoded baseline are therefore left byte-for-byte intact instead of
    silently normalizing the payload while another setting is being changed.
    """

    out = bytearray(normalize_bytes(settings.raw, DP102_LENGTH))
    baseline = decode_dp102(bytes(out))
    assert baseline is not None

    if settings.active_shield.sensitivity != baseline.active_shield.sensitivity:
        out[10] = clamp(settings.active_shield.sensitivity, 1, 10)
    if settings.active_shield.range != baseline.active_shield.range:
        out[11] = clamp(settings.active_shield.range, 1, 5)
    if settings.active_shield.anti_interference != baseline.active_shield.anti_interference:
        out[12] = int(settings.active_shield.anti_interference)
    if settings.delay_minutes != baseline.delay_minutes:
        out[13] = clamp(settings.delay_minutes, 1, 60)
    if settings.smooth_spread_count != baseline.smooth_spread_count:
        out[14] = clamp(settings.smooth_spread_count, 2, 7)
    if settings.timezone_offset_hours != baseline.timezone_offset_hours:
        out[15] = clamp(settings.timezone_offset_hours, -12, 12) & 0xFF
    if settings.device_color != baseline.device_color:
        out[17] = 1 if settings.device_color.lower() == "black" else 0
    if settings.detailed_notifications != baseline.detailed_notifications:
        out[18] = _notification_byte(settings.detailed_notifications)
    if settings.notification_master_enabled != baseline.notification_master_enabled:
        out[19] = int(settings.notification_master_enabled)
    if settings.panel.status_light_enabled != baseline.panel.status_light_enabled:
        out[20] = int(settings.panel.status_light_enabled)
    if settings.panel.buzzer_enabled != baseline.panel.buzzer_enabled:
        out[21] = int(settings.panel.buzzer_enabled)
    if settings.weight_functions != baseline.weight_functions:
        weight = 0
        weight |= 0x01 if settings.weight_functions.automatic else 0
        weight |= 0x02 if settings.weight_functions.sentinel else 0
        weight |= 0x04 if settings.weight_functions.caring else 0
        weight |= 0x40 if settings.weight_functions.track_pet_data else 0
        # Preserve currently unknown weight-function bits.
        out[22] = (out[22] & ~(0x01 | 0x02 | 0x04 | 0x40)) | weight
    if settings.panel.pro_commands_enabled != baseline.panel.pro_commands_enabled:
        out[23] = int(settings.panel.pro_commands_enabled)
    if settings.spin.auto_power_cycle != baseline.spin.auto_power_cycle:
        out[24] = int(settings.spin.auto_power_cycle)
    if settings.spin.lower_speed != baseline.spin.lower_speed:
        out[25] = int(settings.spin.lower_speed)
    if settings.spin.reshuffle_enabled != baseline.spin.reshuffle_enabled:
        out[26] = (out[26] & 0x7F) | (0x80 if settings.spin.reshuffle_enabled else 0)
    if settings.spin.reshuffle_oscillation != baseline.spin.reshuffle_oscillation:
        try:
            oscillation = DP102_RESHUFFLE_LABELS.index(settings.spin.reshuffle_oscillation)
        except ValueError:
            oscillation = 0
        out[26] = (out[26] & 0x80) | oscillation
    if settings.detailed_notifications_ext != baseline.detailed_notifications_ext:
        out[27] = _notification_ext_byte(settings.detailed_notifications_ext)
    if settings.spin.auto_self_check != baseline.spin.auto_self_check:
        out[28] = int(settings.spin.auto_self_check)
    return encode_hex(bytes(out))


def patch_dp102(value: Any, **changes: Any) -> str:
    """Decode, dataclass-replace and re-encode DP102 with reserved bytes intact."""

    settings = decode_dp102(value) or SystemSettings()
    return encode_dp102(replace(settings, **changes))


DP103_LENGTH = 10


def decode_dp103(value: Any) -> TimePowerSettings | None:
    decoded = decode_raw_bytes(value, allow_base64=True)
    if decoded is None:
        return None
    raw = normalize_bytes(decoded, DP103_LENGTH)

    def timer(offset: int) -> TimerSlice:
        return TimerSlice(bool(raw[offset]), raw[offset + 1], raw[offset + 2], raw[offset + 3])

    return TimePowerSettings(
        power_on=timer(0),
        power_off=timer(4),
        hibernate_start=bool(raw[8]),
        hibernate_duration_minutes=raw[9],
    )


def encode_dp103(settings: TimePowerSettings) -> str:
    out = bytearray(DP103_LENGTH)

    def write(offset: int, timer: TimerSlice) -> None:
        out[offset] = int(timer.enabled)
        out[offset + 1] = timer.repeat_mask & 0xFF
        out[offset + 2] = clamp(timer.hour, 0, 23)
        out[offset + 3] = clamp(timer.minute, 0, 59)

    write(0, settings.power_on)
    write(4, settings.power_off)
    out[8] = int(settings.hibernate_start)
    out[9] = clamp(settings.hibernate_duration_minutes, 0, 255)
    return encode_hex(bytes(out))


RECURRENCE_BITS = ((1, "Mo"), (2, "Tu"), (4, "We"), (8, "Th"), (16, "Fr"), (32, "Sa"), (64, "Su"))


def recurrence_mask_to_text(mask: int) -> str:
    mask &= 0xFF
    if mask == 0:
        return "Once"
    if mask == 0x7F:
        return "Every day"
    values = [label for bit, label in RECURRENCE_BITS if mask & bit]
    return " | ".join(values) if values else "Once"


def recurrence_text_to_mask(text: str) -> int:
    if text.lower() == "once":
        return 0
    if text.lower() == "every day":
        return 0x7F
    lowered = text.lower()
    return sum(bit for bit, label in RECURRENCE_BITS if label.lower() in lowered)


DP104_DEFAULT = bytes((0x05, 0x01, 0x05))


def _normalize_dp104(value: Any) -> bytes:
    decoded = decode_raw_bytes(value, allow_base64=True)
    if decoded is None or not decoded:
        return DP104_DEFAULT
    if len(decoded) >= 3:
        return decoded[:3]
    out = bytearray(DP104_DEFAULT)
    out[: len(decoded)] = decoded
    return bytes(out)


def decode_dp104(value: Any) -> DustbinSettings | None:
    decoded = decode_raw_bytes(value, allow_base64=True)
    if decoded is None:
        return None
    raw = _normalize_dp104(decoded)
    switches = raw[0]
    calibration = CalibrationLevel(clamp(raw[1], 0, 3))
    cycle = raw[2] if 1 <= raw[2] <= 10 else 5
    return DustbinSettings(
        toggles=DustbinToggles(
            bin_full_detection=bool(switches & DustbinSwitch.BIN_FULL_DETECTION),
            allow_overfill=bool(switches & DustbinSwitch.ALLOW_OVERFILL),
            keep_upright=bool(switches & DustbinSwitch.KEEP_UPRIGHT),
            dump_override=bool(switches & DustbinSwitch.DUMP_OVERRIDE),
            block_on_full=bool(switches & DustbinSwitch.BLOCK_ON_FULL),
        ),
        calibration=calibration,
        cycle_count=cycle,
        raw=raw,
    )


def encode_dp104(settings: DustbinSettings) -> str:
    out = bytearray(_normalize_dp104(settings.raw))
    baseline = decode_dp104(bytes(out))
    assert baseline is not None

    if settings.toggles != baseline.toggles:
        known_mask = int(
            DustbinSwitch.BIN_FULL_DETECTION
            | DustbinSwitch.ALLOW_OVERFILL
            | DustbinSwitch.KEEP_UPRIGHT
            | DustbinSwitch.DUMP_OVERRIDE
            | DustbinSwitch.BLOCK_ON_FULL
        )
        switches = out[0] & ~known_mask
        switches |= (
            int(DustbinSwitch.BIN_FULL_DETECTION) if settings.toggles.bin_full_detection else 0
        )
        switches |= int(DustbinSwitch.ALLOW_OVERFILL) if settings.toggles.allow_overfill else 0
        switches |= int(DustbinSwitch.KEEP_UPRIGHT) if settings.toggles.keep_upright else 0
        switches |= int(DustbinSwitch.DUMP_OVERRIDE) if settings.toggles.dump_override else 0
        switches |= int(DustbinSwitch.BLOCK_ON_FULL) if settings.toggles.block_on_full else 0
        out[0] = switches
    if settings.calibration != baseline.calibration:
        out[1] = clamp(int(settings.calibration), 0, 3)
    if settings.cycle_count != baseline.cycle_count:
        out[2] = clamp(settings.cycle_count, 1, 10)
    return encode_hex(bytes(out))


DP105_DEFAULT = bytes((0, 1, 0, 1, 2, 1, 3))


def decode_dp105(value: Any) -> KeySettings | None:
    decoded = decode_raw_bytes(value, allow_base64=True)
    if decoded is None:
        return None
    # The app intentionally replaces an undersized payload with the complete
    # default rather than padding a partial value.
    raw = decoded[:7] if len(decoded) >= 7 else DP105_DEFAULT
    return KeySettings(
        lock_mask=raw[0] & 0x0F,
        press=KeyGesture(bool(raw[1]), raw[2]),
        hold_3s=KeyGesture(bool(raw[3]), raw[4]),
        hold_7s=KeyGesture(bool(raw[5]), raw[6]),
    )


def encode_dp105(settings: KeySettings) -> str:
    return encode_hex(
        bytes(
            (
                settings.lock_mask & 0x0F,
                int(settings.press.enabled),
                settings.press.function & 0xFF,
                int(settings.hold_3s.enabled),
                settings.hold_3s.function & 0xFF,
                int(settings.hold_7s.enabled),
                settings.hold_7s.function & 0xFF,
            )
        )
    )


def with_key_lock(settings: KeySettings, key_index: int, locked: bool) -> KeySettings:
    if not 0 <= key_index < 4:
        return settings
    bit = 1 << key_index
    mask = settings.lock_mask | bit if locked else settings.lock_mask & ~bit
    return replace(settings, lock_mask=mask & 0x0F)


def decode_dp106(value: Any) -> SelfCheckStatus | None:
    decoded = decode_raw_bytes(value, allow_base64=True)
    if decoded is None or not decoded:
        return None
    raw = normalize_bytes(decoded, 5)
    return SelfCheckStatus(progress=clamp(raw[0], 0, 100), raw=raw)


def encode_dp106(status: SelfCheckStatus) -> str:
    raw = bytearray(normalize_bytes(status.raw, 5))
    raw[0] = clamp(status.progress, 0, 100)
    return encode_hex(bytes(raw))


FAULT_ITEMS = tuple(
    FaultItem(
        mask=1 << index,
        label=f"Error code {chr(ord('A') + index)}",
        url=f"https://popur.com/pages/s7-error-code-{chr(ord('a') + index)}",
    )
    for index in range(26)
)


def decode_dp125_value(value: Any) -> int:
    """Decode DP125 exactly like the APK (strings are attempted as hex first)."""

    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16)
        except ValueError:
            return 0
    return 0


def decode_dp125(value: Any) -> tuple[FaultItem, ...]:
    fault_value = decode_dp125_value(value)
    return tuple(item for item in FAULT_ITEMS if fault_value & item.mask)


_ACTIVITY_NAMES: dict[str, RecentActivity] = {
    "idle": RecentActivity.IDLE,
    "cat_exist": RecentActivity.CAT_EXIST,
    "cat_left": RecentActivity.CAT_LEFT,
    "cat_done_business": RecentActivity.CAT_DONE_BUSINESS,
    "manual_clean_completed": RecentActivity.MANUAL_CLEAN_COMPLETED,
    "scheduled_clean_completed": RecentActivity.SCHEDULED_CLEAN_COMPLETED,
    "automatic_clean_completed": RecentActivity.AUTOMATIC_CLEAN_COMPLETED,
    "auttomatic_clean_completed": RecentActivity.AUTOMATIC_CLEAN_COMPLETED,
    "bin_full": RecentActivity.BIN_FULL,
    "bin_ful": RecentActivity.BIN_FULL,
    "self-check completed": RecentActivity.SELF_CHECK_COMPLETED,
    "self_check_completed": RecentActivity.SELF_CHECK_COMPLETED,
    "cleaning_started": RecentActivity.CLEANING_STARTED,
    "clean_start": RecentActivity.CLEANING_STARTED,
    "cleaning_paused": RecentActivity.CLEANING_PAUSED,
    "cleanning_paused": RecentActivity.CLEANING_PAUSED,
    "cleaning_resume": RecentActivity.CLEANING_RESUMED,
    "cleaning_resumed": RecentActivity.CLEANING_RESUMED,
}


def decode_dp22(value: Any) -> RecentActivity | None:
    if isinstance(value, RecentActivity):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        code = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            code = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return _ACTIVITY_NAMES.get(text.lower())
    else:
        return None
    try:
        return RecentActivity(code)
    except ValueError:
        return None


def decode_notification_settings(dps: Mapping[int | str, Any]) -> NotificationSettings:
    def get(dp: int) -> Any:
        return dps.get(dp, dps.get(str(dp)))  # type: ignore[arg-type]

    return NotificationSettings(
        master_enabled=parse_bool(get(112)),
        pet_detected_enabled=parse_bool(get(113)),
        pet_finished_enabled=parse_bool(get(114)),
        pet_left_without_business_enabled=parse_bool(get(115)),
        cleaning_started_enabled=parse_bool(get(117)),
        cleaning_paused_enabled=parse_bool(get(118)),
        cleaning_resumed_enabled=parse_bool(get(119)),
        automatic_cleaning_enabled=parse_bool(get(120)),
        scheduled_cleaning_enabled=parse_bool(get(121)),
        manual_cleaning_enabled=parse_bool(get(122)),
        bin_full_enabled=parse_bool(get(123)),
        self_check_enabled=parse_bool(get(124)),
    )


def encode_notification_settings(settings: NotificationSettings) -> dict[int, bool]:
    return {
        112: settings.master_enabled,
        113: settings.pet_detected_enabled,
        114: settings.pet_finished_enabled,
        115: settings.pet_left_without_business_enabled,
        117: settings.cleaning_started_enabled,
        118: settings.cleaning_paused_enabled,
        119: settings.cleaning_resumed_enabled,
        120: settings.automatic_cleaning_enabled,
        121: settings.scheduled_cleaning_enabled,
        122: settings.manual_cleaning_enabled,
        123: settings.bin_full_enabled,
        124: settings.self_check_enabled,
    }


def normalize_dp_mapping(dps: Mapping[int | str, Any]) -> dict[int, Any]:
    """Normalize numeric-string DP keys produced by Tuya libraries to integers."""

    normalized: dict[int, Any] = {}
    for key, value in dps.items():
        try:
            numeric = int(key)
        except (TypeError, ValueError):
            continue
        normalized[numeric] = value
    return normalized


def _decode_numeric_scalar(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return None
    return None


def _decode_int_scalar(value: Any) -> int | None:
    numeric = _decode_numeric_scalar(value)
    if numeric is None:
        return None
    if isinstance(numeric, float) and not numeric.is_integer():
        return None
    return int(numeric)


def decode_snapshot(dps: Mapping[int | str, Any]) -> DeviceSnapshot:
    """Decode all known firmware-4 structures from a raw DPS mapping."""

    raw = normalize_dp_mapping(dps)
    fault_value = decode_dp125_value(raw.get(125))
    run_mode = decode_dp101(raw.get(101))
    return DeviceSnapshot(
        raw_dps=raw,
        run_mode=run_mode,
        machine_status=(
            run_mode.machine_status
            if run_mode is not None
            else decode_dp109_machine_status(raw.get(109))
        ),
        cat_presence=(
            run_mode.cat_presence
            if run_mode is not None
            else decode_dp126_cat_presence(raw.get(126))
        ),
        system_settings=decode_dp102(raw.get(102)),
        time_power=decode_dp103(raw.get(103)),
        dustbin=decode_dp104(raw.get(104)),
        key_settings=decode_dp105(raw.get(105)),
        self_check=decode_dp106(raw.get(106)),
        self_check_fault_value=fault_value,
        self_check_faults=decode_dp125(fault_value),
        recent_activity=decode_dp22(raw.get(22)),
        notifications=decode_notification_settings(raw),
        cat_weight=_decode_numeric_scalar(raw.get(6)),
        daily_clean_count=_decode_int_scalar(raw.get(7)),
        clean_duration=_decode_int_scalar(raw.get(8)),
        automatic_clean_count=_decode_int_scalar(raw.get(12)),
        scheduled_clean_count=_decode_int_scalar(raw.get(15)),
        manual_clean_count=_decode_int_scalar(raw.get(19)),
        total_use_time=_decode_int_scalar(raw.get(116)),
        clean_count_after_full=_decode_int_scalar(raw.get(146)),
        fault_free_time=_decode_int_scalar(raw.get(150)),
        total_clean_count=_decode_int_scalar(raw.get(152)),
        cat_toilet_time=_decode_int_scalar(raw.get(154)),
    )
