"""Static DeviceDpConstants reference recovered from the official app-v2 APK.

This module intentionally records every symbolic constant rather than treating old aliases as
current protocol truth. The dedicated firmware-4 model classes in :mod:`pypopur.dps` take
precedence when an old symbolic name collides with a current packed or notification datapoint.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

# DevicePairingViewModel's firmware-4 pairing filter accepts these product IDs. They identify an
# S7 product family, not an individual device, and are safe to use for local discovery filtering.
S7_PRODUCT_IDS: Final = frozenset({"takeu8kka3naw0rk", "63mvaowa9snym978"})


class DpAliasStatus(StrEnum):
    """How a DeviceDpConstants symbol relates to the app-v2 protocol."""

    CURRENT_PACKED = "current_packed"
    CURRENT_SCALAR = "current_scalar"
    CURRENT_ACTION = "current_action"
    CURRENT_NOTIFICATION = "current_notification"
    PACKED_SUBFIELD = "packed_subfield"
    LEGACY_OR_AMBIGUOUS = "legacy_or_ambiguous"


@dataclass(frozen=True, slots=True)
class DpAliasInfo:
    """One symbolic constant exactly as recovered from DeviceDpConstants."""

    symbol: str
    value: str
    status: DpAliasStatus


@dataclass(frozen=True, slots=True)
class ScalarDpMetadata:
    """Static unit/range evidence recovered for a scalar datapoint.

    ``None`` means the APK evidence inspected so far does not prove that property.
    """

    unit: str | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None


_ALIAS_TEXT: Final = """
DP_ANTI_INTERFERENCE 139
DP_AUTO_BURY_TIME 117
DP_AUTO_CLEAN_COUNT 12
DP_AUTO_CLEAN_COUNTDOWN 18
DP_AUTO_CLEAN_INTERVAL 18
DP_BATTERY_LEVEL 101
DP_BIN_FORCE_USE 136
DP_BIN_FULL_DETECTION 10
DP_BIN_FULL_DISABLE 13
DP_BIN_FULL_LEVEL 109
DP_BIN_OVERLOAD_USE 145
DP_BIN_PRODUCT_INFO 118
DP_BIN_STATUS 122
DP_BIN_STATUS_REPORT 122
DP_BRIGHT_VALUE 22
DP_BUTTON_LOCK 105
DP_CAT_PRESENCE 126
DP_CAT_TOILET_TIME 154
DP_CAT_WEIGHT 6
DP_CHUNKY_LITTER_LEVEL 123
DP_CLEANING_INTENSITY 102
DP_CLEANING_STATS 7
DP_CLEAN_CONTROL 1
DP_CLEAN_COUNT 152
DP_CLEAN_COUNT_AFTER_FULL 146
DP_CLEAN_DURATION 8
DP_CYCLE_COUNT_TYPE 103
DP_DAILY_CLEAN_COUNT 7
DP_DELAY_CLEAN_TIME 113
DP_DEVICE_IDENTITY 110
DP_DEVICE_LOCK 140
DP_DEVICE_NOTIFICATION_SWITCH 135
DP_DEVICE_RENAME 134
DP_DEVICE_RESET 23
DP_DEVICE_STATUS 101
DP_DISPLAY_TYPE 103
DP_DOG_PROOF_TIME 119
DP_DO_NOT_DISTURB_RAW 10
DP_DUSTBIN_SETTINGS 104
DP_FACTORY_RESET 23
DP_FAULT_ALARM 22
DP_FAULT_CODE 22
DP_FAULT_FREE_TIME 150
DP_FILTER_LIFE 150
DP_HUMIDITY 101
DP_KEEP_UPRIGHT 159
DP_KEY_SETTINGS 105
DP_LITTER_CAPACITY 121
DP_LITTER_SPREAD_COUNT __dp102_setting_smooth__
DP_MACHINE_CONTROL_STATUS 22
DP_MACHINE_STATUS 101
DP_MACHINE_WORK_MODE 109
DP_MANUAL_CLEAN 9
DP_MANUAL_CLEAN_COUNT 19
DP_MODE_AUTO_BURY_SWITCH 131
DP_MODE_CARE 138
DP_MODE_CHASE 153
DP_MODE_CHUNKY_LITTER_SWITCH 127
DP_MODE_COOLING 5
DP_MODE_DOG_PROOF_SWITCH 132
DP_MODE_LINGER 148
DP_MODE_LINGER_SWITCH 144
DP_MODE_NO_TROLL_SWITCH 124
DP_MODE_PARKOUR 137
DP_MODE_SENTINEL 141
DP_MODE_SOFT_STOOL_SWITCH 129
DP_MODE_SPECIAL_CLEAN 128
DP_MODE_ZOOMIE 137
DP_NOTIFICATION 21
DP_NOTIFICATION_AUTOMATIC_CLEANING 151
DP_NOTIFICATION_BIN_FULL 156
DP_NOTIFICATION_CLEANING_STARTED 149
DP_NOTIFICATION_MANUAL_CLEANING 153
DP_NOTIFICATION_PET_DETECTED 147
DP_NOTIFICATION_PET_FINISHED 148
DP_NOTIFICATION_SCHEDULED_CLEANING 155
DP_NOTIFICATION_SELF_CHECK 157
DP_NOTIFY_ALL 112
DP_NOTIFY_AUTOMATIC_CLEAN 120
DP_NOTIFY_BIN_FULL 123
DP_NOTIFY_CLEAN_PAUSED 118
DP_NOTIFY_CLEAN_RESUMED 119
DP_NOTIFY_CLEAN_STARTED 117
DP_NOTIFY_MANUAL_CLEAN 122
DP_NOTIFY_PET_DETECTED 113
DP_NOTIFY_PET_DONE_BUSINESS 114
DP_NOTIFY_PET_LEFT 115
DP_NOTIFY_SCHEDULE_CLEAN 121
DP_NOTIFY_SELF_CHECK_DONE 124
DP_NO_TROLL_DELAY 5
DP_OPERATION_MODE 102
DP_PAUSE 1
DP_PET_WEIGHT_TRACKING 17
DP_RADAR_RANGE 112
DP_RADAR_SENSITIVITY 130
DP_RECENT_ACTIVITY_STATUS 22
DP_RUNNING_STATUS 24
DP_SCHEDULED_CLEAN 14
DP_SCHEDULED_CLEAN_COUNT 15
DP_SCHEDULED_ENABLE 14
DP_SCHEDULED_POWER 135
DP_SCHEDULED_TIME 14
DP_SELF_CHECK_FAULT 125
DP_SELF_CHECK_PROGRESS 111
DP_SELF_CHECK_START 110
DP_SELF_CHECK_STATUS 106
DP_SENSOR_CALIBRATION 111
DP_SIFTER_CONTROL 108
DP_SIFTER_SPEC 120
DP_SIFTER_STATUS 144
DP_SOFT_STOOL_MODE 128
DP_SPECIAL_OPERATE 107
DP_SPIN_CONTROL 107
DP_START_SELF_CHECK 3
DP_START_WEIGHT_CALIBRATION 111
DP_START_WEIGHT_CALIBRATION_LEGACY 143
DP_SWITCH 31
DP_SWITCH_LED 20
DP_SYSTEM_SETTINGS 102
DP_TEMPERATURE 101
DP_TIME_POWER_ON_OFF 103
DP_TOTAL_CLEAN_COUNT 152
DP_TOTAL_USE_TIME 116
DP_TRASH_BIN_CONTROL 31
DP_UTC_SETTING 133
DP_VOICE_PROMPT 21
DP_WORK_MODE 21
""".strip()

_CURRENT_PACKED_SYMBOLS: Final = frozenset(
    {
        "DP_DUSTBIN_SETTINGS",
        "DP_KEY_SETTINGS",
        "DP_SELF_CHECK_FAULT",
        "DP_SELF_CHECK_STATUS",
        "DP_SYSTEM_SETTINGS",
        "DP_TIME_POWER_ON_OFF",
    }
)
_CURRENT_SCALAR_SYMBOLS: Final = frozenset(
    {
        "DP_CAT_TOILET_TIME",
        "DP_CAT_WEIGHT",
        "DP_CLEAN_DURATION",
        "DP_DAILY_CLEAN_COUNT",
        "DP_RECENT_ACTIVITY_STATUS",
        "DP_TOTAL_CLEAN_COUNT",
        "DP_TOTAL_USE_TIME",
    }
)
_CURRENT_ACTION_SYMBOLS: Final = frozenset(
    {
        "DP_CLEAN_CONTROL",
        "DP_PAUSE",
        "DP_START_SELF_CHECK",
    }
)
_CURRENT_NOTIFICATION_SYMBOLS: Final = frozenset(
    {
        "DP_NOTIFY_ALL",
        "DP_NOTIFY_AUTOMATIC_CLEAN",
        "DP_NOTIFY_BIN_FULL",
        "DP_NOTIFY_CLEAN_PAUSED",
        "DP_NOTIFY_CLEAN_RESUMED",
        "DP_NOTIFY_CLEAN_STARTED",
        "DP_NOTIFY_MANUAL_CLEAN",
        "DP_NOTIFY_PET_DETECTED",
        "DP_NOTIFY_PET_DONE_BUSINESS",
        "DP_NOTIFY_PET_LEFT",
        "DP_NOTIFY_SCHEDULE_CLEAN",
        "DP_NOTIFY_SELF_CHECK_DONE",
    }
)
_PACKED_SUBFIELD_SYMBOLS: Final = frozenset({"DP_LITTER_SPREAD_COUNT"})


def _status_for_symbol(symbol: str) -> DpAliasStatus:
    if symbol in _CURRENT_PACKED_SYMBOLS:
        return DpAliasStatus.CURRENT_PACKED
    if symbol in _CURRENT_SCALAR_SYMBOLS:
        return DpAliasStatus.CURRENT_SCALAR
    if symbol in _CURRENT_ACTION_SYMBOLS:
        return DpAliasStatus.CURRENT_ACTION
    if symbol in _CURRENT_NOTIFICATION_SYMBOLS:
        return DpAliasStatus.CURRENT_NOTIFICATION
    if symbol in _PACKED_SUBFIELD_SYMBOLS:
        return DpAliasStatus.PACKED_SUBFIELD
    return DpAliasStatus.LEGACY_OR_AMBIGUOUS


_aliases = tuple(
    DpAliasInfo(symbol, value, _status_for_symbol(symbol))
    for line in _ALIAS_TEXT.splitlines()
    for symbol, value in (line.split(maxsplit=1),)
)

DP_ALIAS_COUNT: Final = len(_aliases)
DP_DISTINCT_VALUE_COUNT: Final = len({item.value for item in _aliases})
DP_ALIASES: Final = MappingProxyType({item.symbol: item for item in _aliases})

_by_value: defaultdict[str, list[DpAliasInfo]] = defaultdict(list)
for _item in _aliases:
    _by_value[_item.value].append(_item)
DP_VALUE_ALIASES: Final = MappingProxyType(
    {value: tuple(items) for value, items in sorted(_by_value.items())}
)

_CURRENT_PACKED_VALUES: Final = frozenset({"101", "102", "103", "104", "105", "106", "125"})
_CURRENT_SCALAR_VALUES: Final = frozenset({"6", "7", "8", "22", "116", "152", "154"})
_CURRENT_ACTION_VALUES: Final = frozenset({"1", "3"})
_CURRENT_NOTIFICATION_VALUES: Final = frozenset(
    {"112", "113", "114", "115", "117", "118", "119", "120", "121", "122", "123", "124"}
)


def _status_for_value(value: str) -> DpAliasStatus:
    if value in _CURRENT_PACKED_VALUES:
        return DpAliasStatus.CURRENT_PACKED
    if value in _CURRENT_SCALAR_VALUES:
        return DpAliasStatus.CURRENT_SCALAR
    if value in _CURRENT_ACTION_VALUES:
        return DpAliasStatus.CURRENT_ACTION
    if value in _CURRENT_NOTIFICATION_VALUES:
        return DpAliasStatus.CURRENT_NOTIFICATION
    if value == "__dp102_setting_smooth__":
        return DpAliasStatus.PACKED_SUBFIELD
    return DpAliasStatus.LEGACY_OR_AMBIGUOUS


DP_VALUE_STATUS: Final = MappingProxyType(
    {value: _status_for_value(value) for value in DP_VALUE_ALIASES}
)

# ValueRange.ToiletTime explicitly declares UNIT="s", MIN=0, MAX=10000 for DP154.
# DP8/DP116 remain present here with no unit because their units are not yet proven by static
# evidence; keeping that uncertainty explicit prevents integrations from inventing a duration unit.
SCALAR_DP_METADATA: Final = MappingProxyType(
    {
        8: ScalarDpMetadata(),
        116: ScalarDpMetadata(),
        154: ScalarDpMetadata(unit="s", minimum=0, maximum=10_000),
    }
)


def aliases_for_value(value: int | str) -> tuple[DpAliasInfo, ...]:
    """Return every recovered symbolic alias for a raw DeviceDpConstants value."""

    return DP_VALUE_ALIASES.get(str(value), ())


def statuses_for_value(value: int | str) -> frozenset[DpAliasStatus]:
    """Return all app-v2 classifications represented by aliases sharing *value*."""

    return frozenset(item.status for item in aliases_for_value(value))


def wire_status(value: int | str) -> DpAliasStatus | None:
    """Return the app-v2 wire-level classification for a recovered constant value."""

    return DP_VALUE_STATUS.get(str(value))
