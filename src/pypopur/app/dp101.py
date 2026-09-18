"""Port of ``Dp101RunModeSet`` / ``Dp102SystemSettings`` / ``Dp125SelfCheckFault``.

The packed DP-101 report is five bytes: bin status, running status, machine
status, cat presence, countdown minutes.  Wire values keep the APK's spellings
(including ``bin_opned`` and ``auttomatic_clean_completed``).
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from numbers import Number
from typing import Any

from ..models import BinStatus, CatPresence, MachineStatus, RunningStatus

BIN_STATUS_VALUES = tuple(BinStatus)
RUNNING_STATUS_VALUES = tuple(RunningStatus)
MACHINE_STATUS_VALUES = tuple(MachineStatus)
CAT_PRESENCE_VALUES = tuple(CatPresence)

LEGACY_NORMALIZED_KEYS = frozenset({"24", "18"})
PENDING_CLEANING_ACTIONS = frozenset({"start_cleaning", "continue_cleaning", "pause_cleaning"})
COMPLETED_RUNNING_STATUSES = frozenset(
    {
        RunningStatus.MANUAL_CLEAN_COMPLETED,
        RunningStatus.SCHEDULED_CLEAN_COMPLETED,
        RunningStatus.AUTOMATIC_CLEAN_COMPLETED,
    }
)

_HEX_WS_RE = re.compile(r"\s+")
_INT_RE = re.compile(r"[+-]?\d+")


@dataclass(frozen=True, slots=True)
class ParsedReport:
    """``Dp101RunModeSet$ParsedReport`` — a decoded DP-101 report."""

    bin_status: str = BinStatus.NEAR_EMPTY
    running_status: str = RunningStatus.IDLE
    machine_status: str = MachineStatus.POWER_ON
    cat_presence: str = CatPresence.NO_CAT
    countdown_minutes: int = 0

    def copy(
        self,
        bin_status: str | None = None,
        running_status: str | None = None,
        machine_status: str | None = None,
        cat_presence: str | None = None,
        countdown_minutes: int | None = None,
    ) -> ParsedReport:
        return ParsedReport(
            self.bin_status if bin_status is None else bin_status,
            self.running_status if running_status is None else running_status,
            self.machine_status if machine_status is None else machine_status,
            self.cat_presence if cat_presence is None else cat_presence,
            self.countdown_minutes if countdown_minutes is None else countdown_minutes,
        )


DEFAULT_REPORT = ParsedReport()


def decode_to_bytes(value: Any) -> bytes | None:
    """``Dp102SystemSettings.decodeToBytes`` — byte[]/String/Collection decode.

    Strings try a ``[int, int, ...]`` array form first (non-integer tokens are
    skipped, an all-empty token list fails), then a whitespace-tolerant hex
    form.  Collections keep only numeric elements.  Anything else is None.
    """

    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        decoded = _decode_json_array_string(value)
        if decoded is None:
            return _decode_hex_string(value)
        return decoded
    if isinstance(value, Mapping):
        return None
    if isinstance(value, Iterable):
        ints = [v for v in (_int_value(item) for item in value) if v is not None]
        if not ints:
            return None
        return bytes(v & 0xFF for v in ints)
    return None


def _to_int_or_null(text: str) -> int | None:
    """Kotlin ``String.toIntOrNull`` — optional sign, digits, int32 range."""

    if not _INT_RE.fullmatch(text):
        return None
    value = int(text)
    return value if -(2**31) <= value <= 2**31 - 1 else None


def _int_value(item: Any) -> int | None:
    """Java ``Number.intValue()`` — non-Numbers skip, NaN→0, floats saturate."""

    if isinstance(item, bool) or not isinstance(item, Number):
        return None
    if isinstance(item, complex):
        return None
    if isinstance(item, float):
        if math.isnan(item):
            return 0
        if item >= 2**31 - 1:
            return 2**31 - 1
        if item <= -(2**31):
            return -(2**31)
    return int(item)


def _decode_json_array_string(text: str) -> bytes | None:
    trimmed = text.strip()
    if not (trimmed.startswith("[") and trimmed.endswith("]")):
        return None
    inner = trimmed[1:-1].strip()
    if not inner:
        return b""
    ints = [v for v in (_to_int_or_null(t.strip()) for t in inner.split(",")) if v is not None]
    if not ints:
        return None
    return bytes(v & 0xFF for v in ints)


def _decode_hex_string(text: str) -> bytes | None:
    compact = _HEX_WS_RE.sub("", text).lower()
    if not compact:
        return b""
    if len(compact) % 2:
        return None
    try:
        return bytes(int(compact[i : i + 2], 16) for i in range(0, len(compact), 2))
    except ValueError:
        return None


def _index_or(values: tuple, value: Any, fallback: int) -> int:
    try:
        return values.index(value)
    except ValueError:
        return fallback


def _value_at(values: tuple, index: int, fallback: str) -> str:
    return str(values[index]) if 0 <= index < len(values) else fallback


def parse_report(value: Any) -> ParsedReport | None:
    """``Dp101RunModeSet.parse`` — machine-status strings get a default report."""

    if isinstance(value, str) and value in {str(v) for v in MACHINE_STATUS_VALUES}:
        return DEFAULT_REPORT.copy(machine_status=value)
    raw = decode_to_bytes(value)
    if raw is None or len(raw) < 5:
        return None
    return ParsedReport(
        bin_status=_value_at(BIN_STATUS_VALUES, raw[0], BinStatus.NEAR_EMPTY),
        running_status=_value_at(RUNNING_STATUS_VALUES, raw[1], RunningStatus.IDLE),
        machine_status=_value_at(MACHINE_STATUS_VALUES, raw[2], MachineStatus.POWER_ON),
        cat_presence=_value_at(CAT_PRESENCE_VALUES, raw[3], CatPresence.NO_CAT),
        countdown_minutes=raw[4],
    )


def parse_from_dp_states(dps: Mapping[str, Any] | None) -> ParsedReport | None:
    """``Dp101RunModeSet.parseFromDpStates``."""

    if not dps:
        return None
    return parse_report(dps.get("101"))


def encode_report(report: ParsedReport) -> bytes:
    """``Dp101RunModeSet.encodeReport`` — five packed bytes."""

    return bytes(
        (
            _index_or(BIN_STATUS_VALUES, report.bin_status, 1) & 0xFF,
            _index_or(RUNNING_STATUS_VALUES, report.running_status, 0) & 0xFF,
            _index_or(MACHINE_STATUS_VALUES, report.machine_status, 0) & 0xFF,
            _index_or(CAT_PRESENCE_VALUES, report.cat_presence, 0) & 0xFF,
            max(0, min(report.countdown_minutes, 0xFF)),
        )
    )


def _field_from_dp_states(dps: Mapping[str, Any] | None, name: str) -> Any:
    report = parse_from_dp_states(dps)
    return getattr(report, name) if report is not None else None


def bin_status_from_dp_states(dps: Mapping[str, Any] | None) -> str | None:
    return _field_from_dp_states(dps, "bin_status")


def running_status_from_dp_states(dps: Mapping[str, Any] | None) -> str | None:
    return _field_from_dp_states(dps, "running_status")


def machine_status_from_dp_states(dps: Mapping[str, Any] | None) -> str | None:
    return _field_from_dp_states(dps, "machine_status")


def cat_presence_from_dp_states(dps: Mapping[str, Any] | None) -> str | None:
    return _field_from_dp_states(dps, "cat_presence")


def countdown_minutes_from_dp_states(dps: Mapping[str, Any] | None) -> int:
    report = parse_from_dp_states(dps)
    return report.countdown_minutes if report is not None else 0


def clean_control_from_dp_states(dps: Mapping[str, Any] | None) -> bool | None:
    """``Dp101RunModeSet.cleanControlFromDpStates`` — DP-1 truthiness."""

    if not dps:
        return None
    value = dps.get("1")
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, float):
        return int(value) != 0
    if isinstance(value, str):
        return value.lower() == "true" or value == "1"
    return None


def migrate_legacy_keys(dps: dict[str, Any]) -> None:
    """``Dp101RunModeSet.migrateLegacyKeys`` — legacy DPs 24/18/122/126 → 101."""

    if decode_to_bytes(dps.get("101")) is not None:
        strip_legacy_keys(dps)
        return
    running = dps.get("24")
    if not isinstance(running, str):
        running = None
    machine = dps.get("101")
    if not isinstance(machine, str):
        machine = None
    countdown = dps.get("18")
    if isinstance(countdown, bool) or not isinstance(countdown, int):
        countdown = None
    if (
        running is None
        and machine not in {str(v) for v in MACHINE_STATUS_VALUES}
        and countdown is None
    ):
        strip_legacy_keys(dps)
        return
    bin_status = dps.get("122")
    if not isinstance(bin_status, str):
        bin_status = DEFAULT_REPORT.bin_status
    if running is None:
        running = DEFAULT_REPORT.running_status
    if machine is None or machine not in {str(v) for v in MACHINE_STATUS_VALUES}:
        machine = DEFAULT_REPORT.machine_status
    cat = dps.get("126")
    if not isinstance(cat, str):
        cat = DEFAULT_REPORT.cat_presence
    report = ParsedReport(
        bin_status,
        running,
        machine,
        cat,
        countdown if countdown is not None else DEFAULT_REPORT.countdown_minutes,
    )
    dps["101"] = encode_report(report)
    strip_legacy_keys(dps)


def strip_legacy_keys(dps: dict[str, Any]) -> None:
    """``Dp101RunModeSet.stripLegacyKeys``."""

    for key in LEGACY_NORMALIZED_KEYS:
        dps.pop(key, None)


def _apply_derived_fields(dps: dict[str, Any], report: ParsedReport) -> None:
    dps["126"] = report.cat_presence


def _reconcile_clean_control(dps: dict[str, Any]) -> None:
    """``Dp101RunModeSet.reconcileCleanControl``."""

    control = clean_control_from_dp_states(dps)
    if control is None:
        return
    dps["1"] = control
    report = parse_from_dp_states(dps)
    if report is None:
        return
    running: str | None = None
    if control and report.running_status == RunningStatus.CLEAN_PAUSE:
        running = RunningStatus.CLEAN_START
    elif not control and report.running_status == RunningStatus.CLEAN_START:
        running = RunningStatus.CLEAN_PAUSE
    if running is None:
        return
    report = report.copy(running_status=running)
    dps["101"] = encode_report(report)
    _apply_derived_fields(dps, report)


def apply_to_map(dps: dict[str, Any]) -> dict[str, Any]:
    """``Dp101RunModeSet.applyToMap`` (in-place variant)."""

    migrate_legacy_keys(dps)
    report = parse_report(dps.get("101"))
    if report is None:
        strip_legacy_keys(dps)
        dps.pop("122", None)
        return dps
    if decode_to_bytes(dps.get("101")) is None:
        dps["101"] = encode_report(report)
    _apply_derived_fields(dps, report)
    strip_legacy_keys(dps)
    dps.pop("122", None)
    _reconcile_clean_control(dps)
    return dps


def normalized_copy(dps: Mapping[str, Any]) -> Mapping[str, Any]:
    """``Dp101RunModeSet.applyToMap`` (copying variant)."""

    if not dps:
        return dps
    out = dict(dps)
    apply_to_map(out)
    return out


def patch_dp_states(
    dps: Mapping[str, Any],
    running_status: str | None = None,
    machine_status: str | None = None,
    countdown_minutes: int | None = None,
    bin_status: str | None = None,
    cat_presence: str | None = None,
) -> dict[str, Any]:
    """``Dp101RunModeSet.patchDpStates``."""

    base = parse_from_dp_states(dps) or DEFAULT_REPORT
    patched = base.copy(
        bin_status=bin_status,
        running_status=running_status,
        machine_status=machine_status,
        cat_presence=cat_presence,
        countdown_minutes=countdown_minutes,
    )
    out = dict(dps)
    out["101"] = encode_report(patched)
    strip_legacy_keys(out)
    _apply_derived_fields(out, patched)
    return out


def merge_during_pending_cleaning_action(
    incoming: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    pending_action: str,
    expected_running_status: str,
) -> dict[str, Any]:
    """``Dp101RunModeSet.mergeDuringPendingCleaningAction``."""

    if not incoming:
        return dict(incoming)
    if pending_action not in PENDING_CLEANING_ACTIONS:
        return dict(incoming)
    incoming_running = running_status_from_dp_states(incoming)
    if incoming_running == expected_running_status:
        return dict(incoming)
    if (
        expected_running_status == RunningStatus.CLEAN_START
        and incoming_running == RunningStatus.CLEAN_PAUSE
    ):
        return dict(incoming)
    snapshot_report = parse_from_dp_states(snapshot)
    if pending_action in ("start_cleaning", "continue_cleaning"):
        control: bool | None = True
    elif pending_action == "pause_cleaning":
        control = False
    else:
        control = clean_control_from_dp_states(snapshot)
    machine = snapshot_report.machine_status if snapshot_report else None
    bin_status = snapshot_report.bin_status if snapshot_report else None
    cat = snapshot_report.cat_presence if snapshot_report else None
    countdown = (
        0
        if pending_action == "continue_cleaning"
        else (snapshot_report.countdown_minutes if snapshot_report else 0)
    )
    merged = patch_dp_states(
        incoming,
        running_status=expected_running_status,
        machine_status=machine,
        countdown_minutes=countdown,
        bin_status=bin_status,
        cat_presence=cat,
    )
    if control is not None:
        merged["1"] = control
    apply_to_map(merged)
    return merged


def parse_smooth_spread_count(value: Any) -> int | None:
    """``Dp102SystemSettings.parseSmoothSpreadCount`` — byte 14, clamped 2..7."""

    raw = decode_to_bytes(value)
    if raw is None or len(raw) <= 0x0E:
        return None
    return max(2, min(raw[0x0E], 7))


def spread_count_from_dp_states(dps: Mapping[str, Any] | None, default: int) -> int:
    """``Dp102SystemSettings.spreadCountFromDpStates``."""

    if dps is not None:
        cached = dps.get("__dp102_setting_smooth__")
        if isinstance(cached, bool) or not isinstance(cached, (int, float)):
            cached = None
        if cached is not None:
            return int(cached)
        parsed = parse_smooth_spread_count(dps.get("102"))
        if parsed is not None:
            return parsed
    return default


def parse_device_color_code(value: Any) -> int | None:
    """``Dp102SystemSettings.parseDeviceColorCode`` — byte 17, only 0/1."""

    raw = decode_to_bytes(value)
    if raw is None or len(raw) <= 0x11:
        return None
    code = raw[0x11]
    return code if code in (0, 1) else None


def device_color_label_from_code(code: int) -> str:
    """``Dp102SystemSettings.deviceColorLabelFromCode``."""

    return "black" if code == 1 else "white"


def device_color_code_from_label(label: str) -> int:
    """``Dp102SystemSettings.deviceColorCodeFromLabel``."""

    return int(label == "black")


def validate_smooth_spread(value: int) -> int:
    return max(2, min(value, 7))


def validate_delay_minutes(value: int) -> int:
    return max(1, min(value, 60))


def validate_timezone_offset(value: int) -> int:
    return max(-12, min(value, 12))


def validate_active_shield_range(value: int) -> int:
    return max(1, min(value, 5))


def validate_active_shield_sensitive(value: int) -> int:
    return max(1, min(value, 10))


_KOTLIN_LONG_RE = re.compile(r"[+-]?\d+")
_KOTLIN_HEX_RE = re.compile(r"[+-]?[0-9a-fA-F]+")


def _to_long_or_null(text: str, base: int) -> int | None:
    pattern = _KOTLIN_HEX_RE if base == 16 else _KOTLIN_LONG_RE
    if not pattern.fullmatch(text):
        return None
    try:
        return int(text, base)
    except ValueError:
        return None


def parse_fault_value(value: Any) -> int:
    """``Dp125SelfCheckFault.parseFaultValue`` — hex string first, then decimal.

    Booleans are not ``Number`` in Java and yield 0.
    """

    if isinstance(value, bool):
        return 0
    if isinstance(value, Number):
        return int(value)
    if isinstance(value, str):
        parsed = _to_long_or_null(value, 16)
        if parsed is not None:
            return parsed
        parsed = _to_long_or_null(value, 10)
        if parsed is not None:
            return parsed
    return 0


def fault_from_dp_states(dps: Mapping[str, Any] | None) -> int:
    """``Dp125SelfCheckFault.faultFromDpStates``."""

    if dps is None:
        return 0
    return parse_fault_value(dps.get("125"))
