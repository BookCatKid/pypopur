"""Port of ``DeviceDpStateResolver`` and the ``DeviceRepository.S`` derive."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from ..models import BinStatus as WireBinStatus
from ..models import MachineStatus, RunningStatus
from .dp101 import (
    COMPLETED_RUNNING_STATUSES,
    apply_to_map,
    bin_status_from_dp_states,
    countdown_minutes_from_dp_states,
    fault_from_dp_states,
    machine_status_from_dp_states,
    parse_from_dp_states,
    running_status_from_dp_states,
)

CRITICAL_DP_KEYS = frozenset(
    {"125", "101", "1", "126", "102", "__dp102_setting_smooth__", "106", "110"}
)


class DeviceStatus(StrEnum):
    """``com.popur.android.core.model.data.DeviceStatus``."""

    READY = "ready"
    OFFLINE = "offline"
    ERROR = "error"
    SELF_CHECKING = "self_checking"
    DO_NOT_DISTURB = "do_not_disturb"
    CLEANING_IN_PROGRESS = "cleaning_in_progress"
    CLEANING_PAUSED = "cleaning_paused"
    CLEANING_TO_START = "cleaning_to_start"
    HIBERNATING = "hibernating"
    POWERED_OFF = "powered_off"
    PLEASE_EMPTY_BIN = "please_empty_bin"


class DeviceBinStatus(StrEnum):
    """``com.popur.android.core.model.data.BinStatus`` (app model, not wire)."""

    NEARLY_EMPTY = "nearly_empty"
    HALF_EMPTY = "half_empty"
    ALMOST_FULL = "almost_full"
    BIN_FULL = "bin_full"
    BIN_UNFOUND = "bin_unfound"
    BIN_OPENED = "bin_opened"


_BIN_LABEL_MAP = {
    str(WireBinStatus.BIN_FULL): DeviceBinStatus.BIN_FULL,
    str(WireBinStatus.ALMOST_FULL): DeviceBinStatus.ALMOST_FULL,
    str(WireBinStatus.NEAR_EMPTY): DeviceBinStatus.NEARLY_EMPTY,
    str(WireBinStatus.HALF_EMPTY): DeviceBinStatus.HALF_EMPTY,
    str(WireBinStatus.UNFOUND): DeviceBinStatus.BIN_UNFOUND,
    str(WireBinStatus.BIN_OPENED): DeviceBinStatus.BIN_OPENED,
}


def merge_fill_missing(
    cloud_dps: Mapping[str, Any], cached_dps: Mapping[str, Any]
) -> Mapping[str, Any]:
    """``DeviceDpStateResolver.a`` — cloud wins; cached fills missing keys.

    An empty cloud map returns the cached map unnormalized, exactly like smali.
    """

    if not cloud_dps:
        return cached_dps
    merged = dict(cloud_dps)
    for key, value in cached_dps.items():
        if key not in merged:
            merged[key] = value
    apply_to_map(merged)
    return merged


def merge_with_timestamps(
    cloud_dps: Mapping[str, Any],
    cached_dps: Mapping[str, Any],
    cloud_timestamp: int | None,
    cached_timestamp: int | None,
) -> Mapping[str, Any]:
    """``DeviceDpStateResolver.b`` — cached base, cloud overlay, critical keys.

    The smali's timestamp/countdown/completed-status branch decides whether to
    pre-copy ``101``/``1``/``126`` before the critical-key loop — both outcomes
    converge because those keys are already in the critical set.  The branch is
    kept for auditability.
    """

    if not cached_dps:
        return cloud_dps
    if not cloud_dps:
        return cached_dps
    merged = dict(cached_dps)
    merged.update(cloud_dps)

    trust_cloud_101 = (
        cloud_timestamp is not None
        and cached_timestamp is not None
        and cloud_timestamp > cached_timestamp
    )
    if not trust_cloud_101:
        cloud_report = parse_from_dp_states(cloud_dps)
        cached_report = parse_from_dp_states(cached_dps)
        if (
            cloud_report is None
            or cached_report is None
            or cached_report.countdown_minutes > 0
            and cloud_report.countdown_minutes == 0
            or (
                cloud_report.running_status in COMPLETED_RUNNING_STATUSES
                and cached_report.countdown_minutes > 0
            )
        ):
            trust_cloud_101 = True
    if trust_cloud_101:
        for key in ("101", "1", "126"):
            value = cloud_dps.get(key)
            if value is not None:
                merged[key] = value
    for key in CRITICAL_DP_KEYS:
        value = cloud_dps.get(key)
        if value is not None:
            merged[key] = value
    apply_to_map(merged)
    return merged


def derive_status(
    dps: Mapping[str, Any] | None, online: bool
) -> tuple[DeviceStatus, DeviceBinStatus]:
    """``DeviceRepository.S`` — (DeviceStatus, BinStatus) from merged DP state."""

    if dps is None or not online:
        return DeviceStatus.OFFLINE, DeviceBinStatus.NEARLY_EMPTY
    try:
        running = running_status_from_dp_states(dps)
        machine = machine_status_from_dp_states(dps)
        countdown = countdown_minutes_from_dp_states(dps)
        bin_status = bin_status_from_dp_states(dps)
        fault = fault_from_dp_states(dps)
        if fault != 0:
            status = DeviceStatus.ERROR
        elif machine == "self_checking":
            status = DeviceStatus.SELF_CHECKING
        elif machine == MachineStatus.DISTURB_MODE:
            status = DeviceStatus.DO_NOT_DISTURB
        elif running == RunningStatus.CLEAN_START:
            status = DeviceStatus.CLEANING_IN_PROGRESS
        elif running == RunningStatus.CLEAN_PAUSE:
            status = DeviceStatus.CLEANING_PAUSED
        elif countdown > 0:
            status = DeviceStatus.CLEANING_TO_START
        elif machine == MachineStatus.HIBERNATING:
            status = DeviceStatus.HIBERNATING
        elif machine == MachineStatus.POWER_OFF:
            status = DeviceStatus.POWERED_OFF
        elif bin_status == WireBinStatus.BIN_FULL:
            status = DeviceStatus.PLEASE_EMPTY_BIN
        else:
            status = DeviceStatus.READY
        bin_model = _BIN_LABEL_MAP.get(bin_status, DeviceBinStatus.NEARLY_EMPTY)
        return status, bin_model
    except Exception:
        return DeviceStatus.READY, DeviceBinStatus.NEARLY_EMPTY
