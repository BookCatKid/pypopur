"""Port of ``DeviceRepository`` DP-merge and cleaning-progress paths.

``P`` is the post-write critical-DP hook invoked after a successful
``sendDeviceCommand``; ``D0`` is ``updateDeviceDps`` — the merge that feeds the
``u``/``v`` dp-state flow and the device record; ``v0`` is
``syncCleaningProgressFromDp``, invoked with the merged map at the end of
``D0``; ``q0`` updates the three cleaning maps/flows and persists through
``k0``/``d0``; ``c0`` removes progress state; ``l0``/``e0`` persist/remove the
cleaning start time.
"""

from __future__ import annotations

import inspect
import json
import logging
import math
import time
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field, replace
from typing import Any

from .dp101 import (
    apply_to_map,
    device_color_label_from_code,
    parse_device_color_code,
    parse_smooth_spread_count,
    running_status_from_dp_states,
    spread_count_from_dp_states,
)
from .dp_string import (
    JsonNull,
    _java_double,
    _java_parse_long,
    parse_org_json_object,
)
from .resolver import CRITICAL_DP_KEYS, DeviceBinStatus, DeviceStatus, derive_status

_LOG = logging.getLogger("pypopur.app.repository")

# Kotlin ``setOf`` preserves declaration order — the log/force-copy loops iterate
# in this order.
CRITICAL_DP_ORDER = (
    "1",
    "126",
    "102",
    "__dp102_setting_smooth__",
    "106",
    "110",
    "125",
    "101",
)

_DP102_KEY = "102"
_SMOOTH_KEY = "__dp102_setting_smooth__"

_START_TIME_KEY_PREFIX = "cleaning_start_time_"
_PROGRESS_STATE_KEY_PREFIX = "cleaning_progress_state_"

# ``v0`` treats these running-status values as "done" — note the app's own
# ``auttomatic`` typo is part of the wire contract.
_CLEAN_DONE_STATUSES = frozenset(
    {
        "manual_clean_completed",
        "scheduled_clean_completed",
        "auttomatic_clean_completed",
        "device_power_on",
    }
)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _java_equal(old: Any, new: Any) -> bool:
    """``Intrinsics.areEqual`` — Java ``byte[]`` equality is identity, not value."""

    if isinstance(old, (bytes, bytearray)) or isinstance(new, (bytes, bytearray)):
        return old is new
    return old == new


@dataclass(frozen=True, slots=True)
class RepositoryDevice:
    """Lean stand-in for the app's ``Device`` — only fields ``D0`` touches."""

    device_id: str
    online: bool = False
    dps_data: Mapping[str, Any] = field(default_factory=dict)
    status: DeviceStatus = DeviceStatus.READY
    bin_status: DeviceBinStatus = DeviceBinStatus.NEARLY_EMPTY
    last_update_ms: int = 0
    dp3_value: int | None = None

    def copy(self, **changes: Any) -> RepositoryDevice:
        state = {
            "device_id": self.device_id,
            "online": self.online,
            "dps_data": self.dps_data,
            "status": self.status,
            "bin_status": self.bin_status,
            "last_update_ms": self.last_update_ms,
            "dp3_value": self.dp3_value,
        }
        state.update(changes)
        return RepositoryDevice(**state)


async def _maybe_await(result: Any) -> Any:
    if inspect.isawaitable(result):
        return await result
    return result


def _java_narrow(value: float, bits: int) -> int:
    """Java ``(int)d``/``(long)d`` narrowing — saturate, NaN→0."""

    hi = 2 ** (bits - 1) - 1
    lo = -(2 ** (bits - 1))
    if math.isnan(value):
        return 0
    if value > hi:
        return hi
    if value < lo:
        return lo
    return int(value)


def _opt_long(obj: Mapping[str, Any], key: str, default: int = 0) -> int:
    """``JSONObject.optLong`` — ``JSON.toLong`` coercion with fallback."""

    value = obj.get(key)
    if value is None or isinstance(value, (JsonNull, bool)):
        return default
    if isinstance(value, int):
        return (value + 2**63) % 2**64 - 2**63
    if isinstance(value, float):
        return _java_narrow(value, 64)
    if isinstance(value, str):
        parsed = _java_parse_long(value, 10)
        if parsed is not None:
            return parsed
        double = _java_double(value)
        if double is not None:
            return _java_narrow(double, 64)
    return default


def _opt_int(obj: Mapping[str, Any], key: str, default: int = 0) -> int:
    """``JSONObject.optInt`` — ``JSON.toInteger`` coercion with fallback."""

    value = obj.get(key)
    if value is None or isinstance(value, (JsonNull, bool)):
        return default
    if isinstance(value, int):
        return (value + 2**31) % 2**32 - 2**31
    if isinstance(value, float):
        return _java_narrow(value, 32)
    if isinstance(value, str):
        parsed = _java_parse_long(value, 10)
        if parsed is not None and -(2**31) <= parsed <= 2**31 - 1:
            return parsed
        double = _java_double(value)
        if double is not None:
            return _java_narrow(double, 32)
    return default


def _opt_double(obj: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    """``JSONObject.optDouble`` — ``JSON.toDouble`` coercion with fallback."""

    value = obj.get(key)
    if value is None or isinstance(value, (JsonNull, bool)):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        double = _java_double(value)
        if double is not None:
            return double
    return default


@dataclass(frozen=True, slots=True)
class CleaningProgressMetadata:
    """``CleaningProgressMetadata`` — Kotlin data class field order."""

    started_at: int | None = None
    last_paused_at: int | None = None
    elapsed_before_pause_seconds: float = 0.0
    progress_percent: float = 0.0
    expected_duration_seconds: int = 0
    completed_at: int | None = None
    last_updated_at: int = 0

    def is_active(self) -> bool:
        """``isActive`` — ``startedAt != null && completedAt == null``."""

        return self.started_at is not None and self.completed_at is None

    def is_completed(self) -> bool:
        return self.completed_at is not None

    def is_paused(self) -> bool:
        """``isPaused`` — startedAt cleared, paused stamp set, not completed."""

        return (
            self.started_at is None
            and self.last_paused_at is not None
            and self.completed_at is None
        )

    def is_empty(self) -> bool:
        """``DeviceRepository.M`` — ``lastUpdatedAt`` is not part of the check.

        ``cmpg``/``cmpl`` map ``NaN`` to non-zero, so NaN floats are not empty.
        """

        return (
            self.started_at is None
            and self.last_paused_at is None
            and self.elapsed_before_pause_seconds <= 0
            and self.progress_percent <= 0
            and self.expected_duration_seconds == 0
            and self.completed_at is None
        )


EMPTY_CLEANING_PROGRESS = CleaningProgressMetadata()


def _meta_equal(a: CleaningProgressMetadata, b: CleaningProgressMetadata) -> bool:
    """``Intrinsics.areEqual`` — boxed ``Float.equals`` treats ``NaN == NaN``."""

    return (
        a.started_at == b.started_at
        and a.last_paused_at == b.last_paused_at
        and _float_equal(a.elapsed_before_pause_seconds, b.elapsed_before_pause_seconds)
        and _float_equal(a.progress_percent, b.progress_percent)
        and a.expected_duration_seconds == b.expected_duration_seconds
        and a.completed_at == b.completed_at
        and a.last_updated_at == b.last_updated_at
    )


def _float_equal(a: float, b: float) -> bool:
    return a == b or (math.isnan(a) and math.isnan(b))


def _progress_percent(elapsed: float, expected: int) -> float:
    """``(elapsed / expected) * 100`` coerced to ``0..100`` with Java float rules."""

    if expected == 0:
        if elapsed > 0:
            value = math.inf
        elif elapsed < 0:
            value = -math.inf
        else:
            value = math.nan
    else:
        value = elapsed / expected * 100.0
    if math.isnan(value):
        return value
    return min(max(value, 0.0), 100.0)


def cleaning_progress_to_json(meta: CleaningProgressMetadata) -> str:
    """``k0``'s ``JSONObject`` — nullable Longs are omitted, never ``null``."""

    obj: dict[str, Any] = {}
    if meta.started_at is not None:
        obj["startedAt"] = meta.started_at
    if meta.last_paused_at is not None:
        obj["lastPausedAt"] = meta.last_paused_at
    obj["elapsedBeforePauseSeconds"] = meta.elapsed_before_pause_seconds
    obj["progressPercent"] = meta.progress_percent
    obj["expectedDurationSeconds"] = meta.expected_duration_seconds
    if meta.completed_at is not None:
        obj["completedAt"] = meta.completed_at
    obj["lastUpdatedAt"] = meta.last_updated_at
    return json.dumps(obj, separators=(",", ":"))


def cleaning_progress_from_json(text: str) -> CleaningProgressMetadata | None:
    """``Q`` — ``org.json`` parse of the persisted blob; ``None`` on failure."""

    try:
        obj = parse_org_json_object(text)
        return CleaningProgressMetadata(
            started_at=_opt_long(obj, "startedAt") if "startedAt" in obj else None,
            last_paused_at=(_opt_long(obj, "lastPausedAt") if "lastPausedAt" in obj else None),
            elapsed_before_pause_seconds=_opt_double(obj, "elapsedBeforePauseSeconds"),
            progress_percent=_opt_double(obj, "progressPercent"),
            expected_duration_seconds=_opt_int(obj, "expectedDurationSeconds"),
            completed_at=_opt_long(obj, "completedAt") if "completedAt" in obj else None,
            last_updated_at=_opt_long(obj, "lastUpdatedAt"),
        )
    except Exception:
        _LOG.exception("Repository: 解析清洁进度元数据失败")
        return None


class DeviceRepository:
    """``DeviceRepository`` — dp-state cache + device store seams.

    Seams (all optional callables, sync or async):

    - ``device_lookup(dev_id) -> RepositoryDevice | None`` — ``y``
    - ``persist_color(dev_id, label)`` — ``s0``
    - ``persist_dps(dev_id, merged)`` — ``m0`` (invoked when merged non-empty)
    - ``load_persisted_dps(dev_id)`` — ``f0`` (invoked when merged is empty)
    - ``store_device(device)`` — ``C0``
    - ``datastore`` — the ``DataStore`` seam: a mutable mapping that
      ``l0``/``e0``/``k0``/``d0`` read and write under
      ``cleaning_start_time_<devId>`` / ``cleaning_progress_state_<devId>``.
    """

    def __init__(
        self,
        device_lookup: Callable[[str], RepositoryDevice | None] | None = None,
        persist_color: Callable[[str, str], Any] | None = None,
        persist_dps: Callable[[str, Mapping[str, Any]], Any] | None = None,
        load_persisted_dps: Callable[[str], Any] | None = None,
        store_device: Callable[[RepositoryDevice], Any] | None = None,
        datastore: MutableMapping[str, Any] | None = None,
    ):
        self._device_lookup = device_lookup or (lambda dev_id: None)
        self._persist_color = persist_color or (lambda dev_id, label: None)
        self._persist_dps = persist_dps or (lambda dev_id, dps: None)
        self._load_persisted = load_persisted_dps or (lambda dev_id: None)
        self._store_device = store_device or (lambda device: None)
        self._datastore: MutableMapping[str, Any] = datastore if datastore is not None else {}
        self.dp_states: dict[str, dict[str, Any]] = {}
        self.dp_states_snapshot: dict[str, dict[str, Any]] = {}
        # ``x`` → ``y`` flow: per-device ``CleaningProgressMetadata``.
        self.cleaning_progress: dict[str, CleaningProgressMetadata] = {}
        self.cleaning_progress_snapshot: dict[str, CleaningProgressMetadata] = {}
        # ``r`` → ``s`` flow: ``startedAt`` values mirrored out of ``x``.
        self.cleaning_start_times: dict[str, int] = {}
        self.cleaning_start_times_snapshot: dict[str, int] = {}
        # ``B`` → ``C`` flow: ``elapsedBeforePauseSeconds`` mirrored out of ``x``.
        self.cleaning_elapsed_seconds: dict[str, float] = {}
        self.cleaning_elapsed_snapshot: dict[str, float] = {}

    async def on_command_sent(self, dev_id: str, dps: Mapping[str, Any]) -> None:
        """``P`` — post-write hook: log critical diffs, then ``update_device_dps``."""

        if not dps:
            return
        filtered = {k: v for k, v in dps.items() if k in CRITICAL_DP_KEYS}
        cached = self.dp_states.get(dev_id)
        for key, value in filtered.items():
            old = cached.get(key) if cached is not None else None
            if not _java_equal(old, value):
                _LOG.debug("✅ 强制更新关键DP %s: %s -> %s", key, old, value)
        await self.update_device_dps(dev_id, dps)

    async def update_device_dps(self, dev_id: str, dps: Mapping[str, Any]) -> None:
        """``D0`` (``updateDeviceDps``)."""

        device = self._device_lookup(dev_id)
        if device is None:
            return
        mutable = dict(dps)
        existing = dict(device.dps_data) if device.dps_data else {}
        if mutable.get(_DP102_KEY) is None and existing.get(_DP102_KEY) is not None:
            mutable[_DP102_KEY] = existing[_DP102_KEY]
        apply_to_map(mutable)
        smooth = parse_smooth_spread_count(mutable.get(_DP102_KEY))
        if smooth is not None:
            mutable[_SMOOTH_KEY] = smooth
        color_code = parse_device_color_code(mutable.get(_DP102_KEY))
        color_label = device_color_label_from_code(color_code) if color_code is not None else None
        if color_label is not None:
            await _maybe_await(self._persist_color(dev_id, color_label))

        running = running_status_from_dp_states(mutable)
        incoming_has_126 = "126" in mutable
        existing_126 = existing.get("126")
        if not isinstance(existing_126, str):
            existing_126 = None
        if running == "clean_start" and not incoming_has_126 and existing_126 == "cat_exist":
            _LOG.debug(
                "🔧 清理开始时检测到旧的 cat_exist 状态，将在合并时清除（清理开始说明宠物已离开）"
            )

        cache = dict(self.dp_states.get(dev_id) or {})
        for key, value in mutable.items():
            if key not in CRITICAL_DP_KEYS and key != _DP102_KEY:
                cache[key] = value
        if running == "clean_start" and not incoming_has_126 and cache.get("126") == "cat_exist":
            cache.pop("126", None)
        for key in CRITICAL_DP_ORDER:
            value = mutable.get(key)
            if value is not None:
                cache[key] = value
        incoming_102 = mutable.get(_DP102_KEY)
        if incoming_102 is not None:
            cache[_DP102_KEY] = incoming_102
        merged = dict(cache)
        self.dp_states[dev_id] = merged
        self.dp_states_snapshot = dict(self.dp_states)

        if merged:
            await _maybe_await(self._persist_dps(dev_id, merged))
        else:
            await _maybe_await(self._load_persisted(dev_id))

        status, bin_status = derive_status(merged, device.online)
        dp3 = merged.get("3")
        dp3_value = dp3 if type(dp3) is int else None
        updated = device.copy(
            status=status,
            bin_status=bin_status,
            last_update_ms=_now_ms(),
            dps_data=merged,
            dp3_value=dp3_value,
        )
        await _maybe_await(self._store_device(updated))
        await self.sync_cleaning_progress_from_dp(dev_id, mutable)

    async def sync_cleaning_progress_from_dp(self, dev_id: str, dps: Mapping[str, Any]) -> None:
        """``v0`` — ``syncCleaningProgressFromDp`` on the merged dp map."""

        status = running_status_from_dp_states(dps)
        spread = spread_count_from_dp_states(dps, 0)
        expected = 205 if spread == 7 else spread * 25 + 80
        now = _now_ms()
        meta = self.cleaning_progress.get(dev_id)
        if meta is None:
            meta = EMPTY_CLEANING_PROGRESS

        if status == "clean_start":
            if meta.is_completed():
                new_meta = replace(
                    EMPTY_CLEANING_PROGRESS,
                    started_at=now,
                    expected_duration_seconds=expected,
                    last_updated_at=now,
                )
                _LOG.debug(
                    "Repository: syncCleaningProgressFromDp - "
                    "检测到新清理（metadata是完成状态），重置为0%"
                )
                await self.save_cleaning_start_time(dev_id, now)
            elif 0 < meta.last_updated_at and now - meta.last_updated_at < 3000:
                _LOG.debug(
                    "Repository: syncCleaningProgressFromDp - "
                    "metadata最近已更新（%sms前），跳过自动计算，使用现有值: "
                    "进度=%s%%, startedAt=%s, elapsedBeforePause=%s秒",
                    now - meta.last_updated_at,
                    meta.progress_percent,
                    meta.started_at,
                    meta.elapsed_before_pause_seconds,
                )
                if meta.expected_duration_seconds != expected:
                    new_meta = replace(meta, expected_duration_seconds=expected)
                else:
                    new_meta = meta
            else:
                started = meta.started_at if meta.started_at is not None else now
                stored = meta.elapsed_before_pause_seconds
                elapsed = (now - started) / 1000.0
                if stored > 0:
                    elapsed += stored
                new_meta = replace(
                    meta,
                    started_at=started,
                    last_paused_at=None,
                    progress_percent=_progress_percent(elapsed, expected),
                    expected_duration_seconds=expected,
                    completed_at=None,
                    last_updated_at=now,
                )
                if dev_id not in self.cleaning_start_times:
                    await self.save_cleaning_start_time(dev_id, started)
        elif status == "clean_pause":
            started = meta.started_at if meta.started_at is not None else now
            elapsed = (now - started) / 1000.0 + meta.elapsed_before_pause_seconds
            new_meta = replace(
                meta,
                started_at=None,
                last_paused_at=now,
                elapsed_before_pause_seconds=elapsed,
                progress_percent=_progress_percent(elapsed, expected),
                expected_duration_seconds=expected,
                completed_at=None,
                last_updated_at=now,
            )
        elif status in _CLEAN_DONE_STATUSES:
            await self.remove_cleaning_start_time(dev_id)
            await self.remove_cleaning_progress(dev_id)
            return
        elif meta.expected_duration_seconds != expected:
            new_meta = replace(
                meta,
                expected_duration_seconds=expected,
                last_updated_at=now,
            )
        else:
            new_meta = meta

        if not _meta_equal(new_meta, meta):
            await self.update_cleaning_progress(dev_id, new_meta, persist=True)

    async def update_cleaning_progress(
        self, dev_id: str, meta: CleaningProgressMetadata, persist: bool
    ) -> None:
        """``q0`` — mirror ``meta`` into ``x``/``r``/``B`` and their flows."""

        if meta.is_empty():
            self.cleaning_progress.pop(dev_id, None)
            self.cleaning_progress_snapshot = dict(self.cleaning_progress)
            self.cleaning_start_times.pop(dev_id, None)
            self.cleaning_start_times_snapshot = dict(self.cleaning_start_times)
            self.cleaning_elapsed_seconds.pop(dev_id, None)
            self.cleaning_elapsed_snapshot = dict(self.cleaning_elapsed_seconds)
        else:
            self.cleaning_progress[dev_id] = meta
            self.cleaning_progress_snapshot = dict(self.cleaning_progress)
            if meta.started_at is not None:
                self.cleaning_start_times[dev_id] = meta.started_at
            else:
                self.cleaning_start_times.pop(dev_id, None)
            self.cleaning_start_times_snapshot = dict(self.cleaning_start_times)
            if meta.elapsed_before_pause_seconds > 0:
                self.cleaning_elapsed_seconds[dev_id] = meta.elapsed_before_pause_seconds
            else:
                self.cleaning_elapsed_seconds.pop(dev_id, None)
            self.cleaning_elapsed_snapshot = dict(self.cleaning_elapsed_seconds)
        if not persist:
            return
        if meta.is_empty():
            await self.remove_cleaning_progress_state_from_datastore(dev_id)
        else:
            await self.save_cleaning_progress_state(dev_id, meta)

    async def remove_cleaning_progress(self, dev_id: str) -> None:
        """``c0`` — drop ``x`` + ``y`` flow, then remove persisted state."""

        self.cleaning_progress.pop(dev_id, None)
        self.cleaning_progress_snapshot = dict(self.cleaning_progress)
        await self.remove_cleaning_progress_state_from_datastore(dev_id)
        _LOG.debug("Repository: 移除设备 %s 清理进度状态", dev_id)

    async def save_cleaning_start_time(self, dev_id: str, started_ms: int) -> None:
        """``l0`` — persist ``cleaning_start_time_<devId>``."""

        try:
            self._datastore[_START_TIME_KEY_PREFIX + dev_id] = started_ms
            _LOG.debug(
                "Repository: 保存设备 %s 清理开始时间到DataStore: %s",
                dev_id,
                started_ms,
            )
        except Exception:
            _LOG.exception("Repository: 保存清理开始时间到DataStore失败")

    async def remove_cleaning_start_time(self, dev_id: str) -> None:
        """``e0`` — remove ``cleaning_start_time_<devId>``."""

        try:
            self._datastore.pop(_START_TIME_KEY_PREFIX + dev_id, None)
            _LOG.debug("Repository: 从DataStore删除设备 %s 清理开始时间", dev_id)
        except Exception:
            _LOG.exception("Repository: 删除清理开始时间失败")

    async def save_cleaning_progress_state(
        self, dev_id: str, meta: CleaningProgressMetadata
    ) -> None:
        """``k0`` — persist ``cleaning_progress_state_<devId>`` as JSON."""

        try:
            self._datastore[_PROGRESS_STATE_KEY_PREFIX + dev_id] = cleaning_progress_to_json(meta)
        except Exception:
            _LOG.exception("Repository: 保存清洁进度元数据失败")

    async def remove_cleaning_progress_state_from_datastore(self, dev_id: str) -> None:
        """``d0`` — remove ``cleaning_progress_state_<devId>``."""

        try:
            self._datastore.pop(_PROGRESS_STATE_KEY_PREFIX + dev_id, None)
        except Exception:
            _LOG.exception("Repository: 删除清洁进度元数据失败")
