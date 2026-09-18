"""Typed beans for the mobile cloud read surface.

These parse the ``asyncRequest`` response shapes decoded from the
ThingClips device SDK (``dbppbbp``) and verified against the live
service. Every bean keeps the raw mapping so fields the app ignores
stay reachable.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .sdk.thing_model import ThingSmartThingModel


def _str_or_none(value: Any) -> str | None:
    return None if value is None else str(value)


def _int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class OperateLogEntry:
    """One ``thing.m.smart.operate.all.log`` row — a DP report the device
    sent upstream, newest-first with ``sortType="DESC"``."""

    dp_id: int | None
    time_str: str
    time_stamp: int | None
    value: str
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> OperateLogEntry:
        return cls(
            dp_id=_int_or_none(obj.get("dpId")),
            time_str=_str_or_none(obj.get("timeStr")) or "",
            time_stamp=_int_or_none(obj.get("timeStamp")),
            value=_str_or_none(obj.get("value")) or "",
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class OperateLog:
    """``thing.m.smart.operate.all.log`` result — the ``dps`` page plus
    ``dpc`` (device-property-change rows), paging flag and total."""

    entries: tuple[OperateLogEntry, ...]
    dpc: tuple[Mapping[str, Any], ...]
    has_next: bool
    total: int | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> OperateLog:
        rows = obj.get("dps")
        entries = tuple(
            OperateLogEntry.from_json(row) for row in rows if isinstance(row, Mapping)
        ) if isinstance(rows, list) else ()
        dpc_rows = obj.get("dpc")
        dpc = tuple(
            dict(row) for row in dpc_rows if isinstance(row, Mapping)
        ) if isinstance(dpc_rows, list) else ()
        return cls(
            entries=entries,
            dpc=dpc,
            has_next=bool(obj.get("hasNext")),
            total=_int_or_none(obj.get("total")),
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class FirmwareModule:
    """One ``thing.m.device.upgrade.info`` module row."""

    module_type: int | None
    type_desc: str | None
    current_version: str | None
    upgrade_status: int | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> FirmwareModule:
        return cls(
            module_type=_int_or_none(obj.get("type")),
            type_desc=_str_or_none(obj.get("typeDesc")),
            current_version=_str_or_none(obj.get("currentVersion")),
            upgrade_status=_int_or_none(obj.get("upgradeStatus")),
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class DstInterval:
    """One DST window inside ``thing.m.device.timezone.get``."""

    start: str | None
    end: str | None
    interval: str | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True, slots=True)
class TimezoneInfo:
    """``thing.m.device.timezone.get`` — device timezone plus the DST
    schedule the device applies locally."""

    time_zone_id: str | None
    time_zone: str | None
    dst_intervals: tuple[DstInterval, ...]
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> TimezoneInfo:
        dst = obj.get("daylightSavingTimeResponse")
        intervals: list[DstInterval] = []
        if isinstance(dst, Mapping):
            rows = dst.get("intervals")
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, Mapping):
                        intervals.append(
                            DstInterval(
                                start=_str_or_none(row.get("start")),
                                end=_str_or_none(row.get("end")),
                                interval=_str_or_none(row.get("interval")),
                                raw=dict(row),
                            )
                        )
        return cls(
            time_zone_id=_str_or_none(obj.get("timeZoneId")),
            time_zone=_str_or_none(obj.get("timeZone")),
            dst_intervals=tuple(intervals),
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class TimerItem:
    """One scheduled timer inside a ``thing.m.timer.all.list`` group."""

    timer_id: str | None
    time: str | None
    loops: str | None
    dp_id: int | None
    status: int | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> TimerItem:
        return cls(
            timer_id=_str_or_none(obj.get("timerId")),
            time=_str_or_none(obj.get("time")),
            loops=_str_or_none(obj.get("loops")),
            dp_id=_int_or_none(obj.get("dpId")),
            status=_int_or_none(obj.get("status")),
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class TimerGroup:
    """``thing.m.timer.all.list`` row — timers bucketed by category."""

    category: str | None
    timers: tuple[TimerItem, ...]
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> TimerGroup:
        rows = obj.get("timerList")
        timers = tuple(
            TimerItem.from_json(row) for row in rows if isinstance(row, Mapping)
        ) if isinstance(rows, list) else ()
        return cls(
            category=_str_or_none(obj.get("category")),
            timers=timers,
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class BizProp:
    """``thing.m.device.biz.prop.list`` row — the
    ``DeviceBizPropBean`` business-property record (OTA state, BT
    capability, yuNetState, …)."""

    dev_id: str | None
    yu_net_state: int | None
    bluetooth_capability: str | None
    device_upgrade_status: int | None
    ssid_hash: str | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> BizProp:
        return cls(
            dev_id=_str_or_none(obj.get("devId")),
            yu_net_state=_int_or_none(obj.get("yuNetState")),
            bluetooth_capability=_str_or_none(obj.get("bluetoothCapability")),
            device_upgrade_status=_int_or_none(
                obj.get("otaUpgradeStatus", obj.get("deviceUpgradeStatus"))
            ),
            ssid_hash=_str_or_none(obj.get("ssidHash")),
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class Pet:
    """One ``m.ha.pet.group.list`` row — a household pet profile
    (Popur ``feature/pet`` Pet model). ``owner_id`` is the home gid."""

    pet_id: int | None
    name: str
    pet_type: str | None
    breed_code: str | None
    breed_name: str | None
    sex: int | None
    weight: int | None
    birth: int | None
    avatar: str | None
    ext_info: str | None
    owner_id: str | None
    activeness: int | None
    gmt_create: int | None
    gmt_modified: int | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> Pet:
        return cls(
            pet_id=_int_or_none(obj.get("id")),
            name=_str_or_none(obj.get("name")) or "",
            pet_type=_str_or_none(obj.get("petType")),
            breed_code=_str_or_none(obj.get("breedCode")),
            breed_name=_str_or_none(obj.get("breedName")),
            sex=_int_or_none(obj.get("sex")),
            weight=_int_or_none(obj.get("weight")),
            birth=_int_or_none(obj.get("birth")),
            avatar=_str_or_none(obj.get("avatar")),
            ext_info=_str_or_none(obj.get("extInfo")),
            owner_id=_str_or_none(obj.get("ownerId")),
            activeness=_int_or_none(obj.get("activeness")),
            gmt_create=_int_or_none(obj.get("gmtCreate")),
            gmt_modified=_int_or_none(obj.get("gmtModified")),
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class PetRecord:
    """One ``m.ha.pet.record.list`` row — a per-pet usage/weight log.

    Live shape: ``{devId, dpCode, logType, matchRspVO, time, value}``
    where ``matchRspVO`` is the server's pet match (``{id,
    matchOnPetInfoChange, matchReason}``) and ``value`` is the raw
    base64 DP payload for ``dpCode`` (e.g. ``toilet_usage_data``)."""

    record_id: str | None
    dev_id: str | None
    dp_code: str | None
    log_type: str | None
    pet_id: int | None
    match_reason: str | None
    record_time: int | None
    value: str | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> PetRecord:
        match = obj.get("matchRspVO")
        match_map = match if isinstance(match, Mapping) else {}
        return cls(
            record_id=_str_or_none(obj.get("id")),
            dev_id=_str_or_none(obj.get("devId")),
            dp_code=_str_or_none(obj.get("dpCode")),
            log_type=_str_or_none(obj.get("logType")),
            pet_id=_int_or_none(obj.get("petId", match_map.get("id"))),
            match_reason=_str_or_none(match_map.get("matchReason")),
            record_time=_int_or_none(
                obj.get("recordTime", obj.get("time", obj.get("gmtCreate")))
            ),
            value=_str_or_none(obj.get("value", obj.get("content"))),
            raw=dict(obj),
        )


@dataclass(frozen=True, slots=True)
class PetRecordPage:
    """``m.ha.pet.record.list`` result — a page of pet records. The
    service shape is paged; ``records`` collects whichever list key
    the response carries."""

    records: tuple[PetRecord, ...]
    total: int | None
    has_next: bool
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Any) -> PetRecordPage:
        rows: Any = obj
        total: int | None = None
        has_next = False
        if isinstance(obj, Mapping):
            total = _int_or_none(obj.get("total"))
            has_next = bool(obj.get("hasNext"))
            rows = next(
                (
                    obj[key]
                    for key in ("list", "records", "dps", "data")
                    if isinstance(obj.get(key), list)
                ),
                (),
            )
        records = tuple(
            PetRecord.from_json(row) for row in rows if isinstance(row, Mapping)
        ) if isinstance(rows, list) else ()
        return cls(records=records, total=total, has_next=has_next,
                   raw=dict(obj) if isinstance(obj, Mapping) else {"list": rows})


@dataclass(frozen=True, slots=True)
class DatapointStat:
    """``m.smart.datapoint.stat`` (``DataPointStatBean``) — aggregated
    per-period values plus the period total."""

    data: tuple[str, ...]
    total: str | None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Mapping[str, Any]) -> DatapointStat:
        rows = obj.get("data")
        data = tuple(
            _str_or_none(row) or "" for row in rows
        ) if isinstance(rows, list) else ()
        return cls(
            data=data,
            total=_str_or_none(obj.get("total")),
            raw=dict(obj),
        )


__all__ = [
    "BizProp",
    "DatapointStat",
    "DstInterval",
    "FirmwareModule",
    "OperateLog",
    "OperateLogEntry",
    "Pet",
    "PetRecord",
    "PetRecordPage",
    "ThingSmartThingModel",
    "TimerGroup",
    "TimerItem",
    "TimezoneInfo",
]
