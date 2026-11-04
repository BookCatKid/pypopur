"""Turn received datapoints into discrete activity and fault events.

The live MQTT capture showed that DP22 (recent activity) is sent once per real
event and carries no ``dpsTime``. Every received DP22 therefore yields an event,
even when the value repeats. DP101 is re-sent unchanged and every countdown
minute, so it never yields events. DP125 (fault bitmask) yields one event per
bit that changed compared with the previously known mask.

These helpers are pure: timestamping and the choice of which frames to feed
(live pushes only, not polled snapshots) are left to the caller.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .dps import FAULT_ITEMS, decode_dp22, decode_dp125_value, normalize_dp_mapping
from .models import RecentActivity

log = logging.getLogger(__name__)

_EMPTY: Mapping[str, Any] = MappingProxyType({})

ACTIVITY_EVENT_TYPES: tuple[str, ...] = tuple(
    activity.name.lower() for activity in RecentActivity if activity is not RecentActivity.IDLE
)
FAULT_EVENT_TYPES: tuple[str, ...] = ("fault_detected", "fault_cleared")

_DP_ACTIVITY = 22
_DP_FAULTS = 125


@dataclass(frozen=True)
class ActivityEvent:
    """One discrete event extracted from a DP report."""

    event_type: str
    dp: int
    raw_value: Any
    attributes: Mapping[str, Any] = field(default=_EMPTY)


def _activity_events(value: Any) -> list[ActivityEvent]:
    activity = decode_dp22(value)
    if activity is None:
        log.debug("Ignoring unknown DP22 activity value %r", value)
        return []
    if activity is RecentActivity.IDLE:
        return []
    return [ActivityEvent(event_type=activity.name.lower(), dp=_DP_ACTIVITY, raw_value=value)]


def _fault_events(value: Any, previous: Any) -> list[ActivityEvent]:
    current_mask = decode_dp125_value(value)
    previous_mask = decode_dp125_value(previous)
    if current_mask == previous_mask:
        return []
    events: list[ActivityEvent] = []
    for item in FAULT_ITEMS:
        was_set = bool(previous_mask & item.mask)
        is_set = bool(current_mask & item.mask)
        if was_set == is_set:
            continue
        events.append(
            ActivityEvent(
                event_type="fault_detected" if is_set else "fault_cleared",
                dp=_DP_FAULTS,
                raw_value=value,
                attributes=MappingProxyType(
                    {"fault": item.label, "url": item.url, "mask": item.mask}
                ),
            )
        )
    return events


def extract_activity_events(
    dps: Mapping[int | str, Any],
    previous_raw: Mapping[int | str, Any] | None = None,
) -> list[ActivityEvent]:
    """Extract activity (DP22) and fault (DP125) events from one DP report.

    ``dps`` keys may be integers or numeric strings. DP22 yields an event on
    every call (repeats included); ``idle`` and unknown values yield nothing.
    DP125 is compared with ``previous_raw[125]``: no fault events are produced
    when there is no previous mask, to avoid spurious events at startup. Every
    other DP is ignored.
    """

    current = normalize_dp_mapping(dps)
    previous = normalize_dp_mapping(previous_raw) if previous_raw is not None else {}

    events: list[ActivityEvent] = []
    if _DP_ACTIVITY in current:
        events.extend(_activity_events(current[_DP_ACTIVITY]))
    if _DP_FAULTS in current and _DP_FAULTS in previous:
        events.extend(_fault_events(current[_DP_FAULTS], previous[_DP_FAULTS]))
    return events
