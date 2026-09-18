"""Payload builders for the management write surface.

These mirror the postData shapes the app builds before calling
``asyncRequest`` — ``petJson``/``queryJson`` JSON-string wrappers for
the ``m.ha.pet.*`` endpoints (``PetRemoteDataSource``) and the plain
param maps for the ``thing.m.*`` management endpoints (``dbppbbp``,
``bqbdpqd``, ``bqqbpqb``/``bdbbqbd``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

PET_BIZ_TYPE = 1
"""The ``bizType``/``bizTypes`` constant the app sends for its pets
(``PetRemoteDataSource`` puts boxed ``1`` everywhere)."""

PET_TYPE_CAT = "cat"


def pet_query_json(
    owner_id: str | int,
    *,
    biz_types: Sequence[int] = (PET_BIZ_TYPE,),
    start_time: int | None = None,
    end_time: int | None = None,
    log_type: int | None = None,
    pet_id: int | None = None,
    page_no: int | None = None,
    page_size: int | None = None,
) -> str:
    """``queryJson`` string for ``m.ha.pet.group.list`` /
    ``m.ha.pet.record.list``. ``owner_id`` is the home gid; only the
    fields the app sets are emitted."""
    query: dict[str, Any] = {"ownerId": str(owner_id)}
    if biz_types:
        query["bizTypes"] = list(biz_types)
    if start_time is not None:
        query["startTime"] = start_time
    if end_time is not None:
        query["endTime"] = end_time
    if log_type is not None:
        query["logType"] = log_type
    if pet_id is not None:
        query["petId"] = pet_id
    if page_no is not None:
        query["pageNo"] = page_no
    if page_size is not None:
        query["pageSize"] = page_size
    return json.dumps(query, separators=(",", ":"))


def pet_json(
    owner_id: str | int,
    name: str | None = None,
    *,
    pet_id: int | None = None,
    pet_type: str = PET_TYPE_CAT,
    avatar: str | None = None,
    sex: int | None = None,
    birth: int | None = None,
    weight: int | None = None,
    breed_code: str | None = None,
    ext_info: str | None = None,
    activeness: int | None = None,
    biz_type: int = PET_BIZ_TYPE,
) -> str:
    """``petJson`` string for ``m.ha.pet.group.add`` /
    ``m.ha.pet.group.update``. Mirrors the ordered map the app builds
    in ``PetRemoteDataSource.a``/``.g``."""
    payload: dict[str, Any] = {
        "bizType": biz_type,
        "ownerId": str(owner_id),
        "petType": pet_type,
    }
    if pet_id is not None:
        payload["id"] = pet_id
    for key, value in (
        ("name", name),
        ("avatar", avatar),
        ("sex", sex),
        ("birth", birth),
        ("weight", weight),
        ("breedCode", breed_code),
        ("extInfo", ext_info),
        ("activeness", activeness),
    ):
        if value is not None:
            payload[key] = value
    return json.dumps(payload, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class TimerInstruction:
    """One entry of the ``instruct`` JSON array the
    ``thing.m.timer.group.*`` endpoints carry — ``{dpId, value,
    time}`` as built by the app's timer bean."""

    dp_id: int
    value: Any
    time: str

    def to_json(self) -> dict[str, Any]:
        return {"dpId": self.dp_id, "value": self.value, "time": self.time}


def build_instruct(instructions: Sequence[TimerInstruction | Mapping[str, Any]]) -> str:
    """Serialise the ``instruct`` field the ``thing.m.timer.group.add``
    / ``.update`` postData expects — a JSON array string."""
    rows = [
        inst.to_json() if isinstance(inst, TimerInstruction) else dict(inst)
        for inst in instructions
    ]
    return json.dumps(rows, separators=(",", ":"))


__all__ = [
    "PET_BIZ_TYPE",
    "PET_TYPE_CAT",
    "TimerInstruction",
    "build_instruct",
    "pet_json",
    "pet_query_json",
]
