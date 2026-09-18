"""Cloud transport shim — every typed ``PopurClient`` method over the
app's ``thing.m.device.dp.publish`` HTTP path.

This is the channel the Android app itself uses whenever its MQTT
session is down (``sendByHttp``/``DevCloudControl.atop_publish``), so
reads go through the device's cloud-side DP shadow and writes through
the signed mobile request.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING, Any

from pypopur.transport import PopurTransport

if TYPE_CHECKING:
    from pypopur.mobile import PopurAccount


class CloudHttpTransport(PopurTransport):
    """``PopurTransport`` backed by the signed mobile cloud API."""

    def __init__(self, account: PopurAccount, device_id: str) -> None:
        self._account = account
        self._device_id = device_id

    async def connect(self) -> None:
        """The account session is the connection; nothing to open."""

    async def close(self) -> None:
        """Nothing to close; the account outlives this transport."""

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        dps = dict(await self._account.device_dps(self._device_id))
        if ids is None:
            return dps
        return {dp: value for dp, value in dps.items() if dp in ids}

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        dps_json = json.dumps(
            {str(dp): value for dp, value in values.items()},
            separators=(",", ":"),
        )
        # ``DeviceApi.publish_dps`` postData order: devId, gwId, dps.
        await self._account.api.request(
            "thing.m.device.dp.publish",
            "1.0",
            {"devId": self._device_id, "gwId": self._device_id, "dps": dps_json},
        )
