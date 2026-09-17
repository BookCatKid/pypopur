"""Cloud datapoint transport extension point.

Account bootstrap is implemented separately in :mod:`pypopur.mobile`. ``CloudTransport`` remains
an adapter for callers that want to supply a cloud datapoint backend instead of LAN control.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any, Protocol

from .exceptions import UnsupportedCloudAuthentication
from .transport import PopurTransport


class CloudBackend(Protocol):
    """Interface for a future independently authenticated cloud backend."""

    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]: ...
    async def write_dps(self, values: Mapping[int, Any]) -> None: ...


class CloudTransport(PopurTransport):
    """Delegate to an externally supplied, safely authenticated cloud backend."""

    def __init__(self, backend: CloudBackend) -> None:
        self._backend = backend

    @classmethod
    def login(cls, *args: Any, **kwargs: Any) -> CloudTransport:
        del args, kwargs
        raise UnsupportedCloudAuthentication(
            "CloudTransport does not perform account bootstrap. Use PopurAccount or "
            "bootstrap_discovered_s7 with a MobileAppProfile, then create a local client."
        )

    async def connect(self) -> None:
        await self._backend.connect()

    async def close(self) -> None:
        await self._backend.close()

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        return await self._backend.read_dps(ids)

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        await self._backend.write_dps(values)
