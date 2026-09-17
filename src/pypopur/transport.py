"""Transport interfaces for pypopur."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Collection, Mapping
from typing import Any, Self


class PopurTransport(ABC):
    """Async datapoint transport used by :class:`pypopur.PopurClient`."""

    @abstractmethod
    async def connect(self) -> None:
        """Open or validate the transport. Must be safe to call repeatedly."""

    @abstractmethod
    async def close(self) -> None:
        """Close the transport. Must be safe to call repeatedly."""

    @abstractmethod
    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        """Read device datapoints, optionally filtering to *ids*."""

    @abstractmethod
    async def write_dps(self, values: Mapping[int, Any]) -> None:
        """Write one or more datapoints atomically where the backend supports it."""

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()
