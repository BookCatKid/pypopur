"""Transport interfaces for pypopur."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Collection, Mapping
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


class FallbackTransport(PopurTransport):
    """Primary-first transport with automatic fallback — LAN over cloud.

    Every operation tries ``primary`` first. On failure the primary is
    closed (so the next attempt re-handshakes), the operation retries on
    ``fallback``, and the primary is skipped for ``backoff`` seconds so a
    dead LAN doesn't stall every call. ``active`` reports which channel
    served the last operation: ``"primary"``, ``"fallback"`` or ``None``.
    """

    def __init__(
        self,
        primary: PopurTransport,
        fallback: PopurTransport,
        *,
        backoff: float = 60.0,
        on_fallback: Callable[[Exception], None] | None = None,
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self._backoff = backoff
        self._on_fallback = on_fallback
        self._primary_retry_at = 0.0
        self.active: str | None = None
        self.last_error: Exception | None = None

    async def connect(self) -> None:
        try:
            await self.primary.connect()
            self.active = "primary"
        except Exception as err:
            await self._mark_primary_dead(err)
            await self.fallback.connect()
            self.active = "fallback"

    async def close(self) -> None:
        for transport in (self.primary, self.fallback):
            try:
                await transport.close()
            except Exception:
                pass
        self.active = None

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        if time.monotonic() < self._primary_retry_at:
            self.active = "fallback"
            return await self.fallback.read_dps(ids)
        try:
            result = await self.primary.read_dps(ids)
            self.active = "primary"
            return result
        except Exception as err:
            await self._mark_primary_dead(err)
            result = await self.fallback.read_dps(ids)
            self.active = "fallback"
            return result

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        if time.monotonic() < self._primary_retry_at:
            self.active = "fallback"
            await self.fallback.write_dps(values)
            return
        try:
            await self.primary.write_dps(values)
            self.active = "primary"
        except Exception as err:
            await self._mark_primary_dead(err)
            await self.fallback.write_dps(values)
            self.active = "fallback"

    def reset_backoff(self) -> None:
        """Clear the primary-skip window — the next operation retries the
        primary immediately (e.g. after swapping in a re-discovered host)."""

        self._primary_retry_at = 0.0

    async def _mark_primary_dead(self, err: Exception) -> None:
        self.last_error = err
        self._primary_retry_at = time.monotonic() + self._backoff
        if self._on_fallback is not None:
            try:
                self._on_fallback(err)
            except Exception:
                pass
        try:
            await self.primary.close()
        except Exception:
            pass
