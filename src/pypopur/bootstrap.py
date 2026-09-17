"""Provider-neutral handoff from discovered hardware to LAN credentials."""

from __future__ import annotations

from typing import Protocol

from .discovery import DiscoveredS7
from .local import LocalDeviceConfig


class LocalConfigBootstrap(Protocol):
    """Authenticated provider capable of resolving a discovered S7 for LAN use."""

    async def bootstrap_local_config(self, discovered: DiscoveredS7) -> LocalDeviceConfig: ...


async def resolve_local_config(
    provider: LocalConfigBootstrap, discovered: DiscoveredS7
) -> LocalDeviceConfig:
    """Resolve one discovered S7 without coupling discovery to an account implementation."""

    return await provider.bootstrap_local_config(discovered)
