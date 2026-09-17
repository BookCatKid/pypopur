"""High-level async Popur client."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any, Self

from .dps import (
    DpId,
    decode_dp102,
    decode_dp104,
    decode_dp105,
    decode_snapshot,
    encode_dp102,
    encode_dp103,
    encode_dp104,
    encode_dp105,
    encode_notification_settings,
    with_key_lock,
)
from .exceptions import ProtocolError
from .local import LocalTuyaTransport
from .models import (
    DeviceSnapshot,
    DustbinSettings,
    KeySettings,
    MachineControl,
    NotificationSettings,
    SifterControl,
    SpecialOperation,
    SystemSettings,
    TimePowerSettings,
)
from .transport import PopurTransport


class PopurClient:
    """Async client over a pluggable Popur datapoint transport."""

    def __init__(self, transport: PopurTransport) -> None:
        self.transport = transport
        self._connected = False
        self._lifecycle_lock = asyncio.Lock()
        self._mutation_lock = asyncio.Lock()
        self.last_snapshot: DeviceSnapshot | None = None

    @classmethod
    def local(
        cls,
        host: str,
        device_id: str,
        local_key: str,
        *,
        protocol_version: str | None = None,
        timeout: float = 5.0,
    ) -> PopurClient:
        """Create a LAN client using a legitimate user-supplied local key."""

        return cls(
            LocalTuyaTransport(
                host,
                device_id,
                local_key,
                protocol_version=protocol_version,
                timeout=timeout,
            )
        )

    @property
    def connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        """Connect idempotently; suitable for HA config-entry setup."""

        async with self._lifecycle_lock:
            if self._connected:
                return
            await self.transport.connect()
            self._connected = True

    async def close(self) -> None:
        """Close idempotently; suitable for HA config-entry unload."""

        async with self._lifecycle_lock:
            if not self._connected:
                # Transport close itself is required to be idempotent, and this
                # also cleans up a partially failed backend connect.
                await self.transport.close()
                return
            try:
                await self.transport.close()
            finally:
                self._connected = False

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def refresh(self) -> DeviceSnapshot:
        await self.connect()
        snapshot = decode_snapshot(await self.transport.read_dps())
        self.last_snapshot = snapshot
        return snapshot

    async def read_dps(self, ids: set[int] | None = None) -> Mapping[int, Any]:
        await self.connect()
        return await self.transport.read_dps(ids)

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        await self.connect()
        await self.transport.write_dps(values)

    async def set_cleaning(self, running: bool) -> None:
        await self.write_dps({int(DpId.CLEAN_CONTROL): bool(running)})

    async def start_cleaning(self) -> None:
        await self.set_cleaning(True)

    async def continue_cleaning(self) -> None:
        await self.set_cleaning(True)

    async def pause_cleaning(self) -> None:
        await self.set_cleaning(False)

    async def start_self_check(self) -> None:
        await self.write_dps({int(DpId.SELF_CHECK_CONTROL): True})

    async def stop_self_check(self) -> None:
        await self.write_dps({int(DpId.SELF_CHECK_CONTROL): False})

    async def set_machine_control(self, command: MachineControl | str) -> None:
        await self.write_dps({int(DpId.MACHINE_CONTROL): MachineControl(command).value})

    async def set_power(self, enabled: bool) -> None:
        await self.set_machine_control(
            MachineControl.POWER_ON if enabled else MachineControl.POWER_OFF
        )

    async def reboot(self) -> None:
        await self.set_machine_control(MachineControl.REBOOT)

    async def control_sifter(self, command: SifterControl | str) -> None:
        await self.write_dps({int(DpId.SIFTER_CONTROL): SifterControl(command).value})

    async def open_sifter(self) -> None:
        await self.control_sifter(SifterControl.OPEN)

    async def close_sifter(self) -> None:
        await self.control_sifter(SifterControl.CLOSE)

    async def start_scoop(self) -> None:
        await self.control_sifter(SifterControl.START_SCOOP)

    async def pause_scoop(self) -> None:
        await self.control_sifter(SifterControl.PAUSE_SCOOP)

    async def set_dustbin_open(self, opened: bool) -> None:
        await self.write_dps({int(DpId.TRASH_BIN_CONTROL): bool(opened)})

    async def zero_bin(self) -> None:
        await self.write_dps({int(DpId.SPECIAL_OPERATE): SpecialOperation.ZERO_BIN.value})

    async def recalibrate_spin_sensor(self) -> None:
        await self.write_dps(
            {int(DpId.SPECIAL_OPERATE): (SpecialOperation.RECALIBRATE_SPIN_SENSOR.value)}
        )

    async def recalibrate_scale(self) -> None:
        await self.write_dps({int(DpId.SCALE_RECALIBRATE): True})

    async def set_system_settings(self, settings: SystemSettings) -> None:
        """Write a complete DP102 model.

        Callers performing a partial update should prefer ``update_system_settings`` or one of
        the targeted setters so the fresh read and write are serialized as one transaction.
        """

        await self.write_dps({int(DpId.SYSTEM_SETTINGS): encode_dp102(settings)})

    async def _mutate_system_settings(
        self, mutate: Callable[[SystemSettings], SystemSettings]
    ) -> SystemSettings:
        async with self._mutation_lock:
            values = await self.read_dps({int(DpId.SYSTEM_SETTINGS)})
            current = decode_dp102(values.get(int(DpId.SYSTEM_SETTINGS)))
            if current is None:
                raise ProtocolError(
                    "DP102 is unavailable; refusing to overwrite unknown system settings"
                )
            updated = mutate(current)
            await self.write_dps({int(DpId.SYSTEM_SETTINGS): encode_dp102(updated)})
            return updated

    async def update_system_settings(self, **changes: Any) -> SystemSettings:
        return await self._mutate_system_settings(lambda current: replace(current, **changes))

    async def set_status_light(self, enabled: bool) -> SystemSettings:
        return await self._mutate_system_settings(
            lambda current: replace(
                current,
                panel=replace(current.panel, status_light_enabled=bool(enabled)),
            )
        )

    async def set_buzzer(self, enabled: bool) -> SystemSettings:
        return await self._mutate_system_settings(
            lambda current: replace(
                current,
                panel=replace(current.panel, buzzer_enabled=bool(enabled)),
            )
        )

    async def set_clean_delay(self, minutes: int) -> SystemSettings:
        minutes = max(1, min(60, int(minutes)))
        return await self._mutate_system_settings(
            lambda current: replace(current, delay_minutes=minutes)
        )

    async def set_radar_sensitivity(self, value: int) -> SystemSettings:
        value = max(1, min(10, int(value)))
        return await self._mutate_system_settings(
            lambda current: replace(
                current,
                active_shield=replace(current.active_shield, sensitivity=value),
            )
        )

    async def set_radar_range(self, value: int) -> SystemSettings:
        value = max(1, min(5, int(value)))
        return await self._mutate_system_settings(
            lambda current: replace(
                current,
                active_shield=replace(current.active_shield, range=value),
            )
        )

    async def set_anti_interference(self, enabled: bool) -> SystemSettings:
        return await self._mutate_system_settings(
            lambda current: replace(
                current,
                active_shield=replace(
                    current.active_shield,
                    anti_interference=bool(enabled),
                ),
            )
        )

    async def set_time_power(self, settings: TimePowerSettings) -> None:
        await self.write_dps({int(DpId.TIME_POWER_ON_OFF): encode_dp103(settings)})

    async def set_dustbin_settings(self, settings: DustbinSettings) -> None:
        await self.write_dps({int(DpId.DUSTBIN_SETTINGS): encode_dp104(settings)})

    async def update_dustbin_settings(self, **changes: Any) -> DustbinSettings:
        async with self._mutation_lock:
            values = await self.read_dps({int(DpId.DUSTBIN_SETTINGS)})
            current = decode_dp104(values.get(int(DpId.DUSTBIN_SETTINGS)))
            if current is None:
                raise ProtocolError(
                    "DP104 is unavailable; refusing to overwrite unknown dustbin settings"
                )
            updated = replace(current, **changes)
            await self.write_dps({int(DpId.DUSTBIN_SETTINGS): encode_dp104(updated)})
            return updated

    async def set_key_settings(self, settings: KeySettings) -> None:
        await self.write_dps({int(DpId.KEY_SETTINGS): encode_dp105(settings)})

    async def set_key_lock(self, key_index: int, locked: bool) -> KeySettings:
        async with self._mutation_lock:
            values = await self.read_dps({int(DpId.KEY_SETTINGS)})
            current = decode_dp105(values.get(int(DpId.KEY_SETTINGS)))
            if current is None:
                raise ProtocolError(
                    "DP105 is unavailable; refusing to overwrite unknown key settings"
                )
            updated = with_key_lock(current, key_index, locked)
            await self.write_dps({int(DpId.KEY_SETTINGS): encode_dp105(updated)})
            return updated

    async def set_all_keys_locked(self, locked: bool) -> KeySettings:
        async with self._mutation_lock:
            values = await self.read_dps({int(DpId.KEY_SETTINGS)})
            current = decode_dp105(values.get(int(DpId.KEY_SETTINGS)))
            if current is None:
                raise ProtocolError(
                    "DP105 is unavailable; refusing to overwrite unknown key settings"
                )
            updated = replace(current, lock_mask=0x0F if locked else 0)
            await self.write_dps({int(DpId.KEY_SETTINGS): encode_dp105(updated)})
            return updated

    async def set_notifications(self, settings: NotificationSettings) -> None:
        await self.write_dps(encode_notification_settings(settings))
