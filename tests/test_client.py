from __future__ import annotations

import asyncio
import unittest
from collections.abc import Collection, Mapping
from typing import Any

from pypopur import CloudTransport, PopurClient, UnsupportedCloudAuthentication, decode_dp102
from pypopur.exceptions import ProtocolError
from pypopur.models import (
    BinStatus,
    DustbinSettings,
    KeySettings,
    NotificationSettings,
    SystemSettings,
    TimePowerSettings,
)
from pypopur.transport import PopurTransport


class FakeTransport(PopurTransport):
    def __init__(self) -> None:
        self.connect_calls = 0
        self.close_calls = 0
        self.read_calls = 0
        self.dps: dict[int, Any] = {
            1: False,
            101: "0100000000",
            102: "00" * 29,
            104: "050105",
            105: "00010001020103",
        }
        self.writes: list[dict[int, Any]] = []

    async def connect(self) -> None:
        self.connect_calls += 1

    async def close(self) -> None:
        self.close_calls += 1

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        self.read_calls += 1
        await asyncio.sleep(0)
        if ids is None:
            return dict(self.dps)
        return {dp: self.dps[dp] for dp in ids if dp in self.dps}

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        values = dict(values)
        self.writes.append(values)
        self.dps.update(values)


class FailingCloseTransport(FakeTransport):
    async def close(self) -> None:
        self.close_calls += 1
        raise RuntimeError("close failed")


class FakeCloudBackend:
    def __init__(self) -> None:
        self.connect_calls = 0
        self.close_calls = 0
        self.dps: dict[int, Any] = {1: True, 154: 42}
        self.writes: list[dict[int, Any]] = []

    async def connect(self) -> None:
        self.connect_calls += 1

    async def close(self) -> None:
        self.close_calls += 1

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        if ids is None:
            return dict(self.dps)
        return {dp: value for dp, value in self.dps.items() if dp in ids}

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        copied = dict(values)
        self.writes.append(copied)
        self.dps.update(copied)


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_lifecycle_is_idempotent(self) -> None:
        transport = FakeTransport()
        client = PopurClient(transport)
        await client.connect()
        await client.connect()
        self.assertEqual(transport.connect_calls, 1)
        await client.close()
        self.assertEqual(transport.close_calls, 1)
        await client.close()
        self.assertEqual(transport.close_calls, 2)

    async def test_context_manager_properties_and_direct_io(self) -> None:
        transport = FakeTransport()
        client = PopurClient(transport)
        self.assertFalse(client.connected)
        async with client as entered:
            self.assertIs(entered, client)
            self.assertTrue(client.connected)
            self.assertEqual(await client.read_dps({1}), {1: False})
            await client.write_dps({1: True})
            self.assertEqual(transport.dps[1], True)
        self.assertFalse(client.connected)

        async with transport as entered_transport:
            self.assertIs(entered_transport, transport)
        self.assertGreaterEqual(transport.connect_calls, 2)
        self.assertGreaterEqual(transport.close_calls, 2)

    async def test_close_failure_still_resets_client_lifecycle_state(self) -> None:
        transport = FailingCloseTransport()
        client = PopurClient(transport)
        await client.connect()
        with self.assertRaisesRegex(RuntimeError, "close failed"):
            await client.close()
        self.assertFalse(client.connected)

    def test_local_constructor_builds_transport_without_io(self) -> None:
        client = PopurClient.local(
            "192.0.2.1",
            "device",
            "legitimate-local-key",
            protocol_version="3.5",
            timeout=7,
        )
        self.assertEqual(client.transport.config.host, "192.0.2.1")  # type: ignore[attr-defined]
        self.assertEqual(client.transport.config.protocol_version, "3.5")  # type: ignore[attr-defined]
        self.assertEqual(client.transport.config.timeout, 7)  # type: ignore[attr-defined]

    async def test_refresh_decodes_snapshot(self) -> None:
        transport = FakeTransport()
        client = PopurClient(transport)
        snapshot = await client.refresh()
        self.assertEqual(snapshot.run_mode.bin_status, BinStatus.NEAR_EMPTY)  # type: ignore[union-attr]
        self.assertIs(client.last_snapshot, snapshot)

    async def test_high_level_writes_use_current_v4_dps(self) -> None:
        transport = FakeTransport()
        client = PopurClient(transport)
        await client.start_cleaning()
        self.assertEqual(transport.writes[-1], {1: True})
        await client.continue_cleaning()
        self.assertEqual(transport.writes[-1], {1: True})
        await client.pause_cleaning()
        self.assertEqual(transport.writes[-1], {1: False})
        await client.start_self_check()
        self.assertEqual(transport.writes[-1], {110: True})
        await client.stop_self_check()
        self.assertEqual(transport.writes[-1], {110: False})
        await client.set_power(False)
        self.assertEqual(transport.writes[-1], {109: "power_off"})
        await client.reboot()
        self.assertEqual(transport.writes[-1], {109: "reboot"})
        await client.open_sifter()
        self.assertEqual(transport.writes[-1], {108: "open"})
        await client.start_scoop()
        self.assertEqual(transport.writes[-1], {108: "start_scoop"})
        await client.set_dustbin_open(True)
        self.assertEqual(transport.writes[-1], {31: True})
        await client.zero_bin()
        self.assertEqual(transport.writes[-1], {107: "zeoring"})
        await client.recalibrate_spin_sensor()
        self.assertEqual(transport.writes[-1], {107: "specail_calibrate"})
        await client.recalibrate_scale()
        self.assertEqual(transport.writes[-1], {111: True})

        updated = await client.set_key_lock(1, True)
        self.assertTrue(updated.is_key_locked(1))
        self.assertEqual(transport.writes[-1], {105: "02010001020103"})

        notifications = NotificationSettings(master_enabled=True, bin_full_enabled=True)
        await client.set_notifications(notifications)
        self.assertTrue(transport.writes[-1][112])
        self.assertTrue(transport.writes[-1][123])

    async def test_complete_model_setters_and_rmw_helpers(self) -> None:
        transport = FakeTransport()
        client = PopurClient(transport)

        await client.set_system_settings(SystemSettings())
        self.assertEqual(set(transport.writes[-1]), {102})
        await client.set_time_power(TimePowerSettings())
        self.assertEqual(set(transport.writes[-1]), {103})
        await client.set_dustbin_settings(DustbinSettings())
        self.assertEqual(set(transport.writes[-1]), {104})
        await client.set_key_settings(KeySettings())
        self.assertEqual(set(transport.writes[-1]), {105})

        updated = await client.update_system_settings(delay_minutes=15)
        self.assertEqual(updated.delay_minutes, 15)
        self.assertTrue((await client.set_status_light(True)).panel.status_light_enabled)
        self.assertTrue((await client.set_buzzer(True)).panel.buzzer_enabled)
        self.assertEqual((await client.set_clean_delay(999)).delay_minutes, 60)
        self.assertEqual((await client.set_clean_delay(-5)).delay_minutes, 1)
        self.assertEqual((await client.set_radar_sensitivity(999)).active_shield.sensitivity, 10)
        self.assertEqual((await client.set_radar_sensitivity(-2)).active_shield.sensitivity, 1)
        self.assertEqual((await client.set_radar_range(999)).active_shield.range, 5)
        self.assertEqual((await client.set_radar_range(-2)).active_shield.range, 1)
        self.assertTrue((await client.set_anti_interference(True)).active_shield.anti_interference)

        dustbin = await client.update_dustbin_settings(cycle_count=9)
        self.assertEqual(dustbin.cycle_count, 9)
        self.assertEqual((await client.set_all_keys_locked(True)).lock_mask, 0x0F)
        self.assertEqual((await client.set_all_keys_locked(False)).lock_mask, 0)

    async def test_rmw_refuses_to_overwrite_missing_packed_state(self) -> None:
        transport = FakeTransport()
        client = PopurClient(transport)
        for dp, operation in (
            (102, lambda: client.update_system_settings(delay_minutes=10)),
            (104, lambda: client.update_dustbin_settings(cycle_count=6)),
            (105, lambda: client.set_key_lock(0, True)),
            (105, lambda: client.set_all_keys_locked(True)),
        ):
            with self.subTest(dp=dp, operation=operation):
                transport.dps.pop(dp, None)
                with self.assertRaises(ProtocolError):
                    await operation()
                if dp == 102:
                    transport.dps[102] = "00" * 29
                elif dp == 104:
                    transport.dps[104] = "050105"
                else:
                    transport.dps[105] = "00010001020103"

    async def test_concurrent_system_mutations_are_atomic_and_preserve_raw_bytes(self) -> None:
        transport = FakeTransport()
        raw = bytearray(29)
        raw[0] = 0xAA
        raw[9] = 0x55
        raw[10] = 0  # fallback sensitivity; should remain byte-for-byte unchanged
        raw[22] = 0x80  # unknown bit
        transport.dps[102] = raw.hex()
        client = PopurClient(transport)

        await asyncio.gather(
            client.set_status_light(True),
            client.set_buzzer(True),
        )

        final_raw = bytes.fromhex(transport.dps[102])
        final = decode_dp102(final_raw)
        assert final is not None
        self.assertTrue(final.panel.status_light_enabled)
        self.assertTrue(final.panel.buzzer_enabled)
        self.assertEqual(final_raw[0], 0xAA)
        self.assertEqual(final_raw[9], 0x55)
        self.assertEqual(final_raw[10], 0)
        self.assertEqual(final_raw[22], 0x80)
        self.assertGreaterEqual(transport.read_calls, 2)

    def test_cloud_login_is_explicitly_unsupported(self) -> None:
        with self.assertRaises(UnsupportedCloudAuthentication):
            CloudTransport.login("user@example.invalid", "password")

    async def test_cloud_transport_delegates_all_supported_operations(self) -> None:
        backend = FakeCloudBackend()
        transport = CloudTransport(backend)
        async with transport:
            self.assertEqual(await transport.read_dps({154}), {154: 42})
            await transport.write_dps({1: False})
        self.assertEqual(backend.connect_calls, 1)
        self.assertEqual(backend.close_calls, 1)
        self.assertEqual(backend.writes, [{1: False}])


if __name__ == "__main__":
    unittest.main()
