from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from pypopur.exceptions import (
    HandshakeError,
    MissingLocalKey,
    ProtocolError,
    TransportDependencyMissing,
    TransportError,
)
from pypopur.local import LocalDeviceConfig, LocalTuyaTransport, _default_device_factory


class FakeDevice:
    def __init__(self, device_id: str, host: str, local_key: str, owner: Factory) -> None:
        self.device_id = device_id
        self.host = host
        self.local_key = local_key
        self.owner = owner
        self.version: float | None = None
        self.closed = False
        self.writes: list[dict[str, Any]] = []
        owner.devices.append(self)

    def set_version(self, version: float) -> None:
        self.version = version

    def set_socketTimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def set_socketPersistent(self, value: bool) -> None:
        self.persistent = value

    def status(self) -> dict[str, Any]:
        return self.owner.status_for(self.version)

    def set_multiple_values(self, data: dict[str, Any]) -> dict[str, Any]:
        self.writes.append(dict(data))
        return self.owner.write_result

    def close(self) -> None:
        self.closed = True


class Factory:
    def __init__(self) -> None:
        self.devices: list[FakeDevice] = []
        self.responses: dict[float, dict[str, Any]] = {
            3.5: {"dps": {"1": True, "101": "0100000000"}}
        }
        self.write_result: dict[str, Any] = {}

    def __call__(self, device_id: str, host: str, local_key: str) -> FakeDevice:
        return FakeDevice(device_id, host, local_key, self)

    def status_for(self, version: float | None) -> dict[str, Any]:
        assert version is not None
        return self.responses.get(version, {"Error": "key or version", "Err": "914"})


class MinimalDevice:
    def __init__(self) -> None:
        self.version: float | None = None
        self.closed = False

    def set_version(self, version: float) -> None:
        self.version = version

    def status(self) -> dict[str, Any]:
        return {"dps": {"1": True}}

    def set_multiple_values(self, data: dict[str, Any]) -> dict[str, Any]:
        return {}

    def close(self) -> None:
        self.closed = True


class ScriptedDevice(FakeDevice):
    def __init__(
        self,
        device_id: str,
        host: str,
        local_key: str,
        owner: Factory,
        statuses: list[Any],
        write_result: Any = None,
    ) -> None:
        super().__init__(device_id, host, local_key, owner)
        self.statuses = list(statuses)
        self.scripted_write_result = {} if write_result is None else write_result

    def status(self) -> Any:
        result = self.statuses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def set_multiple_values(self, data: dict[str, Any]) -> Any:
        self.writes.append(dict(data))
        if isinstance(self.scripted_write_result, Exception):
            raise self.scripted_write_result
        return self.scripted_write_result


class LocalTransportTests(unittest.IsolatedAsyncioTestCase):
    def test_local_key_never_appears_in_config_repr(self) -> None:
        config = LocalDeviceConfig("192.0.2.1", "dev", "top-secret-local-key")
        self.assertNotIn("top-secret-local-key", repr(config))
        self.assertIn("<redacted>", repr(config))

    def test_missing_key_rejected_before_transport_creation(self) -> None:
        with self.assertRaises(MissingLocalKey):
            LocalTuyaTransport("192.0.2.1", "dev", "")

    def test_constructor_validates_local_connection_parameters(self) -> None:
        with self.assertRaisesRegex(ValueError, "host"):
            LocalTuyaTransport(" ", "dev", "key")
        with self.assertRaisesRegex(ValueError, "device_id"):
            LocalTuyaTransport("192.0.2.1", " ", "key")
        with self.assertRaisesRegex(ValueError, "timeout"):
            LocalTuyaTransport("192.0.2.1", "dev", "key", timeout=0)

    def test_default_factory_has_clean_dependency_error_and_success_path(self) -> None:
        with (
            patch("pypopur.local.import_module", side_effect=ImportError("missing")),
            self.assertRaises(TransportDependencyMissing),
        ):
            _default_device_factory("dev", "192.0.2.1", "key")

        sentinel = MinimalDevice()

        class FakeTinyTuya:
            @staticmethod
            def Device(device_id: str, host: str, local_key: str) -> MinimalDevice:
                self_tuple = (device_id, host, local_key)
                if self_tuple != ("dev", "192.0.2.1", "key"):
                    raise AssertionError(self_tuple)
                return sentinel

        with patch("pypopur.local.import_module", return_value=FakeTinyTuya):
            self.assertIs(_default_device_factory("dev", "192.0.2.1", "key"), sentinel)

    def test_response_parsing_and_safe_close_helpers(self) -> None:
        self.assertIsNone(LocalTuyaTransport._response_error("not-a-map"))
        self.assertIsNone(LocalTuyaTransport._response_error({"dps": {}}))
        self.assertEqual(
            LocalTuyaTransport._response_error({"Error": "bad", "Err": "not-an-int"}),
            (None, "bad"),
        )
        with self.assertRaisesRegex(TransportError, "unknown TinyTuya error"):
            LocalTuyaTransport._raise_response_error({"Err": 902})
        with self.assertRaisesRegex(ProtocolError, "not a mapping"):
            LocalTuyaTransport._extract_dps([])
        with self.assertRaisesRegex(ProtocolError, "DPS mapping"):
            LocalTuyaTransport._extract_dps({"ok": True})

        LocalTuyaTransport._safe_close_sync(None)

        class BadClose(MinimalDevice):
            def close(self) -> None:
                raise OSError("already gone")

        LocalTuyaTransport._safe_close_sync(BadClose())

    def test_make_device_handles_optional_tuning_and_bad_versions(self) -> None:
        minimal = MinimalDevice()
        transport = LocalTuyaTransport(
            "192.0.2.1", "dev", "key", _device_factory=lambda *_: minimal
        )
        self.assertIs(transport._make_device("3.5"), minimal)
        self.assertEqual(minimal.version, 3.5)

        class BadVersion(MinimalDevice):
            def set_version(self, version: float) -> None:
                raise ValueError("unsupported")

        bad = BadVersion()
        bad_transport = LocalTuyaTransport(
            "192.0.2.1", "dev", "key", _device_factory=lambda *_: bad
        )
        with self.assertRaisesRegex(ProtocolError, "Unsupported local protocol"):
            bad_transport._make_device("9.9")
        self.assertTrue(bad.closed)

    async def test_raw_key_settings_use_base64_on_wire_and_hex_in_cache(self) -> None:
        factory = Factory()
        transport = LocalTuyaTransport(
            "192.0.2.1", "dev", "key", protocol_version="3.5", _device_factory=factory
        )
        values = {105: "00010201030104", 1: True, 125: 0, 109: "power_on"}
        try:
            await transport.write_dps(values)
            self.assertEqual(
                factory.devices[0].writes[-1],
                {"105": "AAECAQMBBA==", "1": True, "125": 0, "109": "power_on"},
            )
            self.assertEqual(await transport.read_dps({105}), {105: "00010201030104"})
            self.assertEqual(values[105], "00010201030104")
        finally:
            await transport.close()

    async def test_explicit_protocol_connect_read_filter_write_and_close(self) -> None:
        factory = Factory()
        factory.responses = {3.4: {"dps": {"1": True, "101": "0100000000"}}}
        transport = LocalTuyaTransport(
            "192.0.2.1",
            "dev",
            "legitimate-local-key",
            protocol_version="3.4",
            _device_factory=factory,
        )
        await transport.connect()
        await transport.connect()
        self.assertEqual(len(factory.devices), 1)
        self.assertTrue(transport.connected)
        self.assertEqual(transport.config.device_id, "dev")
        self.assertEqual(transport.protocol_version, "3.4")
        self.assertEqual(await transport.read_dps({101}), {101: "0100000000"})
        await transport.write_dps({102: "00" * 29, 1: True})
        self.assertEqual(
            factory.devices[0].writes[-1],
            {"102": "A" * 39 + "=", "1": True},
        )
        await transport.close()
        await transport.close()
        self.assertTrue(factory.devices[0].closed)
        self.assertFalse(transport.connected)
        self.assertIsNone(transport.protocol_version)

    async def test_auto_probe_can_select_35_or_34_without_writes(self) -> None:
        for selected, responses, expected_versions in (
            ("3.5", {3.5: {"dps": {"1": True}}}, [3.5]),
            (
                "3.4",
                {
                    3.5: {"Error": "key or version", "Err": "914"},
                    3.4: {"dps": {"1": True}},
                },
                [3.5, 3.4],
            ),
        ):
            with self.subTest(selected=selected):
                factory = Factory()
                factory.responses = responses
                transport = LocalTuyaTransport("192.0.2.1", "dev", "key", _device_factory=factory)
                await transport.connect()
                self.assertEqual(transport.protocol_version, selected)
                self.assertEqual([device.version for device in factory.devices], expected_versions)
                self.assertTrue(all(not device.writes for device in factory.devices))
                await transport.close()

    async def test_auto_probe_uses_read_only_status_and_selects_33_after_newer_failures(
        self,
    ) -> None:
        factory = Factory()
        factory.responses = {
            3.5: {"Error": "key or version", "Err": "914"},
            3.4: {"Error": "key or version", "Err": "914"},
            3.3: {"dps": {"1": False, "105": "00010001020103"}},
        }
        transport = LocalTuyaTransport(
            "192.0.2.1", "dev", "legitimate-local-key", _device_factory=factory
        )
        await transport.connect()
        self.assertEqual(transport.protocol_version, "3.3")
        self.assertEqual([device.version for device in factory.devices], [3.5, 3.4, 3.3])
        self.assertTrue(factory.devices[0].closed)
        self.assertTrue(factory.devices[1].closed)
        self.assertFalse(factory.devices[2].closed)
        self.assertEqual(factory.devices[0].writes, [])
        self.assertEqual(factory.devices[1].writes, [])
        self.assertEqual(factory.devices[2].writes, [])
        await transport.close()

    async def test_key_or_version_error_is_not_misreported_as_invalid_key(self) -> None:
        factory = Factory()
        factory.responses = {
            3.5: {"Error": "key or version", "Err": "914"},
            3.4: {"Error": "key or version", "Err": "914"},
            3.3: {"Error": "key or version", "Err": "914"},
        }
        transport = LocalTuyaTransport(
            "192.0.2.1", "dev", "maybe-wrong-key", _device_factory=factory
        )
        with self.assertRaisesRegex(HandshakeError, "does not provide enough evidence"):
            await transport.connect()

    async def test_non_auth_tinytuya_error_is_transport_error(self) -> None:
        factory = Factory()
        factory.responses = {3.4: {"Error": "timeout", "Err": "902"}}
        transport = LocalTuyaTransport(
            "192.0.2.1",
            "dev",
            "key",
            protocol_version="3.4",
            _device_factory=factory,
        )
        with self.assertRaises(TransportError):
            await transport.connect()

    async def test_mixed_auto_probe_failures_are_transport_error_not_auth_error(self) -> None:
        factory = Factory()
        factory.responses = {
            3.5: {"Error": "key or version", "Err": "914"},
            3.4: {"Error": "timeout", "Err": "902"},
            3.3: {"Error": "key or version", "Err": "914"},
        }
        transport = LocalTuyaTransport("192.0.2.1", "dev", "key", _device_factory=factory)
        with self.assertRaisesRegex(TransportError, "Unable to connect") as raised:
            await transport.connect()
        self.assertNotIsInstance(raised.exception, HandshakeError)

    async def test_dependency_error_is_not_swallowed_by_negotiation(self) -> None:
        def missing_factory(*_: str) -> MinimalDevice:
            raise TransportDependencyMissing("missing tinytuya")

        transport = LocalTuyaTransport("192.0.2.1", "dev", "key", _device_factory=missing_factory)
        with self.assertRaises(TransportDependencyMissing):
            await transport.connect()

    async def test_probe_wraps_low_level_status_errors_and_closes_device(self) -> None:
        factory = Factory()

        def device_factory(device_id: str, host: str, local_key: str) -> ScriptedDevice:
            return ScriptedDevice(
                device_id,
                host,
                local_key,
                factory,
                [OSError("socket down")],
            )

        transport = LocalTuyaTransport(
            "192.0.2.1",
            "dev",
            "key",
            protocol_version="3.5",
            _device_factory=device_factory,
        )
        with self.assertRaisesRegex(TransportError, "status probe failed"):
            await transport.connect()
        self.assertTrue(factory.devices[0].closed)

    async def test_read_error_paths_and_unfiltered_read(self) -> None:
        factory = Factory()

        def device_factory(device_id: str, host: str, local_key: str) -> ScriptedDevice:
            return ScriptedDevice(
                device_id,
                host,
                local_key,
                factory,
                [
                    {"dps": {"1": True, "154": 12}},
                    {"dps": {"1": False, "154": 13}},
                    OSError("read failed"),
                ],
            )

        transport = LocalTuyaTransport(
            "192.0.2.1", "dev", "key", protocol_version="3.5", _device_factory=device_factory
        )
        self.assertEqual(await transport.read_dps(), {1: False, 154: 13})
        with self.assertRaisesRegex(TransportError, "status read failed"):
            await transport.read_dps()
        await transport.close()

        protocol_factory = Factory()

        def protocol_device_factory(device_id: str, host: str, local_key: str) -> ScriptedDevice:
            return ScriptedDevice(
                device_id,
                host,
                local_key,
                protocol_factory,
                [{"dps": {"1": True}}, {"missing": "dps"}],
            )

        protocol_transport = LocalTuyaTransport(
            "192.0.2.1",
            "dev",
            "key",
            protocol_version="3.5",
            _device_factory=protocol_device_factory,
        )
        with self.assertRaises(ProtocolError):
            await protocol_transport.read_dps()
        await protocol_transport.close()

    async def test_read_merges_partial_status_with_connection_probe(self) -> None:
        factory = Factory()

        def device_factory(device_id: str, host: str, local_key: str) -> ScriptedDevice:
            return ScriptedDevice(
                device_id,
                host,
                local_key,
                factory,
                [
                    {"dps": {"101": "0100000000", "154": 12}},
                    {"dps": {"154": 13}},
                ],
            )

        transport = LocalTuyaTransport(
            "192.0.2.1",
            "dev",
            "key",
            protocol_version="3.5",
            _device_factory=device_factory,
        )
        self.assertEqual(
            await transport.read_dps(),
            {101: "0100000000", 154: 13},
        )
        await transport.close()

    async def test_write_noop_response_error_and_low_level_exception(self) -> None:
        factory = Factory()
        transport = LocalTuyaTransport(
            "192.0.2.1", "dev", "key", protocol_version="3.5", _device_factory=factory
        )
        await transport.write_dps({})
        self.assertEqual(factory.devices, [])

        factory.write_result = {"Error": "denied", "Err": 902}
        with self.assertRaisesRegex(TransportError, "denied"):
            await transport.write_dps({1: True})
        await transport.close()

        low_level_factory = Factory()

        def device_factory(device_id: str, host: str, local_key: str) -> ScriptedDevice:
            return ScriptedDevice(
                device_id,
                host,
                local_key,
                low_level_factory,
                [{"dps": {"1": True}}],
                RuntimeError("write exploded"),
            )

        low_level = LocalTuyaTransport(
            "192.0.2.1", "dev", "key", protocol_version="3.5", _device_factory=device_factory
        )
        with self.assertRaisesRegex(TransportError, "DPS write failed"):
            await low_level.write_dps({1: True})
        await low_level.close()


if __name__ == "__main__":
    unittest.main()
