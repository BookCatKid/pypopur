from __future__ import annotations

import unittest

from pypopur import DiscoveredS7, LocalDeviceConfig, resolve_local_config


class FakeBootstrap:
    async def bootstrap_local_config(self, discovered: DiscoveredS7) -> LocalDeviceConfig:
        return LocalDeviceConfig(
            host=discovered.host,
            device_id=discovered.device_id,
            local_key="synthetic-key",
            protocol_version=discovered.protocol_version,
        )


class BootstrapTests(unittest.IsolatedAsyncioTestCase):
    async def test_provider_neutral_resolution(self) -> None:
        discovered = DiscoveredS7("192.0.2.10", "device", "product", "3.5")
        config = await resolve_local_config(FakeBootstrap(), discovered)
        self.assertEqual(config.host, "192.0.2.10")
        self.assertEqual(config.device_id, "device")
        self.assertEqual(config.local_key, "synthetic-key")
        self.assertEqual(config.protocol_version, "3.5")


if __name__ == "__main__":
    unittest.main()
