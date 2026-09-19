"""Tests for FallbackTransport and the active LAN-host discovery helpers."""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from pypopur.discovery import _arp_ips_for_mac, _normalize_mac, find_lan_hosts
from pypopur.transport import FallbackTransport, PopurTransport


class _StubTransport(PopurTransport):
    def __init__(self, *, fail: bool = False, dps: dict | None = None) -> None:
        self.fail = fail
        self.dps = dps
        self.reads = 0
        self.writes: list[dict] = []
        self.closed = 0
        self.connected = 0

    async def connect(self) -> None:
        self.connected += 1
        if self.fail:
            raise OSError("down")

    async def close(self) -> None:
        self.closed += 1

    async def read_dps(self, ids=None):
        self.reads += 1
        if self.fail:
            raise OSError("down")
        if self.dps is not None:
            return {i: v for i, v in self.dps.items() if ids is None or i in ids}
        return {1: "primary" if not self.writes else "w"}

    async def write_dps(self, values) -> None:
        self.writes.append(dict(values))
        if self.fail:
            raise OSError("down")


class FallbackTransportTests(unittest.TestCase):
    def test_primary_serves_when_healthy(self) -> None:
        primary, fallback = _StubTransport(), _StubTransport()
        t = FallbackTransport(primary, fallback)
        asyncio.run(t.connect())
        result = asyncio.run(t.read_dps())
        self.assertEqual(result, {1: "primary"})
        self.assertEqual(t.active, "primary")
        self.assertEqual(fallback.reads, 0)

    def test_failure_falls_back_and_backs_off(self) -> None:
        primary, fallback = _StubTransport(fail=True), _StubTransport()
        t = FallbackTransport(primary, fallback, backoff=60.0)
        asyncio.run(t.read_dps())
        self.assertEqual(t.active, "fallback")
        self.assertEqual(primary.closed, 1)  # dead primary was reset
        # Second call skips the primary entirely (backoff window).
        asyncio.run(t.read_dps())
        self.assertEqual(primary.reads, 1)
        self.assertEqual(fallback.reads, 2)

    def test_primary_retried_after_backoff(self) -> None:
        primary, fallback = _StubTransport(), _StubTransport()
        primary.fail = True
        t = FallbackTransport(primary, fallback, backoff=0.0)
        asyncio.run(t.read_dps())
        self.assertEqual(t.active, "fallback")
        primary.fail = False
        asyncio.run(t.read_dps())
        self.assertEqual(t.active, "primary")

    def test_write_falls_back(self) -> None:
        primary, fallback = _StubTransport(fail=True), _StubTransport()
        t = FallbackTransport(primary, fallback)
        asyncio.run(t.write_dps({112: False}))
        self.assertEqual(fallback.writes, [{112: False}])
        self.assertEqual(t.active, "fallback")

    def test_on_fallback_callback_fires(self) -> None:
        errors: list[Exception] = []
        t = FallbackTransport(
            _StubTransport(fail=True), _StubTransport(), on_fallback=errors.append
        )
        asyncio.run(t.read_dps())
        self.assertEqual(len(errors), 1)
        self.assertIs(t.last_error, errors[0])

    def test_read_fills_missing_dps_from_fallback(self) -> None:
        """The LAN reply omits settings DPs; requested-but-missing ids must
        be filled from the fallback so read-modify-write sees real values."""
        primary = _StubTransport(dps={1: "lan"})
        fallback = _StubTransport(dps={102: "cloud"})
        t = FallbackTransport(primary, fallback)
        result = asyncio.run(t.read_dps({1, 102}))
        # Primary answered with only {1}; fallback supplied the missing 102.
        self.assertEqual(result, {1: "lan", 102: "cloud"})
        self.assertEqual(fallback.reads, 1)
        self.assertEqual(t.active, "primary")

    def test_read_ignores_fallback_gaps(self) -> None:
        primary, fallback = _StubTransport(), _StubTransport(fail=True)
        t = FallbackTransport(primary, fallback)
        result = asyncio.run(t.read_dps({1, 102}))
        self.assertEqual(result, {1: "primary"})
        self.assertEqual(t.active, "primary")

    def test_read_all_skips_gap_fill(self) -> None:
        primary, fallback = _StubTransport(), _StubTransport()
        t = FallbackTransport(primary, fallback)
        asyncio.run(t.read_dps())
        self.assertEqual(fallback.reads, 0)


class LanDiscoveryTests(unittest.TestCase):
    def test_normalize_mac(self) -> None:
        self.assertEqual(_normalize_mac("00:33:7A:07:D7:E6"), "00337a07d7e6")
        self.assertEqual(_normalize_mac("0:33:7a:7:d7:e6"), "00337a07d7e6")
        self.assertEqual(_normalize_mac(""), "")

    def test_arp_ips_for_mac_proc_net_arp(self) -> None:
        table = (
            "IP address       HW type     Flags   HW address            Mask  Device\n"
            "192.168.1.1      0x1         0x2     aa:bb:cc:dd:ee:ff     *     eth0\n"
            "192.168.1.128    0x1         0x2     00:33:7a:07:d7:e6     *     eth0\n"
        )
        with mock.patch(
            "builtins.open", mock.mock_open(read_data=table)
        ):
            self.assertEqual(
                _arp_ips_for_mac("00337a07d7e6"), ["192.168.1.128"]
            )

    def test_find_lan_hosts_prefers_arp_match(self) -> None:
        async def fake_port_open(h, p, t):
            return h.endswith("128")

        async def run() -> list[str]:
            with (
                mock.patch(
                    "pypopur.discovery._arp_ips_for_mac",
                    return_value=["192.168.1.128"],
                ),
                mock.patch(
                    "pypopur.discovery.scan_lan_port",
                    return_value=["192.168.1.128", "192.168.1.50"],
                ),
                mock.patch(
                    "pypopur.discovery._port_open",
                    side_effect=fake_port_open,
                ),
            ):
                return await find_lan_hosts("00:33:7a:07:d7:e6")

        self.assertEqual(asyncio.run(run()), ["192.168.1.128", "192.168.1.50"])

    def test_find_lan_hosts_no_mac_scans(self) -> None:
        async def run() -> list[str]:
            with mock.patch(
                "pypopur.discovery.scan_lan_port",
                return_value=["192.168.1.99"],
            ):
                return await find_lan_hosts(None)

        self.assertEqual(asyncio.run(run()), ["192.168.1.99"])

    def test_local_ip_falls_back_when_broadcast_refused(self) -> None:
        """Linux raises EACCES on a UDP connect to 255.255.255.255 without
        SO_BROADCAST — the HA container hits this; the unicast probe must
        still resolve the outbound interface."""

        import errno

        from pypopur.discovery import _local_ip

        class FakeSock:
            def __init__(self) -> None:
                self.calls: list[tuple[str, int]] = []

            def setsockopt(self, *a) -> None:
                pass

            def connect(self, target) -> None:
                self.calls.append(target)
                if target[0] == "255.255.255.255":
                    raise OSError(errno.EACCES, "Permission denied")

            def getsockname(self):
                return ("192.168.1.50", 0)

            def close(self) -> None:
                pass

        fake = FakeSock()
        with mock.patch(
            "pypopur.discovery.socket.socket", return_value=fake
        ):
            self.assertEqual(_local_ip(), "192.168.1.50")
        self.assertEqual(
            fake.calls, [("255.255.255.255", 7000), ("8.8.8.8", 80)]
        )


if __name__ == "__main__":
    unittest.main()
