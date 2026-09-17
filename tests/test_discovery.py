from __future__ import annotations

import unittest
from unittest.mock import patch

from pypopur.discovery import (
    DiscoveredS7,
    _default_scan,
    discover_s7,
    parse_scan_results,
)
from pypopur.exceptions import ProtocolError, TransportDependencyMissing
from pypopur.reference import S7_PRODUCT_IDS


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def test_parse_scan_results_filters_other_tuya_products_and_normalizes_fields(self) -> None:
        product = min(S7_PRODUCT_IDS)
        results = {
            "192.0.2.10": {
                "gwId": "s7-b",
                "product_id": product,
                "version": 3.5,
            },
            "192.0.2.11": {
                "id": "other",
                "product_id": "not-popur",
                "version": "3.3",
            },
            "192.0.2.12": {
                "devId": "s7-a",
                "productKey": product,
                "pv": "3.4",
            },
        }
        self.assertEqual(
            parse_scan_results(results),
            (
                DiscoveredS7("192.0.2.12", "s7-a", product, "3.4"),
                DiscoveredS7("192.0.2.10", "s7-b", product, "3.5"),
            ),
        )

    def test_parse_scan_results_requires_mapping_and_device_id_for_matching_product(self) -> None:
        product = min(S7_PRODUCT_IDS)
        with self.assertRaisesRegex(ProtocolError, "non-mapping"):
            parse_scan_results({"192.0.2.1": "bad"})  # type: ignore[dict-item]
        with self.assertRaisesRegex(ProtocolError, "device ID"):
            parse_scan_results({"192.0.2.1": {"product_id": product}})

    def test_parse_scan_results_ignores_blank_fields_for_unrelated_devices(self) -> None:
        self.assertEqual(
            parse_scan_results(
                {
                    "192.0.2.1": {"product_id": ""},
                    "192.0.2.2": {"productId": None},
                }
            ),
            (),
        )

    async def test_discover_s7_runs_injected_scanner(self) -> None:
        product = min(S7_PRODUCT_IDS)
        calls = 0

        def scanner():
            nonlocal calls
            calls += 1
            return {
                "192.0.2.20": {
                    "device_id": "dev",
                    "product_id": product,
                    "protocol_version": "3.5",
                }
            }

        self.assertEqual(
            await discover_s7(_scan=scanner),
            (DiscoveredS7("192.0.2.20", "dev", product, "3.5"),),
        )
        self.assertEqual(calls, 1)

    def test_default_scan_dependency_error_and_success_path(self) -> None:
        with (
            patch("pypopur.discovery.import_module", side_effect=ImportError("missing")),
            self.assertRaises(TransportDependencyMissing),
        ):
            _default_scan()

        class FakeTinyTuya:
            @staticmethod
            def deviceScan(*, verbose: bool, color: bool, poll: bool):
                self.assertFalse(verbose)
                self.assertFalse(color)
                self.assertFalse(poll)
                return {"192.0.2.1": {}}

        with patch("pypopur.discovery.import_module", return_value=FakeTinyTuya):
            self.assertEqual(_default_scan(), {"192.0.2.1": {}})


if __name__ == "__main__":
    unittest.main()
