from __future__ import annotations

import unittest

from pypopur.reference import (
    DP_ALIAS_COUNT,
    DP_ALIASES,
    DP_DISTINCT_VALUE_COUNT,
    DP_VALUE_ALIASES,
    DP_VALUE_STATUS,
    SCALAR_DP_METADATA,
    DpAliasStatus,
    aliases_for_value,
    wire_status,
)


class ReferenceTests(unittest.TestCase):
    def test_complete_device_dp_constants_inventory(self) -> None:
        self.assertEqual(DP_ALIAS_COUNT, 127)
        self.assertEqual(DP_DISTINCT_VALUE_COUNT, 79)
        self.assertEqual(len(DP_ALIASES), 127)
        self.assertEqual(len(DP_VALUE_ALIASES), 79)
        self.assertEqual(len(DP_VALUE_STATUS), 79)

    def test_collisions_are_retained_and_classified_per_symbol(self) -> None:
        value_102 = {item.symbol: item.status for item in aliases_for_value(102)}
        self.assertEqual(value_102["DP_SYSTEM_SETTINGS"], DpAliasStatus.CURRENT_PACKED)
        self.assertEqual(
            value_102["DP_OPERATION_MODE"],
            DpAliasStatus.LEGACY_OR_AMBIGUOUS,
        )
        self.assertEqual(
            value_102["DP_CLEANING_INTENSITY"],
            DpAliasStatus.LEGACY_OR_AMBIGUOUS,
        )
        self.assertEqual(wire_status(101), DpAliasStatus.CURRENT_PACKED)
        self.assertEqual(wire_status(102), DpAliasStatus.CURRENT_PACKED)
        self.assertEqual(wire_status(112), DpAliasStatus.CURRENT_NOTIFICATION)
        self.assertEqual(wire_status(139), DpAliasStatus.LEGACY_OR_AMBIGUOUS)

    def test_packed_subfield_sentinel_is_not_fabricated_as_numeric_dp(self) -> None:
        item = DP_ALIASES["DP_LITTER_SPREAD_COUNT"]
        self.assertEqual(item.value, "__dp102_setting_smooth__")
        self.assertEqual(item.status, DpAliasStatus.PACKED_SUBFIELD)

    def test_scalar_value_range_metadata_only_claims_proven_units(self) -> None:
        toilet_time = SCALAR_DP_METADATA[154]
        self.assertEqual(toilet_time.unit, "s")
        self.assertEqual(toilet_time.minimum, 0)
        self.assertEqual(toilet_time.maximum, 10_000)

        self.assertIsNone(SCALAR_DP_METADATA[8].unit)
        self.assertIsNone(SCALAR_DP_METADATA[116].unit)


if __name__ == "__main__":
    unittest.main()
