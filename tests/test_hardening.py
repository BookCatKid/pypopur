from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any, cast

from pypopur.codec import (
    clamp,
    decode_raw_bytes,
    encode_hex,
    normalize_bytes,
    parse_bool,
    require_raw_bytes,
)
from pypopur.dps import (
    decode_dp22,
    decode_dp101,
    decode_dp102,
    decode_dp103,
    decode_dp104,
    decode_dp105,
    decode_dp106,
    decode_dp125_value,
    decode_snapshot,
    encode_dp101,
    encode_dp102,
    encode_dp104,
    normalize_dp_mapping,
    patch_dp102,
    recurrence_mask_to_text,
    recurrence_text_to_mask,
    with_key_lock,
)
from pypopur.exceptions import ProtocolError
from pypopur.models import (
    ActiveShieldSettings,
    DetailedNotificationExtSettings,
    DetailedNotificationSettings,
    KeySettings,
    PanelToggles,
    RecentActivity,
    RunModeReport,
    SpinSettings,
    TimerSlice,
    WeightFunctionSettings,
)
from pypopur.reference import DpAliasStatus, aliases_for_value, statuses_for_value, wire_status


class RawHelperHardeningTests(unittest.TestCase):
    def test_raw_decoder_handles_every_supported_shape_and_rejects_invalid_values(self) -> None:
        self.assertIsNone(decode_raw_bytes(None))
        self.assertEqual(decode_raw_bytes(memoryview(b"\x01\x02")), b"\x01\x02")
        self.assertEqual(decode_raw_bytes(""), b"")
        self.assertIsNone(decode_raw_bytes("[not-json]"))
        self.assertIsNone(decode_raw_bytes("[true, 1]"))
        self.assertEqual(decode_raw_bytes((1, "skip", True, 257)), b"\x01\x01")
        self.assertIsNone(decode_raw_bytes([]))
        self.assertIsNone(decode_raw_bytes(object()))

    def test_required_and_normalized_raw_bytes(self) -> None:
        self.assertEqual(require_raw_bytes("00ff"), b"\x00\xff")
        with self.assertRaisesRegex(ProtocolError, "Invalid raw byte payload$"):
            require_raw_bytes(object())
        with self.assertRaisesRegex(ProtocolError, "for DP8"):
            require_raw_bytes(object(), dp=8)

        self.assertEqual(normalize_bytes(None, 3), b"\x00\x00\x00")
        self.assertEqual(normalize_bytes(b"", 3, b"\x05\x06"), b"\x05\x06\x00")
        self.assertEqual(normalize_bytes(b"\x01\x02\x03\x04", 3), b"\x01\x02\x03")
        self.assertEqual(encode_hex(b"\x0a\xff"), "0aff")
        self.assertEqual(clamp(-5, 0, 10), 0)
        self.assertEqual(clamp(20, 0, 10), 10)

    def test_permissive_boolean_parser(self) -> None:
        cases = (
            (None, False),
            (True, True),
            (False, False),
            (1, True),
            (0.0, False),
            (" true ", True),
            ("FALSE", False),
            ("-2", True),
            ("nonsense", False),
            (object(), False),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertIs(parse_bool(value), expected)


class CodecHardeningTests(unittest.TestCase):
    def test_dp101_legacy_short_and_encoder_fallback_paths(self) -> None:
        legacy = decode_dp101("hibernating")
        self.assertIsNotNone(legacy)
        self.assertEqual(legacy.machine_status.value, "hibernating")  # type: ignore[union-attr]
        self.assertIsNone(decode_dp101("not-a-status"))
        self.assertIsNone(decode_dp101(b"\x00\x01"))

        invalid = RunModeReport()
        object.__setattr__(invalid, "bin_status", cast(Any, "bogus"))
        object.__setattr__(invalid, "running_status", cast(Any, "bogus"))
        object.__setattr__(invalid, "machine_status", cast(Any, "bogus"))
        object.__setattr__(invalid, "cat_presence", cast(Any, "bogus"))
        object.__setattr__(invalid, "countdown_minutes", -1)
        self.assertEqual(encode_dp101(invalid), "0100000000")

    def test_dp102_full_mutation_and_invalid_reshuffle_label(self) -> None:
        baseline = decode_dp102(bytes(29))
        assert baseline is not None
        all_notifications = DetailedNotificationSettings(
            self_check_enabled=True,
            bin_full_enabled=True,
            manual_cleaning_enabled=True,
            scheduled_cleaning_enabled=True,
            automatic_cleaning_enabled=True,
            cleaning_started_enabled=True,
            pet_finished_enabled=True,
            pet_detected_enabled=True,
        )
        all_notifications_ext = DetailedNotificationExtSettings(
            new_firmware_enabled=True,
            pet_left_without_business_enabled=True,
            cleaning_paused_enabled=True,
            cleaning_resumed_enabled=True,
        )
        changed = replace(
            baseline,
            active_shield=ActiveShieldSettings(True, 10, 5),
            delay_minutes=60,
            smooth_spread_count=7,
            timezone_offset_hours=-12,
            device_color="BLACK",
            detailed_notifications=all_notifications,
            notification_master_enabled=True,
            panel=PanelToggles(True, True, True),
            weight_functions=WeightFunctionSettings(True, True, True, True),
            spin=SpinSettings(True, True, True, "5X", True),
            detailed_notifications_ext=all_notifications_ext,
        )
        raw = bytes.fromhex(encode_dp102(changed))
        self.assertEqual(raw[10:15], bytes((10, 5, 1, 60, 7)))
        self.assertEqual(raw[15], 0xF4)
        self.assertEqual(raw[17:22], bytes((1, 0xFF, 1, 1, 1)))
        self.assertEqual(raw[22], 0x47)
        self.assertEqual(raw[23:29], bytes((1, 1, 1, 0x83, 0x0F, 1)))

        invalid_oscillation = replace(
            baseline, spin=replace(baseline.spin, reshuffle_oscillation="9X")
        )
        self.assertEqual(bytes.fromhex(encode_dp102(invalid_oscillation))[26] & 0x7F, 0)

        unusual = bytearray(29)
        unusual[26] = 0x7F
        decoded = decode_dp102(unusual)
        assert decoded is not None
        self.assertEqual(decoded.spin.reshuffle_oscillation, "2X")
        self.assertIsNone(decode_dp102(object()))

    def test_dp102_patch_uses_default_only_when_payload_cannot_decode(self) -> None:
        default_patch = bytes.fromhex(patch_dp102(object(), delay_minutes=12))
        self.assertEqual(default_patch[13], 12)
        raw = bytearray(29)
        raw[0] = 0xAB
        existing_patch = bytes.fromhex(patch_dp102(raw, delay_minutes=13))
        self.assertEqual(existing_patch[0], 0xAB)
        self.assertEqual(existing_patch[13], 13)

    def test_remaining_codec_edge_paths(self) -> None:
        self.assertIsNone(decode_dp103(object()))
        self.assertEqual(recurrence_mask_to_text(0x80), "Once")
        self.assertEqual(recurrence_text_to_mask("once"), 0)
        self.assertEqual(recurrence_text_to_mask("EVERY DAY"), 0x7F)
        self.assertEqual(recurrence_text_to_mask("Tu / Th / Su"), 2 | 8 | 64)

        self.assertIsNone(decode_dp104(object()))
        dustbin = decode_dp104(bytes((0x05, 0xFF, 0)))
        assert dustbin is not None
        self.assertEqual(dustbin.calibration.value, 3)
        self.assertEqual(dustbin.cycle_count, 5)
        changed = replace(dustbin, calibration=0, cycle_count=10)  # type: ignore[arg-type]
        self.assertEqual(bytes.fromhex(encode_dp104(changed))[1:], bytes((0, 10)))

        self.assertIsNone(decode_dp105(object()))
        keys = KeySettings(lock_mask=0b0100)
        self.assertIs(with_key_lock(keys, -1, True), keys)
        self.assertEqual(with_key_lock(keys, 2, False).lock_mask, 0)
        self.assertFalse(keys.is_key_locked(4))

        self.assertIsNone(decode_dp106(object()))
        self.assertIsNone(decode_dp106(b""))

    def test_scalar_status_parsers_reject_ambiguous_values(self) -> None:
        self.assertEqual(decode_dp125_value(True), 1)
        self.assertEqual(decode_dp125_value(2.9), 2)
        self.assertEqual(decode_dp125_value("not-a-number"), 0)
        self.assertEqual(decode_dp125_value(object()), 0)

        self.assertEqual(decode_dp22(RecentActivity.CAT_LEFT), RecentActivity.CAT_LEFT)
        self.assertEqual(decode_dp22(11), RecentActivity.CLEANING_RESUMED)
        self.assertIsNone(decode_dp22(True))
        self.assertIsNone(decode_dp22("  "))
        self.assertIsNone(decode_dp22("unknown activity"))
        self.assertIsNone(decode_dp22(999))

    def test_mapping_and_scalar_snapshot_edge_cases(self) -> None:
        normalized = normalize_dp_mapping({"1": True, 2: False, "bad": "ignored"})
        self.assertEqual(normalized, {1: True, 2: False})

        snapshot = decode_snapshot(
            {
                6: True,
                7: 1.5,
                8: "",
                116: "not-a-number",
                152: 12.0,
                154: 3.5,
            }
        )
        self.assertIsNone(snapshot.cat_weight)
        self.assertIsNone(snapshot.daily_clean_count)
        self.assertIsNone(snapshot.clean_duration)
        self.assertIsNone(snapshot.total_use_time)
        self.assertEqual(snapshot.total_clean_count, 12)
        self.assertIsNone(snapshot.cat_toilet_time)

        float_snapshot = decode_snapshot({6: 4.5, 7: "2.0", 8: object()})
        self.assertEqual(float_snapshot.cat_weight, 4.5)
        self.assertEqual(float_snapshot.daily_clean_count, 2)
        self.assertIsNone(float_snapshot.clean_duration)

    def test_small_model_helpers(self) -> None:
        self.assertFalse(TimerSlice().has_schedule_data)
        self.assertTrue(TimerSlice(hour=1).has_schedule_data)
        self.assertIsNone(RecentActivity.IDLE.display_text)
        self.assertEqual(RecentActivity.CLEANING_RESUMED.display_text, "Cleaning resumed")

    def test_reference_helpers_expose_all_classifications(self) -> None:
        self.assertIn(DpAliasStatus.CURRENT_NOTIFICATION, statuses_for_value(112))
        self.assertEqual(statuses_for_value("does-not-exist"), frozenset())
        self.assertEqual(aliases_for_value("does-not-exist"), ())
        self.assertIsNone(wire_status("does-not-exist"))


if __name__ == "__main__":
    unittest.main()
