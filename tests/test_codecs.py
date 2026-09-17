from __future__ import annotations

import unittest
from dataclasses import replace

from pypopur.codec import decode_raw_bytes
from pypopur.dps import (
    FAULT_ITEMS,
    decode_dp22,
    decode_dp101,
    decode_dp102,
    decode_dp103,
    decode_dp104,
    decode_dp105,
    decode_dp106,
    decode_dp109_machine_status,
    decode_dp125,
    decode_dp125_value,
    decode_dp126_cat_presence,
    decode_notification_settings,
    decode_snapshot,
    encode_dp101,
    encode_dp102,
    encode_dp103,
    encode_dp104,
    encode_dp105,
    encode_dp106,
    encode_notification_settings,
    recurrence_mask_to_text,
    recurrence_text_to_mask,
    with_key_lock,
)
from pypopur.models import (
    BinStatus,
    CalibrationLevel,
    CatPresence,
    DustbinSettings,
    DustbinToggles,
    KeyGesture,
    MachineStatus,
    NotificationSettings,
    RecentActivity,
    RunModeReport,
    RunningStatus,
    TimePowerSettings,
    TimerSlice,
)


class RawCodecTests(unittest.TestCase):
    def test_app_compatible_raw_shapes(self) -> None:
        expected = bytes((0, 1, 254, 255))
        self.assertEqual(decode_raw_bytes(expected), expected)
        self.assertEqual(decode_raw_bytes(bytearray(expected)), expected)
        self.assertEqual(decode_raw_bytes("0001feff"), expected)
        self.assertEqual(decode_raw_bytes("00 01 FE ff"), expected)
        self.assertEqual(decode_raw_bytes("[0, 1, 254, 255]"), expected)
        self.assertEqual(decode_raw_bytes([0, 1, 254, 255]), expected)

    def test_invalid_hex_is_not_guessed(self) -> None:
        self.assertIsNone(decode_raw_bytes("abc"))
        self.assertIsNone(decode_raw_bytes("zz"))


class PackedDpTests(unittest.TestCase):
    def test_dp101_exact_layout_and_wire_spellings(self) -> None:
        report = RunModeReport(
            bin_status=BinStatus.BIN_FULL,
            running_status=RunningStatus.AUTOMATIC_CLEAN_COMPLETED,
            machine_status=MachineStatus.POWER_OFF,
            cat_presence=CatPresence.CAT_LEFT,
            countdown_minutes=255,
        )
        self.assertEqual(encode_dp101(report), "04050302ff")
        self.assertEqual(decode_dp101("04050302ff"), report)
        self.assertEqual(BinStatus.BIN_OPENED.value, "bin_opned")
        self.assertEqual(
            RunningStatus.AUTOMATIC_CLEAN_COMPLETED.value, "auttomatic_clean_completed"
        )

    def test_dp101_out_of_range_enums_fall_back_like_app(self) -> None:
        report = decode_dp101(bytes((99, 99, 99, 99, 7)))
        assert report is not None
        self.assertEqual(report.bin_status, BinStatus.NEAR_EMPTY)
        self.assertEqual(report.running_status, RunningStatus.IDLE)
        self.assertEqual(report.machine_status, MachineStatus.POWER_ON)
        self.assertEqual(report.cat_presence, CatPresence.NO_CAT)
        self.assertEqual(report.countdown_minutes, 7)

    def test_dp102_roundtrip_preserves_reserved_and_unknown_bits(self) -> None:
        raw = bytearray(29)
        raw[0] = 0xAA
        raw[9] = 0x12
        raw[10] = 10
        raw[11] = 5
        raw[12] = 1
        raw[13] = 60
        raw[14] = 7
        raw[15] = 0xF4  # -12 as signed byte
        raw[16] = 0xBB
        raw[17] = 1
        raw[18] = 0xFF
        raw[19] = 1
        raw[20] = 1
        raw[21] = 0
        raw[22] = 0xC7  # known weight bits + an unknown high bit
        raw[23] = 1
        raw[24] = 1
        raw[25] = 1
        raw[26] = 0x83  # enabled + 5X
        raw[27] = 0x0F
        raw[28] = 1

        settings = decode_dp102(bytes(raw))
        assert settings is not None
        self.assertEqual(settings.active_shield.sensitivity, 10)
        self.assertEqual(settings.active_shield.range, 5)
        self.assertTrue(settings.active_shield.anti_interference)
        self.assertEqual(settings.timezone_offset_hours, -12)
        self.assertEqual(settings.device_color, "black")
        self.assertTrue(settings.weight_functions.track_pet_data)
        self.assertTrue(settings.spin.reshuffle_enabled)
        self.assertEqual(settings.spin.reshuffle_oscillation, "5X")
        self.assertTrue(settings.detailed_notifications.pet_detected_enabled)
        self.assertTrue(settings.detailed_notifications_ext.cleaning_resumed_enabled)
        self.assertEqual(bytes.fromhex(encode_dp102(settings)), bytes(raw))

    def test_dp102_clamps_validation_fields_like_app(self) -> None:
        raw = bytearray(29)
        raw[10] = 0
        raw[11] = 99
        raw[13] = 0
        raw[14] = 0
        raw[15] = 100
        settings = decode_dp102(raw)
        assert settings is not None
        self.assertEqual(settings.active_shield.sensitivity, 5)
        self.assertEqual(settings.active_shield.range, 3)
        self.assertEqual(settings.delay_minutes, 5)
        self.assertEqual(settings.smooth_spread_count, 2)
        self.assertEqual(settings.timezone_offset_hours, 12)

    def test_dp103_layout_roundtrip_and_recurrence(self) -> None:
        settings = TimePowerSettings(
            power_on=TimerSlice(True, 0x15, 23, 59),
            power_off=TimerSlice(True, 0x7F, 6, 30),
            hibernate_start=True,
            hibernate_duration_minutes=255,
        )
        expected = bytes((1, 0x15, 23, 59, 1, 0x7F, 6, 30, 1, 255))
        self.assertEqual(bytes.fromhex(encode_dp103(settings)), expected)
        self.assertEqual(decode_dp103(expected), settings)
        self.assertEqual(recurrence_mask_to_text(0), "Once")
        self.assertEqual(recurrence_mask_to_text(0x7F), "Every day")
        self.assertEqual(recurrence_mask_to_text(0x15), "Mo | We | Fr")
        self.assertEqual(recurrence_text_to_mask("Mo | We | Fr"), 0x15)

    def test_dp103_encoder_clamps_time_fields(self) -> None:
        value = bytes.fromhex(
            encode_dp103(
                TimePowerSettings(
                    power_on=TimerSlice(True, 300, 99, 99),
                    hibernate_duration_minutes=999,
                )
            )
        )
        self.assertEqual(value[1:4], bytes((44, 23, 59)))
        self.assertEqual(value[9], 255)

    def test_dp104_defaults_partial_payload_and_roundtrip(self) -> None:
        cloud = decode_dp104("BQEF")
        assert cloud is not None
        self.assertEqual(cloud.cycle_count, 5)
        self.assertIsNone(decode_raw_bytes("idle"))

        defaults = decode_dp104(b"")
        assert defaults is not None
        self.assertTrue(defaults.toggles.bin_full_detection)
        self.assertTrue(defaults.toggles.keep_upright)
        self.assertEqual(defaults.calibration, CalibrationLevel.BALANCED)
        self.assertEqual(defaults.cycle_count, 5)

        partial = decode_dp104(bytes((0x02,)))
        assert partial is not None
        self.assertTrue(partial.toggles.allow_overfill)
        self.assertEqual(partial.calibration, CalibrationLevel.BALANCED)
        self.assertEqual(partial.cycle_count, 5)

        custom = DustbinSettings(
            toggles=DustbinToggles(True, True, False, True, True),
            calibration=CalibrationLevel.MAXIMUM,
            cycle_count=10,
            raw=bytes.fromhex("1b030a"),
        )
        self.assertEqual(encode_dp104(custom), "1b030a")
        self.assertEqual(decode_dp104("1b030a"), custom)
        self.assertEqual(CalibrationLevel.PRECISE.percent, 25)
        self.assertEqual(CalibrationLevel.MAXIMUM.label, "Maximum")

    def test_dp105_default_gestures_and_key_lock_mutation(self) -> None:
        defaults = decode_dp105(b"\x00")
        assert defaults is not None
        self.assertEqual(defaults.press, KeyGesture(True, 0))
        self.assertEqual(defaults.hold_3s, KeyGesture(True, 2))
        self.assertEqual(defaults.hold_7s, KeyGesture(True, 3))

        locked = with_key_lock(defaults, 2, True)
        self.assertTrue(locked.is_key_locked(2))
        self.assertEqual(encode_dp105(locked), "04010001020103")
        self.assertEqual(decode_dp105(encode_dp105(locked)), locked)

    def test_dp106_progress_and_raw_preservation(self) -> None:
        status = decode_dp106(bytes((250, 1, 2, 3, 4)))
        assert status is not None
        self.assertEqual(status.progress, 100)
        self.assertEqual(status.raw, bytes((250, 1, 2, 3, 4)))
        encoded = bytes.fromhex(encode_dp106(replace(status, progress=42)))
        self.assertEqual(encoded, bytes((42, 1, 2, 3, 4)))

    def test_dp125_hex_first_string_parser_and_fault_map(self) -> None:
        self.assertEqual(decode_dp125_value("10"), 0x10)
        self.assertEqual(decode_dp125_value(10), 10)
        faults = decode_dp125((1 << 0) | (1 << 25))
        self.assertEqual([fault.label for fault in faults], ["Error code A", "Error code Z"])
        self.assertEqual(faults[0].url, "https://popur.com/pages/s7-error-code-a")
        self.assertEqual(len(FAULT_ITEMS), 26)

    def test_dp22_accepts_exact_legacy_spellings_from_app(self) -> None:
        self.assertEqual(
            decode_dp22("auttomatic_clean_completed"), RecentActivity.AUTOMATIC_CLEAN_COMPLETED
        )
        self.assertEqual(decode_dp22("bin_ful"), RecentActivity.BIN_FULL)
        self.assertEqual(decode_dp22("0x0b"), RecentActivity.CLEANING_RESUMED)
        self.assertEqual(decode_dp22("cleanning_paused"), RecentActivity.CLEANING_PAUSED)
        self.assertEqual(RecentActivity.CAT_EXIST.display_text, "Pet detected")

    def test_dp109_scalar_machine_status_fallback(self) -> None:
        self.assertEqual(decode_dp109_machine_status("power_on"), MachineStatus.POWER_ON)
        self.assertEqual(
            decode_dp109_machine_status(MachineStatus.POWER_OFF), MachineStatus.POWER_OFF
        )
        self.assertIsNone(decode_dp109_machine_status("unknown"))
        snapshot = decode_snapshot({109: "hibernating"})
        self.assertIsNone(snapshot.run_mode)
        self.assertEqual(snapshot.machine_status, MachineStatus.HIBERNATING)

    def test_dp126_scalar_cat_presence_fallback(self) -> None:
        self.assertEqual(decode_dp126_cat_presence(1), CatPresence.CAT_EXIST)
        self.assertEqual(decode_dp126_cat_presence("cat_left"), CatPresence.CAT_LEFT)
        self.assertIsNone(decode_dp126_cat_presence(99))
        self.assertEqual(decode_snapshot({126: 3}).cat_presence, CatPresence.CAT_DONE_BUSINESS)

    def test_standalone_notification_dp_mapping(self) -> None:
        settings = NotificationSettings(
            master_enabled=True,
            pet_detected_enabled=True,
            cleaning_resumed_enabled=True,
            self_check_enabled=True,
        )
        wire = encode_notification_settings(settings)
        self.assertEqual(set(wire), {112, 113, 114, 115, 117, 118, 119, 120, 121, 122, 123, 124})
        self.assertEqual(decode_notification_settings(wire), settings)

    def test_snapshot_decodes_all_packed_objects_without_legacy_aliases(self) -> None:
        dps = {
            "6": "4.25",
            "7": "3",
            "8": 42,
            "12": "4",
            "15": 5,
            "19": "6",
            "22": "9",
            "101": "0100000000",
            "102": "00" * 29,
            "103": "00" * 10,
            "104": "050105",
            "105": "00010001020103",
            "106": "2a00000000",
            "112": True,
            "116": "120",
            "125": 3,
            "146": "7",
            "150": 8,
            "152": 500,
            "154": "17",
        }
        snapshot = decode_snapshot(dps)
        self.assertEqual(snapshot.run_mode.bin_status, BinStatus.NEAR_EMPTY)  # type: ignore[union-attr]
        self.assertEqual(snapshot.machine_status, MachineStatus.POWER_ON)
        self.assertEqual(snapshot.self_check.progress, 42)  # type: ignore[union-attr]
        self.assertEqual(snapshot.recent_activity, RecentActivity.CLEANING_STARTED)
        self.assertEqual(len(snapshot.self_check_faults), 2)
        self.assertTrue(snapshot.notifications.master_enabled)
        self.assertEqual(snapshot.cat_weight, 4.25)
        self.assertEqual(snapshot.daily_clean_count, 3)
        self.assertEqual(snapshot.clean_duration, 42)
        self.assertEqual(snapshot.automatic_clean_count, 4)
        self.assertEqual(snapshot.scheduled_clean_count, 5)
        self.assertEqual(snapshot.manual_clean_count, 6)
        self.assertEqual(snapshot.total_use_time, 120)
        self.assertEqual(snapshot.clean_count_after_full, 7)
        self.assertEqual(snapshot.fault_free_time, 8)
        self.assertEqual(snapshot.total_clean_count, 500)
        self.assertEqual(snapshot.cat_toilet_time, 17)
        with self.assertRaises(TypeError):
            snapshot.raw_dps[999] = True  # type: ignore[index]

    def test_dp102_unrelated_mutation_preserves_fallback_raw_bytes(self) -> None:
        raw = bytearray(29)
        raw[0] = 0xA5
        raw[10] = 0  # app displays fallback sensitivity=5
        raw[11] = 99  # app displays fallback range=3
        raw[22] = 0x80  # unknown weight-function bit
        settings = decode_dp102(raw)
        assert settings is not None
        updated = replace(settings, delay_minutes=10)
        encoded = bytes.fromhex(encode_dp102(updated))
        self.assertEqual(encoded[0], 0xA5)
        self.assertEqual(encoded[10], 0)
        self.assertEqual(encoded[11], 99)
        self.assertEqual(encoded[22], 0x80)
        self.assertEqual(encoded[13], 10)

    def test_dp104_mutation_preserves_unknown_switch_bits(self) -> None:
        settings = decode_dp104(bytes((0xE5, 1, 5)))
        assert settings is not None
        updated = replace(
            settings,
            toggles=replace(settings.toggles, allow_overfill=True),
        )
        self.assertEqual(bytes.fromhex(encode_dp104(updated))[0], 0xE7)


if __name__ == "__main__":
    unittest.main()
