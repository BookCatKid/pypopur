"""Parity tests for the ``pypopur.app`` layer (com.popur.android ports)."""

from __future__ import annotations

import base64

import pytest

from pypopur.app import dp101, dp_string, helper, manager, repository, resolver


def _report_bytes(
    bin_idx: int = 1,
    running_idx: int = 1,
    machine_idx: int = 0,
    cat_idx: int = 0,
    countdown: int = 0,
) -> bytes:
    return bytes((bin_idx, running_idx, machine_idx, cat_idx, countdown))


class TestDecodeToBytes:
    def test_none(self) -> None:
        assert dp101.decode_to_bytes(None) is None

    def test_bytes_passthrough(self) -> None:
        assert dp101.decode_to_bytes(b"\x01\x02") == b"\x01\x02"

    def test_json_array(self) -> None:
        assert dp101.decode_to_bytes("[1, 2, 255]") == b"\x01\x02\xff"

    def test_json_array_skips_non_ints(self) -> None:
        assert dp101.decode_to_bytes("[1, x, 3]") == b"\x01\x03"

    def test_json_array_empty(self) -> None:
        assert dp101.decode_to_bytes("[]") == b""

    def test_json_array_all_invalid_fails_to_hex(self) -> None:
        # "[x]" fails array decode, then fails hex decode → None
        assert dp101.decode_to_bytes("[x]") is None

    def test_hex_string(self) -> None:
        assert dp101.decode_to_bytes("0102ff") == b"\x01\x02\xff"

    def test_hex_string_whitespace_and_case(self) -> None:
        assert dp101.decode_to_bytes("01 02 FF") == b"\x01\x02\xff"

    def test_hex_empty(self) -> None:
        assert dp101.decode_to_bytes("") == b""

    def test_hex_odd_length(self) -> None:
        assert dp101.decode_to_bytes("abc") is None

    def test_hex_invalid_chars(self) -> None:
        assert dp101.decode_to_bytes("zzzz") is None

    def test_no_base64(self) -> None:
        # "AQI=" is valid base64 but not valid hex — the APK decoder rejects it
        assert dp101.decode_to_bytes("AQI=") is None

    def test_collection_numbers(self) -> None:
        assert dp101.decode_to_bytes([1, "x", 255]) == b"\x01\xff"

    def test_collection_empty(self) -> None:
        assert dp101.decode_to_bytes([]) is None

    def test_collection_all_non_numeric(self) -> None:
        assert dp101.decode_to_bytes(["a", "b"]) is None

    def test_unsupported_type(self) -> None:
        assert dp101.decode_to_bytes(object()) is None

    def test_json_array_float_and_range_tokens_rejected(self) -> None:
        # toIntOrNull rejects floats and out-of-int32-range values, tokens
        # are skipped not fatal
        assert dp101.decode_to_bytes("[1.5,2]") == b"\x02"
        assert dp101.decode_to_bytes("[2147483648]") is None
        assert dp101.decode_to_bytes("[1_0]") is None

    def test_collection_intvalue_semantics(self) -> None:
        # Number.intValue(): float truncation toward zero, NaN→0,
        # saturation at int32 bounds, int wrap keeps the low byte
        assert dp101.decode_to_bytes([1.7, 2]) == b"\x01\x02"
        assert dp101.decode_to_bytes([-1.7]) == b"\xff"
        assert dp101.decode_to_bytes([float("nan")]) == b"\x00"
        assert dp101.decode_to_bytes([3e18]) == b"\xff"
        assert dp101.decode_to_bytes([-3e18]) == b"\x00"
        assert dp101.decode_to_bytes([2**40 + 1]) == b"\x01"
        assert dp101.decode_to_bytes([1 + 2j, 3]) == b"\x03"


class TestParseReport:
    def test_short_payload(self) -> None:
        assert dp101.parse_report(b"\x01\x02") is None

    def test_five_bytes(self) -> None:
        report = dp101.parse_report(_report_bytes(4, 1, 2, 3, 60))
        assert report is not None
        assert report.bin_status == "bin_full"
        assert report.running_status == "clean_start"
        assert report.machine_status == "disturb_mode"
        assert report.cat_presence == "cat_done_business"
        assert report.countdown_minutes == 60

    def test_invalid_indexes_fall_back(self) -> None:
        report = dp101.parse_report(_report_bytes(99, 99, 99, 99, 0))
        assert report is not None
        assert report.bin_status == "near_empty"
        assert report.running_status == "idle"
        assert report.machine_status == "power_on"
        assert report.cat_presence == "no_cat"

    def test_machine_status_string_shorthand(self) -> None:
        report = dp101.parse_report("hibernating")
        assert report == dp101.DEFAULT_REPORT.copy(machine_status="hibernating")

    def test_non_status_string_decodes_as_bytes(self) -> None:
        assert dp101.parse_report("0102030405") == dp101.parse_report(b"\x01\x02\x03\x04\x05")

    def test_extra_bytes_ignored(self) -> None:
        report = dp101.parse_report(_report_bytes(2, 3, 1, 2, 7) + b"\xff\xff")
        assert report is not None
        assert report.bin_status == "half_empty"
        assert report.running_status == "manual_clean_completed"


class TestEncodeReport:
    def test_exact_five_bytes(self) -> None:
        report = dp101.ParsedReport(
            bin_status="bin_full",
            running_status="clean_pause",
            machine_status="hibernating",
            cat_presence="cat_exist",
            countdown_minutes=42,
        )
        assert dp101.encode_report(report) == _report_bytes(4, 2, 1, 1, 42)

    def test_unknown_values_fall_back(self) -> None:
        report = dp101.ParsedReport(
            bin_status="???",
            running_status="???",
            machine_status="???",
            cat_presence="???",
            countdown_minutes=-5,
        )
        # bin fallback is index 1 (near_empty); the others fall back to 0
        assert dp101.encode_report(report) == _report_bytes(1, 0, 0, 0, 0)

    def test_countdown_clamped(self) -> None:
        report = dp101.ParsedReport(countdown_minutes=999)
        assert dp101.encode_report(report)[4] == 255


class TestApplyToMap:
    def test_empty_map_unchanged(self) -> None:
        d: dict = {}
        assert dp101.apply_to_map(d) == {}

    def test_copy_variant_returns_copy(self) -> None:
        src = {"101": _report_bytes()}
        out = dp101.normalized_copy(src)
        assert out is not src
        assert out["126"] == "no_cat"

    def test_decodable_101_string_kept(self) -> None:
        d = {"101": "0101010005"}  # valid hex — decodeToBytes succeeds
        dp101.apply_to_map(d)
        assert d["101"] == "0101010005"  # left as-is, not canonicalized
        assert d["126"] == "no_cat"

    def test_undecodable_101_reencoded(self) -> None:
        # a machine-status string parses as a report but cannot decode to bytes
        d = {"101": "power_on"}
        dp101.apply_to_map(d)
        assert d["101"] == _report_bytes(1, 0, 0, 0, 0)
        assert d["126"] == "no_cat"

    def test_unparseable_101_with_legacy_migrates(self) -> None:
        # legacy keys win: migrateLegacyKeys synthesizes canonical bytes first
        d = {"101": "zz", "24": "clean_start", "18": 5, "122": "bin_full"}
        dp101.apply_to_map(d)
        assert d["101"] == _report_bytes(4, 1, 0, 0, 5)
        assert "24" not in d and "18" not in d and "122" not in d

    def test_unparseable_101_alone_left_as_is(self) -> None:
        d = {"101": "zz", "122": "bin_full"}
        dp101.apply_to_map(d)
        assert d["101"] == "zz"
        assert "122" not in d

    def test_legacy_migration(self) -> None:
        d = {"24": "clean_start", "18": 5, "122": "bin_full", "126": "cat_exist"}
        dp101.apply_to_map(d)
        assert d["101"] == _report_bytes(4, 1, 0, 1, 5)
        assert d["126"] == "cat_exist"
        assert "24" not in d and "18" not in d and "122" not in d

    def test_existing_101_wins_over_legacy(self) -> None:
        d = {"101": _report_bytes(1, 0, 0, 0, 0), "24": "clean_start", "18": 9}
        dp101.apply_to_map(d)
        assert d["101"] == _report_bytes(1, 0, 0, 0, 0)

    def test_clean_control_true_resumes_pause(self) -> None:
        d = {"101": _report_bytes(1, 2, 0, 0, 0), "1": True}
        dp101.apply_to_map(d)
        report = dp101.parse_report(d["101"])
        assert report is not None
        assert report.running_status == "clean_start"
        assert d["1"] is True

    def test_clean_control_false_pauses_start(self) -> None:
        d = {"101": _report_bytes(1, 1, 0, 0, 0), "1": False}
        dp101.apply_to_map(d)
        report = dp101.parse_report(d["101"])
        assert report is not None
        assert report.running_status == "clean_pause"

    def test_clean_control_unrelated_running_kept(self) -> None:
        d = {"101": _report_bytes(1, 0, 0, 0, 0), "1": True}
        dp101.apply_to_map(d)
        assert d["101"] == _report_bytes(1, 0, 0, 0, 0)


class TestCleanControlParsing:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (True, True),
            (False, False),
            (1, True),
            (0, False),
            ("true", True),
            ("TRUE", True),
            ("1", True),
            ("0", False),
            ("yes", False),
            (None, None),
            (object(), None),
        ],
    )
    def test_values(self, value: object, expected: object) -> None:
        assert dp101.clean_control_from_dp_states({"1": value}) == expected

    def test_missing_and_empty(self) -> None:
        assert dp101.clean_control_from_dp_states(None) is None
        assert dp101.clean_control_from_dp_states({}) is None


class TestPatchDpStates:
    def test_none_args_retain_existing(self) -> None:
        d = {"101": _report_bytes(4, 2, 1, 3, 30)}
        out = dp101.patch_dp_states(d, running_status="idle")
        report = dp101.parse_report(out["101"])
        assert report is not None
        assert report.running_status == "idle"
        assert report.bin_status == "bin_full"
        assert report.machine_status == "hibernating"
        assert report.cat_presence == "cat_done_business"
        assert report.countdown_minutes == 30
        assert out["126"] == "cat_done_business"

    def test_unparseable_uses_default(self) -> None:
        out = dp101.patch_dp_states({"101": "zz"}, countdown_minutes=10)
        report = dp101.parse_report(out["101"])
        assert report is not None
        assert report == dp101.DEFAULT_REPORT.copy(countdown_minutes=10)


class TestPendingCleaningMerge:
    def _snapshot(self) -> dict:
        return {
            "101": _report_bytes(4, 2, 1, 1, 15),
            "1": False,
        }

    def test_incoming_empty(self) -> None:
        assert (
            dp101.merge_during_pending_cleaning_action(
                {}, self._snapshot(), "start_cleaning", "clean_start"
            )
            == {}
        )

    def test_action_not_pending(self) -> None:
        incoming = {"101": _report_bytes()}
        assert (
            dp101.merge_during_pending_cleaning_action(
                incoming, self._snapshot(), "other", "clean_start"
            )
            == incoming
        )

    def test_already_expected_status(self) -> None:
        incoming = {"101": _report_bytes(1, 1, 0, 0, 0)}
        assert (
            dp101.merge_during_pending_cleaning_action(
                incoming, self._snapshot(), "start_cleaning", "clean_start"
            )
            == incoming
        )

    def test_start_expected_but_incoming_pause(self) -> None:
        incoming = {"101": _report_bytes(1, 2, 0, 0, 0)}
        assert (
            dp101.merge_during_pending_cleaning_action(
                incoming, self._snapshot(), "start_cleaning", "clean_start"
            )
            == incoming
        )

    def test_start_cleaning_patches(self) -> None:
        incoming = {"101": _report_bytes(1, 0, 0, 0, 0)}
        out = dp101.merge_during_pending_cleaning_action(
            incoming, self._snapshot(), "start_cleaning", "clean_start"
        )
        report = dp101.parse_report(out["101"])
        assert report is not None
        assert report.running_status == "clean_start"
        # preserved from the snapshot
        assert report.machine_status == "hibernating"
        assert report.bin_status == "bin_full"
        assert report.cat_presence == "cat_exist"
        assert report.countdown_minutes == 15
        assert out["1"] is True
        assert out["126"] == "cat_exist"

    def test_continue_cleaning_resets_countdown(self) -> None:
        incoming = {"101": _report_bytes(1, 0, 0, 0, 0)}
        out = dp101.merge_during_pending_cleaning_action(
            incoming, self._snapshot(), "continue_cleaning", "clean_start"
        )
        report = dp101.parse_report(out["101"])
        assert report is not None
        assert report.countdown_minutes == 0

    def test_pause_cleaning_control_false(self) -> None:
        incoming = {"101": _report_bytes(1, 1, 0, 0, 0)}
        out = dp101.merge_during_pending_cleaning_action(
            incoming, self._snapshot(), "pause_cleaning", "clean_pause"
        )
        assert out["1"] is False
        report = dp101.parse_report(out["101"])
        assert report is not None
        assert report.running_status == "clean_pause"


class TestResolver:
    def test_merge_fill_missing(self) -> None:
        cloud = {"101": _report_bytes(), "2": "c"}
        cached = {"2": "old", "9": "cached"}
        out = resolver.merge_fill_missing(cloud, cached)
        assert out["2"] == "c"
        assert out["9"] == "cached"
        assert out["126"] == "no_cat"

    def test_merge_fill_missing_empty_cloud(self) -> None:
        cached = {"1": True}
        assert resolver.merge_fill_missing({}, cached) is cached

    def test_merge_with_timestamps_cloud_newer(self) -> None:
        cloud = {"101": _report_bytes(1, 0, 0, 0, 0), "1": True}
        cached = {"101": _report_bytes(4, 1, 0, 0, 30), "1": False, "7": "x"}
        out = resolver.merge_with_timestamps(cloud, cached, 200, 100)
        report = dp101.parse_report(out["101"])
        assert report is not None
        assert report.countdown_minutes == 0
        assert out["1"] is True
        assert out["7"] == "x"

    def test_merge_with_timestamps_stale_cloud_keeps_countdown(self) -> None:
        cloud = {"101": _report_bytes(1, 0, 0, 0, 0)}
        cached = {"101": _report_bytes(4, 1, 0, 0, 30)}
        out = resolver.merge_with_timestamps(cloud, cached, 100, 200)
        report = dp101.parse_report(out["101"])
        assert report is not None
        # cloud "101" is still force-copied (it is in the critical set)
        assert report.countdown_minutes == 0


class TestDeriveStatus:
    def test_offline(self) -> None:
        assert resolver.derive_status({"101": _report_bytes()}, False) == (
            resolver.DeviceStatus.OFFLINE,
            resolver.DeviceBinStatus.NEARLY_EMPTY,
        )

    def test_none_dps(self) -> None:
        assert resolver.derive_status(None, True) == (
            resolver.DeviceStatus.OFFLINE,
            resolver.DeviceBinStatus.NEARLY_EMPTY,
        )

    def test_fault_wins(self) -> None:
        status, _ = resolver.derive_status({"101": _report_bytes(1, 1, 0, 0, 0), "125": 4}, True)
        assert status == resolver.DeviceStatus.ERROR

    def test_do_not_disturb(self) -> None:
        status, _ = resolver.derive_status({"101": _report_bytes(1, 0, 2, 0, 0)}, True)
        assert status == resolver.DeviceStatus.DO_NOT_DISTURB

    def test_hibernating(self) -> None:
        status, _ = resolver.derive_status({"101": _report_bytes(1, 0, 1, 0, 0)}, True)
        assert status == resolver.DeviceStatus.HIBERNATING

    def test_countdown_to_start(self) -> None:
        status, _ = resolver.derive_status({"101": _report_bytes(1, 0, 0, 0, 30)}, True)
        assert status == resolver.DeviceStatus.CLEANING_TO_START

    def test_cleaning_in_progress(self) -> None:
        status, _ = resolver.derive_status({"101": _report_bytes(1, 1, 0, 0, 0)}, True)
        assert status == resolver.DeviceStatus.CLEANING_IN_PROGRESS

    def test_bin_full(self) -> None:
        status, bin_status = resolver.derive_status({"101": _report_bytes(4, 0, 0, 0, 0)}, True)
        assert status == resolver.DeviceStatus.PLEASE_EMPTY_BIN
        assert bin_status == resolver.DeviceBinStatus.BIN_FULL


class TestDpStringParser:
    def test_json_object(self) -> None:
        assert dp_string.parse_dp_string('{"1":true,"101":"abc"}') == {
            "1": True,
            "101": "abc",
        }

    def test_empty(self) -> None:
        assert dp_string.parse_dp_string("") == {}
        assert dp_string.parse_dp_string("   ") == {}

    def test_legacy_format(self) -> None:
        assert dp_string.parse_dp_string('"1":true,"2":42,"x":hello') == {
            "1": True,
            "2": 42,
            "x": "hello",
        }

    def test_legacy_braced(self) -> None:
        assert dp_string.parse_dp_string("{1:true,2:3.5}") == {
            "1": True,
            "2": 3.5,
        }

    def test_malformed(self) -> None:
        assert dp_string.parse_dp_string("not a map") == {}


class TestOrgJsonParser:
    """``parse_org_json_object`` mirrors AOSP libcore ``JSONTokener``."""

    def test_single_quoted(self) -> None:
        assert dp_string.parse_org_json_object("{'1':true}") == {"1": True}

    def test_unquoted_values(self) -> None:
        assert dp_string.parse_org_json_object("{a:xyz, b:hello}") == {
            "a": "xyz",
            "b": "hello",
        }

    def test_null_sentinel(self) -> None:
        result = dp_string.parse_org_json_object('{"a":null,"b":NULL}')
        assert result["a"] is dp_string.JSON_NULL
        assert result["b"] is dp_string.JSON_NULL

    def test_hex_and_octal_ints(self) -> None:
        assert dp_string.parse_org_json_object('{"a":0x10,"b":010,"c":0Xf}') == {
            "a": 16,
            "b": 8,
            "c": 15,
        }

    def test_number_forms(self) -> None:
        result = dp_string.parse_org_json_object(
            '{"i":-5,"z":-0,"e":5e3,"d":2.5,"f":7f,"big":9223372036854775807}'
        )
        assert result["i"] == -5
        assert result["z"] == 0
        assert result["e"] == 5000.0
        assert result["d"] == 2.5
        assert result["f"] == 7.0
        assert result["big"] == 9223372036854775807

    def test_long_overflow_becomes_double(self) -> None:
        result = dp_string.parse_org_json_object('{"a":9223372036854775808}')
        assert result["a"] == pytest.approx(9.223372036854776e18)

    def test_semicolon_separator(self) -> None:
        assert dp_string.parse_org_json_object('{"a":1;"b":2}') == {
            "a": 1,
            "b": 2,
        }

    def test_equals_and_arrow_separators(self) -> None:
        assert dp_string.parse_org_json_object('{"a"=1,"b"=>2,"c":>3}') == {
            "a": 1,
            "b": 2,
            "c": 3,
        }

    def test_comments(self) -> None:
        assert dp_string.parse_org_json_object('{/*c*/"a"//line\n:1, "b" # tail\n:2}') == {
            "a": 1,
            "b": 2,
        }

    def test_escapes(self) -> None:
        result = dp_string.parse_org_json_object(
            '{"a":"x\\ty","b":\'it\\\'s\',"c":"\\q","d":"\\u0041"}'
        )
        assert result == {"a": "x\ty", "b": "it's", "c": "q", "d": "A"}

    def test_nested(self) -> None:
        assert dp_string.parse_org_json_object('{"a":{"b":1},"c":[1,2]}') == {
            "a": {"b": 1},
            "c": [1, 2],
        }

    def test_array_missing_elements(self) -> None:
        result = dp_string.parse_org_json_object('{"a":[1,,2],"b":[1,],"c":[,]}')
        assert result["a"] == [1, dp_string.JSON_NULL, 2]
        assert result["b"] == [1, dp_string.JSON_NULL]
        assert result["c"] == [dp_string.JSON_NULL, dp_string.JSON_NULL]

    def test_trailing_garbage_ignored(self) -> None:
        assert dp_string.parse_org_json_object('{"a":1}oops') == {"a": 1}

    def test_bom_stripped(self) -> None:
        assert dp_string.parse_org_json_object('\ufeff{"a":1}') == {"a": 1}

    def test_non_string_key_rejected(self) -> None:
        with pytest.raises(ValueError):
            dp_string.parse_org_json_object("{1:2}")
        with pytest.raises(ValueError):
            dp_string.parse_org_json_object("{null:2}")
        with pytest.raises(ValueError):
            dp_string.parse_org_json_object("{true:2}")

    def test_trailing_comma_rejected(self) -> None:
        with pytest.raises(ValueError):
            dp_string.parse_org_json_object('{"a":1,}')

    def test_non_object_top_level_rejected(self) -> None:
        with pytest.raises(ValueError):
            dp_string.parse_org_json_object("[1,2]")
        with pytest.raises(ValueError):
            dp_string.parse_org_json_object('"just a string"')

    def test_dup_keys_last_wins(self) -> None:
        assert dp_string.parse_org_json_object('{"a":1,"a":2}') == {"a": 2}

    def test_parse_dp_string_falls_back_to_legacy(self) -> None:
        # org.json rejects the non-String key, then the legacy parser fills it.
        assert dp_string.parse_dp_string("{1:true, 2:3}") == {"1": True, "2": 3}


class TestSerializeDps:
    def test_basic(self) -> None:
        assert dp_string.serialize_dps({"1": True, "2": 3}) == '{"1":true,"2":3}'

    def test_bytes_to_base64(self) -> None:
        out = dp_string.serialize_dps({"101": b"\x01\x02"})
        assert out == '{"101":"' + base64.b64encode(b"\x01\x02").decode() + '"}'

    def test_strings_quoted(self) -> None:
        assert dp_string.serialize_dps({"a": "b"}) == '{"a":"b"}'

    def test_empty(self) -> None:
        assert dp_string.serialize_dps({}) == "{}"


class _Callback(manager.DeviceControlCallback):
    def __init__(self) -> None:
        self.errors: list[tuple[str, str]] = []
        self.successes = 0

    def on_error(self, code: str, error: str) -> None:
        self.errors.append((code, error))

    def on_success(self) -> None:
        self.successes += 1


class _Listener:
    def __init__(self) -> None:
        self.events: list[tuple] = []

    def on_dev_info_update(self, device_id: str) -> None:
        self.events.append(("info", device_id))

    def on_dp_update(self, device_id: str, dp_str: str) -> None:
        self.events.append(("dp", device_id, dp_str))

    def on_network_status_changed(self, device_id: str, online: bool) -> None:
        self.events.append(("net", device_id, online))

    def on_removed(self, device_id: str) -> None:
        self.events.append(("removed", device_id))

    def on_status_changed(self, device_id: str, online: bool) -> None:
        self.events.append(("status", device_id, online))


class _SdkDevice:
    def __init__(self) -> None:
        self.published: list = []
        self.listener = None
        self.dps = {"101": b"\x01\x00\x00\x00\x00"}

    def publish_dps(self, dps_json: str, callback) -> None:
        self.published.append(dps_json)
        callback.on_success()

    def register_dev_listener(self, listener) -> None:
        self.listener = listener

    def un_register_dev_listener(self) -> None:
        self.listener = None

    def get_dps(self):
        return self.dps


class _StrPublishDevice:
    """Device exposing only a 1-arg string publishDps (``o`` path)."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    def publish_dps(self, dps: str) -> None:
        self.sent.append(dps)


class _RawDevice:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def publish_raw(self, payload: bytes) -> None:
        self.calls.append(("raw", payload))


class TestUnifiedDeviceControlManager:
    def test_get_or_create_device(self) -> None:
        made = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: made)
        assert mgr.get_or_create_device("dev1") is made
        assert mgr.device_state("dev1") is not None
        assert mgr.device_state("dev1").online is False  # type: ignore[union-attr]

    def test_get_or_create_failure(self) -> None:
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: None)
        assert mgr.get_or_create_device("dev1") is None

    def test_send_command_device_not_found(self) -> None:
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: None)
        cb = _Callback()
        mgr.send_device_command("dev1", {"1": True}, cb)
        assert cb.errors == [(manager.DEVICE_NOT_FOUND, "设备实例初始化失败")]

    def test_send_command_sdk_publish(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        cb = _Callback()
        mgr.send_device_command("dev1", {"1": True}, cb)
        assert cb.successes == 1
        assert dev.published == ['{"1":true}']

    def test_send_command_string_publish(self) -> None:
        dev = _StrPublishDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        cb = _Callback()
        mgr.send_device_command("dev1", {"1": True}, cb)
        assert cb.successes == 1
        assert dev.sent == ['{"1":true}']

    def test_send_command_raw_bytes(self) -> None:
        dev = _RawDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        cb = _Callback()
        mgr.send_device_command("dev1", {"102": b"\x01\x02"}, cb)
        assert cb.successes == 1
        assert dev.calls == [("raw", b"\x01\x02")]

    def test_send_command_no_method(self) -> None:
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: object())
        cb = _Callback()
        mgr.send_device_command("dev1", {"1": True}, cb)
        assert cb.errors == [(manager.NO_CONTROL_METHOD, "无法找到可用的控制方法")]

    def test_register_listener_full(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        listener = _Listener()
        assert mgr.register_listener("dev1", listener) is True
        assert mgr.full_listener_flags["dev1"] is True
        assert mgr.device_state("dev1").g is True  # type: ignore[union-attr]
        # duplicate registration is a no-op returning True
        assert mgr.register_listener("dev1", listener) is True

    def test_dp_update_flows_to_listener(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        listener = _Listener()
        mgr.register_listener("dev1", listener)
        bridge = mgr.listener_bridges["dev1"]
        bridge.onDpUpdate("dev1", '{"1":true}')
        assert listener.events == [("dp", "dev1", '{"1":true}')]
        state = mgr.device_state("dev1")
        assert state is not None
        assert state.dp_data["1"] is True

    def test_network_status_updates_e_flag(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        listener = _Listener()
        mgr.register_listener("dev1", listener)
        bridge = mgr.listener_bridges["dev1"]
        bridge.onNetworkStatusChanged("dev1", False)
        state = mgr.device_state("dev1")
        assert state is not None
        assert state.e is False
        assert state.online is False  # b field untouched by this callback
        assert ("net", "dev1", False) in listener.events
        bridge.onNetworkStatusChanged("dev1", True)
        assert mgr.device_state("dev1").e is True  # type: ignore[union-attr]

    def test_status_changed_updates_online(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        listener = _Listener()
        mgr.register_listener("dev1", listener)
        bridge = mgr.listener_bridges["dev1"]
        bridge.onStatusChanged("dev1", True)
        state = mgr.device_state("dev1")
        assert state is not None
        assert state.online is True

    def test_on_removed_cleans_up(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        listener = _Listener()
        mgr.register_listener("dev1", listener)
        bridge = mgr.listener_bridges["dev1"]
        bridge.onRemoved("dev1")
        assert "dev1" not in mgr.device_instances
        assert mgr.device_state("dev1") is None
        # app quirk: the listener set is removed before the fan-out, so
        # onRemoved never reaches app listeners
        assert ("removed", "dev1") not in listener.events

    def test_unregister_listener(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        listener = _Listener()
        mgr.register_listener("dev1", listener)
        assert mgr.unregister_listener("dev1", listener) is True
        assert "dev1" not in mgr.app_listeners
        assert dev.listener is None

    def test_unregister_unknown_listener(self) -> None:
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: _SdkDevice())
        assert mgr.unregister_listener("dev1", _Listener()) is False

    def test_query_device_dp(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        mgr.get_or_create_device("dev1")
        cb = _Callback()
        assert mgr.query_device_dp(dev, cb) is True
        assert cb.successes == 1
        # getDevId is absent and the device matches instance "dev1"
        state = mgr.device_state("dev1")
        assert state is not None
        assert state.online is True
        assert state.dp_data["101"] == b"\x01\x00\x00\x00\x00"

    def test_query_device_dp_empty(self) -> None:
        dev = _SdkDevice()
        dev.dps = {}
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        cb = _Callback()
        assert mgr.query_device_dp(dev, cb) is False

    def test_batch_query(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        cb = _Callback()
        mgr.batch_query_dps("dev1", cb)
        assert cb.successes == 1


class TestHelper:
    @pytest.mark.asyncio
    async def test_send_device_command_success(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        repo = repository.DeviceRepository()
        h = helper.UnifiedDeviceControlHelper(mgr, repo)
        await h.send_device_command("dev1", {"1": True})

    @pytest.mark.asyncio
    async def test_send_device_command_null_rejected(self) -> None:
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: _SdkDevice())
        h = helper.UnifiedDeviceControlHelper(mgr, repository.DeviceRepository())
        with pytest.raises(ValueError):
            await h.send_device_command("dev1", {"1": None})

    @pytest.mark.asyncio
    async def test_send_device_command_failure_raises(self) -> None:
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: None)
        h = helper.UnifiedDeviceControlHelper(mgr, repository.DeviceRepository())
        with pytest.raises(helper.DeviceCommandError) as exc:
            await h.send_device_command("dev1", {"1": True})
        assert exc.value.code == manager.DEVICE_NOT_FOUND

    @pytest.mark.asyncio
    async def test_post_write_hook_merges_critical(self) -> None:
        dev = _SdkDevice()
        mgr = manager.UnifiedDeviceControlManager(device_factory=lambda d: dev)
        device = repository.RepositoryDevice("dev1", online=True)
        repo = repository.DeviceRepository(device_lookup=lambda d: device)
        h = helper.UnifiedDeviceControlHelper(mgr, repo)
        await h.send_device_command("dev1", {"1": True})
        assert repo.dp_states["dev1"]["1"] is True


class TestRepository:
    @pytest.mark.asyncio
    async def test_update_device_dps_merges(self) -> None:
        device = repository.RepositoryDevice("dev1", online=True, dps_data={"102": b"\x00" * 20})
        repo = repository.DeviceRepository(device_lookup=lambda d: device)
        await repo.update_device_dps("dev1", {"101": _report_bytes(1, 1, 0, 0, 5)})
        merged = repo.dp_states["dev1"]
        assert merged["101"] == _report_bytes(1, 1, 0, 0, 5)
        assert merged["102"] == b"\x00" * 20  # preserved from device record
        assert merged["126"] == "no_cat"

    @pytest.mark.asyncio
    async def test_update_device_dps_unknown_device(self) -> None:
        repo = repository.DeviceRepository()
        await repo.update_device_dps("ghost", {"1": True})
        assert "ghost" not in repo.dp_states

    @pytest.mark.asyncio
    async def test_clean_start_clears_stale_cat_exist(self) -> None:
        device = repository.RepositoryDevice("dev1", online=True)
        repo = repository.DeviceRepository(device_lookup=lambda d: device)
        repo.dp_states["dev1"] = {"126": "cat_exist"}
        await repo.update_device_dps("dev1", {"101": _report_bytes(1, 1, 0, 0, 0)})
        # apply_to_map derives 126 into the incoming map, so the stale
        # cat_exist is overwritten by the critical-DP force-copy
        assert repo.dp_states["dev1"]["126"] == "no_cat"

    @pytest.mark.asyncio
    async def test_p_empty_dps_noop(self) -> None:
        repo = repository.DeviceRepository()
        await repo.on_command_sent("dev1", {})
        assert repo.dp_states == {}


class TestCleaningProgress:
    @pytest.fixture(autouse=True)
    def _clock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(repository, "_now_ms", lambda: 1_000_000)

    def _repo(self) -> repository.DeviceRepository:
        device = repository.RepositoryDevice("dev1", online=True)
        return repository.DeviceRepository(device_lookup=lambda d: device)

    @pytest.mark.asyncio
    async def test_clean_start_creates_metadata(self) -> None:
        repo = self._repo()
        await repo.sync_cleaning_progress_from_dp("dev1", {"101": _report_bytes(1, 1, 0, 0, 0)})
        meta = repo.cleaning_progress["dev1"]
        assert meta.started_at == 1_000_000
        assert meta.expected_duration_seconds == 80
        assert meta.progress_percent == 0.0
        assert meta.last_updated_at == 1_000_000
        assert repo.cleaning_start_times["dev1"] == 1_000_000
        assert "dev1" not in repo.cleaning_elapsed_seconds
        store = repo._datastore
        assert store["cleaning_start_time_dev1"] == 1_000_000
        persisted = repository.cleaning_progress_from_json(store["cleaning_progress_state_dev1"])
        assert persisted == meta

    @pytest.mark.asyncio
    async def test_clean_start_resets_completed_metadata(self) -> None:
        repo = self._repo()
        repo.cleaning_progress["dev1"] = repository.CleaningProgressMetadata(
            progress_percent=100.0,
            expected_duration_seconds=80,
            completed_at=900_000,
            last_updated_at=900_000,
        )
        await repo.sync_cleaning_progress_from_dp("dev1", {"101": _report_bytes(1, 1, 0, 0, 0)})
        meta = repo.cleaning_progress["dev1"]
        assert meta.started_at == 1_000_000
        assert meta.completed_at is None
        assert meta.progress_percent == 0.0
        assert repo._datastore["cleaning_start_time_dev1"] == 1_000_000

    @pytest.mark.asyncio
    async def test_clean_pause_banks_elapsed_and_clears_start(self) -> None:
        repo = self._repo()
        repo.cleaning_progress["dev1"] = repository.CleaningProgressMetadata(
            started_at=940_000,
            expected_duration_seconds=80,
            last_updated_at=990_000,
        )
        repo.cleaning_start_times["dev1"] = 940_000
        await repo.sync_cleaning_progress_from_dp("dev1", {"101": _report_bytes(1, 2, 0, 0, 0)})
        meta = repo.cleaning_progress["dev1"]
        # (1_000_000 - 940_000) / 1000 = 60s elapsed, 60/80 → 75%
        assert meta.started_at is None
        assert meta.last_paused_at == 1_000_000
        assert meta.elapsed_before_pause_seconds == 60.0
        assert meta.progress_percent == 75.0
        assert "dev1" not in repo.cleaning_start_times
        assert repo.cleaning_elapsed_seconds["dev1"] == 60.0

    @pytest.mark.asyncio
    async def test_done_status_removes_progress_but_keeps_mirrors(self) -> None:
        repo = self._repo()
        repo.cleaning_progress["dev1"] = repository.CleaningProgressMetadata(
            started_at=940_000,
            expected_duration_seconds=80,
            last_updated_at=990_000,
        )
        repo.cleaning_start_times["dev1"] = 940_000
        repo.cleaning_elapsed_seconds["dev1"] = 30.0
        repo._datastore["cleaning_start_time_dev1"] = 940_000
        repo._datastore["cleaning_progress_state_dev1"] = "{}"
        await repo.sync_cleaning_progress_from_dp("dev1", {"101": _report_bytes(1, 3, 0, 0, 0)})
        assert "dev1" not in repo.cleaning_progress
        assert "cleaning_start_time_dev1" not in repo._datastore
        assert "cleaning_progress_state_dev1" not in repo._datastore
        # ``c0`` only drops ``x`` — the ``r``/``B`` mirrors keep stale entries.
        assert repo.cleaning_start_times["dev1"] == 940_000
        assert repo.cleaning_elapsed_seconds["dev1"] == 30.0

    @pytest.mark.asyncio
    async def test_recently_updated_skips_recalc_but_syncs_expected(
        self,
    ) -> None:
        repo = self._repo()
        repo.cleaning_progress["dev1"] = repository.CleaningProgressMetadata(
            started_at=500_000,
            progress_percent=42.0,
            expected_duration_seconds=60,
            last_updated_at=999_000,
        )
        await repo.sync_cleaning_progress_from_dp("dev1", {"101": _report_bytes(1, 1, 0, 0, 0)})
        meta = repo.cleaning_progress["dev1"]
        # Only expectedDurationSeconds is rewritten; lastUpdatedAt preserved.
        assert meta.expected_duration_seconds == 80
        assert meta.progress_percent == 42.0
        assert meta.last_updated_at == 999_000

    @pytest.mark.asyncio
    async def test_recently_updated_same_expected_noop(self) -> None:
        repo = self._repo()
        repo.cleaning_progress["dev1"] = repository.CleaningProgressMetadata(
            started_at=500_000,
            expected_duration_seconds=80,
            last_updated_at=999_500,
        )
        await repo.sync_cleaning_progress_from_dp("dev1", {"101": _report_bytes(1, 1, 0, 0, 0)})
        assert "cleaning_progress_state_dev1" not in repo._datastore

    @pytest.mark.asyncio
    async def test_spread_seven_gives_205_seconds(self) -> None:
        repo = self._repo()
        await repo.sync_cleaning_progress_from_dp(
            "dev1",
            {"101": _report_bytes(1, 1, 0, 0, 0), "__dp102_setting_smooth__": 7},
        )
        assert repo.cleaning_progress["dev1"].expected_duration_seconds == 205

    @pytest.mark.asyncio
    async def test_other_status_only_syncs_expected(self) -> None:
        repo = self._repo()
        repo.cleaning_progress["dev1"] = repository.CleaningProgressMetadata(
            started_at=500_000,
            expected_duration_seconds=60,
            last_updated_at=900_000,
        )
        await repo.sync_cleaning_progress_from_dp("dev1", {"101": _report_bytes(1, 0, 0, 0, 0)})
        meta = repo.cleaning_progress["dev1"]
        assert meta.expected_duration_seconds == 80
        assert meta.last_updated_at == 1_000_000
        assert meta.started_at == 500_000

    @pytest.mark.asyncio
    async def test_empty_meta_q0_clears_maps_and_store(self) -> None:
        repo = self._repo()
        repo.cleaning_progress["dev1"] = repository.CleaningProgressMetadata()
        repo.cleaning_start_times["dev1"] = 1
        repo.cleaning_elapsed_seconds["dev1"] = 2.0
        repo._datastore["cleaning_progress_state_dev1"] = "{}"
        await repo.update_cleaning_progress(
            "dev1", repository.EMPTY_CLEANING_PROGRESS, persist=True
        )
        assert "dev1" not in repo.cleaning_progress
        assert "dev1" not in repo.cleaning_start_times
        assert "dev1" not in repo.cleaning_elapsed_seconds
        assert "cleaning_progress_state_dev1" not in repo._datastore

    @pytest.mark.asyncio
    async def test_update_device_dps_runs_progress_sync(self) -> None:
        repo = self._repo()
        await repo.update_device_dps("dev1", {"101": _report_bytes(1, 1, 0, 0, 0)})
        assert repo.cleaning_progress["dev1"].started_at == 1_000_000

    def test_metadata_predicates(self) -> None:
        meta = repository.CleaningProgressMetadata
        assert meta(started_at=1).is_active()
        assert meta(started_at=1, completed_at=2).is_completed()
        assert meta(started_at=1, last_paused_at=2).is_active()
        assert meta(last_paused_at=2).is_paused()
        assert not meta(completed_at=2).is_paused()
        assert meta().is_empty()
        assert meta(last_updated_at=9).is_empty()
        assert repository.EMPTY_CLEANING_PROGRESS.is_empty()

    def test_progress_json_round_trip_and_null_omission(self) -> None:
        meta = repository.CleaningProgressMetadata(
            started_at=123,
            elapsed_before_pause_seconds=4.5,
            progress_percent=30.0,
            expected_duration_seconds=80,
            last_updated_at=999,
        )
        text = repository.cleaning_progress_to_json(meta)
        assert "lastPausedAt" not in text
        assert "completedAt" not in text
        assert repository.cleaning_progress_from_json(text) == meta
        assert repository.cleaning_progress_from_json("not json") is None
