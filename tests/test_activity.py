from __future__ import annotations

import unittest

import pypopur
from pypopur.activity import (
    ACTIVITY_EVENT_TYPES,
    FAULT_EVENT_TYPES,
    ActivityEvent,
    extract_activity_events,
)
from pypopur.dps import FAULT_ITEMS
from pypopur.models import RecentActivity


class ActivityEventTypesTests(unittest.TestCase):
    def test_covers_every_non_idle_activity_in_enum_order(self) -> None:
        expected = tuple(a.name.lower() for a in RecentActivity if a is not RecentActivity.IDLE)
        self.assertEqual(ACTIVITY_EVENT_TYPES, expected)
        self.assertNotIn("idle", ACTIVITY_EVENT_TYPES)
        self.assertEqual(len(ACTIVITY_EVENT_TYPES), len(set(ACTIVITY_EVENT_TYPES)))
        self.assertEqual(
            ACTIVITY_EVENT_TYPES,
            (
                "cat_exist",
                "cat_left",
                "cat_done_business",
                "manual_clean_completed",
                "scheduled_clean_completed",
                "automatic_clean_completed",
                "bin_full",
                "self_check_completed",
                "cleaning_started",
                "cleaning_paused",
                "cleaning_resumed",
            ),
        )

    def test_fault_event_types(self) -> None:
        self.assertEqual(FAULT_EVENT_TYPES, ("fault_detected", "fault_cleared"))

    def test_package_exports(self) -> None:
        for name in (
            "ACTIVITY_EVENT_TYPES",
            "FAULT_EVENT_TYPES",
            "ActivityEvent",
            "extract_activity_events",
        ):
            self.assertIn(name, pypopur.__all__)
            self.assertTrue(hasattr(pypopur, name))


class Dp22Tests(unittest.TestCase):
    def test_string_value_as_captured(self) -> None:
        events = extract_activity_events({22: "cat_done_business"})
        self.assertEqual(
            events,
            [ActivityEvent(event_type="cat_done_business", dp=22, raw_value="cat_done_business")],
        )
        self.assertEqual(dict(events[0].attributes), {})

    def test_string_dp_key_from_mqtt_payload(self) -> None:
        events = extract_activity_events({"22": "cleaning_started"})
        self.assertEqual([e.event_type for e in events], ["cleaning_started"])

    def test_integer_value(self) -> None:
        events = extract_activity_events({22: 4})
        self.assertEqual([e.event_type for e in events], ["manual_clean_completed"])
        self.assertEqual(events[0].raw_value, 4)

    def test_misspelled_aliases(self) -> None:
        cases = {
            "auttomatic_clean_completed": "automatic_clean_completed",
            "bin_ful": "bin_full",
            "self-check completed": "self_check_completed",
            "clean_start": "cleaning_started",
            "cleanning_paused": "cleaning_paused",
            "cleaning_resume": "cleaning_resumed",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                events = extract_activity_events({22: raw})
                self.assertEqual([e.event_type for e in events], [expected])
                self.assertEqual(events[0].raw_value, raw)

    def test_every_activity_maps_to_its_event_type(self) -> None:
        for activity in RecentActivity:
            with self.subTest(activity=activity):
                events = extract_activity_events({22: int(activity)})
                if activity is RecentActivity.IDLE:
                    self.assertEqual(events, [])
                    continue
                self.assertEqual(
                    [e.event_type for e in events], [activity.name.lower()]
                )
                self.assertIn(events[0].event_type, ACTIVITY_EVENT_TYPES)

    def test_idle_yields_nothing(self) -> None:
        self.assertEqual(extract_activity_events({22: "idle"}), [])
        self.assertEqual(extract_activity_events({22: 0}), [])

    def test_unknown_yields_nothing_and_logs(self) -> None:
        with self.assertLogs("pypopur.activity", level="DEBUG") as logs:
            self.assertEqual(extract_activity_events({22: "teleported"}), [])
            self.assertEqual(extract_activity_events({22: 99}), [])
        self.assertEqual(len(logs.records), 2)

    def test_repeated_identical_value_still_fires(self) -> None:
        previous = {22: "cat_exist"}
        events = extract_activity_events({22: "cat_exist"}, previous)
        self.assertEqual([e.event_type for e in events], ["cat_exist"])
        again = extract_activity_events({22: "cat_exist"}, {22: "cat_exist"})
        self.assertEqual([e.event_type for e in again], ["cat_exist"])


class Dp125Tests(unittest.TestCase):
    def test_bit_raised(self) -> None:
        events = extract_activity_events({125: 0b10}, {125: 0})
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.event_type, "fault_detected")
        self.assertEqual(event.dp, 125)
        self.assertEqual(event.raw_value, 0b10)
        self.assertEqual(
            dict(event.attributes),
            {"fault": FAULT_ITEMS[1].label, "url": FAULT_ITEMS[1].url, "mask": 0b10},
        )

    def test_bit_cleared(self) -> None:
        events = extract_activity_events({125: 0}, {125: 1})
        self.assertEqual([e.event_type for e in events], ["fault_cleared"])
        self.assertEqual(events[0].attributes["fault"], "Error code A")
        self.assertEqual(events[0].attributes["mask"], 1)

    def test_multiple_bits_raised_and_cleared(self) -> None:
        # previous A+C, now C+D+E: A cleared, D and E raised (bit order).
        events = extract_activity_events({125: 0b11100}, {125: 0b00101})
        self.assertEqual(
            [(e.event_type, e.attributes["mask"]) for e in events],
            [("fault_cleared", 1), ("fault_detected", 8), ("fault_detected", 16)],
        )

    def test_hex_string_values(self) -> None:
        events = extract_activity_events({125: "3"}, {125: "1"})
        self.assertEqual(
            [(e.event_type, e.attributes["mask"]) for e in events], [("fault_detected", 2)]
        )

    def test_without_previous_yields_nothing(self) -> None:
        self.assertEqual(extract_activity_events({125: 0b111}), [])
        self.assertEqual(extract_activity_events({125: 0b111}, None), [])
        self.assertEqual(extract_activity_events({125: 0b111}, {22: "idle"}), [])

    def test_unchanged_yields_nothing(self) -> None:
        self.assertEqual(extract_activity_events({125: 5}, {125: 5}), [])
        self.assertEqual(extract_activity_events({125: "5"}, {125: 5}), [])


class OtherDpTests(unittest.TestCase):
    def test_dp101_alone_yields_nothing(self) -> None:
        self.assertEqual(extract_activity_events({101: "AQUAAwA="}), [])
        self.assertEqual(extract_activity_events({"101": "AQMAAw4="}, {101: "AQMAAw4="}), [])

    def test_other_dps_ignored(self) -> None:
        dps = {1: True, 7: 6, 15: 10, 108: "open", 116: 78514, 146: 26, 152: 194}
        self.assertEqual(extract_activity_events(dps, dps), [])

    def test_mixed_frame(self) -> None:
        events = extract_activity_events(
            {101: "AQUAAwA=", 22: "cat_done_business", 125: 0b1, 1: False},
            {101: "AQUAAwA=", 22: "cat_exist", 125: 0},
        )
        self.assertEqual([e.event_type for e in events], ["cat_done_business", "fault_detected"])
        self.assertEqual([e.dp for e in events], [22, 125])

    def test_empty(self) -> None:
        self.assertEqual(extract_activity_events({}), [])


if __name__ == "__main__":
    unittest.main()
