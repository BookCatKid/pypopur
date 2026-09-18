"""Tests for reads.py beans and the PopurAccount typed read methods."""

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import AsyncMock

from pypopur.mobile import PopurAccount
from pypopur.reads import (
    DatapointStat,
    FirmwareModule,
    OperateLogEntry,
    TimerGroup,
    TimezoneInfo,
)


class _StubApi:
    """Minimal ``ThingMobileApi`` stand-in recording request args."""

    def __init__(self, result: Any) -> None:
        self.result = result
        self.request = AsyncMock(return_value=result)
        self.session = object()
        self.profile = None
        self.install_id = "install-id"

    @property
    def last_call(self) -> dict[str, Any]:
        args, kwargs = self.request.call_args
        return {"args": args, "kwargs": kwargs}


def _account(result: Any) -> tuple[PopurAccount, _StubApi]:
    api = _StubApi(result)
    return PopurAccount(api), api  # type: ignore[arg-type]


class BeanTests(unittest.TestCase):
    def test_operate_log_entry(self) -> None:
        entry = OperateLogEntry.from_json(
            {"dpId": 1, "timeStr": "2026-09-18 07:11:10", "value": "true"}
        )
        self.assertEqual(entry.dp_id, 1)
        self.assertEqual(entry.time_str, "2026-09-18 07:11:10")
        self.assertEqual(entry.value, "true")

    def test_firmware_module(self) -> None:
        mod = FirmwareModule.from_json(
            {
                "type": 0,
                "typeDesc": "Main Module",
                "currentVersion": "3.0.30",
                "upgradeStatus": 2,
            }
        )
        self.assertEqual(mod.module_type, 0)
        self.assertEqual(mod.type_desc, "Main Module")
        self.assertEqual(mod.current_version, "3.0.30")
        self.assertEqual(mod.upgrade_status, 2)

    def test_timezone_info_with_dst(self) -> None:
        tz = TimezoneInfo.from_json(
            {
                "timeZoneId": "America/Los_Angeles",
                "timeZone": "-08:00",
                "daylightSavingTimeResponse": {
                    "intervals": [
                        {"start": "s1", "end": "e1", "interval": "+01:00"},
                    ]
                },
            }
        )
        self.assertEqual(tz.time_zone, "-08:00")
        self.assertEqual(len(tz.dst_intervals), 1)
        self.assertEqual(tz.dst_intervals[0].interval, "+01:00")

    def test_timezone_info_without_dst(self) -> None:
        tz = TimezoneInfo.from_json({"timeZone": "-08:00"})
        self.assertEqual(tz.dst_intervals, ())

    def test_timer_group(self) -> None:
        group = TimerGroup.from_json(
            {
                "category": "cat1",
                "timerList": [
                    {"timerId": "t1", "time": "08:00", "loops": "1111111",
                     "dpId": 4, "status": 1}
                ],
            }
        )
        self.assertEqual(group.category, "cat1")
        self.assertEqual(len(group.timers), 1)
        self.assertEqual(group.timers[0].time, "08:00")
        self.assertEqual(group.timers[0].dp_id, 4)

    def test_datapoint_stat(self) -> None:
        stat = DatapointStat.from_json({"data": ["1", "2"], "total": "3"})
        self.assertEqual(stat.data, ("1", "2"))
        self.assertEqual(stat.total, "3")


class TypedReadTests(unittest.IsolatedAsyncioTestCase):
    async def test_device_events_sends_sp_param(self) -> None:
        account, api = _account(
            {
                "dps": [{"dpId": 1, "timeStr": "t", "timeStamp": 9, "value": "true"}],
                "dpc": [],
                "hasNext": True,
                "total": 1000,
            }
        )
        log = await account.device_events("dev1", dp_ids=[1, 4], limit=20, home_id=7)
        action, version, post = api.last_call["args"]
        self.assertEqual(action, "thing.m.smart.operate.all.log")
        self.assertEqual(version, "1.0")
        self.assertEqual(post["devId"], "dev1")
        self.assertEqual(post["dpIds"], "1,4")
        self.assertEqual(post["limit"], 20)
        self.assertEqual(post["sortType"], "DESC")
        # setSpRequest(true) → the sp=1 URL param.
        self.assertEqual(api.last_call["kwargs"]["url_params"], {"sp": "1"})
        self.assertEqual(api.last_call["kwargs"]["gid"], 7)
        self.assertEqual(log.entries[0].dp_id, 1)
        self.assertEqual(log.entries[0].time_stamp, 9)
        self.assertTrue(log.has_next)
        self.assertEqual(log.total, 1000)

    async def test_device_events_empty(self) -> None:
        account, _ = _account(None)
        log = await account.device_events("dev1")
        self.assertEqual(log.entries, ())
        self.assertFalse(log.has_next)

    async def test_firmware_info(self) -> None:
        account, api = _account(
            [{"type": 0, "typeDesc": "Main", "currentVersion": "3.0.30", "upgradeStatus": 2}]
        )
        mods = await account.firmware_info("dev1", home_id=7)
        self.assertEqual(api.last_call["args"][0], "thing.m.device.upgrade.info")
        self.assertEqual(api.last_call["kwargs"]["gid"], 7)
        self.assertEqual(mods[0].current_version, "3.0.30")

    async def test_device_meta_passthrough(self) -> None:
        account, _ = _account({"sdkVersion": "3.4.7", "capability": 1153})
        meta = await account.device_meta("dev1")
        self.assertEqual(meta["sdkVersion"], "3.4.7")

    async def test_biz_props(self) -> None:
        account, _ = _account(
            [{"devId": "dev1", "yuNetState": 2, "bluetoothCapability": "000120",
              "deviceUpgradeStatus": 0, "otaStatus": 2}]
        )
        props = await account.biz_props("dev1")
        self.assertEqual(props[0].dev_id, "dev1")
        self.assertEqual(props[0].yu_net_state, 2)
        self.assertEqual(props[0].bluetooth_capability, "000120")
        self.assertEqual(props[0].raw["otaStatus"], 2)

    async def test_device_timezone(self) -> None:
        account, api = _account({"timeZone": "-08:00"})
        tz = await account.device_timezone("dev1", lastest_years=3)
        self.assertEqual(api.last_call["args"][0], "thing.m.device.timezone.get")
        self.assertEqual(api.last_call["args"][2]["gwId"], "dev1")
        self.assertEqual(api.last_call["args"][2]["lastestYears"], 3)
        self.assertEqual(tz.time_zone, "-08:00")

    async def test_timers_empty(self) -> None:
        account, _ = _account([])
        self.assertEqual(await account.timers("dev1"), ())

    async def test_datapoint_stats_params(self) -> None:
        account, api = _account({"data": ["1"], "total": "1"})
        stat = await account.datapoint_stats(
            "dev1", dp_id=8, period="day", stat_type="sum",
            year="2026", month="9", day="18", number=30,
        )
        post = api.last_call["args"][2]
        self.assertEqual(api.last_call["args"][0], "m.smart.datapoint.stat")
        self.assertEqual(post["type"], "day")
        self.assertEqual(post["dpId"], 8)
        self.assertEqual(post["statType"], "sum")
        self.assertEqual(post["number"], 30)
        self.assertEqual(stat.data, ("1",))

    async def test_datapoint_stat_rank(self) -> None:
        account, api = _account("rank-3")
        rank = await account.datapoint_stat_rank("dev1", dp_id=8, day="20260918")
        post = api.last_call["args"][2]
        self.assertEqual(api.last_call["args"][0], "m.smart.datapoint.stat.oneday")
        self.assertEqual(post["statType"], "rank")
        self.assertEqual(post["day"], "20260918")
        self.assertEqual(rank, "rank-3")

    async def test_thing_model_caches(self) -> None:
        from pypopur.sdk.thing_model import ThingModelCache

        ThingModelCache.instance().clear()
        account, api = _account(
            {
                "productId": "pid1",
                "productVersion": "1.0.0",
                "services": [
                    {"code": "s", "properties": [], "events": [], "actions": []}
                ],
            }
        )
        model = await account.thing_model("pid1")
        self.assertEqual(api.last_call["args"][0], "thing.m.product.thing.model")
        self.assertEqual(api.last_call["args"][2]["productVersion"], "1.0.0")
        self.assertEqual(model.product_id, "pid1")
        # ddpdbbp$pbddddb — the parsed model lands in qpppdbb.
        self.assertIs(ThingModelCache.instance().get("pid1", "1.0.0"), model)


if __name__ == "__main__":
    unittest.main()
