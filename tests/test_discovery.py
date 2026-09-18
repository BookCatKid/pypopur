"""Parity tests for ``pypopur.sdk.discovery`` — GwBroadcastMonitorService
and ThingSmartHardwareManager (``qbdpdpp``)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pypopur.sdk.device_cache import (
    DeviceRespBean,
    DevListCacheManager,
    ProductBean,
    product_key,
)
from pypopur.sdk.discovery import (
    ActiveEnum,
    DeviceActiveEnum,
    GwBroadcastMonitor,
    HardwareManager,
    HgwBean,
    SaasSdkType,
    is_ap_directly_device_bean,
    is_valid_ip,
)


def _hgw(gw_id="gw1", ip="192.168.1.50", active=ActiveEnum.ACTIVED):
    return HgwBean(gw_id=gw_id, ip=ip, active=active)


class _Monitor:
    def __init__(self, fail=False):
        self.updates = []
        self.configs = []
        self.fail = fail

    def update(self, items):
        if self.fail:
            raise RuntimeError("RemoteException")
        self.updates.append(items)

    def on_config_result(self, config):
        if self.fail:
            raise RuntimeError("RemoteException")
        self.configs.append(config)


class _Hardware:
    """IThingHardware seam recorder."""

    def __init__(self):
        self.added = []  # (hgw, ips, local_key)
        self.put = []  # (gw_id, hgw)
        self.gw_map = {}

    def get_dev_id(self, dev_id):
        return self.gw_map.get(dev_id)

    def put_hgw_bean(self, gw_id, hgw):
        self.put.append((gw_id, hgw))
        self.gw_map[gw_id] = hgw

    def add_hgw(self, hgw, ips, local_key=None):
        self.added.append((hgw, ips, local_key))
        self.gw_map[hgw.gw_id] = hgw


class _Scheduler:
    def __init__(self):
        self.tasks = []  # (delay_ms, fn)

    def __call__(self, delay_ms, fn):
        self.tasks.append((delay_ms, fn))


class TestGwBroadcastMonitor(unittest.TestCase):
    def _monitor(self, **kw):
        sent = []
        stopped = []
        listened = []
        sched = _Scheduler()
        kw.setdefault("send_broadcast", lambda *a: sent.append(a) or len(sent))
        kw.setdefault("stop_broadcast", lambda t: stopped.append(t) or True)
        kw.setdefault("listen_udp", listened.append)
        kw.setdefault("local_ip", lambda: "192.168.1.10")
        kw.setdefault("schedule", sched)
        m = GwBroadcastMonitor(**kw)
        m._sent, m._stopped, m._listened, m._sched = sent, stopped, listened, sched
        return m

    # --- lifecycle --------------------------------------------------------

    def test_start_cas_and_ports(self):
        m = self._monitor()
        acquired = []
        m._acquire_multicast = lambda: acquired.append(1)
        sec = []
        m._set_security_content = sec.append
        self.assertTrue(m.start())
        self.assertFalse(m.finished)
        self.assertFalse(m.start())  # CAS fails second time
        self.assertEqual(acquired, [1])
        self.assertEqual(sec, [GwBroadcastMonitor.SECURITY_FALLBACK])
        self.assertEqual(m._listened, [6650, 6667, 7000])
        # periodic drain scheduled
        self.assertEqual(m._sched.tasks[-1][0], GwBroadcastMonitor.PERIOD_MS)

    def test_stop_releases(self):
        released, shutdown = [], []
        m = self._monitor(
            release_multicast=lambda: released.append(1), shutdown_udp=lambda: shutdown.append(1)
        )
        m.start()
        m.stop()
        self.assertTrue(m.finished)
        self.assertEqual(released, [1])
        self.assertEqual(shutdown, [1])

    # --- discovery broadcast -------------------------------------------------

    def test_send_discovery_payload_and_args(self):
        m = self._monitor()
        m.send_discovery()
        ((addr, port, period, data, ftype, ver, token),) = m._sent
        self.assertEqual(addr, "255.255.255.255")
        self.assertEqual(port, 7000)
        self.assertEqual(period, 6000)
        self.assertEqual(ftype, 0x25)
        self.assertEqual(ver, 5)
        self.assertEqual(token, 0)
        self.assertEqual(json.loads(data.decode("utf-8")), {"ip": "192.168.1.10", "from": "app"})
        self.assertEqual(m.broadcast_token, 1)

    def test_subnet_broadcast_scheduled_when_different(self):
        m = self._monitor(subnet_broadcast=lambda: "192.168.1.255")
        m.send_discovery()
        delay, fn = m._sched.tasks[0]
        self.assertEqual(delay, 3000)
        fn()
        self.assertEqual(len(m._sent), 2)
        self.assertEqual(m._sent[1][0], "192.168.1.255")
        self.assertEqual(m.subnet_broadcast_token, 2)

    def test_subnet_broadcast_skipped_when_same_or_null(self):
        m = self._monitor(subnet_broadcast=lambda: "255.255.255.255")
        m.send_discovery()
        self.assertEqual(m._sched.tasks, [])
        m2 = self._monitor(subnet_broadcast=lambda: None)
        m2.send_discovery()
        self.assertEqual(m2._sched.tasks, [])
        m3 = self._monitor(subnet_broadcast=lambda: (_ for _ in ()).throw(RuntimeError()))
        m3.send_discovery()
        self.assertEqual(m3._sched.tasks, [])

    def test_stop_discovery_resets_tokens(self):
        m = self._monitor()
        m.broadcast_token = 7
        m.subnet_broadcast_token = 9
        m.stop_discovery()
        self.assertEqual(m._stopped, [7, 9])
        self.assertEqual(m.broadcast_token, -1)
        self.assertEqual(m.subnet_broadcast_token, -1)

    def test_resend_stops_previous(self):
        m = self._monitor()
        m.send_discovery()
        m.send_discovery()
        self.assertEqual(m._stopped, [1])

    # --- gwMap dedup -----------------------------------------------------------

    def test_gw_map_same_id_overwrites(self):
        m = self._monitor()
        m.get_gw_bean(_hgw(gw_id="a", ip="1.1.1.1"))
        m.get_gw_bean(_hgw(gw_id="a", ip="2.2.2.2"))
        self.assertEqual(list(m.gw_map), ["a"])
        self.assertEqual(m.gw_map["a"].ip, "2.2.2.2")

    def test_gw_map_same_ip_different_id_evicts(self):
        m = self._monitor()
        m.get_gw_bean(_hgw(gw_id="a", ip="1.1.1.1"))
        m.get_gw_bean(_hgw(gw_id="b", ip="1.1.1.1"))
        self.assertEqual(list(m.gw_map), ["b"])

    # --- update drain ------------------------------------------------------------

    def test_update_tick_drains_and_notifies(self):
        m = self._monitor()
        m.finished = False
        mon = _Monitor()
        m.register_monitor(mon)
        m.get_gw_bean(_hgw())
        m.get_gw_bean(_hgw(gw_id="b", ip="192.168.1.51"))
        m.update_tick()
        self.assertEqual(len(mon.updates), 1)
        self.assertEqual({h.gw_id for h in mon.updates[0]}, {"gw1", "b"})
        self.assertEqual(m.gw_map, {})
        m.update_tick()  # empty — no further update
        self.assertEqual(len(mon.updates), 1)

    def test_update_tick_removes_dead_monitors(self):
        m = self._monitor()
        m.finished = False
        dead, alive = _Monitor(fail=True), _Monitor()
        m.register_monitor(dead)
        m.register_monitor(alive)
        m.get_gw_bean(_hgw())
        m.update_tick()
        self.assertNotIn(dead, m.monitors)
        self.assertIn(alive, m.monitors)
        self.assertEqual(len(alive.updates), 1)

    def test_update_tick_noop_when_finished(self):
        m = self._monitor()
        mon = _Monitor()
        m.register_monitor(mon)
        m.get_gw_bean(_hgw())
        m.update_tick()  # finished → nothing happens, map kept
        self.assertEqual(mon.updates, [])
        self.assertIn("gw1", m.gw_map)

    # --- smart config callback ---------------------------------------------------

    def test_config_result_dropped_when_finished(self):
        m = self._monitor()
        mon = _Monitor()
        m.register_monitor(mon)
        m.on_smart_config_result(5, 0, "cfg")
        self.assertEqual(mon.configs, [])

    def test_config_result_fanout_and_dead_removal(self):
        m = self._monitor()
        m.finished = False
        dead, alive = _Monitor(fail=True), _Monitor()
        m.register_monitor(dead)
        m.register_monitor(alive)
        m.on_smart_config_result(5, 0, "cfg")
        self.assertEqual(alive.configs, ["cfg"])
        self.assertNotIn(dead, m.monitors)


class TestHardwareManager(unittest.TestCase):
    def _manager(self, **kw):
        now = [100_000]
        kw.setdefault("clock_ms", lambda: now[0])
        m = HardwareManager(**kw)
        m._now = now
        return m

    def _dev_cache(self, *dev_ids, meta=None):
        cache = DevListCacheManager()
        for d in dev_ids:
            bean = DeviceRespBean()
            bean.dev_id = d
            bean.product_id = "pid"
            bean.product_ver = "1.0.0"
            bean.local_key = "k" * 16
            bean.meta = meta or {}
            cache.dev_map[d] = bean
        cache.products[product_key("pid", "1.0.0")] = ProductBean("pid")
        return cache

    # --- LAN backoff ------------------------------------------------------------

    def test_lan_backoff_disable_and_expiry(self):
        m = self._manager()
        m.record_lan_result(True, "d")
        for _ in range(3):  # fails <1s after the success → illegal
            m.record_lan_result(False, "d")
        self.assertTrue(m.is_lan_disabled("d"))  # stamps disabled_since
        m._now[0] += 119_999
        self.assertTrue(m.is_lan_disabled("d"))
        m._now[0] += 1
        self.assertFalse(m.is_lan_disabled("d"))  # window elapsed → cleared
        self.assertNotIn("d", m._lan_fail)

    def test_lan_fail_without_recent_success_not_illegal(self):
        m = self._manager()
        # last_ok never recorded (0): now-0 >= 1000 → never counts
        for _ in range(3):
            m.record_lan_result(False, "d")
        self.assertFalse(m.is_lan_disabled("d"))

    def test_lan_fail_outside_burst_window_not_illegal(self):
        m = self._manager()
        m.record_lan_result(True, "d")
        m._now[0] += 2000
        m.record_lan_result(False, "d")
        m._now[0] += 2000
        m.record_lan_result(False, "d")
        m._now[0] += 2000
        m.record_lan_result(False, "d")
        # each fail >1s after last success → illegal_times stays 0
        # (stale rule: lastFail-lastOk > 60s would drop — keep within it)
        self.assertFalse(m.is_lan_disabled("d"))

    def test_lan_stale_entry_removed(self):
        m = self._manager()
        m.record_lan_result(True, "d")
        m._now[0] += 61_000
        m.record_lan_result(False, "d")
        self.assertNotIn("d", m._lan_fail)

    def test_is_lan_disabled_empty_id(self):
        m = self._manager()
        self.assertFalse(m.is_lan_disabled(""))
        self.assertFalse(m.is_lan_disabled(None))

    # --- on_find routing -----------------------------------------------------------

    def test_on_find_actived_known_gw_adds_with_local_key(self):
        hw = _Hardware()
        cache = self._dev_cache("gw1")
        m = self._manager(hardware=hw, dev_cache=cache, products=cache.products)
        m.on_find([_hgw()])
        self.assertEqual(len(hw.added), 1)
        hgw, ips, key = hw.added[0]
        self.assertEqual(hgw.gw_id, "gw1")
        self.assertEqual(ips, 0)
        self.assertEqual(key, "k" * 16)

    def test_on_find_unknown_actived_gw_not_added(self):
        hw = _Hardware()
        m = self._manager(hardware=hw, dev_cache=self._dev_cache())
        m.on_find([_hgw()])
        self.assertEqual(hw.added, [])

    def test_on_find_local_unactive_plain_add(self):
        hw = _Hardware()
        m = self._manager(hardware=hw, dev_cache=self._dev_cache())
        m.on_find([_hgw(active=ActiveEnum.LOCAL_UNACTIVE)])
        self.assertEqual(len(hw.added), 1)
        self.assertIsNone(hw.added[0][2])

    def test_on_find_non_apdirect_local_actived_plain_add(self):
        hw = _Hardware()
        m = self._manager(hardware=hw, dev_cache=self._dev_cache("gw1"))
        m.on_find([_hgw(active=ActiveEnum.LOCAL_ACTIVED)])
        # plain addHgw (local actived, not AP-direct)
        self.assertEqual(len(hw.added), 1)
        self.assertIsNone(hw.added[0][2])

    def test_on_find_apdirect_local_actived_known_gw_keyed(self):
        hw = _Hardware()
        cache = self._dev_cache("gw1", meta={"isSupportDirectlyDevice": True})
        m = self._manager(hardware=hw, dev_cache=cache, products=cache.products)
        m.on_find([_hgw(active=ActiveEnum.LOCAL_ACTIVED)])
        # AP-direct + LOCAL_ACTIVED + checkGw → keyed add; skipped from plain
        self.assertEqual(len(hw.added), 1)
        self.assertEqual(hw.added[0][2], "k" * 16)

    def test_on_find_skips_invalid_ip_and_disabled(self):
        hw = _Hardware()
        m = self._manager(hardware=hw, dev_cache=self._dev_cache("gw1"))
        m.on_find([_hgw(ip="not-an-ip")])
        m.on_find([_hgw(ip="")])
        self.assertEqual(hw.added, [])
        m.record_lan_result(True, "gw1")
        for _ in range(3):
            m.record_lan_result(False, "gw1")
        m.is_lan_disabled("gw1")  # stamp window
        m.on_find([_hgw()])
        self.assertEqual(hw.added, [])

    def test_on_find_null_and_empty_guards(self):
        hw = _Hardware()
        m = self._manager(hardware=hw, dev_cache=self._dev_cache())
        m.on_find(None)
        m.on_find([None])
        HardwareManager(dev_cache=self._dev_cache()).on_find([_hgw()])
        self.assertEqual(hw.added, [])

    def test_on_find_construction_saas(self):
        hw = _Hardware()
        m = self._manager(
            hardware=hw, dev_cache=self._dev_cache(), saas_type=SaasSdkType.CONSTRUCTION
        )
        m.on_find([_hgw()])
        self.assertEqual(len(hw.added), 1)
        self.assertIsNone(hw.added[0][2])

    def test_on_find_cl_saas_put_hgw(self):
        hw = _Hardware()
        m = self._manager(
            hardware=hw, dev_cache=self._dev_cache("gw1"), saas_type=SaasSdkType.COMMERCIAL_LIGHTING
        )
        m.on_find([_hgw()])
        self.assertEqual(hw.put, [("gw1", hw.put[0][1])])
        self.assertEqual(hw.added, [])

    def test_on_find_search_listener_fanout(self):
        hw = _Hardware()

        class L:
            def __init__(self):
                self.found = []

            def on_device_find(self, gw_id, enum):
                self.found.append((gw_id, enum))

        l = L()
        m = self._manager(hardware=hw, dev_cache=self._dev_cache())
        m.add_search_listener(l)
        m.on_find([_hgw(active=ActiveEnum.ACTIVED)])
        self.assertEqual(l.found, [("gw1", "ACTIVED")])
        self.assertEqual(DeviceActiveEnum.to(4), None)

    # --- online updates --------------------------------------------------------

    def test_on_dev_update_event_and_fanout(self):
        events = []

        class L:
            def __init__(self):
                self.updates = []

            def on_device_online_status_update(self, hgw, online):
                self.updates.append((hgw.gw_id, online))

        l = L()
        m = self._manager(event_send=events.append)
        m.add_online_listener(l)
        hgw = _hgw()
        m.on_dev_update(hgw, True)
        self.assertEqual(events, [("dev_online_status", hgw, True)])
        self.assertEqual(l.updates, [("gw1", True)])

    # --- school-time sync ---------------------------------------------------------

    def test_school_time_sent_for_apdirect_local_actived(self):
        sends = []
        cache = self._dev_cache("gw1", meta={"isSupportDirectlyDevice": True})
        m = self._manager(
            dev_cache=cache,
            lan_send=lambda *a: sends.append(a),
            unix_ts=lambda: 1_700_000_000,
            time_zone=lambda: -8,
        )
        m.maybe_sync_school_time(_hgw(active=ActiveEnum.LOCAL_ACTIVED))
        self.assertEqual(len(sends), 1)
        gw, payload, ftype, _cb = sends[0]
        self.assertEqual(gw, "gw1")
        self.assertEqual(payload, {"timeStamp": 1_700_000_000, "timeZone": -8})
        self.assertEqual(ftype, 0x18)

    def test_school_time_skipped_otherwise(self):
        sends = []
        cache = self._dev_cache("gw1")
        m = self._manager(dev_cache=cache, lan_send=lambda *a: sends.append(a))
        m.maybe_sync_school_time(_hgw(active=ActiveEnum.LOCAL_ACTIVED))  # not AP-direct
        cache2 = self._dev_cache("gw1", meta={"isSupportDirectlyDevice": True})
        m2 = self._manager(dev_cache=cache2, lan_send=lambda *a: sends.append(a))
        m2.maybe_sync_school_time(_hgw(active=ActiveEnum.ACTIVED))  # not LOCAL_ACTIVED
        self.assertEqual(sends, [])

    # --- bean lookups --------------------------------------------------------------

    def test_get_local_key_gates(self):
        cache = self._dev_cache("gw1")
        m = self._manager(dev_cache=cache, products=cache.products)
        self.assertEqual(m.get_local_key("gw1"), "k" * 16)
        self.assertIsNone(m.get_local_key("nope"))
        cache.products.clear()
        self.assertIsNone(m.get_local_key("gw1"))

    def test_get_lpv_from_hardware(self):
        hw = _Hardware()
        hw.gw_map["gw1"] = _hgw()
        hw.gw_map["gw1"].version = "3.4"
        m = self._manager(hardware=hw)
        self.assertEqual(m.get_lpv("gw1"), "3.4")
        self.assertIsNone(m.get_lpv("nope"))
        self.assertIsNone(HardwareManager().get_lpv("gw1"))

    # --- helpers --------------------------------------------------------------------

    def test_is_ap_directly_device(self):
        self.assertFalse(is_ap_directly_device_bean(None))
        r = DeviceRespBean()
        self.assertFalse(is_ap_directly_device_bean(r))
        r.meta = {}
        self.assertFalse(is_ap_directly_device_bean(r))
        r.meta = {"isSupportDirectlyDevice": 0}  # presence, not truth
        self.assertTrue(is_ap_directly_device_bean(r))

    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("::1"))
        self.assertFalse(is_valid_ip("nope"))
        self.assertFalse(is_valid_ip(""))
        self.assertFalse(is_valid_ip(None))

    # --- devRespWrap hgw attach + checkGw ----------------------------------------------

    def test_dev_resp_wrap_attaches_hgw(self):
        hw = _Hardware()
        hw.gw_map["gw1"] = _hgw()
        cache = self._dev_cache("gw1")
        cache.hardware = hw
        bean = cache.dev_resp_wrap(cache.dev_map["gw1"], cache.products["pid_1.0.0"])
        self.assertIs(bean.hgw_bean, hw.gw_map["gw1"])
        cache2 = self._dev_cache("gw1")  # no hardware → stays None
        bean2 = cache2.dev_resp_wrap(cache2.dev_map["gw1"], cache2.products["pid_1.0.0"])
        self.assertIsNone(bean2.hgw_bean)

    def test_check_gw(self):
        cache = self._dev_cache("gw1")
        self.assertTrue(cache.check_gw(_hgw()))
        self.assertFalse(cache.check_gw(_hgw(gw_id="nope")))
        self.assertFalse(cache.check_gw(_hgw(gw_id="")))
        self.assertFalse(cache.check_gw(None))


if __name__ == "__main__":
    unittest.main()
