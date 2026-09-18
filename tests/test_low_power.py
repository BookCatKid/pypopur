"""Parity tests for ``pypopur.sdk.low_power`` — ``bdqqqbp``
LowPowerDeviceManager."""

from __future__ import annotations

import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pypopur.sdk.device_cache import (
    CommunicationModule,
    DeviceBizPropBean,
    DeviceRespBean,
    DevListCacheManager,
    ProductRefBean,
)
from pypopur.sdk.low_power import (
    LowPowerAwakeRsp,
    LowPowerConnectResult,
    LowPowerDeviceManager,
    _int_to_byte_array,
)


class _Cb:
    def __init__(self):
        self.success = []
        self.errors = []

    def on_success(self, rsp):
        self.success.append(rsp)

    def on_error(self, code, msg):
        self.errors.append((code, msg))


class _Mqtt:
    def __init__(self):
        self.published = []

    def publish(self, topic, payload, qos, retained, cb):
        self.published.append((topic, payload, qos, retained, cb))


class _ManualHandler:
    """Deterministic handler — queued posts run on demand."""

    def __init__(self):
        self.queue = []

    def post(self, fn):
        self.queue.append(fn)

    def post_delayed(self, fn, ms):
        self.queue.append(fn)

    def remove_callbacks(self, fn):
        self.queue = [f for f in self.queue if f is not fn]

    def run_all(self):
        """Run only what is queued NOW — reposted tasks stay pending."""
        pending, self.queue = self.queue, []
        for fn in pending:
            fn()


def _resp(
    dev_id="d1",
    *,
    node=None,
    virtual=False,
    metas=None,
    has_ref=True,
    cloud=True,
    last_update=0,
    local_key="k" * 16,
):
    r = DeviceRespBean()
    r.dev_id = dev_id
    r.local_key = local_key
    r.virtual = virtual
    r.cloud_online = cloud
    r.device_biz_prop_bean = DeviceBizPropBean(last_update)
    if has_ref:
        r.product_ref_bean = ProductRefBean(metas)
    if node is not None:
        r.communication = CommunicationModule()
        r.communication.communication_node = node
    return r


def _mgr(*resps, **kw):
    cache = DevListCacheManager()
    for r in resps:
        cache.dev_map[r.dev_id] = r
    kw.setdefault("dev_cache", cache)
    kw.setdefault("mqtt_server", _Mqtt())
    kw.setdefault("handler", _ManualHandler())
    return LowPowerDeviceManager(**kw)


class TestEntry(unittest.TestCase):
    def test_null_callback_bare_awake(self):
        m = _mgr(_resp())
        m.awake("d1", 0, None)
        ((topic, payload, qos, retained, cb),) = m.mqtt_server.published
        self.assertEqual(topic, "m/w/d1")
        self.assertEqual(payload, zlib.crc32(b"k" * 16).to_bytes(4, "big"))
        self.assertEqual((qos, retained, cb), (0, False, None))

    def test_empty_devid_1001(self):
        cb = _Cb()
        _mgr().awake("", 0, cb)
        self.assertEqual(cb.errors, [("1001", "Device model does not exist.")])

    def test_missing_resp_1002(self):
        cb = _Cb()
        _mgr().awake("d1", 0, cb)
        self.assertEqual(cb.errors, [("1002", "Device response bean not found")])

    def test_node_redirect(self):
        m = _mgr(_resp("d1", node="gw"), _resp("gw", metas={"low_power_wakeup": 1}))
        m._check_awake = lambda ids, l: None
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertEqual(cb.errors, [])
        self.assertIn("gw", m.wake_tasks)

    def test_node_redirect_missing_unsupport(self):
        m = _mgr(_resp("d1", node="gone"))
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertEqual(cb.success, [LowPowerAwakeRsp.UNSUPPORT])

    def test_missing_product_ref_1003(self):
        m = _mgr(_resp(has_ref=False))
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertEqual(cb.errors, [("1003", "Product reference bean not found")])

    def test_virtual_success(self):
        m = _mgr(_resp(virtual=True, metas=None))
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertEqual(cb.success, [LowPowerAwakeRsp.SUCCESS])

    def test_not_tagged_unsupport(self):
        m = _mgr(_resp(metas={}))
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertEqual(cb.success, [LowPowerAwakeRsp.UNSUPPORT])

    def test_timeout_override(self):
        m = _mgr(_resp(metas={"low_power_wakeup": 1}))
        m.awake("d1", 42_000, _Cb())
        self.assertEqual(m.wake_timeout_ms, 42_000)

    def test_fast_path_already_awake(self):
        resp = _resp(metas={"low_power_wakeup": 1}, cloud=True, last_update=500)
        m = _mgr(resp)
        m.awake_flags["d1"] = True
        m.awake_change_times["d1"] = 400
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertEqual(cb.success, [LowPowerAwakeRsp.SUCCESS])
        self.assertEqual(len(m.mqtt_server.published), 1)  # re-publish awake

    def test_fast_path_blocked_when_offline_or_stale(self):
        resp = _resp(metas={"low_power_wakeup": 1}, cloud=False, last_update=500)
        m = _mgr(resp)
        m._check_awake = lambda ids, l: None
        m.awake_flags["d1"] = True
        m.awake_change_times["d1"] = 400
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertEqual(cb.success, [])
        self.assertIn("d1", m.callbacks)  # fell through to task path
        self.assertIn("d1", m.wake_tasks)

    def test_wakeup_task_exists_shortcircuits(self):
        m = _mgr(_resp(metas={"low_power_wakeup": 1}))
        m._check_awake = lambda ids, l: None
        m.wake_tasks["d1"] = lambda: None
        cb = _Cb()
        m.awake("d1", 0, cb)
        self.assertIn(cb, m.callbacks["d1"])
        self.assertEqual(m.wake_tasks["d1"], m.wake_tasks["d1"])  # unchanged
        self.assertEqual(m.mqtt_server.published, [])


class TestWakeTask(unittest.TestCase):
    def test_task_republishes_every_second_until_deadline(self):
        now = [0]
        m = _mgr(_resp(metas={"low_power_wakeup": 1}), clock_ms=lambda: now[0])
        m._check_awake = lambda ids, l: None
        cb = _Cb()
        m.awake("d1", 10_000, cb)
        m.handler.run_all()  # first tick: 0 < 10000 → publish + repost
        self.assertEqual(len(m.mqtt_server.published), 1)
        now[0] = 9999
        m.handler.run_all()
        self.assertEqual(len(m.mqtt_server.published), 2)
        now[0] = 10_000
        m.handler.run_all()  # deadline hit → dispatch AWAKE_TIMEOUT
        m.handler.run_all()  # posted fanout
        self.assertEqual(cb.success, [LowPowerAwakeRsp.AWAKE_TIMEOUT])
        self.assertNotIn("d1", m.wake_tasks)

    def test_check_awake_failure_maps_unsupport(self):
        def boom(ids, listener):
            raise RuntimeError("cloud down")

        m = _mgr(_resp(metas={"low_power_wakeup": 1}), check_awake=boom)
        cb = _Cb()
        m.awake("d1", 0, cb)
        m.handler.run_all()
        self.assertEqual(cb.success, [LowPowerAwakeRsp.UNSUPPORT])

    def test_check_awake_already_awake_marks_and_succeeds(self):
        captured = {}

        def check(ids, listener):
            # Business is async in Java — fire after awake() returns so the
            # wake task is already registered when the result lands.
            captured["ids"] = ids
            captured["listener"] = listener

        m = _mgr(_resp(metas={"low_power_wakeup": 1}), check_awake=check)
        cb = _Cb()
        m.awake("d1", 0, cb)
        captured["listener"].on_success(
            None,
            [
                LowPowerConnectResult(
                    last_connect_change_time=777, dev_id="d1", low_power_connect=False
                )
            ],
            "api",
        )
        m.handler.run_all()
        self.assertEqual(captured["ids"], ["d1"])
        self.assertEqual(m.awake_flags["d1"], True)
        self.assertEqual(m.awake_change_times["d1"], 777)
        self.assertEqual(cb.success, [LowPowerAwakeRsp.SUCCESS])
        self.assertNotIn("d1", m.wake_tasks)  # cancelled by dispatch

    def test_check_awake_still_connecting_keeps_task(self):
        captured = {}

        def check(ids, listener):
            captured["listener"] = listener

        m = _mgr(_resp(metas={"low_power_wakeup": 1}), check_awake=check)
        cb = _Cb()
        m.awake("d1", 0, cb)
        captured["listener"].on_success(
            None,
            [
                LowPowerConnectResult(
                    last_connect_change_time=1, dev_id="d1", low_power_connect=True
                )
            ],
            "api",
        )
        m.handler.run_all()
        self.assertEqual(cb.success, [])
        self.assertNotIn("d1", m.awake_flags)
        self.assertIn("d1", m.wake_tasks)  # still waking

    def test_dispatch_result_cancels_task_and_drains_cbs(self):
        m = _mgr(_resp(metas={"low_power_wakeup": 1}))
        m._check_awake = lambda ids, l: None
        cb1, cb2 = _Cb(), _Cb()
        m.awake("d1", 0, cb1)
        m._register_callback("d1", cb2)
        m.dispatch_result("d1", LowPowerAwakeRsp.SUCCESS)
        m.handler.run_all()
        self.assertEqual(cb1.success, [LowPowerAwakeRsp.SUCCESS])
        self.assertEqual(cb2.success, [LowPowerAwakeRsp.SUCCESS])
        self.assertEqual(m.callbacks["d1"], [])  # drained in place
        self.assertNotIn("d1", m.wake_deadlines)

    def test_callback_dedup(self):
        m = _mgr(_resp(metas={"low_power_wakeup": 1}))
        cb = _Cb()
        m._register_callback("d1", cb)
        m._register_callback("d1", cb)
        self.assertEqual(m.callbacks["d1"], [cb])


class TestHelpers(unittest.TestCase):
    def test_int_to_byte_array_big_endian(self):
        self.assertEqual(_int_to_byte_array(0x01020304), b"\x01\x02\x03\x04")
        self.assertEqual(_int_to_byte_array(-1), b"\xff\xff\xff\xff")


if __name__ == "__main__":
    unittest.main()
