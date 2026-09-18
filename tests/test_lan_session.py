"""Parity tests for pypopur.sdk.lan_session — the DevTransferService /
GwTransferModel / dpppdpq LAN boundary, verified against Popur S7 2.0.0
smali (smali_classes3/com/thingclips/...hardware...)."""

from __future__ import annotations

import unittest

from pypopur.sdk.crypto import AESUtil
from pypopur.sdk.hexutil import int_to_bytes2
from pypopur.sdk.lan_control import (
    ActiveEnum,
    FrameTypeEnum,
    HgwBean,
    ThingLocalControlBean,
)
from pypopur.sdk.lan_framing import sign_lpv
from pypopur.sdk.lan_session import (
    DevTransfer,
    HardwareServiceProxy,
    HgwBeanCache,
    HResponse,
    ProtocolVersion,
    ThingFrame,
    ThingHardwareManager,
    ThingNetworkApi,
    ThingNetworkInterface,
    TransferModel,
    get_protocol_version,
)

KEY = "0123456789abcdef"
HEX_KEY = KEY.encode().hex()


class FakeApi(ThingNetworkApi):
    """Recording ThingNetworkApi with tunable returns."""

    def __init__(self) -> None:
        self.calls = []
        self.online = set()
        self.connect_ret = 1
        self.send_ret = 0
        self.send_ret2 = 0

    def check_online(self, dev_id):
        self.calls.append(("check_online", dev_id))
        return dev_id in self.online

    def connect_device(self, dev_id, net_id):
        self.calls.append(("connect_device", dev_id, net_id))
        return self.connect_ret

    def connect_device_with_key(self, dev_id, key, version, net_id):
        self.calls.append(("connect_device_with_key", dev_id, key, version, net_id))
        return self.connect_ret

    def start_swap_key(self, dev_id, key):
        self.calls.append(("start_swap_key", dev_id, key))

    def send_bytes(self, data, length, type_, dev_id):
        self.calls.append(("send_bytes", dev_id, type_, bytes(data)))
        return self.send_ret

    def send_bytes2(self, data, length, type_, dev_id):
        self.calls.append(("send_bytes2", dev_id, type_, bytes(data)))
        return self.send_ret2

    def close_device(self, dev_id):
        self.calls.append(("close_device", dev_id))
        self.online.discard(dev_id)

    def close_all_connection(self):
        self.calls.append(("close_all_connection",))
        self.online.clear()

    def enable_debug(self, flag):
        self.calls.append(("enable_debug", flag))

    def set_heart_beat_interval(self, s):
        self.calls.append(("heartbeat_interval", s))

    def set_heart_beat_response_timeout(self, ms):
        self.calls.append(("heartbeat_timeout", ms))

    def parse_aes_data(self, data, key):
        self.calls.append(("parse_aes_data", bytes(data), key))
        return AESUtil(key.encode()).decrypt_with_bytes(data)

    def encrypt_aes_data(self, text, key):
        self.calls.append(("encrypt_aes_data", text, key))
        return AESUtil(key.encode()).encrypt_with_bytes(text)


def _hgw(gw_id="gw1", version="3.4", ip="10.0.0.1", active=ActiveEnum.ACTIVED):
    return HgwBean(gw_id=gw_id, ip=ip, version=version, active=active)


class _Clock:
    def __init__(self, t=1_000_000):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, ms):
        self.t += ms


class _Listener:
    """ITransferAidlInterface-shaped recorder."""

    def __init__(self):
        self.events = []

    def gw_on(self, hgw):
        self.events.append(("gw_on", hgw.gw_id))

    def gw_off(self, hgw):
        self.events.append(("gw_off", hgw.gw_id))

    def response_by_binary(self, dev_id, version, type_, seq, code, data):
        self.events.append(("resp", dev_id, version, type_, seq, code, data))

    def parse_pkg_frame_progress(self, seq, pack):
        self.events.append(("progress", seq, pack))

    def hardware_log(self, level, dev_id, lpv, code, type_):
        self.events.append(("hwlog", level, dev_id, lpv, code, type_))


class _Cb:
    def __init__(self):
        self.ok = []
        self.err = []

    def on_success(self, *a):
        self.ok.append(a)

    def on_error(self, code, msg):
        self.err.append((code, msg))


def _transfer(api=None, clock=None, post=None):
    api = api or FakeApi()
    native = ThingNetworkInterface(api)
    svc = DevTransfer(native, clock_ms=clock or _Clock(), post_delayed=post)
    return svc, api, native


# ---------------------------------------------------------------------------
# ProtocolVersion
# ---------------------------------------------------------------------------


class TestProtocolVersion(unittest.TestCase):
    def test_get_protocol_version(self):
        self.assertIs(get_protocol_version(3), ProtocolVersion.LAN_PROTOCOL_VERSION_3_4)
        self.assertIs(
            get_protocol_version(4),
            ProtocolVersion.LAN_PROTOCOL_VERSION_BEFORE_3_5,
        )
        self.assertIs(get_protocol_version(5), ProtocolVersion.LAN_PROTOCOL_VERSION_3_5)
        self.assertIs(
            get_protocol_version(6),
            ProtocolVersion.LAN_PROTOCOL_VERSION_3_5_1,
        )
        self.assertIs(get_protocol_version(0), ProtocolVersion.DEFAULT)
        self.assertIs(get_protocol_version(99), ProtocolVersion.DEFAULT)


# ---------------------------------------------------------------------------
# DevTransfer — connection lifecycle
# ---------------------------------------------------------------------------


class TestDevTransferConnect(unittest.TestCase):
    def test_add_dev_keyed_below_35_uses_3arg_connect(self):
        svc, api, native = _transfer()
        svc.add_dev(_hgw(version="3.4"), KEY, 7)
        self.assertIn(("connect_device_with_key", "gw1", KEY, 4, 7), api.calls)
        # connectDeviceWithKey(dev,key,J) → 3-arg → version 3.4 (4)
        self.assertIn(("start_swap_key", "gw1", KEY), api.calls)
        self.assertIn("gw1", native.link_close_cb)
        self.assertIn("gw1", native.lan_handshake_cb)
        self.assertNotIn("gw1", svc.live_gw)  # not live until handshake
        self.assertIn("gw1", svc.connecting_gw)

    def test_add_dev_keyed_35_uses_protocol_enum(self):
        svc, api, _ = _transfer()
        svc.add_dev(_hgw(version="3.5"), KEY, 0)
        self.assertIn(
            (
                "connect_device_with_key",
                "gw1",
                KEY,
                int(ProtocolVersion.LAN_PROTOCOL_VERSION_3_5),
                0,
            ),
            api.calls,
        )

    def test_add_dev_unkeyed_below_35_plain_connect(self):
        svc, api, _ = _transfer()
        svc.add_dev(_hgw(version="3.3"), None, 9)
        self.assertIn(("connect_device", "gw1", 9), api.calls)
        # unkeyed success → connectSuccess → live + gw_on fanout
        self.assertIn("gw1", svc.live_gw)
        self.assertIn("gw1", svc.m_timer_ping)

    def test_add_dev_unkeyed_35_connect_with_null_key(self):
        svc, api, _ = _transfer()
        svc.add_dev(_hgw(version="3.5"), None, 3)
        self.assertIn(
            (
                "connect_device_with_key",
                "gw1",
                None,
                int(ProtocolVersion.LAN_PROTOCOL_VERSION_3_5),
                3,
            ),
            api.calls,
        )
        self.assertIn("gw1", svc.live_gw)

    def test_add_dev_already_online_is_noop(self):
        svc, api, _ = _transfer()
        api.online.add("gw1")
        svc.add_dev(_hgw(), KEY, 0)
        self.assertNotIn("connect_device", [c[0] for c in api.calls])
        self.assertNotIn("gw1", svc.live_gw)  # liveGw untouched

    def test_add_dev_connecting_window_dedup(self):
        clock = _Clock()
        svc, api, _ = _transfer(clock=clock)
        svc.add_dev(_hgw(), KEY, 0)
        n = len(api.calls)
        clock.advance(9999)  # < 10 s window
        svc.add_dev(_hgw(), KEY, 0)
        self.assertEqual(len(api.calls), n)  # suppressed
        clock.advance(2)  # now 10001 > window
        svc.add_dev(_hgw(), KEY, 0)
        self.assertEqual(
            2,
            len([c for c in api.calls if c[0] == "connect_device_with_key"]),
        )

    def test_ip_conflict_evicts_and_delays(self):
        clock = _Clock()
        posted = []
        svc, api, _ = _transfer(clock=clock, post=lambda fn, ms: posted.append((fn, ms)))
        # bring gw-old live
        api.connect_ret = 1
        svc.add_dev(_hgw("gw-old", "3.3", "10.0.0.1"), None, 0)
        self.assertIn("gw-old", svc.live_gw)
        # new gw with same ip → conflict → delete old + 3 s delayed connect
        svc.add_dev(_hgw("gw-new", "3.3", "10.0.0.1"), None, 0)
        self.assertNotIn("gw-old", svc.live_gw)
        self.assertEqual(posted[0][1], DevTransfer.IP_CONFLICT_DELAY_MS)
        self.assertIn(("close_device", "gw-old"), api.calls)
        # connect not yet attempted for gw-new
        self.assertNotIn(("connect_device", "gw-new", 0), api.calls)
        posted[0][0]()
        self.assertIn(("connect_device", "gw-new", 0), api.calls)

    def test_connect_failure_marks_offline(self):
        svc, api, _ = _transfer()
        api.connect_ret = -1
        svc.add_dev(_hgw(), KEY, 0)
        self.assertNotIn("gw1", svc.connecting_gw)
        self.assertNotIn("gw1", svc.live_gw)

    def test_handshake_success_connects(self):
        clock = _Clock()
        svc, _api, native = _transfer(clock=clock)
        listener = _Listener()
        svc.register_callback(listener)
        svc.add_dev(_hgw(), KEY, 0)
        clock.advance(120)
        native.dispatch_handshake_success("gw1")
        self.assertIn("gw1", svc.live_gw)
        self.assertIn(("gw_on", "gw1"), listener.events)
        # hardwareLog(9, gwId, lpv, elapsed, -1)
        self.assertIn(("hwlog", 9, "gw1", "3.4", 120, -1), listener.events)

    def test_handshake_error_offline(self):
        svc, _api, native = _transfer()
        listener = _Listener()
        svc.register_callback(listener)
        svc.add_dev(_hgw(), KEY, 0)
        native.dispatch_handshake_error("gw1", -3, "fail")
        self.assertNotIn("gw1", svc.live_gw)
        self.assertIn(("hwlog", 10, "gw1", "3.4", -3, -1), listener.events)

    def test_link_close_offline(self):
        svc, _api, native = _transfer()
        listener = _Listener()
        svc.register_callback(listener)
        svc.add_dev(_hgw("gw1", "3.3"), None, 0)  # unkeyed → immediate live
        native.dispatch_link_close("gw1", -1)
        self.assertNotIn("gw1", svc.live_gw)
        self.assertIn(("gw_off", "gw1"), listener.events)
        self.assertIn(("hwlog", 6, "gw1", "3.3", -1, -1), listener.events)

    def test_update_timer_task_evicts_stale(self):
        clock = _Clock()
        svc, api, _ = _transfer(clock=clock)
        svc.add_dev(_hgw("gw1", "3.3"), None, 0)
        clock.advance(60_001)
        svc.update_timer_task()
        self.assertNotIn("gw1", svc.live_gw)
        self.assertNotIn("gw1", svc.m_timer_ping)
        self.assertIn(("close_device", "gw1"), api.calls)


class TestDevTransferSend(unittest.TestCase):
    def _live(self, svc, api, gw_id="gw1", version="3.4", active=2):
        api.online.add(gw_id)  # native link up
        svc.live_gw[gw_id] = _hgw(gw_id, version, active=active)
        svc.m_timer_ping[gw_id] = svc._clock_ms()

    def test_send_35_uses_sendbytes2(self):
        svc, api, _ = _transfer()
        self._live(svc, api, version="3.5")
        ret = svc.control_by_binary("gw1", FrameTypeEnum.CONTROL_NEW, b"xx")
        self.assertEqual(ret, "0")
        self.assertEqual(api.calls[-1][0], "send_bytes2")

    def test_send_34_actived_uses_sendbytes2(self):
        svc, api, _ = _transfer()
        self._live(svc, api, version="3.4", active=ActiveEnum.ACTIVED)
        svc.control_by_binary("gw1", FrameTypeEnum.CONTROL_NEW, b"xx")
        self.assertEqual(api.calls[-1][0], "send_bytes2")

    def test_send_34_unactive_uses_sendbytes(self):
        svc, api, _ = _transfer()
        self._live(svc, api, version="3.4", active=ActiveEnum.ACTIVING)
        svc.control_by_binary("gw1", FrameTypeEnum.CONTROL_NEW, b"xx")
        self.assertEqual(api.calls[-1][0], "send_bytes")

    def test_send_33_uses_sendbytes(self):
        svc, api, _ = _transfer()
        self._live(svc, api, version="3.3")
        svc.control_by_binary("gw1", FrameTypeEnum.CONTROL, b"xx")
        self.assertEqual(api.calls[-1][0], "send_bytes")

    def test_send_minus1_offlines_gw(self):
        svc, api, _ = _transfer()
        self._live(svc, api, version="3.3")
        api.send_ret = -1
        ret = svc.control_by_binary("gw1", 0x7, b"xx")
        self.assertEqual(ret, "-1")
        self.assertNotIn("gw1", svc.live_gw)

    def test_control_offline_known_gw_208001(self):
        svc, _api, _ = _transfer()
        # gw known in liveGw but native link down
        svc.live_gw["gw1"] = _hgw()
        ret = svc.control_by_binary("gw1", 0x7, b"xx")
        self.assertEqual(ret, "208001")
        self.assertNotIn("gw1", svc.live_gw)  # marked offline

    def test_control_unknown_gw_208002(self):
        svc, _api, _ = _transfer()
        listener = _Listener()
        svc.register_callback(listener)
        ret = svc.control_by_binary("ghost", 0x7, b"xx")
        self.assertEqual(ret, "208002")
        self.assertIn(("gw_off", "ghost"), listener.events)

    def test_delete_dev_only_live(self):
        svc, api, _ = _transfer()
        svc.delete_dev("ghost")
        self.assertNotIn("close_device", [c[0] for c in api.calls])

    def test_delete_all_dev(self):
        svc, api, _ = _transfer()
        listener = _Listener()
        svc.register_callback(listener)
        svc.live_gw["a"] = _hgw("a")
        svc.live_gw["b"] = _hgw("b")
        svc.delete_all_dev()
        self.assertIn(("close_all_connection",), api.calls)
        self.assertEqual(svc.live_gw, {})
        self.assertIn(("gw_off", "a"), listener.events)
        self.assertIn(("gw_off", "b"), listener.events)

    def test_gw_log_frame_fires_progress(self):
        svc, _api, native = _transfer()
        listener = _Listener()
        svc.register_callback(listener)
        svc.add_dev(_hgw("gw1", "3.3"), None, 0)
        data = int_to_bytes2(2) + int_to_bytes2(1) + b"chunk"
        frame = ThingFrame(type=FrameTypeEnum.LAN_REQUEST_GW_LOG, seq=1, code=0, data=data)
        native.dispatch_response_data("gw1", frame)
        self.assertIn(("progress", 1, 2), listener.events)
        self.assertIn(
            ("resp", "gw1", "3.3", FrameTypeEnum.LAN_REQUEST_GW_LOG, 1, 0, data),
            listener.events,
        )


# ---------------------------------------------------------------------------
# TransferModel (GwTransferModel)
# ---------------------------------------------------------------------------


class TestTransferModel(unittest.TestCase):
    def test_control_closed_errors(self):
        model = TransferModel(service=None)
        cb = _Cb()
        model.control("d1", 0x7, b"x", cb)
        self.assertEqual(cb.err, [("11005", "dev transfer is closed")])

    def test_control_success_zero(self):
        svc, api, _ = _transfer()
        api.online.add("gw1")
        svc.live_gw["gw1"] = _hgw()
        model = TransferModel(service=svc)
        cb = _Cb()
        model.control("gw1", 0x7, b"x", cb)
        self.assertEqual(cb.ok, [()])
        self.assertEqual(cb.err, [])

    def test_control_nonzero_reports_11005_with_detail(self):
        svc, api, _ = _transfer()
        api.online.add("gw1")
        svc.live_gw["gw1"] = _hgw(version="3.3")
        api.send_ret = -1
        model = TransferModel(service=svc)
        cb = _Cb()
        model.control("gw1", 0x7, b"x", cb)
        self.assertEqual(
            cb.err,
            [("11005", "tcp is not exist! detail error code -1")],
        )

    def test_reassembly(self):
        model = TransferModel(service=None)
        f1 = int_to_bytes2(3) + int_to_bytes2(1) + b"AAA"
        f2 = int_to_bytes2(3) + int_to_bytes2(2) + b"BBB"
        self.assertIsNone(model._reassemble(f1))
        self.assertIsNone(model._reassemble(f2))
        f3 = int_to_bytes2(3) + int_to_bytes2(3) + b"CCC"
        self.assertEqual(model._reassemble(f3), b"AAABBBCCC")

    def test_response_by_binary_gw_log_reassembles(self):
        model = TransferModel(service=None)
        recvd = []
        model.dev_response_listeners.append(
            type("L", (), {"on_dev_response": lambda s, r: recvd.append(r)})()
        )
        frag = int_to_bytes2(1) + int_to_bytes2(1) + b"log"
        model.response_by_binary("gw1", "3.4", FrameTypeEnum.LAN_REQUEST_GW_LOG, 9, 0, frag)
        self.assertEqual(recvd[0].data_binary, b"log")
        self.assertEqual(model._reassembly, b"")  # reset after completion

    def test_response_by_binary_plain(self):
        model = TransferModel(service=None)
        recvd = []
        model.dev_response_listeners.append(
            type("L", (), {"on_dev_response": lambda s, r: recvd.append(r)})()
        )
        model.response_by_binary("gw1", "3.4", FrameTypeEnum.STATUS, 1, 0, b"{}")
        self.assertEqual(recvd[0].type, FrameTypeEnum.STATUS)

    def test_handle_disconnect_fans_out(self):
        model = TransferModel(service=object())
        got = []
        model.service_disconnect_listeners.append(
            type("L", (), {"on_service_disconnected": lambda s: got.append(1)})()
        )
        model.handle(TransferModel.MSG_SERVICE_DISCONNECTED)
        self.assertEqual(got, [1])
        self.assertFalse(model.connected)

    def test_gw_on_off_dispatch(self):
        model = TransferModel(service=None)
        got = []
        model.dev_response_listeners.append(
            type(
                "L",
                (),
                {
                    "on_dev_response": lambda s, r: None,
                    "on_dev_update": lambda s, h, on: got.append((h.gw_id, on)),
                },
            )()
        )
        model.handle(TransferModel.MSG_GW_ON, _hgw("g1"))
        model.handle(TransferModel.MSG_GW_OFF, _hgw("g2"))
        self.assertEqual(got, [("g1", True), ("g2", False)])


# ---------------------------------------------------------------------------
# HardwareServiceProxy (bdbbqqd)
# ---------------------------------------------------------------------------


class TestProxy(unittest.TestCase):
    def test_add_hgw_drops_key_below_34(self):
        svc, api, _ = _transfer()
        model = TransferModel(service=svc)
        proxy = HardwareServiceProxy(model, monitor=None)
        proxy.add_hgw(_hgw(version="3.3"), KEY, 5)
        self.assertIn(("connect_device", "gw1", 5), api.calls)

    def test_add_hgw_keeps_key_34(self):
        svc, api, _ = _transfer()
        model = TransferModel(service=svc)
        proxy = HardwareServiceProxy(model, monitor=None)
        proxy.add_hgw(_hgw(version="3.4"), KEY, 5)
        self.assertIn(("connect_device_with_key", "gw1", KEY, 4, 5), api.calls)


# ---------------------------------------------------------------------------
# HgwBeanCache (dbpbdpb)
# ---------------------------------------------------------------------------


class TestHgwCache(unittest.TestCase):
    def test_put_get_remove(self):
        cache = HgwBeanCache()
        cache.put("d1", _hgw("g1"))
        self.assertEqual(cache.get("d1").gw_id, "g1")
        cache.remove("d1")
        self.assertIsNone(cache.get("d1"))

    def test_put_empty_or_null_ignored(self):
        cache = HgwBeanCache()
        cache.put("", _hgw())
        cache.put(None, _hgw())
        cache.put("d1", None)
        self.assertIsNone(cache.get(""))
        self.assertIsNone(cache.get("d1"))


# ---------------------------------------------------------------------------
# Response parsers — bdbbqbd family
# ---------------------------------------------------------------------------


class _DpListener:
    """ILocalDpMessageRespListener recorder."""

    def __init__(self, lpv="3.4", local_key=KEY, dedup=False):
        self._lpv = lpv
        self._key = local_key
        self._dedup = dedup
        self.calls = []

    def get_lpv(self, dev_id):
        return self._lpv

    def get_local_key(self, dev_id):
        return self._key

    def is_data_updated(self, dev_id, s, *args):
        return self._dedup

    def on_local_dp_received_success(self, dev_id, dps, t):
        self.calls.append(("dp", dev_id, dps, t))

    def on_local_dp_sub_device_received_success(self, dev_id, cid, ctype, dps, t):
        self.calls.append(("sub", dev_id, cid, ctype, dps, t))

    def on_local_dp_zigbee_group_received_success(self, dev_id, mbid, dps):
        self.calls.append(("zig", dev_id, mbid, dps))

    def on_local_dp_received_error(self, dev_id, code, msg):
        self.calls.append(("err", dev_id, code, msg))

    def on_local_data_received(self, dev_id, protocol, obj):
        self.calls.append(("data", dev_id, protocol, obj))


def _status_resp(data, version="3.4", code=0, dev_id="gw1", seq=7):
    return HResponse(
        dev_id=dev_id,
        type=FrameTypeEnum.STATUS,
        seq=seq,
        code=code,
        data_binary=data,
        version=version,
    )


def _manager(native=None):
    svc, api, _ = _transfer(api=native or FakeApi())
    model = TransferModel(service=svc)
    proxy = HardwareServiceProxy(model, monitor=None)
    mgr = ThingHardwareManager(proxy, svc.native.api)
    return mgr, svc, api


class TestStatusParseChain(unittest.TestCase):
    def test_status_34_delivers_on_local_data(self):
        # pqqqddq: header → data[15:] → JSONObject → cb(devId, protocol, obj)
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.4")
        mgr.local_dp_listener = lis
        inner = b'{"protocol":5,"dps":{"1":true},"t":7}'
        data = b"3.4" + b"\x00" * 4 + int_to_bytes2(3) + int_to_bytes2(4) + inner
        mgr.on_dev_response(_status_resp(data))
        self.assertEqual(len(lis.calls), 1)
        kind, dev_id, protocol, obj = lis.calls[0]
        self.assertEqual(kind, "data")
        self.assertEqual((dev_id, protocol), ("gw1", 5))
        self.assertEqual(obj["dps"], {"1": True})

    def test_status_34_missing_protocol_dropped(self):
        # getInteger("protocol") == null → intValue NPE → parseResp catch
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.4")
        mgr.local_dp_listener = lis
        inner = b'{"dps":{"1":true}}'
        data = b"3.4" + b"\x00" * 4 + int_to_bytes2(3) + int_to_bytes2(4) + inner
        mgr.on_dev_response(_status_resp(data))
        self.assertEqual(lis.calls, [])

    def test_status_34_dedup_drop(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.4", dedup=True)
        mgr.local_dp_listener = lis
        inner = b'{"protocol":5,"dps":{}}'
        data = b"3.4" + b"\x00" * 4 + int_to_bytes2(3) + int_to_bytes2(4) + inner
        mgr.on_dev_response(_status_resp(data))
        self.assertEqual(lis.calls, [])  # isDataUpdated → drop

    def test_status_32_aes(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.2")
        mgr.local_dp_listener = lis
        inner = AESUtil(KEY.encode()).encrypt_with_bytes('{"dps":{"1":true},"cid":"gw1","t":9}')
        data = b"3.2" + b"\x00" * 4 + int_to_bytes2(1) + int_to_bytes2(1) + inner
        mgr.on_dev_response(_status_resp(data, version="3.2"))
        self.assertEqual(lis.calls, [("dp", "gw1", '{"1":true}', 9)])

    def test_status_32_subdevice(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.2")
        mgr.local_dp_listener = lis
        inner = AESUtil(KEY.encode()).encrypt_with_bytes(
            '{"dps":{"1":true},"cid":"sub1","ctype":1,"t":42}'
        )
        data = b"3.2" + b"\x00" * 4 + int_to_bytes2(1) + int_to_bytes2(1) + inner
        mgr.on_dev_response(_status_resp(data, version="3.2"))
        self.assertEqual(lis.calls, [("sub", "gw1", "sub1", 1, '{"1":true}', 42)])

    def test_status_32_zigbee_group(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.2")
        mgr.local_dp_listener = lis
        inner = AESUtil(KEY.encode()).encrypt_with_bytes('{"dps":{"1":true},"ctype":2,"mbid":"g1"}')
        data = b"3.2" + b"\x00" * 4 + int_to_bytes2(1) + int_to_bytes2(1) + inner
        mgr.on_dev_response(_status_resp(data, version="3.2"))
        self.assertEqual(lis.calls, [("zig", "gw1", "g1", '{"1":true}')])

    def test_status_32_null_decrypt_errors(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.2", local_key="")
        mgr.local_dp_listener = lis
        data = b"3.2" + b"\x00" * 4 + int_to_bytes2(1) + int_to_bytes2(1) + b"??"
        mgr.on_dev_response(_status_resp(data, version="3.2"))
        self.assertEqual(
            lis.calls,
            [("err", "gw1", "result data is null", "result data is null")],
        )

    def test_status_31_lpv_sign_base64(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.1")
        mgr.local_dp_listener = lis
        inner_json = '{"dps":{"1":true},"cid":"gw1","s":-1,"t":5}'
        enc = AESUtil(KEY.encode()).encrypt_with_base64(inner_json)
        sign = sign_lpv("3.1", enc, KEY)
        data = ("3.1" + sign + enc).encode()
        mgr.on_dev_response(_status_resp(data, version="3.1"))
        self.assertEqual(lis.calls, [("dp", "gw1", '{"1":true}', 5)])

    def test_status_31_bad_sign_dropped(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.1")
        mgr.local_dp_listener = lis
        enc = AESUtil(KEY.encode()).encrypt_with_base64('{"dps":{"1":true},"cid":"gw1","s":-1}')
        data = ("3.1" + "0" * 16 + enc).encode()
        mgr.on_dev_response(_status_resp(data, version="3.1"))
        self.assertEqual(lis.calls, [])

    def test_status_default_plaintext(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="1.0")
        mgr.local_dp_listener = lis
        data = b'{"dps":{"1":true},"cid":"gw1","t":3}'
        mgr.on_dev_response(_status_resp(data, version="1.0"))
        self.assertEqual(lis.calls, [("dp", "gw1", '{"1":true}', 3)])

    def test_status_nonzero_code_error(self):
        mgr, _, _ = _manager()
        lis = _DpListener()
        mgr.local_dp_listener = lis
        mgr.on_dev_response(_status_resp(b"", code=5))
        self.assertEqual(
            lis.calls,
            [("err", "gw1", "11005", "hResponse return code != 0")],
        )


# ---------------------------------------------------------------------------
# ThingHardwareManager.onDevResponse dispatch
# ---------------------------------------------------------------------------


class TestOnDevResponse(unittest.TestCase):
    def test_heartbeat_skips_log_and_dispatch(self):
        mgr, _, _ = _manager()
        logged = []
        mgr.log_event_listener = type(
            "L",
            (),
            {
                "message_received_log_callback": lambda s, m: logged.append(m),
            },
        )()
        mgr.on_dev_response(HResponse(dev_id="g", type=FrameTypeEnum.HEART_BEAT))
        self.assertEqual(logged, [])

    def test_received_log_shape(self):
        mgr, _, _ = _manager()
        logged = []
        mgr.log_event_listener = type(
            "L",
            (),
            {
                "message_received_log_callback": lambda s, m: logged.append(m),
            },
        )()
        mgr.on_dev_response(HResponse(dev_id="g", type=99, seq=11, code=0, version="3.4"))
        entry = logged[0]
        self.assertEqual(entry["devId"], "g")
        self.assertEqual(entry["type"], 4)
        self.assertEqual(
            entry["readModels"],
            [{"type": 99, "code": 0, "index": 11, "lpv": "3.4"}],
        )

    def test_gw_log_to_raw_listener(self):
        mgr, _, _ = _manager()
        got = []
        mgr.raw_response_listener = type(
            "L",
            (),
            {
                "on_response": lambda s, d, t, ok, data: got.append((d, t, ok, data)),
            },
        )()
        mgr.on_dev_response(
            HResponse(
                dev_id="g",
                type=FrameTypeEnum.LAN_REQUEST_GW_LOG,
                seq=1,
                code=0,
                data_binary=b"payload",
            )
        )
        self.assertEqual(got, [("g", FrameTypeEnum.LAN_REQUEST_GW_LOG, True, b"payload")])

    def test_other_type_33_decrypts(self):
        api = FakeApi()
        mgr, _, _ = _manager(native=api)
        got = []
        mgr.raw_response_listener = type(
            "L",
            (),
            {"on_response": lambda s, d, t, ok, data: got.append(data)},
        )()
        lis = _DpListener(lpv="3.3")
        mgr.local_dp_listener = lis
        cipher = AESUtil(KEY.encode()).encrypt_with_bytes('{"x":1}')
        mgr.on_dev_response(
            HResponse(dev_id="g", type=0x55, code=0, data_binary=cipher, version="3.3")
        )
        self.assertEqual(got, [b'{"x":1}'])

    def test_dp_query_new_subdevice(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.4")
        mgr.local_dp_listener = lis
        body = b'{"dps":{"2":0},"cid":"sub9","ctype":0,"t":8}'
        mgr.on_dev_response(
            HResponse(
                dev_id="gw1",
                type=FrameTypeEnum.DP_QUERY_NEW,
                code=0,
                data_binary=body,
                version="3.4",
            )
        )
        self.assertEqual(lis.calls, [("sub", "gw1", "sub9", 0, '{"2":0}', 8)])

    def test_dp_query_old_cid_ignored(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.4")
        mgr.local_dp_listener = lis
        body = b'{"dps":{"2":0},"cid":"sub9","ctype":0,"t":8}'
        mgr.on_dev_response(
            HResponse(
                dev_id="gw1", type=FrameTypeEnum.DP_QUERY, code=0, data_binary=body, version="3.4"
            )
        )
        # DP_QUERY at ≥3.3 ignores cid → regular dp
        self.assertEqual(lis.calls, [("dp", "gw1", '{"2":0}', 8)])

    def test_dp_query_pre33_cid_checked(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.2")
        mgr.local_dp_listener = lis
        body = b'{"dps":{"2":0},"cid":"sub9","ctype":0,"t":8}'
        mgr.on_dev_response(
            HResponse(
                dev_id="gw1", type=FrameTypeEnum.DP_QUERY, code=0, data_binary=body, version="3.2"
            )
        )
        self.assertEqual(lis.calls, [("sub", "gw1", "sub9", 0, '{"2":0}', 8)])

    def test_ext_stream_online_lists(self):
        mgr, _, _ = _manager()
        lis = _DpListener(lpv="3.4")
        mgr.local_dp_listener = lis
        online_got = []
        ble_got = []
        mgr.local_online_listener = type(
            "L",
            (),
            {"on_sub_dev_update": lambda s, d, on, off: online_got.append((d, on, off))},
        )()
        mgr.ble_connect_listener = type(
            "L",
            (),
            {
                "on_connect_status_changed": lambda s, d, on, off, nb: ble_got.append(
                    (d, on, off, nb)
                )
            },
        )()
        body = (
            b'{"reqType":"subdev_online_stat_report","data":'
            b'{"online":["s1","s2"],"offline":["s3"],"nearby":["s4"]}}'
        )
        mgr.on_dev_response(
            HResponse(
                dev_id="gw1",
                type=FrameTypeEnum.FRM_LAN_EXT_STREAM,
                code=0,
                data_binary=body,
                version="3.4",
            )
        )
        self.assertEqual(online_got, [("gw1", ["s1", "s2"], ["s3"])])
        self.assertEqual(ble_got, [("gw1", ["s1", "s2"], ["s3"], ["s4"])])


# ---------------------------------------------------------------------------
# control(ThingLocalControlBean) end-to-end
# ---------------------------------------------------------------------------


class TestControlBean(unittest.TestCase):
    def test_control_bean_34_sends_and_logs(self):
        svc, api, _ = _transfer()
        api.online.add("gw1")
        svc.live_gw["gw1"] = _hgw("gw1", "3.4", active=ActiveEnum.ACTIVED)
        model = TransferModel(service=svc)
        proxy = HardwareServiceProxy(model, monitor=None)
        mgr = ThingHardwareManager(proxy, api)
        sent_logs = []
        mgr.log_event_listener = type(
            "L",
            (),
            {
                "message_send_log_callback": lambda s, d, t, v: sent_logs.append((d, t, v)),
                "record_log_callback": lambda s, d, t, n, e: None,
            },
        )()
        cb = _Cb()
        bean = ThingLocalControlBean(
            dev_id="gw1",
            frame_type=FrameTypeEnum.CONTROL_NEW,
            data={"dps": {"1": True}},
            lpv="3.4",
            local_key=KEY,
            s=3,
            o=4,
            t=1700000000,
            protocol=5,
        )
        mgr.control(bean, cb)
        # send_bytes2 called (3.4 + ACTIVED)
        send = [c for c in api.calls if c[0] == "send_bytes2"]
        self.assertEqual(len(send), 1)
        payload = send[0][3]
        # 3.4 framing: lpv(3B) ‖ 0*4 ‖ s ‖ o ‖ json
        self.assertEqual(payload[:3], b"3.4")
        self.assertEqual(payload[3:7], b"\x00" * 4)
        self.assertEqual(payload[7:11], int_to_bytes2(3))
        self.assertEqual(payload[11:15], int_to_bytes2(4))
        import json as _json

        obj = _json.loads(payload[15:])
        self.assertEqual(obj["protocol"], 5)
        self.assertEqual(obj["t"], 1700000000)
        self.assertEqual(obj["data"], {"dps": {"1": True}})
        self.assertEqual(cb.ok, [()])
        self.assertEqual(sent_logs, [("gw1", FrameTypeEnum.CONTROL_NEW, "3.4")])

    def test_control_bean_failure_propagates_11005(self):
        svc, api, _ = _transfer()
        model = TransferModel(service=svc)
        proxy = HardwareServiceProxy(model, monitor=None)
        mgr = ThingHardwareManager(proxy, api)
        cb = _Cb()
        bean = ThingLocalControlBean(
            dev_id="ghost",
            frame_type=FrameTypeEnum.CONTROL_NEW,
            data={"dps": {}},
            lpv="3.4",
            local_key=KEY,
        )
        mgr.control(bean, cb)
        # 208002 → "tcp is not exist! detail error code 208002"
        self.assertEqual(
            cb.err,
            [("11005", "tcp is not exist! detail error code 208002")],
        )


if __name__ == "__main__":
    unittest.main()
