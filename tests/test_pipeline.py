"""``PipelineTransport`` — ``publishDps`` channel-routing parity tests."""

from __future__ import annotations

import asyncio
import zlib
from types import SimpleNamespace

import pytest

from pypopur.exceptions import ProtocolError
from pypopur.pipeline import PipelineTransport
from pypopur.sdk.device_cache import (
    DeviceBean,
    DevListCacheManager,
    ProductRefBean,
)
from pypopur.sdk.discovery import ActiveEnum, HgwBean
from pypopur.sdk.lan_control import (
    DevCloudControl,
    DevLocalControl,
    LocalControlModel,
)
from pypopur.sdk.low_power import LowPowerAwakeRsp, LowPowerDeviceManager


def _bean(dev_id: str = "dev1", **kw) -> DeviceBean:
    bean = DeviceBean()
    bean.dev_id = dev_id
    bean.communication_id = dev_id
    bean.is_online = kw.pop("is_online", True)
    bean.pv = kw.pop("pv", "3.4")
    bean.local_key = kw.pop("local_key", "localkey")
    for key, value in kw.items():
        setattr(bean, key, value)
    return bean


class _FakeBusiness:
    """``Business`` duck — records params, returns a canned result."""

    def __init__(self) -> None:
        self.params: list = []
        self.result = SimpleNamespace(
            succeeded=True,
            response=SimpleNamespace(result=[]),
            data=None,
            api_name="m.thing.device.low.power.connect.batch.get",
        )

    def new_api_params(self, api_name, api_version, region=None):
        params = SimpleNamespace(
            api_name=api_name,
            api_version=api_version,
            post_data={},
            session_require=False,
            put_post_data=lambda k, v: params.post_data.__setitem__(k, v),
        )
        self.params.append(params)
        return params

    def request(self, params):
        return self.result


class _FakeMqttClient:
    """``MqttWireClient`` duck — records publishes + status callbacks."""

    def __init__(self) -> None:
        self.published: list = []
        self.status_callbacks: list = []

    def publish(self, topic, payload, cb=None, qos=1, retain=False):
        self.published.append((topic, payload, cb, qos, retain))

    def register_mqtt_callback(self, cb):
        self.status_callbacks.append(cb)


class _FakeCloud:
    """The seam surface ``PipelineTransport`` reads off a cloud backend."""

    def __init__(self) -> None:
        self._cache = DevListCacheManager()
        self._cache.use_new_cache = True
        self._cloud = DevCloudControl(self._cache)
        self._device_api = SimpleNamespace(business=None)
        self.server_up = True
        self._is_lan_online = lambda dev, ch: False
        self._is_mqtt_subscribed = lambda dev: True
        self._subscribe_in = lambda dev: None
        self._query_dev = lambda dev: None
        self._scheduler = None
        self.mqtt_sends: list = []
        self.http_sends: list = []
        self.connected_calls = 0

        def _mqtt(dev_id, dp_map, node_id, ctype, log_key, sand_o, cb):
            self.mqtt_sends.append((dev_id, dp_map))
            cb.on_success()

        self._mqtt_send = _mqtt

        def _http(gw_id, dev_id, dps_json, cb):
            self.http_sends.append((gw_id, dev_id, dps_json))
            cb.on_success()

        self._http_publish = _http

    def _server_available(self) -> bool:
        return self.server_up

    async def connect(self) -> None:
        self.connected_calls += 1

    async def close(self) -> None:
        pass

    async def read_dps(self, ids=None):
        return {9: "cloud"}


class _FakeLocal:
    """The seam surface ``PipelineTransport`` reads off a local transport."""

    def __init__(self, cache: DevListCacheManager, dev_id: str) -> None:
        self._cache = cache
        self._device: DeviceBean | None = None
        self._config = SimpleNamespace(local_key="localkey")
        self._transfer = SimpleNamespace(live_gw={})
        self.sent: list = []
        self.control_error: tuple | None = None

        def _hw(bean, cb):
            self.sent.append(bean)
            if self.control_error is not None:
                cb.on_error(*self.control_error)
            else:
                cb.on_success()

        self._local_control = DevLocalControl(cache, LocalControlModel(cache, hardware_control=_hw))

    def mark_live(self, dev_id: str) -> HgwBean:
        hgw = HgwBean(
            gw_id=dev_id,
            ip="192.168.1.50",
            version="3.4",
            active=ActiveEnum.ACTIVED,
            encrypt=True,
        )
        self._transfer.live_gw[dev_id] = hgw
        return hgw

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def read_dps(self, ids=None):
        return {2: "lan"}


def test_mqtt_channel_write() -> None:
    """LAN absent → MQTT handler → ``control_by_server`` → ``mqtt_send``."""
    cloud = _FakeCloud()
    bean = _bean()
    cloud._cache.dev_bean_map["dev1"] = bean
    t = PipelineTransport("dev1", cloud=cloud, device_bean=bean, schema_fn=lambda d: {})

    asyncio.run(t.write_dps({1: True}))

    assert cloud.mqtt_sends == [("dev1", {"1": True})]
    assert not cloud.http_sends


def test_http_channel_when_mqtt_down() -> None:
    """``!isRealConnect && networkAvailable`` → the HTTP path."""
    cloud = _FakeCloud()
    cloud.server_up = False
    bean = _bean()
    t = PipelineTransport("dev1", cloud=cloud, device_bean=bean, schema_fn=lambda d: {})

    asyncio.run(t.write_dps({1: True}))

    assert not cloud.mqtt_sends
    assert cloud.http_sends and cloud.http_sends[0][0] == "dev1"


def test_lan_channel_write() -> None:
    """Live LAN gw → ``LanCommHandler`` → ``publish_dps_lan`` → hardware."""
    cloud = _FakeCloud()
    bean = _bean()
    local = _FakeLocal(cloud._cache, "dev1")
    hgw = local.mark_live("dev1")
    bean.hgw_bean = hgw
    t = PipelineTransport(
        "dev1",
        local=local,
        cloud=cloud,
        device_bean=bean,
        schema_fn=lambda d: {},
    )

    asyncio.run(t.write_dps({1: True}))

    assert len(local.sent) == 1
    assert local.sent[0].data["dps"] == {"1": True}
    assert not cloud.mqtt_sends


def test_lan_error_falls_back_to_cloud() -> None:
    """LAN error → ``LanCommHandler`` → ``internet_send`` → MQTT."""
    cloud = _FakeCloud()
    bean = _bean()
    local = _FakeLocal(cloud._cache, "dev1")
    hgw = local.mark_live("dev1")
    bean.hgw_bean = hgw
    local.control_error = ("1", "lan fail")
    t = PipelineTransport(
        "dev1",
        local=local,
        cloud=cloud,
        device_bean=bean,
        schema_fn=lambda d: {},
    )

    asyncio.run(t.write_dps({1: True}))

    assert local.sent
    assert cloud.mqtt_sends == [("dev1", {"1": True})]


def test_no_channel_errors() -> None:
    """All channels unavailable → ``sendDpsByApi``/``atop_send`` → 11005."""
    bean = _bean(is_online=False)
    t = PipelineTransport("dev1", device_bean=bean, schema_fn=lambda d: {})

    with pytest.raises(ProtocolError):
        asyncio.run(t.write_dps({1: True}))


def test_repository_post_command_hook() -> None:
    """Successful write → ``repository.on_command_sent(dev_id, map)``."""
    cloud = _FakeCloud()
    bean = _bean()
    calls: list = []
    repo = SimpleNamespace(on_command_sent=lambda dev_id, dps: calls.append((dev_id, dps)))
    t = PipelineTransport(
        "dev1",
        cloud=cloud,
        device_bean=bean,
        repository=repo,
        schema_fn=lambda d: {},
    )

    asyncio.run(t.write_dps({1: True}))

    assert calls == [("dev1", {"1": True})]


def test_read_dps_prefers_lan() -> None:
    """Intranet-controllable → LAN ``queryDps``; else the cloud read."""
    cloud = _FakeCloud()
    bean = _bean()
    local = _FakeLocal(cloud._cache, "dev1")
    hgw = local.mark_live("dev1")
    bean.hgw_bean = hgw
    t = PipelineTransport(
        "dev1",
        local=local,
        cloud=cloud,
        device_bean=bean,
        schema_fn=lambda d: {},
    )

    assert asyncio.run(t.read_dps()) == {2: "lan"}

    local._transfer.live_gw.clear()
    assert asyncio.run(t.read_dps()) == {9: "cloud"}


class _Cb:
    def __init__(self) -> None:
        self.success: list = []
        self.errors: list = []

    def on_success(self, *args) -> None:
        self.success.append(args)

    def on_error(self, code, msg) -> None:
        self.errors.append((code, msg))


def test_low_power_manager_bound() -> None:
    """Cloud with mqtt client + business → ``_awake_fn`` = manager.awake."""
    cloud = _FakeCloud()
    cloud._client = _FakeMqttClient()
    cloud.device_api = SimpleNamespace(business=_FakeBusiness())
    bean = _bean()
    t = PipelineTransport("dev1", cloud=cloud, device_bean=bean, schema_fn=lambda d: {})

    mgr = t.low_power_manager
    assert isinstance(mgr, LowPowerDeviceManager)
    assert t.presenter._awake_fn == mgr.awake


def test_low_power_awake_missing_product_ref_sends() -> None:
    """S7 resp without ``productRefBean`` → awake ``1003`` → the send
    still proceeds through ``internet_send`` (the ``$qddqppb`` awake
    callback maps BOTH branches to the internet send)."""
    cloud = _FakeCloud()
    cloud._client = _FakeMqttClient()
    bean = _bean()
    t = PipelineTransport("dev1", cloud=cloud, device_bean=bean, schema_fn=lambda d: {})

    asyncio.run(t.write_dps({1: True}))

    assert cloud.mqtt_sends == [("dev1", {"1": True})]


def test_low_power_wakeup_publishes_and_checks() -> None:
    """``low_power_wakeup`` device → awake runs the real flow: Business
    ``connect.batch.get`` + ``m/w/<id>`` CRC32 publish."""
    cloud = _FakeCloud()
    cloud._client = _FakeMqttClient()
    business = _FakeBusiness()
    business.result.response = SimpleNamespace(
        result=[{"devId": "dev1", "lastConnectChangeTime": 7, "lowPowerConnect": False}]
    )
    cloud.device_api = SimpleNamespace(business=business)
    bean = _bean(local_key="k" * 16)
    t = PipelineTransport("dev1", cloud=cloud, device_bean=bean, schema_fn=lambda d: {})

    resp = t._cache.dev_map["dev1"]
    resp.product_ref_bean = ProductRefBean({"low_power_wakeup": 1})
    resp.local_key = "k" * 16

    cb = _Cb()
    t.presenter._awake_fn("dev1", 8000, cb)

    # ``qdddbpp.pdqppqb`` — api name/version + devIds JSON-string postData.
    (params,) = business.params
    assert params.api_name == "m.thing.device.low.power.connect.batch.get"
    assert params.api_version == "1.0"
    assert params.post_data["devIds"] == '["dev1"]'
    assert params.session_require is True
    # already-awake → SUCCESS; the wake task still got one publish off.
    assert cb.success == [(LowPowerAwakeRsp.SUCCESS,)]
    (topic, payload, _pub_cb, qos, retain) = cloud._client.published[0]
    assert topic == "m/w/dev1"
    assert payload == zlib.crc32(b"k" * 16).to_bytes(4, "big")
    assert (qos, retain) == (0, False)


def test_low_power_disabled_and_injected() -> None:
    """``low_power_manager=False`` leaves the no-op seam; a given manager
    is bound verbatim."""
    cloud = _FakeCloud()
    bean = _bean()
    t = PipelineTransport(
        "dev1",
        cloud=cloud,
        device_bean=bean,
        schema_fn=lambda d: {},
        low_power_manager=False,
    )
    assert not t.low_power_manager

    cb = _Cb()
    t.presenter._awake_fn("dev1", 8000, cb)
    assert cb.success == [()]

    calls: list = []
    fake = SimpleNamespace(awake=lambda dev_id, ms, c: calls.append((dev_id, ms)))
    t2 = PipelineTransport(
        "dev1",
        cloud=cloud,
        device_bean=_bean(),
        schema_fn=lambda d: {},
        low_power_manager=fake,
    )
    t2.presenter._awake_fn("dev1", 8000, cb)
    assert calls == [("dev1", 8000)]


def test_mqtt_status_callback_releases_tasks() -> None:
    """``$pdqppqb`` — MQTT connect events ``release(false)``."""
    cloud = _FakeCloud()
    cloud._client = _FakeMqttClient()
    bean = _bean()
    t = PipelineTransport("dev1", cloud=cloud, device_bean=bean, schema_fn=lambda d: {})

    mgr = t.low_power_manager
    mgr.wake_tasks["dev1"] = lambda: None
    (cb,) = cloud._client.status_callbacks
    cb.on_connect_success()
    assert mgr.wake_tasks == {}

    mgr.wake_tasks["dev1"] = lambda: None
    cb.on_connect_error("x", "y")
    assert mgr.wake_tasks == {}
