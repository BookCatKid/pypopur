"""``CloudChannelBackend`` — the ``qqdbbpp.send`` cloud router end-to-end.

Covers the four wire-level outcomes of ``control by server``:

- MQTT up + device online → ``smart/mb/out/{id}`` publish (QoS framed);
- MQTT publish error → ``$qddqppb`` HTTP backup;
- MQTT down + network → immediate ``sendByHttp``;
- device offline → ``10203``;
- unsubscribed → ``subscribe("smart/mb/in/{id}")`` before publish.
"""

import json
import unittest

import pytest

from pypopur.cloud import CloudChannelBackend, ProtocolError
from pypopur.sdk.device_cache import (
    CommunicationEnum,
    CommunicationModule,
    CommunicationModuleT,
    DataPointModule,
    DeviceRespBean,
    DeviceTopoMoudle,
    DevListCacheManager,
    ProductBean,
)
from pypopur.sdk.mqtt_session import MqttServerManager

LK = "0123456789abcdef"


class _Api:
    """Duck-typed ``DeviceApi`` — records ``atop_publish`` calls."""

    def __init__(self, ok=True):
        self.atop_calls = []
        self.ok = ok

    def atop_publish(self, pub, cb):
        self.atop_calls.append(pub)
        if cb is None:
            return
        if self.ok:
            cb.on_success()
        else:
            cb.on_error("API_ERR", "boom")

    def get_dps_v1(self, gw_id, dev_id):
        raise AssertionError("not used")


class _Client:
    """Duck-typed ``MqttWireClient`` — records subscribe calls."""

    def __init__(self):
        self.subscribed = []

    def subscribe(self, topics, qoses, cb):
        self.subscribed.append(list(topics))
        if cb is not None:
            cb.on_success()


def _world(*, pv="2.3", cadv="1.0.2", online=True, real_connect=True, pub_ok=True):
    cache = DevListCacheManager()
    prod = ProductBean("p")
    prod.capability = 0x1
    cache.add_product(prod)
    resp = DeviceRespBean()
    resp.dev_id = "d"
    resp.product_id = "p"
    resp.local_key = LK
    resp.cloud_online = online
    resp.is_raw_decoded = True
    resp.data_point_info = DataPointModule()
    resp.data_point_info.dps = {}
    resp.communication = CommunicationModule()
    resp.communication.communication_node = "d"
    resp.communication.communication_modes = [
        CommunicationModuleT(type=CommunicationEnum.MQTT, pv=pv)
    ]
    resp.device_topo = DeviceTopoMoudle()
    resp.gateway_ver_cad = cadv
    cache.dev_map["d"] = resp
    bean = cache.get_dev("d")
    assert bean is not None

    published = []

    def pub(topic, payload, cb):
        published.append((topic, payload))
        if pub_ok:
            cb.on_success()
        else:
            cb.on_error("6000", "publish failed")

    mgr = MqttServerManager("CC" + str(id(cache)))
    mgr.is_real_connect = lambda: real_connect
    mgr.publish_fn = pub
    client = _Client()
    api = _Api()
    backend = CloudChannelBackend(
        api,
        dev_id="d",
        device_bean=bean,
        mqtt_manager=mgr,
        mqtt_client=client,
        cache=cache,
    )
    return backend, mgr, client, api, published


class CloudChannelSendTest(unittest.IsolatedAsyncioTestCase):
    async def test_mqtt_success(self):
        backend, mgr, _, api, published = _world()
        mgr.subscribe_state["smart/mb/in/d"] = True
        await backend.write_dps({1: True})
        assert published, "expected an MQTT publish"
        topic, payload = published[-1]
        self.assertEqual(topic, "smart/mb/out/d")
        self.assertEqual(payload[:3], b"2.3")
        self.assertEqual(api.atop_calls, [])

    async def test_mqtt_error_falls_back_to_http(self):
        backend, mgr, _, api, _published = _world(pub_ok=False)
        mgr.subscribe_state["smart/mb/in/d"] = True
        await backend.write_dps({1: True})
        self.assertEqual(len(api.atop_calls), 1)
        pub = api.atop_calls[0]
        self.assertEqual((pub.gw_id, pub.dev_id), ("d", "d"))
        self.assertEqual(json.loads(pub.dps), {"1": True})

    async def test_mqtt_down_goes_http_direct(self):
        backend, _, _, api, published = _world(real_connect=False)
        await backend.write_dps({1: True})
        self.assertEqual(published, [])
        self.assertEqual(len(api.atop_calls), 1)
        pub = api.atop_calls[0]
        self.assertEqual((pub.gw_id, pub.dev_id), ("d", "d"))
        self.assertEqual(json.loads(pub.dps), {"1": True})

    async def test_offline_device_10203(self):
        backend, _, _, api, published = _world(online=False)
        with pytest.raises(ProtocolError) as ei:
            await backend.write_dps({1: True})
        self.assertIn("10203", str(ei.value))
        self.assertEqual(published, [])
        self.assertEqual(api.atop_calls, [])

    async def test_subscribes_in_topic_before_publish(self):
        backend, _mgr, client, api, published = _world()
        # subscribe_state has no "smart/mb/in/d" → isSubscribe false.
        await backend.write_dps({1: True})
        self.assertIn(["smart/mb/in/d"], client.subscribed)
        self.assertEqual(published[-1][0], "smart/mb/out/d")
        self.assertEqual(api.atop_calls, [])

    async def test_http_failure_propagates(self):
        backend, _, _, api, _ = _world(real_connect=False)
        api.ok = False
        with pytest.raises(ProtocolError) as ei:
            await backend.write_dps({1: True})
        self.assertIn("API_ERR", str(ei.value))


if __name__ == "__main__":
    unittest.main()
