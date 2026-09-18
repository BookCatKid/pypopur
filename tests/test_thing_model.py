"""Parity tests for ``sdk/thing_model.py`` — the THING_MODEL conversion and
link-message chain (``qqbbddb``/``bdpqppd``/``bppdpdq``/``qqqpdpb``/
``bbdppqp``/``qpppdbb``/``qdbpqqq``/``dbddpbp``/``dqqpqbq``)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from pypopur.sdk.comm_pipeline import (
    CommunicationModuleT,
    DevModel,
    ThingDevicePresenter,
    ThingSmartThingMessageType,
)
from pypopur.sdk.device_cache import (
    DeviceBean,
    DeviceRespBean,
    DevListCacheManager,
)
from pypopur.sdk.lan_control import DeviceCommController, LanGate, ResultCallback
from pypopur.sdk.thing_model import (
    LinkFilterConvertUtil,
    LinkMqttServerAdapter,
    ThingModelCache,
    ThingSmartThingModel,
    action_receive,
    action_send,
    event_receive,
    get_thing_model_with_pid,
    link_message_topic,
    property_receive,
    property_send,
    publish_link_message,
    type_spec_convert,
)

MODEL_JSON: dict[str, Any] = {
    "modelId": "m1",
    "productId": "pid1",
    "productVersion": "1.0.0",
    "services": [
        {
            "properties": [
                {
                    "abilityId": 1,
                    "accessMode": "rw",
                    "code": "switch",
                    "typeSpec": {"type": "bool"},
                },
                {
                    "abilityId": 2,
                    "accessMode": "rw",
                    "code": "count",
                    "typeSpec": {"type": "value", "min": 0, "max": 100},
                },
                {
                    "abilityId": 3,
                    "accessMode": "ro",
                    "code": "status",
                    "typeSpec": {"type": "string", "maxlen": 8},
                },
                {
                    "abilityId": 4,
                    "accessMode": "rw",
                    "code": "mode",
                    "typeSpec": {"type": "enum", "range": ["a", "b"]},
                },
            ],
            "actions": [
                {
                    "abilityId": 10,
                    "code": "feed",
                    "inputParams": [
                        {
                            "code": "portion",
                            "typeSpec": {"type": "value", "min": 1, "max": 9},
                        }
                    ],
                    "outputParams": [{"code": "ok", "typeSpec": {"type": "bool"}}],
                }
            ],
            "events": [
                {
                    "abilityId": 20,
                    "code": "alert",
                    "outputParams": [
                        {
                            "code": "level",
                            "typeSpec": {"type": "enum", "range": ["low", "high"]},
                        }
                    ],
                }
            ],
        }
    ],
}


def _services() -> list:
    return ThingSmartThingModel.from_json(MODEL_JSON).services


def _resp(dev_id: str = "dev1", **kw: Any) -> DeviceRespBean:
    resp = DeviceRespBean()
    resp.dev_id = dev_id
    resp.product_id = kw.pop("product_id", "pid1")
    resp.product_ver = kw.pop("product_ver", "1.0.0")
    resp.cloud_online = kw.pop("cloud_online", True)
    for key, value in kw.items():
        setattr(resp, key, value)
    return resp


class _Cb(ResultCallback):
    def __init__(self) -> None:
        self.errors: list[tuple[str, str | None]] = []
        self.successes = 0
        self.results: list[Any] = []

    def on_error(self, code: str, msg: str | None) -> None:
        self.errors.append((code, msg))

    def on_success(self, *args: Any) -> None:
        self.successes += 1
        self.results.append(args[0] if args else None)


# ---------------------------------------------------------------------------
# bbdppqp — TypeSpecCheckUtil
# ---------------------------------------------------------------------------


class TestTypeSpecConvert:
    def test_bool(self) -> None:
        assert type_spec_convert("bool", True, "{}", True) is True
        # a non-Boolean falls through the switch to the compat tail
        assert type_spec_convert("bool", 1, "{}", True) == 1

    def test_string(self) -> None:
        assert type_spec_convert("string", "abc", '{"maxlen":5}', True) == "abc"
        # over-maxlen → simple check fails → compat tail returns the value
        assert type_spec_convert("string", "toolong!!", '{"maxlen":4}', True) == "toolong!!"

    def test_value(self) -> None:
        spec = '{"min":0,"max":10}'
        assert type_spec_convert("value", 5, spec, True) == 5
        # out of range → :cond_10 tail → return value (compat, NOT null)
        assert type_spec_convert("value", 99, spec, True) == 99
        assert type_spec_convert("value", 5.5, spec, True) == 5.5
        # bool is not a Java Number → falls to tail
        assert type_spec_convert("value", True, spec, True) is True

    def test_bitmap(self) -> None:
        spec = '{"maxlen":3}'
        assert type_spec_convert("bitmap", 5, spec, True) == 5
        # out of range → tail → return value
        assert type_spec_convert("bitmap", 8, spec, True) == 8
        # label width used when maxlen == 0
        assert type_spec_convert("bitmap", 3, '{"maxlen":0,"label":["a","b"]}', True) == 3

    def test_enum(self) -> None:
        spec = '{"range":["a","b"]}'
        assert type_spec_convert("enum", "a", spec, True) == "a"
        # enum miss is one of the few hard nulls
        assert type_spec_convert("enum", "z", spec, True) is None

    def test_array(self) -> None:
        spec = '{"maxSize":3,"elementTypeSpec":{"type":"string","maxlen":5}}'
        assert type_spec_convert("array", ["x", "y"], spec, True) == ["x", "y"]
        # oversize → null
        assert type_spec_convert("array", ["a", "b", "c", "d"], spec, True) is None
        # non-list → null
        assert type_spec_convert("array", "nope", spec, True) is None

    def test_struct(self) -> None:
        spec = json.dumps(
            {
                "properties": {
                    "on": {"typeSpec": {"type": "bool"}},
                    "n": {"typeSpec": {"type": "value", "min": 0, "max": 9}},
                }
            }
        )
        out = type_spec_convert("struct", {"on": True, "n": 4}, spec, True)
        assert out == {"on": True, "n": 4}
        # no properties → null
        assert type_spec_convert("struct", {"a": 1}, '{"properties":{}}', True) is None

    def test_unknown_type_returns_value(self) -> None:
        assert type_spec_convert("weird", {"k": 1}, "{}", True) == {"k": 1}
        assert type_spec_convert(None, 7, "{}", True) == 7

    def test_raw_send_receive(self) -> None:
        # receive (strict=False): base64 → hex
        assert type_spec_convert("raw", "aGk=", "{}", False) == "6869"
        # send (strict=True): hex → base64
        assert type_spec_convert("raw", "6869", "{}", True) == "aGk="
        # tolerant commons-codec decode: "abc" → 2 bytes → "69b7"
        assert type_spec_convert("raw", "abc", "{}", False) == "69b7"
        # strict mode: odd-length hex fails the simple check → falls
        # through the switch to the compat tail → returns the value
        assert type_spec_convert("raw", "abc", "{}", True) == "abc"


# ---------------------------------------------------------------------------
# bdpqppd — PropertyCheckUtil
# ---------------------------------------------------------------------------


class TestPropertySend:
    def test_valid_entries_mutate_in_place(self) -> None:
        payload = {"switch": True, "count": 7}
        out = property_send(_services(), payload)
        assert out is payload
        assert payload == {"switch": True, "count": 7}

    def test_readonly_returns_false(self) -> None:
        # Boolean.FALSE — non-null, so publishThingMessageWithType would
        # still send it
        assert property_send(_services(), {"status": "ok"}) is False

    def test_missing_type_spec_returns_false(self) -> None:
        services = _services()
        services[0].properties[0].type_spec = {}
        assert property_send(services, {"switch": True}) is False

    def test_enum_miss_returns_none(self) -> None:
        assert property_send(_services(), {"mode": "zzz"}) is None

    def test_count_mismatch_returns_none(self) -> None:
        assert property_send(_services(), {"switch": True, "nope": 1}) is None

    def test_out_of_range_passes_through(self) -> None:
        # value out-of-range → compat tail returns it → valid
        payload = {"count": 500}
        assert property_send(_services(), payload) is payload


class TestPropertyReceive:
    def test_wraps_value_and_time(self) -> None:
        out = property_receive(_services(), {"switch": True})
        assert set(out) == {"switch"}
        assert out["switch"]["value"] is True
        assert isinstance(out["switch"]["time"], int)

    def test_existing_time_preserved(self) -> None:
        out = property_receive(_services(), {"count": {"value": 3, "time": 42}})
        assert out["count"] == {"value": 3, "time": 42}

    def test_value_only_gets_time_added(self) -> None:
        out = property_receive(_services(), {"count": {"value": 3}})
        assert out["count"]["value"] == 3
        assert "time" in out["count"]

    def test_enum_miss_dropped(self) -> None:
        assert property_receive(_services(), {"mode": "zzz"}) == {}

    def test_null_spec_raises_through_caller(self) -> None:
        services = _services()
        services[0].properties[0].type_spec = None
        # spec.get("type") → AttributeError — mirrors the Java NPE on
        # null.get("type") escaping to qqbbddb's catch
        with pytest.raises(AttributeError):
            property_receive(services, {"switch": True})


# ---------------------------------------------------------------------------
# bppdpdq / qqqpdpb — action/event converters
# ---------------------------------------------------------------------------


class TestActionSend:
    def test_valid(self) -> None:
        payload = {"actionCode": "feed", "inputParams": {"portion": 3}}
        out = action_send(_services(), payload)
        assert out is payload
        assert payload["inputParams"] == {"portion": 3}

    def test_unknown_action_returns_none(self) -> None:
        payload = {"actionCode": "nope", "inputParams": {"portion": 3}}
        assert action_send(_services(), payload) is None

    def test_unknown_param_returns_none(self) -> None:
        payload = {"actionCode": "feed", "inputParams": {"bogus": 3}}
        assert action_send(_services(), payload) is None

    def test_original_value_stored(self) -> None:
        # smali quirk: validation runs but the ORIGINAL value is kept
        payload = {"actionCode": "feed", "inputParams": {"portion": 5}}
        out = action_send(_services(), payload)
        assert out["inputParams"]["portion"] == 5


class TestActionReceive:
    def test_matched_params_kept_original(self) -> None:
        payload = {"actionCode": "feed", "outputParams": {"ok": True, "junk": 1}}
        out = action_receive(_services(), payload)
        assert out["outputParams"] == {"ok": True}

    def test_null_output_params_npe(self) -> None:
        with pytest.raises(TypeError):
            action_receive(_services(), {"actionCode": "feed"})


class TestEventReceive:
    def test_matched_params(self) -> None:
        payload = {"eventCode": "alert", "outputParams": {"level": "high", "junk": 2}}
        out = event_receive(_services(), payload)
        assert out["outputParams"] == {"level": "high"}

    def test_enum_miss_dropped(self) -> None:
        payload = {"eventCode": "alert", "outputParams": {"level": "zzz"}}
        out = event_receive(_services(), payload)
        assert out["outputParams"] == {}


# ---------------------------------------------------------------------------
# qpppdbb — ThingModelCache
# ---------------------------------------------------------------------------


class TestThingModelCache:
    def test_key_and_null_version_default(self) -> None:
        cache = ThingModelCache()
        model = ThingSmartThingModel(product_id="p", product_version=None)
        cache.put(model)
        # null ver → "1.0.0"
        assert cache.get("p", None) is model
        assert cache.get("p", "1.0.0") is model
        # empty-string ver is NOT defaulted (if-nez null check only)
        assert cache.get("p", "") is None

    def test_empty_pid(self) -> None:
        cache = ThingModelCache()
        cache.put(ThingSmartThingModel(product_id="", product_version="1"))
        assert cache.get("", "1") is None

    def test_remove(self) -> None:
        cache = ThingModelCache()
        cache.put(ThingSmartThingModel(product_id="p", product_version="2"))
        cache.remove("p", "2")
        assert cache.get("p", "2") is None


# ---------------------------------------------------------------------------
# qqbbddb — LinkFilterConvertUtil
# ---------------------------------------------------------------------------


class TestConvertOut:
    def _util(self) -> tuple[LinkFilterConvertUtil, DevListCacheManager]:
        cache = DevListCacheManager()
        cache.dev_map["dev1"] = _resp()
        model_cache = ThingModelCache()
        model_cache.put(ThingSmartThingModel.from_json(MODEL_JSON))
        return LinkFilterConvertUtil(cache, model_cache), cache

    def test_property(self) -> None:
        util, _ = self._util()
        out = util.convert_out("dev1", ThingSmartThingMessageType.PROPERTY, {"switch": True})
        assert out == {"switch": True}

    def test_action(self) -> None:
        util, _ = self._util()
        out = util.convert_out(
            "dev1",
            ThingSmartThingMessageType.ACTION,
            {"actionCode": "feed", "inputParams": {"portion": 2}},
        )
        assert out["inputParams"] == {"portion": 2}

    def test_event_returns_none(self) -> None:
        util, _ = self._util()
        assert util.convert_out("dev1", ThingSmartThingMessageType.EVENT, {"e": 1}) is None

    def test_missing_device_returns_none(self) -> None:
        util, _ = self._util()
        assert (
            util.convert_out("ghost", ThingSmartThingMessageType.PROPERTY, {"switch": True}) is None
        )

    def test_null_command(self) -> None:
        util, _ = self._util()
        assert util.convert_out("dev1", ThingSmartThingMessageType.PROPERTY, None) is None

    def test_convert_to_dps_with_link_property(self) -> None:
        util, _cache = self._util()
        updates: list = []
        util.on_dp_update = lambda *a: updates.append(a)
        out = util.convert_to_dps_with_link_property("dev1", '{"switch":{"value":true,"time":11}}')
        assert json.loads(out) == {"1": True}
        assert updates and updates[0][0] == "dev1"

    def test_convert_to_link_property_quirk(self) -> None:
        # smali checks containsKey(abilityId) but reads payload.get(code)
        util, _ = self._util()
        out = json.loads(util.convert_to_link_property("dev1", '{"1":true}'))
        # only abilityId "1" matched → {code: payload.get(code)} → null
        assert out == {"switch": None}


# ---------------------------------------------------------------------------
# qdbpqqq — link publish + LinkMqttServerAdapter
# ---------------------------------------------------------------------------


class _FakeClient:
    def __init__(self) -> None:
        self.published: list = []

    def publish(self, topic, payload, cb=None, **_kw):
        self.published.append((topic, payload))
        if cb is not None:
            cb.on_success()


class _SandO:
    def __init__(self, s: int = 9, o: int = 4242) -> None:
        self._s, self._o = s, o

    def get_s(self) -> int:
        return self._s

    def get_o(self) -> int:
        return self._o


class TestLinkPublish:
    def test_topics(self) -> None:
        assert link_message_topic("d", 0) == "tylink/d/thing/property/set"
        assert link_message_topic("d", 1) == "tylink/d/thing/action/execute"
        assert link_message_topic("d", 2) == ""

    def test_wire_payload(self) -> None:
        client = _FakeClient()
        server = LinkMqttServerAdapter(client)
        cb = _Cb()
        publish_link_message(
            "dev1",
            ThingSmartThingMessageType.PROPERTY,
            {"switch": True},
            _SandO(s=7),
            cb,
            mqtt_server=server,
            current_timestamp=lambda: 1234,
        )
        topic, payload = client.published[0]
        assert topic == "tylink/dev1/thing/property/set"
        assert json.loads(payload) == {
            "msgId": 7,
            "time": 1234,
            "data": {"switch": True},
        }
        assert cb.successes == 1

    def test_event_topic_errors(self) -> None:
        cb = _Cb()
        publish_link_message(
            "d", ThingSmartThingMessageType.EVENT, {}, _SandO(), cb, mqtt_server=_FakeClient()
        )
        assert cb.errors == [("11005", "send error")]

    def test_stat_callback_appends_hash(self) -> None:
        stats: list = []

        class _Fail:
            def publish(self, *a, **k):
                pass

            def publish_link_with_topic(self, builder, cb):
                cb.on_error("6000", "mqtt is not connect")

        publish_link_message(
            "d",
            ThingSmartThingMessageType.PROPERTY,
            {},
            _SandO(),
            _Cb(),
            mqtt_server=_Fail(),
            stat=lambda e, m: stats.append((e, m)),
        )
        assert stats[0][1]["result"] == "fail"


# ---------------------------------------------------------------------------
# qpbpqpq link transports on DevModel
# ---------------------------------------------------------------------------


def _model(dev_id: str = "dev1", **kw: Any) -> DevModel:
    cache = DevListCacheManager()
    cache.use_new_cache = True
    cache.dev_map[dev_id] = kw.pop("resp", _resp(dev_id))
    bean = cache.get_dev(dev_id)
    if bean is None:
        bean = DeviceBean()
        bean.dev_id = dev_id
        bean.dev_resp_bean = cache.dev_map[dev_id]
        bean.communication_id = dev_id
        bean.is_online = True
        cache.dev_bean_map[dev_id] = bean
    gate = LanGate(cache, hgw_provider=lambda c: None)
    model = DevModel(
        dev_id,
        DeviceCommController(dev_id, cache, None),
        cache,
        gate,
        atop_send=kw.pop("atop_send", None),
        mqtt_up=kw.pop("mqtt_up", lambda: True),
    )
    for key, value in kw.items():
        setattr(model, key, value)
    return model


class TestSendLinkMessage:
    def test_mqtt_path(self) -> None:
        model = _model()
        sent: list = []
        model.link_mqtt_server = SimpleNamespace(
            publish_link_with_topic=lambda b, cb: sent.append(b)
        )
        cb = _Cb()
        model.send_link_message_by_mqtt(ThingSmartThingMessageType.PROPERTY, '{"switch":true}', cb)
        assert len(sent) == 1
        assert sent[0].topic_id == "tylink/dev1/thing/property/set"

    def test_mqtt_down_falls_back_to_http(self) -> None:
        calls: list = []
        model = _model(
            mqtt_up=lambda: False,
            atop_send=lambda api, ver, data, cb: calls.append((api, data)),
        )
        model.send_link_message_by_mqtt(
            ThingSmartThingMessageType.PROPERTY, '{"switch":true}', _Cb()
        )
        assert calls == [
            (
                "thing.m.device.dp.publish",
                {"devId": "dev1", "gwId": "dev1", "dps": '{"switch":true}'},
            )
        ]

    def test_not_cloud_online_10202(self) -> None:
        model = _model(resp=_resp(cloud_online=False), mqtt_up=lambda: False)
        cb = _Cb()
        model.send_link_message_by_mqtt(ThingSmartThingMessageType.PROPERTY, "{}", cb)
        assert cb.errors == [("10202", "device is not in cloud online")]

    def test_http_empty_payload_11001(self) -> None:
        model = _model()
        cb = _Cb()
        model.send_link_message_by_http(ThingSmartThingMessageType.PROPERTY, "", cb)
        assert cb.errors == [("11001", None)]

    def test_http_action_api(self) -> None:
        calls: list = []
        model = _model(atop_send=lambda api, ver, data, cb: calls.append((api, data)))
        model.send_link_message_by_http(
            ThingSmartThingMessageType.ACTION,
            '{"actionCode":"feed","inputParams":{"portion":3}}',
            _Cb(),
        )
        api, data = calls[0]
        assert api == "thing.m.device.action.async.publish"
        assert data["actionCode"] == "feed"
        # inputParams JSONObject → getString → its JSON string
        assert data["inputParams"] == '{"portion":3}'

    def test_http_action_parse_error_silent(self) -> None:
        model = _model(atop_send=lambda *a: None)
        cb = _Cb()
        model.send_link_message_by_http(ThingSmartThingMessageType.ACTION, "not-json", cb)
        assert cb.errors == [] and cb.successes == 0

    def test_http_event_silent(self) -> None:
        model = _model(atop_send=lambda *a: None)
        cb = _Cb()
        model.send_link_message_by_http(ThingSmartThingMessageType.EVENT, "{}", cb)
        assert cb.errors == [] and cb.successes == 0

    def test_link_mqtt_send_missing_device(self) -> None:
        model = _model()
        cb = _Cb()
        model.link_mqtt_send("ghost", 0, "{}", cb)
        assert cb.errors == [("10202", "device is not exists")]


# ---------------------------------------------------------------------------
# AbsThingDevice.publishThingMessageWithType
# ---------------------------------------------------------------------------


class TestPublishThingMessage:
    def _presenter(self, modes: list[int], **model_kw: Any) -> ThingDevicePresenter:
        model = _model(**model_kw)
        cache = model.cache
        resp = cache.dev_map["dev1"]
        resp.communication = SimpleNamespace(
            communication_modes=[CommunicationModuleT(t) for t in modes],
            data_model=2,
        )
        return ThingDevicePresenter("dev1", model, cache)

    def _seed_model(self, presenter: ThingDevicePresenter) -> None:
        cache = ThingModelCache.instance()
        cache._map.clear()
        cache.put(ThingSmartThingModel.from_json(MODEL_JSON))

    def test_mqtt_handler_chosen(self) -> None:
        presenter = self._presenter([1])
        self._seed_model(presenter)
        sent: list = []
        presenter.model.link_mqtt_server = SimpleNamespace(
            publish_link_with_topic=lambda b, cb: sent.append(b)
        )
        cb = _Cb()
        presenter.publish_thing_message(ThingSmartThingMessageType.PROPERTY, {"switch": True}, cb)
        assert sent and sent[0].topic_id == "tylink/dev1/thing/property/set"
        assert sent[0].data == {"switch": True}

    def test_http_handler_chosen_when_mqtt_absent(self) -> None:
        calls: list = []
        presenter = self._presenter([2], atop_send=lambda api, ver, data, cb: calls.append(api))
        self._seed_model(presenter)
        presenter.publish_thing_message(
            ThingSmartThingMessageType.PROPERTY, {"switch": True}, _Cb()
        )
        assert calls == ["thing.m.device.dp.publish"]

    def test_conversion_failure_11001(self) -> None:
        presenter = self._presenter([1])
        self._seed_model(presenter)
        cb = _Cb()
        # ro property → property_send returns False → conversion "fails"
        # only for None; False is non-null so it would be sent! use an
        # unmatched key instead → count mismatch → None → 11001
        presenter.publish_thing_message(ThingSmartThingMessageType.PROPERTY, {"bogus": 1}, cb)
        assert cb.errors == [("11001", None)]

    def test_event_type_11001(self) -> None:
        presenter = self._presenter([1])
        self._seed_model(presenter)
        cb = _Cb()
        presenter.publish_thing_message(ThingSmartThingMessageType.EVENT, {"e": 1}, cb)
        assert cb.errors == [("11001", None)]

    def test_no_handler_11005(self) -> None:
        # LAN-only device: chain head stays null
        presenter = self._presenter([0])
        self._seed_model(presenter)
        cb = _Cb()
        presenter.publish_thing_message(ThingSmartThingMessageType.PROPERTY, {"switch": True}, cb)
        assert cb.errors == [("11005", "send error")]


# ---------------------------------------------------------------------------
# getThingModelWithPid
# ---------------------------------------------------------------------------


class TestGetThingModel:
    def test_fetch_and_cache(self) -> None:
        fetches: list = []

        def _fetch(api, ver, data, listener):
            fetches.append((api, data))
            listener.on_success(MODEL_JSON)

        cb = _Cb()
        cache = ThingModelCache()
        get_thing_model_with_pid(_fetch, "pid1", None, cb, model_cache=cache)
        assert fetches == [
            (
                "thing.m.product.thing.model",
                {"productId": "pid1", "productVersion": "1.0.0"},
            )
        ]
        assert cb.successes == 1
        assert cache.get("pid1", "1.0.0") is cb.results[0]

    def test_ver_from_cached_device(self) -> None:
        dev_cache = DevListCacheManager()
        dev_cache.dev_map["d"] = _resp(product_ver="9.9")
        fetches: list = []

        def _fetch(api, ver, data, listener):
            fetches.append(data)
            listener.on_success(MODEL_JSON)

        get_thing_model_with_pid(_fetch, "pid1", "", _Cb(), dev_cache=dev_cache)
        assert fetches[0]["productVersion"] == "9.9"

    def test_failure_forwards(self) -> None:
        cb = _Cb()
        get_thing_model_with_pid(lambda a, v, d, l: l.on_error("E1", "bad"), "p", "1", cb)
        assert cb.errors == [("E1", "bad")]
