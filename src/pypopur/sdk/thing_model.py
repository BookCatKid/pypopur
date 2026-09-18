"""Thing-model subsystem — ports of the link-message conversion and
publishing chain used for ``DataModelType.THING_MODEL`` devices.

smali sources (``smali_classes3`` unless noted):

- ``sdk/device/qqbbddb.smali``    — ``LinkFilterConvertUtil``
- ``sdk/device/bdpqppd.smali``    — ``PropertyCheckUtil``
- ``sdk/device/bppdpdq.smali``    — ``ActionCheckUtil``
- ``sdk/device/qqqpdpb.smali``    — ``EventCheckUtil``
- ``sdk/device/bbdppqp.smali``    — ``TypeSpecCheckUtil``
- ``sdk/device/qpppdbb.smali``    — thing-model singleton cache
- ``sdk/device/qqqbbbd.smali``    — link-message handler base (handle/chain)
- ``sdk/device/dpdqddb.smali``    — base carrying the message type
- ``sdk/device/dbddpbp.smali``    — MQTT link handler
- ``sdk/device/dqqpqbq.smali``    — HTTP link handler
- ``sdk/device/qdbpqqq.smali``    — ``MqttLinkControlModel`` + builder/callback
- ``sdk/device/config/MqttConfig.smali`` — ``tylink/`` prefix
- ``sdk/device/qpbpqpq.smali``    — ``sendLinkMessageByMqtt/Http``
- ``sdk/device/qqdbbpp.smali``    — MQTT leaf (device lookup + SandO)
- ``sdk/device/dqdpbbd.smali``    — ``DevCloudControlImpl`` dispatcher
- ``sdk/device/dbppbbp.smali``    — HTTP leaf ATOP calls
- ``sdk/device/presenter/AbsThingDevice.smali`` —
  ``publishThingMessageWithType``
- ``smart/sdk/bean/ThingSmartThing*.smali`` (smali_classes4) — model beans
- ``sdk/device/utils/linkcheck/bean/*.smali`` — action/event payload beans
- ``smart/android/device/bean/CommonSpecParamsBean.smali`` — spec bean
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, ClassVar

from . import hexutil
from ._fastjson import to_json_bytes, to_json_string
from ._java import text_is_empty
from .comm_pipeline import (
    CommHandler,
    CommunicationEnum,
    DevModel,
    PipelineAnalytics,
    ThingDevicePresenter,
    ThingSmartThingMessageType,
)
from .device_cache import DeviceDataManager, DevListCacheManager
from .lan_control import ResultCallback
from .schema import (
    to_array_schema,
    to_bitmap_schema,
    to_enum_schema,
    to_string_schema,
    to_struct_schema,
    to_value_schema,
)

log = logging.getLogger("pypopur.thing_model")

_TAG = "LinkFilterConvertUtil"

# MqttConfig.downLinkTopicPrefix — "thinglink/".replace("hing", "y")
DOWN_LINK_TOPIC_PREFIX = "tylink/"

# Default product version used when the bean's is empty (qpppdbb /
# getThingModelWithPid both fall back to it).
DEFAULT_PRODUCT_VER = "1.0.0"


# ---------------------------------------------------------------------------
# ThingSmartThing* beans (smali_classes4/smart/sdk/bean)
# ---------------------------------------------------------------------------


@dataclass
class ThingSmartThingProperty:
    """``ThingSmartThingProperty`` — ``typeSpec`` is the raw spec map."""

    ability_id: int = 0
    access_mode: str | None = None
    code: str | None = None
    default_value: Any = None
    type_spec: dict[str, Any] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> ThingSmartThingProperty:
        return cls(
            ability_id=int(obj.get("abilityId") or 0),
            access_mode=obj.get("accessMode"),
            code=obj.get("code"),
            default_value=obj.get("defaultValue"),
            type_spec=obj.get("typeSpec"),
        )


@dataclass
class ThingSmartThingAction:
    """``ThingSmartThingAction`` — ``inputParams``/``outputParams`` are raw
    spec lists (each element deserializes to ``CommonSpecParamsBean``)."""

    ability_id: int = 0
    code: str | None = None
    input_params: list[Any] | None = None
    output_params: list[Any] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> ThingSmartThingAction:
        return cls(
            ability_id=int(obj.get("abilityId") or 0),
            code=obj.get("code"),
            input_params=obj.get("inputParams"),
            output_params=obj.get("outputParams"),
        )


@dataclass
class ThingSmartThingEvent:
    """``ThingSmartThingEvent``."""

    ability_id: int = 0
    code: str | None = None
    output_params: list[Any] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> ThingSmartThingEvent:
        return cls(
            ability_id=int(obj.get("abilityId") or 0),
            code=obj.get("code"),
            output_params=obj.get("outputParams"),
        )


@dataclass
class ThingSmartThingServiceModel:
    """``ThingSmartThingServiceModel``."""

    actions: list[ThingSmartThingAction] | None = None
    events: list[ThingSmartThingEvent] | None = None
    properties: list[ThingSmartThingProperty] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> ThingSmartThingServiceModel:
        def _items(key: str, maker: Any) -> list[Any] | None:
            raw = obj.get(key)
            if raw is None:
                return None
            return [maker(item) if isinstance(item, dict) else item for item in raw]

        return cls(
            actions=_items("actions", ThingSmartThingAction.from_json),
            events=_items("events", ThingSmartThingEvent.from_json),
            properties=_items("properties", ThingSmartThingProperty.from_json),
        )


@dataclass
class ThingSmartThingModel:
    """``ThingSmartThingModel``."""

    extensions: dict[str, Any] | None = None
    model_id: str | None = None
    product_id: str | None = None
    product_version: str | None = None
    services: list[ThingSmartThingServiceModel] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> ThingSmartThingModel:
        raw = obj.get("services")
        return cls(
            extensions=obj.get("extensions"),
            model_id=obj.get("modelId"),
            product_id=obj.get("productId"),
            product_version=obj.get("productVersion"),
            services=(
                [
                    ThingSmartThingServiceModel.from_json(s) if isinstance(s, dict) else s
                    for s in raw
                ]
                if raw is not None
                else None
            ),
        )


@dataclass
class CommonSpecParamsBean:
    """``CommonSpecParamsBean`` — action/event param spec (``code`` +
    ``typeSpec`` map)."""

    code: str | None = None
    type_spec: dict[str, Any] | None = None

    @classmethod
    def from_json(cls, obj: Any) -> CommonSpecParamsBean:
        if not isinstance(obj, dict):
            obj = {}
        return cls(code=obj.get("code"), type_spec=obj.get("typeSpec"))


@dataclass
class ActionSendBean:
    """``ActionSendBean`` — outgoing action payload."""

    action_code: str | None = None
    input_params: dict[str, Any] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> ActionSendBean:
        return cls(
            action_code=obj.get("actionCode"),
            input_params=obj.get("inputParams"),
        )


@dataclass
class ActionReceiveBean:
    """``ActionReceiveBean`` — incoming action-result payload."""

    action_code: str | None = None
    action_time: str | None = None
    output_params: dict[str, Any] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> ActionReceiveBean:
        return cls(
            action_code=obj.get("actionCode"),
            action_time=obj.get("actionTime"),
            output_params=obj.get("outputParams"),
        )


@dataclass
class EventReceiveBean:
    """``EventReceiveBean`` — incoming event payload."""

    event_code: str | None = None
    event_time: str | None = None
    output_params: dict[str, Any] | None = None

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> EventReceiveBean:
        return cls(
            event_code=obj.get("eventCode"),
            event_time=obj.get("eventTime"),
            output_params=obj.get("outputParams"),
        )


# ---------------------------------------------------------------------------
# qpppdbb — thing-model cache singleton
# ---------------------------------------------------------------------------


class ThingModelCache:
    """``qpppdbb`` — ``Map<pid_ver, ThingSmartThingModel>``; empty product
    version falls back to ``"1.0.0"``."""

    _instance: ClassVar[ThingModelCache | None] = None

    def __init__(self) -> None:
        self._map: dict[str, ThingSmartThingModel] = {}

    @classmethod
    def instance(cls) -> ThingModelCache:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @staticmethod
    def _key(product_id: str, product_ver: str | None) -> str:
        return f"{product_id}_{product_ver}"

    def get(self, product_id: str | None, product_ver: str | None) -> ThingSmartThingModel | None:
        """``bdpdqbp(String,String)`` — empty pid → None; NULL ver → 1.0.0
        (empty string is NOT defaulted — ``if-nez`` null check only)."""
        if text_is_empty(product_id):
            return None
        if product_ver is None:
            product_ver = DEFAULT_PRODUCT_VER
        return self._map.get(self._key(product_id, product_ver))

    def put(self, model: ThingSmartThingModel | None) -> None:
        """``bdpdqbp(ThingSmartThingModel)`` — null/empty pid → ignored."""
        if model is None:
            return
        product_id = model.product_id
        if text_is_empty(product_id):
            return
        product_ver = model.product_version
        if product_ver is None:
            product_ver = DEFAULT_PRODUCT_VER
        self._map[self._key(product_id, product_ver)] = model

    def clear(self) -> None:
        self._map.clear()

    def remove(self, product_id: str | None, product_ver: str | None) -> None:
        """``pdqppqb(String,String)`` — empty pid or empty map → no-op."""
        if not self._map:
            return
        if text_is_empty(product_id):
            return
        if product_ver is None:
            product_ver = DEFAULT_PRODUCT_VER
        self._map.pop(self._key(product_id, product_ver), None)


# qdddbpp.dpdbqdp — the thing-model ATOP api.
THING_MODEL_API = "thing.m.product.thing.model"


def get_thing_model_with_pid(
    fetch: Any,
    product_id: str,
    product_ver: str | None,
    cb: Any,
    *,
    model_cache: ThingModelCache | None = None,
    dev_cache: DevListCacheManager | None = None,
) -> None:
    """``ddpdbbp.getThingModelWithPid`` (2108-2268) +
    ``qdddbpp.pdqppqb`` (953-989).

    Empty ``product_ver`` is resolved by scanning the cached dev list for
    a bean with a matching ``productId`` (last match wins — the smali
    loop never breaks), then ``"1.0.0"``.  ``fetch`` is the
    ``Business.asyncRequest`` seam — ``(api, version, post_data,
    listener)`` where ``listener.on_success(result)`` gets the raw result
    and ``listener.on_error(code, msg)`` the failure.  On success the
    parsed ``ThingSmartThingModel`` is put into ``qpppdbb`` and
    ``cb.on_success(model)`` fires.
    """
    if text_is_empty(product_ver) and dev_cache is not None:
        for bean in dev_cache.get_dev_list():
            if bean is not None and bean.product_id == product_id:
                product_ver = bean.product_ver
    if text_is_empty(product_ver):
        product_ver = DEFAULT_PRODUCT_VER
    cache = model_cache or ThingModelCache.instance()

    class _Listener:
        """``ddpdbbp$pbddddb`` — put into ``qpppdbb`` → ``onSuccess``."""

        def on_success(self, result: Any) -> None:
            model = ThingSmartThingModel.from_json(result) if isinstance(result, dict) else result
            cache.put(model)
            if cb is not None:
                cb.on_success(model)

        def on_error(self, code: str, msg: str | None) -> None:
            if cb is not None:
                cb.on_error(code, msg)

    fetch(
        THING_MODEL_API,
        "1.0",
        {"productId": product_id, "productVersion": product_ver},
        _Listener(),
    )


# ---------------------------------------------------------------------------
# bbdppqp — TypeSpecCheckUtil
# ---------------------------------------------------------------------------

_DATA_TYPE_RAW = "raw"  # DataTypeEnum.RAW.getType()


def _decode_base64_loose(data: bytes) -> bytes:
    """``Base64.decodeBase64`` (commons-codec) — discards non-alphabet
    bytes and decodes partial trailing groups."""
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    cleaned = bytes(c for c in data if c in alphabet)
    cleaned += b"=" * ((-len(cleaned)) % 4)
    return base64.b64decode(cleaned, validate=False)


def _simple_convert(type_: str | None, value: Any, spec_json: str | None, strict: bool) -> Any:
    """``bbdppqp.bdpdqbp(String,Object,String,boolean)`` — bool/string/date/
    raw only; every other type → null (caller falls through)."""
    if type_ == "bool":
        if isinstance(value, bool):
            return value
    elif type_ == "string":
        s = str(value) if not isinstance(value, str) else value
        # Java check-casts to String — a non-String raises in the caller's
        # try; here the caller catches our TypeError the same way.
        if not isinstance(value, str):
            raise TypeError(f"cannot cast {type(value).__name__} to String")
        bean = to_string_schema(spec_json)
        if len(s) <= bean.maxlen:
            return value
    elif type_ == "date":
        if 10 <= len(str(value)) <= 13:
            return value
    elif type_ == _DATA_TYPE_RAW:
        if not isinstance(value, str):
            raise TypeError(f"cannot cast {type(value).__name__} to String")
        if not strict:
            # decodeBase64(getBytes) → bytesToHexString
            value = hexutil.bytes_to_hex_string(_decode_base64_loose(value.encode()))
        if value is not None and hexutil.check_hex_string(value):
            if len(value) % 2 == 1:
                return None
            if strict:
                return base64.b64encode(hexutil.hex_string_to_bytes(value) or b"").decode()
            return value
    return None


def _array_elements(
    type_: str | None, values: list[Any], spec_json: str | None, strict: bool
) -> Any:
    """``bbdppqp.bdpdqbp(String,List,String,boolean)`` — only
    bool/string/date/raw element types are converted; anything else
    returns the input list unchanged."""
    if type_ not in ("bool", "string", "date", _DATA_TYPE_RAW):
        return values
    out: list[Any] = []
    count = 0
    for element in values:
        converted = _simple_convert(type_, element, spec_json, strict)
        if converted is not None:
            count += 1
        elif strict:
            return None
        if converted is not None:
            out.append(converted)
    if count == 0:
        return None
    return out


def _struct_fields(
    value: dict[str, Any] | None,
    properties: dict[str, Any],
    strict: bool,
) -> Any:
    """``bbdppqp.bdpdqbp(Map,Map,boolean)`` — mutates ``value`` in place;
    every matched field's converted value is written back. Strict mode fails
    the whole struct on the first invalid field."""
    if value is None:
        return None
    for key, field_value in value.items():
        for prop_key, prop in properties.items():
            if key == prop_key:
                spec = prop.type_spec  # JSONObject at runtime
                converted = type_spec_convert(
                    (spec or {}).get("type"),
                    field_value,
                    to_json_string(spec),
                    strict,
                )
                if converted is None and strict:
                    return None
                if converted is not None:
                    value[key] = converted
                # Java keeps iterating the spec map — keys are unique so no
                # second match is possible; identical to breaking here.
                break
    return value


def type_spec_convert(type_: str | None, value: Any, spec_json: str | None, strict: bool) -> Any:
    """``bbdppqp.pdqppqb(String,Object,String,boolean)``.

    Null is returned ONLY for: simple-type failures, enum misses, array
    failures, struct failures. Out-of-range ``value``/``bitmap`` inputs,
    cast failures, unknown types, and exceptions all fall through to
    ``return value`` — the "compat cloud add unknown type" tail."""
    try:
        converted = _simple_convert(type_, value, spec_json, strict)
        if converted is not None:
            return converted
        if type_ == "enum":
            if not isinstance(value, str):
                raise TypeError(f"cannot cast {type(value).__name__} to String")
            bean = to_enum_schema(spec_json)
            if bean is None or bean.range is None or value not in bean.range:
                return None
            return value
        if type_ == "value":
            if isinstance(value, bool):
                pass  # bool is not a Java Number — falls to compat return
            elif isinstance(value, (int, float)):
                bean = to_value_schema(spec_json)
                if bean.min <= value <= bean.max:
                    return value
        elif type_ == "bitmap":
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"cannot cast {type(value).__name__} to Integer")
            bean = to_bitmap_schema(spec_json)
            width = bean.maxlen
            if width == 0 and bean.label is not None:
                width = len(bean.label)
            if 0 <= value < (1 << width):
                return value
        elif type_ == "array":
            parsed = json.loads(to_json_string(value))
            bean = to_array_schema(spec_json)
            if isinstance(parsed, list) and bean is not None and len(parsed) <= bean.max_size:
                spec = bean.element_type_spec  # JSONObject at runtime
                return _array_elements(
                    (spec or {}).get("type"), parsed, to_json_string(spec), strict
                )
            return None
        elif type_ == "struct":
            bean = to_struct_schema(spec_json)
            if bean is None or not bean.properties:
                return None
            parsed = json.loads(to_json_string(value))
            return _struct_fields(parsed, bean.properties, strict)
    except Exception as exc:
        log.info("checkSendOrReceive error %s", exc)
    log.info("unknown type : %s, also return, compat cloud add unknown type.", type_)
    return value


# ---------------------------------------------------------------------------
# bdpqppd — PropertyCheckUtil
# ---------------------------------------------------------------------------


def _wrap_value(value: Any) -> dict[str, Any]:
    """``bdpqppd.bdpdqbp(Object)`` — JSONObject input with ``value`` but no
    ``time`` gets ``time`` added; one with both is returned unchanged; any
    other input wraps to ``{value, time:now}``."""
    if isinstance(value, dict):
        has_value_only = "value" in value and "time" not in value
        has_both = "value" in value and "time" in value
        if not has_value_only and not has_both:
            return {"value": value, "time": int(time.time() * 1000)}
        if has_value_only:
            value["time"] = int(time.time() * 1000)
        return value
    return {"value": value, "time": int(time.time() * 1000)}


def property_receive(
    services: list[ThingSmartThingServiceModel], payload: dict[str, Any]
) -> dict[str, Any]:
    """``bdpqppd.bdpdqbp(List,Map)`` — inbound code-keyed properties:
    wrap each value, validate (non-strict), keep valid entries wrapped."""
    out: dict[str, Any] = {}
    for service in services:
        props = service.properties
        if not props:
            continue
        for key, raw in payload.items():
            for prop in props:
                if prop is None:
                    continue
                if key == prop.code:
                    spec = prop.type_spec
                    if spec is None or len(spec) == 0:
                        log.info("typeSpec is empty, remove -> key = %s", key)
                    wrapped = _wrap_value(raw)
                    converted = type_spec_convert(
                        spec.get("type"),  # None spec → AttributeError → caller catch
                        wrapped.get("value"),
                        to_json_string(spec),
                        False,
                    )
                    if converted is not None:
                        wrapped["value"] = converted
                        out[key] = wrapped
                    else:
                        log.info("not matched, remove -> key = %s", key)
    return out


def property_send(services: list[ThingSmartThingServiceModel], payload: dict[str, Any]) -> Any:
    """``bdpqppd.pdqppqb(List,Map)`` — outbound code-keyed properties.

    Returns the mutated payload map when every entry validates, ``None``
    on an invalid value or count mismatch, and ``False`` (Java
    ``Boolean.FALSE`` — non-null!) on ``ro`` access or missing typeSpec."""
    count = 0
    for service in services:
        props = service.properties
        if not props:
            continue
        for key, raw in payload.items():
            for prop in props:
                if prop is None:
                    continue
                if key == prop.code:
                    if prop.access_mode == "ro":  # ModeEnum.RO.getType()
                        return False
                    spec = prop.type_spec
                    if spec is None or len(spec) == 0:
                        return False
                    converted = type_spec_convert(spec.get("type"), raw, to_json_string(spec), True)
                    if converted is None:
                        log.info("key :%s is not right", key)
                        return None
                    payload[key] = converted
                    count += 1
    return payload if count == len(payload) else None


# ---------------------------------------------------------------------------
# bppdpdq — ActionCheckUtil
# ---------------------------------------------------------------------------


def action_receive(
    services: list[ThingSmartThingServiceModel], payload: dict[str, Any]
) -> dict[str, Any]:
    """``bppdpdq.bdpdqbp(List,Map)`` — inbound action results; keeps only
    spec-matched params, storing the ORIGINAL value (smali quirk)."""
    bean = ActionReceiveBean.from_json(json.loads(to_json_string(payload)))
    output = bean.output_params
    out: dict[str, Any] = {}
    _ = len(output)  # new HashMap(outputParams.size()) — NPE on null
    found = False
    for service in services:
        actions = service.actions
        if not actions:
            continue
        for action in actions:
            if action is None:
                continue
            spec_list = action.output_params
            if not spec_list:
                continue
            specs = [
                CommonSpecParamsBean.from_json(item)
                for item in json.loads(to_json_string(spec_list))
            ]
            if bean.action_code == action.code:
                for key, raw in output.items():
                    for spec in specs:
                        if key == spec.code:
                            try:
                                converted = type_spec_convert(
                                    (spec.type_spec or {}).get("type"),
                                    raw,
                                    to_json_string(spec.type_spec),
                                    False,
                                )
                                if converted is not None:
                                    out[key] = raw  # stores the ORIGINAL
                                else:
                                    log.info("not matched, remove -> key = %s", key)
                            except Exception as exc:
                                log.error("itemInput %s", exc)
                            break
                found = True
            if found:
                break
        if found:
            continue
    payload["outputParams"] = out
    return payload


def action_send(services: list[ThingSmartThingServiceModel], payload: dict[str, Any]) -> Any:
    """``bppdpdq.pdqppqb(List,Map)`` — outbound actions; validates each
    input param (strict) but stores the ORIGINAL value (smali quirk)."""
    bean = ActionSendBean.from_json(json.loads(to_json_string(payload)))
    input_params = bean.input_params  # deep-copied map; null → NPE on use
    count = 0
    found = False
    for service in services:
        actions = service.actions
        if not actions:
            continue
        for action in actions:
            if action is None:
                continue
            if bean.action_code == action.code:
                spec_list = action.input_params
                found = True
                if not spec_list:
                    count = 0
                    continue
                specs = [
                    CommonSpecParamsBean.from_json(item)
                    for item in json.loads(to_json_string(spec_list))
                ]
                n = 0
                for key, raw in input_params.items():
                    for spec in specs:
                        if key == spec.code:
                            try:
                                converted = type_spec_convert(
                                    (spec.type_spec or {}).get("type"),
                                    raw,
                                    to_json_string(spec.type_spec),
                                    True,
                                )
                                if converted is None:
                                    log.info("not matched, key :%s", key)
                                    return None
                                input_params[key] = raw  # stores the ORIGINAL
                            except Exception as exc:
                                log.error("itemInput %s", exc)
                            n += 1
                            break
                count = n
            if found:
                break
        if found:
            continue
    if count == len(input_params):
        payload["inputParams"] = input_params
        return payload
    return None


# ---------------------------------------------------------------------------
# qqqpdpb — EventCheckUtil
# ---------------------------------------------------------------------------


def event_receive(
    services: list[ThingSmartThingServiceModel], payload: dict[str, Any]
) -> dict[str, Any]:
    """``qqqpdpb.bdpdqbp(List,Map)`` — inbound events; keeps spec-matched
    params, storing the CONVERTED value."""
    bean = EventReceiveBean.from_json(json.loads(to_json_string(payload)))
    output = bean.output_params
    out: dict[str, Any] = {}
    _ = len(output)  # new HashMap(outputParams.size()) — NPE on null
    found = False
    for service in services:
        if service is None:
            continue
        events = service.events
        if not events:
            continue
        for event in events:
            if bean.event_code == event.code:
                spec_list = event.output_params
                found = True
                if not spec_list:
                    continue
                specs = [
                    CommonSpecParamsBean.from_json(item)
                    for item in json.loads(to_json_string(spec_list))
                ]
                for key, raw in output.items():
                    for spec in specs:
                        if key == spec.code:
                            converted = type_spec_convert(
                                (spec.type_spec or {}).get("type"),
                                raw,
                                to_json_string(spec.type_spec),
                                False,
                            )
                            if converted is not None:
                                out[key] = converted  # stores the CONVERTED
                            else:
                                log.info("not matched, remove -> key = %s", key)
                            break
            if found:
                break
        if found:
            continue
    payload["outputParams"] = out
    return payload


# ---------------------------------------------------------------------------
# qqbbddb — LinkFilterConvertUtil
# ---------------------------------------------------------------------------


class LinkFilterConvertUtil:
    """``qqbbddb`` — every method is static in Java; bound to the dev-list
    cache + model cache + the dp-update event post here."""

    def __init__(
        self,
        cache: DevListCacheManager,
        model_cache: ThingModelCache | None = None,
        *,
        on_dp_update: Any = None,
    ) -> None:
        self.cache = cache
        self.model_cache = model_cache or ThingModelCache.instance()
        self.data = DeviceDataManager(cache)
        # ``bdqqbqd.bdpdqbp(devId, dpsJson, isCloud, dpsTime)`` — the
        # DpUpdateEventModel post; ``CentralDpIngest.on_dp_update`` shape.
        self.on_dp_update = on_dp_update

    # -- model lookup --------------------------------------------------------

    def get_thing_model_services(self, dev_id: str) -> list[ThingSmartThingServiceModel] | None:
        """``bdpdqbp(String)`` — resp/model/services each null-or-empty
        → null (with the same warn logs)."""
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is None:
            log.warning("device is not exists!")
            return None
        model = self.model_cache.get(resp.product_id, resp.product_ver)
        if model is None:
            log.warning("device thing model is not exists!")
            return None
        services = model.services
        if not services:
            log.warning("thing model data is empty!")
            return None
        return services

    # -- outgoing conversion (publishThingMessageWithType entry) -------------

    def convert_out(self, dev_id: str, msg_type: int | None, command: Any) -> Any:
        """``bdpdqbp(String,ThingSmartThingMessageType,Object)`` — null
        command/type → None; EVENT → None; PROPERTY → ``bdpqppd``;
        ACTION → ``bppdpdq``; anything else / exception → None."""
        if command is None or msg_type is None:
            return None
        try:
            payload_json = to_json_string(command)
            if msg_type == ThingSmartThingMessageType.EVENT:
                return None
            services = self.get_thing_model_services(dev_id)
            if not services:
                return None
            mapping = json.loads(payload_json)
            if msg_type == ThingSmartThingMessageType.PROPERTY:
                return property_send(services, mapping)
            if msg_type == ThingSmartThingMessageType.ACTION:
                return action_send(services, mapping)
            return None
        except Exception:
            return None

    # -- incoming conversion (link-message ingest) ----------------------------

    def convert_in(
        self, dev_id: str, msg_type: int | None, payload: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """``bdpdqbp(String,ThingSmartThingMessageType,Map)`` — the
        receive-side dispatcher used by the MQTT/HTTP link parsers."""
        if payload is None or msg_type is None:
            log.debug("null")
            return None
        try:
            services = self.get_thing_model_services(dev_id)
            if not services:
                log.warning("thing model data is empty!")
                return None
            # fastjson toJSONString→parseObject deep copy (Map TypeReference)
            mapping = json.loads(to_json_string(payload))
            if msg_type == ThingSmartThingMessageType.EVENT:
                return event_receive(services, mapping)
            if msg_type == ThingSmartThingMessageType.PROPERTY:
                return property_receive(services, mapping)
            if msg_type == ThingSmartThingMessageType.ACTION:
                return action_receive(services, mapping)
            return None
        except Exception as exc:
            log.debug("%s", exc)
            return None

    # -- link property → dps (the bdqqbqd notify path) ------------------------

    def convert_to_dps_with_link_property(self, dev_id: str, payload_json: str) -> str:
        """``bdpdqbp(String,String)`` — code-keyed ``{value,time}`` payloads
        → dpId-keyed dps JSON; merges the dp + time caches and posts the
        dp-update event when anything matched."""
        out: dict[str, Any] = {}
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is not None:
            model = self.model_cache.get(resp.product_id, resp.product_ver)
            if model is None:
                return "{}"
            services = model.services
            if not services:
                return "{}"
            dp_map: dict[str, Any] = {}
            time_map: dict[str, int] = {}
            try:
                payload = json.loads(payload_json)
                for service in services:
                    props = service.properties
                    if not props:
                        continue
                    for prop in props:
                        if prop.code in payload:
                            # getJSONObject — a non-object raises, aborting
                            # the whole loop into the catch (faithful).
                            obj = payload[prop.code]
                            if not isinstance(obj, dict):
                                raise TypeError("not a JSONObject")
                            ability_id = str(prop.ability_id)
                            val = obj.get("value")
                            out[ability_id] = val
                            dp_map[ability_id] = val
                            if "time" in obj:
                                time_map[ability_id] = int(obj["time"])
                if dp_map:
                    self.merge_dp_cache(dev_id, dp_map)
                    self.merge_dp_time(dev_id, time_map)
                    if self.on_dp_update is not None:
                        self.on_dp_update(dev_id, to_json_string(out), True, time_map)
                else:
                    log.debug("no dp need to update")
            except Exception as exc:
                log.debug("convertToDpsWithLinkProperty error : %s", exc)
        return to_json_string(out)

    # -- dpId → code conversion (the publishDps THING_MODEL path) -------------

    def convert_to_link_property(self, dev_id: str, payload_json: str) -> str:
        """``pdqppqb(String,String)`` — dpId-keyed payload → code-keyed
        link property JSON. Faithful quirk: the smali checks
        ``containsKey(abilityId)`` but reads ``payload.get(code)`` — so a
        correctly-keyed input emits ``{code: null}``."""
        out: dict[str, Any] = {}
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is not None:
            model = self.model_cache.get(resp.product_id, resp.product_ver)
            if model is None:
                return "{}"
            services = model.services
            if not services:
                return "{}"
            payload = json.loads(payload_json)
            if payload is None or len(payload) == 0:
                return "{}"
            try:
                for service in services:
                    props = service.properties
                    if not props:
                        continue
                    for prop in props:
                        if str(prop.ability_id) in payload:
                            out[prop.code] = payload.get(prop.code)
            except Exception:
                pass
        return to_json_string(out)

    # -- cache merges ----------------------------------------------------------

    def merge_dp_cache(self, dev_id: str, dps: dict[str, Any]) -> dict | None:
        """``bdpdqbp(String,Map)`` — merge into the cached dps; the INPUT
        map is returned. When the cached map is null the puts land in a
        throwaway HashMap — the bean keeps null (faithful)."""
        if self.cache.get_dev_resp_bean(dev_id) is None:
            return None
        target = self.data.get_dps(dev_id)
        if target is None:
            target = {}
        for k, v in dps.items():
            target[k] = v
        return dps

    def merge_dp_time(self, dev_id: str, dps_time: dict[str, int] | None) -> dict | None:
        """``pdqppqb(String,Map)`` — merge into ``resp.dpsTime``; null input
        or missing resp → None; creates+attaches the map when absent."""
        if dps_time is None:
            log.warning("dpTimeMap == null")
            return None
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is None:
            return None
        target = resp.get_dps_time() if resp.data_point_info else None
        if target is None:
            target = {}
            resp.set_dps_time(target)
        for k, v in dps_time.items():
            target[k] = v
        return dps_time


# ---------------------------------------------------------------------------
# qdbpqqq — MqttLinkControlModel
# ---------------------------------------------------------------------------


@dataclass
class MqttControlBuilder:
    """``MqttControlBuilder`` — the link-message envelope."""

    data: Any = None
    topic_id: str | None = None
    sn: int = 0
    o: int = 0
    s: int = 0
    t: int = 0

    def set_data(self, data: Any) -> MqttControlBuilder:
        self.data = data
        return self

    def set_topic_id(self, topic_id: str) -> MqttControlBuilder:
        self.topic_id = topic_id
        return self

    def set_sn(self, sn: int) -> MqttControlBuilder:
        self.sn = sn
        return self

    def set_o(self, o: int) -> MqttControlBuilder:
        self.o = o
        return self

    def set_s(self, s: int) -> MqttControlBuilder:
        self.s = s
        return self

    def set_t(self, t: int) -> MqttControlBuilder:
        self.t = t
        return self


class _LinkStatCallback:
    """``qdbpqqq$bdpdqbp`` — forwards the result and posts the
    ``thing_vlt9u1rn677ht6wxpnxlt9em1p4pfp2u`` stat; error messages gain a
    trailing ``#`` (already-recorded marker for ``StatStripCallback``)."""

    EVENT_ID = "thing_vlt9u1rn677ht6wxpnxlt9em1p4pfp2u"

    def __init__(
        self, inner: ResultCallback | None, dev_id: str, msg_type: int, stat: Any = None
    ) -> None:
        self.inner = inner
        self.dev_id = dev_id
        self.msg_type = msg_type
        self.stat = stat

    def _type_name(self) -> str:
        if self.msg_type == ThingSmartThingMessageType.ACTION:
            return "action"
        if self.msg_type == ThingSmartThingMessageType.EVENT:
            return "event"
        return "property"

    def on_error(self, code: str, msg: str | None) -> None:
        if self.inner is not None:
            self.inner.on_error(code, f"{msg}#" if msg is not None else "#")
        if self.stat is not None:
            self.stat(
                self.EVENT_ID,
                {
                    "device_id": self.dev_id,
                    "type": self._type_name(),
                    "result": "fail",
                    "errorMsg": f"{code} / {msg}",
                },
            )

    def on_success(self) -> None:
        if self.inner is not None:
            self.inner.on_success()
        if self.stat is not None:
            self.stat(
                self.EVENT_ID,
                {
                    "device_id": self.dev_id,
                    "type": self._type_name(),
                    "result": "success",
                },
            )


def link_message_topic(dev_id: str, msg_type: int) -> str:
    """The topic branch of ``qdbpqqq.bdpdqbp`` — EVENT/other → ""."""
    if msg_type == ThingSmartThingMessageType.PROPERTY:
        return f"{DOWN_LINK_TOPIC_PREFIX}{dev_id}/thing/property/set"
    if msg_type == ThingSmartThingMessageType.ACTION:
        return f"{DOWN_LINK_TOPIC_PREFIX}{dev_id}/thing/action/execute"
    return ""


def publish_link_message(
    dev_id: str,
    msg_type: int,
    data: Any,
    sand_o: Any,
    cb: ResultCallback | None,
    *,
    mqtt_server: Any,
    stat: Any = None,
    current_timestamp: Any = None,
) -> None:
    """``qdbpqqq.bdpdqbp(devId,type,Object,SandO,cb)`` — builds the
    ``MqttControlBuilder`` and calls
    ``IMqttServer.publishLinkWithTopic``."""
    topic = link_message_topic(dev_id, msg_type)
    if text_is_empty(topic):
        if cb is not None:
            cb.on_error("11005", "send error")
        return
    now = current_timestamp() if current_timestamp is not None else int(time.time())
    builder = (
        MqttControlBuilder()
        .set_data(data)
        .set_topic_id(topic)
        .set_sn(sand_o.get_s())
        .set_o(sand_o.get_o())
        .set_s(sand_o.get_s())
        .set_t(int(now))
    )
    if mqtt_server is not None:
        mqtt_server.publish_link_with_topic(builder, _LinkStatCallback(cb, dev_id, msg_type, stat))


class LinkMqttServerAdapter:
    """``bqbppdq.publishLinkWithTopic`` (3558-3894) over a
    ``MqttWireClient``-shaped ``publish(topic, payload, cb)``.

    The ``qqdqqpd``→``ddqdbbd``→``qbbdpbq`` chain renders the builder to
    plaintext ``{"msgId": <s>, "time": <t>, "data": <data>}`` JSON (no
    encryption) and publishes it to ``builder.getTopicId()``; the
    ``smart/mb/in/`` subscribe in ``publishDevice`` is not part of the
    link path.
    """

    def __init__(self, client: Any) -> None:
        self.client = client

    def publish_link_with_topic(
        self, builder: MqttControlBuilder, cb: ResultCallback | None
    ) -> None:
        payload = to_json_bytes({"msgId": builder.s, "time": builder.t, "data": builder.data})
        self.client.publish(builder.topic_id, payload, cb)


# ---------------------------------------------------------------------------
# dpdqddb / dbddpbp / dqqpqbq — link-message comm handlers
# ---------------------------------------------------------------------------


class LinkCommHandler(CommHandler):
    """``dpdqddb`` — ``qqqbbbd`` + the ``ThingSmartThingMessageType`` field."""

    def __init__(
        self,
        dev_id: str,
        msg_type: int,
        model: DevModel,
        analytics: PipelineAnalytics | None = None,
    ) -> None:
        super().__init__(dev_id, model, analytics)
        self.msg_type = msg_type


class LinkMqttCommHandler(LinkCommHandler):
    """``dbddpbp`` — available ⇔ network && ``isCloudOnline``; send →
    ``mDevModel.sendLinkMessageByMqtt``."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.network_available: Any = lambda: True

    def name(self) -> str:
        return "MQTT"

    def available(self) -> bool:
        return self.network_available() and self.model.is_cloud_online()

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        self.model.send_link_message_by_mqtt(self.msg_type, dps, cb)


class LinkHttpCommHandler(LinkCommHandler):
    """``dqqpqbq`` — available ⇔ model present; send →
    ``mDevModel.sendLinkMessageByHttp``."""

    def name(self) -> str:
        return "HTTP"

    def available(self) -> bool:
        return self.model is not None

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        self.model.send_link_message_by_http(self.msg_type, dps, cb)


def publish_thing_message_with_type(
    presenter: ThingDevicePresenter,
    msg_type: int,
    command: Any,
    cb: ResultCallback | None,
    *,
    converter: LinkFilterConvertUtil | None = None,
) -> None:
    """``AbsThingDevice.publishThingMessageWithType`` — converts the
    command through ``qqbbddb`` (null → ``11001``), builds the
    MQTT/HTTP handler chain from the device's communicationModes (with
    the smali's tail-reset quirk), and sends the converted JSON."""
    conv = converter or LinkFilterConvertUtil(presenter.cache)
    converted = conv.convert_out(presenter.dev_id, msg_type, command)
    if converted is None:
        if cb is not None:
            cb.on_error("11001", None)
        return
    resp = presenter.cache.get_dev_resp_bean(presenter.dev_id)
    modes = resp.communication.communication_modes if resp is not None else []
    head: LinkCommHandler | None = None
    tail: LinkCommHandler | None = None
    for mod in modes or []:
        enum_name = CommunicationEnum.get_enum(mod.type)
        if enum_name is None:
            continue
        if enum_name == "MQTT":
            handler: LinkCommHandler | None = LinkMqttCommHandler(
                presenter.dev_id, msg_type, presenter.model, presenter.analytics
            )
            handler.network_available = presenter.model.gate.is_network_available
        elif enum_name == "HTTP":
            handler = LinkHttpCommHandler(
                presenter.dev_id, msg_type, presenter.model, presenter.analytics
            )
        else:
            handler = None
        # qqqbbbd chain build — verbatim: head==null → head=h (tail reset
        # to null); else tail==null → head.next=h; else tail.next=h;
        # tail=h. A null handler mid-chain orphans already-linked tails.
        if head is None:
            tail = None
            head = handler
            continue
        if tail is None:
            head.next_ = handler
        else:
            tail.next_ = handler
        tail = handler
    if head is not None:
        head.handle(to_json_string(converted), cb)
    elif cb is not None:
        cb.on_error("11005", "send error")
