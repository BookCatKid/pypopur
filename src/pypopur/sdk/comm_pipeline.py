"""Communication-mode dispatch pipeline — ports ``AbsThingDevice``
(``smali_classes3/com/thingclips/sdk/device/presenter/AbsThingDevice.smali``),
the handler-chain base ``qqqbbbd`` (``sdk/device/qqqbbbd.smali``), the
per-mode handlers, and the ``qpbpqpq`` DevModel surface.

Verified against smali (see ``docs/parity/01-dispatch.md``).
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from typing import Any, ClassVar

from ._fastjson import to_json_string
from ._java import text_is_empty
from .device_cache import CommunicationModuleT, DevListCacheManager
from .lan_control import (
    DeviceCommController,
    LanGate,
    ResultCallback,
)
from .validation import check_send_command, encode_raw_with_fallback

log = logging.getLogger("pypopur.comm_pipeline")


def _json_get_string(value: Any) -> str | None:
    """fastjson ``JSONObject.getString`` — String→itself; JSONObject/
    JSONArray→``toJSONString``; Number/Boolean→``String.valueOf``;
    null→null."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return to_json_string(value, write_nulls=True)
    return str(value)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CommunicationEnum:
    """``CommunicationEnum`` — type ↔ name map
    (``interior/device/bean/CommunicationEnum.smali``)."""

    LAN = 0
    MQTT = 1
    HTTP = 2
    BLE = 3
    SIGMESH = 4
    THING_MESH = 5
    THING_BEACON = 6
    OTHER = -1
    THING_MATTER = 8
    YU_MQTT = 12
    CLOUD_MODE = 100

    _BY_TYPE: ClassVar[dict[int, str]] = {
        0: "LAN",
        1: "MQTT",
        2: "HTTP",
        3: "BLE",
        4: "SIGMESH",
        5: "THING_MESH",
        6: "THING_BEACON",
        -1: "OTHER",
        8: "THING_MATTER",
        12: "YU_MQTT",
        100: "CLOUD_MODE",
    }

    @classmethod
    def get_enum(cls, type_: int) -> str | None:
        """``getEnum(int)`` — map lookup; unknown → None."""
        return cls._BY_TYPE.get(type_)


class ThingDevicePublishModeEnum:
    """``ThingDevicePublishModeEnum`` ordinals (Local=0, Internet=1,
    Auto=2, Mqtt=3, Http=4) with the ``bppdpdq.bdpdqbp[]`` switch-map
    cases: Internet→1, Local→2, Auto→3, Mqtt→4, Http→5."""

    Local = 0
    Internet = 1
    Auto = 2
    Mqtt = 3
    Http = 4

    _CASE: ClassVar[dict[int, int]] = {Internet: 1, Local: 2, Auto: 3, Mqtt: 4, Http: 5}


class DataModelType:
    """``DataModelType`` (sdk/enums) — THING_DP=1, THING_MODEL=2."""

    THING_DP = 1
    THING_MODEL = 2


class ThingSmartThingMessageType:
    """``ThingSmartThingMessageType`` — plain enum ordinals."""

    PROPERTY = 0
    ACTION = 1
    EVENT = 2


# ---------------------------------------------------------------------------
# Analytics seam (qqpppdp / StatUtils)
# ---------------------------------------------------------------------------


class PipelineAnalytics:
    """``qqpppdp`` + ``StatUtils`` seam — every hook is a no-op by
    default; tests/integrators can observe channel decisions."""

    def on_channel(self, dev_id: str, dps: str, handler: CommHandler) -> None:
        """``bdpdqbp(devId, dps, handler)`` — channel picked."""

    def channel_success(self, dev_id: str) -> None:
        """``pppbppp(devId)``."""

    def channel_error(self, dev_id: str, code: str, msg: str | None) -> None:
        """``bdpdqbp(devId, code, msg)``."""

    def no_channel(self, dev_id: str) -> None:
        """``qddqppb(devId)`` — chain exhausted."""

    def no_channels_requested(self, dev_id: str) -> None:
        """``bppdpdq().bppdpdq(devId)`` — empty/illegal request list."""

    def set_available_channels(self, modes: list) -> None:
        """``DevControllerEventAnalysis.setAvailableChannels``."""

    def stat_error(self, code: str, msg: str | None) -> None:
        """``StatUtils.bdpdqbp(9, "98bd46b1...", {code,msg})`` — the
        ``#``-suppressed per-error event."""


# ---------------------------------------------------------------------------
# Result-callback wrapper (AbsThingDevice$qpppdqb / $dpdbqdp)
# ---------------------------------------------------------------------------


class StatStripCallback:
    """``AbsThingDevice$qpppdqb``/``$dpdbqdp`` — strips a trailing ``#``
    from error messages before forwarding (``#`` marks "stat already
    recorded"); emits the stat event only when no ``#`` was present."""

    def __init__(self, inner: ResultCallback | None, analytics: PipelineAnalytics) -> None:
        self.inner = inner
        self.analytics = analytics

    def on_error(self, code: str, msg: str | None) -> None:
        marked = False
        if msg is not None and msg.endswith("#"):
            msg = msg[: len(msg) - 1]
            marked = True
        if self.inner is not None:
            self.inner.on_error(code, msg)
        if not marked:
            self.analytics.stat_error(code, msg)

    def on_success(self) -> None:
        if self.inner is not None:
            self.inner.on_success()


class _HandlerCallback:
    """``qqqbbbd$bdpdqbp`` — verbatim forward + channel analytics."""

    def __init__(self, handler: CommHandler, inner: ResultCallback | None) -> None:
        self.handler = handler
        self.inner = inner

    def on_error(self, code: str, msg: str | None) -> None:
        if self.inner is not None:
            self.inner.on_error(code, msg)
        self.handler._analytics.channel_error(self.handler.dev_id, code, msg)

    def on_success(self) -> None:
        if self.inner is not None:
            self.inner.on_success()
        self.handler._analytics.channel_success(self.handler.dev_id)


# ---------------------------------------------------------------------------
# DevModel (qpbpqpq) — per-device model surface used by the pipeline
# ---------------------------------------------------------------------------


class DevModel:
    """``qpbpqpq`` — thin orchestration over ``dbqqppp``
    (``DeviceCommController``), the LAN gates, and the ATOP api sends.

    Seams:
    - ``atop_send(api_name, version, post_data, cb)`` — the
      ``dbppbbp`` HTTP leaf (``thing.m.nb.device.dp.publish`` /
      ``thing.m.device.dp.publish`` / ``s.m.dev.dp.get``).
    - ``mqtt_up()`` — ``bpbqqdq.pdqppqb()`` connected flag.
    """

    CAP_API_ONLY = 8  # capability==8 → always sendDpsByApi

    def __init__(
        self,
        dev_id: str,
        controller: DeviceCommController,
        cache: DevListCacheManager,
        gate: LanGate,
        atop_send: Callable[[str, str, dict[str, Any], ResultCallback | None], None] | None = None,
        mqtt_up: Callable[[], bool] | None = None,
        schema_fn: Callable[[str], dict[str, Any] | None] | None = None,
    ) -> None:
        self.dev_id = dev_id
        self.controller = controller
        self.cache = cache
        self.gate = gate
        self.atop_send = atop_send or (lambda api, ver, data, cb: None)
        self.mqtt_up = mqtt_up or (lambda: True)
        # ``bpbqqdq.getSchema(devId)`` — defaults to the ddpdbbp lookup.
        if schema_fn is None:
            from .device_cache import DeviceDataManager

            schema_fn = DeviceDataManager(cache).get_schema_bean
        self.schema_fn = schema_fn
        # pass-through seams for ``send_internet``/``publish_dps``
        # (``is_online``, ``server_available``, ``mqtt_send``,
        # ``http_publish``, ``query_dev``, ``scheduler``, …).
        self.send_seams: dict[str, Any] = {}
        # link-message seams (``dqdpbbd``/``qdbpqqq``) — the plugin's
        # ``IMqttServer`` and the stat tap; ``None`` matches an absent
        # plugin (publish is silently skipped).
        self.link_mqtt_server: Any = None
        self.link_stat: Callable[[str, dict[str, Any]], None] | None = None

    # --- gates -------------------------------------------------------------

    def is_intranet_control(self) -> bool:
        return self.gate.is_intranet_control(self.dev_id)

    def is_cloud_online(self) -> bool:
        return self.gate.is_cloud_online(self.dev_id)

    # --- send entries ------------------------------------------------------

    def intranet_control(self, dps: str, cb: ResultCallback | None) -> None:
        """``intranetControl`` → ``dbqqppp.pdqppqb``."""
        self.controller.publish_dps_lan(dps, cb)

    def internet_send(self, dps: str, cb: ResultCallback | None) -> None:
        """``bppdpdq(dps, cb)`` → ``dbqqppp.bdpdqbp(dps, 0, cb)``
        (qqdbbpp:782 — straight to control-by-server)."""
        self.controller.send_internet(dps, 0, cb, **self.send_seams)

    def publish_forced(
        self, gw_id: str, force_http: bool, dps: str, cb: ResultCallback | None
    ) -> None:
        """``bdpdqbp(String, boolean, String, cb)`` (302-415):
        capability==8 → ``sendDpsByApi``; ``force`` → 5-arg send with
        http flag; else requires ``mqtt_up`` → 5-arg send, else 10202."""
        dev = self.cache.get_dev(self.dev_id)
        if (
            dev is not None
            and dev.product_bean is not None
            and dev.product_bean.capability == self.CAP_API_ONLY
        ):
            self.send_dps_by_api(self.dev_id, dps, cb)
            return
        if force_http:
            self.controller.send_with_node(True, gw_id, dps, 0, cb)
            return
        if self.mqtt_up():
            self.controller.send_with_node(False, gw_id, dps, 0, cb)
        elif cb is not None:
            cb.on_error("10202", "device is not in cloud online")

    def _transform(self, dev_id: str, dps: str) -> dict[str, Any] | None:
        """``bdpdqbp(dps, devId)`` — parse → checkSendCommond →
        encodeRaw side-effect; None on failure."""
        try:
            mapping = json.loads(dps)
        except Exception:
            return None
        if not isinstance(mapping, dict):
            mapping = None
        if not check_send_command(self.schema_fn(dev_id), mapping):
            return None
        encode_raw_with_fallback(self.schema_fn(dev_id), dps, mapping)
        return mapping

    def send_dps_by_api(self, dev_id: str, dps: str, cb: ResultCallback | None) -> None:
        """``sendDpsByApi`` (2126-2190) → ATOP
        ``thing.m.nb.device.dp.publish`` v1.0 ``{devId, dps}``."""
        mapping = self._transform(dev_id, dps)
        if not mapping:
            if cb is not None:
                cb.on_error("11001", None)
            return
        self.atop_send(
            "thing.m.nb.device.dp.publish",
            "1.0",
            {"devId": dev_id, "dps": to_json_string(mapping, write_nulls=True)},
            cb,
        )

    def send_cloud_dps_by_api(self, dev_id: str, dps: str, cb: ResultCallback | None) -> None:
        """``sendCloudDpsByApi`` (2060-2124) → ATOP
        ``thing.m.device.dp.publish`` v1.0 ``{devId, dps}``."""
        mapping = self._transform(dev_id, dps)
        if not mapping:
            if cb is not None:
                cb.on_error("11001", None)
            return
        self.atop_send(
            "thing.m.device.dp.publish",
            "1.0",
            {"devId": dev_id, "dps": to_json_string(mapping, write_nulls=True)},
            cb,
        )

    # -- link-message transports (qpbpqpq / qqdbbpp / dbppbbp) -----------------

    def _sand_o_next(self, dev_id: str) -> Any:
        """``qqdbbpp.bdpdqbp()`` (364-398) — ``SandRMap.get`` → create+put
        when absent → ``SAdd()``."""
        from .sando import SandO, SandRMap

        sand_o = SandRMap.get_instance().get(dev_id)
        if sand_o is None:
            sand_o = SandO()
            SandRMap.get_instance().put(dev_id, sand_o)
        sand_o.s_add()
        return sand_o

    def send_link_message_by_mqtt(self, msg_type: int, msg: str, cb: ResultCallback) -> None:
        """``qpbpqpq.sendLinkMessageByMqtt`` (1970-2024) — MQTT when the
        server and cloud-online are both up, HTTP fallback when only
        cloud-online, ``10202`` otherwise."""
        bean = self.cache.get_dev_resp_bean(self.dev_id)
        cloud_online = bool(bean is not None and bean.is_cloud_online())
        if self.mqtt_up() and cloud_online:
            self.link_mqtt_send(self.dev_id, msg_type, msg, cb)
            return
        if cloud_online:
            self.send_link_message_by_http(msg_type, msg, cb)
            return
        cb.on_error("10202", "device is not in cloud online")

    def link_mqtt_send(self, dev_id: str, msg_type: int, msg: str, cb: ResultCallback) -> None:
        """``dbqqppp.bdpdqbp`` → ``qqdbbpp.bdpdqbp`` (3286-3388) —
        ``10202 "device is not exists"`` on a missing bean, else
        ``dqdpbbd`` → ``qdbpqqq`` link publish."""
        from .thing_model import publish_link_message

        dev = self.cache.get_dev(dev_id)
        if dev is None:
            cb.on_error("10202", "device is not exists")
            return
        publish_link_message(
            dev_id,
            msg_type,
            json.loads(msg),
            self._sand_o_next(dev_id),
            cb,
            mqtt_server=self.link_mqtt_server,
            stat=self.link_stat,
        )

    def send_link_message_by_http(self, msg_type: int, msg: str, cb: ResultCallback) -> None:
        """``qpbpqpq.sendLinkMessageByHttp`` (1901-1968) — ``11001`` on
        empty payload; PROPERTY→``thing.m.device.dp.publish``,
        ACTION→``thing.m.device.action.async.publish``, EVENT→silent."""
        if text_is_empty(msg):
            cb.on_error("11001", None)
            return
        if msg_type == ThingSmartThingMessageType.PROPERTY:
            self.link_http_property(self.dev_id, msg, cb)
        elif msg_type == ThingSmartThingMessageType.ACTION:
            self.link_http_action(self.dev_id, msg, cb)
        # default: LLog.e(TAG, "not support event") — silent return

    def link_http_property(self, dev_id: str, dps: str, cb: ResultCallback) -> None:
        """``qpbpqpq.pbbppqb`` (1376-1398) →
        ``dbppbbp.bppdpdq(devId, devId, dps, cb)``."""
        self.atop_send(
            "thing.m.device.dp.publish",
            "1.0",
            {"devId": dev_id, "gwId": dev_id, "dps": dps},
            cb,
        )

    def link_http_action(self, dev_id: str, msg: str, cb: ResultCallback) -> None:
        """``qpbpqpq.pppbppp`` (1432-1538) → ``dbppbbp.pdqppqb``;
        parse failures only ``L.d`` — no error callback."""
        try:
            obj = json.loads(msg) if msg else None
            if not isinstance(obj, dict) and obj is not None:
                raise ValueError("syntax error, expect {")  # fastjson cast
            if obj is not None and "actionCode" in obj:
                self.atop_send(
                    "thing.m.device.action.async.publish",
                    "1.0",
                    {
                        "devId": dev_id,
                        "actionCode": _json_get_string(obj.get("actionCode")),
                        "inputParams": _json_get_string(obj.get("inputParams")),
                    },
                    cb,
                )
                return
            if cb is not None:
                cb.on_error("11001", None)
        except Exception as exc:
            log.debug("DevModel send action parse error -> %s", exc)


# ---------------------------------------------------------------------------
# qqqbbbd — handler chain
# ---------------------------------------------------------------------------


class CommHandler:
    """``qqqbbbd`` — pipeline node; ``next_`` is the ``bdpdqbp`` link."""

    def __init__(
        self,
        dev_id: str,
        model: DevModel,
        analytics: PipelineAnalytics | None = None,
    ) -> None:
        self.dev_id = dev_id
        self.model = model
        self.next_: CommHandler | None = None
        self._analytics = analytics or PipelineAnalytics()

    def name(self) -> str:
        return ""

    def available(self) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def send(self, dps: str, cb: ResultCallback | None) -> None:  # pragma: no cover
        raise NotImplementedError

    def handle(self, dps: str, cb: ResultCallback | None) -> None:
        """``qqqbbbd.bdpdqbp`` (44-172)."""
        if self.available():
            self._analytics.on_channel(self.dev_id, dps, self)
            self.send(dps, _HandlerCallback(self, cb))
            return
        if self.next_ is not None:
            self.next_.handle(dps, cb)
            return
        self._analytics.no_channel(self.dev_id)
        if cb is not None:
            cb.on_error("11005", "send error,no channel available.")


class MqttCommHandler(CommHandler):
    """``dppdqpp`` — available ⇔ network && isCloudOnline; send →
    ``bpbqqdq.bdpdqbp(devId, 8000, awakeCb)``; BOTH success and error
    → ``mDevModel.bppdpdq(dps, cb)`` (internet send)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.network_available: Callable[[], bool] = lambda: True
        self.awake_fn: Callable[[str, int, ResultCallback], None] = lambda dev_id, ms, cb: (
            cb.on_success()
        )

    def name(self) -> str:
        return "MQTT"

    def available(self) -> bool:
        return self.network_available() and self.model.is_cloud_online()

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        model, dps_s, inner = self.model, dps, cb

        class _Awake:
            def on_error(self, code: str, msg: str | None) -> None:
                model.internet_send(dps_s, inner)

            def on_success(self, *args: Any) -> None:
                model.internet_send(dps_s, inner)

        self.awake_fn(self.dev_id, 8000, _Awake())


class HttpCommHandler(CommHandler):
    """``dbbpdqp`` — available ⇔ model present (always); send →
    ``sendDpsByApi``."""

    def name(self) -> str:
        return "HTTP"

    def available(self) -> bool:
        return self.model is not None

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        self.model.send_dps_by_api(self.dev_id, dps, cb)


class CloudModeHandler(CommHandler):
    """``qbdppbq`` — available ⇔ model present; send →
    ``sendCloudDpsByApi``."""

    def name(self) -> str:
        return "CLOUD_MODE"

    def available(self) -> bool:
        return self.model is not None

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        self.model.send_cloud_dps_by_api(self.dev_id, dps, cb)


class LanCommHandler(CommHandler):
    """``bddqdbd`` — available ⇔ ``isIntranetControl``; send posts a
    500 ms watchdog → ``mDevModel.bppdpdq(dps, cb)`` (internet send,
    bypassing the chain); LAN error ALSO → internet send (+ stat
    unless ``#``-marked); LAN success forwards."""

    WATCHDOG_MS = 500

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.scheduler: Callable[[float, Callable[[], None]], Any] = lambda delay_s, fn: (
            threading.Timer(delay_s, fn).start()
        )
        self.cancel_fn: Callable[[Any], None] = lambda h: (
            h.cancel() if hasattr(h, "cancel") else None
        )

    def name(self) -> str:
        return "LAN"

    def available(self) -> bool:
        return self.model.is_intranet_control()

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        model = self.model
        done = {"v": False}

        def watchdog() -> None:
            if not done["v"]:
                model.internet_send(dps, cb)

        handle = self.scheduler(self.WATCHDOG_MS / 1000.0, watchdog)

        class _Cb:
            def on_error(self_, code: str, msg: str | None) -> None:
                done["v"] = True
                self.cancel_fn(handle)
                model.internet_send(dps, cb)
                if not (msg or "").endswith("#"):
                    self._analytics.stat_error(code, msg)

            def on_success(self_) -> None:
                done["v"] = True
                self.cancel_fn(handle)
                if cb is not None:
                    cb.on_success()

        model.intranet_control(dps, _Cb())


class MatterCommHandler(CommHandler):
    """``qdqbdbd`` — available ⇔ matter device && isMatterOnline &&
    isSubscribe; send → matter device's publishDps ("dp engine")."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.matter_device: Any = None  # IThingMatterDevice seam

    def name(self) -> str:
        return "THING_MATTER"

    def available(self) -> bool:
        d = self.matter_device
        return bool(d and d.is_matter_online() and d.is_subscribe())

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        if self.matter_device is not None:
            self.matter_device.publish_dps(dps, cb)


class BleCommHandler(CommHandler):
    """``bqpdbqq`` — available ⇔ BLE plugin && isBleLocalOnline;
    send → ``bleManager.publishDps`` (plugin absent → silent no-op,
    callback never invoked — faithful)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ble_manager: Any = None

    def name(self) -> str:
        return "BLE"

    def available(self) -> bool:
        return bool(self.ble_manager and self.ble_manager.is_ble_local_online(self.dev_id))

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        if self.ble_manager is not None:
            self.ble_manager.publish_dps(self.dev_id, dps, cb)


class YuMqttHandler(CommHandler):
    """``dqqbppb`` — available ⇔ yu plugin && channel && mqtt_up &&
    ``channel.getStatus(devId).isOnline``; send → channel.sendDps;
    channel null at send → ``11005 "yu channel is null"``."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.yu_plugin: Any = None
        self.mqtt_up: Callable[[], bool] = lambda: False

    def name(self) -> str:
        return "YU_MQTT"

    def _channel(self) -> Any:
        return self.yu_plugin.get_mqtt_channel() if self.yu_plugin else None

    def available(self) -> bool:
        ch = self._channel()
        if ch is None:
            return False
        status = ch.get_status(self.dev_id)
        return self.mqtt_up() and bool(status and status.is_online())

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        ch = self._channel()
        if ch is not None:
            ch.send_dps(self.dev_id, dps, cb)
        elif cb is not None:
            cb.on_error("11005", "yu channel is null")


class SigMeshCommHandler(CommHandler):
    """``qqppqqd`` — available ⇔ mesh control && isMeshLocalOnLine;
    send → ``publishDps(nodeId, category, dps, cb)``."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.mesh_control: Any = None
        self.device_bean: Any = None

    def name(self) -> str:
        return "SIGMESH"

    def available(self) -> bool:
        return bool(self.mesh_control and self.mesh_control.is_mesh_local_online())

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        if self.mesh_control is not None and self.device_bean is not None:
            self.mesh_control.publish_dps(
                self.device_bean.node_id, self.device_bean.category, dps, cb
            )


class ThingMeshCommHandler(SigMeshCommHandler):
    """``pdpdpqp`` — extends ``qqppqqd``; same availability and send."""

    def name(self) -> str:
        return "THING_MESH"


class BeaconCommHandler(CommHandler):
    """``qpppqdb`` — available ⇔ ``next_ != null`` **or**
    (ble plugin && beaconManager.isBeaconLocalOnline)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.beacon_manager: Any = None

    def name(self) -> str:
        return "THING_BEACON"

    def available(self) -> bool:
        if self.next_ is not None:
            return True
        return bool(self.beacon_manager and self.beacon_manager.is_beacon_local_online(self.dev_id))

    def send(self, dps: str, cb: ResultCallback | None) -> None:
        if self.beacon_manager is not None:
            self.beacon_manager.publish_dps(self.dev_id, dps, cb)


# ---------------------------------------------------------------------------
# AbsThingDevice — the per-device presenter
# ---------------------------------------------------------------------------


class ThingDevicePresenter:
    """``AbsThingDevice`` — ``publishDps`` entry points and
    ``publishDpsInPipeline`` chain construction.

    Seams (all default to absent/no-op):
    - ``ble_plugin``: ``order_local_communication_list(resp)``,
      ``ble_manager``, ``beacon_manager``
    - ``yu_plugin``: ``get_mqtt_channel()``
    - ``matter_factory(dev_id)`` → IThingMatterDevice-like
    - ``mesh_control``: IMeshCommonControl-like
    - ``is_single_ble_local_online(dev_id)``
    - ``ble_capability_bit19(cap_str)`` — ``ThingBleUtil.
      parseBleDeviceCapability(cap, 19)``
    - ``thing_model_convert(dev_id, dps)`` — ``qqbbddb.pdqppqb``
    - ``publish_thing_message(type, dps, cb)``
    - ``get_thing_model(pid, ver, cb)`` — async fetch seam
    """

    def __init__(
        self,
        dev_id: str,
        model: DevModel,
        cache: DevListCacheManager,
        analytics: PipelineAnalytics | None = None,
    ) -> None:
        self.dev_id = dev_id
        self.model = model
        self.cache = cache
        self.analytics = analytics or PipelineAnalytics()
        # plugin seams
        self.ble_plugin: Any = None
        self.yu_plugin: Any = None
        self.matter_factory: Callable[[str], Any] | None = None
        self.mesh_control: Any = None
        self.is_single_ble_local_online: Callable[[str], bool] = lambda d: False
        self.ble_capability_bit19: Callable[[str], bool] = lambda c: False
        # THING_MODEL seams — bound to the ``sdk/thing_model.py`` ports by
        # default (lazy imports; that module imports this one).
        self.thing_model_convert: Callable[[str, str], str] = self._convert_link_property
        self.publish_thing_message: Callable[[int, Any, ResultCallback | None], None] = (
            self._publish_thing_message
        )
        self.get_thing_model: Callable[[str, str, Any], None] | None = self._get_thing_model
        # ``Business.asyncRequest`` seam for ``qdddbpp.pdqppqb`` — the
        # caller supplies the parsed result to ``listener.on_success``.
        self.thing_model_fetch: Callable[[str, str, dict[str, Any], Any], None] = (
            lambda api, ver, data, listener: None
        )

    # -- THING_MODEL seam implementations (lazy — thing_model imports us) -----

    def _convert_link_property(self, dev_id: str, dps: str) -> str:
        """``qqbbddb.pdqppqb`` — dpId-keyed → code-keyed link property."""
        from .thing_model import LinkFilterConvertUtil

        return LinkFilterConvertUtil(self.cache).convert_to_link_property(dev_id, dps)

    def _publish_thing_message(
        self, msg_type: int, command: Any, cb: ResultCallback | None
    ) -> None:
        """``AbsThingDevice.publishThingMessageWithType``."""
        from .thing_model import publish_thing_message_with_type

        publish_thing_message_with_type(self, msg_type, command, cb)

    def _get_thing_model(self, product_id: str, product_ver: str, cb: Any) -> None:
        """``ThingOSDevice.getDeviceOperator().
        getThingModelWithProductId`` → ``ddpdbbp.getThingModelWithPid``."""
        from .thing_model import get_thing_model_with_pid

        get_thing_model_with_pid(
            self.thing_model_fetch,
            product_id,
            product_ver,
            cb,
            dev_cache=self.cache,
        )

    # -- entry: 2-arg publishDps ----------------------------------------------

    def publish_dps(self, dps: str, cb: ResultCallback | None = None) -> None:
        """``publishDps(String, IResultCallback)`` (2476-2645)."""
        wrapped = StatStripCallback(cb, self.analytics)
        resp = self.cache.get_dev_resp_bean(self.dev_id)
        if (
            resp is not None
            and resp.communication is not None
            and resp.communication.data_model == DataModelType.THING_MODEL
        ):
            dps = self.thing_model_convert(self.dev_id, dps)
            if resp.thing_model is not None:
                # publishes with the ORIGINAL callback, not the wrapper
                self.publish_thing_message(ThingSmartThingMessageType.PROPERTY, dps, cb)
                return
            if self.get_thing_model is not None:
                outer = self

                class _Fetch:
                    def on_success(self, model: Any = None) -> None:
                        outer.publish_thing_message(
                            ThingSmartThingMessageType.PROPERTY, dps, wrapped
                        )

                    def on_error(self, code: str, msg: str | None) -> None:
                        wrapped.on_error(code, msg)

                self.get_thing_model(resp.product_id, resp.product_ver, _Fetch())
            return
        if resp is not None:
            if self.ble_plugin is None:
                # Java: resp.communication.getCommunicationModes() — NPEs
                # when communication is null; mirrored by attribute access.
                modes = resp.communication.communication_modes
            else:
                modes = self.ble_plugin.order_local_communication_list(resp)
        else:
            modes = []
        self._publish_dps_in_pipeline(dps, modes, wrapped)

    # -- entry: publishDps with mode enum --------------------------------------

    def publish_dps_mode(self, dps: str, mode: int, cb: ResultCallback | None = None) -> None:
        """``publishDps(dps, ThingDevicePublishModeEnum, cb)``
        (2647-2739) — switch-map cases 1..5."""
        case = ThingDevicePublishModeEnum._CASE.get(mode)
        if case == 1:
            self._publish_dps_by_cloud(dps, cb)
        elif case == 2:
            self._publish_dps_by_intranet(dps, cb)
        elif case == 3:
            self.publish_dps(dps, cb)
        elif case == 4:
            self.model.publish_forced("", False, dps, cb)
        elif case == 5:
            self.model.publish_forced("", True, dps, cb)

    def _publish_dps_by_cloud(self, dps: str, cb: ResultCallback | None) -> None:
        """``publishDpsByCloud`` (826-877)."""
        if self.model.mqtt_up():
            self.model.internet_send(dps, cb)
        else:
            cb.on_error("10202", "device is not in cloud online")

    def _publish_dps_by_intranet(self, dps: str, cb: ResultCallback | None) -> None:
        """``publishDpsByIntranet`` (879-931)."""
        if self.model.is_intranet_control():
            self.model.intranet_control(dps, cb)
        elif cb is not None:
            cb.on_error("10201", "device is not in intranet online")

    # -- entry: publishDps with channel list -----------------------------------

    def publish_dps_channels(
        self, dps: str, channel_list_json: str, cb: ResultCallback | None
    ) -> None:
        """``publishDps(dps, channelListJson, cb)`` (2741-3022)."""
        wrapped = StatStripCallback(cb, self.analytics)
        try:
            requested = json.loads(channel_list_json)
        except Exception:
            requested = None
        if not isinstance(requested, list):
            requested = []
        known: list[int] = []
        for item in requested:
            if isinstance(item, int) and CommunicationEnum.get_enum(item) is not None:
                known.append(item)
        if not known:
            self.analytics.no_channels_requested(self.dev_id)
            wrapped.on_error("301001", "communication_types_illegal")
            return
        resp = self.cache.get_dev_resp_bean(self.dev_id)
        dev_modes = resp.communication.communication_modes if resp is not None else None
        if dev_modes is None or not requested:
            wrapped.on_error("301001", "communication_types_illegal")
            return
        picked: list[Any] = []
        for req in known:
            if req == CommunicationEnum.YU_MQTT:
                picked.append(CommunicationModuleT(CommunicationEnum.YU_MQTT))
            else:
                # every matching device module is added (no break)
                for mod in dev_modes:
                    if mod.type == req:
                        picked.append(mod)
        if not picked:
            wrapped.on_error("301001", "communication_types_illegal")
            return
        self._publish_dps_in_pipeline(dps, picked, wrapped)

    # -- pipeline core ---------------------------------------------------------

    def _publish_dps_in_pipeline(
        self, dps: str, modes: list | None, cb: ResultCallback | None
    ) -> None:
        """``publishDpsInPipeline`` (933-1639)."""
        try:
            mapping = json.loads(dps)
        except Exception:
            mapping = None
        if not isinstance(mapping, dict):
            mapping = None
        if not check_send_command(self.model.schema_fn(self.dev_id), mapping):
            if cb is not None:
                cb.on_error("11001", None)
            return
        if not modes:
            if cb is not None:
                cb.on_error("11001", "communication types illegal")
            return
        modes = list(modes)
        if modes[0].type == CommunicationEnum.BLE and modes[-1].type != CommunicationEnum.YU_MQTT:
            modes.append(CommunicationModuleT(CommunicationEnum.YU_MQTT))
        self._check_direct_gateway(modes)
        self.analytics.set_available_channels(modes)

        head: CommHandler | None = None
        for mod in modes:
            handler = self._make_handler(CommunicationEnum.get_enum(mod.type))
            if handler is None:
                continue
            if head is None:
                head = handler
            else:
                tail = head
                while tail.next_ is not None:
                    tail = tail.next_
                tail.next_ = handler
        if head is not None:
            head.handle(dps, cb)
        elif cb is not None:
            cb.on_error("11005", "send error")

    def _make_handler(self, enum_name: str | None) -> CommHandler | None:
        """The ordinal→handler switch (packed-switch pswitch_0..9)."""
        a = self.analytics
        if enum_name == "MQTT":
            h = MqttCommHandler(self.dev_id, self.model, a)
            h.network_available = self.model.gate.is_network_available
            h.awake_fn = self._awake_fn
            return h
        if enum_name == "HTTP":
            return HttpCommHandler(self.dev_id, self.model, a)
        if enum_name == "THING_MATTER":
            h = MatterCommHandler(self.dev_id, self.model, a)
            if self.matter_factory is not None:
                h.matter_device = self.matter_factory(self.dev_id)
            return h
        if enum_name == "LAN":
            h = LanCommHandler(self.dev_id, self.model, a)
            h.next_ = MatterCommHandler(self.dev_id, self.model, a)
            if self.matter_factory is not None:
                h.next_.matter_device = self.matter_factory(self.dev_id)
            h.scheduler = self._scheduler
            h.cancel_fn = self._cancel_fn
            return h
        if enum_name == "BLE":
            h = BleCommHandler(self.dev_id, self.model, a)
            h.ble_manager = self.ble_plugin.get_ble_manager() if self.ble_plugin else None
            return h
        if enum_name == "SIGMESH":
            h = SigMeshCommHandler(self.dev_id, self.model, a)
            h.mesh_control = self.mesh_control
            h.device_bean = self.cache.get_dev(self.dev_id)
            return h
        if enum_name == "THING_MESH":
            h = ThingMeshCommHandler(self.dev_id, self.model, a)
            h.mesh_control = self.mesh_control
            h.device_bean = self.cache.get_dev(self.dev_id)
            return h
        if enum_name == "YU_MQTT":
            h = BleCommHandler(self.dev_id, self.model, a)
            h.ble_manager = self.ble_plugin.get_ble_manager() if self.ble_plugin else None
            f = YuMqttHandler(self.dev_id, self.model, a)
            f.yu_plugin = self.yu_plugin
            f.mqtt_up = self.model.mqtt_up
            h.next_ = f
            return h
        if enum_name == "THING_BEACON":
            h = BeaconCommHandler(self.dev_id, self.model, a)
            h.beacon_manager = self.ble_plugin.get_beacon_manager() if self.ble_plugin else None
            return h
        if enum_name == "CLOUD_MODE":
            return CloudModeHandler(self.dev_id, self.model, a)
        return None

    # injectable seams for handler construction
    _awake_fn: Callable[[str, int, ResultCallback], None] = staticmethod(
        lambda dev_id, ms, cb: cb.on_success()
    )
    _scheduler: Callable[[float, Callable[[], None]], Any] = staticmethod(
        lambda delay_s, fn: threading.Timer(delay_s, fn).start()
    )
    _cancel_fn: Callable[[Any], None] = staticmethod(
        lambda h: h.cancel() if hasattr(h, "cancel") else None
    )

    # -- checkDirectGateway -----------------------------------------------------

    def _check_direct_gateway(self, modes: list) -> None:
        """``checkDirectGateway`` (76-717) — sub-device BLE promotion."""
        resp = self.cache.get_dev_resp_bean(self.dev_id)
        if (
            resp is None
            or resp.device_topo is None
            or text_is_empty(resp.device_topo.parent_dev_id)
        ):
            return
        parent_id = resp.device_topo.parent_dev_id
        parent_resp = self.cache.get_dev_resp_bean(parent_id)
        parent_bean = self.cache.get_dev(parent_id)
        parent_support = False
        if parent_bean is not None:
            cap = getattr(parent_bean, "bluetooth_capability", None)
            if not text_is_empty(cap):
                parent_support = self.ble_capability_bit19(cap)
        if parent_resp is None:
            return
        ble_online = self.is_single_ble_local_online(parent_id)
        parent_modes = parent_resp.communication.communication_modes
        parent_ble_first = bool(parent_modes and parent_modes[0].type == CommunicationEnum.BLE)
        if not (ble_online and parent_support):
            return
        ble_mod = None
        for mod in modes:
            if mod.type == CommunicationEnum.BLE:
                ble_mod = mod  # last match wins (iterator overwrite)
        if ble_mod is not None:
            if parent_ble_first:
                modes.remove(ble_mod)
                modes.insert(0, ble_mod)
            return
        new_mod = CommunicationModuleT(CommunicationEnum.BLE)
        if parent_ble_first:
            modes.insert(0, new_mod)
        else:
            modes.append(new_mod)
