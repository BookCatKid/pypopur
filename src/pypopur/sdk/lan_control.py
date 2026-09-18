"""LAN control chain — the send path above :mod:`pypopur.sdk.lan_framing`.

Layer map (smali canonical):

- ``qqdbbpp`` (sdk/device) — per-device comm controller; LAN entry
  ``pdqppqb(dpsJson, cb)``, DP-map build ``bdpdqbp(nodeId, dpsJson)``,
  cadv/zigbee/ble-mesh frame-type gate ``bdpdqbp(dev,nodeId,0,data,
  sandO,"",cb)``.
- ``bpqqdpq`` (sdk/device) — ``DevLocalControlImpl``: builds the
  ``{dps,cid,ctype,mbid}`` / ``{dps,devId,t,uid}`` payload objects.
- ``dqdpbbd`` — ``bdpdqbp(gwDevId, nodeId, ctype, obj)`` sub-device
  ``cid``/``ctype`` addressing helper.
- ``dddpppb`` (sdk/device) — ``LocalControlModel``: hgw/lpv/localKey
  resolution → ``ThingLocalControlBean`` → ``IThingHardware.control``.
- ``bddqdbd`` — ``ThingLanCommPipeline``: 500 ms watchdog → internet
  fallback; LAN error → unconditional cloud fallback.
- ``qpbpqpq`` — ``isIntranetControl`` / ``isCloudOnline`` gates.

The actual socket/crypto lives in ``libnetwork-android.so`` (JNI); the
port exposes it as the injectable ``hardware_control`` callable taking a
:class:`~pypopur.sdk.lan_framing.LocalControlSpec`-derived
``ThingLocalControlBean``.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional

from ._fastjson import to_json_string
from ._java import text_is_empty
from .device_cache import (
    CommunicationEnum,
    DeviceBean,
    DevListCacheManager,
)
from .lan_framing import (
    check_hgw_version,
)
from .sando import SandO, SandRMap

log = logging.getLogger("thing-lan")


class FrameTypeEnum:
    """``com.thingclips.smart.interior.enums.FrameTypeEnum`` — ``type`` ints."""

    UDP = 0x0
    AP_CONFIG = 0x1
    ACTIVE = 0x2
    BIND = 0x3
    RENAME_GW = 0x4
    RENAME_DEVICE = 0x5
    UNBIND = 0x6
    CONTROL = 0x7
    STATUS = 0x8
    HEART_BEAT = 0x9
    DP_QUERY = 0xA
    QUERY_WIFI = 0xB
    TOKEN_BIND = 0xC
    CONTROL_NEW = 0xD
    ENABLE_WIFI = 0xE
    DP_QUERY_NEW = 0x10
    SCENE_EXECUTE = 0x11
    DP_QUERY_GENERAL = 0x12
    SCENE_EXECUTE_NEW = 0x13
    AP_CONFIG_NEW = 0x14
    AP_CONFIG_ACK = 0x15
    LAN_REQUEST_DEVICE_TYPE = 0x16
    LAN_REQUEST_SCHEMA_TYPE = 0x17
    LAN_REQUEST_SCHOOL_TIME_TYPE = 0x18
    LAN_OTA_BEGIN = 0x1A
    LAN_OTA_SEND = 0x1B
    LAN_OTA_SEND_OVER = 0x1C
    LAN_REQUEST_ACTIVE_TYPE = 0x1D
    IPC_LAN_302 = 0x20
    IPC_LAN_LOCAL_CONFIG = 0x21
    IPC_LAN_LOCAL_CONFIG_WIFI = 0x22
    AP_CONFIG_SEND_SECURITY_INFO = 0x24
    APP_SEND_BROADCAST = 0x25
    FRM_LAN_EXT_STREAM = 0x40
    LAN_AP_ROUTER_TYPE = 0x42
    LAN_SUB_DEV_STAUS_REQUEST = 0xE0  # sic
    LAN_SUB_DEV_STAUS = 0xE1
    LAN_REQUEST_SCENE_RULES = 0xE2
    LAN_GW_RESET = 0xE3
    LAN_SUB_DEV_RESET = 0xE4
    LAN_CHECK_SUB_DEV_UPDATE = 0xE5
    LAN_REQUEST_DEV_UPDATE = 0xE6
    LAN_DOWNLOAD_OTA_PACKAGE = 0xE7
    LAN_OTA_PROGRESS_CHANGED = 0xE8
    LAN_DEV_VERSION_REPORT = 0xE9
    LAN_GW_ACTIVE = 0xF0
    LAN_SUB_DEV_REQUEST = 0xF1
    LAN_DELETE_SUB_DEV = 0xF2
    LAN_REPORT_SUB_DEV = 0xF3
    LAN_SCENE = 0xF4
    LAN_PUBLISH_CLOUD_CONFIG = 0xF5
    LAN_PUBLISH_APP_CONFIG = 0xF6
    LAN_EXPORT_APP_CONFIG = 0xF7
    LAN_PUBLISH_SCENE_PANEL = 0xF8
    LAN_REMOVE_GW = 0xF9
    LAN_CHECK_GW_UPDATE = 0xFA
    LAN_GW_UPDATE = 0xFB
    LAN_SET_GW_CHANNEL = 0xFC
    LAN_GET_GW_CHANNEL = 0xFD
    LAN_REQUEST_GW_LOG = 0xFE


class ActiveEnum:
    """``com.thingclips.smart.interior.enums.ActiveEnum``."""

    UNACTIVE = 0
    ACTIVING = 1
    ACTIVED = 2
    LOCAL_UNACTIVE = 3
    LOCAL_ACTIVED = 4


@dataclass
class HgwBean:
    """``com.thingclips.smart.android.hardware.bean.HgwBean`` — the LAN
    presence record populated by UDP discovery."""

    gw_id: str | None = None
    ip: str | None = None
    version: str | None = None  # lpv
    active: int = ActiveEnum.UNACTIVE
    encrypt: bool = False
    uuid: str | None = None
    product_key: str | None = None
    last_seen_time: int = 0
    sl: int = 0
    ability: int = 0
    mode: int = 0
    token: bool = False


@dataclass
class ThingLocalControlBean:
    """``com.thingclips.smart.interior.hardware.ThingLocalControlBean`` —
    what ``IThingHardware.control`` receives."""

    data: Any = None
    dev_id: str | None = None
    lpv: str | None = None
    s: int = 0
    o: int = 0
    t: int = 0
    protocol: int = 0
    frame_type: int = 0
    local_key: str | None = None


@dataclass
class ThingLocalNormalControlBean:
    """``com.thingclips.smart.interior.hardware.ThingLocalNormalControlBean``
    — what the deprecated ``IThingHardware.normalControl`` receives (the
    DP-query path; no s/o/t/protocol)."""

    data: Any = None
    dev_id: str | None = None
    lpv: str | None = None
    local_key: str | None = None
    frame_type: int = 0


# ---------------------------------------------------------------------------
# ThingUtil.compareVersion
# ---------------------------------------------------------------------------


def _parse_dps(dps_json: str | None) -> dict[str, Any] | None:
    """fastjson ``JSON.parseObject``: empty/null input → ``None``
    (callers then fail validation like Java's NPE-on-null); malformed
    input raises like fastjson's ``JSONException``."""
    if dps_json is None or not dps_json.strip():
        return None
    m = json.loads(dps_json)
    return m  # non-dict passes through


def _version_value(v: str) -> list:
    """``ThingUtil.getValue`` — split on ``.``; unparseable segment → 0."""
    out = []
    for seg in v.split("."):
        try:
            out.append(int(seg))
        except (ValueError, TypeError):
            out.append(0)
    return out


def compare_version(a: str | None, b: str | None) -> int:
    """``ThingUtil.compareVersion`` — null/empty either side → -1; else
    component-wise int compare, equal-prefix → shorter < longer."""
    if not a or not b:
        return -1
    va, vb = _version_value(a), _version_value(b)
    for i in range(min(len(va), len(vb))):
        if va[i] < vb[i]:
            return -1
        if va[i] > vb[i]:
            return 1
    if len(va) == len(vb):
        return 0
    return -1 if len(va) < len(vb) else 1


# ---------------------------------------------------------------------------
# dqdpbbd — sub-device cid/ctype addressing
# ---------------------------------------------------------------------------


def add_cid_ctype(
    cache: DevListCacheManager,
    gw_dev_id: str | None,
    node_id: str | None,
    ctype: int,
    obj: dict[str, Any],
) -> None:
    """``dqdpbbd.bdpdqbp(String,String,int,JSONObject)``.

    Adds ``cid``/``ctype`` when ``node_id`` is non-empty and != gw id —
    *unless* the resolved sub-device's product is infrared or has
    ``bizAttribute & 1`` and the nodeId lacks ``"-v-"``.  An infrared/biz
    nodeId containing ``"-v-"`` is trimmed to before its last occurrence
    and still added.
    """
    if node_id == gw_dev_id or text_is_empty(node_id):
        return
    skip = False
    sub = cache.get_sub_dev(gw_dev_id, node_id)
    if sub is not None:
        dev = cache.get_dev(sub.dev_id)
        product = dev.product_bean if dev is not None else None
        if product is not None and (product.has_infrared() or product.biz_attribute & 0x1 == 0x1):
            if "-v-" in node_id:
                node_id = node_id[: node_id.rindex("-v-")]
            else:
                skip = True
    if not skip:
        obj["cid"] = node_id
        obj["ctype"] = ctype


# ---------------------------------------------------------------------------
# dddpppb — LocalControlModel
# ---------------------------------------------------------------------------


class LocalControlModel:
    """``dddpppb`` — resolves hgw/lpv/localKey, builds
    ``ThingLocalControlBean``, calls the injectable hardware layer.

    ``hardware_control(bean, cb)`` stands in for
    ``IThingHardware.control`` (dpppdpq → bbbdppp assemblers →
    DevTransferService → JNI).  ``timestamp_fn`` is
    ``TimeStampManager.getCurrentTimeStamp``.
    """

    PROTOCOL_DP_COMMAND = 5

    def __init__(
        self,
        cache: DevListCacheManager,
        hardware_control: Callable[[ThingLocalControlBean, ResultCallback], None] | None = None,
        timestamp_fn: Callable[[], int] | None = None,
        uid: str | None = None,
        hgw_provider: Callable[[str], HgwBean | None] | None = None,
        transform: Callable[[str, Any], None] | None = None,
        hardware_normal_control: Callable[[ThingLocalNormalControlBean, ResultCallback], None]
        | None = None,
    ) -> None:
        self.cache = cache
        self.hardware_control = hardware_control
        # ``IThingHardware.normalControl`` — the DP-query send path.
        self.hardware_normal_control = hardware_normal_control
        self.timestamp_fn = timestamp_fn or (lambda: 0)
        self.uid = uid
        # ``hardware.getDev(devId).hgwBean`` — DeviceBean.hgwBean or an
        # external provider (DevTransferService gwMap equivalent).
        self.hgw_provider = hgw_provider
        # ``bdpdqbp(devId, obj)`` pre-send transform hook (232-418).
        self.transform = transform

    def _hgw(self, dev: DeviceBean) -> HgwBean | None:
        if self.hgw_provider is not None:
            return self.hgw_provider(dev.dev_id)
        return getattr(dev, "hgw_bean", None)

    def control(
        self,
        dev_id: str,
        data: Any,
        sand_o: SandO,
        frame_type: int,
        cb: ResultCallback | None = None,
    ) -> None:
        """``bdpdqbp(devId, obj, sandO, frameType, cb)`` (32-120)."""
        dev = self.cache.get_dev(dev_id)
        if dev is None:
            if cb is not None:
                cb.on_error("11005", "device is not exist")
            return
        hgw = self._hgw(dev)
        if hgw is None:
            if cb is not None:
                cb.on_error("11005", "device is not local online")
            return
        lpv = hgw.version
        local_key = dev.local_key if hgw.encrypt else None
        self._control_inner(
            dev_id,
            local_key,
            data,
            lpv,
            sand_o,
            self.PROTOCOL_DP_COMMAND,
            frame_type,
            cb,
        )

    def _control_inner(
        self,
        dev_id: str,
        local_key: str | None,
        data: Any,
        lpv: str | None,
        sand_o: SandO,
        protocol: int,
        frame_type: int,
        cb: ResultCallback | None,
    ) -> None:
        """8-arg ``bdpdqbp`` (550-705)."""
        log.debug("SandR o:%s s: %s", sand_o.o, sand_o.s)
        bean = ThingLocalControlBean(
            data=data,
            dev_id=dev_id,
            lpv=lpv,
            s=sand_o.s,
            o=sand_o.o,
            t=self.timestamp_fn(),
            protocol=protocol,
            frame_type=frame_type,
            local_key=local_key,
        )
        if self.hardware_control is None:
            return
        if self.transform is not None:
            self.transform(dev_id, data)
        self.hardware_control(bean, _LocalControlResult(cb, bean))

    def query_dps(
        self,
        dev_id: str,
        node_id: str | None = "",
        cb: ResultCallback | None = None,
    ) -> None:
        """``pdqppqb(devId, nodeId, cb)`` — LAN DP query.

        Builds ``{"gwId":devId,"devId":devId}`` under ``DP_QUERY`` when
        ``node_id`` is empty; ``{"cid":nodeId}`` under ``DP_QUERY_NEW``
        for sub-device queries (``node_id == dev_id`` → empty object).
        Sends through ``hardware_normal_control``
        (``IThingHardware.normalControl``) — the inner payload is raw
        JSON, not the 3.4 s/o-wrapped control format.
        """
        obj: dict[str, Any] = {}
        dev = self.cache.get_dev(dev_id)
        if dev is None:
            log.error("dev == null")
            if cb is not None:
                cb.on_error("11005", "device is not exist")
            return
        if (
            compare_version(dev.get_cadv(), "1.0.1") >= 0 or dev.is_ble_mesh() or dev.has_zigbee()
        ) and text_is_empty(node_id):
            node_id = dev_id
        if text_is_empty(node_id):
            obj["gwId"] = dev_id
            obj["devId"] = dev_id
            frame_type = FrameTypeEnum.DP_QUERY
        else:
            if node_id != dev_id:
                obj["cid"] = node_id
            frame_type = FrameTypeEnum.DP_QUERY_NEW
        log.debug("queryDp: %s", json.dumps(obj))
        self.send_normal(dev_id, obj, frame_type, cb)

    def send_normal(
        self,
        dev_id: str,
        data: Any,
        frame_type: int,
        cb: ResultCallback | None = None,
    ) -> None:
        """Deprecated 4-arg ``bdpdqbp(devId, data, frameType, cb)``
        (550-705 sibling) — builds ``ThingLocalNormalControlBean`` and
        sends via ``hardware_normal_control``
        (``IThingHardware.normalControl``)."""
        dev = self.cache.get_dev(dev_id)
        if dev is None:
            if cb is not None:
                cb.on_error("11005", "device is not exist")
            return
        hgw = self._hgw(dev)
        if hgw is None:
            if cb is not None:
                cb.on_error("11005", "device is not local online")
            return
        bean = ThingLocalNormalControlBean(
            data=data,
            dev_id=dev_id,
            lpv=hgw.version,
            local_key=dev.local_key if hgw.encrypt else None,
            frame_type=frame_type,
        )
        if self.transform is not None:
            self.transform(dev_id, data)
        if self.hardware_normal_control is not None:
            self.hardware_normal_control(bean, _LocalControlResult(cb, bean))


class _LocalControlResult:
    """``dddpppb$bdpdqbp`` — onError appends ``"#"`` to the message (the
    marker the pipeline uses to skip a duplicate stat event); onSuccess
    forwards."""

    def __init__(self, cb: ResultCallback | None, bean) -> None:
        self.cb = cb
        self.bean = bean

    def on_error(self, code: str, msg: str | None) -> None:
        if self.cb is not None:
            self.cb.on_error(code, (msg or "") + "#")

    def on_success(self) -> None:
        if self.cb is not None:
            self.cb.on_success()


class ResultCallback:
    """``IResultCallback`` — duck-typed."""

    def on_error(self, code: str, msg: Optional[str]) -> None:  # noqa
        pass

    def on_success(self) -> None:
        pass


# ---------------------------------------------------------------------------
# dqdpbbd — DevCloudControlImpl (MQTT/HTTP send leaf)
# ---------------------------------------------------------------------------


@dataclass
class DpPublish:
    """``com.thingclips.smart.interior.device.confusebean.DpPublish`` —
    ATOP ``thing.m.device.dp.publish`` v1.0 postData."""

    gw_id: str | None = None
    dev_id: str | None = None
    dps: str | None = None
    pcc: str | None = None


def _check_pv_version(pv: str | None, minimum: float) -> bool:
    """``ThingUtil.checkPvVersion``: non-empty AND
    ``Float.valueOf(pv) >= minimum``; malformed → raises (Java
    NumberFormatException propagates)."""
    if text_is_empty(pv):
        return False
    return float(pv) >= minimum


class DevCloudControl:
    """``dqdpbbd`` (sdk/device) — "DevCloudControlImpl".

    ``publish_fn`` is ``bbppbbd.bdpdqbp`` — the MqttControlBuilder →
    ``publishDevice`` hop; ``atop_publish`` is
    ``dbppbbp.bdpdqbp(DpPublish, listener)``.
    """

    def __init__(
        self,
        cache: DevListCacheManager,
        *,
        publish_device: Callable[[Any, ResultCallback], None] | None = None,
        atop_publish: Callable[[DpPublish, ResultCallback], None] | None = None,
        timestamp_fn: Callable[[], int] | None = None,
    ) -> None:
        self.cache = cache
        self.publish_device = publish_device
        self.atop_publish = atop_publish
        self.timestamp_fn = timestamp_fn or (lambda: 0)

    def send_command(
        self,
        dev_id: str,
        dp_map: dict[str, Any],
        node_id: str | None,
        ctype: int,
        log_key: str,
        sand_o: SandO,
        cb: ResultCallback | None = None,
    ) -> None:
        """``sendCommand`` (1639-1790): dev null → ``11002``/
        ``"dev==null"``; ``checkPvVersion(pv, 1.1)`` → "dps send by
        mqtt"; else "dps send by Http" → ``sendByHttp(devId, devId,
        json, "")``."""
        dev = self.cache.get_dev(dev_id)
        if dev is None:
            if cb is not None:
                cb.on_error("11002", "dev==null")
            return
        if _check_pv_version(dev.pv, 1.1):
            log.info("dps send by mqtt")
            self._mqtt_send(dev_id, dp_map, dev, node_id, ctype, log_key, sand_o, cb)
        else:
            log.info("dps send by Http")
            self._http_send(dev_id, dev_id, to_json_string(dp_map), cb)

    def _mqtt_send(
        self,
        dev_id: str,
        dp_map: dict[str, Any],
        dev: DeviceBean,
        node_id: str | None,
        ctype: int,
        log_key: str,
        sand_o: SandO,
        cb: ResultCallback | None,
    ) -> None:
        """``bdpdqbp(devId, map, dev, nodeId, type, logKey, sandO, cb)``
        (861-1030) — payload shape by cadv/virtual/zigbee/433wifi, then
        ``bbppbbd.bdpdqbp(devId, pv, localKey, obj, sandO, cb)``."""
        obj: dict[str, Any] = {}
        cadv = dev.get_cadv()
        if compare_version(cadv, "1.0.2") >= 0:
            add_cid_ctype(self.cache, dev_id, node_id, ctype, obj)
            if not text_is_empty(log_key):
                obj["mbid"] = log_key
            obj["dps"] = dp_map
        elif not dev.virtual and (
            compare_version(cadv, "1.0.1") >= 0
            or dev.is_ble_mesh()
            or dev.has_zigbee()
            or (
                dev.is_433_wifi()
                and not text_is_empty(dev.node_id)
                and not text_is_empty(dev.parent_dev_id)
            )
        ):
            add_cid_ctype(self.cache, dev_id, node_id, ctype, obj)
            obj["dps"] = dp_map
        else:
            obj["devId"] = dev_id
            obj["dps"] = dp_map
            if not _check_pv_version(dev.pv, 2.1) and _check_pv_version(dev.pv, 2.0):
                obj["gwId"] = dev_id
        log.debug("SandR o:%s s: %s", sand_o.o, sand_o.s)
        # bbppbbd.bdpdqbp(devId, pv, localKey, obj, sandO, cb)
        if self.publish_device is not None:
            builder = self._control_builder(dev_id, dev.pv, dev.local_key, obj, sand_o)
            self.publish_device(builder, cb)

    def _control_builder(
        self,
        dev_id: str,
        pv: str | None,
        local_key: str | None,
        data: Any,
        sand_o: SandO,
        protocol: int = 5,
    ):
        """``bbppbbd.bdpdqbp(topicId, pv, localKey, data, sandO,
        protocol, cb)`` → ``MqttControlBuilder{data, localKey, pv,
        protocol, topicId, sn=s, o, s, t=(int)timestamp}``."""
        from .mqtt_session import MqttControlBuilder

        return MqttControlBuilder(
            data=data,
            local_key=local_key,
            pv=pv,
            protocol=protocol,
            topic_id=dev_id,
            sn=sand_o.s,
            o=sand_o.o,
            s=sand_o.s,
            t=int(self.timestamp_fn()),
        )

    def send_by_http(
        self,
        gw_id: str,
        dev_id: str,
        dps_json: str,
        pcc: str,
        cb: ResultCallback | None = None,
    ) -> None:
        """``sendByHttp`` — ``DpPublish{gwId,devId,dps,pcc}`` →
        ``dbppbbp.bdpdqbp`` → ATOP ``thing.m.device.dp.publish`` v1.0
        (postData gwId/devId/dps[/pcc])."""
        log.info("network control by http：gwId = %s devId=%s", gw_id, dev_id)
        pub = DpPublish(gw_id=gw_id, dev_id=dev_id, dps=dps_json, pcc=pcc)
        if self.atop_publish is not None:
            self.atop_publish(pub, cb)

    def _http_send(self, gw_id: str, dev_id: str, dps_json: str, cb) -> None:
        """``bdpdqbp(gwId, devId, data, cb)`` (526) → sendByHttp with
        ``pcc=""``."""
        self.send_by_http(gw_id, dev_id, dps_json, "", cb)


# ---------------------------------------------------------------------------
# bpqqdpq — DevLocalControlImpl payload build
# ---------------------------------------------------------------------------


class DevLocalControl:
    """``bpqqdpq`` (sdk/device)."""

    def __init__(
        self,
        cache: DevListCacheManager,
        model: LocalControlModel,
        *,
        timestamp_fn: Callable[[], int] | None = None,
        uid: str | None = None,
    ) -> None:
        self.cache = cache
        self.model = model
        self.timestamp_fn = timestamp_fn or model.timestamp_fn
        self.uid = uid

    def control_new(
        self,
        dev_id: str,
        node_id: str | None,
        ctype: int,
        dp_map: dict[str, Any],
        sand_o: SandO,
        log_key: str,
        cb: ResultCallback | None = None,
    ) -> None:
        """``bdpdqbp(devId, nodeId, type, map, sandO, logKey, cb)``
        (34-85) → ``{cid?,ctype?,mbid?,dps}`` CONTROL_NEW."""
        obj: dict[str, Any] = {}
        add_cid_ctype(self.cache, dev_id, node_id, ctype, obj)
        if not text_is_empty(log_key):
            obj["mbid"] = log_key
        obj["dps"] = dp_map
        self.model.control(dev_id, obj, sand_o, FrameTypeEnum.CONTROL_NEW, cb)

    def control_old(
        self,
        dev_id: str,
        dp_map: dict[str, Any],
        sand_o: SandO,
        cb: ResultCallback | None = None,
    ) -> None:
        """``bdpdqbp(devId, map, sandO, cb)`` (87-205) →
        ``{dps,devId,t?,uid?}`` CONTROL."""
        obj: dict[str, Any] = {"dps": dp_map, "devId": dev_id}
        hgw = self.model._hgw(self.cache.get_dev(dev_id))
        if hgw is not None and check_hgw_version(hgw.version, 1.1):
            obj["t"] = self.timestamp_fn()
        if self.uid is not None:
            obj["uid"] = self.uid
        self.model.control(dev_id, obj, sand_o, FrameTypeEnum.CONTROL, cb)


# ---------------------------------------------------------------------------
# qqdbbpp — per-device comm controller (LAN half)
# ---------------------------------------------------------------------------


class DeviceCommController:
    """``qqdbbpp`` — LAN send entry + DP-map build + frame-type gate.

    ``check_send``/``encode_raw`` are the DevUtil ports;
    ``sand_r_map`` is the per-devId SandO store.
    """

    def __init__(
        self,
        dev_id: str,
        cache: DevListCacheManager,
        local_control: DevLocalControl,
        *,
        sand_r_map: SandRMap | None = None,
        check_send: Callable[[str, dict[str, Any]], bool] | None = None,
        encode_raw: Callable[[str, str, dict[str, Any]], Any] | None = None,
        cloud: DevCloudControl | None = None,
    ) -> None:
        self.dev_id = dev_id
        self.cache = cache
        self.local_control = local_control
        self.sand_r_map = sand_r_map or SandRMap()
        self.check_send = check_send or (lambda d, m: True)
        self.encode_raw = encode_raw or (lambda d, j, m: j)
        self.cloud = cloud

    def next_sand_o(self) -> SandO:
        """``bdpdqbp()`` (364-399): get-or-create per-devId SandO, then
        ``SAdd``."""
        sand_o = self.sand_r_map.get(self.dev_id)
        if sand_o is None:
            sand_o = SandO()
            self.sand_r_map.put(self.dev_id, sand_o)
        sand_o.s_add()
        return sand_o

    def get_comm_and_node(self) -> tuple[str, str | None]:
        """``bdpdqbp(devId)`` → ``pqdbppq{commNode, nodeId}`` (282-362).

        respBean null → ``{devId, devId}``.  Otherwise ``commNode`` =
        ``communication.communicationNode`` (Java NPEs when the
        communication module is absent — mirrored), or ``devId`` when
        commNode is empty AND ``isTripartiteMatter``; ``nodeId`` =
        ``topo.nodeId``, forced to ``""`` when commNode == devId.
        """
        resp = self.cache.get_dev_resp_bean(self.dev_id)
        comm_id: str | None = self.dev_id
        node_id: str | None = self.dev_id
        if resp is not None:
            comm_id = resp.communication.communication_node  # type: ignore[union-attr]
            node_id = resp.device_topo.node_id if resp.device_topo is not None else None
            if text_is_empty(comm_id) and resp.is_tripartite_matter():
                comm_id = self.dev_id
            else:
                # keep nodeId; commNode may still be None
                pass
            if self.dev_id == comm_id:
                node_id = ""
        return comm_id, node_id

    def build_dp_map(self, node_id: str | None, dps_json: str) -> dict[str, Any] | None:
        """``bdpdqbp(nodeId, dpsJson)`` (401-531): non-empty nodeId →
        resolve sub-device by nodeId among ``getSubDevList(devId)`` and
        validate/encode against the **sub-device's** schema; empty →
        this device's schema.  checkSendCommond false → None."""
        if not text_is_empty(node_id):
            sub_dev_id = ""
            for sub in self.cache.get_sub_dev_list_beans(self.dev_id):
                if sub.node_id == node_id:
                    sub_dev_id = sub.dev_id
                    break
            if not text_is_empty(sub_dev_id):
                m = _parse_dps(dps_json)
                if not self.check_send(sub_dev_id, m):
                    return None
                self.encode_raw(sub_dev_id, dps_json, m)
                return m
        m = _parse_dps(dps_json)
        if not self.check_send(self.dev_id, m):
            return None
        self.encode_raw(self.dev_id, dps_json, m)
        return m

    def publish_dps_lan(self, dps_json: str, cb: ResultCallback | None = None) -> None:
        """``pdqppqb(data, cb)`` (2299-2340) → ``bdpdqbp(dev,nodeId,0,
        data,sandO,"",cb)`` (554-638)."""
        sand_o = self.next_sand_o()
        comm_id, node_id = self.get_comm_and_node()
        dev = self.cache.get_dev(comm_id)
        # Java has no null-check on dev — NPEs; mirrored by AttributeError.
        dp_map = self.build_dp_map(node_id, dps_json)
        if dp_map is None:
            if cb is not None:
                cb.on_error("11001", None)
            return
        if (
            compare_version(dev.get_cadv(), "1.0.1") < 0
            and not dev.has_zigbee()
            and not dev.is_ble_mesh()
        ):
            self.local_control.control_old(dev.dev_id, dp_map, sand_o, cb)
        else:
            self.local_control.control_new(dev.dev_id, node_id, 0, dp_map, sand_o, "", cb)

    # -- internet half -----------------------------------------------------

    def send(
        self,
        dps_json: str,
        cb: ResultCallback | None = None,
        *,
        is_network_available: Callable[[], bool] | None = None,
        server_available: Callable[[], bool] | None = None,
        is_lan_online: Callable[[Any, int], bool] | None = None,
        http_publish: Callable[[str, str, str, ResultCallback], None] | None = None,
        query_dev: Callable[[str], None] | None = None,
        scheduler: Callable[[float, Callable[[], None]], Any] | None = None,
        **seams: Any,
    ) -> None:
        """``send(dps, cb)`` (2560-2707) — the ``publishDps`` entry.

        ``dev != null && !isRealConnect && !dev.getCommunicationOnline(LAN)
        && networkAvailable`` → "dps send by http":
        ``sendByHttp(dev.communicationId, devId, json, cb)`` directly
        (no sub-dev lookup) + handler msg 1 → ``queryDev(devId)`` after
        500 ms.  Otherwise → ``bdpdqbp(commNode, nodeId, dps, 0, cb)``
        (the LAN-first ``publish_dps`` path).
        """
        dev = self.cache.get_dev(self.dev_id)
        server_up = server_available or (lambda: True)
        net = is_network_available or (lambda: True)
        lan_online = is_lan_online or (lambda d, e: False)
        if (
            dev is not None
            and not server_up()
            and not lan_online(dev, CommunicationEnum.LAN)
            and net()
        ):
            log.info("dps send by http")
            dp_map = self.build_dp_map(None, dps_json)
            if dp_map is None:
                cb.on_error("11001", None)  # type: ignore[union-attr]
                return
            if http_publish is not None:
                http_publish(dev.communication_id, self.dev_id, to_json_string(dp_map), cb)
            if query_dev is not None:
                (scheduler or LanCommPipeline._default_scheduler)(
                    0.5, lambda: query_dev(self.dev_id)
                )
            return
        comm_id, node_id = self.get_comm_and_node()
        self.publish_dps(
            comm_id,
            node_id,
            dps_json,
            0,
            "",
            cb,
            is_online=is_lan_online,
            is_network_available=is_network_available,
            server_available=server_available,
            http_publish=http_publish,
            query_dev=query_dev,
            scheduler=scheduler,
            **seams,
        )

    def send_internet(
        self,
        dps_json: str,
        ctype: int = 0,
        cb: ResultCallback | None = None,
        **seams: Any,
    ) -> None:
        """``bdpdqbp(dpsJson, type, cb)`` (782-841) — the ``dbqqppp``
        internet entry used by ``qpbpqpq.bppdpdq(dps,cb)``.

        Resolves ``{comm,node}`` via ``get_comm_and_node`` on
        ``this.devId``, fetches the bean by **commId**, and goes
        straight to "control by server" — the LAN check is NOT here
        (it lives in the 6-arg 1163 entry)."""
        sand_o = self.next_sand_o()
        comm_id, node_id = self.get_comm_and_node()
        dev = self.cache.get_dev(comm_id)
        if dev is not None:
            allowed = {
                k: v
                for k, v in seams.items()
                if k
                in (
                    "is_network_available",
                    "server_available",
                    "is_mqtt_subscribed",
                    "subscribe_in",
                    "mqtt_send",
                    "http_publish",
                    "query_dev",
                    "scheduler",
                )
            }
            self.control_by_server(dev, node_id, ctype, dps_json, "", sand_o, cb, **allowed)
        elif cb is not None:
            cb.on_error("11002", "dev is removed")

    def publish_dps(
        self,
        dev_id: str,
        node_id: str | None,
        dps_json: str,
        ctype: int = 0,
        log_key: str = "",
        cb: ResultCallback | None = None,
        *,
        is_online: Callable[[Any, int], bool] | None = None,
        is_network_available: Callable[[], bool] | None = None,
        server_available: Callable[[], bool] | None = None,
        is_mqtt_subscribed: Callable[[str], bool] | None = None,
        subscribe_in: Callable[[str], None] | None = None,
        mqtt_send: Callable[..., None] | None = None,
        http_publish: Callable[[str, str, str, ResultCallback], None] | None = None,
        query_dev: Callable[[str], None] | None = None,
        scheduler: Callable[[float, Callable[[], None]], Any] | None = None,
    ) -> None:
        """``bdpdqbp(devId, nodeId, data, type, logKey, cb)`` (1163).

        1. ``dev = cache.getDev(devId)``; null → ``11002, null``.
        2. ``map = build_dp_map(nodeId, data)``; null → ``11001``.
        3. ``sandO = next_sand_o()``.
        4. ``dev.getCommunicationOnline(LAN)`` → "dps send by local" —
           LAN send wrapped in ``$bppdpdq`` (LAN error → server path).
        5. else → "control by server" (MQTT-first → HTTP backup).

        The injectables stand in for the plugins: ``is_online`` =
        ``IThingDeviceOperate.getIsOnline``; ``server_available`` =
        ``bpbqqdq.pdqppqb()`` (mqtt-up check); ``mqtt_send`` =
        ``dqdpbbd.sendCommand``; ``http_publish`` =
        ``dqdpbbd.sendByHttp`` (ATOP ``thing.m.device.dp.publish`` 1.0).
        """
        dev = self.cache.get_dev(dev_id)
        if dev is None:
            if cb is not None:
                cb.on_error("11002", None)
            return
        dp_map = self.build_dp_map(node_id, dps_json)
        if dp_map is None:
            if cb is not None:
                cb.on_error("11001", None)
            return
        sand_o = self.next_sand_o()
        online = is_online or (lambda d, e: False)
        if online(dev, CommunicationEnum.LAN):
            log.info("dps send by local")

            def lan_err(_c: str, _m: str | None) -> None:
                self.control_by_server(
                    dev,
                    node_id,
                    ctype,
                    dps_json,
                    log_key,
                    sand_o,
                    cb,
                    is_network_available=is_network_available,
                    server_available=server_available,
                    is_mqtt_subscribed=is_mqtt_subscribed,
                    subscribe_in=subscribe_in,
                    mqtt_send=mqtt_send,
                    http_publish=http_publish,
                    query_dev=query_dev,
                    scheduler=scheduler,
                )

            class _LanFallback(ResultCallback):
                def on_error(self, code, msg):
                    lan_err(code, msg)

                def on_success(self):
                    if cb is not None:
                        cb.on_success()

            self._lan_send(dev, node_id, ctype, dps_json, sand_o, log_key, _LanFallback())
        else:
            self.control_by_server(
                dev,
                node_id,
                ctype,
                dps_json,
                log_key,
                sand_o,
                cb,
                is_network_available=is_network_available,
                server_available=server_available,
                is_mqtt_subscribed=is_mqtt_subscribed,
                subscribe_in=subscribe_in,
                mqtt_send=mqtt_send,
                http_publish=http_publish,
                query_dev=query_dev,
                scheduler=scheduler,
            )

    def _lan_send(
        self,
        dev: DeviceBean,
        node_id: str | None,
        ctype: int,
        dps_json: str,
        sand_o: SandO,
        log_key: str,
        cb: ResultCallback | None,
    ) -> None:
        """``bdpdqbp(dev, nodeId, type, data, sandO, logKey, cb)``
        (554-638) — cadv/zigbee/bleMesh gate between CONTROL_NEW and the
        old CONTROL frame."""
        dp_map = self.build_dp_map(node_id, dps_json)
        if dp_map is None:
            if cb is not None:
                cb.on_error("11001", None)
            return
        if (
            compare_version(dev.get_cadv(), "1.0.1") < 0
            and not dev.has_zigbee()
            and not dev.is_ble_mesh()
        ):
            self.local_control.control_old(dev.dev_id, dp_map, sand_o, cb)
        else:
            self.local_control.control_new(dev.dev_id, node_id, ctype, dp_map, sand_o, log_key, cb)

    def control_by_server(
        self,
        dev: DeviceBean,
        node_id: str | None,
        ctype: int,
        dps_json: str,
        log_key: str,
        sand_o: SandO,
        cb: ResultCallback | None,
        *,
        is_network_available: Callable[[], bool] | None = None,
        server_available: Callable[[], bool] | None = None,
        is_mqtt_subscribed: Callable[[str], bool] | None = None,
        subscribe_in: Callable[[str], None] | None = None,
        mqtt_send: Callable[..., None] | None = None,
        http_publish: Callable[[str, str, str, ResultCallback], None] | None = None,
        query_dev: Callable[[str], None] | None = None,
        scheduler: Callable[[float, Callable[[], None]], Any] | None = None,
    ) -> None:
        """``bdpdqbp(dev, nodeId, type, data, logKey, sandO, cb)``
        (630-790) — "control by server".

        - ``!server_available() && networkAvailable`` → HTTP path
          immediately.
        - else if ``dev.isOnline`` → optional
          ``subscribe("smart/mb/in/<devId>")`` then MQTT send wrapped in
          ``$qddqppb`` (MQTT error → HTTP backup).
        - else → ``cb.onError("10203", null)``.
        """
        log.info("control by server")
        dev_id = dev.dev_id
        net = is_network_available or (lambda: True)
        server_up = server_available or (lambda: True)
        if not server_up() and net():
            self._http_send(
                node_id,
                dps_json,
                cb,
                dev_id,
                http_publish=http_publish,
                query_dev=query_dev,
                scheduler=scheduler,
            )
            return
        if dev.is_online:
            dev_id_str = dev_id
            if (
                is_mqtt_subscribed is not None
                and not is_mqtt_subscribed(dev_id_str)
                and subscribe_in is not None
            ):
                subscribe_in(dev_id_str)

            outer = self

            class _MqttFallback(ResultCallback):
                """``qqdbbpp$qddqppb`` — MQTT error → HTTP backup."""

                def on_error(self, code, msg):
                    log.warning("controlByServer send dp failed : %s, start backup http send", msg)
                    outer._http_send(
                        node_id,
                        dps_json,
                        cb,
                        dev_id_str,
                        http_publish=http_publish,
                        query_dev=query_dev,
                        scheduler=scheduler,
                    )

                def on_success(self):
                    if cb is not None:
                        cb.on_success()

            if mqtt_send is not None:
                # inner ``bdpdqbp(devId,data,nodeId,type,logKey,sandO,
                # cb)`` builds the map itself; null → ``11001`` on the
                # WRAPPED cb → ``$qddqppb`` http backup → its own map
                # build fails → ``11001`` on the caller's cb.
                wrapped = _MqttFallback()
                inner_map = self.build_dp_map(node_id, dps_json)
                if inner_map is None:
                    wrapped.on_error("11001", None)
                    return
                mqtt_send(dev_id_str, inner_map, node_id, ctype, log_key, sand_o, wrapped)
        else:
            if cb is not None:
                cb.on_error("10203", None)

    def _http_send(
        self,
        node_id: str | None,
        dps_json: str,
        cb: ResultCallback | None,
        dev_id: str | None,
        *,
        http_publish: Callable[[str, str, str, ResultCallback], None] | None,
        query_dev: Callable[[str], None] | None,
        scheduler: Callable[[float, Callable[[], None]], Any] | None,
    ) -> None:
        """``bdpdqbp(nodeId, dpsJson, cb, devId)`` (988-1055).

        - ``build_dp_map`` null → ``cb.onError("11001", null)`` — no
          null-check on cb here (Java NPEs); mirrored.
        - nodeId empty → ``sendByHttp(devId, devId, json)``
        - else sub lookup: found → ``sendByHttp(devId, subDevId, json)``;
          not found → ``cb.onError("10203", null)``
        - always: after 500 ms → ``bpbqqdq.queryDev(subDevId or
          this.devId)``.
        """
        dp_map = self.build_dp_map(node_id, dps_json)
        if dp_map is None:
            cb.on_error("11001", None)  # type: ignore[union-attr]
            return
        sub_dev_id = ""
        if text_is_empty(node_id):
            if http_publish is not None:
                http_publish(dev_id, dev_id, to_json_string(dp_map), cb)
        else:
            sub = self.cache.get_sub_dev(dev_id, node_id)
            if sub is not None:
                sub_dev_id = sub.dev_id
            if not text_is_empty(sub_dev_id):
                if http_publish is not None:
                    http_publish(dev_id, sub_dev_id, to_json_string(dp_map), cb)
            else:
                cb.on_error("10203", None)  # type: ignore[union-attr]
        if query_dev is not None:
            target = sub_dev_id if not text_is_empty(sub_dev_id) else self.dev_id
            (scheduler or LanCommPipeline._default_scheduler)(0.5, lambda: query_dev(target))

    def send_with_node(
        self,
        force_http: bool,
        node_arg: str | None,
        dps_json: str,
        ctype: int,
        cb: ResultCallback | None = None,
        *,
        query_dev: Callable[[str], None] | None = None,
        scheduler: Callable[[float, Callable[[], None]], Any] | None = None,
    ) -> None:
        """``bdpdqbp(Z, String, String, int, cb)`` (qqdbbpp:1321) — the
        ``dbqqppp`` 5-arg entry behind ``qpbpqpq``'s Mqtt/Http modes.

        1. ``map = bdpdqbp(nodeArg, dps)`` — node resolves a sub-device
           by nodeId (validating against the SUB's schema); null →
           ``11001, null``.
        2. ``dev = getDev(this.devId)``; null → ``11002 "dev==null"``.
        3. ``dev.devId`` empty && ``dev.nodeId`` non-empty →
           ``getSubDev(commId, nodeId)``; still empty →
           ``cb.onError("10203", "can not find sub-device")`` — and
           continues.
        4. ``force_http`` → ``sendByHttp(commId, devId2 ?: commId,
           toJSONString(map, WriteMapNullValue), "")`` + a 500 ms
           ``queryDev(devId2 ?: this.devId)`` runnable.
        5. else "dps publish by mqtt" →
           ``dqdpbbd.bdpdqbp(commId, map, dev, nodeArg ?: commId, type,
           "", sandO, cb)`` — the 861 payload builder.
        """
        sand_o = self.next_sand_o()
        dp_map = self.build_dp_map(node_arg, dps_json)
        if dp_map is None:
            if cb is not None:
                cb.on_error("11001", None)
            return
        dev = self.cache.get_dev(self.dev_id)
        if dev is None:
            if cb is not None:
                cb.on_error("11002", "dev==null")
            return
        node_id2 = dev.node_id
        dev_id2 = dev.dev_id
        comm_id = dev.communication_id
        if text_is_empty(dev_id2) and not text_is_empty(node_id2):
            sub = self.cache.get_sub_dev(comm_id, node_id2)
            if sub is not None:
                dev_id2 = sub.dev_id
            if text_is_empty(dev_id2) and cb is not None:
                cb.on_error("10203", "can not find sub-device")
        if force_http:
            target = dev_id2 if not text_is_empty(dev_id2) else comm_id
            if self.cloud is not None:
                self.cloud.send_by_http(
                    comm_id,
                    target,
                    to_json_string(dp_map, write_nulls=True),
                    "",
                    cb,
                )
            if query_dev is not None:
                q_target = dev_id2 if not text_is_empty(dev_id2) else self.dev_id
                (scheduler or LanCommPipeline._default_scheduler)(0.5, lambda: query_dev(q_target))
            return
        log.info("dps publish by mqtt")
        node_or_comm = comm_id if text_is_empty(node_arg) else node_arg
        if self.cloud is not None:
            self.cloud._mqtt_send(comm_id, dp_map, dev, node_or_comm, ctype, "", sand_o, cb)


# ---------------------------------------------------------------------------
# qpbpqpq — gates
# ---------------------------------------------------------------------------


class LanGate:
    """``qpbpqpq`` — intranet/cloud eligibility checks."""

    def __init__(
        self,
        cache: DevListCacheManager,
        hgw_provider: Callable[[str], HgwBean | None],
        *,
        is_network_available: Callable[[], bool] | None = None,
    ) -> None:
        self.cache = cache
        self.hgw_provider = hgw_provider
        self.is_network_available = is_network_available or (lambda: True)

    def is_intranet_control(self, dev_id: str) -> bool:
        """``qpbpqpq.isIntranetControl`` (1129-1273): plugin+bean present,
        hgw resolved by ``dev.communicationId`` (the comm node, not
        devId); true iff ``active ∈ {ACTIVED, LOCAL_ACTIVED}``."""
        dev = self.cache.get_dev(dev_id)
        if dev is None:
            return False
        hgw = self.hgw_provider(dev.communication_id)
        if hgw is None:
            return False
        return hgw.active in (ActiveEnum.ACTIVED, ActiveEnum.LOCAL_ACTIVED)

    def is_cloud_online(self, dev_id: str) -> bool:
        """``qpbpqpq.isCloudOnline`` (984-1127): wrapped bean's
        ``cloud_online``; when ``communicationId != devId`` the gateway
        device must also be cloud-online."""
        dev = self.cache.get_dev(dev_id)
        if dev is None:
            return False
        if dev.communication_id != dev_id:
            gw = self.cache.get_dev(dev.communication_id)
            if gw is None or not gw.is_online:
                return False
        return bool(dev.is_online)


# ---------------------------------------------------------------------------
# bddqdbd — ThingLanCommPipeline (watchdog + fallback)
# ---------------------------------------------------------------------------


class LanCommPipeline:
    """``bddqdbd`` — ``pdqppqb(command, cb)`` (85-167).

    Runs ``lan_send(command, inner_cb)`` with a 500 ms watchdog on the
    caller-provided scheduler; watchdog fire or inner error →
    ``cloud_send(command, cb)``.  A late LAN success after the watchdog
    still calls ``cb.on_success`` (the flag only guards the watchdog).
    """

    WATCHDOG_MS = 500

    def __init__(
        self,
        lan_send: Callable[[Any, ResultCallback], None],
        cloud_send: Callable[[Any, ResultCallback | None], None],
        scheduler: Callable[[float, Callable[[], None]], Any] | None = None,
    ) -> None:
        self.lan_send = lan_send
        self.cloud_send = cloud_send
        # scheduler(delay_s, fn) → timer handle with .cancel()
        self.scheduler = scheduler or self._default_scheduler

    @staticmethod
    def _default_scheduler(delay_s: float, fn: Callable[[], None]) -> Any:
        t = threading.Timer(delay_s, fn)
        t.daemon = True
        t.start()
        return t

    def send(self, command: Any, cb: ResultCallback | None = None) -> None:
        answered = [False]

        def watchdog() -> None:
            if not answered[0]:
                log.info("LAN request timeout, fallback to internet")
                self.cloud_send(command, cb)

        timer = self.scheduler(self.WATCHDOG_MS / 1000.0, watchdog)

        pipeline = self

        class _Inner(ResultCallback):
            def on_error(self, code: str, msg: str | None) -> None:
                answered[0] = True
                timer.cancel()
                log.info("LAN control error")
                # stat event 9 unless msg ends with "#" (already recorded)
                if not (msg or "").endswith("#"):
                    pipeline.on_stat(command, code, msg)
                pipeline.cloud_send(command, cb)

            def on_success(self) -> None:
                answered[0] = True
                timer.cancel()
                if cb is not None:
                    cb.on_success()

        self.lan_send(command, _Inner())

    def on_stat(self, command: Any, code: str, msg: str | None) -> None:
        """Stat hook (event 9) — overridable/injectable."""
