"""Port of the ThingClips device caches.

``DeviceRespBean``/``DeviceBean``      — interior/public device beans.
``DevListCacheManager``                — ``ppqqqpb`` (sdk/device), the
    ``IThingDevListCacheManager`` implementation: devId→DeviceRespBean map
    plus uuid/sub-device/mesh secondary indices and ``devRespWrap``.
``DeviceDataManager``                  — the ``ddpdbbp`` halves the
    transport layer uses: ``getDp``/``getDps``/``getSchemaBean``.
``pbqdddb`` product key                — ``productId + "_" + (ver|"1.0.0")``.
``ingest_dps``                         — ``pdppddb.bdpdqbp`` central DP
    ingest shared by MQTT and LAN inbound.

Sources: ppqqqpb.smali, ddpdbbp.smali, pdppddb.smali, bpbqqdq.smali,
DeviceRespBean.smali + inner modules, DeviceBean.smali,
CommunicationEnum.smali.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ._java import text_is_empty

log = logging.getLogger("thing-device")


class CommunicationEnum:
    """``com.thingclips.smart.interior.device.bean.CommunicationEnum``."""

    LAN = 0
    MQTT = 1
    HTTP = 2
    BLE = 3
    SIGMESH = 4
    THING_MESH = 5
    THING_BEACON = 6
    THING_MATTER = 8
    YU_MQTT = 12
    CLOUD_MODE = 100


@dataclass
class CommunicationModuleT:
    """``DeviceRespBean$CommunicationModuleT`` — one entry of
    ``communicationModes``: ``{type: int, pv: str}``."""

    type: int = 0
    pv: str | None = None


@dataclass
class CommunicationModule:
    """``DeviceRespBean$CommunicationModule``."""

    communication_modes: list[CommunicationModuleT] | None = None
    communication_node: str | None = None
    connection_status: int = 0
    data_model: int = 0
    local_communication_node: str | None = None
    local_data_model: int = 0
    local_node_id: str | None = None
    mqtt_topic_attr: int = 0


@dataclass
class DataPointModule:
    """``DeviceRespBean$DataPointModule``."""

    dps: dict[str, Any] | None = None
    dps_time: dict[str, int] | None = None
    dp_name: dict[str, str] | None = None
    dp_max_time: int = 0


@dataclass
class DeviceTopoMoudle:
    """``DeviceRespBean$DeviceTopoMoudle`` (sic)."""

    mesh_id: str | None = None
    node_id: str | None = None
    parent_dev_id: str | None = None


# ``LitePresenter.decodeRaw`` hook — the SDK registers an
# ``IThingLitePresenter`` whose ``decodeRaw(devId, dps)`` is invoked lazily
# the first time ``DeviceRespBean.getDps`` runs (DeviceRespBean.smali
# 446-560).  In Python this is a process-wide injectable callable.
_lite_presenter: Callable[[str, dict[str, Any]], bool] | None = None


def set_lite_presenter(fn: Callable[[str, dict[str, Any]], bool] | None) -> None:
    global _lite_presenter
    _lite_presenter = fn


@dataclass
class ProductRefBean:
    """``com.thingclips.smart.home.sdk.bean.ProductRefBean`` — only the
    ``configMetas`` map the low-power manager reads."""

    config_metas: dict[str, Any] | None = None


@dataclass
class DeviceBizPropBean:
    """``com.thingclips.smart.home.sdk.bean.DeviceBizPropBean``."""

    cloud_connect_last_update_time: int = 0


class DeviceRespBean:
    """``com.thingclips.smart.interior.device.bean.DeviceRespBean``.

    ``get_dps`` reproduces the lazy raw-decode: on first call it runs the
    registered lite-presenter ``decodeRaw(devId, dps)`` then flips
    ``is_raw_decoded`` — even if the presenter is absent (the flag is set
    inside the ``plugin != null`` branch in Java only; we mirror that).
    ``get_dps_time`` has no null-check on ``dataPointInfo`` in Java →
    NPE; mirrored by attribute access raising ``AttributeError``.
    """

    def __init__(self) -> None:
        self.access_type: int = 0
        self.active_time: int = 0
        self.base_attribute: int = 0
        self.cloud_online: bool = False
        self.communication: CommunicationModule | None = None
        self.data_point_info: DataPointModule | None = None
        self.dev_attribute: int = 0
        self.dev_id: str | None = None
        self.dev_key: str | None = None
        self.device_topo: DeviceTopoMoudle | None = None
        self.display_order: int = 0
        self.error_code: int = 0
        self.gateway_ver_cad: str | None = None
        self.home_display_order: int = 0
        self.icon_url: str | None = None
        self.ip: str | None = None
        self.is_raw_decoded: bool = False
        self.lat: str | None = None
        self.local_key: str | None = None
        self.lon: str | None = None
        self.mac: str | None = None
        self.meta: dict[str, Any] | None = None
        self.name: str | None = None
        self.owner_id: str | None = None
        self.product_id: str | None = None
        self.product_ref_bean: ProductRefBean | None = None
        self.device_biz_prop_bean: DeviceBizPropBean | None = None
        self.product_ver: str | None = None
        self.protocol_attribute: int = 0
        self.resptime: int = 0
        self.runtime_env: str | None = None
        self.sec_key: str | None = None
        self.skills: dict[str, Any] | None = None
        self.thing_model: Any = None
        self.timezone_id: str | None = None
        self.uuid: str | None = None
        self.virtual: bool = False
        self.virtual_experience: bool = False
        self._lock = threading.Lock()

    # --- DataPointModule accessors (DeviceRespBean.smali 446-720) ---

    def get_dps_may_raw_un_decoded(self) -> dict[str, Any] | None:
        if self.data_point_info is not None:
            return self.data_point_info.dps
        return None

    def get_dps(self) -> dict[str, Any] | None:
        dps = self.get_dps_may_raw_un_decoded()
        if not self.is_raw_decoded:
            with self._lock:
                if not self.is_raw_decoded and _lite_presenter is not None:
                    _lite_presenter(self.dev_id, dps)
                    self.is_raw_decoded = True
        return dps

    def set_dps(self, dps: dict[str, Any] | None) -> None:
        if self.data_point_info is None:
            self.data_point_info = DataPointModule()
        self.data_point_info.dps = dps

    def get_dps_time(self) -> dict[str, int] | None:
        # Java: no null check on dataPointInfo → NPE when absent.
        return self.data_point_info.dps_time  # type: ignore[union-attr]

    def set_dps_time(self, dps_time: dict[str, int] | None) -> None:
        if self.data_point_info is None:
            self.data_point_info = DataPointModule()
        self.data_point_info.dps_time = dps_time

    def get_mesh_id(self) -> str | None:
        if self.device_topo is not None:
            return self.device_topo.mesh_id
        return None

    def is_cloud_online(self) -> bool:
        return self.cloud_online

    def is_tripartite_matter(self) -> bool:
        """``isTripartiteMatter`` — ``accessType == 1``."""
        return self.access_type == 1


@dataclass
class SchemaInfo:
    """``ProductBean$SchemaInfo`` — only the maps the transport touches."""

    schema_map: dict[str, Any] | None = None  # dpId → SchemaBean
    dp_code_schema_map: dict[str, Any] | None = None  # code → SchemaBean


class ProductBean:
    """``ProductBean`` — predicates are ``capability`` bitmask checks
    (ProductBean.smali).  Note ``is_beacon``/``is_bluetooth`` are
    **equality** checks, not masks."""

    CAP_WIFI = 0x1
    CAP_BLUETOOTH = 0x400
    CAP_BLUE_MESH = 0x800
    CAP_ZIGBEE = 0x1000
    CAP_INFRARED = 0x2000
    CAP_SIG_MESH = 0x8000
    CAP_CAT1 = 0x100000
    CAP_BEACON = 0x200000
    CAP_PLC = 0x8000000
    CAP_WISUN = 0x10000000
    CAP_433_A = 0x20000  # has433 checks this OR 0x4000
    CAP_433_B = 0x4000

    def __init__(self, product_id: str | None = None) -> None:
        self.product_id = product_id
        self.schema_info: SchemaInfo | None = None
        self.attribute: int = 0  # DeviceBean.getAttribute() delegates here
        self.biz_attribute: int = 0
        self.capability: int = 0
        self.is_standard: bool = False
        self.s_schema: Any = None  # StandSchema
        self.mesh_category: str | None = None

    def has_wifi(self) -> bool:
        return self.capability & self.CAP_WIFI > 0

    def has_bluetooth(self) -> bool:
        return self.capability & self.CAP_BLUETOOTH > 0

    def has_blue_mesh(self) -> bool:
        return self.capability & self.CAP_BLUE_MESH > 0

    def has_sig_mesh(self) -> bool:
        return self.capability & self.CAP_SIG_MESH > 0

    def has_ble_mesh(self) -> bool:
        return self.has_blue_mesh() or self.has_sig_mesh()

    def has_zigbee(self) -> bool:
        return (
            self.capability & self.CAP_PLC > 0
            or self.capability & self.CAP_WISUN > 0
            or self.capability & self.CAP_ZIGBEE > 0
        )

    def has_infrared(self) -> bool:
        return self.capability & self.CAP_INFRARED > 0

    def has_cat1(self) -> bool:
        return self.capability & self.CAP_CAT1 > 0

    def is_beacon(self) -> bool:
        return self.capability == self.CAP_BEACON

    def is_bluetooth(self) -> bool:
        """``ProductBean.isBluetooth`` — **equality**, pure-BLE product."""
        return self.capability == self.CAP_BLUETOOTH

    def has_433(self) -> bool:
        """``has433`` — ``capability & 0x20000 > 0 || & 0x4000 > 0``."""
        return self.capability & self.CAP_433_A > 0 or self.capability & self.CAP_433_B > 0


class DeviceBean:
    """``com.thingclips.smart.sdk.bean.DeviceBean`` — public bean produced
    by ``devRespWrap``."""

    def __init__(self) -> None:
        self.dev_id: str | None = None
        self.uuid: str | None = None
        self.name: str | None = None
        self.product_id: str | None = None
        self.product_ver: str | None = None
        self.product_bean: ProductBean | None = None
        self.device_biz_prop_bean: DeviceBizPropBean | None = None
        self.local_key: str | None = None
        self.sec_key: str | None = None
        self.pv: str | None = None
        self.cadv: str | None = None
        self.dps: dict[str, Any] | None = None
        self.dps_time: dict[str, int] | None = None
        self.dp_max_time: int = 0
        self.dp_name: dict[str, str] | None = None
        self.meta: dict[str, Any] | None = None
        self.node_id: str | None = None
        self.mesh_id: str | None = None
        self.parent_dev_id: str | None = None
        self.parent_id: str | None = None
        self.ip: str | None = None
        self.mac: str | None = None
        self.lat: str | None = None
        self.lon: str | None = None
        self.icon_url: str | None = None
        self.is_online: bool | None = None
        self.is_local_online: bool | None = None
        self.is_share: bool | None = None
        self.virtual: bool = False
        self.virtual_experience: bool = False
        self.dev_attribute: int = 0
        self.base_attribute: int = 0
        self.protocol_attribute: int = 0
        self.error_code: int = 0
        self.access_type: int = 0
        self.data_model: int = 0
        self.connection_status: int = 0
        self.mqtt_topic_attr: int = 0
        self.has_lan_communication: bool = False
        self.has_mqtt_communication: bool = False
        self.has_ble_communication: bool = False
        self.has_sigmesh_communication: bool = False
        self.has_thing_mesh_communication: bool = False
        self.has_http_communication: bool = False
        self.open_proxy: bool = False
        self.open_relay: bool = False
        self.support_proxy_and_relay: bool = False
        self.runtime_env: str | None = None
        self.timezone_id: str | None = None
        self.owner_id: str | None = None
        self.time: int = 0
        self.shared_time: int = 0
        # ``communicationId`` — respBean.communication.communicationNode.
        self.communication_id: str | None = None
        # ``hgwBean`` — attached by LAN discovery, not by devRespWrap.
        self.hgw_bean = None
        # ``DeviceBizPropBean.bluetoothCapability`` — used by
        # ``AbsThingDevice.checkDirectGateway`` (bit-19 support check).
        self.bluetooth_capability: str | None = None
        # DeviceBean.category — used by the mesh handlers' publishDps.
        self.category: str | None = None

    def get_attribute(self) -> int:
        """``DeviceBean.getAttribute`` → ``productBean.attribute`` (0 when
        product bean absent)."""
        if self.product_bean is None:
            return 0
        return self.product_bean.attribute

    def is_single_ble(self) -> bool:
        """``DeviceBean.isSingleBle`` → ``productBean.isBluetooth()``
        (capability == 0x400 exactly); null product → false."""
        return self.product_bean is not None and self.product_bean.is_bluetooth()

    def is_bluetooth(self) -> bool:
        """→ ``productBean.hasBluetooth()`` (capability & 0x400)."""
        return self.product_bean is not None and self.product_bean.has_bluetooth()

    def is_ble_mesh(self) -> bool:
        """``isBleMesh`` = ``isBlueMesh || isSigMesh``."""
        return self.product_bean is not None and self.product_bean.has_ble_mesh()

    def has_zigbee(self) -> bool:
        return self.product_bean is not None and self.product_bean.has_zigbee()

    def is_beacon(self) -> bool:
        return self.product_bean is not None and self.product_bean.is_beacon()

    def _has_wifi(self) -> bool:
        """private ``hasWifi`` — ``communicationId == devId`` (i.e. the
        device is its own comm node)."""
        return self.communication_id == self.dev_id

    def is_433_wifi(self) -> bool:
        """``is433Wifi`` — virtual → ``product.has433 &&
        product.hasWifi``; else ``product.has433 && hasWifi()``."""
        p = self.product_bean
        if p is None or not p.has_433():
            return False
        if self.virtual:
            return p.has_wifi()
        return self._has_wifi()

    def get_cadv(self) -> str | None:
        return self.cadv


def product_key(product_id: str | None, product_ver: str | None) -> str:
    """``pbqdddb.bdpdqbp(String,String)``: empty ver → ``"1.0.0"``; empty
    productId → ``""``; else ``productId + "_" + ver``."""
    if text_is_empty(product_ver):
        product_ver = "1.0.0"
    if text_is_empty(product_id):
        return ""
    return product_id + "_" + product_ver


class DevListCacheManager:
    """``ppqqqpb`` — ``IThingDevListCacheManager`` implementation."""

    # composite-key separators used literally by the smali
    _SUB_SEP = "parentId/noteId"
    _MESH_SEP = "device/meshId/mac"

    def __init__(self) -> None:
        self.use_new_cache: bool = False  # ``bdpdqbp:Z`` / mUseNewCache
        self.dev_map: dict[str, DeviceRespBean] = {}  # pdqppqb
        self.uuid_map: dict[str, str] = {}  # pbbppqb: uuid → devId
        self.sub_dev_map: dict[str, str] = {}  # bppdpdq: composite → devId
        self.mesh_mac_map: dict[str, str] = {}  # pppbppp
        self.comm_node_ts: dict[str, int] = {}  # qpppdqb: node → millis
        self.dev_bean_map: dict[str, DeviceBean] = {}  # pbddddb
        self.products: dict[str, ProductBean] = {}  # pbqdddb.bdpdqbp
        self._zigbee_ts: dict[str, int] = {}
        # ``IThingHardwarePlugin.getHardwareInstance()`` seam — used by
        # ``devRespWrap`` to attach ``DeviceBean.hgwBean`` (ppqqqpb:3190).
        self.hardware = None
        # ``dddbqdq.getDeviceBizPropBean(devId)`` seam — fallback when
        # ``resp.deviceBizPropBean`` is null (ppqqqpb:3166).
        self.biz_prop_cache = None

    # --- stores ---------------------------------------------------------

    def add_product(self, product: ProductBean) -> None:
        self.products[product_key(product.product_id, None)] = product

    def add_product_versioned(self, product: ProductBean, product_ver: str | None) -> None:
        self.products[product_key(product.product_id, product_ver)] = product

    def add_dev(self, bean: DeviceRespBean) -> None:
        self.add_dev_list([bean])
        if bean.dev_id is not None and not text_is_empty(bean.dev_id):
            self.dev_bean_map.pop(bean.dev_id, None)

    def add_dev_list(self, beans: list[DeviceRespBean | None]) -> None:
        """``bdpdqbp(Map,List)`` + ``bdpdqbp(Map)`` fused (ppqqqpb
        1488-1618): builds a temp map, indexes, then putAll."""
        tmp: dict[str, DeviceRespBean] = {}
        for bean in beans:
            if bean is None or bean.dev_id is None:
                continue
            tmp[bean.dev_id] = bean
            if not text_is_empty(bean.uuid):
                self.uuid_map[bean.uuid] = bean.dev_id
            self._index_sub_dev(bean)
            self._zigbee_inherit(bean)
        self.dev_map.update(tmp)

    def remove_dev(self, dev_id: str) -> bool:
        return self.dev_map.pop(dev_id, None) is not None

    # --- secondary indices (ppqqqpb.pdqppqb(bean) 5259-5454) ------------

    def _index_sub_dev(self, bean: DeviceRespBean) -> None:
        dev_id = bean.dev_id
        comm = bean.communication
        if comm is not None and comm.communication_node != dev_id:
            self.sub_dev_map.setdefault(
                comm.communication_node,
                dev_id,  # gw→sub devId edge
            )
        topo = bean.device_topo
        if topo is None:
            return
        node_id = topo.node_id
        if not text_is_empty(node_id):
            if len(node_id) == 2:
                node_id = "00" + node_id
            if not text_is_empty(topo.parent_dev_id):
                self.sub_dev_map[topo.parent_dev_id + self._SUB_SEP + node_id] = dev_id
            if not text_is_empty(bean.get_mesh_id()):
                self.sub_dev_map[bean.get_mesh_id() + self._SUB_SEP + node_id] = dev_id
        if not text_is_empty(topo.mesh_id) and not text_is_empty(bean.mac):
            self.mesh_mac_map[topo.mesh_id + self._MESH_SEP + bean.mac] = dev_id

    def _zigbee_inherit(self, bean: DeviceRespBean) -> None:
        """``qddqppb(bean)`` (5456-5754): a zigbee sub-device re-added
        within 60 s of its gateway's ``comm_node_ts`` inherits the cached
        bean's dps + cloudOnline."""
        if bean.protocol_attribute & 0x2 > 0:
            return
        comm = bean.communication
        if comm is None or comm.communication_node is None:
            return
        if comm.communication_node == bean.dev_id:
            return
        ts = self.comm_node_ts.get(comm.communication_node)
        if ts is None or ts <= 0:
            return
        import time

        if int(time.time() * 1000) - ts >= 0xEA60:
            return
        product = self.products.get(product_key(bean.product_id, bean.product_ver))
        if product is None or not product.has_zigbee():
            return
        cached = self.dev_map.get(bean.dev_id)
        if cached is None:
            return
        if product.has_zigbee():
            bean.set_dps(cached.get_dps())
            bean.cloud_online = cached.is_cloud_online()

    # --- getters ---------------------------------------------------------

    def get_dev_resp_bean(self, dev_id: str | None) -> DeviceRespBean | None:
        if text_is_empty(dev_id):
            return None
        return self.dev_map.get(dev_id)

    def get_dev(self, dev_id: str | None) -> DeviceBean | None:
        """``getDev(String)`` (3393-3471)."""
        if self.use_new_cache:
            if text_is_empty(dev_id):
                return None
            bean = self.dev_bean_map.get(dev_id)
            if bean is not None:
                return bean
        resp = self.get_dev_resp_bean(dev_id)
        if resp is None:
            return None
        product = self.products.get(product_key(resp.product_id, resp.product_ver))
        if product is None:
            return None
        return self.dev_resp_wrap(resp, product)

    def get_sub_dev(self, parent_dev_id: str | None, node_id: str | None) -> DeviceRespBean | None:
        """``getSubDev`` (3973-4116): nodeId len 2 → ``"00"+nodeId``;
        composite key ``parentDevId + "parentId/noteId" + nodeId``."""
        if text_is_empty(node_id) or text_is_empty(parent_dev_id):
            return None
        if len(node_id) == 2:
            node_id = "00" + node_id
        dev_id = self.sub_dev_map.get(parent_dev_id + self._SUB_SEP + node_id)
        if dev_id is None:
            return None
        return self.dev_map.get(dev_id)

    def get_dev_by_uuid(self, uuid: str) -> DeviceRespBean | None:
        dev_id = self.uuid_map.get(uuid)
        return self.dev_map.get(dev_id) if dev_id else None

    def get_sub_dev_list_beans(self, dev_id: str) -> list[DeviceBean]:
        """``getSubDevList`` (4118-4283): beans whose topo.parentDevId
        == devId OR meshId == devId.  Java NPEs on a bean with no
        deviceTopo — mirrored."""
        if text_is_empty(dev_id):
            return []
        out: list[DeviceBean] = []
        for resp in self.dev_map.values():
            topo = resp.device_topo
            if topo.parent_dev_id == dev_id or resp.get_mesh_id() == dev_id:  # type: ignore[union-attr]
                bean = self.get_dev(resp.dev_id)
                if bean is not None:
                    out.append(bean)
        return out

    def get_dev_list(self) -> list[DeviceRespBean]:
        return list(self.dev_map.values())

    def check_gw(self, hgw) -> bool:
        """``checkGw(HgwBean)`` (ppqqqpb:1932): true iff the bean is
        non-null, ``gwId`` is non-empty, and it resolves in ``dev_map``."""
        if hgw is None or text_is_empty(getattr(hgw, "gw_id", None)):
            return False
        return self.dev_map.get(hgw.gw_id) is not None

    def set_zigbee_sub_dev_timestamp(self, node: str, ts: int) -> None:
        """``setmZigbeeSubDevTimestamp`` feeds ``qpppdqb``."""
        self.comm_node_ts[node] = ts

    # --- update paths ----------------------------------------------------

    def update_sub_dev_dps(self, bean: DeviceRespBean | None, dps: dict[str, Any]) -> None:
        """``updateSubDevDps(bean, map)`` (5957-6030): uses the lazy
        ``get_dps``; creates the map via ``set_dps`` when null."""
        if bean is None:
            return
        if bean.get_dps() is None:
            bean.set_dps({})
        target = bean.get_dps()
        for k, v in dps.items():
            target[k] = v

    def update_sub_dev_dps_by_node(
        self, parent_dev_id: str, node_id: str, dps: dict[str, Any]
    ) -> None:
        self.update_sub_dev_dps(self.get_sub_dev(parent_dev_id, node_id), dps)

    # --- devRespWrap (1997-3370) ----------------------------------------

    def dev_resp_wrap(self, resp: DeviceRespBean, product: ProductBean) -> DeviceBean:
        bean = DeviceBean()
        bean.dev_id = resp.dev_id
        if self.hardware is not None:
            # ppqqqpb:3190 — hgwBean comes from the native gw map, not the
            # devRespBean.
            bean.hgw_bean = self.hardware.get_dev_id(resp.dev_id)
        bean.uuid = resp.uuid
        bean.name = resp.name
        bean.product_id = resp.product_id
        bean.product_ver = resp.product_ver
        bean.product_bean = product
        # ppqqqpb:3156-3180 — resp biz-prop wins; when null the value is
        # fetched from the ``dddbqdq`` biz-prop cache instead.
        if resp.device_biz_prop_bean is not None:
            bean.device_biz_prop_bean = resp.device_biz_prop_bean
        elif self.biz_prop_cache is not None:
            bean.device_biz_prop_bean = self.biz_prop_cache(resp.dev_id)
        bean.local_key = resp.local_key
        bean.sec_key = resp.sec_key
        bean.ip = resp.ip
        bean.mac = resp.mac
        bean.lat = resp.lat
        bean.lon = resp.lon
        bean.icon_url = resp.icon_url
        bean.meta = resp.meta
        bean.owner_id = resp.owner_id
        bean.runtime_env = resp.runtime_env
        bean.timezone_id = resp.timezone_id
        bean.dev_attribute = resp.dev_attribute
        bean.base_attribute = resp.base_attribute
        bean.protocol_attribute = resp.protocol_attribute
        bean.error_code = resp.error_code
        bean.access_type = resp.access_type
        bean.virtual = resp.virtual
        bean.virtual_experience = resp.virtual_experience
        bean.cadv = resp.gateway_ver_cad
        bean.is_online = resp.is_cloud_online()
        topo = resp.device_topo
        if topo is not None:
            bean.node_id = topo.node_id
            bean.mesh_id = topo.mesh_id
            bean.parent_dev_id = topo.parent_dev_id
        bean.parent_id = topo.parent_dev_id if topo and topo.parent_dev_id else resp.get_mesh_id()
        # devRespWrap (ppqqqpb:2084/2153): category = product.meshCategory,
        # overridden by meta["meshCategory"] when the product's is empty.
        if product is not None:
            bean.category = product.mesh_category
        meta = resp.meta
        if meta is not None and text_is_empty(bean.category):
            mc = meta.get("meshCategory")
            if mc is not None and not text_is_empty(str(mc)):
                bean.category = str(mc)
        comm = resp.communication
        if comm is not None:
            bean.connection_status = comm.connection_status
            bean.data_model = comm.data_model
            bean.mqtt_topic_attr = comm.mqtt_topic_attr
            bean.communication_id = comm.communication_node
            modes = comm.communication_modes
            if modes:
                pv: str | None = None
                for m in modes:
                    if m.type == CommunicationEnum.MQTT:
                        bean.has_mqtt_communication = True
                    if m.type == CommunicationEnum.BLE:
                        bean.has_ble_communication = True
                    if m.type == CommunicationEnum.LAN:
                        bean.has_lan_communication = True
                    if m.type == CommunicationEnum.SIGMESH:
                        bean.has_sigmesh_communication = True
                    if m.type == CommunicationEnum.THING_MESH:
                        bean.has_thing_mesh_communication = True
                    if m.type == CommunicationEnum.HTTP:
                        bean.has_http_communication = True
                    if m.type == CommunicationEnum.MQTT:
                        pv = m.pv
                    if text_is_empty(pv) and m.type == CommunicationEnum.BLE:
                        pv = m.pv
                    if text_is_empty(pv) and m.type == CommunicationEnum.HTTP:
                        pv = m.pv
                bean.pv = pv
        dp = resp.data_point_info
        if dp is not None:
            bean.dps = dp.dps
            bean.dps_time = dp.dps_time
            bean.dp_name = dp.dp_name
            bean.dp_max_time = dp.dp_max_time
        return bean


class DeviceDataManager:
    """``ddpdbbp`` — the ``IThingDeviceDataCacheManager`` halves the
    transport layer uses."""

    def __init__(self, cache: DevListCacheManager) -> None:
        self.cache = cache

    def get_dps(self, dev_id: str) -> dict[str, Any] | None:
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is None:
            return None
        return resp.get_dps()

    def get_dp(self, dev_id: str, dp_id: str) -> Any:
        dps = self.get_dps(dev_id)
        if dps is None:
            return None
        return dps.get(dp_id)

    def get_schema_bean(self, dev_id: str) -> dict[str, Any] | None:
        """``getSchemaBean(devId)`` → product ``SchemaInfo.getSchemaMap``
        keyed by dpId (1681-1753)."""
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is None:
            return None
        product = self.cache.products.get(product_key(resp.product_id, resp.product_ver))
        if product is None or product.schema_info is None:
            return None
        return product.schema_info.schema_map

    def get_dp_code_schema_map(self, dev_id: str) -> dict[str, Any] | None:
        """``getDpCodeSchemaMap`` → code-keyed map (1191-1306)."""
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is None:
            return None
        product = self.cache.products.get(product_key(resp.product_id, resp.product_ver))
        if product is None or product.schema_info is None:
            return None
        return product.schema_info.dp_code_schema_map


# ------------------------------------------------------------------------
# Central DP ingest — ``pdppddb`` (sdk/device)
# ------------------------------------------------------------------------


@dataclass
class DpUpdateEvent:
    """``DpUpdateEventModel`` — posted on the SDK event bus; listeners
    (``IDevListener.onDpUpdate``) receive ``(dev_id, dps_json)``."""

    dev_id: str
    dps_json: str
    is_cloud: bool
    dps_time: dict[str, int] | None = None


class CentralDpIngest:
    """``pdppddb`` — shared MQTT/LAN inbound DP ingest.

    ``is_yu_online``, ``is_lan_online``, ``is_cloud_online`` and
    ``is_single_ble_local_online`` are injectable predicates standing in
    for the plugin/device-status lookups (``IYuPlugin``,
    ``DevUtil.isOnline``, …).  ``on_dp_update`` is the
    ``bdqqbqd.bdpdqbp`` event post.
    """

    def __init__(
        self,
        cache: DevListCacheManager,
        data: DeviceDataManager,
        *,
        is_yu_online: Callable[[str], bool] | None = None,
        is_lan_online: Callable[[str], bool] | None = None,
        is_cloud_online: Callable[[str], bool] | None = None,
        is_single_ble_local_online: Callable[[str], bool] | None = None,
        on_dp_update: Callable[[DpUpdateEvent], None] | None = None,
    ) -> None:
        self.cache = cache
        self.data = data
        self.is_yu_online = is_yu_online or (lambda dev_id: False)
        self.is_lan_online = is_lan_online or (lambda dev_id: False)
        self.is_cloud_online = is_cloud_online or (lambda dev_id: False)
        self.is_single_ble_local_online = is_single_ble_local_online or (lambda dev_id: False)
        self.on_dp_update = on_dp_update

    # --- helpers ---------------------------------------------------------

    def merge_dps(self, dev_id: str, dps: dict[str, Any]) -> dict | None:
        """``bdpdqbp(String,Map)`` (180-269): merge into cached dps; the
        *input* map is returned.  When the cached dps map is null the
        puts land in a throwaway HashMap — the bean keeps null."""
        resp = self.cache.get_dev_resp_bean(dev_id)
        if resp is None:
            return None
        target = self.data.get_dps(dev_id)
        if target is None:
            target = {}
        for k, v in dps.items():
            target[k] = v
        return dps

    def merge_dps_time(self, dev_id: str, dps_time: dict[str, int] | None) -> dict | None:
        """``pdqppqb(String,Map)`` (829-931): null map → warn+None;
        creates+attaches ``dpsTime`` when absent; returns input."""
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

    def _filter_single_ble(self, dev_id: str) -> bool:
        """``pdqppqb(String)`` (1088-1144): bean null → True; virtual or
        beacon → False; else ``isSingleBleLocalOnline``."""
        bean = self.cache.get_dev(dev_id)
        if bean is None:
            return True
        if bean.virtual or bean.is_beacon():
            return False
        return self.is_single_ble_local_online(dev_id)

    def _filter_ble_preferred(self, bean: DeviceBean) -> bool:
        """``pdqppqb(DeviceBean)`` (933-1086) + ``bdpdqbp(DeviceBean)``
        (694-785)."""
        if not self.is_single_ble_local_online(bean.dev_id):
            return False
        if bean.meta is not None and "ext_module_in" in bean.meta:
            return False
        if not (self.is_lan_online(bean.dev_id) or self.is_cloud_online(bean.dev_id)):
            return True
        ble_non_single = bean.is_bluetooth() and not bean.is_single_ble()
        if not ble_non_single:
            return False
        resp = self.cache.get_dev_resp_bean(bean.dev_id)
        if resp is None or resp.communication is None:
            return False
        modes = resp.communication.communication_modes
        return bool(modes and modes[0].type == CommunicationEnum.BLE)

    # --- the pipeline ------------------------------------------------------

    def ingest(
        self,
        sub_dev_id: str | None,
        dev_id: str,
        dps_time: dict[str, int] | None,
        dps_json: str,
        from_cloud: bool,
        *,
        decode_raw: Callable[[str, dict[str, Any]], bool],
        check_receive: Callable[[str, dict[str, Any]], bool],
    ) -> None:
        """``bdpdqbp(p0, p1, dpsTime, dpsJson, fromCloud)`` (271-650).
        Java checks the **second** arg for empty and falls back to the
        first; every observed caller passes the same devId twice.
        ``decode_raw``/``check_receive`` are the DevUtil ports passed in
        by the caller."""
        import json

        effective = dev_id if not text_is_empty(dev_id) else sub_dev_id
        bean = self.cache.get_dev(effective)
        if bean is None:
            log.warning("Device does not exist.")
            return
        if bean.is_single_ble() and self._filter_single_ble(effective):
            log.info("filter singleBle mqtt dp . ")
            return
        product = bean.product_bean
        has_wifi = product.has_wifi() if product else False
        has_bt = product.has_bluetooth() if product else False
        has_cat1 = product.has_cat1() if product else False
        if has_bt and from_cloud and (has_cat1 or has_wifi) and self._filter_ble_preferred(bean):
            log.info("filter ble mqtt/lan dp . ")
            return
        dp_map = json.loads(dps_json) if dps_json else {}
        mutated = decode_raw(effective, dp_map)
        if not check_receive(effective, dp_map):
            log.warning("checkReceiveCommand error")
            return
        if dps_time and self.is_yu_online(effective):
            resp = self.cache.get_dev_resp_bean(effective)
            if resp is not None:
                cached_time = resp.get_dps_time() if resp.data_point_info else None
                cached_dps = resp.get_dps()
                if cached_time is not None and cached_dps is not None:
                    for dp, t in list(dps_time.items()):
                        if t is None or t <= 0:
                            continue
                        ct = cached_time.get(dp)
                        cv = cached_dps.get(dp)
                        if (
                            ct is not None
                            and ct > 0
                            and ct >= t
                            and cv is not None
                            and cv == dp_map.get(dp)
                        ):
                            log.warning("mqtt dpsTime is older than cache")
                            dp_map.pop(dp, None)
        if not dp_map:
            log.warning("dpMap is empty")
            return
        merged = self.merge_dps(effective, dp_map)
        self.merge_dps_time(effective, dps_time)
        if merged:
            log.debug("Cloud: %s dps: %s", from_cloud, dps_json)
            out_json = json.dumps(merged) if mutated else dps_json
            if self.on_dp_update is not None:
                self.on_dp_update(DpUpdateEvent(effective, out_json, from_cloud, dps_time))
