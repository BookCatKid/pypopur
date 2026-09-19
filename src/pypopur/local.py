"""Local Tuya LAN transport using a user-owned per-device local key.

Implemented on the ported SDK stack: ``DevTransfer`` (link keeper) →
``TransferModel`` (AIDL hop) → ``HardwareServiceProxy`` (``qpqbbpp``
facade) → ``ThingHardwareManager`` (``dpppdpq``) → ``LocalControlModel``
(``dddpppb``) → ``DeviceCommController`` (``qqdbbpp``), over the concrete
``SocketThingNetworkApi`` 0x55aa/0x6699 transport.

DP writes go through ``DeviceCommController.publish_dps_lan`` — the same
``{dps,devId,t}`` CONTROL payload the app assembles (lpv ≥ 3.4 adds the
``lpv‖0*4‖s‖o‖{protocol,data,t}`` inner wrap before session encryption).
DP reads go through ``LocalControlModel.query_dps`` — the app's LAN
``queryDps``, which sends ``{"gwId":devId,"devId":devId}`` under
``DP_QUERY`` via ``normalControl`` and waits for the device response
through ``ILocalDpMessageRespListener.onLocalDpReceivedSuccess``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any

from .codec import decode_raw_bytes
from .dps import normalize_dp_mapping
from .exceptions import (
    HandshakeError,
    MissingLocalKey,
    ProtocolError,
    TransportError,
)
from .sdk.device_cache import DeviceBean, DevListCacheManager
from .sdk.discovery import ActiveEnum, HgwBean
from .sdk.lan_control import (
    DeviceCommController,
    DevLocalControl,
    LocalControlModel,
    ResultCallback,
)
from .sdk.lan_session import (
    DevTransfer,
    HardwareServiceProxy,
    ThingHardwareManager,
    ThingNetworkInterface,
    TransferModel,
)
from .sdk.lan_socket import SocketThingNetworkApi, ThingNetworkApi
from .transport import PopurTransport


@dataclass(frozen=True, slots=True)
class LocalDeviceConfig:
    """Credentials and connection data for a device already owned by the user."""

    host: str
    device_id: str
    local_key: str
    protocol_version: str | None = None
    timeout: float = 5.0

    def __repr__(self) -> str:
        return (
            f"LocalDeviceConfig(host={self.host!r}, device_id={self.device_id!r}, "
            f"local_key=<redacted>, protocol_version={self.protocol_version!r}, "
            f"timeout={self.timeout!r})"
        )


class _MonitorStub:
    """Stand-in for ``GwBroadcastMonitorModel`` — the monitor-side half of
    ``qpqbbpp``. A standalone transport owns no UDP monitor; the
    registrations ``ThingHardwareManager.register`` performs are recorded
    so the call surface matches the app exactly."""

    def __init__(self) -> None:
        self.monitor_listeners: list = []
        self.config_listeners: list = []

    def add_monitor_listener(self, listener: Any) -> None:
        if listener is not None and listener not in self.monitor_listeners:
            self.monitor_listeners.append(listener)

    def remove_monitor_listener(self, listener: Any) -> None:
        if listener in self.monitor_listeners:
            self.monitor_listeners.remove(listener)

    def add_config_listener(self, listener: Any) -> None:
        if listener is not None and listener not in self.config_listeners:
            self.config_listeners.append(listener)

    def remove_dev(self, dev_id: str) -> None:
        pass


class _FutureCallback(ResultCallback):
    """``IResultCallback`` → ``threading.Event`` bridge."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.error: tuple[str, str | None] | None = None

    def on_error(self, code: str, msg: str | None) -> None:
        self.error = (code, msg)
        self.event.set()

    def on_success(self) -> None:
        self.event.set()


class _DpListener:
    """``ILocalDpMessageRespListener`` (``bpbbqdb``) — supplies lpv/localKey
    to the response parsers, merges every delivered DP body into the
    transport's ``_last_dps``, and completes pending ``read_dps`` waits."""

    def __init__(self, transport: LocalTuyaTransport) -> None:
        self._t = transport

    # --- parser inputs -----------------------------------------------------

    def get_lpv(self, dev_id: str) -> str:
        hgw = self._t._hgw
        if hgw is not None and hgw.version:
            return hgw.version
        return self._t._config.protocol_version or ""

    def get_local_key(self, dev_id: str) -> str:
        return self._t._config.local_key

    def is_data_updated(self, dev_id: str, s: int, o: int | None = None) -> bool:
        # ``bdbdqdp`` dedup — the transport merges idempotently, so no
        # frame is suppressed.
        return False

    # --- deliveries ---------------------------------------------------------

    def on_local_dp_received_success(self, dev_id: str, dps: Any, t: int) -> None:
        self._t._merge_dps(dps)
        self._t._complete_read(None)

    def on_local_dp_sub_device_received_success(
        self, dev_id: str, cid: str, ctype: int, dps: Any, t: int
    ) -> None:
        self._t._merge_dps(dps)
        self._t._complete_read(None)

    def on_local_dp_zigbee_group_received_success(self, dev_id: str, mbid: str, dps: Any) -> None:
        self._t._merge_dps(dps)

    def on_local_data_received(self, dev_id: str, protocol: int, obj: dict) -> None:
        # lpv ≥ 3.4 STATUS pushes arrive as ``{protocol,data:{dps},t}``;
        # a device may also answer DP_QUERY with a STATUS frame, so a
        # delivered body completes a pending read too.
        data = obj.get("data") if isinstance(obj, dict) else None
        if isinstance(data, dict) and "dps" in data:
            self._t._merge_dps(data["dps"])
            self._t._complete_read(None)

    def on_local_dp_received_error(self, dev_id: str, code: str, msg: str) -> None:
        self._t._complete_read(TransportError(f"Local DP read failed: {msg} ({code})"))


class LocalTuyaTransport(PopurTransport):
    """Async LAN transport over the ported Thing SDK stack.

    Popur app-v2 models use hexadecimal strings for the packed RAW datapoints, while the Thing
    SDK LAN path carries schema-RAW values Base64-encoded; ``write_dps`` performs that
    conversion so wire payloads match the official client.  This class never
    obtains a local key from Popur or Tuya cloud: callers must supply a legitimate
    key for their own device.

    ``protocol_version`` maps to ``HgwBean.version`` (the app's lpv — it
    comes from UDP discovery there, from the caller here).  When omitted,
    connect attempts ``AUTO_PROTOCOL_VERSIONS`` in order — the
    ``connect_device_with_key`` fallback defaults to 3.4 first, matching
    the SDK's own default.
    """

    AUTO_PROTOCOL_VERSIONS = ("3.4", "3.5", "3.5.1", "3.3")

    # Firmware-4 schema-RAW datapoints that the official SDK Base64-encodes before
    # LAN delivery. DP125 is also a packed model family member but is an integer
    # bitmask on the wire, so it is deliberately excluded.
    RAW_WIRE_DP_IDS = frozenset({101, 102, 103, 104, 105, 106})

    def __init__(
        self,
        host: str,
        device_id: str,
        local_key: str,
        *,
        protocol_version: str | None = None,
        timeout: float = 5.0,
        api: ThingNetworkApi | None = None,
        uid: str | None = None,
    ) -> None:
        if not host.strip():
            raise ValueError("host must not be empty")
        if not device_id.strip():
            raise ValueError("device_id must not be empty")
        if not local_key:
            raise MissingLocalKey("A per-device local key is required for LAN control")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._config = LocalDeviceConfig(host, device_id, local_key, protocol_version, timeout)
        self._uid = uid

        # --- SDK stack ------------------------------------------------------
        self._api = api if api is not None else SocketThingNetworkApi()
        self._iface = ThingNetworkInterface(self._api)
        if isinstance(self._api, SocketThingNetworkApi):
            self._api.connect_timeout = timeout
            self._api.attach(self._iface)
        self._transfer = DevTransfer(self._iface)
        self._transfer.on_create()
        # ``MSG_SERVICE_CONNECTED`` — asInterface → registerCallback →
        # connected; the model is NOT constructed with the service, or
        # ``register_callback`` would run twice.
        self._model = TransferModel()
        self._model.handle(TransferModel.MSG_SERVICE_CONNECTED, self._transfer)
        self._service = HardwareServiceProxy(self._model, _MonitorStub())
        self._hardware = ThingHardwareManager(self._service, self._iface)
        self._hardware.register()
        self._cache = DevListCacheManager()
        self._cache.use_new_cache = True
        self._control_model = LocalControlModel(
            self._cache,
            hardware_control=self._hardware.control,
            hardware_normal_control=self._hardware.normal_control,
            timestamp_fn=lambda: int(time.time()),
            uid=uid,
        )
        self._local_control = DevLocalControl(self._cache, self._control_model, uid=uid)
        self._controller = DeviceCommController(
            device_id,
            self._cache,
            self._local_control,
            encode_raw=self._encode_raw,
        )
        self._dp_listener = _DpListener(self)
        self._hardware.local_dp_listener = self._dp_listener
        self._api.set_device_address(device_id, host)

        self._hgw: HgwBean | None = None
        self._device: DeviceBean | None = None
        self._selected_protocol_version: str | None = None
        self._last_dps: dict[int, Any] = {}
        self._read_wait: threading.Event | None = None
        self._read_error: Exception | None = None
        self._lock = asyncio.Lock()

    @property
    def config(self) -> LocalDeviceConfig:
        return self._config

    @property
    def protocol_version(self) -> str | None:
        """The explicit or successfully negotiated local protocol version."""

        return self._selected_protocol_version

    @property
    def connected(self) -> bool:
        """Live session — the gw must still be in ``DevTransfer.live_gw``;
        a link that died (or was evicted) requires re-handshake."""

        return (
            self._device is not None
            and self._config.device_id in self._transfer.live_gw
        )

    @property
    def transfer(self) -> DevTransfer:
        """The live ``DevTransfer`` — exposes ``live_gw``/``connecting_gw``."""

        return self._transfer

    def _encode_raw(self, dev_id: str, dps_json: str, m: dict) -> Any:
        """``DevUtil.encodeRaw`` — Base64 for schema-RAW datapoints.

        The standalone transport has no product schema; the S7's firmware-4
        packed RAW DPs are the known schema-RAW members."""
        for dp in self.RAW_WIRE_DP_IDS:
            key = str(dp)
            if key not in m:
                continue
            raw = decode_raw_bytes(m[key], allow_base64=True)
            if raw is None:
                continue
            m[key] = base64.b64encode(raw).decode("ascii")
        return m

    # --- DP bookkeeping ------------------------------------------------------

    def _merge_dps(self, dps: Any) -> None:
        if dps is None:
            return
        if isinstance(dps, str):
            try:
                dps = json.loads(dps)
            except ValueError:
                return
        if not isinstance(dps, Mapping):
            return
        self._last_dps.update(normalize_dp_mapping(dps))

    def _complete_read(self, error: Exception | None) -> None:
        event = self._read_wait
        if event is not None:
            self._read_error = error
            event.set()

    # --- lifecycle -----------------------------------------------------------

    def _connect_once(self, version: str) -> None:
        """``addHgw`` + handshake wait — returns when the gw is in
        ``live_gw`` or raises on failure/timeout."""
        dev_id = self._config.device_id
        hgw = HgwBean(
            gw_id=dev_id,
            ip=self._config.host,
            version=version,
            active=ActiveEnum.ACTIVED,
            encrypt=True,
        )
        self._api.set_device_address(dev_id, self._config.host)
        bean = DeviceBean()
        bean.dev_id = dev_id
        bean.local_key = self._config.local_key
        bean.hgw_bean = hgw
        bean.is_local_online = True
        self._cache.dev_bean_map[dev_id] = bean
        self._hardware.put_hgw_bean(dev_id, hgw)
        self._transfer.add_dev(hgw, self._config.local_key, 0)

        deadline = time.monotonic() + self._config.timeout
        while time.monotonic() < deadline:
            if dev_id in self._transfer.live_gw:
                self._hgw = hgw
                self._device = bean
                self._selected_protocol_version = version
                return
            if dev_id not in self._transfer.connecting_gw:
                # Connecting entry cleared without reaching live_gw —
                # connect or handshake failed.
                self._teardown_probe(dev_id)
                raise HandshakeError(
                    "Device rejected the local handshake (local key or protocol version)"
                )
            time.sleep(0.005)
        self._teardown_probe(dev_id)
        raise TransportError(f"Local handshake timed out for protocol {version}")

    def _teardown_probe(self, dev_id: str) -> None:
        """Fully clear a failed probe so the next version starts clean —
        the S7 allows a single LAN session, so a lingering socket/link
        would reject the follow-up handshake. ``deleteDev`` only acts on
        live gws, so the connecting entry is popped explicitly."""

        self._api.close_device(dev_id)
        self._hardware.remove_hgw_bean(dev_id)
        self._transfer.delete_dev(dev_id)
        self._transfer.connecting_gw.pop(dev_id, None)
        self._cache.dev_bean_map.pop(dev_id, None)

    async def connect(self) -> None:
        async with self._lock:
            if self._device is not None:
                if self._config.device_id in self._transfer.live_gw:
                    return
                # Gw evicted — the socket died or a stale callback removed
                # it; clear and re-handshake instead of failing forever.
                self._device = None
                self._hgw = None
            if self._config.protocol_version is not None:
                versions = (self._config.protocol_version,)
            elif self._selected_protocol_version is not None:
                # Reconnect: try the previously negotiated version first.
                versions = (self._selected_protocol_version,) + tuple(
                    v for v in self.AUTO_PROTOCOL_VERSIONS
                    if v != self._selected_protocol_version
                )
            else:
                versions = self.AUTO_PROTOCOL_VERSIONS
            failures: list[tuple[str, Exception]] = []
            for attempt, version in enumerate(versions):
                if attempt:
                    # The device can still be tearing down the previous
                    # session; give it a beat or the next SYN is refused.
                    await asyncio.sleep(0.4)
                try:
                    await asyncio.to_thread(self._connect_once, version)
                except (
                    TransportError,
                    ProtocolError,
                    HandshakeError,
                    OSError,
                    RuntimeError,
                ) as err:
                    failures.append((version, err))
                    continue
                return
            if len(failures) == 1:
                raise failures[0][1]
            details = "; ".join(f"pv {version}: {error}" for version, error in failures)
            if failures and all(isinstance(error, HandshakeError) for _, error in failures):
                raise HandshakeError(
                    "Local handshake failed for all supported probe versions; the APK does not "
                    "provide enough evidence to distinguish a wrong local key from an unsupported "
                    f"protocol version ({details})"
                )
            raise TransportError(f"Unable to connect to local device ({details})")

    async def close(self) -> None:
        async with self._lock:
            dev_id = self._config.device_id
            self._device = None
            self._hgw = None
            self._selected_protocol_version = None
            await asyncio.to_thread(self._teardown_probe, dev_id)

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        await self.connect()
        async with self._lock:
            if self._device is None:  # pragma: no cover - defensive invariant guard
                raise TransportError("Local transport is not connected")
            wait = threading.Event()
            self._read_wait = wait
            self._read_error = None
            send = _FutureCallback()
            try:
                self._control_model.query_dps(self._config.device_id, "", send)
                if not send.event.wait(self._config.timeout):
                    raise TransportError("Local DP query send timed out")
                if send.error is not None:
                    code, msg = send.error
                    raise TransportError(f"Local DP query failed: {msg or ''} ({code})")
                if not wait.wait(self._config.timeout):
                    raise TransportError("Local DP query response timed out")
                if self._read_error is not None:
                    raise self._read_error
            finally:
                self._read_wait = None
                self._read_error = None
            merged = dict(self._last_dps)
            if ids is None:
                return merged
            requested = set(ids)
            return {dp: value for dp, value in merged.items() if dp in requested}

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        if not values:
            return
        wire_values = {str(int(dp)): value for dp, value in values.items()}
        # Reject undecodable packed payloads before any network I/O; the
        # Base64 conversion itself happens in ``_encode_raw``.
        for dp, value in values.items():
            if int(dp) not in self.RAW_WIRE_DP_IDS:
                continue
            if decode_raw_bytes(value, allow_base64=True) is None:
                raise ProtocolError(f"Invalid raw byte payload for DP{int(dp)}")
        await self.connect()
        async with self._lock:
            if self._device is None:  # pragma: no cover - defensive invariant guard
                raise TransportError("Local transport is not connected")
            send = _FutureCallback()
            self._controller.publish_dps_lan(json.dumps(wire_values), send)
            if not send.event.wait(self._config.timeout):
                raise TransportError("Local DPS write timed out")
            if send.error is not None:
                code, msg = send.error
                raise TransportError(f"Local DPS write failed: {msg or ''} ({code})")
            self._last_dps.update({int(dp): value for dp, value in values.items()})
