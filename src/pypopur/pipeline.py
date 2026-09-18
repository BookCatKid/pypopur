"""LAN-first comm-pipeline transport — ``AbsThingDevice.publishDps``.

Composes a :class:`LocalTuyaTransport` and/or a
:class:`CloudChannelBackend` into the app's channel router:
``publishDps`` → ``publishDpsInPipeline`` → per-mode
``CommHandler`` chain (LAN with the 500 ms watchdog → MQTT/HTTP via
``controlByServer`` / ``sendDpsByApi``).

Mirrors ``UnifiedDeviceControlHelper.sendDeviceCommand`` →
``ThingDevice.getDeviceInstance().publishDps`` →
``DeviceRepository.on_command_sent`` on success.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Collection, Mapping
from typing import Any

from .exceptions import ProtocolError, TransportError
from .sdk._fastjson import to_json_string
from .sdk.comm_pipeline import DevModel, ThingDevicePresenter
from .sdk.device_cache import (
    CommunicationEnum,
    CommunicationModule,
    CommunicationModuleT,
    DeviceBean,
    DeviceRespBean,
    DevListCacheManager,
)
from .sdk.lan_control import (
    DevCloudControl,
    DeviceCommController,
    DevLocalControl,
    LanGate,
    LocalControlModel,
    ResultCallback,
)
from .sdk.low_power import (
    LowPowerDeviceManager,
    MqttServerAdapter,
    TimerHandler,
    low_power_check_awake,
)
from .transport import PopurTransport

__all__ = ["PipelineTransport"]


class PipelineTransport(PopurTransport):
    """Channel-routing transport — the app's ``publishDps`` surface.

    Parameters
    ----------
    dev_id:
        Device ID every channel addresses.
    local:
        A :class:`LocalTuyaTransport` (or compatible object exposing
        ``_cache``/``_local_control``/``_transfer``/``_device``) — the
        LAN channel.
    cloud:
        A :class:`CloudChannelBackend`-compatible object — the
        MQTT/HTTP channel (exposes ``_cloud``/``_device_api``/
        ``_server_available`` and the send seams).
    communication_modes:
        ``communicationModes`` entries for the resp bean — ordered
        ``CommunicationEnum`` values (default ``[LAN, MQTT, HTTP]``).
    device_bean:
        ``DeviceBean`` override stored in the shared cache (online
        state, ``pv``, ``communicationId``, ``productBean``, …).
    repository:
        ``DeviceRepository`` — ``on_command_sent`` fires on successful
        writes (the app's post-command DP cache update).
    schema_fn:
        ``bpbqqdq.getSchema(devId)`` — product schema lookup for
        ``checkSendCommond``; defaults to the cache's
        ``DeviceDataManager`` lookup (a missing schema fails sends
        with ``11001``, as in the app).
    is_network_available:
        ``qdqdbpp``-equivalent network-up predicate.
    low_power_manager:
        ``bdqqqbp`` — the ``MqttCommHandler`` awake seam
        (``bpbqqdq.bdpdqbp(devId, 8000, cb)``). Auto-constructed from
        ``cloud``'s MQTT client + ``device_api.business`` when not
        given; pass ``False`` to leave the default no-op awake seam.
    """

    DEFAULT_MODES = (
        CommunicationEnum.LAN,
        CommunicationEnum.MQTT,
        CommunicationEnum.HTTP,
    )

    def __init__(
        self,
        dev_id: str,
        *,
        local: Any = None,
        cloud: Any = None,
        communication_modes: Collection[int] | None = None,
        device_bean: DeviceBean | None = None,
        repository: Any = None,
        schema_fn: Callable[[str], Any] | None = None,
        is_network_available: Callable[[], bool] | None = None,
        low_power_manager: Any = None,
        uid: str | None = None,
    ) -> None:
        self.dev_id = dev_id
        self.local = local
        self.cloud = cloud
        self.repository = repository
        self._net = is_network_available or (lambda: True)

        cache = (
            local._cache
            if local is not None
            else cloud._cache
            if cloud is not None
            else DevListCacheManager()
        )
        cache.use_new_cache = True
        self._cache = cache

        if device_bean is not None:
            bean = device_bean
        elif local is not None and local._device is not None:
            bean = local._device
        else:
            bean = DeviceBean()
            bean.dev_id = dev_id
            if local is not None:
                bean.local_key = local._config.local_key
        if cloud is not None and cloud._cache is not cache:
            cloud_bean = cloud._cache.get_dev(dev_id)
            if cloud_bean is not None:
                for field in (
                    "is_online",
                    "pv",
                    "communication_id",
                    "product_bean",
                    "product_id",
                    "local_key",
                    "dev_resp_bean",
                ):
                    value = getattr(cloud_bean, field, None)
                    if value is not None and getattr(bean, field, None) is None:
                        setattr(bean, field, value)
        cache.dev_bean_map[dev_id] = bean
        self._bean = bean

        if local is not None:
            local_control = local._local_control
        else:
            local_control = DevLocalControl(cache, LocalControlModel(cache, uid=uid), uid=uid)
        if cloud is not None:
            cloud_control = DevCloudControl(
                cache,
                publish_device=cloud._cloud.publish_device,
                atop_publish=cloud._cloud.atop_publish,
            )
        else:
            cloud_control = DevCloudControl(cache)
        self._controller = DeviceCommController(dev_id, cache, local_control, cloud=cloud_control)
        self._gate = LanGate(
            cache,
            hgw_provider=self._hgw_for,
            is_network_available=self._net,
        )
        self._model = DevModel(
            dev_id,
            self._controller,
            cache,
            self._gate,
            atop_send=self._atop_send,
            mqtt_up=(cloud._server_available if cloud is not None else (lambda: False)),
            schema_fn=schema_fn,
        )
        self._model.send_seams.update(self._send_seams())
        self._presenter = ThingDevicePresenter(dev_id, self._model, cache)
        # THING_MODEL link seams — ``IMqttServer.publishLinkWithTopic``
        # over the wire client and the ``qdddbpp`` model fetch.
        _link_client = getattr(cloud, "_client", None) if cloud is not None else None
        if _link_client is not None:
            from .sdk.thing_model import LinkMqttServerAdapter

            self._model.link_mqtt_server = LinkMqttServerAdapter(_link_client)
        self._presenter.thing_model_fetch = self._thing_model_fetch
        self._low_power = (
            self._build_low_power() if low_power_manager is None else low_power_manager
        )
        if self._low_power:
            self._presenter._awake_fn = self._low_power.awake

        resp = cache.dev_map.get(dev_id)
        if resp is None:
            resp = DeviceRespBean()
            resp.dev_id = dev_id
        comm = resp.communication or CommunicationModule()
        if comm.communication_node is None:
            # Standalone device — the app's cloud response reports
            # ``communicationNode == devId`` (``get_comm_and_node``
            # then forces ``nodeId = ""``).
            comm.communication_node = dev_id
        comm.communication_modes = [
            CommunicationModuleT(t) for t in (communication_modes or self.DEFAULT_MODES)
        ]
        resp.communication = comm
        cache.dev_map[dev_id] = resp
        bean.dev_resp_bean = resp

    # -- seams -----------------------------------------------------------------

    def _hgw_for(self, comm_id: str) -> Any:
        """``qpbpqpq`` hgw lookup — a live ``DevTransfer`` gw entry."""
        if self.local is None:
            return None
        return self.local._transfer.live_gw.get(comm_id)

    def _cloud_device_api(self) -> Any:
        cloud = self.cloud
        if cloud is None:
            return None
        return getattr(cloud, "device_api", None) or getattr(cloud, "_device_api", None)

    def _build_low_power(self) -> LowPowerDeviceManager | None:
        """``bdqqqbp`` wiring — needs an ``IMqttServer`` (the MQTT wire
        client) and the ``qdddbpp`` Business call; missing pieces degrade
        exactly like the app's absent plugin (``send_awake`` no-ops,
        ``check_awake`` raises → ``UNSUPPORT``)."""
        cloud = self.cloud
        if cloud is None:
            return None
        client = getattr(cloud, "_client", None)
        api = self._cloud_device_api()
        business = getattr(api, "business", None) if api is not None else None
        return LowPowerDeviceManager(
            dev_cache=self._cache,
            mqtt_server=MqttServerAdapter(client) if client is not None else None,
            check_awake=(low_power_check_awake(business) if business is not None else None),
            handler=TimerHandler(),
        )

    def _send_seams(self) -> dict:
        cloud = self.cloud
        return {
            "is_network_available": self._net,
            "server_available": (cloud._server_available if cloud is not None else (lambda: False)),
            "is_lan_online": (
                cloud._is_lan_online
                if cloud is not None
                else (lambda dev, ch: self._gate.is_intranet_control(dev))
            ),
            "is_mqtt_subscribed": (
                cloud._is_mqtt_subscribed if cloud is not None else (lambda dev: False)
            ),
            "subscribe_in": (cloud._subscribe_in if cloud is not None else (lambda dev: None)),
            "mqtt_send": (cloud._mqtt_send if cloud is not None else (lambda *a: None)),
            "http_publish": (cloud._http_publish if cloud is not None else (lambda *a: None)),
            "query_dev": ((cloud._query_dev if cloud is not None else None) or (lambda dev: None)),
            "scheduler": (
                (cloud._scheduler if cloud is not None else None)
                or (lambda delay, fn: threading.Timer(delay, fn).start())
            ),
        }

    def _atop_send(
        self,
        api_name: str,
        version: str,
        post_data: dict,
        cb: ResultCallback | None,
    ) -> None:
        """``dbppbbp`` — generic ATOP request for the by-API send paths."""
        api = self._cloud_device_api()
        business = getattr(api, "business", None) if api is not None else None
        if business is None:
            if cb is not None:
                cb.on_error("11005", "no communication channel")
            return
        params = business.new_api_params(api_name, version)
        for key, value in post_data.items():
            params.put_post_data(key, value)
        result = business.request(params)
        if cb is None:
            return
        if result.succeeded:
            cb.on_success()
        else:
            resp = result.response
            cb.on_error(
                (resp.error_code if resp is not None else None) or "0",
                resp.error_msg if resp is not None else None,
            )

    def _thing_model_fetch(
        self, api_name: str, version: str, post_data: dict, listener: Any
    ) -> None:
        """``Business.asyncRequest`` seam for ``qdddbpp.pdqppqb`` —
        forwards the raw result to ``listener.on_success`` (the
        ``thing_model`` port parses it into ``ThingSmartThingModel``)."""
        api = self._cloud_device_api()
        business = getattr(api, "business", None) if api is not None else None
        if business is None:
            listener.on_error("11005", "no communication channel")
            return
        params = business.new_api_params(api_name, version)
        for key, value in post_data.items():
            params.put_post_data(key, value)
        result = business.request(params)
        if result.succeeded:
            listener.on_success(result.data)
        else:
            resp = result.response
            listener.on_error(
                (resp.error_code if resp is not None else None) or "0",
                resp.error_msg if resp is not None else None,
            )

    # -- PopurTransport ---------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._gate.is_intranet_control(self.dev_id) or (self.cloud is not None)

    @property
    def presenter(self) -> ThingDevicePresenter:
        """The ``AbsThingDevice`` presenter — ``publish_dps``/``publish_dps_mode``."""

        return self._presenter

    @property
    def low_power_manager(self) -> Any:
        """``bdqqqbp`` — the low-power awake manager bound to the
        pipeline's ``MqttCommHandler`` seam (``None`` when disabled)."""

        return self._low_power

    async def connect(self) -> None:
        if self.local is not None:
            try:
                await self.local.connect()
            except Exception:
                if self.cloud is None:
                    raise
        if self.cloud is not None:
            await self.cloud.connect()

    async def close(self) -> None:
        if self.local is not None:
            await self.local.close()
        if self.cloud is not None:
            await self.cloud.close()
        if self._low_power is not None:
            # ``bdpdqbp(Z)`` destroy — clears wake tasks + registries.
            self._low_power.release(True)

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        """LAN ``queryDps`` when intranet-controllable, else the cloud read."""
        if self.local is not None and self._gate.is_intranet_control(self.dev_id):
            return await self.local.read_dps(ids)
        if self.cloud is not None:
            return await self.cloud.read_dps(ids)
        raise TransportError("No communication channel is available")

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        dps_map = {str(dp): value for dp, value in values.items()}
        dps_json = to_json_string(dps_map, write_nulls=True)
        done = threading.Event()
        error: list[tuple[str, str | None]] = []

        class _Cb(ResultCallback):
            def on_error(self_, code: str, msg: str | None) -> None:
                error.append((code, msg))
                done.set()

            def on_success(self_) -> None:
                done.set()

        def _send() -> None:
            self._presenter.publish_dps(dps_json, _Cb())

        await asyncio.to_thread(_send)
        await asyncio.to_thread(done.wait)
        if error:
            code, msg = error[0]
            raise ProtocolError(msg or f"publish_dps failed: {code}")
        if self.repository is not None:
            self.repository.on_command_sent(self.dev_id, dps_map)
