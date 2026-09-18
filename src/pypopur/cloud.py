"""Cloud datapoint transport and ATOP wiring.

Account bootstrap is implemented in :mod:`pypopur.mobile`
(:class:`ThingMobileApi`). This module adapts that identity material into
the SDK-faithful ``Business``/``DeviceApi`` layer (:mod:`pypopur.sdk.atop`)
so the ported dispatch pipeline can publish/read datapoints exactly like
``dbppbbp`` does inside the Android app.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Collection, Mapping
from typing import Any, Protocol

from .exceptions import ProtocolError, UnsupportedCloudAuthentication
from .sdk.atop import (
    Business,
    BusinessResult,
    DeviceApi,
    NetworkStatics,
)
from .sdk.security import ThingApiSignManager, ThingNetworkSecurity
from .transport import PopurTransport

HttpPoster = Callable[
    [str, Mapping[str, str], Mapping[str, str]],
    "tuple[int, str | None, list[tuple[str, str]]]",
]
"""``Business.http_post`` seam: ``(url, headers, form_body) ->
(status, body_text, response_headers)``; ``body_text`` may be ``None``."""


def _stdlib_http_post(
    url: str, headers: Mapping[str, str], body: Mapping[str, str], timeout: float
) -> tuple[int, str | None, list[tuple[str, str]]]:
    """Default POST using the same Java-form-encoding rules as
    :func:`pypopur.mobile._stdlib_post_form_sync`."""

    import urllib.error
    import urllib.parse
    import urllib.request

    def _encode_component(value: str) -> str:
        return urllib.parse.quote(value, safe="-_.*").replace("~", "%7E")

    encoded = "&".join(
        f"{_encode_component(str(key))}={_encode_component(str(value))}"
        for key, value in body.items()
    ).encode()
    request = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            **dict(headers),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (
                response.status,
                response.read().decode("utf-8", errors="replace"),
                list(response.headers.items()),
            )
    except urllib.error.HTTPError as err:
        return (
            err.code,
            err.read().decode("utf-8", errors="replace"),
            list(err.headers.items()) if err.headers else [],
        )


class _ProfileHostProvider:
    """``ApiUrlProvider`` pinned to the profile's ``api_host`` (which may
    have already absorbed a post-login regional handoff)."""

    def __init__(self, api_host: str) -> None:
        self._host = api_host.rstrip("/")

    def get_api_url(self) -> str:
        return self._host

    def get_api_url_by_country_code(self, code: str) -> str:
        return self._host


class _SessionAdapter:
    """``atop.UserSession`` over :class:`pypopur.mobile.MobileSession`."""

    def __init__(self, session: Any) -> None:
        self._session = session

    def get_sid(self) -> str | None:
        return self._session.sid

    def get_ecode(self) -> str | None:
        return self._session.ecode


def build_business(
    profile: Any,
    session: Any | None = None,
    *,
    device_id: str,
    http_post: HttpPoster | None = None,
    timeout: float = 10.0,
    signer: ThingApiSignManager | None = None,
    on_session_invalid: Callable[[Any], None] | None = None,
) -> Business:
    """Construct a ``Business`` (``dbppbbp`` transport) from a
    :class:`pypopur.mobile.MobileAppProfile` + ``MobileSession``.

    ``profile.encryption_secret`` is the resolved GLOBAL_S master; it feeds
    both ``ThingNetworkSecurity`` (``getEncryptoKey``) and the cmd-1 signer
    key material.
    """

    net = NetworkStatics(
        app_id=profile.client_id,
        app_secret=profile.encryption_secret,
        app_version=profile.app_version,
        sdk_version=profile.sdk_version,
        device_core_version=profile.device_core_version or "",
        ttid=profile.ttid,
        lang=profile.lang,
        os_system=profile.os_system or "",
        platform=profile.platform or "",
        time_zone_id=profile.time_zone_id or "",
        ch_key=profile.ch_key,
        device_id=device_id,
        api_url_provider=_ProfileHostProvider(profile.api_host),
        channel=profile.channel,
        common_params={**profile.biz_data, **profile.extra_params},
        user=_SessionAdapter(session) if session is not None else None,
        sdk_int="" if profile.sdk_int is None else str(profile.sdk_int),
        brand=profile.brand or "",
        neutral_domain_switch=profile.neutral_domain,
    )

    def _post(url: str, headers: Mapping[str, str], body: Mapping[str, str]):
        if http_post is not None:
            return http_post(url, headers, body)
        return _stdlib_http_post(url, headers, body, timeout)

    return Business(
        net,
        security=ThingNetworkSecurity(profile.encryption_secret),
        http_post=_post,
        signer=signer,
        on_session_invalid=on_session_invalid,
    )


def build_device_api(
    profile: Any,
    session: Any | None = None,
    **kwargs: Any,
) -> DeviceApi:
    """``dbppbbp`` — a ``DeviceApi`` bound to a profile-built ``Business``."""

    return DeviceApi(build_business(profile, session, **kwargs))


class AtopCloudBackend:
    """``CloudBackend`` over ``DeviceApi``: cloud-side DP publish/read via
    ``thing.m.device.dp.publish`` / ``s.m.dev.dp.get``.

    This is the HTTP leg of the app's ``DevCloudControl`` path — the MQTT
    leg and LAN preference live in :mod:`pypopur.sdk.comm_pipeline`.
    """

    def __init__(
        self,
        device_api: DeviceApi,
        *,
        dev_id: str,
        gw_id: str | None = None,
    ) -> None:
        self.device_api = device_api
        self.dev_id = dev_id
        self.gw_id = gw_id or dev_id

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        result = await asyncio.to_thread(self.device_api.get_dps_v1, self.gw_id, self.dev_id)
        return _dp_result_to_map(result, ids)

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        from .sdk._fastjson import to_json_string

        dps = to_json_string({str(k): v for k, v in values.items()})
        result = await asyncio.to_thread(self.device_api.publish_dps, self.dev_id, self.gw_id, dps)
        if not result.succeeded:
            resp = result.response
            raise ProtocolError(
                f"cloud dp publish failed: "
                f"{resp.error_code if resp else '?'} "
                f"{resp.error_msg if resp else ''}".strip()
            )


def _dp_result_to_map(result: BusinessResult, ids: Collection[int] | None) -> Mapping[int, Any]:
    """Normalize ``s.m.dev.dp.get`` ``result`` to ``{dpId: value}``.

    v1 (``DpResp``) carries ``dps`` as a JSON string; v2 (``DpBean[]``)
    carries ``[{dpId, name, value}]`` entries.
    """

    if not result.succeeded:
        resp = result.response
        raise ProtocolError(
            f"cloud dp read failed: "
            f"{resp.error_code if resp else '?'} "
            f"{resp.error_msg if resp else ''}".strip()
        )
    import json

    data = result.data
    out: dict[int, Any] = {}
    if isinstance(data, Mapping):
        dps = data.get("dps")
        if isinstance(dps, str):
            try:
                dps = json.loads(dps)
            except ValueError:
                dps = None
        if isinstance(dps, Mapping):
            for key, value in dps.items():
                out[int(key)] = value
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, Mapping) and "dpId" in entry:
                out[int(entry["dpId"])] = entry.get("value")
    if ids is not None:
        wanted = {int(i) for i in ids}
        out = {k: v for k, v in out.items() if k in wanted}
    return out


class CloudChannelBackend:
    """Cloud DP transport via ``qqdbbpp.send_internet`` — the app's real
    channel router:

    - MQTT down + network up → HTTP ``thing.m.device.dp.publish``
      immediately;
    - MQTT up + ``dev.isOnline`` → optional ``smart/mb/in/{id}``
      subscribe, then MQTT send wrapped in ``$qddqppb`` (error → HTTP
      backup);
    - MQTT up + device offline → ``10203``.

    ``mqtt_manager``/``mqtt_client`` come from
    :mod:`pypopur.sdk.mqtt_session` / :mod:`pypopur.sdk.mqtt_client`;
    without them every send degrades to HTTP exactly like the app does
    when ``isRealConnect`` is false.
    """

    def __init__(
        self,
        device_api: DeviceApi,
        *,
        dev_id: str,
        device_bean: Any,
        mqtt_manager: Any = None,
        mqtt_client: Any = None,
        gw_id: str | None = None,
        uid: str | None = None,
        is_network_available: Callable[[], bool] | None = None,
        is_lan_online: Callable[[Any, int], bool] | None = None,
        query_dev: Callable[[str], None] | None = None,
        scheduler: Callable[[float, Callable[[], None]], Any] | None = None,
        cache: Any = None,
    ) -> None:
        from .sdk.device_cache import DevListCacheManager
        from .sdk.lan_control import (
            DevCloudControl,
            DeviceCommController,
            DevLocalControl,
            LocalControlModel,
        )
        from .sdk.mqtt_session import SMART_MB_IN_PREFIX

        self.device_api = device_api
        self.dev_id = dev_id
        self.gw_id = gw_id or dev_id
        self._manager = mqtt_manager
        self._client = mqtt_client
        self._net = is_network_available or (lambda: True)
        self._is_lan_online = is_lan_online or (lambda dev, ch: False)
        self._query_dev = query_dev
        self._scheduler = scheduler
        self._in_prefix = SMART_MB_IN_PREFIX

        self._cache = cache or DevListCacheManager()
        self._cache.use_new_cache = True
        self._cache.dev_bean_map[dev_id] = device_bean
        self._cloud = DevCloudControl(
            self._cache,
            publish_device=(mqtt_manager.publish_device if mqtt_manager is not None else None),
            atop_publish=device_api.atop_publish,
        )
        model = LocalControlModel(self._cache, uid=uid)
        local_control = DevLocalControl(self._cache, model, uid=uid)
        self._controller = DeviceCommController(
            dev_id, self._cache, local_control, cloud=self._cloud
        )

    # --- send_internet seams -------------------------------------------

    def _server_available(self) -> bool:
        """``bpbqqdq.pdqppqb()`` → ``IMqttServer.isRealConnect`` — the
        manager's session flag (``MqttWireClient`` binds it to the wire
        connected state, with the lazy-reconnect side effect)."""
        fn = (
            self._manager.is_real_connect
            if self._manager is not None
            else (self._client.is_real_connect if self._client is not None else None)
        )
        return bool(fn and fn())

    def _is_mqtt_subscribed(self, dev_id: str) -> bool:
        """``DevControllerEventAnalysis.isSubscribe`` — sub-devices behind
        a gateway (``communicationId != devId``) count as subscribed;
        standalone devices consult ``smart/mb/in/{id}``."""
        if dev_id:
            dev = self._cache.get_dev(dev_id)
            if dev is not None:
                comm = dev.communication_id
                if comm and comm != dev.dev_id:
                    return True
        if self._manager is None:
            return False
        return self._manager.is_subscribe(self._in_prefix + dev_id)

    def _subscribe_in(self, dev_id: str) -> None:
        """``IMqttServer.subscribe("smart/mb/in/"+devId, null)``."""
        if self._client is not None:
            self._client.subscribe([self._in_prefix + dev_id], [1], None)

    def _mqtt_send(
        self,
        dev_id: str,
        inner_map: dict,
        node_id: Any,
        ctype: int,
        log_key: str,
        sand_o: Any,
        cb: Any,
    ) -> None:
        """inner ``qqdbbpp.bdpdqbp(devId, map, nodeId, type, logKey,
        sandO, cb)`` → ``dqdpbbd`` MQTT payload + ``publishDevice``."""
        dev = self._cache.get_dev(dev_id)
        self._cloud._mqtt_send(dev_id, inner_map, dev, node_id, ctype, log_key, sand_o, cb)

    def _http_publish(self, gw_id: str, dev_id: str, dps_json: str, cb: Any) -> None:
        """``sendByHttp`` → ATOP ``thing.m.device.dp.publish``."""
        self._cloud._http_send(gw_id, dev_id, dps_json, cb)

    # --- CloudBackend surface ------------------------------------------

    async def connect(self) -> None:
        if self._client is not None:
            await asyncio.to_thread(self._client.connect)

    async def close(self) -> None:
        if self._client is not None:
            await asyncio.to_thread(self._client.close)

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        """``getDpList`` — ``s.m.dev.dp.get`` v1 (HTTP)."""
        result = await asyncio.to_thread(self.device_api.get_dps_v1, self.gw_id, self.dev_id)
        return _dp_result_to_map(result, ids)

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        from .sdk._fastjson import to_json_string
        from .sdk.lan_control import ResultCallback

        dps = to_json_string({str(k): v for k, v in values.items()})
        event = asyncio.Event()
        box: list = []

        class _Cb(ResultCallback):
            def on_error(self, code: str, msg) -> None:
                box.append((code, msg))
                event.set()

            def on_success(self) -> None:
                event.set()

        await asyncio.to_thread(
            self._controller.send,
            dps,
            _Cb(),
            is_network_available=self._net,
            server_available=self._server_available,
            is_lan_online=self._is_lan_online,
            is_mqtt_subscribed=self._is_mqtt_subscribed,
            subscribe_in=self._subscribe_in,
            mqtt_send=self._mqtt_send,
            http_publish=self._http_publish,
            query_dev=self._query_dev,
            scheduler=self._scheduler,
        )
        await event.wait()
        if box:
            code, msg = box[0]
            raise ProtocolError(f"cloud dp publish failed: {code} {msg or ''}".strip())


class CloudBackend(Protocol):
    """Interface for a future independently authenticated cloud backend."""

    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]: ...
    async def write_dps(self, values: Mapping[int, Any]) -> None: ...


class CloudTransport(PopurTransport):
    """Delegate to an externally supplied, safely authenticated cloud backend."""

    def __init__(self, backend: CloudBackend) -> None:
        self._backend = backend

    @classmethod
    def login(cls, *args: Any, **kwargs: Any) -> CloudTransport:
        del args, kwargs
        raise UnsupportedCloudAuthentication(
            "CloudTransport does not perform account bootstrap. Use PopurAccount or "
            "bootstrap_discovered_s7 with a MobileAppProfile, then create a local client."
        )

    async def connect(self) -> None:
        await self._backend.connect()

    async def close(self) -> None:
        await self._backend.close()

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        return await self._backend.read_dps(ids)

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        await self._backend.write_dps(values)
