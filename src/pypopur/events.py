"""Real-time device events over the app's MQTT push channel.

The app never polls for live state: after login it opens an SSL MQTT
session to ``domain.mobileMqttsUrl`` and receives every DP report,
device-online change and cloud push on ``smart/mb/in/{devId}`` (plus
user-level traffic on ``{partnerIdentity}/mb/{uid}``). This module
rebuilds that channel end-to-end:

- ``getMqttConfigInfo`` → :class:`MqttConnectConfig` (``token`` = sid,
  ``appTag`` = ``"os"``, uid/ecode/partnerIdentity from the session)
- ``qpqbppd`` credentials → :class:`SdkMqttCredentials` — username
  ``partnerIdentity + "_v1_" + appId + "_" + chKey + "_mb_" + sid +
  md5hex(md5hex(appId)+ecode)[-16:]`` and password = ``doCommandNative``
  cmd 2's nested-MD5 seed, centered 16 chars — both emulation-verified
- ``bqbppdq`` session shell → :class:`MqttServerManager` +
  :class:`MqttWireClient` (TLS, ping/reconnect, SUB bookkeeping)
- ``qqpqqpq`` listener semantics → :class:`DeviceEventListener`:
  ``getLocalKey`` strips ``smart/mb/in|out/`` → devId lookup,
  ``isDataUpdated`` strips ``smart/mb/in/``|``m/dg/`` →
  ``ThingMessageCache.is_data_updated_so``, ``getTopicSuffix`` =
  ``["smart/mb/in/", "m/dg/", user_topic]``.

Inbound frames run through ``qbqddpp`` dispatch
(:func:`dispatch_inbound_message`): JSON ``smart/mb/in/`` envelopes get
the pv-2.0 signed/AES path, binary payloads get the pv 1.1–2.3 decoders,
all deduplicated exactly like the app before reaching ``on_event``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .sdk.dedup import ThingMessageCache
from .sdk.mqtt_client import MqttWireClient
from .sdk.mqtt_session import (
    MqttConfigBean,
    MqttConnectConfig,
    MqttServerManager,
    SdkMqttCredentials,
    init_mqtt_config,
)
from .sdk.security import default_cmd2

log = logging.getLogger(__name__)

SMART_MB_IN = "smart/mb/in/"
SMART_MB_OUT = "smart/mb/out/"
M_DG_PREFIX = "m/dg/"


def _dev_id_from_topic(topic: str) -> str:
    """``qqpqqpq`` prefix strip — ``smart/mb/in|out/`` then ``m/dg/``."""

    for prefix in (SMART_MB_IN, SMART_MB_OUT, M_DG_PREFIX):
        if topic.startswith(prefix):
            return topic[len(prefix) :]
    return topic


@dataclass(frozen=True, slots=True)
class DeviceEvent:
    """One decoded inbound push — the ``on_mqtt_dp_received_success``
    payload shaped for consumers.

    ``data`` is the full decoded envelope (``dps``/``dpsTime``/``devId``
    plus type fields for non-DP protocols); ``dps``/``dps_time`` are the
    convenience views lifted out of ``data`` when present.
    """

    dev_id: str
    protocol: int
    data: Mapping[str, Any]
    topic: str
    dps: Mapping[int, Any] = field(default_factory=dict)
    dps_time: Mapping[int, int] = field(default_factory=dict)


def _lift_dps(data: Mapping[str, Any]) -> dict[int, Any]:
    dps = data.get("dps")
    if not isinstance(dps, Mapping):
        return {}
    out: dict[int, Any] = {}
    for key, value in dps.items():
        try:
            out[int(key)] = value
        except (TypeError, ValueError):
            continue
    return out


def _lift_dps_time(data: Mapping[str, Any]) -> dict[int, int]:
    raw = data.get("dpsTime")
    if not isinstance(raw, Mapping):
        return {}
    out: dict[int, int] = {}
    for key, value in raw.items():
        try:
            out[int(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return out


def make_central_ingest_sink(
    ingest: Any,
    schema_provider: Callable[[str], Any] | Mapping[str, Any] | None = None,
) -> Callable[[DeviceEvent], None]:
    """Bridge decoded MQTT DP pushes into ``CentralDpIngest.ingest`` — the
    same merge/filter/stale-``dpsTime`` path the app runs for cloud DPs.

    ``schema_provider`` resolves a devId to its ``SchemaBean`` map (the
    ``DevUtil.decodeRaw``/``checkReceiveCommond`` inputs); a plain mapping
    of ``devId → schemaMap`` also works. With ``None`` both DevUtil seams
    degrade the way the app's null-schema path does (decode=no-op,
    check=true)."""

    from .sdk.validation import check_receive_command, decode_raw

    def schema_for(dev_id: str):
        if schema_provider is None:
            return None
        if callable(schema_provider):
            return schema_provider(dev_id)
        return schema_provider.get(dev_id)

    def sink(event: DeviceEvent) -> None:
        if not event.dps:
            return
        schema = schema_for(event.dev_id)
        ingest.ingest(
            None,
            event.dev_id,
            {str(dp): t for dp, t in event.dps_time.items()} or None,
            json.dumps({str(dp): v for dp, v in event.dps.items()}),
            True,  # from_cloud — MQTT is the cloud channel
            decode_raw=lambda _d, m: decode_raw(m, schema),
            check_receive=lambda _d, m: check_receive_command(schema, m),
        )

    return sink


class DeviceEventListener:
    """``qqpqqpq`` — the app's device ``MqttMessageRespParseListener``."""

    def __init__(
        self,
        local_keys: Mapping[str, str],
        dedup: ThingMessageCache,
        on_event: Callable[[DeviceEvent], None],
        on_error: Callable[[str, str, str], None] | None = None,
        *,
        user_topic: str = "",
        dp_sink: Callable[[DeviceEvent], None] | None = None,
    ) -> None:
        self._local_keys = dict(local_keys)
        self._dedup = dedup
        self._on_event = on_event
        self._on_error = on_error
        self._user_topic = user_topic
        self._dp_sink = dp_sink

    def set_local_key(self, dev_id: str, local_key: str) -> None:
        self._local_keys[dev_id] = local_key

    def get_local_key(self, topic: str) -> str | None:
        """``getLocalKey`` — strip ``smart/mb/in|out/`` → devRespBean
        localKey (mesh fallback omitted: no mesh devices here)."""

        return self._local_keys.get(_dev_id_from_topic(topic))

    def get_topic_suffix(self) -> list[str]:
        """``getTopicSuffix`` = ``["smart/mb/in/", "m/dg/", user_topic]``."""

        return [SMART_MB_IN, M_DG_PREFIX, self._user_topic]

    def is_data_updated(self, topic_id: str, s: int, o: int) -> bool:
        """``isDataUpdated`` — strip ``smart/mb/in/``|``m/dg/`` →
        ``ThingMessageCache.isDataUpdated(devId, s, o)``."""

        dev_id = topic_id
        for prefix in (SMART_MB_IN, M_DG_PREFIX):
            if dev_id.startswith(prefix):
                dev_id = dev_id[len(prefix) :]
                break
        return self._dedup.is_data_updated_so(dev_id, s, o)

    def on_mqtt_dp_received_success(self, topic: str, protocol: int, obj: dict) -> None:
        data = obj if isinstance(obj, Mapping) else {}
        inner = data.get("data")
        payload = inner if isinstance(inner, Mapping) else data
        dev_id = str(
            payload.get("devId") or payload.get("gwId") or _dev_id_from_topic(topic)
        )
        event = DeviceEvent(
            dev_id=dev_id,
            protocol=protocol,
            data=payload,
            topic=topic,
            dps=_lift_dps(payload),
            dps_time=_lift_dps_time(payload),
        )
        if self._dp_sink is not None:
            try:
                self._dp_sink(event)
            except Exception:
                log.exception("dp ingest sink failed")
        try:
            self._on_event(event)
        except Exception:
            log.exception("device event callback failed")

    def on_mqtt_dp_received_error(self, topic: str, code: str, msg: str) -> None:
        if self._on_error is not None:
            try:
                self._on_error(topic, code, msg)
            except Exception:
                log.exception("device error callback failed")


def build_mqtt_credentials(
    profile: Any,
    session: Any,
) -> tuple[MqttConnectConfig, SdkMqttCredentials]:
    """``UserConfigSessionLogoutManager$6.getMqttConfigInfo`` +
    ``qpqbppd`` — session → connect config + OEM credentials.

    ``token`` is the session ``sid`` (verified in smali); ``appTag`` is
    the literal ``"os"``; ``password`` is the emulation-verified cmd-2
    nested-MD5 seed centered on 16 chars.
    """

    config = MqttConnectConfig(
        app_tag="os",
        uid=session.uid,
        ecode=session.ecode,
        partner_identity=session.partner_identity,
        token=session.sid,
    )
    credentials = SdkMqttCredentials(
        config,
        profile.client_id,
        get_ch_key=lambda _b: profile.ch_key,
        do_command_native_2=lambda arg: default_cmd2(arg, profile.signing_key),
    )
    return config, credentials


class PopurMqttEvents:
    """The app's real-time channel: SSL MQTT → decoded device events.

    Constructed from a logged-in :class:`MobileSession` +
    :class:`MobileAppProfile`. ``connect()`` opens TLS to
    ``domain.mobileMqttsUrl:mqttsPort``, registers the listener and
    subscribes every registered device's ``smart/mb/in/{devId}`` plus
    the user topic — the same set the app opens at bootstrap.

    ``manager``/``client`` are exposed so :class:`CloudChannelBackend`
    can share this connection for the write path, exactly like the
    app's singleton ``IMqttServer``.
    """

    def __init__(
        self,
        profile: Any,
        session: Any,
        install_id: str,
        *,
        devices: Mapping[str, str] | None = None,
        on_event: Callable[[DeviceEvent], None] | None = None,
        on_error: Callable[[str, str, str], None] | None = None,
        on_connect: Callable[[], None] | None = None,
        dedup: ThingMessageCache | None = None,
        sock_factory: Callable | None = None,
        tls_context: Any = None,
        tag: str = "os",
        dp_sink: Callable[[DeviceEvent], None] | None = None,
    ) -> None:
        self.profile = profile
        self.session = session
        self._install_id = install_id
        self._on_event = on_event or (lambda event: None)
        self._on_error = on_error
        self._on_connect = on_connect
        self._dedup = dedup or ThingMessageCache()
        self._sock_factory = sock_factory
        self._tls_context = tls_context
        self._tag = tag

        connect_config, self.credentials = build_mqtt_credentials(profile, session)
        self.connect_config = connect_config
        user_topic = self.credentials.user_topic()

        domain = session.domain or {}
        host = str(
            domain.get("mobileMqttsUrl")
            or domain.get("mobileMqttUrl")
            or profile.api_host.replace("https://", "").replace("http://", "")
        )
        try:
            port = int(domain.get("mqttsPort") or 8883)
        except (TypeError, ValueError):
            port = 8883

        self.config: MqttConfigBean = init_mqtt_config(
            host,
            profile.package_name or "com.smartapp.popur.app",
            connect_config.app_tag or tag,
            install_id,
            session.uid or "",
        )
        if port != self.config.port:
            self.config.port = port
            self.config.server_url = f"ssl://{host}:{port}"
            self.config.mqtt_urls = [self.config.server_url]

        self.manager = MqttServerManager.get_instance(tag)
        self.listener = DeviceEventListener(
            devices or {},
            self._dedup,
            self._on_event,
            self._on_error,
            user_topic=user_topic,
            dp_sink=dp_sink,
        )
        if self.listener not in self.manager.message_listeners:
            self.manager.message_listeners.append(self.listener)
        self.client = MqttWireClient(
            self.manager,
            self.config,
            self.credentials,
            sock_factory=sock_factory,
            tls_context=tls_context,
        )
        self._user_topic = user_topic
        # Desired topic → qos set; re-issued after every reconnect because
        # the session is clean (broker drops subscriptions on disconnect).
        self._subscriptions: dict[str, int] = {}
        events = self

        class _StatusCallback:
            def on_connect_success(self) -> None:
                events._resubscribe()
                if events._on_connect is not None:
                    try:
                        events._on_connect()
                    except Exception:
                        log.exception("mqtt on_connect callback failed")

            def on_connect_error(self, code: str, error: str) -> None:
                if events._on_error is not None:
                    try:
                        events._on_error("connect", code, error)
                    except Exception:
                        log.exception("mqtt on_error callback failed")

        self.client.register_mqtt_callback(_StatusCallback())

    def _resubscribe(self) -> None:
        """Re-SUBSCRIBE every desired topic after a (re)connect — the
        manager's ``subscribe_state`` still shows them live, so reset to
        pending first or ``client.subscribe`` would skip the wire call."""

        topics = list(self._subscriptions)
        for topic in topics:
            if self.manager.subscribe_state.get(topic) is True:
                self.manager.subscribe_state[topic] = False
        if topics:
            self.client.subscribe(topics, [self._subscriptions[t] for t in topics], None)

    @property
    def connected(self) -> bool:
        return self.client.connected

    def register_device(self, dev_id: str, local_key: str) -> None:
        """Add a device's localKey so its ``smart/mb/in/{devId}`` frames
        decode (and so :meth:`subscribe_device` can open the topic)."""

        self.listener.set_local_key(dev_id, local_key)

    def subscribe_device(self, dev_id: str, qos: int = 1) -> None:
        """``IMqttServer.subscribe("smart/mb/in/"+devId)`` — live decode
        requires :meth:`register_device` first."""

        self._subscriptions[SMART_MB_IN + dev_id] = qos
        self.client.subscribe([SMART_MB_IN + dev_id], [qos], None)

    async def connect(self, dev_ids: list[str] | None = None) -> None:
        """Open the TLS session and subscribe the device + user topics."""

        await asyncio.to_thread(self.client.connect)
        for dev_id in dev_ids or sorted(self.listener._local_keys):
            self._subscriptions[SMART_MB_IN + dev_id] = 1
        if self._user_topic:
            self._subscriptions[self._user_topic] = 1
        if self._subscriptions:
            topics = list(self._subscriptions)
            await asyncio.to_thread(
                self.client.subscribe, topics, [1] * len(topics), None
            )

    async def close(self) -> None:
        await asyncio.to_thread(self.client.close)
