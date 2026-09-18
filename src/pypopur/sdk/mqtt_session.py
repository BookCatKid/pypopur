"""MQTT session layer — ports of ``bqbppdq`` (MqttServerManager),
``qpqbppd`` (SdkMqttCertificationInfo, the OEM credentials provider),
``MqttConnectConfig`` and ``MqttConfigBean``, plus the ``pqdppqd`` m/m/i/
flow frame.

smali: smali_classes3/com/thingclips/sdk/mqtt/{bqbppdq,qpqbppd,pqdppqd}.smali
       smali_classes3/com/thingclips/smart/android/config/bean/MqttConnectConfig.smali

The socket client (``pqpbdqq``, a vendored Paho wrapper) is intentionally
not ported — this module models everything above it: credential formulas,
config beans, the subscribed-topics bookkeeping map, and
``parseMessage``/``messageArrived`` listener routing. A transport adapter
feeds raw ``(topic, payload)`` into :meth:`MqttServerManager.parse_message`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

from ._fastjson import parse_object
from ._java import java_substring, text_is_empty
from .crypto import AESUtil, crc32, md5_upper
from .mqtt_framing import (
    MqttFrameError,
    build_mqtt_publish,
    dispatch_inbound_message,
)

# pqpbpqd constants — obfuscated via String.replace tricks:
#   "thinglink/".replace("hing", "y")  → "tylink/"
#   "thing/smart/will".replace("hing", "uya") → "tuya/smart/will"
TYLINK_PREFIX = "tylink/"
YU_MB_IN_PREFIX = "yu/mb/in/"
MM_I_PREFIX = "m/m/i/"
SMART_MB_IN_PREFIX = "smart/mb/in/"
SMART_MB_OUT_PREFIX = "smart/mb/out/"
WILL_TOPIC = "tuya/smart/will"
MQTT_SSL_PORT = 0x22B3  # 8883


def _md5_lower(value: str) -> str:
    """``MD5Util.md5AsBase64`` — lowercase hex MD5 (misnamed in Java)."""

    return md5_upper(value).lower()


def _jstr(value) -> str:
    """``StringBuilder.append((String) null)`` renders the literal ``null``."""

    return "null" if value is None else str(value)


# --------------------------------------------------------------------------
# Beans
# --------------------------------------------------------------------------


@dataclass
class MqttControlBuilder:
    """``com.thingclips.smart.interior.mqtt.MqttControlBuilder`` — what
    ``bbppbbd`` hands to ``IMqttServer.publishDevice``."""

    data: Any = None
    local_key: str | None = None
    pv: str | None = None
    protocol: int = 0
    topic_id: str | None = None
    sn: int = 0
    o: int = 0
    s: int = 0
    t: int = 0


@dataclass
class MqttConnectConfig:
    """``MqttConnectConfig`` — populated from the login ``User`` session
    (``partnerIdentity``/``uid``/``token``/``ecode``) and base config."""

    access_id: str | None = None
    app_secret: str | None = None  # field name is "appSercet" in smali
    app_tag: str | None = None
    can_use_mqtt_quic: bool = False
    can_use_ssl: bool = False
    ecode: str | None = None
    partner_identity: str | None = None
    terminal_id: str | None = None
    timestamp: str | None = None
    token: str | None = None
    uid: str | None = None


@dataclass
class MqttConfigBean:
    """``MqttConfigBean`` — the bean ``initMqttConfig`` fills; defaults are
    the smali constants (qos=1, keepAlive=60, timeout=15, maxInflight=60)."""

    client_id: str | None = None
    username: str | None = None  # bean-level name; NOT the wire username
    server_url: str | None = None  # "ssl://host:8883"
    mqtt_urls: list = field(default_factory=list)
    clean_session: bool = True
    qos: int = 1
    keep_alive: int = 60
    time_out: int = 15
    retained: bool = False
    enable_quic: bool = False
    max_inflight: int = 60
    will_topic: str = WILL_TOPIC
    ssl_key: str = ""
    ssl_password: str = ""
    connect_type: int = 1
    host: str | None = None
    port: int = MQTT_SSL_PORT
    ip_address: str | None = None


def init_mqtt_config(
    host: str,
    package_name: str,
    tag: str,
    device_id: str,
    uid: str,
) -> MqttConfigBean:
    """``bqbppdq.initMqttConfig`` (non-industry path, 580-1316).

    - bean ``username`` = ``getDeviceID(app) + "_" + md5hex(uid +
      "sdkfasodifca")`` — this is NOT the wire username (the connection
      model pulls credentials from the ``pbpdpdp`` provider instead).
    - ``clientId`` = ``packageName + "_mb_" + username + "_" + tag``.
    - ``serverUrl`` = ``"ssl://" + host + ":8883"``, ``connectType=1``.
    """

    username = f"{device_id}_{_md5_lower(uid + 'sdkfasodifca')}"
    return MqttConfigBean(
        client_id=f"{package_name}_mb_{username}_{tag}",
        username=username,
        server_url=f"ssl://{host}:{MQTT_SSL_PORT}",
        mqtt_urls=[f"ssl://{host}:{MQTT_SSL_PORT}"],
        host=host,
    )


# --------------------------------------------------------------------------
# Credentials — qpqbppd (SdkMqttCertificationInfo, the mSdk==true path)
# --------------------------------------------------------------------------


class SdkMqttCredentials:
    """``qpqbppd`` — OEM (``ThingSmartNetWork.mSdk == true``) credential
    formulas.

    ``app_id`` is ``ThingSmartNetWork.mAppId`` (the APP2 client id).
    ``get_ch_key(app_id_bytes)`` stands in for
    ``ThingNetworkSecurity.getChKey``; ``do_command_native_2`` for
    ``doCommandNative(ctx, 2, ecode.bytes, null, mD)`` whose exact native
    semantics are still open (audit §F) — inject the emulator/bridge.
    """

    def __init__(
        self,
        config: MqttConnectConfig | None,
        app_id: str,
        get_ch_key: Callable[[bytes], str],
        do_command_native_2: Callable[[bytes], str | None],
    ) -> None:
        self.config = config
        self.app_id = app_id
        self._get_ch_key = get_ch_key
        self._do_command_native_2 = do_command_native_2

    def user_topic(self) -> str:
        """``bdpdqbp()`` — ``partnerIdentity + "/mb/" + uid``; empty config
        → ``""``; null fields render as the literal ``"null"``."""

        if self.config is None:
            return ""
        return f"{_jstr(self.config.partner_identity)}/mb/{_jstr(self.config.uid)}"

    def password(self) -> str:
        """``bppdpdq()`` — ``v = cmd2(ecode.bytes)`` (null →
        ``"value ==null"``); returns ``v[len/2-8 : len/2+8]`` (16 chars
        centered). Null ecode NPEs in Java — ``None.encode()`` raises here."""

        if self.config is None:
            return ""
        v = self._do_command_native_2(self.config.ecode.encode())  # noqa: E1101 — NPE-faithful
        if v is None:
            v = "value ==null"
        half = len(v) >> 1
        # Java substring bounds-checks: a short "value ==null" (12 chars →
        # [-2, 14)) throws StringIndexOutOfBoundsException up the stack.
        return java_substring(v, half - 8, half + 8)

    def username(self) -> str:
        """``qddqppb()`` —
        ``partnerIdentity + "_v1_" + appId + "_" + chKey + "_mb_" + token +
        md5hex(md5hex(appId) + ecode)[-16:]``; null fields render ``"null"``."""

        if self.config is None:
            return ""
        inner = _md5_lower(_md5_lower(self.app_id) + _jstr(self.config.ecode))
        last16 = inner[len(inner) - 16 :]
        ch_key = self._get_ch_key(self.app_id.encode())
        return (
            f"{_jstr(self.config.partner_identity)}_v1_{self.app_id}_{ch_key}"
            f"_mb_{_jstr(self.config.token)}{last16}"
        )


# --------------------------------------------------------------------------
# m/m/i/ flow frame — pqdppqd
# --------------------------------------------------------------------------


def mmi_flow_crc_ok(payload: bytes) -> bool:
    """``pqdppqd.bdpdqbp([B)`` — ``be32(payload[-4:]) == crc32(payload[:-4])``."""

    if len(payload) < 4:
        # Java: arraycopy of a negative length throws IndexOutOfBounds → the
        # whole parse aborts; mirror as False (frame is unparseable).
        return False
    return int.from_bytes(payload[-4:], "big", signed=True) == crc32(payload[:-4])


def mmi_flow_decrypt(local_key: str | None, payload: bytes) -> bytes | None:
    """``pqdppqd.bdpdqbp(String, [B)`` — header ``be16(magic, flags, encFlag,
    len)`` then data ``payload[8:8+len]``; ``0x55aa,0,0`` → AES-decrypt,
    ``0x55aa,0,*`` → raw slice, else → None."""

    if not mmi_flow_crc_ok(payload):
        return None
    magic, flags, enc_flag, length = (
        int.from_bytes(payload[o : o + 2], "big", signed=True) for o in (0, 2, 4, 6)
    )
    if magic != 0x55AA or flags != 0:
        return None
    data = payload[8 : 8 + length]
    if enc_flag == 0:
        return AESUtil(local_key.encode()).decrypt_with_bytes(data)
    return data


# --------------------------------------------------------------------------
# Listener interfaces (duck-typed) + the parseMessage routing
# --------------------------------------------------------------------------


class MqttMessageRespParseListener(Protocol):
    """``MqttMessageRespParseListener`` — device-message listeners."""

    def on_mqtt_dp_received_success(self, topic: str, protocol: int, obj: dict) -> None: ...
    def on_mqtt_dp_received_error(self, topic: str, code: str, msg: str) -> None: ...
    def get_topic_suffix(self) -> list[str]: ...
    def get_local_key(self, dev_or_topic: str) -> str | None: ...
    def is_data_updated(self, topic_id: str, s: int, o: int) -> bool: ...


class MqttFlowRespParseListener(Protocol):
    """``MqttFlowRespParseListener`` — m/m/i/ flow listeners."""

    def get_local_key(self, dev_id: str) -> str | None: ...
    def on_success(self, topic: str, data: bytes | None) -> None: ...


class MqttServerManager:
    """``bqbppdq`` — per-tag singleton shell.

    Only the observable session state is modeled: the ``pppbppp``
    subscribed-topics map, ``isSubscribe`` semantics, listener lists, and
    ``parseMessage`` topic routing. The wire client is injected.
    """

    _instances: ClassVar[dict[str, MqttServerManager]] = {}

    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.subscribe_state: dict[str, bool] = {}  # pppbppp HashMap
        self.message_listeners: list[MqttMessageRespParseListener] = []
        self.flow_listeners: list[MqttFlowRespParseListener] = []
        # Outbound seams: publish_fn(topic, bytes, cb) is the wire client;
        # is_real_connect() the session flag; intercept(topic) → alternate
        # publish callable (uniTag reroute); publish_302 is the `e()` path.
        self.publish_fn: Callable | None = None
        self.publish_302: Callable | None = None
        self.intercept: Callable | None = None
        self.is_real_connect: Callable[[], bool] = lambda: False

    @classmethod
    def get_instance(cls, tag: str) -> MqttServerManager:
        if tag not in cls._instances:
            cls._instances[tag] = cls(tag)
        return cls._instances[tag]

    # -- subscription bookkeeping --------------------------------------

    def is_subscribe(self, topic: str | None) -> bool:
        """``isSubscribe``: empty → true; non-``smart/mb/in/`` → true;
        map miss → **false**; hit → stored Boolean."""

        if text_is_empty(topic):
            return True
        if not topic.startswith(SMART_MB_IN_PREFIX):
            return True
        v = self.subscribe_state.get(topic)
        if v is None:
            return False
        return v

    def mark_subscribe(self, topic: str, ok: bool = True) -> None:
        """``$pbpdpdp.onSuccess`` — each requested topic → ``TRUE``."""

        self.subscribe_state[topic] = ok

    def mark_unsubscribe(self, topic: str) -> None:
        """``unSubscribe`` — the map entry is REMOVED (not set false)."""

        self.subscribe_state.pop(topic, None)

    def subscribe(self, topics: list[str], qoses: list[int]) -> list[str]:
        """``subscribe([String,[I,cb)`` bookkeeping (4512-4792): for each
        ``min(len(topics), len(qoses))`` pair, skip empty topics; a map hit
        of ``TRUE`` is skipped; otherwise the topic is stored ``FALSE``
        (pending) and returned in the request list. An empty request list
        means Java calls ``cb.onSuccess()`` immediately — the caller should
        treat ``[]`` as success."""

        pending: list[str] = []
        for i in range(min(len(topics), len(qoses))):
            topic = topics[i]
            if text_is_empty(topic):
                continue
            if self.subscribe_state.get(topic) is not True:
                self.subscribe_state[topic] = False
                pending.append(topic)
        return pending

    # -- inbound routing — parseMessage (bqbppdq 1424-2003) -------------

    def parse_message(self, topic: str, payload: bytes | None) -> None:
        """``parseMessage(topic, msg)`` — routes by topic prefix to the
        registered listeners, exactly like the Java CopyOnWriteArrayList
        iteration order."""

        if topic.startswith(TYLINK_PREFIX):
            for listener in self.message_listeners:
                try:
                    obj = parse_object(payload.decode())
                    listener.on_mqtt_dp_received_success(topic, -1, obj)
                except Exception as e:
                    listener.on_mqtt_dp_received_error(topic, "ParseMqttMessageError", str(e))
        elif topic.startswith(YU_MB_IN_PREFIX):
            for listener in self.message_listeners:
                try:
                    listener.on_mqtt_dp_received_success(topic, -1, {"data": payload})
                except Exception as e:
                    listener.on_mqtt_dp_received_error(topic, "ParseMqttMessageError", str(e))
        elif not topic.startswith(MM_I_PREFIX):
            for listener in self.message_listeners:
                try:
                    results = dispatch_inbound_message(
                        topic,
                        payload,
                        listener.get_local_key,
                        dedup=listener.is_data_updated,
                        prefixes=listener.get_topic_suffix(),
                    )
                    for protocol, obj in results:
                        listener.on_mqtt_dp_received_success(topic, protocol, obj)
                except MqttFrameError as e:
                    listener.on_mqtt_dp_received_error(topic, e.code, e.message)
                except Exception as e:
                    listener.on_mqtt_dp_received_error(
                        topic, "6002", "ParseMqttMessageError" + str(e)
                    )
        else:
            try:
                for listener in self.flow_listeners:
                    dev_id = topic.replace(MM_I_PREFIX, "")
                    local_key = listener.get_local_key(dev_id)
                    if text_is_empty(local_key):
                        continue
                    data = mmi_flow_decrypt(local_key, payload)
                    listener.on_success(topic, data)
            except Exception:
                pass  # Java: caught and logged ("parseMessage query exception")

    def message_arrived(self, topic: str, payload: bytes | None) -> None:
        """``messageArrived`` — thin wrapper over parseMessage."""

        self.parse_message(topic, payload)

    # -- outbound — publishDevice (bqbppdq 3269-3419) -------------------

    def publish_device(
        self,
        builder: MqttControlBuilder | None,
        cb=None,
    ) -> None:
        """``publishDevice(builder, cb)``:

        1. null builder → ``onError("100001", "MqttControlBuilder is
           empty")``
        2. ``!isRealConnect()`` → ``onError("6000", "mqtt is not
           connect")``
        3. ``!isSubscribe("smart/mb/in/"+topicId)`` →
           ``subscribe(that topic, null)``
        4. (DEFAULT tag) intercept-listener reroute — modeled as the
           injectable ``intercept`` returning an alternate
           ``publish_device`` target or None.
        5. ``bddqqbb`` record → ``ppdpppq`` pv dispatch → framed bytes →
           ``bqbppdq$qpppdqb``: publish to ``"smart/mb/out/"+topicId``;
           protocol 302 → ``e()`` alternate path.
        """
        if builder is None:
            if cb is not None:
                cb.on_error("100001", "MqttControlBuilder is empty")
            return
        if not self.is_real_connect():
            if cb is not None:
                cb.on_error("6000", "mqtt is not connect")
            return
        topic_id = builder.topic_id
        in_topic = SMART_MB_IN_PREFIX + topic_id
        if not self.is_subscribe(in_topic):
            self.subscribe([in_topic], [0])
        if self.intercept is not None:
            alt = self.intercept(SMART_MB_OUT_PREFIX + topic_id)
            if alt is not None:
                alt(builder, cb)
                return
        try:
            payload = build_mqtt_publish(
                builder.pv,
                builder.local_key,
                builder.data,
                builder.topic_id,
                builder.protocol,
                builder.t,
                builder.s,
                builder.o,
            )
        except MqttFrameError as e:
            if cb is not None:
                cb.on_error(e.code, e.message)
            return
        if builder.protocol == 302 and self.publish_302 is not None:
            self.publish_302(payload, SMART_MB_OUT_PREFIX + topic_id, cb)
        elif self.publish_fn is not None:
            self.publish_fn(SMART_MB_OUT_PREFIX + topic_id, payload, cb)
